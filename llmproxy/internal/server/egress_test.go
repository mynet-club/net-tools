package server

import (
	"net/http"
	"testing"
)

// 下游 POST 只放行推理端点。
//
// 曾经 POST 侧完全敞开、把下游路径原样拼到上游 base_url 后面，于是任何持有效 token 的
// 用户都能让网关带着**运营者的上游密钥**去 POST 上游主机上的任意路径
// （/v1/files 上传、/v1/fine_tuning/jobs 开微调任务、/v1/assistants…），
// 而且这些调用完全不进计量 —— 消费模式的模型级访问控制因此形同虚设。
func TestIsAllowedPostPath(t *testing.T) {
	for _, p := range []string{"/v1/chat/completions", "/v1/completions", "/v1/embeddings"} {
		if !isAllowedPostPath(p) {
			t.Errorf("%s 应当在白名单里", p)
		}
	}
	for _, p := range []string{
		"/v1/files", "/v1/fine_tuning/jobs", "/v1/assistants", "/v1/responses",
		"/v1/organization/project", "/v1/chat/completions/", "/v1/Chat/Completions",
		"/v1/", "/v1", "",
	} {
		if isAllowedPostPath(p) {
			t.Errorf("%s 不该在白名单里", p)
		}
	}
}

// 白名单外的路径要在网关这一层就 404，**绝不能打到上游**。
func TestPostPathWhitelistBlocksUpstream(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "vendorA", apiKey: "sk-vendorA"})
	h := newHarness(t, cfgYAML(map[string]string{"vendorA": up.baseURL}, []string{"sk-local"}))

	body := map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	}

	// 白名单内的照常转发
	resp, raw := h.post(t, "/v1/chat/completions", "sk-local", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("chat/completions 应当照常转发，实际 %d: %s", resp.StatusCode, raw)
	}
	calls := len(up.Calls())

	for _, path := range []string{
		"/v1/files", "/v1/fine_tuning/jobs", "/v1/assistants",
		"/v1/responses", "/v1/organization/project", "/v1/nonexistent",
	} {
		resp, raw := h.post(t, path, "sk-local", body)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s 应当 404，实际 %d: %s", path, resp.StatusCode, raw)
		}
	}
	if got := len(up.Calls()); got != calls {
		t.Errorf("白名单外的路径不该打到上游：上游调用数 %d → %d", calls, got)
	}
}

// 用户自配上游时的 base_url 校验。
//
// 两件事必须在这一层挡住：
//   - 带 query 的 base_url：`http://10.0.0.5:9200/_search?x=` 拼上 `/chat/completions`
//     之后，真正打出去的是 `/_search?x=/chat/completions` —— 路径是 base_url 自己带的，
//     上面的 POST 白名单管不住它。
//   - link-local：云元数据服务 169.254.169.254 就在这里，而它永远不是合法的 LLM 上游。
//     这一档没有开关（回环与私网段才有，见 server.block_local_upstream）。
func TestSelfServiceProviderRejectsBadBaseURL(t *testing.T) {
	h := newMUHarness(t)
	token := h.addUser(t, "alice")

	cases := []struct{ name, baseURL string }{
		{"云元数据地址", "http://169.254.169.254/latest/meta-data/iam/security-credentials/role"},
		{"link-local", "http://169.254.1.1/v1"},
		{"IPv4-mapped 的 link-local", "http://[::ffff:169.254.169.254]/v1"},
		{"未指定地址", "http://0.0.0.0:8080/v1"},
		{"带 query（可绕过路径白名单）", "http://10.0.0.5:9200/_search?x="},
		{"带 anchor", "https://api.example.com/v1#f"},
		{"非 http(s)", "file:///etc/passwd"},
		{"缺主机名", "http:///v1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, raw := h.put(t, "/v1/_me/providers/p1", token, map[string]any{
				"base_url": tc.baseURL, "api_key": "k", "models": []string{"*"},
			})
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("%s（%s）应当 400，实际 %d: %s", tc.name, tc.baseURL, resp.StatusCode, raw)
			}
		})
	}

	// 对照：正当用法不能被误伤 —— 回环上的本地推理服务器（ollama / vLLM）默认放行，
	// 本项目的测试与 e2e 也全靠回环上的假上游。
	resp, raw := h.put(t, "/v1/_me/providers/ok", token, map[string]any{
		"base_url": "http://127.0.0.1:11434/v1", "api_key": "k", "models": []string{"*"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("本机推理服务器默认不该被拒，实际 %d: %s", resp.StatusCode, raw)
	}
}

// 打开 server.block_local_upstream 之后，回环与私网段也要被拒。
func TestBlockLocalUpstreamRejectsLoopback(t *testing.T) {
	h := newMUHarnessWith(t, `
server:
  host: 127.0.0.1
  port: 0
  api_keys: [sk-static]
  admin_token: sk-admin
  block_local_upstream: true
routing: {retry: 0, failure_threshold: 3, cooldown_seconds: 1}
providers:
  - name: sys-a
    enabled: true
    base_url: https://api.example.com/v1
    api_key: sk-sys
    weight: 1
    proxy: direct
    models: ["*"]
database: {path: "", retain_days: 30}
log: {level: error}
`)
	token := h.addUser(t, "alice")

	for _, baseURL := range []string{
		"http://127.0.0.1:11434/v1",
		"http://10.0.0.5:9200/v1",
		"http://192.168.1.1/v1",
	} {
		resp, raw := h.put(t, "/v1/_me/providers/p1", token, map[string]any{
			"base_url": baseURL, "api_key": "k", "models": []string{"*"},
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s 在 block_local_upstream 下应当 400，实际 %d: %s", baseURL, resp.StatusCode, raw)
		}
	}
	// link-local 本来就一律拒绝，不受开关影响
	resp, raw := h.put(t, "/v1/_me/providers/p1", token, map[string]any{
		"base_url": "http://169.254.169.254/latest/meta-data/", "api_key": "k", "models": []string{"*"},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("云元数据地址应当 400，实际 %d: %s", resp.StatusCode, raw)
	}
}
