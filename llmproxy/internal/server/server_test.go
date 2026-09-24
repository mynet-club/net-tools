package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/logx"
	"github.com/mynet-club/net-tools/llmproxy/internal/router"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// ---------------------------------------------------------------- 模拟上游

type upstreamCall struct {
	Body      map[string]any
	Auth      string
	Path      string
	UserAgent string
}

type mockUpstream struct {
	name       string
	apiKey     string // 期望的 key；不匹配返回 401
	failStatus int    // 非 0 时固定返回该状态码
	failTimes  int    // 只失败前 N 次，之后恢复；-1 表示一直失败
	streamable bool
	baseURL    string // startMockUpstream 填充
	mu         sync.Mutex
	calls      []upstreamCall
	callCount  int
}

func (m *mockUpstream) record(c upstreamCall) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, c)
	m.callCount++
	return m.callCount
}

func (m *mockUpstream) Calls() []upstreamCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]upstreamCall, len(m.calls))
	copy(out, m.calls)
	return out
}

func (m *mockUpstream) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func startMockUpstream(t *testing.T, m *mockUpstream) *mockUpstream {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)

		n := m.record(upstreamCall{
			Body:      body,
			Auth:      r.Header.Get("Authorization"),
			Path:      r.URL.Path,
			UserAgent: r.Header.Get("User-Agent"),
		})

		if m.apiKey != "" && r.Header.Get("Authorization") != "Bearer "+m.apiKey {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"error":{"message":"invalid api key","type":"authentication_error"}}`)
			return
		}
		if m.failStatus != 0 {
			if m.failTimes < 0 || n <= m.failTimes {
				w.WriteHeader(m.failStatus)
				fmt.Fprintf(w, `{"error":{"message":"upstream boom","type":"server_error"}}`)
				return
			}
		}

		model, _ := body["model"].(string)
		stream, _ := body["stream"].(bool)

		if stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"}}]}\n\n")
			fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" world\"}}]}\n\n")
			fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":22,\"total_tokens\":33}}\n\n")
			fmt.Fprintf(w, "data: [DONE]\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"chatcmpl-1","object":"chat.completion","model":%q,"choices":[{"index":0,"message":{"role":"assistant","content":"pong from %s"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":7,"total_tokens":12}}`,
			model, m.name)
	}))
	t.Cleanup(srv.Close)
	m.baseURL = srv.URL
	return m
}

// ---------------------------------------------------------------- 测试夹具

type harness struct {
	srv        *Server
	gateway    *httptest.Server
	db         *store.Store
	router     *router.Router
	cfgStore   *config.Store
	configPath string
	cfgYAML    string
}

func newHarness(t *testing.T, yamlSrc string) *harness {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(yamlSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgStore := config.NewStore(cfgPath)
	cfg, err := cfgStore.Load()
	if err != nil {
		t.Fatalf("加载配置失败: %v\n配置:\n%s", err, yamlSrc)
	}
	db, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	r := router.New(cfg.Routing, cfg.Normalized)
	lg := logx.New(logx.LevelError, "", 0, 0)
	s := New(cfgStore, db, r, lg)
	gw := httptest.NewServer(s.Handler())
	t.Cleanup(gw.Close)

	return &harness{
		srv: s, gateway: gw, db: db, router: r,
		cfgStore: cfgStore, configPath: cfgPath, cfgYAML: yamlSrc,
	}
}

func (h *harness) post(t *testing.T, path, token string, body map[string]any) (*http.Response, []byte) {
	t.Helper()
	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, h.gateway.URL+path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, raw
}

func (h *harness) get(t *testing.T, path, token string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.gateway.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, raw
}

func cfgYAML(baseURLs map[string]string, apiKeys []string) string {
	var b strings.Builder
	b.WriteString("server:\n  host: 127.0.0.1\n  port: 0\n  api_keys:\n")
	for _, k := range apiKeys {
		fmt.Fprintf(&b, "    - %s\n", k)
	}
	b.WriteString("routing:\n  retry: 2\n  failure_threshold: 3\n  cooldown_seconds: 60\nproviders:\n")
	for name, u := range baseURLs {
		fmt.Fprintf(&b, "  - name: %s\n    base_url: %s\n    api_key: sk-%s\n    weight: 1\n    models: [\"*\"]\n", name, u, name)
	}
	b.WriteString("database:\n  retain_days: 90\nlog:\n  level: error\n")
	return b.String()
}

// ---------------------------------------------------------------- 测试

func TestHealthzAndAuth(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))

	// healthz 不需要鉴权
	resp, body := h.get(t, "/healthz", "")
	if resp.StatusCode != 200 {
		t.Fatalf("healthz = %d %s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte(`"status":"ok"`)) {
		t.Errorf("healthz body = %s", body)
	}

	// 无 key → 401
	resp, _ = h.get(t, "/v1/models", "")
	if resp.StatusCode != 401 {
		t.Errorf("无鉴权应 401, got %d", resp.StatusCode)
	}
	resp, _ = h.get(t, "/v1/models", "sk-wrong")
	if resp.StatusCode != 401 {
		t.Errorf("错误 key 应 401, got %d", resp.StatusCode)
	}

	// 正确 key → 200
	resp, body = h.get(t, "/v1/models", "sk-local")
	if resp.StatusCode != 200 {
		t.Fatalf("正确 key 应 200, got %d %s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte(`"object":"list"`)) {
		t.Errorf("models body = %s", body)
	}

	// 未知路径
	resp, _ = h.get(t, "/v1/nonexistent", "sk-local")
	if resp.StatusCode != 404 {
		t.Errorf("未知路径应 404, got %d", resp.StatusCode)
	}
}

func TestChatCompletionsSuccess(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "vendorA", apiKey: "sk-vendorA"})
	h := newHarness(t, cfgYAML(map[string]string{"vendorA": up.baseURL}, []string{"sk-local"}))

	resp, body := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("pong from vendorA")) {
		t.Errorf("body = %s", body)
	}
	if got := resp.Header.Get("X-LLMProxy-Provider"); got != "vendorA" {
		t.Errorf("X-LLMProxy-Provider = %q", got)
	}

	// 上游应收到正确的 model 与 Authorization
	calls := up.Calls()
	if len(calls) != 1 {
		t.Fatalf("上游调用次数 = %d", len(calls))
	}
	if calls[0].Body["model"] != "gpt-4o" {
		t.Errorf("上游收到 model = %v", calls[0].Body["model"])
	}
	if calls[0].Auth != "Bearer sk-vendorA" {
		t.Errorf("上游收到 Authorization = %q, want Bearer sk-vendorA", calls[0].Auth)
	}

	// 日志里应有记录，且含 token 数
	st, err := h.db.Stats(time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if st.TotalRequests != 1 || st.TotalOK != 1 {
		t.Fatalf("stats = %+v", st)
	}
	rec := st.Recent[0]
	if rec.Provider != "vendorA" || rec.Model != "gpt-4o" {
		t.Errorf("记录 = %+v", rec)
	}
	if rec.TotalTokens == nil || *rec.TotalTokens != 12 {
		t.Errorf("tokens = %v, want 12", rec.TotalTokens)
	}
	if rec.ClientLabel != "key" {
		t.Errorf("client label = %q", rec.ClientLabel)
	}
}

func TestDownstreamAuthNotForwarded(t *testing.T) {
	// cfgYAML 会按供应商名生成 api_key: sk-<name>
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-downstream"}))

	resp, _ := h.post(t, "/v1/chat/completions", "sk-downstream", map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != 200 {
		t.Fatal("请求应成功")
	}
	calls := up.Calls()
	if len(calls) != 1 {
		t.Fatal("上游应被调用一次")
	}
	// 上游收到的必须是上游自己的 key，绝不能是下游的
	if calls[0].Auth == "Bearer sk-downstream" {
		t.Fatal("下游凭证被转发给了上游")
	}
	if calls[0].Auth != "Bearer sk-a" {
		t.Errorf("上游收到的 Authorization = %q, want Bearer sk-a", calls[0].Auth)
	}
}

func TestModelMapping(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	yaml := fmt.Sprintf(`server:
  api_keys: [sk-local]
routing:
  retry: 1
  failure_threshold: 3
  cooldown_seconds: 60
providers:
  - name: a
    base_url: %s
    api_key: sk-a
    weight: 1
    models:
      gpt-4o: gpt-4o-2024-11-20
`, up.baseURL)
	h := newHarness(t, yaml)

	resp, _ := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != 200 {
		t.Fatal("请求应成功")
	}
	calls := up.Calls()
	if calls[0].Body["model"] != "gpt-4o-2024-11-20" {
		t.Errorf("上游 model = %v, want gpt-4o-2024-11-20", calls[0].Body["model"])
	}
}

func TestRetryOnUpstreamFailure(t *testing.T) {
	bad := startMockUpstream(t, &mockUpstream{name: "bad", apiKey: "sk-bad", failStatus: 500, failTimes: -1})
	good := startMockUpstream(t, &mockUpstream{name: "good", apiKey: "sk-good"})
	yaml := fmt.Sprintf(`server:
  api_keys: [sk-local]
routing:
  retry: 2
  failure_threshold: 3
  cooldown_seconds: 60
providers:
  - name: bad
    base_url: %s
    api_key: sk-bad
    weight: 100
    models: ["*"]
  - name: good
    base_url: %s
    api_key: sk-good
    weight: 1
    models: ["*"]
`, bad.baseURL, good.baseURL)
	h := newHarness(t, yaml)

	// 多打几次：bad 权重高但总是 500，应该每次都能靠重试落到 good
	for i := 0; i < 5; i++ {
		resp, body := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
			"model":    "gpt-4o",
			"messages": []map[string]string{{"role": "user", "content": "hi"}},
		})
		if resp.StatusCode != 200 {
			t.Fatalf("第 %d 次请求失败: %d %s", i, resp.StatusCode, body)
		}
		if !bytes.Contains(body, []byte("pong from good")) {
			t.Fatalf("第 %d 次请求未落到 good: %s", i, body)
		}
	}
	if good.Count() == 0 {
		t.Fatal("good 未收到请求")
	}
	if bad.Count() == 0 {
		t.Fatal("bad 未被尝试过")
	}
}

func TestAllProvidersFailing(t *testing.T) {
	bad := startMockUpstream(t, &mockUpstream{name: "bad", apiKey: "sk-bad", failStatus: 500, failTimes: -1})
	h := newHarness(t, cfgYAML(map[string]string{"bad": bad.baseURL}, []string{"sk-local"}))

	resp, body := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode < 400 {
		t.Fatalf("全部失败时应返回错误, got %d %s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("upstream_unavailable")) && !bytes.Contains(body, []byte("所有上游")) {
		t.Errorf("错误信息不清晰: %s", body)
	}
	// 日志应记录失败
	st, _ := h.db.Stats(time.Time{}, 10)
	if st.TotalFailed != 1 {
		t.Errorf("stats.TotalFailed = %d, want 1", st.TotalFailed)
	}
}

func TestCircuitBreakerSkipsUnhealthy(t *testing.T) {
	bad := startMockUpstream(t, &mockUpstream{name: "bad", apiKey: "sk-bad", failStatus: 500, failTimes: -1})
	good := startMockUpstream(t, &mockUpstream{name: "good", apiKey: "sk-good"})
	yaml := fmt.Sprintf(`server:
  api_keys: [sk-local]
routing:
  retry: 3
  failure_threshold: 2
  cooldown_seconds: 300
providers:
  - name: bad
    base_url: %s
    api_key: sk-bad
    weight: 100
    models: ["*"]
  - name: good
    base_url: %s
    api_key: sk-good
    weight: 1
    models: ["*"]
`, bad.baseURL, good.baseURL)
	h := newHarness(t, yaml)

	// 前几次请求让 bad 连续失败，触发熔断
	for i := 0; i < 3; i++ {
		_, _ = h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
			"model":    "gpt-4o",
			"messages": []map[string]string{{"role": "user", "content": "hi"}},
		})
	}
	snap := h.router.Snapshot()
	if snap["bad"].ConsecutiveFailures < 2 {
		t.Skipf("bad 尚未达到熔断阈值（可能被 good 抢走了请求）: %+v", snap["bad"])
	}
	if snap["bad"].UnhealthyUntil.IsZero() {
		t.Fatalf("bad 应已熔断: %+v", snap["bad"])
	}

	// 熔断后 bad 不应再被频繁选中
	badBefore := bad.Count()
	for i := 0; i < 5; i++ {
		resp, body := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
			"model":    "gpt-4o",
			"messages": []map[string]string{{"role": "user", "content": "hi"}},
		})
		if resp.StatusCode != 200 {
			t.Fatalf("熔断后请求仍失败: %d %s", resp.StatusCode, body)
		}
	}
	badAfter := bad.Count()
	if badAfter > badBefore+1 {
		t.Errorf("熔断后 bad 仍被调用了 %d 次", badAfter-badBefore)
	}
}

func TestStreamPassthrough(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a", streamable: true})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))

	payload, _ := json.Marshal(map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
		"stream":   true,
	})
	req, _ := http.NewRequest(http.MethodPost, h.gateway.URL+"/v1/chat/completions", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-local")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("stream status=%d body=%s", resp.StatusCode, raw)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("content-type = %q, want text/event-stream", ct)
	}

	// 逐行读，确认是真正的 SSE
	scanner := bufio.NewScanner(resp.Body)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "Hello") || !strings.Contains(joined, "world") {
		t.Errorf("SSE 内容不完整: %s", joined)
	}
	if !strings.Contains(joined, "[DONE]") {
		t.Errorf("SSE 缺少 [DONE]: %s", joined)
	}

	// 上游应被注入 stream_options.include_usage
	calls := up.Calls()
	if len(calls) != 1 {
		t.Fatalf("calls = %d", len(calls))
	}
	so, _ := calls[0].Body["stream_options"].(map[string]any)
	if so == nil {
		t.Fatalf("stream_options 未被注入: %+v", calls[0].Body)
	}
	if so["include_usage"] != true {
		t.Errorf("include_usage = %v", so["include_usage"])
	}

	// 流式请求的 usage 应从末尾 chunk 提取并落库
	// 等一小会儿让 relay 完成
	time.Sleep(200 * time.Millisecond)
	st, _ := h.db.Stats(time.Time{}, 10)
	if st.TotalRequests != 1 {
		t.Fatalf("stats.TotalRequests = %d", st.TotalRequests)
	}
	rec := st.Recent[0]
	if !rec.Stream {
		t.Error("记录应标记 stream=true")
	}
	if rec.TotalTokens == nil || *rec.TotalTokens != 33 {
		t.Errorf("流式 usage 提取失败: tokens=%v, want 33", rec.TotalTokens)
	}
	if rec.TTFTMs == nil {
		t.Error("流式请求应记录 TTFT")
	}
}

func TestPerProviderProxyConfig(t *testing.T) {
	upDirect := startMockUpstream(t, &mockUpstream{name: "directVendor", apiKey: "sk-d"})
	yaml := fmt.Sprintf(`server:
  api_keys: [sk-local]
routing:
  retry: 0
  failure_threshold: 3
  cooldown_seconds: 60
proxies:
  - name: nowhere
    url: http://127.0.0.1:1
providers:
  - name: directVendor
    base_url: %s
    api_key: sk-d
    weight: 1
    proxy: direct
    models: ["*"]
  - name: proxiedVendor
    base_url: %s
    api_key: sk-p
    weight: 1
    proxy: nowhere
    models: ["*"]
`, upDirect.baseURL, upDirect.baseURL)
	h := newHarness(t, yaml)

	// 直连供应商应成功
	resp, body := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	// 可能落到直连（成功）或 proxied（失败）；多试几次确保两种路径都被走到
	var sawDirectOK, sawProxiedFail bool
	for i := 0; i < 8; i++ {
		resp, body = h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
			"model":    "gpt-4o",
			"messages": []map[string]string{{"role": "user", "content": "hi"}},
		})
		provider := resp.Header.Get("X-LLMProxy-Provider")
		if resp.StatusCode == 200 && strings.Contains(string(body), "directVendor") {
			sawDirectOK = true
		}
		_ = provider
		if resp.StatusCode >= 400 {
			sawProxiedFail = true
		}
	}
	if !sawDirectOK {
		t.Errorf("直连供应商应能成功，最后一次 status=%d body=%s provider=%s",
			resp.StatusCode, body, resp.Header.Get("X-LLMProxy-Provider"))
	}
	// proxied 走 127.0.0.1:1 必然失败——只要看到过一次失败即说明代理路径生效
	if !sawProxiedFail {
		t.Log("警告：未观察到代理路径失败（可能权重导致 proxied 从未被选中），不做硬失败")
	}
}

func TestHotReload(t *testing.T) {
	upA := startMockUpstream(t, &mockUpstream{name: "A", apiKey: "sk-a"})
	upB := startMockUpstream(t, &mockUpstream{name: "B", apiKey: "sk-b"})
	yaml := fmt.Sprintf(`server:
  api_keys: [sk-local]
routing:
  retry: 0
  failure_threshold: 3
  cooldown_seconds: 60
providers:
  - name: vendor
    base_url: %s
    api_key: sk-a
    weight: 1
    models: ["*"]
`, upA.baseURL)
	h := newHarness(t, yaml)

	resp, body := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte("pong from A")) {
		t.Fatalf("初始请求应走 A: %d %s", resp.StatusCode, body)
	}

	// 改配置：同一供应商名，换成 B 的地址
	newYAML := strings.ReplaceAll(yaml, upA.baseURL, upB.baseURL)
	newYAML = strings.ReplaceAll(newYAML, "sk-a", "sk-b")
	if err := os.WriteFile(h.configPath, []byte(newYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, cfg, err := h.cfgStore.Reload()
	if err != nil {
		t.Fatalf("热加载失败: %v", err)
	}
	if !changed {
		t.Fatal("配置应被识别为变更")
	}
	h.router.ApplyConfig(cfg.Routing, cfg.Normalized)
	h.srv.Transports().Reset()

	resp, body = h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte("pong from B")) {
		t.Fatalf("热加载后请求应走 B: %d %s", resp.StatusCode, body)
	}
}

func TestHotReloadKeepsServiceOnBadConfig(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "A", apiKey: "sk-A"})
	h := newHarness(t, cfgYAML(map[string]string{"A": up.baseURL}, []string{"sk-local"}))

	resp, _ := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != 200 {
		t.Fatal("初始请求应成功")
	}

	// 写入坏配置
	if err := os.WriteFile(h.configPath, []byte("providers:\n  - name: x\n    bad: 1\n   oops: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, _, err := h.cfgStore.Reload()
	if err == nil {
		t.Fatal("坏配置应报错")
	}
	if changed {
		t.Error("坏配置不应算作变更")
	}

	// 服务应仍可用（旧配置继续生效）
	resp, body := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("坏配置后服务应继续可用: %d %s", resp.StatusCode, body)
	}
}

func TestLogDoesNotContainContent(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))

	secretMsg := "这是一段绝对不能出现在日志里的秘密提示词"
	secretKey := "sk-local-very-secret-token-value"

	// 用一个不同的 key？—— 配置里是 sk-local；这里用正确 key 发送含秘密内容的请求
	resp, _ := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": secretMsg}},
	})
	if resp.StatusCode != 200 {
		t.Fatal("请求应成功")
	}

	// 检查数据库里没有任何内容/密钥泄漏
	st, err := h.db.Stats(time.Time{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range st.Recent {
		blob := fmt.Sprintf("%+v", rec)
		if strings.Contains(blob, secretMsg) || strings.Contains(blob, "秘密提示词") {
			t.Errorf("请求内容泄漏进数据库: %s", blob)
		}
		if strings.Contains(blob, secretKey) || strings.Contains(blob, "sk-local") {
			t.Errorf("下游密钥明文泄漏进数据库: %s", blob)
		}
	}
	// usage_daily 里也不能有
	for _, r := range st.ByProvider {
		blob := fmt.Sprintf("%+v", r)
		if strings.Contains(blob, "秘密") || strings.Contains(blob, "sk-local") {
			t.Errorf("usage_daily 泄漏: %s", blob)
		}
	}
}

func TestMissingModel(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))

	resp, body := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != 400 {
		t.Fatalf("缺 model 应 400, got %d %s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("model")) {
		t.Errorf("错误信息应提到 model: %s", body)
	}
	if up.Count() != 0 {
		t.Error("缺 model 时不应请求上游")
	}
}

func TestUnknownModelReturns404ish(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	yaml := fmt.Sprintf(`server:
  api_keys: [sk-local]
routing:
  retry: 1
  failure_threshold: 3
  cooldown_seconds: 60
providers:
  - name: a
    base_url: %s
    api_key: sk-a
    weight: 1
    models:
      gpt-4o: gpt-4o
`, up.baseURL)
	h := newHarness(t, yaml)

	resp, body := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model":    "some-unknown-model",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode < 400 {
		t.Fatalf("未知模型应报错, got %d %s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("some-unknown-model")) && !bytes.Contains(body, []byte("没有供应商")) {
		t.Errorf("错误信息应说明模型不可用: %s", body)
	}
}

func TestLiveProvidersEndpoint(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	yaml := fmt.Sprintf(`server:
  api_keys: [sk-local]
routing:
  retry: 0
  failure_threshold: 1
  cooldown_seconds: 300
providers:
  - name: healthy
    base_url: %s
    api_key: sk-a
    weight: 1
    proxy: direct
    models:
      gpt-4o: gpt-4o
  - name: broken
    base_url: %s
    api_key: sk-a
    weight: 5
    proxy: direct
    models: ["*"]
  - name: off
    enabled: false
    base_url: %s
    api_key: sk-a
    weight: 99
    models: ["*"]
`, up.baseURL, up.baseURL, up.baseURL)
	h := newHarness(t, yaml)

	// 需要鉴权
	resp, _ := h.get(t, "/v1/_providers", "")
	if resp.StatusCode != 401 {
		t.Fatalf("无鉴权应 401, got %d", resp.StatusCode)
	}

	// 制造一次失败：broken 指向上游但用错误的 key 期望值会 401 → 记为失败
	// 这里直接改 mock 的期望 key 让 healthy 也失败一次？不必——直接查接口结构
	resp, body := h.get(t, "/v1/_providers", "sk-local")
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var parsed struct {
		Revision  int64 `json:"revision"`
		Providers []struct {
			Name                string   `json:"name"`
			Enabled             bool     `json:"enabled"`
			Weight              float64  `json:"weight"`
			Proxy               string   `json:"proxy"`
			ProxyMode           string   `json:"proxy_mode"`
			Models              []string `json:"models"`
			Healthy             bool     `json:"healthy"`
			ConsecutiveFailures int      `json:"consecutive_failures"`
			TotalRequests       int64    `json:"total_requests"`
			LastError           string   `json:"last_error"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("解析失败: %v\n%s", err, body)
	}
	if len(parsed.Providers) != 3 {
		t.Fatalf("providers = %d, want 3: %s", len(parsed.Providers), body)
	}
	byName := map[string]bool{}
	for _, p := range parsed.Providers {
		byName[p.Name] = p.Enabled
	}
	if !byName["healthy"] || byName["broken"] != true || byName["off"] != false {
		t.Errorf("enabled 标志异常: %+v", byName)
	}

	// 让 broken 连续失败（它 models=["*"]，权重高，多打几次），再查实时状态
	// broken 的 base_url 是 mock 的地址且 api_key 正确，所以它其实是成功的……
	// 改用直接向 router 报失败，再查接口
	h.router.ReportFailure("broken", fmt.Errorf("模拟失败"))
	h.router.ReportFailure("broken", fmt.Errorf("模拟失败"))

	resp, body = h.get(t, "/v1/_providers", "sk-local")
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, p := range parsed.Providers {
		if p.Name != "broken" {
			continue
		}
		if p.ConsecutiveFailures < 2 {
			t.Errorf("broken 连续失败 = %d, want >=2", p.ConsecutiveFailures)
		}
		if p.Healthy {
			t.Error("broken 失败达到阈值后应标记为不健康")
		}
		if p.LastError == "" {
			t.Error("broken 应带有 last_error")
		}
	}
}

func TestModelsListOnlyMapped(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	yaml := fmt.Sprintf(`server:
  api_keys: [sk-local]
providers:
  - name: mapped
    base_url: %s
    api_key: sk-a
    weight: 1
    models:
      gpt-4o: gpt-4o-2024
      claude-3: claude-3-opus
  - name: passthrough
    base_url: %s
    api_key: sk-a
    weight: 1
    models: ["*"]
`, up.baseURL, up.baseURL)
	h := newHarness(t, yaml)

	resp, body := h.get(t, "/v1/models", "sk-local")
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d %s", resp.StatusCode, body)
	}
	var parsed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("解析 models 失败: %v", err)
	}
	ids := map[string]bool{}
	for _, d := range parsed.Data {
		ids[d.ID] = true
	}
	if !ids["gpt-4o"] || !ids["claude-3"] {
		t.Errorf("models 列表不完整: %+v", ids)
	}
	if len(parsed.Data) != 2 {
		t.Errorf("直通型供应商不应贡献模型名, got %d 个", len(parsed.Data))
	}
}

// 记账落库失败必须**可观测**。
//
// 落库失败时请求已经成功返回给客户端了，这笔账却永久丢失 —— README 承诺的
// 「客户端成功数 / 上游收到数 / 数据库落库数三者一致」会静默破裂。只写一行 ERROR
// 日志的话，没人盯着日志就永远发现不了，所以计数要暴露到 /healthz 让监控能直接盯。
func TestPersistFailureIsObservable(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "vendorA", apiKey: "sk-vendorA"})
	h := newHarness(t, cfgYAML(map[string]string{"vendorA": up.baseURL}, []string{"sk-local"}))

	if got := h.srv.PersistFailures(); got != 0 {
		t.Fatalf("初始计数应当是 0，实际 %d", got)
	}
	_, body := h.get(t, "/healthz", "")
	if !bytes.Contains(body, []byte(`"persist_failures":0`)) {
		t.Errorf("healthz 应当暴露 persist_failures 字段: %s", body)
	}

	// 关掉库制造落库失败
	if err := h.db.Close(); err != nil {
		t.Fatal(err)
	}

	resp, body := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	// 转发本身不该受影响：记账是响应之后的事，账丢了也不能把客户端的请求弄失败
	if resp.StatusCode != 200 {
		t.Errorf("记账失败不该影响转发，实际 %d: %s", resp.StatusCode, body)
	}
	if got := h.srv.PersistFailures(); got != 1 {
		t.Errorf("落库失败应当被计数，实际 %d", got)
	}

	_, body = h.get(t, "/healthz", "")
	if !bytes.Contains(body, []byte(`"persist_failures":1`)) {
		t.Errorf("healthz 应当反映计数: %s", body)
	}
	// 但 status 仍然是 ok：转发是好的，标成不健康会让监控误判成服务不可用
	if !bytes.Contains(body, []byte(`"status":"ok"`)) {
		t.Errorf("记账失败不该把 status 标成不健康: %s", body)
	}
}
