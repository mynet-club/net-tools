package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// 两个系统供应商的池子，方便构造「一家声明了、另一家没声明」的场景。
// models 传 YAML 片段，例如 `["*"]` 或 `{fast: m-one}`。
func twoProviderYAML(aName, aURL, aModels, bName, bURL, bModels, pricing string) string {
	return fmt.Sprintf(`
server:
  host: 127.0.0.1
  port: 0
  api_keys: [sk-static]
  admin_token: sk-admin
routing: {retry: 1, failure_threshold: 3, cooldown_seconds: 60}
providers:
  - name: %s
    enabled: true
    base_url: %s/v1
    api_key: sk-a
    weight: 1
    models: %s
  - name: %s
    enabled: true
    base_url: %s/v1
    api_key: sk-b
    weight: 1
    models: %s
database: {path: "", retain_days: 30}
log: {level: error}
%s
`, aName, aURL, aModels, bName, bURL, bModels, pricing)
}

// 明确匹配：own 模式下，只有**自己声明了这个模型名**的系统供应商才是候选。
//
// 早先是把用户的 upstream 硬套到每一家身上 —— 等于对每一家都说「你承接这个模型」，
// 于是池里全都成了候选、按权重随机打，其中大部分其实没这个模型，就随机 400。
func TestStrictMatchOnlyDeclaredProvidersAreCandidates(t *testing.T) {
	declares := newUsageStub(t, 0)
	doesNot := newUsageStub(t, 0)
	h := newMUHarnessWith(t, twoProviderYAML(
		"has-fast", declares.srv.URL, "{fast: m-one}",
		"no-fast", doesNot.srv.URL, "{other: m-two}",
		testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "")

	for i := 0; i < 25; i++ {
		resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
			"model": "fast", "messages": []map[string]string{{"role": "user", "content": "hi"}},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("第 %d 次应当 200，实际 %d: %s", i, resp.StatusCode, raw)
		}
	}
	if doesNot.hitCount() != 0 {
		t.Errorf("没声明 fast 的那家被打到了 %d 次（应当一次都不打）", doesNot.hitCount())
	}
	if declares.hitCount() != 25 {
		t.Errorf("声明了 fast 的那家只被打到 %d 次（应当 25 次）", declares.hitCount())
	}
}

// 第 3 层：真实打出去的上游模型名取**供应商自己 models 映射的值**。
// 用户那条只写下游名 `fast`，声明与改名都由供应商那一层负责。
func TestProviderMapDecidesUpstreamModelName(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newMUHarnessWith(t, twoProviderYAML(
		"declared", stub.srv.URL, "{fast: m-one}",
		"other", "http://127.0.0.1:1", "{x: y}",
		testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "")

	if resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "fast", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("应当 200，实际 %d: %s", resp.StatusCode, raw)
	}
	if got := stub.lastModel(); got != "m-one" {
		t.Errorf("上游收到的模型名 = %q，应当是供应商映射后的 m-one", got)
	}
}

// upstream 列（第 2 层）非空时：供应商要声明的是**这个名字**，真实名仍取它的映射值。
//
//	user_model[fast] --upstream=deepseek--> provider 声明了 deepseek --> models 里翻成 m-one
func TestUpstreamColumnIsTheNameProvidersMustDeclare(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newMUHarnessWith(t, twoProviderYAML(
		"declared", stub.srv.URL, "{deepseek: m-one}",
		"other", "http://127.0.0.1:1", "{fast: nope}",
		testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "deepseek") // 第 1 层 fast，第 2 层 deepseek

	if resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "fast", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("应当 200，实际 %d: %s", resp.StatusCode, raw)
	}
	if got := stub.lastModel(); got != "m-one" {
		t.Errorf("上游收到的模型名 = %q，应当是 m-one", got)
	}
}

// 没声明的直接出局：池子里一家都不认这个名字、又没有直通兜底时，
// 明确失败，而不是硬转发出去让上游回 400。
func TestNoDeclarerFailsWithoutHittingUpstream(t *testing.T) {
	a := newUsageStub(t, 0)
	b := newUsageStub(t, 0)
	h := newMUHarnessWith(t, twoProviderYAML(
		"no-a", a.srv.URL, "{x: y}",
		"no-b", b.srv.URL, "{p: q}",
		testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "nobody-has-this", "")

	resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "nobody-has-this", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("没人声明这个模型名，不该成功: %s", raw)
	}
	if a.hitCount() != 0 || b.hitCount() != 0 {
		t.Errorf("不该打到任何上游：a=%d b=%d", a.hitCount(), b.hitCount())
	}
	// 报错要说清是「池子里没人声明这个名字」，而不是含糊的「没有可用的上游」——
	// 名单里有这个名字（不是权限问题），问题出在池子那一侧。
	if !strings.Contains(string(raw), "没有一家供应商声明") || !strings.Contains(string(raw), "nobody-has-this") {
		t.Errorf("报错应当点明是池子里没人声明这个模型名: %s", raw)
	}
}

// 直通（models: ["*"]）算一种「什么都认」的声明，所以没被点名的名字仍由它接住 ——
// 兜底这个功能本身没有被削弱，只是在有点名声明时优先级最低。
func TestPassthroughStillCatchesUndeclaredNames(t *testing.T) {
	pass := newUsageStub(t, 0)
	declared := newUsageStub(t, 0)
	h := newMUHarnessWith(t, twoProviderYAML(
		"passthru", pass.srv.URL, `["*"]`,
		"declared", declared.srv.URL, "{fast: m-one}",
		testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "whatever-unknown", "")

	if resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "whatever-unknown", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("直通那家应当接住，实际 %d: %s", resp.StatusCode, raw)
	}
	if pass.hitCount() != 1 || declared.hitCount() != 0 {
		t.Errorf("应当只打到直通那家：pass=%d declared=%d", pass.hitCount(), declared.hitCount())
	}
}
