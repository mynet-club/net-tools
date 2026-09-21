package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// 指定状态码的假上游（用来造 402 / 429 这类"这家不能用"）。
func statusUpstream(t *testing.T, code int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"nope"}`, code)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// 给两家供应商录价：alpha 便宜、beta 贵。返回的是「更便宜那家」的名字。
func priceTwoProviders(t *testing.T, h *muHarness, cheap, dear string) {
	t.Helper()
	from := hourFloor(time.Now().Add(-2 * time.Hour))
	if err := h.db.InsertProviderPrice(&store.ProviderPrice{
		Provider: cheap, UpstreamModel: "m", ValidFrom: from, InMiss: 1, Out: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.db.InsertProviderPrice(&store.ProviderPrice{
		Provider: dear, UpstreamModel: "m", ValidFrom: from, InMiss: 9, Out: 90,
	}); err != nil {
		t.Fatal(err)
	}
}

// 规则 B：新会话（没有粘性可用）按当前上游价挑最便宜的那家，而不是权重随机。
// 两家权重相同、都没有粘性 → 以前是 50/50，现在是 10/10 都走便宜的那家。
func TestRuleBPicksCheapestForNewSession(t *testing.T) {
	alpha := newUsageStub(t, 0)
	beta := newUsageStub(t, 0)
	h := newMUHarnessWith(t, twoProviderYAML(
		"alpha", alpha.srv.URL, "{m: m}",
		"beta", beta.srv.URL, "{m: m}",
		testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "m", "")
	priceTwoProviders(t, h, "alpha", "beta")

	for i := 0; i < 10; i++ {
		resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
			"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
		})
		if resp.StatusCode != 200 {
			t.Fatalf("第 %d 次应 200，实际 %d: %s", i, resp.StatusCode, raw)
		}
		if got := resp.Header.Get("X-LLMProxy-Provider"); got != "alpha" {
			t.Fatalf("第 %d 次应当走便宜的 alpha，实际 %q", i, got)
		}
	}
	if beta.hitCount() != 0 {
		t.Errorf("贵的那家不该被打到，实际 %d 次", beta.hitCount())
	}
}

// 规则 A 优先于规则 B：会话已经粘在贵的那家时，不该为了省钱把它挪走
// （缓存省下的输入价远大于供应商之间的价差）。
func TestRuleAAffinityWinsOverRuleBPrice(t *testing.T) {
	alpha := newUsageStub(t, 0)
	beta := newUsageStub(t, 0)
	h := newMUHarnessWith(t, twoProviderYAML(
		"alpha", alpha.srv.URL, "{m: m}",
		"beta", beta.srv.URL, "{m: m}",
		testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "m", "")
	priceTwoProviders(t, h, "alpha", "beta") // alpha 便宜

	// 把粘性钉在贵的 beta 上（模拟"这个会话上次用的是 beta"）
	h.srv.affinity.Set("carol", "ses_pinned", "m", "beta")

	resp, raw := postWithSession(t, h, "/v1/chat/completions", token, "ses_pinned", map[string]any{
		"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	if got := resp.Header.Get("X-LLMProxy-Provider"); got != "beta" {
		t.Errorf("粘性应当压过价格，实际走了 %q", got)
	}
	if aff := resp.Header.Get("X-Llmproxy-Affinity"); aff != "sticky" {
		t.Errorf("应当报 sticky，实际 %q", aff)
	}
}

// 有会话头但还没粘性时：观测值报 cheapest（按价格挑的），而不是含糊的 new。
func TestRuleBReportsCheapestOutcome(t *testing.T) {
	alpha := newUsageStub(t, 0)
	beta := newUsageStub(t, 0)
	h := newMUHarnessWith(t, twoProviderYAML(
		"alpha", alpha.srv.URL, "{m: m}",
		"beta", beta.srv.URL, "{m: m}",
		testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "m", "")
	priceTwoProviders(t, h, "alpha", "beta")

	resp, _ := postWithSession(t, h, "/v1/chat/completions", token, "ses_new", map[string]any{
		"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if aff := resp.Header.Get("X-Llmproxy-Affinity"); aff != "cheapest" {
		t.Errorf("新会话按价格挑时应报 cheapest，实际 %q", aff)
	}
	// 第二次：已经有粘性了 → sticky
	resp, _ = postWithSession(t, h, "/v1/chat/completions", token, "ses_new", map[string]any{
		"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if aff := resp.Header.Get("X-Llmproxy-Affinity"); aff != "sticky" {
		t.Errorf("第二次应当报 sticky，实际 %q", aff)
	}
}

// 402（额度不足）打一次就给那家压冷却，规则 B 下次改用次便宜的。
func TestQuotaExhaustedProviderIsCooled(t *testing.T) {
	broke := statusUpstream(t, http.StatusPaymentRequired)
	beta := newUsageStub(t, 0)
	h := newMUHarnessWith(t, twoProviderYAML(
		"alpha", broke.URL, "{m: m}",
		"beta", beta.srv.URL, "{m: m}",
		testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "m", "")
	priceTwoProviders(t, h, "alpha", "beta") // alpha 便宜但没额度

	// 第一次：规则 B 挑便宜的 alpha → 402 → 换家到 beta，并给 alpha 压冷却
	resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("应当换家成功，实际 %d: %s", resp.StatusCode, raw)
	}
	if got := resp.Header.Get("X-LLMProxy-Provider"); got != "beta" {
		t.Errorf("应当换到 beta，实际 %q", got)
	}
	if !h.srv.router.Cooling("carol", "alpha") {
		t.Fatal("402 之后应当给 alpha 压冷却")
	}
	// 第二次：alpha 在冷却中 → 直接走 beta
	resp, _ = h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if got := resp.Header.Get("X-LLMProxy-Provider"); got != "beta" {
		t.Errorf("冷却期内应当走 beta，实际 %q", got)
	}
	if got := h.srv.cheapestProvider("carol", h.srv.globalProviders(), "m"); got != "beta" {
		t.Errorf("冷却中的 alpha 不该被规则 B 选中，实际挑了 %q", got)
	}
}

// 没录价目时规则 B 自动退场：行为回到按权重随机（两家都会被打到）。
func TestRuleBFallsBackWithoutPrices(t *testing.T) {
	alpha := newUsageStub(t, 0)
	beta := newUsageStub(t, 0)
	h := newMUHarnessWith(t, twoProviderYAML(
		"alpha", alpha.srv.URL, "{m: m}",
		"beta", beta.srv.URL, "{m: m}",
		testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "m", "")

	if got := h.srv.cheapestProvider("carol", h.srv.globalProviders(), "m"); got != "" {
		t.Errorf("没价目时规则 B 应当退场，实际挑了 %q", got)
	}
	seen := map[string]bool{}
	for i := 0; i < 40; i++ {
		resp, _ := h.post(t, "/v1/chat/completions", token, map[string]any{
			"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
		})
		seen[resp.Header.Get("X-LLMProxy-Provider")] = true
	}
	if len(seen) != 2 {
		t.Errorf("没价目时应当仍按权重分担，实际只用到 %v", seen)
	}
}
