package server

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// 往 twoProviderYAML 的 server 段里插一条配置（它本身没有这个键的位置）。
func withServerKey(yaml, key, value string) string {
	return strings.Replace(yaml, "admin_token: sk-admin",
		"admin_token: sk-admin\n  "+key+": "+value, 1)
}

// 两家供应商都声明模型 m 的粘性测试装置，server 段由 extra 追加。
func affinityHarness(t *testing.T, extra string) *muHarness {
	t.Helper()
	alpha := newUsageStub(t, 0)
	beta := newUsageStub(t, 0)
	yaml := twoProviderYAML("alpha", alpha.srv.URL, "{m: m}", "beta", beta.srv.URL, "{m: m}", testPricing)
	if extra != "" {
		for _, kv := range strings.Split(extra, ",") {
			parts := strings.SplitN(kv, "=", 2)
			yaml = withServerKey(yaml, strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	return newMUHarnessWith(t, yaml)
}

// 没配 affinity_ttl_ms 时用默认 24 小时（会话可能隔夜还在继续，
// 而上游的前缀缓存通常也活那么久）。
func TestAffinityDefaultTTLFromConfig(t *testing.T) {
	h := affinityHarness(t, "")
	if h.srv.affinity.ttl != defaultAffinityTTL {
		t.Errorf("未配时应当是默认 %s，实际 %s", defaultAffinityTTL, h.srv.affinity.ttl)
	}
	if !h.srv.affinity.Enabled() {
		t.Error("默认应当是启用的")
	}
}

// 配置里显式写 0 = 关闭：请求照旧按权重随机，不写粘性表，也不写观测头 ——
// 关着时应当完全不可见，而不是留一条永远是 new 的字段来混淆排障。
func TestAffinityDisabledByConfig(t *testing.T) {
	h := affinityHarness(t, "affinity_ttl_ms=0")

	if h.srv.affinity.Enabled() {
		t.Fatal("显式 0 应当关闭粘性")
	}
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "m", "")

	resp, raw := postWithSession(t, h, "/v1/chat/completions", token, "ses_off", map[string]any{
		"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("关闭粘性时请求应当照常成功，实际 %d: %s", resp.StatusCode, raw)
	}
	if aff := resp.Header.Get("X-Llmproxy-Affinity"); aff != "" {
		t.Errorf("关闭粘性时不该写观测头，实际 %q", aff)
	}
	if n := h.srv.affinity.Len(); n != 0 {
		t.Errorf("关闭粘性时不该写表，实际记了 %d 条", n)
	}
	// 连发几次，粘性表也应保持为空（行为完全等价于权重随机）
	for i := 0; i < 5; i++ {
		h.post(t, "/v1/chat/completions", token, map[string]any{
			"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
		})
	}
	if n := h.srv.affinity.Len(); n != 0 {
		t.Errorf("连发之后表仍是空的才对，实际 %d 条", n)
	}
}

// 配置里写了具体值就按它来（毫秒）。
func TestAffinityTTLFromConfig(t *testing.T) {
	h := affinityHarness(t, "affinity_ttl_ms=60000")
	if h.srv.affinity.ttl != 60*time.Second {
		t.Errorf("应当是 60s，实际 %s", h.srv.affinity.ttl)
	}
}

// 热重载必须能改掉粘性 TTL。
//
// ttl 是**缓存**在 affinityStore 里的（不像 stream_idle_timeout_ms 那样每请求实时读
// 配置），所以光把新配置存进 cfgStore 不会生效，必须由重载路径主动调 SetAffinityTTL。
// 曾经三处重载路径（2 秒轮询、首个 SIGHUP、后续 SIGHUP）都漏了这一步，于是运维把
// affinity_ttl_ms 改成 0 想临时关掉粘性排障，SIGHUP 也发了、行为却一点没变 ——
// 而且因为 serverEqual 也没比较这个字段，连「配置已热加载」那行日志都不会打。
func TestAffinityTTLHotReload(t *testing.T) {
	h := affinityHarness(t, "")
	aff := h.srv.affinity
	if !aff.Enabled() {
		t.Fatal("前提不成立：默认应当启用粘性")
	}

	// 关掉：Get/Set 都应当变成空操作
	h.srv.SetAffinityTTL(0)
	if aff.Enabled() {
		t.Error("SetAffinityTTL(0) 之后粘性应当关闭")
	}
	aff.Set("alice", "ses", "m", "alpha")
	if got := aff.Get("alice", "ses", "m"); got != "" {
		t.Errorf("关闭后不该记粘性，实际拿到 %q", got)
	}

	// 再打开
	h.srv.SetAffinityTTL(time.Hour)
	if !aff.Enabled() {
		t.Error("SetAffinityTTL(1h) 之后粘性应当重新启用")
	}
	if aff.TTL() != time.Hour {
		t.Errorf("TTL = %s, want 1h", aff.TTL())
	}
	aff.Set("alice", "ses", "m", "alpha")
	if got := aff.Get("alice", "ses", "m"); got != "alpha" {
		t.Errorf("重新启用后应当能记粘性，实际 %q", got)
	}

	// 缩短 TTL 后旧条目应当**立刻**被当成过期：判定是每次 Get 时按当前 ttl 现算的，
	// 所以 SetTTL 不需要主动清扫（内存也仍由 max 钉死）。
	h.srv.SetAffinityTTL(time.Nanosecond)
	time.Sleep(2 * time.Millisecond)
	if got := aff.Get("alice", "ses", "m"); got != "" {
		t.Errorf("TTL 缩到 1ns 后旧条目应当立即过期，实际拿到 %q", got)
	}
}
