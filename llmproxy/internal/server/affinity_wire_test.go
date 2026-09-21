package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 带 x-session-affinity 头发请求（harness 自带的 post 不支持自定义头）。
func postWithSession(t *testing.T, h *muHarness, path, token, session string, body map[string]any) (*http.Response, []byte) {
	t.Helper()
	return postWithHeaders(t, h, path, token, map[string]string{"X-Session-Affinity": session}, body)
}

func postWithHeaders(t *testing.T, h *muHarness, path, token string, hdrs map[string]string, body map[string]any) (*http.Response, []byte) {
	t.Helper()
	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, h.gateway.URL+path, strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	raw := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		raw = append(raw, buf[:n]...)
		if rerr != nil {
			break
		}
	}
	resp.Body.Close()
	return resp, raw
}

// 永远 500 的假上游，用来制造「这家用不了」。
func failingUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// 两家供应商都点名声明同一个模型时，**同一个会话**必须一直落到同一家 ——
// 这是会话粘性存在的全部意义：上游的前缀缓存按（账号+模型）分区，换家等于冷启动。
func TestSessionSticksToSameProvider(t *testing.T) {
	alpha := newUsageStub(t, 0)
	beta := newUsageStub(t, 0)
	h := newMUHarnessWith(t, twoProviderYAML(
		"alpha", alpha.srv.URL, "{m: m}",
		"beta", beta.srv.URL, "{m: m}",
		testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "m", "")

	var first string
	for i := 0; i < 12; i++ {
		resp, raw := postWithSession(t, h, "/v1/chat/completions", token, "ses_sticky", map[string]any{
			"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("第 %d 次应 200，实际 %d: %s", i, resp.StatusCode, raw)
		}
		got := resp.Header.Get("X-LLMProxy-Provider")
		aff := resp.Header.Get("X-Llmproxy-Affinity")
		if i == 0 {
			first = got
			if aff != "new" {
				t.Errorf("第一次请求（没有粘性记录）应报 new，实际 %q", aff)
			}
		} else {
			if got != first {
				t.Fatalf("第 %d 次换了家：%s → %s（粘性没生效）", i, first, got)
			}
			if aff != "sticky" {
				t.Errorf("第 %d 次应报 sticky，实际 %q", i, aff)
			}
		}
	}
	if s := h.srv.affinity.Get("carol", "ses_sticky", "m"); s != first {
		t.Errorf("粘性表里记的应当是 %q，实际 %q", first, s)
	}
}

// 会话 id 是下游生成的，必须按用户隔离：另一个用户拿同一个会话 id，
// 不该继承别人的粘性，也不该改写别人的记录。
func TestSessionAffinityIsolatedByUser(t *testing.T) {
	alpha := newUsageStub(t, 0)
	beta := newUsageStub(t, 0)
	h := newMUHarnessWith(t, twoProviderYAML(
		"alpha", alpha.srv.URL, "{m: m}",
		"beta", beta.srv.URL, "{m: m}",
		testPricing))
	carol := h.addUser(t, "carol")
	dave := h.addUser(t, "dave")
	setConsumption(t, h, "carol", "m", "")
	setConsumption(t, h, "dave", "m", "")

	// 先让 carol 的这个会话粘住一家
	resp, _ := postWithSession(t, h, "/v1/chat/completions", carol, "ses_shared", map[string]any{
		"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	carolProvider := resp.Header.Get("X-LLMProxy-Provider")
	if carolProvider == "" {
		t.Fatalf("carol 第一次请求没拿到供应商: %v", resp.Header)
	}

	// dave 用同一个会话 id：他的第一次请求应报 new（不继承），且写完之后
	// carol 的记录不能被改写。
	resp, _ = postWithSession(t, h, "/v1/chat/completions", dave, "ses_shared", map[string]any{
		"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if aff := resp.Header.Get("X-Llmproxy-Affinity"); aff != "new" {
		t.Errorf("dave 不该继承 carol 的粘性，实际报 %q", aff)
	}
	if got := h.srv.affinity.Get("carol", "ses_shared", "m"); got != carolProvider {
		t.Errorf("dave 的请求改写了 carol 的粘性：%q → %q", carolProvider, got)
	}
	daveProvider := h.srv.affinity.Get("dave", "ses_shared", "m")
	if daveProvider == "" {
		t.Error("dave 请求之后应当记下自己的粘性")
	}
}

// 请求没带 x-session-affinity 头时：完全照旧按权重随机，且不碰粘性表。
func TestNoSessionHeaderDoesNotTouchStore(t *testing.T) {
	alpha := newUsageStub(t, 0)
	beta := newUsageStub(t, 0)
	h := newMUHarnessWith(t, twoProviderYAML(
		"alpha", alpha.srv.URL, "{m: m}",
		"beta", beta.srv.URL, "{m: m}",
		testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "m", "")

	for i := 0; i < 6; i++ {
		resp, _ := h.post(t, "/v1/chat/completions", token, map[string]any{
			"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("第 %d 次应 200，实际 %d", i, resp.StatusCode)
		}
		if resp.Header.Get("X-Llmproxy-Affinity") != "" {
			t.Errorf("没有会话头时不该写观测字段，实际 %q", resp.Header.Get("X-Llmproxy-Affinity"))
		}
	}
	if n := h.srv.affinity.Len(); n != 0 {
		t.Errorf("没有会话头的请求不该写粘性表，实际记了 %d 条", n)
	}
}

// 「后端不能用就换家」：粘住的那家返回 500 时，本次请求要漂移到另一家，
// **并且**把粘性更新成新家 —— 之后的请求继续用新家，而不是改回去（避免两家来回横跳）。
func TestSessionDriftsAndUpdatesAffinityWhenProviderFails(t *testing.T) {
	broken := failingUpstream(t)
	beta := newUsageStub(t, 0)
	h := newMUHarnessWith(t, twoProviderYAML(
		"alpha", broken.URL, "{m: m}",
		"beta", beta.srv.URL, "{m: m}",
		testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "m", "")

	// 直接把粘性钉在会失败的那家（模拟「上次用的是 alpha」）
	h.srv.affinity.Set("carol", "ses_drift", "m", "alpha")

	resp, raw := postWithSession(t, h, "/v1/chat/completions", token, "ses_drift", map[string]any{
		"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应当漂移到健康的那家并成功，实际 %d: %s", resp.StatusCode, raw)
	}
	if got := resp.Header.Get("X-LLMProxy-Provider"); got != "beta" {
		t.Errorf("应当漂到 beta，实际 %q", got)
	}
	if aff := resp.Header.Get("X-Llmproxy-Affinity"); aff != "drift" {
		t.Errorf("观测字段应报 drift，实际 %q", aff)
	}
	if got := h.srv.affinity.Get("carol", "ses_drift", "m"); got != "beta" {
		t.Errorf("漂移后粘性应更新成 beta，实际 %q", got)
	}

	// 再来一次：这次应当直接 sticky 到 beta
	resp, _ = postWithSession(t, h, "/v1/chat/completions", token, "ses_drift", map[string]any{
		"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if got := resp.Header.Get("X-LLMProxy-Provider"); got != "beta" {
		t.Errorf("漂移之后应继续用 beta，实际 %q", got)
	}
	if aff := resp.Header.Get("X-Llmproxy-Affinity"); aff != "sticky" {
		t.Errorf("第二次应报 sticky，实际 %q", aff)
	}
}

// 所有候选都挂掉时忘掉粘性 —— 下一个请求重新选，而不是钉死在全挂的那批上。
func TestSessionAffinityForgottenWhenAllProvidersFail(t *testing.T) {
	broken1 := failingUpstream(t)
	broken2 := failingUpstream(t)
	h := newMUHarnessWith(t, twoProviderYAML(
		"alpha", broken1.URL, "{m: m}",
		"beta", broken2.URL, "{m: m}",
		testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "m", "")
	h.srv.affinity.Set("carol", "ses_dead", "m", "alpha")

	resp, _ := postWithSession(t, h, "/v1/chat/completions", token, "ses_dead", map[string]any{
		"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("两家都挂了不该成功")
	}
	if got := h.srv.affinity.Get("carol", "ses_dead", "m"); got != "" {
		t.Errorf("全部失败后应当忘掉粘性，实际还记着 %q", got)
	}
}
