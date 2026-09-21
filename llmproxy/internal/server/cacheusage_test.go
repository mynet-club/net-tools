package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// 两套缓存字段都要认得：DeepSeek 显式报 hit/miss；OpenAI / Azure 及其兼容实现
// （不少聚合商是这个形状）只报 cached_tokens，未命中得自己减出来。
// 认不出来的后果不是「少记一笔」，而是命中率凭空变成 0、金额按全未命中高估。
func TestUsageCacheHitMissNormalization(t *testing.T) {
	i64 := func(v int64) *int64 { return &v }
	cases := []struct {
		name string
		u    usageInfo
		hit  int64
		miss int64
		ok   bool
	}{
		{name: "DeepSeek 显式字段",
			u:   usageInfo{PromptTokens: i64(1000), PromptCacheHitTokens: i64(800), PromptCacheMissTokens: i64(200)},
			hit: 800, miss: 200, ok: true},
		{name: "OpenAI 形状：cached 就是命中数",
			u: usageInfo{PromptTokens: i64(1000),
				PromptTokensDetails: &struct {
					CachedTokens *int64 `json:"cached_tokens"`
				}{CachedTokens: i64(800)}},
			hit: 800, miss: 200, ok: true},
		{name: "OpenAI 形状：没命中",
			u: usageInfo{PromptTokens: i64(1000),
				PromptTokensDetails: &struct {
					CachedTokens *int64 `json:"cached_tokens"`
				}{CachedTokens: i64(0)}},
			hit: 0, miss: 1000, ok: true},
		{name: "两套都没报 → ok=false（交给计费侧按全未命中保守估）",
			u: usageInfo{PromptTokens: i64(1000)}, hit: 0, miss: 0, ok: false},
		{name: "cached 比 prompt 还大（上游报错）→ 夹住",
			u: usageInfo{PromptTokens: i64(1000),
				PromptTokensDetails: &struct {
					CachedTokens *int64 `json:"cached_tokens"`
				}{CachedTokens: i64(5000)}},
			hit: 1000, miss: 0, ok: true},
		{name: "负数夹成 0",
			u:   usageInfo{PromptTokens: i64(1000), PromptCacheHitTokens: i64(-5), PromptCacheMissTokens: i64(-7)},
			hit: 0, miss: 0, ok: true},
		{name: "nil 接收者",
			u: usageInfo{}, hit: 0, miss: 0, ok: false},
	}
	for _, c := range cases {
		u := c.u // 取地址，便于 nil 语义一致
		hit, miss, ok := u.cacheHitMiss()
		if ok != c.ok || (ok && (hit != c.hit || miss != c.miss)) {
			t.Errorf("%s: 得到 (%d, %d, %v)，期望 (%d, %d, %v)", c.name, hit, miss, ok, c.hit, c.miss, c.ok)
		}
	}
	// nil 指针本身也不能炸
	var p *usageInfo
	if _, _, ok := p.cacheHitMiss(); ok {
		t.Error("nil usageInfo 应当返回 ok=false")
	}
}

// 只报 OpenAI 形状命中数的上游，命中/未命中要如实进库（金额与命中率都由它推出来）。
func TestOpenAIStyleCacheTokensRecorded(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "cmpl-x", "object": "chat.completion", "model": "sys-model",
			"choices": []map[string]any{{
				"index": 0, "message": map[string]string{"role": "assistant", "content": "ok"},
				"finish_reason": "stop",
			}},
			"usage": map[string]any{
				"prompt_tokens": 1000, "completion_tokens": 500, "total_tokens": 1500,
				"prompt_tokens_details": map[string]any{"cached_tokens": 800},
			},
		})
	}))
	t.Cleanup(up.Close)

	h := newMUHarnessWith(t, consumptionYAML(up.URL, testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "sys-model", "")

	resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "sys-model", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	su, err := h.db.SystemUsageSince("carol", store.MonthStart(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if su.CacheHitTokens != 800 || su.CacheMissTokens != 200 {
		t.Fatalf("OpenAI 形状的 cached_tokens 没被算成命中：hit=%d miss=%d（应当是 800/200）",
			su.CacheHitTokens, su.CacheMissTokens)
	}
}

// 流式那条路径（usage 只在最后一个 chunk 里）走的是同一套归一化，这里钉一下。
func TestOpenAIStyleCacheTokensRecordedOnStream(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"}}]}\n\n")
		fmt.Fprint(w, "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":1000,\"completion_tokens\":500,\"total_tokens\":1500,\"prompt_tokens_details\":{\"cached_tokens\":800}}}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	t.Cleanup(up.Close)

	h := newMUHarnessWith(t, consumptionYAML(up.URL, testPricing))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "sys-model", "")

	resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "sys-model", "stream": true,
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	su, err := h.db.SystemUsageSince("carol", store.MonthStart(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if su.CacheHitTokens != 800 || su.CacheMissTokens != 200 {
		t.Fatalf("流式下的 cached_tokens 没被算成命中：hit=%d miss=%d", su.CacheHitTokens, su.CacheMissTokens)
	}
}
