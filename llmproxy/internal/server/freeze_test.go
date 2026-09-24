package server

import (
	"math"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// usageStub 报的是 DeepSeek 风格：prompt=1000（命中 800 / 未命中 200）、completion=500。
const (
	stubPrompt = 1000
	stubHit    = 800
	stubMiss   = 200
	stubOut    = 500
)

// 请求落库时按**请求开始时刻**生效的价目行把上游成本冻结下来：
// 三档缓存分开计价、输出单独计价、每请求费另加。
func TestFreezeUpstreamCostOnRequest(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "m", "")

	// 价目：命中 1、未命中 2、输出 3（每百万），每请求 0.5
	from := hourFloor(time.Now().Add(-3 * time.Hour))
	if err := h.db.InsertProviderPrice(&store.ProviderPrice{
		Provider: "sys-a", UpstreamModel: "m", ValidFrom: from,
		InHit: 1, InMiss: 2, Out: 3, PerRequestFee: 0.5, Currency: "CNY",
	}); err != nil {
		t.Fatal(err)
	}

	if resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	}); resp.StatusCode != 200 {
		t.Fatalf("请求应当成功，实际 %d: %s", resp.StatusCode, raw)
	}

	want := (float64(stubHit)*1 + float64(stubMiss)*2 + float64(stubOut)*3) / 1e6
	want += 0.5
	st, err := h.db.Stats(time.Time{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.ByProvider) == 0 {
		t.Fatal("没有聚合行")
	}
	row := st.ByProvider[0]
	if row.FrozenRequests != 1 {
		t.Errorf("应当有 1 条已冻结的请求，实际 %d（成本 %v）", row.FrozenRequests, row.CostUpstream)
	}
	if math.Abs(row.CostUpstream-want) > 1e-9 {
		t.Errorf("冻结成本应当是 %v，实际 %v", want, row.CostUpstream)
	}
}

// 没有价目行时保持「未冻结」：报表据此把它归入估算段，而不是当成 0 成本的冻结值。
func TestFreezeSkippedWithoutPriceRow(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "m", "")

	if resp, _ := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	}); resp.StatusCode != 200 {
		t.Fatal("请求应当成功")
	}
	st, err := h.db.Stats(time.Time{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	row := st.ByProvider[0]
	if row.FrozenRequests != 0 || row.CostUpstream != 0 {
		t.Errorf("没有价目时不该冻结：frozen=%d cost=%v", row.FrozenRequests, row.CostUpstream)
	}
}

// 冻结用的是**请求开始时刻**生效的那一档，不是"最新"那一档 ——
// 价格整点生效，跨点请求整单按开始时刻的价，这是设计里明确接受的规则。
func TestFreezeUsesPriceAtRequestStart(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "m", "")

	now := time.Now()
	old := hourFloor(now.Add(-3 * time.Hour))
	if err := h.db.InsertProviderPrice(&store.ProviderPrice{
		Provider: "sys-a", UpstreamModel: "m", ValidFrom: old, Out: 100,
	}); err != nil {
		t.Fatal(err)
	}
	// 未来才生效的新价（output 便宜得多）：本次请求不该用它
	if err := h.db.InsertProviderPrice(&store.ProviderPrice{
		Provider: "sys-a", UpstreamModel: "m", ValidFrom: hourFloor(now.Add(3 * time.Hour)), Out: 0.001,
	}); err != nil {
		t.Fatal(err)
	}

	if resp, _ := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	}); resp.StatusCode != 200 {
		t.Fatal("请求应当成功")
	}
	st, err := h.db.Stats(time.Time{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	row := st.ByProvider[0]
	want := float64(stubOut) * 100 / 1e6 // 只有 out 档有价
	if math.Abs(row.CostUpstream-want) > 1e-9 {
		t.Errorf("应当按开始时刻的旧价冻结（out=100 → %v），实际 %v", want, row.CostUpstream)
	}
}

// 三档口径与夹取：写入档单独计价；未命中在没显式回报时由 prompt 减出来。
func TestUpstreamCostBuckets(t *testing.T) {
	price := &store.ProviderPrice{InHit: 1, InMiss: 2, InWrite: 4, Out: 8, PerRequestFee: 0}
	i := func(v int64) *int64 { return &v }

	// DeepSeek 风格：显式 hit/miss（写入算在未命中里），没有写入档
	rec := &store.RequestRecord{PromptTokens: i(1000), CompletionTokens: i(100), CacheHitTokens: 800, CacheMissTokens: 200}
	if got, want := upstreamCost(price, rec, 1), (800*1.0+200*2.0+100*8.0)/1e6; math.Abs(got-want) > 1e-12 {
		t.Errorf("DeepSeek 风格：得到 %v，期望 %v", got, want)
	}
	// OpenAI 风格：命中 + 写入 + 未命中三档
	rec = &store.RequestRecord{PromptTokens: i(1000), CompletionTokens: i(100), CacheHitTokens: 600, CacheWriteTokens: 300}
	if got, want := upstreamCost(price, rec, 1), (600*1.0+300*4.0+100*2.0+100*8.0)/1e6; math.Abs(got-want) > 1e-12 {
		t.Errorf("三档：得到 %v，期望 %v", got, want)
	}
	// hit+write 超过 prompt → 未命中夹成 0，不能把负数算进去
	rec = &store.RequestRecord{PromptTokens: i(1000), CacheHitTokens: 800, CacheWriteTokens: 900}
	if got, want := upstreamCost(price, rec, 1), (800*1.0+900*4.0)/1e6; math.Abs(got-want) > 1e-12 {
		t.Errorf("超报夹取：得到 %v，期望 %v", got, want)
	}
	// 没有 token（失败请求）只算每请求费
	rec = &store.RequestRecord{}
	p2 := &store.ProviderPrice{PerRequestFee: 0.25}
	if got := upstreamCost(p2, rec, 1); math.Abs(got-0.25) > 1e-12 {
		t.Errorf("无 token 时应当只算每请求费，实际 %v", got)
	}

	// in_write 缺省（0）→ 回落到 in_miss 同价，而不是让写入档免费。
	// 接口省略 in_write 时 Go 的零值就是 0，而 store.ProviderPrice.InWrite 的注释与
	// docs/pricing-design.md §6.1 都承诺「可空 = 与 in_miss 同价」；写入档单价通常还比
	// 未命中贵（Anthropic 系约 1.25×），漏掉它是实打实低估成本。
	noWrite := &store.ProviderPrice{InHit: 1, InMiss: 2, Out: 8}
	rec = &store.RequestRecord{PromptTokens: i(1000), CompletionTokens: i(100), CacheHitTokens: 600, CacheWriteTokens: 300}
	if got, want := upstreamCost(noWrite, rec, 1), (600*1.0+300*2.0+100*2.0+100*8.0)/1e6; math.Abs(got-want) > 1e-12 {
		t.Errorf("in_write 缺省应当按 in_miss 计：得到 %v，期望 %v", got, want)
	}
	// 纯写入档：1e6 个写入 token、in_miss=2 → 该档单独就值 ¥2（回落前是 ¥0）
	rec = &store.RequestRecord{PromptTokens: i(1_000_000), CacheWriteTokens: 1_000_000}
	if got, want := upstreamCost(&store.ProviderPrice{InMiss: 2}, rec, 1), 2.0; math.Abs(got-want) > 1e-12 {
		t.Errorf("纯写入档应当是 %v，实际 %v（0 意味着这一档完全免费）", want, got)
	}
	// 显式配了 in_write 时仍然用它，别被回落逻辑覆盖掉
	rec = &store.RequestRecord{PromptTokens: i(1_000_000), CacheWriteTokens: 1_000_000}
	if got, want := upstreamCost(&store.ProviderPrice{InMiss: 2, InWrite: 5}, rec, 1), 5.0; math.Abs(got-want) > 1e-12 {
		t.Errorf("显式 in_write=5 应当照用，得到 %v，期望 %v", got, want)
	}
}

// 只冻结**系统付费**的请求：BYO 用户用自己的上游，网关不掏钱，不该记成我们的成本。
func TestFreezeSkippedForNonSystemPaid(t *testing.T) {
	h := newConsumptionHarness(t, newUsageStub(t, 0), testPricing)
	from := hourFloor(time.Now().Add(-time.Hour))
	if err := h.db.InsertProviderPrice(&store.ProviderPrice{
		Provider: "sys-a", UpstreamModel: "m", ValidFrom: from, Out: 1,
	}); err != nil {
		t.Fatal(err)
	}
	prompt := int64(1000)
	rec := &store.RequestRecord{
		OK: true, Provider: "sys-a", UpstreamModel: "m",
		PromptTokens: &prompt, SystemPaid: false,
	}
	h.srv.freezeUpstreamCost(rec, time.Now())
	if rec.CostUpstream != nil {
		t.Errorf("非系统付费的请求不该冻结成本，实际 %v", *rec.CostUpstream)
	}
	// 同一个记录改成系统付费就该冻结
	rec.SystemPaid = true
	h.srv.freezeUpstreamCost(rec, time.Now())
	if rec.CostUpstream == nil {
		t.Error("系统付费的请求应当被冻结")
	}
}

// 上游**同时**回报两种缓存形状时不能重复计费。
//
// cacheSplit 的 DeepSeek 分支与 OpenAI 分支对 cache_write_tokens 并不互斥 ——
// 聚合商转发时把两家字段混在一个 usage 里是可能的。而 DeepSeek 的显式 miss 按口径
// **已经包含**写入，于是 write 会被算两遍：prompt=1000 / hit=400 / miss=600 / write=300
// 时三档之和是 1300，超出 prompt 300。
//
// 夹取 miss 而不是丢弃 write：既然上游专门回报了 cache_write_tokens，说明它确实按
// 写入档单独计费（Anthropic 系约 1.25× 溢价），丢掉 write 是低估。夹取后
// hit+write+miss 恰好等于 prompt，不变式成立。
func TestUpstreamCostClampsWhenBucketsExceedPrompt(t *testing.T) {
	price := &store.ProviderPrice{InHit: 1, InMiss: 2, InWrite: 4, Out: 8}
	i := func(v int64) *int64 { return &v }

	// 两种形状并存：显式 hit/miss + cache_write_tokens
	rec := &store.RequestRecord{
		PromptTokens:   i(1000),
		CacheHitTokens: 400, CacheMissTokens: 600, CacheWriteTokens: 300,
	}
	// 夹取后 miss = 1000 - 400 - 300 = 300
	want := (400*1.0 + 300*4.0 + 300*2.0) / 1e6      // 0.0022
	unclamped := (400*1.0 + 300*4.0 + 600*2.0) / 1e6 // 0.0028（超报 300 token）
	if got := upstreamCost(price, rec, 1); math.Abs(got-want) > 1e-12 {
		t.Errorf("三档之和超过 prompt 时应当夹取 miss：得到 %v，期望 %v（不夹取会是 %v，多收 %.0f%%）",
			got, want, unclamped, (unclamped/want-1)*100)
	}

	// hit+write 本身就超过 prompt → miss 夹到 0，不能出现负数
	rec = &store.RequestRecord{PromptTokens: i(1000), CacheHitTokens: 800, CacheWriteTokens: 900}
	want = (800*1.0 + 900*4.0) / 1e6
	if got := upstreamCost(price, rec, 1); math.Abs(got-want) > 1e-12 {
		t.Errorf("hit+write 超报时 miss 应夹到 0：得到 %v，期望 %v", got, want)
	}

	// 正常情况（miss 由 prompt 减出来，三档之和恰好等于 prompt）不受夹取影响
	rec = &store.RequestRecord{
		PromptTokens: i(1000), CompletionTokens: i(100),
		CacheHitTokens: 600, CacheWriteTokens: 300,
	}
	want = (600*1.0 + 300*4.0 + 100*2.0 + 100*8.0) / 1e6
	if got := upstreamCost(price, rec, 1); math.Abs(got-want) > 1e-12 {
		t.Errorf("正常三档不该被夹取影响：得到 %v，期望 %v", got, want)
	}

	// prompt 为 0（失败请求）时不夹取，只算每请求费
	rec = &store.RequestRecord{}
	if got := upstreamCost(&store.ProviderPrice{PerRequestFee: 0.25}, rec, 1); math.Abs(got-0.25) > 1e-12 {
		t.Errorf("无 token 时应当只算每请求费，实际 %v", got)
	}
}
