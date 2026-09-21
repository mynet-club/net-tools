package server

import (
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// shanghai 与生产上填进价目行 peak_tz 的写法一致：固定偏移，不是 IANA 名字
// （Alpine/musl 上没有系统 tzdata，LoadLocation 会失败）。
var shanghai = time.FixedZone("+08:00", 8*3600)

// atWeekday 求「某个指定星期几的 hh:mm（+08:00）」，不硬编码日期，
// 测试因此与「今天」无关。
func atWeekday(wd time.Weekday, h, m int) time.Time {
	d := time.Date(2026, 1, 1, h, m, 0, 0, shanghai)
	for d.Weekday() != wd {
		d = d.AddDate(0, 0, 1)
	}
	return d
}

func ratioPtr(v float64) *float64 { return &v }

// 冻结的上游成本要乘上**请求开始时刻**那一档的峰谷系数 ——
// DeepSeek 的空闲价正好是高峰价的一半，不乘就是整整一倍的误差。
func TestFreezeUpstreamCostAppliesPeakRatio(t *testing.T) {
	h := newConsumptionHarness(t, newUsageStub(t, 0), testPricing)

	peak := atWeekday(time.Wednesday, 10, 0)
	off := atWeekday(time.Wednesday, 13, 0)
	if err := h.db.InsertProviderPrice(&store.ProviderPrice{
		Provider: "sys-a", UpstreamModel: "m", ValidFrom: hourFloor(off.Add(-13 * time.Hour)),
		InHit: 2, InMiss: 2, Out: 2, Currency: "CNY",
		PeakHours:    []string{"09:00-12:00", "14:00-18:00"},
		OffPeakRatio: ratioPtr(0.5), PeakTZ: "+08:00",
	}); err != nil {
		t.Fatal(err)
	}

	freeze := func(at time.Time) float64 {
		prompt, completion := int64(stubPrompt), int64(stubOut)
		rec := &store.RequestRecord{
			OK: true, Provider: "sys-a", UpstreamModel: "m", SystemPaid: true,
			PromptTokens: &prompt, CompletionTokens: &completion,
			CacheHitTokens: stubHit, CacheMissTokens: stubMiss,
		}
		h.srv.freezeUpstreamCost(rec, at)
		if rec.CostUpstream == nil {
			t.Fatalf("%s 应当冻结出金额", at.Format(time.RFC3339))
		}
		return *rec.CostUpstream
	}

	// 单价统一 2/百万，输入 1000 + 输出 500 → 高峰 0.003
	full := float64(stubPrompt+stubOut) * 2 / 1e6
	if got := freeze(peak); math.Abs(got-full) > 1e-12 {
		t.Errorf("高峰时段应当是全价 %v，实际 %v", full, got)
	}
	if got := freeze(off); math.Abs(got-full*0.5) > 1e-12 {
		t.Errorf("空闲时段应当打对折（%v），实际 %v", full*0.5, got)
	}
}

// 分发价同样分时段：两层价格的费率形状一致，系数算法不该各写一份。
func TestFreezeDownstreamChargeAppliesPeakRatio(t *testing.T) {
	h := newConsumptionHarness(t, newUsageStub(t, 0), testPricing)

	peak := atWeekday(time.Wednesday, 10, 0)
	off := atWeekday(time.Wednesday, 13, 0)
	if err := h.db.InsertUserPrice(&store.UserPrice{
		Scope: store.ScopeDefault, Model: "m", ValidFrom: hourFloor(off.Add(-13 * time.Hour)),
		InHit: 4, InMiss: 4, Out: 4, Currency: "CNY",
		PeakHours:    []string{"09:00-12:00"},
		OffPeakRatio: ratioPtr(0.5), PeakTZ: "+08:00",
	}); err != nil {
		t.Fatal(err)
	}

	charge := func(at time.Time) float64 {
		prompt, completion := int64(stubPrompt), int64(stubOut)
		rec := &store.RequestRecord{
			OK: true, SystemPaid: true, UserName: "carol", Model: "m",
			PromptTokens: &prompt, CompletionTokens: &completion,
			CacheHitTokens: stubHit, CacheMissTokens: stubMiss,
		}
		h.srv.freezeDownstreamCharge(rec, at)
		if rec.Charge == nil {
			t.Fatalf("%s 应当冻结出分发金额", at.Format(time.RFC3339))
		}
		return *rec.Charge
	}

	full := float64(stubPrompt+stubOut) * 4 / 1e6
	if got := charge(peak); math.Abs(got-full) > 1e-12 {
		t.Errorf("高峰时段应当按全价收 %v，实际 %v", full, got)
	}
	if got := charge(off); math.Abs(got-full*0.5) > 1e-12 {
		t.Errorf("空闲时段应当按对折收（%v），实际 %v", full*0.5, got)
	}
	// 系统付费的才收费：BYO 用户不该被记账
	prompt := int64(stubPrompt)
	rec := &store.RequestRecord{OK: true, SystemPaid: false, UserName: "carol", Model: "m", PromptTokens: &prompt}
	h.srv.freezeDownstreamCharge(rec, peak)
	if rec.Charge != nil {
		t.Errorf("非系统付费不该冻结分发金额，实际 %v", *rec.Charge)
	}
}

// 规则 B 比价要乘**各家自己**的峰谷系数：两家的高峰时段可以不同，
// 同一时刻谁便宜会因此翻转。不乘就会在空闲时段把贵一倍的家选出来。
func TestRuleBComparesByPeakAdjustedPrice(t *testing.T) {
	alpha := newUsageStub(t, 0)
	beta := newUsageStub(t, 0)
	h := newMUHarnessWith(t, twoProviderYAML(
		"alpha", alpha.srv.URL, "{m: m}",
		"beta", beta.srv.URL, "{m: m}",
		testPricing))

	at := atWeekday(time.Wednesday, 13, 0)
	h.srv.nowFn = func() time.Time { return at }
	from := hourFloor(at.Add(-13 * time.Hour)) // 当天 00:00

	// alpha：任何时候都算高峰（系数 1），基准 1+2=3，恒不随时段变
	if err := h.db.InsertProviderPrice(&store.ProviderPrice{
		Provider: "alpha", UpstreamModel: "m", ValidFrom: from,
		InMiss: 1, Out: 2,
		PeakHours: []string{"00:00-24:00"}, OffPeakRatio: ratioPtr(1), PeakTZ: "+08:00",
	}); err != nil {
		t.Fatal(err)
	}
	// beta：基准贵一倍（2+4=6），但 13:00 落在它的空闲档、系数 0.25 → 1.5，反而更便宜
	if err := h.db.InsertProviderPrice(&store.ProviderPrice{
		Provider: "beta", UpstreamModel: "m", ValidFrom: from,
		InMiss: 2, Out: 4,
		PeakHours: []string{"09:00-12:00"}, OffPeakRatio: ratioPtr(0.25), PeakTZ: "+08:00",
	}); err != nil {
		t.Fatal(err)
	}

	if got := h.srv.cheapestProvider("carol", h.srv.globalProviders(), "m"); got != "beta" {
		t.Fatalf("13:00 时 beta 打折后更便宜，应当选 beta，实际 %q", got)
	}
	// 换到 beta 的高峰时段（10:00）→ beta 变回 6，alpha 重新便宜
	h.srv.nowFn = func() time.Time { return atWeekday(time.Wednesday, 10, 0) }
	if got := h.srv.cheapestProvider("carol", h.srv.globalProviders(), "m"); got != "alpha" {
		t.Fatalf("10:00 时 beta 更贵，应当选 alpha，实际 %q", got)
	}
}

// 价目行没填的峰谷字段**逐字段**沿用全局配置：
// 只填时段而不填时区，意思是「时段我定，时区用全局的」，不该把时段一起丢掉。
func TestPeakRuleFallsBackToGlobalByField(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, `pricing:
  currency: CNY
  peak_hours: ["09:00-12:00"]
  off_peak_ratio: 0.5
  peak_tz: "+08:00"
  models:
    "*": {cache_hit: 0, cache_miss: 0, output: 0}`)

	// 北京 16:00：在全局窗口之外（空闲 0.5），在行内窗口之内（高峰 1）
	at16 := atWeekday(time.Wednesday, 16, 0)
	if got := h.srv.peakRuleAt([]string{"15:00-17:00"}, nil, "").RatioAt(at16); got != 1 {
		t.Errorf("行内时段应当生效（1），实际 %v", got)
	}
	if got := h.srv.peakRuleAt(nil, nil, "").RatioAt(at16); got != 0.5 {
		t.Errorf("什么都不给应当沿用全局（0.5），实际 %v", got)
	}

	// 北京 10:00 = UTC 02:00：按全局时区是高峰，按只有一个字段的覆盖时区是空闲
	at10 := atWeekday(time.Wednesday, 10, 0)
	if got := h.srv.peakRuleAt(nil, nil, "").RatioAt(at10); got != 1 {
		t.Errorf("全局时区（+08:00）判 10:00 为高峰，实际 %v", got)
	}
	if got := h.srv.peakRuleAt(nil, nil, "+00:00").RatioAt(at10); got != 0.5 {
		t.Errorf("只覆盖时区后应当按 UTC 判（空闲 0.5），实际 %v", got)
	}
}

// 峰谷字段要能经管理接口写入并原样读回；非法的时段/时区/系数一律 400。
func TestAdminPricePeakFieldsRoundTrip(t *testing.T) {
	h := priceHarness(t)
	base := hourFloor(time.Now().Add(-2 * time.Hour))

	body := providerPriceBody("deepseek", "deepseek-flash", base.Format(time.RFC3339), 8.0)
	body["peak_hours"] = []string{"09:00-12:00", "14:00-18:00"}
	body["off_peak_ratio"] = 0.5
	body["peak_tz"] = "+08:00"
	resp, raw := h.put(t, "/v1/_admin/prices/provider", adminToken, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("写入带峰谷的价目应 200，实际 %d: %s", resp.StatusCode, raw)
	}

	resp, raw = h.get(t, "/v1/_admin/prices/provider?provider=deepseek&upstream_model=deepseek-flash", adminToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("查历史应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	var hist struct {
		Prices []map[string]any `json:"prices"`
	}
	if err := json.Unmarshal(raw, &hist); err != nil {
		t.Fatalf("解析历史失败: %v\n%s", err, raw)
	}
	if len(hist.Prices) != 1 {
		t.Fatalf("应当只有一条历史，实际 %d: %s", len(hist.Prices), raw)
	}
	p := hist.Prices[0]
	if p["peak_tz"] != "+08:00" {
		t.Errorf("peak_tz 应当原样读回 +08:00，实际 %v", p["peak_tz"])
	}
	if v, _ := p["off_peak_ratio"].(float64); v != 0.5 {
		t.Errorf("off_peak_ratio 应当是 0.5，实际 %v", p["off_peak_ratio"])
	}
	if hours, ok := p["peak_hours"].([]any); !ok || len(hours) != 2 {
		t.Errorf("peak_hours 应当读回两条，实际 %v", p["peak_hours"])
	}

	// 非法值：IANA 时区名、坏时段、越界系数
	for i, patch := range []map[string]any{
		{"peak_tz": "Asia/Shanghai"},
		{"peak_tz": "+15:00"},
		{"peak_hours": []string{"09:00"}},
		{"peak_hours": []string{"12:00-09:00"}},
		{"peak_hours": []string{"09:00-12:00"}, "off_peak_ratio": 1.5},
	} {
		b := providerPriceBody("deepseek", "bad-"+string(rune('a'+i)), base.Format(time.RFC3339), 1)
		for k, v := range patch {
			b[k] = v
		}
		resp, raw = h.put(t, "/v1/_admin/prices/provider", adminToken, b)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("第 %d 个非法峰谷值应当 400，实际 %d: %s", i, resp.StatusCode, raw)
		}
	}

	// 分发价一侧同样能带峰谷
	ub := map[string]any{
		"scope": "default", "model": "fast", "valid_from": base.Format(time.RFC3339),
		"in_hit": 0.02, "in_miss": 1.0, "out": 4.0,
		"peak_hours": []string{"09:00-12:00"}, "off_peak_ratio": 0.5, "peak_tz": "+08:00",
	}
	if resp, raw := h.put(t, "/v1/_admin/prices/user", adminToken, ub); resp.StatusCode != http.StatusOK {
		t.Fatalf("写带峰谷的分发价应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	resp, raw = h.get(t, "/v1/_admin/prices/user?scope=default&model=fast", adminToken)
	if resp.StatusCode != http.StatusOK || !containsAll(string(raw), `"peak_tz":"+08:00"`, `"off_peak_ratio":0.5`) {
		t.Errorf("分发价的峰谷字段应当能读回: %d %s", resp.StatusCode, raw)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
