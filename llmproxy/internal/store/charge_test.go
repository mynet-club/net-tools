package store

import (
	"math"
	"testing"
	"time"
)

// 配额的金额口径：冻结优先、未冻结按估算兜底、混合行按请求数摊。
// 服务端与 CLI 都走这一份（以前 cmd 里有一份简化副本，迟早漂移）。
func TestRowChargeFrozenFirstAndMixed(t *testing.T) {
	now := time.Now()
	// 与 config.PricingConfig 同形状的价目：hit=1 miss=2 out=4，单位百万
	cost := CostFunc(func(model string, hit, miss, out int64, at time.Time) (float64, bool) {
		if model != "u-model" {
			return 0, false
		}
		return (float64(hit)*1 + float64(miss)*2 + float64(out)*4) / 1e6, true
	})
	base := UsageRow{
		UpstreamModel: "u-model", Requests: 10, OK: 10,
		PromptTokens: 1000, CacheHitTokens: 800, CacheMissTokens: 200, CompletionTokens: 100,
	}
	// 1) 全部冻结 → 直接用冻结值
	r := base
	r.Charge, r.FrozenCharges = 5.0, 10
	if got := RowCharge(r, cost, now); got != 5.0 {
		t.Errorf("全冻结应当用冻结值 5，实际 %v", got)
	}
	// 2) 全部未冻结 → 估算
	r = base
	wantEst := (800*1.0 + 200*2.0 + 100*4.0) / 1e6
	if got := RowCharge(r, cost, now); math.Abs(got-wantEst) > 1e-12 {
		t.Errorf("全未冻结应当按估算 %v，实际 %v", wantEst, got)
	}
	// 3) 混合（一半冻结）→ 冻结值 + 一半估算
	r = base
	r.Charge, r.FrozenCharges = 2.0, 5
	if got, want := RowCharge(r, cost, now), 2.0+wantEst*0.5; math.Abs(got-want) > 1e-12 {
		t.Errorf("混合行应当是 %v，实际 %v", want, got)
	}
	// 4) 没有价目时不炸，只算冻结部分
	r = base
	r.Charge, r.FrozenCharges = 3.0, 4
	if got, want := RowCharge(r, nil, now), 3.0; math.Abs(got-want) > 1e-12 {
		t.Errorf("没有价目时应当只拿冻结值 %v，实际 %v", want, got)
	}
}

// 摊分的分母必须是**成功数**，不是总请求数。
//
// 失败请求永远不会被冻结，却照样给 Requests +1。拿 Requests 当分母的话，只要这一行
// 有过任何一次失败，FrozenCharges < Requests 就永久成立、于是永远走摊分路径 ——
// 而失败请求贡献 0 token 却贡献 +1 分母，est 被按失败率重复摊一遍到已冻结的金额上。
// 连带后果是进程重启会凭空抬高用户的当月已用金额（实时路径逐请求累加、失败加 0，
// 重载路径走这里），配额于是提前触顶。
func TestRowChargeDenominatorExcludesFailedRequests(t *testing.T) {
	now := time.Now()
	cost := CostFunc(func(model string, hit, miss, out int64, at time.Time) (float64, bool) {
		return (float64(miss) * 2) / 1e6, true
	})

	// 9 条成功、每条 1e6 未命中输入 → 每条 ¥2、合计冻结 18.0；再加 1 条失败（0 token）
	row := UsageRow{
		UpstreamModel: "u-model",
		Requests:      10, OK: 9, Failed: 1,
		PromptTokens: 9_000_000, CacheMissTokens: 9_000_000,
		Charge: 18.0, FrozenCharges: 9,
	}
	if got := RowCharge(row, cost, now); math.Abs(got-18.0) > 1e-12 {
		t.Errorf("9 成功（全冻结）+ 1 失败应当正好是冻结值 18.0，实际 %v —— "+
			"多出来的部分就是按失败率（10%%）多收的钱", got)
	}

	// 失败率 30%：差额同样线性放大，确认不是恰好抵消
	row.Requests, row.OK, row.Failed = 10, 7, 3
	row.PromptTokens, row.CacheMissTokens = 7_000_000, 7_000_000
	row.Charge, row.FrozenCharges = 14.0, 7
	if got := RowCharge(row, cost, now); math.Abs(got-14.0) > 1e-12 {
		t.Errorf("7 成功（全冻结）+ 3 失败应当正好是 14.0，实际 %v", got)
	}

	// 混合行仍然要摊：5 条成功里只冻结了 2 条 → 冻结值 + 3/5 的估算
	row.Requests, row.OK, row.Failed = 6, 5, 1
	row.PromptTokens, row.CacheMissTokens = 5_000_000, 5_000_000
	row.Charge, row.FrozenCharges = 4.0, 2
	est := 5_000_000 * 2.0 / 1e6 // = 10.0
	if got, want := RowCharge(row, cost, now), 4.0+est*0.6; math.Abs(got-want) > 1e-12 {
		t.Errorf("混合行应当是 %v（冻结 4 + 估算 10 的 3/5），实际 %v", want, got)
	}
}
