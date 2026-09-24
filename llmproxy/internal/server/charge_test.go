package server

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// usageRows 读某个用户的用量行（接口形状），供断言 cost/charge。
func usageRows(t *testing.T, h *muHarness, user string) []map[string]any {
	t.Helper()
	resp, raw := h.get(t, "/v1/_admin/users/"+user+"/usage?days=1", adminToken)
	if resp.StatusCode != 200 {
		t.Fatalf("查用量失败 %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("解析用量失败: %v\n%s", err, raw)
	}
	return out.Rows
}

// 分发价冻结：向用户收多少按 user_prices 冻结，**user:<名> 优先于 default**。
func TestFreezeDownstreamChargeUsesUserScope(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "m", "")

	from := hourFloor(time.Now().Add(-3 * time.Hour))
	if err := h.db.InsertUserPrice(&store.UserPrice{
		Scope: store.ScopeDefault, Model: "m", ValidFrom: from, InHit: 1, InMiss: 2, Out: 3,
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.db.InsertUserPrice(&store.UserPrice{
		Scope: store.ScopeUser("carol"), Model: "m", ValidFrom: from, InHit: 0.5, InMiss: 1, Out: 1.5,
	}); err != nil {
		t.Fatal(err)
	}

	if resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "m", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	}); resp.StatusCode != 200 {
		t.Fatalf("请求应当成功，实际 %d: %s", resp.StatusCode, raw)
	}

	// 按 carol 自己的价（命中 0.5 / 未命中 1 / 输出 1.5）算
	want := (float64(stubHit)*0.5 + float64(stubMiss)*1 + float64(stubOut)*1.5) / 1e6
	rows := usageRows(t, h, "carol")
	if len(rows) == 0 {
		t.Fatal("用量接口没有行")
	}
	row := rows[0]
	if got, _ := row["frozen_charges"].(float64); got != 1 {
		t.Errorf("应当有 1 条已冻结的分发金额，实际 %v（行内容 %v）", row["frozen_charges"], row)
	}
	if got, _ := row["charge"].(float64); math.Abs(got-want) > 1e-9 {
		t.Errorf("冻结的分发金额应当是 %v，实际 %v", want, got)
	}
	if got, _ := row["cost"].(float64); math.Abs(got-want) > 1e-9 {
		t.Errorf("金额合计应当等于冻结值 %v，实际 %v", want, got)
	}
}

// 没录分发价时：不冻结，金额按 legacy `pricing` 单价表估算兜底 —— 配额必须一直有效，
// 不能因为"还没录价目"就变成 0 成本。
func TestChargeFallsBackToLegacyEstimate(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "sys-model", "") // testPricing 里有 sys-model 的单价

	if resp, _ := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "sys-model", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	}); resp.StatusCode != 200 {
		t.Fatal("请求应当成功")
	}
	// testPricing：sys-model = 命中 0.04 / 未命中 2.0 / 输出 8.0
	want := (float64(stubHit)*0.04 + float64(stubMiss)*2.0 + float64(stubOut)*8.0) / 1e6
	rows := usageRows(t, h, "carol")
	if len(rows) == 0 {
		t.Fatal("用量接口没有行")
	}
	row := rows[0]
	if got, _ := row["frozen_charges"].(float64); got != 0 {
		t.Errorf("没录分发价时不该有冻结值，实际 %v", row["frozen_charges"])
	}
	if got, _ := row["cost"].(float64); math.Abs(got-want) > 1e-9 {
		t.Errorf("金额应当回落到估算 %v，实际 %v", want, got)
	}
}

// 配额的金额口径：冻结优先、未冻结按估算兜底、混合行按请求数摊。
func TestRowChargeFrozenFirstAndMixed(t *testing.T) {
	p := &config.PricingConfig{
		Currency: "CNY",
		Models:   map[string]config.ModelPrice{"u-model": {CacheHit: 1, CacheMiss: 2, Output: 4}},
	}
	now := time.Now()
	base := store.UsageRow{
		UpstreamModel: "u-model", Requests: 10, OK: 10,
		PromptTokens: 1000, CacheHitTokens: 800, CacheMissTokens: 200, CompletionTokens: 100,
	}
	// 1) 全部冻结 → 直接用冻结值
	r := base
	r.Charge, r.FrozenCharges = 5.0, 10
	if got := rowCharge(r, p, now); got != 5.0 {
		t.Errorf("全冻结应当用冻结值 5，实际 %v", got)
	}
	// 2) 全部未冻结 → 估算
	r = base
	wantEst := (800*1.0 + 200*2.0 + 100*4.0) / 1e6
	if got := rowCharge(r, p, now); math.Abs(got-wantEst) > 1e-12 {
		t.Errorf("全未冻结应当按估算 %v，实际 %v", wantEst, got)
	}
	// 3) 混合（一半冻结）→ 冻结值 + 一半估算
	r = base
	r.Charge, r.FrozenCharges = 2.0, 5
	if got, want := rowCharge(r, p, now), 2.0+wantEst*0.5; math.Abs(got-want) > 1e-12 {
		t.Errorf("混合行应当是 %v，实际 %v", want, got)
	}
	// 4) 没有 legacy 单价表时不炸，只算冻结部分
	r = base
	r.Charge, r.FrozenCharges = 3.0, 4
	if got, want := rowCharge(r, nil, now), 3.0; math.Abs(got-want) > 1e-12 {
		t.Errorf("没有 legacy 表时应当只拿冻结值 %v，实际 %v", want, got)
	}
}

// 摊分的分母必须是**成功数**，不是总请求数。
//
// 失败请求永远不会被冻结（freezeDownstreamCharge 在 !rec.OK 时直接 return），
// 却照样给 Requests +1。拿 Requests 当分母的话，只要这一行有过任何一次失败，
// FrozenCharges < Requests 就永久成立、于是永远走摊分路径 —— 而失败请求贡献 0 token
// 却贡献 +1 分母，est 被按失败率重复摊一遍到已经冻结的金额上。
// 这里让 legacy 单价与冻结口径一致，差额就一眼可见：**多收的比例正好等于失败率**。
// 连带后果是进程重启会凭空抬高用户的当月已用金额（实时路径逐请求累加、失败请求加 0，
// 重载路径走这里），配额于是提前触顶。
func TestRowChargeDenominatorExcludesFailedRequests(t *testing.T) {
	p := &config.PricingConfig{
		Currency: "CNY",
		Models:   map[string]config.ModelPrice{"u-model": {CacheMiss: 2}},
	}
	now := time.Now()

	// 9 条成功、每条 1e6 未命中输入 → 每条 ¥2、合计冻结 18.0；再加 1 条失败（0 token）
	row := store.UsageRow{
		UpstreamModel: "u-model",
		Requests:      10, OK: 9, Failed: 1,
		PromptTokens: 9_000_000, CacheMissTokens: 9_000_000,
		Charge: 18.0, FrozenCharges: 9,
	}
	if got := rowCharge(row, p, now); math.Abs(got-18.0) > 1e-12 {
		t.Errorf("9 成功（全冻结）+ 1 失败应当正好是冻结值 18.0，实际 %v —— "+
			"多出来的部分就是按失败率（10%%）多收的钱", got)
	}

	// 失败率 30%：差额同样线性放大，确认不是恰好抵消
	row.Requests, row.OK, row.Failed = 10, 7, 3
	row.PromptTokens, row.CacheMissTokens = 7_000_000, 7_000_000
	row.Charge, row.FrozenCharges = 14.0, 7
	if got := rowCharge(row, p, now); math.Abs(got-14.0) > 1e-12 {
		t.Errorf("7 成功（全冻结）+ 3 失败应当正好是 14.0，实际 %v", got)
	}

	// 混合行仍然要摊：5 条成功里只冻结了 2 条 → 冻结值 + 3/5 的估算
	row.Requests, row.OK, row.Failed = 6, 5, 1
	row.PromptTokens, row.CacheMissTokens = 5_000_000, 5_000_000
	row.Charge, row.FrozenCharges = 4.0, 2
	est := 5_000_000 * 2.0 / 1e6 // = 10.0
	if got, want := rowCharge(row, p, now), 4.0+est*0.6; math.Abs(got-want) > 1e-12 {
		t.Errorf("混合行应当是 %v（冻结 4 + 估算 10 的 3/5），实际 %v", want, got)
	}
}

// 分发价只对**系统付费**的消耗成立：BYO 用户自己的上游，网关不掏钱也不向他收钱。
func TestFreezeDownstreamSkippedForNonSystemPaid(t *testing.T) {
	h := newConsumptionHarness(t, newUsageStub(t, 0), testPricing)
	from := hourFloor(time.Now().Add(-time.Hour))
	if err := h.db.InsertUserPrice(&store.UserPrice{
		Scope: store.ScopeDefault, Model: "m", ValidFrom: from, InMiss: 2, Out: 8,
	}); err != nil {
		t.Fatal(err)
	}
	prompt, completion := int64(1000), int64(100)
	rec := &store.RequestRecord{
		OK: true, UserName: "carol", Model: "m", Provider: "sys-a", UpstreamModel: "m",
		PromptTokens: &prompt, CompletionTokens: &completion, SystemPaid: false,
	}
	h.srv.freezeDownstreamCharge(rec, time.Now())
	if rec.Charge != nil {
		t.Errorf("非系统付费不该冻结分发金额，实际 %v", *rec.Charge)
	}
	rec.SystemPaid = true
	h.srv.freezeDownstreamCharge(rec, time.Now())
	if rec.Charge == nil {
		t.Fatal("系统付费应当冻结分发金额")
	}
	if want := (float64(prompt)*2 + float64(completion)*8) / 1e6; math.Abs(*rec.Charge-want) > 1e-12 {
		t.Errorf("分发金额应当是 %v，实际 %v", want, *rec.Charge)
	}
}
