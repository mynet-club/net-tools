package server

import (
	"encoding/json"
	"math"
	"net/http"
	"testing"
	"time"

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

// priced 要反映「金额口径到底可不可用」，而不只是「legacy 兜底表配没配」。
//
// config.yaml 的 pricing 段早已退居为「没有价目行时的估算兜底」，真正的价目在库里。
// 只看 pricing.Enabled() 的话：录了 DB 价目、金额也确实在按请求冻结，接口却仍然回
// priced:false —— 生产上就撞见过这个自相矛盾（frozen_charges=1 而 priced=false）。
func TestUsageReportPricedReflectsDBPrices(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, "") // 刻意不给 legacy pricing 段
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "sys-model", "")

	readPriced := func() bool {
		t.Helper()
		resp, raw := h.get(t, "/v1/_me/usage?days=1", token)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("用量接口应 200，实际 %d: %s", resp.StatusCode, raw)
		}
		var out struct {
			Cost struct {
				Priced bool `json:"priced"`
			} `json:"cost"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("解析用量响应: %v (%s)", err, raw)
		}
		return out.Cost.Priced
	}

	if readPriced() {
		t.Error("既没有 legacy 表、也没有 DB 价目行时，priced 应当是 false")
	}

	from := hourFloor(time.Now().Add(-time.Hour))
	if err := h.db.InsertUserPrice(&store.UserPrice{
		Scope: store.ScopeDefault, Model: "sys-model", ValidFrom: from,
		InMiss: 2, Out: 8, Currency: "CNY",
	}); err != nil {
		t.Fatal(err)
	}
	// 生产路径（admin API）写价目会 Flush 缓存；这里直接写库，手动清一下
	h.srv.usageCache.Flush()
	if !readPriced() {
		t.Error("录了 DB 分发价目之后 priced 应当翻成 true（legacy 兜底表仍然是空的）")
	}
}
