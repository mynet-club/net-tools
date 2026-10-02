package routing

import (
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// §3.D：无价目的 provider 不得当零成本。默认（cheapest 且未显式放行）直接排除，
// 并留下可验证的 candidate_cost_unknown。
func TestCheapestExcludesUnknownCostByDefault(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	in := inputFor(&allowAllGate{}, ObjectiveCheapest,
		offerFor("free-lookalike", 0, 1, testModel).withUnknownCost(),
		offerFor("priced", 1, 1, testModel).withCost(0.01, 0.02),
	)
	plan := planWithSeed(t, ctx, chain, in, deriveSeed(t, "req-cost", testPolicyVer))

	if r, ok := rejectionOf(plan, "free-lookalike"); !ok || r != policy.ReasonCandidateCostUnknown {
		t.Fatalf("无价目候选必须以 candidate_cost_unknown 排除，实际 %+v", plan.Rejections)
	}
	if c, _ := plan.Primary(); c.Provider != "priced" {
		t.Fatalf("首选必须有价目，实际 %s", c.Provider)
	}
	// 关键反证：漏价目的那家绝不能因为「成本 0」被当成最便宜的。
	if containsProviderName(plan, "free-lookalike") {
		t.Errorf("无价目候选出现在计划里，等于按零成本参与比较")
	}
}

// 显式放行未知成本时它们可以进 fallback 链，但**永不占首选位**，
// 且计划上必须留下「这份便宜结论建立在缺价目数据上」的标记。
func TestCheapestNeverRanksUnknownCostFirst(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	build := func(offers ...Offer) policy.RoutingPlan {
		in := inputFor(&allowAllGate{}, ObjectiveCheapest, offers...)
		in.AllowUnknownCost = true
		return planWithSeed(t, ctx, chain, in, deriveSeed(t, "req-cost-allow", testPolicyVer))
	}

	// 无价目的在更低的档：有价目的仍然抢到首选位。
	plan := build(
		offerFor("unknown-cheap", 0, 1, testModel).withUnknownCost(),
		offerFor("priced", 1, 1, testModel).withCost(0.01, 0.02),
	)
	if c, _ := plan.Primary(); c.Provider != "priced" {
		t.Fatalf("未知成本不得因档序更低而占首选，实际 %s", c.Provider)
	}
	if !hasReason(plan, policy.ReasonCandidateCostUnknown) {
		t.Errorf("放行未知成本必须在 ReasonCodes 里留痕，实际 %v", plan.ReasonCodes)
	}
	if len(plan.Rejections) != 0 {
		t.Errorf("显式放行后不该记 Rejection（它进了 Fallbacks），实际 %+v", plan.Rejections)
	}
	if !containsProviderName(plan, "unknown-cheap") {
		t.Errorf("被放行的候选应留在 fallback 链里: %s", joinOrder(plan))
	}

	// 粘性也不能把一个未知成本候选推上 cheapest 的首选位。
	in := inputFor(&allowAllGate{}, ObjectiveCheapest,
		offerFor("priced", 0, 1, testModel).withCost(0.01, 0.02),
		offerFor("unknown", 0, 1, testModel).withUnknownCost(),
	)
	in.AllowUnknownCost = true
	in.Sticky = &StickyState{Provider: "unknown"}
	in.Seed = deriveSeed(t, "req-sticky-unknown", testPolicyVer)
	plan, err := NewPlanner().Plan(ctx, chain, in)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := plan.Primary(); c.Provider != "priced" {
		t.Errorf("粘性把未知成本候选推上了 cheapest 首选位: %s", c.Provider)
	}
}

// cheapest 在同档内的排序：成本升序，稳定 tiebreak 用 provider id。
func TestCheapestOrdersByKnownCost(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	in := inputFor(&allowAllGate{}, ObjectiveCheapest,
		offerFor("cheap", 0, 1, testModel).withCost(0.001, 0.002),
		offerFor("mid", 0, 1, testModel).withCost(0.02, 0.02), // 合计 0.04，第二便宜
		offerFor("zexp", 0, 1, testModel).withCost(0.9, 1.2),  // 合计 2.1，与 aexp 同价
		offerFor("aexp", 0, 1, testModel).withCost(0.9, 1.2),  // 同价 → 按 provider id 升序
	)
	plan := planWithSeed(t, ctx, chain, in, deriveSeed(t, "req-cheapest", testPolicyVer))
	want := []string{"cheap", "mid", "aexp", "zexp"}
	if got := orderOf(plan); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("cheapest 排序不对: %v，应为 %v", got, want)
	}
	if !hasReason(plan, policy.ReasonCheapestFirst) {
		t.Errorf("缺 cheapest_first 解释码: %v", plan.ReasonCodes)
	}
}

// fastest：观测延迟升序；无观测的排最后（拿不到数据不等于 0ms）；冷却中的排最后。
func TestFastestRanksByObservedLatency(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	in := inputFor(&allowAllGate{}, ObjectiveFastest,
		offerFor("noisy", 0, 1, testModel),
		offerFor("slow", 0, 1, testModel).withLatency(900),
		offerFor("quick", 0, 1, testModel).withLatency(120),
		offerFor("cooling-fast", 0, 1, testModel).withLatency(1).cooling(testNow.Add(time.Minute)),
	)
	plan := planWithSeed(t, ctx, chain, in, deriveSeed(t, "req-fastest", testPolicyVer))
	// 键序是（可用性 → 有无观测 → 延迟）：先可用性，是因为「此刻不能用」比「速度未知」
	// 更确定地坏事，所以 1ms 观测的 cooling-fast 要排在可用但没观测的 noisy 之后。
	want := []string{"quick", "slow", "noisy", "cooling-fast"}
	if got := orderOf(plan); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("fastest 排序不对: %v，应为 %v", got, want)
	}
	// 全池都没有观测时也得给出计划（档序 + id 兜底），而不是因为缺数据而卡住业务。
	in2 := inputFor(&allowAllGate{}, ObjectiveFastest,
		offerFor("zeta", 0, 1, testModel), offerFor("alpha", 0, 1, testModel))
	plan2 := planWithSeed(t, ctx, chain, in2, deriveSeed(t, "req-no-obs", testPolicyVer))
	if c, _ := plan2.Primary(); c.Provider != "alpha" {
		t.Errorf("无观测时按稳定 id 兜底，实际 %s", c.Provider)
	}
}

// fastest 的排序解释码在注册表里还没有：明确不硬凑一个语义错的码。
func TestFastestHasNoRankingReasonYet(t *testing.T) {
	if r := ObjectiveFastest.selectionReason(); r.Valid() {
		t.Fatalf("注册表补了 fastest 的码，请同步删除 reasons.go / objective.go 里的缺口说明: %s", r)
	}
}

func TestParseObjective(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    Objective
		wantErr bool
	}{
		{"", DefaultObjective, false},
		{"  cheapest  ", ObjectiveCheapest, false},
		{"FIXED-ORDER", "", true}, // 大小写敏感：目标函数名是稳定标识，不做隐式折叠
		{"smartest", "", true},
	} {
		got, err := ParseObjective(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q 应被拒绝，实际得到 %q", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q 解析失败: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q = %q，应为 %q", tc.in, got, tc.want)
		}
	}
	if !DefaultObjective.valid() {
		t.Error("默认目标函数必须合法")
	}
}
