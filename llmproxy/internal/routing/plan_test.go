package routing

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// §6：固定输入得到固定输出。
//
// 断言的是 Digest **加上** Fallbacks 的实际顺序。Digest 在摘要前会稳定排序，
// 只看它会让「首选和尾巴被打乱」这类回归照样全绿，而首选正是这条契约的全部价值。
func TestSameInputProducesIdenticalPlan(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	seed := deriveSeed(t, "req-1", testPolicyVer)
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder,
		offerFor("alpha", 0, 3, testModel),
		offerFor("beta", 0, 1, testModel),
		offerFor("gamma", 1, 5, testModel),
	)

	var wantDigest, wantOrder string
	for i := 0; i < 20; i++ {
		plan := planWithSeed(t, ctx, chain, in, seed)
		digest, order := mustDigest(t, plan), joinOrder(plan)
		if i == 0 {
			wantDigest, wantOrder = digest, order
			continue
		}
		if digest != wantDigest {
			t.Fatalf("第 %d 次摘要与首次不同: %s vs %s", i, digest, wantDigest)
		}
		if order != wantOrder {
			t.Fatalf("第 %d 次候选顺序抖动: %s vs %s", i, order, wantOrder)
		}
	}
	// 顺带钉住计划外壳字段：这些字段决定执行器试几次、什么时候必须重新规划。
	plan := planWithSeed(t, ctx, chain, in, seed)
	if plan.MaxRetries != 2 || plan.Attempts() != 3 {
		t.Errorf("重试预算不对: max_retries=%d attempts=%d", plan.MaxRetries, plan.Attempts())
	}
	if plan.PolicyVersion != testPolicyVer {
		t.Errorf("版本串应来自调用方传入的策略包版本，实际 %q", plan.PolicyVersion)
	}
	if plan.RoutingSeed != seed {
		t.Errorf("计划必须带回 seed，否则这次决策无从回放")
	}
	if want := testNow.Add(testTTL); !plan.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %s，应为 Now+TTL = %s", plan.ExpiresAt, want)
	}
}

// 抽样真的在发生：等权重下换 seed 会换首选。
//
// 这条挡住一种很阴的回归 —— 把累积扫描写成「永远返回池首」，
// 上面那个固定输入的用例照样全绿（同一份 seed 同一个结论），只有分布坏了。
func TestWeightedSamplingActuallyVaries(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	gate := &allowAllGate{}
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		// 每次换一个 requestID：seed 由 policy 派生（版本参与，见 §2.8），
		// 所以「换请求就是换一次抽样」这件事本身就是被测口径的一部分。
		seed := deriveSeed(t, fmt.Sprintf("req-varies-%d", i), testPolicyVer)
		in := inputFor(gate, ObjectiveFixedOrder,
			offerFor("alpha", 0, 1, testModel),
			offerFor("beta", 0, 1, testModel),
		)
		in.Seed = seed
		plan, err := NewPlanner().Plan(ctx, chain, in)
		if err != nil {
			t.Fatalf("第 %d 次规划失败: %v", i, err)
		}
		c, _ := plan.Primary()
		seen[c.Provider]++
	}
	if seen["alpha"] == 0 || seen["beta"] == 0 {
		t.Fatalf("等权重两家都应被选中过，实际 %v", seen)
	}
}

// §6：候选排除原因必须可验证。每个排除方向都给一个候选，逐个核对稳定码。
func TestExclusionReasonCodesAreVerifiable(t *testing.T) {
	ctx := ctxWithRegions(t, policy.LevelConfidential, "cn")
	chain := orgChain(t)
	gate := newStubGate(map[string]policy.Reason{"denied": policy.ReasonDataLevelDenied})

	in := inputFor(gate, ObjectiveFixedOrder,
		offerFor("ok", 0, 1, testModel).withRegion("cn").withCapabilities(CapabilityTools, CapabilityStreaming),
		offerFor("denied", 0, 1, testModel),                                                   // 权限门拒绝
		offerFor("wrong-region", 0, 1, testModel).withRegion("us"),                            // 区域
		offerFor("too-low", 0, 1, testModel).withRegion("cn").withLevel(policy.LevelInternal), // 数据分级：confidential > internal
		offerFor("no-model", 0, 1, "other-model").withRegion("cn"),                            // 不承接该模型名
		offerFor("no-cap", 0, 1, testModel).withRegion("cn").withCapabilities(),               // 缺所需能力
	)
	in.Requirement.Capabilities = []string{CapabilityTools}

	plan := planWithSeed(t, ctx, chain, in, deriveSeed(t, "req-filter", testPolicyVer))

	want := map[string]policy.Reason{
		"denied":       policy.ReasonDataLevelDenied, // gate 的码原样保留，D 不覆盖策略的解释
		"wrong-region": policy.ReasonCandidateRegionExcluded,
		"too-low":      policy.ReasonCandidateLevelExcluded,
		"no-model":     ReasonCapabilityUnmatched,
		"no-cap":       ReasonCapabilityUnmatched,
	}
	for provider, expect := range want {
		got, ok := rejectionOf(plan, provider)
		if !ok {
			t.Errorf("%s 应有排除记录，实际 Rejections=%+v", provider, plan.Rejections)
			continue
		}
		if got != expect {
			t.Errorf("%s 的排除码 = %s，应为 %s", provider, got, expect)
		}
		if !got.Valid() {
			t.Errorf("%s 的排除码 %s 未注册，会让整份计划不可校验", provider, got)
		}
		if containsProviderName(plan, provider) {
			t.Errorf("%s 被排除了却仍出现在 Fallbacks 里", provider)
		}
	}
	if !hasReason(plan, policy.ReasonCandidateRegionExcluded) {
		t.Errorf("ReasonCodes 应汇总排除方向，实际 %v", plan.ReasonCodes)
	}
	if !containsProviderName(plan, "ok") {
		t.Errorf("唯一合格的候选竟被排除: %+v", plan.Rejections)
	}
	// 每个候选都被 gate 问过：过滤次序把权限放在第一位，就不该有「来不及问」的漏网。
	for _, o := range in.Offers {
		if !gate.asked(o.provider()) {
			t.Errorf("gate 没被问过候选 %s，权限判定被短路了", o.provider())
		}
	}
}

// §6：fallback 不绕过权限。被 Gate 拒的候选绝不能出现在 Fallbacks 的任何位置。
func TestGateRejectionNeverReappearsInFallbacks(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	// 唯一的健康候选被拒：剩下的都在别的档、都不健康，正在冷却。
	gate := newStubGate(map[string]policy.Reason{"alpha": policy.ReasonModelNotAllowed})
	in := inputFor(gate, ObjectiveFixedOrder,
		offerFor("alpha", 0, 9, testModel),
		offerFor("beta", 1, 5, testModel).unhealthy().cooling(testNow.Add(time.Hour)),
	)
	plan := planWithSeed(t, ctx, chain, in, deriveSeed(t, "req-bypass", testPolicyVer))

	if containsProviderName(plan, "alpha") {
		t.Fatalf("被权限门拒绝的 alpha 出现在计划里: %s", joinOrder(plan))
	}
	if r, ok := rejectionOf(plan, "alpha"); !ok || r != policy.ReasonModelNotAllowed {
		t.Fatalf("alpha 应以策略码记入 Rejections，实际 %+v", plan.Rejections)
	}
	// 冷却与不健康都不构成排除（现网「宁可重试也不硬失败」），所以计划仍然产得出来。
	if got := joinOrder(plan); got != "beta" {
		t.Fatalf("应退到 beta，实际 %s", got)
	}
}

// gate 给出未注册/空的原因码时，D 回落到已注册码而不是让整份计划校验失败。
func TestGateUnregisteredReasonFallsBack(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	for _, raw := range []policy.Reason{"", policy.Reason("nat-lang-不行")} {
		gate := newStubGate(map[string]policy.Reason{"beta": raw})
		in := inputFor(gate, ObjectiveFixedOrder,
			offerFor("alpha", 0, 1, testModel),
			offerFor("beta", 0, 1, testModel),
		)
		plan := planWithSeed(t, ctx, chain, in, deriveSeed(t, "req-fallback-code", testPolicyVer))
		if r, _ := rejectionOf(plan, "beta"); r != policy.ReasonCandidatePolicyExcluded {
			t.Errorf("gate 码 %q 未注册时应回落 candidate_policy_excluded，实际 %s", raw, r)
		}
		if err := plan.Validate(testNow); err != nil {
			t.Errorf("回落后的计划仍不合法: %v", err)
		}
	}
}

// 一个候选都不剩时报错，并把解释交给调用方（*PlanError 里带 Rejections）。
func TestNoEligibleCandidateReturnsExplainedError(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	gate := newStubGate(map[string]policy.Reason{"alpha": policy.ReasonNoMatchingRule})
	in := inputFor(gate, ObjectiveFixedOrder, offerFor("alpha", 0, 1, testModel))
	in.Seed = deriveSeed(t, "req-empty", testPolicyVer)

	plan, err := NewPlanner().Plan(ctx, chain, in)
	if !errors.Is(err, ErrNoEligibleCandidate) {
		t.Fatalf("应报「没有可执行候选」，实际 %v", err)
	}
	var pe *PlanError
	if !errors.As(err, &pe) {
		t.Fatalf("错误应是 *PlanError 以携带解释，实际 %T", err)
	}
	if pe.Reason != policy.ReasonNoCandidate {
		t.Errorf("主因 = %s，应为 no_candidate", pe.Reason)
	}
	if r, ok := rejectionOf(policy.RoutingPlan{Rejections: pe.Rejections}, "alpha"); !ok || r != policy.ReasonNoMatchingRule {
		t.Errorf("错误里应带上每个候选的排除码，实际 %+v", pe.Rejections)
	}
	if plan.Executor != "" || len(plan.Fallbacks) != 0 {
		t.Errorf("失败时不能半出一份计划: %+v", plan)
	}
	if !strings.Contains(err.Error(), "alpha=") {
		t.Errorf("错误信息应能自解释（含 provider 与码），实际 %q", err.Error())
	}
}

// §6：过期路径。TTL 到点必须拒绝继续执行，否则策略回滚传不下去。
func TestPlanExpiry(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder, offerFor("alpha", 0, 1, testModel))
	plan := planWithSeed(t, ctx, chain, in, deriveSeed(t, "req-ttl", testPolicyVer))

	if err := CheckFresh(plan, testNow.Add(testTTL-1)); err != nil {
		t.Errorf("TTL 内不该判过期: %v", err)
	}
	if err := CheckFresh(plan, testNow.Add(testTTL)); !errors.Is(err, ErrPlanStale) {
		t.Errorf("到点应判过期，实际 %v", err)
	}
	if err := plan.Validate(testNow.Add(testTTL)); !errors.Is(err, policy.ErrPlanExpired) {
		t.Errorf("policy 层的时效校验也应失败，实际 %v", err)
	}
	// 计划仍然把失效点带在身上，审计和缓存层才有依据。
	if !plan.Expired(testNow.Add(testTTL)) {
		t.Errorf("Expired 应报告已过期")
	}
}

// 输入不合法的每一种形态都必须被拒（而不是静默放行或静默改用别的口径）。
func TestInputValidationRejectsBadInputs(t *testing.T) {
	okCtx := ctxFor(t, policy.LevelInternal)
	okChain := orgChain(t)
	base := func() Input {
		return inputFor(&allowAllGate{}, ObjectiveFixedOrder, offerFor("alpha", 0, 1, testModel))
	}
	cases := []struct {
		name  string
		setup func(*Input, *policy.PolicyContext)
		want  string
	}{
		{"缺权限门", func(in *Input, _ *policy.PolicyContext) { in.Gate = nil }, "权限门"},
		{"范围集合为空", func(in *Input, _ *policy.PolicyContext) {}, "范围集合"},
		{"没传时间", func(in *Input, _ *policy.PolicyContext) { in.Now = time.Time{} }, "Now"},
		{"TTL 非正", func(in *Input, _ *policy.PolicyContext) { in.TTL = 0 }, "TTL"},
		{"重试预算为负", func(in *Input, _ *policy.PolicyContext) { in.MaxRetries = -1 }, "max_retries"},
		{"没有版本", func(in *Input, c *policy.PolicyContext) { in.PolicyVersion = ""; c.PolicyVersion = "" }, "policy_version"},
		{"既无 seed 也无随机源", func(in *Input, _ *policy.PolicyContext) { in.Seed = ""; in.Source = nil }, "随机源"},
		{"seed 格式不对", func(in *Input, _ *policy.PolicyContext) { in.Seed = "abc" }, "routing_seed"},
		{"候选池为空", func(in *Input, _ *policy.PolicyContext) { in.Offers = nil }, "候选池为空"},
		{"同一 provider 重复", func(in *Input, _ *policy.PolicyContext) {
			in.Offers = Offers{offerFor("alpha", 0, 1, testModel), offerFor("alpha", 0, 2, testModel)}
		}, "出现多次"},
		{"同一 provider 两个档", func(in *Input, _ *policy.PolicyContext) {
			in.Offers = Offers{offerFor("alpha", 0, 1, testModel), offerFor("alpha", 2, 1, "other")}
		}, "两个档"},
		{"负权重", func(in *Input, _ *policy.PolicyContext) {
			in.Offers = Offers{offerFor("alpha", 0, -1, testModel)}
		}, "权重"},
		{"未知目标函数", func(in *Input, _ *policy.PolicyContext) { in.Objective = "smartest" }, "目标函数"},
		{"没写要求模型", func(in *Input, _ *policy.PolicyContext) { in.Requirement.Model = "" }, "model"},
		{"分级未判定", func(in *Input, c *policy.PolicyContext) { c.DataLevel = policy.LevelUnknown }, "策略上下文"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := okCtx
			in := base()
			tc.setup(&in, &ctx)
			chain := okChain
			if tc.name == "范围集合为空" {
				chain = policy.ScopeChain{}
			}
			_, err := NewPlanner().Plan(ctx, chain, in)
			if err == nil {
				t.Fatalf("%s 竟然规划成功", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("错误信息应含 %q，实际 %q", tc.want, err.Error())
			}
		})
	}
}

// 未显式给 seed 时走调用方注入的源：线上分布不变，且只消耗一个随机数。
func TestOnlineModeUsesInjectedSource(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	src := newScripted(t, 0.9)
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder,
		offerFor("alpha", 0, 3, testModel),
		offerFor("beta", 0, 1, testModel),
	)
	in.Source = src
	plan, err := NewPlanner().Plan(ctx, chain, in)
	if err != nil {
		t.Fatalf("规划失败: %v", err)
	}
	if src.calls != 1 {
		t.Errorf("一次选路应只消耗 1 个随机数（与现网同），实际 %d", src.calls)
	}
	// 0.9*4 = 3.6 → 越过 alpha 的 3 → 落在 beta。
	if got := joinOrder(plan); !strings.HasPrefix(got, "beta") {
		t.Errorf("抽样结论应为 beta 首选，实际 %s", got)
	}
	if !hasReason(plan, policy.ReasonWeightedChoice) {
		t.Errorf("权重随机应留下 weighted_choice 解释码，实际 %v", plan.ReasonCodes)
	}
	if plan.RoutingSeed != "" {
		t.Errorf("未派生 seed 时计划里的 seed 字段应保持为空，实际 %q", plan.RoutingSeed)
	}
}

// §2.8：粘性命中优先于随机，且命中时**不消耗随机数**。
//
// 脚本里没有可用数字：多消耗一个就直接 panic。
func TestStickyHitConsumesNoRandomness(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	for _, obj := range []Objective{ObjectiveFixedOrder, ObjectiveCheapest, ObjectiveFastest} {
		src := newScripted(t)
		in := inputFor(&allowAllGate{}, obj,
			offerFor("alpha", 0, 1, testModel),
			offerFor("beta", 0, 1, testModel).withCost(0.5, 0.5),
			offerFor("gamma", 0, 1, testModel).withLatency(1),
		)
		in.Source = src
		in.Sticky = &StickyState{Provider: "alpha"}
		plan, err := NewPlanner().Plan(ctx, chain, in)
		if err != nil {
			t.Fatalf("%s 下规划失败: %v", obj, err)
		}
		if c, _ := plan.Primary(); c.Provider != "alpha" {
			t.Errorf("%s 下粘不住 alpha，实际首选 %s", obj, c.Provider)
		}
		if src.calls != 0 {
			t.Errorf("%s 下粘性命中却消耗了 %d 个随机数", obj, src.calls)
		}
		if !hasReason(plan, policy.ReasonAffinityHit) {
			t.Errorf("%s 下缺少 affinity_hit 解释码: %v", obj, plan.ReasonCodes)
		}
	}
}

// 冷却/不健康的那家不粘（现网语义：后端不能用就换家），此时才消耗随机数。
func TestStickyDriftsWhenPreferredIsUnavailable(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	cases := map[string]Offer{
		"冷却中": offerFor("beta", 0, 1, testModel).cooling(testNow.Add(time.Minute)),
		"不健康": offerFor("beta", 0, 1, testModel).unhealthy(),
	}
	for name, cold := range cases {
		src := newScripted(t, 0.5)
		in := inputFor(&allowAllGate{}, ObjectiveFixedOrder,
			offerFor("alpha", 0, 1, testModel),
			cold,
		)
		in.Source = src
		in.Sticky = &StickyState{Provider: "beta"}
		plan, err := NewPlanner().Plan(ctx, chain, in)
		if err != nil {
			t.Fatalf("%s 用例规划失败: %v", name, err)
		}
		if c, _ := plan.Primary(); c.Provider != "alpha" {
			t.Errorf("%s：不该硬粘住不可用的那家，实际 %s", name, c.Provider)
		}
		if src.calls != 1 {
			t.Errorf("%s：未命中粘性时应回落到权重随机，实际消耗 %d 个随机数", name, src.calls)
		}
		if hasReason(plan, policy.ReasonAffinityHit) {
			t.Errorf("%s：没粘住却记了 affinity_hit", name)
		}
	}
}

// 粘性不能跨档：档序承载的是「点名声明优先于通配」这类硬规则，
// 粘性是「在这批合法候选里挑哪一家」，不是绕过候选规则的旁路（与现网同形）。
func TestStickyDoesNotCrossTiers(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	src := newScripted(t, 0.5)
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder,
		offerFor("alpha", 0, 1, testModel),
		offerFor("beta", 1, 1, wildcardModel),
	)
	in.Source = src
	in.Sticky = &StickyState{Provider: "beta"}
	plan, err := NewPlanner().Plan(ctx, chain, in)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := plan.Primary(); c.Provider != "alpha" {
		t.Errorf("粘性别家不能让低优先档上位，实际首选 %s", c.Provider)
	}
	// beta 仍在 fallback 链里：它是合法候选，只是这次没轮到。
	if !containsProviderName(plan, "beta") {
		t.Errorf("低一档的合法候选应留在 fallback 链里: %s", joinOrder(plan))
	}
}

// 粘性过期后不再生效。
func TestStickyExpiry(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	src := newScripted(t, 0.1)
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder,
		offerFor("alpha", 0, 1, testModel),
		offerFor("beta", 0, 1, testModel),
	)
	in.Source = src
	in.Sticky = &StickyState{Provider: "beta", ExpiresAt: testNow.Add(-time.Second)}
	plan, err := NewPlanner().Plan(ctx, chain, in)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := plan.Primary(); c.Provider != "alpha" {
		t.Errorf("过期粘性不该再生效，实际 %s", c.Provider)
	}
}

// fallback 链的构造规则：同档剩余按权重降序、同权重按 provider id 升序，然后接下一档。
func TestFallbackOrderingWithinAndAcrossTiers(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	src := newScripted(t, 0.99) // 落在 tier0 的最后一位 → 由它当首选
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder,
		offerFor("zeta", 0, 5, testModel),
		offerFor("alpha", 0, 5, testModel),
		offerFor("mid", 0, 2, testModel),
		offerFor("beta", 1, 9, testModel),
		offerFor("gamma", 2, 1, testModel),
	)
	in.Source = src
	plan, err := NewPlanner().Plan(ctx, chain, in)
	if err != nil {
		t.Fatal(err)
	}
	// tier0 的抽样池按 id 升序是 [alpha(5) mid(2) zeta(5)]，total=12，
	// x = 0.99*12 = 11.88 → 越过 alpha、mid 的累积值 → 命中 zeta。
	// 尾巴：同档剩余按权重降序、同权重按 id 升序 → alpha(5) 先于 mid(2)；然后 tier1、tier2。
	want := []string{"zeta", "alpha", "mid", "beta", "gamma"}
	if got := orderOf(plan); !reflect.DeepEqual(got, want) {
		t.Fatalf("fallback 顺序不对: %v，应为 %v", got, want)
	}
}

// 未配置的权重按 1 处理（现网同形），并且计划里写出的是真正生效的那个值。
func TestEffectiveWeightIsNormalizedAndRecorded(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder,
		offerFor("alpha", 0, 0, testModel),
		offerFor("beta", 0, 2, testModel),
	)
	plan := planWithSeed(t, ctx, chain, in, deriveSeed(t, "req-weight", testPolicyVer))
	for _, c := range plan.Fallbacks {
		if c.Weight <= 0 {
			t.Errorf("%s 的权重写成了 %v，计划里的权重必须是生效值", c.Provider, c.Weight)
		}
	}
	if plan.Fallbacks[0].Weight == plan.Fallbacks[1].Weight {
		t.Errorf("两家权重被抹平了: %+v", plan.Fallbacks)
	}
}

// D 不得改动调用方的切片：纯函数包含「不污染输入」。
func TestPlanDoesNotMutateInput(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	offers := Offers{
		offerFor("beta", 1, 1, testModel),
		offerFor("alpha", 0, 3, testModel),
	}
	before := append(Offers(nil), offers...)
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder, offers...)
	in.ProcessorChain = []string{"redact"}
	_ = planWithSeed(t, ctx, chain, in, deriveSeed(t, "req-mutate", testPolicyVer))

	if !reflect.DeepEqual(before, offers) {
		t.Errorf("候选切片被改动了:\n before %+v\n after  %+v", before, offers)
	}
	if !reflect.DeepEqual(in.ProcessorChain, []string{"redact"}) {
		t.Errorf("处理器链被改动: %v", in.ProcessorChain)
	}
}

// 处理器链由策略侧决定，D 只原样带过去（§3.D 边界：D 不新增/删改处理器）。
func TestProcessorChainIsEchoed(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder, offerFor("alpha", 0, 1, testModel))
	in.ProcessorChain = []string{"detect-level", "redact"}
	plan := planWithSeed(t, ctx, chain, in, deriveSeed(t, "req-chain", testPolicyVer))
	if !reflect.DeepEqual(plan.ProcessorChain, []string{"detect-level", "redact"}) {
		t.Errorf("处理器链被改动: %v", plan.ProcessorChain)
	}
	blob, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), `"processor_chain":["detect-level","redact"]`) {
		t.Errorf("处理器链没进序列化结果: %s", blob)
	}
}

// 尝试次数由计划自己表达，执行器不必再算一套（也超不过候选数）。
func TestAttemptsBoundedByCandidates(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder,
		offerFor("alpha", 0, 1, testModel),
		offerFor("beta", 0, 1, testModel),
	)
	in.MaxRetries = 10
	plan := planWithSeed(t, ctx, chain, in, deriveSeed(t, "req-attempts", testPolicyVer))
	if plan.MaxRetries != 10 {
		t.Errorf("预算应原样记录，实际 %d", plan.MaxRetries)
	}
	if got := plan.Attempts(); got != 2 {
		t.Errorf("只有两个候选时尝试次数应为 2，实际 %d", got)
	}
}

// DoD 4：并发复用同一个 Planner。Planner 没有字段，这条跑的就是「状态真的外置了」。
func TestConcurrentPlanningIsStable(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	seed := deriveSeed(t, "req-concurrent", testPolicyVer)
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder,
		offerFor("alpha", 0, 3, testModel),
		offerFor("beta", 0, 1, testModel),
		offerFor("gamma", 1, 2, testModel),
	)
	planner := NewPlanner()
	const workers = 16
	done := make(chan string, workers)
	for i := 0; i < workers; i++ {
		go func() {
			local := in
			local.Seed = seed
			plan, err := planner.Plan(ctx, chain, local)
			if err != nil {
				t.Errorf("并发规划失败: %v", err)
				done <- ""
				return
			}
			done <- mustDigest(t, plan)
		}()
	}
	want := ""
	for i := 0; i < workers; i++ {
		got := <-done
		if want == "" {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("并发下第 %d 个 goroutine 得到了不同计划: %s vs %s", i, got, want)
		}
	}
}

// 候选池摘要要能进在线记录（§2.8），且与传入顺序无关。
func TestCandidatesDigestIsOrderIndependent(t *testing.T) {
	a := Offers{offerFor("alpha", 0, 1, testModel), offerFor("beta", 1, 2, testModel)}
	b := Offers{offerFor("beta", 1, 2, testModel), offerFor("alpha", 0, 1, testModel)}
	da, err := a.CandidatesDigest()
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.CandidatesDigest()
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Errorf("候选摘要受传入顺序影响: %s vs %s", da, db)
	}
}

// §2.8「不得依赖 map 遍历顺序」的正向证明：候选池的**传入顺序**不影响计划。
//
// 为什么单独测而不满足于上面那条摘要测试：现网 bucketize 的入参来自
// config 里的 map 遍历，顺序由 runtime 决定，线上只会看到其中一种顺序。
// D 只要在任一环节漏掉「先按稳定 provider ID 排好」，换个传入顺序就会换首选 ——
// 那种缺陷在线上表现为「一切正常」，只在半夜的机器上复现。
// 三个目标函数都要过：fixed-order 的抽样池、cheapest/fastest 的全序都依赖排序键，
// 而 Digest 看不出首选顺序（它先把 Fallbacks 排好），所以顺序要单独比。
func TestPlanIsIndependentOfOfferInputOrder(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	seed := deriveSeed(t, "req-input-order", testPolicyVer)

	pool := Offers{
		offerFor("zeta", 0, 2, testModel).withCost(0.004, 0.001).withLatency(30),
		offerFor("alpha", 0, 2, testModel).withCost(0.001, 0.001).withLatency(90),
		offerFor("mid", 0, 3, testModel).withCost(0.002, 0.002).withLatency(30),
		// beta 在更低的档但最便宜也最快：它绝不该因为「传得靠前」就占首选位。
		offerFor("beta", 1, 5, testModel).withCost(0.0005, 0.0005).withLatency(10),
		offerFor("gamma", 1, 1, testModel).withCost(0.003, 0.003).withLatency(0),
	}
	permutations := []struct {
		name  string
		order []int
	}{
		{"原序", []int{0, 1, 2, 3, 4}},
		{"倒序", []int{4, 3, 2, 1, 0}},
		{"错位", []int{2, 4, 0, 3, 1}},
	}

	for _, objective := range []Objective{ObjectiveFixedOrder, ObjectiveCheapest, ObjectiveFastest} {
		wantDigest, wantOrder := "", ""
		for _, p := range permutations {
			in := inputFor(&allowAllGate{}, objective, permuteOffers(pool, p.order)...)
			in.ProcessorChain = []string{"redact"}
			plan := planWithSeed(t, ctx, chain, in, seed)
			gotDigest, gotOrder := mustDigest(t, plan), joinOrder(plan)
			if wantDigest == "" {
				wantDigest, wantOrder = gotDigest, gotOrder
				continue
			}
			if gotDigest != wantDigest || gotOrder != wantOrder {
				t.Errorf("%s 目标下候选按%s传入时计划变了:\n  基准顺序 %s\n  本次顺序 %s",
					objective, p.name, wantOrder, gotOrder)
			}
		}
	}
}

func permuteOffers(os Offers, order []int) Offers {
	out := make(Offers, 0, len(order))
	for _, i := range order {
		out = append(out, os[i])
	}
	return out
}
