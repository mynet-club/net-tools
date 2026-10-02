package routing

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// policyGate 是**接线方应提供的 Gate 实现形态**：判定全部发生在真实 policy.Resolver 里，
// D 只消费结论。交付说明要求「权限判定不由 D 决定，注入 Gate 由调用方基于 policy.Resolver
// 实现」，这条接缝必须对着真内核钉住形状 —— 只用替身的话，接线方换一个实现就可能少问一次、
// 或把 deny 翻译成放行，而 D 的测试照样全绿。
//
// 判定口径的三处刻意选择：
//  1. 资源写成 `<NamespaceModel>:<候选模型名>`、动作为 ActionUse —— 与 internal/replay
//     的候选授权复查同一口径（那边也是 `policy.NamespaceModel + ":" + c.Model`）。
//     两处不一致会让「在线判定」和「回放判定」对同一次请求给出不同结论；
//  2. 再问一次 `<NamespaceModel>:<上游部署名>`：同一次请求的所有候选共享下游模型名，
//     只有上游部署名能把 deny 精确点到某一家。两个名字都落在 model 命名空间内，
//     不需要为策略新增词汇（provider: 命名空间要 §2.4 的主线评审，D 这边不能自己造）；
//  3. 版本对不上就 fail-closed（Gate 契约第 3 条），见 Allows 里的说明。
type policyGate struct {
	resolver *policy.Resolver
	// asks 记录问过哪几家。本文件所有用例都在单个 goroutine 里跑；
	// 需要并发复用的用例请用无状态替身（见 allowAllGate 上的说明），
	// 否则替身自己的计数会在 -race 里冒充成 D 的竞争。
	asks []string
}

// modelResource 把模型名/部署名拼成策略资源标识（§2.4 的 `<命名空间>:<标识>` 形式）。
func modelResource(name string) string { return policy.NamespaceModel + ":" + name }

func (g *policyGate) Allows(ctx policy.PolicyContext, chain policy.ScopeChain, offer Offer, now time.Time) (bool, policy.Reason) {
	g.asks = append(g.asks, offer.provider())
	// 契约 3：内核所用的策略版本必须与计划上要写的版本是同一个真相。
	// 对不上时宁可全部拒绝，也不产出「审计写着 v1、结论出自 v2」的计划 ——
	// 那种计划会让 §3.0 要求的按 scope 回滚彻底失效（回滚判定看的正是版本串）。
	if ctx.PolicyVersion != g.resolver.Version() {
		return false, policy.ReasonPolicyVersionMissing
	}
	modelDecision := g.resolver.Evaluate(ctx, chain, modelResource(offer.Candidate.Model), policy.ActionUse, now)
	if !modelDecision.Allowed {
		return false, modelDecision.Reason
	}
	// 上游部署名与模型名相同时不必重复问（Evaluate 是纯函数，但重复问会虚增计数，
	// 而「每个候选恰好问过」是本包要断言的行为）。
	if upstream := modelResource(offer.Candidate.UpstreamModel); upstream != modelResource(offer.Candidate.Model) {
		deployment := g.resolver.Evaluate(ctx, chain, upstream, policy.ActionUse, now)
		if !deployment.Allowed {
			return false, deployment.Reason
		}
	}
	return true, modelDecision.Reason
}

// asked 报告这家是否被问过（断言「逐个候选都问权限门」）。
func (g *policyGate) asked(provider string) bool {
	for _, p := range g.asks {
		if p == provider {
			return true
		}
	}
	return false
}

// askedEachOnce 报告询问记录是否恰好是「每家一次」：多问说明 D 在抽样之外还偷问了
// 第二次（会把 gate 的判定次数变成与候选数无关的量），少问说明有人被跳过。
func (g *policyGate) askedEachOnce(offers Offers) bool {
	seen := make(map[string]int, len(offers))
	for _, p := range g.asks {
		seen[p]++
	}
	for _, o := range offers {
		if seen[o.provider()] != 1 {
			return false
		}
	}
	return len(g.asks) == len(offers)
}

// ---------- 真实策略内核的构造（规则字面量内联，不借其他包的测试辅助） ----------

func allowEnt(subject, resource string) policy.Entitlement {
	return policy.Entitlement{
		Subject:  subject,
		Resource: resource,
		Action:   policy.ActionUse,
		Effect:   policy.EffectAllow,
		Source:   "gate-policy-test",
	}
}

func denyEnt(subject, resource, scope string) policy.Entitlement {
	return policy.Entitlement{
		Subject:  subject,
		Scope:    scope,
		Resource: resource,
		Action:   policy.ActionUse,
		Effect:   policy.EffectDeny,
		Source:   "gate-policy-test",
	}
}

func bundleOf(id string, version int, scope policy.ScopeRef, rules ...policy.Entitlement) policy.PolicyBundle {
	return policy.PolicyBundle{ID: id, Version: version, Scope: scope, Entitlements: rules}
}

// gateResolver 用真实策略包构造内核：版本串取自 BundleSet.Filter(chain).PolicyVersion()，
// 不由 handler 拼接（§3.0）。这条链路只有在这里被真实走一遍，才能证明
// RoutingPlan.PolicyVersion 与真正生效的规则内容是同出一份。
func gateResolver(t *testing.T, bundles ...policy.PolicyBundle) *policy.Resolver {
	t.Helper()
	set := policy.MustBundleSet(bundles...)
	resolver, err := policy.FromBundles(set, orgChain(t))
	if err != nil {
		t.Fatalf("构造策略内核失败: %v", err)
	}
	if resolver.RuleCount() == 0 {
		t.Fatal("策略内核一条规则都没有，这条用例等于什么都没判")
	}
	return resolver
}

// gateOffers 给出三条便宜程度不同的候选（同一档、同权重、都承接 testModel）。
// beta 最便宜：这样「策略拒绝的候选即使最便宜也不入选」这条断言才有牙齿 ——
// 如果 deny 只挡住一个本来就不占先的候选，绕过权限的回归也能混过去。
func gateOffers() Offers {
	return Offers{
		offerFor("alpha", 0, 1, testModel).withCost(0.002, 0.001),
		offerFor("beta", 0, 1, testModel).withCost(0.0005, 0.0005),
		offerFor("gamma", 0, 1, testModel).withCost(0.004, 0.001),
	}
}

// gateInputFor 组装输入：版本取真实内核的 Version()，seed 由它派生（§2.8 版本进 seed）。
func gateInputFor(t *testing.T, gate Gate, version string, objective Objective, requestID string, offers Offers) (policy.PolicyContext, policy.ScopeChain, Input) {
	t.Helper()
	ctx := ctxFor(t, policy.LevelInternal)
	ctx.PolicyVersion = version
	in := inputFor(gate, objective, offers...)
	in.RequestID = requestID
	in.PolicyVersion = version
	in.Seed = deriveSeed(t, requestID, version)
	return ctx, orgChain(t), in
}

// TestRealPolicyGateDeniesCheapestCandidate 是 §6「fallback 不绕过权限」的真实策略版：
// 被 deny 的候选即使成本最优，也既不占首选、也不出现在备选链里，而在 Rejections 里
// 带着策略内核自己的原因码（model_not_allowed），运维一眼看得出是策略挡的不是价格。
func TestRealPolicyGateDeniesCheapestCandidate(t *testing.T) {
	resolver := gateResolver(t,
		bundleOf("model-grants", 1, policy.SystemScope, allowEnt("*", "model:*")),
		bundleOf("uni-deployment-deny", 1, policy.MustScope(policy.ScopeOrganization, "university"),
			denyEnt("alice", "model:beta-up", "organization:university")),
	)
	gate := &policyGate{resolver: resolver}
	offers := gateOffers()
	ctx, chain, in := gateInputFor(t, gate, resolver.Version(), ObjectiveCheapest, "req-gate-deny", offers)

	plan, err := NewPlanner().Plan(ctx, chain, in)
	if err != nil {
		t.Fatalf("规划失败: %v", err)
	}

	// beta 是三条里最便宜的（0.001 < 0.003 < 0.005）：没有策略挡着，cheapest 必选它。
	if got := joinOrder(plan); got != "alpha,gamma" {
		t.Errorf("备选链 = %s，期望 [alpha gamma]：被策略拒绝的候选混进了降级链", got)
	}
	if containsProviderName(plan, "beta") {
		t.Error("beta 出现在 Fallbacks 里：降级路径绕过了 policy resolver")
	}
	if reason, ok := rejectionOf(plan, "beta"); !ok || reason != policy.ReasonModelNotAllowed {
		t.Errorf("beta 的排除记录 = %q/%v，期望 model_not_allowed", reason, ok)
	}
	if !hasReason(plan, policy.ReasonModelNotAllowed) {
		t.Error("ReasonCodes 里看不到 model_not_allowed，审计解释不出这次拒绝")
	}
	if !hasReason(plan, policy.ReasonCheapestFirst) {
		t.Error("cheapest 的首选没有留下 cheapest_first 解释码")
	}
	// gate 必须被逐个问到：包括最终落选的 beta，也包括成本排名靠后的 gamma。
	if !gate.askedEachOnce(offers) {
		t.Errorf("gate 询问记录 = %v，期望每家恰好一次", gate.asks)
	}
	if plan.PolicyVersion != resolver.Version() {
		t.Errorf("计划版本 %q != 内核版本 %q：审计里的版本对不上真正生效的规则", plan.PolicyVersion, resolver.Version())
	}

	// 同一 seed 再跑一遍：真实策略判定路径上也必须是固定输入固定输出。
	replay, err := NewPlanner().Plan(ctx, chain, in)
	if err != nil {
		t.Fatal(err)
	}
	if mustDigest(t, plan) != mustDigest(t, replay) || joinOrder(plan) != joinOrder(replay) {
		t.Error("同一 seed 两次规划结论不同：真实 gate 路径上混进了不确定因素")
	}
}

// TestRealPolicyGateFailsClosed 覆盖两种「没有任何候选可用」的策略形态：
// 压根没配授权，以及组织级 deny 压过系统级 default allow。
//
// 两者的期望一致：不出计划、每个候选都带已注册原因码、返回值是零值计划。
// 这里刻意要求**零值计划**而不是「空备选链的计划」—— 后者会被执行器当成
// 「有模型可跑但没有备选」继续用，等于把策略拒绝悄悄降级成运行时错误。
func TestRealPolicyGateFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		rules []policy.PolicyBundle
	}{
		{
			// 只授权别的模型：这次要的 testModel 没配 allow，fail-closed 直接拒。
			name:  "没有授权规则",
			rules: []policy.PolicyBundle{bundleOf("model-grants", 1, policy.SystemScope, allowEnt("alice", "model:other-model"))},
		},
		{
			// 系统包 default allow + 组织包 deny：§2.4 的优先级里 deny 最高，
			// 这条必须传导到 D，否则「组织禁了某个模型」只挡住入口不挡住选路。
			name: "组织级 deny 压过系统级 allow",
			rules: []policy.PolicyBundle{
				bundleOf("model-grants", 1, policy.SystemScope, allowEnt("*", "model:*")),
				bundleOf("uni-ban", 1, policy.MustScope(policy.ScopeOrganization, "university"),
					denyEnt("*", "model:*", "organization:university")),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := gateResolver(t, tc.rules...)
			gate := &policyGate{resolver: resolver}
			offers := gateOffers()
			ctx, chain, in := gateInputFor(t, gate, resolver.Version(), ObjectiveCheapest, "req-gate-deny-all", offers)

			plan, err := NewPlanner().Plan(ctx, chain, in)
			if !errors.Is(err, ErrNoEligibleCandidate) {
				t.Fatalf("错误 = %v，期望 %v", err, ErrNoEligibleCandidate)
			}
			if !reflect.DeepEqual(plan, policy.RoutingPlan{}) {
				t.Errorf("出错时仍返回了非零值计划: %+v", plan)
			}
			var planErr *PlanError
			if !errors.As(err, &planErr) {
				t.Fatalf("错误类型 %T 取不到排除清单", err)
			}
			if planErr.Reason != policy.ReasonNoCandidate {
				t.Errorf("主因 = %q，期望 no_candidate", planErr.Reason)
			}
			if len(planErr.Rejections) != len(offers) {
				t.Fatalf("排除清单 %d 条，候选 %d 条：每家都该有一条解释", len(planErr.Rejections), len(offers))
			}
			for _, o := range offers {
				if reason, ok := rejectionOf(policy.RoutingPlan{Rejections: planErr.Rejections}, o.provider()); !ok {
					t.Errorf("%s 没有排除记录", o.provider())
				} else if reason != policy.ReasonModelNotAllowed {
					t.Errorf("%s 的排除码 = %q，期望 model_not_allowed（策略内核原样传出的码才可审计）", o.provider(), reason)
				}
			}
			if len(gate.asks) != len(offers) {
				t.Errorf("gate 被问 %d 次，候选 %d 家：全部拒绝时也必须逐家问", len(gate.asks), len(offers))
			}
		})
	}
}

// TestStickyCannotPinPolicyDeniedProvider 钉住「粘性不是越权通道」：
// 会话粘性钉在一家被 deny 的后端上时，它既不能被选中（那等于绕过策略出网），
// 也不能只是悄悄消失 —— 它必须带着策略原因码出现在 Rejections 里。
func TestStickyCannotPinPolicyDeniedProvider(t *testing.T) {
	resolver := gateResolver(t,
		bundleOf("model-grants", 1, policy.SystemScope, allowEnt("*", "model:*")),
		bundleOf("uni-deployment-deny", 1, policy.MustScope(policy.ScopeOrganization, "university"),
			denyEnt("alice", "model:beta-up", "organization:university")),
	)
	gate := &policyGate{resolver: resolver}
	ctx, chain, in := gateInputFor(t, gate, resolver.Version(), ObjectiveCheapest, "req-gate-sticky", gateOffers())
	// 粘性指向 beta：最便宜、会话又钉着它 —— 两个「最想用它」的理由都不该越过策略。
	in.Sticky = &StickyState{Provider: "beta", PolicyVersion: resolver.Version()}

	plan, err := NewPlanner().Plan(ctx, chain, in)
	if err != nil {
		t.Fatalf("规划失败: %v", err)
	}
	primary, _ := plan.Primary()
	if primary.Provider == "beta" {
		t.Error("粘性把被策略拒绝的后端钉回了首选位：粘性成了越权通道")
	}
	if containsProviderName(plan, "beta") {
		t.Error("beta 仍在备选链里")
	}
	if hasReason(plan, policy.ReasonAffinityHit) {
		t.Error("策略拒绝的候选却记了 affinity_hit，审计会把这次降级解释成粘性生效")
	}
	if reason, ok := rejectionOf(plan, "beta"); !ok || reason != policy.ReasonModelNotAllowed {
		t.Errorf("beta 的排除记录 = %q/%v，期望 model_not_allowed", reason, ok)
	}
}

// TestRealPolicyGateRejectsOnVersionMismatch 落在 Gate 契约第 3 条上：
// 内核已经加载了新版本，而调用方传进来的还是缓存里的旧版本串时，必须整体拒绝。
//
// 为什么值得单列一条：版本串是这份计划唯一的回滚抓手（§3.0）。
// 一旦允许「用 v2 规则出结论、往审计里写 v1」，回滚判定就永远看不出这次请求
// 其实由新策略放行 —— 而那正是「按 scope 关掉新路径」要防的事故面。
func TestRealPolicyGateRejectsOnVersionMismatch(t *testing.T) {
	resolver := gateResolver(t, bundleOf("model-grants", 1, policy.SystemScope, allowEnt("*", "model:*")))
	gate := &policyGate{resolver: resolver}
	// 故意拿一个不属于当前内核的版本串（形如 handler 用了缓存里的旧版本）。
	ctx, chain, in := gateInputFor(t, gate, "stale-bundle@1", ObjectiveFixedOrder, "req-gate-stale-ver", gateOffers())

	_, err := NewPlanner().Plan(ctx, chain, in)
	var planErr *PlanError
	if !errors.As(err, &planErr) {
		t.Fatalf("版本不一致时竟然出了计划: %v", err)
	}
	for _, rej := range planErr.Rejections {
		if rej.Reason != policy.ReasonPolicyVersionMissing {
			t.Errorf("%s 的排除码 = %q，期望 policy_version_missing", rej.Provider, rej.Reason)
		}
	}
	if len(planErr.Rejections) == 0 {
		t.Error("排除清单为空：拒绝说不出为什么就等于没拒绝")
	}
}

// TestRealPolicyGateReplayIgnoresReloadedPolicy 用真实策略包走一遍 §6 的
// 「策略版本回放一致」：v1 在线定出的计划，在策略升到 v2（并把这家彻底禁掉）之后
// 回放，结论必须与当时逐位相同；而**新的**在线请求在 v2 下出不了计划。
//
// 这条是 recordedGate 的价值所在：回放路径上没有任何一次真实的 Evaluate，
// 所以策略怎么变都改不动历史结论 —— 反之，如果 D 在回放时去问活内核，
// 这条用例就会红，而那意味着历史审计再也不能用来解释当时的行为。
func TestRealPolicyGateReplayIgnoresReloadedPolicy(t *testing.T) {
	v1 := gateResolver(t,
		bundleOf("model-grants", 1, policy.SystemScope, allowEnt("*", "model:*")),
		bundleOf("uni-deployment-deny", 1, policy.MustScope(policy.ScopeOrganization, "university"),
			denyEnt("alice", "model:beta-up", "organization:university")),
	)
	gate1 := &policyGate{resolver: v1}
	ctx, chain, in := gateInputFor(t, gate1, v1.Version(), ObjectiveCheapest, "req-gate-replay", gateOffers())

	onlinePlan, snapshot, err := NewPlanner().PlanWithReplay(ctx, chain, in)
	if err != nil {
		t.Fatalf("v1 在线规划失败: %v", err)
	}
	if snapshot.PolicyVersion != v1.Version() {
		t.Errorf("快照版本 %q != v1 版本 %q", snapshot.PolicyVersion, v1.Version())
	}

	// 同一份内容升到 v2，并且把 alpha、gamma 的部署也禁掉：今天的策略已经不放行任何东西。
	v2 := gateResolver(t,
		bundleOf("model-grants", 2, policy.SystemScope, allowEnt("*", "model:other-model")),
		bundleOf("uni-deployment-deny", 2, policy.MustScope(policy.ScopeOrganization, "university"),
			denyEnt("*", "model:*", "organization:university")),
	)
	if v2.Version() == v1.Version() {
		t.Fatal("两份策略版本串相同，这条用例没测到版本变化")
	}
	// seed 由 policyVersion 派生：版本一变 seed 就变，回放不会把新策略结论冒充旧策略。
	seedV1 := deriveSeed(t, "req-gate-replay", v1.Version())
	seedV2 := deriveSeed(t, "req-gate-replay", v2.Version())
	if seedV1 == seedV2 {
		t.Error("策略版本变了而 seed 没变：§2.8 要求的版本参与派生没生效")
	}

	// 今天重放那次请求：不问 v2，只吃快照里记下的结论。
	gate2 := &policyGate{resolver: v2}
	replayedPlan, _, err := Replay(snapshot)
	if err != nil {
		t.Fatalf("回放断言失败: %v", err)
	}
	if mustDigest(t, onlinePlan) != mustDigest(t, replayedPlan) || joinOrder(onlinePlan) != joinOrder(replayedPlan) {
		t.Errorf("回放结论与线上不同:\n  线上 %s\n  回放 %s", joinOrder(onlinePlan), joinOrder(replayedPlan))
	}
	if len(gate2.asks) != 0 {
		t.Errorf("回放期间问了活内核 %d 次，期望 0 次：回放不得依赖今天的策略", len(gate2.asks))
	}
	// 快照里记的 gate 结论就是当时那份：beta 被拒且带已注册码。
	for _, ro := range snapshot.Offers {
		if ro.Provider == "beta" {
			if ro.GateAllows || ro.GateReason != policy.ReasonModelNotAllowed {
				t.Errorf("快照把 beta 记成 %v/%q，期望 false/model_not_allowed", ro.GateAllows, ro.GateReason)
			}
		} else if !ro.GateAllows {
			t.Errorf("快照把 %s 记成拒绝，与 v1 结论不符", ro.Provider)
		}
	}

	// 同样的输入在 v2 下**现在**跑：必须出不了计划。
	ctx2, chain2, in2 := gateInputFor(t, gate2, v2.Version(), ObjectiveCheapest, "req-gate-replay", gateOffers())
	if _, err := NewPlanner().Plan(ctx2, chain2, in2); !errors.Is(err, ErrNoEligibleCandidate) {
		t.Errorf("v2 下的在线规划错误 = %v，期望 no_candidate", err)
	}
	// 回放的计划仍带历史版本与历史 TTL（版本不是「回放时重新查一遍」出来的）。
	if replayedPlan.PolicyVersion != v1.Version() {
		t.Errorf("回放计划版本 %q != v1 %q", replayedPlan.PolicyVersion, v1.Version())
	}
}
