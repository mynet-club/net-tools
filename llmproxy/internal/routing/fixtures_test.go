package routing

import (
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// testNow 是所有用例的时间基准。D 一律不读时钟（包注释里那条），
// 所以测试里每个 Now 都必须显式传；用它而不是 time.Now 才能钉住 TTL 与冷却。
var testNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

const (
	testModel     = "gpt-5-mini"
	testPolicyVer = "core@1"
	testTTL       = 5 * time.Minute
)

// ---------- gate 替身 ----------

// stubGate 是权限门的测试替身。
//
// 它刻意记录**问过的顺序与次数**：D 声称「每个候选都问过 gate」，
// 那这条断言就得有人盯着，否则把 gate 换成「只问首选」也不会变红。
type stubGate struct {
	deny   map[string]policy.Reason
	asks   []string
	allowR policy.Reason
}

func newStubGate(deny map[string]policy.Reason) *stubGate {
	return &stubGate{deny: deny, allowR: policy.ReasonExplicitAllow}
}

// allowAllGate 是什么都不拒的 gate。仅用于「权限不是本次变量」的用例；
// 生产代码里没有它，D 也不接受 nil Gate（见 Input.Validate）。
//
// 它**刻意不带任何计数字段**：TestConcurrentPlanningIsStable 让 16 个 goroutine 共用
// 同一个实例，替身里放一个裸计数器会在 -race 下报成数据竞争 —— 报的是替身自己，
// 而那条用例要证明的是「Planner 没有共享可变状态」。替身制造假警报，等于教会后来人
// 忽略 -race 的输出。「每个候选都问过 gate」这条契约由带计数的 stubGate 盯着
// （见 TestExclusionReasonCodesAreVerifiable），它只在单 goroutine 用例里用。
type allowAllGate struct{}

func (g *allowAllGate) Allows(policy.PolicyContext, policy.ScopeChain, Offer, time.Time) (bool, policy.Reason) {
	return true, policy.ReasonDefaultAllow
}

func (g *stubGate) Allows(_ policy.PolicyContext, _ policy.ScopeChain, offer Offer, _ time.Time) (bool, policy.Reason) {
	g.asks = append(g.asks, offer.provider())
	if r, ok := g.deny[offer.provider()]; ok {
		return false, r
	}
	return true, g.allowR
}

func (g *stubGate) asked(provider string) bool {
	for _, p := range g.asks {
		if p == provider {
			return true
		}
	}
	return false
}

// ---------- 随机源替身 ----------

// scriptedSource 按脚本吐数，并记录被调用了几次。
//
// 「粘性命中时不消耗随机数」这条契约只能靠计数来证明，所以计数必须是显式的：
// 取完脚本就 panic，避免用例悄悄拿到一串 0（0 会让累积扫描永远命中池首，
// 于是「随机没生效」看起来像「随机生效了」）。
type scriptedSource struct {
	values []float64
	calls  int
	t      *testing.T
}

func newScripted(t *testing.T, values ...float64) *scriptedSource {
	t.Helper()
	return &scriptedSource{values: values, t: t}
}

func (s *scriptedSource) Float64() float64 {
	s.calls++
	if s.calls > len(s.values) {
		s.t.Fatalf("随机源被调用 %d 次，脚本只有 %d 个数：抽样次数也必须是被断言的行为", s.calls, len(s.values))
	}
	v := s.values[s.calls-1]
	if v < 0 || v >= 1 {
		s.t.Fatalf("脚本值 %v 不在 [0,1)，与 RandomSource 契约不符", v)
	}
	return v
}

// ---------- 候选与输入构造 ----------

// offerFor 构造一条最小可用的候选：健康、无冷却、有价目、承接 testModel。
// 其余事实一律用链式 with* 补，让每个用例只写出它与众不同的那一维。
func offerFor(provider string, tier int, weight float64, declared ...string) Offer {
	return Offer{
		Candidate: policy.RouteCandidate{
			Executor:      "http",
			Provider:      provider,
			Model:         testModel,
			UpstreamModel: provider + "-up",
			Weight:        weight,
			MaxDataLevel:  policy.LevelRestricted,
		},
		Tier:           tier,
		Healthy:        true,
		CostPer1KIn:    0.001,
		CostPer1KOut:   0.002,
		CostKnown:      true,
		DeclaredModels: declared,
		Capabilities:   []string{CapabilityStreaming},
	}
}

func (o Offer) withUpstream(name string) Offer {
	n := o
	n.Candidate.UpstreamModel = name
	return n
}

func (o Offer) withRegion(r string) Offer {
	n := o
	n.Candidate.Region = r
	return n
}

func (o Offer) withLevel(l policy.DataLevel) Offer {
	n := o
	n.Candidate.MaxDataLevel = l
	return n
}

func (o Offer) withCost(in, out float64) Offer {
	n := o
	n.CostPer1KIn, n.CostPer1KOut, n.CostKnown = in, out, true
	return n
}

func (o Offer) withUnknownCost() Offer {
	n := o
	n.CostPer1KIn, n.CostPer1KOut, n.CostKnown = 0, 0, false
	return n
}

func (o Offer) withLatency(ms int64) Offer {
	n := o
	n.ObservedLatencyMs = ms
	return n
}

func (o Offer) unhealthy() Offer {
	n := o
	n.Healthy = false
	return n
}

func (o Offer) cooling(until time.Time) Offer {
	n := o
	n.CooldownUntil = until
	return n
}

func (o Offer) withCapabilities(caps ...string) Offer {
	n := o
	n.Capabilities = caps
	return n
}

// ctxFor 构造一个能过 policy 校验的上下文。区域白名单为空 = 不做区域限制
// （policy 的显式约定），要测区域排除时用 withRegions 覆盖。
func ctxFor(t *testing.T, level policy.DataLevel) policy.PolicyContext {
	t.Helper()
	ctx, err := policy.NewPolicyContext(
		policy.Identity{Subject: "alice", Source: "oidc"},
		"qa",
		level,
	)
	if err != nil {
		t.Fatalf("构造上下文失败: %v", err)
	}
	ctx.PolicyVersion = testPolicyVer
	return ctx
}

func ctxWithRegions(t *testing.T, level policy.DataLevel, regions ...string) policy.PolicyContext {
	t.Helper()
	ctx := ctxFor(t, level)
	ctx.AllowedRegions = regions
	return ctx
}

func orgChain(t *testing.T) policy.ScopeChain {
	t.Helper()
	return policy.MustScopeChain(
		policy.MustScope(policy.ScopeUser, "alice"),
		policy.MustScope(policy.ScopeOrganization, "university"),
	)
}

// inputFor 组装规划的公共外壳：TTL 与时间固定，目标函数由用例给。
// Gate 由用例给替身或真实策略门；seed 与注入源都不给 ——
// 必须显式选一种，选错就该报错而不是静默。
func inputFor(gate Gate, objective Objective, offers ...Offer) Input {
	return Input{
		Offers:        offers,
		Gate:          gate,
		Requirement:   Requirement{Model: testModel},
		MaxRetries:    2,
		Objective:     objective,
		Now:           testNow,
		TTL:           testTTL,
		PolicyVersion: testPolicyVer,
	}
}

// planWithSeed 用确定性 seed 规划一次，返回计划。
func planWithSeed(t *testing.T, ctx policy.PolicyContext, chain policy.ScopeChain, in Input, seed string) policy.RoutingPlan {
	t.Helper()
	in.Seed = seed
	plan, err := NewPlanner().Plan(ctx, chain, in)
	if err != nil {
		t.Fatalf("规划失败: %v", err)
	}
	return plan
}

// deriveSeed 走 policy 的派生函数（口径不在 D 里，见 §2.8）。
func deriveSeed(t *testing.T, requestID, policyVersion string) string {
	t.Helper()
	seed, err := policy.DeriveRoutingSeed(requestID, policyVersion, "epoch-1")
	if err != nil {
		t.Fatalf("派生 seed 失败: %v", err)
	}
	return seed
}

// mustDigest 取计划摘要，失败即结束用例。
func mustDigest(t *testing.T, plan policy.RoutingPlan) string {
	t.Helper()
	d, err := plan.Digest()
	if err != nil {
		t.Fatalf("计划摘要失败: %v", err)
	}
	return d
}

// orderOf 按实际顺序取出候选 provider（不参与排序），断言 fallback 链时用。
func orderOf(plan policy.RoutingPlan) []string {
	out := make([]string, 0, len(plan.Fallbacks))
	for _, c := range plan.Fallbacks {
		out = append(out, c.Provider)
	}
	return out
}

func joinOrder(plan policy.RoutingPlan) string { return strings.Join(orderOf(plan), ",") }

// rejectionOf 取某 provider 的排除码；没有排除记录返回 false。
func rejectionOf(plan policy.RoutingPlan, provider string) (policy.Reason, bool) {
	for _, r := range plan.Rejections {
		if r.Provider == provider {
			return r.Reason, true
		}
	}
	return "", false
}

func containsProviderName(plan policy.RoutingPlan, provider string) bool {
	for _, c := range plan.Fallbacks {
		if c.Provider == provider {
			return true
		}
	}
	return false
}

func hasReason(plan policy.RoutingPlan, r policy.Reason) bool {
	for _, got := range plan.ReasonCodes {
		if got == r {
			return true
		}
	}
	return false
}
