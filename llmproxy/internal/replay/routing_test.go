package replay

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// routingCase 造一对配对的判定 + 路由记录：路由回放要靠判定记录拿范围与上下文。
type routingCase struct {
	file     File
	decision DecisionRecord
	routing  RoutingRecord
}

// poolOf 是测试策略集里 alice（学生）确实能用的模型池。
// 计划的候选必须都被策略放行，否则 candidate_grant 检查会先命中 —— 那是另一条断言在管的事。
func poolOf(indexes ...int) []policy.RouteCandidate {
	full := []policy.RouteCandidate{
		candidate("p-demo", "public-demo", 1),
		candidate("p-gpt5", "gpt-5", 3),
		candidate("p-mini", "gpt-mini", 1),
	}
	if len(indexes) == 0 {
		return full
	}
	out := make([]policy.RouteCandidate, 0, len(indexes))
	for _, i := range indexes {
		out = append(out, full[i])
	}
	return out
}

func newRoutingCase(t *testing.T, cands []policy.RouteCandidate, rejs []policy.Rejection, maxRetries int) routingCase {
	t.Helper()
	set := testBundles(t)
	chain := chainOf(t, "alice", "university", "")
	id := identityOf(t, "alice", []string{"student"}, []string{"cs"})
	ctx := ctxOf(t, id, "university", policy.LevelInternal)
	dec := captureDecision(t, set, "req-route", baseNow, chain, id, ctx, "model:gpt-mini", policy.ActionUse)

	route := routingFixture(t, "req-route", dec.PolicyVersion, baseNow, cands, rejs, maxRetries)
	return routingCase{file: NewFile([]DecisionRecord{dec}, []RoutingRecord{route}), decision: dec, routing: route}
}

func assertRoutingPassed(t *testing.T, r *Replayer, rec RoutingRecord, pair DecisionRecord, hasPair bool) {
	t.Helper()
	o := r.ReplayRouting(rec, pair, hasPair)
	if !o.Passed() {
		t.Fatalf("基线路由回放应通过:\n%s", o.String())
	}
}

func TestReplayRoutingBaselinePasses(t *testing.T) {
	c := newRoutingCase(t, poolOf(), []policy.Rejection{rejection("p-demo", policy.ReasonCandidateLevelExcluded)}, 1)
	r := newReplayer(t, testBundles(t), baseNow, false)
	assertRoutingPassed(t, r, c.routing, c.decision, true)
	report, err := r.Run(c.file)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Clean() {
		t.Fatalf("Run 也应全绿:\n%s", report.String())
	}
}

// §2.8 的分工：在线不受影响，但回放必须有显式 seed。缺 seed 一律 fail_closed。
func TestReplayRoutingRequiresSeed(t *testing.T) {
	c := newRoutingCase(t, poolOf(1, 2), nil, 0)
	r := newReplayer(t, testBundles(t), baseNow, false)

	noSeed := c.routing
	noSeed.RoutingSeed = ""
	noSeed.Plan.RoutingSeed = ""
	o := r.ReplayRouting(noSeed, c.decision, true)
	if o.Status != StatusRejected {
		t.Fatalf("缺 seed 必须拒绝回放而不是退回随机: %+v", o)
	}
	if o.Reason != policy.ReasonReplaySeedMissing {
		t.Fatalf("要给出 replay_seed_missing，实际 %s", o.Reason)
	}
	if !hasNoteContaining(o, "拒绝执行") {
		t.Fatalf("拒绝说明要写清为什么不能退回随机: %+v", o.Notes)
	}

	badSeed := c.routing
	badSeed.RoutingSeed = strings.Repeat("g", 64)
	badSeed.Plan.RoutingSeed = ""
	if err := badSeed.Validate(baseNow); err == nil {
		t.Fatal("非法 seed 的记录本身不该通过校验")
	}
	o = r.ReplayRouting(badSeed, c.decision, true)
	if o.Status != StatusRejected {
		t.Fatalf("非法 seed 也要拒绝回放: %+v", o)
	}
}

func TestReplayRoutingDetectsWrongSeedDerivation(t *testing.T) {
	c := newRoutingCase(t, poolOf(1, 2), nil, 0)
	// 改了世代号却没重新派生 seed：§2.8 的 seed 来源断言必须抓到。
	rec := c.routing
	rec.RoutingEpoch = "epoch-8"
	o := newReplayer(t, testBundles(t), baseNow, false).ReplayRouting(rec, c.decision, true)
	if o.Status != StatusMismatch {
		t.Fatalf("seed 与来源不符要暴露: %+v", o)
	}
	d := mustDiffField(t, o, "routing_seed")
	if d.Expected != c.routing.RoutingSeed || d.Actual == c.routing.RoutingSeed {
		t.Fatalf("差异要写清记录值与按 §2.8 重算的值: %+v", d)
	}
}

func TestReplayRoutingDetectsPlanOrderChange(t *testing.T) {
	c := newRoutingCase(t, poolOf(), nil, 2)
	r := newReplayer(t, testBundles(t), baseNow, false)
	original := providersOf(c.routing.Plan.Fallbacks)

	// 把计划里的尝试顺序前两位对调：首选和尝试序列都必须报差异。
	flipped := c.routing
	flipped.Plan.Fallbacks = []policy.RouteCandidate{
		c.routing.Plan.Fallbacks[1], c.routing.Plan.Fallbacks[0], c.routing.Plan.Fallbacks[2]}
	o := r.ReplayRouting(flipped, c.decision, true)
	if o.Status != StatusMismatch {
		t.Fatalf("尝试顺序被改必须暴露: %+v", o)
	}
	if mustDiffField(t, o, "plan.primary").Expected != original[0] {
		t.Fatal("plan.primary 的期望值必须是 seed 复现出来的首选")
	}
	if !hasDiffField(o, "plan.attempts/0") || !hasDiffField(o, "plan.attempts/1") {
		t.Fatalf("尝试序列要逐位比对: %+v", o.Diffs)
	}
}

func TestReplayRoutingDetectsCandidateDigestChange(t *testing.T) {
	c := newRoutingCase(t, poolOf(1, 2), nil, 0)
	r := newReplayer(t, testBundles(t), baseNow, false)

	rec := c.routing
	rec.Candidates = policy.SortCandidates(append(append([]policy.RouteCandidate(nil), c.routing.Candidates...),
		candidate("p-new", "public-demo", 1)))
	// 池子变了但摘要没重算 → 结构校验就失败（不能拿旧摘要蒙过回放）。
	o := r.ReplayRouting(rec, c.decision, true)
	if o.Status != StatusRejected {
		t.Fatalf("候选池与摘要不符要拒绝回放: %+v", o)
	}
	if !hasNoteContaining(o, "candidates_digest") {
		t.Fatalf("要说清是候选摘要问题: %+v", o.Notes)
	}

	// 池子变了、摘要也重算了，但新候选既不在计划也没有排除原因 → 仍然是结构问题。
	rec.CandidatesDigest, _ = policy.CandidatesDigest(rec.Candidates)
	if err := rec.Validate(baseNow); err == nil {
		t.Fatal("新增候选没交代时必须失败")
	} else if !strings.Contains(err.Error(), "既不在计划里也没有排除原因") {
		t.Fatalf("错误要指出候选没交代: %v", err)
	}
}

func TestReplayRoutingDetectsRejectionDrift(t *testing.T) {
	c := newRoutingCase(t, poolOf(), []policy.Rejection{rejection("p-demo", policy.ReasonCandidateUnhealthy)}, 0)
	rec := c.routing
	// 记录说候选被排除了，计划里却没有对应的排除原因：计划与记录不是同一次决策。
	rec.Plan.Rejections = nil
	o := newReplayer(t, testBundles(t), baseNow, false).ReplayRouting(rec, c.decision, true)
	if o.Status != StatusMismatch {
		t.Fatalf("排除原因不一致要暴露: %+v", o)
	}
	d := mustDiffField(t, o, "rejections_digest")
	if !strings.Contains(d.Expected, "p-demo=candidate_unhealthy") || d.Actual != "" {
		t.Fatalf("差异要给出两侧排除原因: %+v", d)
	}
}

func TestReplayRoutingRejectsUnregisteredRejectionReason(t *testing.T) {
	c := newRoutingCase(t, poolOf(1, 2), nil, 0)
	r := newReplayer(t, testBundles(t), baseNow, false)

	rec := c.routing
	rec.Rejections = sortRejections([]policy.Rejection{rejection("p-gpt5", policy.Reason("自然语言解释"))})
	if o := r.ReplayRouting(rec, c.decision, true); o.Status != StatusRejected {
		t.Fatalf("未注册原因码必须拒绝: %+v", o)
	}

	// 被排除的候选又出现在计划里：排除原因不可信。
	conflict := c.routing
	conflict.Rejections = sortRejections([]policy.Rejection{rejection("p-mini", policy.ReasonCandidateUnhealthy)})
	if o := r.ReplayRouting(conflict, c.decision, true); o.Status != StatusRejected {
		t.Fatalf("同一候选既被排除又进计划必须拒绝: %+v", o)
	}
}

// §6「fallback 不绕过权限」：计划里的每个备选模型都必须在当时的策略下站得住。
func TestReplayRoutingDetectsFallbackBypassingPolicy(t *testing.T) {
	// p-max 指向 gpt-max：university 包里有 role:student 的显式 deny。
	cands := append(poolOf(1, 2), candidate("p-max", "gpt-max", 1))
	c := newRoutingCase(t, cands, nil, 2)
	if c.decision.Effect != policy.EffectAllow {
		t.Fatalf("基线判定应放行，配对才有意义: %+v", c.decision)
	}
	o := newReplayer(t, testBundles(t), baseNow, false).ReplayRouting(c.routing, c.decision, true)
	if o.Status != StatusMismatch {
		t.Fatalf("gpt-max 对学生是 deny，作为 fallback 必须被抓到:\n%s", o.String())
	}
	d := mustDiffField(t, o, "candidate_grant/p-max")
	if !strings.Contains(d.Actual, string(policy.ReasonModelNotAllowed)) {
		t.Fatalf("差异里要带上拒绝原因码: %+v", d)
	}
}

func TestReplayRoutingWithoutPairedDecision(t *testing.T) {
	c := newRoutingCase(t, poolOf(1, 2), nil, 0)
	r := newReplayer(t, testBundles(t), baseNow, false)

	o := r.ReplayRouting(c.routing, DecisionRecord{}, false)
	if !o.Passed() {
		t.Fatalf("没有配对记录时仍应能回放选路（降级）:\n%s", o.String())
	}
	if !hasNoteContaining(o, "降级回放") {
		t.Fatalf("必须显式声明降级：没有范围集合就无法按 Filter(chain) 复核版本（§3.0）: %+v", o.Notes)
	}

	// 版本串里出现没加载过的包：拒绝。
	ghost := c.routing
	ghost.PolicyVersion = "university-default@3|system-default@1|ghost-bundle@9"
	ghost.Plan.PolicyVersion = ghost.PolicyVersion
	o = r.ReplayRouting(ghost, DecisionRecord{}, false)
	if o.Status != StatusRejected || o.Reason != policy.ReasonPolicyVersionMissing {
		t.Fatalf("未加载的包必须让版本来源校验失败: %+v", o)
	}
	if !hasNoteContaining(o, "ghost-bundle@9") {
		t.Fatalf("要指出缺哪个包: %+v", o.Notes)
	}
}

// 有配对判定记录时，版本必须按 Filter(chain) 复核（§3.0 的硬要求）。
func TestReplayRoutingVersionSourceUsesFilter(t *testing.T) {
	c := newRoutingCase(t, poolOf(1, 2), nil, 0)
	full := testBundles(t)

	// 记录是按 university 范围写的（不含 hospital-a 包），拿整集版本冒充就必须失败。
	inflated := c.routing
	inflated.PolicyVersion = newReplayer(t, full, baseNow, false).LoadedPolicyVersion()
	inflated.Plan.PolicyVersion = inflated.PolicyVersion
	o := newReplayer(t, full, baseNow, false).ReplayRouting(inflated, c.decision, true)
	if o.Status != StatusRejected || o.Reason != policy.ReasonPolicyVersionMissing {
		t.Fatalf("用整集版本冒充范围版本必须失败: %+v", o)
	}
	if !hasNoteContaining(o, "按范围") {
		t.Fatalf("要说明是 Filter(chain) 复核出来的差异: %+v", o.Notes)
	}

	// 只喂 hospital-a 的包：范围没有策略包覆盖 → 拒绝，而不是静默判 deny。
	hospitalOnly := policy.MustBundleSet(
		bundleOf("hospital-a-default", 2, policy.MustScope(policy.ScopeOrganization, "hospital-a"),
			allowRule("role:doctor", "model:private-mri", policy.ActionUse)),
	)
	o = newReplayer(t, hospitalOnly, baseNow, false).ReplayRouting(c.routing, c.decision, true)
	if o.Status != StatusRejected || o.Reason != policy.ReasonScopeMismatch {
		t.Fatalf("跨组织喂错包必须 scope_mismatch: %+v", o)
	}
}

// 抽样算法标识不一致时只能做解释性回放：不声称首选逐位相同（§2.8 对旧请求的口径）。
func TestReplayRoutingExplanatoryModeOnUnknownAlgo(t *testing.T) {
	c := newRoutingCase(t, poolOf(1, 2), nil, 1)
	rec := c.routing
	rec.SamplingAlgo = "routing-online-v1"
	o := newReplayer(t, testBundles(t), baseNow, false).ReplayRouting(rec, c.decision, true)
	if !o.Passed() {
		t.Fatalf("解释性回放仍应通过（其它项都一致）: %+v", o)
	}
	if !hasNoteContaining(o, "只做解释性回放") {
		t.Fatalf("必须声明是解释性回放: %+v", o.Notes)
	}
	if hasDiffField(o, "plan.primary") {
		t.Fatal("算法不一致时不该比对首选顺序")
	}
}

func TestReplayRoutingUsesInjectedSampler(t *testing.T) {
	c := newRoutingCase(t, poolOf(1, 2), nil, 1)
	// 主线注入 D 的实现后，同算法标识下就用注入的序列比对。
	// 故意给出与记录相反的顺序：一致时必须暴露差异，而不是静默通过。
	recorded := providersOf(c.routing.Plan.Fallbacks)
	reversed := make([]string, 0, len(recorded))
	for i := len(recorded) - 1; i >= 0; i-- {
		reversed = append(reversed, recorded[i])
	}
	if reversed[0] == recorded[0] {
		t.Skip("候选只有一个，无法构造反序")
	}
	r, err := New(testBundles(t), Options{Now: baseNow,
		Sampler: fakeSampler{algo: SamplingAlgoReplayV1, sequence: reversed}})
	if err != nil {
		t.Fatal(err)
	}
	o := r.ReplayRouting(c.routing, c.decision, true)
	if o.Status != StatusMismatch {
		t.Fatalf("注入的抽样序列与记录不符时必须暴露: %s", o.String())
	}
	if mustDiffField(t, o, "plan.primary").Expected != reversed[0] {
		t.Fatalf("首选差异要按注入序列给期望值: %+v", o.Diffs)
	}
	if r.SamplerAlgo() != SamplingAlgoReplayV1 {
		t.Fatal("回放器要报告当前抽样器标识")
	}

	// 抽样器报错时也是拒绝回放，而不是退回随机。
	broken, err := New(testBundles(t), Options{Now: baseNow,
		Sampler: fakeSampler{algo: SamplingAlgoReplayV1, err: errFake}})
	if err != nil {
		t.Fatal(err)
	}
	o = broken.ReplayRouting(c.routing, c.decision, true)
	if o.Status != StatusRejected {
		t.Fatalf("抽样失败必须拒绝回放: %+v", o)
	}
	if o.Reason != policy.ReasonReplaySeedMissing {
		t.Fatalf("抽样输入问题要落到 seed 类原因，实际 %s", o.Reason)
	}
}

func TestReplayClockIsNormalizedToUTCSeconds(t *testing.T) {
	r := newReplayer(t, testBundles(t), baseNow.Add(500*time.Millisecond).In(time.FixedZone("UTC+8", 8*3600)), false)
	if got := r.Clock(); got.Location() != time.UTC || got.Nanosecond() != 0 {
		t.Fatalf("回放时钟要归一到 UTC 秒级，实际 %s", got)
	}
	if !strings.Contains(r.LoadedPolicyVersion(), "|") {
		t.Fatalf("整集版本串应含多个策略包: %s", r.LoadedPolicyVersion())
	}
}

var errFake = errors.New("抽样器内部失败")
