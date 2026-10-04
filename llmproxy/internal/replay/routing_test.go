package replay

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/routing"
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

// P4（2026-10-04 裁决第 5 条 B）：带 replay_snapshot 的 v2 记录必须能声称逐位复现，
// 而声称的前提是快照齐全、算法可核对、快照与记录自洽 —— 三者缺一律退回解释性回放，
// 并把「为什么不能声称」写在报告里。
func TestReplayRoutingBitExactFromSnapshot(t *testing.T) {
	f := baselineFileWithSnapshot(t)
	r := newReplayer(t, testBundles(t), baseNow, false)
	report, err := r.Run(f)
	if err != nil {
		t.Fatalf("v2 记录回放失败: %v\n%s", err, report.String())
	}
	if !report.Clean() {
		t.Fatalf("D 现场算出的计划换到回放侧必须逐字段复现:\n%s", report.String())
	}
	if got := report.BitExactCount(); got != 1 {
		t.Fatalf("带完整快照的记录必须报 1 条逐位复现，实际 %d:\n%s", got, report.String())
	}
	o := routingOutcomeOf(t, report)
	if !o.BitExact {
		t.Fatalf("带完整快照的记录应标记 bit_exact: %+v", o)
	}
	if hasNoteContaining(o, "只做解释性回放") {
		t.Fatalf("这条记录有逐位凭据，报告里不该出现解释性回放的降级备注: %+v", o.Notes)
	}
	if !strings.Contains(o.String(), "首选逐位") {
		t.Fatalf("打印行要看得见逐位标记: %s", o.String())
	}
}

// 记录必须能穿过文件格式再被**另一个进程**复现：内存里相等只证明规划器是纯函数，
// 证明不了快照经 JSON 往返后还是那份输入（时间戳精度、omitempty 字段缺席都可能是坑）。
func TestBitExactSurvivesEncodeDecode(t *testing.T) {
	f := baselineFileWithSnapshot(t)
	data, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"replay_snapshot"`) {
		t.Fatal("v2 导出必须带上 replay_snapshot，否则这份文件没有逐位凭据")
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatalf("往返导入失败: %v", err)
	}
	r := newReplayer(t, testBundles(t), baseNow, false)
	before, err := r.Run(f)
	if err != nil {
		t.Fatal(err)
	}
	after, err := r.Run(got)
	if err != nil {
		t.Fatalf("导入的记录回放失败: %v", err)
	}
	if before.BitExactCount() != 1 || after.BitExactCount() != 1 {
		t.Fatalf("往返前后都该报 1 条逐位，实际 %d / %d:\n%s", before.BitExactCount(), after.BitExactCount(), after.String())
	}
	d1, _ := before.Digest()
	d2, _ := after.Digest()
	if d1 != d2 {
		t.Fatalf("序列化往返改变了回放结论:\n%s\n%s", before.String(), after.String())
	}
}

// 打乱快照里的候选顺序不得改变逐位结论：D 的比较器是全序（provider →
// upstream_model → executor），否则「同一个池子两次遍历顺序不同」就会报成策略差异。
func TestBitExactOrderIsStableUnderOfferShuffle(t *testing.T) {
	in := bitExactReplayInput(t, "req-shuffle", "university-default@3", baseNow)
	plan, _, err := routing.ReplayWithAlgo(in, routing.SamplingAlgoSeededSplitmix64V1)
	if err != nil {
		t.Fatalf("首次重跑失败: %v", err)
	}
	reversed := in
	reversed.Offers = make([]routing.ReplayOffer, len(in.Offers))
	for i := range in.Offers {
		reversed.Offers[i] = in.Offers[len(in.Offers)-1-i]
	}
	plan2, _, err := routing.ReplayWithAlgo(reversed, routing.SamplingAlgoSeededSplitmix64V1)
	if err != nil {
		t.Fatalf("乱序重跑失败: %v", err)
	}
	if len(plan.Fallbacks) != len(plan2.Fallbacks) {
		t.Fatalf("候选数变了: %d vs %d", len(plan.Fallbacks), len(plan2.Fallbacks))
	}
	for i := range plan.Fallbacks {
		if plan.Fallbacks[i].Provider != plan2.Fallbacks[i].Provider {
			t.Fatalf("第 %d 位次序随输入顺序变了: %s vs %s",
				i, plan.Fallbacks[i].Provider, plan2.Fallbacks[i].Provider)
		}
	}
}

// 算法标识与快照互相矛盾时，只能拒绝**声称逐位**，不能拒绝回放本身：
// 解释性回放照样要复核候选摘要、排除原因与授权（§2.8）。
func TestBitExactRefusesWhenAlgoMismatch(t *testing.T) {
	f := baselineFileWithSnapshot(t)
	rec := f.Routings[0]
	rec.SamplingAlgo = SamplingAlgoReplayV1
	pair := f.Decisions[0]
	r := newReplayer(t, testBundles(t), baseNow, false)
	o := r.ReplayRouting(rec, pair, true)
	if o.BitExact {
		t.Fatalf("算法声明不在逐位集合里，报告却声称复现了首选顺序: %+v", o)
	}
	if !hasNoteContaining(o, "不声称首选逐位复现") {
		t.Fatalf("必须看得见拒绝声称逐位的原因: %+v（status=%s）", o.Notes, o.Status)
	}
	if !hasNoteContaining(o, SamplingAlgoReplayV1) {
		t.Fatalf("备注要点名是哪个算法标识不合规: %+v", o.Notes)
	}
}

// 快照与记录顶层各说各话 ⇒ 结构校验就失败：复现出来的结论描述的不是那次决策。
func TestSnapshotContradictingRecordIsRejected(t *testing.T) {
	f := baselineFileWithSnapshot(t)
	tamperedSeeds := []struct {
		name string
		mut  func(*RoutingRecord)
		need string
	}{
		{"seed", func(r *RoutingRecord) { r.Replay.Seed = strings.Repeat("0", len(r.Replay.Seed)) }, "routing_seed"},
		{"policy_version", func(r *RoutingRecord) { r.Replay.PolicyVersion = "other@9" }, "policy_version"},
		{"候选池", func(r *RoutingRecord) { r.Replay.Offers[1].Weight = 99 }, "候选池"},
	}
	for _, tc := range tamperedSeeds {
		rec := f.Routings[0]
		clone := *rec.Replay
		rec.Replay = &clone
		tc.mut(&rec)
		err := rec.Validate(baseNow)
		if err == nil {
			t.Fatalf("%s 被改过却仍通过校验（逐位声称的前提没了）", tc.name)
		}
		if !strings.Contains(err.Error(), tc.need) {
			t.Fatalf("%s 的拒因要点名被改的字段，需要包含 %q，实际: %v", tc.name, tc.need, err)
		}
	}
}

// 采集侧的两个口径：带快照没声明算法要按快照来源补；带快照却声明了不合规的算法要当场拒。
func TestRoutingRecordFromAlgoWithSnapshot(t *testing.T) {
	in := bitExactReplayInput(t, "req-algo", "university-default@3", baseNow)
	plan, _, err := routing.ReplayWithAlgo(in, routing.SamplingAlgoSeededSplitmix64V1)
	if err != nil {
		t.Fatal(err)
	}
	build := func(algo string) (RoutingRecord, error) {
		snapshot := in
		return RoutingRecordFrom(RoutingCapture{
			RequestID:     "req-algo",
			RecordedAt:    baseNow,
			PolicyVersion: in.PolicyVersion,
			RoutingSeed:   in.Seed,
			RoutingEpoch:  "epoch-7",
			SamplingAlgo:  algo,
			Candidates:    replayOfferProjections(in.Offers),
			Plan:          plan,
			Rejections:    plan.Rejections,
			Replay:        &snapshot,
		})
	}
	rec, err := build("")
	if err != nil {
		t.Fatalf("带快照没声明算法必须能落成记录: %v", err)
	}
	if rec.SamplingAlgo != routing.SamplingAlgoSeededSplitmix64V1 {
		t.Fatalf("算法标识应由快照来源补成 %q，实际 %q（落到本包默认值等于自降成解释性回放）",
			routing.SamplingAlgoSeededSplitmix64V1, rec.SamplingAlgo)
	}
	if _, err := build(SamplingAlgoReplayV1); err == nil {
		t.Fatal("带快照却声明解释性抽样算法的记录必须构造失败，不能留下一条自相矛盾的证据")
	} else if !strings.Contains(err.Error(), SamplingAlgoReplayV1) {
		t.Fatalf("拒因要点名冲突的算法标识: %v", err)
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
