package replay

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

func newReplayer(t *testing.T, set *policy.BundleSet, now time.Time, strict bool) *Replayer {
	t.Helper()
	r, err := New(set, Options{Now: now, StrictReasonChain: strict})
	if err != nil {
		t.Fatalf("构造回放器失败: %v", err)
	}
	return r
}

func TestNewFailClosed(t *testing.T) {
	set := testBundles(t)
	if _, err := New(set, Options{}); err == nil {
		t.Fatal("缺时钟必须拒绝构造：回放不能依赖当前时间（§2.8）")
	} else if !strings.Contains(err.Error(), "时钟") {
		t.Fatalf("错误要说清是时钟问题，实际 %v", err)
	}
	if _, err := New(nil, Options{Now: baseNow}); err == nil {
		t.Fatal("空策略集必须拒绝构造")
	}
	if _, err := New(&policy.BundleSet{}, Options{Now: baseNow}); err == nil {
		t.Fatal("零长度策略集必须拒绝构造")
	}
	if _, err := New(set, Options{Now: baseNow, Sampler: fakeSampler{algo: ""}}); err == nil {
		t.Fatal("抽样器没有算法标识必须拒绝")
	}
}

func TestReplayBaselineIsClean(t *testing.T) {
	f := baselineFile(t)
	r := newReplayer(t, testBundles(t), baseNow, false)
	report, err := r.Run(f)
	if err != nil {
		t.Fatalf("回放不该出错: %v", err)
	}
	if !report.Clean() {
		t.Fatalf("基线记录必须逐字段复现:\n%s", report.String())
	}
	if report.Empty() {
		t.Fatal("报告不该为空")
	}
	passed, mismatch, rejected := report.Counts()
	if passed != 3 || mismatch != 0 || rejected != 0 {
		t.Fatalf("统计不对: %d/%d/%d\n%s", passed, mismatch, rejected, report.String())
	}
	if report.LoadedPolicyVersion == "" {
		t.Fatal("报告要带整集版本，才能区分「喂错策略集」和「该范围策略变了」")
	}
}

// TestReplayDigestIgnoresInputOrder 钉住 §2.8「绝不依赖 map 遍历顺序」：
// 同一批记录乱序进入，报告摘要必须一模一样。
func TestReplayDigestIgnoresInputOrder(t *testing.T) {
	f := baselineFile(t)
	r := newReplayer(t, testBundles(t), baseNow, true)
	want, err := r.Run(f)
	if err != nil {
		t.Fatal(err)
	}
	baseDigest, err := want.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if baseDigest == "" || len(baseDigest) != 64 {
		t.Fatalf("报告摘要应是 sha256 十六进制，实际 %q", baseDigest)
	}
	for i := 0; i < 20; i++ {
		shuffled := shuffledFile(t, f, int64(i)+1)
		got, err := r.Run(shuffled)
		if err != nil {
			t.Fatalf("第 %d 次乱序回放失败: %v", i, err)
		}
		digest, err := got.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if digest != baseDigest {
			t.Fatalf("第 %d 次乱序后报告摘要变了:\n基线:\n%s\n乱序:\n%s", i, want.String(), got.String())
		}
	}
}

func TestReplayNeedsFixedClock(t *testing.T) {
	set := testBundles(t)
	chain := chainOf(t, "alice", "university", "")
	id := identityOf(t, "alice", []string{"student"}, []string{"cs"})
	ctx := ctxOf(t, id, "university", policy.LevelInternal)
	rec := captureDecision(t, set, "req-clock", baseNow, chain, id, ctx, "model:gpt-5", policy.ActionUse)

	// 同一份记录、同一个策略集，只把时钟推到身份 TTL 之后：结论必须变成拒绝。
	later := newReplayer(t, set, hoursAfter(9), false)
	o := later.ReplayDecision(rec)
	if o.Status != StatusMismatch {
		t.Fatalf("时钟推后应暴露差异，实际 %+v", o)
	}
	reason := mustDiffField(t, o, "reason")
	if reason.Expected != string(policy.ReasonExplicitAllow) || reason.Actual != string(policy.ReasonIdentityExpired) {
		t.Fatalf("差异要写清期望与实际，实际 %+v", reason)
	}
	if mustDiffField(t, o, "effect").Actual != string(policy.EffectDeny) {
		t.Fatal("effect 差异也要结构化输出")
	}

	// 记录时刻回放必须复现 —— 这正是不允许用墙钟的理由。
	onTime := newReplayer(t, set, baseNow, false)
	if o := onTime.ReplayDecision(rec); !o.Passed() {
		t.Fatalf("按记录时钟应完全复现: %+v", o)
	}
}

func TestReplayDetectsRuleExpiry(t *testing.T) {
	set := testBundles(t)
	chain := chainOf(t, "alice", "university", "")
	// 身份 TTL 比规则 TTL 长，于是到期点由规则决定。
	id := identityOf(t, "alice", []string{"student"}, []string{"cs"})
	id.ExpiresAt = hoursAfter(48)
	ctx := ctxOf(t, id, "university", policy.LevelInternal)
	rec := captureDecision(t, set, "req-expire", baseNow, chain, id, ctx, "model:gpt-5", policy.ActionUse)
	if rec.ExpiresAt == nil {
		t.Fatal("记录必须带生效的到期点")
	}

	// 把 alice 的规则 TTL 缩短到回放时钟之前：策略内容变了（版本串也变了）。
	drifted := policy.MustBundleSet(
		bundleOf("system-default", 1, policy.MustScope(policy.ScopeSystem, "global"),
			allowRule("*", "model:public-demo", policy.ActionUse)),
		bundleOf("university-default", 4, policy.MustScope(policy.ScopeOrganization, "university"),
			withExpiry(allowRule("alice", "model:gpt-5", policy.ActionUse), hoursAfter(1)),
			withExpiry(allowRule("role:student", "model:gpt-mini", policy.ActionUse), hoursAfter(1)),
			withScope(withExpiry(allowRule("alice", "model:gpt-max", policy.ActionUse), hoursAfter(1)), "organization:university"),
			withExpiry(denyRule("role:student", "model:gpt-max", policy.ActionUse), hoursAfter(1)),
			withScope(withExpiry(allowRule("alice", policy.ResourceBodyRaw, policy.ActionRead), hoursAfter(1)), "organization:university"),
		),
	)
	o := newReplayer(t, drifted, hoursAfter(2), false).ReplayDecision(rec)
	if o.Status != StatusRejected {
		t.Fatalf("策略版本变了必须拒绝回放（不能拿新版本假装复现旧结论），实际 %+v", o)
	}
	if o.Reason != policy.ReasonPolicyVersionMissing {
		t.Fatalf("要给出明确的版本来源问题，实际 %s", o.Reason)
	}
	if !hasNoteContaining(o, "university-default@4") {
		t.Fatalf("拒绝原因要把当前生效版本说出来，便于定位漂移: %+v", o.Notes)
	}
}

// 跨组织隔离：hospital-a 的记录喂给不含 hospital-a 包的战略集，必须拒绝回放，
// 而不是让 Evaluate 算出一条 deny 冒充「复现成功」。
func TestReplayCrossOrganizationIsNotSilentDeny(t *testing.T) {
	set := testBundles(t)
	chain := chainOf(t, "bob", "hospital-a", "")
	id := identityOf(t, "bob", []string{"doctor"}, []string{"radiology"})
	ctx := ctxOf(t, id, "hospital-a", policy.LevelConfidential)
	rec := captureDecision(t, set, "req-mri", baseNow, chain, id, ctx, "model:private-mri", policy.ActionUse)
	if rec.Effect != policy.EffectAllow {
		t.Fatalf("本组织内医生应被放行: %+v", rec)
	}

	universityOnly := policy.MustBundleSet(
		bundleOf("system-default", 1, policy.MustScope(policy.ScopeSystem, "global"),
			allowRule("*", "model:public-demo", policy.ActionUse)),
		bundleOf("university-default", 3, policy.MustScope(policy.ScopeOrganization, "university"),
			allowRule("alice", "model:gpt-5", policy.ActionUse)),
	)
	o := newReplayer(t, universityOnly, baseNow, false).ReplayDecision(rec)
	if o.Status != StatusRejected {
		t.Fatalf("喂错组织的包必须拒绝回放，实际 %+v", o)
	}
	if o.Reason != policy.ReasonPolicyVersionMissing {
		t.Fatalf("系统包对任意范围生效，因此这里表现为版本来源不符，实际 %s / %+v", o.Reason, o.Notes)
	}

	// 只喂 hospital-a 的包时，university 的记录同样不能静默变成 deny。
	hospitalOnly := policy.MustBundleSet(
		bundleOf("hospital-a-default", 2, policy.MustScope(policy.ScopeOrganization, "hospital-a"),
			allowRule("role:doctor", "model:private-mri", policy.ActionUse)),
	)
	aliceChain := chainOf(t, "alice", "university", "")
	aliceID := identityOf(t, "alice", []string{"student"}, []string{"cs"})
	aliceRec := captureDecision(t, set, "req-gpt5", baseNow, aliceChain, aliceID,
		ctxOf(t, aliceID, "university", policy.LevelInternal), "model:gpt-5", policy.ActionUse)
	o = newReplayer(t, hospitalOnly, baseNow, false).ReplayDecision(aliceRec)
	if o.Status != StatusRejected || o.Reason != policy.ReasonScopeMismatch {
		t.Fatalf("范围没有策略包覆盖必须是 scope_mismatch 拒绝，实际 %+v", o)
	}
	if !hasNoteContaining(o, "不覆盖记录范围") {
		t.Fatalf("要指出是范围覆盖问题: %+v", o.Notes)
	}
}

func TestReplayStructuredDiffOnTamperedRecord(t *testing.T) {
	set := testBundles(t)
	chain := chainOf(t, "alice", "university", "")
	id := identityOf(t, "alice", []string{"student"}, []string{"cs"})
	ctx := ctxOf(t, id, "university", policy.LevelInternal)
	rec := captureDecision(t, set, "req-tamper", baseNow, chain, id, ctx, "model:gpt-5", policy.ActionUse)

	tampered := rec
	tampered.Effect = policy.EffectDeny
	tampered.Reason = policy.ReasonModelNotAllowed
	if err := tampered.Validate(); err != nil {
		t.Fatalf("篡改后的记录结构上仍要能加载（问题是策略不符，不是记录坏了）: %v", err)
	}
	o := newReplayer(t, set, baseNow, false).ReplayDecision(tampered)
	if o.Status != StatusMismatch {
		t.Fatalf("应报差异，实际 %+v", o)
	}
	if mustDiffField(t, o, "effect").Expected != string(policy.EffectDeny) {
		t.Fatal("effect 差异的期望值必须取自记录")
	}
	if mustDiffField(t, o, "reason").Actual != string(policy.ReasonExplicitAllow) {
		t.Fatal("reason 差异的实际值必须取自回放")
	}
	if o.Passed() {
		t.Fatal("有差异绝不能算通过")
	}

	// §2.9 的原文出网授权同样参与比对：记录说被拒的判定却授了权，必须暴露。
	overGranted := rec
	overGranted.ExternalPlaintextAllowed = true
	o = newReplayer(t, set, baseNow, false).ReplayDecision(overGranted)
	if o.Status != StatusMismatch || !hasDiffField(o, "external_plaintext_allowed") {
		t.Fatalf("原文出网授权档位必须参与比对: %+v", o)
	}
	if !hasNoteContaining(o, "raw_body_grant_missing") {
		t.Fatalf("差异备注要带上授权门槛的原因码，便于定位： %+v", o.Notes)
	}
}

func TestReplayWinnerAndMatchedChain(t *testing.T) {
	set := testBundles(t)
	chain := chainOf(t, "alice", "university", "")
	id := identityOf(t, "alice", []string{"student"}, []string{"cs"})
	ctx := ctxOf(t, id, "university", policy.LevelInternal)
	rec := captureDecision(t, set, "req-winner", baseNow, chain, id, ctx, "model:gpt-max", policy.ActionUse)
	if rec.Winner == nil || rec.Winner.Effect != policy.EffectDeny {
		t.Fatalf("deny 必须是决定性规则: %+v", rec.Winner)
	}
	if rec.Winner.Precedence != policy.PrecedenceDeny.String() {
		t.Fatalf("决定性档位应是 deny，实际 %q", rec.Winner.Precedence)
	}
	if o := newReplayer(t, set, baseNow, false).ReplayDecision(rec); !o.Passed() {
		t.Fatalf("回放应复现 deny 优先级: %+v", o)
	}

	// 把 winner 的 sort_key 改掉：必须被逐字段差异抓到。
	shifted := rec
	key := shifted.Winner.SortKey
	shifted.Winner = &RuleRef{Subject: "role:student", Resource: "model:gpt-max", Action: policy.ActionUse,
		Effect: policy.EffectDeny, Precedence: policy.PrecedenceDeny.String(), SortKey: "被换掉的规则"}
	shifted.Matched[0] = *shifted.Winner
	o := newReplayer(t, set, baseNow, false).ReplayDecision(shifted)
	if o.Status != StatusMismatch {
		t.Fatal("决定性规则被换掉必须暴露")
	}
	if !hasDiffField(o, "winner.sort_key") || !hasDiffField(o, "matched/0.sort_key") {
		t.Fatalf("要同时指出 winner 与命中链的差异: %+v", o.Diffs)
	}
	_ = key
}

func TestReplayStrictReasonChain(t *testing.T) {
	set := testBundles(t)
	chain := chainOf(t, "alice", "university", "")
	id := identityOf(t, "alice", []string{"student"}, []string{"cs"})
	ctx := ctxOf(t, id, "university", policy.LevelInternal)
	rec := captureDecision(t, set, "req-chain", baseNow, chain, id, ctx, "model:gpt-max", policy.ActionUse)
	loose := rec
	loose.Reasons = nil
	if o := newReplayer(t, set, baseNow, false).ReplayDecision(loose); !o.Passed() {
		t.Fatalf("默认只比主原因码与结论: %+v", o)
	}
	o := newReplayer(t, set, baseNow, true).ReplayDecision(loose)
	if o.Status != StatusMismatch || !hasDiffField(o, "reasons_chain") {
		t.Fatalf("严格模式要抓完整原因链: %+v", o)
	}
}

func TestReplayRejectsBrokenRecord(t *testing.T) {
	set := testBundles(t)
	rec := captureDecision(t, set, "req-broken", baseNow, chainOf(t, "alice", "university", ""),
		identityOf(t, "alice", []string{"student"}, []string{"cs"}),
		ctxOf(t, identityOf(t, "alice", nil, nil), "university", policy.LevelInternal), "model:gpt-5", policy.ActionUse)
	rec.Chain = []policy.ScopeRef{policy.MustScope(policy.ScopeUser, "Alice"), rec.Chain[0]}
	o := newReplayer(t, set, baseNow, false).ReplayDecision(rec)
	if o.Status != StatusRejected {
		t.Fatalf("非法记录要拒绝回放而不是硬判: %+v", o)
	}
	if o.Reason != policy.ReasonContextInvalid {
		t.Fatalf("结构问题应落到 context_invalid 类原因，实际 %s", o.Reason)
	}
}

func TestRunRejectsInvalidFile(t *testing.T) {
	f := baselineFile(t)
	f.Routings[0].CandidatesDigest = "坏摘要"
	r := newReplayer(t, testBundles(t), baseNow, false)
	if _, err := r.Run(f); err == nil {
		t.Fatal("记录文件本身坏了必须直接报错，不能产出一份「全绿」报告")
	}
}

func TestReplayerIsConcurrencySafe(t *testing.T) {
	f := baselineFile(t)
	r := newReplayer(t, testBundles(t), baseNow, false)
	want, err := r.Run(f)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, _ := want.Digest()

	var wg sync.WaitGroup
	got := make([]string, 8)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rep, err := r.Run(f)
			if err != nil {
				t.Errorf("并发回放失败: %v", err)
				return
			}
			d, err := rep.Digest()
			if err != nil {
				t.Errorf("摘要失败: %v", err)
				return
			}
			got[i] = d
		}(i)
	}
	wg.Wait()
	for i, d := range got {
		if d != wantDigest {
			t.Fatalf("第 %d 个并发结果与基线不一致: %s vs %s", i, d, wantDigest)
		}
	}
}

func TestReportSummaryAndFailures(t *testing.T) {
	set := testBundles(t)
	chain := chainOf(t, "alice", "university", "")
	id := identityOf(t, "alice", []string{"student"}, []string{"cs"})
	ctx := ctxOf(t, id, "university", policy.LevelInternal)
	rec := captureDecision(t, set, "req-summary", baseNow, chain, id, ctx, "model:gpt-5", policy.ActionUse)
	tampered := rec
	tampered.Effect = policy.EffectDeny
	tampered.Reason = policy.ReasonNoMatchingRule
	report, err := newReplayer(t, set, baseNow, false).Run(NewFile([]DecisionRecord{rec, tampered}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if report.Clean() {
		t.Fatal("有差异的报告不能算干净")
	}
	if len(report.Failures()) != 1 {
		t.Fatalf("只应有一条失败: %s", report.String())
	}
	line := report.Summary()
	for _, want := range []string{"通过 1", "差异 1"} {
		if !strings.Contains(line, want) {
			t.Fatalf("汇总要含 %q，实际 %q", want, line)
		}
	}
	if !strings.Contains(report.String(), "reason: 记录=no_matching_rule 回放=explicit_allow") {
		t.Fatalf("报告要能直接读出期望/实际:\n%s", report.String())
	}
}

// fakeSampler 用来验证「算法标识不一致 → 只做解释性回放」这条分支。
type fakeSampler struct {
	algo     string
	sequence []string
	err      error
}

func (f fakeSampler) Algo() string { return f.algo }

func (f fakeSampler) Sequence(seed string, candidates []policy.RouteCandidate, rejected map[string]bool) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.sequence != nil {
		return append([]string(nil), f.sequence...), nil
	}
	return NewLocalSampler().Sequence(seed, candidates, rejected)
}
