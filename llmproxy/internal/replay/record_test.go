package replay

import (
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

func TestDecisionRecordFromMatchesLiveDecision(t *testing.T) {
	set := testBundles(t)
	chain := chainOf(t, "alice", "university", "")
	id := identityOf(t, "alice", []string{"student"}, []string{"cs"})
	ctx := ctxOf(t, id, "university", policy.LevelInternal)

	rec := captureDecision(t, set, "req-1", baseNow, chain, id, ctx, "model:gpt-5", policy.ActionUse)
	if rec.Effect != policy.EffectAllow {
		t.Fatalf("alice 应被放行，实际 %+v", rec)
	}
	if rec.PolicyVersion == "" {
		t.Fatal("记录的版本串必须来自实际加载的策略包（§3.0）")
	}
	if rec.Winner == nil {
		t.Fatal("放行必须有决定性规则")
	}
	if rec.Winner.SortKey != strings.Join([]string{"alice", "model:gpt-5", policy.ActionUse, ""}, "|") {
		t.Fatalf("winner 的 sort_key 应能复现 A 包的 SortKey，实际 %q", rec.Winner.SortKey)
	}
	if rec.Winner.Precedence != policy.PrecedenceExplicitAllow.String() {
		t.Fatalf("裸 subject 命中应是 explicit_allow 档，实际 %q", rec.Winner.Precedence)
	}
	// Conditions 的取值绝不进记录：这里连规则本身都没带 conditions，
	// 更不能有正文类字段（leak_test.go 统一审查）。
	if strings.Contains(MustEncode(NewFile([]DecisionRecord{rec}, nil)), "expires_at\": \"0001") {
		t.Fatal("空时间不应被写成 0001 年")
	}
}

func TestDecisionRecordRejectsInconsistentShapes(t *testing.T) {
	base := func(t *testing.T) DecisionRecord {
		t.Helper()
		set := testBundles(t)
		chain := chainOf(t, "alice", "university", "")
		id := identityOf(t, "alice", []string{"student"}, []string{"cs"})
		ctx := ctxOf(t, id, "university", policy.LevelInternal)
		return captureDecision(t, set, "req-bad", baseNow, chain, id, ctx, "model:gpt-5", policy.ActionUse)
	}

	cases := []struct {
		name   string
		mutate func(*DecisionRecord)
	}{
		{"缺 request_id", func(r *DecisionRecord) { r.RequestID = "" }},
		{"request_id 含空白", func(r *DecisionRecord) { r.RequestID = "req 1" }},
		{"缺 recorded_at", func(r *DecisionRecord) { r.RecordedAt = time.Time{} }},
		{"缺 policy_version", func(r *DecisionRecord) { r.PolicyVersion = "" }},
		{"范围链为空", func(r *DecisionRecord) { r.Chain = nil }},
		{"范围链未排序", func(r *DecisionRecord) {
			// policy 的稳定顺序是 (kind, id)：organization 在 user 之前，倒过来写就是未归一。
			r.Chain = []policy.ScopeRef{policy.MustScope(policy.ScopeUser, "alice"), policy.MustScope(policy.ScopeOrganization, "university")}
		}},
		{"范围链有重复", func(r *DecisionRecord) {
			r.Chain = []policy.ScopeRef{policy.MustScope(policy.ScopeUser, "alice"), policy.MustScope(policy.ScopeUser, "alice")}
		}},
		{"等级写成未知值", func(r *DecisionRecord) { r.Ctx.DataLevel = "top-secret-ish" }},
		{"接线阶段写错", func(r *DecisionRecord) { r.Ctx.WiringMode = WiringMode("canary") }},
		{"放行却写拒绝原因码", func(r *DecisionRecord) { r.Reason = policy.ReasonNoMatchingRule }},
		{"拒绝却写放行原因码", func(r *DecisionRecord) {
			r.Effect = policy.EffectDeny
			r.Reason = policy.ReasonExplicitAllow
		}},
		{"原因链含未注册项", func(r *DecisionRecord) { r.Reasons = []policy.Reason{policy.Reason("随便一句话")} }},
		{"有命中链却没有 winner", func(r *DecisionRecord) { r.Winner = nil }},
		{"winner 不等于 matched[0]", func(r *DecisionRecord) {
			other := r.Matched[0]
			other.SortKey = "别的规则"
			r.Winner = &other
		}},
		{"拒绝结论却授予原文出网", func(r *DecisionRecord) {
			r.Effect = policy.EffectDeny
			r.Reason = policy.ReasonNoMatchingRule
			r.ExternalPlaintextAllowed = true
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := base(t)
			c.mutate(&rec)
			if err := rec.Validate(); err == nil {
				t.Fatalf("这种记录必须被拒绝：%+v", rec)
			} else if !strings.Contains(err.Error(), "回放记录不合法") {
				t.Fatalf("错误应指向记录不合法，实际 %v", err)
			}
		})
	}
}

func TestDecisionRecordFromRequiresReasonCode(t *testing.T) {
	if _, err := DecisionRecordFrom(DecisionCapture{RequestID: "req-x"}); err == nil {
		t.Fatal("没有原因码的判定结果不允许落记录（§5：安全决策必须返回 reason code）")
	}
}

func TestRoutingRecordValidateCatchesUnaccountedCandidate(t *testing.T) {
	cands := []policy.RouteCandidate{
		candidate("p1", "gpt-mini", 1),
		candidate("p2", "gpt-5", 2),
		candidate("p3", "public-demo", 1),
	}
	rec := routingFixture(t, "req-r1", "university-default@3", baseNow, cands,
		[]policy.Rejection{rejection("p3", policy.ReasonCandidateLevelExcluded)}, 1)
	if err := rec.Validate(baseNow); err != nil {
		t.Fatalf("自洽记录应通过: %v", err)
	}

	// 候选池里凭空多出一个既不在计划也没有排除原因的候选：§6 要求每个候选都有交代。
	tampered := rec
	tampered.Candidates = policy.SortCandidates(append(append([]policy.RouteCandidate(nil), cands...), candidate("p9", "gpt-9", 1)))
	tampered.CandidatesDigest, _ = policy.CandidatesDigest(tampered.Candidates)
	if err := tampered.Validate(baseNow); err == nil {
		t.Fatal("没有交代的候选必须让记录失效")
	} else if !strings.Contains(err.Error(), "既不在计划里也没有排除原因") {
		t.Fatalf("错误应指出候选没交代，实际 %v", err)
	}
}

func TestRoutingRecordValidateCatchesDigestAndRejectionErrors(t *testing.T) {
	cands := []policy.RouteCandidate{candidate("p1", "gpt-mini", 1), candidate("p2", "gpt-5", 2)}
	rec := routingFixture(t, "req-r2", "university-default@3", baseNow, cands, nil, 0)

	if _, err := RoutingRecordFrom(RoutingCapture{
		RequestID: "req", RecordedAt: baseNow, PolicyVersion: "v@1", Candidates: cands,
		Plan: rec.Plan,
	}); err == nil {
		t.Fatal("缺 routing_seed 的记录必须构造失败（§2.8）")
	}

	badDigest := rec
	badDigest.CandidatesDigest = strings.Repeat("0", 64)
	if err := badDigest.Validate(baseNow); err == nil {
		t.Fatal("候选摘要与候选池不符必须失败")
	}

	// 被排除的候选又出现在计划里：排除原因不可信。
	conflict := routingFixture(t, "req-r3", "university-default@3", baseNow, cands, nil, 1)
	conflict.Rejections = sortRejections([]policy.Rejection{rejection("p1", policy.ReasonCandidateUnhealthy)})
	conflict.Plan.Rejections = conflict.Rejections
	if err := conflict.Validate(baseNow); err == nil {
		t.Fatal("同一候选既被排除又进计划必须失败")
	}

	if err := rec.Validate(baseNow.Add(72 * time.Hour)); err != nil {
		t.Fatalf("历史计划放到之后的时钟回放是正常场景: %v", err)
	}
	expiredAtRecord := rec
	expiredAtRecord.Plan.ExpiresAt = baseNow.Add(-time.Minute)
	expiredAtRecord.RecordedAt = baseNow
	if err := expiredAtRecord.Validate(baseNow); err == nil {
		t.Fatal("记录时计划就已过期必须失败")
	}
}

func TestRoutingRecordFromNormalizesOrder(t *testing.T) {
	cands := []policy.RouteCandidate{candidate("p2", "gpt-5", 2), candidate("p1", "gpt-mini", 1)}
	rec, err := RoutingRecordFrom(RoutingCapture{
		RequestID: "req-order", RecordedAt: baseNow, PolicyVersion: "university-default@3",
		RoutingSeed: strings.Repeat("a", 64), Candidates: cands,
		Plan: policy.RoutingPlan{
			Executor: "openai-http", Model: "gpt-5", UpstreamModel: "gpt-5",
			Fallbacks:     []policy.RouteCandidate{cands[0], cands[1]},
			ReasonCodes:   []policy.Reason{policy.ReasonWeightedChoice},
			PolicyVersion: "university-default@3", ExpiresAt: hoursAfter(1),
		},
	})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if rec.Candidates[0].Provider != "p1" {
		t.Fatalf("候选池必须按稳定 provider ID 排序，实际 %+v", providersOf(rec.Candidates))
	}
	if rec.SamplingAlgo != SamplingAlgoReplayV1 {
		t.Fatalf("留空的 sampling_algo 应落到默认值，实际 %q", rec.SamplingAlgo)
	}
}
