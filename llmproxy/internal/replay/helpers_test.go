package replay

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/routing"
)

// 测试基线：全部用合成值（alice / hospital-a / university），不含任何真实密钥或真实个人信息（§5）。
var baseNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// hoursAfter 是相对基线时钟的小时偏移：所有过期判定都钉在可复现的时刻上。
func hoursAfter(h int) time.Time {
	return baseNow.Add(time.Duration(h) * time.Hour)
}

func hoursAfterNow(now time.Time, h int) time.Time {
	return now.Add(time.Duration(h) * time.Hour)
}

func chainOf(t *testing.T, userID, orgID, projectID string) policy.ScopeChain {
	t.Helper()
	scopes := []policy.ScopeRef{policy.MustScope(policy.ScopeUser, userID)}
	if orgID != "" {
		scopes = append(scopes, policy.MustScope(policy.ScopeOrganization, orgID))
	}
	if projectID != "" {
		scopes = append(scopes, policy.MustScope(policy.ScopeProject, projectID))
	}
	return policy.MustScopeChain(scopes...)
}

// identityOf 造一个带成员关系与 TTL 的主体快照（A 包要求成员关系必须带过期时间）。
func identityOf(t *testing.T, subject string, roles, groups []string) policy.Identity {
	t.Helper()
	id, err := policy.NewIdentity(subject, "oidc:university")
	if err != nil {
		t.Fatalf("构造身份失败: %v", err)
	}
	id.Roles = roles
	id.Groups = groups
	id.AuthMethods = []string{"password", "mfa"}
	id.IssuedAt = baseNow.Add(-time.Hour)
	id.ExpiresAt = hoursAfter(8)
	id = id.Normalize()
	if err := id.Validate(); err != nil {
		t.Fatalf("身份校验失败: %v", err)
	}
	return id
}

func ctxOf(t *testing.T, id policy.Identity, org string, level policy.DataLevel) policy.PolicyContext {
	t.Helper()
	ctx, err := policy.NewPolicyContext(id, "qa", level)
	if err != nil {
		t.Fatalf("构造上下文失败: %v", err)
	}
	ctx.Organization = org
	ctx = ctx.Normalize()
	if err := ctx.Validate(); err != nil {
		t.Fatalf("上下文校验失败: %v", err)
	}
	return ctx
}

func allowRule(subject, resource, action string) policy.Entitlement {
	return policy.Entitlement{Subject: subject, Resource: resource, Action: action, Effect: policy.EffectAllow}
}

func denyRule(subject, resource, action string) policy.Entitlement {
	return policy.Entitlement{Subject: subject, Resource: resource, Action: action, Effect: policy.EffectDeny}
}

func withExpiry(e policy.Entitlement, at time.Time) policy.Entitlement {
	e.ExpiresAt = at
	return e
}

func withScope(e policy.Entitlement, scope string) policy.Entitlement {
	e.Scope = scope
	return e
}

func bundleOf(id string, version int, scope policy.ScopeRef, rules ...policy.Entitlement) policy.PolicyBundle {
	return policy.PolicyBundle{ID: id, Version: version, Scope: scope, Entitlements: rules}
}

// testBundles 是两套互不相通的策略包 + 一个系统包，用来验证跨组织隔离。
//
//	university 侧：alice 所在组织，放行 gpt-5、禁止 restricted 场景用外部模型
//	hospital-a 侧：影像科医生才有 private-mri 权限
//	system 侧：全局兜底只放行 public-demo
func testBundles(t *testing.T) *policy.BundleSet {
	t.Helper()
	set, err := policy.NewBundleSet(
		bundleOf("system-default", 1, policy.MustScope(policy.ScopeSystem, "global"),
			allowRule("*", "model:public-demo", policy.ActionUse),
		),
		bundleOf("university-default", 3, policy.MustScope(policy.ScopeOrganization, "university"),
			withExpiry(allowRule("alice", "model:gpt-5", policy.ActionUse), hoursAfter(24)),
			allowRule("role:student", "model:gpt-mini", policy.ActionUse),
			withScope(allowRule("alice", "model:gpt-max", policy.ActionUse), "organization:university"),
			denyRule("role:student", "model:gpt-max", policy.ActionUse),
			withScope(allowRule("alice", policy.ResourceBodyRaw, policy.ActionRead), "organization:university"),
		),
		bundleOf("hospital-a-default", 2, policy.MustScope(policy.ScopeOrganization, "hospital-a"),
			allowRule("role:doctor", "model:private-mri", policy.ActionUse),
		),
	)
	if err != nil {
		t.Fatalf("构造策略集失败: %v", err)
	}
	return set
}

// captureDecision 在给定策略集与时刻上跑一次真实判定并落成记录。
func captureDecision(t *testing.T, set *policy.BundleSet, requestID string, now time.Time,
	chain policy.ScopeChain, id policy.Identity, ctx policy.PolicyContext, resource, action string) DecisionRecord {
	t.Helper()
	r, err := policy.FromBundles(set, chain)
	if err != nil {
		t.Fatalf("构造内核失败: %v", err)
	}
	decision := r.Evaluate(ctx, chain, resource, action, now)
	granted, _ := r.AllowsRawBody(ctx, chain, now)
	rec, err := DecisionRecordFrom(DecisionCapture{
		RequestID:                requestID,
		RecordedAt:               now,
		Chain:                    chain,
		Subject:                  id,
		Ctx:                      ctx,
		Resource:                 resource,
		Action:                   action,
		Decision:                 decision,
		ExternalPlaintextAllowed: granted,
		WiringMode:               ModeShadow,
	})
	if err != nil {
		t.Fatalf("落记录失败: %v", err)
	}
	return rec
}

func candidate(provider, model string, weight float64) policy.RouteCandidate {
	return policy.RouteCandidate{
		Executor:      "openai-http",
		Provider:      provider,
		Model:         model,
		UpstreamModel: model,
		Weight:        weight,
		Region:        "cn-north",
		MaxDataLevel:  policy.LevelConfidential,
	}
}

func rejection(provider string, reason policy.Reason) policy.Rejection {
	return policy.Rejection{Provider: provider, Reason: reason}
}

// routingFixture 造一条自洽的路由记录：seed 按 §2.8 推荐方式派生，
// 计划的候选顺序就是本包抽样器给出的序列，因此回放必然应当逐位复现。
func routingFixture(t *testing.T, requestID, policyVersion string, now time.Time,
	cands []policy.RouteCandidate, rejs []policy.Rejection, maxRetries int) RoutingRecord {
	t.Helper()
	epoch := "epoch-7"
	seed, err := policy.DeriveRoutingSeed(requestID, policyVersion, epoch)
	if err != nil {
		t.Fatalf("派生 seed 失败: %v", err)
	}
	rejected := rejectedProviders(rejs)
	seq, err := NewLocalSampler().Sequence(seed, cands, rejected)
	if err != nil {
		t.Fatalf("抽样失败: %v", err)
	}
	byProvider := map[string]policy.RouteCandidate{}
	for _, c := range cands {
		byProvider[c.Provider] = c
	}
	fallbacks := make([]policy.RouteCandidate, 0, len(seq))
	for _, p := range seq {
		fallbacks = append(fallbacks, byProvider[p])
	}
	primary := fallbacks[0]
	rec, err := RoutingRecordFrom(RoutingCapture{
		RequestID:     requestID,
		RecordedAt:    now,
		PolicyVersion: policyVersion,
		RoutingSeed:   seed,
		RoutingEpoch:  epoch,
		SamplingAlgo:  SamplingAlgoReplayV1,
		Candidates:    cands,
		Rejections:    rejs,
		Plan: policy.RoutingPlan{
			Executor:      primary.Executor,
			Model:         primary.Model,
			UpstreamModel: primary.UpstreamModel,
			Fallbacks:     fallbacks,
			MaxRetries:    maxRetries,
			ReasonCodes:   []policy.Reason{policy.ReasonWeightedChoice},
			PolicyVersion: policyVersion,
			ExpiresAt:     now.Add(time.Hour),
			RoutingSeed:   seed,
			Rejections:    rejs,
		},
	})
	if err != nil {
		t.Fatalf("构造路由记录失败: %v", err)
	}
	return rec
}

// bitExactReplayInput 造一份「D 重跑就能得出那次决策」的完整回放输入（schema v2）。
//
// 现场一律由构造给出、由 routing 侧算结论：如果测试里手搓一份 plan 再配一份快照，
// 断言就只是在和测试自己的期望值对齐，逐位复现这件事一点证据都没留下。
func bitExactReplayInput(t *testing.T, requestID, policyVersion string, now time.Time) routing.ReplayInput {
	t.Helper()
	seed, err := policy.DeriveRoutingSeed(requestID, policyVersion, "epoch-7")
	if err != nil {
		t.Fatalf("派生 seed 失败: %v", err)
	}
	chain := chainOf(t, "alice", "university", "")
	offer := func(provider string, weight float64, gateAllows bool, gateReason policy.Reason) routing.ReplayOffer {
		return routing.ReplayOffer{
			Provider:       provider,
			Executor:       "openai-http",
			Model:          "gpt-mini",
			UpstreamModel:  "gpt-mini",
			Weight:         weight,
			Tier:           0,
			Healthy:        true,
			Region:         "cn-north",
			MaxDataLevel:   policy.LevelConfidential,
			CostPer1KIn:    0.5,
			CostPer1KOut:   1.5,
			CostKnown:      true,
			DeclaredModels: []string{"gpt-mini"},
			GateAllows:     gateAllows,
			GateReason:     gateReason,
		}
	}
	in := routing.ReplayInput{
		RequestID:      requestID,
		PolicyVersion:  policyVersion,
		Seed:           seed,
		Now:            now,
		TTL:            time.Hour,
		Objective:      routing.ObjectiveFixedOrder,
		MaxRetries:     1,
		Requirement:    routing.Requirement{Model: "gpt-mini"},
		Subject:        "alice",
		SubjectSource:  "oidc:university",
		Purpose:        "qa",
		Organization:   "university",
		DataLevel:      policy.LevelInternal,
		AllowedRegions: []string{"cn-north"},
		Scopes:         []policy.ScopeRef(chain),
		Offers: []routing.ReplayOffer{
			offer("gpt-mini", 1, true, policy.ReasonExplicitAllow),
			// 权重 3 的那家最容易在乱序里被误当成首选，留它在池子里正是为了比对次序。
			offer("gpt-5", 3, true, policy.ReasonGroupAllow),
			offer("public-demo", 1, false, policy.ReasonCandidatePolicyExcluded),
		},
	}
	if err := in.Validate(); err != nil {
		t.Fatalf("回放输入不合法: %v", err)
	}
	return in
}

// replayInputFromCandidates 把「本包抽样器看到的候选池」原样搬进 D 的回放进料。
//
// 两侧必须看到同一个池子、同一份排除集，比出来的首选差异才归因到抽样算法本身 ——
// 否则是能力筛或权限门在替我们改池子，测到的就不是「两个算法」。
func replayInputFromCandidates(t *testing.T, seed string, cands []policy.RouteCandidate,
	rejected map[string]bool, model string) routing.ReplayInput {
	t.Helper()
	offers := make([]routing.ReplayOffer, 0, len(cands))
	for _, c := range cands {
		weight := c.Weight
		if weight <= 0 {
			weight = 1
		}
		allow := !rejected[c.Provider]
		reason := policy.ReasonExplicitAllow
		if !allow {
			reason = policy.ReasonCandidatePolicyExcluded
		}
		offers = append(offers, routing.ReplayOffer{
			Provider:       c.Provider,
			Executor:       c.Executor,
			Model:          c.Model,
			UpstreamModel:  c.UpstreamModel,
			Weight:         weight,
			Healthy:        true,
			Region:         c.Region,
			MaxDataLevel:   c.MaxDataLevel,
			CostPer1KIn:    0.5,
			CostPer1KOut:   1.5,
			CostKnown:      true,
			DeclaredModels: []string{"*"},
			GateAllows:     allow,
			GateReason:     reason,
		})
	}
	in := routing.ReplayInput{
		PolicyVersion:  "university-default@3",
		Seed:           seed,
		Now:            baseNow,
		TTL:            time.Hour,
		Objective:      routing.ObjectiveFixedOrder,
		MaxRetries:     1,
		Requirement:    routing.Requirement{Model: model},
		Subject:        "alice",
		SubjectSource:  "oidc:university",
		Purpose:        "qa",
		Organization:   "university",
		DataLevel:      policy.LevelInternal,
		AllowedRegions: []string{"cn-north"},
		Scopes:         []policy.ScopeRef(chainOf(t, "alice", "university", "")),
		Offers:         offers,
	}
	if err := in.Validate(); err != nil {
		t.Fatalf("回放输入不合法: %v", err)
	}
	return in
}

// replayOfferProjections 把快照里的候选压回记录顶层的配置级投影。
// Weight 照抄：ReplayOffer 里已经是有效权重，两侧必须是同一个数（digest 才核得上）。
func replayOfferProjections(os []routing.ReplayOffer) []policy.RouteCandidate {
	out := make([]policy.RouteCandidate, 0, len(os))
	for _, o := range os {
		out = append(out, policy.RouteCandidate{
			Executor:      o.Executor,
			Provider:      o.Provider,
			Model:         o.Model,
			UpstreamModel: o.UpstreamModel,
			Weight:        o.Weight,
			Region:        o.Region,
			MaxDataLevel:  o.MaxDataLevel,
		})
	}
	return out
}

// routingFixtureWithSnapshot 造一条 v2 形态的路由记录：计划由 D 现场算出，
// 记录带着算出它的那份输入。SamplingAlgo 刻意留空，由 RoutingRecordFrom 按快照来源补，
// 这样「带快照没声明算法」那条补值规则也是被测路径的一部分。
func routingFixtureWithSnapshot(t *testing.T, requestID, policyVersion string, now time.Time) RoutingRecord {
	t.Helper()
	in := bitExactReplayInput(t, requestID, policyVersion, now)
	plan, _, err := routing.ReplayWithAlgo(in, routing.SamplingAlgoSeededSplitmix64V1)
	if err != nil {
		t.Fatalf("按声明算法重跑失败: %v", err)
	}
	rec, err := RoutingRecordFrom(RoutingCapture{
		RequestID:     requestID,
		RecordedAt:    now,
		PolicyVersion: policyVersion,
		RoutingSeed:   in.Seed,
		RoutingEpoch:  "epoch-7",
		Candidates:    replayOfferProjections(in.Offers),
		Plan:          plan,
		Rejections:    plan.Rejections,
		Replay:        &in,
	})
	if err != nil {
		t.Fatalf("构造带快照的路由记录失败: %v", err)
	}
	return rec
}

// baselineFileWithSnapshot 是一份 v2 记录集：判定记录 + 一条带完整现场的路由记录。
func baselineFileWithSnapshot(t *testing.T) File {
	t.Helper()
	set := testBundles(t)
	chain := chainOf(t, "alice", "university", "")
	id := identityOf(t, "alice", []string{"student"}, []string{"cs"})
	ctx := ctxOf(t, id, "university", policy.LevelInternal)
	allowed := captureDecision(t, set, "req-bit-exact", baseNow, chain, id, ctx, "model:gpt-mini", policy.ActionUse)
	if allowed.Effect != policy.EffectAllow {
		t.Fatalf("gpt-mini 对 student 应放行，实际 %+v", allowed)
	}
	return NewFile([]DecisionRecord{allowed}, []RoutingRecord{
		routingFixtureWithSnapshot(t, "req-bit-exact", allowed.PolicyVersion, baseNow),
	})
}

// shuffledFile 把记录顺序打乱：确定性回放的报告摘要必须与输入顺序无关。
func shuffledFile(t *testing.T, f File, seed int64) File {
	t.Helper()
	rnd := rand.New(rand.NewSource(seed))
	decisions := append([]DecisionRecord(nil), f.Decisions...)
	routings := append([]RoutingRecord(nil), f.Routings...)
	rnd.Shuffle(len(decisions), func(i, j int) { decisions[i], decisions[j] = decisions[j], decisions[i] })
	rnd.Shuffle(len(routings), func(i, j int) { routings[i], routings[j] = routings[j], routings[i] })
	return File{SchemaVersion: f.SchemaVersion, Decisions: decisions, Routings: routings}
}

// shuffledCandidates 打乱候选池顺序，用来证明稳定排序真的生效。
func shuffledCandidates(cs []policy.RouteCandidate, seed int64) []policy.RouteCandidate {
	rnd := rand.New(rand.NewSource(seed))
	out := append([]policy.RouteCandidate(nil), cs...)
	rnd.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func mustDiffField(t *testing.T, o Outcome, field string) FieldDiff {
	t.Helper()
	for _, d := range o.Diffs {
		if d.Field == field {
			return d
		}
	}
	t.Fatalf("差异里缺字段 %q，实际 %+v（备注 %+v）", field, o.Diffs, o.Notes)
	return FieldDiff{}
}

func hasDiffField(o Outcome, field string) bool {
	for _, d := range o.Diffs {
		if d.Field == field {
			return true
		}
	}
	return false
}

func hasNoteContaining(o Outcome, needle string) bool {
	for _, n := range o.Notes {
		if strings.Contains(n, needle) {
			return true
		}
	}
	return false
}

// routingOutcomeOf 从报告里取那条选路结果：报告按 (kind, request_id) 稳定排序，
// 判定记录总是排在前面，用下标取会拿到错的那条。
func routingOutcomeOf(t *testing.T, r Report) Outcome {
	t.Helper()
	for _, o := range r.Outcomes {
		if o.Kind == KindRouting {
			return o
		}
	}
	t.Fatalf("报告里没有选路结果:\n%s", r.String())
	return Outcome{}
}
