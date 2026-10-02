package replay

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
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
