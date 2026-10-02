package knowledge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 知识库准入必须完全交给 A 包判定：本文件就是那条分工的可执行证明。
// 规则一律写成 `knowledge:<id>` + `read`（领域文档 §8），
// C 侧只负责把判定结果拼成 KnowledgeScope，不参与判定本身。

// allowKBRule 造一条知识库准入规则（resource=knowledge:<id>, action=read）。
func allowKBRule(subject, kb string) policy.Entitlement {
	return policy.Entitlement{
		Subject:  subject,
		Resource: ResourceForKB(kb),
		Action:   policy.ActionRead,
		Effect:   policy.EffectAllow,
		Source:   "example-admit-test",
	}
}

func denyKBRule(subject, kb string) policy.Entitlement {
	return policy.Entitlement{
		Subject:  subject,
		Resource: ResourceForKB(kb),
		Action:   policy.ActionRead,
		Effect:   policy.EffectDeny,
		Source:   "example-admit-test",
	}
}

func admitIdentity(t *testing.T, subject string) policy.Identity {
	t.Helper()
	id, err := policy.NewIdentity(subject, "oidc:example-idp")
	if err != nil {
		t.Fatalf("构造身份失败: %v", err)
	}
	return id
}

func admitContext(t *testing.T, subject, org string, level policy.DataLevel) policy.PolicyContext {
	t.Helper()
	ctx, err := policy.NewPolicyContext(admitIdentity(t, subject), "qa", level)
	if err != nil {
		t.Fatalf("构造策略上下文失败: %v", err)
	}
	ctx.Organization = org
	return ctx
}

func denialFor(t *testing.T, denials []KnowledgeBaseDenial, kb string) policy.Reason {
	t.Helper()
	for _, d := range denials {
		if d.KnowledgeBase == kb {
			return d.Reason
		}
	}
	t.Fatalf("拒绝明细里没有 %s: %+v", kb, denials)
	return ""
}

func TestAdmitKnowledgeBasesRequiresPolicyKernel(t *testing.T) {
	chain := chainOf(t, subjectAlice, orgExample, projExample)
	ctx := admitContext(t, subjectAlice, orgExample, policy.LevelInternal)

	// nil resolver 必须报错而不是「没策略所以全都给」
	allowed, denials, err := AdmitKnowledgeBases(nil, ctx, chain, []string{kbHandbook, kbHR}, baseNow)
	if err == nil {
		t.Fatal("缺少策略内核时必须报错")
	}
	if !errors.Is(err, ErrAdmission) {
		t.Fatalf("应报 ErrAdmission，实际 %v", err)
	}
	if len(allowed) != 0 || len(denials) != 0 {
		t.Fatalf("报错时不得给出任何准入结果: %v %v", allowed, denials)
	}
	if _, err := NewKnowledgeScope(chain, policy.LevelInternal, allowed); err != nil {
		t.Fatalf("空准入集合应能构成合法范围（含义是「一个都不许碰」）: %v", err)
	}
}

func TestAdmitKnowledgeBasesUsesPolicyEngine(t *testing.T) {
	chain := chainOf(t, subjectAlice, orgExample, projExample)
	ctx := admitContext(t, subjectAlice, orgExample, policy.LevelInternal)
	resolver, err := policy.NewResolver(policyVersionV1,
		allowKBRule(subjectAlice, kbHandbook),
		allowKBRule(subjectRival, kbHR),
	)
	if err != nil {
		t.Fatal(err)
	}

	allowed, denials, err := AdmitKnowledgeBases(resolver, ctx, chain, []string{kbHandbook, kbHR, kbHandbook}, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 1 || allowed[0] != kbHandbook {
		t.Fatalf("只应准入 handbook（规则是给 alice 配的）: %v", allowed)
	}
	// 候选集合会去重，所以 hr 只出现在拒绝明细里一次
	if reason := denialFor(t, denials, kbHR); reason != policy.ReasonNoMatchingRule {
		t.Fatalf("未配规则应报 %s，实际 %s", policy.ReasonNoMatchingRule, reason)
	}
	if resolver.Version() != policyVersionV1 {
		t.Fatal("版本串取自内核，不允许本包自造")
	}
}

func TestAdmitKnowledgeBasesDenyBeatsAllow(t *testing.T) {
	chain := chainOf(t, subjectAlice, orgExample, projExample)
	ctx := admitContext(t, subjectAlice, orgExample, policy.LevelInternal)
	resolver, err := policy.NewResolver(policyVersionV1,
		allowKBRule(subjectAlice, kbHandbook),
		denyKBRule(subjectAlice, kbHandbook),
	)
	if err != nil {
		t.Fatal(err)
	}

	allowed, denials, err := AdmitKnowledgeBases(resolver, ctx, chain, []string{kbHandbook}, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 0 {
		t.Fatalf("deny 必须压过 allow: %v", allowed)
	}
	// 拒绝明细里的原因码必须是 A 包注册的码（不是本包自造的字串）
	reason := denialFor(t, denials, kbHandbook)
	if reason != policy.ReasonDenyRule {
		t.Fatalf("应报 %s，实际 %s", policy.ReasonDenyRule, reason)
	}
	if !reason.Valid() {
		t.Fatal("拒绝原因码未在策略层注册")
	}
}

func TestAdmitKnowledgeBasesHonoursExpiry(t *testing.T) {
	chain := chainOf(t, subjectAlice, orgExample, projExample)
	ctx := admitContext(t, subjectAlice, orgExample, policy.LevelInternal)
	expired := allowKBRule(subjectAlice, kbHandbook)
	expired.ExpiresAt = after(-time.Minute)
	resolver, err := policy.NewResolver(policyVersionV1, expired)
	if err != nil {
		t.Fatal(err)
	}

	allowed, denials, err := AdmitKnowledgeBases(resolver, ctx, chain, []string{kbHandbook}, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 0 {
		t.Fatalf("过期授权不得继续准入: %v", allowed)
	}
	if reason := denialFor(t, denials, kbHandbook); reason != policy.ReasonEntitlementExpired {
		t.Fatalf("要能区分「没配」和「配过但过期」，实际 %s", reason)
	}

	// 同一份规则，在过期之前判定结果应当反过来
	before := expired.ExpiresAt.Add(-time.Minute)
	allowedEarlier, _, err := AdmitKnowledgeBases(resolver, ctx, chain, []string{kbHandbook}, before)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowedEarlier) != 1 {
		t.Fatalf("过期前应当准入: %v", allowedEarlier)
	}
}

func TestAdmitKnowledgeBasesRespectsScope(t *testing.T) {
	// 规则只发给邻组织的库范围：alice 的范围集合里没有它，就不该准入。
	rivalRule := allowKBRule("*", kbRivalLab)
	rivalRule.Scope = policy.MustScope(policy.ScopeOrganization, orgRival).Display()
	resolver, err := policy.NewResolver(policyVersionV1, rivalRule)
	if err != nil {
		t.Fatal(err)
	}

	aliceChain := chainOf(t, subjectAlice, orgExample, projExample)
	aliceCtx := admitContext(t, subjectAlice, orgExample, policy.LevelInternal)
	allowed, _, err := AdmitKnowledgeBases(resolver, aliceCtx, aliceChain, []string{kbRivalLab}, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 0 {
		t.Fatalf("跨组织知识库不得被准入: %v", allowed)
	}

	malloryChain := chainOf(t, subjectRival, orgRival, "")
	malloryCtx := admitContext(t, subjectRival, orgRival, policy.LevelInternal)
	got, _, err := AdmitKnowledgeBases(resolver, malloryCtx, malloryChain, []string{kbRivalLab}, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != kbRivalLab {
		t.Fatalf("邻组织主体应准入自己的库: %v", got)
	}
}

func TestAdmitKnowledgeBasesRejectsDirtyIDs(t *testing.T) {
	chain := chainOf(t, subjectAlice, orgExample, projExample)
	ctx := admitContext(t, subjectAlice, orgExample, policy.LevelInternal)
	resolver, err := policy.NewResolver(policyVersionV1, allowKBRule("*", "ok-kb"))
	if err != nil {
		t.Fatal(err)
	}

	allowed, denials, err := AdmitKnowledgeBases(resolver, ctx, chain,
		[]string{"bad kb", "bad:kb", "ok-kb", "  "}, baseNow)
	if err != nil {
		t.Fatal("脏 ID 属于拒绝明细，不该让整个准入失败")
	}
	if len(allowed) != 1 || allowed[0] != "ok-kb" {
		t.Fatalf("只应准入形态合规的库: %v", allowed)
	}
	if len(denials) != 2 {
		t.Fatalf("两个脏 ID 都要进拒绝明细: %+v", denials)
	}
	for _, d := range denials {
		if d.Reason != policy.ReasonContextInvalid {
			t.Fatalf("脏 ID 应报 %s，实际 %s", policy.ReasonContextInvalid, d.Reason)
		}
	}

	// 空范围集合：拒绝而不是按「不限范围」处理（照抄 A 包约定）
	if _, _, err := AdmitKnowledgeBases(resolver, ctx, nil, []string{"ok-kb"}, baseNow); err == nil {
		t.Fatal("空 chain 必须报错")
	} else if !errors.Is(err, ErrAdmission) {
		t.Fatalf("应报 ErrAdmission，实际 %v", err)
	}
}

// TestAdmissionFeedsScopeAndAuditEndToEnd 把「A 判准入 → C 建范围 → 委托 → 审计」串起来，
// 并验证策略版本严格取自实际加载的策略包（手册 §3.0）。
func TestAdmissionFeedsScopeAndAuditEndToEnd(t *testing.T) {
	chain := chainOf(t, subjectAlice, orgExample, projExample)
	ctx := admitContext(t, subjectAlice, orgExample, policy.LevelInternal)

	set := policy.MustBundleSet(policy.PolicyBundle{
		ID:      "example-default",
		Version: 1,
		Scope:   policy.SystemScope,
		Entitlements: []policy.Entitlement{
			allowKBRule(subjectAlice, kbHandbook),
			allowKBRule(subjectAlice, kbHR),
		},
	})
	version, err := admittedVersion(set, chain)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := policy.FromBundles(set, chain)
	if err != nil {
		t.Fatal(err)
	}
	if resolver.Version() != version {
		t.Fatalf("准入用的内核与出具版本的策略包集合必须是同一份: %s vs %s", resolver.Version(), version)
	}

	allowed, denials, err := AdmitKnowledgeBases(resolver, ctx, chain,
		[]string{kbHandbook, kbHR, kbRivalLab}, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 2 || len(denials) != 1 {
		t.Fatalf("准入结果不正确: %v %+v", allowed, denials)
	}
	if denialFor(t, denials, kbRivalLab) != policy.ReasonNoMatchingRule {
		t.Fatal("未配规则的知识库必须被拒")
	}

	scope, err := NewKnowledgeScope(chain, policy.LevelInternal, allowed)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := NewRequestContext("req-admit", subjectAlice, chain, "qa", policy.LevelInternal, version, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if rc.PolicyVersion != version || !strings.Contains(version, "example-default@1") {
		t.Fatalf("上下文版本串必须来自策略包: %s", rc.PolicyVersion)
	}

	fake := fixtureRetriever()
	liveRC := rc
	// 委托请求里的白名单必须正好是准入结果，未准入的库连请求都不该带上
	req, err := BuildRequest(liveRC, scope, Query{Terms: "报销"}, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(req.KnowledgeBases) != 2 || req.KnowledgeBases[0] != kbHandbook || req.KnowledgeBases[1] != kbHR {
		t.Fatalf("请求白名单不正确: %v", req.KnowledgeBases)
	}
	for _, kb := range req.KnowledgeBases {
		if kb == kbRivalLab {
			t.Fatal("未准入的知识库出现在委托请求里")
		}
	}

	// 用真实时钟走一遍委托，确认准入结果直接决定了源侧能看到的范围
	_, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	liveRC.IssuedAt = now
	liveRC.Deadline = now.Add(DefaultBudget)
	liveRC.Budget = DefaultBudget
	liveRC.PolicyVersion = version
	outcome, err := Resolve(context.Background(), fake, liveRC, scope, Query{Terms: "报销"}, now)
	if err != nil {
		t.Fatalf("检索失败: %v", err)
	}
	if outcome.Audit.PolicyVersion != version {
		t.Fatalf("审计版本必须与准入所用的策略包版本一致: %s vs %s", outcome.Audit.PolicyVersion, version)
	}
	if len(outcome.Audit.QueriedBases) != 2 {
		t.Fatalf("只应查询准入的两个库: %v", outcome.Audit.QueriedBases)
	}
	for _, c := range outcome.Citations {
		if !scope.AllowsKB(c.KnowledgeBase) {
			t.Fatalf("引用里出现未准入的知识库 %s", c.KnowledgeBase)
		}
	}

	// 策略包升版：版本串必须变，审计要能归因
	bumped := policy.MustBundleSet(policy.PolicyBundle{
		ID:      "example-default",
		Version: 2,
		Scope:   policy.SystemScope,
		Entitlements: []policy.Entitlement{
			allowKBRule(subjectAlice, kbHandbook),
		},
	})
	newVersion, err := admittedVersion(bumped, chain)
	if err != nil {
		t.Fatal(err)
	}
	if newVersion == version {
		t.Fatal("策略包升版后版本串没变，审计就无法归因")
	}
	newResolver, err := policy.FromBundles(bumped, chain)
	if err != nil {
		t.Fatal(err)
	}
	after, _, err := AdmitKnowledgeBases(newResolver, ctx, chain, []string{kbHandbook, kbHR}, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0] != kbHandbook {
		t.Fatalf("v2 撤掉了 hr 授权，准入集合必须跟着变小: %v", after)
	}
}

// admittedVersion 是「策略版本唯一来源」的样板写法：BundleSet.Filter(chain).PolicyVersion()。
func admittedVersion(set *policy.BundleSet, chain policy.ScopeChain) (string, error) {
	subset, err := set.Filter(chain)
	if err != nil {
		return "", err
	}
	return subset.PolicyVersion()
}
