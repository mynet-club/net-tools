package policy

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"
)

func allowRule(subject, resource, action string) Entitlement {
	return Entitlement{Subject: subject, Resource: resource, Action: action, Effect: EffectAllow}
}

func denyRule(subject, resource, action string) Entitlement {
	return Entitlement{Subject: subject, Resource: resource, Action: action, Effect: EffectDeny}
}

func mustResolver(t *testing.T, version string, rules ...Entitlement) *Resolver {
	t.Helper()
	r, err := NewResolver(version, rules...)
	if err != nil {
		t.Fatalf("构造策略内核失败: %v", err)
	}
	return r
}

// eval 用「alice 是学生、属于 cs 组、org=university、project=proj-lab-7」这套高校上下文求值。
func eval(t *testing.T, r *Resolver, level DataLevel, resource, action string) Decision {
	t.Helper()
	id := student(t, "alice", []string{"student"}, []string{"cs"})
	ctx := ctxOf(t, id, "qa", level)
	ctx.Organization = "university"
	ctx.Project = "proj-lab-7"
	return r.Evaluate(ctx, chain(MustScope(ScopeUser, "alice")), resource, action, baseNow)
}

func TestDenyBeatsExplicitAllow(t *testing.T) {
	// deny > explicit_allow > group_allow > default：这是 §2.4 唯一的次序，
	// 任何一条规则都不能靠「写得更具体」越过 deny。
	r := mustResolver(t, "core@1",
		allowRule("alice", "model:gpt-5", "use"),
		denyRule("role:student", "model:*", "use"),
	)
	d := eval(t, r, LevelInternal, "model:gpt-5", "use")
	if d.Allowed {
		t.Fatalf("deny 必须压过点名 allow，实际放行: %+v", d)
	}
	if d.Reason != ReasonModelNotAllowed {
		t.Fatalf("模型资源的拒绝应给出 model_not_allowed，实际 %s", d.Reason)
	}
	if !containsReason(d.Reasons, ReasonDenyRule) {
		t.Fatalf("原因链应保留 deny_rule: %v", d.Reasons)
	}
	if len(d.Matched) == 0 || d.Matched[0].Effect != EffectDeny {
		t.Fatalf("首条命中必须是 deny: %+v", d.Matched)
	}
	if d.PolicyVersion != "core@1" {
		t.Fatalf("版本串必须透传: %s", d.PolicyVersion)
	}
	// 同一条 deny 换了主体（教师不受限）就应当放行 —— 证明判定确实按主体选择器走。
	r2 := mustResolver(t, "core@1",
		allowRule("alice", "model:gpt-5", "use"),
		denyRule("role:student", "model:*", "use"),
		Entitlement{Subject: "role:teacher", Resource: "model:gpt-5", Action: "use", Effect: EffectAllow},
	)
	teacherID := student(t, "bob", []string{"teacher"}, []string{"cs"})
	ctx := ctxOf(t, teacherID, "research", LevelInternal)
	if got := r2.Evaluate(ctx, chain(MustScope(ScopeUser, "bob")), "model:gpt-5", "use", baseNow); !got.Allowed {
		t.Fatalf("教师不受该 deny 约束，应放行: %+v", got)
	}
}

func TestAllowPrecedenceOrder(t *testing.T) {
	r := mustResolver(t, "core@1",
		allowRule("*", "model:gpt-5", "use"),        // default
		allowRule("group:cs", "model:gpt-5", "use"), // group
		allowRule("alice", "model:gpt-5", "use"),    // explicit
	)
	d := eval(t, r, LevelInternal, "model:gpt-5", "use")
	if !d.Allowed || d.Reason != ReasonExplicitAllow {
		t.Fatalf("点名 allow 应优先，实际 %s", d.Reason)
	}
	if d.Matched[0].Precedence != PrecedenceExplicitAllow {
		t.Fatalf("档位记录不对: %+v", d.Matched[0])
	}

	// 去掉点名规则 → 组级
	r2 := mustResolver(t, "core@1",
		allowRule("*", "model:gpt-5", "use"),
		allowRule("group:cs", "model:gpt-5", "use"),
	)
	if d2 := eval(t, r2, LevelInternal, "model:gpt-5", "use"); d2.Reason != ReasonGroupAllow {
		t.Fatalf("应落到 group_allow，实际 %s", d2.Reason)
	}

	// 只剩通配 → default
	r3 := mustResolver(t, "core@1", allowRule("*", "model:gpt-5", "use"))
	if d3 := eval(t, r3, LevelInternal, "model:gpt-5", "use"); d3.Reason != ReasonDefaultAllow {
		t.Fatalf("应落到 default_allow，实际 %s", d3.Reason)
	}

	// 什么都不配 → 拒绝（fail-closed）。3.0 不能把「没配策略」解释成「全放行」。
	r4 := mustResolver(t, "core@1", allowRule("alice", "model:other", "use"))
	d4 := eval(t, r4, LevelInternal, "model:gpt-5", "use")
	if d4.Allowed || d4.Reason != ReasonModelNotAllowed {
		t.Fatalf("缺席即否：实际 %+v", d4)
	}
}

func TestExpiryAndIdentityValidity(t *testing.T) {
	// 规则过期：区分「没配」和「配过但过期」。
	expired := allowRule("alice", "capability:web-search", "use")
	expired.ExpiresAt = baseNow.Add(-time.Minute)
	r := mustResolver(t, "core@1", expired)
	d := eval(t, r, LevelInternal, "capability:web-search", "use")
	if d.Allowed || d.Reason != ReasonEntitlementExpired {
		t.Fatalf("过期规则应给出 entitlement_expired，实际 %+v", d)
	}

	// 恰好到点：ExpiresAt 是硬边界，now == ExpiresAt 即失效。
	atBoundary := allowRule("alice", "capability:web-search", "use")
	atBoundary.ExpiresAt = baseNow
	if !atBoundary.expired(baseNow) {
		t.Fatal("ExpiresAt == now 必须视为已过期")
	}

	// 身份过期：直接拒，不看规则。
	dead := student(t, "alice", []string{"student"}, []string{"cs"})
	dead.ExpiresAt = baseNow.Add(-time.Second)
	deadCtx, err := NewPolicyContext(dead, "qa", LevelInternal)
	if err != nil {
		t.Fatalf("上下文构造失败: %v", err)
	}
	r2 := mustResolver(t, "core@1", allowRule("*", "capability:web-search", "use"))
	if d2 := r2.Evaluate(deadCtx, chain(MustScope(ScopeUser, "alice")), "capability:web-search", "use", baseNow); d2.Reason != ReasonIdentityExpired {
		t.Fatalf("身份过期应短路拒绝，实际 %+v", d2)
	}

	// 上下文缺 purpose → 拒绝而不是按默认走。
	noPurpose := PolicyContext{Identity: student(t, "alice", []string{"student"}, nil), DataLevel: LevelInternal}
	r3 := mustResolver(t, "core@1", allowRule("*", "model:*", "use"))
	if d3 := r3.Evaluate(noPurpose, chain(MustScope(ScopeUser, "alice")), "model:gpt-5", "use", baseNow); d3.Allowed || d3.Reason != ReasonContextInvalid {
		t.Fatalf("上下文不合法必须拒绝: %+v", d3)
	}
}

func TestDataLevelConditions(t *testing.T) {
	// allow + max-data-level：只允许到 confidential 为止。
	r := mustResolver(t, "core@1",
		Entitlement{Subject: "role:student", Resource: "model:gpt-5", Action: "use",
			Effect: EffectAllow, Conditions: map[string]string{CondMaxDataLevel: "confidential"}},
	)
	if d := eval(t, r, LevelConfidential, "model:gpt-5", "use"); !d.Allowed {
		t.Fatalf("confidential 应放行: %+v", d)
	}
	restricted := student(t, "alice", []string{"student"}, []string{"cs"})
	rctx, err := NewPolicyContext(restricted, "qa", LevelRestricted)
	if err != nil {
		t.Fatal(err)
	}
	d := r.Evaluate(rctx, chain(MustScope(ScopeUser, "alice")), "model:gpt-5", "use", baseNow)
	if d.Allowed {
		t.Fatalf("restricted 超出上界，必须拒绝: %+v", d)
	}
	// 关键：结论必须是 data_level_denied，而不是 no_matching_rule ——
	// 否则运维会以为白名单没配，实际是分级越界。
	if d.Reason != ReasonDataLevelDenied {
		t.Fatalf("应给出 data_level_denied，实际 %s", d.Reason)
	}

	// deny + min-data-level：confidential 及以上一律禁止。
	r2 := mustResolver(t, "core@1",
		allowRule("role:student", "model:gpt-5", "use"),
		denyRule("role:student", "model:gpt-5", "use").withCondition(CondMinDataLevel, "confidential"),
	)
	if d2 := eval(t, r2, LevelInternal, "model:gpt-5", "use"); !d2.Allowed {
		t.Fatalf("internal 不该触发该 deny: %+v", d2)
	}
	if d3 := eval(t, r2, LevelConfidential, "model:gpt-5", "use"); d3.Allowed || d3.Reason != ReasonModelNotAllowed || !containsReason(d3.Reasons, ReasonDenyRule) {
		t.Fatalf("confidential 必须被 deny 拦下: %+v", d3)
	}
}

func (e Entitlement) withCondition(key, value string) Entitlement {
	copied := make(map[string]string, len(e.Conditions)+1)
	for k, v := range e.Conditions {
		copied[k] = v
	}
	copied[key] = value
	e.Conditions = copied
	return e
}

func TestConditionMembershipAndUnknownKey(t *testing.T) {
	cases := []struct {
		name       string
		conditions map[string]string
		allow      bool
	}{
		{"角色满足", map[string]string{CondRole: "student"}, true},
		{"角色不满足", map[string]string{CondRole: "teacher"}, false},
		{"组满足", map[string]string{CondGroup: "cs"}, true},
		{"认证方式满足", map[string]string{CondAuthMethod: "mfa"}, true},
		{"用途满足", map[string]string{CondPurpose: "qa"}, true},
		{"用途不满足", map[string]string{CondPurpose: "batch"}, false},
		{"组织满足", map[string]string{CondOrganization: "university"}, true},
		{"来源满足", map[string]string{CondSource: "oidc:university"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rule := allowRule("alice", "model:gpt-5", "use")
			rule.Conditions = c.conditions
			d := eval(t, mustResolver(t, "core@1", rule), LevelInternal, "model:gpt-5", "use")
			if d.Allowed != c.allow {
				t.Fatalf("期望 allowed=%v，实际 %+v", c.allow, d)
			}
		})
	}
	// 未知键在**判定期**也是 fail-closed，但这一层只是纵深防御：
	// Entitlement.Validate 会在加载期先拒掉它（见 TestUnknownConditionKeyFailsAtLoad），
	// 因为「规则静默不命中」对 deny 规则等于把禁令关掉。这里直接调 conditionsMet，
	// 绕过 Validate 才能测到判定核自己的行为。
	unknown := allowRule("alice", "model:gpt-5", "use")
	unknown.Conditions = map[string]string{"my-company-key": "x"}
	ctx := ctxOf(t, student(t, "alice", []string{"student"}, []string{"cs"}), "qa", LevelInternal)
	if ok, reason := unknown.conditionsMet(ctx); ok {
		t.Errorf("未知条件键不该让规则生效，实际原因 %q", reason)
	} else if reason != ReasonConditionUnmet {
		t.Errorf("未知条件键的原因应是 condition_unmet，实际 %q", reason)
	}
	// 多条键同时不成立时，原因码不能随 map 遍历顺序变化。
	multi := allowRule("alice", "model:gpt-5", "use")
	multi.Conditions = map[string]string{CondRole: "teacher", CondPurpose: "batch"}
	seen := map[Reason]bool{}
	for i := 0; i < 200; i++ {
		seen[eval(t, mustResolver(t, "core@1", multi), LevelInternal, "model:gpt-5", "use").Reason] = true
	}
	if len(seen) != 1 {
		t.Fatalf("原因链出现抖动: %v", seen)
	}
}

func TestScopeAndWildcardMatching(t *testing.T) {
	rule := allowRule("alice", "model:*", "use")
	rule.Scope = "organization:university"
	r := mustResolver(t, "core@1", rule)
	id := student(t, "alice", []string{"student"}, []string{"cs"})
	ctx := ctxOf(t, id, "qa", LevelInternal)
	// 规则限定组织范围，评到项目范围时必须不生效。
	if d := r.Evaluate(ctx, chain(MustScope(ScopeProject, "proj-lab-7")), "model:gpt-5", "use", baseNow); d.Allowed {
		t.Fatal("scope 不匹配不应命中")
	}
	if d := r.Evaluate(ctx, chain(MustScope(ScopeOrganization, "university")), "model:gpt-5", "use", baseNow); !d.Allowed {
		t.Fatal("scope 匹配时应命中")
	}
	// 动作也必须匹配：use 授权不等于 invoke。
	if d := r.Evaluate(ctx, chain(MustScope(ScopeOrganization, "university")), "model:gpt-5", "invoke", baseNow); d.Allowed {
		t.Fatal("action 不匹配不应命中")
	}
	// 中间通配的资源在构造期就报错，不会静默失配。
	if _, err := NewResolver("core@1", allowRule("alice", "mo*el:gpt", "use")); err == nil {
		t.Fatal("中间通配资源必须被拒绝")
	}
}

// TestRuleOrderIndependent 落实「判定不依赖规则书写顺序」。
// 同一条 deny 挪到数组任何位置，结论都必须逐位相同 —— 否则 bundle 重排就是一次静默改策略。
func TestRuleOrderIndependent(t *testing.T) {
	rules := []Entitlement{
		allowRule("*", "model:gpt-5", "use"),
		denyRule("group:cs", "model:gpt-5", "use"),
		allowRule("alice", "model:gpt-5", "use"),
		allowRule("group:cs", "model:gpt-5", "use"),
		denyRule("role:student", "model:gpt-5", "use"),
	}
	var want string
	shuffled := append([]Entitlement(nil), rules...)
	for round := 0; round < 50; round++ {
		rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		d := eval(t, mustResolver(t, "core@1", shuffled...), LevelInternal, "model:gpt-5", "use")
		blob, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		if want == "" {
			want = string(blob)
			continue
		}
		if string(blob) != want {
			t.Fatalf("第 %d 轮判定随规则顺序发生变化:\n%s\n%s", round, want, blob)
		}
	}
	if want == "" {
		t.Fatal("没有产生任何判定")
	}
}

// TestOrganizationPolicyAppliesThroughChain 锁住这次修正的根因：
// 请求同时属于用户、组织和项目三个范围，只传一个 ScopeRef 的话，
// 组织级 deny 对个体请求完全不生效 —— 集团型组织的策略会整层失效。
func TestOrganizationPolicyAppliesThroughChain(t *testing.T) {
	set := MustBundleSet(
		bundle("base", 1, SystemScope, allowRule("*", "model:gpt-5", "use")),
		bundle("uni", 1, MustScope(ScopeOrganization, "university"),
			denyRule("*", "model:gpt-5", "use").withCondition(CondMinDataLevel, "confidential")),
	)
	r, err := FromBundles(set, chainOf(t, "alice", "university", "proj-lab-7"))
	if err != nil {
		t.Fatal(err)
	}
	id := student(t, "alice", []string{"student"}, []string{"cs"})
	full := chainOf(t, "alice", "university", "proj-lab-7")
	if d := r.Evaluate(ctxOf(t, id, "qa", LevelInternal), full, "model:gpt-5", "use", baseNow); !d.Allowed {
		t.Fatalf("internal 不受该 deny 约束，应放行: %+v", d)
	}
	d := r.Evaluate(ctxOf(t, id, "qa", LevelRestricted), full, "model:gpt-5", "use", baseNow)
	if d.Allowed || d.Reason != ReasonModelNotAllowed || !containsReason(d.Reasons, ReasonDenyRule) {
		t.Fatalf("组织级 deny 必须生效: %+v", d)
	}
	// 同一个人换到没有该策略的组织，结论就该翻转 —— 证明生效面确实来自 chain。
	elsewhere, err := FromBundles(set, chainOf(t, "alice", "other-org", ""))
	if err != nil {
		t.Fatal(err)
	}
	if d2 := elsewhere.Evaluate(ctxOf(t, id, "qa", LevelRestricted), chainOf(t, "alice", "other-org", ""), "model:gpt-5", "use", baseNow); !d2.Allowed {
		t.Fatalf("范围外不应套用该 deny: %+v", d2)
	}
	// 空 chain 直接拒绝，不当成「不限范围」。
	if d3 := r.Evaluate(ctxOf(t, id, "qa", LevelInternal), nil, "model:gpt-5", "use", baseNow); d3.Allowed || d3.Reason != ReasonScopeMismatch {
		t.Fatalf("空范围集合必须拒绝: %+v", d3)
	}
}

func TestAllowsRawBody(t *testing.T) {
	// §2.9 规则 4：原文授权只能由管理员策略显式授予，且必须带期限。
	// 通配 default_allow 一律不算授权 —— 否则加一条全局兜底放行就顺手把原文发出网。
	wildcard := allowRule("*", ResourceBodyRaw, ActionRead)
	wildcard.ExpiresAt = hoursAfter(1)
	if ok, why := mustResolver(t, "core@1", wildcard).AllowsRawBody(
		ctxOf(t, student(t, "alice", nil, nil), "qa", LevelInternal),
		chain(MustScope(ScopeUser, "alice")), baseNow); ok {
		t.Fatalf("通配放行不得授予原文出网: %s", why)
	}

	noExpiry := allowRule("alice", ResourceBodyRaw, ActionRead)
	if ok, why := mustResolver(t, "core@1", noExpiry).AllowsRawBody(
		ctxOf(t, student(t, "alice", nil, nil), "qa", LevelInternal),
		chain(MustScope(ScopeUser, "alice")), baseNow); ok {
		t.Fatalf("无期限的原文授权必须拒绝: %s", why)
	}

	grant := allowRule("organization:university", ResourceBodyRaw, ActionRead)
	grant.Scope = "organization:university"
	grant.ExpiresAt = hoursAfter(2)
	id := student(t, "alice", []string{"student"}, nil)
	ctx := ctxOf(t, id, "qa", LevelInternal)
	ctx.Organization = "university"
	ok, why := mustResolver(t, "core@1", grant).AllowsRawBody(ctx, chain(MustScope(ScopeOrganization, "university")), baseNow)
	if !ok || why != ReasonGroupAllow {
		t.Fatalf("带期限的组织级授权应当放行: %v %s", ok, why)
	}
	// 过了期限就不行（ExpiresAt 之后，包括身份先过期的情况）。
	if ok, _ := mustResolver(t, "core@1", grant).AllowsRawBody(ctx, chain(MustScope(ScopeOrganization, "university")), hoursAfter(9)); ok {
		t.Fatal("身份 TTL 到点后原文授权必须失效")
	}
}

func TestDecisionCarriesReplayTTL(t *testing.T) {
	// Decision.ExpiresAt 取规则与身份里较早的到期点：下游可以缓存判定，
	// 但缓存时长绝不能超过其中任何一个的 TTL。
	rule := allowRule("alice", "model:gpt-5", "use")
	rule.ExpiresAt = hoursAfter(2)
	d := eval(t, mustResolver(t, "core@1", rule), LevelInternal, "model:gpt-5", "use")
	if !d.ExpiresAt.Equal(hoursAfter(2)) {
		t.Fatalf("应取规则到期点，实际 %s", d.ExpiresAt)
	}
	// student 的 ExpiresAt 是 +8h，规则 +20h → 取 +8h
	shortRule := allowRule("alice", "model:gpt-5", "use")
	shortRule.ExpiresAt = hoursAfter(20)
	d2 := eval(t, mustResolver(t, "core@1", shortRule), LevelInternal, "model:gpt-5", "use")
	if !d2.ExpiresAt.Equal(hoursAfter(8)) {
		t.Fatalf("应取身份到期点，实际 %s", d2.ExpiresAt)
	}
}

func TestResolverRequiresVersion(t *testing.T) {
	if _, err := NewResolver("", allowRule("alice", "model:*", "use")); err == nil {
		t.Fatal("空版本必须拒绝：RoutingPlan.PolicyVersion 不能来自拼接")
	}
	if _, err := NewResolver("core@1", Entitlement{Subject: "alice", Resource: "model:*", Action: "use", Effect: Effect("maybe")}); err == nil {
		t.Fatal("未知 effect 必须拒绝")
	}
	// 版本为空的老内核（直接构造，绕过校验）也必须拒绝出结论。
	legacy := &Resolver{rules: []Entitlement{allowRule("*", "model:*", "use")}}
	id := student(t, "alice", []string{"student"}, nil)
	ctx := ctxOf(t, id, "qa", LevelInternal)
	d := legacy.Evaluate(ctx, chain(MustScope(ScopeUser, "alice")), "model:gpt-5", "use", baseNow)
	if d.Allowed || d.Reason != ReasonPolicyVersionMissing {
		t.Fatalf("无版本判定必须拒绝: %+v", d)
	}
}

// TestResolverConcurrent 是 DoD 4：构造后规则集不可变，可被并发复用。
func TestResolverConcurrent(t *testing.T) {
	r := mustResolver(t, "core@1",
		allowRule("group:cs", "model:gpt-5", "use"),
		denyRule("role:student", "model:claude", "use"),
		allowRule("role:student", "model:claude", "use").withCondition(CondMaxDataLevel, "internal"),
	)
	ids := make([]Identity, 8)
	for i := range ids {
		ids[i] = student(t, fmt.Sprintf("user-%d", i), []string{"student"}, []string{"cs"})
	}
	var wg sync.WaitGroup
	results := make([]Decision, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, err := NewPolicyContext(ids[i%len(ids)], "qa", LevelInternal)
			if err != nil {
				t.Error(err)
				return
			}
			results[i] = r.Evaluate(ctx, chain(MustScope(ScopeUser, ids[i%len(ids)].Subject)), "model:gpt-5", "use", baseNow)
		}(i)
	}
	wg.Wait()
	first := results[0]
	for i, d := range results {
		if d.Allowed != first.Allowed || d.Reason != first.Reason {
			t.Fatalf("第 %d 次并发判定与首次不一致: %+v vs %+v", i, d, first)
		}
	}
}

func containsReason(list []Reason, want Reason) bool {
	for _, r := range list {
		if r == want {
			return true
		}
	}
	return false
}

// TestSubjectSelectorMatchesCanonicalScopes 钉住 §2.7 之后主体选择器的唯一归属口径：
// project:/organization: 只比结构化范围（ctx 的主归属与范围链），不比 claim 原值。
//
// 差别在真实部署里才看得见：目录把「信息学部/计算机学院」规范成 cs 之后，IdP 里
// 另一个恰好叫 "cs" 的组如果还能靠 Identity.Projects 命中 project:cs 的规则，
// 权限就有了第二个判定入口 —— 而接线方只会维护和审计第一个（范围链）。
func TestSubjectSelectorMatchesCanonicalScopes(t *testing.T) {
	r := mustResolver(t, "core@1", allowRule("project:proj-lab-7", "model:gpt-mini", "use"))
	idOnlyRaw := student(t, "alice", []string{"student"}, []string{"cs"})
	ctxRaw := ctxOf(t, idOnlyRaw, "qa", LevelInternal)

	// 只有 claim 原值、链上和 ctx 上都没有这个项目 → 不命中。
	if d := r.Evaluate(ctxRaw, chain(MustScope(ScopeUser, "alice")), "model:gpt-mini", "use", baseNow); d.Allowed {
		t.Fatalf("claim 原值不得成为授权键: %+v", d)
	}

	// 同一个身份，项目进了范围链 → 命中，且档位是组级放行。
	d := r.Evaluate(ctxRaw, chainOf(t, "alice", "university", "proj-lab-7"), "model:gpt-mini", "use", baseNow)
	if !d.Allowed || d.Reason != ReasonGroupAllow {
		t.Fatalf("链上有该项目应组级放行: %+v", d)
	}

	// 接线方只填主归属的最小形态同样命中。
	ctxPrimary := ctxRaw
	ctxPrimary.Organization = "university"
	ctxPrimary.Project = "proj-lab-7"
	if d := r.Evaluate(ctxPrimary, chain(MustScope(ScopeUser, "alice")), "model:gpt-mini", "use", baseNow); !d.Allowed {
		t.Fatalf("ctx.Project 是主归属，应命中: %+v", d)
	}

	// 组织选择器同样只认结构化范围。
	org := mustResolver(t, "core@1", allowRule("organization:university", "model:gpt-mini", "use"))
	if d := org.Evaluate(ctxRaw, chain(MustScope(ScopeUser, "alice")), "model:gpt-mini", "use", baseNow); d.Allowed {
		t.Fatalf("链上没有该组织时不该命中: %+v", d)
	}
	if d := org.Evaluate(ctxRaw, chainOf(t, "alice", "university", ""), "model:gpt-mini", "use", baseNow); !d.Allowed {
		t.Fatalf("链上有该组织应命中: %+v", d)
	}
}

// TestEntitlementRejectsMalformedScopeSelector 证明写错的范围选择器在加载期就红：
// 「配了但永远不命中」是最难排查的一类策略错误。
func TestEntitlementRejectsMalformedScopeSelector(t *testing.T) {
	oversized := strings.Repeat("x", 300)
	for _, subject := range []string{"project:lab:7", "organization:" + oversized, "project:\x01x"} {
		if err := (Entitlement{Subject: subject, Resource: "model:*", Action: "use", Effect: EffectAllow}).Validate(); err == nil {
			t.Fatalf("%q 应当在加载期被拒", subject)
		}
	}
	// 角色与组比的是 claim 原值，不受范围 ID 形态约束。
	for _, subject := range []string{"role:realm:admin", "group:信息学部 计算机学院"} {
		if err := (Entitlement{Subject: subject, Resource: "model:*", Action: "use", Effect: EffectAllow}).Validate(); err != nil {
			t.Fatalf("%q 不该被范围 ID 规则拒: %v", subject, err)
		}
	}
}
