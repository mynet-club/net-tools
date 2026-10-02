package policy

import (
	"math/rand"
	"strings"
	"testing"
)

func bundle(id string, version int, scope ScopeRef, rules ...Entitlement) PolicyBundle {
	return PolicyBundle{ID: id, Version: version, Scope: scope, Entitlements: rules}
}

func TestBundleValidation(t *testing.T) {
	if err := bundle("", 1, SystemScope).Validate(); err == nil {
		t.Fatal("空 id 必须拒绝")
	}
	if err := bundle("bad|id", 1, SystemScope).Validate(); err == nil {
		t.Fatal("id 含 | 会破坏版本串分节，必须拒绝")
	}
	if err := bundle("ok", 0, SystemScope).Validate(); err == nil {
		t.Fatal("version 0 无法与「未填」区分，必须拒绝")
	}
	if err := bundle("ok", 1, SystemScope, Entitlement{Subject: "alice", Resource: "model:*", Action: "use", Effect: Effect("maybe")}).Validate(); err == nil {
		t.Fatal("规则不合法必须让整包校验失败")
	}
	if err := bundle("ok", 1, ScopeRef{}).Validate(); err == nil {
		t.Fatal("scope 缺失必须拒绝")
	}
}

// 条件的未知键必须在加载期拒绝：判定期它是 fail-closed（规则不生效），
// 于是 `max_data_level` 这种下划线写法会让一条 deny 静默失效 —— 包照常加载、
// 版本照常进审计，敏感流量却一路放行。
func TestUnknownConditionKeyFailsAtLoad(t *testing.T) {
	typo := bundle("typo-cond", 1, SystemScope, Entitlement{
		Subject: "*", Resource: "model:secret", Action: "use", Effect: EffectDeny,
		Conditions: map[string]string{"max_data_level": "internal"},
	})
	err := typo.Validate()
	if err == nil {
		t.Fatal("未知条件键必须让整包校验失败，而不是留到判定期静默不命中")
	}
	for _, want := range []string{"max_data_level", "max-data-level", "purpose", "auth-method"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息要同时点名写错的键并列出可用键，缺 %q: %v", want, err)
		}
	}

	// 保留键一律放行；多个未知键要按固定顺序点名（错误信息也进排查记录）。
	if err := bundle("ok-cond", 1, SystemScope, Entitlement{
		Subject: "*", Resource: "model:*", Action: "use", Effect: EffectAllow,
		Conditions: map[string]string{CondMaxDataLevel: "internal", CondPurpose: "chat"},
	}).Validate(); err != nil {
		t.Errorf("保留键不该被拒: %v", err)
	}
	multi := bundle("two-typo", 1, SystemScope, Entitlement{
		Subject: "*", Resource: "model:*", Action: "use", Effect: EffectAllow,
		Conditions: map[string]string{"zeta": "1", "alpha": "2"},
	})
	if err := multi.Validate(); err == nil || !strings.Contains(err.Error(), "alpha, zeta") {
		t.Errorf("多个未知键要按固定顺序列出: %v", err)
	}
}

// PolicyVersion 是审计与回放的输入，必须在任何构造顺序下逐位一致。
func TestBundleSetVersionIsOrderIndependent(t *testing.T) {
	bundles := []PolicyBundle{
		bundle("university-default", 3, MustScope(ScopeOrganization, "university"), allowRule("role:student", "model:*", "use")),
		bundle("system-base", 1, SystemScope, allowRule("*", "model:gpt-5", "use")),
		bundle("lab-project", 7, MustScope(ScopeProject, "proj-lab-7")),
	}
	first, err := MustBundleSet(bundles...).PolicyVersion()
	if err != nil {
		t.Fatalf("版本串生成失败: %v", err)
	}
	if strings.Count(first, "@") != 3 {
		t.Fatalf("版本串应包含三个 stamp: %s", first)
	}
	for round := 0; round < 40; round++ {
		shuffled := append([]PolicyBundle(nil), bundles...)
		rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		got, err := MustBundleSet(shuffled...).PolicyVersion()
		if err != nil {
			t.Fatal(err)
		}
		if got != first {
			t.Fatalf("构造顺序改变后版本串不同:\n%s\n%s", first, got)
		}
	}
	// 内容版本必须随版本号变化 —— 回放要靠它确认加载的是同一份规则。
	bumped := append([]PolicyBundle(nil), bundles...)
	bumped[1].Version = 2
	second, err := MustBundleSet(bumped...).PolicyVersion()
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("改了版本号版本串必须变化")
	}
	if !strings.Contains(second, "system-base@2") || strings.Contains(second, "system-base@1") {
		t.Fatalf("版本串内容不对: %s", second)
	}
}

func TestBundleSetRejectsDuplicatesAndEmpty(t *testing.T) {
	if _, err := NewBundleSet(
		bundle("core", 1, SystemScope),
		bundle("core", 2, MustScope(ScopeUser, "alice")),
	); err == nil {
		t.Fatal("同一 id 出现两个版本说明加载逻辑出错，必须拒绝")
	}
	// 空集合不能产出空版本串：那等于允许「无版本决策」进审计。
	if _, err := NewBundleSet(); err != nil {
		t.Fatalf("空集合本身合法: %v", err)
	}
	if _, err := MustBundleSet().PolicyVersion(); err == nil {
		t.Fatal("没有任何策略包时 PolicyVersion 必须报错")
	}
	if _, err := MustBundleSet(bundle("core", 1, MustScope(ScopeOrganization, "university"))).
		Filter(chain(MustScope(ScopeOrganization, "other"))); err == nil {
		t.Fatal("范围不匹配时 Filter 必须报错，而不是返回空集合")
	}
}

func TestBundleCoversAndEntitlementsFor(t *testing.T) {
	set := MustBundleSet(
		bundle("system-base", 1, SystemScope, allowRule("*", "model:gpt-5", "use")),
		bundle("uni", 2, MustScope(ScopeOrganization, "university"), allowRule("role:student", "model:claude", "use")),
		bundle("other-org", 4, MustScope(ScopeOrganization, "hospital"), denyRule("role:student", "model:*", "use")),
	)
	// 只有用户范围时，系统包生效、组织包不生效。
	got := set.EntitlementsFor(chain(MustScope(ScopeUser, "alice")))
	if len(got) != 1 || got[0].Subject != "*" {
		t.Fatalf("用户范围只应拿到系统包规则: %+v", got)
	}
	// 完整 chain（用户 + 组织 + 项目）：组织包必须参与 —— 这正是单 scope 接口会让
	// 组织级策略失效的地方。
	full := chainOf(t, "alice", "university", "proj-lab-7")
	got = set.EntitlementsFor(full)
	if len(got) != 2 {
		t.Fatalf("chain 命中组织时应拿到系统包 + 本组织包: %+v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].SortKey() > got[i].SortKey() {
			t.Fatal("并集必须按 SortKey 稳定排序")
		}
	}
	if len(set.EntitlementsFor(chainOf(t, "alice", "hospital", ""))) != 2 {
		t.Fatal("另一家组织的 chain 应拿到系统包 + 它自己的包")
	}
	find := func(id string) PolicyBundle {
		for _, b := range set.Bundles() {
			if b.ID == id {
				return b
			}
		}
		t.Fatalf("找不到策略包 %s", id)
		return PolicyBundle{}
	}
	if !find("system-base").Covers(chain(MustScope(ScopeProject, "p"))) {
		t.Fatal("系统包应覆盖任意范围")
	}
	if find("uni").Covers(chain(MustScope(ScopeProject, "p"))) {
		t.Fatal("组织包不会仅因为「项目隶属于它」就生效：归属关系由各适配器展开成 chain")
	}
	if !find("uni").Covers(chainOf(t, "alice", "university", "p")) {
		t.Fatal("chain 里带了该组织范围时，组织包必须生效")
	}
}

func TestFromBundlesCarriesSetVersion(t *testing.T) {
	set := MustBundleSet(
		bundle("system-base", 1, SystemScope, allowRule("*", "model:gpt-5", "use")),
		bundle("uni", 2, MustScope(ScopeOrganization, "university"), denyRule("role:student", "model:claude", "use")),
	)
	scope := chain(MustScope(ScopeOrganization, "university"))
	r, err := FromBundles(set, scope)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	want, _ := set.Filter(scope)
	wantVersion, _ := want.PolicyVersion()
	if r.Version() != wantVersion {
		t.Fatalf("版本必须取自实际生效的包集合:\n%s\n%s", r.Version(), wantVersion)
	}
	if r.RuleCount() != 2 {
		t.Fatalf("应合并两条规则，实际 %d", r.RuleCount())
	}
	// 重复规则去重：同一内容出现在两个包里不改变结论，只该少一条记录。
	dup := MustBundleSet(
		bundle("a", 1, SystemScope, allowRule("*", "model:gpt-5", "use")),
		bundle("b", 1, MustScope(ScopeOrganization, "university"), allowRule("*", "model:gpt-5", "use")),
	)
	rd, err := FromBundles(dup, scope)
	if err != nil {
		t.Fatal(err)
	}
	if rd.RuleCount() != 1 {
		t.Fatalf("重复规则应去重，实际 %d", rd.RuleCount())
	}
	if _, err := FromBundles(nil, scope); err == nil {
		t.Fatal("空策略集必须拒绝")
	}
}
