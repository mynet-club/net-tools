package policy

import (
	"strings"
	"testing"
	"time"
)

// 测试基线时间：所有过期判定都显式传 now，不用 wall clock，回放才谈得上确定。
var baseNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func hoursAfter(h int) time.Time { return baseNow.Add(time.Duration(h) * time.Hour) }

// student 造一个带角色和组的高校学生身份。
func student(t *testing.T, subject string, roles, groups []string) Identity {
	t.Helper()
	id, err := NewIdentity(subject, "oidc:university")
	if err != nil {
		t.Fatalf("构造身份失败: %v", err)
	}
	id.Roles = roles
	id.Groups = groups
	id.Projects = []string{"proj-lab-7"}
	id.AuthMethods = []string{"password", "mfa"}
	id.DisplayName = subject + "-student"
	id.IssuedAt = baseNow.Add(-time.Hour)
	id.ExpiresAt = hoursAfter(8)
	id = id.Normalize()
	if err := id.Validate(); err != nil {
		t.Fatalf("身份校验失败: %v", err)
	}
	return id
}

func ctxOf(t *testing.T, id Identity, purpose string, level DataLevel) PolicyContext {
	t.Helper()
	ctx, err := NewPolicyContext(id, purpose, level)
	if err != nil {
		t.Fatalf("构造上下文失败: %v", err)
	}
	return ctx
}

// chain 把单个范围包成判定集合：判定、规则并集与策略包过滤都收 ScopeChain。
func chain(scopes ...ScopeRef) ScopeChain { return MustScopeChain(scopes...) }

// chainOf 构造用户+组织+项目的完整范围集合，这是真实请求的形态。
func chainOf(t *testing.T, userID, orgID, projectID string) ScopeChain {
	t.Helper()
	scopes := []ScopeRef{MustScope(ScopeUser, userID)}
	if orgID != "" {
		scopes = append(scopes, MustScope(ScopeOrganization, orgID))
	}
	if projectID != "" {
		scopes = append(scopes, MustScope(ScopeProject, projectID))
	}
	return chain(scopes...)
}

func TestScopeRefValidation(t *testing.T) {
	cases := []struct {
		name string
		kind ScopeKind
		id   string
		ok   bool
	}{
		{"普通用户", ScopeUser, "u-10086", true},
		{"组织", ScopeOrganization, "university", true},
		{"项目", ScopeProject, "proj-lab-7", true},
		{"系统", ScopeSystem, "global", true},
		{"空 ID", ScopeUser, "", false},
		{"含冒号", ScopeUser, "a:b", false},
		{"含空白", ScopeUser, " a", false},
		{"含控制字符", ScopeUser, "a\x00b", false},
		{"超长 ID", ScopeUser, strings.Repeat("x", maxScopeIDLen+1), false},
		{"未知类型", ScopeKind("tenant"), "x", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := NewScopeRef(c.kind, c.id)
			if !c.ok {
				if err == nil {
					t.Fatalf("应当拒绝 %q:%q", c.kind, c.id)
				}
				return
			}
			if err != nil {
				t.Fatalf("应当通过，实际 %v", err)
			}
			if s.Display() != string(c.kind)+":"+c.id {
				t.Fatalf("Display 形态不对: %s", s.Display())
			}
		})
	}
}

// §2.7：结构化 scope 是两个字段，同 ID 不同 kind 必须是不同范围 ——
// 旧 scope == 用户名的写法正是把 user:university 和 organization:university 混成一个键。
func TestScopeKindSeparatesSameID(t *testing.T) {
	user := MustScope(ScopeUser, "university")
	org := MustScope(ScopeOrganization, "university")
	if user.Is(org) {
		t.Fatal("user:university 与 organization:university 必须不同")
	}
	if user.Less(org) == org.Less(user) {
		t.Fatal("排序必须是全序：两者不可同时小于或同时不小于")
	}
	if !org.Less(user) {
		t.Fatal("organization 应排在 user 之前，排序键要跨进程稳定")
	}
	// Display 只给人看：带冒号的 ID 在构造期就被拒，日志里的范围才能唯一还原。
	if _, err := NewScopeRef(ScopeUser, "a:b"); err == nil {
		t.Fatal("含冒号的 ID 必须拒绝")
	}
}

func TestScopeSelectorMatching(t *testing.T) {
	cases := []struct {
		selector string
		scope    ScopeRef
		ok       bool
	}{
		{"", MustScope(ScopeProject, "p"), true},
		{"*", MustScope(ScopeUser, "u"), true},
		{"user:*", MustScope(ScopeUser, "u"), true},
		{"user:*", MustScope(ScopeProject, "u"), false},
		{"user:alice", MustScope(ScopeUser, "alice"), true},
		{"user:alice", MustScope(ScopeUser, "bob"), false},
		{"organization:university", MustScope(ScopeOrganization, "university"), true},
	}
	for _, c := range cases {
		sel, err := ParseScopeSelector(c.selector)
		if err != nil {
			t.Fatalf("选择器 %q 解析失败: %v", c.selector, err)
		}
		if got := sel.Matches(c.scope); got != c.ok {
			t.Errorf("选择器 %q 对 %s 应当 %v，实际 %v", c.selector, c.scope.Display(), c.ok, got)
		}
	}
	// 裸用户名（不带 kind）必须报错，而不是静默当成 user:*
	if _, err := ParseScopeSelector("alice"); err == nil {
		t.Fatal("裸 alice 这种旧 scope 形式必须被拒绝")
	}
	if _, err := ParseScopeSelector("tenant:x"); err == nil {
		t.Fatal("未知 kind 必须被拒绝")
	}
	if _, err := ParseScopeSelector("user:"); err == nil {
		t.Fatal("缺 ID 的选择器必须被拒绝")
	}
}

func TestIdentityRules(t *testing.T) {
	// 邮箱不能当 subject（§2.1：姓名、邮箱、学号都不是稳定主键）。
	if _, err := NewIdentity("alice@example.com", "oidc"); err == nil {
		t.Fatal("邮箱形态的 subject 必须被拒绝")
	}
	// 显示名不能当关联键。
	if err := (Identity{Subject: "alice", Source: "oidc", DisplayName: "alice"}).Validate(); err == nil {
		t.Fatal("subject 与显示名相同必须被拒绝")
	}
	// 带角色却没有过期时间：一次越权提权会永久生效。
	if err := (Identity{Subject: "alice", Roles: []string{"teacher"}}).Validate(); err == nil {
		t.Fatal("成员关系必须带 ExpiresAt")
	}
	// 无成员关系的机器身份可以不带 TTL。
	if err := (Identity{Subject: "svc-backup", Source: "api_key"}).Validate(); err != nil {
		t.Fatalf("纯 subject 身份不应要求过期时间: %v", err)
	}
	if err := (Identity{Subject: ""}).Validate(); err == nil {
		t.Fatal("空 subject 必须拒绝")
	}
	if err := (Identity{Subject: "a b"}).Validate(); err == nil {
		t.Fatal("含空白的 subject 必须拒绝")
	}
}

func TestIdentityNormalizeAndExpiry(t *testing.T) {
	id := Identity{
		Subject:   "  alice ",
		Source:    " oidc ",
		Roles:     []string{"teacher", "student", "teacher", ""},
		Groups:    []string{"cs", "cs", "lab"},
		ExpiresAt: hoursAfter(1),
	}
	id = id.Normalize()
	if id.Subject != "alice" || id.Source != "oidc" {
		t.Fatalf("空白未清理: %+v", id)
	}
	if strings.Join(id.Roles, ",") != "student,teacher" {
		t.Fatalf("角色应排序去重，实际 %v", id.Roles)
	}
	if !id.HasRole("teacher") || id.HasRole("admin") {
		t.Fatal("成员判定不对")
	}
	// 大小写敏感：把 CS 和 cs 折叠成一个组，方向上是越权。
	if id.HasRole("Teacher") {
		t.Fatal("角色判定不应忽略大小写")
	}
	if id.Expired(baseNow) || !id.Expired(hoursAfter(2)) {
		t.Fatal("过期判定不对")
	}
	if err := id.ValidAt(baseNow); err != nil {
		t.Fatalf("有效期内应当可用: %v", err)
	}
	future := id
	future.IssuedAt = hoursAfter(3)
	if err := future.ValidAt(baseNow); err == nil {
		t.Fatal("尚未生效的身份必须拒绝")
	}
}

func TestDataLevelOrderAndParse(t *testing.T) {
	// 领域序：public < internal < confidential < restricted
	if !(LevelPublic < LevelInternal && LevelInternal < LevelConfidential && LevelConfidential < LevelRestricted) {
		t.Fatal("常量表顺序被改动了 —— §2.3 的四级排序是固定的")
	}
	if LevelPublic.AtLeast(LevelRestricted) {
		t.Fatal("public 不应该不低于 restricted")
	}
	if !LevelRestricted.AtLeast(LevelConfidential) || LevelRestricted.Exceeds(LevelRestricted) {
		t.Fatal("AtLeast 应含相等，Exceeds 应严格大于")
	}
	// 这条是「禁止字符串字典序」的理由本身：字典序与领域序在 confidential/internal 上相反。
	if !(LevelConfidential.String() < LevelInternal.String()) {
		t.Fatal("用例前提失效：字典序应当把 confidential 排在 internal 之前")
	}
	if LevelConfidential <= LevelInternal {
		t.Fatal("领域序弄反了：confidential 必须高于 internal")
	}
	for _, s := range []string{"public", "internal", "confidential", "restricted", "RESTRICTED", " public "} {
		if _, err := ParseDataLevel(s); err != nil {
			t.Fatalf("%q 应当可解析: %v", s, err)
		}
	}
	for _, s := range []string{"", "secret", "top-secret", "unknown", "public2", "五级"} {
		if _, err := ParseDataLevel(s); err == nil {
			t.Fatalf("%q 必须被拒绝，禁止私自扩级", s)
		}
	}
	if LevelUnknown.Valid() || LevelUnknown.String() != "unknown" || LevelUnknown.Rank() != 0 {
		t.Fatal("零值必须是 Unknown（而不是 public）")
	}
	if len(Levels()) != 4 {
		t.Fatalf("Levels 必须恰好给出四级，实际 %d", len(Levels()))
	}
}

func TestEffectiveLevelMax(t *testing.T) {
	got, err := EffectiveLevel(LevelInternal, LevelRestricted, LevelPublic)
	if err != nil || got != LevelRestricted {
		t.Fatalf("effective 应取三者最大值，实际 %v %v", got, err)
	}
	got, err = EffectiveLevel(LevelPublic, LevelPublic, LevelConfidential)
	if err != nil || got != LevelConfidential {
		t.Fatalf("知识库等级更高时应取知识库等级，实际 %v %v", got, err)
	}
	// 任何一个未判定都必须报错，而不是当成 public 放行。
	cases := [][3]DataLevel{
		{LevelUnknown, LevelPublic, LevelPublic},
		{LevelPublic, LevelUnknown, LevelPublic},
		{LevelPublic, LevelPublic, LevelUnknown},
	}
	for i, c := range cases {
		if _, err := EffectiveLevel(c[0], c[1], c[2]); err == nil {
			t.Fatalf("第 %d 组：未判定的等级必须报错", i)
		}
	}
}

func TestPolicyContextValidateAndRegion(t *testing.T) {
	id := student(t, "alice", []string{"student"}, []string{"cs"})
	ctx := ctxOf(t, id, "qa", LevelInternal)
	if err := ctx.Validate(); err != nil {
		t.Fatalf("合法上下文不应报错: %v", err)
	}
	// purpose 必填：留空会让 deny 规则整体失配，方向是放行。
	bad := ctx
	bad.Purpose = "  "
	if err := bad.Normalize().Validate(); err == nil {
		t.Fatal("缺 purpose 必须报错")
	}
	// 分级未判定必须报错（零值不等于 public）。
	bad = ctx
	bad.DataLevel = LevelUnknown
	if err := bad.Validate(); err == nil {
		t.Fatal("未判定的 DataLevel 必须报错")
	}
	// 只写 project 不写 organization：范围层级不完整。
	bad = ctx
	bad.Project = "proj-lab-7"
	if err := bad.Validate(); err == nil {
		t.Fatal("project 必须与 organization 同时给出")
	}
	// 区域：空列表 = 不限制；一旦限制，未声明区域的候选出局。
	bad = ctx
	bad.AllowedRegions = []string{"cn-north", "cn-north", "eu"}
	bad = bad.Normalize()
	if !bad.RegionAllowed("cn-north") || !bad.RegionAllowed("eu") || bad.RegionAllowed("") {
		t.Fatalf("区域判定不对: %+v", bad.AllowedRegions)
	}
	if strings.Join(bad.AllowedRegions, ",") != "cn-north,eu" {
		t.Fatalf("区域列表应排序去重: %v", bad.AllowedRegions)
	}
	free := ctx
	if free.RestrictsRegions() || !free.RegionAllowed("anything") {
		t.Fatal("未配置区域约束时不应限制选路")
	}
}
