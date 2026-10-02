// Package university 是 llmproxy 3.0 的高校参考实现（工作包 G）。
//
// 它的定位是「一个租户怎么把通用对象拼起来」，而不是核心包的一部分：
// 学生、教师、学院、课程、实验室、科研项目这些高校特有概念，全部通过
// internal/identity 的通用映射机制（claim 名单 + 范围规则 + 目录别名表）
// 和 internal/policy 的通用对象（ScopeRef / Entitlement / PolicyBundle）表达，
// 一个字段都不写进 internal/（手册 §3.G 与 §9「G 只允许使用通用对象」）。
//
// 三条刻意的设计：
//  1. claim 里的组织/院系是**显示名**（会改名、可能重名），必须由 ScopeDirectory
//     换成稳定 ID 才进范围集合 —— 让显示名直接当授权键，改名那天策略集体失效；
//  2. 目录默认 fail-closed（认不出就报错），只在显式配置的取值上退回 slug 兜底；
//  3. 身份层不判权限：Profiles/Mapper 只产出 Identity + ScopeChain，
//     「谁能用哪个模型」一律由 bundles.go 的规则 + policy.Resolver 决定。
//
// 所有 fixture 都是合成值：主体用 uid-* 前缀，邮箱/电话用保留域与文档号段，
// IdP 用 .invalid（RFC 2606）。没有真实学校账号，也没有任何网络依赖。
package university

import (
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/identity"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// BaseNow 是全套 fixture 共用的时间基准。
//
// 为什么钉死而不是 time.Now()：身份 TTL、规则过期、路由 seed 都吃 now，
// 用墙钟会让同一个用例在半夜跨过边界时改变结论，回放断言当场失去意义。
var BaseNow = time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)

// 校内组织的稳定范围 ID（claim 显示名 → 这些 ID 的换算见 Directory）。
const (
	OrgCampus     = "university"
	OrgPartner    = "partner-institute"
	OrgCsCollege  = "cs-college"
	OrgMedCollege = "medical-college"
	OrgPhyCollege = "physics-college"
	OrgEeCollege  = "ee-college"
)

// 课程、实验室与科研项目的稳定范围 ID。
const (
	CourseIntro   = "cs101" // 人工智能导论
	CourseSeminar = "cs305" // 编译原理研讨（已结课）
	LabResearch   = "lab7"
	LabInstrument = "lab12"
	ProjectLab7   = "proj-lab-7"
	ProjectGrant  = "proj-grant-2026"
)

// RoutingEpoch 是候选池的世代号：池子或权重变一次就 +1。
//
// 它进 seed 派生（§2.8 的第三段），所以「换了候选池还复用旧 seed」这种
// 假装能复现的情况会被 seed 变化挡住。
const RoutingEpoch = "campus-offers-2026-03"

// Directory 是校内目录维护的别名表：claim 原值 → 稳定范围 ID。
//
// 只登记「显示名形态」的取值（组织与院系），课程号/项目号这类本身就是编码的
// 取值交给 SlugDirectory 兜底 —— 全表登记会让目录变成第二套课程数据库，
// 没人会及时更新它，结果是解析失败率随学期涨。
// AllowUnknown 保持默认 false：认不出的显示名必须报错，不能静默把中文原名
// 当范围 ID 写进授权判定面。
func Directory() identity.StaticDirectory {
	return identity.StaticDirectory{
		Entries: map[policy.ScopeKind]map[string]string{
			policy.ScopeOrganization: {
				"本校":    OrgCampus,
				"合作院校":  OrgPartner,
				"计算机学院": OrgCsCollege,
				"医学院":   OrgMedCollege,
				"物理学院":  OrgPhyCollege,
				"电子学院":  OrgEeCollege,
			},
			policy.ScopeProject: {
				"第七实验室": LabResearch,
			},
		},
		Fallback: identity.DefaultSlugDirectory(),
	}
}

// Mapper 是「校内 OIDC claims → Identity + ScopeChain」的映射表。
//
// RoleClaims/GroupClaims 写成多名单：校内 IdP 历史上把角色塞在 roles，
// 新版 Keycloak 放到 realm_access.roles，按顺序取第一个非空 —— 只写一个名字
// 的话，切换 IdP 那天解析会静默产出「无角色身份」，靠角色匹配的规则全部失效。
// ScopeRules 声明层级：组织/院系都进 organization 范围，项目/课程/实验室都进
// project 范围，各取一个 primary 填 PolicyContext 的同名字段。
func Mapper() (*identity.ClaimMapper, error) {
	return identity.NewClaimMapper(identity.MapperConfig{
		SubjectClaims:     []string{"sub"},
		DisplayNameClaims: []string{"displayName", "name"},
		RoleClaims:        []string{"realm_access.roles", "roles"},
		GroupClaims:       []string{"memberOf", "groups"},
		ProjectClaims:     []string{"researchProjects", "projects"},
		AuthMethodClaims:  []string{"amr"},
		Directory:         Directory(),
		MaxValuesPerClaim: 64,
		ScopeRules: []identity.ScopeRule{
			{Claim: "organization", Kind: policy.ScopeOrganization, Primary: true},
			{Claim: "department", Kind: policy.ScopeOrganization},
			{Claim: "projects", Kind: policy.ScopeProject, Primary: true},
			{Claim: "course", Kind: policy.ScopeProject},
			{Claim: "lab", Kind: policy.ScopeProject},
		},
	})
}

// Profiles 是六份高校主体画像，覆盖策略会区别对待的所有维度：
// 角色（学生/研究生助理/教师/PI/实验员/交流生）、组织归属（本校/合作院校/院系）、
// 项目与课程范围（选课即入范围）、数据档位（能不能碰到 confidential/restricted）。
//
// claim 里的组织与院系故意写显示名（中文），课程号写编码，让别名表与 slug
// 兜底两条路都被真实走到。Email/Phone 是保留域与文档号段，专门用来断言它们
// 不会出现在 Principal、审计与错误信息里。
func Profiles() []identity.UniversityProfile {
	return []identity.UniversityProfile{
		{
			Fixture: "student-1001", Subject: "uid-stu-1001", DisplayName: "Sample Student One",
			Organization: "本校", Department: "计算机学院",
			Roles: []string{"student"}, Groups: []string{"undergraduate", "计算机学院"},
			Courses: []string{"CS101"}, AuthMethods: []string{"pwd", "otp"},
			Email: "student-1001@example.invalid", Phone: "13800000000",
		},
		{
			Fixture: "teacher-li-synthetic", Subject: "uid-tea-2001", DisplayName: "Sample Teacher Li",
			Organization: "本校", Department: "计算机学院",
			Roles: []string{"teacher", "course-staff"}, Groups: []string{"faculty", "计算机学院"},
			Courses: []string{"CS305"}, Projects: []string{"proj-curriculum"},
			AuthMethods: []string{"pwd", "totp"},
			Email:       "teacher-li@example.invalid",
		},
		{
			Fixture: "pi-3001", Subject: "uid-pi-3001", DisplayName: "Sample PI Three",
			Organization: "本校", Department: "医学院",
			Roles: []string{"teacher", "project-lead"}, Groups: []string{"faculty"},
			Projects: []string{ProjectLab7, ProjectGrant}, Lab: "第七实验室",
			AuthMethods: []string{"pwd", "totp"},
		},
		{
			Fixture: "lab-admin-4001", Subject: "uid-lab-4001", DisplayName: "Sample Lab Admin",
			Organization: "本校", Department: "物理学院",
			Roles: []string{"lab-admin"}, Groups: []string{"staff"},
			Projects: []string{"proj-instrument"}, Lab: "Lab12",
			AuthMethods: []string{"cert"},
		},
		{
			// 研究生助理：学生角色 + 实验室成员。这是策略冲突的真实形态 ——
			// 实验室层给了它受限模型，全校层对 role:student 有一条显式 deny，
			// 后者必须压过前者（deny 不看层级高低）。
			Fixture: "ra-6001", Subject: "uid-ra-6001", DisplayName: "Sample Research Assistant",
			Organization: "本校", Department: "医学院",
			Roles: []string{"student", "graduate-assistant"}, Groups: []string{"undergraduate"},
			Projects: []string{ProjectLab7}, Lab: "第七实验室",
			AuthMethods: []string{"pwd", "totp"},
		},
		{
			// 交流生：主组织是合作院校，但选了本校的课 —— 课程范围照样命中。
			// 这条画像专门用来验「跨组织主体蹭不到组织层授权，但课程层是按范围发的」。
			Fixture: "exchange-5001", Subject: "uid-exg-5001", DisplayName: "Sample Exchange Student",
			Organization: "合作院校", Department: "电子学院",
			Roles: []string{"student", "exchange"}, Groups: []string{"exchange"},
			Courses: []string{"CS101"}, AuthMethods: []string{"pwd"},
		},
	}
}

// Provider 造一个离线可用的身份来源：fixture 按 BaseNow 签发，
// 内部时钟也钉在同一个时刻 —— 两者必须同一个基准，否则 TTL 边界用例
// 会在「签发时刻」和「判定时刻」之间留下一个不可控的缝。
func Provider(now time.Time) (*identity.FakeProvider, error) {
	mapper, err := Mapper()
	if err != nil {
		return nil, err
	}
	fixtures := make(map[string]identity.Claims, len(Profiles()))
	for _, p := range Profiles() {
		fixtures[p.FixtureName()] = p.Claims(now)
	}
	return identity.NewFakeProvider(identity.FakeOptions{
		Source:   "campus-oidc",
		Name:     "campus-fake-idp",
		Mapper:   mapper,
		Fixtures: fixtures,
	}, identity.WithClock(func() time.Time { return now }))
}
