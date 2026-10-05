// Package enterprise 是 llmproxy 3.0 的企业集团参考实现，与 examples/university 平行。
//
// 它的定位和高校示例一样：**一个租户怎么把通用对象拼起来**，而不是核心包的一部分。
// 集团、子公司、部门、项目组、客户项目、合作方（外包）这些企业特有概念，全部通过
// internal/identity 的通用映射机制（claim 名单 + 范围规则 + 目录别名表）和
// internal/policy 的通用对象（ScopeRef / Entitlement / PolicyBundle）表达，一个字段
// 都不写进 internal/。它证明的是「同一套内核换一个垂直场景照样成立」，不是新增能力。
//
// 对象映射沿用 docs/optimization-plan.md §「高校与企业集团的对象映射」那张表：
//
//	Tenant          某大学          →  集团公司（organization 范围 ent-group）
//	Department      学院、图书馆     →  子公司 / 部门（organization 范围 sub-*/dept-*）
//	Team / Project  课程、实验室     →  项目组 / 客户项目 / 成本中心（project 范围）
//	Identity        教师、学生       →  员工 / 管理者 / 合作方
//	KnowledgeScope  课程资料、制度库  →  产品库、制度库、客户资料
//
// 企业示例相对高校示例刻意走通的四条差异（每一条都对应一个真实的采购/合规诉求）：
//
//  1. **身份来源要分家**（§0.3 的动机）：员工走 `corp-oidc`，合作方走 `partner-oidc`。
//     同一个项目范围（ACME 交付）两边都进，但项目模型只在 `source: corp-oidc` 下发放 ——
//     这是 `source:` 条件在企业侧唯一的正经用法，也是 §0.2 第 4 行被 §0.3 推翻的原因：
//     合规审计要能在事件重放里问出「当时按哪个来源判的」。
//  2. **保底靠范围、点名靠规则**：合作方不进任何集团组织范围，组织层发的模型对他们
//     天然缺席；「合作方碰内部模型」另有一条 system 范围的显式 deny 把它说成规则，
//     而不是一个恰好没配的巧合。
//  3. **数据出境**：境外区域在**集团层**显式 deny，路由侧的区域约束只是第二道防线。
//  4. **客户资料与员工手册分栏**：客户资料到 restricted，只在财务/法务的部门层发放；
//     研发拿不到 —— 同一个人可以同时属于研发中心与某客户项目组，权限按**范围命中**叠加，
//     不是按人打标签。
//
// 所有 fixture 都是合成值：主体用 uid-* 前缀，邮箱/电话用保留域与文档号段，
// IdP 用 .invalid（RFC 2606）。没有真实企业账号，也没有任何网络依赖。
package enterprise

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

// Profile 就是 identity 包里的样例画像载体。整个 3.0 只有这一个 fixture 形状，
// 企业示例复用它而不是另造一个 —— 「样例画像」是输入，不是领域对象。
type Profile = identity.UniversityProfile

// 两个身份来源。它们的区别不是「哪个更可信」，而是「这个人是不是我们自己签发的」：
// 员工由集团 IdP 签发，合作方由对方 IdP 签发、经联邦信任接入。策略内核不认来源的
// 强弱，只把它当一个字符串条件 —— 分不分、怎么分，是配置者的事。
const (
	SourceEmployee = "corp-oidc"
	SourcePartner  = "partner-oidc"
)

// 企业组织的稳定范围 ID（中文显示名 → 这些 ID 的换算见 Directory）。
//
// 集团与子公司/部门都落在 `organization` 这一种范围里（内核只有一种组织范围），
// 两档对应高校的「本校 + 学院」：集团层发基线，子公司/部门层发各自的模型。
const (
	OrgGroup    = "ent-group"    // 集团
	OrgPartner  = "partner-org"  // 合作方自己的组织（外部，仅用于让范围链合法）
	SubCloud    = "sub-cloud"    // 云服务子公司
	SubMfg      = "sub-mfg"      // 制造子公司
	DeptFinance = "dept-finance" // 财务部
	DeptRnd     = "dept-rnd"     // 研发中心
	DeptLegal   = "dept-legal"   // 法务部
	DeptHr      = "dept-hr"      // 人力资源部
	DeptOps     = "dept-ops"     // 运维部
)

// 项目范围：客户项目、项目组、成本中心都进 project 范围。
const (
	ProjectAcme    = "client-acme"     // 客户项目：ACME 交付
	ProjectPay     = "team-pay"        // 支付平台项目组
	ProjectCcFin26 = "cc-finance-2026" // 财务成本中心：2026 年度
)

// RoutingEpoch 是候选池的世代号：池子或权重变一次就 +1。
//
// 它进 seed 派生（§2.8 的第三段），所以「换了候选池还复用旧 seed」这种
// 假装能复现的情况会被 seed 变化挡住。
const RoutingEpoch = "ent-offers-2026-03"

// Directory 是企业目录维护的别名表：claim 原值 → 稳定范围 ID。
//
// 只登记「显示名形态」的取值（集团/子公司/部门/合作方/客户项目名），
// 项目代号（team-pay）这类本身就是编码的取值交给 SlugDirectory 兜底 ——
// 全表登记会让目录变成第二套组织架构系统，没人会及时更新它，
// 结果是解析失败率随组织调整上涨。
// AllowUnknown 保持默认 false：认不出的显示名必须报错，不能静默把中文原名
// 当范围 ID 写进授权判定面。
func Directory() identity.StaticDirectory {
	return identity.StaticDirectory{
		Entries: map[policy.ScopeKind]map[string]string{
			policy.ScopeOrganization: {
				"集团":     OrgGroup,
				"合作方":    OrgPartner,
				"云服务子公司": SubCloud,
				"制造子公司":  SubMfg,
				"财务部":    DeptFinance,
				"研发中心":   DeptRnd,
				"法务部":    DeptLegal,
				"人力资源部":  DeptHr,
				"运维部":    DeptOps,
			},
			policy.ScopeProject: {
				"ACME交付": ProjectAcme,
			},
		},
		Fallback: identity.DefaultSlugDirectory(),
	}
}

// Mapper 是「企业 IdP claims → Identity + ScopeChain」的映射表。
//
// RoleClaims/GroupClaims 写成多名单：集团历史上把角色塞在 roles，
// 换到 Keycloak 后放到 realm_access.roles，按顺序取第一个非空 —— 只写一个名字
// 的话，切换 IdP 那天解析会静默产出「无角色身份」，靠角色匹配的规则全部失效。
// ScopeRules 声明：集团与子公司/部门都进 organization 范围，客户项目/项目组/成本中心
// 都进 project 范围，各取一个 primary 填 PolicyContext 的同名字段。
func Mapper() (*identity.ClaimMapper, error) {
	return identity.NewClaimMapper(identity.MapperConfig{
		SubjectClaims:     []string{"sub"},
		DisplayNameClaims: []string{"displayName", "name"},
		RoleClaims:        []string{"realm_access.roles", "roles"},
		GroupClaims:       []string{"memberOf", "groups"},
		ProjectClaims:     []string{"projects"},
		AuthMethodClaims:  []string{"amr"},
		Directory:         Directory(),
		MaxValuesPerClaim: 64,
		ScopeRules: []identity.ScopeRule{
			{Claim: "organization", Kind: policy.ScopeOrganization, Primary: true},
			{Claim: "department", Kind: policy.ScopeOrganization},
			{Claim: "projects", Kind: policy.ScopeProject, Primary: true},
		},
	})
}

// employeeProfiles 是员工侧画像：由集团 IdP（corp-oidc）签发。
//
// 覆盖面按「策略会怎么区分他们」挑：普通员工（基线）、管理者（跨部门可见）、
// 财务（客户资料到 restricted）、研发（产品库 + 私有模型 + 参与 ACME 交付）、
// 实习生（受限档位）、法务（客户资料 + 制度库）。每个都够写一条 allow 和一条 deny。
func employeeProfiles() []Profile {
	return []Profile{
		{
			// 云服务子公司的一名普通员工：组织归集团，部门归子公司那一档 ——
			// 两档组织范围同时在链上，子公司层发的模型与集团层发的基线都够得着。
			Fixture: "employee-1001", Subject: "uid-emp-1001", DisplayName: "Sample Employee",
			Organization: "集团", Department: "云服务子公司",
			Roles: []string{"employee"}, Groups: []string{"all-staff", "cloud-team"},
			Projects:    []string{ProjectPay},
			AuthMethods: []string{"pwd", "totp"},
			Email:       "employee-1001@example.invalid", Phone: "13900000000",
		},
		{
			Fixture: "manager-2001", Subject: "uid-mgr-2001", DisplayName: "Sample Manager",
			Organization: "集团", Department: "研发中心",
			Roles: []string{"employee", "manager"}, Groups: []string{"all-staff", "managers", "研发中心"},
			Projects: []string{ProjectPay}, AuthMethods: []string{"pwd", "totp"},
			Email: "manager-2001@example.invalid",
		},
		{
			// 财务：客户资料（restricted）的正规出口之一。成本中心也进它的范围链。
			Fixture: "finance-3001", Subject: "uid-fin-3001", DisplayName: "Sample Finance",
			Organization: "集团", Department: "财务部",
			Roles: []string{"employee", "finance"}, Groups: []string{"all-staff", "finance"},
			Projects: []string{ProjectCcFin26}, AuthMethods: []string{"pwd", "totp"},
		},
		{
			// 研发：产品库、私有代码模型，并且**同时**在 ACME 客户项目组里。
			// 这条画像专门用来和合作方对照：同一个 project:client-acme 范围，
			// 一个来源是 corp-oidc，一个是 partner-oidc，结论必须分开。
			Fixture: "rnd-4001", Subject: "uid-rnd-4001", DisplayName: "Sample Engineer",
			Organization: "集团", Department: "研发中心",
			Roles: []string{"employee", "engineer"}, Groups: []string{"all-staff", "rnd"},
			Projects: []string{ProjectPay, ProjectAcme}, AuthMethods: []string{"pwd", "totp"},
		},
		{
			// 实习生：在研发中心的**部门范围**里，但**不在 group:rnd 里**。
			// 这是「组织范围与组是两个维度」的落点：部门层的代码模型发给 group:rnd，
			// 所以实习生够不着它；集团层按 role:employee 发的通用模型才轮得到他。
			Fixture: "intern-5001", Subject: "uid-int-5001", DisplayName: "Sample Intern",
			Organization: "集团", Department: "研发中心",
			Roles: []string{"employee", "intern"}, Groups: []string{"all-staff", "interns"},
			AuthMethods: []string{"pwd"},
		},
		{
			// 法务：客户资料的另一个正规出口。制度库也在这一层发放。
			Fixture: "legal-6001", Subject: "uid-leg-6001", DisplayName: "Sample Counsel",
			Organization: "集团", Department: "法务部",
			Roles: []string{"employee", "legal"}, Groups: []string{"all-staff", "legal"},
			AuthMethods: []string{"pwd", "totp"},
		},
	}
}

// partnerProfiles 是合作方侧画像：由对方 IdP（partner-oidc）签发。
//
// 关键：他们落在自己的组织范围（partner-org），**不进集团范围 ent-group** ——
// 所以集团层/部门层发的模型与知识对他们天然缺席；同时他们进了 project:client-acme，
// 所以客户项目范围内的资源照样按项目授权，而不是被一刀切挡在外面。
// 「合作方碰内部模型」另有一条显式 deny（见 bundles.go）把它说成一条规则。
func partnerProfiles() []Profile {
	return []Profile{
		{
			Fixture: "partner-7001", Subject: "uid-partner-7001", DisplayName: "Sample Partner Dev",
			Organization: "合作方", Department: "",
			Roles: []string{"contractor"}, Groups: []string{"contractors"},
			Projects: []string{ProjectAcme}, AuthMethods: []string{"pwd", "totp"},
		},
	}
}

// Fixtures 返回全套画像的 fixture 名 → claims，按来源分成两组。
//
// 两个来源各造一个 provider：员工是集团 IdP、合作方是对方 IdP，
// 这是**真实拓扑**（同一批人不会从两个 IdP 登进来），也是策略能把
// `source:` 当条件用的前提 —— 如果大家都从一个源进来，那一列永远只有一个取值。
func Fixtures(now time.Time) (employee, partner map[string]identity.Claims) {
	employee = map[string]identity.Claims{}
	for _, p := range employeeProfiles() {
		employee[p.FixtureName()] = p.Claims(now)
	}
	partner = map[string]identity.Claims{}
	for _, p := range partnerProfiles() {
		partner[p.FixtureName()] = p.Claims(now)
	}
	return employee, partner
}

// Providers 造两个离线可用的身份来源：员工与合作伙伴。
//
// fixture 按 now 签发，内部时钟也钉在同一个时刻 —— 两者必须同一个基准，否则
// TTL 边界用例会在「签发时刻」和「判定时刻」之间留下一个不可控的缝。
func Providers(now time.Time) (employee, partner *identity.FakeProvider, err error) {
	mapper, err := Mapper()
	if err != nil {
		return nil, nil, err
	}
	empClaims, partClaims := Fixtures(now)
	clock := identity.WithClock(func() time.Time { return now })
	employee, err = identity.NewFakeProvider(identity.FakeOptions{
		Source: SourceEmployee, Name: "corp-fake-idp", Mapper: mapper, Fixtures: empClaims,
	}, clock)
	if err != nil {
		return nil, nil, err
	}
	partner, err = identity.NewFakeProvider(identity.FakeOptions{
		Source: SourcePartner, Name: "partner-fake-idp", Mapper: mapper, Fixtures: partClaims,
	}, clock)
	return employee, partner, err
}
