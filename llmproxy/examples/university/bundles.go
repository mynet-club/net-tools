package university

import (
	"strconv"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 模型目录：这里都是**下游请求名**。策略与能力判定按这个名字发放，
// 上游真名（deployment）在 catalog 里，deny 规则可以精确点到某一家部署。
const (
	ModelLite       = "campus-lite"       // 全校基线，校内 vLLM
	ModelGeneral    = "campus-general"    // 教师可用，最高 confidential
	ModelRestricted = "campus-restricted" // 科研组专用，可到 restricted
	ModelReview     = "cs-code-review"    // 计算机学院自有模型
	ModelTutor101   = "cs101-tutor"       // 课程模型：选课即入范围
	ModelTutor305   = "cs305-tutor"       // 已结课的课程模型
	ModelCloud      = "frontier-cloud"    // 外部云，境内区域
	ModelForeign    = "foreign-frontier"  // 外部云，境外区域
	ModelPilot      = "pilot-reasoning"   // 点名授权给某位 PI 的试点模型
)

// 知识库与处理器标识：与模型同属一套资源命名空间，判定口径完全一致。
const (
	KnowledgePublic      = "campus-public"
	KnowledgeCourse      = "cs101-materials"
	KnowledgeLabNotes    = "lab7-notes"
	KnowledgeInstruments = "instrument-log"

	ProcessorSidecar = "campus-content-check"
)

// PurposeWriting 是「科研写作用途」。原文出网授权按用途绑定（Conditions 的
// purpose 键是精确相等）：换一个用途就要重新判定，不能沿用科研组的授权。
const PurposeWriting = "research-writing"

// 授权期限都从 BaseNow 起算，测试不依赖真实时间。
var (
	grantTTL     = BaseNow.AddDate(0, 0, 30) // 实验室原文授权：一学期
	pilotTTL     = BaseNow.AddDate(0, 0, 90) // 试点模型点名授权
	farTTL       = BaseNow.AddDate(1, 0, 0)
	expiredTerm  = BaseNow.AddDate(0, 0, -1) // CS305 结课：课程模型已失效
	expiredGrant = BaseNow.AddDate(0, 0, -3) // CS305 结课：原文授权已回收
)

// modelResource / knowledgeResource / processorResource 把标识拼成 §2.4 的资源形态。
func modelResource(name string) string {
	return policy.NamespaceModel + ":" + name
}

func scopedResource(namespace, name string) string {
	return namespace + ":" + name
}

// scopeSelector 把范围写成规则里的选择器形式（kind:id）。
func scopeSelector(kind policy.ScopeKind, id string) string {
	return string(kind) + ":" + id
}

// bundle 把规则装进带版本的策略包，并给每条规则补齐来源与版本。
//
// 补齐放在装配处而不是逐条手写：漏了 Version 的规则会在版本串里与真实内容脱钩，
// 回放时无法证明「当时生效的就是这一份」。
func bundle(id string, scope policy.ScopeRef, version int, rules ...policy.Entitlement) policy.PolicyBundle {
	stamp := "v" + strconv.Itoa(version)
	for i := range rules {
		if rules[i].Source == "" {
			rules[i].Source = id
		}
		if rules[i].Version == "" {
			rules[i].Version = stamp
		}
	}
	return policy.PolicyBundle{ID: id, Version: version, Scope: scope, Entitlements: rules}
}

// systemBundle 是全局层：对任意范围集合都生效（PolicyBundle.Covers 对 system 的约定）。
//
// 这里故意留一条「兜底放行原文出网」的通配规则，它是合规演练里最常见的错配 ——
// 有人以为写了全局 allow 就等于授权。A 包规定通配不算原文授权
// （AllowsRawBody 只认显式与组级授权），场景测试把这条钉死。
func systemBundle() policy.PolicyBundle {
	return bundle("campus-system", policy.SystemScope, 1,
		policy.Entitlement{
			Subject: "*", Resource: policy.ResourceBodyRaw, Action: policy.ActionRead,
			Effect: policy.EffectAllow, ExpiresAt: farTTL,
		},
		policy.Entitlement{
			Subject: "*", Resource: scopedResource(policy.NamespaceKnowledge, KnowledgePublic),
			Action: policy.ActionRead, Effect: policy.EffectAllow,
		},
	)
}

// organizationBundle 是全校层：学生/教师/职工基线，外加两条硬禁令。
func organizationBundle() policy.PolicyBundle {
	// 组织级规则一律带 Scope：跨组织的同名角色（合作院校也叫 student）
	// 不能因为角色名相同就蹭到本校的授权。
	orgScope := scopeSelector(policy.ScopeOrganization, OrgCampus)
	return bundle("university-default", policy.MustScope(policy.ScopeOrganization, OrgCampus), 3,
		// 学生基线只到 internal：confidential 及以上由条件挡掉 → data_level_denied。
		policy.Entitlement{
			Subject: "role:student", Resource: modelResource(ModelLite), Action: policy.ActionUse,
			Effect: policy.EffectAllow, Scope: orgScope,
			Conditions: map[string]string{policy.CondMaxDataLevel: "internal"},
		},
		// 教师到 confidential 为止；restricted 不在全校层发放，只在科研组层发放。
		policy.Entitlement{
			Subject: "role:teacher", Resource: modelResource(ModelGeneral), Action: policy.ActionUse,
			Effect: policy.EffectAllow, Scope: orgScope,
			Conditions: map[string]string{policy.CondMaxDataLevel: "confidential"},
		},
		policy.Entitlement{
			Subject: "group:faculty", Resource: modelResource(ModelCloud), Action: policy.ActionUse,
			Effect: policy.EffectAllow, Scope: orgScope,
			Conditions: map[string]string{policy.CondMaxDataLevel: "internal"},
		},
		// 仪器运行日志只发职工岗；学生没有任何规则覆盖它 —— 缺席即否。
		policy.Entitlement{
			Subject: "group:staff", Resource: scopedResource(policy.NamespaceKnowledge, KnowledgeInstruments),
			Action: policy.ActionRead, Effect: policy.EffectAllow, Scope: orgScope,
		},
		// 处理器授权与模型授权走同一个内核，不为处理器另造词汇。
		policy.Entitlement{
			Subject: "role:teacher", Resource: scopedResource(policy.NamespaceProcessor, ProcessorSidecar),
			Action: policy.ActionInvoke, Effect: policy.EffectAllow, Scope: orgScope,
		},
		// 科研受限模型：学生显式禁止。deny 压过一切 allow，包括学院/课程层的兜底放行。
		policy.Entitlement{
			Subject: "role:student", Resource: modelResource(ModelRestricted), Action: policy.ActionUse,
			Effect: policy.EffectDeny, Scope: orgScope,
		},
		// 数据不出境：境外部署在全校层显式禁止，路由侧的区域约束只是第二道防线。
		policy.Entitlement{
			Subject: "*", Resource: modelResource(ModelForeign), Action: policy.ActionUse,
			Effect: policy.EffectDeny, Scope: orgScope,
		},
	)
}

// collegeBundle 是院系层：计算机学院自有的代码评审模型。
//
// 主体选择器写 organization:cs-college 而不是 group:计算机学院 —— 角色与组吃
// IdP claim 原值（改名就漂移），组织吃结构化范围，后者才是能长期授权的键。
func collegeBundle() policy.PolicyBundle {
	return bundle("cs-college-default", policy.MustScope(policy.ScopeOrganization, OrgCsCollege), 1,
		policy.Entitlement{
			Subject:  scopeSelector(policy.ScopeOrganization, OrgCsCollege),
			Resource: modelResource(ModelReview), Action: policy.ActionUse,
			Effect:     policy.EffectAllow,
			Conditions: map[string]string{policy.CondMaxDataLevel: "internal"},
		},
	)
}

// courseBundles 是课程层：选课即入范围，结课即回收。
//
// CS101 在读，课程模型与课件库可用；CS305 已结课，它的课程模型与原文授权都带着
// 过去的 ExpiresAt —— 「策略过期」和「压根没配」在原因码上是两个结论，必须分开钉。
func courseBundles() []policy.PolicyBundle {
	return []policy.PolicyBundle{
		bundle("cs101-course", policy.MustScope(policy.ScopeProject, CourseIntro), 1,
			policy.Entitlement{
				Subject:  scopeSelector(policy.ScopeProject, CourseIntro),
				Resource: modelResource(ModelTutor101), Action: policy.ActionUse,
				Effect: policy.EffectAllow,
			},
			policy.Entitlement{
				Subject:  scopeSelector(policy.ScopeProject, CourseIntro),
				Resource: scopedResource(policy.NamespaceKnowledge, KnowledgeCourse),
				Action:   policy.ActionRead, Effect: policy.EffectAllow,
			},
		),
		bundle("cs305-course", policy.MustScope(policy.ScopeProject, CourseSeminar), 2,
			policy.Entitlement{
				Subject:  scopeSelector(policy.ScopeProject, CourseSeminar),
				Resource: modelResource(ModelTutor305), Action: policy.ActionUse,
				Effect: policy.EffectAllow, ExpiresAt: expiredTerm,
			},
			policy.Entitlement{
				Subject:  scopeSelector(policy.ScopeProject, CourseSeminar),
				Resource: policy.ResourceBodyRaw, Action: policy.ActionRead,
				Effect: policy.EffectAllow, ExpiresAt: expiredGrant,
			},
		),
	}
}

// labBundle 是实验室/科研组层：受限模型与「原文出网」这类高危授权只在这一层发放。
//
// 原文授权必须同时具备三样（§2.9 规则 4）：组级以上的主体选择器、绑定范围、
// 自带期限。这里三条齐备，所以 PI 在科研写作用途下放行；换一个用途就退回最严。
//
// 主体选择器吃 project:lab7 而不是 PI 的 projects claim：范围链里的 lab7 来自
// lab claim（第七实验室），PolicyContext.Project 是另一个项目 ——
// 只有链上命中才能让「不在主归属也依然有效」的项目级授权成立（A 包 §3）。
func labBundle() policy.PolicyBundle {
	labSel := scopeSelector(policy.ScopeProject, LabResearch)
	return bundle("lab7-research", policy.MustScope(policy.ScopeProject, LabResearch), 1,
		policy.Entitlement{
			Subject: labSel, Resource: modelResource(ModelRestricted), Action: policy.ActionUse,
			Effect: policy.EffectAllow,
		},
		policy.Entitlement{
			Subject: labSel, Resource: scopedResource(policy.NamespaceKnowledge, KnowledgeLabNotes),
			Action: policy.ActionRead, Effect: policy.EffectAllow,
		},
		policy.Entitlement{
			Subject: labSel, Resource: policy.ResourceBodyRaw, Action: policy.ActionRead,
			Effect:     policy.EffectAllow,
			Conditions: map[string]string{policy.CondPurpose: PurposeWriting},
			ExpiresAt:  grantTTL,
		},
	)
}

// projectBundle 是科研项目层：点名授权（explicit_allow 档）在这里发放。
//
// 主体选择器直接写稳定 subject：它压过所有组级授权，是「个别试点」的正确写法，
// 但必须带期限 —— 永不过期的点名授权等于给一个人开了不可回收的后门。
func projectBundle() policy.PolicyBundle {
	return bundle("grant-2026", policy.MustScope(policy.ScopeProject, ProjectGrant), 1,
		policy.Entitlement{
			Subject: "uid-pi-3001", Resource: modelResource(ModelPilot), Action: policy.ActionUse,
			Effect:    policy.EffectAllow,
			Scope:     scopeSelector(policy.ScopeProject, ProjectGrant),
			ExpiresAt: pilotTTL,
		},
	)
}

// Bundles 返回全校实际加载的策略集 —— PolicyVersion 的唯一来源。
//
// 版本串必须先按范围过滤再取（BundleSet.Filter(chain).PolicyVersion()）：
// 拿全集版本进审计会写下「生效规则里包含与本次请求无关的包」。
func Bundles() (*policy.BundleSet, error) {
	courses := courseBundles()
	bundles := make([]policy.PolicyBundle, 0, len(courses)+5)
	bundles = append(bundles, systemBundle(), organizationBundle(), collegeBundle())
	bundles = append(bundles, courses...)
	bundles = append(bundles, labBundle(), projectBundle())
	return policy.NewBundleSet(bundles...)
}
