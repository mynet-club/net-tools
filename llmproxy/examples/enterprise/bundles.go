package enterprise

import (
	"strconv"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 模型目录：这里都是**下游请求名**。策略与能力判定按这个名字发放，
// 上游真名（deployment）在 catalog 里，deny 规则可以精确点到某一家部署。
const (
	ModelLite        = "corp-lite"             // 全员基线，集团私有化集群
	ModelGeneral     = "corp-general"          // 员工可用，最高 confidential
	ModelCode        = "corp-code"             // 研发中心自有代码模型
	ModelFinance     = "corp-finance"          // 财务分析，可到 restricted
	ModelAcme        = "acme-assist"           // 客户项目助手：只有集团自签身份可用
	ModelCloudOps    = "cloudops-assist"       // 云服务子公司自有模型
	ModelCloudCn     = "frontier-cloud-cn"     // 境内合规云
	ModelCloudGlobal = "frontier-cloud-global" // 境外云：集团层显式禁止
	ModelPilot       = "pilot-longcontext"     // 点名授权给财务某位的长上下文模型
	ModelRetired     = "legacy-batch"          // 已下线的批处理模型：授权带过去的到期点
)

// 知识库与处理器标识：与模型同属一套资源命名空间，判定口径完全一致。
const (
	KnowledgeHandbook = "corp-handbook" // 员工手册
	KnowledgeProduct  = "corp-product"  // 产品库
	KnowledgeCustomer = "corp-customer" // 客户资料（restricted）
	KnowledgePolicy   = "corp-policy"   // 制度库
	KnowledgeAcmeSpec = "acme-spec"     // ACME 交付资料

	ProcessorDlp = "corp-dlp" // 数据防泄漏 sidecar
)

// 用途按业务线绑定：原文出网授权与用途精确相等，换一个用途就要重新判定。
const (
	PurposeSupport = "customer-support"
	PurposeEng     = "internal-eng"
	PurposeFinance = "finance-review"
)

// 授权期限都从 BaseNow 起算，测试不依赖真实时间。
var (
	grantTTL     = BaseNow.AddDate(0, 0, 90) // 管理者原文授权：一个季度
	pilotTTL     = BaseNow.AddDate(0, 0, 180)
	farTTL       = BaseNow.AddDate(1, 0, 0)
	expiredBatch = BaseNow.AddDate(0, 0, -7) // legacy-batch 下线：授权已回收
)

// modelResource / scopedResource 把标识拼成 §2.4 的资源形态。
func modelResource(name string) string { return policy.NamespaceModel + ":" + name }

func scopedResource(namespace, name string) string { return namespace + ":" + name }

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
// 五条规则各有用途：
//   - 全员基线模型只发到 internal —— 档位收紧是 allow 的条件。
//   - 员工手册对全员可读（合作方也是「人」，手册读得到）。
//   - **通配放行原文出网**：故意的错配，用来证明「写了全局 allow ≠ 授权」（§2.9 规则 4）。
//   - **合作方令**：显式 deny 内部模型。这条刻意不写 Scope，因为合作方不在集团
//     组织范围里 —— 加了 Scope 就永远不生效，等于把最该看得见的一条禁令藏起来。
//     范围缺席本身已经挡住了他们，这条 deny 是把它从「恰好没配」变成「一条规则」。
func systemBundle() policy.PolicyBundle {
	return bundle("corp-system", policy.SystemScope, 1,
		policy.Entitlement{
			Subject: "group:all-staff", Resource: modelResource(ModelLite), Action: policy.ActionUse,
			Effect:     policy.EffectAllow,
			Conditions: map[string]string{policy.CondMaxDataLevel: "internal"},
		},
		policy.Entitlement{
			Subject: "group:all-staff", Resource: scopedResource(policy.NamespaceKnowledge, KnowledgeHandbook),
			Action: policy.ActionRead, Effect: policy.EffectAllow,
		},
		// 通配放行原文出网：合规演练里最常见的错配 —— 有人以为写了全局 allow 就等于授权。
		// A 包规定通配不算原文授权（AllowsRawBody 只认显式与组级授权），场景测试把这条钉死。
		policy.Entitlement{
			Subject: "*", Resource: policy.ResourceBodyRaw, Action: policy.ActionRead,
			Effect: policy.EffectAllow, ExpiresAt: farTTL,
		},
		policy.Entitlement{
			Subject: "group:contractors", Resource: modelResource(ModelLite), Action: policy.ActionUse,
			Effect: policy.EffectDeny,
		},
		policy.Entitlement{
			Subject: "group:contractors", Resource: modelResource(ModelGeneral), Action: policy.ActionUse,
			Effect: policy.EffectDeny,
		},
	)
}

// groupBundle 是集团层：员工基线与两条硬约束。
//
// 组织级规则一律带 Scope：跨集团的同名角色（合作方也叫 employee 的情形）不能因为
// 角色名相同就蹭到集团授权。数据出境那条写 `*` + Scope=ent-group —— 它管的是
// 「从集团网络里发出的请求」，合作方自带网络，不在这一层。
//
// 原文出网授权（body.raw）必须同时具备三样（§2.9 规则 4）：组级以上的主体选择器、
// 绑定范围、自带期限。这里三条齐备，所以管理者在内部工程用途下放行；换一个用途退回最严。
func groupBundle() policy.PolicyBundle {
	orgScope := scopeSelector(policy.ScopeOrganization, OrgGroup)
	return bundle("corp-group-default", policy.MustScope(policy.ScopeOrganization, OrgGroup), 3,
		policy.Entitlement{
			Subject: "role:employee", Resource: modelResource(ModelGeneral), Action: policy.ActionUse,
			Effect: policy.EffectAllow, Scope: orgScope,
			Conditions: map[string]string{policy.CondMaxDataLevel: "confidential"},
		},
		policy.Entitlement{
			Subject: "group:all-staff", Resource: modelResource(ModelCloudCn), Action: policy.ActionUse,
			Effect: policy.EffectAllow, Scope: orgScope,
			Conditions: map[string]string{policy.CondMaxDataLevel: "internal"},
		},
		// 处理器授权与模型授权走同一个内核，不为处理器另造词汇。
		policy.Entitlement{
			Subject: "role:employee", Resource: scopedResource(policy.NamespaceProcessor, ProcessorDlp),
			Action: policy.ActionInvoke, Effect: policy.EffectAllow, Scope: orgScope,
		},
		// 原文出网：只有管理者 + 内部工程用途 + 一个季度。
		policy.Entitlement{
			Subject: "group:managers", Resource: policy.ResourceBodyRaw, Action: policy.ActionRead,
			Effect: policy.EffectAllow, Scope: orgScope,
			Conditions: map[string]string{policy.CondPurpose: PurposeEng},
			ExpiresAt:  grantTTL,
		},
		// 数据不出境：境外部署在集团层显式禁止，路由侧的区域约束只是第二道防线。
		policy.Entitlement{
			Subject: "*", Resource: modelResource(ModelCloudGlobal), Action: policy.ActionUse,
			Effect: policy.EffectDeny, Scope: orgScope,
		},
	)
}

// departmentBundles 是子公司/部门层：各自的模型与知识栏位。
//
// 客户资料（restricted）只在财务与法务的部门层发放：研发拿不到 —— 同一个人可以
// 同时在研发中心与某客户项目组，权限按范围命中叠加，不是按人打标签。
func departmentBundles() []policy.PolicyBundle {
	return []policy.PolicyBundle{
		bundle("dept-finance-default", policy.MustScope(policy.ScopeOrganization, DeptFinance), 1,
			policy.Entitlement{
				Subject: "role:finance", Resource: modelResource(ModelFinance), Action: policy.ActionUse,
				Effect: policy.EffectAllow,
			},
			policy.Entitlement{
				Subject: "role:finance", Resource: scopedResource(policy.NamespaceKnowledge, KnowledgeCustomer),
				Action: policy.ActionRead, Effect: policy.EffectAllow,
			},
		),
		bundle("dept-legal-default", policy.MustScope(policy.ScopeOrganization, DeptLegal), 1,
			policy.Entitlement{
				Subject: "role:legal", Resource: scopedResource(policy.NamespaceKnowledge, KnowledgeCustomer),
				Action: policy.ActionRead, Effect: policy.EffectAllow,
			},
			policy.Entitlement{
				Subject: "role:legal", Resource: scopedResource(policy.NamespaceKnowledge, KnowledgePolicy),
				Action: policy.ActionRead, Effect: policy.EffectAllow,
			},
		),
		bundle("dept-rnd-default", policy.MustScope(policy.ScopeOrganization, DeptRnd), 1,
			policy.Entitlement{
				Subject: "group:rnd", Resource: modelResource(ModelCode), Action: policy.ActionUse,
				Effect: policy.EffectAllow,
			},
			policy.Entitlement{
				Subject: "group:rnd", Resource: scopedResource(policy.NamespaceKnowledge, KnowledgeProduct),
				Action: policy.ActionRead, Effect: policy.EffectAllow,
			},
		),
		// 子公司层：证明第二档组织范围同样能独立发资源。
		bundle("sub-cloud-default", policy.MustScope(policy.ScopeOrganization, SubCloud), 1,
			policy.Entitlement{
				Subject:  scopeSelector(policy.ScopeOrganization, SubCloud),
				Resource: modelResource(ModelCloudOps), Action: policy.ActionUse,
				Effect: policy.EffectAllow,
			},
		),
	}
}

// projectBundles 是客户项目/成本中心层：范围命中即入，结项即回收。
//
// ACME 交付助手是**来源条件**的落点：员工与合作方都在 project:client-acme 范围内，
// 但规则要 `source: corp-oidc` —— 同一个范围、两种来源，结论必须分开。这正是
// §0.3 让 `identity_source` 落库的原因：事后要能问出「当时按哪个来源判的」。
// 交付资料（acme-spec）则**不**加来源条件：项目文档本来就该给项目里的人看。
//
// cc-finance-2026 是点名授权（explicit_allow 档）：直接写稳定 subject，压过组级授权，
// 但必须带期限 —— 永不过期的点名授权等于给一个人开了不可回收的后门。
//
// legacy-batch 是**已下线**的模型：它唯一的 allow 带着过去的 ExpiresAt，
// 用来把「过期」和「压根没配」分成人两个结论。
func projectBundles() []policy.PolicyBundle {
	acmeSel := scopeSelector(policy.ScopeProject, ProjectAcme)
	return []policy.PolicyBundle{
		bundle("client-acme", policy.MustScope(policy.ScopeProject, ProjectAcme), 1,
			policy.Entitlement{
				Subject: acmeSel, Resource: modelResource(ModelAcme), Action: policy.ActionUse,
				Effect: policy.EffectAllow,
				Conditions: map[string]string{
					policy.CondSource:       SourceEmployee,
					policy.CondMaxDataLevel: "confidential",
				},
			},
			policy.Entitlement{
				Subject: acmeSel, Resource: scopedResource(policy.NamespaceKnowledge, KnowledgeAcmeSpec),
				Action: policy.ActionRead, Effect: policy.EffectAllow,
			},
		),
		bundle("cc-finance-2026", policy.MustScope(policy.ScopeProject, ProjectCcFin26), 1,
			policy.Entitlement{
				Subject:   "uid-fin-3001",
				Resource:  modelResource(ModelPilot),
				Action:    policy.ActionUse,
				Effect:    policy.EffectAllow,
				ExpiresAt: pilotTTL,
			},
		),
		bundle("legacy-batch-retired", policy.MustScope(policy.ScopeProject, ProjectPay), 2,
			policy.Entitlement{
				Subject:   "uid-emp-1001",
				Resource:  modelResource(ModelRetired),
				Action:    policy.ActionUse,
				Effect:    policy.EffectAllow,
				ExpiresAt: expiredBatch,
			},
		),
	}
}

// Bundles 返回集团实际加载的策略集 —— PolicyVersion 的唯一来源。
//
// 版本串必须先按范围过滤再取（BundleSet.Filter(chain).PolicyVersion()）：
// 拿全集版本进审计会写下「生效规则里包含与本次请求无关的包」。
func Bundles() (*policy.BundleSet, error) {
	depts := departmentBundles()
	projects := projectBundles()
	bundles := make([]policy.PolicyBundle, 0, len(depts)+len(projects)+2)
	bundles = append(bundles, systemBundle(), groupBundle())
	bundles = append(bundles, depts...)
	bundles = append(bundles, projects...)
	return policy.NewBundleSet(bundles...)
}
