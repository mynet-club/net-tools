package knowledge

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// KnowledgeScope 是一次请求被允许触达的知识库集合与分级上限。
//
// 它是**派生物**，不是权限模型：范围集合取自 policy.ScopeChain（B 包展开），
// 分级上限取自 policy.DataLevel（A 包判定），知识库准入取自 A 包对
// `knowledge:<id>` + `read` 的判定结果（见 AdmitKnowledgeBases）。
//
// 为什么不在这儿写一套自己的权限判断（手册 §3.C 的禁止项）：
// 文档 ACL 的事实只有知识源那一侧是完整的，网关这一侧只有「哪个库能碰」。
// 网关若自己拼一套，两处规则迟早漂移，而漂移的方向永远是「多放行」。
type KnowledgeScope struct {
	// Chain 是本次请求覆盖的结构化范围集合（user / organization / project）。
	// 直接引用 A 包对象，不复制同构结构体（手册 §5）。
	Chain policy.ScopeChain `json:"chain"`
	// KnowledgeBases 是已准入的知识库稳定 ID 集合，排序去重。
	// 空集合是合法值，含义是「一个都不许碰」：Resolve 会直接短路，不发委托请求。
	KnowledgeBases []string `json:"knowledge_bases"`
	// MaxDataLevel 是本请求可触达文档的最高分级上限（生效分级）。
	MaxDataLevel policy.DataLevel `json:"max_data_level"`
}

var (
	// ErrScope 表示知识范围本身不合法（缺范围、缺分级、知识库 ID 形态错误）。
	ErrScope = errors.New("knowledge: 知识范围不合法")
	// ErrKBID 表示知识库 ID 形态不合法。
	ErrKBID = errors.New("knowledge: 知识库 ID 不合法")
	// ErrAdmission 表示无法完成知识库准入计算（策略内核缺失等）。
	ErrAdmission = errors.New("knowledge: 知识库准入计算失败")
)

// NewKnowledgeScope 构造并校验知识范围。
//
// 空 chain 一律拒绝：A 包的约定是「漏传范围不能被解释成不限范围」，
// 这里照抄同一条规则——空集合如果按「全部知识库可达」处理，
// 一次上游漏传就会把所有组织的文档发给一个未知主体。
func NewKnowledgeScope(chain policy.ScopeChain, maxLevel policy.DataLevel, knowledgeBases []string) (KnowledgeScope, error) {
	normalized, err := policy.NewScopeChain(chain...)
	if err != nil {
		return KnowledgeScope{}, fmt.Errorf("%w: %v", ErrScope, err)
	}
	if !maxLevel.Valid() {
		return KnowledgeScope{}, fmt.Errorf("%w: 分级上限未指定（零值 LevelUnknown 不是 public）", ErrScope)
	}
	kbs := sortUniqueStrings(knowledgeBases)
	for _, kb := range kbs {
		if err := ValidateKnowledgeBaseID(kb); err != nil {
			return KnowledgeScope{}, err
		}
	}
	return KnowledgeScope{Chain: normalized, KnowledgeBases: kbs, MaxDataLevel: maxLevel}, nil
}

// Validate 校验范围自身（供 BuildRequest 与直接手构结构体的路径使用）。
//
// 为什么要独立暴露校验：KnowledgeScope 全是导出字段，接线方可以直接字面量构造。
// 只在新建时校验等于不校验——手构的空 chain 会一路走到 Filter，
// 然后「所有归属都不在集合内」，表现为「所有文档都被兜底丢弃」这种难查的故障；
// 而提前报错能直接指出是范围没传。
func (s KnowledgeScope) Validate() error {
	if _, err := policy.NewScopeChain(s.Chain...); err != nil {
		return fmt.Errorf("%w: %v", ErrScope, err)
	}
	if !s.MaxDataLevel.Valid() {
		return fmt.Errorf("%w: 分级上限未指定", ErrScope)
	}
	for _, kb := range s.KnowledgeBases {
		if err := ValidateKnowledgeBaseID(kb); err != nil {
			return err
		}
	}
	return nil
}

// ValidateKnowledgeBaseID 校验知识库稳定 ID。
//
// 禁冒号是刻意的：知识库在策略里以 `knowledge:<id>` 形式出现（领域文档 §8），
// ID 自身含冒号会让资源名出现两个分隔符，规则审查和前缀通配都失去意义。
func ValidateKnowledgeBaseID(kb string) error {
	if err := validateStableID("knowledge_base", kb, maxStableIDLen); err != nil {
		return fmt.Errorf("%w: %v", ErrKBID, err)
	}
	return nil
}

// ResourceForKB 返回该知识库在 A 包里的资源名（`knowledge:<id>`）。
// 唯一出口，避免各处手拼字符串拼出两种形式。
func ResourceForKB(kb string) string {
	return policy.NamespaceKnowledge + ":" + kb
}

// AllowsKB 报告知识库是否在允许集合内。
func (s KnowledgeScope) AllowsKB(kb string) bool {
	kb = strings.TrimSpace(kb)
	for _, item := range s.KnowledgeBases {
		if item == kb {
			return true
		}
	}
	return false
}

// LevelAllows 报告文档分级是否不超过上限。
//
// 任一侧为 LevelUnknown 时返回 false：没判定分级的文档必须丢弃，
// 不能按「最宽松的一档」处理——那正是 §2.3 把零值设计成 Unknown 而不是 public 的原因。
func (s KnowledgeScope) LevelAllows(level policy.DataLevel) bool {
	if !s.MaxDataLevel.Valid() || !level.Valid() {
		return false
	}
	return !level.Exceeds(s.MaxDataLevel)
}

// Organizations 返回 chain 里的组织 ID 集合（排序去重）。
func (s KnowledgeScope) Organizations() []string {
	return s.idsOfKind(policy.ScopeOrganization)
}

// Projects 返回 chain 里的项目 ID 集合（排序去重）。
func (s KnowledgeScope) Projects() []string {
	return s.idsOfKind(policy.ScopeProject)
}

func (s KnowledgeScope) idsOfKind(kind policy.ScopeKind) []string {
	out := make([]string, 0, len(s.Chain))
	for _, ref := range s.Chain {
		if ref.Kind == kind {
			out = append(out, ref.ID)
		}
	}
	return sortUniqueStrings(out)
}

// CoversOwner 是跨组织兜底检查：知识源声明的文档归属必须落在这次请求的范围内。
//
// 规则（与 §2.7 结构化 scope 一致，不猜层级）：
//   - system 归属：不属于任何组织，跳过本项检查（分级与知识库白名单仍然生效）；
//   - user 归属：必须等于本次主体；
//   - organization / project 归属：必须是 chain 中精确存在的一项。
//
// 这一步**不是网关在判定文档权限**：文档能不能读由知识源说了算，
// 这里只拦「知识源返回了本次范围之外的归属」这种异常（源侧配置错误或响应被串号），
// 属于不放大权限的兜底。真出现说明协议已经不可信，必须丢弃并留 reason code。
func (s KnowledgeScope) CoversOwner(owner policy.ScopeRef, subject string) (bool, Reason) {
	if err := owner.Validate(); err != nil {
		return false, ReasonSubjectMismatch
	}
	switch owner.Kind {
	case policy.ScopeSystem:
		return true, ""
	case policy.ScopeUser:
		if owner.ID == subject {
			return true, ""
		}
		return false, ReasonSubjectMismatch
	case policy.ScopeOrganization, policy.ScopeProject:
		if s.Chain.Includes(owner) {
			return true, ""
		}
		return false, ReasonCrossOrg
	}
	return false, ReasonCrossOrg
}

// KnowledgeBaseDenial 是一个知识库被拒的记录，供管理台解释「为什么这个库检索不到」。
type KnowledgeBaseDenial struct {
	KnowledgeBase string        `json:"knowledge_base"`
	Reason        policy.Reason `json:"reason"`
}

// AdmitKnowledgeBases 用 A 包内核算候选知识库的准入，返回允许集合与拒绝明细。
//
// 这是**知识库级**准入（资源 knowledge:<id> + 动作 read，领域文档 §8 明确规定 C 用这两个值）。
// 单篇文档的 ACL 永远不在这里判——网关没有那些事实。
//
// deny 优先、过期、conditions 全部由 policy.Resolver 决定，本函数不参与排序也不做兜底放行：
// 内核说 no 就是 no。resolver 为 nil 时返回错误而不是「全部允许」——
// 漏接线时最危险的失败模式是「因为没有策略所以全都给」。
func AdmitKnowledgeBases(r *policy.Resolver, ctx policy.PolicyContext, chain policy.ScopeChain, candidates []string, now time.Time) ([]string, []KnowledgeBaseDenial, error) {
	if r == nil {
		return nil, nil, fmt.Errorf("%w: 没有策略内核，无法判定知识库准入（fail_closed）", ErrAdmission)
	}
	normalized, err := policy.NewScopeChain(chain...)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrAdmission, err)
	}
	kbs := sortUniqueStrings(candidates)
	allowed := make([]string, 0, len(kbs))
	var denials []KnowledgeBaseDenial
	for _, kb := range kbs {
		if err := ValidateKnowledgeBaseID(kb); err != nil {
			denials = append(denials, KnowledgeBaseDenial{KnowledgeBase: kb, Reason: policy.ReasonContextInvalid})
			continue
		}
		decision := r.Evaluate(ctx, normalized, ResourceForKB(kb), policy.ActionRead, now)
		if decision.Allowed {
			allowed = append(allowed, kb)
			continue
		}
		denials = append(denials, KnowledgeBaseDenial{KnowledgeBase: kb, Reason: decision.Reason})
	}
	return sortUniqueStrings(allowed), denials, nil
}
