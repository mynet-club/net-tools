package identity

import (
	"errors"
	"fmt"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// Principal 是一次成功身份解析的产物：主体快照 + 它所属的完整范围集合。
//
// 它是本包与下游（server 接线、D 路由、H 管理台）之间唯一的传递物。
// 里面刻意没有 claims 原文、没有凭证、没有公钥：这些留在内存的那几个函数栈帧里就够了，
// 塞进 Principal 就等于决定把它们一路带进审计、JSON 响应和缓存。
type Principal struct {
	// Identity 是已校验的主体快照（policy §2.1）。
	Identity policy.Identity `json:"identity"`
	// Chain 是展开后的范围集合（手册 §2.7 + 领域文档 §5）。
	// 至少含 user 范围；组织与项目归属由 ClaimMapper 从 claims 推出。
	Chain policy.ScopeChain `json:"chain"`
	// Source 与 Identity.Source 一致，冗余出来是为了让审计行不用钻嵌套字段。
	Source string `json:"source"`
	// Provider 是产出它的实现名（oidc / fake / saml / ldap），用于区分同一 source
	// 下的多条通路（例如校内 OIDC 与 VPN LDAP 都归 “campus”）。
	Provider string `json:"provider"`
	// Organization / Project 是主组织与主项目，用于填 PolicyContext 的同名字段。
	// 只从被标为 primary 的映射规则取，取值顺序稳定（见 ClaimMapper）。
	Organization string `json:"organization,omitempty"`
	Project      string `json:"project,omitempty"`
	// ValidUntil 是本次解析结论的有效期上限，等于 Identity.ExpiresAt。
	// 下游缓存身份/判定结果时只能用到这个点（Decision.ExpiresAt 的输入之一）。
	ValidUntil time.Time `json:"valid_until,omitempty"`
	// RequestID 是调用方传进来的关联 ID，原样带回，便于与请求日志对齐。
	RequestID string `json:"request_id,omitempty"`
}

// Validate 复核不变量。构造后走完这条路再交给下游。
func (p Principal) Validate() error {
	if err := p.Identity.Validate(); err != nil {
		return mapIdentityError(err)
	}
	if len(p.Chain) == 0 {
		return fmt.Errorf("%w: 范围集合为空，判定会把漏传当成不限范围", ErrScopeUnmapped)
	}
	// 这里不用 policy.MustScope：subject 是外部输入，含冒号或控制字符时它必须给出错误，
	// 而不是把 panic 递给 HTTP 处理链。
	userScope := policy.ScopeRef{Kind: policy.ScopeUser, ID: p.Identity.Subject}
	if err := userScope.Validate(); err != nil {
		return fmt.Errorf("%w: subject 不能当范围 ID 使用", ErrSubjectUnstable)
	}
	if !p.Chain.Includes(userScope) {
		return fmt.Errorf("%w: 范围集合缺少主体自身的 user 范围", ErrScopeUnmapped)
	}
	if p.Project != "" && p.Organization == "" {
		return fmt.Errorf("%w: 给了 project 却没给 organization（policy §2.2 会直接拒绝上下文）", ErrConfig)
	}
	if !p.ValidUntil.IsZero() && p.ValidUntil != p.Identity.ExpiresAt {
		return fmt.Errorf("%w: ValidUntil 与 Identity.ExpiresAt 不一致", ErrInternal)
	}
	return nil
}

// PolicyContext 把主体快照成一次判定所需的上下文（领域文档 §8 的 B 侧职责）。
//
// 本包只填身份、用途、主组织/主项目：
//   - DataLevel 由调用方的正文检测器给出（B 不读正文，也不许猜分级）；
//   - AllowedRegions 与 PolicyVersion 属于策略与路由层的事实，留空由接线方补
//     （PolicyVersion 必须来自实际加载的 bundle，不能在这里拼字符串）。
//
// 注意这里**不做任何允许/拒绝判断**，产出的是 policy 的输入而不是输出。
func (p Principal) PolicyContext(purpose string, level policy.DataLevel) (policy.PolicyContext, error) {
	ctx := policy.PolicyContext{
		Identity:     p.Identity,
		Purpose:      purpose,
		Organization: p.Organization,
		Project:      p.Project,
		DataLevel:    level,
	}
	ctx = ctx.Normalize()
	if err := ctx.Validate(); err != nil {
		return policy.PolicyContext{}, mapIdentityError(err)
	}
	return ctx, nil
}

// ScopesDisplay 只供日志使用；范围 ID 不进审计，落库一律用 ScopeCount。
func (p Principal) ScopesDisplay() string { return p.Chain.Display() }

// mapIdentityError 把 policy 的校验错误换成本包语义。
//
// 不直接 %w 透传原错误：policy 的文案会带上 subject 原值（例如「形如邮箱（a@b.edu）」），
// 一路带上去就会把邮箱塞进审计与错误响应。所以这里逐条认出哨兵、只保留哨兵本身，
// 兜底分支也不写原错误文本（丢了细节就去 IdP 侧按 RequestID 对，不在本层扩散）。
func mapIdentityError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case isSubjectShapeError(err):
		return fmt.Errorf("%w: 请改用 IdP 的稳定标识 claim（不要把邮箱、姓名或学号当 subject）: %v", ErrSubjectUnstable, policy.ErrSubjectUnstable)
	case isMembershipTTL(err):
		return fmt.Errorf("%w: token 带 role/group/project 就必须带 exp，且本包会把 ExpiresAt 写进身份: %v", ErrMembershipTTL, policy.ErrMembershipTTL)
	case errors.Is(err, policy.ErrIdentityExpired):
		return fmt.Errorf("%w: 身份快照已过期: %v", ErrExpired, policy.ErrIdentityExpired)
	case errors.Is(err, policy.ErrIdentityNotYet):
		return fmt.Errorf("%w: 身份快照尚未生效: %v", ErrNotYetValid, policy.ErrIdentityNotYet)
	case errors.Is(err, policy.ErrPurposeMissing):
		return fmt.Errorf("%w: purpose 必填（下游按用途区分配额与合规口径）: %v", ErrConfig, policy.ErrPurposeMissing)
	case errors.Is(err, policy.ErrContext):
		return fmt.Errorf("%w: 策略上下文不完整: %v", ErrConfig, policy.ErrContext)
	case errors.Is(err, policy.ErrScopeID), errors.Is(err, policy.ErrScopeKind):
		return fmt.Errorf("%w: 范围引用不合法: %v", ErrScopeUnmapped, policy.ErrScopeID)
	default:
		return fmt.Errorf("%w: 领域层校验未通过（细节请回 IdP 侧按 RequestID 对齐）", ErrInternal)
	}
}

// isSubjectShapeError 识别 policy 侧「subject 不能作稳定键」的结论。
//
// 用 errors.Is 而不是判字符串：policy 的文案里带着 subject 原值，
// 把它 %w 进来就等于让邮箱顺着错误链进了审计与 HTTP 响应。
func isSubjectShapeError(err error) bool {
	return errors.Is(err, policy.ErrSubjectUnstable) || errors.Is(err, policy.ErrSubjectRequired)
}

// isMembershipTTL 识别 policy 侧「成员关系缺过期时间」的结论。
func isMembershipTTL(err error) bool {
	return errors.Is(err, policy.ErrMembershipTTL)
}
