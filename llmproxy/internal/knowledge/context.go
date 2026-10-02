package knowledge

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 预算与结果数的边界。
//
// 上限是必须的：手册 §5 要求「所有外部调用必须设置 timeout、body limit 和目标约束」。
// 没有硬上限时，一个把预算写成 1 小时的配置会把网关的连接池拖死，
// 而调用方还以为只是「检索慢」。
const (
	// DefaultBudget 是未显式指定时的委托超时预算。
	DefaultBudget = 3 * time.Second
	// MaxBudget 是允许配置的最长预算，超过直接拒绝构造。
	MaxBudget = 30 * time.Second
	// DefaultMaxResults 是默认的引用条数上限。
	DefaultMaxResults = 10
	// MaxResultsCeiling 是允许的结果数上限（提示词装配和费用都按命中数放大）。
	MaxResultsCeiling = 100
	// maxPurposeLen 是用途串的长度上限。
	maxPurposeLen = 64
	// maxPolicyVersionLen 是策略版本串的长度上限（形如 id@version|id@version）。
	maxPolicyVersionLen = 512
)

var (
	// ErrContext 表示委托上下文不合法。
	ErrContext = errors.New("knowledge: 检索上下文不合法")
	// ErrContextExpired 表示上下文已过截止时间——过期后必须重新判定，不能复用旧结论。
	ErrContextExpired = errors.New("knowledge: 检索上下文已过截止时间")
)

// RequestContext 是一次委托检索必须携带的上下文。
//
// 一句话说清它存在的意义：**没有它，知识源就只能凭「谁在问」猜权限**。
// 委托协议要判定的正是「这个主体、在这些范围里、为了这个用途、上限到哪一级、
// 按哪一版策略」，缺任何一项，知识源只能选择全给或全不给，两者都是事故。
//
// PolicyVersion 必须来自 A 包 BundleSet.Filter(chain).PolicyVersion()（手册 §3.0），
// 不允许 handler 临时拼接：拼接出来的版本串和真正生效的规则内容对不上，
// 审计与回放当场失去意义。
//
// 时间字段序列化走 time.Time 的默认编码（RFC3339，手册 §5）。
// Budget 是 time.Duration，JSON 里落纳秒整数；线上协议另有 budget_ms 字段，
// 由 BuildRequest 单向转换，禁止反向靠默认值猜。
type RequestContext struct {
	RequestID      string            `json:"request_id"`
	Subject        string            `json:"subject"`
	Chain          policy.ScopeChain `json:"chain"`
	Purpose        string            `json:"purpose"`
	EffectiveLevel policy.DataLevel  `json:"effective_level"`
	PolicyVersion  string            `json:"policy_version"`
	Budget         time.Duration     `json:"budget"`
	MaxResults     int               `json:"max_results"`
	IssuedAt       time.Time         `json:"issued_at"`
	Deadline       time.Time         `json:"deadline"`
}

// NewRequestContext 构造上下文：填默认预算与上限、按 now 推出截止时间，然后校验。
//
// effective 传的是「生效分级上限」，也就是 §2.3 的 effective（或由 D/E 接线时传入的
// 用户档位与检测档位的组合结果）。这里不做分级组合运算，避免 C 变成第二个判定现场；
// 需要 C 贡献 knowledge_level 时调 EffectiveLevelFor。
func NewRequestContext(requestID, subject string, chain policy.ScopeChain, purpose string, effective policy.DataLevel, policyVersion string, now time.Time) (RequestContext, error) {
	rc := RequestContext{
		RequestID:      strings.TrimSpace(requestID),
		Subject:        strings.TrimSpace(subject),
		Chain:          chain,
		Purpose:        strings.TrimSpace(purpose),
		EffectiveLevel: effective,
		PolicyVersion:  strings.TrimSpace(policyVersion),
		Budget:         DefaultBudget,
		MaxResults:     DefaultMaxResults,
		IssuedAt:       now.UTC(),
	}
	rc.Deadline = rc.IssuedAt.Add(rc.Budget)
	if err := rc.Validate(now); err != nil {
		return RequestContext{}, err
	}
	return rc, nil
}

// WithBudget 返回替换超时预算后的副本；超过 MaxBudget 或非正值直接报错而不是静默夹紧。
//
// 不夹紧是刻意的：静默夹紧会让调用方以为自己配了 60 秒、实际只有 30 秒，
// 超时报错时排查方向完全错。
func (rc RequestContext) WithBudget(budget time.Duration) (RequestContext, error) {
	out := rc
	out.Budget = budget
	out.Deadline = out.IssuedAt.Add(budget)
	return out, out.validateFields()
}

// WithMaxResults 返回替换结果数上限后的副本。
func (rc RequestContext) WithMaxResults(maxResults int) (RequestContext, error) {
	out := rc
	out.MaxResults = maxResults
	return out, out.validateFields()
}

// WithDeadline 用外部已知的截止时间收窄预算（上游 HTTP 请求带 deadline 的场景）。
//
// 只允许收窄、不允许放宽：放宽等于让下游一个组件替整条链路续期。
func (rc RequestContext) WithDeadline(deadline time.Time, now time.Time) (RequestContext, error) {
	out := rc
	out.Deadline = deadline.UTC()
	budget := out.Deadline.Sub(out.IssuedAt)
	if budget < 0 {
		return RequestContext{}, fmt.Errorf("%w: 截止时间早于签发时间", ErrContext)
	}
	out.Budget = budget
	if err := out.Validate(now); err != nil {
		return RequestContext{}, err
	}
	return out, nil
}

// Validate 做完整校验，含时效检查（now 显式传参，与 A 包同一口径）。
func (rc RequestContext) Validate(now time.Time) error {
	if err := rc.validateFields(); err != nil {
		return err
	}
	if rc.Expired(now) {
		return fmt.Errorf("%w: deadline=%s now=%s", ErrContextExpired,
			rc.Deadline.Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// validateFields 校验字段形态，不含时效（WithXxx 用，避免构造链上反复比对时钟）。
func (rc RequestContext) validateFields() error {
	if err := validateStableID("request_id", rc.RequestID, maxRequestIDLen); err != nil {
		return fmt.Errorf("%w: %v", ErrContext, err)
	}
	if err := validateSubjectID(rc.Subject); err != nil {
		return fmt.Errorf("%w: %v", ErrContext, err)
	}
	chain, err := policy.NewScopeChain(rc.Chain...)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrContext, err)
	}
	// chain 必须包含 user:<subject>：A 包的约定是集合至少含用户范围。
	// 漏了它，组织级/项目级规则会以为自己面向的是「整个组织」，
	// 而实际上连请求者是谁都没传进来。
	userScope := policy.ScopeRef{Kind: policy.ScopeUser, ID: rc.Subject}
	if err := userScope.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrContext, err)
	}
	if !chain.Includes(userScope) {
		return fmt.Errorf("%w: 范围集合缺少主体自身（user:%s）", ErrContext, rc.Subject)
	}
	if rc.Purpose == "" {
		return fmt.Errorf("%w: purpose 不能为空（配额、出网与保留策略都按用途区分）", ErrContext)
	}
	if len(rc.Purpose) > maxPurposeLen {
		return fmt.Errorf("%w: purpose 长度 %d 超过上限 %d", ErrContext, len(rc.Purpose), maxPurposeLen)
	}
	if strings.ContainsAny(rc.Purpose, "\r\n\t") {
		return fmt.Errorf("%w: purpose 不能含空白或控制字符", ErrContext)
	}
	if !rc.EffectiveLevel.Valid() {
		return fmt.Errorf("%w: 生效分级未指定（零值 LevelUnknown 不等于 public）", ErrContext)
	}
	if rc.PolicyVersion == "" {
		return fmt.Errorf("%w: policy_version 不能为空，且必须来自实际加载的策略包", ErrContext)
	}
	if len(rc.PolicyVersion) > maxPolicyVersionLen {
		return fmt.Errorf("%w: policy_version 超长（%d 字节）", ErrContext, len(rc.PolicyVersion))
	}
	if strings.ContainsAny(rc.PolicyVersion, " \t\r\n") {
		return fmt.Errorf("%w: policy_version 不能含空白", ErrContext)
	}
	if rc.Budget <= 0 {
		return fmt.Errorf("%w: 超时预算必须为正，当前 %s", ErrContext, rc.Budget)
	}
	if rc.Budget > MaxBudget {
		return fmt.Errorf("%w: 超时预算 %s 超过上限 %s", ErrContext, rc.Budget, MaxBudget)
	}
	if rc.MaxResults <= 0 {
		return fmt.Errorf("%w: max_results 必须为正，当前 %d", ErrContext, rc.MaxResults)
	}
	if rc.MaxResults > MaxResultsCeiling {
		return fmt.Errorf("%w: max_results %d 超过上限 %d", ErrContext, rc.MaxResults, MaxResultsCeiling)
	}
	if rc.IssuedAt.IsZero() {
		return fmt.Errorf("%w: issued_at 不能为零值", ErrContext)
	}
	if rc.Deadline.IsZero() {
		return fmt.Errorf("%w: deadline 不能为零值", ErrContext)
	}
	if !rc.Deadline.After(rc.IssuedAt) {
		return fmt.Errorf("%w: deadline 不晚于 issued_at", ErrContext)
	}
	return nil
}

// Expired 报告上下文是否已过截止时间。now 等于 deadline 时算过期（与 A 包同一口径）。
func (rc RequestContext) Expired(now time.Time) bool { return !now.Before(rc.Deadline) }

// Remaining 返回剩余预算，永不为负（负值会让 context.WithTimeout 立刻过期，
// 但错误信息里出现负数时长会让现场误判成「预算是负的」）。
func (rc RequestContext) Remaining(now time.Time) time.Duration {
	left := rc.Deadline.Sub(now)
	if left <= 0 {
		return 0
	}
	return left
}

// UserScope 返回主体自身的范围引用。
func (rc RequestContext) UserScope() policy.ScopeRef {
	return policy.ScopeRef{Kind: policy.ScopeUser, ID: rc.Subject}
}

// ScopeDisplay 给日志用的范围串（只进日志，禁止当存储键，见 policy.ScopeChain）。
func (rc RequestContext) ScopeDisplay() string { return rc.Chain.Display() }
