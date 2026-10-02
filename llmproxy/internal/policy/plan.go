package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// RouteCandidate 是计划里的一个可执行候选（§2.5 的 Fallbacks 元素）。
//
// Provider 必须是稳定 ID（供应商名或配置里的稳定标识），不允许用显示名或
// base_url 当键 —— 换域名会让历史审计断链。
type RouteCandidate struct {
	Executor      string    `json:"executor"`
	Provider      string    `json:"provider"`
	Model         string    `json:"model"`
	UpstreamModel string    `json:"upstream_model"`
	Weight        float64   `json:"weight,omitempty"`
	Region        string    `json:"region,omitempty"`
	MaxDataLevel  DataLevel `json:"max_data_level"`
}

// Rejection 记录一个被排除的候选及其原因（§6：候选排除原因必须可验证）。
type Rejection struct {
	Provider string `json:"provider"`
	Reason   Reason `json:"reason"`
}

// RoutingPlan 是一次路由决策的完整计划（§2.5）。
//
// 除手册列出的九个字段外，这里带 RoutingSeed 和 Rejections：前者是 §2.8 要求
// 在线请求必须记录的回放输入，后者是 §6 要求可验证的排除原因。两者都是纯增量，
// 不改变原字段语义，序列化后直接进审计。
type RoutingPlan struct {
	Executor       string           `json:"executor"`
	Model          string           `json:"model"`
	UpstreamModel  string           `json:"upstream_model"`
	Fallbacks      []RouteCandidate `json:"fallbacks,omitempty"`
	ProcessorChain []string         `json:"processor_chain,omitempty"`
	MaxRetries     int              `json:"max_retries"`
	ReasonCodes    []Reason         `json:"reason_codes,omitempty"`
	PolicyVersion  string           `json:"policy_version"`
	ExpiresAt      time.Time        `json:"expires_at"`

	RoutingSeed string      `json:"routing_seed,omitempty"`
	Rejections  []Rejection `json:"rejections,omitempty"`
}

var (
	ErrPlan          = errors.New("policy: 路由计划不合法")
	ErrCandidate     = errors.New("policy: 路由候选不合法")
	ErrPlanExpired   = errors.New("policy: 路由计划已过期")
	ErrReasonUnknown = errors.New("policy: 未注册的原因码")
)

// Validate 校验计划的完整性与时效。now 由调用方传入，便于回放。
//
// ExpiresAt 是必填的：没有 TTL 的计划会被下游无限缓存，一次策略回滚就再也
// 传不下去 —— 这正是 §3.0 要求「任何新路径都能按 scope 回滚到 legacy」的前提。
func (p RoutingPlan) Validate(now time.Time) error {
	if p.Executor == "" {
		return fmt.Errorf("%w: executor 不能为空", ErrPlan)
	}
	if p.Model == "" {
		return fmt.Errorf("%w: model 不能为空", ErrPlan)
	}
	if p.UpstreamModel == "" {
		return fmt.Errorf("%w: upstream_model 不能为空", ErrPlan)
	}
	if p.PolicyVersion == "" {
		return fmt.Errorf("%w: policy_version 不能为空（必须来自实际加载的策略包）", ErrPlan)
	}
	if p.MaxRetries < 0 {
		return fmt.Errorf("%w: max_retries 不能为负", ErrPlan)
	}
	if p.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: 缺少 expires_at", ErrPlan)
	}
	if !p.ExpiresAt.After(now) {
		return fmt.Errorf("%w: %s（now=%s）", ErrPlanExpired, p.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	for i, c := range p.Fallbacks {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("%w: 第 %d 个候选: %v", ErrPlan, i, err)
		}
	}
	for _, r := range p.ReasonCodes {
		if !r.Valid() {
			return fmt.Errorf("%w: %q", ErrReasonUnknown, string(r))
		}
	}
	for _, r := range p.Rejections {
		if !r.Reason.Valid() {
			return fmt.Errorf("%w: %q", ErrReasonUnknown, string(r.Reason))
		}
	}
	if dup := duplicateProvider(p.Fallbacks); dup != "" {
		return fmt.Errorf("%w: 候选 %s 重复", ErrPlan, dup)
	}
	return nil
}

// Validate 校验单个候选。
func (c RouteCandidate) Validate() error {
	if c.Provider == "" {
		return fmt.Errorf("%w: provider 不能为空", ErrCandidate)
	}
	if c.Executor == "" {
		return fmt.Errorf("%w: provider %s 缺少 executor", ErrCandidate, c.Provider)
	}
	if c.UpstreamModel == "" {
		return fmt.Errorf("%w: provider %s 缺少 upstream_model", ErrCandidate, c.Provider)
	}
	if c.Weight < 0 {
		return fmt.Errorf("%w: provider %s 权重为负", ErrCandidate, c.Provider)
	}
	if !c.MaxDataLevel.Valid() {
		return fmt.Errorf("%w: provider %s 的 MaxDataLevel 未指定", ErrCandidate, c.Provider)
	}
	return nil
}

// Expired 报告计划是否已过期。
func (p RoutingPlan) Expired(now time.Time) bool { return !now.Before(p.ExpiresAt) }

// Primary 返回首选候选（即 Fallbacks 的第一个）。空列表返回 false。
func (p RoutingPlan) Primary() (RouteCandidate, bool) {
	if len(p.Fallbacks) == 0 {
		return RouteCandidate{}, false
	}
	return p.Fallbacks[0], true
}

// Attempts 给出最大尝试次数：首次 + MaxRetries 次重试，且不会超过候选数。
// 执行侧照这个值循环，就不会出现「计划说三次、代码试五次」的偏差。
func (p RoutingPlan) Attempts() int {
	n := 1 + p.MaxRetries
	if len(p.Fallbacks) > 0 && n > len(p.Fallbacks) {
		n = len(p.Fallbacks)
	}
	return n
}

// SortCandidates 按稳定键排序：provider → upstream_model → executor。
//
// §2.8 明确禁止依赖 map 遍历顺序。选路和回放必须用同一个排序函数，
// 否则「同一输入同一输出」会在第一次候选顺序抖动时就破了。
func SortCandidates(cs []RouteCandidate) []RouteCandidate {
	out := append([]RouteCandidate(nil), cs...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		if out[i].UpstreamModel != out[j].UpstreamModel {
			return out[i].UpstreamModel < out[j].UpstreamModel
		}
		return out[i].Executor < out[j].Executor
	})
	return out
}

func duplicateProvider(cs []RouteCandidate) string {
	seen := make(map[string]bool, len(cs))
	for _, c := range cs {
		if seen[c.Provider] {
			return c.Provider
		}
		seen[c.Provider] = true
	}
	return ""
}

// Digest 是计划的规范摘要，进审计用于「同输入同计划」的回归断言。
//
// 先把候选排序再序列化，因此摘要不受构造时的切片顺序影响；时间统一按 RFC3339
// 编码（§5），跨语言侧只需按同一 JSON 结构重算即可对齐。
func (p RoutingPlan) Digest() (string, error) {
	clone := p
	clone.Fallbacks = SortCandidates(p.Fallbacks)
	clone.ReasonCodes = Reasons(p.ReasonCodes)
	clone.Rejections = sortRejections(p.Rejections)
	data, err := json.Marshal(clone)
	if err != nil {
		return "", fmt.Errorf("policy: 计划序列化失败: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func sortRejections(rs []Rejection) []Rejection {
	out := append([]Rejection(nil), rs...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}

// CandidatesDigest 是候选池摘要（§2.8：在线请求至少记录 routing_seed、候选摘要、
// 最终计划和 policy_version）。只覆盖稳定标识与权重，不含密钥和 base_url。
func CandidatesDigest(cs []RouteCandidate) (string, error) {
	type wire struct {
		Provider      string  `json:"provider"`
		UpstreamModel string  `json:"upstream_model"`
		Weight        float64 `json:"weight,omitempty"`
	}
	sorted := SortCandidates(cs)
	items := make([]wire, 0, len(sorted))
	for _, c := range sorted {
		items = append(items, wire{Provider: c.Provider, UpstreamModel: c.UpstreamModel, Weight: c.Weight})
	}
	data, err := json.Marshal(items)
	if err != nil {
		return "", fmt.Errorf("policy: 候选序列化失败: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// seedDomain 是摘要的域分隔前缀。带上版本，改算法时旧审计不会被误当成可复现。
const seedDomain = "llmproxy-routing-seed-v1"

// DeriveRoutingSeed 实现 §2.8 推荐的 seed 来源：
//
//	routing_seed = H(request_id || policy_version || routing_epoch)
//
// 三段用长度前缀拼接，避免 request_id 里含分隔符时与另一个请求撞出同一个 seed。
// routingEpoch 是路由配置的世代号（候选集或权重发生一次变化就 +1），
// 由调用方提供 —— 本包不猜，也不读配置。
//
// 这个函数只派生 seed，不改变线上抽样算法；抽样在 internal/routing（D 包）。
func DeriveRoutingSeed(requestID, policyVersion, routingEpoch string) (string, error) {
	if requestID == "" {
		return "", fmt.Errorf("policy: request_id 为空，无法派生 routing_seed")
	}
	if policyVersion == "" {
		return "", fmt.Errorf("%w: policy_version 为空，无法派生 routing_seed", ErrPlan)
	}
	h := sha256.New()
	writeSegment := func(segment string) {
		_, _ = fmt.Fprintf(h, "%d:%s;", len(segment), segment)
	}
	writeSegment(seedDomain)
	writeSegment(requestID)
	writeSegment(policyVersion)
	writeSegment(routingEpoch)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:]), nil
}

// ParseRoutingSeed 校验外部传入的 seed（回放输入里带的那个）。
func ParseRoutingSeed(s string) error {
	if len(s) != sha256.Size*2 {
		return fmt.Errorf("policy: routing_seed 应为 %d 位十六进制，当前 %d 位", sha256.Size*2, len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("policy: routing_seed 不是合法十六进制: %w", err)
	}
	return nil
}
