package routing

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// wildcardModel 是 DeclaredModels 里的通配声明，语义与现网 config.Provider 的
// models: ["*"] 一致：这家能承接任意模型名（直通）。
const wildcardModel = "*"

// 能力名（Requirement.Capabilities / Offer.Capabilities）用同一套小写短横线词汇。
// 这里只是给测试和接线方一个共同的常量，D 不校验取值集合：能力表由各执行器声明，
// 在 D 里做封闭集合会把新能力卡在包外（新增能力应扩执行器侧，不是扩这里）。
const (
	CapabilityTools     = "tools"
	CapabilityVision    = "vision"
	CapabilityStreaming = "streaming"
	CapabilityJSON      = "json-mode"
)

// Offer 是一个候选能提供的东西 + 调用方查到的当下状态。
//
// 它是 D 与外界之间**唯一的候选载体**：policy.RouteCandidate 是进审计与执行器的
// 结论形状（不含可变状态），Offer 在它外面套上「这次为什么能用/优先」的事实。
// 之所以嵌而不复制：Provider/Model/UpstreamModel/Weight/Region/MaxDataLevel 的
// 含义必须与 §2.5 完全一致，另起一套字段名就会开始出现两份候选真相。
//
// 字段全是值类型或字符串切片，没有接口、指针、函数 —— 这是刻意的：
// 一旦塞进 *sql.Row、http.Client、config.Provider 之类的东西，这个结构就再也
// 无法作为回放输入落审计（§2.8 要求回放不依赖当前 provider 配置或数据库状态）。
type Offer struct {
	// Candidate 是进计划的候选（executor / provider / model / upstream_model /
	// weight / region / max_data_level）。
	Candidate policy.RouteCandidate `json:"candidate"`

	// Tier 是调用方算好的档号，小者优先。D 不解释档名的含义，也不保留任何档序表
	// （现网的 8 档由接线方映射，见包注释「档序不归 D」）。
	Tier int `json:"tier"`

	// Healthy 是调用方读到的健康位（熔断计数、探针结论都已在外部折算成这一位）。
	// false 不表示「永远不能用」，只表示「此刻不优先」：全档都不健康时仍会入选，
	// 与现网「宁可重试也不硬失败」保持一致。
	Healthy bool `json:"healthy"`

	// CooldownUntil 是冷却到期时刻（零值 = 没有冷却）。用绝对时间而不是剩余时长：
	// 时长要在 now 上再算一次，回放时 once 传入的时刻不同就会得出相反结论。
	CooldownUntil time.Time `json:"cooldown_until,omitempty"`

	// CostPer1KIn / CostPer1KOut 是每 1K token 的输入/输出单价（元或美元由部署统一，
	// D 只比较大小不定单位）。CostKnown=false 时这两个值**不参与**任何结论。
	CostPer1KIn  float64 `json:"cost_per_1k_in"`
	CostPer1KOut float64 `json:"cost_per_1k_out"`
	CostKnown    bool    `json:"cost_known"`

	// ObservedLatencyMs 是调用方聚合好的观测延迟（毫秒）。<=0 表示无观测，
	// fastest 目标函数下永不占先 —— 没观测不等于零延迟。
	ObservedLatencyMs int64 `json:"observed_latency_ms"`

	// DeclaredModels 是这家显式声明承接的模型名，含 "*" 表示通配兜底。
	// 空切片表示什么都不承接（fail-closed）：漏配映射不能变成「什么都能接」。
	DeclaredModels []string `json:"declared_models,omitempty"`

	// Capabilities 是这家确实具备的能力名（tools/vision/streaming…）。
	Capabilities []string `json:"capabilities,omitempty"`
}

// Requirement 表达这次请求的硬性能力要求。
//
// Model 是**下游（调用方）请求的模型名**，不是上游真名：权限和能力都按这个名字判定，
// UpstreamModel 只是选定候选之后的转换结果。
type Requirement struct {
	Model        string   `json:"model"`
	Capabilities []string `json:"capabilities,omitempty"`
}

var ErrRequirement = errors.New("routing: 能力要求不合法")

// Validate 要求模型名非空。能力列表按大小写敏感比较（上游能力名区分得很），
// 顺序无关紧要：成员判定走集合。
func (r Requirement) Validate() error {
	if strings.TrimSpace(r.Model) == "" {
		return fmt.Errorf("%w: model 不能为空", ErrRequirement)
	}
	for _, c := range r.Capabilities {
		if strings.TrimSpace(c) == "" {
			return fmt.Errorf("%w: capabilities 含空项", ErrRequirement)
		}
	}
	return nil
}

// servesModel 报告这家是否承接该模型名。点名声明与通配都算承接；
// 「点名声明优先于通配」这类**取舍**不在这里做 —— 那是档序（调用方）的事。
func (o Offer) servesModel(model string) bool {
	for _, m := range o.DeclaredModels {
		if m == wildcardModel || m == model {
			return true
		}
	}
	return false
}

// hasCapabilities 报告是否具备全部要求的能力。缺任一即 false（fail-closed）。
func (o Offer) hasCapabilities(required []string) bool {
	if len(required) == 0 {
		return true
	}
	have := make(map[string]bool, len(o.Capabilities))
	for _, c := range o.Capabilities {
		have[c] = true
	}
	for _, c := range required {
		if !have[c] {
			return false
		}
	}
	return true
}

// provider 是稳定排序键（§2.8：候选排序必须先按稳定 provider ID）。
func (o Offer) provider() string { return o.Candidate.Provider }

// effectiveWeight 返回本次真正使用的权重。
//
// 非正权重按 1 处理，语义与现网 bucketize 的 `if w <= 0 { w = 1 }` 一致：
// 没配权重的供应商默认有一份，不能让漏配变成永久不入选。
// 计划里写出的权重（policy.RouteCandidate.Weight）就是这个折算后的值，
// 回放输入因此自带「有效权重」而不需要重新派生。
func (o Offer) effectiveWeight() float64 {
	if o.Candidate.Weight > 0 {
		return o.Candidate.Weight
	}
	return 1
}

// isAvailableAt 报告这一刻这家能不能用。Healthy=false 或在冷却中都算不可用。
//
// 「不可用」不等于「被排除」：现网在全档不可用时照样按权重随机（宁可重试也不硬失败），
// D 保持同一分布。它真正的用处是粘性别钉死一家正在冷却的后端。
func (o Offer) isAvailableAt(now time.Time) bool {
	return o.Healthy && !now.Before(o.CooldownUntil)
}

// unitCost 是 cheapest 的排序键：输入 + 输出各 1K 的合计。
//
// 不在这里按真实 token 数加权：D 看不到正文，也不该猜分词结果（§5）。
// 需要按用量加权时，调用方把折算后的单价放进 CostPer1KIn、CostPer1KOut 置 0 传进来。
func (o Offer) unitCost() float64 {
	if !o.CostKnown {
		return 0
	}
	return o.CostPer1KIn + o.CostPer1KOut
}

// hasObservedLatency 报告是否有可用的观测延迟。
func (o Offer) hasObservedLatency() bool { return o.ObservedLatencyMs > 0 }

// candidateForPlan 产出进计划的候选：权重换成有效权重，这样审计里的 weight
// 就是真正决定流量分布的那个数。
func (o Offer) candidateForPlan() policy.RouteCandidate {
	c := o.Candidate
	c.Weight = o.effectiveWeight()
	return c
}

// Offers 是候选池。
type Offers []Offer

var (
	ErrOffer        = errors.New("routing: 候选输入不合法")
	ErrOfferDup     = errors.New("routing: 候选池里同一个 provider 出现多次")
	ErrTierConflict = errors.New("routing: 同一个 provider 被放进两个档")
)

// Validate 逐条复用 policy.RouteCandidate 的校验，并补齐 D 需要的约束。
//
// 同一 provider 只能有一条：熔断状态、粘性和计划的去重键都是 provider
// （policy.RoutingPlan.Validate 也会拒绝重复候选）。两个上游模型确实要同时可选时，
// 由调用方先按模型映射规则决出唯一一条 —— D 不猜优先级。
//
// 非法候选直接报错而不是塞进 Rejections：那是调用方的构造 bug，
// 静默排除会把配置错误伪装成「策略不允许」，审计就再也查不出真因。
func (os Offers) Validate() error {
	if len(os) == 0 {
		return fmt.Errorf("%w: 候选池为空", ErrOffer)
	}
	seen := make(map[string]int, len(os))
	for i, o := range os {
		if err := o.Candidate.Validate(); err != nil {
			return fmt.Errorf("%w: 第 %d 个候选: %v", ErrOffer, i, err)
		}
		if o.Tier < 0 {
			return fmt.Errorf("%w: %s 的 tier 为负（%d）", ErrOffer, o.provider(), o.Tier)
		}
		if o.Candidate.Weight < 0 {
			return fmt.Errorf("%w: %s 权重为负", ErrOffer, o.provider())
		}
		if o.CostKnown && (o.CostPer1KIn < 0 || o.CostPer1KOut < 0) {
			return fmt.Errorf("%w: %s 已知成本却含负价", ErrOffer, o.provider())
		}
		if prev, ok := seen[o.provider()]; ok {
			if prev != o.Tier {
				return fmt.Errorf("%w: %s 同时在档 %d 和档 %d", ErrTierConflict, o.provider(), prev, o.Tier)
			}
			return fmt.Errorf("%w: %s", ErrOfferDup, o.provider())
		}
		seen[o.provider()] = o.Tier
	}
	return nil
}

// CandidatesDigest 给出候选池摘要，供在线记录（§2.8 至少记 seed、候选摘要、计划、版本）。
func (os Offers) CandidatesDigest() (string, error) {
	cs := make([]policy.RouteCandidate, 0, len(os))
	for _, o := range os {
		cs = append(cs, o.candidateForPlan())
	}
	return policy.CandidatesDigest(cs)
}

// sortedByProviderID 返回按稳定 provider ID 升序的副本，权重相同不再参与比较。
//
// 抽样必须走这个顺序：现网 bucketize 的入参来自 CandidatesOf（已按名字排序），
// 累积扫描的结果依赖池内顺序，两边用同一份排序才能让同 fixture 同结论。
// 复制入参是为了不改动调用方切片 —— Planner 无共享可变状态也包含「不污染输入」。
func sortedByProviderID(os []Offer) []Offer {
	out := append([]Offer(nil), os...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].provider() != out[j].provider() {
			return out[i].provider() < out[j].provider()
		}
		// provider 唯一时到不了这里；真出现（回放输入被人工拼过）就用上游名兜底，
		// 保证比较器是全序，不会出现「谁都不小于谁」导致的顺序抖动。
		return out[i].Candidate.UpstreamModel < out[j].Candidate.UpstreamModel
	})
	return out
}

// StickyState 是会话粘性（现网的 prefer）：把一段对话钉在同一家，别被权重随机打散
// 上游的前缀缓存。
type StickyState struct {
	// Provider 是钉住的那家（稳定 ID）。
	Provider string `json:"provider"`
	// ExpiresAt 是粘性的失效时刻（零值 = 由调用方控制生命周期）。
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// PolicyVersion 记录粘性建立时的策略版本。版本变了不自动失效（§2.8 只要求版本
	// 参与 seed），但调用方可以按它主动清粘性；D 只用它做解释。
	PolicyVersion string `json:"policy_version,omitempty"`
}

// isActiveAt 报告粘性在 now 时刻是否还作数。
func (s *StickyState) isActiveAt(now time.Time) bool {
	if s == nil || s.Provider == "" {
		return false
	}
	return s.ExpiresAt.IsZero() || now.Before(s.ExpiresAt)
}
