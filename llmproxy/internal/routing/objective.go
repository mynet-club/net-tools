package routing

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// Objective 是候选排序的目标函数。三档就够了，再多会把「排序」变成一套没有主人的
// 打分系统：每个权重的来源和取值口径都要有人负责，而 D 只负责按给定事实排序。
type Objective string

const (
	// ObjectiveFixedOrder 只用档序 + 粘性 + 有效权重随机，最贴近现网 PickFromPreferring：
	// 线上切到 3.0 时不改变流量分布（§2.8 的第一条）。
	ObjectiveFixedOrder Objective = "fixed-order"

	// ObjectiveCheapest 在档序之内按已知成本升序。未知成本的处置见 AllowUnknownCost。
	ObjectiveCheapest Objective = "cheapest"

	// ObjectiveFastest 在档序之内按观测延迟升序；无观测的候选排在有观测之后（永不占先）。
	ObjectiveFastest Objective = "fastest"
)

// DefaultObjective 是漏配时的取值。选 fixed-order 是有意的：它是唯一与现网同分布的
// 一档，漏配最坏也只是「没有变聪明」，而不是「把流量整体挪到另一家」。
const DefaultObjective = ObjectiveFixedOrder

// ErrObjective 表示目标函数名不在三档之内。
var ErrObjective = fmt.Errorf("routing: 未知的目标函数（可用值：fixed-order、cheapest、fastest）")

// ParseObjective 解析目标函数；空串落到 DefaultObjective，未知取值报错不静默回落。
func ParseObjective(s string) (Objective, error) {
	switch trimmed := strings.TrimSpace(s); trimmed {
	case "":
		return DefaultObjective, nil
	default:
		o := Objective(trimmed)
		if !o.valid() {
			return "", fmt.Errorf("%w: %q", ErrObjective, trimmed)
		}
		return o, nil
	}
}

func (o Objective) valid() bool {
	switch o {
	case ObjectiveFixedOrder, ObjectiveCheapest, ObjectiveFastest:
		return true
	}
	return false
}

func (o Objective) String() string { return string(o) }

// normalize 给空值补默认，让 Validate 和排序看到同一个取值。
func (o Objective) normalize() Objective {
	if o == "" {
		return DefaultObjective
	}
	return o
}

// rankKey 把一个候选在该目标函数下压成可比较的键。全部来自 Offer 的既有事实，
// 不含当前时间与全局状态：now 显式传入，冷却位只反映调用方给的数据。
func (o Objective) less(a, b Offer, now time.Time) bool {
	switch o {
	case ObjectiveCheapest:
		// 「有没有价目」压在档序之前：无价目的候选根本无法参与成本比较，
		// 让它因为处在更低的档而占首选位，等于把「不知道多少钱」当成「最便宜」
		// —— 这正是 §3.D 明令禁止的零成本假设。档序仍然决定**有价目者之间**的先后。
		if a.CostKnown != b.CostKnown {
			return a.CostKnown
		}
		if a.Tier != b.Tier {
			return a.Tier < b.Tier
		}
		// 同一档里能用的先排；全档都在冷却时它们照样参与（不排除，见 Offer.Healthy 的说明）。
		if aa, ba := a.isAvailableAt(now), b.isAvailableAt(now); aa != ba {
			return aa
		}
		if ac, bc := a.unitCost(), b.unitCost(); ac != bc {
			return ac < bc
		}
	case ObjectiveFastest:
		if a.Tier != b.Tier {
			return a.Tier < b.Tier
		}
		// 可用性先于延迟：拿不到延迟数据不等于延迟为 0，正在冷却的便宜延迟观测
		// 更不该压过一家此刻可用的。两者都**不排除**对方（全档不可用时仍入选，
		// 与现网「宁可重试也不硬失败」同形）。
		if aa, ba := a.isAvailableAt(now), b.isAvailableAt(now); aa != ba {
			return aa
		}
		if ah, bh := a.hasObservedLatency(), b.hasObservedLatency(); ah != bh {
			return ah
		}
		if a.ObservedLatencyMs != b.ObservedLatencyMs {
			return a.ObservedLatencyMs < b.ObservedLatencyMs
		}
	default: // fixed-order
		if a.Tier != b.Tier {
			return a.Tier < b.Tier
		}
		// 同档剩余候选按权重降序、同权重按 provider id 升序（fallback 链的构造规则）。
		if aw, bw := a.effectiveWeight(), b.effectiveWeight(); aw != bw {
			return aw > bw
		}
	}
	if a.provider() != b.provider() {
		return a.provider() < b.provider()
	}
	// 最后兜底：上游模型名 + 执行器，保证比较器是全序（policy.SortCandidates 同思路）。
	if a.Candidate.UpstreamModel != b.Candidate.UpstreamModel {
		return a.Candidate.UpstreamModel < b.Candidate.UpstreamModel
	}
	return a.Candidate.Executor < b.Candidate.Executor
}

// rank 返回该目标函数下的稳定全序副本。
func (o Objective) rank(os []Offer, now time.Time) []Offer {
	out := append([]Offer(nil), os...)
	sort.SliceStable(out, func(i, j int) bool { return o.less(out[i], out[j], now) })
	return out
}

// selectionReason 是首选的排序解释码。
//
// fastest 在注册表里没有对应码（见 reasons.go 的缺口表），返回空值表示不写解释码：
// 与其借一个语义错的码，不如只留 Rejections 与顺序本身。
func (o Objective) selectionReason() policy.Reason {
	switch o {
	case ObjectiveCheapest:
		return policy.ReasonCheapestFirst
	case ObjectiveFastest:
		return ""
	default:
		return ""
	}
}
