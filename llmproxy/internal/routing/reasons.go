package routing

import (
	"fmt"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 下面几个常量是 D 想要的原因码在 policy 注册表里的落地值。
//
// 原因码集合是**封闭注册表**：未注册的值会让 policy.RoutingPlan.Validate() 直接失败
// （policy.ErrReasonUnknown），所以在 D 里写裸字符串等于产出一份不可审计的计划。
// 本包不改 internal/policy，只把缺口记在这里 —— 主线补码后，改动就是换掉等号右边一行。
var (
	// ReasonCapabilityUnmatched 想表达的是「这家承接不了这个模型名 / 缺所需能力」。
	//
	// 注册表里目前没有 candidate_capability_unmatched（现有 candidate_* 只覆盖
	// unhealthy / policy / region / level / cost 五个方向），先用 model_not_allowed 落地：
	// 含义方向一致（这个模型对这家不可用），但它与策略侧「模型不在许可范围」共用一个码，
	// 排查时看不出是技术不承接还是策略不授权。已在交付说明里列为需主线补的码。
	ReasonCapabilityUnmatched = policy.ReasonModelNotAllowed

	// 关于「这家在冷却中」：D **不产生**冷却类排除（冷却只影响粘性与档内先后，见
	// Offer.Healthy 的说明），因此这里不需要新码。一旦接线方要求「冷却即排除」，
	// 应使用已注册的 candidate_unhealthy —— 现网的 healthy 位定义就是
	// !now.Before(UnhealthyUntil)（见 internal/router 的 bucketize），两者语义重合。
)

// normalizeGateReason 保证进 Rejections 的码一定可审计。
//
// Gate 允许返回策略内核自己的原因码（model_not_allowed / data_level_denied…），
// 那是最有价值的解释，D 原样保留。但零值或未注册值不能进计划（会让整份计划校验失败，
// 连带把同批其它候选的解释也丢掉），此时回落到 candidate_policy_excluded：
// 结论仍是「被权限门拒掉」，只是解释粒度降级。
func normalizeGateReason(r policy.Reason) policy.Reason {
	if r.Valid() {
		return r
	}
	return policy.ReasonCandidatePolicyExcluded
}

// gateReasonOnAllow 处理放行方向的原因码。
//
// 放行码（explicit_allow / group_allow…）只进回放快照，不进计划的 Rejections，
// 所以未注册或零值都可以留空：留空只是丢掉一层解释，不影响结论。
// 反过来，拒绝方向必须有已注册的码（见 normalizeGateReason），因为 §6 要求
// 「候选排除原因可验证」，而计划校验会直接拒绝未注册的码。
func gateReasonOnAllow(r policy.Reason) policy.Reason {
	if r.Valid() {
		return r
	}
	return ""
}

// explainMissingCost 在显式允许未知成本时把这件事写进 ReasonCodes。
//
// 为什么用 ReasonCodes 而不是 Rejections：这些候选**进了** Fallbacks，
// 把它们记成 Rejection 会让审计说「排除了它」，与实际执行相反。
func explainMissingCost(ranked []Offer) []policy.Reason {
	for _, o := range ranked {
		if !o.CostKnown {
			return []policy.Reason{policy.ReasonCandidateCostUnknown}
		}
	}
	return nil
}

// describeRejections 把排除清单压成一行，只用于错误信息给人看。
// 内容全部是 provider 与已注册原因码，不含价目之外的业务数据与任何凭证。
func describeRejections(rs []policy.Rejection) string {
	if len(rs) == 0 {
		return ""
	}
	out := make([]byte, 0, 32*len(rs))
	for i, r := range rs {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, fmt.Sprintf("%s=%s", r.Provider, string(r.Reason))...)
	}
	return string(out)
}
