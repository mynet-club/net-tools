package routing

import (
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// Gate 是「这个候选这次请求允不允许用」的唯一提问入口。
//
// 为什么是一个接口而不是直接收 *policy.Resolver：§3.D 禁止 D 绕过 policy resolver，
// 但「怎么把候选映射成资源与动作」属于策略侧词汇（model:<名> + use），归接线方实现；
// D 一旦自己拼判定入参，就有了第二个权限判定实现点，resolver 的规则改动不会同步过来。
//
// 实现必须满足三条契约：
//  1. 同一个 (ctx, chain, offer, now) 必须给出同一个结论 —— 结论抖动会让回放对不上；
//  2. 拒绝时必须给一个已注册的 policy.Reason；D 会原样写进 Rejections
//     （给了未注册或空值时 D 会回落到 candidate_policy_excluded，不会放行）；
//  3. 判定所用的策略版本必须与 Input.PolicyVersion / ctx.PolicyVersion 一致，
//     否则审计里的版本和真正生效的规则内容对不上（手册 §3.0）。
//
// 失败方向是 fail-closed：D 只认 allowed=true，接口 panic 或返回零值都等于拒绝。
type Gate interface {
	Allows(ctx policy.PolicyContext, chain policy.ScopeChain, offer Offer, now time.Time) (bool, policy.Reason)
}
