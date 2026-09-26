package store

import "time"

// CostFunc 按价目算一行用量的估算金额。ok=false 表示这个模型没价目。
// 参数形状与 config.PricingConfig.Cost 对齐，避免 store 反向依赖 config。
type CostFunc func(model string, cacheHit, cacheMiss, completion int64, at time.Time) (float64, bool)

// RowCharge 给一行用量算金额：**冻结优先**，未冻结的部分按价目估算兜底。
//
// 配额必须一直有效，所以不能「只认冻结值」—— 还没录分发价的模型会瞬间变成 0 成本，
// 配额就形同虚设。切换期的同一天聚合行可能一半冻结一半没冻结，这时按请求数把估算
// 部分按比例摊出来，免得切换当天成本突跳。
//
// 服务端、CLI、API 一律走这一份：以前 cmd 里有一份简化副本（rowChargeOf），
// 两边算法一旦漂移就会「CLI 报一个数、API 报另一个数」。
//
// 注意这与 stats 的「估算段/冻结段分开列」不矛盾：那是**报表口径**要求两段分开展示，
// 这里是**配额/账单口径**要求必须连续可用。
func RowCharge(r UsageRow, cost CostFunc, now time.Time) float64 {
	// 摊分的分母用 OK（成功请求数）而不是 Requests：**失败请求永远不会被冻结**
	// （冻结在 !rec.OK 时直接 return），却照样给 Requests +1。
	// 拿 Requests 当分母的话，只要这一行有过任何一次失败，FrozenCharges < Requests
	// 就永久成立，于是永远走摊分路径 —— 失败请求贡献 0 token 却贡献 +1 分母，
	// est 会被按失败率重复摊一遍到已经冻结的金额上。实测 9 成功 + 1 失败：
	// 正确是 18.0，算出来 19.8，多收正好 10%（= 失败率）。
	if r.OK > 0 && r.FrozenCharges >= r.OK {
		return r.Charge
	}
	hit, miss := r.CacheHitTokens, r.CacheMissTokens
	if hit+miss == 0 && r.PromptTokens > 0 {
		miss = r.PromptTokens // 上游没报缓存拆分时按「输入全部未命中」保守估
	}
	est := 0.0
	if cost != nil {
		if v, ok := cost(r.UpstreamModel, hit, miss, r.CompletionTokens, now); ok {
			est = v
		}
	}
	if r.FrozenCharges == 0 || r.OK == 0 {
		return est
	}
	// 残留的不精确（明确接受）：成功但上游没回报 usage 的请求同样不会被冻结，
	// 却仍被算进这个分母，于是摊出来的比例略偏大。要彻底精确得在 usage_user_daily
	// 里单记一列「可冻结请求数」，那是一次 schema 迁移。
	unfrozen := float64(r.OK-r.FrozenCharges) / float64(r.OK)
	return r.Charge + est*unfrozen
}
