package server

import (
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// 规则 B：没有会话粘性可用时（新会话，或粘性那家已经不适用），
// 按**当前上游成本**从低到高挑候选，而不是权重随机。
//
// 与规则 A 的关系：A 管"已有会话继续用哪家"（保缓存），B 管"新起一个会话用哪家"（省钱）。
// 两者顺序固定 —— 先看粘性，粘性没得用才轮到价格；否则会话中途换家会把前缀缓存打掉，
// 而缓存省下的输入价（命中与未命中差几十倍）远大于供应商之间的价差。
//
// 额度不足/被限流（上游回 402/429）时给那家记一段短期冷却，于是下次新会话自然落到次便宜的家。

// ruleBQuotaCooldown 是 402/429 之后压的冷却时长。
//
// 比路由配置里的 cooldown_seconds 长：额度问题不会几秒钟就好，而"被限流"通常也要等一个窗口。
// 太短会让规则 B 一遍遍把请求送到已经没额度的家。
const ruleBQuotaCooldown = 5 * time.Minute

// providerCostFact 是「这家此刻每 1K token 的输入/输出有效成本」。
// 币种不同或没有价目的家不出现在结果里 —— 不知道价不等于零价。
type providerCostFact struct {
	in  float64
	out float64
}

// providerCostFacts 是规则 B 与 3.0 候选构造**共用**的成本事实来源。
//
// 两个消费者必须读同一份计算：规则 B 用 (in+out) 挑最便宜的家，routing.Offer
// 用同一对数字给 cheapest 目标函数排序。各算一份就会在峰谷系数或币种口径上
// 出现「规则 B 选了 A、3.0 计划说 B」的静默分叉。
func (s *Server) providerCostFacts(providers []config.Provider, model string, now time.Time) map[string]providerCostFact {
	out := make(map[string]providerCostFact, len(providers))
	if s.db == nil {
		return out
	}
	prices, err := s.db.ProviderPricesEffective(now)
	if err != nil {
		s.log.Warnf("查当前在效价目失败，成本事实本次跳过: %v", err)
		return out
	}
	if len(prices) == 0 {
		return out
	}
	type key struct{ provider, upstream string }
	byKey := make(map[key]store.ProviderPrice, len(prices))
	for _, p := range prices {
		byKey[key{p.Provider, p.UpstreamModel}] = p
	}
	base := s.baseCurrency()
	for _, p := range providers {
		if !p.Enabled {
			continue
		}
		up, ok := p.UpstreamModel(model)
		if !ok {
			continue
		}
		price, ok := byKey[key{p.Name, up}]
		if !ok {
			continue
		}
		// 币种与基准币不符的不参与比价：排序键是 (in_miss + out) 的**数值**，
		// 混币种会比出完全错误的结果。写入口已经拒了异币种，这里是防御 ——
		// 库里可能有早于那道校验的行，或者被直接 SQL 插进来的。
		// 跳过而不是当成 0 价：当成 0 会让它永远胜出，那比不选它还糟。
		if !sameCurrency(price.Currency, base) {
			continue
		}
		ratio := s.peakRuleAt(price.PeakHours, price.OffPeakRatio, price.PeakTZ).RatioAt(now)
		out[p.Name] = providerCostFact{in: price.InMiss * ratio, out: price.Out * ratio}
	}
	return out
}

// cheapestProvider 在当前候选里按上游价挑最便宜的一家；挑不出来返回空串
// （调用方回落到原来的按权重随机）。
//
// 三条刻意的取舍：
//   - **只按有价目的候选排**：没录价目的候选不参与"比价"（不知道价不等于便宜）。
//     全都没价目 → 返回空串，行为与以前完全一致。
//   - **跳过冷却中的候选**：这正是 402/429 记冷却的意义；也顺带避开熔断中的家。
//   - **排序键是 in_miss + out**：把两档单价相加当标量，粗糙但透明 —— 输入输出都贵的家一定靠后。
//     真正精确的做法是按实测 token 混合比加权，那需要历史数据，留待以后。
//   - **乘上各家自己的峰谷系数**：单价是「供应商 × 模型 × 时段」的函数，两家的
//     高峰时段（甚至时区）可以不同，同一时刻谁便宜会因此翻转。不乘就会在空闲时段
//     把贵的家选出来 —— DeepSeek 的高峰价正好是空闲价的两倍，错一次就是双倍成本。
func (s *Server) cheapestProvider(scope string, providers []config.Provider, model string) string {
	now := s.now()
	facts := s.providerCostFacts(providers, model, now)
	best, bestCost := "", 0.0
	for _, p := range providers {
		if !p.Enabled {
			continue
		}
		if s.router.Cooling(userBucket(scope), p.Name) {
			continue
		}
		f, ok := facts[p.Name]
		if !ok {
			continue
		}
		cost := f.in + f.out
		if best == "" || cost < bestCost {
			best, bestCost = p.Name, cost
		}
	}
	return best
}
