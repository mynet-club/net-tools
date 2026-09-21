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

// cheapestProvider 在当前候选里按上游价挑最便宜的一家；挑不出来返回空串
// （调用方回落到原来的按权重随机）。
//
// 三条刻意的取舍：
//   - **只按有价目的候选排**：没录价目的候选不参与"比价"（不知道价不等于便宜）。
//     全都没价目 → 返回空串，行为与以前完全一致。
//   - **跳过冷却中的候选**：这正是 402/429 记冷却的意义；也顺带避开熔断中的家。
//   - **排序键是 in_miss + out**：把两档单价相加当标量，粗糙但透明 —— 输入输出都贵的家一定靠后。
//     真正精确的做法是按实测 token 混合比加权，那需要历史数据，留待以后。
func (s *Server) cheapestProvider(scope string, providers []config.Provider, model string) string {
	if s.db == nil {
		return ""
	}
	prices, err := s.db.ProviderPricesEffective(time.Now())
	if err != nil {
		s.log.Warnf("查当前在效价目失败，规则 B 本次跳过: %v", err)
		return ""
	}
	if len(prices) == 0 {
		return ""
	}
	type key struct{ provider, upstream string }
	byKey := make(map[key]store.ProviderPrice, len(prices))
	for _, p := range prices {
		byKey[key{p.Provider, p.UpstreamModel}] = p
	}

	best, bestCost := "", 0.0
	for _, p := range providers {
		if !p.Enabled {
			continue
		}
		up, ok := p.UpstreamModel(model)
		if !ok {
			continue
		}
		if s.router.Cooling(scope, p.Name) {
			continue
		}
		price, ok := byKey[key{p.Name, up}]
		if !ok {
			continue
		}
		cost := price.InMiss + price.Out
		if best == "" || cost < bestCost {
			best, bestCost = p.Name, cost
		}
	}
	return best
}
