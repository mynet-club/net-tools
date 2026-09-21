package server

import (
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// 计价冻结（docs/pricing-design.md §4）：请求落库前，按**请求开始时刻**生效的上游价目行
// 把这次的成本算好写死。之后价目怎么改都不影响这一行的金额 —— 这是「记录历史计价」的落地。
//
// 为什么用开始时刻：上游只在响应结束时给一份 usage 快照，**没有 token 时间线**；
// 要按生成时刻切进不同价格区间，只能按请求时长摊分 —— 那是估计，不是计量。
// 一个请求一个价，与「价格整点生效」的价目表一一对应，可审计。
// 峰谷同理：用的是开始时刻那个时段的系数，不是结束时刻的。
//
// 只冻结**系统付费**（走系统池）的请求：BYO 用户用自己的上游，网关不掏钱，
// 真实成本该是 0，而且上游价目表里也没有他家的行。这类请求保持「未冻结」，
// 报表把它归入估算段（对它而言估算段也是 0 成本）。
func (s *Server) freezeUpstreamCost(rec *store.RequestRecord, started time.Time) {
	if rec == nil || !rec.SystemPaid || rec.Provider == "" || rec.UpstreamModel == "" {
		return
	}
	// 只有真正跑完、有 usage 的请求才谈得上成本：4xx/5xx 的响应里没有 usage，
	// 冻一个「只有每请求费」的金额出来反而是错的。
	if !rec.OK || rec.PromptTokens == nil {
		return
	}
	price, err := s.db.ProviderPriceAt(rec.Provider, rec.UpstreamModel, started)
	if err != nil {
		s.log.Warnf("查上游价目失败（%s/%s）: %v", rec.Provider, rec.UpstreamModel, err)
		return
	}
	if price == nil {
		return // 没配价目 → 保持未冻结，报表归入估算段
	}
	ratio := s.peakRuleAt(price.PeakHours, price.OffPeakRatio, price.PeakTZ).RatioAt(started)
	amount := upstreamCost(price, rec, ratio)
	rec.PriceUpstreamID = price.ID
	rec.CostUpstream = &amount
	rec.Currency = price.Currency
}

// globalPeakRule 是全局（config.yaml 的 pricing 段）的峰谷规则，作为价目行的回落。
func (s *Server) globalPeakRule() config.PeakRule {
	if s.cfgStore == nil {
		return config.PeakRule{}
	}
	if c := s.cfgStore.Current(); c != nil {
		return c.Pricing.PeakRule()
	}
	return config.PeakRule{}
}

// peakRuleAt 组装这次请求该用的峰谷规则：价目行自带的部分优先，**逐字段**沿用全局。
//
// 逐字段而不是整条覆盖：价目行可能只填了 peak_hours 而没填 peak_tz，
// 那意思是"时段我定，时区用全局的"，不该因为 ratio 为空就把时段一起丢掉。
func (s *Server) peakRuleAt(hours []string, ratio *float64, tz string) config.PeakRule {
	r := s.globalPeakRule()
	if len(hours) > 0 {
		r.Hours = hours
	}
	if ratio != nil {
		r.OffPeakRatio = *ratio
	}
	if tz != "" {
		r.TZ = tz
	}
	return r
}

// upstreamCost 按上游价目的三档算一次请求的成本（单价单位是「每百万 token」）。
// ratio 是该时刻的峰谷系数（高峰 1，空闲按配置打折）。
func upstreamCost(p *store.ProviderPrice, rec *store.RequestRecord, ratio float64) float64 {
	return costFromRates(p.InHit, p.InMiss, p.InWrite, p.Out, p.PerRequestFee, rec, ratio)
}

// costFromRates 是上游价与分发价共用的三档算法：两层价格的费率形状完全一致，
// 各写一份迟早会漂移（一边改了夹取、另一边没改）。
//
// 三档口径：prompt = 命中 + 写入 + 未命中。
//   - DeepSeek 类：显式报 hit/miss（写入被算在未命中里），以它为准；
//   - neolink 类：报 cached_tokens（命中）与 cache_write_tokens（写入），未命中要减出来。
//
// 峰谷系数只乘 token 部分，**不乘 per_request_fee**：每请求固定费是接入费，
// 与用量无关，供应商也不给它做峰谷浮动。
//
// reasoning_out（推理输出单独计价）暂时不生效：我们还没解析上游的 reasoning_tokens，
// 拿不到那个数就不该假装算得准 —— 输出一律按 out 档计。
func costFromRates(inHit, inMiss, inWrite, out, perReq float64, rec *store.RequestRecord, ratio float64) float64 {
	prompt := tokOr0(rec.PromptTokens)
	completion := tokOr0(rec.CompletionTokens)

	hit, write := rec.CacheHitTokens, rec.CacheWriteTokens
	if hit < 0 {
		hit = 0
	}
	if write < 0 {
		write = 0
	}
	var miss int64
	if rec.CacheMissTokens > 0 {
		miss = rec.CacheMissTokens
	} else {
		miss = prompt - hit - write
		if miss < 0 {
			miss = 0
		}
	}

	sum := float64(hit)*inHit + float64(write)*inWrite + float64(miss)*inMiss + float64(completion)*out
	return sum/1e6*ratio + perReq
}

// freezeDownstreamCharge 按**分发价**（user_prices）冻结"向这个用户收多少钱"。
//
// 与上游成本一样按请求开始时刻取价、一样只在成功且有 usage 时冻结。
// 取价顺序由 store 保证：user:<用户名> 优先，没有则回落 default。
// 只有系统付费的消耗才谈得上收费 —— BYO 用户用自己的上游，网关不掏钱也不向他收钱，
// 那部分只有上游成本要算（而且属于他自己），分发金额保持未冻结。
func (s *Server) freezeDownstreamCharge(rec *store.RequestRecord, started time.Time) {
	if rec == nil || !rec.SystemPaid || rec.UserName == "" || rec.Model == "" {
		return
	}
	if !rec.OK || rec.PromptTokens == nil {
		return
	}
	price, err := s.db.UserPriceAt(rec.UserName, rec.Model, started)
	if err != nil {
		s.log.Warnf("查分发价目失败（%s/%s）: %v", rec.UserName, rec.Model, err)
		return
	}
	if price == nil {
		return // 没配分发价 → 保持未冻结，计费侧按估算兜底
	}
	ratio := s.peakRuleAt(price.PeakHours, price.OffPeakRatio, price.PeakTZ).RatioAt(started)
	amount := costFromRates(price.InHit, price.InMiss, price.InWrite, price.Out, price.PerRequestFee, rec, ratio)
	rec.PriceDownstreamID = price.ID
	rec.Charge = &amount
	if rec.Currency == "" {
		rec.Currency = price.Currency
	}
}

func tokOr0(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// rowCharge 给一行用量算金额：**冻结优先**，未冻结的部分按 legacy 单价表估算兜底。
//
// 配额必须一直有效，所以这里不能"只认冻结值" —— 还没录分发价的模型会瞬间变成 0 成本，
// 配额就形同虚设。切换期的同一天聚合行可能一半冻结一半没冻结，这时按请求数把估算部分
// 按比例摊出来，免得切换当天成本突跳。
//
// 注意这与 stats 的「估算段/冻结段分开列」不矛盾：那是**报表口径**要求两段分开展示，
// 这里是**配额/账单口径**要求必须连续可用。
func rowCharge(r store.UsageRow, p *config.PricingConfig, now time.Time) float64 {
	if r.Requests > 0 && r.FrozenCharges >= r.Requests {
		return r.Charge
	}
	hit, miss := r.CacheHitTokens, r.CacheMissTokens
	if hit+miss == 0 && r.PromptTokens > 0 {
		miss = r.PromptTokens // 上游没报缓存拆分时按「输入全部未命中」保守估
	}
	est := 0.0
	if p != nil && p.Enabled() {
		if c, ok := p.Cost(r.UpstreamModel, hit, miss, r.CompletionTokens, now); ok {
			est = c
		}
	}
	if r.FrozenCharges == 0 || r.Requests == 0 {
		return est
	}
	unfrozen := float64(r.Requests-r.FrozenCharges) / float64(r.Requests)
	return r.Charge + est*unfrozen
}
