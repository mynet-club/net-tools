package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PricingConfig 是消费模式的单价表。
//
// 它只用来**估算金额**，不做扣款、不记余额 —— 那是支付系统的活。
// 但估算要准，否则配额就成了摆设，所以三个维度都得支持：
//
//   - 缓存命中 / 未命中分开计价：DeepSeek 的命中价只有未命中的 1/50，
//     把输入全按未命中价算，agent 类负载的估算能偏高一个量级。
//   - 空闲 / 高峰两档：多数供应商的高峰价是空闲价的 2 倍。
//   - 输出单独计价。
//
// 单价单位统一为「每百万 token」，与各家官网的报价口径一致，省得换算。
type PricingConfig struct {
	Currency     string                `yaml:"currency"`
	OffPeakRatio float64               `yaml:"off_peak_ratio"`
	PeakHours    []string              `yaml:"peak_hours"`
	Models       map[string]ModelPrice `yaml:"models"`

	windows []timeWindow
}

// ModelPrice 是单个模型的单价（每百万 token）。
type ModelPrice struct {
	CacheHit  float64 `yaml:"cache_hit"`
	CacheMiss float64 `yaml:"cache_miss"`
	Output    float64 `yaml:"output"`
}

type timeWindow struct {
	startMin int
	endMin   int
}

// Enabled 报告是否配置了单价表。
func (p *PricingConfig) Enabled() bool {
	return p != nil && len(p.Models) > 0
}

func (p *PricingConfig) normalize() error {
	if p == nil {
		return nil
	}
	if p.Currency == "" {
		p.Currency = "CNY"
	}
	if p.OffPeakRatio < 0 || p.OffPeakRatio > 1 {
		return fmt.Errorf("pricing.off_peak_ratio 需要在 0~1 之间（0 或 1 表示不分时段），当前是 %v", p.OffPeakRatio)
	}
	p.windows = nil
	for _, spec := range p.PeakHours {
		w, err := parseTimeWindow(spec)
		if err != nil {
			return fmt.Errorf("pricing.peak_hours 里的 %q 不是合法时段（形如 09:00-12:00）: %w", spec, err)
		}
		p.windows = append(p.windows, w)
	}
	if len(p.windows) == 0 {
		p.OffPeakRatio = 1 // 没配高峰时段就没有空闲概念
	}
	for name, mp := range p.Models {
		if mp.CacheHit < 0 || mp.CacheMiss < 0 || mp.Output < 0 {
			return fmt.Errorf("pricing.models.%s 的单价不能为负", name)
		}
	}
	return nil
}

func parseTimeWindow(s string) (timeWindow, error) {
	parts := strings.SplitN(strings.TrimSpace(s), "-", 2)
	if len(parts) != 2 {
		return timeWindow{}, fmt.Errorf("缺少 \"-\"")
	}
	start, err := parseClock(parts[0])
	if err != nil {
		return timeWindow{}, err
	}
	end, err := parseClock(parts[1])
	if err != nil {
		return timeWindow{}, err
	}
	if end <= start {
		return timeWindow{}, fmt.Errorf("结束时间必须晚于开始时间")
	}
	return timeWindow{startMin: start, endMin: end}, nil
}

func parseClock(s string) (int, error) {
	parts := strings.SplitN(strings.TrimSpace(s), ":", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("%q 不是 HH:MM", s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 24 {
		return 0, fmt.Errorf("%q 的小时部分不合法", s)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("%q 的分钟部分不合法", s)
	}
	return h*60 + m, nil
}

// PriceFor 返回该模型的单价；没有精确匹配时退回 "*"，都没有则返回 false。
//
// 键一律用**上游模型名**（供应商真正计费的那个名字），不是下游请求里的别名。
func (p *PricingConfig) PriceFor(model string) (ModelPrice, bool) {
	if p == nil || len(p.Models) == 0 {
		return ModelPrice{}, false
	}
	if mp, ok := p.Models[model]; ok {
		return mp, true
	}
	if mp, ok := p.Models["*"]; ok {
		return mp, true
	}
	return ModelPrice{}, false
}

// ratioAt 返回该时刻的计价系数。
//
// 只按「周一~周五 + 时段」判断，不识别法定节假日 —— 那些天会按高峰价算，
// 估算会略偏高。要更准就自己把单价填成实际均价。
func (p *PricingConfig) ratioAt(t time.Time) float64 {
	if p == nil || p.OffPeakRatio >= 1 || len(p.windows) == 0 {
		return 1
	}
	wd := t.Weekday()
	if wd == time.Saturday || wd == time.Sunday {
		return p.OffPeakRatio
	}
	min := t.Hour()*60 + t.Minute()
	for _, w := range p.windows {
		if min >= w.startMin && min < w.endMin {
			return 1
		}
	}
	return p.OffPeakRatio
}

// Cost 估算一次请求的金额。priced=false 表示这个模型没配单价（金额按 0 计）。
//
// cacheMiss 传 0 时按「输入全部未命中」处理 —— 上游不报缓存拆分时的保守估计。
func (p *PricingConfig) Cost(model string, cacheHit, cacheMiss, output int64, at time.Time) (float64, bool) {
	mp, ok := p.PriceFor(model)
	if !ok {
		return 0, false
	}
	const mtok = 1_000_000
	c := float64(cacheHit)/mtok*mp.CacheHit +
		float64(cacheMiss)/mtok*mp.CacheMiss +
		float64(output)/mtok*mp.Output
	return c * p.ratioAt(at), true
}
