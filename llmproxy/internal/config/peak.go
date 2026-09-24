package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// 峰谷计时（设计见 docs/pricing-design.md §3「时间段」）。
//
// 单价普遍分高峰/空闲两档 —— DeepSeek 的空闲价正好是高峰价的一半，
// 所以一次请求的单价是「供应商 × 模型 × 时段」的函数。这里负责最后那一维：
// 给定时刻，返回该乘的系数。
//
// **时段按供应商所在时区解释，不按服务器时区。** 生产上的服务器是 UTC，
// 把 DeepSeek 的 "09:00-12:00"（北京时间）当本地时间用会错位 8 小时，
// 高峰判成空闲 —— 账正好差一倍。所以规则自带 TZ。
//
// TZ 用**固定偏移**（"+08:00"）而不是 IANA 名字（"Asia/Shanghai"）：
// 固定偏移不依赖系统 tzdata（Alpine/musl 的精简镜像常常没有 zoneinfo，
// LoadLocation 会失败），而国内供应商本来就固定 +8、没有夏令时。
// 代价是表达不了 EST/PDT 这类带夏令时的时区 —— 真遇到再加。

// PeakRule 是一条峰谷规则：哪几段是高峰、空闲乘几、按哪个时区判。
type PeakRule struct {
	Hours        []string // 形如 "09:00-12:00"；空 = 不分时段
	OffPeakRatio float64  // 空闲时段系数；>= 1、<= 0（视为未设置）或没有 Hours = 不分时段
	TZ           string   // 固定偏移，形如 "+08:00"；空 = +00:00
}

// RatioAt 返回 t 时刻该乘的计价系数：高峰 1，空闲 OffPeakRatio。
//
// 只按「周一~周五 + 时段」判断，**不识别法定节假日** —— DeepSeek 的规则里
// 节假日算空闲，这里会当高峰，偏高估（不会低估）。要更准就把单价填成均价，
// 或等以后加节假日表。
//
// OffPeakRatio <= 0 一律当「没设置」处理，返回 1（不打折）而不是 0。
// 0 意味着「空闲时段免费」，那必须是一个显式表达的决定，不能靠缺省值撞上：
// 价目行只填了 peak_hours、ratio 逐字段回落全局、而全局又没配 pricing 段时，
// 组装出来的 ratio 就是 0 —— 于是高峰之外的全部流量成本与计费一起归零，
// 而且完全静默（不报错、FROZEN 列还显示已冻结，只是金额是 0）。
// 宁可不打折，不要免费。
func (r PeakRule) RatioAt(t time.Time) float64 {
	if len(r.Hours) == 0 || r.OffPeakRatio >= 1 || r.OffPeakRatio <= 0 {
		return 1
	}
	windows, err := parseWindows(r.Hours)
	if err != nil || len(windows) == 0 {
		return 1 // 写入时已校验过，这里只在数据被改坏时兜底
	}
	loc, err := ParseTZ(r.TZ)
	if err != nil {
		return 1
	}
	lt := t.In(loc)
	if wd := lt.Weekday(); wd == time.Saturday || wd == time.Sunday {
		return r.OffPeakRatio
	}
	min := lt.Hour()*60 + lt.Minute()
	for _, w := range windows {
		if min >= w.startMin && min < w.endMin {
			return 1
		}
	}
	return r.OffPeakRatio
}

// Validate 校验规则本身是否合法（写库前调）。
//
// 0 在这里是合法的：价目行的 off_peak_ratio 可空、为空时逐字段回落全局，
// 那条路径组装出来的就是 0，不能在这一层拒掉（RatioAt 会把它当「未设置」按不打折处理）。
// 「调用方显式填了 0」是另一回事 —— 那几乎一定是笔误，由 store.validatePeak 拒，
// 只有它分得清 nil（回落全局）与 0（显式免费）。
func (r PeakRule) Validate() error {
	if _, err := parseWindows(r.Hours); err != nil {
		return err
	}
	if len(r.Hours) > 0 && (r.OffPeakRatio < 0 || r.OffPeakRatio > 1) {
		return fmt.Errorf("off_peak_ratio 需要在 0~1 之间（1 表示不分时段），当前是 %v", r.OffPeakRatio)
	}
	_, err := ParseTZ(r.TZ)
	return err
}

func parseWindows(specs []string) ([]timeWindow, error) {
	out := make([]timeWindow, 0, len(specs))
	for _, spec := range specs {
		if strings.TrimSpace(spec) == "" {
			continue
		}
		w, err := parseTimeWindow(spec)
		if err != nil {
			return nil, fmt.Errorf("peak_hours 里的 %q 不是合法时段（形如 09:00-12:00）: %w", spec, err)
		}
		out = append(out, w)
	}
	return out, nil
}

// ParseTZ 解析固定偏移时区，接受 "+08:00" / "+0800" / "+8" / "-05:30"。
// 空串 = UTC。
func ParseTZ(s string) (*time.Location, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.UTC, nil
	}
	sign := 1
	switch s[0] {
	case '+':
		s = s[1:]
	case '-':
		sign, s = -1, s[1:]
	default:
		return nil, fmt.Errorf("peak_tz 需要带正负号（形如 +08:00），当前是 %q", s)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("peak_tz 缺少偏移量（形如 +08:00）")
	}
	var h, m int
	switch {
	case strings.Contains(s, ":"):
		parts := strings.SplitN(s, ":", 2)
		var err error
		if h, err = strconv.Atoi(parts[0]); err != nil {
			return nil, fmt.Errorf("peak_tz 的小时部分不合法: %q", parts[0])
		}
		if m, err = strconv.Atoi(parts[1]); err != nil {
			return nil, fmt.Errorf("peak_tz 的分钟部分不合法: %q", parts[1])
		}
	case len(s) > 2: // HHMM
		var err error
		if h, err = strconv.Atoi(s[:len(s)-2]); err != nil {
			return nil, fmt.Errorf("peak_tz 的小时部分不合法: %q", s)
		}
		if m, err = strconv.Atoi(s[len(s)-2:]); err != nil {
			return nil, fmt.Errorf("peak_tz 的分钟部分不合法: %q", s)
		}
	default:
		var err error
		if h, err = strconv.Atoi(s); err != nil {
			return nil, fmt.Errorf("peak_tz 的小时部分不合法: %q", s)
		}
	}
	if m > 59 {
		return nil, fmt.Errorf("peak_tz 的分钟部分不合法: %q", s)
	}
	offset := sign * (h*3600 + m*60)
	if offset < -12*3600 || offset > 14*3600 {
		return nil, fmt.Errorf("peak_tz 超出 UTC 偏移范围（-12:00 ~ +14:00），当前是 %q", s)
	}
	return time.FixedZone(fmt.Sprintf("UTC%+03d:%02d", sign*h, m), offset), nil
}
