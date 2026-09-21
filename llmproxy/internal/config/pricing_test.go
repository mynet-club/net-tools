package config

import (
	"math"
	"testing"
	"time"
)

// 刻意不硬编码 2026-09-01 是周几：从任意基准日推到目标星期，
// 这样测试与「今天」无关。
//
// 时刻用 +08:00 构造，与 samplePricing 里的 peak_tz 一致 —— 峰谷是按
// **供应商时区**判的，与跑测试的机器在哪个时区无关。
func weekdayAt(h, m int, wd time.Weekday) time.Time {
	d := time.Date(2026, 9, 1, h, m, 0, 0, cst)
	for d.Weekday() != wd {
		d = d.AddDate(0, 0, 1)
	}
	return d
}

var cst = time.FixedZone("+08:00", 8*3600)

func samplePricing(t *testing.T) *PricingConfig {
	t.Helper()
	p := &PricingConfig{
		Currency:     "CNY",
		OffPeakRatio: 0.5,
		PeakHours:    []string{"09:00-12:00", "14:00-18:00"},
		PeakTZ:       "+08:00",
		Models: map[string]ModelPrice{
			"deepseek-flash": {CacheHit: 0.04, CacheMiss: 2.0, Output: 8.0},
			"*":              {CacheHit: 0, CacheMiss: 0, Output: 0},
		},
	}
	if err := p.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return p
}

func TestPricingCostCacheSplit(t *testing.T) {
	p := samplePricing(t)
	peak := weekdayAt(10, 0, time.Monday)

	// 各 1M token：0.04 + 2.0 + 8.0
	got, ok := p.Cost("deepseek-flash", 1_000_000, 1_000_000, 1_000_000, peak)
	if !ok {
		t.Fatal("应该能定价")
	}
	if math.Abs(got-10.04) > 1e-9 {
		t.Fatalf("期望 10.04，得到 %v", got)
	}

	// 同样的量，全部算成缓存未命中 → 明显更贵。这条就是「不区分缓存会高估」的证据
	miss, _ := p.Cost("deepseek-flash", 0, 2_000_000, 1_000_000, peak)
	if math.Abs(miss-12.0) > 1e-9 {
		t.Fatalf("期望 12.0，得到 %v", miss)
	}
	if miss <= got {
		t.Fatal("不区分缓存的估算应当更高")
	}
}

func TestPricingOffPeak(t *testing.T) {
	p := samplePricing(t)
	peak := weekdayAt(10, 0, time.Monday)
	off := weekdayAt(13, 0, time.Monday) // 午休时间，不在任何高峰段
	weekend := weekdayAt(10, 0, time.Saturday)

	peakCost, _ := p.Cost("deepseek-flash", 100_000, 100_000, 100_000, peak)
	offCost, _ := p.Cost("deepseek-flash", 100_000, 100_000, 100_000, off)
	weekendCost, _ := p.Cost("deepseek-flash", 100_000, 100_000, 100_000, weekend)

	if math.Abs(offCost*2-peakCost) > 1e-9 {
		t.Fatalf("空闲价应为高峰价的一半：peak=%v off=%v", peakCost, offCost)
	}
	if math.Abs(weekendCost-offCost) > 1e-9 {
		t.Fatalf("周末全天算空闲：weekend=%v off=%v", weekendCost, offCost)
	}
}

func TestPricingFallbackAndUnknown(t *testing.T) {
	p := samplePricing(t)
	now := weekdayAt(10, 0, time.Monday)

	if c, ok := p.Cost("some-other-model", 1_000_000, 1_000_000, 1_000_000, now); !ok || c != 0 {
		t.Fatalf("未列出但有 \"*\" 兜底：ok=%v cost=%v", ok, c)
	}

	// 没有任何单价配置时不该假装能定价
	empty := &PricingConfig{}
	if err := empty.normalize(); err != nil {
		t.Fatal(err)
	}
	if _, ok := empty.Cost("deepseek-flash", 1, 1, 1, now); ok {
		t.Fatal("空单价表不应定价成功")
	}
	if empty.Enabled() {
		t.Fatal("空单价表 Enabled 应为 false")
	}
}

func TestPricingValidation(t *testing.T) {
	bad := []PricingConfig{
		{OffPeakRatio: 1.5},
		{PeakHours: []string{"09:00"}},
		{PeakHours: []string{"12:00-09:00"}},
		{PeakHours: []string{"aa:00-12:00"}},
		{Models: map[string]ModelPrice{"m": {Output: -1}}},
	}
	for i, p := range bad {
		if err := p.normalize(); err == nil {
			t.Fatalf("第 %d 个非法配置应当报错", i)
		}
	}
}

// 没配高峰时段时不该有时段折价，否则等于悄悄打折。
func TestPricingNoPeakWindowMeansNoDiscount(t *testing.T) {
	p := &PricingConfig{OffPeakRatio: 0.5, Models: map[string]ModelPrice{"m": {Output: 10}}}
	if err := p.normalize(); err != nil {
		t.Fatal(err)
	}
	c, _ := p.Cost("m", 0, 0, 1_000_000, time.Now())
	if math.Abs(c-10) > 1e-9 {
		t.Fatalf("期望 10，得到 %v", c)
	}
}
