package config

import (
	"testing"
	"time"
)

func wednesdayAt(h, m int, loc *time.Location) time.Time {
	d := time.Date(2026, 1, 1, h, m, 0, 0, loc)
	for d.Weekday() != time.Wednesday {
		d = d.AddDate(0, 0, 1)
	}
	return d
}

func saturdayAt(h, m int, loc *time.Location) time.Time {
	d := time.Date(2026, 1, 1, h, m, 0, 0, loc)
	for d.Weekday() != time.Saturday {
		d = d.AddDate(0, 0, 1)
	}
	return d
}

func TestParseTZOffsets(t *testing.T) {
	ok := map[string]int{
		"":       0,
		"+00:00": 0,
		"+08:00": 8 * 3600,
		"+0800":  8 * 3600,
		"+8":     8 * 3600,
		"-05:30": -(5*3600 + 30*60),
		"+14:00": 14 * 3600,
		"-12:00": -12 * 3600,
		"+05:45": 5*3600 + 45*60,
	}
	for in, want := range ok {
		loc, err := ParseTZ(in)
		if err != nil {
			t.Fatalf("%q 应当能解析: %v", in, err)
		}
		if _, off := time.Date(2026, 1, 1, 0, 0, 0, 0, loc).Zone(); off != want {
			t.Errorf("%q 的偏移应当是 %d 秒，实际 %d", in, want, off)
		}
	}

	// 拒掉 IANA 名字：固定偏移不依赖系统 tzdata，名字则依赖，Alpine 上常缺
	for _, bad := range []string{"08:00", "Asia/Shanghai", "UTC", "+15:00", "+08:70", "+", "+aa:00", "-13:00"} {
		if _, err := ParseTZ(bad); err == nil {
			t.Errorf("%q 应当被拒", bad)
		}
	}
}

// 峰谷按**供应商时区**判，不按服务器时区。这是最容易错的地方：
// 生产上的服务器是 UTC，把 DeepSeek 的 09:00-12:00 当本地时间用会错位 8 小时。
func TestPeakRuleTZDecidesPeak(t *testing.T) {
	at := wednesdayAt(3, 0, time.UTC) // UTC 周三 03:00 = 北京周三 11:00

	beijing := PeakRule{Hours: []string{"09:00-12:00"}, OffPeakRatio: 0.5, TZ: "+08:00"}
	if got := beijing.RatioAt(at); got != 1 {
		t.Errorf("北京 11:00 应当是高峰（1），实际 %v", got)
	}
	utc := PeakRule{Hours: []string{"09:00-12:00"}, OffPeakRatio: 0.5, TZ: "+00:00"}
	if got := utc.RatioAt(at); got != 0.5 {
		t.Errorf("同一时刻在 UTC 是 03:00、属空闲，应当是 0.5，实际 %v", got)
	}
}

// 时段是半开区间 [start, end)：09:00 算高峰、12:00 已经不算。
func TestPeakRuleWindowBoundaries(t *testing.T) {
	r := PeakRule{Hours: []string{"09:00-12:00", "14:00-18:00"}, OffPeakRatio: 0.5, TZ: "+08:00"}
	cases := []struct {
		h, m int
		want float64
	}{
		{8, 59, 0.5},
		{9, 0, 1},
		{11, 59, 1},
		{12, 0, 0.5},
		{13, 59, 0.5},
		{14, 0, 1},
		{17, 59, 1},
		{18, 0, 0.5},
		{23, 0, 0.5},
	}
	for _, c := range cases {
		if got := r.RatioAt(wednesdayAt(c.h, c.m, cst)); got != c.want {
			t.Errorf("周三 %02d:%02d 应当是 %v，实际 %v", c.h, c.m, c.want, got)
		}
	}
	if got := r.RatioAt(saturdayAt(10, 0, cst)); got != 0.5 {
		t.Errorf("周末全天算空闲（0.5），实际 %v", got)
	}
}

func TestPeakRuleDefaults(t *testing.T) {
	at := wednesdayAt(10, 0, cst)

	// 没配时段 → 不分档
	if got := (PeakRule{}).RatioAt(at); got != 1 {
		t.Errorf("没有时段时应当是 1，实际 %v", got)
	}
	// 系数 >= 1 → 等于不分档
	if got := (PeakRule{Hours: []string{"09:00-12:00"}, OffPeakRatio: 1, TZ: "+08:00"}).RatioAt(at); got != 1 {
		t.Errorf("系数为 1 时应当是 1，实际 %v", got)
	}
	// 数据被改坏（时段不合法）→ 退回 1，而不是让计价算出 NaN 或崩
	if got := (PeakRule{Hours: []string{"nonsense"}, OffPeakRatio: 0.5, TZ: "+08:00"}).RatioAt(at); got != 1 {
		t.Errorf("时段不合法时应当退回 1，实际 %v", got)
	}
	// 时区不合法 → 同样退回 1
	if got := (PeakRule{Hours: []string{"09:00-12:00"}, OffPeakRatio: 0.5, TZ: "Asia/Shanghai"}).RatioAt(at); got != 1 {
		t.Errorf("时区不合法时应当退回 1，实际 %v", got)
	}

	// 系数缺省（0）→ 当成「未设置」按不打折处理，而不是「空闲时段免费」。
	//
	// 这几条必须在**空闲时刻**断言：高峰时段本来就返回 1，测不出区别 ——
	// 而这正是这个坑当初漏过去的原因（价目行只填 peak_hours、ratio 逐字段回落全局、
	// 全局又没配 pricing 段时，组装出来的 ratio 就是 0，于是高峰之外的流量全部记 ¥0）。
	offPeak := wednesdayAt(13, 0, cst)
	if got := (PeakRule{Hours: []string{"09:00-12:00"}, OffPeakRatio: 0, TZ: "+08:00"}).RatioAt(offPeak); got != 1 {
		t.Errorf("系数为 0（未设置）时空闲时段应当退回 1，实际 %v（0 意味着这笔流量免费）", got)
	}
	if got := (PeakRule{Hours: []string{"09:00-12:00"}, OffPeakRatio: -0.5, TZ: "+08:00"}).RatioAt(offPeak); got != 1 {
		t.Errorf("系数为负时应当退回 1，实际 %v", got)
	}
	// 对照：同一时刻、系数确实配了 0.5 → 该打折就打折，别把正常路径一起改坏
	if got := (PeakRule{Hours: []string{"09:00-12:00"}, OffPeakRatio: 0.5, TZ: "+08:00"}).RatioAt(offPeak); got != 0.5 {
		t.Errorf("系数为 0.5 时空闲时段应当是 0.5，实际 %v", got)
	}
}

func TestPeakRuleValidate(t *testing.T) {
	mk := func(hours []string, ratio float64, tz string) PeakRule {
		return PeakRule{Hours: hours, OffPeakRatio: ratio, TZ: tz}
	}
	bad := []PeakRule{
		mk([]string{"09:00"}, 0.5, "+08:00"),
		mk([]string{"12:00-09:00"}, 0.5, "+08:00"),
		mk([]string{"aa:00-12:00"}, 0.5, "+08:00"),
		mk([]string{"09:00-12:00"}, 1.5, "+08:00"),
		mk([]string{"09:00-12:00"}, -0.1, "+08:00"),
		mk([]string{"09:00-12:00"}, 0.5, "Asia/Shanghai"),
		mk(nil, 0.5, "+15:00"),
	}
	for i, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("第 %d 条非法规则（%+v）应当被拒", i, r)
		}
	}
	good := []PeakRule{
		{},
		mk(nil, 0, ""),
		mk([]string{"00:00-24:00"}, 1, "+08:00"),
		mk([]string{"09:00-12:00", "14:00-18:00"}, 0.5, "+08:00"),
	}
	for i, r := range good {
		if err := r.Validate(); err != nil {
			t.Errorf("第 %d 条合法规则（%+v）不该报错: %v", i, r, err)
		}
	}
}
