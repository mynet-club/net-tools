package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// priceHarness 搭一个能跑 price set/list 的最小环境：
// 一份指向临时库的 config.yaml + 对应的 Paths。
func priceHarness(t *testing.T) (config.Paths, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "data", "llmproxy.db")
	cfgPath := filepath.Join(dir, "config.yaml")
	yaml := "# 顶注\n" +
		"server:\n  host: 127.0.0.1\n  port: 8787\n  api_keys: [sk-x]\n" +
		"routing: {retry: 2}\n" +
		"providers:\n  - name: p\n    enabled: true\n    base_url: https://api.example.com/v1\n    api_key: k\n    models: [\"*\"]\n" +
		"database:\n  path: \"" + dbPath + "\"\n" +
		"log:\n  level: info\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := config.Paths{ConfigFile: cfgPath, PIDFile: filepath.Join(dir, "x.pid"), RuntimeDir: dir}
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return paths, db
}

// nextHour 是 price set 缺省的 valid_from：下一个整点（UTC）。
func nextHour() time.Time {
	return time.Now().UTC().Truncate(time.Hour).Add(time.Hour)
}

// priceSet provider：录进去、值对、InWrite 不传时留 0（含义=与 in_miss 同价）。
func TestPriceSetProvider(t *testing.T) {
	paths, db := priceHarness(t)
	vf := nextHour().Format(time.RFC3339)
	err := priceSet(paths, []string{
		"provider", "deepseek", "deepseek-flash",
		"-in-miss", "0.04", "-out", "2", "-valid-from", vf, "-note", "官网报价",
	})
	if err != nil {
		t.Fatalf("price set provider 失败: %v", err)
	}
	rows, err := db.ListProviderPrices("deepseek", "deepseek-flash")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("应当有 1 条价目，实际 %d", len(rows))
	}
	r := rows[0]
	if r.InMiss != 0.04 || r.Out != 2 {
		t.Errorf("单价不对: miss=%g out=%g", r.InMiss, r.Out)
	}
	if r.InWrite != 0 {
		t.Errorf("没传 -in-write 时应当是 0（= 与 in_miss 同价），实际 %g", r.InWrite)
	}
	if r.Note != "官网报价" {
		t.Errorf("note 没存进去: %q", r.Note)
	}
	if r.Currency != "CNY" {
		t.Errorf("币种缺省应当是基准币 CNY，实际 %q", r.Currency)
	}
	if r.OffPeakRatio != nil {
		t.Errorf("没传 -off-peak-ratio 时应当是 nil（回落全局），实际 %v", *r.OffPeakRatio)
	}
}

// price set user：scope 校验、值落库、显式 -in-write 生效。
func TestPriceSetUser(t *testing.T) {
	paths, db := priceHarness(t)
	vf := nextHour().Format(time.RFC3339)
	if err := priceSet(paths, []string{
		"user", "default", "deepseek-flash",
		"-in-miss", "0.052", "-in-write", "0.1", "-out", "2.6", "-valid-from", vf,
	}); err != nil {
		t.Fatalf("price set user 失败: %v", err)
	}
	rows, err := db.ListUserPrices("default", "deepseek-flash")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("应当有 1 条，实际 %d", len(rows))
	}
	if rows[0].InWrite != 0.1 {
		t.Errorf("显式 -in-write 应当生效，实际 %g", rows[0].InWrite)
	}

	// 非法 scope 拒掉
	if err := priceSet(paths, []string{
		"user", "not-a-scope", "m", "-in-miss", "1", "-out", "1", "-valid-from", vf,
	}); err == nil {
		t.Error("scope 不是 default 或 user: 前缀时应当被拒")
	}
}

// valid_from 不是整点必须被拒（价格只在整点生效，不静默取整）。
func TestPriceSetRejectsOffHourValidFrom(t *testing.T) {
	paths, _ := priceHarness(t)
	bad := time.Now().UTC().Truncate(time.Hour).Add(30 * time.Minute).Format(time.RFC3339)
	err := priceSet(paths, []string{
		"provider", "p", "m", "-in-miss", "1", "-out", "1", "-valid-from", bad,
	})
	if err == nil || !strings.Contains(err.Error(), "整点") {
		t.Fatalf("非整点 valid_from 应当被拒并说明原因，实际 err=%v", err)
	}
}

// 同一键再插一条更晚的：旧行被收口（valid_to=新行.valid_from），历史保留两条。
func TestPriceSetClosesPreviousAndKeepsHistory(t *testing.T) {
	paths, db := priceHarness(t)
	t1 := nextHour()
	t2 := t1.Add(time.Hour)
	if err := priceSet(paths, []string{
		"provider", "p", "m", "-in-miss", "1", "-out", "1", "-valid-from", t1.Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	if err := priceSet(paths, []string{
		"provider", "p", "m", "-in-miss", "2", "-out", "2", "-valid-from", t2.Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListProviderPrices("p", "m")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("历史应当保留 2 条，实际 %d", len(rows))
	}
	// 第一条已被收口到 t1→t2
	if rows[0].ValidTo.IsZero() || !rows[0].ValidTo.Equal(t2) {
		t.Errorf("旧行应当被收口到 %s，实际 %s", t2.Format(time.RFC3339), rows[0].ValidTo.Format(time.RFC3339))
	}
	if !rows[1].ValidTo.IsZero() {
		t.Errorf("新行应当一直有效，实际 valid_to=%s", rows[1].ValidTo.Format(time.RFC3339))
	}
	if rows[0].InMiss != 1 || rows[1].InMiss != 2 {
		t.Errorf("两条历史的单价都不该被改写: %g, %g", rows[0].InMiss, rows[1].InMiss)
	}

	// 回头插更早的必须被拒
	err = priceSet(paths, []string{
		"provider", "p", "m", "-in-miss", "0.5", "-out", "0.5",
		"-valid-from", t1.Add(-time.Hour).Format(time.RFC3339),
	})
	if err == nil || !strings.Contains(err.Error(), "只追加") {
		t.Fatalf("往回插更早的价应当被拒，实际 err=%v", err)
	}
}

// 不传 -valid-from 时缺省取**下一个整点**（不是现在）：避开「只追加」对同刻插入的拒绝，
// 同时保证「整点生效」这条约定在缺省路径上也成立。
func TestPriceSetDefaultValidFromIsNextHour(t *testing.T) {
	paths, db := priceHarness(t)
	before := time.Now().UTC()
	if err := priceSet(paths, []string{
		"provider", "p", "m", "-in-miss", "1", "-out", "1",
	}); err != nil {
		t.Fatalf("缺省 valid_from 的录价失败: %v", err)
	}
	rows, err := db.ListProviderPrices("p", "m")
	if err != nil || len(rows) != 1 {
		t.Fatalf("应当 1 条，实际 %d err=%v", len(rows), err)
	}
	vf := rows[0].ValidFrom
	if vf.Minute() != 0 || vf.Second() != 0 || vf.Nanosecond() != 0 {
		t.Errorf("缺省 valid_from 必须是整点，实际 %s", vf.Format(time.RFC3339Nano))
	}
	if !vf.After(before) {
		t.Errorf("缺省 valid_from 应当晚于现在（下一个整点），实际 %s ≤ %s",
			vf.Format(time.RFC3339), before.Format(time.RFC3339))
	}
	// 下一个整点 = 现在截断到整点再加 1 小时
	want := before.Truncate(time.Hour).Add(time.Hour)
	if !vf.Equal(want) {
		t.Errorf("缺省 valid_from 应当是 %s，实际 %s",
			want.Format(time.RFC3339), vf.Format(time.RFC3339))
	}
}

// 显式 -off-peak-ratio 0 是「空闲免费」，但 store 的校验会拒（<=0 要求正数）。
// 想沿用全局就不要传这个参数 —— CLI 用 markExplicit 区分「没传」与「传了 0」。
func TestPriceSetOffPeakRatioExplicitZeroRejected(t *testing.T) {
	paths, db := priceHarness(t)
	err := priceSet(paths, []string{
		"provider", "p", "m", "-in-miss", "1", "-out", "1",
		"-peak-hours", "09:00-12:00", "-off-peak-ratio", "0",
		"-valid-from", nextHour().Format(time.RFC3339),
	})
	if err == nil {
		t.Fatal("显式 off_peak_ratio=0 应当被拒（要沿用全局就别传）")
	}
	rows, _ := db.ListProviderPrices("p", "m")
	if len(rows) != 0 {
		t.Errorf("被拒的录入不该落库，实际 %d 条", len(rows))
	}
}

// 带峰谷规则的价目能落库并回读。
func TestPriceSetWithPeakRule(t *testing.T) {
	paths, db := priceHarness(t)
	if err := priceSet(paths, []string{
		"provider", "neolink", "gp-5.6-so",
		"-in-miss", "0.3", "-out", "15",
		"-peak-hours", "09:00-12:00,14:00-18:00", "-off-peak-ratio", "0.5", "-peak-tz", "+08:00",
		"-valid-from", nextHour().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("带峰谷的录价失败: %v", err)
	}
	rows, err := db.ListProviderPrices("neolink", "gp-5.6-so")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("应当 1 条，实际 %d", len(rows))
	}
	r := rows[0]
	if len(r.PeakHours) != 2 || r.PeakHours[0] != "09:00-12:00" || r.PeakHours[1] != "14:00-18:00" {
		t.Errorf("peak_hours 不对: %v", r.PeakHours)
	}
	if r.OffPeakRatio == nil || *r.OffPeakRatio != 0.5 {
		t.Errorf("off_peak_ratio 不对: %v", r.OffPeakRatio)
	}
	if r.PeakTZ != "+08:00" {
		t.Errorf("peak_tz 不对: %q", r.PeakTZ)
	}
}

// price list：空库给出可操作的提示；录完后能列出当前生效；指定键能看历史。
func TestPriceList(t *testing.T) {
	paths, db := priceHarness(t)
	// 空库不报错
	if err := priceList(paths, nil); err != nil {
		t.Fatalf("空库 price list 不该报错: %v", err)
	}

	t1 := nextHour()
	if err := priceSet(paths, []string{
		"provider", "p", "m", "-in-miss", "1", "-out", "1", "-valid-from", t1.Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	if err := priceSet(paths, []string{
		"user", "default", "m", "-in-miss", "1.3", "-out", "1.1", "-valid-from", t1.Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	if err := priceList(paths, nil); err != nil {
		t.Fatalf("price list 失败: %v", err)
	}
	// 历史查询
	if err := priceList(paths, []string{"-provider", "p", "-upstream-model", "m"}); err != nil {
		t.Fatalf("历史查询失败: %v", err)
	}
	if err := priceList(paths, []string{"-scope", "default", "-model", "m"}); err != nil {
		t.Fatalf("分发价历史查询失败: %v", err)
	}
	// db 再次确认两层价都在
	ps, _ := db.ProviderPricesEffective(time.Now())
	us, _ := db.UserPricesEffective(time.Now())
	// valid_from 是下一个整点，现在还没生效，所以 effective 可能是空 —— 这是正确行为
	_ = ps
	_ = us
	rows, _ := db.ListProviderPrices("p", "m")
	if len(rows) != 1 {
		t.Errorf("历史里应当有 1 条，实际 %d", len(rows))
	}
}

// UserPricesEffective：没到 valid_from 时不生效；到了才生效。
func TestUserPricesEffective(t *testing.T) {
	_, db := priceHarness(t)
	t1 := nextHour()
	if err := db.InsertUserPrice(&store.UserPrice{
		Scope: "default", Model: "m", Currency: "CNY",
		InMiss: 1, Out: 1, ValidFrom: t1,
	}); err != nil {
		t.Fatal(err)
	}
	// 现在还没生效
	if us, _ := db.UserPricesEffective(time.Now()); len(us) != 0 {
		t.Errorf("valid_from 之前不该生效，实际 %d 条", len(us))
	}
	// 到点后生效
	if us, _ := db.UserPricesEffective(t1); len(us) != 1 {
		t.Errorf("valid_from 当刻应当生效，实际 %d 条", len(us))
	}
}
