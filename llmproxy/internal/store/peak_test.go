package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// 峰谷字段（含时区）要原样落库。peak_tz 是后加的列，最容易在迁移里丢掉。
func TestPricePeakFieldsRoundTrip(t *testing.T) {
	s := openTestStore(t)
	off := 0.5

	if err := s.InsertProviderPrice(&ProviderPrice{
		Provider: "deepseek", UpstreamModel: "deepseek-flash", ValidFrom: t9(),
		InMiss: 2, Out: 8,
		PeakHours: []string{"09:00-12:00", "14:00-18:00"}, OffPeakRatio: &off, PeakTZ: "+08:00",
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ProviderPriceAt("deepseek", "deepseek-flash", t9())
	if err != nil || got == nil {
		t.Fatalf("查上游价目: %v %+v", err, got)
	}
	if got.PeakTZ != "+08:00" || got.OffPeakRatio == nil || *got.OffPeakRatio != 0.5 || len(got.PeakHours) != 2 {
		t.Errorf("上游价目的峰谷没原样落库: %+v", got)
	}
	plist, err := s.ListProviderPrices("deepseek", "deepseek-flash")
	if err != nil || len(plist) != 1 || plist[0].PeakTZ != "+08:00" {
		t.Errorf("ListProviderPrices 漏了 peak_tz: %v %+v", err, plist)
	}

	// 分发价一侧：峰谷三列原本根本不存在，是这次一起补的
	if err := s.InsertUserPrice(&UserPrice{
		Scope: ScopeDefault, Model: "fast", ValidFrom: t9(), InMiss: 1, Out: 4,
		PeakHours: []string{"09:00-12:00"}, OffPeakRatio: &off, PeakTZ: "+08:00",
	}); err != nil {
		t.Fatal(err)
	}
	u, err := s.UserPriceAt("anyone", "fast", t9())
	if err != nil || u == nil {
		t.Fatalf("查分发价目: %v %+v", err, u)
	}
	if u.PeakTZ != "+08:00" || u.OffPeakRatio == nil || *u.OffPeakRatio != 0.5 || len(u.PeakHours) != 1 {
		t.Errorf("分发价目的峰谷没原样落库: %+v", u)
	}
	rows, err := s.ListUserPrices(ScopeDefault, "fast")
	if err != nil || len(rows) != 1 || rows[0].PeakTZ != "+08:00" || len(rows[0].PeakHours) != 1 {
		t.Errorf("ListUserPrices 漏了峰谷字段: %v %+v", err, rows)
	}
}

// 非法的峰谷规则要在写库前被拒：时段写法错、时区是 IANA 名、系数越界。
func TestPricePeakValidation(t *testing.T) {
	s := openTestStore(t)
	off, bad := 0.5, 1.5

	for i, p := range []ProviderPrice{
		{Provider: "p", UpstreamModel: "m1", ValidFrom: t9(), PeakHours: []string{"09:00"}},
		{Provider: "p", UpstreamModel: "m2", ValidFrom: t9(), PeakHours: []string{"12:00-09:00"}},
		{Provider: "p", UpstreamModel: "m3", ValidFrom: t9(), PeakHours: []string{"09:00-12:00"}, PeakTZ: "Asia/Shanghai"},
		{Provider: "p", UpstreamModel: "m4", ValidFrom: t9(), PeakHours: []string{"09:00-12:00"}, OffPeakRatio: &bad},
	} {
		cp := p
		if err := s.InsertProviderPrice(&cp); err == nil {
			t.Errorf("第 %d 条非法峰谷应当被拒: %+v", i, cp)
		}
	}
	// 分发价一侧同样被拒
	if err := s.InsertUserPrice(&UserPrice{
		Scope: ScopeDefault, Model: "m", ValidFrom: t9(), PeakTZ: "-13:00",
	}); err == nil {
		t.Error("越界的 peak_tz 应当被拒")
	}
	// 合法写法不该被误伤
	if err := s.InsertProviderPrice(&ProviderPrice{
		Provider: "p", UpstreamModel: "ok", ValidFrom: t9(),
		PeakHours: []string{"09:00-12:00"}, OffPeakRatio: &off, PeakTZ: "+08:00",
	}); err != nil {
		t.Errorf("合法峰谷不该被拒: %v", err)
	}

	// 显式填 0 要拒：0 意味着「空闲时段免费」，而 config.PeakRule.RatioAt 会把 <= 0
	// 当成「未设置」按不打折处理 —— 填 0 既拿不到免费、又几乎一定是笔误
	// （想沿用全局却写了个 0）。这一层分得清 nil 与 0，所以由它来说清楚。
	zero := 0.0
	if err := s.InsertProviderPrice(&ProviderPrice{
		Provider: "p", UpstreamModel: "zero-ratio", ValidFrom: t9(),
		PeakHours: []string{"09:00-12:00"}, OffPeakRatio: &zero, PeakTZ: "+08:00",
	}); err == nil {
		t.Error("显式 off_peak_ratio=0 应当被拒（想沿用全局就不要传这个字段）")
	}
	if err := s.InsertUserPrice(&UserPrice{
		Scope: ScopeDefault, Model: "zero-ratio", ValidFrom: t9(),
		PeakHours: []string{"09:00-12:00"}, OffPeakRatio: &zero, PeakTZ: "+08:00",
	}); err == nil {
		t.Error("分发价一侧显式 off_peak_ratio=0 也应当被拒")
	}
	// 但「只填时段、ratio 留空回落全局」是 README 明确支持的写法，不能被上面那条误伤
	if err := s.InsertProviderPrice(&ProviderPrice{
		Provider: "p", UpstreamModel: "inherit-ratio", ValidFrom: t9(),
		PeakHours: []string{"09:00-12:00"}, PeakTZ: "+08:00",
	}); err != nil {
		t.Errorf("只填时段、ratio 沿用全局不该被拒: %v", err)
	}
}

// 老库的价目表已经有峰谷但没有 peak_tz 列（user_prices 连峰谷都没有）：
// 升级要能补齐列、旧数据不丢、补完能正常读写。
func TestMigratePricePeakColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-peak.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`
CREATE TABLE provider_prices (
  id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT NOT NULL, upstream_model TEXT NOT NULL,
  currency TEXT NOT NULL DEFAULT 'CNY', in_miss REAL NOT NULL DEFAULT 0, in_hit REAL NOT NULL DEFAULT 0,
  in_write REAL NOT NULL DEFAULT 0, out REAL NOT NULL DEFAULT 0, reasoning_out REAL NOT NULL DEFAULT 0,
  per_request_fee REAL NOT NULL DEFAULT 0, peak_hours TEXT NOT NULL DEFAULT '', off_peak_ratio REAL,
  valid_from INTEGER NOT NULL, valid_to INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE user_prices (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL DEFAULT 'default', model TEXT NOT NULL,
  currency TEXT NOT NULL DEFAULT 'CNY', in_miss REAL NOT NULL DEFAULT 0, in_hit REAL NOT NULL DEFAULT 0,
  in_write REAL NOT NULL DEFAULT 0, out REAL NOT NULL DEFAULT 0, reasoning_out REAL NOT NULL DEFAULT 0,
  per_request_fee REAL NOT NULL DEFAULT 0, valid_from INTEGER NOT NULL,
  valid_to INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL
);
INSERT INTO provider_prices (provider, upstream_model, peak_hours, off_peak_ratio, valid_from, created_at)
  VALUES ('old','m','09:00-12:00',0.5,1,1);
`); err != nil {
		t.Fatalf("造老库失败: %v", err)
	}
	_ = raw.Close()

	s := openTestStoreAt(t, path)

	// 老行保留，峰谷不动，peak_tz 补成空串（= 沿用全局）
	rows, err := s.ListProviderPrices("old", "m")
	if err != nil || len(rows) != 1 {
		t.Fatalf("老价目行应当保留: %v %+v", err, rows)
	}
	if rows[0].PeakTZ != "" || len(rows[0].PeakHours) != 1 || rows[0].OffPeakRatio == nil {
		t.Errorf("老行的峰谷不该被动: %+v", rows[0])
	}

	// 补列之后能写带 peak_tz 的新行
	off := 0.5
	if err := s.InsertProviderPrice(&ProviderPrice{
		Provider: "new", UpstreamModel: "m", ValidFrom: t9(), Out: 1,
		PeakHours: []string{"09:00-12:00"}, OffPeakRatio: &off, PeakTZ: "+08:00",
	}); err != nil {
		t.Fatalf("迁移后应当能写 peak_tz: %v", err)
	}
	if got, err := s.ProviderPriceAt("new", "m", t9()); err != nil || got == nil || got.PeakTZ != "+08:00" {
		t.Errorf("迁移后 peak_tz 没落库: %v %+v", err, got)
	}

	// user_prices 的三列同样补齐
	if err := s.InsertUserPrice(&UserPrice{
		Scope: ScopeDefault, Model: "m", ValidFrom: t9(),
		PeakHours: []string{"09:00-12:00"}, OffPeakRatio: &off, PeakTZ: "+08:00",
	}); err != nil {
		t.Fatalf("迁移后应当能写分发价的峰谷: %v", err)
	}
	if u, err := s.UserPriceAt("x", "m", t9()); err != nil || u == nil || u.PeakTZ != "+08:00" {
		t.Errorf("迁移后分发价的 peak_tz 没落库: %v %+v", err, u)
	}

	// 确认列真的加上了（而不是靠内存里的空值蒙过去）
	for _, c := range []struct{ table, col string }{
		{"provider_prices", "peak_tz"},
		{"user_prices", "peak_tz"},
		{"user_prices", "peak_hours"},
		{"user_prices", "off_peak_ratio"},
	} {
		ok, err := hasColumn(s.db, c.table, c.col)
		if err != nil || !ok {
			t.Errorf("%s.%s 应当在迁移后存在（ok=%v err=%v）", c.table, c.col, ok, err)
		}
	}
}
