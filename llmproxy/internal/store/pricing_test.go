package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func t9() time.Time  { return time.Date(2026, 9, 21, 9, 0, 0, 0, time.UTC) }
func t12() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) }

// 整点生效是与使用者的约定：校验**拒绝**非整点，不静默取整 ——
// 静默取整会在「我以为立即生效」的场景里造成账目对不上。
func TestProviderPriceRequiresHourAlignedValidFrom(t *testing.T) {
	s := openTestStore(t)
	round := t9()
	bad := time.Date(2026, 9, 21, 9, 30, 0, 0, time.UTC)
	sec := time.Date(2026, 9, 21, 9, 0, 5, 0, time.UTC)

	if err := s.InsertProviderPrice(&ProviderPrice{Provider: "p", UpstreamModel: "m", ValidFrom: round, Out: 1}); err != nil {
		t.Fatalf("整点应当能插: %v", err)
	}
	for _, vf := range []time.Time{bad, sec, {}} {
		err := s.InsertProviderPrice(&ProviderPrice{Provider: "p", UpstreamModel: "other", ValidFrom: vf, Out: 1})
		if err == nil {
			t.Errorf("valid_from=%s 应当被拒", vf)
		} else if !strings.Contains(err.Error(), "整点") && !strings.Contains(err.Error(), "valid_from") {
			t.Errorf("错误信息 %q 没说明是整点问题", err.Error())
		}
	}
	// valid_to 也必须整点 / 必须晚于 valid_from
	if err := s.InsertProviderPrice(&ProviderPrice{
		Provider: "p", UpstreamModel: "m", ValidFrom: t12(),
		ValidTo: time.Date(2026, 9, 21, 12, 30, 0, 0, time.UTC),
	}); err == nil {
		t.Error("valid_to 非整点应当被拒")
	}
	if err := s.InsertProviderPrice(&ProviderPrice{
		Provider: "p", UpstreamModel: "m", ValidFrom: t12(), ValidTo: t9(),
	}); err == nil {
		t.Error("valid_to 早于 valid_from 应当被拒")
	}
	// 负单价 / 缺关键字段
	if err := s.InsertProviderPrice(&ProviderPrice{Provider: "p", UpstreamModel: "neg", ValidFrom: t9(), Out: -1}); err == nil {
		t.Error("负单价应当被拒")
	}
	if err := s.InsertProviderPrice(&ProviderPrice{UpstreamModel: "m", ValidFrom: t9()}); err == nil {
		t.Error("缺 provider 应当被拒")
	}
	if err := s.InsertProviderPrice(&ProviderPrice{Provider: "p", ValidFrom: t9()}); err == nil {
		t.Error("缺 upstream_model 应当被拒")
	}
}

// 币种留空时默认 CNY，金额与费率要原样落库（含缓存写入档与每请求费）。
func TestProviderPriceRoundTrip(t *testing.T) {
	s := openTestStore(t)
	off := 0.5
	in := &ProviderPrice{
		Provider: "deepseek", UpstreamModel: "deepseek-flash",
		InMiss: 2.0, InHit: 0.04, InWrite: 2.5, Out: 8.0,
		ReasoningOut: 8.0, PerRequestFee: 0.01,
		PeakHours: []string{"09:00-12:00", "14:00-18:00"}, OffPeakRatio: &off,
		ValidFrom: t9(), Note: "官网报价折后",
	}
	if err := s.InsertProviderPrice(in); err != nil {
		t.Fatalf("插入失败: %v", err)
	}
	if in.Currency != "CNY" {
		t.Errorf("币种留空时应当默认 CNY，实际 %q", in.Currency)
	}
	got, err := s.ProviderPriceAt("deepseek", "deepseek-flash", t9())
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("查不到刚插入的价目")
	}
	if got.InMiss != 2.0 || got.InHit != 0.04 || got.InWrite != 2.5 || got.Out != 8.0 {
		t.Errorf("费率没原样落库: %+v", got)
	}
	if got.ReasoningOut != 8.0 || got.PerRequestFee != 0.01 {
		t.Errorf("推理价/每请求费没原样落库: %+v", got)
	}
	if got.Note != "官网报价折后" || len(got.PeakHours) != 2 || got.OffPeakRatio == nil || *got.OffPeakRatio != 0.5 {
		t.Errorf("备注/峰谷没原样落库: %+v", got)
	}
}

// 同一键上插入新价时，旧的有效行要被收口成 [旧.valid_from, 新.valid_from)；
// 历史行因此天然保留，这是「记录历史计价」的落地方式。
func TestProviderPriceInsertClosesPreviousAndKeepsHistory(t *testing.T) {
	s := openTestStore(t)
	if err := s.InsertProviderPrice(&ProviderPrice{Provider: "p", UpstreamModel: "m", ValidFrom: t9(), Out: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertProviderPrice(&ProviderPrice{Provider: "p", UpstreamModel: "m", ValidFrom: t12(), Out: 2}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListProviderPrices("p", "m")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("应当保留两条历史，实际 %d 条: %+v", len(rows), rows)
	}
	if !rows[0].ValidFrom.Equal(t9()) || !rows[0].ValidTo.Equal(t12()) {
		t.Errorf("旧行应当被收口成 [9:00, 12:00)，实际 %s → %s",
			rows[0].ValidFrom.Format(time.RFC3339), rows[0].ValidTo.Format(time.RFC3339))
	}
	if !rows[1].ValidFrom.Equal(t12()) || !rows[1].ValidTo.IsZero() {
		t.Errorf("新行应当是 [12:00, ∞)，实际 %s → %s",
			rows[1].ValidFrom.Format(time.RFC3339), rows[1].ValidTo.Format(time.RFC3339))
	}
}

// 价目按时间只追加：插入更早的或同一时刻的都会被拒 —— 回头插旧价等于改写历史。
func TestProviderPriceAppendOnly(t *testing.T) {
	s := openTestStore(t)
	if err := s.InsertProviderPrice(&ProviderPrice{Provider: "p", UpstreamModel: "m", ValidFrom: t12(), Out: 2}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertProviderPrice(&ProviderPrice{Provider: "p", UpstreamModel: "m", ValidFrom: t9(), Out: 1}); err == nil {
		t.Error("插入更早的价目应当被拒")
	} else if !strings.Contains(err.Error(), "只追加") {
		t.Errorf("错误信息应当说明只追加，实际 %q", err.Error())
	}
	if err := s.InsertProviderPrice(&ProviderPrice{Provider: "p", UpstreamModel: "m", ValidFrom: t12(), Out: 3}); err == nil {
		t.Error("同一 valid_from 应当被拒（重复）")
	}
}

// 查价按半开区间 [valid_from, valid_to)：边界上 12:00 属于新价。
func TestProviderPriceAtBoundaries(t *testing.T) {
	s := openTestStore(t)
	if err := s.InsertProviderPrice(&ProviderPrice{Provider: "p", UpstreamModel: "m", ValidFrom: t9(), Out: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertProviderPrice(&ProviderPrice{Provider: "p", UpstreamModel: "m", ValidFrom: t12(), Out: 2}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		at   time.Time
		want float64 // 0 = 查不到
	}{
		{t9().Add(-time.Minute), 0},      // 价目生效之前
		{t9(), 1},                        // 9:00 整：旧价生效
		{t9().Add(90 * time.Minute), 1},  // 10:30：仍属旧价
		{t12(), 2},                       // 12:00 整：新价接棒（半开区间）
		{t12().Add(30 * time.Minute), 2}, // 12:30：新价
	}
	for _, c := range cases {
		got, err := s.ProviderPriceAt("p", "m", c.at)
		if err != nil {
			t.Fatalf("查价失败: %v", err)
		}
		if c.want == 0 {
			if got != nil {
				t.Errorf("%s 不该查到价目，实际 %+v", c.at.Format(time.RFC3339), got)
			}
			continue
		}
		if got == nil || got.Out != c.want {
			t.Errorf("%s 应当查到 out=%v，实际 %+v", c.at.Format(time.RFC3339), c.want, got)
		}
	}
	// 别的键查不到
	if got, err := s.ProviderPriceAt("p", "nope", t9()); err != nil || got != nil {
		t.Errorf("别的模型不该查到价目: %+v %v", got, err)
	}
}

// 路由用：某时刻「仍然生效」的全部上游价目行。
func TestProviderPricesEffective(t *testing.T) {
	s := openTestStore(t)
	for _, p := range []ProviderPrice{
		{Provider: "alpha", UpstreamModel: "m", ValidFrom: t9(), Out: 1},
		{Provider: "beta", UpstreamModel: "m", ValidFrom: t9(), Out: 3},
		{Provider: "alpha", UpstreamModel: "m", ValidFrom: t12(), Out: 2},
	} {
		cp := p
		if err := s.InsertProviderPrice(&cp); err != nil {
			t.Fatal(err)
		}
	}
	// 10:00：alpha 的旧价（out=1）与 beta（out=3）在效
	at10 := t9().Add(time.Hour)
	rows, err := s.ProviderPricesEffective(at10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("10:00 应当有两条在效价目，实际 %d: %+v", len(rows), rows)
	}
	got := map[string]float64{}
	for _, r := range rows {
		got[r.Provider] = r.Out
	}
	if got["alpha"] != 1 || got["beta"] != 3 {
		t.Errorf("10:00 在效价目不对: %v", got)
	}
	// 13:00：alpha 换成新价（out=2）
	rows, err = s.ProviderPricesEffective(t12().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got = map[string]float64{}
	for _, r := range rows {
		got[r.Provider] = r.Out
	}
	if got["alpha"] != 2 || got["beta"] != 3 {
		t.Errorf("13:00 在效价目不对: %v", got)
	}
}

// 分发价取价规则：user:<名> 优先，没有则回落 default。
func TestUserPriceAtScopeResolution(t *testing.T) {
	s := openTestStore(t)
	if err := s.InsertUserPrice(&UserPrice{Scope: ScopeDefault, Model: "fast", ValidFrom: t9(), InMiss: 2, Out: 8}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertUserPrice(&UserPrice{Scope: ScopeUser("arthur"), Model: "fast", ValidFrom: t9(), InMiss: 1, Out: 4}); err != nil {
		t.Fatal(err)
	}
	// arthur 有专属价
	got, err := s.UserPriceAt("arthur", "fast", t9())
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.InMiss != 1 || got.Scope != ScopeUser("arthur") {
		t.Errorf("arthur 应当拿到自己的价，实际 %+v", got)
	}
	// bob 没有专属价 → 回落 default
	got, err = s.UserPriceAt("bob", "fast", t9())
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.InMiss != 2 || got.Scope != ScopeDefault {
		t.Errorf("bob 应当回落到 default 价，实际 %+v", got)
	}
	// 没有该模型的价目 → nil
	if got, err := s.UserPriceAt("arthur", "nope", t9()); err != nil || got != nil {
		t.Errorf("没有价目时应当返回 nil: %+v %v", got, err)
	}
	// scope 非法被拒
	if err := s.InsertUserPrice(&UserPrice{Scope: "everyone", Model: "fast", ValidFrom: t9()}); err == nil {
		t.Error("非法 scope 应当被拒")
	}
	// scope 留空 = default
	up := &UserPrice{Model: "bare", ValidFrom: t9(), Out: 1}
	if err := s.InsertUserPrice(up); err != nil {
		t.Fatalf("scope 留空应当当 default 处理: %v", err)
	}
	if up.Scope != ScopeDefault {
		t.Errorf("scope 留空时应当变成 %q，实际 %q", ScopeDefault, up.Scope)
	}
}

// 老库（requests/usage_daily 还是旧形状、没有冻结列）升级：要能补上列、旧数据不丢，
// 而且补完之后新写法（带冻结金额）能正常插入。
func TestMigratePricingColumnsFromLegacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`
CREATE TABLE requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, request_id TEXT NOT NULL,
  client_key_hash TEXT, client_label TEXT, client_ip TEXT,
  model TEXT NOT NULL, provider TEXT, upstream_model TEXT, stream INTEGER NOT NULL DEFAULT 0,
  status_code INTEGER, ok INTEGER NOT NULL DEFAULT 0, latency_ms INTEGER, ttft_ms INTEGER,
  prompt_tokens INTEGER, completion_tokens INTEGER, total_tokens INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0, error_type TEXT, error_msg TEXT
);
CREATE TABLE usage_daily (
  day TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0, ok INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0,
  prompt_tokens INTEGER NOT NULL DEFAULT 0, completion_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens INTEGER NOT NULL DEFAULT 0, latency_sum_ms INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, provider, model)
);
INSERT INTO requests (ts, request_id, model, provider, ok) VALUES (1,'old','m','sys-a',1);
INSERT INTO usage_daily (day, provider, model, requests) VALUES ('2026-09-20','sys-a','m',1);
`); err != nil {
		t.Fatalf("造老库失败: %v", err)
	}
	_ = raw.Close()

	s := openTestStoreAt(t, path)

	// 旧数据还在
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM requests`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("旧请求行应当保留，实际 n=%d err=%v", n, err)
	}
	// 冻结列已经补上：新写入能用
	cost := 1.25
	rec := RequestRecord{
		Ts: time.Now(), RequestID: "new", Model: "m", Provider: "sys-a",
		UpstreamModel: "m", OK: true, CostUpstream: &cost, PriceUpstreamID: 7, Currency: "CNY",
	}
	if err := s.InsertRequest(rec); err != nil {
		t.Fatalf("迁移后写入应成功: %v", err)
	}
	st, err := s.Stats(time.Time{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range st.ByProvider {
		if r.Provider == "sys-a" && r.Model == "m" {
			// 老行没有冻结金额（估算段），新行有 —— frozen 应当只数到 1
			if r.FrozenRequests != 1 {
				t.Errorf("已冻结请求数应当是 1（老行不算），实际 %d", r.FrozenRequests)
			}
			if r.CostUpstream != 1.25 {
				t.Errorf("冻结成本应当是 1.25，实际 %v", r.CostUpstream)
			}
			return
		}
	}
	t.Fatalf("没找到 sys-a/m 的聚合行: %+v", st.ByProvider)
}

// openTestStoreAt 打开指定路径的库（迁移测试要自己造老库）。
func openTestStoreAt(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
