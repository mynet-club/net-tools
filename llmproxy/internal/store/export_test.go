package store

import (
	"testing"
	"time"
)

// 导出与月合计：同一套账，适合出账/对账。金额字段由调用方用 RowCharge 补。
func TestUsageExportAndMonthlyRollup(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	day := now.Format("2006-01-02")
	charge := 2.5

	for i, u := range []string{"alice", "bob"} {
		for j := 0; j < 2; j++ {
			c := charge * float64(j+1)
			if err := s.InsertRequest(RequestRecord{
				Ts: now, RequestID: "e-" + u + string(rune('0'+j)), UserName: u,
				Model: "m", Provider: "p", UpstreamModel: "m-up", SystemPaid: true, OK: true,
				PromptTokens: i64(10), CompletionTokens: i64(5), TotalTokens: i64(15),
				CacheMissTokens: 10, Charge: &c, Currency: "CNY", Attempts: 1,
			}); err != nil {
				t.Fatal(err)
			}
		}
		_ = i
	}

	rows, err := s.UsageExportRows(UsageExportFilter{})
	if err != nil {
		t.Fatal(err)
	}
	// 2 用户 × 同一天同模型 → 聚合成 2 行
	if len(rows) != 2 {
		t.Fatalf("应当 2 行（每用户一行），实际 %d: %+v", len(rows), rows)
	}
	// 按日升序、带用户名
	if rows[0].UserName == "" {
		t.Error("导出行应当带 UserName")
	}
	// 金额由调用方算：冻结优先
	for i := range rows {
		rows[i].Amount = RowCharge(rows[i].UsageRow, nil, now)
		if rows[i].Amount <= 0 {
			t.Errorf("行 %d 金额应当 > 0: %+v", i, rows[i])
		}
	}

	// 只导 alice
	alice, err := s.UsageExportRows(UsageExportFilter{UserName: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range alice {
		if r.UserName != "alice" {
			t.Fatalf("过滤失效: %+v", r)
		}
	}

	// 月合计
	roll, err := s.MonthlyRollup(time.Time{}, time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(roll) != 2 {
		t.Fatalf("月合计应当 2 个用户，实际 %d: %+v", len(roll), roll)
	}
	byUser := map[string]MonthlyRollupRow{}
	for _, r := range roll {
		byUser[r.UserName] = r
		if r.Month != day[:7] {
			t.Errorf("月份应当是 %s，实际 %s", day[:7], r.Month)
		}
	}
	if a := byUser["alice"]; a.Requests != 2 || a.Charge != 2.5+5.0 {
		t.Errorf("alice 月合计不对: %+v", a)
	}
	if b := byUser["bob"]; b.Requests != 2 {
		t.Errorf("bob 月合计不对: %+v", b)
	}
}
