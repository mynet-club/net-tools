package store

import (
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 导出与月合计：同一套账，适合出账/对账。金额由调用方用 RowCharge 补。
//
// 读的是 usage_scope_daily，每行带自己的归属。「全部范围」是显式的 AllScopes* 读法，
// 不是「传个空集合」那种会被误会的默认 —— 出账出错是要对钱负责的。
func TestUsageExportAndMonthlyRollup(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	day := now.Format("2006-01-02")
	charge := 2.5

	for _, u := range []string{"alice", "bob"} {
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
	}

	rows, err := s.AllScopesUsageExportRows(time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	// 2 用户 × 同一天同模型 → 每个范围聚合成一行
	if len(rows) != 2 {
		t.Fatalf("应当 2 行（每范围一行），实际 %d: %+v", len(rows), rows)
	}
	if rows[0].Scope.Kind != policy.ScopeUser || rows[0].Scope.ID == "" {
		t.Errorf("导出行必须带自己的归属: %+v", rows[0])
	}
	// 金额由调用方算：冻结优先
	for i := range rows {
		if got := RowCharge(rows[i].UsageRow, nil, now); got <= 0 {
			t.Errorf("行 %d 金额应当 > 0: %+v", i, rows[i])
		}
	}

	// 只导 alice：范围过滤是逐行的归属判断，不是靠名字前缀猜
	alice := policy.MustScope(policy.ScopeUser, "alice")
	only, err := s.ScopeUsageExportRows(alice, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(only) != 1 {
		t.Fatalf("alice 应当 1 行: %+v", only)
	}
	for _, r := range only {
		if r.Scope != alice {
			t.Fatalf("过滤失效: %+v", r)
		}
	}

	// 月合计
	roll, err := s.AllScopesMonthlyRollup(time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(roll) != 2 {
		t.Fatalf("月合计应当 2 个范围，实际 %d: %+v", len(roll), roll)
	}
	byScope := map[policy.ScopeRef]ScopeMonthlyRollupRow{}
	for _, r := range roll {
		byScope[r.Scope] = r
		if r.Month != day[:7] {
			t.Errorf("月份应当是 %s，实际 %s", day[:7], r.Month)
		}
	}
	if a := byScope[alice]; a.Requests != 2 || a.Charge != 2.5+5.0 {
		t.Errorf("alice 月合计不对: %+v", a)
	}
	bob := policy.MustScope(policy.ScopeUser, "bob")
	if b := byScope[bob]; b.Requests != 2 {
		t.Errorf("bob 月合计不对: %+v", b)
	}

	// 单范围的月合计与全量口径必须一致，否则「按范围出账」会对不上总账
	single, err := s.ScopeMonthlyRollup(alice, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(single) != 1 || single[0].Charge != byScope[alice].Charge {
		t.Errorf("单范围月合计对不上: %+v vs %+v", single, byScope[alice])
	}
}

// 零范围必须被拒：导出全部走 AllScopes*，把零值当「全部」是一个会被误会的默认。
func TestScopeUsageReadsRejectZeroScope(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.ScopeUsageExportRows(policy.ScopeRef{}, time.Time{}, time.Time{}); err == nil {
		t.Error("ScopeUsageExportRows 应当拒绝零范围")
	}
	if _, err := s.ScopeMonthlyRollup(policy.ScopeRef{}, time.Time{}, time.Time{}); err == nil {
		t.Error("ScopeMonthlyRollup 应当拒绝零范围")
	}
	if _, err := s.ScopeSystemUsageRows(policy.ScopeRef{}, time.Now()); err == nil {
		t.Error("ScopeSystemUsageRows 应当拒绝零范围")
	}
	if _, err := s.ScopeUsageTotals(nil, time.Time{}, time.Time{}); err == nil {
		t.Error("ScopeUsageTotals 空范围集合应当报错，而不是返回全部")
	}
}
