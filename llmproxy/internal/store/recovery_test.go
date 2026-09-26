package store

import (
	"path/filepath"
	"testing"
	"time"
)

// 重启恢复：关掉再打开，用户、价目、冻结金额、熔断状态都必须原样回来，
// 且不串用户。这是「落库、关闭、重启、恢复」验收标准的直接落地。
func TestReopenRestoresUsersPricesFrozenAndStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recover.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.CreateUser("alice", TokenHash("sk-a")); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser("bob", TokenHash("sk-b")); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertUserProvider(UserProvider{
		UserName: "alice", Name: "up", BaseURL: "https://api.example.com/v1", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertUserModel(UserModel{
		UserName: "alice", Model: "gpt", Upstream: "gpt-4o", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	hour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	if err := s.InsertUserPrice(&UserPrice{
		Scope: ScopeDefault, Model: "gpt", ValidFrom: hour, InMiss: 2, Out: 8,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertProviderPrice(&ProviderPrice{
		Provider: "sys-a", UpstreamModel: "gpt-4o", ValidFrom: hour, InMiss: 1, Out: 4,
	}); err != nil {
		t.Fatal(err)
	}

	cost := 1.5
	charge := 3.5
	if err := s.InsertRequest(RequestRecord{
		Ts: time.Now(), RequestID: "r-alice", UserName: "alice", Model: "gpt",
		Provider: "sys-a", UpstreamModel: "gpt-4o", SystemPaid: true, OK: true,
		PromptTokens: i64(100), CompletionTokens: i64(50), TotalTokens: i64(150),
		CacheMissTokens: 100, Attempts: 1,
		PriceUpstreamID: 1, CostUpstream: &cost, PriceDownstreamID: 1, Charge: &charge,
		Currency: "CNY",
	}); err != nil {
		t.Fatal(err)
	}
	// bob 的请求，证明重启后不串用户
	if err := s.InsertRequest(RequestRecord{
		Ts: time.Now(), RequestID: "r-bob", UserName: "bob", Model: "gpt",
		Provider: "sys-a", UpstreamModel: "gpt-4o", SystemPaid: true, OK: true,
		PromptTokens: i64(10), CompletionTokens: i64(5), TotalTokens: i64(15),
		CacheMissTokens: 10, Attempts: 1,
		PriceUpstreamID: 1, CostUpstream: &cost, PriceDownstreamID: 1, Charge: &charge,
		Currency: "CNY",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveProviderStatus([]ProviderStatus{
		{Scope: "alice", Name: "up", Enabled: true, ConsecutiveFailures: 3, TotalRequests: 9, UnhealthyUntil: time.Now().Add(time.Minute)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// —— 模拟进程重启 ——
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("重新 Open: %v", err)
	}
	defer s2.Close()

	users, err := s2.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, u := range users {
		names[u.Name] = true
	}
	if !names["alice"] || !names["bob"] {
		t.Errorf("重启后用户丢了: %v", names)
	}

	models, err := s2.ListUserModels("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 1 || models[0].Upstream != "gpt-4o" {
		t.Errorf("alice 的模型授权应当回来: %+v", models)
	}

	// 分发价冻结（用户行）必须原样
	aliceRows, err := s2.SystemUsageRowsSince("alice", time.Now().AddDate(0, 0, -1))
	if err != nil {
		t.Fatal(err)
	}
	if len(aliceRows) != 1 {
		t.Fatalf("alice 应当 1 行用量，实际 %d", len(aliceRows))
	}
	if aliceRows[0].Charge != 3.5 || aliceRows[0].FrozenCharges != 1 {
		t.Errorf("分发冻结应当原样恢复 charge=3.5 frozen=1，实际 %+v", aliceRows[0])
	}
	bobRows, _ := s2.SystemUsageRowsSince("bob", time.Now().AddDate(0, 0, -1))
	if len(bobRows) != 1 || bobRows[0].Charge != 3.5 {
		t.Errorf("bob 的账应当独立且完整: %+v", bobRows)
	}

	// 上游成本冻结在 usage_daily（全局账），两人各一笔：1.5×2=3
	st, err := s2.Stats(time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.ByProvider) != 1 {
		t.Fatalf("应当 1 行供应商汇总，实际 %d", len(st.ByProvider))
	}
	up := st.ByProvider[0]
	if up.CostUpstream != 3.0 || up.FrozenRequests != 2 {
		t.Errorf("上游冻结应当原样恢复 cost=3 frozen=2（两人各 1.5/1），实际 %+v", up)
	}

	// 熔断状态（含冷却截止时间）恢复
	pstats, err := s2.LoadProviderStatus()
	if err != nil {
		t.Fatal(err)
	}
	pst, ok := statusOf(pstats, "alice", "up")
	if !ok {
		t.Fatalf("alice/up 的熔断状态应当恢复，实际 %+v", pstats)
	}
	if pst.ConsecutiveFailures != 3 || pst.TotalRequests != 9 || pst.UnhealthyUntil.IsZero() {
		t.Errorf("熔断状态不完整: %+v", pst)
	}
	if _, ok := statusOf(pstats, "bob", "up"); ok {
		t.Error("bob 不该看到 alice 的熔断状态")
	}

	// 价目历史也回来，且仍按整点查询
	p, err := s2.UserPriceAt("bob", "gpt", hour.Add(time.Minute))
	if err != nil || p == nil {
		t.Fatalf("UserPriceAt: %v %v", p, err)
	}
	if p.InMiss != 2 || p.Out != 8 {
		t.Errorf("分发价恢复不对: %+v", p)
	}
}

// 改价不得重算历史：已冻结的请求永远按它当时冻结的金额计。
// 这是「历史价格变化不会改变已冻结请求金额」的直接验收。
func TestPriceChangeDoesNotRewriteFrozenHistory(t *testing.T) {
	s := openTestStore(t)
	hour := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	next := hour.Add(time.Hour)

	oldUp := &ProviderPrice{Provider: "sys-a", UpstreamModel: "m", ValidFrom: hour, InMiss: 1, Out: 4}
	if err := s.InsertProviderPrice(oldUp); err != nil {
		t.Fatal(err)
	}
	cost := 4.0 // 1e6 out × 4 / 1e6
	if err := s.InsertRequest(RequestRecord{
		Ts: time.Now().Add(-90 * time.Minute), RequestID: "r-old", UserName: "u",
		Model: "m", Provider: "sys-a", UpstreamModel: "m", SystemPaid: true, OK: true,
		PromptTokens: i64(0), CompletionTokens: i64(1_000_000), TotalTokens: i64(1_000_000),
		CostUpstream: &cost, Currency: "CNY", Attempts: 1,
	}); err != nil {
		t.Fatal(err)
	}

	// 改价：下一小时起 out 从 4 涨到 400
	if err := s.InsertProviderPrice(&ProviderPrice{
		Provider: "sys-a", UpstreamModel: "m", ValidFrom: next, InMiss: 1, Out: 400,
	}); err != nil {
		t.Fatal(err)
	}

	// 历史请求的冻结值不能动
	st, err := s.Stats(time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.ByProvider) != 1 {
		t.Fatalf("应当 1 行供应商汇总，实际 %d", len(st.ByProvider))
	}
	if got := st.ByProvider[0].CostUpstream; got != 4.0 {
		t.Errorf("改价后历史成本仍应是 4.0，实际 %v —— 重算会把改价当成追缴", got)
	}

	// 新请求按新价冻结，两笔并存、互不覆盖
	newCost := 400.0 // 1e6 out × 400 / 1e6
	if err := s.InsertRequest(RequestRecord{
		Ts: time.Now(), RequestID: "r-new", UserName: "u",
		Model: "m", Provider: "sys-a", UpstreamModel: "m", SystemPaid: true, OK: true,
		CompletionTokens: i64(1_000_000), TotalTokens: i64(1_000_000),
		CostUpstream: &newCost, Currency: "CNY", Attempts: 1,
	}); err != nil {
		t.Fatal(err)
	}
	st, err = s.Stats(time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.ByProvider[0].CostUpstream; got != 404.0 {
		t.Errorf("历史 4 + 新价 400 = 404，实际 %v", got)
	}

	// 行级冻结也不受后续改价影响：用户行的 Charge 是冻结写死的
	charge := 404.0
	if err := s.InsertRequest(RequestRecord{
		Ts: time.Now(), RequestID: "r-charge", UserName: "u2",
		Model: "m", Provider: "sys-a", UpstreamModel: "m", SystemPaid: true, OK: true,
		CompletionTokens: i64(1_000_000), TotalTokens: i64(1_000_000),
		Charge: &charge, Currency: "CNY", Attempts: 1,
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.SystemUsageRowsSince("u2", time.Now().AddDate(0, 0, -1))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("应当 1 行，实际 %d", len(rows))
	}
	// 全冻结 → RowCharge 直接取冻结值，绝不按新价目重算
	if got := RowCharge(rows[0], nil, time.Now()); got != 404.0 {
		t.Errorf("全冻结行应当直接取冻结合计 404，实际 %v", got)
	}
}
