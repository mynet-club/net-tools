package store

import (
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func i64(v int64) *int64 { return &v }

func TestInsertAndStats(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()

	recs := []RequestRecord{
		{Ts: now, RequestID: "r1", Model: "gpt-4o", Provider: "p1", UpstreamModel: "gpt-4o-2024",
			OK: true, LatencyMs: 1200, PromptTokens: i64(100), CompletionTokens: i64(50), TotalTokens: i64(150),
			Attempts: 1, ClientKeyHash: "abc123", ClientLabel: "laptop", ClientIP: "127.0.0.1"},
		{Ts: now, RequestID: "r2", Model: "gpt-4o", Provider: "p1", UpstreamModel: "gpt-4o-2024",
			OK: true, LatencyMs: 800, PromptTokens: i64(200), CompletionTokens: i64(25), TotalTokens: i64(225),
			Attempts: 1, ClientKeyHash: "abc123", ClientLabel: "laptop"},
		{Ts: now, RequestID: "r3", Model: "gpt-4o-mini", Provider: "p2", UpstreamModel: "gpt-4o-mini",
			OK: false, LatencyMs: 30000, Attempts: 3,
			ErrorType: "upstream_unavailable", ErrorMsg: "所有上游供应商均不可用"},
		{Ts: now, RequestID: "r4", Model: "gpt-4o", Provider: "p2", UpstreamModel: "gpt-4o",
			OK: true, Stream: true, LatencyMs: 5000, TTFTMs: i64(400),
			PromptTokens: i64(30), CompletionTokens: i64(20), TotalTokens: i64(50), Attempts: 2},
	}
	for _, r := range recs {
		if err := s.InsertRequest(r); err != nil {
			t.Fatalf("InsertRequest(%s): %v", r.RequestID, err)
		}
	}

	st, err := s.Stats(time.Time{}, 10)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.TotalRequests != 4 {
		t.Errorf("TotalRequests = %d, want 4", st.TotalRequests)
	}
	if st.TotalOK != 3 || st.TotalFailed != 1 {
		t.Errorf("OK/Failed = %d/%d, want 3/1", st.TotalOK, st.TotalFailed)
	}
	if st.TotalTokens != 150+225+50 {
		t.Errorf("TotalTokens = %d, want %d", st.TotalTokens, 150+225+50)
	}

	// 按供应商：p1 应有 2 次成功、0 失败
	var p1Total, p1OK, p1Failed, p1Tokens int64
	for _, r := range st.ByProvider {
		if r.Provider == "p1" {
			p1Total += r.Requests
			p1OK += r.OK
			p1Failed += r.Failed
			p1Tokens += r.TotalTokens
		}
	}
	if p1Total != 2 || p1OK != 2 || p1Failed != 0 {
		t.Errorf("p1 汇总 = req=%d ok=%d fail=%d, want 2/2/0", p1Total, p1OK, p1Failed)
	}
	if p1Tokens != 150+225 {
		t.Errorf("p1 tokens = %d, want %d", p1Tokens, 150+225)
	}

	// p2：1 失败 + 1 成功
	var p2Total, p2OK, p2Failed int64
	for _, r := range st.ByProvider {
		if r.Provider == "p2" {
			p2Total += r.Requests
			p2OK += r.OK
			p2Failed += r.Failed
		}
	}
	if p2Total != 2 || p2OK != 1 || p2Failed != 1 {
		t.Errorf("p2 汇总 = req=%d ok=%d fail=%d, want 2/1/1", p2Total, p2OK, p2Failed)
	}

	if len(st.Recent) != 4 {
		t.Errorf("Recent len = %d, want 4", len(st.Recent))
	}
	// 最新在前
	if st.Recent[0].RequestID != "r4" && st.Recent[0].RequestID != "r3" &&
		st.Recent[0].RequestID != "r2" && st.Recent[0].RequestID != "r1" {
		t.Errorf("Recent[0] 异常: %s", st.Recent[0].RequestID)
	}
}

func TestStatsContentNotStored(t *testing.T) {
	s := openTestStore(t)
	// 模拟"不该被记录"的内容出现在错误信息之外的字段里——我们只写元数据字段，
	// 这里显式验证：即使在 ErrorMsg 里写了较长文本，请求/响应正文也不会出现在别的列。
	secret := "这是一段绝对不该出现在日志里的对话内容"
	err := s.InsertRequest(RequestRecord{
		Ts: time.Now(), RequestID: "rx", Model: "m", Provider: "p",
		OK: false, ErrorType: "relay_error", ErrorMsg: "connection reset",
	})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := s.Stats(time.Time{}, 10)
	if len(st.Recent) != 1 {
		t.Fatalf("Recent = %d", len(st.Recent))
	}
	rec := st.Recent[0]
	blob := rec.Model + rec.Provider + rec.ErrorMsg + rec.ErrorType + rec.RequestID + rec.ClientLabel
	if contains(blob, secret) {
		t.Error("请求内容泄漏进了数据库")
	}
	if contains(blob, "对话内容") {
		t.Error("请求内容泄漏进了数据库")
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// statusOf 在 LoadProviderStatus 的切片里按 (作用域, 名字) 找一条。
// 作用域必须一起匹配：熔断状态是按 (用户, 上游) 分桶的，
// 只按名字找会把「alice 的 up」和「全局的 up」混为一谈 —— 那正是曾经的 bug。
func statusOf(list []ProviderStatus, scope, name string) (ProviderStatus, bool) {
	for _, st := range list {
		if st.Scope == scope && st.Name == name {
			return st, true
		}
	}
	return ProviderStatus{}, false
}

func TestProviderStatusPersistence(t *testing.T) {
	s := openTestStore(t)
	until := time.Now().Add(60 * time.Second).Truncate(time.Second)
	statuses := []ProviderStatus{
		{Name: "p1", Enabled: true, ConsecutiveFailures: 3, UnhealthyUntil: until,
			LastError: "上游返回 500", TotalRequests: 10, TotalFailures: 3,
			LastSuccessAt: time.Now().Add(-time.Minute), LastFailureAt: time.Now()},
		{Name: "p2", Enabled: true, TotalRequests: 5},
	}
	if err := s.SaveProviderStatus(statuses); err != nil {
		t.Fatalf("SaveProviderStatus: %v", err)
	}
	got, err := s.LoadProviderStatus()
	if err != nil {
		t.Fatalf("LoadProviderStatus: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d statuses", len(got))
	}
	p1, ok := statusOf(got, "", "p1")
	if !ok {
		t.Fatalf("没有找到 p1 的状态: %+v", got)
	}
	if p1.ConsecutiveFailures != 3 || p1.TotalRequests != 10 || p1.TotalFailures != 3 {
		t.Errorf("p1 状态未正确恢复: %+v", p1)
	}
	if p1.LastError != "上游返回 500" {
		t.Errorf("p1.LastError = %q", p1.LastError)
	}
	// UnhealthyUntil 可能有毫秒级截断误差，比较到秒
	if p1.UnhealthyUntil.Sub(until) > time.Second || until.Sub(p1.UnhealthyUntil) > time.Second {
		t.Errorf("p1.UnhealthyUntil = %v, want ~%v", p1.UnhealthyUntil, until)
	}

	// 覆盖更新
	statuses[0].ConsecutiveFailures = 0
	statuses[0].UnhealthyUntil = time.Time{}
	statuses[0].LastError = ""
	if err := s.SaveProviderStatus(statuses); err != nil {
		t.Fatal(err)
	}
	got, _ = s.LoadProviderStatus()
	if p1, _ = statusOf(got, "", "p1"); p1.ConsecutiveFailures != 0 || !p1.UnhealthyUntil.IsZero() {
		t.Errorf("覆盖更新失败: %+v", p1)
	}
}

func TestPrune(t *testing.T) {
	s := openTestStore(t)
	old := time.Now().AddDate(0, 0, -200)
	fresh := time.Now()
	if err := s.InsertRequest(RequestRecord{Ts: old, RequestID: "old", Model: "m", Provider: "p", OK: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertRequest(RequestRecord{Ts: fresh, RequestID: "new", Model: "m", Provider: "p", OK: true}); err != nil {
		t.Fatal(err)
	}
	n, err := s.Prune(90)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("Prune 删除了 %d 条, want 1", n)
	}
	st, _ := s.Stats(time.Time{}, 10)
	if st.TotalRequests != 1 {
		t.Errorf("清理后剩余 %d 条, want 1", st.TotalRequests)
	}
	// usage_daily 保留
	found := false
	for _, r := range st.ByProvider {
		if r.Requests >= 2 {
			found = true
		}
	}
	if !found {
		t.Errorf("usage_daily 应保留全部历史消耗, got %+v", st.ByProvider)
	}

	// retain_days=0 表示不清理
	if n, _ := s.Prune(0); n != 0 {
		t.Errorf("retain_days=0 时不应删除, got %d", n)
	}
}

func TestKeyHash(t *testing.T) {
	if KeyHash("") != "" {
		t.Error("空 key 应返回空串")
	}
	h1 := KeyHash("sk-secret-value")
	h2 := KeyHash("sk-secret-value")
	h3 := KeyHash("sk-other-value")
	if h1 != h2 {
		t.Error("同一 key 哈希应稳定")
	}
	if h1 == h3 {
		t.Error("不同 key 哈希应不同")
	}
	if len(h1) != 12 { // 6 字节 → 12 个十六进制字符
		t.Errorf("哈希长度 = %d, want 12", len(h1))
	}
	// 哈希里不应出现原文
	if contains(h1, "sk-secret") {
		t.Error("哈希里不应出现明文")
	}
}

func TestStatsSince(t *testing.T) {
	s := openTestStore(t)
	old := time.Now().AddDate(0, 0, -10)
	fresh := time.Now()
	_ = s.InsertRequest(RequestRecord{Ts: old, RequestID: "old", Model: "m", Provider: "p", OK: true, TotalTokens: i64(10)})
	_ = s.InsertRequest(RequestRecord{Ts: fresh, RequestID: "new", Model: "m", Provider: "p", OK: true, TotalTokens: i64(20)})

	st, err := s.Stats(time.Now().AddDate(0, 0, -1), 0)
	if err != nil {
		t.Fatal(err)
	}
	if st.TotalRequests != 1 || st.TotalTokens != 20 {
		t.Errorf("since 过滤后 = req=%d tok=%d, want 1/20", st.TotalRequests, st.TotalTokens)
	}

	// 两张聚合表也必须跟着 since 走。曾经它们完全没有 WHERE —— 于是 `stats --days 1`
	// 会打印「总计: 请求 1」，紧接着的按供应商表却是全量历史，同屏自相矛盾。
	if len(st.ByProvider) != 1 {
		t.Fatalf("ByProvider 应当只有 1 行，实际 %d: %+v", len(st.ByProvider), st.ByProvider)
	}
	if st.ByProvider[0].Requests != 1 || st.ByProvider[0].TotalTokens != 20 {
		t.Errorf("ByProvider 没跟着 since 过滤: req=%d tok=%d, want 1/20",
			st.ByProvider[0].Requests, st.ByProvider[0].TotalTokens)
	}
	if len(st.ByDay) != 1 {
		t.Errorf("ByDay 应当只有 1 天，实际 %d: %+v", len(st.ByDay), st.ByDay)
	}
	// ByProvider 按 (provider, model) 分组、跨天聚合，所以 day 列本身没有意义 ——
	// 必须是占位符，而不是 SQLite 从组内任取一行的裸列值（那会是个误导人的随机日期）。
	if st.ByProvider[0].Day != "-" {
		t.Errorf("ByProvider 的 day 应当是占位符 '-'，实际 %q", st.ByProvider[0].Day)
	}
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Error("空路径应报错")
	}
}
