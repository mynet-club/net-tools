package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUserLifecycle(t *testing.T) {
	s := openTestStore(t)
	token, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if !strings.HasPrefix(token, "sk-") || len(token) < 20 {
		t.Fatalf("token 形态不对: %q", token)
	}

	if err := s.CreateUser("alice", TokenHash(token)); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// token 明文绝不能落库
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE token_hash = ?`, token).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("库里出现了明文 token")
	}

	if err := s.CreateUser("alice", TokenHash("sk-another")); err == nil {
		t.Error("重复用户名应当报错")
	}

	u, err := s.GetUserByTokenHash(TokenHash(token))
	if err != nil || u == nil {
		t.Fatalf("按 token 查用户失败: u=%v err=%v", u, err)
	}
	if u.Name != "alice" || !u.Enabled {
		t.Errorf("用户信息不对: %+v", u)
	}

	if got, _ := s.GetUserByTokenHash(TokenHash("sk-nope")); got != nil {
		t.Error("未知 token 不应当匹配到用户")
	}

	if err := s.SetUserEnabled("alice", false); err != nil {
		t.Fatalf("SetUserEnabled: %v", err)
	}
	if u, _ = s.GetUser("alice"); u.Enabled {
		t.Error("禁用后 Enabled 仍为 true")
	}
	if err := s.SetUserEnabled("nobody", false); err == nil {
		t.Error("操作不存在的用户应当报错")
	}

	// 轮换 token：旧的失效、新的可用
	newToken, _ := NewToken()
	if err := s.SetUserToken("alice", TokenHash(newToken)); err != nil {
		t.Fatalf("SetUserToken: %v", err)
	}
	if got, _ := s.GetUserByTokenHash(TokenHash(token)); got != nil {
		t.Error("轮换后旧 token 仍然可用")
	}
	if got, _ := s.GetUserByTokenHash(TokenHash(newToken)); got == nil {
		t.Error("轮换后新 token 不可用")
	}

	if err := s.DeleteUser("alice"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if u, _ = s.GetUser("alice"); u != nil {
		t.Error("删除后仍能查到用户")
	}
	if err := s.DeleteUser("alice"); err == nil {
		t.Error("重复删除应当报错")
	}
}

func TestUserProviderCRUDAndCascade(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateUser("alice", TokenHash("sk-a")); err != nil {
		t.Fatal(err)
	}

	enc := []byte{0x01, 0x02, 0x03, 0x04}
	p := UserProvider{
		UserName:   "alice",
		Name:       "my-upstream",
		BaseURL:    "https://api.example.com/v1",
		APIKeyEnc:  enc,
		Enabled:    true,
		ModelsJSON: `["*"]`,
		// Weight / TimeoutMs 故意留零值，应当被规整
	}
	if err := s.UpsertUserProvider(p); err != nil {
		t.Fatalf("UpsertUserProvider: %v", err)
	}
	if err := s.UpsertUserProvider(UserProvider{
		UserName: "bob", Name: "x", BaseURL: "https://x/v1", Enabled: true,
	}); err == nil {
		t.Error("给不存在的用户配上游应当报错")
	}

	got, err := s.ListUserProviders("alice")
	if err != nil || len(got) != 1 {
		t.Fatalf("ListUserProviders: %v len=%d", err, len(got))
	}
	if got[0].Weight != 1 || got[0].TimeoutMs != 120000 {
		t.Errorf("零值未被规整: weight=%v timeout=%d", got[0].Weight, got[0].TimeoutMs)
	}
	if len(got[0].APIKeyEnc) != len(enc) || got[0].APIKeyEnc[0] != enc[0] {
		t.Errorf("密文没有原样存取: %v", got[0].APIKeyEnc)
	}

	// 同名覆盖
	if err := s.UpsertUserProvider(UserProvider{
		UserName: "alice", Name: "my-upstream", BaseURL: "https://api2.example.com/v1",
		APIKeyEnc: []byte{0x09}, Enabled: false, Weight: 3, ModelsJSON: `{"a":"b"}`,
	}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ListUserProviders("alice")
	if len(got) != 1 || got[0].BaseURL != "https://api2.example.com/v1" || got[0].Enabled || got[0].Weight != 3 {
		t.Errorf("覆盖后数据不对: %+v", got[0])
	}

	all, err := s.ListAllUserProviders()
	if err != nil || len(all["alice"]) != 1 {
		t.Errorf("ListAllUserProviders: %v %v", err, all)
	}

	if ok, _ := s.DeleteUserProvider("alice", "nope"); ok {
		t.Error("删除不存在的上游应返回 false")
	}
	if ok, err := s.DeleteUserProvider("alice", "my-upstream"); err != nil || !ok {
		t.Errorf("删除已存在的上游: ok=%v err=%v", ok, err)
	}

	// 级联：删用户要把上游一起删掉
	if err := s.UpsertUserProvider(UserProvider{
		UserName: "alice", Name: "again", BaseURL: "https://x/v1", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser("alice"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListUserProviders("alice"); len(got) != 0 {
		t.Errorf("删用户后上游没被清掉: %v", got)
	}
}

func TestInsertRequestPerUserUsage(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()
	pt, ct, tt := int64(100), int64(20), int64(120)

	if err := s.InsertRequest(RequestRecord{
		Ts: now, RequestID: "r1", UserName: "alice", ClientLabel: "alice",
		Model: "deepseek-flash", Provider: "p1", OK: true, StatusCode: 200, LatencyMs: 10,
		PromptTokens: &pt, CompletionTokens: &ct, TotalTokens: &tt,
	}); err != nil {
		t.Fatalf("InsertRequest: %v", err)
	}
	// 静态 key（无归属用户）不应进用户维度
	if err := s.InsertRequest(RequestRecord{
		Ts: now, RequestID: "r2", ClientLabel: "local", Model: "deepseek-flash",
		Provider: "p1", OK: true, StatusCode: 200, LatencyMs: 10,
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := s.UsageByUser(time.Time{}, "alice")
	if err != nil {
		t.Fatalf("UsageByUser: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("用户维度行数应为 1，实际 %d", len(rows))
	}
	if rows[0].TotalTokens != 120 || rows[0].Requests != 1 || rows[0].OK != 1 {
		t.Errorf("用户维度统计不对: %+v", rows[0])
	}

	tot, err := s.TotalByUser(time.Time{}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if tot.Requests != 1 || tot.TotalTokens != 120 || tot.PromptTokens != 100 || tot.OutputTokens != 20 {
		t.Errorf("累计值不对: %+v", tot)
	}
	if tot.LastDay != now.Format("2006-01-02") {
		t.Errorf("LastDay 不对: %q", tot.LastDay)
	}

	if other, _ := s.UsageByUser(time.Time{}, "bob"); len(other) != 0 {
		t.Errorf("别的用户不应查到数据: %v", other)
	}
	// 全局维度不受影响：两条都在
	st, err := s.Stats(time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if st.TotalRequests != 2 {
		t.Errorf("全局统计应仍为 2 条，实际 %d", st.TotalRequests)
	}
}

func TestProviderStatusScopeIsolation(t *testing.T) {
	s := openTestStore(t)
	if err := s.SaveProviderStatus([]ProviderStatus{
		{Scope: "", Name: "shared", Enabled: true, ConsecutiveFailures: 1, TotalRequests: 10},
		{Scope: "alice", Name: "shared", Enabled: true, ConsecutiveFailures: 9, TotalRequests: 90},
		{Scope: "bob", Name: "shared", Enabled: true, ConsecutiveFailures: 2, TotalRequests: 20},
	}); err != nil {
		t.Fatalf("SaveProviderStatus: %v", err)
	}

	got, err := s.LoadProviderStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st := got["shared"]; st.ConsecutiveFailures != 1 || st.Scope != "" {
		t.Errorf("全局作用域取错了: %+v", st)
	}
	if st := got["alice/shared"]; st.ConsecutiveFailures != 9 {
		t.Errorf("alice 作用域取错了: %+v", st)
	}
	if st := got["bob/shared"]; st.ConsecutiveFailures != 2 {
		t.Errorf("bob 作用域取错了: %+v", st)
	}
	if len(got) != 3 {
		t.Errorf("应有 3 条，实际 %d: %v", len(got), got)
	}

	// 同名不同作用域必须互不覆盖
	if err := s.SaveProviderStatus([]ProviderStatus{
		{Scope: "alice", Name: "shared", Enabled: true, ConsecutiveFailures: 0, TotalRequests: 91},
	}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.LoadProviderStatus()
	if got["shared"].TotalRequests != 10 {
		t.Error("写 alice 的作用域污染了全局记录")
	}
	if got["bob/shared"].TotalRequests != 20 {
		t.Error("写 alice 的作用域污染了 bob 的记录")
	}
	if got["alice/shared"].TotalRequests != 91 {
		t.Error("alice 的记录没更新")
	}
}

// TestMigrateLegacyProviderStats 覆盖老库升级：单用户时代的 provider_stats
// 主键只有 name，打开时应自动补上 scope 维度且不丢数据。
func TestMigrateLegacyProviderStats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := `
CREATE TABLE provider_stats (
  name                 TEXT    PRIMARY KEY,
  enabled              INTEGER NOT NULL DEFAULT 1,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  unhealthy_until      INTEGER NOT NULL DEFAULT 0,
  last_error           TEXT,
  last_success_at      INTEGER,
  last_failure_at      INTEGER,
  total_requests       INTEGER NOT NULL DEFAULT 0,
  total_failures       INTEGER NOT NULL DEFAULT 0,
  updated_at           INTEGER NOT NULL
);`
	if _, err := db.Exec(legacy); err != nil {
		t.Fatalf("造老库失败: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO provider_stats
	  (name, enabled, consecutive_failures, total_requests, total_failures, last_error, updated_at)
	  VALUES ('legacy-prov', 1, 2, 7, 3, 'boom', 1)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("打开老库（应自动迁移）失败: %v", err)
	}
	defer s.Close()

	got, err := s.LoadProviderStatus()
	if err != nil {
		t.Fatal(err)
	}
	st, ok := got["legacy-prov"]
	if !ok {
		t.Fatalf("迁移后老数据丢了: %v", got)
	}
	if st.Scope != "" {
		t.Errorf("老数据应归入全局作用域，实际 scope=%q", st.Scope)
	}
	if st.ConsecutiveFailures != 2 || st.TotalRequests != 7 || st.TotalFailures != 3 || st.LastError != "boom" {
		t.Errorf("迁移后字段值不对: %+v", st)
	}

	// 迁移后按作用域写入应当正常
	if err := s.SaveProviderStatus([]ProviderStatus{
		{Scope: "alice", Name: "my-up", Enabled: true, TotalRequests: 1},
	}); err != nil {
		t.Fatalf("迁移后写入失败: %v", err)
	}
	got2, _ := s.LoadProviderStatus()
	if _, ok := got2["alice/my-up"]; !ok {
		t.Errorf("迁移后作用域写入不可用: %v", got2)
	}

	// 再打开一次应当是幂等的（列已存在，不重复迁移）
	s.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("二次打开失败: %v", err)
	}
	defer s2.Close()
	got3, _ := s2.LoadProviderStatus()
	if len(got3) != len(got2) {
		t.Errorf("二次迁移改变了数据: %v → %v", got2, got3)
	}
}

func TestRevisionBumpsOnUserChanges(t *testing.T) {
	s := openTestStore(t)
	r0, err := s.Revision()
	if err != nil {
		t.Fatalf("Revision: %v", err)
	}

	if err := s.CreateUser("alice", TokenHash("sk-a")); err != nil {
		t.Fatal(err)
	}
	r1, _ := s.Revision()
	if r1 <= r0 {
		t.Errorf("建用户后修订号应增长: %d → %d", r0, r1)
	}

	if err := s.UpsertUserProvider(UserProvider{
		UserName: "alice", Name: "p", BaseURL: "https://x/v1", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	r2, _ := s.Revision()
	if r2 <= r1 {
		t.Errorf("配上游后修订号应增长: %d → %d", r1, r2)
	}

	if _, err := s.DeleteUserProvider("alice", "p"); err != nil {
		t.Fatal(err)
	}
	r3, _ := s.Revision()
	if r3 <= r2 {
		t.Errorf("删上游后修订号应增长: %d → %d", r2, r3)
	}

	if err := s.SetUserEnabled("alice", false); err != nil {
		t.Fatal(err)
	}
	if r4, _ := s.Revision(); r4 <= r3 {
		t.Errorf("禁用用户后修订号应增长: %d → %d", r3, r4)
	}
}

func TestScopeKeyHelpers(t *testing.T) {
	if k := scopeKey("", "p"); k != "p" {
		t.Errorf("全局键应等于名字，实际 %q", k)
	}
	if k := scopeKey("alice", "p"); k != "alice/p" {
		t.Errorf("作用域键应为 alice/p，实际 %q", k)
	}
	scope, name := SplitScopeKey("alice/p")
	if scope != "alice" || name != "p" {
		t.Errorf("SplitScopeKey 还原错误: %q %q", scope, name)
	}
	scope, name = SplitScopeKey("p")
	if scope != "" || name != "p" {
		t.Errorf("无作用域时不应拆分: %q %q", scope, name)
	}
}
