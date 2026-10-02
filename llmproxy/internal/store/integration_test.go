package store

// 真库集成测试：同一套断言跑在 SQLite / MySQL / PostgreSQL 上。
//
// 默认**只跑 SQLite**（零依赖，CI 与本地都绿）。要打真库：
//
//	LLMPROXY_TEST_MYSQL_DSN='user:pass@tcp(127.0.0.1:3306)/llmproxy_test?parseTime=true'
//	LLMPROXY_TEST_PG_DSN='postgres://user:pass@127.0.0.1:5432/llmproxy_test?sslmode=disable'
//	go test ./internal/store -run Integration -v
//
// 或用脚本：./scripts/test-matrix.sh（自动起一次性容器）。
//
// 跳过条件写死在 openIntegration：环境变量为空就 t.Skip，绝不静默假绿。

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// integrationCase 是一组「换任何驱动都必须成立」的操作。
// 刻意不测 SQL 方言细节（那是 dialect_test 的事），只测业务语义。
func runIntegrationSuite(t *testing.T, driver, pathOrDSN string) {
	s, err := OpenDialect(driver, pathOrDSN)
	if err != nil {
		t.Fatalf("OpenDialect(%s): %v", driver, err)
	}
	defer s.Close()

	// 真库是共享的：用户名带上时间戳，避免上次跑挂了留下的残留撞 UNIQUE
	uid := fmt.Sprintf("it-%d", time.Now().UnixNano()%1e9)

	// 表建出来了
	has, err := s.dialect.HasTable(s.db, "requests")
	if err != nil || !has {
		t.Fatalf("requests 表应当存在: has=%v err=%v", has, err)
	}

	// 用户
	if err := s.CreateUser(uid, TokenHash("sk-"+uid)); err != nil {
		t.Fatal(err)
	}
	u, err := s.GetUser(uid)
	if err != nil || u == nil || u.Name != uid {
		t.Fatalf("GetUser: %+v %v", u, err)
	}

	// 上游 + 模型映射
	if err := s.UpsertUserProvider(UserProvider{
		UserName: uid, Name: "up", BaseURL: "https://api.example.com/v1", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertUserModel(UserModel{
		UserName: uid, Model: "m", Upstream: "m-up", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	// 价目（整点）：provider/model 也带后缀，避免真库上撞「只追加」
	hour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	prov := "p-" + uid
	if err := s.InsertProviderPrice(&ProviderPrice{
		Provider: prov, UpstreamModel: "m-up", ValidFrom: hour, InMiss: 2, Out: 8,
	}); err != nil {
		t.Fatal(err)
	}
	model := "m-" + uid
	if err := s.InsertScopePrice(&ScopePrice{
		Scope: policy.SystemScope, Model: model, ValidFrom: hour, InMiss: 2, Out: 8,
	}); err != nil {
		t.Fatal(err)
	}

	// 请求账本 + 冻结
	// uidScope 提前定义：账本按 (user, uid) 范围落，读侧也按同一个范围读。
	uidScope := policy.MustScope(policy.ScopeUser, uid)
	cost, charge := 1.5, 3.5
	if err := s.InsertRequest(RequestRecord{
		Ts: time.Now(), RequestID: "it-" + uid, UserName: uid, Model: model,
		Provider: prov, UpstreamModel: "m-up", SystemPaid: true, OK: true,
		PromptTokens: i64(100), CompletionTokens: i64(50), TotalTokens: i64(150),
		CacheMissTokens: 100, Attempts: 1,
		CostUpstream: &cost, Charge: &charge, Currency: "CNY",
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := s.ScopeSystemUsageRows(uidScope, time.Now().AddDate(0, 0, -1))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Charge != 3.5 {
		t.Fatalf("冻结金额应当回来: %+v", rows)
	}

	// RowCharge 全冻结直接取冻结值 —— 与驱动无关
	if got := RowCharge(rows[0], nil, time.Now()); got != 3.5 {
		t.Errorf("RowCharge = %v, want 3.5", got)
	}

	// 价目按整点查询
	p, err := s.ProviderPriceAt(prov, "m-up", hour.Add(time.Minute))
	if err != nil || p == nil || p.Out != 8 {
		t.Fatalf("ProviderPriceAt: %+v %v", p, err)
	}

	// 熔断状态
	if err := s.SaveProviderBucketStates([]ProviderBucketState{
		{Scope: uidScope, Name: "up", Enabled: true, ConsecutiveFailures: 2},
	}); err != nil {
		t.Fatal(err)
	}
	sts, err := s.LoadProviderBucketStates()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, st := range sts {
		if st.Scope == uidScope && st.Name == "up" && st.ConsecutiveFailures == 2 {
			found = true
		}
	}
	if !found {
		t.Errorf("熔断状态应当恢复: %+v", sts)
	}

	// 删用户：配置级联清掉、账本保留
	if err := s.DeleteUser(uid); err != nil {
		t.Fatal(err)
	}
	if ms, _ := s.ListUserModels(uid); len(ms) != 0 {
		t.Errorf("删用户后模型映射应清掉: %+v", ms)
	}
	if rows, _ := s.ScopeSystemUsageRows(uidScope, time.Now().AddDate(0, 0, -1)); len(rows) == 0 {
		t.Error("删用户后用量账本应当保留")
	}
}

// TestIntegrationSQLite 是基线：始终跑，证明套件本身是绿的。
func TestIntegrationSQLite(t *testing.T) {
	runIntegrationSuite(t, "sqlite", t.TempDir()+"/it.db")
}

// TestIntegrationMySQL 跑真库 MySQL；没配 DSN 就跳过。
func TestIntegrationMySQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("LLMPROXY_TEST_MYSQL_DSN"))
	if dsn == "" {
		t.Skip("设置 LLMPROXY_TEST_MYSQL_DSN 后才跑 MySQL 集成测试")
	}
	runIntegrationSuite(t, "mysql", dsn)
}

// TestIntegrationPostgres 跑真库 PostgreSQL；没配 DSN 就跳过。
func TestIntegrationPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("LLMPROXY_TEST_PG_DSN"))
	if dsn == "" {
		t.Skip("设置 LLMPROXY_TEST_PG_DSN 后才跑 PostgreSQL 集成测试")
	}
	runIntegrationSuite(t, "postgres", dsn)
}
