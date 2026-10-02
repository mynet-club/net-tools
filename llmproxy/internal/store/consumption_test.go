package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 消费模式：设置项、模型映射、系统付费用量。
func TestConsumptionSettingsAndModels(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateUser("carol", TokenHash("sk-carol")); err != nil {
		t.Fatal(err)
	}

	// 默认必须是 byo：新用户不该悄悄获得消费系统上游的能力
	u, err := s.GetUser("carol")
	if err != nil || u == nil {
		t.Fatalf("GetUser: %v", err)
	}
	if u.Mode != ModeBYO {
		t.Fatalf("新用户默认模式应为 byo，实际 %q", u.Mode)
	}
	// 配额在 scope_quota（§2.7 规则 2）：CreateUser 同一事务里补的行，初值全 0 = 不限。
	carol := policy.MustScope(policy.ScopeUser, "carol")
	q := mustQuota(t, s, carol)
	if q.QuotaMonthTokens != 0 || q.QuotaMonthCost != 0 || q.RPM != 0 || q.MaxConcurrent != 0 {
		t.Fatalf("新用户的配额与限流应为「不限」: %+v", q)
	}

	if err := s.SetUserMode("carol", ModeConsumption); err != nil {
		t.Fatal(err)
	}
	if err := s.SetScopeQuota(ScopeQuota{
		Scope: carol, QuotaMonthTokens: 5_000_000, QuotaMonthCost: 12.5, RPM: 30, MaxConcurrent: 4, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	u, _ = s.GetUser("carol")
	if u.Mode != ModeConsumption {
		t.Fatalf("模式没落库: %+v", u)
	}
	if got := mustQuota(t, s, carol); got.QuotaMonthTokens != 5_000_000 || got.QuotaMonthCost != 12.5 ||
		got.RPM != 30 || got.MaxConcurrent != 4 {
		t.Fatalf("配额没落库: %+v", got)
	}
	if !u.IsConsumption() {
		t.Fatal("IsConsumption 应为 true")
	}

	// 模型映射：既是白名单也是映射
	if err := s.UpsertUserModel(UserModel{
		UserName: "carol", Model: "fast", Upstream: "deepseek-flash", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertUserModel(UserModel{
		UserName: "carol", Model: "pro", Upstream: "deepseek-v4-pro", Provider: "deepseek", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	// 同名再写是覆盖，不是新增
	if err := s.UpsertUserModel(UserModel{
		UserName: "carol", Model: "fast", Upstream: "deepseek-v4-pro", Enabled: false,
	}); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListUserModels("carol")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("期望 2 条映射，实际 %d 条: %+v", len(list), list)
	}
	byName := map[string]UserModel{}
	for _, m := range list {
		byName[m.Model] = m
	}
	if m := byName["fast"]; m.Upstream != "deepseek-v4-pro" || m.Enabled {
		t.Fatalf("覆盖没生效: %+v", m)
	}
	if m := byName["pro"]; m.Provider != "deepseek" {
		t.Fatalf("provider 没落库: %+v", m)
	}

	// 别人的映射不能串台
	all, err := s.ListAllUserModels()
	if err != nil {
		t.Fatal(err)
	}
	if len(all["carol"]) != 2 || len(all["dave"]) != 0 {
		t.Fatalf("按用户分组不对: %+v", all)
	}

	if ok, err := s.DeleteUserModel("carol", "pro"); err != nil || !ok {
		t.Fatalf("删除失败: ok=%v err=%v", ok, err)
	}
	if ok, _ := s.DeleteUserModel("carol", "pro"); ok {
		t.Fatal("重复删除不该返回 true")
	}
	if list, _ := s.ListUserModels("carol"); len(list) != 1 {
		t.Fatalf("删除后应剩 1 条: %+v", list)
	}
}

// 只有 system_paid 的用量才进配额；用户自己掏钱的用量不能算进他的消费额度。
func TestSystemUsageOnlyCountsSystemPaid(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateUser("carol", TokenHash("sk-carol")); err != nil {
		t.Fatal(err)
	}
	day := time.Now()
	pt, ct := int64(1000), int64(200)

	// 系统付费：记账 1000/200，其中 800 命中缓存
	if err := s.InsertRequest(RequestRecord{
		Ts: day, RequestID: "r1", Model: "fast", Provider: "deepseek", Stream: true,
		StatusCode: 200, OK: true, UserName: "carol", SystemPaid: true,
		PromptTokens: &pt, CompletionTokens: &ct, TotalTokens: ptrInt64(1200),
		CacheHitTokens: 800, CacheMissTokens: 200,
	}); err != nil {
		t.Fatal(err)
	}
	// 自己的上游：不进配额
	if err := s.InsertRequest(RequestRecord{
		Ts: day, RequestID: "r2", Model: "mine", Provider: "carol-own", Stream: true,
		StatusCode: 200, OK: true, UserName: "carol",
		PromptTokens: &pt, CompletionTokens: &ct, TotalTokens: ptrInt64(1200),
	}); err != nil {
		t.Fatal(err)
	}

	su, err := s.SystemUsageSince("carol", MonthStart(day))
	if err != nil {
		t.Fatal(err)
	}
	if su.Requests != 1 || su.TotalTokens != 1200 {
		t.Fatalf("只应统计系统付费那一条: %+v", su)
	}
	if su.CacheHitTokens != 800 || su.CacheMissTokens != 200 {
		t.Fatalf("缓存拆分没落库: %+v", su)
	}

	// 全量口径仍然是两条
	all, err := s.TotalByUser(MonthStart(day), "carol")
	if err != nil {
		t.Fatal(err)
	}
	if all.Requests != 2 {
		t.Fatalf("全量统计应为 2 条: %+v", all)
	}
}

// 老库（usage_user_daily 没有 system_paid/cache 列）升级上来不能丢数据。
func TestMigrateConsumptionFromLegacy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// 复刻「消费模式之前」的表：users 无 mode 列，usage_user_daily 主键无 system_paid
	legacy := `
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
  token_hash TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE usage_user_daily (
  day TEXT NOT NULL, user_name TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL,
  requests INTEGER NOT NULL DEFAULT 0, ok INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0,
  prompt_tokens INTEGER NOT NULL DEFAULT 0, completion_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens INTEGER NOT NULL DEFAULT 0, latency_sum_ms INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, user_name, provider, model));
INSERT INTO users (name, token_hash, enabled, created_at, updated_at)
  VALUES ('old', 'deadbeef', 1, 1, 1);
INSERT INTO usage_user_daily VALUES ('2026-09-01','old','deepseek','deepseek-flash',3,3,0,900,300,1200,1500);
`
	if _, err := raw.Exec(legacy); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	// 用新代码打开：应当自动补列 + 重建表
	s, err := Open(path)
	if err != nil {
		t.Fatalf("打开老库失败: %v", err)
	}
	defer s.Close()

	u, err := s.GetUser("old")
	if err != nil || u == nil {
		t.Fatalf("老用户丢失: %v", err)
	}
	if u.Mode != ModeBYO {
		t.Fatalf("迁移后老用户应为 byo，实际 %q", u.Mode)
	}
	// 配额列**不再由这里补回来**（migrateConsumption 只补 mode）：3.0 的配额真源是 scope_quota，
	// 在 users 上留四列等于给旧形状续命。
	for _, col := range usersQuotaLegacyCols {
		if has, err := columnExists(s.db, "users", col); err != nil || has {
			t.Errorf("users.%s 不该出现在升级后的库里: has=%v err=%v", col, has, err)
		}
	}
	// 这种库从来没有过配额列，回填没有旧值可搬，但配额行必须存在：
	// buildRegistry 缺行时拒绝重建快照（不是按「不限」放行），漏补会让老账号上线就 401。
	if q := mustQuota(t, s, policy.MustScope(policy.ScopeUser, "old")); q.QuotaMonthTokens != 0 || !q.Enabled {
		t.Fatalf("无旧列的库也要补出「不限」的配额行: %+v", q)
	}
	// 老数据保留：条数、token 数不变
	su, err := s.SystemUsageSince("old", time.Date(2026, 9, 1, 0, 0, 0, 0, time.Local))
	if err != nil {
		t.Fatal(err)
	}
	if su.Requests != 0 {
		t.Fatalf("老数据不该被算成系统付费: %+v", su)
	}
	all, err := s.TotalByUser(time.Time{}, "old")
	if err != nil {
		t.Fatal(err)
	}
	if all.Requests != 3 || all.TotalTokens != 1200 || all.PromptTokens != 900 {
		t.Fatalf("迁移后老数据对不上: %+v", all)
	}

	// 幂等：再打开一次不能报错，也不能把数据搬没
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("二次打开失败（迁移不幂等）: %v", err)
	}
	defer s2.Close()
	if all2, _ := s2.TotalByUser(time.Time{}, "old"); all2.Requests != 3 {
		t.Fatalf("二次迁移后数据变了: %+v", all2)
	}
}

func ptrInt64(v int64) *int64 { return &v }
