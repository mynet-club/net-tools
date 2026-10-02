package store

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 一次性范围迁移（§2.7）里两处只有「第二次跑」才暴露的地方：
// scope_quota 的回填必须可重入，服务端方言必须先拿到库外备份的确认。
// 这两条都是回归测试：前一条曾经用 INSERT ... SELECT ... ON CONFLICT 写，
// 在 SQLite 上是语法错误；后一条曾经只打印一句提示就继续改表。

// seedUserQuotaRow 直接写 users 行，而不走 CreateUser / SetUserQuota。
//
// 回填读的输入是 users 表的裸列，走配额接口会顺手把 scope_quota 也写好（过渡期双写），
// 那样就测不到「回填到底灌了哪几列」。
func seedUserQuotaRow(t *testing.T, s *Store, name string, tokens int64, cost float64, at time.Time) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO users
		(name, token_hash, enabled, created_at, updated_at,
		 quota_month_tokens, quota_month_cost, rpm, max_concurrent)
		VALUES (?,?,1,?,?,?,0,0,0)`,
		name, "hash-"+name, at.UnixMilli(), at.UnixMilli(), tokens, cost); err != nil {
		t.Fatalf("写 users 失败: %v", err)
	}
}

func scanQuotaRow(t *testing.T, s *Store, kind, id string) (tokens int64, cost float64, rpm int, createdAt int64) {
	t.Helper()
	err := s.db.QueryRow(`SELECT quota_month_tokens, quota_month_cost, rpm, created_at
		FROM scope_quota WHERE scope_kind=? AND scope_id=?`, kind, id).
		Scan(&tokens, &cost, &rpm, &createdAt)
	if err != nil {
		t.Fatalf("查 (%s, %s) 的配额行失败: %v", kind, id, err)
	}
	return tokens, cost, rpm, createdAt
}

func countQuotaRows(t *testing.T, s *Store, kind string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM scope_quota WHERE scope_kind=?`, kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestScopeQuotaBackfillReentrant 验证回填可以跑第二遍，且第二遍是「覆盖」而不是
// 撞主键、静默跳过、或者整表删了重灌。
//
// 重入是真实路径：上一轮灌完但收口校验没过（或进程被 kill）时版本号没落，
// 下一次启动会带着已经存在的 scope_quota 再来一遍。
func TestScopeQuotaBackfillReentrant(t *testing.T) {
	s := openTestStore(t)
	made := time.Unix(1735689600, 0).UTC()
	seedUserQuotaRow(t, s, "alice", 5_000_000, 30.5, made)
	seedUserQuotaRow(t, s, "bob", 0, 0, made)

	// 3.0 的写路径可能已经往非 user 范围写过配额。回填既不能碰那些行，
	// 也不能在回滚时把它们一起删掉。
	orgScope := policy.ScopeRef{Kind: policy.ScopeOrganization, ID: "dept-a"}
	if err := s.SetScopeQuota(ScopeQuota{
		Scope: orgScope, QuotaMonthTokens: 100, RPM: 3, MaxConcurrent: 1, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	p := newScopeMigrationPlan(s.db, s.dialect, scopeBackup{})

	// 第一轮：目标表本轮才建（st.scopeQuota = false）。
	if err := p.backfillScopeQuota(scopeSchemaState{}, &ScopeMigrationReport{}); err != nil {
		t.Fatalf("首轮回填失败: %v", err)
	}
	if n := countQuotaRows(t, s, "user"); n != 2 {
		t.Fatalf("user 范围应当每个用户一行，实际 %d", n)
	}

	// 第二轮前把源改一遍：重入必须带上新值，否则「配额已就位」是个假结论。
	if _, err := s.db.Exec(`UPDATE users SET rpm = 42, quota_month_cost = 7.5 WHERE name = 'alice'`); err != nil {
		t.Fatal(err)
	}
	if err := p.backfillScopeQuota(scopeSchemaState{scopeQuota: true}, &ScopeMigrationReport{}); err != nil {
		t.Fatalf("重入回填失败: %v", err)
	}
	if n := countQuotaRows(t, s, "user"); n != 2 {
		t.Fatalf("重入不该造出重复行，实际 %d", n)
	}
	if _, _, rpm, createdAt := scanQuotaRow(t, s, "user", "alice"); rpm != 42 {
		t.Errorf("重入没把改过的 rpm 带上: %d", rpm)
	} else if createdAt != made.UnixMilli() {
		// 配额行的年龄跟主体走：改成「迁移那一刻」会让老限额在报表里显示成新设的。
		t.Errorf("created_at 应当沿用 users 的值: %d vs %d", createdAt, made.UnixMilli())
	}
	if _, cost, _, _ := scanQuotaRow(t, s, "user", "alice"); cost != 7.5 {
		t.Errorf("重入没把改过的月成本带上: %v", cost)
	}
	if tokens, _, rpm, _ := scanQuotaRow(t, s, "organization", "dept-a"); tokens != 100 || rpm != 3 {
		t.Errorf("回填不该动非 user 范围的行: tokens=%d rpm=%d", tokens, rpm)
	}
}

// TestScopeMigrationRollsBackOnLateVerifyFailure 覆盖「DDL 与回填都跑完了，收口校验才失败」
// 这条唯一没法靠预检避免的路径。
//
// §2.7 要的是两件事同时成立：失败后不许带着半套结构继续启动，且库不是废的 ——
// 补偿必须把它退回 2.x 形状、数据一行不少，运维修好原因后重开就能迁完。
// scopeMigrationFault 这个钩子就是为了测这条路径而存在（生产里恒为 nil）。
func TestScopeMigrationRollsBackOnLateVerifyFailure(t *testing.T) {
	path := newLegacyScopeDBFile(t)

	origFault := scopeMigrationFault
	t.Cleanup(func() { scopeMigrationFault = origFault })
	scopeMigrationFault = func(check string) error {
		if check == "归属覆盖" {
			return errors.New("注入：归属覆盖检查没通过")
		}
		return nil
	}

	if _, err := Open(path); err == nil {
		t.Fatal("收口校验失败必须让 Open 报错，不能静默放行半套结构")
	} else if !errors.Is(err, ErrScopeMigration) {
		t.Fatalf("错误必须可判定为迁移失败: %v", err)
	}
	scopeMigrationFault = nil

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	// 结构退回 2.x：拼接列还在，范围两列与派生表都不在。
	if has, err := columnExists(db, "provider_stats", "scope"); err != nil || !has {
		t.Errorf("回滚后 provider_stats.scope 应当还在（那是唯一的退路）: has=%v err=%v", has, err)
	}
	for _, t2 := range []struct{ table, col string }{
		{"provider_stats", "scope_kind"}, {"user_prices", "scope_id"}, {"requests", "routing_seed"},
	} {
		if has, err := columnExists(db, t2.table, t2.col); err != nil || has {
			t.Errorf("回滚后 %s.%s 不该存在: has=%v err=%v", t2.table, t2.col, has, err)
		}
	}
	for _, table := range []string{"scope_quota", "usage_scope_daily", legacyProviderStatsShadow} {
		if has, err := tableExists(db, table); err != nil || has {
			t.Errorf("回滚后 %s 不该存在（本轮新建的要整张撤掉）: has=%v err=%v", table, has, err)
		}
	}
	// 版本号没落：落了就等于对外宣称「这是 3.0 库」，而结构其实已经退回了。
	if v, err := dbScalarInt(db, SQLiteDialect{}, "SELECT COUNT(*) FROM meta WHERE key='"+metaScopeSchemaVersion+"'"); err != nil || v != 0 {
		t.Errorf("回滚后不该有 scope 版本号: rows=%d err=%v", v, err)
	}
	// 数据守恒：补偿只撤结构。
	for _, tc := range []struct {
		table string
		want  int64
	}{{"provider_stats", 2}, {"user_prices", 2}, {"requests", 1}} {
		n, err := dbScalarInt(db, SQLiteDialect{}, "SELECT COUNT(*) FROM "+tc.table)
		if err != nil || n != tc.want {
			t.Errorf("回滚后 %s 应当还是 %d 行: %d err=%v", tc.table, tc.want, n, err)
		}
	}

	// 修好原因（这里是注入消失）后重开：必须能走完，而不是留下一个只有备份文件能救的库。
	s, err := Open(path)
	if err != nil {
		t.Fatalf("第二次打开应当迁完: %v", err)
	}
	defer s.Close()
	if v, err := s.AppliedScopeSchemaVersion(); err != nil || v != ScopeSchemaVersion {
		t.Errorf("迁移完成标记应当落到 %d: %d err=%v", ScopeSchemaVersion, v, err)
	}
	if n := countQuotaRows(t, s, "user"); n != 0 {
		t.Errorf("这个 fixture 没有 users 行，user 范围配额应当 0 行: %d", n)
	}
	if has, err := columnExists(db, "provider_stats", "scope"); err != nil || has {
		t.Errorf("迁移完成后拼接列必须消失: has=%v err=%v", has, err)
	}
	// 补列路径也要走通：回滚删掉的列，第二轮得重新补上，且明细行还是那一条。
	for _, col := range []string{"scope_kind", "routing_seed"} {
		if has, err := columnExists(s.db, "requests", col); err != nil || !has {
			t.Errorf("第二轮迁移后 requests.%s 应当存在: has=%v err=%v", col, has, err)
		}
	}
	if n, err := dbScalarInt(s.db, s.dialect, "SELECT COUNT(*) FROM requests"); err != nil || n != 1 {
		t.Errorf("补列两轮之后 requests 还是 1 行才对: %d err=%v", n, err)
	}
}

// columnExists / tableExists 是给测试用的形状查询（生产代码只问单列，见 Dialect.HasColumn）。
func columnExists(db *sql.DB, table, column string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`, table, column).Scan(&n)
	return n > 0, err
}

func tableExists(db *sql.DB, table string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n)
	return n > 0, err
}

// TestRequireExternalScopeBackupGate 钉住「服务端方言不许无确认地自动改表」。
//
// §2.7 要迁移前有可恢复备份。SQLite 能自己复制库文件，MySQL / PG 不能 ——
// 那种库上自动跑一次改主键的迁移，等于替运维决定这份数据可以不备份。
func TestRequireExternalScopeBackupGate(t *testing.T) {
	origLookup := scopeBackupAckLookup
	t.Cleanup(func() { scopeBackupAckLookup = origLookup })

	// SQLite 恒放行：它有真正的文件备份，加一道门只会挡住无人值守的升级。
	if err := requireExternalScopeBackup(SQLiteDialect{}); err != nil {
		t.Errorf("sqlite 不该被确认门挡住: %v", err)
	}

	withoutAck := func(string) string { return "" }
	withAck := func(string) string { return "done" }
	// 拼错的值不算确认：把「没备份」当成「备份过了」是往危险方向解释，代价不对称。
	typoAck := func(string) string { return "yes" }

	for _, tc := range []struct {
		name    string
		d       Dialect
		lookup  func(string) string
		keyword string
		wantErr bool
	}{
		{"mysql 未确认", MySQLDialect{}, withoutAck, "mysqldump", true},
		{"postgres 未确认", PostgresDialect{}, withoutAck, "pg_dump", true},
		{"mysql 确认值写错", MySQLDialect{}, typoAck, "mysqldump", true},
		{"mysql 已确认", MySQLDialect{}, withAck, "", false},
		{"postgres 已确认", PostgresDialect{}, withAck, "", false},
	} {
		scopeBackupAckLookup = tc.lookup
		err := requireExternalScopeBackup(tc.d)
		switch {
		case tc.wantErr && err == nil:
			t.Errorf("%s：应当拒绝，却放行了", tc.name)
		case !tc.wantErr && err != nil:
			t.Errorf("%s：应当放行，实际 %v", tc.name, err)
		case tc.wantErr:
			if !errors.Is(err, ErrScopeMigration) {
				t.Errorf("%s：错误必须可判定为迁移失败: %v", tc.name, err)
			}
			// 这道门排在打印备份提示之前，所以拒绝时必须把入口捎在错误里。
			if !strings.Contains(err.Error(), scopeBackupAckEnv) {
				t.Errorf("%s：错误要点名确认变量 %s: %v", tc.name, scopeBackupAckEnv, err)
			}
			if tc.keyword != "" && !strings.Contains(err.Error(), tc.keyword) {
				t.Errorf("%s：错误要给出备份入口（含 %q）: %v", tc.name, tc.keyword, err)
			}
		}
	}
}
