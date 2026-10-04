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

// legacyUsersQuotaCols 是 2.x 加在 users 上的四列配额/限流列（列名 + 类型）。
//
// 3.0 的 userSchema 已经不建它们：那份形状只存在于**旧二进制留下的库文件**里，
// 而回填的输入恰恰是它。测试要走那条路径就得手工造出这个形状，
// 且建表和补列共用这一份定义 —— 两处漂移就会测出「fixture 有、迁移看不见」的假绿。
var legacyUsersQuotaCols = []string{
	"quota_month_tokens INTEGER NOT NULL DEFAULT 0",
	"quota_month_cost REAL NOT NULL DEFAULT 0",
	"rpm INTEGER NOT NULL DEFAULT 0",
	"max_concurrent INTEGER NOT NULL DEFAULT 0",
}

// legacyUserRow 是一条要写进 2.x 形状 users 表的记录。
type legacyUserRow struct {
	name      string
	tokens    int64
	cost      float64
	rpm, conc int
	mode      string
	enabled   bool
}

// ensureLegacyUsersQuotaCols 把 2.x 那四列补到 users 表上（已有的跳过）。
func ensureLegacyUsersQuotaCols(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, col := range legacyUsersQuotaCols {
		// 重复补同一列在 SQLite 上是「列已存在」的错误，所以先问一声。
		name := strings.Fields(col)[0]
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('users') WHERE name=?`, name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			continue
		}
		if _, err := db.Exec("ALTER TABLE users ADD COLUMN " + col); err != nil {
			t.Fatalf("补 2.x 列 %s 失败: %v", name, err)
		}
	}
}

// seedUserQuotaRow 直接写 users 行，而不走 CreateUser。
//
// 回填读的输入是 users 表的裸列；CreateUser 会在同一事务里顺手补一行全 0 的 scope_quota，
// 那样就测不到「回填到底灌了哪几列」—— 而回填把旧列的值搬错一格，只有在迁移结果里才看得见。
func seedUserQuotaRow(t *testing.T, s *Store, name string, tokens int64, cost float64, at time.Time) {
	t.Helper()
	ensureLegacyUsersQuotaCols(t, s.db)
	if _, err := s.db.Exec(`INSERT INTO users
		(name, token_hash, enabled, created_at, updated_at,
		 quota_month_tokens, quota_month_cost, rpm, max_concurrent)
		VALUES (?,?,1,?,?,?,0,0,0)`,
		name, "hash-"+name, at.UnixMilli(), at.UnixMilli(), tokens, cost); err != nil {
		t.Fatalf("写 users 失败: %v", err)
	}
}

// newLegacyUsersDBFile 在一个 2.x 形状的库文件上再建出 2.x 的 users 表并写行。
//
// users 表整张按老形状写（不是 CREATE + 补列）：这样「2.x 库里 users 有什么」是由这份
// fixture 说的，而不是被当前 userSchema 悄悄带跑 —— 后者会让退役测试变成空跑。
func newLegacyUsersDBFile(t *testing.T, rows ...legacyUserRow) string {
	t.Helper()
	path := newLegacyScopeDBFile(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	ddl := `CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  token_hash TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  mode TEXT NOT NULL DEFAULT 'byo',
  ` + strings.Join(legacyUsersQuotaCols, ",\n  ") + `
);`
	if _, err := db.Exec(ddl); err != nil {
		t.Fatalf("造 2.x users 表失败: %v", err)
	}
	made := time.Unix(1735689600, 0).UTC().UnixMilli()
	for _, r := range rows {
		mode := r.mode
		if mode == "" {
			mode = ModeBYO
		}
		enabled := 1
		if !r.enabled {
			enabled = 0
		}
		if _, err := db.Exec(`INSERT INTO users
			(name, token_hash, enabled, created_at, updated_at, mode,
			 quota_month_tokens, quota_month_cost, rpm, max_concurrent)
			VALUES (?,?,?,?,?,?,?,?,?,?)`,
			r.name, "hash-"+r.name, enabled, made, made, mode,
			r.tokens, r.cost, r.rpm, r.conc); err != nil {
			t.Fatalf("写 2.x users 行失败: %v", err)
		}
	}
	return path
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

	// 第一轮：目标表本轮才建（st.scopeQuota = false），users 带着 2.x 的配额列。
	if err := p.backfillScopeQuota(scopeSchemaState{usersQuotaLegacy: true}, &ScopeMigrationReport{}); err != nil {
		t.Fatalf("首轮回填失败: %v", err)
	}
	if n := countQuotaRows(t, s, "user"); n != 2 {
		t.Fatalf("user 范围应当每个用户一行，实际 %d", n)
	}

	// 第二轮前把源改一遍：重入必须带上新值，否则「配额已就位」是个假结论。
	if _, err := s.db.Exec(`UPDATE users SET rpm = 42, quota_month_cost = 7.5 WHERE name = 'alice'`); err != nil {
		t.Fatal(err)
	}
	if err := p.backfillScopeQuota(scopeSchemaState{scopeQuota: true, usersQuotaLegacy: true}, &ScopeMigrationReport{}); err != nil {
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
	// 执行面摘要两列（版本 4）和 scope 两列一样是本轮补的，回滚必须一并撤掉：
	// 留着它们，「结构退回 2.x」这句话就是假的——老库会被读成「有摘要列、只是没值」。
	for _, t2 := range []struct{ table, col string }{
		{"provider_stats", "scope_kind"}, {"user_prices", "scope_id"},
		{"requests", "routing_seed"}, {"requests", "executor"}, {"requests", "exchange_reason"},
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
	for _, col := range []string{"scope_kind", "routing_seed", "executor", "exchange_reason"} {
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

// TestScopeMigrationRetiresUsersQuotaColumns 是 §2.7 规则 8 的「旧字段退役」那半步：
// 配额搬进 scope_quota 之后，users 上那四列必须从库里消失。
//
// 为什么值得单独钉：读/写侧都已经改到 scope_quota 之后，旧列留着**不会有任何报错** ——
// 它只是悄悄变成第二个配额存放处，直到某天有人照着 2.x 的形状写回那一列，
// 两套账的差值就变成用户账单上的争议行。所以断言的是形状，不是行为。
func TestScopeMigrationRetiresUsersQuotaColumns(t *testing.T) {
	path := newLegacyUsersDBFile(t,
		legacyUserRow{name: "alice", tokens: 5_000_000, cost: 30.5, rpm: 7, conc: 2, mode: ModeConsumption, enabled: true},
		legacyUserRow{name: "bob", enabled: true},
	)
	s := openTestStoreAt(t, path)

	for _, col := range usersQuotaLegacyCols {
		if has, err := columnExists(s.db, "users", col); err != nil || has {
			t.Errorf("迁移后 users.%s 不该还在: has=%v err=%v", col, has, err)
		}
	}
	// 身份列必须留着：enabled 说的是「账号能不能用」，从来不是某个范围的限额。
	for _, col := range []string{"mode", "enabled", "token_hash"} {
		if has, err := columnExists(s.db, "users", col); err != nil || !has {
			t.Errorf("users.%s 是身份事实，不许被退役掉: has=%v err=%v", col, has, err)
		}
	}

	// 值一格都不能搬错 —— 而且必须由 3.0 的读路径读得出（证明退役没把配额一起删走）。
	alice := mustQuota(t, s, policy.MustScope(policy.ScopeUser, "alice"))
	if alice.QuotaMonthTokens != 5_000_000 || alice.QuotaMonthCost != 30.5 || alice.RPM != 7 || alice.MaxConcurrent != 2 {
		t.Errorf("旧列的值必须逐格进 scope_quota: %+v", alice)
	}
	bob := mustQuota(t, s, policy.MustScope(policy.ScopeUser, "bob"))
	if bob.QuotaMonthTokens != 0 || bob.RPM != 0 || bob.MaxConcurrent != 0 {
		t.Errorf("旧列的 0（= 不限）不该被搬成任何限额: %+v", bob)
	}

	// 再开一次：这一轮走「版本号已落」的幂等收尾，列早就不在了，
	// 既不许报错，也不许把已经迁好的配额行改动（重复 DROP 在 SQLite 上是错误，所以逐列先问在不在）。
	again, err := Open(path)
	if err != nil {
		t.Fatalf("二次打开失败（退役不幂等）: %v", err)
	}
	defer again.Close()
	if n := countQuotaRows(t, again, "user"); n != 2 {
		t.Errorf("二次打开之后 user 范围配额行还是 2 行才对: %d", n)
	}
	if q := mustQuota(t, again, policy.MustScope(policy.ScopeUser, "alice")); q.RPM != 7 {
		t.Errorf("二次打开不该改动已迁好的配额: %+v", q)
	}
}

// TestRetireUsersQuotaColumnsWaitsForQuotaRows 钉住退役的那道守卫。
//
// 「每个 user 都有配额行」不成立时，users 的旧列是唯一的配额真值：那种库里删列
// 就是销毁数据，而 3.0 的读路径紧接着会把缺行的用户当成「配额读不出来」（buildRegistry 拒绝重建快照）。
// 所以这里保留列 + 打提示，并且**不许让 Open 失败**（半套形状不能启动，但缺配额行不是半套形状）；
// 等运维补齐配额行，下一次启动必须自己把列收干净。
func TestRetireUsersQuotaColumnsWaitsForQuotaRows(t *testing.T) {
	path := newLegacyUsersDBFile(t, legacyUserRow{name: "alice", rpm: 9, enabled: true})
	s := openTestStoreAt(t, path)
	if has, err := columnExists(s.db, "users", "rpm"); err != nil || has {
		t.Fatalf("正常迁移后 users.rpm 应当已经消失: has=%v err=%v", has, err)
	}
	s.Close()

	// 造出守卫要拦的那种库：结构是 3.0、版本号已落，但 alice 的配额行没了，
	// 而旧列被（人工恢复/半套 dump）添了回来，里面是唯一一份限额。
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"ALTER TABLE users ADD COLUMN rpm INTEGER NOT NULL DEFAULT 0",
		"UPDATE users SET rpm = 9 WHERE name = 'alice'",
		"DELETE FROM scope_quota WHERE scope_kind='user' AND scope_id='alice'",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	origOut := scopeMigrationOutput
	t.Cleanup(func() { scopeMigrationOutput = origOut })
	var notes strings.Builder
	scopeMigrationOutput = &notes

	alice := policy.MustScope(policy.ScopeUser, "alice")
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("守卫拦下退役时 Open 必须照常成功（缺行不是半套形状）: %v", err)
	}
	if has, err := columnExists(s2.db, "users", "rpm"); err != nil || !has {
		t.Errorf("配额行缺失时旧列必须保留（那是唯一的限额真值）: has=%v err=%v", has, err)
	}
	if n := countQuotaRows(t, s2, "user"); n != 0 {
		t.Errorf("这一步的前提是 alice 缺配额行，实际读到 %d 行", n)
	}
	if !strings.Contains(notes.String(), "保留") {
		t.Errorf("要把「为什么没删、删了会怎样」打进启动日志，实际: %s", notes.String())
	}

	// 补齐配额行（管理员重新给一次限额），旧列就不再是任何真值的唯一存放处了。
	if err := s2.SetScopeQuota(ScopeQuota{Scope: alice, RPM: 9, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	s2.Close()

	s3, err := Open(path)
	if err != nil {
		t.Fatalf("补齐之后重开应当成功: %v", err)
	}
	defer s3.Close()
	if has, err := columnExists(s3.db, "users", "rpm"); err != nil || has {
		t.Errorf("补齐配额行之后，下一次启动应当自动把旧列退役: has=%v err=%v", has, err)
	}
	if q := mustQuota(t, s3, alice); q.RPM != 9 {
		t.Errorf("退役不能把限额一起删走: %+v", q)
	}
}

// TestScopeQuotaBackfillWithoutLegacyColumns 管的是回填的**输入选择**：
// users 没带过那四列（比消费模式更早的库）时，缺行的用户要补出「不限」，
// 而已经有行的用户绝不能被同步语句改回全 0 —— 那是丢配额，不是幂等。
func TestScopeQuotaBackfillWithoutLegacyColumns(t *testing.T) {
	s := openTestStore(t)
	alice, carol := policy.MustScope(policy.ScopeUser, "alice"), policy.MustScope(policy.ScopeUser, "carol")
	if err := s.CreateUser("alice", TokenHash("sk-alice")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetScopeQuota(ScopeQuota{Scope: alice, QuotaMonthTokens: 900, RPM: 5, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// CreateUser 总是顺手补配额行，所以「有 users 行、没配额行」只能由裸 SQL 造出来
	// —— 那正是 3.0 之前的库里长期存在的形状。
	now := time.Unix(1735689600, 0).UTC().UnixMilli()
	if _, err := s.db.Exec(`INSERT INTO users (name, token_hash, enabled, created_at, updated_at, mode)
		VALUES ('carol','hash-carol',1,?,?,'byo')`, now, now); err != nil {
		t.Fatal(err)
	}
	// 这里的 st 是「旧列不在」（usersQuotaLegacy 零值）：只有补行那一条 INSERT，没有同步。
	p := newScopeMigrationPlan(s.db, s.dialect, scopeBackup{})
	if err := p.backfillScopeQuota(scopeSchemaState{scopeQuota: true}, &ScopeMigrationReport{}); err != nil {
		t.Fatalf("无旧列的回填失败: %v", err)
	}

	// alice 已经有行了：没有旧列就没有「源」，同步那句要是跑了，她的 900/5 会变成 0/0，
	// 而那读起来像「管理员把限额放开了」。
	if got := mustQuota(t, s, alice); got.QuotaMonthTokens != 900 || got.RPM != 5 {
		t.Errorf("无旧列时不该改动已写过的配额行: %+v", got)
	}
	if got := mustQuota(t, s, carol); got.QuotaMonthTokens != 0 || got.RPM != 0 || !got.Enabled {
		t.Errorf("carol 应当补出全 0（= 不限）且沿用账号的启用状态: %+v", got)
	}
	if n := countQuotaRows(t, s, "user"); n != 2 {
		t.Errorf("两个用户都该有一行: %d", n)
	}
}

// 结构已是 3.0、镜像却是空的 —— 那是「老账本没有任何读路径能看见」的形状：规则 8 之后
// 用量只读 usage_scope_daily，补不上镜像就等于把老账本报成 0 元。这里钉住补齐的三种情形：
// 没有老账单是空操作、空表补全、目标表非空时一条都不碰。
func TestMirrorUsageScopeDailyOnlyFillsEmptyMirror(t *testing.T) {
	s := openTestStore(t)

	// 新库第一次打开就是这个形状：没有老账单，必须干净地什么都不做。
	if err := mirrorUsageScopeDailyIfEmpty(s.db, s.dialect); err != nil {
		t.Fatalf("没有老账单时不该报错: %v", err)
	}

	// 写 usage_user_daily 的那条路 3.0 已经不走，所以旧账单只能由裸 SQL 造出来。
	const cols = `day, user_name, provider, model, upstream_model, system_paid,
		requests, ok, failed, prompt_tokens, completion_tokens, total_tokens,
		latency_sum_ms, charge, frozen_charges`
	if _, err := s.db.Exec(`INSERT INTO usage_user_daily (` + cols + `) VALUES
		('2026-09-01','old','deepseek','deepseek-flash','',0,3,3,0,900,300,1200,1500,0,0),
		('2026-09-02','older','deepseek','deepseek-flash','',0,1,1,0,10,5,15,50,0,0)`); err != nil {
		t.Fatal(err)
	}
	if err := mirrorUsageScopeDailyIfEmpty(s.db, s.dialect); err != nil {
		t.Fatalf("补镜像失败: %v", err)
	}
	old := policy.MustScope(policy.ScopeUser, "old")
	tot, err := s.ScopeUsageTotals([]policy.ScopeRef{old}, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if tot.Requests != 3 || tot.TotalTokens != 1200 || tot.FirstDay != "2026-09-01" {
		t.Errorf("老账单没按 (user, old) 补进来: %+v", tot)
	}

	// 目标表已经有行（上一轮补过、或者 3.0 正在记账）：那条镜像是整表 INSERT...SELECT，
	// 非空时再跑一次就是双份账单，所以这里必须一条都不补。
	if _, err := s.db.Exec(`INSERT INTO usage_user_daily (` + cols + `) VALUES
		('2026-09-03','ghost','deepseek','deepseek-flash','',0,9,9,0,90,9,99,90,0,0)`); err != nil {
		t.Fatal(err)
	}
	if err := mirrorUsageScopeDailyIfEmpty(s.db, s.dialect); err != nil {
		t.Fatalf("目标表非空时不该报错: %v", err)
	}
	if n, _, err := tableRowCount(s.db, s.dialect, "usage_scope_daily"); err != nil {
		t.Fatal(err)
	} else if n != 2 {
		t.Errorf("目标表非空时一条都不该补，实际 %d 行", n)
	}
	if g := policy.MustScope(policy.ScopeUser, "ghost"); hasScopeUsageRows(t, s, g) {
		t.Error("ghost 是补镜像之后才写进旧表的，不该出现在范围表里")
	}
}

// hasScopeUsageRows 报告某个范围在 usage_scope_daily 里有没有行。
func hasScopeUsageRows(t *testing.T, s *Store, scope policy.ScopeRef) bool {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM usage_scope_daily WHERE scope_kind=? AND scope_id=?`,
		string(scope.Kind), scope.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// scanRequestSummary 读回一条请求的执行面摘要。
//
// 刻意用 sql.NullString：这三种读法（NULL / 空串 / 有值）的区别就是裁决第 4 条的全部
// 落点，用 string 扫会把 NULL 塌成空串，测试当场变成空跑。
func scanRequestSummary(t *testing.T, s *Store, requestID string) (sql.NullString, sql.NullString) {
	t.Helper()
	var exe, reason sql.NullString
	if err := s.db.QueryRow(`SELECT executor, exchange_reason FROM requests WHERE request_id=?`,
		requestID).Scan(&exe, &reason); err != nil {
		t.Fatalf("读 %s 的执行面摘要失败: %v", requestID, err)
	}
	return exe, reason
}

// assertSummaryNULL 断言「这一行没有执行面事实」。
func assertSummaryNULL(t *testing.T, s *Store, requestID, why string) {
	t.Helper()
	exe, reason := scanRequestSummary(t, s, requestID)
	if exe.Valid || reason.Valid {
		t.Errorf("%s：executor/exchange_reason 都该是 NULL（%s），实际 %q(valid=%v) / %q(valid=%v)",
			requestID, why, exe.String, exe.Valid, reason.String, reason.Valid)
	}
}

// assertSummary 断言摘要两列的确切取值（want 为空串时读出的就是「不应用」）。
func assertSummary(t *testing.T, s *Store, requestID, wantExecutor, wantReason, why string) {
	t.Helper()
	exe, reason := scanRequestSummary(t, s, requestID)
	if !exe.Valid || !reason.Valid {
		t.Errorf("%s：两列都该是有值的一格（%s），实际 executor valid=%v / reason valid=%v",
			requestID, why, exe.Valid, reason.Valid)
		return
	}
	if exe.String != wantExecutor || reason.String != wantReason {
		t.Errorf("%s：摘要不对（%s），期望 %q/%q，实际 %q/%q",
			requestID, why, wantExecutor, wantReason, exe.String, reason.String)
	}
}

// TestRequestSummaryColumnsAreNotBackfilled 钉住版本 4 迁移的「补列不回填」那半条裁决。
//
// 2026-10-04 裁决第 4 条（B）要求新查询能分清两件事：「没有这一列的事实」与
// 「事实是不应用」。这两格只有靠历史行保持 NULL 才分得开 —— 迁移把老行填成空串，
// 就等于替 2.x 编造了一次「当时决定不走执行器」，而那时执行器还不存在。
//
// 同时钉住写入侧：迁移之后的行永远落在另外两格里，读侧因此可以按「NULL 只可能是历史」
// 来解释计数，而不必去比对时间戳。
func TestRequestSummaryColumnsAreNotBackfilled(t *testing.T) {
	s := openTestStoreAt(t, newLegacyScopeDBFile(t))

	if v, err := s.AppliedScopeSchemaVersion(); err != nil || v != ScopeSchemaVersion {
		t.Fatalf("迁移应当盖到版本 %d: %d err=%v", ScopeSchemaVersion, v, err)
	}
	// fixture 里那条 requests 行（old-req）是 2.x 时代的账单。
	assertSummaryNULL(t, s, "old-req", "历史行不许回填")

	alice := policy.MustScope(policy.ScopeUser, "alice")
	if err := s.CreateUser("alice", TokenHash("sk-alice")); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// 没交给执行器的一次（2.x 传输）：两列都是空串。
	if err := s.InsertRequest(RequestRecord{
		Ts: now, RequestID: "legacy-transport", Scope: alice,
		Model: "deepseek-flash", Provider: "p1", OK: true, StatusCode: 200,
	}); err != nil {
		t.Fatalf("InsertRequest: %v", err)
	}
	// 交给执行器、且那一发超时的一次：承载者与结果码各归一位。
	if err := s.InsertRequest(RequestRecord{
		Ts: now, RequestID: "delegated", Scope: alice,
		Model: "deepseek-flash", Provider: "p1", OK: false, StatusCode: 0,
		Executor: "http-openai", ExchangeReason: "executor_timeout",
	}); err != nil {
		t.Fatalf("InsertRequest: %v", err)
	}
	assertSummary(t, s, "legacy-transport", "", "", "空串才是「不应用」这一格")
	assertSummary(t, s, "delegated", "http-openai", "executor_timeout", "走过执行器就得留下承载者与结果码")

	// 账面证据：只有历史行算「没有执行面事实」。
	rep, err := s.ScopeMigrationReportForDialect()
	if err != nil {
		t.Fatalf("只读报告失败: %v", err)
	}
	if rep.SummaryUnknown != 1 {
		t.Errorf("summary_unknown 应当只数历史行（1 条），实际 %d", rep.SummaryUnknown)
	}
}

// TestNewDBRequestSummaryColumnsFromDDL 钉住新库这一侧：两列由建表语句直接带出来，
// 不靠迁移补，因而新库里**造不出** NULL。
//
// 这条和上一条是同一个契约的两半：只有「NULL 只可能来自版本 4 之前」成立，
// 按 NULL 统计历史段才是可信的；新库若也漏出 NULL，那个计数就变成两种原因的混合。
func TestNewDBRequestSummaryColumnsFromDDL(t *testing.T) {
	s := openTestStore(t)
	for _, col := range []string{"executor", "exchange_reason"} {
		if has, err := columnExists(s.db, "requests", col); err != nil || !has {
			t.Errorf("新库的 requests.%s 应当由 DDL 直接建出来: has=%v err=%v", col, has, err)
		}
	}
	bob := policy.MustScope(policy.ScopeUser, "bob")
	if err := s.CreateUser("bob", TokenHash("sk-bob")); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertRequest(RequestRecord{
		Ts: time.Now(), RequestID: "fresh", Scope: bob,
		Model: "m", Provider: "p1", OK: true, StatusCode: 200,
	}); err != nil {
		t.Fatal(err)
	}
	assertSummary(t, s, "fresh", "", "", "新库不委托的一发也必须落在空串格里")

	rep, err := s.ScopeMigrationReportForDialect()
	if err != nil {
		t.Fatalf("只读报告失败: %v", err)
	}
	if rep.SummaryUnknown != 0 {
		t.Errorf("新库不该有「没有执行面事实」的行: %d", rep.SummaryUnknown)
	}
}

// TestRequestSummaryColumnsHealAfterVersionThree 钉住第三条调用路径：
// 结构已经是 3.0（版本 3 迁完）、只有版本号要往前走的库。
//
// 现网真有这种库 —— 上一版二进制迁的就是版本 3。它打开时 needsWork() 为假，
// 走的是「不动数据、不建备份、直接盖章」那条最短的分支；如果补列没挂在那条分支上，
// 这些库会带着一个「版本 4 却没有两列」的形状启动，而读侧第一次撞「列不存在」时
// 没人能想到原因在启动序列里。
func TestRequestSummaryColumnsHealAfterVersionThree(t *testing.T) {
	path := newLegacyScopeDBFile(t)
	s := openTestStoreAt(t, path)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// 退回「版本 3 迁完」的形状：列删掉、版本号改成 3（其余结构不动）。
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, col := range []string{"executor", "exchange_reason"} {
		if _, err := db.Exec("ALTER TABLE requests DROP COLUMN " + col); err != nil {
			t.Fatalf("撤掉 %s 失败: %v", col, err)
		}
	}
	if err := metaSetInt(db, SQLiteDialect{}, metaScopeSchemaVersion, 3); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := openTestStoreAt(t, path)
	if v, err := s2.AppliedScopeSchemaVersion(); err != nil || v != ScopeSchemaVersion {
		t.Fatalf("版本 3 的库必须升到 %d: %d err=%v", ScopeSchemaVersion, v, err)
	}
	for _, col := range []string{"executor", "exchange_reason"} {
		if has, err := columnExists(s2.db, "requests", col); err != nil || !has {
			t.Errorf("补建之后 requests.%s 必须存在: has=%v err=%v", col, has, err)
		}
	}
	// 补建只加列，一样不许回填：那条历史行还是 NULL。
	assertSummaryNULL(t, s2, "old-req", "补建路径同样不许回填")
	// 明细行没被这次启动动过。
	if n, err := dbScalarInt(s2.db, s2.dialect, "SELECT COUNT(*) FROM requests"); err != nil || n != 1 {
		t.Errorf("补建不该增删 requests 行: %d err=%v", n, err)
	}
}
