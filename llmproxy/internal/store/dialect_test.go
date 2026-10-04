package store

import (
	"fmt"
	"strings"
	"testing"
)

// Dialect 是「通用数据库操作界面」的下半截：占位符与 upsert 的方言差异只准出现在这里。
func TestSQLiteDialectRebindAndUpsert(t *testing.T) {
	d := SQLiteDialect{}
	if d.Name() != "sqlite" || d.Driver() != "sqlite" {
		t.Errorf("Name/Driver = %q/%q", d.Name(), d.Driver())
	}
	q := "SELECT * FROM t WHERE a = ? AND b = ?"
	if got := d.Rebind(q); got != q {
		t.Errorf("SQLite Rebind 应当原样，实际 %q", got)
	}
	up := d.Upsert("usage_daily",
		"day, provider, model, requests",
		"day, provider, model",
		"requests, ok")
	for _, want := range []string{
		"INSERT INTO usage_daily",
		"VALUES (?,?,?,?)",
		"ON CONFLICT(day, provider, model) DO UPDATE SET",
		"requests = excluded.requests",
		"ok = excluded.ok",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("Upsert 缺 %q:\n%s", want, up)
		}
	}
}

// PG 的 $n 改写：顺序必须跟 ? 的出现次序一致。
func TestRebindDollar(t *testing.T) {
	got := rebindDollar("INSERT INTO t (a,b,c) VALUES (?,?,?) ON CONFLICT(x) DO UPDATE SET a = ?")
	want := "INSERT INTO t (a,b,c) VALUES ($1,$2,$3) ON CONFLICT(x) DO UPDATE SET a = $4"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if rebindDollar("SELECT 1") != "SELECT 1" {
		t.Error("没有 ? 的语句不该被改动")
	}
}

// dialectByName：空名 = sqlite；未知驱动要报错并点名支持列表。
func TestDialectByName(t *testing.T) {
	for _, name := range []string{"", "sqlite", "SQLite"} {
		d, err := dialectByName(name)
		if err != nil || d.Name() != "sqlite" {
			t.Errorf("dialectByName(%q) = %v, %v", name, d, err)
		}
	}
	if _, err := dialectByName("mysql"); err != nil {
		t.Errorf("mysql 应当可用: %v", err)
	}
	if _, err := dialectByName("postgres"); err != nil {
		t.Errorf("postgres 应当可用: %v", err)
	}
	if _, err := dialectByName("oracle"); err == nil {
		t.Error("未知驱动应当报错")
	} else if !strings.Contains(err.Error(), "sqlite") {
		t.Errorf("错误信息该列出支持的驱动: %v", err)
	}
}

// MySQL：upsert 换成 ON DUPLICATE KEY；DDL 把 AUTOINCREMENT / REAL / INTEGER 翻过去。
func TestMySQLDialect(t *testing.T) {
	d := MySQLDialect{}
	up := d.Upsert("usage_daily", "day, provider, model, requests", "day, provider, model", "requests, ok")
	if !strings.Contains(up, "ON DUPLICATE KEY UPDATE") {
		t.Errorf("MySQL upsert 语法不对: %s", up)
	}
	if strings.Contains(up, "ON CONFLICT") {
		t.Errorf("MySQL 不该出现 ON CONFLICT: %s", up)
	}
	if !strings.Contains(up, "requests = VALUES(requests)") {
		t.Errorf("MySQL 赋值应当用 VALUES(): %s", up)
	}
	ddl := d.RewriteDDL("id INTEGER PRIMARY KEY AUTOINCREMENT, cost REAL, n INTEGER")
	if strings.Contains(ddl, "AUTOINCREMENT") || strings.Contains(ddl, "REAL") {
		t.Errorf("MySQL DDL 未翻译: %s", ddl)
	}
	if !strings.Contains(ddl, "AUTO_INCREMENT") || !strings.Contains(ddl, "DOUBLE") {
		t.Errorf("MySQL DDL 翻译不全: %s", ddl)
	}
	// TEXT 不能带 DEFAULT（MySQL 1101）；短字段走 VARCHAR(191)，长正文放宽
	ddl = d.RewriteDDL("currency TEXT NOT NULL DEFAULT '', error_msg TEXT")
	if strings.Contains(ddl, "TEXT") {
		t.Errorf("TEXT 应当被替换掉: %s", ddl)
	}
	if !strings.Contains(ddl, "VARCHAR(128) NOT NULL DEFAULT") {
		t.Errorf("带 DEFAULT 的 TEXT 应成 VARCHAR(128): %s", ddl)
	}
	if !strings.Contains(ddl, "error_msg VARCHAR(1024)") {
		t.Errorf("错误正文应放宽到 VARCHAR(1024): %s", ddl)
	}
	if d.Rebind("SELECT ?") != "SELECT ?" {
		t.Error("MySQL 占位符仍是 ?")
	}
}

// PostgreSQL：$n 占位符 + 与 SQLite 同形的 ON CONFLICT。
func TestPostgresDialect(t *testing.T) {
	d := PostgresDialect{}
	up := d.Upsert("usage_daily", "day, provider, model, requests", "day, provider, model", "requests, ok")
	if !strings.Contains(up, "ON CONFLICT(day, provider, model)") {
		t.Errorf("PG upsert 语法不对: %s", up)
	}
	if !strings.Contains(up, "VALUES ($1,$2,$3,$4)") {
		t.Errorf("PG 占位符应当是 $n: %s", up)
	}
	if !strings.Contains(up, "requests = excluded.requests") {
		t.Errorf("PG 赋值应当用 excluded: %s", up)
	}
	ddl := d.RewriteDDL("id INTEGER PRIMARY KEY AUTOINCREMENT, cost REAL")
	if !strings.Contains(ddl, "BIGSERIAL") || !strings.Contains(ddl, "DOUBLE PRECISION") {
		t.Errorf("PG DDL 翻译不全: %s", ddl)
	}
}

// execSchema / splitStatements：多条 DDL 要拆开逐条跑。
func TestSplitStatements(t *testing.T) {
	stmts := splitStatements("CREATE TABLE a (x);\n\nCREATE TABLE b (y);\n")
	if len(stmts) != 2 {
		t.Fatalf("应当 2 条，实际 %d: %v", len(stmts), stmts)
	}
	if !strings.HasPrefix(stmts[0], "CREATE TABLE a") || !strings.HasPrefix(stmts[1], "CREATE TABLE b") {
		t.Errorf("切分不对: %v", stmts)
	}
	if firstLine("CREATE TABLE a (\n  x INT\n);") != "CREATE TABLE a (" {
		t.Errorf("firstLine = %q", firstLine("CREATE TABLE a (\n  x INT\n);"))
	}
}

// 重开一个已迁移的 MySQL 库时，重复索引名（1061）必须按幂等吞掉。
//
// 为什么单独钉这一条：DDL 常量习惯在索引上面写一行说明，而 splitStatements 只按分号切，
// 于是「整段的第一行」是注释。按第一行判语句类型时，那条 CREATE INDEX 就不认识了 ——
// 真库腿第一次在真 MySQL 上重开时正是这样硬失败的（Error 1061 冒成迁移失败）。
// 断言用 scopeSchema30 / scopeIndexDDL30 这两份**发货中的** DDL 逐条过，
// 而不是手抄一行：手抄的那份会和常量各自漂移，漂走的那天这条守卫就不在测真东西了。
func TestIsIgnorableDDLHandlesCommentPrefixedIndexes(t *testing.T) {
	d := MySQLDialect{}
	dupErr := fmt.Errorf("Error 1061 (42000): Duplicate key name 'idx_x'")

	// 两份发货 DDL：建表段与挂在既有表上的范围索引段，都过一遍 MySQL 的 RewriteDDL
	chunks := []string{scopeSchema30}
	for _, ix := range scopeIndexDDL30 {
		chunks = append(chunks, ix.ddl)
	}

	indexes := 0
	for _, src := range chunks {
		for _, stmt := range splitStatements(d.RewriteDDL(src)) {
			if !strings.HasPrefix(ddlHead(stmt), "CREATE INDEX") {
				continue
			}
			indexes++
			if !isIgnorableDDL(d, stmt, dupErr) {
				t.Errorf("重复建索引要按幂等吞掉，实际当成失败: %q", ddlHead(stmt))
			}
			// 同一句话术只有 1061 才吞：真出错（列不存在）必须照红。
			if isIgnorableDDL(d, stmt, fmt.Errorf("Error 1054 (42S22): Unknown column 'scope_kind'")) {
				t.Errorf("非「已经建过」的错误不许被吞: %q", ddlHead(stmt))
			}
		}
	}
	if indexes == 0 {
		t.Fatal("发货 DDL 里一条 CREATE INDEX 都没扫到，夹具或切分变了")
	}

	// 带说明注释的那一形态单独钉一次（上面扫到的第一条未必带注释）。
	commented := "-- 说明行\nCREATE INDEX idx_x ON t(a)"
	if firstLine(commented) == ddlHead(commented) {
		t.Errorf("ddlHead 应当跳过注释行，实际 %q", ddlHead(commented))
	}
	if !isIgnorableDDL(d, commented, dupErr) {
		t.Error("注释在前的 CREATE INDEX 仍要认出语句类型")
	}
	// 其它方言没有「吞 1061」这回事：PG 的 IF NOT EXISTS 自己就幂等。
	if isIgnorableDDL(PostgresDialect{}, commented, dupErr) {
		t.Error("只有 MySQL 走这条兜底")
	}
}

// DB 接口与 *Store 对得上：编译期断言在 iface.go，这里再跑一次 Open 走接口。
func TestOpenSatisfiesDB(t *testing.T) {
	s := openTestStore(t)
	var db DB = s
	if err := db.CreateUser("iface", TokenHash("sk")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetUser("iface"); err != nil {
		t.Fatal(err)
	}
}
