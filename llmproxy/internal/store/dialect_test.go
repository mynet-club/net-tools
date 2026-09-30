package store

import (
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
