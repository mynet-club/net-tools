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
	if _, err := dialectByName("oracle"); err == nil {
		t.Error("未知驱动应当报错")
	} else if !strings.Contains(err.Error(), "sqlite") {
		t.Errorf("错误信息该列出支持的驱动: %v", err)
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
