package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// 范围迁移后的表形状必须同时满足两件事（手册 §2.7 规则 1/2、§2.8、§2.9）：
//  1. 归属只用 scope_kind + scope_id 两列表达，任何「拼起来的串」都不许留在库里 ——
//     拼接键一旦存在，改天就会有人拿它当主键，而分隔符两侧的内容是不可逆的；
//  2. 表里没有任何正文、提示词、凭证、个人信息类的列。§2.8 只允许摘要与版本号，
//     §2.9 的正文访问只存在于单次请求的内存里。
//
// 这两条都是「加了就再也删不掉」的那类错误：列一旦进表并被写过，删列就是删数据。
// 所以这里用会失败的断言钉住，而不是靠 review 时记得住。

// legacyScopeShapeDDL 是 2.x 多用户时代的三张表：归属用**单个拼接列**表达
// （provider_stats.scope 是裸用户名或空串，user_prices.scope 是 'default' 或 'user:<名>'）。
// 这正是 §2.7 要消灭的形状 —— 迁移后它必须彻底消失。
const legacyScopeShapeDDL = `
CREATE TABLE provider_stats (
  scope                TEXT    NOT NULL DEFAULT '',
  name                 TEXT    NOT NULL,
  enabled              INTEGER NOT NULL DEFAULT 1,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  unhealthy_until      INTEGER NOT NULL DEFAULT 0,
  last_error           TEXT,
  last_success_at      INTEGER,
  last_failure_at      INTEGER,
  total_requests       INTEGER NOT NULL DEFAULT 0,
  total_failures       INTEGER NOT NULL DEFAULT 0,
  updated_at           INTEGER NOT NULL,
  PRIMARY KEY (scope, name)
);
CREATE TABLE user_prices (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  scope           TEXT    NOT NULL DEFAULT 'default',
  model           TEXT    NOT NULL,
  currency        TEXT    NOT NULL DEFAULT 'CNY',
  in_miss         REAL    NOT NULL DEFAULT 0,
  in_hit          REAL    NOT NULL DEFAULT 0,
  in_write        REAL    NOT NULL DEFAULT 0,
  out             REAL    NOT NULL DEFAULT 0,
  reasoning_out   REAL    NOT NULL DEFAULT 0,
  per_request_fee REAL    NOT NULL DEFAULT 0,
  peak_hours      TEXT    NOT NULL DEFAULT '',
  off_peak_ratio  REAL,
  peak_tz         TEXT    NOT NULL DEFAULT '',
  valid_from      INTEGER NOT NULL,
  valid_to        INTEGER NOT NULL DEFAULT 0,
  note            TEXT    NOT NULL DEFAULT '',
  created_at      INTEGER NOT NULL
);
INSERT INTO provider_stats (scope, name, enabled, total_requests, total_failures, updated_at)
  VALUES ('', 'pool-a', 1, 40, 3, 1), ('alice', 'own-up', 1, 7, 0, 1);
INSERT INTO user_prices (scope, model, in_miss, out, valid_from, created_at)
  VALUES ('default', 'gpt-4o', 2.5, 10, 1, 1), ('user:alice', 'gpt-4o', 1.5, 6, 1, 1);
-- requests 也留一张：它没有拼接归属列，但有账单，是「迁移不许动明细行」最硬的样本。
CREATE TABLE requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, request_id TEXT NOT NULL,
  client_key_hash TEXT, model TEXT NOT NULL, provider TEXT, ok INTEGER NOT NULL DEFAULT 0,
  latency_ms INTEGER, prompt_tokens INTEGER, completion_tokens INTEGER, total_tokens INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0, error_type TEXT, error_msg TEXT
);
INSERT INTO requests (ts, request_id, model, provider, ok) VALUES (1, 'old-req', 'gpt-4o', 'pool-a', 1);
`

// newLegacyScopeDBFile 造一个 2.x 形状、带数据的库文件并返回路径。
//
// 只写这三张表：其余表由 Open() 的建表语句补齐（新表本来就空，不参与迁移判断），
// 手写全套 2.x DDL 迟早和 store.go 走样 —— 那时测到的就是这个 fixture 而不是迁移逻辑。
// provider_stats / user_prices / requests 三张必须是老形状：前两张带拼接列，
// 第三张是「迁移只补列、不动行」的样本。
func newLegacyScopeDBFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy-scope.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(legacyScopeShapeDDL); err != nil {
		t.Fatalf("造 2.x 库失败: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// columnNames 返回表的列名（顺序即建表顺序）。
func columnNames(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?) ORDER BY cid`, table)
	if err != nil {
		t.Fatalf("查 %s 的列失败: %v", table, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// forbiddenColumnFragments 是「一读就知道不该出现在持久层」的名字片段。
//
// 刻意不含 token / key / name 这种裸词：prompt_tokens、client_key_hash、
// provider_stats.name（供应商名，不是人名）都是合法列，把它们算进来只会让人
// 以后直接放宽整个检查。片段一律带下划线或够长，避免误伤又保住拦截面。
var forbiddenColumnFragments = []string{
	"content", "body", "message", "payload", "context",
	"email", "phone", "ssn", "id_card", "address",
	"authorization", "cookie", "api_key", "apikey", "secret", "password", "plaintext", "raw_",
}

// TestMigratedTablesCarryNoPayloadColumns 扫全部按范围键定的表：
// 既没有正文/凭证/个人信息列，也没有残留的拼接归属列。
func TestMigratedTablesCarryNoPayloadColumns(t *testing.T) {
	s := openTestStoreAt(t, newLegacyScopeDBFile(t))

	for _, table := range []string{
		"provider_stats", "user_prices", "requests", "audit_log", "scope_quota", "usage_scope_daily",
	} {
		cols := columnNames(t, s.db, table)
		if len(cols) == 0 {
			t.Fatalf("%s 没有列，fixture 或建表语句坏了", table)
		}
		for _, c := range cols {
			lower := strings.ToLower(c)
			for _, bad := range forbiddenColumnFragments {
				if strings.Contains(lower, bad) {
					t.Errorf("%s.%s：列名含 %q —— 正文与凭证不进库（§2.8/§2.9）", table, c, bad)
				}
			}
		}
		joined := strings.Join(cols, ",")
		if strings.Contains(joined, "scope_id") && strings.Contains(joined, "scope_kind") {
			continue
		}
		// 每张按范围键定的表都必须带**成对**的两列，缺一列就等于按范围查不出来。
		t.Errorf("%s 缺范围列对：只有 %s", table, joined)
	}
}

// TestMigratedSchemaHasNoConcatenatedScopeColumn 钉住「拼接形状彻底消失」。
func TestMigratedSchemaHasNoConcatenatedScopeColumn(t *testing.T) {
	s := openTestStoreAt(t, newLegacyScopeDBFile(t))

	for _, table := range []string{"provider_stats", "user_prices"} {
		for _, c := range columnNames(t, s.db, table) {
			if c == "scope" || c == "scope_key" {
				t.Errorf("%s.%s 还在：迁移必须把单列归属换成 (scope_kind, scope_id) 两列", table, c)
			}
		}
	}
}

// TestMigratedScopeValuesAreNotConcatenated 查数据面：老串拆开之后
// scope_id 必须正好是原值去掉前缀的那一段 —— 「user:alice」整串进 scope_id 也算泄漏拼接形状。
func TestMigratedScopeValuesAreNotConcatenated(t *testing.T) {
	s := openTestStoreAt(t, newLegacyScopeDBFile(t))

	// 全局池的供应商归 (system,'global')：空作用域不是「没有归属」，是「系统级」。
	buckets := []struct{ name, kind, id string }{
		{"pool-a", "system", "global"},
		{"own-up", "user", "alice"},
	}
	for _, b := range buckets {
		var kind, id string
		err := s.db.QueryRow(`SELECT scope_kind, scope_id FROM provider_stats WHERE name=?`, b.name).
			Scan(&kind, &id)
		if err != nil {
			t.Fatalf("查 provider_stats %q 失败: %v", b.name, err)
		}
		if kind != b.kind || id != b.id {
			t.Errorf("provider_stats[%s] = (%s,%s)，想要 (%s,%s)", b.name, kind, id, b.kind, b.id)
		}
		if strings.Contains(id, ":") {
			t.Errorf("provider_stats[%s].scope_id 含冒号，是拼接残留: %q", b.name, id)
		}
	}

	rows, err := s.db.Query(`SELECT scope_kind, scope_id FROM user_prices ORDER BY scope_kind, scope_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var kind, id string
		if err := rows.Scan(&kind, &id); err != nil {
			t.Fatal(err)
		}
		// 旧哨兵 'default' 必须换成 (system,'global')：留着它，「按范围查价」就会
		// 把系统价目当成某个叫 default 的主体。
		if id == "default" || id == "user" || strings.Contains(id, ":") {
			t.Errorf("user_prices.scope_id 还是拼接串或旧哨兵: %q (kind=%s)", id, kind)
		}
		got = append(got, kind+"|"+id)
	}
	if len(got) != 2 {
		t.Fatalf("user_prices 应当映射出 2 行，实际 %d", len(got))
	}
}
