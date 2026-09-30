package store

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

// MySQLDialect：占位符与 SQLite 同为 `?`；upsert 用 ON DUPLICATE KEY UPDATE。
// 连接参数（超时、charset）写在 DSN 里，这里不再拼 PRAGMA 一类的东西。
type MySQLDialect struct{}

func (MySQLDialect) Name() string   { return "mysql" }
func (MySQLDialect) Driver() string { return "mysql" }

func (MySQLDialect) Open(dsn string) (*sql.DB, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("database.dsn 为空（mysql 需要 user:pass@tcp(host:3306)/dbname 形式）")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开 MySQL 失败: %w", err)
	}
	// MySQL 是真连接池：限住上限，避免压测把 max_connections 打满
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	return db, nil
}

// mysqlReserved 会被 MySQL 语法当关键字的列名。引用起来才能当标识符。
// 只在 SQL 里替换，Go 代码中的同名变量不受影响。
var mysqlReserved = []string{"out", "key", "status", "day", "value"}

func (MySQLDialect) Rebind(query string) string {
	return mysqlRewriteUpsert(quoteMySQLIdents(query))
}

// quoteMySQLIdents 给保留字列名加反引号。用词边界，免得误伤 reasoning_out / timeout。
func quoteMySQLIdents(q string) string {
	for _, col := range mysqlReserved {
		re := regexp.MustCompile(`(^|[(,\s])` + col + `($|[,\s)=])`)
		q = re.ReplaceAllString(q, "${1}`"+col+"`${2}")
	}
	return q
}

// mysqlRewriteUpsert 把 SQLite/PG 形状的 upsert 翻成 MySQL：
//
//	ON CONFLICT(a,b) DO UPDATE SET x = excluded.x, y = y + 1
//	→ ON DUPLICATE KEY UPDATE x = VALUES(x), y = y + 1
//
// 冲突键由表上的 UNIQUE/PRIMARY KEY 决定，MySQL 指定不了键列表。
// SET 子句里的 `excluded.col` 换成 `VALUES(col)`；其余表达式原样保留。
var (
	reConflict = regexp.MustCompile(`ON CONFLICT\([^)]*\) DO UPDATE SET\s*`)
	reExcluded = regexp.MustCompile(`excluded\.(\w+)`)
)

func mysqlRewriteUpsert(q string) string {
	q = reConflict.ReplaceAllString(q, "ON DUPLICATE KEY UPDATE ")
	q = reExcluded.ReplaceAllString(q, "VALUES($1)")
	return q
}

func (MySQLDialect) RewriteDDL(sql string) string {
	s := sql
	s = strings.ReplaceAll(s, "INTEGER PRIMARY KEY AUTOINCREMENT", "BIGINT AUTO_INCREMENT PRIMARY KEY")
	s = strings.ReplaceAll(s, "INTEGER", "BIGINT")
	s = strings.ReplaceAll(s, "REAL", "DOUBLE")
	// MySQL 不允许 TEXT 列带 DEFAULT，且 utf8mb4 下索引列安全宽度是 191 字符。
	// 标识符/币种等短字段 → VARCHAR(191)（覆盖所有 TEXT 主键）；错误正文等长字段单独放宽。
	for _, col := range []string{"error_msg", "last_error", "note"} {
		re := regexp.MustCompile(`(` + col + `\s+)TEXT\b`)
		s = re.ReplaceAllString(s, `${1}VARCHAR(1024)`)
	}
	// MySQL 不允许 TEXT 列带 DEFAULT，且 utf8mb4 下索引列安全宽度受限。
	// 复合主键最多 6 列，VARCHAR(128)×6×4=3072 刚好压线 —— 再宽就要撞
	// max key length is 3072 bytes（usage_user_daily 的主键有 5 个字符串列）。
	for _, col := range []string{"error_msg", "last_error", "note"} {
		re := regexp.MustCompile(`(` + col + `\s+)TEXT\b`)
		s = re.ReplaceAllString(s, `${1}VARCHAR(1024)`)
	}
	s = regexp.MustCompile(`\bTEXT\b`).ReplaceAllString(s, "VARCHAR(128)")
	// meta.key 是 MySQL 保留字，列名要加反引号（只匹配行首的列定义）
	s = regexp.MustCompile(`(?m)^(\s*)key(\s+)`).ReplaceAllString(s, "${1}`key`${2}")
	// MySQL 没有 CREATE INDEX IF NOT EXISTS；去掉标记，重复建索引由调用方忽略 1061
	s = strings.ReplaceAll(s, "CREATE INDEX IF NOT EXISTS ", "CREATE INDEX ")
	return s
}

func (d MySQLDialect) Upsert(table, insertCols, conflictCols, updateCols string) string {
	ph := placeholders(strings.Count(insertCols, ",") + 1)
	sets := make([]string, 0)
	for _, c := range strings.Split(updateCols, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		sets = append(sets, c+" = VALUES("+c+")")
	}
	// conflictCols 由唯一键保证（表 DDL 里要有 UNIQUE/PRIMARY KEY），
	// 这里不写 ON DUPLICATE KEY 后面的键列表 —— MySQL 语法不支持指定。
	_ = conflictCols
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON DUPLICATE KEY UPDATE %s",
		table, insertCols, ph, strings.Join(sets, ", "))
}

func (MySQLDialect) HasTable(db *sql.DB, table string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema = DATABASE() AND table_name = ?`, table).Scan(&n)
	return n > 0, err
}

func (MySQLDialect) HasColumn(db *sql.DB, table, column string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?`, table, column).Scan(&n)
	return n > 0, err
}
