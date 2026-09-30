package store

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresDialect：占位符是 $1…$n（Rebind 改写），upsert 与 SQLite 同形。
// 驱动用 pgx 的 database/sql 包装（纯 Go，CGO_ENABLED=0 可交叉编译）。
type PostgresDialect struct{}

func (PostgresDialect) Name() string   { return "postgres" }
func (PostgresDialect) Driver() string { return "pgx" }

func (PostgresDialect) Open(dsn string) (*sql.DB, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("database.dsn 为空（postgres 需要 postgres://user:pass@host:5432/db 形式）")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开 PostgreSQL 失败: %w", err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	return db, nil
}

func (PostgresDialect) Rebind(query string) string { return rebindDollar(query) }

func (PostgresDialect) RewriteDDL(sql string) string {
	s := sql
	s = strings.ReplaceAll(s, "INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
	s = strings.ReplaceAll(s, "INTEGER", "BIGINT")
	s = strings.ReplaceAll(s, "REAL", "DOUBLE PRECISION")
	s = strings.ReplaceAll(s, "BLOB", "BYTEA")
	return s
}

func (d PostgresDialect) Upsert(table, insertCols, conflictCols, updateCols string) string {
	ph := placeholders(strings.Count(insertCols, ",") + 1)
	// PG 的 upsert 与 SQLite 同形，但占位符要换成 $n
	sets := make([]string, 0)
	for _, c := range strings.Split(updateCols, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		sets = append(sets, c+" = excluded."+c)
	}
	q := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT(%s) DO UPDATE SET %s",
		table, insertCols, ph, conflictCols, strings.Join(sets, ", "))
	return d.Rebind(q)
}

func (PostgresDialect) HasTable(db *sql.DB, table string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema = current_schema() AND table_name = $1`, table).Scan(&n)
	return n > 0, err
}

func (PostgresDialect) HasColumn(db *sql.DB, table, column string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2`,
		table, column).Scan(&n)
	return n > 0, err
}
