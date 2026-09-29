package store

import (
	"database/sql"
	"fmt"
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

func (MySQLDialect) Rebind(query string) string { return query }

func (MySQLDialect) RewriteDDL(sql string) string {
	s := sql
	s = strings.ReplaceAll(s, "INTEGER PRIMARY KEY AUTOINCREMENT", "BIGINT AUTO_INCREMENT PRIMARY KEY")
	s = strings.ReplaceAll(s, "INTEGER", "BIGINT")
	s = strings.ReplaceAll(s, "REAL", "DOUBLE")
	// MySQL 的 TEXT 主键长度受限，KEY 列统一走 VARCHAR(191)（utf8mb4 下 764 字节 < 767）
	s = strings.ReplaceAll(s, "key   TEXT    PRIMARY KEY", "  `key` VARCHAR(191) PRIMARY KEY")
	s = strings.ReplaceAll(s, "key TEXT PRIMARY KEY", "`key` VARCHAR(191) PRIMARY KEY")
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
