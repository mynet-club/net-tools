package store

import (
	"database/sql"
	"fmt"
	"strings"
)

// Dialect 是数据库方言层：**只有这里**允许出现驱动差异。
//
// 业务 SQL 统一写 SQLite/MySQL 形状（`?` 占位符 + `ON CONFLICT`），
// 需要改写的方言（PostgreSQL 的 `$n`、MySQL 的 upsert）在 Rebind / Upsert 里完成。
// 这样 server / CLI / UI 认的是 Store 接口，不感知底下是 sqlite 还是 mysql。
type Dialect interface {
	// Name 是配置里的 driver 名：sqlite | mysql | postgres。
	Name() string
	// Driver 是 database/sql 的驱动注册名。
	Driver() string
	// Open 打开连接池并设好连接参数。pathOrDSN 对 sqlite 是文件路径，对其它是 DSN。
	Open(pathOrDSN string) (*sql.DB, error)
	// Rebind 把 `?` 占位符改写成该方言的形式（SQLite/MySQL 原样，PG 变 $1…）。
	Rebind(query string) string
	// Upsert 生成插入并按冲突键更新的语句。
	// insertCols 与 updateCols 是逗号分隔的列名；conflictCols 是冲突键。
	Upsert(table, insertCols, conflictCols, updateCols string) string
	// RewriteDDL 把以 SQLite 方言书写的 DDL 改写成该方言。
	// schema 常量只维护一份；差异（AUTOINCREMENT / REAL / INTEGER）在这里翻译。
	RewriteDDL(sql string) string
	// HasTable 报告表是否存在（迁移用）。
	HasTable(db *sql.DB, table string) (bool, error)
	// HasColumn 报告列是否存在（迁移用）。
	HasColumn(db *sql.DB, table, column string) (bool, error)
}

// SQLiteDialect 是默认实现：单文件、零依赖、CGO_ENABLED=0 可交叉编译。
type SQLiteDialect struct{}

func (SQLiteDialect) Name() string   { return "sqlite" }
func (SQLiteDialect) Driver() string { return "sqlite" }

func (SQLiteDialect) Open(pathOrDSN string) (*sql.DB, error) {
	if strings.TrimSpace(pathOrDSN) == "" {
		return nil, fmt.Errorf("数据库路径为空")
	}
	// 路径与连接参数拼装见 sqliteDSN()：busy_timeout / WAL / _txlock 必须走 DSN
	db, err := sql.Open("sqlite", sqliteDSN(pathOrDSN))
	if err != nil {
		return nil, fmt.Errorf("打开 SQLite 失败: %w", err)
	}
	// modernc.org/sqlite 是单连接语义，开多了反而容易 SQLITE_BUSY
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	return db, nil
}

func (SQLiteDialect) Rebind(query string) string { return query }

func (SQLiteDialect) RewriteDDL(sql string) string { return sql }

func (d SQLiteDialect) Upsert(table, insertCols, conflictCols, updateCols string) string {
	ph := placeholders(strings.Count(insertCols, ",") + 1)
	sets := make([]string, 0)
	for _, c := range strings.Split(updateCols, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		sets = append(sets, c+" = excluded."+c)
	}
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON CONFLICT(%s) DO UPDATE SET %s",
		table, insertCols, ph, conflictCols, strings.Join(sets, ", "))
}

func (SQLiteDialect) HasTable(db *sql.DB, table string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n)
	return n > 0, err
}

func (SQLiteDialect) HasColumn(db *sql.DB, table, column string) (bool, error) {
	var n int
	err := db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM pragma_table_info('%s') WHERE name = ?`, table), column).Scan(&n)
	return n > 0, err
}

// placeholders 生成 ?,?,? —— n 个。
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// rebindQuery 把 `?` 依次换成 $1, $2…（PostgreSQL）。字符串字面量里的 ? 不处理 ——
// 本包 SQL 不把 `?` 写进字面量，测试钉住了这一点。
func rebindDollar(query string) string {
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// dialectByName 按配置里的 driver 名取方言。
func dialectByName(name string) (Dialect, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "sqlite":
		return SQLiteDialect{}, nil
	case "mysql":
		return MySQLDialect{}, nil
	case "postgres", "postgresql", "pg":
		return PostgresDialect{}, nil
	default:
		return nil, fmt.Errorf("不支持的 database.driver %q（支持 sqlite / mysql / postgres）", name)
	}
}
