package store

import (
	"database/sql"
	"fmt"
	"sort"
	"time"
)

// 消费模式（consumption）相关的表结构与读写。
//
// 迁移策略刻意分成两种：
//   - users 表早先版本就有数据，只能加列（SQLite 的 ALTER TABLE ADD COLUMN 是安全的）；
//   - usage_user_daily 的主键要从 (day,user,provider,model) 加上 system_paid，
//     主键变了只能重建表再搬数据（与 provider_stats 加 scope 时同一套做法）。
func migrateConsumption(db *sql.DB) error {
	if err := addColumnsIfMissing(db, "users", map[string]string{
		"mode":               "TEXT NOT NULL DEFAULT 'byo'",
		"quota_month_tokens": "INTEGER NOT NULL DEFAULT 0",
		"quota_month_cost":   "REAL NOT NULL DEFAULT 0",
		"rpm":                "INTEGER NOT NULL DEFAULT 0",
		"max_concurrent":     "INTEGER NOT NULL DEFAULT 0",
	}); err != nil {
		return err
	}
	return migrateUsageUserDaily(db)
}

func hasColumn(db *sql.DB, table, col string) (bool, error) {
	var n int
	// 表名是本包内的常量，不是外部输入
	q := fmt.Sprintf(`SELECT COUNT(*) FROM pragma_table_info('%s') WHERE name = ?`, table)
	if err := db.QueryRow(q, col).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// addColumnsIfMissing 按列名排序后逐个补齐，保证多次运行行为一致。
func addColumnsIfMissing(db *sql.DB, table string, cols map[string]string) error {
	names := make([]string, 0, len(cols))
	for name := range cols {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		ok, err := hasColumn(db, table, name)
		if err != nil {
			return err
		}
		if ok {
			continue
		}
		q := fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, name, cols[name])
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("给 %s 增加列 %s 失败: %w", table, name, err)
		}
	}
	return nil
}

func migrateUsageUserDaily(db *sql.DB) error {
	ok, err := hasColumn(db, "usage_user_daily", "system_paid")
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// 老数据全是 byo（当时还没有消费模式），所以 system_paid 填 0；
	// 缓存拆分没记过，按「输入全部未命中」搬过去 —— 这是偏保守的口径，不会漏收。
	// upstream_model 老表没有，用下游名顶上（同名直通时两者本来就相同）。
	for _, q := range []string{
		`ALTER TABLE usage_user_daily RENAME TO _usage_user_daily_legacy`,
		usageUserDailyDDL,
		`INSERT INTO usage_user_daily (
		   day, user_name, provider, model, upstream_model, system_paid,
		   requests, ok, failed,
		   prompt_tokens, cache_hit_tokens, cache_miss_tokens, completion_tokens, total_tokens, latency_sum_ms)
		 SELECT day, user_name, provider, model, model, 0,
		        requests, ok, failed,
		        prompt_tokens, 0, prompt_tokens, completion_tokens, total_tokens, latency_sum_ms
		 FROM _usage_user_daily_legacy`,
		`DROP TABLE _usage_user_daily_legacy`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("迁移 usage_user_daily 失败: %w", err)
		}
	}
	return tx.Commit()
}

// ------------------------------------------------------------------ 设置项

// SetUserMode 切换下游模式（byo / consumption）。
func (s *Store) SetUserMode(name, mode string) error {
	return s.userUpdate("mode = ?", []any{mode}, name)
}

// SetUserQuota 设置月度配额；0 表示不限。
func (s *Store) SetUserQuota(name string, tokens int64, cost float64) error {
	return s.userUpdate("quota_month_tokens = ?, quota_month_cost = ?", []any{tokens, cost}, name)
}

// SetUserLimits 设置 RPM 与并发上限；0 表示不限。
func (s *Store) SetUserLimits(name string, rpm, maxConcurrent int) error {
	return s.userUpdate("rpm = ?, max_concurrent = ?", []any{rpm, maxConcurrent}, name)
}

// ------------------------------------------------------------------ 模型映射

// ListUserModels 返回某用户的模型映射（按模型名排序）。
func (s *Store) ListUserModels(userName string) ([]UserModel, error) {
	rows, err := s.db.Query(`
SELECT user_name, model, upstream, provider, enabled, created_at, updated_at
FROM user_models WHERE user_name = ? ORDER BY model`, userName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanUserModels(rows)
}

// ListAllUserModels 一次取出全部用户的模型映射，供服务端构建快照用。
func (s *Store) ListAllUserModels() (map[string][]UserModel, error) {
	rows, err := s.db.Query(`
SELECT user_name, model, upstream, provider, enabled, created_at, updated_at
FROM user_models ORDER BY user_name, model`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list, err := scanUserModels(rows)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]UserModel, len(list))
	for _, m := range list {
		out[m.UserName] = append(out[m.UserName], m)
	}
	return out, nil
}

func scanUserModels(rows *sql.Rows) ([]UserModel, error) {
	out := []UserModel{}
	for rows.Next() {
		var m UserModel
		var enabled, created, updated int64
		if err := rows.Scan(&m.UserName, &m.Model, &m.Upstream, &m.Provider,
			&enabled, &created, &updated); err != nil {
			return nil, err
		}
		m.Enabled = enabled != 0
		m.CreatedAt = time.UnixMilli(created)
		m.UpdatedAt = time.UnixMilli(updated)
		out = append(out, m)
	}
	return out, rows.Err()
}

// UpsertUserModel 新增或覆盖一条模型映射。
func (s *Store) UpsertUserModel(m UserModel) error {
	if m.Model == "" {
		return fmt.Errorf("模型名不能为空")
	}
	enabled := 0
	if m.Enabled {
		enabled = 1
	}
	now := time.Now().UnixMilli()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`
INSERT INTO user_models (user_name, model, upstream, provider, enabled, created_at, updated_at)
VALUES (?,?,?,?,?,?,?)
ON CONFLICT(user_name, model) DO UPDATE SET
  upstream   = excluded.upstream,
  provider   = excluded.provider,
  enabled    = excluded.enabled,
  updated_at = excluded.updated_at`,
		m.UserName, m.Model, m.Upstream, m.Provider, enabled, now, now); err != nil {
		return fmt.Errorf("写入 user_models 失败: %w", err)
	}
	if err := bumpRevision(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteUserModel 删除一条模型映射。
func (s *Store) DeleteUserModel(userName, model string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec(`DELETE FROM user_models WHERE user_name = ? AND model = ?`, userName, model)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		if err := bumpRevision(tx); err != nil {
			return false, err
		}
	}
	return n > 0, tx.Commit()
}

// ------------------------------------------------------------------ 系统付费用量

// SystemUsage 是某用户一段时间内**由系统上游承接**的用量。
// 只有这部分进入配额与金额估算 —— 用户用自己的上游时，账单不是网关主人的。
type SystemUsage struct {
	Requests         int64
	OK               int64
	Failed           int64
	PromptTokens     int64
	CacheHitTokens   int64
	CacheMissTokens  int64
	CompletionTokens int64
	TotalTokens      int64
}

// SystemUsageSince 汇总 userName 从 since 起的系统付费用量。
func (s *Store) SystemUsageSince(userName string, since time.Time) (SystemUsage, error) {
	var out SystemUsage
	err := s.db.QueryRow(`
SELECT COALESCE(SUM(requests),0), COALESCE(SUM(ok),0), COALESCE(SUM(failed),0),
       COALESCE(SUM(prompt_tokens),0), COALESCE(SUM(cache_hit_tokens),0),
       COALESCE(SUM(cache_miss_tokens),0), COALESCE(SUM(completion_tokens),0),
       COALESCE(SUM(total_tokens),0)
FROM usage_user_daily
WHERE user_name = ? AND system_paid = 1 AND day >= ?`,
		userName, since.Format("2006-01-02")).Scan(
		&out.Requests, &out.OK, &out.Failed,
		&out.PromptTokens, &out.CacheHitTokens, &out.CacheMissTokens,
		&out.CompletionTokens, &out.TotalTokens)
	return out, err
}

// SystemUsageRowsSince 按「上游 + 上游模型」拆开返回系统付费用量。
//
// 内存计数在进程重启后要从库里重建金额，而金额必须按每个上游模型各自的单价算，
// 所以这里不能只返回一个总数，得带上 upstream_model 与缓存拆分。
func (s *Store) SystemUsageRowsSince(userName string, since time.Time) ([]UsageRow, error) {
	rows, err := s.db.Query(`
SELECT '', provider, model, upstream_model, system_paid,
       SUM(requests), SUM(ok), SUM(failed),
       SUM(prompt_tokens), SUM(completion_tokens), SUM(total_tokens),
       0,
       SUM(cache_hit_tokens), SUM(cache_miss_tokens)
FROM usage_user_daily
WHERE user_name = ? AND system_paid = 1 AND day >= ?
GROUP BY provider, model, upstream_model`, userName, since.Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []UsageRow{}
	for rows.Next() {
		var r UsageRow
		var systemPaid int64
		if err := rows.Scan(&r.Day, &r.Provider, &r.Model, &r.UpstreamModel, &systemPaid,
			&r.Requests, &r.OK, &r.Failed,
			&r.PromptTokens, &r.CompletionTokens, &r.TotalTokens, &r.AvgLatencyMs,
			&r.CacheHitTokens, &r.CacheMissTokens); err != nil {
			return nil, err
		}
		r.SystemPaid = systemPaid != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// MonthStart 返回 t 所在自然月的零点（按本地时区）。
func MonthStart(t time.Time) time.Time {
	y, m, _ := t.Date()
	return time.Date(y, m, 1, 0, 0, 0, 0, t.Location())
}
