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
//
// 这里只补 mode。**不补** quota_month_tokens / quota_month_cost / rpm / max_concurrent：
// 那四列是 2.x 的配额存放处，3.0 的读写全在 scope_quota（§2.7 规则 2）。继续在这里补列，
// 等于每次启动都给「第二份配额真相」补一次骨血 —— 老库里已经有的那几列由一次性迁移
// 回填成配额行后删掉（scope_migration.go 的 retireUsersQuotaColumns），新库里它们压根不出现。
func migrateConsumption(db *sql.DB, d Dialect) error {
	if err := addColumnsIfMissing(db, d, "users", map[string]string{
		"mode": "TEXT NOT NULL DEFAULT 'byo'",
	}); err != nil {
		return err
	}
	return migrateUsageUserDaily(db, d)
}

func hasColumn(db *sql.DB, d Dialect, table, col string) (bool, error) {
	return d.HasColumn(db, table, col)
}

// addColumnsIfMissing 按列名排序后逐个补齐，保证多次运行行为一致。
// 列类型以 SQLite 方言书写，ALTER 前经 RewriteDDL 翻译。
func addColumnsIfMissing(db *sql.DB, d Dialect, table string, cols map[string]string) error {
	names := make([]string, 0, len(cols))
	for name := range cols {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		ok, err := hasColumn(db, d, table, name)
		if err != nil {
			return err
		}
		if ok {
			continue
		}
		typ := d.RewriteDDL(cols[name])
		q := d.Rebind(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, name, typ))
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("给 %s 增加列 %s 失败: %w", table, name, err)
		}
	}
	return nil
}

func migrateUsageUserDaily(db *sql.DB, d Dialect) error {
	ok, err := hasColumn(db, d, "usage_user_daily", "system_paid")
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
		d.RewriteDDL(usageUserDailyDDL),
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
		if _, err := tx.Exec(d.Rebind(q)); err != nil {
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

// 配额与限流**不在这里**：§2.7 规则 2 把它们挪到了 scope_quota（按范围），
// 写侧是 Store.SetScopeQuota / PatchScopeQuota，读侧是 GetScopeQuota / ListScopeQuotas。
// 2.x 那对按用户名的 SetUserQuota / SetUserLimits 与「users → scope_quota」的镜像写
// （syncScopeQuotaFromUsers）已经随规则 8 删除：双写的代价不是多写一次库，
// 而是两张表可以各持一半真值还不报错 —— 配额决定的是「这个月还花不花得起网关的钱」，
// 两套账的差值最终都变成用户账单上的争议行。

// ------------------------------------------------------------------ 模型映射

// ListUserModels 返回某用户的模型映射（按模型名排序）。
func (s *Store) ListUserModels(userName string) ([]UserModel, error) {
	rows, err := s.query(`
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
	rows, err := s.query(`
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

	if _, err := txExec(tx, s.dialect, `
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
	if err := bumpRevision(tx, s.dialect); err != nil {
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

	res, err := txExec(tx, s.dialect, `DELETE FROM user_models WHERE user_name = ? AND model = ?`, userName, model)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		if err := bumpRevision(tx, s.dialect); err != nil {
			return false, err
		}
	}
	return n > 0, tx.Commit()
}

// ClearUserModels 清空某用户的全部模型映射。
// 消费模式下「没有映射」= 继承系统池声明的全部模型，所以这是「放开限制」的动作。
func (s *Store) ClearUserModels(userName string) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := txExec(tx, s.dialect, `DELETE FROM user_models WHERE user_name = ?`, userName)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		if err := bumpRevision(tx, s.dialect); err != nil {
			return 0, err
		}
	}
	return n, tx.Commit()
}

// ------------------------------------------------------------------ 系统付费用量
//
// 2.x 这里还有两条按 user_name 读 usage_user_daily 的方法（SystemUsageSince /
// SystemUsageRowsSince），已随 §2.7 规则 8 删除：读侧只剩 scope_store.go 里按
// (scope_kind, scope_id) 的那一组 —— ScopeSystemUsage 给总数，
// ScopeSystemUsageRows 给「按上游 + 上游模型」拆开的行。

// SystemUsage 是一段区间内**由系统上游承接**的用量。
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

// MonthStart 返回 t 所在自然月的零点（按本地时区）。
func MonthStart(t time.Time) time.Time {
	y, m, _ := t.Date()
	return time.Date(y, m, 1, 0, 0, 0, 0, t.Location())
}
