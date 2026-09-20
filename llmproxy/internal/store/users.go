package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// 多用户（中转器）模式的表结构。
//
// 设计取舍：
//   - 下游 token 只存 SHA-256，明文只在创建/轮换时返回一次给你
//   - 上游 api_key 存 AES-GCM 密文（密钥在 master.key），库里没有明文
//   - 用户用量单独一张表，不动已有的 usage_daily（避免改主键、避免迁移风险）
const userSchema = `
CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT    NOT NULL UNIQUE,
  token_hash TEXT    NOT NULL UNIQUE,
  enabled    INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  -- 下游模式：byo = 自带自己的上游；consumption = 允许消费系统上游（受白名单与配额约束）
  mode               TEXT    NOT NULL DEFAULT 'byo',
  quota_month_tokens INTEGER NOT NULL DEFAULT 0,  -- 0 = 不限
  quota_month_cost   REAL    NOT NULL DEFAULT 0,  -- 0 = 不限
  rpm                INTEGER NOT NULL DEFAULT 0,  -- 0 = 不限
  max_concurrent     INTEGER NOT NULL DEFAULT 0   -- 0 = 不限
);

-- user_models 只对 consumption 用户有意义：既是「能不能用这个模型」的白名单，
-- 也是「下游名 → 系统模型名」的映射表。没在这张表里的模型一律拒绝。
CREATE TABLE IF NOT EXISTS user_models (
  user_name  TEXT    NOT NULL,
  model      TEXT    NOT NULL,                     -- 下游请求里的模型名
  upstream   TEXT    NOT NULL DEFAULT '',          -- 系统里真实模型名，空 = 同名
  provider   TEXT    NOT NULL DEFAULT '',          -- 限定走哪个系统供应商，空 = 系统池里按权重选
  enabled    INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_name, model)
);

CREATE TABLE IF NOT EXISTS user_providers (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_name   TEXT    NOT NULL,
  name        TEXT    NOT NULL,
  base_url    TEXT    NOT NULL,
  api_key_enc BLOB,
  weight      REAL    NOT NULL DEFAULT 1,
  enabled     INTEGER NOT NULL DEFAULT 1,
  timeout_ms  INTEGER NOT NULL DEFAULT 120000,
  proxy       TEXT    NOT NULL DEFAULT '',
  models_json TEXT    NOT NULL DEFAULT '[]',
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  UNIQUE(user_name, name)
);
CREATE INDEX IF NOT EXISTS idx_user_providers_user ON user_providers(user_name);

CREATE TABLE IF NOT EXISTS usage_user_daily (
` + usageUserDailyBody + `
);
`

// usageUserDailyBody 单独抽出来：迁移重建表时要复用同一份定义，避免两处走样。
//
// upstream_model 单独存一列是刻意的：单价表按**上游模型名**计价（供应商真正收钱的那个名字），
// 而消费模式允许每个用户把下游名映射到不同的上游模型，只存下游名会让定价算错。
const usageUserDailyBody = `  day               TEXT    NOT NULL,
  user_name         TEXT    NOT NULL,
  provider          TEXT    NOT NULL,
  model             TEXT    NOT NULL,
  upstream_model    TEXT    NOT NULL DEFAULT '',
  -- 1 = 这次消耗由网关（系统上游）付费，要计入该用户的配额与金额
  system_paid       INTEGER NOT NULL DEFAULT 0,
  requests          INTEGER NOT NULL DEFAULT 0,
  ok                INTEGER NOT NULL DEFAULT 0,
  failed            INTEGER NOT NULL DEFAULT 0,
  prompt_tokens     INTEGER NOT NULL DEFAULT 0,
  cache_hit_tokens  INTEGER NOT NULL DEFAULT 0,
  cache_miss_tokens INTEGER NOT NULL DEFAULT 0,
  completion_tokens INTEGER NOT NULL DEFAULT 0,
  total_tokens      INTEGER NOT NULL DEFAULT 0,
  latency_sum_ms    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, user_name, provider, model, upstream_model, system_paid)`

// usageUserDailyDDL 是重建该表时用的完整语句。
const usageUserDailyDDL = `CREATE TABLE IF NOT EXISTS usage_user_daily (
` + usageUserDailyBody + `
)`

// User 是一个下游用户。库里只有 token 的摘要，没有明文。
type User struct {
	Name      string
	TokenHash string
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time

	// Mode 决定这个用户能不能用系统上游：byo（默认）或 consumption。
	Mode string
	// 配额与限流，0 一律表示「不限」。
	QuotaMonthTokens int64
	QuotaMonthCost   float64
	RPM              int
	MaxConcurrent    int
}

// IsConsumption 报告该用户是否为消费模式。
func (u *User) IsConsumption() bool { return u != nil && u.Mode == ModeConsumption }

const (
	// ModeBYO 自带上游：只能用 user_providers 里的上游，网关不替他付上游的钱。
	ModeBYO = "byo"
	// ModeConsumption 消费系统上游：受 user_models 白名单与配额约束，账单归网关主人。
	ModeConsumption = "consumption"
)

// UserModel 是 consumption 用户的一条模型映射（同时就是白名单条目）。
type UserModel struct {
	UserName  string
	Model     string // 下游请求里的模型名
	Upstream  string // 系统里真实模型名，空 = 同名
	Provider  string // 限定系统供应商，空 = 系统池按权重选
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// UserProvider 是用户自己配置的上游。APIKeyEnc 是 AES-GCM 密文（nonce||密文）。
type UserProvider struct {
	UserName   string
	Name       string
	BaseURL    string
	APIKeyEnc  []byte
	Weight     float64
	Enabled    bool
	TimeoutMs  int
	Proxy      string
	ModelsJSON string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// UserProviderStat 是某用户某上游的累计请求数（来自 provider_stats）。
type UserProviderStat struct {
	Name             string
	ConsecutiveFails int
	UnhealthyUntil   time.Time
	LastError        string
	TotalRequests    int64
	TotalFailures    int64
}

// ------------------------------------------------------------------ token

// NewToken 生成一个下游 token，形如 sk-<32 位十六进制>。
func NewToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("生成 token 失败: %w", err)
	}
	return "sk-" + hex.EncodeToString(b), nil
}

// TokenHash 计算下游 token 的摘要，用于在库里查找用户。
//
// 这里的摘要存的是完整值（不像 requests.client_key_hash 只存前 6 字节）：
// 因为要用它做等值查找，而 SHA-256 本身不可逆，泄露摘要不等于泄露 token。
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ------------------------------------------------------------------ 用户

// CreateUser 建一个用户。tokenHash 由调用方用 TokenHash 算好。
func (s *Store) CreateUser(name, tokenHash string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("用户名不能为空")
	}
	if strings.ContainsAny(name, "/ \t\n") {
		return fmt.Errorf("用户名 %q 不能包含斜杠或空白", name)
	}
	if tokenHash == "" {
		return errors.New("token 摘要不能为空")
	}
	now := time.Now().UnixMilli()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(
		`INSERT INTO users (name, token_hash, enabled, created_at, updated_at) VALUES (?,?,1,?,?)`,
		name, tokenHash, now, now); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("用户 %q 已存在", name)
		}
		return fmt.Errorf("创建用户失败: %w", err)
	}
	if err := bumpRevision(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// userColumns 与 scanUser 成对维护：列顺序改一处必须改另一处。
const userColumns = `name, token_hash, enabled, created_at, updated_at,
       mode, quota_month_tokens, quota_month_cost, rpm, max_concurrent`

func scanUser(sc interface{ Scan(...any) error }) (User, error) {
	var u User
	var enabled, created, updated int64
	err := sc.Scan(&u.Name, &u.TokenHash, &enabled, &created, &updated,
		&u.Mode, &u.QuotaMonthTokens, &u.QuotaMonthCost, &u.RPM, &u.MaxConcurrent)
	if err != nil {
		return u, err
	}
	u.Enabled = enabled != 0
	u.CreatedAt = time.UnixMilli(created)
	u.UpdatedAt = time.UnixMilli(updated)
	return u, nil
}

// ListUsers 按名字返回全部用户（含已禁用的）。
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT ` + userColumns + ` FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// GetUser 按名字查用户；不存在返回 (nil, nil)。
func (s *Store) GetUser(name string) (*User, error) {
	return s.getUser(`WHERE name = ?`, name)
}

// GetUserByTokenHash 按 token 摘要查用户；不存在返回 (nil, nil)。
func (s *Store) GetUserByTokenHash(hash string) (*User, error) {
	return s.getUser(`WHERE token_hash = ?`, hash)
}

func (s *Store) getUser(where string, arg any) (*User, error) {
	row := s.db.QueryRow(`SELECT `+userColumns+` FROM users `+where, arg)
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

// SetUserEnabled 启用/禁用一个用户。
func (s *Store) SetUserEnabled(name string, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	return s.userUpdate("enabled = ?", []any{v}, name)
}

// SetUserToken 换 token（轮换）。旧 token 立即失效。
func (s *Store) SetUserToken(name, tokenHash string) error {
	if tokenHash == "" {
		return errors.New("token 摘要不能为空")
	}
	err := s.userUpdate("token_hash = ?", []any{tokenHash}, name)
	if isUniqueViolation(err) {
		return errors.New("该 token 已属于其他用户")
	}
	return err
}

// userUpdate 执行「SET <setClause>, updated_at = now WHERE name = ?」并推进修订号。
func (s *Store) userUpdate(setClause string, setArgs []any, name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	args := append(append([]any{}, setArgs...), time.Now().UnixMilli(), name)
	res, err := tx.Exec(`UPDATE users SET `+setClause+`, updated_at = ? WHERE name = ?`, args...)
	if err != nil {
		return fmt.Errorf("更新用户失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("用户 %q 不存在", name)
	}
	if err := bumpRevision(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteUser 删除用户及其全部上游配置。
func (s *Store) DeleteUser(name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM user_providers WHERE user_name = ?`, name); err != nil {
		return err
	}
	res, err := tx.Exec(`DELETE FROM users WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("用户 %q 不存在", name)
	}
	if err := bumpRevision(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// ------------------------------------------------------------------ 用户上游

// UpsertUserProvider 新增或覆盖某个用户的一个上游（按 (用户, 名字) 唯一）。
func (s *Store) UpsertUserProvider(p UserProvider) error {
	if strings.TrimSpace(p.UserName) == "" || strings.TrimSpace(p.Name) == "" {
		return errors.New("用户名与上游名都不能为空")
	}
	if p.TimeoutMs <= 0 {
		p.TimeoutMs = 120000
	}
	if p.Weight <= 0 {
		p.Weight = 1
	}
	if p.ModelsJSON == "" {
		p.ModelsJSON = "[]"
	}
	now := time.Now().UnixMilli()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE name = ?`, p.UserName).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return fmt.Errorf("用户 %q 不存在", p.UserName)
	}

	enabled := 0
	if p.Enabled {
		enabled = 1
	}
	if _, err := tx.Exec(`
INSERT INTO user_providers (
  user_name, name, base_url, api_key_enc, weight, enabled, timeout_ms, proxy, models_json,
  created_at, updated_at
) VALUES (?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(user_name, name) DO UPDATE SET
  base_url    = excluded.base_url,
  api_key_enc = excluded.api_key_enc,
  weight      = excluded.weight,
  enabled     = excluded.enabled,
  timeout_ms  = excluded.timeout_ms,
  proxy       = excluded.proxy,
  models_json = excluded.models_json,
  updated_at  = excluded.updated_at`,
		p.UserName, p.Name, p.BaseURL, p.APIKeyEnc, p.Weight, enabled, p.TimeoutMs, p.Proxy, p.ModelsJSON,
		now, now); err != nil {
		return fmt.Errorf("保存上游失败: %w", err)
	}
	if err := bumpRevision(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// ListUserProviders 返回某用户的全部上游，按名字排序。
func (s *Store) ListUserProviders(userName string) ([]UserProvider, error) {
	rows, err := s.db.Query(`
SELECT user_name, name, base_url, api_key_enc, weight, enabled, timeout_ms, proxy, models_json,
       created_at, updated_at
FROM user_providers WHERE user_name = ? ORDER BY name`, userName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanUserProviders(rows)
}

// ListAllUserProviders 一次取回所有用户的上游，供服务端构建快照用。
func (s *Store) ListAllUserProviders() (map[string][]UserProvider, error) {
	rows, err := s.db.Query(`
SELECT user_name, name, base_url, api_key_enc, weight, enabled, timeout_ms, proxy, models_json,
       created_at, updated_at
FROM user_providers ORDER BY user_name, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	all, err := scanUserProviders(rows)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]UserProvider, len(all))
	for _, p := range all {
		out[p.UserName] = append(out[p.UserName], p)
	}
	return out, nil
}

func scanUserProviders(rows *sql.Rows) ([]UserProvider, error) {
	out := []UserProvider{}
	for rows.Next() {
		var p UserProvider
		var enabled, created, updated int64
		if err := rows.Scan(&p.UserName, &p.Name, &p.BaseURL, &p.APIKeyEnc, &p.Weight, &enabled,
			&p.TimeoutMs, &p.Proxy, &p.ModelsJSON, &created, &updated); err != nil {
			return nil, err
		}
		p.Enabled = enabled != 0
		p.CreatedAt = time.UnixMilli(created)
		p.UpdatedAt = time.UnixMilli(updated)
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteUserProvider 删除某用户的一个上游。返回是否确实删掉了。
func (s *Store) DeleteUserProvider(userName, name string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec(`DELETE FROM user_providers WHERE user_name = ? AND name = ?`, userName, name)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		if err := bumpRevision(tx); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

// ------------------------------------------------------------------ 按用户统计

// UsageByUser 查询某个用户的按日、按上游、按模型消耗。
// since 为零值表示不限起始日期。
func (s *Store) UsageByUser(since time.Time, userName string) ([]UsageRow, error) {
	where := `WHERE user_name = ?`
	args := []any{userName}
	if !since.IsZero() {
		where += ` AND day >= ?`
		args = append(args, since.Format("2006-01-02"))
	}
	rows, err := s.db.Query(`
SELECT day, provider, model, upstream_model, system_paid,
       SUM(requests), SUM(ok), SUM(failed),
       SUM(prompt_tokens), SUM(completion_tokens), SUM(total_tokens),
       CASE WHEN SUM(requests)>0 THEN CAST(SUM(latency_sum_ms) AS REAL)/SUM(requests) ELSE 0 END,
       SUM(cache_hit_tokens), SUM(cache_miss_tokens)
FROM usage_user_daily `+where+`
GROUP BY day, provider, model, upstream_model, system_paid
ORDER BY day DESC, model
LIMIT 500`, args...)
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

// UserTotals 是某个用户的累计消耗。
//
// 字段名与 JSON 键刻意不同：这套接口对外一律 snake_case，
// 且输出 token 数在别处叫 completion_tokens，这里跟着叫，免得同一个人面对两套名字。
type UserTotals struct {
	Requests     int64  `json:"requests"`
	OK           int64  `json:"ok"`
	Failed       int64  `json:"failed"`
	TotalTokens  int64  `json:"total_tokens"`
	PromptTokens int64  `json:"prompt_tokens"`
	OutputTokens int64  `json:"completion_tokens"`
	FirstDay     string `json:"first_day"`
	LastDay      string `json:"last_day"`
}

// TotalByUser 汇总某用户从 since 起的累计消耗。
func (s *Store) TotalByUser(since time.Time, userName string) (UserTotals, error) {
	where := `WHERE user_name = ?`
	args := []any{userName}
	if !since.IsZero() {
		where += ` AND day >= ?`
		args = append(args, since.Format("2006-01-02"))
	}
	var out UserTotals
	var first, last sql.NullString
	err := s.db.QueryRow(`
SELECT COALESCE(SUM(requests),0), COALESCE(SUM(ok),0), COALESCE(SUM(failed),0),
       COALESCE(SUM(total_tokens),0), COALESCE(SUM(prompt_tokens),0), COALESCE(SUM(completion_tokens),0),
       MIN(day), MAX(day)
FROM usage_user_daily `+where, args...).Scan(
		&out.Requests, &out.OK, &out.Failed, &out.TotalTokens,
		&out.PromptTokens, &out.OutputTokens, &first, &last)
	if err != nil {
		return out, err
	}
	out.FirstDay, out.LastDay = first.String, last.String
	return out, nil
}
