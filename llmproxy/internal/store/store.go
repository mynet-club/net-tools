// Package store 用 SQLite 记录请求明细、供应商状态与每日消耗汇总。
//
// 设计约束：**不记录任何请求/响应内容**，只落元数据（模型名、延迟、token 数、
// 状态码、错误类型等）。客户端凭证也只存不可逆的哈希前缀。
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// RequestRecord 是一次下游请求的元数据。请求/响应内容永远不落库。
type RequestRecord struct {
	Ts               time.Time
	RequestID        string
	ClientKeyHash    string
	ClientLabel      string
	ClientIP         string
	UserName         string // 多用户模式下归属的用户名；空 = 静态 key 或未启用多用户
	Model            string
	Provider         string
	UpstreamModel    string
	Stream           bool
	StatusCode       int
	OK               bool
	LatencyMs        int64
	TTFTMs           *int64
	PromptTokens     *int64
	CompletionTokens *int64
	TotalTokens      *int64
	Attempts         int
	ErrorType        string
	ErrorMsg         string

	// 消费模式相关：
	//   SystemPaid 表示这次消耗由网关（系统上游）付费，要计入该用户的配额与金额。
	//   缓存拆分只在上游（如 DeepSeek）回报时才有值；两个都为 0 而 prompt>0 时，
	//   计费按「输入全部未命中」处理，属于偏保守的估计。
	SystemPaid      bool
	CacheHitTokens  int64
	CacheMissTokens int64
	// CacheWriteTokens 是「写入缓存」的输入 token（第三档，neolink 等会报）。
	// 上游不报时为 0 —— 此时写入部分被算进未命中档，属于偏保守的估计。
	CacheWriteTokens int64

	// 计价冻结（见 docs/pricing-design.md §4）：落库时按**请求开始时刻**生效的价目行
	// 算好金额写死。CostUpstream / Charge 为 nil = 这一行没有冻结金额（切换前的历史行、
	// 或当时没有价目可用），报表据此把它归入「估算段」。两个 id 指向当时用的价目行，供回溯。
	PriceUpstreamID   int64
	CostUpstream      *float64
	PriceDownstreamID int64
	Charge            *float64
	Currency          string
}

// ProviderStatus 是持久化的供应商运行期状态。
// Scope 为空表示全局配置里的供应商，否则是某个用户名（多用户各自的上游）。
type ProviderStatus struct {
	Scope               string
	Name                string
	Enabled             bool
	ConsecutiveFailures int
	UnhealthyUntil      time.Time
	LastError           string
	LastSuccessAt       time.Time
	LastFailureAt       time.Time
	TotalRequests       int64
	TotalFailures       int64
}

// UsageRow 是统计查询的一行结果。
type UsageRow struct {
	Day              string
	Provider         string
	Model            string
	UpstreamModel    string
	Requests         int64
	OK               int64
	Failed           int64
	PromptTokens     int64
	CompletionTokens int64
	TotalTokens      int64
	CacheHitTokens   int64
	CacheMissTokens  int64
	AvgLatencyMs     float64
	// CostUpstream 是**冻结**的上游成本合计（按请求开始时刻的价目算好写死的那些）；
	// FrozenRequests 是其中已冻结的请求数，与 Requests 相减就是还没冻结（估算段）的部分。
	CostUpstream   float64
	FrozenRequests int64
	// Charge / FrozenCharges 是**分发价**（向用户收多少）的同一对：冻结金额与已冻结请求数。
	Charge        float64
	FrozenCharges int64
	// SystemPaid 表示这一行的消耗由网关（系统上游）付费 —— 只有这些行才计金额
	SystemPaid bool
}

// Stats 是 `llmproxy stats` 的汇总输出。
type Stats struct {
	TotalRequests int64
	TotalOK       int64
	TotalFailed   int64
	TotalTokens   int64
	ByProvider    []UsageRow
	ByDay         []UsageRow
	Recent        []RequestRecord
}

type Store struct {
	db *sql.DB
}

// schema 只放 DDL。连接级参数（busy_timeout / journal_mode / synchronous / _txlock）
// 一律在 dsn() 里给 —— 它们必须对**每一条**连接生效，而 db.Exec(schema) 只作用于
// 当时那一条。详见 dsn 的注释。
const schema = `
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT    PRIMARY KEY,
  value INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS requests (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  ts                INTEGER NOT NULL,
  request_id        TEXT    NOT NULL,
  client_key_hash   TEXT,
  client_label      TEXT,
  client_ip         TEXT,
  model             TEXT    NOT NULL,
  provider          TEXT,
  upstream_model    TEXT,
  stream            INTEGER NOT NULL DEFAULT 0,
  status_code       INTEGER,
  ok                INTEGER NOT NULL DEFAULT 0,
  latency_ms        INTEGER,
  ttft_ms           INTEGER,
  prompt_tokens     INTEGER,
  completion_tokens INTEGER,
  total_tokens      INTEGER,
  attempts          INTEGER NOT NULL DEFAULT 0,
  error_type        TEXT,
  error_msg         TEXT,
  -- 第三档缓存：写入缓存的输入 token（neolink 等会报；用于复核冻结金额）
  cache_write_tokens INTEGER,
  -- 计价冻结（见 docs/pricing-design.md）：落库时按**请求开始时刻**生效的价目行算好写死。
  -- cost_upstream / charge 为 NULL 表示这一行没有冻结金额（切换前的历史行、或当时没有价目
  -- 可用）—— 报表据此把它归入「估算段」，不要与冻结段混在一个合计里。
  price_upstream_id   INTEGER NOT NULL DEFAULT 0,
  cost_upstream       REAL,
  price_downstream_id INTEGER NOT NULL DEFAULT 0,
  charge              REAL,
  currency            TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_requests_provider_ts ON requests(provider, ts);
CREATE INDEX IF NOT EXISTS idx_requests_model_ts ON requests(model, ts);

CREATE TABLE IF NOT EXISTS provider_stats (
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

CREATE TABLE IF NOT EXISTS usage_daily (
  day                TEXT    NOT NULL,
  provider           TEXT    NOT NULL,
  model              TEXT    NOT NULL,
  requests           INTEGER NOT NULL DEFAULT 0,
  ok                 INTEGER NOT NULL DEFAULT 0,
  failed             INTEGER NOT NULL DEFAULT 0,
  prompt_tokens      INTEGER NOT NULL DEFAULT 0,
  completion_tokens  INTEGER NOT NULL DEFAULT 0,
  total_tokens       INTEGER NOT NULL DEFAULT 0,
  latency_sum_ms     INTEGER NOT NULL DEFAULT 0,
  -- 冻结的上游成本合计，以及其中「已冻结」的请求数（其余是估算段）
  cost_upstream      REAL    NOT NULL DEFAULT 0,
  frozen_requests    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, provider, model)
);
`

// dsn 把库路径与连接级参数拼成 modernc.org/sqlite 的 file: URI。
//
// 这些参数必须走 DSN，不能只靠 schema 开头那几行 PRAGMA：journal_mode=WAL 写进库文件头、
// 是持久的，但 busy_timeout 与 synchronous 是**每连接**属性 —— 靠一次性 db.Exec(schema)
// 设置，只在「池里恰好只有一条永不回收的连接」时成立。驱动一旦因 I/O 错误丢弃并重开连接
// （driver.ErrBadConn），新连接就静默降级成 busy_timeout=0 + synchronous=FULL：
// 前者让任何跨进程锁竞争立刻失败而不等 5 秒，后者让每次 commit 都 fsync，而且都没有日志。
//
// _txlock=immediate 解决另一件事：SQLite 的 busy_timeout **不覆盖**「deferred 事务内
// 读锁升级成写锁」—— 那种冲突立刻返回 SQLITE_BUSY（这是 SQLite 刻意的防死锁设计）。
// 价目收口与用户上游 upsert 都是「先 SELECT 再 UPDATE」，CLI 与服务端并发时会随机报
// database is locked。让事务一开头就拿写锁，就落回 busy_timeout 的等待路径。
// 本包 14 处事务全是写事务，所以没有只读事务会被这个设置拖累。
//
// 用 file: URI 而不是「裸路径 + ?query」：裸路径形式下驱动按第一个 '?' 切分 DSN，
// 路径里真带 '?' 就会切错；URI 形式交给 SQLite 解析，路径部分由 url.URL 百分号转义
// （空格、'?'、'#' 三种路径都有测试覆盖）。
func dsn(path string) string {
	u := url.URL{
		Scheme: "file",
		Path:   path,
		RawQuery: "_pragma=busy_timeout(5000)" +
			"&_pragma=journal_mode(WAL)" +
			"&_pragma=synchronous(NORMAL)" +
			"&_txlock=immediate",
	}
	return u.String()
}

// Open 打开（必要时创建）SQLite 数据库。文件权限强制 0600。
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("数据库路径为空")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("创建数据库目录失败: %w", err)
	}
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("打开 SQLite 失败: %w", err)
	}
	// modernc.org/sqlite 是单连接语义，开多了反而容易 SQLITE_BUSY
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("初始化数据库结构失败: %w", err)
	}
	// 单用户时代的 provider_stats 主键只有 name，这里补上 scope 维度
	if err := migrateProviderStatsScope(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("迁移 provider_stats 失败: %w", err)
	}
	if _, err := db.Exec(userSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("初始化多用户表结构失败: %w", err)
	}
	// 消费模式：users 加列 + usage_user_daily 重建（主键要加 system_paid）
	if err := migrateConsumption(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("迁移消费模式表结构失败: %w", err)
	}
	// 计价与成本模型：provider_prices（上游价）+ user_prices（分发价），都带历史
	if _, err := db.Exec(pricingSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("初始化计价表结构失败: %w", err)
	}
	// 已有库补上请求行的冻结列（新库在上面的 DDL 里就有了）
	if err := migratePricingColumns(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("迁移计价冻结列失败: %w", err)
	}
	// WAL 模式下会生成 -wal/-shm 文件，一并收紧权限
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); err == nil {
			_ = os.Chmod(p, 0o600)
		}
	}
	return &Store{db: db}, nil
}

// migrateProviderStatsScope 把单用户时代的 provider_stats（主键只有 name）
// 升级成 (scope, name)：已有行归入 scope=”，也就是「全局配置里的供应商」。
//
// SQLite 不能改主键，只能重建。用列是否存在来判断，重复调用无副作用。
func migrateProviderStatsScope(db *sql.DB) error {
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('provider_stats') WHERE name='scope'`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	cols := `scope, name, enabled, consecutive_failures, unhealthy_until,
	         last_error, last_success_at, last_failure_at, total_requests, total_failures, updated_at`
	for _, q := range []string{
		`ALTER TABLE provider_stats RENAME TO _provider_stats_legacy`,
		`CREATE TABLE provider_stats (
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
		 )`,
		`INSERT INTO provider_stats (` + cols + `)
		 SELECT '', name, enabled, consecutive_failures, unhealthy_until,
		        last_error, last_success_at, last_failure_at, total_requests, total_failures, updated_at
		 FROM _provider_stats_legacy`,
		`DROP TABLE _provider_stats_legacy`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return fmt.Errorf("迁移步骤失败: %w", err)
		}
	}
	return tx.Commit()
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) DB() *sql.DB { return s.db }

func nowMs(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func int64Val(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func ptrVal(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

func nullable(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func f64Val(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

// InsertRequest 写入一条请求明细，并同步更新 usage_daily 汇总。
func (s *Store) InsertRequest(rec RequestRecord) error {
	if rec.Ts.IsZero() {
		rec.Ts = time.Now()
	}
	day := rec.Ts.Format("2006-01-02")
	stream := 0
	if rec.Stream {
		stream = 1
	}
	okInc, failedInc := 0, 1
	if rec.OK {
		okInc, failedInc = 1, 0
	}
	provider := rec.Provider
	if provider == "" {
		provider = "-"
	}
	model := rec.Model
	if model == "" {
		model = "-"
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(`
INSERT INTO requests (
  ts, request_id, client_key_hash, client_label, client_ip,
  model, provider, upstream_model, stream,
  status_code, ok, latency_ms, ttft_ms,
  prompt_tokens, completion_tokens, total_tokens,
  attempts, error_type, error_msg,
  cache_write_tokens, price_upstream_id, cost_upstream, price_downstream_id, charge, currency
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		nowMs(rec.Ts), rec.RequestID, rec.ClientKeyHash, rec.ClientLabel, rec.ClientIP,
		model, provider, rec.UpstreamModel, stream,
		nullable(int64(rec.StatusCode)), map[bool]int{true: 1, false: 0}[rec.OK],
		nullable(rec.LatencyMs), ptrVal(rec.TTFTMs),
		ptrVal(rec.PromptTokens), ptrVal(rec.CompletionTokens), ptrVal(rec.TotalTokens),
		rec.Attempts, rec.ErrorType, rec.ErrorMsg,
		nullable(rec.CacheWriteTokens), rec.PriceUpstreamID, f64Val(rec.CostUpstream),
		rec.PriceDownstreamID, f64Val(rec.Charge), rec.Currency,
	)
	if err != nil {
		return fmt.Errorf("写入 requests 失败: %w", err)
	}

	if provider != "-" {
		// 冻结段与估算段要能分开看：frozen_requests 记「已冻结金额的请求数」，
		// 与 requests 相减就是还没冻结（估算）的那些。
		frozen := 0
		cost := 0.0
		if rec.CostUpstream != nil {
			frozen, cost = 1, *rec.CostUpstream
		}
		_, err = tx.Exec(`
INSERT INTO usage_daily (
  day, provider, model, requests, ok, failed,
  prompt_tokens, completion_tokens, total_tokens, latency_sum_ms,
  cost_upstream, frozen_requests
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(day, provider, model) DO UPDATE SET
  requests          = requests + excluded.requests,
  ok                = ok + excluded.ok,
  failed            = failed + excluded.failed,
  prompt_tokens     = prompt_tokens + excluded.prompt_tokens,
  completion_tokens = completion_tokens + excluded.completion_tokens,
  total_tokens      = total_tokens + excluded.total_tokens,
  latency_sum_ms    = latency_sum_ms + excluded.latency_sum_ms,
  cost_upstream     = cost_upstream + excluded.cost_upstream,
  frozen_requests   = frozen_requests + excluded.frozen_requests`,
			day, provider, model, 1, okInc, failedInc,
			int64Val(rec.PromptTokens), int64Val(rec.CompletionTokens), int64Val(rec.TotalTokens),
			rec.LatencyMs, cost, frozen,
		)
		if err != nil {
			return fmt.Errorf("写入 usage_daily 失败: %w", err)
		}
	}

	// 多用户模式下额外记一份「按用户」的汇总；静态 key 没有归属用户，不记
	if rec.UserName != "" {
		systemPaid := 0
		if rec.SystemPaid {
			systemPaid = 1
		}
		// 上游模型名决定单价；取不到时退化成下游名（同名直通的情况下两者相同）
		upstream := rec.UpstreamModel
		if upstream == "" {
			upstream = model
		}
		chargeVal, chargeFrozen := 0.0, 0
		if rec.Charge != nil {
			chargeVal, chargeFrozen = *rec.Charge, 1
		}
		_, err = tx.Exec(`
INSERT INTO usage_user_daily (
  day, user_name, provider, model, upstream_model, system_paid,
  requests, ok, failed,
  prompt_tokens, cache_hit_tokens, cache_miss_tokens, completion_tokens, total_tokens, latency_sum_ms,
  charge, frozen_charges
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(day, user_name, provider, model, upstream_model, system_paid) DO UPDATE SET
  requests          = requests + excluded.requests,
  ok                = ok + excluded.ok,
  failed            = failed + excluded.failed,
  prompt_tokens     = prompt_tokens + excluded.prompt_tokens,
  cache_hit_tokens  = cache_hit_tokens + excluded.cache_hit_tokens,
  cache_miss_tokens = cache_miss_tokens + excluded.cache_miss_tokens,
  completion_tokens = completion_tokens + excluded.completion_tokens,
  total_tokens      = total_tokens + excluded.total_tokens,
  latency_sum_ms    = latency_sum_ms + excluded.latency_sum_ms,
  charge            = charge + excluded.charge,
  frozen_charges    = frozen_charges + excluded.frozen_charges`,
			day, rec.UserName, provider, model, upstream, systemPaid, 1, okInc, failedInc,
			int64Val(rec.PromptTokens), rec.CacheHitTokens, rec.CacheMissTokens,
			int64Val(rec.CompletionTokens), int64Val(rec.TotalTokens),
			rec.LatencyMs, chargeVal, chargeFrozen,
		)
		if err != nil {
			return fmt.Errorf("写入 usage_user_daily 失败: %w", err)
		}
	}

	return tx.Commit()
}

// SaveProviderStatus 批量写入供应商运行期状态。
func (s *Store) SaveProviderStatus(statuses []ProviderStatus) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
INSERT INTO provider_stats (
  scope, name, enabled, consecutive_failures, unhealthy_until,
  last_error, last_success_at, last_failure_at,
  total_requests, total_failures, updated_at
) VALUES (?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(scope, name) DO UPDATE SET
  enabled              = excluded.enabled,
  consecutive_failures = excluded.consecutive_failures,
  unhealthy_until      = excluded.unhealthy_until,
  last_error           = excluded.last_error,
  last_success_at      = excluded.last_success_at,
  last_failure_at      = excluded.last_failure_at,
  total_requests       = excluded.total_requests,
  total_failures       = excluded.total_failures,
  updated_at           = excluded.updated_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().UnixMilli()
	for _, st := range statuses {
		enabled := 0
		if st.Enabled {
			enabled = 1
		}
		if _, err := stmt.Exec(
			st.Scope, st.Name, enabled, st.ConsecutiveFailures, nowMs(st.UnhealthyUntil),
			st.LastError, nowMs(st.LastSuccessAt), nowMs(st.LastFailureAt),
			st.TotalRequests, st.TotalFailures, now,
		); err != nil {
			return fmt.Errorf("写入 provider_stats %s 失败: %w", st.Name, err)
		}
	}
	return tx.Commit()
}

// LoadProviderStatus 读取全部供应商状态（含各用户自己的上游），重启后恢复熔断。
//
// 返回**切片**而不是 map：ProviderStatus 自带 Scope 与 Name，而把两者拼成复合键会丢信息 ——
// 键 "alice/my-up" 既可能是「用户 alice 的上游 my-up」，也可能是一个名字里真带斜杠的
// 全局供应商，恢复时无法还原（SplitScopeKey 只能猜）。ORDER BY 则让恢复结果不依赖
// SQL 的返回顺序：同一份库两次读出来必须一样。
func (s *Store) LoadProviderStatus() ([]ProviderStatus, error) {
	rows, err := s.db.Query(`
SELECT COALESCE(scope,''), name, enabled, consecutive_failures, unhealthy_until,
       COALESCE(last_error,''), COALESCE(last_success_at,0), COALESCE(last_failure_at,0),
       total_requests, total_failures
FROM provider_stats ORDER BY scope, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ProviderStatus{}
	for rows.Next() {
		var st ProviderStatus
		var enabled, unhealthyUntil, lastOK, lastFail int64
		if err := rows.Scan(&st.Scope, &st.Name, &enabled, &st.ConsecutiveFailures, &unhealthyUntil,
			&st.LastError, &lastOK, &lastFail,
			&st.TotalRequests, &st.TotalFailures); err != nil {
			return nil, err
		}
		st.Enabled = enabled != 0
		if unhealthyUntil != 0 {
			st.UnhealthyUntil = time.UnixMilli(unhealthyUntil)
		}
		if lastOK != 0 {
			st.LastSuccessAt = time.UnixMilli(lastOK)
		}
		if lastFail != 0 {
			st.LastFailureAt = time.UnixMilli(lastFail)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// Prune 删除 retainDays 天前的请求明细；usage_daily 保留（体积很小，且是长期消耗视图）。
func (s *Store) Prune(retainDays int) (int64, error) {
	if retainDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().AddDate(0, 0, -retainDays).UnixMilli()
	res, err := s.db.Exec(`DELETE FROM requests WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Revision 返回用户与上游配置的修订号：任何一次增删改都会 +1。
// 运行中的服务靠轮询它发现「CLI 在另一个进程里改了配置」。
func (s *Store) Revision() (int64, error) {
	var v int64
	err := s.db.QueryRow(`SELECT COALESCE((SELECT value FROM meta WHERE key='revision'),0)`).Scan(&v)
	return v, err
}

// bumpRevision 在事务里把修订号 +1。
func bumpRevision(tx *sql.Tx) error {
	_, err := tx.Exec(`INSERT INTO meta(key,value) VALUES('revision',1)
	  ON CONFLICT(key) DO UPDATE SET value = value + 1`)
	return err
}

// isUniqueViolation 判断是否撞了唯一约束（modernc sqlite 的错误文本里带这个）。
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// Stats 查询消耗统计。since 为零值表示不限起始时间。
func (s *Store) Stats(since time.Time, recentLimit int) (*Stats, error) {
	out := &Stats{
		ByProvider: []UsageRow{},
		ByDay:      []UsageRow{},
		Recent:     []RequestRecord{},
	}

	where := ""
	args := []any{}
	// usage_daily 是按**天**聚合的（day 是 TEXT），粒度与 requests.ts 的毫秒不同，
	// 所以要另起一个 where。曾经这两个查询完全没有 WHERE —— 于是 `stats --days 1`
	// 会打印「总计: 请求 1」，紧接着的按供应商表却是全量历史，同屏自相矛盾。
	dayWhere := ""
	dayArgs := []any{}
	if !since.IsZero() {
		where = " WHERE ts >= ?"
		args = append(args, since.UnixMilli())
		dayWhere = " WHERE day >= ?"
		dayArgs = append(dayArgs, since.Format("2006-01-02"))
	}
	// 注意残留的边界误差（数据模型决定，无法消除）：总计按毫秒精确过滤，
	// 而两张聚合表只能按整天过滤，所以 since 当天里早于 since 时刻的那部分
	// 会出现在聚合表里、却不在总计里。要更细就得让 usage_daily 按小时聚合。
	err := s.db.QueryRow(`
SELECT COUNT(*),
       COALESCE(SUM(CASE WHEN ok=1 THEN 1 ELSE 0 END),0),
       COALESCE(SUM(CASE WHEN ok=0 THEN 1 ELSE 0 END),0),
       COALESCE(SUM(COALESCE(total_tokens,0)),0)
FROM requests`+where, args...).Scan(
		&out.TotalRequests, &out.TotalOK, &out.TotalFailed, &out.TotalTokens)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.Query(`
SELECT '-', provider, model,
       SUM(requests), SUM(ok), SUM(failed),
       SUM(prompt_tokens), SUM(completion_tokens), SUM(total_tokens),
       CASE WHEN SUM(requests)>0 THEN CAST(SUM(latency_sum_ms) AS REAL)/SUM(requests) ELSE 0 END,
       COALESCE(SUM(cost_upstream),0), COALESCE(SUM(frozen_requests),0)
FROM usage_daily`+dayWhere+`
GROUP BY provider, model
ORDER BY SUM(requests) DESC, provider, model
LIMIT 200`, dayArgs...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r UsageRow
		if err := rows.Scan(&r.Day, &r.Provider, &r.Model,
			&r.Requests, &r.OK, &r.Failed,
			&r.PromptTokens, &r.CompletionTokens, &r.TotalTokens, &r.AvgLatencyMs,
			&r.CostUpstream, &r.FrozenRequests); err != nil {
			rows.Close()
			return nil, err
		}
		out.ByProvider = append(out.ByProvider, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows2, err := s.db.Query(`
SELECT day, '-', '-',
       SUM(requests), SUM(ok), SUM(failed),
       SUM(prompt_tokens), SUM(completion_tokens), SUM(total_tokens),
       CASE WHEN SUM(requests)>0 THEN CAST(SUM(latency_sum_ms) AS REAL)/SUM(requests) ELSE 0 END,
       COALESCE(SUM(cost_upstream),0), COALESCE(SUM(frozen_requests),0)
FROM usage_daily`+dayWhere+`
GROUP BY day
ORDER BY day DESC
LIMIT 90`, dayArgs...)
	if err != nil {
		return nil, err
	}
	for rows2.Next() {
		var r UsageRow
		if err := rows2.Scan(&r.Day, &r.Provider, &r.Model,
			&r.Requests, &r.OK, &r.Failed,
			&r.PromptTokens, &r.CompletionTokens, &r.TotalTokens, &r.AvgLatencyMs,
			&r.CostUpstream, &r.FrozenRequests); err != nil {
			rows2.Close()
			return nil, err
		}
		out.ByDay = append(out.ByDay, r)
	}
	rows2.Close()
	if err := rows2.Err(); err != nil {
		return nil, err
	}

	if recentLimit > 0 {
		if err := s.loadRecent(out, recentLimit); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) loadRecent(out *Stats, limit int) error {
	rows, err := s.db.Query(`
SELECT ts, request_id, COALESCE(client_key_hash,''), COALESCE(client_label,''), COALESCE(client_ip,''),
       model, COALESCE(provider,''), COALESCE(upstream_model,''), stream,
       status_code, ok, latency_ms, ttft_ms,
       prompt_tokens, completion_tokens, total_tokens,
       attempts, COALESCE(error_type,''), COALESCE(error_msg,'')
FROM requests
ORDER BY ts DESC
LIMIT ?`, limit)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var rec RequestRecord
		var ts, status, okFlag, stream, latency, attempts sql.NullInt64
		var ttft, pt, ct, tt sql.NullInt64
		if err := rows.Scan(&ts, &rec.RequestID, &rec.ClientKeyHash, &rec.ClientLabel, &rec.ClientIP,
			&rec.Model, &rec.Provider, &rec.UpstreamModel, &stream,
			&status, &okFlag, &latency, &ttft,
			&pt, &ct, &tt,
			&attempts, &rec.ErrorType, &rec.ErrorMsg); err != nil {
			return err
		}
		if ts.Valid {
			rec.Ts = time.UnixMilli(ts.Int64)
		}
		rec.Stream = stream.Int64 != 0
		rec.StatusCode = int(status.Int64)
		rec.OK = okFlag.Int64 != 0
		rec.LatencyMs = latency.Int64
		rec.Attempts = int(attempts.Int64)
		if ttft.Valid {
			v := ttft.Int64
			rec.TTFTMs = &v
		}
		if pt.Valid {
			v := pt.Int64
			rec.PromptTokens = &v
		}
		if ct.Valid {
			v := ct.Int64
			rec.CompletionTokens = &v
		}
		if tt.Valid {
			v := tt.Int64
			rec.TotalTokens = &v
		}
		out.Recent = append(out.Recent, rec)
	}
	return rows.Err()
}

// KeyHash 对下游 API key 做不可逆摘要，日志里只存这个前缀。
// 用 SHA-256；对自用场景的长随机 key 来说足够，且不引入额外密钥管理。
func KeyHash(key string) string {
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:6])
}
