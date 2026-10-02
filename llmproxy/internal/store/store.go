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

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"

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

	// Scope 是这次请求归属的**范围**（3.0 §2.7 规则 2）。零值 = 没有归属信息
	// （静态 key、或未启用多用户），落 NULL 而不是猜一个。
	//
	// 过渡期口径：只给了 UserName 时按规则 3 落成 (user, <用户名>)，
	// 解析集中在 resolveRequestScope 一处。
	// §2.7 规则 8：主线接线完成后删掉那条 UserName 兜底 —— 届时调用方一律传 Scope。
	Scope policy.ScopeRef

	// 路由决策痕迹（§2.8：在线请求至少要记 routing_seed、候选集摘要、最终计划、policy_version）。
	// 全是**摘要与版本号**，不含任何正文；空串落 NULL = 那条路径还没接入观测。
	// 有 seed 才谈得上逐位复现，没 seed 只能做解释性回放。
	PolicyVersion    string
	RoutingEpoch     string
	RoutingSeed      string
	CandidatesDigest string
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
	db      *sql.DB
	dialect Dialect
}

// rebind 把 SQL 交给方言改写（占位符、upsert、保留字）。dialect 为 nil 时原样。
func (s *Store) rebind(q string) string {
	if s == nil || s.dialect == nil {
		return q
	}
	return s.dialect.Rebind(q)
}

// exec / query / queryRow：业务 SQL 一律走这三个，**不要**直接摸 s.db ——
// 否则 MySQL 的 ON CONFLICT、PG 的 ? 占位符会漏改写。
func (s *Store) exec(q string, args ...any) (sql.Result, error) {
	return s.db.Exec(s.rebind(q), args...)
}

func (s *Store) query(q string, args ...any) (*sql.Rows, error) {
	return s.db.Query(s.rebind(q), args...)
}

func (s *Store) queryRow(q string, args ...any) *sql.Row {
	return s.db.QueryRow(s.rebind(q), args...)
}

func txExec(tx *sql.Tx, d Dialect, q string, args ...any) (sql.Result, error) {
	if d != nil {
		q = d.Rebind(q)
	}
	return tx.Exec(q, args...)
}

func txQueryRow(tx *sql.Tx, d Dialect, q string, args ...any) *sql.Row {
	if d != nil {
		q = d.Rebind(q)
	}
	return tx.QueryRow(q, args...)
}

// insertID 执行 INSERT 并取回自增主键。
// PostgreSQL / SQLite 用 RETURNING id；MySQL 驱动不支持 RETURNING，走 LastInsertId。
func insertID(tx *sql.Tx, d Dialect, q string, args ...any) (int64, error) {
	name := ""
	if d != nil {
		name = d.Name()
	}
	if name == "mysql" {
		res, err := txExec(tx, d, q, args...)
		if err != nil {
			return 0, err
		}
		return res.LastInsertId()
	}
	var id int64
	err := txQueryRow(tx, d, q+" RETURNING id", args...).Scan(&id)
	return id, err
}

// schema 只放 DDL。连接级参数（busy_timeout / journal_mode / synchronous / _txlock）
// 一律在 sqliteDSN() 里给 —— 它们必须对**每一条**连接生效，而 db.Exec(schema) 只作用于
// 当时那一条。详见 dsn 的注释。
//
// 刻意是 var 而不是 const：requests 的 scope/路由痕迹列与 provider_stats 的 3.0 形状
// 都由 scope_schema.go 的单一定义生成 —— 新库的建表语句与老库的一次性迁移必须逐列一致，
// 抄两遍就会出现「新库有列、老库补不上」或者反过来。
var schema = `
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
  currency            TEXT    NOT NULL DEFAULT '',
  -- 3.0 §2.7 规则 2 + §2.8：归属范围与路由决策痕迹，全部可空 ——
  -- 静态 key 的请求没有归属范围，2.x 的历史行也一律不回填（猜的归属会污染账单，规则 5）。
  -- 这里同样**没有任何正文/提示词列**，列定义见 scope_schema.go。
` + scopeColsFragment(requestsScopeCols30) + `
);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_requests_provider_ts ON requests(provider, ts);
CREATE INDEX IF NOT EXISTS idx_requests_model_ts ON requests(model, ts);
-- 范围桶索引 idx_requests_scope_bucket **不在这里建**：老库的 requests 此刻还没有 scope_kind
-- 列（那一列由 §2.7 的一次性迁移补），在这里建会撞「列不存在」而让 Open 失败。
-- 它统一由 migrateScopeSchema 在列齐了之后按 scope_schema.go 的那一份定义建，幂等。

-- 路由桶 (scope, provider) 的熔断状态：主键 (scope_kind, scope_id, name) 正是
-- §2.7 规则 4 的桶最终键。2.x 的单列 scope（裸用户名 / 空串）形状由 scope_migration.go
-- 一次性搬过来，所以这里不再维护旧的 scope TEXT 定义。
CREATE TABLE IF NOT EXISTS provider_stats (
` + providerStatsBody30 + `
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

// sqliteDSN 把库路径与连接级参数拼成 modernc.org/sqlite 的 file: URI。
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
func sqliteDSN(path string) string {
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
// 等价于 OpenDialect("sqlite", path) —— 保留这个入口，CLI 与测试少写一个参数。
func Open(path string) (*Store, error) {
	return OpenDialect("sqlite", path)
}

// OpenDialect 按 driver 名打开数据库并跑完全部迁移。
// pathOrDSN：sqlite 是文件路径；mysql/postgres 是 DSN（支持 ${ENV} 由 config 层展开）。
func OpenDialect(driver, pathOrDSN string) (*Store, error) {
	d, err := dialectByName(driver)
	if err != nil {
		return nil, err
	}
	if d.Name() == "sqlite" {
		if strings.TrimSpace(pathOrDSN) == "" {
			return nil, errors.New("数据库路径为空")
		}
		if err := os.MkdirAll(filepath.Dir(pathOrDSN), 0o700); err != nil {
			return nil, fmt.Errorf("创建数据库目录失败: %w", err)
		}
	}
	db, err := d.Open(pathOrDSN)
	if err != nil {
		return nil, err
	}

	if err := execSchema(db, d, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("初始化数据库结构失败: %w", err)
	}
	// 单用户时代的 provider_stats 主键只有 name，这里补上 scope 维度
	if err := migrateProviderStatsScope(db, d); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("迁移 provider_stats 失败: %w", err)
	}
	if err := execSchema(db, d, userSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("初始化多用户表结构失败: %w", err)
	}
	if err := execSchema(db, d, auditSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("初始化审计表失败: %w", err)
	}
	// 消费模式：users 加列 + usage_user_daily 重建（主键要加 system_paid）
	if err := migrateConsumption(db, d); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("迁移消费模式表结构失败: %w", err)
	}
	// 计价与成本模型：provider_prices（上游价）+ user_prices（分发价），都带历史
	if err := execSchema(db, d, pricingSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("初始化计价表结构失败: %w", err)
	}
	// 已有库补上请求行的冻结列（新库在上面的 DDL 里就有了）
	if err := migratePricingColumns(db, d); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("迁移计价冻结列失败: %w", err)
	}
	// §2.7 的一次性 scope 迁移：**必须排在所有 2.x 迁移之后**（它读 2.x 的最终形状），
	// 并且失败就让整个 Open 失败 —— 半途而废的 scope 结构比不开库危险得多
	// （账单会挂到错误的主体上）。细节与备份/回滚口径见 scope_migration.go。
	if err := migrateScopeSchema(db, d, pathOrDSN); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("scope 结构迁移失败（数据库已回到迁移前，请修复后重试）: %w", err)
	}
	// SQLite：WAL 模式下会生成 -wal/-shm 文件，一并收紧权限
	if d.Name() == "sqlite" {
		for _, p := range []string{pathOrDSN, pathOrDSN + "-wal", pathOrDSN + "-shm"} {
			if _, err := os.Stat(p); err == nil {
				_ = os.Chmod(p, 0o600)
			}
		}
	}
	return &Store{db: db, dialect: d}, nil
}

// execSchema 按方言改写 DDL 并逐条执行。
// 不一次 Exec 整段：MySQL/PG 驱动对多语句 Exec 支持不一，拆开最稳。
// MySQL 的 CREATE INDEX 没有 IF NOT EXISTS，重复执行报 1061 —— 这里吞掉，
// 保证同一套 schema 多次 Open 幂等。
func execSchema(db *sql.DB, d Dialect, ddl string) error {
	for _, stmt := range splitStatements(d.RewriteDDL(ddl)) {
		if _, err := db.Exec(d.Rebind(stmt)); err != nil {
			if isIgnorableDDL(d, stmt, err) {
				continue
			}
			return fmt.Errorf("执行 DDL 失败（%s）: %w", firstLine(stmt), err)
		}
	}
	return nil
}

// isIgnorableDDL 判定「已经建过」类错误：MySQL 重复索引名 1061。
func isIgnorableDDL(d Dialect, stmt string, err error) bool {
	if d.Name() != "mysql" {
		return false
	}
	msg := err.Error()
	return strings.HasPrefix(firstLine(stmt), "CREATE INDEX") &&
		(strings.Contains(msg, "1061") || strings.Contains(msg, "Duplicate key name"))
}

// splitStatements 按分号切 DDL，丢掉空段。字符串字面量里不写分号（本包 DDL 遵守）。
func splitStatements(ddl string) []string {
	var out []string
	for _, part := range strings.Split(ddl, ";") {
		p := strings.TrimSpace(part)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// migrateProviderStatsScope 把单用户时代的 provider_stats（主键只有 name）
// 升级成 (scope, name)：已有行归入 scope=”，也就是「全局配置里的供应商」。
//
// 用列是否存在来判断，重复调用无副作用。
//
// 「有 scope 列」与「有 scope_kind 列」是两代形状，判据必须两条都看：
// 3.0 的表**没有** scope 列（主键是 scope_kind + scope_id + name），
// 只看「没有 scope 就重建」会把已经迁好的库再降回 2.x 的单列形状（数据不丢但形状倒退）。
// 2.x→3.0 的那一步由 scope_migration.go 负责，这里只管「单用户→2.x」。
func migrateProviderStatsScope(db *sql.DB, d Dialect) error {
	has, err := d.HasColumn(db, "provider_stats", "scope")
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	has30, err := d.HasColumn(db, "provider_stats", "scope_kind")
	if err != nil {
		return err
	}
	if has30 {
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
		if _, err := txExec(tx, d, q); err != nil {
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

// emptyToNil 把空串落成 NULL：requests 的路由痕迹列「没有」与「是空串」是同一件事，
// 用 NULL 表示就不必在读侧再造一个 is-not-empty 的特例。
func emptyToNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// scopeCol / scopeIDCol 成对给出 requests 的范围两列（定不出归属就两列都 NULL）。
func scopeCol(ok bool, kind policy.ScopeKind) any {
	if !ok {
		return nil
	}
	return string(kind)
}

func scopeIDCol(ok bool, id string) any {
	if !ok {
		return nil
	}
	return id
}

// InsertRequest 写入一条请求明细，并同步更新 usage_daily / usage_scope_daily。
//
// 两张聚合表的分工（§2.7 规则 5）：
//
//	usage_daily        全局按（日, 供应商, 模型）—— 2.x 就有，口径一字未动
//	usage_scope_daily  按（日, 范围, ...）—— 谁花掉了这些 token
//
// usage_user_daily 已经**不再写入**：那张表只剩 2.x 的历史行，读它的是 scope 迁移，
// 运行时读用量一律走 usage_scope_daily（见 iface.go 的规则 8 说明）。
func (s *Store) InsertRequest(rec RequestRecord) error {
	if rec.Ts.IsZero() {
		rec.Ts = time.Now()
	}
	// 调用方给了非零 Scope 却非法（比如 ID 超长或带冒号）时必须失败，不能降级成
	// 「按 UserName 归属」或「无归属」—— 那会让账单挂到错误的主体上。
	if hasScope(rec.Scope) {
		if err := rec.Scope.Validate(); err != nil {
			return fmt.Errorf("写入 requests：%s 的 scope 非法: %w", rec.RequestID, err)
		}
	}
	scope, scoped := resolveRequestScope(rec)
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

	_, err = txExec(tx, s.dialect, `
INSERT INTO requests (
  ts, request_id, client_key_hash, client_label, client_ip,
  model, provider, upstream_model, stream,
  status_code, ok, latency_ms, ttft_ms,
  prompt_tokens, completion_tokens, total_tokens,
  attempts, error_type, error_msg,
  cache_write_tokens, price_upstream_id, cost_upstream, price_downstream_id, charge, currency,
  scope_kind, scope_id, policy_version, routing_epoch, routing_seed, candidates_digest
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		nowMs(rec.Ts), rec.RequestID, rec.ClientKeyHash, rec.ClientLabel, rec.ClientIP,
		model, provider, rec.UpstreamModel, stream,
		nullable(int64(rec.StatusCode)), map[bool]int{true: 1, false: 0}[rec.OK],
		nullable(rec.LatencyMs), ptrVal(rec.TTFTMs),
		ptrVal(rec.PromptTokens), ptrVal(rec.CompletionTokens), ptrVal(rec.TotalTokens),
		rec.Attempts, rec.ErrorType, rec.ErrorMsg,
		nullable(rec.CacheWriteTokens), rec.PriceUpstreamID, f64Val(rec.CostUpstream),
		rec.PriceDownstreamID, f64Val(rec.Charge), rec.Currency,
		// 范围两列成对出现：定得出范围就两列都有，定不出就两列都 NULL。
		// 一半一半的形状会让「按范围查」把那条行同时算进「有归属」和「无归属」两边。
		scopeCol(scoped, scope.Kind), scopeIDCol(scoped, scope.ID),
		emptyToNil(rec.PolicyVersion), emptyToNil(rec.RoutingEpoch),
		emptyToNil(rec.RoutingSeed), emptyToNil(rec.CandidatesDigest),
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
		_, err = txExec(tx, s.dialect, `
INSERT INTO usage_daily (
  day, provider, model, requests, ok, failed,
  prompt_tokens, completion_tokens, total_tokens, latency_sum_ms,
  cost_upstream, frozen_requests
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(day, provider, model) DO UPDATE SET
  requests          = usage_daily.requests + excluded.requests,
  ok                = usage_daily.ok + excluded.ok,
  failed            = usage_daily.failed + excluded.failed,
  prompt_tokens     = usage_daily.prompt_tokens + excluded.prompt_tokens,
  completion_tokens = usage_daily.completion_tokens + excluded.completion_tokens,
  total_tokens      = usage_daily.total_tokens + excluded.total_tokens,
  latency_sum_ms    = usage_daily.latency_sum_ms + excluded.latency_sum_ms,
  cost_upstream     = usage_daily.cost_upstream + excluded.cost_upstream,
  frozen_requests   = usage_daily.frozen_requests + excluded.frozen_requests`,
			day, provider, model, 1, okInc, failedInc,
			int64Val(rec.PromptTokens), int64Val(rec.CompletionTokens), int64Val(rec.TotalTokens),
			rec.LatencyMs, cost, frozen,
		)
		if err != nil {
			return fmt.Errorf("写入 usage_daily 失败: %w", err)
		}
	}

	// 3.0 的按范围聚合：一次请求能进 usage_scope_daily 的前提是定得出范围
	// （rec.Scope，或退到 rec.UserName 落成 (user, 名) —— 解析只在 resolveRequestScope
	// 这一处）；定不出就只落上面两张 —— 补一个默认范围等于凭空造归属。
	//
	// 这里**不再**写 usage_user_daily：那是 2.x 的按用户账本，3.0 的按范围账本是它的
	// 超集（人 = (user, 名) 那一桶）。继续双写等于让同一笔钱有两个真源，
	// 而迁移之后两者必然分叉（新范围种类的账单只会出现在新表里）。
	if scoped {
		upstream := rec.UpstreamModel
		if upstream == "" {
			upstream = model
		}
		toks := usageTokens{
			prompt:     int64Val(rec.PromptTokens),
			cacheHit:   rec.CacheHitTokens,
			cacheMiss:  rec.CacheMissTokens,
			completion: int64Val(rec.CompletionTokens),
			total:      int64Val(rec.TotalTokens),
			latencyMs:  rec.LatencyMs,
			charge:     rec.Charge,
		}
		if err := s.upsertScopeUsage(tx, scope, day, provider, model, upstream,
			rec.SystemPaid, rec.OK, !rec.OK, toks); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// Prune 删除 retainDays 天前的请求明细；usage_daily 保留（体积很小，且是长期消耗视图）。
func (s *Store) Prune(retainDays int) (int64, error) {
	if retainDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().AddDate(0, 0, -retainDays).UnixMilli()
	res, err := s.exec(`DELETE FROM requests WHERE ts < ?`, cutoff)
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
	err := s.queryRow(`SELECT COALESCE((SELECT value FROM meta WHERE key='revision'),0)`).Scan(&v)
	return v, err
}

// bumpRevision 在事务里把修订号 +1。
//
// `value = meta.value + 1` 带表名限定：PostgreSQL 里裸 `value` 会与
// EXCLUDED.value 撞成「column reference is ambiguous」；MySQL/SQLite 也接受这写法。
func bumpRevision(tx *sql.Tx, d Dialect) error {
	_, err := txExec(tx, d, `INSERT INTO meta(key,value) VALUES('revision',1)
	  ON CONFLICT(key) DO UPDATE SET value = meta.value + 1`)
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
	err := s.queryRow(`
SELECT COUNT(*),
       COALESCE(SUM(CASE WHEN ok=1 THEN 1 ELSE 0 END),0),
       COALESCE(SUM(CASE WHEN ok=0 THEN 1 ELSE 0 END),0),
       COALESCE(SUM(COALESCE(total_tokens,0)),0)
FROM requests`+where, args...).Scan(
		&out.TotalRequests, &out.TotalOK, &out.TotalFailed, &out.TotalTokens)
	if err != nil {
		return nil, err
	}

	rows, err := s.query(`
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

	rows2, err := s.query(`
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
	rows, err := s.query(`
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
