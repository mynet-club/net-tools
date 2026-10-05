package store

import (
	"database/sql"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// DB 是**通用数据库操作界面**：server / CLI / UI 只认这一层，
// 不感知底下是 SQLite、MySQL 还是 PostgreSQL。
//
// 以前业务包直接握着 *Store 具体类型，换驱动就得改所有签名；收成接口之后：
//   - 测试可以塞假实现；
//   - 方言差异关在 Dialect 里；
//   - 事务边界、金额口径（RowCharge）继续由本包保证。
//
// 实现体是 *Store（见 store.go）。新增方法时：先加进接口，再在 *Store 上落现，
// 否则 var _ DB = (*Store)(nil) 会在编译期报出来。
type DB interface {
	// ── 用户与授权 ──────────────────────────────────────────────
	CreateUser(name, tokenHash string) error
	GetUser(name string) (*User, error)
	GetUserByTokenHash(hash string) (*User, error)
	ListUsers() ([]User, error)
	SetUserEnabled(name string, enabled bool) error
	SetUserMode(name, mode string) error
	SetUserToken(name, tokenHash string) error
	DeleteUser(name string) error
	Revision() (int64, error)

	// ── 用户自有上游 / 模型映射 ────────────────────────────────
	UpsertUserProvider(p UserProvider) error
	ListUserProviders(userName string) ([]UserProvider, error)
	DeleteUserProvider(userName, name string) (bool, error)
	ListAllUserProviders() (map[string][]UserProvider, error)
	UpsertUserModel(m UserModel) error
	ListUserModels(userName string) ([]UserModel, error)
	DeleteUserModel(userName, model string) (bool, error)
	ClearUserModels(userName string) (int64, error)
	ListAllUserModels() (map[string][]UserModel, error)

	// ── 请求账本与用量 ─────────────────────────────────────────
	InsertRequest(rec RequestRecord) error
	Stats(since time.Time, recentLimit int) (*Stats, error)
	// Prune 按 database.retain_days 清**请求明细**（requests 表）。
	//
	// 审计表不在这条路上：audit_log 没有清理器，2026-10-05 裁决认永久保留。
	Prune(retainDays int) (int64, error)

	// ── 价目（上游成本 / 分发价，都带历史） ────────────────────
	//
	// §2.7 规则 8 在这一块已经收干净：分发价只有 ScopePrice 一种形状、只有下面那组
	// ScopePrice* 方法一个入口。2.x 的 'default' / 'user:<名>' 前缀适配层
	// （UserPrice 结构、InsertUserPrice / UserPriceAt / UserPricesEffective /
	// ListUserPrices / HasEffectiveUserPrices，以及 ScopeDefault / ScopeUser 两个常量）
	// 全部删除 —— 取价的「本人范围 → 全局默认」回落现在由 ScopePriceAtChain 按
	// specificity 链条给出，全局兜底就是 (system, 'global')。
	//
	// 还剩两处**刻意保留**的旧约定，都不在运行时的读写主线上：
	//   - DecodeLegacyPriceScope：只服务一次性迁移（读 2.x 库里那列 scope 串）。
	//   - resolveRequestScope 里 UserName → (user, 名)：§2.7 规则 3 的归属口径，
	//     是在线调用方没带 Scope 时唯一允许的推导点，集中在这一处。
	//
	// 其余三块的收口状态：
	//   - 审计：无范围的 Audit/AuditRecent 已删，写侧只剩 AuditScope，读侧三条都返回带范围的条目。
	//   - 熔断：ProviderStatus/SaveProviderStatus/LoadProviderStatus 已删，桶状态只有
	//     ProviderBucketState 一种形状，键就是 (scope_kind, scope_id, provider)。
	//   - 用量：按 user_name 读 usage_user_daily 的那五条（UsageByUser / TotalByUser /
	//     SystemUsageSince / SystemUsageRowsSince / UsageExportRows + MonthlyRollup）已删。
	//     用量只有 usage_scope_daily 一个读源，「某个人的账」就是 (user, 名) 那一桶；
	//     InsertRequest 也不再双写老表。
	//
	// 配额侧已经没有遗留项可删了：2.x 的 SetUserQuota/SetUserLimits 与「读不到配额行就
	// 回读 users 额度列」的兜底随规则 8 一起删掉，写侧只剩 SetScopeQuota/PatchScopeQuota。
	InsertProviderPrice(p *ProviderPrice) error
	ProviderPriceAt(provider, upstreamModel string, t time.Time) (*ProviderPrice, error)
	ProviderPricesEffective(t time.Time) ([]ProviderPrice, error)
	ListProviderPrices(provider, upstreamModel string) ([]ProviderPrice, error)

	// ── 3.0 结构化 scope API（§2.7：新增的唯一入口，一律收 policy.ScopeRef/ScopeChain）──
	// 路由桶 (scope_kind, scope_id, provider) 的熔断状态
	SaveProviderBucketStates(states []ProviderBucketState) error
	LoadProviderBucketStates() ([]ProviderBucketState, error)
	LoadProviderBucketsForScope(scope policy.ScopeRef) ([]ProviderBucketState, error)
	DeleteProviderBucketsForScope(scope policy.ScopeRef) (int64, error)

	// 分发价：按范围键定，「最具体的那条生效」
	InsertScopePrice(p *ScopePrice) error
	ScopePriceAt(scope policy.ScopeRef, model string, t time.Time) (*ScopePrice, error)
	ScopePriceAtChain(chain policy.ScopeChain, model string, t time.Time) (*ScopePrice, error)
	ListScopePrices(scope policy.ScopeRef, model string) ([]ScopePrice, error)
	ListAllScopePrices(t time.Time) ([]ScopePrice, error)
	HasEffectiveScopePrices(t time.Time, scopes ...policy.ScopeRef) (bool, error)

	// 配额与限流：按范围
	SetScopeQuota(q ScopeQuota) error
	PatchScopeQuota(scope policy.ScopeRef, p QuotaPatch) error
	GetScopeQuota(scope policy.ScopeRef) (*ScopeQuota, error)
	ListScopeQuotas() ([]ScopeQuota, error)
	DeleteScopeQuota(scope policy.ScopeRef) (bool, error)

	// 用量：按范围的明细、汇总与导出
	UsageByScope(scope policy.ScopeRef, since, until time.Time) ([]ScopeUsageRow, error)
	AggregateScopeUsage(scopes []policy.ScopeRef, since, until time.Time) ([]UsageRow, error)
	ScopeUsageTotals(scopes []policy.ScopeRef, since, until time.Time) (UsageTotals, error)
	ScopeSystemUsage(scope policy.ScopeRef, since time.Time) (SystemUsage, error)
	ScopeSystemUsageRows(scope policy.ScopeRef, since time.Time) ([]UsageRow, error)
	ScopeChargeTotal(scope policy.ScopeRef, since, until time.Time, cost CostFunc) (float64, error)
	ScopeUsageExportRows(scope policy.ScopeRef, since, until time.Time) ([]ScopeUsageRow, error)
	AllScopesUsageExportRows(since, until time.Time) ([]ScopeUsageRow, error)
	ScopeMonthlyRollup(scope policy.ScopeRef, since, until time.Time) ([]ScopeMonthlyRollupRow, error)
	AllScopesMonthlyRollup(since, until time.Time) ([]ScopeMonthlyRollupRow, error)

	// 审计：写侧一律带范围；读侧全量那条也返回带范围的条目
	AuditScope(scope policy.ScopeRef, actor, action, target, detail string) error
	AuditRecentAll(n int) ([]ScopedAuditEntry, error)
	AuditRecentByScope(scope policy.ScopeRef, n int) ([]ScopedAuditEntry, error)
	AuditRecentForScopes(scopes []policy.ScopeRef, n int) ([]ScopedAuditEntry, error)
	// AuditVolume 是审计表的规模读数（全表聚合，只给低频观测面用）。
	//
	// Prune 不清这张表：retain_days 只管请求明细，审计行是 2026-10-05 裁决的
	// 「永久保留」承诺，代价由这两位数在 /healthz 与 /metrics 上兑现。
	AuditVolume() (AuditVolume, error)

	// 在线请求的路由痕迹（§2.8）
	RoutingTraceForRequest(requestID string) (*RoutingTrace, error)

	// scope 结构的落地版本（接线时用它判断「这个库已经是 3.0 形状了」，而不是探测列名）
	AppliedScopeSchemaVersion() (int64, error)

	// ── 杂项 ───────────────────────────────────────────────────
	// DB 暴露底层 *sql.DB，仅供 store 包内的迁移与测试；
	// 业务代码**不要**拿它执行 SQL（那是方言层的事）。
	DB() *sql.DB
	Close() error
}

// 断言 *Store 实现 DB —— 接口改了而实现没跟上时，编译期就会红。
var _ DB = (*Store)(nil)
