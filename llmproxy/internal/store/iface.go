package store

import (
	"database/sql"
	"time"
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
	SetUserQuota(name string, tokens int64, cost float64) error
	SetUserLimits(name string, rpm, maxConcurrent int) error
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
	UsageByUser(since time.Time, userName string) ([]UsageRow, error)
	TotalByUser(since time.Time, userName string) (UserTotals, error)
	SystemUsageSince(userName string, since time.Time) (SystemUsage, error)
	SystemUsageRowsSince(userName string, since time.Time) ([]UsageRow, error)
	Prune(retainDays int) (int64, error)

	// ── 价目（上游成本 / 分发价，都带历史） ────────────────────
	InsertProviderPrice(p *ProviderPrice) error
	ProviderPriceAt(provider, upstreamModel string, t time.Time) (*ProviderPrice, error)
	ProviderPricesEffective(t time.Time) ([]ProviderPrice, error)
	ListProviderPrices(provider, upstreamModel string) ([]ProviderPrice, error)
	InsertUserPrice(p *UserPrice) error
	UserPriceAt(userName, model string, t time.Time) (*UserPrice, error)
	UserPricesEffective(t time.Time) ([]UserPrice, error)
	ListUserPrices(scope, model string) ([]UserPrice, error)
	HasEffectiveUserPrices(userName string, t time.Time) (bool, error)

	// ── 熔断状态 ───────────────────────────────────────────────
	SaveProviderStatus(statuses []ProviderStatus) error
	LoadProviderStatus() ([]ProviderStatus, error)

	// ── 杂项 ───────────────────────────────────────────────────
	// DB 暴露底层 *sql.DB，仅供 store 包内的迁移与测试；
	// 业务代码**不要**拿它执行 SQL（那是方言层的事）。
	DB() *sql.DB
	Close() error
}

// 断言 *Store 实现 DB —— 接口改了而实现没跟上时，编译期就会红。
var _ DB = (*Store)(nil)
