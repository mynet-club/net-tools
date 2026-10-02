package store

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 3.0 结构化 scope 在存储层的落点（手册 §2.7）。
//
// 本文件是**唯一**允许在 store 里读写「字符串 scope」的地方：2.x 用 `provider_stats.scope`
// 存裸用户名、用 `user_prices.scope` 存 'default' / 'user:<名>' 前缀约定，两种约定互不相通。
// 3.0 一律拆成 scope_kind + scope_id 两列（规则 1：禁止把两者再拼回一个字符串），
// 旧 API 靠本文件的 decode/encode 适配 —— 每个 encode 都标了「主线接线完成后删除」。

// ScopeSchemaVersion 是本包 scope 结构的版本，落在 meta 的 scope_schema_version 行。
//
// 它和 replay 的记录文件版本、config 的 config_schema_version 是三套独立编号；
// 放这里的目的是让主线接线时能用一次读库判断「这个库升到 3.0 的 scope 形状了没有」，
// 而不是靠探测列名。取值 3 对齐 3.0。
const ScopeSchemaVersion int64 = 3

// meta 表里与 scope 迁移相关的键。
//
// 只有整数键：meta 的 value 列是 INTEGER，文本存不进去。备份文件路径与它的 SHA-256
// 因此**不进 meta** —— 它们进迁移日志（scopeMigrationOutput）与 ScopeMigrationReport
// （运维脚本 `--check` 拿得到的 JSON）。备份文件名本身带库路径与 Unix 毫秒，可 glob：
// `<库文件>.pre-scope-<ms>.bak`，不需要库内再记一份指针（记了反而是第二个真相源）。
const (
	metaScopeSchemaVersion = "scope_schema_version"
	metaScopeMigratedAt    = "scope_migrated_at" // Unix 毫秒：meta.value 是整数列，RFC3339 存不进去
)

// 旧字符串 scope 的字面量，只有这一处定义。
const (
	legacyProviderScopeGlobal = ""        // provider_stats：空串 = 全局配置里的供应商
	legacyPriceScopeDefault   = "default" // user_prices：全局默认分发价
	legacyPriceScopeUserPfx   = "user:"   // user_prices：单用户覆盖前缀
)

var (
	// ErrScopeRequired 表示传入了零值 ScopeRef。落库必须有范围，缺了就报错而不是补一个默认值 ——
	// 补默认值会把「调用方忘了传 scope」变成「静默写进全局桶」，那是最难查的一类脏数据。
	ErrScopeRequired = errors.New("store: 缺少 scope（零值 ScopeRef）")
	// ErrLegacyScope 表示旧字符串 scope 无法映射到 3.0 的结构化范围。
	ErrLegacyScope = errors.New("store: 无法映射的旧 scope 取值")
)

// checkScope 校验范围引用并包装成带上下文的错误。
// 校验口径完全交给 policy.ScopeRef.Validate（闭集 + ID 规则），本包不另立一套。
func checkScope(where string, scope policy.ScopeRef) error {
	if scope.Kind == "" && scope.ID == "" {
		return fmt.Errorf("%w: %s", ErrScopeRequired, where)
	}
	if err := scope.Validate(); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	return nil
}

// hasScope 报告是否给了一个非零范围（零值 = 调用方没打算归属到任何范围）。
func hasScope(scope policy.ScopeRef) bool { return scope.Kind != "" || scope.ID != "" }

// scopeArgs 把范围摊成 SQL 参数（顺序恒为 kind, id）。
// 只有这一处负责列序，避免各查询各写一遍写反。
func scopeArgs(scope policy.ScopeRef) []any { return []any{string(scope.Kind), scope.ID} }

// isSystemScope 报告是否是那个唯一的系统范围（等价于 policy.SystemScope）。
func isSystemScope(scope policy.ScopeRef) bool { return scope.Is(policy.SystemScope) }

// isScopeParam 报告一个 SQL 读回来的 scope 列是否可用。
// requests 的可空列在 3.0 之前是 NULL（= 无归属信息），扫进来就是空串。
func isScopeParam(kind, id string) bool { return kind != "" && id != "" }

// ------------------------------------------------------------------ 旧约定编解码
//
// 这一节只剩**升级迁移**要用的解码：运行时读写一律走 (scope_kind, scope_id)，
// 旧字符串只在「读一份 2.x 的表」时出现。反向编码随旧 API 一起删掉了。

// decodeLegacyProviderScope 把 provider_stats 的旧 scope 串映射成结构化范围：
//
//	''          → (system, 'global')     全局配置里的供应商
//	'<用户名>'   → (user, '<用户名>')      该用户自有的上游
//
// 只有迁移（scope_migration.go）用它：老库那一列还在的时候，取值就这两种形状。
// 用户名必须本身就是一个合法的 scope ID（policy 禁冒号/控制字符）。老库里若存在含冒号的
// 用户名，这里必须报错而不是清洗 —— 清洗等于把两个不同的主体并成一个桶。
func decodeLegacyProviderScope(s string) (policy.ScopeRef, error) {
	if s == legacyProviderScopeGlobal {
		return policy.SystemScope, nil
	}
	return policy.NewScopeRef(policy.ScopeUser, s)
}

// legacyUserScope 把「用户名」这个 2.x 的主体标识落成 (user, 名)。
//
// 用户请求归属、分发价回落、配额镜像都走这一处 —— 「谁是这个主体」在 store 里
// 只有一种写法，不留第二个解析点。名字非法（空、含冒号/控制字符）时返回错误，
// 调用方按「查不到」处理，不猜一个默认范围。
func legacyUserScope(userName string) (policy.ScopeRef, error) {
	name := strings.TrimSpace(userName)
	if name == "" {
		return policy.ScopeRef{}, fmt.Errorf("%w: 用户名为空，无归属范围", ErrScopeRequired)
	}
	return policy.NewScopeRef(policy.ScopeUser, name)
}

// DecodeLegacyPriceScope 把 user_prices 的旧 scope 串映射成结构化范围：
//
//	'default'      → (system, 'global')
//	'user:<名>'    → (user, '<名>')
//
// 导出它的唯一理由：分发价的管理接口收到的还是旧串，而写审计必须有范围 ——
// 让 server 自己再解析一遍 'default' / 'user:' 前缀就是跨包复制业务规则。
//
// §2.7 规则 8：随旧分发价接口一起删除（调用方改用结构化 ScopePrice 后无人需要解析旧串）。
func DecodeLegacyPriceScope(s string) (policy.ScopeRef, error) {
	switch {
	case s == legacyPriceScopeDefault:
		return policy.SystemScope, nil
	case strings.HasPrefix(s, legacyPriceScopeUserPfx):
		return policy.NewScopeRef(policy.ScopeUser, strings.TrimPrefix(s, legacyPriceScopeUserPfx))
	default:
		return policy.ScopeRef{}, fmt.Errorf("%w: %q（旧约定只认 %q 与 %q<用户名>）",
			ErrLegacyScope, s, legacyPriceScopeDefault, legacyPriceScopeUserPfx)
	}
}

// encodeLegacyPriceScope 是反向映射，只服务旧 API 的 UserPrice.Scope 裸串字段。
//
// §2.7 规则 8：主线接线完成后删除。
func encodeLegacyPriceScope(scope policy.ScopeRef) (string, error) {
	switch {
	case isSystemScope(scope):
		return legacyPriceScopeDefault, nil
	case scope.Kind == policy.ScopeUser:
		return legacyPriceScopeUserPfx + scope.ID, nil
	default:
		return "", fmt.Errorf("%w: 旧分发价接口无法表达 %s", ErrLegacyScope, scope.Display())
	}
}

// ------------------------------------------------------------------ 结构化对象

// scopeOrder 是范围 specificity 的固定次序：越靠前越具体。
//
// 分发价的「最具体的那条生效」沿用 2.x 口径，只是键从字符串前缀换成了结构化范围。
// 层级归属（谁的父是谁）不在本包：由身份层（工作包 B）展开成 ScopeChain 传进来。
var scopeOrder = map[policy.ScopeKind]int{
	policy.ScopeUser:         0,
	policy.ScopeProject:      1,
	policy.ScopeOrganization: 2,
	policy.ScopeSystem:       3,
}

func scopeSpecificity(scope policy.ScopeRef) int {
	if r, ok := scopeOrder[scope.Kind]; ok {
		return r
	}
	return len(scopeOrder)
}

// ProviderBucketState 是一个路由桶 (scope, provider) 的熔断运行期状态。
//
// 字段与持久化列一一对应；Scope 是结构化范围，Name 是桶的 provider 那一腿
// （全局池的供应商名或该用户自有的上游名）。
type ProviderBucketState struct {
	Scope               policy.ScopeRef
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

// bucketKey 只给日志与测试断言用，禁止当存储键（§2.7 规则 1）。
func (b ProviderBucketState) bucketKey() string {
	return b.Scope.Display() + "/" + b.Name
}

// ScopePrice 是一条**按范围键定**的分发价目行（3.0 形态）。
//
// 与旧的 UserPrice 的区别只有范围：旧的那份用 'default' / 'user:<名>' 字符串前缀约定，
// 这一份直接带 policy.ScopeRef，因此组织级、项目级分发价在存储层第一次有了表达形式。
// 价目行仍按时间只追加、整点生效（口径与 2.x 一致，见 docs/pricing-design.md）。
type ScopePrice struct {
	ID            int64
	Scope         policy.ScopeRef
	Model         string
	Currency      string
	InMiss        float64
	InHit         float64
	InWrite       float64
	Out           float64
	ReasoningOut  float64
	PerRequestFee float64
	PeakHours     []string
	OffPeakRatio  *float64
	PeakTZ        string
	ValidFrom     time.Time
	ValidTo       time.Time // 零值 = 一直有效
	Note          string
	CreatedAt     time.Time
}

// ToLegacy 把结构化行摊回旧的 UserPrice，只给旧读路径用。
//
// §2.7 规则 8：主线接线完成后删除。
func (p *ScopePrice) ToLegacy() *UserPrice {
	scope, err := encodeLegacyPriceScope(p.Scope)
	if err != nil {
		// 组织/项目级的行在旧接口里没有对应字面量：留空串，旧调用方按「未知作用域」处理，
		// 不会被误当成 default（default 会被旧取价逻辑当成全局兜底而错用报价）。
		scope = ""
	}
	return &UserPrice{
		ID: p.ID, Scope: scope, Model: p.Model, Currency: p.Currency,
		InMiss: p.InMiss, InHit: p.InHit, InWrite: p.InWrite, Out: p.Out,
		ReasoningOut: p.ReasoningOut, PerRequestFee: p.PerRequestFee,
		PeakHours: p.PeakHours, OffPeakRatio: p.OffPeakRatio, PeakTZ: p.PeakTZ,
		ValidFrom: p.ValidFrom, ValidTo: p.ValidTo, Note: p.Note, CreatedAt: p.CreatedAt,
	}
}

// ScopeQuota 是一个范围的月度配额与限流设置。0 一律表示「不限」（沿用 2.x 口径）。
//
// user 范围的行与 users 表一一对应（迁移时回填、旧写路径双写），
// organization / project 范围的行是 3.0 新增能力 —— 2.x 没有地方放组织级配额。
type ScopeQuota struct {
	Scope            policy.ScopeRef
	QuotaMonthTokens int64
	QuotaMonthCost   float64
	RPM              int
	MaxConcurrent    int
	Enabled          bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// ScopedAuditEntry 是一条带范围的审计。Detail 沿用旧口径：不许写密钥明文。
type ScopedAuditEntry struct {
	Ts     time.Time       `json:"ts"`
	Scope  policy.ScopeRef `json:"scope"`
	Actor  string          `json:"actor"`
	Action string          `json:"action"`
	Target string          `json:"target"`
	Detail string          `json:"detail"`
}

// RoutingTrace 是一次在线请求的路由决策痕迹（§2.8 要求在线至少记录的那些）。
//
// 只含摘要与版本，**不含正文**：有 seed 才谈得上逐位复现，没 seed 只能做解释性回放。
type RoutingTrace struct {
	RequestID        string
	Scope            policy.ScopeRef
	PolicyVersion    string
	RoutingEpoch     string
	RoutingSeed      string
	CandidatesDigest string
}
