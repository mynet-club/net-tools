package store

import (
	"fmt"
	"sort"
	"strings"
)

// 3.0 scope 结构化后的表结构（手册 §2.7）。
//
// 全部以 SQLite 方言书写，由 Dialect.RewriteDDL 翻译成 MySQL/PostgreSQL —— 与其余表同一套做法。
//
// 列宽刻意写成 VARCHAR(n) 而不是 TEXT，两个理由：
//  1. MySQL 的 utf8mb4 按每字符 4 字节算索引宽度，复合主键用默认改写出来的 VARCHAR(128)
//     会撞 max key length 3072（本文件里最宽的键是 usage_scope_daily 的 7 列主键）；
//  2. scope_id 的上界由 internal/policy 的 maxScopeIDLen = 256 决定，这里写死同一个数，
//     才不会出现「Go 侧校验通过、MySQL 建索引时才发现放不下」的两套口径。

// providerStatsBody30 是 3.0 的熔断状态表定义。
//
// 主键就是 §2.7 规则 4 的**路由桶最终键** (scope_kind, scope_id, provider) ——
// provider_stats.name 存的正是桶的 provider 那一腿（全局池的供应商名 / 该用户自有的上游名），
// 所以桶状态天然按桶唯一，不需要再造一个并行的唯一索引。
//
// 单独抽成 body 常量：一次性迁移重建这张表时必须复用同一份定义，避免两处走样
// （与 usageUserDailyBody 同一套做法）。
const providerStatsBody30 = `  scope_kind           VARCHAR(16)   NOT NULL,
  scope_id             VARCHAR(256)  NOT NULL,
  name                 VARCHAR(191)  NOT NULL,
  enabled              INTEGER NOT NULL DEFAULT 1,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  unhealthy_until      INTEGER NOT NULL DEFAULT 0,
  last_error           TEXT,
  last_success_at      INTEGER,
  last_failure_at      INTEGER,
  total_requests       INTEGER NOT NULL DEFAULT 0,
  total_failures       INTEGER NOT NULL DEFAULT 0,
  updated_at           INTEGER NOT NULL,
  PRIMARY KEY (scope_kind, scope_id, name)`

// providerStatsDDL30 是完整建表语句（迁移里重建用）。
const providerStatsDDL30 = `CREATE TABLE provider_stats (
` + providerStatsBody30 + `
)`

// scopeSchema30 是 3.0 新增的表：按 scope 键定的配额与用量聚合。
//
// 刻意**不改写** users / usage_user_daily 的既有行（§2.7 规则 5「历史明细的归属不改变」）：
// 这两张新表是**叠加维度**，配额从 users 回填、聚合从 usage_user_daily 回填，
// 老报表与老账本继续按原样可读。
const scopeSchema30 = `
CREATE TABLE IF NOT EXISTS scope_quota (
  scope_kind         VARCHAR(16)   NOT NULL,
  scope_id           VARCHAR(256)  NOT NULL,
  quota_month_tokens INTEGER NOT NULL DEFAULT 0,
  quota_month_cost   REAL    NOT NULL DEFAULT 0,
  rpm                INTEGER NOT NULL DEFAULT 0,
  max_concurrent     INTEGER NOT NULL DEFAULT 0,
  enabled            INTEGER NOT NULL DEFAULT 1,
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL,
  PRIMARY KEY (scope_kind, scope_id)
);

CREATE TABLE IF NOT EXISTS usage_scope_daily (
  day                VARCHAR(10)   NOT NULL,
  scope_kind         VARCHAR(16)   NOT NULL,
  scope_id           VARCHAR(256)  NOT NULL,
  provider           VARCHAR(128)  NOT NULL,
  model              VARCHAR(128)  NOT NULL,
  upstream_model     VARCHAR(128)  NOT NULL DEFAULT '',
  system_paid        INTEGER NOT NULL DEFAULT 0,
  requests           INTEGER NOT NULL DEFAULT 0,
  ok                 INTEGER NOT NULL DEFAULT 0,
  failed             INTEGER NOT NULL DEFAULT 0,
  prompt_tokens      INTEGER NOT NULL DEFAULT 0,
  cache_hit_tokens   INTEGER NOT NULL DEFAULT 0,
  cache_miss_tokens  INTEGER NOT NULL DEFAULT 0,
  completion_tokens  INTEGER NOT NULL DEFAULT 0,
  total_tokens       INTEGER NOT NULL DEFAULT 0,
  latency_sum_ms     INTEGER NOT NULL DEFAULT 0,
  charge             REAL    NOT NULL DEFAULT 0,
  frozen_charges     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, scope_kind, scope_id, provider, model, upstream_model, system_paid)
);
CREATE INDEX IF NOT EXISTS idx_usage_scope_daily_day ON usage_scope_daily(day);
-- 桶维度（(scope, provider)）的择廉/熔断回看走这条；主键的前缀覆盖不了 provider 在后的查询
CREATE INDEX IF NOT EXISTS idx_usage_scope_daily_bucket ON usage_scope_daily(scope_kind, scope_id, provider, day);
`

// ------------------------------------------------------------------ 补列清单（新库与老库共用）

// scopeColumn 是一列的「列名 + SQLite 类型」。
//
// 这一份清单**同时**喂给两处：新库的建表 DDL（scopeColsFragment）与老库的
// ALTER TABLE ADD COLUMN（scopeColsMap）。写成两处曾经出现过「新库有列、老库补不上」
// 以及反过来「补了列但建表语句没加」，所以列定义只维护这一份。
type scopeColumn struct {
	name string
	typ  string
}

// requestsScopeCols30 是 §2.8 要求在线记录的路由字段 + §2.7 规则 2 的归属列。
//
// 全部**可空**：老行不回填归属，因为 2.x 的 requests 压根没有用户列，
// 猜出来的归属会污染账单（§2.7 规则 5）。NULL 就是「这条请求没有归属信息」——
// 新库写入时也照样可能为 NULL（静态 key、未启用多用户），不是迁移遗留。
// 同样也不回填 policy_version/routing_seed —— §2.8：旧请求没有 seed 时只能做解释性回放。
//
// 这里**没有任何正文/提示词类列**（§2.8/§2.9），scope_leak_test.go 把它变成会失败的断言。
var requestsScopeCols30 = []scopeColumn{
	{"scope_kind", "VARCHAR(16)"},
	{"scope_id", "VARCHAR(256)"},
	{"policy_version", "VARCHAR(64)"},
	{"routing_epoch", "VARCHAR(64)"},
	// routing_seed 是 policy.DeriveRoutingSeed 出来的 64 位十六进制串；digest 同形态
	{"routing_seed", "VARCHAR(64)"},
	{"candidates_digest", "VARCHAR(64)"},
}

// auditScopeCols30 是审计表的 scope 维度。
//
// 与 requests 相反：audit_log 在 2.x 只记管理员操作，那些操作**本来就**属于
// (system,'global')，所以默认值就是事实陈述而不是猜测 —— 老库 ADD COLUMN 时
// 各家方言都会用默认值填满既有行，一次到位，不需要额外 UPDATE 回填。
var auditScopeCols30 = []scopeColumn{
	{"scope_kind", "VARCHAR(16) NOT NULL DEFAULT 'system'"},
	{"scope_id", "VARCHAR(256) NOT NULL DEFAULT 'global'"},
}

// scopeColsFragment 生成建表语句里那段列定义（每行两空格缩进，行间用逗号）。
// base 那段必须以逗号结尾（见 store.go / audit.go 的写法）。
func scopeColsFragment(cols []scopeColumn) string {
	lines := make([]string, 0, len(cols))
	for _, c := range cols {
		lines = append(lines, fmt.Sprintf("  %-20s %s", c.name, c.typ))
	}
	return strings.Join(lines, ",\n")
}

// scopeColsMap 转成 addColumnsIfMissing 要的「列名 → 类型」形状。
func scopeColsMap(cols []scopeColumn) map[string]string {
	m := make(map[string]string, len(cols))
	for _, c := range cols {
		m[c.name] = c.typ
	}
	return m
}

// scopeColNames 是补列后的建索引/校验要用的稳定列序。
func scopeColNames(cols []scopeColumn) []string {
	names := make([]string, 0, len(cols))
	for _, c := range cols {
		names = append(names, c.name)
	}
	sort.Strings(names)
	return names
}

// scopeIndexDDL30 是补列之后要建的索引（分开执行：各家 ALTER 不支持附带索引）。
//
// requests 的桶索引覆盖 (scope_kind, scope_id, provider, ts) —— §2.7 规则 4 的桶最终键就是它，
// 按范围回看某个供应商的时间序列不再需要全表扫。
//
// 每条各带自己的表名，因为**这三张表都是既有表**：一次性迁移必须能在「列还没补上」
// 或「老库压根没建过这张表」时逐条判断（见 execScopeIndexes），不能整段执行。
// 三条都写成 IF NOT EXISTS 以便重复执行；MySQL 没有这个标记，RewriteDDL 会去掉，
// 重复建同名索引的 1061 由 execSchema 吞掉。
type scopeIndexDDL struct {
	table string
	ddl   string
}

var scopeIndexDDL30 = []scopeIndexDDL{
	{"requests", "CREATE INDEX IF NOT EXISTS idx_requests_scope_bucket ON requests(scope_kind, scope_id, provider, ts)"},
	{"audit_log", "CREATE INDEX IF NOT EXISTS idx_audit_scope ON audit_log(scope_kind, scope_id, ts)"},
	{"user_prices", "CREATE INDEX IF NOT EXISTS idx_user_prices_scope ON user_prices(scope_kind, scope_id, model, valid_from)"},
}

// userPricesScopeCols30 是分发价的范围两列：老库用 ALTER 补，新库直接写在 DDL 里。
//
// 与 requests 不同，这两列是 NOT NULL 且**没有默认值可给** —— 一行的范围必须显式算出来
// （映射规则见 scope_migration.go），所以补列时先带空默认、由迁移回填，回填后收口校验。
var userPricesScopeCols30 = []scopeColumn{
	{"scope_kind", "VARCHAR(16) NOT NULL DEFAULT ''"},
	{"scope_id", "VARCHAR(256) NOT NULL DEFAULT ''"},
}
