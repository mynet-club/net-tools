package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 3.0 §2.7 的一次性 scope 迁移。
//
// # 它做什么
//
// 把 2.x 的两套字符串作用域约定搬进结构化的 (scope_kind, scope_id)：
//
//	provider_stats.scope  ''（全局）      → (system, 'global')
//	provider_stats.scope  '<用户名>'       → (user, '<用户名>')
//	user_prices.scope     'default'       → (system, 'global')
//	user_prices.scope     'user:<用户名>'  → (user, '<用户名>')
//	users 的配额列 quota_month_tokens / quota_month_cost / rpm / max_concurrent
//	                     → scope_quota 的 (user, 名) 行；enabled 一并作为该行的初值
//	                       （一次性映射，不是镜像：账号可用性留在 users，见下）
//	                     回填完成后那四列从 users 上**删掉**（§2.7 规则 8 的旧字段退役）
//	users.enabled        → 留在 users（身份事实），同时作为配额行 enabled 的初值
//	users 没有那四列（比消费模式更早的库）
//	                     → 照样补出全 0（= 不限）的配额行：「每个 user 都有一行」是
//	                       3.0 读路径的前提，不是旧库才有的负担
//	usage_user_daily.user_name             → usage_scope_daily 的 scope_kind='user' + scope_id=名
//	audit_log 既有行                       → (system, 'global')（2.x 只记管理员的全局操作）
//	requests 既有行                        → **不回填**（见下）
//
// 映射规则封闭、可核对，判定只在 preflightScopeMapping 与回填那两处，且复用 scope.go
// 的解码器 —— 「预检放行」与「写入落点」不可能各按一套口径。
// 映射不出来的取值（例如 provider_stats.scope='team:ops'、用户名里含冒号）是**硬失败**：
// 清洗等于把两个不同主体并成一个路由桶，那比迁移失败严重得多。
//
// # 为什么 requests 不回填
//
// 2.x 的 requests 表压根没有用户列（只有 client_key_hash 与 client_label），
// 猜出来的归属会污染账单（§2.7 规则 5）。所以新列一律 NULL，迁移报告以
// UnknownAttribution 计数**明示**有多少条历史请求没有归属，而不是静默跳过。
// policy_version / routing_seed 同样不回填 —— §2.8：旧请求没有 seed 时只能做解释性回放。
//
// # 失败就不启动
//
// 校验不过 → 自动补偿回滚（把已执行的每一步反向做一遍）→ 返回错误，OpenDialect 随之失败。
// SQLite 另有一层文件级备份：迁移前整库复制 + SHA-256（记进 meta 与日志），
// 补偿不彻底时**用文件还原**；还原后仍然报错退出，绝不带着半迁移的库继续跑。
// MySQL / PostgreSQL **不假装能自动 dump**：只打印外部 dump 入口，并把重命名出来的
// 影子表（_provider_stats_pre30）留在库里作为第二份数据，附上清理 SQL。
//
// # 表名为什么不改成 scope_prices
//
// user_prices 到 3.0 的语义已经是「按范围键定的分发价」，改名更贴切，但本工作包只能写
// internal/store/ 与一个新脚本：README、docs/pricing-design.md、docs/OVERVIEW.md、UI 与 CLI
// 文案都在可改范围之外，改表名会让那一堆文档与库内实名对不上。Go 侧的调用点也一份没少 ——
// UserPrice / InsertUserPrice 这些名字最终是**被删掉**的，不是被改名的。
// 所以这里只做「列换代 + 索引换代」，表名留给主线接线那一步统一处理。

// scopeMoneyTolerance 是金额守恒的浮点容差（单位：元）。
//
// 迁移前后是同一批行，但求和顺序会变（老表按用户键扫、新表按范围键扫），
// 而浮点加法不满足结合律。取 1e-6 元：远小于任何真实记账差异（最小档位也在 1e-3 元级），
// 又足够吸收求和顺序带来的噪声。超过这个量就不是浮点问题，是真丢了行。
const scopeMoneyTolerance = 1e-6

// legacyProviderStatsShadow 是重建 provider_stats 时改名出来的影子表。
// 名字带 pre30 而不是 tmp：运维在库里看到它就该明白「这是 3.0 迁移前的那一代形状」。
const legacyProviderStatsShadow = "_provider_stats_pre30"

var (
	// scopeMigrationFault 是**只在测试里**用的注入钩子：对某个检查名返回错误，
	// 把「DDL 已经做完之后才失败」这条路径变成可运行的测试（见 scope_migration_test.go）。
	// 生产代码不设置它 —— nil 表示没有故障。
	scopeMigrationFault func(check string) error

	// scopeMigrationOutput 是运维提示的去向。默认 stderr：外部 dump 入口、备份位置与
	// 影子表清理 SQL 必须出现在启动日志里，而不是等有人去翻文档。
	scopeMigrationOutput io.Writer = os.Stderr
)

// ErrScopeMigration 是迁移失败的基错：调用方据此区分「结构问题」与「连接问题」。
var ErrScopeMigration = errors.New("store: scope 迁移失败")

// ScopeMigrationReport 是一次迁移（或一次只读体检）的可核对结果。
//
// 成对出现的 Before/After 必须相等，否则对应检查项就失败了。导出是为了让运维脚本
// 能在**动手之前**先拿到这些数字，而不是事后从日志里刨。
type ScopeMigrationReport struct {
	Driver     string `json:"driver"`
	Location   string `json:"location,omitempty"`
	From30Only bool   `json:"from_30_only"` // 结构已是 3.0 形状（只有版本号要落 / 已迁完）

	// 检查 ①：行数守恒。
	ProviderStatsBefore int64 `json:"provider_stats_before"`
	ProviderStatsAfter  int64 `json:"provider_stats_after"`
	UserPricesBefore    int64 `json:"user_prices_before"`
	UserPricesAfter     int64 `json:"user_prices_after"`
	RequestsBefore      int64 `json:"requests_before"`
	RequestsAfter       int64 `json:"requests_after"`
	UsersBefore         int64 `json:"users_before"`
	ScopeQuotaRows      int64 `json:"scope_quota_rows"`
	UsageScopeRows      int64 `json:"usage_scope_daily_rows"`

	// 检查 ③：金额守恒（RowCharge 口径，cost 传 nil —— 迁移期没有价目上下文，
	// 冻结值原样相加，未冻结段按估算兜底为 0，两张表走的是同一份实现）。
	ChargeUser  float64 `json:"charge_user"`
	ChargeScope float64 `json:"charge_scope"`

	// 检查 ④：归属覆盖。
	MappedBuckets      int64    `json:"mapped_buckets"`      // provider_stats 映射出的桶数
	MappedPrices       int64    `json:"mapped_prices"`       // user_prices 映射出的价目行数
	UnknownAttribution int64    `json:"unknown_attribution"` // requests 里 scope 为 NULL 的行（刻意的）
	OrphanScopeRows    int64    `json:"orphan_scope_rows"`   // (user,名) 在 users 里查不到的行（只报告）
	OrphanSources      []string `json:"orphan_sources,omitempty"`

	// 备份与恢复入口。
	BackupPath   string `json:"backup_path,omitempty"`
	BackupSHA256 string `json:"backup_sha256,omitempty"`
	ExternalDump string `json:"external_dump,omitempty"` // 非 SQLite：必须由运维执行的 dump 入口
}

// ------------------------------------------------------------------ 形状快照

// scopeSchemaState 是相关各表的形状快照：每个布尔决定一个阶段要不要执行。
type scopeSchemaState struct {
	providerStats       bool // 表存在
	providerStatsLegacy bool // 有 scope 列（2.x 形状）
	providerStats30     bool // 有 scope_kind 列（3.0 形状）
	userPrices          bool
	userPricesLegacy    bool
	userPrices30        bool
	requests30          bool
	audit30             bool
	usageUserDaily      bool // 回填来源
	scopeQuota          bool // 目标表已存在（可能是上一轮跑到一半留下的）
	usageScopeDaily     bool
	// usersQuotaLegacy 是 users 上还留着 2.x 那四列配额/限流列。它只决定**回填读哪份输入**
	// （旧列的值 vs 全 0 初值），不参与 needsWork —— 「有没有配额列」不是 2.x 账单形状的
	// 判据：比消费模式更早的库同样没有那四列，把它的行搬对靠的是收口校验而不是列探测。
	usersQuotaLegacy bool
}

// needsWork 报告**既有表**是否还是 2.x 形状（要不要动数据/重建表）。
//
// scope_quota / usage_scope_daily 是叠加的派生表，由 execScopeDerived 无条件补齐，
// 不参与这里的判定 —— 否则全新库第一次打开也会走完整迁移（含文件备份），
// 而那条路径的语义是「这个库有过账单，我要搬它」。
func (st scopeSchemaState) needsWork() bool {
	return st.providerStatsLegacy || st.userPricesLegacy || !st.requests30 || !st.audit30
}

// pendingTablesConflict 检出「同一张表同时有两代形状」这种没法自动判定的状态。
//
// 正常流程造不出它（改名与补列都成对完成）。撞上了就交给人来看 ——
// 自动挑一个解释，等于在一份有真实账单的库上赌一把。
func (st scopeSchemaState) pendingTablesConflict() error {
	if st.providerStatsLegacy && st.providerStats30 {
		return fmt.Errorf("%w：provider_stats 同时有 scope 与 scope_kind 两列，无法判定当前形状；"+
			"请先确认哪一代是真的（影子表 %s 可能没清理干净）", ErrScopeMigration, legacyProviderStatsShadow)
	}
	if st.userPricesLegacy && st.userPrices30 {
		return fmt.Errorf("%w：user_prices 同时有 scope 与 scope_kind 两列 —— "+
			"这是「迁移做完但版本号没落」的中间态，旧列的删除步骤没跑完", ErrScopeMigration)
	}
	return nil
}

func loadScopeSchemaState(db *sql.DB, d Dialect) (scopeSchemaState, error) {
	var st scopeSchemaState
	var err error
	if st.providerStats, err = d.HasTable(db, "provider_stats"); err != nil {
		return st, err
	}
	if st.providerStats {
		if st.providerStatsLegacy, err = d.HasColumn(db, "provider_stats", "scope"); err != nil {
			return st, err
		}
		if st.providerStats30, err = d.HasColumn(db, "provider_stats", "scope_kind"); err != nil {
			return st, err
		}
	}
	if st.userPrices, err = d.HasTable(db, "user_prices"); err != nil {
		return st, err
	}
	if st.userPrices {
		if st.userPricesLegacy, err = d.HasColumn(db, "user_prices", "scope"); err != nil {
			return st, err
		}
		if st.userPrices30, err = d.HasColumn(db, "user_prices", "scope_kind"); err != nil {
			return st, err
		}
	}
	if st.requests30, err = d.HasColumn(db, "requests", "scope_kind"); err != nil {
		return st, err
	}
	if st.audit30, err = d.HasColumn(db, "audit_log", "scope_kind"); err != nil {
		return st, err
	}
	if st.usageUserDaily, err = d.HasTable(db, "usage_user_daily"); err != nil {
		return st, err
	}
	// 只认 quota_month_tokens 一列代表整组：四列是同一个版本一起加的，
	// 而 HasColumn 在表不存在时返回 false，新库与老库都问得出结果，不用先判表在不在。
	if st.usersQuotaLegacy, err = d.HasColumn(db, "users", "quota_month_tokens"); err != nil {
		return st, err
	}
	if st.scopeQuota, err = d.HasTable(db, "scope_quota"); err != nil {
		return st, err
	}
	st.usageScopeDaily, err = d.HasTable(db, "usage_scope_daily")
	return st, err
}

// ------------------------------------------------------------------ 入口

// execScopeDerived 建两张叠加表（scope_quota / usage_scope_daily）与它们自己的索引。
// 全是 CREATE ... IF NOT EXISTS（MySQL 的重复索引名由 execSchema 吞 1061），可重复执行。
func execScopeDerived(db *sql.DB, d Dialect) error {
	return execSchema(db, d, scopeSchema30)
}

// execScopeIndexes 建挂在**既有表**上的范围索引（requests / audit_log / user_prices）。
//
// 必须由本文件来建：那三张表的 DDL 里刻意没写这几条 —— 老库的表这时还没有 scope_kind 列，
// 在 schema 阶段建会撞「列不存在」，让整个 Open 失败。
//
// 逐条判「表在不在、列在不在」：三条各自独立，某张表缺席（极老的库里没有审计表）
// 不该让另外两条也不建；而列不在意味着补列那一步没跑成，属于要报错的状态，
// 由后面的收口校验（scope_kind 空串/闭集检查）兜住，这里跳过不是放过。
func execScopeIndexes(db *sql.DB, d Dialect) error {
	for _, ix := range scopeIndexDDL30 {
		ok, err := d.HasTable(db, ix.table)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if has, err := d.HasColumn(db, ix.table, "scope_kind"); err != nil {
			return err
		} else if !has {
			continue
		}
		if err := execSchema(db, d, ix.ddl+";"); err != nil {
			return fmt.Errorf("建 %s 的范围索引失败: %w", ix.table, err)
		}
	}
	return nil
}

// migrateScopeSchema 执行 §2.7 的一次性 scope 迁移（幂等：版本号已落就直接返回）。
//
// pathOrDSN 只在 SQLite 下用于文件备份。其它方言只打印外部 dump 入口 ——
// 本函数不会替运维做逻辑备份，也不假装做了。
func migrateScopeSchema(db *sql.DB, d Dialect, pathOrDSN string) error {
	cur, err := metaInt(db, d, metaScopeSchemaVersion)
	if err != nil {
		return err
	}
	if cur >= ScopeSchemaVersion {
		// 已经迁完：派生表与范围索引再补一次（幂等）。用外部逻辑备份恢复过库的人
		// 可能只恢复了部分结构，这两句把缺的派生表补回来，而不是等第一次写入报错。
		if err := execScopeDerived(db, d); err != nil {
			return fmt.Errorf("%w: 补建 scope 派生表失败: %w", ErrScopeMigration, err)
		}
		if err := execScopeIndexes(db, d); err != nil {
			return err
		}
		// 再补一次旧列退役：**上一版的二进制**迁完时还没有这一步，它的库里 users 仍带着
		// 2.x 那四列配额列（3.0 不读它们，但形状没收干净）。删不动只打提示 ——
		// 版本号已落、结构是完整的 3.0，不该为一句收尾的 DDL 把库锁在门外。
		retireUsersQuotaColumnsQuietly(db, d)
		// 老账单的镜像也在这条分支补：上一版二进制盖版本号时还没有「读源只剩
		// usage_scope_daily」这件事，那种库结构全对、镜像却是空的。
		return mirrorUsageScopeDailyIfEmpty(db, d)
	}

	st, err := loadScopeSchemaState(db, d)
	if err != nil {
		return err
	}
	if conflict := st.pendingTablesConflict(); conflict != nil {
		return conflict
	}
	// 叠加表先落（只有 DDL，不含数据）：回填与收口校验都要求它们存在。
	if err := execScopeDerived(db, d); err != nil {
		return fmt.Errorf("%w: 创建 scope 派生表失败: %w", ErrScopeMigration, err)
	}
	if !st.needsWork() {
		// 既有表已经是 3.0 形状（新库由各表的 DDL 直接建好）：不动数据、不建备份。
		// 全新库第一次打开就走这条分支。
		if err := execScopeIndexes(db, d); err != nil {
			return fmt.Errorf("%w: 建 scope 索引失败: %w", ErrScopeMigration, err)
		}
		// 配额行仍然要补齐：needsWork 说的是「没有 2.x 的表形状要搬」，不是「库里没有人」。
		// 比多用户时代早的库升级上来时，各张表都是新建的 3.0 形状，users 里却已经有账号 ——
		// 那种账号缺配额行会让 buildRegistry 拒绝重建快照（新账号上线直接 401 一片），
		// 而这条分支下面就要对外宣称「这是 3.0 库」。
		if err := writeScopeQuotaRows(db, d, st); err != nil {
			return err
		}
		// needsWork() 说的是「四张表的形状不用搬」，不是「库里没有老账单」：比消费模式还早的库
		// 可能只有 users + usage_user_daily，走的就是这条分支。镜像必须排在版本号之前 ——
		// 版本号一落，下次的早退分支虽然也会补，但那一轮的收口校验已经不再管这批账了。
		if err := mirrorUsageScopeDailyIfEmpty(db, d); err != nil {
			return err
		}
		if err := stampScopeSchemaVersion(db, d, scopeBackup{}, time.Now()); err != nil {
			return err
		}
		// 旧列在这一步退役：writeScopeQuotaRows 已经按同一份输入把（可能存在的）旧列值搬进了
		// 配额行，所以守卫在这里只是兜底，防的是「行还没落成就把唯一的真值删走」。
		// 新库根本没有那四列（userSchema 已经不建），退役对它就是空转。
		retireUsersQuotaColumnsQuietly(db, d)
		return nil
	}

	// 1) 预检（**只读**）：映射是否封闭、有没有会撞桶的重复键、用户名能否当范围键。
	//    这一步能在任何 DDL 之前失败，失败时没有回滚负担。
	rep, err := preflightScopeMapping(db, d, st)
	if err != nil {
		return err
	}

	// 2) 备份。非 SQLite 方言先过「库外备份已就绪」这道确认门。
	if err := requireExternalScopeBackup(d); err != nil {
		return err
	}
	backup, err := backupForScopeMigration(db, d, pathOrDSN)
	if err != nil {
		return err
	}
	rep.BackupPath, rep.BackupSHA256, rep.ExternalDump = backup.path, backup.sha256, backup.externalHint
	if backup.externalHint != "" {
		fmt.Fprintf(scopeMigrationOutput, "[scope-migration] %s\n", backup.externalHint)
	}

	// 3) 逐阶段执行，每步登记反向操作；任一阶段失败就当场补偿并返回合并后的错误。
	return newScopeMigrationPlan(db, d, backup).runAll(st, rep)
}

// AppliedScopeSchemaVersion 返回库里已落地的 scope 结构版本（没落就是 0）。
//
// 主线接线时用这一句判断「能不能按 3.0 的形状读写」，而不是靠探测列名 ——
// 探测列名会把「迁移跑到一半」误判成「已经是新形状」。
func (s *Store) AppliedScopeSchemaVersion() (int64, error) {
	return metaInt(s.db, s.dialect, metaScopeSchemaVersion)
}

// ------------------------------------------------------------------ 预检

// preflightScopeMapping 在**不改任何数据**的前提下判定映射规则能否封闭地跑通：
//
//	a. provider_stats.scope 的每个不同取值都映射得出（'' = 全局，否则裸用户名）；
//	b. 映射后的桶键 (scope_kind, scope_id, name) 不重复 —— 重复就是并桶；
//	c. user_prices.scope 的每个取值都映射得出（'default' 或 'user:<名>'）；
//	d. 每个用户名（users.name 与 usage_user_daily.user_name）都能当 (user, 名) 的 scope_id；
//	e. 记下迁移前的基线计数，供收口校验对比。
func preflightScopeMapping(db *sql.DB, d Dialect, st scopeSchemaState) (*ScopeMigrationReport, error) {
	rep := &ScopeMigrationReport{Driver: d.Name()}

	if st.providerStatsLegacy {
		if err := checkLegacyProviderStatsMapping(db, d, rep); err != nil {
			return nil, err
		}
	}
	if st.userPricesLegacy {
		if err := checkLegacyUserPricesMapping(db, d, rep); err != nil {
			return nil, err
		}
	}
	if err := checkUserNamesAreScopes(db, d, st); err != nil {
		return nil, err
	}
	var err error
	if rep.RequestsBefore, _, err = tableRowCount(db, d, "requests"); err != nil {
		return nil, err
	}
	rep.UsersBefore, _, err = tableRowCount(db, d, "users")
	return rep, err
}

// checkLegacyProviderStatsMapping 逐桶判定旧 scope 取值，同时检出并桶风险。
func checkLegacyProviderStatsMapping(db *sql.DB, d Dialect, rep *ScopeMigrationReport) error {
	rows, err := db.Query(d.Rebind(`SELECT COALESCE(scope,''), name FROM provider_stats
		ORDER BY COALESCE(scope,''), name`))
	if err != nil {
		return err
	}
	defer rows.Close()

	// 判定用的键是「三个字段组成的 Go 值」，不是拼出来的字符串（§2.7 规则 1）——
	// 这里要检出的是「两个旧取值映射到同一个新主键」。
	type bucket3 struct{ kind, id, name string }
	seen := make(map[bucket3]int)
	total := int64(0)
	for rows.Next() {
		var scope, name string
		if err := rows.Scan(&scope, &name); err != nil {
			return err
		}
		total++
		ref, err := decodeLegacyProviderScope(scope)
		if err != nil {
			return fmt.Errorf("%w：provider_stats 有作用域 %q（供应商 %s）——"+
				"旧约定只认「空串=全局」与「裸用户名」，含冒号或控制字符的取值要人工定夺",
				ErrScopeMigration, scope, name)
		}
		k := bucket3{string(ref.Kind), ref.ID, name}
		seen[k]++
		if n := seen[k]; n == 2 {
			return fmt.Errorf("%w：provider_stats 迁移后会有两个旧作用域落进同一个路由桶 %s/%s/%s"+
				"（各自行数 %d）—— 并桶等于把两条上游的熔断计数混在一起",
				ErrScopeMigration, k.kind, k.id, k.name, n)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rep.ProviderStatsBefore = total
	rep.MappedBuckets = int64(len(seen))
	return nil
}

// checkLegacyUserPricesMapping 判定分发价的旧 scope 串。
func checkLegacyUserPricesMapping(db *sql.DB, d Dialect, rep *ScopeMigrationReport) error {
	rows, err := db.Query(d.Rebind(`SELECT scope, model, valid_from FROM user_prices
		ORDER BY scope, model, valid_from`))
	if err != nil {
		return err
	}
	defer rows.Close()

	total := int64(0)
	for rows.Next() {
		var scope, model string
		var validFrom int64
		if err := rows.Scan(&scope, &model, &validFrom); err != nil {
			return err
		}
		total++
		if _, err := DecodeLegacyPriceScope(strings.TrimSpace(scope)); err != nil {
			return fmt.Errorf("%w：user_prices 有作用域 %q（模型 %s，valid_from=%d）——"+
				"旧约定只认 %q 与 %q<用户名>", ErrScopeMigration, scope, model, validFrom,
				legacyPriceScopeDefault, legacyPriceScopeUserPfx)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rep.UserPricesBefore = total
	rep.MappedPrices = total
	return nil
}

// checkUserNamesAreScopes 确认每个用户名都能当 (user, 名) 的 scope_id。
//
// 两个来源都要查：users.name（scope_quota 回填的键）与 usage_user_daily.user_name
// （用量聚合回填的键 —— 删掉的用户仍留着账单行，那些行也必须有归属）。
// 查不过就是硬失败：归属挂不上主体的账单行，比「迁移失败」更难发现。
func checkUserNamesAreScopes(db *sql.DB, d Dialect, st scopeSchemaState) error {
	sources := []struct{ table, column string }{{"users", "name"}}
	if st.usageUserDaily {
		sources = append(sources, struct{ table, column string }{"usage_user_daily", "user_name"})
	}
	for _, src := range sources {
		rows, err := db.Query(d.Rebind(fmt.Sprintf(`SELECT DISTINCT %s FROM %s ORDER BY %s`,
			src.column, src.table, src.column)))
		if err != nil {
			return err
		}
		var bad string
		var found bool
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			if _, err := legacyUserScope(name); err != nil && !found {
				bad, found = name, true
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if found {
			return fmt.Errorf("%w：%s.%s 有 %q —— 它做不成 (user, 名) 的范围键"+
				"（policy 禁冒号与控制字符），需要人工改名或清理后再迁移",
				ErrScopeMigration, src.table, src.column, bad)
		}
	}
	return nil
}

// ------------------------------------------------------------------ 备份

// scopeBackup 是一次迁移留下的备份线索：SQLite 是文件，其它是「请外部 dump」。
type scopeBackup struct {
	location     string // SQLite 的库文件路径（恢复时要用）
	path         string
	sha256       string
	externalHint string
}

// backupForScopeMigration：
//
//	sqlite   —— 先 checkpoint 把 WAL 落盘，再整库复制 + SHA-256（记进 meta 与日志）。
//	mysql/pg —— **不做任何「我已经备份了」的暗示**：只打印必须由运维执行的 dump 入口，
//	            并把重命名出来的影子表保留下来，作为库内的第二份数据。
func backupForScopeMigration(db *sql.DB, d Dialect, pathOrDSN string) (scopeBackup, error) {
	if d.Name() != "sqlite" {
		return scopeBackup{externalHint: externalDumpHint(d)}, nil
	}
	// WAL 模式下 -wal 里还有没落盘的页；直接复制主文件会拿到一个少了尾巴的备份。
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return scopeBackup{}, fmt.Errorf("%w: 迁移前 checkpoint 失败: %w", ErrScopeMigration, err)
	}
	// 文件名带上 Unix 毫秒：多次尝试不互相覆盖，也不会覆盖上一轮那份。
	dst := fmt.Sprintf("%s.pre-scope-%d.bak", pathOrDSN, time.Now().UnixMilli())
	if err := copyFile(pathOrDSN, dst); err != nil {
		return scopeBackup{}, fmt.Errorf("%w: 备份 SQLite 库文件失败: %w", ErrScopeMigration, err)
	}
	sum, err := fileSHA256(dst)
	if err != nil {
		_ = os.Remove(dst)
		return scopeBackup{}, err
	}
	if err := os.Chmod(dst, 0o600); err != nil {
		_ = os.Remove(dst)
		return scopeBackup{}, fmt.Errorf("%w: 收紧备份权限失败: %w", ErrScopeMigration, err)
	}
	fmt.Fprintf(scopeMigrationOutput, "[scope-migration] 已备份 %s → %s（SHA-256 %s，权限 0600）\n",
		pathOrDSN, dst, sum)
	return scopeBackup{location: pathOrDSN, path: dst, sha256: sum}, nil
}

// externalDumpHint 是打印给运维的**外部**备份入口；本函数不做任何备份动作。
//
// DSN 里有密码，所以只说怎么取，绝不把 DSN 打进日志。
func externalDumpHint(d Dialect) string {
	switch d.Name() {
	case "mysql":
		return "MySQL：本次迁移不做自动备份。请先在库外执行 " +
			"`mysqldump --single-transaction <db> > pre-scope.sql`（DSN 见配置 database.dsn），" +
			"失败时用该文件恢复；迁移会把 provider_stats 改名为 " + legacyProviderStatsShadow +
			" 并**保留**，作为库内的第二份数据。"
	case "postgres":
		return "PostgreSQL：本次迁移不做自动备份。请先在库外执行 " +
			"`pg_dump --format=custom -f pre-scope.dump <db>`，失败时用 `pg_restore --clean` 恢复；" +
			"迁移会把 provider_stats 改名为 " + legacyProviderStatsShadow + " 并**保留**。"
	default:
		return "未知方言：" + d.Name() + "，请先自行做逻辑备份再迁移。"
	}
}

// scopeBackupAckEnv 是「库外逻辑备份已经做好」的操作员确认变量。
const scopeBackupAckEnv = "LLMPROXY_SCOPE_MIGRATION_BACKUP_ACK"

// scopeBackupAckLookup 单独抽一层：测试要验这道门，但不该改真实进程环境。
var scopeBackupAckLookup = os.Getenv

// requireExternalScopeBackup 挡住「服务端方言上无人值守地自动改表」。
//
// §2.7 要的是「迁移前自动备份、失败可恢复」。SQLite 能整库复制文件，MySQL / PG 不能 ——
// 那种库上不打招呼就跑一次改主键 + 并桶的迁移，等于替运维决定「这份数据可以不备份」。
// 服务以 systemd 起来时这一步往往发生在升级后的第一次启动，没人会盯着日志。
//
// 所以确认门放在写完预检、动第一笔数据之前：没确认就直接退出，此时库里最多只有
// execScopeDerived 建的两张**空**派生表（幂等 DDL，下一轮照常接着跑）。
// 全新库不走这里 —— 那条路在 needsWork() 就分出去了，没有数据要保护。
func requireExternalScopeBackup(d Dialect) error {
	if d.Name() == "sqlite" {
		return nil
	}
	if scopeBackupAckLookup(scopeBackupAckEnv) == "done" {
		return nil
	}
	// 拒绝时把备份入口一并带上：这道门排在打印 hint 的备份步骤之前，
	// 不捎上的话运维只会看到一句「请先备份」而不知道该跑哪条命令。
	return fmt.Errorf("%w: %s 的备份本进程做不了，必须先在库外做完逻辑备份、再设置 %s=done 确认。"+
		"现在退出，未改动任何数据。%s",
		ErrScopeMigration, d.Name(), scopeBackupAckEnv, externalDumpHint(d))
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func fileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// restoreSQLiteBackup 用文件备份整库还原：补偿式回滚不彻底时的最后一道。
//
// 调用前必须已经关掉连接（否则 -wal 会被写回去）。同名 -wal/-shm 一并删掉：
// 留着的话 SQLite 会把旧 WAL 当有效日志重放进刚还原的主文件，等于白还原。
func restoreSQLiteBackup(path, backupPath, wantSHA string) error {
	if wantSHA == "" {
		return fmt.Errorf("备份 %s 没有记录 SHA-256，无法复核后恢复", backupPath)
	}
	got, err := fileSHA256(backupPath)
	if err != nil {
		return fmt.Errorf("恢复前复核备份失败: %w", err)
	}
	if got != wantSHA {
		return fmt.Errorf("备份 %s 的 SHA-256 与迁移时记录的不一致（实际 %s，记录 %s），拒绝用它恢复",
			backupPath, got, wantSHA)
	}
	for _, p := range []string{path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); err == nil {
			if err := os.Remove(p); err != nil {
				return err
			}
		}
	}
	if err := copyFile(backupPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// ------------------------------------------------------------------ 执行与补偿

// scopeMigrationPlan 持有「已执行的步骤 + 它们的反向操作」。
//
// 反向操作按登记的**逆序**执行。DDL 在 MySQL 里会隐式提交，事务保护不了它 ——
// 补偿式回滚（而不是 ROLLBACK）是这里唯一诚实的做法。
type scopeMigrationPlan struct {
	db       *sql.DB
	d        Dialect
	backup   scopeBackup
	steps    []scopeStep
	finished bool
}

type scopeStep struct {
	name string
	undo func() error
}

func newScopeMigrationPlan(db *sql.DB, d Dialect, backup scopeBackup) *scopeMigrationPlan {
	return &scopeMigrationPlan{db: db, d: d, backup: backup}
}

func (p *scopeMigrationPlan) add(name string, undo func() error) {
	p.steps = append(p.steps, scopeStep{name: name, undo: undo})
}

// exec 跑一条语句，失败包装成迁移错误（带上语句首行，运维在日志里能直接定位）。
func (p *scopeMigrationPlan) exec(q string, args ...any) error {
	if _, err := p.db.Exec(p.d.Rebind(q), args...); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrScopeMigration, firstLine(q), err)
	}
	return nil
}

// runAll 顺序跑完全部阶段 + 收口校验 + 收尾。
//
// 任何一个环节失败都走 fail：先补偿，再把「原始错误 + 补偿结果」一起报出去。
// 顺序是刻意的：
//
//  1. 重建 provider_stats（改主键，唯一必须整表搬的一张）
//  2. user_prices 换代（补列 + 逐行映射，不重建表 —— 保住 id 与 requests 的引用）
//  3. 补 requests / audit_log 的列，然后才建这三张表上的范围索引
//  4. 回填 scope_quota（users 的 1:1 镜像）
//  5. 回填 usage_scope_daily（usage_user_daily 的镜像，原表一行不动）
//  6. 收口校验：四项全过才允许继续
//  7. 收尾：删掉 2.x 的旧列/旧索引/影子表，落版本号，最后退役 users 上的四列配额列
//
// 4、5 排在 6 之前，因为校验查的就是它们的结果；7 排在 6 之后，
// 因为「旧列」是唯一的退路 —— 校验没过就删掉它，等于失败时把退路也烧了。
// users 的配额列排在**版本号之后**（见 finish）：它不是本次迁移的任何输入，
// 而删到一半时回滚会把已经校验通过的 3.0 结构拆掉，不如留给下一次启动的幂等收尾。
func (p *scopeMigrationPlan) runAll(st scopeSchemaState, rep *ScopeMigrationReport) error {
	phases := []struct {
		name string
		fn   func() error
	}{
		{"重建 provider_stats", func() error { return p.rebuildProviderStats(st, rep) }},
		{"换代 user_prices", func() error { return p.migrateUserPrices(st, rep) }},
		{"补 requests/audit_log 的列", func() error { return p.addScopeColumns(st, rep) }},
		{"回填 scope_quota", func() error { return p.backfillScopeQuota(st, rep) }},
		{"回填 usage_scope_daily", func() error { return p.backfillUsageScopeDaily(st, rep) }},
		{"收口校验", func() error { return p.verify(st, rep) }},
		{"清理 2.x 遗留并落版本号", func() error { return p.finish(st, rep) }},
	}
	for _, ph := range phases {
		if err := ph.fn(); err != nil {
			return p.fail(fmt.Errorf("%s阶段: %w", ph.name, err))
		}
	}
	return nil
}

// fail 执行补偿并把错误合并出去。
func (p *scopeMigrationPlan) fail(cause error) error {
	if p.finished {
		// 版本号已经落了：此刻库的结构是完整的 3.0，回滚反而会把好库拆了。
		return cause
	}
	if rbErr := p.rollback(); rbErr != nil {
		return fmt.Errorf("%w（补偿回滚的结果：%v）", cause, rbErr)
	}
	fmt.Fprintf(scopeMigrationOutput, "[scope-migration] 已回滚到迁移前的结构；原因：%v\n", cause)
	return cause
}

// rollback 逆序执行补偿。任一步失败就改用文件备份（仅 SQLite）。
func (p *scopeMigrationPlan) rollback() error {
	var errs []string
	for i := len(p.steps) - 1; i >= 0; i-- {
		st := p.steps[i]
		if st.undo == nil {
			continue
		}
		if err := st.undo(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", st.name, err))
		}
	}
	p.steps = nil
	if len(errs) == 0 {
		return nil
	}
	joined := strings.Join(errs, "; ")
	if p.backup.path != "" {
		if err := p.restoreFromBackupFile(); err != nil {
			return fmt.Errorf("补偿有失败项（%s），文件恢复也失败（%v）—— 需要人工介入，备份在 %s",
				joined, err, p.backup.path)
		}
		fmt.Fprintf(scopeMigrationOutput,
			"[scope-migration] 补偿有失败项（%s），已用文件备份整库还原：%s\n", joined, p.backup.path)
		return nil
	}
	return fmt.Errorf("补偿失败：%s —— 本方言没有自动备份，请按外部 dump 入口手工恢复", joined)
}

// restoreFromBackupFile 关闭连接后用备份覆盖主库（仅 SQLite 路径）。
func (p *scopeMigrationPlan) restoreFromBackupFile() error {
	_ = p.db.Close()
	return restoreSQLiteBackup(p.backup.location, p.backup.path, p.backup.sha256)
}

// ------------------------------------------------------------------ 各阶段

// legacyBucketRow 是 provider_stats 的一行原样读数（除 scope 外全部按扫进来的类型留着）。
//
// 刻意不做任何类型往返：updated_at 之类必须**逐位不变**地搬到新表 ——
// 桶状态的新旧程度是运维判断熔断冷却的依据，不能被迁移时间覆盖。
type legacyBucketRow struct {
	scope     string
	name      string
	enabled   int64
	consec    int64
	unhealthy int64
	lastErr   string
	lastOK    int64
	lastFail  int64
	totalReq  int64
	totalFail int64
	updated   int64
}

// rebuildProviderStats 把 provider_stats 从 (scope, name) 换成 (scope_kind, scope_id, name)。
//
// 主键变了只能重建（与 migrateProviderStatsScope / migrateUsageUserDaily 同一套做法）。
// 范围由 decodeLegacyProviderScope 逐行判定 —— 与旧 API 适配层共用一份实现，
// 预检判过的取值在这里只会得到同样的落点。
func (p *scopeMigrationPlan) rebuildProviderStats(st scopeSchemaState, _ *ScopeMigrationReport) error {
	if !st.providerStatsLegacy {
		return nil
	}
	// 影子表已经存在 = 上一轮的残留或人工恢复的结果：哪一份是真的本迁移猜不出来，
	// 直接失败让人看。留到这里再撞「表已存在」的原始错误，运维读不出这是残留。
	if ok, err := p.d.HasTable(p.db, legacyProviderStatsShadow); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("%w：%s 已经存在（上一轮迁移的残留，或人工恢复留下的第二份）——"+
			"先确认它和 provider_stats 哪一份是真的，再决定改名或删掉；本迁移不替你猜",
			ErrScopeMigration, legacyProviderStatsShadow)
	}
	rows, err := p.db.Query(p.d.Rebind(`SELECT COALESCE(scope,''), name, enabled, consecutive_failures,
		unhealthy_until, COALESCE(last_error,''), COALESCE(last_success_at,0), COALESCE(last_failure_at,0),
		total_requests, total_failures, updated_at FROM provider_stats ORDER BY COALESCE(scope,''), name`))
	if err != nil {
		return err
	}
	defer rows.Close()
	var all []legacyBucketRow
	for rows.Next() {
		var r legacyBucketRow
		if err := rows.Scan(&r.scope, &r.name, &r.enabled, &r.consec, &r.unhealthy, &r.lastErr,
			&r.lastOK, &r.lastFail, &r.totalReq, &r.totalFail, &r.updated); err != nil {
			return err
		}
		if _, err := decodeLegacyProviderScope(r.scope); err != nil {
			return fmt.Errorf("%w: provider_stats 作用域 %q（供应商 %s）: %w", ErrScopeMigration, r.scope, r.name, err)
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	// 改名而不是原地 DROP+CREATE：老表在整个搬迁期间都还在，失败时它就是退路。
	if err := p.exec(`ALTER TABLE provider_stats RENAME TO ` + legacyProviderStatsShadow); err != nil {
		return err
	}
	p.add("把 provider_stats 这个名字还给影子表", func() error {
		// 撤销改名要先让出新名字：此时 provider_stats 是本迁移建的那张 3.0 空表/半满表。
		return execMulti(p.db, p.d, []string{
			`DROP TABLE IF EXISTS provider_stats`,
			`ALTER TABLE ` + legacyProviderStatsShadow + ` RENAME TO provider_stats`,
		})
	})

	if err := p.exec(p.d.RewriteDDL(providerStatsDDL30)); err != nil {
		return err
	}
	p.add("删掉本迁移建出来的 3.0 形状 provider_stats", func() error {
		return p.exec(`DROP TABLE IF EXISTS provider_stats`)
	})

	for _, r := range all {
		ref, err := decodeLegacyProviderScope(r.scope)
		if err != nil {
			return fmt.Errorf("%w: provider_stats 作用域 %q: %w", ErrScopeMigration, r.scope, err)
		}
		if err := p.exec(`
INSERT INTO provider_stats (
  scope_kind, scope_id, name, enabled, consecutive_failures, unhealthy_until,
  last_error, last_success_at, last_failure_at, total_requests, total_failures, updated_at
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			string(ref.Kind), ref.ID, r.name, r.enabled, r.consec, r.unhealthy, r.lastErr,
			r.lastOK, r.lastFail, r.totalReq, r.totalFail, r.updated); err != nil {
			return fmt.Errorf("%w: 搬 provider_stats 桶 %s/%s 失败: %w",
				ErrScopeMigration, ref.Display(), r.name, err)
		}
	}
	return nil
}

// migrateUserPrices 给 user_prices 补上范围两列并按旧串回填。
//
// 这一步**不重建表**：主键还是那个自增 id，而 requests.price_downstream_id 指着它 ——
// 重建会让历史请求指向错误的价目行；MySQL/PG 的自增序列在显式插值后也不会自己前进。
// 于是走「ADD COLUMN（带空默认）→ 逐行按旧串映射 → 建新索引」，
// 旧列与旧索引留到最后校验通过才删（见 dropLegacyStructures）。
func (p *scopeMigrationPlan) migrateUserPrices(st scopeSchemaState, _ *ScopeMigrationReport) error {
	if !st.userPricesLegacy {
		return nil
	}
	if err := addColumnsIfMissing(p.db, p.d, "user_prices", scopeColsMap(userPricesScopeCols30)); err != nil {
		return err
	}
	p.add("删掉 user_prices 的范围两列与新索引", func() error {
		return execMulti(p.db, p.d, []string{
			dropIndexSQL(p.d, "idx_user_prices_scope", "user_prices"),
			`ALTER TABLE user_prices DROP COLUMN scope_id`,
			`ALTER TABLE user_prices DROP COLUMN scope_kind`,
		})
	})

	rows, err := p.db.Query(p.d.Rebind(`SELECT id, scope FROM user_prices ORDER BY id`))
	if err != nil {
		return err
	}
	type priceKey struct {
		id    int64
		scope string
	}
	var keys []priceKey
	for rows.Next() {
		var k priceKey
		if err := rows.Scan(&k.id, &k.scope); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, k)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}

	for _, k := range keys {
		ref, err := DecodeLegacyPriceScope(strings.TrimSpace(k.scope))
		if err != nil {
			return fmt.Errorf("%w: user_prices id=%d 的作用域 %q: %w", ErrScopeMigration, k.id, k.scope, err)
		}
		if err := p.exec(`UPDATE user_prices SET scope_kind=?, scope_id=? WHERE id=?`,
			string(ref.Kind), ref.ID, k.id); err != nil {
			return fmt.Errorf("%w: 回填 user_prices id=%d 失败: %w", ErrScopeMigration, k.id, err)
		}
	}
	return nil
}

// addScopeColumns 给 requests 与 audit_log 补上范围/路由列。
//
// requests：只加列、不回填（见文件头「为什么 requests 不回填」）。
// audit_log：ALTER 的列默认值就把既有行落成 (system,'global') —— 2.x 的审计只记管理员全局
// 操作，那是事实陈述而不是猜测。随后那条 UPDATE 只碰空串行，防的是「补列之后又被裸 SQL
// 插进空范围」这类脏形状。
func (p *scopeMigrationPlan) addScopeColumns(st scopeSchemaState, _ *ScopeMigrationReport) error {
	var undo []string
	if !st.requests30 {
		if err := addColumnsIfMissing(p.db, p.d, "requests", scopeColsMap(requestsScopeCols30)); err != nil {
			return err
		}
		// 补偿里**先删索引再删列**（MySQL 不许删还有索引在上的列），所以顺序不能反。
		undo = append(undo, dropIndexSQL(p.d, "idx_requests_scope_bucket", "requests"))
		for _, c := range requestsScopeCols30 {
			undo = append(undo, fmt.Sprintf("ALTER TABLE requests DROP COLUMN %s", c.name))
		}
	}
	if !st.audit30 {
		if err := addColumnsIfMissing(p.db, p.d, "audit_log", scopeColsMap(auditScopeCols30)); err != nil {
			return err
		}
		// 补列时各家的默认值就会把既有行填成 (system,'global')；这条 UPDATE 只兜
		// 「历史上被裸 SQL 插进过空范围」那种脏形状，正常库里它影响 0 行。
		if _, err := p.db.Exec(p.d.Rebind(`UPDATE audit_log SET scope_kind='system', scope_id='global'
			WHERE scope_kind='' OR scope_id=''`)); err != nil {
			return fmt.Errorf("%w: 归一 audit_log 既有行失败: %w", ErrScopeMigration, err)
		}
		undo = append(undo, dropIndexSQL(p.d, "idx_audit_scope", "audit_log"),
			`ALTER TABLE audit_log DROP COLUMN scope_id`,
			`ALTER TABLE audit_log DROP COLUMN scope_kind`)
	}
	if len(undo) > 0 {
		captured := append([]string{}, undo...)
		p.add("删掉 requests/audit_log 补上的列与索引", func() error {
			return execMulti(p.db, p.d, captured)
		})
	}
	// 列齐了才建索引（三条各自判「表在、列在」，见 execScopeIndexes）。
	if err := execScopeIndexes(p.db, p.d); err != nil {
		return fmt.Errorf("%w: %w", ErrScopeMigration, err)
	}
	return nil
}

// writeScopeQuotaRows 落「每个 user 一行配额」这件事：先按旧列覆盖已有行，再补没有的键。
//
// 输入按 st.usersQuotaLegacy 二选一（见 backfillScopeQuota），两条语句都**不删行**，
// 也不会碰非 user 范围的行。两家都不写成带冲突子句的 INSERT ... SELECT：
// SQLite 的 upsert 只挂在 VALUES 形式上，那条写法在 SQLite 直接是语法错误
// （MySQL / PostgreSQL 都允许，所以三家共用一份语句的前提就是不用它）。
//
// 这里不含补偿登记 —— 纯追加、可重入，失败时由调用方决定怎么收尾。
func writeScopeQuotaRows(db *sql.DB, d Dialect, st scopeSchemaState) error {
	src := scopeQuotaInitSQL
	if st.usersQuotaLegacy {
		src = scopeQuotaBackfillSQL
		if _, err := db.Exec(d.Rebind(scopeQuotaSyncSQL)); err != nil {
			return fmt.Errorf("%w: 同步 scope_quota 已有行失败: %w", ErrScopeMigration, err)
		}
	}
	if _, err := db.Exec(d.Rebind(src)); err != nil {
		return fmt.Errorf("%w: 回填 scope_quota 失败: %w", ErrScopeMigration, err)
	}
	return nil
}

// backfillScopeQuota 建出 (user, 名) 的配额行，并登记撤销它们的那一步。
//
// 输入有两份，按 st.usersQuotaLegacy 选：
//
//	旧列在 —— 搬 users 上的配额/限流值（2.x 库）。
//	旧列不在 —— 全 0（= 不限）+ users.enabled 作初值（比消费模式更早的库）。
//
// 两份都必须落行：3.0 的读路径（buildRegistry）缺行就拒绝重建快照，
// 收口校验也查「每个 user 一行」。漏了这一步，那种库升级上来第一次同步用户就会 401 一片。
//
// 键的两列在 SQL 里分别给出（常量 'user' 与 name 列），**没有拼接**（§2.7 规则 1）；
// 用户名能否当 scope_id 已在预检里逐个查过。
func (p *scopeMigrationPlan) backfillScopeQuota(st scopeSchemaState, _ *ScopeMigrationReport) error {
	createdHere := !st.scopeQuota
	if err := writeScopeQuotaRows(p.db, p.d, st); err != nil {
		return err
	}
	if createdHere {
		p.add("删掉本轮回填出来的 scope_quota", func() error {
			return p.exec(`DROP TABLE IF EXISTS scope_quota`)
		})
	} else {
		// 表上一轮就建好了（版本号没落）：只撤本轮灌进去的 user 范围行，
		// 组织/项目范围的行不属于本轮（那种行只可能来自 3.0 的写路径），不许一并删掉。
		p.add("撤掉本轮回填进 scope_quota 的行", func() error {
			return p.exec(`DELETE FROM scope_quota WHERE scope_kind='user'`)
		})
	}
	return nil
}

// scopeQuotaBackfillSQL 把 users 的配额列镜像成 (user, 名) 的 scope_quota 行，
// 只灌 scope_quota 里还不存在的键。
//
// 键的两列在 SQL 里分别给出（常量 'user' 与 name 列），**没有拼接**（§2.7 规则 1）；
// 用户名能否当 scope_id 已在预检里逐个查过。
// created_at/updated_at 取 users 行上的时间戳：配额行的年龄跟着主体走，
// 否则「早就设好的限额」会在报表里显示成迁移那一刻改的。
//
// 这里**不带冲突子句**：SQLite 的 upsert 只挂在 VALUES 形式上，
// `INSERT ... SELECT ... ON CONFLICT(...) DO UPDATE` 在 SQLite 直接是语法错误
// （MySQL / PostgreSQL 都允许，所以三家共用一份语句的前提就是不用它）。
// 第二次进来（上一轮回填完但校验没过/版本号没落）的幂等由
// NOT EXISTS + scopeQuotaSyncSQL 覆盖，等价于「撞了主键就更新」而不是静默跳过。
const scopeQuotaBackfillSQL = `
INSERT INTO scope_quota (
  scope_kind, scope_id, quota_month_tokens, quota_month_cost, rpm, max_concurrent,
  enabled, created_at, updated_at
)
SELECT 'user', u.name, u.quota_month_tokens, u.quota_month_cost, u.rpm, u.max_concurrent,
       u.enabled, u.created_at, u.updated_at
FROM users u
WHERE NOT EXISTS (
  SELECT 1 FROM scope_quota q WHERE q.scope_kind='user' AND q.scope_id = u.name
)`

// scopeQuotaInitSQL 给还没有配额行的 user 范围补一行「不限」。
//
// 走这条的是**没带过配额列**的库：比消费模式更早的 2.x 库（那时 users 上只有身份列）。
// 那种库没有旧值可搬，但「每个 user 都有一行」是收口校验与 3.0 读路径共同的不变量，
// 所以在这里补出来，而不是让那种库永远开不了。
// 全 0 = 不限，跟 CreateUser 的初值同一口径；enabled 沿用账号的启用状态，
// created_at/updated_at 跟主体走（配额行的年龄不等于迁移时刻）。
const scopeQuotaInitSQL = `
INSERT INTO scope_quota (
  scope_kind, scope_id, quota_month_tokens, quota_month_cost, rpm, max_concurrent,
  enabled, created_at, updated_at
)
SELECT 'user', u.name, 0, 0, 0, 0, u.enabled, u.created_at, u.updated_at
FROM users u
WHERE NOT EXISTS (
  SELECT 1 FROM scope_quota q WHERE q.scope_kind='user' AND q.scope_id = u.name
)`

// scopeQuotaSyncSQL 把已经存在的 user 范围行按 users 的当前值覆盖一遍。
//
// 只在「上一轮灌过一半」这种重入场景真正生效（首轮表是空的，0 行）。
// created_at 不在 SET 列表里：那一列记的是主体第一次出现的时刻，
// 重入迁移不该把老主体的年龄改写成现在。
//
// 三家通用的相关子查询写法（SQLite 不支持 UPDATE ... FROM，MySQL 的
// UPDATE 多表语法又和 PostgreSQL 不同，所以两边都用子查询而不是 JOIN）。
const scopeQuotaSyncSQL = `
UPDATE scope_quota SET
  quota_month_tokens = (SELECT u.quota_month_tokens FROM users u WHERE u.name = scope_quota.scope_id),
  quota_month_cost   = (SELECT u.quota_month_cost   FROM users u WHERE u.name = scope_quota.scope_id),
  rpm                = (SELECT u.rpm                FROM users u WHERE u.name = scope_quota.scope_id),
  max_concurrent     = (SELECT u.max_concurrent     FROM users u WHERE u.name = scope_quota.scope_id),
  enabled            = (SELECT u.enabled            FROM users u WHERE u.name = scope_quota.scope_id),
  updated_at         = (SELECT u.updated_at         FROM users u WHERE u.name = scope_quota.scope_id)
WHERE scope_kind='user'
  AND EXISTS (SELECT 1 FROM users u WHERE u.name = scope_quota.scope_id)`

// usageScopeMirrorSQL 把 usage_user_daily 整表按 (user, 名) 复制进 usage_scope_daily。
//
// 两个调用点共用同一句：回填阶段（真正的一次性迁移）与「结构已是 3.0 但镜像还空着」的补齐
// （见 mirrorUsageScopeDailyIfEmpty）。分两处写就会漂移 —— 一处补了列、另一处忘了。
// 不带 ON CONFLICT：目标表灌之前必然是空的。
const usageScopeMirrorSQL = `
INSERT INTO usage_scope_daily (
  day, scope_kind, scope_id, provider, model, upstream_model, system_paid,
  requests, ok, failed, prompt_tokens, cache_hit_tokens, cache_miss_tokens,
  completion_tokens, total_tokens, latency_sum_ms, charge, frozen_charges
)
SELECT day, 'user', user_name, provider, model, upstream_model, system_paid,
       requests, ok, failed, prompt_tokens, cache_hit_tokens, cache_miss_tokens,
       completion_tokens, total_tokens, latency_sum_ms, charge, frozen_charges
FROM usage_user_daily`

// backfillUsageScopeDaily 从 usage_user_daily 回填按范围的日聚合。
//
// 「历史明细的归属不改变」（§2.7 规则 5）在这里的具体含义：
// usage_user_daily 一行都不动，新表只是**从它复制出一份按范围键的同一批事实**，
// 老报表与老账本继续按原样可读。scope_kind 是常量 'user'、scope_id 取 user_name 列，
// 两列各写各的（没有拼接）。
//
// INSERT 不带 ON CONFLICT：新表这时必然是空的（有行就说明上一轮已经回填过、
// 只是版本号没落 —— 那种情况由收口的幂等重建处理，见 truncateUsageScope）。
func (p *scopeMigrationPlan) backfillUsageScopeDaily(st scopeSchemaState, _ *ScopeMigrationReport) error {
	if !st.usageUserDaily {
		return nil
	}
	createdHere := !st.usageScopeDaily
	if !createdHere {
		// 表已经存在（上一轮跑到一半）：清空再灌，保证「灌进去的就是 usage_user_daily 的镜像」，
		// 否则收口的行数/金额守恒会拿一份混了两轮的表去比。
		if err := p.exec(`DELETE FROM usage_scope_daily`); err != nil {
			return err
		}
	}
	if _, err := p.db.Exec(p.d.Rebind(usageScopeMirrorSQL)); err != nil {
		return fmt.Errorf("%w: 回填 usage_scope_daily 失败: %w", ErrScopeMigration, err)
	}
	if createdHere {
		p.add("删掉本轮回填出来的 usage_scope_daily", func() error {
			return p.exec(`DROP TABLE IF EXISTS usage_scope_daily`)
		})
	} else {
		// 已经存在过的表不能整张删（3.0 的写路径可能已经往里记过东西）：
		// 回滚就把本轮插入的行按 (user, 名) 全部撤回 —— 本轮插入的只有这一种范围。
		p.add("撤掉本轮回填进 usage_scope_daily 的行", func() error {
			return p.exec(`DELETE FROM usage_scope_daily WHERE scope_kind='user'`)
		})
	}
	return nil
}

// mirrorUsageScopeDailyIfEmpty 给「结构已经是 3.0、但老账还没镜像过来」的库补一次回填。
//
// 为什么单独要有这一句：3.0 的用量**只有 usage_scope_daily 一个读源**（规则 8 之后
// usage_user_daily 既不写也不读了）。而 needsWork() 只看四张表的形状 —— 一张表形状齐了、
// 老 usage_user_daily 里却还留着账单的库（比消费模式还早、又从没建过 provider_stats 的库，
// 或被上一版二进制提前盖上版本号的库）会直接走「不动数据」分支，版本号一落，
// 那批账单就再也没有读路径能看见：**账单凭空变成 0**，而这正是最贵的那种静默失败。
//
// 只在目标表为空时动手：那时不可能重复计数，也不可能在真跑过 3.0 的库上盖掉实时行。
// 目标表有行就说明镜像已经发生（或者 3.0 正在记账），这里一律不碰。
func mirrorUsageScopeDailyIfEmpty(db *sql.DB, d Dialect) error {
	userRows, hasLegacy, err := tableRowCount(db, d, "usage_user_daily")
	if err != nil || !hasLegacy || userRows == 0 {
		return err
	}
	scopeRows, _, err := tableRowCount(db, d, "usage_scope_daily")
	if err != nil {
		return err
	}
	if scopeRows > 0 {
		return nil
	}
	if _, err := db.Exec(d.Rebind(usageScopeMirrorSQL)); err != nil {
		return fmt.Errorf("%w: 补镜像 usage_scope_daily 失败: %w", ErrScopeMigration, err)
	}
	fmt.Fprintf(scopeMigrationOutput,
		"[scope-migration] 结构已是 3.0 但 usage_scope_daily 是空的：已把 usage_user_daily 的 %d 行老账单补镜像过来\n",
		userRows)
	return nil
}

// ------------------------------------------------------------------ 收口校验

// verify 跑手册 §2.7 交付要求的四项检查；任一项不过就返回错误（触发补偿 + 拒绝启动）。
//
// scopeMigrationFault 让「DDL 已做完之后才失败」这条路径可被测试覆盖。
func (p *scopeMigrationPlan) verify(st scopeSchemaState, rep *ScopeMigrationReport) error {
	// ① 行数守恒。
	if st.providerStatsLegacy {
		n, _, err := tableRowCount(p.db, p.d, "provider_stats")
		if err != nil {
			return err
		}
		rep.ProviderStatsAfter = n
		if n != rep.ProviderStatsBefore {
			return fmt.Errorf("%w: 行数守恒失败 provider_stats %d → %d",
				ErrScopeMigration, rep.ProviderStatsBefore, n)
		}
	}
	if st.userPricesLegacy {
		n, _, err := tableRowCount(p.db, p.d, "user_prices")
		if err != nil {
			return err
		}
		rep.UserPricesAfter = n
		if n != rep.UserPricesBefore {
			return fmt.Errorf("%w: 行数守恒失败 user_prices %d → %d",
				ErrScopeMigration, rep.UserPricesBefore, n)
		}
	}
	var err error
	if rep.RequestsAfter, _, err = tableRowCount(p.db, p.d, "requests"); err != nil {
		return err
	}
	if rep.RequestsAfter != rep.RequestsBefore {
		return fmt.Errorf("%w: 行数守恒失败 requests %d → %d（迁移不该动请求行的数量）",
			ErrScopeMigration, rep.RequestsBefore, rep.RequestsAfter)
	}
	if rep.UsersBefore, _, err = tableRowCount(p.db, p.d, "users"); err != nil {
		return err
	}
	if rep.ScopeQuotaRows, _, err = tableRowCount(p.db, p.d, "scope_quota"); err != nil {
		return err
	}
	// 每个 user 范围都该有一行配额（回填的定义就是这件事）。
	quotaUsers, err := dbScalarInt(p.db, p.d, `SELECT COUNT(*) FROM scope_quota WHERE scope_kind='user'`)
	if err != nil {
		return err
	}
	if quotaUsers != rep.UsersBefore {
		return fmt.Errorf("%w: scope_quota 与 users 不同数：user 范围 %d 行、users %d 行",
			ErrScopeMigration, quotaUsers, rep.UsersBefore)
	}
	if rep.UsageScopeRows, _, err = tableRowCount(p.db, p.d, "usage_scope_daily"); err != nil {
		return err
	}

	// ② 新主键唯一。
	for _, t := range pkCheckTables() {
		if err := checkPKUniqueness(p.db, p.d, t.table, t.cols); err != nil {
			return err
		}
	}
	if err := injectFault("新主键唯一"); err != nil {
		return err
	}

	// ③ 金额守恒（RowCharge 口径；容差见 scopeMoneyTolerance）。
	if st.usageUserDaily {
		userTotal, userRows, err := sumRowCharges(p.db, p.d, usageUserDailyChargeSQL)
		if err != nil {
			return err
		}
		scopeTotal, scopeRows, err := sumRowCharges(p.db, p.d, usageScopeDailyChargeSQL)
		if err != nil {
			return err
		}
		rep.ChargeUser, rep.ChargeScope = userTotal, scopeTotal
		if userRows != scopeRows {
			return fmt.Errorf("%w: 用量行数守恒失败 usage_user_daily=%d usage_scope_daily=%d",
				ErrScopeMigration, userRows, scopeRows)
		}
		if diff := absFloat(scopeTotal - userTotal); diff > scopeMoneyTolerance {
			return fmt.Errorf("%w: 金额守恒失败（RowCharge 口径）按用户 %.10f、按范围 %.10f，"+
				"差 %.10f 元，超过容差 %g", ErrScopeMigration, userTotal, scopeTotal, diff, scopeMoneyTolerance)
		}
	}
	if err := injectFault("金额守恒"); err != nil {
		return err
	}

	// ④ 归属覆盖：闭集取值、(user,名) 可解析、孤儿只报告。
	if err := checkScopeKindClosed(p.db, p.d); err != nil {
		return err
	}
	if err := checkScopeCoverage(p.db, p.d, rep); err != nil {
		return err
	}
	return injectFault("归属覆盖")
}

func pkCheckTables() []struct {
	table string
	cols  []string
} {
	return []struct {
		table string
		cols  []string
	}{
		{"provider_stats", []string{"scope_kind", "scope_id", "name"}},
		{"scope_quota", []string{"scope_kind", "scope_id"}},
		{"usage_scope_daily", []string{"day", "scope_kind", "scope_id", "provider", "model", "upstream_model", "system_paid"}},
	}
}

// injectFault 是测试注入点：生产里 scopeMigrationFault 为 nil，等于没有故障。
func injectFault(check string) error {
	if scopeMigrationFault == nil {
		return nil
	}
	if err := scopeMigrationFault(check); err != nil {
		return fmt.Errorf("%w: %s 检查失败: %w", ErrScopeMigration, check, err)
	}
	return nil
}

// checkPKUniqueness 检出同一新主键下有多行。
//
// 表上的主键本该挡住它，但那前提是 DDL 建成了 —— 「影子表 + 手工恢复」过的库里
// 主键可能已经不完整，所以这一项要显式数一遍，而不是指望约束。
// 用一条 COUNT 的子查询而不是逐行扫：大表上后者会把迁移本身变成瓶颈。
func checkPKUniqueness(db *sql.DB, d Dialect, table string, cols []string) error {
	if ok, err := d.HasTable(db, table); err != nil || !ok {
		return err
	}
	list := strings.Join(cols, ", ")
	q := d.Rebind(fmt.Sprintf(`SELECT COUNT(*) FROM (SELECT 1 FROM %s GROUP BY %s HAVING COUNT(*) > 1) dup`,
		table, list))
	var n int64
	if err := db.QueryRow(q).Scan(&n); err != nil {
		return fmt.Errorf("%w: 检查 %s 的新主键唯一性失败: %w", ErrScopeMigration, table, err)
	}
	if n > 0 {
		return fmt.Errorf("%w: %s 迁移后有 %d 组重复的新主键 (%s) —— 说明映射把不同主体并进了同一个桶",
			ErrScopeMigration, table, n, list)
	}
	return nil
}

// scopeKindsInPolicy 是闭集的字面展开，取自 policy 的四个常量。
//
// 写在这里而不是硬编码字符串：policy 新增类型时这里会**跟着变**（编译不过或检查放宽），
// 而不是悄悄把新类型当成非法取值。
func scopeKindsInPolicy() []string {
	return []string{
		string(policy.ScopeUser),
		string(policy.ScopeOrganization),
		string(policy.ScopeProject),
		string(policy.ScopeSystem),
	}
}

// checkScopeKindClosed 确认每张表的 scope_kind 都在 policy 的闭集里、且不为空串。
//
// 闭集之外的取值（比如有人用裸 SQL 写了 'team'）会让上层按类型分支的逻辑走空，
// 那类 bug 表现为「账单少一截」，必须在这里就拦住。空串同样拦。
// requests 例外：那里的 NULL 是「没有归属」，是刻意的（见文件头）。
func checkScopeKindClosed(db *sql.DB, d Dialect) error {
	quoted := make([]string, 0, 4)
	for _, k := range scopeKindsInPolicy() {
		quoted = append(quoted, "'"+k+"'")
	}
	in := strings.Join(quoted, ", ")
	for _, t := range []struct {
		table    string
		nullable bool
	}{
		{"provider_stats", false},
		{"user_prices", false},
		{"scope_quota", false},
		{"usage_scope_daily", false},
		{"audit_log", false},
		{"requests", true},
	} {
		if ok, err := d.HasTable(db, t.table); err != nil {
			return err
		} else if !ok {
			continue
		}
		if ok, err := d.HasColumn(db, t.table, "scope_kind"); err != nil {
			return err
		} else if !ok {
			continue
		}
		// 非法取值：不在闭集里，而且不是「NULL（仅 requests 允许）」。
		q := fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE scope_kind NOT IN (%s)
			AND scope_kind IS NOT NULL`, t.table, in)
		n, err := dbScalarInt(db, d, q)
		if err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%w: %s.scope_kind 有 %d 行落在闭集之外（只允许 %s）",
				ErrScopeMigration, t.table, n, in)
		}
		if t.nullable {
			continue
		}
		// NOT NULL 列上 SQL 层不会给 NULL，但 DEFAULT '' 能给出空串。
		n, err = dbScalarInt(db, d, fmt.Sprintf(
			`SELECT COUNT(*) FROM %s WHERE scope_kind=''`, t.table))
		if err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%w: %s 有 %d 行的 scope_kind 是空串 —— 迁移的回填没覆盖到它们，"+
				"归属不明的行不许留在按范围读写的表里", ErrScopeMigration, t.table, n)
		}
	}
	return nil
}

// checkScopeCoverage 数出「无归属的历史请求」与「(user,名) 在 users 里查不到」的行。
//
// 孤儿是**已知状态而不是错误**：DeleteUser 刻意保留 user_prices 的历史价目行与
// usage_user_daily / usage_scope_daily 的账单行（钱已经花掉了）。所以这里只计数、
// 只列来源 —— 既不静默丢，也不当失败。
// scope_quota 例外：那一张是 users 的 1:1 镜像，出现孤儿就是回填出了问题，直接失败。
func checkScopeCoverage(db *sql.DB, d Dialect, rep *ScopeMigrationReport) error {
	if ok, err := d.HasColumn(db, "requests", "scope_kind"); err != nil {
		return err
	} else if ok {
		n, err := dbScalarInt(db, d, `SELECT COUNT(*) FROM requests WHERE scope_kind IS NULL OR scope_id IS NULL`)
		if err != nil {
			return err
		}
		rep.UnknownAttribution = n
	}
	// scope_quota 的孤儿 = 硬失败。
	if err := checkNoOrphanScope(db, d, "scope_quota", true); err != nil {
		return err
	}
	for _, t := range []string{"provider_stats", "user_prices", "usage_scope_daily"} {
		n, err := orphanUserScopeRows(db, d, t)
		if err != nil {
			return err
		}
		if n > 0 {
			rep.OrphanScopeRows += n
			rep.OrphanSources = append(rep.OrphanSources, fmt.Sprintf("%s: %d 行", t, n))
		}
	}
	if rep.OrphanScopeRows > 0 {
		fmt.Fprintf(scopeMigrationOutput,
			"[scope-migration] 有 %d 行的 (user,名) 在 users 里查不到（%s）—— 那是删用户时刻意保留的"+
				"价目/账单行，迁移不丢它们；要清理请人工确认之后再动手\n",
			rep.OrphanScopeRows, strings.Join(rep.OrphanSources, ", "))
	}
	return nil
}

func orphanUserScopeRows(db *sql.DB, d Dialect, table string) (int64, error) {
	if ok, err := d.HasTable(db, table); err != nil || !ok {
		return 0, err
	}
	if ok, err := d.HasColumn(db, table, "scope_kind"); err != nil || !ok {
		return 0, err
	}
	return dbScalarInt(db, d, fmt.Sprintf(`SELECT COUNT(*) FROM %s s WHERE s.scope_kind='user'
		AND NOT EXISTS (SELECT 1 FROM users u WHERE u.name = s.scope_id)`, table))
}

func checkNoOrphanScope(db *sql.DB, d Dialect, table string, strict bool) error {
	n, err := orphanUserScopeRows(db, d, table)
	if err != nil {
		return err
	}
	if n > 0 && strict {
		return fmt.Errorf("%w: %s 有 %d 个 (user,名) 在 users 里查不到 —— 它是 users 的 1:1 镜像，"+
			"不该有孤儿", ErrScopeMigration, table, n)
	}
	return nil
}

// usageUserDailyChargeSQL / usageScopeDailyChargeSQL 是同一份金额读数的两个来源。
//
// 列的顺序完全一致（键那一列换成 scope_kind+scope_id 也一样宽），所以两边共用一份 Scan。
const usageUserDailyChargeSQL = `SELECT day, user_name, provider, model, upstream_model, system_paid,
       requests, ok, failed, prompt_tokens, cache_hit_tokens, cache_miss_tokens,
       completion_tokens, total_tokens, charge, frozen_charges
FROM usage_user_daily ORDER BY day, user_name, provider, model, upstream_model, system_paid`

const usageScopeDailyChargeSQL = `SELECT day, scope_id, provider, model, upstream_model, system_paid,
       requests, ok, failed, prompt_tokens, cache_hit_tokens, cache_miss_tokens,
       completion_tokens, total_tokens, charge, frozen_charges
FROM usage_scope_daily ORDER BY day, scope_kind, scope_id, provider, model, upstream_model, system_paid`

// sumRowCharges 按 RowCharge 口径（冻结优先 + 估算兜底，这里 cost=nil）逐行合计金额。
//
// 刻意不做「先合计再乘系数」：摊分比例按行不同，合并后再算会算错（见 charge.go）。
// 两张表走同一份实现，「迁移前后金额一致」这句话才有意义。
func sumRowCharges(db *sql.DB, d Dialect, q string) (float64, int64, error) {
	if ok, err := d.HasTable(db, tableNameOfChargeQuery(q)); err != nil {
		return 0, 0, err
	} else if !ok {
		return 0, 0, nil
	}
	rows, err := db.Query(d.Rebind(q))
	if err != nil {
		return 0, 0, fmt.Errorf("%w: 读取金额失败: %w", ErrScopeMigration, err)
	}
	defer rows.Close()
	total := 0.0
	n := int64(0)
	for rows.Next() {
		var (
			r                         UsageRow
			key                       string
			systemPaid, reqs, latency int64
			_                         = latency
		)
		if err := rows.Scan(&r.Day, &key, &r.Provider, &r.Model, &r.UpstreamModel, &systemPaid,
			&reqs, &r.OK, &r.Failed, &r.PromptTokens, &r.CacheHitTokens, &r.CacheMissTokens,
			&r.CompletionTokens, &r.TotalTokens, &r.Charge, &r.FrozenCharges); err != nil {
			return total, n, fmt.Errorf("%w: 读取金额失败: %w", ErrScopeMigration, err)
		}
		r.Requests = reqs
		r.SystemPaid = systemPaid != 0
		total += RowCharge(r, nil, time.Time{})
		n++
	}
	if err := rows.Err(); err != nil {
		return total, n, err
	}
	return total, n, nil
}

func absFloat(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

// ------------------------------------------------------------------ 收尾

// dropLegacyStructures（在 finish 里）把 2.x 的遗留结构彻底移除：
// user_prices 的旧列与旧索引、provider_stats 的影子表、users 上的四列配额/限流。
//
// 旧列与旧索引**三种方言都删** —— §2.7 规则 1 要求库里不再留着字符串 scope 列。
// 影子表分两家：
//
//	SQLite   直接删（文件备份是更强的恢复点，留着只会被下一次体检当成脏数据）。
//	MySQL/PG 保留（没有文件级备份，库内这一份是唯一退路），并把清理 SQL 打到日志。
//
// MySQL 删列前必须先删掉建在它上面的索引，否则报错。
func (p *scopeMigrationPlan) finish(st scopeSchemaState, _ *ScopeMigrationReport) error {
	if st.userPricesLegacy {
		if err := p.dropLegacyPriceScope(); err != nil {
			return err
		}
	}
	if st.providerStatsLegacy {
		if p.d.Name() == "sqlite" {
			if err := p.exec(`DROP TABLE IF EXISTS ` + legacyProviderStatsShadow); err != nil {
				return err
			}
		} else {
			fmt.Fprintf(scopeMigrationOutput,
				"[scope-migration] scope 迁移完成。库内影子表 %s 确认无误后可以删：DROP TABLE %s;\n",
				legacyProviderStatsShadow, legacyProviderStatsShadow)
		}
	}
	if err := stampScopeSchemaVersion(p.db, p.d, p.backup, time.Now()); err != nil {
		return err
	}
	p.finished = true
	// 退役 users 的配额列排在**落版本号之后**：这四列不是迁移的任何输入（回填早就跑完了），
	// 删到一半失败也不该把刚校验通过的库回滚掉 —— 版本号已落，fail() 那时会直接返回原始错误，
	// 残余的列交给下一次启动的幂等收尾。
	retireUsersQuotaColumnsQuietly(p.db, p.d)
	return nil
}

// dropLegacyPriceScope 删掉 user_prices 的 2.x 字符串列与建在它上面的索引。
//
// 顺序：先索引后列（MySQL 否则报「索引还在」）。MySQL 的 DROP INDEX 没有 IF EXISTS，
// 所以先问 information_schema 索引在不在 —— 老库来自更早的版本时它可能本来就没有。
func (p *scopeMigrationPlan) dropLegacyPriceScope() error {
	const legacyIdx = "idx_user_prices_key"
	if p.d.Name() == "mysql" {
		ok, err := mysqlHasIndex(p.db, "user_prices", legacyIdx)
		if err != nil {
			return err
		}
		if ok {
			if err := p.exec(dropIndexSQL(p.d, legacyIdx, "user_prices")); err != nil {
				return err
			}
		}
	} else if err := p.exec(dropIndexSQL(p.d, legacyIdx, "user_prices")); err != nil {
		return err
	}
	if _, err := p.db.Exec(p.d.Rebind(`ALTER TABLE user_prices DROP COLUMN scope`)); err != nil {
		return fmt.Errorf("%w: 删除 user_prices.scope 旧列失败（旧列上的索引必须先删干净）: %w",
			ErrScopeMigration, err)
	}
	return nil
}

// usersQuotaLegacyCols 是 2.x 挤在 users 上的配额/限流列，迁移收尾时逐列退役。
//
// enabled 不在名单里：账号能不能用是**身份**事实，主体是用户本身，3.0 照旧读 users.enabled。
// 配额行上那一列叫 enabled 说的是另一件事（这一行的限额生效与否），迁移只做一次性映射，
// 之后两边不再互相镜像 —— 那正是规则 8 要删掉的双写。
var usersQuotaLegacyCols = []string{"quota_month_tokens", "quota_month_cost", "rpm", "max_concurrent"}

// retireUsersQuotaColumns 把 users 上那四列删掉：配额的真值已经在 scope_quota 里。
//
// 为什么**不**像 provider_stats 的影子表那样给 MySQL/PG 留一份：那几列不是备份，
// 而是第二个能读写配额的真值来源。值已经搬完、收口校验刚比过行数，留着只会让
// 「哪一列说了算」重新变成问题 —— 同一条理由适用于 user_prices.scope，
// 那张的旧列也是三种方言都删（见 dropLegacyPriceScope）。
//
// 逐列先问在不在：上一轮删到一半留下的尾巴要靠幂等的后续调用收尾，
// 而重复 DROP 在 MySQL / PG 上是错误而不是空操作。
func retireUsersQuotaColumns(db *sql.DB, d Dialect) error {
	for _, col := range usersQuotaLegacyCols {
		has, err := d.HasColumn(db, "users", col)
		if err != nil {
			return err
		}
		if !has {
			continue
		}
		if _, err := db.Exec(d.Rebind("ALTER TABLE users DROP COLUMN " + col)); err != nil {
			return fmt.Errorf("删 users.%s 失败: %w", col, err)
		}
	}
	return nil
}

// retireUsersQuotaColumnsQuietly 是「收尾顺便把旧列删干净」：删不动不许把库锁在门外。
//
// 三个调用点都在数据已经安全之后（2.x 路径是收口校验通过并落了版本号，另两个是幂等补齐），
// 而 3.0 的读写路径压根不碰那几列（GetScopeQuota 缺行时返回 nil 而不回读 users，见 scope_store.go）。
// 于是「列还在」只是形状没收干净：为一句 cosmetic 的 DDL 失败让 Open 一直报错，
// 等于把一个能用的网关停在门口。
//
// 唯一必须停下来等的是**配额行还没配齐**：那种库里旧列是唯一剩下的配额真值，
// 删了就等于销毁数据，而且 3.0 的读路径会立刻把缺行的用户当成「配额读不出来」。
// 所以这里先数缺行的用户，非零就只打提示。
func retireUsersQuotaColumnsQuietly(db *sql.DB, d Dialect) {
	missing, err := usersWithoutQuotaRows(db, d)
	if err != nil {
		fmt.Fprintf(scopeMigrationOutput,
			"[scope-migration] users 的 2.x 配额列没去检查（%v）—— 保持原样，不影响读写\n", err)
		return
	}
	if missing > 0 {
		fmt.Fprintf(scopeMigrationOutput,
			"[scope-migration] 有 %d 个用户还没有 scope_quota 行，users 的 2.x 配额列因此**保留**："+
				"那是它们唯一的配额真值。补齐配额行后重启即可自动退役\n", missing)
		return
	}
	if err := retireUsersQuotaColumns(db, d); err != nil {
		var hints []string
		for _, col := range usersQuotaLegacyCols {
			hints = append(hints, "ALTER TABLE users DROP COLUMN "+col+";")
		}
		fmt.Fprintf(scopeMigrationOutput,
			"[scope-migration] users 的 2.x 配额列没能删干净（配额真源已经是 scope_quota，"+
				"不影响读写）：%v。手工收尾：%s\n", err, strings.Join(hints, " "))
	}
}

// usersWithoutQuotaRows 数出「users 里有行、scope_quota 里没有对应 (user,名) 行」的用户数。
//
// 收口校验查的是两边**同数**，这一句查的是「谁缺行」—— 退役旧列之前要的是后者，
// 因为同数也可能一边是 alice/bob、另一边是 alice/carol（孤儿那一项另查）。
// 任一张表缺席就返回错误：那时「查不出来」绝不能读成「没人缺行」，
// 否则 scope_quota 还没建的库里，这一步会把唯一的配额真值删掉。
func usersWithoutQuotaRows(db *sql.DB, d Dialect) (int64, error) {
	for _, table := range []string{"users", "scope_quota"} {
		ok, err := d.HasTable(db, table)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, fmt.Errorf("表 %s 不存在，查不了配额行覆盖", table)
		}
	}
	return dbScalarInt(db, d, `SELECT COUNT(*) FROM users u WHERE NOT EXISTS (
		SELECT 1 FROM scope_quota q WHERE q.scope_kind='user' AND q.scope_id = u.name)`)
}

// mysqlHasIndex 报告 MySQL 表上有没有这个索引名（information_schema）。
func mysqlHasIndex(db *sql.DB, table, index string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.statistics
		WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`, table, index).Scan(&n)
	return n > 0, err
}

// ------------------------------------------------------------------ meta 与工具

// metaInt 读一个整数 meta 键（缺行 = 0）。
func metaInt(db *sql.DB, d Dialect, key string) (int64, error) {
	var v int64
	err := db.QueryRow(d.Rebind(`SELECT COALESCE((SELECT value FROM meta WHERE key=?),0)`), key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		// meta 表还不存在（极老的库或半截重建）：当成「没落过版本」。
		if ok, tableErr := d.HasTable(db, "meta"); tableErr == nil && !ok {
			return 0, nil
		}
		return 0, err
	}
	return v, nil
}

// metaSetInt 写一个整数 meta 键。
func metaSetInt(db *sql.DB, d Dialect, key string, value int64) error {
	_, err := db.Exec(d.Rebind(`INSERT INTO meta(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value = ?`), key, value, value)
	return err
}

// stampScopeSchemaVersion 落版本号与迁移时间。
//
// meta 表只有 value INTEGER 一列能存值，所以时间戳存 Unix 毫秒。备份路径与 SHA-256 是文本，
// 存不进整数列 —— 它们打进了日志（scopeMigrationOutput），运维真正需要的是「文件在哪」。
func stampScopeSchemaVersion(db *sql.DB, d Dialect, backup scopeBackup, at time.Time) error {
	if err := metaSetInt(db, d, metaScopeSchemaVersion, ScopeSchemaVersion); err != nil {
		return fmt.Errorf("写 %s 失败: %w", metaScopeSchemaVersion, err)
	}
	if err := metaSetInt(db, d, metaScopeMigratedAt, at.UnixMilli()); err != nil {
		return fmt.Errorf("写 %s 失败: %w", metaScopeMigratedAt, err)
	}
	fmt.Fprintf(scopeMigrationOutput,
		"[scope-migration] scope 结构已升到 %d（%s）；备份：%s；失败时的恢复：%s\n",
		ScopeSchemaVersion, at.Format(time.RFC3339), backupLocationFor(backup), restoreHintFor(backup))
	return nil
}

func backupLocationFor(b scopeBackup) string {
	if b.path != "" {
		return fmt.Sprintf("%s（SHA-256 %s，权限 0600）", b.path, b.sha256)
	}
	return "无（本方言不自动 dump，见外部备份入口）"
}

// restoreHintFor 把「出事之后怎么手工恢复」写清楚 —— 迁移日志的价值全在这句上。
func restoreHintFor(b scopeBackup) string {
	if b.path != "" {
		return fmt.Sprintf("关闭进程，删掉 %s-wal 与 %s-shm，再把备份文件覆盖回 %s",
			b.location, b.location, b.location)
	}
	return "用迁移前在库外做的逻辑备份恢复（本方言没有自动备份）"
}

// tableRowCount 数行数；第二个返回值是「表在不在」（表不存在不报错，返回 0,false,nil）。
//
// 迁移里到处要判「这张表有没有」，用错误文本去嗅探（"no such table" / "relation ... does not exist"）
// 会让三种方言各写一套，所以统一走 Dialect.HasTable。
func tableRowCount(db *sql.DB, d Dialect, table string) (int64, bool, error) {
	ok, err := d.HasTable(db, table)
	if err != nil || !ok {
		return 0, ok, err
	}
	n, err := dbScalarInt(db, d, `SELECT COUNT(*) FROM `+table)
	return n, true, err
}

func dbScalarInt(db *sql.DB, d Dialect, q string) (int64, error) {
	var n int64
	err := db.QueryRow(d.Rebind(q)).Scan(&n)
	return n, err
}

// tableNameOfChargeQuery 从金额读数语句里认 out 表名 —— 只服务于本文件那两条常量。
func tableNameOfChargeQuery(q string) string {
	if strings.Contains(q, "usage_user_daily") {
		return "usage_user_daily"
	}
	return "usage_scope_daily"
}

// execMulti 顺序执行一串语句（补偿回滚用）。
//
// 遇到「这东西本来就没有」继续往下走：补偿路径常常要撤销一个上游阶段没来得及做的动作，
// 那种情况下 DROP 不存在的索引/列是正常结果，不是失败。
func execMulti(db *sql.DB, d Dialect, qs []string) error {
	var errs []string
	for _, q := range qs {
		if _, err := db.Exec(d.Rebind(q)); err != nil {
			if isIgnorableDDL(d, q, err) || isMissingObjectErr(err) {
				continue
			}
			errs = append(errs, fmt.Sprintf("%s: %v", firstLine(q), err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// dropIndexSQL 生成删索引语句（三家写法不同：MySQL 要带表名，SQLite/PG 支持 IF EXISTS）。
func dropIndexSQL(d Dialect, index, table string) string {
	switch d.Name() {
	case "mysql":
		return fmt.Sprintf("DROP INDEX %s ON %s", index, table)
	default:
		return fmt.Sprintf("DROP INDEX IF EXISTS %s", index)
	}
}

// isMissingObjectErr：补偿时会撤一些本来就没建过的东西（索引、列）。
//
// 三家给「对象不存在」的措辞各不相同，这里只认最稳的几种特征串。
func isMissingObjectErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, s := range []string{
		"no such index", "no such table", "no such column", // SQLite
		"Can't DROP", "1091", "doesn't exist", // MySQL
		"does not exist", // PostgreSQL
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------ 运维只读入口

// ScopeMigrationCheck 是运维脚本与 `--check` 用的只读体检：跑一遍映射预检 + 四项校验，
// **不改任何数据**，返回报告与「现在迁移会不会失败」的结论。
//
// 手册 §2.7 要求「确定性、可核对」：可核对的意思是动手之前就能拿到这些数字。
// 判据没有第二份 —— 用的就是迁移自己那套 preflight / verify 函数，
// 所以「体检通过」与「迁移不会失败」这两句话是同义的。
func ScopeMigrationCheck(driver, pathOrDSN string) (*ScopeMigrationReport, error) {
	d, err := dialectByName(driver)
	if err != nil {
		return nil, err
	}
	db, err := d.Open(pathOrDSN)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	st, err := loadScopeSchemaState(db, d)
	if err != nil {
		return nil, err
	}
	if conflict := st.pendingTablesConflict(); conflict != nil {
		return nil, conflict
	}
	rep, err := preflightScopeMapping(db, d, st)
	if err != nil {
		return nil, err
	}
	rep.From30Only = !st.needsWork()
	if cur, err := metaInt(db, d, metaScopeSchemaVersion); err == nil && cur >= ScopeSchemaVersion {
		rep.From30Only = true
	}
	if d.Name() == "sqlite" {
		rep.Location = filepath.Base(pathOrDSN)
	} else {
		rep.Location = d.Name()
		rep.ExternalDump = externalDumpHint(d)
	}
	// 已经迁完 / 结构就位：把终值报出来；还没迁：报的是「现在这张库」的读数，
	// 行守恒那一项在这里没有前后差可看，所以只报数不判失败。
	if rep.ProviderStatsAfter, _, err = tableRowCount(db, d, "provider_stats"); err != nil {
		return nil, err
	}
	if rep.UserPricesAfter, _, err = tableRowCount(db, d, "user_prices"); err != nil {
		return nil, err
	}
	if rep.RequestsAfter, _, err = tableRowCount(db, d, "requests"); err != nil {
		return nil, err
	}
	if rep.ScopeQuotaRows, _, err = tableRowCount(db, d, "scope_quota"); err != nil {
		return nil, err
	}
	if rep.UsageScopeRows, _, err = tableRowCount(db, d, "usage_scope_daily"); err != nil {
		return nil, err
	}
	if err := checkPKUniquenessAll(db, d); err != nil {
		return nil, err
	}
	if err := checkScopeKindClosed(db, d); err != nil {
		return nil, err
	}
	if err := checkScopeCoverage(db, d, rep); err != nil {
		return nil, err
	}
	// 两张用量表都已经存在时才比金额（否则比的是「还没灌」与「灌了」）。
	if st.usageUserDaily && st.usageScopeDaily {
		userTotal, userRows, err := sumRowCharges(db, d, usageUserDailyChargeSQL)
		if err != nil {
			return nil, err
		}
		scopeTotal, scopeRows, err := sumRowCharges(db, d, usageScopeDailyChargeSQL)
		if err != nil {
			return nil, err
		}
		rep.ChargeUser, rep.ChargeScope = userTotal, scopeTotal
		if userRows != scopeRows {
			return nil, fmt.Errorf("%w: 两张用量表行数已经不一致 usage_user_daily=%d usage_scope_daily=%d",
				ErrScopeMigration, userRows, scopeRows)
		}
		if diff := absFloat(scopeTotal - userTotal); diff > scopeMoneyTolerance {
			return nil, fmt.Errorf("%w: 两张用量表金额已经不一致（RowCharge 口径）%.10f vs %.10f，差 %.10f 元",
				ErrScopeMigration, userTotal, scopeTotal, diff)
		}
	}
	return rep, nil
}

// checkPKUniquenessAll 给只读体检用：三张表逐个查。
func checkPKUniquenessAll(db *sql.DB, d Dialect) error {
	for _, t := range pkCheckTables() {
		if err := checkPKUniqueness(db, d, t.table, t.cols); err != nil {
			return err
		}
	}
	return nil
}

// ScopeMigrationReportForDialect 报告当前库的迁移状态（已连好的 Store 上）。
func (s *Store) ScopeMigrationReportForDialect() (*ScopeMigrationReport, error) {
	st, err := loadScopeSchemaState(s.db, s.dialect)
	if err != nil {
		return nil, err
	}
	if conflict := st.pendingTablesConflict(); conflict != nil {
		return nil, conflict
	}
	rep, err := preflightScopeMapping(s.db, s.dialect, st)
	if err != nil {
		return nil, err
	}
	rep.From30Only = !st.needsWork()
	if n, _, err := tableRowCount(s.db, s.dialect, "scope_quota"); err == nil {
		rep.ScopeQuotaRows = n
	}
	if n, _, err := tableRowCount(s.db, s.dialect, "usage_scope_daily"); err == nil {
		rep.UsageScopeRows = n
	}
	if err := checkScopeCoverage(s.db, s.dialect, rep); err != nil {
		return nil, err
	}
	return rep, nil
}
