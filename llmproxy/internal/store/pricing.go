package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 计价与成本模型（设计见 docs/pricing-design.md）的存储层。
//
// 两层价格，用途分离：
//
//	provider_prices  上游价 —— 我们付给上游多少钱，驱动路由择廉与真实成本
//	user_prices      分发价 —— 我们向用户收多少钱，驱动计费与配额
//
// 价格**只在整点生效**（与使用者的约定）：valid_from 必须是整点，校验拒绝非整点，
// 不静默取整 —— 静默取整会在「我以为立即生效」的场景里造成账目对不上。
// 生效区间是**半开区间** [valid_from, valid_to)：valid_to=0 表示一直有效。
//
// 价目行按时间**只追加**：同一 (键) 上新行的 valid_from 必须严格晚于已有行，
// 插入时把此前仍然有效（valid_to=0）的那条收口成 [旧行.valid_from, 新行.valid_from)。
// 这样历史天然保留，账目可回溯 —— 这正是「记录历史计价」的落地方式。

// pricingSchema 是 var：user_prices 的范围两列与老库 ALTER 共用一份定义（见下面注释）。
//
// 分发价按范围键定之后，2.x 的 idx_user_prices_key（建在字符串 scope 上）由一次性迁移换掉：
// 新索引 idx_user_prices_scope 也**不在这里建** —— 老库补列之前它会长在一个不存在的列上。
// 两条（建新索引、删旧索引 + 旧列）都排在 scope_migration.go 的阶段里，顺序是
// 「列 → 新索引 → 校验通过 → 删旧索引 → 删旧列」。
var pricingSchema = `
CREATE TABLE IF NOT EXISTS provider_prices (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  provider           TEXT    NOT NULL,
  upstream_model     TEXT    NOT NULL,
  currency           TEXT    NOT NULL DEFAULT 'CNY',
  in_miss            REAL    NOT NULL DEFAULT 0,
  in_hit             REAL    NOT NULL DEFAULT 0,
  in_write           REAL    NOT NULL DEFAULT 0,
  out                REAL    NOT NULL DEFAULT 0,
  reasoning_out      REAL    NOT NULL DEFAULT 0,
  per_request_fee    REAL    NOT NULL DEFAULT 0,
  peak_hours         TEXT    NOT NULL DEFAULT '',
  off_peak_ratio     REAL,
  peak_tz            TEXT    NOT NULL DEFAULT '',
  valid_from         INTEGER NOT NULL,
  valid_to           INTEGER NOT NULL DEFAULT 0,
  note               TEXT    NOT NULL DEFAULT '',
  created_at         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_provider_prices_key ON provider_prices(provider, upstream_model, valid_from);

-- 分发价按**范围**键定（3.0 §2.7 规则 1/2）：scope_kind + scope_id 两列，
-- 不再有 2.x 那个 'default' / 'user:<名>' 的字符串前缀列。
-- 表名沿用 user_prices 没改：改名只动得到 SQL 与文档，动不到 Go 侧的 UserPrice/ScopePrice 调用点，
-- 而 README、docs/pricing-design.md、docs/OVERVIEW.md 都在本工作包的可改范围之外。
-- 改名与否则归主线接线那一步统一处理（取舍见 scope_migration.go 顶部的说明）。
--
-- 两列的定义与老库 ALTER 用的那份是同一个（scope_schema.go 的 userPricesScopeCols30）：
-- 新库建表带上、老库补齐并回填，两处永远逐列一致。DEFAULT '' 只是 ALTER 的语法要求
-- （NOT NULL 列不能无默认地加在有数据的表上），迁移的收口校验会保证落库的行范围非空。
CREATE TABLE IF NOT EXISTS user_prices (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
` + scopeColsFragment(userPricesScopeCols30) + `,
  model              TEXT    NOT NULL,
  currency           TEXT    NOT NULL DEFAULT 'CNY',
  in_miss            REAL    NOT NULL DEFAULT 0,
  in_hit             REAL    NOT NULL DEFAULT 0,
  in_write           REAL    NOT NULL DEFAULT 0,
  out                REAL    NOT NULL DEFAULT 0,
  reasoning_out      REAL    NOT NULL DEFAULT 0,
  per_request_fee    REAL    NOT NULL DEFAULT 0,
  peak_hours         TEXT    NOT NULL DEFAULT '',
  off_peak_ratio     REAL,
  peak_tz            TEXT    NOT NULL DEFAULT '',
  valid_from         INTEGER NOT NULL,
  valid_to           INTEGER NOT NULL DEFAULT 0,
  note               TEXT    NOT NULL DEFAULT '',
  created_at         INTEGER NOT NULL
);
`

// ProviderPrice 是一条**上游**价目行：供应商 × 上游模型 × 一段生效期。
// 单价单位统一为「每百万 token」，与各家官网报价口径一致。
type ProviderPrice struct {
	ID            int64
	Provider      string
	UpstreamModel string
	Currency      string
	InMiss        float64
	InHit         float64
	InWrite       float64 // 0 = 与 InMiss 同价
	Out           float64
	ReasoningOut  float64 // 0 = 与 Out 同价
	PerRequestFee float64
	// 峰谷规则：价目行自带，空则**沿用全局**（config.yaml 的 pricing 段）。
	// 按供应商所在时区判（TZ 形如 "+08:00"），不是服务器时区。
	PeakHours    []string // nil = 沿用全局
	OffPeakRatio *float64 // nil = 沿用全局
	PeakTZ       string   // "" = 沿用全局
	ValidFrom    time.Time
	ValidTo      time.Time // 零值 = 一直有效
	Note         string
	CreatedAt    time.Time
}

// UserPrice 是一条**分发**价目行的旧形状（我们向用户收多少）。
//
// Scope 是 2.x 的字符串前缀约定（"default" / "user:<用户名>"），表里已经没有这一列，
// 读写都经过 scope.go 的编解码适配到 (scope_kind, scope_id)。
//
// §2.7 规则 8：主线接线完成后删除整个结构，调用方改用 ScopePrice
// （字段同名，范围换成 policy.ScopeRef）。
type UserPrice struct {
	ID            int64
	Scope         string
	Model         string // 下游模型名（客户端填的那个）
	Currency      string
	InMiss        float64
	InHit         float64
	InWrite       float64
	Out           float64
	ReasoningOut  float64
	PerRequestFee float64
	PeakHours     []string // 同上，空 = 沿用全局
	OffPeakRatio  *float64
	PeakTZ        string
	ValidFrom     time.Time
	ValidTo       time.Time
	Note          string
	CreatedAt     time.Time
}

// ScopeDefault 是分发价的全局默认作用域。§2.7 规则 8：主线接线完成后删除。
const ScopeDefault = "default"

// ScopeUser 拼出旧接口的单用户作用域串。§2.7 规则 8：主线接线完成后删除。
func ScopeUser(userName string) string { return "user:" + userName }

// onTheHour 报告时刻是否落在整点（按其自身 Location 的钟面表示：分/秒/纳秒全为 0）。
//
// 这是与使用者的约定：**价格只在整点生效**。校验拒绝非整点，不静默取整。
// 调用方应当传入运营时区下的时刻（生产是 Asia/Shanghai）。
func onTheHour(t time.Time) bool {
	return t.Minute() == 0 && t.Second() == 0 && t.Nanosecond() == 0
}

func validateRate(name string, v float64) error {
	if v < 0 {
		return fmt.Errorf("%s 不能为负，当前是 %v", name, v)
	}
	return nil
}

// validatePeak 校验价目行自带的峰谷规则。
// 空值（= 沿用全局）不做校验 —— 那是 config.yaml 里 pricing 段的事。
//
// 但「显式填 0」要拒：0 意味着空闲时段免费，而 config.PeakRule.RatioAt 会把 <= 0
// 当成「未设置」按不打折处理，所以填 0 既拿不到免费、又几乎肯定是笔误
// （多半是想沿用全局却写了个 0）。这里分得清 nil 与 0，就在这一层说清楚。
func validatePeak(hours []string, ratio *float64, tz string) error {
	if len(hours) > 0 && ratio != nil && *ratio <= 0 {
		return fmt.Errorf("off_peak_ratio 需要是 0~1 之间的正数（1 表示不分时段），当前是 %v；"+
			"想沿用全局的系数就不要传这个字段", *ratio)
	}
	r := config.PeakRule{Hours: hours, TZ: tz}
	if ratio != nil {
		r.OffPeakRatio = *ratio
	}
	return r.Validate()
}

func (p *ProviderPrice) validate() error {
	if strings.TrimSpace(p.Provider) == "" {
		return errors.New("provider 不能为空")
	}
	if strings.TrimSpace(p.UpstreamModel) == "" {
		return errors.New("upstream_model 不能为空")
	}
	if strings.TrimSpace(p.Currency) == "" {
		p.Currency = "CNY"
	}
	if p.ValidFrom.IsZero() {
		return errors.New("valid_from 不能为空")
	}
	if !onTheHour(p.ValidFrom) {
		return fmt.Errorf("valid_from 必须是整点（价格只在整点生效），当前是 %s", p.ValidFrom.Format(time.RFC3339))
	}
	if !p.ValidTo.IsZero() {
		if !onTheHour(p.ValidTo) {
			return fmt.Errorf("valid_to 必须是整点，当前是 %s", p.ValidTo.Format(time.RFC3339))
		}
		if !p.ValidTo.After(p.ValidFrom) {
			return fmt.Errorf("valid_to 需要晚于 valid_from，当前是 %s → %s",
				p.ValidFrom.Format(time.RFC3339), p.ValidTo.Format(time.RFC3339))
		}
	}
	for _, c := range []struct {
		name string
		v    float64
	}{
		{"in_miss", p.InMiss}, {"in_hit", p.InHit}, {"in_write", p.InWrite},
		{"out", p.Out}, {"reasoning_out", p.ReasoningOut}, {"per_request_fee", p.PerRequestFee},
	} {
		if err := validateRate(c.name, c.v); err != nil {
			return err
		}
	}
	return validatePeak(p.PeakHours, p.OffPeakRatio, p.PeakTZ)
}

// legacyUserPriceToScope 把旧的字符串作用域行转成结构化行；范围串非法时返回旧接口的错误文案。
//
// 校验口径只有一份：ScopePrice.validate()。这里只负责「旧归一化 + 解码」——
// 空 scope 仍然当 default 处理并写回调用方的结构体（旧行为，有测试钉住）。
//
// §2.7 规则 8：主线接线完成后删除。
func legacyUserPriceToScope(p *UserPrice) (*ScopePrice, error) {
	scopeStr := strings.TrimSpace(p.Scope)
	if scopeStr == "" {
		scopeStr = ScopeDefault
		p.Scope = ScopeDefault
	}
	scope, err := DecodeLegacyPriceScope(scopeStr)
	if err != nil {
		return nil, err
	}
	return &ScopePrice{
		ID: p.ID, Scope: scope, Model: p.Model, Currency: p.Currency,
		InMiss: p.InMiss, InHit: p.InHit, InWrite: p.InWrite, Out: p.Out,
		ReasoningOut: p.ReasoningOut, PerRequestFee: p.PerRequestFee,
		PeakHours: p.PeakHours, OffPeakRatio: p.OffPeakRatio, PeakTZ: p.PeakTZ,
		ValidFrom: p.ValidFrom, ValidTo: p.ValidTo, Note: p.Note, CreatedAt: p.CreatedAt,
	}, nil
}

func tsOf(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func timeOf(ts int64) time.Time {
	if ts == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ts).UTC()
}

// InsertProviderPrice 插入一条新的上游价目行，并把同键上此前仍然有效的那条收口。
//
// 只追加：同一 (provider, upstream_model) 上新行的 valid_from 必须严格晚于已有行，
// 否则报错 —— 回头插更早的价格等于改写历史，正是「记录历史计价」要避免的事。
func (s *Store) InsertProviderPrice(p *ProviderPrice) error {
	if p == nil {
		return errors.New("价目行为空")
	}
	if err := p.validate(); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var latest int64
	err = txQueryRow(tx, s.dialect, `SELECT COALESCE(MAX(valid_from),0) FROM provider_prices WHERE provider=? AND upstream_model=?`,
		p.Provider, p.UpstreamModel).Scan(&latest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if latest != 0 && p.ValidFrom.UnixMilli() <= latest {
		return fmt.Errorf("价目按时间只追加：%s 的 %s 已有 valid_from=%s，新行不得早于或等于它",
			p.Provider, p.UpstreamModel, time.UnixMilli(latest).UTC().Format(time.RFC3339))
	}

	if _, err := txExec(tx, s.dialect, `UPDATE provider_prices SET valid_to=? WHERE provider=? AND upstream_model=? AND valid_to=0`,
		p.ValidFrom.UnixMilli(), p.Provider, p.UpstreamModel); err != nil {
		return err
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	id, err := insertID(tx, s.dialect, `INSERT INTO provider_prices
		(provider, upstream_model, currency, in_miss, in_hit, in_write, out, reasoning_out,
		 per_request_fee, peak_hours, off_peak_ratio, peak_tz, valid_from, valid_to, note, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.Provider, p.UpstreamModel, p.Currency, p.InMiss, p.InHit, p.InWrite, p.Out, p.ReasoningOut,
		p.PerRequestFee, strings.Join(p.PeakHours, ","), p.OffPeakRatio, p.PeakTZ,
		p.ValidFrom.UnixMilli(), tsOf(p.ValidTo), p.Note, p.CreatedAt.UnixMilli())
	if err != nil {
		return err
	}
	p.ID = id
	return tx.Commit()
}

// InsertUserPrice 插入一条分发价目行（旧字符串作用域接口）。
//
// 实现已经整体委托给 InsertScopePrice —— 追加、收口、校验只有一份实现，
// 避免「新旧两套口径算出不同金额」。
//
// §2.7 规则 8：主线接线完成后删除，调用方改用 InsertScopePrice。
func (s *Store) InsertUserPrice(p *UserPrice) error {
	if p == nil {
		return errors.New("价目行为空")
	}
	sp, err := legacyUserPriceToScope(p)
	if err != nil {
		return err
	}
	if err := s.InsertScopePrice(sp); err != nil {
		return err
	}
	p.ID = sp.ID
	return nil
}

const providerPriceCols = `id, provider, upstream_model, currency, in_miss, in_hit, in_write,
	out, reasoning_out, per_request_fee, peak_hours, off_peak_ratio, peak_tz,
	valid_from, valid_to, note, created_at`

// 分发价的列与读取路径只有一份：scopePriceCols / scanScopePrice（见 scope_store.go）。
// 旧接口的 UserPrice 由 ScopePrice.ToLegacy() 转换出来 —— 表里已没有 scope 字符串列，
// 这里不再维护第二套列清单：两套 SELECT 不同步曾经让价目静默查不出来。

// scanProviderPrice 是该表的**唯一**读取路径。
// 列与 Scan 必须一一对应，抽出来是为了让「加了列忘了改 Scan」这类错
// 只可能发生在一个地方（曾经因为 SELECT 与 Scan 不同步而静默查不出数据）。
func scanProviderPrice(row interface{ Scan(...any) error }) (*ProviderPrice, error) {
	var (
		p         ProviderPrice
		peak      string
		offPeak   sql.NullFloat64
		validFrom int64
		validTo   int64
		createdAt int64
	)
	if err := row.Scan(&p.ID, &p.Provider, &p.UpstreamModel, &p.Currency, &p.InMiss, &p.InHit,
		&p.InWrite, &p.Out, &p.ReasoningOut, &p.PerRequestFee, &peak, &offPeak, &p.PeakTZ,
		&validFrom, &validTo, &p.Note, &createdAt); err != nil {
		return nil, err
	}
	if peak != "" {
		p.PeakHours = strings.Split(peak, ",")
	}
	if offPeak.Valid {
		v := offPeak.Float64
		p.OffPeakRatio = &v
	}
	p.ValidFrom = timeOf(validFrom)
	p.ValidTo = timeOf(validTo)
	p.CreatedAt = timeOf(createdAt)
	return &p, nil
}

// ProviderPriceAt 查某个时刻对该 (供应商, 上游模型) 生效的上游价目行；没有则返回 nil。
// 生效区间是半开区间 [valid_from, valid_to)。价目行本身整点生效，所以用时刻本身判断
// 与「先整点截断再查」等价。
//
// ORDER BY 带 `id DESC` 做确定性 tie-break：正常情况下同一 (供应商, 模型) 不该有两条
// valid_from 相同的行（插入时的「只追加」校验会拒），但表上**没有 UNIQUE 约束**，
// 直接 SQL 插入仍可能造出并列。没有 tie-break 时 LIMIT 1 取哪条由 SQLite 决定，
// 同一份库两次查可能给出不同金额 —— 那是不可复现的账。
//
// 实测下来 SQLite 目前**碰巧**给出与 `id DESC` 相同的结果（索引会隐式附加 rowid，
// 等值 valid_from 的条目按 rowid 升序排列，DESC 扫描自然先遇到最大 id）。
// 但那是实现细节、不是契约，所以这里显式写出来。也正因为碰巧一致，
// 这一条**没有**回归测试能区分「有 tie-break」与「没有」—— 写过的版本在去掉
// tie-break 后照样通过，那种测试只会制造假信心，已删除。
//
// 跨进程竞态造不出并列：DSN 里带了 _txlock=immediate，事务一开始就拿写锁，
// 第二个事务必须等第一个提交，于是它的 SELECT MAX(valid_from) 能看到前者的行、
// 被「只追加」校验拒掉。这也是没有给两张价目表加 UNIQUE 约束的理由 ——
// 为一个 API 已不可达的状态在有真实数据的生产库上做迁移，不划算。
func (s *Store) ProviderPriceAt(provider, upstreamModel string, t time.Time) (*ProviderPrice, error) {
	if strings.TrimSpace(provider) == "" || strings.TrimSpace(upstreamModel) == "" {
		return nil, errors.New("provider 与 upstream_model 不能为空")
	}
	ts := t.UnixMilli()
	row := s.queryRow(`SELECT `+providerPriceCols+` FROM provider_prices
		WHERE provider=? AND upstream_model=? AND valid_from<=? AND (valid_to=0 OR valid_to>?)
		ORDER BY valid_from DESC, id DESC LIMIT 1`, provider, upstreamModel, ts, ts)
	p, err := scanProviderPrice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

// ProviderPricesEffective 给出某时刻仍然生效的**全部**上游价目行，按 (供应商, 上游模型) 排序。
// 路由（规则 B）用它算「现在谁便宜」。
func (s *Store) ProviderPricesEffective(t time.Time) ([]ProviderPrice, error) {
	ts := t.UnixMilli()
	rows, err := s.query(`SELECT `+providerPriceCols+` FROM provider_prices
		WHERE valid_from<=? AND (valid_to=0 OR valid_to>?)
		ORDER BY provider, upstream_model`, ts, ts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []ProviderPrice{}
	for rows.Next() {
		p, err := scanProviderPrice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// UserPriceAt 查某个时刻该用户对该**下游**模型的分发价：
// 先找 (user, <名>)，没有则回落 (system, 'global')（旧 scope=default）；都没有返回 nil。
//
// 实现委托 ScopePriceAt，范围由 scope.go 的解码器集中给出 —— 旧的 'user:' 前缀解析
// 在这一份代码里只出现一次。
//
// §2.7 规则 8：主线接线完成后删除，调用方改用 ScopePriceAt / ScopePriceAtChain。
func (s *Store) UserPriceAt(userName, model string, t time.Time) (*UserPrice, error) {
	if strings.TrimSpace(model) == "" {
		return nil, errors.New("model 不能为空")
	}
	// 最具体的那条生效：用户名在前，全局兜底在后。
	// 用户名非法（含冒号/控制字符）时旧接口同样查不到行（那种键插不进来），
	// 所以这一腿直接跳过，行为与旧的「查不到就回落」等价。
	legs := []policy.ScopeRef{policy.SystemScope}
	if userScope, err := legacyUserScope(userName); err == nil {
		legs = []policy.ScopeRef{userScope, policy.SystemScope}
	}
	for _, scope := range legs {
		p, err := s.ScopePriceAt(scope, model, t)
		if err != nil || p != nil {
			if p == nil {
				return nil, err
			}
			return p.ToLegacy(), err
		}
	}
	return nil, nil
}

// HasEffectiveUserPrices 报告当前是否有生效的分发价目行（该用户的覆盖，或 default）。
//
// 用来回答「这个部署到底有没有在计价」。不能只看 config.yaml 的 legacy pricing 表 ——
// 那张表已经退居为「没有价目行时的估算兜底」，真正的价目在库里。只报 legacy 表的话，
// 明明录了价目、金额也确实在按请求冻结，接口却仍然回 priced:false，字面自相矛盾。
//
// §2.7 规则 8：主线接线完成后删除，调用方改用 HasEffectiveScopePrices。
func (s *Store) HasEffectiveUserPrices(userName string, t time.Time) (bool, error) {
	scopes := []policy.ScopeRef{policy.SystemScope}
	if userScope, err := legacyUserScope(userName); err == nil {
		scopes = append(scopes, userScope)
	}
	return s.HasEffectiveScopePrices(t, scopes...)
}

// UserPricesEffective 给出在 t 时刻生效的全部分发价目行（跨范围，含全局默认与各用户覆盖）。
// 旧的 scope 串由 ScopePrice.ToLegacy() 还原；组织/项目级的行还原不出来，
// Scope 留空串 —— 旧接口本就没有那种范围，调用方（`llmproxy status`）只用来数条数。
//
// §2.7 规则 8：主线接线完成后删除，调用方改用 ListAllScopePrices。
func (s *Store) UserPricesEffective(t time.Time) ([]UserPrice, error) {
	rows, err := s.ListAllScopePrices(t)
	if err != nil {
		return nil, err
	}
	out := make([]UserPrice, 0, len(rows))
	for i := range rows {
		out = append(out, *rows[i].ToLegacy())
	}
	return out, nil
}

// ListProviderPrices 列出某个 (供应商, 上游模型) 的全部价目行（含历史），按 valid_from 升序。
// 界面与排障用：要看「这个模型什么时候涨过价」时直接读它。
func (s *Store) ListProviderPrices(provider, upstreamModel string) ([]ProviderPrice, error) {
	rows, err := s.query(`SELECT `+providerPriceCols+` FROM provider_prices
		WHERE provider=? AND upstream_model=? ORDER BY valid_from ASC`, provider, upstreamModel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []ProviderPrice{}
	for rows.Next() {
		p, err := scanProviderPrice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// ListUserPrices 列出某个 (旧 scope 串, 模型) 的全部分发价目行（含历史），按 valid_from 升序。
//
// 两处口径刻意与旧实现一致：
//   - scope 串无法映射 → 返回空结果而不是报错。管理台允许任意串进来查询，映射不上
//     等价于「那个范围一行都没有」；迁移已保证库里不存在映射不出来的行，所以这里没有
//     静默丢数据的风险（服务端在 scope/model 为空时本就返回 400）。
//   - model 为空 → 同样返回空。旧的 `WHERE scope=? AND model=?` 就是这个结果；
//     要「某范围的全部模型」请用 ListScopePrices。
//
// §2.7 规则 8：主线接线完成后删除，调用方改用 ListScopePrices。
func (s *Store) ListUserPrices(scope, model string) ([]UserPrice, error) {
	ref, err := DecodeLegacyPriceScope(strings.TrimSpace(scope))
	if err != nil {
		if errors.Is(err, ErrLegacyScope) {
			return []UserPrice{}, nil
		}
		return nil, err
	}
	if strings.TrimSpace(model) == "" {
		return []UserPrice{}, nil
	}
	rows, err := s.ListScopePrices(ref, model)
	if err != nil {
		return nil, err
	}
	out := make([]UserPrice, 0, len(rows))
	for i := range rows {
		out = append(out, *rows[i].ToLegacy())
	}
	return out, nil
}

// migratePricingColumns 给**已有**的库补上计价冻结相关列。
// 新库由 schema 里的 DDL 一次建全，这里只管老库升级（生产上的库已经有 requests/usage_daily 数据）。
func migratePricingColumns(db *sql.DB, d Dialect) error {
	// 峰谷时区是后加的：老库的价目表已经有 peak_hours / off_peak_ratio
	//（user_prices 连这两个都没有），这里一次补齐。
	if err := addColumnsIfMissing(db, d, "provider_prices", map[string]string{
		"peak_tz": "TEXT NOT NULL DEFAULT ''",
	}); err != nil {
		return err
	}
	if err := addColumnsIfMissing(db, d, "user_prices", map[string]string{
		"peak_hours":     "TEXT NOT NULL DEFAULT ''",
		"off_peak_ratio": "REAL",
		"peak_tz":        "TEXT NOT NULL DEFAULT ''",
	}); err != nil {
		return err
	}
	if err := addColumnsIfMissing(db, d, "requests", map[string]string{
		"cache_write_tokens":  "INTEGER",
		"price_upstream_id":   "INTEGER NOT NULL DEFAULT 0",
		"cost_upstream":       "REAL",
		"price_downstream_id": "INTEGER NOT NULL DEFAULT 0",
		"charge":              "REAL",
		"currency":            "TEXT NOT NULL DEFAULT ''",
	}); err != nil {
		return err
	}
	if err := addColumnsIfMissing(db, d, "usage_daily", map[string]string{
		"cost_upstream":   "REAL NOT NULL DEFAULT 0",
		"frozen_requests": "INTEGER NOT NULL DEFAULT 0",
	}); err != nil {
		return err
	}
	return addColumnsIfMissing(db, d, "usage_user_daily", map[string]string{
		"charge":         "REAL NOT NULL DEFAULT 0",
		"frozen_charges": "INTEGER NOT NULL DEFAULT 0",
	})
}
