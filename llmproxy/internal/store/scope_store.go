package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 3.0 结构化 scope 的读写 API（手册 §2.7 规则 4）。
//
// 一律收 policy.ScopeRef / policy.ScopeChain，返回结构化范围，**不提供任何字符串 scope 入参的新方法**。
// 文件末尾的「旧 API 适配」一节才出现裸串，且每个都标了删除时机。

// ------------------------------------------------------------------ 熔断桶

// providerBucketCols 与 scanProviderBucket 成对维护：列顺序改一处必须改另一处。
const providerBucketCols = `scope_kind, scope_id, name, enabled, consecutive_failures, unhealthy_until,
       COALESCE(last_error,''), COALESCE(last_success_at,0), COALESCE(last_failure_at,0),
       total_requests, total_failures`

func scanProviderBucket(sc interface{ Scan(...any) error }) (ProviderBucketState, error) {
	var st ProviderBucketState
	var kind string
	var enabled, unhealthyUntil, lastOK, lastFail int64
	if err := sc.Scan(&kind, &st.Scope.ID, &st.Name, &enabled, &st.ConsecutiveFailures, &unhealthyUntil,
		&st.LastError, &lastOK, &lastFail, &st.TotalRequests, &st.TotalFailures); err != nil {
		return st, err
	}
	parsed, err := policy.ParseScopeKind(kind)
	if err != nil {
		return st, fmt.Errorf("provider_stats 里有非法 scope_kind: %w", err)
	}
	st.Scope = policy.ScopeRef{Kind: parsed, ID: st.Scope.ID}
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
	return st, nil
}

// SaveProviderBucketStates 批量写入路由桶 (scope, provider) 的熔断状态。
//
// 冲突键就是表主键 (scope_kind, scope_id, provider) —— §2.7 规则 4 的桶最终键，
// 所以「同一个桶的两次写入」合并、「不同主体的同名 provider」互不覆盖，都不需要应用层判重。
func (s *Store) SaveProviderBucketStates(states []ProviderBucketState) error {
	for _, st := range states {
		if err := checkScope("SaveProviderBucketStates", st.Scope); err != nil {
			return err
		}
		if st.Name == "" {
			return errors.New("SaveProviderBucketStates: provider 名不能为空")
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(s.rebind(`
INSERT INTO provider_stats (
  scope_kind, scope_id, name, enabled, consecutive_failures, unhealthy_until,
  last_error, last_success_at, last_failure_at, total_requests, total_failures, updated_at
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(scope_kind, scope_id, name) DO UPDATE SET
  enabled              = excluded.enabled,
  consecutive_failures = excluded.consecutive_failures,
  unhealthy_until      = excluded.unhealthy_until,
  last_error           = excluded.last_error,
  last_success_at      = excluded.last_success_at,
  last_failure_at      = excluded.last_failure_at,
  total_requests       = excluded.total_requests,
  total_failures       = excluded.total_failures,
  updated_at           = excluded.updated_at`))
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().UnixMilli()
	for _, st := range states {
		enabled := 0
		if st.Enabled {
			enabled = 1
		}
		if _, err := stmt.Exec(
			string(st.Scope.Kind), st.Scope.ID, st.Name, enabled, st.ConsecutiveFailures, nowMs(st.UnhealthyUntil),
			st.LastError, nowMs(st.LastSuccessAt), nowMs(st.LastFailureAt),
			st.TotalRequests, st.TotalFailures, now,
		); err != nil {
			return fmt.Errorf("写入 provider_stats %s 失败: %w", st.bucketKey(), err)
		}
	}
	return tx.Commit()
}

// LoadProviderBucketStates 读取全部桶状态（重启后恢复熔断）。
//
// 返回切片而不是 map：把 (kind,id,name) 折成复合键就会丢信息，且复合键正是 §2.7 规则 1 禁止的形式。
// ORDER BY 让恢复结果不依赖 SQL 返回顺序：同一份库两次读出来必须一样。
func (s *Store) LoadProviderBucketStates() ([]ProviderBucketState, error) {
	rows, err := s.query(`SELECT ` + providerBucketCols + `
FROM provider_stats ORDER BY scope_kind, scope_id, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProviderBuckets(rows)
}

// LoadProviderBucketsForScope 读取某个主体名下的全部桶（接线时给 router 按 scope 装桶用）。
func (s *Store) LoadProviderBucketsForScope(scope policy.ScopeRef) ([]ProviderBucketState, error) {
	if err := checkScope("LoadProviderBucketsForScope", scope); err != nil {
		return nil, err
	}
	rows, err := s.query(`SELECT `+providerBucketCols+`
FROM provider_stats WHERE scope_kind=? AND scope_id=? ORDER BY name`, scopeArgs(scope)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProviderBuckets(rows)
}

func scanProviderBuckets(rows *sql.Rows) ([]ProviderBucketState, error) {
	out := []ProviderBucketState{}
	for rows.Next() {
		st, err := scanProviderBucket(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// DeleteProviderBucketsForScope 清掉某个主体的全部桶（删用户时级联用，防止同名新用户继承熔断计数）。
func (s *Store) DeleteProviderBucketsForScope(scope policy.ScopeRef) (int64, error) {
	if err := checkScope("DeleteProviderBucketsForScope", scope); err != nil {
		return 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := txExec(tx, s.dialect, `DELETE FROM provider_stats WHERE scope_kind=? AND scope_id=?`, scopeArgs(scope)...)
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

// ------------------------------------------------------------------ 分发价

const scopePriceCols = `id, scope_kind, scope_id, model, currency, in_miss, in_hit, in_write,
	out, reasoning_out, per_request_fee, peak_hours, off_peak_ratio, peak_tz,
	valid_from, valid_to, note, created_at`

func scanScopePrice(row interface{ Scan(...any) error }) (*ScopePrice, error) {
	var (
		p         ScopePrice
		kind      string
		peak      string
		offPeak   sql.NullFloat64
		validFrom int64
		validTo   int64
		createdAt int64
	)
	if err := row.Scan(&p.ID, &kind, &p.Scope.ID, &p.Model, &p.Currency, &p.InMiss, &p.InHit, &p.InWrite,
		&p.Out, &p.ReasoningOut, &p.PerRequestFee, &peak, &offPeak, &p.PeakTZ,
		&validFrom, &validTo, &p.Note, &createdAt); err != nil {
		return nil, err
	}
	parsed, err := policy.ParseScopeKind(kind)
	if err != nil {
		return nil, fmt.Errorf("user_prices 里有非法 scope_kind: %w", err)
	}
	p.Scope = policy.ScopeRef{Kind: parsed, ID: p.Scope.ID}
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

func (p *ScopePrice) validate() error {
	if err := checkScope("分发价目行", p.Scope); err != nil {
		return err
	}
	if strings.TrimSpace(p.Model) == "" {
		return errors.New("model 不能为空")
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

// InsertScopePrice 插入一条按范围键定的分发价目行。
//
// 口径与 2.x 一致：整点生效、按时间只追加、插入时把同 (scope, model) 上仍然有效的旧行收口。
// 「只追加」的键从字符串 scope 换成了 (scope_kind, scope_id) —— 语义等价，
// 但组织级与项目级价目现在也各自成序列，不会再和某个用户的覆盖行互相收口。
func (s *Store) InsertScopePrice(p *ScopePrice) error {
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
	err = txQueryRow(tx, s.dialect, `SELECT COALESCE(MAX(valid_from),0) FROM user_prices
		WHERE scope_kind=? AND scope_id=? AND model=?`,
		string(p.Scope.Kind), p.Scope.ID, p.Model).Scan(&latest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if latest != 0 && p.ValidFrom.UnixMilli() <= latest {
		return fmt.Errorf("价目按时间只追加：%s / %s 已有 valid_from=%s，新行不得早于或等于它",
			p.Scope.Display(), p.Model, time.UnixMilli(latest).UTC().Format(time.RFC3339))
	}

	if _, err := txExec(tx, s.dialect, `UPDATE user_prices SET valid_to=?
		WHERE scope_kind=? AND scope_id=? AND model=? AND valid_to=0`,
		p.ValidFrom.UnixMilli(), string(p.Scope.Kind), p.Scope.ID, p.Model); err != nil {
		return err
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	id, err := insertID(tx, s.dialect, `INSERT INTO user_prices
		(scope_kind, scope_id, model, currency, in_miss, in_hit, in_write, out, reasoning_out,
		 per_request_fee, peak_hours, off_peak_ratio, peak_tz, valid_from, valid_to, note, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		string(p.Scope.Kind), p.Scope.ID, p.Model, p.Currency, p.InMiss, p.InHit, p.InWrite, p.Out,
		p.ReasoningOut, p.PerRequestFee, strings.Join(p.PeakHours, ","), p.OffPeakRatio, p.PeakTZ,
		p.ValidFrom.UnixMilli(), tsOf(p.ValidTo), p.Note, p.CreatedAt.UnixMilli())
	if err != nil {
		return err
	}
	p.ID = id
	return tx.Commit()
}

// ScopePriceAt 查某个时刻对该 (范围, 下游模型) 生效的分发价目行；没有则返回 nil。
//
// ORDER BY 带 `id DESC` 做确定性 tie-break，理由与 ProviderPriceAt 相同：
// 表上没有 UNIQUE 约束，没有 tie-break 时同一份库两次查询可能给出不同金额。
func (s *Store) ScopePriceAt(scope policy.ScopeRef, model string, t time.Time) (*ScopePrice, error) {
	if err := checkScope("ScopePriceAt", scope); err != nil {
		return nil, err
	}
	if strings.TrimSpace(model) == "" {
		return nil, errors.New("model 不能为空")
	}
	ts := t.UnixMilli()
	row := s.queryRow(`SELECT `+scopePriceCols+` FROM user_prices
		WHERE scope_kind=? AND scope_id=? AND model=? AND valid_from<=? AND (valid_to=0 OR valid_to>?)
		ORDER BY valid_from DESC, id DESC LIMIT 1`, string(scope.Kind), scope.ID, model, ts, ts)
	p, err := scanScopePrice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

// ScopePriceAtChain 按范围集合取分发价：命中集合里**最具体**的那个范围的价。
//
// 一个请求同时属于 user / project / organization，而 system 全局兜底永远在链条末端；
// specificity 次序固定为 user > project > organization > system（见 scopeOrder）。
// 「缺席即否」不适用于价格：一个范围都没命中就返回 nil，由调用方决定兜底报价 ——
// 把分发价当 0 会让配额形同虚设（见 charge.go 的 RowCharge 注释）。
func (s *Store) ScopePriceAtChain(chain policy.ScopeChain, model string, t time.Time) (*ScopePrice, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: ScopePriceAtChain 至少需要一个范围", ErrScopeRequired)
	}
	ordered := make([]policy.ScopeRef, 0, len(chain))
	for _, sc := range chain {
		if err := sc.Validate(); err != nil {
			return nil, fmt.Errorf("ScopePriceAtChain: %w", err)
		}
		ordered = append(ordered, sc)
	}
	sortBySpecificity(ordered)
	for _, sc := range ordered {
		p, err := s.ScopePriceAt(sc, model, t)
		if err != nil || p != nil {
			return p, err
		}
	}
	return nil, nil
}

// sortBySpecificity 按具体度原地排序（越具体越靠前），同档按 kind、ID 稳定排序，
// 这样排序结果与传入顺序无关 —— §2.8 要求不得依赖 map/切片原始顺序。
func sortBySpecificity(scopes []policy.ScopeRef) {
	for i := 1; i < len(scopes); i++ {
		for j := i; j > 0; j-- {
			a, b := scopes[j-1], scopes[j]
			sa, sb := scopeSpecificity(a), scopeSpecificity(b)
			if sa < sb || (sa == sb && a.Less(b)) {
				scopes[j-1], scopes[j] = scopes[j], scopes[j-1]
				continue
			}
			break
		}
	}
}

// ListScopePrices 列出某个 (范围, 模型) 的全部分发价目行（含历史），按 valid_from 升序。
func (s *Store) ListScopePrices(scope policy.ScopeRef, model string) ([]ScopePrice, error) {
	if err := checkScope("ListScopePrices", scope); err != nil {
		return nil, err
	}
	args := []any{string(scope.Kind), scope.ID}
	where := `WHERE scope_kind=? AND scope_id=?`
	if strings.TrimSpace(model) != "" {
		where += ` AND model=?`
		args = append(args, model)
	}
	return s.queryScopePrices(`SELECT `+scopePriceCols+` FROM user_prices `+where+` ORDER BY valid_from ASC`, args...)
}

// ListAllScopePrices 返回在 t 时刻生效的全部分发价目行（跨范围）；t 为零值表示不限。
// 管理台与 `price list` 用它展示「哪些范围被单独定过价」。
func (s *Store) ListAllScopePrices(t time.Time) ([]ScopePrice, error) {
	where := ""
	args := []any{}
	if !t.IsZero() {
		ts := t.UnixMilli()
		where = ` WHERE valid_from<=? AND (valid_to=0 OR valid_to>?)`
		args = append(args, ts, ts)
	}
	return s.queryScopePrices(`SELECT `+scopePriceCols+` FROM user_prices`+where+`
ORDER BY scope_kind, scope_id, model, valid_from`, args...)
}

// HasEffectiveScopePrices 报告这些范围里是否存在当前生效的分发价目行（任一命中即为真）。
func (s *Store) HasEffectiveScopePrices(t time.Time, scopes ...policy.ScopeRef) (bool, error) {
	pairs := make([]string, 0, len(scopes))
	args := []any{}
	for _, sc := range scopes {
		if err := checkScope("HasEffectiveScopePrices", sc); err != nil {
			return false, err
		}
		pairs = append(pairs, "(scope_kind=? AND scope_id=?)")
		args = append(args, string(sc.Kind), sc.ID)
	}
	if len(pairs) == 0 {
		return false, nil
	}
	ts := t.UnixMilli()
	q := `SELECT 1 FROM user_prices WHERE (` + strings.Join(pairs, " OR ") + `)
		AND valid_from<=? AND (valid_to=0 OR valid_to>?) LIMIT 1`
	var found int
	err := s.queryRow(q, append(args, ts, ts)...).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) queryScopePrices(q string, args ...any) ([]ScopePrice, error) {
	rows, err := s.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []ScopePrice{}
	for rows.Next() {
		p, err := scanScopePrice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// ------------------------------------------------------------------ 配额

const scopeQuotaCols = `scope_kind, scope_id, quota_month_tokens, quota_month_cost,
	rpm, max_concurrent, enabled, created_at, updated_at`

func scanScopeQuota(row interface{ Scan(...any) error }) (ScopeQuota, error) {
	var q ScopeQuota
	var kind string
	var enabled, created, updated int64
	if err := row.Scan(&kind, &q.Scope.ID, &q.QuotaMonthTokens, &q.QuotaMonthCost,
		&q.RPM, &q.MaxConcurrent, &enabled, &created, &updated); err != nil {
		return q, err
	}
	parsed, err := policy.ParseScopeKind(kind)
	if err != nil {
		return q, fmt.Errorf("scope_quota 里有非法 scope_kind: %w", err)
	}
	q.Scope = policy.ScopeRef{Kind: parsed, ID: q.Scope.ID}
	q.Enabled = enabled != 0
	q.CreatedAt = time.UnixMilli(created)
	q.UpdatedAt = time.UnixMilli(updated)
	return q, nil
}

// upsertScopeQuotaTx 在事务里按范围写入配额（0 = 不限，enabled 由调用方给）。
//
// 单独成函数是因为有两个写侧要用同一份 SQL：SetScopeQuota（唯一的配额写入口）与
// CreateUser（建号同一事务里补的那一行）。两处各写一遍就会有一处漏列。
func upsertScopeQuotaTx(tx *sql.Tx, d Dialect, q ScopeQuota) error {
	if err := checkScope("写入 scope_quota", q.Scope); err != nil {
		return err
	}
	if q.QuotaMonthTokens < 0 || q.QuotaMonthCost < 0 || q.RPM < 0 || q.MaxConcurrent < 0 {
		return fmt.Errorf("配额与限流不能为负（0 表示不限）: tokens=%d cost=%v rpm=%d concurrent=%d",
			q.QuotaMonthTokens, q.QuotaMonthCost, q.RPM, q.MaxConcurrent)
	}
	now := time.Now().UnixMilli()
	if _, err := txExec(tx, d, `
INSERT INTO scope_quota (
  scope_kind, scope_id, quota_month_tokens, quota_month_cost, rpm, max_concurrent,
  enabled, created_at, updated_at
) VALUES (?,?,?,?,?,?,?,?,?)
ON CONFLICT(scope_kind, scope_id) DO UPDATE SET
  quota_month_tokens = excluded.quota_month_tokens,
  quota_month_cost   = excluded.quota_month_cost,
  rpm                = excluded.rpm,
  max_concurrent     = excluded.max_concurrent,
  enabled            = excluded.enabled,
  updated_at         = excluded.updated_at`,
		string(q.Scope.Kind), q.Scope.ID, q.QuotaMonthTokens, q.QuotaMonthCost, q.RPM, q.MaxConcurrent,
		boolToInt(q.Enabled), now, now); err != nil {
		return fmt.Errorf("写入 scope_quota 失败: %w", err)
	}
	return nil
}

// SetScopeQuota 写入某个范围的配额与限流（按范围 upsert）。0 = 不限。
//
// 修订号照旧 +1：服务端靠轮询它发现「CLI 在另一个进程里改了配置」。
func (s *Store) SetScopeQuota(q ScopeQuota) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := upsertScopeQuotaTx(tx, s.dialect, q); err != nil {
		return err
	}
	if err := bumpRevision(tx, s.dialect); err != nil {
		return err
	}
	return tx.Commit()
}

// GetScopeQuota 查某个范围的配额；没有行返回 (nil, nil)。
//
// 「没行」与「限额为 0」是两件事，调用方必须区分：0 是管理员显式给的「不限」，
// 而 nil 是这一行的配额从来没被配置过（org / project 范围尤其常见）。把 nil 当 0，
// 等于让「未配置」在报表里显示成「额度为零」，反过来也一样糟。
//
// §2.7 规则 2/8：users 表的配额列不再是读路径 —— 一次性迁移会把它们回填进这张表，
// 收口校验查的正是「每个 user 范围都有一行」。这里刻意**不留**回读 users 的兜底：
// 兜底意味着两张表可以各持一半真值而没人报错，而配额决定的是「还花不花得起钱」。
func (s *Store) GetScopeQuota(scope policy.ScopeRef) (*ScopeQuota, error) {
	if err := checkScope("GetScopeQuota", scope); err != nil {
		return nil, err
	}
	q, err := scanScopeQuota(s.queryRow(`SELECT `+scopeQuotaCols+` FROM scope_quota
		WHERE scope_kind=? AND scope_id=?`, scopeArgs(scope)...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &q, nil
}

// QuotaPatch 是「只改给到的那几项」的配额补丁：nil = 保持原值，0 = 不限。
type QuotaPatch struct {
	Tokens        *int64
	Cost          *float64
	RPM           *int
	MaxConcurrent *int
	Enabled       *bool
}

// PatchScopeQuota 读-改-写一个范围的配额与限流。
//
// 单独一个方法而不是让调用方自己 Get + Set：三个写侧（管理界面 PATCH、CLI 改配额、
// CLI 改限流）都会各写一遍「缺行时从哪起步」，漏掉任何一遍都会把「这次没改的那一项」
// 写成 0 = 不限 —— 管理员点一下改 token 上限，顺手清了同一个人的金额上限。
//
// 缺行按「全 0 = 不限、启用」起步：org / project 范围第一次设限走的就是这条路径，
// 而 user 范围的行在一次性迁移与 CreateUser 里都会有，缺行属于异常，
// 这里按「未配置」处理而不是报错，是为了让新范围的第一次配置不必先插空行。
func (s *Store) PatchScopeQuota(scope policy.ScopeRef, p QuotaPatch) error {
	if err := checkScope("PatchScopeQuota", scope); err != nil {
		return err
	}
	cur, err := s.GetScopeQuota(scope)
	if err != nil {
		return err
	}
	if cur == nil {
		cur = &ScopeQuota{Scope: scope, Enabled: true}
	}
	if p.Tokens != nil {
		cur.QuotaMonthTokens = *p.Tokens
	}
	if p.Cost != nil {
		cur.QuotaMonthCost = *p.Cost
	}
	if p.RPM != nil {
		cur.RPM = *p.RPM
	}
	if p.MaxConcurrent != nil {
		cur.MaxConcurrent = *p.MaxConcurrent
	}
	if p.Enabled != nil {
		cur.Enabled = *p.Enabled
	}
	if cur.QuotaMonthTokens < 0 || cur.QuotaMonthCost < 0 || cur.RPM < 0 || cur.MaxConcurrent < 0 {
		return fmt.Errorf("配额与限流不能为负（0 表示不限）: tokens=%d cost=%v rpm=%d concurrent=%d",
			cur.QuotaMonthTokens, cur.QuotaMonthCost, cur.RPM, cur.MaxConcurrent)
	}
	cur.Scope = scope
	return s.SetScopeQuota(*cur)
}

// ListScopeQuotas 按（类型, ID）稳定顺序返回全部范围配额。
func (s *Store) ListScopeQuotas() ([]ScopeQuota, error) {
	rows, err := s.query(`SELECT ` + scopeQuotaCols + ` FROM scope_quota ORDER BY scope_kind, scope_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScopeQuota{}
	for rows.Next() {
		q, err := scanScopeQuota(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// DeleteScopeQuota 删掉某个范围的配额行（删用户时级联用）。
func (s *Store) DeleteScopeQuota(scope policy.ScopeRef) (bool, error) {
	if err := checkScope("DeleteScopeQuota", scope); err != nil {
		return false, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := txExec(tx, s.dialect, `DELETE FROM scope_quota WHERE scope_kind=? AND scope_id=?`, scopeArgs(scope)...)
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

// ------------------------------------------------------------------ 按范围的用量聚合

// ScopeUsageRow 是一行按范围键定的日聚合。复用 UsageRow 的度量字段，避免跨包复制结构体。
type ScopeUsageRow struct {
	UsageRow
	Scope policy.ScopeRef `json:"scope"`
}

// upsertScopeUsage 把一次请求计入 usage_scope_daily。
//
// 与 usage_user_daily 的关系是**叠加维度**而不是改写：老表的行含义一字未动（§2.7 规则 5），
// 新表按请求所属的叶子范围计数。组织/项目层的合计由调用方把成员范围传进来（层级归属在 B）。
func (s *Store) upsertScopeUsage(tx *sql.Tx, scope policy.ScopeRef, day, provider, model, upstream string,
	systemPaid, okInc, failedInc bool, tokens usageTokens) error {

	sp := 0
	if systemPaid {
		sp = 1
	}
	okV, failV := 0, 1
	if okInc {
		okV, failV = 1, 0
	}
	chargeVal, chargeFrozen := 0.0, 0
	if tokens.charge != nil {
		chargeVal, chargeFrozen = *tokens.charge, 1
	}
	_, err := txExec(tx, s.dialect, `
INSERT INTO usage_scope_daily (
  day, scope_kind, scope_id, provider, model, upstream_model, system_paid,
  requests, ok, failed,
  prompt_tokens, cache_hit_tokens, cache_miss_tokens, completion_tokens, total_tokens, latency_sum_ms,
  charge, frozen_charges
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(day, scope_kind, scope_id, provider, model, upstream_model, system_paid) DO UPDATE SET
  requests          = usage_scope_daily.requests + excluded.requests,
  ok                = usage_scope_daily.ok + excluded.ok,
  failed            = usage_scope_daily.failed + excluded.failed,
  prompt_tokens     = usage_scope_daily.prompt_tokens + excluded.prompt_tokens,
  cache_hit_tokens  = usage_scope_daily.cache_hit_tokens + excluded.cache_hit_tokens,
  cache_miss_tokens = usage_scope_daily.cache_miss_tokens + excluded.cache_miss_tokens,
  completion_tokens = usage_scope_daily.completion_tokens + excluded.completion_tokens,
  total_tokens      = usage_scope_daily.total_tokens + excluded.total_tokens,
  latency_sum_ms    = usage_scope_daily.latency_sum_ms + excluded.latency_sum_ms,
  charge            = usage_scope_daily.charge + excluded.charge,
  frozen_charges    = usage_scope_daily.frozen_charges + excluded.frozen_charges`,
		day, string(scope.Kind), scope.ID, provider, model, upstream, sp,
		1, okV, failV,
		tokens.prompt, tokens.cacheHit, tokens.cacheMiss, tokens.completion, tokens.total, tokens.latencyMs,
		chargeVal, chargeFrozen,
	)
	if err != nil {
		return fmt.Errorf("写入 usage_scope_daily 失败: %w", err)
	}
	return nil
}

// usageTokens 是一次请求的计数入参（单独成结构，避免 upsertScopeUsage 拖十个位置参数）。
type usageTokens struct {
	prompt     int64
	cacheHit   int64
	cacheMiss  int64
	completion int64
	total      int64
	latencyMs  int64
	charge     *float64
}

const scopeUsageSelectTail = `,
       SUM(requests), SUM(ok), SUM(failed),
       SUM(prompt_tokens), SUM(completion_tokens), SUM(total_tokens),
       CASE WHEN SUM(requests)>0 THEN CAST(SUM(latency_sum_ms) AS REAL)/SUM(requests) ELSE 0 END,
       SUM(cache_hit_tokens), SUM(cache_miss_tokens),
       COALESCE(SUM(charge),0), COALESCE(SUM(frozen_charges),0)`

// scopeUsageSelectCols 带范围两列（GROUP BY 必须一起带上，PG/MySQL 的 ONLY_FULL_GROUP_BY 会拒裸列）。
const scopeUsageSelectCols = `day, scope_kind, scope_id, provider, model, upstream_model, system_paid` + scopeUsageSelectTail

// aggregatedUsageCols 是跨范围汇总用的同一份列，去掉范围两列。
const aggregatedUsageCols = `day, provider, model, upstream_model, system_paid` + scopeUsageSelectTail

// UsageByScope 返回某个范围的按日、按上游、按模型用量。since/until 为零值表示不限。
func (s *Store) UsageByScope(scope policy.ScopeRef, since, until time.Time) ([]ScopeUsageRow, error) {
	if err := checkScope("UsageByScope", scope); err != nil {
		return nil, err
	}
	where, args := scopeDayFilter([]policy.ScopeRef{scope}, since, until)
	return s.queryScopeUsage(`SELECT `+scopeUsageSelectCols+` FROM usage_scope_daily `+where+`
GROUP BY day, scope_kind, scope_id, provider, model, upstream_model, system_paid
ORDER BY day DESC, scope_kind, scope_id, provider, model
LIMIT 2000`, args...)
}

// AggregateScopeUsage 把多个成员范围的用量**向上汇总**成一份按日明细（§2.7 规则 5）。
//
// 为什么要调用方传成员集合：范围之间的父子归属归身份层（B）展开，本包不猜层级 ——
// 猜出来的汇总会把跨组织的消耗并到一张账单上。传空集合直接报错，不返回「全部」。
//
// 返回的是不带范围的行：跨范围合并后「这一行属于哪个范围」不再成立，
// 硬塞一个范围进结果只会让人以为可以按它再查一次。
func (s *Store) AggregateScopeUsage(scopes []policy.ScopeRef, since, until time.Time) ([]UsageRow, error) {
	if len(scopes) == 0 {
		return nil, fmt.Errorf("%w: AggregateScopeUsage 至少需要一个范围", ErrScopeRequired)
	}
	for _, sc := range scopes {
		if err := sc.Validate(); err != nil {
			return nil, fmt.Errorf("AggregateScopeUsage: %w", err)
		}
	}
	where, args := scopeDayFilter(scopes, since, until)
	rows, err := s.query(`SELECT `+aggregatedUsageCols+` FROM usage_scope_daily `+where+`
GROUP BY day, provider, model, upstream_model, system_paid
ORDER BY day DESC, provider, model
LIMIT 2000`, args...)
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
			&r.CacheHitTokens, &r.CacheMissTokens, &r.Charge, &r.FrozenCharges); err != nil {
			return nil, err
		}
		r.SystemPaid = systemPaid != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// ScopeUsageTotals 汇总多个范围的累计计数（配额判断的 token 侧）。
func (s *Store) ScopeUsageTotals(scopes []policy.ScopeRef, since, until time.Time) (UserTotals, error) {
	var out UserTotals
	if len(scopes) == 0 {
		return out, fmt.Errorf("%w: ScopeUsageTotals 至少需要一个范围", ErrScopeRequired)
	}
	for _, sc := range scopes {
		if err := sc.Validate(); err != nil {
			return out, fmt.Errorf("ScopeUsageTotals: %w", err)
		}
	}
	where, args := scopeDayFilter(scopes, since, until)
	var first, last sql.NullString
	err := s.queryRow(`
SELECT COALESCE(SUM(requests),0), COALESCE(SUM(ok),0), COALESCE(SUM(failed),0),
       COALESCE(SUM(total_tokens),0), COALESCE(SUM(prompt_tokens),0), COALESCE(SUM(completion_tokens),0),
       COALESCE(SUM(cache_hit_tokens),0), COALESCE(SUM(cache_miss_tokens),0),
       MIN(day), MAX(day)
FROM usage_scope_daily `+where, args...).Scan(
		&out.Requests, &out.OK, &out.Failed, &out.TotalTokens,
		&out.PromptTokens, &out.OutputTokens,
		&out.CacheHitTokens, &out.CacheMissTokens, &first, &last)
	out.FirstDay, out.LastDay = first.String, last.String
	return out, err
}

// ScopeSystemUsage 汇总某个范围由系统上游承接的用量（配额计 token 的口径）。
func (s *Store) ScopeSystemUsage(scope policy.ScopeRef, since time.Time) (SystemUsage, error) {
	var out SystemUsage
	if err := checkScope("ScopeSystemUsage", scope); err != nil {
		return out, err
	}
	err := s.queryRow(`
SELECT COALESCE(SUM(requests),0), COALESCE(SUM(ok),0), COALESCE(SUM(failed),0),
       COALESCE(SUM(prompt_tokens),0), COALESCE(SUM(cache_hit_tokens),0),
       COALESCE(SUM(cache_miss_tokens),0), COALESCE(SUM(completion_tokens),0),
       COALESCE(SUM(total_tokens),0)
FROM usage_scope_daily
WHERE scope_kind=? AND scope_id=? AND system_paid=1 AND day >= ?`,
		append(scopeArgs(scope), since.Format("2006-01-02"))...).Scan(
		&out.Requests, &out.OK, &out.Failed,
		&out.PromptTokens, &out.CacheHitTokens, &out.CacheMissTokens,
		&out.CompletionTokens, &out.TotalTokens)
	return out, err
}

// ScopeChargeTotal 按 RowCharge 口径（冻结优先 + 估算兜底）合计金额，给配额判断用。
//
// 口径与 2.x 完全一致（见 charge.go），只是聚合键从 user_name 换成了 (scope_kind, scope_id)。
// 逐行算完再相加，不做「先合计再乘系数」—— 摊分比例按行不同，合并后再算会算错。
func (s *Store) ScopeChargeTotal(scope policy.ScopeRef, since, until time.Time, cost CostFunc) (float64, error) {
	rows, err := s.UsageByScope(scope, since, until)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	total := 0.0
	for _, r := range rows {
		total += RowCharge(r.UsageRow, cost, now)
	}
	return total, nil
}

// ScopeUsageExportRows 按（日, 范围, 上游, 模型）导出用量，时间升序、不截断（出账用）。
func (s *Store) ScopeUsageExportRows(scope policy.ScopeRef, since, until time.Time) ([]ScopeUsageRow, error) {
	if err := checkScope("ScopeUsageExportRows", scope); err != nil {
		return nil, err
	}
	where, args := scopeDayFilter([]policy.ScopeRef{scope}, since, until)
	return s.queryScopeUsage(`SELECT `+scopeUsageSelectCols+` FROM usage_scope_daily `+where+`
GROUP BY day, scope_kind, scope_id, provider, model, upstream_model, system_paid
ORDER BY day, provider, model`, args...)
}

// scopeDayFilter 生成 (scope 命中任一) AND day 区间的 WHERE 片段。
// 范围之间用 OR 串联而不是拼 IN：(kind,id) 是复合键，拼成字符串 IN 列表正是 §2.7 规则 1 禁止的形式。
func scopeDayFilter(scopes []policy.ScopeRef, since, until time.Time) (string, []any) {
	pairs := make([]string, 0, len(scopes))
	args := make([]any, 0, len(scopes)*2+2)
	for _, sc := range scopes {
		pairs = append(pairs, "(scope_kind=? AND scope_id=?)")
		args = append(args, string(sc.Kind), sc.ID)
	}
	where := "WHERE (" + strings.Join(pairs, " OR ") + ")"
	if !since.IsZero() {
		where += " AND day >= ?"
		args = append(args, since.Format("2006-01-02"))
	}
	if !until.IsZero() {
		where += " AND day <= ?"
		args = append(args, until.Format("2006-01-02"))
	}
	return where, args
}

func (s *Store) queryScopeUsage(q string, args ...any) ([]ScopeUsageRow, error) {
	rows, err := s.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ScopeUsageRow{}
	for rows.Next() {
		var r ScopeUsageRow
		var kind string
		var systemPaid int64
		if err := rows.Scan(&r.Day, &kind, &r.Scope.ID, &r.Provider, &r.Model, &r.UpstreamModel, &systemPaid,
			&r.Requests, &r.OK, &r.Failed,
			&r.PromptTokens, &r.CompletionTokens, &r.TotalTokens, &r.AvgLatencyMs,
			&r.CacheHitTokens, &r.CacheMissTokens, &r.Charge, &r.FrozenCharges); err != nil {
			return nil, err
		}
		parsed, err := policy.ParseScopeKind(kind)
		if err != nil {
			return nil, fmt.Errorf("usage_scope_daily 里有非法 scope_kind: %w", err)
		}
		r.Scope = policy.ScopeRef{Kind: parsed, ID: r.Scope.ID}
		r.SystemPaid = systemPaid != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// ------------------------------------------------------------------ 审计

// AuditScope 记一条带范围的审计。
//
// 管理员的全局操作传 policy.SystemScope；组织/项目内的操作必须传对应范围，
// 这样 3.0 的审计才可按范围导出（§2.7 规则 2）。action 为空仍然静默忽略（沿用旧行为）。
func (s *Store) AuditScope(scope policy.ScopeRef, actor, action, target, detail string) error {
	if action == "" {
		return nil
	}
	if err := checkScope("AuditScope", scope); err != nil {
		return err
	}
	_, err := s.exec(`INSERT INTO audit_log (ts, scope_kind, scope_id, actor, action, target, detail)
		VALUES (?,?,?,?,?,?,?)`,
		time.Now().UnixMilli(), string(scope.Kind), scope.ID, actor, action, target, detail)
	return err
}

const auditScopedCols = `ts, scope_kind, scope_id, actor, action, target, detail`

// AuditRecentByScope 返回某个范围最近的 n 条审计（新的在前）。
func (s *Store) AuditRecentByScope(scope policy.ScopeRef, n int) ([]ScopedAuditEntry, error) {
	if err := checkScope("AuditRecentByScope", scope); err != nil {
		return nil, err
	}
	return s.queryScopedAudit(`SELECT `+auditScopedCols+` FROM audit_log
		WHERE scope_kind=? AND scope_id=? ORDER BY id DESC LIMIT ?`, append(scopeArgs(scope), auditLimit(n))...)
}

// AuditRecentForScopes 返回这些范围合在一起的最近 n 条审计（按时间倒序，新的在前）。
// 组织管理员看的是「本组织 + 本组织下各项目」的并集，所以入参是集合而不是单个范围。
func (s *Store) AuditRecentForScopes(scopes []policy.ScopeRef, n int) ([]ScopedAuditEntry, error) {
	if len(scopes) == 0 {
		return nil, fmt.Errorf("%w: AuditRecentForScopes 至少需要一个范围", ErrScopeRequired)
	}
	pairs := make([]string, 0, len(scopes))
	args := make([]any, 0, len(scopes)*2+1)
	for _, sc := range scopes {
		if err := sc.Validate(); err != nil {
			return nil, fmt.Errorf("AuditRecentForScopes: %w", err)
		}
		pairs = append(pairs, "(scope_kind=? AND scope_id=?)")
		args = append(args, string(sc.Kind), sc.ID)
	}
	args = append(args, auditLimit(n))
	return s.queryScopedAudit(`SELECT `+auditScopedCols+` FROM audit_log WHERE (`+
		strings.Join(pairs, " OR ")+`) ORDER BY id DESC LIMIT ?`, args...)
}

func auditLimit(n int) int {
	if n <= 0 {
		return 100
	}
	return n
}

func (s *Store) queryScopedAudit(q string, args ...any) ([]ScopedAuditEntry, error) {
	rows, err := s.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScopedAuditEntry{}
	for rows.Next() {
		var e ScopedAuditEntry
		var ts int64
		var kind string
		if err := rows.Scan(&ts, &kind, &e.Scope.ID, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		e.Ts = time.UnixMilli(ts)
		parsed, err := policy.ParseScopeKind(kind)
		if err != nil {
			return nil, fmt.Errorf("audit_log 里有非法 scope_kind: %w", err)
		}
		e.Scope = policy.ScopeRef{Kind: parsed, ID: e.Scope.ID}
		out = append(out, e)
	}
	return out, rows.Err()
}

// boolToInt 把布尔落成 0/1 列。
func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// ------------------------------------------------------------------ 请求归属与路由痕迹

// resolveRequestScope 定出一条请求的归属范围（集中一处，别处不再解析裸串）。
//
// 优先用调用方显式给的 Scope（3.0 路径）；只给了旧的 UserName 时按 §2.7 规则 3 落到
// (user, <用户名>)。两者都没有 = 静态 key，没有归属，不猜。
//
// UserName 那一段：§2.7 规则 8 —— 主线接线完成后删除（届时调用方一律传 Scope）。
func resolveRequestScope(rec RequestRecord) (policy.ScopeRef, bool) {
	if hasScope(rec.Scope) && rec.Scope.Validate() == nil {
		return rec.Scope, true
	}
	if ref, err := legacyUserScope(rec.UserName); err == nil {
		return ref, true
	}
	return policy.ScopeRef{}, false
}

// RoutingTraceForRequest 按 request_id 取回一次在线请求的路由痕迹（§2.8 的在线记录）。
// 找不到返回 (nil, nil)。
func (s *Store) RoutingTraceForRequest(requestID string) (*RoutingTrace, error) {
	if strings.TrimSpace(requestID) == "" {
		return nil, errors.New("request_id 不能为空")
	}
	var (
		kind, seed, epoch, digest, version sql.NullString
		scopeID                            sql.NullString
	)
	err := s.queryRow(`SELECT request_id, scope_kind, scope_id, policy_version, routing_epoch,
		routing_seed, candidates_digest
		FROM requests WHERE request_id=? ORDER BY id DESC LIMIT 1`, requestID).
		Scan(&requestID, &kind, &scopeID, &version, &epoch, &seed, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	trace := &RoutingTrace{
		RequestID:        requestID,
		PolicyVersion:    version.String,
		RoutingEpoch:     epoch.String,
		RoutingSeed:      seed.String,
		CandidatesDigest: digest.String,
	}
	if isScopeParam(kind.String, scopeID.String) {
		parsed, err := policy.ParseScopeKind(kind.String)
		if err != nil {
			return nil, fmt.Errorf("requests 里有非法 scope_kind: %w", err)
		}
		trace.Scope = policy.ScopeRef{Kind: parsed, ID: scopeID.String}
	}
	return trace, nil
}
