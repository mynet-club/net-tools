package store

import (
	"time"
)

// UsageExportFilter 圈定一次导出的范围。UserName 为空 = 全部用户。
type UsageExportFilter struct {
	UserName string
	Since    time.Time // 零值 = 不限
	Until    time.Time // 零值 = 不限
	Limit    int       // 0 = 不限（导出默认不截断，报表接口才有 500 上限）
}

// UsageExportRow 是导出/对账用的一行：用量 + 金额（冻结优先的合计）。
// 金额由调用方用 RowCharge 算好填入，保证 CLI / API / 导出同一口径。
type UsageExportRow struct {
	UsageRow
	// UserName 所属用户；静态 key 的请求此字段为空。
	UserName string
	// Amount 是「冻结优先 + 估算兜底」的合计（配额与账单口径，不是报表分段口径）。
	Amount float64
}

// UsageExportRows 按日、用户、上游、模型导出用量。
// 与 UsageByUser 的区别：不限单用户、不截断 500 行、按时间升序（适合出账）。
func (s *Store) UsageExportRows(f UsageExportFilter) ([]UsageExportRow, error) {
	where := "WHERE 1=1"
	args := []any{}
	if f.UserName != "" {
		where += " AND user_name = ?"
		args = append(args, f.UserName)
	}
	if !f.Since.IsZero() {
		where += " AND day >= ?"
		args = append(args, f.Since.Format("2006-01-02"))
	}
	if !f.Until.IsZero() {
		where += " AND day <= ?"
		args = append(args, f.Until.Format("2006-01-02"))
	}
	q := `
SELECT day, user_name, provider, model, upstream_model, system_paid,
       SUM(requests), SUM(ok), SUM(failed),
       SUM(prompt_tokens), SUM(completion_tokens), SUM(total_tokens),
       CASE WHEN SUM(requests)>0 THEN CAST(SUM(latency_sum_ms) AS REAL)/SUM(requests) ELSE 0 END,
       SUM(cache_hit_tokens), SUM(cache_miss_tokens),
       COALESCE(SUM(charge),0), COALESCE(SUM(frozen_charges),0)
FROM usage_user_daily ` + where + `
GROUP BY day, user_name, provider, model, upstream_model, system_paid
ORDER BY day, user_name, model, provider`
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
	}
	rows, err := s.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []UsageExportRow{}
	for rows.Next() {
		var e UsageExportRow
		var systemPaid int64
		if err := rows.Scan(&e.Day, &e.UserName, &e.Provider, &e.Model, &e.UpstreamModel, &systemPaid,
			&e.Requests, &e.OK, &e.Failed,
			&e.PromptTokens, &e.CompletionTokens, &e.TotalTokens, &e.AvgLatencyMs,
			&e.CacheHitTokens, &e.CacheMissTokens, &e.Charge, &e.FrozenCharges); err != nil {
			return nil, err
		}
		e.SystemPaid = systemPaid != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

// MonthlyRollupRow 是月合计一行（对账/账单用）。
type MonthlyRollupRow struct {
	Month    string  `json:"month"` // YYYY-MM
	UserName string  `json:"user_name"`
	Requests int64   `json:"requests"`
	OK       int64   `json:"ok"`
	Failed   int64   `json:"failed"`
	Tokens   int64   `json:"total_tokens"`
	Charge   float64 `json:"charge"` // 冻结合计
	Frozen   int64   `json:"frozen_charges"`
}

// MonthlyRollup 按「月 × 用户」合计系统付费消耗（账单口径）。
// day 存的是 YYYY-MM-DD，取前 7 位即自然月；跨时区的「自然月」由调用方用 MonthStart 切好区间。
func (s *Store) MonthlyRollup(since, until time.Time, userName string) ([]MonthlyRollupRow, error) {
	where := "WHERE system_paid = 1"
	args := []any{}
	if userName != "" {
		where += " AND user_name = ?"
		args = append(args, userName)
	}
	if !since.IsZero() {
		where += " AND day >= ?"
		args = append(args, since.Format("2006-01-02"))
	}
	if !until.IsZero() {
		where += " AND day <= ?"
		args = append(args, until.Format("2006-01-02"))
	}
	rows, err := s.query(`
SELECT substr(day, 1, 7) AS month, user_name,
       SUM(requests), SUM(ok), SUM(failed), SUM(total_tokens),
       COALESCE(SUM(charge),0), COALESCE(SUM(frozen_charges),0)
FROM usage_user_daily `+where+`
GROUP BY month, user_name
ORDER BY month, user_name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []MonthlyRollupRow{}
	for rows.Next() {
		var r MonthlyRollupRow
		if err := rows.Scan(&r.Month, &r.UserName,
			&r.Requests, &r.OK, &r.Failed, &r.Tokens,
			&r.Charge, &r.Frozen); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
