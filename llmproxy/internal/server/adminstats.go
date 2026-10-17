package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// adminStats 是统计看板的聚合读数（GET /v1/_admin/stats?days=N，缺省 7 天）。
//
// 只出聚合不出明细：明细行数无上界，看板要的是趋势与分组对比；逐条明细在
// usage/export 与 /v1/_admin/users/{name}/usage 里。三个视角（按日 / 按模型 /
// 按范围）都从 usage_scope_daily 现场聚合（§2.7 读侧口径），不拉明细回来自己加。
func (s *Server) adminStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET")
		return
	}
	days := 7
	if q := r.URL.Query().Get("days"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 || n > 365 {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "days 需要是 1~365 的整数")
			return
		}
		days = n
	}
	// 含今天的自然日窗口：since = 今天往前 days-1 天的零点。
	since := time.Now().AddDate(0, 0, -(days - 1))
	stats, err := s.db.ScopeUsageStats(since, time.Time{})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	var totals store.UsageRow
	for _, r := range stats.ByDay {
		totals.Requests += r.Requests
		totals.OK += r.OK
		totals.Failed += r.Failed
		totals.PromptTokens += r.PromptTokens
		totals.CompletionTokens += r.CompletionTokens
		totals.TotalTokens += r.TotalTokens
		totals.CacheHitTokens += r.CacheHitTokens
		totals.CacheMissTokens += r.CacheMissTokens
		totals.Charge += r.Charge
		totals.FrozenCharges += r.FrozenCharges
	}

	byDay := make([]map[string]any, 0, len(stats.ByDay))
	for _, r := range stats.ByDay {
		byDay = append(byDay, map[string]any{
			"day":               r.Day,
			"requests":          r.Requests,
			"ok":                r.OK,
			"failed":            r.Failed,
			"prompt_tokens":     r.PromptTokens,
			"completion_tokens": r.CompletionTokens,
			"total_tokens":      r.TotalTokens,
			"charge":            r.Charge,
		})
	}
	byModel := make([]map[string]any, 0, len(stats.ByModel))
	for _, r := range stats.ByModel {
		byModel = append(byModel, map[string]any{
			"provider":       r.Provider,
			"model":          r.Model,
			"requests":       r.Requests,
			"ok":             r.OK,
			"failed":         r.Failed,
			"total_tokens":   r.TotalTokens,
			"charge":         r.Charge,
			"avg_latency_ms": r.AvgLatencyMs,
		})
	}
	byScope := make([]map[string]any, 0, len(stats.ByScope))
	for _, sr := range stats.ByScope {
		byScope = append(byScope, map[string]any{
			"scope": map[string]string{
				"kind": string(sr.Scope.Kind),
				"id":   sr.Scope.ID,
			},
			"requests":     sr.Requests,
			"ok":           sr.OK,
			"failed":       sr.Failed,
			"total_tokens": sr.TotalTokens,
			"charge":       sr.Charge,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"days": days,
		"totals": map[string]any{
			"requests":     totals.Requests,
			"ok":           totals.OK,
			"failed":       totals.Failed,
			"total_tokens": totals.TotalTokens,
			"charge":       totals.Charge,
		},
		"by_day":   byDay,
		"by_model": byModel,
		"by_scope": byScope,
	})
}
