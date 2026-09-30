package server

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// adminUsageExport：GET /v1/_admin/usage/export?user=&since=&until=&monthly=1
//
// 输出 CSV（text/csv），给管理台下载或脚本拉账。金额口径与配额一致
// （store.RowCharge 冻结优先），所以导出的数能和 /usage、status 对上。
func (s *Server) adminUsageExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET")
		return
	}
	q := r.URL.Query()
	user := strings.TrimSpace(q.Get("user"))
	since, err := parseExportDay(q.Get("since"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "since: "+err.Error())
		return
	}
	until, err := parseExportDay(q.Get("until"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "until: "+err.Error())
		return
	}
	monthly := q.Get("monthly") == "1" || q.Get("monthly") == "true"

	name := "usage"
	if user != "" {
		name += "-" + user
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if monthly {
		rows, err := s.db.MonthlyRollup(since, until, user)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		if err := cw.Write([]string{
			"month", "user_name", "requests", "ok", "failed",
			"total_tokens", "charge", "frozen_charges",
		}); err != nil {
			return
		}
		for _, r := range rows {
			_ = cw.Write([]string{
				r.Month, r.UserName,
				fmt.Sprint(r.Requests), fmt.Sprint(r.OK), fmt.Sprint(r.Failed), fmt.Sprint(r.Tokens),
				fmt.Sprintf("%.6f", r.Charge), fmt.Sprint(r.Frozen),
			})
		}
		return
	}

	rows, err := s.db.UsageExportRows(store.UsageExportFilter{
		UserName: user, Since: since, Until: until,
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	pricing := s.cfgStore.Current().Pricing
	now := time.Now()
	if err := cw.Write([]string{
		"day", "user_name", "provider", "model", "upstream_model", "system_paid",
		"requests", "ok", "failed",
		"prompt_tokens", "completion_tokens", "total_tokens",
		"cache_hit_tokens", "cache_miss_tokens",
		"charge_frozen", "frozen_charges", "amount", "currency",
	}); err != nil {
		return
	}
	for _, r := range rows {
		amount := rowCharge(r.UsageRow, &pricing, now)
		_ = cw.Write([]string{
			r.Day, r.UserName, r.Provider, r.Model, r.UpstreamModel,
			map[bool]string{true: "1", false: "0"}[r.SystemPaid],
			fmt.Sprint(r.Requests), fmt.Sprint(r.OK), fmt.Sprint(r.Failed),
			fmt.Sprint(r.PromptTokens), fmt.Sprint(r.CompletionTokens), fmt.Sprint(r.TotalTokens),
			fmt.Sprint(r.CacheHitTokens), fmt.Sprint(r.CacheMissTokens),
			fmt.Sprintf("%.6f", r.Charge), fmt.Sprint(r.FrozenCharges),
			fmt.Sprintf("%.6f", amount), pricing.Currency,
		})
	}
}

func parseExportDay(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	return time.ParseInLocation("2006-01-02", s, time.Local)
}
