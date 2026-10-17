package server

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// TestAdminStats 聚合读数：三个视角各自 SUM、窗口过滤生效、只出聚合不出明细。
func TestAdminStats(t *testing.T) {
	h := newMUHarness(t)

	today := time.Now().Format("2006-01-02")
	old := time.Now().AddDate(0, 0, -30).Format("2006-01-02")
	ins := func(day, kind, id, prov, model string, reqs, toks int64, charge float64) {
		t.Helper()
		_, err := h.db.DB().Exec(`
INSERT INTO usage_scope_daily
  (day, scope_kind, scope_id, provider, model, upstream_model, system_paid,
   requests, ok, failed, prompt_tokens, cache_hit_tokens, cache_miss_tokens,
   completion_tokens, total_tokens, latency_sum_ms, charge, frozen_charges)
VALUES (?,?,?,?,?,?,1, ?, ?,0, ?,0,0, ?, ?, ?, ?, 0)`,
			day, kind, id, prov, model, model,
			reqs, reqs, toks/2, toks/2, toks, reqs*100, charge)
		if err != nil {
			t.Fatalf("灌数据失败: %v", err)
		}
	}
	ins(today, "user", "alice", "a", "m1", 10, 1000, 1.5)
	ins(today, "user", "alice", "a", "m2", 5, 500, 0.5)
	ins(today, "user", "bob", "a", "m1", 2, 200, 0.1)
	ins(old, "user", "alice", "a", "m1", 99, 9999, 99) // 30 天前：7 天窗口外

	code, raw := adminGet(t, h, "/v1/_admin/stats?days=7")
	if code != 200 {
		t.Fatalf("状态 %d：%s", code, raw)
	}
	var out struct {
		Days   int `json:"days"`
		Totals struct {
			Requests    int64   `json:"requests"`
			OK          int64   `json:"ok"`
			Failed      int64   `json:"failed"`
			TotalTokens int64   `json:"total_tokens"`
			Charge      float64 `json:"charge"`
		} `json:"totals"`
		ByDay []struct {
			Day         string `json:"day"`
			Requests    int64  `json:"requests"`
			TotalTokens int64  `json:"total_tokens"`
		} `json:"by_day"`
		ByModel []struct {
			Provider     string  `json:"provider"`
			Model        string  `json:"model"`
			Requests     int64   `json:"requests"`
			Charge       float64 `json:"charge"`
			AvgLatencyMs float64 `json:"avg_latency_ms"`
		} `json:"by_model"`
		ByScope []struct {
			Scope struct {
				Kind string `json:"kind"`
				ID   string `json:"id"`
			} `json:"scope"`
			Requests int64 `json:"requests"`
		} `json:"by_scope"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("响应解析失败: %v\n%s", err, raw)
	}

	// 窗口过滤：30 天前那行不进 7 天窗口
	if out.Totals.Requests != 17 || out.Totals.TotalTokens != 1700 {
		t.Fatalf("总量不对（窗口外的行不该计入）: %+v", out.Totals)
	}
	if out.Totals.OK != 17 || out.Totals.Failed != 0 {
		t.Fatalf("成败拆分不对: %+v", out.Totals)
	}
	if fmt.Sprintf("%.2f", out.Totals.Charge) != "2.10" {
		t.Fatalf("金额不对: %v", out.Totals.Charge)
	}
	if len(out.ByDay) != 1 || out.ByDay[0].Day != today {
		t.Fatalf("按日应只有今天一行: %+v", out.ByDay)
	}
	// 按模型：m1 两家用户合计 12 次、m2 5 次
	models := map[string]int64{}
	for _, m := range out.ByModel {
		models[m.Model] += m.Requests
	}
	if models["m1"] != 12 || models["m2"] != 5 {
		t.Fatalf("按模型聚合不对: %v", models)
	}
	// 按范围：alice 15 / bob 2
	scopes := map[string]int64{}
	for _, s := range out.ByScope {
		scopes[s.Scope.Kind+":"+s.Scope.ID] += s.Requests
	}
	if scopes["user:alice"] != 15 || scopes["user:bob"] != 2 {
		t.Fatalf("按范围聚合不对: %v", scopes)
	}
	// 平均延迟 = latency_sum / requests = 100ms
	if out.ByModel[0].AvgLatencyMs != 100 {
		t.Fatalf("平均延迟不对: %v", out.ByModel[0].AvgLatencyMs)
	}

	// days 校验：0 与 400 都拒
	for _, q := range []string{"days=0", "days=400", "days=abc"} {
		code, _ := adminGet(t, h, "/v1/_admin/stats?"+q)
		if code != 400 {
			t.Fatalf("%s 应 400，实际 %d", q, code)
		}
	}
}
