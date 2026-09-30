package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// /healthz 的 metrics 段：字段稳定、分位可算、结构规模可见。
func TestHealthzExposesRuntimeMetrics(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))

	// 打一发请求，让指标有数
	if resp, body := h.post(t, "/v1/chat/completions", "sk-local", chatBody("m")); resp.StatusCode != 200 {
		t.Fatalf("请求应当成功: %d %s", resp.StatusCode, body)
	}

	resp, raw := h.get(t, "/healthz", "")
	if resp.StatusCode != 200 {
		t.Fatalf("healthz: %d %s", resp.StatusCode, raw)
	}
	var out struct {
		Status          string         `json:"status"`
		PersistFailures int64          `json:"persist_failures"`
		Metrics         map[string]any `json:"metrics"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("解析 healthz: %v (%s)", err, raw)
	}
	if out.Status != "ok" {
		t.Errorf("status = %q", out.Status)
	}
	m := out.Metrics
	for _, key := range []string{
		"inflight", "requests", "ok", "client_err", "upstream_err",
		"rate_limited", "retries", "circuit_cools",
		"latency_ms", "latency_sample", "affinity_entries", "transport_cache",
	} {
		if _, ok := m[key]; !ok {
			t.Errorf("metrics 缺字段 %q: %v", key, m)
		}
	}
	if got, _ := m["requests"].(float64); got < 1 {
		t.Errorf("requests 至少 1，实际 %v", m["requests"])
	}
	if got, _ := m["ok"].(float64); got < 1 {
		t.Errorf("ok 至少 1，实际 %v", m["ok"])
	}
	lat, ok := m["latency_ms"].(map[string]any)
	if !ok {
		t.Fatalf("latency_ms 应当是对象: %v", m["latency_ms"])
	}
	for _, q := range []string{"p50", "p95", "p99", "max"} {
		if _, ok := lat[q]; !ok {
			t.Errorf("latency_ms 缺 %s: %v", q, lat)
		}
	}
}

// 观测器本身：分类、重试、限流、熔断、DB 耗时。
func TestRuntimeMetricsObserve(t *testing.T) {
	m := newRuntimeMetrics()
	// requests 在入口累加，observe 只记终态 —— 四次请求各占一次 inflight
	for i := 0; i < 4; i++ {
		m.beginRequest()()
	}
	m.observe(&store.RequestRecord{OK: true, LatencyMs: 10, Attempts: 1, StatusCode: 200})
	m.observe(&store.RequestRecord{OK: false, LatencyMs: 20, Attempts: 3, StatusCode: 502, ErrorType: "upstream_http"})
	m.observe(&store.RequestRecord{OK: false, LatencyMs: 5, Attempts: 1, StatusCode: 429, ErrorType: "rate_limited"})
	m.observe(&store.RequestRecord{OK: false, LatencyMs: 5, Attempts: 1, StatusCode: 0, ErrorType: "client_gone"})
	m.noteRateLimited()
	m.noteCircuitCool()
	m.noteDBWrite(3*time.Millisecond, nil)

	snap := m.snapshot()
	if got := snap["requests"].(int64); got != 4 {
		t.Errorf("requests = %v", got)
	}
	if got := snap["ok"].(int64); got != 1 {
		t.Errorf("ok = %v", got)
	}
	if got := snap["upstream_err"].(int64); got != 1 {
		t.Errorf("upstream_err = %v", got)
	}
	if got := snap["client_gone"].(int64); got != 1 {
		t.Errorf("client_gone = %v", got)
	}
	if got := snap["client_err"].(int64); got != 1 {
		t.Errorf("client_err = %v（429 走 client 桶）", got)
	}
	if got := snap["retries"].(int64); got != 1 {
		t.Errorf("retries = %v（只有 attempts>1 那次）", got)
	}
	if got := snap["rate_limited"].(int64); got != 1 {
		t.Errorf("rate_limited = %v", got)
	}
	if got := snap["circuit_cools"].(int64); got != 1 {
		t.Errorf("circuit_cools = %v", got)
	}
	if got := snap["db_write_ms"].(int64); got != 3 {
		t.Errorf("db_write_ms = %v", got)
	}
	if got := snap["inflight"].(int64); got != 0 {
		t.Errorf("inflight 应当回到 0，实际 %v", got)
	}
}

// 百分位：样本有序时 p50/p99/max 取对位置。
func TestLatencyPercentiles(t *testing.T) {
	samples := make([]int64, 100)
	for i := range samples {
		samples[i] = int64(i + 1) // 1..100
	}
	p := latencyPercentiles(samples)
	if p["p50"] != 50 || p["p99"] != 99 || p["max"] != 100 {
		t.Errorf("分位不对: %v", p)
	}
	empty := latencyPercentiles(nil)
	if empty["p50"] != 0 || empty["max"] != 0 {
		t.Errorf("空样本应当全 0: %v", empty)
	}
}

// 确认 handleHealthz 在 metrics 为 nil 时也不炸（构造器漏接线的兜底）。
func TestHealthzSafeWithoutMetrics(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))
	h.srv.metrics = nil
	resp, raw := h.get(t, "/healthz", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics 为 nil 时 healthz 仍应 200: %d %s", resp.StatusCode, raw)
	}
}

func TestPrometheusMetrics(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))
	if resp, _ := h.post(t, "/v1/chat/completions", "sk-local", chatBody("m")); resp.StatusCode != 200 {
		t.Fatal("请求失败")
	}
	resp, raw := h.get(t, "/metrics", "")
	if resp.StatusCode != 200 {
		t.Fatalf("metrics = %d %s", resp.StatusCode, raw)
	}
	text := string(raw)
	for _, name := range []string{
		"llmproxy_requests_total", "llmproxy_ok_total", "llmproxy_inflight",
		"llmproxy_latency_ms", "llmproxy_persist_failures",
	} {
		if !strings.Contains(text, name) {
			t.Errorf("缺指标 %s:\n%s", name, text)
		}
	}
	if !strings.Contains(text, `llmproxy_latency_ms{q="p99"}`) {
		t.Errorf("延迟分位标签不对:\n%s", text)
	}
}
