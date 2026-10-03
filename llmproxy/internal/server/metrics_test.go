package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/executor"
	"github.com/mynet-club/net-tools/llmproxy/internal/knowledge"
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

// ---------------------------------------------------------------- §3.I 委托面维度

// 执行器与检索两个面的计数与快照形状。
//
// 这里刻意喂三类「不该记」的输入（空名、空原因码、负耗时）：它们都必须被丢掉而不是
// 变成一个 0 值序列 —— 一个凭空的 0 会被读成「观测过且没事」，而实际是没观测过。
func TestRuntimeMetricsExecutorAndKnowledgeDimensions(t *testing.T) {
	m := newRuntimeMetrics()
	m.observeExecutorExchange("http-openai", "")
	m.observeExecutorExchange("http-openai", string(executor.ReasonTimeout))
	m.observeExecutorExchange("", "不该进标签")
	m.noteExecutorRejection(executorRejectUnregistered)
	m.noteExecutorRejection("")
	m.noteExecutorSkip(executorSkipPlanDrift)

	m.noteKnowledgeQuery("t-src")
	m.noteKnowledgeFailure("t-src", string(knowledge.ReasonTimeout))
	m.noteKnowledgeFailure("t-src", "")
	m.noteKnowledgeFailure("", string(knowledge.ReasonTimeout))
	m.observeKnowledgeResult(120, 3, true)
	m.observeKnowledgeResult(-1, 5, false) // 坏样本：不进均值也不计命中

	snap := m.snapshot()
	ex, ok := snap["executor"].(map[string]any)
	if !ok {
		t.Fatalf("metrics 缺 executor 段: %v", snap["executor"])
	}
	if got := int64Map(ex["exchanges"])["http-openai"]; got != 2 {
		t.Errorf("exchanges[http-openai] = %d，want 2（空名那条不许记账）", got)
	}
	fails := nestedInt64Map(ex["failures_by_reason"])
	if got := fails["http-openai"][string(executor.ReasonTimeout)]; got != 1 {
		t.Errorf("失败维度不对: %v", fails)
	}
	if int64Map(ex["rejected_by_stage"])[executorRejectUnregistered] != 1 {
		t.Errorf("rejected_by_stage = %v", ex["rejected_by_stage"])
	}
	if int64Map(ex["skipped"])[executorSkipPlanDrift] != 1 {
		t.Errorf("skipped = %v", ex["skipped"])
	}

	kb, ok := snap["knowledge"].(map[string]any)
	if !ok {
		t.Fatalf("metrics 缺 knowledge 段: %v", snap["knowledge"])
	}
	// 被问到 1 次、失败 1 次：分子分母都在，失败率才谈得上算。
	if int64Map(kb["queries_by_source"])["t-src"] != 1 {
		t.Errorf("queries_by_source = %v", kb["queries_by_source"])
	}
	if nestedInt64Map(kb["failures_by_source"])["t-src"][string(knowledge.ReasonTimeout)] != 1 {
		t.Errorf("failures_by_source = %v", kb["failures_by_source"])
	}
	if int64Map(kb["failures_by_reason"])[string(knowledge.ReasonTimeout)] != 1 {
		t.Errorf("跨源汇总的失败维度 = %v", kb["failures_by_reason"])
	}
	if got := int64Value(kb["measured"]); got != 1 {
		t.Errorf("measured = %d，负耗时那条不许占样本", got)
	}
	if got := int64Value(kb["avg_duration_ms"]); got != 120 {
		t.Errorf("avg_duration_ms = %d", got)
	}
	if got := int64Value(kb["citations"]); got != 3 {
		t.Errorf("citations = %d，坏样本的命中数不许累加", got)
	}
	if got := int64Value(kb["truncated"]); got != 1 {
		t.Errorf("truncated = %d", got)
	}

	// legacy（一次委托都没发生）时两段都在、都是空表：字段在不在不能取决于跑没跑过。
	empty := newRuntimeMetrics().snapshot()
	if _, ok := empty["executor"].(map[string]any); !ok {
		t.Error("空快照也该有 executor 段")
	}
	if _, ok := empty["knowledge"].(map[string]any); !ok {
		t.Error("空快照也该有 knowledge 段")
	}
}

// 委托交换的失败维度必须落进两个封闭集合之内。
//
// 未注册的 ReasonCode 值走 wiring_unclassified：ReasonCode.String() 对它会拼出
// executor_unregistered(<原样>)，那串文本长度与内容都不受控，进标签就是让一次
// 越界的码值决定 /metrics 的序列数。
func TestExecutorExchangeReasonStaysInClosedSets(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		want   string
	}{
		{"成功无失败码", nil, 200, ""},
		{"上游 4xx", nil, 404, string(executor.ReasonUpstreamClientStatus)},
		{"上游 5xx", nil, 503, string(executor.ReasonUpstreamServerStatus)},
		{"注册码", &executor.ExecutionError{Code: executor.ReasonConnectFailed}, 0, string(executor.ReasonConnectFailed)},
		{"未注册码", &executor.ExecutionError{Code: executor.ReasonCode("编一个")}, 0, executorReasonUnclassified},
		{"空码", &executor.ExecutionError{}, 0, executorReasonUnclassified},
		{"非执行器错误", errors.New("别的东西"), 0, executorReasonUnclassified},
		{"错误优先于状态码", &executor.ExecutionError{Code: executor.ReasonTimeout}, 500, string(executor.ReasonTimeout)},
	}
	for _, tc := range cases {
		got := executorExchangeReason(tc.err, tc.status)
		if got != tc.want {
			t.Errorf("%s: reason = %q，want %q", tc.name, got, tc.want)
		}
		if got == "" {
			continue
		}
		if got == executorReasonUnclassified {
			continue
		}
		if !executor.ReasonCode(got).Valid() {
			t.Errorf("%s: 标签值 %q 不在执行器注册码表里", tc.name, got)
		}
	}
}

// 标签值来自配置（知识源名），而那一列的校验只禁空白与路径分隔符、**没禁引号**：
// /metrics 不鉴权，没转义的一个 `"` 就是 exposition 文本注入。
func TestPromLabelEscapesQuotedNames(t *testing.T) {
	if got := promLabel(`a"b`); got != `a\"b` {
		t.Errorf("引号没转义: %q", got)
	}
	if got := promLabel(`a\b`); got != `a\\b` {
		t.Errorf("反斜杠没转义: %q", got)
	}
	if got := promLabel("a\nb"); got != `a\nb` {
		t.Errorf("换行没转义: %q", got)
	}
	// 转义顺序也要成立：先转义反斜杠，否则 \" 里的 \ 会被二次转义。
	if got := promLabel(`a\"b`); got != `a\\\"b` {
		t.Errorf("复合转义不对: %q", got)
	}
}

// 未注册的知识原因码不建标签（口径同审计写入侧：那种值在审计就要被拒）。
func TestKnowledgeFailureMetricIgnoresUnregisteredReason(t *testing.T) {
	m := newRuntimeMetrics()
	kbFailureMetric(m, "t-src", knowledge.Reason("retrieval_made_up"))
	kbFailureMetric(m, "t-src", knowledge.ReasonTimeout)
	snap := m.snapshot()["knowledge"].(map[string]any)
	byReason := int64Map(snap["failures_by_reason"])
	if len(byReason) != 1 {
		t.Fatalf("失败维度 = %v，未注册的码不该建序列", byReason)
	}
	if _, ok := byReason[string(knowledge.ReasonTimeout)]; !ok {
		t.Errorf("注册过的码没记上: %v", byReason)
	}
}
