package server

import (
	"fmt"
	"net/http"
	"strings"
)

// handleMetrics 输出 Prometheus 文本格式。
// /healthz 的 JSON 仍在（脚本与健康检查用）；这里是给抓取生态用的另一张皮。
// 指标名稳定，改名 = 破坏 dashboard，见 CHANGELOG。
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := s.metrics.snapshot()
	lat, _ := m["latency_ms"].(map[string]int64)
	var b strings.Builder
	pf := func(name, help, typ string, v float64, labels string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s%s %g\n", name, help, name, typ, name, labels, v)
	}
	g := func(k string) float64 {
		switch x := m[k].(type) {
		case int64:
			return float64(x)
		case int:
			return float64(x)
		case float64:
			return x
		default:
			return 0
		}
	}
	pf("llmproxy_requests_total", "转发请求总数", "counter", g("requests"), "")
	pf("llmproxy_ok_total", "成功请求", "counter", g("ok"), "")
	pf("llmproxy_client_err_total", "下游 4xx", "counter", g("client_err"), "")
	pf("llmproxy_upstream_err_total", "上游/网关 5xx", "counter", g("upstream_err"), "")
	pf("llmproxy_client_gone_total", "客户端提前断开", "counter", g("client_gone"), "")
	pf("llmproxy_rate_limited_total", "限流拒绝", "counter", g("rate_limited"), "")
	pf("llmproxy_retries_total", "发生重试的请求", "counter", g("retries"), "")
	pf("llmproxy_circuit_cools_total", "熔断/冷却次数", "counter", g("circuit_cools"), "")
	pf("llmproxy_db_write_ms_total", "记账写库累计毫秒", "counter", g("db_write_ms"), "")
	pf("llmproxy_db_write_fail_total", "记账写库失败", "counter", g("db_write_fail"), "")
	pf("llmproxy_inflight", "在途请求", "gauge", g("inflight"), "")
	pf("llmproxy_affinity_entries", "粘性表条目", "gauge", float64(s.affinity.Len()), "")
	pf("llmproxy_transport_cache", "Transport 缓存", "gauge", float64(s.transports.Len()), "")
	pf("llmproxy_persist_failures", "落库失败（账在丢）", "counter", float64(s.persistFailures.Load()), "")
	if lat != nil {
		for _, q := range []string{"p50", "p95", "p99", "max"} {
			pf("llmproxy_latency_ms", "转发延迟分位", "gauge", float64(lat[q]), `{q="`+q+`"}`)
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
