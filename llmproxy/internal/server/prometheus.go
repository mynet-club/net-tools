package server

import (
	"fmt"
	"net/http"
	"sort"
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

	// §3.I：3.0 委托面（执行器交换与知识检索）。标签取值空间全是封闭集合 ——
	// 执行器名只来自注册表，原因码只来自 executor / knowledge 两个注册表，
	// 拒候选的阶段名是接线侧常量。唯一来自配置的是知识源名，它按文本写出前
	// 必须过 promLabel：那一列的校验禁掉空白/换行/路径分隔符，**没有**禁掉引号，
	// 而 /metrics 不鉴权，一条没转义的 `"` 就是 exposition 文本注入。
	if ex, ok := m["executor"].(map[string]any); ok {
		if by := int64Map(ex["exchanges"]); len(by) > 0 {
			for _, name := range sortedKeys(by) {
				pf("llmproxy_executor_exchanges_total", "交给执行器承载的上游交换次数", "counter",
					float64(by[name]), `{executor="`+promLabel(name)+`"}`)
			}
		}
		if by := nestedInt64Map(ex["failures_by_reason"]); len(by) > 0 {
			for _, name := range sortedKeys(by) {
				for _, reason := range sortedKeys(by[name]) {
					pf("llmproxy_executor_failures_total", "执行器交换的稳定失败码计数", "counter",
						float64(by[name][reason]),
						`{executor="`+promLabel(name)+`",reason="`+promLabel(reason)+`"}`)
				}
			}
		}
		if by := int64Map(ex["rejected_by_stage"]); len(by) > 0 {
			for _, stage := range sortedKeys(by) {
				// 不带执行器名：注册不上的那个名字正是被拒原因，让它进标签等于让
				// 被观测的东西决定观测的基数。
				pf("llmproxy_executor_rejected_total", "候选在网关侧被拒、一次都没出网", "counter",
					float64(by[stage]), `{stage="`+promLabel(stage)+`"}`)
			}
		}
		if by := int64Map(ex["skipped"]); len(by) > 0 {
			for _, reason := range sortedKeys(by) {
				pf("llmproxy_executor_skipped_total", "本该委托却退回 2.x 传输的次数", "counter",
					float64(by[reason]), `{reason="`+promLabel(reason)+`"}`)
			}
		}
	}
	if kb, ok := m["knowledge"].(map[string]any); ok {
		if by := int64Map(kb["queries_by_source"]); len(by) > 0 {
			for _, src := range sortedKeys(by) {
				pf("llmproxy_knowledge_searches_total", "源级检索被问到的次数（含委托没发出去的）", "counter",
					float64(by[src]), `{source="`+promLabel(src)+`"}`)
			}
		}
		if by := nestedInt64Map(kb["failures_by_source"]); len(by) > 0 {
			for _, src := range sortedKeys(by) {
				for _, reason := range sortedKeys(by[src]) {
					pf("llmproxy_knowledge_failures_total", "按源分的检索失败原因码计数", "counter",
						float64(by[src][reason]),
						`{source="`+promLabel(src)+`",reason="`+promLabel(reason)+`"}`)
				}
			}
		}
		if by := int64Map(kb["failures_by_reason"]); len(by) > 0 {
			for _, reason := range sortedKeys(by) {
				// 跨源汇总那一份：告警「检索是不是都在超时」不该按源写规则。
				pf("llmproxy_knowledge_failure_reasons_total", "跨源汇总的检索失败原因码计数", "counter",
					float64(by[reason]), `{reason="`+promLabel(reason)+`"}`)
			}
		}
		pf("llmproxy_knowledge_duration_ms_total", "源级检索累计耗时（只含真跑过的）", "counter",
			float64(int64Value(kb["duration_ms_total"])), "")
		pf("llmproxy_knowledge_measured_total", "有耗时样本的检索次数", "counter",
			float64(int64Value(kb["measured"])), "")
		pf("llmproxy_knowledge_citations_total", "源侧回报的命中总数", "counter",
			float64(int64Value(kb["citations"])), "")
		pf("llmproxy_knowledge_truncated_total", "被结果上限截断的检索次数", "counter",
			float64(int64Value(kb["truncated"])), "")
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

// promLabel 转义标签值里的三个必转字符。
//
// 只在标签值来自配置或注册表之外不需要它 —— 但这里全部按它走一遍：漏一个来源
// 就是 exposition 文本注入，而这个端点不带鉴权。
func promLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

// sortedKeys 让 exposition 文本对同一份快照逐字节相同：map 的遍历顺序是随机的，
// 而 /metrics 的输出会被测试与快照比对消费。
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func int64Map(v any) map[string]int64 {
	m, _ := v.(map[string]int64)
	return m
}

func nestedInt64Map(v any) map[string]map[string]int64 {
	m, _ := v.(map[string]map[string]int64)
	return m
}

func int64Value(v any) int64 {
	n, _ := v.(int64)
	return n
}
