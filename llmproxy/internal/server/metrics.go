package server

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// 运行指标（/healthz）。刻意不引 Prometheus 客户端：本项目的观测对象是
// 「机器可读的一份 JSON」，不是一套抓取生态。热路径只做 atomic 累加，
// 延迟百分位在查询时对环形样本现算。
//
// 字段一旦进 /healthz 就是接口：删改要写 CHANGELOG。
type runtimeMetrics struct {
	inflight     atomic.Int64
	requests     atomic.Int64
	ok           atomic.Int64
	clientErr    atomic.Int64 // 4xx：客户端问题
	upstreamErr  atomic.Int64 // 5xx：上游/网关问题
	clientGone   atomic.Int64
	rateLimited  atomic.Int64
	retries      atomic.Int64 // attempts > 1 的请求
	circuitCools atomic.Int64 // 熔断/冷却次数
	dbWriteMs    atomic.Int64 // InsertRequest 累计耗时
	dbWriteFail  atomic.Int64

	latMu   sync.Mutex
	lat     []int64 // 环形缓冲，毫秒
	latPos  int
	latFull bool
}

// latRingSize 足够估出 p99，又不至于在高 QPS 下变成延迟采样器的内存负担。
const latRingSize = 4096

func newRuntimeMetrics() *runtimeMetrics {
	return &runtimeMetrics{lat: make([]int64, latRingSize)}
}

func (m *runtimeMetrics) beginRequest() func() {
	if m == nil {
		return func() {}
	}
	m.inflight.Add(1)
	m.requests.Add(1)
	return func() { m.inflight.Add(-1) }
}

// observe 记一次请求的终态。rec.OK / LatencyMs / Attempts / StatusCode 已填好。
func (m *runtimeMetrics) observe(rec *store.RequestRecord) {
	if m == nil || rec == nil {
		return
	}
	switch {
	case rec.OK:
		m.ok.Add(1)
	case rec.ErrorType == "client_gone":
		m.clientGone.Add(1)
	case rec.StatusCode >= 500 || rec.StatusCode == 0:
		m.upstreamErr.Add(1)
	default:
		m.clientErr.Add(1)
	}
	if rec.Attempts > 1 {
		m.retries.Add(1)
	}
	m.observeLatency(rec.LatencyMs)
}

func (m *runtimeMetrics) observeLatency(latMs int64) {
	if latMs < 0 {
		latMs = 0
	}
	m.latMu.Lock()
	m.lat[m.latPos] = latMs
	m.latPos++
	if m.latPos >= len(m.lat) {
		m.latPos = 0
		m.latFull = true
	}
	m.latMu.Unlock()
}

func (m *runtimeMetrics) noteRateLimited() {
	if m != nil {
		m.rateLimited.Add(1)
	}
}

func (m *runtimeMetrics) noteCircuitCool() {
	if m != nil {
		m.circuitCools.Add(1)
	}
}

func (m *runtimeMetrics) noteDBWrite(d time.Duration, err error) {
	if m == nil {
		return
	}
	m.dbWriteMs.Add(d.Milliseconds())
	if err != nil {
		m.dbWriteFail.Add(1)
	}
}

// snapshot 出一份给 /healthz 的 map。延迟分位对环形样本排序后现算。
func (m *runtimeMetrics) snapshot() map[string]any {
	if m == nil {
		return map[string]any{}
	}
	m.latMu.Lock()
	n := m.latPos
	if m.latFull {
		n = len(m.lat)
	}
	samples := make([]int64, n)
	copy(samples, m.lat[:n])
	m.latMu.Unlock()
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return map[string]any{
		"inflight":       m.inflight.Load(),
		"requests":       m.requests.Load(),
		"ok":             m.ok.Load(),
		"client_err":     m.clientErr.Load(),
		"upstream_err":   m.upstreamErr.Load(),
		"client_gone":    m.clientGone.Load(),
		"rate_limited":   m.rateLimited.Load(),
		"retries":        m.retries.Load(),
		"circuit_cools":  m.circuitCools.Load(),
		"db_write_ms":    m.dbWriteMs.Load(),
		"db_write_fail":  m.dbWriteFail.Load(),
		"latency_ms":     latencyPercentiles(samples),
		"latency_sample": n,
	}
}

func latencyPercentiles(sorted []int64) map[string]int64 {
	if len(sorted) == 0 {
		return map[string]int64{"p50": 0, "p95": 0, "p99": 0, "max": 0}
	}
	pick := func(q float64) int64 {
		i := int(q * float64(len(sorted)-1))
		if i < 0 {
			i = 0
		}
		if i >= len(sorted) {
			i = len(sorted) - 1
		}
		return sorted[i]
	}
	return map[string]int64{
		"p50": pick(0.50),
		"p95": pick(0.95),
		"p99": pick(0.99),
		"max": sorted[len(sorted)-1],
	}
}
