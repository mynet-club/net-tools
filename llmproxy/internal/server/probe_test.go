package server

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 探活：活着的上游记成功，挂掉的记失败（进熔断计数）。
func TestActiveProbeRound(t *testing.T) {
	var hits int64
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(200)
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer bad.Close()

	up := startMockUpstream(t, &mockUpstream{name: "sys-good", apiKey: "k"})
	_ = up
	// 直接构造 harness 不便，改用轻量：Probe.round 要 *Server —— 用 consumption harness
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)

	// 把两个假上游塞进 globalProviders 不容易；改为测 one() 的成败路径
	p := newActiveProbe(time.Second)
	p.one(h.srv, "good", good.URL, "")
	st := h.srv.router.SnapshotFor(policy.SystemScope)
	if g := st["good"]; g.TotalRequests == 0 {
		// ReportSuccessFor 会 +TotalRequests
		t.Errorf("good 应记一次成功: %+v", g)
	}
	p.one(h.srv, "bad", bad.URL, "")
	st = h.srv.router.SnapshotFor(policy.SystemScope)
	if b := st["bad"]; b.ConsecutiveFailures == 0 {
		t.Errorf("bad 应记一次失败: %+v", b)
	}
}
