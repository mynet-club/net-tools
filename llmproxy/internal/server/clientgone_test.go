package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// 客户端在上游响应之前断开：不该赖供应商，也不该换一家重试。
//
// 曾经 RoundTrip 报 context canceled 时会走「供应商失败」那条路 —— 给这家记一次
// 连续失败、然后 continue 去打下一家。于是：
//
//   - failure_threshold 默认是 3，几个爱掐连接的客户端就能把一家健康上游打进冷却；
//   - 客户端已经走了，第二家还是被白打一次，并且也被记一笔莫须有的失败。
//
// 这条是在生产上实测到的：一次 curl 10 秒超时断开，网关日志里 neolink 与 deepseek
// 各挨了一条「请求失败: context canceled」，用量表里两家各多一条 failed，
// 最后还回了个 502 upstream_unavailable —— 把客户端的行为归因成了上游全挂。
func TestClientDisconnectDoesNotBlameProviders(t *testing.T) {
	release := make(chan struct{})
	var callsA, callsB int32
	slow := func(counter *int32) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(counter, 1)
			<-release // 一直不响应，逼客户端先断开
		}
	}
	upA := httptest.NewServer(slow(&callsA))
	upB := httptest.NewServer(slow(&callsB))
	defer func() { close(release); upA.Close(); upB.Close() }()

	// provA 点名声明了 m，provB 是通配兜底 —— 按「点名声明优先于通配兜底」，
	// 第一个被打的一定是 provA，于是「有没有重试到 provB」是确定的、不靠权重运气。
	h := newHarness(t, fmt.Sprintf(`
server:
  host: 127.0.0.1
  port: 0
  api_keys: [sk-static]
  request_timeout_ms: 60000
routing: {retry: 2, failure_threshold: 3, cooldown_seconds: 60}
providers:
  - name: provA
    enabled: true
    base_url: %s/v1
    api_key: sk-a
    weight: 1
    proxy: direct
    models: {m: m-up}
  - name: provB
    enabled: true
    base_url: %s/v1
    api_key: sk-b
    weight: 1
    proxy: direct
    models: ["*"]
database: {path: "", retain_days: 90}
log: {level: error}
`, upA.URL, upB.URL))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		h.gateway.URL+"/v1/chat/completions",
		bytes.NewReader([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-static")

	done := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()

	// 等 provA 确实收到请求了再断开，否则测的是「还没发出去就取消」
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(&callsA) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt32(&callsA) == 0 {
		t.Fatal("provA 没有收到请求，测试前提不成立")
	}
	cancel()
	<-done

	// 给网关一点时间处理这次断开
	time.Sleep(400 * time.Millisecond)

	if n := atomic.LoadInt32(&callsB); n != 0 {
		t.Errorf("客户端已断开，不该再重试到第二家（provB 被打了 %d 次）", n)
	}
	st := h.router.Snapshot()
	if got := st["provA"].ConsecutiveFailures; got != 0 {
		t.Errorf("客户端断开不该给 provA 记连续失败，实际 %d"+
			"（failure_threshold=3，三次就会把一家健康上游误打进冷却）", got)
	}
	if got := st["provB"].ConsecutiveFailures; got != 0 {
		t.Errorf("provB 压根没被打，却有 %d 次连续失败", got)
	}

	stats, err := h.db.Stats(time.Time{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Recent) == 0 {
		t.Fatal("没有落库的请求记录")
	}
	if et := stats.Recent[0].ErrorType; et != "client_gone" {
		t.Errorf("错误类型应当是 client_gone，实际 %q（%s）", et, stats.Recent[0].ErrorMsg)
	}
	if stats.Recent[0].OK {
		t.Errorf("客户端断开的请求不该记成成功: %+v", stats.Recent[0])
	}
}
