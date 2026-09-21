package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 流式请求的测试装置：只起一家供应商，并把两个超时都设成能快速触发的值。
// retry=1 是为了不让失败切换到第二家去、把结果搅浑；failure_threshold 调高免得熔断插手。
func idleStreamYAML(upstreamURL, pricing string, idleMs, providerTimeoutMs int) string {
	return fmt.Sprintf(`
server:
  host: 127.0.0.1
  port: 0
  api_keys: [sk-static]
  admin_token: sk-admin
  request_timeout_ms: 600000
  stream_idle_timeout_ms: %d
routing: {retry: 1, failure_threshold: 1000, cooldown_seconds: 1}
providers:
  - name: sys-a
    enabled: true
    base_url: %s/v1
    api_key: sk-sys
    weight: 1
    proxy: direct
    timeout_ms: %d
    models: ["*"]
database: {path: "", retain_days: 30}
log: {level: error}
%s
`, idleMs, upstreamURL, providerTimeoutMs, pricing)
}

// 上游发了头和一个 chunk 之后再不动 —— 应当在空闲上限处失败，而不是耗满总时限。
//
// 这就是线上那条 `FAIL/200 ... context deadline exceeded, 949040ms` 的形状：状态码早已
// 200 发出去，卡在流中间，然后一直等到总时限才断。
func TestStreamIdleTimeoutFailsStalledUpstream(t *testing.T) {
	stall := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"}}]}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-stall // 之后一动不动
	}))
	defer func() { close(stall); up.Close() }()

	h := newMUHarnessWith(t, idleStreamYAML(up.URL, testPricing, 1500, 600000))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "sys-model", "")

	start := time.Now()
	h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "sys-model", "stream": true,
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	elapsed := time.Since(start)

	// 空闲上限 1.5s：留足余量，但只要明显小于总时限（600s）就说明看门狗起作用了
	if elapsed > 8*time.Second {
		t.Fatalf("空闲超时没生效：等了 %s（上限 1.5s，总时限 600s）", elapsed)
	}
	st, err := h.db.Stats(time.Time{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Recent) == 0 {
		t.Fatal("没有落库的请求记录")
	}
	rec := st.Recent[0]
	if rec.OK {
		t.Errorf("卡死的流不该记成成功: %+v", rec)
	}
	if rec.ErrorType != "upstream_idle" {
		t.Errorf("错误类型应当是 upstream_idle，实际 %q（%s）", rec.ErrorType, rec.ErrorMsg)
	}
	if !strings.Contains(rec.ErrorMsg, "空闲") {
		t.Errorf("错误信息该说清是空闲超时: %q", rec.ErrorMsg)
	}
}

// 上游慢但一直有数据 —— 不能被掐断，哪怕它跑得比「供应商超时」还久。
//
// 这是改动的另一半目的：流式不再受总时限约束（旧行为会在 provider timeout 处切断
// 一次正常的长回答），只由空闲看门狗管。
func TestSlowButAliveStreamSurvives(t *testing.T) {
	const chunks = 10
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		f, _ := w.(http.Flusher)
		for i := 0; i < chunks; i++ {
			fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"%d\"}}]}\n\n", i)
			if f != nil {
				f.Flush()
			}
			time.Sleep(250 * time.Millisecond) // 每个 chunk 间隔 250ms，远小于空闲上限
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		if f != nil {
			f.Flush()
		}
	}))
	t.Cleanup(up.Close)

	// 总时长约 2.5s，而供应商超时只有 1s：旧的总时限行为会在 1s 处把流切断
	h := newMUHarnessWith(t, idleStreamYAML(up.URL, testPricing, 1500, 1000))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "sys-model", "")

	resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "sys-model", "stream": true,
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应 200，实际 %d", resp.StatusCode)
	}
	body := string(raw)
	for i := 0; i < chunks; i++ {
		if !strings.Contains(body, fmt.Sprintf("\"%d\"", i)) && !(i == 0 && strings.Contains(body, ":0")) {
			t.Fatalf("第 %d 个 chunk 没转发出去，流被提前掐断了。收到 %d 字节", i, len(body))
		}
	}
	if !strings.Contains(body, "[DONE]") {
		t.Errorf("流没走完（缺 [DONE]），收到 %d 字节", len(body))
	}
	st, err := h.db.Stats(time.Time{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Recent) == 0 {
		t.Fatal("没有落库的请求记录")
	}
	if !st.Recent[0].OK {
		t.Fatalf("慢但活着的流不该判失败: %+v", st.Recent[0])
	}
}

// 关掉空闲看门狗（0）时要退回旧行为：这时流式仍受总时限约束。
// 钉住这一点，免得以后以为「只要配了流式就永远不受时限管」。
func TestStreamIdleDisabledFallsBackToTotalTimeout(t *testing.T) {
	stall := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"}}]}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-stall
	}))
	defer func() { close(stall); up.Close() }()

	// idle=0 关闭；总时限取 min(provider 1000ms, 全局) = 1s
	h := newMUHarnessWith(t, idleStreamYAML(up.URL, testPricing, 0, 1000))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "sys-model", "")

	start := time.Now()
	h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "sys-model", "stream": true,
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if elapsed := time.Since(start); elapsed > 8*time.Second {
		t.Fatalf("总时限没生效：等了 %s", elapsed)
	}
	st, err := h.db.Stats(time.Time{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Recent) == 0 || st.Recent[0].OK {
		t.Fatalf("关闭看门狗时应当仍由总时限把卡死的流判失败: %+v", st.Recent)
	}
	if et := st.Recent[0].ErrorType; et == "upstream_idle" {
		t.Errorf("看门狗已关闭，不该报成空闲超时（%s）", et)
	}
}
