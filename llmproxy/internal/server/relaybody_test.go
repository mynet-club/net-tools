package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 非流式响应必须有内存上限：下游的**请求**体有 http.MaxBytesReader 管着，
// 上游的**响应**体却曾经完全没限 —— 一个 BYO 用户把 base_url 指向一个返回超大响应的
// 非 SSE 端点，一次请求就能把网关内存吃光。
//
// 撞上上限时还要**改判 502**，而不是把截断的 body 当正常响应发下去。
func TestNonStreamResponseSizeLimit(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// 分块写，免得测试装置自己也分配一大块；比上限多写 1 字节就够触发判定
		buf := make([]byte, 64*1024)
		for remain := int64(maxUpstreamResponseBytes) + 1; remain > 0; {
			n := int64(len(buf))
			if n > remain {
				n = remain
			}
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			remain -= n
		}
	}))
	defer up.Close()

	h := newHarness(t, cfgYAML(map[string]string{"vendorA": up.URL}, []string{"sk-local"}))
	resp, raw := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("超大响应应当改判 502，实际 %d", resp.StatusCode)
	}
	if !bytes.Contains(raw, []byte("上限")) {
		t.Errorf("错误信息该说清是撞上了缓冲上限，实际：%s", truncateMsg(string(raw), 200))
	}

	// 库里要归因成上游响应体的问题，不能记成成功
	time.Sleep(100 * time.Millisecond)
	st, err := h.db.Stats(time.Time{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Recent) == 0 {
		t.Fatal("没有落库的请求记录")
	}
	if st.Recent[0].OK {
		t.Errorf("撞上上限的请求不该记成成功: %+v", st.Recent[0])
	}
	if et := st.Recent[0].ErrorType; et != "upstream_body" {
		t.Errorf("错误类型应当是 upstream_body，实际 %q（%s）", et, st.Recent[0].ErrorMsg)
	}
}

// 非流式：上游在响应中途断掉时，客户端要收到 502，而不是一个 200 + 截断 body。
//
// 曾经 WriteHeader 在读 body 之前就执行、上游的 Content-Length 也已经复制给下游了，
// 于是 io.Copy 中途失败时客户端收到的是 200 + 残缺 JSON ——
// 它无法区分「模型返回了空补全」和「代理挂了」。
func TestNonStreamMidBodyFailureReturns502(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// 声明 4096 字节却只写 12 字节就返回：Go 的 http 服务端会检测到短写、
		// 直接关掉连接而不发正常的结束标记，客户端那边就是一次读失败。
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[`))
	}))
	defer up.Close()

	h := newHarness(t, cfgYAML(map[string]string{"vendorA": up.URL}, []string{"sk-local"}))
	resp, raw := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("上游中途断开应当改判 502，实际 %d（body=%s）", resp.StatusCode, truncateMsg(string(raw), 200))
	}

	time.Sleep(100 * time.Millisecond)
	st, err := h.db.Stats(time.Time{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Recent) == 0 {
		t.Fatal("没有落库的请求记录")
	}
	if st.Recent[0].OK {
		t.Errorf("中途断开的响应不该记成成功: %+v", st.Recent[0])
	}
	if et := st.Recent[0].ErrorType; et != "upstream_body" {
		t.Errorf("错误类型应当是 upstream_body，实际 %q（%s）", et, st.Recent[0].ErrorMsg)
	}
}

// 正常的非流式响应不能被上面两条改动误伤：状态码、body 与 usage 都要照常。
func TestNonStreamHappyPathUnaffected(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "vendorA", apiKey: "sk-vendorA"})
	h := newHarness(t, cfgYAML(map[string]string{"vendorA": up.baseURL}, []string{"sk-local"}))

	resp, raw := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("正常响应应当 200，实际 %d: %s", resp.StatusCode, truncateMsg(string(raw), 300))
	}
	if !bytes.Contains(raw, []byte("choices")) {
		t.Errorf("body 应当原样透传，实际：%s", truncateMsg(string(raw), 300))
	}
	// 网关自己加的两个观测头仍然要在
	if resp.Header.Get("X-LLMProxy-Provider") == "" {
		t.Error("缺少 X-LLMProxy-Provider 头")
	}

	time.Sleep(100 * time.Millisecond)
	st, err := h.db.Stats(time.Time{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Recent) == 0 || !st.Recent[0].OK {
		t.Fatalf("正常请求应当记成成功: %+v", st.Recent)
	}
	if st.Recent[0].PromptTokens == nil {
		t.Error("usage 应当被提取出来（非流式走 consumeJSON）")
	}
}
