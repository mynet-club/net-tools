package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 上游流起来之后一个字都没吐就断（线上 INTERNAL_ERROR 的形状）——
// 客户端不能只收到半截空 SSE，要拿到一条人读友好 + 机器可识别的
// 「压缩会话后重试」指令。
func TestEmptyStreamEmitsCompactHint(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// 声明比实际写出的更长：handler 一返回，客户端读 body 就会
		// unexpected EOF —— 等价于线上 HTTP/2 RST_STREAM 的「流被掐断」。
		w.Header().Set("Content-Length", "100000")
		w.WriteHeader(http.StatusOK)
		// 只吐 role，没有 content，然后提前结束（不写 [DONE]）
		fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	t.Cleanup(up.Close)

	h := newMUHarnessWith(t, idleStreamYAML(up.URL, testPricing, 5000, 600000))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "sys-model", "")

	resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "sys-model", "stream": true,
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	_ = resp
	body := string(raw)

	if !strings.Contains(body, emptyHintCode) {
		t.Errorf("应注入机器可识别指令 %q，实际收到：%s", emptyHintCode, truncateMsg(body, 400))
	}
	if !strings.Contains(body, emptyHintAction) {
		t.Errorf("应包含 action=%q，实际收到：%s", emptyHintAction, truncateMsg(body, 400))
	}
	if !strings.Contains(body, "压缩会话") {
		t.Errorf("应包含人读提示「压缩会话」，实际收到：%s", truncateMsg(body, 400))
	}
	if !strings.Contains(body, "[DONE]") {
		t.Errorf("应补 [DONE] 收尾，实际收到：%s", truncateMsg(body, 400))
	}

	// 归因要记成上游重置，不能是含糊的 relay_error
	time.Sleep(100 * time.Millisecond)
	st, err := h.db.Stats(time.Time{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Recent) == 0 {
		t.Fatal("没有落库的请求记录")
	}
	rec := st.Recent[0]
	if rec.OK {
		t.Errorf("空流不该记成成功: %+v", rec)
	}
	if rec.ErrorType != "upstream_stream_reset" && rec.ErrorType != "relay_error" {
		t.Errorf("错误类型应是 upstream_stream_reset（或至少 relay_error），实际 %q（%s）", rec.ErrorType, rec.ErrorMsg)
	}
}

// 正常跑完的流**不能**被补指令 —— 否则会在 [DONE] 后面多一帧，把好答案搅乱。
func TestNormalStreamDoesNotGetHint(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hello\"}}]}\n\n")
		fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\" world\"},\"finish_reason\":\"stop\"}]}\n\n")
		fmt.Fprint(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(up.Close)

	h := newMUHarnessWith(t, idleStreamYAML(up.URL, testPricing, 5000, 600000))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "sys-model", "")

	_, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "sys-model", "stream": true,
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	body := string(raw)

	if strings.Contains(body, emptyHintCode) {
		t.Errorf("正常完成的流不该注入指令，收到：%s", truncateMsg(body, 400))
	}
	if !strings.Contains(body, "Hello") || !strings.Contains(body, "[DONE]") {
		t.Errorf("正常内容应原样转发，收到：%s", truncateMsg(body, 400))
	}
}

// 已经吐了正文、中途才被掐 —— 有内容就别用指令覆盖，只补 [DONE] 以外的错误说明
// 也要克制：正文在就不注入（见 shouldEmitEmptyHint）。
func TestPartialContentStreamDoesNotGetHint(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"已经说了一半\"}}]}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(30 * time.Millisecond)
	}))
	t.Cleanup(up.Close)

	h := newMUHarnessWith(t, idleStreamYAML(up.URL, testPricing, 5000, 600000))
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "sys-model", "")

	_, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "sys-model", "stream": true,
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	body := string(raw)

	if strings.Contains(body, emptyHintCode) {
		t.Errorf("已有正文时不该注入压缩指令，收到：%s", truncateMsg(body, 400))
	}
}

// noteContent 只量 JSON 原文里 content 字符串的字节数（含转义符），
// 用来判断「有没有说话」—— 不求解码后的精确长度。
func TestUsageScannerContentLen(t *testing.T) {
	sc := &usageScanner{start: time.Now()}
	sc.noteContent([]byte(`{"choices":[{"index":0,"delta":{"content":"abc"}}]}`))
	if got := sc.contentBytes(); got != 3 {
		t.Errorf("contentLen = %d, want 3", got)
	}
	// 原文是 x\"y —— 引号前有反斜杠，扫描器数 4 个原始字节
	sc.noteContent([]byte(`{"choices":[{"index":0,"delta":{"content":"x\"y"}}]}`))
	if got := sc.contentBytes(); got != 7 {
		t.Errorf("contentLen = %d, want 7（3 + 4）", got)
	}
	// 空字符串不算「说了话」
	sc2 := &usageScanner{start: time.Now()}
	sc2.noteContent([]byte(`{"choices":[{"index":0,"delta":{"content":""}}]}`))
	if got := sc2.contentBytes(); got != 0 {
		t.Errorf("空 content 的 contentLen = %d, want 0", got)
	}
}
