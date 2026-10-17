package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockAnthropicUpstream 只说 Anthropic 线格式：记录收到的请求（路径/头/正文形状），
// 按请求的 stream 与否回 Messages 响应或事件流。
type mockAnthropicUpstream struct {
	mu       sync.Mutex
	calls    []map[string]any
	baseURL  string
	failMode bool
}

func startMockAnthropicUpstream(t *testing.T, m *mockAnthropicUpstream) *mockAnthropicUpstream {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		m.mu.Lock()
		m.calls = append(m.calls, map[string]any{
			"path":              r.URL.Path,
			"x-api-key":         r.Header.Get("x-api-key"),
			"anthropic-version": r.Header.Get("anthropic-version"),
			"body":              body,
		})
		m.mu.Unlock()

		if m.failMode {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"type":"error","error":{"type":"permission_error","message":"plan 用完了"}}`)
			return
		}

		stream, _ := body["stream"].(bool)
		if stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, `event: message_start
data: {"type":"message_start","message":{"id":"msg_up","type":"message","role":"assistant","model":"up-m","content":[],"usage":{"input_tokens":9,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"嗯"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"你好"}}

event: content_block_stop
data: {"type":"content_block_stop","index":1}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":12}}

event: message_stop
data: {"type":"message_stop"}
`)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"msg_up","type":"message","role":"assistant","model":"up-m",
			"content":[{"type":"thinking","thinking":"嗯"},{"type":"text","text":"你好"}],
			"stop_reason":"end_turn","stop_sequence":null,
			"usage":{"input_tokens":9,"output_tokens":12}}`)
	}))
	t.Cleanup(srv.Close)
	m.baseURL = srv.URL
	return m
}

func (m *mockAnthropicUpstream) Calls() []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]map[string]any, len(m.calls))
	copy(out, m.calls)
	return out
}

// anthropicUpYAML 是 protocol: anthropic_messages 的供应商配置。
func anthropicUpYAML(baseURL string) string {
	return fmt.Sprintf(`server:
  host: 127.0.0.1
  port: 0
  api_keys:
    - sk-local
providers:
  - name: xiaomi
    base_url: %s/v1
    api_key: sk-up
    weight: 1
    protocol: anthropic_messages
    models: ["*"]
database:
  retain_days: 90
log:
  level: error
`, baseURL)
}

// TestAnthropicUpstreamDoubleFlipNonStream 二次翻转的非流式全链路：
// OpenAI 客户端进 → 治理核（OpenAI 形状）→ Anthropic 上游 → 回形到 OpenAI。
func TestAnthropicUpstreamDoubleFlipNonStream(t *testing.T) {
	up := startMockAnthropicUpstream(t, &mockAnthropicUpstream{})
	h := newHarness(t, anthropicUpYAML(up.baseURL))

	resp, raw := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model": "m1", "max_tokens": 32,
		"messages": []map[string]any{{"role": "user", "content": "你好"}},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("状态 %d：%s", resp.StatusCode, raw)
	}
	var chat struct {
		Choices []struct {
			Message struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &chat); err != nil {
		t.Fatalf("OpenAI 客户端拿到的不是 chat 形状: %v\n%s", err, raw)
	}
	if len(chat.Choices) != 1 || chat.Choices[0].Message.Content != "你好" {
		t.Fatalf("内容没回形: %s", raw)
	}
	if chat.Choices[0].Message.ReasoningContent != "嗯" {
		t.Fatalf("推理正文没回形到 reasoning_content: %s", raw)
	}
	if chat.Usage == nil || chat.Usage.PromptTokens != 9 || chat.Usage.CompletionTokens != 12 {
		t.Fatalf("usage 没回形: %s", raw)
	}

	// 上游收到的必须是 Messages 形状 + 认证双带 + /v1/messages 路径
	calls := up.Calls()
	if len(calls) != 1 {
		t.Fatalf("上游调用 %d 次", len(calls))
	}
	if calls[0]["path"] != "/v1/messages" {
		t.Fatalf("上游路径应为 /v1/messages，实际 %v", calls[0]["path"])
	}
	if calls[0]["x-api-key"] != "sk-up" || calls[0]["anthropic-version"] == "" {
		t.Fatalf("认证头没带全: %v", calls[0])
	}
	body := calls[0]["body"].(map[string]any)
	if body["max_tokens"] == nil || body["model"] != "m1" {
		t.Fatalf("Messages 请求头字段不对: %v", body)
	}
	if msgs, ok := body["messages"].([]any); !ok || len(msgs) != 1 {
		t.Fatalf("Messages 消息没翻对: %v", body["messages"])
	}
}

// TestAnthropicUpstreamDoubleFlipStream 同一条链的流式：客户端拿 OpenAI chunk
// （含 usage 尾包），记账照常落库。
func TestAnthropicUpstreamDoubleFlipStream(t *testing.T) {
	up := startMockAnthropicUpstream(t, &mockAnthropicUpstream{})
	h := newHarness(t, anthropicUpYAML(up.baseURL))

	resp, raw := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model": "m1", "max_tokens": 32, "stream": true,
		"messages": []map[string]any{{"role": "user", "content": "你好"}},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("状态 %d：%s", resp.StatusCode, raw)
	}
	body := string(raw)
	if !strings.Contains(body, `"content":"你好"`) {
		t.Fatalf("文本增量没回形: %s", body)
	}
	if !strings.Contains(body, `"reasoning_content":"嗯"`) {
		t.Fatalf("推理增量没回形: %s", body)
	}
	if !strings.Contains(body, `"completion_tokens":12`) || !strings.Contains(body, "[DONE]") {
		t.Fatalf("usage 尾包 / [DONE] 缺失: %s", body)
	}

	// 记账：usageScanner 必须从回形后的 OpenAI 流里拿到 usage
	st, err := h.db.Stats(time.Time{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Recent) != 1 || st.Recent[0].TotalTokens == nil || *st.Recent[0].TotalTokens == 0 {
		t.Fatalf("记账没落: %+v", st.Recent)
	}
}

// TestAnthropicUpstreamAnthropicClient 双翻叠加：Anthropic 客户端进、Anthropic 上游出，
// 中间治理核仍是 OpenAI 形状（两头的 thinking 都要活下来）。
func TestAnthropicUpstreamAnthropicClient(t *testing.T) {
	up := startMockAnthropicUpstream(t, &mockAnthropicUpstream{})
	h := newHarness(t, anthropicUpYAML(up.baseURL))

	resp, raw := h.post(t, "/v1/messages", "sk-local", map[string]any{
		"model": "m1", "max_tokens": 32,
		"messages": []map[string]any{{"role": "user", "content": "你好"}},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("状态 %d：%s", resp.StatusCode, raw)
	}
	var out struct {
		Type    string `json:"type"`
		Content []struct {
			Type     string `json:"type"`
			Text     string `json:"text"`
			Thinking string `json:"thinking"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("响应不是 Messages 形状: %v\n%s", err, raw)
	}
	if len(out.Content) != 2 || out.Content[0].Type != "thinking" || out.Content[0].Thinking != "嗯" {
		t.Fatalf("thinking 块没活过两趟翻转: %s", raw)
	}
	if out.Content[1].Type != "text" || out.Content[1].Text != "你好" {
		t.Fatalf("text 块不对: %s", raw)
	}
	if out.Usage.InputTokens != 9 || out.Usage.OutputTokens != 12 {
		t.Fatalf("usage 不对: %s", raw)
	}
}

// TestAnthropicUpstreamErrorShape 上游失败由网关的错误分类接管（不透传上游原文），
// 两种客户端各自拿到自己的信封形状 —— 翻译层只换信封不改判词。
func TestAnthropicUpstreamErrorShape(t *testing.T) {
	up := startMockAnthropicUpstream(t, &mockAnthropicUpstream{failMode: true})
	h := newHarness(t, anthropicUpYAML(up.baseURL))

	// OpenAI 客户端：{"error":{...}}
	resp, raw := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
		"model": "m1", "max_tokens": 8,
		"messages": []map[string]any{{"role": "user", "content": "x"}},
	})
	if resp.StatusCode != 403 {
		t.Fatalf("状态应透传 403: %d", resp.StatusCode)
	}
	var oe struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &oe); err != nil || oe.Error.Type != "upstream_unavailable" || !strings.Contains(oe.Error.Message, "403") {
		t.Fatalf("OpenAI 侧错误形状不对: %s", raw)
	}

	// Anthropic 客户端：{"type":"error","error":{...}}
	resp, raw = h.post(t, "/v1/messages", "sk-local", map[string]any{
		"model": "m1", "max_tokens": 8,
		"messages": []map[string]any{{"role": "user", "content": "x"}},
	})
	if resp.StatusCode != 403 {
		t.Fatalf("状态应透传 403: %d", resp.StatusCode)
	}
	var ae struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &ae); err != nil || ae.Type != "error" || !strings.Contains(ae.Error.Message, "403") {
		t.Fatalf("Anthropic 侧错误形状不对: %s", raw)
	}
}
