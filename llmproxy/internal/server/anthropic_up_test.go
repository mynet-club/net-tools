package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/processor"
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
    max_data_level: internal
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

func TestAnthropicUpstreamPreservesThinkingConfig(t *testing.T) {
	up := startMockAnthropicUpstream(t, &mockAnthropicUpstream{})
	h := newHarness(t, anthropicUpYAML(up.baseURL))
	cases := []struct {
		name   string
		fields string
	}{
		{"budget_1024", `{"thinking":{"type":"enabled","budget_tokens":1024}}`},
		{"budget_12000", `{"thinking":{"type":"enabled","budget_tokens":12000}}`},
		{"budget_50000", `{"thinking":{"type":"enabled","budget_tokens":50000}}`},
		{"disabled", `{"thinking":{"type":"disabled"}}`},
		{"adaptive_low", `{"thinking":{"type":"adaptive"},"output_config":{"effort":"low"}}`},
		{"adaptive_medium", `{"thinking":{"type":"adaptive"},"output_config":{"effort":"medium"}}`},
		{"adaptive_high", `{"thinking":{"type":"adaptive"},"output_config":{"effort":"high"}}`},
		{"adaptive_max", `{"thinking":{"type":"adaptive"},"output_config":{"effort":"max"}}`},
		{"adaptive_xhigh", `{"thinking":{"type":"adaptive"},"output_config":{"effort":"xhigh"}}`},
		{"adaptive_default", `{"thinking":{"type":"adaptive"}}`},
		{"thinking_display", `{"thinking":{"type":"enabled","budget_tokens":1024,"display":"omitted"}}`},
		{"output_format", `{"thinking":{"type":"adaptive"},"output_config":{"effort":"high","format":{"type":"json_schema","schema":{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"],"additionalProperties":false}}}}`},
		{"output_effort_only", `{"output_config":{"effort":"low"}}`},
		{"absent", `{}`},
		{"thinking_null", `{"thinking":null}`},
		{"output_config_null", `{"output_config":null}`},
		{"both_null", `{"thinking":null,"output_config":null}`},
		{"enabled_output_null", `{"thinking":{"type":"enabled","budget_tokens":12000},"output_config":null}`},
	}
	for _, stream := range []bool{false, true} {
		for i, tc := range cases {
			t.Run(fmt.Sprintf("stream=%t/%s", stream, tc.name), func(t *testing.T) {
				body := anthropicBody(stream)
				body["model"] = fmt.Sprintf("m%d", i+1)
				body["max_tokens"] = float64(65536 + i)
				if err := json.Unmarshal([]byte(tc.fields), &body); err != nil {
					t.Fatal(err)
				}
				wantCalls := len(up.Calls()) + 1
				resp, raw := h.post(t, "/v1/messages", "sk-local", body)
				if resp.StatusCode != 200 {
					t.Fatalf("状态 %d：%s", resp.StatusCode, raw)
				}
				wantType := "application/json"
				if stream {
					wantType = "text/event-stream"
				}
				if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, wantType) {
					t.Errorf("响应类型 %q，期望 %q", ct, wantType)
				}
				calls := up.Calls()
				if len(calls) != wantCalls {
					t.Fatalf("上游调用次数 %d，期望 %d", len(calls), wantCalls)
				}
				call := calls[len(calls)-1]
				if call["path"] != "/v1/messages" {
					t.Errorf("上游路径不对: %v", call["path"])
				}
				got := call["body"].(map[string]any)
				for _, key := range []string{"thinking", "output_config", "max_tokens", "model"} {
					wantValue, wantPresent := body[key]
					gotValue, gotPresent := got[key]
					if gotPresent != wantPresent || !reflect.DeepEqual(gotValue, wantValue) {
						t.Errorf("%s = %#v（存在 %t），期望 %#v（存在 %t）", key, gotValue, gotPresent, wantValue, wantPresent)
					}
				}
				if _, ok := got["reasoning_effort"]; ok {
					t.Errorf("Anthropic 上游不应收到 reasoning_effort: %v", got)
				}
				if gotStream, _ := got["stream"].(bool); gotStream != stream {
					t.Errorf("上游 stream = %t，期望 %t", gotStream, stream)
				}
			})
		}
	}
}

func TestAnthropicUpstreamNativeConfigRespectsProcessors(t *testing.T) {
	cases := []struct {
		name         string
		effort       string
		hasPII       bool
		wantThinking map[string]any
	}{
		{"effort_none", "none", false, map[string]any{"type": "disabled"}},
		{"effort_low", "low", false, map[string]any{"type": "enabled", "budget_tokens": float64(4096)}},
		{"pii_format", "", true, map[string]any{"type": "enabled", "budget_tokens": float64(12000)}},
		{"effort_none_and_pii", "none", true, map[string]any{"type": "disabled"}},
	}
	for _, stream := range []bool{false, true} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("stream=%t/%s", stream, tc.name), func(t *testing.T) {
				up := startMockAnthropicUpstream(t, &mockAnthropicUpstream{})
				src := anthropicUpYAML(up.baseURL) + policySection("enforce", "t-open", "system:gateway", 1) + "processors:\n"
				if tc.effort != "" {
					src += procDecl("effort", processor.TypeFieldReplace, "before-upstream", "transform-body", nil)
				}
				if tc.hasPII {
					src += procDecl("pii", processor.TypePIIMask, "before-upstream", "transform-body", nil)
				}
				h := newHarness(t, src)
				writePolicyBundle(t, h, policyBundleOpen)
				if tc.effort != "" {
					writeProcParam(t, h, "effort", fmt.Sprintf(`{"rules":[{"name":"effort","path":"reasoning_effort","mapping":{"medium":%q}}]}`, tc.effort))
				}
				body := anthropicBody(stream)
				body["max_tokens"] = 65536
				body["thinking"] = map[string]any{"type": "enabled", "budget_tokens": 12000}
				wantFormat := map[string]any{
					"type": "json_schema",
					"schema": map[string]any{
						"type": "object", "description": "联系 someone@example.com",
						"properties": map[string]any{"answer": map[string]any{"type": "string"}},
					},
				}
				if tc.hasPII {
					body["output_config"] = map[string]any{"effort": "medium", "format": wantFormat}
				}
				resp, raw := h.post(t, "/v1/messages", "sk-local", body)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("状态 %d：%s", resp.StatusCode, raw)
				}
				if got := resp.Header.Get("X-Llmproxy-Body-Pipeline"); got != "buffered" {
					t.Errorf("请求应经过正文处理链，实际头=%q", got)
				}
				wantType := "application/json"
				if stream {
					wantType = "text/event-stream"
				}
				if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, wantType) {
					t.Errorf("响应类型 %q，期望 %q", ct, wantType)
				}
				calls := up.Calls()
				if len(calls) != 1 {
					t.Fatalf("上游调用 %d 次，期望 1 次", len(calls))
				}
				if calls[0]["path"] != "/v1/messages" {
					t.Errorf("上游路径不对: %v", calls[0]["path"])
				}
				got := calls[0]["body"].(map[string]any)
				if !reflect.DeepEqual(got["thinking"], tc.wantThinking) {
					t.Errorf("thinking = %#v，期望 %#v", got["thinking"], tc.wantThinking)
				}
				if _, ok := got["reasoning_effort"]; ok {
					t.Errorf("Anthropic 上游不应收到 reasoning_effort: %v", got)
				}
				if gotStream, _ := got["stream"].(bool); gotStream != stream {
					t.Errorf("上游 stream = %t，期望 %t", gotStream, stream)
				}
				if !tc.hasPII {
					if _, ok := got["output_config"]; ok {
						t.Errorf("无原生 output_config 时不应新增: %v", got["output_config"])
					}
					return
				}
				output, ok := got["output_config"].(map[string]any)
				if !ok {
					t.Fatalf("output_config 丢失: %v", got)
				}
				if tc.effort != "" {
					if _, ok := output["effort"]; ok {
						t.Errorf("处理器改写推理后不应恢复原生 effort: %v", output)
					}
				} else if output["effort"] != "medium" {
					t.Errorf("仅脱敏不应丢失原生 effort: %v", output)
				}
				format, _ := output["format"].(map[string]any)
				schema, _ := format["schema"].(map[string]any)
				description, _ := schema["description"].(string)
				if strings.Contains(description, "someone@example.com") || !strings.HasPrefix(description, "联系 <masked:email:") {
					t.Errorf("schema.description 未正确脱敏: %q", description)
				}
				wantFormat["schema"].(map[string]any)["description"] = description
				if !reflect.DeepEqual(format, wantFormat) {
					t.Errorf("脱敏后 format 结构不应丢失: %#v", format)
				}
			})
		}
	}
}

func TestAnthropicUpstreamChatReasoningEffort(t *testing.T) {
	up := startMockAnthropicUpstream(t, &mockAnthropicUpstream{})
	h := newHarness(t, anthropicUpYAML(up.baseURL))
	cases := []struct {
		effort string
		want   map[string]any
	}{
		{"none", map[string]any{"type": "disabled"}},
		{"low", map[string]any{"type": "enabled", "budget_tokens": float64(4096)}},
		{"medium", map[string]any{"type": "enabled", "budget_tokens": float64(16384)}},
		{"high", map[string]any{"type": "enabled", "budget_tokens": float64(32768)}},
	}
	for _, stream := range []bool{false, true} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("stream=%t/%s", stream, tc.effort), func(t *testing.T) {
				wantCalls := len(up.Calls()) + 1
				resp, raw := h.post(t, "/v1/chat/completions", "sk-local", map[string]any{
					"model": "m1", "max_tokens": 65536, "stream": stream,
					"reasoning_effort": tc.effort,
					"messages":         []map[string]any{{"role": "user", "content": "你好"}},
				})
				if resp.StatusCode != 200 {
					t.Fatalf("状态 %d：%s", resp.StatusCode, raw)
				}
				calls := up.Calls()
				if len(calls) != wantCalls {
					t.Fatalf("上游调用次数 %d，期望 %d", len(calls), wantCalls)
				}
				body := calls[len(calls)-1]["body"].(map[string]any)
				if !reflect.DeepEqual(body["thinking"], tc.want) {
					t.Errorf("thinking = %#v，期望 %#v", body["thinking"], tc.want)
				}
				for _, key := range []string{"reasoning_effort", "output_config"} {
					if _, ok := body[key]; ok {
						t.Errorf("上游不应收到 %s: %v", key, body)
					}
				}
			})
		}
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
