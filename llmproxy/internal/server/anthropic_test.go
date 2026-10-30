package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// anthropicBody 是 /v1/messages 的最小合法请求。
func anthropicBody(stream bool) map[string]any {
	b := map[string]any{
		"model":      "m1",
		"max_tokens": 64,
		"system":     "你是助手",
		"messages":   []map[string]any{{"role": "user", "content": "你好"}},
	}
	if stream {
		b["stream"] = true
	}
	return b
}

func TestAnthropicMessagesNonStream(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))

	resp, raw := h.post(t, "/v1/messages", "sk-local", anthropicBody(false))
	if resp.StatusCode != 200 {
		t.Fatalf("状态 %d：%s", resp.StatusCode, raw)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("响应类型不对: %s", ct)
	}

	var out struct {
		Type    string `json:"type"`
		Role    string `json:"role"`
		Model   string `json:"model"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("响应不是合法 JSON: %v\n%s", err, raw)
	}
	if out.Type != "message" || out.Role != "assistant" {
		t.Fatalf("信封不对: %s", raw)
	}
	if len(out.Content) != 1 || out.Content[0].Type != "text" ||
		!strings.Contains(out.Content[0].Text, "pong from a") {
		t.Fatalf("内容块不对: %s", raw)
	}
	if out.StopReason != "end_turn" {
		t.Fatalf("stop_reason 不对: %s", out.StopReason)
	}
	// mock 上游回 prompt=5 / completion=7
	if out.Usage.InputTokens != 5 || out.Usage.OutputTokens != 7 {
		t.Fatalf("usage 没映射对: %+v", out.Usage)
	}

	// 上游收到的必须是 OpenAI 形状（system + user 两条消息）
	calls := up.Calls()
	if len(calls) != 1 {
		t.Fatalf("上游调用次数 %d", len(calls))
	}
	msgs, _ := calls[0].Body["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("内部消息数不对: %v", calls[0].Body["messages"])
	}
	// base_url 带 /v1，转发时拼的是去掉 /v1 前缀的路径（与 OpenAI 入口同一口径）
	if calls[0].Path != "/chat/completions" {
		t.Fatalf("上游路径不对: %s", calls[0].Path)
	}
	if calls[0].Auth != "Bearer sk-a" {
		t.Fatalf("上游鉴权没带运营者密钥: %q", calls[0].Auth)
	}
}

func TestAnthropicMessagesStream(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))

	resp, raw := h.post(t, "/v1/messages", "sk-local", anthropicBody(true))
	if resp.StatusCode != 200 {
		t.Fatalf("状态 %d：%s", resp.StatusCode, raw)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("流式响应类型不对: %s", ct)
	}
	body := string(raw)
	var events []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "event: ") {
			events = append(events, strings.TrimPrefix(line, "event: "))
		}
	}
	joined := strings.Join(events, ",")
	// mock 上游不发 finish_reason（只有两个 content 片段 + usage 尾包），收尾靠 Close 兜底
	for _, want := range []string{"message_start", "content_block_start", "content_block_delta", "content_block_stop", "message_delta", "message_stop"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("缺事件 %s：%v\n%s", want, events, body)
		}
	}
	if !strings.Contains(body, `"text":"Hello"`) || !strings.Contains(body, `"text":" world"`) {
		t.Fatalf("文本增量没翻过去: %s", body)
	}
	// mock 上游 usage prompt=11 / completion=22 —— 空 choices 尾包形态
	if !strings.Contains(body, `"output_tokens":22`) {
		t.Fatalf("message_delta 应带 usage 真值: %s", body)
	}
	// 帧结构：每帧 event + data 两行
	for _, block := range strings.Split(strings.TrimSpace(body), "\n\n") {
		lines := strings.Split(block, "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[0], "event: ") || !strings.HasPrefix(lines[1], "data: ") {
			t.Fatalf("SSE 帧结构不对: %q", block)
		}
	}
}

func TestAnthropicMessagesUpstreamError(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a", failStatus: 500, failTimes: -1})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))

	resp, raw := h.post(t, "/v1/messages", "sk-local", anthropicBody(false))
	if resp.StatusCode != 500 {
		t.Fatalf("上游 500 应透传状态: %d", resp.StatusCode)
	}
	var out struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("错误体不是合法 JSON: %v\n%s", err, raw)
	}
	// 上游失败由网关的错误分类接管（不透传上游原文），翻译层保住它的类型与文案
	if out.Type != "error" || out.Error.Type != "upstream_unavailable" || !strings.Contains(out.Error.Message, "500") {
		t.Fatalf("错误形状不对: %s", raw)
	}
}

func TestAnthropicMessagesValidationAndAuth(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))

	// 鉴权与 OpenAI 入口同一套
	resp, _ := h.post(t, "/v1/messages", "", anthropicBody(false))
	if resp.StatusCode != 401 {
		t.Fatalf("无鉴权应 401, got %d", resp.StatusCode)
	}

	// 缺 max_tokens → 400 + Anthropic 错误形状
	resp, raw := h.post(t, "/v1/messages", "sk-local", map[string]any{
		"model":    "m1",
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != 400 {
		t.Fatalf("缺 max_tokens 应 400, got %d：%s", resp.StatusCode, raw)
	}
	if !bytes.Contains(raw, []byte(`"type":"error"`)) || !bytes.Contains(raw, []byte("max_tokens")) {
		t.Fatalf("校验错误形状不对: %s", raw)
	}
}

func TestAnthropicCountTokens(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))

	// count_tokens 不带 max_tokens 也必须过
	resp, raw := h.post(t, "/v1/messages/count_tokens", "sk-local", map[string]any{
		"model":    "m1",
		"messages": []map[string]any{{"role": "user", "content": "一二三四五六七八"}},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("count_tokens = %d：%s", resp.StatusCode, raw)
	}
	var out map[string]int
	if err := json.Unmarshal(raw, &out); err != nil || out["input_tokens"] <= 0 {
		t.Fatalf("count_tokens 响应不对: %s", raw)
	}
	if up.Count() != 0 {
		t.Fatalf("count_tokens 不该打上游，实际 %d 次", up.Count())
	}
}

func TestAnthropicThinkingNonStream(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a", reasoning: true})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))

	body := anthropicBody(false)
	body["thinking"] = map[string]any{"type": "enabled", "budget_tokens": 1024}
	resp, raw := h.post(t, "/v1/messages", "sk-local", body)
	if resp.StatusCode != 200 {
		t.Fatalf("状态 %d：%s", resp.StatusCode, raw)
	}
	var out struct {
		Content []struct {
			Type     string `json:"type"`
			Text     string `json:"text"`
			Thinking string `json:"thinking"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("响应解析失败: %v\n%s", err, raw)
	}
	if len(out.Content) != 2 || out.Content[0].Type != "thinking" || !strings.Contains(out.Content[0].Thinking, "先想想") {
		t.Fatalf("thinking 块应在最前: %s", raw)
	}
	if out.Content[1].Type != "text" {
		t.Fatalf("text 块应跟在后面: %s", raw)
	}
	// 预算 1024 → 上游收到 reasoning_effort=low
	if eff, _ := up.Calls()[0].Body["reasoning_effort"].(string); eff != "low" {
		t.Fatalf("reasoning_effort 应为 low，上游收到 %q", eff)
	}
}

func TestAnthropicThinkingStream(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a", reasoning: true})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))

	body := anthropicBody(true)
	body["thinking"] = map[string]any{"type": "enabled", "budget_tokens": 20000}
	resp, raw := h.post(t, "/v1/messages", "sk-local", body)
	if resp.StatusCode != 200 {
		t.Fatalf("状态 %d：%s", resp.StatusCode, raw)
	}
	b := string(raw)
	if !strings.Contains(b, `"type":"thinking"`) || !strings.Contains(b, `"type":"thinking_delta"`) {
		t.Fatalf("流里缺 thinking 事件: %s", b)
	}
	// 事件序：thinking 块要完整闭合再开 text 块
	start := strings.Index(b, `"type":"thinking"`)
	stop := strings.Index(b, "event: content_block_stop")
	text := strings.Index(b, `"type":"text"`)
	if !(start < stop && stop < text) {
		t.Fatalf("thinking 块生命周期顺序不对:\n%s", b)
	}
	if eff, _ := up.Calls()[0].Body["reasoning_effort"].(string); eff != "medium" {
		t.Fatalf("预算 20000 应映射 medium，上游收到 %q", eff)
	}
}

func TestAnthropicMessagesOpenAIReasoningEffort(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))
	cases := []struct {
		name   string
		fields string
		effort string
	}{
		{"enabled", `{"thinking":{"type":"enabled","budget_tokens":1024}}`, "low"},
		{"disabled", `{"thinking":{"type":"disabled"}}`, "none"},
		{"adaptive_low", `{"thinking":{"type":"adaptive"},"output_config":{"effort":"low"}}`, "low"},
		{"adaptive_medium", `{"thinking":{"type":"adaptive"},"output_config":{"effort":"medium"}}`, "medium"},
		{"adaptive_high", `{"thinking":{"type":"adaptive"},"output_config":{"effort":"high"}}`, "high"},
		{"adaptive_max", `{"thinking":{"type":"adaptive"},"output_config":{"effort":"max"}}`, "xhigh"},
		{"adaptive_xhigh", `{"thinking":{"type":"adaptive"},"output_config":{"effort":"xhigh"}}`, "xhigh"},
		{"adaptive_default", `{"thinking":{"type":"adaptive"}}`, ""},
		{"output_effort_only", `{"output_config":{"effort":"low"}}`, "low"},
		{"absent", `{}`, ""},
	}
	for _, stream := range []bool{false, true} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("stream=%t/%s", stream, tc.name), func(t *testing.T) {
				body := anthropicBody(stream)
				body["max_tokens"] = 65536
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
				if call.Path != "/chat/completions" {
					t.Errorf("上游路径不对: %s", call.Path)
				}
				for _, key := range []string{"thinking", "output_config"} {
					if _, ok := call.Body[key]; ok {
						t.Errorf("OpenAI 上游不应收到 %s: %v", key, call.Body)
					}
				}
				effort, present := call.Body["reasoning_effort"]
				if tc.effort == "" {
					if present {
						t.Errorf("缺省请求不应带 reasoning_effort: %v", effort)
					}
				} else if effort != tc.effort {
					t.Errorf("reasoning_effort = %v，期望 %q", effort, tc.effort)
				}
				if gotStream, _ := call.Body["stream"].(bool); gotStream != stream {
					t.Errorf("上游 stream = %t，期望 %t", gotStream, stream)
				}
			})
		}
	}
}

func TestDetachAnthropicReasoning(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		effort   string
		baseline string
	}{
		{"unchanged", `{"thinking":{"type":"enabled","budget_tokens":12000},"reasoning_effort":"medium"}`, "medium", "medium"},
		{"native_disabled", `{"thinking":{"type":"disabled"},"reasoning_effort":"medium"}`, "none", "none"},
		{"native_effort", `{"thinking":{"type":"adaptive"},"output_config":{"effort":"low"},"reasoning_effort":"medium"}`, "low", "low"},
		{"native_removed", `{"reasoning_effort":"medium"}`, "", ""},
		{"common_overrides_native", `{"thinking":{"type":"enabled","budget_tokens":12000},"reasoning_effort":"none"}`, "none", "medium"},
		{"common_removed", `{"thinking":{"type":"enabled","budget_tokens":12000}}`, "", "medium"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), anthropicReasoningKey{}, anthropicReasoning{effort: "medium"})
			ctx, raw, err := detachAnthropicReasoning(ctx, []byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			var effort string
			if value, ok := fields["reasoning_effort"]; ok {
				if err := json.Unmarshal(value, &effort); err != nil {
					t.Fatal(err)
				}
			}
			if effort != tc.effort {
				t.Fatalf("reasoning_effort=%q，期望 %q", effort, tc.effort)
			}
			for _, key := range []string{"thinking", "output_config"} {
				if _, ok := fields[key]; ok {
					t.Errorf("OpenAI 正文不应带 %s", key)
				}
			}
			processed := ctx.Value(anthropicReasoningKey{}).(anthropicReasoning)
			if processed.effort != tc.baseline {
				t.Errorf("处理后的基线=%q，期望 %q", processed.effort, tc.baseline)
			}
		})
	}
	for _, raw := range []string{`null`, `[]`, `{`, `{"thinking":"invalid"}`, `{"reasoning_effort":1}`} {
		ctx := context.WithValue(context.Background(), anthropicReasoningKey{}, anthropicReasoning{})
		if _, _, err := detachAnthropicReasoning(ctx, []byte(raw)); err == nil {
			t.Errorf("处理后非法正文应拒绝: %s", raw)
		}
	}
}

// TestAnthropicStreamKeepsBilling 证明翻译只动出口：上游 usage 记账照常落库。
func TestAnthropicStreamKeepsBilling(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))

	resp, raw := h.post(t, "/v1/messages", "sk-local", anthropicBody(true))
	if resp.StatusCode != 200 {
		t.Fatalf("状态 %d：%s", resp.StatusCode, raw)
	}
	reqs, err := h.db.Stats(time.Time{}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs.Recent) != 1 {
		t.Fatalf("requests 应有 1 行，实际 %d", len(reqs.Recent))
	}
	rec := reqs.Recent[0]
	if rec.TotalTokens == nil || *rec.TotalTokens == 0 {
		t.Fatalf("记账 token 为 0 —— usageScanner 应拿到上游 usage: %+v", rec)
	}
	if !rec.Stream {
		t.Fatalf("流式标记没落对: %+v", rec)
	}
}
