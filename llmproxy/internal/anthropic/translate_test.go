package anthropic

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func mustReq(t *testing.T, body string) *Request {
	t.Helper()
	var r Request
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("请求体解析失败: %v", err)
	}
	return &r
}

func TestToChatBasicText(t *testing.T) {
	req := mustReq(t, `{
		"model": "claude-sonnet-4-5", "max_tokens": 128,
		"system": "你是助手",
		"messages": [{"role": "user", "content": "你好"}],
		"temperature": 0.5, "top_p": 0.9, "top_k": 40,
		"stop_sequences": ["END"], "stream": true
	}`)
	chat, est, err := ToChat(req)
	if err != nil {
		t.Fatal(err)
	}
	if chat.Model != "claude-sonnet-4-5" || chat.MaxTokens != 128 {
		t.Fatalf("model/max_tokens 没带上: %+v", chat)
	}
	if len(chat.Messages) != 2 || chat.Messages[0].Role != "system" || chat.Messages[1].Role != "user" {
		t.Fatalf("消息结构不对: %+v", chat.Messages)
	}
	if chat.Messages[0].Content != "你是助手" || chat.Messages[1].Content != "你好" {
		t.Fatalf("内容没翻对: %+v", chat.Messages)
	}
	if len(chat.Stop) != 1 || chat.Stop[0] != "END" || !chat.Stream {
		t.Fatalf("stop/stream 没翻对: %+v", chat)
	}
	if est <= 0 {
		t.Fatalf("估算 token 应为正，拿到 %d", est)
	}
	// top_k 没有对应物，不该出现在内部形状里
	if strings.Contains(mustJSON(t, chat), "top_k") {
		t.Fatal("top_k 不该被带进内部请求")
	}
}

func TestToChatBlocksToolsAndToolResults(t *testing.T) {
	req := mustReq(t, `{
		"model": "m", "max_tokens": 10,
		"messages": [
			{"role": "user", "content": [{"type": "text", "text": "查天气"}]},
			{"role": "assistant", "content": [
				{"type": "text", "text": "我来查"},
				{"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"city": "北京"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "toolu_1", "result": [{"type": "text", "text": "晴"}]}
			]}
		],
		"tools": [{"name": "get_weather", "description": "查天气", "input_schema": {"type": "object"}}],
		"tool_choice": {"type": "tool", "name": "get_weather"}
	}`)
	chat, _, err := ToChat(req)
	if err != nil {
		t.Fatal(err)
	}
	// system 没有；user 文本 1 条 + assistant(带 tool_calls) 1 条 + tool 结果 1 条
	if len(chat.Messages) != 3 {
		t.Fatalf("应有 3 条内部消息，实际 %d: %+v", len(chat.Messages), chat.Messages)
	}
	asst := chat.Messages[1]
	if asst.Role != "assistant" || len(asst.ToolCalls) != 1 {
		t.Fatalf("assistant 的 tool_calls 没翻对: %+v", asst)
	}
	if asst.ToolCalls[0].ID != "toolu_1" || asst.ToolCalls[0].Function.Name != "get_weather" {
		t.Fatalf("工具调用字段不对: %+v", asst.ToolCalls[0])
	}
	var args map[string]any
	if err := json.Unmarshal([]byte(asst.ToolCalls[0].Function.Arguments), &args); err != nil || args["city"] != "北京" {
		t.Fatalf("input 没翻成 arguments 字符串: %q", asst.ToolCalls[0].Function.Arguments)
	}
	toolMsg := chat.Messages[2]
	if toolMsg.Role != "tool" || toolMsg.ToolCallID != "toolu_1" || toolMsg.Content != "晴" {
		t.Fatalf("tool_result 没翻成 tool 消息: %+v", toolMsg)
	}
	if len(chat.Tools) != 1 || chat.Tools[0].Function.Name != "get_weather" {
		t.Fatalf("tools 没翻对: %+v", chat.Tools)
	}
	tc, ok := chat.ToolChoice.(map[string]any)
	if !ok || tc["type"] != "function" {
		t.Fatalf("tool_choice 点名没翻对: %#v", chat.ToolChoice)
	}
}

func TestToChatToolChoiceAliases(t *testing.T) {
	for _, tc := range []struct {
		body string
		want string
	}{
		{`"auto"`, "auto"},
		{`"none"`, "none"},
		{`"required"`, "required"},
	} {
		// Anthropic 侧的 auto/any/none
		anth := map[string]string{"auto": "auto", "none": "none", "required": "any"}[tc.want]
		req := mustReq(t, `{
			"model": "m", "max_tokens": 1,
			"messages": [{"role": "user", "content": "x"}],
			"tool_choice": {"type": "`+anth+`"}
		}`)
		chat, _, err := ToChat(req)
		if err != nil {
			t.Fatal(err)
		}
		if chat.ToolChoice != tc.want {
			t.Fatalf("tool_choice %s → %#v，想要 %s", anth, chat.ToolChoice, tc.want)
		}
	}
}

func TestToChatValidation(t *testing.T) {
	cases := []string{
		`{"max_tokens": 1, "messages": [{"role":"user","content":"x"}]}`,                 // 缺 model
		`{"model": "m", "max_tokens": 1}`,                                                // 缺 messages
		`{"model": "m", "max_tokens": 1, "messages": [{"role":"system","content":"x"}]}`, // role 越界
	}
	for _, body := range cases {
		if _, _, err := ToChat(mustReq(t, body)); err == nil {
			t.Fatalf("应报错的请求过了: %s", body)
		}
	}
}

func TestFromChatTextAndTools(t *testing.T) {
	resp := &ChatResponse{ID: "x", Model: "up-model"}
	var ch struct {
		Index   int `json:"index"`
		Message struct {
			Role             string         `json:"role"`
			Content          string         `json:"content"`
			ReasoningContent string         `json:"reasoning_content"`
			Reasoning        string         `json:"reasoning"`
			ToolCalls        []ChatToolCall `json:"tool_calls,omitempty"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	}
	ch.Message.Role = "assistant"
	ch.Message.Content = "答案"
	ch.FinishReason = "tool_calls"
	tc := ChatToolCall{ID: "toolu_9", Type: "function"}
	tc.Function.Name = "f"
	tc.Function.Arguments = `{"a":1}`
	ch.Message.ToolCalls = []ChatToolCall{tc}
	resp.Choices = append(resp.Choices, ch)
	resp.Usage = &ChatUsage{PromptTokens: 11, CompletionTokens: 22}

	out, err := FromChat(resp, "fallback")
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != "message" || out.Role != "assistant" || out.Model != "up-model" {
		t.Fatalf("头字段不对: %+v", out)
	}
	if len(out.Content) != 2 || out.Content[0].Type != "text" || out.Content[1].Type != "tool_use" {
		t.Fatalf("内容块不对: %+v", out.Content)
	}
	if out.Content[1].ID != "toolu_9" || string(out.Content[1].Input) != `{"a":1}` {
		t.Fatalf("tool_use 块不对: %+v", out.Content[1])
	}
	if out.StopReason != "tool_use" {
		t.Fatalf("stop_reason: %s", out.StopReason)
	}
	if out.Usage.InputTokens != 11 || out.Usage.OutputTokens != 22 {
		t.Fatalf("usage 不对: %+v", out.Usage)
	}
}

func TestToChatThinkingMapping(t *testing.T) {
	cases := []struct {
		budget int
		want   string
	}{
		{0, "medium"},    // 不带预算按 medium
		{1024, "low"},    // <8192
		{8192, "medium"}, // <24576
		{24576, "high"},  // 之上
	}
	for _, tc := range cases {
		req := mustReq(t, `{"model":"m","max_tokens":1,
			"messages":[{"role":"user","content":"x"}],
			"thinking":{"type":"enabled","budget_tokens":`+itoa(tc.budget)+`}}`)
		chat, _, err := ToChat(req)
		if err != nil {
			t.Fatal(err)
		}
		if chat.ReasoningEffort != tc.want {
			t.Fatalf("budget=%d → %q，想要 %q", tc.budget, chat.ReasoningEffort, tc.want)
		}
	}
	// disabled 与缺省都不写这个字段
	for _, src := range []string{
		`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"x"}],"thinking":{"type":"disabled"}}`,
		`{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"x"}]}`,
	} {
		req := mustReq(t, src)
		chat, _, err := ToChat(req)
		if err != nil {
			t.Fatal(err)
		}
		if chat.ReasoningEffort != "" {
			t.Fatalf("%s 时不该带 reasoning_effort，拿到 %q", src, chat.ReasoningEffort)
		}
	}
}

func TestFromChatThinkingBlock(t *testing.T) {
	resp := &ChatResponse{Model: "up"}
	var ch struct {
		Index   int `json:"index"`
		Message struct {
			Role             string         `json:"role"`
			Content          string         `json:"content"`
			ReasoningContent string         `json:"reasoning_content"`
			Reasoning        string         `json:"reasoning"`
			ToolCalls        []ChatToolCall `json:"tool_calls,omitempty"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	}
	ch.Message.Role = "assistant"
	ch.Message.ReasoningContent = "先想想"
	ch.Message.Content = "答案"
	ch.FinishReason = "stop"
	resp.Choices = append(resp.Choices, ch)

	out, err := FromChat(resp, "fallback")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Content) != 2 || out.Content[0].Type != "thinking" || out.Content[0].Thinking != "先想想" {
		t.Fatalf("thinking 块应在最前: %+v", out.Content)
	}
	if out.Content[1].Type != "text" || out.Content[1].Text != "答案" {
		t.Fatalf("text 块不对: %+v", out.Content[1])
	}
}

func TestStopReasonMapping(t *testing.T) {
	cases := map[string]string{
		"stop":           "end_turn",
		"length":         "max_tokens",
		"tool_calls":     "tool_use",
		"function_call":  "tool_use",
		"content_filter": "end_turn",
		"":               "end_turn",
		"weird":          "end_turn",
	}
	for in, want := range cases {
		if got := stopReason(in, false); got != want {
			t.Fatalf("stopReason(%q) = %s，想要 %s", in, got, want)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
