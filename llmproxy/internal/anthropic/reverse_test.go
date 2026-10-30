package anthropic

import (
	"encoding/json"
	"testing"
)

func TestToMessagesShapes(t *testing.T) {
	chat := &ChatRequest{
		Model:           "up-m",
		MaxTokens:       256,
		Temperature:     ptrF(0.7),
		Stop:            []string{"END"},
		Stream:          true,
		ReasoningEffort: "low",
		Messages: []ChatMessage{
			{Role: "system", Content: "你是助手"},
			{Role: "user", Content: "查天气"},
			{Role: "assistant", Content: "我来查"},
			func() ChatMessage {
				m := ChatMessage{Role: "assistant"}
				var tc ChatToolCall
				tc.ID = "toolu_1"
				tc.Type = "function"
				tc.Function.Name = "get_weather"
				tc.Function.Arguments = `{"city":"北京"}`
				m.ToolCalls = []ChatToolCall{tc}
				return m
			}(),
			{Role: "tool", ToolCallID: "toolu_1", Content: "晴"},
			{Role: "tool", ToolCallID: "toolu_2", Content: "阴"},
		},
		Tools: []ChatTool{{
			Type:     "function",
			Function: ChatFunction{Name: "get_weather", Description: "查天气", Parameters: json.RawMessage(`{"type":"object"}`)},
		}},
		ToolChoice: map[string]any{"type": "function", "function": map[string]string{"name": "get_weather"}},
	}

	req, err := ToMessages(chat)
	if err != nil {
		t.Fatal(err)
	}
	if req.Model != "up-m" || req.MaxTokens != 256 || !req.Stream {
		t.Fatalf("头字段不对: %+v", req)
	}
	if len(req.StopSequences) != 1 || req.StopSequences[0] != "END" {
		t.Fatalf("stop 没翻对: %+v", req.StopSequences)
	}
	if req.Thinking == nil || req.Thinking.Type != "enabled" || req.Thinking.BudgetTokens != 4096 {
		t.Fatalf("reasoning_effort=low 应翻回预算 4096: %+v", req.Thinking)
	}
	if len(req.System) == 0 {
		t.Fatal("system 丢了")
	}
	// messages：system 单出；user 文本轮；assistant 文本轮；assistant 工具轮；
	// 两条 tool 结果并进同一个 user 轮（Anthropic 的 tool_result 语义）
	if len(req.Messages) != 4 {
		t.Fatalf("应有 4 条 messages（两条 tool 结果并轮），实际 %d: %+v", len(req.Messages), req.Messages)
	}
	if req.Messages[3].Role != "user" {
		t.Fatalf("tool 结果应落在 user 轮: %+v", req.Messages[3])
	}
	blocks, err := parseContent(req.Messages[3].Content)
	if err != nil || len(blocks) != 2 || blocks[0].Type != "tool_result" || blocks[1].ToolUseID != "toolu_2" {
		t.Fatalf("tool_result 块不对: %+v (err=%v)", blocks, err)
	}
	// assistant 工具轮
	ablocks, _ := parseContent(req.Messages[2].Content)
	if len(ablocks) != 1 || ablocks[0].Type != "tool_use" || ablocks[0].Name != "get_weather" {
		t.Fatalf("tool_use 块不对: %+v", ablocks)
	}
	if req.ToolChoice == nil || req.ToolChoice.Type != "tool" || req.ToolChoice.Name != "get_weather" {
		t.Fatalf("tool_choice 点名没翻回: %+v", req.ToolChoice)
	}
	if len(req.Tools) != 1 || req.Tools[0].Name != "get_weather" {
		t.Fatalf("tools 没翻回: %+v", req.Tools)
	}
}

func TestToMessagesThinkingMapping(t *testing.T) {
	for _, tc := range []struct {
		effort string
		kind   string
		budget int
	}{
		{"", "", 0},
		{"none", "disabled", 0},
		{"low", "enabled", 4096},
		{"medium", "enabled", 16384},
		{"high", "enabled", 32768},
	} {
		t.Run(tc.effort, func(t *testing.T) {
			req, err := ToMessages(&ChatRequest{
				Model: "m", MaxTokens: 65536,
				Messages:        []ChatMessage{{Role: "user", Content: "x"}},
				ReasoningEffort: tc.effort,
			})
			if err != nil {
				t.Fatal(err)
			}
			if tc.kind == "" {
				if req.Thinking != nil {
					t.Fatalf("缺省强度不应启用 thinking: %+v", req.Thinking)
				}
				return
			}
			if req.Thinking == nil || req.Thinking.Type != tc.kind || req.Thinking.BudgetTokens != tc.budget {
				t.Fatalf("thinking = %+v，想要 type=%s budget=%d", req.Thinking, tc.kind, tc.budget)
			}
		})
	}
}

func TestFromMessagesShape(t *testing.T) {
	resp := &Response{
		ID: "msg_1", Model: "up-m",
		Content: []ResponseBlock{
			{Type: "thinking", Thinking: "先想想"},
			{Type: "text", Text: "答案"},
			{Type: "tool_use", ID: "toolu_9", Name: "f", Input: json.RawMessage(`{"a":1}`)},
		},
		StopReason: "tool_use",
		Usage:      Usage{InputTokens: 3, OutputTokens: 4},
	}
	chat, err := FromMessages(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(chat.Choices) != 1 {
		t.Fatalf("choices 数不对: %d", len(chat.Choices))
	}
	ch := chat.Choices[0]
	if ch.Message.ReasoningContent != "先想想" || ch.Message.Content != "答案" {
		t.Fatalf("文本/推理没翻对: %+v", ch.Message)
	}
	if len(ch.Message.ToolCalls) != 1 || ch.Message.ToolCalls[0].ID != "toolu_9" {
		t.Fatalf("tool_calls 没翻对: %+v", ch.Message.ToolCalls)
	}
	if ch.FinishReason != "tool_calls" {
		t.Fatalf("finish_reason: %s", ch.FinishReason)
	}
	if chat.Usage == nil || chat.Usage.PromptTokens != 3 || chat.Usage.CompletionTokens != 4 {
		t.Fatalf("usage 没翻对: %+v", chat.Usage)
	}
}

// TestMessagesChatRoundTrip 证明两次翻转（治理核 → 上游 → 治理核）语义守恒。
func TestMessagesChatRoundTrip(t *testing.T) {
	orig := &ChatRequest{
		Model:     "m",
		MaxTokens: 64,
		Messages: []ChatMessage{
			{Role: "system", Content: "规则"},
			{Role: "user", Content: "问题"},
			{Role: "assistant", Content: "回答"},
		},
	}
	req, err := ToMessages(orig)
	if err != nil {
		t.Fatal(err)
	}
	back, _, err := ToChat(req)
	if err != nil {
		t.Fatal(err)
	}
	if back.Model != orig.Model || back.MaxTokens != orig.MaxTokens {
		t.Fatalf("头字段不守恒: %+v", back)
	}
	if len(back.Messages) != len(orig.Messages) {
		t.Fatalf("消息数不守恒: %+v", back.Messages)
	}
	for i := range orig.Messages {
		if back.Messages[i].Role != orig.Messages[i].Role ||
			back.Messages[i].Content != orig.Messages[i].Content {
			t.Fatalf("第 %d 条不守恒: %+v ≠ %+v", i, back.Messages[i], orig.Messages[i])
		}
	}
}

func TestToMessagesValidation(t *testing.T) {
	if _, err := ToMessages(&ChatRequest{MaxTokens: 1, Messages: []ChatMessage{{Role: "user", Content: "x"}}}); err == nil {
		t.Fatal("缺 model 应报错")
	}
	if _, err := ToMessages(&ChatRequest{Model: "m"}); err == nil {
		t.Fatal("缺 messages 应报错")
	}
	if _, err := ToMessages(&ChatRequest{Model: "m", Messages: []ChatMessage{{Role: "root", Content: "x"}}}); err == nil {
		t.Fatal("role 越界应报错")
	}
}

func TestChatFinishReasonInverse(t *testing.T) {
	cases := map[string]string{
		"end_turn":      "stop",
		"max_tokens":    "length",
		"tool_use":      "tool_calls",
		"stop_sequence": "stop",
		"":              "stop",
		"weird":         "stop",
	}
	for in, want := range cases {
		if got := chatFinishReason(in, false); got != want {
			t.Fatalf("chatFinishReason(%q) = %s，想要 %s", in, got, want)
		}
	}
	if chatFinishReason("", true) != "tool_calls" {
		t.Fatal("无 stop_reason 但有工具调用时应判 tool_calls")
	}
}

func ptrF(f float64) *float64 { return &f }
