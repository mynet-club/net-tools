package anthropic

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// ToChat 把 Anthropic Messages 请求翻成内部 chat/completions 形状。
//
// 一处刻意的丢弃：top_k —— OpenAI 形状没有这个字段也没有等价物，静默丢弃
// （带上去反而会被一些上游判成非法字段）。
//
// OpenAI 没有精确预算字段；这里只生成跨协议强度，原生参数由 HTTP 边缘保留。
//
// 返回的 estimate 是给 message_start / count_tokens 用的输入 token 估算值。
func ToChat(req *Request) (*ChatRequest, int, error) {
	if strings.TrimSpace(req.Model) == "" {
		return nil, 0, fmt.Errorf("缺少 model 字段")
	}
	if len(req.Messages) == 0 {
		return nil, 0, fmt.Errorf("messages 不能为空")
	}

	out := &ChatRequest{
		Model:           req.Model,
		MaxTokens:       req.MaxTokens,
		Temperature:     req.Temperature,
		TopP:            req.TopP,
		Stop:            req.StopSequences,
		Stream:          req.Stream,
		ReasoningEffort: ReasoningEffort(req.Thinking, req.OutputConfig),
	}

	// system → 首条 system 消息
	sysText := flattenContent(req.System, "text")
	if strings.TrimSpace(sysText) != "" {
		out.Messages = append(out.Messages, ChatMessage{Role: "system", Content: sysText})
	}

	est := EstimateText(sysText)
	for i := range req.Messages {
		msgs, e, err := chatMessages(&req.Messages[i])
		if err != nil {
			return nil, 0, fmt.Errorf("messages[%d]: %w", i, err)
		}
		out.Messages = append(out.Messages, msgs...)
		est += e
	}

	// tools → OpenAI function 形状；tool_choice → 对应枚举/点名对象
	for _, t := range req.Tools {
		if strings.TrimSpace(t.Name) == "" {
			return nil, 0, fmt.Errorf("tools 里有缺 name 的项")
		}
		params := t.InputSchema
		if len(params) == 0 {
			params = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		out.Tools = append(out.Tools, ChatTool{
			Type: "function",
			Function: ChatFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  params,
			},
		})
		est += EstimateText(t.Name + t.Description + string(params))
	}
	if req.ToolChoice != nil {
		switch req.ToolChoice.Type {
		case "auto":
			out.ToolChoice = "auto"
		case "none":
			out.ToolChoice = "none"
		case "any":
			out.ToolChoice = "required"
		case "tool":
			if req.ToolChoice.Name == "" {
				return nil, 0, fmt.Errorf("tool_choice.type=tool 时必须带 name")
			}
			out.ToolChoice = map[string]any{
				"type":     "function",
				"function": map[string]string{"name": req.ToolChoice.Name},
			}
		default:
			return nil, 0, fmt.Errorf("tool_choice.type 取值不认：%s", req.ToolChoice.Type)
		}
	}

	return out, est, nil
}

// chatMessages 把一条 Anthropic 消息翻成一条或多条 OpenAI 消息。
// tool_result 块会拆成独立的 role=tool 消息（OpenAI 侧工具结果必须单列一条）。
func chatMessages(m *Message) ([]ChatMessage, int, error) {
	blocks, err := parseContent(m.Content)
	if err != nil {
		return nil, 0, err
	}
	if blocks == nil {
		// 纯字符串 content
		if m.Role != "user" && m.Role != "assistant" {
			return nil, 0, fmt.Errorf("role 只认 user/assistant，收到 %q", m.Role)
		}
		text := unquoteIfJSONString(m.Content)
		return []ChatMessage{{Role: m.Role, Content: text}}, EstimateText(text), nil
	}

	var out []ChatMessage
	var texts []string
	var toolCalls []ChatToolCall
	est := 0
	for _, b := range blocks {
		switch b.Type {
		case "text":
			texts = append(texts, b.Text)
			est += EstimateText(b.Text)
		case "image":
			if b.Source == nil {
				return nil, 0, fmt.Errorf("image 块缺 source")
			}
			est += 1000 // 图片按固定粗估，只影响 message_start 的显示值
		case "tool_use":
			args := string(b.Input)
			if args == "" {
				args = "{}"
			}
			tc := ChatToolCall{ID: b.ID, Type: "function"}
			tc.Function.Name = b.Name
			tc.Function.Arguments = args
			toolCalls = append(toolCalls, tc)
			est += EstimateText(b.Name + args)
		case "tool_result":
			res := flattenContent(b.Result, "text")
			out = append(out, ChatMessage{
				Role:       "tool",
				ToolCallID: b.ToolUseID,
				Content:    res,
			})
			est += EstimateText(res)
		case "thinking":
			// 历史轮的思考正文不进上游：内部是 OpenAI 形状，没有这个字段；
			// 带签名的块也没有可校验的对端。当轮的 thinking 由请求参数决定
			// （见 reasoningEffort），响应侧的推理正文由 FromChat 翻回来。
		default:
			return nil, 0, fmt.Errorf("不认的内容块类型 %q", b.Type)
		}
	}

	if m.Role != "user" && m.Role != "assistant" {
		return nil, 0, fmt.Errorf("role 只认 user/assistant，收到 %q", m.Role)
	}

	// 主消息：text 拼一条；assistant 的 tool_use 挂 tool_calls
	if len(texts) > 0 || len(toolCalls) > 0 {
		msg := ChatMessage{Role: m.Role}
		if len(texts) > 0 {
			msg.Content = strings.Join(texts, "\n\n")
		} else if m.Role == "assistant" {
			// 只有工具调用时 content 置空串（部分上游要求 content 字段存在）
			msg.Content = ""
		}
		msg.ToolCalls = toolCalls
		out = append([]ChatMessage{msg}, out...)
	}
	return out, est, nil
}

func ReasoningEffort(th *Thinking, output *OutputConfig) string {
	if th != nil && th.Type == "disabled" {
		return "none"
	}
	if output != nil && output.Effort != "" {
		if output.Effort == "max" {
			return "xhigh"
		}
		return output.Effort
	}
	if th == nil || th.Type != "enabled" {
		return ""
	}
	switch {
	case th.BudgetTokens == 0:
		return "medium"
	case th.BudgetTokens < 8192:
		return "low"
	case th.BudgetTokens < 24576:
		return "medium"
	default:
		return "high"
	}
}

// FromChat 把 OpenAI 形状的非流式响应翻成 Anthropic Messages 响应。
//
// 上游给了推理正文（reasoning_content，另一些网关叫 reasoning）就翻成 thinking
// 块放最前面 —— 不管这次请求有没有点 thinking：deepseek-reasoner 这类上游换了
// 模型就一直在想，把它想的东西藏掉才是损失。请求侧不回传 thinking 块
// （chatMessages 丢弃），所以这里造的块不需要签名也能闭环。
func FromChat(resp *ChatResponse, fallbackModel string) (*Response, error) {
	out := &Response{
		ID:           "msg_" + randHex(16),
		Type:         "message",
		Role:         "assistant",
		Model:        resp.Model,
		Content:      []ResponseBlock{},
		StopSequence: nil,
	}
	if out.Model == "" {
		out.Model = fallbackModel
	}
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("上游响应里没有 choices")
	}
	ch := resp.Choices[0]
	if think := firstNonEmpty(ch.Message.ReasoningContent, ch.Message.Reasoning); think != "" {
		out.Content = append(out.Content, ResponseBlock{Type: "thinking", Thinking: think})
	}
	if t := strings.TrimSpace(ch.Message.Content); t != "" {
		out.Content = append(out.Content, ResponseBlock{Type: "text", Text: t})
	}
	for _, tc := range ch.Message.ToolCalls {
		input := json.RawMessage(tc.Function.Arguments)
		if !json.Valid(input) {
			input = json.RawMessage(`{}`)
		}
		out.Content = append(out.Content, ResponseBlock{
			Type:  "tool_use",
			ID:    tc.ID,
			Name:  tc.Function.Name,
			Input: input,
		})
	}
	out.StopReason = stopReason(ch.FinishReason, len(ch.Message.ToolCalls) > 0)
	if resp.Usage != nil {
		out.Usage = Usage{
			InputTokens:  resp.Usage.PromptTokens,
			OutputTokens: resp.Usage.CompletionTokens,
		}
	}
	return out, nil
}

// firstNonEmpty 回第一个非空串（reasoning_content 与 reasoning 两个字段名取先到者）。
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// stopReason 把 OpenAI 的 finish_reason 翻成 Anthropic 的 stop_reason。
func stopReason(finish string, hasTools bool) string {
	switch finish {
	case "length":
		return "max_tokens"
	case "tool_calls", "function_call":
		return "tool_use"
	case "stop", "content_filter", "":
		if hasTools && finish == "" {
			return "tool_use"
		}
		return "end_turn"
	default:
		return "end_turn"
	}
}

// EstimateTokens 估算一段文本的 token 数：4 字符 ≈ 1 token 的粗估。
//
// 只用于两处「先给个数、事后有真值再覆盖」的显示位（message_start 的
// input_tokens、count_tokens 端点），**不参与记账** —— 记账走 usageScanner
// 从上游响应里拿的真值。
func EstimateText(text string) int {
	n := len([]rune(text))
	if n == 0 {
		return 0
	}
	return (n + 3) / 4
}

// randHex 生成 n 字节的十六进制随机串（消息 id、工具调用 id 用）。
func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// parseContent 判别 content 的两种形态：
// 纯字符串返回 nil；块数组返回块列表；形态不对报错。
func parseContent(c Content) ([]ContentBlock, error) {
	trimmed := strings.TrimSpace(string(c))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var blocks []ContentBlock
		if err := json.Unmarshal(c, &blocks); err != nil {
			return nil, fmt.Errorf("content 块数组解析失败: %w", err)
		}
		return blocks, nil
	}
	return nil, nil
}

// flattenContent 把 content 的两种形态拍平成字符串（要一种块类型时只取该类型）。
func flattenContent(c Content, wantType string) string {
	blocks, err := parseContent(c)
	if err != nil {
		return ""
	}
	if blocks == nil {
		return unquoteIfJSONString(c)
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == wantType && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n\n")
}

// unquoteIfJSONString：content 是 JSON 字符串字面量时去掉外层引号。
// 裸文本（非合法 JSON 字符串）原样返回。
func unquoteIfJSONString(c Content) string {
	var s string
	if err := json.Unmarshal(c, &s); err == nil {
		return s
	}
	return string(c)
}
