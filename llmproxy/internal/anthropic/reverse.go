package anthropic

import (
	"encoding/json"
	"fmt"
	"strings"
)

// 出网侧的反向翻译（内部 chat/completions 形状 ⇄ Anthropic Messages 形状）。
//
// 二次翻转的下半场：治理核只认 OpenAI 形状，上游是 Anthropic 协议时，
// 执行器拿这里的 ToMessages 把已定稿的 OpenAI 正文翻成 /v1/messages 请求，
// 再拿 FromMessages / RevStreamTranslator 把响应（含流）翻回 OpenAI 形状 ——
// relay、usageScanner、客户端侧包装器看到的永远是同一种形状。
//
// 与正向翻译（ToChat / FromChat / StreamTranslator）互为镜像：来回两趟丢的
// 都是同一类东西（thinking 签名、top_k），不做不对称的「特殊照顾」。

// contentPart 是 OpenAI 形状多模态消息里的一个块（text / image_url）。
type contentPart struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	ImageURL *struct {
		URL string `json:"url"`
	} `json:"image_url,omitempty"`
}

// ToMessages 把内部 chat/completions 请求翻成 Anthropic Messages 请求。
func ToMessages(chat *ChatRequest) (*Request, error) {
	if strings.TrimSpace(chat.Model) == "" {
		return nil, fmt.Errorf("缺少 model 字段")
	}
	if len(chat.Messages) == 0 {
		return nil, fmt.Errorf("messages 不能为空")
	}

	out := &Request{
		Model:         chat.Model,
		MaxTokens:     chat.MaxTokens,
		Temperature:   chat.Temperature,
		TopP:          chat.TopP,
		StopSequences: chat.Stop,
		Stream:        chat.Stream,
	}
	if chat.ReasoningEffort == "none" {
		out.Thinking = &Thinking{Type: "disabled"}
	} else if chat.ReasoningEffort != "" {
		out.Thinking = &Thinking{Type: "enabled", BudgetTokens: budgetForEffort(chat.ReasoningEffort)}
	}

	for _, m := range chat.Messages {
		switch m.Role {
		case "system":
			text := contentText(m.Content)
			if strings.TrimSpace(text) != "" {
				out.System = appendSystem(out.System, text)
			}
		case "user":
			blocks, err := userBlocks(m)
			if err != nil {
				return nil, err
			}
			out.Messages = append(out.Messages, Message{Role: "user", Content: marshalBlocks(blocks)})
		case "assistant":
			blocks := []ContentBlock{}
			if text := contentText(m.Content); strings.TrimSpace(text) != "" {
				blocks = append(blocks, ContentBlock{Type: "text", Text: text})
			}
			for _, tc := range m.ToolCalls {
				args := json.RawMessage(tc.Function.Arguments)
				if !json.Valid(args) {
					args = json.RawMessage(`{}`)
				}
				blocks = append(blocks, ContentBlock{
					Type: "tool_use", ID: tc.ID, Name: tc.Function.Name, Input: args,
				})
			}
			if len(blocks) > 0 {
				out.Messages = append(out.Messages, Message{Role: "assistant", Content: marshalBlocks(blocks)})
			}
		case "tool":
			// OpenAI 的工具结果单列一条 role=tool；Anthropic 要放进 user 轮的
			// tool_result 块。连续多条 tool 结果并进同一个 user 轮。
			blk := ContentBlock{
				Type:      "tool_result",
				ToolUseID: m.ToolCallID,
				Result:    marshalBlocks([]ContentBlock{{Type: "text", Text: contentText(m.Content)}}),
			}
			if n := len(out.Messages); n > 0 && out.Messages[n-1].Role == "user" {
				if blocks, err := parseContent(out.Messages[n-1].Content); err == nil && allToolResults(blocks) {
					out.Messages[n-1].Content = marshalBlocks(append(blocks, blk))
					continue
				}
			}
			out.Messages = append(out.Messages, Message{Role: "user", Content: marshalBlocks([]ContentBlock{blk})})
		default:
			return nil, fmt.Errorf("role 只认 system/user/assistant/tool，收到 %q", m.Role)
		}
	}

	for _, t := range chat.Tools {
		out.Tools = append(out.Tools, Tool{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			InputSchema: t.Function.Parameters,
		})
	}
	if chat.ToolChoice != nil {
		tc, err := parseToolChoice(chat.ToolChoice)
		if err != nil {
			return nil, err
		}
		out.ToolChoice = tc
	}
	return out, nil
}

// parseToolChoice 认两种 tool_choice 形态：字符串枚举与 function 点名对象。
// 按 JSON 形状认而不是按 Go 类型 switch —— 上游链路里这个值可能来自
// map[string]any、map[string]string 嵌套或别的等价构造，类型 switch 会静默漏掉。
func parseToolChoice(v any) (*ToolChoice, error) {
	if s, ok := v.(string); ok {
		switch s {
		case "auto":
			return &ToolChoice{Type: "auto"}, nil
		case "none":
			return &ToolChoice{Type: "none"}, nil
		case "required":
			return &ToolChoice{Type: "any"}, nil
		}
		return nil, fmt.Errorf("tool_choice 取值不认：%s", s)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("tool_choice 编码失败: %w", err)
	}
	var parsed struct {
		Type     string `json:"type"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("tool_choice 形状不认: %w", err)
	}
	if parsed.Function.Name != "" {
		return &ToolChoice{Type: "tool", Name: parsed.Function.Name}, nil
	}
	switch parsed.Type {
	case "auto":
		return &ToolChoice{Type: "auto"}, nil
	case "none":
		return &ToolChoice{Type: "none"}, nil
	case "any", "required":
		return &ToolChoice{Type: "any"}, nil
	}
	return nil, fmt.Errorf("tool_choice 形状不认：%s", raw)
}

// FromMessages 把 Anthropic Messages 响应翻回内部 chat/completions 形状。
func FromMessages(resp *Response) (*ChatResponse, error) {
	out := &ChatResponse{
		ID:    resp.ID,
		Model: resp.Model,
	}
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
	ch.Index = 0
	ch.Message.Role = "assistant"

	var texts, thinks []string
	for _, b := range resp.Content {
		switch b.Type {
		case "thinking":
			thinks = append(thinks, b.Thinking)
		case "text":
			texts = append(texts, b.Text)
		case "tool_use":
			args := string(b.Input)
			if args == "" {
				args = "{}"
			}
			tc := ChatToolCall{ID: b.ID, Type: "function"}
			tc.Function.Name = b.Name
			tc.Function.Arguments = args
			ch.Message.ToolCalls = append(ch.Message.ToolCalls, tc)
		}
	}
	ch.Message.Content = strings.Join(texts, "\n\n")
	ch.Message.ReasoningContent = strings.Join(thinks, "\n\n")
	ch.FinishReason = chatFinishReason(resp.StopReason, len(ch.Message.ToolCalls) > 0)

	out.Choices = append(out.Choices, ch)
	if resp.Usage.InputTokens > 0 || resp.Usage.OutputTokens > 0 {
		out.Usage = &ChatUsage{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.InputTokens + resp.Usage.OutputTokens,
		}
	}
	return out, nil
}

// chatFinishReason 是 stopReason 的逆映射。
func chatFinishReason(stop string, hasTools bool) string {
	switch stop {
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	case "end_turn", "stop_sequence", "":
		if hasTools && stop == "" {
			return "tool_calls"
		}
		return "stop"
	default:
		return "stop"
	}
}

// 只有跨协议且没有原始预算时才按档位选择代表预算。
func budgetForEffort(eff string) int {
	switch eff {
	case "low":
		return 4096
	case "high":
		return 32768
	default:
		return 16384
	}
}

// ── 小工具 ─────────────────────────────────────────────────────────

// contentText 把 OpenAI 消息的 content（字符串或多模态块数组）拍平成纯文本。
// 图片块不参与拍平（正文用途只取文本）。
func contentText(v any) string {
	switch c := v.(type) {
	case nil:
		return ""
	case string:
		return c
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	var parts []contentPart
	if err := json.Unmarshal(raw, &parts); err != nil {
		return ""
	}
	var out []string
	for _, p := range parts {
		if p.Type == "text" && p.Text != "" {
			out = append(out, p.Text)
		}
	}
	return strings.Join(out, "\n\n")
}

// userBlocks 把 user 消息的 content 翻成块数组（文本与图片）。
func userBlocks(m ChatMessage) ([]ContentBlock, error) {
	if s, ok := m.Content.(string); ok {
		return []ContentBlock{{Type: "text", Text: s}}, nil
	}
	raw, err := json.Marshal(m.Content)
	if err != nil {
		return nil, fmt.Errorf("user content 编码失败: %w", err)
	}
	var parts []contentPart
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil, fmt.Errorf("user content 形状不认: %w", err)
	}
	var blocks []ContentBlock
	for _, p := range parts {
		switch p.Type {
		case "text":
			blocks = append(blocks, ContentBlock{Type: "text", Text: p.Text})
		case "image_url":
			if p.ImageURL == nil {
				return nil, fmt.Errorf("image_url 块缺 url")
			}
			blocks = append(blocks, ContentBlock{
				Type:   "image",
				Source: imageSourceFromDataURL(p.ImageURL.URL),
			})
		default:
			return nil, fmt.Errorf("不认的内容块类型 %q", p.Type)
		}
	}
	if len(blocks) == 0 {
		blocks = []ContentBlock{{Type: "text", Text: ""}}
	}
	return blocks, nil
}

// imageSourceFromDataURL 把 data:<media>;base64,<data> 形式的 URL 还原成
// Anthropic 的 image source；还原不了就退化成 url 形态（交给上游判）。
func imageSourceFromDataURL(url string) *ImageSource {
	const prefix = "data:"
	if !strings.HasPrefix(url, prefix) {
		return &ImageSource{Type: "url", URL: url}
	}
	rest := url[len(prefix):]
	semi := strings.Index(rest, ";")
	comma := strings.Index(rest, ",")
	if semi < 0 || comma < 0 || comma < semi {
		return &ImageSource{Type: "url", URL: url}
	}
	return &ImageSource{
		Type:      "base64",
		MediaType: rest[:semi],
		Data:      rest[comma+1:],
	}
}

// marshalBlocks 把块数组编成 Content（块数组形态）。
func marshalBlocks(blocks []ContentBlock) Content {
	raw, err := json.Marshal(blocks)
	if err != nil {
		return json.RawMessage(`[]`)
	}
	return raw
}

// appendSystem 把多条 system 文本并成一份 Content（字符串形态）。
func appendSystem(cur Content, text string) Content {
	full := text
	if len(cur) != 0 {
		full = flattenContent(cur, "text") + "\n\n" + text
	}
	raw, _ := json.Marshal(full)
	return raw
}

// allToolResults 报告这一组块是不是全是 tool_result（决定能不能并轮）。
func allToolResults(blocks []ContentBlock) bool {
	if len(blocks) == 0 {
		return false
	}
	for _, b := range blocks {
		if b.Type != "tool_result" {
			return false
		}
	}
	return true
}
