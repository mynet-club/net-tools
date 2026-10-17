// Package anthropic 是 Anthropic Messages 线格式（/v1/messages）与内部
// OpenAI chat/completions 形状之间的双向翻译。
//
// 为什么是「边缘翻译」而不是给每家上游写方言：网关后面的策略判定、限流、
// 选路、处理器、记账全部按内部请求形状工作，入口把方言翻成内部形状，
// 这些面就一视同仁地罩住 Anthropic 协议进来的流量；出口再把结果翻回去。
// 翻译只搬语义，不复算任何业务规则。
package anthropic

import "encoding/json"

// ── Anthropic Messages 线格式（只列网关用得到的字段）────────────────

// Request 是 POST /v1/messages 的请求体。
//
// content 的两种形态（字符串或块数组）都收：Claude Code 用块数组，
// 一行 curl 常用字符串，二者语义相同。
type Request struct {
	Model         string          `json:"model"`
	MaxTokens     int             `json:"max_tokens"`
	Messages      []Message       `json:"messages"`
	System        Content         `json:"system,omitempty"`
	Tools         []Tool          `json:"tools,omitempty"`
	ToolChoice    *ToolChoice     `json:"tool_choice,omitempty"`
	Temperature   *float64        `json:"temperature,omitempty"`
	TopP          *float64        `json:"top_p,omitempty"`
	TopK          *float64        `json:"top_k,omitempty"` // OpenAI 形状没有对应物，翻译时丢弃
	StopSequences []string        `json:"stop_sequences,omitempty"`
	Stream        bool            `json:"stream,omitempty"`
	Metadata      *Metadata       `json:"metadata,omitempty"`
	Thinking      json.RawMessage `json:"thinking,omitempty"` // 原样收下但不参与翻译（见 ToChat 注释）
}

// Metadata 只有 user_id 一个字段会被上游认得；这里收下是为了校验形态。
type Metadata struct {
	UserID string `json:"user_id,omitempty"`
}

// Message 是一条对话消息。Content 兼容字符串与块数组两种形态。
type Message struct {
	Role    string  `json:"role"`
	Content Content `json:"content"`
}

// Content 兼容「纯字符串」与「块数组」两种 content 形态。
//
// Anthropic 线格式里两者都合法；内部用 RawMessage 收，在翻译处一次判别，
// 免得在类型上分叉出两个 Message 结构。必须是**别名**而不是新定义类型：
// 新定义类型不继承 json.RawMessage 的 Marshal/Unmarshal 方法，会被当成
// base64 字节串解码（实测报 illegal base64 data）。
type Content = json.RawMessage

// ContentBlock 是块数组形态里的一个块。type 取 text / image / tool_use /
// tool_result；thinking 块收下但丢弃（见 ToChat 注释）。
type ContentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	Source    *ImageSource    `json:"source,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Result    Content         `json:"result,omitempty"`
}

// ImageSource 是 image 块的图源（base64 或 url 两种）。
type ImageSource struct {
	Type      string `json:"type"`
	MediaType string `json:"media_type,omitempty"`
	Data      string `json:"data,omitempty"`
	URL       string `json:"url,omitempty"`
}

// Tool 是一个工具声明：名字、说明、JSON Schema 输入。
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// ToolChoice 是工具选择策略：auto / any / none / tool（点名）。
type ToolChoice struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

// Response 是非流式的响应体。
type Response struct {
	ID           string          `json:"id"`
	Type         string          `json:"type"` // 恒为 "message"
	Role         string          `json:"role"` // 恒为 "assistant"
	Model        string          `json:"model"`
	Content      []ResponseBlock `json:"content"`
	StopReason   string          `json:"stop_reason"`
	StopSequence *string         `json:"stop_sequence"`
	Usage        Usage           `json:"usage"`
}

// ResponseBlock 是响应里的内容块：text 或 tool_use。
type ResponseBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text,omitempty"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

// Usage 是 Anthropic 口径的用量。count_tokens 端点只回 input_tokens。
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// ── 内部 OpenAI 形状（只列翻译用得到的字段）────────────────────────

// ChatRequest 是内部 chat/completions 请求形状。
type ChatRequest struct {
	Model       string        `json:"model"`
	Messages    []ChatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature *float64      `json:"temperature,omitempty"`
	TopP        *float64      `json:"top_p,omitempty"`
	Stop        []string      `json:"stop,omitempty"`
	Stream      bool          `json:"stream,omitempty"`
	Tools       []ChatTool    `json:"tools,omitempty"`
	ToolChoice  any           `json:"tool_choice,omitempty"`
}

// ChatMessage 是 OpenAI 形状的对话消息。content 可以是字符串或多模态块数组；
// tool_calls 是助手侧发起的工具调用，tool_call_id 是工具侧回填的结果归属。
type ChatMessage struct {
	Role       string         `json:"role"`
	Content    any            `json:"content,omitempty"`
	ToolCalls  []ChatToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

// ChatTool 是 OpenAI 形状的工具声明。
type ChatTool struct {
	Type     string       `json:"type"`
	Function ChatFunction `json:"function"`
}

// ChatFunction 是 tools[].function。
type ChatFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// ChatToolCall 是 assistant 消息里的一个工具调用。
type ChatToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// ChatResponse 是非流式的 OpenAI 形状响应。
type ChatResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role      string         `json:"role"`
			Content   string         `json:"content"`
			ToolCalls []ChatToolCall `json:"tool_calls,omitempty"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *ChatUsage `json:"usage,omitempty"`
}

// ChatUsage 是 OpenAI 形状的用量。
type ChatUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

// ChatChunk 是流式的一个增量片段。
type ChatChunk struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Role      string `json:"role"`
			Content   string `json:"content"`
			ToolCalls []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *ChatUsage `json:"usage,omitempty"`
}
