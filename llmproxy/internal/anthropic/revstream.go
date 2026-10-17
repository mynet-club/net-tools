package anthropic

import (
	"bytes"
	"encoding/json"
	"strings"
)

// RevStreamTranslator 是 StreamTranslator 的镜像：吃 Anthropic 的 SSE 事件流，
// 吐 OpenAI 形状的 chunk 流（含收尾的 finish_reason 与 usage 尾包）。
//
// 二次翻转的流式下半场：执行器从 Anthropic 上游读到的帧进来，出去的字节就是
// relay / usageScanner / 客户端侧包装器都认得的 OpenAI SSE（data: 行 + [DONE]）。
//
// usage 归并：message_start 带 input_tokens、message_delta 带 output_tokens，
// 两边到齐（或流结束）才合成一个 usage 尾包 —— usageScanner 靠这个尾包记账，
// 少了它这条流的用量就记成 0。
type RevStreamTranslator struct {
	buf       bytes.Buffer // 上游 SSE 半包
	chunkID   string
	model     string
	usageIn   int
	usageOut  int
	sawUsage  bool
	finished  bool // finish + usage 已出
	closed    bool // [DONE] 已出
	stop      string
	toolIndex int // OpenAI 侧 tool_calls[].index 计数
	toolOpen  bool
	frames    bytes.Buffer // 待输出的 OpenAI SSE 帧
}

// NewRevStreamTranslator 建一个反向流翻译器。
func NewRevStreamTranslator() *RevStreamTranslator {
	return &RevStreamTranslator{
		chunkID:   "chatcmpl-" + randHex(8),
		toolIndex: -1,
	}
}

// FeedBytes 收一段上游原始字节（SSE 半包没关系，内部自己攒帧），
// 返回可以原样写给下游的 OpenAI SSE 帧。
func (t *RevStreamTranslator) FeedBytes(p []byte) []byte {
	t.buf.Write(p)
	for {
		all := t.buf.Bytes()
		i := bytes.Index(all, []byte("\n\n"))
		if i < 0 {
			break
		}
		frame := all[:i]
		t.buf.Next(i + 2)
		t.feedFrame(frame)
	}
	out := append([]byte(nil), t.frames.Bytes()...)
	t.frames.Reset()
	return out
}

// Close 收尾：补 finish chunk 与 usage 尾包，最后一帧 [DONE]。幂等。
func (t *RevStreamTranslator) Close() []byte {
	if t.closed {
		return nil
	}
	t.closed = true
	if t.stop == "" {
		t.stop = "stop"
	}
	t.emitFinish()
	t.frames.WriteString("data: [DONE]\n\n")
	out := append([]byte(nil), t.frames.Bytes()...)
	t.frames.Reset()
	return out
}

// feedFrame 处理一个完整的 Anthropic SSE 帧（event + data 行）。
func (t *RevStreamTranslator) feedFrame(frame []byte) {
	payload := SSEDataPayload(frame)
	if payload == "" {
		return
	}
	var ev map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		return
	}
	var typ string
	_ = json.Unmarshal(ev["type"], &typ)
	switch typ {
	case "message_start":
		var ms struct {
			Message struct {
				ID    string `json:"id"`
				Model string `json:"model"`
				Usage struct {
					InputTokens int `json:"input_tokens"`
				} `json:"usage"`
			} `json:"message"`
		}
		if err := json.Unmarshal([]byte(payload), &ms); err == nil {
			t.model = ms.Message.Model
			t.usageIn = ms.Message.Usage.InputTokens
			t.sawUsage = true
		}
	case "content_block_start":
		var bs struct {
			ContentBlock struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"content_block"`
		}
		if err := json.Unmarshal([]byte(payload), &bs); err == nil && bs.ContentBlock.Type == "tool_use" {
			t.toolIndex++
			t.toolOpen = true
			idx := t.toolIndex
			t.emitChunk(func(c *ChatChunk) {
				tc := ChatChunkToolCall{Index: idx, ID: bs.ContentBlock.ID, Type: "function"}
				tc.Function.Name = bs.ContentBlock.Name
				c.Choices[0].Delta.ToolCalls = append(c.Choices[0].Delta.ToolCalls, tc)
			})
		}
	case "content_block_delta":
		var d struct {
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				Thinking    string `json:"thinking"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(payload), &d); err != nil {
			return
		}
		switch d.Delta.Type {
		case "text_delta":
			t.emitChunk(func(c *ChatChunk) { c.Choices[0].Delta.Content = d.Delta.Text })
		case "thinking_delta":
			t.emitChunk(func(c *ChatChunk) {
				c.Choices[0].Delta.ReasoningContent = d.Delta.Thinking
			})
		case "input_json_delta":
			idx := t.toolIndex
			t.emitChunk(func(c *ChatChunk) {
				tc := ChatChunkToolCall{Index: idx}
				tc.Function.Arguments = d.Delta.PartialJSON
				c.Choices[0].Delta.ToolCalls = append(c.Choices[0].Delta.ToolCalls, tc)
			})
		}
	case "message_delta":
		var d struct {
			Delta struct {
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
			Usage struct {
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(payload), &d); err == nil {
			t.stop = d.Delta.StopReason
			if d.Usage.OutputTokens > 0 {
				t.usageOut = d.Usage.OutputTokens
				t.sawUsage = true
			}
		}
	case "message_stop":
		t.emitFinish()
	}
}

// emitFinish 把 finish_reason chunk 与 usage 尾包写进输出缓冲（只出一次）。
func (t *RevStreamTranslator) emitFinish() {
	if t.finished {
		return
	}
	t.finished = true
	stop := t.stop
	t.emitChunk(func(c *ChatChunk) {
		c.Choices[0].FinishReason = chatFinishReason(stop, t.toolOpen)
	})
	if t.sawUsage {
		t.emitChunk(func(c *ChatChunk) {
			c.Choices = nil
			c.Usage = &ChatUsage{
				PromptTokens:     t.usageIn,
				CompletionTokens: t.usageOut,
				TotalTokens:      t.usageIn + t.usageOut,
			}
		})
	}
}

// emitChunk 构造一个 OpenAI chunk、套上 SSE 封帧写进输出缓冲。
func (t *RevStreamTranslator) emitChunk(fill func(*ChatChunk)) {
	chunk := ChatChunk{ID: t.chunkID, Model: t.model, Choices: []ChatChunkChoice{{}}}
	fill(&chunk)
	data, err := json.Marshal(chunk)
	if err != nil {
		return
	}
	t.frames.Write([]byte("data: "))
	t.frames.Write(data)
	t.frames.WriteString("\n\n")
}

// SSEDataPayload 从一个 SSE 帧里抽出 data 载荷（多行 data 按规范用 \n 拼接）。
// 出网侧（RevStreamTranslator）与入网侧（server 的包装器）共用同一套帧解析口径。
func SSEDataPayload(frame []byte) string {
	var parts []string
	for _, line := range strings.Split(string(frame), "\n") {
		if strings.HasPrefix(line, "data:") {
			parts = append(parts, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	return strings.Join(parts, "\n")
}
