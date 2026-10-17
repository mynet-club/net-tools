package anthropic

import (
	"encoding/json"
)

// StreamTranslator 把 OpenAI chat 的流式增量翻成 Anthropic 的事件流。
//
// 事件生命周期按 Anthropic 的契约拼：message_start →（content_block_start →
// content_block_delta* → content_block_stop）* → message_delta → message_stop。
// 两个细节：
//   - usage 可能在 finish_reason 之后的**另一个**空 choices 片段里才到
//     （stream_options.include_usage 的形态），所以 message_delta/message_stop
//     压到「拿到 usage 或上游流结束」才发，免得客户端只拿到估算值；
//   - 上游没给 finish_reason 就断流时，Close() 也要把开着的块和收尾事件补上 ——
//     缺 message_stop 的流会让 Claude Code 一直等。
type StreamTranslator struct {
	model   string
	msgID   string
	estIn   int
	started bool

	blockIdx  int
	blockOpen bool
	blockType string // "text" | "tool_use"

	sawFinish bool
	finish    string
	hasTools  bool
	finalized bool
	outChars  int
	usage     *ChatUsage
}

// NewStreamTranslator 建一个流式翻译器。estIn 是 message_start 里报的
// 输入 token 估算值（只影响显示，不参与记账）。
func NewStreamTranslator(model string, estIn int) *StreamTranslator {
	return &StreamTranslator{
		model:    model,
		msgID:    "msg_" + randHex(16),
		estIn:    estIn,
		blockIdx: -1,
	}
}

// Feed 接一段上游 SSE 的 data 载荷（一个 OpenAI chunk 的 JSON），
// 返回要发给下游的完整事件帧（已带 event/data 封帧）。载荷为空（注释行、
// 心跳）时返回 nil。
func (t *StreamTranslator) Feed(data []byte) ([]byte, error) {
	if t.finalized {
		return nil, nil
	}
	var chunk ChatChunk
	if err := json.Unmarshal(data, &chunk); err != nil {
		return nil, err
	}
	var out []byte

	if !t.started {
		t.started = true
		out = append(out, t.messageStart()...)
	}

	for _, c := range chunk.Choices {
		if think := firstNonEmpty(c.Delta.ReasoningContent, c.Delta.Reasoning); think != "" {
			if t.blockOpen && t.blockType != "thinking" {
				out = append(out, t.blockStop()...)
			}
			if !t.blockOpen {
				out = append(out, t.blockStart("thinking", "", "")...)
			}
			out = append(out, eventFrame("content_block_delta", map[string]any{
				"type":  "content_block_delta",
				"index": t.blockIdx,
				"delta": map[string]any{"type": "thinking_delta", "thinking": think},
			})...)
			t.outChars += len([]rune(think))
		}
		if s := c.Delta.Content; s != "" {
			if t.blockOpen && t.blockType != "text" {
				out = append(out, t.blockStop()...)
			}
			if !t.blockOpen {
				out = append(out, t.blockStart("text", "", "")...)
			}
			out = append(out, eventFrame("content_block_delta", map[string]any{
				"type":  "content_block_delta",
				"index": t.blockIdx,
				"delta": map[string]any{"type": "text_delta", "text": s},
			})...)
			t.outChars += len([]rune(s))
		}
		for _, tc := range c.Delta.ToolCalls {
			first := tc.ID != "" || tc.Function.Name != ""
			if first {
				if t.blockOpen {
					out = append(out, t.blockStop()...)
				}
				id := tc.ID
				if id == "" {
					id = "toolu_" + randHex(12)
				}
				out = append(out, t.blockStart("tool_use", id, tc.Function.Name)...)
				t.hasTools = true
			}
			if args := tc.Function.Arguments; args != "" {
				if !t.blockOpen || t.blockType != "tool_use" {
					// 上游没发首片段就直接吐参数（不规范但存在）：补一个工具块
					if t.blockOpen {
						out = append(out, t.blockStop()...)
					}
					out = append(out, t.blockStart("tool_use", "toolu_"+randHex(12), "")...)
					t.hasTools = true
				}
				out = append(out, eventFrame("content_block_delta", map[string]any{
					"type":  "content_block_delta",
					"index": t.blockIdx,
					"delta": map[string]any{"type": "input_json_delta", "partial_json": args},
				})...)
				t.outChars += len(args) / 4
			}
		}
		if c.FinishReason != "" {
			t.sawFinish = true
			t.finish = c.FinishReason
		}
	}

	if chunk.Usage != nil {
		t.usage = chunk.Usage
	}
	// finish 与 usage 都到手（或 finish 后又来了一段 = usage 尾包）就收尾
	if t.sawFinish && t.usage != nil {
		out = append(out, t.finishMessage()...)
	}
	return out, nil
}

// Close 收尾：关掉开着的块、补 message_delta/message_stop。幂等。
// 上游带了 finish_reason 但 usage 迟迟没来时，这里用估算值兜底收尾。
func (t *StreamTranslator) Close() []byte {
	if t.finalized {
		return nil
	}
	if !t.started {
		t.started = true
		out := t.messageStart()
		return append(out, t.finishMessage()...)
	}
	return t.finishMessage()
}

// ── 事件帧拼装 ─────────────────────────────────────────────────────

func (t *StreamTranslator) messageStart() []byte {
	return eventFrame("message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id":            t.msgID,
			"type":          "message",
			"role":          "assistant",
			"model":         t.model,
			"content":       []any{},
			"stop_reason":   nil,
			"stop_sequence": nil,
			"usage": map[string]any{
				"input_tokens":  t.estIn,
				"output_tokens": 0,
			},
		},
	})
}

func (t *StreamTranslator) blockStart(kind, id, name string) []byte {
	t.blockIdx++
	t.blockOpen = true
	t.blockType = kind
	var block map[string]any
	switch kind {
	case "tool_use":
		block = map[string]any{"type": "tool_use", "id": id, "name": name, "input": map[string]any{}}
	case "thinking":
		block = map[string]any{"type": "thinking", "thinking": ""}
	default:
		block = map[string]any{"type": "text", "text": ""}
	}
	return eventFrame("content_block_start", map[string]any{
		"type":          "content_block_start",
		"index":         t.blockIdx,
		"content_block": block,
	})
}

func (t *StreamTranslator) blockStop() []byte {
	t.blockOpen = false
	return eventFrame("content_block_stop", map[string]any{
		"type":  "content_block_stop",
		"index": t.blockIdx,
	})
}

func (t *StreamTranslator) finishMessage() []byte {
	t.finalized = true
	var out []byte
	if t.blockOpen {
		out = append(out, t.blockStop()...)
	}
	stop := "end_turn"
	if t.sawFinish {
		stop = stopReason(t.finish, t.hasTools)
	}
	outTok := (t.outChars + 3) / 4
	if t.usage != nil && t.usage.CompletionTokens > 0 {
		outTok = t.usage.CompletionTokens
	}
	out = append(out, eventFrame("message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": stop, "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": outTok},
	})...)
	out = append(out, eventFrame("message_stop", map[string]any{"type": "message_stop"})...)
	return out
}

// eventFrame 拼一个 SSE 事件帧：event 行 + data 行 + 空行。
func eventFrame(name string, payload any) []byte {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	frame := make([]byte, 0, len(name)+len(data)+16)
	frame = append(frame, "event: "...)
	frame = append(frame, name...)
	frame = append(frame, '\n', 'd', 'a', 't', 'a', ':', ' ')
	frame = append(frame, data...)
	frame = append(frame, '\n', '\n')
	return frame
}
