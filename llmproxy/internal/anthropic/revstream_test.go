package anthropic

import (
	"encoding/json"
	"strings"
	"testing"
)

// revAll 喂一段（可断开的）Anthropic 事件流，拼出全部 OpenAI SSE 输出。
// split 模拟网络半包：每 FeedBytes 只给 7 个字节。
func revAll(t *testing.T, stream string, split bool) string {
	t.Helper()
	tr := NewRevStreamTranslator()
	var out strings.Builder
	if split {
		for i := 0; i < len(stream); i += 7 {
			end := i + 7
			if end > len(stream) {
				end = len(stream)
			}
			out.Write(tr.FeedBytes([]byte(stream[i:end])))
		}
	} else {
		out.Write(tr.FeedBytes([]byte(stream)))
	}
	out.Write(tr.Close())
	return out.String()
}

// revChunks 把输出里的 data 载荷解析成 chunk 对象（[DONE] 跳过）。
func revChunks(t *testing.T, frames string) ([]ChatChunk, bool) {
	t.Helper()
	var chunks []ChatChunk
	sawDone := false
	for _, line := range strings.Split(frames, "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			sawDone = true
			continue
		}
		var c ChatChunk
		if err := json.Unmarshal([]byte(payload), &c); err != nil {
			t.Fatalf("chunk 解析失败: %v (%s)", err, payload)
		}
		chunks = append(chunks, c)
	}
	return chunks, sawDone
}

const revTextStream = `event: message_start
data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"up-m","content":[],"usage":{"input_tokens":11,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" world"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":22}}

event: message_stop
data: {"type":"message_stop"}
`

func TestRevStreamTextAndUsage(t *testing.T) {
	frames := revAll(t, revTextStream, true) // 半包喂法也必须成立
	chunks, sawDone := revChunks(t, frames)
	if !sawDone {
		t.Fatalf("缺 [DONE] 收尾: %s", frames)
	}
	var texts []string
	var finish string
	var usage *ChatUsage
	for _, c := range chunks {
		if len(c.Choices) > 0 {
			if c.Choices[0].Delta.Content != "" {
				texts = append(texts, c.Choices[0].Delta.Content)
			}
			if c.Choices[0].FinishReason != "" {
				finish = c.Choices[0].FinishReason
			}
		}
		if c.Usage != nil {
			usage = c.Usage
		}
	}
	if strings.Join(texts, "") != "Hello world" {
		t.Fatalf("文本增量不对: %q", strings.Join(texts, ""))
	}
	if finish != "stop" {
		t.Fatalf("finish_reason 应为 stop: %q", finish)
	}
	if usage == nil || usage.PromptTokens != 11 || usage.CompletionTokens != 22 {
		t.Fatalf("usage 尾包没归并对: %+v", usage)
	}
}

const revToolStream = `event: message_start
data: {"type":"message_start","message":{"id":"msg_2","type":"message","role":"assistant","model":"up-m","content":[],"usage":{"input_tokens":5,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"先想想"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_7","name":"f","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"a\":"}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"1}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":1}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":8}}

event: message_stop
data: {"type":"message_stop"}
`

func TestRevStreamThinkingAndTool(t *testing.T) {
	frames := revAll(t, revToolStream, false)
	chunks, _ := revChunks(t, frames)
	var think string
	var args strings.Builder
	var toolID, toolName, finish string
	for _, c := range chunks {
		if len(c.Choices) == 0 {
			continue
		}
		d := c.Choices[0].Delta
		think += d.ReasoningContent
		for _, tc := range d.ToolCalls {
			if tc.ID != "" {
				toolID, toolName = tc.ID, tc.Function.Name
			}
			args.WriteString(tc.Function.Arguments)
		}
		if c.Choices[0].FinishReason != "" {
			finish = c.Choices[0].FinishReason
		}
	}
	if think != "先想想" {
		t.Fatalf("thinking 没翻成 reasoning_content: %q", think)
	}
	if toolID != "toolu_7" || toolName != "f" {
		t.Fatalf("工具首片不对: %s %s", toolID, toolName)
	}
	if args.String() != `{"a":1}` {
		t.Fatalf("工具参数碎片没拼对: %q", args.String())
	}
	if finish != "tool_calls" {
		t.Fatalf("finish_reason 应为 tool_calls: %q", finish)
	}
}

func TestRevStreamCloseWithoutStop(t *testing.T) {
	tr := NewRevStreamTranslator()
	out := tr.FeedBytes([]byte(`event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"半"}}

`))
	out = append(out, tr.Close()...)
	frames := string(out)
	chunks, sawDone := revChunks(t, frames)
	if !sawDone {
		t.Fatalf("断流也必须补 [DONE]: %s", frames)
	}
	finish := ""
	for _, c := range chunks {
		if len(c.Choices) > 0 && c.Choices[0].FinishReason != "" {
			finish = c.Choices[0].FinishReason
		}
	}
	if finish != "stop" {
		t.Fatalf("无 stop_reason 时应兜底 stop: %q", finish)
	}
	// 幂等
	if f := tr.Close(); len(f) != 0 {
		t.Fatalf("Close 应幂等，拿到 %s", f)
	}
}

func TestRevStreamUsageWithoutStopReason(t *testing.T) {
	// message_delta 只带 usage 不带 stop_reason（存在这种上游）：finish 兜底 + usage 照记
	stream := `event: message_start
data: {"type":"message_start","message":{"id":"m","type":"message","role":"assistant","model":"x","content":[],"usage":{"input_tokens":2,"output_tokens":0}}}

event: message_delta
data: {"type":"message_delta","delta":{},"usage":{"output_tokens":3}}

event: message_stop
data: {"type":"message_stop"}
`
	chunks, _ := revChunks(t, revAll(t, stream, false))
	var usage *ChatUsage
	for _, c := range chunks {
		if c.Usage != nil {
			usage = c.Usage
		}
	}
	if usage == nil || usage.PromptTokens != 2 || usage.CompletionTokens != 3 {
		t.Fatalf("usage 归并不对: %+v", usage)
	}
}
