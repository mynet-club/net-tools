package anthropic

import (
	"encoding/json"
	"strings"
	"testing"
)

// feedAll 喂一批上游 data 载荷并拼出全部输出帧，最后 Close。
func feedAll(t *testing.T, tr *StreamTranslator, chunks ...string) string {
	t.Helper()
	var out strings.Builder
	for _, c := range chunks {
		frame, err := tr.Feed([]byte(c))
		if err != nil {
			t.Fatalf("Feed 失败: %v", err)
		}
		out.Write(frame)
	}
	out.Write(tr.Close())
	return out.String()
}

// eventNames 按顺序抽出事件帧里的 event 名。
func eventNames(frames string) []string {
	var names []string
	for _, line := range strings.Split(frames, "\n") {
		if strings.HasPrefix(line, "event: ") {
			names = append(names, strings.TrimPrefix(line, "event: "))
		}
	}
	return names
}

func TestStreamTextLifecycle(t *testing.T) {
	tr := NewStreamTranslator("claude-x", 7)
	frames := feedAll(t, tr,
		`{"choices":[{"index":0,"delta":{"role":"assistant","content":"你"}}]}`,
		`{"choices":[{"index":0,"delta":{"content":"好"}}]}`,
		`{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		`{"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":2}}`,
	)
	want := []string{"message_start", "content_block_start", "content_block_delta",
		"content_block_delta", "content_block_stop", "message_delta", "message_stop"}
	got := eventNames(frames)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("事件序列不对:\n got %v\nwant %v", got, want)
	}
	if !strings.Contains(frames, `"text":"你"`) || !strings.Contains(frames, `"text":"好"`) {
		t.Fatalf("文本增量丢了: %s", frames)
	}
	if !strings.Contains(frames, `"input_tokens":7`) {
		t.Fatalf("message_start 的 input_tokens 不对: %s", frames)
	}
	// usage 真值应落在 message_delta 的 output_tokens 上
	if !strings.Contains(frames, `"output_tokens":2`) {
		t.Fatalf("message_delta 的 output_tokens 应取 usage 真值: %s", frames)
	}
}

func TestStreamToolCallLifecycle(t *testing.T) {
	tr := NewStreamTranslator("claude-x", 1)
	frames := feedAll(t, tr,
		`{"choices":[{"index":0,"delta":{"role":"assistant","content":"查"}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"toolu_1","type":"function","function":{"name":"f","arguments":""}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"a\":"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"1}"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":4}}`,
	)
	want := []string{"message_start",
		"content_block_start", "content_block_delta", "content_block_stop",
		"content_block_start", "content_block_delta", "content_block_delta", "content_block_stop",
		"message_delta", "message_stop"}
	got := eventNames(frames)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("事件序列不对:\n got %v\nwant %v", got, want)
	}
	if !strings.Contains(frames, `"type":"tool_use"`) || !strings.Contains(frames, `"id":"toolu_1"`) {
		t.Fatalf("工具块头不对: %s", frames)
	}
	if !strings.Contains(frames, `"partial_json":"{\"a\":"`) {
		t.Fatalf("input_json_delta 不对: %s", frames)
	}
	if !strings.Contains(frames, `"stop_reason":"tool_use"`) {
		t.Fatalf("stop_reason 应为 tool_use: %s", frames)
	}
}

func TestStreamCloseWithoutFinish(t *testing.T) {
	tr := NewStreamTranslator("claude-x", 1)
	frames := feedAll(t, tr,
		`{"choices":[{"index":0,"delta":{"content":"半"}}]}`,
	)
	want := []string{"message_start", "content_block_start", "content_block_delta",
		"content_block_stop", "message_delta", "message_stop"}
	if got := eventNames(frames); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("断流收尾序列不对: %v", got)
	}
	if !strings.Contains(frames, `"stop_reason":"end_turn"`) {
		t.Fatalf("无 finish_reason 时应兜底 end_turn: %s", frames)
	}
}

func TestStreamCloseWithoutAnyChunk(t *testing.T) {
	tr := NewStreamTranslator("claude-x", 1)
	frames := tr.Close()
	want := []string{"message_start", "message_delta", "message_stop"}
	if got := eventNames(string(frames)); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("空流也必须给出合法事件序列: %v", got)
	}
}

func TestStreamFinalizedIsIdempotent(t *testing.T) {
	tr := NewStreamTranslator("claude-x", 1)
	frames := feedAll(t, tr,
		`{"choices":[{"index":0,"delta":{"content":"x"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`,
	)
	if n := strings.Count(frames, "event: message_stop"); n != 1 {
		t.Fatalf("message_stop 应恰好一个，实际 %d", n)
	}
	// 再喂/再关都不该再产出事件
	if f, _ := tr.Feed([]byte(`{"choices":[{"index":0,"delta":{"content":"y"}}]}`)); len(f) != 0 {
		t.Fatalf("收尾后 Feed 应静默，拿到 %s", f)
	}
	if f := tr.Close(); len(f) != 0 {
		t.Fatalf("收尾后 Close 应静默，拿到 %s", f)
	}
}

func TestStreamEventFramesAreValidSSE(t *testing.T) {
	tr := NewStreamTranslator("claude-x", 1)
	frames := feedAll(t, tr, `{"choices":[{"index":0,"delta":{"content":"你好 \"世界\""}}]}`)
	for _, block := range strings.Split(strings.TrimSpace(frames), "\n\n") {
		lines := strings.Split(block, "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[0], "event: ") || !strings.HasPrefix(lines[1], "data: ") {
			t.Fatalf("帧结构不对: %q", block)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[1], "data: ")), &payload); err != nil {
			t.Fatalf("data 不是合法 JSON: %v (%q)", err, block)
		}
		if payload["type"] == nil {
			t.Fatalf("事件缺 type: %q", block)
		}
	}
}
