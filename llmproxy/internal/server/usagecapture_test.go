package server

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// 这个文件钉住的是一条不变式：**只要上游回报了 usage，网关就必须拿到它**。
//
// 拿不到的后果不是「少记一笔」，而是这条请求的 token 与金额全部记 0、配额一分不扣，
// 而上游照样向我们收钱 —— freeze.go 的两处冻结都因 PromptTokens == nil 直接 return，
// limits.go 的估算兜底也是按 token 数算的，token 是 0 就救不回来。
// 下面两个用例分别堵住两条绕过路径。

// 客户端自带 stream_options 时，注入不能被整个跳过。
//
// 旧写法是「键不存在才注入」，于是客户端发 {"include_usage":false}、发一个空对象、
// 或者发某个我们认不出的方言字段，都能让上游不回报 usage —— 一个 JSON 字段就打开配额闸门。
// 计量是网关自己的需求，不该由下游客户端决定，所以这里一律覆盖 include_usage，
// 同时保留客户端的其他子字段（不破坏它原本的语义）。
func TestRewriteModelBodyForcesIncludeUsage(t *testing.T) {
	cases := []struct {
		name string
		body string
		want map[string]any
	}{
		{name: "没带 stream_options：注入",
			body: `{"model":"m","stream":true}`,
			want: map[string]any{"include_usage": true}},
		{name: "显式关掉 include_usage：仍被强制打开",
			body: `{"model":"m","stream":true,"stream_options":{"include_usage":false}}`,
			want: map[string]any{"include_usage": true}},
		{name: "空对象",
			body: `{"model":"m","stream":true,"stream_options":{}}`,
			want: map[string]any{"include_usage": true}},
		{name: "null",
			body: `{"model":"m","stream":true,"stream_options":null}`,
			want: map[string]any{"include_usage": true}},
		{name: "不是对象（数组）：整个换掉",
			body: `{"model":"m","stream":true,"stream_options":[1,2]}`,
			want: map[string]any{"include_usage": true}},
		{name: "带了别的子字段：保留它们，只覆盖 include_usage",
			body: `{"model":"m","stream":true,"stream_options":{"continuous_usage_stats":true,"include_usage":false}}`,
			want: map[string]any{"include_usage": true, "continuous_usage_stats": true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := rewriteModelBody([]byte(tc.body), "upstream-model", true)
			if err != nil {
				t.Fatalf("rewriteModelBody: %v", err)
			}
			var m map[string]any
			if err := json.Unmarshal(out, &m); err != nil {
				t.Fatalf("输出不是合法 JSON: %v (%s)", err, out)
			}
			if m["model"] != "upstream-model" {
				t.Errorf("model = %v，上游模型名没被替换", m["model"])
			}
			so, ok := m["stream_options"].(map[string]any)
			if !ok {
				t.Fatalf("stream_options 不是对象: %#v", m["stream_options"])
			}
			if so["include_usage"] != true {
				t.Errorf("include_usage = %#v，必须是 true（否则上游不回报 usage，这条请求记 0）", so["include_usage"])
			}
			if len(so) != len(tc.want) {
				t.Errorf("stream_options = %#v, want %#v", so, tc.want)
			}
			for k, v := range tc.want {
				if so[k] != v {
					t.Errorf("stream_options[%q] = %#v, want %#v", k, so[k], v)
				}
			}
		})
	}
}

// 非流式不该动 stream_options：那条请求本来就没有 SSE 末尾 chunk，
// 强行注入只会白白改掉客户端的字段。
func TestRewriteModelBodyNonStreamLeavesStreamOptionsAlone(t *testing.T) {
	out, err := rewriteModelBody(
		[]byte(`{"model":"m","stream_options":{"include_usage":false}}`), "up", false)
	if err != nil {
		t.Fatalf("rewriteModelBody: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("输出不是合法 JSON: %v (%s)", err, out)
	}
	so, _ := m["stream_options"].(map[string]any)
	if so["include_usage"] != false {
		t.Errorf("非流式请求的 stream_options 被改动了: %#v", m["stream_options"])
	}
}

// 改写 body 不能破坏其他字段的数值精度（这是 rewriteModelBody 用 json.RawMessage 的理由）。
func TestRewriteModelBodyPreservesPrecisionAndFields(t *testing.T) {
	body := `{"model":"m","stream":true,"temperature":1.0000000000000002,` +
		`"big":123456789012345678901234567890,"messages":[{"role":"user","content":"hi"}]}`
	out, err := rewriteModelBody([]byte(body), "up", true)
	if err != nil {
		t.Fatalf("rewriteModelBody: %v", err)
	}
	got := string(out)
	for _, want := range []string{
		`1.0000000000000002`,
		`123456789012345678901234567890`,
		`"role":"user"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("输出里找不到 %s（精度或字段被破坏）: %s", want, got)
		}
	}
}

// errWriter 模拟「写向下游失败」—— 客户端断开、或网络抖动。
type errWriter struct{}

func (errWriter) Write(p []byte) (int, error) { return 0, errors.New("client gone") }

const usageSSE = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"}}]}\n\n" +
	"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\n" +
	"data: [DONE]\n\n"

// relay 的写法是 io.Copy(io.MultiWriter(scanner, dest), body)（forwarder.go 的 SSE 分支）。
// scanner 必须排在 dest 前面：MultiWriter 在任一 writer 出错时立即停止、不再写后面的，
// 而 usage 恰恰在流的末尾。反过来的话，一次「内容已从上游读到、写向下游时失败」的转发
// 会把 usage 一起丢掉 —— 上游那边 token 已经生成、钱已经付了，我们这边一条都记不上。
//
// 这个顺序不显眼、改回去也不会编译失败，所以两个方向都断言一遍。
func TestUsageScannerPrecedesDownstreamWriter(t *testing.T) {
	t.Run("scanner 在前：下游写失败仍捕获 usage", func(t *testing.T) {
		scanner := &usageScanner{start: time.Now()}
		if _, err := io.Copy(io.MultiWriter(scanner, errWriter{}), strings.NewReader(usageSSE)); err == nil {
			t.Fatal("期望下游写失败，却没有报错")
		}
		if scanner.usage.PromptTokens == nil {
			t.Fatal("usage 丢了：scanner 必须排在 MultiWriter 的第一位")
		}
		if got := *scanner.usage.PromptTokens; got != 11 {
			t.Errorf("PromptTokens = %d, want 11", got)
		}
		if got := *scanner.usage.CompletionTokens; got != 7 {
			t.Errorf("CompletionTokens = %d, want 7", got)
		}
	})

	// 对照组：钉住「顺序反了就会丢」这个前提本身，而不是 stdlib 的偶然行为。
	// 如果哪天这条断言失败了，说明 MultiWriter 的语义变了，
	// 那么 forwarder.go 里的顺序以及上面那条用例都需要重新评估。
	t.Run("对照：scanner 在后则 usage 丢失", func(t *testing.T) {
		scanner := &usageScanner{start: time.Now()}
		_, _ = io.Copy(io.MultiWriter(errWriter{}, scanner), strings.NewReader(usageSSE))
		if scanner.usage.PromptTokens != nil {
			t.Error("对照组本该丢掉 usage —— io.MultiWriter 的语义变了？请重新确认 forwarder.go 里的顺序")
		}
	})
}

// scanner 从不报错，所以把它放在 MultiWriter 第一位是安全的：
// 它绝不会成为那个截断下游数据的原因。
func TestUsageScannerWriteNeverFails(t *testing.T) {
	scanner := &usageScanner{start: time.Now()}
	for _, p := range [][]byte{nil, {}, []byte("garbage"), []byte(usageSSE)} {
		n, err := scanner.Write(p)
		if err != nil {
			t.Fatalf("Write(%q) 报错: %v（它必须恒不报错，否则会截断给客户端的数据）", p, err)
		}
		if n != len(p) {
			t.Fatalf("Write(%q) = %d, want %d", p, n, len(p))
		}
	}
}
