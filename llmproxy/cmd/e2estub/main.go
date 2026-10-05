// 端到端验证用的假上游：每个请求往日志里记一笔自己是谁，响应体也带上自己的名字，
// 这样就能断言「alice 的请求到底被哪个上游接走了」。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// echoModel 是一个有特殊含义的模型名：打到它的请求，假上游把**收到的最后一条消息**
// 原样回进响应。
//
// 为什么要在假上游里长这一个分支：正文改写（pii-mask 的占位符）发生在网关进程内，
// 而「改写真的到达了进程之外」只有出网那一头能证明 —— 客户端看到的回话是上游给的，
// 上游复述自己收到了什么，才把「网关只是本地改了一份」这条路堵掉。
// 名字里带 e2e 且不与任何真实模型重名，所以既有断言（响应恒为 served-by:<名字>）不受影响。
const echoModel = "e2e-echo"

// echoMessage 是 probe 里的一条消息。正文保持 JSON 原样，见 lastMessageText。
type echoMessage struct {
	Content json.RawMessage `json:"content"`
}

func main() {
	name := flag.String("name", "stub", "上游标识")
	port := flag.Int("port", 19101, "监听端口")
	logPath := flag.String("log", "/tmp/stub.log", "命中日志")
	modelList := flag.String("models", "", "GET /v1/models 返回的模型名，逗号分隔（空 = 不提供该接口）")
	flag.Parse()

	f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var hits int64
	http.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		// stream / stream_options 要逐字记下来：端到端那一头只有「上游真收到了什么」
		// 能证明网关的正文改写（模型名、include_usage）真的到达了进程之外。
		var probe struct {
			Model         string `json:"model"`
			Stream        bool   `json:"stream"`
			StreamOptions *struct {
				IncludeUsage bool `json:"include_usage"`
			} `json:"stream_options"`
			// content 用 RawMessage 接：多模态请求里它是数组，按 string 解码会让
			// 整个 probe 解析失败（连 model/stream 都读不出来），而这两件是既有断言的依据。
			Messages []echoMessage `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&probe)
		_, _ = fmt.Fprintf(f, "%s %s model=%s stream=%t include_usage=%t\n",
			time.Now().Format("15:04:05"), *name, probe.Model, probe.Stream,
			probe.StreamOptions != nil && probe.StreamOptions.IncludeUsage)

		// 回话内容：默认只报「我是谁」；echo 模型复述收到的最后一条消息。
		parts := []string{"served-by:", *name}
		if probe.Model == echoModel {
			parts = []string{lastMessageText(probe.Messages)}
		}

		if probe.Stream {
			// 流式：逐段吐、每段都 flush，客户端据此判断网关有没有「缓存整包再发」。
			w.Header().Set("Content-Type", "text/event-stream")
			fl, _ := w.(http.Flusher)
			chunk := func(o map[string]any) {
				data, err := json.Marshal(o)
				if err != nil {
					return
				}
				_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
				if fl != nil {
					fl.Flush()
				}
			}
			base := map[string]any{
				"id": "chatcmpl-e2e", "object": "chat.completion.chunk",
				"created": time.Now().Unix(), "model": probe.Model,
			}
			for _, part := range parts {
				chunk(withBase(base, map[string]any{
					"choices": []map[string]any{{"index": 0, "delta": map[string]string{"content": part}}},
				}))
			}
			chunk(withBase(base, map[string]any{
				"choices": []map[string]any{},
				"usage":   map[string]int{"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
			}))
			_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
			if fl != nil {
				fl.Flush()
			}
			return
		}

		resp := map[string]any{
			"id": "chatcmpl-e2e", "object": "chat.completion",
			"created": time.Now().Unix(), "model": probe.Model,
			"choices": []map[string]any{{
				"index":         0,
				"message":       map[string]string{"role": "assistant", "content": strings.Join(parts, "")},
				"finish_reason": "stop",
			}},
			"usage": map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	http.HandleFunc("/hits", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%d", atomic.LoadInt64(&hits))
	})

	// /v1/models：给「从上游同步模型列表」用。不传 -models 就 404，
	// 正好用来验证「上游不提供该接口时界面要引导到手动添加」。
	http.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		if *modelList == "" {
			http.NotFound(w, r)
			return
		}
		data := []map[string]any{}
		for _, id := range strings.Split(*modelList, ",") {
			id = strings.TrimSpace(id)
			if id != "" {
				data = append(data, map[string]any{"id": id, "object": "model"})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
	})

	if err := http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", *port), nil); err != nil {
		panic(err)
	}
}

// withBase 把公共字段与这一帧的字段合成一帧（不改 base，逐帧共用同一张底表）。
func withBase(base map[string]any, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// lastMessageText 取最后一条消息的正文文本。
//
// 是字符串就原样返回；是数组或多模态结构就返回其 JSON 形态 —— 复述的是「我收到了这么
// 一段东西」，把结构拆开重组会让断言要按本工具的字段布局写，那不是端到端该锁的东西。
func lastMessageText(msgs []echoMessage) string {
	if len(msgs) == 0 {
		return ""
	}
	raw := msgs[len(msgs)-1].Content
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}
