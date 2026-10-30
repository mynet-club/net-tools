package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mynet-club/net-tools/llmproxy/internal/anthropic"
)

// Anthropic Messages 兼容入口（/v1/messages、/v1/messages/count_tokens）。
//
// 架构是**边缘翻译**：入口把 Anthropic 线格式翻成内部 chat/completions 形状，
// 交给 handleUpstreamPost 走完全一样的鉴权、限流、策略、选路、处理器与记账；
// 出口用 anthropicWriter 把响应（含 SSE 流）翻回 Anthropic 格式。管线一个字节
// 不改，治理面一视同仁地罩住两种协议进来的流量。
type anthropicReasoningKey struct{}

type anthropicReasoning struct {
	Thinking     json.RawMessage `json:"thinking,omitempty"`
	OutputConfig json.RawMessage `json:"output_config,omitempty"`
	effort       string
}

// writeAnthropicError 按 Anthropic 的错误形状回错：
// {"type":"error","error":{"type":…,"message":…}}。
func writeAnthropicError(w http.ResponseWriter, status int, kind, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":  "error",
		"error": map[string]string{"type": kind, "message": msg},
	})
}

// handleAnthropic 处理 POST /v1/messages 与 POST /v1/messages/count_tokens。
// 鉴权已完成（handleV1 在分发前统一做的）。
func (s *Server) handleAnthropic(w http.ResponseWriter, r *http.Request, auth authResult) {
	cfg := s.cfgStore.Current()
	r.Body = http.MaxBytesReader(w, r.Body, cfg.Server.MaxBodyBytes())
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeAnthropicError(w, http.StatusRequestEntityTooLarge, "request_too_large",
			fmt.Sprintf("请求体超过 %d MB 上限", cfg.Server.MaxBodyMB))
		return
	}

	var areq anthropic.Request
	if err := json.Unmarshal(raw, &areq); err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error",
			fmt.Sprintf("请求体不是合法 JSON: %v", err))
		return
	}

	if r.URL.Path == "/v1/messages/count_tokens" {
		_, est, err := anthropic.ToChat(&areq)
		if err != nil {
			writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]int{"input_tokens": est})
		return
	}

	// /v1/messages：Anthropic 侧 max_tokens 必填（count_tokens 共用形状但不要求）
	if areq.MaxTokens <= 0 {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error",
			"max_tokens 必须为正整数")
		return
	}
	chat, est, err := anthropic.ToChat(&areq)
	if err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	var original anthropicReasoning
	_ = json.Unmarshal(raw, &original)
	body, err := json.Marshal(struct {
		*anthropic.ChatRequest
		anthropicReasoning
	}{chat, original})
	if err != nil {
		writeAnthropicError(w, http.StatusInternalServerError, "api_error",
			fmt.Sprintf("内部请求编码失败: %v", err))
		return
	}

	// 合成内部请求：路径换成 /v1/chat/completions，其余头（鉴权、X-Identity-Token、
	// X-Request-Id、会话粘性）原样带过去 —— 策略与记账看到的与 OpenAI 协议请求无异。
	baseline := anthropicReasoning{effort: chat.ReasoningEffort}
	r2 := r.Clone(context.WithValue(r.Context(), anthropicReasoningKey{}, baseline))
	r2.URL.Path = "/v1/chat/completions"
	r2.Method = http.MethodPost
	r2.Body = io.NopCloser(bytes.NewReader(body))
	r2.ContentLength = int64(len(body))
	r2.Header.Set("Content-Type", "application/json")

	wrap := newAnthropicWriter(w, areq.Model, est)
	s.handleUpstreamPost(wrap, r2, auth)
	wrap.finish()
}

// 必须在处理器之后提取，原生配置里的文本同样需要脱敏，且不能恢复处理器已删除的字段。
func detachAnthropicReasoning(ctx context.Context, raw []byte) (context.Context, []byte, error) {
	baseline, ok := ctx.Value(anthropicReasoningKey{}).(anthropicReasoning)
	if !ok {
		return ctx, raw, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return ctx, nil, err
	}
	if fields == nil {
		return ctx, nil, fmt.Errorf("请求体不是 JSON 对象")
	}
	var current struct {
		Thinking        *anthropic.Thinking     `json:"thinking"`
		OutputConfig    *anthropic.OutputConfig `json:"output_config"`
		ReasoningEffort string                  `json:"reasoning_effort"`
	}
	if err := json.Unmarshal(raw, &current); err != nil {
		return ctx, nil, err
	}
	// 未显式改写通用强度时，以处理后的原生参数重算，避免两种表达发生分歧。
	if current.ReasoningEffort == baseline.effort {
		baseline.effort = anthropic.ReasoningEffort(current.Thinking, current.OutputConfig)
		delete(fields, "reasoning_effort")
		if baseline.effort != "" {
			fields["reasoning_effort"], _ = json.Marshal(baseline.effort)
		}
	}
	processed := anthropicReasoning{
		Thinking: fields["thinking"], OutputConfig: fields["output_config"],
		effort: baseline.effort,
	}
	delete(fields, "thinking")
	delete(fields, "output_config")
	body, err := json.Marshal(fields)
	if err != nil {
		return ctx, nil, err
	}
	return context.WithValue(ctx, anthropicReasoningKey{}, processed), body, nil
}

// anthropicWriter 拦住管线写下来的 OpenAI 形状响应，翻成 Anthropic 形状再落给
// 真正的 ResponseWriter：流式逐帧翻（不缓冲整个流），非流式收完再翻，
// 错误体翻成 Anthropic 错误形状。
type anthropicWriter struct {
	w     http.ResponseWriter
	model string
	estIn int

	hdr    http.Header
	status int
	wrote  bool
	mode   int // 0 未定 / 1 json / 2 sse / 3 错误 json
	buf    bytes.Buffer
	sseBuf bytes.Buffer
	tr     *anthropic.StreamTranslator
}

const (
	modeJSON  = 1
	modeSSE   = 2
	modeError = 3
)

func newAnthropicWriter(w http.ResponseWriter, model string, estIn int) *anthropicWriter {
	return &anthropicWriter{w: w, model: model, estIn: estIn, hdr: http.Header{}}
}

func (a *anthropicWriter) Header() http.Header { return a.hdr }

func (a *anthropicWriter) WriteHeader(status int) {
	if a.wrote {
		return
	}
	a.wrote = true
	a.status = status
	ct := a.hdr.Get("Content-Type")
	switch {
	case status >= 400:
		a.mode = modeError
	case strings.Contains(ct, "text/event-stream"):
		a.mode = modeSSE
		a.tr = anthropic.NewStreamTranslator(a.model, a.estIn)
	default:
		a.mode = modeJSON
	}

	// 逐头透传，但长度与类型归翻译后的输出管（翻译后字节数必然不同）。
	dst := a.w.Header()
	for k, vs := range a.hdr {
		switch http.CanonicalHeaderKey(k) {
		case "Content-Length", "Content-Type", "Transfer-Encoding", "Connection":
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	if a.mode == modeSSE {
		dst.Set("Content-Type", "text/event-stream; charset=utf-8")
		dst.Set("Cache-Control", "no-cache")
	} else {
		dst.Set("Content-Type", "application/json; charset=utf-8")
	}
	a.w.WriteHeader(status)
}

func (a *anthropicWriter) Write(p []byte) (int, error) {
	if !a.wrote {
		a.WriteHeader(http.StatusOK)
	}
	if a.mode == modeSSE {
		a.sseBuf.Write(p)
		a.drainSSE()
		return len(p), nil
	}
	a.buf.Write(p)
	return len(p), nil
}

// Flush 让上游管线的流式 flush 语义保留：半包留在 sseBuf 里，整帧翻完立即冲。
func (a *anthropicWriter) Flush() {
	if a.mode == modeSSE {
		a.drainSSE()
	}
	if f, ok := a.w.(http.Flusher); ok {
		f.Flush()
	}
}

// drainSSE 把 sseBuf 里**完整的** OpenAI SSE 帧翻成 Anthropic 事件帧写出。
// 帧按空行分隔；data 载荷的 [DONE] 是流结束标记，翻不出来也不该翻。
func (a *anthropicWriter) drainSSE() {
	for {
		buf := a.sseBuf.Bytes()
		i := bytes.Index(buf, []byte("\n\n"))
		if i < 0 {
			return
		}
		frame := buf[:i]
		a.sseBuf.Next(i + 2)
		payload := sseDataPayload(frame)
		if payload == "" || payload == "[DONE]" {
			continue
		}
		out, err := a.tr.Feed([]byte(payload))
		if err != nil {
			// 翻不动的帧跳过：不合法的上游帧不该把整条流打断
			continue
		}
		if len(out) > 0 {
			_, _ = a.w.Write(out)
			if f, ok := a.w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}
}

// finish 在管线写完后收尾：流式补收尾事件，非流式翻完整响应，错误体翻错误形状。
func (a *anthropicWriter) finish() {
	if !a.wrote {
		a.WriteHeader(http.StatusOK)
	}
	switch a.mode {
	case modeSSE:
		a.drainSSE()
		if a.tr == nil {
			a.tr = anthropic.NewStreamTranslator(a.model, a.estIn)
		}
		if out := a.tr.Close(); len(out) > 0 {
			_, _ = a.w.Write(out)
		}
		a.Flush()
	case modeError:
		a.writeTranslatedError()
	default:
		a.writeTranslatedMessage()
	}
}

func (a *anthropicWriter) writeTranslatedMessage() {
	var resp anthropic.ChatResponse
	if err := json.Unmarshal(a.buf.Bytes(), &resp); err != nil {
		writeAnthropicBody(a.w, map[string]any{
			"type": "error",
			"error": map[string]string{
				"type":    "api_error",
				"message": "上游响应翻译失败：" + err.Error(),
			},
		})
		return
	}
	out, err := anthropic.FromChat(&resp, a.model)
	if err != nil {
		writeAnthropicBody(a.w, map[string]any{
			"type":  "error",
			"error": map[string]string{"type": "api_error", "message": err.Error()},
		})
		return
	}
	writeAnthropicBody(a.w, out)
}

// writeTranslatedError 把 OpenAI 形状的错误体翻成 Anthropic 错误形状。
// 形状对不上时把原文收进 message，别把上游的诊断吞掉。
func (a *anthropicWriter) writeTranslatedError() {
	var oe struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	kind := "api_error"
	msg := strings.TrimSpace(a.buf.String())
	if err := json.Unmarshal(a.buf.Bytes(), &oe); err == nil && oe.Error.Message != "" {
		msg = oe.Error.Message
		if oe.Error.Type != "" {
			kind = oe.Error.Type
		}
	}
	writeAnthropicBody(a.w, map[string]any{
		"type":  "error",
		"error": map[string]string{"type": kind, "message": msg},
	})
}

func writeAnthropicBody(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
}

// sseDataPayload 从一个 SSE 帧里抽出 data 载荷 —— 帧解析口径与出网侧共用
// （anthropic.SSEDataPayload），两处各写一份迟早走偏。
var sseDataPayload = anthropic.SSEDataPayload

// 确认 anthropicWriter 仍满足 http.Flusher（relay 的流式路径按它判断）。
var _ http.Flusher = (*anthropicWriter)(nil)
