package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mynet-club/net-tools/llmproxy/internal/anthropic"
	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

// anthropicTransport 是二次翻转的出网侧。
//
// 治理核（策略、选路、限流、记账、旁路扫描、客户端侧包装器）一律只认 OpenAI 形状；
// 只有真正发往 Anthropic 协议上游的这一跳做形变：请求翻成 /v1/messages，
// 响应（含 SSE 流与错误体）翻回 OpenAI 形状。翻译只搬语义，不参与任何判定。
//
// 路径口径与 OpenAI 侧对称：base_url 一律填到 /v1 一层（如 https://host/v1），
// chat 交换打到 <base_url>/messages。非 chat 端点（/v1/embeddings 之类）不是
// Messages 族，原样放行让上游自己报错 —— 翻成 /v1/messages 只会把错误搅浑。
type anthropicTransport struct {
	inner http.RoundTripper
}

// wrapAnthropicTransport 只对 anthropic_messages 协议的供应商包翻译层。
func wrapAnthropicTransport(tr http.RoundTripper, prov *config.Provider) http.RoundTripper {
	if prov != nil && prov.Protocol == config.ProtocolAnthropicMessages {
		return &anthropicTransport{inner: tr}
	}
	return tr
}

func (t *anthropicTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || !strings.HasSuffix(req.URL.Path, "/chat/completions") {
		return t.inner.RoundTrip(req)
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("读取待翻译请求体失败: %w", err)
	}
	_ = req.Body.Close()

	var chat anthropic.ChatRequest
	if err := json.Unmarshal(raw, &chat); err != nil {
		return nil, fmt.Errorf("请求体不是 chat/completions 形状: %w", err)
	}
	msgReq, err := anthropic.ToMessages(&chat)
	if err != nil {
		return nil, fmt.Errorf("请求翻不成 Messages 形状: %w", err)
	}
	body, err := json.Marshal(msgReq)
	if err != nil {
		return nil, fmt.Errorf("Messages 请求编码失败: %w", err)
	}

	out := req.Clone(req.Context())
	out.URL.Path = strings.TrimSuffix(req.URL.Path, "/chat/completions") + "/messages"
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	out.Header.Set("Content-Type", "application/json")
	// Anthropic 官方认 x-api-key + anthropic-version；不少兼容端点只认 Bearer —— 双带。
	if auth := out.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		out.Header.Set("x-api-key", strings.TrimPrefix(auth, "Bearer "))
	}
	out.Header.Set("anthropic-version", "2023-06-01")

	resp, err := t.inner.RoundTrip(out)
	if err != nil {
		return nil, err
	}
	return translateAnthropicResp(resp, chat.Model), nil
}

// translateAnthropicResp 把 Anthropic 上游响应翻回 OpenAI 形状（三种形态：
// 错误体、SSE 流、整体 JSON）。响应头里的长度与类型随形变作废，由上层重新声明。
func translateAnthropicResp(resp *http.Response, fallbackModel string) *http.Response {
	ct := resp.Header.Get("Content-Type")
	switch {
	case resp.StatusCode >= 400:
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamResponseBytes))
		_ = resp.Body.Close()
		setTranslatedBody(resp, translateAnthropicError(raw))
	case strings.Contains(ct, "text/event-stream"):
		resp.Body = &anthropicStreamReader{src: resp.Body, tr: anthropic.NewRevStreamTranslator()}
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
	default:
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamResponseBytes))
		_ = resp.Body.Close()
		var mr anthropic.Response
		if err == nil {
			err = json.Unmarshal(raw, &mr)
		}
		var out []byte
		if err == nil {
			var chat *anthropic.ChatResponse
			chat, err = anthropic.FromMessages(&mr)
			if err == nil {
				if chat.Model == "" {
					chat.Model = fallbackModel
				}
				out, err = json.Marshal(chat)
			}
		}
		if err != nil {
			// 翻不动就别装作翻好了：包成一个 OpenAI 形状的错误体，让上层按
			// 「这家的响应不可用」归因，而不是把 Anthropic 原文塞给 OpenAI 客户端。
			out = mustJSONBytes(map[string]any{"error": map[string]string{
				"type":    "api_error",
				"message": "Anthropic 上游响应翻不回 chat 形状：" + err.Error(),
			}})
		}
		setTranslatedBody(resp, out)
	}
	return resp
}

// translateAnthropicError 把 Anthropic 错误体翻成 OpenAI 错误形状。
// 形状对不上时保留原文进 message，不吞上游诊断。
func translateAnthropicError(raw []byte) []byte {
	var ae struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	kind := "api_error"
	msg := strings.TrimSpace(string(raw))
	if err := json.Unmarshal(raw, &ae); err == nil && ae.Error.Message != "" {
		msg = ae.Error.Message
		if ae.Error.Type != "" {
			kind = ae.Error.Type
		}
	}
	return mustJSONBytes(map[string]any{"error": map[string]string{"type": kind, "message": msg}})
}

// setTranslatedBody 换掉响应体并作废长度头（翻译后字节数必然不同）。
func setTranslatedBody(resp *http.Response, body []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Del("Content-Length")
	resp.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp.Header.Del("Content-Encoding")
}

func mustJSONBytes(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"error":{"type":"api_error","message":"内部编码失败"}}`)
	}
	return b
}

// anthropicStreamReader 把上游的 Anthropic SSE 流逐帧翻成 OpenAI chunk 流。
// 半包在 RevStreamTranslator 内部攒；EOF 时补收尾（finish/usage/[DONE]）。
type anthropicStreamReader struct {
	src io.ReadCloser
	tr  *anthropic.RevStreamTranslator
	buf bytes.Buffer
	eof bool
}

func (r *anthropicStreamReader) Read(p []byte) (int, error) {
	for r.buf.Len() == 0 && !r.eof {
		tmp := make([]byte, 32<<10)
		n, err := r.src.Read(tmp)
		if n > 0 {
			r.buf.Write(r.tr.FeedBytes(tmp[:n]))
		}
		if err == io.EOF {
			r.eof = true
			r.buf.Write(r.tr.Close())
		} else if err != nil {
			return 0, err
		}
	}
	return r.buf.Read(p)
}

func (r *anthropicStreamReader) Close() error { return r.src.Close() }
