package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

// 管理台的「快速测试」：按某个作用域（或某个上游）真发一条请求。
//
// 这是给人确认「这条映射/这家上游到底通不通」用的探针，所以：
//   - max_tokens 压到 8 —— 它是探针，不是替用户跑业务（真实花费是几个 token）；
//   - **不写记账、不报熔断**：管理员的探测不该算到用户配额上，也不该影响路由状态；
//   - 打的是映射之后的真实模型名，所以「模型名写错了」这类问题也能测出来。
const (
	testMaxTokens = 8
	testTimeout   = 20 * time.Second
	testPrompt    = "ping"
)

type testOutcome struct {
	OK            bool   `json:"ok"`
	Provider      string `json:"provider,omitempty"`
	UpstreamModel string `json:"upstream_model,omitempty"`
	Status        int    `json:"status,omitempty"`
	LatencyMs     int64  `json:"latency_ms"`
	TTFTMs        int64  `json:"ttft_ms,omitempty"`
	Content       string `json:"content,omitempty"`
	Tokens        int64  `json:"tokens,omitempty"`
	Error         string `json:"error,omitempty"`
	Note          string `json:"note,omitempty"`
}

// runUpstreamTest 用给定的候选上游与模型发一条极小请求。
func (s *Server) runUpstreamTest(ctx context.Context, scope string, providers []config.Provider, model string) testOutcome {
	if strings.TrimSpace(model) == "" {
		return testOutcome{Error: "没有指定要测的模型"}
	}
	cand, err := s.router.PickFrom(scope, providers, model, map[string]bool{})
	if err != nil {
		// 选不出候选：把原因说清楚（收窄？池子里没有？上游都不可用？）
		msg := err.Error()
		if note := s.unusableNote(scope); note != "" {
			msg = note
		}
		return testOutcome{Error: "选不出可用上游：" + msg}
	}

	proxyURL, err := cand.Provider.Proxy.Resolve(s.cfgStore.Current().ProxyIndex)
	if err != nil {
		return testOutcome{Error: "上游 %s 的代理配置有问题: " + err.Error(), Provider: cand.Provider.Name}
	}
	tr, err := s.transports.Get(proxyURL)
	if err != nil {
		return testOutcome{Error: "构造上游连接失败: " + err.Error(), Provider: cand.Provider.Name}
	}

	body, err := json.Marshal(map[string]any{
		"model":      cand.UpstreamModel,
		"messages":   []map[string]string{{"role": "user", "content": testPrompt}},
		"max_tokens": testMaxTokens,
		"stream":     false,
	})
	if err != nil {
		return testOutcome{Error: err.Error()}
	}

	timeout := testTimeout
	if t := time.Duration(cand.Provider.TimeoutMs) * time.Millisecond; t > 0 && t < timeout {
		timeout = t
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	upURL := strings.TrimSuffix(cand.Provider.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upURL, bytes.NewReader(body))
	if err != nil {
		return testOutcome{Error: err.Error(), Provider: cand.Provider.Name, UpstreamModel: cand.UpstreamModel}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cand.Provider.APIKey)
	req.Header.Set("User-Agent", "llmproxy/"+config.Version)

	out := testOutcome{Provider: cand.Provider.Name, UpstreamModel: cand.UpstreamModel}
	started := time.Now()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		out.LatencyMs = time.Since(started).Milliseconds()
		out.Error = "连不上上游：" + err.Error()
		if strings.Contains(err.Error(), "context deadline exceeded") {
			out.Error = fmt.Sprintf("上游 %s 在 %s 内没有响应", upURL, timeout)
		}
		return out
	}
	defer func() { _ = resp.Body.Close() }()
	out.TTFTMs = time.Since(started).Milliseconds()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	out.LatencyMs = time.Since(started).Milliseconds()
	out.Status = resp.StatusCode
	if resp.StatusCode >= 400 {
		out.Error = fmt.Sprintf("上游返回 HTTP %d", resp.StatusCode)
		if snippet := strings.TrimSpace(string(raw)); snippet != "" {
			if len(snippet) > 300 {
				snippet = snippet[:300] + "…"
			}
			out.Error += "：" + snippet
		}
		return out
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage *struct {
			TotalTokens int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &parsed); err == nil {
		if len(parsed.Choices) > 0 {
			out.Content = parsed.Choices[0].Message.Content
		}
		if parsed.Usage != nil {
			out.Tokens = parsed.Usage.TotalTokens
		}
	}
	out.OK = true
	out.Note = "这是一次真实请求（最多 8 个 token），不计入任何用户的配额，也不影响熔断状态"
	return out
}

// adminTestUser 按某个用户的路由发一条测试请求（用在「模型范围」的每条映射上）。
func (s *Server) adminTestUser(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 POST")
		return
	}
	if u, err := s.db.GetUser(name); err != nil || u == nil {
		writeJSONError(w, http.StatusNotFound, "not_found", fmt.Sprintf("用户 %q 不存在", name))
		return
	}
	var req struct {
		Model string `json:"model"`
	}
	if err := readJSONBody(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	model := strings.TrimSpace(req.Model)
	if model == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "缺少 model")
		return
	}

	providers, _ := s.providersFor(name, model)
	if len(providers) == 0 {
		// 与真实请求同样的归因，免得测试说「没上游」而真请求说「403」
		if consumption, narrowed, listed := s.consumptionVerdict(name, model); consumption && narrowed && !listed {
			writeJSON(w, http.StatusOK, testOutcome{
				Error: fmt.Sprintf("模型 %q 不在这个用户的可用范围内（管理员给他收窄了）", model),
			})
			return
		}
		msg := "没有可用的上游供应商"
		if note := s.unusableNote(name); note != "" {
			msg = note
		}
		writeJSON(w, http.StatusOK, testOutcome{Error: msg})
		return
	}
	// 用该用户的作用域去选，这样熔断状态与真实请求一致
	out := s.runUpstreamTest(r.Context(), name, providers, model)
	s.log.Infof("管理员测试了用户 %s 的模型 %s → 上游 %s（ok=%v）", name, model, out.Provider, out.OK)
	writeJSON(w, http.StatusOK, out)
}

// adminTestProvider 直接测某一家系统上游（用来确认「这家配得对不对」）。
func (s *Server) adminTestProvider(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 POST")
		return
	}
	providers := s.globalProviders()
	var found *config.Provider
	for i := range providers {
		if providers[i].Name == name {
			found = &providers[i]
			break
		}
	}
	if found == nil {
		writeJSONError(w, http.StatusNotFound, "not_found",
			fmt.Sprintf("系统上游里没有 %q", name))
		return
	}

	var req struct {
		Model string `json:"model"`
	}
	_ = readJSONBody(w, r, &req)
	model := strings.TrimSpace(req.Model)
	if model == "" {
		// 没指定就用它声明的第一个模型名；直通型没有名字可挑，只能让调用方给
		names := make([]string, 0, len(found.Models.Map))
		for down := range found.Models.Map {
			if down != "*" {
				names = append(names, down)
			}
		}
		if len(names) > 0 {
			model = names[0]
		}
	}
	if model == "" {
		writeJSON(w, http.StatusOK, testOutcome{
			Error: "这家上游没有声明具体的模型名（可能是直通），测试时要指定一个 model",
		})
		return
	}
	out := s.runUpstreamTest(r.Context(), "", []config.Provider{*found}, model)
	s.log.Infof("管理员测试了系统上游 %s（模型 %s，ok=%v）", name, model, out.OK)
	writeJSON(w, http.StatusOK, out)
}
