package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
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

// adminTestProvider 测某一家系统上游的**某一个模型**（界面上就是每条映射右边那个「测试」）。
//
// 请求里可以内联 base_url / api_key / proxy，理由与 discover 相同：界面刚改完还没保存时
// 也要能测，否则又是「先保存才能验」那个别扭的顺序。这不扩大权限 —— 调用方本来就能把
// 同一个地址配成上游、让网关拿同一把密钥去请求。
func (s *Server) adminTestProvider(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 POST")
		return
	}
	var req struct {
		Model   string `json:"model"`
		BaseURL string `json:"base_url"`
		APIKey  string `json:"api_key"`
		Proxy   string `json:"proxy"`
	}
	_ = readJSONBody(w, r, &req)

	providers := s.globalProviders()
	var found *config.Provider
	for i := range providers {
		if providers[i].Name == name {
			found = &providers[i]
			break
		}
	}
	inlineBase := strings.TrimSpace(req.BaseURL)
	if found == nil && inlineBase == "" {
		writeJSONError(w, http.StatusNotFound, "not_found",
			fmt.Sprintf("系统上游里没有 %q，也没带 base_url（用 GET /v1/_admin/providers 看有哪些）", name))
		return
	}

	prov := config.Provider{Name: name, Enabled: true}
	if found != nil {
		prov = *found
	}
	if inlineBase != "" {
		prov.BaseURL = inlineBase
	}
	if k := strings.TrimSpace(req.APIKey); k != "" {
		prov.APIKey = k
	}
	if v := strings.TrimSpace(req.Proxy); v != "" {
		ref, err := config.NormalizeProxy(v, s.cfgStore.Current().ProxyIndex)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
			return
		}
		prov.Proxy = ref
	}
	if strings.TrimSpace(prov.BaseURL) == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "缺 base_url：先填上游地址")
		return
	}
	if strings.TrimSpace(prov.APIKey) == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"缺 api_key：新加的供应商要先填密钥（已存在的留空则沿用保存过的那把）")
		return
	}

	model := strings.TrimSpace(req.Model)
	if model == "" && found != nil {
		// 没指定就挑它声明过的第一个**上游**模型名（映射的右边）。
		// 不能拿下游名：映射允许改名（a: b），拿下游名等于把一个上游不认识的名字打过去。
		ups := make([]string, 0, len(found.Models.Map))
		for _, up := range found.Models.Map {
			if up != "" && up != "*" {
				ups = append(ups, up)
			}
		}
		sort.Strings(ups)
		if len(ups) > 0 {
			model = ups[0]
		}
	}
	if model == "" {
		// 直通型（没声明任何具体模型名）又不给 model：问上游要一份模型列表，拿第一个真实的
		// 名字去测。直通下「这家通不通、密钥认不认」就是全部要回答的问题，
		// 而随便编一个名字打过去只会换回一个 404，那不叫测试。
		proxyURL, err := prov.Proxy.Resolve(s.cfgStore.Current().ProxyIndex)
		if err != nil {
			writeJSON(w, http.StatusOK, testOutcome{Error: "上游代理配置有问题：" + err.Error()})
			return
		}
		ids, err := s.fetchModelIDs(r.Context(), prov.BaseURL, prov.APIKey, proxyURL, true)
		if err != nil {
			writeJSON(w, http.StatusOK, testOutcome{
				Error: "这家上游是直通型、又没声明模型名，想自动挑一个来测，但它没给出模型列表：" +
					err.Error() + "。改在「指定映射」里加一条带模型名的映射再测",
			})
			return
		}
		model = ids[0]
	}

	// 探测的语义是「把这个名字原样打给上游」，所以强制直通：
	// 上游到底认哪些名字由它自己的 /v1/models 说了算，不该被本地的映射声明挡在前面 ——
	// 「映射表里还没有这个名字」恰恰是来测它的常见原因。
	prov.Models = config.ModelSpec{Passthrough: true}

	out := s.runUpstreamTest(r.Context(), "", []config.Provider{prov}, model)
	s.log.Infof("管理员测试了系统上游 %s 的模型 %s（ok=%v）", name, model, out.OK)
	writeJSON(w, http.StatusOK, out)
}
