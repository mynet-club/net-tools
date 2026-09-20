package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

// 上游模型列表的探测：界面靠它把「手写映射」变成「勾选」。
//
// 两个刻意的约束：
//
//  1. 响应体只用来提取模型名，**原样丢弃、不回传给客户端** —— 否则这个接口
//     就成了一个「带鉴权的通用 GET 代理」，能被用来读上游的其它响应。
//  2. 允许在请求里内联 base_url / api_key（配合「刚填好、还没保存」就点同步的场景）。
//     这不扩大权限：用户本来就能把同一个地址配成上游、让网关拿他的密钥去请求。
const discoverTimeout = 15 * time.Second

// discoverUpstreamModels 用用户自己的上游配置拉一次 /v1/models。
func (s *Server) discoverUpstreamModels(w http.ResponseWriter, r *http.Request, e *userEntry, name string) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET / POST")
		return
	}
	if !validName(name) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "上游名不合法")
		return
	}

	var req struct {
		BaseURL string `json:"base_url"`
		APIKey  string `json:"api_key"`
	}
	if r.Method == http.MethodPost && r.Body != nil {
		// body 可以为空：那时表示用已保存的配置
		_ = readJSONBody(w, r, &req)
	}
	baseURL := strings.TrimSpace(req.BaseURL)
	apiKey := strings.TrimSpace(req.APIKey)

	var stored *config.Provider
	for i := range e.Providers {
		if e.Providers[i].Name == name {
			stored = &e.Providers[i]
			break
		}
	}
	if baseURL == "" {
		if stored == nil {
			writeJSONError(w, http.StatusNotFound, "not_found",
				fmt.Sprintf("上游 %q 还没有保存过：先保存一次，或在请求里带上 base_url", name))
			return
		}
		baseURL = stored.BaseURL
	}
	if apiKey == "" && stored != nil {
		apiKey = stored.APIKey
	}
	if apiKey == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"缺少上游 api_key：先保存一次，或在请求里带上")
		return
	}

	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"base_url 必须是 http/https 开头的合法 URL")
		return
	}

	// 用户的上游该走代理就走代理：与转发时用同一套连接层
	proxyURL := ""
	if stored != nil {
		if resolved, err := stored.Proxy.Resolve(s.cfgStore.Current().ProxyIndex); err == nil {
			proxyURL = resolved
		}
	}
	tr, err := s.transports.Get(proxyURL)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "构造上游连接失败: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), discoverTimeout)
	defer cancel()

	target := strings.TrimSuffix(baseURL, "/") + "/models"
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "构造请求失败: "+err.Error())
		return
	}
	hreq.Header.Set("Authorization", "Bearer "+apiKey)
	hreq.Header.Set("Accept", "application/json")
	hreq.Header.Set("User-Agent", "llmproxy/"+config.Version)

	resp, err := tr.RoundTrip(hreq)
	if err != nil {
		msg := "连不上上游：" + err.Error()
		if strings.Contains(err.Error(), "context deadline exceeded") {
			msg = fmt.Sprintf("上游 %s 在 %s 内没有响应", target, discoverTimeout)
		}
		writeJSONError(w, http.StatusBadGateway, "upstream_unreachable", msg)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		writeJSONError(w, http.StatusBadGateway, "upstream_denied",
			fmt.Sprintf("上游拒绝了这把密钥（HTTP %d）：检查 api_key 是否正确", resp.StatusCode))
		return
	}
	// 404/405 基本就是「这家不提供 /v1/models」：这不是故障，是常态，
	// 所以直接把用户引到手动添加，而不是甩一个 HTTP 状态码让他猜。
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		writeJSONError(w, http.StatusUnprocessableEntity, "no_models",
			"这个上游没有提供 /v1/models（它可能只支持对话接口）。用「手动添加」把模型名写上就行")
		return
	}
	if resp.StatusCode >= 400 {
		writeJSONError(w, http.StatusBadGateway, "upstream_error",
			fmt.Sprintf("上游返回 HTTP %d", resp.StatusCode))
		return
	}

	models := parseModelIDs(body)
	if len(models) == 0 {
		writeJSONError(w, http.StatusUnprocessableEntity, "no_models",
			"没从这个上游解析出模型列表（它可能不提供 /v1/models）。先用「手动添加」把模型名写上")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"models":     models,
		"count":      len(models),
		"base_url":   baseURL,
		"fetched_at": time.Now().Format(time.RFC3339),
	})
}

type modelEntry struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Model string `json:"model"`
}

// parseModelIDs 尽量宽容地解析上游的模型列表。
//
// OpenAI 标准是 {"data":[{"id":"..."}]}，但自建/兼容端点的形态五花八门，
// 这里把常见的几种都试一遍 —— 猜错的代价只是让用户手动加，比直接报错好。
func parseModelIDs(raw []byte) []string {
	var probe struct {
		Data   []modelEntry `json:"data"`
		Models []modelEntry `json:"models"`
	}
	seen := map[string]bool{}
	out := []string{}
	add := func(list []modelEntry) {
		for _, m := range list {
			id := strings.TrimSpace(m.ID)
			if id == "" {
				id = strings.TrimSpace(m.Name)
			}
			if id == "" {
				id = strings.TrimSpace(m.Model)
			}
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	if err := json.Unmarshal(raw, &probe); err == nil {
		add(probe.Data)
		add(probe.Models)
	}
	// 也接受裸数组：["a","b"] 或 [{"id":"a"}]
	if len(out) == 0 {
		var ids []string
		if err := json.Unmarshal(raw, &ids); err == nil {
			for _, id := range ids {
				id = strings.TrimSpace(id)
				if id != "" && !seen[id] {
					seen[id] = true
					out = append(out, id)
				}
			}
		} else {
			var entries []modelEntry
			if err := json.Unmarshal(raw, &entries); err == nil {
				add(entries)
			}
		}
	}
	sort.Strings(out)
	return out
}
