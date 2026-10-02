package server

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// userMode 把库里的用户模式规范化成对外名字。
func userMode(u *store.User) string {
	if u != nil && u.IsConsumption() {
		return store.ModeConsumption
	}
	return store.ModeBYO
}

// 管理接口：管理员用 admin_token 操作别人。
//
// 与管理相关的读操作都走这里，因为管理员要看的不是「我自己的那一片」，而是整台网关：
// 谁在用、用了多少、什么模式、配额还剩多少、模型映射配了什么。
//
// 模型名不经 URL 路径传递（放 body 或 query）：模型名里可能带 "/"，
// 比如 qwen/qwen-max —— 塞进路径就得处理转义，放请求体里没这个问题。

func (s *Server) adminUsersRoute(w http.ResponseWriter, r *http.Request, tail string) {
	// 集合：GET 列表 / POST 建用户
	if tail == "" {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.adminListUsers(w)
		case http.MethodPost:
			s.adminCreateUser(w, r)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
				fmt.Sprintf("不支持的方法 %s", r.Method))
		}
		return
	}

	parts := strings.Split(tail, "/")
	name := parts[0]
	if !validName(name) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"用户名只能包含字母、数字、点、下划线、连字符，长度 1~64")
		return
	}
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	if len(parts) > 2 {
		writeJSONError(w, http.StatusNotFound, "invalid_request_error", "路径过深")
		return
	}

	switch action {
	case "":
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.adminShowUser(w, name)
		case http.MethodPut, http.MethodPost:
			s.adminUpdateUser(w, r, name)
		case http.MethodDelete:
			if err := s.db.DeleteUser(name); err != nil {
				writeJSONError(w, http.StatusNotFound, "not_found", err.Error())
				return
			}
			s.router.ForgetScope(name)
			if s.meters != nil {
				s.meters.Forget(name)
			}
			s.usageCache.InvalidateUser(name)
			_ = s.SyncUsers()
			s.audit("admin", "user.delete", name, "")
			s.log.Warnf("管理员删除了用户 %s", name)
			writeJSON(w, http.StatusOK, map[string]any{"deleted": name})
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
				fmt.Sprintf("不支持的方法 %s", r.Method))
		}
	case "token":
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 POST")
			return
		}
		token, err := store.NewToken()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		if err := s.db.SetUserToken(name, store.TokenHash(token)); err != nil {
			writeJSONError(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		_ = s.SyncUsers()
		s.log.Warnf("管理员轮换了用户 %s 的 token（旧 token 已失效）", name)
		writeJSON(w, http.StatusOK, map[string]any{
			"name":  name,
			"token": token,
			"note":  "明文只在这里返回一次，请立刻交给用户",
		})
	case "enable", "disable":
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 POST")
			return
		}
		if err := s.db.SetUserEnabled(name, action == "enable"); err != nil {
			writeJSONError(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		_ = s.SyncUsers()
		s.log.Warnf("管理员%s了用户 %s", map[bool]string{true: "启用", false: "停用"}[action == "enable"], name)
		writeJSON(w, http.StatusOK, map[string]any{"name": name, "enabled": action == "enable"})
	case "providers":
		s.adminUserProviders(w, r, name)
	case "models":
		s.adminUserModels(w, r, name)
	case "usage":
		s.adminUserUsage(w, r, name)
	case "test":
		s.adminTestUser(w, r, name)
	default:
		writeJSONError(w, http.StatusNotFound, "invalid_request_error",
			"可用路径：/v1/_admin/users/{name}[/token|enable|disable|providers|models|usage|test]")
	}
}

// userSummary 是列表与详情共用的用户快照。
func (s *Server) userSummary(name string) (map[string]any, error) {
	u, err := s.db.GetUser(name)
	if err != nil || u == nil {
		return nil, fmt.Errorf("用户 %q 不存在", name)
	}
	// 快照只给「哪些上游可用 / 模型范围」这类运行期视图，配额与限流一律读库里的
	// 权威行（scope_quota，§2.7 规则 2）：users 行上已经没有这些列。
	scope, err := policy.NewScopeRef(policy.ScopeUser, name)
	if err != nil {
		return nil, fmt.Errorf("用户 %q 的名字当不了范围键: %w", name, err)
	}
	q, err := s.db.GetScopeQuota(scope)
	if err != nil {
		return nil, err
	}
	if q == nil {
		// 没有配额行 = 没配过限额，各项按「不限」（0）显示。
		q = &store.ScopeQuota{Scope: scope}
	}
	e := s.usersSnapshot().byName[name]

	// 本月「系统付费」用量：只有这部分进配额与金额
	usedTokens, usedCost := s.meters.Snapshot(name)
	all, err := s.db.TotalByUser(time.Time{}, name)
	if err != nil {
		return nil, err
	}

	out := map[string]any{
		"name":       u.Name,
		"enabled":    u.Enabled,
		"mode":       userMode(u),
		"created_at": u.CreatedAt.Format(time.RFC3339),
		"quota": map[string]any{
			"month_tokens": q.QuotaMonthTokens,
			"month_cost":   q.QuotaMonthCost,
			"used_tokens":  usedTokens,
			"used_cost":    usedCost,
			"currency":     s.pricingCurrency(),
		},
		"limits": map[string]any{
			"rpm":            q.RPM,
			"max_concurrent": q.MaxConcurrent,
		},
		"usage_all": map[string]any{ // 全部流量（含用户自己上游的，不计配额）
			"requests":     all.Requests,
			"ok":           all.OK,
			"failed":       all.Failed,
			"total_tokens": all.TotalTokens,
		},
	}
	if e != nil {
		out["providers"] = providerNames(e.Providers)
		out["broken_providers"] = e.Broken
		names, source, passthrough := s.effectiveModels(e)
		out["models"] = names
		out["models_source"] = source // inherit = 继承系统池；own = 该用户被收窄
		if passthrough {
			out["models_passthrough"] = true
		}
	} else {
		if ms, err := s.db.ListUserModels(name); err == nil {
			names := make([]string, 0, len(ms))
			for _, m := range ms {
				names = append(names, m.Model)
			}
			sort.Strings(names)
			out["models"] = names
		}
	}
	return out, nil
}

func (s *Server) adminListUsers(w http.ResponseWriter) {
	users, err := s.db.ListUsers()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		sum, err := s.userSummary(u.Name)
		if err != nil {
			continue
		}
		out = append(out, sum)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"users":    out,
		"currency": s.pricingCurrency(),
		"priced":   s.cfgStore.Current().Pricing.Enabled(),
	})
}

func (s *Server) adminShowUser(w http.ResponseWriter, name string) {
	sum, err := s.userSummary(name)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

// adminUpdateUser 改单个用户的设置。只应用请求里给到的字段，
// 没给的保持原值 —— 否则界面改个配额就会把模式一起重置。
func (s *Server) adminUpdateUser(w http.ResponseWriter, r *http.Request, name string) {
	var req struct {
		Mode             *string  `json:"mode"`
		QuotaMonthTokens *int64   `json:"quota_month_tokens"`
		QuotaMonthCost   *float64 `json:"quota_month_cost"`
		RPM              *int     `json:"rpm"`
		MaxConcurrent    *int     `json:"max_concurrent"`
		Enabled          *bool    `json:"enabled"`
	}
	if err := readJSONBody(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	u, err := s.db.GetUser(name)
	if err != nil || u == nil {
		writeJSONError(w, http.StatusNotFound, "not_found", fmt.Sprintf("用户 %q 不存在", name))
		return
	}

	if req.Mode != nil {
		mode := strings.ToLower(strings.TrimSpace(*req.Mode))
		if mode != store.ModeBYO && mode != store.ModeConsumption {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
				"mode 只能是 byo 或 consumption")
			return
		}
		if err := s.db.SetUserMode(name, mode); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	// 配额与限流都落在**范围配额行**上（§2.7 规则 2）：一次 PATCH 只交给 PatchScopeQuota，
	// 避免「token 改了、金额被顺手清零」这种各写一半的事故。
	if req.QuotaMonthTokens != nil || req.QuotaMonthCost != nil || req.RPM != nil || req.MaxConcurrent != nil {
		// NewScopeRef 而不是 MustScope：老库里可能有改规则之前建的、当不了范围键的名字，
		// 那种情况下要回 400 说清名字有问题，而不是 panic 掉这个请求。
		scope, err := policy.NewScopeRef(policy.ScopeUser, name)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
				fmt.Sprintf("用户 %q 的名字当不了范围键: %v", name, err))
			return
		}
		patch := store.QuotaPatch{
			Tokens:        req.QuotaMonthTokens,
			Cost:          req.QuotaMonthCost,
			RPM:           req.RPM,
			MaxConcurrent: req.MaxConcurrent,
		}
		for _, item := range []struct {
			label string
			bad   bool
		}{
			{"配额", req.QuotaMonthTokens != nil && *req.QuotaMonthTokens < 0},
			{"金额配额", req.QuotaMonthCost != nil && *req.QuotaMonthCost < 0},
			{"rpm", req.RPM != nil && *req.RPM < 0},
			{"并发上限", req.MaxConcurrent != nil && *req.MaxConcurrent < 0},
		} {
			if item.bad {
				writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
					item.label+"不能为负（0 = 不限）")
				return
			}
		}
		if err := s.db.PatchScopeQuota(scope, patch); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	if req.Enabled != nil {
		if err := s.db.SetUserEnabled(name, *req.Enabled); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	if err := s.SyncUsers(); err != nil {
		s.log.Errorf("刷新用户快照失败: %v", err)
	}

	sum, err := s.userSummary(name)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	// 切成消费模式但一条映射都没有的话，他一个模型都调不了 —— 这里要说出来
	if ms, _ := s.db.ListUserModels(name); u.IsConsumption() && len(ms) == 0 {
		sum["warning"] = "这个用户还没有模型映射，消费模式下他会一个模型都调不了（403）；" +
			"用「添加模型映射」给他加几条"
	}
	s.log.Infof("管理员更新了用户 %s 的设置", name)
	writeJSON(w, http.StatusOK, sum)
}

// adminUserModels 管理某个用户的模型映射（消费模式的白名单）。
func (s *Server) adminUserModels(w http.ResponseWriter, r *http.Request, name string) {
	u, err := s.db.GetUser(name)
	if err != nil || u == nil {
		writeJSONError(w, http.StatusNotFound, "not_found", fmt.Sprintf("用户 %q 不存在", name))
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		ms, err := s.db.ListUserModels(name)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		out := make([]map[string]any, 0, len(ms))
		for _, m := range ms {
			out = append(out, map[string]any{
				"model": m.Model, "upstream": m.Upstream,
				"provider": m.Provider, "enabled": m.Enabled,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user": name, "mode": userMode(u), "models": out,
		})

	case http.MethodPut, http.MethodPost:
		var req struct {
			Model    string `json:"model"`
			Upstream string `json:"upstream"`
			Provider string `json:"provider"`
			Enabled  *bool  `json:"enabled"`
		}
		if err := readJSONBody(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
			return
		}
		model := strings.TrimSpace(req.Model)
		if model == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
				"model 必填：客户端请求里要填的那个模型名")
			return
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		if err := s.db.UpsertUserModel(store.UserModel{
			UserName: name, Model: model,
			Upstream: strings.TrimSpace(req.Upstream),
			Provider: strings.TrimSpace(req.Provider),
			Enabled:  enabled,
		}); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		if err := s.SyncUsers(); err != nil {
			s.log.Errorf("刷新用户快照失败: %v", err)
		}
		resp := map[string]any{"user": name, "model": model, "upstream": req.Upstream, "enabled": enabled}
		if !u.IsConsumption() {
			resp["note"] = "该用户当前是 byo 模式，这条映射要等他切到 consumption 才生效"
		}
		s.log.Infof("管理员给用户 %s 配置了模型映射 %s", name, model)
		writeJSON(w, http.StatusOK, resp)

	case http.MethodDelete:
		model := strings.TrimSpace(r.URL.Query().Get("model"))
		if model == "" {
			// 不带 model = 清空全部 → 该用户回到「继承系统池的全部模型」
			n, err := s.db.ClearUserModels(name)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
				return
			}
			if err := s.SyncUsers(); err != nil {
				s.log.Errorf("刷新用户快照失败: %v", err)
			}
			s.log.Infof("管理员清空了用户 %s 的模型映射（%d 条），改为继承系统池", name, n)
			writeJSON(w, http.StatusOK, map[string]any{
				"user": name, "deleted": n, "models_source": "inherit",
				"note": "已清空映射，该用户现在继承系统池声明的全部模型",
			})
			return
		}
		ok, err := s.db.DeleteUserModel(name, model)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		if !ok {
			writeJSONError(w, http.StatusNotFound, "not_found",
				fmt.Sprintf("用户 %s 没有模型 %q 的映射", name, model))
			return
		}
		if err := s.SyncUsers(); err != nil {
			s.log.Errorf("刷新用户快照失败: %v", err)
		}
		s.log.Infof("管理员删除了用户 %s 的模型映射 %s", name, model)
		writeJSON(w, http.StatusOK, map[string]any{"user": name, "deleted": model})

	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
			"只支持 GET / PUT / DELETE")
	}
}

// adminUserProviders 看某个用户自己配的上游（密钥脱敏）。
func (s *Server) adminUserProviders(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET")
		return
	}
	e := s.usersSnapshot().byName[name]
	if e == nil {
		writeJSONError(w, http.StatusNotFound, "not_found", fmt.Sprintf("用户 %q 不存在", name))
		return
	}
	list := make([]map[string]any, 0, len(e.Providers))
	for _, p := range e.Providers {
		list = append(list, maskProvider(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user": name, "providers": list, "broken": e.Broken,
	})
}

// adminUserUsage 看某个用户的用量（与用户自助看到的同一份数据）。
func (s *Server) adminUserUsage(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET")
		return
	}
	if u, err := s.db.GetUser(name); err != nil || u == nil {
		writeJSONError(w, http.StatusNotFound, "not_found", fmt.Sprintf("用户 %q 不存在", name))
		return
	}
	days, err := parseDays(r.URL.Query().Get("days"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	s.writeUsageReport(w, name, days)
}

// adminListSystemProviders 列出系统上游（config.yaml 里的 providers），
// 供管理员代用户配模型映射时挑选 —— 要能看到每家「声明了哪些模型」。
func (s *Server) adminListSystemProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET")
		return
	}
	snap := s.router.SnapshotFor("")
	cfg := s.cfgStore.Current()
	out := make([]map[string]any, 0, len(cfg.Normalized))
	for _, p := range cfg.Normalized {
		models := map[string]any{}
		switch {
		case p.Models.Passthrough:
			models = map[string]any{"passthrough": true}
		case p.Models.CatchAll:
			models = map[string]any{"map": p.Models.Map, "catch_all": true}
		default:
			models = map[string]any{"map": p.Models.Map}
		}
		proxy := p.Proxy.Mode
		if p.Proxy.Mode == "named" {
			proxy = p.Proxy.Name
		} else if p.Proxy.Mode == "inline" {
			proxy = p.Proxy.URL
		}
		st := snap[p.Name]
		healthy := st.UnhealthyUntil.IsZero() || !time.Now().Before(st.UnhealthyUntil)
		out = append(out, map[string]any{
			"name": p.Name, "enabled": p.Enabled, "base_url": p.BaseURL,
			"models": models, "proxy": proxy, "weight": p.Weight,
			"healthy": healthy && p.Enabled,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

// parseDays 解析 ?days= 参数，默认 30，范围 1~3650。
func parseDays(v string) (int, error) {
	if v == "" {
		return 30, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 3650 {
		return 0, errors.New("days 需要在 1~3650 之间")
	}
	return n, nil
}
