package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/secrets"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// 多用户（中转器）模式：
//
//	每个用户有自己的下游 token（库里只存 SHA-256）和自己的一组上游
//	（base_url + 加密后的 api_key）。请求路径只读内存快照，不碰数据库。
//
// 快照刷新：任何一次管理/自助写操作在同进程内立即重建；CLI 在别的进程里改的，
// 会主动发 SIGHUP 让服务立刻重建（服务没在跑、或没权限发信号，则退回运行时循环
// 每 2 秒一次的修订号轮询）。

// userEntry 是一个用户的运行期视图。
type userEntry struct {
	Name      string
	Enabled   bool
	Providers []config.Provider
	// Broken 记录解密失败或校验不过的上游名（典型原因：master.key 被换过）
	Broken []string

	// 消费模式相关
	Consumption      bool
	QuotaMonthTokens int64
	QuotaMonthCost   float64
	RPM              int
	MaxConcurrent    int
	// Models 既是白名单也是「下游名 → 系统模型」的映射，只对消费模式有意义
	Models []store.UserModel
}

// userRegistry 是用户表的只读快照。
type userRegistry struct {
	byToken  map[string]*userEntry
	byName   map[string]*userEntry
	rev      int64
	loadedAt time.Time
}

func (r *userRegistry) empty() bool { return r == nil || len(r.byName) == 0 }

// WithSecrets 注入主密钥以启用多用户能力。不调用则退回单用户（静态 key）模式。
func (s *Server) WithSecrets(c *secrets.Cipher) *Server {
	s.secrets = c
	return s
}

// MultiUserEnabled 报告是否启用了多用户模式。
func (s *Server) MultiUserEnabled() bool { return s.secrets != nil }

// usersSnapshot 返回当前快照；未启用多用户时返回空快照。
func (s *Server) usersSnapshot() *userRegistry {
	if s.secrets == nil {
		return &userRegistry{byToken: map[string]*userEntry{}, byName: map[string]*userEntry{}}
	}
	if p := s.users.Load(); p != nil {
		return p
	}
	return &userRegistry{byToken: map[string]*userEntry{}, byName: map[string]*userEntry{}}
}

// SyncUsers 立即重建用户快照。
func (s *Server) SyncUsers() error {
	if s.secrets == nil || s.db == nil {
		return nil
	}
	s.usersMu.Lock()
	defer s.usersMu.Unlock()

	reg, err := s.buildRegistry()
	if err != nil {
		return err
	}
	s.users.Store(reg)
	return nil
}

// SyncUsersIfChanged 只在库里的修订号变化时重建（供运维循环轮询）。
func (s *Server) SyncUsersIfChanged() {
	if s.secrets == nil || s.db == nil {
		return
	}
	rev, err := s.db.Revision()
	if err != nil {
		s.log.Warnf("读取用户配置修订号失败: %v", err)
		return
	}
	if cur := s.users.Load(); cur != nil && cur.rev == rev {
		return
	}
	if err := s.SyncUsers(); err != nil {
		s.log.Errorf("重建用户快照失败: %v", err)
		return
	}
	if n := len(s.usersSnapshot().byName); n > 0 {
		s.log.Infof("用户配置已加载（%d 个用户）", n)
	}
}

func (s *Server) buildRegistry() (*userRegistry, error) {
	reg := &userRegistry{
		byToken:  map[string]*userEntry{},
		byName:   map[string]*userEntry{},
		loadedAt: time.Now(),
	}
	users, err := s.db.ListUsers()
	if err != nil {
		return nil, err
	}
	provs, err := s.db.ListAllUserProviders()
	if err != nil {
		return nil, err
	}
	models, err := s.db.ListAllUserModels()
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		e := &userEntry{
			Name:             u.Name,
			Enabled:          u.Enabled,
			Consumption:      u.IsConsumption(),
			QuotaMonthTokens: u.QuotaMonthTokens,
			QuotaMonthCost:   u.QuotaMonthCost,
			RPM:              u.RPM,
			MaxConcurrent:    u.MaxConcurrent,
		}
		for _, um := range models[u.Name] {
			if um.Enabled {
				e.Models = append(e.Models, um)
			}
		}
		for _, up := range provs[u.Name] {
			p, err := s.userProviderToConfig(up)
			if err != nil {
				// 单个上游不可用不应拖垮整个用户；记名并跳过
				e.Broken = append(e.Broken, up.Name)
				s.log.Warnf("用户 %s 的上游 %s 不可用: %v", u.Name, up.Name, err)
				continue
			}
			e.Providers = append(e.Providers, p)
		}
		reg.byToken[u.TokenHash] = e
		reg.byName[u.Name] = e
	}
	if rev, err := s.db.Revision(); err == nil {
		reg.rev = rev
	}
	return reg, nil
}

// userProviderToConfig 把库里的一行还原成运行期的供应商（解密 api_key）。
func (s *Server) userProviderToConfig(up store.UserProvider) (config.Provider, error) {
	key, err := s.secrets.Decrypt(up.APIKeyEnc)
	if err != nil {
		return config.Provider{}, err
	}
	if strings.TrimSpace(key) == "" {
		return config.Provider{}, errors.New("缺少上游 api_key")
	}
	var models config.ModelSpec
	if err := json.Unmarshal([]byte(up.ModelsJSON), &models); err != nil {
		return config.Provider{}, fmt.Errorf("models 存储形态非法: %w", err)
	}
	if models.Passthrough == false && len(models.Map) == 0 && !models.CatchAll {
		return config.Provider{}, errors.New("models 为空")
	}
	cfg := s.cfgStore.Current()
	proxy, err := config.NormalizeProxy(up.Proxy, cfg.ProxyIndex)
	if err != nil {
		return config.Provider{}, err
	}
	return config.Provider{
		Name:      up.Name,
		Enabled:   up.Enabled,
		BaseURL:   up.BaseURL,
		APIKey:    key,
		Weight:    up.Weight,
		TimeoutMs: up.TimeoutMs,
		Models:    models,
		Proxy:     proxy,
	}, nil
}

// providersFor 返回这次请求该用哪组上游，以及这组是不是「系统池」。
//
// isSystem 决定这次消耗算谁的账：系统池 = 网关主人付费，要进用户的配额与金额。
//
// 三种作用域：
//   - 静态 key（scope 为空）：系统池。这是网关主人自己在用。
//   - consumption 用户：系统池。**没配模型映射时继承系统池声明的全部模型**（开箱可用）；
//     配了映射则被收窄成那些 —— 那时它既是白名单也是别名表。
//   - byo 用户：只能用自己配的上游。**一个都没配时不再回退系统池**：
//     否则等于用户白嫖网关主人的上游。要消费就走 consumption 模式，那样才有计量与配额。
func (s *Server) providersFor(scope, model string) (list []config.Provider, isSystem bool) {
	if scope == "" {
		return s.globalProviders(), true
	}
	e := s.usersSnapshot().byName[scope]
	if e == nil {
		return nil, false
	}
	if e.Consumption {
		if len(e.Models) == 0 {
			// 方案 A：没配映射就继承系统池声明的全部模型，不必逐用户配
			return s.globalProviders(), true
		}
		return s.scopedSystemProviders(e, model), true
	}
	return e.Providers, false
}

// effectiveModels 返回一个消费用户实际能调的逻辑模型名，以及这份清单的来源。
//
//	source = "own"      用户自己被收窄的列表（配了映射）
//	source = "inherit"  继承系统池声明的名字（没配映射）
//
// passthrough=true 表示系统池里至少有家接受任意模型名，这时列举不全，只能说明。
func (s *Server) effectiveModels(e *userEntry) (names []string, source string, passthrough bool) {
	if e == nil {
		return nil, "", false
	}
	if len(e.Models) > 0 {
		return modelNames(e.Models), "own", false
	}
	seen := map[string]bool{}
	for _, p := range s.globalProviders() {
		if !p.Enabled {
			continue
		}
		if p.Models.Passthrough {
			passthrough = true
		}
		for down := range p.Models.Map {
			if down == "*" || seen[down] {
				continue
			}
			seen[down] = true
			names = append(names, down)
		}
	}
	sort.Strings(names)
	return names, "inherit", passthrough
}

// consumptionVerdict 给「选不出候选」这件事归因，好让报错说清是权限问题还是池子问题。
//
//	consumption  是不是消费用户
//	narrowed     他是不是配了自己的收窄列表
//	listed       那个模型在不在他的收窄列表里
func (s *Server) consumptionVerdict(scope, model string) (consumption, narrowed, listed bool) {
	e := s.usersSnapshot().byName[scope]
	if e == nil || !e.Consumption {
		return false, false, false
	}
	narrowed = len(e.Models) > 0
	for _, m := range e.Models {
		if m.Model == model {
			return true, true, true
		}
	}
	return true, narrowed, false
}

// scopedSystemProviders 把系统池按用户的模型映射收窄。
//
// 明确匹配，三层：
//
//	第 1 层  客户端发来的名字（user_models.model）
//	第 2 层  供应商侧的模型名（user_models.upstream，留空 = 与第 1 层同名）
//	第 3 层  这家真实打出去的上游模型名（取它自己 models 映射的值）
//
// 判候选的依据是**这家自己声明了没有**：`models` 里点名了这个第 2 层名字（或它是直通/catch-all）
// 才算候选，否则这家直接出局。映射完再把 ModelSpec 收成「只有这一个模型」，
// 后面的选路逻辑（PickFrom）不用为消费模式写任何特例。
//
// 早先的做法是把用户的 upstream 硬套到**每一家**身上 —— 等于对每一家都说「你承接这个模型」，
// 于是池里全都成了候选、按权重随机打，其中大部分其实没有这个模型，就随机 400。
// 现在没声明就是没声明，选不出候选时明确失败，不再硬转发出去让上游回错。
func (s *Server) scopedSystemProviders(e *userEntry, model string) []config.Provider {
	var (
		mapped   bool
		upstream string
		onlyFor  string
	)
	for _, m := range e.Models {
		if m.Model == model {
			mapped = true
			upstream = m.Upstream
			onlyFor = m.Provider
			break
		}
	}
	if !mapped {
		return nil
	}
	if upstream == "" {
		upstream = model // 第 2 层留空 = 与第 1 层同名
	}

	sys := s.globalProviders()
	out := make([]config.Provider, 0, len(sys))
	for _, p := range sys {
		if !p.Enabled {
			continue
		}
		if onlyFor != "" && !strings.EqualFold(onlyFor, p.Name) {
			continue
		}
		// 这家自己认不认这个第 2 层名字？不认就不是候选（直通/catch-all 算认，但是最低优先级）
		real, ok := p.UpstreamModel(upstream)
		if !ok {
			continue
		}
		cp := p
		cp.Models = config.ModelSpec{Map: map[string]string{model: real}}
		out = append(out, cp)
	}
	return out
}

// hasNoProviders 区分「根本没配上游」和「配了但都不可用」：
// 前者要给可操作的下一步（配一个，或改走消费模式），后者是排障信息。
func (s *Server) hasNoProviders(scope string) bool {
	e := s.usersSnapshot().byName[scope]
	return e != nil && !e.Consumption && len(e.Providers) == 0 && len(e.Broken) == 0
}

// unusableNote 在用户配的上游全部不可用时给一句能定位问题的报错。
func (s *Server) unusableNote(scope string) string {
	if scope == "" {
		return ""
	}
	e := s.usersSnapshot().byName[scope]
	if e == nil || len(e.Broken) == 0 {
		return ""
	}
	return fmt.Sprintf("你配置的上游 %s 全部不可用（解密或校验失败，常见原因：master.key 被更换、base_url/models 非法）。"+
		"请重新配置上游，详见服务端日志。", strings.Join(e.Broken, ", "))
}

func (s *Server) globalProviders() []config.Provider {
	cfg := s.cfgStore.Current()
	if cfg == nil {
		return nil
	}
	return cfg.Normalized
}

// PersistProviderStatus 把所有作用域的熔断状态落库（重启后继续熔断）。
func (s *Server) PersistProviderStatus() error {
	if s.db == nil {
		return nil
	}
	enabled := map[string]bool{}
	for _, p := range s.globalProviders() {
		enabled["\x00"+p.Name] = p.Enabled
	}
	for _, e := range s.usersSnapshot().byName {
		for _, p := range e.Providers {
			enabled[e.Name+"\x00"+p.Name] = p.Enabled
		}
	}

	list := []store.ProviderStatus{}
	for _, item := range s.router.SnapshotAll() {
		list = append(list, store.ProviderStatus{
			Scope:               item.Scope,
			Name:                item.Name,
			Enabled:             enabled[item.Scope+"\x00"+item.Name],
			ConsecutiveFailures: item.State.ConsecutiveFailures,
			UnhealthyUntil:      item.State.UnhealthyUntil,
			LastError:           item.State.LastError,
			LastSuccessAt:       item.State.LastSuccessAt,
			LastFailureAt:       item.State.LastFailureAt,
			TotalRequests:       item.State.TotalRequests,
			TotalFailures:       item.State.TotalFailures,
		})
	}
	return s.db.SaveProviderStatus(list)
}

// UserCount 返回已加载的用户数（供启动日志用）。
func (s *Server) UserCount() int { return len(s.usersSnapshot().byName) }

// ------------------------------------------------------------------ 接口公共件

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// readJSONBody 读取并解析请求体（限制 1MB，这些接口不该收大 body）。
func readJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("请求体不是合法 JSON: %w", err)
	}
	return nil
}

// nameRe 限制用户名与上游名：它们会进 URL 路径和作用域键，必须干净。
var nameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func validName(s string) bool { return nameRe.MatchString(s) }

// adminOK 校验管理凭证。未配置 admin_token 时管理接口整体关闭。
func (s *Server) adminOK(r *http.Request) (bool, string) {
	cfg := s.cfgStore.Current()
	if !cfg.Server.HasAdminToken() {
		return false, "管理接口未启用（需要在配置里设置 server.admin_token）"
	}
	got := extractToken(r)
	if got == "" {
		return false, "缺少管理凭证"
	}
	if !keyMatches(got, cfg.Server.AdminToken) {
		return false, "管理凭证无效"
	}
	return true, ""
}

// meScope 返回自助接口应操作的作用域；静态 key 没有用户身份，不允许自助。
func meScope(auth authResult) (string, bool) {
	if auth.UserName == "" {
		return "", false
	}
	return auth.UserName, true
}

// maskProvider 把一个上游渲染成可安全返回给客户端的形态（密钥只留尾部 4 位）。
func maskProvider(p config.Provider) map[string]any {
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
	return map[string]any{
		"name":       p.Name,
		"enabled":    p.Enabled,
		"base_url":   p.BaseURL,
		"api_key":    secrets.Mask(p.APIKey), // 永远不回显明文
		"weight":     p.Weight,
		"timeout_ms": p.TimeoutMs,
		"proxy":      proxy,
		"models":     models,
	}
}

// ------------------------------------------------------------------ 自助接口

// handleMe 处理 /v1/_me* 下的所有请求。auth 已经通过鉴权。
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, auth authResult) {
	if !s.MultiUserEnabled() {
		writeJSONError(w, http.StatusNotImplemented, "not_configured",
			"多用户模式未启用（服务端缺少主密钥）")
		return
	}
	scope, ok := meScope(auth)
	if !ok {
		writeJSONError(w, http.StatusForbidden, "no_identity",
			"当前凭证是静态 key，没有用户身份，无法使用自助接口")
		return
	}
	e := s.usersSnapshot().byName[scope]
	if e == nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}

	// /v1/_me
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/_me"), "/")
	if rest == "" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET")
			return
		}
		tot, err := s.db.TotalByUser(time.Time{}, scope)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		out := map[string]any{
			"name":           e.Name,
			"enabled":        e.Enabled,
			"mode":           modeOf(e),
			"provider_count": len(e.Providers),
			"providers":      providerNames(e.Providers),
			"usage": map[string]any{
				"requests":          tot.Requests,
				"ok":                tot.OK,
				"failed":            tot.Failed,
				"prompt_tokens":     tot.PromptTokens,
				"completion_tokens": tot.OutputTokens,
				"total_tokens":      tot.TotalTokens,
				"first_day":         tot.FirstDay,
				"last_day":          tot.LastDay,
			},
		}
		if e.RPM > 0 || e.MaxConcurrent > 0 {
			out["limits"] = map[string]any{"rpm": e.RPM, "max_concurrent": e.MaxConcurrent}
		}
		if e.Consumption {
			used, cost := s.meters.Snapshot(e.Name)
			q := map[string]any{
				"month_tokens": e.QuotaMonthTokens,
				"month_cost":   e.QuotaMonthCost,
				// used_* 只算「走系统上游」的那部分：用户用自己的上游时不该占他的消费额度
				"used_tokens": used,
				"used_cost":   cost,
				"currency":    s.pricingCurrency(),
			}
			if e.QuotaMonthTokens > 0 {
				left := e.QuotaMonthTokens - used
				if left < 0 {
					left = 0
				}
				q["left_tokens"] = left
			}
			if e.QuotaMonthCost > 0 {
				left := e.QuotaMonthCost - cost
				if left < 0 {
					left = 0
				}
				q["left_cost"] = left
			}
			out["quota"] = q
			names, source, passthrough := s.effectiveModels(e)
			out["models"] = names
			out["models_source"] = source
			if passthrough {
				// 列举不全时要说清楚，免得用户以为只有这几个
				out["models_passthrough"] = true
			}
		}
		if len(e.Broken) > 0 {
			out["broken_providers"] = e.Broken
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	if strings.HasPrefix(rest, "providers") {
		s.handleMeProviders(w, r, e, strings.Trim(strings.TrimPrefix(rest, "providers"), "/"))
		return
	}
	if rest == "usage" {
		s.handleMeUsage(w, r, scope)
		return
	}
	writeJSONError(w, http.StatusNotFound, "invalid_request_error",
		"可用路径：/v1/_me、/v1/_me/providers、/v1/_me/usage")
}

// modeOf 把运行期视图还原成对外的模式名。
func modeOf(e *userEntry) string {
	if e != nil && e.Consumption {
		return store.ModeConsumption
	}
	return store.ModeBYO
}

// modelNames 列出消费用户白名单里的模型（只给下游名，不暴露映射后的上游名）。
func modelNames(ms []store.UserModel) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Model)
	}
	sort.Strings(out)
	return out
}

// pricingCurrency 返回单价表的币种，供界面显示单位。
func (s *Server) pricingCurrency() string {
	if c := s.cfgStore.Current(); c != nil && c.Pricing.Currency != "" {
		return c.Pricing.Currency
	}
	return "CNY"
}

func providerNames(ps []config.Provider) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}

func (s *Server) handleMeProviders(w http.ResponseWriter, r *http.Request, e *userEntry, name string) {
	// 列表
	if name == "" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
				"列表用 GET，新增/覆盖用 PUT /v1/_me/providers/{name}")
			return
		}
		list := make([]map[string]any, 0, len(e.Providers))
		for _, p := range e.Providers {
			list = append(list, maskProvider(p))
		}
		writeJSON(w, http.StatusOK, map[string]any{"providers": list, "broken": e.Broken})
		return
	}

	if !validName(name) {
		// 名字里带 "/" 的是子动作：/v1/_me/providers/{name}/discover
		// （validName 不允许斜杠，所以要在它之前拆）
		if idx := strings.Index(name, "/"); idx > 0 {
			action := name[idx+1:]
			upName := name[:idx]
			if action == "discover" {
				s.discoverUpstreamModels(w, r, e, upName)
				return
			}
			writeJSONError(w, http.StatusNotFound, "invalid_request_error",
				"可用路径：/v1/_me/providers、/v1/_me/providers/{name}、/v1/_me/providers/{name}/discover")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"上游名只能包含字母、数字、点、下划线、连字符，长度 1~64")
		return
	}

	switch r.Method {
	case http.MethodPut, http.MethodPost:
		s.upsertMyProvider(w, r, e.Name, name)
	case http.MethodDelete:
		deleted, err := s.db.DeleteUserProvider(e.Name, name)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		if !deleted {
			writeJSONError(w, http.StatusNotFound, "not_found", fmt.Sprintf("上游 %q 不存在", name))
			return
		}
		if err := s.SyncUsers(); err != nil {
			s.log.Errorf("刷新用户快照失败: %v", err)
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": name})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
			fmt.Sprintf("不支持的方法 %s", r.Method))
	}
}

// providerReq 是自助接口的上游配置入参。字段用指针以区分「没传」和「传了零值」，
// 这样更新时可以只改一个字段而不必重传密钥。
type providerReq struct {
	BaseURL   *string         `json:"base_url"`
	APIKey    *string         `json:"api_key"`
	Weight    *float64        `json:"weight"`
	TimeoutMs *int            `json:"timeout_ms"`
	Proxy     *string         `json:"proxy"`
	Models    json.RawMessage `json:"models"`
	Enabled   *bool           `json:"enabled"`
}

func (s *Server) upsertMyProvider(w http.ResponseWriter, r *http.Request, userName, name string) {
	var req providerReq
	if err := readJSONBody(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}

	cfg := s.cfgStore.Current()

	// 取已有记录（更新场景）：没传的字段沿用旧值
	existing, err := s.findMyProvider(userName, name)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	baseURL := ""
	if req.BaseURL != nil {
		baseURL = strings.TrimSpace(*req.BaseURL)
	} else if existing != nil {
		baseURL = existing.BaseURL
	}
	if baseURL == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "base_url 必填")
		return
	}
	u, err := config.ParseBaseURL(baseURL)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "base_url "+err.Error())
		return
	}
	// 用户可控的 base_url 等于「让网关以它自己的网络位置发请求、再把响应逐字节读回来」
	// 的能力，所以要做出网校验。link-local（含云元数据）一律拒绝；回环与私网段只在
	// block_local_upstream 打开时拒绝，免得打断「上游是本机 ollama」这类正当用法。
	// 界线与局限见 config.CheckUpstreamEgress。
	if err := config.CheckUpstreamEgress(u, cfg != nil && cfg.Server.BlockLocalUpstream); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	baseURL = strings.TrimRight(baseURL, "/")

	// api_key：新建必填；更新时省略表示沿用旧密钥
	var encKey []byte
	var plainForCheck string
	if req.APIKey != nil {
		plainForCheck = strings.TrimSpace(*req.APIKey)
		if plainForCheck == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
				"api_key 不能是空字符串（想保留原密钥就别传这个字段）")
			return
		}
		if encKey, err = s.secrets.Encrypt(plainForCheck); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	} else if existing != nil && len(existing.APIKeyEnc) > 0 {
		encKey = existing.APIKeyEnc
	} else {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "api_key 必填")
		return
	}

	// models：新建必填；更新时省略沿用旧值
	modelsJSON := ""
	if len(req.Models) > 0 {
		spec, err := config.ParseModelsJSON(req.Models)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
			return
		}
		b, err := json.Marshal(spec)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		modelsJSON = string(b)
	} else if existing != nil {
		modelsJSON = existing.ModelsJSON
	} else {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			`models 必填（例如 ["*"] 表示任意模型直通，或 {"gpt-4o":"gpt-4o-2024-11-20"}）`)
		return
	}

	weight := 1.0
	if existing != nil && existing.Weight > 0 {
		weight = existing.Weight
	}
	if req.Weight != nil {
		if *req.Weight <= 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "weight 必须大于 0")
			return
		}
		weight = *req.Weight
	}

	timeoutMs := 120000
	if existing != nil && existing.TimeoutMs > 0 {
		timeoutMs = existing.TimeoutMs
	}
	if req.TimeoutMs != nil {
		if *req.TimeoutMs < 1000 || *req.TimeoutMs > 3600000 {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
				"timeout_ms 需要在 1000~3600000 之间")
			return
		}
		timeoutMs = *req.TimeoutMs
	}

	proxyRaw := ""
	if existing != nil {
		proxyRaw = existing.Proxy
	}
	if req.Proxy != nil {
		proxyRaw = strings.TrimSpace(*req.Proxy)
	}
	if _, err := config.NormalizeProxy(proxyRaw, cfg.ProxyIndex); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}

	enabled := true
	if existing != nil {
		enabled = existing.Enabled
	}
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	rec := store.UserProvider{
		UserName:   userName,
		Name:       name,
		BaseURL:    baseURL,
		APIKeyEnc:  encKey,
		Weight:     weight,
		Enabled:    enabled,
		TimeoutMs:  timeoutMs,
		Proxy:      proxyRaw,
		ModelsJSON: modelsJSON,
	}
	if err := s.db.UpsertUserProvider(rec); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	// 立刻生效，不等轮询
	if err := s.SyncUsers(); err != nil {
		s.log.Errorf("刷新用户快照失败: %v", err)
	}
	s.log.Infof("用户 %s 更新了上游 %s（%s）", userName, name, baseURL)

	e := s.usersSnapshot().byName[userName]
	if e != nil {
		for _, p := range e.Providers {
			if p.Name == name {
				writeJSON(w, http.StatusOK, map[string]any{"provider": maskProvider(p)})
				return
			}
		}
	}
	// 保存成功但这个上游没进快照（例如解密/校验不过），如实告知
	writeJSON(w, http.StatusOK, map[string]any{
		"name":  name,
		"saved": true,
		"warning": "已保存，但该上游暂不可用，请检查 base_url / api_key / models；" +
			"明细见服务端日志",
	})
}

func (s *Server) findMyProvider(userName, name string) (*store.UserProvider, error) {
	list, err := s.db.ListUserProviders(userName)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].Name == name {
			return &list[i], nil
		}
	}
	return nil, nil
}

func (s *Server) handleMeUsage(w http.ResponseWriter, r *http.Request, scope string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET")
		return
	}
	days, err := parseDays(r.URL.Query().Get("days"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	s.writeUsageReport(w, scope, days)
}

// writeUsageReport 出一个用户的用量报表。用户自助（/v1/_me/usage）与管理员
// （/v1/_admin/users/{name}/usage）共用同一份实现 —— 两处各写一遍迟早会漂移。
func (s *Server) writeUsageReport(w http.ResponseWriter, scope string, days int) {
	since := time.Now().AddDate(0, 0, -days)
	rows, err := s.db.UsageByUser(since, scope)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	tot, err := s.db.TotalByUser(since, scope)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	type row struct {
		Day              string   `json:"day"`
		Provider         string   `json:"provider"`
		Model            string   `json:"model"`
		UpstreamModel    string   `json:"upstream_model,omitempty"`
		Requests         int64    `json:"requests"`
		OK               int64    `json:"ok"`
		Failed           int64    `json:"failed"`
		PromptTokens     int64    `json:"prompt_tokens"`
		CacheHitTokens   int64    `json:"cache_hit_tokens"`
		CacheMissTokens  int64    `json:"cache_miss_tokens"`
		CompletionTokens int64    `json:"completion_tokens"`
		TotalTokens      int64    `json:"total_tokens"`
		AvgLatencyMs     float64  `json:"avg_latency_ms"`
		SystemPaid       bool     `json:"system_paid"`
		Cost             *float64 `json:"cost,omitempty"`
		// 冻结的分发金额与已冻结请求数：Cost 是"冻结优先 + 估算兜底"的合计，
		// 想分清两段就看这两个（FrozenCharges < Requests 的部分是估算的）。
		Charge        float64 `json:"charge,omitempty"`
		FrozenCharges int64   `json:"frozen_charges,omitempty"`
	}
	out := make([]row, 0, len(rows))
	now := time.Now()
	pricing := s.cfgStore.Current().Pricing
	for _, r := range rows {
		item := row{
			Day: r.Day, Provider: r.Provider, Model: r.Model, UpstreamModel: r.UpstreamModel,
			Requests: r.Requests, OK: r.OK, Failed: r.Failed,
			PromptTokens: r.PromptTokens, CacheHitTokens: r.CacheHitTokens,
			CacheMissTokens: r.CacheMissTokens, CompletionTokens: r.CompletionTokens,
			TotalTokens: r.TotalTokens, AvgLatencyMs: r.AvgLatencyMs,
			SystemPaid: r.SystemPaid,
		}
		// 只有网关自己掏钱的那部分才谈得上金额；用户用自己的上游是他自己跟供应商结算。
		// 金额口径与配额一致：冻结优先、未冻结按 legacy 单价表估算兜底。
		if r.SystemPaid && (r.FrozenCharges > 0 || pricing.Enabled()) {
			c := rowCharge(r, &pricing, now)
			item.Cost = &c
			item.Charge = r.Charge
			item.FrozenCharges = r.FrozenCharges
		}
		out = append(out, item)
	}

	// 汇总金额同样只算系统付费的部分，和配额口径保持一致
	var monthCost float64
	if rows, err := s.db.SystemUsageRowsSince(scope, store.MonthStart(now)); err == nil {
		for _, r := range rows {
			monthCost += rowCharge(r, &pricing, now)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"days":   days,
		"totals": tot,
		"rows":   out,
		"cost": map[string]any{
			"currency":     pricing.Currency,
			"priced":       pricing.Enabled(),
			"month_system": monthCost,
			"counted_upto": now.Format("2006-01-02"),
			"note":         "只统计走系统上游的消耗；金额冻结优先（按请求开始时刻的价目行算好写死），未冻结的部分按 config.yaml 的 pricing 表估算兜底",
		},
	})
}

// ------------------------------------------------------------------ 管理接口

// handleAdmin 处理 /v1/_admin* 下的所有请求。
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if !s.MultiUserEnabled() {
		writeJSONError(w, http.StatusNotImplemented, "not_configured",
			"多用户模式未启用（服务端缺少主密钥）")
		return
	}
	if ok, msg := s.adminOK(r); !ok {
		s.log.Warnf("管理接口鉴权失败 ip=%s: %s", clientIP(r), msg)
		writeJSONError(w, http.StatusForbidden, "admin_denied", msg)
		return
	}

	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/_admin"), "/")
	switch {
	case rest == "users" || strings.HasPrefix(rest, "users/"):
		s.adminUsersRoute(w, r, strings.Trim(strings.TrimPrefix(rest, "users"), "/"))
	case rest == "config" || strings.HasPrefix(rest, "config/"):
		s.handleAdminConfig(w, r, strings.Trim(strings.TrimPrefix(rest, "config"), "/"))
	case rest == "prices" || strings.HasPrefix(rest, "prices/"):
		s.adminPricesRoute(w, r, strings.Trim(strings.TrimPrefix(rest, "prices"), "/"))
	case rest == "providers":
		s.adminListSystemProviders(w, r)
	case strings.HasPrefix(rest, "providers/"):
		tail := strings.Trim(strings.TrimPrefix(rest, "providers"), "/")
		parts := strings.Split(tail, "/")
		if len(parts) == 2 {
			switch parts[1] {
			case "discover":
				s.discoverSystemModels(w, r, parts[0])
				return
			case "test":
				s.adminTestProvider(w, r, parts[0])
				return
			}
		}
		writeJSONError(w, http.StatusNotFound, "invalid_request_error",
			"可用路径：/v1/_admin/providers[/{name}/discover|/test]")
	default:
		writeJSONError(w, http.StatusNotFound, "invalid_request_error",
			"可用路径：/v1/_admin/users[/{name}[/token|enable|disable|providers|models|usage]]、"+
				"/v1/_admin/providers[/{name}/discover]、/v1/_admin/config[/providers|/validate]")
	}
}

func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := readJSONBody(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if !validName(name) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"用户名只能包含字母、数字、点、下划线、连字符，长度 1~64")
		return
	}
	token, err := store.NewToken()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if err := s.db.CreateUser(name, store.TokenHash(token)); err != nil {
		writeJSONError(w, http.StatusConflict, "already_exists", err.Error())
		return
	}
	_ = s.SyncUsers()
	s.log.Warnf("管理员创建了用户 %s", name)
	writeJSON(w, http.StatusCreated, map[string]any{
		"name":  name,
		"token": token,
		"note":  "明文只在这里返回一次，请立刻交给用户",
		"usage": "用户拿这个 token 调 /v1/chat/completions，并用 PUT /v1/_me/providers/{name} 配自己的上游",
	})
}
