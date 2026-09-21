// Package server 是下游 HTTP 服务：鉴权、路由、上游转发。
//
// 安全约定：
//   - 默认只监听 127.0.0.1
//   - 下游凭证用常数时间比较；日志里只存凭证的 SHA-256 前缀
//   - 不把客户端的 Authorization 转发给上游
//   - 不记录任何请求/响应内容
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/dialer"
	"github.com/mynet-club/net-tools/llmproxy/internal/logx"
	"github.com/mynet-club/net-tools/llmproxy/internal/router"
	"github.com/mynet-club/net-tools/llmproxy/internal/secrets"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

type Server struct {
	cfgStore   *config.Store
	db         *store.Store
	router     *router.Router
	log        *logx.Logger
	transports *dialer.TransportCache
	httpSrv    *http.Server
	startedAt  time.Time

	// 多用户模式：secrets 非空表示启用；用户快照按修订号刷新，请求路径只读内存。
	secrets *secrets.Cipher
	users   atomic.Pointer[userRegistry]
	usersMu sync.Mutex

	uiHandler http.Handler

	// 消费模式的当月计数与限流（内存，见 limits.go）
	meters *meterSet

	// 配置写回后等热加载的时长；测试里置 0 可跳过等待
	configApplyWait time.Duration
}

func New(cfgStore *config.Store, db *store.Store, r *router.Router, lg *logx.Logger) *Server {
	s := &Server{
		cfgStore:   cfgStore,
		db:         db,
		router:     r,
		log:        lg,
		transports: dialer.NewTransportCache(),
		startedAt:  time.Now(),
	}
	s.uiHandler = s.newUIHandler()
	s.configApplyWait = 4 * time.Second
	s.meters = newMeterSet(db, func() *config.PricingConfig {
		if c := cfgStore.Current(); c != nil {
			return &c.Pricing
		}
		return nil
	})
	return s
}

func (s *Server) Router() *router.Router             { return s.router }
func (s *Server) Transports() *dialer.TransportCache { return s.transports }

// Handler 返回 HTTP 路由表（测试与 Start 共用）。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/ui", s.handleUserUI)
	mux.HandleFunc("/ui/", s.handleUserUI)
	mux.HandleFunc("/admin", s.handleAdminUI)
	mux.HandleFunc("/admin/", s.handleAdminUI)
	mux.HandleFunc("/v1/models", s.handleModels)
	mux.HandleFunc("/v1/_providers", s.handleProviders)
	mux.HandleFunc("/v1/", s.handleV1)
	mux.HandleFunc("/", s.handleNotFound)
	return s.withAccessLog(mux)
}

// statusRecorder 记录状态码，供访问日志使用。
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int64
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.written += int64(n)
	return n, err
}

// Flush 必须转发，否则流式响应会失去实时性。
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// withAccessLog 记录每一行请求。排查「客户端到底发了什么」时这是唯一的线索，
// 所以即使是 404 / 405 也要记。只记方法、路径、状态、耗时，不含内容与密钥。
func (s *Server) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// healthz 探活太频繁，不记
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		started := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if rec.status == 0 {
			rec.status = http.StatusOK
		}
		s.log.Infof("← %s %s%s %d %s %dB ip=%s",
			r.Method, r.URL.Path, querySuffix(r.URL.RawQuery),
			rec.status, time.Since(started).Round(time.Millisecond),
			rec.written, clientIP(r))
	})
}

func querySuffix(q string) string {
	if q == "" {
		return ""
	}
	return "?" + q
}

// Start 启动 HTTP 服务（阻塞）。
func (s *Server) Start() error {
	cfg := s.cfgStore.Current()
	if cfg == nil {
		return fmt.Errorf("配置尚未加载")
	}
	s.httpSrv = &http.Server{
		Addr:              net.JoinHostPort(cfg.Server.Host, fmt.Sprint(cfg.Server.Port)),
		Handler:           s.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		// 不设 ReadTimeout/WriteTimeout：流式响应可能持续很久，
		// 由每个上游请求自己的 timeout 控制。
		MaxHeaderBytes: 1 << 20,
	}
	s.log.Infof("监听 %s", s.httpSrv.Addr)
	return s.httpSrv.ListenAndServe()
}

// Shutdown 优雅退出。
func (s *Server) Shutdown(timeout time.Duration) {
	if s.httpSrv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := s.httpSrv.Shutdown(ctx); err != nil {
		s.log.Warnf("HTTP 服务关闭时出错: %v", err)
	}
}

// ------------------------------------------------------------------ 鉴权

// authResult 是一次鉴权的结果。
//
// 多用户模式下 UserName/Scope 会被填上：Scope 决定这次请求能用哪组上游
// （用户自己的，或回退到全局配置），也决定熔断状态落在哪个桶里。
type authResult struct {
	KeyHash  string
	Label    string
	ClientIP string
	OK       bool
	UserName string // DB 用户的名字；静态 key 为空
	Scope    string // 路由作用域，等于 UserName 或空串
	Disabled bool   // 凭证有效但账号已停用
}

func keyMatches(got, want string) bool {
	// 先做摘要再常数时间比较，避免通过响应时间泄漏长度
	a := sha256.Sum256([]byte(got))
	b := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// extractToken 从 Authorization 或 X-Api-Key 里取出下游凭证。
func extractToken(r *http.Request) string {
	authz := r.Header.Get("Authorization")
	if authz == "" {
		// 也接受 X-Api-Key（部分客户端用这个）
		return strings.TrimSpace(r.Header.Get("X-Api-Key"))
	}
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	return strings.TrimSpace(authz)
}

func (s *Server) authenticate(r *http.Request) authResult {
	cfg := s.cfgStore.Current()
	ip := clientIP(r)
	res := authResult{ClientIP: ip}
	presented := extractToken(r)
	reg := s.usersSnapshot()

	// 1) 多用户模式：先按 token 摘要找 DB 用户（这类身份更具体，自带上游）
	if presented != "" && !reg.empty() {
		if e := reg.byToken[store.TokenHash(presented)]; e != nil {
			res.KeyHash = store.KeyHash(presented)
			res.Label = e.Name
			res.UserName = e.Name
			res.Scope = e.Name
			if !e.Enabled {
				res.Disabled = true
				return res // OK 保持 false
			}
			res.OK = true
			return res
		}
	}

	// 没有任何凭证来源时（既没配静态 key、也没建用户），沿用本机匿名的老行为
	if !cfg.Server.RequiresAuth() && reg.empty() {
		res.OK = true
		res.Label = "local"
		return res
	}

	// 2) 静态 key（单用户/兼容路径）：作用域为空 = 用全局配置里的供应商
	if presented == "" {
		return res
	}
	for _, k := range cfg.Server.APIKeys {
		if keyMatches(presented, k.Key) {
			res.OK = true
			res.KeyHash = store.KeyHash(k.Key)
			res.Label = k.Label
			if res.Label == "" {
				res.Label = "key"
			}
			return res
		}
	}
	return res
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSONError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message": msg,
			"type":    code,
		},
	})
}

// ------------------------------------------------------------------ 路由

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgStore.Current()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "ok",
		"version":   config.Version,
		"uptime_s":  int(time.Since(s.startedAt).Seconds()),
		"revision":  s.cfgStore.Revision(),
		"providers": len(cfg.Normalized),
	})
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET")
		return
	}
	auth := s.authenticate(r)
	if !auth.OK {
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "无效的 API key")
		return
	}
	// 每个用户只看到自己那组上游声明的模型（回退到全局时才看到全局的）
	seen := map[string]bool{}
	type modelCard struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		OwnedBy string `json:"owned_by"`
	}
	data := []modelCard{}
	// 消费用户能调哪些模型：没配映射就是继承系统池声明的全部（方案 A），配了就是他那份收窄列表。
	// 直接列有效清单，别让用户从系统池里猜。
	if e := s.usersSnapshot().byName[auth.Scope]; e != nil && e.Consumption {
		names, _, _ := s.effectiveModels(e)
		for _, m := range names {
			if seen[m] {
				continue
			}
			seen[m] = true
			data = append(data, modelCard{ID: m, Object: "model", OwnedBy: "llmproxy"})
		}
	}
	list, _ := s.providersFor(auth.Scope, "")
	for _, p := range list {
		if !p.Enabled || p.Models.Passthrough {
			continue
		}
		for down := range p.Models.Map {
			if seen[down] {
				continue
			}
			seen[down] = true
			data = append(data, modelCard{
				ID: down, Object: "model", Created: 0, OwnedBy: "llmproxy",
			})
		}
	}
	// 按名字排序，输出稳定
	for i := 0; i < len(data); i++ {
		for j := i + 1; j < len(data); j++ {
			if data[j].ID < data[i].ID {
				data[i], data[j] = data[j], data[i]
			}
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"object": "list",
		"data":   data,
	})
}

// handleProviders 返回运行中进程的供应商实时状态（含熔断），供 `llmproxy providers` 使用。
// 需要鉴权：状态里含 last_error 等信息。
func (s *Server) handleProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET")
		return
	}
	auth := s.authenticate(r)
	if !auth.OK {
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "无效的 API key")
		return
	}
	cfg := s.cfgStore.Current()
	// 消费用户的可用上游是按模型映射逐次收窄的，状态页展示「系统池」更有意义
	providers, _ := s.providersFor(auth.Scope, "")
	if e := s.usersSnapshot().byName[auth.Scope]; e != nil && e.Consumption {
		providers = s.globalProviders()
	}
	snap := s.router.SnapshotFor(auth.Scope)

	type liveProvider struct {
		Name                string   `json:"name"`
		Enabled             bool     `json:"enabled"`
		Weight              float64  `json:"weight"`
		Proxy               string   `json:"proxy"`
		ProxyMode           string   `json:"proxy_mode"`
		BaseURL             string   `json:"base_url"`
		Models              []string `json:"models"` // 空 = 直通
		Healthy             bool     `json:"healthy"`
		ConsecutiveFailures int      `json:"consecutive_failures"`
		UnhealthyUntil      string   `json:"unhealthy_until,omitempty"`
		TotalRequests       int64    `json:"total_requests"`
		TotalFailures       int64    `json:"total_failures"`
		LastError           string   `json:"last_error,omitempty"`
		LastSuccessAt       string   `json:"last_success_at,omitempty"`
		LastFailureAt       string   `json:"last_failure_at,omitempty"`
	}
	out := make([]liveProvider, 0, len(providers))
	now := time.Now()
	for _, p := range providers {
		st := snap[p.Name]
		healthy := st.UnhealthyUntil.IsZero() || !now.Before(st.UnhealthyUntil)
		lp := liveProvider{
			Name:                p.Name,
			Enabled:             p.Enabled,
			Weight:              p.Weight,
			ProxyMode:           p.Proxy.Mode,
			BaseURL:             p.BaseURL,
			Healthy:             healthy && p.Enabled,
			ConsecutiveFailures: st.ConsecutiveFailures,
			TotalRequests:       st.TotalRequests,
			TotalFailures:       st.TotalFailures,
			LastError:           st.LastError,
		}
		switch p.Proxy.Mode {
		case "named":
			lp.Proxy = p.Proxy.Name
		case "inline":
			lp.Proxy = p.Proxy.URL
		default:
			lp.Proxy = "direct"
		}
		if !p.Models.Passthrough {
			for name := range p.Models.Map {
				lp.Models = append(lp.Models, name)
			}
			sort.Strings(lp.Models)
		}
		if !st.UnhealthyUntil.IsZero() {
			lp.UnhealthyUntil = st.UnhealthyUntil.Format(time.RFC3339)
		}
		if !st.LastSuccessAt.IsZero() {
			lp.LastSuccessAt = st.LastSuccessAt.Format(time.RFC3339)
		}
		if !st.LastFailureAt.IsZero() {
			lp.LastFailureAt = st.LastFailureAt.Format(time.RFC3339)
		}
		out = append(out, lp)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"revision":  s.cfgStore.Revision(),
		"routing":   cfg.Routing,
		"scope":     auth.Scope, // 空 = 全局配置；否则是某个用户自己的上游
		"providers": out,
	})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSONError(w, http.StatusNotFound, "invalid_request_error",
		fmt.Sprintf("路径 %s 不存在。可用端点：POST /v1/chat/completions、GET /v1/models、GET /healthz、GET /ui/（网页控制台）", r.URL.Path))
}

// handleV1 处理所有 /v1/* 请求。
func (s *Server) handleV1(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// /v1/models 已在 mux 上单独注册，这里兜底其余路径
	if path == "/v1" || path == "/v1/" {
		writeJSONError(w, http.StatusNotFound, "invalid_request_error", "请使用 /v1/chat/completions 或 /v1/models")
		return
	}

	// 管理接口用自己的 admin_token 鉴权，必须走在下游鉴权前面
	if strings.HasPrefix(path, "/v1/_admin") {
		s.handleAdmin(w, r)
		return
	}

	auth := s.authenticate(r)
	if !auth.OK {
		if auth.Disabled {
			s.log.Warnf("账号已停用 ip=%s path=%s user=%s", auth.ClientIP, path, auth.UserName)
			writeJSONError(w, http.StatusForbidden, "account_disabled",
				fmt.Sprintf("账号 %s 已停用", auth.UserName))
			return
		}
		s.log.Warnf("鉴权失败 ip=%s path=%s", auth.ClientIP, path)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "无效的 API key")
		return
	}

	// 自助接口先于上游转发处理（否则会被当成上游路径转发出去）
	if strings.HasPrefix(path, "/v1/_me") {
		s.handleMe(w, r, auth)
		return
	}

	switch r.Method {
	case http.MethodPost:
		s.handleUpstreamPost(w, r, auth)
	case http.MethodGet:
		// 只放行 models，其余 GET 一律 404（避免误暴露）
		writeJSONError(w, http.StatusNotFound, "invalid_request_error",
			fmt.Sprintf("不支持 GET %s。可用端点：POST /v1/chat/completions、GET /v1/models", path))
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
			fmt.Sprintf("不支持的方法 %s", r.Method))
	}
}
