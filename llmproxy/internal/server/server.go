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

	// 会话粘性：把同一个 (用户, 会话, 模型) 钉在同一个后端，保住上游的前缀缓存。
	// 见 affinity.go 与 forwarder.go 里的接线。
	affinity *affinityStore

	// /discover 的频率与并发闸门（用户可控的出网探测，见 discover.go）
	discoverGate *discoverGate

	// 用量报表的短 TTL 缓存（界面轮询热点，见 statscache.go）
	usageCache *usageReportCache

	// persistFailures 是「请求已成功返回给客户端、但记账落库失败」的累计次数。
	//
	// 这个数必须是**可观测**的：落库失败时请求已经发出去了，账却永久丢失 ——
	// README 承诺的「客户端成功数 / 上游收到数 / 数据库落库数三者一致」会静默破裂，
	// 而只写一行 ERROR 日志的话，没人盯着日志就永远发现不了。
	// 所以暴露到 /healthz，让监控能直接盯这一个数。
	persistFailures atomic.Int64

	// 配置写回后等热加载的时长；测试里置 0 可跳过等待
	configApplyWait time.Duration

	// 规则 B 比价用的时钟。留空走 time.Now，测试可换成固定时刻 ——
	// 「空闲时段谁便宜」这种判断依赖当前时间，不给测试一个把手就没法稳定断言。
	nowFn func() time.Time
}

// now 返回当前时刻；测试可以通过 nowFn 固定它。
func (s *Server) now() time.Time {
	if s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now()
}

func New(cfgStore *config.Store, db *store.Store, r *router.Router, lg *logx.Logger) *Server {
	// 会话粘性的保留时长跟配置走：没配用默认 24h，显式 0 = 关闭（请求照旧随机选）
	affTTL := defaultAffinityTTL
	if c := cfgStore.Current(); c != nil {
		affTTL = time.Duration(c.Server.AffinityTTL()) * time.Millisecond
	}
	s := &Server{
		cfgStore:     cfgStore,
		db:           db,
		router:       r,
		log:          lg,
		transports:   dialer.NewTransportCache(),
		startedAt:    time.Now(),
		affinity:     newAffinityStore(affTTL, defaultAffinityMax),
		discoverGate: newDiscoverGate(),
		usageCache:   newUsageReportCache(),
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

// InvalidateUsageCache 丢掉用量报表缓存。
// CLI 写价目/用户后发 SIGHUP，服务端要立刻反映新数据，不能等 TTL。
func (s *Server) InvalidateUsageCache() { s.usageCache.Flush() }

// egressCheck 给**用户可控上游**用的拨号层出网判定。strict 跟
// server.block_local_upstream 走（热重载实时生效）；系统池不走这里。
//
// 这是「配置校验 + 实际拨号再校验」的第二层：配置时 CheckUpstreamEgress 看到的
// DNS 结果可能在拨号前被改掉（rebinding），所以真正 connect 前还要再判一次。
func (s *Server) egressCheck() dialer.IPCheck {
	return func(ip net.IP) error {
		strict := false
		if c := s.cfgStore.Current(); c != nil {
			strict = c.Server.BlockLocalUpstream
		}
		return config.CheckResolvedIP(ip, strict)
	}
}

// transportFor 按候选归属拿连接池：用户自有上游带拨号层出网校验，系统池不带
// （运营者自己写的 base_url，自己负责）。两套不能混用同一个缓存条目。
func (s *Server) transportFor(systemPaid bool, proxyURL string) (*http.Transport, error) {
	if systemPaid {
		return s.transports.Get(proxyURL)
	}
	return s.transports.GetChecked(proxyURL, s.egressCheck())
}

// SetAffinityTTL 热重载时更新会话粘性的保留时长。
//
// 必须显式调：affinity_ttl_ms 被缓存在 affinityStore 里，不像 stream_idle_timeout_ms
// 那样每请求实时读配置，所以光把新配置存进 cfgStore 是不会生效的。
func (s *Server) SetAffinityTTL(d time.Duration) { s.affinity.SetTTL(d) }

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
	// /v1 要显式注册：只注册 /v1/ 的话 ServeMux 会把 GET /v1 用 301 重定向到 /v1/，
	// 而不少客户端在重定向时会丢掉 Authorization 头，于是探活变成 401。
	mux.HandleFunc("/v1", s.handleV1)
	mux.HandleFunc("/v1/", s.handleV1)
	mux.HandleFunc("/", s.handleNotFound)
	return s.withAccessLog(s.withCORS(mux))
}

// withCORS 让浏览器里的客户端（桌面端设置页的「测试连接」、网页控制台以外的
// 前端）能直接调本机网关。
//
// 没有这一层时的症状是 `fetch failed`：带 Authorization 的跨域请求浏览器会先发
// OPTIONS 预检，而路由表只注册了 GET/POST，预检拿到 405 且响应里没有
// Access-Control-Allow-*，于是浏览器把真正的请求掐掉 —— curl 不走预检，所以
// 「curl 通、界面测试失败」。这正是 MiMo Desktop 设置里测自定义模型时报错的原因。
//
// 放开跨域不会让接口多暴露：没 key 一样 401，有 key 的人在浏览器里本来也能用 curl。
// 鉴权仍走 Authorization 头，不走 Cookie，所以 Allow-Origin 可以是 `*`。
func (s *Server) withCORS(next http.Handler) http.Handler {
	const (
		allowOrigin  = "*"
		allowMethods = "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS"
		allowHeaders = "Authorization, Content-Type, Accept, X-Requested-With"
		maxAge       = "86400"
	)
	apply := func(w http.ResponseWriter) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", allowOrigin)
		h.Set("Access-Control-Allow-Methods", allowMethods)
		h.Set("Access-Control-Allow-Headers", allowHeaders)
		h.Set("Access-Control-Max-Age", maxAge)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apply(w)
		// 预检到此为止：不进路由表，免得被各 handler 的「只支持 GET」打成 405
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
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
		// 非 0 表示有请求已经成功返回给客户端、但记账没落库 —— 账在丢，要查磁盘/锁。
		// 刻意不影响 status：转发本身是好的，把它标成不健康会让监控误判成服务不可用。
		"persist_failures": s.persistFailures.Load(),
	})
}

// PersistFailures 返回记账落库失败的累计次数（观测/测试用）。
func (s *Server) PersistFailures() int64 { return s.persistFailures.Load() }

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
	// 消费模式用户一律 403：他们没有自己的上游，这个接口对他们只会展示**系统池** ——
	// 而系统池视图里含 base_url、内联代理 URL（常带 user:pass）与 last_error
	// （上游错误响应体的前 300 字节）。用户台压根不调这个接口（它用的是 /v1/_me 的
	// broken_providers），所以拒掉不损失任何功能，却一次堵住两条泄漏。
	//
	// BYO 用户照旧放行：他们看到的是**自己**那些上游的状态（下面按 auth.Scope 收窄过），
	// base_url 与错误正文本来就是他们自己的东西 ——「我配的上游为什么在冷却」是正当需求，
	// 而且有测试钉住（TestCircuitBreakerIsolatedByUser）。静态 key 是运营者自己，也照旧。
	if e := s.usersSnapshot().byName[auth.Scope]; e != nil && e.Consumption {
		writeJSONError(w, http.StatusForbidden, "invalid_request_error",
			"消费模式用户没有自己的上游，这里不展示系统池；用量请看 /v1/_me/usage")
		return
	}
	// 走到这里只剩静态 key（全局作用域）与 BYO 用户（自己的上游），
	// 两者都按 auth.Scope 收窄即可 —— 消费模式已经在上面被拒了。
	providers, _ := s.providersFor(auth.Scope, "")
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

	// GET /v1 与 /v1/ 回模型列表。
	//
	// 严格说 OpenAI 的规范里只有 /v1/models，没有 GET /v1 —— 但把 base_url 直接粘进
	// 浏览器或拿它探活是很常见的动作，回一句 404 提示不如回「现在能用哪些模型」。
	// 直接复用 handleModels，所以鉴权、以及「每个用户只看到自己那份」的收窄
	// 与 /v1/models 完全一致，不扩大任何暴露面（匿名仍然是 401）。
	if path == "/v1" || path == "/v1/" {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			s.handleModels(w, r)
			return
		}
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
			fmt.Sprintf("不支持 %s /v1。可用端点：POST /v1/chat/completions、GET /v1/models", r.Method))
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
		if !isAllowedPostPath(path) {
			writeJSONError(w, http.StatusNotFound, "invalid_request_error",
				fmt.Sprintf("不支持 POST %s。可用端点：%s", path, strings.Join(allowedPostPaths, "、")))
			return
		}
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

// allowedPostPaths 是下游可以 POST 的端点白名单。
//
// 曾经 POST 侧完全敞开、把下游路径原样拼到上游 base_url 后面，于是任何持有效 token 的
// 用户都能让网关带着**运营者的上游密钥**去 POST 上游主机上的任意路径
// （/v1/files 上传、/v1/fine_tuning/jobs 开微调任务、/v1/assistants…），
// 而且这些调用完全不进计量 —— 消费模式的模型级访问控制因此形同虚设。
// GET 侧本来就写了「避免误暴露」，这里补齐。
//
// 收录判据是「响应形状与 chat/completions 同族、usage 能被 usageScanner 认出来」：
// 放行的端点都能被正常计量；不放行的要么没有 usage、要么形状不同（如 OpenAI 的
// /v1/responses 用 output 而不是 choices），转发了就是白送。要加新端点，
// 先确认 usageScanner 认得它的 usage 形状。
var allowedPostPaths = []string{
	"/v1/chat/completions",
	"/v1/completions",
	"/v1/embeddings",
}

// isAllowedPostPath 报告这个路径是否在白名单里。
//
// 比的是 `r.URL.Path`（**已解码**），拼接上游 URL 时用的也是它 —— 两边同源，
// 所以 `%2F` / `%3F` 这类编码定界符无法在「检查」与「拼接」之间制造差异：
// `/v1/chat%2Fcompletions` 解码后就是 `/v1/chat/completions`，检查通过、
// 拼出去的也正是这个路径，与合法请求完全等价。
func isAllowedPostPath(path string) bool {
	for _, p := range allowedPostPaths {
		if path == p {
			return true
		}
	}
	return false
}
