package server

// LDAP 登录端点：目录口令只在这里出现一次，换取网关签发的短时会话令牌。
//
// 为什么单独一个端点而不是每请求 bind：
//   - 目录口令不再随每个模型请求上传，减少暴露面；
//   - 目录只承受登录量级的连接，而不是每请求一次 bind；
//   - 请求路径可以用统一的 X-Identity-Token 头，与 OIDC 完全同形。
//
// 这个端点不需要网关 API key（它本身就是换取身份的一步），因此必须按 IP 限速：
// 没有限速的登录口就是一份可被离线撞库的目录口令预言机。

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/identity"
)

const (
	// identityLoginPath 是 LDAP 登录换 token 的端点。
	identityLoginPath = "/v1/_identity/ldap/login"
	// loginMaxConcurrent 是全局并发上限：一次 bind 两条连接（服务账号 + 用户），
	// 4 个并发已经能压住目录侧，也不会让一个慢目录把网关的连接吃光。
	loginMaxConcurrent = 4
	// loginPerIPPerMin 是单 IP 每分钟的登录尝试上限。
	loginPerIPPerMin = 10
	// loginBodyLimit 是登录请求体上限：用户名 + 口令远小于这个数。
	loginBodyLimit = 8 << 10
)

// loginGate 管着登录端点的全局并发与单 IP 频率，形状与 discoverGate 一致。
type loginGate struct {
	mu      sync.Mutex
	sem     chan struct{}
	windows map[string]*loginWindow
	nowFn   func() time.Time
}

type loginWindow struct {
	minute string
	count  int
}

func newLoginGate() *loginGate {
	return &loginGate{
		sem:     make(chan struct{}, loginMaxConcurrent),
		windows: map[string]*loginWindow{},
		nowFn:   time.Now,
	}
}

// Acquire 占一个并发位并检查该 IP 这一分钟的次数。
func (g *loginGate) Acquire(ip string) (release func(), err error) {
	select {
	case g.sem <- struct{}{}:
	default:
		return func() {}, fmt.Errorf("登录请求过于繁忙（全局最多 %d 个并发），请稍后再试", loginMaxConcurrent)
	}
	release = func() { <-g.sem }

	now := g.nowFn()
	minute := now.UTC().Format("2006-01-02T15:04")
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.windows) > 4096 {
		// 攻击者可以用大量源地址把 map 撑大；过期窗口在每次越过容量时清一次。
		for k, v := range g.windows {
			if v.minute != minute {
				delete(g.windows, k)
			}
		}
	}
	w := g.windows[ip]
	if w == nil || w.minute != minute {
		w = &loginWindow{minute: minute}
		g.windows[ip] = w
	}
	if w.count >= loginPerIPPerMin {
		for k, v := range g.windows {
			if v.minute != minute {
				delete(g.windows, k)
			}
		}
		<-g.sem
		return func() {}, fmt.Errorf("登录尝试过于频繁（每分钟最多 %d 次），请稍后再试", loginPerIPPerMin)
	}
	w.count++
	return release, nil
}

// handleLDAPLogin 处理 POST /v1/_identity/ldap/login。
func (s *Server) handleLDAPLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
			"只支持 POST /v1/_identity/ldap/login")
		return
	}
	cfg := s.cfgStore.Current()
	rt := s.policyFor(cfg)
	if rt == nil || rt.idn == nil || rt.idn.ldap == nil {
		writeJSONError(w, http.StatusNotFound, "not_found",
			"本网关没有启用 LDAP 身份（identity.provider=ldap）")
		return
	}

	ip := clientIP(r)
	release, err := s.loginGate.Acquire(ip)
	if err != nil {
		writeJSONError(w, http.StatusTooManyRequests, "rate_limited", err.Error())
		return
	}
	defer release()

	r.Body = http.MaxBytesReader(w, r.Body, loginBodyLimit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"请求体必须是 JSON：{\"username\":\"...\",\"password\":\"...\"}")
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" || req.Password == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "username 与 password 必填")
		return
	}
	requestID := strings.TrimSpace(r.Header.Get("X-Request-Id"))
	if requestID == "" {
		requestID = fmt.Sprintf("ldap-login-%d", s.now().UnixNano())
	}

	principal, err := rt.idn.authenticateLDAP(r.Context(), username, req.Password, requestID)
	if err != nil {
		// 对外的文案只有两种：凭据不对 / 目录暂时不可用。
		// 不回显目录原文（常含 DN 与内部结构），也不区分「用户不存在」与「口令错误」。
		switch {
		case errors.Is(err, identity.ErrDirectoryUnavailable):
			s.log.Errorf("LDAP 登录依赖不可用 ip=%s request_id=%s: %v", ip, requestID, err)
			writeJSONError(w, http.StatusServiceUnavailable, "directory_unavailable",
				"目录服务暂时不可用，请稍后再试")
		case errors.Is(err, identity.ErrConfig), errors.Is(err, identity.ErrInternal):
			s.log.Errorf("LDAP 登录运行态异常 ip=%s request_id=%s: %v", ip, requestID, err)
			writeJSONError(w, http.StatusInternalServerError, "internal", "身份服务内部错误")
		default:
			s.log.Warnf("LDAP 登录失败 ip=%s request_id=%s", ip, requestID)
			writeJSONError(w, http.StatusUnauthorized, "authentication_error",
				"用户名或口令不正确")
		}
		return
	}

	token, expiresAt, err := rt.idn.issueLDAPSession(principal)
	if err != nil {
		s.log.Errorf("LDAP 会话令牌签发失败 request_id=%s: %v", requestID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal", "签发会话令牌失败")
		return
	}
	s.log.Infof("LDAP 登录成功 user=%s ip=%s request_id=%s", principal.Identity.Subject, ip, requestID)
	writeJSON(w, http.StatusOK, map[string]any{
		"token":        token,
		"token_type":   "Bearer",
		"expires_at":   expiresAt.UTC().Format(time.RFC3339),
		"subject":      principal.Identity.Subject,
		"display_name": principal.Identity.DisplayName,
		"header":       IdentityHeaderName,
	})
}
