package server

// OAuth 2.0 / OIDC 授权码登录（PKCE）。
//
// 流程：
//   1. GET  /v1/_auth/oauth/start     → 302 到 IdP，state 与 PKCE verifier 存在内存里，
//      state 同时写进一枚 SameSite=Lax 的 HttpOnly cookie（防登录 CSRF）；
//   2. GET  /v1/_auth/oauth/callback  → 校验 state（一次性）→ 换 token → 读 userinfo
//      → 映射 subject → 开号/校验 → 签发网关会话令牌 → 生成一次性 code；
//   3. 302 回 <spa_path>#/oauth-callback?code=…；
//   4. POST /v1/_auth/oauth/exchange  → 用一次性的 code 换会话令牌（60 秒有效）。
//
// token 不进 URL：回调只带 60 秒、一次性的 code，真正的会话令牌由 SPA 用 POST 取。
// 这样浏览器历史、Referer、访问日志里都不会留下可复用的凭证。

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

const (
	oauthStartPath      = "/v1/_auth/oauth/start"
	oauthExchangePath   = "/v1/_auth/oauth/exchange"
	oauthCallbackCookie = "llmproxy_oauth_state"
	oauthStateTTL       = 10 * time.Minute
	oauthCodeTTL        = 60 * time.Second
	oauthBodyLimit      = 4 << 10
)

type oauthPending struct {
	verifier string
	expires  time.Time
}

type oauthCode struct {
	token   string
	subject string
	expires time.Time
}

// oauthFlows 是两类一次性凭据的内存取（单进程；多副本部署时回调必须落到同一实例，
// 与 sticky session 同一前提）。
type oauthFlows struct {
	mu      sync.Mutex
	pending map[string]oauthPending
	codes   map[string]oauthCode
}

func newOAuthFlows() *oauthFlows {
	return &oauthFlows{
		pending: map[string]oauthPending{},
		codes:   map[string]oauthCode{},
	}
}

func (f *oauthFlows) putPending(state, verifier string, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, v := range f.pending {
		if now.After(v.expires) {
			delete(f.pending, k)
		}
	}
	f.pending[state] = oauthPending{verifier: verifier, expires: now.Add(oauthStateTTL)}
}

func (f *oauthFlows) takePending(state string, now time.Time) (oauthPending, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pending[state]
	delete(f.pending, state)
	if !ok || now.After(p.expires) {
		return oauthPending{}, false
	}
	return p, true
}

func (f *oauthFlows) putCode(code, token, subject string, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, v := range f.codes {
		if now.After(v.expires) {
			delete(f.codes, k)
		}
	}
	f.codes[code] = oauthCode{token: token, subject: subject, expires: now.Add(oauthCodeTTL)}
}

func (f *oauthFlows) takeCode(code string, now time.Time) (oauthCode, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.codes[code]
	delete(f.codes, code)
	if !ok || now.After(c.expires) {
		return oauthCode{}, false
	}
	return c, true
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// handleOAuthStart 处理 GET /v1/_auth/oauth/start。
func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET")
		return
	}
	cfg := s.cfgStore.Current()
	oc := cfg.Auth.OAuth
	if !oc.Configured() || !cfg.Auth.Methods.OAuthEnabled() {
		writeJSONError(w, http.StatusNotFound, "not_found", "统一身份认证登录未启用")
		return
	}

	state, err := randHex(24)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "生成 state 失败")
		return
	}
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "生成 PKCE 失败")
		return
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	s.oauthFlows.putPending(state, verifier, s.now())

	http.SetCookie(w, &http.Cookie{
		Name:     oauthCallbackCookie,
		Value:    state,
		Path:     strings.TrimSuffix(config.OAuthCallbackPath, "/callback"),
		MaxAge:   int(oauthStateTTL / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})

	target, err := url.Parse(oc.AuthURL)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "auth_url 不合法")
		return
	}
	q := target.Query()
	q.Set("response_type", "code")
	q.Set("client_id", oc.ClientID)
	q.Set("redirect_uri", oc.RedirectURL)
	q.Set("scope", strings.Join(oc.Scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// handleOAuthCallback 处理 GET /v1/_auth/oauth/callback。
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET")
		return
	}
	cfg := s.cfgStore.Current()
	oc := cfg.Auth.OAuth
	if !oc.Configured() || !cfg.Auth.Methods.OAuthEnabled() {
		writeOAuthPage(w, http.StatusNotFound, "统一身份认证登录未启用")
		return
	}

	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.log.Warnf("OAuth 回调携带错误: %s", e)
		writeOAuthPage(w, http.StatusBadRequest, "身份提供方返回了错误："+e)
		return
	}
	code, state := q.Get("code"), q.Get("state")
	if code == "" || state == "" {
		writeOAuthPage(w, http.StatusBadRequest, "回调缺少 code 或 state")
		return
	}

	// state 必须与发起时写入的 cookie 一致（防登录 CSRF），并且只能使用一次
	cookie, err := r.Cookie(oauthCallbackCookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		writeOAuthPage(w, http.StatusBadRequest, "登录状态已失效，请重新发起登录")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oauthCallbackCookie, Value: "", Path: strings.TrimSuffix(config.OAuthCallbackPath, "/callback"),
		MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil,
	})
	pending, ok := s.oauthFlows.takePending(state, s.now())
	if !ok {
		writeOAuthPage(w, http.StatusBadRequest, "登录状态已失效，请重新发起登录")
		return
	}

	client := &http.Client{Timeout: oc.Timeout()}
	accessToken, err := exchangeOAuthCode(client, &oc, code, pending.verifier)
	if err != nil {
		s.log.Errorf("OAuth 换取 token 失败: %v", err)
		writeOAuthPage(w, http.StatusBadGateway, "身份提供方暂时不可用，请稍后再试")
		return
	}
	subject, display, err := fetchOAuthSubject(client, &oc, accessToken)
	if err != nil {
		s.log.Errorf("OAuth 读取 userinfo 失败: %v", err)
		writeOAuthPage(w, http.StatusBadGateway, "身份提供方暂时不可用，请稍后再试")
		return
	}
	if !validName(subject) {
		writeOAuthPage(w, http.StatusBadRequest,
			"身份提供方返回的账号不能作网关用户名（只允许字母、数字、点、下划线、连字符）")
		return
	}
	if _, err := s.ensureLoginUser(subject); err != nil {
		if err == errLoginUserDisabled {
			writeOAuthPage(w, http.StatusForbidden, "账号 "+subject+" 已停用")
			return
		}
		s.log.Errorf("OAuth 登录开户失败 subject=%s: %v", subject, err)
		writeOAuthPage(w, http.StatusInternalServerError, "登录失败，请联系管理员")
		return
	}

	token, _, err := s.issueLoginSession(subject, display, "oauth")
	if err != nil {
		s.log.Errorf("OAuth 签发会话失败 subject=%s: %v", subject, err)
		writeOAuthPage(w, http.StatusInternalServerError, "签发会话令牌失败")
		return
	}
	oneTime, err := randHex(24)
	if err != nil {
		writeOAuthPage(w, http.StatusInternalServerError, "登录失败")
		return
	}
	s.oauthFlows.putCode(oneTime, token, subject, s.now())
	s.auditUser(subject, "auth.login", subject, "oauth")

	target := strings.TrimSuffix(oc.SPAPath, "/") + "/#/oauth-callback?code=" + url.QueryEscape(oneTime)
	http.Redirect(w, r, target, http.StatusFound)
}

// handleOAuthExchange 处理 POST /v1/_auth/oauth/exchange：一次性 code 换会话令牌。
func (s *Server) handleOAuthExchange(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 POST")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, oauthBodyLimit)
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "请求体必须是 {\"code\":\"...\"}")
		return
	}
	c, ok := s.oauthFlows.takeCode(strings.TrimSpace(req.Code), s.now())
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"登录凭据已失效，请重新发起登录")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      c.token,
		"token_type": "Bearer",
		"subject":    c.subject,
		"header":     IdentityHeaderName,
	})
}

// exchangeOAuthCode 用授权码换 access_token。
func exchangeOAuthCode(client *http.Client, oc *config.OAuthConfig, code, verifier string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", oc.RedirectURL)
	form.Set("code_verifier", verifier)
	if oc.AuthStyle == "post" {
		form.Set("client_id", oc.ClientID)
		form.Set("client_secret", oc.ClientSecret)
	}
	req, err := http.NewRequest(http.MethodPost, oc.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if oc.AuthStyle != "post" {
		req.SetBasicAuth(oc.ClientID, oc.ClientSecret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("token 端点返回 %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("token 响应里没有 access_token")
	}
	return out.AccessToken, nil
}

// fetchOAuthSubject 用 access_token 读 userinfo，取 subject 与显示名。
func fetchOAuthSubject(client *http.Client, oc *config.OAuthConfig, accessToken string) (string, string, error) {
	req, err := http.NewRequest(http.MethodGet, oc.UserinfoURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("userinfo 返回 %d", resp.StatusCode)
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return "", "", fmt.Errorf("userinfo 不是 JSON: %w", err)
	}
	claim := func(name string) string {
		v, ok := claims[name]
		if !ok || v == nil {
			return ""
		}
		s, ok := v.(string)
		if !ok {
			return ""
		}
		return strings.TrimSpace(s)
	}
	subject := claim(oc.SubjectClaim)
	if subject == "" {
		return "", "", fmt.Errorf("userinfo 缺少 %s", oc.SubjectClaim)
	}
	display := claim(oc.NameClaim)
	if display == subject {
		display = ""
	}
	return subject, display, nil
}

// writeOAuthPage 给浏览器一段可读的错误页（回调是顶层导航，不是 XHR）。
func writeOAuthPage(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `<!doctype html><meta charset="utf-8"><title>登录失败</title>
<body style="font:14px/1.7 -apple-system,BlinkMacSystemFont,'PingFang SC',sans-serif;padding:48px;color:#0f172a">
<h2 style="margin:0 0 8px">登录未完成</h2>
<p style="color:#64748b">`+htmlEscape(msg)+`</p>
<p><a href="/spa/user/#/login">返回登录页</a></p>`)
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}
