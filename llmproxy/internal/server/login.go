package server

// 本地账号密码登录，以及「登录会话」这条凭证线。
//
// 三种登录方式（本地账密 / LDAP / OAuth）最终都落到同一件事：给浏览器一枚短时会话
// 令牌，SNAP 用它访问 /v1/_me*。下游 token（sk-…）仍然只用于调模型 —— 两条线分开：
//   - 会话令牌 = 「证明我是谁」，可读可改自己的资料；
//   - 下游 token = 「调用模型」，可被脚本持有，泄露了就轮换。
//
// 本地密码只存 bcrypt 摘要（users.password_hash）。没有密码的用户只能用 token 或
// 目录/SSO 登录；管理员在建号后用 PUT /v1/_admin/users/{name}/password 设置。

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mynet-club/net-tools/llmproxy/internal/identity"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/secrets"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

const (
	passwordLoginPath = "/v1/_auth/password/login"
	passwordBodyLimit = 8 << 10
	// bcrypt 只处理前 72 字节；显式拒绝更长口令，避免「看起来设了 100 位」的误解。
	minPasswordBytes = 8
	maxPasswordBytes = 72
)

const (
	loginSessionSource   = "gateway-login"
	loginSessionProvider = "gateway-session"
)

var (
	errLoginSubjectInvalid = errors.New("身份 subject 不能作网关用户名")
	errLoginUserDisabled   = errors.New("账号已停用")
)

// dummyPasswordHash 让「用户不存在」与「口令错误」走同量级的 bcrypt 比较，
// 不给出可测量的账号枚举信号。
var dummyPasswordHash = func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("llmproxy-dummy-password"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return h
}()

// loginSessionCodec 构造「本地账密 / OAuth」共用的会话编解码器。
func (s *Server) loginSessionCodec() (*identity.SessionCodec, error) {
	if s.secrets == nil {
		return nil, errors.New("多用户模式未启用（服务端缺少主密钥）")
	}
	cfg := s.cfgStore.Current()
	return identity.NewSessionCodecWithProvider(
		s.secrets.Derive(secrets.PurposeLoginSession, secrets.DeriveVersionV1),
		loginSessionSource, loginSessionProvider, cfg.Auth.SessionTTL())
}

// issueLoginSession 为一次成功登录签发网关会话令牌。
func (s *Server) issueLoginSession(subject, display, method string) (string, time.Time, error) {
	codec, err := s.loginSessionCodec()
	if err != nil {
		return "", time.Time{}, err
	}
	ttl := s.cfgStore.Current().Auth.SessionTTL()
	now := s.now()
	id := policy.Identity{
		Subject:     subject,
		Source:      loginSessionSource,
		DisplayName: display,
		AuthMethods: []string{method},
		IssuedAt:    now,
		ExpiresAt:   now.Add(ttl),
	}.Normalize()
	principal := identity.Principal{
		Identity:   id,
		Chain:      policy.ScopeChain{policy.MustScope(policy.ScopeUser, subject)},
		Source:     loginSessionSource,
		ValidUntil: id.ExpiresAt,
	}
	return codec.Issue(principal, ttl)
}

// ensureLoginUser 让一次成功的外部登录对应到一个网关用户：
// 不存在就按 subject 开号（默认 byo），停用则拒绝。
//
// 开号用的 token 是一枚**没人知道**的随机值：用户第一次进控制台后，在 token 页面
// 自己创建/轮换一枚真正要用的。这样「登录」与「拿到脚本凭证」仍是两个动作。
func (s *Server) ensureLoginUser(subject string) (*userEntry, error) {
	if !validName(subject) {
		return nil, errLoginSubjectInvalid
	}
	if e := s.usersSnapshot().byName[subject]; e != nil {
		if !e.Enabled {
			return nil, errLoginUserDisabled
		}
		return e, nil
	}
	placeholder, err := store.NewToken()
	if err != nil {
		return nil, err
	}
	if err := s.db.CreateUser(subject, store.TokenHash(placeholder)); err != nil {
		// 并发首登：另一个请求刚建好同名账号，按已存在处理
		if e := s.usersSnapshot().byName[subject]; e != nil {
			return e, nil
		}
		return nil, err
	}
	_ = s.SyncUsers()
	e := s.usersSnapshot().byName[subject]
	if e == nil {
		return nil, errors.New("用户刚创建但未能加载")
	}
	return e, nil
}

// authenticateLoginSession 是 /v1/_me* 的第二种凭证：X-Identity-Token。
//
// 只用于自助接口（不用于模型调用）。先试外部身份（LDAP 会话 / OIDC JWT），
// 再试本地登录会话；两边都验不过就是没有身份。
func (s *Server) authenticateLoginSession(r *http.Request) authResult {
	res := authResult{ClientIP: clientIP(r), Bucket: policy.SystemScope}
	raw := strings.TrimSpace(r.Header.Get(IdentityHeaderName))
	if raw == "" {
		return res
	}

	subject := ""
	cfg := s.cfgStore.Current()
	if rt := s.policyFor(cfg); rt != nil && rt.idn != nil {
		if p, err := rt.idn.resolve(r.Context(), raw, ""); err == nil {
			subject = p.Identity.Subject
		}
	}
	if subject == "" {
		if codec, err := s.loginSessionCodec(); err == nil {
			if cred, cErr := identity.NewCredential(identity.CredentialSessionToken, raw); cErr == nil {
				if p, rErr := codec.Resolve(r.Context(), cred); rErr == nil {
					subject = p.Identity.Subject
				}
			}
		}
	}
	if subject == "" {
		return res
	}

	e := s.usersSnapshot().byName[subject]
	if e == nil {
		return res
	}
	if !e.Enabled {
		res.Disabled = true
		return res
	}
	res.OK = true
	res.UserName = subject
	res.Label = subject
	res.Bucket = userBucket(subject)
	return res
}

// handlePasswordLogin 处理 POST /v1/_auth/password/login。
func (s *Server) handlePasswordLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
			"只支持 POST /v1/_auth/password/login")
		return
	}
	if !s.MultiUserEnabled() {
		writeJSONError(w, http.StatusNotImplemented, "not_configured",
			"多用户模式未启用（服务端缺少主密钥）")
		return
	}
	cfg := s.cfgStore.Current()
	if !cfg.Auth.Methods.PasswordEnabled() {
		writeJSONError(w, http.StatusNotFound, "not_found", "本地账号登录未启用")
		return
	}

	ip := clientIP(r)
	release, err := s.loginGate.Acquire(ip)
	if err != nil {
		writeJSONError(w, http.StatusTooManyRequests, "rate_limited", err.Error())
		return
	}
	defer release()

	r.Body = http.MaxBytesReader(w, r.Body, passwordBodyLimit)
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

	// 用户不存在 / 没设密码 / 密码错误，对外只有一句话，且都跑一次 bcrypt。
	hash := ""
	if e := s.usersSnapshot().byName[username]; e != nil && e.Enabled {
		if h, hErr := s.db.GetUserPasswordHash(username); hErr == nil {
			hash = h
		}
	}
	compareAgainst := []byte(hash)
	if len(compareAgainst) == 0 {
		compareAgainst = dummyPasswordHash
	}
	if err := bcrypt.CompareHashAndPassword(compareAgainst, []byte(req.Password)); err != nil || hash == "" {
		s.log.Warnf("本地密码登录失败 user=%s ip=%s", username, ip)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error", "用户名或口令不正确")
		return
	}

	token, expiresAt, err := s.issueLoginSession(username, "", "password")
	if err != nil {
		s.log.Errorf("本地密码登录签发会话失败 user=%s: %v", username, err)
		writeJSONError(w, http.StatusInternalServerError, "internal", "签发会话令牌失败")
		return
	}
	s.auditUser(username, "auth.login", username, "password")
	s.log.Infof("本地密码登录成功 user=%s ip=%s", username, ip)
	writeJSON(w, http.StatusOK, map[string]any{
		"token":        token,
		"token_type":   "Bearer",
		"expires_at":   expiresAt.UTC().Format(time.RFC3339),
		"subject":      username,
		"display_name": "",
		"header":       IdentityHeaderName,
	})
}

// handleAdminSetPassword 处理 PUT /v1/_admin/users/{name}/password。
func (s *Server) handleAdminSetPassword(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 PUT")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := readJSONBody(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	if len(req.Password) < minPasswordBytes || len(req.Password) > maxPasswordBytes {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"口令长度必须在 8..72 字节之间（bcrypt 的上限是 72 字节）")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "口令摘要失败")
		return
	}
	if err := s.db.SetUserPassword(name, string(hash)); err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			writeJSONError(w, http.StatusNotFound, "not_found", "用户不存在")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.auditUser("admin", "user.set_password", name, "")
	s.log.Warnf("管理员为用户 %s 设置了本地密码", name)
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "updated": true})
}
