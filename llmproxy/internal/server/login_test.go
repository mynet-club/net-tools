package server

// P1 登录后端测试：本地账密、会话态自助、管理员设密码、LDAP 首登开户、OAuth 授权码全流程。

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// reqJSON 发一次带自定义头的请求，返回状态码、响应头与解析后的 JSON。
func reqJSON(t *testing.T, method, target string, headers map[string]string, body any) (int, http.Header, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		payload, _ := json.Marshal(body)
		rd = strings.NewReader(string(payload))
	}
	req, err := http.NewRequest(method, target, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, raw
}

func setTestPassword(t *testing.T, h *muHarness, name, password string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.db.SetUserPassword(name, string(hash)); err != nil {
		t.Fatalf("SetUserPassword(%s): %v", name, err)
	}
}

func TestPasswordLoginAndSessionSelfService(t *testing.T) {
	h := newMUHarness(t)
	h.addUser(t, "alice")
	setTestPassword(t, h, "alice", "correct-horse-1")

	code, _, raw := reqJSON(t, http.MethodPost, h.gateway.URL+passwordLoginPath, nil,
		map[string]any{"username": "alice", "password": "correct-horse-1"})
	if code != http.StatusOK {
		t.Fatalf("账密登录应 200，实际 %d: %s", code, raw)
	}
	sess, _ := jsonMap(t, raw)["token"].(string)
	if sess == "" {
		t.Fatalf("登录响应没有会话令牌: %s", raw)
	}

	// 会话令牌可读自己的资料
	code, _, raw = reqJSON(t, http.MethodGet, h.gateway.URL+"/v1/_me",
		map[string]string{IdentityHeaderName: sess}, nil)
	if code != http.StatusOK {
		t.Fatalf("会话令牌应能调 /v1/_me，实际 %d: %s", code, raw)
	}
	if name, _ := jsonMap(t, raw)["name"].(string); name != "alice" {
		t.Errorf("/v1/_me name = %q，期望 alice", name)
	}

	// 会话令牌可以创建/轮换下游 token
	code, _, raw = reqJSON(t, http.MethodPost, h.gateway.URL+"/v1/_me/token",
		map[string]string{IdentityHeaderName: sess}, map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("会话令牌应能轮换 token，实际 %d: %s", code, raw)
	}
	if tok, _ := jsonMap(t, raw)["token"].(string); !strings.HasPrefix(tok, "sk-") {
		t.Fatalf("轮换没有返回下游 token: %s", raw)
	}

	// 但会话令牌不能拿去调模型：模型调用只认下游 token
	code, _, _ = reqJSON(t, http.MethodPost, h.gateway.URL+"/v1/chat/completions",
		map[string]string{IdentityHeaderName: sess}, map[string]any{"model": "x"})
	if code != http.StatusUnauthorized {
		t.Fatalf("会话令牌调模型应 401，实际 %d", code)
	}
}

func TestPasswordLoginRejectsWithoutLeaking(t *testing.T) {
	h := newMUHarness(t)
	h.addUser(t, "alice")
	setTestPassword(t, h, "alice", "correct-horse-1")

	cases := []struct{ name, user, pass string }{
		{"密码错误", "alice", "wrong-password"},
		{"用户不存在", "nobody", "whatever-123"},
		{"没设密码", "sk-none", "whatever-123"},
	}
	for _, c := range cases {
		code, _, raw := reqJSON(t, http.MethodPost, h.gateway.URL+passwordLoginPath, nil,
			map[string]any{"username": c.user, "password": c.pass})
		if code != http.StatusUnauthorized {
			t.Fatalf("%s 应 401，实际 %d: %s", c.name, code, raw)
		}
		if strings.Contains(string(raw), c.pass) {
			t.Errorf("%s 的响应不得回显口令", c.name)
		}
	}

	if err := h.db.SetUserEnabled("alice", false); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}
	code, _, _ := reqJSON(t, http.MethodPost, h.gateway.URL+passwordLoginPath, nil,
		map[string]any{"username": "alice", "password": "correct-horse-1"})
	if code != http.StatusUnauthorized {
		t.Fatalf("停用账号应 401，实际 %d", code)
	}
}

func TestAdminSetsPasswordThenLogin(t *testing.T) {
	h := newMUHarness(t)
	h.addUser(t, "carol")
	admin := map[string]string{"Authorization": "Bearer sk-admin"}

	code, _, raw := reqJSON(t, http.MethodPut, h.gateway.URL+"/v1/_admin/users/carol/password", admin,
		map[string]any{"password": "another-pass-1"})
	if code != http.StatusOK {
		t.Fatalf("管理员设密码应 200，实际 %d: %s", code, raw)
	}
	code, _, raw = reqJSON(t, http.MethodPost, h.gateway.URL+passwordLoginPath, nil,
		map[string]any{"username": "carol", "password": "another-pass-1"})
	if code != http.StatusOK {
		t.Fatalf("设置后应能登录，实际 %d: %s", code, raw)
	}

	code, _, _ = reqJSON(t, http.MethodPut, h.gateway.URL+"/v1/_admin/users/carol/password", admin,
		map[string]any{"password": "short"})
	if code != http.StatusBadRequest {
		t.Fatalf("过短口令应 400，实际 %d", code)
	}
	code, _, _ = reqJSON(t, http.MethodPut, h.gateway.URL+"/v1/_admin/users/nobody/password", admin,
		map[string]any{"password": "another-pass-1"})
	if code != http.StatusNotFound {
		t.Fatalf("不存在的用户应 404，实际 %d", code)
	}
}

func TestLDAPLoginProvisionsUserForSelfService(t *testing.T) {
	h := newMintHarness(t)
	resp, raw := h.post(t, identityLoginPath, "",
		map[string]any{"username": "alice", "password": "correct-horse"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LDAP 登录应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	sess, _ := jsonMap(t, raw)["token"].(string)

	if _, err := h.db.GetUser("alice"); err != nil {
		t.Fatalf("首登应按 subject 开号: %v", err)
	}
	code, _, meRaw := reqJSON(t, http.MethodGet, h.gateway.URL+"/v1/_me",
		map[string]string{IdentityHeaderName: sess}, nil)
	if code != http.StatusOK {
		t.Fatalf("LDAP 会话令牌应能调 /v1/_me，实际 %d: %s", code, meRaw)
	}
}

// oauthTestIdP 是一个最小的假 IdP：token 端点校验 PKCE，userinfo 返回 sub/name。
type oauthTestIdP struct {
	srv       *httptest.Server
	challenge string
	verifier  string
	tokenHits int
}

func newOAuthTestIdP(t *testing.T) *oauthTestIdP {
	t.Helper()
	idp := &oauthTestIdP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idp.tokenHits++
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("code") != "idp-code" {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		verifier := r.Form.Get("code_verifier")
		idp.verifier = verifier
		sum := sha256.Sum256([]byte(verifier))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != idp.challenge {
			http.Error(w, "pkce mismatch", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-1", "token_type": "Bearer"})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-1" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "bob", "name": "Bob"})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

type oauthHarness struct {
	*muHarness
	idp *oauthTestIdP
}

func (idp *oauthTestIdP) harness(t *testing.T) *oauthHarness {
	t.Helper()
	h := newMUHarness(t)
	// 覆盖配置：在基础配置后追加 auth.oauth 段（热加载同一份文件）
	cfg := h.cfgYAML + `
auth:
  oauth:
    provider_name: 学校 SSO
    client_id: cid
    client_secret: csecret
    auth_url: ` + idp.srv.URL + `/authorize
    token_url: ` + idp.srv.URL + `/token
    userinfo_url: ` + idp.srv.URL + `/userinfo
    redirect_url: http://127.0.0.1:1/v1/_auth/oauth/callback
    spa_path: /spa/user/
`
	if err := os.WriteFile(h.configPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.cfgStore.Reload(); err != nil {
		t.Fatalf("热加载配置失败: %v", err)
	}
	return &oauthHarness{muHarness: h, idp: idp}
}

func TestOAuthLoginFlow(t *testing.T) {
	h := newOAuthTestIdP(t).harness(t)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// 1) 发起登录：拿到 IdP 重定向与 state cookie
	resp, err := noRedirect.Get(h.gateway.URL + oauthStartPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start 应 302，实际 %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	state := q.Get("state")
	if state == "" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("start 的跳转参数不对: %s", loc)
	}
	var stateCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == oauthCallbackCookie {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("start 没有写 state cookie")
	}

	h.idp.challenge = q.Get("code_challenge")

	// 2) 回调：带 code 与 cookie
	cb := h.gateway.URL + "/v1/_auth/oauth/callback?code=idp-code&state=" + url.QueryEscape(state)
	req, _ := http.NewRequest(http.MethodGet, cb, nil)
	req.AddCookie(stateCookie)
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback 应 302，实际 %d", resp.StatusCode)
	}
	back, _ := url.Parse(resp.Header.Get("Location"))
	if !strings.HasPrefix(back.Path, "/spa/user/") {
		t.Fatalf("回调应跳回 SPA，实际 %s", back)
	}
	frag, _ := url.ParseQuery(strings.TrimPrefix(back.Fragment, "/oauth-callback?"))
	oneTime := frag.Get("code")
	if oneTime == "" {
		t.Fatalf("回调没有带一次性 code: %s", back)
	}

	// 3) 一次性 code 换会话令牌，然后自助接口可用（首登已开号）
	code, _, raw := reqJSON(t, http.MethodPost, h.gateway.URL+oauthExchangePath, nil,
		map[string]any{"code": oneTime})
	if code != http.StatusOK {
		t.Fatalf("exchange 应 200，实际 %d: %s", code, raw)
	}
	sess, _ := jsonMap(t, raw)["token"].(string)
	code, _, raw = reqJSON(t, http.MethodGet, h.gateway.URL+"/v1/_me",
		map[string]string{IdentityHeaderName: sess}, nil)
	if code != http.StatusOK {
		t.Fatalf("OAuth 会话令牌应能调 /v1/_me，实际 %d: %s", code, raw)
	}
	if name, _ := jsonMap(t, raw)["name"].(string); name != "bob" {
		t.Errorf("OAuth 首登应开 bob 的号，实际 %q", name)
	}

	// 一次性 code 不能复用
	code, _, _ = reqJSON(t, http.MethodPost, h.gateway.URL+oauthExchangePath, nil,
		map[string]any{"code": oneTime})
	if code != http.StatusBadRequest {
		t.Fatalf("一次性 code 复用应 400，实际 %d", code)
	}
}

func TestAuthMethodsReflectOAuthConfig(t *testing.T) {
	h := newOAuthTestIdP(t).harness(t)
	code, _, raw := reqJSON(t, http.MethodGet, h.gateway.URL+authMethodsPath, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("methods = %d: %s", code, raw)
	}
	var payload struct {
		Methods []AuthMethod `json:"methods"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	for _, m := range payload.Methods {
		if m.ID == "oauth" {
			if !m.Enabled || m.Label != "学校 SSO" {
				t.Fatalf("OAuth tab 应启用且用配置文案: %+v", m)
			}
			return
		}
	}
	t.Fatalf("methods 里没有 oauth: %s", raw)
}
