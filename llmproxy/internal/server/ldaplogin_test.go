package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/identity"
	"github.com/mynet-club/net-tools/llmproxy/internal/secrets"
)

type loginFakeDirectory struct {
	entry       identity.LDAPEntry
	password    string
	unavailable bool
}

func (f *loginFakeDirectory) Lookup(_ context.Context, _ identity.LDAPTrust, _ string) (identity.LDAPEntry, error) {
	if f.unavailable {
		return identity.LDAPEntry{}, fmt.Errorf("%w", identity.ErrDirectoryUnavailable)
	}
	return f.entry, nil
}

func (f *loginFakeDirectory) LookupDN(_ context.Context, _ identity.LDAPTrust, _ string) (identity.LDAPEntry, error) {
	return f.entry, nil
}

func (f *loginFakeDirectory) Bind(_ context.Context, _ identity.LDAPTrust, _ string, password string) error {
	if password != f.password {
		return fmt.Errorf("%w", identity.ErrCredential)
	}
	return nil
}

func (f *loginFakeDirectory) Groups(_ context.Context, _ identity.LDAPTrust, _ string) ([]string, error) {
	return nil, nil
}

// loginHarness 起一个 shadow 夹具，并把 LDAP 运行态注入当前配置修订。
//
// 生产路径由 newLDAPIdentityRuntime 构造；这里注入同一个 Provider/SessionCodec
// 组合，覆盖「登录端点 → 目录绑定 → 签发令牌」这条链路，而不需要真的起一个 LDAP 服务。
func loginHarness(t *testing.T, dir identity.LDAPDirectory) *harness {
	t.Helper()
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"})+
		policySection("shadow", "t-open", "system:gateway", 1))
	// 生产里 LDAP 会话的 HMAC 子密钥来自 master.key；这里给一份主密钥，
	// 让「登录 → 开户 → 会话令牌」走与生产相同的路径。
	cipher, err := secrets.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("生成主密钥失败: %v", err)
	}
	h.srv.WithSecrets(cipher)
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatalf("SyncUsers: %v", err)
	}

	provider, err := identity.NewLDAPDirectoryProvider(identity.LDAPTrust{
		Source:             "campus-ldap",
		URL:                "ldaps://ldap.example.edu:636",
		BindDN:             "cn=svc,dc=example,dc=edu",
		BindPassword:       "svc",
		BaseDN:             "ou=people,dc=example,dc=edu",
		UserAttr:           "uid",
		IdentityTTL:        15 * time.Minute,
		AllowedBindTargets: []string{"ldap.example.edu:636"},
	}, dir)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := identity.NewSessionCodec(
		[]byte("0123456789abcdef0123456789abcdef"), "campus-ldap", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	h.srv.policyMu.Lock()
	h.srv.policyRun = &policyRuntime{
		mode: config.PolicyModeShadow,
		idn: &identityRuntime{
			provider: codec, source: "campus-ldap",
			ldap: provider, sessions: codec, sessionTTL: 15 * time.Minute,
		},
	}
	h.srv.policyRunRev = h.cfgStore.Revision()
	h.srv.policyMu.Unlock()
	return h
}

func loginAliceDirectory() *loginFakeDirectory {
	return &loginFakeDirectory{
		entry: identity.LDAPEntry{
			DN: "uid=alice,ou=people,dc=example,dc=edu",
			Attrs: map[string][]string{
				"uid":         {"alice"},
				"displayname": {"Alice"},
			},
		},
		password: "correct-horse",
	}
}

func postLogin(t *testing.T, h *harness, username, password string) (int, map[string]any) {
	t.Helper()
	resp, raw := h.post(t, identityLoginPath, "", map[string]any{
		"username": username,
		"password": password,
	})
	return resp.StatusCode, jsonMap(t, raw)
}

func TestLDAPLoginIssuesSessionToken(t *testing.T) {
	h := loginHarness(t, loginAliceDirectory())
	code, body := postLogin(t, h, "alice", "correct-horse")
	if code != http.StatusOK {
		t.Fatalf("登录应 200，实际 %d: %v", code, body)
	}
	token, _ := body["token"].(string)
	if token == "" {
		t.Fatal("响应里没有 token")
	}
	if got, _ := body["subject"].(string); got != "alice" {
		t.Errorf("subject = %q", got)
	}
	claim, _ := body["header"].(string)
	if claim != IdentityHeaderName {
		t.Errorf("header = %q，want %q", claim, IdentityHeaderName)
	}
}

func TestLDAPLoginRejectsWrongPasswordWithoutLeaking(t *testing.T) {
	h := loginHarness(t, loginAliceDirectory())
	code, body := postLogin(t, h, "alice", "wrong-password")
	if code != http.StatusUnauthorized {
		t.Fatalf("错误口令应 401，实际 %d: %v", code, body)
	}
	raw := fmt.Sprint(body)
	if strings.Contains(raw, "wrong-password") {
		t.Error("响应不得回显口令")
	}
	if msg, _ := body["error"].(map[string]any); msg != nil {
		if strings.Contains(fmt.Sprint(msg), "uid=") {
			t.Error("响应不得回显目录 DN")
		}
	}
}

func TestLDAPLoginDependencyFailureIs503(t *testing.T) {
	dir := loginAliceDirectory()
	dir.unavailable = true
	h := loginHarness(t, dir)
	code, body := postLogin(t, h, "alice", "correct-horse")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("目录不可用应 503，实际 %d: %v", code, body)
	}
}

func TestLDAPLoginNotFoundWhenDisabled(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))
	resp, raw := h.post(t, identityLoginPath, "", map[string]any{
		"username": "alice", "password": "x",
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("未启用 LDAP 时应 404，实际 %d: %s", resp.StatusCode, raw)
	}
}

func TestLDAPLoginRateLimited(t *testing.T) {
	h := loginHarness(t, loginAliceDirectory())
	var last int
	for i := 0; i < loginPerIPPerMin+1; i++ {
		last, _ = postLogin(t, h, "alice", "wrong-password")
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("超过单 IP 每分钟上限后应 429，最后一次 %d", last)
	}
}
