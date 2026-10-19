package server

// 自助 token 端点的测试：登录下半场的口径都在这里钉住 ——
// 首登开号、轮换即失效、过期/缺令牌拒绝、subject 不合法不改名、停用账号不给发。

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/identity"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/secrets"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// mintClock 是可拨的判定时钟：过期用例靠它，不靠 sleep。
type mintClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *mintClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mintClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type mintHarness struct {
	*harness
	codec *identity.SessionCodec
	clock *mintClock
}

// newMintHarness 在登录夹具之上补两样：主密钥（多用户模式）与可拨时钟。
func newMintHarness(t *testing.T) *mintHarness {
	t.Helper()
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"})+
		policySection("shadow", "t-open", "system:gateway", 1))
	cipher, err := secrets.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("生成主密钥失败: %v", err)
	}
	h.srv.WithSecrets(cipher)
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatalf("SyncUsers: %v", err)
	}

	clock := &mintClock{now: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}
	codec, err := identity.NewSessionCodec(
		[]byte("0123456789abcdef0123456789abcdef"), "campus-ldap", 15*time.Minute,
		identity.WithClock(clock.Now), identity.WithStrictClock())
	if err != nil {
		t.Fatal(err)
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
	}, loginAliceDirectory())
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
	return &mintHarness{harness: h, codec: codec, clock: clock}
}

// issue 用会话编解码器直接签一枚身份令牌（与登录端点签出来的是同一种）。
func (h *mintHarness) issue(t *testing.T, subject string) string {
	t.Helper()
	now := h.clock.Now()
	id := policy.Identity{
		Subject:     subject,
		Source:      "campus-ldap",
		DisplayName: subject + "-display",
		AuthMethods: []string{"ldap"},
		IssuedAt:    now,
		ExpiresAt:   now.Add(15 * time.Minute),
	}.Normalize()
	chain, err := policy.NewScopeChain(policy.MustScope(policy.ScopeUser, subject))
	if err != nil {
		t.Fatal(err)
	}
	prin := identity.Principal{
		Identity:   id,
		Chain:      chain,
		Source:     "campus-ldap",
		ValidUntil: id.ExpiresAt,
	}
	token, _, err := h.codec.Issue(prin, 15*time.Minute)
	if err != nil {
		t.Fatalf("签发身份令牌失败: %v", err)
	}
	return token
}

// postMint 发一次自助 token 请求；ident 为空表示不带身份头。
func postMint(t *testing.T, gatewayURL, ident string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, gatewayURL+identityTokenPath, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if ident != "" {
		req.Header.Set(IdentityHeaderName, ident)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, jsonMap(t, raw)
}

func (h *mintHarness) mint(t *testing.T, ident string) (int, map[string]any) {
	t.Helper()
	return postMint(t, h.gateway.URL, ident)
}

func TestIdentityMintTokenCreatesThenRotates(t *testing.T) {
	h := newMintHarness(t)
	code, body := h.mint(t, h.issue(t, "alice"))
	if code != http.StatusCreated {
		t.Fatalf("首登创建应 201，实际 %d: %v", code, body)
	}
	if created, _ := body["created"].(bool); !created {
		t.Errorf("created 应为 true: %v", body)
	}
	first, _ := body["token"].(string)
	if !strings.HasPrefix(first, "sk-") {
		t.Fatalf("下游 token 应以 sk- 开头: %q", first)
	}
	if name, _ := body["name"].(string); name != "alice" {
		t.Errorf("name = %q，want alice", name)
	}

	// 新 token 立即可用：自助口发出来的 token 必须能进 /v1/_me。
	if resp, raw := h.get(t, "/v1/_me", first); resp.StatusCode != http.StatusOK {
		t.Fatalf("新 token 应能调 /v1/_me，实际 %d: %s", resp.StatusCode, raw)
	}

	// 轮换：200、created=false、旧 token 立即失效。
	code, body = h.mint(t, h.issue(t, "alice"))
	if code != http.StatusOK {
		t.Fatalf("轮换应 200，实际 %d: %v", code, body)
	}
	if created, _ := body["created"].(bool); created {
		t.Errorf("轮换的 created 应为 false: %v", body)
	}
	second, _ := body["token"].(string)
	if second == first {
		t.Fatal("轮换必须换出一枚新 token")
	}
	if resp, _ := h.get(t, "/v1/_me", first); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("旧 token 应立即失效，实际 %d", resp.StatusCode)
	}
	if resp, raw := h.get(t, "/v1/_me", second); resp.StatusCode != http.StatusOK {
		t.Errorf("新 token 应可用，实际 %d: %s", resp.StatusCode, raw)
	}
}

func TestIdentityMintTokenMissingIdentityHeader(t *testing.T) {
	h := newMintHarness(t)
	code, body := h.mint(t, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("缺身份头应 401，实际 %d: %v", code, body)
	}
}

func TestIdentityMintTokenExpiredSessionRejected(t *testing.T) {
	h := newMintHarness(t)
	token := h.issue(t, "alice")
	h.clock.Advance(16 * time.Minute)
	code, body := h.mint(t, token)
	if code != http.StatusUnauthorized {
		t.Fatalf("过期令牌应 401，实际 %d: %v", code, body)
	}
	if msg, _ := body["error"].(map[string]any); msg == nil || !strings.Contains(fmt.Sprint(msg), "过期") {
		t.Errorf("过期应明确提示重新登录: %v", body)
	}
}

func TestIdentityMintTokenRejectsNonNameSubject(t *testing.T) {
	h := newMintHarness(t)
	// 「张三」能过身份与范围校验，但进不了网关用户名（nameRe）——
	// 不许改名兜底，改出来的名字会与目录 subject 永久对不上。
	code, body := h.mint(t, h.issue(t, "张三"))
	if code != http.StatusBadRequest {
		t.Fatalf("subject 不能作用户名应 400，实际 %d: %v", code, body)
	}
}

func TestIdentityMintTokenDisabledAccount(t *testing.T) {
	h := newMintHarness(t)
	if err := h.db.CreateUser("alice", store.TokenHash("sk-seed")); err != nil {
		t.Fatal(err)
	}
	if err := h.db.SetUserEnabled("alice", false); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}
	code, body := h.mint(t, h.issue(t, "alice"))
	if code != http.StatusForbidden {
		t.Fatalf("停用账号应 403，实际 %d: %v", code, body)
	}
}

func TestIdentityMintTokenNotFoundWithoutIdentity(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))
	cipher, err := secrets.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h.srv.WithSecrets(cipher)
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}
	code, body := postMint(t, h.gateway.URL, "v1.x.y")
	if code != http.StatusNotFound {
		t.Fatalf("未启用身份时应 404，实际 %d: %v", code, body)
	}
}

func TestIdentityMintTokenRequiresMultiUser(t *testing.T) {
	// 身份在、主密钥不在：登录能换会话令牌，但下游 token 无处安放（多用户模式没开）。
	h := loginHarness(t, loginAliceDirectory())
	code, body := postMint(t, h.gateway.URL, "v1.x.y")
	if code != http.StatusNotImplemented {
		t.Fatalf("多用户未启用应 501，实际 %d: %v", code, body)
	}
}
