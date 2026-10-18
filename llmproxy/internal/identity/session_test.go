package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

func sessionTestKey() []byte { return []byte("0123456789abcdef0123456789abcdef") }

func sessionTestPrincipal() Principal {
	exp := ldapTestNow.Add(15 * time.Minute)
	id := policy.Identity{
		Subject:     "alice",
		Source:      "campus-ldap",
		DisplayName: "Alice",
		Roles:       []string{"faculty"},
		Groups:      []string{"cs-faculty"},
		AuthMethods: []string{"ldap"},
		IssuedAt:    ldapTestNow,
		ExpiresAt:   exp,
	}.Normalize()
	chain, err := policy.NewScopeChain(
		policy.MustScope(policy.ScopeUser, "alice"),
		policy.MustScope(policy.ScopeOrganization, "computer-science"),
	)
	if err != nil {
		panic(err)
	}
	return Principal{
		Identity:     id,
		Chain:        chain,
		Source:       "campus-ldap",
		Provider:     "ldap",
		Organization: "computer-science",
		ValidUntil:   exp,
	}
}

func newTestSessionCodec(t *testing.T, now *time.Time) *SessionCodec {
	t.Helper()
	c, err := NewSessionCodec(sessionTestKey(), "campus-ldap", 15*time.Minute,
		WithClock(func() time.Time { return *now }))
	if err != nil {
		t.Fatalf("构造会话编解码器失败: %v", err)
	}
	return c
}

func TestSessionCodecRoundTrip(t *testing.T) {
	now := ldapTestNow
	c := newTestSessionCodec(t, &now)
	prin := sessionTestPrincipal()
	token, exp, err := c.Issue(prin, 15*time.Minute)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if !exp.Equal(ldapTestNow.Add(15 * time.Minute)) {
		t.Errorf("expires_at = %v", exp)
	}
	cred, err := NewCredential(CredentialSessionToken, token)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Resolve(context.Background(), cred.WithRequestID("req-session"))
	if err != nil {
		t.Fatalf("验开失败: %v", err)
	}
	if got.Identity.Subject != "alice" || got.Organization != "computer-science" {
		t.Errorf("主体还原不对: %+v", got.Identity)
	}
	if !got.Chain.Includes(policy.MustScope(policy.ScopeOrganization, "computer-science")) {
		t.Errorf("范围链没有还原: %s", got.Chain.Display())
	}
	if got.Identity.ExpiresAt.Unix() != exp.Unix() {
		t.Errorf("ExpiresAt = %v，want %v", got.Identity.ExpiresAt, exp)
	}
}

func TestSessionCodecRejectsTamperedPayload(t *testing.T) {
	now := ldapTestNow
	c := newTestSessionCodec(t, &now)
	token, _, err := c.Issue(sessionTestPrincipal(), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token 段数 = %d", len(parts))
	}
	// 改 payload 的最后一个字符：签名必须对不上。
	payload := []byte(parts[1])
	if payload[len(payload)-1] == 'A' {
		payload[len(payload)-1] = 'B'
	} else {
		payload[len(payload)-1] = 'A'
	}
	tampered := parts[0] + "." + string(payload) + "." + parts[2]
	cred, _ := NewCredential(CredentialSessionToken, tampered)
	if _, err := c.Resolve(context.Background(), cred); !errors.Is(err, ErrSignature) {
		t.Fatalf("篡改 payload 应报 ErrSignature，实际 %v", err)
	}
}

func TestSessionCodecRejectsExpired(t *testing.T) {
	now := ldapTestNow
	c := newTestSessionCodec(t, &now)
	token, _, err := c.Issue(sessionTestPrincipal(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(5*time.Minute + DefaultClockSkew + time.Second)
	cred, _ := NewCredential(CredentialSessionToken, token)
	if _, err := c.Resolve(context.Background(), cred); !errors.Is(err, ErrExpired) {
		t.Fatalf("过期令牌应报 ErrExpired，实际 %v", err)
	}
}

func TestSessionCodecRejectsWrongKindAndSource(t *testing.T) {
	now := ldapTestNow
	c := newTestSessionCodec(t, &now)
	oidc, _ := NewCredential(CredentialOIDCToken, "a.b.c")
	if _, err := c.Resolve(context.Background(), oidc); !errors.Is(err, ErrCredentialKind) {
		t.Errorf("凭证类型不符应报 ErrCredentialKind，实际 %v", err)
	}

	token, _, err := c.Issue(sessionTestPrincipal(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewSessionCodec(sessionTestKey(), "other-source", time.Minute,
		WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	cred, _ := NewCredential(CredentialSessionToken, token)
	if _, err := other.Resolve(context.Background(), cred); !errors.Is(err, ErrIssuerMismatch) {
		t.Errorf("来源不符应报 ErrIssuerMismatch，实际 %v", err)
	}
}

func TestSessionCodecTTLBound(t *testing.T) {
	now := ldapTestNow
	c := newTestSessionCodec(t, &now)
	if _, _, err := c.Issue(sessionTestPrincipal(), 25*time.Hour); !errors.Is(err, ErrConfig) {
		t.Fatalf("超过上限的 TTL 必须拒绝，实际 %v", err)
	}
}
