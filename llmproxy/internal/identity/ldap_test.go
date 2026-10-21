package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// fakeLDAPDirectory 是目录协议层的测试替身：只提供本包需要的四个动作，
// 不模拟 BER/TLS —— 那部分由 go-ldap 负责，单独测它没有价值。
type fakeLDAPDirectory struct {
	byName    map[string]LDAPEntry
	byDN      map[string]LDAPEntry
	passwords map[string]string
	groups    []string

	lookupErr error
	bindErr   error
	groupsErr error
}

func (f *fakeLDAPDirectory) Lookup(_ context.Context, _ LDAPTrust, username string) (LDAPEntry, error) {
	if f.lookupErr != nil {
		return LDAPEntry{}, f.lookupErr
	}
	entry, ok := f.byName[username]
	if !ok {
		return LDAPEntry{}, errors.Join(ErrLDAPEntryNotFound, errors.New("not found"))
	}
	return entry, nil
}

func (f *fakeLDAPDirectory) LookupDN(_ context.Context, _ LDAPTrust, dn string) (LDAPEntry, error) {
	if f.lookupErr != nil {
		return LDAPEntry{}, f.lookupErr
	}
	entry, ok := f.byDN[dn]
	if !ok {
		return LDAPEntry{}, errors.Join(ErrLDAPEntryNotFound, errors.New("not found"))
	}
	return entry, nil
}

func (f *fakeLDAPDirectory) Bind(_ context.Context, trust LDAPTrust, dn, password string) error {
	if f.bindErr != nil {
		return f.bindErr
	}
	if trust.Source == "" {
		return errors.New("fake: 缺 source")
	}
	if f.passwords[dn] != password {
		return errors.Join(ErrCredential, errors.New("invalid credentials"))
	}
	return nil
}

func (f *fakeLDAPDirectory) Groups(_ context.Context, _ LDAPTrust, _ string) ([]string, error) {
	if f.groupsErr != nil {
		return nil, f.groupsErr
	}
	return append([]string(nil), f.groups...), nil
}

var ldapTestNow = time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)

func newTestLDAPProvider(t *testing.T, dir LDAPDirectory) *LDAPDirectoryProvider {
	t.Helper()
	p, err := NewLDAPDirectoryProvider(LDAPTrust{
		Source:             "campus-ldap",
		URL:                "ldaps://ldap.example.edu:636",
		BindDN:             "cn=svc,ou=services,dc=example,dc=edu",
		BindPassword:       "svc-secret",
		BaseDN:             "ou=people,dc=example,dc=edu",
		UserAttr:           "uid",
		GroupAttr:          "memberOf",
		RoleAttr:           "eduPersonScopedAffiliation",
		IdentityTTL:        15 * time.Minute,
		AllowedBindTargets: []string{"ldap.example.edu:636"},
		Timeout:            2 * time.Second,
	}, dir, WithClock(func() time.Time { return ldapTestNow }))
	if err != nil {
		t.Fatalf("构造 LDAP 来源失败: %v", err)
	}
	return p
}

func aliceEntry() LDAPEntry {
	return LDAPEntry{
		DN: "uid=alice,ou=people,dc=example,dc=edu",
		Attrs: map[string][]string{
			"uid":                        {"alice"},
			"displayname":                {"Alice Zhang"},
			"mail":                       {"alice@example.edu"},
			"memberof":                   {"cn=cs-faculty,ou=groups,dc=example,dc=edu"},
			"edupersonScopedAffiliation": {"faculty@example.edu"},
			"department":                 {"computer-science"},
		},
	}
}

func aliceDirectory() *fakeLDAPDirectory {
	entry := aliceEntry()
	return &fakeLDAPDirectory{
		byName: map[string]LDAPEntry{"alice": entry},
		byDN:   map[string]LDAPEntry{entry.DN: entry},
		passwords: map[string]string{
			entry.DN: "correct-horse",
		},
	}
}

func TestLDAPAuthenticateMapsDirectoryEntry(t *testing.T) {
	p := newTestLDAPProvider(t, aliceDirectory())
	prin, err := p.Authenticate(context.Background(), "alice", "correct-horse", "req-1")
	if err != nil {
		t.Fatalf("认证失败: %v", err)
	}
	if prin.Identity.Subject != "alice" {
		t.Errorf("subject = %q", prin.Identity.Subject)
	}
	if prin.Identity.DisplayName != "Alice Zhang" {
		t.Errorf("display_name = %q", prin.Identity.DisplayName)
	}
	if got := strings.Join(prin.Identity.Groups, ","); got != "cs-faculty" {
		t.Errorf("groups = %q（组 DN 应只保留 CN）", got)
	}
	if got := strings.Join(prin.Identity.Roles, ","); got != "faculty@example.edu" {
		t.Errorf("roles = %q", got)
	}
	if !prin.Chain.Includes(policy.MustScope(policy.ScopeUser, "alice")) {
		t.Error("链里必须含 user:alice")
	}
	if !prin.Chain.Includes(policy.MustScope(policy.ScopeOrganization, "computer-science")) {
		t.Errorf("department 应展开成 organization 范围: %s", prin.Chain.Display())
	}
	wantExp := ldapTestNow.Add(15 * time.Minute)
	if !prin.Identity.ExpiresAt.Equal(wantExp) {
		t.Errorf("ExpiresAt = %v，want %v（目录没有 exp，必须由 IdentityTTL 派生）", prin.Identity.ExpiresAt, wantExp)
	}
	// mail 只能留在临时 claims 里，不能进 Principal。
	if strings.Contains(strings.Join(prin.Identity.Groups, ","), "@") {
		t.Error("邮箱形态的取值不得进 Principal")
	}
}

func TestLDAPNumericSubjectRequiresExplicitOptIn(t *testing.T) {
	entry := LDAPEntry{
		DN: "uid=20133399,ou=people,dc=example,dc=edu",
		Attrs: map[string][]string{
			"uid": {"20133399"},
			"cn":  {"Numeric User"},
		},
	}
	dir := &fakeLDAPDirectory{
		byName:    map[string]LDAPEntry{"20133399": entry},
		byDN:      map[string]LDAPEntry{entry.DN: entry},
		passwords: map[string]string{entry.DN: "correct-horse"},
	}
	build := func(allow bool) *LDAPDirectoryProvider {
		t.Helper()
		p, err := NewLDAPDirectoryProvider(LDAPTrust{
			Source:              "campus-ldap",
			URL:                 "ldaps://ldap.example.edu:636",
			BindDN:              "cn=svc,ou=services,dc=example,dc=edu",
			BindPassword:        "svc-secret",
			BaseDN:              "ou=people,dc=example,dc=edu",
			UserAttr:            "uid",
			AllowNumericSubject: allow,
			IdentityTTL:         15 * time.Minute,
			AllowedBindTargets:  []string{"ldap.example.edu:636"},
			Timeout:             2 * time.Second,
		}, dir, WithClock(func() time.Time { return ldapTestNow }))
		if err != nil {
			t.Fatalf("构造 LDAP 来源失败: %v", err)
		}
		return p
	}
	if _, err := build(false).Authenticate(context.Background(), "20133399", "correct-horse", "req-num"); err == nil {
		t.Fatal("默认必须拒绝纯数字学号形态的 subject")
	}
	prin, err := build(true).Authenticate(context.Background(), "20133399", "correct-horse", "req-num")
	if err != nil {
		t.Fatalf("显式放开后应认证成功: %v", err)
	}
	if prin.Identity.Subject != "20133399" {
		t.Errorf("subject = %q", prin.Identity.Subject)
	}
}

func TestLDAPAuthenticateRejectsWrongPassword(t *testing.T) {
	p := newTestLDAPProvider(t, aliceDirectory())
	_, err := p.Authenticate(context.Background(), "alice", "wrong", "req-2")
	if !errors.Is(err, ErrCredential) {
		t.Fatalf("错误口令应归到 ErrCredential，实际 %v", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Error("错误文案不得带口令原文")
	}
}

func TestLDAPAuthenticateDistinguishesDependencyFailure(t *testing.T) {
	dir := aliceDirectory()
	dir.lookupErr = errors.Join(ErrDirectoryUnavailable, errors.New("dial timeout"))
	p := newTestLDAPProvider(t, dir)
	_, err := p.Authenticate(context.Background(), "alice", "correct-horse", "req-3")
	if !errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatalf("目录不可用应归到 ErrDirectoryUnavailable，实际 %v", err)
	}
	if got := ReasonFor(err); got != ReasonDirectoryUnavailable {
		t.Errorf("原因码 = %q", got)
	}
	if !isDependencyFailure(ReasonFor(err)) {
		t.Error("目录不可用必须是 dependency failure（审计 Outcome=error）")
	}
}

func TestLDAPAuthenticateEntryNotFoundAndAmbiguous(t *testing.T) {
	p := newTestLDAPProvider(t, &fakeLDAPDirectory{byName: map[string]LDAPEntry{}, byDN: map[string]LDAPEntry{}, passwords: map[string]string{}})
	if _, err := p.Authenticate(context.Background(), "ghost", "x", "req-4"); !errors.Is(err, ErrLDAPEntryNotFound) {
		t.Errorf("未知用户应报 ErrLDAPEntryNotFound，实际 %v", err)
	}

	dir := aliceDirectory()
	dir.lookupErr = ErrLDAPEntryAmbiguous
	p = newTestLDAPProvider(t, dir)
	if _, err := p.Authenticate(context.Background(), "alice", "correct-horse", "req-5"); !errors.Is(err, ErrLDAPEntryAmbiguous) {
		t.Errorf("多条目应报 ErrLDAPEntryAmbiguous，实际 %v", err)
	}
}

func TestLDAPObjectGUIDBecomesStableHex(t *testing.T) {
	entry := LDAPEntry{
		DN: "CN=Alice,OU=People,DC=example,DC=edu",
		Attrs: map[string][]string{
			"objectguid": {"\x01\x02\xab"},
			"cn":         {"Alice"},
		},
	}
	dir := &fakeLDAPDirectory{
		byName:    map[string]LDAPEntry{"alice": entry},
		byDN:      map[string]LDAPEntry{entry.DN: entry},
		passwords: map[string]string{entry.DN: "pw"},
	}
	p, err := NewLDAPDirectoryProvider(LDAPTrust{
		Source:             "ad",
		URL:                "ldaps://ad.example.edu:636",
		BindDN:             "svc@example.edu",
		BindPassword:       "svc",
		BaseDN:             "DC=example,DC=edu",
		UserAttr:           "objectGUID",
		IdentityTTL:        15 * time.Minute,
		AllowedBindTargets: []string{"ad.example.edu:636"},
	}, dir, WithClock(func() time.Time { return ldapTestNow }))
	if err != nil {
		t.Fatal(err)
	}
	prin, err := p.Authenticate(context.Background(), "alice", "pw", "req-6")
	if err != nil {
		t.Fatal(err)
	}
	if prin.Identity.Subject != "0102ab" {
		t.Errorf("objectGUID 应转十六进制，实际 %q", prin.Identity.Subject)
	}
}

func TestLDAPProviderConstructorSecurityBounds(t *testing.T) {
	base := LDAPTrust{
		Source:             "ldap",
		URL:                "ldaps://ldap.example.edu:636",
		BindDN:             "cn=svc",
		BindPassword:       "pw",
		BaseDN:             "ou=people,dc=example,dc=edu",
		UserAttr:           "uid",
		IdentityTTL:        15 * time.Minute,
		AllowedBindTargets: []string{"ldap.example.edu:636"},
	}
	cases := []struct {
		name   string
		mutate func(*LDAPTrust)
	}{
		{"空目标白名单", func(t *LDAPTrust) { t.AllowedBindTargets = nil }},
		{"目标不在白名单", func(t *LDAPTrust) { t.AllowedBindTargets = []string{"other:636"} }},
		{"缺服务账号", func(t *LDAPTrust) { t.BindDN = "" }},
		{"缺用户属性", func(t *LDAPTrust) { t.UserAttr = "" }},
		{"TTL 超上限", func(t *LDAPTrust) { t.IdentityTTL = 25 * time.Hour }},
		{"Timeout 超上限", func(t *LDAPTrust) { t.Timeout = time.Minute }},
		{"口令上限超上限", func(t *LDAPTrust) { t.MaxPasswordBytes = 5000 }},
		{"ldaps + StartTLS", func(t *LDAPTrust) { t.StartTLS = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trust := base
			tc.mutate(&trust)
			if _, err := NewLDAPDirectoryProvider(trust, aliceDirectory()); err == nil {
				t.Fatal("不安全配置必须在构造期失败")
			}
		})
	}
}

func TestLDAPPasswordLengthBound(t *testing.T) {
	dir := aliceDirectory()
	dir.passwords["uid=alice,ou=people,dc=example,dc=edu"] = strings.Repeat("x", 300)
	p, err := NewLDAPDirectoryProvider(LDAPTrust{
		Source:             "ldap",
		URL:                "ldaps://ldap.example.edu:636",
		BindDN:             "cn=svc",
		BindPassword:       "pw",
		BaseDN:             "ou=people,dc=example,dc=edu",
		UserAttr:           "uid",
		IdentityTTL:        15 * time.Minute,
		AllowedBindTargets: []string{"ldap.example.edu:636"},
		MaxPasswordBytes:   32,
	}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Authenticate(context.Background(), "alice", strings.Repeat("x", 33), "req-7"); !errors.Is(err, ErrCredentialTooLarge) {
		t.Fatalf("超长口令应报 ErrCredentialTooLarge，实际 %v", err)
	}
}
