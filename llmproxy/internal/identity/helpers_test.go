package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 本工作包的测试基线：全部场景离线、无真实学校账号、无第三方 JWT 库。
// 时间一律固定（baseNow），这样 TTL 边界是确定的而不是「今天恰好能过」。

// baseNow 是所有用例共用的「当前时刻」。取整秒，避免 NumericDate 的亚秒截断
// 让「期望的 ExpiresAt」与「token 里解出来的」差几百纳秒。
var baseNow = time.Date(2026, time.October, 15, 3, 0, 0, 0, time.UTC)

func fixedClock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}

// testAuthority 生成一次性的签发方。放在测试帮助里而不是生产文件，
// 是为了让「生产代码不含私钥生成路径」这件事在文件层面就能看见。
func testAuthority(t *testing.T) *FakeAuthority {
	t.Helper()
	authority, err := NewFakeAuthority()
	if err != nil {
		t.Fatalf("构造测试签发方失败: %v", err)
	}
	return authority
}

// urlAlphabet 是 base64url 的字母表，测试用它枚举「同一字节的等价文本表示」。
const urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// 签名测试需要拿到测试签发方的私钥与公钥：同包访问器，避免在生产类型上开放私钥。
func testRSAPrivate(t *testing.T, a *FakeAuthority) *rsa.PrivateKey {
	t.Helper()
	return a.rsaKey
}

func testECPrivate(t *testing.T, a *FakeAuthority) *ecdsa.PrivateKey {
	t.Helper()
	return a.ecKey
}

func testRSAPublic(t *testing.T, a *FakeAuthority) *rsa.PublicKey {
	t.Helper()
	return &a.rsaKey.PublicKey
}

func testECPublic(t *testing.T, a *FakeAuthority) *ecdsa.PublicKey {
	t.Helper()
	return &a.ecKey.PublicKey
}

func testForeignPublic(t *testing.T, a *FakeAuthority) *rsa.PublicKey {
	t.Helper()
	return &a.foreign.PublicKey
}

// oidcOptions 是构造 OIDCProvider 时最常用的参数。
type oidcOptions struct {
	clock      time.Time
	skew       time.Duration
	strict     bool
	maxLive    time.Duration
	mapper     *ClaimMapper
	audit      *AuditRecorder
	audience   string
	types      []string
	algorithms []Alg
	source     string
}

func (o oidcOptions) apply(cfg OIDCConfig) (OIDCConfig, []Option) {
	var opts []Option
	if o.audience != "" {
		cfg.Audience = o.audience
	}
	if len(o.types) > 0 {
		cfg.AllowedTypes = o.types
	}
	if len(o.algorithms) > 0 {
		cfg.Algorithms = o.algorithms
	}
	cfg.MaxLifetime = o.maxLive
	cfg.Mapper = o.mapper
	if o.source != "" {
		cfg.Source = o.source
	}
	opts = append(opts, WithClock(fixedClock(o.clockOrNow())))
	if o.strict {
		opts = append(opts, WithStrictClock())
	} else if o.skew != 0 {
		opts = append(opts, WithClockSkew(o.skew))
	}
	if o.audit != nil {
		opts = append(opts, WithAudit(o.audit))
	}
	return cfg, opts
}

func (o oidcOptions) clockOrNow() time.Time {
	if o.clock.IsZero() {
		return baseNow
	}
	return o.clock
}

// newOIDC 组装一个「已注入固定时钟与公钥来源」的 OIDCProvider。
func newOIDC(t *testing.T, keys KeySource, o oidcOptions) *OIDCProvider {
	t.Helper()
	cfg, opts := o.apply(OIDCConfig{
		Source:   "campus-oidc",
		Name:     "oidc",
		Issuer:   FakeDefaultIssuer,
		Audience: FakeDefaultAudience,
	})
	p, err := NewOIDCProvider(cfg, keys, opts...)
	if err != nil {
		t.Fatalf("构造 OIDCProvider 失败: %v", err)
	}
	return p
}

// studentProfile 是最常用的一份样例画像（离线、无真实账号）。
func studentProfile() UniversityProfile {
	for _, p := range UniversitySampleProfiles() {
		if p.Fixture == "student-1001" {
			return p
		}
	}
	panic("内置高校样例必须含 student-1001")
}

func profileByFixture(t *testing.T, fixture string) UniversityProfile {
	t.Helper()
	for _, p := range UniversitySampleProfiles() {
		if p.Fixture == fixture {
			return p
		}
	}
	t.Fatalf("内置高校样例里没有 %q", fixture)
	return UniversityProfile{}
}

// mustToken 签一个 token，失败即终止用例。
func mustToken(t *testing.T, a *FakeAuthority, req SignRequest) string {
	t.Helper()
	token, err := a.Sign(req)
	if err != nil {
		t.Fatalf("签名测试 token 失败: %v", err)
	}
	return token
}

// oidcCredential 把 token 包成凭证。
func oidcCredential(t *testing.T, token string) Credential {
	t.Helper()
	cred, err := NewCredential(CredentialOIDCToken, token)
	if err != nil {
		t.Fatalf("构造凭证失败: %v", err)
	}
	return cred
}

// resolveOK 期望解析成功并返回 Principal。
func resolveOK(t *testing.T, p Provider, cred Credential) Principal {
	t.Helper()
	principal, err := p.Resolve(context.Background(), cred)
	if err != nil {
		t.Fatalf("解析应当成功，实际失败: %v", err)
	}
	return principal
}

// resolveErr 期望解析失败，并断言错误链能认出 want 哨兵。
func resolveErr(t *testing.T, p Provider, cred Credential, want error) error {
	t.Helper()
	_, err := p.Resolve(context.Background(), cred)
	if err == nil {
		t.Fatalf("解析应当失败（期望 %v）", want)
	}
	if err.Error() == "" {
		t.Fatal("错误必须有可读文本")
	}
	if !errors.Is(err, want) {
		t.Fatalf("错误链应认出 %v，实际: %v", want, err)
	}
	return err
}

// assertScopeChain 断言范围集合的内容（顺序按 policy 的稳定排序）。
func assertScopeChain(t *testing.T, chain policy.ScopeChain, want ...string) {
	t.Helper()
	got := chain.Display()
	if got != strings.Join(want, ",") {
		t.Fatalf("ScopeChain 不符\n期望 %s\n实际 %s", strings.Join(want, ","), got)
	}
}

// assertReason 断言错误的原因码。
func assertReason(t *testing.T, err error, want ReasonCode) {
	t.Helper()
	if got := ReasonFor(err); got != want {
		t.Fatalf("原因码期望 %q，实际 %q（错误：%v）", want, got, err)
	}
}

// equalStrings 比较两个字符串切片（顺序敏感：成员关系一律已归一化排序）。
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// encodeSegment 把字节按 base64url（无填充）编成一段，用于手工拼装篡改 token。
func encodeSegment(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

// jsonNumber 造一个 NumericDate 形态的 claim 值（模拟 JSON 解码结果）。
func jsonNumber(sec int64) json.Number {
	return json.Number(strconv.FormatInt(sec, 10))
}
