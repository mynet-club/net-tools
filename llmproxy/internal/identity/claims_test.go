package identity

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 标准 claims 的解析与往返：Payload() 写出去什么，ParseClaims 就该读回什么。
//
// 这条性质必须钉住：FakeAuthority 与真实 IdP 的差别只在签名，
// 如果本包的序列化与解析不对称，Fake 测绿的路径在真实环境会走偏。
func TestClaimsRoundTripThroughPayload(t *testing.T) {
	want := studentProfile().Claims(baseNow)
	payload, err := want.Payload()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseClaims(payload)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got.Issuer != want.Issuer || got.Subject != want.Subject {
		t.Fatalf("iss/sub 不符: %+v vs %+v", got, want)
	}
	if !equalStrings(got.Audience, want.Audience) {
		t.Fatalf("aud 不符: %v vs %v", got.Audience, want.Audience)
	}
	if !got.Expiry.Equal(want.Expiry) {
		t.Fatalf("exp 不符: %v vs %v", got.Expiry, want.Expiry)
	}
	if !got.NotBefore.Equal(want.NotBefore) || !got.IssuedAt.Equal(want.IssuedAt) {
		t.Fatal("nbf/iat 必须能往返")
	}
	if got.JWTID != want.JWTID {
		t.Fatal("jti 不符")
	}
	if !got.HasExpiry {
		t.Fatal("HasExpiry 必须为真")
	}
	mapper, err := DefaultClaimMapper()
	if err != nil {
		t.Fatal(err)
	}
	// 非标准 claim 也要留着（映射器就靠它们）。
	values, err := mapper.listValues(got, "roles")
	if err != nil || !equalStrings(values, []string{"student"}) {
		t.Fatalf("roles claim 往返失败: %v %v", values, err)
	}
}

// Payload 以强类型字段为准，Extra 里的同名残留不能覆盖签发意图。
func TestClaimsPayloadIgnoresStaleStandardKeysInExtra(t *testing.T) {
	claims := studentProfile().Claims(baseNow)
	claims.Extra["exp"] = json.Number("1") // 有人改了 Expiry 忘了改 Extra
	claims.Expiry = baseNow.Add(2 * time.Hour)
	payload, err := claims.Payload()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseClaims(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Expiry.Equal(baseNow.Add(2 * time.Hour)) {
		t.Fatalf("Extra 里的陈旧 exp 不应生效: %v", got.Expiry)
	}
}

// Clone 必须是深拷贝：AddFixture 靠它保证「注册之后没人改过但身份变了」不会发生。
func TestClaimsCloneIsDeep(t *testing.T) {
	original := studentProfile().Claims(baseNow)
	clone := original.Clone()
	clone.Extra["roles"] = []any{"admin"}
	if items, ok := original.Extra["roles"].([]any); !ok || len(items) != 1 || items[0] != "student" {
		t.Fatalf("改副本影响了原件: %v", original.Extra["roles"])
	}
}

// aud 的两种合法形态。
func TestClaimsAudienceForms(t *testing.T) {
	for _, payloadText := range []string{
		`{"iss":"i","sub":"s","aud":"one","exp":1760000000}`,
		`{"iss":"i","sub":"s","aud":["one","two"],"exp":1760000000}`,
	} {
		c, err := ParseClaims([]byte(payloadText))
		if err != nil {
			t.Fatalf("%s: %v", payloadText, err)
		}
		if len(c.Audience) == 0 {
			t.Fatalf("%s: aud 应解析出来", payloadText)
		}
	}
	if _, err := ParseClaims([]byte(`{"aud":[1,2]}`)); !errors.Is(err, ErrClaimsInvalid) {
		t.Fatalf("aud 数组含非字符串必须失败: %v", err)
	}
	if _, err := ParseClaims([]byte(`{"aud":42}`)); !errors.Is(err, ErrClaimsInvalid) {
		t.Fatalf("aud 是数字必须失败: %v", err)
	}
}

// 时间字段与结构的各种非法形态必须给出可区分的错误，而不是静默当成零值。
func TestClaimsMalformedInputs(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    error
	}{
		{"exp 是字符串", `{"sub":"s","exp":"1760000000"}`, ErrClaimsInvalid},
		{"exp 把毫秒当秒", `{"sub":"s","exp":1760000000000}`, ErrClaimsInvalid},
		{"exp 早于 2000 年", `{"sub":"s","exp":100}`, ErrClaimsInvalid},
		{"iat 是布尔", `{"sub":"s","exp":1760000000,"iat":true}`, ErrClaimsInvalid},
		{"sub 是数字", `{"sub":20210101,"exp":1760000000}`, ErrClaimsInvalid},
		{"jti 是数字", `{"sub":"s","exp":1760000000,"jti":7}`, ErrClaimsInvalid},
		{"payload 不是对象", `[1,2,3]`, ErrClaimsInvalid},
		{"payload 不是 JSON", `not json at all`, ErrClaimsInvalid},
		{"iss 是数组", `{"iss":["a"],"sub":"s","exp":1760000000}`, ErrClaimsInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseClaims([]byte(tc.payload))
			if !errors.Is(err, tc.want) {
				t.Fatalf("期望 %v，实际 %v", tc.want, err)
			}
		})
	}
}

// 深嵌套 claims 不许把栈打爆。
func TestClaimsRejectsDeepNesting(t *testing.T) {
	payload := `{"a":` + strings.Repeat(`{"b":`, maxClaimsDepth+2) + `1` +
		strings.Repeat(`}`, maxClaimsDepth+2) + `}}`
	if _, err := ParseClaims([]byte(payload)); !errors.Is(err, ErrClaimsInvalid) {
		t.Fatalf("超过嵌套上限必须拒绝: %v", err)
	}
	// 上限之内要能过，否则这条规则会变成新的登录障碍。
	shallow := `{"a":` + strings.Repeat(`{"b":`, maxClaimsDepth-1) + `1` +
		strings.Repeat(`}`, maxClaimsDepth-1) + `}}`
	if _, err := ParseClaims([]byte(shallow)); err != nil {
		t.Fatalf("上限之内不应失败: %v", err)
	}
}

// 解析错误不得带 claims 原文（encoding/json 的报错会带出处字节）。
func TestClaimsParseErrorDoesNotEchoPayload(t *testing.T) {
	private := `{"sub":"only-person","exp":1760000000,"id_card":"11010119900307123",}`
	_, err := ParseClaims([]byte(private))
	if err == nil {
		t.Fatal("语法错误应当失败")
	}
	if strings.Contains(err.Error(), "110101") || strings.Contains(err.Error(), "only-person") {
		t.Fatalf("解析错误不得回显 payload 内容: %v", err)
	}
}

// claims 层的时效校验边界（不经过签名路径，直接判 Validate 的语义）。
func TestValidateClaimsTimeBoundaries(t *testing.T) {
	exp := baseNow.Add(time.Hour)
	base := Claims{
		Issuer: FakeDefaultIssuer, Audience: []string{FakeDefaultAudience},
		Subject: "uid-stu-1001", Expiry: exp, HasExpiry: true, IssuedAt: baseNow,
	}
	v := ValidateClaims{Issuer: FakeDefaultIssuer, Audience: FakeDefaultAudience, Now: fixedClock(baseNow)}
	if err := v.Validate(base); err != nil {
		t.Fatalf("正常 claims 应通过: %v", err)
	}

	// now == exp（严格时钟）即失效。
	strict := v
	strict.Now = fixedClock(exp)
	strict.StrictClock = true
	if err := strict.Validate(base); !errors.Is(err, ErrExpired) {
		t.Fatalf("now == exp 必须判过期: %v", err)
	}

	// 默认容忍度下 now == exp 仍可用（NTP 抖动的现实妥协）。
	tolerant := v
	tolerant.Now = fixedClock(exp)
	if err := tolerant.Validate(base); err != nil {
		t.Fatalf("默认 60 秒容忍应放行临界点: %v", err)
	}

	// 偏移量可配置：给 30 分钟就能容忍 29 分钟的漂移。
	wide := v
	wide.Now = fixedClock(exp.Add(29 * time.Minute))
	wide.Skew = 30 * time.Minute
	if err := wide.Validate(base); err != nil {
		t.Fatalf("配置的 skew 应生效: %v", err)
	}
	narrow := wide
	narrow.Now = fixedClock(exp.Add(31 * time.Minute))
	if err := narrow.Validate(base); !errors.Is(err, ErrExpired) {
		t.Fatalf("超出 skew 的过期必须失败: %v", err)
	}

	// nbf 未到：超出容忍度就拒。
	notYet := base
	notYet.NotBefore = baseNow.Add(5 * time.Minute)
	if err := v.Validate(notYet); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("nbf 未到应报 ErrNotYetValid: %v", err)
	}
	// nbf 在容忍度内则放行。
	nbfSkew := v
	nbfSkew.Now = fixedClock(baseNow.Add(4 * time.Minute))
	nbfSkew.Skew = 5 * time.Minute
	if err := nbfSkew.Validate(notYet); err != nil {
		t.Fatalf("容忍度内的 nbf 漂移应放行: %v", err)
	}

	// 缺 exp 与 exp 过期是两个不同结论。
	missing := base
	missing.HasExpiry = false
	missing.Expiry = time.Time{}
	if err := v.Validate(missing); !errors.Is(err, ErrExpiryMissing) {
		t.Fatalf("缺 exp 应报 ErrExpiryMissing: %v", err)
	}
	if errors.Is(v.Validate(missing), ErrExpired) {
		t.Fatal("缺 exp 不能被判成已过期")
	}

	// iat 在未来。
	futureIssue := base
	futureIssue.IssuedAt = baseNow.Add(10 * time.Minute)
	if err := v.Validate(futureIssue); !errors.Is(err, ErrIssuedInFuture) {
		t.Fatalf("iat 在未来应报错: %v", err)
	}

	// 生命周期上限。
	longLife := base
	longLife.Expiry = baseNow.Add(24 * time.Hour)
	capped := v
	capped.MaxLifetime = time.Hour
	if err := capped.Validate(longLife); !errors.Is(err, ErrLifetimeTooLong) {
		t.Fatalf("超过 MaxLifetime 应报错: %v", err)
	}
	capped.MaxLifetime = 0
	if err := capped.Validate(longLife); err != nil {
		t.Fatalf("不配置上限时不该收紧: %v", err)
	}
}

// 每个时效结论都要有独立原因码，否则大盘读不出「过期」和「缺 exp」的区别。
func TestClockReasonCodesAreDistinct(t *testing.T) {
	seen := map[ReasonCode]string{}
	cases := []struct {
		name string
		err  error
	}{
		{"过期", ErrExpired},
		{"缺 exp", ErrExpiryMissing},
		{"nbf 未到", ErrNotYetValid},
		{"iat 在未来", ErrIssuedInFuture},
		{"生命周期超限", ErrLifetimeTooLong},
	}
	for _, tc := range cases {
		reason := ReasonFor(tc.err)
		if !reason.Valid() {
			t.Fatalf("%s 的原因码 %q 未注册", tc.name, reason)
		}
		if previous, dup := seen[reason]; dup {
			t.Fatalf("%s 与 %s 共用了原因码 %q", tc.name, previous, reason)
		}
		seen[reason] = tc.name
	}
}

func TestValidateClaimsIssuerAudienceAndScope(t *testing.T) {
	c := Claims{
		Issuer: "https://a.invalid", Audience: []string{"client-1"},
		Subject: "uid-1", Expiry: baseNow.Add(time.Hour), HasExpiry: true,
		Extra: map[string]any{"scope": "openid profile"},
	}
	v := ValidateClaims{Issuer: "https://a.invalid", Audience: "client-1", Now: fixedClock(baseNow)}
	if err := v.Validate(c); err != nil {
		t.Fatalf("应通过: %v", err)
	}
	// iss 大小写敏感：折叠会让本包与 IdP 各有各的通过集合。
	caps := c
	caps.Issuer = "HTTPS://A.INVALID"
	if err := v.Validate(caps); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("iss 必须精确相等: %v", err)
	}
	unconfigured := v
	unconfigured.Issuer = ""
	if err := unconfigured.Validate(c); !errors.Is(err, ErrConfig) {
		t.Fatalf("未配置 issuer 属于配置错误: %v", err)
	}
	noAudience := v
	noAudience.Audience = ""
	noAudience.ExtraAudiences = nil
	if err := noAudience.Validate(c); !errors.Is(err, ErrConfig) {
		t.Fatalf("未配置 audience 属于配置错误: %v", err)
	}
	// scope 要求。
	scoped := v
	scoped.RequiredScopes = []string{"openid", "email"}
	if err := scoped.Validate(c); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("scope 缺 email 应失败: %v", err)
	}
	scoped.RequiredScopes = []string{"openid"}
	if err := scoped.Validate(c); err != nil {
		t.Fatalf("scope 满足应通过: %v", err)
	}
}

// 时间戳解析：小数秒、边界值、非法值。
func TestNumericDateParsesExactly(t *testing.T) {
	for _, tc := range []struct {
		in   string
		sec  int64
		nsec int32
		ok   bool
	}{
		{"1760000000", 1760000000, 0, true},
		{"1760000000.5", 1760000000, 500000000, true},
		{"1760000000.000000001", 1760000000, 1, true},
		{"1760000000.1234567899", 1760000000, 123456789, true}, // 超出 9 位截断
		{"1760000000.1.2", 0, 0, false},
		{"", 0, 0, false},
		{"abc", 0, 0, false},
	} {
		sec, nsec, ok := parseNumericDate(tc.in)
		if ok != tc.ok || (ok && (sec != tc.sec || nsec != tc.nsec)) {
			t.Fatalf("%q 解析结果 %d/%d/%v，期望 %d/%d/%v", tc.in, sec, nsec, ok, tc.sec, tc.nsec, tc.ok)
		}
	}
	// 秒值超出可接受区间：宁可报错，不给「2286 年才过期」的身份。
	if _, ok := numericDateToTime(json.Number("99999999999999")); ok {
		t.Fatal("毫秒当秒必须失败")
	}
	if _, ok := numericDateToTime(json.Number("1")); ok {
		t.Fatal("早于 2000 年必须失败")
	}
}

// Identity.ExpiresAt 必须来自 token 的 exp，A 包的校验因此不会失败。
func TestIdentityExpiryComesFromTokenExp(t *testing.T) {
	claims := studentProfile().Claims(baseNow)
	mapper, err := DefaultClaimMapper()
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := mapper.Map(claims, "campus-oidc")
	if err != nil {
		t.Fatal(err)
	}
	if !mapped.Identity.ExpiresAt.Equal(claims.Expiry) {
		t.Fatalf("ExpiresAt 必须等于 exp: %v vs %v", mapped.Identity.ExpiresAt, claims.Expiry)
	}
	if mapped.Identity.ExpiresAt.IsZero() {
		t.Fatal("带 roles 的身份必须有过期时间（A 包会拒）")
	}
	if err := mapped.Identity.ValidAt(baseNow); err != nil {
		t.Fatalf("有效期内应可用: %v", err)
	}
	if err := mapped.Identity.ValidAt(claims.Expiry); err == nil {
		t.Fatal("到达过期点后 A 包必须判不可用")
	}

	// 主组织/主项目要能填进 PolicyContext 且不违反 §2.2。
	principal := Principal{
		Identity: mapped.Identity, Chain: mapped.Chain, Source: "campus-oidc",
		Provider: "oidc", Organization: mapped.Organization, Project: mapped.Project,
		ValidUntil: mapped.Identity.ExpiresAt,
	}
	if err := principal.Validate(); err != nil {
		t.Fatalf("Principal 自校验失败: %v", err)
	}
	ctx, err := principal.PolicyContext("batch", policy.LevelConfidential)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Project != "" && ctx.Organization == "" {
		t.Fatal("给了 project 必须给 organization")
	}
	if ctx.Identity.ExpiresAt != claims.Expiry {
		t.Fatal("上下文里的身份过期时间必须原样传递")
	}
}
