package identity

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// fake.go 的交付要求是「必须提供 fake provider，不能要求真实学校账号才能测试」（手册 §3.B）。
// 本文件钉两件事：① fake 走的是与 OIDC 完全相同的校验+映射管线（否则 fake 全绿会掩盖真实缺陷）；
// ② UniversitySampleProfiles 的每个样例都能被真实链路解析成预期范围集合 —— G 包要直接依赖这份契约。

// sampleExpectation 是内置高校样例的期望解析结果。
// 这里把 chain 逐条写死，是为了让「改一个 claim 字段名就悄悄少一层范围」这类改动当场失败。
type sampleExpectation struct {
	fixture      string
	subject      string
	displayName  string
	organization string
	project      string
	roles        []string
	groups       []string
	projects     []string
	authMethods  []string
	chain        []string
}

func universitySampleExpectations() []sampleExpectation {
	return []sampleExpectation{
		{
			fixture: "student-1001", subject: "uid-stu-1001", displayName: "Sample Student",
			organization: "university", project: "",
			roles: []string{"student"}, groups: []string{"cs-college", "undergraduate"},
			projects: []string{"cs-101", "math-201"}, authMethods: []string{"otp", "pwd"},
			chain: []string{
				"organization:cs-college", "organization:university",
				"project:cs-101", "project:math-201", "user:uid-stu-1001",
			},
		},
		{
			fixture: "teacher-2001", subject: "uid-tea-2001", displayName: "Sample Teacher",
			organization: "university", project: "proj-curriculum",
			roles: []string{"course-staff", "teacher"}, groups: []string{"cs-college", "faculty"},
			projects: []string{"cs-305", "proj-curriculum"}, authMethods: []string{"pwd", "totp"},
			chain: []string{
				"organization:cs-college", "organization:university",
				"project:cs-305", "project:proj-curriculum", "user:uid-tea-2001",
			},
		},
		{
			fixture: "pi-3001", subject: "uid-pi-3001", displayName: "Sample PI",
			organization: "university", project: "proj-grant-2026",
			roles: []string{"project-lead", "teacher"}, groups: []string{"faculty"},
			projects: []string{"lab-7", "proj-grant-2026", "proj-lab-7"}, authMethods: []string{"pwd", "totp"},
			chain: []string{
				"organization:medical-college", "organization:university",
				"project:lab-7", "project:proj-grant-2026", "project:proj-lab-7", "user:uid-pi-3001",
			},
		},
		{
			fixture: "lab-admin-4001", subject: "uid-lab-4001", displayName: "Sample Lab Admin",
			organization: "university", project: "proj-instrument",
			roles: []string{"lab-admin"}, groups: []string{"physics-lab", "staff"},
			projects: []string{"lab-12", "proj-instrument"}, authMethods: []string{"cert"},
			chain: []string{
				"organization:physics-college", "organization:university",
				"project:lab-12", "project:proj-instrument", "user:uid-lab-4001",
			},
		},
		{
			fixture: "exchange-5001", subject: "uid-exg-5001", displayName: "Sample Exchange Student",
			organization: "partner-institute", project: "",
			roles: []string{"exchange", "student"}, groups: []string{"exchange", "university-guest"},
			projects: []string{"cs-101"}, authMethods: []string{"pwd"},
			chain: []string{
				"organization:ee-college", "organization:partner-institute",
				"project:cs-101", "user:uid-exg-5001",
			},
		},
	}
}

// 每个内置样例都必须被「真链路」（FakeAuthority 现场签 + OIDCProvider 验签 + 映射）完整解析。
// 这是 G 包写端到端场景时的依赖前提，必须钉住。
func TestUniversitySampleProfilesResolveThroughOIDC(t *testing.T) {
	authority := testAuthority(t)
	provider := newOIDC(t, authority, oidcOptions{})

	for _, want := range universitySampleExpectations() {
		t.Run(want.fixture, func(t *testing.T) {
			profile := profileByFixture(t, want.fixture)
			token := mustToken(t, authority, SignRequest{Profile: profile, At: baseNow})
			principal := resolveOK(t, provider, oidcCredential(t, token))

			if err := principal.Validate(); err != nil {
				t.Fatalf("样例产出的 Principal 必须自校验通过: %v", err)
			}
			if err := principal.Identity.Validate(); err != nil {
				t.Fatalf("样例产出的身份必须通过 A 包校验: %v", err)
			}
			assertIdentityShape(t, principal.Identity, want)
			if principal.Source != "campus-oidc" || principal.Provider != "oidc" {
				t.Fatalf("来源与实例名应来自配置: %+v", principal)
			}
			if principal.Organization != want.organization {
				t.Fatalf("主组织期望 %q，实际 %q", want.organization, principal.Organization)
			}
			if principal.Project != want.project {
				t.Fatalf("主项目期望 %q，实际 %q", want.project, principal.Project)
			}
			assertScopeChain(t, principal.Chain, want.chain...)
			// 样例的时效必须来自 exp（默认 8 小时的一节课长度）。
			if !principal.ValidUntil.Equal(baseNow.Add(8 * time.Hour)) {
				t.Fatalf("ValidUntil 应等于 token 的 exp，实际 %v", principal.ValidUntil)
			}
			// PolicyContext 是 B 交给下游的唯一形态，必须填得出来。
			if _, err := principal.PolicyContext("qa", policy.LevelInternal); err != nil {
				t.Fatalf("样例必须能填出合法策略上下文: %v", err)
			}
		})
	}
}

func assertIdentityShape(t *testing.T, id policy.Identity, want sampleExpectation) {
	t.Helper()
	if id.Subject != want.subject {
		t.Fatalf("Subject 期望 %q，实际 %q", want.subject, id.Subject)
	}
	if id.DisplayName != want.displayName {
		t.Fatalf("DisplayName 期望 %q，实际 %q", want.displayName, id.DisplayName)
	}
	if !equalStrings(id.Roles, want.roles) {
		t.Fatalf("Roles 期望 %v，实际 %v", want.roles, id.Roles)
	}
	if !equalStrings(id.Groups, want.groups) {
		t.Fatalf("Groups 期望 %v，实际 %v", want.groups, id.Groups)
	}
	if !equalStrings(id.Projects, want.projects) {
		t.Fatalf("Projects 期望 %v，实际 %v", want.projects, id.Projects)
	}
	if !equalStrings(id.AuthMethods, want.authMethods) {
		t.Fatalf("AuthMethods 期望 %v，实际 %v", want.authMethods, id.AuthMethods)
	}
}

// FakeProvider 与 OIDCProvider 必须给出逐字段相同的结果 —— 手册要求 fake「不走另一套逻辑」，
// 否则 fake 全绿会掩盖真实解析路径的缺陷。这里连时间戳都要求一致。
func TestFakeProviderAndOIDCProviderAreSameShape(t *testing.T) {
	authority := testAuthority(t)
	profile := profileByFixture(t, "pi-3001")
	token := mustToken(t, authority, SignRequest{Profile: profile, At: baseNow})
	oidcPrincipal := resolveOK(t, newOIDC(t, authority, oidcOptions{}), oidcCredential(t, token))

	fake, err := NewFakeProvider(FakeOptions{
		Source:   "campus-oidc", // 与 OIDC 侧取同一个来源标识，才能整对象比较
		Name:     "fake",
		Issuer:   FakeDefaultIssuer,
		Audience: FakeDefaultAudience,
		Fixtures: map[string]Claims{"pi-3001": profile.Claims(baseNow)},
	}, WithClock(fixedClock(baseNow)))
	if err != nil {
		t.Fatalf("构造 fake 来源失败: %v", err)
	}
	fakePrincipal := resolveOK(t, fake, FakeCredential("pi-3001"))

	if fakePrincipal.Provider != "fake" {
		t.Fatalf("Provider 字段应记录实例名: %+v", fakePrincipal)
	}
	fakePrincipal.Provider = oidcPrincipal.Provider
	if !reflect.DeepEqual(fakePrincipal, oidcPrincipal) {
		t.Fatalf("fake 与真链路结果不一致\nfake: %+v\noidc: %+v", fakePrincipal, oidcPrincipal)
	}
}

// 内置高校样例来源：fixture 名可预期、每个样例都能离线解析。
//
// 这里刻意不注入固定时钟：NewFakeUniversityProvider 用真实当下时刻生成 fixture，
// 把时钟冻在别处只会让时效边界变成用例之间的运气差异。
func TestFakeUniversityProviderResolvesEverySample(t *testing.T) {
	provider, err := NewFakeUniversityProvider()
	if err != nil {
		t.Fatalf("构造内置高校来源失败: %v", err)
	}
	if provider.Name() != "fake-university" || provider.Source() != "campus-fake" {
		t.Fatalf("默认来源标识不符: name=%q source=%q", provider.Name(), provider.Source())
	}

	wantNames := make([]string, 0, 5)
	for _, want := range universitySampleExpectations() {
		wantNames = append(wantNames, want.fixture)
	}
	sort.Strings(wantNames) // FixtureNames 返回排序结果，断言必须按同一口径
	if !equalStrings(provider.FixtureNames(), wantNames) {
		t.Fatalf("内置 fixture 名不符\n期望 %v\n实际 %v", wantNames, provider.FixtureNames())
	}

	for _, want := range universitySampleExpectations() {
		t.Run(want.fixture, func(t *testing.T) {
			principal := resolveOK(t, provider, FakeCredential(want.fixture))
			if err := principal.Validate(); err != nil {
				t.Fatalf("Principal 自校验失败: %v", err)
			}
			assertIdentityShape(t, principal.Identity, want)
			if principal.Organization != want.organization || principal.Project != want.project {
				t.Fatalf("主组织/主项目不符: org=%q project=%q", principal.Organization, principal.Project)
			}
			assertScopeChain(t, principal.Chain, want.chain...)
			// 时效来自 fixture 的 exp（签发用真实当下时钟，这里只断言长度）。
			if principal.ValidUntil.IsZero() || time.Until(principal.ValidUntil) < 7*time.Hour {
				t.Fatalf("身份有效期应覆盖一节课长度: %v", principal.ValidUntil)
			}
		})
	}
}

// fake 的默认配置：名称/来源/签发参数留空都有确定的默认值，且来源缺失时回落 provider 名。
func TestFakeProviderDefaults(t *testing.T) {
	plain, err := NewFakeProvider(FakeOptions{})
	if err != nil {
		t.Fatalf("fake 来源不应因配置缺省而失败: %v", err)
	}
	if plain.Name() != "fake" || plain.Source() != "fake" {
		t.Fatalf("默认 name/source 应为 fake: name=%q source=%q", plain.Name(), plain.Source())
	}

	named, err := NewFakeProvider(FakeOptions{Name: "shadow-fake"})
	if err != nil {
		t.Fatal(err)
	}
	if named.Name() != "shadow-fake" || named.Source() != "shadow-fake" {
		t.Fatalf("Source 缺省时应回落 provider 名: %+v / %+v", named.Name(), named.Source())
	}

	// 默认 issuer/audience 是 .invalid 保留域，配好 fixture 就能直接解析。
	profile := studentProfile()
	fake, err := NewFakeProvider(FakeOptions{
		Fixtures: map[string]Claims{"student": profile.Claims(baseNow)},
	}, WithClock(fixedClock(baseNow)))
	if err != nil {
		t.Fatal(err)
	}
	principal := resolveOK(t, fake, FakeCredential("student"))
	if principal.Identity.Subject != profile.Subject {
		t.Fatalf("解析出的 subject 不符: %+v", principal.Identity)
	}
	if principal.Source != "fake" {
		t.Fatalf("Identity.Source 应来自配置: %q", principal.Identity.Source)
	}
}

// 未预知的 fixture 名必须失败，而不是退化成「按显示名造一个身份」。
func TestFakeProviderUnknownFixtureFails(t *testing.T) {
	audit := NewAuditRecorder(0)
	provider, err := NewFakeProvider(FakeOptions{}, WithClock(fixedClock(baseNow)), WithAudit(audit))
	if err != nil {
		t.Fatal(err)
	}
	err = resolveErr(t, provider, FakeCredential("nobody-here"), ErrFixtureNotFound)
	if !strings.Contains(err.Error(), "nobody-here") {
		t.Fatalf("错误要指出是哪个 fixture 名（fixture 名不是个人信息）: %v", err)
	}
	event, ok := audit.Last()
	if !ok {
		t.Fatal("失败解析必须留审计")
	}
	// 码必须是 fixture_not_found 而不是 subject_missing：前者要补测试数据，
	// 后者要去找 IdP 为什么没给 sub claim —— 混用会让影子运行的失败统计指错方向。
	if event.Outcome != OutcomeDenied || event.Reason != ReasonFixtureNotFound {
		t.Fatalf("未知 fixture 是拒绝而不是错误，且要给专用码: %+v", event)
	}
	if event.Subject != "" {
		t.Fatalf("没有真实主体时不得填 subject: %+v", event)
	}
	if event.SubjectRef == "" {
		t.Fatal("必须有凭证摘要供关联同一凭证的多次失败")
	}
}

// 凭证类型必须与来源匹配：OIDC 凭证不能喂 fake，反之亦然。
func TestFakeProviderRejectsForeignCredentialKind(t *testing.T) {
	provider, err := NewFakeUniversityProvider()
	if err != nil {
		t.Fatal(err)
	}
	err = resolveErr(t, provider, oidcCredential(t, "not-a-real-token"), ErrCredentialKind)
	assertReason(t, err, ReasonCredentialInvalid)
}

// AddFixture 存副本、AddFailure 固定失败，都是「可编程」的全部含义；
// 没有副本语义的话，并发用例里会出现「没人改过但身份变了」这种无法复现的失败。
func TestFakeProviderFixtureIsolationAndFailures(t *testing.T) {
	profile := studentProfile()
	claims := profile.Claims(baseNow)
	extra := claims.Extra
	provider, err := NewFakeProvider(FakeOptions{Fixtures: map[string]Claims{"student": claims}},
		WithClock(fixedClock(baseNow)))
	if err != nil {
		t.Fatal(err)
	}
	before := resolveOK(t, provider, FakeCredential("student"))

	// 改调用方自己那份 map：已注册的 fixture 不许跟着变。
	delete(extra, "organization")
	extra["department"] = "someone-elses-college"
	after := resolveOK(t, provider, FakeCredential("student"))
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("fixture 必须是副本:\nbefore %+v\nafter %+v", before, after)
	}

	provider.AddFailure("student", ErrExpired)
	err = resolveErr(t, provider, FakeCredential("student"), ErrExpired)
	assertReason(t, err, ReasonTokenExpired)

	// 配了失败却没给错误：只能是内部错误，绝不能当成成功或「拒绝」。
	provider.AddFailure("broken", nil)
	audit := NewAuditRecorder(0)
	provider2, err := NewFakeProvider(FakeOptions{}, WithAudit(audit))
	if err != nil {
		t.Fatal(err)
	}
	provider2.AddFailure("broken", nil)
	err = resolveErr(t, provider2, FakeCredential("broken"), ErrInternal)
	assertReason(t, err, ReasonInternalError)
	event, _ := audit.Last()
	if event.Outcome != OutcomeError {
		t.Fatalf("内部错误必须记成 error 而不是 denied: %+v", event)
	}
}

// fixture 名是编程错误而非运行期事实：空名与超长名一律 panic，不留 error 分支。
func TestFakeCredentialPanicsOnProgrammingErrors(t *testing.T) {
	assertPanic(t, "空 fixture 名必须 panic", func() { FakeCredential("") })
	assertPanic(t, "超长 fixture 名必须 panic", func() {
		FakeCredential(strings.Repeat("x", maxCredentialBytes+1))
	})
	cred := FakeCredential("student-1001")
	if cred.Kind() != CredentialFakeFixture || cred.Value() != "student-1001" {
		t.Fatalf("凭证形态不符: %v", cred)
	}
}

func assertPanic(t *testing.T, want string, run func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal(want)
		}
	}()
	run()
}

// claims 校验分支：fake 与 OIDC 共用 ValidateClaims，所以每条时效拒绝路径都要在 fake 上成立。
func TestFakeProviderClaimsValidationPaths(t *testing.T) {
	profile := studentProfile()

	t.Run("issuer 不符", func(t *testing.T) {
		provider, err := NewFakeProvider(FakeOptions{
			Issuer: "https://other-issuer.invalid/issuer",
		}, WithClock(fixedClock(baseNow)))
		if err != nil {
			t.Fatal(err)
		}
		provider.AddFixture("student", profile.Claims(baseNow))
		err = resolveErr(t, provider, FakeCredential("student"), ErrIssuerMismatch)
		assertReason(t, err, ReasonIssuerMismatch)
	})

	t.Run("audience 不符", func(t *testing.T) {
		provider, err := NewFakeProvider(FakeOptions{Audience: "other-client"}, WithClock(fixedClock(baseNow)))
		if err != nil {
			t.Fatal(err)
		}
		provider.AddFixture("student", profile.Claims(baseNow))
		err = resolveErr(t, provider, FakeCredential("student"), ErrAudienceMismatch)
		assertReason(t, err, ReasonAudienceMismatch)
	})

	t.Run("已过期", func(t *testing.T) {
		provider, err := NewFakeProvider(FakeOptions{}, WithClock(fixedClock(baseNow)))
		if err != nil {
			t.Fatal(err)
		}
		expired := profile
		expired.Lifetime = -time.Minute // 负数 Lifetime 就是「签一个已过期的 token」
		provider.AddFixture("student", expired.Claims(baseNow))
		err = resolveErr(t, provider, FakeCredential("student"), ErrExpired)
		assertReason(t, err, ReasonTokenExpired)
	})

	t.Run("缺 exp", func(t *testing.T) {
		provider, err := NewFakeProvider(FakeOptions{}, WithClock(fixedClock(baseNow)))
		if err != nil {
			t.Fatal(err)
		}
		claims := profile.Claims(baseNow)
		claims.HasExpiry = false
		claims.Expiry = time.Time{}
		provider.AddFixture("student", claims)
		err = resolveErr(t, provider, FakeCredential("student"), ErrExpiryMissing)
		assertReason(t, err, ReasonExpiryMissing)
	})

	t.Run("生命周期超运营上限", func(t *testing.T) {
		provider, err := NewFakeProvider(FakeOptions{MaxLifetime: time.Hour}, WithClock(fixedClock(baseNow)))
		if err != nil {
			t.Fatal(err)
		}
		provider.AddFixture("student", profile.Claims(baseNow)) // 默认 8 小时
		err = resolveErr(t, provider, FakeCredential("student"), ErrLifetimeTooLong)
		assertReason(t, err, ReasonLifetimeExceeded)
	})

	t.Run("严格时钟拒绝未来时刻", func(t *testing.T) {
		provider, err := NewFakeProvider(FakeOptions{StrictClock: true}, WithClock(fixedClock(baseNow)))
		if err != nil {
			t.Fatal(err)
		}
		// nbf 在前，所以带未来 nbf 的 token 先落在 not_yet_valid 上。
		future := profile.Claims(baseNow.Add(10 * time.Second))
		provider.AddFixture("student", future)
		err = resolveErr(t, provider, FakeCredential("student"), ErrNotYetValid)
		assertReason(t, err, ReasonNotYetValid)

		// 去掉 nbf 才能单独走到 iat 的未来判定（签发方时钟异常/伪造）。
		futureNotBefore := future.Clone()
		futureNotBefore.NotBefore = time.Time{}
		provider.AddFixture("student-no-nbf", futureNotBefore)
		err = resolveErr(t, provider, FakeCredential("student-no-nbf"), ErrIssuedInFuture)
		assertReason(t, err, ReasonIssuedInFuture)

		// 默认容忍 60 秒偏移：同样 10 秒的未来 iat 在宽松模式下必须能用，
		// 否则校内 NTP 抖一下就是全员登录失败。
		lenient, err := NewFakeProvider(FakeOptions{}, WithClock(fixedClock(baseNow)))
		if err != nil {
			t.Fatal(err)
		}
		lenient.AddFixture("student", future)
		resolveOK(t, lenient, FakeCredential("student"))
	})
}

// fake 必须吃同一份映射表：默认 fail-closed 的目录在 fake 上同样把映射挡掉。
func TestFakeProviderUsesTheSameMapper(t *testing.T) {
	profile := studentProfile()
	strictCfg := DefaultMapperConfig()
	strictCfg.Directory = StaticDirectory{
		Entries: map[policy.ScopeKind]map[string]string{policy.ScopeOrganization: {}},
	}
	strictMapper, err := NewClaimMapper(strictCfg)
	if err != nil {
		t.Fatal(err)
	}

	lenient, err := NewFakeProvider(FakeOptions{}, WithClock(fixedClock(baseNow)))
	if err != nil {
		t.Fatal(err)
	}
	lenient.AddFixture("student", profile.Claims(baseNow))
	resolveOK(t, lenient, FakeCredential("student"))

	strict, err := NewFakeProvider(FakeOptions{Mapper: strictMapper}, WithClock(fixedClock(baseNow)))
	if err != nil {
		t.Fatal(err)
	}
	strict.AddFixture("student", profile.Claims(baseNow))
	err = resolveErr(t, strict, FakeCredential("student"), ErrScopeUnmapped)
	assertReason(t, err, ReasonScopeUnmapped)
}

// FakeAuthority 的默认签发参数与内置样例一致，WithIdentity 覆盖后必须真的生效：
// 否则「iss/aud 不符」这类负例是假通过。
func TestFakeAuthorityIdentityOverride(t *testing.T) {
	profile := studentProfile()

	defaults, err := NewFakeAuthority()
	if err != nil {
		t.Fatal(err)
	}
	if defaults.Issuer() != FakeDefaultIssuer || defaults.Audience() != FakeDefaultAudience {
		t.Fatalf("默认签发参数不符: %q %q", defaults.Issuer(), defaults.Audience())
	}
	if defaults.RSAKeyID() != "fake-rsa-key" || defaults.ECKeyID() != "fake-ec-key" {
		t.Fatalf("默认 kid 不符: %q %q", defaults.RSAKeyID(), defaults.ECKeyID())
	}

	custom, err := NewFakeAuthority()
	if err != nil {
		t.Fatal(err)
	}
	custom.WithIdentity("https://campus.invalid/idp", "llmproxy-shadow")
	if custom.Issuer() != "https://campus.invalid/idp" || custom.Audience() != "llmproxy-shadow" {
		t.Fatal("WithIdentity 必须链式覆盖签发参数")
	}
	token := mustToken(t, custom, SignRequest{Profile: profile, At: baseNow})

	matching := newOIDC(t, custom, oidcOptions{audience: "llmproxy-shadow"})
	// newOIDC 的 issuer 固定是 FakeDefaultIssuer，这里必须换成自定义签发方才能验过。
	cfg := OIDCConfig{
		Source: "campus-oidc", Issuer: custom.Issuer(), Audience: custom.Audience(),
	}
	customProvider, err := NewOIDCProvider(cfg, custom, WithClock(fixedClock(baseNow)))
	if err != nil {
		t.Fatal(err)
	}
	principal := resolveOK(t, customProvider, oidcCredential(t, token))
	if principal.Identity.Subject != profile.Subject {
		t.Fatalf("覆盖签发参数后仍要能解析: %+v", principal.Identity)
	}

	// 反路：按默认 issuer 配的 provider 必须认不出这个 token。
	resolveErr(t, matching, oidcCredential(t, token), ErrIssuerMismatch)
}

// 换一把别的 key 签的同内容 token 必须验不过（fake 与真链路同形的另一半证明）。
func TestFakeAuthorityTokensOnlyVerifyWithTheirOwnKeys(t *testing.T) {
	profile := studentProfile()
	authority := testAuthority(t)
	other := testAuthority(t)
	token := mustToken(t, authority, SignRequest{Profile: profile, At: baseNow})

	// 只用公钥材料组装的静态来源也要能验过：证明 fake 没有偷偷走后门。
	material, err := authority.Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	publicOnly := newOIDC(t, &StaticKeys{Material: material}, oidcOptions{})
	resolveOK(t, publicOnly, oidcCredential(t, token))

	// 另一台签发方的同内容 token：kid 相同（都是 fake-rsa-key）但密钥不同 → 只能是签名不符。
	crossToken := mustToken(t, other, SignRequest{Profile: profile, At: baseNow})
	err = resolveErr(t, publicOnly, oidcCredential(t, crossToken), ErrSignature)
	assertReason(t, err, ReasonSignatureInvalid)

	// 来源里只放「外部公钥」（同一 kid）：同样必须验不过，且不能退化成 claims 错误。
	foreignOnly := &StaticKeys{Material: []JWK{{KeyID: authority.RSAKeyID(), Algorithm: AlgRS256, Public: testForeignPublic(t, authority)}}}
	foreignProvider := newOIDC(t, foreignOnly, oidcOptions{})
	err = resolveErr(t, foreignProvider, oidcCredential(t, token), ErrSignature)
	assertReason(t, err, ReasonSignatureInvalid)

	// 用外部私钥签、kid 仍写本来源：找对了 key 但签名对不上，这条路径必须单独成立。
	byForeign := mustToken(t, authority, SignRequest{Profile: profile, At: baseNow, SignWithForeign: true})
	resolveErr(t, publicOnly, oidcCredential(t, byForeign), ErrSignature)

	// ES256 分支同理：换 key 后必须验不过。
	ecToken := mustToken(t, authority, SignRequest{Profile: profile, At: baseNow, Algorithm: AlgES256})
	ecKeys := &StaticKeys{Material: []JWK{{KeyID: authority.ECKeyID(), Algorithm: AlgES256, Public: testECPublic(t, other)}}}
	resolveErr(t, newOIDC(t, ecKeys, oidcOptions{}), oidcCredential(t, ecToken), ErrSignature)
}

// 签名夹具自身的配置错误必须明确报错，而不是签出一个「看起来能过」的 token。
func TestFakeAuthoritySignConfigErrors(t *testing.T) {
	authority := testAuthority(t)

	if _, err := authority.Sign(SignRequest{At: baseNow}); !errors.Is(err, ErrConfig) {
		t.Fatalf("既没有 Claims 也没有 Profile 必须报配置错误: %v", err)
	}
	if _, err := authority.Sign(SignRequest{Profile: studentProfile(), At: baseNow, Algorithm: AlgES256, SignWithForeign: true}); !errors.Is(err, ErrConfig) {
		t.Fatalf("外部密钥只有 RSA，配 ES256 必须是配置错误: %v", err)
	}
	if _, err := authority.Sign(SignRequest{
		Profile: studentProfile(), At: baseNow, HeaderExtras: map[string]any{"alg": "none"},
	}); !errors.Is(err, ErrConfig) {
		t.Fatal("不支持的保护头字段必须报错，不能静默忽略（静默忽略会造出假绿的用例）")
	}
	if _, err := authority.Sign(SignRequest{
		Profile: studentProfile(), At: baseNow, HeaderExtras: map[string]any{"crit": "b64"},
	}); !errors.Is(err, ErrConfig) {
		t.Fatal("crit 必须是数组")
	}

	// 正路：显式覆盖 typ / kid 都能签出来。
	if _, err := authority.Sign(SignRequest{
		Profile: studentProfile(), At: baseNow,
		HeaderExtras: map[string]any{"typ": "at+JWT", "crit": []any{"custom"}}, Kid: "rotated-key",
	}); err != nil {
		t.Fatalf("合法覆盖应当能签发: %v", err)
	}
}

// RawPayload 是畸形 claims 的最小复现入口（真链路会先验签再解析，所以这条必须落在 claims 上）。
func TestFakeAuthorityRawPayloadProducesClaimsError(t *testing.T) {
	authority := testAuthority(t)
	provider := newOIDC(t, authority, oidcOptions{})
	token := mustToken(t, authority, SignRequest{Profile: studentProfile(), At: baseNow, RawPayload: []byte("not-json")})
	err := resolveErr(t, provider, oidcCredential(t, token), ErrClaimsInvalid)
	assertReason(t, err, ReasonClaimsInvalid)
	if strings.Contains(err.Error(), "not-json") {
		t.Fatalf("claims 解析错误不得回显原文: %v", err)
	}
}

// 编译期断言：fake 的两个类型都满足各自接口（手册要求 fake 可直接替换真实来源）。
var (
	_ Provider  = (*FakeProvider)(nil)
	_ KeySource = (*FakeAuthority)(nil)
)
