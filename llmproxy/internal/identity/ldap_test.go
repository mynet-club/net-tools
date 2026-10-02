package identity

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ldap.go 是 stub，但它已经对外开放了三件有安全语义的事：
// 配置期挡住「没有 TTL 的目录身份」、解析期对口令长度与结构设限、
// 以及任何情况下都不把口令递到实现之外。
// 这三件事现在就钉住，真实现接上来的时候才不会被「顺手放宽」。

// ldapTrust 是最小可用配置：BaseDN / UserAttr / IdentityTTL 三项都必填，
// 所以基准用例先把它们给全，负例再逐项拆掉。
func ldapTrust() LDAPTrust {
	return LDAPTrust{
		Source:      "campus-ldap",
		BaseDN:      "ou=people,dc=hospital-a,dc=invalid",
		UserAttr:    "uid",
		GroupAttr:   "memberOf",
		IdentityTTL: 2 * time.Hour,
	}
}

func mustLDAPProvider(t *testing.T, trust LDAPTrust, opts ...Option) *UnconfiguredLDAPProvider {
	t.Helper()
	provider, err := NewUnconfiguredLDAPProvider(trust, opts...)
	if err != nil {
		t.Fatalf("构造 LDAP 占位来源失败: %v", err)
	}
	return provider
}

// bindCredential 把 "dn\npassword" 包成凭证（DN 与口令都是合成值，不含真实账号）。
func bindCredential(t *testing.T, value string) Credential {
	t.Helper()
	cred, err := NewCredential(CredentialLDAPBind, value)
	if err != nil {
		t.Fatalf("构造 bind 凭证失败: %v", err)
	}
	return cred
}

// credentialOfKind 用指定类型包凭证，用于测「凭证串味」这条拒绝路径。
func credentialOfKind(t *testing.T, kind CredentialKind, value string) Credential {
	t.Helper()
	cred, err := NewCredential(kind, value)
	if err != nil {
		t.Fatalf("构造 %q 凭证失败: %v", kind, err)
	}
	return cred
}

const (
	ldapSampleDN       = "uid=alice,ou=people,dc=hospital-a,dc=invalid"
	ldapSamplePassword = "Sup3r-Synthetic-Passphrase"
)

// assertEmptyPrincipal 断言失败路径没漏出半个身份。
// Principal 含切片字段、不能用 == 比较，只能走 DeepEqual。
func assertEmptyPrincipal(t *testing.T, principal Principal) {
	t.Helper()
	if !reflect.DeepEqual(principal, Principal{}) {
		t.Fatalf("失败路径必须返回空 Principal，实际 %+v", principal)
	}
}

func TestNewUnconfiguredLDAPProviderRequiresCompleteConfig(t *testing.T) {
	// 每一项单独缺失都必须建库即失败，而不是留到第一次 bind：
	// 缺 TTL 的目录身份一旦进了缓存，账号被禁用后仍能继续用。
	cases := []struct {
		name   string
		mutate func(*LDAPTrust)
	}{
		{"缺 BaseDN", func(cfg *LDAPTrust) { cfg.BaseDN = "" }},
		{"缺 UserAttr", func(cfg *LDAPTrust) { cfg.UserAttr = "" }},
		{"IdentityTTL 未设置", func(cfg *LDAPTrust) { cfg.IdentityTTL = 0 }},
		{"IdentityTTL 为负", func(cfg *LDAPTrust) { cfg.IdentityTTL = -time.Minute }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trust := ldapTrust()
			tc.mutate(&trust)
			provider, err := NewUnconfiguredLDAPProvider(trust)
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("配置不完整必须被拒（%+v），实际: %v", trust, err)
			}
			if provider != nil {
				t.Fatal("配置不合法时不能返回可用的来源对象")
			}
			assertReason(t, err, ReasonConfigInvalid)
		})
	}
}

func TestUnconfiguredLDAPProviderKeepsTrustConfiguration(t *testing.T) {
	trust := ldapTrust()
	trust.MaxPasswordBytes = 512
	provider := mustLDAPProvider(t, trust)

	if got := provider.Name(); got != "ldap" {
		t.Fatalf("provider 名应是稳定的 %q（进审计，改名会断掉历史查询），实际 %q", "ldap", got)
	}
	// Trust() 必须原样回吐配置：接线层要靠它核对目录地址与 TTL，
	// 任何静默改写都会让「配置里写的」和「实际生效的」不一致。
	kept := provider.Trust()
	if kept.IdentityTTL != trust.IdentityTTL {
		t.Fatalf("IdentityTTL 从 %v 变成 %v", trust.IdentityTTL, kept.IdentityTTL)
	}
	if kept.BaseDN != trust.BaseDN || kept.UserAttr != trust.UserAttr {
		t.Fatalf("目录基准被改写: %+v", kept)
	}
	if kept.MaxPasswordBytes != 512 {
		t.Fatalf("口令长度上限被改写: %d", kept.MaxPasswordBytes)
	}
	// Source 留空时回落到 provider 名，不能让 Identity.Source 变空串。
	unnamed := ldapTrust()
	unnamed.Source = ""
	if got := mustLDAPProvider(t, unnamed).source; got != "ldap" {
		t.Fatalf("未配置 Source 应回落到 %q，实际 %q", "ldap", got)
	}
	if got := mustLDAPProvider(t, ldapTrust()).source; got != "campus-ldap" {
		t.Fatalf("Source 必须用配置值（conditions 里的 source 键按它精确匹配），实际 %q", got)
	}
}

func TestUnconfiguredLDAPProviderRejectsOtherCredentialKinds(t *testing.T) {
	provider := mustLDAPProvider(t, ldapTrust())
	// 凭证类型串味必须挡在解析入口：让 OIDC token 走 LDAP 通路，
	// 真实现接上之后就是拿目录 bind 去验一个 JWT。
	candidates := []Credential{
		credentialOfKind(t, CredentialOIDCToken, ldapSampleDN+"\n"+ldapSamplePassword),
		credentialOfKind(t, CredentialSAMLAssertion, "ZmFrZS1hc3NlcnRpb24="),
		FakeCredential("student-1001"),
	}
	for _, cred := range candidates {
		principal, err := provider.Resolve(context.Background(), cred)
		if !errors.Is(err, ErrCredentialKind) {
			t.Fatalf("%q 凭证必须被拒，实际: %v", cred.Kind(), err)
		}
		assertReason(t, err, ReasonCredentialInvalid)
		assertEmptyPrincipal(t, principal)
	}
}

func TestUnconfiguredLDAPProviderFailsWithNotImplemented(t *testing.T) {
	recorder := NewAuditRecorder(0)
	provider := mustLDAPProvider(t, ldapTrust(), WithClock(fixedClock(baseNow)), WithAudit(recorder))
	cred := bindCredential(t, ldapSampleDN+"\n"+ldapSamplePassword).WithRequestID("req-ldap-1")

	principal, err := provider.Resolve(context.Background(), cred)
	// stub 只允许失败：任何「返回零值 + nil error」的实现都是静默放行，
	// 调用方会把空身份当成解析成功继续走策略评估。
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("未实现的来源必须报 ErrNotImplemented，实际: %v", err)
	}
	assertReason(t, err, ReasonNotImplemented)
	assertEmptyPrincipal(t, principal)

	events := recorder.Events()
	if len(events) != 1 {
		t.Fatalf("bind 失败应留下恰好一条审计，实际 %d 条: %+v", len(events), events)
	}
	event := events[0]
	// Outcome 是 error 而不是 denied：来源没实现是部署问题，不是调用方的凭证问题。
	// 混成 denied 会把「接线还没做完」读成「有人在试探登录」。
	if event.Outcome != OutcomeError {
		t.Fatalf("未实现路径的 Outcome 应是 error，实际 %q", event.Outcome)
	}
	if event.Reason != ReasonNotImplemented || !event.Reason.Valid() {
		t.Fatalf("原因码应是注册过的 not_implemented，实际 %q", event.Reason)
	}
	if event.Source != "campus-ldap" || event.Provider != "ldap" {
		t.Fatalf("审计来源/实例名不符: %+v", event)
	}
	if event.Subject != ldapSampleDN {
		t.Fatalf("审计应记录 bind DN 作为主体线索，实际 %q", event.Subject)
	}
	if event.RequestID != "req-ldap-1" {
		t.Fatalf("RequestID 必须透传（把身份日志与请求日志对上），实际 %q", event.RequestID)
	}
	if !event.OccurredAt.Equal(baseNow) {
		t.Fatalf("审计时刻应取注入时钟，实际 %v", event.OccurredAt)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("事件本身必须能过校验: %v", err)
	}
}

func TestUnconfiguredLDAPProviderNeverLeaksTheBindPassword(t *testing.T) {
	recorder := NewAuditRecorder(0)
	provider := mustLDAPProvider(t, ldapTrust(), WithAudit(recorder))
	cred := bindCredential(t, ldapSampleDN+"\n"+ldapSamplePassword)

	_, resolveFailure := provider.Resolve(context.Background(), cred)
	if resolveFailure == nil {
		t.Fatal("未实现路径必须失败")
	}
	// 口令只能停在 splitBindCredential 的返回值里：
	// 错误文本、审计事件的单行形式与 JSON 序列化都必须看不到它。
	sinks := map[string]string{"error": resolveFailure.Error()}
	events := recorder.Events()
	if len(events) != 1 {
		t.Fatalf("期望一条审计，实际 %d", len(events))
	}
	sinks["audit-string"] = events[0].String()
	raw, jsonErr := json.Marshal(events[0])
	if jsonErr != nil {
		t.Fatalf("序列化审计事件失败: %v", jsonErr)
	}
	sinks["audit-json"] = string(raw)
	for name, content := range sinks {
		if needle, found := containsAny(content, ldapSamplePassword, cred.Value()); found {
			t.Fatalf("%s 泄露了 bind 凭证片段 %q: %s", name, needle, content)
		}
	}

	// AD 的 userPrincipalName 形态（邮箱）当 DN 用时，主体线索只能落摘要：
	// 否则「被拒的登录尝试」会把邮箱原文写进审计表。
	recorder.Reset()
	upnCredential := bindCredential(t, "alice@hospital-a.invalid\n"+ldapSamplePassword)
	if _, err := provider.Resolve(context.Background(), upnCredential); err == nil {
		t.Fatal("未实现路径必须失败")
	}
	last, ok := recorder.Last()
	if !ok {
		t.Fatal("应当留下审计事件")
	}
	if last.Subject != "" {
		t.Fatalf("邮箱形态的主体不得记原文，实际 %q", last.Subject)
	}
	if last.SubjectRef == "" {
		t.Fatal("主体被脱敏后仍要有摘要可供关联")
	}
	if needle, found := containsAny(last.String(), "alice@hospital-a.invalid", ldapSamplePassword); found {
		t.Fatalf("审计泄露了 %q: %s", needle, last.String())
	}
	if err := last.Validate(); err != nil {
		t.Fatalf("事件本身必须能过校验: %v", err)
	}
}

func TestSplitBindCredentialRejectsMalformedAndOversizedValues(t *testing.T) {
	longPassword := strings.Repeat("p", defaultMaxPasswordBytes+1)
	// 汉字口令：限长按字节算，100 个汉字（300 字节）就在 256 的上限之外。
	// 这条必须钉住，否则实现方很容易把它改成 utf8.RuneCountInString 而放宽三倍。
	cjkPassword := strings.Repeat("密", 100)

	cases := []struct {
		name         string
		value        string
		limit        int
		wantErr      error
		wantDN       string
		wantPassword string
	}{
		{
			name:    "没有换行分隔",
			value:   ldapSampleDN + " " + ldapSamplePassword,
			wantErr: ErrCredential,
		},
		{
			name:    "空 DN",
			value:   "\n" + ldapSamplePassword,
			wantErr: ErrCredential,
		},
		{
			name:    "空口令",
			value:   ldapSampleDN + "\n",
			wantErr: ErrCredential,
		},
		{
			name:    "口令超默认上限",
			value:   ldapSampleDN + "\n" + longPassword,
			wantErr: ErrCredentialTooLarge,
		},
		{
			name:    "口令按字节而非字符计长度",
			value:   ldapSampleDN + "\n" + cjkPassword,
			wantErr: ErrCredentialTooLarge,
		},
		{
			name:    "命中自定义上限之外",
			value:   ldapSampleDN + "\n" + strings.Repeat("p", 17),
			limit:   16,
			wantErr: ErrCredentialTooLarge,
		},
		{
			name:         "自定义上限边界内",
			value:        ldapSampleDN + "\n" + strings.Repeat("p", 16),
			limit:        16,
			wantDN:       ldapSampleDN,
			wantPassword: strings.Repeat("p", 16),
		},
		{
			name:         "默认上限边界内",
			value:        ldapSampleDN + "\n" + strings.Repeat("p", defaultMaxPasswordBytes),
			wantDN:       ldapSampleDN,
			wantPassword: strings.Repeat("p", defaultMaxPasswordBytes),
		},
		{
			// 只按第一个换行拆分：DN 里不能有换行（目录侧也不允许），
			// 而口令可以含换行 —— 这条语义真实现必须沿用，否则口令会被截断成
			// 「拿去 bind 的是另一个口令」。
			name:         "口令内含换行时只拆第一个",
			value:        ldapSampleDN + "\npass\nword",
			wantDN:       ldapSampleDN,
			wantPassword: "pass\nword",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dn, password, err := splitBindCredential(tc.value, tc.limit)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("应当报 %v，实际: %v", tc.wantErr, err)
				}
				// 失败时两个分量都必须为空：半拆出来的值一旦被下游拿去 bind，
				// 就是拿调用方控制的可疑字符串去问目录。
				if dn != "" || password != "" {
					t.Fatalf("失败路径必须清空 DN 与口令，实际 dn=%q 口令长度=%d", dn, len(password))
				}
				return
			}
			if err != nil {
				t.Fatalf("合法凭证被拒: %v", err)
			}
			if dn != tc.wantDN {
				t.Fatalf("DN 期望 %q，实际 %q", tc.wantDN, dn)
			}
			if password != tc.wantPassword {
				t.Fatalf("口令拆分结果不符，期望 %d 字节，实际 %d 字节",
					len(tc.wantPassword), len(password))
			}
		})
	}

	// 超长口令的原因码必须是 credential_too_long：它是「被拒的输入」，
	// 与 signature_invalid 混在一起就看不出这是在试探缓冲区。
	_, _, oversizedErr := splitBindCredential(ldapSampleDN+"\n"+longPassword, 0)
	assertReason(t, oversizedErr, ReasonCredentialTooLong)
	_, _, malformedErr := splitBindCredential(ldapSampleDN+" "+ldapSamplePassword, 0)
	assertReason(t, malformedErr, ReasonCredentialInvalid)
}

func TestLDAPResolveRejectsOversizedBindCredential(t *testing.T) {
	// 整条链路也要挡住：接线层常常直接把 Authorization 头包成凭证，
	// 上限若只写在 splitBindCredential 里，就得由 Resolve 真的调用它才算数。
	cases := []struct {
		name  string
		trust func(*LDAPTrust)
		value string
	}{
		{"默认上限", func(cfg *LDAPTrust) {}, ldapSampleDN + "\n" + strings.Repeat("p", defaultMaxPasswordBytes+1)},
		{"自定义上限", func(cfg *LDAPTrust) { cfg.MaxPasswordBytes = 8 }, ldapSampleDN + "\n" + strings.Repeat("p", 9)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trust := ldapTrust()
			tc.trust(&trust)
			provider := mustLDAPProvider(t, trust)
			principal, err := provider.Resolve(context.Background(), bindCredential(t, tc.value))
			if !errors.Is(err, ErrCredentialTooLarge) {
				t.Fatalf("超长口令必须被拒，实际: %v", err)
			}
			assertReason(t, err, ReasonCredentialTooLong)
			assertEmptyPrincipal(t, principal)
		})
	}
}

func TestUnconfiguredLDAPProviderBindNeverSucceeds(t *testing.T) {
	provider := mustLDAPProvider(t, ldapTrust())
	ctx := context.Background()
	fullTrust := ldapTrust()

	// 空 DN / 空口令：匿名 bind 在部分目录配置里会成功，
	// 所以这里必须在进目录之前拒掉，而不是指望对端报错。
	emptyDN, dnErr := provider.Bind(ctx, "", ldapSamplePassword, fullTrust)
	if !errors.Is(dnErr, ErrCredential) {
		t.Fatalf("空 DN 必须被拒，实际: %v", dnErr)
	}
	assertReason(t, dnErr, ReasonCredentialInvalid)
	assertEmptyPrincipal(t, emptyDN)

	emptyPassword, passwordErr := provider.Bind(ctx, ldapSampleDN, "", fullTrust)
	if !errors.Is(passwordErr, ErrCredential) {
		t.Fatalf("空口令必须被拒（空口令在部分目录里是匿名绑定），实际: %v", passwordErr)
	}
	assertEmptyPrincipal(t, emptyPassword)

	// base 由配置给，不接受调用方现传：否则任何人都能指定基准去做跨 OU 查询。
	noBase := ldapTrust()
	noBase.BaseDN = ""
	principal, baseErr := provider.Bind(ctx, ldapSampleDN, ldapSamplePassword, noBase)
	if !errors.Is(baseErr, ErrConfig) {
		t.Fatalf("缺 BaseDN 必须报配置错误，实际: %v", baseErr)
	}
	assertReason(t, baseErr, ReasonConfigInvalid)
	assertEmptyPrincipal(t, principal)

	// 参数齐全时也只能是「尚未实现」：stub 绝不能返回一个看起来成功的 Principal。
	principal, err := provider.Bind(ctx, ldapSampleDN, ldapSamplePassword, fullTrust)
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("Bind 在未实现期必须失败，实际: %v", err)
	}
	assertReason(t, err, ReasonNotImplemented)
	assertEmptyPrincipal(t, principal)
}

func TestLDAPMappingPlanRecordsTheUnimplementedMappingPoints(t *testing.T) {
	// 映射点是这个 stub 唯一的「文档即约束」：后续实现若漏掉 TTL、
	// 或把邮箱/手机号带进 Principal，就得能在计划里找到对应条目。
	plan := LDAPMappingPlan()
	if len(plan) == 0 {
		t.Fatal("未实现部分必须有映射点清单")
	}
	joined := strings.Join(plan, "\n")
	for _, needle := range []string{"IdentityTTL", "Subject", "memberOf", "mail"} {
		if !strings.Contains(joined, needle) {
			t.Fatalf("映射计划应覆盖 %q，实际:\n%s", needle, joined)
		}
	}
	// 返回副本：调用方（包括测试）改写切片不能改坏计划本身。
	plan[0] = "被改写的一行"
	if LDAPMappingPlan()[0] == "被改写的一行" {
		t.Fatal("LDAPMappingPlan 必须返回副本")
	}
}

func TestLDAPProviderSatisfiesProviderContract(t *testing.T) {
	// 编译期断言之外再钉一次行为：接线层拿到的是 Provider 接口，
	// Resolve 的失败方向必须可辨认（带本包前缀、不吞原因、不产出身份）。
	var provider Provider = mustLDAPProvider(t, ldapTrust())
	if provider.Name() != "ldap" {
		t.Fatalf("接口名漂移: %q", provider.Name())
	}
	principal, err := provider.Resolve(context.Background(),
		bindCredential(t, ldapSampleDN+"\n"+ldapSamplePassword))
	assertEmptyPrincipal(t, principal)
	if err == nil || !strings.HasPrefix(err.Error(), "identity:") {
		t.Fatalf("错误必须带本包前缀且不吞原因，实际: %v", err)
	}
}

// IdentityTTL 必须有上限：这个字段的存在理由就是「被禁账号不能继续可用」，
// 只判「为正」会放过 100 年这种写法 —— 配置校验要挡的是语义，不是符号。
func TestLDAPProviderCapsIdentityTTL(t *testing.T) {
	overlong := ldapTrust()
	overlong.IdentityTTL = 100 * 365 * 24 * time.Hour
	if _, err := NewUnconfiguredLDAPProvider(overlong); !errors.Is(err, ErrConfig) {
		t.Fatalf("超长 TTL 必须在构造期被拒，实际: %v", err)
	}
	atLimit := ldapTrust()
	atLimit.IdentityTTL = maxLDAPIdentityTTL
	if _, err := NewUnconfiguredLDAPProvider(atLimit); err != nil {
		t.Fatalf("正好等于上限应当可用: %v", err)
	}
}

// 每条失败路径都要留审计：凭证串味、结构非法、口令超限、能力未实现。
// OIDC 与 fake 一直这么做；LDAP 少记一条，「有人在拿畸形 bind 试探」就完全不可见。
func TestLDAPResolveEveryFailureIsAudited(t *testing.T) {
	audit := NewAuditRecorder(0)
	provider := mustLDAPProvider(t, ldapTrust(), WithAudit(audit))

	cases := []struct {
		name        string
		cred        Credential
		wantReason  ReasonCode
		wantOutcome Outcome
	}{
		{"凭证类型不符", credentialOfKind(t, CredentialOIDCToken, "not-a-bind"), ReasonCredentialInvalid, OutcomeDenied},
		{"缺少换行分隔", bindCredential(t, "uid=alice-only"), ReasonCredentialInvalid, OutcomeDenied},
		{"口令超限", bindCredential(t, ldapSampleDN+"\n"+strings.Repeat("p", 300)), ReasonCredentialTooLong, OutcomeDenied},
		// 尚未实现是「本包没接通」，不是「这个人被拒」：Outcome 必须是 error（见 dependencyReasons）。
		{"能力未实现", bindCredential(t, ldapSampleDN+"\nZZldap-password"), ReasonNotImplemented, OutcomeError},
	}
	for _, item := range cases {
		if _, err := provider.Resolve(context.Background(), item.cred); err == nil {
			t.Fatalf("%s 应当失败", item.name)
		}
		event, ok := audit.Last()
		if !ok {
			t.Fatalf("%s 必须留一条审计事件", item.name)
		}
		if event.Reason != item.wantReason || event.Outcome != item.wantOutcome {
			t.Fatalf("%s 的结论 = %s/%s，期望 %s/%s", item.name, event.Outcome, event.Reason, item.wantOutcome, item.wantReason)
		}
		if strings.Contains(event.String(), "ZZldap-password") {
			t.Fatalf("%s 的审计行带出了口令原文: %s", item.name, event.String())
		}
	}
}
