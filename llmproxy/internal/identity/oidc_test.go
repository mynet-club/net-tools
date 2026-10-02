package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 正常路径：一份完整的高校 OIDC claims → 期望的 Identity 字段与 ScopeChain。
//
// 这条用例同时是 B 的核心职责证明：policy 包故意不猜层级（领域文档 §5），
// 「学生属于哪个院系、哪门课」全部由这里的映射表展开成完整 chain。
func TestOIDCResolvesStudentClaimsIntoIdentityAndScopeChain(t *testing.T) {
	authority := testAuthority(t)
	audit := NewAuditRecorder(0)
	provider := newOIDC(t, authority, oidcOptions{audit: audit})

	profile := studentProfile()
	token := mustToken(t, authority, SignRequest{Profile: profile, At: baseNow})

	principal := resolveOK(t, provider, oidcCredential(t, token))

	id := principal.Identity
	if id.Subject != "uid-stu-1001" {
		t.Fatalf("Subject 应为稳定 ID，实际 %q", id.Subject)
	}
	if id.Source != "campus-oidc" {
		t.Fatalf("Source 应来自配置，实际 %q", id.Source)
	}
	if id.DisplayName != "Sample Student" {
		t.Fatalf("DisplayName 实际 %q", id.DisplayName)
	}
	if strings.Contains(id.Subject, "@") {
		t.Fatal("subject 不该是邮箱形态")
	}
	wantRoles := []string{"student"}
	if !equalStrings(id.Roles, wantRoles) {
		t.Fatalf("Roles 期望 %v，实际 %v", wantRoles, id.Roles)
	}
	// 成员关系一律归一化排序（policy.Normalize 的口径），否则回放摘要会飘。
	if !equalStrings(id.Groups, []string{"cs-college", "undergraduate"}) {
		t.Fatalf("Groups 期望排序去重，实际 %v", id.Groups)
	}
	if !equalStrings(id.Projects, []string{"cs-101", "math-201"}) {
		t.Fatalf("Projects（来自 course claim）实际 %v", id.Projects)
	}
	if !equalStrings(id.AuthMethods, []string{"otp", "pwd"}) {
		t.Fatalf("AuthMethods 期望 amr 的内容，实际 %v", id.AuthMethods)
	}
	// ExpiresAt 必须来自 token 的 exp：A 包要求带 roles 就带过期时间。
	if !id.IssuedAt.Equal(baseNow) {
		t.Fatalf("IssuedAt 应等于 iat，实际 %v", id.IssuedAt)
	}
	wantExpiry := baseNow.Add(8 * time.Hour)
	if !id.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("ExpiresAt 应等于 exp（%v），实际 %v", wantExpiry, id.ExpiresAt)
	}
	if !principal.ValidUntil.Equal(wantExpiry) {
		t.Fatalf("ValidUntil 必须与 Identity.ExpiresAt 一致，实际 %v", principal.ValidUntil)
	}
	if err := id.Validate(); err != nil {
		t.Fatalf("产出的身份必须能通过 A 包校验: %v", err)
	}
	if err := principal.Validate(); err != nil {
		t.Fatalf("Principal 自校验失败: %v", err)
	}

	// 范围集合：user + 主组织 + 院系 + 每门课，按 (kind, ID) 稳定排序。
	assertScopeChain(t, principal.Chain,
		"organization:cs-college",
		"organization:university",
		"project:cs-101",
		"project:math-201",
		"user:uid-stu-1001",
	)
	if principal.Organization != "university" {
		t.Fatalf("主组织应取 primary 规则的值，实际 %q", principal.Organization)
	}
	// 学生只有 course 没有 project claim：主项目留空，PolicyContext 才不会违反 §2.2。
	if principal.Project != "" {
		t.Fatalf("学生样例不该有主项目，实际 %q", principal.Project)
	}

	// 审计只记 subject/source/结论/计数，不记范围 ID 与 claims 内容。
	events := audit.Events()
	if len(events) != 1 {
		t.Fatalf("成功解析应产生 1 条审计，实际 %d", len(events))
	}
	event := events[0]
	if event.Outcome != OutcomeSuccess || event.Reason != ReasonSuccess {
		t.Fatalf("审计结论错误: %+v", event)
	}
	if event.Subject != "uid-stu-1001" || event.Source != "campus-oidc" || event.Provider != "oidc" {
		t.Fatalf("审计主体/来源不符: %+v", event)
	}
	if event.ScopeCount != 5 || event.RoleCount != 1 {
		t.Fatalf("审计计数应反映派生结果: %+v", event)
	}
	if event.OccurredAt.IsZero() {
		t.Fatal("审计必须带时间")
	}
}

// PI 样例证明「多项目 + 主项目」的展开，以及 claims 数组顺序不影响结论。
func TestOIDCExpandsProjectScopesDeterministically(t *testing.T) {
	authority := testAuthority(t)
	provider := newOIDC(t, authority, oidcOptions{})

	profile := profileByFixture(t, "pi-3001")
	token := mustToken(t, authority, SignRequest{Profile: profile, At: baseNow})
	principal := resolveOK(t, provider, oidcCredential(t, token))

	if principal.Organization != "university" || principal.Project != "proj-grant-2026" {
		t.Fatalf("主组织/主项目不符: %+v", principal)
	}
	if !principal.Chain.Includes(policy.MustScope(policy.ScopeProject, "proj-lab-7")) {
		t.Fatalf("项目范围应展开进 chain: %s", principal.Chain.Display())
	}
	if !principal.Chain.Includes(policy.MustScope(policy.ScopeOrganization, "medical-college")) {
		t.Fatalf("院系范围应展开进 chain: %s", principal.Chain.Display())
	}

	// 同一 claims 把数组顺序颠倒：结论必须逐字节相同（回放一致的前提）。
	shuffled := profile
	shuffled.Projects = []string{"proj-grant-2026", "proj-lab-7"}
	reversed := mustToken(t, authority, SignRequest{Profile: shuffled, At: baseNow})
	other := resolveOK(t, provider, oidcCredential(t, reversed))
	if other.Chain.Display() != principal.Chain.Display() {
		t.Fatalf("claims 数组顺序影响了范围集合:\n%s\n%s", principal.Chain.Display(), other.Chain.Display())
	}
	if other.Project != principal.Project {
		t.Fatalf("主项目必须取稳定代表值，实际 %q vs %q", principal.Project, other.Project)
	}
}

// ES256 与 RS256 都要能过：配置里两个算法都放开时，实际走的是两条不同的验签分支。
func TestOIDCSupportsBothRegisteredAlgorithms(t *testing.T) {
	authority := testAuthority(t)
	provider := newOIDC(t, authority, oidcOptions{})

	for _, algorithm := range []Alg{AlgRS256, AlgES256} {
		t.Run(string(algorithm), func(t *testing.T) {
			token := mustToken(t, authority, SignRequest{Profile: studentProfile(), At: baseNow, Algorithm: algorithm})
			principal := resolveOK(t, provider, oidcCredential(t, token))
			if principal.Identity.Subject != "uid-stu-1001" {
				t.Fatalf("%s 解析出的 subject 不符: %q", algorithm, principal.Identity.Subject)
			}
		})
	}
}

func TestOIDCPolicyContextCarriesOrganizationAndProject(t *testing.T) {
	authority := testAuthority(t)
	provider := newOIDC(t, authority, oidcOptions{})
	token := mustToken(t, authority, SignRequest{Profile: profileByFixture(t, "teacher-2001"), At: baseNow})
	principal := resolveOK(t, provider, oidcCredential(t, token))

	ctx, err := principal.PolicyContext("qa", policy.LevelInternal)
	if err != nil {
		t.Fatalf("构造策略上下文失败: %v", err)
	}
	if ctx.Purpose != "qa" || ctx.DataLevel != policy.LevelInternal {
		t.Fatalf("上下文字段不符: %+v", ctx)
	}
	if ctx.Organization != "university" || ctx.Project != "proj-curriculum" {
		t.Fatalf("主组织/主项目应带进上下文: %+v", ctx)
	}
	// B 不参与判定，也不猜区域与策略版本：那两个字段属于 D/H。
	if len(ctx.AllowedRegions) != 0 || ctx.PolicyVersion != "" {
		t.Fatalf("身份层不该填区域与策略版本: %+v", ctx)
	}
	if _, err := principal.PolicyContext("", policy.LevelInternal); err == nil {
		t.Fatal("空 purpose 必须失败（A 包 §2.2 要求必填）")
	}
}

// 签名不符：同一个 kid、另一把私钥签的 token 必须拒掉。
func TestOIDCRejectsSignatureMismatch(t *testing.T) {
	authority := testAuthority(t)
	audit := NewAuditRecorder(0)
	provider := newOIDC(t, authority, oidcOptions{audit: audit})

	token := mustToken(t, authority, SignRequest{Profile: studentProfile(), At: baseNow, SignWithForeign: true})
	err := resolveErr(t, provider, oidcCredential(t, token), ErrSignature)
	assertReason(t, err, ReasonSignatureInvalid)

	event, ok := audit.Last()
	if !ok || event.Outcome != OutcomeDenied || event.Reason != ReasonSignatureInvalid {
		t.Fatalf("签名失败必须记成 denied 而不是 error: %+v", event)
	}
	// 这条路径连 claims 都没解出来（未验签的 claims 不可信），只留凭证摘要。
	if strings.Contains(err.Error(), "uid-stu-1001") {
		t.Fatalf("签名失败的错误不得回显未受信 claims 内容: %v", err)
	}
	if event.Subject != "" {
		t.Fatalf("未验签时不该把 claims 里的值当 subject 记录: %+v", event)
	}
	if event.SubjectRef == "" {
		t.Fatal("至少要留下可关联的凭证摘要")
	}
}

// 篡改已签 token 的内容必须失败：换 payload、换签名段两条路都要拦住。
func TestOIDCRejectsTamperedTokens(t *testing.T) {
	authority := testAuthority(t)
	provider := newOIDC(t, authority, oidcOptions{})

	student := mustToken(t, authority, SignRequest{Profile: studentProfile(), At: baseNow})
	teacherClaims := profileByFixture(t, "teacher-2001").Claims(baseNow)
	teacherPayload := mustPayload(t, teacherClaims)

	studentParts := strings.Split(student, ".")
	if len(studentParts) != 3 {
		t.Fatal("token 必须是三段 compact JWS")
	}

	// 1) 保留别人的签名段、换上提权 payload：签名段与内容不再对应。
	swapped := studentParts[0] + "." + encodeSegment(teacherPayload) + "." + studentParts[2]
	err := resolveErr(t, provider, oidcCredential(t, swapped), ErrSignature)
	assertReason(t, err, ReasonSignatureInvalid)

	// 2) 保留 payload、把签名段改成等长的乱码。
	bogusSig := strings.Repeat("A", len(studentParts[2]))
	spliced := studentParts[0] + "." + studentParts[1] + "." + bogusSig
	resolveErr(t, provider, oidcCredential(t, spliced), ErrSignature)

	// 3) 空签名段（alg:none 形态）即使头里写了 RS256 也要拦住。
	emptySig := studentParts[0] + "." + studentParts[1] + "."
	resolveErr(t, provider, oidcCredential(t, emptySig), ErrTokenMalformed)
}

func mustPayload(t *testing.T, claims Claims) []byte {
	t.Helper()
	payload, err := claims.Payload()
	if err != nil {
		t.Fatalf("claims 序列化失败: %v", err)
	}
	return payload
}

// iss / aud 不匹配。
func TestOIDCRejectsWrongIssuerAndAudience(t *testing.T) {
	authority := testAuthority(t)
	provider := newOIDC(t, authority, oidcOptions{})

	wrongIssuer := mustToken(t, authority.WithIdentity("https://other.idp.invalid", FakeDefaultAudience),
		SignRequest{Profile: studentProfile(), At: baseNow})
	err := resolveErr(t, provider, oidcCredential(t, wrongIssuer), ErrIssuerMismatch)
	assertReason(t, err, ReasonIssuerMismatch)

	wrongAudience := mustToken(t, authority.WithIdentity(FakeDefaultIssuer, "another-client"),
		SignRequest{Profile: studentProfile(), At: baseNow})
	err = resolveErr(t, provider, oidcCredential(t, wrongAudience), ErrAudienceMismatch)
	assertReason(t, err, ReasonAudienceMismatch)

	// aud 含多值默认拒绝：那是签给别的 client 的 token 的典型形态。
	multi := Claims{
		Issuer:    FakeDefaultIssuer,
		Audience:  []string{FakeDefaultAudience, "other-client"},
		Subject:   "uid-stu-1001",
		Expiry:    baseNow.Add(time.Hour),
		IssuedAt:  baseNow,
		HasExpiry: true,
		Extra:     map[string]any{"roles": []any{"student"}},
	}
	multiToken := mustToken(t, authority, SignRequest{Claims: multi, At: baseNow})
	err = resolveErr(t, provider, oidcCredential(t, multiToken), ErrAudienceMismatch)
	assertReason(t, err, ReasonAudienceMismatch)

	// 显式允许多值 aud 后必须真的放行 —— 这条断言保证开关不是摆设。
	lenient, err := NewOIDCProvider(OIDCConfig{
		Source:             "campus-oidc",
		Issuer:             FakeDefaultIssuer,
		Audience:           FakeDefaultAudience,
		AllowMultiAudience: true,
	}, authority, WithClock(fixedClock(baseNow)))
	if err != nil {
		t.Fatal(err)
	}
	principal, err := lenient.Resolve(context.Background(), oidcCredential(t, multiToken))
	if err != nil {
		t.Fatalf("显式允许多值 aud 后应放行: %v", err)
	}
	if principal.Identity.Subject != "uid-stu-1001" {
		t.Fatalf("放行后身份不符: %+v", principal.Identity)
	}
}

// 时钟：exp 已过、nbf 未到、缺 exp、iat 在未来，四者给出可区分的错误。
func TestOIDCClockErrorsAreDistinguishable(t *testing.T) {
	authority := testAuthority(t)

	expired := studentProfile()
	expired.Lifetime = -time.Hour
	expiredToken := mustToken(t, authority, SignRequest{Profile: expired, At: baseNow})
	provider := newOIDC(t, authority, oidcOptions{strict: true})
	err := resolveErr(t, provider, oidcCredential(t, expiredToken), ErrExpired)
	assertReason(t, err, ReasonTokenExpired)

	notYet := studentProfile()
	claims := notYet.Claims(baseNow.Add(time.Hour))
	notYetToken := mustToken(t, authority, SignRequest{Claims: claims, At: claims.NotBefore})
	err = resolveErr(t, provider, oidcCredential(t, notYetToken), ErrNotYetValid)
	assertReason(t, err, ReasonNotYetValid)

	missingExpiry := studentProfile().Claims(baseNow)
	missingExpiry.HasExpiry = false
	missingExpiry.Expiry = time.Time{}
	missingToken := mustToken(t, authority, SignRequest{Claims: missingExpiry, At: baseNow})
	err = resolveErr(t, provider, oidcCredential(t, missingToken), ErrExpiryMissing)
	assertReason(t, err, ReasonExpiryMissing)
	if errors.Is(err, ErrExpired) {
		t.Fatal("缺 exp 与 exp 过期必须是两个不同的错误")
	}

	futureIssue := studentProfile().Claims(baseNow)
	futureIssue.IssuedAt = baseNow.Add(10 * time.Minute)
	futureToken := mustToken(t, authority, SignRequest{Claims: futureIssue, At: baseNow})
	err = resolveErr(t, provider, oidcCredential(t, futureToken), ErrIssuedInFuture)
	assertReason(t, err, ReasonIssuedInFuture)
}

// TTL 边界与偏移配置。
func TestOIDCExpiryBoundaryAndSkew(t *testing.T) {
	authority := testAuthority(t)
	profile := studentProfile()
	profile.Lifetime = time.Hour
	token := mustToken(t, authority, SignRequest{Profile: profile, At: baseNow})

	strict := newOIDC(t, authority, oidcOptions{clock: baseNow.Add(time.Hour), strict: true})
	err := resolveErr(t, strict, oidcCredential(t, token), ErrExpired)
	assertReason(t, err, ReasonTokenExpired)

	// now == exp 即失效（默认容忍度内的 1 秒前仍有效），比较口径只有一处定义。
	justBefore := newOIDC(t, authority, oidcOptions{clock: baseNow.Add(time.Hour - time.Second), strict: true})
	resolveOK(t, justBefore, oidcCredential(t, token))

	skewed := newOIDC(t, authority, oidcOptions{clock: baseNow.Add(time.Hour + 30*time.Minute), skew: 31 * time.Minute})
	resolveOK(t, skewed, oidcCredential(t, token))

	tooMuchSkew := newOIDC(t, authority, oidcOptions{clock: baseNow.Add(time.Hour + 31*time.Minute), skew: 31 * time.Minute})
	resolveErr(t, tooMuchSkew, oidcCredential(t, token), ErrExpired)

	// 默认容忍度是 60 秒：正好卡在过期点时默认配置应放行（NTP 抖动的现实妥协）。
	defaulted := newOIDC(t, authority, oidcOptions{clock: baseNow.Add(time.Hour)})
	resolveOK(t, defaulted, oidcCredential(t, token))
}

// 比 IdP 更严的生命周期上限。
func TestOIDCMaxLifetimeCap(t *testing.T) {
	authority := testAuthority(t)
	long := studentProfile()
	long.Lifetime = 24 * time.Hour
	token := mustToken(t, authority, SignRequest{Profile: long, At: baseNow})

	provider := newOIDC(t, authority, oidcOptions{maxLive: time.Hour})
	err := resolveErr(t, provider, oidcCredential(t, token), ErrLifetimeTooLong)
	assertReason(t, err, ReasonLifetimeExceeded)

	// 不配置就是 IdP 说了算（保持既有部署能跑）。
	open := newOIDC(t, authority, oidcOptions{})
	resolveOK(t, open, oidcCredential(t, token))
}

// subject 是邮箱形态：A 包会拒，B 必须在上游给出清晰错误而不是 panic。
func TestOIDCRejectsEmailShapedSubjectUpstream(t *testing.T) {
	authority := testAuthority(t)
	provider := newOIDC(t, authority, oidcOptions{})

	claims := studentProfile().Claims(baseNow)
	claims.Subject = "real.student@example.edu"
	claims.Extra["sub"] = claims.Subject
	token := mustToken(t, authority, SignRequest{Claims: claims, At: baseNow})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("上游必须给错误而不是 panic: %v", r)
		}
	}()
	err := resolveErr(t, provider, oidcCredential(t, token), ErrSubjectUnstable)
	assertReason(t, err, ReasonSubjectUnstable)
	if strings.Contains(err.Error(), "example.edu") {
		t.Fatalf("错误信息不得回显邮箱原文: %v", err)
	}
	if !strings.Contains(err.Error(), "sub") {
		t.Fatalf("错误必须指出是哪个 claim 出问题: %v", err)
	}
}

// 纯数字学号形态：默认拒绝（会随人事系统重建而失效），可显式放开。
func TestOIDCNumericSubjectIsRejectableButConfigurable(t *testing.T) {
	authority := testAuthority(t)
	strictProvider := newOIDC(t, authority, oidcOptions{})

	claims := studentProfile().Claims(baseNow)
	claims.Subject = "20210101234"
	claims.Extra["sub"] = claims.Subject
	token := mustToken(t, authority, SignRequest{Claims: claims, At: baseNow})
	err := resolveErr(t, strictProvider, oidcCredential(t, token), ErrSubjectUnstable)
	assertReason(t, err, ReasonSubjectUnstable)

	cfg := DefaultMapperConfig()
	cfg.AllowNumericSubject = true
	mapper, err := NewClaimMapper(cfg)
	if err != nil {
		t.Fatal(err)
	}
	lenient := newOIDC(t, authority, oidcOptions{mapper: mapper})
	principal := resolveOK(t, lenient, oidcCredential(t, token))
	if principal.Identity.Subject != "20210101234" {
		t.Fatalf("放开后应按 IdP 的 claim 使用: %q", principal.Identity.Subject)
	}
}

// 未知 claim 映射：映射表写的是 roles，但 token 给的是对象 → 明确拒绝而不是静默无角色。
func TestOIDCRejectsUnexpectedClaimShape(t *testing.T) {
	authority := testAuthority(t)
	provider := newOIDC(t, authority, oidcOptions{})

	claims := studentProfile().Claims(baseNow)
	claims.Extra["roles"] = map[string]any{"items": []any{"student"}}
	token := mustToken(t, authority, SignRequest{Claims: claims, At: baseNow})
	err := resolveErr(t, provider, oidcCredential(t, token), ErrClaimShape)
	assertReason(t, err, ReasonClaimShapeInvalid)

	// 数字数组同理：不会静默变成角色名。
	claims.Extra["roles"] = []any{jsonNumber(2001)}
	token = mustToken(t, authority, SignRequest{Claims: claims, At: baseNow})
	resolveErr(t, provider, oidcCredential(t, token), ErrClaimShape)
}

// 超大 claim 列表（DoS 面）。
func TestOIDCCapsOversizedClaimLists(t *testing.T) {
	authority := testAuthority(t)
	provider := newOIDC(t, authority, oidcOptions{})

	claims := studentProfile().Claims(baseNow)
	huge := make([]any, DefaultMaxValuesPerClaim+1)
	for i := range huge {
		huge[i] = "group-" + string(rune('a'+i%26))
	}
	claims.Extra["groups"] = huge
	token := mustToken(t, authority, SignRequest{Claims: claims, At: baseNow})
	err := resolveErr(t, provider, oidcCredential(t, token), ErrClaimOverflow)
	assertReason(t, err, ReasonClaimOverflow)
}

// 依赖失败：公钥来源不可用 → Outcome=error 而不是 denied。
func TestOIDCKeySourceFailureIsClassifiedAsError(t *testing.T) {
	authority := testAuthority(t)
	audit := NewAuditRecorder(0)
	failing := &StaticKeys{Err: errors.New("jwks 拉取失败")}
	provider := newOIDC(t, failing, oidcOptions{audit: audit})

	token := mustToken(t, authority, SignRequest{Profile: studentProfile(), At: baseNow})
	err := resolveErr(t, provider, oidcCredential(t, token), ErrKeySourceUnavailable)
	assertReason(t, err, ReasonKeyUnavailable)

	event, _ := audit.Last()
	if event.Outcome != OutcomeError {
		t.Fatalf("IdP 抖动不能记成 denied（会把故障误报成攻击）: %+v", event)
	}
	if event.Subject != "" {
		t.Fatalf("未验签路径不该有 subject: %+v", event)
	}
	if event.SubjectRef == "" {
		t.Fatal("必须有凭证摘要供关联")
	}
	// 具体失败原因不进审计事件。
	if strings.Contains(event.String(), "jwks 拉取失败") {
		t.Fatalf("审计不得带上游原文: %s", event)
	}
}

// 未知 kid 与缺 kid。
func TestOIDCRejectsUnknownOrMissingKid(t *testing.T) {
	authority := testAuthority(t)
	provider := newOIDC(t, authority, oidcOptions{})

	token := mustToken(t, authority, SignRequest{Profile: studentProfile(), At: baseNow, Kid: "rotated-away"})
	err := resolveErr(t, provider, oidcCredential(t, token), ErrKeyNotFound)
	assertReason(t, err, ReasonKeyMissing)

	noKid := mustToken(t, authority, SignRequest{Profile: studentProfile(), At: baseNow, OmitKid: true})
	resolveErr(t, provider, oidcCredential(t, noKid), ErrKeyNotFound)

	// 只有一把 key 且显式允许时才能回落。
	allKeys, err := authority.Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	single := &StaticKeys{Material: []JWK{allKeys[0]}} // 第 0 把是 RSA
	cfg := OIDCConfig{
		Source: "campus-oidc", Issuer: FakeDefaultIssuer, Audience: FakeDefaultAudience,
		AllowSingleKeyWithoutKid: true,
	}
	lenient, err := NewOIDCProvider(cfg, single, WithClock(fixedClock(baseNow)))
	if err != nil {
		t.Fatal(err)
	}
	good := mustToken(t, authority, SignRequest{Profile: studentProfile(), At: baseNow, OmitKid: true})
	resolveOK(t, lenient, oidcCredential(t, good))
}

// 凭证类型不匹配：OIDC 来源不能收 fake fixture。
func TestOIDCRejectsOtherCredentialKinds(t *testing.T) {
	provider := newOIDC(t, &StaticKeys{}, oidcOptions{})
	err := resolveErr(t, provider, FakeCredential("student-1001"), ErrCredentialKind)
	assertReason(t, err, ReasonCredentialInvalid)
}

// 构造期就把不完整的配置挡住。
func TestOIDCConfigValidation(t *testing.T) {
	authority := testAuthority(t)
	if _, err := NewOIDCProvider(OIDCConfig{Issuer: FakeDefaultIssuer}, authority); err == nil {
		t.Fatal("缺 audience 必须构造失败")
	}
	if _, err := NewOIDCProvider(OIDCConfig{Audience: FakeDefaultAudience}, authority); err == nil {
		t.Fatal("缺 issuer 必须构造失败")
	}
	if _, err := NewOIDCProvider(OIDCConfig{Issuer: FakeDefaultIssuer, Audience: FakeDefaultAudience}, nil); err == nil {
		t.Fatal("没有公钥来源必须构造失败（本包不自己出网）")
	}
	if _, err := NewOIDCProvider(OIDCConfig{
		Issuer: FakeDefaultIssuer, Audience: FakeDefaultAudience, Algorithms: []Alg{"HS256"},
	}, authority); err == nil {
		t.Fatal("对称算法不许进允许集合")
	}
}

// 取消的 context 必须由 KeySource 尊重，身份层不吞掉取消信号。
func TestOIDCHonorsContextCancellation(t *testing.T) {
	authority := testAuthority(t)
	token := mustToken(t, authority, SignRequest{Profile: studentProfile(), At: baseNow})
	provider := newOIDC(t, KeySourceFunc(func(ctx context.Context) ([]JWK, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}), oidcOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := provider.Resolve(ctx, oidcCredential(t, token))
	if err == nil {
		t.Fatal("已取消的 context 必须让解析失败")
	}
	if !errors.Is(err, ErrKeySourceUnavailable) {
		t.Fatalf("应归类为依赖不可用: %v", err)
	}
	if strings.Contains(err.Error(), "identity: 内部错误") {
		t.Fatalf("取消不该被归成内部错误: %v", err)
	}
}
