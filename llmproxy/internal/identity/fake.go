package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sort"
	"sync"
	"time"
)

// FakeProvider 是无需真实学校账号、无需联网即可跑完全部场景的身份来源。
//
// 为什么必须有它（手册 §3.B 的硬要求）：校内 IdP 的测试租户不外授，
// 生产 claims 含学生个人信息，两者都不能进 CI。
//
// 关键设计是它**不走另一套逻辑**：fixture 进的是与 OIDCProvider 完全相同的
// claims 校验 + 映射管线，所以「Fake 全绿」不会掩盖真实解析路径的缺陷。
// Fake 测不到验签，那部分由 FakeAuthority 现场签真 token 喂给 OIDCProvider 覆盖。
type FakeProvider struct {
	mu       sync.RWMutex
	fixtures map[string]Claims
	failures map[string]error

	source   string
	name     string
	validate ValidateClaims
	mapper   *ClaimMapper
	settings settings
}

// FakeOptions 配置 FakeProvider。
type FakeOptions struct {
	Source string
	Name   string
	// Issuer / Audience 用于 claims 校验；留空取 FakeDefaultIssuer / FakeDefaultAudience。
	Issuer      string
	Audience    string
	Skew        time.Duration
	StrictClock bool
	MaxLifetime time.Duration
	// Mapper 留空取默认映射（默认映射对内置的高校样例是够用的）。
	Mapper *ClaimMapper
	// Fixtures 是预置的 claims 集：键就是凭证内容（fixture 名）。
	Fixtures map[string]Claims
}

// Fake 内置样例的默认 issuer / audience。
//
// 用一眼假的字面量而不是真实域名（.invalid 是 RFC 2606 保留 TLD）：
// 真实域名一旦被复制进生产配置，等于给外部签发方开了口子。
const (
	FakeDefaultIssuer   = "https://fake.identity.invalid/issuer"
	FakeDefaultAudience = "llmproxy-fake-client"
)

// NewFakeProvider 构造可编程的假来源。opts 里的 WithClock/WithAudit 同样生效。
func NewFakeProvider(cfg FakeOptions, opts ...Option) (*FakeProvider, error) {
	mapper := cfg.Mapper
	if mapper == nil {
		var err error
		mapper, err = DefaultClaimMapper()
		if err != nil {
			return nil, err
		}
	}
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = FakeDefaultIssuer
	}
	audience := cfg.Audience
	if audience == "" {
		audience = FakeDefaultAudience
	}
	name := cfg.Name
	if name == "" {
		name = "fake"
	}
	s := newSettings(opts)
	if cfg.Skew != 0 {
		s.skew = cfg.Skew
	}
	if cfg.StrictClock {
		s.strictClock = true
		s.skew = 0
	}
	p := &FakeProvider{
		fixtures: make(map[string]Claims, len(cfg.Fixtures)),
		failures: make(map[string]error),
		source:   identitySource(cfg.Source, name),
		name:     name,
		mapper:   mapper,
		settings: s,
	}
	p.validate = ValidateClaims{
		Issuer:      issuer,
		Audience:    audience,
		Skew:        s.skew,
		StrictClock: s.strictClock,
		Now:         s.now,
		MaxLifetime: cfg.MaxLifetime,
	}
	for key, claims := range cfg.Fixtures {
		p.AddFixture(key, claims)
	}
	return p, nil
}

// NewFakeUniversityProvider 构造内置高校样例来源：学生、教师、PI、实验员、
// 跨院系交流生各一份 fixture，完全离线可用。
func NewFakeUniversityProvider(opts ...Option) (*FakeProvider, error) {
	p, err := NewFakeProvider(FakeOptions{Source: "campus-fake", Name: "fake-university"}, opts...)
	if err != nil {
		return nil, err
	}
	for _, profile := range UniversitySampleProfiles() {
		p.AddFixture(profile.FixtureName(), profile.Claims(time.Now().UTC()))
	}
	return p, nil
}

// Name 实现 Provider。
func (p *FakeProvider) Name() string { return p.name }

// Source 返回写进 Identity.Source 的标识。
func (p *FakeProvider) Source() string { return p.source }

// AddFixture 预置一份 claims。键即凭证内容（fixture 名），重复写入按覆盖处理。
//
// 存的是副本：调用方后续改自己那份 map 不该影响已注册的 fixture，
// 否则并发用例里会出现「没人改过但身份变了」这种无法复现的失败。
func (p *FakeProvider) AddFixture(name string, claims Claims) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fixtures[name] = claims.Clone()
}

// AddFailure 让某个凭证固定返回给定错误，用于测拒绝路径而不必构造畸形 token。
func (p *FakeProvider) AddFailure(name string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures[name] = err
}

// FixtureNames 返回已预置的凭证名（排序，便于测试断言）。
func (p *FakeProvider) FixtureNames() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, 0, len(p.fixtures))
	for k := range p.fixtures {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Resolve 实现 Provider：走与 OIDC 相同的校验与映射管线。
func (p *FakeProvider) Resolve(ctx context.Context, cred Credential) (Principal, error) {
	at := p.settings.nowTime()
	principal, hint, err := p.resolve(cred)
	if err == nil {
		p.settings.record(NewAuditEvent(principal, OutcomeSuccess, ReasonSuccess, at))
		return principal, nil
	}
	reason := ReasonFor(err)
	outcome := OutcomeDenied
	if isDependencyFailure(reason) {
		outcome = OutcomeError
	}
	event := NewFailureEvent(p.source, p.name, hint, outcome, reason, at, cred.RequestID())
	if event.Subject == "" && event.SubjectRef == "" {
		event.SubjectRef = SubjectRef(cred.Value())
	}
	p.settings.record(event)
	return Principal{}, err
}

func (p *FakeProvider) resolve(cred Credential) (Principal, string, error) {
	if cred.Kind() != CredentialFakeFixture {
		return Principal{}, "", fmt.Errorf("%w: 本来源只接受 %q 凭证，实际是 %q",
			ErrCredentialKind, CredentialFakeFixture, cred.Kind())
	}
	key := cred.Value()
	p.mu.RLock()
	failure, hasFailure := p.failures[key]
	claims, hasFixture := p.fixtures[key]
	p.mu.RUnlock()

	if hasFailure {
		if failure == nil {
			return Principal{}, "", fmt.Errorf("%w: fixture 被配置为失败但未给错误", ErrInternal)
		}
		return Principal{}, "", failure
	}
	if !hasFixture {
		return Principal{}, "", fmt.Errorf("%w: 请求了名为 %q 的 claims fixture 但未预置（请先 AddFixture）",
			ErrFixtureNotFound, key)
	}
	if err := p.validate.Validate(claims); err != nil {
		return Principal{}, claims.Subject, err
	}
	mapped, err := p.mapper.Map(claims, p.source)
	if err != nil {
		return Principal{}, claims.Subject, err
	}
	principal := Principal{
		Identity:     mapped.Identity,
		Chain:        mapped.Chain,
		Source:       p.source,
		Provider:     p.name,
		Organization: mapped.Organization,
		Project:      mapped.Project,
		ValidUntil:   mapped.Identity.ExpiresAt,
		RequestID:    cred.RequestID(),
	}
	if err := principal.Validate(); err != nil {
		return Principal{}, claims.Subject, err
	}
	return principal, "", nil
}

// FakeCredential 用 fixture 名造凭证，省掉调用方每次写 NewCredential。
//
// 这里允许 panic：fixture 名由调用方在同一进程里给定，为空只可能是编程错误，
// 而把它变成 error 会让每个测试用例都要处理一个永不为真的分支。
func FakeCredential(fixtureName string) Credential {
	if fixtureName == "" {
		panic("identity: FakeCredential 需要非空 fixture 名")
	}
	cred, err := NewCredential(CredentialFakeFixture, fixtureName)
	if err != nil {
		panic(fmt.Sprintf("identity: 非法 fixture 名（长度 %d）: %v", len(fixtureName), err))
	}
	return cred
}

// UniversityProfile 是一份高校样例的主体画像。
//
// 它存在的原因不是「凑测试数据」，而是把手册 §3.G 要的映射关系先落成可执行样例：
// role/group/project claim → Identity 字段 → ScopeChain。
// G 包写端到端场景时可以直接复用，不必再猜一遍字段名。
// 全部取值都是可识别为假的编码，不含任何真实个人信息。
type UniversityProfile struct {
	// Fixture 是凭证名（也是 FakeProvider 的键）；留空则用 Subject。
	Fixture string
	// Subject 必须是稳定 ID：样例一律用 uid- 前缀，不能是邮箱或纯数字学号形态。
	Subject      string
	DisplayName  string
	Organization string
	Department   string
	Roles        []string
	Groups       []string
	Projects     []string
	Courses      []string
	Lab          string
	// Lifetime 是 token 有效期；0 取 8 小时（校园一节课的长度），负数表示「签一个已过期的 token」。
	Lifetime time.Duration
	// AuthMethods 对应 amr claim。
	AuthMethods []string
	// Email / Phone 是**故意放进去**的个人信息字段，
	// 专门用来断言它们不会出现在 Principal、审计事件与错误信息里。
	// 永远不要在这里填真实值（样例一律用 .invalid 保留域）。
	Email string
	Phone string
}

// FixtureName 返回凭证名。
func (u UniversityProfile) FixtureName() string {
	if u.Fixture != "" {
		return u.Fixture
	}
	return u.Subject
}

// Claims 按画像生成 claims。at 是签发时刻。
//
// 注意：画像不填 issuer/audience 之外的签发身份 —— 那两项由 FakeAuthority 覆盖
// （见 Sign），否则 WithIdentity 换签发方时画像里的硬编码默认值会赢，
// 「iss 不符」这类负例就会假通过。
func (u UniversityProfile) Claims(at time.Time) Claims {
	lifetime := u.Lifetime
	if lifetime == 0 {
		lifetime = 8 * time.Hour // 校园一节课的长度
	}
	// 故意传负数 Lifetime 是「签一个已经过期的 token」，这是造过期负例的正常用法，
	// 不能当成「没填」而被默认值吃掉。
	iat := at.UTC().Truncate(time.Second)
	exp := iat.Add(lifetime)
	extra := map[string]any{
		"name":         u.DisplayName,
		"roles":        toAnySlice(u.Roles),
		"groups":       toAnySlice(u.Groups),
		"projects":     toAnySlice(u.Projects),
		"course":       toAnySlice(u.Courses),
		"lab":          u.Lab,
		"amr":          toAnySlice(u.AuthMethods),
		"scope":        "openid profile",
		"organization": u.Organization,
		"department":   u.Department,
		// 刻意放入的 PII，只为泄露断言存在。
		"email": u.Email,
		"phone": u.Phone,
	}
	return Claims{
		Issuer:    FakeDefaultIssuer,
		Audience:  []string{FakeDefaultAudience},
		Subject:   u.Subject,
		Expiry:    exp,
		IssuedAt:  iat,
		NotBefore: iat,
		HasExpiry: true,
		JWTID:     fmt.Sprintf("fake-jti-%s-%d", u.Subject, iat.Unix()),
		Extra:     extra,
	}
}

// UniversitySampleProfiles 返回内置的高校样例画像集合。
//
// 覆盖面按「策略会怎么区分他们」挑：学生（低权限）、教师（可用校内模型）、
// PI（带科研项目）、实验员（受限数据）、跨机构交流生（多组织范围）。
// 每个样例都够写一条 allow 和一条 deny 的用例，不需要再补真实账号。
func UniversitySampleProfiles() []UniversityProfile {
	return []UniversityProfile{
		{
			Fixture: "student-1001", Subject: "uid-stu-1001", DisplayName: "Sample Student",
			Organization: "university", Department: "cs-college",
			Roles: []string{"student"}, Groups: []string{"undergraduate", "cs-college"},
			Courses: []string{"cs-101", "math-201"}, AuthMethods: []string{"pwd", "otp"},
			Email: "sample.student@example.invalid", Phone: "13800000000",
		},
		{
			Fixture: "teacher-2001", Subject: "uid-tea-2001", DisplayName: "Sample Teacher",
			Organization: "university", Department: "cs-college",
			Roles: []string{"teacher", "course-staff"}, Groups: []string{"faculty", "cs-college"},
			Courses: []string{"cs-305"}, Projects: []string{"proj-curriculum"},
			AuthMethods: []string{"pwd", "totp"},
			Email:       "sample.teacher@example.invalid",
		},
		{
			Fixture: "pi-3001", Subject: "uid-pi-3001", DisplayName: "Sample PI",
			Organization: "university", Department: "medical-college",
			Roles: []string{"teacher", "project-lead"}, Groups: []string{"faculty"},
			Projects: []string{"proj-lab-7", "proj-grant-2026"}, Lab: "lab-7",
			AuthMethods: []string{"pwd", "totp"},
		},
		{
			Fixture: "lab-admin-4001", Subject: "uid-lab-4001", DisplayName: "Sample Lab Admin",
			Organization: "university", Department: "physics-college",
			Roles: []string{"lab-admin"}, Groups: []string{"staff", "physics-lab"},
			Projects: []string{"proj-instrument"}, Lab: "lab-12",
			AuthMethods: []string{"cert"},
		},
		{
			Fixture: "exchange-5001", Subject: "uid-exg-5001", DisplayName: "Sample Exchange Student",
			Organization: "partner-institute", Department: "ee-college",
			Roles:       []string{"student", "exchange"},
			Groups:      []string{"exchange", "university-guest"},
			Courses:     []string{"cs-101"},
			AuthMethods: []string{"pwd"},
		},
	}
}

func toAnySlice(in []string) []any {
	if len(in) == 0 {
		return nil
	}
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

// FakeAuthority 是内存里的签发方：现场生成密钥、现场签真的 compact JWS。
//
// 有了它，OIDCProvider 的验签与 claims 分支就能在「不联网、不需要学校账号、
// 不提交任何密钥材料」的前提下全部跑通 —— 这是手册 §8 第 8 条
// （另一个 agent 能独立复现测试）的前提。生产路径不会用到它：私钥只在内存里生成。
type FakeAuthority struct {
	rsaKey   *rsa.PrivateKey
	ecKey    *ecdsa.PrivateKey
	foreign  *rsa.PrivateKey
	rsaKID   string
	ecKID    string
	issuer   string
	audience string
}

// NewFakeAuthority 生成一次性测试密钥（RSA 2048 + P-256）。
func NewFakeAuthority() (*FakeAuthority, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("%w: 生成测试 RSA 密钥失败", ErrInternal)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: 生成测试 EC 密钥失败", ErrInternal)
	}
	foreign, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("%w: 生成测试外部密钥失败", ErrInternal)
	}
	return &FakeAuthority{
		rsaKey:   rsaKey,
		ecKey:    ecKey,
		foreign:  foreign,
		rsaKID:   "fake-rsa-key",
		ecKID:    "fake-ec-key",
		issuer:   FakeDefaultIssuer,
		audience: FakeDefaultAudience,
	}, nil
}

// WithIdentity 覆盖签发参数（issuer/audience），返回自身便于链式使用。
func (a *FakeAuthority) WithIdentity(issuer, audience string) *FakeAuthority {
	if issuer != "" {
		a.issuer = issuer
	}
	if audience != "" {
		a.audience = audience
	}
	return a
}

// Issuer / Audience 暴露签发参数，方便配置对应的 Provider。
func (a *FakeAuthority) Issuer() string   { return a.issuer }
func (a *FakeAuthority) Audience() string { return a.audience }

// Keys 实现 KeySource：只返回公钥（不出网，也不含私钥）。
func (a *FakeAuthority) Keys(_ context.Context) ([]JWK, error) {
	return []JWK{
		{KeyID: a.rsaKID, Algorithm: AlgRS256, Public: &a.rsaKey.PublicKey},
		{KeyID: a.ecKID, Algorithm: AlgES256, Public: &a.ecKey.PublicKey},
	}, nil
}

// RSAKeyID / ECKeyID 暴露 kid，供测试构造「未知 kid」这类负例。
func (a *FakeAuthority) RSAKeyID() string { return a.rsaKID }
func (a *FakeAuthority) ECKeyID() string  { return a.ecKID }

// SignRequest 描述一次签名请求。
type SignRequest struct {
	// Profile 与 Claims 二选一：给了 Claims 就用它，否则从 Profile 现场生成。
	Profile UniversityProfile
	Claims  Claims
	// Algorithm 默认 RS256；Type 默认 "JWT"；At 默认当前 UTC 秒。
	Algorithm Alg
	Type      string
	At        time.Time
	// Kid 覆盖保护头的 kid（写一个来源里没有的值就能测「未知 kid」）。
	Kid string
	// OmitKid 为真时保护头不写 kid。
	OmitKid bool
	// SignWithForeign 用来源外的私钥签名：验签必然失败，是「签名不符」的最小复现。
	SignWithForeign bool
	// HeaderExtras 覆盖/追加保护头字段，目前支持 "typ" 与 "crit"。
	HeaderExtras map[string]any
	// RawPayload 直接指定 payload 字节，用于测畸形 claims。
	RawPayload []byte
}

// Sign 造出一个真实可验签（或刻意不可验签）的 compact JWS。
func (a *FakeAuthority) Sign(req SignRequest) (string, error) {
	at := req.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	claims := req.Claims
	if claims.Extra == nil {
		if req.Profile.Subject != "" {
			claims = req.Profile.Claims(at)
			// 画像只描述「这个人是谁」，issuer/audience 属于签发方：
			// 以 FakeAuthority 为准覆盖，否则 WithIdentity 换签发方不生效，
			// 「iss/aud 不符」的负例就会假通过。
			claims.Issuer = a.issuer
			claims.Audience = []string{a.audience}
		} else {
			return "", fmt.Errorf("%w: SignRequest 既没有 Claims 也没有 Profile", ErrConfig)
		}
	} else {
		claims = claims.Clone()
	}
	if claims.Issuer == "" {
		claims.Issuer = a.issuer
	}
	if len(claims.Audience) == 0 {
		claims.Audience = []string{a.audience}
	}
	payload := req.RawPayload
	if payload == nil {
		var err error
		payload, err = claims.Payload()
		if err != nil {
			return "", err
		}
	}
	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = AlgRS256
	}
	headerType := req.Type
	if headerType == "" {
		headerType = "JWT"
	}
	kid := req.Kid
	if kid == "" && !req.OmitKid {
		if algorithm == AlgES256 {
			kid = a.ecKID
		} else {
			kid = a.rsaKID
		}
	}
	header := JWSHeader{Algorithm: algorithm, Type: headerType, KeyID: kid}
	for key, value := range req.HeaderExtras {
		if err := applyHeaderExtra(&header, key, value); err != nil {
			return "", err
		}
	}
	var signer any
	switch algorithm {
	case AlgES256:
		if req.SignWithForeign {
			signer = a.foreign
		} else {
			signer = a.ecKey
		}
	default:
		if req.SignWithForeign {
			// 用来源外的 RSA 私钥签，kid 仍写本来源的 key：
			// 「找对了 key 但签名对不上」这条路径必须单独覆盖。
			signer = a.foreign
		} else {
			signer = a.rsaKey
		}
	}
	if req.SignWithForeign && algorithm == AlgES256 {
		// 外部密钥是 RSA，不能拿去按 ES256 签；这种组合是配置错误。
		return "", fmt.Errorf("%w: SignWithForeign 目前只提供 RSA 密钥，请配 RS256", ErrConfig)
	}
	return SignJWS(signer, header, payload)
}

// SignUniversityToken 是「画像 → 真 token」的快捷方式，给端到端样例用。
func (a *FakeAuthority) SignUniversityToken(profile UniversityProfile, at time.Time) (string, error) {
	return a.Sign(SignRequest{Profile: profile, At: at})
}

// applyHeaderExtra 支持覆盖 typ 与追加 crit。
//
// 未支持的键给出明确错误而不是静默忽略：静默忽略会让测试以为自己在测某个分支，
// 实际跑的是另一条 —— 假绿的测试比没有测试更糟。
func applyHeaderExtra(header *JWSHeader, key string, value any) error {
	switch key {
	case "crit":
		items, ok := value.([]any)
		if !ok {
			return fmt.Errorf("%w: crit 需要数组", ErrConfig)
		}
		for _, item := range items {
			s, isStr := item.(string)
			if !isStr {
				return fmt.Errorf("%w: crit 项必须是字符串", ErrConfig)
			}
			header.Critical = append(header.Critical, s)
		}
		return nil
	case "typ":
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("%w: typ 必须是字符串", ErrConfig)
		}
		header.Type = s
		return nil
	case "kid":
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("%w: kid 必须是字符串", ErrConfig)
		}
		header.KeyID = s
		return nil
	default:
		return fmt.Errorf("%w: 暂不支持覆盖保护头字段 %q", ErrConfig, key)
	}
}

// 编译期断言：FakeProvider 与 FakeAuthority 满足各自接口。
var (
	_ Provider  = (*FakeProvider)(nil)
	_ KeySource = (*FakeAuthority)(nil)
)
