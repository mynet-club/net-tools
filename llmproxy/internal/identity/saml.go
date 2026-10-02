package identity

import (
	"context"
	"fmt"
	"time"
)

// SAMLProvider 是 SAML 2.0 Web SSO 的身份来源抽象。
//
// 为什么只给接口不给实现：SAML 的签名走 XML-DSig（信封签名 + Reference Digest），
// 需要 XML 规范化（C14N）实现，标准库没有；手写 C14N 属于「错了也不会报错」的高风险代码，
// 应由主线单独评审后专门做，而不是在这个工作包里顺手糊一段。
// 本包用 ErrNotImplemented 明确表态（手册 §7：未实现部分必须用 stub，不许伪装完成）。
type SAMLProvider interface {
	// ParseResponse 校验 Response/Assertion 的签名与条件，产出主体上下文。
	// encoded 是 SAMLResponse 的 Base64 原文；trust 是签发方配置（实体 ID + 证书）。
	ParseResponse(ctx context.Context, encoded string, trust SAMLTrust) (Principal, error)
}

// SAMLTrust 是一个受信任 SAML 签发方的配置。
//
// 这些字段现在是「接口先占位」，实现时每个都要真正参与校验，缺一个就是可绕过的洞。
// 特别是 AudienceRestriction：SAML 断言默认只对指定受众有效，
// 不校验它等于允许把别的 SP 收到的断言拿到这里重放。
type SAMLTrust struct {
	// EntityID 是 IdP 的实体 ID（对应 AssertionIssuer），与 OIDC 的 iss 同位。
	EntityID string
	// ACSAudience 是本服务（SP）的受众名，对应 Conditions/AudienceRestriction。
	ACSAudience string
	// CertificatePEM 是验证信封签名的 IdP 证书（PEM，只含公钥证书）。
	// 实现必须校验它与所述 key 一致，不能只看「签名能过」——
	// 签名过只说明有人签了，不说明是我们信任的那把 key 签的。
	CertificatePEM []byte
	// ClockSkew 容忍的时钟偏移，语义同 OIDC；0 取 DefaultClockSkew。
	ClockSkew time.Duration
	// MaxAssertionLifetime 限制 NotOnOrAfter 相对 IssuedAt 的距离；0 表示不收紧。
	MaxAssertionLifetime time.Duration
	// Mapper 是 SAML 属性 → Identity/ScopeChain 的映射表。
	Mapper *ClaimMapper
	// RequireSignedAssertions 要求断言本身带签名（只签 Response 信封不够：
	// 部分部署会把未签断言的 Response 放进中间层缓存，内容可被替换）。
	RequireSignedAssertions bool
}

// UnconfiguredSAMLProvider 是 SAML 的占位实现（stub）。
//
// 它的价值在于「现在就能接线」：server 侧可以把 SAML 通路注册进配置、
// 读入证书与映射表，等解析器落地时只换实现不动调用点。
// 任何调用都明确失败，不会退化成「假装成功但身份是空的」。
type UnconfiguredSAMLProvider struct {
	trust    SAMLTrust
	source   string
	provider string
	settings settings
}

// NewUnconfiguredSAMLProvider 构造占位实现。
//
// 配置在这里就校验：写错配置在启动期暴露，比等到真去接 SAML 那天才发现好。
func NewUnconfiguredSAMLProvider(trust SAMLTrust, source string, opts ...Option) (*UnconfiguredSAMLProvider, error) {
	if trust.EntityID == "" {
		return nil, fmt.Errorf("%w: SAML 需要配置 IdP 的 entityID", ErrConfig)
	}
	if trust.ACSAudience == "" {
		return nil, fmt.Errorf("%w: SAML 需要配置 SP 受众名（AudienceRestriction）", ErrConfig)
	}
	if len(trust.CertificatePEM) == 0 {
		return nil, fmt.Errorf("%w: SAML 需要配置 IdP 签名证书", ErrConfig)
	}
	if source == "" {
		source = "saml"
	}
	return &UnconfiguredSAMLProvider{
		trust:    trust,
		source:   source,
		provider: "saml",
		settings: newSettings(opts),
	}, nil
}

// Name 实现 Provider。
func (p *UnconfiguredSAMLProvider) Name() string { return p.provider }

// Trust 返回已校验的签发方配置，供实现替换时复用同一份配置。
func (p *UnconfiguredSAMLProvider) Trust() SAMLTrust { return p.trust }

// Resolve 实现 Provider：拒绝 SAML 凭证并给出「通路未实现」的明确结论。
//
// 刻意不返回一个「空身份」让下游继续跑：那会让审计里出现一条没有主体
// 却走完全链路的记录，比直接失败危险得多。
func (p *UnconfiguredSAMLProvider) Resolve(_ context.Context, cred Credential) (Principal, error) {
	p.settings.record(NewFailureEvent(p.source, p.provider, "", OutcomeError, ReasonNotImplemented,
		p.settings.nowTime(), cred.RequestID()))
	return Principal{}, fmt.Errorf("%w: SAML 断言解析（XML-DSig 验签 + 属性映射）尚未实现，映射点见 SAMLMappingPlan()", ErrNotImplemented)
}

// ParseResponse 实现 SAMLProvider，同样只返回未实现。
func (p *UnconfiguredSAMLProvider) ParseResponse(_ context.Context, _ string, trust SAMLTrust) (Principal, error) {
	if trust.EntityID == "" || trust.ACSAudience == "" {
		return Principal{}, fmt.Errorf("%w: SAML 需要 entityID 与 SP 受众名", ErrConfig)
	}
	return Principal{}, fmt.Errorf("%w: SAML 断言解析尚未实现", ErrNotImplemented)
}

// samlMappingPlan 是未来实现的映射点清单。
//
// 把它写成代码里的常量而不是交付说明里的一段话，是因为交付说明会被折叠、
// 而接线的人一定会先读接口 —— 手册 §7 要求「未实现部分必须明确」。
var samlMappingPlan = []string{
	"NameID(Format=persistent) → Identity.Subject；绝不用 EmailAddress 形态当主键（邮箱一改，历史授权与用量就断链，且 policy §2.1 会在下游拒掉）",
	"eduPersonPrincipalName → DisplayName 候选，不参与 Subject 候选",
	"eduPersonScopedAffiliation(faculty/student/employee/affiliate) → Identity.Roles",
	"eduPersonEntitlement 中的院系 URN → organization/department 范围（层级由适配层展开，policy 不猜）",
	"universityOid / eduPersonOrgDN → organization 根范围",
	"Conditions/NotOnOrAfter → Identity.ExpiresAt；缺 NotOnOrAfter 必须拒绝（SAML 允许无时效断言，而带 roles 的身份必须有过期时间）",
	"SubjectConfirmationData/NotOnOrAfter 与 AuthnStatement/SessionNotOnOrAfter 取较早值作为 TTL 上限",
	"AuthnContextClassRef(password/two-factor/OTP) → Identity.AuthMethods",
	"属性 email / mobile / telephoneNumber 一律不进 Principal、不进审计（同 OIDC）",
	"OneTimeUse + 断言重放缓存由实现方负责（本包不出网不落库），缓存键用断言 ID 的摘要而非原文",
}

// SAMLMappingPlan 返回未实现部分的映射点，供接线方评估工作量。
func SAMLMappingPlan() []string { return append([]string(nil), samlMappingPlan...) }

// 编译期断言：stub 同时满足 Provider 与 SAMLProvider。
var (
	_ Provider     = (*UnconfiguredSAMLProvider)(nil)
	_ SAMLProvider = (*UnconfiguredSAMLProvider)(nil)
)
