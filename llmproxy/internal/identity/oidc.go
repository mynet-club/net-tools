package identity

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// OIDCConfig 是一个 OIDC 来源的配置。
//
// 全部字段都是「接一所学校要改的东西」，没有一个是代码里可以猜的：
// issuer/audience 猜错等于接受别的签发方的 token；角色 claim 名猜错等于丢掉 deny 规则。
type OIDCConfig struct {
	// Source 写进 Identity.Source，必须是稳定标识（如 "campus-oidc"）：
	// conditions 里的 source 键按它精确匹配。
	Source string
	// Name 是审计里的 provider 实例名；留空按 "oidc"。同一机构接多个 IdP 时靠它区分。
	Name string
	// Issuer 期望的 iss，精确相等比较。
	Issuer string
	// Audience 期望的 aud（本服务的 client 标识）。
	Audience string
	// ExtraAudiences 允许同时接受的其它 client 标识。
	ExtraAudiences []string
	// AllowMultiAudience 允许 token 的 aud 含多个值。
	AllowMultiAudience bool
	// Algorithms 允许的签名算法；留空取 DefaultAlgorithms()。
	Algorithms []Alg
	// AllowedTypes 允许的 typ（大小写不敏感）；留空取 DefaultAllowedTypes。
	AllowedTypes []string
	// RequiredScopes 非空时校验 scope claim 必须包含这些项。
	RequiredScopes []string
	// MaxLifetime 限制 token 自签发起的可用时长；0 表示不额外收紧。
	// 留出这个口子是因为部分校内 IdP 把 token 签成 24 小时，泄露后可用窗口过长。
	MaxLifetime time.Duration
	// Mapper 是 claim → Identity/ScopeChain 的映射表；留空取默认映射。
	Mapper *ClaimMapper
	// AllowSingleKeyWithoutKid 允许「token 不带 kid 且来源只有一把 key」时继续验签。
	// 默认关闭，理由见 lookupKey。
	AllowSingleKeyWithoutKid bool
}

// OIDCProvider 解析并校验 OIDC 的 JWT（compact JWS，RS256/ES256）。
//
// 生命周期：构造后所有字段只读，可在多个 goroutine 之间长期复用
// （手册 §6 要求并发/重复调用测试）。公钥来源是注入的接口，本类型自己不发起网络连接。
type OIDCProvider struct {
	name     string
	source   string
	validate ValidateClaims
	header   headerPolicy
	mapper   *ClaimMapper
	keys     KeySource
	settings settings
}

// headerPolicy 是保护头层的校验参数。
// 它和 claims 层分开，是因为必须在验签**之前**判完 —— 见 Resolve 的顺序说明。
type headerPolicy struct {
	algorithms       []Alg
	allowedTypes     []string
	allowSingleNoKid bool
}

// NewOIDCProvider 构造来源。配置不完整时直接失败，不留到第一个登录请求。
//
// 构造期校验是刻意的：issuer/audience 漏配若等到运行期才发现，
// 表现是「谁都能登进来」—— 那是失败方向里最坏的一种。
func NewOIDCProvider(cfg OIDCConfig, keys KeySource, opts ...Option) (*OIDCProvider, error) {
	if keys == nil {
		return nil, fmt.Errorf("%w: OIDC 来源必须注入公钥来源（本包不自己出网）", ErrConfig)
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("%w: issuer 不能为空", ErrConfig)
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("%w: audience 不能为空", ErrConfig)
	}
	mapper := cfg.Mapper
	if mapper == nil {
		var err error
		mapper, err = DefaultClaimMapper()
		if err != nil {
			return nil, err
		}
	}
	algorithms := cfg.Algorithms
	if len(algorithms) == 0 {
		algorithms = DefaultAlgorithms()
	}
	for _, a := range algorithms {
		if !a.valid() {
			return nil, fmt.Errorf("%w: %q 不在支持的算法集合内", ErrConfig, string(a))
		}
	}
	s := newSettings(opts)
	name := cfg.Name
	if name == "" {
		name = "oidc"
	}
	return &OIDCProvider{
		name:   name,
		source: identitySource(cfg.Source, name),
		mapper: mapper,
		keys:   keys,
		validate: ValidateClaims{
			Issuer:             cfg.Issuer,
			Audience:           cfg.Audience,
			ExtraAudiences:     append([]string(nil), cfg.ExtraAudiences...),
			AllowMultiAudience: cfg.AllowMultiAudience,
			Skew:               s.skew,
			StrictClock:        s.strictClock,
			Now:                s.now,
			MaxLifetime:        cfg.MaxLifetime,
			RequiredScopes:     append([]string(nil), cfg.RequiredScopes...),
		},
		settings: s,
		header: headerPolicy{
			algorithms:       append([]Alg(nil), algorithms...),
			allowedTypes:     append([]string(nil), cfg.AllowedTypes...),
			allowSingleNoKid: cfg.AllowSingleKeyWithoutKid,
		},
	}, nil
}

// Name 实现 Provider。
func (p *OIDCProvider) Name() string { return p.name }

// Source 返回写进 Identity.Source 的来源标识。
func (p *OIDCProvider) Source() string { return p.source }

// Resolve 实现 Provider。
//
// 顺序固定为：拆包 → 判头 → 取 key → 验签 → 解 claims → 判时效 → 映射。
// 判头必须在验签前（alg 混淆攻击利用的正是「先按头里的算法走一遍」的实现），
// 验签必须在读 claims 前（未验签的 claims 一个字都不能信）。
// 调换这两步是本包最不能被「顺手重构」坏的地方：编译和单测都不会报错，
// 只有攻击者会报错。
func (p *OIDCProvider) Resolve(ctx context.Context, cred Credential) (Principal, error) {
	at := p.settings.nowTime()
	principal, hint, err := p.resolve(ctx, cred)
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
		// 连 claims 都没解出来时只能记凭证摘要：不知道「是谁」，
		// 但运维仍需要把同一凭证的多次失败串起来。
		event.SubjectRef = SubjectRef(cred.Value())
	}
	p.settings.record(event)
	return Principal{}, err
}

// resolve 做实际工作，并把「失败时已知的 subject 原值」带出去供审计脱敏。
func (p *OIDCProvider) resolve(ctx context.Context, cred Credential) (Principal, string, error) {
	if cred.Kind() != CredentialOIDCToken {
		return Principal{}, "", fmt.Errorf("%w: 本来源只接受 %q 凭证，实际是 %q",
			ErrCredentialKind, CredentialOIDCToken, cred.Kind())
	}
	if ctx == nil {
		ctx = context.Background()
	}
	jws, err := parseJWS(cred.Value())
	if err != nil {
		return Principal{}, "", err
	}
	if err := validateHeader(jws.Header, p.header.algorithms, p.header.allowedTypes); err != nil {
		return Principal{}, "", err
	}
	keys, err := p.fetchKeys(ctx)
	if err != nil {
		return Principal{}, "", err
	}
	key, err := lookupKey(keys, jws.Header.KeyID, p.header.allowSingleNoKid)
	if err != nil {
		return Principal{}, "", err
	}
	if err := key.Validate(); err != nil {
		return Principal{}, "", err
	}
	if err := verifyJWS(jws, key); err != nil {
		return Principal{}, "", err
	}
	claims, err := ParseClaims(jws.Payload)
	if err != nil {
		return Principal{}, "", err
	}
	hint := claims.Subject
	if err := p.validate.Validate(claims); err != nil {
		return Principal{}, hint, err
	}
	mapped, err := p.mapper.Map(claims, p.source)
	if err != nil {
		return Principal{}, hint, err
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
		return Principal{}, hint, err
	}
	return principal, hint, nil
}

// fetchKeys 从注入的来源取公钥。
//
// 来源返回的非哨兵错误一律归成 ErrKeySourceUnavailable：IdP 抖动的具体原因
// （DNS、TLS、对端 500）属于接线层的日志，顺着身份解析的错误链进审计结论只会污染原因码。
func (p *OIDCProvider) fetchKeys(ctx context.Context) ([]JWK, error) {
	keys, err := p.keys.Keys(ctx)
	if err != nil {
		if isKnownFailure(err) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrKeySourceUnavailable, plainDependencyReason(err))
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: 公钥集合为空", ErrKeySourceUnavailable)
	}
	return keys, nil
}

func isKnownFailure(err error) bool {
	return errors.Is(err, ErrKeySourceUnavailable) || errors.Is(err, ErrKeyMaterial) ||
		errors.Is(err, ErrConfig) || errors.Is(err, ErrInternal)
}

// plainDependencyReason 把第三方错误压成类别词。
//
// 不直接拼原文：某些实现对「未知 kid」会把请求 URL（含 tenant 路径）甚至 key 材料
// 写进 message，而这条 message 会跟着审计事件走。宁可丢掉细节，细节在接线层的日志里。
func plainDependencyReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	return "unavailable"
}

// 编译期断言：OIDCProvider 满足 Provider 契约。
var _ Provider = (*OIDCProvider)(nil)
