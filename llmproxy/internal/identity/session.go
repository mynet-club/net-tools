package identity

// 本文件是 LDAP 登录后的**网关会话令牌**：目录只认证一次，之后的请求带这枚
// 短时 token，而不是每次都把目录口令带上来。
//
// 为什么不用 OIDC 那套 JWS：JWS 只允许非对称算法，而这里没有外部 IdP 分发的
// 公钥；验签方和签发方都是同一个网关进程。用本地派生的 HMAC 子密钥签一枚
// 自包含令牌，既不需要新增密钥文件，也不会把「对称密钥当公钥分发」那条路
// 打开（令牌从不离开网关与客户端之间的这条链路，且带 exp）。
//
// 令牌格式：`v1.<base64url(payload)>.<base64url(hmac-sha256)>`。
// 显式版本前缀让将来换算法时旧令牌直接失效，而不是靠解出来的字段猜。

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

const (
	sessionTokenVersion  = "v1"
	maxSessionTokenBytes = 16 * 1024
	// maxSessionTTL 是签发侧与服务端的共同上限。目录身份不能拿一个「一年有效」
	// 的令牌把「被禁用账号要及时失效」这条约束废掉。
	maxSessionTTL = 24 * time.Hour
)

type sessionScope struct {
	Kind string `json:"k"`
	ID   string `json:"i"`
}

type sessionClaims struct {
	Subject      string         `json:"sub"`
	DisplayName  string         `json:"name,omitempty"`
	Roles        []string       `json:"roles,omitempty"`
	Groups       []string       `json:"groups,omitempty"`
	Organization string         `json:"org,omitempty"`
	Project      string         `json:"project,omitempty"`
	Chain        []sessionScope `json:"chain"`
	Source       string         `json:"src"`
	Provider     string         `json:"prov"`
	IssuedAt     int64          `json:"iat"`
	ExpiresAt    int64          `json:"exp"`
}

// SessionCodec 同时是签发器与 Provider：LDAP 登录端点用它签发，请求路径用它验开。
// 两边共用一份密钥与 TTL 口径，避免「签出来的 token 自己验不过」。
type SessionCodec struct {
	key      []byte
	source   string
	provider string
	maxTTL   time.Duration
	settings settings
}

// NewSessionCodec 构造 LDAP 会话令牌编解码器。key 必须至少 32 字节（调用方从主密钥派生）。
func NewSessionCodec(key []byte, source string, maxTTL time.Duration, opts ...Option) (*SessionCodec, error) {
	return NewSessionCodecWithProvider(key, source, "ldap-session", maxTTL, opts...)
}

// NewSessionCodecWithProvider 允许换一个 provider 标签（本地账密 / OAuth 的网关会话
// 与 LDAP 会话不是同一个签发方；标签不同，令牌互相验不过）。
func NewSessionCodecWithProvider(key []byte, source, provider string, maxTTL time.Duration, opts ...Option) (*SessionCodec, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("%w: 会话密钥至少 32 字节", ErrConfig)
	}
	if strings.TrimSpace(source) == "" {
		return nil, fmt.Errorf("%w: 会话令牌缺少 source", ErrConfig)
	}
	if strings.TrimSpace(provider) == "" {
		return nil, fmt.Errorf("%w: 会话令牌缺少 provider", ErrConfig)
	}
	if maxTTL <= 0 || maxTTL > maxSessionTTL {
		return nil, fmt.Errorf("%w: 会话 TTL %v 必须在 (0, %v] 内", ErrConfig, maxTTL, maxSessionTTL)
	}
	return &SessionCodec{
		key:      append([]byte(nil), key...),
		source:   source,
		provider: provider,
		maxTTL:   maxTTL,
		settings: newSettings(opts),
	}, nil
}

func (c *SessionCodec) Name() string { return c.provider }

// Issue 为一次成功的目录绑定签发短时令牌。
func (c *SessionCodec) Issue(p Principal, ttl time.Duration) (string, time.Time, error) {
	if err := p.Validate(); err != nil {
		return "", time.Time{}, err
	}
	if ttl <= 0 || ttl > c.maxTTL {
		return "", time.Time{}, fmt.Errorf("%w: 会话 TTL %v 必须在 (0, %v] 内", ErrConfig, ttl, c.maxTTL)
	}
	now := c.settings.nowTime()
	exp := now.Add(ttl)
	claims := sessionClaims{
		Subject:      p.Identity.Subject,
		DisplayName:  p.Identity.DisplayName,
		Roles:        append([]string(nil), p.Identity.Roles...),
		Groups:       append([]string(nil), p.Identity.Groups...),
		Organization: p.Organization,
		Project:      p.Project,
		Chain:        make([]sessionScope, 0, len(p.Chain)),
		Source:       p.Source,
		// Provider 记签发者（ldap-session），不是上游目录实现名（ldap）：
		// 验签时比的是「这枚 token 由谁签的」，与身份来源是两件事。
		Provider:  c.provider,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
	}
	for _, s := range p.Chain {
		claims.Chain = append(claims.Chain, sessionScope{Kind: string(s.Kind), ID: s.ID})
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("%w: 会话 claims 编码失败", ErrInternal)
	}
	signingInput := sessionTokenVersion + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(c.sign(signingInput)), exp, nil
}

// Resolve 实现 Provider：验签、校验时效与来源，并把 claims 还原成 Principal。
func (c *SessionCodec) Resolve(_ context.Context, cred Credential) (Principal, error) {
	if cred.Kind() != CredentialSessionToken {
		err := fmt.Errorf("%w: 本来源只接受 %q 凭证，实际是 %q",
			ErrCredentialKind, CredentialSessionToken, cred.Kind())
		c.recordFailure("", ReasonCredentialInvalid, cred.RequestID())
		return Principal{}, err
	}
	claims, err := c.parse(cred.Value())
	if err != nil {
		c.recordFailure("", ReasonFor(err), cred.RequestID())
		return Principal{}, err
	}
	now := c.settings.nowTime()
	if now.After(time.Unix(claims.ExpiresAt, 0).Add(c.settings.skew)) {
		err := fmt.Errorf("%w: 会话令牌已过期", ErrExpired)
		c.recordFailure(claims.Subject, ReasonTokenExpired, cred.RequestID())
		return Principal{}, err
	}
	if time.Unix(claims.IssuedAt, 0).After(now.Add(c.settings.skew)) {
		err := fmt.Errorf("%w: 会话令牌签发时间晚于当前时间", ErrIssuedInFuture)
		c.recordFailure(claims.Subject, ReasonIssuedInFuture, cred.RequestID())
		return Principal{}, err
	}
	if claims.Source != c.source || claims.Provider != c.provider {
		err := fmt.Errorf("%w: 会话令牌来源与本网关注册的来源不符", ErrIssuerMismatch)
		c.recordFailure(claims.Subject, ReasonIssuerMismatch, cred.RequestID())
		return Principal{}, err
	}

	chain := make(policy.ScopeChain, 0, len(claims.Chain))
	for _, s := range claims.Chain {
		ref, refErr := policy.NewScopeRef(policy.ScopeKind(s.Kind), s.ID)
		if refErr != nil {
			err := fmt.Errorf("%w: 会话令牌里的范围不合法", ErrScopeUnmapped)
			c.recordFailure(claims.Subject, ReasonScopeUnmapped, cred.RequestID())
			return Principal{}, err
		}
		chain = append(chain, ref)
	}
	chain, err = policy.NewScopeChain(chain...)
	if err != nil {
		c.recordFailure(claims.Subject, ReasonScopeUnmapped, cred.RequestID())
		return Principal{}, fmt.Errorf("%w: 会话令牌的范围集合不合法", ErrScopeUnmapped)
	}
	id := policy.Identity{
		Subject:     claims.Subject,
		Source:      claims.Source,
		DisplayName: claims.DisplayName,
		Roles:       append([]string(nil), claims.Roles...),
		Groups:      append([]string(nil), claims.Groups...),
		AuthMethods: []string{"ldap"},
		IssuedAt:    time.Unix(claims.IssuedAt, 0),
		ExpiresAt:   time.Unix(claims.ExpiresAt, 0),
	}
	id = id.Normalize()
	p := Principal{
		Identity:     id,
		Chain:        chain,
		Source:       claims.Source,
		Provider:     claims.Provider,
		Organization: claims.Organization,
		Project:      claims.Project,
		ValidUntil:   id.ExpiresAt,
		RequestID:    cred.RequestID(),
	}
	if err := p.Validate(); err != nil {
		c.recordFailure(claims.Subject, ReasonFor(err), cred.RequestID())
		return Principal{}, err
	}
	c.settings.record(NewAuditEvent(p, OutcomeSuccess, ReasonSuccess, c.settings.nowTime()))
	return p, nil
}

func (c *SessionCodec) parse(value string) (sessionClaims, error) {
	if len(value) > maxSessionTokenBytes {
		return sessionClaims{}, fmt.Errorf("%w: 会话令牌超过 %d 字节", ErrCredentialTooLarge, maxSessionTokenBytes)
	}
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) != 3 || parts[0] != sessionTokenVersion {
		return sessionClaims{}, fmt.Errorf("%w: 会话令牌格式不合法", ErrTokenMalformed)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return sessionClaims{}, fmt.Errorf("%w: 会话令牌 payload 不是 base64url", ErrTokenMalformed)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) == 0 {
		return sessionClaims{}, fmt.Errorf("%w: 会话令牌签名段不合法", ErrTokenMalformed)
	}
	want := c.sign(parts[0] + "." + parts[1])
	if !hmac.Equal(sig, want) {
		return sessionClaims{}, fmt.Errorf("%w: 会话令牌签名校验失败", ErrSignature)
	}
	var claims sessionClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return sessionClaims{}, fmt.Errorf("%w: 会话令牌 payload 不是 JSON", ErrTokenMalformed)
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return sessionClaims{}, fmt.Errorf("%w: 会话令牌缺少 subject", ErrSubjectMissing)
	}
	if claims.ExpiresAt <= 0 {
		return sessionClaims{}, fmt.Errorf("%w: 会话令牌缺少 exp", ErrExpiryMissing)
	}
	return claims, nil
}

func (c *SessionCodec) sign(input string) []byte {
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write([]byte(input))
	return mac.Sum(nil)
}

func (c *SessionCodec) recordFailure(subject string, reason ReasonCode, requestID string) {
	outcome := OutcomeDenied
	if isDependencyFailure(reason) {
		outcome = OutcomeError
	}
	event := NewFailureEvent(c.source, c.provider, subject, outcome, reason, c.settings.nowTime(), requestID)
	c.settings.record(event)
}
