package config

// 登录方式与 OAuth 客户端（P1）。
//
// 口径：
//   - methods 的每一项都是「是否在登录页露面」的开关，未配置一律视为启用；
//     真正的可用性还要看依赖是否齐（LDAP 要 identity.provider=ldap，OAuth 要配齐客户端）；
//   - OAuth 走授权码 + PKCE，回调固定 /v1/_auth/oauth/callback；
//   - 会话令牌寿命默认 12 小时，上限 24 小时（与 LDAP 会话同一约束：
//     目录/账号被禁用后，令牌不能长期续命）。

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	defaultLoginSessionTTL = 12 * time.Hour
	maxLoginSessionTTL     = 24 * time.Hour
	// OAuthCallbackPath 是授权码回调路径，配置的 redirect_url 必须指向它。
	OAuthCallbackPath = "/v1/_auth/oauth/callback"

	defaultOAuthTimeout = 10 * time.Second
	maxOAuthTimeout     = 60 * time.Second
)

// AuthConfig 是 auth 段。
type AuthConfig struct {
	Methods      AuthMethodsConfig `yaml:"methods"`
	OAuth        OAuthConfig       `yaml:"oauth"`
	SessionTTLMs int               `yaml:"session_ttl_ms"`
}

// AuthMethodsConfig 是登录页四个 tab 的开关。nil = 启用。
type AuthMethodsConfig struct {
	Password *bool `yaml:"password"`
	Token    *bool `yaml:"token"`
	OAuth    *bool `yaml:"oauth"`
	LDAP     *bool `yaml:"ldap"`
}

func toggle(on *bool, def bool) bool {
	if on == nil {
		return def
	}
	return *on
}

func (m AuthMethodsConfig) PasswordEnabled() bool { return toggle(m.Password, true) }
func (m AuthMethodsConfig) TokenEnabled() bool    { return toggle(m.Token, true) }
func (m AuthMethodsConfig) OAuthEnabled() bool    { return toggle(m.OAuth, true) }
func (m AuthMethodsConfig) LDAPEnabled() bool     { return toggle(m.LDAP, true) }

// OAuthConfig 是一个通用的 OAuth 2.0 / OIDC 授权码客户端。
type OAuthConfig struct {
	// ProviderName 是登录页上的文案（如「统一身份认证」「学校 SSO」）。
	ProviderName string   `yaml:"provider_name"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	AuthURL      string   `yaml:"auth_url"`
	TokenURL     string   `yaml:"token_url"`
	UserinfoURL  string   `yaml:"userinfo_url"`
	Scopes       []string `yaml:"scopes"`
	// RedirectURL 必须是外部可访问的绝对地址，路径固定为 /v1/_auth/oauth/callback。
	RedirectURL string `yaml:"redirect_url"`
	// SubjectClaim 是从 userinfo 里取稳定 ID 的字段；默认 sub。
	SubjectClaim string `yaml:"subject_claim"`
	// NameClaim 是显示名；默认 name。
	NameClaim string `yaml:"name_claim"`
	// AuthStyle 是客户端认证方式：basic（默认）或 post。
	AuthStyle string `yaml:"auth_style"`
	TimeoutMs int    `yaml:"timeout_ms"`
	// SPAPath 是登录成功后跳回的 SPA 路径；默认 /spa/user/。
	SPAPath string `yaml:"spa_path"`
}

// Configured 报告 OAuth 客户端是否配齐（决定登录页是否出现这个 tab）。
func (o *OAuthConfig) Configured() bool {
	return strings.TrimSpace(o.ClientID) != "" &&
		strings.TrimSpace(o.ClientSecret) != "" &&
		strings.TrimSpace(o.AuthURL) != "" &&
		strings.TrimSpace(o.TokenURL) != "" &&
		strings.TrimSpace(o.UserinfoURL) != "" &&
		strings.TrimSpace(o.RedirectURL) != ""
}

func (o *OAuthConfig) Timeout() time.Duration {
	if o.TimeoutMs <= 0 {
		return defaultOAuthTimeout
	}
	return time.Duration(o.TimeoutMs) * time.Millisecond
}

func (a *AuthConfig) SessionTTL() time.Duration {
	if a.SessionTTLMs <= 0 {
		return defaultLoginSessionTTL
	}
	return time.Duration(a.SessionTTLMs) * time.Millisecond
}

// normalize 校验并补默认值。任何一步失败都返回配置错误（启动即拒绝）。
func (a *AuthConfig) normalize() error {
	if a.SessionTTLMs == 0 {
		a.SessionTTLMs = int(defaultLoginSessionTTL / time.Millisecond)
	}
	ttl := time.Duration(a.SessionTTLMs) * time.Millisecond
	if ttl < time.Minute || ttl > maxLoginSessionTTL {
		return fmt.Errorf("auth.session_ttl_ms = %d，必须在 60000..%d 之间",
			a.SessionTTLMs, maxLoginSessionTTL/time.Millisecond)
	}
	return a.OAuth.normalize()
}

func (o *OAuthConfig) normalize() error {
	// 一个字段都没填 = 不启用 OAuth，不算错
	anySet := o.ProviderName != "" || o.ClientID != "" || o.ClientSecret != "" ||
		o.AuthURL != "" || o.TokenURL != "" || o.UserinfoURL != "" || o.RedirectURL != ""
	if !anySet {
		return nil
	}
	var missing []string
	for name, v := range map[string]string{
		"client_id": o.ClientID, "client_secret": o.ClientSecret,
		"auth_url": o.AuthURL, "token_url": o.TokenURL,
		"userinfo_url": o.UserinfoURL, "redirect_url": o.RedirectURL,
	} {
		if strings.TrimSpace(v) == "" {
			missing = append(missing, "auth.oauth."+name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("OAuth 客户端配置不完整，缺：%s", strings.Join(missing, "、"))
	}

	if o.ProviderName == "" {
		o.ProviderName = "统一身份认证"
	}
	if len(o.Scopes) == 0 {
		o.Scopes = []string{"openid", "profile"}
	}
	if o.SubjectClaim == "" {
		o.SubjectClaim = "sub"
	}
	if o.NameClaim == "" {
		o.NameClaim = "name"
	}
	if o.AuthStyle == "" {
		o.AuthStyle = "basic"
	}
	if o.AuthStyle != "basic" && o.AuthStyle != "post" {
		return fmt.Errorf("auth.oauth.auth_style 只能是 basic 或 post，当前是 %q", o.AuthStyle)
	}
	if o.SPAPath == "" {
		o.SPAPath = "/spa/user/"
	}
	if !strings.HasPrefix(o.SPAPath, "/") {
		return fmt.Errorf("auth.oauth.spa_path 必须以 / 开头，当前是 %q", o.SPAPath)
	}
	if o.TimeoutMs == 0 {
		o.TimeoutMs = int(defaultOAuthTimeout / time.Millisecond)
	}
	to := time.Duration(o.TimeoutMs) * time.Millisecond
	if to < 500*time.Millisecond || to > maxOAuthTimeout {
		return fmt.Errorf("auth.oauth.timeout_ms = %d，必须在 500..%d 之间",
			o.TimeoutMs, maxOAuthTimeout/time.Millisecond)
	}

	for name, raw := range map[string]string{
		"auth_url": o.AuthURL, "token_url": o.TokenURL, "userinfo_url": o.UserinfoURL,
	} {
		if err := checkOAuthURL(raw); err != nil {
			return fmt.Errorf("auth.oauth.%s 不合法: %w", name, err)
		}
	}
	u, err := url.Parse(o.RedirectURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("auth.oauth.redirect_url 必须是绝对地址，当前是 %q", o.RedirectURL)
	}
	if u.Path != OAuthCallbackPath {
		return fmt.Errorf("auth.oauth.redirect_url 的路径必须是 %s，当前是 %q", OAuthCallbackPath, u.Path)
	}
	if err := checkOAuthURL(o.RedirectURL); err != nil {
		return fmt.Errorf("auth.oauth.redirect_url 不合法: %w", err)
	}
	return nil
}

// checkOAuthURL 要求 https；本机回环地址允许 http（本地联调/测试）。
func checkOAuthURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Hostname() == "" {
		return fmt.Errorf("缺少主机名")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		h := strings.ToLower(u.Hostname())
		if h == "localhost" || h == "127.0.0.1" || h == "::1" {
			return nil
		}
		return fmt.Errorf("必须使用 https（只有本机回环地址允许 http）")
	default:
		return fmt.Errorf("协议必须是 https，当前是 %q", u.Scheme)
	}
}
