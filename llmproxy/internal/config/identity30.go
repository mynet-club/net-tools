package config

// 本文件是 §3.0 的**外部身份签发**配置块（identity:）。
//
// 语义（决策包 §0.1 第 11′–14′ 行 / §9）：下游每请求带一枚 IdP 签发的 token
// （请求头 X-Identity-Token），网关校验它、把其中的 org/project 成员关系并入这次
// 请求的范围链。整段缺省 = 不启用 —— 与今天的逐字节行为相同，这是「升级二进制
// 不动配置」的同一取法（见 policy30.go 的 policy 段）。
//
// 为什么单独一个文件：identity 段是「网关是否认外部签发的身份」这一个问题的唯一
// 答案，它和 policy 段（3.0 是否参与判定）是两个正交的开关，读配置的人需要一眼
// 看出边界。接线（provider 构造、逐请求校验、范围绑定）全部以这里解析出的取值
// 为准，任何 handler 都不许自己拼 issuer/audience。
//
// **刻意不 import internal/identity**：本包只负责「形状与必填」这一层，
// 算法的合法性、键来源的构造、claim 的映射规则都在 server 启动期用领域包校验
// （见 internal/server/identity30.go 的 CheckIdentityRuntime），与 policy 段通过
// KnownScopes 小接口出借校验能力的先例一致（§5「包之间靠小接口通信」）。

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// IdentityProviderOIDC 是 OIDC 身份来源类型。
const IdentityProviderOIDC = "oidc"

// IdentityProviderLDAP 是目录（LDAP / AD）身份来源类型。
const IdentityProviderLDAP = "ldap"

const (
	// DefaultLDAPSessionTTL 是 LDAP 登录换取的会话令牌默认寿命。
	DefaultLDAPSessionTTL = 15 * time.Minute
	maxLDAPSessionTTL     = 24 * time.Hour
	defaultLDAPTimeoutMs  = 5000
	maxLDAPTimeoutMs      = 30000
)

// LDAPIdentityConfig 是 identity.provider=ldap 时的目录配置。
//
// 口令只用于登录端点的一次绑定，不进入请求路径；网关据此签发短时会话令牌。
type LDAPIdentityConfig struct {
	// URL 是目录地址，支持 ldap:// 与 ldaps://。
	URL string `yaml:"url"`
	// BindDN / BindPassword 是服务账号，用于按 UserAttr 搜索用户条目。
	BindDN       string `yaml:"bind_dn"`
	BindPassword string `yaml:"bind_password"`
	// BaseDN 是用户搜索基准点。
	BaseDN string `yaml:"base_dn"`
	// UserAttr 是稳定用户标识属性（uid / sAMAccountName / objectGUID）。
	UserAttr string `yaml:"user_attr"`
	// DisplayNameAttr 是显示名属性（缺省 displayName，回落 cn）。
	DisplayNameAttr string `yaml:"display_name_attr"`
	// GroupAttr 是用户条目上的组属性（AD 常用 memberOf）。
	GroupAttr string `yaml:"group_attr"`
	// GroupBaseDN 非空时按 member=<用户 DN> 反查组，而不是只读 GroupAttr。
	GroupBaseDN string `yaml:"group_base_dn"`
	// RoleAttr 是角色/身份属性（如 eduPersonScopedAffiliation）。
	RoleAttr string `yaml:"role_attr"`
	// TimeoutMs 是连接与单次目录操作的时限（500..30000）。
	TimeoutMs int `yaml:"timeout_ms"`
	// StartTLS 在 ldap:// 上升级 TLS；与 ldaps:// 二选一。
	StartTLS bool `yaml:"start_tls"`
	// RootCAFile 是校验证书用的 PEM 文件（相对配置文件目录）。
	RootCAFile string `yaml:"root_ca_file"`
	// AllowedBindTargets 是允许连接的目录 host:port 白名单。必填。
	AllowedBindTargets []string `yaml:"allowed_targets"`
	// SessionTTLMs 是登录后签发的会话令牌寿命（60000..86400000）。
	SessionTTLMs int `yaml:"session_ttl_ms"`
	// MaxPasswordBytes 是目录口令长度上限。
	MaxPasswordBytes int `yaml:"max_password_bytes"`
}

// isZero 报告 LDAP 段是否一个字都没写。
func (l LDAPIdentityConfig) isZero() bool {
	return strings.TrimSpace(l.URL) == "" &&
		strings.TrimSpace(l.BindDN) == "" &&
		strings.TrimSpace(l.BindPassword) == "" &&
		strings.TrimSpace(l.BaseDN) == "" &&
		strings.TrimSpace(l.UserAttr) == "" &&
		strings.TrimSpace(l.DisplayNameAttr) == "" &&
		strings.TrimSpace(l.GroupAttr) == "" &&
		strings.TrimSpace(l.GroupBaseDN) == "" &&
		strings.TrimSpace(l.RoleAttr) == "" &&
		l.TimeoutMs == 0 && !l.StartTLS &&
		strings.TrimSpace(l.RootCAFile) == "" &&
		len(l.AllowedBindTargets) == 0 &&
		l.SessionTTLMs == 0 && l.MaxPasswordBytes == 0
}

// IdentityConfig 是 identity 段。
//
// 刻意**不暴露 max_lifetime**（裁决 13′「只认 claims 自带的 exp」）：那份口径
// 明确不加网关侧的 TTL 上限，多一个能收紧寿命的旋钮就多一个「读 token 的人
// 以为是它会话上限」的误解面。到期一律以 claims 的 exp 为准，网关不设第二条线。
type IdentityConfig struct {
	// Provider 是身份来源类型。今天只实现 oidc；saml/ldap 等必须显式报错，
	// 不能「不认识就当没配」—— 静默忽略会让运维以为接上了（与 policy.mode 同口径）。
	Provider string `yaml:"provider"`
	// Source 是写进 policy.Identity.Source 的来源标识，用来区分「目录里的人」
	// 与网关自己的 llmproxy-user-token / llmproxy-api-key。必填。
	Source string `yaml:"source"`
	// Issuer 是 OIDC 的 iss，必须与 token 的 iss 精确相等。
	Issuer string `yaml:"issuer"`
	// Audience 是预期的 aud（单受众）。多受众见 ExtraAudiences。
	Audience string `yaml:"audience"`
	// ExtraAudiences 是除 Audience 之外还接受的 aud 值。
	ExtraAudiences []string `yaml:"extra_audiences"`
	// AllowMultiAudience 打开后才接受「aud 是数组」的 token（默认拒绝：
	// 多受众 token 的意图不明确，宽松放行会让一枚给别的应用签的 token 也能进网关）。
	AllowMultiAudience bool `yaml:"allow_multi_audience"`
	// Algorithms 是允许的签名算法（RS256/ES256 等）。留空取领域包的默认集合；
	// 填了就必须落在受支持集合内（算法白名单是防 alg 混淆攻击的第一道，见 oidc.go）。
	Algorithms []string `yaml:"algorithms"`
	// AllowSingleKeyWithoutKid 允许「token 不带 kid 且来源只有一把 key」时继续验签。
	// 默认关闭：轮换窗口里猜错 key 会把本该失败的 token 验过。
	AllowSingleKeyWithoutKid bool `yaml:"allow_single_key_without_kid"`
	// JWKSFile 是本机 JWKS 文件路径（相对配置文件所在目录；也可写绝对路径）。
	//
	// 只认本机文件、**拒绝 http(s):// 形式**：出网取键要走 dialer 与出网策略，
	// 那是另一个包的事（本包与 identity 包都不发起网络连接）。HTTP JWKS 作为
	// 已知限制写进文档，等需要时按 §5 的对称接口补一个受约束的 fetcher。
	JWKSFile string `yaml:"jwks_file"`
	// LDAP 是 provider=ldap 时的目录配置。
	LDAP LDAPIdentityConfig `yaml:"ldap"`

	// --- 加载期解析出的派生值，运行期只读 ---
	enabled bool
}

// Enabled 报告 identity 段是否**完整配置且可用**。
//
// legacy 模式下即使配置完整也返回 true：真正的「不参与」由 server 侧的
// UsesPolicy 门槛决定（policyRuntime 在 legacy 时根本不构造）。这里只回答
// 「这段配置本身是不是一份合法的 OIDC 配置」。
func (c *IdentityConfig) Enabled() bool { return c != nil && c.enabled }

// ResolveJWKS 返回 JWKS 文件的绝对路径；baseDir 是配置文件所在目录
// （用 Config.BundleBaseDir() 取，与策略包目录同一套相对基准）。
func (c *IdentityConfig) ResolveJWKS(baseDir string) string {
	if c == nil {
		return ""
	}
	p := strings.TrimSpace(c.JWKSFile)
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(baseDir, p)
}

// isZero 报告整段是否一个字都没写（用 Provider 与所有其余字段共同判断）。
func (c *IdentityConfig) isZero() bool {
	return strings.TrimSpace(c.Provider) == "" &&
		strings.TrimSpace(c.Source) == "" &&
		strings.TrimSpace(c.Issuer) == "" &&
		strings.TrimSpace(c.Audience) == "" &&
		len(c.ExtraAudiences) == 0 &&
		len(c.Algorithms) == 0 &&
		strings.TrimSpace(c.JWKSFile) == "" &&
		!c.AllowMultiAudience && !c.AllowSingleKeyWithoutKid &&
		c.LDAP.isZero()
}

// normalize 校验并派生 identity 段。由 Config.normalize 调用（在 policy 段之后，
// 这样 legacy 的告警口径与 policy.bundles 一致）。
func (c *IdentityConfig) normalize(policyMode PolicyMode, warnings *[]string) error {
	if c == nil || c.isZero() {
		// 整段缺省：不启用。这是唯一能保证「升级二进制不动配置」的取值。
		c.enabled = false
		return nil
	}

	provider := strings.ToLower(strings.TrimSpace(c.Provider))
	if provider == "" {
		return fmt.Errorf("identity.provider 必填（可用：oidc、ldap）—— " +
			"identity 段要么整段不写（不启用外部身份），要么写清 provider，不能只填一半")
	}
	switch provider {
	case IdentityProviderOIDC, IdentityProviderLDAP:
	default:
		return fmt.Errorf("identity.provider 是 %q，可用 oidc 或 ldap；saml 尚未实现，"+
			"不能当成「不认识就忽略」—— 那会让运维以为外部身份已经接上了", c.Provider)
	}
	c.Provider = provider

	c.Source = strings.TrimSpace(c.Source)
	if c.Source == "" {
		return fmt.Errorf("identity.source 必填（会写进 policy.Identity.Source，用来区分外部身份与网关自身的 token）")
	}
	// 来源标识不得与网关自身的两把词冲突：Source 是「这条身份从哪儿来」的判据，
	// 撞上 llmproxy-user-token/llmproxy-api-key 会让审计与条件规则把外部身份
	// 误当成网关自己签发的人（保留词汇冲突，宁可启动失败）。
	switch c.Source {
	case "llmproxy-user-token", "llmproxy-api-key":
		return fmt.Errorf("identity.source 不能是网关保留值 %q（那是网关自身 token 的来源标识）", c.Source)
	}

	if provider == IdentityProviderOIDC {
		return c.normalizeOIDC(policyMode, warnings)
	}
	return c.normalizeLDAP(policyMode, warnings)
}

// normalizeOIDC 校验 OIDC 段（原有字段全部保留）。
func (c *IdentityConfig) normalizeOIDC(policyMode PolicyMode, warnings *[]string) error {
	c.Issuer = strings.TrimSpace(c.Issuer)
	c.Audience = strings.TrimSpace(c.Audience)
	c.JWKSFile = strings.TrimSpace(c.JWKSFile)
	if !c.LDAP.isZero() {
		return fmt.Errorf("identity.provider=oidc 时不要配置 identity.ldap 段")
	}
	if c.Issuer == "" {
		return fmt.Errorf("identity.issuer 必填（必须与 token 的 iss 精确相等）")
	}
	if c.Audience == "" {
		return fmt.Errorf("identity.audience 必填（多受众见 identity.extra_audiences）")
	}
	if c.JWKSFile == "" {
		return fmt.Errorf("identity.jwks_file 必填（本机 JWKS 文件路径，相对配置文件所在目录）")
	}
	if strings.Contains(c.JWKSFile, "://") {
		return fmt.Errorf("identity.jwks_file 只接受本机文件路径，不支持 %q —— "+
			"出网取键要走受约束的 dialer 与出网策略，属另一个包；"+
			"请把 IdP 的 JWKS 落到本机文件再用本机路径", c.JWKSFile)
	}
	c.markEnabled(policyMode, warnings)
	return nil
}

// normalizeLDAP 校验目录段，并给出安全边界：
// 目标白名单必填、服务账号必填、口令与 TTL 都有上下限。
func (c *IdentityConfig) normalizeLDAP(policyMode PolicyMode, warnings *[]string) error {
	if c.Issuer != "" || c.Audience != "" || len(c.ExtraAudiences) > 0 || len(c.Algorithms) > 0 ||
		c.AllowMultiAudience || c.AllowSingleKeyWithoutKid || strings.TrimSpace(c.JWKSFile) != "" {
		return fmt.Errorf("identity.provider=ldap 时不要配置 OIDC 字段（issuer / audience / jwks_file / algorithms 等）")
	}
	ld := &c.LDAP
	ld.URL = strings.TrimSpace(ld.URL)
	ld.BindDN = strings.TrimSpace(ld.BindDN)
	ld.BindPassword = strings.TrimSpace(ld.BindPassword)
	ld.BaseDN = strings.TrimSpace(ld.BaseDN)
	ld.UserAttr = strings.TrimSpace(ld.UserAttr)
	ld.DisplayNameAttr = strings.TrimSpace(ld.DisplayNameAttr)
	ld.GroupAttr = strings.TrimSpace(ld.GroupAttr)
	ld.GroupBaseDN = strings.TrimSpace(ld.GroupBaseDN)
	ld.RoleAttr = strings.TrimSpace(ld.RoleAttr)
	ld.RootCAFile = strings.TrimSpace(ld.RootCAFile)

	if ld.URL == "" || ld.BindDN == "" || ld.BindPassword == "" || ld.BaseDN == "" || ld.UserAttr == "" {
		return fmt.Errorf("identity.ldap 需要 url / bind_dn / bind_password / base_dn / user_attr 五项齐全")
	}
	u, err := url.Parse(ld.URL)
	if err != nil {
		return fmt.Errorf("identity.ldap.url 不合法: %v", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "ldap" && scheme != "ldaps") || u.Hostname() == "" {
		return fmt.Errorf("identity.ldap.url 必须是 ldap:// 或 ldaps:// 且带主机名，实际 %q", ld.URL)
	}
	if ld.StartTLS && scheme == "ldaps" {
		return fmt.Errorf("identity.ldap.url 已是 ldaps:// 时不能再配 start_tls（二选一）")
	}
	if scheme == "ldap" && !ld.StartTLS {
		return fmt.Errorf("identity.ldap.url 使用 ldap:// 时必须配 start_tls: true —— " +
			"否则目录口令会明文传输")
	}
	port := u.Port()
	if port == "" {
		if scheme == "ldaps" {
			port = "636"
		} else {
			port = "389"
		}
	}
	target := net.JoinHostPort(u.Hostname(), port)
	if len(ld.AllowedBindTargets) == 0 {
		return fmt.Errorf("identity.ldap.allowed_targets 必填（空名单表示不允许任何目录目标，不是不做限制）")
	}
	allowed := false
	for i, item := range ld.AllowedBindTargets {
		trimmed := strings.TrimSpace(item)
		ld.AllowedBindTargets[i] = trimmed
		if strings.EqualFold(trimmed, target) {
			allowed = true
		}
	}
	if !allowed {
		return fmt.Errorf("identity.ldap.url 的目标 %s 不在 allowed_targets 里（必须逐条写 host:port）", target)
	}
	if ld.DisplayNameAttr == "" {
		ld.DisplayNameAttr = "displayName"
	}
	if ld.GroupAttr == "" {
		ld.GroupAttr = "memberOf"
	}
	if ld.RoleAttr == "" {
		ld.RoleAttr = "eduPersonScopedAffiliation"
	}
	if ld.TimeoutMs == 0 {
		ld.TimeoutMs = defaultLDAPTimeoutMs
	}
	if ld.TimeoutMs < 500 || ld.TimeoutMs > maxLDAPTimeoutMs {
		return fmt.Errorf("identity.ldap.timeout_ms = %d，必须在 500..%d 之间", ld.TimeoutMs, maxLDAPTimeoutMs)
	}
	if ld.SessionTTLMs == 0 {
		ld.SessionTTLMs = int(DefaultLDAPSessionTTL / time.Millisecond)
	}
	if ld.SessionTTLMs < 60_000 || ld.SessionTTLMs > int(maxLDAPSessionTTL/time.Millisecond) {
		return fmt.Errorf("identity.ldap.session_ttl_ms = %d，必须在 60000..%d 之间",
			ld.SessionTTLMs, int(maxLDAPSessionTTL/time.Millisecond))
	}
	if ld.MaxPasswordBytes == 0 {
		ld.MaxPasswordBytes = 256
	}
	if ld.MaxPasswordBytes < 1 || ld.MaxPasswordBytes > 4096 {
		return fmt.Errorf("identity.ldap.max_password_bytes = %d，必须在 1..4096 之间", ld.MaxPasswordBytes)
	}
	c.markEnabled(policyMode, warnings)
	return nil
}

func (c *IdentityConfig) markEnabled(policyMode PolicyMode, warnings *[]string) {
	c.enabled = true
	if policyMode == PolicyModeLegacy {
		// 回滚期间的正常状态，与 policy.bundles 在 legacy 下的告警同口径：
		// 配置留着不动，切成非 legacy 就生效。
		*warnings = append(*warnings,
			"policy.mode=legacy，已配置的 identity 段不会参与任何判定（回滚期间的正常状态）")
	}
}

// IsLDAP 报告身份来源是否为目录。
func (c *IdentityConfig) IsLDAP() bool {
	return c != nil && c.enabled && c.Provider == IdentityProviderLDAP
}

// SessionTTL 返回 LDAP 会话令牌寿命。
func (c *IdentityConfig) SessionTTL() time.Duration {
	if c == nil || c.LDAP.SessionTTLMs <= 0 {
		return DefaultLDAPSessionTTL
	}
	return time.Duration(c.LDAP.SessionTTLMs) * time.Millisecond
}

// LDAPTimeout 返回目录连接与单次操作的时限。
func (c *IdentityConfig) LDAPTimeout() time.Duration {
	if c == nil || c.LDAP.TimeoutMs <= 0 {
		return defaultLDAPTimeoutMs * time.Millisecond
	}
	return time.Duration(c.LDAP.TimeoutMs) * time.Millisecond
}

// ResolveRootCA 返回 LDAP 根证书文件的绝对路径（相对配置文件目录）。
func (c *IdentityConfig) ResolveRootCA(baseDir string) string {
	if c == nil {
		return ""
	}
	p := strings.TrimSpace(c.LDAP.RootCAFile)
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(baseDir, p)
}
