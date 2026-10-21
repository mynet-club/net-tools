package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// LDAPProvider 是目录（LDAP / AD）绑定认证的身份来源抽象。
//
// 认证只发生在登录那一刻；请求路径用的是 SessionCodec 签发的短时令牌。
// 这样目录口令不会随着每个模型请求反复上传，也不需要把口令缓存在内存里。
type LDAPProvider interface {
	// Bind 校验 DN + 口令，并读取属性映射成主体上下文。
	// searchBase 与属性名来自 LDAPTrust，不接受调用方传入（否则任何人都能
	// 指定 base 去做跨 OU 查询，等于把目录变成可被探测的接口）。
	Bind(ctx context.Context, dn string, password string, trust LDAPTrust) (Principal, error)
}

// LDAPTrust 是一个目录来源的配置。
type LDAPTrust struct {
	// Source 写进 Identity.Source（如 "campus-ldap"），必须与 OIDC 的来源名不同：
	// 同名会让 conditions 里的 source 键把两条通路并成一类，deny 范围随之失配。
	Source string
	// URL 是目录地址，支持 ldap:// 与 ldaps://。
	URL string
	// BindDN / BindPassword 是服务账号：先用它做条目搜索，再用用户 DN + 用户口令
	// 做一次绑定来验证口令。空口令的匿名搜索不支持 —— 那等于把目录开放给任何能
	// 访问网关的人枚举。
	BindDN       string
	BindPassword string
	// BaseDN 是搜索基准点。
	BaseDN string
	// UserAttr 是稳定用户标识属性名（OpenLDAP 常用 uid，AD 用 sAMAccountName；
	// objectGUID 也可用，本实现会把它转成十六进制）。
	UserAttr string
	// AllowNumericSubject 放开「纯数字学号/工号」形态的 subject。
	// 默认关闭：数字标识可能随人事系统重建而复用。目录确实以学号/工号作
	// 长期稳定 ID 时（国内高校常见）显式打开，此时审计只记摘要。
	AllowNumericSubject bool
	// DisplayNameAttr 是显示名属性（缺省 displayName，回落 cn）。
	DisplayNameAttr string
	// GroupAttr 是组成员属性名（AD 通常直接用 memberOf）。
	GroupAttr string
	// GroupBaseDN 是组条目所在子树。非空时按 member=<用户 DN> 反查组；
	// 为空则只读用户条目上的 GroupAttr。
	GroupBaseDN string
	// RoleAttr 是角色/身份属性（如 eduPersonScopedAffiliation）。
	RoleAttr string
	// IdentityTTL 是身份结论的最长存活时间。
	// LDAP 条目本身没有过期语义，必须显式给一个：不加 TTL 的目录身份
	// 一旦进了缓存，账号被禁用后仍能继续用（这是最常见的目录集成事故）。
	IdentityTTL time.Duration
	// MaxPasswordBytes 限制口令长度，防一次超大 bind 打满内存。
	MaxPasswordBytes int
	// AllowedBindTargets 是允许连的目录地址白名单（host:port）。必填：
	// 空表示「没有授权任何目标」，不是「不做限制」。
	AllowedBindTargets []string
	// Timeout 是连接与单次操作的时限。
	Timeout time.Duration
	// StartTLS 在 ldap:// 连接上升级 TLS；与 ldaps:// 二选一。
	StartTLS bool
	// RootCAFile 是校验证书用的 PEM 文件；空 = 系统根证书。
	RootCAFile string
	// Mapper 是目录属性 → Identity/ScopeChain 的映射表。
	Mapper *ClaimMapper
}

// LDAPEntry 是一条目录条目的最小视图。属性名统一小写。
type LDAPEntry struct {
	DN    string
	Attrs map[string][]string
}

// LDAPDirectory 是目录协议层的注入点。
//
// 把「怎么连目录」从「怎么映射身份」里拆开：生产用 GoLDAPDirectory，
// 测试用内存实现；映射、TTL、审计、口令长度这些安全规则只写一份。
type LDAPDirectory interface {
	Lookup(ctx context.Context, trust LDAPTrust, username string) (LDAPEntry, error)
	LookupDN(ctx context.Context, trust LDAPTrust, dn string) (LDAPEntry, error)
	Bind(ctx context.Context, trust LDAPTrust, dn, password string) error
	Groups(ctx context.Context, trust LDAPTrust, userDN string) ([]string, error)
}

// LDAPDirectoryProvider 是 LDAP 身份来源的实际实现。
type LDAPDirectoryProvider struct {
	trust    LDAPTrust
	source   string
	provider string
	dir      LDAPDirectory
	mapper   *ClaimMapper
	settings settings
}

// NewLDAPDirectoryProvider 构造 LDAP 身份来源，并在构造期校验全部安全相关配置。
func NewLDAPDirectoryProvider(trust LDAPTrust, dir LDAPDirectory, opts ...Option) (*LDAPDirectoryProvider, error) {
	if dir == nil {
		return nil, fmt.Errorf("%w: LDAP 需要注入目录实现", ErrConfig)
	}
	if strings.TrimSpace(trust.BaseDN) == "" {
		return nil, fmt.Errorf("%w: LDAP 需要配置 BaseDN", ErrConfig)
	}
	if strings.TrimSpace(trust.UserAttr) == "" {
		return nil, fmt.Errorf("%w: LDAP 需要配置稳定用户标识属性名（uid / sAMAccountName / objectGUID）", ErrConfig)
	}
	if strings.TrimSpace(trust.BindDN) == "" || trust.BindPassword == "" {
		return nil, fmt.Errorf("%w: LDAP 需要配置服务账号 BindDN/BindPassword（匿名搜索不支持）", ErrConfig)
	}
	if trust.IdentityTTL <= 0 {
		return nil, fmt.Errorf("%w: LDAP 必须配置 IdentityTTL（目录条目没有过期语义，缺 TTL 会让被禁账号继续可用）", ErrConfig)
	}
	if trust.IdentityTTL > maxLDAPIdentityTTL {
		return nil, fmt.Errorf("%w: IdentityTTL %v 超过上限 %v（目录身份必须周期性重新校验）",
			ErrConfig, trust.IdentityTTL, maxLDAPIdentityTTL)
	}
	target, err := ldapTarget(trust)
	if err != nil {
		return nil, err
	}
	if !ldapTargetAllowed(trust, target) {
		return nil, fmt.Errorf("%w: LDAP 目标 %s 不在 AllowedBindTargets 白名单里（空名单表示不允许任何目标）",
			ErrConfig, target)
	}
	if trust.Timeout <= 0 {
		trust.Timeout = 5 * time.Second
	}
	if trust.Timeout > maxLDAPTimeout {
		return nil, fmt.Errorf("%w: LDAP Timeout %v 超过上限 %v", ErrConfig, trust.Timeout, maxLDAPTimeout)
	}
	if trust.StartTLS && strings.HasPrefix(strings.ToLower(trust.URL), "ldaps://") {
		return nil, fmt.Errorf("%w: URL 已是 ldaps:// 时不能再配 StartTLS（二选一）", ErrConfig)
	}
	if !trust.StartTLS && strings.HasPrefix(strings.ToLower(trust.URL), "ldap://") {
		return nil, fmt.Errorf("%w: ldap:// 未启用 StartTLS 时目录口令会明文传输；请改用 ldaps:// 或配 start_tls: true", ErrConfig)
	}
	if trust.MaxPasswordBytes <= 0 {
		trust.MaxPasswordBytes = defaultMaxPasswordBytes
	}
	if trust.MaxPasswordBytes > maxLDAPPasswordBytes {
		return nil, fmt.Errorf("%w: MaxPasswordBytes %d 超过上限 %d",
			ErrConfig, trust.MaxPasswordBytes, maxLDAPPasswordBytes)
	}
	if trust.GroupAttr == "" {
		trust.GroupAttr = "memberOf"
	}
	if trust.DisplayNameAttr == "" {
		trust.DisplayNameAttr = "displayName"
	}
	if trust.RoleAttr == "" {
		trust.RoleAttr = "eduPersonScopedAffiliation"
	}
	mapper := trust.Mapper
	if mapper == nil {
		mapper, err = NewClaimMapper(ldapMapperConfig(trust))
		if err != nil {
			return nil, err
		}
	}
	source := strings.TrimSpace(trust.Source)
	if source == "" {
		source = "ldap"
	}
	return &LDAPDirectoryProvider{
		trust:    trust,
		source:   source,
		provider: "ldap",
		dir:      dir,
		mapper:   mapper,
		settings: newSettings(opts),
	}, nil
}

func (p *LDAPDirectoryProvider) Name() string { return p.provider }

// Trust 返回已校验的配置。
func (p *LDAPDirectoryProvider) Trust() LDAPTrust { return p.trust }

// Authenticate 用用户名 + 口令登录一次目录：服务账号查到用户 DN，再用用户口令绑定，
// 最后读取组/角色属性并映射成 Principal。
func (p *LDAPDirectoryProvider) Authenticate(ctx context.Context, username, password, requestID string) (Principal, error) {
	if err := p.checkLoginInput(username, password); err != nil {
		p.recordFailure(username, ReasonFor(err), requestID)
		return Principal{}, err
	}
	entry, err := p.dir.Lookup(ctx, p.trust, strings.TrimSpace(username))
	if err != nil {
		p.recordFailure(username, ReasonFor(err), requestID)
		return Principal{}, err
	}
	return p.finish(ctx, entry, password, requestID)
}

// Resolve 实现 Provider：接受 "dn\npassword" 形式的 CredentialLDAPBind。
//
// 请求路径不使用这条：它每次都会上传目录口令。保留它是为了给受信前置代理/
// 管理工具一个明确的入口，同时让接口契约完整。
func (p *LDAPDirectoryProvider) Resolve(ctx context.Context, cred Credential) (Principal, error) {
	if cred.Kind() != CredentialLDAPBind {
		err := fmt.Errorf("%w: 本来源只接受 %q 凭证，实际是 %q",
			ErrCredentialKind, CredentialLDAPBind, cred.Kind())
		p.recordFailure("", ReasonFor(err), cred.RequestID())
		return Principal{}, err
	}
	dn, password, err := splitBindCredential(cred.Value(), p.trust.MaxPasswordBytes)
	if err != nil {
		p.recordFailure("", ReasonFor(err), cred.RequestID())
		return Principal{}, err
	}
	entry, err := p.dir.LookupDN(ctx, p.trust, dn)
	if err != nil {
		p.recordFailure(dn, ReasonFor(err), cred.RequestID())
		return Principal{}, err
	}
	return p.finish(ctx, entry, password, cred.RequestID())
}

// Bind 实现 LDAPProvider。传入的 trust 只用于接口兼容；实际连接参数一律取
// 构造期校验过的 p.trust，避免调用方拿另一份 trust 绕过目标白名单。
func (p *LDAPDirectoryProvider) Bind(ctx context.Context, dn string, password string, _ LDAPTrust) (Principal, error) {
	if strings.TrimSpace(dn) == "" {
		return Principal{}, fmt.Errorf("%w: bind DN 不能为空", ErrCredential)
	}
	if password == "" {
		// 空口令在部分目录配置里意味着匿名绑定，那绝不能当作认证成功。
		return Principal{}, fmt.Errorf("%w: bind 口令不能为空（空口令在部分目录里是匿名绑定）", ErrCredential)
	}
	limit := p.trust.MaxPasswordBytes
	if limit <= 0 {
		limit = defaultMaxPasswordBytes
	}
	if len(password) > limit {
		return Principal{}, fmt.Errorf("%w: 口令长度 %d 超过上限 %d", ErrCredentialTooLarge, len(password), limit)
	}
	entry, err := p.dir.LookupDN(ctx, p.trust, dn)
	if err != nil {
		return Principal{}, err
	}
	return p.finish(ctx, entry, password, "")
}

func (p *LDAPDirectoryProvider) finish(ctx context.Context, entry LDAPEntry, password, requestID string) (Principal, error) {
	if err := p.dir.Bind(ctx, p.trust, entry.DN, password); err != nil {
		p.recordFailure(entry.DN, ReasonFor(err), requestID)
		return Principal{}, err
	}
	var groups []string
	if strings.TrimSpace(p.trust.GroupBaseDN) != "" {
		var err error
		groups, err = p.dir.Groups(ctx, p.trust, entry.DN)
		if err != nil {
			p.recordFailure(entry.DN, ReasonFor(err), requestID)
			return Principal{}, err
		}
	}
	now := p.settings.nowTime()
	principal, err := p.principalFromEntry(entry, groups, now, requestID)
	if err != nil {
		p.recordFailure(entry.DN, ReasonFor(err), requestID)
		return Principal{}, err
	}
	p.settings.record(NewAuditEvent(principal, OutcomeSuccess, ReasonSuccess, now))
	return principal, nil
}

func (p *LDAPDirectoryProvider) checkLoginInput(username, password string) error {
	name := strings.TrimSpace(username)
	if name == "" {
		return fmt.Errorf("%w: 用户名不能为空", ErrCredential)
	}
	if len(name) > maxLDAPUsernameBytes {
		return fmt.Errorf("%w: 用户名长度 %d 超过上限 %d", ErrCredentialTooLarge, len(name), maxLDAPUsernameBytes)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: 用户名含控制字符", ErrCredential)
		}
	}
	if password == "" {
		return fmt.Errorf("%w: 口令不能为空（空口令在部分目录里是匿名绑定）", ErrCredential)
	}
	limit := p.trust.MaxPasswordBytes
	if limit <= 0 {
		limit = defaultMaxPasswordBytes
	}
	if len(password) > limit {
		return fmt.Errorf("%w: 口令长度 %d 超过上限 %d", ErrCredentialTooLarge, len(password), limit)
	}
	return nil
}

// principalFromEntry 把一条目录条目映射成 Principal。
//
// 所有属性一律按小写键放进 Claims.Extra；objectGUID 这类二进制属性转十六进制，
// 保证同一个主体每次编码一致。组 DN 只保留 CN —— 目录里组条目被移动时，
// 授权不应跟着一起断。
func (p *LDAPDirectoryProvider) principalFromEntry(entry LDAPEntry, groups []string, now time.Time, requestID string) (Principal, error) {
	extra := make(map[string]any, len(entry.Attrs)+1)
	for k, values := range entry.Attrs {
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" || len(values) == 0 {
			continue
		}
		if key == "objectguid" {
			hexed := make([]string, 0, len(values))
			for _, v := range values {
				hexed = append(hexed, hex.EncodeToString([]byte(v)))
			}
			values = hexed
		}
		if len(values) == 1 {
			extra[key] = values[0]
		} else {
			extra[key] = anyStrings(values)
		}
	}
	groupKey := strings.ToLower(p.trust.GroupAttr)
	if strings.TrimSpace(p.trust.GroupBaseDN) != "" {
		// 配了组子树就以反查结果为准；查不到就是没有组，不能回落到用户条目上
		// 可能残留的 memberOf —— 那会让「组子树里已移除的人」继续保留组。
		extra[groupKey] = anyStrings(normalizeGroupNames(groups))
	} else if raw, ok := extra[groupKey]; ok {
		extra[groupKey] = anyStrings(normalizeGroupNames(claimStrings(raw)))
	}

	claims := Claims{
		IssuedAt:  now,
		Expiry:    now.Add(p.trust.IdentityTTL),
		HasExpiry: true,
		Extra:     extra,
	}
	mapped, err := p.mapper.Map(claims, p.source)
	if err != nil {
		return Principal{}, err
	}
	principal := Principal{
		Identity:     mapped.Identity,
		Chain:        mapped.Chain,
		Source:       p.source,
		Provider:     p.provider,
		Organization: mapped.Organization,
		Project:      mapped.Project,
		ValidUntil:   mapped.Identity.ExpiresAt,
		RequestID:    requestID,
	}
	if err := principal.Validate(); err != nil {
		return Principal{}, err
	}
	return principal, nil
}

func (p *LDAPDirectoryProvider) recordFailure(subject string, reason ReasonCode, requestID string) {
	outcome := OutcomeDenied
	if isDependencyFailure(reason) {
		outcome = OutcomeError
	}
	p.settings.record(NewFailureEvent(p.source, p.provider, subject, outcome, reason,
		p.settings.nowTime(), requestID))
}

// ldapMapperConfig 把目录属性名翻成映射器的 claim 路径。
//
// LMAP 的默认 SubjectClaims 是 OIDC 的 sub；LDAP 没有 sub，必须用配置的稳定属性。
// 其余字段沿用映射器的默认语义（角色/组/项目），但组和角色的 claim 名改成
// 目录里实际的那几个，大小写统一成小写（LDAP 属性名本身不区分大小写）。
func ldapMapperConfig(trust LDAPTrust) MapperConfig {
	return MapperConfig{
		SubjectClaims:       []string{strings.ToLower(strings.TrimSpace(trust.UserAttr))},
		AllowNumericSubject: trust.AllowNumericSubject,
		DisplayNameClaims:   uniqueLower(trust.DisplayNameAttr, "displayname", "cn"),
		RoleClaims:          uniqueLower(trust.RoleAttr, "edupersonScopedAffiliation"),
		GroupClaims:         uniqueLower(trust.GroupAttr, "memberof"),
		ProjectClaims:       []string{"projects", "project", "course", "lab"},
		ScopeRules: []ScopeRule{
			{Claim: "organization", Kind: policy.ScopeOrganization, Primary: true},
			{Claim: "department", Kind: policy.ScopeOrganization},
			{Claim: "college", Kind: policy.ScopeOrganization},
			{Claim: "projects", Kind: policy.ScopeProject, Primary: true},
			{Claim: "project", Kind: policy.ScopeProject},
			{Claim: "course", Kind: policy.ScopeProject},
			{Claim: "lab", Kind: policy.ScopeProject},
		},
	}
}

func uniqueLower(values ...string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func anyStrings(values []string) []any {
	out := make([]any, 0, len(values))
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// claimStrings 把 Extra 里的字符串或字符串列表统一成 []string。
func claimStrings(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		out := make([]string, 0, len(typed))
		for _, v := range typed {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// normalizeGroupNames 把 memberOf 这类组 DN 压成 CN；不是 DN 的值原样保留。
func normalizeGroupNames(values []string) []string {
	out := make([]string, 0, len(values))
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if dn, err := ldap.ParseDN(v); err == nil && len(dn.RDNs) > 0 && len(dn.RDNs[0].Attributes) > 0 {
			if cn := strings.TrimSpace(dn.RDNs[0].Attributes[0].Value); cn != "" {
				out = append(out, cn)
				continue
			}
		}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// splitBindCredential 拆出 DN 与口令。
func splitBindCredential(value string, maxPasswordBytes int) (dn string, password string, err error) {
	for i := 0; i < len(value); i++ {
		if value[i] == '\n' {
			dn = value[:i]
			password = value[i+1:]
			if dn == "" {
				return "", "", fmt.Errorf("%w: bind 凭证缺少 DN", ErrCredential)
			}
			if password == "" {
				return "", "", fmt.Errorf("%w: bind 凭证缺少口令", ErrCredential)
			}
			limit := maxPasswordBytes
			if limit <= 0 {
				limit = defaultMaxPasswordBytes
			}
			if len(password) > limit {
				return "", "", fmt.Errorf("%w: 口令长度 %d 超过上限 %d", ErrCredentialTooLarge, len(password), limit)
			}
			return dn, password, nil
		}
	}
	return "", "", fmt.Errorf("%w: bind 凭证必须是 \"dn\\npassword\" 形式", ErrCredential)
}

const (
	// defaultMaxPasswordBytes 是口令长度兜底上限。
	//
	// 256 足够容纳任何合理的口令与口令短语；超过这个长度的「口令」
	// 要么是配置错误，要么是在试探缓冲区，两种都不该继续往下走。
	defaultMaxPasswordBytes = 256
	maxLDAPPasswordBytes    = 4096
	maxLDAPUsernameBytes    = 256
	maxLDAPTimeout          = 30 * time.Second
	// maxLDAPIdentityTTL 是目录身份结论的最长存活时间。
	//
	// 目录没有 exp，TTL 只能由配置给；没有上限时「TTL=100 年」也能建库，
	// 而那正好废掉这个字段唯一的用途（被禁/改密账号要在可接受的时间内失效）。
	// 24 小时对齐「至少要过一夜再重读目录」的运维直觉：再长就该由接线层做
	// 显式的重新认证，而不是靠一条缓存的身份结论撑着装备变更。
	maxLDAPIdentityTTL = 24 * time.Hour
)

// LDAPMappingPlan 返回目录字段到身份字段的映射点（实现已按此落地，保留给接线方核对）。
func LDAPMappingPlan() []string {
	return []string{
		"UserAttr（uid / sAMAccountName / objectGUID）→ Identity.Subject；objectGUID 转十六进制，entryDN 与 cn 不能当主键",
		"DisplayNameAttr（缺省 displayName，回落 cn）→ Identity.DisplayName",
		"memberOf / GroupBaseDN 反查 → Identity.Groups（组 DN 只保留 CN）",
		"RoleAttr（如 eduPersonScopedAffiliation）→ Identity.Roles",
		"department / college / organization → organization 范围；projects / project / course / lab → project 范围",
		"IdentityTTL 派生 ExpiresAt（目录不提供 exp）",
		"mail / telephoneNumber / mobile 属性不进 Principal、不进审计",
		"绑定失败只区分「凭据无效」与「目录不可用」，不回显服务端原文",
	}
}

// ---------------------------------------------------------------- 目录协议实现

// GoLDAPDirectory 是基于 go-ldap 的生产实现。
type GoLDAPDirectory struct{}

// NewGoLDAPDirectory 返回生产目录实现。
func NewGoLDAPDirectory() *GoLDAPDirectory { return &GoLDAPDirectory{} }

// Lookup 用服务账号按 UserAttr 查用户条目。
func (d *GoLDAPDirectory) Lookup(ctx context.Context, trust LDAPTrust, username string) (LDAPEntry, error) {
	conn, err := dialLDAP(ctx, trust)
	if err != nil {
		return LDAPEntry{}, err
	}
	defer conn.Close()
	if err := conn.Bind(trust.BindDN, trust.BindPassword); err != nil {
		return LDAPEntry{}, directoryError(err, "服务账号绑定失败")
	}
	filter := fmt.Sprintf("(%s=%s)", trust.UserAttr, ldap.EscapeFilter(username))
	entries, err := searchLDAP(conn, trust, trust.BaseDN, filter, 2)
	if err != nil {
		return LDAPEntry{}, err
	}
	switch len(entries) {
	case 0:
		return LDAPEntry{}, fmt.Errorf("%w: 用户 %q 不在目录里", ErrLDAPEntryNotFound, username)
	case 1:
		return entries[0], nil
	default:
		return LDAPEntry{}, fmt.Errorf("%w: 标识 %q 匹配到 %d 条目录条目", ErrLDAPEntryAmbiguous, username, len(entries))
	}
}

// LookupDN 按 DN 读一条条目（base scope）。
func (d *GoLDAPDirectory) LookupDN(ctx context.Context, trust LDAPTrust, dn string) (LDAPEntry, error) {
	conn, err := dialLDAP(ctx, trust)
	if err != nil {
		return LDAPEntry{}, err
	}
	defer conn.Close()
	if err := conn.Bind(trust.BindDN, trust.BindPassword); err != nil {
		return LDAPEntry{}, directoryError(err, "服务账号绑定失败")
	}
	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", ldapAttributes(trust), nil)
	res, err := conn.Search(req)
	if err != nil {
		return LDAPEntry{}, directoryError(err, "读取用户条目失败")
	}
	if len(res.Entries) == 0 {
		return LDAPEntry{}, fmt.Errorf("%w: DN 不存在", ErrLDAPEntryNotFound)
	}
	return entryFromLDAP(res.Entries[0]), nil
}

// Bind 用用户 DN + 口令做一次真实绑定。这是「口令正确」的唯一判据。
func (d *GoLDAPDirectory) Bind(ctx context.Context, trust LDAPTrust, dn, password string) error {
	conn, err := dialLDAP(ctx, trust)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Bind(dn, password); err != nil {
		return directoryError(err, "用户绑定失败")
	}
	return nil
}

// Groups 按 member=<用户 DN> 反查组，返回 CN 列表。
func (d *GoLDAPDirectory) Groups(ctx context.Context, trust LDAPTrust, userDN string) ([]string, error) {
	if strings.TrimSpace(trust.GroupBaseDN) == "" {
		return nil, nil
	}
	conn, err := dialLDAP(ctx, trust)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.Bind(trust.BindDN, trust.BindPassword); err != nil {
		return nil, directoryError(err, "服务账号绑定失败")
	}
	filter := fmt.Sprintf("(member=%s)", ldap.EscapeFilter(userDN))
	req := ldap.NewSearchRequest(trust.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		1000, 0, false, filter, []string{"cn"}, nil)
	res, err := conn.Search(req)
	if err != nil {
		return nil, directoryError(err, "组查询失败")
	}
	out := make([]string, 0, len(res.Entries))
	for _, entry := range res.Entries {
		if cn := strings.TrimSpace(entry.GetAttributeValue("cn")); cn != "" {
			out = append(out, cn)
			continue
		}
		out = append(out, normalizeGroupNames([]string{entry.DN})...)
	}
	return out, nil
}

func searchLDAP(conn *ldap.Conn, trust LDAPTrust, baseDN, filter string, sizeLimit int) ([]LDAPEntry, error) {
	req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		sizeLimit, int(trust.Timeout.Seconds()), false, filter, ldapAttributes(trust), nil)
	res, err := conn.Search(req)
	if err != nil {
		return nil, directoryError(err, "用户查询失败")
	}
	out := make([]LDAPEntry, 0, len(res.Entries))
	for _, entry := range res.Entries {
		out = append(out, entryFromLDAP(entry))
	}
	return out, nil
}

func ldapAttributes(trust LDAPTrust) []string {
	attrs := uniqueLower(trust.UserAttr, trust.DisplayNameAttr, trust.GroupAttr, trust.RoleAttr,
		"cn", "displayName", "department", "organization", "college",
		"projects", "project", "course", "lab")
	out := make([]string, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, a)
	}
	return out
}

func entryFromLDAP(entry *ldap.Entry) LDAPEntry {
	attrs := make(map[string][]string, len(entry.Attributes))
	for _, a := range entry.Attributes {
		attrs[strings.ToLower(a.Name)] = append([]string(nil), a.Values...)
	}
	return LDAPEntry{DN: entry.DN, Attrs: attrs}
}

func dialLDAP(ctx context.Context, trust LDAPTrust) (*ldap.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDirectoryUnavailable, err)
	}
	target, err := ldapTarget(trust)
	if err != nil {
		return nil, err
	}
	if !ldapTargetAllowed(trust, target) {
		return nil, fmt.Errorf("%w: LDAP 目标 %s 不在 AllowedBindTargets 白名单里", ErrConfig, target)
	}
	timeout := trust.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tlsCfg, err := ldapTLSConfig(trust)
	if err != nil {
		return nil, err
	}
	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: timeout})}
	if strings.HasPrefix(strings.ToLower(trust.URL), "ldaps://") {
		opts = append(opts, ldap.DialWithTLSConfig(tlsCfg))
	}
	conn, err := ldap.DialURL(trust.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: 连接目录失败", ErrDirectoryUnavailable)
	}
	conn.SetTimeout(timeout)
	if trust.StartTLS {
		if err := conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("%w: StartTLS 失败", ErrDirectoryUnavailable)
		}
	}
	return conn, nil
}

func ldapTLSConfig(trust LDAPTrust) (*tls.Config, error) {
	u, err := url.Parse(trust.URL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("%w: LDAP URL 不合法", ErrConfig)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if strings.TrimSpace(trust.RootCAFile) == "" {
		return cfg, nil
	}
	pem, err := os.ReadFile(trust.RootCAFile)
	if err != nil {
		return nil, fmt.Errorf("%w: 读取 LDAP RootCAFile 失败: %v", ErrConfig, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%w: LDAP RootCAFile 不是合法的 PEM 证书", ErrConfig)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

// directoryError 把 go-ldap 的错误归成两类：凭据无效（denied）与目录不可用（error）。
// 不把服务端原文带出去：LDAP 错误里常含 DN 与内部目录结构。
func directoryError(err error, action string) error {
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		return fmt.Errorf("%w: %s", ErrDirectoryUnavailable, action)
	}
	if ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
		return fmt.Errorf("%w: 目录凭据无效", ErrCredential)
	}
	return fmt.Errorf("%w: %s", ErrDirectoryUnavailable, action)
}

// ldapTarget 解析 URL 成 host:port，并校验 scheme。
func ldapTarget(trust LDAPTrust) (string, error) {
	u, err := url.Parse(strings.TrimSpace(trust.URL))
	if err != nil {
		return "", fmt.Errorf("%w: LDAP URL 不合法: %v", ErrConfig, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "ldap" && scheme != "ldaps" {
		return "", fmt.Errorf("%w: LDAP URL 协议只能是 ldap:// 或 ldaps://，实际 %q", ErrConfig, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("%w: LDAP URL 缺少主机名", ErrConfig)
	}
	port := u.Port()
	if port == "" {
		if scheme == "ldaps" {
			port = "636"
		} else {
			port = "389"
		}
	}
	return net.JoinHostPort(host, port), nil
}

func ldapTargetAllowed(trust LDAPTrust, target string) bool {
	for _, allowed := range trust.AllowedBindTargets {
		if strings.EqualFold(strings.TrimSpace(allowed), target) {
			return true
		}
	}
	return false
}

// 编译期断言。
var (
	_ Provider      = (*LDAPDirectoryProvider)(nil)
	_ LDAPProvider  = (*LDAPDirectoryProvider)(nil)
	_ LDAPDirectory = (*GoLDAPDirectory)(nil)
)
