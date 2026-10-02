package identity

import (
	"context"
	"fmt"
	"time"
)

// LDAPProvider 是目录（LDAP / AD）绑定认证的身份来源抽象。
//
// 同样只给接口 + stub：真正的目录查询要走 TCP/LDAP 协议栈（标准库没有），
// 而手册 §5 要求「所有外部调用必须设置 timeout、body limit 和目标约束」，
// 连接与出网策略归接线层。本包定义的是「绑定成功之后怎么变成 Identity」。
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
	// BaseDN 是搜索基准点。
	BaseDN string
	// UserAttr 是稳定用户标识属性名（OpenLDAP 常用 uid，AD 用 objectGUID）。
	UserAttr string
	// GroupAttr 是组成员属性名（AD 通常要靠 memberOf 反向查询）。
	GroupAttr string
	// GroupBaseDN 是组条目所在子树。
	GroupBaseDN string
	// Mapper 是目录属性 → Identity/ScopeChain 的映射表。
	Mapper *ClaimMapper
	// IdentityTTL 是身份结论的最长存活时间。
	// LDAP 条目本身没有过期语义，必须显式给一个：不加 TTL 的目录身份
	// 一旦进了缓存，账号被禁用后仍能继续用（这是最常见的目录集成事故）。
	IdentityTTL time.Duration
	// MaxPasswordBytes 限制口令长度，防一次超大 bind 打满内存。
	MaxPasswordBytes int
	// AllowedBindTargets 是允许连的目录地址白名单（host:port）。
	// 空表示由接线层负责约束，本包不会替它放开出网。
	AllowedBindTargets []string
}

// UnconfiguredLDAPProvider 是 LDAP 的占位实现（stub）。
type UnconfiguredLDAPProvider struct {
	trust    LDAPTrust
	source   string
	provider string
	settings settings
}

// NewUnconfiguredLDAPProvider 构造占位实现，并在构造期校验必填项。
func NewUnconfiguredLDAPProvider(trust LDAPTrust, opts ...Option) (*UnconfiguredLDAPProvider, error) {
	if trust.BaseDN == "" {
		return nil, fmt.Errorf("%w: LDAP 需要配置 BaseDN", ErrConfig)
	}
	if trust.UserAttr == "" {
		return nil, fmt.Errorf("%w: LDAP 需要配置稳定用户标识属性名（uid / objectGUID）", ErrConfig)
	}
	if trust.IdentityTTL <= 0 {
		return nil, fmt.Errorf("%w: LDAP 必须配置 IdentityTTL（目录条目没有过期语义，缺 TTL 会让被禁账号继续可用）", ErrConfig)
	}
	if trust.IdentityTTL > maxLDAPIdentityTTL {
		// 上限与下限同样重要：这个字段存在的理由就是「被禁账号不能长期继续可用」，
		// 配成一年等于没配，而配置校验只会因为它「为正」而放过。
		return nil, fmt.Errorf("%w: IdentityTTL %v 超过上限 %v（目录身份必须周期性重新校验）",
			ErrConfig, trust.IdentityTTL, maxLDAPIdentityTTL)
	}
	source := trust.Source
	if source == "" {
		source = "ldap"
	}
	return &UnconfiguredLDAPProvider{
		trust:    trust,
		source:   source,
		provider: "ldap",
		settings: newSettings(opts),
	}, nil
}

// Name 实现 Provider。
func (p *UnconfiguredLDAPProvider) Name() string { return p.provider }

// Trust 返回已校验的配置。
func (p *UnconfiguredLDAPProvider) Trust() LDAPTrust { return p.trust }

// Resolve 实现 Provider。
//
// 凭证必须是 CredentialLDAPBind；值按 "dn\npassword" 拆分。
// 这里连拆分都做了长度上限检查，是因为口令长度上限只能在这里判：
// 拆分之前先限行长度，实现替换后这条约束容易被丢掉，而超大 bind 是可用的 DoS 面。
func (p *UnconfiguredLDAPProvider) Resolve(_ context.Context, cred Credential) (Principal, error) {
	// 每一次失败都要留一条审计：OIDC 与 fake 的凭证类型不符、结构非法都会落事件，
	// LDAP 如果不落，「有人在拿畸形 bind 试探」在大盘上就是不可见的。
	// subject 只取拆分出来的 DN（调用方自己提供的标识符，且邮箱形态由审计层脱敏），
	// 拿不到 DN 时留空并由 SubjectRef 串同一次凭证 —— 口令原文永不进事件。
	at := p.settings.nowTime()
	recordFailure := func(hint string, err error) {
		reason := ReasonFor(err)
		outcome := OutcomeDenied
		if isDependencyFailure(reason) {
			outcome = OutcomeError
		}
		event := NewFailureEvent(p.source, p.provider, hint, outcome, reason, at, cred.RequestID())
		if event.Subject == "" && event.SubjectRef == "" {
			event.SubjectRef = SubjectRef(cred.Value())
		}
		p.settings.record(event)
	}

	if cred.Kind() != CredentialLDAPBind {
		err := fmt.Errorf("%w: 本来源只接受 %q 凭证，实际是 %q",
			ErrCredentialKind, CredentialLDAPBind, cred.Kind())
		recordFailure("", err)
		return Principal{}, err
	}
	dn, _, err := splitBindCredential(cred.Value(), p.trust.MaxPasswordBytes)
	if err != nil {
		recordFailure("", err)
		return Principal{}, err
	}
	recordFailure(dn, ErrNotImplemented)
	// 口令在这里刻意不再引用：未实现路径不需要它，而把它传下去就意味着
	// 将来某次改动可能把它写进错误文本。拆分只做长度与结构检查。
	return Principal{}, fmt.Errorf("%w: LDAP 绑定与属性映射尚未实现，映射点见 LDAPMappingPlan()", ErrNotImplemented)
}

// Bind 实现 LDAPProvider。
func (p *UnconfiguredLDAPProvider) Bind(_ context.Context, dn string, password string, trust LDAPTrust) (Principal, error) {
	if dn == "" {
		return Principal{}, fmt.Errorf("%w: bind DN 不能为空", ErrCredential)
	}
	if password == "" {
		// 空口令在部分目录配置里意味着匿名绑定，那绝不能当作认证成功。
		return Principal{}, fmt.Errorf("%w: bind 口令不能为空（空口令在部分目录里是匿名绑定）", ErrCredential)
	}
	if trust.BaseDN == "" {
		return Principal{}, fmt.Errorf("%w: LDAP 需要配置 BaseDN", ErrConfig)
	}
	return Principal{}, fmt.Errorf("%w: LDAP 绑定尚未实现", ErrNotImplemented)
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

// defaultMaxPasswordBytes 是口令长度兜底上限。
//
// 256 足够容纳任何合理的口令与口令短语；超过这个长度的「口令」
// 要么是配置错误，要么是在试探缓冲区，两种都不该继续往下走。
const defaultMaxPasswordBytes = 256

// maxLDAPIdentityTTL 是目录身份结论的最长存活时间。
//
// 目录没有 exp，TTL 只能由配置给；没有上限时「TTL=100 年」也能建库，
// 而那正好废掉这个字段唯一的用途（被禁/改密账号要在可接受的时间内失效）。
// 24 小时对齐「至少要过一夜再重读目录」的运维直觉：再长就该由接线层做
// 显式的重新认证，而不是靠一条缓存的身份结论撑着装备变更。
const maxLDAPIdentityTTL = 24 * time.Hour

// ldapMappingPlan 是未来实现的映射点清单。
var ldapMappingPlan = []string{
	"uid / objectGUID → Identity.Subject（entryDN 与 cn 都不能当主键：改姓名或移动条目就断链）",
	"displayName / cn → Identity.DisplayName",
	"memberOf 组 DN 的 CN → Identity.Groups；再由 MapperConfig.ScopeRules 展开成 organization/project 范围",
	"自定义角色属性（如 eduPersonScopedAffiliation 的目录版）→ Identity.Roles",
	"saslauthz 的授权 ID 与认证 ID 分离时，只允许授权 ID 进 Subject",
	"pwdLastSet / lastLogin 一类时间属性 → Identity.IssuedAt；目录给不出 exp，TTL 必须由 LDAPTrust.IdentityTTL 派生 ExpiresAt",
	"accountStatus / pwdLocked 为禁用态时必须在解析阶段拒绝，不能只靠上游同步",
	"mail / telephoneNumber / mobile 属性一律不进 Principal、不进审计（同 OIDC）",
	"绑定失败的原因码只区分「凭据无效」与「目录不可用」，不回显服务端返回的原文（里面常含 DN 与内部结构）",
}

// LDAPMappingPlan 返回未实现部分的映射点。
func LDAPMappingPlan() []string { return append([]string(nil), ldapMappingPlan...) }

// 编译期断言。
var (
	_ Provider     = (*UnconfiguredLDAPProvider)(nil)
	_ LDAPProvider = (*UnconfiguredLDAPProvider)(nil)
)
