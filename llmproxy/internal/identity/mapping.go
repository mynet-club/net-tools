package identity

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// ScopeRule 把某个 claim 的取值展开成指定类型的范围。
//
// 领域文档 §5 说得很清楚：范围之间的父子归属由各适配器展开成完整 chain 传进去，
// policy 包不猜层级。所以「学生属于哪个学院、哪个课题组、哪门课」必须由这里的配置
// 说明 —— 漏一层，那一层的组织级/项目级策略就对这个请求永不生效，
// 而表现为「策略配了没生效」，比报错更难发现。
type ScopeRule struct {
	// Claim 是 claim 路径，支持点号下钻嵌套对象，如 "authorization.colleges"。
	Claim string
	// Kind 只能是 organization 或 project：user 范围由 subject 自动产生，
	// system 范围不归身份层决定（让 token 能自封 system 范围等于自封管理员）。
	Kind policy.ScopeKind
	// Primary 标记该规则负责填 PolicyContext 的同名字段（主组织/主项目）。
	// 同一 Kind 有多条 primary 时，只有第一条参与填写，其余仍进 chain。
	Primary bool
}

// ScopeDirectory 把 claim 里的原始值换成稳定的范围 ID。
//
// 这一层是「禁止用显示名当关联键」（手册 §5）的落地点：claim 里拿到的是
// 「计算机学院」这样的显示名，改名就把历史授权和用量断掉；
// 生产部署应当用 StaticDirectory 提供运营维护的别名表，Slug 只是兜底。
type ScopeDirectory interface {
	// Canonical 返回稳定 ID。ok=false 表示无法解析（映射器据此报错，不静默丢范围）。
	Canonical(kind policy.ScopeKind, raw string) (id string, ok bool)
}

// SlugDirectory 用归一化规则把 claim 原值转成小写短横线 ID。
//
// 它只做字符层面的变换，不查表：适合「claim 值本身就是编码」的场景
// （不少学校的 course 字段是 CS101-2024F 这种代码）。含中文或会改名的显示名时，
// 改用 StaticDirectory 并让它保持默认的 fail-closed。
type SlugDirectory struct {
	// MaxLenBytes 是产出 ID 的字节上限（policy 的 scope ID 上限是 256，这里默认更严）。
	// 超长不静默截断：截断会把两个长名字并成同一个 ID，属于合并越权方向。
	MaxLenBytes int
}

// DefaultSlugDirectory 是映射器的默认目录。
func DefaultSlugDirectory() SlugDirectory { return SlugDirectory{MaxLenBytes: 128} }

// Canonical 实现 ScopeDirectory。
func (d SlugDirectory) Canonical(_ policy.ScopeKind, raw string) (string, bool) {
	maxLen := d.MaxLenBytes
	if maxLen <= 0 {
		maxLen = 128
	}
	id := slugify(raw)
	if id == "" {
		return "", false
	}
	if len(id) > maxLen {
		return "", false
	}
	ref, err := policy.NewScopeRef(policy.ScopeOrganization, id)
	if err != nil {
		return "", false
	}
	return ref.ID, true
}

func slugify(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	// 含冒号的取值直接拒掉，而不是「把冒号丢了继续」。
	//
	// 冒号是 policy.ScopeRef 的 Display() 结构分隔符（kind:id），带冒号的 ID 会让
	// Display() 无法还原；更重要的是丢弃是静默的：「info:sci」与「infosci」会并成
	// 同一个范围 ID，而这两个在来源侧是两个组织。合并方向的错误授权比登录失败严重
	// （与 MaxLenBytes 不许截断同理），所以宁可让这条取值走 StaticDirectory 别名表。
	if strings.ContainsRune(trimmed, ':') {
		return ""
	}
	var b strings.Builder
	b.Grow(len(trimmed))
	lastWasDash := false
	for _, r := range trimmed {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(unicode.ToLower(r))
			lastWasDash = false
		case r == ' ' || r == '\t' || r == '_' || r == '.' || r == '/' || r == '-':
			if !lastWasDash && b.Len() > 0 {
				b.WriteByte('-')
				lastWasDash = true
			}
		default:
			// 其它字符（控制字符、标点）一律丢弃而不是替换成 '-'：
			// 保留可见字符会让「同一个逻辑范围的不同写法」映射到不同 ID。
			// 结构分隔符冒号不走这里 —— 它在入口就被整体拒绝了（见函数开头）。
			continue
		}
	}
	out := strings.Trim(b.String(), "-")
	// 全部字符都被丢弃时只剩空串，交给调用方按 ok=false 处理。
	if out == "" {
		return ""
	}
	return out
}

// StaticDirectory 是运营维护的别名表：claim 原值 → 稳定范围 ID。
//
// 这是推荐的产形态：各校 OIDC 的组名（"信息学部/计算机学院/2021级"）既会改名又会重复，
// 把它直接当 scope ID 会让策略在改名那天集体失效。表由 G/接线包按学校灌进来。
type StaticDirectory struct {
	// Entries 按范围类型分桶：Entries[policy.ScopeOrganization]["原始 claim 值"] = "cs-college"。
	Entries map[policy.ScopeKind]map[string]string
	// AllowUnknown 打开时，表里没有的取值退回「原值即编码」。
	//
	// 默认关（零值）是刻意的：反过来的开关 RequireKnown 会让「最小写法」
	// `StaticDirectory{Entries: …}` 变成放行显示名当授权键的宽松目录 ——
	// 零值必须是 fail-closed（§5）。要打开它得写明理由：这条路径把 claim 原文
	// 直接当范围 ID，中文院系名与改名都会进授权判定面。
	AllowUnknown bool
	// Fallback 是未命中时的回退目录；nil 表示不回退。
	// 显式配置的回退不受 AllowUnknown 影响 —— 运营选了 SlugDirectory 就是选了它。
	Fallback ScopeDirectory
}

// Canonical 实现 ScopeDirectory。
func (d StaticDirectory) Canonical(kind policy.ScopeKind, raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if bucket, ok := d.Entries[kind]; ok {
		if id, found := bucket[trimmed]; found {
			ref, err := policy.NewScopeRef(kind, id)
			if err != nil {
				return "", false
			}
			return ref.ID, true
		}
	}
	if d.Fallback != nil {
		return d.Fallback.Canonical(kind, raw)
	}
	if !d.AllowUnknown {
		return "", false
	}
	// 未命中且显式允许宽松：原值本身就是稳定编码时可直接用（仍然拒绝冒号/空白）。
	return stableIDFromRaw(kind, trimmed)
}

func stableIDFromRaw(kind policy.ScopeKind, raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	ref, err := policy.NewScopeRef(kind, raw)
	if err != nil {
		return "", false
	}
	return ref.ID, true
}

// MapperConfig 是可配置的 claim 映射表（手册 §3.B「外部身份到内部 Identity 的映射」）。
//
// 各校 claim 命名完全不同：角色可能叫 roles、realm_access.roles、也可能叫 user_role；
// 组可能叫 groups、memberOf、affiliation。把这些名字写死在代码里，
// 接第二所学校就得改核心代码 —— 那正是手册 §3.G 禁止的「高校字段硬编码进内核」。
type MapperConfig struct {
	SubjectClaims       []string
	DisplayNameClaims   []string
	RoleClaims          []string
	GroupClaims         []string
	ProjectClaims       []string
	AuthMethodClaims    []string
	ScopeRules          []ScopeRule
	Directory           ScopeDirectory
	MaxValuesPerClaim   int
	AllowNumericSubject bool
}

// DefaultMapperConfig 给出一个「典型 Keycloak/校内 OIDC」形态的默认映射。
//
// 默认值只是起点：接一所新学校必须按它的 claim 结构覆盖，
// 因为「默认能跑」和「默认正确」是两件事 —— 角色 claim 名字猜错时，
// 解析会静默产出一个无角色身份，deny 规则里靠角色匹配的那些全部失效。
func DefaultMapperConfig() MapperConfig {
	return MapperConfig{
		SubjectClaims:     []string{"sub"},
		DisplayNameClaims: []string{"name", "preferred_username", "nickname"},
		RoleClaims:        []string{"roles", "realm_access.roles", "resource_access.llmproxy.roles"},
		GroupClaims:       []string{"groups", "memberOf", "affiliation"},
		ProjectClaims:     []string{"projects", "course", "lab"},
		AuthMethodClaims:  []string{"amr", "acr"},
		ScopeRules: []ScopeRule{
			{Claim: "organization", Kind: policy.ScopeOrganization, Primary: true},
			{Claim: "department", Kind: policy.ScopeOrganization},
			{Claim: "college", Kind: policy.ScopeOrganization},
			{Claim: "projects", Kind: policy.ScopeProject, Primary: true},
			{Claim: "course", Kind: policy.ScopeProject},
			{Claim: "lab", Kind: policy.ScopeProject},
		},
		Directory:         DefaultSlugDirectory(),
		MaxValuesPerClaim: DefaultMaxValuesPerClaim,
	}
}

// ClaimMapper 是校验过的映射表实例：构造完成后只读，可并发复用。
type ClaimMapper struct {
	cfg MapperConfig
}

// NewClaimMapper 构造并校验映射表。
func NewClaimMapper(cfg MapperConfig) (*ClaimMapper, error) {
	def := DefaultMapperConfig()
	if len(cfg.SubjectClaims) == 0 {
		cfg.SubjectClaims = def.SubjectClaims
	}
	if len(cfg.DisplayNameClaims) == 0 {
		cfg.DisplayNameClaims = def.DisplayNameClaims
	}
	if len(cfg.RoleClaims) == 0 {
		cfg.RoleClaims = def.RoleClaims
	}
	if len(cfg.GroupClaims) == 0 {
		cfg.GroupClaims = def.GroupClaims
	}
	if len(cfg.ProjectClaims) == 0 {
		cfg.ProjectClaims = def.ProjectClaims
	}
	if len(cfg.AuthMethodClaims) == 0 {
		cfg.AuthMethodClaims = def.AuthMethodClaims
	}
	if len(cfg.ScopeRules) == 0 {
		cfg.ScopeRules = def.ScopeRules
	}
	if cfg.Directory == nil {
		cfg.Directory = def.Directory
	}
	if cfg.MaxValuesPerClaim <= 0 {
		cfg.MaxValuesPerClaim = def.MaxValuesPerClaim
	}

	for _, path := range cfg.allPaths() {
		if err := validateClaimPath(path); err != nil {
			return nil, err
		}
	}
	seenOrganizations := 0
	seenProjects := 0
	for _, rule := range cfg.ScopeRules {
		if err := validateClaimPath(rule.Claim); err != nil {
			return nil, err
		}
		// user 由 subject 自动产生，system 不许由 token 声明：这两类写进规则就是配置错误。
		if rule.Kind != policy.ScopeOrganization && rule.Kind != policy.ScopeProject {
			return nil, fmt.Errorf("%w: 范围规则 %q 的类型 %q 不受支持（user 来自 subject，system 不由 token 声明）",
				ErrConfig, rule.Claim, rule.Kind)
		}
		if rule.Primary {
			switch rule.Kind {
			case policy.ScopeOrganization:
				seenOrganizations++
				if seenOrganizations > 1 {
					return nil, fmt.Errorf("%w: 只允许一条 primary 的 organization 规则（主组织必须唯一，否则回放会飘）", ErrConfig)
				}
			case policy.ScopeProject:
				seenProjects++
				if seenProjects > 1 {
					return nil, fmt.Errorf("%w: 只允许一条 primary 的 project 规则", ErrConfig)
				}
			}
		}
	}
	return &ClaimMapper{cfg: cfg}, nil
}

// DefaultClaimMapper 返回默认映射表（等价于 NewClaimMapper(DefaultMapperConfig())）。
func DefaultClaimMapper() (*ClaimMapper, error) {
	return NewClaimMapper(DefaultMapperConfig())
}

func (c MapperConfig) allPaths() []string {
	out := make([]string, 0, len(c.SubjectClaims)+len(c.DisplayNameClaims)+len(c.RoleClaims)+
		len(c.GroupClaims)+len(c.ProjectClaims)+len(c.AuthMethodClaims))
	out = append(out, c.SubjectClaims...)
	out = append(out, c.DisplayNameClaims...)
	out = append(out, c.RoleClaims...)
	out = append(out, c.GroupClaims...)
	out = append(out, c.ProjectClaims...)
	out = append(out, c.AuthMethodClaims...)
	return out
}

// Mapped 是映射结果：身份快照 + 完整范围集合 + 主组织/主项目。
type Mapped struct {
	Identity     policy.Identity
	Chain        policy.ScopeChain
	Organization string
	Project      string
}

// Map 把 claims 映射成 Mapped。
//
// source 写进 Identity.Source，必须是稳定的来源标识（配置里给），不能用显示名。
// 任何一步失败都返回错误，绝不返回「部分映射」的身份：半映射的身份会被下游
// 当成合法主体继续判定，而缺的那个范围恰好可能是唯一 deny 它的范围。
func (m *ClaimMapper) Map(c Claims, source string) (Mapped, error) {
	subject, err := m.subject(c)
	if err != nil {
		return Mapped{}, err
	}
	displayName, err := m.optionalString(c, m.cfg.DisplayNameClaims)
	if err != nil {
		return Mapped{}, err
	}
	roles, err := m.collect(c, m.cfg.RoleClaims)
	if err != nil {
		return Mapped{}, err
	}
	groups, err := m.collect(c, m.cfg.GroupClaims)
	if err != nil {
		return Mapped{}, err
	}
	claimProjects, err := m.collect(c, m.cfg.ProjectClaims)
	if err != nil {
		return Mapped{}, err
	}
	authMethods, err := m.collect(c, m.cfg.AuthMethodClaims)
	if err != nil {
		return Mapped{}, err
	}

	chain, organization, project, err := m.expandScopes(c, subject)
	if err != nil {
		return Mapped{}, err
	}
	// claim 里的项目列表并进范围集合：policy 的 project: 选择器要能在 chain 里命中它，
	// 否则「按项目授权」的规则对只有项目 claim、没有 project 范围 claim 的 token 失效。
	for _, p := range claimProjects {
		id, ok := m.cfg.Directory.Canonical(policy.ScopeProject, p)
		if !ok {
			return Mapped{}, fmt.Errorf("%w: 项目 claim 无法换成稳定 ID", ErrScopeUnmapped)
		}
		ref, refErr := scopeRefOf(policy.ScopeProject, id)
		if refErr != nil {
			return Mapped{}, fmt.Errorf("%w: 项目 ID 不合法", ErrScopeUnmapped)
		}
		if !chain.Includes(ref) {
			chain = append(chain, ref)
		}
	}
	sortScopesInPlace(chain)

	id := policy.Identity{
		Subject:     subject,
		Source:      source,
		DisplayName: displayName,
		Roles:       roles,
		Groups:      groups,
		Projects:    claimProjects,
		AuthMethods: authMethods,
		IssuedAt:    c.IssuedAt,
		ExpiresAt:   c.Expiry,
	}
	id = id.Normalize()
	if err := id.Validate(); err != nil {
		return Mapped{}, mapIdentityError(err)
	}
	if project != "" && organization == "" {
		// 不报错：项目范围仍然进 chain（项目级 deny 必须参与判定），
		// 只是不填 PolicyContext.Project —— 否则 §2.2 的「有 project 必须有 organization」
		// 会把整次解析判成失败，白丢一个身份本来合法的用户。
		project = ""
	}
	return Mapped{Identity: id, Chain: chain, Organization: organization, Project: project}, nil
}

// subject 按候选 claim 顺序取第一个非空值，并做稳定 ID 形态检查。
func (m *ClaimMapper) subject(c Claims) (string, error) {
	for _, path := range m.cfg.SubjectClaims {
		v, ok := lookup(c, path)
		if !ok || v == nil {
			continue
		}
		s, isStr := v.(string)
		if !isStr {
			return "", fmt.Errorf("%w: subject 来源 %q 不是字符串（%s）", ErrClaimShape, path, typeName(v))
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// 邮箱形态在这里就先拒：policy 也会拒，但那句错误带着 subject 原值，
		// 一旦顺着错误链进审计就是 PII 落库。上游给清晰错误还能保住原因码。
		if looksLikeEmail(s) {
			return "", fmt.Errorf("%w: subject 来自 claim %q 且形如邮箱；请改用 IdP 的稳定标识（sub/工号 UID）",
				ErrSubjectUnstable, path)
		}
		if !m.cfg.AllowNumericSubject && looksLikePhoneOrStudentID(s) {
			return "", fmt.Errorf("%w: subject 来自 claim %q 且形如手机号/纯数字学号；这类标识会随人事系统重建而失效或复用。"+
				"确认它是 IdP 长期稳定 ID 时可用 MapperConfig.AllowNumericSubject 放开（此时审计只记摘要）",
				ErrSubjectUnstable, path)
		}
		return s, nil
	}
	return "", fmt.Errorf("%w: 候选 claim %v 都没有可用取值", ErrSubjectMissing, m.cfg.SubjectClaims)
}

// optionalString 按候选顺序取第一个字符串型 claim，忽略类型不符的项。
//
// 只有「装饰性」字段可以这么宽松：显示名解析不出来只是界面上少个名字，
// 让它把登录判失败得不偿失。角色/组/项目一律走 listValues，类型不符即报错 ——
// 静默丢掉一个角色 claim 等于丢掉所有靠它匹配的 deny 规则。
func (m *ClaimMapper) optionalString(c Claims, paths []string) (string, error) {
	for _, path := range paths {
		v, ok := lookup(c, path)
		if !ok || v == nil {
			continue
		}
		s, isStr := v.(string)
		if !isStr {
			continue
		}
		if s = strings.TrimSpace(s); s != "" {
			return s, nil
		}
	}
	return "", nil
}

// collect 把多条 claim 的取值合并成去重排序的列表。
func (m *ClaimMapper) collect(c Claims, paths []string) ([]string, error) {
	var out []string
	for _, path := range paths {
		values, err := m.listValues(c, path)
		if err != nil {
			return nil, err
		}
		out = append(out, values...)
	}
	return sortedUnique(out), nil
}

// listValues 读取一个 claim 的列表形态取值。
func (m *ClaimMapper) listValues(c Claims, path string) ([]string, error) {
	v, ok := lookup(c, path)
	if !ok || v == nil {
		return nil, nil
	}
	switch typed := v.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil, nil
		}
		return []string{strings.TrimSpace(typed)}, nil
	case []any:
		if len(typed) > m.cfg.MaxValuesPerClaim {
			return nil, fmt.Errorf("%w: claim %q 有 %d 项，上限 %d",
				ErrClaimOverflow, path, len(typed), m.cfg.MaxValuesPerClaim)
		}
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			s, isStr := item.(string)
			if !isStr {
				return nil, fmt.Errorf("%w: claim %q 含非字符串项（%s）", ErrClaimShape, path, typeName(item))
			}
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: claim %q 的类型 %s 不受支持（只接受字符串或字符串数组）",
			ErrClaimShape, path, typeName(v))
	}
}

// expandScopes 按规则把 claims 展开成完整范围集合，并给出主组织/主项目。
func (m *ClaimMapper) expandScopes(c Claims, subject string) (policy.ScopeChain, string, string, error) {
	userRef, err := scopeRefOf(policy.ScopeUser, subject)
	if err != nil {
		return nil, "", "", fmt.Errorf("%w: subject 不能当 user 范围 ID: %v", ErrSubjectUnstable, policy.ErrScopeID)
	}
	scopes := []policy.ScopeRef{userRef}
	var organization, project string

	for _, rule := range m.cfg.ScopeRules {
		values, err := m.listValues(c, rule.Claim)
		if err != nil {
			return nil, "", "", err
		}
		var collected []string
		for _, raw := range values {
			id, ok := m.cfg.Directory.Canonical(rule.Kind, raw)
			if !ok {
				return nil, "", "", fmt.Errorf("%w: claim %q 的取值无法换成稳定 ID（映射表与 token 不一致，"+
					"或目录表未命中且未开 AllowUnknown）", ErrScopeUnmapped, rule.Claim)
			}
			ref, refErr := scopeRefOf(rule.Kind, id)
			if refErr != nil {
				return nil, "", "", fmt.Errorf("%w: claim %q 换出的 ID 不合法: %v", ErrScopeUnmapped, rule.Claim, policy.ErrScopeID)
			}
			scopes = append(scopes, ref)
			collected = append(collected, ref.ID)
		}
		if len(collected) == 0 {
			continue
		}
		if !rule.Primary {
			continue
		}
		// 代表值取排序后的第一个：claims 里数组顺序会变（IdP 不保证稳定），
		// 不排序就会让同一个用户两次请求的主组织不同，判定与审计都飘。
		sort.Strings(collected)
		switch rule.Kind {
		case policy.ScopeOrganization:
			if organization == "" {
				organization = collected[0]
			}
		case policy.ScopeProject:
			if project == "" {
				project = collected[0]
			}
		}
	}

	chain, chainErr := policy.NewScopeChain(scopes...)
	if chainErr != nil {
		return nil, "", "", fmt.Errorf("%w: %v", ErrScopeUnmapped, policy.ErrScopeID)
	}
	return chain, organization, project, nil
}

// lookupClaim 按点分路径下钻 claims。
//
// 只走 map[string]any，不猜任何「常见包装结构」：猜包装结构会把映射语义写死进代码，
// 换一所学校就要改内核，而手册要求的是改配置。
func lookupClaim(raw map[string]any, path string) (any, bool) {
	segments := strings.Split(path, ".")
	var current any = raw
	for _, seg := range segments {
		asMap, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		value, found := asMap[seg]
		if !found {
			return nil, false
		}
		current = value
	}
	return current, true
}

// lookup 按路径读 claim 取值，标准 claim 优先读强类型字段。
//
// 解析路径下 Extra 里本来就有 iss/sub/exp（ParseClaims 原样保留了全部键），
// 但直接构造的 Claims（测试夹具、G 包的样例数据）只填强类型字段。
// 以强类型为准既避免「改了 Subject 但映射器读到旧 Extra 值」，
// 也让 Payload()/映射器对同一份 Claims 的读法一致。
func lookup(c Claims, path string) (any, bool) {
	if v, ok := standardClaimValue(c, path); ok {
		return v, true
	}
	return lookupClaim(c.Extra, path)
}

// standardClaimValue 把标准 claim 的强类型字段呈现成 claim 取值形态。
// 字段为空视为「没有这个 claim」，交给 Extra 兜底。
func standardClaimValue(c Claims, path string) (any, bool) {
	switch path {
	case "iss":
		return c.Issuer, c.Issuer != ""
	case "sub":
		return c.Subject, c.Subject != ""
	case "jti":
		return c.JWTID, c.JWTID != ""
	case "aud":
		switch len(c.Audience) {
		case 0:
			return nil, false
		case 1:
			return c.Audience[0], true
		default:
			return toAnySlice(c.Audience), true
		}
	case "exp":
		if !c.HasExpiry || c.Expiry.IsZero() {
			return nil, false
		}
		return json.Number(strconv.FormatInt(c.Expiry.Unix(), 10)), true
	case "nbf":
		if c.NotBefore.IsZero() {
			return nil, false
		}
		return json.Number(strconv.FormatInt(c.NotBefore.Unix(), 10)), true
	case "iat":
		if c.IssuedAt.IsZero() {
			return nil, false
		}
		return json.Number(strconv.FormatInt(c.IssuedAt.Unix(), 10)), true
	default:
		return nil, false
	}
}

// validateClaimPath 检查点分路径的写法。
func validateClaimPath(path string) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return fmt.Errorf("%w: claim 路径为空", ErrConfig)
	}
	if trimmed != path {
		return fmt.Errorf("%w: claim 路径 %q 首尾有空白", ErrConfig, path)
	}
	for _, seg := range strings.Split(trimmed, ".") {
		if seg == "" {
			return fmt.Errorf("%w: claim 路径 %q 含空段", ErrConfig, path)
		}
	}
	return nil
}

func sortScopesInPlace(scopes []policy.ScopeRef) {
	sort.SliceStable(scopes, func(i, j int) bool { return scopes[i].Less(scopes[j]) })
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	sort.Strings(out)
	j := 0
	for i := range out {
		if i == 0 || out[i] != out[i-1] {
			out[j] = out[i]
			j++
		}
	}
	return out[:j]
}
