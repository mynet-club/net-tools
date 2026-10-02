package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Entitlement 是一条授权规则（§2.4），表示主体对模型、能力、知识库、处理器和预算的授权。
//
// 规则本身是数据，不是代码：合并、排序和命中全由 Resolver 用固定优先级完成，
// 各包不得自带一套判定次序。
type Entitlement struct {
	Subject    string            `json:"subject"`
	Scope      string            `json:"scope,omitempty"`
	Resource   string            `json:"resource"`
	Action     string            `json:"action"`
	Effect     Effect            `json:"effect"`
	Conditions map[string]string `json:"conditions,omitempty"`
	Source     string            `json:"source,omitempty"`
	Version    string            `json:"version,omitempty"`
	ExpiresAt  time.Time         `json:"expires_at,omitempty"`
}

var (
	ErrEntitlement     = errors.New("policy: 授权规则不合法")
	ErrEffect          = errors.New("policy: effect 只能 allow 或 deny")
	ErrSubjectSelector = errors.New("policy: subject 选择器格式错误")
)

// Conditions 保留键。其余键一律视为不满足（fail-closed），并且**加载期就拒绝**。
//
// 语义统一为**规则的前置条件**：所有键都成立，规则才生效；分级上界/下界是两个
// 显式键，对 allow 和 deny 表现一致，不会出现「给 deny 写上界反而把禁令跳过」。
const (
	CondPurpose      = "purpose"
	CondOrganization = "organization"
	CondProject      = "project"
	CondSource       = "source"
	CondDataLevel    = "data-level"
	CondMaxDataLevel = "max-data-level"
	CondMinDataLevel = "min-data-level"
	CondRole         = "role"
	CondGroup        = "group"
	CondAuthMethod   = "auth-method"
)

// conditionKeys 列出全部保留键，顺序固定（错误信息要能逐字复现）。
var conditionKeys = []string{
	CondPurpose, CondOrganization, CondProject, CondSource, CondDataLevel,
	CondMaxDataLevel, CondMinDataLevel, CondRole, CondGroup, CondAuthMethod,
}

// 未知键为什么必须在加载期拦住：判定期它是 fail-closed（规则不生效），
// 于是 `max_data_level` 这种下划线写法会让一条 deny **静默失效** ——
// 策略包照常加载、版本照常进审计，敏感流量却一路放行。
// 「配了但没生效」正是 §3.0 要求在影子阶段之前排除掉的那类事故，
// 让它以启动失败的形式出现，比在差异报告里多一行 no_candidate 便宜得多。
func (e Entitlement) unknownConditionKeys() []string {
	if len(e.Conditions) == 0 {
		return nil
	}
	keys := make([]string, 0, len(e.Conditions))
	for key := range e.Conditions {
		if !isConditionKey(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func isConditionKey(key string) bool {
	for _, k := range conditionKeys {
		if k == key {
			return true
		}
	}
	return false
}

// Validate 校验规则的必填项与选择器可解析性。
//
// 校验放在构造/加载期而不是判定期：一条写错的选择器如果到判定期才发现，
// 效果是静默不命中，于是默认拒绝 —— 现场会表现为「配了策略但没生效」。
func (e Entitlement) Validate() error {
	if strings.TrimSpace(e.Subject) == "" {
		return fmt.Errorf("%w: subject 不能为空", ErrEntitlement)
	}
	if strings.TrimSpace(e.Resource) == "" {
		return fmt.Errorf("%w: resource 不能为空", ErrEntitlement)
	}
	if strings.TrimSpace(e.Action) == "" {
		return fmt.Errorf("%w: action 不能为空", ErrEntitlement)
	}
	if !e.Effect.Valid() {
		return fmt.Errorf("%w: %q", ErrEffect, string(e.Effect))
	}
	if _, err := ParseScopeSelector(e.Scope); err != nil {
		return err
	}
	if !matchPatternsValid(e.Resource, e.Action) {
		return fmt.Errorf("%w: 通配只允许出现在尾部（如 model:*）", ErrEntitlement)
	}
	for _, key := range []string{CondMaxDataLevel, CondMinDataLevel} {
		if v, ok := e.Conditions[key]; ok {
			if _, err := ParseDataLevel(v); err != nil {
				return err
			}
		}
	}
	if unknown := e.unknownConditionKeys(); len(unknown) > 0 {
		return fmt.Errorf("%w: 条件键 %q 不是保留键，这条规则永远不会命中（可用键：%s）",
			ErrEntitlement, strings.Join(unknown, ", "), strings.Join(conditionKeys, ", "))
	}
	kind, value, err := parseSubjectSelector(e.Subject)
	if err != nil {
		return err
	}
	// project:/organization: 的取值必须是合法范围 ID：判定阶段是拿它去比范围链，
	// 形态写错（含冒号、含空白、超长）的规则永远匹配不上，而「配了却不生效」正是
	// 上面那句注释要排除的情形 —— 选择器能解析不代表取值能命中。
	if scopeKind, isScope := selectorScopeKind(kind); isScope {
		if _, err := NewScopeRef(scopeKind, value); err != nil {
			return fmt.Errorf("%w: 主体选择器 %q 的取值不是合法的%s ID: %v",
				ErrEntitlement, e.Subject, scopeKind, err)
		}
	}
	return nil
}

// selectorScopeKind 把主体选择器类型映射到它比较的范围类型。
// role/group 返回 false：那两类比的是 Identity 里的 claim 原值，不是结构化范围。
func selectorScopeKind(kind selectorKind) (ScopeKind, bool) {
	switch kind {
	case selectorProject:
		return ScopeProject, true
	case selectorOrganization:
		return ScopeOrganization, true
	}
	return "", false
}

// selectorKind 是 subject 选择器的类型。
type selectorKind int

const (
	selectorSelf selectorKind = iota
	selectorAll
	selectorRole
	selectorGroup
	selectorProject
	selectorOrganization
)

// parseSubjectSelector 解析 §2.4 的主体选择器：
//
//   - 兜底档（default）
//     <subject>             精确主体（explicit_allow）
//     role:<r>              角色成员（group_allow）
//     group:<g>             组/部门成员（group_allow）
//     project:<p>           项目成员（group_allow）
//     organization:<o>      组织成员（group_allow）
//
// 裸 subject 不带前缀，因为外部 IdP 的 stable ID 形态千差万别，
// 而前缀选择器的关键字是封闭集合，不会与真实 ID 冲突。
func parseSubjectSelector(s string) (kind selectorKind, value string, err error) {
	s = strings.TrimSpace(s)
	if s == "*" {
		return selectorAll, "", nil
	}
	for _, p := range []struct {
		prefix string
		kind   selectorKind
	}{{"role:", selectorRole}, {"group:", selectorGroup}, {"project:", selectorProject}, {"organization:", selectorOrganization}} {
		if strings.HasPrefix(s, p.prefix) {
			value = strings.TrimSpace(s[len(p.prefix):])
			if value == "" {
				return 0, "", fmt.Errorf("%w: %q 缺少取值", ErrSubjectSelector, s)
			}
			return p.kind, value, nil
		}
		if strings.EqualFold(s, p.prefix) {
			return 0, "", fmt.Errorf("%w: %q 缺少取值", ErrSubjectSelector, s)
		}
	}
	if strings.Contains(s, ":") {
		return 0, "", fmt.Errorf("%w: 未知前缀 %q（可用：role:、group:、project:、organization:，或裸 subject、*）",
			ErrSubjectSelector, s)
	}
	if strings.ContainsAny(s, " \t") {
		return 0, "", fmt.Errorf("%w: 裸 subject 不能含空白", ErrSubjectSelector)
	}
	return selectorSelf, s, nil
}

// matchSubject 报告规则是否命中当前主体，并给出命中档位。
//
// 组织与项目一律走**结构化范围**（ctx 上的主归属 + 已解析出的范围链），不再看
// Identity.Projects 这类 claim 原值。理由：范围链是 §2.7 之后唯一的归属口径，
// 而 claim 原值是显示名 —— 把它当第二个关联键，就等于允许「IdP 里恰好叫
// <别人项目 ID>」的组命中这条规则，而这正是链上判定要排除的形态。
// 角色和组没有规范化过程（IdP 的角色名本身就是策略作者写的选择器取值），
// 所以那两个分支继续读 Identity 的成员关系。
//
// 比较用的 ScopeRef 直接拼字段而不过 NewScopeRef：加载期已经校验过取值形态
// （见 Validate），判定热路径上再做一次校验只会让一次求值多出 N 次字符串检查。
func (e Entitlement) matchSubject(ctx PolicyContext, chain ScopeChain) (Precedence, bool) {
	kind, value, err := parseSubjectSelector(e.Subject)
	if err != nil {
		return 0, false
	}
	switch kind {
	case selectorAll:
		return PrecedenceDefault, true
	case selectorSelf:
		if value == ctx.Identity.Subject {
			return PrecedenceExplicitAllow, true
		}
		return 0, false
	case selectorRole:
		if ctx.Identity.HasRole(value) {
			return PrecedenceGroupAllow, true
		}
		return 0, false
	case selectorGroup:
		if ctx.Identity.HasGroup(value) {
			return PrecedenceGroupAllow, true
		}
		return 0, false
	case selectorProject:
		if ctx.Project == value || chain.Includes(ScopeRef{Kind: ScopeProject, ID: value}) {
			return PrecedenceGroupAllow, true
		}
		return 0, false
	case selectorOrganization:
		if ctx.Organization == value || chain.Includes(ScopeRef{Kind: ScopeOrganization, ID: value}) {
			return PrecedenceGroupAllow, true
		}
		return 0, false
	}
	return 0, false
}

// matchPatternsValid 拒绝中间通配（如 `mo*del`）：只有 `*` 和以 `*` 结尾的形式合法。
// 中间通配的匹配语义不可预期，也不利于用前缀索引做规则审查。
func matchPatternsValid(resource, action string) bool {
	return patternValid(resource) && patternValid(action)
}

func patternValid(p string) bool {
	i := strings.IndexByte(p, '*')
	if i < 0 {
		return true
	}
	return i == len(p)-1 && strings.Count(p, "*") == 1
}

// matchWildcard 实现尾部通配匹配：pattern 为 "*" 或在末尾写 "xxx*"。
func matchWildcard(pattern, value string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == value
}

func (e Entitlement) matchesResource(resource string) bool {
	return matchWildcard(e.Resource, resource)
}

func (e Entitlement) matchesAction(action string) bool {
	return matchWildcard(e.Action, action)
}

// matchesChain 报告规则作用范围是否覆盖判定范围集合中的任一项。
//
// 覆盖任一即生效：组织级规则要在「用户 + 组织 + 项目」这类集合上参与判定，
// 而不是只在请求被当成组织范围时才生效。
func (e Entitlement) matchesChain(chain ScopeChain) bool {
	sel, err := ParseScopeSelector(e.Scope)
	if err != nil {
		return false
	}
	for _, s := range chain {
		if sel.Matches(s) {
			return true
		}
	}
	return false
}

// conditionsMet 检查 Conditions，返回 false 时给出原因码。
//
// 按 key 排序遍历：多条键同时不成立时，返回哪个原因码必须与 map 遍历顺序无关，
// 否则审计链每次抖动，回放就对不上。
func (e Entitlement) conditionsMet(ctx PolicyContext) (bool, Reason) {
	keys := make([]string, 0, len(e.Conditions))
	for key := range e.Conditions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		want := e.Conditions[key]
		switch key {
		case CondMaxDataLevel:
			ceiling, err := ParseDataLevel(want)
			if err != nil || ctx.DataLevel.Exceeds(ceiling) {
				return false, ReasonDataLevelDenied
			}
		case CondMinDataLevel:
			floor, err := ParseDataLevel(want)
			if err != nil || !ctx.DataLevel.AtLeast(floor) {
				return false, ReasonDataLevelDenied
			}
		case CondRole:
			if !ctx.Identity.HasRole(want) {
				return false, ReasonConditionUnmet
			}
		case CondGroup:
			if !ctx.Identity.HasGroup(want) {
				return false, ReasonConditionUnmet
			}
		case CondAuthMethod:
			if !ctx.Identity.HasAuthMethod(want) {
				return false, ReasonConditionUnmet
			}
		case CondPurpose:
			if ctx.Purpose != want {
				return false, ReasonConditionUnmet
			}
		case CondOrganization:
			if ctx.Organization != want {
				return false, ReasonConditionUnmet
			}
		case CondProject:
			if ctx.Project != want {
				return false, ReasonConditionUnmet
			}
		case CondSource:
			if ctx.Identity.Source != want {
				return false, ReasonConditionUnmet
			}
		case CondDataLevel:
			if ctx.DataLevel.String() != want {
				return false, ReasonConditionUnmet
			}
		default:
			// 未知键一律不满足（fail-closed）。新增事实必须走本包的保留键扩展，
			// 并升级策略版本 —— 不允许各包自行往 Conditions 里塞私有键。
			return false, ReasonConditionUnmet
		}
	}
	return true, ""
}

// expired 报告规则在 now 时刻是否已失效。ExpiresAt 为零值表示长期有效
// （系统级默认策略通常不带过期时间）；主体成员关系的 TTL 由 Identity 自己带。
func (e Entitlement) expired(now time.Time) bool {
	return !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt)
}

// SortKey 给出同档命中多条时的稳定 tiebreaker：主体、资源、动作、版本。
//
// 判定结果不能依赖规则数组的书写顺序（否则同一条 deny 挪动位置就会改变结论），
// 所以 Resolver 先按档位、再按这个键选出确定的一条。
func (e Entitlement) SortKey() string {
	return strings.Join([]string{e.Subject, e.Resource, e.Action, e.Version}, "|")
}
