package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ScopeKind 是范围类型。取值固定为下面四种。
//
// 新增类型属于破坏性变更：要走主线评审、同步迁移 store 的 scope_kind 取值校验，
// 并升级 config_schema_version —— 各包不得自行扩充。
type ScopeKind string

const (
	ScopeUser         ScopeKind = "user"
	ScopeOrganization ScopeKind = "organization"
	ScopeProject      ScopeKind = "project"
	ScopeSystem       ScopeKind = "system"
)

// maxScopeIDLen 是 scope ID 的长度上限。
// 这个值同时是数据库主键列的一部分，留足余量又必须有上限，否则索引宽度不可控。
const maxScopeIDLen = 256

// ScopeRef 是结构化范围引用（§2.7）。
//
// 落库一律拆成 scope_kind + scope_id 两列；Display() 的结果只能进日志和界面，
// 禁止把它当主键、外键或路由桶的键 —— 3.0 不保留旧 scope == 用户名的字符串拼接。
type ScopeRef struct {
	Kind ScopeKind `json:"kind"`
	ID   string    `json:"id"`
}

// SystemScope 是全局配置（系统池供应商、默认策略）所属的范围。
var SystemScope = ScopeRef{Kind: ScopeSystem, ID: "global"}

var (
	ErrScopeKind      = errors.New("policy: 未知的 scope 类型")
	ErrScopeID        = errors.New("policy: scope ID 不合法")
	ErrScopeIDTooLong = errors.New("policy: scope ID 超长")
)

// NewScopeRef 构造并校验一个范围引用。
func NewScopeRef(kind ScopeKind, id string) (ScopeRef, error) {
	s := ScopeRef{Kind: kind, ID: id}
	if err := s.Validate(); err != nil {
		return ScopeRef{}, err
	}
	return s, nil
}

// MustScope 是给测试和内置样例用的构造器：非法时 panic。
// 只允许用于编译期就能确定合法的常量，运行期输入走 NewScopeRef。
func MustScope(kind ScopeKind, id string) ScopeRef {
	s, err := NewScopeRef(kind, id)
	if err != nil {
		panic(err)
	}
	return s
}

// Valid 报告类型是否在固定取值集合内。
func (k ScopeKind) Valid() bool {
	switch k {
	case ScopeUser, ScopeOrganization, ScopeProject, ScopeSystem:
		return true
	}
	return false
}

// ParseScopeKind 解析 scope 类型字符串，未知取值给出可读错误（而不是静默回落到 user）。
func ParseScopeKind(s string) (ScopeKind, error) {
	k := ScopeKind(strings.TrimSpace(s))
	if !k.Valid() {
		return "", fmt.Errorf("%w: %q（可用值：user、organization、project、system）", ErrScopeKind, s)
	}
	return k, nil
}

// Validate 校验范围引用。ID 禁止含冒号与空白字符：
// Display() 用冒号分隔 kind 和 ID，含冒号会让日志里的范围无法唯一还原；
// 含空白则会让主键在大小写/空格清洗后产生重复行。
func (s ScopeRef) Validate() error {
	if !s.Kind.Valid() {
		return fmt.Errorf("%w: %q", ErrScopeKind, string(s.Kind))
	}
	if s.ID == "" {
		return fmt.Errorf("%w: 不能为空", ErrScopeID)
	}
	if len(s.ID) > maxScopeIDLen {
		return fmt.Errorf("%w: %d 字节，上限 %d", ErrScopeIDTooLong, len(s.ID), maxScopeIDLen)
	}
	if strings.TrimSpace(s.ID) != s.ID {
		return fmt.Errorf("%w: 首尾不能是空白字符", ErrScopeID)
	}
	for i := 0; i < len(s.ID); i++ {
		c := s.ID[i]
		if c == ':' || c < 0x20 || c == 0x7f {
			return fmt.Errorf("%w: 不能含冒号或控制字符", ErrScopeID)
		}
	}
	return nil
}

// Display 返回人类可读形式，仅用于日志与界面。
func (s ScopeRef) Display() string {
	return string(s.Kind) + ":" + s.ID
}

// Is 报告是否指向同一个范围。ScopeRef 只有字符串字段，可直接用 == 比较，
// 这里提供方法是为了读起来清楚。
func (s ScopeRef) Is(o ScopeRef) bool { return s == o }

// Less 给出跨进程稳定的排序键：先类型后 ID。
//
// 路由候选、审计记录和回放输入都依赖这个顺序，绝不能依赖 map 遍历顺序（§2.8）。
func (s ScopeRef) Less(o ScopeRef) bool {
	if s.Kind != o.Kind {
		return s.Kind < o.Kind
	}
	return s.ID < o.ID
}

// ScopeSelector 是 Entitlement.Scope 里的选择器形式，三者之一：
//
//   - 匹配任何范围
//     kind:*           匹配某个类型下的所有范围
//     kind:id          精确匹配
//
// 注意它不是 ScopeRef：选择器可以带通配，不能当存储键。
type ScopeSelector struct {
	Kind    ScopeKind // 空 = 通配全部
	KindAny bool
	ID      string // "*" 或具体 ID
	All     bool
}

var ErrScopeSelector = errors.New("policy: scope 选择器格式错误")

// ParseScopeSelector 解析选择器。空串按通配处理（策略不写 scope 就是对所有范围生效）。
func ParseScopeSelector(s string) (ScopeSelector, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return ScopeSelector{All: true}, nil
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		kind, err := ParseScopeKind(s[:i])
		if err != nil {
			return ScopeSelector{}, err
		}
		id := s[i+1:]
		if id == "" {
			return ScopeSelector{}, fmt.Errorf("%w: %q 缺少 ID 部分", ErrScopeSelector, s)
		}
		return ScopeSelector{Kind: kind, ID: id}, nil
	}
	// 不带类型前缀的选择器只可能是通配；其余一律拒绝，避免把裸用户名的歧义
	// 形式重新引入 —— 那正是 3.0 要一次性清掉的旧包袱。
	return ScopeSelector{}, fmt.Errorf("%w: %q 需要写成 kind:id 或 *", ErrScopeSelector, s)
}

// Matches 报告选择器是否覆盖给定范围。
func (sel ScopeSelector) Matches(s ScopeRef) bool {
	if sel.All {
		return true
	}
	if sel.Kind != s.Kind {
		return false
	}
	return sel.ID == "*" || sel.ID == s.ID
}

// ScopeChain 是一次判定所覆盖的范围集合。
//
// 一个请求同时落在多个范围里：使用者（user:alice）、所属组织（organization:university）、
// 所在项目（project:proj-lab-7）。只传单个范围会让组织级、项目级策略永远不生效 ——
// 传集合才是 §2.7「结构化 scope」的正确用法：规则命中集合中任一范围即参与判定，
// 优先级仍由 Resolver 唯一地按 deny > explicit_allow > group_allow > default 决定。
//
// 至少要包含用户范围；system 类型的策略包对任意集合都生效，不需要调用方显式传。
type ScopeChain []ScopeRef

// NewScopeChain 校验、去重并按稳定顺序排序范围集合。
func NewScopeChain(scopes ...ScopeRef) (ScopeChain, error) {
	if len(scopes) == 0 {
		return nil, fmt.Errorf("%w: 判定至少需要一个范围", ErrScopeID)
	}
	seen := make(map[ScopeRef]bool, len(scopes))
	out := make(ScopeChain, 0, len(scopes))
	for _, s := range scopes {
		if err := s.Validate(); err != nil {
			return nil, err
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sortScopes(out)
	return out, nil
}

// MustScopeChain 只用于测试与内置样例。
func MustScopeChain(scopes ...ScopeRef) ScopeChain {
	chain, err := NewScopeChain(scopes...)
	if err != nil {
		panic(err)
	}
	return chain
}

// UserChain 构造「只有用户范围」的集合，是最常见的形态。
func UserChain(userID string) (ScopeChain, error) {
	user, err := NewScopeRef(ScopeUser, userID)
	if err != nil {
		return nil, err
	}
	return ScopeChain{user}, nil
}

// Includes 报告集合里是否已有某个范围。
func (c ScopeChain) Includes(s ScopeRef) bool {
	for _, item := range c {
		if item.Is(s) {
			return true
		}
	}
	return false
}

// Display 供日志使用，禁止当存储键。
func (c ScopeChain) Display() string {
	parts := make([]string, 0, len(c))
	for _, s := range c {
		parts = append(parts, s.Display())
	}
	return strings.Join(parts, ",")
}

func sortScopes(scopes []ScopeRef) {
	sort.SliceStable(scopes, func(i, j int) bool { return scopes[i].Less(scopes[j]) })
}
