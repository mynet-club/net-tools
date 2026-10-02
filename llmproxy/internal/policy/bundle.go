package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// PolicyBundle 是一组带版本的策略内容（§3.0）。
//
// bundle id + version 就是策略内容版本，它进 RoutingPlan.PolicyVersion、
// 进审计、也是回放的输入之一。它和 config_schema_version 是两码事：
// 后者是配置文件结构版本，只用于加载与迁移校验。
type PolicyBundle struct {
	ID           string        `json:"id"`
	Version      int           `json:"version"`
	Scope        ScopeRef      `json:"scope"`
	Entitlements []Entitlement `json:"entitlements,omitempty"`
}

var (
	ErrBundle          = errors.New("policy: 策略包不合法")
	ErrBundleDuplicate = errors.New("policy: 策略包重复")
	ErrBundleEmpty     = errors.New("policy: 没有可用的策略包")
)

// Validate 校验策略包。Version 从 1 起：0 会让「未填」和「第 0 版」无法区分，
// 而回放要靠版本号确认加载的是同一份内容。
func (b PolicyBundle) Validate() error {
	if strings.TrimSpace(b.ID) == "" {
		return fmt.Errorf("%w: id 不能为空", ErrBundle)
	}
	if strings.ContainsAny(b.ID, "|@") {
		return fmt.Errorf("%w: id 不能含 | 或 @，它们是分节符", ErrBundle)
	}
	if b.Version < 1 {
		return fmt.Errorf("%w: version 需要 ≥ 1，当前 %d", ErrBundle, b.Version)
	}
	if err := b.Scope.Validate(); err != nil {
		return err
	}
	for i, e := range b.Entitlements {
		if err := e.Validate(); err != nil {
			// 序号从 1 起，并带上 resource：一个包里的规则常常都是 subject=*，
			// 只报主体等于没报，改配置的人得能在文本里认出自己写的那一条。
			return fmt.Errorf("%w: 第 %d 条规则（subject=%s resource=%s）: %v",
				ErrBundle, i+1, e.Subject, e.Resource, err)
		}
	}
	return nil
}

// Stamp 返回 `id@version`，用于审计与版本串。
func (b PolicyBundle) Stamp() string {
	return fmt.Sprintf("%s@%d", b.ID, b.Version)
}

// Covers 报告本包是否作用于范围集合中的任一项。
//
// system 包对任意集合生效；其余包必须精确命中集合里的某个范围，
// 不会「因为项目属于该组织」就自动生效 —— 父子归属由各适配器展开成
// 完整 chain 传进来，本包不猜层级。
func (b PolicyBundle) Covers(chain ScopeChain) bool {
	if b.Scope.Kind == ScopeSystem {
		return true
	}
	return chain.Includes(b.Scope)
}

// BundleSet 是实际加载的策略包集合，PolicyVersion 的唯一来源。
//
// 集合内部分两个维度：按范围筛选子集、按固定顺序产出规则并集。
// 顺序固定是刻意的 —— 版本串要能在另一台机器上逐位复现，才能拿它做回放输入。
type BundleSet struct {
	bundles []PolicyBundle
}

// NewBundleSet 构造集合并做校验：包必须合法，且不允许同一个 id 出现两个版本
// （那意味着加载逻辑出错了，而不是「策略叠加」）。
func NewBundleSet(bundles ...PolicyBundle) (*BundleSet, error) {
	seen := map[string]bool{}
	sorted := append([]PolicyBundle(nil), bundles...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Scope.Less(sorted[j].Scope) {
			return true
		}
		if sorted[j].Scope.Less(sorted[i].Scope) {
			return false
		}
		return sorted[i].ID < sorted[j].ID
	})
	for _, b := range sorted {
		if err := b.Validate(); err != nil {
			return nil, err
		}
		if seen[b.ID] {
			return nil, fmt.Errorf("%w: %s 出现了多个版本", ErrBundleDuplicate, b.ID)
		}
		seen[b.ID] = true
	}
	return &BundleSet{bundles: sorted}, nil
}

// MustBundleSet 只用于测试和内置样例。
func MustBundleSet(bundles ...PolicyBundle) *BundleSet {
	s, err := NewBundleSet(bundles...)
	if err != nil {
		panic(err)
	}
	return s
}

// Len 返回包数量。
func (s *BundleSet) Len() int { return len(s.bundles) }

// Bundles 返回包列表的稳定副本（已按范围、ID 排序）。
func (s *BundleSet) Bundles() []PolicyBundle {
	return append([]PolicyBundle(nil), s.bundles...)
}

// PolicyVersion 是 §3.0 要求的策略内容版本串：所有生效包的 `id@version` 按稳定顺序
// 用 `|` 连接。空集合返回错误而不是空串 —— 空串会让审计里出现「无版本决策」，
// 事后无法判定当时加载的是哪套规则。
func (s *BundleSet) PolicyVersion() (string, error) {
	if s == nil || len(s.bundles) == 0 {
		return "", ErrBundleEmpty
	}
	parts := make([]string, 0, len(s.bundles))
	for _, b := range s.bundles {
		parts = append(parts, b.Stamp())
	}
	return strings.Join(parts, "|"), nil
}

// EntitlementsFor 返回覆盖范围集合的规则并集，按 SortKey 稳定排序。
//
// 这里只做并集，不做优先级：优先级唯一地由 Resolver 按 deny > explicit > group > default
// 决定。任何调用方自己想「先取组织包再取系统包」的合并都是第二套业务规则，禁止。
func (s *BundleSet) EntitlementsFor(chain ScopeChain) []Entitlement {
	var out []Entitlement
	for _, b := range s.bundles {
		if !b.Covers(chain) {
			continue
		}
		out = append(out, b.Entitlements...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].SortKey() < out[j].SortKey() })
	return out
}

// Filter 返回覆盖范围集合的子集，用于按 scope 出具版本串。
func (s *BundleSet) Filter(chain ScopeChain) (*BundleSet, error) {
	var sub []PolicyBundle
	for _, b := range s.bundles {
		if b.Covers(chain) {
			sub = append(sub, b)
		}
	}
	if len(sub) == 0 {
		return nil, fmt.Errorf("%w: 范围 %s 没有匹配的策略包", ErrBundleEmpty, chain.Display())
	}
	return &BundleSet{bundles: sub}, nil
}
