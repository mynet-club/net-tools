package config

// 本文件是 §3.0 的 3.0 接线配置块：config_schema_version + policy 段。
//
// 为什么单独一个文件：policy 块是「3.0 是否参与这次请求」的唯一开关，
// 它和 providers/routing 那套 2.x 静态路由是两套并行语义，读配置的人需要一眼
// 看出边界在哪。接线（shadow → enforce → 全量替换）全部以这里解析出的
// Mode/ActiveBundle 为准，任何 handler 都不许自己拼 policy version。

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 配置文件结构版本（不是策略内容版本）。
const (
	// SchemaVersionLegacy 是 2.x 起的配置形态。现存配置一律没写
	// config_schema_version，缺省必须按 2 处理 —— 让老配置读不出来
	// 就等于用一次升级把所有实例停掉。
	SchemaVersionLegacy = 2
	// SchemaVersion3 是引入 policy 块之后的结构版本。
	SchemaVersion3 = 3
)

// PolicyMode 是 3.0 的接线模式（§3.0 三阶段）。
type PolicyMode string

const (
	// PolicyModeShadow：解析身份、策略与候选计划，但**不改变**实际 provider，
	// 也不读正文；只记差异与耗时。影子模式必须产出 policy version，
	// 否则事后想复现「当时算出了什么」就没有依据。
	PolicyModeShadow PolicyMode = "shadow"
	// PolicyModeEnforce：新策略允许影响路由与处理器。
	PolicyModeEnforce PolicyMode = "enforce"
	// PolicyModeLegacy：完全沿用现有 provider 路由，3.0 不参与。
	PolicyModeLegacy PolicyMode = "legacy"
)

func (m PolicyMode) String() string { return string(m) }

// PolicyBundleRef 是配置里的一个策略包**引用**：id + version + 生效范围。
//
// 这里刻意不含授权内容（entitlements）：内容是 H 的存储/发布流程持有的，
// 配置只负责「加载哪一版、作用在哪个范围」。把内容也塞进配置会让策略发布
// 出现两个真值来源（文件与库），版本回滚时两者会互相打脸。
type PolicyBundleRef struct {
	ID      string `yaml:"id"`
	Version int    `yaml:"version"`
	Scope   string `yaml:"scope"`
}

// PolicyConfig 是 policy 段。
type PolicyConfig struct {
	// Mode 是接线模式；缺省（整段不写）等价于 legacy。
	Mode string `yaml:"mode"`
	// ActiveBundle 指向 bundles 里生效的那一条（按 id）。
	ActiveBundle string `yaml:"active_bundle"`
	// FallbackToLegacy 报告 3.0 算不出可用计划时是否回落旧路由。
	// 缺省 true：§3.0 要求「任何新路径都必须可以按 scope 回滚到 legacy」，
	// 关掉它是显式的 fail-closed 决定，只在 enforce 下有意义。
	FallbackToLegacy *bool             `yaml:"fallback_to_legacy"`
	Bundles          []PolicyBundleRef `yaml:"bundles"`

	// --- 加载期解析出的派生值，运行期只读 ---
	mode      PolicyMode
	refIndex  map[string]PolicyBundleRef
	scopeRefs map[string]policy.ScopeRef
}

// ModeResolved 返回接线模式（加载期已定值，未加载时按 legacy）。
func (p *PolicyConfig) ModeResolved() PolicyMode {
	if p == nil || p.mode == "" {
		return PolicyModeLegacy
	}
	return p.mode
}

// UsesPolicy 报告 3.0 是否参与本次请求（shadow 也算参与，只是不改路由）。
func (p *PolicyConfig) UsesPolicy() bool { return p.ModeResolved() != PolicyModeLegacy }

// EnforcesPolicy 报告是否允许 3.0 的计划影响路由与处理器。
func (p *PolicyConfig) EnforcesPolicy() bool { return p.ModeResolved() == PolicyModeEnforce }

// PolicyVersion 是 RoutingPlan.PolicyVersion 的**唯一**来源：
// 实际加载的那一版策略包，形态 id@version。legacy 或未加载时返回空串 ——
// 空串表示「本次没有策略版本」，它比编一个 "legacy@0" 诚实：
// 回放时看到空就知道当时根本没有 3.0 判定。
func (p *PolicyConfig) PolicyVersion() string {
	if p == nil || !p.UsesPolicy() {
		return ""
	}
	ref, ok := p.ActiveRef()
	if !ok {
		return ""
	}
	return fmt.Sprintf("%s@%d", ref.ID, ref.Version)
}

// ActiveRef 返回生效中的那条引用。
func (p *PolicyConfig) ActiveRef() (PolicyBundleRef, bool) {
	if p == nil {
		return PolicyBundleRef{}, false
	}
	ref, ok := p.refIndex[strings.TrimSpace(p.ActiveBundle)]
	return ref, ok
}

// ActiveScope 返回生效策略包的作用范围。
func (p *PolicyConfig) ActiveScope() (policy.ScopeRef, bool) {
	ref, ok := p.ActiveRef()
	if !ok {
		return policy.ScopeRef{}, false
	}
	s, ok := p.scopeRefs[ref.ID]
	return s, ok
}

// FallbackToLegacyEnabled 报告 3.0 失败时是否允许回落旧路由（缺省 true）。
func (p *PolicyConfig) FallbackToLegacyEnabled() bool {
	if p == nil || p.FallbackToLegacy == nil {
		return true
	}
	return *p.FallbackToLegacy
}

// KnownScopes 是「目录里确实存在的范围」这个能力。
//
// 用接口而不是直接引 internal/identity 的类型：配置包不该知道目录怎么实现
// （OIDC、LDAP 还是静态表），而 §5 要求包之间靠小接口通信。
// 传 nil 表示本次加载没有目录可对照，lint 跳过。
type KnownScopes interface {
	HasScope(policy.ScopeRef) bool
}

// LintScopes 把每个引用范围与目录的规范 ID 集对照，返回告警（不是错误）。
//
// 为什么只 warn：范围不存在于目录时，最可能的原因是目录还没同步完（HR 系统
// 凌晨推数），把整个配置加载失败会让网关在同步窗口里直接起不来。
// 但必须说出来 —— 静默接受一个拼错的 organization id，等于那条策略永远不生效，
// 运维却在审计里看不到任何痕迹。
func (p *PolicyConfig) LintScopes(known KnownScopes) []string {
	if p == nil || known == nil {
		return nil
	}
	var out []string
	for _, ref := range p.Bundles {
		s, ok := p.scopeRefs[ref.ID]
		if !ok {
			continue
		}
		if known.HasScope(s) {
			continue
		}
		out = append(out, fmt.Sprintf(
			"policy.bundles 里 %s 的范围 %s 不在目录的已知范围内 —— 该包不会命中任何请求（检查拼写，或先同步目录）",
			ref.ID, s.Display()))
	}
	return out
}

// normalize 校验并派生 policy 段。由 Config.normalize 调用。
func (p *PolicyConfig) normalize(known KnownScopes, warnings *[]string) error {
	if p == nil {
		return nil
	}
	mode := strings.TrimSpace(p.Mode)
	active := strings.TrimSpace(p.ActiveBundle)
	if mode == "" && len(p.Bundles) == 0 && active == "" {
		// 整段缺省：legacy。这是唯一能保证「升级二进制不动配置」的取值。
		p.mode = PolicyModeLegacy
		return nil
	}
	switch PolicyMode(mode) {
	case PolicyModeShadow, PolicyModeEnforce, PolicyModeLegacy:
		p.mode = PolicyMode(mode)
	case "":
		// 配了 bundle 却没写 mode：不能替它猜。猜 legacy 会让这些包静默不生效，
		// 猜 shadow 会让人以为差异报告已经有了。
		return fmt.Errorf("policy.mode 必须显式写 shadow、enforce 或 legacy（已配置 policy.bundles，不能省略）")
	default:
		return fmt.Errorf("policy.mode 是 %q，只能是 shadow、enforce 或 legacy", p.Mode)
	}

	if p.mode == PolicyModeLegacy {
		// legacy 下 active_bundle/bundles 不参与判定，但也不报错：回滚开关要能
		// 「改成 legacy 就立刻停」，删掉整段配置不该成为回滚的前置动作。
		if len(p.Bundles) > 0 {
			*warnings = append(*warnings,
				"policy.mode=legacy，已配置的 policy.bundles 不会生效（回滚期间的正常状态）")
		}
		p.refIndex = nil
		return nil
	}

	if len(p.Bundles) == 0 {
		return fmt.Errorf("policy.mode=%s 时必须配置至少一个 policy.bundles 条目，否则没有任何策略内容版本可审计", p.mode)
	}
	if active == "" {
		return fmt.Errorf("policy.mode=%s 时必须写 policy.active_bundle（策略版本是审计与回放的输入，不能由 handler 临时拼）", p.mode)
	}

	refIndex := make(map[string]PolicyBundleRef, len(p.Bundles))
	scopeRefs := make(map[string]policy.ScopeRef, len(p.Bundles))
	ids := make([]string, 0, len(p.Bundles))
	for i, ref := range p.Bundles {
		id := strings.TrimSpace(ref.ID)
		label := fmt.Sprintf("policy.bundles[%d]", i)
		if id == "" {
			label += "（id 为空）"
		} else {
			label += "（id=" + id + "）"
		}
		// 规则不在这里重抄：构造一个只带引用的 policy.PolicyBundle 交给领域包校验，
		// 这样 id 的分隔符约束、version ≥ 1、范围格式都只有 policy 包一份定义
		//（§5「领域对象属于所属包」）。授权内容由 H 补，这里为空是合法的。
		s, err := parseConfigScope(ref.Scope)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if err := (policy.PolicyBundle{ID: id, Version: ref.Version, Scope: s}).Validate(); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if _, dup := refIndex[id]; dup {
			return fmt.Errorf("policy.bundles 里 id=%s 出现多次（同一 id 只能有一版；发新版请改名或走 H 的版本发布）", id)
		}
		refIndex[id] = ref
		scopeRefs[id] = s
		ids = append(ids, id)
	}
	if _, ok := refIndex[active]; !ok {
		sort.Strings(ids)
		return fmt.Errorf("policy.active_bundle=%q 不在 policy.bundles 里（可用：%s）",
			p.ActiveBundle, strings.Join(ids, "、"))
	}
	if p.FallbackToLegacy != nil && !*p.FallbackToLegacy && p.mode == PolicyModeShadow {
		// shadow 不改路由，这个开关在影子模式下没有任何作用点。
		// 留着它会让配置看起来像「影子也 fail-closed」，而真出事时才发现
		// 关掉的语义在 legacy 那条路上根本执行不到。
		return fmt.Errorf("policy.mode=shadow 时 fallback_to_legacy 无意义（影子模式不改变 provider，请删掉该字段或设为 true）")
	}
	p.refIndex = refIndex
	p.scopeRefs = scopeRefs
	for _, warn := range p.LintScopes(known) {
		*warnings = append(*warnings, warn)
	}
	return nil
}

// parseConfigScope 把 "organization:university" 这样的配置值解析成范围引用。
func parseConfigScope(raw string) (policy.ScopeRef, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return policy.ScopeRef{}, fmt.Errorf("scope 不能为空（必须写成 kind:id，例如 organization:university）")
	}
	kindPart, idPart, found := strings.Cut(v, ":")
	if !found {
		return policy.ScopeRef{}, fmt.Errorf("scope %q 需要写成 kind:id（organization:university、project:cs-lab-7、user:alice）", v)
	}
	kind, err := policy.ParseScopeKind(kindPart)
	if err != nil {
		return policy.ScopeRef{}, err
	}
	return policy.NewScopeRef(kind, idPart)
}
