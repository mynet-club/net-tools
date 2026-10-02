package config

// 本文件是 §3.H 的**声明表**：处理器（processors）与知识源（knowledge_sources）。
//
// 为什么单独成文而不是塞进 config.go：这两段是 3.0 的面，它们和 providers 那种
// 2.x 静态路由没有关系，读配置的人需要一眼看出「这里声明的是约束，不是接线」。
//
// 三段边界（与本包 policy30.go 同一套取舍）：
//  1. **规则不在这里重抄**。每个条目的合法性交给所属领域包判：处理器交给
//     processor.Spec.Validate()（阶段闭集、档位与类型的一致性、绝对上限、白名单形态），
//     知识源交给 knowledge 的端点与知识库 ID 规则。配置层自己写一遍 URL 校验，
//     就会出现「配置认得而运行时拒收」这种两头都对不上的错。
//  2. **这里只声明，不运行**。处理器的运行参数（脱敏规则表、JSON Schema、sidecar 的
//     HTTP 客户端与原文出网授权判定器）由注册期绑定，E 包明确写了「cfg 在这里绑定
//     而不是 Build 时传入」；知识源的 transport 必须由接线方从出网策略里注入。
//     把这两样塞进配置文件等于让配置成为第二个真值来源，而且密钥会跟着进文件。
//  3. **必填项不留隐含默认**。body_access、fail_closed、scope、两个字节上限与超时
//     都要求显式写：这些字段每一项都直接决定「正文会不会离开网关」「失败时放行还是拒」。
//     缺省值在这类字段上不是便利，是把一次漏配变成一次静默的宽松放行（同一个理由见
//     policy.data_level 不给缺省）。

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/knowledge"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/processor"
)

// maxSourceNameLen 是知识源名字的长度上限。与 processor.MaxNameLen 同值但不是引它的规则：
// 那条管的是处理器标识符（进策略资源名），这条管的是配置文件里的一个键。
const maxSourceNameLen = 128

// ProcessorDef 是 processors 段里的一条声明。
//
// 字段是 processor.Spec 的配置文件形态：超时用毫秒整数（与 providers[].timeout_ms 同形，
// 配置文件里写 "800ms" 这种带单位的串会让 YAML 把它读成字符串而加载器按 int 取），
// 档位与阶段用字符串（构造 Spec 时才转成领域包的封闭枚举）。
//
// 同时带 json tag：管理 API 的请求体就是这一份结构（§9 的「H 只能调用服务端策略接口」
// 要求界面与配置文件看到的是同一套字段名）。复制一份 DTO 到 server 包，
// 就会出现「加了字段只加了一边」这种两边都对不上的错。
type ProcessorDef struct {
	Name             string   `yaml:"name" json:"name"`
	Type             string   `yaml:"type" json:"type"`
	Phase            string   `yaml:"phase" json:"phase"`
	Scope            string   `yaml:"scope" json:"scope"`
	TimeoutMs        int      `yaml:"timeout_ms" json:"timeout_ms"`
	MaxInputBytes    int64    `yaml:"max_input_bytes" json:"max_input_bytes"`
	MaxOutputBytes   int64    `yaml:"max_output_bytes" json:"max_output_bytes"`
	FailClosed       *bool    `yaml:"fail_closed" json:"fail_closed"`
	BodyAccess       string   `yaml:"body_access" json:"body_access"`
	AllowRawBody     bool     `yaml:"allow_raw_body" json:"allow_raw_body,omitempty"`
	AllowedEndpoints []string `yaml:"allowed_endpoints" json:"allowed_endpoints,omitempty"`
	Version          string   `yaml:"version" json:"version"`
}

// KnowledgeSourceDef 是 knowledge_sources 段里的一条声明（json tag 同上）。
type KnowledgeSourceDef struct {
	Name             string   `yaml:"name" json:"name"`
	Endpoint         string   `yaml:"endpoint" json:"endpoint"`
	KnowledgeBases   []string `yaml:"knowledge_bases" json:"knowledge_bases"`
	TimeoutMs        int      `yaml:"timeout_ms" json:"timeout_ms"`
	MaxResponseBytes int64    `yaml:"max_response_bytes" json:"max_response_bytes"`
}

// Spec 把配置条目还原成领域对象，并当场跑一遍领域校验。
//
// 三处刻意比 Spec.Validate 更严：body_access、fail_closed、scope 都要求显式写。
// ParseBodyAccess 把空串落到 metadata-only（那是**请求上下文**的默认档，那里有调用方
// 兜着），配置里留空则意味着「忘了写」；而 metadata-only 对 pii-mask 直接不合法，
// 于是漏配的表现是一条错误信息指认档位选错，没人会想到其实是没写。
func (d ProcessorDef) Spec() (processor.Spec, error) {
	access := strings.TrimSpace(d.BodyAccess)
	if access == "" {
		return processor.Spec{}, fmt.Errorf("body_access 必须显式写成 metadata-only、inspect-body 或 transform-body" +
			"（这一档决定处理器能不能读正文、能不能改写正文，不能靠缺省）")
	}
	if d.FailClosed == nil {
		return processor.Spec{}, fmt.Errorf("fail_closed 必须显式写成 true 或 false" +
			"（§5 要求失败策略明确：true = 处理器出错就拒绝请求，false = 放行原文）")
	}
	scope := strings.TrimSpace(d.Scope)
	if scope == "" {
		return processor.Spec{}, fmt.Errorf("scope 必须显式写成 * 或 kind:id（不限范围要写成 *，留空会被读成漏配）")
	}
	if d.TimeoutMs <= 0 {
		return processor.Spec{}, fmt.Errorf("timeout_ms 必须为正（本包禁止 0 = 不限；上限 %d ms）",
			processor.MaxTimeout.Milliseconds())
	}
	phase, err := processor.ParsePhase(d.Phase)
	if err != nil {
		return processor.Spec{}, err
	}
	parsedAccess, err := policy.ParseBodyAccess(access)
	if err != nil {
		return processor.Spec{}, err
	}
	endpoints := make([]string, 0, len(d.AllowedEndpoints))
	for _, ep := range d.AllowedEndpoints {
		endpoints = append(endpoints, strings.TrimSpace(ep))
	}
	spec := processor.Spec{
		Name: strings.TrimSpace(d.Name), Type: strings.TrimSpace(d.Type),
		Phase: phase, Scope: scope,
		Timeout:          time.Duration(d.TimeoutMs) * time.Millisecond,
		MaxInputBytes:    d.MaxInputBytes,
		MaxOutputBytes:   d.MaxOutputBytes,
		FailClosed:       *d.FailClosed,
		BodyAccess:       parsedAccess,
		AllowRawBody:     d.AllowRawBody,
		AllowedEndpoints: endpoints,
		Version:          strings.TrimSpace(d.Version),
	}
	if err := spec.Validate(); err != nil {
		return processor.Spec{}, err
	}
	return spec, nil
}

// normalize 校验 processors 段，返回领域形态与「已声明但类型不认识」的告警。
//
// 类型不在内置五种里只 warn 不 error：processor 的类型集合**刻意不封闭**
// （RegisterType 允许部署追加自定义实现），配置层把它判死等于禁掉扩展能力。
// 但必须说出来 —— 内置类型拼错一个字母（pii-mak）会一路通过 Spec.Validate，
// 直到装配期才炸成「类型没有对应工厂」，而那时现场已经换了个人在看。
func (d ProcessorDef) normalize(knownTypes map[string]bool) (processor.Spec, string, error) {
	spec, err := d.Spec()
	if err != nil {
		return processor.Spec{}, "", err
	}
	warning := ""
	if knownTypes != nil && !knownTypes[spec.Type] {
		warning = fmt.Sprintf("处理器 %s 的类型 %q 不在内置类型里（%s）—— "+
			"自定义类型要由部署在注册期 RegisterType 注入，没注入时装配会失败",
			spec.Name, spec.Type, strings.Join(processorTypes(), "、"))
	}
	return spec, warning, nil
}

// processorTypes 返回内置类型名（顺序固定，供错误信息与界面提示用）。
//
// 取的是 NewRegistry 的已注册类型而不是手抄一张表：E 包加类型时这里自动跟上，
// 手抄的那份会变成「配置文档里的类型列表比运行时少一个」。
func processorTypes() []string {
	return processor.NewRegistry().KnownTypes()
}

// normalizeProcessors 校验整段声明并做名字去重。派生出的 Spec 切片按名字排序，
// 让「同一份意图写出同一份文本」这件事成立（§2.8 不依赖原始顺序的原则同样适用于配置）。
func (c *Config) normalizeProcessors() error {
	known := map[string]bool{}
	for _, t := range processorTypes() {
		known[t] = true
	}
	seen := map[string]bool{}
	specs := make([]processor.Spec, 0, len(c.Processors))
	for i, def := range c.Processors {
		label := fmt.Sprintf("processors[%d]", i)
		if strings.TrimSpace(def.Name) == "" {
			label += "（name 为空）"
		} else {
			label += "（name=" + strings.TrimSpace(def.Name) + "）"
		}
		spec, warning, err := def.normalize(known)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if seen[spec.Name] {
			return fmt.Errorf("processors 里 name=%s 出现多次（处理器名是注册表的键，重复会让「谁最后写」决定线上行为）", spec.Name)
		}
		seen[spec.Name] = true
		if warning != "" {
			c.Warnings = append(c.Warnings, warning)
		}
		specs = append(specs, spec)
	}
	sort.SliceStable(specs, func(i, j int) bool { return specs[i].Name < specs[j].Name })
	c.ProcessorSpecs = specs
	return nil
}

// normalizeKnowledgeSources 校验知识源段：端点必须过委托协议那一关，
// 知识库 ID 必须过 A/C 那一关，而两个源不许服务同一个库。
func (c *Config) normalizeKnowledgeSources() error {
	seenName := map[string]bool{}
	seenKB := map[string]string{}
	for i, src := range c.KnowledgeSources {
		label := fmt.Sprintf("knowledge_sources[%d]", i)
		name := strings.TrimSpace(src.Name)
		if name == "" {
			return fmt.Errorf("%s: name 不能为空（它是审计里区分多个委托入口的唯一标识）", label)
		}
		if len(name) > maxSourceNameLen {
			return fmt.Errorf("%s: name 长度 %d 超过上限 %d", label, len(name), maxSourceNameLen)
		}
		if strings.ContainsAny(name, " \t\r\n\x00/\\") {
			return fmt.Errorf("%s: name %q 不能含空白、换行或路径分隔符（它会进日志与审计字段，也需要能被原样查回来）", label, name)
		}
		if seenName[name] {
			return fmt.Errorf("knowledge_sources 里 name=%s 出现多次（同一名字的两个源无法在审计里分开）", name)
		}
		seenName[name] = true

		if _, err := knowledge.ValidateEndpoint(src.Endpoint); err != nil {
			return fmt.Errorf("%s（name=%s）: endpoint: %w", label, name, err)
		}
		if len(src.KnowledgeBases) == 0 {
			return fmt.Errorf("%s（name=%s）: knowledge_bases 不能为空 —— 一个不服务任何库的源是死配置，"+
				"而它仍然占着一个委托端点", label, name)
		}
		for _, raw := range src.KnowledgeBases {
			kb := strings.TrimSpace(raw)
			if err := knowledge.ValidateKnowledgeBaseID(kb); err != nil {
				return fmt.Errorf("%s（name=%s）: knowledge_bases: %w", label, name, err)
			}
			if owner, dup := seenKB[kb]; dup {
				return fmt.Errorf("知识库 %s 同时被 %s 与 %s 声明 —— 一次检索会打到两个委托入口，"+
					"而引用与审计都分不清是哪一篇来的", kb, owner, name)
			}
			seenKB[kb] = name
		}
		if src.TimeoutMs <= 0 {
			return fmt.Errorf("%s（name=%s）: timeout_ms 必须为正（兜底预算 %d ms，上限 MaxBudget %d ms）",
				label, name, knowledge.DefaultBudget.Milliseconds(), knowledge.MaxBudget.Milliseconds())
		}
		if time.Duration(src.TimeoutMs)*time.Millisecond > knowledge.MaxBudget {
			return fmt.Errorf("%s（name=%s）: timeout_ms %d 超过委托预算上限 %d ms"+
				"（超上限的预算会把连接池拖住，而调用方还以为只是检索慢）",
				label, name, src.TimeoutMs, knowledge.MaxBudget.Milliseconds())
		}
		if src.MaxResponseBytes <= 0 {
			return fmt.Errorf("%s（name=%s）: max_response_bytes 必须为正（§5 要求外部调用都有体积上限，0 不是不限）", label, name)
		}
	}
	return nil
}

// DeclVocabulary 是两段声明的**取值域与上限**，给管理台渲染下拉框用。
//
// 为什么由服务端下发而不是前端写死（§9「H 只能调用服务端策略接口，不能在前端重新计算」）：
// 阶段闭集、绝对上限、内置类型这三样都是领域包的事实，前端抄一份就会在领域包扩充那天
// 变成「界面上选不到、配置里其实能写」。前端拿它只用于提示与预填，判定仍在服务端。
type DeclVocabulary struct {
	ProcessorTypes       []string `json:"processor_types"`
	Phases               []string `json:"phases"`
	BodyAccesses         []string `json:"body_accesses"`
	ScopeKinds           []string `json:"scope_kinds"`
	MaxTimeoutMs         int64    `json:"max_timeout_ms"`
	AbsoluteMaxInput     int64    `json:"absolute_max_input_bytes"`
	AbsoluteMaxOutput    int64    `json:"absolute_max_output_bytes"`
	MaxNameLen           int      `json:"max_name_len"`
	MaxAllowedEndpoints  int      `json:"max_allowed_endpoints"`
	MaxKnowledgeBudgetMs int64    `json:"max_knowledge_budget_ms"`
	DefaultBudgetMs      int64    `json:"default_budget_ms"`
}

// Vocabulary 返回当前二进制的声明取值域。
func Vocabulary() DeclVocabulary {
	phases := make([]string, 0, 5)
	for _, p := range processor.Phases() {
		phases = append(phases, string(p))
	}
	return DeclVocabulary{
		// 类型取注册表（自定义类型注入后这里自动跟上）；档位与范围种类是领域包的常量。
		ProcessorTypes:       processorTypes(),
		Phases:               phases,
		BodyAccesses:         []string{string(policy.BodyMetadataOnly), string(policy.BodyInspect), string(policy.BodyTransform)},
		ScopeKinds:           []string{string(policy.ScopeUser), string(policy.ScopeOrganization), string(policy.ScopeProject), string(policy.ScopeSystem)},
		MaxTimeoutMs:         processor.MaxTimeout.Milliseconds(),
		AbsoluteMaxInput:     processor.AbsoluteMaxInputBytes,
		AbsoluteMaxOutput:    processor.AbsoluteMaxOutputBytes,
		MaxNameLen:           processor.MaxNameLen,
		MaxAllowedEndpoints:  processor.MaxAllowedEndpoints,
		MaxKnowledgeBudgetMs: knowledge.MaxBudget.Milliseconds(),
		DefaultBudgetMs:      knowledge.DefaultBudget.Milliseconds(),
	}
}

// ProcessorSpecsView 返回加载期的处理器声明（原样切片，运行期只读）。//
// 用方法而不是让调用方直接遍历 Config.Processors：调用方要的是**已经过领域校验**的形态，
// 而配置文件里那份还带着「字符串阶段」「毫秒整数」这类配置词汇。
// 未经 normalize 的 Config（零值）返回 nil，nil 的含义是「没有声明」，不是「不限」。
func (c *Config) ProcessorSpecsView() []processor.Spec {
	if c == nil {
		return nil
	}
	return c.ProcessorSpecs
}

// KnowledgeSourcesView 返回知识源声明（同上，只读）。
func (c *Config) KnowledgeSourcesView() []KnowledgeSourceDef {
	if c == nil {
		return nil
	}
	return c.KnowledgeSources
}

// lintProcessorActivity 报告「声明了但当前接线模式不会跑」。
//
// 只 warn 不 error：提前把配置准备好是正常做法（§3.0 的三阶段本来就要求能先把声明表
// 写出来再切 enforce），拦住写入等于逼运维分两次改文件。但必须说破 ——
// 影子与强制之外都不碰正文，声明表在那两种模式下没有任何作用点，
// 而「配了脱敏结果原文照样出网」是这一屏最不能让人误解的一件事。
func (c *Config) lintProcessorActivity() {
	if len(c.Processors) == 0 && len(c.KnowledgeSources) == 0 {
		return
	}
	if c.Policy.ModeResolved() == PolicyModeEnforce {
		return
	}
	var what []string
	if len(c.Processors) > 0 {
		what = append(what, fmt.Sprintf("%d 个处理器声明", len(c.Processors)))
	}
	if len(c.KnowledgeSources) > 0 {
		what = append(what, fmt.Sprintf("%d 个知识源声明", len(c.KnowledgeSources)))
	}
	c.Warnings = append(c.Warnings, fmt.Sprintf(
		"已配置 %s，但 policy.mode=%s：只有 enforce 才允许 3.0 影响路由与处理器（§3.0 规则 2），"+
			"这些声明现在不会生效", strings.Join(what, "、"), c.Policy.ModeResolved()))
}
