package processor

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrRegistryDuplicate 表示同名处理器重复注册。
var ErrRegistryDuplicate = errors.New("processor: 处理器名已注册")

// registration 是一条注册项：声明 + 绑定的运行参数。
type registration struct {
	spec Spec
	cfg  *Config
}

// Registry 是「按名字注册、按 Spec 列表装配」的注册表。
//
// 构造后可并发读写（内部一把 RWMutex）：注册发生在启动/热更新期，
// 装配发生在每条请求上，所以读路径用快照而不是持锁跑处理器。
type Registry struct {
	mu      sync.RWMutex
	types   map[string]Factory
	entries map[string]registration // key = 处理器名
}

// NewRegistry 返回带四个内置处理器 + sidecar 工厂的注册表。
func NewRegistry() *Registry {
	r := &Registry{
		types:   map[string]Factory{},
		entries: map[string]registration{},
	}
	// 内置类型先注册，自定义类型可以覆盖同名实现（例如换一套脱敏规则）。
	for _, item := range []struct {
		typ     string
		factory Factory
	}{
		{TypePIIMask, newPIIMask},
		{TypeFieldReplace, newFieldReplace},
		{TypeJSONSchema, newSchemaValidator},
		{TypeResultFilter, newResultFilter},
		{TypeSidecar, newSidecar},
	} {
		if err := r.RegisterType(item.typ, item.factory); err != nil {
			panic(err) // 编程错误，不是运行期输入
		}
	}
	return r
}

// RegisterType 注册一个类型工厂。重复注册同名类型是**替换**而不是报错：
// 内置类型需要能被组织级实现替换（例如换掉脱敏词表），而替换必须显式发生一次，
// 所以这里不做「静默合并」。
func (r *Registry) RegisterType(typ string, factory Factory) error {
	if factory == nil {
		return Errorf(ErrRegistry, "type %q 的工厂为空", typ)
	}
	if !safeIdentifier(typ) {
		return Errorf(ErrRegistry, "type %q 不是安全标识符", typ)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.types[typ] = factory
	return nil
}

// KnownTypes 返回已注册的类型名（排序）。
func (r *Registry) KnownTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.types))
	for t := range r.types {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Register 按名字注册一个处理器声明及其运行参数。
//
// cfg 在这里绑定而不是 Build 时传入：装配调用方拿到的是策略下发的 Spec（数据面），
// 若它同时能塞进一个 HTTP 客户端或端点，白名单与出网约束就形同虚设。
// 同名重复注册直接拒绝（ErrRegistryDuplicate）—— 覆盖式注册会让「谁最后写」
// 决定线上行为，而版本升级的正确做法是先 Deregister 再 Register。
func (r *Registry) Register(spec Spec, cfg *Config) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	factory, ok := r.factoryFor(spec.Type)
	if !ok {
		return Errorf(ErrRegistry, "%s: 类型 %q 没有对应工厂（已注册类型：%s）",
			spec.Name, spec.Type, strings.Join(r.KnownTypes()[:min(len(r.KnownTypes()), 64)], "、"))
	}
	if _, err := factory(spec, cfg); err != nil {
		// 工厂在注册期就跑一次：配置错误（非法正则、缺客户端、schema 越界）
		// 必须在这里炸，而不是等第一条真实请求。
		return Errorf(ErrRegistry, "%s: 构造失败: %v", spec.Name, err)
	}
	next := registration{spec: spec, cfg: copyConfig(cfg)}
	r.mu.Lock()
	defer r.mu.Unlock()
	if exist, ok := r.entries[spec.Name]; ok {
		return Errorf(ErrRegistryDuplicate, "%s 已注册版本 %s，拒绝被版本 %s 覆盖（升级请先 Deregister）",
			spec.Name, exist.spec.Version, spec.Version)
	}
	r.entries[spec.Name] = next
	return nil
}

// Deregister 注销一个名字，返回它此前的版本。用于显式的处理器升级。
func (r *Registry) Deregister(name string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	old, ok := r.entries[name]
	if !ok {
		return "", false
	}
	delete(r.entries, name)
	return old.spec.Version, true
}

// Lookup 返回名字的注册声明。
func (r *Registry) Lookup(name string) (Spec, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	old, ok := r.entries[name]
	if !ok {
		return Spec{}, false
	}
	return old.spec, true
}

// Names 返回已注册名字（排序）。
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.entries))
	for name := range r.entries {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (r *Registry) factoryFor(typ string) (Factory, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.types[typ]
	return f, ok
}

// BuildOptions 是装配一次 Pipeline 的可选参数。
type BuildOptions struct {
	// PolicyVersion 来自实际加载的策略包（BundleSet/Resolver 的 Version），
	// 不允许 handler 临时拼接（手册 §3.0、A 文档 §6）。留空则审计不带策略版本。
	PolicyVersion string
	// Clock 固定时间源，测试用。
	Clock func() time.Time
}

// AssemblyError 是装配期错误，带原因码，管理台可以直接按码聚合。
type AssemblyError struct {
	Processor string
	Reason    Reason
	Err       error
}

func (e *AssemblyError) Error() string {
	return fmt.Sprintf("processor: 装配 %s 失败（%s）: %v", e.Processor, e.Reason, e.Err)
}

func (e *AssemblyError) Unwrap() error { return e.Err }

// Build 按 Spec 列表装配 Pipeline。
//
// 规则：
//  1. 每个 Spec 必须已注册；名字不认识 → ReasonNotRegistered，
//     版本不认识 → ReasonVersionReject。**不做「按名字取最新版本」的宽松匹配**：
//     策略写 pii-mask@1.0.0 而运行时是 1.0.1 时，静默换成新实现意味着
//     策略版本与真实行为脱钩，审计与回放全部失真。
//  2. 阶段不匹配当前执行路径的 Spec 会被装配（一条 Pipeline 同时服务请求/响应/审计），
//     执行时按阶段选取，所以策略里给的顺序只影响同阶段内的先后。
//  3. 构造失败一律是装配错误，请求路径永远拿不到半装配的 Pipeline。
func (r *Registry) Build(specs []Spec, opts *BuildOptions) (*Pipeline, error) {
	if opts == nil {
		opts = &BuildOptions{}
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	stages := make([]stage, 0, len(specs))
	for i, spec := range specs {
		if err := spec.Validate(); err != nil {
			return nil, &AssemblyError{Processor: spec.Name, Reason: ReasonConfigInvalid, Err: err}
		}
		r.mu.RLock()
		reg, ok := r.entries[spec.Name]
		r.mu.RUnlock()
		if !ok {
			return nil, &AssemblyError{Processor: spec.Name, Reason: ReasonNotRegistered,
				Err: Errorf(ErrRegistry, "名字未注册（已注册：%s）", strings.Join(r.Names(), "、"))}
		}
		if reg.spec.Version != spec.Version {
			return nil, &AssemblyError{Processor: spec.Name, Reason: ReasonVersionReject,
				Err: Errorf(ErrRegistry, "策略要求版本 %s，运行时注册的是 %s（不静默替换实现）",
					spec.Version, reg.spec.Version)}
		}
		if reg.spec.Type != spec.Type {
			return nil, &AssemblyError{Processor: spec.Name, Reason: ReasonVersionReject,
				Err: Errorf(ErrRegistry, "策略声明类型 %s，运行时注册的是 %s", spec.Type, reg.spec.Type)}
		}
		factory, ok := r.factoryFor(spec.Type)
		if !ok {
			return nil, &AssemblyError{Processor: spec.Name, Reason: ReasonNotRegistered,
				Err: Errorf(ErrRegistry, "类型 %q 没有工厂", spec.Type)}
		}
		proc, err := factory(spec, reg.cfg)
		if err != nil {
			return nil, &AssemblyError{Processor: spec.Name, Reason: ReasonConfigInvalid, Err: err}
		}
		if proc == nil {
			return nil, &AssemblyError{Processor: spec.Name, Reason: ReasonConfigInvalid,
				Err: Errorf(ErrRegistry, "工厂返回空处理器")}
		}
		_, isStream := proc.(StreamProcessor)
		stages = append(stages, stage{spec: spec, proc: proc, hasStream: isStream, index: i})
	}
	// 跨阶段执行次序固定为 §2.6 的 phaseOrder：策略里的顺序只影响同阶段内的先后
	// （Build 的文档承诺）。不排序的话，把 before-route 写在 before-classify 前面
	// 就会真的颠倒执行次序 —— 那等于让策略文本改写运行时语义。
	// SliceStable 保证同阶段内维持策略给出的相对顺序。
	sort.SliceStable(stages, func(i, j int) bool {
		return phaseRank(stages[i].spec.Phase) < phaseRank(stages[j].spec.Phase)
	})
	return &Pipeline{
		stages:        stages,
		policyVersion: opts.PolicyVersion,
		clock:         clock,
	}, nil
}

// copyConfig 复制一份 Config，避免注册后调用方继续改切片内容。
//
// 不复制的后果：注册表持有的规则表被外部就地修改，等于一条请求能改另一条请求的策略。
func copyConfig(cfg *Config) *Config {
	if cfg == nil {
		return nil
	}
	out := *cfg
	out.PseudonymKey = append([]byte(nil), cfg.PseudonymKey...)
	out.PIITypes = append([]string(nil), cfg.PIITypes...)
	out.Rules = append([]ReplaceRule(nil), cfg.Rules...)
	for i := range out.Rules {
		out.Rules[i].Mapping = copyMapping(cfg.Rules[i].Mapping)
	}
	out.FilterRules = append([]FilterRule(nil), cfg.FilterRules...)
	for i := range out.FilterRules {
		out.FilterRules[i].Keywords = append([]string(nil), cfg.FilterRules[i].Keywords...)
	}
	out.Schema = append(json.RawMessage(nil), cfg.Schema...)
	if cfg.Headers != nil {
		out.Headers = make(map[string]string, len(cfg.Headers))
		for k, v := range cfg.Headers {
			out.Headers[k] = v
		}
	}
	return &out
}

func copyMapping(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
