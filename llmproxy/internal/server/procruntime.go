package server

// 本文件是 §3.0「执行期接线」的装配半段：把 processors 段的**声明**装配成
// 可运行的 processor.Pipeline，并回答「这条范围链上到底跑哪些处理器」。
//
// 三段边界（与 procconf.go 的取舍同源，不是重复声明）：
//  1. **声明仍是唯一真值源**。阶段、档位、上限、超时、失败策略、出网白名单一律来自
//     配置文件，本文件只做「按名字把运行参数绑上去 + 按范围挑出该跑的声明」。
//  2. **运行参数不进配置文件**。脱敏类型子集、字段替换规则、JSON Schema、结果过滤词表、
//     sidecar 的实际端点与请求头，来自 <配置目录>/processor_params/<名字>.json。
//     理由与 procconf.go 相同：让它们进 config.yaml 就有两个真值来源，而 sidecar 的
//     请求头常带令牌，那是把密钥拉进一份会被备份、被同步的文件里。
//  3. **客户端与原文授权判定器只在这里注入**。E 包拒绝自己造连接（那会绕过 dialer 的
//     出网白名单），也拒绝在缺判定器时注册 allow_raw_body —— 两者都由本文件提供。
//
// 装配失败**不在这里回话**：它记在 procRuntime 上，等 enforce 的请求真要用这条链时
// 由执行半段（procexec.go）拒掉。影子模式则完全不受影响（§3.0 线 1「影子不读正文」）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/processor"
)

// procParamDirName 是运行参数目录名，相对配置文件所在目录（与 policy.bundle_dir 同基准）。
const procParamDirName = "processor_params"

// procParamAllowedKeys 是每个类型可接受的参数键。
//
// 为什么要这张表而不是「多余的键忽略」：有人把 schema 写在 pii-mask 的参数文件里，
// 忽略就等于「配了但没生效」—— 表现是脱敏照常跑、schema 校验从来没跑过，
// 而界面上两条声明都在。键名不认识必须当场炸。
var procParamAllowedKeys = map[string][]string{
	processor.TypePIIMask:      {"pii_types"},
	processor.TypeFieldReplace: {"rules", "max_path_depth"},
	processor.TypeJSONSchema:   {"schema"},
	processor.TypeResultFilter: {"filter_rules", "filter_mode", "filter_replacement", "max_line_bytes"},
	processor.TypeSidecar:      {"endpoint", "headers", "max_retries", "idempotent"},
}

// procParamOptionalType 是唯一「可以没有参数文件」的类型：
// 内置脱敏词表与「每次请求随机 salt」都是 E 包内的确定默认，没有需要运营者填的东西。
const procParamOptionalType = processor.TypePIIMask

// processorParamFile 是 <名字>.json 的磁盘形态。
//
// 只放**数据**参数：HTTPClient、Grants、PseudonymKey 不在这里 —— 前两个由本文件注入
// （文件里给出一个客户端等于绕过出网策略），第三个是密钥；把它们写成键会被
// DisallowUnknownFields 直接拒掉，而不是静默接受一个看起来能配的样子。
type processorParamFile struct {
	PIITypes          []string                `json:"pii_types"`
	Rules             []processor.ReplaceRule `json:"rules"`
	MaxPathDepth      int                     `json:"max_path_depth"`
	Schema            json.RawMessage         `json:"schema"`
	FilterRules       []processor.FilterRule  `json:"filter_rules"`
	FilterMode        processor.FilterMode    `json:"filter_mode"`
	FilterReplacement string                  `json:"filter_replacement"`
	MaxLineBytes      int                     `json:"max_line_bytes"`
	Endpoint          string                  `json:"endpoint"`
	Headers           map[string]string       `json:"headers"`
	MaxRetries        int                     `json:"max_retries"`
	Idempotent        bool                    `json:"idempotent"`
}

// procRuntime 是一份配置修订对应的处理器链装配态，挂在 policyRuntime 上
// （同生同灭：策略改了范围链，可跑的声明集也就变了，分两套缓存必然对不上）。
type procRuntime struct {
	rt    *policyRuntime
	reg   *processor.Registry
	dir   string // 运行参数目录
	specs []processor.Spec

	// regErrs 记「这条声明装配不起来」的原因（名字 → 人话）。
	// 留着而不是直接返回错误：一条坏声明不该让整条策略链路消失，
	// 但它必须能让 enforce 的请求拒得有名有姓。
	regErrs map[string]string

	mu        sync.Mutex
	pipelines map[string]*processor.Pipeline // chain.Display() → 链
	pipeErrs  map[string]error
}

// buildProcRuntime 按当前配置的声明表装配注册表。
//
// 返回 nil 表示「这个修订版没有处理器声明」—— 那是最常见的形态，
// 不是错误，也不该在日志里留下「装配失败」。
func (s *Server) buildProcRuntime(cfg *config.Config, rt *policyRuntime) *procRuntime {
	if cfg == nil || len(cfg.ProcessorSpecs) == 0 {
		return nil
	}
	pr := &procRuntime{
		rt:        rt,
		reg:       processor.NewRegistry(),
		dir:       filepath.Join(cfg.BundleBaseDir(), procParamDirName),
		specs:     append([]processor.Spec(nil), cfg.ProcessorSpecs...),
		regErrs:   map[string]string{},
		pipelines: map[string]*processor.Pipeline{},
		pipeErrs:  map[string]error{},
	}
	for _, spec := range pr.specs {
		params, err := pr.loadParams(spec, s)
		if err != nil {
			pr.regErrs[spec.Name] = err.Error()
			continue
		}
		if err := pr.reg.Register(spec, params); err != nil {
			pr.regErrs[spec.Name] = fmt.Sprintf("%v（运行参数：%s/%s.json；除 %s 外每个类型都必须有这个文件）",
				err, pr.dir, spec.Name, procParamOptionalType)
			continue
		}
	}
	names := make([]string, 0, len(pr.specs))
	for _, spec := range pr.specs {
		if _, bad := pr.regErrs[spec.Name]; bad {
			continue
		}
		names = append(names, spec.Name)
	}
	if len(pr.regErrs) > 0 {
		bad := make([]string, 0, len(pr.regErrs))
		for name, reason := range pr.regErrs {
			bad = append(bad, fmt.Sprintf("%s: %s", name, reason))
		}
		sort.Strings(bad)
		// ERROR 而不是 WARN：声明了却没装起来，在 enforce 下就是一条会拒请求的缺口，
		// 在别的模式下是「界面说这条声明存在而运行时没人跑它」。
		s.log.Errorf("处理器声明装配失败 %d/%d（enforce 下命中这些声明的请求会被拒绝，不放行未处理正文）: %s",
			len(bad), len(pr.specs), strings.Join(bad, "; "))
		return pr
	}
	s.log.Infof("处理器链装配完成：%d 条声明 %s", len(names), strings.Join(names, ","))
	return pr
}

// loadParams 读并校验一个声明对应的运行参数文件，返回 E 包要的 Config。
//
// 两次解码（先 map 拿键名、再结构体拿值）是刻意的：结构体解码看不到「文件里写了哪些键」，
// 而「写了不该写的键」必须被拒（见 procParamAllowedKeys）。
func (pr *procRuntime) loadParams(spec processor.Spec, s *Server) (*processor.Config, error) {
	path := filepath.Join(pr.dir, spec.Name+".json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if spec.Type == procParamOptionalType {
			return nil, nil // 交给工厂的默认（内置词表 + 每请求随机 salt）
		}
		// 缺文件不在这里报错，交给注册期的工厂错误：那道错误会说清「缺少 schema」还是
		// 「至少需要一条规则」，而这里再编一份类型必填表就是第二套判据。
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读运行参数文件失败: %w", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("运行参数文件不是合法 JSON: %w", err)
	}
	allowed := map[string]bool{}
	for _, k := range procParamAllowedKeys[spec.Type] {
		allowed[k] = true
	}
	for k := range keys {
		if !allowed[k] {
			return nil, fmt.Errorf("%s 不接受参数键 %q（这个类型可用：%s；HTTP 客户端、原文授权判定器与假名密钥不接受文件注入）",
				spec.Type, k, strings.Join(procParamAllowedKeys[spec.Type], "、"))
		}
	}
	var pf processorParamFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pf); err != nil {
		return nil, fmt.Errorf("运行参数解析失败: %w", err)
	}
	cfgP := &processor.Config{
		PIITypes:          pf.PIITypes,
		Rules:             pf.Rules,
		MaxPathDepth:      pf.MaxPathDepth,
		Schema:            pf.Schema,
		FilterRules:       pf.FilterRules,
		FilterMode:        pf.FilterMode,
		FilterReplacement: pf.FilterReplacement,
		MaxLineBytes:      pf.MaxLineBytes,
		Headers:           pf.Headers,
		MaxRetries:        pf.MaxRetries,
		Idempotent:        pf.Idempotent,
	}
	if spec.Type == processor.TypeSidecar {
		cfgP.Endpoint = pf.Endpoint
		client, cErr := s.sidecarClient(spec)
		if cErr != nil {
			return nil, cErr
		}
		cfgP.HTTPClient = client
		cfgP.Grants = &procGrant{rt: pr.rt}
	}
	return cfgP, nil
}

// sidecarClient 给 http-sidecar 造一个受出网策略约束的客户端。
//
// 三点取舍：
//   - 直连（不经 providers[].proxy 那套代理配置）：sidecar 是管理员声明的网关内部依赖，
//     它的可达性由 allowed_endpoints 决定，跟用户上游的代理出口不是一回事；
//   - 不设 client.Timeout：时限来自 Spec.Timeout 的 context，而 E 的重试预算就在这个
//     context 里花。客户端级超时会把「第一次失败后重试」一起掐掉，表现为大量超时；
//   - block_local_upstream 不作用于这里：那道墙是给「用户自带的 base_url」设的，
//     而本条目标必须命中 allowed_endpoints（E 在构造期与重定向两处都判），
//     内网端点恰恰是这类处理器的正常形态。
func (s *Server) sidecarClient(spec processor.Spec) (*http.Client, error) {
	tr, err := s.Transports().Get("")
	if err != nil {
		// 绝不退回 http.DefaultTransport：那等于绕过 dialer 的出口口径去连一个出网端点，
		// 而审计里看不出差别。这里让整条声明装配失败，enforce 的请求据此被拒并留下原因，
		// 比「悄悄换了个没受控的连接」诚实。
		return nil, fmt.Errorf("%s: sidecar 连接构造失败: %w", spec.Name, err)
	}
	return &http.Client{Transport: tr}, nil
}

// procGrant 是注入给 sidecar 的原文出网授权判定器。
//
// 它不是「一个 Resolver」：Resolver 是按范围链构造的，而判定发生在请求期、
// 用的是那次请求的链。做成薄壳现取，才能守住「授权判定的唯一业务源是 A 包」
// （E 包里那句 *policy.Resolver 天然满足接口 的意义就在这里落地）。
type procGrant struct{ rt *policyRuntime }

func (g *procGrant) AllowsRawBody(ctx policy.PolicyContext, chain policy.ScopeChain, now time.Time) (bool, policy.Reason) {
	if g == nil || g.rt == nil {
		return false, policy.ReasonRawBodyGrantMissing
	}
	res, _, err := g.rt.resolverFor(chain)
	if err != nil {
		// 这个范围没有生效的策略包 = 没有任何管理员授权过原文出网。
		// 返回「没授权」而不是「判定失败」：前者是结论，后者会让调用方以为重试有用。
		return false, policy.ReasonRawBodyGrantMissing
	}
	return res.AllowsRawBody(ctx, chain, now)
}

// pipelineFor 返回作用于这条范围链的处理器链（nil 表示这条链上没有声明参与）。
//
// 缓存按 chain.Display()：与 resolvers 同一个口径，配置换修订时整个 procRuntime 被丢掉。
func (pr *procRuntime) pipelineFor(chain policy.ScopeChain, version string) (*processor.Pipeline, error) {
	if pr == nil {
		return nil, nil
	}
	key := chain.Display()
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if p, ok := pr.pipelines[key]; ok {
		return p, nil
	}
	if perr, ok := pr.pipeErrs[key]; ok {
		return nil, perr
	}
	applicable, blocked := pr.applicable(chain)
	if len(blocked) > 0 {
		// 命中了这条链、却装不起来的声明：把原因缓存下来，请求期据此拒绝。
		perr := fmt.Errorf("%s", strings.Join(blocked, "; "))
		pr.pipeErrs[key] = perr
		return nil, perr
	}
	if len(applicable) == 0 {
		pr.pipelines[key] = nil
		return nil, nil
	}
	p, err := pr.reg.Build(applicable, &processor.BuildOptions{PolicyVersion: version})
	if err != nil {
		pr.pipeErrs[key] = fmt.Errorf("装配处理器链失败: %w", err)
		return nil, pr.pipeErrs[key]
	}
	pr.pipelines[key] = p
	return p, nil
}

// applicable 按声明的 scope 挑出参与这条范围链的声明。
//
// 判据复用 policy.ParseScopeSelector/Matches（A 包），本包不写第二套范围匹配：
// 「kind:id 命中链上任一范围」这条规则一旦有两份实现，就会出现
// 「配置说这条声明管这个组织，而运行时没跑它」。
func (pr *procRuntime) applicable(chain policy.ScopeChain) (specs []processor.Spec, blocked []string) {
	for _, spec := range pr.specs {
		sel, err := policy.ParseScopeSelector(spec.Scope)
		if err != nil {
			blocked = append(blocked, fmt.Sprintf("%s: scope %q 不合法: %v", spec.Name, spec.Scope, err))
			continue
		}
		hit := false
		for _, ref := range chain {
			if sel.Matches(ref) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		if reason, bad := pr.regErrs[spec.Name]; bad {
			blocked = append(blocked, fmt.Sprintf("%s 装配不起来: %s", spec.Name, reason))
			continue
		}
		specs = append(specs, spec)
	}
	return specs, blocked
}

// CheckProcessorParams 在启动时校验声明的运行参数文件（main 调用；失败即拒绝启动）。
//
// 这里不装配 Pipeline：sidecar 的客户端要等 Server 与 dialer 就位。
// 但**文件形态**的错误（写坏 JSON、键名拼错、类型不匹配的键）与策略包缺文件是同一类事故
// —— 网关照常应答而脱敏从来没跑过，比拒之门外危险得多（同一个理由见 CheckPolicyRuntime）。
func CheckProcessorParams(cfg *config.Config) error {
	if cfg == nil || len(cfg.ProcessorSpecs) == 0 {
		return nil
	}
	dir := filepath.Join(cfg.BundleBaseDir(), procParamDirName)
	for _, spec := range cfg.ProcessorSpecs {
		path := filepath.Join(dir, spec.Name+".json")
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			if spec.Type == procParamOptionalType {
				continue
			}
			return fmt.Errorf("处理器 %s（%s）需要运行参数文件 %s：该类型的规则表/schema/端点只能在这里给",
				spec.Name, spec.Type, path)
		}
		if err != nil {
			return fmt.Errorf("读处理器运行参数文件失败: %w", err)
		}
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(data, &keys); err != nil {
			return fmt.Errorf("处理器 %s 的运行参数文件 %s 不是合法 JSON: %w", spec.Name, path, err)
		}
		for _, k := range []string{processor.TypePIIMask, processor.TypeFieldReplace, processor.TypeJSONSchema,
			processor.TypeResultFilter, processor.TypeSidecar} {
			if spec.Type != k {
				continue
			}
			allowed := map[string]bool{}
			for _, a := range procParamAllowedKeys[k] {
				allowed[a] = true
			}
			for key := range keys {
				if !allowed[key] {
					return fmt.Errorf("处理器 %s（%s）的参数文件含不可用的键 %q：%s 只接受 %s",
						spec.Name, spec.Type, key, spec.Type, strings.Join(procParamAllowedKeys[k], "、"))
				}
			}
			return nil
		}
		// 类型不在上面五个之内：Spec.Validate 已经挡掉了（闭集），到不了这里。
		// 真到了说明有人绕过了配置层，明确报错比默默放行好。
		return fmt.Errorf("处理器 %s 的类型 %q 不受支持", spec.Name, spec.Type)
	}
	return nil
}
