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
//  3. **客户端、正文交付器与两道授权判定器只在这里注入**。E 包拒绝自己造连接（那会绕过 dialer 的
//     出网白名单），也拒绝在缺判定器时注册 allow_raw_body / 缺交付器时注册正文注入 ——
//     两者都由本文件提供。
//
// 装配失败**不在这里回话**：它记在 procRuntime 上，等 enforce 的请求真要用这条链时
// 由执行半段（procexec.go）拒掉。影子模式则完全不受影响（§3.0 线 1「影子不读正文」）。

import (
	"encoding/json"
	"errors"
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
	"github.com/mynet-club/net-tools/llmproxy/internal/secrets"
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
	// kb-context-inject 只接受两个**预算**键：交付器与两道授权判定器都在本文件注入
	// （参数文件里写一个端点等于绕过出网策略，写一个判定器等于绕开 A 包这个唯一真值源）。
	processor.TypeKnowledgeContextInject: {"max_passages", "max_total_bytes"},
}

// procParamFileOptional 报告「这个类型可以没有参数文件」。
//
// 两个，理由完全不同：
//   - pii-mask：内置脱敏词表 + 每请求随机 salt 都是 E 包内的确定默认，没东西要运营者填；
//   - kb-context-inject：它的全部必填运行参数（交付器、两道判定器）本来就只能由本文件
//     注入，文件里那两个键只是可选预算。缺文件时**仍然必须**给出带交付器的 Config ——
//     交给工厂的 nil Config 会报「需要 Config」，把「你没写参数文件」说成
//     「接线没注入交付器」，指错方向的错误比没有错误更费时间。
func procParamFileOptional(specType string) bool {
	return specType == processor.TypePIIMask || specType == processor.TypeKnowledgeContextInject
}

// processorParamFile 是 <名字>.json 的磁盘形态。
//
// 只放**数据**参数：HTTPClient、Grants、ContentGrants、KnowledgeContent、PseudonymKey
// 不在这里 —— 前四个由本文件注入（文件里给出一个客户端或端点等于绕过出网策略，
// 给出一个判定器等于在 A 包之外再造一个授权真值源），最后一个是密钥；
// 把它们写成键会被 DisallowUnknownFields 直接拒掉，
// 而不是静默接受一个看起来能配的样子。
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
	// MaxPassages / MaxTotalBytes 是 kb-context-inject 带进 prompt 的篇数与字节上限。
	// 留空或越界由 E 包回落到保守缺省（那里没有「不限」这种取值）。
	MaxPassages   int `json:"max_passages"`
	MaxTotalBytes int `json:"max_total_bytes"`
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
		params = pr.withSecrets(spec, params, s)
		if err := pr.reg.Register(spec, params); err != nil {
			pr.regErrs[spec.Name] = fmt.Sprintf("%v（运行参数：%s/%s.json；除 pii-mask 与 kb-context-inject 外，每个类型都必须有这个文件）",
				err, pr.dir, spec.Name)
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
	// 假名密钥只在这一个装配点注入，所以「没有主密钥可派生」也只在这里点名一次：
	// pii-mask 会退回每请求随机 salt（占位只在单次请求内稳定），那不是错误、是本包
	// 一直以来的默认。但运营者以为两个请求能对上同一个人时，只看文档不够 ——
	// 必须有一条启动日志说出「这次没对上」。
	if s.secrets == nil && pr.declaresPIIMask() {
		s.log.Warnf("主密钥不可用：pii-mask 的假名只在同一次请求内稳定（换请求就换值），" +
			"需要跨请求关联时请配置 master.key 并重启")
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
		// 正文注入这一条即使没有参数文件，也必须拿到**带注入件**的 Config：
		// 交付器与判定器只能在这里注入，返回 nil 会让工厂报「需要 Config」。
		if spec.Type == processor.TypeKnowledgeContextInject {
			return pr.kbInjectConfig(s, nil), nil
		}
		// 其余类型都不在这里报「缺文件」，交给注册期的工厂错误：那道错误会说清
		// 「缺少 schema」还是「至少需要一条规则」，而这里再编一份类型必填表就是第二套判据。
		//（pii-mask 没有必填运行参数，工厂的内置词表 + 每请求随机 salt 就是正确答案。）
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
			return nil, fmt.Errorf("%s 不接受参数键 %q（这个类型可用：%s；HTTP 客户端、两道授权判定器、正文交付器与假名密钥不接受文件注入）",
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
	if spec.Type == processor.TypeKnowledgeContextInject {
		cfgP = pr.kbInjectConfig(s, cfgP)
		cfgP.ContentMaxPassages = pf.MaxPassages
		cfgP.ContentMaxBytes = pf.MaxTotalBytes
	}
	return cfgP, nil
}

// withSecrets 把「只能由接线注入、且来源是主密钥」的参数绑到 Config 上。
//
// 目前只有一件：pii-mask 的假名密钥（从 master.key 派生的专用子密钥，裁决 18′）。
// 它**不是**主密钥本身，而是一段域分隔的 HMAC 输出：假名会出现在转发出去的正文里，
// 等于一个可观测的使用面，用主密钥原值做这件事会把那条面摊给任何看得到请求体的人。
// 派生因此同时满足两条原本冲突的要求 —— 跨请求稳定（同一个主密钥、同一个域 ⇒ 同一个值）
// 和不给主密钥开可反推的使用面（子密钥无法反推主密钥，也不与凭证加解密同键）。
//
// 为什么挂在 loadParams 的调用点上而不是写进去：那个函数的职责是「读并校验磁盘上的
// 运行参数」，而密钥必须在**有参数文件和没有参数文件两条路径上完全一致** ——
// 写进去就要在两个 return 各补一次，漏一个就是「补了 pii_types 反而丢了稳定假名」。
//
// 派不出来（主密钥不可用）时保持原样：E 包按每请求随机 salt 跑，那正是密钥位存在
// 之前的行为，不是错误。差别由 buildProcRuntime 那条 WARN 说出，不在这里静默。
func (pr *procRuntime) withSecrets(spec processor.Spec, params *processor.Config, s *Server) *processor.Config {
	if spec.Type != processor.TypePIIMask {
		return params
	}
	key := s.secrets.Derive(secrets.PurposePIIPseudonym, secrets.DeriveVersionV1)
	if len(key) == 0 {
		return params
	}
	if params == nil {
		params = &processor.Config{}
	}
	params.PseudonymKey = key
	return params
}

// declaresPIIMask 报告这一版有没有 pii-mask 声明（决定要不要说那句主密钥 WARN）。
func (pr *procRuntime) declaresPIIMask() bool {
	for _, spec := range pr.specs {
		if spec.Type == processor.TypePIIMask {
			return true
		}
	}
	return false
}

// kbInjectConfig 给 kb-context-inject 装上三件只能由接线注入的东西：
// 正文交付器、body.raw 判定器（检索词能否出网）、knowledge.content 判定器（正文能否进上下文）。
//
// 三道门在这里齐、不在参数文件里齐，是因为它们分别牵着三个真值源：
// 交付器牵着 knowledge_sources 的出网 transport，两个判定器牵着**这一版**策略包。
// 让它们经文件注入等于在 A 包和 dialer 之外再造一份授权与出网路径。
//
// pf 为 nil 表示「没有参数文件」：预算留空，由 E 回落到保守缺省 —— 那与
// 「写了文件但里面没这两个键」是同一种形态，不该有两种结果。
func (pr *procRuntime) kbInjectConfig(s *Server, pf *processor.Config) *processor.Config {
	cfgP := pf
	if cfgP == nil {
		cfgP = &processor.Config{}
	}
	cfgP.KnowledgeContent = &kbContentDeliverer{s: s, rt: pr.rt}
	cfgP.Grants = &procGrant{rt: pr.rt}
	cfgP.ContentGrants = &procContentGrant{rt: pr.rt}
	return cfgP
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
//
// 原文出网的**留痕**不在这里（audit30.go 的 egress.allow），而在 processorCall
// 构造那一刻：留痕要带 request_id 才指得回是哪一次请求，而这个方法拿到的只有
// (ctx, chain, now) —— 接口那三位参数是刻意与 *policy.Resolver 同形的，加一位
// request_id 就会破掉「E 不重做判定次序、也不 import 判定实现」这条被测试钉住的
// 设计性质（admission_test.go 那句 var checker RawBodyGrantChecker = resolver）。
// 所以判定留在这里，留痕与 fail closed 上移到唯一知道 request_id 的那一层。
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

// procContentGrant 是注入给 kb-context-inject 的「正文能否进上下文」判定器。
//
// 与 procGrant 同形、同一条理由：Resolver 按范围链构造，判定发生在请求期、
// 用的是那次请求的链，所以做成薄壳现取，E 包里那份
// `var checker KnowledgeContentGrantChecker = resolver` 的性质才成立
// （授权判定的唯一业务源是 A 包，接线只负责「取到当前这一版」）。
//
// 两道门各自独立：procGrant 管的是 body.raw（检索词能不能出网），
// 这里管的是 knowledge.content（源侧文档正文能不能进 prompt）。
// 合并成一个判定器会丢掉「管理员只准带内容、不准带原文检索词」这种合法组合。
type procContentGrant struct{ rt *policyRuntime }

func (g *procContentGrant) AllowsKnowledgeContent(ctx policy.PolicyContext, chain policy.ScopeChain, now time.Time) (bool, policy.Reason) {
	if g == nil || g.rt == nil {
		return false, policy.ReasonKnowledgeContentGrantMissing
	}
	res, _, err := g.rt.resolverFor(chain)
	if err != nil {
		// 这个范围没有生效的策略包 = 没有任何管理员授权过正文进上下文。
		// 报「没授权」而不是「判定失败」：前者是结论，后者会让调用方以为重试有意义。
		return false, policy.ReasonKnowledgeContentGrantMissing
	}
	return res.AllowsKnowledgeContent(ctx, chain, now)
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
		// 用 errors.Join 而不是把原因拼成一个字符串：拼接会丢掉每条原因里的 %w 链，
		// 于是执行半段就分不出「装配失败」与「用户级在替自己开注入」——
		// 后者要记一条点名指标与 WARN，前者只要一条通用拒绝。
		perr := errors.Join(blocked...)
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
func (pr *procRuntime) applicable(chain policy.ScopeChain) (specs []processor.Spec, blocked []error) {
	for _, spec := range pr.specs {
		sel, err := policy.ParseScopeSelector(spec.Scope)
		if err != nil {
			blocked = append(blocked, fmt.Errorf("%s: scope %q 不合法: %w", spec.Name, spec.Scope, err))
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
			blocked = append(blocked, fmt.Errorf("%s 装配不起来: %s", spec.Name, reason))
			continue
		}
		if spec.Type == processor.TypeKnowledgeContextInject {
			if has, platformLevel := pr.injectionAuthority(chain); has && !platformLevel {
				blocked = append(blocked, fmt.Errorf(
					"%w：%s 命中范围链 %s，但覆盖这条链的 knowledge.content 授权全部来自 user 级策略包"+
						"（「用户级范围不得自助开启注入」的运行期判定，决策包 §0.1 第 1 条「谁授权」）",
					ErrInjectEnableNotPlatformLevel, spec.Name, chain.Display()))
				continue
			}
		}
		specs = append(specs, spec)
	}
	return specs, blocked
}

// ErrInjectEnableNotPlatformLevel 是「覆盖这条链的 knowledge.content 授权全部来自 user 级
// 策略包」这一条运行期判定的哨兵错误。
//
// 它只服务可观测性：拒绝口径不变（enforce 下仍是 §2.9 规则 5 的
// processor_unavailable，回话里不出现这条文案），但执行半段要能把它与其它装配失败
// 分开 —— 前者记一条点名指标与 WARN（「谁在替自己开闸」是可审计事实），
// 后者只需一条通用拒绝。所以它必须经 errors.Join 原样穿到 processorCall，
// 而不是被拼成字符串。
var ErrInjectEnableNotPlatformLevel = errors.New("正文注入的启用权不在平台/组织级")

// injectionAuthority 报告这条范围链上的正文注入启用权落在哪一层。
//
// 这是决策包 §0.1 第 1 条「谁授权」的**运行期判定**：注入声明只允许由平台/组织级的
// 策略授权开启，用户级范围不得自助开启 —— 声明表住在平台配置文件里是结构性事实，
// 而这句话要能被运行时判出来。归属真进请求路径之后（P8），判定的依据就现成：
// 覆盖这条链的策略包里，哪一个既授了 knowledge.content、范围种类又不是 user。
//
// 为什么判在**授权**这一侧而不是声明的 scope 字面：声明只是「哪些链参与」的选择器，
// 真正开闸的是那条 knowledge.content 授权。而用户级链（只有 user:<名>）今天正是
// 用户的常态形态 —— 按声明字面判会把「平台替某个用户开的注入」一起误伤，
// 按授权来源判才问得准「这次开闸是谁给的」。
//
// 两个返回值分开，是因为它们对应两件不同的事，合起来会答错：
//   - has=false：这条链上根本没有 knowledge.content 授权 —— 那是「管理员没授权」，
//     既有路径按「不注入」处理（见 TestKbContentWithoutRawTermsGrantSendsNothing），
//     不是本判定要拦的形态；
//   - has=true 且 platformLevel=false：授权全来自 user 级包 —— 用户级范围在替自己开闸，
//     本条按「装配不起来」拒之（enforce 下该请求被拒，而不是静默不注入）。
func (pr *procRuntime) injectionAuthority(chain policy.ScopeChain) (has bool, platformLevel bool) {
	if pr == nil || pr.rt == nil || pr.rt.set == nil {
		return false, false
	}
	for _, b := range pr.rt.set.Bundles() {
		if !b.Covers(chain) || !bundleGrantsKnowledgeContent(b) {
			continue
		}
		has = true
		if b.Scope.Kind != policy.ScopeUser {
			platformLevel = true
		}
	}
	return has, platformLevel
}

// bundleGrantsKnowledgeContent 报告这个包有没有一条 knowledge.content 的放行规则。
//
// 只看 allow、不看 deny：deny 是收紧方向，把它算成「有授权」会让一个
// 「显式禁止取正文」的包反而成了开闸依据。
func bundleGrantsKnowledgeContent(b policy.PolicyBundle) bool {
	for _, e := range b.Entitlements {
		if e.Resource == policy.ResourceKnowledgeContent && e.Effect == policy.EffectAllow {
			return true
		}
	}
	return false
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
			if procParamFileOptional(spec.Type) {
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
			processor.TypeResultFilter, processor.TypeSidecar, processor.TypeKnowledgeContextInject} {
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
		// 类型不在上面六个之内：Spec.Validate 已经挡掉了（闭集），到不了这里。
		// 真到了说明有人绕过了配置层，明确报错比默默放行好。
		return fmt.Errorf("处理器 %s 的类型 %q 不受支持", spec.Name, spec.Type)
	}
	return nil
}
