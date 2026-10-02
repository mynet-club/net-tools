package university

// 端到端场景运行器：把「身份 → 策略 → 路由 → 处理器 → 执行器 → 审计」串成一条链。
//
// 为什么示例自带运行器：统一装配层还没落地（那是 H 包的接线器）。这里把装配顺序
// 钉死成一份可执行基线，测试只声明「谁、什么上下文、要哪个模型」即可断言全链结论。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/executor"
	"github.com/mynet-club/net-tools/llmproxy/internal/identity"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/processor"
	"github.com/mynet-club/net-tools/llmproxy/internal/routing"
)

// 处理器实例名与版本。ProcessorSpec 只有名字，版本绑定发生在注册期。
const (
	ProcSchema  = "campus-chat-schema"
	ProcMask    = "campus-pii-mask"
	ProcSidecar = ProcessorSidecar
	ProcFilter  = "campus-result-filter"
	ProcVersion = "1.0.0"
)

// ChatSchema 只约束「像不像一次 chat 调用」，不含任何高校字段：正文业务校验属于
// 各校自己的处理器配置，不属于网关。
var ChatSchema = json.RawMessage(`{"type":"object","required":["model","messages"],"properties":` +
	`{"model":{"type":"string","minLength":1,"maxLength":64},"messages":{"type":"array","items":` +
	`{"type":"object","required":["role","content"],"properties":{"role":{"type":"string"},"content":{"type":"string"}}}}}}`)

// SampleBody 里 %s 处填模型名。手机号取文档号段、邮箱取保留域名，专门用来断言它们
// 既不会原样出网，也不会出现在审计里。
const SampleBody = `{"model":"%s","messages":[{"role":"user",` +
	`"content":"请联系 13800000000 或 coach@example.test 确认进度"}]}`

// SampleReply 是本地模型的回放响应：凭证与手机号都出现在 content 里，用来证明响应侧
// 过滤链确实有东西可滤（而不是碰巧没命中）。
const SampleReply = `{"id":"chatcmpl-campus-1","object":"chat.completion","choices":[{"index":0,` +
	`"message":{"role":"assistant","content":"已记录，联系 13800000000，令牌 sk-campussyntheticcredential00"}}],` +
	`"usage":{"prompt_tokens":37,"completion_tokens":21,"total_tokens":58}}`

// SampleSecret 是合成凭证样例（被 drop-synthetic-credential 规则命中）。
const SampleSecret = "sk-campussyntheticcredential00"

// 合成目标全部使用 .invalid（RFC 2606 保留 TLD）：即使有人误把注入的假传输换成真
// 客户端，也解析不出可路由的地址。
const (
	SidecarEndpoint = "https://sidecar.campus.invalid/v1/check"
	LocalBaseURL    = "http://campus-models.invalid"
	RemoteBaseURL   = "https://cloud.frontier.invalid"
	ChatPath        = "/v1/chat/completions"

	procTimeout     = 5 * time.Second
	executorTimeout = 10 * time.Second
	maxBodyBytes    = 1 << 20
	planTTL         = 5 * time.Minute
)

// fakeTransport 是注入式假传输：记录请求体、返回固定响应，一次真实拨号都不发。
// 为什么注入 RoundTripper 而不是起监听：其余代码路径（请求编码、逐跳头过滤、
// CheckRedirect）与生产完全相同，只有「拨号」这一步被替换。
type fakeTransport struct {
	reply    string
	lastBody []byte
	calls    int
}

func (t *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		bs, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		t.lastBody, t.calls = bs, t.calls+1
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(t.reply)),
	}, nil
}

// payload 返回 sidecar 最近一次收到的投递文档（同包测试直接读，不需导出访问器）。
func (t *fakeTransport) payload() map[string]any {
	var doc map[string]any
	_ = json.Unmarshal(t.lastBody, &doc)
	return doc
}

// OffersFor 返回某个下游模型名的候选池，顺序与权重固定。
//
// 为什么档序是「校内 vLLM 主/备 → 无价目本地小模型 → 境内云 → 境外云」：
// fixed-order 先按档取首选、档内按权重抽样，把档序写死回放断言才有唯一答案。
// 上游真名逐家显式给：policy.RouteCandidate 不接受留空 —— 「没写就等于和下游同名」
// 会把一次改名的影响面藏进代码里。
func OffersFor(model string) routing.Offers {
	// 位置字段：provider / 执行器 / 上游真名 / 区域 / 可承载分级 / 档 / 权重 /
	// 健康 / 有价目 / 输入价 / 输出价 / 观测延迟 / 能力。
	rows := []struct {
		provider, execName, upstream, region string
		level                                policy.DataLevel
		tier, weight                         int
		isHealthy, isCostKnown               bool
		costIn, costOut                      float64
		latency                              int64
		capabilities                         []string
	}{
		{"campus-vllm-a", "vllm", "vllm-" + model, "campus-dc1", policy.LevelConfidential, 0, 3, true, true, .02, .06, 120, []string{"chat", "streaming", "tools"}},
		{"campus-vllm-b", "vllm", "vllm-" + model + "-r", "campus-dc2", policy.LevelInternal, 0, 1, true, true, .02, .06, 180, []string{"chat", "streaming"}},
		{"campus-ollama-mini", "ollama", "ollama-" + model, "campus-lab", policy.LevelInternal, 1, 1, true, false, 0, 0, 400, []string{"chat"}},
		{"frontier-cloud-cn", "http-compat", "cloud-" + model, "cn-east", policy.LevelInternal, 2, 2, true, true, .30, 1.20, 90, []string{"chat", "streaming", "tools"}},
		{"frontier-cloud-us", "http-compat", "cloud-" + model + "-us", "us-west", policy.LevelPublic, 2, 5, false, true, .40, 1.60, 60, []string{"chat", "streaming"}},
	}
	offers := make(routing.Offers, 0, len(rows))
	for _, r := range rows {
		offers = append(offers, routing.Offer{
			Candidate: policy.RouteCandidate{
				Executor: r.execName, Provider: r.provider, Model: model,
				UpstreamModel: r.upstream, Weight: float64(r.weight),
				Region: r.region, MaxDataLevel: r.level,
			},
			Tier: r.tier, Healthy: r.isHealthy, CostPer1KIn: r.costIn,
			CostPer1KOut: r.costOut, CostKnown: r.isCostKnown, ObservedLatencyMs: r.latency,
			DeclaredModels: []string{model}, Capabilities: r.capabilities,
		})
	}
	return offers
}

// Scenario 是一条场景的输入声明。
type Scenario struct {
	RequestID, Fixture, Purpose, Model string
	// 三档数据来源分开给：生效分级取最大值，只给一个数字就断言不了
	// 「检测器把公开请求抬到 confidential」这条规则。
	UserLevel, DetectedLevel, KnowledgeLevel policy.DataLevel
	Regions                                  []string // 空 = 不限区域（AllowedRegions 是白名单语义）
	Capability                               string
	Objective                                routing.Objective
	IsRawSidecar                             bool // 装载「要求原文」的 sidecar：正文授权贯通链路
	At                                       time.Time
	Sticky                                   *routing.StickyState
	Random                                   routing.RandomSource // 非空 = 线上模式（Seed 置空）
}

// Result 是一条场景的全部产出。
type Result struct {
	Principal      identity.Principal
	Chain          policy.ScopeChain
	Context        policy.PolicyContext
	Resolver       *policy.Resolver
	PolicyVersion  string
	Decision       policy.Decision
	IsRawBodyAllow bool
	RawBodyReason  policy.Reason
	RoutingSeed    string
	Plan           policy.RoutingPlan
	Replay         routing.ReplayInput
	PlanErr        error
	PipelineErr    error
	Sent           []byte
	Delivered      []byte
	Snapshot       executor.Snapshot
	Audit          AuditRow
}

// AuditRow 是审计行的**投影**（真实 sink 归 H 包，这里只示范该断言什么）。
// 结构体里没有正文字段：正文只以 sha256 摘要与字节数出现（§2.9 规则 6）。
type AuditRow struct {
	RequestID      string          `json:"request_id"`
	PolicyVersion  string          `json:"policy_version"`
	RoutingSeed    string          `json:"routing_seed"`
	Subject        string          `json:"subject"`
	ScopeChain     string          `json:"scope_chain"`
	Model          string          `json:"model"`
	Provider       string          `json:"provider_id"`
	Executor       string          `json:"executor"`
	Tier           int             `json:"tier"`
	IsAllowed      bool            `json:"is_allowed"`
	Reason         policy.Reason   `json:"reason"`
	Reasons        []policy.Reason `json:"reasons"`
	IsRawBodyAllow bool            `json:"is_raw_body_allow"`
	ContentMode    string          `json:"sidecar_content_mode"`
	BodyHash       string          `json:"body_sha256"`
	BodyBytes      int             `json:"body_bytes"`
	Status         int             `json:"upstream_status"`
	HasUsage       bool            `json:"has_usage"`
	ContentBytes   int             `json:"content_bytes"`
	Failures       []string        `json:"rejection_reasons"`
}

// World 是一套固定装配：身份来源、策略集、两个注入式假传输。
type World struct {
	Provider *identity.FakeProvider
	Bundles  *policy.BundleSet
	Sink     *fakeTransport // sidecar 出网目标
	Upstream *fakeTransport // 模型调用目标
	// Now 是本套装配的时间基准，与 Provider 的时钟是同一个值：TTL 边界、规则过期
	// 和 seed 都吃 now，两处基准分开就会在「签发」与「判定」之间留下不可控的缝。
	Now time.Time
}

// NewWorld 装配一次示例网关。所有时间都来自 BaseNow，保证跨运行可复现。
func NewWorld() (*World, error) {
	provider, err := Provider(BaseNow)
	if err != nil {
		return nil, err
	}
	set, err := Bundles()
	if err != nil {
		return nil, err
	}
	return &World{Provider: provider, Bundles: set, Now: BaseNow,
		Sink:     &fakeTransport{reply: `{"allowed":true,"action":"pass","short_code":"synthetic-ok"}`},
		Upstream: &fakeTransport{reply: SampleReply}}, nil
}

// buildChain 注册并装配这条链。每次运行都新建注册表：注册表拒绝同名不同版本覆盖，
// 跨用例复用会让「改了处理器版本」这类配置错误在用例之间互相污染。
//
// 为什么原文型 sidecar 排在脱敏之前：它声明 allow_raw_body，拿到的就该是原文；放在
// pii-mask 之后它读到的是掩码文，那份授权等于白配。默认链不带它，普通 sidecar 收
// 掩码正文（content_mode=masked）。AllowRawBody 不因「这次没授权」而降为 false ——
// E 包规定无授权即失败，降级成摘要会把合规缺口伪装成请求成功。
func (w *World) buildChain(s Scenario, resolver *policy.Resolver, version string) (*processor.Pipeline, error) {
	base := func(name, typ string, phase processor.Phase, access policy.BodyAccess) processor.Spec {
		return processor.Spec{
			Name: name, Type: typ, Phase: phase, Version: ProcVersion, Timeout: procTimeout,
			MaxInputBytes: maxBodyBytes, MaxOutputBytes: maxBodyBytes,
			FailClosed: true, BodyAccess: access,
		}
	}
	sidecar := base(ProcSidecar, processor.TypeSidecar, processor.PhaseBeforeUpstream, policy.BodyTransform)
	sidecar.AllowedEndpoints, sidecar.AllowRawBody = []string{SidecarEndpoint}, s.IsRawSidecar
	specs := []processor.Spec{base(ProcSchema, processor.TypeJSONSchema, processor.PhaseBeforeRoute, policy.BodyInspect)}
	if s.IsRawSidecar {
		specs = append(specs, sidecar)
	}
	specs = append(specs, base(ProcMask, processor.TypePIIMask, processor.PhaseBeforeUpstream, policy.BodyTransform))
	if !s.IsRawSidecar {
		specs = append(specs, sidecar)
	}
	specs = append(specs, base(ProcFilter, processor.TypeResultFilter, processor.PhaseAfterUpstream, policy.BodyTransform))

	reg := processor.NewRegistry()
	for _, spec := range specs {
		var cfg *processor.Config
		switch spec.Type {
		case processor.TypeJSONSchema:
			cfg = &processor.Config{Schema: ChatSchema}
		case processor.TypePIIMask:
			cfg = &processor.Config{
				PIITypes: []string{processor.PIIPhone, processor.PIIEmail, processor.PIIIDCard},
				// 假名化键是合成值：真实部署从密钥管理注入，绝不在仓库里落盘。
				PseudonymKey: []byte("campus-synthetic-pseudonym-key-32b"),
			}
		case processor.TypeSidecar:
			cfg = &processor.Config{
				Endpoint: SidecarEndpoint,
				// 客户端由接线方注入：本包不自建连接，否则 dialer 的出网白名单被绕过。
				HTTPClient: &http.Client{Transport: w.Sink, Timeout: procTimeout},
				// 原文授权判定器就是策略内核：处理器不自建第二套判定。
				Grants: resolver, Idempotent: true,
			}
		case processor.TypeResultFilter:
			cfg = &processor.Config{FilterRules: []processor.FilterRule{
				{Name: "drop-synthetic-credential", Pattern: `sk-[a-z0-9]{8,}`, Replacement: "[credential-redacted]"},
				{Name: "drop-document-phone", Keywords: []string{"13800000000"}, Replacement: "[phone-redacted]"},
			}}
		}
		if err := reg.Register(spec, cfg); err != nil {
			return nil, err
		}
	}
	return reg.Build(specs, &processor.BuildOptions{PolicyVersion: version})
}

// Run 跑完整链路。策略/路由/处理器层的失败都收进 Result 字段返回，只有装配与 IO 层
// 的意外才抛 error —— 「被拒」是一条结论，不是一个故障。
func (w *World) Run(ctx context.Context, s Scenario) (*Result, error) {
	now := s.At
	if now.IsZero() {
		now = w.Now
	}
	principal, err := w.Provider.Resolve(ctx, identity.FakeCredential(s.Fixture))
	if err != nil {
		return nil, fmt.Errorf("university: 解析 fixture %q: %w", s.Fixture, err)
	}
	// 版本必须先按范围过滤再取：拿全集版本进审计会写下与本次请求无关的规则包。
	filtered, err := w.Bundles.Filter(principal.Chain)
	if err != nil {
		return nil, err
	}
	version, err := filtered.PolicyVersion()
	if err != nil {
		return nil, err
	}
	resolver, err := policy.FromBundles(filtered, principal.Chain)
	if err != nil {
		return nil, err
	}
	level, err := policy.EffectiveLevel(s.UserLevel, s.DetectedLevel, s.KnowledgeLevel)
	if err != nil {
		return nil, err
	}
	pctx, err := principal.PolicyContext(s.Purpose, level)
	if err != nil {
		return nil, err
	}
	pctx.AllowedRegions, pctx.PolicyVersion = s.Regions, version

	res := &Result{Principal: principal, Chain: principal.Chain, Context: pctx,
		Resolver: resolver, PolicyVersion: version}
	res.Decision = resolver.Evaluate(pctx, principal.Chain, modelResource(s.Model), policy.ActionUse, now)
	res.IsRawBodyAllow, res.RawBodyReason = resolver.AllowsRawBody(pctx, principal.Chain, now)

	// routing_seed = H(request_id || policy_version || routing_epoch)（§2.8）。
	seed, err := policy.DeriveRoutingSeed(s.RequestID, version, RoutingEpoch)
	if err != nil {
		return nil, err
	}
	res.RoutingSeed = seed
	in := routing.Input{
		RequestID: s.RequestID, Offers: OffersFor(s.Model),
		Gate:        &policyGate{resolver: resolver, ctx: pctx, chain: principal.Chain, now: now},
		Requirement: routing.Requirement{Model: s.Model}, MaxRetries: 2,
		ProcessorChain: processorNames(s.IsRawSidecar), Objective: s.Objective,
		Sticky: s.Sticky, Seed: seed, PolicyVersion: version, TTL: planTTL, Now: now,
	}
	if s.Capability != "" {
		in.Requirement.Capabilities = []string{s.Capability}
	}
	if s.Random != nil {
		in.Source, in.Seed, res.RoutingSeed = s.Random, "", ""
	}
	plan, replay, planErr := routing.NewPlanner().PlanWithReplay(pctx, principal.Chain, in)
	res.Plan, res.Replay, res.PlanErr = plan, replay, planErr
	if planErr != nil {
		res.Audit = AuditRow{RequestID: s.RequestID, PolicyVersion: version,
			RoutingSeed: res.RoutingSeed, Subject: pctx.Identity.Subject,
			ScopeChain: principal.Chain.Display(), Model: s.Model,
			Reason: noCandidate(planErr)}
		var pe *routing.PlanError
		if errors.As(planErr, &pe) {
			for _, r := range pe.Rejections {
				res.Audit.Failures = append(res.Audit.Failures, r.Provider+":"+string(r.Reason))
			}
		}
		return res, nil
	}
	cand, ok := plan.Primary()
	if !ok {
		return nil, errors.New("university: 计划里没有首选候选")
	}

	pipeline, err := w.buildChain(s, resolver, version)
	if err != nil {
		return nil, err
	}
	reqResult, err := pipeline.RunRequest(ctx, &processor.Request{
		RequestID: s.RequestID, Model: s.Model, Policy: pctx, Chain: principal.Chain,
		Now: now, Body: processor.NewOwnedBody([]byte(fmt.Sprintf(SampleBody, s.Model))),
	})
	if err != nil {
		// 处理器 fail-closed（典型是 sidecar 声明 allow_raw_body 而授权缺失）：
		// 一个字节都不该发往上游，这里直接收尾。
		res.PipelineErr = err
		return res, nil
	}
	// 送出去的正文就是过滤链跑完的正文：审计里只留它的摘要与字节数（§2.9 规则 6），
	// 所以 Result 不再另存一份「掩码前/掩码后」——两份都是同一份正文。
	res.Sent = reqResult.Body
	w.Upstream.calls, w.Upstream.lastBody = 0, nil

	exec, err := w.executorFor(cand.Executor, seed)
	if err != nil {
		return nil, err
	}
	attempt, err := executor.AttemptFromPlan(plan, cand, executor.Attempt{
		RequestID: s.RequestID, BaseURL: baseURLFor(cand.Executor), Path: ChatPath,
		Body: append([]byte(nil), res.Sent...), Timeout: executorTimeout,
		MaxResponseBytes: maxBodyBytes,
	})
	if err != nil {
		return nil, err
	}
	outcome, err := exec.Execute(ctx, attempt)
	if err != nil {
		return nil, fmt.Errorf("university: 执行器 %s: %w", cand.Executor, err)
	}
	body, readErr := io.ReadAll(outcome.Body)
	closeErr := outcome.Body.Close()
	if readErr != nil || closeErr != nil {
		return nil, fmt.Errorf("university: 读上游响应体: %v %v", readErr, closeErr)
	}
	res.Snapshot = outcome.Snapshot()

	respResult, err := pipeline.RunResponse(ctx, &processor.Response{
		RequestID: s.RequestID, Model: cand.Model, StatusCode: outcome.StatusCode,
		ContentType: "application/json", Policy: pctx, Chain: principal.Chain, Now: now,
		Body: processor.NewBufferedBody(body),
	})
	if err != nil {
		return nil, err
	}
	res.Delivered = respResult.Body

	obs := outcome.Observed()
	mode, _ := w.Sink.payload()["content_mode"].(string)
	res.Audit = AuditRow{
		RequestID: s.RequestID, PolicyVersion: version, RoutingSeed: res.RoutingSeed,
		Subject: pctx.Identity.Subject, ScopeChain: principal.Chain.Display(),
		Model: plan.Model, Provider: cand.Provider, Executor: cand.Executor,
		Tier: tierOf(plan, cand), IsAllowed: res.Decision.Allowed,
		Reason: res.Decision.Reason, Reasons: res.Decision.Reasons,
		IsRawBodyAllow: res.IsRawBodyAllow, ContentMode: mode,
		BodyHash: hashHex(res.Sent), BodyBytes: len(res.Sent),
		Status: outcome.StatusCode, HasUsage: obs.HasUsage, ContentBytes: obs.ContentBytes,
	}
	for _, r := range plan.Rejections {
		res.Audit.Failures = append(res.Audit.Failures, r.Provider+":"+string(r.Reason))
	}
	return res, nil
}

// noCandidate 把规划错误投影成稳定原因码（PlanError 之外的意外一律记 no_candidate）。
func noCandidate(err error) policy.Reason {
	var pe *routing.PlanError
	if errors.As(err, &pe) {
		return pe.Reason
	}
	return policy.ReasonNoCandidate
}

// tierOf 回查首选候选的档号：计划只留候选本身，档号是 Offer 侧的事实。
func tierOf(plan policy.RoutingPlan, cand policy.RouteCandidate) int {
	for _, o := range OffersFor(cand.Model) {
		if o.Candidate.Provider == cand.Provider {
			return o.Tier
		}
	}
	return -1
}

// baseURLFor 把执行器名映射到基址：校内执行器指向校内地址，出站目标固定。
func baseURLFor(execName string) string {
	if execName == "http-compat" {
		return RemoteBaseURL
	}
	return LocalBaseURL
}

// processorNames 是写进 RoutingPlan.ProcessorChain 的链名（顺序即执行次序）。
func processorNames(isRawSidecar bool) []string {
	if isRawSidecar {
		return []string{ProcSchema, ProcSidecar, ProcMask, ProcFilter}
	}
	return []string{ProcSchema, ProcMask, ProcSidecar, ProcFilter}
}

// policyGate 用策略内核实现 routing.Gate：路由不许自带第二套权限判定。
type policyGate struct {
	resolver *policy.Resolver
	ctx      policy.PolicyContext
	chain    policy.ScopeChain
	now      time.Time
}

// Allows 按候选的下游模型名判 model:<名> + use。
//
// 为什么不用 UpstreamModel：权限与能力都按下游请求名发放（§2.5），上游真名只是选定
// 候选之后的转换结果，拿它判权限会让同一模型的不同部署得到不同结论。
func (g *policyGate) Allows(_ policy.PolicyContext, _ policy.ScopeChain, offer routing.Offer, _ time.Time) (bool, policy.Reason) {
	d := g.resolver.Evaluate(g.ctx, g.chain, modelResource(offer.Candidate.Model), policy.ActionUse, g.now)
	return d.Allowed, d.Reason
}

// executorFor 按候选声明的执行器名取实现；目标一律走注入的假传输，不触网。
func (w *World) executorFor(execName, seed string) (executor.Executor, error) {
	opts := executor.Options{Name: execName, Transport: w.Upstream}
	switch execName {
	case "vllm":
		return executor.NewVLLM(opts)
	case "ollama":
		return executor.NewOllama(opts)
	case "http-compat":
		return executor.NewHTTPExecutor(opts)
	default:
		// 未注册的执行器名回落到确定性 fake：回放不依赖任何传输实现。
		return executor.NewFake(seed, executor.FakeRule{Body: []byte(SampleReply)}), nil
	}
}

// hashHex 是正文的 sha256 摘要：审计只留摘要与字节数，不留正文。
func hashHex(bs []byte) string {
	sum := sha256.Sum256(bs)
	return hex.EncodeToString(sum[:])
}
