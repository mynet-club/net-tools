package server

// 本文件是 §3.F 的接线层：把「计划里声明的执行器」变成实际承载一次上游交换的对象。
//
// 打通的是哪一段：配置修订 → 执行器装配（按出网通道惰性构造） → 计划候选的执行器名
// 解析 → Attempt 构造（目标 / 凭证 / 正文 / 超时 / 上限全显式） → 一次交换 → 既有 relay。
// 此前 `internal/executor` 在 internal/server 里没有任何调用点，线上请求一律不经过它。
//
// 三条边界，逐条都有「不这么做会怎样」：
//
//  1. **计量语义一个字不改**。执行器的回报只用来拼一个 relay 能消费的结构，
//     usage / TTFT / 计费 / 熔断 / 粘性全部走原路。§3.F 的禁止项就是这一条：
//     执行器顺手算钱会出现第二套计价口径，而 relay 里那套是现网账本的事实来源。
//  2. **只有 enforce 且计划确实生效（shot.Applied）才委托**。legacy / shadow 下
//     2.x 传输原样跑（§3.0 线 2）。影子一旦能换传输层，差异报告里就掺进了
//     被观测者自己的改动。
//  3. **流式不委托**。F 的 Attempt 契约强制 Timeout 与 MaxResponseBytes 为正
//     （executor.Attempt.Validate），而现网流式刻意「无总时限」（idle.go：长回答
//     会被总时限正常掐断）且「边收边转发、不缓存全文、无字节上限」（§2.9 规则 7）。
//     把这两样塞进流式是一次功能回退；要打通它得先让 F 能表达「以调用方 ctx 为准、
//     不缓存」的通道 —— 那是接口裁决，不在接线里偷偷做。
//
// 失败方向：计划里有这个候选、但它声明的执行器名本网关注册不上 → **拒掉这个候选**，
// 不出网也不回落到 2.x 通道。回落等于让「计划说用哪个执行器」变成一句装饰，
// 而那正是 §8 点名的「绕过出网控制的快捷路径」。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/executor"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// executorNameOpenAI 是本网关注册的执行器名，与 policy30.go 构造候选时写进
// RouteCandidate.Executor 的值同源。另起一个字面量就是第二个事实源：
// 声明面改了就静默变成「计划里的名字没注册」，而那条路是拒候选。
const executorNameOpenAI = policyExecutorOpenAI

// 观测维度用的固定标签值（§3.I）。三组都是**接线侧的封闭集合**，取值不来自请求内容：
//
//   - rejected：候选在网关侧被拒、一次都没出网的阶段名。计划里那个注册不上的执行器名
//     刻意不进标签 —— 它本身就是被拒原因，让被观测的东西决定 /metrics 的基数，
//     一个错配的策略包就能把序列数打爆（这两个端点都不鉴权）。
//   - skipped：本该委托却退回 2.x 的原因。今天只有一种（计划与真实目标对不上），
//     正常不委托的几种边界不记，否则「委托率」读起来像失败率。
//   - wiring_unclassified：执行器返回了非 ExecutionError 的错误。今天只有一处
//     （roundTrip 里「error 为空却没有 body」那种自相矛盾）。它**不是** executor 包
//     注册码，所以单独占一个值，不去冒充 reasons.go 里的任何一个。
const (
	executorRejectUnregistered = "plan_name_unregistered"
	executorRejectChannel      = "channel_build_failed"
	executorSkipPlanDrift      = "plan_upstream_mismatch"
	executorReasonUnclassified = "wiring_unclassified"
	// exchangeReasonNone 是执行记录里「这次交换没有失败码」的写法。空串在日志里
	// 会塌成一个看不见的字段，而 reason= 这一位正是用来区分「成功」与「没记上」。
	exchangeReasonNone = "-"
)

// executorChannelMax 是执行器实例缓存的条数上限。一条 = 一个（执行器, 归属, 代理）
// 组合，键的空间由用户可自建上游的代理数决定，不设上限就等于让一份运行态里的 map
// 跟着 DB 长。越界后不再缓存、每请求现构造：宁可少复用连接池（底层 transport 仍由
// dialer.TransportCache 复用），也不留一个无界结构。
const executorChannelMax = 64

// executorChannel 是一条出网通道。同协议形态、同归属、同代理 = 同一条连接池，
// 也才是同一个执行器实例：HTTPExecutor 把 transport 绑在实例上（Attempt 只带目标），
// 所以一个名字在生产里对应多个实例 —— 这一点与 executor.Registry（名字→单实例）
// 的假设冲突，已在 docs/3.0-stage-summary.md §4 登记为待裁决项。
type executorChannel struct {
	name       string
	proto      executor.Protocol
	systemPaid bool
	proxyURL   string
}

type executorEntry struct {
	exec *executor.HTTPExecutor
	err  error
}

// executorRuntime 是一份配置修订对应的执行器装配态，挂在 policyRuntime 上。
//
// 与 rt.proc / rt.kb 同一条理由：能用哪个执行器由「模式 + 计划 + 这一版配置」共同
// 决定，单独缓存必然和策略改动对不上。
type executorRuntime struct {
	// names 是这份修订注册得出来的执行器名 → 协议形态（声明面）。
	names map[string]executor.Protocol

	mu      sync.Mutex
	entries map[executorChannel]executorEntry
	capped  bool
}

// buildExecutorRuntime 按配置修订装配执行器声明表。
//
// 今天只有一个名字：OpenAI 兼容 HTTP 直通，即 2.x 转发链路一直在跑的那一套。
// 本地后端（ollama / vllm）要逐家声明协议形态，那是配置面变更（§2.7 规则 4 的
// 口径：新语义要带版本与迁移说明），不在这一包里顺手加。
func (s *Server) buildExecutorRuntime() *executorRuntime {
	return &executorRuntime{
		names: map[string]executor.Protocol{
			executorNameOpenAI: executor.ProtocolOpenAIChat,
		},
		entries: map[executorChannel]executorEntry{},
	}
}

// protocolOf 回报一个执行器名在这份配置里注册的协议形态。
func (er *executorRuntime) protocolOf(name string) (executor.Protocol, bool) {
	if er == nil {
		return "", false
	}
	p, ok := er.names[name]
	return p, ok
}

// names 返回注册名的稳定排序清单（日志与排障用，不参与决策）。
func (er *executorRuntime) sortedNames() []string {
	if er == nil {
		return nil
	}
	out := make([]string, 0, len(er.names))
	for n := range er.names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// channel 按通道取执行器实例，惰性构造并缓存（含缓存构造失败）。
//
// 失败为什么要缓存而不是每次重试：transport 造不出来是配置事实（代理 URL 写坏了），
// 每个请求重撞一次只会把日志刷满，而报错点仍然是「命中这条通道的那次请求」。
func (er *executorRuntime) channel(s *Server, ch executorChannel) (*executor.HTTPExecutor, error) {
	er.mu.Lock()
	defer er.mu.Unlock()

	if e, ok := er.entries[ch]; ok {
		return e.exec, e.err
	}
	if er.capped {
		built, err := s.newUpstreamExecutor(ch)
		if err != nil {
			return nil, err
		}
		return built, nil
	}

	built, err := s.newUpstreamExecutor(ch)
	er.entries[ch] = executorEntry{exec: built, err: err}
	if len(er.entries) >= executorChannelMax {
		er.capped = true
	}
	return built, err
}

// newUpstreamExecutor 构造一条通道上的执行器实例。
//
// transport 只从 s.transportFor 拿：那是现网唯一的出网来源（用户自有上游带拨号层
// 出网校验、系统池不带，两套不共用缓存条目）。执行器构造时又必须拿到非 nil 的
// transport —— 回落到 http.DefaultTransport 是一条不受出网策略约束的暗通道。
func (s *Server) newUpstreamExecutor(ch executorChannel) (*executor.HTTPExecutor, error) {
	if ch.proto == "" {
		return nil, fmt.Errorf("执行器 %q 未注册协议形态", ch.name)
	}
	tr, err := s.transportFor(ch.systemPaid, ch.proxyURL)
	if err != nil {
		return nil, fmt.Errorf("执行器 %s 构造 transport 失败: %w", ch.name, err)
	}
	if tr == nil {
		return nil, fmt.Errorf("执行器 %s 拿到的 transport 为空", ch.name)
	}
	e, err := executor.NewHTTPExecutor(executor.Options{
		Name:      ch.name,
		Protocol:  ch.proto,
		Transport: tr,
		UserAgent: "llmproxy/" + config.Version, // 上游可见的 UA 与 2.x 保持一致
		Capabilities: []string{
			executor.CapabilityStreaming, executor.CapabilityTools,
			executor.CapabilityVision, executor.CapabilityJSON,
		},
	})
	if err != nil {
		return nil, err
	}
	return e, nil
}

// executorAsk 是一次委托判定的输入，全部是「这一跳」的事实。
//
// 它带着请求体与上游密钥，因此**不得**跨请求存活、不得序列化进日志或审计
// （口径同 executor.Attempt 的 (secret) 标注）。
type executorAsk struct {
	prov          *config.Provider
	model         string
	upstreamModel string
	requestID     string
	path          string // 拼给上游的相对路径（如 /chat/completions）
	accept        string
	proxyURL      string
	isStream      bool
	timeout       time.Duration
	body          []byte
}

// executorCall 是判定通过后的调用现场：执行器实例 + 已经填好的 Attempt。
type executorCall struct {
	name    string
	proto   executor.Protocol
	exec    *executor.HTTPExecutor
	attempt executor.Attempt
}

// executorCallFor 判定这一次候选交换是否交给 F 执行器，并给出调用现场。
//
// 三种结论必须分清楚，它们在日志里长得一样、在排障上完全不同：
//   - (nil, nil)：这次不委托，2.x 传输原样跑（模式不对 / 流式 / 计划没描述这家 / 时限不可表达）；
//   - (nil, err)：这个候选**不能用**（计划声明了本网关注册不上的执行器名，或通道装不起来），
//     调用方按「换下一家」处理，绝不出网；
//   - (call, nil)：委托，调用方只该把 call 当黑盒用。
func (s *Server) executorCallFor(rt *policyRuntime, shot *policyShot, ask executorAsk) (*executorCall, error) {
	// 边界 2：只有 enforce 且计划真的生效才往下走。
	if rt == nil || rt.exec == nil || shot == nil || !shot.Applied || rt.mode != config.PolicyModeEnforce {
		return nil, nil
	}
	if ask.prov == nil {
		return nil, nil
	}
	// 边界 3：流式留在 2.x（文件头给了不可委托的理由）。
	if ask.isStream {
		return nil, nil
	}
	// 时限必须原样可表达：Attempt.Timeout 强制为正，而现网的 timeout 取自
	// provider.timeout_ms（配置加载时兜到 120s）。0 或负值在这里就不是「不限」，
	// 而是「这次交换没法交给 F 描述」，交回 2.x 跑它原来的行为。
	if ask.timeout <= 0 {
		return nil, nil
	}
	// 计划没描述这家（没有候选、或候选没有执行器名）时不委托：委托要求
	// 「计划声明的执行器」与「实际跑的执行器」是同一件事，缺前者就无从核对。
	cand, has := planCandidateFor(shot.Plan, ask.prov.Name)
	if !has || strings.TrimSpace(cand.Executor) == "" {
		return nil, nil
	}
	// 上游模型名对不上说明「循环里要发的目标」与「那份计划」不是一回事（配置在
	// 请求生命周期里换过版）。这时按 2.x 原样跑并留痕：拿计划里的名字去覆盖
	// 真实目标，等于让审计描述一次没发生的交换。
	if cand.UpstreamModel != "" && cand.UpstreamModel != ask.upstreamModel {
		// 这条也是委托面唯一会「本该走执行器却静默回到 2.x」的路径，所以给它一个
		// 指标位（§3.I）：日志会滚，而运维要的是「这一小时有没有出现过」。
		s.metrics.noteExecutorSkip(executorSkipPlanDrift)
		s.log.Warnf("event=executor_plan_drift request_id=%s provider=%s plan_upstream=%s actual_upstream=%s 本次不委托",
			ask.requestID, ask.prov.Name, cand.UpstreamModel, ask.upstreamModel)
		return nil, nil
	}
	proto, ok := rt.exec.protocolOf(cand.Executor)
	if !ok {
		// 计划里有这家、名字却注册不上 —— 这是唯一「宁可不跑也不猜一个」的分支：
		// 回落到 2.x 等于把计划声明的执行器降级成注释。
		s.metrics.noteExecutorRejection(executorRejectUnregistered)
		return nil, fmt.Errorf("计划声明的执行器 %q 本网关未注册（已注册：%s）",
			cand.Executor, strings.Join(rt.exec.sortedNames(), ", "))
	}
	ch := executorChannel{
		name:       cand.Executor,
		proto:      proto,
		systemPaid: ask.prov.SystemPaid,
		proxyURL:   ask.proxyURL,
	}
	ex, err := rt.exec.channel(s, ch)
	if err != nil {
		s.metrics.noteExecutorRejection(executorRejectChannel)
		return nil, err
	}

	attempt := executor.Attempt{
		RequestID:     ask.requestID,
		Provider:      ask.prov.Name,
		Protocol:      proto,
		BaseURL:       ask.prov.BaseURL,
		APIKey:        ask.prov.APIKey,
		Path:          ask.path,
		Model:         ask.model,
		UpstreamModel: ask.upstreamModel,
		Body:          ask.body,
		IsStream:      false,
		// WantUsage 留给流式：include_usage 只对 SSE 有意义，而流式不委托（边界 3）。
		// 声明矛盾时执行器显式报错（prepareRequest），这里不制造那种矛盾。
		WantUsage: false,
		Timeout:   ask.timeout,
		// 与 relay 的非流式缓冲上限同源：两条上限必须同值，否则「谁先拦」变成运气，
		// 报出来的归因也跟着变。
		MaxResponseBytes: maxUpstreamResponseBytes,
		Headers:          ask.headers(),
		Accept:           ask.accept,
		ProxyURL:         ask.proxyURL,
		// EgressCheck 刻意留空：出网判定已经在 dialer 的拨号层绑进 transport 里
		// （s.transportFor 对自有上游用 GetChecked），再填一份就是两个校验点。
	}
	return &executorCall{name: cand.Executor, proto: proto, exec: ex, attempt: attempt}, nil
}

// headers 复制供应商的附加头。执行器会剥掉 Authorization / Host / 逐跳头，
// 复制一份是为了不改配置里的 map（Attempt 是短生命周期数据，配置不是）。
func (ask executorAsk) headers() map[string]string {
	if ask.prov == nil || len(ask.prov.ExtraHeaders) == 0 {
		return nil
	}
	out := make(map[string]string, len(ask.prov.ExtraHeaders))
	for k, v := range ask.prov.ExtraHeaders {
		out[k] = v
	}
	return out
}

// planCandidateFor 从计划里取出该 provider 的候选。
//
// 计划里同一 provider 可能出现多次（不同 upstream_model），取第一条：执行器名与
// provider 是一对一的（一家上游只会用一种协议形态），后面的重复项不改变结论。
func planCandidateFor(plan policy.RoutingPlan, provider string) (policy.RouteCandidate, bool) {
	for _, c := range plan.Fallbacks {
		if c.Provider == provider {
			return c, true
		}
	}
	return policy.RouteCandidate{}, false
}

// roundTrip 用执行器打一次上游，返回 relay 能直接消费的结构。
//
// 为什么要过一层 *http.Response 而不是把 relay 改成吃 Outcome：relay 是全仓行为最密
// 的一段（usage 扫描、TTFT、看门狗触达、流式逐段、处理器包装），改它的签名等于把
// 计量的事实来源搬进接线层 —— 那是边界 1 禁止的方向。这里只做形状适配：状态码、
// 过滤后的响应头、体积声明、以及**未经改写的字节流**。
func (c *executorCall) roundTrip(ctx context.Context) (*http.Response, error) {
	out, err := c.exec.Execute(ctx, c.attempt)
	if err != nil {
		return nil, err
	}
	if out.Body == nil {
		// error 为空却没有 body：执行器实现的自相矛盾。宁可按失败处理，
		// 也不交给 relay 一个 nil Body —— 那会在 io.Copy 里 panic，
		// 而 panic 在这条链上意味着客户端拿到一个没有任何记录的断连。
		return nil, fmt.Errorf("执行器 %s 返回了没有 body 的交换结果", c.name)
	}
	return &http.Response{
		StatusCode:    out.StatusCode,
		Header:        out.Headers,
		Body:          out.Body,
		ContentLength: out.ContentLength,
		// Proto 三项是必填形态：relay 不读它们，但 http.Response 的零值 Proto
		// 会让任何后续的调试打印（httputil.DumpResponse）第一行就是空的。
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}, nil
}

// executorExchangeReason 把一次委托交换折算成稳定的失败维度（§3.I 的指标标签）。
//
// 三个来源按次序判，返回空串表示「这次交换没有失败码」：
//
//  1. ExecutionError 且码在注册表内 —— 直接用它（封闭集合，见 reasons.go）；
//  2. 其它错误（含码不在表里）—— wiring_unclassified，不冒充 reasons.go 里的任何一个码；
//  3. 交换成功但上游返回 4xx/5xx —— 用 executor 包里**已导出的**那两个常量，
//     阈值（4xx/5xx）与包内非导出的 reasonForStatus 同形。这里不写字符串字面量，
//     否则将来执行器改分类口径，指标会跟着历史归因分叉。
//
// 注意上游 4xx/5xx 算进「失败」维度是有意的：这两个码在执行器侧的定义就是
// 「一次完成了的交换、但对方明确说不行」。看板要把执行器自身故障与上游业务状态
// 分开看，靠的是 reason 标签，不是靠这里少记一笔。
func executorExchangeReason(err error, statusCode int) string {
	if err != nil {
		var ee *executor.ExecutionError
		// 只认注册表内的码：ReasonCode.String() 对未注册值会拼出
		// executor_unregistered(<原样>)，那串东西可能带任意文本，不能进标签。
		if errors.As(err, &ee) && ee.Code.Valid() {
			return string(ee.Code)
		}
		return executorReasonUnclassified
	}
	switch {
	case statusCode >= 400 && statusCode < 500:
		return string(executor.ReasonUpstreamClientStatus)
	case statusCode >= 500:
		return string(executor.ReasonUpstreamServerStatus)
	}
	return ""
}

// upstreamFailMessage 把一次上游交换的失败折算回现网那句归因文本。
//
// 执行器的错误文本刻意不含底层措辞（executor.ExecutionError.Error() 只拼稳定码），
// 所以「是不是超时」不能靠 contains 判断，要看码；2.x 那条路径仍然按文本判
// （transport 直接返回 net/url 的错误，那里没有稳定码可用）。
//
// 调用方必须先排掉「客户端真的走了」再进这里（forwarder 的归因块就是这个次序）：
// 委托时执行器把同一个 deadline 又包了一层（http.go :152），到点时先动的是哪个
// ctx 没有保证，于是「我们的时限到了」在执行器侧可能报成 caller_canceled。
// 次序保证了 parent ctx 还活着 —— 那 caller_canceled 只可能是那个派生时限，
// 归因与 2.x 同形；反过来若把它当「客户端断开」放行，一次正常超时就会变成
// 不给这家记失败的 499，而熔断口径跟着抖。
func upstreamFailMessage(err error, provider string, timeout time.Duration) (string, bool) {
	var ee *executor.ExecutionError
	if errors.As(err, &ee) {
		switch ee.Code {
		case executor.ReasonTimeout, executor.ReasonCallerCanceled:
			return fmt.Sprintf("供应商 %s 请求超时（%s）", provider, timeout), true
		}
		return "", false
	}
	msg := err.Error()
	if strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "Client.Timeout") {
		return fmt.Sprintf("供应商 %s 请求超时（%s）", provider, timeout), true
	}
	return "", false
}
