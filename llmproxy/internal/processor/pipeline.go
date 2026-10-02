package processor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// stage 是 Pipeline 里已装配的一个处理器槽位。
type stage struct {
	spec      Spec
	proc      Processor
	hasStream bool
	index     int
}

// Pipeline 是一条按 Spec 列表装配好的处理器链，可被多条请求并发复用。
//
// 装配完成后 stages 与 policyVersion 不再变化（Registry.Build 是唯一构造点），
// 所以读路径不需要锁；请求态全部活在每次调用的局部变量里。
type Pipeline struct {
	stages        []stage
	policyVersion string
	clock         func() time.Time
}

// Specs 返回链上所有声明（含阶段），按装配顺序。
func (p *Pipeline) Specs() []Spec {
	out := make([]Spec, 0, len(p.stages))
	for _, st := range p.stages {
		out = append(out, st.spec)
	}
	return out
}

// PolicyVersion 返回审计里带的策略版本（可能为空）。
func (p *Pipeline) PolicyVersion() string { return p.policyVersion }

// Len 返回链上处理器数量。
func (p *Pipeline) Len() int { return len(p.stages) }

// HasStageFor 报告某个阶段是否有处理器参与。
// 接线方（主线/H 包）用它决定「这一路要不要调用 pipeline」。
func (p *Pipeline) HasStageFor(phase Phase) bool {
	for _, st := range p.stages {
		if st.spec.Phase == phase {
			return true
		}
	}
	return false
}

// StagesFor 返回某个阶段上的处理器名（按装配顺序），供管理台解释链条。
func (p *Pipeline) StagesFor(phase Phase) []string {
	var out []string
	for _, st := range p.stages {
		if st.spec.Phase == phase {
			out = append(out, st.spec.Name)
		}
	}
	return out
}

// Request 是一次请求侧处理（before-classify / before-route / before-upstream）的输入。
//
// 这里刻意不含任何金额、token 计量或供应商凭证字段：处理器不参与计费结论（§2.6）。
type Request struct {
	RequestID string
	Model     string
	Stream    bool
	Metadata  json.RawMessage
	Body      *Body
	Policy    policy.PolicyContext
	Chain     policy.ScopeChain
	Now       time.Time
}

// Response 是一次响应侧处理的输入。Stream=true 时应当走 WrapStream；
// Stream=false 时 Body 已是缓冲形态。
type Response struct {
	RequestID   string
	Model       string
	StatusCode  int
	ContentType string
	Stream      bool
	Metadata    json.RawMessage
	Body        *Body
	Policy      policy.PolicyContext
	Chain       policy.ScopeChain
	Now         time.Time
}

// AuditInput 是 audit 阶段的输入。它**没有** Body 字段：
// 审计阶段只能看元数据，这是结构上的保证，比「文档里写别读」可靠。
type AuditInput struct {
	RequestID string
	Model     string
	Metadata  json.RawMessage
	Policy    policy.PolicyContext
	Chain     policy.ScopeChain
	Now       time.Time
}

// Result 是一次 Pipeline 调用的结果。
//
// Body 语义（§2.9 规则 8 的接线契约）：
//   - 未启用正文处理（或处理器全部跳过）→ Body 为 nil 且 Buffered=false，
//     调用方继续把原始流透传下去，不会因为接了 pipeline 而缓存整个请求；
//   - Buffered=true → 原始流已被本链消费，调用方必须改为发送 Result.Body。
type Result struct {
	RequestID     string
	PolicyVersion string
	Body          []byte
	Buffered      bool
	// BufferingNotice 是 §2.9 规则 8 要求显式声明的那句话（未缓冲时为空）。
	// 把它做成数据而不是文档里的一句话：接线方（主线/H 包）可以在响应头与日志里
	// 原样带出来，审计与代码解释同一件事实，不会两份口径。
	BufferingNotice string
	Elapsed         time.Duration
	Rewrites        []Rewrite
	Reasons         []Reason
	Outcome         Reason
	Entries         []AuditEntry
	Versions        []NameVersion
	Audit           AuditRecord
	Metadata        json.RawMessage
}

// RunRequest 跑请求侧三个阶段。
func (p *Pipeline) RunRequest(ctx context.Context, req *Request) (*Result, error) {
	if req == nil {
		return nil, Errorf(ErrConfigInvalid, "请求为空")
	}
	st := &runState{cur: req.Body, started: p.clock()}
	err := p.run(ctx, st, runArgs{
		now: req.Now, requestID: req.RequestID, model: req.Model, stream: req.Stream,
		pctx: req.Policy, chain: req.Chain, metadata: req.Metadata,
	}, func(s Spec) bool { return s.Phase.IsRequestPhase() })
	return p.finish(st, req.RequestID, err), err
}

// RunResponse 跑响应侧阶段（已缓冲的形态）。
//
// 流式响应必须用 WrapStream：把 SSE 读成一块再处理，就是把整段响应缓存进内存，
// 而 forwarder 现在的流式路径（边收边写 + 空闲看门狗）正是靠「不缓存」才成立的。
func (p *Pipeline) RunResponse(ctx context.Context, resp *Response) (*Result, error) {
	if resp == nil {
		return nil, Errorf(ErrConfigInvalid, "响应为空")
	}
	st := &runState{cur: resp.Body, started: p.clock()}
	err := p.run(ctx, st, runArgs{
		now: resp.Now, requestID: resp.RequestID, model: resp.Model, stream: resp.Stream,
		statusCode: resp.StatusCode, contentType: resp.ContentType,
		pctx: resp.Policy, chain: resp.Chain, metadata: resp.Metadata,
	}, func(s Spec) bool { return s.Phase == PhaseAfterUpstream })
	return p.finish(st, resp.RequestID, err), err
}

// RunAudit 跑 audit 阶段：只喂元数据，正文句柄恒为 nil。
func (p *Pipeline) RunAudit(ctx context.Context, in *AuditInput) (*Result, error) {
	if in == nil {
		return nil, Errorf(ErrConfigInvalid, "审计输入为空")
	}
	st := &runState{started: p.clock()}
	err := p.run(ctx, st, runArgs{
		now: in.Now, requestID: in.RequestID, model: in.Model,
		pctx: in.Policy, chain: in.Chain, metadata: in.Metadata,
	}, func(s Spec) bool { return s.Phase == PhaseAudit })
	res := p.finish(st, in.RequestID, err)
	res.Buffered = false // 审计阶段绝不缓冲正文，即便出错也不改变这个事实
	res.Body = nil
	// 审计视图与结果口径必须一致：越权声明 transform 的审计处理器伪造产出时，
	// finish 里的 record 会先于这两行落下 buffered 标记，这里一并纠正回来，
	// 否则审计会宣称发生了从未存在的缓冲。
	res.Audit.Buffered = false
	res.Audit.Untouched = true
	res.BufferingNotice = "" // 未缓冲时不许留下「已进入缓冲管道」的声明
	return res, err
}

// runArgs 是同一次调用在各阶段间共享的只读输入。
type runArgs struct {
	now         time.Time
	requestID   string
	model       string
	stream      bool
	statusCode  int
	contentType string
	pctx        policy.PolicyContext
	chain       policy.ScopeChain
	metadata    json.RawMessage
}

// runState 是一次调用的可变状态。
type runState struct {
	cur      *Body
	buffered bool
	// transformed 表示 cur 里的字节已由链上某个处理器产出，不再是客户端原文。
	// §2.9 规则 3 的判定依据：外部调用能送的是「脱敏后的正文」，
	// 而「还没人脱敏过的正文」就是原文，必须有管理员授权才能送。
	transformed bool
	entries     []AuditEntry
	rewrites    []Rewrite
	reasons     []Reason
	outcome     Reason
	metadata    json.RawMessage
	started     time.Time
}

// run 是三个阶段共用的执行循环。
//
// 失败处理规则（§2.9 规则 5 的落地）：
//   - classInfrastructure（超时、依赖故障）按 Spec.FailClosed 决定
//     拒绝整次请求，还是跳过该处理器并留原因码；
//   - classViolation（档位越权、超大小、目标未授权）与 classVerdict（判定成立）
//     **无视 FailClosed 一律拒绝** —— 把「跳过安全检查」做成一个可配置的兜底，
//     等于允许运营用一个布尔值关掉脱敏与出网白名单。
func (p *Pipeline) run(ctx context.Context, st *runState, args runArgs, selectStage func(Spec) bool) error {
	for _, stg := range p.stages {
		spec := stg.spec
		if !selectStage(spec) {
			continue
		}
		entry := newEntry(spec)
		in := &Input{
			RequestID:         args.requestID,
			Phase:             spec.Phase,
			Model:             args.model,
			Purpose:           args.pctx.Purpose,
			Stream:            args.stream,
			StatusCode:        args.statusCode,
			ContentType:       args.contentType,
			Metadata:          args.metadata,
			DeclaredBodyBytes: st.cur.DeclaredBytes(),
			Policy:            args.pctx,
			Chain:             args.chain,
			Now:               args.now,
			Spec:              spec,
			access:            spec.BodyAccess,
			body:              st.cur,
			transformed:       st.transformed,
		}
		stageStarted := p.clock()
		out, err := p.invoke(ctx, stg, in)
		entry.Elapsed = p.clock().Sub(stageStarted)
		// 留痕必须在成功与失败两条路径上都做：被拒绝的处理器同样要能审出它试过什么。
		entry.DeniedReads = in.deniedReads
		entry.SummaryOnly = in.summaryOnly
		entry.GrantReason = in.grantReason

		if in.read {
			// 读了正文就是 buffered pipeline（规则 8）：审计与调用方都要看到这个事实。
			entry.Buffered = true
			st.buffered = true
			entry.InputBytes = in.body.readBytesOf()
			if data := in.body.bufferedData(); data != nil {
				entry.InputHash = sha256Hex(data)
			}
		}

		if err != nil {
			reason, class := classify(err)
			entry.Outcome = reason
			entry.Reasons = Reasons([]Reason{reason})
			if class == classInfrastructure && !spec.FailClosed {
				// fail_open：跳过。out 被丢弃，正文保持进入本阶段前的形态，
				// 但原因码必须留痕 —— 否则「脱敏挂了但请求成功」在审计里看不出区别。
				entry.Outcome = ReasonFailOpenSkipped
				entry.Reasons = Reasons([]Reason{reason, ReasonFailOpenSkipped})
				st.reasons = append(st.reasons, reason, ReasonFailOpenSkipped)
				if st.outcome == "" {
					st.outcome = ReasonFailOpenSkipped
				}
				st.entries = append(st.entries, entry)
				continue
			}
			st.reasons = append(st.reasons, reason)
			st.entries = append(st.entries, entry)
			return err
		}
		if out == nil {
			out = &Output{}
		}
		entry.Outcome = out.Reason
		if entry.Outcome == "" {
			entry.Outcome = ReasonOK
		}
		entry.Reasons = Reasons([]Reason{entry.Outcome})
		entry.Attempts = out.Attempts
		entry.Rewrites = out.Rewrites
		st.rewrites = append(st.rewrites, out.Rewrites...)
		if out.Metadata != nil {
			st.metadata = out.Metadata
		}
		if out.Body != nil {
			if vErr := p.checkReplacement(spec, out.Body); vErr != nil {
				entry.Outcome, _ = classify(vErr)
				st.entries = append(st.entries, entry)
				return vErr
			}
			// §2.9 规则 2：原始正文处理完立即释放。释放的是**上一档**的正文，
			// 也就是产出新正文之前的那一份。
			if st.cur != nil {
				st.cur.discard()
				entry.ReleaseOrigin = true
			}
			entry.OutputBytes = int64(len(out.Body))
			entry.OutputHash = sha256Hex(out.Body)
			entry.Buffered = true
			st.cur = NewOwnedBody(out.Body)
			st.buffered = true
			st.transformed = true
		}
		st.entries = append(st.entries, entry)
	}
	return nil
}

// MaxBodyAccess 返回整条链需要的最高正文档位。
//
// 接线方（主线/H 包）在把 pipeline 插进 forwarder 之前先问这个：
// 只有链上全是 metadata-only 时，才允许继续走「不缓存任何请求」的透传路径（规则 7）。
func (p *Pipeline) MaxBodyAccess() policy.BodyAccess {
	maxAccess := policy.BodyMetadataOnly
	for _, st := range p.stages {
		if bodyAccessRank(st.spec.BodyAccess) > bodyAccessRank(maxAccess) {
			maxAccess = st.spec.BodyAccess
		}
	}
	return maxAccess
}

// RequiresBodyBuffering 报告这条链是否至少要读一次正文。
// false 时接线方可以完整保留现有的流式透传路径（规则 7 的接线前提）。
func (p *Pipeline) RequiresBodyBuffering() bool { return p.MaxBodyAccess().CanReadBody() }

// bodyAccessRank 给三档排序，只用于「这条链最高需要哪一档」这一种问题。
//
// A 包没有提供档位大小关系的方法，这是刻意的：三档不是一把权限刻度尺，而是三种
// 能力形态（inspect 能读不能写、transform 能写、metadata 都不能）。所以这张表留在
// E 的使用侧，并且只用于取最大值；「够不够读 / 够不够换」的判定一律走
// policy.BodyAccess 的 CanReadBody / CanReplaceBody —— 否则 E 就有了第二套档位语义。
func bodyAccessRank(a policy.BodyAccess) int {
	switch a {
	case policy.BodyTransform:
		return 2
	case policy.BodyInspect:
		return 1
	default:
		return 0
	}
}

// BodyAccessAdmission 是一个 Spec 的档位准入声明（规则 8 要求的显式对外声明）。
type BodyAccessAdmission struct {
	Processor     string            `json:"processor"`
	Type          string            `json:"type"`
	Version       string            `json:"version"`
	Phase         Phase             `json:"phase"`
	Access        policy.BodyAccess `json:"access"`
	NeedsBuffer   bool              `json:"needs_buffer"`
	ReplacesBody  bool              `json:"replaces_body"`
	RawBodyWanted bool              `json:"raw_body_wanted,omitempty"`
}

// BodyAccessAdmissions 逐条列出链上处理器需要的档位，不做任何判定。
// 管理台与接线日志用它回答三个问题：会读正文吗、会换正文吗、会把原文送出网关吗。
func (p *Pipeline) BodyAccessAdmissions() []BodyAccessAdmission {
	out := make([]BodyAccessAdmission, 0, len(p.stages))
	for _, st := range p.stages {
		out = append(out, BodyAccessAdmission{
			Processor:     st.spec.Name,
			Type:          st.spec.Type,
			Version:       st.spec.Version,
			Phase:         st.spec.Phase,
			Access:        st.spec.BodyAccess,
			NeedsBuffer:   st.spec.BodyAccess.CanReadBody(),
			ReplacesBody:  st.spec.BodyAccess.CanReplaceBody(),
			RawBodyWanted: st.spec.AllowRawBody,
		})
	}
	return out
}

// checkReplacement 校验处理器产出的新正文没有越过声明的档位与大小。
func (p *Pipeline) checkReplacement(spec Spec, body []byte) error {
	if !spec.BodyAccess.CanReplaceBody() {
		return Errorf(ErrBodyReplaceDenied, "%s 档位为 %s，却产出了 %d 字节新正文",
			spec.Name, spec.BodyAccess, len(body))
	}
	if int64(len(body)) > spec.MaxOutputBytes {
		return Errorf(ErrOutputTooLarge, "%s 产出 %d 字节，超过 max_output_bytes %d",
			spec.Name, len(body), spec.MaxOutputBytes)
	}
	return nil
}

// invoke 带超时地调用一个处理器。
func (p *Pipeline) invoke(ctx context.Context, stg stage, in *Input) (*Output, error) {
	spec := stg.spec
	// 上限放宽到 2×MaxTimeout 而不是直接报错：Spec.Validate 已经按 MaxTimeout 拒过
	// 越界声明，正常路径到不了这里。真到了（有人绕过 Validate 手搭 Spec）时
	// **拒绝执行**比「悄悄把它夹到 2 分钟」好 —— 后者会让一个本想设 10 分钟的配置
	// 变成 2 分钟，表现为大量超时，而审计里看不出原因。
	if spec.Timeout <= 0 || spec.Timeout > 2*MaxTimeout {
		return nil, Errorf(ErrConfigInvalid, "%s: timeout %s 越界（上限 %s）", spec.Name, spec.Timeout, MaxTimeout)
	}
	procCtx, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()
	out, err := stg.proc.Process(procCtx, in)
	if errors.Is(procCtx.Err(), context.DeadlineExceeded) {
		// 处理器内部没判 deadline 时由运行时兜住：超时归为基础设施失败，
		// 于是 fail_open 的增强处理器挂了不拖垮请求，而脱敏这类 fail_closed 的会拒。
		if err == nil {
			return nil, Errorf(ErrTimeout, "%s 超过 %s", spec.Name, spec.Timeout)
		}
		return nil, Errorf(ErrTimeout, "%s 超过 %s: %v", spec.Name, spec.Timeout, err)
	}
	return out, err
}

// currentBytes 返回链条当前的正文字节（已缓冲时）。
func (st *runState) currentBytes() ([]byte, error) {
	if st.cur == nil {
		return nil, ErrNoBody
	}
	return st.cur.buffer(AbsoluteMaxInputBytes)
}

// finish 组装 Result。即便出错也要返回 Result：
// 被拒绝的请求同样要进审计（谁被挡住了、为什么），这是审计闭环的前提。
func (p *Pipeline) finish(st *runState, requestID string, err error) *Result {
	res := &Result{
		RequestID:     requestID,
		PolicyVersion: p.policyVersion,
		Elapsed:       p.clock().Sub(st.started),
		Rewrites:      mergeRewrites(st.rewrites),
		Reasons:       Reasons(st.reasons),
		Entries:       st.entries,
		Versions:      versionsOf(p.Specs()),
		Buffered:      st.buffered,
		Metadata:      st.metadata,
	}
	if err != nil {
		reason, _ := classify(err)
		res.Outcome = reason
		res.Reasons = Reasons(append(res.Reasons, reason))
	} else if st.outcome != "" {
		// 不用 res.Reasons[0]：那个切片是按字典序排过的，取第一个等于把
		// 「本次调用的结论」交给字符串顺序决定，回放时解释会变。
		res.Outcome = st.outcome
	} else {
		res.Outcome = ReasonOK
	}
	if st.buffered {
		if data, derr := st.currentBytes(); derr == nil {
			res.Body = data
		}
	}
	res.Audit = p.record(requestID, res, Phase(""))
	res.BufferingNotice = bufferingNotice(res.Buffered, res.Body)
	return res
}

// bufferingNotice 生成规则 8 要求的显式声明。
//
// 只有真的缓冲了正文才有这句话：没缓冲时编造一句「已进入缓冲管道」
// 会让接线方据此改掉透传路径，反而凭空引入缓存。
func bufferingNotice(buffered bool, body []byte) string {
	if !buffered {
		return ""
	}
	return fmt.Sprintf("请求/响应正文已进入缓冲处理管道（%d 字节），调用方须改用 Result.Body 继续转发", len(body))
}

// record 从 Result 生成审计视图。
func (p *Pipeline) record(requestID string, res *Result, phase Phase) AuditRecord {
	return AuditRecord{
		RequestID:     requestID,
		PolicyVersion: p.policyVersion,
		Phase:         phase,
		Buffered:      res.Buffered,
		Untouched:     !res.Buffered,
		Elapsed:       res.Elapsed,
		Entries:       res.Entries,
		Versions:      res.Versions,
	}
}

// ------------------------------------------------------------------ 流式响应

// streamStats 让运行时问出「这条包装链内部同时缓存了多少字节」。
// 每个流式实现都要往下问一层，因为包装链中间可能夹着计数器。
type streamStats interface {
	streamMaxBuffered() int
}

// maxBufferedOf 对任意 reader 取高水位；不认识的就返回 0。
func maxBufferedOf(r io.Reader) int {
	if ss, ok := r.(streamStats); ok {
		return ss.streamMaxBuffered()
	}
	return 0
}

// WrapStream 把响应流交给 after-upstream 的流式处理器逐段包装，**不缓存整段响应**。
//
// 为什么不用统一接口：统一成 Process 就得先把流读成字节再交回，那正好违反 §2.9
// 规则 7。所以这里返回一个增量读者，Spec.Timeout 只约束**包装建立**这一步
// （网络往返、配置校验）；逐块读取的时限仍由 forwarder 的空闲看门狗负责 ——
// 一次长回答可以正常跑几分钟，按总时限掐会把好端端的流切断。
// 链上任何一个处理器不支持流式，本方法在**读第一个字节之前**就返回错误 —— 且这条错误
// 不受 FailClosed 影响（见下面的 classViolation 说明）。此时调用方还没发状态码，
// 可以干净地失败，或者由接线方自己决定换一条不含该处理器的链。
func (p *Pipeline) WrapStream(ctx context.Context, resp *Response) (*Stream, error) {
	if resp == nil {
		return nil, Errorf(ErrConfigInvalid, "响应为空")
	}
	st := &runState{cur: resp.Body, started: p.clock()}
	var current io.Reader
	if resp.Body != nil {
		// 取读者本身不消耗任何字节：未缓冲时返回的就是底层那个 reader。
		// 真正的字节只有在处理器调用它时才流动 —— metadata-only 的链一次都不会调用。
		r, err := resp.Body.stream()
		if err != nil {
			return nil, err
		}
		current = r
	}
	meters := make([]*streamMeter, 0, len(p.stages))
	for _, stg := range p.stages {
		spec := stg.spec
		if spec.Phase != PhaseAfterUpstream {
			continue
		}
		entry := newEntry(spec)
		st.entries = append(st.entries, entry)
		idx := len(st.entries) - 1
		in := &Input{
			RequestID:         resp.RequestID,
			Phase:             spec.Phase,
			Model:             resp.Model,
			Purpose:           resp.Policy.Purpose,
			Stream:            true,
			StatusCode:        resp.StatusCode,
			ContentType:       resp.ContentType,
			Metadata:          resp.Metadata,
			DeclaredBodyBytes: resp.Body.DeclaredBytes(),
			Policy:            resp.Policy,
			Chain:             resp.Chain,
			Now:               resp.Now,
			Spec:              spec,
			access:            spec.BodyAccess,
			// body 刻意留空：流式路径上唯一的正文入口是下面的 meter 读者。
			// 把原始句柄也给出去，处理器就能用 in.Body() 整段缓冲，
			// 或者把已被上一个过滤器消费过的流再读一遍（两种都只读到半截内容）。
			body:        nil,
			transformed: false,
		}
		sp, ok := stg.proc.(StreamProcessor)
		if !ok {
			reason, class := classify(ErrStreamUnsupported)
			st.entries[idx].Outcome = reason
			st.entries[idx].Reasons = Reasons([]Reason{reason})
			st.reasons = append(st.reasons, reason)
			// 这里**没有** fail_open 的余地：ErrStreamUnsupported 在 reason.go 里被归成
			// classViolation（「跳过 = 把没过滤的响应原样放给客户端」），而违规类无视 FailClosed。
			// 写成 if class != classInfrastructure || spec.FailClosed 的话，条件恒真却看着像
			// 有个逃生口 —— 以后有人会「顺手把它修成能跳过」，那才是真缺口。所以直接无条件失败。
			return nil, Errorf(ErrStreamUnsupported,
				"%s 无法在流式响应上增量运行（%s/%s），此时尚未读取任何正文", spec.Name, reason, class)
		}
		if current == nil {
			return nil, Errorf(ErrNoBody, "%s 需要处理响应流，但这次调用没有响应正文", spec.Name)
		}
		// 计数器放在过滤器**上游**：它量的是这个过滤器实际消费到的字节与摘要。
		meter := &streamMeter{src: current, name: spec.Name, entryIdx: idx}
		meters = append(meters, meter)
		procCtx, cancel := context.WithTimeout(ctx, spec.Timeout)
		wrapped, err := sp.ProcessStream(procCtx, in, meter)
		cancel()
		if err != nil {
			reason, class := classify(err)
			st.entries[idx].Outcome = reason
			st.entries[idx].Reasons = Reasons([]Reason{reason})
			if class == classInfrastructure && !spec.FailClosed {
				st.entries[idx].Outcome = ReasonFailOpenSkipped
				st.reasons = append(st.reasons, reason, ReasonFailOpenSkipped)
				continue
			}
			st.reasons = append(st.reasons, reason)
			return nil, err
		}
		if wrapped == nil {
			wrapped = current
		}
		st.entries[idx].Buffered = false
		current = wrapped
	}
	return &Stream{
		reader:    current,
		pipeline:  p,
		state:     st,
		meters:    meters,
		requestID: resp.RequestID,
	}, nil
}

// Stream 是增量过滤后的响应流。
type Stream struct {
	reader    io.Reader
	pipeline  *Pipeline
	state     *runState
	meters    []*streamMeter
	requestID string

	outHash   incrementalHash
	outBytes  int64
	done      bool
	err       error
	stoppedAt time.Time
}

// HasProcessors 报告这条链上是否真的有流式处理器。
// false 时调用方应当继续走原有透传路径（§2.9 规则 7 的接线前提）。
func (s *Stream) HasProcessors() bool { return len(s.meters) > 0 }

// Read 实现 io.Reader：每块数据过完链后计数并增量哈希。
func (s *Stream) Read(p []byte) (int, error) {
	if s.reader == nil {
		return 0, io.EOF
	}
	n, err := s.reader.Read(p)
	if n > 0 {
		s.outBytes += int64(n)
		s.outHash.write(p[:n])
	}
	if err != nil && !s.done {
		s.done = true
		s.err = err
		s.stoppedAt = s.pipeline.clock()
	}
	return n, err
}

// MaxBufferedBytes 返回链上流式处理器的缓冲高水位。
//
// 这是给测试用的**可证伪**断言：它统计实现内部同时持有的最大字节数，
// 因此可以断言「高水位远小于响应总长」，而不只是断言「看起来像流式的」。
func (s *Stream) MaxBufferedBytes() int { return maxBufferedOf(s.reader) }

// Audit 返回累计的审计记录。EOF 之后调用最完整。
func (s *Stream) Audit() AuditRecord {
	st := s.state
	for i := range st.entries {
		if st.entries[i].OutputBytes == 0 && st.entries[i].Outcome != ReasonFailOpenSkipped {
			st.entries[i].OutputBytes = s.outBytes
			st.entries[i].OutputHash = s.outHash.hex()
			st.entries[i].Elapsed = s.elapsed()
		}
	}
	for _, meter := range s.meters {
		if meter.entryIdx >= 0 && meter.entryIdx < len(st.entries) {
			st.entries[meter.entryIdx].InputBytes = meter.readBytes
			st.entries[meter.entryIdx].InputHash = meter.hash.hex()
		}
	}
	return AuditRecord{
		RequestID:     s.requestID,
		PolicyVersion: s.pipeline.policyVersion,
		Phase:         PhaseAfterUpstream,
		Buffered:      false,
		Untouched:     false,
		Elapsed:       s.elapsed(),
		Entries:       st.entries,
		Versions:      versionsOf(s.pipeline.Specs()),
	}
}

func (s *Stream) elapsed() time.Duration {
	if !s.stoppedAt.IsZero() {
		return s.stoppedAt.Sub(s.state.started)
	}
	return s.pipeline.clock().Sub(s.state.started)
}

// Err 返回流终止时的错误（io.EOF 记 nil）。
func (s *Stream) Err() error {
	if errors.Is(s.err, io.EOF) {
		return nil
	}
	return s.err
}

// streamMeter 量一个过滤器消费到的字节并增量哈希（内存 O(1)）。
type streamMeter struct {
	src       io.Reader
	name      string
	entryIdx  int
	readBytes int64
	hash      incrementalHash
}

func (m *streamMeter) Read(p []byte) (int, error) {
	n, err := m.src.Read(p)
	if n > 0 {
		m.readBytes += int64(n)
		m.hash.write(p[:n])
	}
	return n, err
}

// streamMaxBuffered 把问题往下传：计数器自己不缓存任何字节。
func (m *streamMeter) streamMaxBuffered() int { return maxBufferedOf(m.src) }

// incrementalHash 是 sha256 的流式封装，供不缓冲全文的路径算内容指纹。
type incrementalHash struct {
	h     hash.Hash
	wrote bool
}

func (x *incrementalHash) write(data []byte) {
	if x.h == nil {
		x.h = sha256.New()
	}
	x.h.Write(data)
	x.wrote = true
}

// hex 返回带算法前缀的摘要；没写过任何字节时返回空串（审计里区分「没内容」和「内容为空」）。
func (x *incrementalHash) hex() string {
	if !x.wrote {
		return ""
	}
	return "sha256:" + hex.EncodeToString(x.h.Sum(nil))
}
