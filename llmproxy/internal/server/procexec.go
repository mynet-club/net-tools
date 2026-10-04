package server

// 本文件是 §3.0「执行期接线」的执行半段：把装配好的处理器链插进请求生命周期。
//
// 三个决定都在这里写明，因为它们都是别人将来会问「为什么这样排」的地方：
//
//  1. **只有 enforce 参与**。影子模式的手册定义就是「不读正文、不改路由」（§3.0 线 1），
//     而读正文的处理器一旦在影子里跑起来，影子就不再是只读旁观者：
//     sidecar 会被真实流量打，脱敏改写会消耗上游配额。
//  2. **「before-route」以选路（router.PickFromPreferring）为界，不以计划计算为界**。
//     判定核 policyJudge 被管理口的路由模拟复用，而模拟必须一点痕迹都不留
//     （§3.0 线 1、policyJudge 的注释）：把处理器放进去，模拟一次就会真打一次 sidecar。
//     所以请求侧阶段排在判定与配额之后、选路之前。
//  3. **装不起来就拒，不放行**。声明命中了这条范围链却装配失败（缺参数文件、
//     端点不在白名单、版本对不上）时，enforce 下这个请求被拒而不是原文送出去 ——
//     「脱敏没跑成但请求照常」正是 §2.9 规则 5 禁止的形态。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/processor"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// requestPhases 是请求侧的三个阶段，顺序与 §2.6 的执行次序一致。
var requestPhases = []processor.Phase{
	processor.PhaseBeforeClassify,
	processor.PhaseBeforeRoute,
	processor.PhaseBeforeUpstream,
}

// procCall 是一次请求的处理器执行上下文。nil 表示处理器不参与这次请求。
type procCall struct {
	server *Server
	pipe   *processor.Pipeline
	// err 是「本该参与却装配不起来」的原因；非空时请求必须被拒（见文件头决定 3）。
	err error

	ctx   policy.PolicyContext
	chain policy.ScopeChain

	requestID string
	model     string
	path      string
	scope     string
	// actor 是这次请求的范围原值（用户名，静态 key 为空）：留痕的归属由它算，
	// 与拒绝/出网两条动作用同一条规则（见 audit30.go 的 requestAuditScope30）。
	actor  string
	stream bool
	now    time.Time
}

// processorCall 决定处理器是否参与这次请求，并带回执行上下文。
//
// 返回 nil 表示不参与（legacy、影子、本范围没有声明，或本范围根本没有生效的策略包 ——
// 那种情况按 §3.0 的「可按 scope 回滚到 legacy」理解）。
// 返回非 nil 且 err 非空表示「参与，但必须拒绝」。
func (s *Server) processorCall(rt *policyRuntime, scope, requestID, model, path string,
	stream bool, now time.Time) *procCall {
	if rt == nil || rt.mode != config.PolicyModeEnforce || rt.proc == nil {
		return nil
	}
	pc := &procCall{server: s, actor: scope, requestID: requestID, model: model, path: path, stream: stream, now: now}
	chain, err := policyChainFor(scope)
	if err != nil {
		pc.err = fmt.Errorf("范围链不合法: %w", err)
		pc.scope = scope
		return pc
	}
	pc.chain = chain
	pc.scope = chain.Display()
	// 版本取自本范围链生效的子集，与判定核同一口径（§6「审计版本必须取子集版本」）。
	res, version, err := rt.resolverFor(chain)
	if err != nil {
		// 没有包覆盖这条链 = 这个范围没启用 3.0。声明在这里不越权生效。
		return nil
	}
	id, err := policyIdentity(scope)
	if err != nil {
		pc.err = fmt.Errorf("身份不可构造: %w", err)
		return pc
	}
	ctx, err := policy.NewPolicyContext(id, policyPurposeFor(path), rt.dataLevel)
	if err != nil {
		pc.err = fmt.Errorf("策略上下文不合法: %v", err)
		return pc
	}
	ctx.PolicyVersion = version
	pc.ctx = ctx

	pipe, perr := rt.proc.pipelineFor(chain, version)
	pc.pipe = pipe
	pc.err = perr
	if perr == nil {
		pc.err = s.traceRawBodyGrant30(res, pc)
	}
	if pc.err == nil && pc.participates() {
		s.log.Debugf("event=processor_chain request_id=%s scope=%s policy_version=%s chain=%s buffer=%t",
			requestID, pc.scope, version, strings.Join(pc.chainNames(), ","), pc.pipe.RequiresBodyBuffering())
	}
	return pc
}

// traceRawBodyGrant30 给「链上有处理器声明要未脱敏正文、而且这次真的被授权了」留一条
// egress.allow，并在留痕写不进去时让这次请求根本进不到处理器（返回非空 err）。
//
// 为什么在这一层：sidecar 每次调用都自己现判（processor.Input 拿不到 request_id），
// 而「凭什么这份内容能出网」这条证据必须指得回是哪一次请求。判定仍然只有 A 包一个
// 真值源，这里只是把同一个结论在它有 request_id 的地方记下来 —— 于是运行时那次判定
// 与留痕可能隔着一次策略包发布，两个结论各自都成立：审计记的是「装配时已授权」，
// 处理器侧的 GrantReason 记的是「送出那一刻的判定」，两条都在，不做互相冒充。
//
// 只记被授权的这一半是刻意的：没授权时 sidecar 只拿到脱敏正文，那是缺省形态，
// requests 表逐条记着这次交换。把缺省也写一遍等于把审计表养成第二张流量表（§6 体积）。
//
// 写不进去就拒：锁定口径「任何降级不得绕过权限或隐私策略」在这一条上的意思就是
// 「写审计失败」不能变成「原文照常出网」。
func (s *Server) traceRawBodyGrant30(res *policy.Resolver, pc *procCall) error {
	names := rawBodyProcessors30(pc.pipe)
	if len(names) == 0 || res == nil {
		return nil
	}
	granted, reason := res.AllowsRawBody(pc.ctx, pc.chain, pc.now)
	if !granted {
		return nil
	}
	scope := requestAuditScope30(pc.actor)
	for _, name := range names {
		detail := egressDetail30{
			RequestID:     pc.requestID,
			Why:           egressWhyRawBody,
			DataLevel:     pc.ctx.DataLevel.String(),
			Processor:     name,
			AllowRawBody:  true,
			GrantReason:   string(reason),
			PolicyVersion: pc.ctx.PolicyVersion,
		}
		if err := s.auditDetail30(scope, pc.actor, auditActionEgressAllow30, "processor:"+name, detail); err != nil {
			return fmt.Errorf("原文出网授权(%s)的留痕写不进审计库，本次请求不予处理: %w", name, err)
		}
	}
	return nil
}

// rawBodyProcessors30 按装配顺序列出声明需要未脱敏正文的处理器名。
//
// 用 BodyAccessAdmissions 而不是新加一个 Pipeline 方法：那张表已经逐条给出
// RawBodyWanted，再加一个访问器就是同一件事的两个来源。
func rawBodyProcessors30(pipe *processor.Pipeline) []string {
	if pipe == nil {
		return nil
	}
	var out []string
	for _, adm := range pipe.BodyAccessAdmissions() {
		if adm.RawBodyWanted {
			out = append(out, adm.Processor)
		}
	}
	return out
}

// participates 报告这条链上是否真的有处理器。
func (pc *procCall) participates() bool {
	return pc != nil && pc.pipe != nil && pc.pipe.Len() > 0
}

// chainNames 按装配顺序给出链上的处理器名。
func (pc *procCall) chainNames() []string {
	if pc == nil || pc.pipe == nil {
		return nil
	}
	out := make([]string, 0, pc.pipe.Len())
	for _, spec := range pc.pipe.Specs() {
		out = append(out, spec.Name)
	}
	return out
}

// pendingFor 报告链上有没有参与某个阶段的处理器。
func (pc *procCall) pendingFor(phases ...processor.Phase) bool {
	if pc == nil || pc.pipe == nil {
		return false
	}
	for _, phase := range phases {
		if pc.pipe.HasStageFor(phase) {
			return true
		}
	}
	return false
}

// runRequest 跑请求侧阶段，返回要送给上游的正文字节。
//
// 未启用正文处理时原样返回 raw：Pipeline 一次都不会去碰那个句柄，
// 于是 §2.9 规则 7 的「不为了统一接口而缓存请求」在接线上仍然成立。
func (pc *procCall) runRequest(ctx context.Context, raw []byte) ([]byte, error) {
	if pc == nil {
		return raw, nil
	}
	if pc.err != nil {
		return raw, pc.err
	}
	if !pc.pendingFor(requestPhases...) {
		return raw, nil
	}
	res, err := pc.pipe.RunRequest(ctx, &processor.Request{
		RequestID: pc.requestID,
		Model:     pc.model,
		Stream:    pc.stream,
		Metadata:  procRequestMetadata(pc.path, len(raw)),
		Body:      processor.NewBufferedBody(raw),
		Policy:    pc.ctx,
		Chain:     pc.chain,
		Now:       pc.now,
	})
	pc.logResult("request", res, err)
	if err != nil {
		return raw, err
	}
	if res.Buffered && res.Body != nil {
		return res.Body, nil
	}
	return raw, nil
}

// runResponse 跑响应侧阶段（已缓冲的形态，即非流式响应）。
func (pc *procCall) runResponse(ctx context.Context, statusCode int, contentType string, data []byte) ([]byte, error) {
	if pc == nil {
		return data, nil
	}
	if pc.err != nil {
		return data, pc.err
	}
	if !pc.pendingFor(processor.PhaseAfterUpstream) {
		return data, nil
	}
	res, err := pc.pipe.RunResponse(ctx, &processor.Response{
		RequestID:   pc.requestID,
		Model:       pc.model,
		StatusCode:  statusCode,
		ContentType: contentType,
		Stream:      false,
		Metadata:    procResponseMetadata(statusCode, contentType, len(data)),
		Body:        processor.NewBufferedBody(data),
		Policy:      pc.ctx,
		Chain:       pc.chain,
		Now:         pc.now,
	})
	pc.logResult("response", res, err)
	if err != nil {
		return data, err
	}
	if res.Buffered && res.Body != nil {
		return res.Body, nil
	}
	return data, nil
}

// wrapStream 把流式响应交给 after-upstream 的流式处理器逐段包装（不缓存整段）。
//
// 必须在写状态码**之前**调用：WrapStream 在读取任何字节之前就会因为
// 「链上有不支持流式的处理器」而失败，那时还能干净地回一个错误；
// 等 200 已经发出去就只能给一个截断的流，客户端分不清「模型返回空」和「代理挂了」。
//
// src 由调用方给（relay 那侧是「上游读者 + 看门狗触达」那一层），本方法不接受
// *http.Response：包装链必须插在看门狗**下游**，否则过滤器卡住时没有人 touch 看门狗，
// 空闲超时形同废掉。
func (pc *procCall) wrapStream(ctx context.Context, statusCode int, contentType string,
	declared int64, src io.Reader) (*processor.Stream, error) {
	if pc == nil {
		return nil, nil
	}
	if pc.err != nil {
		return nil, pc.err
	}
	if !pc.pendingFor(processor.PhaseAfterUpstream) {
		return nil, nil
	}
	st, err := pc.pipe.WrapStream(ctx, &processor.Response{
		RequestID:   pc.requestID,
		Model:       pc.model,
		StatusCode:  statusCode,
		ContentType: contentType,
		Stream:      true,
		Metadata:    procResponseMetadata(statusCode, contentType, int(declared)),
		Body:        processor.NewBodyReader(src, declared),
		Policy:      pc.ctx,
		Chain:       pc.chain,
		Now:         pc.now,
	})
	if err != nil {
		pc.logStream(nil, err)
		return nil, err
	}
	return st, nil
}

// streamAudit 在流结束后补一条留痕（缓冲高水位是唯一能量化的「确实没缓存全文」证据）。
func (pc *procCall) streamAudit(st *processor.Stream) {
	if pc == nil || st == nil {
		return
	}
	rec := st.Audit()
	pc.logf("event=processor stage=stream request_id=%s scope=%s buffered=%t untouched=%t elapsed=%s max_buffered=%d versions=%s entries=%s",
		pc.requestID, pc.scope, rec.Buffered, rec.Untouched, rec.Elapsed, st.MaxBufferedBytes(),
		joinVersions(rec.Versions), joinEntries(rec.Entries))
}

// runAudit 跑 audit 阶段：只喂元数据。正文句柄在 E 包里是结构性缺席的，
// 接线方就算想带正文也没有入口（AuditInput 没有 Body 字段）。
func (pc *procCall) runAudit(ctx context.Context, metadata json.RawMessage) {
	if pc == nil || pc.pipe == nil || pc.err != nil {
		return
	}
	if !pc.pendingFor(processor.PhaseAudit) {
		return
	}
	res, err := pc.pipe.RunAudit(ctx, &processor.AuditInput{
		RequestID: pc.requestID,
		Model:     pc.model,
		Metadata:  metadata,
		Policy:    pc.ctx,
		Chain:     pc.chain,
		Now:       pc.now,
	})
	pc.logResult("audit", res, err)
}

// procRequestMetadata 组装进处理器的请求元数据。
//
// 只放路径与大小：请求头原样进 metadata 等于把 Authorization/Cookie 送进处理器，
// 而 sidecar 会把 metadata 一起投递出去（凭证走这条路比原文出网更糟）。
func procRequestMetadata(path string, size int) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"path": path, "bytes": size})
	return b
}

func procResponseMetadata(status int, contentType string, size int) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"status": status, "content_type": contentType, "bytes": size})
	return b
}

// procAuditMetadata 是给 audit 阶段处理器的输入：这次转发的**结论**，不是内容。
//
// audit 阶段的定位（§2.6）是「事后留痕与合规统计」，它能做的判断只到「这次转发属于哪类」。
// 字段集合刻意不含正文、错误原文与任何凭证：ErrorMsg 里可能有上游返回的内容片段，
// 而 §2.9 规则 6 允许的只有类型/范围/哈希/版本这一类。
func procAuditMetadata(rec *store.RequestRecord) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"request_id":     rec.RequestID,
		"error_type":     rec.ErrorType, // 空串 = 转发没出错；非空时只是错误**类别**，不含原文
		"model":          rec.Model,
		"provider":       rec.Provider,
		"status":         rec.StatusCode,
		"stream":         rec.Stream,
		"ok":             rec.OK,
		"attempts":       rec.Attempts,
		"policy_version": rec.PolicyVersion,
	})
	return b
}

// writeProcessorError 在**还没发过状态码**时把这次转发改判成处理器错误。
//
// 与 writeBadGateway 同一套理由：上游的 Content-Type / Content-Length 不清掉，
// 客户端就会按上游声明的规格去读这个 JSON 错误体。
func writeProcessorError(w http.ResponseWriter, err error) {
	status, kind, msg := processorHTTP(err)
	w.Header().Del("Content-Type")
	w.Header().Del("Content-Length")
	writeJSONError(w, status, kind, msg)
}

// bodyPipelineHeader 是 §2.9 规则 8 要的「这条请求进了哪种正文管道」声明头。
const bodyPipelineHeader = "X-Llmproxy-Body-Pipeline"

// markBodyPipeline 把一次正文管道形态**累加**进回话头，而不是覆盖。
//
// 覆盖会丢事实：请求侧被整段读过并改写过（buffered）的那条请求，响应侧仍可逐段包装
// （stream）。规则 8 要声明的是「这条请求进过 buffered pipeline」，只剩一个 stream
// 就等于排障时看不出正文曾被整段读过 —— 而「整段读过」正是大小上限与超时预算生效的地方。
func markBodyPipeline(h http.Header, mark string) {
	prev := h.Get(bodyPipelineHeader)
	if prev == "" {
		h.Set(bodyPipelineHeader, mark)
		return
	}
	if strings.Contains(prev, mark) {
		return
	}
	h.Set(bodyPipelineHeader, prev+","+mark)
}

// logResult 落一条处理器留痕。
//
// 字段集合就是 §2.9 规则 6 允许的那些：request ID、处理器名/类型/版本、阶段、
// 范围、原因码、字节数与摘要、耗时、档位。正文、字段名、命中关键词一律不出现 ——
// E 包的 AuditEntry 结构里本来就没有这些字段，日志照着结构写就不可能多写。
func (pc *procCall) logResult(stage string, res *processor.Result, err error) {
	if pc == nil || pc.pipe == nil {
		return
	}
	if res == nil {
		pc.logf("event=processor stage=%s request_id=%s scope=%s outcome=no_result err=%s",
			stage, pc.requestID, pc.scope, processorMessage(err))
		return
	}
	pc.logf("event=processor stage=%s request_id=%s scope=%s outcome=%s buffered=%t elapsed=%s versions=%s entries=%s",
		stage, pc.requestID, pc.scope, res.Outcome, res.Buffered, res.Elapsed,
		joinVersions(res.Versions), joinEntries(res.Entries))
}

func (pc *procCall) logStream(st *processor.Stream, err error) {
	if pc == nil {
		return
	}
	versions := ""
	if st != nil {
		versions = joinVersions(st.Audit().Versions)
	}
	pc.logf("event=processor stage=stream request_id=%s scope=%s err=%s versions=%s",
		pc.requestID, pc.scope, processorMessage(err), versions)
}

func (pc *procCall) logf(format string, args ...any) {
	if pc == nil || pc.server == nil {
		return
	}
	pc.server.log.Infof(format, args...)
}

// joinVersions 给出「哪个版本的处理器参与了这次处理」。
func joinVersions(list []processor.NameVersion) string {
	parts := make([]string, 0, len(list))
	for _, v := range list {
		parts = append(parts, fmt.Sprintf("%s@%s(%s)", v.Name, v.Version, v.Type))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "|")
}

// joinEntries 逐条给出处理器的结论，不含任何内容字段。
func joinEntries(list []processor.AuditEntry) string {
	parts := make([]string, 0, len(list))
	for _, e := range list {
		parts = append(parts, fmt.Sprintf("%s:%s phase=%s access=%s in=%d out=%d hash=%s released=%t denied_reads=%d summary_only=%t attempts=%d",
			e.Processor, e.Outcome, e.Phase, e.Access, e.InputBytes, e.OutputBytes,
			shortHash(e.OutputHash), e.ReleaseOrigin, e.DeniedReads, e.SummaryOnly, e.Attempts))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "|")
}

// shortHash 只取摘要前 12 位：日志要能对齐同一个内容，不需要一条可以拿去撞库的长摘要。
func shortHash(s string) string {
	if s == "" {
		return "-"
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// processorHTTP 把处理器失败映射成对客户端的回话。
//
// 归类口径是「谁改得了」：
//   - 客户端改得了（正文不合 schema、命中拦截、不是合法 JSON）→ 400；
//   - 超大小 → 413（与网关自身的 request_too_large 同一个码，客户端动作也相同）；
//   - 原文出网未获授权 → 403（这是策略结论，与 model_not_allowed 同类）；
//   - 其余（超时、依赖挂、声明装配不起来、档位/白名单不匹配）→ 503：
//     那是网关自己的事，让客户端重试或让运维改配置，绝不是让客户端改内容。
//
// 回话里只有原因码与处理器名，绝不带 err.Error() 之外的信息：schema 违规的错误原文
// 可能含实例路径，而某些规则表里「路径 + 长度」就足以定位字段内容（§2.9 规则 6）。
func processorHTTP(err error) (int, string, string) {
	switch reasonOf(err) {
	case processor.ReasonInputTooLarge:
		return http.StatusRequestEntityTooLarge, "processor_input_too_large",
			"请求正文超过处理器声明的大小上限（见 max_input_bytes）"
	case processor.ReasonSchemaViolation, processor.ReasonInvalidInput,
		processor.ReasonContentBlocked, processor.ReasonSidecarReject:
		return http.StatusBadRequest, "processor_rejected",
			fmt.Sprintf("内容未通过处理器检查（原因：%s）", reasonOf(err))
	case processor.ReasonGrantMissing, processor.ReasonGrantCheckerBlank:
		return http.StatusForbidden, "processor_grant_denied",
			"该请求需要把原文送出网关，而管理员策略未授予原文出网（raw_body_grant_missing）"
	}
	return http.StatusServiceUnavailable, "processor_unavailable",
		fmt.Sprintf("处理器链不可用（原因：%s）", reasonOf(err))
}

// reasonOf 从错误反推原因码，只用于回话归类。
//
// 为什么 server 包要自己判一次：Pipeline 已经把 classify 的结论放在 Result.Outcome 里，
// 但 WrapStream 的失败路径不返回 Result（那时还没读任何字节），而装配错误根本就没进
// Pipeline。这里的映射**不决定**能不能跳过某个处理器 —— 那个判断只在 E 包发生一次。
func reasonOf(err error) processor.Reason {
	if err == nil {
		return processor.ReasonOK
	}
	table := []struct {
		reason    processor.Reason
		sentinels []error
	}{
		{processor.ReasonInputTooLarge, []error{processor.ErrInputTooLarge, processor.ErrLineTooLarge}},
		{processor.ReasonSchemaViolation, []error{processor.ErrSchemaViolation}},
		{processor.ReasonInvalidInput, []error{processor.ErrInvalidJSON}},
		{processor.ReasonContentBlocked, []error{processor.ErrContentBlocked}},
		{processor.ReasonSidecarReject, []error{processor.ErrSidecarReject}},
		{processor.ReasonGrantMissing, []error{processor.ErrRawBodyDenied}},
		{processor.ReasonGrantCheckerBlank, []error{processor.ErrGrantCheckerBlank}},
		{processor.ReasonTimeout, []error{processor.ErrTimeout}},
		{processor.ReasonEndpointDenied, []error{processor.ErrEndpointDenied}},
		{processor.ReasonStreamUnsupported, []error{processor.ErrStreamUnsupported}},
		{processor.ReasonConfigInvalid, []error{processor.ErrConfigInvalid, processor.ErrSchemaUnsupported}},
		{processor.ReasonNotRegistered, []error{processor.ErrRegistry, processor.ErrPhase, processor.ErrSpec}},
	}
	for _, item := range table {
		for _, target := range item.sentinels {
			if errors.Is(err, target) {
				return item.reason
			}
		}
	}
	return processor.ReasonFailed
}

// processorMessage 取一条不含内容的安全错误文案（只进日志，不进回话）。
func processorMessage(err error) string {
	if err == nil {
		return "ok"
	}
	return truncateMsg(strings.ReplaceAll(err.Error(), "\n", " "), 240)
}
