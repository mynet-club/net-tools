package knowledge

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// Outcome 是一次委托检索的完整产物：引用 + 兜底丢弃记录 + 审计事件。
//
// 它是调用方唯一该看的东西。特别地：Failure 非空时 Citations 必定为空——
// 这条不变量由 Resolve 保证，所以接线时不需要（也不应该）自己写
// 「失败了就用已有的部分结果」这种分支；那种分支就是 fail_open 的入口。
type Outcome struct {
	RequestID      string           `json:"request_id"`
	Citations      []Citation       `json:"citations"`
	Dropped        []DropRecord     `json:"dropped,omitempty"`
	KnowledgeLevel policy.DataLevel `json:"knowledge_level"`
	HitCount       int              `json:"hit_count"`
	Truncated      bool             `json:"truncated,omitempty"`
	AclVersion     string           `json:"acl_version,omitempty"`
	PolicyVersion  string           `json:"policy_version"`
	DurationMS     int64            `json:"duration_ms"`
	Failure        *RetrievalError  `json:"failure,omitempty"`
	Audit          AuditEvent       `json:"audit"`
}

// IsReadable 报告这次检索是否产出了「可读」的文档。
//
// 语义上等价于「网关允许把这些引用交给模型上下文」。失败与零命中都返回 false，
// 这正是 fail_closed 的体现：拿不到判定就不给内容。
func (o *Outcome) IsReadable() bool { return o != nil && len(o.Citations) > 0 }

// EffectiveLevel 是 §2.3 组合规则里 knowledge_level 的那一项。
func (o *Outcome) EffectiveLevel(userLevel policy.DataLevel) (policy.DataLevel, error) {
	return EffectiveLevelFor(userLevel, o.KnowledgeLevel)
}

// Resolve 走一次完整的检索委托：装配上下文 → 调用知识源 → 网关侧兜底 → 产出审计事件。
//
// 失败语义（本函数最重要的一条）：
//
//	任何检索失败 = 判定为「不可读」，返回空 Citations，同时在审计里留下失败原因码。
//
// 为什么坚持 fail_closed：检索失败时网关并不知道「本来该给哪几篇」。
// 这时候按空放行是唯一不越权的选择；按「大概都是公开文档」放行，
// 就等于把知识源的可用性故障换算成一次数据泄露——而且是在没有任何判定依据的情况下。
//
// now 显式传参（与 A 包同一口径）：过期判定吃注入时钟，才能写出确定性测试与回放。
// 耗时是观测值、不参与任何判定，所以内部允许读一次 wall clock 量它。
//
// 返回的 error 与 Outcome 同时给出：调用方可以先判 err，也可以直接用 Outcome.Audit
// 落审计（两者内容一致），不强迫调用方在「报错」和「留痕」之间二选一。
func Resolve(
	ctx context.Context,
	retriever DelegatedRetriever,
	rc RequestContext,
	scope KnowledgeScope,
	q Query,
	now time.Time,
) (*Outcome, error) {
	if retriever == nil {
		return nil, fmt.Errorf("%w: 没有注入检索委托实现（fail_closed，绝不按无知识源放行）", ErrRetriever)
	}
	if err := rc.Validate(now); err != nil {
		return nil, err
	}
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if len(rc.Chain) == 0 {
		return nil, fmt.Errorf("%w: chain 为空", ErrContext)
	}

	started := rc.IssuedAt
	name := retrieverName(retriever)
	outcome := &Outcome{
		RequestID:      rc.RequestID,
		KnowledgeLevel: policy.LevelPublic,
		PolicyVersion:  rc.PolicyVersion,
	}

	// 没有任何知识库被准入：直接短路，一次委托请求都不发。
	// 短路是必要的——发出去也只会拿到「范围之外」的结果，
	// 而对端可能压根没实现「空白名单」的语义，反过来给了全部库的文档。
	if len(scope.KnowledgeBases) == 0 {
		outcome.Failure = &RetrievalError{Reason: ReasonNoKnowledgeAllow, Detail: "没有准入的知识库"}
		audit := baseAudit(rc, scope, q, started, now, ReasonNoKnowledgeAllow, policy.LevelPublic, "")
		audit.FailureDetail = "no admitted knowledge base; delegation request not sent"
		audit.QueriedBases = nil
		audit.Retriever = name
		outcome.Audit = audit
		return outcome, nil
	}

	req, err := BuildRequest(rc, scope, q, now)
	if err != nil {
		outcome.Failure = &RetrievalError{Reason: ReasonProtocolInvalid, KB: scope.KnowledgeBases, Detail: "请求装配失败"}
		outcome.Audit = baseAudit(rc, scope, q, started, now, ReasonProtocolInvalid, policy.LevelPublic, "")
		outcome.Audit.Retriever = name
		return outcome, err
	}

	// 用上下文把预算传下去：即使实现不检查 req.Deadline（协议要求它检查，但兜底不能指望对方），
	// ctx 到点也会取消，超时语义由网关这一侧钉死。
	callCtx, cancel := context.WithDeadline(ctx, rc.Deadline)
	defer cancel()

	elapsedStart := time.Now()
	resp, err := retriever.Retrieve(callCtx, req)
	elapsed := time.Since(elapsedStart)
	if elapsed < 0 {
		// wall clock 回拨（NTP 校正）时不要让审计里出现负耗时：它会被当成数据错误排查半天。
		elapsed = 0
	}

	if err != nil {
		failErr := asRetrievalError(err, scope.KnowledgeBases)
		outcome.Failure = failErr
		outcome.DurationMS = elapsed.Milliseconds()
		outcome.Audit = baseAudit(rc, scope, q, started, started.Add(elapsed), failErr.Reason, policy.LevelPublic, "")
		outcome.Audit.QueriedBases = req.KnowledgeBases
		outcome.Audit.FailureDetail = failErr.Error()
		outcome.Audit.Retriever = name
		// Citations 保持为空：这就是 fail_closed 的落地点。
		// 返回归一后的错误而不是原错误（原因见 asRetrievalError）。
		return outcome, failErr
	}

	filtered, err := Filter(resp, req, now)
	if err != nil {
		failErr := asRetrievalError(err, req.KnowledgeBases)
		outcome.Failure = failErr
		outcome.DurationMS = elapsed.Milliseconds()
		outcome.Audit = baseAudit(rc, scope, q, started, started.Add(elapsed), failErr.Reason, policy.LevelPublic, resp.AclVersion)
		outcome.Audit.QueriedBases = req.KnowledgeBases
		outcome.Audit.FailureDetail = failErr.Error()
		outcome.Audit.Retriever = name
		return outcome, failErr
	}

	resultCode := ReasonNoHits
	if filtered.HitCount > 0 {
		resultCode = ReasonOK
	}
	outcome.Citations = filtered.Citations()
	outcome.Dropped = filtered.Dropped()
	outcome.HitCount = filtered.HitCount
	outcome.KnowledgeLevel = filtered.MaxDataLevel
	outcome.Truncated = filtered.Truncated || resp.Truncated
	outcome.AclVersion = resp.AclVersion
	outcome.DurationMS = elapsed.Milliseconds()
	outcome.Audit = baseAudit(rc, scope, q, started, started.Add(elapsed), resultCode, filtered.MaxDataLevel, resp.AclVersion)
	outcome.Audit.QueriedBases = req.KnowledgeBases
	outcome.Audit.HitCount = filtered.HitCount
	outcome.Audit.DroppedCount = len(filtered.dropped)
	outcome.Audit.DroppedReasons = Reasons(dropReasonsOf(filtered.dropped))
	outcome.Audit.Truncated = outcome.Truncated
	outcome.Audit.CitationDigests = digestList(outcome.Citations)
	outcome.Audit.FailureDetail = ""
	outcome.Audit.Retriever = name
	return outcome, nil
}

// baseAudit 组装审计事件的公共部分。
//
// 单独成函数是为了让「成功路径」和「每一条失败路径」用的是同一个构造器：
// 失败路径漏记字段是最常见的审计缺陷，事后想统计「知识源超时占比」就发现分母不全。
func baseAudit(
	rc RequestContext,
	scope KnowledgeScope,
	q Query,
	started time.Time,
	finished time.Time,
	resultCode Reason,
	knowledgeLevel policy.DataLevel,
	aclVersion string,
) AuditEvent {
	durationMS := finished.Sub(started).Milliseconds()
	if durationMS < 0 {
		durationMS = 0
	}
	return AuditEvent{
		RequestID:           rc.RequestID,
		Subject:             rc.Subject,
		SubjectRef:          subjectRef(rc.Subject),
		Chain:               append(policy.ScopeChain(nil), rc.Chain...),
		Purpose:             rc.Purpose,
		AllowedBases:        append([]string(nil), scope.KnowledgeBases...),
		QueryDigest:         q.Digest(),
		MaxDataLevel:        knowledgeLevel.String(),
		RequestMaxDataLevel: scope.MaxDataLevel.String(),
		ResultCode:          resultCode,
		PolicyVersion:       rc.PolicyVersion,
		AclVersion:          aclVersion,
		DurationMS:          durationMS,
		StartedAt:           started.UTC(),
		FinishedAt:          finished.UTC(),
	}
}

// asRetrievalError 把任意错误归一成带稳定原因码的 RetrievalError。
//
// 为什么一定要归一：底层错误文案会随依赖库变化（甚至含 URL 与响应片段），
// 直接进审计就是「审计内容不稳定 + 可能泄露」两个问题一次发生。
//
// 归一后**只把原错误挂在 Cause 上供 errors.Is/As 分类**，
// Resolve 对外返回的也是这个归一错误：返回原错误等于把「审计不泄露」
// 守住的正文又从日志那条路放出去。
func asRetrievalError(err error, kbs []string) *RetrievalError {
	normalized := func(reason Reason, detail string) *RetrievalError {
		return &RetrievalError{
			Reason: reason,
			KB:     append([]string(nil), kbs...),
			Detail: detail,
			Cause:  err,
		}
	}
	var re *RetrievalError
	if errors.As(err, &re) && re != nil {
		// 已经分类过：复制一份补齐 KB，不改调用方手里的错误（它可能被并发共享）。
		clone := *re
		if len(clone.KB) == 0 {
			clone.KB = append([]string(nil), kbs...)
		}
		// Cause 只在「原错误不是它自己」时补挂：自引用会让 errors.Is 无限下钻。
		if err != error(re) {
			clone.Cause = err
		}
		return &clone
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return normalized(ReasonTimeout, "上下文超时")
	case errors.Is(err, context.Canceled):
		return normalized(ReasonCancelled, "调用方取消")
	case errors.Is(err, ErrProtocol):
		return normalized(ReasonProtocolInvalid, "协议不符")
	}
	return normalized(ReasonUnavailable, "委托实现返回未分类错误")
}

// digestList 收集引用摘要（只收集摘要，不收集任何内容字段）。
func digestList(in []Citation) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, c := range in {
		out = append(out, c.Digest)
	}
	return out
}
