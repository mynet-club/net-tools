package identity

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Outcome 是身份这一步的结论档位。三档足够，不引入第四档：
//
//   - success：解析出可用身份；
//   - denied：凭证或 claims 不合格，明确拒绝（调用方的问题，走 401）；
//   - error：依赖不可用或内部缺陷（公钥取不到等），不是拒绝，走 503。
//
// 把 denied 与 error 混成一档，运维大盘就会把 IdP 故障看成「攻击增多」，
// 值班按错误结论去收紧策略。
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeDenied  Outcome = "denied"
	OutcomeError   Outcome = "error"
)

func (o Outcome) Valid() bool {
	return o == OutcomeSuccess || o == OutcomeDenied || o == OutcomeError
}

func (o Outcome) String() string { return string(o) }

// AuditEvent 是一条身份来源审计（手册 §3.B「身份来源审计」）。
//
// 字段集合是刻意收窄的：只有主体、来源、结论、原因码、时间，外加两个不含内容的计数。
// 明确**不记录**：token 原文、JWS 头与签名、公钥材料、claims 里的邮箱/手机号/姓名，
// 也不记录范围 ID 列表（组织代号本身可能就是敏感命名）。要还原细节请去 IdP 侧的日志，
// 用 RequestID 对齐。落库时这张表的列与这里一一对应，加字段必须先过一次评审。
type AuditEvent struct {
	// Subject 是稳定主体 ID。PII 形态（邮箱、手机号）不放原文，改放 SubjectRef。
	Subject string `json:"subject,omitempty"`
	// SubjectRef 是主体（或凭证）的单向摘要，用于把同一主体的多次失败串起来。
	SubjectRef string     `json:"subject_ref,omitempty"`
	Source     string     `json:"source"`
	Provider   string     `json:"provider"`
	Outcome    Outcome    `json:"outcome"`
	Reason     ReasonCode `json:"reason"`
	// ScopeCount 只记数量不记 ID：判断「这个角色解析出来范围对不对」不需要暴露范围名。
	ScopeCount int `json:"scope_count"`
	// RoleCount 同上。
	RoleCount  int       `json:"role_count"`
	RequestID  string    `json:"request_id,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

// Validate 检查事件自身是否合格（原因码必须注册过、Outcome 必须在三档里）。
//
// 未注册的原因码必须挡在这里：否则一年后审计查询会因为「以前没见过的值」失去可比性，
// 而手册 §5 要求的原因码稳定性就是靠这一点保证的。
func (e AuditEvent) Validate() error {
	if !e.Outcome.Valid() {
		return fmt.Errorf("%w: outcome %q", ErrInternal, string(e.Outcome))
	}
	if !e.Reason.Valid() {
		return fmt.Errorf("%w: 原因码 %q 未注册", ErrInternal, string(e.Reason))
	}
	if e.Source == "" {
		return fmt.Errorf("%w: source 不能为空", ErrInternal)
	}
	if isPIIShape(e.Subject) {
		return fmt.Errorf("%w: 审计不得记录邮箱/手机号形态的主体原文", ErrInternal)
	}
	return nil
}

// String 给出单行日志形式。只有白名单字段，没有 claims 内容。
func (e AuditEvent) String() string {
	subject := e.Subject
	if subject == "" {
		subject = "-"
	}
	ref := e.SubjectRef
	if ref == "" {
		ref = "-"
	}
	return fmt.Sprintf("identity-audit source=%s provider=%s subject=%s ref=%s outcome=%s reason=%s scopes=%d roles=%d request=%s at=%s",
		e.Source, e.Provider, subject, ref, e.Outcome, e.Reason, e.ScopeCount, e.RoleCount,
		orDash(e.RequestID), e.OccurredAt.Format(time.RFC3339))
}

// MarshalJSON 走默认结构体编码；单独实现是为了把 PII 主体的检查前置到序列化时。
// 只要事件是构造器出来的这一步就不会命中，但直接手构结构体（例如测试）也得拒绝。
func (e AuditEvent) MarshalJSON() ([]byte, error) {
	if isPIIShape(e.Subject) {
		e.Subject = ""
		if e.SubjectRef == "" {
			e.SubjectRef = SubjectRef("<redacted>")
		}
	}
	type auditAlias AuditEvent
	return json.Marshal(auditAlias(e))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// NewAuditEvent 从 Principal 构造成功事件。
func NewAuditEvent(p Principal, outcome Outcome, reason ReasonCode, at time.Time) AuditEvent {
	e := AuditEvent{
		Source:     p.Source,
		Provider:   p.Provider,
		Outcome:    outcome,
		Reason:     reason,
		ScopeCount: len(p.Chain),
		RoleCount:  len(p.Identity.Roles),
		OccurredAt: at,
	}
	setSubject(&e, p.Identity.Subject)
	return e
}

// NewFailureEvent 构造失败事件。
//
// 失败时 subject 能不能记录要看它的形态：被拒的往往正是「邮箱当 subject」这种情况，
// 把原值写进审计等于把拒绝理由变成 PII 落库。因此这里只写摘要。
func NewFailureEvent(source, provider string, rawSubject string, outcome Outcome, reason ReasonCode, at time.Time, requestID string) AuditEvent {
	e := AuditEvent{
		Source:     source,
		Provider:   provider,
		Outcome:    outcome,
		Reason:     reason,
		RequestID:  requestID,
		OccurredAt: at,
	}
	setSubject(&e, rawSubject)
	return e
}

// setSubject 按形态决定记原文还是记摘要。
func setSubject(e *AuditEvent, raw string) {
	if raw == "" {
		return
	}
	if isPIIShape(raw) {
		e.SubjectRef = SubjectRef(raw)
		return
	}
	e.Subject = raw
	e.SubjectRef = SubjectRef(raw)
}

// AuditSink 接收身份审计事件。落库、转发 SIEM 都由实现方负责（本包不出网、不碰数据库）。
//
// 实现必须可并发调用。
type AuditSink interface {
	Record(event AuditEvent)
}

// AuditFunc 把普通函数适配成 AuditSink。
type AuditFunc func(AuditEvent)

func (f AuditFunc) Record(event AuditEvent) {
	if f != nil {
		f(event)
	}
}

// NopAudit 丢弃所有事件，是默认值。
//
// 默认丢弃而不是默认落库：接线阶段（手册 §3.0 的 shadow）先要保证不写坏别人的表，
// 需要留痕时由调用方显式注入 sink。
type NopAudit struct{}

func (NopAudit) Record(AuditEvent) {}

// AuditRecorder 是内存环形缓冲，给测试和影子运行用（线程安全）。
type AuditRecorder struct {
	mu     sync.Mutex
	events []AuditEvent
	limit  int
}

// NewAuditRecorder 构造最多容量为 limit 的记录器；limit ≤ 0 表示不限量。
func NewAuditRecorder(limit int) *AuditRecorder {
	return &AuditRecorder{limit: limit}
}

func (r *AuditRecorder) Record(event AuditEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	if r.limit > 0 && len(r.events) > r.limit {
		r.events = r.events[len(r.events)-r.limit:]
	}
}

// Events 返回副本，调用方可以安全遍历。
func (r *AuditRecorder) Events() []AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]AuditEvent, len(r.events))
	copy(out, r.events)
	return out
}

// Last 返回最后一条事件（没有则零值）。
func (r *AuditRecorder) Last() (AuditEvent, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == 0 {
		return AuditEvent{}, false
	}
	return r.events[len(r.events)-1], true
}

// Reset 清空缓冲，便于在同一进程里分隔用例。
func (r *AuditRecorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = nil
}

// containsAny 是给测试用的检查器：断言输出里不出现敏感片段。
// 之所以放在生产文件里，是因为 leak_test.go 与 audit_test.go 都要用它，
// 而测试辅助函数写在 _test.go 就无法跨包复用。
func containsAny(haystack string, needles ...string) (string, bool) {
	for _, n := range needles {
		if n == "" {
			continue
		}
		if strings.Contains(haystack, n) {
			return n, true
		}
	}
	return "", false
}
