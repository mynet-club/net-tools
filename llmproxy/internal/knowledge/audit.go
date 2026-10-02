package knowledge

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// ErrAudit 表示审计事件自身不合格。
var ErrAudit = errors.New("knowledge: 检索审计事件不合法")

// AuditEvent 是一次检索委托的审计事件（手册 §3.C：不记录正文的审计事件）。
//
// 字段集合是刻意收窄的白名单：主体、范围、知识库、查询摘要哈希、命中数、
// 命中集最高分级、请求分级上限、策略版本、知识源 ACL 世代、耗时、结果码、丢弃原因码。
//
// 明确**不记录**：文档正文、标题明文、检索词原文、知识源侧的 ACL 规则内容。
// 为什么连检索词原文都不记：检索词就是用户提问的一部分（「我的裁员赔偿怎么算」），
// 记原文等于把正文换个表再存一遍，§2.9 的「正文不落库」当场失效。
// 要复盘具体内容，用 RequestID 去知识源侧对齐它的访问日志——
// 那里才有完整事实，也有做鉴权的那套权限上下文。
type AuditEvent struct {
	RequestID  string            `json:"request_id"`
	Subject    string            `json:"subject"`
	SubjectRef string            `json:"subject_ref,omitempty"`
	Chain      policy.ScopeChain `json:"chain"`
	Purpose    string            `json:"purpose"`

	// AllowedBases 是本次准入的知识库集合（网关侧白名单）。
	AllowedBases []string `json:"allowed_knowledge_bases"`
	// QueriedBases 是实际发出委托请求的集合；为准空短路时它是空的，
	// 这个区别能回答「查不到是因为没授权，还是因为授权了但库里没有」。
	QueriedBases []string `json:"queried_knowledge_bases,omitempty"`

	// QueryDigest 是检索词的域分隔摘要（Query.Digest），用于把同一查询的多次检索串起来。
	QueryDigest string `json:"query_digest"`

	HitCount       int      `json:"hit_count"`
	DroppedCount   int      `json:"dropped_count"`
	DroppedReasons []Reason `json:"dropped_reasons,omitempty"`

	// MaxDataLevel 是命中文档里的最高分级（§2.3 的 knowledge_level）。
	MaxDataLevel string `json:"max_data_level"`
	// RequestMaxDataLevel 是本次请求允许的分级上限，两者一起才看得出「被上限截掉了多少」。
	RequestMaxDataLevel string `json:"request_max_data_level"`

	// ResultCode 是本次委托的稳定结论码。
	ResultCode Reason `json:"result_code"`
	// FailureDetail 只在失败时有值，且只允许稳定短语（不含响应体）。
	FailureDetail string `json:"failure_detail,omitempty"`

	// PolicyVersion 必须来自实际加载的策略包（手册 §3.0）：
	// 策略版本变更要能在审计上看出来，否则「同一查询今天少了几篇」无法归因。
	PolicyVersion string `json:"policy_version"`
	// AclVersion 是知识源侧 ACL 的世代，进审计供「当初到底按哪套 ACL 判的」复盘。
	AclVersion string `json:"acl_version,omitempty"`

	Truncated  bool      `json:"truncated,omitempty"`
	DurationMS int64     `json:"duration_ms"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`

	// Retriever 是实现标识（如 http / fake），只记名字不记端点细节。
	Retriever string `json:"retriever,omitempty"`

	// CitationDigests 是最终放行引用的摘要列表（内容摘要，非正文）。
	// 上限由请求的 max_results 决定，因此体积可控。
	CitationDigests []string `json:"citation_digests,omitempty"`
}

// Validate 校验事件形态：原因码必须注册过、主体不能是 PII 形态、摘要必须是 sha256。
//
// 这一步不是形式主义：审计表一旦写进未注册的原因码，
// 一年后的查询会因为「以前没见过的值」失去可比性（§5 的稳定性要求就是靠这里守住的）。
func (e AuditEvent) Validate() error {
	if err := validateStableID("request_id", e.RequestID, maxRequestIDLen); err != nil {
		return fmt.Errorf("%w: %v", ErrAudit, err)
	}
	if err := validateSubjectID(e.Subject); err != nil {
		return fmt.Errorf("%w: %v", ErrAudit, err)
	}
	if len(e.Chain) == 0 {
		return fmt.Errorf("%w: chain 为空", ErrAudit)
	}
	if _, err := policy.NewScopeChain(e.Chain...); err != nil {
		return fmt.Errorf("%w: %v", ErrAudit, err)
	}
	if strings.TrimSpace(e.Purpose) == "" {
		return fmt.Errorf("%w: purpose 缺失", ErrAudit)
	}
	if err := ValidateDigest(e.QueryDigest); err != nil {
		return fmt.Errorf("%w: %v", ErrAudit, err)
	}
	if !e.ResultCode.Valid() {
		return fmt.Errorf("%w: 结果码 %q 未注册", ErrAudit, string(e.ResultCode))
	}
	if err := ValidateReasons(e.DroppedReasons); err != nil {
		return fmt.Errorf("%w: %v", ErrAudit, err)
	}
	if e.HitCount < 0 || e.DroppedCount < 0 {
		return fmt.Errorf("%w: 计数为负", ErrAudit)
	}
	if e.DurationMS < 0 {
		return fmt.Errorf("%w: 耗时为负", ErrAudit)
	}
	if e.PolicyVersion == "" {
		return fmt.Errorf("%w: policy_version 缺失，策略变更无法在审计上归因", ErrAudit)
	}
	if !e.StartedAt.IsZero() && !e.FinishedAt.IsZero() && e.FinishedAt.Before(e.StartedAt) {
		return fmt.Errorf("%w: finished_at 早于 started_at", ErrAudit)
	}
	for _, d := range e.CitationDigests {
		if err := ValidateDigest(d); err != nil {
			return fmt.Errorf("%w: 引用摘要不合法: %v", ErrAudit, err)
		}
	}
	return nil
}

// MarshalJSON 走结构体编码，但先做一次 PII 兜底：
// 邮箱/手机号形态的主体绝不落原文，只留截断摘要。
//
// 为什么在序列化时兜而不是只靠 Validate：审计事件也可能被手构出来直接落库
// （接线早期的临时路径），序列化点是最后一道能拦住的地方。
func (e AuditEvent) MarshalJSON() ([]byte, error) {
	if looksLikePII(e.Subject) {
		// 先算摘要再清空：顺序反了就会得到一个空 ref，「被拒的理由」本身成了断链。
		if e.SubjectRef == "" {
			e.SubjectRef = subjectRef(e.Subject)
		}
		e.Subject = ""
	}
	type auditAlias AuditEvent
	return json.Marshal(auditAlias(e))
}

// String 给出单行日志形式：只有稳定标识与计数，永远没有内容。
//
// 主体在这里也走一次 PII 兜底（与 MarshalJSON 同一口径）：日志是最容易把
// 邮箱/手机号永久留在别人能读到的地方的一条路径，而手构事件可以绕过 Validate。
func (e AuditEvent) String() string {
	subject := e.Subject
	if looksLikePII(subject) {
		if e.SubjectRef == "" {
			// 先算摘要再隐去，理由同 MarshalJSON：断链比多留一个标识更糟。
			e.SubjectRef = subjectRef(subject)
		}
		subject = ""
	}
	return fmt.Sprintf(
		"knowledge-audit request=%s subject=%s ref=%s purpose=%s kb=%d queried=%d hits=%d dropped=%d drop_reasons=%s level=%s ceiling=%s result=%s policy=%s acl=%s duration_ms=%d at=%s",
		orDash(e.RequestID), orDash(subject), orDash(e.SubjectRef), orDash(e.Purpose),
		len(e.AllowedBases), len(e.QueriedBases), e.HitCount, e.DroppedCount,
		joinReasons(e.DroppedReasons), orDash(e.MaxDataLevel), orDash(e.RequestMaxDataLevel),
		string(e.ResultCode), orDash(e.PolicyVersion), orDash(e.AclVersion),
		e.DurationMS, e.FinishedAt.UTC().Format(time.RFC3339))
}

// joinReasons 拼原因码（空集返回 "-"）。
func joinReasons(in []Reason) string {
	if len(in) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(in))
	for _, r := range in {
		parts = append(parts, string(r))
	}
	return strings.Join(parts, ",")
}

// looksLikePII 是邮箱/手机号形态的粗筛。
//
// 只做形态判断、不做归一化：这里的目标是「别把明显的个人信息写进审计」，
// 不是「识别所有 PII」（那是检测器的活，属于 inspect-body，不归本包）。
func looksLikePII(s string) bool {
	if s == "" {
		return false
	}
	if strings.ContainsRune(s, '@') {
		return true
	}
	digits := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			digits++
		}
	}
	// 纯数字且长度像手机号（11 位）：这是最常见的误落库形态。
	return digits == len(s) && len(s) >= 11
}

// subjectRef 是主体的截断摘要（12 位十六进制）。
// 截断是刻意的：主体 ID 可能被字典命中，展示面越小越好；
// 关联同一次事故用 RequestID 更可靠。
func subjectRef(raw string) string {
	if raw == "" {
		return ""
	}
	return ShortDigest(DigestString(raw))
}

// AuditSink 接收检索审计事件（落库、转发 SIEM 由实现方负责；本包不出网不碰数据库）。
//
// 实现必须可并发调用（DoD 4）。
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
// 默认丢弃而不是默认落库：接线阶段（手册 §3.0 的 shadow）先保证不写坏别人的表，
// 需要留痕时由调用方显式注入 sink。
type NopAudit struct{}

func (NopAudit) Record(AuditEvent) {}

// AuditRecorder 是内存环形缓冲，给测试与影子运行用（线程安全）。
type AuditRecorder struct {
	mu       sync.Mutex
	events   []AuditEvent
	rejected int
	limit    int
}

// NewAuditRecorder 构造最多容量为 limit 的记录器；limit ≤ 0 表示不限量。
func NewAuditRecorder(limit int) *AuditRecorder {
	return &AuditRecorder{limit: limit}
}

// Record 追加事件。事件必须通过自身校验，否则直接丢弃并计数。
func (r *AuditRecorder) Record(event AuditEvent) {
	if err := event.Validate(); err != nil {
		// 不合格的事件不落缓冲：测试里出现「审计事件构造错误」应该表现为
		// 事件缺失 + Failed 计数，而不是一条半成品记录混进断言。
		r.mu.Lock()
		r.rejected++
		r.mu.Unlock()
		return
	}
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

// Last 返回最后一条事件（没有则 false）。
func (r *AuditRecorder) Last() (AuditEvent, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == 0 {
		return AuditEvent{}, false
	}
	return r.events[len(r.events)-1], true
}

// Rejected 返回被自身校验拒绝的事件数（排障用：它非零就说明接线写错了构造路径）。
func (r *AuditRecorder) Rejected() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rejected
}

// Reset 清空缓冲，便于同一进程内分隔用例。
func (r *AuditRecorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = nil
	r.rejected = 0
}
