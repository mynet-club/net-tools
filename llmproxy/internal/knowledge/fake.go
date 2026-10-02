package knowledge

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// FakeDocument 是**模拟知识源侧**的一条索引条目（测试与参考实现用，手册 §3.C 交付要求）。
//
// 定位要说清楚：IndexedTitle / IndexedText 代表「知识源那一侧的原始数据」，
// 它们只在 FakeRetriever 内部用来算摘要，永远不会出现在协议响应、引用或审计里
// （Retrieve 构造出去的是 Digest / TitleDigest）。
// 这正是委托协议的证明题：网关侧全程只需要摘要就能工作。
//
// 测试数据一律用明显虚构的标识（example-org / u-alice / doc-1）：
// 手册 §5 与 §8 都要求 fixture 里不得出现真实个人信息与真实密钥。
type FakeDocument struct {
	SourceID      string
	KnowledgeBase string
	OwnerScope    policy.ScopeRef
	Level         policy.DataLevel
	// IndexedTitle 是源侧标题明文，仅用于算 TitleDigest。
	IndexedTitle string
	// IndexedText 是源侧原文，仅用于算 Digest 与匹配检索词。
	IndexedText string
	// ReadableBy 是源侧 ACL 选择器集合（见下面 fakeSelector* 常量）。
	ReadableBy []string
	// RuleID 是本篇「可读」的判定依据。留空可用来模拟协议字段缺失。
	RuleID    string
	ExpiresAt time.Time
	Score     float64
}

// 缺陷模拟开关：让 fake 表现得像一个「没实现完整」的知识源，
// 用来证明网关侧的兜底与 fail_closed 真的生效，而不是只写在注释里。
const (
	// FakeReturnUnreadable 让整站把判定不可读的文档也返回（Allowed=false）。
	FakeReturnUnreadable = "return_unreadable"
	// FakeOmitEvidence 让整站省略 rule_id（协议字段缺失）。
	FakeOmitEvidence = "omit_evidence"
	// FakeOmitDigest 让整站把摘要写成空串。
	FakeOmitDigest = "omit_digest"
	// FakeForceReturnDocument 写在单篇的 ReadableBy 里：只让这一篇被越权返回。
	FakeForceReturnDocument = "!return_unreadable"
	// FakeForceNoEvidenceDocument 写在单篇的 ReadableBy 里：只让这一篇缺判定依据。
	FakeForceNoEvidenceDocument = "!omit_evidence"
)

// 源侧 ACL 选择器写法（这套语义只存在于 fake 内部，网关完全不认识它）。
//
// 支持：* | subject:<id> | user:<id> | organization:<id> | project:<id>
// 刻意不复用 policy 的主体选择器：复用了就看不出「网关与知识源各判各的」是否真成立，
// 而那正是委托协议的全部意义。
const (
	fakeSelectorAll     = "*"
	fakeSelectorSubject = "subject:"
	fakeSelectorUser    = "user:"
	fakeSelectorOrg     = "organization:"
	fakeSelectorProject = "project:"
)

// FakeRetriever 是内存版委托实现：证明协议可用、跨组织隔离可测，
// 并且不要求任何真实知识源就能跑测试（手册 §3.B 对 fake provider 的同一要求）。
//
// 可并发复用（DoD 4）：文档池与注入项都在锁保护下读写，Retrieve 只取快照后工作。
type FakeRetriever struct {
	// Name 是审计里出现的实现标识。
	Name string

	mu                sync.RWMutex
	docs              []FakeDocument
	aclVersion        string
	delay             time.Duration
	fault             error
	hook              RespondHook
	simulations       []string
	ignoreRequestSize bool
	calls             int
	requests          []RetrieveRequest
}

// RespondHook 接管整个响应构造（协议异常、串号响应等场景）。
// 钩子返回的响应仍会被网关侧 Validate / Filter 再收一道：钩子绕不过兜底。
type RespondHook func(context.Context, RetrieveRequest) (RetrieveResponse, error)

// NewFakeRetriever 构造内存知识源。
func NewFakeRetriever(docs ...FakeDocument) *FakeRetriever {
	f := &FakeRetriever{Name: "fake", aclVersion: "fake-acl-v1"}
	f.Add(docs...)
	return f
}

// RetrieverName 实现 NamedRetriever，供审计标注实现来源。
func (f *FakeRetriever) RetrieverName() string {
	if f.Name == "" {
		return "fake"
	}
	return f.Name
}

// Add 追加索引条目（返回自身便于链式构造）。
func (f *FakeRetriever) Add(docs ...FakeDocument) *FakeRetriever {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.docs = append(f.docs, docs...)
	return f
}

// WithACLVersion 设置源侧 ACL 世代（进审计）。
func (f *FakeRetriever) WithACLVersion(v string) *FakeRetriever {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.aclVersion = v
	return f
}

// WithDelay 让每次检索阻塞指定时长（超时测试用，可被 ctx 取消）。
func (f *FakeRetriever) WithDelay(d time.Duration) *FakeRetriever {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delay = d
	return f
}

// WithFault 让每次检索返回指定错误（fail_closed 测试用）。
func (f *FakeRetriever) WithFault(err error) *FakeRetriever {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fault = err
	return f
}

// WithFailure 让每次检索返回带稳定原因码的委托失败。
func (f *FakeRetriever) WithFailure(reason Reason, detail string) *FakeRetriever {
	return f.WithFault(&RetrievalError{Reason: reason, Detail: detail})
}

// WithRespondHook 注入响应钩子。
func (f *FakeRetriever) WithRespondHook(h RespondHook) *FakeRetriever {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook = h
	return f
}

// WithSimulation 打开整站级缺陷模拟（见 FakeReturnUnreadable 等常量）。
func (f *FakeRetriever) WithSimulation(names ...string) *FakeRetriever {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.simulations = append(f.simulations, names...)
	return f
}

// WithoutRequestLimit 让 fake 无视请求的 max_results 全量返回，
// 用于验证**网关侧**的结果数截断（源侧已经截过并不能证明兜底有效）。
func (f *FakeRetriever) WithoutRequestLimit() *FakeRetriever {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ignoreRequestSize = true
	return f
}

// Calls 返回被调用次数（用来断言「没有准入知识库时一次都不发」）。
func (f *FakeRetriever) Calls() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.calls
}

// Requests 返回收到的请求副本（断言权限上下文确实传给了源侧）。
func (f *FakeRetriever) Requests() []RetrieveRequest {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return append([]RetrieveRequest(nil), f.requests...)
}

// LastRequest 返回最近一次收到的请求（没有则 false）。
func (f *FakeRetriever) LastRequest() (RetrieveRequest, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.requests) == 0 {
		return RetrieveRequest{}, false
	}
	return f.requests[len(f.requests)-1], true
}

// Reset 清空调用记录与注入项（保留文档池），便于同一实例分隔用例。
func (f *FakeRetriever) Reset() *FakeRetriever {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = 0
	f.requests = nil
	f.fault = nil
	f.hook = nil
	f.delay = 0
	f.simulations = nil
	f.ignoreRequestSize = false
	return f
}

type fakeSnapshot struct {
	docs              []FakeDocument
	aclVersion        string
	delay             time.Duration
	fault             error
	hook              RespondHook
	simulations       []string
	ignoreRequestSize bool
}

// record 在一次加锁里同时记调用数、请求副本并取出快照。
// 分两次加锁会让并发测试里「第 N 次调用对应哪个请求」对不上。
func (f *FakeRetriever) record(req RetrieveRequest) fakeSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.requests = append(f.requests, cloneRequest(req))
	return fakeSnapshot{
		docs:              append([]FakeDocument(nil), f.docs...),
		aclVersion:        f.aclVersion,
		delay:             f.delay,
		fault:             f.fault,
		hook:              f.hook,
		simulations:       append([]string(nil), f.simulations...),
		ignoreRequestSize: f.ignoreRequestSize,
	}
}

// Retrieve 实现 DelegatedRetriever：按 fake 自己的 ACL 判定每篇文档是否可读，
// 只把摘要与判定依据交给调用方。
//
// 这段代码就是「知识源侧必须做什么」的可执行说明：
// 它读 req.Subject + req.Chain + req.MaxDataLevel + req.KnowledgeBases 自己判，
// 不看任何调用方塞进来的「这篇可读」标签——协议里根本没有那种字段。
func (f *FakeRetriever) Retrieve(ctx context.Context, req RetrieveRequest) (RetrieveResponse, error) {
	snap := f.record(req)
	if snap.hook != nil {
		return snap.hook(ctx, req)
	}
	if err := req.Validate(); err != nil {
		return RetrieveResponse{}, err
	}
	if snap.delay > 0 {
		timer := time.NewTimer(snap.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return RetrieveResponse{}, retrievalErrorFromContext(ctx, req.KnowledgeBases)
		}
	}
	if snap.fault != nil {
		return RetrieveResponse{}, snap.fault
	}
	if ctx.Err() != nil {
		return RetrieveResponse{}, retrievalErrorFromContext(ctx, req.KnowledgeBases)
	}

	returned := make([]ReturnedDocument, 0, len(snap.docs))
	for _, doc := range snap.docs {
		if !req.KnowledgeBaseAllowed(doc.KnowledgeBase) {
			// 请求没提到的知识库一律不返回：源侧也要守白名单，
			// 否则「网关传了子集、源侧给了全集」的兜底就只剩网关那一道。
			continue
		}
		readable := subjectMayRead(doc, req)
		forced := containsString(snap.simulations, FakeReturnUnreadable) ||
			containsString(doc.ReadableBy, FakeForceReturnDocument)
		if !readable && !forced {
			continue
		}
		if !matchesQuery(doc, req) {
			continue
		}
		item := ReturnedDocument{
			SourceID:      doc.SourceID,
			KnowledgeBase: doc.KnowledgeBase,
			OwnerKind:     string(doc.OwnerScope.Kind),
			OwnerID:       doc.OwnerScope.ID,
			DataLevel:     doc.Level.String(),
			Digest:        Digest([]byte(doc.IndexedText)),
			TitleDigest:   TitleDigest(doc.IndexedTitle),
			Allowed:       readable,
			RuleID:        doc.RuleID,
			AclVersion:    snap.aclVersion,
			ExpiresAt:     doc.ExpiresAt,
			Score:         doc.Score,
		}
		if containsString(snap.simulations, FakeOmitEvidence) ||
			containsString(doc.ReadableBy, FakeForceNoEvidenceDocument) {
			item.RuleID = ""
		}
		if containsString(snap.simulations, FakeOmitDigest) {
			item.Digest = ""
		}
		returned = append(returned, item)
	}

	// 稳定排序后返回：源侧顺序抖动不应该改变网关判定，fake 先自证确定性，
	// 免得测试失败时分不清是哪一侧的问题。
	sort.SliceStable(returned, func(i, j int) bool {
		if returned[i].SourceID != returned[j].SourceID {
			return returned[i].SourceID < returned[j].SourceID
		}
		return returned[i].KnowledgeBase < returned[j].KnowledgeBase
	})

	truncated := false
	if !snap.ignoreRequestSize && len(returned) > req.MaxResults {
		returned = returned[:req.MaxResults]
		truncated = true
	}

	return RetrieveResponse{
		ProtocolVersion: ProtocolVersion,
		RequestID:       req.RequestID,
		Documents:       returned,
		Truncated:       truncated,
		AclVersion:      snap.aclVersion,
		EvaluatedAt:     req.IssuedAt,
	}, nil
}

// subjectMayRead 是「源侧自己鉴权」的实现：主体或范围命中 ReadableBy 才可读。
func subjectMayRead(doc FakeDocument, req RetrieveRequest) bool {
	for _, sel := range doc.ReadableBy {
		if sel == FakeForceReturnDocument || sel == FakeForceNoEvidenceDocument {
			continue // 缺陷模拟标记不是授权选择器
		}
		sel = strings.TrimSpace(sel)
		switch {
		case sel == fakeSelectorAll:
			return true
		case strings.HasPrefix(sel, fakeSelectorSubject):
			if strings.TrimPrefix(sel, fakeSelectorSubject) == req.Subject {
				return true
			}
		case strings.HasPrefix(sel, fakeSelectorUser):
			if strings.TrimPrefix(sel, fakeSelectorUser) == req.Subject {
				return true
			}
		case strings.HasPrefix(sel, fakeSelectorOrg):
			if chainHasScope(req.Chain, policy.ScopeOrganization, strings.TrimPrefix(sel, fakeSelectorOrg)) {
				return true
			}
		case strings.HasPrefix(sel, fakeSelectorProject):
			if chainHasScope(req.Chain, policy.ScopeProject, strings.TrimPrefix(sel, fakeSelectorProject)) {
				return true
			}
		}
	}
	return false
}

func chainHasScope(chain policy.ScopeChain, kind policy.ScopeKind, id string) bool {
	for _, s := range chain {
		if s.Kind == kind && s.ID == id {
			return true
		}
	}
	return false
}

// matchesQuery 只在源侧内部比较检索词。网关没传原文时（AllowRawTerms=false），
// 源侧退化为「按范围与白名单返回全部可读条目」——这符合协议：
// 摘要不支持全文匹配，指望它做全文检索才是 bug。
func matchesQuery(doc FakeDocument, req RetrieveRequest) bool {
	terms := strings.TrimSpace(req.SearchTerms)
	if terms == "" {
		return true
	}
	needle := strings.ToLower(terms)
	return strings.Contains(strings.ToLower(doc.IndexedText), needle) ||
		strings.Contains(strings.ToLower(doc.IndexedTitle), needle)
}

func retrievalErrorFromContext(ctx context.Context, kbs []string) error {
	reason := ReasonCancelled
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		reason = ReasonTimeout
	}
	return &RetrievalError{
		Reason: reason,
		KB:     append([]string(nil), kbs...),
		Detail: "委托上下文已超时或取消",
		Cause:  ctx.Err(),
	}
}

// cloneRequest 深拷贝切片，避免调用方后续改动影响记录内容。
func cloneRequest(req RetrieveRequest) RetrieveRequest {
	out := req
	out.Chain = append(policy.ScopeChain(nil), req.Chain...)
	out.KnowledgeBases = append([]string(nil), req.KnowledgeBases...)
	return out
}

// 编译期断言：fake 同时满足委托接口与带名接口。
var (
	_ DelegatedRetriever = (*FakeRetriever)(nil)
	_ NamedRetriever     = (*FakeRetriever)(nil)
)
