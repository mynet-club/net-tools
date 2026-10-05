package knowledge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// ProtocolVersion 是委托协议版本，写进每一次请求与响应的握手字段。
//
// 为什么显式带版本而不是靠 URL：知识源是外部系统，升级节奏不一致。
// 不带版本时，字段语义一变（比如 allowed 的判定依据从自由文本换成规则 ID）
// 就会表现为「老源返回的文档突然缺依据」，网关只能整体拒绝，
// 而现场看到的报错会让人以为是数据问题。破坏性变更必须升版本号并走主线评审。
const ProtocolVersion = "llmproxy-knowledge-acl-v1"

// maxProtocolDocs 是单次响应允许解析出的文档条数硬上限。
//
// 这条上限独立于 MaxResults：知识源如果被攻陷或有 bug，可以返回十万条「可读」文档，
// 网关在反序列化阶段就要止住，而不是等 Filter 逐条丢弃。
const maxProtocolDocs = 1000

var (
	// ErrProtocol 表示委托协议字段缺失或形态不符（一律 fail_closed）。
	ErrProtocol = errors.New("knowledge: 检索委托协议不符")
	// ErrRetriever 表示委托实现自身配置不全（未注入传输、端点非法等）。
	ErrRetriever = errors.New("knowledge: 检索委托实现不合法")
)

// Query 是一次检索的查询内容。
//
// 检索词本身也是用户内容（「我的裁员赔偿怎么算」这种提问，检索词就是敏感信息），
// 所以镜像 §2.9 正文访问契约：默认只把**摘要**交给知识源，
// 只有 AllowRawTerms=true（由管理员策略显式授予、带期限与审计）才传原文。
// 只传摘要时知识源仍可按自己侧的意图改写检索（例如按已存的用户问题向量），
// 网关不假设它能做全文匹配。
type Query struct {
	Terms         string
	AllowRawTerms bool
	// Pepper 是给检索词摘要用的密钥位（由网关注入，见 Server.kbQuery）。
	// 它是**网关的秘密**，绝不进委托请求体、不进审计、不进日志 ——
	// 请求体里只有摘要结果本身。
	//
	// 留空 = 退回无密钥的域分隔摘要，也就是本字段存在之前的行为：低熵检索词
	// （「张三 绩效」这类）又能被离线穷举还原出明文。之所以留这条路而不是 fail closed，
	// 是因为主密钥面对本包不可见（拿不到 secrets.Cipher 的嵌入式用法与测试都直接构造 Query），
	// 在这里拒绝会把「接线忘了注入」伪装成「协议不合法」。
	// 因此这条不变量由接线侧守住：Server.kbQuery 是唯一的构造入口，pepper 来自 master.key。
	Pepper []byte
}

// Digest 返回检索词的摘要；空检索词也有摘要（对空串取摘要），
// 这样审计里「没检索词」和「摘要没算」是可区分的两件事。
//
// 域前缀与标题摘要同一口径（见 citation.go 的 queryDigestDomain）：裸 sha256 会让
// 同一个短语出现在 query 位和 title 位时产出同一个值，审计里就等于把「这个人搜过
// 这个词」和「存在这么一份文档」并成一条可离线命中的证据。
//
// **有 Pepper 时它是 HMAC 的密钥，不只是前缀**：用户会搜「张三 绩效」这种低熵短语，
// 不带密钥的摘要可以被穷举字典离线还原出检索词明文（审计表就是那本字典的语料）。
// 截断展示一律走 ShortDigest，等值判定才比完整摘要。
func (q Query) Digest() string {
	normalized := strings.TrimSpace(q.Terms)
	if len(q.Pepper) == 0 {
		return domainDigest(queryDigestDomain, normalized)
	}
	return keyedDomainDigest(queryDigestDomain, q.Pepper, normalized)
}

// RetrieveRequest 是委托检索的请求体。
//
// 字段就是「知识源完成鉴权所需的最小集合」：主体 + 结构化范围集合 + 用途 +
// 分级上限 + 允许触达的知识库 + 结果数与时间预算。
// **注意这里没有任何「已判定可读」的结论**：网关传的是上下文，
// 判定权在知识源（手册 §3.C 的委托原则）。
type RetrieveRequest struct {
	ProtocolVersion string            `json:"protocol_version"`
	RequestID       string            `json:"request_id"`
	Subject         string            `json:"subject"`
	Chain           policy.ScopeChain `json:"chain"`
	Purpose         string            `json:"purpose"`
	// Organization 是主归属组织 ID（可空）。它只是提示，鉴权仍以 Chain 为准：
	// 多组织主体的「主组织」由各适配器（B）决定，本包不猜层级。
	Organization string `json:"organization,omitempty"`
	// KnowledgeBases 是网关侧已准入的知识库集合。知识源必须在**这个集合之内**再按自己的
	// ACL 判定单篇文档；集合之外的文档一律不许出现在响应里。
	KnowledgeBases []string  `json:"knowledge_bases"`
	MaxDataLevel   string    `json:"max_data_level"`
	PolicyVersion  string    `json:"policy_version"`
	MaxResults     int       `json:"max_results"`
	IssuedAt       time.Time `json:"issued_at"`
	Deadline       time.Time `json:"deadline"`
	// BudgetMS 是 Deadline-IssuedAt 的毫秒数，供无法解析 RFC3339 时兜底限时。
	BudgetMS int64 `json:"budget_ms"`
	// QueryDigest 是检索词摘要，恒定存在，供审计与「同查询」关联。
	QueryDigest string `json:"query_digest"`
	// SearchTerms 只有在 AllowRawTerms=true 时才被填充（见 BuildRequest）。
	SearchTerms   string `json:"search_terms,omitempty"`
	AllowRawTerms bool   `json:"allow_raw_terms,omitempty"`
}

// ReturnedDocument 是知识源返回的一篇文档（协议单元）。
//
// 它的字段集合就是本包的底线：**只有摘要，没有正文，也没有标题明文**。
// 知识源如果想给标题，请给 TitleDigest；需要展示明文标题时凭 SourceID 回源，
// 由源侧再判一次权限（标题经常含人名、项目代号，落进网关审计就是个人信息落库）。
type ReturnedDocument struct {
	SourceID      string `json:"source_id"`
	KnowledgeBase string `json:"knowledge_base"`
	// OwnerKind / OwnerID 是文档归属的结构化范围（§2.7），供网关做跨组织兜底。
	OwnerKind string `json:"owner_kind"`
	OwnerID   string `json:"owner_id"`
	// DataLevel 是文档分级名（public / internal / confidential / restricted）。
	// 用字符串而不是序号：跨语言对接时序号会被当成可比较的自定义档位，
	// 出问题时是「按字典序比大小」这种直接越权的错法。
	DataLevel string `json:"data_level"`
	// Digest 是文档内容的 sha256 摘要，由**知识源侧**计算。
	Digest string `json:"digest"`
	// TitleDigest 是标题的域分隔摘要（见 citation.go 的取舍说明）。
	TitleDigest string `json:"title_digest"`
	// Allowed 是知识源自己的判定结论：本篇对该主体是否可读。
	Allowed bool `json:"allowed"`
	// RuleID 是判定依据：知识源侧的规则 ID 或原因码（手册 §3.C 要求的可审计凭据）。
	// 只写「true」不算依据：事后无法证明当初确实有权读。
	RuleID string `json:"rule_id"`
	// DecisionReason 是补充说明用的稳定码（可选，禁止自由文本，见 ValidateDocument）。
	DecisionReason string    `json:"decision_reason,omitempty"`
	AclVersion     string    `json:"acl_version,omitempty"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	Score          float64   `json:"score,omitempty"`
}

// RetrieveResponse 是委托检索的响应体。
type RetrieveResponse struct {
	ProtocolVersion string             `json:"protocol_version"`
	RequestID       string             `json:"request_id"`
	Documents       []ReturnedDocument `json:"documents"`
	// Truncated 表示知识源侧因自己的上限没给全（网关侧还会再截一次）。
	Truncated bool `json:"truncated,omitempty"`
	// AclVersion 是知识源侧 ACL 数据的世代，进审计：判定争议要能对上当时的那套 ACL。
	AclVersion string `json:"acl_version,omitempty"`
	// EvaluatedAt 是知识源完成鉴权的时刻。
	EvaluatedAt time.Time `json:"evaluated_at,omitempty"`
	// ExpiresAt 是本次判定结果的复用上限（结果级 TTL）。
	// 没有它，网关会把一次鉴权结论缓存到 ACL 已改之后，形成「已撤销仍可读」。
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// DecisionReason 是整次检索层面的补充原因码（可选）。
	DecisionReason string `json:"decision_reason,omitempty"`
}

// DelegatedRetriever 是检索委托接口。
//
// 语义约定（对接方必须逐条实现，见 docs/3.0-knowledge-delegation.md §4.1「接口形状」与 §4.6）：
//  1. 实现方**必须自己完成鉴权**：按 req.Subject + req.Chain + req.Purpose 判定每篇文档
//     对该主体是否可读，并在响应里逐条给出 Allowed 与 RuleID。
//  2. 网关不做文档级判定，也不接受网关传来的任何「这篇可读」标签——req 里的
//     KnowledgeBases 只是知识库白名单（由 A 包判定），不是文档结论。
//  3. 任何失败（超时、鉴权依赖不可用、字段缺失）必须以 error 返回，
//     调用方按 fail_closed 处理成「不可读」。返回空文档列表 ≠ 失败，而是「没有可读文档」。
//  4. 实现必须可并发复用（DoD 4）：不得把一次请求的状态存在自身字段上。
//  5. 实现不得返回文档正文与标题明文。
type DelegatedRetriever interface {
	Retrieve(ctx context.Context, req RetrieveRequest) (RetrieveResponse, error)
}

// NamedRetriever 是可选接口：实现方报出自己的名字，审计里就能区分是哪一路委托失败。
//
// 只允许报名字，不允许报端点与凭证：审计表会被很多人读到，
// 「哪台内网机器在提供检索」本身就是可被利用的信息。
type NamedRetriever interface {
	DelegatedRetriever
	RetrieverName() string
}

// retrieverName 取出实现名（未实现 NamedRetriever 时返回空串）。
func retrieverName(r DelegatedRetriever) string {
	if nr, ok := r.(NamedRetriever); ok {
		return nr.RetrieverName()
	}
	return ""
}

// RetrievalError 是一次委托失败。
//
// 消息里只允许出现原因码、HTTP 状态码、知识库 ID 这类稳定标识，
// **绝不允许出现响应体、检索词原文或文档 ID 列表**：
// 失败信息会被打进日志、甚至回显给调用方，那里正是泄漏最常发生的位置。
type RetrievalError struct {
	Reason     Reason `json:"reason"`
	StatusCode int    `json:"status_code,omitempty"`
	// KB 是失败发生时正在访问的知识库集合（排序后），用于定位是哪一路出问题。
	KB []string `json:"knowledge_bases,omitempty"`
	// Detail 是排障用的安全短语（不含内容、不含响应体）。
	Detail string `json:"detail,omitempty"`
	// Cause 是底层错误，**只用于 errors.Is/As 归类，绝不进 Error() 文本**：
	// 底层文案可能带内网地址、响应片段甚至文档内容（例如 JSON 解码错误会回显上下文字节），
	// 而错误既会被打进日志也可能回显给调用方，那里正是泄露最常发生的位置。
	// 保留 Cause 是为了让接线方仍然能按 context.DeadlineExceeded 这类事实分支，
	// 不必为了分类去读一段会泄露的文案。
	Cause error `json:"-"`
}

// Error 实现 error。
func (e *RetrievalError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "knowledge: 检索委托失败 reason=%s", string(e.Reason))
	if e.StatusCode > 0 {
		fmt.Fprintf(&b, " status=%d", e.StatusCode)
	}
	if len(e.KB) > 0 {
		fmt.Fprintf(&b, " kb=%s", strings.Join(e.KB, ","))
	}
	if e.Detail != "" {
		fmt.Fprintf(&b, " detail=%s", e.Detail)
	}
	return b.String()
}

// Unwrap 指向底层错误供 errors.Is/As 分类，但 Error() 不带它的文案。
//
// 为什么不干脆丢掉底层错误：丢掉会让「是超时还是被取消」这类排障事实消失，
// 接线方只能按 Reason 粗分支；带上文案又违反「错误输出不含内容」。
// 这个折中同时满足两边：分类信息在，文案不外流。
func (e *RetrievalError) Unwrap() error { return e.Cause }

// IsFailClosed 报告该错误是否应按「不可读」处理。
//
// 答案是「恒真」——这个函数存在是为了把这条规则写成代码而不是文档：
// 任何检索失败都不等于放行。接线时只要走这个判断，就不会有人写出
// 「超时了就按 public 返回」的兜底。
func IsFailClosed(err error) bool { return err != nil }

// BuildRequest 由上下文 + 知识范围 + 查询装配委托请求。
//
// 这里是网关侧唯一一次把「权限上下文」交给外部的地方，所以先做两件事：
// 校验上下文与范围；按 §2.9 的镜像规则决定是否携带检索词原文。
func BuildRequest(rc RequestContext, scope KnowledgeScope, q Query, now time.Time) (RetrieveRequest, error) {
	if err := rc.Validate(now); err != nil {
		return RetrieveRequest{}, err
	}
	if err := scope.Validate(); err != nil {
		return RetrieveRequest{}, err
	}
	req := RetrieveRequest{
		ProtocolVersion: ProtocolVersion,
		RequestID:       rc.RequestID,
		Subject:         rc.Subject,
		Chain:           append(policy.ScopeChain(nil), rc.Chain...),
		Purpose:         rc.Purpose,
		KnowledgeBases:  append([]string(nil), scope.KnowledgeBases...),
		MaxDataLevel:    scope.MaxDataLevel.String(),
		PolicyVersion:   rc.PolicyVersion,
		MaxResults:      rc.MaxResults,
		IssuedAt:        rc.IssuedAt.UTC(),
		Deadline:        rc.Deadline.UTC(),
		BudgetMS:        rc.Budget.Milliseconds(),
		QueryDigest:     q.Digest(),
		AllowRawTerms:   q.AllowRawTerms,
	}
	if len(scope.Organizations()) > 0 {
		// 取排序后的第一个作为主归属提示：顺序稳定，回放才不会出现同一请求两次不同提示。
		req.Organization = scope.Organizations()[0]
	}
	if q.AllowRawTerms {
		// 只有显式授权才带原文。没授权时**连字段都不出现**，
		// 而不是出现一个空串：省得对端把「空检索词」当成「检索全部」。
		req.SearchTerms = q.Terms
	}
	if err := req.Validate(); err != nil {
		return RetrieveRequest{}, err
	}
	return req, nil
}

// Validate 校验请求必填字段。知识源侧也必须用它自检（导出的原因见协议文档 §2）。
func (req RetrieveRequest) Validate() error {
	if req.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: 协议版本 %q，本实现只接受 %q", ErrProtocol, req.ProtocolVersion, ProtocolVersion)
	}
	if err := validateStableID("request_id", req.RequestID, maxRequestIDLen); err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if err := validateSubjectID(req.Subject); err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if len(req.Chain) == 0 {
		return fmt.Errorf("%w: chain 为空——没有范围就无法鉴权，禁止按「不限范围」处理", ErrProtocol)
	}
	chain, err := policy.NewScopeChain(req.Chain...)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	user := policy.ScopeRef{Kind: policy.ScopeUser, ID: req.Subject}
	if !chain.Includes(user) {
		return fmt.Errorf("%w: chain 未包含主体自身 user:%s", ErrProtocol, req.Subject)
	}
	if strings.TrimSpace(req.Purpose) == "" {
		return fmt.Errorf("%w: purpose 缺失", ErrProtocol)
	}
	if !req.MaxDataLevelValue().Valid() {
		return fmt.Errorf("%w: max_data_level %q 不在固定四级内", ErrProtocol, req.MaxDataLevel)
	}
	if len(req.KnowledgeBases) == 0 {
		return fmt.Errorf("%w: knowledge_bases 为空，没有可触达的知识库", ErrProtocol)
	}
	for _, kb := range req.KnowledgeBases {
		if err := ValidateKnowledgeBaseID(kb); err != nil {
			return err
		}
	}
	if req.MaxResults <= 0 || req.MaxResults > MaxResultsCeiling {
		return fmt.Errorf("%w: max_results %d 不在 1..%d 内", ErrProtocol, req.MaxResults, MaxResultsCeiling)
	}
	if req.Deadline.IsZero() {
		return fmt.Errorf("%w: deadline 缺失，知识源无法限时返回", ErrProtocol)
	}
	if req.QueryDigest == "" {
		return fmt.Errorf("%w: query_digest 缺失", ErrProtocol)
	}
	return nil
}

// MaxDataLevelValue 把分级名解析回 policy.DataLevel。
func (req RetrieveRequest) MaxDataLevelValue() policy.DataLevel {
	level, err := policy.ParseDataLevel(req.MaxDataLevel)
	if err != nil {
		return policy.LevelUnknown
	}
	return level
}

// KnowledgeBaseAllowed 报告知识库在本次允许集合内。
func (req RetrieveRequest) KnowledgeBaseAllowed(kb string) bool {
	return containsString(req.KnowledgeBases, kb)
}

// ValidateEnvelope 校验响应的「外壳」：协议版本、请求回显、条数上限。
//
// 这三项失败必须整份拒绝，因为它们意味着「这份载荷整体不可信」：
//   - 版本不符：字段语义未对齐，逐条判读等于猜；
//   - request_id 不符（串号）：并发扇出到多路知识源时，响应错配会把别人的可读文档
//     递到这个主体手上——这是本包最不能省的一道校验；
//   - 条数超硬上限：知识源被攻陷或有 bug 时可能返回十万条，
//     必须在反序列化后立刻止住，而不是指望 Filter 逐条丢。
//
// 单篇文档的形态问题不在这里拒绝，交给 Filter 逐条丢弃并给原因码：
// 丢弃只会让结果变小，不会放大权限，也不至于让一条坏数据废掉整次检索。
func (resp RetrieveResponse) ValidateEnvelope(req RetrieveRequest) error {
	if resp.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: 响应协议版本 %q", ErrProtocol, resp.ProtocolVersion)
	}
	if resp.RequestID == "" {
		return fmt.Errorf("%w: 响应缺少 request_id", ErrProtocol)
	}
	if resp.RequestID != req.RequestID {
		return fmt.Errorf("%w: 响应 request_id 与请求不符（%q ≠ %q）", ErrProtocol, resp.RequestID, req.RequestID)
	}
	if len(resp.Documents) > maxProtocolDocs {
		return fmt.Errorf("%w: 响应文档条数 %d 超过硬上限 %d", ErrProtocol, len(resp.Documents), maxProtocolDocs)
	}
	return nil
}

// Validate 校验响应外壳并逐篇自检（导出给对接方在源侧自测用）。
func (resp RetrieveResponse) Validate(req RetrieveRequest) error {
	if err := resp.ValidateEnvelope(req); err != nil {
		return err
	}
	for i, doc := range resp.Documents {
		if err := doc.Validate(); err != nil {
			return fmt.Errorf("%w: 第 %d 篇: %v", ErrProtocol, i, err)
		}
	}
	return nil
}

// Validate 校验单篇文档的协议形态。
func (doc ReturnedDocument) Validate() error {
	if reason := doc.protocolViolation(); reason != "" {
		return fmt.Errorf("%w: 文档形态不符（%s）", ErrProtocol, string(reason))
	}
	return nil
}

// protocolViolation 返回该篇违反协议时应当使用的丢弃原因码；空串表示形态合规。
//
// 返回稳定码而不是 error 是为了让 Filter 能把「哪一类坏数据」统计进审计：
// 只报错不分类，现场就无法区分「源侧没实现依据字段」和「摘要被截断」这两种完全不同的故障。
func (doc ReturnedDocument) protocolViolation() Reason {
	if err := validateStableID("source_id", doc.SourceID, maxStableIDLen); err != nil {
		return ReasonProtocolMissing
	}
	if err := ValidateKnowledgeBaseID(doc.KnowledgeBase); err != nil {
		return ReasonProtocolMissing
	}
	kind, err := policy.ParseScopeKind(doc.OwnerKind)
	if err != nil {
		return ReasonProtocolMissing
	}
	if kind != policy.ScopeSystem {
		owner := policy.ScopeRef{Kind: kind, ID: doc.OwnerID}
		if err := owner.Validate(); err != nil {
			return ReasonProtocolMissing
		}
	}
	if _, err := policy.ParseDataLevel(doc.DataLevel); err != nil {
		return ReasonLevelUnknown
	}
	if err := ValidateDigest(doc.Digest); err != nil {
		return ReasonDigestInvalid
	}
	if err := ValidateDigest(doc.TitleDigest); err != nil {
		return ReasonDigestInvalid
	}
	if strings.TrimSpace(doc.RuleID) == "" {
		// 没有 rule_id 就是协议形态不完整，Allowed 是真还是假都一样：
		// Allowed=true 时网关不知道这篇为什么可读，放行等于把「源侧说可以」这句话
		// 当成权限本身；Allowed=false 时这条仍然要进丢弃记录，缺依据就让「为什么被拒」
		// 变成一条无法复核的猜测。检查发生在 Allowed 判定之前（filter.go:119），
		// 所以缺依据的拒绝篇报 document_acl_evidence_missing 而不是 not_readable_at_source。
		return ReasonEvidenceMissing
	}
	if len(doc.RuleID) > maxStableIDLen || strings.ContainsAny(doc.RuleID, " \t\r\n") || containsControl(doc.RuleID) {
		// rule_id 是审计里的关联键：带空白会被日志切成两段，带控制字符是日志注入的入口。
		return ReasonEvidenceMissing
	}
	if doc.DecisionReason != "" && !reasonStyleOK(doc.DecisionReason) {
		return ReasonProtocolMissing
	}
	if doc.Score < 0 {
		return ReasonProtocolMissing
	}
	return ""
}

// OwnerScope 还原文档归属为结构化范围引用。
func (doc ReturnedDocument) OwnerScope() policy.ScopeRef {
	kind, err := policy.ParseScopeKind(doc.OwnerKind)
	if err != nil {
		return policy.ScopeRef{}
	}
	return policy.ScopeRef{Kind: kind, ID: doc.OwnerID}
}

// Level 解析文档分级名。
func (doc ReturnedDocument) Level() policy.DataLevel {
	level, err := policy.ParseDataLevel(doc.DataLevel)
	if err != nil {
		return policy.LevelUnknown
	}
	return level
}

func containsString(in []string, v string) bool {
	for _, s := range in {
		if s == v {
			return true
		}
	}
	return false
}
