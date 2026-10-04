package knowledge

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// ContentProtocolVersion 是「正文交付通道」的协议版本（决策包 §8.1，主线 2026-10-04
// 裁决为配置开关）。
//
// 为什么单独一个版本而不是把检索协议升到 v2：检索协议 v1 的字段集合是一句被测试锁住的
// 承诺（「只有摘要，没有正文」，leak_test.go），而正文交付的成立条件比检索多两道
// （平台配置开关 + 管理员授权 + 源侧逐篇再判一次）。把两件事塞进同一次握手会让
// 「没开开关的部署」也必须在协议层解释正文字段的语义；分开之后检索那条链一个字节都不用动，
// 开关关着时现网行为与裁决前逐字节相同 —— 那是 §8.1 的第一条验收。
//
// 与 ProtocolVersion 同样是精确匹配：破坏性变更必须升版本号并走主线评审。
const ContentProtocolVersion = "llmproxy-knowledge-content-v1"

// 正文通道的绝对上限。与 Spec 的 AbsoluteMaxInputBytes 同一理由：
// 「0 = 不限」这种读法等于允许把任意大的正文留在网关内存里，
// 所以这里给的是**声明也越不过去**的绝对值，而不是默认值。
const (
	// maxContentPassages 是单次交付的篇数硬上限（反序列化阶段就止住，不等逐条丢）。
	// 取 MaxResultsCeiling：能申请的篇目本来就来自一次准入，两个上限一致才不会
	// 出现「准入给了 100 篇、申请时才发现只能申 8 篇」这种要人猜的错配。
	maxContentPassages = MaxResultsCeiling
	// AbsoluteMaxPassageBytes 是单篇正文的绝对上限。单篇超限是**丢弃**而不是截断：
	// 截断后的字节流对不上准入阶段那个摘要，等于一边声称「这是那篇文档」
	// 一边交付另一份字节。
	AbsoluteMaxPassageBytes = 256 << 10
	// AbsoluteMaxContentBytes 是一次交付全部正文的绝对上限。
	AbsoluteMaxContentBytes = 1 << 20
	// DefaultContentPassages / DefaultContentBytes 是声明缺省时网关自己取的保守值。
	DefaultContentPassages = 8
	DefaultContentBytes    = 64 << 10
)

// ContentAsk 是「请把这一篇的正文交付给网关」的请求项。
//
// ExpectedDigest 必须来自**同一次准入检索**返回的那个摘要（见 BuildContentRequest）：
// 它是网关侧唯一能把「被授权的那一篇」和「被交付的那一篇」钉在一起的凭据。
// 没有它，源侧返回什么内容都只能靠 source_id 自证，而 source_id 是对方给的字符串 ——
// 那等于把内容一致性交给对端的诚实度。
type ContentAsk struct {
	SourceID       string    `json:"source_id"`
	KnowledgeBase  string    `json:"knowledge_base"`
	ExpectedDigest string    `json:"expected_digest"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
}

// Key 是一篇文档的稳定标识键（与 Citation.Key 同一分隔口径）。
func (a ContentAsk) Key() string { return a.KnowledgeBase + "\x00" + a.SourceID }

func (a ContentAsk) validate() error {
	if err := validateStableID("source_id", a.SourceID, maxStableIDLen); err != nil {
		return err
	}
	if err := ValidateKnowledgeBaseID(a.KnowledgeBase); err != nil {
		return err
	}
	// 这里必须比完整摘要：截断形式可以碰撞，撞上了就等于把 A 篇的授权当成 B 篇的。
	return ValidateDigest(a.ExpectedDigest)
}

// ContentRequest 是正文交付的请求体。
//
// 身份字段与 RetrieveRequest 同形（主体 + 范围链 + 用途 + 分级上限 + 策略版本），
// 因为源侧要做的判定就是同一套：它必须能独立回答「这个人有没有权拿到这篇正文」，
// 而不是复用上一次检索的结论 —— 上一次结论可能已经过期。
type ContentRequest struct {
	ProtocolVersion string            `json:"protocol_version"`
	RequestID       string            `json:"request_id"`
	Subject         string            `json:"subject"`
	Chain           policy.ScopeChain `json:"chain"`
	Purpose         string            `json:"purpose"`
	KnowledgeBases  []string          `json:"knowledge_bases"`
	MaxDataLevel    string            `json:"max_data_level"`
	PolicyVersion   string            `json:"policy_version"`
	Documents       []ContentAsk      `json:"documents"`
	// MaxPassages / MaxTotalBytes 是网关侧的预算，源侧不得给得更多。
	// 写成请求字段而不是只留在网关本地：源侧知道上限就能在自己的排序阶段先裁掉
	// 给不下的篇目，省一次注定被丢弃的交付。
	MaxPassages   int       `json:"max_passages"`
	MaxTotalBytes int       `json:"max_total_bytes"`
	IssuedAt      time.Time `json:"issued_at"`
	Deadline      time.Time `json:"deadline"`
	// BudgetMS 是 Deadline-IssuedAt 的毫秒数，供无法解析 RFC3339 时兜底限时。
	BudgetMS int64 `json:"budget_ms"`
}

// MaxDataLevelValue 把分级名解析回 policy.DataLevel（与 RetrieveRequest 同一口径）。
func (req ContentRequest) MaxDataLevelValue() policy.DataLevel {
	level, err := policy.ParseDataLevel(req.MaxDataLevel)
	if err != nil {
		return policy.LevelUnknown
	}
	return level
}

// KnowledgeBaseAllowed 报告知识库在本次允许集合内。
func (req ContentRequest) KnowledgeBaseAllowed(kb string) bool {
	return containsString(req.KnowledgeBases, kb)
}

// findAsk 在请求里找这一篇的申请项。
func findAsk(req ContentRequest, kb, sourceID string) (ContentAsk, bool) {
	for _, ask := range req.Documents {
		if ask.KnowledgeBase == kb && ask.SourceID == sourceID {
			return ask, true
		}
	}
	return ContentAsk{}, false
}

// Validate 校验正文交付请求的形态。
func (req ContentRequest) Validate() error {
	if req.ProtocolVersion != ContentProtocolVersion {
		return fmt.Errorf("%w: 正文交付协议版本 %q，本实现只接受 %q",
			ErrProtocol, req.ProtocolVersion, ContentProtocolVersion)
	}
	if err := validateStableID("request_id", req.RequestID, maxRequestIDLen); err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if err := validateSubjectID(req.Subject); err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if len(req.Chain) == 0 {
		return fmt.Errorf("%w: chain 为空——正文交付同样要有范围才能鉴权", ErrProtocol)
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
		return fmt.Errorf("%w: knowledge_bases 为空", ErrProtocol)
	}
	for _, kb := range req.KnowledgeBases {
		if err := ValidateKnowledgeBaseID(kb); err != nil {
			return err
		}
	}
	if len(req.Documents) == 0 {
		return fmt.Errorf("%w: documents 为空——没有准入篇目时不该发出交付请求（调用方必须短路）", ErrProtocol)
	}
	if len(req.Documents) > maxContentPassages {
		return fmt.Errorf("%w: 请求篇数 %d 超过上限 %d", ErrProtocol, len(req.Documents), maxContentPassages)
	}
	if req.MaxPassages <= 0 || req.MaxPassages > maxContentPassages {
		return fmt.Errorf("%w: max_passages %d 不在 1..%d 内", ErrProtocol, req.MaxPassages, maxContentPassages)
	}
	if req.MaxTotalBytes <= 0 || req.MaxTotalBytes > AbsoluteMaxContentBytes {
		return fmt.Errorf("%w: max_total_bytes %d 不在 1..%d 内", ErrProtocol, req.MaxTotalBytes, AbsoluteMaxContentBytes)
	}
	if req.Deadline.IsZero() {
		return fmt.Errorf("%w: deadline 缺失", ErrProtocol)
	}
	seen := make(map[string]bool, len(req.Documents))
	for i, ask := range req.Documents {
		if err := ask.validate(); err != nil {
			return fmt.Errorf("%w: 第 %d 项: %v", ErrProtocol, i, err)
		}
		key := ask.Key()
		if seen[key] {
			return fmt.Errorf("%w: 第 %d 项与更早的项指向同一篇（%s/%s）", ErrProtocol, i, ask.KnowledgeBase, ask.SourceID)
		}
		seen[key] = true
		if !req.KnowledgeBaseAllowed(ask.KnowledgeBase) {
			return fmt.Errorf("%w: 第 %d 项的知识库 %s 不在允许集合内", ErrProtocol, i, ask.KnowledgeBase)
		}
	}
	return nil
}

// Passage 是正文交付的载体。
//
// **本包唯一被允许持有文档正文字节的类型** —— leak_test.go 把这条写成显式例外
// （按类型登记，只许一个），而不是靠字段名绕过词表。它成立的前提是三件事同时在场：
// 平台配置开了正文开关、管理员策略授了 knowledge.content、源侧对这**一篇**又判了一次可交付。
// 缺任何一件，这个类型不该被构造出来。
//
// 生命周期：只在内存里，用完必须走 ClearContent()；
// 不得进审计、日志、错误文案、数据库或任何持久化字段（§2.9 规则 1、2、6）。
type Passage struct {
	SourceID      string `json:"source_id"`
	KnowledgeBase string `json:"knowledge_base"`
	// Digest 是源侧对**本次交付的字节**计算的 sha256，必须与准入阶段的摘要相等。
	// 它是自证而不是冗余：只报 source_id 的话，网关无从知道交付的是不是那一篇。
	Digest      string `json:"digest"`
	DataLevel   string `json:"data_level"`
	TitleDigest string `json:"title_digest,omitempty"`
	// RuleID 是源侧「这一篇可以交原文」的依据。Allowed=true 不等于正文可交付，
	// 所以这一位在交付通道里是必填而不是可选。
	RuleID         string    `json:"rule_id"`
	DecisionReason string    `json:"decision_reason,omitempty"`
	AclVersion     string    `json:"acl_version,omitempty"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	// Verbatim 是文档正文字节。用 []byte 而不是 string 是刻意的：
	// string 在 Go 里不可变，规则 2 要的「处理完立即释放」就落不了地
	// （赋 nil 只会让那份字节继续活在别的字符串头里）；[]byte 能真的清零。
	Verbatim []byte `json:"verbatim,omitempty"`
}

// ClearContent 就地把正文字节清零并丢弃引用（§2.9 规则 2 的落地点）。
//
// 只清 Verbatim：其余字段都是标识与依据，留在审计里是有用的。
func (p *Passage) ClearContent() {
	if p == nil {
		return
	}
	for i := range p.Verbatim {
		p.Verbatim[i] = 0
	}
	p.Verbatim = nil
}

// VerbatimBytes 报告正文长度。字节数属于元数据（与 Body.DeclaredBytes 同一口径），
// 所以三档都能问，不需要先读正文。
func (p Passage) VerbatimBytes() int { return len(p.Verbatim) }

// Level 解析源侧申报的分级（非法 → LevelUnknown）。
func (p Passage) Level() policy.DataLevel {
	level, err := policy.ParseDataLevel(p.DataLevel)
	if err != nil {
		return policy.LevelUnknown
	}
	return level
}

// Display 是日志与界面上能安全说出来的最小形式：永不含正文。
func (p Passage) Display() string {
	return fmt.Sprintf("%s/%s@%s", p.KnowledgeBase, p.SourceID, ShortDigest(p.Digest))
}

// protocolViolation 返回该篇被逐条丢弃时应用的原因码；空串表示形态合规。
//
// 与 ReturnedDocument.protocolViolation 的关键差别是摘要那三条：
//   - Digest 必须等于申请项里的 ExpectedDigest（证明「这就是被授权的那一篇」）；
//   - Digest 还必须等于交付字节自己的 sha256（证明「源侧没有在里面换内容」）；
//   - 两条任何一条不成立都是整篇丢弃：正文一旦进了将要出网的 prompt，
//     就没有「先收下再标记可疑」这种安全中间态。
func (p Passage) protocolViolation(req ContentRequest) Reason {
	if err := validateStableID("source_id", p.SourceID, maxStableIDLen); err != nil {
		return ReasonContentFieldMissing
	}
	if err := ValidateKnowledgeBaseID(p.KnowledgeBase); err != nil {
		return ReasonContentFieldMissing
	}
	if !req.KnowledgeBaseAllowed(p.KnowledgeBase) {
		return ReasonKBNotAllowed
	}
	if _, err := policy.ParseDataLevel(p.DataLevel); err != nil {
		return ReasonLevelUnknown
	}
	if err := ValidateDigest(p.Digest); err != nil {
		return ReasonDigestInvalid
	}
	if p.TitleDigest != "" {
		if err := ValidateDigest(p.TitleDigest); err != nil {
			return ReasonDigestInvalid
		}
	}
	if strings.TrimSpace(p.RuleID) == "" {
		return ReasonContentEvidenceMissing
	}
	if len(p.RuleID) > maxStableIDLen || strings.ContainsAny(p.RuleID, " \t\r\n") || containsControl(p.RuleID) {
		// rule_id 是审计里的关联键：带空白会被日志切成两段，带控制字符是日志注入的入口。
		return ReasonContentEvidenceMissing
	}
	if p.DecisionReason != "" && !reasonStyleOK(p.DecisionReason) {
		return ReasonContentFieldMissing
	}
	if len(p.Verbatim) == 0 {
		// 「交付一篇空正文」不是一种部分成功：它让网关留下一条看起来有内容的引用，
		// 实际什么都没拿到，回放时这种篇目最难解释。
		return ReasonContentFieldMissing
	}
	if len(p.Verbatim) > AbsoluteMaxPassageBytes {
		return ReasonContentTooLarge
	}
	asked, ok := findAsk(req, p.KnowledgeBase, p.SourceID)
	if !ok {
		// 没申请过的篇：在检索方向只是多一条被丢弃的引用，在正文方向却是把一份
		// 没申请过的内容放进网关内存，所以这里一律丢。
		return ReasonContentNotRequested
	}
	if asked.ExpectedDigest != p.Digest {
		return ReasonContentDigestMismatch
	}
	if Digest(p.Verbatim) != p.Digest {
		return ReasonContentDigestMismatch
	}
	return ""
}

// ContentResponse 是正文交付的响应体。
type ContentResponse struct {
	ProtocolVersion string    `json:"protocol_version"`
	RequestID       string    `json:"request_id"`
	Passages        []Passage `json:"passages"`
	Truncated       bool      `json:"truncated,omitempty"`
	AclVersion      string    `json:"acl_version,omitempty"`
	EvaluatedAt     time.Time `json:"evaluated_at,omitempty"`
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
	DecisionReason  string    `json:"decision_reason,omitempty"`
}

// ValidateEnvelope 校验交付响应的「外壳」：版本、请求回显、条数与字节预算。
//
// 前三项与 RetrieveResponse.ValidateEnvelope 同一理由（版本未对齐、串号、
// 被攻陷的源返回海量数据）。后两项是正文通道独有的：
//   - 交付条数不得超过请求条数：源侧返回网关没要的篇目，等于把一份没申请过的
//     内容放进网关内存，这里整份拒绝而不是逐条丢（逐条丢会让一次坏响应
//     掩盖同一次里的其他问题）；
//   - 总字节不得超过请求预算：预算是网关愿意在内存里放多少正文的唯一表达，
//     超出预算的响应说明对端没在实现这条协议，继续逐条判读就是猜。
func (resp ContentResponse) ValidateEnvelope(req ContentRequest) error {
	if resp.ProtocolVersion != ContentProtocolVersion {
		return fmt.Errorf("%w: 交付响应协议版本 %q", ErrProtocol, resp.ProtocolVersion)
	}
	if resp.RequestID == "" {
		return fmt.Errorf("%w: 交付响应缺少 request_id", ErrProtocol)
	}
	if resp.RequestID != req.RequestID {
		return fmt.Errorf("%w: 交付响应 request_id 与请求不符（%q ≠ %q）", ErrProtocol, resp.RequestID, req.RequestID)
	}
	if len(resp.Passages) > maxContentPassages {
		return fmt.Errorf("%w: 交付条数 %d 超过硬上限 %d", ErrProtocol, len(resp.Passages), maxContentPassages)
	}
	if len(resp.Passages) > len(req.Documents) {
		return fmt.Errorf("%w: 交付条数 %d 超过本次请求的 %d 篇", ErrProtocol, len(resp.Passages), len(req.Documents))
	}
	if len(resp.Passages) > req.MaxPassages {
		return fmt.Errorf("%w: 交付条数 %d 超过预算 max_passages=%d", ErrProtocol, len(resp.Passages), req.MaxPassages)
	}
	total := 0
	for _, p := range resp.Passages {
		total += len(p.Verbatim)
	}
	if total > req.MaxTotalBytes {
		return fmt.Errorf("%w: 交付总字节 %d 超过预算 max_total_bytes=%d", ErrProtocol, total, req.MaxTotalBytes)
	}
	return nil
}

// Validate 校验外壳并逐篇自检（导出给对接方在源侧自测）。
func (resp ContentResponse) Validate(req ContentRequest) error {
	if err := resp.ValidateEnvelope(req); err != nil {
		return err
	}
	for i, p := range resp.Passages {
		if err := p.Validate(req); err != nil {
			return fmt.Errorf("%w: 第 %d 篇: %v", ErrProtocol, i, err)
		}
	}
	return nil
}

// Validate 校验单篇交付的协议形态。
func (p Passage) Validate(req ContentRequest) error {
	if reason := p.protocolViolation(req); reason != "" {
		return fmt.Errorf("%w: 交付形态不符（%s）", ErrProtocol, string(reason))
	}
	return nil
}

// DelegatedContentDeliverer 是正文交付委托接口（可选实现，独立于 DelegatedRetriever）。
//
// 语义约定（对接方必须逐条实现）：
//  1. 实现方必须**自己再判一次**这一篇正文可否交付，并给出 RuleID；
//     上一次检索给出 Allowed=true **不等于**正文可交付（分级、脱敏状态、库策略都可能不同）。
//  2. 只允许交付 req.Documents 里申请过的那几篇，Digest 必须是本次交付字节的 sha256。
//  3. 任何失败必须以 error 返回，调用方按 fail_closed 处理成「没有正文」。
//     返回空 passages ≠ 失败，是「这些篇都没有可交付正文」。
//  4. 实现必须可并发复用；不得把一次请求的状态挂在自身字段上。
//  5. 实现不得返回与 ExpectedDigest 不符的字节 —— 网关逐篇重算并整篇丢弃。
type DelegatedContentDeliverer interface {
	DeliverContent(ctx context.Context, req ContentRequest) (ContentResponse, error)
}

// NamedContentDeliverer 是可选接口：交付方报名字，审计里能区分是哪一路失败。
// 与 NamedRetriever 同一条限制：只许报名字，不许报端点与凭证。
type NamedContentDeliverer interface {
	DelegatedContentDeliverer
	ContentDelivererName() string
}

func contentDelivererName(d DelegatedContentDeliverer) string {
	if nd, ok := d.(NamedContentDeliverer); ok {
		return nd.ContentDelivererName()
	}
	return ""
}

// BuildContentRequest 从**准入结果**装配一次正文交付请求。
//
// 入参是 []ReturnedDocument（源侧刚返回的那些篇）而不是任意 ID 列表，这是刻意的：
// 网关只能索取「源侧本次已经声明可读」的文档；凭空报一个 source_id
// 等于让网关替源侧做一次它没做过的判定。
//
// 只保留 Allowed=true 且准入结论未过期的篇。一篇都没剩下时返回的 req.Documents 为空，
// 此时不做 Validate（Validate 拒空 documents），由调用方判空后短路 —— 见 DeliverContents。
func BuildContentRequest(rc RequestContext, scope KnowledgeScope, docs []ReturnedDocument,
	maxPassages, maxTotalBytes int, now time.Time) (ContentRequest, error) {
	if err := rc.Validate(now); err != nil {
		return ContentRequest{}, err
	}
	if err := scope.Validate(); err != nil {
		return ContentRequest{}, err
	}
	if len(rc.Chain) == 0 {
		return ContentRequest{}, fmt.Errorf("%w: chain 为空", ErrContext)
	}

	asks := make([]ContentAsk, 0, len(docs))
	for _, doc := range docs {
		if !doc.Allowed {
			continue
		}
		if !doc.ExpiresAt.IsZero() && !doc.ExpiresAt.After(now) {
			// 准入结论已过期：不申请。这时「能不能拿正文」已经没有依据可答，
			// 补问一次只会让源侧按**新的** ACL 给出一个与当初那次判定无关的答案。
			continue
		}
		ask := ContentAsk{
			SourceID:       strings.TrimSpace(doc.SourceID),
			KnowledgeBase:  strings.TrimSpace(doc.KnowledgeBase),
			ExpectedDigest: strings.ToLower(strings.TrimSpace(doc.Digest)),
			ExpiresAt:      doc.ExpiresAt.UTC(),
		}
		if err := ask.validate(); err != nil {
			return ContentRequest{}, fmt.Errorf("%w: 准入篇目 %s/%s 不可申请正文: %v",
				ErrProtocol, ask.KnowledgeBase, ask.SourceID, err)
		}
		asks = append(asks, ask)
	}
	// 稳定顺序：交付预算的裁剪结果必须与源侧返回顺序无关，否则回放对不上。
	sort.SliceStable(asks, func(i, j int) bool {
		if asks[i].KnowledgeBase != asks[j].KnowledgeBase {
			return asks[i].KnowledgeBase < asks[j].KnowledgeBase
		}
		return asks[i].SourceID < asks[j].SourceID
	})

	passages := clampInt(maxPassages, DefaultContentPassages, maxContentPassages)
	if len(asks) > passages {
		asks = asks[:passages]
	}
	totalBytes := clampInt(maxTotalBytes, DefaultContentBytes, AbsoluteMaxContentBytes)

	req := ContentRequest{
		ProtocolVersion: ContentProtocolVersion,
		RequestID:       rc.RequestID,
		Subject:         rc.Subject,
		Chain:           append(policy.ScopeChain(nil), rc.Chain...),
		Purpose:         rc.Purpose,
		KnowledgeBases:  append([]string(nil), scope.KnowledgeBases...),
		MaxDataLevel:    scope.MaxDataLevel.String(),
		PolicyVersion:   rc.PolicyVersion,
		Documents:       asks,
		MaxPassages:     passages,
		MaxTotalBytes:   totalBytes,
		IssuedAt:        rc.IssuedAt.UTC(),
		Deadline:        rc.Deadline.UTC(),
		BudgetMS:        rc.Budget.Milliseconds(),
	}
	if len(asks) == 0 {
		return req, nil
	}
	if err := req.Validate(); err != nil {
		return ContentRequest{}, err
	}
	return req, nil
}

// clampInt 把声明值夹进 [1, abs]；缺省（<=0）或越界都**回落到保守缺省**，绝不出现「不限」。
//
// 为什么不信任声明值：一个把 max_bytes 误写成 0 或 1<<40 的声明，
// 按「0 = 不限」解释就等于允许把任意大的正文留在网关内存里（同 Spec 的绝对上限理由）。
// 越界也不取绝对上限：把「写错了」读成「那就给到最大」是一次静默放大授权面，
// 回落到保守缺省才是可解释的错法（声明有没有生效在审计计数里看得出来）。
func clampInt(value, defaultVal, abs int) int {
	if value <= 0 || value > abs {
		return defaultVal
	}
	return value
}

// ContentOutcome 是一次正文交付的完整产物。不变量与 Outcome 同形：
// Failure 非空时 Passages 必定为空 —— 调用方不需要（也不应该）写
// 「失败就用已经拿到的部分正文」那种分支，那正是 fail_open 的入口。
type ContentOutcome struct {
	RequestID      string            `json:"request_id"`
	Passages       []Passage         `json:"-"`
	Dropped        []DropRecord      `json:"dropped,omitempty"`
	RequestedCount int               `json:"requested_count"`
	HitCount       int               `json:"hit_count"`
	TotalBytes     int               `json:"total_bytes"`
	MaxDataLevel   policy.DataLevel  `json:"max_data_level"`
	Truncated      bool              `json:"truncated,omitempty"`
	AclVersion     string            `json:"acl_version,omitempty"`
	PolicyVersion  string            `json:"policy_version"`
	DurationMS     int64             `json:"duration_ms"`
	Failure        *RetrievalError   `json:"failure,omitempty"`
	Audit          ContentAuditEvent `json:"audit"`
}

// HasContent 报告这次交付是否真的拿到了正文。
//
// 语义上等价于「网关进程此刻持有文档原文」，所以它是审计与面板上
// 「这次有没有开正文」的唯一判据。
func (o *ContentOutcome) HasContent() bool { return o != nil && len(o.Passages) > 0 }

// DeliverContents 走一次完整的正文交付：装配申请 → 调用交付方 → 网关侧兜底 → 产出审计事件。
//
// 失败语义与 Resolve 同一条：任何交付失败 = 没有正文，返回空 Passages 并在审计里留原因码。
//
// 网关侧兜底逐篇做的事（每一条都是整篇丢弃，不截断）：
//   - 形态不符（含没申请过的篇、Digest 与准入摘要或交付字节不符、缺 rule_id、单篇超绝对上限）；
//   - 同一篇重复交付；
//   - 分级越出本次范围上限、交付方声明的这篇到期时刻已过。
//
// 字节预算是**整份**门槛而不是逐篇裁（见 ValidateEnvelope）：逐篇裁会让「哪几篇进了 prompt」
// 取决于丢弃顺序与对端返回顺序，回放与审计都说不清；整份拒绝则是一个可解释的二值事实。
func DeliverContents(
	ctx context.Context,
	deliverer DelegatedContentDeliverer,
	rc RequestContext,
	scope KnowledgeScope,
	admitted []ReturnedDocument,
	maxPassages, maxTotalBytes int,
	now time.Time,
) (*ContentOutcome, error) {
	if deliverer == nil {
		return nil, fmt.Errorf("%w: 没有注入正文交付实现（fail_closed，绝不把「没有正文」当成放行）", ErrRetriever)
	}
	if err := rc.Validate(now); err != nil {
		return nil, err
	}
	name := contentDelivererName(deliverer)
	outcome := &ContentOutcome{
		RequestID:     rc.RequestID,
		PolicyVersion: rc.PolicyVersion,
		MaxDataLevel:  policy.LevelPublic,
	}

	req, err := BuildContentRequest(rc, scope, admitted, maxPassages, maxTotalBytes, now)
	if err != nil {
		outcome.Failure = &RetrievalError{Reason: ReasonContentProtocolInvalid, KB: scope.KnowledgeBases, Detail: "交付请求装配失败"}
		outcome.Audit = baseContentAudit(rc, scope, rc.IssuedAt, now, ReasonContentProtocolInvalid, policy.LevelPublic, "")
		outcome.Audit.Deliverer = name
		return outcome, err
	}
	outcome.RequestedCount = len(req.Documents)

	// 没有可申请的篇：一次请求都不发。与 Resolve 的「没有准入知识库」短路同形，
	// 理由更强 —— 发出去一个空集合，对端多半会按「全部可读文档」来理解。
	if len(req.Documents) == 0 {
		outcome.Failure = &RetrievalError{Reason: ReasonContentNothingAdmitted, KB: scope.KnowledgeBases, Detail: "没有处于有效期内的准入篇目"}
		outcome.Audit = baseContentAudit(rc, scope, rc.IssuedAt, now, ReasonContentNothingAdmitted, policy.LevelPublic, "")
		outcome.Audit.QueriedBases = nil
		outcome.Audit.Deliverer = name
		return outcome, nil
	}

	callCtx, cancel := context.WithDeadline(ctx, rc.Deadline)
	defer cancel()

	elapsedStart := time.Now()
	resp, err := deliverer.DeliverContent(callCtx, req)
	elapsed := time.Since(elapsedStart)
	if elapsed < 0 {
		// wall clock 回拨（NTP 校正）时别让审计出现负耗时（同 Resolve 的口径）。
		elapsed = 0
	}
	if err != nil {
		failErr := asRetrievalError(err, req.KnowledgeBases)
		outcome.Failure = failErr
		outcome.DurationMS = elapsed.Milliseconds()
		outcome.Audit = baseContentAudit(rc, scope, rc.IssuedAt, rc.IssuedAt.Add(elapsed), failErr.Reason, policy.LevelPublic, "")
		outcome.Audit.QueriedBases = req.KnowledgeBases
		outcome.Audit.RequestedCount = len(req.Documents)
		outcome.Audit.FailureDetail = failErr.Error()
		outcome.Audit.Deliverer = name
		return outcome, failErr
	}

	if envErr := resp.ValidateEnvelope(req); envErr != nil {
		failErr := contentProtocolError(envErr, req.KnowledgeBases)
		outcome.Failure = failErr
		outcome.DurationMS = elapsed.Milliseconds()
		outcome.Audit = baseContentAudit(rc, scope, rc.IssuedAt, rc.IssuedAt.Add(elapsed), failErr.Reason, policy.LevelPublic, resp.AclVersion)
		outcome.Audit.QueriedBases = req.KnowledgeBases
		outcome.Audit.RequestedCount = len(req.Documents)
		outcome.Audit.FailureDetail = failErr.Error()
		outcome.Audit.Deliverer = name
		// 外壳不合格时**主动清掉**已经反序列化进内存的正文：
		// 这条路径上 resp 是本地变量，出函数就能被回收，但「能回收」不等于
		// 「已清零」—— 规则 2 要的是内容不留在堆上等着被人翻。
		clearPassages(resp.Passages)
		return outcome, failErr
	}

	kept := make([]Passage, 0, len(resp.Passages))
	keptIdx := make(map[int]bool, len(resp.Passages))
	var dropped []DropRecord
	seen := map[string]bool{}
	maxLevel := policy.LevelPublic
	for i := range resp.Passages {
		p := resp.Passages[i]
		key := p.Key()
		if reason := p.protocolViolation(req); reason != "" {
			dropped = append(dropped, DropRecord{SourceID: p.SourceID, KnowledgeBase: p.KnowledgeBase, Reason: reason})
			continue
		}
		if seen[key] {
			dropped = append(dropped, DropRecord{SourceID: p.SourceID, KnowledgeBase: p.KnowledgeBase, Reason: ReasonDuplicate})
			continue
		}
		level := p.Level()
		if scope.MaxDataLevel.Valid() && level.Exceeds(scope.MaxDataLevel) {
			dropped = append(dropped, DropRecord{SourceID: p.SourceID, KnowledgeBase: p.KnowledgeBase, Reason: ReasonLevelExceeded})
			continue
		}
		// 这里判的是**交付方声明的这篇的到期时刻**（不是申请项的：申请项在
		// BuildContentRequest 里已经按 now 筛过一轮，留到这里的必然还没到期）。
		// 源侧完全可以交一份「当初授权、此刻已撤」的正文，撤权残留正是 §3.C 要点名的形态。
		if !p.ExpiresAt.IsZero() && !p.ExpiresAt.After(now) {
			dropped = append(dropped, DropRecord{SourceID: p.SourceID, KnowledgeBase: p.KnowledgeBase, Reason: ReasonContentExpired})
			continue
		}
		seen[key] = true
		kept = append(kept, p)
		keptIdx[i] = true
		if level.Exceeds(maxLevel) {
			maxLevel = level
		}
	}
	// 没被留下的篇目里那些字节不会再被任何人读到：立刻清零，不等 GC。
	// 按下标判定而不是按 Key：重复篇被丢时它与保留项同键，按键判会漏清零那一份。
	// 也必须改 resp.Passages 本身：range 出来的副本清零只抹掉共享数组的内容，
	// 副本上的 `Verbatim = nil` 落不到原切片，留着一条长度非零的空正文更难解释。
	for i := range resp.Passages {
		if !keptIdx[i] {
			resp.Passages[i].ClearContent()
		}
	}
	sortPassages(kept)

	total := 0
	for i := range kept {
		total += len(kept[i].Verbatim)
	}
	outcome.Passages = kept
	outcome.HitCount = len(kept)
	outcome.Dropped = dropped
	outcome.MaxDataLevel = maxLevel
	outcome.Truncated = resp.Truncated
	outcome.AclVersion = resp.AclVersion
	outcome.DurationMS = elapsed.Milliseconds()
	outcome.TotalBytes = total

	resultCode := ReasonContentNone
	if len(kept) > 0 {
		resultCode = ReasonContentOK
	}
	outcome.Audit = baseContentAudit(rc, scope, rc.IssuedAt, rc.IssuedAt.Add(elapsed), resultCode, maxLevel, resp.AclVersion)
	outcome.Audit.QueriedBases = req.KnowledgeBases
	outcome.Audit.RequestedCount = len(req.Documents)
	outcome.Audit.DeliveredCount = len(kept)
	outcome.Audit.DeliveredBytes = total
	outcome.Audit.DroppedCount = len(dropped)
	outcome.Audit.DroppedReasons = Reasons(dropReasonsOf(dropped))
	outcome.Audit.Truncated = outcome.Truncated
	outcome.Audit.DeliveredDigests = passageDigests(kept)
	outcome.Audit.Deliverer = name
	return outcome, nil
}

// contentProtocolError 把交付响应的协议不符收敛成正文方向的稳定码。
//
// 不能直接用 asRetrievalError：它把 ErrProtocol 归成 retrieval_protocol_invalid，
// 于是「正文交付的协议问题」在审计里和「检索的协议问题」混成一行，
// 而 §8.1 第三条口径要的恰恰是能单独统计「原文进过网关的失败」。
// Detail 只写固定短句：对端错误文案可能含 URL 甚至响应片段，不进审计。
func contentProtocolError(err error, kbs []string) *RetrievalError {
	return &RetrievalError{
		Reason: ReasonContentProtocolInvalid,
		KB:     append([]string(nil), kbs...),
		Detail: "交付响应协议不符",
		Cause:  err,
	}
}

// clearPassages 批量清零（外壳不合格整份拒绝时用最直接）。
func clearPassages(in []Passage) {
	for i := range in {
		in[i].ClearContent()
	}
}

// Key 是这一篇的稳定标识键。
func (p Passage) Key() string { return p.KnowledgeBase + "\x00" + p.SourceID }

// sortPassages 按稳定顺序排序交付结果（知识库 → 来源 ID → 摘要）。
// 与 SortCitations 同一口径：注入进正文的顺序必须与对端返回顺序无关。
func sortPassages(in []Passage) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].KnowledgeBase != in[j].KnowledgeBase {
			return in[i].KnowledgeBase < in[j].KnowledgeBase
		}
		if in[i].SourceID != in[j].SourceID {
			return in[i].SourceID < in[j].SourceID
		}
		return in[i].Digest < in[j].Digest
	})
}

func passageDigests(in []Passage) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, p.Digest)
	}
	return out
}

// ContentAuditEvent 是一次正文交付的审计事件。
//
// 与 AuditEvent 分开成两个类型、两个审计动作（`knowledge.search` / `knowledge.content`）
// 是 §8.1 的第三条口径：检索「拿到引用」和「拿到原文」是两种合规事件，
// 值班要能单独统计后者，也要能在只看到前者的表里确认「这次没有开正文」。
//
// 明确**不记录**：正文字节或其任何片段、标题明文。字节数与摘要属于元数据，可以记。
type ContentAuditEvent struct {
	RequestID  string            `json:"request_id"`
	Subject    string            `json:"subject"`
	SubjectRef string            `json:"subject_ref,omitempty"`
	Chain      policy.ScopeChain `json:"chain"`
	Purpose    string            `json:"purpose"`

	AllowedBases []string `json:"allowed_knowledge_bases"`
	QueriedBases []string `json:"queried_knowledge_bases,omitempty"`

	RequestedCount int `json:"requested_count"`
	DeliveredCount int `json:"delivered_count"`
	// DeliveredBytes 是交付正文总字节数：它是「这次到底搬了多少内容进网关」的量化答案。字段名不叫 content_bytes、方法不叫 ContentBytes，
	// 是为了让本包的禁词扫描（leak_test.go）能继续「见 content 即红」而不必开特例：
	// 审计面里需要的只是量级，不是这个词。
	DeliveredBytes int      `json:"delivered_bytes"`
	DroppedCount   int      `json:"dropped_count"`
	DroppedReasons []Reason `json:"dropped_reasons,omitempty"`

	MaxDataLevel        string `json:"max_data_level"`
	RequestMaxDataLevel string `json:"request_max_data_level"`

	ResultCode    Reason `json:"result_code"`
	FailureDetail string `json:"failure_detail,omitempty"`

	PolicyVersion string `json:"policy_version"`
	AclVersion    string `json:"acl_version,omitempty"`

	Truncated  bool      `json:"truncated,omitempty"`
	DurationMS int64     `json:"duration_ms"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`

	Deliverer string `json:"deliverer,omitempty"`

	// DeliveredDigests 是实际交付的内容摘要（逐篇，非正文）。
	DeliveredDigests []string `json:"delivered_digests,omitempty"`
}

// baseContentAudit 组装交付审计的公共部分。
//
// 与 baseAudit 同一条理由：成功与每一条失败路径共用同一个构造器，
// 失败路径漏记字段会让「正文交付失败率」这类统计失去分母。
func baseContentAudit(rc RequestContext, scope KnowledgeScope, started, finished time.Time,
	resultCode Reason, level policy.DataLevel, aclVersion string) ContentAuditEvent {
	durationMS := finished.Sub(started).Milliseconds()
	if durationMS < 0 {
		durationMS = 0
	}
	return ContentAuditEvent{
		RequestID:           rc.RequestID,
		Subject:             rc.Subject,
		SubjectRef:          subjectRef(rc.Subject),
		Chain:               append(policy.ScopeChain(nil), rc.Chain...),
		Purpose:             rc.Purpose,
		AllowedBases:        append([]string(nil), scope.KnowledgeBases...),
		MaxDataLevel:        level.String(),
		RequestMaxDataLevel: scope.MaxDataLevel.String(),
		ResultCode:          resultCode,
		PolicyVersion:       rc.PolicyVersion,
		AclVersion:          aclVersion,
		DurationMS:          durationMS,
		StartedAt:           started.UTC(),
		FinishedAt:          finished.UTC(),
	}
}

// Validate 校验交付审计事件形态（与 AuditEvent.Validate 同一组门槛）。
func (e ContentAuditEvent) Validate() error {
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
	if !e.ResultCode.Valid() {
		return fmt.Errorf("%w: 结果码 %q 未注册", ErrAudit, string(e.ResultCode))
	}
	if err := ValidateReasons(e.DroppedReasons); err != nil {
		return fmt.Errorf("%w: %v", ErrAudit, err)
	}
	if e.RequestedCount < 0 || e.DeliveredCount < 0 || e.DeliveredBytes < 0 || e.DroppedCount < 0 {
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
	for _, d := range e.DeliveredDigests {
		if err := ValidateDigest(d); err != nil {
			return fmt.Errorf("%w: 交付摘要不合法: %v", ErrAudit, err)
		}
	}
	return nil
}

// MarshalJSON 走一次 PII 兜底（与 AuditEvent 同一口径：序列化点是最后能拦住的地方）。
func (e ContentAuditEvent) MarshalJSON() ([]byte, error) {
	if looksLikePII(e.Subject) {
		if e.SubjectRef == "" {
			e.SubjectRef = subjectRef(e.Subject)
		}
		e.Subject = ""
	}
	type contentAuditAlias ContentAuditEvent
	return json.Marshal(contentAuditAlias(e))
}

// String 是单行日志形态：只有标识与计数，永远没有正文。
func (e ContentAuditEvent) String() string {
	subject := e.Subject
	if looksLikePII(subject) {
		if e.SubjectRef == "" {
			e.SubjectRef = subjectRef(subject)
		}
		subject = ""
	}
	return fmt.Sprintf(
		"knowledge-content-audit request=%s subject=%s ref=%s purpose=%s requested=%d delivered=%d bytes=%d dropped=%d drop_reasons=%s level=%s ceiling=%s result=%s policy=%s acl=%s duration_ms=%d at=%s",
		orDash(e.RequestID), orDash(subject), orDash(e.SubjectRef), orDash(e.Purpose),
		e.RequestedCount, e.DeliveredCount, e.DeliveredBytes, e.DroppedCount,
		joinReasons(e.DroppedReasons), orDash(e.MaxDataLevel), orDash(e.RequestMaxDataLevel),
		string(e.ResultCode), orDash(e.PolicyVersion), orDash(e.AclVersion),
		e.DurationMS, e.FinishedAt.UTC().Format(time.RFC3339))
}
