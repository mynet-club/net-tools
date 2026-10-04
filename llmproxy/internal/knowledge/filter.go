package knowledge

import (
	"fmt"
	"sort"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// FilterResult 是兜底过滤的产物。
//
// HitCount / MaxDataLevel 是审计字段，Dropped 是解释面：
// 两者分开是为了让「命中 0 篇」也能说清原因（全被兜底丢弃 vs 源侧本来就没有）。
// citations 与 dropped 是未导出字段：只由 Filter 填充，
// 免得外部手构出一个「HitCount=5 但引用为空」的自相矛盾结果进审计。
type FilterResult struct {
	citations []Citation
	dropped   []DropRecord
	// accepted 是与 citations **一一对齐**的源侧原始文档条目（同序、同截断）。
	// 只由 Filter 填充，理由与 citations 相同：外部手构一份「引用与文档对不上」的
	// 结果，正文交付就会拿一个不存在的准入结论去申请原文。
	accepted     []ReturnedDocument
	HitCount     int              `json:"hit_count"`
	MaxDataLevel policy.DataLevel `json:"max_data_level"`
	Truncated    bool             `json:"truncated,omitempty"`
	Reasons      []Reason         `json:"reasons,omitempty"`
}

// Citations 返回引用的副本（调用方改动不会影响审计记录）。
func (r FilterResult) Citations() []Citation { return append([]Citation(nil), r.citations...) }

// Accepted 返回**兜底过滤后仍然留下**的那些文档条目（副本，顺序与 Citations 一致）。
//
// 它是正文交付的唯一合法输入（content.go 的 BuildContentRequest）：交付申请必须建立在
// 「源侧本次真的判过可读、并且带着 expires_at 与 digest」的事实上，而不是从引用反推 ——
// Citation 结构上没有 Allowed/ExpiresAt，反推等于替源侧编造一个它没给过的到期时刻。
// 返回副本是为了让调用方改不动过滤结果本身（同一份结果还要落审计）。
func (r FilterResult) Accepted() []ReturnedDocument {
	return append([]ReturnedDocument(nil), r.accepted...)
}

// Dropped 返回丢弃记录的副本。
func (r FilterResult) Dropped() []DropRecord { return append([]DropRecord(nil), r.dropped...) }

// dropSink 收集丢弃记录（内部使用，保证 dropped 与 reasons 出自同一份数据）。
type dropSink struct{ records []DropRecord }

// dropReasonsOf 抽出丢弃记录里的原因码（审计只统计码，不带任何内容字段）。
func dropReasonsOf(records []DropRecord) []Reason {
	out := make([]Reason, 0, len(records))
	for _, r := range records {
		out = append(out, r.Reason)
	}
	return out
}

func (s *dropSink) add(doc ReturnedDocument, reason Reason) {
	s.records = append(s.records, DropRecord{
		SourceID:      doc.SourceID,
		KnowledgeBase: doc.KnowledgeBase,
		Reason:        reason,
	})
}

func (s *dropSink) addCitation(c Citation, reason Reason) {
	s.records = append(s.records, DropRecord{
		SourceID:      c.SourceID,
		KnowledgeBase: c.KnowledgeBase,
		Reason:        reason,
	})
}

func (s *dropSink) reasons() []Reason { return dropReasonsOf(s.records) }

// Filter 是**网关侧硬约束的兜底再收一道**，不是文档权限判定。
//
// 与知识源判定的区别必须说清楚，否则这一层看起来就像在越权：
//   - 知识源判定：掌握文档 ACL 的全部事实（谁属于哪个部门、哪份档案挂在哪个项目），
//     它回答「这篇对这个主体可读吗」。这是唯一的权限判定现场。
//   - 本函数：只知道交给它的那份上下文（req.Chain / req.KnowledgeBases / req.MaxDataLevel），
//     只丢弃任何**超出这份上下文**的返回项。
//     它从不因为「知识源没说不行」而放行，也从不按文档自带的标签文本判权限。
//
// 一句话：Filter 只能让结果集合变小，永远不可能变大。
// 不这么做会出什么事：知识源配错（把组织 A 的库挂进组织 B 的白名单）、
// 或响应在并发扇出中被串号，越权文档就会直达模型上下文；
// 而网关这一侧唯一还兜得住的，就是「你返回的东西不在我给你的范围内，丢弃」。
//
// 丢弃必须给 reason code（手册 §5）：没有原因码的丢弃等于「静默少了几篇」，
// 现场排查只能靠猜。
//
// now 显式传参（与 A 包同一口径）：过期判定吃注入的时钟，
// 这条路径才写得出确定性测试，回放也对得齐。
func Filter(resp RetrieveResponse, req RetrieveRequest, now time.Time) (FilterResult, error) {
	if err := req.Validate(); err != nil {
		return FilterResult{}, err
	}
	// 外壳不符（版本、串号、条数膨胀）整份拒绝：这一份载荷整体不可信。
	if err := resp.ValidateEnvelope(req); err != nil {
		return FilterResult{}, err
	}

	var drops dropSink
	result := FilterResult{}

	// 结果级 TTL 过期：整份响应作废，一条都不留。
	// 逐条判分会让「ACL 改了但只改了一半」这种状态被当成可信结果，
	// 而事实是这批判定已整体不可信。
	if !resp.ExpiresAt.IsZero() && !now.Before(resp.ExpiresAt) {
		for _, doc := range resp.Documents {
			drops.add(doc, ReasonACLExpired)
		}
		result.dropped = drops.records
		result.MaxDataLevel = policy.LevelPublic
		result.Reasons = Reasons(drops.reasons())
		return result, nil
	}

	ceiling := req.MaxDataLevelValue()

	// 遍历顺序固定：先按稳定键排序，再逐条判定。
	// 不排序的话，同一份响应在对端返回顺序抖动时会得出不同的「谁被截断」结论，
	// 审计摘要跟着抖，回放就不成立（§2.8 同一口径）。
	docs := append([]ReturnedDocument(nil), resp.Documents...)
	sortReturnedDocuments(docs)

	stamp := chooseStamp(resp.EvaluatedAt, now)
	candidates := make([]Citation, 0, len(docs))
	// byDoc 是「引用 → 源侧条目」的回查表，供 Accepted 用。
	// 键与 Citation.Key() 同形：dedupeCitations 正是按这个键判重复的，
	// 两处用同一个键才能保证引用与条目不会因为「哪一处先算重」而错位。
	byDoc := map[string]ReturnedDocument{}
	for _, doc := range docs {
		// 先按协议形态自检，坏数据逐条丢弃并给出稳定码：
		// 一条坏文档不该废掉整次检索，但更不能带着可疑形态进入引用集合。
		if violation := doc.protocolViolation(); violation != "" {
			drops.add(doc, violation)
			continue
		}
		if reason := hardConstraint(req, doc, ceiling, now); reason != "" {
			drops.add(doc, reason)
			continue
		}
		citation, err := NewCitation(doc, stamp)
		if err != nil {
			drops.add(doc, ReasonProtocolMissing)
			continue
		}
		candidates = append(candidates, citation)
		byDoc[citation.Key()] = doc
	}

	// 引用集合内部再收一道：同一篇文档重复出现只留一条；
	// 同一来源 ID 出现两个不同摘要说明源侧状态不一致，两篇一起丢（fail_closed），
	// 因为网关没有第三种信息可以判断哪一版是对的。
	citations := dedupeCitations(candidates, &drops)

	// 结果数上限：网关侧再截一次。
	// 对端已经按 max_results 截过也要截——「对端是否实现上限」不受本包控制，
	// 而引用条数直接放大提示词体积与费用。
	if len(citations) > req.MaxResults {
		for _, c := range citations[req.MaxResults:] {
			drops.addCitation(c, ReasonOverResultLimit)
		}
		citations = citations[:req.MaxResults]
		result.Truncated = true
	}

	result.citations = citations
	// accepted 与 citations 一一对齐（同序、同去重、同截断），正文交付据此申请。
	// 缺一条回查到的条目就跳过那一篇而不是塞一个零值进去：零值 ExpiresAt 会被
	// 交付侧读成「这条准入没有到期时刻」，那是一次凭空放宽。
	result.accepted = make([]ReturnedDocument, 0, len(citations))
	for _, c := range citations {
		if doc, ok := byDoc[c.Key()]; ok {
			result.accepted = append(result.accepted, doc)
		}
	}
	result.HitCount = len(citations)
	result.MaxDataLevel = MaxKnowledgeLevel(citations)
	result.dropped = drops.records
	result.Reasons = Reasons(drops.reasons())
	return result, nil
}

// hardConstraint 返回该篇应被丢弃的原因码；空串表示没有任何硬约束被违反。
//
// 检查次序固定：先「源侧自己说不可读」，再知识库白名单、分级上限、归属范围、判定时效。
// 次序固定的意义是原因码可复现——同一输入永远报同一个码；
// 否则一次策略调整会让大盘上同类事件的码分布随机变化，看不出真实原因。
//
// 这里只列「硬约束」。协议形态（缺摘要、缺依据、分级名非法）由
// ReturnedDocument.protocolViolation 先判：形态不符与越界是两种故障，
// 混成同一个码就分不清「对端没实现协议」和「对端给了范围外的文档」。
func hardConstraint(req RetrieveRequest, doc ReturnedDocument, ceiling policy.DataLevel, now time.Time) Reason {
	if !doc.Allowed {
		// 知识源自己标了不可读却被返回：一律不出网关。
		// 这一步绝不能省——它正是「未授权文档」进入模型上下文的唯一入口。
		return ReasonNotReadableAtSource
	}
	if !req.KnowledgeBaseAllowed(doc.KnowledgeBase) {
		return ReasonKBNotAllowed
	}
	if doc.Level().Exceeds(ceiling) {
		return ReasonLevelExceeded
	}
	if reason := coversOwner(req.Chain, doc.OwnerScope(), req.Subject); reason != "" {
		return reason
	}
	if !doc.ExpiresAt.IsZero() && !now.Before(doc.ExpiresAt) {
		return ReasonACLExpired
	}
	return ""
}

// coversOwner 是跨范围归属的唯一实现：文档声明的归属必须落在这次请求的范围集合内。
//
// system 归属不适用本检查（它不属于任何组织，分级与知识库白名单仍然生效）；
// user 归属必须等于本次主体；organization / project 归属必须在 chain 里精确存在。
// 本包不猜「项目属于组织」的层级：层级由各适配器（B/G）展开成完整 chain 传进来，
// 与 policy 包约定一致。
func coversOwner(chain policy.ScopeChain, owner policy.ScopeRef, subject string) Reason {
	if err := owner.Validate(); err != nil {
		return ReasonSubjectMismatch
	}
	switch owner.Kind {
	case policy.ScopeSystem:
		return ""
	case policy.ScopeUser:
		if owner.ID == subject {
			return ""
		}
		return ReasonSubjectMismatch
	case policy.ScopeOrganization, policy.ScopeProject:
		for _, s := range chain {
			if s.Is(owner) {
				return ""
			}
		}
		return ReasonCrossOrg
	}
	return ReasonCrossOrg
}

// dedupeCitations 按 (知识库, 来源 ID) 去重。
func dedupeCitations(in []Citation, drops *dropSink) []Citation {
	if len(in) == 0 {
		return nil
	}
	// 先统计每个 key 出现的摘要种类：>1 种就是「同来源两版本」，全部丢弃。
	digests := make(map[string]map[string]bool, len(in))
	for _, c := range in {
		key := c.Key()
		if digests[key] == nil {
			digests[key] = make(map[string]bool, 1)
		}
		digests[key][c.Digest] = true
	}
	seen := make(map[string]bool, len(in))
	out := make([]Citation, 0, len(in))
	for _, c := range in {
		key := c.Key()
		if len(digests[key]) > 1 {
			drops.addCitation(c, ReasonDuplicate)
			continue
		}
		if seen[key] {
			// 完全相同的重复条目：只留第一条，其余丢弃并留码（不报错，因为它不构成不可信）。
			drops.addCitation(c, ReasonDuplicate)
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}

// MaxKnowledgeLevel 返回引用集合里的最高分级，零命中返回 LevelPublic。
//
// 零命中必须是 public 而不是 LevelUnknown：手册 §2.3 的组合规则里
// knowledge_level 是必须参与取 max 的入参，传 Unknown 会让 policy.EffectiveLevel
// 直接报错，把「这次没检索到东西」升级成整条链路失败。
func MaxKnowledgeLevel(citations []Citation) policy.DataLevel {
	out := policy.LevelPublic
	for _, c := range citations {
		level := c.Level()
		if !level.Valid() {
			// 引用里出现非法分级说明构造有 bug：按最严的一档处理，
			// 让上层要么报错要么走 restricted 的保守路由，绝不按 public 放行。
			return policy.LevelRestricted
		}
		if level > out {
			out = level
		}
	}
	return out
}

// EffectiveLevelFor 把命中文档的最高分级作为 §2.3 组合规则里的 knowledge_level 入参：
//
//	effective = max(user_level, detected_level, knowledge_level)
//
// detected_level 这里恒传 LevelPublic：**知识检索层不读正文，也没有正文可检测**
// （本包任何结构都不持有正文，见 citation.go）。检测档位由 E 包的分类器给出后，
// 由接线方再调一次 policy.EffectiveLevel 合并三方。在这里传 public 是
// 「C 只贡献 knowledge_level」这一分工的可读证据，而不是把检测当成 0 分忽略掉。
//
// 不这么做会出什么事：如果这里直接返回 max(user, knowledge) 并让接线方以为已含检测，
// 一次含敏感原文的提问就会按较低的档位路由到不该去的供应商。
func EffectiveLevelFor(userLevel policy.DataLevel, hitDocsMaxLevel policy.DataLevel) (policy.DataLevel, error) {
	effective, err := policy.EffectiveLevel(userLevel, policy.LevelPublic, hitDocsMaxLevel)
	if err != nil {
		return policy.LevelUnknown, fmt.Errorf(
			"knowledge: 生效分级组合失败（C 只贡献 knowledge_level，detected_level 归分类器）: %w", err)
	}
	return effective, nil
}

// sortReturnedDocuments 按稳定键排序：来源 ID → 知识库。
//
// 相关性分数的排序属于呈现层：兜底判定不能被分数影响，
// 否则「分数高」就等于「可以越范围」，那是把排序当权限。
func sortReturnedDocuments(in []ReturnedDocument) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].SourceID != in[j].SourceID {
			return in[i].SourceID < in[j].SourceID
		}
		return in[i].KnowledgeBase < in[j].KnowledgeBase
	})
}

// chooseStamp 优先用知识源声明的鉴权时刻，没有则用 now。
func chooseStamp(evaluatedAt time.Time, now time.Time) time.Time {
	if evaluatedAt.IsZero() {
		return now
	}
	return evaluatedAt
}

// DropRecord 是一条兜底丢弃记录。
//
// 只记稳定 ID 与原因码：丢弃本身是「这篇不该出现」，
// 再把它的标题或摘要片段记进去等于二次泄露同一条信息。
type DropRecord struct {
	SourceID      string `json:"source_id"`
	KnowledgeBase string `json:"knowledge_base"`
	Reason        Reason `json:"reason"`
}

// Validate 校验丢弃记录的原因码已注册（审计落库前调用）。
func (d DropRecord) Validate() error {
	if err := validateStableID("source_id", d.SourceID, maxStableIDLen); err != nil {
		return err
	}
	if !d.Reason.Valid() {
		return fmt.Errorf("knowledge: 丢弃原因码 %q 未注册", string(d.Reason))
	}
	return nil
}
