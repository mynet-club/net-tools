package server

// 本文件是 §3.C 的接线层：把 internal/knowledge 的委托协议接到请求路径上，让「知识库
// 检索」成为一项有身份、有范围、有策略版本、有审计的自助能力，而不是「配了
// knowledge_sources 就能问」的旁路。
//
// 五条不可越过的线（与 docs/3.0-stage-summary.md §3 同口径）：
//
//  1. **准入判定只有 A 包一个真值源**。某个知识库能不能碰，只问
//     knowledge.AdmitKnowledgeBases（资源 `knowledge:<id>` + 动作 `read`）。本层不写第二套
//     权限规则；客户端传来的库名只能**收窄**候选，永远不能扩展 —— 声明段里没有的库连
//     委托入口都不存在，策略就算放行也没法问，这类「接线事实」单列成
//     undeclared 而不是混进策略拒绝码（原因码注册表只能记真实判定）。
//  2. **委托客户端只从出网策略构造**。transport 一律取 `s.Transports().Get("")`，
//     拿不到就让这个源装配失败、请求期指名报错，绝不回落 http.DefaultTransport ——
//     与 sidecar 同一条理由：默认 transport 不受出网白名单管，而审计看不出差别。
//  3. **失败不产出部分结果**。knowledge.Outcome 的不变量是「Failure 非空 ⇒ Citations 必空」，
//     本层不加「失败了就用已有结果」的分支，那正是 fail_open 的入口。被问到的源**全部**
//     失败时回话是 502，而不是一个看起来像「库里没有」的空集合。
//  4. **检索词一律只传摘要**（§2.9 规则 4：原文授权只能由管理员策略授予）。本版没有
//     「原文检索词」这个授权位，所以请求体不接受 `allow_raw_terms`：未知键在严格解码这一关
//     就被拒掉，越权意图不静默降级成「当作没看见」。
//  5. **审计按源逐条落，且必须落得进去**。多源就是多条 knowledge.AuditEvent ——
//     「哪个库查到几篇」与「哪一家失败」是两个事实。detail 直接落事件的序列化形态，
//     结构上就不含正文、标题明文与检索词原文（C 包在序列化点还兜一次 PII）。
//     审计写不进去时本次结果**不交付**：能读出内容却留不下痕的接口就是绕过审计。
//
// 模式口径与处理器的差别值得写下来：处理器只在 enforce 参与（读正文有合规成本），而
// 检索在 shadow 与 enforce 下都可用 —— 它不改变 2.x 的任何行为，准入判定在两种模式下
// 都由同一个内核给出；legacy（根本没有策略内核）一律 501，因为「没有策略所以全都给」
// 是 §3.C 明令禁止的失败模式。静态 key 则一律 403：C 包要求范围集合含 `user:<subject>`，
// 而共享钥匙没有主体，退化成「按 system 范围检索」等于把网关主人的授权借给所有拿钥匙的人。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/knowledge"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

const (
	// kbAuditAction 是检索在审计表里的动作名。
	kbAuditAction = "knowledge.search"
	// kbPurpose 是知识检索的用途串，同时进 policy.PolicyContext 与委托上下文。
	//
	// 它**不**走 policyPurposeFor：那个函数面向的是模型调用（chat/embedding/inference），
	// 而「查知识库」与「问模型」的合规口径不同 —— 合成一个值会让 deny 规则没法只针对
	// 检索收紧。新增用途取值必须同时进策略文档，这里就是那个来源。
	kbPurpose = "knowledge-search"
	// kbMaxQueryBytes 是检索词的长度上限。委托只发摘要，长度不进协议字段，
	// 但上限仍然要有：没有限制的输入会让审计体积与对端处理成本失去边界。
	kbMaxQueryBytes = 4096
)

var (
	// errKnowledgeNoPolicy：legacy，没有内核就没法判准入。
	errKnowledgeNoPolicy = errors.New("多用户策略链路未启用（policy.mode=legacy），无法判定知识库准入")
	// errKnowledgeNoSource：这个修订没声明知识源。
	errKnowledgeNoSource = errors.New("未配置知识源（knowledge_sources 段为空）")
	// errKnowledgeNoBundle：本范围链上没有生效的策略包 = 没有任何管理员授权过知识库。
	errKnowledgeNoBundle = errors.New("当前范围没有生效的策略包，因此没有任何知识库被授权")
	// errKnowledgeNoIdentity：名字落不成可归属范围（邮箱形态用户名等脏数据）。
	errKnowledgeNoIdentity = errors.New("当前身份无法构造检索上下文（主体必须是可归属的稳定 ID）")
	// errKnowledgeAudit：审计落库失败，被包住的原始错误只进日志。
	errKnowledgeAudit = errors.New("检索审计落库失败")
)

// knowledgeSource 是一条 knowledge_sources 声明装配出来的委托入口。
type knowledgeSource struct {
	name      string
	bases     []string
	retriever knowledge.DelegatedRetriever
	budget    time.Duration
	// err 非空 = 这个源装配不起来。检索命中它时指名报错，而不是静默跳过：
	// 「配了却从来没生效」是知识源这一侧最难查的故障形态。
	err string
}

// knowledgeRuntime 是一份配置修订对应的知识源装配态，挂在 policyRuntime 上
// （与 procRuntime 同一生命周期：范围链变了，可准入的库也就变了）。
type knowledgeRuntime struct {
	rt      *policyRuntime
	sources []*knowledgeSource
	// byKB 是知识库 → 源。配置层已保证一个库只属于一个源（procconf.go 的重复声明检查），
	// 所以这里是一一映射；一对多会让引用与审计分不清来源。
	byKB map[string]*knowledgeSource
}

// buildKnowledgeRuntime 按当前配置装配委托入口。
//
// 返回 nil 表示「这个修订版没有知识源声明」—— 那是最常见形态，不是错误。
func (s *Server) buildKnowledgeRuntime(cfg *config.Config, rt *policyRuntime) *knowledgeRuntime {
	if cfg == nil || len(cfg.KnowledgeSources) == 0 {
		return nil
	}
	kr := &knowledgeRuntime{rt: rt, byKB: map[string]*knowledgeSource{}}
	tr, trErr := s.Transports().Get("")
	for i := range cfg.KnowledgeSources {
		d := &cfg.KnowledgeSources[i]
		src := &knowledgeSource{name: strings.TrimSpace(d.Name), budget: kbBudgetOf(d.TimeoutMs)}
		for _, raw := range d.KnowledgeBases {
			if kb := strings.TrimSpace(raw); kb != "" {
				src.bases = append(src.bases, kb)
			}
		}
		sort.Strings(src.bases)
		switch {
		case trErr != nil:
			// 「没有受出网策略管的出口」比「端点写错了」更根本，原因写在这里而不是留到
			// 第一次检索才发现。
			src.err = fmt.Sprintf("出网 transport 不可用: %v（本网关禁止回落默认 transport）", trErr)
		default:
			r, err := knowledge.NewHTTPRetriever(d.Endpoint, knowledge.TransportDo(tr, src.budget))
			if err != nil {
				src.err = "委托客户端装配失败: " + err.Error()
			} else {
				r.MaxResponseBytes = d.MaxResponseBytes
				r.FallbackBudget = src.budget
				// 名字落在 AuditEvent.Retriever 上：审计里区分多个委托入口靠的就是它，
				// 而端点地址不进审计也不进用户面回话。
				r.Name = src.name
				src.retriever = r
			}
		}
		for _, kb := range src.bases {
			kr.byKB[kb] = src
		}
		kr.sources = append(kr.sources, src)
	}
	return kr
}

// kbBudgetOf 把毫秒配置换成预算。非正值取默认：加载期已经要求 timeout_ms 为正，
// 走到这里只可能是未经 normalize 的零值 Config（测试与内部构造），那不该变成「没有超时」。
func kbBudgetOf(timeoutMs int) time.Duration {
	if timeoutMs <= 0 {
		return knowledge.DefaultBudget
	}
	return time.Duration(timeoutMs) * time.Millisecond
}

// declared 返回声明过的知识库（排序去重）—— 候选集的唯一来源。
func (kr *knowledgeRuntime) declared() []string {
	if kr == nil {
		return nil
	}
	out := make([]string, 0, len(kr.byKB))
	for kb := range kr.byKB {
		out = append(out, kb)
	}
	sort.Strings(out)
	return out
}

// sourceOf 返回服务某个库的源名（没有则空串）。
func (kr *knowledgeRuntime) sourceOf(kb string) string {
	if kr == nil {
		return ""
	}
	if src, ok := kr.byKB[kb]; ok {
		return src.name
	}
	return ""
}

// knowledgeCall 是一次自助检索的判定现场：范围链、身份、生效策略版本与判定内核。
type knowledgeCall struct {
	kr        *knowledgeRuntime
	res       *policy.Resolver
	scope     policy.ScopeRef
	subject   string
	chain     policy.ScopeChain
	ctx       policy.PolicyContext
	version   string
	maxLevel  policy.DataLevel
	requestID string
	now       time.Time
}

// knowledgeFor 装配判定现场。四类失败都返回错误而不是「换一个看起来能用的键」：
// legacy、没有源、本范围没有生效包、身份不合法 —— 各自有明确的回话口径。
func (s *Server) knowledgeFor(bucket policy.ScopeRef, requestID string, now time.Time) (*knowledgeCall, error) {
	rt := s.policyFor(s.cfgStore.Current())
	if rt == nil {
		return nil, errKnowledgeNoPolicy
	}
	if rt.kb == nil {
		return nil, errKnowledgeNoSource
	}
	chain, err := policyChainFor(bucket.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errKnowledgeNoIdentity, err)
	}
	id, err := policyIdentity(bucket.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errKnowledgeNoIdentity, err)
	}
	res, version, err := rt.resolverFor(chain)
	if err != nil {
		return nil, errKnowledgeNoBundle
	}
	ctx, err := policy.NewPolicyContext(id, kbPurpose, rt.dataLevel)
	if err != nil {
		return nil, fmt.Errorf("%w: 策略上下文不合法: %v", errKnowledgeNoIdentity, err)
	}
	ctx.PolicyVersion = version
	return &knowledgeCall{
		kr:        rt.kb,
		res:       res,
		scope:     bucket,
		subject:   bucket.ID,
		chain:     chain,
		ctx:       ctx,
		version:   version,
		maxLevel:  rt.dataLevel,
		requestID: requestID,
		now:       now,
	}, nil
}

// admit 算候选库的准入结论。want 为空 = 「全部声明过的库」。
//
// notDeclared 是接线事实（这个库没有委托入口），不是策略结论，所以它不进审计的
// 原因码集合，只回给调用方解释「为什么它压根不在列表里」。
func (kc *knowledgeCall) admit(want []string) (allowed []string, denials []knowledge.KnowledgeBaseDenial, notDeclared []string, err error) {
	declared := kc.kr.declared()
	candidates := declared
	if len(want) > 0 {
		set := map[string]bool{}
		requested := make([]string, 0, len(want))
		for _, raw := range want {
			if kb := strings.TrimSpace(raw); kb != "" {
				set[kb] = true
				requested = append(requested, kb)
			}
		}
		candidates = nil
		for _, kb := range declared {
			if set[kb] {
				candidates = append(candidates, kb)
			}
		}
		for _, kb := range kbSortedUnique(requested) {
			if _, ok := kc.kr.byKB[kb]; !ok {
				notDeclared = append(notDeclared, kb)
			}
		}
	}
	if len(candidates) == 0 {
		return nil, nil, notDeclared, nil
	}
	allowed, denials, err = knowledge.AdmitKnowledgeBases(kc.res, kc.ctx, kc.chain, candidates, kc.now)
	return allowed, denials, notDeclared, err
}

// kbFailure 是一个源这一侧的失败结论（回话与审计都只认原因码 + 稳定短语）。
type kbFailure struct {
	Source         string   `json:"source"`
	KnowledgeBases []string `json:"knowledge_bases"`
	Reason         string   `json:"reason_code"`
	Detail         string   `json:"detail,omitempty"`
}

// kbOutcome 是一次检索的汇总（跨源合并后的结果）。
type kbOutcome struct {
	Citations      []knowledge.Citation
	KnowledgeLevel policy.DataLevel
	Truncated      bool
	// Queried 是被问到的源数（含装配失败的那些），Failures 与之相等就是「全挂了」。
	Queried  int
	Failures []kbFailure
}

// allFailed 报告是否「凡是该问的都问失败了」—— 这是 502 与 200 空结果的分界。
func (o *kbOutcome) allFailed() bool {
	return o != nil && o.Queried > 0 && len(o.Failures) == o.Queried
}

// kbSearchSink 落一条源级审计。target 用源名（AuditEvent.Retriever 同值），
// 因为一次检索可能涉及多个入口，「哪一家」必须在范围键之外单独可查。
type kbSearchSink func(ev knowledge.AuditEvent, target string) error

// kbFailureMetric 把一个**注册过**的原因码抄给指标（§3.I 的检索失败维度）。
//
// 未注册的码不建标签：那种值在审计写入侧就会被 knowledge 包拒掉，指标再给它一条
// 序列等于为一个还没定型的归因建历史基线。
func kbFailureMetric(m *runtimeMetrics, source string, reason knowledge.Reason) {
	if !reason.Valid() {
		return
	}
	m.noteKnowledgeFailure(source, string(reason))
}

// kbSearch 对每个被准入的源发一次委托，逐源留审计。
//
// 总预算取各源预算之和并以 MaxBudget 为顶，每个源再按「此刻还剩多少」收窄截止时间：
// 只允许收窄不允许放宽（WithDeadline 的既有约定），否则一个慢源会替整条链路续期。
func (s *Server) kbSearch(ctx context.Context, kc *knowledgeCall, allowed []string,
	terms string, maxResults int, sink kbSearchSink) (*kbOutcome, error) {

	out := &kbOutcome{Citations: []knowledge.Citation{}, KnowledgeLevel: policy.LevelPublic}
	grouped := map[*knowledgeSource][]string{}
	for _, kb := range allowed {
		if src, ok := kc.kr.byKB[kb]; ok {
			grouped[src] = append(grouped[src], kb)
		}
	}
	total := time.Duration(0)
	for _, src := range kc.kr.sources {
		if len(grouped[src]) > 0 {
			total += src.budget
		}
	}
	if total <= 0 {
		return out, nil
	}
	if total > knowledge.MaxBudget {
		total = knowledge.MaxBudget
	}
	deadline := kc.now.Add(total)

	base, err := knowledge.NewRequestContext(kc.requestID, kc.subject, kc.chain, kbPurpose, kc.maxLevel, kc.version, kc.now)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errKnowledgeNoIdentity, err)
	}
	base, err = base.WithMaxResults(maxResults)
	if err != nil {
		return nil, fmt.Errorf("结果数上限不合法: %v", err)
	}
	q := knowledge.Query{Terms: terms}

	// 按声明顺序发请求：同一份输入两次运行的顺序必须一致，否则回话与审计没法逐位比对。
	for _, src := range kc.kr.sources {
		kbs := grouped[src]
		if len(kbs) == 0 {
			continue
		}
		out.Queried++
		// §3.I 指标：被问到就算一次，不看后面成不成。分子分母都齐了才谈得上失败率，
		// 而「装配阶段就失败」的那些源正是要在指标里露出来的部分。
		s.metrics.noteKnowledgeQuery(src.name)
		// gatewayFailure 是「失败在网关这一侧、委托压根没发出去」这一类结论的统一落法：
		// 先留一条最小审计，再记失败。少了前半段，「这个源从来没生效」与「没人查过」在
		// 审计上就同形了 —— 而边界 5 要求凡被问到的源都恰好留下一条痕。
		gatewayFailure := func(reason knowledge.Reason, detail string) error {
			if err := sink(minKBAudit(kc, kbs, q, reason, detail), src.name); err != nil {
				return err
			}
			kbFailureMetric(s.metrics, src.name, reason)
			out.Failures = append(out.Failures, kbFailure{src.name, kbs, string(reason), detail})
			return nil
		}
		scope, err := knowledge.NewKnowledgeScope(kc.chain, kc.maxLevel, kbs)
		if err != nil {
			if gerr := gatewayFailure(knowledge.ReasonProtocolInvalid, "知识范围不合法: "+err.Error()); gerr != nil {
				return nil, gerr
			}
			continue
		}
		rc, err := base.WithDeadline(deadline, time.Now().UTC())
		if err != nil {
			if gerr := gatewayFailure(knowledge.ReasonContextExpired, "剩余预算已用尽: "+err.Error()); gerr != nil {
				return nil, gerr
			}
			continue
		}
		if src.retriever == nil {
			if gerr := gatewayFailure(knowledge.ReasonTransportNotConfigured, src.err); gerr != nil {
				return nil, gerr
			}
			continue
		}
		outcome, rerr := knowledge.Resolve(ctx, src.retriever, rc, scope, q, time.Now())
		if outcome == nil {
			// Resolve 的前置校验失败（上下文/范围/检索器）不产出事件，同样走最小留痕。
			if gerr := gatewayFailure(knowledge.ReasonUnavailable, errText(rerr)); gerr != nil {
				return nil, gerr
			}
			continue
		}
		if err := sink(outcome.Audit, src.name); err != nil {
			return nil, err
		}
		// §3.I 指标：耗时/命中/截断一律取审计事件里的源侧事实，不在接线侧另算一份
		// （自己掐表会得到「含落库的耗时」，那与源侧响应慢不是一回事）。
		s.metrics.observeKnowledgeResult(outcome.Audit.DurationMS, outcome.Audit.HitCount, outcome.Audit.Truncated)
		if outcome.Failure != nil {
			// Citations 必空（C 包不变量），这里也不做「留一点算一点」的补偿。
			kbFailureMetric(s.metrics, src.name, outcome.Failure.Reason)
			out.Failures = append(out.Failures, kbFailure{src.name, kbs, string(outcome.Failure.Reason), outcome.Audit.FailureDetail})
			continue
		}
		out.Citations = append(out.Citations, outcome.Citations...)
		if outcome.Truncated {
			out.Truncated = true
		}
		if outcome.KnowledgeLevel.Exceeds(out.KnowledgeLevel) {
			out.KnowledgeLevel = outcome.KnowledgeLevel
		}
	}

	knowledge.SortCitations(out.Citations)
	// 全局截断只影响回话：各源审计里的 hit_count 保持源侧事实，不被合并口径改写。
	if len(out.Citations) > maxResults {
		out.Citations = out.Citations[:maxResults]
		out.Truncated = true
	}
	return out, nil
}

// minKBAudit 给「Resolve 连事件都没产出」的路径造一条最小留痕。
//
// 只填能确定属实的东西（请求号、范围链、原因码、查询摘要、版本），不假造分级与耗时 ——
// 那些字段一旦被编出来，事后统计就会把「装配失败」算成「一次真实的零命中检索」。
func minKBAudit(kc *knowledgeCall, kbs []string, q knowledge.Query, reason knowledge.Reason, detail string) knowledge.AuditEvent {
	return knowledge.AuditEvent{
		RequestID:           kc.requestID,
		Subject:             kc.subject,
		Chain:               append(policy.ScopeChain(nil), kc.chain...),
		Purpose:             kbPurpose,
		AllowedBases:        append([]string(nil), kbs...),
		QueryDigest:         q.Digest(),
		MaxDataLevel:        kc.maxLevel.String(),
		RequestMaxDataLevel: kc.maxLevel.String(),
		ResultCode:          reason,
		FailureDetail:       detail,
		PolicyVersion:       kc.version,
		// Retriever 留空：这次委托根本没发出去，填任何实现名都是替知识源编造事实。
		// 「失败在网关这一侧」由 sink 的 target（源名）+ 原因码
		// retrieval_transport_not_configured / retrieval_dependency_unavailable 一起说明。
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func kbSortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// handleMeKnowledge 处理 /v1/_me/knowledge 与 /v1/_me/knowledge/search。
func (s *Server) handleMeKnowledge(w http.ResponseWriter, r *http.Request, e *userEntry, scope policy.ScopeRef, sub string) {
	switch sub {
	case "":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET")
			return
		}
		s.knowledgeList(w, e, scope)
	case "search":
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 POST")
			return
		}
		s.knowledgeSearch(w, r, e, scope)
	default:
		writeJSONError(w, http.StatusNotFound, "invalid_request_error",
			"可用路径：/v1/_me/knowledge、/v1/_me/knowledge/search")
	}
}

// knowledgeDenialRow 是拒绝明细的回话形态：库、源、策略原因码。
type knowledgeDenialRow struct {
	KnowledgeBase string `json:"knowledge_base"`
	Source        string `json:"source"`
	Reason        string `json:"reason"`
}

func kbDenialRows(kr *knowledgeRuntime, denials []knowledge.KnowledgeBaseDenial) []knowledgeDenialRow {
	rows := make([]knowledgeDenialRow, 0, len(denials))
	for _, d := range denials {
		rows = append(rows, knowledgeDenialRow{d.KnowledgeBase, kr.sourceOf(d.KnowledgeBase), string(d.Reason)})
	}
	return rows
}

// knowledgeList 回答「我这些库到底被授权了没有，以及问哪个入口」。
//
// 只读、无副作用，因此不落审计（与 /v1/_me/routing 同一口径：看判定结论不是访问内容）。
// 端点地址刻意不出现 —— 用户要的是「能不能问」，委托入口的网络位置属于运维面。
func (s *Server) knowledgeList(w http.ResponseWriter, e *userEntry, scope policy.ScopeRef) {
	kc, err := s.knowledgeFor(scope, newRequestID(), time.Now())
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	allowed, denials, _, err := kc.admit(nil)
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, kb := range allowed {
		allowedSet[kb] = true
	}
	reasonOf := map[string]string{}
	for _, d := range denials {
		reasonOf[d.KnowledgeBase] = string(d.Reason)
	}

	bases := make([]map[string]any, 0, len(allowed)+len(denials))
	for _, kb := range kc.kr.declared() {
		row := map[string]any{
			"knowledge_base": kb,
			"source":         kc.kr.sourceOf(kb),
			"allowed":        allowedSet[kb],
		}
		if !allowedSet[kb] {
			row["reason"] = reasonOf[kb]
		}
		bases = append(bases, row)
	}
	sources := make([]map[string]any, 0, len(kc.kr.sources))
	for _, src := range kc.kr.sources {
		status := "ready"
		if src.retriever == nil {
			status = "unavailable"
		}
		item := map[string]any{
			"name":            src.name,
			"status":          status,
			"knowledge_bases": src.bases,
			"budget_ms":       src.budget.Milliseconds(),
		}
		if src.err != "" {
			item["error"] = src.err
		}
		sources = append(sources, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"policy_version":  kc.version,
		"max_data_level":  kc.maxLevel.String(),
		"knowledge_bases": bases,
		"sources":         sources,
		"note":            "准入只由策略内核算（资源 knowledge:<库> + 动作 read）；单篇文档的可读性由知识源自己判",
	})
}

// knowledgeSearch 是一次带策略准入的委托检索。
func (s *Server) knowledgeSearch(w http.ResponseWriter, r *http.Request, e *userEntry, scope policy.ScopeRef) {
	var body struct {
		Query          string   `json:"query"`
		KnowledgeBases []string `json:"knowledge_bases"`
		// 指针而不是 int：省略 = 用默认值，显式给 0 或负数 = 入参错。
		// 用 int 就分不清这两件事，「客户端以为自己限了 0 条」会被当成「没限」而放行默认条数。
		MaxResults *int `json:"max_results"`
	}
	// 严格解码：多余的键直接拒。客户端递 allow_raw_terms 是越权尝试，必须被指认，
	// 而不是「忽略未知字段」把它咽下去。
	if err := readJSONBodyStrict(w, r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	terms := strings.TrimSpace(body.Query)
	if terms == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"query 不能为空（检索词参与委托与审计摘要，空值没有可判定对象）")
		return
	}
	if len(terms) > kbMaxQueryBytes {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			fmt.Sprintf("query 过长（上限 %d 字节）", kbMaxQueryBytes))
		return
	}
	maxResults := knowledge.DefaultMaxResults
	if body.MaxResults != nil {
		maxResults = *body.MaxResults
	}
	if maxResults < 1 || maxResults > knowledge.MaxResultsCeiling {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			fmt.Sprintf("max_results 必须在 1..%d（当前 %d）", knowledge.MaxResultsCeiling, maxResults))
		return
	}

	kc, err := s.knowledgeFor(scope, newRequestID(), time.Now())
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	allowed, denials, notDeclared, err := kc.admit(body.KnowledgeBases)
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	q := knowledge.Query{Terms: terms}
	payload := map[string]any{
		"request_id":                 kc.requestID,
		"policy_version":             kc.version,
		"max_data_level":             kc.maxLevel.String(),
		"denied_knowledge_bases":     kbDenialRows(kc.kr, denials),
		"undeclared_knowledge_bases": notDeclared,
		"citations":                  []knowledge.Citation{},
		"failures":                   []kbFailure{},
		"note":                       "引用只含摘要与 source_id：正文与标题请凭它回源知识源取，由源侧再判一次权限（网关不留副本）",
	}

	if len(allowed) == 0 {
		// 一次委托都不发。这仍然要留痕：「有人试过并且被全量拒绝」是权限大盘要的事实，
		// 只在回话里出现就等于审计上「没人查过」。
		s.kbAuditDenied(kc, scope, e.Name, q, denials)
		payload["knowledge_level"] = policy.LevelPublic.String()
		payload["hit_count"] = 0
		writeJSON(w, http.StatusOK, payload)
		return
	}

	res, err := s.kbSearch(r.Context(), kc, allowed, terms, maxResults, s.kbAuditSink(e.Name, scope))
	if err != nil {
		writeKnowledgeError(w, err)
		return
	}
	payload["knowledge_level"] = res.KnowledgeLevel.String()
	payload["hit_count"] = len(res.Citations)
	payload["citations"] = res.Citations
	payload["failures"] = res.Failures
	if res.Truncated {
		payload["truncated"] = true
	}
	if res.allFailed() {
		// 全失败不能伪装成「库里没有」：调用方需要知道这次没有拿到任何判定依据。
		payload["error"] = map[string]any{
			"type":    "knowledge_unavailable",
			"message": "所有被准入的知识源都失败了，本次没有任何可读结果",
		}
		writeJSON(w, http.StatusBadGateway, payload)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

// kbAuditSink 把每个源的 AuditEvent 落到本次请求的归属范围。
func (s *Server) kbAuditSink(actor string, scope policy.ScopeRef) kbSearchSink {
	return func(ev knowledge.AuditEvent, target string) error {
		detail, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("%w: 审计事件序列化失败: %v", errKnowledgeAudit, err)
		}
		if err := s.db.AuditScope(scope, actor, kbAuditAction, target, string(detail)); err != nil {
			// 原始错误只进日志：存储层报错可能带上 SQL 参数，那里头一次出现的是摘要而不是内容，
			// 但回话里连摘要都不该有。
			s.log.Errorf("知识检索审计落库失败（request_id=%s, source=%s）: %v", ev.RequestID, target, err)
			return fmt.Errorf("%w: %v", errKnowledgeAudit, err)
		}
		// 日志走事件自带的单行形态（只含标识与计数，序列化点还兜一次 PII）。
		s.log.Debugf("event=knowledge_search %s", ev.String())
		return nil
	}
}

// kbAuditDenied 给「全部候选都被拒、一次委托都没发」的检索留痕。
//
// 这条路径没有 knowledge.AuditEvent（没调 Resolve），所以 detail 由接线自己拼，
// 字段集合照 §2.9 规则 6 收窄到「ID / 类型 / 范围 / 哈希 / 策略版本」。
func (s *Server) kbAuditDenied(kc *knowledgeCall, scope policy.ScopeRef, actor string,
	q knowledge.Query, denials []knowledge.KnowledgeBaseDenial) {

	detail, err := json.Marshal(map[string]any{
		"request_id":     kc.requestID,
		"purpose":        kbPurpose,
		"chain":          kc.chain,
		"query_digest":   q.Digest(),
		"result_code":    knowledge.ReasonNoKnowledgeAllow,
		"policy_version": kc.version,
		"max_data_level": kc.maxLevel.String(),
		"denied":         kbDenialRows(kc.kr, denials),
		"delegation":     "not_sent",
	})
	if err != nil {
		s.log.Errorf("知识检索拒绝留痕序列化失败（request_id=%s）: %v", kc.requestID, err)
		return
	}
	if err := s.db.AuditScope(scope, actor, kbAuditAction, "-", string(detail)); err != nil {
		s.log.Errorf("知识检索拒绝留痕落库失败（request_id=%s）: %v", kc.requestID, err)
	}
}

// writeKnowledgeError 把接线层的错误映射成回话。
func writeKnowledgeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errKnowledgeNoPolicy), errors.Is(err, errKnowledgeNoSource):
		writeJSONError(w, http.StatusNotImplemented, "not_configured", err.Error())
	case errors.Is(err, errKnowledgeNoBundle), errors.Is(err, errKnowledgeNoIdentity):
		writeJSONError(w, http.StatusForbidden, "no_entitlement", err.Error())
	case errors.Is(err, errKnowledgeAudit):
		writeJSONError(w, http.StatusInternalServerError, "audit_write_failed",
			"检索审计落库失败，本次结果不予交付（留不下痕的检索等于绕过审计）")
	default:
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
	}
}
