package server

// 本文件是决策包 §8.1「正文通道」的接线半段：把 E 包那个消费者侧窄接口
// （processor.KnowledgeContentDeliverer）落到 internal/knowledge 的委托协议上。
//
// E 包刻意不 import C 包 —— 它只说「给我几篇带标识与分级的正文」。怎么问、问谁、
// 拿到之后留什么痕，全部在这一层，因为这一层才知道请求路径上的那些东西：
// 出网 transport、范围链、生效策略包、审计库、指标。
//
// 四条线（与 knowledge30.go 的文件头同口径，这里是正文方向的那一份）：
//
//  1. **三道锁缺一不可**。平台开关（return_raw_body + 独立 delivery_endpoint，
//     见 buildKnowledgeRuntime）决定「哪些源参与」；管理员授权（knowledge.content
//     与 body.raw，E 侧已判，这里对**出网动作**再判一次）决定「这次能不能带内容」；
//     源侧逐篇再判定（DeliverContents 的 RuleID 与摘要双重锚定）决定「这一篇给不给」。
//     本层不替任何一道松口，也不写「前两过了就当第三道也过」的推断。
//  2. **授权判定只有 A 一个真值源，但每个出网点自己问一遍**。E 在构造 Output 之前判过
//     knowledge.content / body.raw；这里在把原文检索词写进委托请求之前又判一次 body.raw。
//     两次判定用的是同一个 Resolver、同一个上下文，所以不会出现两个结论；
//     少任何一次都是「某一处出网没人问过授权」，那正是锁定口径要防的形态。
//  3. **失败不产出部分结果**。任何一个源的交付失败 = 整次取正文失败（返回 error，
//     已收进内存的正文字节就地清零），由声明里的 fail_closed 决定这次请求是拒还是
//     原样放行 —— 绝不「拿到几篇算几篇」。
//  4. **审计写不进去就不交付**。真有正文进过网关内存（delivered_count > 0）、交付失败、
//     或**网关侧兜底丢过篇目**这三种形态必须落库；落不进去就清零并报错，
//     正文一个字都不会进 prompt。
//     只有「零交付、零失败、零丢弃」不写行：那意味着源侧对这批准入的篇目回答
//     「都没有可交付正文」，而注入发生在**每一条**请求上，把这种缺省回答逐条抄一遍
//     等于把审计表养成第二张流量表（同 traceRawBodyGrant30 的取舍）。
//     那一次的证据在处理器留痕里（event=processor 的 entries 段带结论码
//     knowledge_no_content / knowledge_grant_missing）。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/mynet-club/net-tools/llmproxy/internal/knowledge"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/processor"
)

// kbContentAuditAction 是正文交付在审计表里的动作名，与检索的 knowledge.search 分开：
// 「问到过」与「原文真的进过网关」是两条完全不同的合规事实，合成一行就没法单独统计。
const kbContentAuditAction = "knowledge.content"

var (
	// errKbContentNoSource：开关没打开 —— 声明写着要注入正文，而没有任何源允许交付。
	errKbContentNoSource = errors.New("没有开启正文交付的知识源（knowledge_sources[].return_raw_body）")
	// errKbContentNoUser：范围链里没有 user 范围。委托协议要求链含主体自身，
	// 审计也必须有「这次关于谁」的归属位，两者都落不下去就只能失败。
	errKbContentNoUser = errors.New("范围链里没有 user 范围，正文交付无法归属")
	// errKbContentTermsDenied：原文检索词的授权在这一刻不成立。
	errKbContentTermsDenied = errors.New("检索词原文出网未获授权")
	// errKbContentFailed：源侧交付失败（依赖故障或协议不符），已收字节已清零。
	errKbContentFailed = errors.New("知识正文交付失败")
)

// kbContentDeliverer 是 processor.KnowledgeContentDeliverer 的接线实现。
//
// 它不持有任何请求态（源清单与端点都来自这一版配置的装配结果，判定现场每次现算），
// 所以同一实例可被并发复用 —— E 侧那条「实现必须可并发复用」的约定在这里兑现。
type kbContentDeliverer struct {
	s  *Server
	rt *policyRuntime
}

// contentSources 返回参与正文交付的源（开了开关且委托客户端装配成功）。
//
// 顺序就是配置里的声明顺序：交付预算按这个顺序逐源发放，
// 换一套顺序就会让「哪几篇进了 prompt」随源声明顺序变化，回放对不上。
func (d *kbContentDeliverer) contentSources() []*knowledgeSource {
	if d == nil || d.rt == nil || d.rt.kb == nil {
		return nil
	}
	var out []*knowledgeSource
	for _, src := range d.rt.kb.sources {
		// deliverer 与 contentEndpoint 在装配期同时挂上（buildKnowledgeRuntime），所以这里
		// 查 deliverer 就是查「这个源真的被允许交付正文」；retriever 也一起查，因为
		// 注入要先问一次检索才有余下的申请依据。
		if src == nil || src.retriever == nil || src.deliverer == nil {
			continue
		}
		out = append(out, src)
	}
	return out
}

// KnowledgeContentEndpoints 枚举本条通道的全部出网目标：每个参与源的**检索**入口
// 与**交付**入口都在列内。
//
// 检索入口也算进来不是凑数：注入要先问一次检索才拿到「源侧本次判过可读」的那几篇，
// 那一发同样是出网。声明的 allowed_endpoints 因此必须覆盖两条，
// E 的白名单校验才有完整对象 —— 否则「白名单只管交付端点」会变成检索那条旁路。
func (d *kbContentDeliverer) KnowledgeContentEndpoints() []string {
	var out []string
	for _, src := range d.contentSources() {
		for _, ep := range []string{src.endpoint, src.contentEndpoint} {
			if ep != "" {
				out = append(out, ep)
			}
		}
	}
	sort.Strings(out)
	return out
}

// FetchKnowledgeContent 取一次正文：准入 → 检索（原文检索词）→ 逐源交付 → 逐源留痕。
//
// 空 Passages + nil error 表示「没有可交付正文」，不是失败；
// 任何失败都以 error 返回，由 E 按 fail_closed 处置。
func (d *kbContentDeliverer) FetchKnowledgeContent(ctx context.Context,
	req processor.KnowledgeContentRequest) (processor.KnowledgeContentResult, error) {

	empty := processor.KnowledgeContentResult{}
	srcs := d.contentSources()
	if len(srcs) == 0 {
		return empty, fmt.Errorf("%w: %v", errKbContentFailed, errKbContentNoSource)
	}
	user, ok := kbContentUserScope(req.Chain)
	if !ok {
		return empty, fmt.Errorf("%w: %v", errKbContentFailed, errKbContentNoUser)
	}
	res, version, err := d.rt.resolverFor(req.Chain)
	if err != nil {
		// 这条链上没有生效的策略包：没有任何管理员授权过任何库，一次委托都不该发。
		// 复用检索口那个哨兵（errKnowledgeNoBundle 的语义在这里逐字成立），
		// 不另造一个同义词 —— 两个错误指向同一个原因时，排查者只会多花一次工夫。
		return empty, fmt.Errorf("%w: %v", errKbContentFailed, errKnowledgeNoBundle)
	}
	identity, err := policyIdentity(user.ID)
	if err != nil {
		return empty, fmt.Errorf("%w: %v", errKbContentNoUser, err)
	}
	// 知识库**准入**沿用检索口的 purpose（knowledge-search）：管理员为「哪个库能碰」
	// 写的那条规则不该因为触发方是模型请求还是自助检索而给出不同答案。
	// 而 knowledge.content / body.raw 两道授权用的是这次请求自己的上下文
	// （req.Policy），因为那两问的正是「这一次模型调用能不能带内容」。
	kbCtx, err := policy.NewPolicyContext(identity, kbPurpose, d.rt.dataLevel)
	if err != nil {
		return empty, fmt.Errorf("%w: 策略上下文不合法: %v", errKbContentNoUser, err)
	}
	kbCtx.PolicyVersion = version
	kc := &knowledgeCall{
		kr: d.rt.kb, res: res, scope: user, subject: user.ID, chain: req.Chain,
		ctx: kbCtx, version: version, maxLevel: d.rt.dataLevel,
		requestID: req.RequestID, now: req.Now,
	}

	want := make([]string, 0, len(srcs)*2)
	for _, src := range srcs {
		want = append(want, src.bases...)
	}
	allowed, _, _, err := kc.admit(want)
	if err != nil {
		return empty, fmt.Errorf("%w: 知识库准入判定失败: %v", errKbContentFailed, err)
	}
	if len(allowed) == 0 {
		// 一个库都没被准入：一次委托都不发，也就没有任何内容进过网关。
		// 这里不写 knowledge.search 的拒绝行（自助检索口写那条是因为它是用户主动动作）：
		// 注入在每条请求上都会走到这一步，逐条写「没权限」会把审计表变成流量表。
		return empty, nil
	}

	// 出网点自查：委托请求会带上原文检索词（协议只有 allow_raw_terms 一个位，
	// 不存在「送脱敏检索词」这种形态），所以这一发必须自己有授权依据。
	granted, termsReason := res.AllowsRawBody(req.Policy, req.Chain, req.Now)
	if !granted {
		return empty, fmt.Errorf("%w: %v（判定依据 %s）", errKbContentFailed, errKbContentTermsDenied, termsReason)
	}

	scope := requestAuditScope30(user.ID)
	// 检索这一步的审计走的是既有的 knowledge.search sink：每个被问到的源都恰好留一条痕，
	// 与自助检索口同一形状（正文通道不另开一份检索留痕，也不省掉那一条）。
	// 返回的 kbOutcome 这里用不上 —— 引用已经化成 hits 里的篇目，回话不是本层的产物。
	_, hits, err := d.s.kbSearchRun(ctx, kc, allowed,
		knowledge.Query{Terms: req.Terms, AllowRawTerms: true},
		kbContentMaxResults(req.MaxPassages),
		d.s.kbAuditSink(user.ID, scope))
	if err != nil {
		return empty, fmt.Errorf("%w: 检索委托失败: %v", errKbContentFailed, err)
	}
	if len(hits) == 0 {
		// 问到了但没有任何一篇是「源侧本次判过可读且未过期」的：没有依据可申请正文。
		return empty, nil
	}

	passages := make([]processor.KnowledgeContentPassage, 0, len(hits))
	usedBytes := 0
	// 失败或审计写不进去时把已经收进内存的正文全部清零：函数返回之后不该有任何一份
	// 原文留在调用方拿不到的地方等着 GC（§2.9 规则 2）。
	defer func() {
		if err != nil {
			for i := range passages {
				p := &passages[i]
				for j := range p.Verbatim {
					p.Verbatim[j] = 0
				}
				p.Verbatim = nil
			}
			passages = nil
		}
	}()

	for _, hit := range hits {
		passagesLeft := req.MaxPassages - len(passages)
		bytesLeft := req.MaxTotalBytes - usedBytes
		if passagesLeft <= 0 || bytesLeft <= 0 {
			// 预算用尽。必须在这里停而不是把 0 交给 C：那边的 clampInt 把
			// 「0 或越界」读成「回落到保守缺省」，传 0 会变成「再给 8 篇」。
			break
		}
		content, derr := knowledge.DeliverContents(ctx, hit.source.deliverer, hit.rc, hit.scope,
			hit.docs, passagesLeft, bytesLeft, req.Now)
		// 三种必写形态：真有正文进过网关内存、这一源交付失败、C 侧兜底丢过篇目。
		// 第三种必须写：那正是「问到过内容但一个字都没进 prompt」的唯一留痕处，
		// 少了它，摘要不符这类协议不符事件在审计表里和「压根没有内容」长得一样。
		if content != nil && (content.HasContent() || content.Failure != nil || len(content.Dropped) > 0) {
			if aerr := d.s.kbContentAudit(user.ID, scope, content.Audit, hit.source.name); aerr != nil {
				err = aerr
				return empty, aerr
			}
		}
		if derr != nil {
			if content != nil && content.Failure != nil {
				kbFailureMetric(d.s.metrics, hit.source.name, content.Failure.Reason)
			}
			err = fmt.Errorf("%w: %s: %v", errKbContentFailed, hit.source.name, errText(derr))
			return empty, err
		}
		for i := range content.Passages {
			p := content.Passages[i]
			// Verbatim 的切片头直接交给 E：字节归属随之转移，E 渲染完就地清零。
			// 这里不复制一份 —— 复制会让同一份原文在堆上多活一份，而规则 2 要的是
			// 「用完立刻只有一份都没有」。
			passages = append(passages, processor.KnowledgeContentPassage{
				SourceID: p.SourceID, KnowledgeBase: p.KnowledgeBase, Digest: p.Digest,
				DataLevel: p.Level(), RuleID: p.RuleID, ExpiresAt: p.ExpiresAt, Verbatim: p.Verbatim,
			})
		}
		usedBytes += content.TotalBytes
	}
	return processor.KnowledgeContentResult{Passages: passages}, nil
}

// kbContentUserScope 取范围链里的 user 范围（正文交付的归属位）。
func kbContentUserScope(chain policy.ScopeChain) (policy.ScopeRef, bool) {
	for _, ref := range chain {
		if ref.Kind == policy.ScopeUser && ref.ID != "" {
			return ref, true
		}
	}
	return policy.ScopeRef{}, false
}

// kbContentMaxResults 把「要几篇正文」当成检索条数上限。
//
// 不同额：检索 20 篇只要 8 篇正文，多问的那 12 篇引用会进审计与内存却没有任何用途，
// 而检索词面积也按那个上限放大过。两个数同额才是「只为索取正文而问」的最小形态。
func kbContentMaxResults(maxPassages int) int {
	if maxPassages < 1 {
		return knowledge.DefaultMaxResults
	}
	if maxPassages > knowledge.MaxResultsCeiling {
		return knowledge.MaxResultsCeiling
	}
	return maxPassages
}

// kbContentAudit 落一条正文交付审计（按源逐条，target 用源名）。
//
// detail 是 ContentAuditEvent 的序列化形态：C 包在结构上就不放正文与标题明文，
// 序列化点还兜一次 PII。写不进去由调用方当成失败处理（本函数返回 error 而不是只记日志）。
//
// 这里直接调 db.AuditScope 而不走 auditDetail30：那条路径会再 Marshal 一次，
// 而 Marshal(json.RawMessage) 会把 `<`、`>`、`&` 转成 `\u003c` 这样的转义序列 ——
// 审计表里就会存下一份「与 C 包序列化结果不同」的 detail，回放对账时那是一处假差异。
func (s *Server) kbContentAudit(actor string, scope policy.ScopeRef, ev knowledge.ContentAuditEvent, target string) error {
	if s.db == nil {
		return fmt.Errorf("%w: 审计库不可用", errKnowledgeAudit)
	}
	detail, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("%w: 正文交付审计序列化失败: %v", errKnowledgeAudit, err)
	}
	if err := s.db.AuditScope(scope, actor, kbContentAuditAction, target, string(detail)); err != nil {
		// 存储层原始错误只进日志：那里可能带 SQL 参数，而参数里出现的是摘要与计数，
		// 不是内容 —— 但回话里连摘要都不该有。
		s.log.Errorf("知识正文交付审计落库失败（request_id=%s, source=%s）: %v", ev.RequestID, target, err)
		return fmt.Errorf("%w: %v", errKnowledgeAudit, err)
	}
	// 日志走事件自带的单行形态（只含标识与计数，序列化点还兜一次 PII）。
	s.log.Debugf("event=knowledge_content %s", ev.String())
	return nil
}

// 编译期证明接线实现确实是 E 包要的那个接口（改了签名要在这一行炸，而不是到运行期）。
var _ processor.KnowledgeContentDeliverer = (*kbContentDeliverer)(nil)
