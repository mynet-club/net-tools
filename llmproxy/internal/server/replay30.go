package server

// 本文件补上 §2.8 证据链缺的最后一段：**线上真的跑过的判定与选路**如何变成一份
// 可以被另一个进程读回去的记录文件。
//
// 为什么必须在判定现场采集，而不是事后从库里重建：
// requests 表里与回放有关的只有 policy_version / routing_epoch / routing_seed /
// candidates_digest 四列（见 store.RoutingTrace），当时的候选池、计划与逐家排除原因
// 都不在库里。而 internal/replay 的 RoutingRecord 要求「候选池 + 计划 + 排除记录」
// 三者自洽（摘要必须能从候选重算、每个候选要么进计划要么有排除码），光有 seed
// 拼不出那份池子。所以导出只能发生在判定还活着的那一刻。
//
// 为什么是内存窗口而不是新表：
//   - 记录里带 subject（用户名）与成员关系，那是个人信息。落库等于把它复制进
//     retain_days 天才清理的审计库，而 §2.9 要的是「原样留在受控导出通道里」；
//   - 新表要三方言迁移 + 测试矩阵（§2.7），为一个运维诊断动作付这个代价不值；
//   - 有界窗口 + dropped 计数把「采了多少、丢了多少」摊在明面上，比一张没人查的表诚实。
//     重启即失是**已知限制**，写进 /healthz 之外的状态接口响应与 docs/3.0-verification.md。
//
// 三条采集纪律（与 §3.0 的三条线同源）：
//  1. 只在 enforce 采集。影子的判定没有作用到任何请求上，把它记成「一次真实决策」
//     会让回放去复现一次从未发生的授权。
//  2. 只有计划真的驱动了选路（shot.Applied）才写选路记录 —— 与 policy30.go 文件头
//     「seed/epoch/digest 三者成组出现」的落库口径完全一致：半个痕迹比没痕迹更坏。
//     判定记录则相反：策略拒绝（Blocked）也是一次**真的发生过**的结论，必须留证据。
//  3. 记录里只有标识、档位、原因码与时间。导出前 replay.Encode 还会按禁用词表扫一遍
//     JSON 键，采集侧不给自己留「顺手多塞一个字段」的后门。
//
// 抽样按 request_id 的哈希而不是计数器：计数器在多 goroutine 下顺序不定，重启后
// 从哪开始也不定，于是「同一条请求该不该被采到」没有答案；哈希让采样集合可复现，
// 排查时才敢问「为什么这次没记录」。

import (
	"hash/fnv"
	"sync"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/replay"
	"github.com/mynet-club/net-tools/llmproxy/internal/routing"
)

const (
	// replayWindowDefaultCapacity 是窗口默认保留的**请求数**（不是记录数：
	// 一条请求最多一条判定 + 一条选路）。上限的意义是内存有界，不是「够用」。
	replayWindowDefaultCapacity = 512
	replayWindowMaxCapacity     = 4096
	// replayPermilleFull 是千分制的满值。
	replayPermilleFull = 1000
)

// replaySamplingAlgoOnline 声明线上那次抽样用的是哪个随机源，取值来自 D（唯一事实源）：
// internal/routing 的 SeededSource（sha256(seed) → splitmix64 → [0,1) 浮点），
// 抽样发生在档序/目标函数筛完之后的首选池里。
//
// 它必须与 internal/replay 缺省的 replay-sampling-v1（SHA-256 计数器整数流 +
// 不放回全池抽样）**不同名**：两个算法在同一条 seed 下会得出不同的尝试顺序，
// 把它们混成一个标识，回放就会把「首选顺序不同」报成策略差异，
// 或者更糟 —— 让人以为逐位复现了。
//
// 名字以前在这里也写了一份字面量，现在不写了（2026-10-04 裁决第 5 条 B）：
// 「线上抽样与回放重跑是同一条实现」这句话要有证据，而两份字面量互相「碰巧一致」
// 不是证据。D 的 BitExactAlgos() 同时给出回放侧能不能声称逐位。
const replaySamplingAlgoOnline = routing.SamplingAlgoSeededSplitmix64V1

// replayEntry 是一条请求采到的记录对。
//
// 成对存放而不是两张独立切片，是因为选路回放**需要**同 request_id 的判定记录：
// 有它才拿得到范围链，于是策略版本能按 Filter(chain) 复核、计划里每个候选也能
// 重跑一次授权判定（§6「fallback 不绕过权限」）。窗口淘汰时把一对一起丢掉，
// 否则留下的就是一堆「只能降级回放」的孤记录。
//
// key 是这次判定的**请求范围**（结构化 ScopeRef，不是裸用户名字符串 ——
// 2026-10-04 裁决第 7 条 C）：DB 用户是 user:<名字>，静态 key 是 system:global。
// 键型与导出过滤型同形，才谈得上「按范围导」；裸名字那种形态下，组织级过滤
// 连要比什么都比不出来。键只到请求范围为止，组织与项目在 chain 里（下面那条注释）。
type replayEntry struct {
	key      policy.ScopeRef
	decision replay.DecisionRecord
	routing  *replay.RoutingRecord // nil = 这次判定没有驱动选路（策略拒绝、回落 legacy）
}

// replayScopeMatch 报告一个精确范围是否覆盖这条记录。
//
// 两个条件按「或」用，缺一个都不完整：
//   - key 相等 = 「这次判定就是为这个范围做的」（用户流量、网关自己的静态 key 流量）；
//   - chain 命中 = 「这次判定被这个范围参与过」。组织级、项目级策略之所以可能，
//     全靠这一条：请求范围永远是一个人（2.x 的路由作用域就是用户名），
//     而一次判定同时落在 user / organization / project 上（§2.7 的 ScopeChain）。
//     只比 key 的话，「把这次事故涉及的那个组织的全部判定导出来」仍然做不到 ——
//     那正是这条裁决要解的问题。
//
// 只认精确范围、不认通配：通配按字符串相等会一个都匹配不上而静默空采，
// 在证据里比报错更糟（校验在 parseScopeParam 那一层就已经挡住了）。
func replayScopeMatch(filter, key policy.ScopeRef, chain policy.ScopeChain) bool {
	if filter.Is(key) {
		return true
	}
	return chain.Includes(filter)
}

// replayWindow 是有界的采集窗口。开关、千分率与范围过滤都由管理口改，缺省关闭。
//
// 缺省关闭不是怕麻烦：记录里带 subject，采集本身是一次数据聚合。运维要它的时候
// 明确打开、用完导出、再 clear，比长期开着把用户名的分布留在内存里好解释。
type replayWindow struct {
	mu       sync.Mutex
	enabled  bool
	permille int
	// filter 是采集侧的精确范围过滤，零值 = 全部。与导出侧同一个类型、同一条匹配
	// 规则（replayScopeMatch）：两处各写一遍就会「开关只采 alice，导出却能把
	// 整个组织取走」这种对不上的口径留在运维面上。
	filter   policy.ScopeRef
	capacity int

	entries  []replayEntry
	captured int64
	dropped  int64
	failed   int64
}

func newReplayWindow() *replayWindow {
	return &replayWindow{capacity: replayWindowDefaultCapacity}
}

// replaySampleHit 用 request_id 的哈希落进千分桶。
//
// 0 与满值先短路：permille=0 时不该为一条永不采集的请求算哈希，
// 1000 时同理（那是「全采」，不是「按千分率采」）。
func replaySampleHit(requestID string, permille int) bool {
	if permille <= 0 {
		return false
	}
	if permille >= replayPermilleFull {
		return true
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(requestID))
	return h.Sum64()%uint64(replayPermilleFull) < uint64(permille)
}

// shouldCapture 报告这次请求要不要采。纯判定，不留痕迹：计数只在真存下一条时加。
//
// chain 由调用方（判定现场）给，不在这里重算：窗口要回答的是「当时那次判定覆盖哪些范围」，
// 而再问一遍活的策略拿到的已经是现在那份了。
func (w *replayWindow) shouldCapture(key policy.ScopeRef, chain policy.ScopeChain, requestID string) bool {
	if w == nil || requestID == "" {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.enabled {
		return false
	}
	if w.filter != (policy.ScopeRef{}) && !replayScopeMatch(w.filter, key, chain) {
		return false
	}
	return replaySampleHit(requestID, w.permille)
}

// add 存入一条记录对并按容量淘汰最旧的。
func (w *replayWindow) add(e replayEntry) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.entries = append(w.entries, e)
	w.captured++
	capacity := w.capacity
	if capacity <= 0 {
		capacity = replayWindowDefaultCapacity
	}
	for len(w.entries) > capacity {
		w.entries = w.entries[1:]
		w.dropped++
	}
}

// countFailed 记一次「想采但没构造成功」。它必须是个数得出来的数：
// 采集侧静默失败，运维看到的就是「窗口里比线上少了几条」，而没有任何地方说为什么。
func (w *replayWindow) countFailed() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.failed++
}

// file 把当前窗口落成记录文件。filter 非零时只导那一个范围（分范围出证据用）：
// 请求范围正好是它，**或**当时那次判定的范围链里有它。
//
// 用 e.decision.Chain 而不是另存一份链：链本来就在记录里（回放要按它复核
// Filter(chain)），再存一份就是两个真相，而且这两份会在记录构造失败时分开漂移。
//
// 返回的丢弃数与失败数是**整窗累计**，不按范围过滤：它们回答的是
// 「这个开关开着期间丢了多少」，而不是「这个范围丢了多少」。
func (w *replayWindow) file(filter policy.ScopeRef) (replay.File, int64, int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	decisions := make([]replay.DecisionRecord, 0, len(w.entries))
	routings := make([]replay.RoutingRecord, 0, len(w.entries))
	for _, e := range w.entries {
		if filter != (policy.ScopeRef{}) && !replayScopeMatch(filter, e.key, e.decision.Chain) {
			continue
		}
		decisions = append(decisions, e.decision)
		if e.routing != nil {
			routings = append(routings, *e.routing)
		}
	}
	return replay.NewFile(decisions, routings), w.dropped, w.failed
}

// stats 给状态视图（不含任何 subject —— 状态口要回答「采了多少」，
// 谁被采到是导出那份文件的事，两个面的暴露程度不一样）。
//
// scope_filter 是 kind:id 的全串形态（user:alice / organization:university /
// system:global），没设过滤时是空串：过滤条件是管理员自己写的，它属于 §2.9
// 允许出现的「范围」，而记录级的归属只出现在导出那份文件里。
func (w *replayWindow) stats() map[string]any {
	w.mu.Lock()
	defer w.mu.Unlock()
	routings := 0
	for _, e := range w.entries {
		if e.routing != nil {
			routings++
		}
	}
	filter := ""
	if w.filter != (policy.ScopeRef{}) {
		filter = w.filter.Display()
	}
	return map[string]any{
		"enabled":         w.enabled,
		"sample_permille": w.permille,
		"scope_filter":    filter,
		"capacity":        w.capacity,
		"entries":         len(w.entries),
		"decisions":       len(w.entries),
		"routings":        routings,
		"captured":        w.captured,
		"dropped":         w.dropped,
		"failed":          w.failed,
	}
}

// configure 改采集开关。指针语义：缺省项不动 —— 一次「只把比例调到 50‰」的请求
// 不该顺手关掉开关或清空范围过滤。返回改完之后的快照。
//
// scope 传的是**已校验的结构化范围**（nil = 不动；零值 ScopeRef = 清掉过滤）。
// 解析与通配拒绝留在管理口那一层（parseScopeParam），窗口不参与语法判断 ——
// 否则「400 说破」这件事就变成窗口里一个没人看的 error 分支。
func (w *replayWindow) configure(enabled *bool, permille *int, scope *policy.ScopeRef, capacity *int) map[string]any {
	w.mu.Lock()
	if enabled != nil {
		w.enabled = *enabled
	}
	if permille != nil {
		w.permille = *permille
	}
	if scope != nil {
		w.filter = *scope
	}
	if capacity != nil && *capacity > 0 {
		w.capacity = *capacity
		for len(w.entries) > w.capacity {
			w.entries = w.entries[1:]
			w.dropped++
		}
	}
	w.mu.Unlock()
	return w.stats()
}

// clear 丢掉窗口里的记录并把计数归零。
//
// 归零而不是保留历史累计：clear 的语义是「这批证据我已经拿走了」。留着上一批的
// dropped 与 failed，下一次导出就没法区分「刚才掉的」和「上周掉的」。
func (w *replayWindow) clear() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.entries = nil
	w.captured = 0
	w.dropped = 0
	w.failed = 0
}

// captureReplay 把一次已经跑完的判定落成回放记录。
//
// 挂在 policyEvaluate（线上入口）而不是 policyJudge 上：管理口的路由模拟复用同一个
// 判定核，但它不是「一次真实决策」。模拟请求进窗口，就等于在证据链里掺进人为流量 ——
// 与 §3.0 线 1 禁止模拟进影子计数是同一条理由。
//
// 失败只 WARN、不改请求结果：采集是观测面，观测面出问题绝不能把用户的请求变差。
// 但 WARN 里只带 request_id —— 错误文案可能含记录字段值，正文与密钥一律不许顺着
// 这条路泄漏（§2.9 规则 6）。
//
// scope 是 2.x 传进来的路由作用域（用户名，静态 key 为空）。它**不**直接当窗口的键：
// 键一律是结构化范围，由 requestAuditScope30 给（裁决 7=C；和 P6 那三类留痕同一个归属
// 规则，一条规则只写一遍）。
func (s *Server) captureReplay(rt *policyRuntime, scope, requestID string, shot *policyShot) {
	w := s.replayWin
	if rt == nil || shot == nil || w == nil {
		return
	}
	if rt.mode != config.PolicyModeEnforce {
		return
	}
	// 没有版本就没有可回放的判定：范围没被任何策略包覆盖时，这次请求按旧路由走，
	// 记一条 policy_version 为空的记录既过不了 §2.8 的自校验，也会把
	// 「这个范围退出了 3.0」误报成「3.0 判了它」。
	if shot.Version == "" || shot.res == nil {
		return
	}
	key := requestAuditScope30(scope)
	if !w.shouldCapture(key, shot.chain, requestID) {
		return
	}

	// 原文出网结论必须由当时的 Resolver 现算（不从 processor 那边借用）：
	// 回放侧会重跑 AllowsRawBody 并比对这一位，两处口径不同就必然报差异。
	// 判定为拒绝时按「没授予」记 —— DecisionRecord.Validate 钉死了这条不变量
	// （拒绝的结论不可能同时授予原文出网）。
	external := false
	if shot.Decision.Allowed {
		external, _ = shot.res.AllowsRawBody(shot.judgeCtx, shot.chain, shot.judgeNow)
	}

	decision, err := replay.DecisionRecordFrom(replay.DecisionCapture{
		RequestID:                requestID,
		RecordedAt:               shot.judgeNow,
		Chain:                    shot.chain,
		Subject:                  shot.subject,
		Ctx:                      shot.judgeCtx,
		Resource:                 shot.resource,
		Action:                   shot.action,
		Decision:                 shot.Decision,
		ExternalPlaintextAllowed: external,
		WiringMode:               replay.ModeEnforce,
	})
	if err != nil {
		w.countFailed()
		s.log.Warnf("回放记录采集失败（判定）request_id=%s: %v", requestID, err)
		return
	}
	entry := replayEntry{key: key, decision: decision}

	// 选路记录只在计划真的作用到本请求时才写（理由见文件头纪律 2）。
	if shot.Applied {
		routingRec, rerr := replay.RoutingRecordFrom(replay.RoutingCapture{
			RequestID:     requestID,
			RecordedAt:    shot.judgeNow,
			PolicyVersion: shot.Version,
			RoutingSeed:   shot.Seed,
			RoutingEpoch:  shot.Epoch,
			SamplingAlgo:  replaySamplingAlgoOnline,
			Candidates:    replayCandidatesOf(shot.Candidates),
			Plan:          shot.Plan,
			Rejections:    shot.Plan.Rejections,
			// 完整现场：有它，导出那份文件的选路记录才有「首选顺序逐位复现」的凭据；
			// 没有它（shot 上为 nil）记录照样导出，只是回放侧只能做解释性回放。
			Replay: shot.replaySnapshot,
		})
		if rerr != nil {
			w.countFailed()
			s.log.Warnf("回放记录采集失败（选路）request_id=%s: %v", requestID, rerr)
			return
		}
		entry.routing = &routingRec
	}
	w.add(entry)
}

// replayCandidatesOf 把候选池落成记录里的形态：**权重按有效权重写**。
//
// 为什么不是直接抄 Offer.Candidate：那里面是配置原值（未配置 = 0），而计划里的候选
// 权重是 routing.Offer.candidateForPlan() 折算后的有效权重。两处不一致的话，
// 记录顶层的 candidates_digest 就和请求表里那一列、和计划内的候选都对不上，
// 「导出记录能与线上落库痕迹对上」这条最基本的证据就断了。
// RoutingRecordFrom 会再按稳定顺序排一次，顺序不由这里决定。
func replayCandidatesOf(os routing.Offers) []policy.RouteCandidate {
	out := make([]policy.RouteCandidate, 0, len(os))
	for _, o := range os {
		c := o.Candidate
		if c.Weight <= 0 {
			c.Weight = 1
		}
		out = append(out, c)
	}
	return out
}

// replayWiringModeNote 说明这批记录采集自哪个接线阶段。
//
// 窗口只采 enforce（见 captureReplay 的纪律 1），所以这里不是「读当前模式」而是
// 「说清记录的含义」：模式在采集之后可能被切成 shadow，而已经躺在窗口里的那批记录
// 描述仍然是它们当时真实作用过的那次判定。
func replayWiringModeNote() string {
	return "记录只在 policy.mode=enforce 时采集；影子的判定没有作用到任何请求上，不构成回放证据"
}

// replayClock 给状态视图用的当前时刻（测试里跟着 nowFn 走，保证可断言）。
func (s *Server) replayClock() time.Time { return s.now().UTC() }
