package routing

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

var (
	// ErrInput 表示调用方构造的规划输入不合法（缺权限门、读时钟时间没传、候选池脏…）。
	// 这类错误一律**不出计划**：半合法的计划会被执行器当真，代价比报错大。
	ErrInput = errors.New("routing: 规划输入不合法")

	// ErrNoEligibleCandidate 表示所有候选都被排除了。用 errors.As 取 *PlanError 拿清单。
	ErrNoEligibleCandidate = errors.New("routing: 没有可执行的候选")

	// ErrPlanStale 表示计划已过 TTL，调用方必须重新规划而不能继续执行。
	ErrPlanStale = errors.New("routing: 计划已过期")
)

// PlanError 携带排除清单。
//
// 为什么把排除原因做成错误的一部分而不是只写日志：策略拒绝、区域限制、全档冷却这三种
// 情况现场动作完全不同（补授权 / 改区域白名单 / 等熔断），运维拿不到 Rejections 就只能
// 猜。计划结构本身装不下「没有计划」的解释，所以走错误通道。
type PlanError struct {
	// Reason 是主原因码（目前为 no_candidate）。
	Reason policy.Reason
	// Rejections 是每个被排除候选的稳定原因码，按 provider 升序。
	Rejections []policy.Rejection
	// Detail 是补充说明（例如候选池为空），可为 nil。
	Detail error
}

func (e *PlanError) Error() string {
	out := fmt.Sprintf("routing: 给不出计划（主因 %s）", e.Reason)
	if d := describeRejections(e.Rejections); d != "" {
		out += "：" + d
	}
	if e.Detail != nil {
		out += "：" + e.Detail.Error()
	}
	return out
}

// Unwrap 让 errors.Is(err, ErrNoEligibleCandidate) 成立，同时 errors.As 仍可取到清单。
func (e *PlanError) Unwrap() error {
	if e.Detail != nil {
		return e.Detail
	}
	return ErrNoEligibleCandidate
}

// Input 是一次规划的完整输入。所有可变状态都在这里传进来，D 一个都不自己查。
//
// 这个类型刻意**不可序列化**（含 Gate 与 RandomSource 两个接口字段）：能落审计的
// 是 ReplayInput，由 PlanWithReplay 产出。把两者分开是因为一旦允许序列化 Input，
// 就会有人把「今天的 gate」当成「当时的 gate」回放，得出与当时相反的结论。
type Input struct {
	// RequestID 只用于把快照与那次请求对上（D 不参与抽样：抽样只认 Seed，
	// 而 Seed 已由 policy.DeriveRoutingSeed 把 request_id 吃进去了）。
	RequestID string

	// Offers 是候选池。Tier 由调用方算好，D 不推导。
	Offers Offers

	// Gate 是权限门。必填：为 nil 直接报错，绝不按「没提权限就当允许」处理 ——
	// 那等于在 D 里开一条绕过 policy resolver 的捷径（§3.D）。
	Gate Gate

	// Requirement 表达这次请求的硬性能力要求（模型名 + 所需能力）。
	Requirement Requirement

	// MaxRetries 是重试预算，进 RoutingPlan.MaxRetries。实际尝试次数由
	// plan.Attempts() 表达（受候选数上限约束），D 不另算一套。
	MaxRetries int

	// ProcessorChain 由调用方（处理器/策略侧）决定，D 只原样带进计划：
	// 处理器要不要跑是策略结论，不是路由偏好（§3.D 边界）。
	ProcessorChain []string

	// Objective 是排序目标函数；空值取 DefaultObjective（与现网同分布的一档）。
	Objective Objective

	// AllowUnknownCost 是「允许无价目候选参与 cheapest」的显式开关。
	// 默认 false：无价目直接排除并给 candidate_cost_unknown（§3.D 禁止当零成本）。
	AllowUnknownCost bool

	// Sticky 是会话粘性，nil = 没有。
	Sticky *StickyState

	// Now 是本次决策的时间基准。必填：D 不读时钟，否则同输入不同秒就不同结论，
	// 冷却与 TTL 都无法回放。
	Now time.Time

	// TTL 是计划有效期（相对 Now）。必填且必须为正：没有 ExpiresAt 的计划会被下游
	// 无限缓存，策略回滚就再也传不下去（§3.0 要求任何新路径可按 scope 回滚）。
	TTL time.Duration

	// Seed 是 routing_seed（policy.DeriveRoutingSeed 的产物）。非空即用确定性源抽样，
	// 线上一致地记录它，回放才有逐位相同的可能。
	Seed string

	// Source 是线上模式注入的随机源（保持现网流量分布）。Seed 为空时必填。
	Source RandomSource

	// PolicyVersion 是本次生效的策略内容版本，必须来自实际加载的策略包
	// （BundleSet.Filter(chain).PolicyVersion()）。空则回落到 ctx.PolicyVersion；
	// 两者都空时报错 —— 计划上的版本字段是回滚与审计的唯一抓手。
	PolicyVersion string
}

// Planner 是规划器本体：**没有任何字段**。
//
// 这不是偷懒。现网 Router 把供应商配置、熔断状态、随机源、时钟都装在一个带锁对象里，
// 于是「选路」这件事没法在别处复用（影子运行、路由模拟、回放都要复制一遍）。
// 状态全部外置成数据之后，规划本身是纯函数，可以并发、可以缓存、可以在管理台里
// 拿任意输入试跑而不改动线上任何东西（DoD 4）。
type Planner struct{}

// NewPlanner 构造规划器。返回值可被任意多个 goroutine 长期复用。
func NewPlanner() *Planner { return &Planner{} }

// Plan 产出一份路由计划。
func (p *Planner) Plan(ctx policy.PolicyContext, chain policy.ScopeChain, in Input) (policy.RoutingPlan, error) {
	plan, _, err := p.PlanWithReplay(ctx, chain, in)
	return plan, err
}

// PlanWithReplay 同时产出计划与可回放的输入快照（§2.8：在线请求至少记录
// routing_seed、候选摘要、最终计划、policy_version）。
//
// 快照里带上**当时逐个问过 gate 的结论**，回放就不再需要活的策略内核：
// 用今天的策略回放昨天的请求，几乎必然得出不同答案，而那种答案没有任何价值。
func (p *Planner) PlanWithReplay(ctx policy.PolicyContext, chain policy.ScopeChain, in Input) (policy.RoutingPlan, ReplayInput, error) {
	normalized := ctx.Normalize()
	if in.PolicyVersion == "" {
		// ctx 里带版本时补进 Input，保证 gate 与计划看到的是同一个版本串。
		in.PolicyVersion = normalized.PolicyVersion
	}
	if err := in.Validate(normalized, chain); err != nil {
		return policy.RoutingPlan{}, ReplayInput{}, err
	}
	// 版本的真相只有一处：定下来后写回 ctx，gate 实现读 ctx.PolicyVersion 时
	// 不会再拿到一个空串或另一份版本。
	normalized.PolicyVersion = in.PolicyVersion

	src, err := resolveSource(in.Seed, in.Source)
	if err != nil {
		return policy.RoutingPlan{}, ReplayInput{}, err
	}

	objective := in.Objective.normalize()
	viewed := p.screen(normalized, chain, in, objective)
	if len(viewed.survivors) == 0 {
		return policy.RoutingPlan{}, ReplayInput{}, &PlanError{
			Reason:     policy.ReasonNoCandidate,
			Rejections: sortRejections(viewed.rejections),
		}
	}

	ranked := objective.rank(viewed.survivors, in.Now)
	primary, reasonCodes := p.choosePrimary(objective, ranked, in, src)
	// 首选所在档之外的候选按目标函数排好接在后面（同档剩余 → 下一档），
	// 首选本身从尾部摘掉，避免 Fallbacks 里出现同一家两次
	// （policy.RoutingPlan.Validate 会直接拒绝重复 provider）。
	tail := withoutProvider(ranked, primary.provider())

	fallbacks := make([]policy.RouteCandidate, 0, len(ranked))
	fallbacks = append(fallbacks, primary.candidateForPlan())
	for _, o := range tail {
		fallbacks = append(fallbacks, o.candidateForPlan())
	}

	rejectionReasons := make([]policy.Reason, 0, len(viewed.rejections))
	for _, r := range viewed.rejections {
		rejectionReasons = append(rejectionReasons, r.Reason)
	}
	reasonCodes = append(reasonCodes, rejectionReasons...)
	if objective == ObjectiveCheapest && in.AllowUnknownCost {
		// 显式放行未知成本时，把这件事标在计划上：这些候选进了 Fallbacks，
		// 不能记成 Rejection，但审计必须看得出「这份便宜结论建立在缺价目的数据上」。
		reasonCodes = append(reasonCodes, explainMissingCost(ranked)...)
	}

	plan := policy.RoutingPlan{
		Executor:       primary.Candidate.Executor,
		Model:          primary.Candidate.Model,
		UpstreamModel:  primary.Candidate.UpstreamModel,
		Fallbacks:      fallbacks,
		ProcessorChain: append([]string(nil), in.ProcessorChain...),
		MaxRetries:     in.MaxRetries,
		ReasonCodes:    policy.Reasons(reasonCodes),
		PolicyVersion:  in.PolicyVersion,
		ExpiresAt:      in.Now.Add(in.TTL),
		RoutingSeed:    in.Seed,
		Rejections:     sortRejections(viewed.rejections),
	}
	// 出口自校：计划不合法就不返回。宁可在规划期报错，也不让执行器拿到一份
	// 过不了 §2.5 校验的计划再去审计表里失败。
	if err := plan.Validate(in.Now); err != nil {
		return policy.RoutingPlan{}, ReplayInput{}, fmt.Errorf("%w: %v", ErrInput, err)
	}

	snapshot, err := in.snapshotReplay(normalized, chain, objective, viewed, primary)
	if err != nil {
		return policy.RoutingPlan{}, ReplayInput{}, err
	}
	return plan, snapshot, nil
}

// gateVerdict 是一次权限提问的结论。
type gateVerdict struct {
	Allowed bool          `json:"allowed"`
	Reason  policy.Reason `json:"reason"`
}

// screening 是一遍候选过滤的结果。
type screening struct {
	// survivors 是全部过滤都通过的候选。
	survivors []Offer
	// verdicts 记录每个候选的 gate 结论（含被其它过滤排除的），回放快照要用。
	verdicts map[string]gateVerdict
	// rejections 是每个被排除候选的稳定原因码。
	rejections []policy.Rejection
}

// screen 逐个过滤候选。
//
// 过滤次序是固定的，且必须固定：一个候选可能同时不满足几项，记录哪一条原因取决于次序。
// 次序本身按「越严重越先」排：
//
//  1. 权限（Gate）—— 越权是最严重的错误方向，deny 不能被任何优化绕过；
//  2. 区域与数据分级 —— 合规约束，与策略同源；
//  3. 能力与模型承接 —— 技术可行性；
//  4. 成本 —— 只是优化偏好，绝不能盖过前三条。
//
// 同一候选只记第一条命中的原因：一份 Rejection 对应一个结论，避免审计里出现
// 「既说不允许又说没价目」的多重解释。
func (p *Planner) screen(ctx policy.PolicyContext, chain policy.ScopeChain, in Input, objective Objective) screening {
	out := screening{verdicts: make(map[string]gateVerdict, len(in.Offers))}
	for _, offer := range in.Offers {
		allowed, reason := in.Gate.Allows(ctx, chain, offer, in.Now)
		if !allowed {
			out.verdicts[offer.provider()] = gateVerdict{Allowed: false, Reason: normalizeGateReason(reason)}
			out.rejections = append(out.rejections, policy.Rejection{Provider: offer.provider(), Reason: normalizeGateReason(reason)})
			continue
		}
		out.verdicts[offer.provider()] = gateVerdict{Allowed: true, Reason: gateReasonOnAllow(reason)}

		// 区域：口径完全走 policy.PolicyContext.RegionAllowed（§8 D：D 消费 AllowedRegions）。
		if !ctx.RegionAllowed(offer.Candidate.Region) {
			out.rejections = append(out.rejections, policy.Rejection{Provider: offer.provider(), Reason: policy.ReasonCandidateRegionExcluded})
			continue
		}
		// 数据分级：候选声明的最高等级低于本次请求的有效分级 → 排除。
		// 用 Exceeds 而不是字符串/秩直接比较（policy 的固定口径）。
		if ctx.DataLevel.Exceeds(offer.Candidate.MaxDataLevel) {
			out.rejections = append(out.rejections, policy.Rejection{Provider: offer.provider(), Reason: policy.ReasonCandidateLevelExcluded})
			continue
		}
		// 能力匹配：承接不了模型名，或缺任一所需能力。
		if !offer.servesModel(in.Requirement.Model) || !offer.hasCapabilities(in.Requirement.Capabilities) {
			out.rejections = append(out.rejections, policy.Rejection{Provider: offer.provider(), Reason: ReasonCapabilityUnmatched})
			continue
		}
		// 成本：cheapest 下无价目者默认不参与（§3.D 不得当零成本）。
		if objective == ObjectiveCheapest && !offer.CostKnown && !in.AllowUnknownCost {
			out.rejections = append(out.rejections, policy.Rejection{Provider: offer.provider(), Reason: policy.ReasonCandidateCostUnknown})
			continue
		}
		out.survivors = append(out.survivors, offer)
	}
	return out
}

// choosePrimary 定出首选，并返回该结论的解释码。
//
// 粘性优先于随机，且命中时**不调用随机源**（§2.8）。这条不是洁癖：随机数消耗一次
// 就把序列往后推一格，同一次决策在「命中粘性」与「未命中」两条路径上会让后续候选
// 分布整体错位，回放与影子比对就永远解释不清。
//
// 粘性只在首选所在的**同一档**内生效。现网同理：prefer 是在最终候选池里
// 挑一家，不是绕过候选规则（internal/router 的 PickFromPreferring 把这段写在池子
// 定下来之后）。跨档钉住会把「点名声明优先于通配」这类硬规则变成软建议。
func (p *Planner) choosePrimary(objective Objective, ranked []Offer, in Input, src RandomSource) (Offer, []policy.Reason) {
	pool := primaryPool(objective, ranked)

	if in.Sticky.isActiveAt(in.Now) {
		for _, o := range pool {
			// 冷却中或已判不健康的那家不粘（现网语义：后端不能用就换家，
			// 漂完之后上层更新粘性，不再来回横跳）。
			if o.provider() == in.Sticky.Provider && o.isAvailableAt(in.Now) {
				return o, []policy.Reason{policy.ReasonAffinityHit}
			}
		}
	}
	if objective == ObjectiveFixedOrder {
		return weightedSample(pool, src), []policy.Reason{policy.ReasonWeightedChoice}
	}
	// cheapest / fastest 是确定性排序：第一名就是排名第一名，不掺随机。
	// 稳定 tiebreak 在 Objective.less 的末尾（provider → upstream → executor）。
	reason := objective.selectionReason()
	if reason == "" {
		return ranked[0], nil
	}
	return ranked[0], []policy.Reason{reason}
}

// primaryPool 给出「粘性可以落在哪些候选上 / fixed-order 在哪些候选里抽样」。
//
// 规则：首选所在档的全部成员。cheapest 额外要求价目可得性与首选一致 ——
// 否则显式 AllowUnknownCost 时，粘性会把一个无价目候选推上首选位，
// 那就绕过了「未知成本绝不参与 cheapest 第一名」这条硬约束。
//
// 池内一律按稳定 provider ID 排好：累积扫描的结果依赖池内顺序，顺序一抖，
// 同一个随机数会指向另一家（§2.8 禁止依赖 map 遍历顺序）。
func primaryPool(objective Objective, ranked []Offer) []Offer {
	first := ranked[0]
	var pool []Offer
	for _, o := range ranked {
		if o.Tier != first.Tier {
			continue
		}
		if objective == ObjectiveCheapest && o.CostKnown != first.CostKnown {
			continue
		}
		pool = append(pool, o)
	}
	return sortedByProviderID(pool)
}

// weightedSample 按有效权重在档内抽一家，算法与现网 PickFromPreferring 的累积扫描
// 同形（x = Float64()*total；acc += w；x <= acc 即命中；兜底取最后一个）。
//
// 不复制现网的 `total <= 0 → total = len(pool)` 兜底：有效权重恒 ≥1（Offer.effectiveWeight），
// 该分支不可达；留着反而会在真的出现 0 权重时掩盖输入错误。
//
// 只消耗一个随机数：现网一次选路也只调一次 rnd.Float64()。
func weightedSample(pool []Offer, src RandomSource) Offer {
	var total float64
	for _, o := range pool {
		total += o.effectiveWeight()
	}
	x := src.Float64() * total
	var acc float64
	for _, o := range pool {
		acc += o.effectiveWeight()
		if x <= acc {
			return o
		}
	}
	return pool[len(pool)-1]
}

// withoutProvider 返回去掉指定 provider 的副本，顺序保持不变（已按目标函数排好）。
func withoutProvider(os []Offer, provider string) []Offer {
	out := make([]Offer, 0, len(os))
	for _, o := range os {
		if o.provider() == provider {
			continue
		}
		out = append(out, o)
	}
	return out
}

// sortRejections 让排除清单本身也是确定的顺序（provider 升序、同 provider 按码升序）。
// 不排序的话，Rejections 会跟着候选池的传入顺序变，Digest 也就跟着变。
func sortRejections(rs []policy.Rejection) []policy.Rejection {
	if len(rs) == 0 {
		return nil
	}
	out := append([]policy.Rejection(nil), rs...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}

// Validate 校验输入。chain 一并检查：policy 的判定在 chain 为空时一律拒绝，
// 那会让所有候选以 candidate_policy_excluded 出局，报错点离真因隔了一层，
// 所以在入口直接判掉。
func (in Input) Validate(ctx policy.PolicyContext, chain policy.ScopeChain) error {
	if in.Gate == nil {
		return fmt.Errorf("%w: 缺少权限门（Gate）—— 没有它就无法在不绕过 policy resolver 的前提下判定候选", ErrInput)
	}
	if len(chain) == 0 {
		return fmt.Errorf("%w: 范围集合为空，判定无从进行", ErrInput)
	}
	if err := ctx.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInput, err)
	}
	if err := in.Requirement.Validate(); err != nil {
		return err
	}
	if err := in.Offers.Validate(); err != nil {
		return err
	}
	if !in.Objective.normalize().valid() {
		return fmt.Errorf("%w: 目标函数 %q", ErrInput, string(in.Objective))
	}
	if in.Now.IsZero() {
		return fmt.Errorf("%w: 必须显式传入 Now（本包不读时钟，否则同输入不同秒就不同结论）", ErrInput)
	}
	if in.TTL <= 0 {
		return fmt.Errorf("%w: TTL 必须为正，否则计划没有失效点", ErrInput)
	}
	if in.MaxRetries < 0 {
		return fmt.Errorf("%w: max_retries 为负（%d）", ErrInput, in.MaxRetries)
	}
	if in.PolicyVersion == "" {
		return fmt.Errorf("%w: 缺少 policy_version（必须来自实际加载的策略包，不能由 handler 拼接）", ErrInput)
	}
	if in.Seed == "" && in.Source == nil {
		return fmt.Errorf("%w: 既无 seed 也无注入随机源", ErrInput)
	}
	return nil
}

// validateSeed 校验外部传入的 routing_seed。口径完全交给 policy.ParseRoutingSeed，
// D 不自定一套格式（否则回放输入与派生函数就对不上了）。
func validateSeed(seed string) error {
	if err := policy.ParseRoutingSeed(seed); err != nil {
		return fmt.Errorf("%w: %v", ErrInput, err)
	}
	return nil
}

// CheckFresh 让调用方在真正发出上游请求之前复查计划时效（§2.5 的 ExpiresAt 语义）。
//
// 为什么要单独一个函数而不是只看 Validate：一次规划可能被打进上下文里缓存复用，
// 而 §3.0 要求策略回滚能尽快生效 —— 缓存里那份计划过期后必须重新规划，
// 不能靠「反正已经算出来了」继续执行旧的权限结论。
func CheckFresh(plan policy.RoutingPlan, now time.Time) error {
	if plan.Expired(now) {
		return fmt.Errorf("%w: %s（now=%s）[%s]", ErrPlanStale,
			plan.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339), policy.ReasonPlanExpired)
	}
	return nil
}
