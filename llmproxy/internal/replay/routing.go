package replay

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/routing"
)

// ReplayRouting 重跑一次选路决策。
//
// §2.8 的分工在这里落成可执行的断言：
//   - 在线模式的权重随机不受影响，本函数不碰任何全局随机源；
//   - 回放必须显式用记录里的 seed 建立独立确定性随机源 —— seed 缺失或非法时
//     直接拒绝回放（fail-closed），绝不退回随机再假装复现了；
//   - 记录声明的 sampling_algo 与当前抽样器不一致时，只能做「解释性回放」：
//     仍校验候选摘要、排除原因与权限，但不声称首选逐位相同（§2.8 对旧请求的口径）。
//
// 首选逐位那条路（2026-10-04 裁决第 5 条 B）只认记录自带的 replay_snapshot：
// 有快照且算法在 D 的逐位集合里，就交给 internal/routing 的窄接口重跑并逐字段比对；
// 二者缺一律退回解释性回放，并把「为什么不能声称逐位」的原因写进 Notes ——
// 一份看起来通过、其实什么也没证明的报告，比一份差异报告更坏。
//
// pair 是同 request_id 的判定记录：有它才能拿到范围集合与上下文，
// 于是版本来源可以按 Filter(chain) 复核，计划里每个候选也都能重跑一次授权判定
// （§6「fallback 不绕过权限」）。
func (r *Replayer) ReplayRouting(rec RoutingRecord, pair DecisionRecord, hasPair bool) Outcome {
	o := Outcome{Kind: KindRouting, RequestID: rec.RequestID}
	if err := rec.Validate(r.now); err != nil {
		return reject(o, policy.ReasonContextInvalid, err.Error())
	}

	r.checkRoutingVersionSource(&o, rec, pair, hasPair)
	if o.Status == StatusRejected {
		return o
	}

	if rec.RoutingSeed == "" {
		return reject(o, policy.ReasonReplaySeedMissing,
			"记录里没有 routing_seed：在线抽样不受影响，但回放不能退回随机数，拒绝执行（§2.8）")
	}
	if err := policy.ParseRoutingSeed(rec.RoutingSeed); err != nil {
		return reject(o, policy.ReasonReplaySeedMissing, err.Error())
	}

	// seed 来源本身也要能复核：§2.8 推荐 H(request_id || policy_version || routing_epoch)。
	if rec.RoutingEpoch != "" {
		derived, err := policy.DeriveRoutingSeed(rec.RequestID, rec.PolicyVersion, rec.RoutingEpoch)
		if err != nil {
			return reject(o, policy.ReasonPolicyVersionMissing, err.Error())
		}
		addDiff(&o, "routing_seed", rec.RoutingSeed, derived)
		if rec.Plan.RoutingSeed == "" {
			o.Notes = append(o.Notes, "计划里没写 routing_seed，只有记录顶层有：接线时必须两处一致落库")
		}
	}

	rejected := rejectedProviders(rec.Rejections)

	// 候选摘要：证明「回放用的池子」和「在线时的池子」是同一个。
	digest, err := policy.CandidatesDigest(rec.Candidates)
	if err != nil {
		return reject(o, policy.ReasonContextInvalid, err.Error())
	}
	addDiff(&o, "candidates_digest", rec.CandidatesDigest, digest)

	algo := rec.SamplingAlgoOrDefault()
	switch {
	case rec.Replay != nil:
		r.collectBitExactDiffs(&o, rec, rejected)
	case algo != r.sampler.Algo():
		o.Notes = append(o.Notes, fmt.Sprintf(
			"记录声明抽样算法 %q，当前抽样器 %q：只做解释性回放，不比对首选顺序（§2.8）",
			algo, r.sampler.Algo()))
	default:
		r.collectSequenceDiffs(&o, rec, rejected)
	}

	// 排除原因的一致性：被排除的 provider 绝不能出现在计划里，也不能被抽样序列选中。
	planProviders := providersOf(rec.Plan.Fallbacks)
	for _, p := range planProviders {
		if rejected[p] {
			addDiff(&o, "rejections/"+p, "已排除，不得进入计划", "出现在 plan.fallbacks")
		}
	}
	for _, rej := range rec.Rejections {
		if !rej.Reason.Valid() {
			addDiff(&o, "rejections/"+rej.Provider, "已注册原因码", string(rej.Reason))
		}
	}
	addDiff(&o, "rejections_digest", rejectionsList(rec.Rejections), rejectionsList(rec.Plan.Rejections))

	if hasPair {
		r.collectCandidateGrantDiffs(&o, rec, pair)
	}

	if o.Status == StatusRejected {
		o.normalize()
		return o
	}
	if len(o.Diffs) == 0 {
		o.Status = StatusPassed
	} else {
		o.Status = StatusMismatch
	}
	o.normalize()
	return o
}

// checkRoutingVersionSource 复核 §3.0 的版本来源。
func (r *Replayer) checkRoutingVersionSource(o *Outcome, rec RoutingRecord, pair DecisionRecord, hasPair bool) {
	if hasPair {
		chain, err := pair.ScopeChain()
		if err != nil {
			*o = reject(*o, policy.ReasonScopeMismatch, err.Error())
			return
		}
		subset, err := r.set.Filter(chain)
		if err != nil {
			*o = reject(*o, policy.ReasonScopeMismatch,
				fmt.Sprintf("已加载的策略集不覆盖记录范围 %s: %v", chain.Display(), err))
			return
		}
		scoped, err := subset.PolicyVersion()
		if err != nil {
			*o = reject(*o, policy.ReasonPolicyVersionMissing, err.Error())
			return
		}
		if scoped != rec.PolicyVersion {
			*o = reject(*o, policy.ReasonPolicyVersionMissing,
				fmt.Sprintf("记录版本 %q，按范围 Filter(%s) 后的实际版本 %q", rec.PolicyVersion, chain.Display(), scoped))
			return
		}
		return
	}
	if missing := r.verifyVersionComposedOf(rec.PolicyVersion); len(missing) > 0 {
		*o = reject(*o, policy.ReasonPolicyVersionMissing,
			fmt.Sprintf("记录版本串里的 %s 不在已加载的策略包中", strings.Join(missing, ",")))
		return
	}
	o.Notes = append(o.Notes,
		"没有同 request_id 的判定记录：只能校验版本串由已加载的包组成，无法按 Filter(chain) 复核（降级回放）")
}

// collectSequenceDiffs 用记录里的 seed 重建尝试序列，并与计划的顺序比对。
func (r *Replayer) collectSequenceDiffs(o *Outcome, rec RoutingRecord, rejected map[string]bool) {
	sequence, err := r.sampler.Sequence(rec.RoutingSeed, rec.Candidates, rejected)
	if err != nil {
		*o = reject(*o, policy.ReasonReplaySeedMissing, err.Error())
		return
	}
	if len(sequence) == 0 {
		*o = reject(*o, policy.ReasonNoCandidate, "抽样序列为空")
		return
	}
	attempts := rec.Plan.Attempts()
	if attempts > len(sequence) {
		// 计划声明的尝试次数超过了「排除之后还能复现的候选数」：
		// 在线时它会被候选数截断，回放时必须把截断点说出来，否则差异会被当成顺序问题。
		o.Notes = append(o.Notes, fmt.Sprintf(
			"计划声明 %d 次尝试，可复现序列只有 %d 个候选（其余被排除）", rec.Plan.Attempts(), len(sequence)))
		attempts = len(sequence)
	}
	expected := sequence[:attempts]
	actual := providersOf(rec.Plan.Fallbacks)

	addDiff(o, "plan.primary", expected[0], firstOrEmpty(actual))
	if len(actual) < attempts {
		addDiff(o, "plan.attempts_count", fmt.Sprintf("%d", attempts), fmt.Sprintf("%d", len(actual)))
	}
	limit := attempts
	if len(actual) < limit {
		limit = len(actual)
	}
	for i := 0; i < limit; i++ {
		addDiff(o, fmt.Sprintf("plan.attempts/%d", i), expected[i], actual[i])
	}
}

// collectBitExactDiffs 用记录自带的完整快照重跑规划，逐字段比对首选与次序。
//
// 与 collectSequenceDiffs 的区别不是「比得严一点」，而是**比的是不同的东西**：
// 那条重跑的是本包抽样器（replay-sampling-v1）在配置级候选投影上的序列，
// 这一条重跑的是 D 的规划器在当时那份运行时事实上的计划。
// 后者才是「首选顺序逐位复现」这句话的证据（裁决第 5 条 B）。
//
// 逐位的判定刻意取「这一段的差异数为 0」而不是「整体 passed」：
// 授权还在不在（collectCandidateGrantDiffs）与顺序复现不复现是两件独立的事，
// 混成一个布尔会让「策略收紧了但顺序没变」被报成回放失败。
func (r *Replayer) collectBitExactDiffs(o *Outcome, rec RoutingRecord, rejected map[string]bool) {
	in, algo, err := rec.BitExactReplay()
	if err != nil {
		// 快照在、算法对不上（或快照与顶层自相矛盾，那已在 Validate 里拒过）：
		// 退回解释性回放，但把拒绝声称逐位的**原因**留在报告里。
		o.Notes = append(o.Notes, fmt.Sprintf("%v：只做解释性回放，不声称首选逐位复现（§2.8）", err))
		if rec.SamplingAlgoOrDefault() == r.sampler.Algo() {
			r.collectSequenceDiffs(o, rec, rejected)
		}
		return
	}

	plan, digest, err := routing.ReplayWithAlgo(in, algo)
	if err != nil {
		*o = reject(*o, policy.ReasonContextInvalid,
			fmt.Sprintf("按记录声明的算法 %q 重跑规划失败: %v", algo, err))
		return
	}

	before := len(o.Diffs)
	recordedDigest, derr := rec.Plan.Digest()
	if derr != nil {
		*o = reject(*o, policy.ReasonContextInvalid, derr.Error())
		return
	}
	addDiff(o, "bit_exact/plan_digest", recordedDigest, digest)
	addDiff(o, "bit_exact/routing_seed", rec.Plan.RoutingSeed, plan.RoutingSeed)
	addDiff(o, "bit_exact/fallbacks_count", fmt.Sprintf("%d", len(rec.Plan.Fallbacks)), fmt.Sprintf("%d", len(plan.Fallbacks)))
	for i := 0; i < len(rec.Plan.Fallbacks) && i < len(plan.Fallbacks); i++ {
		addDiff(o, fmt.Sprintf("bit_exact/order/%d", i),
			candidateSignature(rec.Plan.Fallbacks[i]), candidateSignature(plan.Fallbacks[i]))
	}
	o.BitExact = len(o.Diffs) == before
}

// candidateSignature 把一个候选压成一行可比的字段串。
// 次序比对必须逐字段而不是只比 provider：计划里「同一家换了上游模型或有效权重」
// 也是结论变了，只看 provider 会把它报成复现。
func candidateSignature(c policy.RouteCandidate) string {
	return fmt.Sprintf("%s|model=%s|upstream=%s|executor=%s|weight=%v|region=%s|level=%s",
		c.Provider, c.Model, c.UpstreamModel, c.Executor, c.Weight, c.Region, c.MaxDataLevel.String())
}

// collectCandidateGrantDiffs 用配对判定记录的范围与上下文，重跑计划里每个候选的授权判定。
//
// 这是 §6「fallback 不绕过权限」的回放版：备选模型必须在当时的策略下也站得住，
// 否则一次降级就成了一条没被策略承认的出网路径。
func (r *Replayer) collectCandidateGrantDiffs(o *Outcome, rec RoutingRecord, pair DecisionRecord) {
	chain, err := pair.ScopeChain()
	if err != nil {
		return
	}
	_, ctx, err := pair.PolicyContext()
	if err != nil {
		return
	}
	resolver, err := policy.FromBundles(r.set, chain)
	if err != nil {
		return
	}
	for _, c := range rec.Plan.Fallbacks {
		resource := policy.NamespaceModel + ":" + c.Model
		decision := resolver.Evaluate(ctx, chain, resource, policy.ActionUse, r.now)
		if !decision.Allowed {
			addDiff(o, "candidate_grant/"+c.Provider, "策略放行", "拒绝："+string(decision.Reason))
		}
	}
}

func rejectedProviders(rs []policy.Rejection) map[string]bool {
	out := make(map[string]bool, len(rs))
	for _, rej := range rs {
		out[rej.Provider] = true
	}
	return out
}

// rejectionsList 把排除记录渲染成稳定顺序的字符串，用于逐字段比对。
func rejectionsList(rs []policy.Rejection) string {
	parts := make([]string, 0, len(rs))
	for _, rej := range rs {
		parts = append(parts, rej.Provider+"="+string(rej.Reason))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func firstOrEmpty(in []string) string {
	if len(in) == 0 {
		return "<空>"
	}
	return in[0]
}
