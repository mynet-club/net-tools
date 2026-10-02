package replay

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// ReplayRouting 重跑一次选路决策。
//
// §2.8 的分工在这里落成可执行的断言：
//   - 在线模式的权重随机不受影响，本函数不碰任何全局随机源；
//   - 回放必须显式用记录里的 seed 建立独立确定性随机源 —— seed 缺失或非法时
//     直接拒绝回放（fail_closed），绝不退回随机再假装复现了；
//   - 记录声明的 sampling_algo 与当前抽样器不一致时，只能做「解释性回放」：
//     仍校验候选摘要、排除原因与权限，但不声称首选逐位相同（§2.8 对旧请求的口径）。
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
	if algo != r.sampler.Algo() {
		o.Notes = append(o.Notes, fmt.Sprintf(
			"记录声明抽样算法 %q，当前抽样器 %q：只做解释性回放，不比对首选顺序（§2.8）",
			algo, r.sampler.Algo()))
	} else {
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
