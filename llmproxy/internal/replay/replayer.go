package replay

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// Options 是回放参数。
type Options struct {
	// Now 是回放的固定时钟。必填：策略与身份的过期语义只有钉住 now 才能复现（§2.8）。
	Now time.Time

	// Sampler 是抽样器实现。留空用本包的 replay-sampling-v1；
	// D 包合并后主线注入其实现，即可获得与在线模式逐位一致的复现。
	Sampler Sampler

	// StrictReasonChain 额外比对完整原因链（默认只比主原因码）。
	// 默认不严格是因为 Reasons 里会带 condition_unmet 这类中间过程项，
	// 规则文案微调就可能让它抖动；门禁要钉的是结论和决定性规则。
	StrictReasonChain bool
}

// Replayer 用一套已加载的策略包 + 一个固定时钟重跑记录。
//
// 构造后不可变，可并发复用（与 A 包 Resolver 同一口径）。
type Replayer struct {
	set               *policy.BundleSet
	now               time.Time
	sampler           Sampler
	strictReasonChain bool
	loadedVersion     string
}

// New 构造回放器。三处 fail_closed：策略集为空、时钟缺失、抽样器不合法。
func New(set *policy.BundleSet, opts Options) (*Replayer, error) {
	if set == nil || set.Len() == 0 {
		return nil, ErrEmptyBundleSet
	}
	if opts.Now.IsZero() {
		return nil, ErrClockRequired
	}
	sampler := opts.Sampler
	if sampler == nil {
		sampler = NewLocalSampler()
	}
	if sampler.Algo() == "" {
		return nil, fmt.Errorf("%w: 抽样器缺 Algo 标识", ErrSamplerNil)
	}
	loaded, err := set.PolicyVersion()
	if err != nil {
		return nil, fmt.Errorf("replay: 已加载策略集出版本串失败: %w", err)
	}
	return &Replayer{
		set:               set,
		now:               nowUTC(opts.Now),
		sampler:           sampler,
		strictReasonChain: opts.StrictReasonChain,
		loadedVersion:     loaded,
	}, nil
}

// Clock 返回回放时钟（UTC、秒级）。
func (r *Replayer) Clock() time.Time { return r.now }

// LoadedPolicyVersion 返回整集版本串。
func (r *Replayer) LoadedPolicyVersion() string { return r.loadedVersion }

// SamplerAlgo 返回当前抽样器标识。
func (r *Replayer) SamplerAlgo() string { return r.sampler.Algo() }

// Run 回放整份记录：判定逐条重跑，选路按 request_id 找配对的判定记录补上范围上下文。
//
// 记录文件本身不合法时直接返回错误（fail_closed），而不是产出一份「全是拒绝」的报告 ——
// 后者在 CI 里看起来也像失败，但会把「记录写坏了」误报成「策略变了」。
func (r *Replayer) Run(f File) (Report, error) {
	if err := f.Validate(r.now); err != nil {
		return Report{}, err
	}
	paired := r.indexDecisions(f.Decisions)
	outcomes := make([]Outcome, 0, len(f.Decisions)+len(f.Routings))
	for _, rec := range f.Decisions {
		outcomes = append(outcomes, r.ReplayDecision(rec))
	}
	for _, rec := range f.Routings {
		pair, hasPair := paired[rec.RequestID]
		outcomes = append(outcomes, r.ReplayRouting(rec, pair, hasPair))
	}
	return Report{
		Clock:               r.now,
		LoadedPolicyVersion: r.loadedVersion,
		Outcomes:            sortedOutcomes(outcomes),
	}, nil
}

// indexDecisions 按 request_id 建判定记录索引，每个 id 取稳定顺序里的第一条。
//
// 一个请求可能产生多条判定记录（模型可用性 + 原文出网授权），配对只是为了给选路回放
// 提供范围集合与上下文；取第一条前先按 (resource, action) 排序，保证乱序输入命中同一条。
func (r *Replayer) indexDecisions(recs []DecisionRecord) map[string]DecisionRecord {
	sorted := append([]DecisionRecord(nil), recs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].RequestID != sorted[j].RequestID {
			return sorted[i].RequestID < sorted[j].RequestID
		}
		if sorted[i].Resource != sorted[j].Resource {
			return sorted[i].Resource < sorted[j].Resource
		}
		return sorted[i].Action < sorted[j].Action
	})
	out := make(map[string]DecisionRecord, len(sorted))
	for _, rec := range sorted {
		if _, ok := out[rec.RequestID]; !ok {
			out[rec.RequestID] = rec
		}
	}
	return out
}

// ReplayDecision 重跑一条判定记录。
//
// 步骤固定：记录自校验 → 还原范围集合与上下文 → 按范围过滤策略包 → 复核版本来源 →
// 用固定时钟重跑 Evaluate 与 AllowsRawBody → 逐字段比对。
func (r *Replayer) ReplayDecision(rec DecisionRecord) Outcome {
	o := Outcome{Kind: KindDecision, RequestID: rec.RequestID}
	if err := rec.Validate(); err != nil {
		return reject(o, policy.ReasonContextInvalid, err.Error())
	}
	chain, err := rec.ScopeChain()
	if err != nil {
		return reject(o, policy.ReasonScopeMismatch, err.Error())
	}
	_, ctx, err := rec.PolicyContext()
	if err != nil {
		return reject(o, policy.ReasonContextInvalid, err.Error())
	}

	// FromBundles 内部就是 BundleSet.Filter(chain)：范围没有任何策略包覆盖时直接失败。
	// 这正是跨组织隔离要的语义 —— 喂 hospital-a 的记录却只给 university 的包，
	// 必须拒绝回放，而不是让 Evaluate 算出一条 deny 冒充「复现成功」。
	resolver, err := policy.FromBundles(r.set, chain)
	if err != nil {
		return reject(o, policy.ReasonScopeMismatch,
			fmt.Sprintf("已加载的策略集不覆盖记录范围 %s: %v", chain.Display(), err))
	}

	// §3.0：审计/计划里的 policy_version 必须来自实际加载并 Filter(chain) 后的子集版本。
	if resolver.Version() != rec.PolicyVersion {
		return reject(o, policy.ReasonPolicyVersionMissing,
			fmt.Sprintf("记录版本 %q，当前范围实际生效版本 %q", rec.PolicyVersion, resolver.Version()))
	}

	decision := resolver.Evaluate(ctx, chain, rec.Resource, rec.Action, r.now)
	granted, grantReason := resolver.AllowsRawBody(ctx, chain, r.now)

	collectDecisionDiffs(&o, rec, decision, granted, grantReason, r.strictReasonChain)
	if len(o.Diffs) == 0 {
		o.Status = StatusPassed
		o.normalize()
		return o
	}
	o.Status = StatusMismatch
	o.normalize()
	return o
}

func collectDecisionDiffs(o *Outcome, rec DecisionRecord, d policy.Decision, granted bool, grantReason policy.Reason, strict bool) {
	effect := policy.EffectDeny
	if d.Allowed {
		effect = policy.EffectAllow
	}
	addDiff(o, "effect", string(rec.Effect), string(effect))
	addDiff(o, "reason", string(rec.Reason), string(d.Reason))
	addDiff(o, "policy_version", rec.PolicyVersion, d.PolicyVersion)

	if got := timePtr(d.ExpiresAt); !sameTimePtr(rec.ExpiresAt, got) {
		addDiff(o, "expires_at", formatTimePtr(rec.ExpiresAt), formatTimePtr(got))
	}
	addDiff(o, "matched_count", fmt.Sprintf("%d", len(rec.Matched)), fmt.Sprintf("%d", len(d.Matched)))

	actual := ruleRefsOf(d.Matched)
	expected := rec.Matched
	limit := len(expected)
	if len(actual) < limit {
		limit = len(actual)
	}
	for i := 0; i < limit; i++ {
		collectRuleRefDiffs(o, fmt.Sprintf("matched/%d", i), expected[i], actual[i])
	}
	if len(expected) != len(actual) {
		// 命中链长度不同已经由 matched_count 体现，这里补一条「哪一侧多出来」的可读说明。
		o.Notes = append(o.Notes, fmt.Sprintf("命中链长度不一致：记录 %d 条，回放 %d 条", len(expected), len(actual)))
	}

	if rec.Winner != nil && len(actual) > 0 {
		collectRuleRefDiffs(o, "winner", *rec.Winner, actual[0])
	} else if rec.Winner == nil && len(actual) > 0 {
		addDiff(o, "winner", "<无命中>", actual[0].SortKey)
	} else if rec.Winner != nil && len(actual) == 0 {
		addDiff(o, "winner", rec.Winner.SortKey, "<无命中>")
	}

	// external_plaintext_allowed 只在记录为 allow 时参与比对。
	//
	// 拒绝记录里这一位被 DecisionRecord.Validate 钉死为 false（record.go 里那条
	// 「deny 不得带原文出网授权」的不变量），因此它对「这次到底允不允许原文出网」
	// 不携带任何信息；而回放侧是按**另一个资源**（body.raw/read）独立重算的 —— 直接比
	// 会把「带原文授权的范围里发生的一次真实拒绝」报成差异，那既不是策略变了也不是记录
	// 坏了。跳过这一位不损失信息：拒绝是否被复现由上面的 effect/reason 差异负责。
	// 允许记录照旧逐位比 —— 那里这一位才是真信号（裁决 2026-10-05 §0.2 第 1 条）。
	if rec.Effect != policy.EffectDeny {
		addDiff(o, "external_plaintext_allowed", fmt.Sprintf("%t", rec.ExternalPlaintextAllowed), fmt.Sprintf("%t", granted))
		if rec.ExternalPlaintextAllowed != granted {
			// 授权档位差异常来自两条门槛：允许档位（explicit/group 而非通配）与授权自身期限。
			o.Notes = append(o.Notes, fmt.Sprintf("原文出网授权回放结论 %v，原因码 %s", granted, string(grantReason)))
		}
	}

	if strict {
		want := reasonsList(rec.Reasons)
		got := reasonsList(d.Reasons)
		addDiff(o, "reasons_chain", want, got)
	}
}

func collectRuleRefDiffs(o *Outcome, prefix string, exp, got RuleRef) {
	addDiff(o, prefix+".subject", exp.Subject, got.Subject)
	addDiff(o, prefix+".scope", exp.Scope, got.Scope)
	addDiff(o, prefix+".resource", exp.Resource, got.Resource)
	addDiff(o, prefix+".action", exp.Action, got.Action)
	addDiff(o, prefix+".effect", string(exp.Effect), string(got.Effect))
	addDiff(o, prefix+".source", exp.Source, got.Source)
	addDiff(o, prefix+".version", exp.Version, got.Version)
	addDiff(o, prefix+".precedence", exp.Precedence, got.Precedence)
	addDiff(o, prefix+".sort_key", exp.SortKey, got.SortKey)
	if !sameTimePtr(exp.ExpiresAt, got.ExpiresAt) {
		addDiff(o, prefix+".expires_at", formatTimePtr(exp.ExpiresAt), formatTimePtr(got.ExpiresAt))
	}
}

// reasonsList 把原因链渲染成稳定顺序的字符串（policy.Reasons 已经排序，这里再兜一次）。
func reasonsList(in []policy.Reason) string {
	parts := make([]string, 0, len(in))
	for _, reason := range in {
		parts = append(parts, string(reason))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// verifyVersionComposedOf 检查记录里的版本串是否完全由已加载的包组成。
//
// 用于没有配对判定记录（因此拿不到范围集合）的选路记录：这时没法算出 Filter(chain)
// 的子集版本，但「版本串里每个 id@version 都真实加载过」仍然可验证。
// 返回缺少的 stamp，供调用方写明确错误。
func (r *Replayer) verifyVersionComposedOf(version string) []string {
	loaded := map[string]bool{}
	for _, b := range r.set.Bundles() {
		loaded[b.Stamp()] = true
	}
	var missing []string
	for _, stamp := range strings.Split(version, "|") {
		if stamp == "" {
			continue
		}
		if !loaded[stamp] {
			missing = append(missing, stamp)
		}
	}
	sort.Strings(missing)
	return missing
}

func addDiff(o *Outcome, field, expected, actual string) {
	if expected == actual {
		return
	}
	o.Diffs = append(o.Diffs, FieldDiff{Field: field, Expected: expected, Actual: actual})
}

func reject(o Outcome, reason policy.Reason, detail string) Outcome {
	o.Status = StatusRejected
	o.Reason = reason
	if detail != "" {
		o.Notes = append(o.Notes, detail)
	}
	o.normalize()
	return o
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "<空>"
	}
	return nowUTC(t).Format(time.RFC3339)
}
