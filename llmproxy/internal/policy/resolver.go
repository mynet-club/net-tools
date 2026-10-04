package policy

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Resolver 是按 §2.4 固定优先级求值的策略内核。
//
// 构造完成后规则集不再变化，因此可以被多个请求并发使用（DoD 4）。
// 求值不读时钟以外的外部状态：now 由调用方显式传入，回放时传当时的时间即可复现。
type Resolver struct {
	rules   []Entitlement
	version string
}

var ErrResolver = errors.New("policy: 策略内核初始化失败")

// NewResolver 构造内核。version 必须来自实际加载的策略集（BundleSet.PolicyVersion），
// 不允许 handler 临时拼接 —— 否则审计里的版本和真正生效的规则内容对不上。
func NewResolver(version string, rules ...Entitlement) (*Resolver, error) {
	if version == "" {
		return nil, fmt.Errorf("%w: version 不能为空", ErrResolver)
	}
	// 去重：同一份规则可能来自多个策略包的并集（例如系统包和组织包写了同一条），
	// 重复规则会命中多次但结论不变，去重只是为了让 Matched 和摘要稳定可读。
	seen := make(map[string]bool, len(rules))
	kept := make([]Entitlement, 0, len(rules))
	for _, raw := range rules {
		if err := raw.Validate(); err != nil {
			return nil, err
		}
		key := raw.Effect.String() + "\x00" + raw.SortKey()
		if seen[key] {
			continue
		}
		seen[key] = true
		kept = append(kept, raw)
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].SortKey() < kept[j].SortKey() })
	return &Resolver{rules: kept, version: version}, nil
}

// FromBundles 用覆盖 chain 的策略包构造内核，版本串取自包集合本身。
func FromBundles(set *BundleSet, chain ScopeChain) (*Resolver, error) {
	if set == nil {
		return nil, fmt.Errorf("%w: 策略集为空", ErrResolver)
	}
	subset, err := set.Filter(chain)
	if err != nil {
		return nil, err
	}
	version, err := subset.PolicyVersion()
	if err != nil {
		return nil, err
	}
	return NewResolver(version, subset.EntitlementsFor(chain)...)
}

// Version 返回生效的策略内容版本。
func (r *Resolver) Version() string { return r.version }

// RuleCount 返回去重后的规则条数，用于启动日志和自检。
func (r *Resolver) RuleCount() int { return len(r.rules) }

// hit 是一条命中规则的求值中间结果。
type hit struct {
	rule       Entitlement
	precedence Precedence
}

// Evaluate 求值一次授权判定。chain 是本次请求覆盖的范围集合（见 ScopeChain）。
//
// 顺序固定为：上下文合法性 → 身份时效 → 版本存在 → 规则命中 → 优先级选取。
// 前两步失败直接拒绝（fail-closed），不做「拿不到身份就按默认放行」的兜底。
func (r *Resolver) Evaluate(ctx PolicyContext, chain ScopeChain, resource, action string, now time.Time) Decision {
	reasons := make([]Reason, 0, 4)

	if err := ctx.Validate(); err != nil {
		reason := ReasonIdentityMissing
		if errors.Is(err, ErrPurposeMissing) || errors.Is(err, ErrContext) {
			reason = ReasonContextInvalid
		}
		return Decision{Allowed: false, Reason: reason, Reasons: Reasons(reasons), PolicyVersion: r.version}
	}
	if err := ctx.Identity.ValidAt(now); err != nil {
		reason := ReasonIdentityExpired
		if errors.Is(err, ErrIdentityNotYet) {
			reason = ReasonIdentityNotYet
		}
		return Decision{Allowed: false, Reason: reason, Reasons: Reasons(reasons), PolicyVersion: r.version}
	}
	if r.version == "" {
		return Decision{Allowed: false, Reason: ReasonPolicyVersionMissing, Reasons: Reasons(reasons)}
	}
	if len(chain) == 0 {
		// 没有范围就没法判定规则该不该生效；拒绝而不是当成「不限范围」，
		// 否则上游漏传 scope 会静默放大所有规则的生效面。
		return Decision{Allowed: false, Reason: ReasonScopeMismatch, Reasons: Reasons(append(reasons, ReasonScopeMismatch)), PolicyVersion: r.version}
	}

	var hits []hit
	skippedExpired := false
	levelBlocked := false
	for _, rule := range r.rules {
		if !rule.matchesResource(resource) || !rule.matchesAction(action) {
			continue
		}
		if !rule.matchesChain(chain) {
			continue
		}
		precedence, ok := rule.matchSubject(ctx, chain)
		if !ok {
			continue
		}
		if rule.expired(now) {
			// 记录「本来会命中但已过期」，让拒绝原因能区分「没配」和「配过但过期了」——
			// 现场排查时这两个结论的动作完全不同。
			skippedExpired = true
			continue
		}
		// Conditions 是规则的前置条件，对 allow 和 deny 完全一致：不满足就不生效。
		// 「confidential 及以上禁止」写成 deny + min-data-level，
		// 「只允许到 confidential」写成 allow + max-data-level。
		if met, why := rule.conditionsMet(ctx); !met {
			if why == ReasonDataLevelDenied {
				levelBlocked = true
			}
			reasons = append(reasons, why)
			continue
		}
		if rule.Effect == EffectDeny {
			precedence = PrecedenceDeny
		}
		hits = append(hits, hit{rule: rule, precedence: precedence})
	}

	if len(hits) == 0 {
		// 优先级：过期 > 分级压制 > 模型未授权 > 无匹配规则。
		// 分级压制单独成一个结论是必要的 —— 它说明策略确实存在，
		// 只是这次请求的数据等级越了界，运维要调的是分级而不是白名单。
		reason := ReasonNoMatchingRule
		switch {
		case skippedExpired:
			reason = ReasonEntitlementExpired
		case levelBlocked:
			reason = ReasonDataLevelDenied
		case ResourceOf(resource) == NamespaceModel:
			reason = ReasonModelNotAllowed
		}
		return Decision{
			Allowed:       false,
			Reason:        reason,
			Reasons:       Reasons(reasons),
			PolicyVersion: r.version,
		}
	}

	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].precedence != hits[j].precedence {
			return hits[i].precedence < hits[j].precedence
		}
		return hits[i].rule.SortKey() < hits[j].rule.SortKey()
	})

	winner := hits[0]
	matched := make([]MatchedRule, 0, len(hits))
	for _, h := range hits {
		matched = append(matched, h.rule.matchedRule(h.precedence))
	}

	if winner.rule.Effect == EffectDeny {
		// 主原因对模型资源沿用 model_not_allowed，与现网 403 的错误语义对齐；
		// deny_rule 同时进原因链，保证审计能区分「被显式禁止」和「压根没配 allow」。
		reason := ReasonDenyRule
		if ResourceOf(resource) == NamespaceModel {
			reason = ReasonModelNotAllowed
		}
		return Decision{
			Allowed:       false,
			Reason:        reason,
			Reasons:       Reasons(append(reasons, ReasonDenyRule, reason)),
			Matched:       matched,
			PolicyVersion: r.version,
			ExpiresAt:     earliestExpiry(winner.rule, ctx.Identity, now),
		}
	}

	var allowed Reason
	switch winner.precedence {
	case PrecedenceExplicitAllow:
		allowed = ReasonExplicitAllow
	case PrecedenceGroupAllow:
		allowed = ReasonGroupAllow
	default:
		allowed = ReasonDefaultAllow
	}
	return Decision{
		Allowed:       true,
		Reason:        allowed,
		Reasons:       Reasons(append(reasons, allowed)),
		Matched:       matched,
		PolicyVersion: r.version,
		ExpiresAt:     earliestExpiry(winner.rule, ctx.Identity, now),
	}
}

// AllowsRawBody 判定能否把未脱敏正文交给外部 sidecar（§2.9 规则 3、4）。
//
// 两道门槛：
//  1. 只认显式或组级 allow 规则 —— 通配 default_allow 不算授权，否则「配了一条
//     全局兜底放行」就顺手把原文出网能力发给所有处理器，方向完全错了；
//  2. **授权本身**必须带 ExpiresAt。不能用 Decision.ExpiresAt 代替：那个值是
//     「规则与身份里较早的到期点」，身份 TTL 会让一条永不过期的授权看起来有期限，
//     于是永久出网授权被静默放行 —— 规则 4 要的正是让配置者补上授权自身的期限。
func (r *Resolver) AllowsRawBody(ctx PolicyContext, chain ScopeChain, now time.Time) (bool, Reason) {
	d := r.Evaluate(ctx, chain, ResourceBodyRaw, ActionRead, now)
	if !d.Allowed {
		return false, d.Reason
	}
	switch d.Reason {
	case ReasonExplicitAllow, ReasonGroupAllow:
		if len(d.Matched) == 0 {
			return false, ReasonRawBodyGrantMissing
		}
		if d.Matched[0].ExpiresAt.IsZero() {
			return false, ReasonRawBodyGrantMissing
		}
		return true, d.Reason
	}
	return false, ReasonRawBodyGrantMissing
}

// AllowsKnowledgeContent 判定能否向知识源索取文档正文（决策包 §8.1）。
//
// 门槛与 AllowsRawBody 完全同形，因为要防的是同一类错：
//  1. 只认显式或组级 allow —— 通配 default_allow 不算授权，否则一条全局兜底放行
//     就把「正文进网关」发给了所有人；
//  2. 授权本身必须带 ExpiresAt（不能用 Decision.ExpiresAt 代替，理由同 AllowsRawBody）。
//
// 这里**不**检查「平台配置有没有打开正文开关」：配置位在接线侧（server），
// A 包只回答「这个人、这个范围，凭什么可以拿到正文」。两道门各由一侧持有，
// 缺任何一道都不交付正文（见 docs/3.0-decision-packages.md §8.1 的开关形状）。
func (r *Resolver) AllowsKnowledgeContent(ctx PolicyContext, chain ScopeChain, now time.Time) (bool, Reason) {
	d := r.Evaluate(ctx, chain, ResourceKnowledgeContent, ActionRead, now)
	if !d.Allowed {
		return false, d.Reason
	}
	switch d.Reason {
	case ReasonExplicitAllow, ReasonGroupAllow:
		if len(d.Matched) == 0 {
			return false, ReasonKnowledgeContentGrantMissing
		}
		if d.Matched[0].ExpiresAt.IsZero() {
			return false, ReasonKnowledgeContentGrantMissing
		}
		return true, d.Reason
	}
	return false, ReasonKnowledgeContentGrantMissing
}

func (e Entitlement) matchedRule(p Precedence) MatchedRule {
	return MatchedRule{
		Subject:    e.Subject,
		Scope:      e.Scope,
		Resource:   e.Resource,
		Action:     e.Action,
		Effect:     e.Effect,
		Source:     e.Source,
		Version:    e.Version,
		Precedence: p,
		ExpiresAt:  e.ExpiresAt,
	}
}

// earliestExpiry 给出「这次结论最晚什么时候必须重新判定」：取命中规则与身份的较早到期点。
// 下游可以据此缓存判定结果，但缓存时长绝不能超过身份或规则的 TTL。
func earliestExpiry(rule Entitlement, id Identity, now time.Time) time.Time {
	var out time.Time
	for _, candidate := range []time.Time{rule.ExpiresAt, id.ExpiresAt} {
		if candidate.IsZero() {
			continue
		}
		if out.IsZero() || candidate.Before(out) {
			out = candidate
		}
	}
	if !out.IsZero() && out.Before(now) {
		return out
	}
	return out
}
