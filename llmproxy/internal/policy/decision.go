package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Reason 是安全与路由决策的稳定原因码（§2.5、§5）。
//
// 字符串一旦发布就不改：审计查询、指标标签和管理台的解释都靠它做聚合。
// 新增原因码只能追加，禁止重命名或复用旧值表达新语义。
type Reason string

const (
	// 允许方向。
	ReasonExplicitAllow Reason = "explicit_allow"
	ReasonGroupAllow    Reason = "group_allow"
	ReasonDefaultAllow  Reason = "default_allow"

	// 拒绝方向。
	ReasonDenyRule            Reason = "deny_rule"
	ReasonNoMatchingRule      Reason = "no_matching_rule"
	ReasonModelNotAllowed     Reason = "model_not_allowed"
	ReasonIdentityMissing     Reason = "identity_missing"
	ReasonIdentityExpired     Reason = "identity_expired"
	ReasonIdentityNotYet      Reason = "identity_not_yet"
	ReasonContextInvalid      Reason = "context_invalid"
	ReasonEntitlementExpired  Reason = "entitlement_expired"
	ReasonConditionUnmet      Reason = "condition_unmet"
	ReasonScopeMismatch       Reason = "scope_mismatch"
	ReasonDataLevelDenied     Reason = "data_level_denied"
	ReasonRegionDenied        Reason = "region_denied"
	ReasonRawBodyGrantMissing Reason = "raw_body_grant_missing"
	// ReasonKnowledgeContentGrantMissing 是「正文进网关」这一侧缺授权（决策包 §8.1）。
	// 与 raw_body_grant_missing 分开是因为排查方向相反：那个是「客户端原文要出网」，
	// 这个是「源侧正文要进来」，同一句话盖不住两种合规事件。
	ReasonKnowledgeContentGrantMissing Reason = "knowledge_content_grant_missing"
	ReasonPolicyVersionMissing         Reason = "policy_version_missing"

	// 路由方向（由 internal/routing 产生，枚举在此登记以保证跨包一致）。
	ReasonNoCandidate             Reason = "no_candidate"
	ReasonCandidateUnhealthy      Reason = "candidate_unhealthy"
	ReasonCandidatePolicyExcluded Reason = "candidate_policy_excluded"
	ReasonCandidateRegionExcluded Reason = "candidate_region_excluded"
	ReasonCandidateLevelExcluded  Reason = "candidate_level_excluded"
	ReasonCandidateCostUnknown    Reason = "candidate_cost_unknown"
	// ReasonCandidateCapabilityUnmatched 是「这家上游承接不了这个模型名 / 缺所需能力」。
	// 与 model_not_allowed 的区别是排查方向：那是策略不授权，这是技术不承接，
	// 混用一个码会让运维去改策略而不是改模型映射（D 包 §3.D 申请追加）。
	ReasonCandidateCapabilityUnmatched Reason = "candidate_capability_unmatched"
	ReasonAffinityHit                  Reason = "affinity_hit"
	ReasonWeightedChoice               Reason = "weighted_choice"
	ReasonCheapestFirst                Reason = "cheapest_first"
	ReasonFallbackUsed                 Reason = "fallback_used"
	ReasonRetryExhausted               Reason = "retry_exhausted"
	ReasonPlanExpired                  Reason = "plan_expired"
	ReasonReplaySeedMissing            Reason = "replay_seed_missing"
)

var allReasons = map[Reason]bool{}

func init() {
	for _, r := range []Reason{
		ReasonExplicitAllow, ReasonGroupAllow, ReasonDefaultAllow,
		ReasonDenyRule, ReasonNoMatchingRule, ReasonModelNotAllowed,
		ReasonIdentityMissing, ReasonIdentityExpired, ReasonIdentityNotYet,
		ReasonContextInvalid, ReasonEntitlementExpired,
		ReasonConditionUnmet, ReasonScopeMismatch, ReasonDataLevelDenied,
		ReasonRegionDenied, ReasonRawBodyGrantMissing, ReasonKnowledgeContentGrantMissing,
		ReasonPolicyVersionMissing,
		ReasonNoCandidate, ReasonCandidateUnhealthy, ReasonCandidatePolicyExcluded,
		ReasonCandidateRegionExcluded, ReasonCandidateLevelExcluded,
		ReasonCandidateCostUnknown, ReasonCandidateCapabilityUnmatched,
		ReasonAffinityHit, ReasonWeightedChoice,
		ReasonCheapestFirst, ReasonFallbackUsed, ReasonRetryExhausted,
		ReasonPlanExpired, ReasonReplaySeedMissing,
	} {
		allReasons[r] = true
	}
}

// Valid 报告原因码是否在注册表内。测试用它挡住自然语言或拼错的值。
func (r Reason) Valid() bool { return allReasons[r] }

// Reasons 返回去重排序后的原因码副本，用于序列化进审计。
func Reasons(in []Reason) []Reason {
	if len(in) == 0 {
		return nil
	}
	set := make(map[Reason]bool, len(in))
	out := make([]Reason, 0, len(in))
	for _, r := range in {
		if r == "" {
			continue
		}
		if !set[r] {
			set[r] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Effect 是授权规则的效力方向（§2.4）。
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

func (e Effect) Valid() bool { return e == EffectAllow || e == EffectDeny }

func (e Effect) String() string { return string(e) }

// Precedence 是 §2.4 固定的拒绝优先级：
//
//	deny > explicit_allow > group_allow > default
type Precedence int

const (
	PrecedenceDeny Precedence = iota
	PrecedenceExplicitAllow
	PrecedenceGroupAllow
	PrecedenceDefault
)

// String 给出可进审计的档位名。
func (p Precedence) String() string {
	switch p {
	case PrecedenceDeny:
		return "deny"
	case PrecedenceExplicitAllow:
		return "explicit_allow"
	case PrecedenceGroupAllow:
		return "group_allow"
	case PrecedenceDefault:
		return "default"
	}
	return "unknown"
}

// MatchedRule 是一次判定实际命中的规则摘要，进审计以便回放和解释。
// Matched 按优先级升序排列，**第 0 条即决定性规则**。
// 只记录选择器和标识，不记录 Conditions 的值（可能含组织内敏感命名）。
type MatchedRule struct {
	Subject    string     `json:"subject"`
	Scope      string     `json:"scope,omitempty"`
	Resource   string     `json:"resource"`
	Action     string     `json:"action"`
	Effect     Effect     `json:"effect"`
	Source     string     `json:"source,omitempty"`
	Version    string     `json:"version,omitempty"`
	Precedence Precedence `json:"precedence"`
	ExpiresAt  time.Time  `json:"expires_at,omitempty"`
}

// Decision 是一次安全判定的结果。
//
// Allowed 为 false 时 Reason 必定有效；Reasons 给出完整命中链，
// 供管理台解释「为什么是这个结论」。
type Decision struct {
	Allowed       bool          `json:"allowed"`
	Reason        Reason        `json:"reason"`
	Reasons       []Reason      `json:"reasons,omitempty"`
	Matched       []MatchedRule `json:"matched,omitempty"`
	PolicyVersion string        `json:"policy_version,omitempty"`
	ExpiresAt     time.Time     `json:"expires_at,omitempty"`
}

// Explain 给人看的说明。只用于日志和界面：**不得**包含正文、密钥或 Conditions 值，
// 内容全部来自原因码和规则选择器。
func (d Decision) Explain() string {
	var b strings.Builder
	if d.Allowed {
		b.WriteString("允许")
	} else {
		b.WriteString("拒绝")
	}
	fmt.Fprintf(&b, "（%s）", d.Reason)
	if len(d.Matched) > 0 {
		last := d.Matched[len(d.Matched)-1]
		fmt.Fprintf(&b, " 命中规则 %s %s/%s 档位 %s", last.Subject, last.Resource, last.Action, last.Precedence)
	}
	if d.PolicyVersion != "" {
		fmt.Fprintf(&b, " 策略版本 %s", d.PolicyVersion)
	}
	return b.String()
}
