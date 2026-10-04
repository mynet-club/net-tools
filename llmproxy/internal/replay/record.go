package replay

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/routing"
)

// 记录结构的字段命名纪律（§2.8 / §2.9 / §5）：
//
// 一次在线请求的判定与选路要能被审计和回放，但审计表绝不能用它复原正文。
// 因此本文件里的每个结构只写「标识、档位、原因码、时间」，不写任何可能承载
// 内容的字段：连 body / digest-of-body / prompt / messages / api_key / token /
// password / raw 这类名字都不允许出现 —— 字段名本身就会诱导实现方往里塞东西。
// leak_test.go 用反射与 JSON 键扫描把这条纪律变成会失败的断言。

// SubjectSnapshot 是身份快照里与判定有关的那部分字段。
//
// 刻意不含 DisplayName：显示名属于个人信息，判定不需要它（§2.1 就禁止拿它当键），
// 记进审计只会扩大泄露面。Roles/Groups/Projects/AuthMethods 必须留，
// 因为 Conditions 与主体选择器按它们命中；IssuedAt/ExpiresAt 也必须留，
// 否则回放无法复现 identity_expired。
type SubjectSnapshot struct {
	Subject     string     `json:"subject"`
	Source      string     `json:"source"`
	Roles       []string   `json:"roles,omitempty"`
	Groups      []string   `json:"groups,omitempty"`
	Projects    []string   `json:"projects,omitempty"`
	AuthMethods []string   `json:"auth_methods,omitempty"`
	IssuedAt    *time.Time `json:"issued_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// Identity 还原成判定用的 policy.Identity（成员关系按 policy 的规则归一化后校验）。
func (s SubjectSnapshot) Identity() (policy.Identity, error) {
	id := policy.Identity{
		Subject:     s.Subject,
		Source:      s.Source,
		Roles:       append([]string(nil), s.Roles...),
		Groups:      append([]string(nil), s.Groups...),
		Projects:    append([]string(nil), s.Projects...),
		AuthMethods: append([]string(nil), s.AuthMethods...),
		IssuedAt:    timeValue(s.IssuedAt),
		ExpiresAt:   timeValue(s.ExpiresAt),
	}
	id = id.Normalize()
	if err := id.Validate(); err != nil {
		return policy.Identity{}, err
	}
	return id, nil
}

func subjectSnapshotOf(id policy.Identity) SubjectSnapshot {
	id = id.Normalize()
	return SubjectSnapshot{
		Subject:     id.Subject,
		Source:      id.Source,
		Roles:       append([]string(nil), id.Roles...),
		Groups:      append([]string(nil), id.Groups...),
		Projects:    append([]string(nil), id.Projects...),
		AuthMethods: append([]string(nil), id.AuthMethods...),
		IssuedAt:    timePtr(id.IssuedAt),
		ExpiresAt:   timePtr(id.ExpiresAt),
	}
}

// ContextSnapshot 是 PolicyContext 的可序列化投影（§2.2）。
//
// 分级存等级名而不是 policy 的整数序数：等级排序是 A 包的内部 iota，
// 记录把它钉死会让将来的常量调整悄悄改变历史语义。名字则要过 ParseDataLevel，
// 拼错立刻报错（fail-closed）。
type ContextSnapshot struct {
	Purpose        string     `json:"purpose"`
	Organization   string     `json:"organization,omitempty"`
	Project        string     `json:"project,omitempty"`
	DataLevel      string     `json:"data_level"`
	AllowedRegions []string   `json:"allowed_regions,omitempty"`
	WiringMode     WiringMode `json:"wiring_mode,omitempty"`
}

// PolicyContext 还原成判定用的上下文。
func (c ContextSnapshot) PolicyContext(id policy.Identity) (policy.PolicyContext, error) {
	level, err := policy.ParseDataLevel(c.DataLevel)
	if err != nil {
		return policy.PolicyContext{}, err
	}
	ctx := policy.PolicyContext{
		Identity:       id,
		Purpose:        c.Purpose,
		Organization:   c.Organization,
		Project:        c.Project,
		DataLevel:      level,
		AllowedRegions: append([]string(nil), c.AllowedRegions...),
	}
	ctx = ctx.Normalize()
	if err := ctx.Validate(); err != nil {
		return policy.PolicyContext{}, err
	}
	return ctx, nil
}

func contextSnapshotOf(ctx policy.PolicyContext, mode WiringMode) ContextSnapshot {
	regions := append([]string(nil), ctx.AllowedRegions...)
	sort.Strings(regions)
	return ContextSnapshot{
		Purpose:        ctx.Purpose,
		Organization:   ctx.Organization,
		Project:        ctx.Project,
		DataLevel:      ctx.DataLevel.String(),
		AllowedRegions: regions,
		WiringMode:     mode,
	}
}

// RuleRef 是对命中规则的最小引用：只有标识，没有规则内容。
//
// Conditions 的取值绝不进记录（项目代号、内部组名一旦随审计扩散就收不回来，
// 这也是 A 包 Decision.Explain() 同样的口径）。SortKey 显式存下来，
// 回放时可以直接断言「决定性规则还是那条」，而不必依赖规则数组的书写顺序。
type RuleRef struct {
	Subject    string        `json:"subject"`
	Scope      string        `json:"scope,omitempty"`
	Resource   string        `json:"resource"`
	Action     string        `json:"action"`
	Effect     policy.Effect `json:"effect"`
	Source     string        `json:"source,omitempty"`
	Version    string        `json:"version,omitempty"`
	Precedence string        `json:"precedence"`
	SortKey    string        `json:"sort_key"`
	ExpiresAt  *time.Time    `json:"expires_at,omitempty"`
}

// ruleKeyOf 复算 A 包 Entitlement.SortKey()（subject|resource|action|version）。
// MatchedRule 正是这四个字段的投影，所以不需要规则本身就能还原这个键。
func ruleKeyOf(m policy.MatchedRule) string {
	return strings.Join([]string{m.Subject, m.Resource, m.Action, m.Version}, "|")
}

func ruleRefOf(m policy.MatchedRule) RuleRef {
	return RuleRef{
		Subject:    m.Subject,
		Scope:      m.Scope,
		Resource:   m.Resource,
		Action:     m.Action,
		Effect:     m.Effect,
		Source:     m.Source,
		Version:    m.Version,
		Precedence: m.Precedence.String(),
		SortKey:    ruleKeyOf(m),
		ExpiresAt:  timePtr(m.ExpiresAt),
	}
}

// sameRuleRef 逐字段比较规则引用。
// 不用 == 比较整个结构体：time.Time 用 == 会连单调时钟和地点指针一起比，
// 从 JSON 复原出来的那条永远和现场那条「不相等」，属于假差异。
func sameRuleRef(a, b RuleRef) bool {
	return a.Subject == b.Subject &&
		a.Scope == b.Scope &&
		a.Resource == b.Resource &&
		a.Action == b.Action &&
		a.Effect == b.Effect &&
		a.Source == b.Source &&
		a.Version == b.Version &&
		a.Precedence == b.Precedence &&
		a.SortKey == b.SortKey &&
		sameTimePtr(a.ExpiresAt, b.ExpiresAt)
}

// DecisionRecord 是一次安全判定的回放记录（§2.8）。
type DecisionRecord struct {
	RequestID     string            `json:"request_id"`
	RecordedAt    time.Time         `json:"recorded_at"`
	PolicyVersion string            `json:"policy_version"`
	Chain         []policy.ScopeRef `json:"scope_chain"`
	Subject       SubjectSnapshot   `json:"subject"`
	Ctx           ContextSnapshot   `json:"context"`
	Resource      string            `json:"resource"`
	Action        string            `json:"action"`

	Effect    policy.Effect   `json:"effect"`
	Reason    policy.Reason   `json:"reason"`
	Reasons   []policy.Reason `json:"reasons,omitempty"`
	Winner    *RuleRef        `json:"winner,omitempty"`
	Matched   []RuleRef       `json:"matched,omitempty"`
	ExpiresAt *time.Time      `json:"expires_at,omitempty"`

	// ExternalPlaintextAllowed 记录 AllowsRawBody 的结论：是否允许未脱敏文本出网给
	// sidecar（§2.9 规则 3、4）。它是个布尔，正文本身从不进记录。
	ExternalPlaintextAllowed bool `json:"external_plaintext_allowed"`
}

// Validate 校验记录的自洽性。任何不一致都在回放前失败，而不是回放中「大概对得上」。
func (r DecisionRecord) Validate() error {
	if strings.TrimSpace(r.RequestID) == "" {
		return fmt.Errorf("%w: request_id 不能为空", ErrRecordInvalid)
	}
	if strings.ContainsAny(r.RequestID, " \t\r\n") {
		return fmt.Errorf("%w: request_id %q 含空白，无法作为配对键", ErrRecordInvalid, r.RequestID)
	}
	if r.RecordedAt.IsZero() {
		return fmt.Errorf("%w: %s 缺 recorded_at", ErrRecordInvalid, r.RequestID)
	}
	if r.PolicyVersion == "" {
		return fmt.Errorf("%w: %s 缺 policy_version（必须来自实际加载的策略包，§3.0）", ErrRecordInvalid, r.RequestID)
	}
	if len(r.Chain) == 0 {
		return fmt.Errorf("%w: %s 的 scope_chain 为空", ErrRecordInvalid, r.RequestID)
	}
	if err := r.chainNormalized(); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrRecordInvalid, r.RequestID, err)
	}
	if _, err := r.Subject.Identity(); err != nil {
		return fmt.Errorf("%w: %s: subject: %v", ErrRecordInvalid, r.RequestID, err)
	}
	if _, err := r.Ctx.PolicyContext(mustIdentity(r.Subject)); err != nil {
		return fmt.Errorf("%w: %s: context: %v", ErrRecordInvalid, r.RequestID, err)
	}
	if !r.Ctx.WiringMode.Valid() {
		return fmt.Errorf("%w: %s: wiring_mode %q 不在 shadow|enforce|legacy 内", ErrRecordInvalid, r.RequestID, r.Ctx.WiringMode)
	}
	if strings.TrimSpace(r.Resource) == "" || strings.TrimSpace(r.Action) == "" {
		return fmt.Errorf("%w: %s: resource/action 必填", ErrRecordInvalid, r.RequestID)
	}
	if !r.Effect.Valid() {
		return fmt.Errorf("%w: %s: effect %q", ErrRecordInvalid, r.RequestID, string(r.Effect))
	}
	if !r.Reason.Valid() {
		return fmt.Errorf("%w: %s: 未注册的原因码 %q", ErrRecordInvalid, r.RequestID, string(r.Reason))
	}
	if r.Effect == policy.EffectAllow && !reasonNames[r.Reason] {
		return fmt.Errorf("%w: %s: 放行的结论必须落在 allow 档原因码上，当前 %q", ErrRecordInvalid, r.RequestID, string(r.Reason))
	}
	if r.Effect == policy.EffectDeny && reasonNames[r.Reason] {
		return fmt.Errorf("%w: %s: 拒绝的结论不能用 allow 档原因码 %q", ErrRecordInvalid, r.RequestID, string(r.Reason))
	}
	for _, reason := range r.Reasons {
		if !reason.Valid() {
			return fmt.Errorf("%w: %s: 原因链含未注册项 %q", ErrRecordInvalid, r.RequestID, string(reason))
		}
	}
	if len(r.Matched) == 0 && r.Winner != nil {
		return fmt.Errorf("%w: %s: 没有命中规则却写了 winner", ErrRecordInvalid, r.RequestID)
	}
	if len(r.Matched) > 0 {
		if r.Winner == nil {
			return fmt.Errorf("%w: %s: 有命中规则但缺 winner", ErrRecordInvalid, r.RequestID)
		}
		// A 包约定 Matched[0] 就是决定性规则；记录必须遵守同一条，
		// 否则回放比对的是「随便一条命中」而不是决定结论的那条。
		if !sameRuleRef(*r.Winner, r.Matched[0]) {
			return fmt.Errorf("%w: %s: winner 必须等于 matched[0]（决定性规则）", ErrRecordInvalid, r.RequestID)
		}
	}
	if r.ExternalPlaintextAllowed && r.Effect != policy.EffectAllow {
		return fmt.Errorf("%w: %s: 判定为拒绝时不可能授予原文出网", ErrRecordInvalid, r.RequestID)
	}
	return nil
}

// chainNormalized 要求范围链已按 policy 的稳定顺序排好。
// 未归一的链会让同一次判定产生不同的记录（不同的 Digest / 不同的排序输入），
// 回放的前提就没了 —— 所以这里失败，而不是悄悄排一下。
func (r DecisionRecord) chainNormalized() error {
	refs := make([]policy.ScopeRef, 0, len(r.Chain))
	for _, s := range r.Chain {
		if err := s.Validate(); err != nil {
			return err
		}
		refs = append(refs, s)
	}
	want, err := policy.NewScopeChain(refs...)
	if err != nil {
		return err
	}
	if len(want) != len(refs) {
		return fmt.Errorf("scope_chain 含重复范围")
	}
	for i := range want {
		if want[i] != refs[i] {
			return fmt.Errorf("scope_chain 必须按 (kind, id) 稳定排序后再写入，当前第 %d 项是 %s", i, refs[i].Display())
		}
	}
	return nil
}

// ScopeChain 还原判定范围集合（已校验过顺序，这里只做类型转换）。
func (r DecisionRecord) ScopeChain() (policy.ScopeChain, error) {
	chain, err := policy.NewScopeChain(r.Chain...)
	if err != nil {
		return nil, err
	}
	return chain, nil
}

// PolicyContext 还原身份 + 上下文，一次调用给齐判定需要的两个输入。
func (r DecisionRecord) PolicyContext() (policy.Identity, policy.PolicyContext, error) {
	id, err := r.Subject.Identity()
	if err != nil {
		return policy.Identity{}, policy.PolicyContext{}, err
	}
	ctx, err := r.Ctx.PolicyContext(id)
	if err != nil {
		return policy.Identity{}, policy.PolicyContext{}, err
	}
	return id, ctx, nil
}

// DecisionCapture 是从在线请求现场构造记录所需的输入。
//
// PolicyVersion 只从 Decision 取（A 包里它由 BundleSet.Filter(chain).PolicyVersion()
// 注入），这里不接受任何外部传入的版本串 —— §3.0 要求 RoutingPlan/审计的版本必须来自
// 实际加载并过滤后的策略包，不能被 handler 临时拼接。
type DecisionCapture struct {
	RequestID  string
	RecordedAt time.Time
	Chain      policy.ScopeChain
	Subject    policy.Identity
	Ctx        policy.PolicyContext
	Resource   string
	Action     string
	Decision   policy.Decision

	// ExternalPlaintextAllowed 来自 Resolver.AllowsRawBody 的第一个返回值。
	ExternalPlaintextAllowed bool

	// WiringMode 是 §3.0 的接线阶段；留空按 enforce 处理（记录默认描述真实生效的决策）。
	WiringMode WiringMode
}

// DecisionRecordFrom 把一次在线判定落成回放记录。
func DecisionRecordFrom(c DecisionCapture) (DecisionRecord, error) {
	if c.Decision.Reason == "" {
		return DecisionRecord{}, fmt.Errorf("%w: 判定结果缺原因码", ErrRecordInvalid)
	}
	mode := c.WiringMode
	if mode == "" {
		mode = ModeEnforce
	}
	chain := append([]policy.ScopeRef(nil), c.Chain...)
	sortedChain, err := policy.NewScopeChain(chain...)
	if err != nil {
		return DecisionRecord{}, fmt.Errorf("%w: scope_chain: %v", ErrRecordInvalid, err)
	}
	effect := policy.EffectDeny
	if c.Decision.Allowed {
		effect = policy.EffectAllow
	}
	rec := DecisionRecord{
		RequestID:                c.RequestID,
		RecordedAt:               nowUTC(c.RecordedAt),
		PolicyVersion:            c.Decision.PolicyVersion,
		Chain:                    sortedChain,
		Subject:                  subjectSnapshotOf(c.Subject),
		Ctx:                      contextSnapshotOf(c.Ctx, mode),
		Resource:                 c.Resource,
		Action:                   c.Action,
		Effect:                   effect,
		Reason:                   c.Decision.Reason,
		Reasons:                  append([]policy.Reason(nil), c.Decision.Reasons...),
		Matched:                  ruleRefsOf(c.Decision.Matched),
		ExpiresAt:                timePtr(c.Decision.ExpiresAt),
		ExternalPlaintextAllowed: c.ExternalPlaintextAllowed,
	}
	if len(rec.Matched) > 0 {
		winner := rec.Matched[0]
		rec.Winner = &winner
	}
	if err := rec.Validate(); err != nil {
		return DecisionRecord{}, err
	}
	return rec, nil
}

func ruleRefsOf(ms []policy.MatchedRule) []RuleRef {
	out := make([]RuleRef, 0, len(ms))
	for _, m := range ms {
		out = append(out, ruleRefOf(m))
	}
	return out
}

func mustIdentity(s SubjectSnapshot) policy.Identity {
	id, err := s.Identity()
	if err != nil {
		return policy.Identity{}
	}
	return id
}

// RoutingRecord 是一次选路决策的回放记录（§2.8：在线至少记录
// routing_seed、候选摘要、最终计划和 policy_version）。
type RoutingRecord struct {
	RequestID     string    `json:"request_id"`
	RecordedAt    time.Time `json:"recorded_at"`
	PolicyVersion string    `json:"policy_version"`

	RoutingSeed      string `json:"routing_seed,omitempty"`
	RoutingEpoch     string `json:"routing_epoch,omitempty"`
	SamplingAlgo     string `json:"sampling_algo,omitempty"`
	CandidatesDigest string `json:"candidates_digest"`

	// Candidates 是当时的候选池，必须按 policy.SortCandidates 的稳定顺序写入：
	// §2.8 明确禁止依赖 map 遍历顺序，抽样和回放共用同一个排序函数才对得上。
	Candidates []policy.RouteCandidate `json:"candidates"`

	Plan       policy.RoutingPlan `json:"plan"`
	Rejections []policy.Rejection `json:"rejections,omitempty"`

	// Replay 是那次规划的**完整回放输入**（schema v2，2026-10-04 裁决第 5 条 B）。
	//
	// 为什么 Candidates 那份投影不够：它是配置级候选，没有当时的健康度、冷却截止、
	// 观测延迟、价目可得性，也没有目标函数、能力要求、粘性、决策时刻与计划 TTL ——
	// 而首选顺序恰恰由这些运行时事实决定。缺任何一位，重跑得出的都是「今天的池子」
	// 的次序，不是当时那次的次序。
	//
	// nil = 这条记录采自 v1，或当时组不出快照：只能做解释性回放。
	// 有值不等于能声称逐位 —— 还要过 sampling_algo 那一层核对，见 ReplayRouting。
	Replay *routing.ReplayInput `json:"replay_snapshot,omitempty"`
}

// SamplingAlgoOrDefault 返回记录声明的抽样算法标识；空值按本包默认算法处理，
// 因为「没写」就是「按 replay-sampling-v1 抽的」那条最常见路径。
func (r RoutingRecord) SamplingAlgoOrDefault() string {
	if r.SamplingAlgo == "" {
		return SamplingAlgoReplayV1
	}
	return r.SamplingAlgo
}

// Validate 校验路由记录的自洽性。now 是回放时钟：计划的 TTL 只要求
// 「记录当时有效」，历史计划放到今天回放是正常场景，所以过期只豁免不看结构。
func (r RoutingRecord) Validate(now time.Time) error {
	if strings.TrimSpace(r.RequestID) == "" {
		return fmt.Errorf("%w: request_id 不能为空", ErrRecordInvalid)
	}
	if strings.ContainsAny(r.RequestID, " \t\r\n") {
		return fmt.Errorf("%w: request_id %q 含空白，无法作为配对键", ErrRecordInvalid, r.RequestID)
	}
	if r.RecordedAt.IsZero() {
		return fmt.Errorf("%w: %s 缺 recorded_at", ErrRecordInvalid, r.RequestID)
	}
	if r.PolicyVersion == "" {
		return fmt.Errorf("%w: %s 缺 policy_version（§3.0 要求来自实际加载的策略包）", ErrRecordInvalid, r.RequestID)
	}
	if r.RoutingSeed != "" {
		if err := policy.ParseRoutingSeed(r.RoutingSeed); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrRecordInvalid, r.RequestID, err)
		}
	}
	if len(r.Candidates) == 0 {
		return fmt.Errorf("%w: %s: 候选池为空，无法回放选路", ErrRecordInvalid, r.RequestID)
	}
	if err := r.candidatesNormalized(); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrRecordInvalid, r.RequestID, err)
	}
	want, err := policy.CandidatesDigest(r.Candidates)
	if err != nil {
		return fmt.Errorf("%w: %s: 候选摘要无法计算: %v", ErrRecordInvalid, r.RequestID, err)
	}
	if r.CandidatesDigest != want {
		return fmt.Errorf("%w: %s: candidates_digest 与候选池对不上（记录被改过或候选顺序变了）", ErrRecordInvalid, r.RequestID)
	}
	if err := r.validatePlan(now); err != nil {
		return err
	}
	if err := r.validateRejections(); err != nil {
		return err
	}
	return r.validateReplaySnapshot()
}

// validateReplaySnapshot 核对快照与记录顶层是不是**同一件事**的两个面。
//
// 这层核对存在的全部理由是：逐位复现这个声称一旦成立，「回放结论不同」就变成了
// 缺陷报告。如果快照可以与顶层字段各说各话，那份缺陷报告描述的就不是当时那次决策，
// 而是某份被改过或写错版本的输入。四项核对都指向同一个问题：
//   - seed 不同 ⇒ 重跑的是另一次随机流；
//   - 策略版本不同 ⇒ 声明的版本与被复现的那份不是同一个（§3.0 的版本来源）；
//   - request_id 不同 ⇒ 配对错了请求；
//   - 候选摘要不同 ⇒ 池子被换过，而摘要正是「同一个池子」的唯一凭据。
//
// 快照本身还必须是 D 认得的合法输入（Validate 要求 seed 与全部运行时事实齐全）。
func (r RoutingRecord) validateReplaySnapshot() error {
	if r.Replay == nil {
		return nil
	}
	in := *r.Replay
	if err := in.Validate(); err != nil {
		return fmt.Errorf("%w: %s: replay_snapshot 不是合法的回放输入: %v", ErrRecordInvalid, r.RequestID, err)
	}
	if in.Seed != r.RoutingSeed {
		return fmt.Errorf("%w: %s: replay_snapshot.seed 与记录 routing_seed 不一致（%q vs %q）",
			ErrRecordInvalid, r.RequestID, in.Seed, r.RoutingSeed)
	}
	if in.PolicyVersion != r.PolicyVersion {
		return fmt.Errorf("%w: %s: replay_snapshot.policy_version 与记录不一致（%q vs %q）",
			ErrRecordInvalid, r.RequestID, in.PolicyVersion, r.PolicyVersion)
	}
	if in.RequestID != "" && in.RequestID != r.RequestID {
		return fmt.Errorf("%w: %s: replay_snapshot.request_id 是 %q，配不上这条记录",
			ErrRecordInvalid, r.RequestID, in.RequestID)
	}
	digest, err := in.CandidatesDigest()
	if err != nil {
		return fmt.Errorf("%w: %s: replay_snapshot 的候选摘要算不出来: %v", ErrRecordInvalid, r.RequestID, err)
	}
	if digest != r.CandidatesDigest {
		return fmt.Errorf("%w: %s: replay_snapshot 的候选池与记录顶层 candidates_digest 不是同一个池子",
			ErrRecordInvalid, r.RequestID)
	}
	return nil
}

// BitExactReplay 交出「有资格声称首选逐位复现」的那份输入与它声明的算法。
//
// 不够格时返回**错误**而不是 false：调用方必须把原因写进报告或状态口，
// 静默降级正是 §2.8 最怕的那种回放 —— 一份看起来通过、其实什么也没证明的报告。
//
// 三个门槛一个都不能少：
//  1. 记录带得上 replay_snapshot（v1 记录没有当时的运行时事实）；
//  2. 声明的算法在 D 的逐位集合里（否则重跑用的是另一个算法）；
//  3. 快照与记录顶层自洽（validateReplaySnapshot；否则复现的是另一份输入）。
func (r RoutingRecord) BitExactReplay() (routing.ReplayInput, string, error) {
	algo := r.SamplingAlgoOrDefault()
	if r.Replay == nil {
		return routing.ReplayInput{}, algo, fmt.Errorf(
			"%w: 记录不带 replay_snapshot（采自 schema v1，或采集时组不出完整快照）", ErrNotBitExact)
	}
	if !routing.AlgoSupportsBitExact(algo) {
		return routing.ReplayInput{}, algo, fmt.Errorf(
			"%w: 记录声明抽样算法 %q，而路由侧只对 %v 承诺逐位；快照与声明不是同一条实现路径",
			ErrNotBitExact, algo, routing.BitExactAlgos())
	}
	if err := r.validateReplaySnapshot(); err != nil {
		return routing.ReplayInput{}, algo, err
	}
	return *r.Replay, algo, nil
}

// candidatesNormalized 断言候选池已按稳定顺序排列且 provider 唯一。
func (r RoutingRecord) candidatesNormalized() error {
	seen := map[string]bool{}
	for _, c := range r.Candidates {
		if err := c.Validate(); err != nil {
			return err
		}
		if seen[c.Provider] {
			return fmt.Errorf("候选 provider %q 重复", c.Provider)
		}
		seen[c.Provider] = true
	}
	want := policy.SortCandidates(r.Candidates)
	for i := range want {
		if want[i] != r.Candidates[i] {
			return fmt.Errorf("候选必须按 (provider, upstream_model, executor) 稳定排序后再写入，当前第 %d 项是 %s", i, r.Candidates[i].Provider)
		}
	}
	return nil
}

func (r RoutingRecord) validatePlan(now time.Time) error {
	if r.Plan.PolicyVersion != r.PolicyVersion {
		return fmt.Errorf("%w: %s: plan.policy_version 与记录 policy_version 不一致（%q vs %q）",
			ErrRecordInvalid, r.RequestID, r.Plan.PolicyVersion, r.PolicyVersion)
	}
	if r.Plan.RoutingSeed != "" && r.RoutingSeed != "" && r.Plan.RoutingSeed != r.RoutingSeed {
		return fmt.Errorf("%w: %s: plan.routing_seed 与记录 routing_seed 不一致", ErrRecordInvalid, r.RequestID)
	}
	if len(r.Plan.Fallbacks) == 0 {
		return fmt.Errorf("%w: %s: 计划里没有候选，在线时不可能产出这样的计划", ErrRecordInvalid, r.RequestID)
	}
	if err := r.Plan.Validate(now); err != nil {
		if !isPlanExpired(err) {
			return fmt.Errorf("%w: %s: plan: %v", ErrRecordInvalid, r.RequestID, err)
		}
		// 计划过期只有一种情况可以容忍：记录当时它还有效（回放历史计划是正常场景）。
		// 用记录时刻再校验一次，结构问题和「写下时就已过期」的计划仍然会失败。
		if errAgain := r.Plan.Validate(r.RecordedAt); errAgain != nil {
			return fmt.Errorf("%w: %s: 计划在记录时刻就已无效: %v", ErrRecordInvalid, r.RequestID, errAgain)
		}
	}
	// 计划里的候选必须都来自记录的候选池：否则回放拿的池子和在线时不是一个。
	pool := map[string]policy.RouteCandidate{}
	for _, c := range r.Candidates {
		pool[c.Provider] = c
	}
	for _, c := range r.Plan.Fallbacks {
		if _, ok := pool[c.Provider]; !ok {
			return fmt.Errorf("%w: %s: 计划里的候选 %q 不在候选池中", ErrRecordInvalid, r.RequestID, c.Provider)
		}
	}
	return nil
}

func (r RoutingRecord) validateRejections() error {
	pool := map[string]bool{}
	for _, c := range r.Candidates {
		pool[c.Provider] = true
	}
	inPlan := map[string]bool{}
	for _, c := range r.Plan.Fallbacks {
		inPlan[c.Provider] = true
	}
	seen := map[string]bool{}
	for _, rej := range r.Rejections {
		if !rej.Reason.Valid() {
			return fmt.Errorf("%w: %s: 排除原因 %q 未注册", ErrRecordInvalid, r.RequestID, string(rej.Reason))
		}
		if !pool[rej.Provider] {
			return fmt.Errorf("%w: %s: 被排除的 %q 不在候选池中", ErrRecordInvalid, r.RequestID, rej.Provider)
		}
		if inPlan[rej.Provider] {
			return fmt.Errorf("%w: %s: %q 既被排除又进了计划", ErrRecordInvalid, r.RequestID, rej.Provider)
		}
		if seen[rej.Provider] {
			return fmt.Errorf("%w: %s: 排除记录里 %q 重复", ErrRecordInvalid, r.RequestID, rej.Provider)
		}
		seen[rej.Provider] = true
	}
	if !sortedRejections(r.Rejections) {
		return fmt.Errorf("%w: %s: 排除记录必须按 (provider, reason) 稳定排序后再写入", ErrRecordInvalid, r.RequestID)
	}
	// §6「候选排除原因可验证」：池子里每个候选都必须有交代 —— 要么在计划里，
	// 要么有一条带原因码的排除记录。静默消失的候选意味着存在没被记录的第二套过滤规则。
	for _, c := range r.Candidates {
		if !inPlan[c.Provider] && !seen[c.Provider] {
			return fmt.Errorf("%w: %s: 候选 %q 既不在计划里也没有排除原因", ErrRecordInvalid, r.RequestID, c.Provider)
		}
	}
	return nil
}

func sortedRejections(rs []policy.Rejection) bool {
	for i := 1; i < len(rs); i++ {
		prev, cur := rs[i-1], rs[i]
		if prev.Provider == cur.Provider {
			if prev.Reason > cur.Reason {
				return false
			}
			continue
		}
		if prev.Provider > cur.Provider {
			return false
		}
	}
	return true
}

func isPlanExpired(err error) bool {
	// 历史计划的 TTL 早就过了；回放比对的是「当时的选择」，不是「现在还能不能用」。
	// 结构问题（缺字段、未注册原因码等）必须继续失败。
	return err != nil && strings.Contains(err.Error(), policy.ErrPlanExpired.Error())
}

// RoutingCapture 是从在线选路现场构造记录的输入。
type RoutingCapture struct {
	RequestID     string
	RecordedAt    time.Time
	PolicyVersion string
	RoutingSeed   string
	RoutingEpoch  string
	SamplingAlgo  string
	Candidates    []policy.RouteCandidate
	Plan          policy.RoutingPlan
	Rejections    []policy.Rejection

	// Replay 是 PlanWithReplay 当场产出的那份回放输入。
	//
	// nil 时记录退化成 v1 形态（只有配置级候选投影）：判定回放照做，选路只做解释性
	// 回放。它不是可选装饰 —— 首选顺序的逐位复现没有它就无从谈起（裁决第 5 条 B）。
	Replay *routing.ReplayInput
}

// RoutingRecordFrom 把一次在线选路落成回放记录。
//
// 候选与排除记录在这里归一成稳定顺序：调用方可能来自 map，写记录时必须先排序，
// 否则同一台机器两次落库会产生两个摘要不同的记录（§2.8）。
func RoutingRecordFrom(c RoutingCapture) (RoutingRecord, error) {
	// 在线记录必须带 seed：§2.8 明确「在线请求至少记录 routing_seed」。
	// 构造期就拒绝，比写下一条永远只能做解释性回放、又没人去回放的记录好。
	// Validate 仍然接受 seed 为空，这样历史/外部导入的记录能被加载进来，
	// 由回放侧给出 replay_seed_missing 的明确拒绝。
	if c.RoutingSeed == "" {
		return RoutingRecord{}, fmt.Errorf("%w: %s: 在线路由记录必须写 routing_seed（§2.8）", ErrRecordInvalid, c.RequestID)
	}
	if err := policy.ParseRoutingSeed(c.RoutingSeed); err != nil {
		return RoutingRecord{}, fmt.Errorf("%w: %s: %v", ErrRecordInvalid, c.RequestID, err)
	}
	algo := c.SamplingAlgo
	switch {
	case algo != "":
	case c.Replay != nil:
		// 带了 D 产出的快照却没声明算法：按快照的来源补上，而不是让它落到本包默认值
		// replay-sampling-v1 上 —— 那会让一条本来能声称逐位的记录自降成解释性回放，
		// 而没人会去查一个「看起来正常」的备注。
		algo = routing.SamplingAlgoSeededSplitmix64V1
	default:
		algo = SamplingAlgoReplayV1
	}
	if c.Replay != nil && !routing.AlgoSupportsBitExact(algo) {
		// 快照与算法声明互相矛盾：那是采集侧写错了标识，必须当场失败。
		// 留下去只会得到一条自相矛盾的记录，而文件级校验会把整份导出一起拒掉。
		return RoutingRecord{}, fmt.Errorf(
			"%w: %s: 带着 replay_snapshot 却声明抽样算法 %q（D 只承诺逐位 %v）",
			ErrRecordInvalid, c.RequestID, algo, routing.BitExactAlgos())
	}
	rec := RoutingRecord{
		RequestID:     c.RequestID,
		RecordedAt:    nowUTC(c.RecordedAt),
		PolicyVersion: c.PolicyVersion,
		RoutingSeed:   c.RoutingSeed,
		RoutingEpoch:  c.RoutingEpoch,
		SamplingAlgo:  algo,
		Candidates:    policy.SortCandidates(c.Candidates),
		Plan:          c.Plan,
		Rejections:    sortRejections(c.Rejections),
	}
	if c.Replay != nil {
		// 存副本而不是转发调用方的指针：记录一旦落成就是**当时那份**，
		// 而 shot 上的快照随请求结束还会被读几次，谁都不该在导出前改它。
		clone := *c.Replay
		rec.Replay = &clone
	}
	digest, err := policy.CandidatesDigest(rec.Candidates)
	if err != nil {
		return RoutingRecord{}, fmt.Errorf("%w: %v", ErrRecordInvalid, err)
	}
	rec.CandidatesDigest = digest
	if err := rec.Validate(rec.RecordedAt); err != nil {
		return RoutingRecord{}, err
	}
	return rec, nil
}

func sortRejections(rs []policy.Rejection) []policy.Rejection {
	out := append([]policy.Rejection(nil), rs...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}
