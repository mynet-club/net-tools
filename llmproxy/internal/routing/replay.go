package routing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// ReplayOffer 是回放输入里的一条候选：当时生效的那些值，不是「现在的」。
//
// 每个字段都必须是**当时的结论**，这是 §2.8 的硬要求：
//   - Weight 记的是有效权重（已把未配置折算成 1），回放不重新派生，
//     否则「权重默认值改了」这一件无关的事就会让历史决策变样；
//   - CooldownUntil 是绝对时刻，不是剩余时长，配着 ReplayInput.Now 才能还原当时判定；
//   - GateAllows/GateReason 是当时的权限结论摘要：回放**不问活的策略**，
//     用今天的 bundle 回放昨天的请求，得出的结论对解释那次事故毫无用处。
type ReplayOffer struct {
	Provider      string           `json:"provider"`
	Executor      string           `json:"executor"`
	Model         string           `json:"model"`
	UpstreamModel string           `json:"upstream_model"`
	Weight        float64          `json:"weight"`
	Tier          int              `json:"tier"`
	Healthy       bool             `json:"healthy"`
	CooldownUntil time.Time        `json:"cooldown_until,omitempty"`
	Region        string           `json:"region,omitempty"`
	MaxDataLevel  policy.DataLevel `json:"max_data_level"`

	CostPer1KIn  float64 `json:"cost_per_1k_in"`
	CostPer1KOut float64 `json:"cost_per_1k_out"`
	CostKnown    bool    `json:"cost_known"`

	ObservedLatencyMs int64    `json:"observed_latency_ms"`
	DeclaredModels    []string `json:"declared_models,omitempty"`
	Capabilities      []string `json:"capabilities,omitempty"`

	GateAllows bool          `json:"gate_allows"`
	GateReason policy.Reason `json:"gate_reason,omitempty"`
}

// ReplayInput 是一次规划的全部回放输入（§2.8 逐条对应）。
//
// 字段与 §2.8 要求的对应关系：
//   - 候选顺序 → Offers 原样保留传入顺序（D 内部比较器是全序，结论本身与顺序无关；
//     保留顺序是为了让审计看得见当时那份池子，并让人工篡改能被 Digest 发现）；
//   - 有效权重 → ReplayOffer.Weight；
//   - 策略版本 → PolicyVersion（版本参与 seed 派生，见 DeriveRoutingSeed 的三段输入，
//     所以版本一变 seed 就变，回放不会把新策略的结论冒充旧策略）；
//   - 粘性状态 → Sticky；
//   - seed → Seed（必需；缺 seed 只能做解释性回放，不能声称逐位相同 → 直接报错）；
//   - 当时的 gate 结论摘要 → 每条 ReplayOffer 的 GateAllows/GateReason；
//   - 当时的时间 → Now + TTL（**不取当前时间**）。
//
// 这里**没有**的：time.Now、math/rand、供应商配置对象、数据库句柄。全部字段都是
// 值类型或字符串切片，接口/函数/指针一个都不许出现 —— safety_test.go 用反射把这条
// 变成会失败的断言，因为一旦有人加了个 *sql.DB 或 config.Provider，这份快照就不再
// 是「当时的世界」，而是一份会被今天的配置改写的假回放。
type ReplayInput struct {
	// RequestID 只做索引与解释；抽样只认 Seed。
	RequestID     string `json:"request_id,omitempty"`
	PolicyVersion string `json:"policy_version"`
	Seed          string `json:"seed"`

	// Now 是当时决策的时间基准，TTL 是当时的计划有效期。
	Now time.Time     `json:"now"`
	TTL time.Duration `json:"ttl"`

	Objective        Objective    `json:"objective"`
	AllowUnknownCost bool         `json:"allow_unknown_cost,omitempty"`
	MaxRetries       int          `json:"max_retries"`
	ProcessorChain   []string     `json:"processor_chain,omitempty"`
	Requirement      Requirement  `json:"requirement"`
	Sticky           *StickyState `json:"sticky,omitempty"`

	// 决策上下文快照（PolicyContext 的字段按原样搬运，回放时重建同一个 ctx 供
	// 区域与分级过滤使用；不问活的策略，所以这些值必须自带）。
	Subject        string           `json:"subject"`
	SubjectSource  string           `json:"subject_source,omitempty"`
	Purpose        string           `json:"purpose"`
	Organization   string           `json:"organization,omitempty"`
	Project        string           `json:"project,omitempty"`
	DataLevel      policy.DataLevel `json:"data_level"`
	AllowedRegions []string         `json:"allowed_regions,omitempty"`

	// Scopes 是当时的范围集合（结构化 scope，§2.7：不拼回一个字符串）。
	Scopes []policy.ScopeRef `json:"scopes,omitempty"`

	// Offers 顺序即当时的候选顺序。
	Offers []ReplayOffer `json:"offers"`
}

// ErrReplayInput 表示回放输入不完整或夹带了活状态。
var ErrReplayInput = errors.New("routing: 回放输入不合法")

// Validate 校验回放输入。
//
// 缺 seed 时**拒绝**而不是降级：§2.8 说旧请求只能做「解释性回放」，而一个会声称
// 复现结论的 API 最危险的就是给出不保证复现的结果。要做解释性回放就走 Planner.Plan
// （它接受注入随机源并在 ReasonCodes 里说明用的是哪条路径），别用它冒充逐位复现。
func (in ReplayInput) Validate() error { return in.validate(true) }

// validateComplete 只做结构完整性检查，不要求 seed。
//
// 线上用注入随机源（不派生 seed）规划时，快照照样得能写进审计、也能被结构校验挡住
// 写坏的字段 —— 只是这份输入只能做 §2.8 说的「解释性回放」，不能声称逐位复现。
// 要求 seed 的那条路留给 Validate（PlanFromReplay 的入口）。
func (in ReplayInput) validateComplete() error { return in.validate(false) }

func (in ReplayInput) validate(requireSeed bool) error {
	if in.Seed == "" && requireSeed {
		return &PlanError{
			Reason: policy.ReasonReplaySeedMissing,
			Detail: fmt.Errorf("%w: 缺少 routing_seed，只能做解释性回放，不能声称逐位复现", ErrReplayInput),
		}
	}
	if in.Seed != "" {
		if err := policy.ParseRoutingSeed(in.Seed); err != nil {
			return fmt.Errorf("%w: %v", ErrReplayInput, err)
		}
	}
	if in.PolicyVersion == "" {
		return fmt.Errorf("%w: 缺少 policy_version", ErrReplayInput)
	}
	if in.Now.IsZero() {
		return fmt.Errorf("%w: 时间戳必须由回放输入自带（本包不读时钟）", ErrReplayInput)
	}
	if in.TTL <= 0 {
		return fmt.Errorf("%w: ttl 必须为正", ErrReplayInput)
	}
	if in.MaxRetries < 0 {
		return fmt.Errorf("%w: max_retries 为负", ErrReplayInput)
	}
	if err := in.Requirement.Validate(); err != nil {
		return err
	}
	if len(in.Offers) == 0 {
		return fmt.Errorf("%w: 候选清单为空", ErrReplayInput)
	}
	if !in.DataLevel.Valid() {
		return fmt.Errorf("%w: data_level 未判定（零值 LevelUnknown 不是「宽松」，是漏配）", ErrReplayInput)
	}
	if in.Subject == "" {
		return fmt.Errorf("%w: subject 不能为空", ErrReplayInput)
	}
	if !in.Objective.normalize().valid() {
		return fmt.Errorf("%w: 目标函数 %q", ErrReplayInput, string(in.Objective))
	}
	seen := make(map[string]bool, len(in.Offers))
	for i, o := range in.Offers {
		if o.Provider == "" {
			return fmt.Errorf("%w: 第 %d 条候选缺 provider", ErrReplayInput, i)
		}
		if seen[o.Provider] {
			return fmt.Errorf("%w: provider %s 出现两次", ErrReplayInput, o.Provider)
		}
		seen[o.Provider] = true
		if o.Tier < 0 {
			return fmt.Errorf("%w: %s 的 tier 为负", ErrReplayInput, o.Provider)
		}
		if o.Weight < 0 {
			return fmt.Errorf("%w: %s 的有效权重为负", ErrReplayInput, o.Provider)
		}
		if !o.MaxDataLevel.Valid() {
			return fmt.Errorf("%w: %s 的 max_data_level 未指定", ErrReplayInput, o.Provider)
		}
		if !o.GateAllows && !o.GateReason.Valid() {
			// 拒绝却没给可解释的码：这条回放记录写不出 Rejections，
			// 而 §6 要求「候选排除原因可验证」。
			return fmt.Errorf("%w: %s 被权限门拒绝但没有已注册原因码", ErrReplayInput, o.Provider)
		}
	}
	for _, s := range in.Scopes {
		if err := s.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// CandidatesDigest 给出当时的候选池摘要（§2.8 要求在线记录的字段之一）。
func (in ReplayInput) CandidatesDigest() (string, error) {
	cs := make([]policy.RouteCandidate, 0, len(in.Offers))
	for _, o := range in.Offers {
		cs = append(cs, o.toOffer().candidateForPlan())
	}
	return policy.CandidatesDigest(cs)
}

// Digest 是回放输入自身的摘要：把整份输入按 JSON 规范形式哈希，顺序参与计算。
// 用途是把「同一份输入」这个前提变成可比对的值 —— 输入被人为改过一个权重或一条
// gate 结论，摘要就变了，于是「回放结论不同」能被归因到输入而不是规划器。
func (in ReplayInput) Digest() (string, error) {
	data, err := json.Marshal(in)
	if err != nil {
		return "", fmt.Errorf("routing: 回放输入序列化失败: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// toOffer 把回放里的一条候选还原成规划用的 Offer。
//
// Weight 直接照抄：ReplayOffer.Weight 已经是有效权重，effectiveWeight() 的
// 「非正折算成 1」在这里是恒等变换，不会把当时的分布改样。
func (o ReplayOffer) toOffer() Offer {
	return Offer{
		Candidate: policy.RouteCandidate{
			Executor:      o.Executor,
			Provider:      o.Provider,
			Model:         o.Model,
			UpstreamModel: o.UpstreamModel,
			Weight:        o.Weight,
			Region:        o.Region,
			MaxDataLevel:  o.MaxDataLevel,
		},
		Tier:              o.Tier,
		Healthy:           o.Healthy,
		CooldownUntil:     o.CooldownUntil,
		CostPer1KIn:       o.CostPer1KIn,
		CostPer1KOut:      o.CostPer1KOut,
		CostKnown:         o.CostKnown,
		ObservedLatencyMs: o.ObservedLatencyMs,
		DeclaredModels:    o.DeclaredModels,
		Capabilities:      o.Capabilities,
	}
}

// recordedGate 是回放用的权限门：只回答当时记下来的结论。
//
// 它存在的全部意义是「回放不问活的策略」。未知 provider 一律按拒绝处理（fail-closed）：
// 回放进料里没记这家，就说明那次规划时它不在池子里，把它放开等于凭空造出当年不存在的选项。
type recordedGate struct {
	verdicts map[string]gateVerdict
}

func (g recordedGate) Allows(_ policy.PolicyContext, _ policy.ScopeChain, offer Offer, _ time.Time) (bool, policy.Reason) {
	v, ok := g.verdicts[offer.provider()]
	if !ok {
		return false, policy.ReasonCandidatePolicyExcluded
	}
	return v.Allowed, v.Reason
}

// PlanFromReplay 用一份回放输入重算当时的计划。
//
// 与 Planner.Plan 走的是同一段代码，差别只在三个外部依赖的来源：
// 时间取自输入、随机源由 seed 派生、权限结论取自输入记录。
// 因此「回放一致」不是靠两份实现互相同步，而是靠它们本来就是同一个函数。
func PlanFromReplay(in ReplayInput) (policy.RoutingPlan, error) {
	if err := in.Validate(); err != nil {
		return policy.RoutingPlan{}, err
	}
	ctx := policy.PolicyContext{
		Identity: policy.Identity{
			Subject: in.Subject,
			Source:  in.SubjectSource,
		},
		Purpose:        in.Purpose,
		Organization:   in.Organization,
		Project:        in.Project,
		DataLevel:      in.DataLevel,
		AllowedRegions: in.AllowedRegions,
		PolicyVersion:  in.PolicyVersion,
	}.Normalize()
	if err := ctx.Validate(); err != nil {
		return policy.RoutingPlan{}, fmt.Errorf("%w: %v", ErrReplayInput, err)
	}
	chain, err := policy.NewScopeChain(in.Scopes...)
	if err != nil {
		return policy.RoutingPlan{}, fmt.Errorf("%w: %v", ErrReplayInput, err)
	}

	offers := make(Offers, 0, len(in.Offers))
	verdicts := make(map[string]gateVerdict, len(in.Offers))
	for _, ro := range in.Offers {
		offers = append(offers, ro.toOffer())
		verdicts[ro.Provider] = gateVerdict{Allowed: ro.GateAllows, Reason: ro.GateReason}
	}

	planner := NewPlanner()
	plan, _, err := planner.PlanWithReplay(ctx, chain, Input{
		Offers:           offers,
		Gate:             recordedGate{verdicts: verdicts},
		Requirement:      in.Requirement,
		MaxRetries:       in.MaxRetries,
		ProcessorChain:   in.ProcessorChain,
		Objective:        in.Objective,
		AllowUnknownCost: in.AllowUnknownCost,
		Sticky:           in.Sticky,
		Now:              in.Now,
		TTL:              in.TTL,
		Seed:             in.Seed,
		PolicyVersion:    in.PolicyVersion,
	})
	return plan, err
}

// ErrNotReproducible 表示同一份回放输入得到了不同结论 —— 那是 D 的缺陷，
// 不是数据问题：规划器是纯函数，任何一次抖动都必须当成 bug 立刻暴露。
var ErrNotReproducible = errors.New("routing: 回放不可复现")

// Replay 断言「固定输入 → 固定输出」，返回计划与其摘要（§6：策略版本回放一致）。
//
// 断言强度刻意超过 Digest 一个字段：policy.RoutingPlan.Digest() 在摘要前会对
// Fallbacks 做稳定排序（那是对的，摘要要能跨实现比对），因此**摘要看不出首选顺序**。
// 光比 Digest 会让「首选和 fallback 顺序被搅乱」这种回归照样全绿，所以这里同时比
// Fallbacks 的实际顺序。
//
// 连续跑两遍是为了抓两类只在第二次才现形的问题：复用了上一次的切片、
// 以及 map 遍历顺序渗进了排序键。
func Replay(in ReplayInput) (policy.RoutingPlan, string, error) {
	first, err := PlanFromReplay(in)
	if err != nil {
		return policy.RoutingPlan{}, "", err
	}
	second, err := PlanFromReplay(in)
	if err != nil {
		return policy.RoutingPlan{}, "", err
	}
	digestA, err := first.Digest()
	if err != nil {
		return policy.RoutingPlan{}, "", err
	}
	digestB, err := second.Digest()
	if err != nil {
		return policy.RoutingPlan{}, "", err
	}
	if digestA != digestB {
		return policy.RoutingPlan{}, "", fmt.Errorf("%w: 摘要 %s != %s", ErrNotReproducible, digestA, digestB)
	}
	orderA, orderB := providerOrder(first), providerOrder(second)
	if orderA != orderB {
		return policy.RoutingPlan{}, "", fmt.Errorf("%w: 候选顺序抖动 %s != %s", ErrNotReproducible, orderA, orderB)
	}
	return first, digestA, nil
}

// providerOrder 按实际顺序拼出候选清单（不参与排序），供复现断言比对。
func providerOrder(plan policy.RoutingPlan) string {
	out := make([]string, 0, len(plan.Fallbacks))
	for _, c := range plan.Fallbacks {
		out = append(out, c.Provider)
	}
	if len(out) == 0 {
		return "-"
	}
	return fmt.Sprint(out)
}

// SamplingAlgoSeededSplitmix64V1 是线上抽样与快照回放**共用**的那条算法标识。
//
// 它是这个字符串的唯一事实源（2026-10-04 裁决第 5 条 B）：接线侧往记录里写
// sampling_algo 时引用这里的常量，回放侧也拿同一个常量判断能不能声称逐位。
// 两个出处各写一份字面量，「线上与回放是同一个算法」这句话就没有证据可言 ——
// 而它正是逐位复现唯一凭据的那一半（另一半是 ReplayInput 带得上当时的运行时事实）。
//
// 标识描述的是 source.go 的四个魔数 + weightedSample 的累积扫描 + Objective.less
// 的次序这三件事**合起来**的那条路径，改其中任何一项都要新增 v2 标识并把旧值留在
// bitExactAlgos 里，否则历史记录会被新实现误报成「可逐位复现」。
const SamplingAlgoSeededSplitmix64V1 = "routing-seeded-splitmix64-v1"

// ErrNotBitExact 表示记录声明的抽样算法不在本包能逐位复现的集合里。
//
// 拿到这个错误**不是**记录坏了：那是「这份输入只能做解释性回放」，
// 而本包绝不返回一个不保证逐位的计划来冒充逐位结论。
var ErrNotBitExact = errors.New("routing: 该抽样算法不承诺逐位复现")

// bitExactAlgos 是逐位可复现算法的封闭集合 —— 只列**实现真的在本包里**的那些。
var bitExactAlgos = map[string]bool{SamplingAlgoSeededSplitmix64V1: true}

// AlgoSupportsBitExact 报告某个 sampling_algo 标识能不能声称首选逐位相同。
func AlgoSupportsBitExact(algo string) bool { return bitExactAlgos[algo] }

// BitExactAlgos 返回封闭集合的稳定顺序副本，供状态口把取值空间摊开而不是藏在注释里。
func BitExactAlgos() []string {
	out := make([]string, 0, len(bitExactAlgos))
	for algo := range bitExactAlgos {
		out = append(out, algo)
	}
	sort.Strings(out)
	return out
}

// ReplayWithAlgo 按记录声明的算法重跑一次规划，并给出「逐位复现」这一层的结论。
//
// 这就是裁决第 5 条 B 要的那个窄接口，它只做两件事：
//   - 算法核对：声明的标识不在 bitExactAlgos 里就返回 ErrNotBitExact，
//     连计划都不给 —— 一个「看起来一样」的次序比不复现更坏，因为它会把
//     「顺序本来就不同」这件事实消化成一条不存在的策略差异。
//   - 一致时委托 Replay：与线上跑的是同一段代码（Planner.PlanWithReplay），
//     复现性不靠两份实现互相同步，而靠它们本来就是同一个函数。
//
// 它**不**接受活的策略内核、时钟或随机源：全部现场都必须在 in 里自带，
// 否则这个入口就退化成「用今天的配置解释昨天的决策」。
func ReplayWithAlgo(in ReplayInput, algo string) (policy.RoutingPlan, string, error) {
	if !AlgoSupportsBitExact(algo) {
		return policy.RoutingPlan{}, "", fmt.Errorf("%w: 记录声明 %q，本包承诺逐位的算法只有 %v",
			ErrNotBitExact, algo, BitExactAlgos())
	}
	return Replay(in)
}

// snapshotReplay 把一次线上规划落成可回放的输入（PlanWithReplay 内部使用）。
//
// 只搬数据、不搬依赖：Input 里的 Gate 与 Source 两个接口字段在这里被换成
// 逐个 provider 的结论表和 seed，因此快照里不可能藏着活的策略内核或随机源。
func (in Input) snapshotReplay(ctx policy.PolicyContext, chain policy.ScopeChain, objective Objective,
	viewed screening, primary Offer) (ReplayInput, error) {

	offers := make([]ReplayOffer, 0, len(in.Offers))
	for _, o := range in.Offers {
		verdict := viewed.verdicts[o.provider()]
		offers = append(offers, ReplayOffer{
			Provider:          o.Candidate.Provider,
			Executor:          o.Candidate.Executor,
			Model:             o.Candidate.Model,
			UpstreamModel:     o.Candidate.UpstreamModel,
			Weight:            o.effectiveWeight(),
			Tier:              o.Tier,
			Healthy:           o.Healthy,
			CooldownUntil:     o.CooldownUntil,
			Region:            o.Candidate.Region,
			MaxDataLevel:      o.Candidate.MaxDataLevel,
			CostPer1KIn:       o.CostPer1KIn,
			CostPer1KOut:      o.CostPer1KOut,
			CostKnown:         o.CostKnown,
			ObservedLatencyMs: o.ObservedLatencyMs,
			DeclaredModels:    append([]string(nil), o.DeclaredModels...),
			Capabilities:      append([]string(nil), o.Capabilities...),
			GateAllows:        verdict.Allowed,
			GateReason:        verdict.Reason,
		})
	}
	var sticky *StickyState
	if in.Sticky != nil {
		clone := *in.Sticky
		if clone.PolicyVersion == "" {
			clone.PolicyVersion = in.PolicyVersion
		}
		sticky = &clone
	}
	snapshot := ReplayInput{
		RequestID:        in.RequestID,
		PolicyVersion:    in.PolicyVersion,
		Seed:             in.Seed,
		Now:              in.Now,
		TTL:              in.TTL,
		Objective:        objective,
		AllowUnknownCost: in.AllowUnknownCost,
		MaxRetries:       in.MaxRetries,
		ProcessorChain:   append([]string(nil), in.ProcessorChain...),
		Requirement:      in.Requirement,
		Sticky:           sticky,
		Subject:          ctx.Identity.Subject,
		SubjectSource:    ctx.Identity.Source,
		Purpose:          ctx.Purpose,
		Organization:     ctx.Organization,
		Project:          ctx.Project,
		DataLevel:        ctx.DataLevel,
		AllowedRegions:   append([]string(nil), ctx.AllowedRegions...),
		Scopes:           append([]policy.ScopeRef(nil), chain...),
		Offers:           offers,
	}
	// 自检：产出的快照必须能被 PlanFromReplay 直接吃下去。回放进料写坏了
	// （比如 gate 拒绝了却没记码）必须在写入审计前发现，而不是回放时才发现 ——
	// 那时原始现场已经没了。
	if err := snapshot.validateComplete(); err != nil {
		return ReplayInput{}, fmt.Errorf("%w: 回放快照不合法: %v", ErrInput, err)
	}
	// 首选必须在快照里（否则回放会选出一个线上不存在的候选）。
	if !containsProvider(offers, primary.provider()) {
		return ReplayInput{}, fmt.Errorf("%w: 首选 %s 不在候选快照里", ErrInput, primary.provider())
	}
	return snapshot, nil
}

func containsProvider(os []ReplayOffer, provider string) bool {
	for _, o := range os {
		if o.Provider == provider {
			return true
		}
	}
	return false
}
