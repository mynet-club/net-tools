// Package router 负责上游供应商的选择：按权重随机，结合可用性（熔断冷却）与失败重试。
package router

import (
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

// State 是单个供应商的运行期状态，跨配置热重载按 name 保留。
type State struct {
	ConsecutiveFailures int
	UnhealthyUntil      time.Time
	TotalRequests       int64
	TotalFailures       int64
	LastError           string
	LastSuccessAt       time.Time
	LastFailureAt       time.Time
}

// Router 持有当前配置的供应商列表与各自的运行期状态。
//
// 状态按「作用域」分桶：全局作用域（""）对应配置文件里的供应商，
// 每个用户名是一个独立作用域，对应用户自带的上游。这样熔断天然隔离 ——
// 一个用户把自己的上游打成 429，不会摘掉别人的同名上游。
type Router struct {
	mu        sync.Mutex
	routing   config.RoutingConfig
	providers []config.Provider
	scoped    map[string]map[string]*State // 作用域 → 供应商名 → 状态
	rnd       *rand.Rand
	now       func() time.Time
}

// ScopedState 是一条带作用域的状态，用于在 Router 与持久化之间搬运。
type ScopedState struct {
	Scope string
	Name  string
	State State
}

func New(routing config.RoutingConfig, providers []config.Provider) *Router {
	r := &Router{
		routing:   routing,
		providers: append([]config.Provider(nil), providers...),
		scoped:    map[string]map[string]*State{"": {}},
		rnd:       rand.New(rand.NewSource(time.Now().UnixNano())),
		now:       time.Now,
	}
	for _, p := range providers {
		r.scoped[""][p.Name] = &State{}
	}
	return r
}

// stateLocked 取某个作用域下某供应商的状态；不存在则创建一个。调用方须持锁。
func (r *Router) stateLocked(scope, name string) *State {
	m, ok := r.scoped[scope]
	if !ok {
		m = map[string]*State{}
		r.scoped[scope] = m
	}
	st, ok := m[name]
	if !ok {
		st = &State{}
		m[name] = st
	}
	return st
}

// ForgetScope 丢弃某个作用域的全部状态（用户被删或不再有上游时调用）。
func (r *Router) ForgetScope(scope string) {
	if scope == "" {
		return // 全局作用域由 ApplyConfig 管理
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.scoped, scope)
}

// ApplyConfig 热重载后替换全局供应商列表；同名供应商的运行期状态被保留。
// 只重建全局作用域，各用户作用域的状态原样保留。
func (r *Router) ApplyConfig(routing config.RoutingConfig, providers []config.Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routing = routing
	r.providers = append([]config.Provider(nil), providers...)
	prev := r.scoped[""]
	next := make(map[string]*State, len(providers))
	for _, p := range providers {
		if s, ok := prev[p.Name]; ok {
			next[p.Name] = s
		} else {
			next[p.Name] = &State{}
		}
	}
	r.scoped[""] = next
}

// Providers 返回当前供应商列表的副本。
func (r *Router) Providers() []config.Provider {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]config.Provider, len(r.providers))
	copy(out, r.providers)
	return out
}

// Candidate 是一次选择的结果。
type Candidate struct {
	Provider      config.Provider
	UpstreamModel string
}

// Candidates 是 CandidatesOf 在全局配置上的快捷方式。
func (r *Router) Candidates(model string) []Candidate {
	r.mu.Lock()
	providers := append([]config.Provider(nil), r.providers...)
	r.mu.Unlock()
	return CandidatesOf(providers, model)
}

// CandidatesOf 返回一组候选里承接 model 的已启用供应商（含上游模型名），
// 按名字排序，便于调试。不看熔断状态。
func CandidatesOf(providers []config.Provider, model string) []Candidate {
	var out []Candidate
	for _, p := range providers {
		if !p.Enabled {
			continue
		}
		up, ok := p.UpstreamModel(model)
		if !ok {
			continue
		}
		out = append(out, Candidate{Provider: p, UpstreamModel: up})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider.Name < out[j].Provider.Name })
	return out
}

// Pick 是 PickFrom 在全局配置上的快捷方式。
func (r *Router) Pick(model string, exclude map[string]bool) (*Candidate, error) {
	r.mu.Lock()
	providers := append([]config.Provider(nil), r.providers...)
	r.mu.Unlock()
	return r.PickFrom("", providers, model, exclude)
}

// PickFrom 按权重随机挑选一个承接 model 的供应商，排除 exclude 中的名字。
//
// candidates 由调用方给出：全局作用域传配置里的供应商，用户作用域传该用户自己的上游。
// 熔断状态按 (作用域, 供应商名) 隔离。
//
// 可用性规则：
//   - 连续失败达到 threshold 后，该供应商被摘除 cooldownSeconds
//   - 优先在"健康"供应商中按权重随机
//   - 若一个健康供应商都没有，则在全部候选中按权重随机（宁可重试也不要硬失败）
func (r *Router) PickFrom(scope string, candidates []config.Provider, model string, exclude map[string]bool) (*Candidate, error) {
	return r.PickFromPreferring(scope, candidates, model, exclude, "")
}

// PickFromPreferring 在 PickFrom 的基础上多一个「优先选这家」。
//
// 用途是会话粘性：把同一个会话钉在同一个后端，别让权重随机把一段对话的前缀缓存
// 打散到多家 —— 缓存是按「上游账号 + 模型」分区的，换家等于从冷缓存重来。
//
// prefer 是**软**约束，三条语义都要记住：
//
//  1. 它只在最终候选池里生效。若某个模型名被别家点名声明过（于是「点名声明优先于
//     通配兜底」把兜底那家挤出了候选池），即便 prefer 指着那家兜底的，也不会生效 ——
//     否则粘性就成了绕过候选规则的旁路。代价是：某个模型的声明方集合变化时，
//     会话可能迁移一次（罕见，且只会发生一次）。
//  2. 那家正在冷却时**不生效**，直接按原规则漂移到别家（「后端不能用就换家」）。
//     漂移之后上层会更新粘性，于是不会改回来——避免两家来回横跳把两边的缓存都弄冷。
//  3. prefer 为空、或它不在候选里（停用/不承接这个模型/被 exclude），等同于没提。
//
// scored 是候选 + 它的选择权重 + 此刻健不健康。
type scored struct {
	c       Candidate
	w       float64
	healthy bool
}

// buckets 把候选按「点名声明 / 通配兜底」×「健康 / 全部」分成四堆。
type buckets struct{ explHealthy, explAll, fbHealthy, fbAll []scored }

// bucketize 把候选按归属（自有 / 系统）、声明方式（点名 / 通配）、健康度分类。
//
// 选路（PickFromPreferring）与界面展示（PlanFor）共用这一份分类，两边的次序不会走偏 ——
// 「界面上写的顺序」就是「真实会走的顺序」，这是这个函数存在的全部理由。
// exclude 传 nil 表示不做排除（展示场景）。
func (r *Router) bucketize(scope string, candidates []config.Provider, model string, exclude map[string]bool) (own, sys buckets) {
	now := r.now()
	// 先看这个模型有没有**启用中**的点名映射（exclude 也算：重试排除的那家
	// 映射还在，不该因此放万能匹配进来）。有就只走映射，没有才用通配。
	hasNamed := false
	for _, p := range candidates {
		if p.Enabled && p.Declares(model) {
			hasNamed = true
			break
		}
	}
	for _, p := range candidates {
		if !p.Enabled {
			continue
		}
		if hasNamed && !p.Declares(model) {
			continue // 有映射就只走映射，通配整档出局
		}
		up, ok := p.UpstreamModel(model)
		if !ok {
			continue
		}
		if exclude[p.Name] {
			continue
		}
		w := p.Weight
		if w <= 0 {
			w = 1
		}
		item := scored{c: Candidate{Provider: p, UpstreamModel: up}, w: w}
		declares := p.Declares(model)

		// 只读查状态：Pick 不应为没跑过的供应商创建状态
		var unhealthyUntil time.Time
		if m, ok := r.scoped[scope]; ok {
			if st, ok := m[p.Name]; ok {
				unhealthyUntil = st.UnhealthyUntil
			}
		}
		// healthy 的语义是「这家此刻能不能用」，与它被放进哪一堆无关 ——
		// explAll/fbAll 里也装着健康成员，这个标志不能只在写入 *Healthy 时才置位。
		item.healthy = !now.Before(unhealthyUntil)

		b := &own
		if p.SystemPaid {
			b = &sys
		}
		if declares {
			b.explAll = append(b.explAll, item)
		} else {
			b.fbAll = append(b.fbAll, item)
		}
		if item.healthy {
			if declares {
				b.explHealthy = append(b.explHealthy, item)
			} else {
				b.fbHealthy = append(b.fbHealthy, item)
			}
		}
	}
	return own, sys
}

// tierKey 是优先级次序里的一格。整个次序由下面的 priorityTiers 唯一定义，
// 选路（PickFromPreferring）与界面展示（PlanFor）都从它派生 ——
// 档序只写一处，两边不可能走偏。
type tierKey struct {
	kind     string // own-declares / system-declares / own-wildcard / system-wildcard
	label    string
	sys      bool // true = 取系统池那组
	declares bool // true = 取「点名声明」那堆，false = 「通配兜底」
	healthy  bool // true = 只取健康的
}

// priorityTiers 是候选池的优先级次序，从高到低：
//
//	自有·点名·健康 → 自有·点名 → 系统·点名·健康 → 系统·点名 →
//	自有·兜底·健康 → 自有·兜底 → 系统·兜底·健康 → 系统·兜底
//
// 三条规则叠起来，**从外到内**依次是：
//
//  1. 点名声明**独占**，通配兜底不参战 —— 只要有人点名声明了这个模型名，
//     写 models: ["*"] / catch-all 的家就整档出局（见 bucketize 末尾）。
//     心智模型：「有映射按映射表来，没映射才看万能匹配」。
//     若两者并存，mimo 之类的请求会被串到根本没有该模型的直通上游上，白白 400。
//  2. 同一层里，自有上游优先于系统池：用户自己配的先花他自己的钱。
//  3. 层内先健康的，兜不住了再拿不健康的顶上。
var priorityTiers = []tierKey{
	{"own-declares", "自有上游（点名）", false, true, true},
	{"own-declares", "自有上游（点名）", false, true, false},
	{"system-declares", "系统池（点名）", true, true, true},
	{"system-declares", "系统池（点名）", true, true, false},
	{"own-wildcard", "自有上游（直通）", false, false, true},
	{"own-wildcard", "自有上游（直通）", false, false, false},
	{"system-wildcard", "系统池（直通）", true, false, true},
	{"system-wildcard", "系统池（直通）", true, false, false},
}

// pick 按 tierKey 从两组桶里取出对应的那一堆。
func (k tierKey) pick(own, sys buckets) []scored {
	b := own
	if k.sys {
		b = sys
	}
	switch {
	case k.declares && k.healthy:
		return b.explHealthy
	case k.declares:
		return b.explAll
	case k.healthy:
		return b.fbHealthy
	default:
		return b.fbAll
	}
}

// priorityOrder 按优先级把 8 堆依次摊开，调用方取第一堆非空的。
func priorityOrder(own, sys buckets) [][]scored {
	out := make([][]scored, 0, len(priorityTiers))
	for _, k := range priorityTiers {
		out = append(out, k.pick(own, sys))
	}
	return out
}

// PlanFor 返回某个模型**会被按什么顺序消费**的分档清单，只读、不改任何状态。
//
// 给界面用：「我的模型」里要能看清这个模型先走哪家、再走哪家。档序取自
// priorityTiers（与真实选路同一份定义），所以界面上看到的次序就是实际会走的次序。
// 同一档内部的成员是**按权重随机 + 会话粘性**，不分先后，所以档内不再排序。
func (r *Router) PlanFor(scope string, candidates []config.Provider, model string) []Tier {
	r.mu.Lock()
	defer r.mu.Unlock()

	own, sys := r.bucketize(scope, candidates, model, nil)

	out := []Tier{}
	// 相邻两格是同一档的「健康 / 全部」，合并成一档看；档内健康在前、冷却在后
	// （档内不保证先后 —— 选路是按权重随机，但「现在能用」该先看到）。
	for i := 0; i < len(priorityTiers); i++ {
		k := priorityTiers[i]
		if !k.healthy {
			continue // 只由 healthy 那格发起，避免同档重复
		}
		allKey := k
		allKey.healthy = false
		all := allKey.pick(own, sys)
		if len(all) == 0 {
			continue
		}
		items := make([]scored, 0, len(all))
		for _, it := range all {
			if it.healthy {
				items = append(items, it)
			}
		}
		for _, it := range all {
			if !it.healthy {
				items = append(items, it)
			}
		}
		t := Tier{Kind: k.kind, Label: k.label}
		for _, it := range items {
			t.Providers = append(t.Providers, PlanEntry{
				Name:          it.c.Provider.Name,
				UpstreamModel: it.c.UpstreamModel,
				Weight:        it.w,
				Healthy:       it.healthy,
			})
		}
		out = append(out, t)
	}
	return out
}

// Tier 是「这个模型会被按什么顺序消费」里的一档。
type Tier struct {
	Kind      string      // own-declares / system-declares / own-wildcard / system-wildcard
	Label     string      // 中文标签，直接给界面用
	Providers []PlanEntry // 档内成员：按权重随机选，档内不分先后
}

// PlanEntry 是某一档里的一家上游。
type PlanEntry struct {
	Name          string
	UpstreamModel string
	Weight        float64
	Healthy       bool
}

func (r *Router) PickFromPreferring(scope string, candidates []config.Provider, model string, exclude map[string]bool, prefer string) (*Candidate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	own, sys := r.bucketize(scope, candidates, model, exclude)

	var pool []scored
	for _, cand := range priorityOrder(own, sys) {
		if len(cand) > 0 {
			pool = cand
			break
		}
	}
	if len(pool) == 0 {
		return nil, fmt.Errorf("没有供应商能承接模型 %q（可能已被排除或未配置）", model)
	}

	// 会话粘性：优先项在池子里且健康，就用它（语义见 PickFromPreferring 的说明）。
	// 放在池子定下来之后，是为了让「点名声明优先于兜底」仍然说了算 ——
	// 粘性是"在这批合法候选里挑哪一家"，不是"绕过候选规则"。
	if prefer != "" {
		for _, item := range pool {
			if item.c.Provider.Name == prefer && item.healthy {
				c := item.c
				return &c, nil
			}
		}
	}

	var total float64
	for _, item := range pool {
		total += item.w
	}
	if total <= 0 {
		total = float64(len(pool))
	}
	x := r.rnd.Float64() * total
	var acc float64
	for _, item := range pool {
		acc += item.w
		if x <= acc {
			c := item.c
			return &c, nil
		}
	}
	c := pool[len(pool)-1].c
	return &c, nil
}

// Cooling 报告某个 (作用域, 供应商) 此刻是否在冷却中。
//
// 只读、不创建状态 —— 规则 B 的路由排序要用它跳过正在冷却的家，
// 而"看一眼"不该给没跑过的供应商建一条记录。
func (r *Router) Cooling(scope, name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.scoped[scope]
	if !ok {
		return false
	}
	st, ok := m[name]
	if !ok {
		return false
	}
	return r.now().Before(st.UnhealthyUntil)
}

// CoolFor 直接给某个 (作用域, 供应商) 压一段冷却，不走"连续失败达阈值"那条路。
//
// 给 402 / 429 这类**明确的额度或限流信号**用：它们不需要攒够次数，
// 一次就该让这家让位（次便宜的顶上），否则规则 B 会一遍遍把请求送到已经没额度的家。
// 冷却只延长不缩短：已有更晚的恢复时间就保留。
func (r *Router) CoolFor(scope, name string, d time.Duration) {
	if d <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.stateLocked(scope, name)
	until := r.now().Add(d)
	if until.After(st.UnhealthyUntil) {
		st.UnhealthyUntil = until
	}
}

// ReportSuccess 是 ReportSuccessFor 在全局作用域上的快捷方式。
func (r *Router) ReportSuccess(name string) { r.ReportSuccessFor("", name) }

// ReportSuccessFor 重置连续失败计数并解除熔断。
func (r *Router) ReportSuccessFor(scope, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.stateLocked(scope, name)
	st.ConsecutiveFailures = 0
	st.UnhealthyUntil = time.Time{}
	st.LastError = ""
	st.TotalRequests++
	st.LastSuccessAt = r.now()
}

// ReportFailure 是 ReportFailureFor 在全局作用域上的快捷方式。
func (r *Router) ReportFailure(name string, err error) { r.ReportFailureFor("", name, err) }

// ReportFailureFor 累加连续失败；达到阈值后进入冷却。
func (r *Router) ReportFailureFor(scope, name string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.stateLocked(scope, name)
	st.TotalRequests++
	st.TotalFailures++
	st.ConsecutiveFailures++
	if err != nil {
		st.LastError = err.Error()
		if len(st.LastError) > 500 {
			st.LastError = st.LastError[:500]
		}
	}
	now := r.now()
	st.LastFailureAt = now
	if st.ConsecutiveFailures >= r.routing.FailureThreshold && r.routing.CooldownSeconds > 0 {
		st.UnhealthyUntil = now.Add(time.Duration(r.routing.CooldownSeconds) * time.Second)
	}
}

// Snapshot 是 SnapshotFor 在全局作用域上的快捷方式。
func (r *Router) Snapshot() map[string]State { return r.SnapshotFor("") }

// SnapshotFor 返回某个作用域下全部供应商状态的副本。
func (r *Router) SnapshotFor(scope string) map[string]State {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]State)
	for k, v := range r.scoped[scope] {
		out[k] = *v
	}
	return out
}

// SnapshotAll 返回所有作用域的状态，用于落库。
func (r *Router) SnapshotAll() []ScopedState {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []ScopedState
	for scope, m := range r.scoped {
		for name, st := range m {
			out = append(out, ScopedState{Scope: scope, Name: name, State: *st})
		}
	}
	return out
}

// RestoreScoped 从持久化恢复全部作用域的状态（重启后继续熔断）。
// 已存在的作用域按名字覆盖，新作用域按需创建。
//
// 这是**唯一**的恢复入口：状态是按 (作用域, 供应商) 分桶的，全局池是 ""、
// 每个用户自己的上游是用户名。曾经还有一个只写全局作用域的 RestoreState，
// 生产代码调了它，于是用户级熔断重启即丢、还在库里长出名叫 "alice/my-up"
// 的幽灵条目 —— 那个 API 已经删掉，让编译器杜绝重犯。
func (r *Router) RestoreScoped(list []ScopedState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, item := range list {
		*r.stateLocked(item.Scope, item.Name) = item.State
	}
}

// RetryLimit 返回本次配置允许的最大尝试次数（1 次首发 + retry 次重试）。
func (r *Router) RetryLimit() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.routing.Retry < 0 {
		return 1
	}
	return r.routing.Retry + 1
}

// SetNowFunc 仅测试用：替换时间源。
func (r *Router) SetNowFunc(f func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = f
}
