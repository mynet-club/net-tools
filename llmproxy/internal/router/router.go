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
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	type weighted struct {
		c Candidate
		w float64
	}
	var healthy, all []weighted
	for _, p := range candidates {
		if !p.Enabled {
			continue
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
		item := weighted{c: Candidate{Provider: p, UpstreamModel: up}, w: w}
		all = append(all, item)

		// 只读查状态：Pick 不应为没跑过的供应商创建状态
		var unhealthyUntil time.Time
		if m, ok := r.scoped[scope]; ok {
			if st, ok := m[p.Name]; ok {
				unhealthyUntil = st.UnhealthyUntil
			}
		}
		if !now.Before(unhealthyUntil) {
			healthy = append(healthy, item)
		}
	}

	pool := healthy
	if len(pool) == 0 {
		pool = all
	}
	if len(pool) == 0 {
		return nil, fmt.Errorf("没有供应商能承接模型 %q（可能已被排除或未配置）", model)
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

// RestoreState 从持久化恢复全局作用域的运行期状态（重启后继续熔断）。
func (r *Router) RestoreState(states map[string]State) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, st := range states {
		*r.stateLocked("", name) = st
	}
}

// RestoreScoped 从持久化恢复全部作用域的状态。
// 已存在的作用域按名字覆盖，新作用域按需创建。
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
