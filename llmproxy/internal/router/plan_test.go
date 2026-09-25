package router

import (
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

// owned / system 造两家候选，用来验证「自有优先、点名压兜底」的档序。
func owned(name string, spec config.ModelSpec) config.Provider {
	p := mkProvider(name, 1, spec)
	return p
}

func system(name string, spec config.ModelSpec) config.Provider {
	p := mkProvider(name, 1, spec)
	p.SystemPaid = true
	return p
}

func declares(m map[string]string) config.ModelSpec { return config.ModelSpec{Map: m} }

// PlanFor 给出的档序必须与真实选路一致：自有·点名 → 系统·点名 → 自有·直通 → 系统·直通。
func TestPlanForTierOrder(t *testing.T) {
	r := New(config.RoutingConfig{}, nil)
	cands := []config.Provider{
		system("sys-wild", config.ModelSpec{Passthrough: true}),
		owned("own-wild", config.ModelSpec{Passthrough: true}),
		system("sys-named", declares(map[string]string{"m": "m"})),
		owned("own-named", declares(map[string]string{"m": "m"})),
	}
	plan := r.PlanFor("", cands, "m")
	if len(plan) != 4 {
		t.Fatalf("应当有 4 档，实际 %d: %+v", len(plan), plan)
	}
	wantKinds := []string{"own-declares", "system-declares", "own-wildcard", "system-wildcard"}
	wantNames := []string{"own-named", "sys-named", "own-wild", "sys-wild"}
	for i, tier := range plan {
		if tier.Kind != wantKinds[i] {
			t.Errorf("第 %d 档 kind = %q，期望 %q", i+1, tier.Kind, wantKinds[i])
		}
		if len(tier.Providers) != 1 || tier.Providers[0].Name != wantNames[i] {
			t.Errorf("第 %d 档成员 = %+v，期望 %q", i+1, tier.Providers, wantNames[i])
		}
	}
}

// 有人点名声明时，直通档就不该出现在计划里吗？—— 不，它**仍然在**，
// 只是排在后面（选路时只有点名档空了才会轮到它）。这一点必须和 PlanFor 的语义一致。
func TestPlanForKeepsWildcardButLower(t *testing.T) {
	r := New(config.RoutingConfig{}, nil)
	cands := []config.Provider{
		owned("named", declares(map[string]string{"m": "m"})),
		owned("wild", config.ModelSpec{Passthrough: true}),
	}
	plan := r.PlanFor("", cands, "m")
	if len(plan) != 2 {
		t.Fatalf("应当 2 档，实际 %d", len(plan))
	}
	if plan[0].Kind != "own-declares" || plan[1].Kind != "own-wildcard" {
		t.Errorf("档序不对: %q, %q", plan[0].Kind, plan[1].Kind)
	}
}

// 不承接这个模型的供应商不进计划。
func TestPlanForSkipsNonServing(t *testing.T) {
	r := New(config.RoutingConfig{}, nil)
	cands := []config.Provider{
		owned("other", declares(map[string]string{"别的模型": "x"})),
		owned("mine", declares(map[string]string{"m": "m"})),
	}
	plan := r.PlanFor("", cands, "m")
	total := 0
	for _, tier := range plan {
		total += len(tier.Providers)
	}
	if total != 1 {
		t.Fatalf("只有一家承接，实际计划里有 %d 家: %+v", total, plan)
	}
	if plan[0].Providers[0].Name != "mine" {
		t.Errorf("应当是 mine，实际 %q", plan[0].Providers[0].Name)
	}
}

// 冷却中的排在同一档的后面，且 healthy=false。
func TestPlanForMarksCoolingLast(t *testing.T) {
	r := New(config.RoutingConfig{}, nil)
	cands := []config.Provider{
		owned("cooling", declares(map[string]string{"m": "m"})),
		owned("warm", declares(map[string]string{"m": "m"})),
	}
	r.CoolFor("", "cooling", 60_000_000_000) // 60s
	plan := r.PlanFor("", cands, "m")
	if len(plan) != 1 {
		t.Fatalf("应当合成 1 档，实际 %d", len(plan))
	}
	ps := plan[0].Providers
	if len(ps) != 2 {
		t.Fatalf("应当 2 家，实际 %d", len(ps))
	}
	if ps[0].Name != "warm" || !ps[0].Healthy {
		t.Errorf("健康的应当排前面，实际 %+v", ps[0])
	}
	if ps[1].Name != "cooling" || ps[1].Healthy {
		t.Errorf("冷却的应当排后面且标不健康，实际 %+v", ps[1])
	}
}
