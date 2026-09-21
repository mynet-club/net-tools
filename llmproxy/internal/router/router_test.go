package router

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

func mkProvider(name string, weight float64, models config.ModelSpec) config.Provider {
	return config.Provider{
		Name:    name,
		Enabled: true,
		Weight:  weight,
		Models:  models,
	}
}

func passthrough(name string, weight float64) config.Provider {
	return mkProvider(name, weight, config.ModelSpec{Passthrough: true})
}

func mapped(name string, weight float64, pairs map[string]string) config.Provider {
	return mkProvider(name, weight, config.ModelSpec{Map: pairs})
}

func TestPickWeightedDistribution(t *testing.T) {
	r := New(config.RoutingConfig{Retry: 2, FailureThreshold: 3, CooldownSeconds: 60}, []config.Provider{
		passthrough("heavy", 90),
		passthrough("light", 10),
	})
	counts := map[string]int{}
	const n = 4000
	for i := 0; i < n; i++ {
		c, err := r.Pick("m", nil)
		if err != nil {
			t.Fatal(err)
		}
		counts[c.Provider.Name]++
	}
	// 权重 90:10，期望约 9:1；给较宽的容差避免偶发失败
	ratio := float64(counts["heavy"]) / float64(counts["light"])
	if ratio < 5 || ratio > 20 {
		t.Errorf("权重分布明显偏离，heavy=%d light=%d ratio=%.2f（期望接近 9）",
			counts["heavy"], counts["light"], ratio)
	}
}

func TestPickOnlyProvidersServingModel(t *testing.T) {
	r := New(config.RoutingConfig{}, []config.Provider{
		mapped("gpt-only", 5, map[string]string{"gpt-4o": "gpt-4o"}),
		mapped("claude-only", 5, map[string]string{"claude-3": "claude-3"}),
		passthrough("any", 1),
	})
	for i := 0; i < 200; i++ {
		c, err := r.Pick("gpt-4o", nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.Provider.Name == "claude-only" {
			t.Fatal("选到了不承接该模型的供应商")
		}
		if c.UpstreamModel != "gpt-4o" {
			t.Errorf("upstream model = %q", c.UpstreamModel)
		}
	}
}

func TestUpstreamModelMapping(t *testing.T) {
	r := New(config.RoutingConfig{}, []config.Provider{
		mapped("mapped", 1, map[string]string{"gpt-4o": "gpt-4o-2024-11-20"}),
		passthrough("passthru", 1),
	})
	c, err := r.Pick("gpt-4o", nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Provider.Name == "mapped" && c.UpstreamModel != "gpt-4o-2024-11-20" {
		t.Errorf("映射未生效: %q", c.UpstreamModel)
	}
	if c.Provider.Name == "passthru" && c.UpstreamModel != "gpt-4o" {
		t.Errorf("直通未生效: %q", c.UpstreamModel)
	}
}

func TestPickExclude(t *testing.T) {
	r := New(config.RoutingConfig{}, []config.Provider{
		passthrough("a", 1000),
		passthrough("b", 1),
	})
	exclude := map[string]bool{"a": true}
	for i := 0; i < 50; i++ {
		c, err := r.Pick("m", exclude)
		if err != nil {
			t.Fatal(err)
		}
		if c.Provider.Name != "b" {
			t.Fatalf("exclude 未生效，选到了 %q", c.Provider.Name)
		}
	}
}

func TestPickAllExcluded(t *testing.T) {
	r := New(config.RoutingConfig{}, []config.Provider{passthrough("a", 1)})
	_, err := r.Pick("m", map[string]bool{"a": true})
	if err == nil || !strings.Contains(err.Error(), "没有供应商") {
		t.Fatalf("全部排除时应报错, got %v", err)
	}
}

func TestPickNoProviderForModel(t *testing.T) {
	r := New(config.RoutingConfig{}, []config.Provider{
		mapped("only", 1, map[string]string{"x": "x"}),
	})
	_, err := r.Pick("unknown-model", nil)
	if err == nil {
		t.Fatal("没有供应商承接该模型时应报错")
	}
}

func TestCircuitBreaker(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	r := New(config.RoutingConfig{FailureThreshold: 3, CooldownSeconds: 60, Retry: 5}, []config.Provider{
		passthrough("bad", 1000),
		passthrough("good", 1),
	})
	r.SetNowFunc(func() time.Time { return now })

	// 连续失败 3 次后 bad 进入熔断
	for i := 0; i < 3; i++ {
		r.ReportFailure("bad", fmt.Errorf("boom %d", i))
	}
	snap := r.Snapshot()
	if snap["bad"].ConsecutiveFailures != 3 {
		t.Errorf("consecutive = %d, want 3", snap["bad"].ConsecutiveFailures)
	}
	if !snap["bad"].UnhealthyUntil.After(now) {
		t.Errorf("应进入熔断, unhealthyUntil=%v", snap["bad"].UnhealthyUntil)
	}

	// 熔断期间应选到 good
	for i := 0; i < 30; i++ {
		c, err := r.Pick("m", nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.Provider.Name != "good" {
			t.Fatalf("熔断期间不应选到 bad, got %q", c.Provider.Name)
		}
	}

	// 冷却时间过去后 bad 恢复参与选择
	now = now.Add(61 * time.Second)
	got := map[string]bool{}
	for i := 0; i < 100; i++ {
		c, err := r.Pick("m", nil)
		if err != nil {
			t.Fatal(err)
		}
		got[c.Provider.Name] = true
	}
	if !got["bad"] {
		t.Error("冷却结束后 bad 应恢复参与选择")
	}
}

func TestCircuitBreakerFallbackWhenAllUnhealthy(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	r := New(config.RoutingConfig{FailureThreshold: 1, CooldownSeconds: 60}, []config.Provider{
		passthrough("a", 1),
		passthrough("b", 1),
	})
	r.SetNowFunc(func() time.Time { return now })
	r.ReportFailure("a", fmt.Errorf("x"))
	r.ReportFailure("b", fmt.Errorf("y"))
	// 全部熔断时仍应能选到供应商（宁可重试也不要硬失败）
	c, err := r.Pick("m", nil)
	if err != nil {
		t.Fatalf("全部熔断时应回退选择, got %v", err)
	}
	if c == nil {
		t.Fatal("pick 返回了 nil")
	}
}

func TestReportSuccessResets(t *testing.T) {
	r := New(config.RoutingConfig{FailureThreshold: 3, CooldownSeconds: 60}, []config.Provider{
		passthrough("a", 1),
	})
	r.ReportFailure("a", fmt.Errorf("x"))
	r.ReportFailure("a", fmt.Errorf("x"))
	r.ReportSuccess("a")
	snap := r.Snapshot()
	if snap["a"].ConsecutiveFailures != 0 {
		t.Errorf("成功后应清零连续失败, got %d", snap["a"].ConsecutiveFailures)
	}
	if !snap["a"].UnhealthyUntil.IsZero() {
		t.Errorf("成功后应解除熔断, got %v", snap["a"].UnhealthyUntil)
	}
}

func TestApplyConfigPreservesState(t *testing.T) {
	r := New(config.RoutingConfig{FailureThreshold: 3, CooldownSeconds: 60}, []config.Provider{
		passthrough("keep", 1),
		passthrough("gone", 1),
	})
	r.ReportFailure("keep", fmt.Errorf("x"))
	r.ReportFailure("keep", fmt.Errorf("x"))

	r.ApplyConfig(config.RoutingConfig{FailureThreshold: 3, CooldownSeconds: 60}, []config.Provider{
		passthrough("keep", 5),
		passthrough("new", 5),
	})
	snap := r.Snapshot()
	if snap["keep"].ConsecutiveFailures != 2 {
		t.Errorf("同名供应商状态应保留, got %d", snap["keep"].ConsecutiveFailures)
	}
	if _, ok := snap["gone"]; ok {
		t.Error("已移除的供应商状态不应保留")
	}
	if _, ok := snap["new"]; !ok {
		t.Error("新增供应商应有状态")
	}
}

func TestRestoreState(t *testing.T) {
	r := New(config.RoutingConfig{FailureThreshold: 3, CooldownSeconds: 60}, []config.Provider{
		passthrough("a", 1),
	})
	future := time.Now().Add(30 * time.Second)
	r.RestoreState(map[string]State{
		"a": {ConsecutiveFailures: 3, UnhealthyUntil: future, TotalRequests: 10, TotalFailures: 3},
	})
	snap := r.Snapshot()
	if snap["a"].ConsecutiveFailures != 3 || snap["a"].TotalRequests != 10 {
		t.Errorf("状态未恢复: %+v", snap["a"])
	}
}

func TestCandidates(t *testing.T) {
	r := New(config.RoutingConfig{}, []config.Provider{
		mapped("b", 1, map[string]string{"m": "m-b"}),
		mapped("a", 1, map[string]string{"m": "m-a"}),
		mapped("c", 1, map[string]string{"other": "x"}),
	})
	cands := r.Candidates("m")
	if len(cands) != 2 {
		t.Fatalf("candidates = %d, want 2", len(cands))
	}
	if cands[0].Provider.Name != "a" || cands[1].Provider.Name != "b" {
		t.Errorf("candidates 应按名字排序, got %v %v", cands[0].Provider.Name, cands[1].Provider.Name)
	}
}

func TestPickSkipsDisabled(t *testing.T) {
	disabled := passthrough("disabled-heavy", 10000)
	f := false
	disabled.Enabled = f
	r := New(config.RoutingConfig{}, []config.Provider{
		disabled,
		passthrough("enabled-light", 1),
	})
	for i := 0; i < 50; i++ {
		c, err := r.Pick("m", nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.Provider.Name != "enabled-light" {
			t.Fatalf("选到了已停用的供应商 %q", c.Provider.Name)
		}
	}
	// Candidates 也不应列出停用供应商
	if got := r.Candidates("m"); len(got) != 1 || got[0].Provider.Name != "enabled-light" {
		t.Errorf("Candidates = %+v", got)
	}
}

func TestRetryLimit(t *testing.T) {
	r := New(config.RoutingConfig{Retry: 2}, nil)
	if r.RetryLimit() != 3 {
		t.Errorf("retry=2 → 3 次尝试, got %d", r.RetryLimit())
	}
	r.ApplyConfig(config.RoutingConfig{Retry: 0}, nil)
	if r.RetryLimit() != 1 {
		t.Errorf("retry=0 → 1 次尝试, got %d", r.RetryLimit())
	}
}

// ---- 多用户相关：状态按作用域隔离 ----

func TestScopeIsolationInCircuitBreaker(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	r := New(config.RoutingConfig{FailureThreshold: 3, CooldownSeconds: 60, Retry: 5},
		[]config.Provider{passthrough("shared", 1000)})
	r.SetNowFunc(func() time.Time { return now })

	// 同名上游，三种作用域
	alice := []config.Provider{passthrough("upstream", 1)}
	bob := []config.Provider{passthrough("upstream", 1)}

	for i := 0; i < 3; i++ {
		r.ReportFailureFor("alice", "upstream", fmt.Errorf("boom"))
	}

	// alice 的已熔断
	if got := r.SnapshotFor("alice")["upstream"].ConsecutiveFailures; got != 3 {
		t.Errorf("alice 连续失败应为 3，实际 %d", got)
	}
	if !r.SnapshotFor("alice")["upstream"].UnhealthyUntil.After(now) {
		t.Error("alice 的上游应处于熔断")
	}
	// bob 的不受影响
	if m := r.SnapshotFor("bob"); len(m) != 0 {
		t.Errorf("bob 不该有状态，实际 %v", m)
	}
	if c, err := r.PickFrom("bob", bob, "m", nil); err != nil || c.Provider.Name != "upstream" {
		t.Errorf("bob 应能正常选到自己的上游: %v %v", c, err)
	}
	// 全局的更不受影响
	if got := r.SnapshotFor(""); len(got) != 1 || got["shared"].ConsecutiveFailures != 0 {
		t.Errorf("全局状态被污染: %v", got)
	}

	// alice 熔断期间，即使只有这一个候选，也仍然返回它（宁可重试不硬失败）
	c, err := r.PickFrom("alice", alice, "m", nil)
	if err != nil {
		t.Fatalf("全部不健康时仍应返回候选: %v", err)
	}
	if c.Provider.Name != "upstream" {
		t.Errorf("应回退到唯一候选，实际 %s", c.Provider.Name)
	}
}

func TestPickFromUsesOnlyGivenCandidates(t *testing.T) {
	r := New(config.RoutingConfig{FailureThreshold: 3}, []config.Provider{
		passthrough("global-only", 1),
	})
	// 全局有 global-only，但 alice 只带了自己那个；不应选到全局的
	alice := []config.Provider{passthrough("alice-up", 1)}
	for i := 0; i < 20; i++ {
		c, err := r.PickFrom("alice", alice, "m", nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.Provider.Name != "alice-up" {
			t.Fatalf("选到了候选之外的供应商: %s", c.Provider.Name)
		}
	}
	// 候选为空 → 报错
	if _, err := r.PickFrom("alice", nil, "m", nil); err == nil {
		t.Error("候选为空时应当报错")
	}
}

func TestSnapshotAllAndRestoreScoped(t *testing.T) {
	r := New(config.RoutingConfig{FailureThreshold: 3, CooldownSeconds: 60}, []config.Provider{
		passthrough("g", 1),
	})
	r.ReportFailureFor("alice", "a1", fmt.Errorf("x"))
	r.ReportSuccessFor("bob", "b1")

	all := r.SnapshotAll()
	if len(all) != 3 {
		t.Fatalf("应有 3 条状态，实际 %d: %v", len(all), all)
	}
	seen := map[string]bool{}
	for _, s := range all {
		seen[s.Scope+"/"+s.Name] = true
	}
	for _, want := range []string{"/g", "alice/a1", "bob/b1"} {
		if !seen[want] {
			t.Errorf("缺少作用域条目 %s", want)
		}
	}

	// 恢复到新 Router（模拟重启）
	r2 := New(config.RoutingConfig{FailureThreshold: 3, CooldownSeconds: 60}, []config.Provider{
		passthrough("g", 1),
	})
	r2.RestoreScoped(all)
	if got := r2.SnapshotFor("alice")["a1"].TotalFailures; got != 1 {
		t.Errorf("恢复后 alice/a1 失败数应为 1，实际 %d", got)
	}
	if got := r2.SnapshotFor("bob")["b1"].TotalRequests; got != 1 {
		t.Errorf("恢复后 bob/b1 请求数应为 1，实际 %d", got)
	}
}

func TestForgetScope(t *testing.T) {
	r := New(config.RoutingConfig{FailureThreshold: 3}, []config.Provider{passthrough("g", 1)})
	r.ReportFailureFor("alice", "a1", fmt.Errorf("x"))
	if len(r.SnapshotFor("alice")) != 1 {
		t.Fatal("alice 状态未建立")
	}
	r.ForgetScope("alice")
	if len(r.SnapshotFor("alice")) != 0 {
		t.Error("ForgetScope 未清掉作用域")
	}
	// 全局作用域不允许被清掉
	r.ForgetScope("")
	if len(r.SnapshotFor("")) != 1 {
		t.Error("ForgetScope(\"\") 不应清空全局作用域")
	}
}

func TestApplyConfigKeepsUserScopes(t *testing.T) {
	r := New(config.RoutingConfig{FailureThreshold: 3, CooldownSeconds: 60}, []config.Provider{
		passthrough("g", 1),
	})
	r.ReportFailureFor("alice", "a1", fmt.Errorf("x"))

	// 热重载：全局换了一个供应商
	r.ApplyConfig(config.RoutingConfig{FailureThreshold: 3, CooldownSeconds: 60}, []config.Provider{
		passthrough("g2", 1),
	})
	if len(r.SnapshotFor("")) != 1 {
		t.Errorf("全局作用域应只剩新供应商: %v", r.SnapshotFor(""))
	}
	if _, ok := r.SnapshotFor("")["g2"]; !ok {
		t.Error("新供应商状态未建立")
	}
	if got := r.SnapshotFor("alice")["a1"].ConsecutiveFailures; got != 1 {
		t.Errorf("热重载不应影响用户作用域，实际 %d", got)
	}
}

// 点名声明过这个模型的供应商，优先于靠 ["*"] 兜底的供应商。
//
// 现实里的样子：一家 deepseek 写 models: ["*"]（声明「任何模型名我都接」），
// 另一家 neolink 点名声明 {gpt-5-sol: gp-5.6-so}。两家权重都是 1 时，
// 如果平权随机，一半请求会被送去 deepseek —— 而它根本不认 gpt-5-sol，
// 于是同一个模型名时而正常、时而 400。
func TestPickDeclaredBeatsPassthrough(t *testing.T) {
	r := New(config.RoutingConfig{}, []config.Provider{
		mapped("neolink", 1, map[string]string{"gpt-5-sol": "gp-5.6-so"}),
		passthrough("deepseek", 1), // 权重相同，故意不靠权重压制
	})
	for i := 0; i < 500; i++ {
		c, err := r.Pick("gpt-5-sol", nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.Provider.Name != "neolink" {
			t.Fatalf("第 %d 次选到了兜底供应商 %q（应当只走点名声明的那家）", i, c.Provider.Name)
		}
		if c.UpstreamModel != "gp-5.6-so" {
			t.Fatalf("上游名 = %q", c.UpstreamModel)
		}
	}
}

// catch-all（models 里有 "*"）与直通同类：也算兜底，让位给点名声明的。
func TestPickDeclaredBeatsCatchAll(t *testing.T) {
	r := New(config.RoutingConfig{}, []config.Provider{
		mapped("pinned", 1, map[string]string{"fast": "m-one"}),
		mkProvider("catchall", 1, config.ModelSpec{Map: map[string]string{"*": "*"}, CatchAll: true}),
	})
	for i := 0; i < 300; i++ {
		c, err := r.Pick("fast", nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.Provider.Name != "pinned" {
			t.Fatalf("第 %d 次选到了 catch-all 供应商 %q", i, c.Provider.Name)
		}
	}
	// 没被点名的模型名，仍旧由 catch-all 接住
	c, err := r.Pick("随便一个名字", nil)
	if err != nil {
		t.Fatalf("catch-all 应当接住未声明的模型名: %v", err)
	}
	if c.Provider.Name != "catchall" {
		t.Errorf("应当是 catchall，实际 %q", c.Provider.Name)
	}
}

// 兜底本身不能失效：池子里只有直通型时，照样用它。
func TestPickFallsBackToPassthroughWhenNobodyDeclares(t *testing.T) {
	r := New(config.RoutingConfig{}, []config.Provider{
		passthrough("any-a", 1),
		passthrough("any-b", 1),
	})
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		c, err := r.Pick("随便", nil)
		if err != nil {
			t.Fatal(err)
		}
		seen[c.Provider.Name]++
	}
	if len(seen) != 2 {
		t.Errorf("两家直通应当都在分担，实际 %v", seen)
	}
}

// 点名声明的那家进了冷却，也不该把请求让给兜底的 ——
// 「指名道姓要走这家」比「随便找一家能接的」更强，宁可让上层看到熔断，也别悄悄换个上游。
func TestPickDeclaredStaysPreferredEvenWhenUnhealthy(t *testing.T) {
	r := New(config.RoutingConfig{FailureThreshold: 1, CooldownSeconds: 60}, []config.Provider{
		mapped("declared", 1, map[string]string{"m": "m"}),
		passthrough("fallback", 1),
	})
	r.ReportFailure("declared", fmt.Errorf("boom")) // 打进冷却
	c, err := r.Pick("m", nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Provider.Name != "declared" {
		t.Errorf("冷却中也不该换上游，实际选了 %q", c.Provider.Name)
	}
}

// 重试时把点名的那家排除掉（它刚失败），这时才轮到兜底的顶上。
func TestPickDeclaredExcludedThenFallsBack(t *testing.T) {
	r := New(config.RoutingConfig{}, []config.Provider{
		mapped("declared", 1, map[string]string{"m": "m"}),
		passthrough("fallback", 1),
	})
	c, err := r.Pick("m", map[string]bool{"declared": true})
	if err != nil {
		t.Fatal(err)
	}
	if c.Provider.Name != "fallback" {
		t.Errorf("点名那家被排除后应当由兜底顶上，实际 %q", c.Provider.Name)
	}
}

// 点名的那家被停用，就退回到兜底。
func TestPickDeclaredDisabledFallsBack(t *testing.T) {
	d := mapped("declared", 1, map[string]string{"m": "m"})
	d.Enabled = false
	r := New(config.RoutingConfig{}, []config.Provider{d, passthrough("fallback", 1)})
	c, err := r.Pick("m", nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Provider.Name != "fallback" {
		t.Errorf("应当由兜底接，实际 %q", c.Provider.Name)
	}
}
