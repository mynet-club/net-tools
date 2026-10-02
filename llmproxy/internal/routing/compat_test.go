package routing

import (
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 旧版静态 provider 路由兼容（§6 最后一条）。
//
// fixture 的形状与 internal/router 的 PickFromPreferring 一一对应：
//   - 候选池 = 该模型的承接者，池内按 provider 名升序（现网 CandidatesOf 就按名字排序）；
//   - Tier 由**调用方**按现网 8 档次序算好：
//     0 自有·点名·健康 / 1 自有·点名·冷却 / 2 系统·点名·健康 / 3 系统·点名·冷却 /
//     4 自有·兜底·健康 / 5 自有·兜底·冷却 / 6 系统·兜底·健康 / 7 系统·兜底·冷却；
//     D 只认「小者优先」，不认识这些档名（手册 §5：档序只有一个事实源）。
//   - 抽样 = 首个非空档内按有效权重的累积扫描，随机数由脚本给定，
//     所以期望值可以手算 —— 本文件**不重新实现**现网算法，只钉住同 fixture 同结论。
//
// 每条期望值旁边的算式就是现网那段代码在同一输入下会走的路径。

func TestLegacyParityPicks(t *testing.T) {
	cases := []struct {
		name   string
		offers []Offer
		prefer string
		draw   float64
		want   string
		calc   string
	}{
		{
			name: "权重 3:1 小随机数命中池首",
			// total = 3+1 = 4；x = 0.25*4 = 1.0；acc(alpha)=3 → 1.0 ≤ 3 → alpha
			offers: []Offer{offerFor("alpha", 0, 3, testModel), offerFor("beta", 0, 1, testModel)},
			draw:   0.25, want: "alpha", calc: "x=1.0 ≤ 3",
		},
		{
			name: "权重 3:1 大随机数命中池尾",
			// x = 0.9*4 = 3.6；acc(alpha)=3 → 3.6 > 3；acc(beta)=4 → 3.6 ≤ 4 → beta
			offers: []Offer{offerFor("alpha", 0, 3, testModel), offerFor("beta", 0, 1, testModel)},
			draw:   0.9, want: "beta", calc: "x=3.6 > 3, ≤ 4",
		},
		{
			name:   "随机数取 0 也落在池首",
			offers: []Offer{offerFor("alpha", 0, 1, testModel), offerFor("beta", 0, 1, testModel)},
			draw:   0, want: "alpha", calc: "x=0 ≤ 1",
		},
		{
			name: "未配权重按 1 参与（现网 bucketize 同形）",
			// alpha 权重 0 → 折算 1；total = 1+2 = 3；x = 0.6*3 = 1.8；
			// acc(alpha)=1 → 1.8 > 1；acc(beta)=3 → 1.8 ≤ 3 → beta
			offers: []Offer{offerFor("alpha", 0, 0, testModel), offerFor("beta", 0, 2, testModel)},
			draw:   0.6, want: "beta", calc: "w(0)→1, x=1.8 ∈ (1,3]",
		},
		{
			name: "自有·点名档非空时系统池不参与",
			// 首个非空档是 tier0 = {alpha}，tier1 的 beta 权重再高也轮不到。
			offers: []Offer{offerFor("alpha", 0, 1, testModel), offerFor("beta", 1, 99, testModel)},
			draw:   0.5, want: "alpha", calc: "pool=[alpha], total=1, x=0.5 ≤ 1",
		},
		{
			name: "点名声明压过通配兜底",
			// 现网：有人点名声明该模型 → 通配整档不进池；调用方把兜底那家放 tier4。
			// 池 = tier0 = {declared}。
			offers: []Offer{
				offerFor("declared", 0, 1, testModel),
				offerFor("catchall", 4, 5, wildcardModel),
			},
			draw: 0.99, want: "declared", calc: "pool=[declared]",
		},
		{
			name: "只有兜底能接时兜底入选",
			offers: []Offer{
				offerFor("catchall-a", 4, 1, wildcardModel),
				offerFor("catchall-b", 4, 1, wildcardModel),
			},
			draw: 0.75, want: "catchall-b", calc: "pool=[a(1) b(1)], total=2, x=1.5 > 1 → b",
		},
		{
			name: "全档冷却时仍按权重随机（宁可重试也不硬失败）",
			// 调用方把冷却的两家标到 tier1（现网 *All 档），tier0 为空 → 池 = tier1。
			offers: []Offer{
				offerFor("alpha", 1, 1, testModel).cooling(testNow.Add(time.Minute)),
				offerFor("beta", 1, 1, testModel).unhealthy(),
			},
			draw: 0.75, want: "beta", calc: "pool=[alpha(1) beta(1)], x=1.5 > 1 → beta",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := ctxFor(t, policy.LevelInternal)
			chain := orgChain(t)
			src := newScripted(t, tc.draw)
			in := inputFor(&allowAllGate{}, ObjectiveFixedOrder, tc.offers...)
			in.Source = src
			if tc.prefer != "" {
				in.Sticky = &StickyState{Provider: tc.prefer}
			}
			plan, err := NewPlanner().Plan(ctx, chain, in)
			if err != nil {
				t.Fatalf("规划失败: %v", err)
			}
			if src.calls != 1 {
				t.Errorf("现网一次选路只取一个随机数，实际取了 %d 个", src.calls)
			}
			c, _ := plan.Primary()
			if c.Provider != tc.want {
				t.Fatalf("首选 = %s，应为 %s（%s）", c.Provider, tc.want, tc.calc)
			}
			// 首选必须把上游模型名带回去：现网 PickFromPreferring 的粘性分支也要带上，
			// 丢掉映射就等于把请求发给一个并不叫这个名字的上游。
			if c.UpstreamModel != c.Provider+"-up" {
				t.Errorf("上游模型名不对: %+v", c)
			}
		})
	}
}

// 粘性（现网 prefer）在池内且可用 → 直接命中，不取随机数。
func TestLegacyParityStickyPreferred(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	src := newScripted(t) // 脚本里没有数：取一个就 panic
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder,
		offerFor("alpha", 0, 1, testModel),
		offerFor("beta", 0, 1, testModel).withUpstream("beta-real"),
	)
	in.Source = src
	in.Sticky = &StickyState{Provider: "beta"}
	plan, err := NewPlanner().Plan(ctx, chain, in)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := plan.Primary()
	if c.Provider != "beta" || c.UpstreamModel != "beta-real" {
		t.Fatalf("应粘住 beta 并带上它自己的上游名，实际 %+v", c)
	}
	if src.calls != 0 {
		t.Errorf("命中粘性却消耗了 %d 个随机数（现网直接 return，不掷骰子）", src.calls)
	}
}

// 粘性指向「池外」的候选（现网语义：不在最终候选池 = 当作没提）。
//
// 现网把这条写成两段：prefer 只在池子里生效，否则按原规则随机。
// D 里池子 = 首选所在档，beta 在 tier1 而 tier0 非空 → beta 不在池内 → 随机。
func TestLegacyParityStickyOutsidePool(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	src := newScripted(t, 0.1)
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder,
		offerFor("alpha", 0, 1, testModel),
		offerFor("beta", 1, 1, testModel),
	)
	in.Source = src
	in.Sticky = &StickyState{Provider: "beta"}
	plan, err := NewPlanner().Plan(ctx, chain, in)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := plan.Primary(); c.Provider != "alpha" {
		t.Errorf("池外的 prefer 不该生效，实际 %s", c.Provider)
	}
	if src.calls != 1 {
		t.Errorf("没命中粘性时必须回落到权重随机，实际消耗 %d 个随机数", src.calls)
	}
}

// 与现网的一处**已知差异**（不是回归）：现网重试时「点名声明独占」会把通配整档
// 从所有池子里摘掉，因此声明方全部失败后现网直接报「没有供应商能承接」；
// D 把通配候选留在低一档的 fallback 链上，交给执行器按 Attempts() 继续试。
//
// 这条差异写成测试是为了让它在评审时显眼：如果主线要求 fallback 也与现网一致，
// 修法在**调用方的档序计算**（不传通配候选）而不是 D 里再加一份独占规则 ——
// 那样会凭空多出第二个事实源（§5）。
func TestKnownDifferenceWildcardStaysInFallbackChain(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder,
		offerFor("declared", 0, 1, testModel),
		offerFor("catchall", 4, 1, wildcardModel),
	)
	plan := planWithSeed(t, ctx, chain, in, deriveSeed(t, "req-diff", testPolicyVer))

	if c, _ := plan.Primary(); c.Provider != "declared" {
		t.Fatalf("首选仍须与现网一致（declared），实际 %s", c.Provider)
	}
	if got := strings.Join(orderOf(plan), ","); got != "declared,catchall" {
		t.Fatalf("fallback 链应与现网不同（多留一档兜底），实际 %s", got)
	}
}

// 现网的档内随机 + 档序 + 冷却三段合起来的完整 fixture：
// 六个 provider 分别落在 8 档中的四档，逐个随机数核对首选。
func TestLegacyParityMixedTiers(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	offers := []Offer{
		offerFor("own-sys-b", 2, 4, testModel),      // 系统·点名·健康
		offerFor("own-decl", 0, 1, testModel),       // 自有·点名·健康
		offerFor("own-catch", 4, 10, wildcardModel), // 自有·兜底·健康
		offerFor("own-decl-cooling", 1, 7, testModel).cooling(testNow.Add(time.Minute)),
		offerFor("sys-decl", 2, 2, testModel), // 同档：系统·点名·健康
	}
	// tier0 只有 own-decl → 无论随机数多大都选它。
	for _, draw := range []float64{0.0, 0.5, 0.99} {
		src := newScripted(t, draw)
		in := inputFor(&allowAllGate{}, ObjectiveFixedOrder, offers...)
		in.Source = src
		plan, err := NewPlanner().Plan(ctx, chain, in)
		if err != nil {
			t.Fatal(err)
		}
		if c, _ := plan.Primary(); c.Provider != "own-decl" {
			t.Fatalf("draw=%.2f 下首选 = %s，应为 own-decl（tier0 唯一成员）", draw, c.Provider)
		}
	}
	// 把 tier0、tier1 抽空：只剩系统·点名·健康档（权重 4 与 2，池内按 id 升序）。
	src := newScripted(t, 0.9)
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder, offers...)
	in.Requirement.Model = testModel
	in.Offers = Offers{
		offerFor("own-sys-b", 2, 4, testModel),
		offerFor("sys-decl", 2, 2, testModel),
		offerFor("own-catch", 4, 10, wildcardModel),
	}
	in.Source = src
	plan, err := NewPlanner().Plan(ctx, chain, in)
	if err != nil {
		t.Fatal(err)
	}
	// 池 = [own-sys-b(4) sys-decl(2)]，total=6，x=5.4 > 4 → sys-decl。
	if c, _ := plan.Primary(); c.Provider != "sys-decl" {
		t.Errorf("首选 = %s，应为 sys-decl（x=5.4 落在 (4,6]）", c.Provider)
	}
	// 兜底那家权重最高（10），但档序更低 → 只能进 fallback 链，不能压过系统点名档。
	if got := strings.Join(orderOf(plan), ","); got != "sys-decl,own-sys-b,own-catch" {
		t.Errorf("fallback 链不对: %s", got)
	}
}
