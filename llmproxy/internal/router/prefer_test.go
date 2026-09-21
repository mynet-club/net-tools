package router

import (
	"errors"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

// 会话粘性：点名的那家在候选池里且健康，就一直用它。
//
// 这是它存在的全部意义 —— 同一段对话的前缀缓存是按（上游账号+模型）分区的，
// 权重随机换家等于每次从冷缓存重来。
func TestPreferringHonorsNamedProvider(t *testing.T) {
	r := New(config.RoutingConfig{}, []config.Provider{
		mapped("alpha", 1, map[string]string{"m": "m"}),
		mapped("beta", 1, map[string]string{"m": "beta-up"}),
	})
	for i := 0; i < 300; i++ {
		c, err := r.PickFromPreferring("", r.providers, "m", nil, "beta")
		if err != nil {
			t.Fatal(err)
		}
		if c.Provider.Name != "beta" {
			t.Fatalf("第 %d 次没粘住，选到了 %q", i, c.Provider.Name)
		}
		// prefer 分支也必须走这家自己的映射，别返回裸 Provider 丢掉上游名
		if c.UpstreamModel != "beta-up" {
			t.Fatalf("第 %d 次上游名 = %q，应当是映射后的 beta-up", i, c.UpstreamModel)
		}
	}
}

// prefer 为空 == 老的 PickFrom：照旧按权重分担。
func TestPreferringEmptyIsPlainPick(t *testing.T) {
	r := New(config.RoutingConfig{}, []config.Provider{
		mapped("alpha", 1, map[string]string{"m": "m"}),
		mapped("beta", 1, map[string]string{"m": "m"}),
	})
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		c, err := r.PickFromPreferring("", r.providers, "m", nil, "")
		if err != nil {
			t.Fatal(err)
		}
		seen[c.Provider.Name]++
	}
	if len(seen) != 2 {
		t.Errorf("没指定优先项时应当两家都在分担，实际 %v", seen)
	}
}

// 点名的那家不在候选里（停用 / 不承接这个模型）→ 当作没提，正常选。
func TestPreferringIgnoredWhenUnavailable(t *testing.T) {
	disabled := mapped("beta", 1, map[string]string{"m": "m"})
	disabled.Enabled = false

	r := New(config.RoutingConfig{}, []config.Provider{
		mapped("alpha", 1, map[string]string{"m": "m"}),
		disabled,
	})
	for i := 0; i < 50; i++ {
		c, err := r.PickFromPreferring("", r.providers, "m", nil, "beta")
		if err != nil {
			t.Fatal(err)
		}
		if c.Provider.Name != "alpha" {
			t.Fatalf("停用的那家不该被粘住，实际 %q", c.Provider.Name)
		}
	}

	// 另一家不承接这个模型，同理
	r2 := New(config.RoutingConfig{}, []config.Provider{
		mapped("alpha", 1, map[string]string{"m": "m"}),
		mapped("beta", 1, map[string]string{"other": "other"}),
	})
	c, err := r2.PickFromPreferring("", r2.providers, "m", nil, "beta")
	if err != nil {
		t.Fatal(err)
	}
	if c.Provider.Name != "alpha" {
		t.Errorf("不承接该模型的那家不该被粘住，实际 %q", c.Provider.Name)
	}
}

// 重试时把点名的那家排除掉（它刚失败）→ 让位给另一家。
func TestPreferringIgnoredWhenExcluded(t *testing.T) {
	r := New(config.RoutingConfig{}, []config.Provider{
		mapped("alpha", 1, map[string]string{"m": "m"}),
		mapped("beta", 1, map[string]string{"m": "m"}),
	})
	c, err := r.PickFromPreferring("", r.providers, "m", map[string]bool{"beta": true}, "beta")
	if err != nil {
		t.Fatal(err)
	}
	if c.Provider.Name != "alpha" {
		t.Errorf("被排除的那家不该被粘住，实际 %q", c.Provider.Name)
	}
}

// 「后端不能用就换家」：点名的那家在冷却中时不粘，直接漂到健康的另一家。
// 漂移之后上层会把粘性更新到新家，于是不会改回来（避免两家来回横跳）。
func TestPreferringDriftsWhenPreferredIsCooling(t *testing.T) {
	r := New(config.RoutingConfig{FailureThreshold: 1, CooldownSeconds: 60}, []config.Provider{
		mapped("alpha", 1, map[string]string{"m": "m"}),
		mapped("beta", 1, map[string]string{"m": "m"}),
	})
	if c, _ := r.Pick("m", nil); c == nil {
		t.Fatal("初始选路失败")
	}
	r.ReportFailure("beta", errors.New("boom")) // 把点名的那家打进冷却

	for i := 0; i < 50; i++ {
		c, err := r.PickFromPreferring("", r.providers, "m", nil, "beta")
		if err != nil {
			t.Fatal(err)
		}
		if c.Provider.Name != "alpha" {
			t.Fatalf("冷却中的那家不该被粘住，实际 %q", c.Provider.Name)
		}
	}
}

// 粘性不能绕过「点名声明优先于通配兜底」。
//
// 场景：alpha 点名声明了 m，beta 是 models: ["*"] 的兜底。兜底那家已经被挤出候选池，
// 此时即便粘性指着 beta 也不生效 —— 否则粘性就成了绕过候选规则的旁路。
// 代价是声明方集合变化时会话会迁移一次，这是刻意接受的。
func TestPreferringDoesNotBypassDeclaredPriority(t *testing.T) {
	r := New(config.RoutingConfig{}, []config.Provider{
		mapped("alpha", 1, map[string]string{"m": "m"}),
		passthrough("beta", 1),
	})
	for i := 0; i < 200; i++ {
		c, err := r.PickFromPreferring("", r.providers, "m", nil, "beta")
		if err != nil {
			t.Fatal(err)
		}
		if c.Provider.Name != "alpha" {
			t.Fatalf("第 %d 次被粘到了兜底那家 %q（不该绕过点名声明的优先）", i, c.Provider.Name)
		}
	}
}

// 只有兜底那家能接的时候，粘性对它生效（此时它就在候选池里）。
func TestPreferringWorksWithinFallbackPool(t *testing.T) {
	r := New(config.RoutingConfig{}, []config.Provider{
		passthrough("beta", 1),
		passthrough("gamma", 1),
	})
	for i := 0; i < 100; i++ {
		c, err := r.PickFromPreferring("", r.providers, "没人声明过的名字", nil, "gamma")
		if err != nil {
			t.Fatal(err)
		}
		if c.Provider.Name != "gamma" {
			t.Fatalf("兜底之间也该能粘，实际 %q", c.Provider.Name)
		}
	}
}

// prefer 的那家在最终候选池里，但**正在冷却** —— 不该硬粘死它。
//
// 这条钉的是 router.go 里 `item.healthy` 那个判断：把 healthy 检查删掉，
// 下面这个用例必须变红（否则「后端不能用就换家」这条语义就是裸奔的 ——
// 早期写测试时只构造了「prefer 那家压根不在池子里」的情况，删掉 healthy 也全绿）。
func TestPreferringDoesNotStickWhenInPoolButUnhealthy(t *testing.T) {
	r := New(config.RoutingConfig{FailureThreshold: 1, CooldownSeconds: 60}, []config.Provider{
		mapped("alpha", 1, map[string]string{"m": "m"}),
		mapped("beta", 1, map[string]string{"m": "m"}),
	})
	// 两家都点名声明、也都进冷却 → 最终池子是 explAll，且两家里 healthy 都是 false。
	// 这时 prefer 指着 beta：它在池子里，但不能用。
	r.ReportFailure("alpha", errors.New("boom"))
	r.ReportFailure("beta", errors.New("boom"))

	seen := map[string]int{}
	for i := 0; i < 300; i++ {
		c, err := r.PickFromPreferring("", r.providers, "m", nil, "beta")
		if err != nil {
			t.Fatal(err)
		}
		seen[c.Provider.Name]++
	}
	if seen["alpha"] == 0 {
		t.Errorf("prefer 在池子里但已冷却时不该硬粘死它，实际 %v", seen)
	}
	if seen["beta"] == 0 {
		t.Errorf("两家都在冷却时应当按权重随机（既不硬粘也不硬换），实际 %v", seen)
	}
}
