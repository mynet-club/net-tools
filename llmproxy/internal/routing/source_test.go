package routing

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// 手工复现一次发生器（sha256(seed) 前 8 字节小端 + splitmix64），
// 证明 SeededSource 是「按公开算法可重算」的，而不是只有本包能懂的私有状态。
// 跨语言侧（审计离线复核、Go 版本升级）只需要这两步。
func referenceFloat64(seed string, n int) float64 {
	sum := sha256.Sum256([]byte(seed))
	state := binary.LittleEndian.Uint64(sum[:8])
	for i := 0; i <= n; i++ {
		state += 0x9E3779B97F4A7C15
		z := state
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
		z = (z ^ (z >> 27)) * 0x94D049BB133111EB
		if i == n {
			return float64((z^(z>>31))>>11) * (1.0 / float64(uint64(1)<<53))
		}
	}
	panic("unreachable")
}

func TestSeededSourceMatchesPublicAlgorithm(t *testing.T) {
	seed := deriveSeed(t, "req-algo", testPolicyVer)
	src := SeededSource(seed)
	for i := 0; i < 5; i++ {
		want := referenceFloat64(seed, i)
		if got := src.Float64(); math.Abs(got-want) > 1e-18 {
			t.Fatalf("第 %d 个数与公开算法不一致: %v vs %v", i, got, want)
		}
	}
}

// 同一 seed 同一序列；不同 seed 序列不同。这是「逐位复现」的底层保证。
func TestSeededSourceIsDeterministic(t *testing.T) {
	seed := deriveSeed(t, "req-same", testPolicyVer)
	a, b := SeededSource(seed), SeededSource(seed)
	for i := 0; i < 50; i++ {
		fa, fb := a.Float64(), b.Float64()
		if fa != fb {
			t.Fatalf("第 %d 个数两个实例不一致: %v vs %v", i, fa, fb)
		}
		if fa < 0 || fa >= 1 {
			t.Fatalf("第 %d 个数 %v 越出 [0,1)", i, fa)
		}
	}
	other := deriveSeed(t, "req-other", testPolicyVer)
	if other == seed {
		t.Fatal("seed 派生失效：不同 requestID 撞出了同一个 seed")
	}
	if SeededSource(other).Float64() == SeededSource(seed).Float64() {
		t.Error("不同 seed 的第一个输出相同，说明状态没被 seed 完整决定")
	}
}

// seed 的每个比特都要影响输出：不能只用前缀（否则 requestID 后缀相同的两个请求会撞车）。
func TestSeededSourceUsesWholeSeed(t *testing.T) {
	base := strings.Repeat("a", 64)
	tail := strings.Repeat("a", 63) + "b"
	if SeededSource(base).Float64() == SeededSource(tail).Float64() {
		t.Error("只改变了 seed 的最后一位却给出同一个数")
	}
}

// 分布粗检：权重 3:1 的池子里，抽取比例应接近 3:1。
//
// 这条不是为了精确（种子序列不是独立同分布的样本流），而是挡住「累积扫描写成
// 恒定返回池首」这类只看单点看不出来的回归。
func TestSeededSamplingRoughlyFollowsWeights(t *testing.T) {
	pool := sortedByProviderID([]Offer{
		offerFor("alpha", 0, 3, testModel),
		offerFor("beta", 0, 1, testModel),
	})
	hits := map[string]int{}
	for i := 0; i < 2000; i++ {
		// 每轮换一个 requestID 再派生 seed：走的就是线上那条路，
		// 顺带证明「seed 派生 → 抽样」整条链的分布是权重比例的。
		seed := deriveSeed(t, "req-dist-"+strconv.Itoa(i), testPolicyVer)
		c := weightedSample(pool, SeededSource(seed))
		hits[c.provider()]++
	}
	ratio := float64(hits["alpha"]) / float64(hits["beta"])
	if ratio < 1.8 || ratio > 7 {
		t.Fatalf("权重 3:1 的实测比例 %.2f 偏离过大: %v", ratio, hits)
	}
}

// 并发取数：每个实例各自持有状态，不共享、不加锁、不互相串号。
func TestSeededSourceConcurrentInstances(t *testing.T) {
	seed := deriveSeed(t, "req-race", testPolicyVer)
	ref := SeededSource(seed)
	want := make([]float64, 32)
	for i := range want {
		want[i] = ref.Float64() // 单个实例推进，作为各 goroutine 的期望序列
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			src := SeededSource(seed)
			for k := 0; k < 32; k++ {
				if got := src.Float64(); got != want[k] {
					t.Errorf("并发下第 %d 个数不一致: %v vs %v", k, got, want[k])
					return
				}
			}
		}()
	}
	wg.Wait()
}

// 非法 seed 必须在抽样前拦掉：放行会让「回放用了另一个发生器状态」伪装成成功。
func TestResolveSourceRejectsBadSeed(t *testing.T) {
	for _, seed := range []string{"abc", strings.Repeat("z", 64), strings.Repeat("0", 63)} {
		if _, err := resolveSource(seed, newScripted(t, 0.5)); err == nil {
			t.Errorf("seed %q 应被拒绝", seed)
		}
	}
	// 有合法 seed 时忽略注入源：否则回放会跟着线上那个源的节奏走。
	src := newScripted(t)
	got, err := resolveSource(deriveSeed(t, "req-x", testPolicyVer), src)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.(*splitmixSource); !ok {
		t.Errorf("带 seed 时必须用确定性源，实际 %T", got)
	}
	if src.calls != 0 {
		t.Errorf("注入源不该被碰")
	}
	// 两者都没有 → 报错，且不退到 math/rand 全局源。
	if _, err := resolveSource("", nil); err == nil {
		t.Error("既无 seed 也无注入源必须报错")
	} else if !strings.Contains(err.Error(), "随机源") {
		t.Errorf("错误信息应说明缺随机源: %v", err)
	}
}
