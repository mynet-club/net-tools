package replay

import (
	"strconv"
	"strings"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

func seedFor(t *testing.T, requestID, version, epoch string) string {
	t.Helper()
	seed, err := policy.DeriveRoutingSeed(requestID, version, epoch)
	if err != nil {
		t.Fatalf("派生 seed 失败: %v", err)
	}
	return seed
}

// §2.8 的核心断言：候选排序只认稳定 provider ID，绝不依赖 map 遍历顺序。
func TestSamplerIsInvariantToInputOrder(t *testing.T) {
	cands := []policy.RouteCandidate{
		candidate("p1", "gpt-mini", 1),
		candidate("p2", "gpt-5", 5),
		candidate("p3", "public-demo", 2),
		candidate("p4", "internal-a", 1),
	}
	seed := seedFor(t, "req-sampler", "university-default@3", "epoch-1")
	s := NewLocalSampler()
	want, err := s.Sequence(seed, cands, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		got, err := s.Sequence(seed, shuffledCandidates(cands, int64(i)+1), nil)
		if err != nil {
			t.Fatalf("第 %d 次打乱后抽样失败: %v", i, err)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("第 %d 次打乱后序列变了: %v vs %v", i, got, want)
		}
	}
}

func TestSamplerIsRepeatableAndPermutation(t *testing.T) {
	cands := []policy.RouteCandidate{candidate("p1", "gpt-mini", 1), candidate("p2", "gpt-5", 3)}
	seed := seedFor(t, "req-repeat", "university-default@3", "epoch-1")
	s := NewLocalSampler()
	first, err := s.Sequence(seed, cands, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 {
		t.Fatalf("不放回抽样必须覆盖全部候选: %v", first)
	}
	for i := 0; i < 50; i++ {
		again, err := s.Sequence(seed, cands, nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(again, ",") != strings.Join(first, ",") {
			t.Fatalf("同一 seed 必须给出同一序列: %v vs %v", again, first)
		}
	}
	if first[0] == first[1] {
		t.Fatal("序列里出现重复候选")
	}
	// 不同 seed 给出不同序列（至少不恒等于稳定顺序，否则等于没抽样）。
	other := seedFor(t, "req-repeat-2", "university-default@3", "epoch-1")
	second, err := s.Sequence(other, cands, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second[0] == first[0] && second[1] == first[1] {
		t.Log("两个 seed 恰好同序：概率事件，不做失败断言")
	}
}

func TestSamplerHonoursZeroWeight(t *testing.T) {
	cands := []policy.RouteCandidate{
		candidate("never", "gpt-mini", 0),
		candidate("heavy", "gpt-5", 10),
		candidate("mid", "public-demo", 4),
	}
	s := NewLocalSampler()
	for i := 0; i < 200; i++ {
		seed := seedFor(t, "req-zero", "university-default@3", "epoch-"+string(rune('a'+i%26)))
		seq, err := s.Sequence(seed, cands, nil)
		if err != nil {
			t.Fatal(err)
		}
		if seq[0] == "never" {
			// 权重全为 0 时才允许均匀分布；这里有正权重，0 权重候选不能当首选。
			t.Fatalf("权重 0 的候选被选为首选（第 %d 次）: %v", i, seq)
		}
	}
}

func TestSamplerDistributionFollowsWeights(t *testing.T) {
	cands := []policy.RouteCandidate{
		candidate("light", "gpt-mini", 1),
		candidate("heavy", "gpt-5", 9),
	}
	s := NewLocalSampler()
	heavyPrimary := 0
	total := 400
	for i := 0; i < total; i++ {
		seed := seedFor(t, "req-dist-"+strconv.Itoa(i), "university-default@3", "epoch-1")
		seq, err := s.Sequence(seed, cands, nil)
		if err != nil {
			t.Fatal(err)
		}
		if seq[0] == "heavy" {
			heavyPrimary++
		}
	}
	// 9:1 的权重，首选比例应显著偏向 heavy；只要求过半，避免把断言做成脆弱的统计检验。
	if heavyPrimary*2 < total {
		t.Fatalf("权重抽样没有体现权重分布：heavy 首选 %d/%d", heavyPrimary, total)
	}
}

func TestSamplerSkipsRejectedAndAllZeroWeightFallsBackToUniform(t *testing.T) {
	cands := []policy.RouteCandidate{candidate("p1", "gpt-mini", 1), candidate("p2", "gpt-5", 1)}
	seed := seedFor(t, "req-rejected", "university-default@3", "epoch-1")
	s := NewLocalSampler()
	seq, err := s.Sequence(seed, cands, map[string]bool{"p2": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(seq) != 1 || seq[0] != "p1" {
		t.Fatalf("被排除的候选必须不参与抽样: %v", seq)
	}

	zero := []policy.RouteCandidate{candidate("p1", "gpt-mini", 0), candidate("p2", "gpt-5", 0)}
	first, err := s.Sequence(seed, zero, nil)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.Sequence(seed, zero, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(first, ",") != strings.Join(again, ",") {
		t.Fatal("全零权重的退化路径也必须确定性")
	}
	if len(first) != 2 {
		t.Fatalf("全零权重仍要给出完整尝试序列: %v", first)
	}
}

func TestSamplerRejectsBadInput(t *testing.T) {
	seed := seedFor(t, "req-bad", "university-default@3", "epoch-1")
	s := NewLocalSampler()
	if _, err := s.Sequence("zz", []policy.RouteCandidate{candidate("p1", "m", 1)}, nil); err == nil {
		t.Fatal("非法 seed 必须报错")
	}
	if _, err := s.Sequence(seed, nil, nil); err == nil {
		t.Fatal("空候选池必须报错")
	}
	if _, err := s.Sequence(seed, []policy.RouteCandidate{candidate("p1", "m", 1)},
		map[string]bool{"p1": true}); err == nil {
		t.Fatal("候选全被排除必须报错，不能返回空序列冒充复现")
	}
	negative := []policy.RouteCandidate{{Executor: "e", Provider: "p1", Model: "m", UpstreamModel: "m", Weight: -1, MaxDataLevel: policy.LevelPublic}}
	if _, err := s.Sequence(seed, negative, nil); err == nil {
		t.Fatal("负权重必须报错")
	}
	dup := []policy.RouteCandidate{candidate("p1", "m", 1), candidate("p1", "m2", 1)}
	if _, err := s.Sequence(seed, dup, nil); err == nil {
		t.Fatal("provider 重复必须报错")
	}
	huge := []policy.RouteCandidate{candidate("p1", "m", 1e18)}
	if _, err := s.Sequence(seed, huge, nil); err == nil {
		t.Fatal("超出上限的权重必须报错")
	}
}

func TestSamplerDoesNotUseGlobalRandom(t *testing.T) {
	// 同 seed 在同一进程内、跨不同候选顺序都恒定；如果实现偷用了全局随机源，
	// 这两次调用就会分叉。
	cands := []policy.RouteCandidate{candidate("p1", "gpt-mini", 1), candidate("p2", "gpt-5", 2), candidate("p3", "public-demo", 3)}
	seed := seedFor(t, "req-noglobal", "university-default@3", "epoch-1")
	s := NewLocalSampler()
	a, _ := s.Sequence(seed, cands, nil)
	b, _ := s.Sequence(seed, shuffledCandidates(cands, 7), nil)
	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Fatalf("抽样依赖了额外状态: %v vs %v", a, b)
	}
}
