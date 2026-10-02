package replay

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// Sampler 是回放侧的确定性抽样接口（§2.8）。
//
// 分工必须清楚：**在线模式的权重随机不受本包影响**，本接口只负责「给定 seed 之后，
// 用独立的确定性随机源复现当时那次选择」。D 包（internal/routing）合并后，
// 主线可以把自己的抽样实现注进来（Algo() 返回 D 的算法标识），这样在线与回放逐位一致；
// 记录里的 sampling_algo 就是用来判断能不能做这种强断言的。
type Sampler interface {
	// Algo 返回抽样算法标识，与 RoutingRecord.SamplingAlgo 对齐。
	Algo() string

	// Sequence 返回尝试顺序（首选在前），元素是 provider 稳定 ID。
	// rejected 里的 provider 已被排除，不参与抽样；候选必须按稳定顺序进入。
	Sequence(seed string, candidates []policy.RouteCandidate, rejected map[string]bool) ([]string, error)
}

// samplingDomain 是派生随机流的域分隔前缀。带上算法名，改抽样口径时
// 旧记录不会被新实现误当成「可逐位复现」。
const samplingDomain = "llmproxy-replay-sampling-v1"

// weightScale 把 float 权重量化成整数刻度。
//
// 抽样必须跨机器、跨语言逐位可复现，浮点累加顺序与 FMA 优化都可能改变结果；
// 量化成定点整数后用整数取模，结果只取决于 seed 流与权重刻度。
const weightScale = 1_000_000

// maxWeight 是单个权重的上限，超出说明配置写错了（而不是「极大优先」）。
const maxWeight = 1e12

// localSampler 是本包自带的确定性抽样实现（replay-sampling-v1）。
type localSampler struct{}

// NewLocalSampler 返回默认抽样器。
func NewLocalSampler() Sampler { return localSampler{} }

func (localSampler) Algo() string { return SamplingAlgoReplayV1 }

// Sequence 用 seed 派生的比特流做**不放回**加权抽样：
//  1. 候选先按 policy.SortCandidates 的稳定顺序排好（§2.8 禁止依赖 map 遍历顺序）；
//  2. 剔除被排除的 provider；
//  3. 每抽一次消耗一个 64 位派生值，按整数权重前缀和定位；
//  4. 权重总和为 0 时退化成等概率（仍然确定性），避免整条回放卡死。
func (s localSampler) Sequence(seed string, candidates []policy.RouteCandidate, rejected map[string]bool) ([]string, error) {
	if err := policy.ParseRoutingSeed(seed); err != nil {
		return nil, err
	}
	pool, err := poolFor(candidates, rejected)
	if err != nil {
		return nil, err
	}
	if len(pool) == 0 {
		return nil, errors.New("replay: 候选全部被排除，无法复现任何选择")
	}
	units, err := weightUnits(pool)
	if err != nil {
		return nil, err
	}
	seedBytes, err := decodeHexSeed(seed)
	if err != nil {
		return nil, err
	}

	remaining := make([]policy.RouteCandidate, len(pool))
	copy(remaining, pool)
	leftUnits := make([]uint64, len(units))
	copy(leftUnits, units)

	out := make([]string, 0, len(pool))
	counter := uint64(0)
	for len(remaining) > 0 {
		total := uint64(0)
		for _, u := range leftUnits {
			total += u
		}
		draw := s.nextDraw(seedBytes, counter)
		counter++
		idx := 0
		if total == 0 {
			// 全零权重：等概率。留着它而不是报错，是因为在线侧允许权重全 0（等价于均匀分布），
			// 回放必须能复现同一次选择；但这条退化路径要在报告里显式写出来。
			idx = int(draw % uint64(len(remaining)))
		} else {
			target := draw % total
			acc := uint64(0)
			for i, u := range leftUnits {
				acc += u
				if target < acc {
					idx = i
					break
				}
			}
		}
		out = append(out, remaining[idx].Provider)
		remaining = append(remaining[:idx], remaining[idx+1:]...)
		leftUnits = append(leftUnits[:idx], leftUnits[idx+1:]...)
	}
	return out, nil
}

// nextDraw 给出第 i 个 64 位派生值：SHA-256(domain || seed || be64(i)) 的前 8 字节。
//
// 用计数器模式而不是靠 math/rand 的种子：math/rand 的内部算法是 Go 实现细节，
// 升级运行时就可能改变序列，那会让历史审计永远回放不出来。
func (localSampler) nextDraw(seedBytes []byte, counter uint64) uint64 {
	h := sha256.New()
	_, _ = h.Write([]byte(samplingDomain))
	_, _ = h.Write([]byte{byte(len(seedBytes))})
	_, _ = h.Write(seedBytes)
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], counter)
	_, _ = h.Write(be[:])
	sum := h.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8])
}

// poolFor 去重（同 provider 只留一个）、剔除被排除项，并保证稳定顺序。
func poolFor(candidates []policy.RouteCandidate, rejected map[string]bool) ([]policy.RouteCandidate, error) {
	sorted := policy.SortCandidates(candidates)
	seen := make(map[string]bool, len(sorted))
	out := make([]policy.RouteCandidate, 0, len(sorted))
	for _, c := range sorted {
		if err := c.Validate(); err != nil {
			return nil, err
		}
		if seen[c.Provider] {
			return nil, fmt.Errorf("replay: 候选 provider %q 重复", c.Provider)
		}
		seen[c.Provider] = true
		if rejected[c.Provider] {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

// weightUnits 把权重量化成整数刻度；非法权重（负数、NaN、Inf、超上限）直接报错，
// 让抽样器静默按 0 处理就是把配置错误变成不可见的行为差异。
func weightUnits(cs []policy.RouteCandidate) ([]uint64, error) {
	out := make([]uint64, 0, len(cs))
	for _, c := range cs {
		if math.IsNaN(c.Weight) || math.IsInf(c.Weight, 0) {
			return nil, fmt.Errorf("replay: 候选 %q 的权重不是有限值: %v", c.Provider, c.Weight)
		}
		if c.Weight < 0 {
			return nil, fmt.Errorf("replay: 候选 %q 的权重为负: %v", c.Provider, c.Weight)
		}
		if c.Weight > maxWeight {
			return nil, fmt.Errorf("replay: 候选 %q 的权重超出上限 %v", c.Provider, maxWeight)
		}
		out = append(out, uint64(math.Round(c.Weight*weightScale)))
	}
	return out, nil
}

// decodeHexSeed 把记录里的十六进制 seed 还原成字节。
// 先过 policy.ParseRoutingSeed 的闭集校验，再解码：长度或字符不对都必须报错，
// 而不是截断后抽出一个「看起来一样」的序列。
func decodeHexSeed(seed string) ([]byte, error) {
	if err := policy.ParseRoutingSeed(seed); err != nil {
		return nil, err
	}
	out, err := hex.DecodeString(seed)
	if err != nil {
		return nil, fmt.Errorf("replay: routing_seed 解码失败: %w", err)
	}
	return out, nil
}

// providersOf 返回候选的 provider 顺序，用于把抽样序列转成可比对的字段值。
func providersOf(cs []policy.RouteCandidate) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Provider)
	}
	return out
}
