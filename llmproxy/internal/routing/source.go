package routing

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// RandomSource 是抽样用的随机数来源。只要一个方法，是为了让调用方能把现网
// 正在使用的那个随机源（例如 rand.Rand）原样注入，不改变流量分布。
//
// 约定与 math/rand.Float64 一致：返回值落在 [0,1)。
type RandomSource interface {
	Float64() float64
}

// 回放用的确定性发生器参数。改动任何一项都会让历史 ReplayInput 失效，
// 因此这里带版本号：需要换算法时新增 v2 常量并让回放输入自带算法标识。
const (
	// splitmixGoldenGamma 是 splitmix64 的增量常量 0x9E3779B97F4A7C15
	// （= 2^64 / 黄金比例）。这些魔数是公开标准算法的一部分，跨语言实现照抄
	// 即可与这里逐位一致。
	splitmixGoldenGamma = uint64(0x9E3779B97F4A7C15)
	splitmixMix1        = uint64(0xBF58476D1CE4E5B9)
	splitmixMix2        = uint64(0x94D049BB133111EB)
	// float53Mask 取高 53 位，凑成 [0,1) 上均匀的双精度数，
	// 与 math/rand.Float64 的构造方式相同，分布因此可直接对比。
	float53Shift = 11
)

// splitmixSource 是 splitmix64 状态机。单个实例只服务一次规划，不跨请求共享，
// 所以不需要锁；Planner 本身无状态，并发安全来自「每次调用各自 new」。
type splitmixSource struct {
	state uint64
}

// SeededSource 按显式 seed 构造确定性随机源（§2.8 回放模式的唯一入口）。
//
// 状态 = sha256(seed 的 UTF-8 字节) 的前 8 字节按小端解释。seed 本身应是
// policy.DeriveRoutingSeed 产出、policy.ParseRoutingSeed 校验过的 64 位十六进制串；
// 这里再哈希一次是为了让「任意字符串 seed」也有固定长度与均匀分布，
// 而不是靠调用方自觉。
//
// 不使用 math/rand：全局源会被别人 Seed 干扰且带锁，rand.New 的源码实现则从
// Go 1.20 起在 jumpHash 与旧的 lagged Fibonacci 之间变过 —— 审计要能十年后重算，
// 就不能把结论压在标准库的内部实现上。
func SeededSource(seed string) RandomSource {
	sum := sha256.Sum256([]byte(seed))
	return &splitmixSource{state: binary.LittleEndian.Uint64(sum[:8])}
}

// Uint64 推进状态并输出一个 64 位数（splitmix64 标准形式：先加后混淆）。
func (s *splitmixSource) Uint64() uint64 {
	s.state += splitmixGoldenGamma
	z := s.state
	z = (z ^ (z >> 30)) * splitmixMix1
	z = (z ^ (z >> 27)) * splitmixMix2
	return z ^ (z >> 31)
}

// Float64 返回 [0,1) 上的确定性双精度数。
func (s *splitmixSource) Float64() float64 {
	return float64(s.Uint64()>>float53Shift) * (1.0 / float64(uint64(1)<<53))
}

// resolveSource 决定本次规划用哪个随机源。
//
// 规则：Seed 非空一律走确定性源（线上派生 seed 后用它抽样，等于顺手拿到可回放能力，
// 且分布仍是均匀权重随机）；否则用调用方注入的 Source（现网行为）；两个都没有就报错，
// 绝不退化成 math/rand 全局源 —— 静默用全局源会让这条审计再也解释不出来。
func resolveSource(seed string, src RandomSource) (RandomSource, error) {
	if seed != "" {
		if err := validateSeed(seed); err != nil {
			return nil, err
		}
		return SeededSource(seed), nil
	}
	if src != nil {
		return src, nil
	}
	return nil, fmt.Errorf("%w: 既没有 seed 也没有注入随机源，无法在不牺牲可复现性的前提下抽样", ErrInput)
}
