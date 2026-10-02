package replay

import (
	"errors"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 本包的哨兵错误。回放的失败路径一律 fail_closed，所以这些错误都必须由调用方
// 显式处理，不允许「拿不到就按不通过」以外的静默兜底。
var (
	// ErrClockRequired 回放必须显式指定时钟：策略与身份的过期语义全靠 now 复现，
	// 用当前墙钟会让同一条记录在 8 小时后变成 deny，于是「回放一致」再也无法证明。
	ErrClockRequired = errors.New("replay: 回放必须显式指定时钟 now")

	// ErrEmptyBundleSet 没有策略包就没有任何可复现的判定来源。
	ErrEmptyBundleSet = errors.New("replay: 策略集为空")

	// ErrSeedMissing 回放输入缺 routing_seed（§2.8）。
	ErrSeedMissing = errors.New("replay: 路由记录缺 routing_seed，回放拒绝执行")

	// ErrRecordInvalid 记录结构不合法（缺字段、顺序未归一、字段互相矛盾）。
	ErrRecordInvalid = errors.New("replay: 回放记录不合法")

	// ErrSchemaVersion 记录文件的结构版本不受支持：宁可拒绝加载，
	// 也不要按猜测解析出一份「看起来一致」的报告。
	ErrSchemaVersion = errors.New("replay: 记录文件结构版本不受支持")

	// ErrForbiddenField 记录里出现了被禁字段词（正文/凭证类）。
	ErrForbiddenField = errors.New("replay: 记录含被禁字段")

	// ErrSamplerNil 注入了空的抽样器。
	ErrSamplerNil = errors.New("replay: 抽样器为空")
)

// WiringMode 是 §3.0 的接线阶段。它进记录，是因为差异报告必须能区分
// 「shadow 只观测不改流量」和「enforce 真的换了 provider」两种结论。
type WiringMode string

const (
	ModeShadow  WiringMode = "shadow"
	ModeEnforce WiringMode = "enforce"
	ModeLegacy  WiringMode = "legacy"
)

// Valid 报告接线阶段取值是否封闭。空串按 legacy 之外的显式约定处理：
// 记录里不允许留空，否则回放无法判断这条决策到底有没有影响线上流量。
func (m WiringMode) Valid() bool {
	switch m {
	case ModeShadow, ModeEnforce, ModeLegacy:
		return true
	}
	return false
}

// SamplingAlgoReplayV1 是本包默认抽样器的算法标识（replay-sampling-v1）。
// 记录显式带这个标识，replayer 才会逐位比对首选与尝试顺序；
// 其它标识（例如 D 包自己的算法名）只做解释性回放 —— 对齐 §2.8
// 「旧请求没有 seed 时只能做解释性回放，不能声称逐位相同」。
const SamplingAlgoReplayV1 = "replay-sampling-v1"

// nowUTC 把时间归一到 UTC 并截到秒。
//
// 策略 TTL、身份 TTL、计划 TTL 全都以秒为单位书写，亚秒只会让 JSON 出现
// RFC3339Nano 的小数尾巴，跨语言侧按 RFC3339 重算摘要时反而对不上（§5 要求序列化统一 RFC3339）。
func nowUTC(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.UTC().Truncate(time.Second)
}

// sameTime 比较两个时刻是否为同一点（含「都为空」）。零值和非零值必须判不等：
// 把「没有到期时间」当成「1970 年到期」会把长期授权误报成差异。
func sameTime(a, b time.Time) bool {
	if a.IsZero() || b.IsZero() {
		return a.IsZero() == b.IsZero()
	}
	return a.UTC().Truncate(time.Second).Equal(b.UTC().Truncate(time.Second))
}

// timePtr 把可选的时间字段转成指针。
//
// 用 *time.Time 而不是 time.Time + omitempty：encoding/json 的 omitempty 对结构体值
// 无效，零值时间会被写成 "0001-01-01T00:00:00Z"，跨语言侧读到它会把「没有期限」
// 误判成「早已到期」。留空就是字段缺席。
func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	v := nowUTC(t)
	return &v
}

func timeValue(p *time.Time) time.Time {
	if p == nil {
		return time.Time{}
	}
	return *p
}

func sameTimePtr(a, b *time.Time) bool { return sameTime(timeValue(a), timeValue(b)) }

func formatTimePtr(p *time.Time) string {
	if p == nil {
		return "<空>"
	}
	return formatTime(*p)
}

// reasonNames 是允许出现在 allow 结论上的原因码，供记录校验用。
var reasonNames = map[policy.Reason]bool{
	policy.ReasonExplicitAllow: true,
	policy.ReasonGroupAllow:    true,
	policy.ReasonDefaultAllow:  true,
}
