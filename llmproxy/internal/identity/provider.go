package identity

import (
	"context"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// Provider 是一个外部身份来源。
//
// 契约（实现必须全部满足，否则接线方无法安全复用）：
//  1. 构造完成后配置不可变，实现必须可并发复用（手册 §6 要求跑 -race）；
//  2. Resolve 不产生副作用：不写库、不出网更新状态、不改调用方传入的凭证；
//  3. 失败必须返回可区分的错误，且 errors.Is 能认出本包的哨兵，ReasonFor(err) 给出原因码；
//  4. 成功返回的 Principal 一定通过 Principal.Validate()；
//  5. 绝不做模型权限判断 —— 需要判定请把 Principal 交给 policy.Resolver。
type Provider interface {
	// Name 是来源实例的稳定标识，进审计的 provider 字段。小写短横线形式。
	Name() string

	// Resolve 校验凭证并产出主体上下文。
	// ctx 只用于取外部依赖（例如公钥来源）；凭证走 Credential，不进 ctx。
	Resolve(ctx context.Context, cred Credential) (Principal, error)
}

// DefaultClockSkew 是允许的 IdP 与本机的时钟偏差。
//
// 完全不容偏差不可能对：校内 NTP 掉一次线，全员的 token 会在几分钟内集体「过期」；
// 偏差给太大则等于把 token 有效期拉长，被盗 token 的可用窗口跟着变长。
// 60 秒是这两头的折中，Config 可以按 IdP 的实测偏差覆盖。
const DefaultClockSkew = 60 * time.Second

// DefaultMaxValuesPerClaim 是单个 claim 展开成成员关系条目的上限。
//
// 上限必须有：某些 IdP 会把整个院系的组都塞进一个 token，一条 claim 上千项时
// 排序去重的开销和内存都会被放大 —— 而身份解析在每个请求的热路径上。
const DefaultMaxValuesPerClaim = 256

// settings 是各 Provider 共享的可选配置。
type settings struct {
	audit       AuditSink
	now         func() time.Time
	skew        time.Duration
	strictClock bool
}

func newSettings(opts []Option) settings {
	s := settings{audit: NopAudit{}, now: time.Now, skew: DefaultClockSkew}
	for _, opt := range opts {
		opt(&s)
	}
	if s.audit == nil {
		s.audit = NopAudit{}
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.strictClock {
		s.skew = 0
	}
	if s.skew < 0 {
		s.skew = 0
	}
	return s
}

// Option 调整 Provider 的可选行为。
type Option func(*settings)

// WithAudit 注入审计落点；nil 等价于 NopAudit。
func WithAudit(sink AuditSink) Option {
	return func(s *settings) { s.audit = sink }
}

// WithClock 注入时钟。测试用它把 TTL 边界钉成确定值；
// 生产留空即 time.Now —— 不吃真实时间才能做到手册 §6 的「固定输入固定输出」。
func WithClock(now func() time.Time) Option {
	return func(s *settings) {
		if now != nil {
			s.now = now
		}
	}
}

// WithClockSkew 设置允许的时钟偏移。
func WithClockSkew(d time.Duration) Option {
	return func(s *settings) { s.skew = d }
}

// WithStrictClock 关闭时钟偏移容忍（skew 强制为 0）。
//
// 用一个显式开关而不是「传 0 表示不允许偏移」：0 值同时是「未设置」，
// 靠 0 表达严格语义会让所有没写这个字段的配置悄悄变成最严格模式。
func WithStrictClock() Option {
	return func(s *settings) { s.strictClock = true }
}

// nowTime 返回当前判定时刻。
func (s settings) nowTime() time.Time { return s.now() }

// record 发审计事件。
//
// 实现方 panic 不能拖垮身份解析：留痕失败是运维问题，把正常登录打断才是事故。
// 落库/转发由 sink 自己负责，本包不碰数据库也不出网。
func (s settings) record(event AuditEvent) {
	defer func() { _ = recover() }()
	if s.audit == nil {
		return
	}
	s.audit.Record(event)
}

// identitySource 给出 Identity.Source 的最终值：配置名缺失时回落到 provider 名。
func identitySource(source, providerName string) string {
	if source != "" {
		return source
	}
	return providerName
}

// scopeRefOf 构造范围引用（不 panic 的版本，专门用于外部输入）。
func scopeRefOf(kind policy.ScopeKind, id string) (policy.ScopeRef, error) {
	ref, err := policy.NewScopeRef(kind, id)
	if err != nil {
		return policy.ScopeRef{}, err
	}
	return ref, nil
}
