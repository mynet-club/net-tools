package processor

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Reason 是处理器运行时的稳定原因码。
//
// 为什么不复用 policy.Reason：A 包的注册表表达的是「一次授权判定为什么是这个结论」，
// 而这里要表达的是「一次数据变换为什么失败、被跳过、被限制」——超时、输入超限、
// sidecar 拒收这些属于实现层事实。往 A 的注册表里塞处理器细节有两个后果：
// A 的契约已经被主线冻结（不得修改），且 RoutingPlan.Validate 对未注册的码直接失败。
// 所以 E 自带一张封闭表，只增不改、不重命名；语义能与 A 对齐的两条
// （raw_body_grant_missing、retry_exhausted）刻意保持同名同值，接线时可以合并成一个字段。
//
// 原文授权判定的**策略侧**原因码仍然是 policy.Reason，单独放在
// AuditEntry.GrantReason 里透传，不与本表混用 —— 否则审计里分不清
// 「管理员没授权」和「sidecar 超时」。
type Reason string

const (
	// 正常方向。
	ReasonOK Reason = "ok"

	// 装配与配置（构造期就失败，不会等到请求期）。
	ReasonNotRegistered   Reason = "processor_not_registered"
	ReasonVersionReject   Reason = "processor_version_mismatch"
	ReasonConfigInvalid   Reason = "processor_config_invalid"
	ReasonPhaseDenied     Reason = "processor_phase_not_allowed"
	ReasonSchemaUnsupport Reason = "schema_keyword_unsupported"

	// 正文访问与资源限制（§2.9）。
	ReasonBodyAccessDenied  Reason = "body_access_denied"
	ReasonBodyReplaceDenied Reason = "body_replace_denied"
	ReasonInputTooLarge     Reason = "input_too_large"
	ReasonOutputTooLarge    Reason = "output_too_large"
	ReasonStreamUnsupported Reason = "stream_unsupported"
	ReasonNoInput           Reason = "no_input"

	// 外部依赖（sidecar）。
	ReasonTimeout           Reason = "processor_timeout"
	ReasonFailed            Reason = "processor_failed"
	ReasonEndpointDenied    Reason = "endpoint_not_allowed"
	ReasonGrantMissing      Reason = "raw_body_grant_missing"
	ReasonGrantCheckerBlank Reason = "grant_checker_missing"
	ReasonRetryExhausted    Reason = "retry_exhausted"
	ReasonSidecarReject     Reason = "sidecar_reject"

	// 判定结论（处理器本职工作的产出，不是故障）。
	ReasonSchemaViolation Reason = "schema_violation"
	ReasonInvalidInput    Reason = "invalid_input"
	ReasonContentBlocked  Reason = "content_blocked"
	ReasonLimitExceeded   Reason = "limit_exceeded"

	// fail_open 跳过留痕：正文保持不变，但审计必须能看到「这次没处理」。
	ReasonFailOpenSkipped Reason = "fail_open_skipped"
)

var allReasons = map[Reason]bool{}

func init() {
	for _, r := range []Reason{
		ReasonOK,
		ReasonNotRegistered, ReasonVersionReject, ReasonConfigInvalid, ReasonPhaseDenied, ReasonSchemaUnsupport,
		ReasonBodyAccessDenied, ReasonBodyReplaceDenied, ReasonInputTooLarge, ReasonOutputTooLarge,
		ReasonStreamUnsupported, ReasonNoInput,
		ReasonTimeout, ReasonFailed, ReasonEndpointDenied, ReasonGrantMissing,
		ReasonGrantCheckerBlank, ReasonRetryExhausted, ReasonSidecarReject,
		ReasonSchemaViolation, ReasonInvalidInput, ReasonContentBlocked, ReasonLimitExceeded,
		ReasonFailOpenSkipped,
	} {
		allReasons[r] = true
	}
}

// Valid 报告原因码是否在注册表内。测试用它挡住自然语言或拼错的值。
func (r Reason) Valid() bool { return allReasons[r] }

func (r Reason) String() string { return string(r) }

// Reasons 去重排序，保证同一次处理的原因链与 map 遍历顺序无关。
func Reasons(in []Reason) []Reason {
	if len(in) == 0 {
		return nil
	}
	set := make(map[Reason]bool, len(in))
	out := make([]Reason, 0, len(in))
	for _, r := range in {
		if r == "" || !r.Valid() {
			// 未注册的码宁可丢掉也不要落进审计：它会随日志扩散成不可聚合的脏值。
			continue
		}
		if !set[r] {
			set[r] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	if len(out) == 0 {
		return nil
	}
	return out
}

// failureClass 是一次处理器失败的归类，决定 FailClosed 能不能把它跳过。
type failureClass int

const (
	// classInfrastructure 是外部依赖故障（超时、网络、5xx）。
	// 只有这一类允许按 fail_open 跳过：增强处理挂了，不该让整次请求失败。
	classInfrastructure failureClass = iota

	// classViolation 是资源/权限越界（档位不足、超大小、目标不在白名单、原文未授权）。
	// 这类**无视 FailClosed**：把它跳过等于给「跳过检查」开后门，
	// 而 §2.9 要的恰恰是这两道门槛不可协商。
	classViolation

	// classVerdict 是处理器本职判定成立（schema 不符、命中违禁词、正文不是合法 JSON）。
	// 判定成立就是结论，不是故障，同样不允许 fail_open 把它冲掉。
	classVerdict
)

func (c failureClass) String() string {
	switch c {
	case classInfrastructure:
		return "infrastructure"
	case classViolation:
		return "violation"
	case classVerdict:
		return "verdict"
	}
	return "unknown"
}

var (
	ErrSpec              = errors.New("processor: 处理器声明不合法")
	ErrPhase             = errors.New("processor: 未知的处理阶段")
	ErrRegistry          = errors.New("processor: 注册表装配失败")
	ErrBodyAccessDenied  = errors.New("processor: 当前档位禁止读取正文")
	ErrBodyReplaceDenied = errors.New("processor: 当前档位禁止替换正文")
	ErrInputTooLarge     = errors.New("processor: 输入超过大小上限")
	ErrOutputTooLarge    = errors.New("processor: 输出超过大小上限")
	ErrLineTooLarge      = errors.New("processor: 单行超过流式缓冲上限")
	ErrDepthTooDeep      = errors.New("processor: 路径深度超过上限")
	ErrTooManyRules      = errors.New("processor: 规则表规模超过上限")
	ErrTimeout           = errors.New("processor: 处理器超时")
	ErrConfigInvalid     = errors.New("processor: 处理器配置不合法")
	ErrSchemaUnsupported = errors.New("processor: JSON Schema 关键字不在受限子集内")
	ErrSchemaViolation   = errors.New("processor: 实例不符合 schema")
	ErrInvalidJSON       = errors.New("processor: 正文不是合法 JSON")
	ErrNoBody            = errors.New("processor: 本次调用没有正文输入")
	ErrEndpointDenied    = errors.New("processor: 出网目标不在白名单内")
	ErrGrantCheckerBlank = errors.New("processor: 缺少原文授权判定器，无法校验 allow_raw_body")
	ErrRawBodyDenied     = errors.New("processor: 原文出网未获管理员授权")
	ErrStreamUnsupported = errors.New("processor: 该处理器不支持流式增量处理")
	ErrSidecarFailed     = errors.New("processor: sidecar 调用失败")
	ErrSidecarReject     = errors.New("processor: sidecar 判定拒绝")
	ErrRetryExhausted    = errors.New("processor: sidecar 重试次数已用尽")
	ErrContentBlocked    = errors.New("processor: 响应命中拦截规则")
	ErrProcessFailed     = errors.New("processor: 处理器返回失败")
)

// classify 把错误映射成（原因码，归类）。顺序即优先级：越具体的哨兵排得越前，
// 因为包装链上多个哨兵可能同时命中（sidecar 超时同时带 ErrSidecarFailed 与 ErrTimeout）。
func classify(err error) (Reason, failureClass) {
	switch {
	case err == nil:
		return ReasonOK, classInfrastructure
	case errors.Is(err, ErrTimeout):
		return ReasonTimeout, classInfrastructure
	case errors.Is(err, ErrBodyAccessDenied):
		return ReasonBodyAccessDenied, classViolation
	case errors.Is(err, ErrBodyReplaceDenied):
		return ReasonBodyReplaceDenied, classViolation
	case errors.Is(err, ErrInputTooLarge), errors.Is(err, ErrLineTooLarge):
		return ReasonInputTooLarge, classViolation
	case errors.Is(err, ErrOutputTooLarge):
		return ReasonOutputTooLarge, classViolation
	case errors.Is(err, ErrDepthTooDeep), errors.Is(err, ErrTooManyRules):
		return ReasonLimitExceeded, classViolation
	case errors.Is(err, ErrEndpointDenied):
		return ReasonEndpointDenied, classViolation
	case errors.Is(err, ErrGrantCheckerBlank):
		return ReasonGrantCheckerBlank, classViolation
	case errors.Is(err, ErrRawBodyDenied):
		return ReasonGrantMissing, classViolation
	case errors.Is(err, ErrConfigInvalid), errors.Is(err, ErrSchemaUnsupported):
		return ReasonConfigInvalid, classViolation
	case errors.Is(err, ErrStreamUnsupported):
		// 跳过 = 把没过滤的响应原样放给客户端，方向错误，所以按违规处理。
		return ReasonStreamUnsupported, classViolation
	case errors.Is(err, ErrSchemaViolation):
		return ReasonSchemaViolation, classVerdict
	case errors.Is(err, ErrContentBlocked):
		return ReasonContentBlocked, classVerdict
	case errors.Is(err, ErrInvalidJSON):
		return ReasonInvalidInput, classVerdict
	case errors.Is(err, ErrSidecarReject):
		return ReasonSidecarReject, classVerdict
	case errors.Is(err, ErrNoBody):
		return ReasonNoInput, classViolation
	case errors.Is(err, ErrRetryExhausted), errors.Is(err, ErrSidecarFailed), errors.Is(err, ErrProcessFailed):
		return ReasonFailed, classInfrastructure
	}
	return ReasonFailed, classInfrastructure
}

// Errorf 是包内统一的错误构造器，保证原因码与 errors.Is 哨兵成对出现。
func Errorf(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", sentinel, fmt.Sprintf(format, args...))
}

// safeIdentifier 校验要写进日志/审计的短标识符（处理器名、类型、版本、改写类别）。
//
// 不放任任意字符串进审计：一条含换行或原文的「名字」就能把 §2.9 规则 6 的
// 「只允许类型、范围、哈希」变成日志注入的口子。
func safeIdentifier(name string) bool {
	if name == "" || len(name) > MaxNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == ':' || c == '/':
		default:
			return false
		}
	}
	return true
}

// sanitizeShortCode 清理 sidecar 回传的短码：只保留安全字符并截断长度。
// 返回空串表示这个值不该进审计。
func sanitizeShortCode(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 48 {
		s = s[:48]
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			b.WriteByte(c)
		}
	}
	return b.String()
}
