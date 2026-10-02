package executor

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strings"
)

// 哨兵 error：调用方用 errors.Is 判大类，用 errors.As 取 *ExecutionError 拿稳定码。
// 每个哨兵都在 reasons.go 里有对偶的 ReasonCode —— 哨兵面向代码分支，
// 码面向审计聚合，缺一个都会逼调用方去匹配错误文本（那是最脆的契约）。
var (
	// ErrTimeout 表示交换超时（Attempt.Timeout 或注入的 transport 期限先到）。
	ErrTimeout = errors.New("executor: 上游调用超时")

	// ErrCallerCanceled 表示调用方上下文取消（客户端断开等）。
	ErrCallerCanceled = errors.New("executor: 调用方取消")

	// ErrConnect 表示连接层失败（DNS/TCP/TLS/代理握手）。
	ErrConnect = errors.New("executor: 连接失败")

	// ErrEgressDenied 表示出网校验拒绝了最终拨号目标。
	ErrEgressDenied = errors.New("executor: 出网目标被校验拒绝")

	// ErrBodyLimit 表示响应体读取越过体积上限，流已截断。
	ErrBodyLimit = errors.New("executor: 响应体超过上限")
)

// ExecutionError 是本包对外的统一错误形状。
//
// 为什么 Error() 不包含 Cause 的文本：底层错误会带完整 URL（含端口、路径，
// 某些包装还会带响应字节片段），而这些一旦被拼进 Error() 就会顺着日志与
// 下游错误响应外流。凭证类信息（Authorization 头）不会进 URL，但
// 「网关在打哪个内网地址」本身就是不该给终端用户看的信息。
// Cause 只通过 Unwrap 链暴露给 errors.Is/As —— 分支判定不需要文本。
type ExecutionError struct {
	// Code 是稳定失败码（reasons.go 封闭集合内的值）。
	Code ReasonCode
	// Provider 是稳定供应商标识 (log-ok)，可为空（尚未定靶就失败时）。
	Provider string
	// Detail 是**人工撰写**的补充说明。禁止把正文、密钥、URL、响应片段拼进来；
	// 由本包生成的 Detail 全部来自固定文案表。
	Detail string
	// Cause 是底层错误，仅供 errors.Is/As，不参与 Error() 文本。
	Cause error
}

func (e *ExecutionError) Error() string {
	if e == nil {
		return "<nil>"
	}
	var b strings.Builder
	b.WriteString("executor[")
	b.WriteString(e.Code.String())
	b.WriteString("]")
	if e.Provider != "" {
		b.WriteString(" provider=")
		b.WriteString(sanitizeIdent(e.Provider))
	}
	if e.Detail != "" {
		b.WriteString(" ")
		b.WriteString(e.Detail)
	}
	return b.String()
}

// Unwrap 返回**哨兵**而不是原始 Cause：哨兵由 Code 反推，保证
// errors.Is(err, ErrTimeout) 这类判定只依赖本包的稳定词汇，
// 不依赖 net/url 的内部措辞（Go 版本一升级措辞就可能变）。
// 原始 Cause 挂在 sentinel 链外一层，需要时可用 interface{ Unwrap() error } 自取。
func (e *ExecutionError) Unwrap() error {
	s := sentinelForCode(e.Code)
	if s == nil || e.Cause == nil {
		return s
	}
	return &causeChain{sentinel: s, cause: e.Cause}
}

// causeChain 把「本包哨兵」与「原始底层错误」串成一条 Unwrap 链。
type causeChain struct {
	sentinel error
	cause    error
}

func (c *causeChain) Error() string { return c.sentinel.Error() }
func (c *causeChain) Unwrap() error { return c.cause }

func sentinelForCode(code ReasonCode) error {
	switch code {
	case ReasonTimeout:
		return ErrTimeout
	case ReasonCallerCanceled:
		return ErrCallerCanceled
	case ReasonConnectFailed:
		return ErrConnect
	case ReasonEgressDenied:
		return ErrEgressDenied
	case ReasonBodyTooLarge:
		return ErrBodyLimit
	case ReasonAttemptInvalid:
		return ErrAttempt
	case ReasonTargetRejected:
		return ErrTarget
	case ReasonNotConfigured:
		return ErrNotConfigured
	case ReasonRequestShapeInvalid:
		return ErrRequestShape
	}
	return nil
}

// 与哨兵对偶的补充错误变量（reasons.go 的码在这里有实现）。
var (
	// ErrNotConfigured 表示执行器缺工作前提。
	ErrNotConfigured = errors.New("executor: 执行器未正确配置")
	// ErrRequestShape 表示请求/响应协议形态不符。
	ErrRequestShape = errors.New("executor: 协议形态不符")
)

// newError 构造一个执行错误。detail 必须是固定文案（构造点自律，没有运行时兜底）。
func newError(code ReasonCode, provider, detail string, cause error) *ExecutionError {
	return &ExecutionError{Code: code, Provider: provider, Detail: detail, Cause: cause}
}

// Classify 把任意底层错误折算成稳定失败码，构造统一错误。
//
// 判定顺序是刻意的：先 context（取消与超时必须精确分开，现网 forwarder 为此
// 专门写了 wd.Fired() 分支，见 forwarder.go :360-382），再出网拒绝（它的文本
// 里带 IP，绝不能进对外 Error()），再 timeout/net.Error/TLS/URL。
// 最后才是 connect_failed 的兜底 —— 「不知道是什么网络错」按可重试的网络故障
// 归类，与现网 ReportFailureFor 的口径一致。
func Classify(err error, provider string) *ExecutionError {
	if err == nil {
		return nil
	}
	// 已经分类过就不再二次包装（幂等：调用方可能拿到执行器错误再加工重试预算）。
	var already *ExecutionError
	if errors.As(err, &already) {
		return already
	}
	fail := func(code ReasonCode, detail string) *ExecutionError {
		return newError(code, provider, detail, err)
	}

	switch {
	case errors.Is(err, context.Canceled):
		return fail(ReasonCallerCanceled, "调用方上下文已取消")
	case errors.Is(err, context.DeadlineExceeded):
		return fail(ReasonTimeout, "到达 Attempt.Timeout")
	}

	text := err.Error()
	// dialer 的出网拒绝文本固定以「拒绝拨号到 / 拒绝连接」开头（egress.go :41, :65, :74）。
	// 用前缀而非包含匹配：错误链拼接后真目标地址会出现在任意位置，包含匹配
	// 会把带这些字样的网络报错文本误升级成出网拒绝。
	if strings.HasPrefix(text, "拒绝拨号到") || strings.HasPrefix(text, "拒绝连接") ||
		errors.Is(err, ErrEgressDenied) {
		return fail(ReasonEgressDenied, "出网校验拒绝了拨号目标")
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fail(ReasonTimeout, "传输层超时")
	}
	// http.Client 超时报 "Client.Timeout exceeded ..."，url.Error 包裹一切。
	if strings.Contains(text, "Client.Timeout") {
		return fail(ReasonTimeout, "HTTP 客户端超时")
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		// URL 错误里挑内层继续判：拒绝/超时/TLS 都可能在里面。
		if urlErr.Err != nil {
			if k := Classify(urlErr.Err, provider); k != nil && k.Code != ReasonConnectFailed {
				k.Cause = err
				return k
			}
		}
		return fail(ReasonConnectFailed, "请求发送失败")
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return fail(ReasonConnectFailed, "TLS 证书校验失败")
	}
	if _, ok := err.(net.Error); ok { // 非超时的网络错误（拒绝连接、不可达…）
		return fail(ReasonConnectFailed, "连接层失败")
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return fail(ReasonConnectFailed, "连接层失败")
	}
	return fail(ReasonConnectFailed, "未分类的传输失败")
}

// sanitizeIdent 清洗会进错误文本的标识符：掐掉可能被塞进 Provider 等字段的
// 空白与控制符（换行会被用来在日志里伪造下一条记录）。
// 不做白名单：Provider 值域由配置层校验，这里只保证错误文本单行、不可注入。
func sanitizeIdent(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}
