package knowledge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 响应体上限与协议默认值。
const (
	// DefaultMaxResponseBytes 是单次响应允许读取的字节上限（1 MiB）。
	// 手册 §5 要求「所有外部调用必须设置 body limit」：知识源被攻陷或返回错误页时，
	// 不限体积会直接把网关的内存吃穿。
	DefaultMaxResponseBytes int64 = 1 << 20
	// maxReadOverhead 是探测「是否超限」多读的那一个字节。
	maxReadOverhead = 1
	// contentTypeJSON 是要求对端返回的媒体类型。
	contentTypeJSON = "application/json"
)

// DoFunc 是被注入的 HTTP 执行函数。
//
// 为什么强制注入而不是内部自建 client：
// 网关的出网策略（代理、直连白名单、TLS 校验口径）在 transport 层，
// 本包如果偷偷 new 一个 http.Client 就绕过了整套出网控制（手册 §8 明令禁止快捷路径）。
// 没有注入时一律 fail_closed，而不是回落到 http.DefaultClient。
type DoFunc func(*http.Request) (*http.Response, error)

// HTTPRetriever 是委托协议的 HTTP 客户端实现（对接外部知识源 sidecar）。
//
// 它只做四件事：装配 JSON 请求、限时限体积读取、把状态码与失败翻译成稳定原因码、
// 校验响应协议。**不做任何权限判断**——权限在端点那一侧。
type HTTPRetriever struct {
	// Endpoint 是知识源的委托入口（必须是 http/https，禁止内嵌凭证）。
	Endpoint string
	// Do 是注入的执行函数；为 nil 时直接拒绝工作（见 Retrieve）。
	Do DoFunc
	// MaxResponseBytes 是响应体上限，≤0 时取 DefaultMaxResponseBytes。
	MaxResponseBytes int64
	// FallbackBudget 是当请求上下文没给出可用剩余预算时的兜底超时。
	// 为零取 DefaultBudget。
	FallbackBudget time.Duration
	// Name 是审计里的实现标识。
	Name string
}

var (
	// ErrEndpoint 表示委托端点配置不合法。
	ErrEndpoint = errors.New("knowledge: 检索委托端点不合法")
	// ErrNoTransport 表示没有注入 HTTP 执行函数。
	ErrNoTransport = errors.New("knowledge: 未注入 HTTP 执行函数（fail_closed）")
)

// NewHTTPRetriever 构造 HTTP 委托客户端。
//
// do 必须来自调用方（通常是 internal/dialer 造出的、受出网策略约束的 transport）：
// 传 nil 会在这里就报错，而不是等到第一次检索才发现「原来一直在用默认 transport 裸连」。
func NewHTTPRetriever(endpoint string, do DoFunc) (*HTTPRetriever, error) {
	clean, err := validateEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if do == nil {
		return nil, fmt.Errorf("%w: %v", ErrNoTransport, "NewHTTPRetriever 需要注入 Do 函数")
	}
	return &HTTPRetriever{
		Endpoint:         clean,
		Do:               do,
		MaxResponseBytes: DefaultMaxResponseBytes,
		FallbackBudget:   DefaultBudget,
		Name:             "http",
	}, nil
}

// TransportDo 把一个 http.RoundTripper 包成 DoFunc，并钉死超时。
//
// 用独立 http.Client 而不是复用调用方的：client 的 Timeout 是最后一道兜底，
// 上下文预算算错时（例如上游给了个超长 deadline）这里仍然会切断。
func TransportDo(transport http.RoundTripper, timeout time.Duration) DoFunc {
	if transport == nil {
		// 这里不返回 http.DefaultTransport 的实现，而是返回一个会立刻失败的 DoFunc：
		// 默认 transport 不受出网策略约束，用它就等于绕过 §8 禁止的快捷路径。
		// 少了这道判断，client.Transport 为 nil 时会被静默替换成 DefaultTransport，
		// 于是「注入了什么」和「实际走了哪条路」在审计上完全对不上。
		return func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("%w: 没有提供 RoundTripper，且本包禁止回落默认 transport", ErrNoTransport)
		}
	}
	if timeout <= 0 {
		timeout = DefaultBudget
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// 不跟随重定向：知识源端点由管理员配置，一旦允许 3xx 跳转，
		// 一个被改写的 DNS 或反向代理配置就能把请求引到出网白名单之外的主机，
		// 而审计里记录的还是原来那个端点。
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return client.Do
}

// RetrieverName 实现 NamedRetriever。
func (c *HTTPRetriever) RetrieverName() string {
	if c.Name == "" {
		return "http"
	}
	return c.Name
}

// Validate 校验配置（构造后可能被逐字段修改，接线启动时调用一次）。
func (c *HTTPRetriever) Validate() error {
	if _, err := validateEndpoint(c.Endpoint); err != nil {
		return err
	}
	if c.Do == nil {
		return fmt.Errorf("%w: Retrieve 不会自动创建 client", ErrNoTransport)
	}
	if c.MaxResponseBytes <= 0 {
		return fmt.Errorf("%w: 响应体上限必须为正，当前 %d", ErrEndpoint, c.MaxResponseBytes)
	}
	return nil
}

// Retrieve 实现 DelegatedRetriever。
//
// 错误一律收敛成 *RetrievalError（稳定原因码），消息里没有响应体、没有检索词原文：
// 失败信息会被打进日志，甚至回显给调用方，那里正是泄露最常发生的位置。
func (c *HTTPRetriever) Retrieve(ctx context.Context, req RetrieveRequest) (RetrieveResponse, error) {
	if err := c.Validate(); err != nil {
		return RetrieveResponse{}, err
	}
	if err := req.Validate(); err != nil {
		return RetrieveResponse{}, &RetrievalError{
			Reason: ReasonProtocolInvalid,
			KB:     append([]string(nil), req.KnowledgeBases...),
			Detail: "请求字段不符",
		}
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return RetrieveResponse{}, &RetrievalError{Reason: ReasonProtocolInvalid, Detail: "请求序列化失败"}
	}

	budget := c.budgetFor(req)
	if budget <= 0 {
		// 预算已经花完：不再出网，直接判不可读。
		return RetrieveResponse{}, &RetrievalError{
			Reason: ReasonTimeout,
			KB:     append([]string(nil), req.KnowledgeBases...),
			Detail: "剩余预算为零",
		}
	}
	callCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, c.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return RetrieveResponse{}, &RetrievalError{Reason: ReasonProtocolInvalid, Detail: "请求构造失败"}
	}
	httpReq.Header.Set("Content-Type", contentTypeJSON)
	httpReq.Header.Set("Accept", contentTypeJSON)
	// 只带请求 ID 做链路关联：它不含内容，也不含身份凭证。
	httpReq.Header.Set("X-Request-Id", req.RequestID)
	// 刻意不设 Authorization：凭证属于 transport 层（由注入方携带）。
	// 一旦在本结构里存 token，它就会顺着 JSON 进审计和错误信息（见协议文档 §6）。

	resp, err := c.Do(httpReq)
	if err != nil {
		return RetrieveResponse{}, c.classifyTransportError(err, req)
	}
	if resp == nil {
		return RetrieveResponse{}, &RetrievalError{Reason: ReasonUnavailable, Detail: "transport 返回空响应"}
	}
	defer drainAndClose(resp, c.MaxResponseBytes)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// 非 2xx 一律失败（fail_closed）。状态码可以进日志；响应体不行——
		// 知识源的 403 页面经常带文档标题甚至片段。
		return RetrieveResponse{}, &RetrievalError{
			Reason:     ReasonUpstreamStatus,
			StatusCode: resp.StatusCode,
			KB:         append([]string(nil), req.KnowledgeBases...),
			Detail:     "非 2xx 状态",
		}
	}

	mediaType, err := mimeMainType(resp)
	if err != nil {
		return RetrieveResponse{}, &RetrievalError{Reason: ReasonProtocolInvalid, Detail: "响应媒体类型头不合法"}
	}
	if mediaType != contentTypeJSON {
		return RetrieveResponse{}, &RetrievalError{
			Reason: ReasonProtocolInvalid,
			KB:     append([]string(nil), req.KnowledgeBases...),
			Detail: "响应不是 application/json（多半是中间代理返回了登录页或错误页）",
		}
	}

	limit := c.effectiveLimit()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+maxReadOverhead))
	if readErr != nil {
		return RetrieveResponse{}, c.classifyTransportError(readErr, req)
	}
	if int64(len(data)) > limit {
		return RetrieveResponse{}, &RetrievalError{
			Reason: ReasonResponseTooLarge,
			Detail: fmt.Sprintf("响应体超过上限 %d 字节", limit),
		}
	}

	var decoded RetrieveResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		// 不把 err 原文放进返回值：解码错误会带上下文字节，那正是响应内容。
		return RetrieveResponse{}, &RetrievalError{Reason: ReasonProtocolInvalid, Detail: "响应不是合法协议 JSON"}
	}
	// 只校验外壳（协议版本、串号、条数）。单篇形态问题留给 Filter 逐条丢弃并给出原因码，
	// 这样「对端返回了一条坏数据」不会把整次检索打成失败。
	if err := decoded.ValidateEnvelope(req); err != nil {
		return RetrieveResponse{}, &RetrievalError{
			Reason: ReasonProtocolInvalid,
			KB:     append([]string(nil), req.KnowledgeBases...),
			Detail: "响应外壳校验失败",
		}
	}
	return decoded, nil
}

// budgetFor 取「上下文剩余预算」与「兜底预算」的较小值。
//
// 为什么还要再夹一次：req.Deadline 是对端可读的字段，
// 一个被改坏（或故意拖时间）的 deadline 不应该让本地请求无限存活。
func (c *HTTPRetriever) budgetFor(req RetrieveRequest) time.Duration {
	fallback := c.FallbackBudget
	if fallback <= 0 {
		fallback = DefaultBudget
	}
	if fallback > MaxBudget {
		fallback = MaxBudget
	}
	if req.Deadline.IsZero() {
		return fallback
	}
	left := time.Until(req.Deadline)
	if left <= 0 {
		return 0
	}
	if left < fallback {
		return left
	}
	return fallback
}

func (c *HTTPRetriever) effectiveLimit() int64 {
	if c.MaxResponseBytes > 0 {
		return c.MaxResponseBytes
	}
	return DefaultMaxResponseBytes
}

// classifyTransportError 把底层错误映射成稳定原因码，且不带出错误原文。
//
// 底层错误只挂在 Cause 上：http 的报错会带 URL、端口甚至响应字节片段，
// 这些进了 Error() 就会顺着日志外流（见 delegation.go 的 RetrievalError）。
func (c *HTTPRetriever) classifyTransportError(err error, req RetrieveRequest) error {
	kbs := append([]string(nil), req.KnowledgeBases...)
	fail := func(reason Reason, detail string) error {
		return &RetrievalError{Reason: reason, KB: kbs, Detail: detail, Cause: err}
	}
	var timeoutErr interface{ Timeout() bool }
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fail(ReasonTimeout, "上下文超时")
	case errors.Is(err, context.Canceled):
		return fail(ReasonCancelled, "调用方取消")
	case errors.Is(err, ErrNoTransport):
		return fail(ReasonTransportNotConfigured, "未注入 transport")
	case errors.As(err, &timeoutErr) && timeoutErr.Timeout():
		return fail(ReasonTimeout, "传输层超时")
	}
	return fail(ReasonUnavailable, "传输层失败")
}

// mimeMainType 取响应的媒体类型主串。
//
// 只接受 application/json：对端返回 text/html 通常意味着中间有代理把请求重定向到了
// 登录页或错误页。这时候把 HTML 当协议解析会得到一堆误导性错误，
// 而「状态码 200 但不是协议」本身就是一个明确的协议不符信号。
func mimeMainType(resp *http.Response) (string, error) {
	raw := resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		// 错误消息里不回显 raw：头值由对端控制，会顺着 Detail 进审计。
		return "", errors.New("响应 Content-Type 不合法")
	}
	return strings.ToLower(mediaType), nil
}

// drainAndClose 释放响应体。
//
// 读取上限同样作用于关闭路径：错误响应体可能是无限流，
// 不限量读完再关会把「失败」变成「拖垮进程」。
func drainAndClose(resp *http.Response, limit int64) {
	if resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
	_ = resp.Body.Close()
}

// ValidateEndpoint 暴露 validateEndpoint 给配置加载与控制台写入使用。
//
// 为什么要出口而不是让调用方自己判 URL：端点的合法形态（禁凭证、禁 query、禁 fragment、
// 只允许 http/https）是委托协议的规则，配置层再抄一遍就会出现「配置认得而本包拒收」
// 或反过来 —— 而两处判据一旦分叉，写进审计的端点和真正会打的地址不是同一个。
func ValidateEndpoint(raw string) (string, error) { return validateEndpoint(raw) }

// validateEndpoint 校验并归一化委托端点。
//
// 拒绝内嵌凭证（https://user:pass@host）：凭证进了 URL 就会出现在日志、
// 错误信息和审计的端点字段里，而手册 §8 要求本包结构里根本不存凭证。
// 拒绝 fragment / query：入口 URL 由管理员配置，带上可变部分会让「同一个源」
// 在审计里显示成多个端点，也无法用固定规则做哈希比对。
func validateEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("%w: 不能为空", ErrEndpoint)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrEndpoint, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("%w: 只允许 http/https，当前 %q", ErrEndpoint, parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("%w: 缺少主机名", ErrEndpoint)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("%w: URL 里不能携带凭证，请由注入的 transport 承担认证", ErrEndpoint)
	}
	if parsed.Fragment != "" {
		return "", fmt.Errorf("%w: 不能带 fragment", ErrEndpoint)
	}
	if parsed.RawQuery != "" {
		return "", fmt.Errorf("%w: 不能带查询串（可变入口会让端点无法固定比对）", ErrEndpoint)
	}
	return strings.TrimRight(parsed.String(), "?"), nil
}

var _ DelegatedRetriever = (*HTTPRetriever)(nil)
var _ NamedRetriever = (*HTTPRetriever)(nil)
