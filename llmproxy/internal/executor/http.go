package executor

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	stdpath "path"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/dialer"
)

// HTTPExecutor 是按在线协议形态（Protocol）驱动的上游执行器。
//
// 一个实例绑定一套「怎么出去」的配置（代理、出网校验、UA、默认协议），
// 服务任意多个目标 Attempt —— 目标本身（base URL / 密钥 / 超时 / 体积上限）
// 全部来自 Attempt，这正是 F 包与现网 forwarder 的关键差别：现网的传输
// 配置和供应商候选搅在同一个选路循环里，本地后端想复用这条链路就得整段复制。
//
// 远程 OpenAI 兼容上游、vLLM（同为 OpenAI 兼容）、Ollama（原生协议，
// 挂一个 shape 适配器，见 local.go）都由本类型承载。
type HTTPExecutor struct {
	name         string
	protocol     Protocol
	capabilities []string
	userAgent    string
	transport    http.RoundTripper
	// proxyURL 是构造期固化的出口代理（探活比对用；空 = 直连）。
	proxyURL string
	// adapt 是请求形态适配器（Ollama 原生方言用），可为 nil（OpenAI 兼容形态原样发）。
	// 入参是已定稿的 OpenAI 形态正文，返回**实际发送的路径与正文**：原生协议
	// 连入口路径都不同，只给正文不给路径就还得让调用方知道方言的路径名，适配器就漏了。
	adapt func(a *Attempt, openaiBody []byte) (path string, body []byte, err error)
}

// Options 构造 HTTPExecutor 的「怎么出去」部分。
type Options struct {
	// Name 是这张通道表里的稳定名（对应 policy.RouteCandidate.Executor）：生产侧由
	// server 的 executorRuntime 按（名字 × 归属 × 代理）持有实例，本包不再有注册表。
	Name string
	// Protocol 是该执行器的默认协议；Attempt.Protocol 非空时逐次覆盖。
	Protocol Protocol
	// Capabilities 声明能力名（取值同 routing.Capability*），填进 Offer 供 D 匹配。
	Capabilities []string
	// UserAgent 为空时用 DefaultUserAgent。
	UserAgent string

	// Transport 非空时直接使用（接线方共享连接池 / 测试注入用）。
	// 为空时由 ProxyURL + EgressCheck 经 internal/dialer 构造。
	Transport http.RoundTripper
	// ProxyURL 是本执行器固定使用的代理（空 = 直连）。
	ProxyURL string
	// EgressCheck 是出网校验（nil = 不校验，运营者自管路径）。
	EgressCheck dialer.IPCheck
	// AdaptRequest 是请求形态适配器（接收定稿 OpenAI 正文，返回方言路径与正文）；
	// 一般只有 local.go 的构造函数会设置。
	AdaptRequest func(a *Attempt, openaiBody []byte) (path string, body []byte, err error)
}

// DefaultUserAgent 是本包的默认 UA。不带 config.Version：执行器与配置版本
// 解耦（版本进不进 UA 是接线口径，不该固化进传输层）。
const DefaultUserAgent = "llmproxy-executor/3.0"

// NewHTTPExecutor 构造执行器。transport 构造失败（代理 URL 非法等）在这里
// 就报错而不是拖到第一次执行 —— 配置错误要在线启动时暴露。
//
// 禁止的行为：不给 transport 也不给 dialer 参数时**不会**回落到
// http.DefaultTransport（不受出网策略约束的默认通道是 §8 点名的快捷路径），
// 而是显式构造一个走 dialer.NewChecked 的直连 transport，环境代理被钉死为关闭。
func NewHTTPExecutor(opts Options) (*HTTPExecutor, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, fmt.Errorf("%w: 执行器缺少 Name", ErrNotConfigured)
	}
	proto := opts.Protocol
	if proto == "" {
		proto = ProtocolOpenAIChat
	}
	if !proto.valid() {
		return nil, fmt.Errorf("%w: 未知协议 %q", ErrNotConfigured, string(proto))
	}
	tr := opts.Transport
	if tr == nil {
		built, err := newTransport(opts.ProxyURL, opts.EgressCheck)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotConfigured, err)
		}
		tr = built
	}
	caps := opts.Capabilities
	if caps == nil {
		caps = []string{CapabilityStreaming}
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}
	return &HTTPExecutor{
		name:         opts.Name,
		protocol:     proto,
		capabilities: append([]string(nil), caps...),
		userAgent:    ua,
		transport:    tr,
		proxyURL:     opts.ProxyURL,
		adapt:        opts.AdaptRequest,
	}, nil
}

// Name 实现 Executor。
func (e *HTTPExecutor) Name() string { return e.name }

// Capabilities 实现 Executor。返回副本：调用方改不动执行器的能力声明。
func (e *HTTPExecutor) Capabilities() []string {
	return append([]string(nil), e.capabilities...)
}

// Protocol 回报默认协议（管理台展示与回放断言用）。
func (e *HTTPExecutor) Protocol() Protocol { return e.protocol }

// Execute 实现 Executor。一次调用 = 一次交换：不重试、不换家、不记费。
//
// 错误分界（doc.go）：
//   - error 非 nil：交换没有完整发生（目标被拒 / 连不上 / 超时 / 请求形态非法），
//     返回的 Outcome 为零值；
//   - error 为 nil：拿到了响应头。上游 4xx/5xx 走 Outcome.Failure 码回报，
//     状态码与错误体原样透传 —— 「上游说不行」是这次交换的事实，不是执行器的故障。
func (e *HTTPExecutor) Execute(ctx context.Context, a Attempt) (Outcome, error) {
	if err := a.Validate(); err != nil {
		return Outcome{}, newError(ReasonAttemptInvalid, a.Provider, "执行入参未通过校验", err)
	}

	proto := a.Protocol
	if proto == "" {
		proto = e.protocol
	}
	path, body, err := e.prepareRequest(proto, &a)
	if err != nil {
		// prepareRequest 的失败都是 Attempt 数据与声明的协议形态对不上，
		// 错误里只有形态说明，没有正文。
		return Outcome{}, err
	}
	// URL 拼装放在正文定稿之后：适配器可能换入口路径（Ollama 原生），
	// 目标约束必须校验**真正发出去**的那个路径，而不是校验完再被换掉。
	fullURL, err := buildURL(a.BaseURL, path)
	if err != nil {
		return Outcome{}, newError(ReasonTargetRejected, a.Provider, "目标未通过安全约束", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, a.Timeout)
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, fullURL, bytes.NewReader(body))
	if err != nil {
		cancel()
		return Outcome{}, newError(ReasonTargetRejected, a.Provider, "请求构造失败", err)
	}
	e.setHeaders(req, a, body)

	client := &http.Client{
		Transport: e.transport,
		// 绝不跟随重定向：3xx 会把请求引到出网约束之外的主机，而审计记录的还是
		// 原目标（口径同 knowledge.TransportDo :103-107 的理由）。
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		// 注意 cancel 的时机（现网 forwarder :356-359 的原话）：context 控制
		// 整个请求-响应生命周期，过早 cancel 会让后续读 body 失败。
		// 失败路径没有 body 可读，立刻取消；成功路径把 cancel 挂到 Body.Close 上。
		cancel()
		// ctx 是调用方的：调用方先到期/断开时报 caller_canceled 而不是 timeout ——
		// 这不是上游的错，也不该换一家重试（forwarder.go :364-379 的原始理由）。
		if ctx.Err() != nil {
			return Outcome{}, newError(ReasonCallerCanceled, a.Provider, "调用方在响应前取消", ctx.Err())
		}
		return Outcome{}, Classify(err, a.Provider)
	}

	out := Outcome{
		StatusCode:    resp.StatusCode,
		Headers:       filterHopByHop(resp.Header),
		IsStream:      a.IsStream,
		Failure:       reasonForStatus(resp.StatusCode),
		ContentLength: resp.ContentLength,
		obs:           newObserver(modeFor(proto, a.IsStream)),
	}
	out.Body = &cancelOnClose{
		rc:     newScanReader(resp.Body, out.obs, a.MaxResponseBytes),
		cancel: cancel,
	}
	return out, nil
}

// prepareRequest 按 Attempt 的显式声明定稿「发什么、发到哪个路径」：
// 上游模型名改写、usage 注入、协议适配器翻译。顺序是刻意的：
// 先在这份 OpenAI 形态的正文上做字段级改写（model / stream_options 的语义
// 是 OpenAI 的），最后一步才由适配器翻译成方言形态 —— 适配器拿到的永远是
// 「已定稿的 OpenAI 形态」，它只负责形变，不再改语义。
func (e *HTTPExecutor) prepareRequest(proto Protocol, a *Attempt) (string, []byte, error) {
	body := a.Body
	if len(body) == 0 {
		return "", nil, newError(ReasonRequestShapeInvalid, a.Provider, "请求体为空", nil)
	}
	fail := func(cause error) (string, []byte, error) {
		return "", nil, newError(ReasonRequestShapeInvalid, a.Provider, "请求体不满足协议形态要求", cause)
	}
	if a.UpstreamModel != "" {
		rewritten, err := rewriteModelInBody(body, a.UpstreamModel)
		if err != nil {
			return fail(err)
		}
		body = rewritten
	}
	if a.WantUsage {
		if !a.IsStream {
			// include_usage 只对流式有意义；调用方声明矛盾时显式报错，
			// 静默忽略会让「usage 为什么没回来」查两天。
			return fail(fmt.Errorf("WantUsage 需要同时声明 IsStream"))
		}
		if proto != ProtocolOpenAIChat {
			// Ollama 原生协议没有 stream_options：用量在收尾行里自带，
			// 注入无处落笔。调用方声明了不属于这个方言的开关，同样显式报错。
			return fail(fmt.Errorf("WantUsage 仅适用于 OpenAI 兼容协议"))
		}
		rewritten, err := injectIncludeUsage(body)
		if err != nil {
			return fail(err)
		}
		body = rewritten
	}
	path := a.Path
	if e.adapt != nil {
		// 适配器接收**已定稿的 OpenAI 形态正文**，返回方言形态的路径与正文；
		// 两份切片都只在发请求的一瞬存在，不落任何导出结构（doc.go 正文访问契约）。
		adaptedPath, adapted, err := e.adapt(a, body)
		if err != nil {
			return fail(err)
		}
		if len(adapted) == 0 {
			return fail(fmt.Errorf("请求形态适配器未产出正文"))
		}
		body = adapted
		if adaptedPath != "" {
			path = adaptedPath
		}
	}
	return path, body, nil
}

// setHeaders 组装请求头。口径逐条对应现网 forwarder :340-353：
// Content-Type / Authorization / UA 固定设置，Accept 透传下游，
// 附加头绝不覆盖 Authorization 与 Host，刻意不转发下游的
// Authorization / Cookie / X-Api-Key（那会把手持的凭证面扩大到用户可控输入）。
func (e *HTTPExecutor) setHeaders(req *http.Request, a Attempt, body []byte) {
	req.Header.Set("Content-Type", "application/json")
	if a.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.APIKey)
	}
	req.Header.Set("User-Agent", e.userAgent)
	req.ContentLength = int64(len(body))
	if a.Accept != "" {
		req.Header.Set("Accept", a.Accept)
	}
	for k, v := range a.Headers {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "host" || isHopByHop(k) {
			continue // 绝不让附加头覆盖鉴权、Host 或逐跳语义
		}
		req.Header.Set(k, v)
	}
}

// cancelOnClose 把 context 的 cancel 挂到 Body 上。
// 流没关，请求生命周期就没完——提前 cancel 等于掐自己的 body。
type cancelOnClose struct {
	rc     *scanReader
	cancel context.CancelFunc
}

func (c *cancelOnClose) Read(p []byte) (int, error) { return c.rc.Read(p) }

func (c *cancelOnClose) Close() error {
	err := c.rc.Close()
	c.cancel()
	return err
}

// 下游通常把 Body 直接 io.Copy 到 flushWriter：Read 到一块 flush 一块，
// 包装层不需要额外实现 Flusher（Flush 的是 ResponseWriter 而不是响应体）。
var _ io.ReadCloser = (*cancelOnClose)(nil)

// ------------------------------------------------------------------ 探活

// ProbeTarget 是一次健康检查的目标（§3.F 交付项之一）。
//
// 为什么探活单独一个窄结构而不是复用 Attempt：探活没有正文、没有模型语义，
// 塞一个空 Body 的 Attempt 会让「Attempt 一定有正文」这条不变量在下游失效。
type ProbeTarget struct {
	// Provider 是稳定标识 (log-ok)。
	Provider string
	// BaseURL / APIKey / ProxyURL / Headers 语义同 Attempt 同名字段。
	BaseURL string
	APIKey  string
	// Timeout 必填为正（§5）。现网探针固定 5s（probe.go :81），这里交给调用方。
	Timeout time.Duration
	// MaxResponseBytes 探活响应上限：/models 清单可能很大，探活只关心状态码。
	MaxResponseBytes int64
	// ProxyURL 与 EgressCheck 同 Attempt；nil 时沿用执行器实例的构造期配置。
	ProxyURL    string
	EgressCheck dialer.IPCheck
}

// ProbeResult 是探活结论。执行器只回报事实，熔断计数/冷却推进归调用方
// （现网是 router.ReportFailureFor 的职责，未来是接线层）。
type ProbeResult struct {
	// Healthy：拿到 <500 的状态码即算活着。
	// 401/403/404 也算 —— 服务在应答，只是探针姿势不对（probe.go :100-102 的
	// 现网口径原样保留：把它们判死会让密钥轮换瞬间全线冷却）。
	Healthy bool
	// StatusCode 为 0 表示请求没打完（网络/超时/被拒），细节在 Err。
	StatusCode int
	// Err 是分类后的失败（复用 Classify 的封闭码体系），可为 nil。
	Err *ExecutionError
}

// Probe 打一次 GET <base>/models。不重试、不改配置、不记熔断 —— 只回报。
func (e *HTTPExecutor) Probe(ctx context.Context, t ProbeTarget) ProbeResult {
	if t.Timeout <= 0 {
		return ProbeResult{Err: newError(ReasonAttemptInvalid, t.Provider, "探活必须显式给超时", nil)}
	}
	limit := t.MaxResponseBytes
	if limit <= 0 {
		limit = defaultProbeLimit
	}
	proxy := t.ProxyURL
	check := t.EgressCheck
	fullURL, err := buildURL(t.BaseURL, probePath)
	if err != nil {
		return ProbeResult{Err: newError(ReasonTargetRejected, t.Provider, "探活目标未通过安全约束", err)}
	}
	callCtx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, fullURL, nil)
	if err != nil {
		return ProbeResult{Err: newError(ReasonTargetRejected, t.Provider, "探活请求构造失败", err)}
	}
	if t.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+t.APIKey)
	}
	req.Header.Set("User-Agent", e.userAgent)

	transport := e.transport
	if proxy != e.proxyURL || check != nil {
		// 探针目标与执行器默认出口不一致时现构造 transport：
		// 探活频率低，不复用缓存；错误必须显式返回而不是悄悄走默认出口。
		built, terr := newTransport(proxy, check)
		if terr != nil {
			return ProbeResult{Err: Classify(terr, t.Provider)}
		}
		transport = built
	}
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return ProbeResult{Err: Classify(err, t.Provider)}
	}
	defer func() {
		// 读完即弃：探活不关心清单内容，但必须排空有界字节让连接可复用，
		// 且不排空超界体积（现网 probe.go 直接 Close，这里至少加个上限）。
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
		_ = resp.Body.Close()
	}()
	return ProbeResult{Healthy: resp.StatusCode < 500, StatusCode: resp.StatusCode}
}

const (
	probePath         = "/models"
	defaultProbeLimit = 64 << 10
)

// ------------------------------------------------------------------ 目标约束

// buildURL 拼装并校验最终请求 URL。这是执行器自己的安全边界（不是权限判断）：
//
//   - 只允许 http/https：file/gopher 之类 scheme 在 SSRF 清单上排第一页；
//   - 拒绝 URL 内嵌凭证（https://user:pass@host）：凭证进了 URL 就会出现在
//     日志、错误信息与审计的端点字段里（口径同 knowledge.validateEndpoint :320-351）；
//   - 路径必须绝对、已清理（拒绝 ".."，不依赖 http.Client 的宽容处理）；
//   - 路径里不许带 query/fragment：定界符混进路径会让「检查的路径」与
//     「发送的路径」不是一回事（server.go :695-700 用解码同源路径堵过这类差异，
//     这里从输入侧再堵一层）。
func buildURL(base, reqPath string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil {
		return "", fmt.Errorf("BaseURL 解析失败: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("只允许 http/https，当前 %q", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("BaseURL 缺少主机名")
	}
	if u.User != nil {
		return "", fmt.Errorf("BaseURL 不允许内嵌凭证")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("BaseURL 不能携带查询串或片段（可变入口无法固定比对）")
	}
	if !strings.HasPrefix(reqPath, "/") {
		return "", fmt.Errorf("Path 必须以 / 开头，当前 %q", reqPath)
	}
	if strings.ContainsAny(reqPath, "?#%\\") {
		return "", fmt.Errorf("Path 含查询/片段/百分号/反斜杠等定界符")
	}
	cleaned := stdpath.Clean(reqPath)
	if cleaned != reqPath {
		// 只接受已清理路径："..%2F" 之类的歧义形态在上一行 ContainsAny 已被拦下，
		// 这里挡的是明文 "../"：不依赖 http.Client 的宽容处理替我们做安全决定。
		return "", fmt.Errorf("Path 不是已清理的绝对路径")
	}
	return strings.TrimRight(u.String(), "/") + cleaned, nil
}

// isHopByHop 判定逐跳头。口径复制自 internal/server/forwarder.go :860-867，
// **有意复制而不是 import internal/server**：F 包不许依赖转发层（包边界），
// 而这份清单是 RFC 7230 钉死的枚举，两份的一致性用表驱动测试锁住即可。
// 改动任何一侧都必须同步另一侧 —— 两侧清单不一致的后果是同一个头在
// 请求方向被剥掉、响应方向被透传，这类不对称 bug 极难排查。
func isHopByHop(k string) bool {
	switch strings.ToLower(k) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailers", "transfer-encoding", "upgrade":
		return true
	}
	return false
}

// filterHopByHop 产出可透传给下游的响应头副本（剥掉逐跳头）。
// 返回新 map：调用方改它不会碰到 *http.Response 内部状态。
func filterHopByHop(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		if isHopByHop(k) {
			continue
		}
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// newTransport 经 internal/dialer 构造受出网约束的 transport。
// 关键参数与 dialer.TransportCache.GetChecked :84-96 保持同一口径：
// TLS1.2 下限、HTTP/2 尝试、显式关闭环境代理。
func newTransport(proxyURL string, check dialer.IPCheck) (*http.Transport, error) {
	d, err := dialer.NewChecked(proxyURL, check)
	if err != nil {
		return nil, err
	}
	t := &http.Transport{
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	// 直连时显式把 t.Proxy 置 nil：Go 默认读 HTTP_PROXY/HTTPS_PROXY 环境变量，
	// 而本工具的代理完全由配置决定，不应该被环境悄悄改道
	// （dialer/transport.go :64-65 的原话，口径必须一致）。
	t.Proxy = nil
	return t, nil
}
