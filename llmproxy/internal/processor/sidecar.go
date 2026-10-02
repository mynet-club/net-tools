package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 本文件是唯一的**出网**处理器：把处理请求交给一个外部 HTTP sidecar 判定。
//
// 三条硬约束来自任务边界，不是风格偏好：
//  1. 客户端由注册期注入（Config.HTTPClient），本包绝不自己 http.Get —— 现网出口策略
//     由 internal/dialer 的 AllowParsed 在传输层执行，用默认 transport 就等于绕过它；
//  2. 目标必须命中 Spec.AllowedEndpoints，且禁止跟随重定向（否则白名单只管第一次请求）；
//  3. 送出去的默认是「已脱敏的正文」或「摘要」，原文必须同时满足
//     Spec.AllowRawBody 与管理员授权（policy.Resolver.AllowsRawBody）—— §2.9 规则 3、4。

// sidecar 的正文投递形态。
const (
	// SidecarContentNone 只送元数据摘要（metadata-only 档位，或原文未获授权且尚无脱敏结果）。
	SidecarContentNone = "none"
	// SidecarContentMasked 送链上已产出的脱敏正文（默认形态）。
	SidecarContentMasked = "masked"
	// SidecarContentRaw 送原文，仅在 allow_raw_body 且管理员授权成立时出现。
	SidecarContentRaw = "raw"
)

// sidecar 动作（响应里的 action 字段）。
const (
	SidecarActionPass  = "pass"
	SidecarActionMask  = "mask"
	SidecarActionLabel = "label"
)

const (
	// SidecarPayloadVersion 是投递文档的契约版本。sidecar 侧要能按版本区分字段含义，
	// 否则 E 加一个字段就成为「上游悄悄改了请求格式」。
	SidecarPayloadVersion = 1
	// MaxMetadataBytes 限制送给 sidecar 的元数据大小：元数据由接线方提供，
	// 一个 30MB 的 metadata 说明有人把正文塞进来了，尺寸上限是第一道拦截。
	MaxMetadataBytes = 8 << 10
	// sidecarBackoffBase/sidecarMaxBackoff 是重试间隔。退避必须存在：
	// 一个已经 5xx 的依赖被每条请求连打三次只会加剧故障，
	// 而上限是为了让「重试」不至于吃掉整个 Spec.Timeout 预算。
	sidecarBackoffBase = 25 * time.Millisecond
	sidecarMaxBackoff  = 250 * time.Millisecond
)

// sidecarPayload 是投递给 sidecar 的请求体。
//
// Content 带 omitempty：metadata-only 时这个字段必须**不存在**，
// 而不是存在但为空串 —— 空串会被下游解读成「正文是空的」，
// 而无测试断言的序列化差异正是最容易在重构中丢掉的一条安全属性。
type sidecarPayload struct {
	Version       int             `json:"version"`
	RequestID     string          `json:"request_id"`
	Processor     string          `json:"processor"`
	ProcessorVer  string          `json:"processor_version"`
	Phase         string          `json:"phase"`
	Model         string          `json:"model,omitempty"`
	Purpose       string          `json:"purpose,omitempty"`
	Stream        bool            `json:"stream,omitempty"`
	BodyAccess    string          `json:"body_access"`
	ContentMode   string          `json:"content_mode"`
	ContentLen    int64           `json:"content_len"`
	ContentHash   string          `json:"content_hash,omitempty"`
	DeclaredBytes int64           `json:"declared_bytes,omitempty"`
	Scopes        string          `json:"scopes,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
	PolicyVersion string          `json:"policy_version,omitempty"`
	Content       string          `json:"content,omitempty"`
}

// sidecarReply 是 sidecar 的响应契约。只认这四个字段，多余字段忽略。
type sidecarReply struct {
	Allowed   *bool    `json:"allowed"`
	Action    string   `json:"action,omitempty"`
	ShortCode string   `json:"short_code,omitempty"`
	Rewrites  []string `json:"rewrites,omitempty"`
	Body      string   `json:"body,omitempty"`
}

// sidecar 是外部 HTTP 判定处理器。
//
// 字段全是注册期定死的配置，没有可变状态：调用计数、占位表这些都必须是每次调用的
// 局部状态（见 Processor 注释）。clock 也算配置 —— 一个包里有两套钟，
// 回放和测试就只能对上其中一套。
type sidecar struct {
	spec       Spec
	endpoint   string // 规范化后的目标，构造期算一次（请求期不再解析 URL）
	client     *http.Client
	grants     RawBodyGrantChecker
	clock      func() time.Time
	headers    map[string]string
	maxRetries int
	idempotent bool
}

func newSidecar(spec Spec, cfg *Config) (Processor, error) {
	if cfg == nil {
		return nil, Errorf(ErrConfigInvalid, "%s: http-sidecar 需要 Config（客户端与端点只能在注册期绑定）", spec.Name)
	}
	if cfg.HTTPClient == nil {
		return nil, Errorf(ErrConfigInvalid,
			"%s: 缺少 HTTPClient。必须由接线方注入带出网策略的客户端；本包自己建连接就绕过了 dialer 的目标白名单", spec.Name)
	}
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, Errorf(ErrConfigInvalid, "%s: 缺少 endpoint", spec.Name)
	}
	if len(spec.AllowedEndpoints) == 0 {
		return nil, Errorf(ErrConfigInvalid, "%s: http-sidecar 必须声明 allowed_endpoints，否则出网目标不可审", spec.Name)
	}
	// 授权判定器在**构造期**就要就位：allow_raw_body 意味着客户端原文要出网，
	// 缺判定器却照常注册的话，缺口要到第一个真实请求才暴露，而那时原文已经在请求路径上了。
	// 与 rawBodyGranted 里那道运行期检查并存是刻意的 —— 那是「有人绕过注册直接拼 struct」的兜底。
	if spec.AllowRawBody && cfg.Grants == nil {
		return nil, Errorf(ErrGrantCheckerBlank,
			"%s: 声明了 allow_raw_body 但未注入 Config.Grants（原文出网必须有管理员授权可校验，注册即拒绝）", spec.Name)
	}
	target, err := canonicalEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, Errorf(ErrEndpointInvalid, "%s: %v", spec.Name, err)
	}
	// 构造期先查一次白名单：注册一个注定被拒的端点是纯粹的配错，
	// 留到请求期报会让它看起来像依赖故障。
	if !endpointAllowed(target, spec.AllowedEndpoints) {
		return nil, Errorf(ErrEndpointDenied, "%s: endpoint %s 不在 allowed_endpoints 内", spec.Name, target)
	}
	if cfg.MaxRetries < 0 || cfg.MaxRetries > AbsoluteMaxRetries {
		return nil, Errorf(ErrConfigInvalid, "%s: max_retries %d 必须落在 [0,%d]", spec.Name, cfg.MaxRetries, AbsoluteMaxRetries)
	}
	if !cfg.Idempotent && cfg.MaxRetries > 0 {
		// 非幂等调用的重试次数**强制归零**并直接报错，而不是悄悄按 0 处理：
		// 静默降级会让运营以为配了重试，实际一次都没重放。
		return nil, Errorf(ErrConfigInvalid,
			"%s: idempotent=false 时 max_retries 必须为 0（非幂等调用重试会产生重复副作用）", spec.Name)
	}
	retries := cfg.MaxRetries
	if cfg.Idempotent && retries == 0 {
		retries = DefaultSidecarMaxRetry
	}
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		if err := validSidecarHeader(k, v); err != nil {
			return nil, Errorf(ErrConfigInvalid, "%s: %v", spec.Name, err)
		}
		headers[k] = v
	}
	// 复制一份注入的客户端并钉死 CheckRedirect。
	// 直接改 cfg.HTTPClient.CheckRedirect 有两个后果：那个客户端可能被别的组件共享，
	// 而且并发修改一个 struct 字段是数据竞争（-race 会红）。
	// 不设 CheckRedirect 更糟：Go 默认跟随 3xx，一次 302 就能把字节从白名单之外的地址
	// 取回来，allowed_endpoints 于是只管了第一次请求 —— 目标约束必须覆盖整条重定向链。
	signed := *cfg.HTTPClient
	signed.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		next, cErr := canonicalEndpoint(req.URL.String())
		if cErr != nil {
			return Errorf(ErrEndpointDenied, "%s: 重定向目标不合法: %v", spec.Name, cErr)
		}
		// 重定向后同源同路径才算同一个端点（只允许 path 前缀内的重排）。
		if !endpointAllowed(next, []string{target}) {
			return Errorf(ErrEndpointDenied, "%s: 禁止重定向到白名单外的目标", spec.Name)
		}
		return nil
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &sidecar{
		spec:       spec,
		endpoint:   target,
		client:     &signed,
		grants:     cfg.Grants,
		clock:      clock,
		headers:    headers,
		maxRetries: retries,
		idempotent: cfg.Idempotent,
	}, nil
}

// validSidecarHeader 拦住注入类与逐跳头。
//
// Header 值含 CR/LF 就能在 HTTP 请求里插出一行任意内容（响应走私的经典入口）；
// 逐跳头（Host、Content-Length、Connection、Transfer-Encoding）由 transport 自己管，
// 手工设置会让请求直接不合法。
func validSidecarHeader(name, value string) error {
	if name == "" || len(name) > 128 {
		return fmt.Errorf("头名长度不合法")
	}
	if strings.ContainsAny(name, "\r\n\t :") {
		return fmt.Errorf("头名 %q 含非法字符", name)
	}
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("头 %s 的值含换行（禁止请求走私）", name)
	}
	switch strings.ToLower(name) {
	case "host", "content-length", "connection", "transfer-encoding", "expect", "upgrade":
		return fmt.Errorf("头 %s 由 transport 管理，不允许在配置里设置", name)
	}
	return nil
}

func (s *sidecar) Spec() Spec { return s.spec }

// Process 调用一次 sidecar。
//
// 失败语义（§2.9 规则 5）：
//   - 依赖故障（网络、超时、5xx、重试用尽）→ classInfrastructure，按 FailClosed 决定
//     拒整次请求还是跳过；
//   - 违规（目标不在白名单、超大小、原文未授权）与判定不通过（allowed=false）
//     → classViolation / classVerdict，**无视 FailClosed 一律拒绝**。
func (s *sidecar) Process(ctx context.Context, in *Input) (*Output, error) {
	payload, err := s.buildPayload(in)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, Errorf(ErrProcessFailed, "%s: 投递文档序列化失败: %v", s.spec.Name, err)
	}
	// MaxInputBytes 在这里量的是**实际出网的字节**：正文超限已经在取正文时报过，
	// 但元数据 + 包装同样能把出网体量撑大，只卡正文等于漏掉一半。
	if int64(len(data)) > s.spec.MaxInputBytes {
		return nil, Errorf(ErrInputTooLarge, "%s: 投递 %d 字节，超过 max_input_bytes %d",
			s.spec.Name, len(data), s.spec.MaxInputBytes)
	}

	reply, attempts, err := s.call(ctx, data)
	if err != nil {
		return nil, err
	}
	out := &Output{Attempts: attempts, Reason: ReasonOK}
	if !boolValue(reply.Allowed) {
		// 判定不通过是**结论**，不是故障：fail_open 也不能把它冲掉，
		// 否则 sidecar 说「拦下」而网关照样转发，接这个处理器就毫无意义。
		code := sanitizeShortCode(reply.ShortCode)
		if code == "" {
			code = "unspecified"
		}
		return nil, Errorf(ErrSidecarReject, "%s: sidecar 判定拒绝（%s）", s.spec.Name, code)
	}
	if len(reply.Rewrites) > 0 {
		for _, kind := range reply.Rewrites {
			kind = sanitizeShortCode(kind)
			if kind == "" {
				continue
			}
			out.Rewrites = append(out.Rewrites, Rewrite{Kind: kindFor("sidecar:", kind), Count: 1})
		}
	}
	if reply.Body != "" {
		if !in.CanReplaceBody() {
			// 冲突处理：策略说「不许替换正文」，sidecar 却给了新正文。
			// 这里**不猜**：悄悄丢掉新正文可能放走本该被打码的内容，
			// 悄悄接受又越过档位。拒绝整次请求并留原因码才是可审计的行为。
			return nil, Errorf(ErrBodyReplaceDenied,
				"%s: 档位为 %s 但 sidecar 返回了新正文（%d 字节），拒绝而不是二选一",
				s.spec.Name, in.access, len(reply.Body))
		}
		if int64(len(reply.Body)) > s.spec.MaxOutputBytes {
			return nil, Errorf(ErrOutputTooLarge, "%s: sidecar 返回 %d 字节，超过 max_output_bytes %d",
				s.spec.Name, len(reply.Body), s.spec.MaxOutputBytes)
		}
		out.Body = []byte(reply.Body)
	}
	if meta := s.replyMetadata(reply); len(meta) > 0 {
		out.Metadata = meta
	}
	return out, nil
}

// replyMetadata 把 sidecar 的结论摘要整理成审计可留的形态：只留短码与动作，
// 且都过一遍 sanitizeShortCode —— 外部服务的任何字段都是**不可信输入**，
// 直接进审计就等于让一个第三方往我们的日志里写任意字符串（规则 6）。
func (s *sidecar) replyMetadata(reply *sidecarReply) json.RawMessage {
	code := sanitizeShortCode(reply.ShortCode)
	action := sanitizeShortCode(reply.Action)
	if code == "" && action == "" {
		return nil
	}
	meta := map[string]string{}
	if code != "" {
		meta["short_code"] = code
	}
	if action != "" {
		meta["action"] = action
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return nil
	}
	return data
}

// buildPayload 决定这次到底送出什么。判定顺序就是 §2.9 规则 3、4 的顺序。
func (s *sidecar) buildPayload(in *Input) (*sidecarPayload, error) {
	payload := &sidecarPayload{
		Version:       SidecarPayloadVersion,
		RequestID:     in.RequestID,
		Processor:     s.spec.Name,
		ProcessorVer:  s.spec.Version,
		Phase:         string(in.Phase),
		Model:         in.Model,
		Purpose:       in.Purpose,
		Stream:        in.Stream,
		BodyAccess:    string(s.spec.BodyAccess),
		ContentMode:   SidecarContentNone,
		DeclaredBytes: in.DeclaredBodyBytes,
		Scopes:        in.Chain.Display(),
		PolicyVersion: in.Policy.PolicyVersion,
	}
	if len(in.Metadata) > 0 {
		if len(in.Metadata) > MaxMetadataBytes {
			return nil, Errorf(ErrInputTooLarge, "%s: 元数据 %d 字节，超过投递上限 %d",
				s.spec.Name, len(in.Metadata), MaxMetadataBytes)
		}
		payload.Metadata = append(json.RawMessage(nil), in.Metadata...)
	}
	if !in.CanReadBody() {
		// metadata-only：一个字节都不取，摘要里也不含内容。
		// 这是本包最重要的快路径，由「读取即 panic」的测试守着。
		return payload, nil
	}
	data, err := in.Body()
	if err != nil {
		return nil, err
	}
	payload.ContentLen = int64(len(data))
	payload.ContentHash = sha256Hex(data)
	switch {
	case s.spec.AllowRawBody:
		granted, reason, gErr := s.rawBodyGranted(in)
		in.NoteGrantReason(reason)
		if gErr != nil {
			return nil, gErr
		}
		if !granted {
			// 声明了 allow_raw_body 却没有管理员授权：**拒绝**而不是退化成摘要。
			// 退化会让策略作者以为原文送到了 sidecar 并据此做了判定，
			// 实际收到的是摘要 —— 那是用「请求成功」掩盖一个合规缺口。
			return nil, Errorf(ErrRawBodyDenied,
				"%s: 声明 allow_raw_body 但 %s 未获管理员授权（策略侧原因码：%s）",
				s.spec.Name, in.Policy.Purpose, fallbackReason(reason))
		}
		payload.ContentMode = SidecarContentRaw
		payload.Content = string(data)
	case in.transformed:
		// 链上已有处理器产出新正文（典型是 pii-mask 在前）：默认送的就是这份脱敏正文。
		payload.ContentMode = SidecarContentMasked
		payload.Content = string(data)
	default:
		// 还能读正文，但读到的就是客户端原文，且没授权原文出网 —— 只能送摘要。
		// 留一个原因码，好让运营看出「sidecar 收到的是摘要而不是脱敏正文」，
		// 这两者的判定质量差别很大。
		payload.ContentMode = SidecarContentNone
		in.NoteSummaryOnlyFallback()
	}
	return payload, nil
}

// rawBodyGranted 走管理员授权链路。
//
// 判定本身不在这里做：deny > explicit_allow > group_allow 的次序、通配不算授权、
// 授权自带过期，全部由 A 包的 Resolver 持有（手册 §5 把这块归业务层）。
// E 只做两件事：**必须**调用它，以及拿不到判定器时绝不放行。
func (s *sidecar) rawBodyGranted(in *Input) (bool, policy.Reason, error) {
	if s.grants == nil {
		return false, "", Errorf(ErrGrantCheckerBlank,
			"%s: 声明了 allow_raw_body 但注册时未注入授权判定器（Config.Grants），无法校验", s.spec.Name)
	}
	now := in.Now
	if now.IsZero() {
		// 接线方没给请求时间：退回注册期注入的时间源，而不是就地 time.Now()。
		// 退到墙上时钟会让「同一请求的两次判定」得到不同的授权结论 ——
		// 授权自带过期，跨过边界那一秒重放就翻面，而 §2.8 要求回放可复现。
		now = s.clock()
	}
	allowed, reason := s.grants.AllowsRawBody(in.Policy, in.Chain, now)
	return allowed, reason, nil
}

// call 执行带重试的 POST。
//
// 重试预算：所有尝试共享同一份 Spec.Timeout（由 Pipeline 通过 ctx 传入），
// 不做「每次尝试各给一个 Timeout」—— 那会把最坏耗时放大成 超时 × 次数，
// 而调用方（forwarder）只按一个时限等。
func (s *sidecar) call(ctx context.Context, payload []byte) (*sidecarReply, int, error) {
	attempts := 0
	var lastErr error
	for attempt := 0; attempt <= s.maxRetries; attempt++ {
		if attempt > 0 {
			if waitErr := waitBackoff(ctx, sidecarBackoffBase<<uint(attempt-1)); waitErr != nil {
				return nil, attempts, Errorf(ErrTimeout, "%s: 重试等待期间超时: %v", s.spec.Name, waitErr)
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, attempts, Errorf(ErrTimeout, "%s: %v", s.spec.Name, err)
		}
		attempts++
		reply, retryable, err := s.attempt(ctx, payload)
		if err == nil {
			return reply, attempts, nil
		}
		lastErr = err
		if !retryable || !s.idempotent {
			// 非幂等时一次都不重试（maxRetries 已在构造期归零，这里是第二道）：
			// 一个已经落了判定结果的 sidecar 被重放两次，就是两条重复副作用。
			return nil, attempts, err
		}
	}
	return nil, attempts, Errorf(ErrRetryExhausted, "%s: %d 次尝试后仍失败（%v）",
		s.spec.Name, attempts, unwrapText(lastErr))
}

// attempt 单次调用。第二个返回值表示「这次失败可以重放」。
func (s *sidecar) attempt(ctx context.Context, payload []byte) (*sidecarReply, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, false, Errorf(ErrEndpointInvalid, "%s: 请求构造失败: %v", s.spec.Name, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		// CheckRedirect 拒绝重定向时，错误会被 transport 包一层带出来。
		// 必须先认出它：把「出网目标不被允许」当成可重试的依赖故障，
		// 就等于允许对同一个白名单外地址反复冲击，还会把违规降级成 fail_open 可跳过。
		if errors.Is(err, ErrEndpointDenied) {
			return nil, false, Errorf(ErrEndpointDenied, "%s: %v", s.spec.Name, errText(err))
		}
		return nil, true, Errorf(ErrSidecarFailed, "%s: 调用失败: %v", s.spec.Name, errText(err))
	}
	defer func() {
		// 排空少量字节以便连接复用；失败无所谓。
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()
	// 双保险：即使注入的客户端没设 CheckRedirect，也不能被 302 带出白名单。
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, false, Errorf(ErrEndpointDenied,
			"%s: sidecar 返回重定向 %d（禁止跟随，否则白名单只管第一次请求）", s.spec.Name, resp.StatusCode)
	}
	// MaxOutputBytes + 1：区分「正好等于上限」与「还有更多」，后者必须拒。
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.spec.MaxOutputBytes+1))
	if err != nil {
		return nil, true, Errorf(ErrSidecarFailed, "%s: 读取响应失败: %v", s.spec.Name, errText(err))
	}
	if int64(len(body)) > s.spec.MaxOutputBytes {
		// 超限是**违规**（依赖不守约），不是可重试的故障：重试只会再收一次超大响应。
		return nil, false, Errorf(ErrOutputTooLarge, "%s: sidecar 响应超过 max_output_bytes %d 字节",
			s.spec.Name, s.spec.MaxOutputBytes)
	}
	switch {
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode == http.StatusRequestTimeout:
		return nil, true, Errorf(ErrSidecarFailed, "%s: sidecar 返回 %d", s.spec.Name, resp.StatusCode)
	case resp.StatusCode >= 400:
		// 4xx 是「这个请求本身不被接受」，重放同一个请求不会变好。
		return nil, false, Errorf(ErrSidecarFailed, "%s: sidecar 拒绝请求，状态码 %d", s.spec.Name, resp.StatusCode)
	}
	var reply sidecarReply
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&reply); err != nil {
		return nil, false, Errorf(ErrSidecarFailed, "%s: 响应不是合法 JSON: %v", s.spec.Name, err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, false, Errorf(ErrSidecarFailed, "%s: 响应尾部有多余内容", s.spec.Name)
	}
	if reply.Allowed == nil {
		return nil, false, Errorf(ErrSidecarFailed, "%s: 响应缺少 allowed 字段（不放行未显式允许的回复）", s.spec.Name)
	}
	return &reply, false, nil
}

// waitBackoff 可被 ctx 打断的退避。
func waitBackoff(ctx context.Context, d time.Duration) error {
	if d > sidecarMaxBackoff {
		d = sidecarMaxBackoff
	}
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func boolValue(p *bool) bool { return p != nil && *p }

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// unwrapText 剥掉包装链上的哨兵前缀，只留可读部分，用于「重试用尽」的聚合报错。
func unwrapText(err error) string {
	if err == nil {
		return "nil"
	}
	msg := err.Error()
	if i := strings.Index(msg, ": "); i >= 0 {
		return msg[i+2:]
	}
	return msg
}

// fallbackReason 给空策略原因码一个占位值，避免审计里出现空白字段。
func fallbackReason(r policy.Reason) policy.Reason {
	if r == "" {
		return "unspecified"
	}
	return r
}
