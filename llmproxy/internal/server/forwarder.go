package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// bodyProbe 只读出路由所需的字段，不碰消息内容。
type bodyProbe struct {
	Model         string           `json:"model"`
	Stream        bool             `json:"stream"`
	StreamOptions *json.RawMessage `json:"stream_options"`
}

type usageInfo struct {
	PromptTokens     *int64 `json:"prompt_tokens"`
	CompletionTokens *int64 `json:"completion_tokens"`
	TotalTokens      *int64 `json:"total_tokens"`
	// DeepSeek 等会回报输入里命中/未命中缓存的部分，两者单价差得很远，
	// 计费必须区分；不回报的上游保持为 0，由计费侧按「全部未命中」保守处理。
	PromptCacheHitTokens  *int64 `json:"prompt_cache_hit_tokens"`
	PromptCacheMissTokens *int64 `json:"prompt_cache_miss_tokens"`
	// OpenAI / Azure 及其兼容实现（不少聚合商都是这个形状）把命中数放在这里：
	// cached_tokens 是**命中**的那部分，未命中要自己从 prompt_tokens 里减出来。
	// 只认上面两个字段的话，这类上游的命中会被记成 0 —— 于是命中率凭空消失，
	// 金额又按「全部未命中」被高估。
	PromptTokensDetails *struct {
		CachedTokens *int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
}

// cacheHitMiss 把两套字段归一化成「命中/未命中」两个数，ok=false 表示上游压根没报。
//
// 显式的 hit/miss（DeepSeek 风格）优先；只有 cached_tokens 时，命中 = cached，
// 未命中 = prompt_tokens - cached。负数一律夹成 0：上游报的数字不可全信，
// 让它们进到金额里比丢掉更糟。
func (u *usageInfo) cacheHitMiss() (hit, miss int64, ok bool) {
	if u == nil {
		return 0, 0, false
	}
	if u.PromptCacheHitTokens != nil || u.PromptCacheMissTokens != nil {
		if u.PromptCacheHitTokens != nil {
			hit = *u.PromptCacheHitTokens
		}
		if u.PromptCacheMissTokens != nil {
			miss = *u.PromptCacheMissTokens
		}
		if hit < 0 {
			hit = 0
		}
		if miss < 0 {
			miss = 0
		}
		return hit, miss, true
	}
	if u.PromptTokensDetails != nil && u.PromptTokensDetails.CachedTokens != nil && u.PromptTokens != nil {
		hit = *u.PromptTokensDetails.CachedTokens
		if hit < 0 {
			hit = 0
		}
		if hit > *u.PromptTokens {
			hit = *u.PromptTokens // cached 比 prompt 还大只可能是上游算错，夹住
		}
		return hit, *u.PromptTokens - hit, true
	}
	return 0, 0, false
}

// handleUpstreamPost 把 /v1/* 的 POST 请求按模型路由到上游供应商。
func (s *Server) handleUpstreamPost(w http.ResponseWriter, r *http.Request, auth authResult) {
	cfg := s.cfgStore.Current()
	started := time.Now()
	requestID := r.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = newRequestID()
	}

	rec := store.RequestRecord{
		Ts:            started,
		RequestID:     requestID,
		ClientKeyHash: auth.KeyHash,
		ClientLabel:   auth.Label,
		ClientIP:      auth.ClientIP,
		UserName:      auth.UserName, // 空 = 静态 key；非空时额外记一份用户维度用量
	}

	// 这次请求该用哪组上游由「用户的模式 + 模型名」共同决定，而模型名在请求体里，
	// 所以上游池要等读完 body 再解析（见下面的 providersFor 调用）。
	// 作用域同时决定熔断状态落在哪个桶里 —— 用户之间互不影响。
	scope := auth.Scope

	// 用户级限流与配额：都不依赖请求体，先判，省得白读一遍 body。
	// 限流对两种模式都生效（单个用户打满网关跟模式无关），配额只对消费模式生效。
	if e := s.usersSnapshot().byName[scope]; e != nil {
		release, err := s.meters.Acquire(e.Name, e.RPM, e.MaxConcurrent)
		if err != nil {
			var le *limitedError
			if errors.As(err, &le) {
				s.fail(w, rec, le.status, le.kind, le.msg, 0, started)
				return
			}
			s.fail(w, rec, http.StatusInternalServerError, "internal", err.Error(), 0, started)
			return
		}
		defer release()

		if e.Consumption {
			if _, _, exceeded, msg := s.meters.CheckQuota(e.Name, e.QuotaMonthTokens, e.QuotaMonthCost); exceeded {
				s.fail(w, rec, http.StatusPaymentRequired, "quota_exceeded", msg, 0, started)
				return
			}
		}
	}

	// 请求体上限
	r.Body = http.MaxBytesReader(w, r.Body, cfg.Server.MaxBodyBytes())
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.fail(w, rec, http.StatusRequestEntityTooLarge, "request_too_large",
				fmt.Sprintf("请求体超过 %d MB 上限", cfg.Server.MaxBodyMB), 0, started)
			return
		}
		s.fail(w, rec, http.StatusBadRequest, "invalid_request_error",
			fmt.Sprintf("读取请求体失败: %v", err), 0, started)
		return
	}

	var probe bodyProbe
	if err := json.Unmarshal(raw, &probe); err != nil {
		s.fail(w, rec, http.StatusBadRequest, "invalid_request_error",
			fmt.Sprintf("请求体不是合法 JSON: %v", err), 0, started)
		return
	}
	rec.Model = probe.Model
	rec.Stream = probe.Stream
	if strings.TrimSpace(probe.Model) == "" {
		s.fail(w, rec, http.StatusBadRequest, "invalid_request_error",
			"请求体缺少 model 字段", 0, started)
		return
	}

	// 上游池：消费模式要按「这个模型映射到哪个上游」来收窄，所以必须等 model 到手
	providers, isSystem := s.providersFor(scope, probe.Model)
	rec.SystemPaid = isSystem
	if len(providers) == 0 {
		// 归因要分清：是「管理员把你能用的收窄了」，还是「系统池里根本没有这个模型」。
		// 前者 403 并告诉用户找谁；后者是池子的问题，不是用户的权限问题。
		if consumption, narrowed, listed := s.consumptionVerdict(scope, probe.Model); consumption && narrowed && !listed {
			s.fail(w, rec, http.StatusForbidden, "model_not_allowed",
				fmt.Sprintf("模型 %q 不在你的可用列表里（管理员给你指定了模型范围）；"+
					"要用这个模型请联系管理员放开", probe.Model), 0, started)
			return
		}
		msg := "没有可用的上游供应商"
		// 「根本没配」和「配了但都不可用」要分开说：前者是可操作的下一步，后者是排障
		if s.hasNoProviders(scope) {
			msg = "你还没有配自己的上游：可以用 PUT /v1/_me/providers/{名字} 配一个，" +
				"或者让管理员把你的模式改成 consumption 来使用系统上游（那部分按配额计费）"
		} else if note := s.unusableNote(scope); note != "" {
			msg = note
		} else if consumption, narrowed, listed := s.consumptionVerdict(scope, probe.Model); consumption && narrowed && listed {
			// 名单里有这个名字（所以不是权限问题），但池子里没有一家声明它。
			// 明确说清是「池子缺这个模型」，别让它混在一句含糊的「没有可用的上游」里。
			msg = fmt.Sprintf("系统池里没有一家供应商声明了模型 %q："+
				"在某家供应商的 models 里加上这个名字，或者把它从这个用户的模型范围里去掉", probe.Model)
		}
		s.fail(w, rec, http.StatusBadGateway, "upstream_unavailable", msg, 0, started)
		return
	}

	// 上游超时：取全局上限与供应商自身超时的较小值
	globalTimeout := time.Duration(cfg.Server.RequestTimeoutMs) * time.Millisecond

	maxAttempts := s.router.RetryLimit()
	exclude := map[string]bool{}
	var (
		lastErr       error
		lastStatus    int
		lastProvider  string
		lastUpstreamM string
	)
	attempts := 0

	// 会话粘性：下游（MiMoCode 等）会在 x-session-affinity 里带会话 id，没有这个头
	// 就没有粘性，照旧按权重随机。粘性的键是 (用户, 会话, 模型) —— 上游的前缀缓存
	// 本来就按模型分区，一个会话还会调多个模型。配置里 affinity_ttl_ms=0 时整体关闭，
	// 这时连观测头都不写，免得留一条永远是 new 的字段来混淆排障。
	affinityOn := s.affinity.Enabled()
	affinitySession := ""
	prefer := ""
	if affinityOn {
		affinitySession = r.Header.Get("X-Session-Affinity")
		prefer = s.affinity.Get(scope, affinitySession, probe.Model) // 头为空时返回 ""
	}

	for i := 0; i < maxAttempts; i++ {
		cand, err := s.router.PickFromPreferring(scope, providers, probe.Model, exclude, prefer)
		if err != nil {
			if lastErr == nil {
				lastErr = fmt.Errorf("%w（当前可用模型：%s）", err, describeModels(providers))
			}
			break
		}
		attempts++

		// 观测：告诉调用方这次是按粘性选的（sticky）还是漂移过来的（drift），
		// 或者本来就没粘性记录（new）。排障与上线验证都要看这一列。
		if affinityOn && affinitySession != "" {
			outcome := "new"
			if prefer != "" {
				if cand.Provider.Name == prefer {
					outcome = "sticky"
				} else {
					outcome = "drift"
				}
			}
			w.Header().Set("X-Llmproxy-Affinity", outcome)
		}

		proxyURL, err := cand.Provider.Proxy.Resolve(cfg.ProxyIndex)
		if err != nil {
			s.log.Errorf("供应商 %s 代理配置错误: %v", cand.Provider.Name, err)
			lastErr = err
			exclude[cand.Provider.Name] = true
			continue
		}

		tr, err := s.transports.Get(proxyURL)
		if err != nil {
			s.log.Errorf("供应商 %s 构造代理失败: %v", cand.Provider.Name, err)
			lastErr = err
			exclude[cand.Provider.Name] = true
			continue
		}

		provTimeout := time.Duration(cand.Provider.TimeoutMs) * time.Millisecond
		timeout := provTimeout
		if globalTimeout > 0 && globalTimeout < timeout {
			timeout = globalTimeout
		}
		// 流式不用总时限（长回答会被正常掐断），改成「连续多久没数据」的看门狗。
		// 见 idle.go 的说明。
		var (
			ctx    context.Context
			cancel context.CancelFunc
			wd     *idleWatchdog
		)
		if probe.Stream && cfg.Server.StreamIdleMs() > 0 {
			ctx, cancel = context.WithCancel(r.Context())
			wd = newIdleWatchdog(time.Duration(cfg.Server.StreamIdleMs())*time.Millisecond, cancel)
			defer wd.Stop()
		} else {
			ctx, cancel = context.WithTimeout(r.Context(), timeout)
		}

		upBody, err := rewriteModelBody(raw, cand.UpstreamModel, probe.Stream)
		if err != nil {
			cancel()
			lastErr = err
			exclude[cand.Provider.Name] = true
			continue
		}

		// base_url 已在配置校验里去掉末尾斜杠；上游路径按 OpenAI 兼容约定拼接
		suffix := strings.TrimPrefix(r.URL.Path, "/v1")
		if suffix == "" {
			suffix = r.URL.Path
		}
		upURL := cand.Provider.BaseURL + suffix

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, upURL, bytes.NewReader(upBody))
		if err != nil {
			cancel()
			lastErr = err
			exclude[cand.Provider.Name] = true
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+cand.Provider.APIKey)
		req.Header.Set("User-Agent", "llmproxy/"+config.Version)
		req.ContentLength = int64(len(upBody))
		if accept := r.Header.Get("Accept"); accept != "" {
			req.Header.Set("Accept", accept)
		}
		for k, v := range cand.Provider.ExtraHeaders {
			if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Host") {
				continue // 绝不让配置覆盖鉴权与 Host
			}
			req.Header.Set(k, v)
		}
		// 刻意不转发下游的 Authorization / Cookie / X-Api-Key

		resp, err := tr.RoundTrip(req)
		if err != nil {
			// 注意：这里才能 cancel。context 会控制整个请求-响应生命周期，
			// 过早 cancel 会导致后续读 body 失败。
			cancel()
			if wd.Fired() {
				// 看门狗掐的：上下文是被 Cancel 而不是超时，不认一下会误报成「客户端断开」
				err = fmt.Errorf("供应商 %s 连续 %s 没有返回数据（空闲超时）",
					cand.Provider.Name, wd.Idle())
			} else if errMsg := err.Error(); strings.Contains(errMsg, "context deadline exceeded") || strings.Contains(errMsg, "Client.Timeout") {
				err = fmt.Errorf("供应商 %s 请求超时（%s）", cand.Provider.Name, timeout)
			}
			s.log.Warnf("供应商 %s 请求失败: %v", cand.Provider.Name, err)
			s.router.ReportFailureFor(scope, cand.Provider.Name, err)
			lastErr = err
			lastProvider = cand.Provider.Name
			lastUpstreamM = cand.UpstreamModel
			exclude[cand.Provider.Name] = true
			continue
		}
		wd.Touch() // 响应头到了也算「有数据在动」

		if retryableStatus(resp.StatusCode) {
			snippet := readSnippet(resp.Body, 300)
			_ = resp.Body.Close()
			cancel()
			s.log.Warnf("供应商 %s 返回 %d: %s", cand.Provider.Name, resp.StatusCode, snippet)
			s.router.ReportFailureFor(scope, cand.Provider.Name, fmt.Errorf("上游返回 %d: %s", resp.StatusCode, snippet))
			lastErr = fmt.Errorf("供应商 %s 返回 %d", cand.Provider.Name, resp.StatusCode)
			lastStatus = resp.StatusCode
			lastProvider = cand.Provider.Name
			lastUpstreamM = cand.UpstreamModel
			exclude[cand.Provider.Name] = true
			continue
		}

		// ---- 成功路径：把响应交给客户端（body 读完之后才能 cancel）
		s.router.ReportSuccessFor(scope, cand.Provider.Name)
		rec.Provider = cand.Provider.Name
		rec.UpstreamModel = cand.UpstreamModel
		rec.Attempts = attempts
		rec.StatusCode = resp.StatusCode

		// 记录/更新粘性。只有真正成功的响应才钉住这家；非重试类 4xx
		// （比如这家在配置里声明了这个名字、上游其实不认）说明「这家用不了」——
		// 忘掉粘性让下一个请求重新选。这条很要紧：4xx 不触发熔断，
		// 不忘掉的话会话会被钉在一家只会报错的后端上死循环。
		if affinitySession != "" {
			if resp.StatusCode < 400 {
				s.affinity.Set(scope, affinitySession, probe.Model, cand.Provider.Name)
			} else {
				s.affinity.Set(scope, affinitySession, probe.Model, "")
			}
		}

		func() {
			defer cancel()
			s.relay(w, r, resp, &rec, started, wd)
		}()
		return
	}

	// 全部尝试失败：忘掉粘性，让下一个请求重新选 —— 别把会话钉在一家已经全挂的后端上
	if affinitySession != "" {
		s.affinity.Set(scope, affinitySession, probe.Model, "")
	}

	// 全部尝试失败
	rec.Attempts = attempts
	rec.Provider = lastProvider
	rec.UpstreamModel = lastUpstreamM
	if lastStatus == 0 {
		lastStatus = http.StatusBadGateway
	}
	msg := "所有上游供应商均不可用"
	if lastErr != nil {
		msg = fmt.Sprintf("所有上游供应商均不可用：%v", lastErr)
	}
	s.fail(w, rec, lastStatus, "upstream_unavailable", msg, attempts, started)
}

// relay 把上游响应原样写给下游；同时提取 usage / TTFT 元数据。
func (s *Server) relay(w http.ResponseWriter, r *http.Request, resp *http.Response, rec *store.RequestRecord, started time.Time, wd *idleWatchdog) {
	defer resp.Body.Close()

	// 复制响应头（跳过 hop-by-hop）
	for k, vs := range resp.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-LLMProxy-Provider", rec.Provider)
	w.Header().Set("X-LLMProxy-Request-Id", rec.RequestID)
	w.WriteHeader(resp.StatusCode)

	contentType := resp.Header.Get("Content-Type")
	isSSE := strings.Contains(contentType, "text/event-stream")

	scanner := &usageScanner{start: started}
	var dest io.Writer = w
	if f, ok := w.(http.Flusher); ok && isSSE {
		dest = &flushWriter{w: w, f: f}
	}

	var written int64
	var copyErr error
	if isSSE {
		// 流式：边转发边扫 usage，不缓存全文。
		// body 外面包一层，读到字节就喂一次看门狗 —— 于是「上游慢但活着」不会被误杀，
		// 「上游卡住不动」会在空闲上限处失败。
		body := io.Reader(resp.Body)
		if wd != nil {
			body = &activityReader{r: resp.Body, touch: wd.Touch}
		}
		written, copyErr = io.Copy(io.MultiWriter(dest, scanner), body)
	} else {
		var buf bytes.Buffer
		written, copyErr = io.Copy(&buf, resp.Body)
		if copyErr == nil {
			scanner.consumeJSON(buf.Bytes())
			_, _ = w.Write(buf.Bytes())
		}
	}
	_ = written

	rec.LatencyMs = time.Since(started).Milliseconds()
	rec.TTFTMs = scanner.TTFT()
	rec.PromptTokens = scanner.usage.PromptTokens
	rec.CompletionTokens = scanner.usage.CompletionTokens
	rec.TotalTokens = scanner.usage.TotalTokens
	rec.CacheHitTokens = scanner.usage.cacheHit
	rec.CacheMissTokens = scanner.usage.cacheMiss
	rec.OK = resp.StatusCode < 400 && copyErr == nil
	if copyErr != nil {
		if wd.Fired() {
			// 读操作被 Cancel 掉时报的是 context canceled，和「下游断开」长得一样；
			// 看门狗标记过就说明是空闲超时，归因要写清楚。
			rec.ErrorType = "upstream_idle"
			rec.ErrorMsg = fmt.Sprintf("上游 %s 连续 %s 没有返回数据（空闲超时）", rec.Provider, wd.Idle())
		} else {
			rec.ErrorType = "relay_error"
			rec.ErrorMsg = copyErr.Error()
		}
	}
	s.persist(rec)
}

// describeModels 汇总这组候选里可用声明的模型名，用于「模型不可用」时的报错提示。
func describeModels(providers []config.Provider) string {
	seen := map[string]bool{}
	var names []string
	anyCatchAll := false
	for _, p := range providers {
		if !p.Enabled {
			continue
		}
		if p.Models.Passthrough || p.Models.CatchAll {
			anyCatchAll = true
		}
		for name := range p.Models.Map {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	if anyCatchAll {
		return fmt.Sprintf("%s，另有供应商接受任意模型名（models 含 \"*\"）", strings.Join(names, ", "))
	}
	if len(names) == 0 {
		return "（无）"
	}
	return strings.Join(names, ", ")
}

func (s *Server) fail(w http.ResponseWriter, rec store.RequestRecord, status int, errType, msg string, attempts int, started time.Time) {
	rec.LatencyMs = time.Since(started).Milliseconds()
	rec.Attempts = attempts
	rec.StatusCode = status
	rec.OK = false
	rec.ErrorType = errType
	rec.ErrorMsg = truncateMsg(msg, 400)
	s.persist(&rec)
	s.log.Warnf("请求失败 id=%s model=%s status=%d type=%s msg=%s",
		rec.RequestID, rec.Model, status, errType, rec.ErrorMsg)
	writeJSONError(w, status, errType, msg)
}

func (s *Server) persist(rec *store.RequestRecord) {
	// 系统付费的消耗先进内存计数，再落库：万一落库失败，宁可让用户少用一点，
	// 也不要让他白用 —— 配额是网关主人自保的闸门。
	if s.meters != nil && rec.SystemPaid && rec.UserName != "" {
		s.meters.Add(rec.UserName, rec.UpstreamModel,
			int64Or0(rec.PromptTokens), rec.CacheHitTokens, rec.CacheMissTokens,
			int64Or0(rec.CompletionTokens), rec.Ts)
	}
	if s.db == nil {
		return
	}
	if err := s.db.InsertRequest(*rec); err != nil {
		s.log.Errorf("写入请求日志失败: %v", err)
	}
}

func int64Or0(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// ------------------------------------------------------------------ 工具

// rewriteModelBody 只替换 model 字段，必要时注入 stream_options.include_usage，
// 其余字段原样保留（用 json.RawMessage 避免数值精度被破坏）。
func rewriteModelBody(body []byte, upstreamModel string, stream bool) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("请求体不是 JSON 对象: %w", err)
	}
	quoted, err := json.Marshal(upstreamModel)
	if err != nil {
		return nil, err
	}
	m["model"] = quoted
	if stream {
		if _, ok := m["stream_options"]; !ok {
			// 注入 include_usage，这样流式响应末尾会带 token 统计
			m["stream_options"] = json.RawMessage(`{"include_usage":true}`)
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// retryableStatus 判断上游状态码是否值得换一个供应商重试。
func retryableStatus(code int) bool {
	switch {
	case code >= 500:
		return true
	case code == 408, code == 425, code == 429:
		return true
	case code == 401, code == 403:
		return true // 该供应商的密钥/权限有问题，换一家试
	case code == 404:
		return true // 可能只是这家没这个模型
	}
	return false
}

func isHopByHop(k string) bool {
	switch strings.ToLower(k) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailers", "transfer-encoding", "upgrade":
		return true
	}
	return false
}

// flushWriter 每写一块就 flush，保证 SSE 实时到达。
type flushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	fw.f.Flush()
	return n, err
}

// usageScanner 从响应中提取 usage 与 TTFT，**不保留任何内容**。
type usageScanner struct {
	start   time.Time
	ttft    time.Duration
	gotTTFT bool
	buf     []byte
	usage   struct {
		PromptTokens     *int64
		CompletionTokens *int64
		TotalTokens      *int64
		cacheHit         int64
		cacheMiss        int64
	}
}

func (u *usageScanner) Write(p []byte) (int, error) {
	if !u.gotTTFT && len(p) > 0 {
		u.ttft = time.Since(u.start)
		u.gotTTFT = true
	}
	u.buf = append(u.buf, p...)
	// 只处理完整的 data: 行；处理完立即丢弃，不累积全文
	for {
		i := bytes.IndexByte(u.buf, '\n')
		if i < 0 {
			// 防御：缓冲区异常增长时只保留尾部（usage 出现在流末尾）
			if len(u.buf) > 64*1024 {
				u.buf = u.buf[len(u.buf)-4096:]
			}
			break
		}
		line := u.buf[:i]
		u.buf = u.buf[i+1:]
		trimmed := bytes.TrimSpace(line)
		if !bytes.HasPrefix(trimmed, []byte("data:")) {
			continue
		}
		data := bytes.TrimSpace(trimmed[5:])
		if !bytes.Contains(data, []byte(`"usage"`)) {
			continue
		}
		var chunk struct {
			Usage *usageInfo `json:"usage"`
		}
		if err := json.Unmarshal(data, &chunk); err != nil || chunk.Usage == nil {
			continue
		}
		if chunk.Usage.PromptTokens != nil {
			u.usage.PromptTokens = chunk.Usage.PromptTokens
		}
		if chunk.Usage.CompletionTokens != nil {
			u.usage.CompletionTokens = chunk.Usage.CompletionTokens
		}
		if chunk.Usage.TotalTokens != nil {
			u.usage.TotalTokens = chunk.Usage.TotalTokens
		}
		if hit, miss, ok := chunk.Usage.cacheHitMiss(); ok {
			u.usage.cacheHit = hit
			u.usage.cacheMiss = miss
		}
	}
	return len(p), nil
}

func (u *usageScanner) consumeJSON(b []byte) {
	if u.gotTTFT && len(b) > 0 {
		// 非流式：TTFT 等价于完整响应到达
	} else if len(b) > 0 {
		u.ttft = time.Since(u.start)
		u.gotTTFT = true
	}
	if !bytes.Contains(b, []byte(`"usage"`)) {
		return
	}
	var obj struct {
		Usage *usageInfo `json:"usage"`
	}
	if err := json.Unmarshal(b, &obj); err != nil || obj.Usage == nil {
		return
	}
	if obj.Usage.PromptTokens != nil {
		u.usage.PromptTokens = obj.Usage.PromptTokens
	}
	if obj.Usage.CompletionTokens != nil {
		u.usage.CompletionTokens = obj.Usage.CompletionTokens
	}
	if obj.Usage.TotalTokens != nil {
		u.usage.TotalTokens = obj.Usage.TotalTokens
	}
	if hit, miss, ok := obj.Usage.cacheHitMiss(); ok {
		u.usage.cacheHit = hit
		u.usage.cacheMiss = miss
	}
}

func (u *usageScanner) TTFT() *int64 {
	if !u.gotTTFT {
		return nil
	}
	v := u.ttft.Milliseconds()
	return &v
}

func readSnippet(r io.Reader, n int) string {
	buf := make([]byte, n)
	read, _ := io.ReadFull(r, buf)
	out := strings.TrimSpace(string(buf[:read]))
	return truncateMsg(out, n)
}

func truncateMsg(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
