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
	// cached_tokens 是**命中**的那部分，未命中要自己从 prompt_tokens 里减出来；
	// cache_write_tokens 是**写入**缓存的那部分（第三档，单价常高于未命中）。
	// 只认上面两个字段的话，这类上游的命中会被记成 0 —— 于是命中率凭空消失，
	// 金额又按「全部未命中」被高估。
	PromptTokensDetails *struct {
		CachedTokens     *int64 `json:"cached_tokens"`
		CacheWriteTokens *int64 `json:"cache_write_tokens"`
	} `json:"prompt_tokens_details"`
}

// usageCache 是一次请求的输入缓存拆分（三档）。
type usageCache struct {
	hit   int64 // 命中缓存
	write int64 // 写入缓存
	miss  int64 // 既没命中也没写入
	ok    bool  // 上游是否报了缓存信息；false 时由调用方按「全部未命中」保守处理
}

// cacheSplit 把两套字段归一化成三档，ok=false 表示上游压根没报。
//
// 显式的 hit/miss（DeepSeek 风格）优先；只有 cached_tokens 时，命中 = cached，
// 未命中 = prompt_tokens - cached - write。负数一律夹成 0：上游报的数字不可全信，
// 让它们进到金额里比丢掉更糟。
func (u *usageInfo) cacheSplit() usageCache {
	if u == nil {
		return usageCache{}
	}
	clamp := func(v int64) int64 {
		if v < 0 {
			return 0
		}
		return v
	}
	var write int64
	if u.PromptTokensDetails != nil && u.PromptTokensDetails.CacheWriteTokens != nil {
		write = clamp(*u.PromptTokensDetails.CacheWriteTokens)
	}
	if u.PromptCacheHitTokens != nil || u.PromptCacheMissTokens != nil {
		c := usageCache{write: write, ok: true}
		if u.PromptCacheHitTokens != nil {
			c.hit = clamp(*u.PromptCacheHitTokens)
		}
		if u.PromptCacheMissTokens != nil {
			c.miss = clamp(*u.PromptCacheMissTokens)
		}
		return c
	}
	if u.PromptTokensDetails != nil && u.PromptTokensDetails.CachedTokens != nil && u.PromptTokens != nil {
		c := usageCache{write: write, ok: true}
		c.hit = clamp(*u.PromptTokensDetails.CachedTokens)
		if c.hit > *u.PromptTokens {
			c.hit = *u.PromptTokens // cached 比 prompt 还大只可能是上游算错，夹住
		}
		c.miss = *u.PromptTokens - c.hit - write
		if c.miss < 0 {
			c.miss = 0
		}
		return c
	}
	return usageCache{}
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

	// 用户级限流与配额：限流不依赖请求体，先判，省得白读一遍 body。
	// 限流对两种模式都生效（单个用户打满网关跟模式无关）。
	// **配额不在这里判** —— 它只约束「花网关的钱」，而混合模式下同一个模型可能有
	// 自有上游在承接（用户自己结算）。要等模型解析完、知道有没有自有候选之后再判，
	// 否则「额度用完」会连他自己的上游一起挡住。见下面 providersFor 之后那一段。
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

	// 上游池：消费模式要按「这个模型映射到哪个上游」来收窄，所以必须等 model 到手。
	// 混合模式下这个池子可能同时含自有上游（用户自己付费）与系统池（网关付费），
	// 所以这里给的是「池里有没有系统候选」的初值，**最终账按实际落地的候选定**
	// （见循环里 cand 选中处的赋值）—— 否则自有上游命中却记成网关付费就是记错账。
	providers, poolHasSystem := s.providersFor(scope, probe.Model)
	rec.SystemPaid = poolHasSystem

	// 配额只约束「花网关的钱」：池子里有自有候选（会优先被选中）时放行 ——
	// 那是用户自己的上游，没理由拿网关的额度卡他。自有层全被排除后回落到系统池
	// 才会真的花网关的钱，那种情况配额是软限制（见 README 三条语义）。
	if e := s.usersSnapshot().byName[scope]; e != nil && e.Consumption && !poolHasOwn(providers) {
		if _, _, exceeded, msg := s.meters.CheckQuota(e.Name, e.QuotaMonthTokens, e.QuotaMonthCost); exceeded {
			s.fail(w, rec, http.StatusPaymentRequired, "quota_exceeded", msg, 0, started)
			return
		}
	}
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
	affinityPrefer := ""
	if affinityOn {
		affinitySession = r.Header.Get("X-Session-Affinity")
		affinityPrefer = s.affinity.Get(scope, affinitySession, probe.Model) // 头为空时返回 ""
	}
	// 规则 B：没有粘性可用时（新会话，或粘性那家已不适用）按**当前上游价**挑最便宜的。
	// 挑不出来就留空、回落到按权重随机 —— 没录价目时行为与以前完全一致。
	prefer := affinityPrefer
	if prefer == "" {
		prefer = s.cheapestProvider(scope, providers, probe.Model)
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

		// 这次实际会花谁的钱：候选自带归属（自有上游 = 用户自己的，系统池 = 网关掏）。
		// 放在这里而不是等成功 —— 失败路径也要按「最后试的那家」归类，
		// 它们共用同一个 rec，落在哪家就记哪家的账。
		rec.SystemPaid = cand.Provider.SystemPaid

		// 观测：告诉调用方这次是按粘性选的（sticky）还是漂移过来的（drift），
		// 或者本来就没粘性记录（new）。排障与上线验证都要看这一列。
		if affinityOn && affinitySession != "" {
			outcome := "new" // 既没粘性也没价目 → 按权重随机
			switch {
			case affinityPrefer != "" && cand.Provider.Name == affinityPrefer:
				outcome = "sticky" // 规则 A：沿用这个会话上次那家
			case affinityPrefer != "":
				outcome = "drift" // 粘性那家不能用，漂移了
			case prefer != "":
				outcome = "cheapest" // 规则 B：新会话按价格挑的
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
			} else if r.Context().Err() != nil {
				// 客户端已经断开。这不是供应商的错，也**不该再换一家重试** ——
				// 重试只会白打一次上游、再给第二家记一笔莫须有的失败。
				//
				// 这条很要紧：failure_threshold 默认是 3，几个爱掐连接的客户端就能把
				// 一家健康上游打进冷却。看门狗取消的是派生出的 ctx、不是 r.Context()，
				// 所以这个判断只会命中「真的是客户端走了」。
				//
				// 499 沿用 nginx 对「客户端主动断开」的记法；客户端已经走了，
				// 这个状态码只进库和日志，不会真的发出去。
				s.log.Infof("客户端在上游响应前断开 ip=%s model=%s provider=%s",
					auth.ClientIP, probe.Model, cand.Provider.Name)
				rec.Provider = cand.Provider.Name
				rec.UpstreamModel = cand.UpstreamModel
				s.fail(w, rec, 499, "client_gone", "客户端在上游返回前断开", attempts, started)
				return
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
			if resp.StatusCode == http.StatusPaymentRequired || resp.StatusCode == http.StatusTooManyRequests {
				// 额度不足 / 被限流：这是**明确**的信号，一次就该让这家让位 ——
				// 攒够失败次数再冷却太慢，规则 B 会一遍遍把请求送到已经没额度的家。
				s.router.CoolFor(scope, cand.Provider.Name, ruleBQuotaCooldown)
				s.log.Warnf("供应商 %s 返回 %d，压 %s 冷却（规则 B 下次改用次便宜的）",
					cand.Provider.Name, resp.StatusCode, ruleBQuotaCooldown)
			}
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
		rec.Provider = cand.Provider.Name
		rec.UpstreamModel = cand.UpstreamModel
		rec.Attempts = attempts
		rec.StatusCode = resp.StatusCode

		outcome := func() relayOutcome {
			defer cancel()
			return s.relay(w, r, resp, &rec, started, wd)
		}()

		// 熔断要等 relay 的结果再记：一家「返回 200 响应头、然后卡死不吐字节」的供应商，
		// 正是空闲看门狗专门为它设计的那种故障。在读到 body 之前就报成功的话，
		// 它会被永久判为健康 —— 看门狗掐掉它、库里记成 upstream_idle，router 却毫不知情。
		if outcome == relayOK {
			s.router.ReportSuccessFor(scope, cand.Provider.Name)
		} else if outcome == relayUpstreamFailed {
			s.router.ReportFailureFor(scope, cand.Provider.Name,
				fmt.Errorf("上游在响应中途失败：%s", rec.ErrorMsg))
		}

		// 记录/更新粘性，同样看 relay 的结果。只有真正跑完的响应才钉住这家；
		// 非重试类 4xx（比如这家在配置里声明了这个名字、上游其实不认）与流中途失败
		// 都说明「这家用不了」—— 忘掉粘性让下一个请求重新选。这条很要紧：
		// 这两种情况都不足以立刻熔断，不忘掉的话会话会被钉在一家只会报错的后端上死循环。
		if affinitySession != "" {
			if outcome == relayOK && resp.StatusCode < 400 {
				s.affinity.Set(scope, affinitySession, probe.Model, cand.Provider.Name)
			} else {
				s.affinity.Set(scope, affinitySession, probe.Model, "")
			}
		}
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

// relayOutcome 是 relay 的结果，用来决定熔断计数与会话粘性怎么记。
//
// 为什么不在 relay 内部直接调 router：relay 手上只有 rec，而熔断是按
// (作用域, 供应商) 分桶的，作用域来自鉴权结果、不等于 rec.UserName（静态 key
// 两者都为空，但语义不同）。把决策留给调用方，省得在这里猜。
type relayOutcome int

const (
	relayOK             relayOutcome = iota // 干净跑完
	relayUpstreamFailed                     // 上游的问题（空闲超时）：该记一次失败
	relayClientGone                         // 下游断开：不是供应商的错，成败都不记
	relayAmbiguous                          // 归因不明：不记失败（见 relay 里的说明）
)

// maxUpstreamResponseBytes 是**非流式**上游响应体在内存里的缓冲上限。
//
// 下游的请求体有 http.MaxBytesReader 管着，上游的响应体却曾经完全没限 ——
// 于是一个 BYO 用户把 base_url 指向一个返回超大（或无限慢）响应的非 SSE 端点，
// 一次请求就能把网关的内存吃光。上限取得很宽松：正常的 LLM JSON 响应远小于它
// （32 MB 的补全已经荒谬），撞上就说明对面不是个正常的上游。
// 流式路径不受影响 —— 它边收边转发、不缓存全文。
const maxUpstreamResponseBytes = 32 << 20

// writeBadGateway 在**还没发过状态码**时把这次转发改判成 502。
//
// 上游的 Content-Type / Content-Length 必须先清掉，否则会与这个 JSON 错误体不符 ——
// 客户端按上游声明的长度去读，读出来就是一坨残缺 JSON，比一个干净的 502 更难排障。
func writeBadGateway(w http.ResponseWriter, msg string) {
	w.Header().Del("Content-Type")
	w.Header().Del("Content-Length")
	writeJSONError(w, http.StatusBadGateway, "upstream_error", msg)
}

// relay 把上游响应原样写给下游；同时提取 usage / TTFT 元数据。
func (s *Server) relay(w http.ResponseWriter, r *http.Request, resp *http.Response, rec *store.RequestRecord, started time.Time, wd *idleWatchdog) relayOutcome {
	defer resp.Body.Close()

	// 复制响应头（跳过 hop-by-hop）。
	//
	// WriteHeader 刻意**不在这里**调用：非流式要先把 body 读完才知道该发什么状态码。
	// 先发 200 再发现读失败的话，客户端只能收到一个 200 + 截断 body，
	// 分不清「模型返回了空补全」和「代理挂了」。
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

	contentType := resp.Header.Get("Content-Type")
	isSSE := strings.Contains(contentType, "text/event-stream")

	scanner := &usageScanner{start: started}
	var dest io.Writer = w
	if f, ok := w.(http.Flusher); ok && isSSE {
		dest = &flushWriter{w: w, f: f}
	}

	var written int64
	var copyErr error
	outcome := relayOK
	if isSSE {
		w.WriteHeader(resp.StatusCode)
		// 流式：边转发边扫 usage，不缓存全文。
		// body 外面包一层，读到字节就喂一次看门狗 —— 于是「上游慢但活着」不会被误杀，
		// 「上游卡住不动」会在空闲上限处失败。
		body := io.Reader(resp.Body)
		if wd != nil {
			body = &activityReader{r: resp.Body, touch: wd.Touch}
		}
		// scanner 必须排在 dest 前面：MultiWriter 在任一 writer 出错时就停止、
		// 不再写后面的，而 usage chunk 恰恰在流的末尾。反过来的话，客户端在
		// 收到 usage 之前断开（网络抖动，或者故意掐这个时机）就会拿到完整答案
		// 而记账为 0 —— 上游那边 token 已经生成、钱已经付了。
		// scanner.Write 恒返回 (len(p), nil)，放前面绝不会截断给客户端的数据。
		written, copyErr = io.Copy(io.MultiWriter(scanner, dest), body)
	} else {
		// 非流式：先读完、再发状态码，并且**有上限**（见 maxUpstreamResponseBytes）。
		// LimitReader 读满 n 字节且不报错就代表「可能还有更多」，据此判截断。
		var buf bytes.Buffer
		written, copyErr = io.Copy(&buf, io.LimitReader(resp.Body, maxUpstreamResponseBytes))
		switch {
		case copyErr != nil:
			// 读上游就失败了：还没发过任何状态码，可以干净地改判 502
			rec.ErrorType = "upstream_body"
			rec.ErrorMsg = fmt.Sprintf("读上游响应失败：%v", copyErr)
			outcome = relayUpstreamFailed
			writeBadGateway(w, rec.ErrorMsg)
		case buf.Len() >= maxUpstreamResponseBytes:
			rec.ErrorType = "upstream_body"
			rec.ErrorMsg = fmt.Sprintf("上游响应超过 %d MB 上限，已拒绝缓冲", maxUpstreamResponseBytes>>20)
			// copyErr 必须置上：rec.OK 是 `StatusCode < 400 && copyErr == nil` 算出来的，
			// 而这时上游的状态码是 200 —— 不置就会把一次拒收记成成功请求。
			copyErr = errors.New(rec.ErrorMsg)
			outcome = relayUpstreamFailed
			writeBadGateway(w, rec.ErrorMsg)
		default:
			scanner.consumeJSON(buf.Bytes())
			w.WriteHeader(resp.StatusCode)
			if _, werr := w.Write(buf.Bytes()); werr != nil {
				// 头已经发出去了，改判不了；只记下来。写不进去多半是下游断开。
				copyErr = werr
			}
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
	rec.CacheWriteTokens = scanner.usage.cacheWrite
	rec.OK = resp.StatusCode < 400 && copyErr == nil

	if copyErr != nil && rec.ErrorType == "" {
		switch {
		case wd.Fired():
			// 读操作被 Cancel 掉时报的是 context canceled，和「下游断开」长得一样；
			// 看门狗标记过就说明是空闲超时，归因要写清楚。
			rec.ErrorType = "upstream_idle"
			rec.ErrorMsg = fmt.Sprintf("上游 %s 连续 %s 没有返回数据（空闲超时）", rec.Provider, wd.Idle())
			outcome = relayUpstreamFailed
		case r.Context().Err() != nil:
			// 下游主动断开：不是供应商的错。既不该记它失败（否则一个爱掐连接的客户端
			// 就能把一家好上游打进冷却），也不该记成功。
			rec.ErrorType = "client_gone"
			rec.ErrorMsg = "客户端在响应结束前断开"
			outcome = relayClientGone
		default:
			// 归因不明：可能是读上游出错，也可能是写下游出错（MultiWriter 把两边
			// 的错误合成了一个）。分不清就不赖供应商 —— 宁可漏记一次失败，
			// 也不要因为下游的破网络把好上游打进冷却。
			rec.ErrorType = "relay_error"
			rec.ErrorMsg = copyErr.Error()
			outcome = relayAmbiguous
		}
	}

	// 计价冻结：按**请求开始时刻**生效的价目行把成本/收费算好写死（见 freeze.go）。
	// 上游成本（我们付供应商多少）与分发金额（我们向用户收多少）分别冻结、各自带价目行 id。
	s.freezeUpstreamCost(rec, started)
	s.freezeDownstreamCharge(rec, started)
	s.persist(rec)
	return outcome
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
			int64Or0(rec.CompletionTokens), rec.Ts, rec.Charge)
	}
	if s.db == nil {
		return
	}
	if err := s.db.InsertRequest(*rec); err != nil {
		// 请求已经成功返回给客户端了，这笔账却永久丢了 —— 计数器 + 日志双管齐下，
		// 因为只写日志的话没人盯着就永远发现不了（详见 Server.persistFailures 的注释）。
		n := s.persistFailures.Add(1)
		s.log.Errorf("写入请求日志失败（累计 %d 次，账在丢，请查磁盘空间与库锁）: %v", n, err)
	}
}

func int64Or0(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// ------------------------------------------------------------------ 工具

// rewriteModelBody 只替换 model 字段，流式时强制打开 stream_options.include_usage，
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
		m["stream_options"] = withIncludeUsage(m["stream_options"])
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// withIncludeUsage 强制打开 stream_options.include_usage，同时保留客户端的其他子字段。
//
// 不能只在键缺失时才注入：客户端自带 stream_options（哪怕写的是 include_usage:false，
// 或者只是某个我们认不出的方言字段）就会把注入整个跳过 —— 上游于是不回报 usage，
// 这条请求的 token 与金额全部记 0、配额一分不扣，而上游照样向我们收钱。
// 计量是网关自己的需求，不该由下游客户端决定，所以这里一律覆盖 include_usage。
func withIncludeUsage(raw json.RawMessage) json.RawMessage {
	only := json.RawMessage(`{"include_usage":true}`)
	var opts map[string]json.RawMessage
	// raw 缺失（nil）、是 null、不是对象、或解析不了时，整个换成我们要的形状
	if err := json.Unmarshal(raw, &opts); err != nil || opts == nil {
		return only
	}
	opts["include_usage"] = json.RawMessage(`true`)
	out, err := json.Marshal(opts)
	if err != nil {
		return only
	}
	return out
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
	case code == 402:
		return true // 额度/余额不足：换一家试，并给这家记一段冷却（见下面的 CoolFor）
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
		cacheWrite       int64
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
		if c := chunk.Usage.cacheSplit(); c.ok {
			u.usage.cacheHit, u.usage.cacheMiss, u.usage.cacheWrite = c.hit, c.miss, c.write
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
	if c := obj.Usage.cacheSplit(); c.ok {
		u.usage.cacheHit, u.usage.cacheMiss, u.usage.cacheWrite = c.hit, c.miss, c.write
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
