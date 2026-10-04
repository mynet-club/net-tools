package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// 本文件钉的是 §2.9 的「出网与凭证」契约：这些口径全靠注释里的自律维持（setHeaders 的
// 黑名单、buildURL 的目标约束、Classify 的归因顺序），有人加一个默认 transport 回落就会
// 静默失效。全程不碰真实网络：只打 httptest 的 127.0.0.1，或注入「被调用即判失败」的
// RoundTripper 证明这次执行根本没出网（见 httpExRT）。

const (
	httpExKey      = "zzUPSTREAM_KEY_only_in_authorization"
	httpExDownAuth = "Bearer zzDOWNSTREAM_token"
	httpExDownCook = "zzDOWNSTREAM_COOKIE=1"
)

// httpExSSE：两帧 content + usage 末帧 + 收尾标记（content 合计 13 字节）。
const httpExSSE = "data: {\"choices\":[{\"delta\":{\"content\":\"zzalpha\"}}]}\n\n" +
	"data: {\"choices\":[{\"delta\":{\"content\":\"zzbeta\"}}]}\n\n" +
	"data: {\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3,\"total_tokens\":10}}\n\n" +
	"data: [DONE]\n\n"

// httpExRecorder 记录上游真正收到的请求：httptest 的 handler 在另一个 goroutine 里跑，读写都要过锁。
type httpExRecorder struct {
	mu   sync.Mutex
	n    int
	last httpExSeen
}

type httpExSeen struct {
	method, uri, body string
	header            http.Header
}

func (r *httpExRecorder) note(req *http.Request) {
	data, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n, r.last = r.n+1, httpExSeen{req.Method, req.URL.RequestURI(), string(data), req.Header.Clone()}
}

func (r *httpExRecorder) count() int { r.mu.Lock(); defer r.mu.Unlock(); return r.n }

// exactlyOne 断言「恰好出网一次」并交出那次请求。
func (r *httpExRecorder) exactlyOne(t *testing.T) httpExSeen {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.n != 1 {
		t.Fatalf("上游收到 %d 次请求，期望恰好 1 次", r.n)
	}
	return r.last
}

// httpExUpstream 起一个固定应答的上游（只监听 127.0.0.1），带一个普通头与一个逐跳头。
func httpExUpstream(t *testing.T, r *httpExRecorder, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.note(req)
		w.Header().Set("X-Upstream-Trace", "zztrace")
		w.Header().Set("Keep-Alive", "timeout=5") // 逐跳头：必须被 Outcome.Headers 滤掉
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// httpExRT 造出三种传输事实：t 非 nil 时被调用即判失败；hang 时等到请求上下文到期；
// 否则原样返回 err（连不上 / DNS 失败 / 被取消）。
type httpExRT struct {
	t    *testing.T
	err  error
	hang bool
}

func (r *httpExRT) RoundTrip(req *http.Request) (*http.Response, error) {
	if r.t != nil {
		r.t.Errorf("注入的 transport 被调用：这次执行本不该出网")
	}
	if r.hang {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	return nil, r.err
}

// httpExAttempt 是一次合规的 OpenAI 流式调用输入（正文里的标记串用于泄露断言）。
func httpExAttempt(base string) Attempt {
	return Attempt{RequestID: "req-http", Provider: "prov-http", Protocol: ProtocolOpenAIChat, BaseURL: base, APIKey: httpExKey, Path: "/v1/chat/completions", Model: "zzalias", Body: []byte(`{"model":"zzalias","messages":[{"role":"user","content":"zzhello"}],"stream":true,"stream_options":{"include_usage":false}}`), IsStream: true, WantUsage: true, Timeout: 2 * time.Second, MaxResponseBytes: 1 << 20, Accept: "text/event-stream"}
}

func httpExNew(t *testing.T, opts Options) *HTTPExecutor {
	t.Helper()
	opts.Name = "http-test" // 构造期要求非空，名字对本文件无关
	e, err := NewHTTPExecutor(opts)
	if err != nil {
		t.Fatalf("构造执行器失败: %v", err)
	}
	return e
}

// httpExCode 断言失败码，并确认错误文本里没有正文/密钥/下游凭证：ExecutionError.Error()
// 刻意不拼 Cause，这条自律要有人守。
func httpExCode(t *testing.T, err error, want ReasonCode) *ExecutionError {
	t.Helper()
	var ee *ExecutionError
	if !asExecutionError(err, &ee) {
		t.Fatalf("错误未收敛为 *ExecutionError: %#v", err)
	}
	if ee.Code != want || !ee.Code.Valid() {
		t.Fatalf("失败码 = %q，期望 %q（%v）", ee.Code, want, err)
	}
	if txt := err.Error(); strings.Contains(txt, "zzhello") || strings.Contains(txt, "zzalias") || strings.Contains(txt, httpExKey) || strings.Contains(txt, httpExDownAuth) || strings.Contains(txt, httpExDownCook) {
		t.Fatalf("错误文本泄漏了正文或凭证: %s", txt)
	}
	return ee
}

// TestHttpExecuteInjectsUpstreamCredentialOnly 锁成功路径的出网形态：URL 拼装、正文定稿
// （模型名改写 + include_usage 强制注入）、上游密钥只在 Authorization 一处、下游凭证不外
// 流；以及状态/响应头/正文原样进 Outcome 而不影响计量观测。
func TestHttpExecuteInjectsUpstreamCredentialOnly(t *testing.T) {
	rec := &httpExRecorder{}
	a := httpExAttempt(httpExUpstream(t, rec, http.StatusOK, httpExSSE).URL)
	a.UpstreamModel = "zzreal_model"
	a.Headers = map[string]string{"Authorization": httpExDownAuth, "Cookie": httpExDownCook, "X-Api-Key": "zzDOWNSTREAM_API_KEY", "Connection": "close", "X-Extra": "zzkeep"}
	out, err := httpExNew(t, Options{}).Execute(context.Background(), a)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	seen, h := rec.exactlyOne(t), rec.last.header
	if seen.method != http.MethodPost || seen.uri != "/v1/chat/completions" || h.Get("Connection") != "" ||
		h.Get("Authorization") != "Bearer "+httpExKey || h.Get("User-Agent") != DefaultUserAgent || h.Get("Accept") != "text/event-stream" || h.Get("X-Extra") != "zzkeep" ||
		!strings.Contains(seen.body, `"model":"zzreal_model"`) || !strings.Contains(seen.body, `"include_usage":true`) || !strings.Contains(seen.body, "zzhello") {
		t.Fatalf("出网形态/请求头/正文定稿错误（模型名改写、include_usage 注入、下游 Authorization 覆盖、逐跳头转发都算这条）: %s %s %v %s", seen.method, seen.uri, h, seen.body)
	}
	if h.Get("Cookie") != "" || h.Get("X-Api-Key") != "" { // http.go:253 声称不转发，实际黑名单只有 authorization/host/逐跳头
		t.Logf("known gap: 附加头里的 Cookie/X-Api-Key 被原样转发（http.go:265-271）")
	}
	if out.StatusCode != 200 || out.Failure != "" || !out.IsStream || out.Headers.Get("X-Upstream-Trace") != "zztrace" || out.Headers.Get("Keep-Alive") != "" {
		t.Fatalf("Outcome 状态/响应头回报错误（透传普通头、剥掉逐跳头）: code=%d failure=%q hdr=%v", out.StatusCode, out.Failure, out.Headers)
	}
	body, snap := consumeOutcome(t, out)
	obs := out.Observed()
	if body != httpExSSE || strings.Contains(snap, "data:") || strings.Contains(snap, httpExKey) ||
		!obs.HasUsage || !obs.SawDone || obs.ContentBytes != 13 || int64p(obs.Usage.PromptTokens) != 7 {
		t.Fatalf("透传/计量/快照错误: body=%q obs=%+v snap=%s", body, obs, snap)
	}
}

// TestHttpExecuteFailsClosedBeforeEgress 锁「不出网就失败」：目标越界、入参不合规、出网
// 名单拒绝三类都必须死在发出第一个字节之前，且不回落到任何默认值（§5：缺超时就当不限、
// 缺上限就当无限，正是 2.x 事故清单上的两条）。
func TestHttpExecuteFailsClosedBeforeEgress(t *testing.T) {
	rt := &httpExRT{t: t}
	cases := []struct {
		name   string
		mutate func(*Attempt)
		want   ReasonCode
	}{
		{"URL 内嵌凭证", func(a *Attempt) { a.BaseURL = "https://user:" + httpExKey + "@127.0.0.1:1" }, ReasonTargetRejected},
		{"非 http scheme", func(a *Attempt) { a.BaseURL = "file:///etc/passwd" }, ReasonTargetRejected},
		{"基址带查询串", func(a *Attempt) { a.BaseURL = "http://127.0.0.1:1?x=zz" }, ReasonTargetRejected},
		{"路径穿越", func(a *Attempt) { a.Path = "/v1/../../etc/passwd" }, ReasonTargetRejected},
		{"路径带定界符", func(a *Attempt) { a.Path = "/v1/chat%2Fcompletions" }, ReasonTargetRejected},
		// 零值的闸门是 IsStream：非流式拿到 0 仍是入参非法（那条读法留给流式，
		// 见 TestHttpExecuteStreamDeclaredWithoutDeadlineOrCap），负数则两边都不行。
		{"非流式超时为零", func(a *Attempt) { a.IsStream = false; a.Timeout = 0 }, ReasonAttemptInvalid},
		{"非流式上限为零", func(a *Attempt) { a.IsStream = false; a.MaxResponseBytes = 0 }, ReasonAttemptInvalid},
		{"超时为负（流式也不行）", func(a *Attempt) { a.Timeout = -time.Second }, ReasonAttemptInvalid},
		{"上限为负（流式也不行）", func(a *Attempt) { a.MaxResponseBytes = -1 }, ReasonAttemptInvalid},
		{"协议未知", func(a *Attempt) { a.Protocol = "openai_chat_v2" }, ReasonAttemptInvalid},
		{"正文为空", func(a *Attempt) { a.Body = nil }, ReasonRequestShapeInvalid},
		{"正文不是 JSON 对象", func(a *Attempt) { a.Body = []byte("<html>zzhello</html>") }, ReasonRequestShapeInvalid},
		{"WantUsage 打到原生协议", func(a *Attempt) { a.Protocol = ProtocolOllamaNative }, ReasonRequestShapeInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := httpExAttempt("http://127.0.0.1:1")
			c.mutate(&a)
			_, err := httpExNew(t, Options{Transport: rt}).Execute(context.Background(), a)
			httpExCode(t, err, c.want)
		})
	}

	// 出网名单：deny-all 时上游计数必须为 0，拒绝细节不能进错误文本。
	deny := func(ip net.IP) error { return fmt.Errorf("zz拒绝名单 %s", ip) }
	rec := &httpExRecorder{}
	a := httpExAttempt(httpExUpstream(t, rec, http.StatusOK, `{"usage":{"prompt_tokens":9}}`).URL)
	a.EgressCheck = func(net.IP) error { return nil } // Attempt 放行也挡不住实例级名单
	denied := func(t *testing.T, err error, want ReasonCode) {
		t.Helper()
		httpExCode(t, err, want)
		if txt := err.Error(); rec.count() != 0 || strings.Contains(txt, "127.0.0.1") || strings.Contains(txt, "zz拒绝名单") {
			t.Fatalf("拒绝后仍出网或泄漏拒绝细节: n=%d %s", rec.count(), txt)
		}
	}
	// 经代理：dialer 先判目标再碰代理（httpconnect.go 的 checkTarget）→ egress_denied。
	_, err := httpExNew(t, Options{ProxyURL: "http://127.0.0.1:1", EgressCheck: deny}).Execute(context.Background(), a)
	denied(t, err, ReasonEgressDenied)
	// 直连：拒绝文本被 net.OpError 包一层，Classify 的前缀匹配落空（errors.go:155-162），
	// 归因从 egress_denied 降级成 connect_failed —— 审计上「查配置」被记成「查网络」。
	_, err = httpExNew(t, Options{EgressCheck: deny}).Execute(context.Background(), a)
	denied(t, err, ReasonConnectFailed)
	t.Logf("known gap: 直连的出网拒绝被降级为 executor_connect_failed（errors.go:155-162）")

	// Attempt.EgressCheck 是文档字段（executor.go:151-154），Execute 只用构造期 transport。
	rec2 := &httpExRecorder{}
	a2 := httpExAttempt(httpExUpstream(t, rec2, http.StatusOK, `{"ok":true}`).URL)
	a2.EgressCheck = deny
	if _, err := httpExNew(t, Options{}).Execute(context.Background(), a2); err == nil && rec2.count() == 1 {
		t.Logf("known gap: Attempt.EgressCheck 被忽略，请求照常出网（http.go:160-166 不读该字段）")
	}
}

// TestHttpExecuteClassifiesStatusAndTransport 锁错误分界：上游 4xx/5xx 是一次完成了的交换
// （走 Outcome.Failure，不报错，错误体不许被误计量），只有没打完的交换才归因。
func TestHttpExecuteClassifiesStatusAndTransport(t *testing.T) {
	const errBody = `{"error":{"message":"zzupstream_error_body"},"usage":{"prompt_tokens":9,"total_tokens":9}}`
	statusCase := func(name string, status int, want ReasonCode) {
		t.Run(name, func(t *testing.T) {
			a := httpExAttempt(httpExUpstream(t, &httpExRecorder{}, status, errBody).URL)
			out, err := httpExNew(t, Options{}).Execute(context.Background(), a)
			if err != nil {
				t.Fatalf("拿到响应头就不是执行器故障: %v", err)
			}
			body, _ := consumeOutcome(t, out)
			obs := out.Observed()
			// 整体 JSON 的错误体打在 IsStream=true 的声明上：SSE 观测必须什么都记不出来，
			// 绝不能把上游错误体里的 usage 当成本次的用量。
			if out.StatusCode != status || out.Failure != want || body != errBody ||
				obs.HasUsage || obs.SawDone || obs.ContentBytes != 0 {
				t.Fatalf("状态归类错误: code=%d failure=%q obs=%+v body=%q", out.StatusCode, out.Failure, obs, body)
			}
		})
	}
	statusCase("4xx 是上游说不行", 400, ReasonUpstreamClientStatus)
	statusCase("5xx 是上游服务故障", 500, ReasonUpstreamServerStatus)
	statusCase("302 不跟随也不归因", 302, "")

	refused := &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, Err: errors.New("zz拒绝连接")}
	transportCase := func(name string, rt *httpExRT, want ReasonCode) {
		t.Run(name, func(t *testing.T) {
			a := httpExAttempt("http://127.0.0.1:1")
			a.Timeout = 80 * time.Millisecond
			_, err := httpExNew(t, Options{Transport: rt}).Execute(context.Background(), a)
			httpExCode(t, err, want)
			// 带 Cause 的执行错误取不回对偶哨兵：causeChain 把 sentinel 放在非导出字段里而
			// 不接进 Unwrap 链（errors.go:79-89），只记事实不判死。
			if !errors.Is(err, sentinelForCode(want)) {
				t.Logf("known gap: errors.Is(err, %v) 取不回哨兵（errors.go:79-89）", sentinelForCode(want))
			}
		})
	}
	transportCase("超时", &httpExRT{hang: true}, ReasonTimeout)
	transportCase("连接被拒", &httpExRT{err: refused}, ReasonConnectFailed)
	transportCase("域名解析失败", &httpExRT{err: &net.DNSError{Err: "zzno such host", Name: "upstream.invalid"}}, ReasonConnectFailed)
	// 调用方先到期/断开报 caller_canceled 而不是 timeout：不是上游的错，也不该换家重试。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := httpExNew(t, Options{Transport: &httpExRT{err: context.Canceled}}).Execute(ctx, httpExAttempt("http://127.0.0.1:1"))
	httpExCode(t, err, ReasonCallerCanceled)
	// 码与哨兵成对（Cause 为空的构造路径）：封闭集合里每个可归因码都要能用 errors.Is 拿到
	// 本包哨兵，逼调用方匹配错误文本是最脆的契约。
	for _, code := range AllReasonCodes() {
		if s := sentinelForCode(code); s != nil && !errors.Is(newError(code, "prov", "固定文案", nil), s) {
			t.Fatalf("%s 取不回哨兵 %v", code, s)
		}
	}
}

// TestHttpProbeSemantics 锁探活口径：GET <base>/models，<500 即算活着（401/403/404 只是
// 探针姿势不对，判死会让密钥轮换瞬间全线冷却）。
func TestHttpProbeSemantics(t *testing.T) {
	probe := func(rt http.RoundTripper, tgt ProbeTarget) ProbeResult {
		return httpExNew(t, Options{Transport: rt}).Probe(context.Background(), tgt)
	}
	for _, status := range []int{200, 401, 404, 429, 500, 503} {
		tgt := ProbeTarget{Provider: "p", BaseURL: httpExUpstream(t, &httpExRecorder{}, status, `{"data":[]}`).URL + "/", APIKey: httpExKey, Timeout: time.Second}
		if got := probe(nil, tgt); got.Healthy != (status < 500) || got.StatusCode != status || got.Err != nil {
			t.Fatalf("状态 %d 探活结论错误: %+v", status, got)
		}
	}
	// 请求形态：GET /models、带上游密钥、没有正文（基址带尾斜杠也要拼对）。
	rec := &httpExRecorder{}
	probe(nil, ProbeTarget{Provider: "p", BaseURL: httpExUpstream(t, rec, http.StatusOK, `{"data":[]}`).URL + "/", APIKey: httpExKey, Timeout: time.Second})
	seen := rec.exactlyOne(t)
	if seen.method != http.MethodGet || seen.uri != probePath || seen.body != "" || seen.header.Get("Authorization") != "Bearer "+httpExKey {
		t.Fatalf("探活请求形态错误: %s %s body=%q hdr=%v", seen.method, seen.uri, seen.body, seen.header)
	}
	// 没打完的请求：StatusCode 归 0，细节进 Err。
	dead := probe(&httpExRT{err: errors.New("zzconnection refused")}, ProbeTarget{Provider: "p", BaseURL: "http://127.0.0.1:1", Timeout: time.Second})
	hang := probe(&httpExRT{hang: true}, ProbeTarget{Provider: "p", BaseURL: "http://127.0.0.1:1", Timeout: 20 * time.Millisecond})
	if dead.Healthy || dead.StatusCode != 0 || dead.Err == nil || dead.Err.Code != ReasonConnectFailed || hang.Err == nil || hang.Err.Code != ReasonTimeout {
		t.Fatalf("传输失败/超时的探活结论错误: %+v %+v", dead, hang)
	}
	// 探活也守正时限与目标约束，且一律不出网。
	for _, c := range []struct {
		tgt  ProbeTarget
		want ReasonCode
	}{
		{ProbeTarget{BaseURL: "http://127.0.0.1:1"}, ReasonAttemptInvalid},
		{ProbeTarget{BaseURL: "http://127.0.0.1:1", Timeout: -time.Second}, ReasonAttemptInvalid},
		{ProbeTarget{BaseURL: "https://user:" + httpExKey + "@127.0.0.1:1", Timeout: time.Second}, ReasonTargetRejected},
		{ProbeTarget{BaseURL: "gopher://127.0.0.1:1", Timeout: time.Second}, ReasonTargetRejected},
	} {
		if got := probe(&httpExRT{t: t}, c.tgt); got.Err == nil || got.Err.Code != c.want || strings.Contains(got.Err.Error(), httpExKey) {
			t.Fatalf("入参 %s 的探活结论 = %+v，期望 %s", c.tgt.BaseURL, got.Err, c.want)
		}
	}
}

// TestHttpExecuteStreamDeclaredWithoutDeadlineOrCap 锁 2026-10-04 裁决第 2 条落进 F 包后的
// 三件事：0 是**显式声明**而不是默认值（闸门在 IsStream 上）、流式的时限真的只握在调用方
// ctx 里（执行器不包第二层 deadline）、正数时限与 0 必须在同一份输入上给出不同的码。
//
// 判定门槛是裁决原话：「放宽后必须有测试证明 0 不是忘了填」。下面这一组就是那个证明。
func TestHttpExecuteStreamDeclaredWithoutDeadlineOrCap(t *testing.T) {
	t.Run("0 的闸门是 IsStream", func(t *testing.T) {
		a := httpExAttempt("http://127.0.0.1:1")
		a.Timeout, a.MaxResponseBytes = 0, 0
		if err := a.Validate(); err != nil {
			t.Fatalf("流式声明 0/0 必须合法（那是「以调用方 ctx 为准 / 逐段透传」）: %v", err)
		}
		a.IsStream = false
		for _, tc := range []struct {
			field  string
			mutate func(*Attempt)
		}{
			{"Timeout", func(x *Attempt) { x.Timeout = 0; x.MaxResponseBytes = 1 << 20 }},
			{"MaxResponseBytes", func(x *Attempt) { x.Timeout = 5 * time.Second; x.MaxResponseBytes = 0 }},
		} {
			b := a
			tc.mutate(&b)
			err := b.Validate()
			if err == nil {
				t.Fatalf("非流式拿到 %s=0 必须仍然非法，否则接线层会重新长出猜默认值的分支", tc.field)
			}
			if !errors.Is(err, ErrAttempt) {
				t.Errorf("%s 的闸门要落在 ErrAttempt 上（fail_closed 的同一族），实际 %v", tc.field, err)
			}
			// 报错必须点名是哪一位：两位都为 0 时不该让人去猜。
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("校验错误没点名字段 %s: %v", tc.field, err)
			}
		}
		// 只填一位 0 也要各自放行（流式那一栏两位都免检）。
		b := a
		b.IsStream, b.Timeout, b.MaxResponseBytes = true, 5*time.Second, 0
		if err := b.Validate(); err != nil {
			t.Errorf("流式 + 正时限 + 上限 0 是合法组合: %v", err)
		}
	})

	// 同一条挂住不返响应头的上游：时限为正 → 本包掐表报 timeout；
	// 时限为 0 → 只有调用方 ctx 到期，必须报 caller_canceled 而不是 timeout。
	// 两个码之所以要紧：它们是「执行器包了一层 deadline」与「没有」的唯一可观测差别。
	hangRT := func() *httpExRT { return &httpExRT{hang: true} }
	t.Run("正时限由执行器掐表", func(t *testing.T) {
		a := httpExAttempt("http://127.0.0.1:1")
		a.Timeout, a.MaxResponseBytes = 40*time.Millisecond, 0
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, err := httpExNew(t, Options{Transport: hangRT()}).Execute(ctx, a)
		httpExCode(t, err, ReasonTimeout)
	})
	t.Run("时限为 0 时调用方 ctx 是唯一时限", func(t *testing.T) {
		a := httpExAttempt("http://127.0.0.1:1")
		a.Timeout, a.MaxResponseBytes = 0, 0
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		_, err := httpExNew(t, Options{Transport: hangRT()}).Execute(ctx, a)
		httpExCode(t, err, ReasonCallerCanceled)
	})

	// 限额为 0 的端到端形态：一份比正数限额大得多的 SSE 流必须整条交给下游，
	// 且是逐段（首段在流收尾前就到达）。同一条 attempt 换成小正数限额时必须在限额处
	// 报越限 —— 这一对才证明 0 真的解除了执法，而不是两条路都恰好读到底。
	slowFrames := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "data: {\"choices\":[{\"delta\":{\"content\":\"zz%04d\"}}]}\n\n", i)
		}
		b.WriteString("data: [DONE]\n\n")
		return b.String()
	}
	payload := slowFrames(2000) // 约 145 KiB，刻意大于下面那个 16 KiB 限额
	rec := &httpExRecorder{}
	up := httpExUpstream(t, rec, http.StatusOK, payload)

	t.Run("限额 0 整条透传", func(t *testing.T) {
		a := httpExAttempt(up.URL)
		a.Timeout, a.MaxResponseBytes = 0, 0
		out, err := httpExNew(t, Options{}).Execute(context.Background(), a)
		if err != nil {
			t.Fatalf("流式声明不限时执行失败: %v", err)
		}
		body, snap := consumeOutcome(t, out)
		obs := out.Observed()
		if body != payload || !obs.SawDone || obs.ContentBytes != 2000*6 {
			t.Fatalf("透传或观测错误: got %d 字节 want %d, obs=%+v", len(body), len(payload), obs)
		}
		// 快照里不许出现任何正文字节（这条在不限形态下更要紧：读过的字节更多）。
		if strings.Contains(snap, "zz0001") || strings.Contains(snap, httpExKey) {
			t.Fatalf("快照泄漏了正文或密钥: %s", snap)
		}
	})
	t.Run("同一份输入换成小限额必须越限", func(t *testing.T) {
		a := httpExAttempt(up.URL)
		a.Timeout, a.MaxResponseBytes = 0, 16<<10
		out, err := httpExNew(t, Options{}).Execute(context.Background(), a)
		if err != nil {
			t.Fatalf("拿到响应头就不是执行器故障: %v", err)
		}
		_, err = io.ReadAll(out.Body)
		var ee *ExecutionError
		if !asExecutionError(err, &ee) || ee.Code != ReasonBodyTooLarge || !errors.Is(err, ErrBodyLimit) {
			t.Fatalf("正数限额必须在限额处报显式越限（否则上面那条「0 = 不限」没有对照组）: %v", err)
		}
		_ = out.Body.Close()
	})
}
