package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 正文交付那条 HTTP 边的用例（决策包 §8.1 的出网面）。
//
// 与检索那一份（http_test.go）同构，但多查三件正文方向独有的事：
//  1. 独立入口 —— 没配交付端点时必须一步都不出网，而检索那条链照旧工作；
//  2. 失败路径不得把响应字节变成错误文案（403 页面上常写着标题甚至片段）；
//  3. 解码/外壳不合格时必须返回**零值载荷**，不能让调用方接手一份已经躺着正文的半成品。

// deliveryPath 是测试里交付入口的路径名（与检索入口 /retrieve 分开，证明两条路各自独立）。
const deliveryPath = "/deliver"

// delivererFor 构造一个「检索 + 交付都指向同一个测试服务」的客户端。
func delivererFor(t *testing.T, srv *httptest.Server) *HTTPRetriever {
	t.Helper()
	client, err := NewHTTPRetriever(srv.URL+"/retrieve", TransportDo(srv.Client().Transport, 2*time.Second))
	if err != nil {
		t.Fatalf("构造 HTTP 委托客户端失败: %v", err)
	}
	client.DeliveryEndpoint = srv.URL + deliveryPath
	return client
}

// contentAskFor 按「准入一篇」装配一份可过协议校验的交付请求。
func contentAskFor(t *testing.T, bodies ...string) (ContentRequest, RequestContext, KnowledgeScope) {
	t.Helper()
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	admitted := make([]ReturnedDocument, 0, len(bodies))
	for i, body := range bodies {
		admitted = append(admitted, admittedWithBody(fmt.Sprintf("doc-%d", i+1), kbHandbook, policy.LevelInternal, body))
	}
	req, err := BuildContentRequest(rc, scope, admitted, DefaultContentPassages, DefaultContentBytes, now)
	if err != nil {
		t.Fatalf("装配交付请求失败: %v", err)
	}
	return req, rc, scope
}

// deliverHandler 是一台按申请回吐正文的知识源：摘要一律按交付字节重算（约定 2）。
func deliverHandler(status int, mediaType string, mutate func(*ContentResponse, ContentRequest)) http.HandlerFunc {
	return deliverHandlerNote(status, mediaType, nil, mutate)
}

// deliverHandlerNote 多一个记录钩子：请求体只能读一次，所以要观察「对端收到了什么」
// 与「回吐什么」必须写在同一个 handler 里（再读一次拿到的是空体，
// 于是协议字段全空，测出来的就不是网关的判定而是测试自己的装配错误）。
func deliverHandlerNote(status int, mediaType string,
	note func(*http.Request, ContentRequest),
	mutate func(*ContentResponse, ContentRequest)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var got ContentRequest
		if err := json.Unmarshal(body, &got); err != nil {
			return
		}
		if note != nil {
			note(r, got)
		}
		resp := ContentResponse{
			ProtocolVersion: ContentProtocolVersion,
			RequestID:       got.RequestID,
			AclVersion:      "example-acl@5",
			EvaluatedAt:     got.IssuedAt,
		}
		for i, ask := range got.Documents {
			text := fmt.Sprintf("第 %d 篇的正文", i+1)
			resp.Passages = append(resp.Passages, Passage{
				SourceID:      ask.SourceID,
				KnowledgeBase: ask.KnowledgeBase,
				Digest:        DigestString(text),
				DataLevel:     policy.LevelInternal.String(),
				RuleID:        "content-rule-" + ask.SourceID,
				AclVersion:    "example-acl@5",
				Verbatim:      []byte(text),
			})
		}
		if mutate != nil {
			mutate(&resp, got)
		}
		// 头必须在 WriteHeader 之前设：net/http 不会因为 body 是 JSON 就自动给媒体类型，
		// 少这一步就会把「网关按协议判」测成「网关被嗅探出来的 text/plain 判死」。
		if mediaType != "" {
			w.Header().Set("Content-Type", mediaType)
		} else {
			w.Header().Set("Content-Type", contentTypeJSON)
		}
		if status != 0 {
			w.WriteHeader(status)
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func retrievalReason(t *testing.T, err error) *RetrievalError {
	t.Helper()
	var re *RetrievalError
	if !errors.As(err, &re) {
		t.Fatalf("交付失败必须收敛成 *RetrievalError，实际 %T: %v", err, err)
	}
	return re
}

func TestHTTPDeliverContentHappyPath(t *testing.T) {
	var (
		hits atomic.Int64
		path atomic.Value
		hdr  atomic.Value
		echo atomic.Value
	)
	srv := newTestServer(t, deliverHandlerNote(0, "", func(r *http.Request, got ContentRequest) {
		hits.Add(1)
		path.Store(r.URL.Path)
		hdr.Store(r.Header.Clone())
		echo.Store(got)
	}, nil))
	client := delivererFor(t, srv)
	req, _, _ := contentAskFor(t, "无关", "无关")

	resp, err := client.DeliverContent(context.Background(), req)
	if err != nil {
		t.Fatalf("正常交付不应失败: %v", err)
	}
	if len(resp.Passages) != 2 {
		t.Fatalf("交付篇数不符: %+v", resp.Passages)
	}
	if resp.AclVersion != "example-acl@5" {
		t.Fatalf("源侧 ACL 世代没解出来: %s", resp.AclVersion)
	}
	if got := path.Load().(string); got != deliveryPath {
		t.Fatalf("交付请求走了检索入口: %s", got)
	}
	if hits.Load() != 1 {
		t.Fatalf("一次交付应当只发一个请求: %d", hits.Load())
	}

	sent := echo.Load().(ContentRequest)
	if sent.ProtocolVersion != ContentProtocolVersion || sent.Subject != subjectAlice || len(sent.Chain) == 0 {
		t.Fatalf("交付请求的身份字段必须与检索同形（源侧要自己判）: %+v", sent)
	}
	if len(sent.Documents) != 2 || sent.Documents[0].ExpectedDigest == "" {
		t.Fatalf("申请项必须带着准入摘要: %+v", sent.Documents)
	}
	headers := hdr.Load().(http.Header)
	if got := headers.Get("Content-Type"); got != contentTypeJSON {
		t.Fatalf("请求媒体类型: %q", got)
	}
	if got := headers.Get("Accept"); got != contentTypeJSON {
		t.Fatalf("请求 Accept: %q", got)
	}
	if got := headers.Get("X-Request-Id"); got != req.RequestID {
		t.Fatalf("请求 ID 没带上，链路对不上: %q", got)
	}
	// 凭证属于注入的 transport，不属于这个结构：这里必须一条 Authorization 都没有。
	if headers.Get("Authorization") != "" {
		t.Fatal("交付请求携带了 Authorization 头")
	}
}

// TestHTTPDeliverContentWithoutDeliveryEndpointIsFailClosed 钉死开关的那一面：
// 没配交付端点 = 这个源不做正文交付，一次都不许出网；同时检索那条链必须照旧可用
// ——这是 §8.1「开关关掉时现网行为逐字节相同」在客户端层的等价形式。
func TestHTTPDeliverContentWithoutDeliveryEndpointIsFailClosed(t *testing.T) {
	var hits atomic.Int64
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == deliveryPath {
			t.Errorf("没有配置交付端点却收到了交付请求")
		}
		echoHandler(nil, 0, contentTypeJSON)(w, r)
	})
	client := delivererFor(t, srv)
	client.DeliveryEndpoint = ""
	req, _, _ := contentAskFor(t, "A")

	if err := client.ValidateContent(); err == nil {
		t.Fatal("开关打开但没配端点时，启动校验必须报错")
	}
	before := hits.Load()
	resp, err := client.DeliverContent(context.Background(), req)
	if err == nil {
		t.Fatal("没有交付端点必须报错")
	}
	if len(resp.Passages) != 0 {
		t.Fatal("报错时不得返回半成品载荷")
	}
	if hits.Load() != before {
		t.Fatal("不得为交付发起任何请求")
	}
	// 检索方向完全不受影响。
	if err := client.Validate(); err != nil {
		t.Fatalf("检索侧配置仍然合法: %v", err)
	}
	searchReq := liveRequest(t, subjectAlice, orgExample, policy.LevelInternal, kbHandbook)
	if _, err := client.Retrieve(context.Background(), searchReq); err != nil {
		t.Fatalf("未配交付端点不该影响检索: %v", err)
	}
	if hits.Load() != before+1 {
		t.Fatalf("检索应当且仅当发过一次请求: %d", hits.Load()-before)
	}
}

func TestHTTPDeliverContentValidatesDeliveryEndpointShape(t *testing.T) {
	srv := newTestServer(t, deliverHandler(0, "", nil))
	req, _, _ := contentAskFor(t, "A")

	cases := []string{
		"ftp://example.invalid/deliver",
		"http://user:pass@example.invalid/deliver",
		"http://example.invalid/deliver?token=1",
		"http://example.invalid/deliver#frag",
		"example.invalid/deliver",
	}
	for _, raw := range cases {
		client := delivererFor(t, srv)
		client.DeliveryEndpoint = raw
		if err := client.ValidateContent(); !errors.Is(err, ErrEndpoint) {
			t.Fatalf("端点 %q 必须被拒（只许 http/https、禁凭证禁 query 禁 fragment），err=%v", raw, err)
		}
		if _, err := client.DeliverContent(context.Background(), req); err == nil {
			t.Fatalf("端点 %q 不合法时不得出网", raw)
		}
	}
}

// TestHTTPDeliverContentNon2xxDoesNotLeakResponseBody 是正文方向最要紧的一条：
// 知识源的 403 页面经常写着文档标题甚至正文片段。状态码可以进审计，字节一个都不许。
func TestHTTPDeliverContentNon2xxDoesNotLeakResponseBody(t *testing.T) {
	const sentinel = "ZZSENTINEL_ERRORPAGE_BODY"
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "<html>无权访问 "+sentinel+"</html>")
	})
	client := delivererFor(t, srv)
	req, _, _ := contentAskFor(t, "A")

	resp, err := client.DeliverContent(context.Background(), req)
	if err == nil {
		t.Fatal("非 2xx 必须失败（fail_closed）")
	}
	re := retrievalReason(t, err)
	if re.Reason != ReasonUpstreamStatus || re.StatusCode != http.StatusForbidden {
		t.Fatalf("原因码应为上游状态: %+v", re)
	}
	if len(resp.Passages) != 0 {
		t.Fatal("非 2xx 不得带出载荷")
	}
	for _, out := range []string{err.Error(), re.Detail, fmt.Sprintf("%+v", re)} {
		if strings.Contains(out, sentinel) {
			t.Fatalf("错误输出带出了响应体明文: %s", out)
		}
	}
}

func TestHTTPDeliverContentRejectsNonJSONResponse(t *testing.T) {
	req, _, _ := contentAskFor(t, "A")

	t.Run("媒体类型不是 application/json", func(t *testing.T) {
		// 中间代理把请求重定向到登录页时就是这个形态：状态 200、内容是 HTML。
		srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "<html>登录 ZZSENTINEL_LOGINPAGE</html>")
		})
		client := delivererFor(t, srv)
		resp, err := client.DeliverContent(context.Background(), req)
		if err == nil {
			t.Fatal("HTML 响应必须判协议不符")
		}
		if got := retrievalReason(t, err); got.Reason != ReasonContentProtocolInvalid {
			t.Fatalf("原因码应为交付协议不符: %+v", got)
		}
		if len(resp.Passages) != 0 || strings.Contains(err.Error(), "ZZSENTINEL") {
			t.Fatalf("不得留下载荷或带出内容: %+v %v", resp.Passages, err)
		}
	})

	t.Run("媒体类型头本身不合法", func(t *testing.T) {
		srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			// 手写一个无法解析的头值（Go 的 ResponseWriter 会原样带出）。
			w.Header()["Content-Type"] = []string{"not a media type !!"}
			_, _ = io.WriteString(w, "{}")
		})
		client := delivererFor(t, srv)
		if _, err := client.DeliverContent(context.Background(), req); err == nil {
			t.Fatal("头值解析失败必须报错，而不是当成 JSON 继续读")
		}
	})

	t.Run("响应不是合法协议 JSON", func(t *testing.T) {
		// 截断的 JSON：encoding/json 在报错前已经写入过完整的那一篇，
		// 所以这条路径必须返回零值载荷（本包那条清理义务的可观测形式）。
		srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentTypeJSON)
			_, _ = io.WriteString(w, `{"protocol_version":"`+ContentProtocolVersion+
				`","request_id":"req-u-alice","passages":[{"source_id":"doc-1","knowledge_base":"`+kbHandbook+
				`","digest":"`+DigestString("ZZSENTINEL_TRUNCATED")+`","data_level":"internal","rule_id":"r","verbatim":"ZZSENTINEL_TRUNCATED"`)
		})
		client := delivererFor(t, srv)
		resp, err := client.DeliverContent(context.Background(), req)
		if err == nil {
			t.Fatal("半截 JSON 必须报错")
		}
		if got := retrievalReason(t, err); got.Reason != ReasonContentProtocolInvalid {
			t.Fatalf("原因码应为交付协议不符: %+v", got)
		}
		if len(resp.Passages) != 0 || len(resp.RequestID) > 0 {
			t.Fatalf("解码失败必须返回零值载荷，不能把已解析的那一篇交回去: %+v", resp)
		}
		if strings.Contains(err.Error(), "ZZSENTINEL") {
			t.Fatalf("解码错误不得带出响应片段: %v", err)
		}
	})
}

// TestHTTPDeliverContentEnvelopeMismatchIsRejectedBeforeReturn 查客户端侧的外壳门槛：
// 串号响应与超预算响应都不能回到调用方手里，更不能把里面的正文带回去。
func TestHTTPDeliverContentEnvelopeMismatchIsRejectedBeforeReturn(t *testing.T) {
	req, _, _ := contentAskFor(t, "A", "B")

	t.Run("request_id 不符", func(t *testing.T) {
		srv := newTestServer(t, deliverHandler(0, "", func(resp *ContentResponse, _ ContentRequest) {
			resp.RequestID = "req-another-call"
		}))
		client := delivererFor(t, srv)
		resp, err := client.DeliverContent(context.Background(), req)
		if err == nil {
			t.Fatal("串号响应必须拒")
		}
		if got := retrievalReason(t, err); got.Reason != ReasonContentProtocolInvalid {
			t.Fatalf("原因码: %+v", got)
		}
		if len(resp.Passages) != 0 {
			t.Fatal("串号响应里的正文不得交回调用方")
		}
	})

	t.Run("超出预算", func(t *testing.T) {
		srv := newTestServer(t, deliverHandler(0, "", func(resp *ContentResponse, _ ContentRequest) {
			for i := range resp.Passages {
				resp.Passages[i].Verbatim = []byte(strings.Repeat("x", AbsoluteMaxPassageBytes))
				resp.Passages[i].Digest = Digest([]byte(resp.Passages[i].Verbatim))
			}
		}))
		client := delivererFor(t, srv)
		resp, err := client.DeliverContent(context.Background(), req)
		if err == nil {
			t.Fatal("超出字节预算的响应必须整份拒")
		}
		if got := retrievalReason(t, err); got.Reason != ReasonContentProtocolInvalid {
			t.Fatalf("原因码: %+v", got)
		}
		if len(resp.Passages) != 0 {
			t.Fatalf("整份拒时不得返回任何载荷: %d 篇", len(resp.Passages))
		}
	})

	t.Run("协议版本用了检索那套", func(t *testing.T) {
		srv := newTestServer(t, deliverHandler(0, "", func(resp *ContentResponse, _ ContentRequest) {
			resp.ProtocolVersion = ProtocolVersion
		}))
		client := delivererFor(t, srv)
		if _, err := client.DeliverContent(context.Background(), req); err == nil {
			t.Fatal("交付响应必须核对交付协议版本")
		}
	})
}

func TestHTTPDeliverContentResponseTooLarge(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentTypeJSON)
		// 远超客户端上限的无限流：不限体积读取会把网关内存吃穿，所以探测多读一个字节就判超。
		_, _ = io.WriteString(w, `{"protocol_version":"`+ContentProtocolVersion+`","request_id":"req-u-alice","passages":[`)
		_, _ = io.WriteString(w, `{"source_id":"doc-1","verbatim":"`+strings.Repeat("z", 4<<20)+`"`)
	})
	client := delivererFor(t, srv)
	req, _, _ := contentAskFor(t, "A")

	_, err := client.DeliverContent(context.Background(), req)
	if err == nil {
		t.Fatal("超限响应必须报错")
	}
	if got := retrievalReason(t, err); got.Reason != ReasonResponseTooLarge {
		t.Fatalf("原因码应为响应超限: %+v", got)
	}
}

// TestHTTPDeliverContentDoesNotEgressWithoutBudget 与 transport 缺失那条：
// 两条都不该把请求发出去 —— 出网之前先本地判完。
func TestHTTPDeliverContentDoesNotEgressWithoutBudget(t *testing.T) {
	var hits atomic.Int64
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		deliverHandler(0, "", nil)(w, r)
	})

	t.Run("剩余预算为零", func(t *testing.T) {
		client := delivererFor(t, srv)
		req, _, _ := contentAskFor(t, "A")
		req.Deadline = time.Now().Add(-time.Second)
		_, err := client.DeliverContent(context.Background(), req)
		if err == nil {
			t.Fatal("预算花完必须报错")
		}
		if got := retrievalReason(t, err); got.Reason != ReasonTimeout {
			t.Fatalf("原因码应为超时: %+v", got)
		}
		if hits.Load() != 0 {
			t.Fatal("预算耗尽时不得出网")
		}
	})

	t.Run("未注入 transport", func(t *testing.T) {
		client := delivererFor(t, srv)
		client.Do = TransportDo(nil, time.Second) // 禁止回落默认 transport 的那条
		req, _, _ := contentAskFor(t, "A")
		_, err := client.DeliverContent(context.Background(), req)
		if err == nil {
			t.Fatal("没有 transport 必须 fail_closed")
		}
		if got := retrievalReason(t, err); got.Reason != ReasonTransportNotConfigured {
			t.Fatalf("原因码应为未注入 transport: %+v", got)
		}
		if hits.Load() != 0 {
			t.Fatal("未注入 transport 时不得出网")
		}
	})
}

// TestHTTPDeliverContentFollowsNoRedirect 证明 3xx 不会被当成跳转：
// 被改写的 DNS 或反代配置不应该把正文请求引到白名单外的主机，
// 而审计里记的还是原来那个端点。
func TestHTTPDeliverContentFollowsNoRedirect(t *testing.T) {
	var redirected atomic.Int64
	target := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		deliverHandler(0, "", nil)(w, r)
	})
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+deliveryPath)
		w.WriteHeader(http.StatusFound)
	})
	client := delivererFor(t, srv)
	req, _, _ := contentAskFor(t, "A")

	_, err := client.DeliverContent(context.Background(), req)
	if err == nil {
		t.Fatal("3xx 必须按非 2xx 失败，而不是跟随")
	}
	if got := retrievalReason(t, err); got.Reason != ReasonUpstreamStatus || got.StatusCode != http.StatusFound {
		t.Fatalf("原因码应为上游状态 302: %+v", got)
	}
	if redirected.Load() != 0 {
		t.Fatal("跟随了重定向，出网白名单就被绕过了")
	}
}

// TestHTTPDeliverContentRejectsMalformedRequestBeforeEgress 查发出前的最后一道本地判：
// 版本串了、申请集合空了，都不许变成一次出网。
func TestHTTPDeliverContentRejectsMalformedRequestBeforeEgress(t *testing.T) {
	var hits atomic.Int64
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		deliverHandler(0, "", nil)(w, r)
	})
	client := delivererFor(t, srv)

	broken := func(mutate func(*ContentRequest)) ContentRequest {
		req, _, _ := contentAskFor(t, "A")
		mutate(&req)
		return req
	}
	cases := map[string]func(*ContentRequest){
		"检索版本号":        func(r *ContentRequest) { r.ProtocolVersion = ProtocolVersion },
		"空申请集合":        func(r *ContentRequest) { r.Documents = nil },
		"预算为 0（不等于不限）": func(r *ContentRequest) { r.MaxTotalBytes = 0 },
		"缺范围链":         func(r *ContentRequest) { r.Chain = nil },
	}
	for name, mutate := range cases {
		_, err := client.DeliverContent(context.Background(), broken(mutate))
		if err == nil {
			t.Fatalf("%s：不合法的交付请求必须被拒", name)
		}
		if got := retrievalReason(t, err); got.Reason != ReasonContentProtocolInvalid {
			t.Fatalf("%s：原因码应为交付协议不符: %+v", name, got)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("本地就该拒掉的请求一次都不该出网: %d", hits.Load())
	}
}

// TestHTTPDeliverContentsEndToEnd 把两层接起来跑一次：
// 网关的逐篇兜底必须对 HTTP 边同样生效（源侧换了内容就是整篇丢），
// 且审计里标注的 deliverer 是 http 而不是 fake。
func TestHTTPDeliverContentsEndToEnd(t *testing.T) {
	body := "会被换掉的那一篇"
	srv := newTestServer(t, deliverHandler(0, "", func(resp *ContentResponse, req ContentRequest) {
		// 源侧事后改写：摘要仍然报自己算的那份（与准入摘要不符）。
		for i := range resp.Passages {
			resp.Passages[i].Verbatim = []byte("源侧偷换了内容")
			resp.Passages[i].Digest = Digest([]byte("源侧偷换了内容"))
		}
	}))
	client := delivererFor(t, srv)

	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	admitted := []ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, body)}

	outcome, err := DeliverContents(context.Background(), client, rc, scope, admitted,
		DefaultContentPassages, DefaultContentBytes, now)
	if err != nil {
		t.Fatalf("逐篇丢弃不应升级成整份失败: %v", err)
	}
	if len(outcome.Passages) != 0 {
		t.Fatalf("摘要与准入不符的正文必须整篇丢弃: %+v", outcome.Passages)
	}
	if len(outcome.Dropped) != 1 || outcome.Dropped[0].Reason != ReasonContentDigestMismatch {
		t.Fatalf("丢弃原因码: %+v", outcome.Dropped)
	}
	if outcome.Audit.Deliverer != "http" {
		t.Fatalf("审计交付方应标注 http: %s", outcome.Audit.Deliverer)
	}
	if outcome.Audit.ResultCode != ReasonContentNone || outcome.Audit.DeliveredBytes != 0 {
		t.Fatalf("结果码与字节数不符: %+v", outcome.Audit)
	}
	if err := outcome.Audit.Validate(); err != nil {
		t.Fatalf("HTTP 边的审计形态: %v", err)
	}
	if strings.Contains(mustMarshal(t, outcome), "偷换了内容") || strings.Contains(mustMarshal(t, outcome), body) {
		t.Fatal("被丢弃的正文不得出现在 outcome 的序列化形态里")
	}
}

// TestHTTPDeliverContentsNeverReachAuditKeepsSearchChain 复核开关关掉那侧的兼容性：
// 只配检索端点的既有部署（DeliveryEndpoint 为空）在 Resolve 全链路上行为不变。
func TestHTTPDeliverContentsNeverReachAuditKeepsSearchChain(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == deliveryPath {
			t.Errorf("开关关着的部署不该有交付请求到达: %s", r.URL.Path)
		}
		echoHandler([]ReturnedDocument{docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg())}, 0, contentTypeJSON)(w, r)
	})
	client, err := NewHTTPRetriever(srv.URL+"/retrieve", TransportDo(srv.Client().Transport, 2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)

	outcome := mustResolve(t, client, rc, scope, Query{Terms: "报销"}, now)
	if len(outcome.Citations) != 1 {
		t.Fatalf("检索链必须照常工作: %+v", outcome.Citations)
	}
	// 同一次请求里申请正文：必须在出网之前就被拒（没有交付入口）。
	if _, err := DeliverContents(context.Background(), client, rc, scope,
		[]ReturnedDocument{docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg())},
		DefaultContentPassages, DefaultContentBytes, now); err == nil {
		t.Fatal("没有配置交付端点时正文交付必须失败，而不是降级成「用引用当正文」")
	}
	if strings.Contains(mustMarshal(t, outcome.Audit), "verbatim") {
		t.Fatal("检索审计里不该出现正文字段")
	}
}
