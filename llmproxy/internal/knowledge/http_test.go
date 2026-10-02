package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// liveRequest 装配一份「真实时钟有效」的委托请求（原因见 resolve_test.go 的 liveContext）。
func liveRequest(t *testing.T, subject, org string, level policy.DataLevel, kbs ...string) RetrieveRequest {
	t.Helper()
	rc, now := liveContext(t, subject, org, level)
	scope := mustScope(t, rc.Chain, level, kbs...)
	req, err := BuildRequest(rc, scope, Query{Terms: "报销"}, now)
	if err != nil {
		t.Fatalf("装配委托请求失败: %v", err)
	}
	return req
}

// newTestServer 起本地测试服务（手册 §6：测试不许打真实网络）。
func newTestServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// retrieverFor 构造指向该服务的委托客户端（transport 由测试注入，验证注入路径本身可用）。
func retrieverFor(t *testing.T, srv *httptest.Server) *HTTPRetriever {
	t.Helper()
	client, err := NewHTTPRetriever(srv.URL+"/retrieve", TransportDo(srv.Client().Transport, 2*time.Second))
	if err != nil {
		t.Fatalf("构造 HTTP 委托客户端失败: %v", err)
	}
	return client
}

// echoHandler 是最省事的知识源：按请求里的白名单回吐给定文档。
func echoHandler(docs []ReturnedDocument, status int, mediaType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var got RetrieveRequest
		_ = json.Unmarshal(body, &got)
		resp := RetrieveResponse{
			ProtocolVersion: ProtocolVersion,
			RequestID:       got.RequestID,
			AclVersion:      "example-acl@5",
			EvaluatedAt:     got.IssuedAt,
			Documents:       docs,
		}
		if status != 0 {
			w.WriteHeader(status)
		}
		if mediaType != "" {
			w.Header().Set("Content-Type", mediaType)
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func TestHTTPRetrieverHappyPath(t *testing.T) {
	var (
		mu       sync.Mutex
		gotReqs  []RetrieveRequest
		headers  []http.Header
		intoPath []string
	)
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var got RetrieveRequest
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("知识侧收到的请求不是合法协议 JSON: %v", err)
		}
		mu.Lock()
		gotReqs = append(gotReqs, got)
		headers = append(headers, r.Header.Clone())
		intoPath = append(intoPath, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", contentTypeJSON)
		_ = json.NewEncoder(w).Encode(RetrieveResponse{
			ProtocolVersion: ProtocolVersion,
			RequestID:       got.RequestID,
			AclVersion:      "example-acl@5",
			ExpiresAt:       got.Deadline.Add(time.Minute),
			Documents: []ReturnedDocument{
				docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg()),
			},
		})
	})
	client := retrieverFor(t, srv)
	req := liveRequest(t, subjectAlice, orgExample, policy.LevelInternal, kbHandbook)

	resp, err := client.Retrieve(context.Background(), req)
	if err != nil {
		t.Fatalf("正常检索不应失败: %v", err)
	}
	if err := resp.Validate(req); err != nil {
		t.Fatalf("响应应为合法协议: %v", err)
	}
	if len(resp.Documents) != 1 || resp.Documents[0].SourceID != "doc-1" {
		t.Fatalf("响应内容不正确: %+v", resp.Documents)
	}
	if resp.AclVersion != "example-acl@5" {
		t.Fatalf("源侧 ACL 世代没解出来: %s", resp.AclVersion)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(gotReqs) != 1 || gotReqs[0].Subject != subjectAlice || len(gotReqs[0].Chain) == 0 {
		t.Fatalf("对端应收到完整鉴权上下文: %+v", gotReqs)
	}
	if gotReqs[0].PolicyVersion != policyVersionV1 {
		t.Fatal("策略版本必须过线传递")
	}
	if gotReqs[0].BudgetMS <= 0 || gotReqs[0].Deadline.IsZero() {
		t.Fatal("时间预算必须过线传递，源侧才有限时依据")
	}
	if gotReqs[0].SearchTerms != "" {
		t.Fatal("未授权时不得把检索词原文发过线")
	}
	h := headers[0]
	if got := h.Get("Content-Type"); !strings.HasPrefix(got, contentTypeJSON) {
		t.Fatalf("请求体类型应为 JSON，实际 %q", got)
	}
	if h.Get("X-Request-Id") != req.RequestID {
		t.Fatal("必须带请求 ID 做链路关联（它不含内容与凭证）")
	}
	if h.Get("Authorization") != "" {
		t.Fatal("本包不得携带凭证：认证属于注入的 transport 层")
	}
	if intoPath[0] != "/retrieve" {
		t.Fatalf("入口路径不正确: %s", intoPath[0])
	}
}

func TestHTTPRetrieverNon2xxIsFailClosed(t *testing.T) {
	// 知识源的 403 页面常带文档标题甚至片段：状态码可以进日志，响应体不行。
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentTypeJSON)
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"forbidden","hint":"`+secretBody+`"}`)
	})
	client := retrieverFor(t, srv)
	req := liveRequest(t, subjectAlice, orgExample, policy.LevelInternal, kbHandbook)

	resp, err := client.Retrieve(context.Background(), req)
	if err == nil {
		t.Fatal("非 2xx 必须失败，不能当成「没有可读文档」")
	}
	if len(resp.Documents) != 0 {
		t.Fatal("失败时不得带出任何文档")
	}
	var re *RetrievalError
	if !errors.As(err, &re) {
		t.Fatalf("错误必须是带稳定码的 RetrievalError，实际 %T", err)
	}
	if re.Reason != ReasonUpstreamStatus || re.StatusCode != http.StatusForbidden {
		t.Fatalf("应报上游状态码，实际 %+v", re)
	}
	assertNoLeak(t, "非2xx错误信息", err.Error())
	if !IsFailClosed(err) {
		t.Fatal("非 2xx 必须按不可读处理")
	}
}

func TestHTTPRetrieverRedirectIsNotFollowed(t *testing.T) {
	// 端点由管理员固定配置。跟随 3xx 等于让被改写的 DNS 或反向代理
	// 把请求带到出网白名单之外，而审计里记的还是原来那个端点。
	var escaped int32
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/elsewhere") {
			atomic.AddInt32(&escaped, 1)
			_, _ = io.WriteString(w, `{"documents":[{"source_id":"doc-secret"}]}`)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	client := retrieverFor(t, srv)
	req := liveRequest(t, subjectAlice, orgExample, policy.LevelInternal, kbHandbook)

	_, err := client.Retrieve(context.Background(), req)
	if err == nil {
		t.Fatal("3xx 必须判失败")
	}
	if atomic.LoadInt32(&escaped) != 0 {
		t.Fatal("客户端跟随了重定向，出网目标脱离了管理员配置")
	}
	var re *RetrievalError
	if !errors.As(err, &re) || re.StatusCode != http.StatusFound {
		t.Fatalf("应把 302 原样报出来，实际 %+v", err)
	}
}

func TestHTTPRetrieverBodyOverLimit(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var got RetrieveRequest
		_ = json.Unmarshal(body, &got)
		w.Header().Set("Content-Type", contentTypeJSON)
		// 体积远超上限：知识源被攻陷或返回错误页时的形状
		_, _ = io.WriteString(w, `{"protocol_version":"`+ProtocolVersion+`","request_id":"`+got.RequestID+
			`","documents":[{"digest":"`+strings.Repeat("a", 4096)+`"}]`)
	})
	client := retrieverFor(t, srv)
	client.MaxResponseBytes = 512
	req := liveRequest(t, subjectAlice, orgExample, policy.LevelInternal, kbHandbook)

	_, err := client.Retrieve(context.Background(), req)
	if err == nil {
		t.Fatal("响应体超限必须失败")
	}
	var re *RetrievalError
	if !errors.As(err, &re) || re.Reason != ReasonResponseTooLarge {
		t.Fatalf("应报响应超限，实际 %+v", err)
	}
	if strings.Contains(err.Error(), strings.Repeat("a", 100)) {
		t.Fatal("错误信息里不得带出响应内容")
	}
	assertNoLeak(t, "超限错误信息", err.Error())
}

func TestHTTPRetrieverProtocolViolations(t *testing.T) {
	req := liveRequest(t, subjectAlice, orgExample, policy.LevelInternal, kbHandbook)

	t.Run("响应不是合法 JSON", func(t *testing.T) {
		srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentTypeJSON)
			_, _ = io.WriteString(w, `{"protocol_version": `+secretBody)
		})
		_, err := retrieverFor(t, srv).Retrieve(context.Background(), req)
		assertProtocolFailure(t, err, "响应不是合法协议 JSON")
	})

	t.Run("响应类型是 HTML 登录页", func(t *testing.T) {
		srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, "<html>请重新登录 "+secretTitle+"</html>")
		})
		_, err := retrieverFor(t, srv).Retrieve(context.Background(), req)
		assertProtocolFailure(t, err, "响应不是 application/json")
	})

	t.Run("缺媒体类型头", func(t *testing.T) {
		srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{}`)
		})
		_, err := retrieverFor(t, srv).Retrieve(context.Background(), req)
		assertProtocolFailure(t, err, "响应不是 application/json")
	})

	t.Run("非法媒体类型头不得回显原值", func(t *testing.T) {
		srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/="+secretBody)
			_, _ = io.WriteString(w, `{}`)
		})
		_, err := retrieverFor(t, srv).Retrieve(context.Background(), req)
		assertProtocolFailure(t, err, "媒体类型头不合法")
		assertNoLeak(t, "媒体类型错误", err.Error())
	})

	t.Run("响应 request_id 串号", func(t *testing.T) {
		srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentTypeJSON)
			_ = json.NewEncoder(w).Encode(RetrieveResponse{
				ProtocolVersion: ProtocolVersion,
				RequestID:       "req-别人的请求",
				Documents:       []ReturnedDocument{docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg())},
			})
		})
		_, err := retrieverFor(t, srv).Retrieve(context.Background(), req)
		assertProtocolFailure(t, err, "响应外壳校验失败")
	})

	t.Run("响应文档条数超硬上限", func(t *testing.T) {
		docs := make([]ReturnedDocument, 0, maxProtocolDocs+1)
		for i := 0; i <= maxProtocolDocs; i++ {
			docs = append(docs, docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg()))
		}
		srv := newTestServer(t, echoHandler(docs, 0, contentTypeJSON))
		_, err := retrieverFor(t, srv).Retrieve(context.Background(), req)
		assertProtocolFailure(t, err, "响应外壳校验失败")
	})

	t.Run("请求本身不合规", func(t *testing.T) {
		srv := newTestServer(t, echoHandler(nil, 0, contentTypeJSON))
		broken := req
		broken.KnowledgeBases = nil
		_, err := retrieverFor(t, srv).Retrieve(context.Background(), broken)
		assertProtocolFailure(t, err, "请求字段不符")
	})
}

func TestHTTPRetrieverTimeoutWithinBudget(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
		_, _ = io.WriteString(w, "{}")
	})

	t.Run("上下文预算切断", func(t *testing.T) {
		rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
		rc, err := rc.WithDeadline(now.Add(30*time.Millisecond), now)
		if err != nil {
			t.Fatal(err)
		}
		scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
		req, err := BuildRequest(rc, scope, Query{}, now)
		if err != nil {
			t.Fatal(err)
		}
		client := retrieverFor(t, srv)
		started := time.Now()
		_, err = client.Retrieve(context.Background(), req)
		if err == nil {
			t.Fatal("超过剩余预算必须失败")
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("没有被 30ms 预算切断，实际等了 %s", elapsed)
		}
		var re *RetrievalError
		if !errors.As(err, &re) || (re.Reason != ReasonTimeout && re.Reason != ReasonCancelled) {
			t.Fatalf("超时应映射成稳定码，实际 %+v", err)
		}
	})

	t.Run("兜底预算切断", func(t *testing.T) {
		// 请求本身有 3 秒预算，但客户端的 FallbackBudget 更短：
		// 「对端 deadline 写多长都不该让本地请求无限存活」这条要能单独测。
		client := retrieverFor(t, srv)
		client.FallbackBudget = 30 * time.Millisecond
		req := liveRequest(t, subjectAlice, orgExample, policy.LevelInternal, kbHandbook)
		started := time.Now()
		_, err := client.Retrieve(context.Background(), req)
		if err == nil {
			t.Fatal("兜底预算到点必须失败")
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("兜底预算未生效，实际等了 %s", elapsed)
		}
		var re *RetrievalError
		if !errors.As(err, &re) || re.Reason != ReasonTimeout {
			t.Fatalf("应报超时，实际 %+v", err)
		}
	})
}

func TestHTTPRetrieverRefusesMissingTransport(t *testing.T) {
	req := liveRequest(t, subjectAlice, orgExample, policy.LevelInternal, kbHandbook)

	if _, err := NewHTTPRetriever("http://example.internal/retrieve", nil); err == nil {
		t.Fatal("未注入 Do 函数必须在构造期就报错，而不是等到第一次检索")
	} else if !errors.Is(err, ErrNoTransport) {
		t.Fatalf("应报 ErrNoTransport，实际 %v", err)
	}

	// transport 为 nil 时不得回落到 http.DefaultTransport（那是绕过出网策略的快捷路径）
	do := TransportDo(nil, time.Second)
	if do == nil {
		t.Fatal("TransportDo 必须始终返回可用函数")
	}
	client, err := NewHTTPRetriever("http://example.internal/retrieve", do)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Retrieve(context.Background(), req)
	var re *RetrievalError
	if !errors.As(err, &re) || re.Reason != ReasonTransportNotConfigured {
		t.Fatalf("未注入 transport 应报稳定码并 fail_closed，实际 %+v", err)
	}

	// 手改字段把 Do 摘掉也要被 Validate 拦住
	manual := &HTTPRetriever{Endpoint: "http://example.internal/retrieve", MaxResponseBytes: DefaultMaxResponseBytes}
	if err := manual.Validate(); err == nil {
		t.Fatal("Validate 必须拒绝没有 Do 的客户端")
	}
}

func TestHTTPRetrieverEndpointValidation(t *testing.T) {
	do := TransportDo(&http.Transport{}, time.Second)
	cases := map[string]string{
		"空端点":        "",
		"非 HTTP 协议":  "socks5://example.internal:1080",
		"URL 内嵌凭证":   "https://user:pass@example.internal/retrieve",
		"带查询串":       "https://example.internal/retrieve?debug=1",
		"带 fragment": "https://example.internal/retrieve#frag",
		"缺主机名":       "http:///retrieve",
	}
	for name, endpoint := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewHTTPRetriever(endpoint, do); err == nil {
				t.Fatalf("必须拒绝端点 %q", endpoint)
			} else if !errors.Is(err, ErrEndpoint) {
				t.Fatalf("应报 ErrEndpoint，实际 %v", err)
			}
		})
	}
	// 正常端点：路径保留、空白归一化
	client, err := NewHTTPRetriever("  https://kb.example.internal/v1/retrieve  ", do)
	if err != nil {
		t.Fatal(err)
	}
	if client.Endpoint != "https://kb.example.internal/v1/retrieve" {
		t.Fatalf("端点归一化不正确: %s", client.Endpoint)
	}
}

func TestHTTPRetrieverEndToEndStaysFailClosed(t *testing.T) {
	// 知识源「实现不完整」的形状：把邻组织文档和白名单外的库文档一并返回，
	// 还带着正文形状的字段。端到端必须一个都不留。
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var got RetrieveRequest
		_ = json.Unmarshal(body, &got)
		w.Header().Set("Content-Type", contentTypeJSON)
		_ = json.NewEncoder(w).Encode(RetrieveResponse{
			ProtocolVersion: ProtocolVersion,
			RequestID:       got.RequestID,
			AclVersion:      "example-acl@9",
			Documents: []ReturnedDocument{
				docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg()),
				docForFilter("doc-9", kbHandbook, policy.LevelInternal, policy.MustScope(policy.ScopeOrganization, orgRival)),
				docForFilter("doc-7", kbRivalLab, policy.LevelPublic, ownerOrg()),
				func() ReturnedDocument {
					leaky := docForFilter("doc-3", kbHR, policy.LevelRestricted, ownerOrg())
					leaky.Digest = DigestString(secretBody)
					leaky.TitleDigest = TitleDigest(secretTitle)
					return leaky
				}(),
			},
		})
	})
	client := retrieverFor(t, srv)
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)

	outcome, err := Resolve(context.Background(), client, rc, scope, Query{Terms: "报销"}, now)
	if err != nil {
		t.Fatalf("部分文档被丢弃不是失败: %v", err)
	}
	if len(outcome.Citations) != 1 || outcome.Citations[0].SourceID != "doc-1" {
		t.Fatalf("跨组织/跨库/超分级的返回项必须被兜底丢弃: %+v", outcome.Citations)
	}
	// 端到端不泄露：错误、审计、序列化结果都过一遍
	assertNoLeak(t, "引用集合", citeDump(t, outcome.Citations))
	assertNoLeak(t, "审计一行", outcome.Audit.String())
	blob, err := json.Marshal(outcome.Audit)
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeak(t, "审计 JSON", string(blob))
	if outcome.Audit.ResultCode != ReasonOK {
		t.Fatalf("仍有一篇可读时结果码应是 %s，实际 %s", ReasonOK, outcome.Audit.ResultCode)
	}
}

func TestHTTPRetrieverSendsRawTermsOnlyWhenGranted(t *testing.T) {
	var received []RetrieveRequest
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var got RetrieveRequest
		_ = json.Unmarshal(body, &got)
		received = append(received, got)
		w.Header().Set("Content-Type", contentTypeJSON)
		_ = json.NewEncoder(w).Encode(RetrieveResponse{ProtocolVersion: ProtocolVersion, RequestID: got.RequestID})
	})
	client := retrieverFor(t, srv)
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)

	req, err := BuildRequest(rc, scope, Query{Terms: secretBody}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Retrieve(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	grant, err := BuildRequest(rc, scope, Query{Terms: secretBody, AllowRawTerms: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Retrieve(context.Background(), grant); err != nil {
		t.Fatal(err)
	}

	if len(received) != 2 {
		t.Fatalf("应收到两次请求，实际 %d", len(received))
	}
	if received[0].SearchTerms != "" {
		t.Fatal("未授权时原文检索词不得过线")
	}
	if received[1].SearchTerms != secretBody || !received[1].AllowRawTerms {
		t.Fatal("显式授权时必须把原文与标志一起传过去")
	}
	// 两次都必须带摘要：审计关联不依赖原文是否发送
	if received[0].QueryDigest != req.QueryDigest || received[1].QueryDigest != grant.QueryDigest {
		t.Fatal("检索词摘要必须原样送达")
	}
}

func TestHTTPRetrieverIsReusableUnderConcurrency(t *testing.T) {
	var served int32
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&served, 1)
		body, _ := io.ReadAll(r.Body)
		var got RetrieveRequest
		_ = json.Unmarshal(body, &got)
		w.Header().Set("Content-Type", contentTypeJSON)
		_ = json.NewEncoder(w).Encode(RetrieveResponse{
			ProtocolVersion: ProtocolVersion,
			RequestID:       got.RequestID,
			EvaluatedAt:     got.IssuedAt,
			Documents: []ReturnedDocument{
				docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg()),
			},
		})
	})
	client := retrieverFor(t, srv)
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)

	const workers = 12
	var wg sync.WaitGroup
	problems := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outcome, err := Resolve(context.Background(), client, rc, scope, Query{Terms: "报销"}, now)
			switch {
			case err != nil:
				problems <- "并发检索失败: " + err.Error()
			case len(outcome.Citations) != 1:
				problems <- "并发下引用被串改"
			}
		}()
	}
	wg.Wait()
	close(problems)
	for msg := range problems {
		t.Fatal(msg)
	}
	if got := atomic.LoadInt32(&served); got != workers {
		t.Fatalf("每次并发检索都应过线一次，实际 %d", got)
	}
}

func assertProtocolFailure(t *testing.T, err error, wantDetail string) {
	t.Helper()
	if err == nil {
		t.Fatalf("必须失败：%s", wantDetail)
	}
	var re *RetrievalError
	if !errors.As(err, &re) {
		t.Fatalf("错误必须是 RetrievalError，实际 %T: %v", err, err)
	}
	if re.Reason != ReasonProtocolInvalid {
		t.Fatalf("应报 %s，实际 %+v", ReasonProtocolInvalid, re)
	}
	if !strings.Contains(re.Detail, wantDetail) {
		t.Fatalf("Detail 应含 %q，实际 %q", wantDetail, re.Detail)
	}
	assertNoLeak(t, "协议错误", err.Error())
}

// citeDump 把引用集合序列化成一串（泄露断言用）。
func citeDump(t *testing.T, in []Citation) string {
	t.Helper()
	blob, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	return string(blob)
}
