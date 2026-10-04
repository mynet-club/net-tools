package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// liveContext 用**真实时钟**作签发时间构造上下文。
//
// 为什么这里不能用基线时间 baseNow：Resolve 会把 rc.Deadline 变成真实的
// context 超时（超时语义只能吃墙钟），拿一个历史时刻当签发时间会「一出发就过期」，
// 测到的是 fixture 的钟走慢了，而不是逻辑对不对。
// 分级/过期这类**判定**用例仍走 baseNow（见 filter_test.go、delegation_test.go），
// 那些路径完全不碰墙钟。
func liveContext(t *testing.T, subject, org string, level policy.DataLevel) (RequestContext, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	rc, err := NewRequestContext("req-"+subject, subject, chainOf(t, subject, org, projExample), "qa", level, policyVersionV1, now)
	if err != nil {
		t.Fatalf("构造检索上下文失败: %v", err)
	}
	return rc, now
}

// mustResolve 走一次检索委托并在意外失败时直接终止用例。
func mustResolve(t *testing.T, r DelegatedRetriever, rc RequestContext, scope KnowledgeScope, q Query, now time.Time) *Outcome {
	t.Helper()
	outcome, err := Resolve(context.Background(), r, rc, scope, q, now)
	if err != nil {
		t.Fatalf("检索委托意外失败: %v", err)
	}
	return outcome
}

// fixtureRetriever 是 happy path 的内存知识源：跨组织、跨分级、跨库各放一条。
func fixtureRetriever() *FakeRetriever {
	return NewFakeRetriever(
		fakeDoc("doc-1", kbHandbook, policy.MustScope(policy.ScopeOrganization, orgExample), policy.LevelInternal, "报销流程说明"),
		fakeDoc("doc-2", kbHandbook, policy.MustScope(policy.ScopeProject, projExample), policy.LevelConfidential, "项目预算表"),
		fakeDoc("doc-3", kbHR, policy.MustScope(policy.ScopeOrganization, orgExample), policy.LevelInternal, secretBody),
		// 邻组织的文档：alice 无权，源侧就不该给
		fakeDoc("doc-9", kbRivalLab, policy.MustScope(policy.ScopeOrganization, orgRival), policy.LevelPublic,
			rivalBody, "organization:"+orgRival),
	)
}

func TestResolveHappyPath(t *testing.T) {
	fake := fixtureRetriever().WithACLVersion("example-acl@7")
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)

	outcome := mustResolve(t, fake, rc, scope, Query{Terms: "报销"}, now)

	if !outcome.IsReadable() {
		t.Fatal("有可读文档时 IsReadable 必须为 true")
	}
	if outcome.HitCount != 2 || len(outcome.Citations) != 2 {
		t.Fatalf("应命中 handbook + hr 各一篇: %+v", outcome.Citations)
	}
	if outcome.Failure != nil {
		t.Fatalf("成功路径不该带失败: %+v", outcome.Failure)
	}
	// doc-2 是 confidential：超过本次上限，兜底丢弃而不是采信
	if outcome.KnowledgeLevel != policy.LevelInternal {
		t.Fatalf("命中集最高分级应是被上限截断后的 internal，实际 %s", outcome.KnowledgeLevel)
	}
	if !droppedFor(outcome.Dropped, "doc-2", ReasonLevelExceeded) {
		t.Fatalf("分级超限必须留兜底记录: %+v", outcome.Dropped)
	}
	if outcome.Audit.ResultCode != ReasonOK {
		t.Fatalf("结果码应为 %s，实际 %s", ReasonOK, outcome.Audit.ResultCode)
	}
	if outcome.Audit.AclVersion != "example-acl@7" {
		t.Fatalf("源侧 ACL 世代必须进审计: %s", outcome.Audit.AclVersion)
	}
	if outcome.Audit.Retriever != "fake" {
		t.Fatalf("审计必须记委托实现名（只记名字，不记端点）: %s", outcome.Audit.Retriever)
	}
	if outcome.Audit.PolicyVersion != policyVersionV1 {
		t.Fatal("策略版本必须来自上下文并落进审计")
	}
	if len(outcome.Audit.CitationDigests) != 2 {
		t.Fatalf("审计里的引用摘要条数应与命中数一致: %v", outcome.Audit.CitationDigests)
	}
	if err := outcome.Audit.Validate(); err != nil {
		t.Fatalf("审计事件必须自身合法: %v", err)
	}
	if fake.Calls() != 1 {
		t.Fatalf("应发出一次委托请求，实际 %d", fake.Calls())
	}
	// §2.3 的接缝：knowledge_level 参与 max 组合
	effective, err := outcome.EffectiveLevel(policy.LevelPublic)
	if err != nil || effective != policy.LevelInternal {
		t.Fatalf("知识档位应把 public 主体抬到 internal: %v %v", effective, err)
	}
	// 传给源侧的必须是完整鉴权上下文（不是「已判定可读」的结论）
	sent, ok := fake.LastRequest()
	if !ok || len(sent.Chain) == 0 || sent.Subject != subjectAlice {
		t.Fatalf("委托请求缺少鉴权上下文: %+v", sent)
	}
	for _, doc := range sent.KnowledgeBases {
		if doc == kbRivalLab {
			t.Fatal("请求里出现了未准入的知识库")
		}
	}
}

func TestResolveShortCircuitsWithoutAdmittedKnowledgeBase(t *testing.T) {
	fake := fixtureRetriever()
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	// 空集合是合法值，含义是「一个都不许碰」
	scope, err := NewKnowledgeScope(rc.Chain, policy.LevelInternal, nil)
	if err != nil {
		t.Fatalf("空知识库集合应可构造: %v", err)
	}

	outcome, err := Resolve(context.Background(), fake, rc, scope, Query{Terms: "报销"}, now)
	if err != nil {
		t.Fatalf("没有准入知识库不是错误，是不可读: %v", err)
	}
	if fake.Calls() != 0 {
		t.Fatal("没有准入知识库时必须一次都不发委托请求：发出去反而可能拿到「空白名单=全部库」的误解结果")
	}
	if outcome.IsReadable() || len(outcome.Citations) != 0 {
		t.Fatal("短路路径必须零引用")
	}
	if outcome.Failure == nil || outcome.Failure.Reason != ReasonNoKnowledgeAllow {
		t.Fatalf("短路必须给稳定原因码: %+v", outcome.Failure)
	}
	if outcome.Audit.ResultCode != ReasonNoKnowledgeAllow {
		t.Fatalf("审计结果码应为 %s，实际 %s", ReasonNoKnowledgeAllow, outcome.Audit.ResultCode)
	}
	// 「没授权」与「授权了但库里没有」必须可区分：queried 为空、allowed 为空
	if len(outcome.Audit.QueriedBases) != 0 {
		t.Fatalf("短路时 queried 必须为空: %v", outcome.Audit.QueriedBases)
	}
	if err := outcome.Audit.Validate(); err != nil {
		t.Fatalf("短路审计也必须合法可落库: %v", err)
	}
}

func TestResolveIsFailClosedOnRetrievalFailure(t *testing.T) {
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)

	cases := []struct {
		name       string
		fault      error
		wantReason Reason
	}{
		{"依赖不可用", errors.New("connection refused"), ReasonUnavailable},
		{"稳定失败码", &RetrievalError{Reason: ReasonUpstreamStatus, StatusCode: 503}, ReasonUpstreamStatus},
		{"协议不符", fmt.Errorf("包装一层: %w", ErrProtocol), ReasonProtocolInvalid},
		{"上下文超时", context.DeadlineExceeded, ReasonTimeout},
		{"调用方取消", context.Canceled, ReasonCancelled},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := fixtureRetriever().WithFault(c.fault)
			outcome, err := Resolve(context.Background(), fake, rc, scope, Query{Terms: "报销"}, now)
			if err == nil {
				t.Fatal("检索失败必须同时返回错误，不能被当成成功")
			}
			if outcome == nil {
				t.Fatal("失败也必须给出 Outcome（审计要能落库）")
			}
			if outcome.Failure == nil || outcome.Failure.Reason != c.wantReason {
				t.Fatalf("失败原因码应为 %s，实际 %+v", c.wantReason, outcome.Failure)
			}
			// fail_closed 的落地点：失败 ⇒ 零引用 ⇒ 不可读
			if len(outcome.Citations) != 0 || outcome.HitCount != 0 || outcome.IsReadable() {
				t.Fatalf("检索失败时绝不能放行任何引用: %+v", outcome.Citations)
			}
			if outcome.KnowledgeLevel != policy.LevelPublic {
				t.Fatalf("失败时知识档位应停在 public，实际 %s", outcome.KnowledgeLevel)
			}
			if outcome.Audit.ResultCode != c.wantReason {
				t.Fatalf("审计结果码应为 %s，实际 %s", c.wantReason, outcome.Audit.ResultCode)
			}
			if outcome.Audit.FailureDetail == "" {
				t.Fatal("失败原因必须留痕，否则现场无从归因")
			}
			if !IsFailClosed(err) {
				t.Fatal("IsFailClosed 必须把任何错误判成「按不可读处理」")
			}
			if err := outcome.Audit.Validate(); err != nil {
				t.Fatalf("失败路径的审计同样要能落库: %v", err)
			}
		})
	}
}

func TestResolveRejectsMissingInputs(t *testing.T) {
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	fake := fixtureRetriever()

	if _, err := Resolve(context.Background(), nil, rc, scope, Query{}, now); err == nil {
		t.Fatal("没有注入检索实现必须报错：缺接线不能变成「没有知识源也照样放行」")
	} else if !errors.Is(err, ErrRetriever) {
		t.Fatalf("应报 ErrRetriever，实际 %v", err)
	}
	if fake.Calls() != 0 {
		t.Fatal("参数不符时不应触达知识源")
	}
	if _, err := Resolve(context.Background(), fake, rc, scope, Query{}, now.Add(time.Hour)); err == nil {
		t.Fatal("过期上下文不能再发起检索")
	}
	brokenScope := scope
	brokenScope.MaxDataLevel = policy.LevelUnknown
	if _, err := Resolve(context.Background(), fake, rc, brokenScope, Query{}, now); err == nil {
		t.Fatal("分级上限未判定时不能发起检索")
	}
}

func TestResolveTimesOutWithinBudget(t *testing.T) {
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	rc, err := rc.WithDeadline(now.Add(30*time.Millisecond), now)
	if err != nil {
		t.Fatal(err)
	}
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	fake := NewFakeRetriever(fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, "很慢的库")).
		WithDelay(2 * time.Second)

	started := time.Now()
	outcome, err := Resolve(context.Background(), fake, rc, scope, Query{Terms: "报销"}, now)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("sidecar 超时必须报错")
	}
	if elapsed > time.Second {
		t.Fatalf("超时没有被预算切断，实际等了 %s", elapsed)
	}
	if outcome.Failure == nil || (outcome.Failure.Reason != ReasonTimeout && outcome.Failure.Reason != ReasonCancelled) {
		t.Fatalf("超时应映射成稳定码，实际 %+v", outcome.Failure)
	}
	if len(outcome.Citations) != 0 || outcome.IsReadable() {
		t.Fatal("超时后不得放行引用")
	}
	if outcome.Audit.ResultCode != ReasonTimeout && outcome.Audit.ResultCode != ReasonCancelled {
		t.Fatalf("审计要能区分超时/取消，实际 %s", outcome.Audit.ResultCode)
	}
}

func TestResolveStopsWhenCallerCancels(t *testing.T) {
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	fake := NewFakeRetriever(fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, "慢")).WithDelay(2 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcome, err := Resolve(ctx, fake, rc, scope, Query{Terms: "报销"}, now)
	if err == nil {
		t.Fatal("调用方已取消时必须失败")
	}
	if outcome.Failure == nil || outcome.Failure.Reason != ReasonCancelled {
		t.Fatalf("应报取消码，实际 %+v", outcome.Failure)
	}
	if len(outcome.Citations) != 0 {
		t.Fatal("取消后不得放行引用")
	}
}

func TestResolveEnforcesResultCountCeiling(t *testing.T) {
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	rc, err := rc.WithMaxResults(3)
	if err != nil {
		t.Fatal(err)
	}
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	docs := make([]FakeDocument, 0, 8)
	for i := 0; i < 8; i++ {
		docs = append(docs, fakeDoc(fmt.Sprintf("doc-%02d", i), kbHandbook, ownerOrg(), policy.LevelInternal, "手册正文"))
	}
	// WithoutRequestLimit：源侧无视 max_results 全量返回，验证的是**网关侧**的截断
	fake := NewFakeRetriever(docs...).WithoutRequestLimit()

	outcome := mustResolve(t, fake, rc, scope, Query{Terms: "手册"}, now)
	if len(outcome.Citations) != 3 {
		t.Fatalf("结果数上限必须由网关兜底: %d", len(outcome.Citations))
	}
	if !outcome.Truncated {
		t.Fatal("被截断必须留标志，否则下游以为「库里就这些」")
	}
	if !outcome.Audit.Truncated {
		t.Fatal("截断标志要进审计")
	}
	if !containsReason(outcome.Audit.DroppedReasons, ReasonOverResultLimit) {
		t.Fatalf("超限丢弃要留原因码: %+v", outcome.Dropped)
	}
}

func TestResolveDropsUntrustworthySourceResponses(t *testing.T) {
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)

	t.Run("源侧返回未授权文档", func(t *testing.T) {
		fake := NewFakeRetriever(
			fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, "可读"),
			fakeDoc("doc-x", kbHR, ownerOrg(), policy.LevelInternal, secretBody, "subject:nobody"),
		).WithSimulation(FakeReturnUnreadable)
		outcome := mustResolve(t, fake, rc, scope, Query{Terms: "报销"}, now)
		if len(outcome.Citations) != 1 || outcome.Citations[0].SourceID != "doc-1" {
			t.Fatalf("源侧标了不可读的一篇必须被丢弃: %+v", outcome.Citations)
		}
		if !containsReason(outcome.Audit.DroppedReasons, ReasonNotReadableAtSource) {
			t.Fatalf("丢弃原因码缺失: %v", outcome.Audit.DroppedReasons)
		}
	})

	t.Run("缺判定依据", func(t *testing.T) {
		fake := NewFakeRetriever(fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, "可读")).
			WithSimulation(FakeOmitEvidence)
		outcome := mustResolve(t, fake, rc, scope, Query{Terms: "报销"}, now)
		if len(outcome.Citations) != 0 {
			t.Fatal("没有判定依据的文档不得进引用集合：「源侧说可以」这句话不是权限")
		}
		if !containsReason(outcome.Audit.DroppedReasons, ReasonEvidenceMissing) {
			t.Fatalf("应留 %s，实际 %v", ReasonEvidenceMissing, outcome.Audit.DroppedReasons)
		}
		if outcome.Audit.ResultCode != ReasonNoHits {
			t.Fatalf("全被丢弃的结果码应是 %s，实际 %s", ReasonNoHits, outcome.Audit.ResultCode)
		}
	})

	t.Run("摘要缺失", func(t *testing.T) {
		fake := NewFakeRetriever(fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, "可读")).
			WithSimulation(FakeOmitDigest)
		outcome := mustResolve(t, fake, rc, scope, Query{Terms: "报销"}, now)
		if len(outcome.Citations) != 0 || !containsReason(outcome.Audit.DroppedReasons, ReasonDigestInvalid) {
			t.Fatalf("缺摘要的条目必须丢弃并留码: %+v %v", outcome.Citations, outcome.Audit.DroppedReasons)
		}
	})

	t.Run("串号响应", func(t *testing.T) {
		fake := NewFakeRetriever(fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, "可读")).
			WithRespondHook(func(_ context.Context, req RetrieveRequest) (RetrieveResponse, error) {
				resp := validResponse(req)
				resp.RequestID = "req-别的请求"
				return resp, nil
			})
		outcome, err := Resolve(context.Background(), fake, rc, scope, Query{Terms: "报销"}, now)
		if err == nil {
			t.Fatal("串号响应必须整份拒绝（那是别人的可读集合）")
		}
		if outcome.Failure == nil || outcome.Failure.Reason != ReasonProtocolInvalid {
			t.Fatalf("应报协议不符，实际 %+v", outcome.Failure)
		}
		if len(outcome.Citations) != 0 {
			t.Fatal("拒绝时不得留下引用")
		}
	})

	t.Run("协议版本不符", func(t *testing.T) {
		fake := NewFakeRetriever(fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, "可读")).
			WithRespondHook(func(_ context.Context, req RetrieveRequest) (RetrieveResponse, error) {
				resp := validResponse(req)
				resp.ProtocolVersion = "unknown-v9"
				return resp, nil
			})
		if _, err := Resolve(context.Background(), fake, rc, scope, Query{Terms: "报销"}, now); err == nil {
			t.Fatal("字段语义未对齐时不能逐条猜着采信")
		}
	})

	t.Run("判定已过期的整份响应", func(t *testing.T) {
		fake := NewFakeRetriever(fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, "可读")).
			WithRespondHook(func(_ context.Context, req RetrieveRequest) (RetrieveResponse, error) {
				resp := validResponse(req)
				resp.ExpiresAt = now.Add(-time.Second)
				return resp, nil
			})
		outcome := mustResolve(t, fake, rc, scope, Query{Terms: "报销"}, now)
		if len(outcome.Citations) != 0 {
			t.Fatalf("ACL 已改世后的旧判定不能复用: %+v", outcome.Citations)
		}
		if !containsReason(outcome.Audit.DroppedReasons, ReasonACLExpired) {
			t.Fatalf("应留过期码，实际 %v", outcome.Audit.DroppedReasons)
		}
	})

	t.Run("跨组织与跨库文档直达", func(t *testing.T) {
		// 源侧配错：把邻组织的文档、白名单外知识库的文档返回给了 alice。网关只能靠兜底拦住。
		fake := NewFakeRetriever(fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, "可读")).
			WithRespondHook(func(_ context.Context, req RetrieveRequest) (RetrieveResponse, error) {
				return RetrieveResponse{
					ProtocolVersion: ProtocolVersion, RequestID: req.RequestID,
					Documents: []ReturnedDocument{
						docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg()),
						docForFilter("doc-9", kbHandbook, policy.LevelInternal, policy.MustScope(policy.ScopeOrganization, orgRival)),
						docForFilter("doc-7", kbRivalLab, policy.LevelPublic, ownerOrg()),
					},
				}, nil
			})
		outcome := mustResolve(t, fake, rc, scope, Query{Terms: "报销"}, now)
		if len(outcome.Citations) != 1 || outcome.Citations[0].SourceID != "doc-1" {
			t.Fatalf("跨组织、跨库的返回项必须被兜底丢弃: %+v", outcome.Citations)
		}
		if !containsReason(outcome.Audit.DroppedReasons, ReasonCrossOrg) ||
			!containsReason(outcome.Audit.DroppedReasons, ReasonKBNotAllowed) {
			t.Fatalf("两类兜底丢弃要留各自的原因码: %v", outcome.Audit.DroppedReasons)
		}
	})
}

func TestResolveKeepsCrossOrganizationDataApart(t *testing.T) {
	fake := fixtureRetriever()

	aliceRC, aliceNow := liveContext(t, subjectAlice, orgExample, policy.LevelConfidential)
	aliceScope := mustScope(t, aliceRC.Chain, policy.LevelConfidential, kbHandbook, kbHR, kbRivalLab)
	alice := mustResolve(t, fake, aliceRC, aliceScope, Query{Terms: "报销"}, aliceNow)

	malloryRC, malloryNow := liveContext(t, subjectRival, orgRival, policy.LevelInternal)
	malloryScope := mustScope(t, malloryRC.Chain, policy.LevelInternal, kbRivalLab)
	mallory := mustResolve(t, fake, malloryRC, malloryScope, Query{Terms: "报销"}, malloryNow)

	if containsSource(alice.Citations, "doc-9") {
		t.Fatal("alice 拿到了邻组织的 doc-9：跨组织隔离失败")
	}
	if !containsSource(mallory.Citations, "doc-9") {
		t.Fatalf("mallory 应能拿到自己组织的 doc-9: %+v", mallory.Citations)
	}
	// 摘要集合完全不相交：审计里出现的引用不会跨主体串
	aliceDigests := map[string]bool{}
	for _, c := range alice.Citations {
		aliceDigests[c.Digest] = true
	}
	for _, c := range mallory.Citations {
		if aliceDigests[c.Digest] {
			t.Fatalf("两个主体拿到了同一篇摘要 %s", ShortDigest(c.Digest))
		}
	}
	// 传下去的白名单也各自受限
	if last, ok := fake.LastRequest(); !ok || last.Subject != subjectRival || len(last.KnowledgeBases) != 1 {
		t.Fatalf("委托请求应携带本次准入的子集: %+v", last)
	}
}

func TestResolveIsReusableUnderConcurrency(t *testing.T) {
	// DoD 4：同一实例被并发复用，且并发下结果不受彼此污染。
	fake := fixtureRetriever()
	recorder := NewAuditRecorder(0)
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelConfidential)
	scope := mustScope(t, rc.Chain, policy.LevelConfidential, kbHandbook, kbHR)
	query := Query{Terms: "报销"}

	const rounds = 16
	var baseline *Outcome
	for i := 0; i < rounds; i++ {
		outcome := mustResolve(t, fake, rc, scope, query, now)
		if i == 0 {
			baseline = outcome
			continue
		}
		if len(outcome.Citations) != len(baseline.Citations) {
			t.Fatalf("顺序复用时命中数抖动: %d vs %d", len(outcome.Citations), len(baseline.Citations))
		}
		for j := range outcome.Citations {
			if outcome.Citations[j] != baseline.Citations[j] {
				t.Fatalf("顺序复用时引用抖动: %d", j)
			}
		}
	}
	if fake.Calls() != rounds {
		t.Fatalf("调用计数应准确: %d", fake.Calls())
	}

	var wg sync.WaitGroup
	problems := make(chan string, rounds)
	for i := 0; i < rounds; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outcome, err := Resolve(context.Background(), fake, rc, scope, query, now)
			switch {
			case err != nil:
				problems <- fmt.Sprintf("并发检索失败: %v", err)
			case len(outcome.Citations) != 3:
				problems <- fmt.Sprintf("并发下命中数不正确: %d", len(outcome.Citations))
			default:
				recorder.Record(outcome.Audit)
			}
		}()
	}
	wg.Wait()
	close(problems)
	for msg := range problems {
		t.Fatal(msg)
	}
	if got := len(recorder.Events()); got != rounds {
		t.Fatalf("审计并发写入不完整: %d", got)
	}
	if rejected := recorder.Rejected(); rejected != 0 {
		t.Fatalf("并发下产出的审计事件必须全部合法，rejected=%d", rejected)
	}
	// 并发下每次请求都必须带着自己的上下文，而不是被别的 goroutine 改写
	for _, sent := range fake.Requests() {
		if sent.Subject != subjectAlice || sent.RequestID != rc.RequestID {
			t.Fatalf("委托请求之间发生串用: %s %s", sent.RequestID, sent.Subject)
		}
	}
}

func TestResolveReflectsPolicyVersionChange(t *testing.T) {
	// 手册 §3.0：策略版本必须来自实际加载的策略包，且变更要能在审计上看出来。
	fake := fixtureRetriever()
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)

	first := mustResolve(t, fake, rc, scope, Query{Terms: "报销"}, now)

	updated := rc
	updated.PolicyVersion = "example-default@2"
	second := mustResolve(t, fake, updated, scope, Query{Terms: "报销"}, now)

	if first.Audit.PolicyVersion == second.Audit.PolicyVersion {
		t.Fatal("策略版本变了但审计没变，说明审计里的版本是硬编码的")
	}
	if second.Audit.PolicyVersion != "example-default@2" {
		t.Fatalf("审计版本应为新策略包: %s", second.Audit.PolicyVersion)
	}
	if second.PolicyVersion != "example-default@2" {
		t.Fatal("Outcome 也要带版本，调用方不必再翻审计")
	}
	// 版本必须真的传给了知识源：源侧判定要按同一套策略对齐
	sent, _ := fake.LastRequest()
	if sent.PolicyVersion != "example-default@2" {
		t.Fatalf("策略版本没传给知识源: %s", sent.PolicyVersion)
	}
}

func TestResolveStaysEmptyWhenSourceReturnsNothing(t *testing.T) {
	fake := NewFakeRetriever().WithACLVersion("example-acl@1")
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)

	outcome := mustResolve(t, fake, rc, scope, Query{Terms: "没有的东西"}, now)
	if outcome.IsReadable() || outcome.HitCount != 0 {
		t.Fatal("零命中就是零命中，不该有引用")
	}
	// 「库里没有」是正常结果，不是失败：不能返回 error 让上层误判成故障
	if outcome.Failure != nil {
		t.Fatalf("空结果不该被记成失败: %+v", outcome.Failure)
	}
	if outcome.Audit.ResultCode != ReasonNoHits {
		t.Fatalf("结果码应为 %s，实际 %s", ReasonNoHits, outcome.Audit.ResultCode)
	}
	if outcome.KnowledgeLevel != policy.LevelPublic {
		t.Fatalf("零命中档位必须是 public（否则 §2.3 组合会报错）: %s", outcome.KnowledgeLevel)
	}
	if len(outcome.Audit.QueriedBases) != 1 {
		t.Fatalf("零命中也要记实际查询过的库，用来和「没授权」区分: %v", outcome.Audit.QueriedBases)
	}
}

// TestOutcomeDocumentsCarryAdmissionForContentDelivery 钉死正文交付的输入来源：
// Outcome.Documents 是与 Citations 一一对齐的**源侧本次判定**，因此可以直接装配成
// 交付请求；被兜底丢弃的篇目绝不以任何形态留在这里。
func TestOutcomeDocumentsCarryAdmissionForContentDelivery(t *testing.T) {
	fake := fixtureRetriever().WithACLVersion("example-acl@7")
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)

	outcome := mustResolve(t, fake, rc, scope, Query{Terms: "报销"}, now)
	if len(outcome.Documents) == 0 || len(outcome.Documents) != len(outcome.Citations) {
		t.Fatalf("准入条目必须与引用一一对齐: %d vs %d", len(outcome.Documents), len(outcome.Citations))
	}
	for i, c := range outcome.Citations {
		doc := outcome.Documents[i]
		if doc.SourceID != c.SourceID || doc.KnowledgeBase != c.KnowledgeBase {
			t.Fatalf("第 %d 篇指向不同文档: %s/%s ≠ %s/%s", i, doc.KnowledgeBase, doc.SourceID, c.KnowledgeBase, c.SourceID)
		}
		if strings.ToLower(doc.Digest) != c.Digest {
			t.Fatalf("第 %d 篇摘要与引用不符: %s ≠ %s", i, doc.Digest, c.Digest)
		}
		if !doc.Allowed || strings.TrimSpace(doc.RuleID) == "" {
			t.Fatalf("进准入集合的条目必须带着源侧本次的可读判定与依据: %+v", doc)
		}
		// 分级越界的那篇（doc-2 是 confidential）在引用里已经被丢了，
		// 如果它的条目还留在 Documents 里，正文交付就能凭它申请一篇不该申请的原文。
		if doc.SourceID == "doc-2" {
			t.Fatal("越界篇目留下了准入依据")
		}
	}

	req, err := BuildContentRequest(rc, scope, outcome.Documents, DefaultContentPassages, DefaultContentBytes, now)
	if err != nil {
		t.Fatalf("一次成功检索的准入集合应能装配出交付请求: %v", err)
	}
	if len(req.Documents) != len(outcome.Documents) {
		t.Fatalf("申请项条数应等于准入条数: %d vs %d", len(req.Documents), len(outcome.Documents))
	}
	for _, ask := range req.Documents {
		if ask.ExpectedDigest == "" {
			t.Fatalf("申请项缺少准入摘要: %+v", ask)
		}
	}
}

// TestOutcomeDocumentsEmptyOnEveryNoContentPath：失败、短路、零命中三条路径都不能留下
// 准入依据 —— 「一次失败的检索」拿去申请原文，就是 §3.C 明令禁止的那条路。
func TestOutcomeDocumentsEmptyOnEveryNoContentPath(t *testing.T) {
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)

	t.Run("检索失败", func(t *testing.T) {
		outcome, err := Resolve(context.Background(), fixtureRetriever().WithFault(errors.New("connection refused")),
			rc, scope, Query{Terms: "报销"}, now)
		if err == nil {
			t.Fatal("失败必须返回错误")
		}
		if outcome == nil {
			t.Fatal("失败也要给 Outcome（审计要能落库）")
		}
		if len(outcome.Documents) != 0 {
			t.Fatalf("失败路径不得留下准入依据: %+v", outcome.Documents)
		}
	})

	t.Run("没有准入知识库", func(t *testing.T) {
		emptyScope, err := NewKnowledgeScope(rc.Chain, policy.LevelInternal, nil)
		if err != nil {
			t.Fatal(err)
		}
		outcome, err := Resolve(context.Background(), fixtureRetriever(), rc, emptyScope, Query{Terms: "报销"}, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(outcome.Documents) != 0 {
			t.Fatalf("短路路径不得留下准入依据: %+v", outcome.Documents)
		}
	})

	t.Run("零命中", func(t *testing.T) {
		outcome := mustResolve(t, NewFakeRetriever(), rc, scope, Query{Terms: "没有的东西"}, now)
		if len(outcome.Documents) != 0 {
			t.Fatalf("零命中不得留下准入依据: %+v", outcome.Documents)
		}
	})

	t.Run("全部被兜底丢弃", func(t *testing.T) {
		fake := NewFakeRetriever(fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, "可读")).
			WithSimulation(FakeOmitEvidence)
		outcome := mustResolve(t, fake, rc, scope, Query{Terms: "报销"}, now)
		if len(outcome.Citations) != 0 || len(outcome.Documents) != 0 {
			t.Fatalf("没有判定依据就没有准入: %+v", outcome.Documents)
		}
	})
}

// TestOutcomeDocumentsNeverSurviveSerialization：Documents 是 `json:"-"`。
// 这不只是「别把字段带进审计」——审计与回放那条链反序列化出来的 Outcome
// 因此结构上没有准入依据，拿它去装配交付请求只会得到一个空申请集合，
// 而空申请集合在协议层不合法。原文申请必须发生在同一次请求的内存里。
func TestOutcomeDocumentsNeverSurviveSerialization(t *testing.T) {
	fake := fixtureRetriever().WithACLVersion("example-acl@7")
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)
	outcome := mustResolve(t, fake, rc, scope, Query{Terms: "报销"}, now)
	if len(outcome.Documents) == 0 {
		t.Fatal("用例前提：这次检索应留下准入条目")
	}

	data, err := json.Marshal(outcome)
	if err != nil {
		t.Fatalf("Outcome 必须可序列化（审计与回放依赖它）: %v", err)
	}
	if strings.Contains(string(data), `"documents"`) {
		t.Fatalf("准入条目序列化进了审计形态: %s", string(data))
	}

	var revived Outcome
	if err := json.Unmarshal(data, &revived); err != nil {
		t.Fatal(err)
	}
	if len(revived.Citations) == 0 {
		t.Fatal("用例前提：引用应能序列化往返")
	}
	if len(revived.Documents) != 0 {
		t.Fatalf("反序列化产物不得携带准入依据: %+v", revived.Documents)
	}
	req, err := BuildContentRequest(rc, scope, revived.Documents, DefaultContentPassages, DefaultContentBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Documents) != 0 {
		t.Fatalf("凭反序列化产物申请到了正文: %+v", req.Documents)
	}
	if err := req.Validate(); err == nil {
		t.Fatal("空申请集合必须不合法，调用方必须短路而不是把空集合发给知识源")
	}
}

// validResponse 造一份外壳与内容都合规的响应，供「只改一个字段」的用例使用。
func validResponse(req RetrieveRequest) RetrieveResponse {
	return RetrieveResponse{
		ProtocolVersion: ProtocolVersion,
		RequestID:       req.RequestID,
		AclVersion:      "example-acl@3",
		Documents:       []ReturnedDocument{docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg())},
	}
}

func containsReason(in []Reason, want Reason) bool {
	for _, r := range in {
		if r == want {
			return true
		}
	}
	return false
}

func containsSource(in []Citation, sourceID string) bool {
	for _, c := range in {
		if c.SourceID == sourceID {
			return true
		}
	}
	return false
}

func droppedFor(in []DropRecord, sourceID string, reason Reason) bool {
	for _, d := range in {
		if d.SourceID == sourceID && d.Reason == reason {
			return true
		}
	}
	return false
}
