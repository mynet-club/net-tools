package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 正文通道（决策包 §8.1）的测试基线与 Resolve 那套同口径：
// 判定类用例走 baseNow（不碰墙钟），交付类用例走 liveContext（Deadline 会变成真实 ctx 超时）。

// admittedWithBody 造一篇「源侧刚声明可读」的返回文档：摘要按 body 算，
// 正文交付那条链上的双重摘要校验才有对照对象（ExpectedDigest 与交付字节的 sha256 必须同源）。
func admittedWithBody(sourceID, kb string, level policy.DataLevel, body string) ReturnedDocument {
	doc := docForFilter(sourceID, kb, level, ownerOrg())
	doc.Digest = DigestString(body)
	return doc
}

// docWithVerbatim 在 fakeDoc 之上追加源侧的**第二次判定**：这篇的原文可以交给网关。
// 与 ReadableBy 分开传参是刻意的 —— 用例里必须能看出这是两件事。
func docWithVerbatim(doc FakeDocument, ruleID string, sels ...string) FakeDocument {
	doc.VerbatimBy = sels
	doc.VerbatimRuleID = ruleID
	return doc
}

// contentPassage 造一篇形态合规的交付载荷（Digest 就是交付字节的 sha256）。
func contentPassage(sourceID, kb string, level policy.DataLevel, body, ruleID string) Passage {
	return Passage{
		SourceID:      sourceID,
		KnowledgeBase: kb,
		Digest:        DigestString(body),
		DataLevel:     level.String(),
		TitleDigest:   TitleDigest("标题-" + sourceID),
		RuleID:        ruleID,
		AclVersion:    "fake-acl-v1",
		Verbatim:      []byte(body),
	}
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	blob, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	return string(blob)
}

// deliver 走一次交付并在意外失败时终止用例（与 mustResolve 同形）。
func deliver(t *testing.T, d DelegatedContentDeliverer, rc RequestContext, scope KnowledgeScope,
	admitted []ReturnedDocument, now time.Time) *ContentOutcome {
	t.Helper()
	outcome, err := DeliverContents(context.Background(), d, rc, scope, admitted,
		DefaultContentPassages, DefaultContentBytes, now)
	if err != nil {
		t.Fatalf("正文交付意外失败: %v", err)
	}
	return outcome
}

// contentFixture 是一篇可读且可交付的文档，外加对应的准入声明。
func contentFixture(t *testing.T, sourceID, kb, body string, level policy.DataLevel) (*FakeRetriever, []ReturnedDocument, time.Time) {
	t.Helper()
	fake := NewFakeRetriever(docWithVerbatim(
		fakeDoc(sourceID, kb, ownerOrg(), level, body, "subject:"+subjectAlice),
		"content-rule-"+sourceID, "subject:"+subjectAlice))
	_, now := liveContext(t, subjectAlice, orgExample, level)
	return fake, []ReturnedDocument{admittedWithBody(sourceID, kb, level, body)}, now
}

func TestBuildContentRequestUsesOnlyAdmittedDocs(t *testing.T) {
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)

	good := admittedWithBody("doc-2", kbHandbook, policy.LevelInternal, "B")
	goodEarly := admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")
	unreadable := admittedWithBody("doc-3", kbHR, policy.LevelInternal, "C")
	unreadable.Allowed = false
	expired := admittedWithBody("doc-4", kbHR, policy.LevelInternal, "D")
	expired.ExpiresAt = after(-time.Minute)

	// 故意乱序传入：申请集合的顺序必须与调用方/源侧的顺序无关（预算裁剪结果才对得上回放）。
	req, err := BuildContentRequest(rc, scope, []ReturnedDocument{good, unreadable, expired, goodEarly},
		DefaultContentPassages, DefaultContentBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Documents) != 2 || req.Documents[0].SourceID != "doc-1" || req.Documents[1].SourceID != "doc-2" {
		t.Fatalf("只该留下 Allowed 且未过期的篇目，并按 kb/source_id 稳定排序: %+v", req.Documents)
	}
	if req.ProtocolVersion != ContentProtocolVersion || req.RequestID != rc.RequestID {
		t.Fatalf("协议与请求标识不符: %+v", req)
	}
	if req.MaxDataLevel != policy.LevelInternal.String() || req.PolicyVersion != rc.PolicyVersion {
		t.Fatalf("身份与分级上下文必须与检索请求同形: %+v", req)
	}
	if len(req.Chain) != len(rc.Chain) {
		t.Fatal("范围链必须原样传给源侧，否则源侧无从独立鉴权")
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("装配出的请求必须自证合规: %v", err)
	}
}

// TestBuildContentRequestShortCircuitsWithoutAdmission 钉死那条「空集合不请求」的约定：
// 空 documents 的请求要么不发、要么被协议拒 —— 两种都不能让对端按「全部可读」来猜。
func TestBuildContentRequestShortCircuitsWithoutAdmission(t *testing.T) {
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)

	req, err := BuildContentRequest(rc, scope, []ReturnedDocument{},
		DefaultContentPassages, DefaultContentBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Documents) != 0 {
		t.Fatalf("没有准入篇目时申请集合必须为空: %+v", req.Documents)
	}
	if err := req.Validate(); err == nil {
		t.Fatal("空申请集合的请求必须被协议拒（调用方应短路而不是发出去）")
	}
}

func TestBuildContentRequestClampsBudget(t *testing.T) {
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	docs := []ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")}

	cases := []struct {
		name            string
		passages, bytes int
		wantPassages    int
		wantBytes       int
	}{
		{"缺省取保守值", 0, 0, DefaultContentPassages, DefaultContentBytes},
		{"负值不解释成不限", -1, -1, DefaultContentPassages, DefaultContentBytes},
		// 越界回落到保守缺省而不是绝对上限：把「写错了」读成「给到最大」是静默放大授权面。
		{"越界回落到保守缺省", maxContentPassages * 4, AbsoluteMaxContentBytes * 4, DefaultContentPassages, DefaultContentBytes},
		{"声明值原样生效", 3, 4096, 3, 4096},
	}
	for _, tc := range cases {
		req, err := BuildContentRequest(rc, scope, docs, tc.passages, tc.bytes, now)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if req.MaxPassages != tc.wantPassages || req.MaxTotalBytes != tc.wantBytes {
			t.Errorf("%s: 预算夹取不符 got=%d/%d want=%d/%d",
				tc.name, req.MaxPassages, req.MaxTotalBytes, tc.wantPassages, tc.wantBytes)
		}
	}

	// 申请篇数也必须被预算裁掉，而不是留给对端去猜。
	many := make([]ReturnedDocument, 0, 12)
	for i := 0; i < 12; i++ {
		many = append(many, admittedWithBody("doc-"+string(rune('a'+i)), kbHandbook, policy.LevelInternal, "x"))
	}
	req, err := BuildContentRequest(rc, scope, many, 5, DefaultContentBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Documents) != 5 {
		t.Fatalf("预算 5 篇时申请集合必须只剩 5 篇: %d", len(req.Documents))
	}
}

func TestBuildContentRequestRejectsUnusableAdmission(t *testing.T) {
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)

	broken := admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")
	broken.Digest = "短摘要"
	if _, err := BuildContentRequest(rc, scope, []ReturnedDocument{broken},
		DefaultContentPassages, DefaultContentBytes, now); err == nil {
		t.Fatal("缺完整摘要的准入篇目不能变成申请项：没有 ExpectedDigest 就无从证明交付的是同一篇")
	}

	otherKB := admittedWithBody("doc-1", kbHR, policy.LevelInternal, "A")
	if _, err := BuildContentRequest(rc, scope, []ReturnedDocument{otherKB},
		DefaultContentPassages, DefaultContentBytes, now); err == nil {
		t.Fatal("范围外的知识库不能出现在申请集合里")
	}
}

func TestContentRequestValidateRejectsMalformed(t *testing.T) {
	base := func() ContentRequest {
		rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
		scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
		req, err := BuildContentRequest(rc, scope,
			[]ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")},
			DefaultContentPassages, DefaultContentBytes, now)
		if err != nil {
			t.Fatal(err)
		}
		_ = now
		return req
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("基线请求必须合规: %v", err)
	}

	t.Run("协议版本必须精确匹配", func(t *testing.T) {
		req := base()
		req.ProtocolVersion = ProtocolVersion // 拿检索版本号来申请正文
		if err := req.Validate(); !errors.Is(err, ErrProtocol) {
			t.Fatalf("两套协议各发各的：检索版本不能用来申请正文，err=%v", err)
		}
	})

	t.Run("重复篇目必须拒", func(t *testing.T) {
		req := base()
		req.Documents = append(req.Documents, req.Documents[0])
		if err := req.Validate(); err == nil {
			t.Fatal("同一篇申请两次等于给它两份预算")
		}
	})

	t.Run("范围外知识库必须拒", func(t *testing.T) {
		req := base()
		ask := req.Documents[0]
		ask.KnowledgeBase = kbHR
		ask.SourceID = "doc-9"
		req.Documents = append(req.Documents, ask)
		if err := req.Validate(); err == nil {
			t.Fatal("申请项的知识库必须落在允许集合内")
		}
	})

	t.Run("预算越界必须拒", func(t *testing.T) {
		req := base()
		req.MaxTotalBytes = AbsoluteMaxContentBytes + 1
		if err := req.Validate(); err == nil {
			t.Fatal("声明值越不过绝对上限")
		}
		req = base()
		req.MaxPassages = 0
		if err := req.Validate(); err == nil {
			t.Fatal("max_passages=0 不能被解释成不限")
		}
	})

	t.Run("空集合必须拒", func(t *testing.T) {
		req := base()
		req.Documents = nil
		if err := req.Validate(); err == nil {
			t.Fatal("空申请集合发出去会被对端按「全部」理解")
		}
	})
}

func TestContentResponseEnvelopeRejectsOverDelivery(t *testing.T) {
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	req, err := BuildContentRequest(rc, scope,
		[]ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")},
		8, 4096, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = now

	resp := func(bodies ...string) ContentResponse {
		out := ContentResponse{ProtocolVersion: ContentProtocolVersion, RequestID: req.RequestID}
		for i, body := range bodies {
			out.Passages = append(out.Passages, contentPassage(
				"doc-"+string(rune('a'+i)), kbHandbook, policy.LevelInternal, body, "r"))
		}
		return out
	}

	if err := resp("A").ValidateEnvelope(req); err != nil {
		t.Fatalf("合规交付不该被外壳校验拒: %v", err)
	}
	if err := resp(strings.Repeat("A", 5000)).ValidateEnvelope(req); err == nil {
		t.Fatal("超过字节预算的响应必须整份拒：逐篇裁字节会让「哪几篇进了 prompt」依赖丢弃顺序")
	}

	// 条数超过申请数：对端没在实现这条协议，整份拒而不是逐条丢。
	two := ContentResponse{ProtocolVersion: ContentProtocolVersion, RequestID: req.RequestID, Passages: []Passage{
		contentPassage("doc-1", kbHandbook, policy.LevelInternal, "A", "r"),
		contentPassage("doc-2", kbHandbook, policy.LevelInternal, "B", "r"),
	}}
	if err := two.ValidateEnvelope(req); err == nil {
		t.Fatal("交付条数不得超过本次申请条数")
	}

	// 串号响应（request_id 不符）在任何逐条判定之前就该被拒。
	mismatch := resp("A")
	mismatch.RequestID = "req-other"
	if err := mismatch.ValidateEnvelope(req); err == nil {
		t.Fatal("request_id 不符的响应必须拒：把 A 次交付的正文接到 B 次请求上是越权")
	}

	// 版本不符。
	wrongVersion := resp("A")
	wrongVersion.ProtocolVersion = ProtocolVersion
	if err := wrongVersion.ValidateEnvelope(req); err == nil {
		t.Fatal("交付响应必须核对交付协议版本")
	}
}

func TestDeliverContentsHappyPath(t *testing.T) {
	fake, admitted, now := contentFixture(t, "doc-3", kbHR, secretBody, policy.LevelInternal)
	rc, _ := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)

	outcome := deliver(t, fake, rc, scope, admitted, now)

	if len(outcome.Passages) != 1 {
		t.Fatalf("应当交付 1 篇: %+v", outcome.Dropped)
	}
	p := outcome.Passages[0]
	if string(p.Verbatim) != secretBody || p.Digest != DigestString(secretBody) {
		t.Fatalf("交付内容与摘要不符: %+v", p)
	}
	if p.RuleID != "content-rule-doc-3" {
		t.Fatalf("源侧的交付依据必须留在载体上: %+v", p)
	}
	if outcome.HitCount != 1 || outcome.RequestedCount != 1 || outcome.TotalBytes != len(secretBody) {
		t.Fatalf("计数不符: %+v", outcome)
	}
	if outcome.MaxDataLevel != policy.LevelInternal {
		t.Fatalf("交付分级应为源侧申报值: %s", outcome.MaxDataLevel)
	}
	if outcome.Audit.ResultCode != ReasonContentOK || outcome.Audit.Deliverer != "fake" {
		t.Fatalf("审计结果码/交付方标注不符: %+v", outcome.Audit)
	}
	if err := outcome.Audit.Validate(); err != nil {
		t.Fatalf("审计形态: %v", err)
	}
	if fake.ContentCalls() != 1 {
		t.Fatalf("交付应当调用一次: %d", fake.ContentCalls())
	}
	// 源侧收到的请求里带着与检索同形的身份：它必须自己判，不能靠网关转述结论。
	sent, ok := fake.LastContentRequest()
	if !ok || sent.Subject != subjectAlice || len(sent.Chain) == 0 {
		t.Fatalf("交付请求身份字段缺失: %+v", sent)
	}
}

// TestDeliverContentsNilDelivererIsFailClosed 钉死「没有交付实现」不等于「放行」：
// 处理器拿不到正文就只能按没有上下文工作。
func TestDeliverContentsNilDelivererIsFailClosed(t *testing.T) {
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	outcome, err := DeliverContents(context.Background(), nil, rc, scope,
		[]ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")},
		DefaultContentPassages, DefaultContentBytes, now)
	if err == nil {
		t.Fatal("没有交付实现必须报错")
	}
	if outcome != nil {
		t.Fatal("报错时不该产出一个半成品的交付结果")
	}
}

// TestDeliverContentsShortCircuitsWithoutAdmission 断言「一篇都没准入时一次都不发」：
// 空集合发出去，对端多半按「全部可读文档」来理解。
func TestDeliverContentsShortCircuitsWithoutAdmission(t *testing.T) {
	fake, _, now := contentFixture(t, "doc-1", kbHandbook, "A", policy.LevelInternal)
	rc, _ := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)

	unreadable := admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")
	unreadable.Allowed = false

	outcome := deliver(t, fake, rc, scope, []ReturnedDocument{unreadable}, now)
	if fake.ContentCalls() != 0 {
		t.Fatalf("没有可申请的篇目时一次都不该发: %d", fake.ContentCalls())
	}
	if len(outcome.Passages) != 0 || outcome.Failure == nil {
		t.Fatalf("必须产空正文并留失败原因: %+v", outcome)
	}
	if outcome.Failure.Reason != ReasonContentNothingAdmitted {
		t.Fatalf("原因码应为 %s: %+v", ReasonContentNothingAdmitted, outcome.Failure)
	}
	if outcome.Audit.ResultCode != ReasonContentNothingAdmitted || len(outcome.Audit.QueriedBases) != 0 {
		t.Fatalf("短路的审计不该声称查过任何库: %+v", outcome.Audit)
	}
	if err := outcome.Audit.Validate(); err != nil {
		t.Fatalf("短路路径的审计也必须完整: %v", err)
	}
}

func TestDeliverContentsFailureIsFailClosed(t *testing.T) {
	fake, admitted, now := contentFixture(t, "doc-1", kbHandbook, "A", policy.LevelInternal)
	fake.WithContentFailure(ReasonUnavailable, "源侧不可用")
	rc, _ := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)

	outcome, err := DeliverContents(context.Background(), fake, rc, scope, admitted,
		DefaultContentPassages, DefaultContentBytes, now)
	if err == nil {
		t.Fatal("交付失败必须返回错误")
	}
	if len(outcome.Passages) != 0 || outcome.HitCount != 0 || outcome.TotalBytes != 0 {
		t.Fatalf("失败必须产空结果（不得用部分正文继续工作）: %+v", outcome)
	}
	if outcome.Failure == nil || outcome.Failure.Reason != ReasonUnavailable {
		t.Fatalf("失败原因码丢失: %+v", outcome.Failure)
	}
	if outcome.Audit.ResultCode != ReasonUnavailable || outcome.Audit.DeliveredCount != 0 {
		t.Fatalf("失败路径的审计必须留下同一条原因码: %+v", outcome.Audit)
	}
	if err := outcome.Audit.Validate(); err != nil {
		t.Fatalf("失败审计形态: %v", err)
	}
}

// TestDeliverContentsDropsEachViolation 逐条钉死网关侧的整篇丢弃规则。
// 每条都是一次「源侧合规地交了一份不合规的载荷」——这正是真实对端最容易出的错。
func TestDeliverContentsDropsEachViolation(t *testing.T) {
	tests := []struct {
		name string
		// asks 是本次准入的申请篇目；build 依据请求构造要交付的篇目。
		asks    []ReturnedDocument
		build   func(req ContentRequest) []Passage
		maxByte int
		want    Reason
		kept    int
	}{
		{
			name: "没申请过的篇",
			asks: []ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")},
			build: func(req ContentRequest) []Passage {
				return []Passage{contentPassage("doc-99", kbHandbook, policy.LevelInternal, "没申请过", "r")}
			},
			want: ReasonContentNotRequested,
		},
		{
			name: "缺交付依据",
			asks: []ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")},
			build: func(req ContentRequest) []Passage {
				return []Passage{contentPassage("doc-1", kbHandbook, policy.LevelInternal, "A", "")}
			},
			want: ReasonContentEvidenceMissing,
		},
		{
			name: "摘要与交付字节不符",
			asks: []ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")},
			build: func(req ContentRequest) []Passage {
				p := contentPassage("doc-1", kbHandbook, policy.LevelInternal, "A", "r")
				p.Verbatim = []byte("换了内容")
				return []Passage{p}
			},
			want: ReasonContentDigestMismatch,
		},
		{
			name: "准入摘要本身不符",
			asks: []ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")},
			build: func(req ContentRequest) []Passage {
				p := contentPassage("doc-1", kbHandbook, policy.LevelInternal, "A", "r")
				p.Digest = DigestString("另一篇")
				return []Passage{p}
			},
			want: ReasonContentDigestMismatch,
		},
		{
			name: "分级越出范围上限",
			asks: []ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")},
			build: func(req ContentRequest) []Passage {
				return []Passage{contentPassage("doc-1", kbHandbook, policy.LevelConfidential, "A", "r")}
			},
			want: ReasonLevelExceeded,
		},
		{
			name: "交付方声明的到期时刻已过",
			asks: []ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")},
			build: func(req ContentRequest) []Passage {
				p := contentPassage("doc-1", kbHandbook, policy.LevelInternal, "A", "r")
				p.ExpiresAt = baseNow // 基线时间相对用例的 now 已是过去
				return []Passage{p}
			},
			want: ReasonContentExpired,
		},
		{
			name: "单篇超绝对上限",
			asks: []ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")},
			build: func(req ContentRequest) []Passage {
				body := strings.Repeat("A", AbsoluteMaxPassageBytes+1)
				return []Passage{contentPassage("doc-1", kbHandbook, policy.LevelInternal, body, "r")}
			},
			// 单篇超限要能走到逐条判定，字节预算得先放行（否则整份在协议层就被拒了）。
			maxByte: AbsoluteMaxContentBytes,
			want:    ReasonContentTooLarge,
		},
		{
			name: "同一篇重复交付",
			// 重复用例要有两个申请项，否则外壳的条数门槛会先把整份拒掉。
			asks: []ReturnedDocument{
				admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A"),
				admittedWithBody("doc-2", kbHandbook, policy.LevelInternal, "B"),
			},
			build: func(req ContentRequest) []Passage {
				return []Passage{
					contentPassage("doc-1", kbHandbook, policy.LevelInternal, "A", "r"),
					contentPassage("doc-1", kbHandbook, policy.LevelInternal, "A", "r"),
				}
			},
			want: ReasonDuplicate,
			kept: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
			scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)

			var delivered []Passage
			fake := NewFakeRetriever().WithContentHook(func(_ context.Context, req ContentRequest) (ContentResponse, error) {
				delivered = tc.build(req)
				return ContentResponse{
					ProtocolVersion: ContentProtocolVersion,
					RequestID:       req.RequestID,
					Passages:        delivered,
					AclVersion:      "fake-acl-v1",
				}, nil
			})

			maxByte := tc.maxByte
			if maxByte == 0 {
				maxByte = DefaultContentBytes
			}
			outcome, err := DeliverContents(context.Background(), fake, rc, scope, tc.asks,
				DefaultContentPassages, maxByte, now)
			if err != nil {
				t.Fatalf("%s: 不该整份失败: %v", tc.name, err)
			}
			if len(outcome.Passages) != tc.kept {
				t.Fatalf("留下的篇数不符: %+v", outcome.Passages)
			}
			if len(outcome.Dropped) == 0 || outcome.Dropped[0].Reason != tc.want {
				t.Fatalf("丢弃原因码应为 %s: %+v", tc.want, outcome.Dropped)
			}
			want := ReasonContentNone
			if tc.kept > 0 {
				want = ReasonContentOK
			}
			if outcome.Audit.ResultCode != want {
				t.Fatalf("结果码应为 %s: %s", want, outcome.Audit.ResultCode)
			}
			if outcome.Audit.DroppedCount != len(outcome.Dropped) {
				t.Fatalf("审计的丢弃计数与丢弃记录不符: %+v", outcome.Audit)
			}
			if err := outcome.Audit.Validate(); err != nil {
				t.Fatalf("丢弃路径的审计也必须完整: %v", err)
			}
			// 被丢的正文必须清零（§2.9 规则 2），不能只靠「出了作用域会被 GC」。
			for _, p := range delivered {
				if keptContainsKey(outcome.Passages, p.Key()) {
					continue
				}
				if len(p.Verbatim) != 0 {
					t.Fatalf("丢弃篇目的正文没清零：%s 还剩 %d 字节", p.SourceID, len(p.Verbatim))
				}
			}
		})
	}
}

func keptContainsKey(in []Passage, key string) bool {
	for _, p := range in {
		if p.Key() == key {
			return true
		}
	}
	return false
}

// TestDeliverContentsOrderIsDeterministic 证明注入顺序与源侧返回顺序无关：
// 同一份内容以两种顺序交付，留下的篇目序列必须一致（回放与审计摘要才对得上）。
func TestDeliverContentsOrderIsDeterministic(t *testing.T) {
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	admitted := []ReturnedDocument{
		admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A"),
		admittedWithBody("doc-2", kbHandbook, policy.LevelInternal, "B"),
	}

	bodies := map[string]string{"doc-1": "A", "doc-2": "B"}
	run := func(in []string) []string {
		fake := NewFakeRetriever().WithContentHook(func(_ context.Context, req ContentRequest) (ContentResponse, error) {
			var out []Passage
			for _, id := range in {
				out = append(out, contentPassage(id, kbHandbook, policy.LevelInternal, bodies[id], "r"))
			}
			return ContentResponse{ProtocolVersion: ContentProtocolVersion, RequestID: req.RequestID, Passages: out}, nil
		})
		outcome := deliver(t, fake, rc, scope, admitted, now)
		keys := make([]string, 0, len(outcome.Passages))
		for _, p := range outcome.Passages {
			keys = append(keys, p.SourceID)
		}
		return keys
	}

	first := run([]string{"doc-1", "doc-2"})
	second := run([]string{"doc-2", "doc-1"})
	if strings.Join(first, ",") != "doc-1,doc-2" || strings.Join(second, ",") != "doc-1,doc-2" {
		t.Fatalf("交付结果必须按稳定顺序返回: %v vs %v", first, second)
	}
}

func TestContentAuditEventValidationAndPII(t *testing.T) {
	event := ContentAuditEvent{
		RequestID:           "req-content",
		Subject:             subjectAlice,
		Chain:               chainOf(t, subjectAlice, orgExample, projExample),
		Purpose:             "qa",
		AllowedBases:        []string{kbHandbook},
		RequestedCount:      1,
		DeliveredCount:      1,
		DeliveredBytes:      42,
		MaxDataLevel:        policy.LevelInternal.String(),
		RequestMaxDataLevel: policy.LevelInternal.String(),
		ResultCode:          ReasonContentOK,
		PolicyVersion:       policyVersionV1,
		StartedAt:           baseNow,
		FinishedAt:          baseNow,
		DeliveredDigests:    []string{DigestString("A")},
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("合规审计不该被拒: %v", err)
	}

	broken := event
	broken.ResultCode = Reason("临时编的")
	if err := broken.Validate(); err == nil {
		t.Fatal("未注册的结果码必须拒（正文方向的结果码同样只能追加不能现编）")
	}
	broken = event
	broken.PolicyVersion = ""
	if err := broken.Validate(); err == nil {
		t.Fatal("缺策略版本的交付审计无法归因")
	}
	broken = event
	broken.DeliveredDigests = []string{"短摘要"}
	if err := broken.Validate(); err == nil {
		t.Fatal("半截摘要不能让取证失去依据")
	}

	// 个人信息兜底：序列化点要拦住邮箱/手机号形态的主体（与检索审计同一口径）。
	pii := event
	pii.Subject = "alice@example.com"
	blob := mustMarshal(t, pii)
	if strings.Contains(blob, "alice@example.com") {
		t.Fatalf("邮箱主体不得落交付审计: %s", blob)
	}
	if !strings.Contains(blob, `"subject_ref":"`) {
		t.Fatalf("隐去主体时必须留下可关联的截断摘要: %s", blob)
	}
	if strings.Contains(pii.String(), "alice@example.com") {
		t.Fatalf("单行日志同样要隐去: %s", pii.String())
	}
}

// TestContentProtocolVersionsAreIndependent 锁住「检索链零改动」这条验收：
// 开关关掉时现网只走 ProtocolVersion 那一套，正文版本的存在不改变它的任何语义。
func TestContentProtocolVersionsAreIndependent(t *testing.T) {
	if ProtocolVersion == ContentProtocolVersion {
		t.Fatal("两套协议必须各自独立编号，否则开关关掉时的兼容性承诺就没了")
	}
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	searchReq, err := BuildRequest(rc, scope, Query{Terms: "A"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if searchReq.ProtocolVersion != ProtocolVersion {
		t.Fatalf("检索请求版本被正文通道污染: %s", searchReq.ProtocolVersion)
	}
	contentReq, err := BuildContentRequest(rc, scope,
		[]ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")},
		DefaultContentPassages, DefaultContentBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	if contentReq.ProtocolVersion != ContentProtocolVersion {
		t.Fatalf("交付请求版本不符: %s", contentReq.ProtocolVersion)
	}
	// 交叉使用两个版本号都必须被拒：版本串了就没法判断对端到底实现了哪套协议。
	cross := contentReq
	cross.ProtocolVersion = ProtocolVersion
	if err := cross.Validate(); !errors.Is(err, ErrProtocol) {
		t.Fatal("检索版本号不能用于正文交付请求")
	}
}
