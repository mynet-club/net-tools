package knowledge

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 源侧（fake）在正文方向必须自己做的事，都在这里钉死。
//
// 这批用例与 content_test.go 的分工要说清：那一份查**网关侧兜底**（拿到载荷后逐篇判），
// 这一份查**源侧再判定**（该不该给）。两边都钉住，三道锁的第二道才是事实而不是注释 ——
// 委托接口的约定 1（Allowed=true 不等于正文可交付）只有被反证过一次才算立住。

// grantVerbatim 给一篇文档加上「原文可交付」的源侧授权（选择器与依据分开传，
// 是为了让用例里能看出这是**第二次**判定，不是复用 ReadableBy）。
func grantVerbatim(doc FakeDocument, ruleID string, sels ...string) FakeDocument {
	doc.VerbatimBy = append([]string(nil), sels...)
	doc.VerbatimRuleID = ruleID
	return doc
}

// addFault 追加一个源侧缺陷标记。标记串以 ! 开头，selectorsMatch 不认它是授权，
// 所以「只有标记、没有授权」的文档正好能造出「源侧越权硬给」那一类。
func addFault(doc FakeDocument, marker string) FakeDocument {
	doc.VerbatimBy = append(append([]string(nil), doc.VerbatimBy...), marker)
	return doc
}

// LevelScope 是「分级上限 + 允许知识库」这一组用例参数（写成结构体是为了在表驱动里可读）。
type LevelScope struct {
	level policy.DataLevel
	kbs   []string
}

// fakeContentRun 用一份文档池加一组准入声明跑一次交付；意外失败直接终止用例。
func fakeContentRun(t *testing.T, docs []FakeDocument, admitted []ReturnedDocument,
	scope LevelScope, maxPassages, maxBytes int, opts ...func(*FakeRetriever)) (*ContentOutcome, *FakeRetriever) {
	t.Helper()
	fake := NewFakeRetriever(docs...)
	for _, opt := range opts {
		opt(fake)
	}
	rc, now := liveContext(t, subjectAlice, orgExample, scope.level)
	sc := mustScope(t, rc.Chain, scope.level, scope.kbs...)
	outcome, err := DeliverContents(context.Background(), fake, rc, sc, admitted, maxPassages, maxBytes, now)
	if err != nil {
		t.Fatalf("交付不该整体报错（除非用例就是要失败路径）: %v", err)
	}
	return outcome, fake
}

func TestFakeDeliversOnlyDocumentsWithVerbatimGrant(t *testing.T) {
	body1, body2 := "第一篇的正文", "第二篇的正文"
	granted := grantVerbatim(
		fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, body1, "subject:"+subjectAlice),
		"content-rule-doc-1", "subject:"+subjectAlice)
	// doc-2 引用可读（ReadableBy 命中）但源侧没给原文授权 —— 这正是约定 1 要区分的那一篇。
	refOnly := fakeDoc("doc-2", kbHandbook, ownerOrg(), policy.LevelInternal, body2, "subject:"+subjectAlice)

	admitted := []ReturnedDocument{
		admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, body1),
		admittedWithBody("doc-2", kbHandbook, policy.LevelInternal, body2),
	}
	outcome, fake := fakeContentRun(t, []FakeDocument{granted, refOnly}, admitted,
		LevelScope{policy.LevelInternal, []string{kbHandbook}}, DefaultContentPassages, DefaultContentBytes)

	if outcome.RequestedCount != 2 {
		t.Fatalf("两篇都已准入，申请集合应当是 2: %+v", outcome)
	}
	if len(outcome.Passages) != 1 || outcome.Passages[0].SourceID != "doc-1" {
		t.Fatalf("只该交付源侧授权过原文的那一篇: %+v", outcome.Passages)
	}
	if string(outcome.Passages[0].Verbatim) != body1 {
		t.Fatal("交付的字节必须是源侧那份原文")
	}
	if outcome.Passages[0].RuleID != "content-rule-doc-1" {
		t.Fatalf("源侧的交付依据必须带上: %+v", outcome.Passages[0])
	}
	if len(outcome.Dropped) != 0 {
		t.Fatalf("源侧没给的篇不该出现在丢弃记录里（它压根没被交付）: %+v", outcome.Dropped)
	}
	if outcome.Audit.ResultCode != ReasonContentOK || outcome.Audit.DeliveredCount != 1 {
		t.Fatalf("审计不符: %+v", outcome.Audit)
	}
	if fake.ContentCalls() != 1 {
		t.Fatalf("一次交付应当只调用一次: %d", fake.ContentCalls())
	}
}

// TestFakeContentRejudgesOwnershipPerRequest 证明第二道锁是按**本次请求**重算的：
// 一篇文档的引用对全网公开（ReadableBy=*）、原文只授权给另一个组织，
// alice 来申请正文就必须拿不到 —— 复用上一次的 Allowed 结论就会拿到。
func TestFakeContentRejudgesOwnershipPerRequest(t *testing.T) {
	body := "只有对手组织能拿原文"
	doc := grantVerbatim(fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, body, "*"),
		"content-rule-doc-1", "organization:"+orgRival)
	admitted := []ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, body)}

	outcome, _ := fakeContentRun(t, []FakeDocument{doc}, admitted,
		LevelScope{policy.LevelInternal, []string{kbHandbook}}, DefaultContentPassages, DefaultContentBytes)
	if len(outcome.Passages) != 0 || outcome.HitCount != 0 || outcome.TotalBytes != 0 {
		t.Fatalf("跨组织授权不能被本次请求继承: %+v", outcome.Passages)
	}
	if outcome.Audit.ResultCode != ReasonContentNone {
		t.Fatalf("源侧拒绝交付是正常结论，不是失败: %s", outcome.Audit.ResultCode)
	}

	// 同一篇换成被授权的那个组织来申请就必须拿到 —— 证明拒的原因确实是选择器而不是别的东西。
	fake := NewFakeRetriever(doc)
	rc, now := liveContext(t, subjectAlice, orgRival, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	req, err := BuildContentRequest(rc, scope, admitted, DefaultContentPassages, DefaultContentBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := fake.DeliverContent(context.Background(), req)
	if err != nil {
		t.Fatalf("源侧交付不该报错: %v", err)
	}
	if len(resp.Passages) != 1 || string(resp.Passages[0].Verbatim) != body {
		t.Fatalf("授权命中的组织应当拿到原文: %+v", resp.Passages)
	}
}

// TestFakeContentIgnoreAdmissionStillMeetsGatewayLevelGate 是有意的反向用例：
// 缺陷模拟让源侧跳过再判定，把没授权的正文硬交出来。网关在这一层**看不出**越权
// （摘要对得上、这篇确实申请过），所以这里断言的是两件事：
//  1. 分级上限那道闸仍然生效 —— 源侧硬给也越不过 scope 的 ceiling；
//  2. 源侧硬给的公开级正文会进结果，并在审计里留下交付篇数与依据，值班看得到「这次搬了原文进网关」。
//
// 换句话说：正文可交付性的真值源在源侧，这是委托协议的既有代价；
// 网关能保证的是「不给越出范围上限的正文留活路」加上「每一次交付都可归因」。
func TestFakeContentIgnoreAdmissionStillMeetsGatewayLevelGate(t *testing.T) {
	givenBody := "源侧没授权原文却硬给"
	secretBody2 := "越出上限的机密正文"
	plain := fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, givenBody, "*")
	tooHigh := fakeDoc("doc-2", kbHandbook, ownerOrg(), policy.LevelConfidential, secretBody2, "*")

	admitted := []ReturnedDocument{
		admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, givenBody),
		admittedWithBody("doc-2", kbHandbook, policy.LevelConfidential, secretBody2),
	}
	outcome, _ := fakeContentRun(t, []FakeDocument{plain, tooHigh}, admitted,
		LevelScope{policy.LevelInternal, []string{kbHandbook}}, DefaultContentPassages, DefaultContentBytes,
		func(f *FakeRetriever) { f.WithContentSimulation(FakeContentIgnoreAdmission) })

	if len(outcome.Passages) != 1 || outcome.Passages[0].SourceID != "doc-1" {
		t.Fatalf("分级越限的那一篇必须被网关丢掉: %+v", outcome.Passages)
	}
	if len(outcome.Dropped) != 1 || outcome.Dropped[0].Reason != ReasonLevelExceeded {
		t.Fatalf("丢弃原因码应为分级越限: %+v", outcome.Dropped)
	}
	if strings.Contains(mustMarshal(t, outcome.Audit), secretBody2) {
		t.Fatal("被丢掉的正文不得出现在审计里")
	}
	if outcome.Audit.DeliveredCount != 1 || outcome.Audit.DeliveredBytes != len(givenBody) {
		t.Fatalf("硬给那一篇必须可归因: %+v", outcome.Audit)
	}
}

// TestFakeContentFaultMarkersMapToGatewayDrops 把每个源侧缺陷标记接到一条网关丢弃规则上：
// 标记名与原因码一一对应，读用例的人不需要猜「这个模拟测的是哪条闸」。
func TestFakeContentFaultMarkersMapToGatewayDrops(t *testing.T) {
	body := "同一份正文"
	newDoc := func() FakeDocument {
		return fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, body, "subject:"+subjectAlice)
	}
	// 每条用例都带两个申请名额（doc-2 只是个占位声明，池里没有对应文档）：
	// 单篇交付时条数不会超过申请数，外壳门槛放行，才走得到逐条判定。
	admitted := []ReturnedDocument{
		admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, body),
		admittedWithBody("doc-2", kbHandbook, policy.LevelInternal, "占位的那一篇"),
	}

	tests := []struct {
		name string
		doc  FakeDocument
		want Reason
		sim  string
	}{
		{
			name: "交付字节与准入摘要不符",
			doc:  addFault(grantVerbatim(newDoc(), "content-rule-doc-1", "subject:"+subjectAlice), FakeForceContentWrongDigest),
			want: ReasonContentDigestMismatch,
		},
		{
			name: "缺原文交付依据",
			// 有 VerbatimBy 授权但没 VerbatimRuleID，再叠上「不许用兜底依据」的标记：
			// 源侧交出一份说不出理由的正文。
			doc:  addFault(grantVerbatim(newDoc(), "", "subject:"+subjectAlice), FakeForceContentNoRuleDocument),
			want: ReasonContentEvidenceMissing,
		},
		{
			name: "整站缺依据",
			doc:  grantVerbatim(newDoc(), "content-rule-doc-1", "subject:"+subjectAlice),
			want: ReasonContentEvidenceMissing,
			sim:  FakeContentOmitEvidence,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var opts []func(*FakeRetriever)
			if tc.sim != "" {
				name := tc.sim
				opts = append(opts, func(f *FakeRetriever) { f.WithContentSimulation(name) })
			}
			outcome, _ := fakeContentRun(t, []FakeDocument{tc.doc}, admitted,
				LevelScope{policy.LevelInternal, []string{kbHandbook}}, DefaultContentPassages, DefaultContentBytes, opts...)
			if len(outcome.Passages) != 0 {
				t.Fatalf("这一篇必须整篇丢弃而不是收下再标记可疑: %+v", outcome.Passages)
			}
			if len(outcome.Dropped) != 1 || outcome.Dropped[0].Reason != tc.want {
				t.Fatalf("丢弃原因码应为 %s: %+v", tc.want, outcome.Dropped)
			}
			if outcome.Audit.ResultCode != ReasonContentNone {
				t.Fatalf("全丢之后结果码应为 %s: %s", ReasonContentNone, outcome.Audit.ResultCode)
			}
			if err := outcome.Audit.Validate(); err != nil {
				t.Fatalf("丢弃路径的审计也要完整: %v", err)
			}
		})
	}
}

// TestFakeContentUnaskedDocumentIsDropped 模拟源侧多给：
// 索引没跟上或缓存未失效时，对端会把网关没申请过的篇也交出来。
// 条数没超过申请数（外壳放行）时必须由逐条判定兜住，这才有「网关只认申请集合」的对照组。
func TestFakeContentUnaskedDocumentIsDropped(t *testing.T) {
	askedBody := "申请过的正文"
	asked := grantVerbatim(
		fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, askedBody, "subject:"+subjectAlice),
		"content-rule-doc-1", "subject:"+subjectAlice)
	// doc-9 从未被申请（不在准入声明里），却带着硬塞标记。
	unaskedBody := "网关没申请过的正文"
	unasked := addFault(
		fakeDoc("doc-9", kbHandbook, ownerOrg(), policy.LevelInternal, unaskedBody, "*"),
		FakeForceContentUnaskedDocument)

	admitted := []ReturnedDocument{
		admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, askedBody),
		// 占第二个名额：让总交付条数不超过申请条数，走逐条判定而不是整份拒。
		admittedWithBody("doc-2", kbHandbook, policy.LevelInternal, "池里没有的那一篇"),
	}
	outcome, _ := fakeContentRun(t, []FakeDocument{asked, unasked}, admitted,
		LevelScope{policy.LevelInternal, []string{kbHandbook}}, DefaultContentPassages, DefaultContentBytes)

	if len(outcome.Passages) != 1 || outcome.Passages[0].SourceID != "doc-1" {
		t.Fatalf("没申请过的正文不得进结果: %+v", outcome.Passages)
	}
	if len(outcome.Dropped) != 1 || outcome.Dropped[0].Reason != ReasonContentNotRequested {
		t.Fatalf("丢弃原因码应为 %s: %+v", ReasonContentNotRequested, outcome.Dropped)
	}
	if outcome.Dropped[0].SourceID != "doc-9" {
		t.Fatalf("丢弃记录要能指到那一篇: %+v", outcome.Dropped)
	}
}

// TestFakeContentRespectsBudgetButOverDeliveryFailsClosed 钉死预算的两侧：
// 守预算的源侧，装不下的部分由它自己裁（网关标 truncated）；
// 无视预算的源侧**整份拒**，网关不会「收下装得下的那几篇」——
// 逐篇裁字节会让「进了 prompt 的是哪几篇」取决于丢弃顺序，回放与审计都说不清。
func TestFakeContentRespectsBudgetButOverDeliveryFailsClosed(t *testing.T) {
	bodies := map[string]string{
		"doc-1": strings.Repeat("a", 400),
		"doc-2": strings.Repeat("b", 400),
		"doc-3": strings.Repeat("c", 400),
	}
	var docs []FakeDocument
	var admitted []ReturnedDocument
	for _, id := range []string{"doc-1", "doc-2", "doc-3"} {
		docs = append(docs, grantVerbatim(
			fakeDoc(id, kbHandbook, ownerOrg(), policy.LevelInternal, bodies[id], "subject:"+subjectAlice),
			"content-rule-"+id, "subject:"+subjectAlice))
		admitted = append(admitted, admittedWithBody(id, kbHandbook, policy.LevelInternal, bodies[id]))
	}

	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)

	t.Run("源侧守预算", func(t *testing.T) {
		fake := NewFakeRetriever(docs...)
		outcome, err := DeliverContents(context.Background(), fake, rc, scope, admitted,
			DefaultContentPassages, 1000, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(outcome.Passages) != 2 || outcome.TotalBytes != 800 {
			t.Fatalf("应当只交付装得下的 2 篇: %d 篇 %d 字节", len(outcome.Passages), outcome.TotalBytes)
		}
		if !outcome.Truncated || !outcome.Audit.Truncated {
			t.Fatalf("源侧裁过就必须标 truncated，否则面板以为拿到全集: %+v", outcome.Audit)
		}
	})

	t.Run("源侧无视预算则整份拒", func(t *testing.T) {
		fake := NewFakeRetriever(docs...).WithoutContentBudget()
		outcome, err := DeliverContents(context.Background(), fake, rc, scope, admitted,
			DefaultContentPassages, 1000, now)
		if err == nil {
			t.Fatal("超出预算的交付必须报错")
		}
		if len(outcome.Passages) != 0 || outcome.TotalBytes != 0 {
			t.Fatalf("报错时不得留下部分正文: %d 篇 %d 字节", len(outcome.Passages), outcome.TotalBytes)
		}
		if outcome.Failure == nil || outcome.Failure.Reason != ReasonContentProtocolInvalid {
			t.Fatalf("原因码应为交付协议不符: %+v", outcome.Failure)
		}
		if outcome.Audit.DeliveredCount != 0 || outcome.Audit.DeliveredBytes != 0 {
			t.Fatalf("整份拒的审计不得记成交付过: %+v", outcome.Audit)
		}
		if err := outcome.Audit.Validate(); err != nil {
			t.Fatalf("整份拒路径的审计也要完整: %v", err)
		}
	})
}

// TestFakeContentFailurePathsAreFailClosed 覆盖源侧直接报错的两条：注入故障与上下文取消。
// 两条都必须产空结果 —— 「正文拿不到」永远不等于「那就用已经拿到的」。
func TestFakeContentFailurePathsAreFailClosed(t *testing.T) {
	body := "会被拒绝的正文"
	doc := grantVerbatim(fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, body, "subject:"+subjectAlice),
		"content-rule-doc-1", "subject:"+subjectAlice)
	admitted := []ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, body)}

	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)

	t.Run("注入故障", func(t *testing.T) {
		fake := NewFakeRetriever(doc).WithContentFault(errors.New("源侧 500"))
		outcome, err := DeliverContents(context.Background(), fake, rc, scope, admitted,
			DefaultContentPassages, DefaultContentBytes, now)
		if err == nil {
			t.Fatal("源侧报错必须往上传")
		}
		if len(outcome.Passages) != 0 || outcome.Failure == nil || outcome.Failure.Reason != ReasonUnavailable {
			t.Fatalf("未分类错误应收敛成不可用: %+v", outcome.Failure)
		}
		if strings.Contains(outcome.Audit.FailureDetail, body) {
			t.Fatalf("失败详情不得带出正文: %s", outcome.Audit.FailureDetail)
		}
	})

	t.Run("上下文已取消", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		fake := NewFakeRetriever(doc)
		outcome, err := DeliverContents(ctx, fake, rc, scope, admitted,
			DefaultContentPassages, DefaultContentBytes, now)
		if err == nil {
			t.Fatal("取消必须报错")
		}
		if len(outcome.Passages) != 0 {
			t.Fatal("取消后不得留下正文")
		}
		if outcome.Failure == nil || outcome.Failure.Reason != ReasonCancelled {
			t.Fatalf("原因码应为调用方取消: %+v", outcome.Failure)
		}
		if err := outcome.Audit.Validate(); err != nil {
			t.Fatalf("取消路径的审计也要完整: %v", err)
		}
	})
}

// TestFakeContentCountersAndReset 把「同一实例分隔用例」这条 DoD 要求在正文方向也钉住：
// 计数器与缺陷注入若不在 Reset 里清掉，下一个用例会带着上一个的模拟开关跑绿 ——
// 那种绿比红更危险。
func TestFakeContentCountersAndReset(t *testing.T) {
	body := "重复使用的正文"
	doc := grantVerbatim(fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, body, "subject:"+subjectAlice),
		"content-rule-doc-1", "subject:"+subjectAlice)
	admitted := []ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, body)}
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)

	fake := NewFakeRetriever(doc).WithContentSimulation(FakeContentOmitEvidence)
	outcome, err := DeliverContents(context.Background(), fake, rc, scope, admitted,
		DefaultContentPassages, DefaultContentBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	// 注入的缺陷必须生效：整站缺依据 → 逐篇丢 → 没有正文。
	if len(outcome.Passages) != 0 || len(outcome.Dropped) != 1 {
		t.Fatalf("缺陷模拟没生效: %+v %+v", outcome.Passages, outcome.Dropped)
	}
	if fake.ContentCalls() != 1 || len(fake.ContentRequests()) != 1 {
		t.Fatalf("调用计数不符: %d", fake.ContentCalls())
	}
	first, ok := fake.LastContentRequest()
	if !ok || len(first.Documents) != 1 || first.Documents[0].SourceID != "doc-1" {
		t.Fatalf("记录的请求应可回放: %+v", first)
	}
	if first.ProtocolVersion != ContentProtocolVersion {
		t.Fatalf("记录的请求必须带交付协议版本: %s", first.ProtocolVersion)
	}

	fake.Reset()
	if fake.ContentCalls() != 0 || len(fake.ContentRequests()) != 0 {
		t.Fatal("Reset 必须清正文方向的调用记录")
	}
	if _, ok := fake.LastContentRequest(); ok {
		t.Fatal("Reset 后不该还能取到上一次的请求")
	}
	clean := deliver(t, fake, rc, scope, admitted, now)
	if len(clean.Passages) != 1 {
		t.Fatalf("Reset 必须清掉缺陷注入，否则用例之间互相污染: %+v", clean.Dropped)
	}
}

// TestContentDelivererNameIsAuditSafe 报名字这条限制在正文方向同样成立：
// 只许报实现名，不许把端点（含主机名与可能的凭证）写进审计行。
func TestContentDelivererNameIsAuditSafe(t *testing.T) {
	doc := grantVerbatim(fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, "A", "subject:"+subjectAlice),
		"content-rule-doc-1", "subject:"+subjectAlice)
	fake := NewFakeRetriever(doc)
	if fake.ContentDelivererName() != "fake" {
		t.Fatalf("缺省实现名: %s", fake.ContentDelivererName())
	}
	fake.Name = "example-sidecar"
	if fake.ContentDelivererName() != "example-sidecar" {
		t.Fatalf("自定义实现名: %s", fake.ContentDelivererName())
	}
	// 只实现委托接口、不报名字的实现，审计里必须记空串而不是网关去猜。
	if got := contentDelivererName(unnamedDeliverer{}); got != "" {
		t.Fatalf("未报名字的交付方应记空: %q", got)
	}

	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	outcome := deliver(t, fake, rc, scope,
		[]ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, "A")}, now)
	if outcome.Audit.Deliverer != "example-sidecar" {
		t.Fatalf("审计交付方标注不符: %s", outcome.Audit.Deliverer)
	}
	if blob := mustMarshal(t, outcome.Audit); strings.Contains(blob, "//") || strings.Contains(blob, "http") {
		t.Fatalf("审计里不得出现任何端点形态: %s", blob)
	}
}

// unnamedDeliverer 只实现委托接口，用来测「没报名字」那条分支。
type unnamedDeliverer struct{}

func (unnamedDeliverer) DeliverContent(_ context.Context, req ContentRequest) (ContentResponse, error) {
	return ContentResponse{ProtocolVersion: ContentProtocolVersion, RequestID: req.RequestID}, nil
}

// TestFakeContentRequestCarriesNoPlaintext 是「网关侧全程只需要摘要」那道证明题的正文版：
// 交付请求里最敏感的东西只是 ExpectedDigest（sha256 串），检索词与正文都不在协议字段里；
// 载荷回来后，明文也只能活在载体那一个字段里。
func TestFakeContentRequestCarriesNoPlaintext(t *testing.T) {
	body := "只有源侧知道的明文 ZZSENTINEL_FAKE_REQ"
	title := "只有源侧知道的标题 ZZSENTINEL_FAKE_TITLE"
	doc := grantVerbatim(
		fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, body, "subject:"+subjectAlice),
		"content-rule-doc-1", "subject:"+subjectAlice)
	doc.IndexedTitle = title
	admitted := []ReturnedDocument{admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, body)}

	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	req, err := BuildContentRequest(rc, scope, admitted, DefaultContentPassages, DefaultContentBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	if blob := mustMarshal(t, req); strings.Contains(blob, "ZZSENTINEL") {
		t.Fatalf("交付请求里出现了源侧明文: %s", blob)
	}

	outcome, err := DeliverContents(context.Background(), NewFakeRetriever(doc), rc, scope, admitted,
		DefaultContentPassages, DefaultContentBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.Passages) != 1 || string(outcome.Passages[0].Verbatim) != body {
		t.Fatalf("正文应当只在载体这一个字段里: %+v", outcome.Passages)
	}
	// outcome 整体序列化（Passages 是 json:"-"）与审计行都不能带出明文。
	if blob := mustMarshal(t, outcome); strings.Contains(blob, "ZZSENTINEL") {
		t.Fatalf("outcome 的序列化形态带出了正文: %s", blob)
	}
	if strings.Contains(outcome.Audit.String(), "ZZSENTINEL") {
		t.Fatalf("单行日志带出了正文: %s", outcome.Audit.String())
	}
	for _, line := range []string{outcome.Passages[0].Display(), outcome.Passages[0].RuleID} {
		if strings.Contains(line, "ZZSENTINEL") {
			t.Fatalf("标识形态带出了正文: %s", line)
		}
	}
}
