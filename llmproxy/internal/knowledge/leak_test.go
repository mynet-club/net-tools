package knowledge

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// leakMarkers 是测试 fixture 里的「正文/标题明文」标记。
// 断言口径很简单：任何会被写进日志、审计、错误信息或协议 JSON 的字符串里
// 都不许出现它们——出现就说明本包把内容当元数据带出来了（手册 §3.C 的禁止项）。
var leakMarkers = []string{
	secretBody,
	secretTitle,
	rivalBody,
	"正文-", // docForFilter 的明文输入，只应进摘要
	"标题-", // 同上
	"报销流程说明",
	"项目预算表",
}

// assertNoLeak 断言一段输出里没有任何明文标记。
func assertNoLeak(t *testing.T, label, out string) {
	t.Helper()
	for _, marker := range leakMarkers {
		if strings.Contains(out, marker) {
			t.Fatalf("%s 里出现了内容明文 %q：输出=%s", label, marker, out)
		}
	}
}

// forbiddenFieldWords 是本包结构体禁止出现的字段名要素（字段名与 JSON 标签都查）。
//
// 为什么用「字段名词法」而不是「跑一遍看有没有正文」：正文一定会先体现成
// 某个 Content/Body/Snippet 字段，名字层面钉死比事后扫描更靠前，
// 也挡得住「加了个字段但这次测试没填它」这种最隐蔽的越界。
// 手册 §3.C 要求「任何结构体都不得持有文档正文」，这条测试就是那句要求的可执行形式。
var forbiddenFieldWords = []string{
	"body", "payload", "fulltext", "content", "text", "snippet", "excerpt",
	"paragraph", "raw", "secret", "password", "passwd", "credential", "apikey",
	"api_key", "token", "privatekey", "private_key", "baseurl", "base_url",
}

// 例外说明：
//   - "raw" 只允许出现在 **布尔开关** 字段上（Query.AllowRawTerms /
//     RetrieveRequest.AllowRawTerms）：它是「是否授权携带原文」的标志位，
//     本身不是内容。真正的原文字段叫 SearchTerms，由 BuildRequest 严格门控。
//   - "text" 只允许出现在 FakeDocument 的 IndexedTitle / IndexedText 上，
//     那代表「知识源侧的索引数据」，是本包证明「只需要摘要就能工作」的对照组，
//     不参与任何协议 JSON、引用与审计（本文件下方有专门用例逐条钉死）。
func isAllowedException(field reflect.StructField, word string) bool {
	switch word {
	case "raw":
		return field.Type.Kind() == reflect.Bool
	case "text":
		return false // FakeDocument 整体不参与本扫描，见 fakeStructReason
	}
	return false
}

// fakeStructReason 记录 FakeDocument 不参与词法扫描的理由。
const fakeStructReason = "FakeDocument 是知识源侧的索引条目（模拟对端数据库），不属于委托协议与网关侧结构；" +
	"它的明文只用于计算摘要，TestFakeNeverPutsPlaintextOnTheWire 逐条钉死这一点。"

// scannedStructs 是必须通过词法扫描的结构体集合：协议、引用、审计、失败与结果。
func scannedStructs() []any {
	return []any{
		KnowledgeScope{},
		RequestContext{},
		Query{},
		RetrieveRequest{},
		ReturnedDocument{},
		RetrieveResponse{},
		Citation{},
		DropRecord{},
		FilterResult{},
		Outcome{},
		AuditEvent{},
		retrievalErrorSample(),
		KnowledgeBaseDenial{},
		fakeRetrieverSample(),
		httpRetrieverSample(),
	}
}

// 下面几个探针把「只有指针/函数字段」的结构体也纳入扫描（结构体本身不含明文，
// 但字段名同样要过词法关，否则「Endpoint 换成 BaseURL」就绕过了扫描）。
func retrievalErrorSample() any { return RetrievalError{} }
func fakeRetrieverSample() any  { return struct{ Name string }{} }
func httpRetrieverSample() any {
	return struct {
		Endpoint         string
		MaxResponseBytes int64
		FallbackBudget   string
		Name             string
	}{}
}

// fieldScanner 累积扫描结果：violations 是命中项，visited 是被查过的字段数。
// 记 visited 是为了让「扫描本身是空转」也能被测试抓到——
// 一个只遍历顶层字段的递归会永远绿灯，那种测试比没有测试更危险。
type fieldScanner struct {
	seen       map[reflect.Type]bool
	violations []string
	visited    int
}

func TestNoStructInThisPackageHoldsDocumentBody(t *testing.T) {
	var scanner fieldScanner
	scanner.seen = map[reflect.Type]bool{}
	for _, sample := range scannedStructs() {
		delete(scanner.seen, reflect.TypeOf(sample)) // 每个根结构体各自展开一次嵌套
		scanner.walk(reflect.TypeOf(sample), "")
	}
	if len(scanner.violations) != 0 {
		t.Fatalf("协议/审计结构体里存在正文字段:\n%s", strings.Join(scanner.violations, "\n"))
	}
	if scanner.visited < 80 {
		t.Fatalf("词法扫描覆盖的字段过少（%d），说明递归没有真正展开嵌套结构", scanner.visited)
	}
	// FakeDocument 单独说明理由，避免读者以为扫描漏了它
	t.Log(fakeStructReason)
}

// TestBodyFieldWouldBeCaught 是扫描器的反向对照：证明它真的会拒绝正文字段。
// 少了这条，前面的绿灯可能只是扫描器本身写错了。
func TestBodyFieldWouldBeCaught(t *testing.T) {
	type badCitation struct {
		SourceID string `json:"source_id"`
		Body     string `json:"body"`
		Snippet  string `json:"snippet"`
		APIKey   string `json:"api_key"`
		Payload  []byte
		Excerpt  string
	}
	var scanner fieldScanner
	scanner.seen = map[reflect.Type]bool{}
	scanner.walk(reflect.TypeOf(badCitation{}), "")
	got := strings.Join(scanner.violations, "\n")
	for _, want := range []string{"Body", "Snippet", "APIKey", "Payload", "Excerpt"} {
		if !strings.Contains(got, "."+want+"（") {
			t.Errorf("扫描器漏报字段 %s，说明词法关形同虚设：\n%s", want, got)
		}
	}

	// 唯一的合法例外：布尔开关里的 raw 不算内容
	type allowedGate struct {
		AllowRawTerms bool `json:"allow_raw_terms"`
	}
	var gate fieldScanner
	gate.seen = map[reflect.Type]bool{}
	gate.walk(reflect.TypeOf(allowedGate{}), "")
	if len(gate.violations) != 0 {
		t.Errorf("布尔开关不应被判成正文字段: %v", gate.violations)
	}
}

// walk 递归检查结构体字段名与 JSON 标签。
func (s *fieldScanner) walk(typ reflect.Type, path string) {
	if typ == nil || s.seen[typ] {
		return
	}
	s.seen[typ] = true
	switch typ.Kind() {
	case reflect.Ptr:
		s.walk(typ.Elem(), path+"*")
		return
	case reflect.Slice, reflect.Array, reflect.Map:
		s.walk(typ.Elem(), path+"[]")
		return
	case reflect.Struct:
	default:
		return
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := strings.ToLower(field.Name)
		tag := strings.ToLower(field.Tag.Get("json"))
		s.visited++
		for _, word := range forbiddenFieldWords {
			if !strings.Contains(name, word) && !strings.Contains(tag, word) {
				continue
			}
			if isAllowedException(field, word) {
				continue
			}
			s.violations = append(s.violations, fmt.Sprintf(
				"%s.%s（json=%q）命中禁用词 %q：本包结构体不得持有文档正文或凭证",
				prettyType(typ, path), field.Name, tag, word))
		}
		// 函数字段（Do / 响应钩子）不持有内容；其余递归下去，嵌套结构才是藏字段的地方
		if field.Type.Kind() != reflect.Func {
			s.walk(field.Type, path+field.Name+".")
		}
	}
}

func prettyType(typ reflect.Type, path string) string {
	if path == "" {
		return typ.String()
	}
	return path
}

// TestPopulatedFixturesSerializeWithoutContent 用「填满了值」的样本逐条序列化，
// 作为词法扫描之外的运行时兜底：字段名合规但把正文塞进了 TitleDigest 也算泄露。
func TestPopulatedFixturesSerializeWithoutContent(t *testing.T) {
	rc := mustContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)
	req := mustRequest(t)
	doc := docForFilter("doc-3", kbHandbook, policy.LevelInternal, ownerOrg())
	doc.Digest = DigestString(secretBody)
	doc.TitleDigest = TitleDigest(secretTitle)
	resp := RetrieveResponse{
		ProtocolVersion: ProtocolVersion,
		RequestID:       req.RequestID,
		AclVersion:      "example-acl@2",
		EvaluatedAt:     baseNow,
		ExpiresAt:       after(time.Minute),
		Documents:       []ReturnedDocument{doc},
	}
	filtered, err := Filter(resp, req, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	citation := filtered.citations[0]
	event := baseAudit(rc, scope, Query{Terms: secretBody}, baseNow, baseNow, ReasonOK, policy.LevelInternal, "example-acl@2")
	event.QueriedBases = scope.KnowledgeBases
	event.CitationDigests = []string{citation.Digest}
	event.DroppedReasons = Reasons([]Reason{ReasonLevelExceeded})

	samples := map[string]any{
		"RequestContext":   rc,
		"KnowledgeScope":   scope,
		"RetrieveRequest":  req,
		"ReturnedDocument": doc,
		"RetrieveResponse": resp,
		"Citation":         citation,
		"FilterResult":     filtered,
		"AuditEvent":       event,
		"RetrievalError":   &RetrievalError{Reason: ReasonUnavailable, Detail: "传输层失败", KB: scope.KnowledgeBases},
	}
	for name, sample := range samples {
		blob, err := json.Marshal(sample)
		if err != nil {
			t.Fatalf("%s 序列化失败: %v", name, err)
		}
		assertNoLeak(t, name+" 的 JSON", string(blob))
	}

	// 引用与审计的人类可读形式同样不能带内容
	assertNoLeak(t, "Citation.Display", citation.Display())
	assertNoLeak(t, "AuditEvent.String", event.String())
	if !strings.Contains(citation.Display(), kbHandbook) || !strings.Contains(citation.Display(), ShortDigest(doc.Digest)) {
		t.Fatalf("引用展示必须保留可关联标识: %s", citation.Display())
	}
}

// TestFakeNeverPutsPlaintextOnTheWire 证明「知识源侧有明文、网关侧只有摘要」：
// 委托协议本身不要求任何一方交出正文。
func TestFakeNeverPutsPlaintextOnTheWire(t *testing.T) {
	fake := NewFakeRetriever(
		fakeDoc("doc-1", kbHandbook, ownerOrg(), policy.LevelInternal, secretBody, "subject:"+subjectAlice),
		fakeDoc("doc-2", kbHR, ownerOrg(), policy.LevelInternal, rivalBody, "organization:"+orgRival),
	)
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)

	outcome, err := Resolve(context.Background(), fake, rc, scope, Query{Terms: secretBody, AllowRawTerms: true}, now)
	if err != nil {
		t.Fatalf("检索失败: %v", err)
	}
	if len(outcome.Citations) != 1 || outcome.Citations[0].SourceID != "doc-1" {
		t.Fatalf("只有本主体可读的那篇该留下: %+v", outcome.Citations)
	}
	// 源侧返回的载荷：连明文标题都不许出现
	sent, err := BuildRequest(rc, scope, Query{Terms: secretBody, AllowRawTerms: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := fake.Retrieve(context.Background(), sent)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeak(t, "知识源响应 JSON", string(blob))
	for _, doc := range resp.Documents {
		if doc.Digest != DigestString(secretBody) {
			t.Fatal("摘要必须由源侧按原文计算，否则网关无从关联")
		}
		if doc.TitleDigest != TitleDigest("标题-doc-1") {
			t.Fatalf("标题必须是摘要形态: %s", doc.TitleDigest)
		}
	}
	assertNoLeak(t, "引用集合", citeDump(t, outcome.Citations))
	assertNoLeak(t, "审计一行", outcome.Audit.String())
	auditBlob, err := json.Marshal(outcome.Audit)
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeak(t, "审计 JSON", string(auditBlob))
	if outcome.Audit.QueryDigest != (Query{Terms: secretBody}).Digest() {
		t.Fatal("审计只留检索词摘要")
	}
	// 这条用例里检索词恰好等于某篇文档的正文，正是域分隔要挡的场景：
	// 审计里的「搜过这个词」不能拿去离线命中「存在这份文档」。
	if outcome.Audit.QueryDigest == DigestString(secretBody) {
		t.Fatal("检索词摘要必须与正文摘要跨域隔离")
	}
	// 被丢弃文档（邻组织）的内容也不能出现在丢弃记录里
	dropBlob, err := json.Marshal(outcome.Dropped)
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeak(t, "丢弃记录 JSON", string(dropBlob))
}

// TestErrorMessagesCarryOnlyStableIDs 断言失败路径的报错文本没有内容。
func TestErrorMessagesCarryOnlyStableIDs(t *testing.T) {
	fake := fixtureRetriever().WithFault(errorsNewWithContent())
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)

	outcome, err := Resolve(context.Background(), fake, rc, scope, Query{Terms: secretBody}, now)
	if err == nil {
		t.Fatal("必须失败")
	}
	if err.Error() != outcome.Failure.Error() {
		t.Fatalf("错误与 Failure 应一致: %v vs %v", err, outcome.Failure)
	}
	assertNoLeak(t, "错误信息", err.Error())
	assertNoLeak(t, "失败详情", outcome.Audit.FailureDetail)
	// 未分类错误必须被收敛成稳定码：原始文案（可能含 URL、响应片段）不进审计
	if outcome.Failure.Reason != ReasonUnavailable {
		t.Fatalf("未分类错误应归为 %s，实际 %+v", ReasonUnavailable, outcome.Failure)
	}
	if strings.Contains(outcome.Audit.FailureDetail, "connection") {
		t.Fatalf("底层错误原文不该进审计: %s", outcome.Audit.FailureDetail)
	}
}

func errorsNewWithContent() error {
	return fmt.Errorf("dial tcp 10.0.0.7:8443: connect: connection refused (%s)", secretBody)
}

// TestReflectionSeesNoCredentialFields 单独把凭证形态的词列出来查一遍：
// 手册 §8 要求本包结构里根本不存密钥，认证一律属于注入的 transport。
func TestReflectionSeesNoCredentialFields(t *testing.T) {
	credentialWords := []string{"secret", "password", "passwd", "credential", "apikey", "api_key", "token", "privatekey", "private_key", "authorization"}
	for _, sample := range scannedStructs() {
		typ := reflect.TypeOf(sample)
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			lowered := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
			for _, word := range credentialWords {
				if strings.Contains(lowered, word) {
					t.Errorf("%s.%s 疑似凭证字段（命中 %q）：认证应由注入的 transport 承担", typ.Name(), field.Name, word)
				}
			}
		}
	}
}

// TestMarshalRedactsPIISubject 断言序列化点的个人信息兜底。
func TestMarshalRedactsPIISubject(t *testing.T) {
	event := AuditEvent{
		RequestID: "req-pii", Subject: "alice@example.com", Chain: chainOf(t, subjectAlice, orgExample, projExample),
		Purpose: "qa", QueryDigest: DigestString("x"), ResultCode: ReasonOK,
		MaxDataLevel: policy.LevelInternal.String(), RequestMaxDataLevel: policy.LevelInternal.String(),
		PolicyVersion: policyVersionV1, StartedAt: baseNow, FinishedAt: baseNow,
	}
	blob, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "alice@example.com") {
		t.Fatalf("邮箱主体不得落审计: %s", blob)
	}
	if !strings.Contains(string(blob), `"subject_ref":"`) {
		t.Fatalf("隐去主体时必须留下可关联的截断摘要: %s", blob)
	}
	if strings.Contains(event.String(), "alice@example.com") {
		t.Fatalf("单行日志同样要隐去: %s", event.String())
	}
	// 手机号形态
	phone := event
	phone.Subject = "13800001111"
	phoneBlob, err := json.Marshal(phone)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(phoneBlob), "13800001111") {
		t.Fatalf("手机号形态的主体不得落审计: %s", phoneBlob)
	}
}
