package knowledge

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
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
//
// 口径（2026-10-04 主线裁决正文通道为配置开关之后）：手册 §3.C 原文是
// 「任何结构体都不得持有文档正文」，那句话在开关打开之后不再逐字成立 —— 源侧
// 开了开关就要把原文交给网关。改成三条同样硬、且可执行的说法，一条都不能少：
//  1. 词表照旧全量生效，**唯一**的豁免必须是 contentCarriers 里逐类型逐字段登记的条目；
//  2. 从任何会被序列化（落库、落日志、回客户端）的形状出发，沿 JSON 字段图到不了那个载体；
//  3. 真交过一次正文之后，审计 JSON、单行日志、错误文案、丢弃记录里都不出现那份明文。
//
// 换句话说：守卫没有放松，只是把「不许有正文」换成「正文只能活在登记在册的那一个字段里，
// 并且那个字段在任何能被写下来的路径上都不可达」。
var forbiddenFieldWords = []string{
	"body", "payload", "fulltext", "content", "text", "snippet", "excerpt",
	"paragraph", "raw", "secret", "password", "passwd", "credential", "apikey",
	"api_key", "token", "privatekey", "private_key", "baseurl", "base_url",
	// verbatim 是本包给「文档正文字节」起的唯一字段名（Passage.Verbatim）。
	// 把它列进禁词而不是让载体字段游离在词表外：以后任何类型想用这个名字
	// 都会先撞红，逼作者去登记 —— 新增载体是主线评审事项，不是顺手改一行。
	"verbatim",
}

// contentCarriers 是登记在册的正文载体：类型 → 被豁免的字段名集合。
//
// 为什么是「类型 + 字段」而不是把 verbatim/content 从词表里放行：
// 单看字段名放行，等于允许 Passage 以后再加第二个、第三个正文字段都自动过关；
// 精确到「这个类型的这个字段」，新增字段就必须新增登记，而下面那条用例
// 把登记数量钉死成 1 个类型 1 个字段 —— 多一个都要主线改测试并复核。
var contentCarriers = map[reflect.Type]map[string]bool{
	reflect.TypeOf(Passage{}): {"Verbatim": true},
}

// carrierReason 记录这条豁免成立的**前提**，供失败信息与后来人阅读：
// 豁免不是「这里放行了就安全」，而是「开关 + 管理员授权 + 源侧逐篇再判」三道锁都在场，
// 且这个载体只活在内存里（ClearContent 负责释放）、到不了任何持久面。
const carrierReason = "Passage.Verbatim 是决策包 §8.1 正文通道唯一的内存载体；" +
	"它成立的前提是配置开关 return_raw_body + knowledge.content 授权 + 源侧逐篇再判定三道锁，" +
	"并且 TestContentCarrierIsUnreachableFromPersistedShapes 钉死它不可序列化。"

// 例外说明：
//   - "raw" 只允许出现在 **布尔开关** 字段上（Query.AllowRawTerms /
//     RetrieveRequest.AllowRawTerms）：它是「是否授权携带原文」的标志位，
//     本身不是内容。真正的原文字段叫 SearchTerms，由 BuildRequest 严格门控。
//   - "text" 只允许出现在 FakeDocument 的 IndexedTitle / IndexedText 上，
//     那代表「知识源侧的索引数据」，是本包证明「只需要摘要就能工作」的对照组，
//     不参与任何协议 JSON、引用与审计（本文件下方有专门用例逐条钉死）。
//   - "verbatim" 只允许出现在 contentCarriers 登记的那个字段上。
func isAllowedException(owner reflect.Type, field reflect.StructField, word string) bool {
	switch word {
	case "raw":
		return field.Type.Kind() == reflect.Bool
	case "text":
		return false // FakeDocument 整体不参与本扫描，见 fakeStructReason
	case "verbatim":
		return contentCarriers[owner][field.Name]
	}
	return false
}

// fakeStructReason 记录源侧模拟类型不参与词法扫描的理由。
const fakeStructReason = "FakeDocument 是知识源侧的索引条目（模拟对端数据库）、FakeRetriever 是对端进程本身，" +
	"两者都不属于委托协议与网关侧结构，因此整体不参与本扫描（不是按字段开特例）；" +
	"FakeDocument 的明文（IndexedTitle / IndexedText）与原文交付选择器（VerbatimBy / VerbatimRuleID）" +
	"只用于算摘要与源侧判定，FakeRetriever 里的 content* 私有字段只是缺陷模拟开关与调用记录（不含字节）。" +
	"网关从这两类拿到的东西一律要过协议校验与逐条判定，那部分由 scannedStructs 覆盖，" +
	"并由 TestFakeNeverPutsPlaintextOnTheWire 与 TestContentChannelKeepsPlaintextInOneCarrierOnly 逐条钉死。"

// scannedStructs 是必须通过词法扫描的结构体集合：协议、引用、审计、失败与结果，
// 以及正文通道（§8.1）那一整套 —— 载体自己也必须进扫描，豁免才是「登记过的一个字段」
// 而不是「整个类型没被查过」。
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
		HTTPRetriever{},
		// 正文通道。
		ContentAsk{},
		ContentRequest{},
		Passage{},
		ContentResponse{},
		ContentOutcome{},
		ContentAuditEvent{},
	}
}

// 下面几个探针把「只有指针/函数字段」的结构体也纳入扫描（结构体本身不含明文，
// 但字段名同样要过词法关，否则「Endpoint 换成 BaseURL」就绕过了扫描）。
func retrievalErrorSample() any { return RetrievalError{} }

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
		t.Fatalf("协议/审计结构体里存在未登记的正文字段:\n%s", strings.Join(scanner.violations, "\n"))
	}
	if scanner.visited < 150 {
		t.Fatalf("词法扫描覆盖的字段过少（%d），说明递归没有真正展开嵌套结构", scanner.visited)
	}
	assertCarrierRegistry(t)
	t.Logf("词法扫描覆盖 %d 个字段（下限 150）", scanner.visited)
	// FakeDocument 单独说明理由，避免读者以为扫描漏了它
	t.Log(fakeStructReason)
	t.Log(carrierReason)
}

// assertCarrierRegistry 把「豁免只有一个类型一个字段」写成断言而不是注释。
//
// 三条都要钉住，缺任何一条豁免都会悄悄扩大：
//   - 数量：登记项 >1 个类型或 >1 个字段 = 有人新增载体而没走评审；
//   - 存在性：登记的字段必须真的在那个类型上（改过名却留着登记 = 豁免给了一个不存在的字段，
//     而真正的新字段反而自由放行）；
//   - 形态：豁免字段必须是 []byte。string 无法清零，§2.9 规则 2 的「处理完立即释放」
//     落不了地，所以载体只许是可清零的字节切片。
func assertCarrierRegistry(t *testing.T) {
	t.Helper()
	if len(contentCarriers) != 1 {
		t.Fatalf("正文载体类型必须恰好登记 1 个，当前 %d 个：新增载体要走主线评审并同步 §8.1", len(contentCarriers))
	}
	for typ, fields := range contentCarriers {
		if len(fields) != 1 {
			t.Fatalf("%s 的豁免字段必须恰好 1 个，当前 %d 个", typ, len(fields))
		}
		for name, ok := range fields {
			if !ok {
				t.Fatalf("%s.%s 登记位为 false，等于登记了一个空豁免", typ, name)
			}
			field, found := typ.FieldByName(name)
			if !found {
				t.Fatalf("登记的载体字段 %s.%s 不存在：豁免指向了一个不存在的字段，"+
					"真实正文字段反而不受约束", typ, name)
			}
			if field.Type != reflect.TypeOf([]byte(nil)) {
				t.Fatalf("载体字段 %s.%s 必须是 []byte（可清零），当前 %s：%s",
					typ, name, field.Type, carrierReason)
			}
		}
	}
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
		Verbatim []byte `json:"verbatim"`
	}
	var scanner fieldScanner
	scanner.seen = map[reflect.Type]bool{}
	scanner.walk(reflect.TypeOf(badCitation{}), "")
	got := strings.Join(scanner.violations, "\n")
	for _, want := range []string{"Body", "Snippet", "APIKey", "Payload", "Excerpt", "Verbatim"} {
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

// TestSecondCarrierFieldOnTheCarrierIsCaught 是最贴近真实越界形状的三组对照：
//  1. 豁免精确到「类型 + 字段名」：换一个类型抄一份 Verbatim 照样红，
//     否则豁免就退化成「这个字段名整个免检」；
//  2. 登记在册的 Passage 必须绿，证明豁免真的生效而不是注释里写着好看；
//  3. 载体的字段清单是钉死的：在 Passage 上加一个改名叫 Plain 的正文字段，
//     词法关看不见它（[]byte 不在词表里），但字段集钉子会红 ——
//     新增载体字段必须同时改这条用例，也就是必须过一次评审。
func TestSecondCarrierFieldOnTheCarrierIsCaught(t *testing.T) {
	type badPassage struct {
		SourceID string `json:"source_id"`
		Verbatim []byte `json:"verbatim"`
	}
	var scanner fieldScanner
	scanner.seen = map[reflect.Type]bool{}
	scanner.walk(reflect.TypeOf(badPassage{}), "")
	// 这个类型不在 contentCarriers 里，所以连 Verbatim 都不该被豁免。
	if !strings.Contains(strings.Join(scanner.violations, "\n"), ".Verbatim（") {
		t.Fatalf("未登记类型上的 Verbatim 必须红，否则豁免变成了按字段名放行：\n%v", scanner.violations)
	}

	// 登记类型上的同名字段则必须绿（否则豁免本身失效）。
	var real fieldScanner
	real.seen = map[reflect.Type]bool{}
	real.walk(reflect.TypeOf(Passage{}), "")
	if len(real.violations) != 0 {
		t.Fatalf("已登记载体 Passage 不该有违规: %v", real.violations)
	}

	// 载体字段集的钉子：Passage 的字段清单是这份豁免的边界，改它必须显式改这里。
	got := passageFieldNames()
	want := []string{"AclVersion", "DataLevel", "DecisionReason", "Digest", "ExpiresAt",
		"KnowledgeBase", "RuleID", "SourceID", "TitleDigest", "Verbatim"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("载体字段集变了，必须逐条评审：\n当前 %v\n登记 %v", got, want)
	}
}

// passageFieldNames 按字典序列出 Passage 的字段名（供字段集钉子比对）。
func passageFieldNames() []string {
	typ := reflect.TypeOf(Passage{})
	out := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		out = append(out, typ.Field(i).Name)
	}
	sort.Strings(out)
	return out
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
			if isAllowedException(typ, field, word) {
				continue
			}
			s.violations = append(s.violations, fmt.Sprintf(
				"%s.%s（json=%q）命中禁用词 %q：除 contentCarriers 登记的载体字段外，本包结构体不得持有文档正文或凭证",
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

// persistedShapes 是会被写进审计表、单行日志、错误文案或客户端响应的那些形状。
//
// 口径与词法扫描不同层：词法扫描问「字段叫什么」，这条问「能不能走到载体」。
// 一条 `Audit Passages []Passage json:"passages"` 的字段名完全合规（passages 不在词表里），
// 但它会把整份正文顺着审计 JSON 写进库里 —— 只有可达性检查拦得住这种形状。
//
// ContentResponse 不在这里：它是源侧→网关的入站协议外壳，开关打开时本来就带正文；
// 网关不落库、不转发它，而「谁把它挂进审计结构」正是这条用例要立刻红的场景。
func persistedShapes() []any {
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
		KnowledgeBaseDenial{},
		retrievalErrorSample(),
		ContentAsk{},
		ContentRequest{},
		ContentOutcome{},
		ContentAuditEvent{},
	}
}

// jsonFieldSerializes 报告字段是否会被 encoding/json 写出去。
// 未导出字段与 json:"-" 都不落盘，因此不构成可达路径。
func jsonFieldSerializes(field reflect.StructField) bool {
	if field.PkgPath != "" {
		return false
	}
	tag := field.Tag.Get("json")
	if tag == "-" || strings.HasPrefix(tag, "-,") {
		return false
	}
	switch field.Type.Kind() {
	case reflect.Func, reflect.Chan, reflect.Interface, reflect.UnsafePointer:
		return false // 函数/通道不参与序列化；接口字段的实际类型不在类型图里，交给运行时用例兜
	}
	return true
}

// contentCarrierPath 沿 JSON 字段图寻找登记载体，返回命中的路径。
func contentCarrierPath(typ reflect.Type, path string, seen map[reflect.Type]bool) (string, bool) {
	if typ == nil || seen[typ] {
		return "", false
	}
	seen[typ] = true
	switch typ.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Array, reflect.Map:
		return contentCarrierPath(typ.Elem(), path+"[]", seen)
	case reflect.Struct:
	default:
		return "", false
	}
	if contentCarriers[typ] != nil {
		return path, true
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !jsonFieldSerializes(field) {
			continue
		}
		if hit, ok := contentCarrierPath(field.Type, path+"."+field.Name, seen); ok {
			return hit, true
		}
	}
	return "", false
}

func TestContentCarrierIsUnreachableFromPersistedShapes(t *testing.T) {
	for _, sample := range persistedShapes() {
		typ := reflect.TypeOf(sample)
		if typ == nil {
			t.Fatalf("%T 是 nil 样本，可达性检查会空转", sample)
		}
		if typ.Kind() != reflect.Struct {
			t.Fatalf("持久面样本必须是结构体，当前 %s", typ)
		}
		if path, ok := contentCarrierPath(typ, typ.Name(), map[reflect.Type]bool{}); ok {
			t.Fatalf("%s 沿 JSON 字段图能到达正文载体（路径 %s）：\n"+
				"这意味着这份形状一旦被序列化就带上文档原文，审计表/日志/客户端响应里会有正文。\n"+
				"载体只许活在内存里（Passage.ClearContent），要落库请落摘要与字节数。\n"+
				carrierReason, typ, path)
		}
	}

	// 载体对 JSON 的不可达是靠 ContentOutcome.Passages 的 "-" 标签实现的：
	// 标签一旦有人改成可序列化，上面的可达性检查会红，这里再给一条指名字段的解释。
	field, ok := reflect.TypeOf(ContentOutcome{}).FieldByName("Passages")
	if !ok {
		t.Fatal("ContentOutcome.Passages 不存在：交付结果形状变了，请同步 §8.1 与守卫")
	}
	if tag := field.Tag.Get("json"); tag != "-" {
		t.Fatalf("ContentOutcome.Passages 的 json 标签必须是 \"-\"（当前 %q）："+
			"结果对象要整体落审计旁路与回放记录，正文字段必须靠标签挡在序列化之外", tag)
	}

	// 反向对照一：把载体挂进审计形状必须被抓到，否则这条守卫是空转。
	type badAudit struct {
		RequestID string    `json:"request_id"`
		Passages  []Passage `json:"passages"`
	}
	if _, ok := contentCarrierPath(reflect.TypeOf(badAudit{}), "badAudit", map[reflect.Type]bool{}); !ok {
		t.Fatal("可达性检查没抓到 badAudit.Passages：形同虚设")
	}
	// 反向对照二：ContentResponse 确实能到达载体（证明递归真的在走嵌套字段），
	// 而它不在持久面样本里 —— 两条合起来才说明「抓得到但没让它进持久面」。
	if _, ok := contentCarrierPath(reflect.TypeOf(ContentResponse{}), "ContentResponse", map[reflect.Type]bool{}); !ok {
		t.Fatal("ContentResponse 应能到达载体：抓不到说明递归没展开嵌套结构")
	}
}

// TestContentChannelKeepsPlaintextInOneCarrierOnly 是运行时兜底：真的交过一次正文之后，
// 明文只许出现在登记载体那一个字段里，其余形状一律查不到。
//
// 词法扫描和可达性检查都是静态的；这条用例证明三道锁之外没有第四份副本
// （Display()、审计 JSON、单行日志、失败错误文案、丢弃记录都实际跑一遍）。
func TestContentChannelKeepsPlaintextInOneCarrierOnly(t *testing.T) {
	fake := NewFakeRetriever(docWithVerbatim(
		fakeDoc("doc-3", kbHR, ownerOrg(), policy.LevelInternal, secretBody, "subject:"+subjectAlice),
		"content-rule-doc-3", "subject:"+subjectAlice))
	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)
	admitted := []ReturnedDocument{admittedWithBody("doc-3", kbHR, policy.LevelInternal, secretBody)}

	outcome, err := DeliverContents(context.Background(), fake, rc, scope, admitted,
		DefaultContentPassages, DefaultContentBytes, now)
	if err != nil {
		t.Fatalf("交付失败: %v", err)
	}
	if len(outcome.Passages) != 1 {
		t.Fatalf("应当交付 1 篇: %+v", outcome.Dropped)
	}
	// 明文确实在载体里（否则下面的「到处都查不到」只是因为根本没交付成功）
	if got := string(outcome.Passages[0].Verbatim); got != secretBody {
		t.Fatalf("载体必须持有交付的字节，当前 %q", got)
	}
	if !outcome.HasContent() {
		t.Fatal("HasContent 是「这次开过正文」的唯一判据")
	}
	if outcome.Audit.ResultCode != ReasonContentOK || outcome.Audit.DeliveredCount != 1 ||
		outcome.Audit.DeliveredBytes != len(secretBody) {
		t.Fatalf("交付审计计数不符: %+v", outcome.Audit)
	}
	if err := outcome.Audit.Validate(); err != nil {
		t.Fatalf("交付审计形态不合法: %v", err)
	}

	outcomeBlob, err := json.Marshal(outcome)
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeak(t, "ContentOutcome JSON", string(outcomeBlob))
	auditBlob, err := json.Marshal(outcome.Audit)
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeak(t, "交付审计 JSON", string(auditBlob))
	assertNoLeak(t, "交付审计单行日志", outcome.Audit.String())
	assertNoLeak(t, "载体 Display", outcome.Passages[0].Display())
	dropBlob, err := json.Marshal(outcome.Dropped)
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeak(t, "丢弃记录 JSON", string(dropBlob))

	// 审计里那份摘要必须能与载体对上（否则「交付过哪一篇」无从复盘），
	// 但对上的必须是摘要而不是明文。
	if len(outcome.Audit.DeliveredDigests) != 1 ||
		outcome.Audit.DeliveredDigests[0] != DigestString(secretBody) {
		t.Fatalf("交付审计必须留摘要: %+v", outcome.Audit.DeliveredDigests)
	}

	// 失败路径：源侧错误文案里带明文时，网关只能留稳定码。
	failing := NewFakeRetriever().WithContentFault(
		fmt.Errorf("deliver failed: upstream leaked (%s)", secretBody))
	failOutcome, err := DeliverContents(context.Background(), failing, rc, scope, admitted,
		DefaultContentPassages, DefaultContentBytes, now)
	if err == nil {
		t.Fatal("交付失败必须返回错误")
	}
	if len(failOutcome.Passages) != 0 {
		t.Fatalf("失败必须 fail_closed 成「没有正文」: %+v", failOutcome.Passages)
	}
	assertNoLeak(t, "交付失败错误文案", err.Error())
	assertNoLeak(t, "交付失败审计", failOutcome.Audit.String())
	assertNoLeak(t, "交付失败审计 JSON", mustMarshal(t, failOutcome.Audit))
	if failOutcome.Failure.Reason != ReasonUnavailable {
		t.Fatalf("未分类交付错误应归为 %s: %+v", ReasonUnavailable, failOutcome.Failure)
	}
}

// TestDroppedPassageContentIsZeroed 钉死 §2.9 规则 2「处理完立即释放」：
// 没被留下的正文必须被清零，而不是等 GC 或等调用方忘记这件事。
func TestDroppedPassageContentIsZeroed(t *testing.T) {
	// 用既有的泄露标记：留下的那篇交对了摘要，丢掉的那篇交的是**另一篇的字节**。
	const goodBody = secretBody
	const droppedBody = rivalBody

	rc, now := liveContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)
	admitted := []ReturnedDocument{
		admittedWithBody("doc-1", kbHandbook, policy.LevelInternal, goodBody),
		admittedWithBody("doc-2", kbHandbook, policy.LevelInternal, secretBody),
	}

	var delivered ContentResponse
	fake := NewFakeRetriever().WithContentHook(func(_ context.Context, req ContentRequest) (ContentResponse, error) {
		delivered = ContentResponse{
			ProtocolVersion: ContentProtocolVersion,
			RequestID:       req.RequestID,
			AclVersion:      "fake-acl-v1",
			// doc-2 那份的字节与准入摘要不符 → 整篇丢弃
			Passages: []Passage{
				contentPassage("doc-1", kbHandbook, policy.LevelInternal, goodBody, "content-rule-doc-1"),
				contentPassage("doc-2", kbHandbook, policy.LevelInternal, droppedBody, "content-rule-doc-2"),
			},
		}
		return delivered, nil
	})

	outcome, err := DeliverContents(context.Background(), fake, rc, scope, admitted,
		DefaultContentPassages, DefaultContentBytes, now)
	if err != nil {
		t.Fatalf("交付失败: %v", err)
	}
	if len(outcome.Passages) != 1 || string(outcome.Passages[0].Verbatim) != goodBody {
		t.Fatalf("只该留下摘要对得上的那一篇: %+v", outcome.Dropped)
	}
	if len(outcome.Dropped) != 1 || outcome.Dropped[0].Reason != ReasonContentDigestMismatch {
		t.Fatalf("不符摘要的那篇应记 %s: %+v", ReasonContentDigestMismatch, outcome.Dropped)
	}
	// delivered 与 DeliverContents 内部的 resp 共享同一个底层数组，
	// 所以这里能直接看到「网关有没有把丢掉的那份清零」。
	if len(delivered.Passages) != 2 {
		t.Fatalf("钩子记录的交付条数应为 2: %+v", delivered.Passages)
	}
	dropped := delivered.Passages[1]
	if len(dropped.Verbatim) != 0 {
		t.Fatalf("被丢弃篇目的正文必须清零并释放引用，当前长度 %d", len(dropped.Verbatim))
	}
	if dropped.Digest == "" || dropped.SourceID != "doc-2" {
		t.Fatalf("清零只抹字节，标识与依据要留着（丢弃记录才追得回来）: %+v", dropped)
	}
	assertNoLeak(t, "清零后的交付形状", mustMarshal(t, delivered.Passages[1]))
}
