package server

// §3.C 检索委托接线的三类必测（手册要求：正常路径 / 拒绝路径 / 失败路径）。
//
// 断言全部盯「接线会犯的错」，而不是 C 包自己的功能（那些在 internal/knowledge 测过）：
//   - 准入判定绕过策略内核，或客户端递来的库名把候选集放大（§3.C 禁止项）；
//   - 被拒的库仍然出网（未授权请求不得出网）；
//   - 源侧失败时把部分结果当成可读结果（fail_open 的入口）；
//   - 检索词原文进委托请求、进审计、进回话（§2.9 规则 4/6）；
//   - 静态 key 退化成「按 system 范围检索」（把网关主人的授权借给共享钥匙）；
//   - 审计落不进去却把结果交付了（绕过审计的快捷路径，§8 DoD 6）。

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/knowledge"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// ---------------------------------------------------------------- 夹具

// policyBundleKB 是知识检索用的包：放行 kb-open、显式拒 kb-closed，模型一律放行。
//
// id 沿用 t-open：版本串就是 t-open@1，与被复用的 writePolicyBundle 夹具保持一致，
// 断言里盯版本串的那些用例不用改。
const policyBundleKB = `
id: t-open
version: 1
scope: system:gateway
entitlements:
  - subject: "*"
    resource: "model:*"
    action: use
    effect: allow
  - subject: "*"
    resource: "knowledge:kb-open"
    action: read
    effect: allow
  - subject: "*"
    resource: "knowledge:kb-closed"
    action: read
    effect: deny
`

// kbYAML 拼出「多用户 + 可选策略段 + 一个知识源」的配置。
//
// 两个库一起声明（kb-open / kb-closed），这样「策略拒了但源侧本来有文档」这条
// 最危险的越权路径有地方可测。
//
// 供应商补 max_data_level：multiUserYAML 那份没有它，而 policy.mode 不是 legacy 时
// 配置加载会直接拒掉已启用的供应商 —— 缺分级不能按最宽松处理。
func kbYAML(endpoint, mode string) string {
	src := strings.Replace(multiUserYAML,
		"    weight: 1\n",
		"    weight: 1\n    max_data_level: internal\n", 1)
	if mode != "" {
		src += policySection(mode, "t-open", "system:gateway", 1)
	}
	src += "knowledge_sources:\n" +
		"  - name: t-src\n" +
		"    endpoint: " + endpoint + "\n" +
		"    knowledge_bases: [kb-open, kb-closed]\n" +
		"    timeout_ms: 1500\n" +
		"    max_response_bytes: 65536\n"
	return src
}

// kbStub 是一个按委托协议应答的假知识源。
//
// 它刻意走 HTTP 而不是注入 fake retriever：接线层负责造委托客户端，
// 那正是「端点、超时、体积上限有没有真的生效」唯一可测的形态。
type kbStub struct {
	srv    *httptest.Server
	mu     sync.Mutex
	reqs   []knowledge.RetrieveRequest
	docs   func(req knowledge.RetrieveRequest) []knowledge.ReturnedDocument
	status int
	delay  time.Duration
	// echoID 非空时用它当响应里的 request_id（模拟串号：不是 req.RequestID 就是协议不符）。
	echoID string
}

func startKBStub(t *testing.T) *kbStub {
	t.Helper()
	st := &kbStub{}
	st.srv = httptest.NewServer(http.HandlerFunc(st.handle))
	t.Cleanup(st.srv.Close)
	return st
}

func (st *kbStub) url() string { return st.srv.URL }

func (st *kbStub) handle(w http.ResponseWriter, r *http.Request) {
	if st.delay > 0 {
		time.Sleep(st.delay)
	}
	raw, _ := io.ReadAll(r.Body)
	var req knowledge.RetrieveRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	st.mu.Lock()
	st.reqs = append(st.reqs, req)
	st.mu.Unlock()

	if err := req.Validate(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if st.status != 0 {
		w.WriteHeader(st.status)
		return
	}
	docs := st.docs
	if docs == nil {
		docs = func(q knowledge.RetrieveRequest) []knowledge.ReturnedDocument {
			out := make([]knowledge.ReturnedDocument, 0, len(q.KnowledgeBases))
			for _, kb := range q.KnowledgeBases {
				out = append(out, kbDoc(kb, "doc-"+kb, policy.LevelInternal.String()))
			}
			return out
		}
	}
	echo := st.echoID
	if echo == "" {
		echo = req.RequestID
	}
	resp := knowledge.RetrieveResponse{
		ProtocolVersion: knowledge.ProtocolVersion,
		RequestID:       echo,
		Documents:       docs(req),
		AclVersion:      "acl-1",
		EvaluatedAt:     time.Now().UTC(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (st *kbStub) calls() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.reqs)
}

// lastReq 返回源侧收到的最后一个委托请求（断言要看的是「到底发出去了什么」）。
func (st *kbStub) lastReq(t *testing.T) knowledge.RetrieveRequest {
	t.Helper()
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.reqs) == 0 {
		t.Fatal("知识源一次都没收到委托请求")
	}
	return st.reqs[len(st.reqs)-1]
}

// kbDoc 是一篇协议形态合规的可读文档。
func kbDoc(kb, sourceID, level string) knowledge.ReturnedDocument {
	return knowledge.ReturnedDocument{
		SourceID:      sourceID,
		KnowledgeBase: kb,
		// 归属写成 system + gateway：C 包的跨组织兜底对 system 归属跳过范围检查，
		// 于是「库白名单 + 分级上限」这两条硬约束成为唯一变量，用例能各测各的。
		// owner_id 不能留空 —— coversOwner 在按 kind 分流之前先 Validate 整个范围引用。
		OwnerKind:   string(policy.ScopeSystem),
		OwnerID:     "gateway",
		DataLevel:   level,
		Digest:      knowledge.Digest([]byte("正文内容-" + sourceID)),
		TitleDigest: knowledge.TitleDigest("标题-" + sourceID),
		Allowed:     true,
		RuleID:      "rule-test-1",
	}
}

func kbHarness(t *testing.T, endpoint, mode string) *muHarness {
	t.Helper()
	return kbHarnessWithConfig(t, kbYAML(endpoint, mode))
}

// kbHarnessWithConfig 收整份配置：需要改知识源字段（例如把 timeout_ms 收紧）的用例
// 走这里，而不是往夹具里加参数 —— 夹具的参数集一旦开始为单个用例让路就没法读了。
func kbHarnessWithConfig(t *testing.T, src string) *muHarness {
	t.Helper()
	h := newMUHarnessWith(t, src)
	if strings.Contains(src, "policy:") {
		writePolicyBundle(t, h.harness, policyBundleKB)
	}
	return h
}

// kbBudgetYAML 同 kbYAML，但把委托预算换成给定值。
func kbBudgetYAML(endpoint, mode string, timeoutMs int) string {
	return strings.Replace(kbYAML(endpoint, mode), "timeout_ms: 1500",
		fmt.Sprintf("timeout_ms: %d", timeoutMs), 1)
}

// kbSearch 发一次自助检索，返回状态码与解析后的回话。
func kbSearch(t *testing.T, h *muHarness, token string, body map[string]any) (int, map[string]any) {
	t.Helper()
	resp, raw := h.post(t, "/v1/_me/knowledge/search", token, body)
	var out map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

func kbAudit(t *testing.T, h *muHarness, user string) []store.ScopedAuditEntry {
	t.Helper()
	rows, err := h.db.AuditRecentByScope(policy.MustScope(policy.ScopeUser, user), 50)
	if err != nil {
		t.Fatalf("回读审计: %v", err)
	}
	var out []store.ScopedAuditEntry
	for _, row := range rows {
		if row.Action == kbAuditAction {
			out = append(out, row)
		}
	}
	return out
}

// ---------------------------------------------------------------- 正常路径

func TestKnowledgeSearchDelegatesAdmittedKBOnly(t *testing.T) {
	stub := startKBStub(t)
	h := kbHarness(t, stub.url(), "shadow")
	token := h.addUser(t, "alice")

	status, out := kbSearch(t, h, token, map[string]any{"query": "报销标准是什么", "knowledge_bases": []string{"kb-open"}})
	if status != http.StatusOK {
		t.Fatalf("status = %d %v", status, out)
	}
	if stub.calls() != 1 {
		t.Fatalf("委托请求应该只发一次，实际 %d 次", stub.calls())
	}
	req := stub.lastReq(t)
	if len(req.KnowledgeBases) != 1 || req.KnowledgeBases[0] != "kb-open" {
		t.Errorf("出网的库集合 = %v，应该只有被点名且被准入的那一个", req.KnowledgeBases)
	}
	if req.Purpose != kbPurpose || req.PolicyVersion != "t-open@1" {
		t.Errorf("委托上下文 purpose/version = %q/%q", req.Purpose, req.PolicyVersion)
	}
	if req.MaxDataLevel != policy.LevelInternal.String() {
		t.Errorf("分级上限 = %q，应该来自 policy.data_level", req.MaxDataLevel)
	}
	hits, _ := out["hit_count"].(float64)
	if hits != 1 {
		t.Fatalf("hit_count = %v，回话 %v", out["hit_count"], out)
	}
	cites, _ := out["citations"].([]any)
	if len(cites) != 1 {
		t.Fatalf("citations = %v", out["citations"])
	}
	cite := cites[0].(map[string]any)
	if cite["source_id"] != "doc-kb-open" || cite["knowledge_base"] != "kb-open" {
		t.Errorf("引用 = %v", cite)
	}
	// 引用只有摘要：标题与正文一个字都不该出现（§2.9 规则 6）。
	for _, banned := range []string{"正文内容", "标题-"} {
		if strings.Contains(string(mustJSON(t, out)), banned) {
			t.Errorf("回话里出现了 %q", banned)
		}
	}
}

func TestKnowledgeListReportsAdmissionPerKB(t *testing.T) {
	stub := startKBStub(t)
	h := kbHarness(t, stub.url(), "shadow")
	token := h.addUser(t, "alice")

	resp, raw := h.get(t, "/v1/_me/knowledge", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d %s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out["policy_version"] != "t-open@1" {
		t.Errorf("policy_version = %v", out["policy_version"])
	}
	text := string(raw)
	if strings.Contains(text, stub.url()) {
		t.Error("用户面回话里出现了委托端点：库能不能问是用户的事，入口地址不是")
	}
	bases, _ := out["knowledge_bases"].([]any)
	if len(bases) != 2 {
		t.Fatalf("knowledge_bases = %v", out["knowledge_bases"])
	}
	got := map[string]map[string]any{}
	for _, b := range bases {
		row := b.(map[string]any)
		got[row["knowledge_base"].(string)] = row
	}
	if got["kb-open"]["allowed"] != true {
		t.Errorf("kb-open 应该被准入：%v", got["kb-open"])
	}
	if got["kb-closed"]["allowed"] == true {
		t.Errorf("kb-closed 应该被策略拒掉：%v", got["kb-closed"])
	}
	if reason, _ := got["kb-closed"]["reason"].(string); reason == "" {
		t.Error("被拒的库必须带原因码，否则「查不到」只能靠猜")
	}
	srcs, _ := out["sources"].([]any)
	if len(srcs) != 1 || srcs[0].(map[string]any)["status"] != "ready" {
		t.Errorf("sources = %v", out["sources"])
	}
	if stub.calls() != 0 {
		t.Error("清单是只读判定，不该发出任何委托请求")
	}
}

func TestKnowledgeSearchSendsDigestOnlyAndAuditsIt(t *testing.T) {
	stub := startKBStub(t)
	h := kbHarness(t, stub.url(), "enforce")
	token := h.addUser(t, "alice")

	const terms = "裁员赔偿怎么算"
	status, out := kbSearch(t, h, token, map[string]any{"query": terms})
	if status != http.StatusOK {
		t.Fatalf("status = %d %v", status, out)
	}
	req := stub.lastReq(t)
	if req.AllowRawTerms || req.SearchTerms != "" {
		t.Errorf("检索词原文出网了：allow=%t terms=%q", req.AllowRawTerms, req.SearchTerms)
	}
	if want := (knowledge.Query{Terms: terms}).Digest(); req.QueryDigest != want {
		t.Errorf("query_digest = %q，应为 %q", req.QueryDigest, want)
	}

	rows := kbAudit(t, h, "alice")
	if len(rows) != 1 {
		t.Fatalf("应该有 1 条检索审计，实际 %d", len(rows))
	}
	row := rows[0]
	if row.Target != "t-src" {
		t.Errorf("target = %q，应该落在源名上（多源时分不清哪一家）", row.Target)
	}
	if row.Actor != "alice" {
		t.Errorf("actor = %q", row.Actor)
	}
	if strings.Contains(row.Detail, terms) {
		t.Error("检索词原文进了审计（§2.9 正文不落库）")
	}
	var ev knowledge.AuditEvent
	if err := json.Unmarshal([]byte(row.Detail), &ev); err != nil {
		t.Fatalf("审计 detail 不是 AuditEvent 形态: %v", err)
	}
	if ev.ResultCode != knowledge.ReasonOK && ev.ResultCode != knowledge.ReasonNoHits {
		t.Errorf("result_code = %q", ev.ResultCode)
	}
	if ev.QueryDigest == "" || ev.PolicyVersion != "t-open@1" {
		t.Errorf("审计缺摘要/版本: %+v", ev)
	}
	if len(ev.Chain) != 1 || ev.Chain[0].ID != "alice" {
		t.Errorf("chain = %v，检索必须带上归属范围", ev.Chain)
	}
	// kb-closed 被策略拒掉这件事也要留在同一条审计里（AllowedBases 只含被准入的）。
	if len(ev.AllowedBases) != 1 || ev.AllowedBases[0] != "kb-open" {
		t.Errorf("allowed_knowledge_bases = %v", ev.AllowedBases)
	}
}

// ---------------------------------------------------------------- 拒绝路径

func TestKnowledgeSearchNeverEgressesDeniedOrUndeclared(t *testing.T) {
	stub := startKBStub(t)
	h := kbHarness(t, stub.url(), "enforce")
	token := h.addUser(t, "alice")

	status, out := kbSearch(t, h, token, map[string]any{
		"query":           "只能问被拒的库",
		"knowledge_bases": []string{"kb-closed"},
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d %v", status, out)
	}
	if stub.calls() != 0 {
		t.Fatalf("被策略拒掉的库仍然出网了（%d 次委托）", stub.calls())
	}
	denied, _ := out["denied_knowledge_bases"].([]any)
	if len(denied) != 1 {
		t.Fatalf("denied = %v", out["denied_knowledge_bases"])
	}
	if hits, _ := out["hit_count"].(float64); hits != 0 {
		t.Errorf("全拒时 hit_count = %v", hits)
	}
	// 「试过且被全量拒绝」必须留痕：只在回话里出现等于审计上没人查过。
	rows := kbAudit(t, h, "alice")
	if len(rows) != 1 {
		t.Fatalf("被拒的检索也应该有一条留痕，实际 %d", len(rows))
	}
	if rows[0].Target != "-" {
		t.Errorf("未发出委托时 target = %q，应为占位符 -", rows[0].Target)
	}
	var detail map[string]any
	if err := json.Unmarshal([]byte(rows[0].Detail), &detail); err != nil {
		t.Fatalf("detail 不是 JSON: %v", err)
	}
	if detail["result_code"] != knowledge.ReasonNoKnowledgeAllow.String() || detail["delegation"] != "not_sent" {
		t.Errorf("detail = %v", detail)
	}
	if strings.Contains(rows[0].Detail, "只能问被拒的库") {
		t.Error("检索词原文进了审计")
	}
}

func TestKnowledgeSearchRejectsUndeclaredWithoutWidening(t *testing.T) {
	stub := startKBStub(t)
	h := kbHarness(t, stub.url(), "enforce")
	token := h.addUser(t, "alice")

	// 客户端递一个声明段里根本没有的库：它不扩候选，也不出网，但必须被指认。
	status, out := kbSearch(t, h, token, map[string]any{
		"query":           "越权候选",
		"knowledge_bases": []string{"kb-open", "kb-ghost"},
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d %v", status, out)
	}
	undeclared, _ := out["undeclared_knowledge_bases"].([]any)
	if len(undeclared) != 1 || undeclared[0] != "kb-ghost" {
		t.Errorf("undeclared = %v", out["undeclared_knowledge_bases"])
	}
	req := stub.lastReq(t)
	if len(req.KnowledgeBases) != 1 || req.KnowledgeBases[0] != "kb-open" {
		t.Errorf("出网集合 = %v，客户端递的名字不该把候选放大", req.KnowledgeBases)
	}
}

func TestKnowledgeSearchRejectsRawTermsKey(t *testing.T) {
	stub := startKBStub(t)
	h := kbHarness(t, stub.url(), "enforce")
	token := h.addUser(t, "alice")

	// §2.9 规则 4：原文授权只能由管理员策略授予。客户端声明它是越权尝试，
	// 严格解码必须把它指认出来，而不是「忽略未知字段」咽下去。
	status, out := kbSearch(t, h, token, map[string]any{"query": "带原文", "allow_raw_terms": true})
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d %v，应拒绝未知键", status, out)
	}
	if stub.calls() != 0 {
		t.Error("请求体被拒后不该发出任何委托")
	}
}

func TestKnowledgeSearchRequiresIdentity(t *testing.T) {
	stub := startKBStub(t)
	h := kbHarness(t, stub.url(), "enforce")

	// 静态 key 没有主体：C 包要求范围集合含 user:<subject>，所以它落不出检索上下文。
	// 退化成「按 system 范围检索」等于把网关主人的授权借给所有拿钥匙的人。
	resp, raw := h.post(t, "/v1/_me/knowledge/search", "sk-static", map[string]any{"query": "静态钥匙"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d %s", resp.StatusCode, raw)
	}
	if stub.calls() != 0 {
		t.Error("无身份的检索不该触达知识源")
	}
}

func TestKnowledgeEndpointsClosedUnderLegacy(t *testing.T) {
	stub := startKBStub(t)
	h := kbHarness(t, stub.url(), "")
	token := h.addUser(t, "alice")

	// legacy = 没有判定内核。这里必须是「没配好」而不是「没规则所以全放行」（§3.C）。
	for _, path := range []string{"/v1/_me/knowledge"} {
		resp, raw := h.get(t, path, token)
		if resp.StatusCode != http.StatusNotImplemented {
			t.Errorf("GET %s status = %d %s", path, resp.StatusCode, raw)
		}
	}
	if status, out := kbSearch(t, h, token, map[string]any{"query": "遗留模式"}); status != http.StatusNotImplemented {
		t.Errorf("search status = %d %v", status, out)
	}
	if stub.calls() != 0 {
		t.Error("legacy 下不允许发出委托")
	}
}

func TestKnowledgeSearchValidatesInput(t *testing.T) {
	stub := startKBStub(t)
	h := kbHarness(t, stub.url(), "enforce")
	token := h.addUser(t, "alice")

	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{"空检索词", map[string]any{"query": "   "}, http.StatusBadRequest},
		{"超长检索词", map[string]any{"query": strings.Repeat("词", kbMaxQueryBytes)}, http.StatusBadRequest},
		{"结果数为零以下", map[string]any{"query": "x", "max_results": 0}, http.StatusBadRequest},
		{"结果数超上限", map[string]any{"query": "x", "max_results": knowledge.MaxResultsCeiling + 1}, http.StatusBadRequest},
	}
	for _, c := range cases {
		status, _ := kbSearch(t, h, token, c.body)
		if status != c.want {
			t.Errorf("%s: status = %d，应为 %d", c.name, status, c.want)
		}
	}
	if stub.calls() != 0 {
		t.Error("入参不合法时不该有任何委托发出")
	}

	if resp, _ := h.get(t, "/v1/_me/knowledge/unknown", token); resp.StatusCode != http.StatusNotFound {
		t.Errorf("未知子路径 status = %d", resp.StatusCode)
	}
	if resp, _ := h.get(t, "/v1/_me/knowledge/search", token); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET search status = %d，应该只支持 POST", resp.StatusCode)
	}
}

// ---------------------------------------------------------------- 失败路径

func TestKnowledgeSearchSourceFailureIsNotPartialResult(t *testing.T) {
	stub := startKBStub(t)
	stub.status = http.StatusInternalServerError
	h := kbHarness(t, stub.url(), "enforce")
	token := h.addUser(t, "alice")

	status, out := kbSearch(t, h, token, map[string]any{"query": "源侧 500"})
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d %v，全源失败必须是 502 而不是空的 200", status, out)
	}
	if cites, _ := out["citations"].([]any); len(cites) != 0 {
		t.Errorf("失败时仍然交付了引用：%v", cites)
	}
	fails, _ := out["failures"].([]any)
	if len(fails) != 1 {
		t.Fatalf("failures = %v", out["failures"])
	}
	row := fails[0].(map[string]any)
	if row["reason_code"] != knowledge.ReasonUpstreamStatus.String() || row["source"] != "t-src" {
		t.Errorf("failure = %v", row)
	}
	rows := kbAudit(t, h, "alice")
	if len(rows) != 1 {
		t.Fatalf("失败也要留痕，实际 %d 条", len(rows))
	}
	var ev knowledge.AuditEvent
	if err := json.Unmarshal([]byte(rows[0].Detail), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.ResultCode != knowledge.ReasonUpstreamStatus {
		t.Errorf("审计 result_code = %q", ev.ResultCode)
	}
	if strings.Contains(rows[0].Detail, "正文内容") {
		t.Error("失败留痕里出现了内容")
	}
}

func TestKnowledgeSearchProtocolMismatchFailsClosed(t *testing.T) {
	stub := startKBStub(t)
	// 串号：响应的 request_id 与请求不符 → 整份载荷不可信（C 包的 ValidateEnvelope）。
	stub.echoID = "someone-elses-request"
	h := kbHarness(t, stub.url(), "enforce")
	token := h.addUser(t, "alice")

	status, out := kbSearch(t, h, token, map[string]any{"query": "串号响应"})
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d %v", status, out)
	}
	fails, _ := out["failures"].([]any)
	if len(fails) != 1 {
		t.Fatalf("failures = %v", out["failures"])
	}
	if got := fails[0].(map[string]any)["reason_code"]; got != knowledge.ReasonProtocolInvalid.String() {
		t.Errorf("reason_code = %v", got)
	}
}

func TestKnowledgeSearchTimeoutUsesConfiguredBudget(t *testing.T) {
	stub := startKBStub(t)
	stub.delay = 300 * time.Millisecond
	// 把 timeout_ms 收到比源侧延迟小：预算必须真的作用到出网那一层，
	// 而不是只在配置里写着好看。
	h := kbHarnessWithConfig(t, kbBudgetYAML(stub.url(), "enforce", 80))
	token := h.addUser(t, "alice")

	status, out := kbSearch(t, h, token, map[string]any{"query": "超时"})
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d %v", status, out)
	}
	fails, _ := out["failures"].([]any)
	if len(fails) != 1 {
		t.Fatalf("failures = %v", out["failures"])
	}
	if got := fails[0].(map[string]any)["reason_code"]; got != knowledge.ReasonTimeout.String() {
		t.Errorf("reason_code = %v，应为超时", got)
	}
}

func TestKnowledgeSearchLevelCeilingDropsHigherDocs(t *testing.T) {
	stub := startKBStub(t)
	stub.docs = func(req knowledge.RetrieveRequest) []knowledge.ReturnedDocument {
		out := make([]knowledge.ReturnedDocument, 0, len(req.KnowledgeBases))
		for _, kb := range req.KnowledgeBases {
			out = append(out, kbDoc(kb, "doc-confidential", policy.LevelConfidential.String()))
		}
		return out
	}
	h := kbHarness(t, stub.url(), "enforce")
	token := h.addUser(t, "alice")

	status, out := kbSearch(t, h, token, map[string]any{"query": "越级文档"})
	if status != http.StatusOK {
		t.Fatalf("status = %d %v，兜底丢弃不是失败", status, out)
	}
	if hits, _ := out["hit_count"].(float64); hits != 0 {
		t.Errorf("分级上限之上的文档被交付了：%v", out["citations"])
	}
	rows := kbAudit(t, h, "alice")
	if len(rows) != 1 {
		t.Fatalf("审计 %d 条", len(rows))
	}
	var ev knowledge.AuditEvent
	if err := json.Unmarshal([]byte(rows[0].Detail), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.ResultCode != knowledge.ReasonNoHits || ev.DroppedCount != 1 {
		t.Errorf("result_code=%q dropped=%d", ev.ResultCode, ev.DroppedCount)
	}
	if len(ev.DroppedReasons) != 1 || ev.DroppedReasons[0] != knowledge.ReasonLevelExceeded {
		t.Errorf("dropped_reasons = %v", ev.DroppedReasons)
	}
}

func TestKnowledgeAssemblyFailureReportedBySource(t *testing.T) {
	// 端点合法但根本连不上（127.0.0.1:9）：transport 造得出来，装配不报错，
	// 失败发生在委托那一跳 —— 回话必须点名是哪个源，而不是「库里没有」。
	stub := startKBStub(t)
	h := kbHarness(t, "http://127.0.0.1:9/retrieve", "enforce")
	token := h.addUser(t, "alice")

	status, out := kbSearch(t, h, token, map[string]any{"query": "连不上的源"})
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d %v", status, out)
	}
	fails, _ := out["failures"].([]any)
	if len(fails) != 1 || fails[0].(map[string]any)["source"] != "t-src" {
		t.Fatalf("failures = %v", out["failures"])
	}
	if stub.calls() != 0 {
		t.Error("健康的源不该被牵连")
	}
}

// mustJSON 序列化并让失败直接终止用例。
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
