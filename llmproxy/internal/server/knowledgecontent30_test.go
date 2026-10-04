package server

// 正文通道接线的三类必测（决策包 §8.1「配置开关 + kb-context-inject」）。
//
// 断言全部盯「接线会犯的错」：E 包自己那 22 条已经证明处理器逻辑成立，这里要守的是
// 把协议、策略包、审计库与出网 transport 拼起来时能漏的那几道：
//   - 开关关着却照样出网取正文（第一道锁失效）；
//   - 白名单只覆盖交付端点，检索那一发成了旁路；
//   - 没有管理员授权时仍然去问知识源（未授权请求不得出网）；
//   - 源侧交付失败时把「拿到几篇算几篇」当结果（部分结果 = fail_open 的入口）；
//   - 审计写不进去却把正文交付了出去（绕过审计的快捷路径）；
//   - 正文进了 prompt 却同时进了审计 detail / 日志 / 回话（§2.9 规则 6）。
//
// 夹具刻意走真实的两个 httptest 端点而不是注入 fake 交付器：交付器是接线自己造的，
// 「端点、协议版本、预算字段、摘要锚定到底有没有真的发出去」只有把 HTTP 打一遍才知道。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/knowledge"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/processor"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// ---------------------------------------------------------------- 夹具

// policyBundleKBContent 在检索包的基础上补两道正文授权，都带到期时刻：
// knowledge.content（正文能不能进上下文）与 body.raw（检索词原文能不能出网）。
//
// 主体一律写**显式名字**而不是 `*`：A 包对这两道的口径是「通配 default_allow 不算授权」
// （internal/policy/resolver.go 的 AllowsRawBody/AllowsKnowledgeContent），
// 写成 `*` 会让每一发都在判定处被拒，而拒因看起来是「管理员没授权」——
// 夹具要给的是「授权齐了」这一侧，越权那一侧由 knowledge.content 缺席的用例负责。
//
// alice 对应用户 token 的链，gateway 对应静态 key 的链（两条都要能过门，
// 区别只在正文交付那一步有没有 user 范围可归属）。
const policyBundleKBContent = `
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
  - subject: alice
    resource: "knowledge.content"
    action: read
    effect: allow
    expires_at: "2030-01-01T00:00:00Z"
  - subject: alice
    resource: "body.raw"
    action: read
    effect: allow
    expires_at: "2030-01-01T00:00:00Z"
  - subject: gateway
    resource: "knowledge.content"
    action: read
    effect: allow
    expires_at: "2030-01-01T00:00:00Z"
  - subject: gateway
    resource: "body.raw"
    action: read
    effect: allow
    expires_at: "2030-01-01T00:00:00Z"
`

// 只给 knowledge.content、没有 body.raw：两道锁各自独立，缺后者时委托请求
// 不许带原文检索词（而协议没有「送脱敏检索词」形态，所以整条取正文必须停）。
const policyBundleKBContentNoRaw = `
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
  - subject: alice
    resource: "knowledge.content"
    action: read
    effect: allow
    expires_at: "2030-01-01T00:00:00Z"
`

// kbDeliverStub 是协议形态合规的正文交付端点。
type kbDeliverStub struct {
	srv    *httptest.Server
	mu     sync.Mutex
	reqs   []knowledge.ContentRequest
	status int
	// wrongDigest 非空时用它替换应答里的摘要（模拟「交的是另一份字节」）。
	wrongDigest bool
	// noRule 模拟源侧不报判定依据（协议里这一位必填）。
	noRule bool
}

func startKBDeliverStub(t *testing.T) *kbDeliverStub {
	t.Helper()
	st := &kbDeliverStub{}
	st.srv = httptest.NewServer(http.HandlerFunc(st.handle))
	t.Cleanup(st.srv.Close)
	return st
}

func (st *kbDeliverStub) url() string { return st.srv.URL }

func (st *kbDeliverStub) calls() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.reqs)
}

func (st *kbDeliverStub) lastReq(t *testing.T) knowledge.ContentRequest {
	t.Helper()
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.reqs) == 0 {
		t.Fatal("交付端点一次都没收到请求")
	}
	return st.reqs[len(st.reqs)-1]
}

func (st *kbDeliverStub) handle(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var req knowledge.ContentRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	st.mu.Lock()
	st.reqs = append(st.reqs, req)
	failed := st.status != 0
	wrong := st.wrongDigest
	noRule := st.noRule
	st.mu.Unlock()

	if err := req.Validate(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if failed {
		w.WriteHeader(st.status)
		return
	}
	resp := knowledge.ContentResponse{
		ProtocolVersion: knowledge.ContentProtocolVersion,
		RequestID:       req.RequestID,
		AclVersion:      "acl-1",
		EvaluatedAt:     time.Now().UTC(),
	}
	for _, ask := range req.Documents {
		body := []byte("正文内容-" + ask.SourceID)
		digest := ask.ExpectedDigest
		if wrong {
			digest = knowledge.Digest([]byte("另一份字节"))
		}
		ruleID := "rule-deliver-1"
		if noRule {
			ruleID = ""
		}
		resp.Passages = append(resp.Passages, knowledge.Passage{
			SourceID:      ask.SourceID,
			KnowledgeBase: ask.KnowledgeBase,
			Digest:        digest,
			DataLevel:     policy.LevelInternal.String(),
			RuleID:        ruleID,
			ExpiresAt:     time.Now().UTC().Add(time.Hour),
			Verbatim:      body,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// kbContentSetup 是一份正文通道用例的输入。字段全部具名，因为两个 bool
// 排在一起（switchOn/grants）在任何一行调用里都读不出谁是谁。
type kbContentSetup struct {
	upstream string
	search   string
	deliver  string
	// switchOn 写 knowledge_sources[].return_raw_body。
	switchOn bool
	// bundle 是本用例的策略包内容（空则用 policyBundleKBContent）。
	bundle string
	mode   string
	decls  []string
	// endpointList 覆盖声明的 allowed_endpoints（nil = 两个端点都写）。
	endpointList []string
	// params 是运行参数文件内容（空则不写文件，走「参数文件可选」那条支路）。
	params string
	// failClosed 写进声明。
	failClosed bool
	// declScope 是声明的命中范围：正文注入的声明禁止全局命中（Spec.Validate 只接受
	// kind:id 或 kind:*，因为每次命中都要做一次准入判定、一次可能出网的委托和一条
	// egress.allow 留痕），所以夹具必须给一个。缺省 user:alice 对应用户 token 那条链；
	// 静态 key 的链上只有 system:gateway，要测「无法归属」就换成它。
	declScope string
}

func (s kbContentSetup) harness(t *testing.T) *muHarness {
	t.Helper()
	src := cfgYAML(map[string]string{"vendorA": s.upstream}, []string{"sk-local"})
	if s.mode != "" {
		src += policySection(s.mode, "t-open", "system:gateway", 1)
	}
	src += "knowledge_sources:\n" +
		"  - name: t-src\n" +
		"    endpoint: " + s.search + "\n" +
		"    knowledge_bases: [kb-open]\n" +
		"    timeout_ms: 3000\n" +
		"    max_response_bytes: 65536\n"
	if s.switchOn {
		src += "    return_raw_body: true\n" +
			"    delivery_endpoint: " + s.deliver + "\n"
	}
	if len(s.decls) > 0 {
		src += "processors:\n" + strings.Join(s.decls, "")
	}
	h := newMUHarnessWith(t, src)
	bundle := s.bundle
	if bundle == "" {
		bundle = policyBundleKBContent
	}
	writePolicyBundle(t, h.harness, bundle)
	if s.params != "" {
		writeProcParam(t, h.harness, "inject", s.params)
	}
	return h
}

// kbContentDecl 拼一条 kb-context-inject 声明。
func kbContentDecl(s kbContentSetup) string {
	list := s.endpointList
	if list == nil {
		list = []string{s.search, s.deliver}
	}
	parts := make([]string, 0, len(list))
	for _, ep := range list {
		parts = append(parts, fmt.Sprintf("%q", ep))
	}
	scope := s.declScope
	if scope == "" {
		scope = "user:alice"
	}
	return procDecl("inject", processor.TypeKnowledgeContextInject, "before-upstream", "transform-body",
		map[string]string{
			"scope":             fmt.Sprintf("%q", scope),
			"allow_raw_body":    "true",
			"allowed_endpoints": "[" + strings.Join(parts, ", ") + "]",
			"fail_closed":       fmt.Sprintf("%t", s.failClosed),
			"max_output_bytes":  "65536",
		})
}

// kbContentChat 以**用户 token** 发一条模型请求（正文注入只发生在有主体的请求上）。
func kbContentChat(t *testing.T, h *muHarness, token, requestID, content string) (*http.Response, []byte) {
	t.Helper()
	payload := fmt.Sprintf(`{"model":"gpt-4o","messages":[{"role":"user","content":%q}]}`, content)
	req, err := http.NewRequest(http.MethodPost, h.gateway.URL+"/v1/chat/completions", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Request-Id", requestID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

// kbContentUser 建用户并把夹具里那个假上游挂成她自己的 provider。
//
// 为什么必须挂：这批用例的关键证据是「上游到底收到了什么字节」，而多用户网关下用户
// token 走自带 key 那条路 —— 没有用户级 provider 时请求在路由处就 502 了，
// 处理器那一跳根本没跑，断言会退化成「什么都没发生」的空证。
func kbContentUser(t *testing.T, h *muHarness, name, upstream string) string {
	t.Helper()
	token := h.addUser(t, name)
	h.addProvider(t, name, name+"-up", upstream+"/v1", "sk-"+name, `["*"]`)
	return token
}

func kbContentRows(t *testing.T, h *muHarness, user string) []store.ScopedAuditEntry {
	t.Helper()
	rows, err := h.db.AuditRecentByScope(policy.MustScope(policy.ScopeUser, user), 200)
	if err != nil {
		t.Fatalf("读审计: %v", err)
	}
	var out []store.ScopedAuditEntry
	for _, row := range rows {
		if row.Action == kbContentAuditAction {
			out = append(out, row)
		}
	}
	return out
}

// kbContentEgressRows 按 request_id 取原文出网授权留痕。
//
// 归属范围必须跟着主体走而不是统一查 system：traceRawBodyGrant30 用的是
// requestAuditScope30(actor)，用户 token 落 user:<名字>、静态 key 落 system:gateway。
// 借 egressRowsFor（只查 system）会在用户用例上报出「一条也没有」，而那条留痕其实写了。
func kbContentEgressRows(t *testing.T, h *muHarness, user, requestID string) []store.ScopedAuditEntry {
	t.Helper()
	ref := policy.SystemScope
	if user != "" {
		ref = policy.MustScope(policy.ScopeUser, user)
	}
	var out []store.ScopedAuditEntry
	for _, row := range auditRows(t, h.harness, ref, auditActionEgressAllow30) {
		d := decodeDetail[egressDetail30](t, row)
		if d.RequestID == requestID && d.Why == egressWhyRawBody {
			out = append(out, row)
		}
	}
	return out
}

// ---------------------------------------------------------------- 正常路径

// 开关开 + 两道授权齐 + 白名单覆盖两个端点：正文必须真的进上游请求体，
// 而留痕要说得出「哪几篇、多少字节、依据什么」。
func TestKbContentInjectDeliversIntoUpstreamBody(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	search := startKBStub(t)
	deliver := startKBDeliverStub(t)

	setup := kbContentSetup{upstream: up.url(), search: search.url(), deliver: deliver.url(),
		switchOn: true, mode: "enforce", failClosed: true, params: `{"max_passages":2,"max_total_bytes":4096}`}
	setup.decls = []string{kbContentDecl(setup)}
	h := setup.harness(t)
	token := kbContentUser(t, h, "alice", setup.upstream)

	resp, body := kbContentChat(t, h, token, "req-kbc-ok", "报销标准是什么")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应正常转发，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 300))
	}

	sent := up.last(t)
	if !strings.Contains(sent, "retrieved_context-") {
		t.Errorf("上游没收到注入块: %s", truncateMsg(sent, 400))
	}
	if !strings.Contains(sent, "正文内容-doc-kb-open") {
		t.Errorf("上游没收到知识正文: %s", truncateMsg(sent, 400))
	}

	// 检索那一发：原文检索词只在授权成立时才出现，而 max_results 与篇数预算同额。
	sreq := search.lastReq(t)
	if !sreq.AllowRawTerms || sreq.SearchTerms == "" {
		t.Errorf("委托请求的检索词形态 = allow_raw_terms:%t terms=%q，正文通道要的是原文检索词",
			sreq.AllowRawTerms, sreq.SearchTerms)
	}
	if sreq.MaxResults != 2 {
		t.Errorf("max_results = %d，应该与 max_passages 同额（多问的篇目只会放大检索面积）", sreq.MaxResults)
	}
	if sreq.Purpose != kbPurpose || sreq.PolicyVersion != "t-open@1" {
		t.Errorf("委托上下文 purpose/version = %q/%q", sreq.Purpose, sreq.PolicyVersion)
	}

	// 交付那一发：申请的篇目必须来自检索结果，预算来自声明。
	dreq := deliver.lastReq(t)
	if len(dreq.Documents) != 1 || dreq.Documents[0].KnowledgeBase != "kb-open" {
		t.Fatalf("交付申请篇目 = %+v", dreq.Documents)
	}
	if dreq.Documents[0].SourceID != "doc-kb-open" || dreq.Documents[0].ExpectedDigest == "" {
		t.Errorf("交付申请必须带源侧给过的标识与摘要: %+v", dreq.Documents[0])
	}
	if dreq.MaxPassages != 2 || dreq.MaxTotalBytes != 4096 {
		t.Errorf("交付预算 = %d/%d，想要 2/4096（声明的运行参数没传到）", dreq.MaxPassages, dreq.MaxTotalBytes)
	}
	if !dreq.Deadline.After(time.Now().UTC()) {
		t.Errorf("交付请求的 deadline = %v，必须带剩余预算而不是缺省值", dreq.Deadline)
	}

	rows := kbContentRows(t, h, "alice")
	if len(rows) != 1 {
		t.Fatalf("应恰好 1 条正文交付留痕，实际 %d", len(rows))
	}
	ev := decodeDetail[knowledge.ContentAuditEvent](t, rows[0])
	if ev.DeliveredCount != 1 || ev.DeliveredBytes <= 0 {
		t.Errorf("留痕的交付量 = %d 篇 / %d 字节: %+v", ev.DeliveredCount, ev.DeliveredBytes, ev)
	}
	if ev.RequestID != "req-kbc-ok" || ev.Subject != "alice" || ev.PolicyVersion != "t-open@1" {
		t.Errorf("留痕的归属位 = %+v", ev)
	}
	if rows[0].Target != "t-src" {
		t.Errorf("target = %q，想要源名（多条痕按源区分）", rows[0].Target)
	}
	// §2.9 规则 6：正文只进 prompt，不进留痕也不进回话。检索词同理 —— 用户问的那句话
	// 不该在审计表里再存一份。
	for _, banned := range []string{"正文内容", "报销标准"} {
		if strings.Contains(rows[0].Detail, banned) {
			t.Errorf("审计 detail 里出现了 %q: %s", banned, rows[0].Detail)
		}
	}
	if bytes.Contains(body, []byte("正文内容-")) {
		t.Errorf("回话里出现了知识正文（交付器交的是文档内容，不是应答内容）: %s", truncateMsg(string(body), 300))
	}
	// 原文授权那一发也必须在（两份证据各说一件事，互不冒充）。
	if n := len(kbContentEgressRows(t, h, "alice", "req-kbc-ok")); n != 1 {
		t.Errorf("原文授权留痕应恰好 1 条，实际 %d", n)
	}
}

// 参数文件缺省时预算回落到保守缺省，而不是「不限」或 0。
// 这一条钉的是 procParamFileOptional 那条支路真的把交付器与判定器注上了。
func TestKbContentInjectWithoutParamFileStillRuns(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	search := startKBStub(t)
	deliver := startKBDeliverStub(t)

	setup := kbContentSetup{upstream: up.url(), search: search.url(), deliver: deliver.url(),
		switchOn: true, mode: "enforce", failClosed: true}
	setup.decls = []string{kbContentDecl(setup)}
	h := setup.harness(t)
	token := kbContentUser(t, h, "alice", setup.upstream)

	resp, body := kbContentChat(t, h, token, "req-kbc-no-param", "报销标准是什么")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("没有参数文件也应能注入（预算走保守缺省），实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 300))
	}
	dreq := deliver.lastReq(t)
	if dreq.MaxPassages < 1 || dreq.MaxTotalBytes < 1 {
		t.Errorf("缺省预算 = %d/%d，必须是正数而不是 0 或不限", dreq.MaxPassages, dreq.MaxTotalBytes)
	}
	if !strings.Contains(up.last(t), "retrieved_context-") {
		t.Error("上游没收到注入块")
	}
}

// ---------------------------------------------------------------- 拒绝路径

// 平台开关关着：声明要正文而没有任何源能交付 → 注册期就装配不起来，
// enforce 下命中它的请求被拒，且**一个字节的委托都不出网**。
//
// 这里钉的是「不许悄悄什么都不注入」：那种形态在界面上看起来声明生效、在审计里
// 一条也没有，出了事查不到是开关没开还是链路坏了。
func TestKbContentSwitchOffRefusesWithoutEgress(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	search := startKBStub(t)
	deliver := startKBDeliverStub(t)

	setup := kbContentSetup{upstream: up.url(), search: search.url(), deliver: deliver.url(),
		switchOn: false, mode: "enforce", failClosed: true}
	setup.decls = []string{kbContentDecl(setup)}
	h := setup.harness(t)
	token := kbContentUser(t, h, "alice", setup.upstream)

	resp, body := kbContentChat(t, h, token, "req-kbc-switch-off", "报销标准是什么")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("开关关着时应拒而不是放行未注入正文，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 300))
	}
	if got := errorKind(t, body); got != "processor_unavailable" {
		t.Errorf("错误类型 = %q", got)
	}
	if n := up.count(); n != 0 {
		t.Errorf("被拒的请求不该打到上游，实际 %d 次", n)
	}
	if n := search.calls() + deliver.calls(); n != 0 {
		t.Errorf("开关关着时知识源一侧不该有任何出网，实际 %d 次", n)
	}
}

// 白名单只写交付端点：检索那一发同样是出网，没被覆盖就是旁路 → 注册失败。
func TestKbContentWhitelistMustCoverSearchEndpointToo(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	search := startKBStub(t)
	deliver := startKBDeliverStub(t)

	setup := kbContentSetup{upstream: up.url(), search: search.url(), deliver: deliver.url(),
		switchOn: true, mode: "enforce", failClosed: true,
		// 只报交付入口：这正是要防的那种「白名单看起来写了、其实漏了一半」。
		endpointList: []string{deliver.url()}}
	setup.decls = []string{kbContentDecl(setup)}
	h := setup.harness(t)
	token := kbContentUser(t, h, "alice", setup.upstream)

	resp, body := kbContentChat(t, h, token, "req-kbc-whitelist", "报销标准是什么")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("白名单漏了检索端点应拒，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 300))
	}
	if n := search.calls(); n != 0 {
		t.Errorf("未被白名单覆盖的检索端点一次都不该被连，实际 %d 次", n)
	}
}

// 只有 knowledge.content、没有 body.raw：检索词原文出不去，整条取正文停在判定之前。
// 请求本身照常转发（注入没发生不等于请求违规），而知识源一次都没被问。
func TestKbContentWithoutRawTermsGrantSendsNothing(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	search := startKBStub(t)
	deliver := startKBDeliverStub(t)

	setup := kbContentSetup{upstream: up.url(), search: search.url(), deliver: deliver.url(),
		switchOn: true, mode: "enforce", failClosed: true, bundle: policyBundleKBContentNoRaw,
		params: `{"max_passages":2,"max_total_bytes":4096}`}
	setup.decls = []string{kbContentDecl(setup)}
	h := setup.harness(t)
	token := kbContentUser(t, h, "alice", setup.upstream)

	resp, body := kbContentChat(t, h, token, "req-kbc-no-raw", "报销标准是什么")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("缺授权是「不注入」而不是「拒请求」，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 300))
	}
	if got := up.last(t); strings.Contains(got, "retrieved_context-") {
		t.Errorf("没有授权时不该有任何注入痕迹: %s", truncateMsg(got, 300))
	}
	if n := search.calls() + deliver.calls(); n != 0 {
		t.Errorf("授权不齐时不该有任何委托出网，实际 %d 次", n)
	}
	if n := len(kbContentRows(t, h, "alice")); n != 0 {
		t.Errorf("没有交付动作就不该有正文留痕，实际 %d 条", n)
	}
}

// 静态 key 没有主体：正文交付无法归属（委托协议要求链含 user:<主体>），
// 于是 fail_closed 下拒 —— 而不是退化成「按网关主人的授权取正文」。
//
// 声明这里特意命中 system:gateway（静态 key 的那条链）：命中面是运营逐条圈的，
// 而这条用例要钉的是**命中之后**那一跳 —— 取正文的实现没有「链上没主体就按系统范围
// 问一次」这种兜底。
func TestKbContentStaticKeyFailsClosedWithoutSubject(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	search := startKBStub(t)
	deliver := startKBDeliverStub(t)

	setup := kbContentSetup{upstream: up.url(), search: search.url(), deliver: deliver.url(),
		switchOn: true, mode: "enforce", failClosed: true, declScope: "system:gateway",
		params: `{"max_passages":2,"max_total_bytes":4096}`}
	setup.decls = []string{kbContentDecl(setup)}
	h := setup.harness(t)

	resp, body := procChat(t, h.harness, "req-kbc-static", "报销标准是什么", false)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("共享钥匙下应 fail closed，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 300))
	}
	if n := search.calls() + deliver.calls(); n != 0 {
		t.Errorf("无法归属的主体不该惊动知识源，实际出网 %d 次", n)
	}
}

// ---------------------------------------------------------------- 失败路径

// 交付端点故障 + fail_closed：503，上游一次都不收；fail_open：跳过注入、
// 正文逐字节原样转发。两种形态都不许把「拿到一半」当成结果。
func TestKbContentDeliveryFailureFollowsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name       string
		failClosed bool
		wantStatus int
	}{
		{"fail_closed 即拒", true, http.StatusServiceUnavailable},
		{"fail_open 跳过注入并照常转发", false, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := startProcUpstream(t, procJSON("pong"))
			search := startKBStub(t)
			deliver := startKBDeliverStub(t)
			deliver.status = http.StatusInternalServerError

			setup := kbContentSetup{upstream: up.url(), search: search.url(), deliver: deliver.url(),
				switchOn: true, mode: "enforce", failClosed: tc.failClosed,
				params: `{"max_passages":2,"max_total_bytes":4096}`}
			setup.decls = []string{kbContentDecl(setup)}
			h := setup.harness(t)
			token := kbContentUser(t, h, "alice", setup.upstream)

			resp, body := kbContentChat(t, h, token, "req-kbc-fail", "报销标准是什么")
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d，想要 %d: %s", resp.StatusCode, tc.wantStatus, truncateMsg(string(body), 300))
			}
			if tc.failClosed {
				if n := up.count(); n != 0 {
					t.Errorf("被拒的请求不该打到上游，实际 %d 次", n)
				}
				return
			}
			if got := up.last(t); strings.Contains(got, "retrieved_context-") {
				t.Errorf("fail_open 跳过时正文不该被动过: %s", truncateMsg(got, 300))
			}
			// 失败也必须留痕：否则「正文通路坏了」在审计里与「库里没东西」同形。
			rows := kbContentRows(t, h, "alice")
			if len(rows) != 1 {
				t.Fatalf("交付失败应留 1 条痕，实际 %d", len(rows))
			}
			ev := decodeDetail[knowledge.ContentAuditEvent](t, rows[0])
			if ev.ResultCode == "" || ev.DeliveredCount != 0 {
				t.Errorf("失败留痕 = code=%q delivered=%d", ev.ResultCode, ev.DeliveredCount)
			}
		})
	}
}

// 摘要对不上 = 交的不是申请的那一篇：整篇丢，一条都不进 prompt。
// 这一条钉的是「网关侧兜底」而不是源侧自觉（§2.9 规则 5 的禁止形态是降级绕过隐私策略）。
func TestKbContentDigestMismatchDropsEveryPassage(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	search := startKBStub(t)
	deliver := startKBDeliverStub(t)
	deliver.wrongDigest = true

	setup := kbContentSetup{upstream: up.url(), search: search.url(), deliver: deliver.url(),
		switchOn: true, mode: "enforce", failClosed: true, params: `{"max_passages":2,"max_total_bytes":4096}`}
	setup.decls = []string{kbContentDecl(setup)}
	h := setup.harness(t)
	token := kbContentUser(t, h, "alice", setup.upstream)

	resp, body := kbContentChat(t, h, token, "req-kbc-digest", "报销标准是什么")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("摘要不符应只丢篇目而不是拒请求，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 300))
	}
	sent := up.last(t)
	if strings.Contains(sent, "retrieved_context-") || strings.Contains(sent, "正文内容") {
		t.Errorf("未锚定摘要的字节进了 prompt: %s", truncateMsg(sent, 400))
	}
	if n := len(kbContentRows(t, h, "alice")); n != 1 {
		t.Errorf("交付端点确实被问过，留痕应恰好 1 条，实际 %d", n)
	}
}

// 审计写不进去就不交付：正文通道的每一发出网都要求留痕先落地。
//
// 注意这里被拦下的位置在**原文授权留痕**那一发（traceRawBodyGrant30 在装配期就要写
// egress.allow，而 kb-context-inject 必然声明 allow_raw_body）—— 它比取正文更早。
// 所以这条钉的是不变量「审计库不可用时正文字节不会流向任何一侧」，
// 而不是「一定是交付环节报的错」；换交付环节的写法需要先造一个只缺审计的中间态，
// 那需要给存储层开测试后门，不值得为一条已经成立的不变量开。
func TestKbContentAuditFailureBlocksEgress(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	search := startKBStub(t)
	deliver := startKBDeliverStub(t)

	setup := kbContentSetup{upstream: up.url(), search: search.url(), deliver: deliver.url(),
		switchOn: true, mode: "enforce", failClosed: true, params: `{"max_passages":2,"max_total_bytes":4096}`}
	setup.decls = []string{kbContentDecl(setup)}
	h := setup.harness(t)
	token := kbContentUser(t, h, "alice", setup.upstream)

	// 摘掉审计库：写留痕的每一发都会失败。
	h.srv.db = nil

	resp, body := kbContentChat(t, h, token, "req-kbc-noaudit", "报销标准是什么")
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("审计写不进去时不该照常交付正文: %s", truncateMsg(string(body), 300))
	}
	if n := up.count(); n != 0 {
		t.Errorf("被拒的请求不该打到上游，实际 %d 次", n)
	}
	if n := search.calls() + deliver.calls(); n != 0 {
		t.Errorf("留痕失败后不该有任何出网，实际 %d 次", n)
	}
}

// ---------------------------------------------------------------- 装配事实

// 交付器报出的出网端点必须同时含检索与交付两个入口，且只含**开了开关**的源。
// 白名单校验的对象就是这一份枚举，它少一项等于那一发没人管。
func TestKbContentEndpointsEnumerateBothEntrypoints(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	search := startKBStub(t)
	deliver := startKBDeliverStub(t)

	// 两个源：一个开正文、一个只检索。
	src := cfgYAML(map[string]string{"vendorA": up.url()}, []string{"sk-local"})
	src += policySection("enforce", "t-open", "system:gateway", 1)
	src += "knowledge_sources:\n" +
		"  - name: t-on\n    endpoint: " + search.url() + "\n" +
		"    knowledge_bases: [kb-open]\n    timeout_ms: 3000\n    max_response_bytes: 65536\n" +
		"    return_raw_body: true\n    delivery_endpoint: " + deliver.url() + "\n" +
		"  - name: t-off\n    endpoint: " + search.url() + "/idle\n" +
		"    knowledge_bases: [kb-closed]\n    timeout_ms: 3000\n    max_response_bytes: 65536\n"
	h := newMUHarnessWith(t, src)
	writePolicyBundle(t, h.harness, policyBundleKBContent)

	d := &kbContentDeliverer{s: h.srv, rt: h.srv.policyFor(h.cfgStore.Current())}
	if d.rt == nil {
		t.Fatal("没有策略运行态，装配次序或包文件出了问题")
	}
	got := d.KnowledgeContentEndpoints()
	want := []string{search.url(), deliver.url()}
	sort.Strings(want)
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("出网端点枚举 = %v，想要 %v（只检索的源不该进来，检索入口必须在）", got, want)
	}
	if len(d.contentSources()) != 1 {
		t.Errorf("参与正文交付的源 = %d，想要 1", len(d.contentSources()))
	}
}
