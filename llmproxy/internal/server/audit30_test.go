package server

// 请求期取证留痕的三类必测（2026-10-04 决策包第 6 条，接线侧取 C）。
//
// 断言盯的是这一档特有的四类越界：
//   - 把处置事实记成观察数据（影子/legacy 也落行）；
//   - detail 里出现正文（审计表是 §2.9 规则 6 唯一的自由文本位）；
//   - 缺省形态也落行（审计表被养成第二张流量表，§6 点名的体积代价）；
//   - 留痕写不进去时**照常出网**（锁定口径：任何降级不得绕过权限或隐私策略）。
//
// 归属（scope）单独钉一次：三条动作共用 requestAuditScope30，规则写错等于按范围导不出。

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/processor"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// ---------------------------------------------------------------- 夹具

// auditChat 发一条内容与模型都由用例指定的转发请求（测泄漏就要控制内容）。
func auditChat(t *testing.T, h *harness, requestID, model, content string) (*http.Response, []byte) {
	t.Helper()
	payload := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":%q}]}`, model, content)
	req, err := http.NewRequest(http.MethodPost, h.gateway.URL+"/v1/chat/completions", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-local")
	req.Header.Set("X-Request-Id", requestID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

// auditRows 读某个范围最近的审计（写侧全部是同步的，所以不需要等）。
func auditRows(t *testing.T, h *harness, scope policy.ScopeRef, action string) []store.ScopedAuditEntry {
	t.Helper()
	all, err := h.db.AuditRecentByScope(scope, 200)
	if err != nil {
		t.Fatalf("读审计失败: %v", err)
	}
	var out []store.ScopedAuditEntry
	for _, e := range all {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

// decodeDetail 把 detail 解回结构体：断言字段集合比断言子串更结实 ——
// 换成手拼字符串的写法时，多一个少一个字段都可能悄悄发生。
func decodeDetail[T any](t *testing.T, e store.ScopedAuditEntry) T {
	t.Helper()
	var out T
	if err := json.Unmarshal([]byte(e.Detail), &out); err != nil {
		t.Fatalf("detail 不是预期结构: %v\n%s", err, e.Detail)
	}
	return out
}

// egressRowsFor 按 request_id 取某一条出网留痕（why 是分类位）。
func egressRowsFor(t *testing.T, h *harness, requestID, why string) []store.ScopedAuditEntry {
	t.Helper()
	var out []store.ScopedAuditEntry
	for _, row := range auditRows(t, h, policy.SystemScope, auditActionEgressAllow30) {
		d := decodeDetail[egressDetail30](t, row)
		if d.RequestID == requestID && d.Why == why {
			out = append(out, row)
		}
	}
	return out
}

// sidecarEcho 是一个把收到的请求体原样记下来的 sidecar。
func sidecarEcho(t *testing.T) (*httptest.Server, func() string) {
	t.Helper()
	var last string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		last = string(raw)
		fmt.Fprint(w, `{"allowed":true,"short_code":"ok"}`)
	}))
	t.Cleanup(srv.Close)
	return srv, func() string { return last }
}

// procYAMLWithLevel 按给定档位拼配置。只在 policy 段上替换，不动整份 YAML ——
// provider 行里也有一个 "max_data_level: internal"，按子串换会先命中它，
// 于是「改档位」悄悄改成了上游的承接上限，被测的那一维压根没动。
func procYAMLWithLevel(upstreamURL, mode, level string) string {
	return cfgYAML(map[string]string{"vendorA": upstreamURL}, []string{"sk-local"}) +
		strings.Replace(policySection(mode, "t-open", "system:gateway", 1),
			"data_level: internal", "data_level: "+level, 1)
}

// ---------------------------------------------------------------- 拒绝证据

// enforce 下的一次真实拒绝要能按范围问回来「哪条规则拒的、当时哪一版生效」。
func TestAudit30DenyEvidence(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce")

	resp, body := auditChat(t, h, "req-audit-deny", "secret-model", piiSample)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("secret-model 应被拒，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	// 2026-10-05 裁决 16′ 的正反两面写在这一条里：下游那一句不带规则标识，
	// 而**同一次**拒绝的审计行必须照旧带 —— 只断言前者会把取证面拆掉，
	// 只断言后者会漏掉这次收窄要防的外泄。
	if strings.Contains(string(body), "命中规则") {
		t.Errorf("403 文案不得含命中规则选择器（规则标识只给管理侧）: %s", body)
	}
	if !strings.Contains(string(body), "拒绝（") || !strings.Contains(string(body), "策略版本 t-open@1") {
		t.Errorf("403 文案仍要给结论码与生效版本，实际 %s", body)
	}

	rows := auditRows(t, h, policy.SystemScope, auditActionPolicyDeny30)
	if len(rows) != 1 {
		t.Fatalf("一次拒绝应有 1 条 policy.deny，实际 %d", len(rows))
	}
	row := rows[0]
	if row.Target != "model:secret-model" {
		t.Errorf("target = %q，want model:secret-model", row.Target)
	}
	d := decodeDetail[denyDetail30](t, row)
	if d.RequestID != "req-audit-deny" {
		t.Errorf("detail.request_id = %q", d.RequestID)
	}
	if d.Reason == "" || !policy.Reason(d.Reason).Valid() {
		t.Errorf("reason 必须是注册过的稳定码，实际 %q", d.Reason)
	}
	if d.PolicyVersion != "t-open@1" {
		t.Errorf("policy_version = %q，want t-open@1（取证要指着当时生效的那一版）", d.PolicyVersion)
	}
	if d.Mode != "enforce" {
		t.Errorf("mode = %q，want enforce", d.Mode)
	}
	if d.Winner == nil || d.Winner.Resource != "model:secret-model" || d.Winner.Effect != "deny" {
		t.Fatalf("winner 必须指出决定性规则，实际 %+v", d.Winner)
	}
	// 泄漏断言：正文是这条请求唯一的内容，它出现在任何一位都是事故。
	for _, forbidden := range []string{"someone@example.com", "13800138000", "我的邮箱"} {
		if strings.Contains(row.Detail, forbidden) {
			t.Errorf("detail 不得含正文片段 %q: %s", forbidden, row.Detail)
		}
	}
}

// 影子与 legacy 一条都不落：那次拒绝没有作用到任何请求上，
// 落进审计等于把观察数据写成处置事实（与 §2.8「影子不构成回放证据」同一条口径）。
func TestAudit30ShadowWritesNoRequestEvidence(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "shadow")

	if resp, body := auditChat(t, h, "req-audit-shadow", "secret-model", piiSample); resp.StatusCode != http.StatusOK {
		t.Fatalf("影子不得改变结果: %d %s", resp.StatusCode, body)
	}
	if n := len(auditRows(t, h, policy.SystemScope, auditActionPolicyDeny30)); n != 0 {
		t.Errorf("影子下不该有 policy.deny，实际 %d 条", n)
	}
	if n := len(auditRows(t, h, policy.SystemScope, auditActionEgressAllow30)); n != 0 {
		t.Errorf("影子下不该有 egress.allow，实际 %d 条（3.0 没参与这次出网就不该宣称授权过）", n)
	}
}

// ---------------------------------------------------------------- 出网授权

// internal 内容出网到承接得住它的上游：留痕要说清「凭什么这份内容能出网」。
func TestAudit30EgressDataLevelEvidence(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce")

	resp, body := auditChat(t, h, "req-audit-level", "gpt-4o", piiSample)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应正常转发，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if n := up.count(); n != 1 {
		t.Fatalf("留痕不该挡住出网，上游实际收到 %d 次", n)
	}

	rows := egressRowsFor(t, h, "req-audit-level", egressWhyDataLevel)
	if len(rows) != 1 {
		t.Fatalf("一发上游交换应有 1 条分级出网留痕，实际 %d", len(rows))
	}
	d := decodeDetail[egressDetail30](t, rows[0])
	if d.Provider != "vendorA" {
		t.Errorf("provider = %q", d.Provider)
	}
	if d.DataLevel != "internal" || d.ProviderMaxLevel != "internal" {
		t.Errorf("两个级别字段各说一件事，实际 content=%q ceiling=%q", d.DataLevel, d.ProviderMaxLevel)
	}
	// 执行器字段要说真话：enforce 下这一发（非流式）真的由 F 执行器委托承载，
	// 记的就是注册名而不是兜底值。exchangeLegacyXport 那一支由
	// TestAudit30DetailSizeIsBounded 直接调 auditEgressDataLevel30 时显式覆盖。
	if d.Executor != policyExecutorOpenAI {
		t.Errorf("executor = %q，want %q（enforce 非流式这发由 F 执行器承载）", d.Executor, policyExecutorOpenAI)
	}
	if d.AllowRawBody {
		t.Errorf("这一条不是在说原文，allow_raw_body 不得为真")
	}
	if d.PolicyVersion != "t-open@1" {
		t.Errorf("policy_version = %q", d.PolicyVersion)
	}
	if n := len(egressRowsFor(t, h, "req-audit-level", egressWhyRawBody)); n != 0 {
		t.Errorf("链上没有原文授权声明时不该有 raw_body 行，实际 %d", n)
	}
	for _, forbidden := range []string{"someone@example.com", "13800138000"} {
		if strings.Contains(rows[0].Detail, forbidden) {
			t.Errorf("detail 不得含正文片段 %q: %s", forbidden, rows[0].Detail)
		}
	}
}

// public 内容出网就是流量本身：requests 表逐条记着 provider 与结果码，
// 再写一遍只是把审计表撑成第二张流量表 —— 这条断言守着「只记非缺省」那道闸。
func TestAudit30PublicContentWritesNoEgressRow(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := newHarness(t, procYAMLWithLevel(up.url(), "enforce", "public"))
	writePolicyBundle(t, h, policyBundleOpen)

	resp, body := auditChat(t, h, "req-audit-public", "gpt-4o", piiSample)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应正常转发，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if n := len(auditRows(t, h, policy.SystemScope, auditActionEgressAllow30)); n != 0 {
		t.Errorf("public 出网不该留痕，实际 %d 条", n)
	}
	// 流量本身仍然记着：删掉的是重复留痕，不是证据。
	if got := recentRecord(t, h, "req-audit-public").Provider; got != "vendorA" {
		t.Errorf("requests 表应记到 provider，实际 %q", got)
	}
}

// 原文授权被真的消费时（sidecar 收到未脱敏正文）留一条 raw_body。
func TestAudit30RawBodyGrantEvidence(t *testing.T) {
	sidecar, sidecarBody := sidecarEcho(t)
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("scan", processor.TypeSidecar, "before-route", "inspect-body", map[string]string{
			"allow_raw_body":    "true",
			"allowed_endpoints": fmt.Sprintf(`[%q]`, sidecar.URL+"/v1/scan"),
		}))
	writeProcParam(t, h, "scan", fmt.Sprintf(`{"endpoint":%q}`, sidecar.URL+"/v1/scan"))
	// 换成带原文授权的那套包（t-open 同名，内容里多一条带期限的 body.raw allow）。
	writePolicyBundle(t, h, policyBundleDenyWithRawGrant)

	resp, body := auditChat(t, h, "req-audit-raw", "gpt-4o", piiSample)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("授权成立时应正常转发，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	// 先钉住「这条留痕描述的事实真的发生了」：原文确实出了网关。
	if sent := sidecarBody(); !strings.Contains(sent, "13800138000") {
		t.Fatalf("sidecar 应收到原文（否则这条 raw_body 在冒充没发生过的事）: %s", truncateMsg(sent, 300))
	}

	rows := egressRowsFor(t, h, "req-audit-raw", egressWhyRawBody)
	if len(rows) != 1 {
		t.Fatalf("应恰好 1 条原文授权留痕，实际 %d", len(rows))
	}
	d := decodeDetail[egressDetail30](t, rows[0])
	if d.Processor != "scan" {
		t.Errorf("processor = %q，want scan（target 指着它）", d.Processor)
	}
	if rows[0].Target != "processor:scan" {
		t.Errorf("target = %q", rows[0].Target)
	}
	if !d.AllowRawBody {
		t.Error("raw_body 行的 allow_raw_body 必须为真")
	}
	if grant := policy.Reason(d.GrantReason); !grant.Valid() || grant != policy.ReasonExplicitAllow {
		t.Errorf("grant_reason = %q，want explicit_allow（通配放行不算授权）", d.GrantReason)
	}
	if d.DataLevel != "internal" {
		t.Errorf("data_level = %q", d.DataLevel)
	}
	if strings.Contains(rows[0].Detail, "13800138000") || strings.Contains(rows[0].Detail, "someone@example.com") {
		t.Errorf("原文出了网，但留痕本身一个字都不许带: %s", rows[0].Detail)
	}
	// 同一次请求里两个非缺省事实各留一条，互不冒充。
	if n := len(egressRowsFor(t, h, "req-audit-raw", egressWhyDataLevel)); n != 1 {
		t.Errorf("分级出网那一条应独立存在，实际 %d", n)
	}
}

// 声明了 allow_raw_body 却没授权：403 之外还要钉「不留痕」。
// 留痕是给「凭什么能出网」的，把没发生的授权写成一条记录比不写更糟。
func TestAudit30RawBodyWithoutGrantLeavesNoRow(t *testing.T) {
	sidecar, _ := sidecarEcho(t)
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("scan", processor.TypeSidecar, "before-route", "inspect-body", map[string]string{
			"allow_raw_body":    "true",
			"allowed_endpoints": fmt.Sprintf(`[%q]`, sidecar.URL+"/v1/scan"),
		}))
	writeProcParam(t, h, "scan", fmt.Sprintf(`{"endpoint":%q}`, sidecar.URL+"/v1/scan"))

	resp, body := auditChat(t, h, "req-audit-nogrant", "gpt-4o", piiSample)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("未授权应 403，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if n := len(egressRowsFor(t, h, "req-audit-nogrant", egressWhyRawBody)); n != 0 {
		t.Errorf("未授权不得留 egress.allow，实际 %d 条", n)
	}
}

// ---------------------------------------------------------------- 归属与体积

// 三条动作共用一条归属规则：用户名下按 user:<名>，静态 key 按 system:global。
// 归属写错的代价不是报错，是「按范围导的时候导不到」（§2.7 规则 2）。
func TestAudit30RequestScopeMapping(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "system:global"},
		{"   ", "system:global"},
		{"alice", "user:alice"},
		// 带冒号的名字成不了 scope id（老库里旁路写进来的脏名字就是这一类）：
		// 退到全局并留下 actor 原值，也比「这条证据根本没写过」好。
		{"team:alpha", "system:global"},
	} {
		if got := requestAuditScope30(tc.in).Display(); got != tc.want {
			t.Errorf("requestAuditScope30(%q) = %s，want %s", tc.in, got, tc.want)
		}
	}

	// 用户范围的那一条要真能按范围读回来（写进去读不到等于没写）。
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce")
	user, err := policy.NewScopeRef(policy.ScopeUser, "alice")
	if err != nil {
		t.Fatal(err)
	}
	shot := &policyShot{
		resource: "model:secret-model",
		Version:  "t-open@1",
		Decision: policy.Decision{Reason: policy.ReasonDenyRule},
	}
	h.srv.auditPolicyDeny30(user, "alice", "req-audit-user", shot)
	rows := auditRows(t, h, user, auditActionPolicyDeny30)
	if len(rows) != 1 || rows[0].Actor != "alice" {
		t.Fatalf("user:alice 范围应读到 1 条 actor=alice，实际 %+v", rows)
	}
	if n := len(auditRows(t, h, policy.SystemScope, auditActionPolicyDeny30)); n != 0 {
		t.Errorf("同一条不该同时落在两个范围上（两处都记 = 两个真值源）: %d", n)
	}
}

// detail 的体积是这条决策的代价项：字段集合固定，唯一会变长的 Reasons 有上限。
// 这里同时把实测值打在日志里，交付说明引用的是同一个数字。
func TestAudit30DetailSizeIsBounded(t *testing.T) {
	// 真实注册过的原因码，取够 14 个来触发封顶：夹具要是自己编一个不存在的码，
	// 断言就只在测自己了。
	many := []policy.Reason{
		policy.ReasonDenyRule, policy.ReasonNoMatchingRule, policy.ReasonModelNotAllowed,
		policy.ReasonIdentityMissing, policy.ReasonIdentityExpired, policy.ReasonIdentityNotYet,
		policy.ReasonContextInvalid, policy.ReasonEntitlementExpired, policy.ReasonConditionUnmet,
		policy.ReasonScopeMismatch, policy.ReasonDataLevelDenied, policy.ReasonRegionDenied,
		policy.ReasonRawBodyGrantMissing, policy.ReasonPolicyVersionMissing,
	}
	shot := &policyShot{
		resource: "model:secret-model",
		Version:  "t-open@1",
		Decision: policy.Decision{Reason: policy.ReasonDenyRule, Reasons: many},
	}
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce")
	h.srv.auditPolicyDeny30(policy.SystemScope, "alice", "req-audit-size", shot)

	rows := auditRows(t, h, policy.SystemScope, auditActionPolicyDeny30)
	if len(rows) != 1 {
		t.Fatalf("应有 1 条，实际 %d", len(rows))
	}
	d := decodeDetail[denyDetail30](t, rows[0])
	if len(d.Reasons) != denyReasonsCap30 {
		t.Errorf("reasons 必须封顶在 %d 条，实际 %d", denyReasonsCap30, len(d.Reasons))
	}
	if !d.ReasonsCut {
		t.Error("截断必须显式声明，不能悄悄少写")
	}
	for _, c := range d.Reasons {
		if !policy.Reason(c).Valid() {
			t.Errorf("detail 只许装注册过的稳定码，实际 %q", c)
		}
	}
	if size := len(rows[0].Detail); size > 2048 {
		t.Errorf("单条 detail 超过 2 KiB（%d 字节），审计表会被体积拖垮", size)
	} else {
		t.Logf("实测 policy.deny detail = %d 字节（封顶 %d 条原因）", size, denyReasonsCap30)
	}

	// 出网那条同样有界：字段集合固定，没有自由文本位。
	if err := h.srv.auditEgressDataLevel30(policy.SystemScope, "alice", "req-audit-size", shot,
		"vendorA", "internal", exchangeLegacyXport); err != nil {
		t.Fatalf("写留痕失败: %v", err)
	}
	if probe := auditRows(t, h, policy.SystemScope, auditActionEgressAllow30); len(probe) != 1 {
		t.Fatalf("应有 1 条出网留痕，实际 %d", len(probe))
	} else if size := len(probe[0].Detail); size > 1024 {
		t.Errorf("单条 egress.allow detail 超过 1 KiB（%d 字节）", size)
	} else {
		t.Logf("实测 egress.allow detail = %d 字节", size)
	}
}

// ---------------------------------------------------------------- 写不进去时

// 审计库不可用（这里用 db=nil 表达，与真故障同一条返回路径）时：
// 出网那两条必须拒发，一个字节都不许离开网关。
func TestAudit30EgressFailsClosed(t *testing.T) {
	sidecar, _ := sidecarEcho(t)
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("scan", processor.TypeSidecar, "before-route", "inspect-body", map[string]string{
			"allow_raw_body":    "true",
			"allowed_endpoints": fmt.Sprintf(`[%q]`, sidecar.URL+"/v1/scan"),
		}))
	writeProcParam(t, h, "scan", fmt.Sprintf(`{"endpoint":%q}`, sidecar.URL+"/v1/scan"))
	writePolicyBundle(t, h, policyBundleDenyWithRawGrant)

	// 原文授权这一条先单独验：留痕写不进去 → 处理器一次也不被调用（原文没出网）。
	h.srv.db = nil
	resp, body := auditChat(t, h, "req-audit-failclosed-raw", "gpt-4o", piiSample)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("留痕写不进去应 503，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if got := errorKind(t, body); got != "audit_unavailable" {
		t.Errorf("错误类型 = %q，want audit_unavailable（不能归成 processor_unavailable 让运维去查 sidecar）", got)
	}
	if strings.Contains(string(body), "13800138000") {
		t.Errorf("回话不得带正文: %s", body)
	}
	if n := up.count(); n != 0 {
		t.Errorf("正文不该打到上游，实际 %d 次", n)
	}

	// 分级出网那一条排在 transport 之前：同一次 db=nil 下也发不出去。
	// 这里换一条没有原文声明的链，保证失败来自分级留痕而不是上一条路径。
	up2 := startProcUpstream(t, procJSON("pong"))
	h2 := procHarness(t, up2.url(), "enforce")
	h2.srv.db = nil
	if resp2, body2 := auditChat(t, h2, "req-audit-failclosed-level", "gpt-4o", piiSample); resp2.StatusCode != http.StatusServiceUnavailable ||
		errorKind(t, body2) != "audit_unavailable" {
		t.Fatalf("分级出网留痕失败也应 503/audit_unavailable，实际 %d: %s", resp2.StatusCode, truncateMsg(string(body2), 200))
	}
	if n := up2.count(); n != 0 {
		t.Errorf("留痕失败的那一发不该出网，实际 %d 次", n)
	}
}

// 拒绝那条反过来：请求已经被拒了，留痕写不进去**不能**把它改成放行。
// 两处方向相反，共同点是「审计状态永不改变安全结论」。
func TestAudit30DenyStaysDeniedWhenAuditFails(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce")
	h.srv.db = nil

	resp, _ := auditChat(t, h, "req-audit-deny-nodb", "secret-model", piiSample)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("审计写不进去也不能把拒绝变成放行，实际 %d", resp.StatusCode)
	}
	if n := up.count(); n != 0 {
		t.Errorf("被拒的请求不该打到上游，实际 %d 次", n)
	}
}
