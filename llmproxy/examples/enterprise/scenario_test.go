package enterprise

// 企业集团参考实现的端到端场景测试（与 examples/university 同形）。
//
// 断言的重心是高校示例没有、而企业场景独占的那几条结论：
//  1. **来源条件**：同一个项目范围、两种身份来源，结论必须分开（§0.3 的动机）；
//  2. **范围缺席 + 显式 deny**：合作方不进集团组织范围，另有一条规则把这件事说清楚；
//  3. **两档组织**：集团层发基线，子公司/部门层发各自的模型与知识栏位；
//  4. **数据出境**：境外部署在集团层显式禁止；
//  5. 原文出网授权贯通到处理器、审计只留摘要（与高校示例一致的既有口径）。
//
// 全部用例离线：身份是 fixture，出网目标是注入的假传输，时间钉在 BaseNow。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/routing"
)

// base 补齐一条场景没写的三档分级：生效分级取三档最大值。
func base(s Scenario) Scenario {
	if !s.UserLevel.Valid() {
		s.UserLevel = policy.LevelInternal
	}
	if !s.DetectedLevel.Valid() {
		s.DetectedLevel = policy.LevelPublic
	}
	if !s.KnowledgeLevel.Valid() {
		s.KnowledgeLevel = policy.LevelPublic
	}
	if s.Purpose == "" {
		s.Purpose = PurposeEng
	}
	if s.RequestID == "" {
		s.RequestID = "req-" + s.Fixture + "-" + s.Model
	}
	return s
}

func run(t *testing.T, w *World, s Scenario) *Result {
	t.Helper()
	r, err := w.Run(context.Background(), base(s))
	if err != nil {
		t.Fatalf("场景 %s 跑挂了: %v", s.RequestID, err)
	}
	return r
}

func containsReason(list []policy.Reason, want policy.Reason) bool {
	for _, r := range list {
		if r == want {
			return true
		}
	}
	return false
}

func TestScenarioDecisionMatrix(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name              string
		s                 Scenario
		wantAllowed       bool
		wantReason        policy.Reason
		wantReasonInChain bool
	}{
		{"员工基线（internal）", Scenario{Fixture: "employee-1001", Model: ModelLite},
			true, policy.ReasonGroupAllow, false},
		{"员工基线被分级挡掉", Scenario{Fixture: "employee-1001", Model: ModelLite,
			UserLevel: policy.LevelConfidential}, false, policy.ReasonDataLevelDenied, false},
		{"合作方被显式禁止用内部模型", Scenario{Fixture: "partner-7001", Model: ModelLite},
			false, policy.ReasonModelNotAllowed, true},
		{"合作方碰集团通用模型同样被禁", Scenario{Fixture: "partner-7001", Model: ModelGeneral},
			false, policy.ReasonModelNotAllowed, true},
		{"员工到 confidential 为止", Scenario{Fixture: "employee-1001", Model: ModelGeneral,
			UserLevel: policy.LevelConfidential}, true, policy.ReasonGroupAllow, false},
		{"员工碰 restricted 被挡", Scenario{Fixture: "employee-1001", Model: ModelGeneral,
			UserLevel: policy.LevelRestricted}, false, policy.ReasonDataLevelDenied, false},
		{"集团层境内合规云", Scenario{Fixture: "employee-1001", Model: ModelCloudCn},
			true, policy.ReasonGroupAllow, false},
		{"境外部署集团层显式禁止", Scenario{Fixture: "employee-1001", Model: ModelCloudGlobal},
			false, policy.ReasonModelNotAllowed, true},
		{"子公司层模型按组织范围发放", Scenario{Fixture: "employee-1001", Model: ModelCloudOps},
			true, policy.ReasonGroupAllow, false},
		{"别的部门蹭不到子公司模型", Scenario{Fixture: "manager-2001", Model: ModelCloudOps},
			false, policy.ReasonModelNotAllowed, false},
		{"部门层代码模型发给 group:rnd", Scenario{Fixture: "rnd-4001", Model: ModelCode},
			true, policy.ReasonGroupAllow, false},
		{"实习生不在 group:rnd 里，够不着部门模型", Scenario{Fixture: "intern-5001", Model: ModelCode},
			false, policy.ReasonModelNotAllowed, false},
		{"财务碰 restricted 客户资料模型", Scenario{Fixture: "finance-3001", Model: ModelFinance,
			UserLevel: policy.LevelRestricted}, true, policy.ReasonGroupAllow, false},
		{"研发碰财务模型（缺席即否）", Scenario{Fixture: "rnd-4001", Model: ModelFinance},
			false, policy.ReasonModelNotAllowed, false},
		{"点名授权（explicit 压过组级）", Scenario{Fixture: "finance-3001", Model: ModelPilot},
			true, policy.ReasonExplicitAllow, false},
		{"过期与缺席是两个结论（过期）", Scenario{Fixture: "employee-1001", Model: ModelRetired},
			false, policy.ReasonEntitlementExpired, false},
		{"过期与缺席是两个结论（缺席）", Scenario{Fixture: "manager-2001", Model: ModelRetired},
			false, policy.ReasonModelNotAllowed, false},
		{"目录里没有的模型", Scenario{Fixture: "employee-1001", Model: "no-such-model"},
			false, policy.ReasonModelNotAllowed, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			callsBefore := w.Upstream.calls
			r := run(t, w, c.s)
			if r.Decision.Allowed != c.wantAllowed {
				t.Fatalf("allowed = %v，期望 %v（reason=%v 命中 %d 条）",
					r.Decision.Allowed, c.wantAllowed, r.Decision.Reason, len(r.Decision.Matched))
			}
			if r.Decision.Reason != c.wantReason {
				t.Errorf("reason = %q，期望 %q（原因链 %v）", r.Decision.Reason, c.wantReason, r.Decision.Reasons)
			}
			if c.wantReasonInChain && !containsReason(r.Decision.Reasons, c.wantReason) {
				t.Errorf("原因链里没有 %q: %v", c.wantReason, r.Decision.Reasons)
			}
			if !c.wantAllowed {
				if w.Upstream.calls != callsBefore {
					t.Errorf("被拒场景却发生了 %d 次上游调用", w.Upstream.calls-callsBefore)
				}
				if r.Audit.Status != 0 || r.Audit.HasUsage {
					t.Errorf("被拒场景的审计出现了上游响应事实: %+v", r.Audit)
				}
			}
		})
	}
}

// 来源条件：同一个项目范围，员工与合作方的结论必须分开。
//
// 这是企业示例最该钉死的一条，也是 §0.3 让 `identity_source` 落库的直接动机：
// 事后拿到一条「某人用了 acme-assist」的记录，必须能回答他当时是不是集团自签身份。
// 两个主体都命中 project:client-acme，差别只在 source 一位。
func TestIdentitySourceSeparatesSameScope(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	emp := run(t, w, Scenario{Fixture: "rnd-4001", Model: ModelAcme, RequestID: "req-acme-emp"})
	if !emp.Decision.Allowed {
		t.Fatalf("集团自签身份在 ACME 项目里应能用客户助手: %v %v", emp.Decision.Reason, emp.Decision.Reasons)
	}
	if emp.Audit.Source != SourceEmployee {
		t.Errorf("员工记录的来源 = %q，期望 %q", emp.Audit.Source, SourceEmployee)
	}
	// 交付资料不加来源条件：项目文档本来就该给项目里的人看。
	if d := emp.Resolver.Evaluate(emp.Context, emp.Chain,
		scopedResource(policy.NamespaceKnowledge, KnowledgeAcmeSpec), policy.ActionRead, BaseNow); !d.Allowed {
		t.Errorf("项目成员应能读交付资料: %v", d.Reason)
	}

	part := run(t, w, Scenario{Fixture: "partner-7001", Model: ModelAcme, RequestID: "req-acme-part"})
	if part.Decision.Allowed {
		t.Fatal("合作方在同一个项目范围内也不该拿到客户助手（来源条件应把它挡下）")
	}
	if !containsReason(part.Decision.Reasons, policy.ReasonConditionUnmet) {
		t.Errorf("拒绝原因要指认来源条件本身，而不是一句 model_not_allowed: %v", part.Decision.Reasons)
	}
	if part.Audit.Source != SourcePartner {
		t.Errorf("合作方记录的来源 = %q，期望 %q", part.Audit.Source, SourcePartner)
	}
	// 但交付资料照样读得到：来源条件只加在需要它的那一条规则上。
	if d := part.Resolver.Evaluate(part.Context, part.Chain,
		scopedResource(policy.NamespaceKnowledge, KnowledgeAcmeSpec), policy.ActionRead, BaseNow); !d.Allowed {
		t.Errorf("合作方是项目成员，应能读交付资料: %v", d.Reason)
	}
}

// 客户资料分栏：按部门范围发放，不是按人打标签。
func TestCustomerDataStaysInFinanceAndLegal(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	finance := run(t, w, Scenario{Fixture: "finance-3001", Model: ModelFinance, RequestID: "req-cust-fin"})
	if d := finance.Resolver.Evaluate(finance.Context, finance.Chain,
		scopedResource(policy.NamespaceKnowledge, KnowledgeCustomer), policy.ActionRead, BaseNow); !d.Allowed {
		t.Errorf("财务应能读客户资料: %v", d.Reason)
	}
	legal := run(t, w, Scenario{Fixture: "legal-6001", Model: ModelLite, RequestID: "req-cust-leg"})
	if d := legal.Resolver.Evaluate(legal.Context, legal.Chain,
		scopedResource(policy.NamespaceKnowledge, KnowledgeCustomer), policy.ActionRead, BaseNow); !d.Allowed {
		t.Errorf("法务应能读客户资料: %v", d.Reason)
	}
	rnd := run(t, w, Scenario{Fixture: "rnd-4001", Model: ModelCode, RequestID: "req-cust-rnd"})
	if d := rnd.Resolver.Evaluate(rnd.Context, rnd.Chain,
		scopedResource(policy.NamespaceKnowledge, KnowledgeCustomer), policy.ActionRead, BaseNow); d.Allowed {
		t.Error("研发不该读得到客户资料")
	}
}

// 原文出网授权必须贯通到处理器一侧，而且「没授权」要长成 fail-closed 的样子。
func TestRawBodyGrantReachesProcessor(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	raw := Scenario{Fixture: "manager-2001", Model: ModelGeneral, Purpose: PurposeEng,
		UserLevel: policy.LevelConfidential, IsRawSidecar: true, RequestID: "req-raw-mgr"}
	r := run(t, w, raw)
	if r.PipelineErr != nil {
		t.Fatalf("管理者在内部工程用途下有原文授权，处理器不该失败: %v", r.PipelineErr)
	}
	if !r.IsRawBodyAllow {
		t.Error("策略侧应给出原文授权")
	}
	if got := w.Sink.payload()["content_mode"]; got != "raw" {
		t.Errorf("sidecar 的 content_mode = %v，期望 raw", got)
	}
	if !strings.Contains(string(w.Sink.lastBody), "13900000000") {
		t.Error("原文授权下 sidecar 应看到未脱敏正文")
	}
	// 授权只放开「给 sidecar 的那一份」：上游正文仍必须是掩码文。
	if strings.Contains(string(r.Sent), "13900000000") {
		t.Errorf("发往上游的正文里仍有手机号: %s", r.Sent)
	}

	// 换一个用途就退回最严：授权按 purpose 精确绑定。
	noGrant := run(t, w, Scenario{Fixture: "manager-2001", Model: ModelGeneral, Purpose: PurposeSupport,
		UserLevel: policy.LevelConfidential, IsRawSidecar: true, RequestID: "req-raw-purpose"})
	if noGrant.PipelineErr == nil {
		t.Fatal("换用途后原文授权应失效，处理器必须 fail-closed")
	}
	if !strings.Contains(noGrant.PipelineErr.Error(), string(policy.ReasonRawBodyGrantMissing)) {
		t.Errorf("失败原因要指回策略侧原因码，实际: %v", noGrant.PipelineErr)
	}

	// 普通员工不是 group:managers，没有任何原文授权。
	emp := run(t, w, Scenario{Fixture: "employee-1001", Model: ModelGeneral, Purpose: PurposeEng,
		UserLevel: policy.LevelConfidential, IsRawSidecar: true, RequestID: "req-raw-emp"})
	if emp.IsRawBodyAllow || emp.PipelineErr == nil {
		t.Errorf("无原文授权的 sidecar 必须 fail-closed: allow=%v err=%v", emp.IsRawBodyAllow, emp.PipelineErr)
	}
}

// 确定性：同一输入两次跑出同一份计划，并且回放输入能独立复原它（§2.8）。
func TestRoutingIsDeterministicAndReplayable(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	s := base(Scenario{Fixture: "employee-1001", Model: ModelLite, RequestID: "req-replay-1"})
	first := run(t, w, s)
	second := run(t, w, s)
	if first.RoutingSeed != second.RoutingSeed || first.RoutingSeed == "" {
		t.Fatalf("同输入两次 seed 不同：%q vs %q", first.RoutingSeed, second.RoutingSeed)
	}
	replayed, digest, err := routing.Replay(first.Replay)
	if err != nil {
		t.Fatalf("回放失败: %v", err)
	}
	if planOrder(replayed) != planOrder(first.Plan) {
		t.Errorf("回放次序 = %s，与线上 %s 不一致", planOrder(replayed), planOrder(first.Plan))
	}
	if replayed.RoutingSeed != first.RoutingSeed {
		t.Errorf("回放 seed = %q，线上 seed = %q", replayed.RoutingSeed, first.RoutingSeed)
	}
	if len(digest) != 64 {
		t.Errorf("候选摘要 = %q，want 64 位十六进制", digest)
	}
	other := run(t, w, base(Scenario{Fixture: "employee-1001", Model: ModelLite, RequestID: "req-replay-2"}))
	if other.RoutingSeed == first.RoutingSeed {
		t.Error("request_id 变了 seed 却一样，说明 seed 没吃到请求身份")
	}
}

func planOrder(plan policy.RoutingPlan) string {
	names := make([]string, 0, len(plan.Fallbacks))
	for _, c := range plan.Fallbacks {
		names = append(names, c.Provider)
	}
	return strings.Join(names, ">")
}

// 粘性：会话内钉住那家，只要它还活着就不漂移（§2.8 里粘性命中不消耗随机数）。
func TestStickyKeepsPrimary(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	sticky := &routing.StickyState{Provider: "corp-vllm-b", ExpiresAt: BaseNow.Add(time.Minute)}
	r := run(t, w, base(Scenario{Fixture: "employee-1001", Model: ModelLite,
		RequestID: "req-sticky", Sticky: sticky}))
	primary, ok := r.Plan.Primary()
	if !ok {
		t.Fatalf("计划里没有首选: %v", r.PlanErr)
	}
	if primary.Provider != "corp-vllm-b" {
		t.Errorf("粘性未生效：首选 = %s", primary.Provider)
	}
	dead := run(t, w, base(Scenario{Fixture: "employee-1001", Model: ModelLite,
		RequestID: "req-sticky-dead",
		Sticky:    &routing.StickyState{Provider: "frontier-cloud-global", ExpiresAt: BaseNow.Add(time.Minute)}}))
	if dead.PlanErr != nil {
		t.Fatalf("粘住的候选不可用时仍应给出计划: %v", dead.PlanErr)
	}
	deadPrimary, _ := dead.Plan.Primary()
	if deadPrimary.Provider == "frontier-cloud-global" {
		t.Error("被策略禁止的候选不该被粘住")
	}
}

// 区域白名单：只允许 cn-east，集团私有化集群与境外那家都要留下排除理由。
func TestCandidateExclusionsAreVerifiable(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	region := run(t, w, Scenario{Fixture: "employee-1001", Model: ModelCloudCn,
		Regions: []string{"cn-east"}, RequestID: "req-region"})
	if region.PlanErr != nil {
		t.Fatalf("境内云可用，不该给不出计划: %v", region.PlanErr)
	}
	primary, _ := region.Plan.Primary()
	if primary.Provider != "frontier-cloud-cn" {
		t.Errorf("区域白名单下首选 = %s，期望 frontier-cloud-cn", primary.Provider)
	}
	for _, name := range []string{"corp-vllm-a", "corp-vllm-b"} {
		if reason := rejectionOf(region.Plan, name); reason != policy.ReasonCandidateRegionExcluded {
			t.Errorf("%s 的排除原因 = %q，期望 %q", name, reason, policy.ReasonCandidateRegionExcluded)
		}
	}
	// 分级门：境外那家只承接 public，internal 请求必须把它挡在候选之外。
	level := run(t, w, Scenario{Fixture: "employee-1001", Model: ModelCloudCn,
		RequestID: "req-level-gate"})
	if reason := rejectionOf(level.Plan, "frontier-cloud-global"); reason != policy.ReasonCandidateLevelExcluded {
		t.Errorf("超分级候选的排除原因 = %q，期望 %q", reason, policy.ReasonCandidateLevelExcluded)
	}
}

func rejectionOf(plan policy.RoutingPlan, provider string) policy.Reason {
	for _, r := range plan.Rejections {
		if r.Provider == provider {
			return r.Reason
		}
	}
	return ""
}

// 审计投影里不能有正文与个人信息（§2.9 规则 6）。
func TestAuditRowCarriesNoBodyOrPII(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	r := run(t, w, base(Scenario{Fixture: "employee-1001", Model: ModelLite, RequestID: "req-audit"}))
	raw, err := json.Marshal(r.Audit)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, leak := range []string{"13900000000", "employee-1001@example.invalid", SampleSecret, "请联系"} {
		if strings.Contains(doc, leak) {
			t.Errorf("审计里出现了不该有的内容 %q: %s", leak, doc)
		}
	}
	if len(r.Audit.BodyHash) != 64 || r.Audit.BodyHash == hashHex(nil) {
		t.Errorf("body_sha256 异常: %q", r.Audit.BodyHash)
	}
	if r.Audit.BodyBytes == 0 || r.Audit.ContentBytes == 0 {
		t.Errorf("字节数缺失：body=%d content=%d", r.Audit.BodyBytes, r.Audit.ContentBytes)
	}
	if r.Audit.Provider == "" || r.Audit.Executor == "" || r.Audit.Tier < 0 {
		t.Errorf("候选侧事实缺失: %+v", r.Audit)
	}
	if r.Audit.PolicyVersion == "" || r.Audit.RoutingSeed == "" {
		t.Error("审计必须能回指当时的策略版本与 seed")
	}
	if r.Audit.Source == "" {
		t.Error("审计必须留下身份来源（§0.3）")
	}
}

// 策略版本只描述这条链上的包：拿全集版本进审计会写下与请求无关的规则。
func TestPolicyVersionIsScopedToChain(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	emp := run(t, w, base(Scenario{Fixture: "employee-1001", Model: ModelLite, RequestID: "req-ver-emp"}))
	if strings.Contains(emp.PolicyVersion, "dept-finance-default") ||
		strings.Contains(emp.PolicyVersion, "client-acme") {
		t.Errorf("员工的策略版本里混进了与他无关的包: %s", emp.PolicyVersion)
	}
	for _, want := range []string{"corp-system@1", "corp-group-default@3", "sub-cloud-default@1"} {
		if !strings.Contains(emp.PolicyVersion, want) {
			t.Errorf("员工（云服务子公司）的版本串应含 %s: %s", want, emp.PolicyVersion)
		}
	}
	fin := run(t, w, base(Scenario{Fixture: "finance-3001", Model: ModelFinance, RequestID: "req-ver-fin"}))
	if !strings.Contains(fin.PolicyVersion, "dept-finance-default@1") {
		t.Errorf("财务在财务部范围内，版本串应含该包: %s", fin.PolicyVersion)
	}
	part := run(t, w, base(Scenario{Fixture: "partner-7001", Model: ModelLite, RequestID: "req-ver-part"}))
	if !strings.Contains(part.PolicyVersion, "client-acme@1") {
		t.Errorf("合作方的版本串应含客户项目包: %s", part.PolicyVersion)
	}
	if strings.Contains(part.PolicyVersion, "corp-group-default") {
		t.Errorf("合作方不在集团范围里，不该带上集团包: %s", part.PolicyVersion)
	}
}

// 计划里带的处理器链必须与实际执行的链一致。
func TestPlanProcessorChainMatchesPipeline(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []Scenario{
		{Fixture: "employee-1001", Model: ModelLite, RequestID: "req-chain-default"},
		{Fixture: "manager-2001", Model: ModelGeneral, Purpose: PurposeEng,
			UserLevel: policy.LevelConfidential, IsRawSidecar: true, RequestID: "req-chain-raw"},
	} {
		r := run(t, w, base(s))
		want := strings.Join(processorNames(s.IsRawSidecar), ",")
		got := strings.Join(r.Plan.ProcessorChain, ",")
		if got != want {
			t.Errorf("%s：计划里的链 = %s，实际装配 = %s", s.RequestID, got, want)
		}
	}
}
