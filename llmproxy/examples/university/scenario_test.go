package university

// 高校参考实现的端到端场景测试（§3.G 交付：e2e）。
//
// 断言的重心不是「代码能跑」，而是五条容易被示例美化掉的结论：
//  1. 授权按范围发放 —— 跨组织蹭不到、结课即回收、点名授权带期限；
//  2. deny 只压它点名的资源，且压过任何层级的 allow；
//  3. 原文出网授权贯通到处理器 —— 没授权时 fail-closed，一个字节都不发；
//  4. 候选排除原因可验证（§6）—— 分级、区域、缺价目各有码，不是一句「没候选」；
//  5. 审计只留摘要与字节数（§2.9 规则 6）—— 手机号/邮箱/凭证都不进审计。
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

// base 补齐一条场景没写的三档分级：生效分级取三档最大值，只给一档就断言不了
// 「检测器把公开请求抬到 confidential」这条规则。
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
		s.Purpose = "chat"
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
		wantReasonInChain bool // 断言 reasons 链里也有这个码
	}{
		{"学生基线（internal）", Scenario{Fixture: "student-1001", Model: ModelLite},
			true, policy.ReasonGroupAllow, false},
		{"学生基线被分级挡掉", Scenario{Fixture: "student-1001", Model: ModelLite,
			UserLevel: policy.LevelConfidential}, false, policy.ReasonDataLevelDenied, false},
		{"检测器抬档同样挡掉", Scenario{Fixture: "student-1001", Model: ModelLite,
			DetectedLevel: policy.LevelConfidential}, false, policy.ReasonDataLevelDenied, false},
		{"科研模型对学生显式禁止", Scenario{Fixture: "student-1001", Model: ModelRestricted},
			false, policy.ReasonModelNotAllowed, true},
		{"实验室授权压不过对学生的显式禁止", Scenario{Fixture: "ra-6001", Model: ModelRestricted},
			false, policy.ReasonModelNotAllowed, true},
		{"选课即入范围", Scenario{Fixture: "student-1001", Model: ModelTutor101},
			true, policy.ReasonGroupAllow, false},
		{"没选过的课程模型（缺席即否）", Scenario{Fixture: "student-1001", Model: ModelTutor305},
			false, policy.ReasonModelNotAllowed, false},
		{"结课即回收（过期与缺席是两个结论）", Scenario{Fixture: "teacher-li-synthetic", Model: ModelTutor305},
			false, policy.ReasonEntitlementExpired, false},
		{"教师到 confidential 为止", Scenario{Fixture: "teacher-li-synthetic", Model: ModelGeneral,
			UserLevel: policy.LevelConfidential}, true, policy.ReasonGroupAllow, false},
		{"教师碰 restricted 被挡", Scenario{Fixture: "teacher-li-synthetic", Model: ModelGeneral,
			UserLevel: policy.LevelRestricted}, false, policy.ReasonDataLevelDenied, false},
		{"院系模型按组织范围发放", Scenario{Fixture: "teacher-li-synthetic", Model: ModelReview},
			true, policy.ReasonGroupAllow, false},
		{"点名授权（explicit 压过组级）", Scenario{Fixture: "pi-3001", Model: ModelPilot,
			Purpose: PurposeWriting}, true, policy.ReasonExplicitAllow, false},
		{"交流生蹭不到本校组织授权", Scenario{Fixture: "exchange-5001", Model: ModelLite},
			false, policy.ReasonModelNotAllowed, false},
		{"交流生选了课就能用课程模型", Scenario{Fixture: "exchange-5001", Model: ModelTutor101},
			true, policy.ReasonGroupAllow, false},
		{"境外部署全校显式禁止", Scenario{Fixture: "teacher-li-synthetic", Model: ModelForeign},
			false, policy.ReasonModelNotAllowed, true},
		{"实验员没有面向他的模型规则", Scenario{Fixture: "lab-admin-4001", Model: ModelLite},
			false, policy.ReasonModelNotAllowed, false},
		{"目录里没有的模型", Scenario{Fixture: "student-1001", Model: "no-such-model"},
			false, policy.ReasonModelNotAllowed, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// World 在子用例之间复用，上游计数会累加：断言「被拒就没有出网」
			// 必须看这一条用例期间的增量，而不是绝对值。
			callsBefore := w.Upstream.calls
			r := run(t, w, c.s)
			if r.Decision.Allowed != c.wantAllowed {
				t.Fatalf("allowed = %v，期望 %v（reason=%v 命中 %d 条）",
					r.Decision.Allowed, c.wantAllowed, r.Decision.Reason, len(r.Decision.Matched))
			}
			if r.Decision.Reason != c.wantReason {
				t.Errorf("reason = %q，期望 %q", r.Decision.Reason, c.wantReason)
			}
			if c.wantReasonInChain && !containsReason(r.Decision.Reasons, c.wantReason) {
				t.Errorf("原因链里没有 %q: %v", c.wantReason, r.Decision.Reasons)
			}
			// 被拒的请求不能有任何出网痕迹：计划给不出是结论，发出去才是事故。
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

func containsReason(list []policy.Reason, want policy.Reason) bool {
	for _, r := range list {
		if r == want {
			return true
		}
	}
	return false
}

// deny 只压它点名的那个资源，不会把主体整体踢出范围。
//
// 为什么单独钉：实验室层同时给了受限模型、笔记库与原文授权，全校层对 role:student
// 有一条显式禁止。把「模型被 deny」实现成「该主体在 lab7 内一律否」这种过度拒绝，
// 在影子期差异报告里长得像「新策略更严了」，很容易被当成预期结果放过。
func TestDenyIsScopedToItsResource(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	r := run(t, w, base(Scenario{Fixture: "ra-6001", Model: ModelRestricted, RequestID: "req-deny-scope"}))
	if r.Decision.Allowed {
		t.Fatal("全校层对学生的显式禁止必须压过实验室层的放行")
	}
	if !containsReason(r.Decision.Reasons, policy.ReasonDenyRule) {
		t.Errorf("原因链要指认 deny 规则本身，而不是一句 model_not_allowed: %v", r.Decision.Reasons)
	}
	d := r.Resolver.Evaluate(r.Context, r.Chain,
		scopedResource(policy.NamespaceKnowledge, KnowledgeLabNotes), policy.ActionRead, BaseNow)
	if !d.Allowed || d.Reason != policy.ReasonGroupAllow {
		t.Errorf("deny 泄漏到了同范围内的其他资源: allowed=%v reason=%v", d.Allowed, d.Reason)
	}

	// 原文授权按范围发放，实验室里的每个学生助理都拿得到 —— 这是范围授权的既定代价。
	// 把它钉在这里而不是藏起来：「不是 PI 就自动没有原文」是不成立的想当然，
	// 第二道防线只能是模型层的 deny 与分级门，不能指望授权本身挑人。
	ra := run(t, w, base(Scenario{Fixture: "ra-6001", Model: ModelLite,
		Purpose: PurposeWriting, RequestID: "req-ra-raw"}))
	if !ra.IsRawBodyAllow {
		t.Errorf("RA 在 lab7 范围内且用途匹配，应拿到原文授权，实际 %v", ra.RawBodyReason)
	}
	// 用途不匹配时立刻收回：授权不是「进了实验室就永久有效」。
	chat := run(t, w, base(Scenario{Fixture: "ra-6001", Model: ModelLite, RequestID: "req-ra-chat"}))
	if chat.IsRawBodyAllow || chat.RawBodyReason != policy.ReasonRawBodyGrantMissing {
		t.Errorf("chat 用途不该沿用科研写作的原文授权: %v %v", chat.IsRawBodyAllow, chat.RawBodyReason)
	}
	// 不在范围内的人连用途都对不上：交流生选了课也不沾实验室层。
	exchange := run(t, w, base(Scenario{Fixture: "exchange-5001", Model: ModelTutor101,
		Purpose: PurposeWriting, RequestID: "req-ex-raw"}))
	if exchange.IsRawBodyAllow || exchange.RawBodyReason != policy.ReasonRawBodyGrantMissing {
		t.Errorf("课程范围不该带来实验室的原文授权: %v %v",
			exchange.IsRawBodyAllow, exchange.RawBodyReason)
	}
}

// 原文出网授权必须贯通到处理器一侧，而且「没授权」要长成 fail-closed 的样子。
//
// 为什么分开断言三件事：sidecar 拿到原文、上游拿到掩码文、无授权时零出网，
// 任何一条单独看都可能是另一条的巧合（比如上游那家恰好没被调用）。
func TestRawBodyGrantReachesProcessor(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	raw := Scenario{Fixture: "pi-3001", Model: ModelRestricted, Purpose: PurposeWriting,
		UserLevel: policy.LevelConfidential, IsRawSidecar: true}
	r := run(t, w, raw)
	if r.PipelineErr != nil {
		t.Fatalf("PI 在科研写作用途下有原文授权，处理器不该失败: %v", r.PipelineErr)
	}
	if !r.IsRawBodyAllow {
		t.Error("策略侧应给出原文授权")
	}
	if got := w.Sink.payload()["content_mode"]; got != "raw" {
		t.Errorf("sidecar 的 content_mode = %v，期望 raw", got)
	}
	if !strings.Contains(string(w.Sink.lastBody), "13800000000") {
		t.Error("原文授权下 sidecar 应看到未脱敏正文")
	}
	// 授权只放开「给 sidecar 的那一份」：上游正文仍必须是掩码文。
	if strings.Contains(string(r.Sent), "13800000000") {
		t.Errorf("发往上游的正文里仍有手机号: %s", r.Sent)
	}
	if r.Audit.BodyHash == "" || r.Audit.BodyBytes == 0 {
		t.Error("审计必须留下正文摘要与字节数")
	}

	// 换一个用途就退回最严：授权按 purpose 精确绑定，不能沿用科研组的。
	noGrant := run(t, w, Scenario{Fixture: raw.Fixture, Model: raw.Model, Purpose: "chat",
		UserLevel: raw.UserLevel, IsRawSidecar: true, RequestID: "req-purpose-switch"})
	if noGrant.PipelineErr == nil {
		t.Fatal("换用途后原文授权应失效，处理器必须 fail-closed")
	}
	if !strings.Contains(noGrant.PipelineErr.Error(), string(policy.ReasonRawBodyGrantMissing)) {
		t.Errorf("失败原因要指回策略侧原因码，实际: %v", noGrant.PipelineErr)
	}

	// 教师没有任何原文授权：即便系统包里那条通配 allow 存在，也不算授权（§2.9 规则 4）。
	teacher := run(t, w, Scenario{Fixture: "teacher-li-synthetic", Model: ModelGeneral,
		Purpose: PurposeWriting, UserLevel: policy.LevelConfidential,
		IsRawSidecar: true, RequestID: "req-teacher-raw"})
	if teacher.IsRawBodyAllow {
		t.Error("通配 allow 不该被当成原文出网授权")
	}
	if teacher.PipelineErr == nil {
		t.Fatal("无原文授权的 sidecar 必须 fail-closed")
	}
}

func TestCandidateExclusionsAreVerifiable(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	// 区域白名单：只允许 cn-east，校内三家与境外那家都要留下排除理由。
	region := run(t, w, Scenario{Fixture: "teacher-li-synthetic", Model: ModelCloud,
		Regions: []string{"cn-east"}})
	if region.PlanErr != nil {
		t.Fatalf("境内云可用，不该给不出计划: %v", region.PlanErr)
	}
	primary, _ := region.Plan.Primary()
	if primary.Provider != "frontier-cloud-cn" {
		t.Errorf("区域白名单下首选 = %s，期望 frontier-cloud-cn", primary.Provider)
	}
	for _, name := range []string{"campus-vllm-a", "campus-vllm-b", "campus-ollama-mini"} {
		if reason := rejectionOf(region.Plan, name); reason != policy.ReasonCandidateRegionExcluded {
			t.Errorf("%s 的排除原因 = %q，期望 %q", name, reason, policy.ReasonCandidateRegionExcluded)
		}
	}

	// cheapest 目标下无价目的候选不能当零成本参与（§3.D）。
	cheap := run(t, w, Scenario{Fixture: "teacher-li-synthetic", Model: ModelCloud,
		Objective: routing.ObjectiveCheapest, RequestID: "req-cheapest"})
	if cheap.PlanErr != nil {
		t.Fatalf("cheapest 场景应给得出计划: %v", cheap.PlanErr)
	}
	if reason := rejectionOf(cheap.Plan, "campus-ollama-mini"); reason != policy.ReasonCandidateCostUnknown {
		t.Errorf("无价目候选的排除原因 = %q，期望 %q", reason, policy.ReasonCandidateCostUnknown)
	}

	// 分级门：境外那家只承接 public，internal 请求必须把它挡在候选之外。
	level := run(t, w, Scenario{Fixture: "teacher-li-synthetic", Model: ModelCloud,
		RequestID: "req-level-gate"})
	if reason := rejectionOf(level.Plan, "frontier-cloud-us"); reason != policy.ReasonCandidateLevelExcluded {
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

// 确定性：同一输入两次跑出同一份计划，并且回放输入能独立复原它（§2.8）。
func TestRoutingIsDeterministicAndReplayable(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	s := base(Scenario{Fixture: "student-1001", Model: ModelLite, RequestID: "req-replay-1"})
	first := run(t, w, s)
	second := run(t, w, s)
	if first.RoutingSeed != second.RoutingSeed || first.RoutingSeed == "" {
		t.Fatalf("同输入两次 seed 不同：%q vs %q", first.RoutingSeed, second.RoutingSeed)
	}
	if got := planOrder(second.Plan); got != planOrder(first.Plan) {
		t.Errorf("两次次序不同：%s vs %s", got, planOrder(first.Plan))
	}
	replayed, digest, err := routing.Replay(first.Replay)
	if err != nil {
		t.Fatalf("回放失败: %v", err)
	}
	if got := planOrder(replayed); got != planOrder(first.Plan) {
		t.Errorf("回放次序 = %s，与线上 %s 不一致", got, planOrder(first.Plan))
	}
	if replayed.RoutingSeed != first.RoutingSeed {
		t.Errorf("回放 seed = %q，线上 seed = %q", replayed.RoutingSeed, first.RoutingSeed)
	}
	if len(digest) != 64 {
		t.Errorf("候选摘要 = %q，want 64 位十六进制", digest)
	}

	// seed 的第三个输入是路由代：换池子必须换 seed，否则「复现」是假的。
	other := run(t, w, base(Scenario{Fixture: "student-1001", Model: ModelLite, RequestID: "req-replay-2"}))
	if other.RoutingSeed == first.RoutingSeed {
		t.Error("request_id 变了 seed 却一样，说明 seed 没吃到请求身份")
	}

	// 线上模式：抽样来自注入的随机源，此时不能声称有逐位复现的 seed。
	online := run(t, w, base(Scenario{Fixture: "student-1001", Model: ModelLite,
		RequestID: "req-online", Random: routing.SeededSource("campus-online")}))
	if online.RoutingSeed != "" {
		t.Errorf("线上模式的 Result.RoutingSeed 应为空，实际 %q", online.RoutingSeed)
	}
	if online.Plan.RoutingSeed != "" {
		t.Errorf("线上模式的计划不该带 seed，实际 %q", online.Plan.RoutingSeed)
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
	sticky := &routing.StickyState{Provider: "campus-vllm-b", ExpiresAt: BaseNow.Add(time.Minute)}
	r := run(t, w, base(Scenario{Fixture: "student-1001", Model: ModelLite,
		RequestID: "req-sticky", Sticky: sticky}))
	primary, ok := r.Plan.Primary()
	if !ok {
		t.Fatalf("计划里没有首选: %v", r.PlanErr)
	}
	if primary.Provider != "campus-vllm-b" {
		t.Errorf("粘性未生效：首选 = %s", primary.Provider)
	}
	// 粘到一家已经不可用的候选时，必须换而不是硬粘。
	dead := run(t, w, base(Scenario{Fixture: "student-1001", Model: ModelLite,
		RequestID: "req-sticky-dead",
		Sticky:    &routing.StickyState{Provider: "frontier-cloud-us", ExpiresAt: BaseNow.Add(time.Minute)}}))
	if dead.PlanErr != nil {
		t.Fatalf("粘住的候选不可用时仍应给出计划: %v", dead.PlanErr)
	}
	deadPrimary, _ := dead.Plan.Primary()
	if deadPrimary.Provider == "frontier-cloud-us" {
		t.Error("不健康/超分级的候选不该被粘住")
	}
}

// 审计投影里不能有正文与个人信息（§2.9 规则 6）。
func TestAuditRowCarriesNoBodyOrPII(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	r := run(t, w, base(Scenario{Fixture: "student-1001", Model: ModelLite, RequestID: "req-audit"}))
	raw, err := json.Marshal(r.Audit)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, leak := range []string{"13800000000", "student-1001@example.invalid", SampleSecret, "请联系"} {
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
}

// 策略版本只描述这条链上的包：拿全集版本进审计会写下与请求无关的规则。
func TestPolicyVersionIsScopedToChain(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	student := run(t, w, base(Scenario{Fixture: "student-1001", Model: ModelLite, RequestID: "req-ver-stu"}))
	if strings.Contains(student.PolicyVersion, "lab7-research") ||
		strings.Contains(student.PolicyVersion, "cs305-course") {
		t.Errorf("学生的策略版本里混进了与他无关的包: %s", student.PolicyVersion)
	}
	if !strings.Contains(student.PolicyVersion, "cs101-course@1") {
		t.Errorf("课程包应进版本串: %s", student.PolicyVersion)
	}
	pi := run(t, w, base(Scenario{Fixture: "pi-3001", Model: ModelRestricted,
		Purpose: PurposeWriting, UserLevel: policy.LevelConfidential, RequestID: "req-ver-pi"}))
	if !strings.Contains(pi.PolicyVersion, "lab7-research@1") {
		t.Errorf("PI 在 lab7 范围内，版本串应含该包: %s", pi.PolicyVersion)
	}
	// 系统包对任意链都生效，两边都得有。
	for _, v := range []string{student.PolicyVersion, pi.PolicyVersion} {
		if !strings.Contains(v, "campus-system@1") {
			t.Errorf("系统包必须出现在每条链的版本串里: %s", v)
		}
	}
}

// 计划里带的处理器链必须与实际执行的链一致：路由按链选路，接线按链执行，
// 两边不是同一份就等于「选出来的计划跑不出来的东西」。
func TestPlanProcessorChainMatchesPipeline(t *testing.T) {
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []Scenario{
		{Fixture: "student-1001", Model: ModelLite, RequestID: "req-chain-default"},
		{Fixture: "pi-3001", Model: ModelRestricted, Purpose: PurposeWriting,
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
