package processor

// 第一波补测试：正文准入（§2.9 三档 + 原文出网管理员授权）。
// 共享助手（pipeSpec / pipeBuild / pipeRequest 等）定义在 pipeline_test.go，
// 均以 pipe 前缀命名。

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 编译期证明：A 包的 *policy.Resolver 天然满足 E 包的授权判定接口 ——
// 判定次序（deny > explicit_allow > group_allow、通配不算授权、授权自带期限）
// 的唯一业务源在 A，E 不重做也不自行放行。
var _ RawBodyGrantChecker = (*policy.Resolver)(nil)

// ------------------------------------------------------------------ 三档边界

func TestInputAccessFlagsAlignWithPolicyParse(t *testing.T) {
	// Input 的 CanReadBody/CanReplaceBody 口径必须与 policy.ParseBodyAccess 完全对齐。
	cases := []struct {
		raw         string
		wantTier    policy.BodyAccess
		wantRead    bool
		wantReplace bool
	}{
		{"", policy.BodyMetadataOnly, false, false},
		{"metadata-only", policy.BodyMetadataOnly, false, false},
		{"inspect-body", policy.BodyInspect, true, false},
		{"transform-body", policy.BodyTransform, true, true},
		{"TRANSFORM-BODY", policy.BodyTransform, true, true},
	}
	for _, tc := range cases {
		a, err := policy.ParseBodyAccess(tc.raw)
		if err != nil {
			t.Fatalf("%q 解析失败: %v", tc.raw, err)
		}
		if a != tc.wantTier {
			t.Fatalf("%q 解析为 %s", tc.raw, a)
		}
		in := &Input{
			access: a,
			Spec:   pipeSpec("x", PhaseBeforeUpstream, a),
			body:   NewBufferedBody([]byte("hi")),
		}
		if in.CanReadBody() != tc.wantRead {
			t.Errorf("%q: CanReadBody = %v，期望 %v", tc.raw, in.CanReadBody(), tc.wantRead)
		}
		if in.CanReplaceBody() != tc.wantReplace {
			t.Errorf("%q: CanReplaceBody = %v，期望 %v", tc.raw, in.CanReplaceBody(), tc.wantReplace)
		}
		data, err := in.Body()
		switch {
		case tc.wantRead && err != nil:
			t.Errorf("%q: 应能读正文却报错: %v", tc.raw, err)
		case tc.wantRead && string(data) != "hi":
			t.Errorf("%q: 正文 = %q", tc.raw, data)
		case !tc.wantRead && !errors.Is(err, ErrBodyAccessDenied):
			t.Errorf("%q: metadata-only 下 Body() 必须被拒: %v", tc.raw, err)
		case !tc.wantRead && data != nil:
			t.Errorf("%q: 被拒时不得返回任何字节", tc.raw)
		}
		if in.deniedReads > 0 == tc.wantRead {
			t.Errorf("%q: deniedReads 留痕不对（=%d）", tc.raw, in.deniedReads)
		}
	}
	for _, bad := range []string{"read-body", "raw", "transform", "full"} {
		if _, err := policy.ParseBodyAccess(bad); err == nil {
			t.Errorf("%q 必须被拒绝：档位是封闭集合", bad)
		}
	}
}

func TestMetadataOnlyCannotReadBodyEndToEnd(t *testing.T) {
	// 端到端证明「不是请别读，而是读不到」：正文背后是一读就 panic 的流。
	type probe struct {
		canRead    bool
		canReplace bool
		bodyErr    error
		streamErr  error
		declared   int64
	}
	var got probe
	behaviors := map[string]pipeBehavior{"probe": {fn: func(_ context.Context, in *Input) (*Output, error) {
		got.canRead = in.CanReadBody()
		got.canReplace = in.CanReplaceBody()
		got.declared = in.DeclaredBodyBytes
		data, err := in.Body()
		got.bodyErr = err
		if data != nil {
			return nil, errors.New("metadata-only 竟返回了字节")
		}
		r, sErr := in.StreamReader()
		got.streamErr = sErr
		if r != nil {
			return nil, errors.New("metadata-only 竟交出了读者")
		}
		// 被挡也要继续走完链条：Pipeline 不许因此报错，但留痕必须能审出来。
		return &Output{}, nil
	}}}
	spec := pipeSpec("probe", PhaseBeforeUpstream, policy.BodyMetadataOnly)
	p, _, _ := pipeBuild(t, behaviors, spec)
	res, err := p.RunRequest(context.Background(),
		pipeRequest(t, "mo-1", NewBodyReader(pipePanicReader{}, 1_000_000)))
	if err != nil {
		t.Fatalf("metadata-only 的取正文尝试不应炸掉请求: %v", err)
	}
	if got.canRead || got.canReplace {
		t.Fatalf("档位能力位错误: read=%v replace=%v", got.canRead, got.canReplace)
	}
	if !errors.Is(got.bodyErr, ErrBodyAccessDenied) || !errors.Is(got.streamErr, ErrBodyAccessDenied) {
		t.Fatalf("Body/StreamReader 必须返回 ErrBodyAccessDenied: %v / %v", got.bodyErr, got.streamErr)
	}
	if got.declared != 1_000_000 {
		t.Errorf("大小属于元数据，metadata-only 也应可见: %d", got.declared)
	}
	entry := pipeEntry(t, res, "probe")
	if entry.DeniedReads != 2 {
		t.Errorf("DeniedReads = %d，两次被挡尝试都要留痕", entry.DeniedReads)
	}
	if res.Buffered || res.Body != nil {
		t.Error("metadata-only 不得进入缓冲形态（规则 7 的行为回归点）")
	}
}

func TestInspectBodyReadsButCannotReplace(t *testing.T) {
	// inspect-body 只读不可替换：即便处理器 fail_open，档位越权也是违规，必须拒。
	behaviors := map[string]pipeBehavior{"insp": {fn: func(_ context.Context, in *Input) (*Output, error) {
		data, err := in.Body()
		if err != nil {
			return nil, err
		}
		if string(data) != "original-body" {
			return nil, errors.New("inspect 档读到的正文不对")
		}
		return &Output{Body: []byte("SMUGGLED")}, nil // 越权：判定型处理器不该产出新正文
	}}}
	spec := pipeSpec("insp", PhaseBeforeUpstream, policy.BodyInspect)
	spec.FailClosed = false
	p, _, _ := pipeBuild(t, behaviors, spec)
	orig := []byte("original-body")
	res, err := p.RunRequest(context.Background(), pipeRequest(t, "ib-1", NewBufferedBody(orig)))
	if err == nil {
		t.Fatal("inspect-body 产出替换正文必须被拒，即使 fail_open")
	}
	if res.Outcome != ReasonBodyReplaceDenied {
		t.Errorf("Outcome = %s，期望 body_replace_denied", res.Outcome)
	}
	if string(res.Body) == "SMUGGLED" {
		t.Fatal("越权替换的正文不得放行")
	}
	if !res.Buffered || string(res.Body) != "original-body" {
		t.Errorf("读过正文后必须按 buffered 语义回传未替换正文: %v %q", res.Buffered, res.Body)
	}
}

func TestTransformBodyReplaceWithinOutputLimit(t *testing.T) {
	behaviors := map[string]pipeBehavior{"tr": {fn: func(_ context.Context, in *Input) (*Output, error) {
		if !in.CanReplaceBody() {
			return nil, errors.New("transform 档应可替换")
		}
		if _, err := in.Body(); err != nil {
			return nil, err
		}
		return &Output{Body: []byte(strings.Repeat("N", 2048))}, nil
	}}}
	spec := pipeSpec("tr", PhaseBeforeUpstream, policy.BodyTransform)
	spec.MaxInputBytes = 4096
	spec.MaxOutputBytes = 1024 // 处理器产出 2048，越界
	p, _, _ := pipeBuild(t, behaviors, spec)
	res, err := p.RunRequest(context.Background(), pipeRequest(t, "tb-1", NewBufferedBody([]byte("src"))))
	if err == nil {
		t.Fatal("产出超过 MaxOutputBytes 必须拒绝")
	}
	if res.Outcome != ReasonOutputTooLarge {
		t.Errorf("Outcome = %s，期望 output_too_large", res.Outcome)
	}

	// 合规产出：替换成功，最终正文是新 buffer，哈希进审计、字节不进审计。
	spec.MaxOutputBytes = 4096
	p2, _, _ := pipeBuild(t, behaviors, spec)
	res2, err := p2.RunRequest(context.Background(), pipeRequest(t, "tb-2", NewBufferedBody([]byte("src"))))
	if err != nil {
		t.Fatal(err)
	}
	if string(res2.Body) != strings.Repeat("N", 2048) {
		t.Errorf("替换后正文 = %q", res2.Body)
	}
	entry := pipeEntry(t, res2, "tr")
	if entry.OutputBytes != 2048 || !strings.HasPrefix(entry.OutputHash, "sha256:") {
		t.Errorf("输出计量不对: %+v", entry)
	}
}

func TestDeniedReadsRecordedWhenErrorSwallowed(t *testing.T) {
	// 处理器吞掉档位错误继续走完时，审计里仍要能看出「试过读正文」。
	behaviors := map[string]pipeBehavior{"sly": {fn: func(_ context.Context, in *Input) (*Output, error) {
		_, err1 := in.Body()
		_, err2 := in.StreamReader()
		if err1 == nil || err2 == nil {
			return nil, errors.New("metadata-only 竟读成功")
		}
		return &Output{}, nil // 故意不回报错
	}}}
	spec := pipeSpec("sly", PhaseBeforeUpstream, policy.BodyMetadataOnly)
	p, _, _ := pipeBuild(t, behaviors, spec)
	res, err := p.RunRequest(context.Background(), pipeRequest(t, "dr", NewBufferedBody([]byte("secret"))))
	if err != nil {
		t.Fatal(err)
	}
	if got := pipeEntry(t, res, "sly").DeniedReads; got != 2 {
		t.Errorf("DeniedReads = %d，期望 2", got)
	}
}

// ------------------------------------------------------------------ 审计阶段结构性无正文

func TestRunAuditCannotSeeBody(t *testing.T) {
	t.Run("声明档位也不给正文", func(t *testing.T) {
		var bodyErr error
		behaviors := map[string]pipeBehavior{"aud": {fn: func(_ context.Context, in *Input) (*Output, error) {
			// AuditInput 按结构没有 Body 字段；即便处理器声明了 transform 也拿不到。
			_, bodyErr = in.Body()
			return &Output{}, nil
		}}}
		spec := pipeSpec("aud", PhaseAudit, policy.BodyTransform)
		p, _, _ := pipeBuild(t, behaviors, spec)
		res, err := p.RunAudit(context.Background(), &AuditInput{
			RequestID: "au-1", Model: "gpt-test",
			Policy: pipeCtx(t, "alice"), Chain: pipeChain("alice"), Now: pipeBaseNow,
		})
		if err != nil {
			t.Fatalf("审计调用本身应成功: %v", err)
		}
		if !errors.Is(bodyErr, ErrNoBody) {
			t.Fatalf("审计阶段取正文必须失败: %v", bodyErr)
		}
		if res.Buffered || res.Body != nil || res.Audit.Buffered {
			t.Error("审计结果不得带任何缓冲正文")
		}
		if !res.Audit.Untouched {
			t.Error("审计记录应标记 input_untouched")
		}
	})

	t.Run("审计处理器伪造产出不改变无缓冲事实", func(t *testing.T) {
		// 越权声明 transform 的审计阶段处理器凭空造字节：Result.Body 仍必须是 nil，
		// 且审计视图不许宣称发生过缓冲。
		behaviors := map[string]pipeBehavior{"aud": {fn: func(_ context.Context, in *Input) (*Output, error) {
			return &Output{Body: []byte("fabricated")}, nil
		}}}
		spec := pipeSpec("aud", PhaseAudit, policy.BodyTransform)
		p, _, _ := pipeBuild(t, behaviors, spec)
		res, err := p.RunAudit(context.Background(), &AuditInput{
			RequestID: "au-3", Model: "gpt-test",
			Policy: pipeCtx(t, "alice"), Chain: pipeChain("alice"), Now: pipeBaseNow,
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.Body != nil || res.Buffered {
			t.Error("审计阶段不得把伪造字节作为正文交回")
		}
		if res.Audit.Buffered || !res.Audit.Untouched {
			t.Errorf("审计视图与结果口径不一致: %+v", res.Audit)
		}
		if res.BufferingNotice != "" {
			t.Errorf("未缓冲却留下缓冲声明: %q", res.BufferingNotice)
		}
	})

	t.Run("metadata-only 尝试读正文只留痕", func(t *testing.T) {
		behaviors := map[string]pipeBehavior{"aud": {fn: func(_ context.Context, in *Input) (*Output, error) {
			_, _ = in.Body() // 被档位挡住
			return &Output{}, nil
		}}}
		spec := pipeSpec("aud", PhaseAudit, policy.BodyMetadataOnly)
		p, _, _ := pipeBuild(t, behaviors, spec)
		res, err := p.RunAudit(context.Background(), &AuditInput{
			RequestID: "au-2", Model: "gpt-test",
			Policy: pipeCtx(t, "alice"), Chain: pipeChain("alice"), Now: pipeBaseNow,
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := pipeEntry(t, res, "aud").DeniedReads; got != 1 {
			t.Errorf("DeniedReads = %d", got)
		}
		if res.Buffered || res.Body != nil || !res.Audit.Untouched {
			t.Error("审计运行不得标记 buffered")
		}
	})
}

// ------------------------------------------------------------------ 准入声明

func TestBodyAccessAdmissionTable(t *testing.T) {
	meta := pipeSpec("meta", PhaseBeforeUpstream, policy.BodyMetadataOnly)
	insp := pipeSpec("insp", PhaseBeforeRoute, policy.BodyInspect)
	tr := pipeSpec("tr", PhaseBeforeUpstream, policy.BodyTransform)
	tr.AllowRawBody = true
	tr.AllowedEndpoints = []string{"https://sidecar.test/"}
	p, _, _ := pipeBuild(t, nil, insp, tr, meta)

	adm := p.BodyAccessAdmissions()
	if len(adm) != 3 {
		t.Fatalf("准入表长度 = %d", len(adm))
	}
	// 准入表反映装配后的执行次序（跨阶段规范化；同阶段保持策略顺序：tr 在 meta 前）。
	wantOrder := []string{"insp", "tr", "meta"}
	wantRead := []bool{true, true, false}
	wantReplace := []bool{false, true, false}
	wantRaw := []bool{false, true, false}
	for i, a := range adm {
		if a.Processor != wantOrder[i] {
			t.Fatalf("准入表次序 = %v，期望规范化后的执行次序 %v", []string{adm[0].Processor, adm[1].Processor, adm[2].Processor}, wantOrder)
		}
		if a.NeedsBuffer != wantRead[i] || a.ReplacesBody != wantReplace[i] || a.RawBodyWanted != wantRaw[i] {
			t.Errorf("%s: NeedsBuffer=%v ReplacesBody=%v RawBodyWanted=%v", a.Processor, a.NeedsBuffer, a.ReplacesBody, a.RawBodyWanted)
		}
		if a.Version != "v1" || a.Type != pipeTypeFake {
			t.Errorf("%s: 版本/类型声明不对: %+v", a.Processor, a)
		}
	}
}

func TestMaxBodyAccessAndRequiresBuffering(t *testing.T) {
	cases := []struct {
		name       string
		accesses   []policy.BodyAccess
		wantMax    policy.BodyAccess
		wantBuffer bool
	}{
		{"全 metadata-only", []policy.BodyAccess{policy.BodyMetadataOnly, policy.BodyMetadataOnly}, policy.BodyMetadataOnly, false},
		{"夹一个 inspect", []policy.BodyAccess{policy.BodyMetadataOnly, policy.BodyInspect}, policy.BodyInspect, true},
		{"夹一个 transform", []policy.BodyAccess{policy.BodyInspect, policy.BodyTransform}, policy.BodyTransform, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var specs []Spec
			for i, a := range tc.accesses {
				specs = append(specs, pipeSpec(string(rune('a'+i)), PhaseBeforeUpstream, a))
			}
			p, _, _ := pipeBuild(t, nil, specs...)
			if got := p.MaxBodyAccess(); got != tc.wantMax {
				t.Errorf("MaxBodyAccess = %s，期望 %s", got, tc.wantMax)
			}
			if got := p.RequiresBodyBuffering(); got != tc.wantBuffer {
				t.Errorf("RequiresBodyBuffering = %v，期望 %v", got, tc.wantBuffer)
			}
		})
	}
	// 空链：最严档，接线方保留透传。
	p, _, _ := pipeBuild(t, nil)
	if p.MaxBodyAccess() != policy.BodyMetadataOnly || p.RequiresBodyBuffering() || p.Len() != 0 {
		t.Fatal("空链必须报告不需要缓冲")
	}
}

// ------------------------------------------------------------------ 原文出网管理员授权

func pipeRawRule(subject, scope string, effect policy.Effect, expires time.Time) policy.Entitlement {
	return policy.Entitlement{
		Subject:   subject,
		Scope:     scope,
		Resource:  policy.ResourceBodyRaw,
		Action:    policy.ActionRead,
		Effect:    effect,
		ExpiresAt: expires,
	}
}

func pipeGrantResolver(t *testing.T, rules ...policy.Entitlement) *policy.Resolver {
	t.Helper()
	r, err := policy.NewResolver("grants@1", rules...)
	if err != nil {
		t.Fatalf("构造策略内核失败: %v", err)
	}
	return r
}

// TestAllowsRawBodyTwoGates 用 RawBodyGrantChecker 接口（而非具体类型）钉住 A 包
// 契约在 E 侧的使用口径：缺席即否、通配不算授权、授权必须自带期限。
func TestAllowsRawBodyTwoGates(t *testing.T) {
	expiry := pipeBaseNow.Add(24 * time.Hour)
	cases := []struct {
		title      string
		rules      []policy.Entitlement
		subject    string
		roles      []string
		now        time.Time
		wantAllow  bool
		wantReason policy.Reason
	}{
		{"缺席即否（没配任何授权）", nil, "alice", nil, pipeBaseNow, false, policy.ReasonNoMatchingRule},
		{"通配 default_allow 不算原文授权",
			[]policy.Entitlement{pipeRawRule("*", "", policy.EffectAllow, time.Time{})},
			"alice", nil, pipeBaseNow, false, policy.ReasonRawBodyGrantMissing},
		{"显式授权但没带期限",
			[]policy.Entitlement{pipeRawRule("alice", "", policy.EffectAllow, time.Time{})},
			"alice", nil, pipeBaseNow, false, policy.ReasonRawBodyGrantMissing},
		{"显式授权 + 期限",
			[]policy.Entitlement{pipeRawRule("alice", "", policy.EffectAllow, expiry)},
			"alice", nil, pipeBaseNow, true, policy.ReasonExplicitAllow},
		{"期限前一纳秒仍有效",
			[]policy.Entitlement{pipeRawRule("alice", "", policy.EffectAllow, expiry)},
			"alice", nil, expiry.Add(-time.Nanosecond), true, policy.ReasonExplicitAllow},
		{"到期时刻即失效（显式 now，不靠墙上时钟）",
			[]policy.Entitlement{pipeRawRule("alice", "", policy.EffectAllow, expiry)},
			"alice", nil, expiry, false, policy.ReasonEntitlementExpired},
		{"deny 压过一切",
			[]policy.Entitlement{
				pipeRawRule("alice", "", policy.EffectAllow, expiry),
				pipeRawRule("alice", "", policy.EffectDeny, time.Time{}),
			},
			"alice", nil, pipeBaseNow, false, policy.ReasonDenyRule},
		{"组级授权带期限也算数",
			[]policy.Entitlement{pipeRawRule("role:staff", "", policy.EffectAllow, expiry)},
			"carol", []string{"staff"}, pipeBaseNow, true, policy.ReasonGroupAllow},
		{"跨组织不借授权（范围不含 hospital 的规则不生效）",
			[]policy.Entitlement{pipeRawRule("alice", "organization:hospital-a", policy.EffectAllow, expiry)},
			"alice", nil, pipeBaseNow, false, policy.ReasonNoMatchingRule},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			var checker RawBodyGrantChecker = pipeGrantResolver(t, tc.rules...)
			ctx := pipeCtx(t, tc.subject, tc.roles...)
			allowed, reason := checker.AllowsRawBody(ctx, pipeChain(tc.subject), tc.now)
			if allowed != tc.wantAllow || reason != tc.wantReason {
				t.Fatalf("AllowsRawBody = (%v, %s)，期望 (%v, %s)", allowed, reason, tc.wantAllow, tc.wantReason)
			}
			if allowed && tc.wantReason != policy.ReasonExplicitAllow && tc.wantReason != policy.ReasonGroupAllow {
				t.Fatal("只有显式或组级授权可以放行原文出网")
			}
		})
	}

	// 身份过期同样 fail_closed：判定不吃墙上时钟，只吃显式 now。
	stale := pipeGrantResolver(t, pipeRawRule("role:staff", "", policy.EffectAllow, expiry))
	ctx := pipeCtx(t, "carol", "staff")
	late := pipeBaseNow.AddDate(0, 0, 60) // 身份 ExpiresAt = base+30d，已过
	if ok, reason := stale.AllowsRawBody(ctx, pipeChain("carol"), late); ok || reason != policy.ReasonIdentityExpired {
		t.Fatalf("身份过期后应 fail_closed: (%v, %s)", ok, reason)
	}
}

// pipeGrantSpy 是 fake 授权判定器，用来取证「判定吃的 now 是谁给的」。
type pipeGrantSpy struct {
	mu        sync.Mutex
	allowed   bool
	reason    policy.Reason
	calls     int
	lastNow   time.Time
	lastCtx   policy.PolicyContext
	lastChain policy.ScopeChain
}

func (s *pipeGrantSpy) AllowsRawBody(ctx policy.PolicyContext, chain policy.ScopeChain, now time.Time) (bool, policy.Reason) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.lastCtx, s.lastChain, s.lastNow = ctx, chain, now
	return s.allowed, s.reason
}

func (s *pipeGrantSpy) snapshot() (int, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.lastNow
}

func TestGrantCheckUsesExplicitNowFromRequest(t *testing.T) {
	spy := &pipeGrantSpy{allowed: false, reason: policy.ReasonRawBodyGrantMissing}
	behaviors := map[string]pipeBehavior{"gate": {fn: func(_ context.Context, in *Input) (*Output, error) {
		granted, reason := spy.AllowsRawBody(in.Policy, in.Chain, in.Now)
		in.NoteGrantReason(reason)
		if !granted {
			return nil, Errorf(ErrRawBodyDenied, "原文出网未获管理员授权")
		}
		return &Output{}, nil
	}}}
	spec := pipeSpec("gate", PhaseBeforeUpstream, policy.BodyTransform)
	spec.AllowRawBody = true
	spec.AllowedEndpoints = []string{"https://sidecar.test/"}
	spec.FailClosed = false // 违规类失败：fail_open 也跳不过
	p, _, _ := pipeBuild(t, behaviors, spec)

	req := pipeRequest(t, "now-1", NewBufferedBody([]byte("body")))
	res, err := p.RunRequest(context.Background(), req)
	if err == nil {
		t.Fatal("未授权时必须 fail_closed 拒绝，绝不能按允许处理")
	}
	calls, seen := spy.snapshot()
	if calls != 1 {
		t.Fatalf("判定次数 = %d", calls)
	}
	if !seen.Equal(pipeBaseNow) || seen.IsZero() {
		t.Errorf("判定收到的 now = %v，必须原样来自 Request.Now（禁止 time.Now()）", seen)
	}
	if spy.lastCtx.Identity.Subject != "alice" || spy.lastCtx.Purpose != "qa" {
		t.Errorf("判定上下文透传不对: %+v", spy.lastCtx)
	}
	if len(spy.lastChain) != 2 {
		t.Errorf("范围链没有透传: %v", spy.lastChain)
	}
	if res.Outcome != ReasonGrantMissing {
		t.Errorf("Outcome = %s，期望 raw_body_grant_missing", res.Outcome)
	}
	// 失败路径也要把策略侧原因码留在审计里（合规事件 vs 可用性事件要能分开）。
	entry := pipeEntry(t, res, "gate")
	if entry.GrantReason != policy.ReasonRawBodyGrantMissing {
		t.Errorf("GrantReason = %q", entry.GrantReason)
	}

	// now 的零值必须由调用方掌控：Request.Now 留空时 Input.Now 也为零（不注入墙上时钟）。
	zeroSpy := &pipeGrantSpy{}
	behaviors2 := map[string]pipeBehavior{"gate": {fn: func(_ context.Context, in *Input) (*Output, error) {
		zeroSpy.AllowsRawBody(in.Policy, in.Chain, in.Now)
		return &Output{}, nil
	}}}
	p2, _, _ := pipeBuild(t, behaviors2, pipeSpec("gate", PhaseBeforeUpstream, policy.BodyMetadataOnly))
	if _, err := p2.RunRequest(context.Background(), pipeRequest(t, "now-2", nil)); err != nil {
		t.Fatal(err)
	}
	req3 := pipeRequest(t, "now-3", nil)
	req3.Now = time.Time{}
	if _, err := p2.RunRequest(context.Background(), req3); err != nil {
		t.Fatal(err)
	}
	if _, seen := zeroSpy.snapshot(); !seen.IsZero() {
		t.Errorf("Request.Now 留空时 Pipeline 却注入了时间: %v", seen)
	}
	_ = zeroSpy.calls
}

// pipeGrantProbe 用注册期注入的 Config.Grants 做判定 —— 与 sidecar 的接法一致：
// 判定本身完全交给 A 包，探针只做「必须去查、查不到就拒」。
type pipeGrantProbe struct {
	spec Spec
	cfg  *Config
	rec  *pipeRecorder
}

func (g *pipeGrantProbe) Spec() Spec { return g.spec }

func (g *pipeGrantProbe) Process(ctx context.Context, in *Input) (*Output, error) {
	g.rec.note(in)
	if !in.Spec.AllowRawBody {
		return &Output{}, nil
	}
	if g.cfg == nil || g.cfg.Grants == nil {
		return nil, Errorf(ErrGrantCheckerBlank, "%s: 未注入授权判定器", g.spec.Name)
	}
	granted, reason := g.cfg.Grants.AllowsRawBody(in.Policy, in.Chain, in.Now)
	in.NoteGrantReason(reason)
	if !granted {
		return nil, Errorf(ErrRawBodyDenied, "%s: 管理员未授权原文出网", g.spec.Name)
	}
	return &Output{}, nil
}

func pipeProbePipeline(t *testing.T, grants RawBodyGrantChecker, spec Spec) *Pipeline {
	t.Helper()
	reg := NewRegistry()
	rec := pipeNewRecorder()
	if err := reg.RegisterType("pipe-grant-probe", func(s Spec, cfg *Config) (Processor, error) {
		return &pipeGrantProbe{spec: s, cfg: cfg, rec: rec}, nil
	}); err != nil {
		t.Fatal(err)
	}
	spec.Type = "pipe-grant-probe"
	if err := reg.Register(spec, &Config{Grants: grants}); err != nil {
		t.Fatalf("注册探针失败: %v", err)
	}
	p, err := reg.Build([]Spec{spec}, nil)
	if err != nil {
		t.Fatalf("装配失败: %v", err)
	}
	return p
}

// TestProcessorSideConsultsGrantChecker 端到端钉住「processor 侧真的去查管理员授权，
// 而不是自己放过」：通配 default_allow 在 A 包不算授权，处理器侧就必须拒。
func TestProcessorSideConsultsGrantChecker(t *testing.T) {
	mkSpec := func() Spec {
		s := pipeSpec("probe", PhaseBeforeUpstream, policy.BodyTransform)
		s.Type = "pipe-grant-probe"
		s.AllowRawBody = true
		s.AllowedEndpoints = []string{"https://sidecar.test/"}
		s.FailClosed = false // 合规缺口不许被 fail_open 冲掉
		return s
	}

	t.Run("通配放行不构成授权", func(t *testing.T) {
		wildcard := pipeGrantResolver(t, pipeRawRule("*", "", policy.EffectAllow, time.Time{}))
		p := pipeProbePipeline(t, wildcard, mkSpec())
		res, err := p.RunRequest(context.Background(), pipeRequest(t, "g-wild", NewBufferedBody([]byte("raw"))))
		if err == nil {
			t.Fatal("通配 default_allow 下竟然放行原文出网")
		}
		if res.Outcome != ReasonGrantMissing {
			t.Errorf("Outcome = %s", res.Outcome)
		}
		if got := pipeEntry(t, res, "probe").GrantReason; got != policy.ReasonRawBodyGrantMissing {
			t.Errorf("GrantReason = %q，期望策略侧码", got)
		}
	})

	t.Run("真授权（显式+期限）才放行", func(t *testing.T) {
		granted := pipeGrantResolver(t, pipeRawRule("alice", "", policy.EffectAllow, pipeBaseNow.Add(time.Hour)))
		p := pipeProbePipeline(t, granted, mkSpec())
		res, err := p.RunRequest(context.Background(), pipeRequest(t, "g-ok", NewBufferedBody([]byte("raw"))))
		if err != nil {
			t.Fatalf("有效授权应放行: %v", err)
		}
		if res.Outcome != ReasonOK {
			t.Errorf("Outcome = %s", res.Outcome)
		}
		entry := pipeEntry(t, res, "probe")
		if entry.GrantReason != policy.ReasonExplicitAllow {
			t.Errorf("GrantReason = %q", entry.GrantReason)
		}
		if entry.SummaryOnly {
			t.Error("原文已获授权并直发，不该标记 summary_only")
		}
		if entry.Outcome != ReasonOK {
			t.Errorf("条目 Outcome = %s", entry.Outcome)
		}
	})

	t.Run("授权到期后同一请求被拒（now 驱动）", func(t *testing.T) {
		expiry := pipeBaseNow.Add(time.Hour)
		granted := pipeGrantResolver(t, pipeRawRule("alice", "", policy.EffectAllow, expiry))
		p := pipeProbePipeline(t, granted, mkSpec())
		req := pipeRequest(t, "g-exp", NewBufferedBody([]byte("raw")))
		if _, err := p.RunRequest(context.Background(), req); err != nil {
			t.Fatalf("到期前必须放行: %v", err)
		}
		req2 := pipeRequest(t, "g-exp2", NewBufferedBody([]byte("raw")))
		req2.Now = expiry.Add(time.Second)
		res, err := p.RunRequest(context.Background(), req2)
		if err == nil {
			t.Fatal("到期后必须拒绝")
		}
		if got := pipeEntry(t, res, "probe").GrantReason; got != policy.ReasonEntitlementExpired {
			t.Errorf("GrantReason = %q，期望区分「配过但过期」", got)
		}
	})

	t.Run("声明 allow_raw_body 却没注入判定器", func(t *testing.T) {
		p := pipeProbePipeline(t, nil, mkSpec())
		_, err := p.RunRequest(context.Background(), pipeRequest(t, "g-blank", NewBufferedBody([]byte("raw"))))
		if err == nil {
			t.Fatal("拿不到判定器绝不能按允许处理（fail_closed）")
		}
		if !errors.Is(err, ErrGrantCheckerBlank) {
			t.Errorf("应报 ErrGrantCheckerBlank: %v", err)
		}
	})
}

func TestTransformedBodyFlagVisibleToLaterStages(t *testing.T) {
	// §2.9 规则 3 的分界信息：链上是否已经有人把原文换掉，后面的处理器只能靠
	// Input.TransformedBody() 判断「我拿到的是脱敏正文还是客户端原文」。
	var firstVal, secondVal bool
	behaviors := map[string]pipeBehavior{
		"first": {fn: func(_ context.Context, in *Input) (*Output, error) {
			firstVal = in.TransformedBody()
			return &Output{Body: []byte("MASKED")}, nil
		}},
		"second": {fn: func(_ context.Context, in *Input) (*Output, error) {
			secondVal = in.TransformedBody()
			data, err := in.Body()
			if err != nil {
				return nil, err
			}
			if string(data) != "MASKED" {
				return nil, errors.New("第二个处理器读到的不是上一档产出")
			}
			return &Output{}, nil
		}},
	}
	p, _, _ := pipeBuild(t, behaviors,
		pipeSpec("first", PhaseBeforeUpstream, policy.BodyTransform),
		pipeSpec("second", PhaseBeforeUpstream, policy.BodyTransform))
	if _, err := p.RunRequest(context.Background(), pipeRequest(t, "tf", NewBufferedBody([]byte("client-original")))); err != nil {
		t.Fatal(err)
	}
	if firstVal {
		t.Error("链首处理器的 TransformedBody 应为 false（它拿到的就是客户端原文）")
	}
	if !secondVal {
		t.Error("替换发生后的处理器 TransformedBody 应为 true")
	}
}

func TestGrantReasonAndSummaryOnlyRecordedOnBothPaths(t *testing.T) {
	// 留痕必须覆盖成功与失败两条路径：pipeline.go 在 classify 之前统一拷贝
	// deniedReads / summaryOnly / grantReason。
	behaviors := map[string]pipeBehavior{
		"ok": {fn: func(_ context.Context, in *Input) (*Output, error) {
			in.NoteGrantReason(policy.ReasonExplicitAllow)
			in.NoteSummaryOnlyFallback()
			return &Output{}, nil
		}},
		"bad": {fn: func(_ context.Context, in *Input) (*Output, error) {
			in.NoteGrantReason(policy.ReasonRawBodyGrantMissing)
			in.NoteSummaryOnlyFallback()
			return nil, Errorf(ErrProcessFailed, "依赖故障")
		}},
	}
	okSpec := pipeSpec("ok", PhaseBeforeUpstream, policy.BodyMetadataOnly)
	badSpec := pipeSpec("bad", PhaseBeforeUpstream, policy.BodyMetadataOnly)
	badSpec.FailClosed = false // fail_open 跳过也要保住合规留痕
	p, _, _ := pipeBuild(t, behaviors, okSpec, badSpec)
	res, err := p.RunRequest(context.Background(), pipeRequest(t, "trace", nil))
	if err != nil {
		t.Fatal(err)
	}
	eOK := pipeEntry(t, res, "ok")
	if eOK.GrantReason != policy.ReasonExplicitAllow || !eOK.SummaryOnly {
		t.Errorf("成功路径留痕丢失: %+v", eOK)
	}
	eBad := pipeEntry(t, res, "bad")
	if eBad.GrantReason != policy.ReasonRawBodyGrantMissing || !eBad.SummaryOnly {
		t.Errorf("失败路径留痕丢失: %+v", eBad)
	}
	if eBad.Outcome != ReasonFailOpenSkipped {
		t.Errorf("bad 条目 Outcome = %s", eBad.Outcome)
	}
}
