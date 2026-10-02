package processor

// 第一波补测试（流水线与准入）：本文件承载共享助手（统一 pipe 前缀，任务约定，
// 避免与第二波的 processor_helpers_test.go 撞名）与 pipeline.go / body.go 的
// 行为测试：顺序与短路、fail_open/fail_closed、超时、超限、流式透传、并发、
// 正文释放与审计不泄露。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// ------------------------------------------------------------------ 共享助手

const pipeTypeFake = "pipe-fake"

// pipeBaseNow 是所有测试显式传入的时间基准：流水线与准入判定都必须原样使用它，
// 任何一处偷用 time.Now 都会让这里的确定性断言变红。
var pipeBaseNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// pipeBehavior 是一个 fake 处理器的行为脚本；stream 非空时该 fake 实现 StreamProcessor。
type pipeBehavior struct {
	fn     func(context.Context, *Input) (*Output, error)
	stream func(context.Context, *Input, io.Reader) (io.Reader, error)
}

// pipeRecorder 汇总 fake 的调用轨迹（并发安全）。
type pipeRecorder struct {
	mu     sync.Mutex
	order  []string
	inputs map[string][]*Input
}

func pipeNewRecorder() *pipeRecorder {
	return &pipeRecorder{inputs: make(map[string][]*Input)}
}

func (r *pipeRecorder) note(in *Input) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order = append(r.order, in.Spec.Name)
	r.inputs[in.Spec.Name] = append(r.inputs[in.Spec.Name], in)
}

func (r *pipeRecorder) sequence() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.order...)
}

func (r *pipeRecorder) calls(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.inputs[name])
}

func (r *pipeRecorder) lastInput(name string) *Input {
	r.mu.Lock()
	defer r.mu.Unlock()
	list := r.inputs[name]
	if len(list) == 0 {
		return nil
	}
	return list[len(list)-1]
}

// pipePlain 是只实现 Process 的 fake：WrapStream 会判定它不支持流式。
type pipePlain struct {
	spec Spec
	cfg  *Config
	rec  *pipeRecorder
	beh  pipeBehavior
}

func (f *pipePlain) Spec() Spec { return f.spec }

func (f *pipePlain) Process(ctx context.Context, in *Input) (*Output, error) {
	f.rec.note(in)
	if f.beh.fn == nil {
		return &Output{}, nil
	}
	return f.beh.fn(ctx, in)
}

// pipeStreamed 在 pipePlain 之上补 ProcessStream。
type pipeStreamed struct {
	pipePlain
}

func (s *pipeStreamed) ProcessStream(ctx context.Context, in *Input, src io.Reader) (io.Reader, error) {
	s.rec.note(in)
	if s.beh.stream == nil {
		return src, nil
	}
	return s.beh.stream(ctx, in, src)
}

func pipeFactory(rec *pipeRecorder, behaviors map[string]pipeBehavior) Factory {
	return func(spec Spec, cfg *Config) (Processor, error) {
		base := pipePlain{spec: spec, cfg: cfg, rec: rec}
		if behaviors != nil {
			base.beh = behaviors[spec.Name]
		}
		if base.beh.stream != nil {
			return &pipeStreamed{pipePlain: base}, nil
		}
		return &base, nil
	}
}

func pipeSpec(name string, phase Phase, access policy.BodyAccess) Spec {
	return Spec{
		Name:           name,
		Type:           pipeTypeFake,
		Phase:          phase,
		Version:        "v1",
		Timeout:        2 * time.Second,
		MaxInputBytes:  1 << 20,
		MaxOutputBytes: 1 << 20,
		FailClosed:     true,
		BodyAccess:     access,
	}
}

// pipeBuild 用自定义 fake 类型装配一条链：注册发生在构造期，任何 Spec/Config 错误
// 都会在这里 t.Fatal，不会拖到请求路径。
func pipeBuildCfg(t *testing.T, cfg *Config, behaviors map[string]pipeBehavior, specs ...Spec) (*Pipeline, *pipeRecorder, *Registry) {
	t.Helper()
	rec := pipeNewRecorder()
	reg := NewRegistry()
	if err := reg.RegisterType(pipeTypeFake, pipeFactory(rec, behaviors)); err != nil {
		t.Fatalf("注册 fake 类型失败: %v", err)
	}
	for _, s := range specs {
		if err := reg.Register(s, cfg); err != nil {
			t.Fatalf("注册 %s 失败: %v", s.Name, err)
		}
	}
	p, err := reg.Build(specs, &BuildOptions{PolicyVersion: "test-bundle@1"})
	if err != nil {
		t.Fatalf("装配失败: %v", err)
	}
	return p, rec, reg
}

func pipeBuild(t *testing.T, behaviors map[string]pipeBehavior, specs ...Spec) (*Pipeline, *pipeRecorder, *Registry) {
	t.Helper()
	return pipeBuildCfg(t, nil, behaviors, specs...)
}

func pipeIdentity(t *testing.T, subject string, roles ...string) policy.Identity {
	t.Helper()
	id, err := policy.NewIdentity(subject, "oidc-test")
	if err != nil {
		t.Fatalf("构造身份失败: %v", err)
	}
	if len(roles) > 0 {
		id.Roles = roles
		id.ExpiresAt = pipeBaseNow.AddDate(0, 0, 30)
	}
	return id
}

func pipeCtx(t *testing.T, subject string, roles ...string) policy.PolicyContext {
	t.Helper()
	ctx, err := policy.NewPolicyContext(pipeIdentity(t, subject, roles...), "qa", policy.LevelInternal)
	if err != nil {
		t.Fatalf("构造策略上下文失败: %v", err)
	}
	ctx.Organization = "university"
	return ctx
}

func pipeChain(subject string) policy.ScopeChain {
	return policy.MustScopeChain(
		policy.MustScope(policy.ScopeUser, subject),
		policy.MustScope(policy.ScopeOrganization, "university"),
	)
}

func pipeRequest(t *testing.T, requestID string, body *Body) *Request {
	t.Helper()
	return &Request{
		RequestID: requestID,
		Model:     "gpt-test",
		Body:      body,
		Policy:    pipeCtx(t, "alice"),
		Chain:     pipeChain("alice"),
		Now:       pipeBaseNow,
	}
}

func pipeResponse(requestID string, body *Body) *Response {
	return &Response{
		RequestID:   requestID,
		Model:       "gpt-test",
		StatusCode:  200,
		ContentType: "application/json",
		Body:        body,
	}
}

// pipeSource 是带读取计数的正文字流：所有「不得把正文读进内存」的断言都靠它取证。
type pipeSource struct {
	data  []byte
	pos   int
	bytes atomic.Int64
}

func (s *pipeSource) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	n := copy(p, s.data[s.pos:])
	s.pos += n
	s.bytes.Add(int64(n))
	return n, nil
}

func (s *pipeSource) readBytes() int64 { return s.bytes.Load() }

// pipePanicReader 一被读取就 panic：doc.go 承诺的「未启用正文处理时一个字节都不碰」
// 由它做最尖锐的证明。
type pipePanicReader struct{}

func (pipePanicReader) Read([]byte) (int, error) {
	panic("metadata-only 路径读取了正文")
}

// pipeFlakySource 先给 head 字节再报错，模拟流中途断裂。
type pipeFlakySource struct {
	head []byte
	sent int
}

func (f *pipeFlakySource) Read(p []byte) (int, error) {
	if f.sent >= len(f.head) {
		return 0, errors.New("上游连接中断")
	}
	n := copy(p, f.head[f.sent:])
	f.sent += n
	return n, nil
}

// pipeUpcase 是增量过滤 fake：就地转大写，零额外缓冲，并把高水位往下传。
type pipeUpcase struct{ src io.Reader }

func (u *pipeUpcase) Read(p []byte) (int, error) {
	n, err := u.src.Read(p)
	for i := 0; i < n; i++ {
		if c := p[i]; c >= 'a' && c <= 'z' {
			p[i] = c - 32
		}
	}
	return n, err
}

func (u *pipeUpcase) streamMaxBuffered() int { return maxBufferedOf(u.src) }

// ------------------------------------------------------------------ 断言助手

func pipeEntry(t *testing.T, res *Result, name string) AuditEntry {
	t.Helper()
	for _, e := range res.Entries {
		if e.Processor == name {
			return e
		}
	}
	t.Fatalf("审计里没有处理器 %s 的条目（共 %d 条）", name, len(res.Entries))
	return AuditEntry{}
}

func pipeHasReason(t *testing.T, res *Result, want Reason) {
	t.Helper()
	for _, r := range res.Reasons {
		if r == want {
			return
		}
	}
	t.Fatalf("原因链 %v 里没有 %s", res.Reasons, want)
}

// pipeAssertAuditReasonsSane 检查审计面所有原因码都在注册表内（§5：稳定枚举）。
func pipeAssertAuditReasonsSane(t *testing.T, res *Result) {
	t.Helper()
	if !res.Outcome.Valid() {
		t.Errorf("Result.Outcome %q 不在原因码注册表内", res.Outcome)
	}
	for _, r := range res.Reasons {
		if !r.Valid() {
			t.Errorf("Result.Reasons 含未注册码 %q", r)
		}
	}
	for _, e := range res.Entries {
		if !e.Outcome.Valid() {
			t.Errorf("%s: Outcome %q 未注册", e.Processor, e.Outcome)
		}
		for _, r := range e.Reasons {
			if !r.Valid() {
				t.Errorf("%s: Reasons 含未注册码 %q", e.Processor, r)
			}
		}
	}
}

// pipeForbiddenLeakWords 与 internal/policy/leak_test.go、internal/identity/leak_test.go
// 同口径：审计面的结构体连字段名都不许出现这些词。
var pipeForbiddenLeakWords = []string{
	"body", "payload", "content", "prompt", "message", "token", "secret",
	"api_key", "apikey", "credential", "password", "raw", "text",
}

func pipeAssertNoLeakFields(t *testing.T, value any) {
	t.Helper()
	typ := reflect.TypeOf(value)
	for typ != nil && typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ == nil || typ.Kind() != reflect.Struct {
		t.Fatalf("只对结构体做字段审查，当前是 %v", typ)
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue // 未导出字段不参与序列化
		}
		tag := strings.ToLower(field.Tag.Get("json"))
		if j := strings.Index(tag, ","); j >= 0 {
			tag = tag[:j]
		}
		haystack := strings.ToLower(field.Name) + "|" + tag
		for _, word := range pipeForbiddenLeakWords {
			if strings.Contains(haystack, word) {
				t.Errorf("%s.%s（json=%q）含被禁字段词 %q：审计对象不得携带正文/凭证类字段",
					typ.Name(), field.Name, field.Tag.Get("json"), word)
			}
		}
	}
}

// ------------------------------------------------------------------ 顺序与短路

func TestPipelineRunsStagesInOrderAndShortCircuitsOnDeny(t *testing.T) {
	boom := Errorf(ErrContentBlocked, "命中拦截规则")
	behaviors := map[string]pipeBehavior{
		"first":  {fn: func(context.Context, *Input) (*Output, error) { return &Output{}, nil }},
		"second": {fn: func(context.Context, *Input) (*Output, error) { return nil, boom }},
		"third":  {fn: func(context.Context, *Input) (*Output, error) { return &Output{}, nil }},
	}
	specs := []Spec{
		pipeSpec("first", PhaseBeforeUpstream, policy.BodyMetadataOnly),
		pipeSpec("second", PhaseBeforeUpstream, policy.BodyMetadataOnly),
		pipeSpec("third", PhaseBeforeUpstream, policy.BodyMetadataOnly),
	}
	// second 故意 fail_open=false：判定成立（verdict）不许被 fail_open 冲掉。
	specs[1].FailClosed = false

	p, rec, _ := pipeBuild(t, behaviors, specs...)
	res, err := p.RunRequest(context.Background(), pipeRequest(t, "req-1", NewBufferedBody([]byte(`{"k":"v"}`))))
	if err == nil {
		t.Fatal("第二级判定拒绝后必须报错")
	}
	if got := rec.sequence(); strings.Join(got, ",") != "first,second" {
		t.Fatalf("短路失败：实际执行序列 %v", got)
	}
	if rec.calls("third") != 0 {
		t.Fatal("拒绝后第三级不得执行")
	}
	if res.Outcome != ReasonContentBlocked {
		t.Errorf("Result.Outcome = %s，期望 content_blocked", res.Outcome)
	}
	pipeHasReason(t, res, ReasonContentBlocked)
	// 被拒绝的处理器也要留痕（成功与失败两条路径都做审计）。
	if len(res.Entries) != 2 {
		t.Fatalf("审计条目应为 2（third 未执行不出现），实际 %d", len(res.Entries))
	}
	if got := pipeEntry(t, res, "second").Outcome; got != ReasonContentBlocked {
		t.Errorf("second 条目 Outcome = %s", got)
	}
	if pipeFindEntry(res, "third") != nil {
		t.Error("未执行的处理器不得出现在审计里")
	}
	pipeAssertAuditReasonsSane(t, res)
}

func pipeFindEntry(res *Result, name string) *AuditEntry {
	for i := range res.Entries {
		if res.Entries[i].Processor == name {
			return &res.Entries[i]
		}
	}
	return nil
}

func TestPipelineEnforcesCanonicalPhaseOrder(t *testing.T) {
	noop := func(context.Context, *Input) (*Output, error) { return &Output{}, nil }
	// 策略把执行次序写反：运行时必须按 §2.6 的固定阶段次序执行，
	// 策略里的顺序只影响同阶段内的先后（Registry.Build 的文档承诺）。
	behaviors := map[string]pipeBehavior{
		"cls": {fn: noop}, "route1": {fn: noop}, "route2": {fn: noop}, "up": {fn: noop},
	}
	specs := []Spec{
		pipeSpec("up", PhaseBeforeUpstream, policy.BodyMetadataOnly),
		pipeSpec("route2", PhaseBeforeRoute, policy.BodyMetadataOnly),
		pipeSpec("route1", PhaseBeforeRoute, policy.BodyMetadataOnly),
		pipeSpec("cls", PhaseBeforeClassify, policy.BodyMetadataOnly),
	}
	p, rec, _ := pipeBuild(t, behaviors, specs...)
	if _, err := p.RunRequest(context.Background(), pipeRequest(t, "req-order", nil)); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(rec.sequence(), ","); got != "cls,route2,route1,up" {
		t.Fatalf("跨阶段次序未规范化：实际 %s（同阶段内应保留策略顺序）", got)
	}
	// Specs/StagesFor 与规范化后的次序一致。
	if got := p.StagesFor(PhaseBeforeRoute); strings.Join(got, ",") != "route2,route1" {
		t.Fatalf("同阶段内顺序应保持策略顺序: %v", got)
	}
	if !p.HasStageFor(PhaseBeforeClassify) || p.HasStageFor(PhaseAudit) {
		t.Fatal("HasStageFor 判定错误")
	}
}

// ------------------------------------------------------------------ fail 策略显式化

func TestFailOpenSkipsInfrastructureFailureOnly(t *testing.T) {
	replace := func(context.Context, *Input) (*Output, error) {
		return &Output{Body: []byte("AAA")}, nil
	}
	crash := func(context.Context, *Input) (*Output, error) {
		// 基础设施故障 + 附带产出：产出必须整体丢弃，正文停留在故障前形态。
		return &Output{Body: []byte("partial")}, Errorf(ErrProcessFailed, "依赖故障")
	}
	last := func(context.Context, *Input) (*Output, error) { return &Output{}, nil }

	behaviors := map[string]pipeBehavior{"a": {fn: replace}, "b": {fn: crash}, "c": {fn: last}}
	specA := pipeSpec("a", PhaseBeforeUpstream, policy.BodyTransform)
	specB := pipeSpec("b", PhaseBeforeUpstream, policy.BodyTransform)
	specB.FailClosed = false
	specC := pipeSpec("c", PhaseBeforeUpstream, policy.BodyTransform)
	specC.FailClosed = false

	p, rec, _ := pipeBuild(t, behaviors, specA, specB, specC)
	res, err := p.RunRequest(context.Background(), pipeRequest(t, "req-fo", NewBufferedBody([]byte("orig"))))
	if err != nil {
		t.Fatalf("fail_open 的基础设施故障不应拒绝整次请求: %v", err)
	}
	if rec.calls("c") != 1 {
		t.Fatal("跳过后链条应继续执行")
	}
	if string(res.Body) != "AAA" {
		t.Fatalf("被跳过处理器的产出发出正文污染: %q", res.Body)
	}
	if res.Outcome != ReasonFailOpenSkipped {
		t.Errorf("Outcome = %s，期望 fail_open_skipped", res.Outcome)
	}
	pipeHasReason(t, res, ReasonFailed)
	pipeHasReason(t, res, ReasonFailOpenSkipped)
	entryB := pipeEntry(t, res, "b")
	if entryB.Outcome != ReasonFailOpenSkipped {
		t.Errorf("b 条目 Outcome = %s", entryB.Outcome)
	}
	if entryB.OutputBytes != 0 {
		t.Errorf("b 被跳过不应有输出字节记录: %d", entryB.OutputBytes)
	}

	// 反面：同一个故障在 fail_closed 下必须拒掉整次请求。
	specB.FailClosed = true
	p2, rec2, _ := pipeBuild(t, behaviors, specA, specB, specC)
	res2, err2 := p2.RunRequest(context.Background(), pipeRequest(t, "req-fc", NewBufferedBody([]byte("orig"))))
	if err2 == nil {
		t.Fatal("fail_closed 的依赖故障必须拒绝请求")
	}
	if rec2.calls("c") != 0 {
		t.Fatal("fail_closed 拒绝后链条不得继续")
	}
	if res2.Outcome != ReasonFailed {
		t.Errorf("Outcome = %s，期望 processor_failed", res2.Outcome)
	}
	pipeAssertAuditReasonsSane(t, res)
	pipeAssertAuditReasonsSane(t, res2)
}

func TestViolationAndVerdictFailuresIgnoreFailOpen(t *testing.T) {
	cases := []struct {
		title    string
		err      error
		wantCode Reason
	}{
		{"档位越权替换", Errorf(ErrBodyReplaceDenied, "越权替换"), ReasonBodyReplaceDenied},
		{"出网目标未授权", Errorf(ErrEndpointDenied, "目标不在白名单"), ReasonEndpointDenied},
		{"原文未获管理员授权", Errorf(ErrRawBodyDenied, "缺授权"), ReasonGrantMissing},
		{"输入超限", Errorf(ErrInputTooLarge, "超限"), ReasonInputTooLarge},
		{"判定成立", Errorf(ErrSchemaViolation, "不符 schema"), ReasonSchemaViolation},
		{"内容命中拦截", Errorf(ErrContentBlocked, "命中"), ReasonContentBlocked},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			failure := tc.err
			behaviors := map[string]pipeBehavior{
				"solo": {fn: func(context.Context, *Input) (*Output, error) { return nil, failure }},
				"next": {fn: func(context.Context, *Input) (*Output, error) { return &Output{}, nil }},
			}
			spec := pipeSpec("solo", PhaseBeforeUpstream, policy.BodyTransform)
			spec.FailClosed = false // 安全违规不允许被这个开关跳过
			p, rec, _ := pipeBuild(t, behaviors, spec, pipeSpec("next", PhaseBeforeUpstream, policy.BodyMetadataOnly))
			res, err := p.RunRequest(context.Background(), pipeRequest(t, "req-v", NewBufferedBody([]byte("x"))))
			if err == nil {
				t.Fatal("违规/判定类失败必须拒绝，即使 fail_open")
			}
			if res.Outcome != tc.wantCode {
				t.Errorf("Outcome = %s，期望 %s", res.Outcome, tc.wantCode)
			}
			if rec.calls("next") != 0 {
				t.Fatal("违规拒绝后链条不得继续")
			}
		})
	}
}

// ------------------------------------------------------------------ 超时

func TestProcessorTimeoutUsesStableReasonAndKeepsBodyWhole(t *testing.T) {
	replace := func(context.Context, *Input) (*Output, error) {
		return &Output{Body: []byte("AAA")}, nil
	}
	late := func(context.Context, *Input) (*Output, error) {
		// 不尊重 deadline 的处理器：运行时必须兜住，且其产出不得进链条。
		time.Sleep(80 * time.Millisecond)
		return &Output{Body: []byte("PARTIAL-HALF-DONE")}, nil
	}
	behaviors := map[string]pipeBehavior{"pre": {fn: replace}, "slow": {fn: late}}

	for _, failClosed := range []bool{true, false} {
		slow := pipeSpec("slow", PhaseBeforeUpstream, policy.BodyTransform)
		slow.Timeout = 20 * time.Millisecond
		slow.FailClosed = failClosed
		p, _, _ := pipeBuild(t, behaviors, pipeSpec("pre", PhaseBeforeUpstream, policy.BodyTransform), slow)
		res, err := p.RunRequest(context.Background(), pipeRequest(t, "req-to", NewBufferedBody([]byte("orig"))))
		if failClosed {
			if err == nil {
				t.Fatal("fail_closed 下超时必须拒绝整次请求")
			}
			if res.Outcome != ReasonTimeout {
				t.Errorf("Outcome = %s，期望稳定码 processor_timeout", res.Outcome)
			}
			pipeHasReason(t, res, ReasonTimeout)
		} else {
			if err != nil {
				t.Fatalf("fail_open 下超时按跳过处理: %v", err)
			}
			if res.Outcome != ReasonFailOpenSkipped {
				t.Errorf("fail_open 超时后 Outcome = %s", res.Outcome)
			}
		}
		// 两条路径都不许留下超时处理器的半成品正文。
		if string(res.Body) != "AAA" {
			t.Fatalf("放行半成品正文: %q", res.Body)
		}
		entry := pipeEntry(t, res, "slow")
		if entry.OutputBytes != 0 {
			t.Errorf("超时条目不应记录输出字节: %d", entry.OutputBytes)
		}
		if entry.Outcome != ReasonTimeout && failClosed {
			t.Errorf("条目 Outcome = %s", entry.Outcome)
		}
	}
}

func TestInvokeRejectsOutOfRangeTimeout(t *testing.T) {
	// 绕过 Build 手搭 Spec（Timeout<=0 或 >2×MaxTimeout）：invoke 必须拒绝执行而不是
	// 静默夹取或无限等待（「0 = 不限」在这里不存在）。
	for _, bad := range []time.Duration{0, -time.Second, 2*MaxTimeout + time.Second} {
		spec := pipeSpec("bad", PhaseBeforeUpstream, policy.BodyMetadataOnly)
		spec.Timeout = bad
		rec := pipeNewRecorder()
		proc, err := pipeFactory(rec, map[string]pipeBehavior{"bad": {}})(spec, nil)
		if err != nil {
			t.Fatal(err)
		}
		p := &Pipeline{stages: []stage{{spec: spec, proc: proc}}, clock: time.Now}
		res, err := p.RunRequest(context.Background(), pipeRequest(t, "req-bt", nil))
		if err == nil {
			t.Fatalf("timeout=%v 必须拒绝执行", bad)
		}
		if res.Outcome != ReasonConfigInvalid {
			t.Errorf("Outcome = %s，期望 processor_config_invalid", res.Outcome)
		}
		if rec.calls("bad") != 0 {
			t.Fatal("越界 timeout 不得把处理器跑起来")
		}
	}
}

// ------------------------------------------------------------------ 大小限制 / body.go

func TestInputTooLargeIsViolationAndNotFullyRead(t *testing.T) {
	big := &pipeSource{data: []byte(strings.Repeat("x", 4096))}
	readAll := func(_ context.Context, in *Input) (*Output, error) {
		if _, err := in.Body(); err != nil {
			return nil, err
		}
		return &Output{}, nil
	}
	behaviors := map[string]pipeBehavior{"gate": {fn: readAll}}
	spec := pipeSpec("gate", PhaseBeforeUpstream, policy.BodyTransform)
	spec.MaxInputBytes = 64
	spec.MaxOutputBytes = 4096
	spec.FailClosed = false // 超限是违规：fail_open 也跳不过去

	p, _, _ := pipeBuild(t, behaviors, spec)
	res, err := p.RunRequest(context.Background(), pipeRequest(t, "req-big", NewBodyReader(big, 4096)))
	if err == nil {
		t.Fatal("输入超过 MaxInputBytes 必须拒绝")
	}
	if res.Outcome != ReasonInputTooLarge {
		t.Errorf("Outcome = %s", res.Outcome)
	}
	// 关键：超限内容没有被读进内存 —— 只碰了上限 +1 字节用于鉴别「正好/超出」。
	if got := big.readBytes(); got > 65 {
		t.Fatalf("超限正文被整段读进内存：源侧被读走 %d 字节（上限 64+1）", got)
	}
	if res.Buffered || len(res.Body) != 0 {
		t.Error("超限失败不得留下缓冲产物")
	}
}

func TestBodyReaderBoundaryDeclaredMismatchAndMidReadError(t *testing.T) {
	t.Run("正好等于上限放行，多一字节拒绝", func(t *testing.T) {
		readAll := func(_ context.Context, in *Input) (*Output, error) {
			data, err := in.Body()
			if err != nil {
				return nil, err
			}
			// 契约要求产出**新**正文（规则 2）：把读到的切片原样当替换正文交回，
			// 会在释放上一档时被清零 —— 这是实现层陷阱，已按缺陷上报主线。
			fresh := append([]byte(nil), data...)
			return &Output{Body: fresh}, nil
		}
		mk := func(size int) (*Result, error) {
			src := &pipeSource{data: []byte(strings.Repeat("y", size))}
			spec := pipeSpec("b", PhaseBeforeUpstream, policy.BodyTransform)
			spec.MaxInputBytes = 64
			spec.MaxOutputBytes = 1 << 20
			p, _, _ := pipeBuild(t, map[string]pipeBehavior{"b": {fn: readAll}}, spec)
			return p.RunRequest(context.Background(), pipeRequest(t, "req-bnd", NewBodyReader(src, int64(size))))
		}
		res, err := mk(64)
		if err != nil || string(res.Body) != strings.Repeat("y", 64) {
			t.Fatalf("64 字节应恰好放行: %v %q", err, res.Body)
		}
		if _, err := mk(65); err == nil {
			t.Fatal("65 字节必须拒绝（LimitReader+1 鉴别更多）")
		}
	})

	t.Run("声明长度与实际不符", func(t *testing.T) {
		var declared int64
		var gotLen int
		behaviors := map[string]pipeBehavior{"b": {fn: func(_ context.Context, in *Input) (*Output, error) {
			declared = in.DeclaredBodyBytes
			data, err := in.Body()
			gotLen = len(data)
			return nil, err
		}}}
		spec := pipeSpec("b", PhaseBeforeUpstream, policy.BodyInspect)
		p, _, _ := pipeBuild(t, behaviors, spec)
		src := &pipeSource{data: []byte(strings.Repeat("z", 20))}
		res, err := p.RunRequest(context.Background(), pipeRequest(t, "req-dm", NewBodyReader(src, 4096)))
		if err != nil {
			t.Fatal(err)
		}
		if declared != 4096 {
			t.Errorf("DeclaredBodyBytes = %d，期望按声明 4096 透传", declared)
		}
		if gotLen != 20 {
			t.Errorf("实际读取 %d 字节，期望 20（声明只是元数据）", gotLen)
		}
		// 审计里的 input_bytes 必须是真读到的量，不是声明量。
		if got := pipeEntry(t, res, "b").InputBytes; got != 20 {
			t.Errorf("条目 InputBytes = %d，期望 20", got)
		}
	})

	t.Run("reader 中途报错", func(t *testing.T) {
		readAll := func(_ context.Context, in *Input) (*Output, error) {
			if _, err := in.Body(); err != nil {
				return nil, err
			}
			return &Output{}, nil
		}
		for _, failClosed := range []bool{true, false} {
			spec := pipeSpec("b", PhaseBeforeUpstream, policy.BodyInspect)
			spec.FailClosed = failClosed
			p, _, _ := pipeBuild(t, map[string]pipeBehavior{"b": {fn: readAll}}, spec)
			src := &pipeFlakySource{head: []byte("partial-read")}
			res, err := p.RunRequest(context.Background(), pipeRequest(t, "req-fl", NewBodyReader(src, 12)))
			// 半截正文永远不得被缓冲放行：失败路径不留可转发的部分内容。
			if res.Buffered || len(res.Body) != 0 {
				t.Errorf("fail_closed=%v 时失败路径留下缓冲产物 buffered=%v body=%q", failClosed, res.Buffered, res.Body)
			}
			if failClosed {
				// 读取失败发生在 Input.Body() 内部，处理器如实上报：fail_closed 拒整次请求。
				if !errors.Is(err, ErrProcessFailed) {
					t.Fatalf("fail_closed 时错误应包 ErrProcessFailed: %v", err)
				}
				if res.Outcome != ReasonFailed {
					t.Errorf("fail_closed：Outcome = %s，期望 processor_failed（基础设施类）", res.Outcome)
				}
			} else {
				// 中途断流是基础设施失败：fail_open 可以跳过，但原因码必须留痕。
				if err != nil {
					t.Fatalf("fail_open 应跳过基础设施类失败: %v", err)
				}
				pipeHasReason(t, res, ReasonFailed)
				pipeHasReason(t, res, ReasonFailOpenSkipped)
				if res.Outcome != ReasonFailOpenSkipped {
					t.Errorf("fail_open：Outcome = %s", res.Outcome)
				}
			}
		}
	})

	t.Run("缓冲句柄与 nil 句柄的直接语义", func(t *testing.T) {
		b := NewBodyReader(strings.NewReader("hello"), 5)
		if b.DeclaredBytes() != 5 {
			t.Errorf("DeclaredBytes = %d", b.DeclaredBytes())
		}
		data, err := b.buffer(1024)
		if err != nil || string(data) != "hello" {
			t.Fatalf("buffer: %q %v", data, err)
		}
		if b.readBytesOf() != 5 {
			t.Errorf("readBytesOf = %d", b.readBytesOf())
		}
		// limit<=0 时夹到绝对上限，绝不出现「不限」。
		var nilBody *Body
		if nilBody.DeclaredBytes() != 0 {
			t.Error("nil 句柄声明大小应为 0")
		}
		if _, err := nilBody.buffer(10); !errors.Is(err, ErrNoBody) {
			t.Errorf("nil 句柄 buffer 应 ErrNoBody: %v", err)
		}
		if _, err := nilBody.stream(); !errors.Is(err, ErrNoBody) {
			t.Errorf("nil 句柄 stream 应 ErrNoBody: %v", err)
		}
		nilBody.discard() // 不得 panic
		if nilBody.bufferedData() != nil || nilBody.readBytesOf() != 0 {
			t.Error("nil 句柄辅助方法返回值不干净")
		}
		tooBig := NewBufferedBody([]byte(strings.Repeat("m", 200)))
		if _, err := tooBig.buffer(100); !errors.Is(err, ErrInputTooLarge) {
			t.Errorf("已缓冲超限也应拒绝: %v", err)
		}
	})
}

func TestBodyReleaseSemantics(t *testing.T) {
	// 借用语义：调用方的 buffer 只丢引用、不清零（那是人家的内存）。
	orig := []byte("caller-owned-secret")
	borrowed := NewBufferedBody(orig)
	if _, err := borrowed.buffer(1 << 10); err != nil {
		t.Fatal(err)
	}
	borrowed.discard()
	if string(orig) != "caller-owned-secret" {
		t.Fatal("借用句柄释放时不得清零调用方内存")
	}
	if _, err := borrowed.buffer(1 << 10); !errors.Is(err, ErrBodyAccessDenied) {
		t.Errorf("已释放句柄再读必须拒绝: %v", err)
	}
	if _, err := borrowed.stream(); !errors.Is(err, ErrBodyAccessDenied) {
		t.Errorf("已释放句柄取流必须拒绝: %v", err)
	}
	borrowed.discard() // 幂等

	// 自持语义：链条自己分配的拷贝释放时清零（§2.9 规则 2）。
	content := []byte("owned-secret")
	owned := NewOwnedBody(content)
	owned.discard()
	for i, c := range content {
		if c != 0 {
			t.Fatalf("owned 正文第 %d 字节未清零: %q", i, content)
		}
	}
}

func TestOriginalBodyReleasedAndNotReadableAgain(t *testing.T) {
	var savedIn *Input
	var produced []byte
	behaviors := map[string]pipeBehavior{
		"mask": {fn: func(_ context.Context, in *Input) (*Output, error) {
			savedIn = in // 故意把 Input 留到链条之外，模拟处理器藏引用回看原文
			out := &Output{Body: []byte("MASKED-ONE")}
			produced = out.Body
			return out, nil
		}},
		"swap": {fn: func(_ context.Context, in *Input) (*Output, error) {
			return &Output{Body: []byte("SWAPPED-TWO")}, nil
		}},
	}
	orig := []byte("client-original-body")
	p, _, _ := pipeBuild(t, behaviors,
		pipeSpec("mask", PhaseBeforeUpstream, policy.BodyTransform),
		pipeSpec("swap", PhaseBeforeUpstream, policy.BodyTransform))
	res, err := p.RunRequest(context.Background(), pipeRequest(t, "rel", NewBufferedBody(orig)))
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Body) != "SWAPPED-TWO" {
		t.Errorf("最终正文 = %q", res.Body)
	}
	// 上一档正文在处理完立即释放：中间产物（mask 的输出）已被清零。
	for _, c := range produced {
		if c != 0 {
			t.Fatal("中间正文替换后没有清零（规则 2）")
		}
	}
	// 藏了原始句柄再回看：必须拒绝，而不是给一份缓存副本。
	if _, err := savedIn.Body(); !errors.Is(err, ErrBodyAccessDenied) {
		t.Errorf("链条结束后回看原始正文未被拒绝: %v", err)
	}
	// 调用方自己的原始 buffer 不被越权清零。
	if string(orig) != "client-original-body" {
		t.Error("原始正文是借用的，不得清零调用方内存")
	}
	if !pipeEntry(t, res, "swap").ReleaseOrigin {
		t.Error("替换发生时的上一档释放必须留痕")
	}
}

// ------------------------------------------------------------------ 缓冲语义与声明（规则 8）

func TestBufferedResultSemanticsAndNotice(t *testing.T) {
	readOnly := func(_ context.Context, in *Input) (*Output, error) {
		if _, err := in.Body(); err != nil {
			return nil, err
		}
		return &Output{}, nil
	}
	replace := func(context.Context, *Input) (*Output, error) {
		return &Output{Body: []byte("NEW")}, nil
	}

	// 全 metadata-only：不缓冲、无通知，调用方继续透传。
	pMeta, _, _ := pipeBuild(t, nil, pipeSpec("m", PhaseBeforeUpstream, policy.BodyMetadataOnly))
	res, err := pMeta.RunRequest(context.Background(), pipeRequest(t, "n1", NewBufferedBody([]byte("payload"))))
	if err != nil {
		t.Fatal(err)
	}
	if res.Body != nil || res.Buffered || res.BufferingNotice != "" {
		t.Fatalf("metadata-only 链不得宣告缓冲: buffered=%v notice=%q", res.Buffered, res.BufferingNotice)
	}
	if !res.Audit.Untouched || res.Audit.Buffered {
		t.Error("审计里 untouched/buffered 与结果不一致")
	}

	// inspect 读取即 buffered：Result 带原文并显式声明。
	pInsp, _, _ := pipeBuild(t, map[string]pipeBehavior{"r": {fn: readOnly}},
		pipeSpec("r", PhaseBeforeUpstream, policy.BodyInspect))
	res, err = pInsp.RunRequest(context.Background(), pipeRequest(t, "n2", NewBufferedBody([]byte("payload"))))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Buffered || string(res.Body) != "payload" {
		t.Fatalf("inspect 读取后应 buffered 并回传原正文: %v %q", res.Buffered, res.Body)
	}
	if res.BufferingNotice == "" || !strings.Contains(res.BufferingNotice, "7 字节") {
		t.Errorf("缓冲声明缺失或数字不对: %q", res.BufferingNotice)
	}

	// transform 替换：Result.Body 是替换后的正文。
	pTr, _, _ := pipeBuild(t, map[string]pipeBehavior{"t": {fn: replace}},
		pipeSpec("t", PhaseBeforeUpstream, policy.BodyTransform))
	res, err = pTr.RunRequest(context.Background(), pipeRequest(t, "n3", NewBufferedBody([]byte("payload"))))
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Body) != "NEW" || !res.Buffered {
		t.Errorf("transform 后 Result.Body = %q", res.Body)
	}
}

func TestRunResponseReplacesBufferedBody(t *testing.T) {
	replace := func(_ context.Context, in *Input) (*Output, error) {
		if in.StatusCode != 200 {
			return nil, errors.New("StatusCode 未透传")
		}
		data, err := in.Body()
		if err != nil {
			return nil, err
		}
		return &Output{Body: append([]byte("FILTERED:"), data...)}, nil
	}
	spec := pipeSpec("rf", PhaseAfterUpstream, policy.BodyTransform)
	p, _, _ := pipeBuild(t, map[string]pipeBehavior{"rf": {fn: replace}}, spec)
	resp := pipeResponse("n4", NewBufferedBody([]byte("answer")))
	resp.Policy = pipeCtx(t, "alice")
	resp.Chain = pipeChain("alice")
	resp.Now = pipeBaseNow
	res, err := p.RunResponse(context.Background(), resp)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Body) != "FILTERED:answer" || !res.Buffered {
		t.Errorf("响应侧替换失败: %q buffered=%v", res.Body, res.Buffered)
	}
	// 请求侧阶段不应在响应调用里执行。
	if res.Outcome != ReasonOK {
		t.Errorf("Outcome = %s", res.Outcome)
	}
}

// ------------------------------------------------------------------ 流式（规则 7）

func TestWrapStreamFailsBeforeReadingFirstByte(t *testing.T) {
	// after-upstream 的处理器不支持流式：失败必须发生在读第一个字节之前，
	// 调用方还没发状态码，可以干净回落到不过滤路径。
	src := &pipeSource{data: []byte("do-not-buffer-me")}
	behaviors := map[string]pipeBehavior{"plain": {fn: func(context.Context, *Input) (*Output, error) {
		return &Output{}, nil
	}}}
	for _, failClosed := range []bool{true, false} {
		spec := pipeSpec("plain", PhaseAfterUpstream, policy.BodyInspect)
		spec.FailClosed = failClosed
		p, _, _ := pipeBuild(t, behaviors, spec)
		_, err := p.WrapStream(context.Background(), pipeResponse("s1", NewBodyReader(src, int64(len(src.data)))))
		if err == nil {
			t.Fatal("不支持流式的 after-upstream 处理器必须让 WrapStream 提前失败")
		}
		if !errors.Is(err, ErrStreamUnsupported) {
			t.Errorf("错误应包 ErrStreamUnsupported: %v", err)
		}
	}
	if got := src.readBytes(); got != 0 {
		t.Fatalf("WrapStream 失败路径读了 %d 字节，必须一字节都不碰", got)
	}
}

func TestStreamPassthroughReadsNoBytesWhenNoBufferingRequired(t *testing.T) {
	// §2.9 规则 7 的行为回归点：链上全是 metadata-only 时，接进 pipeline 这个动作
	// 本身绝不能把请求/响应读进内存 —— 正文句柄背后是「一读就 panic」的流。
	behaviors := map[string]pipeBehavior{
		"meta": {fn: func(_ context.Context, in *Input) (*Output, error) {
			if in.CanReadBody() {
				return nil, errors.New("metadata-only 却报告可读")
			}
			return &Output{}, nil
		}},
	}
	specs := []Spec{
		pipeSpec("meta", PhaseBeforeUpstream, policy.BodyMetadataOnly),
	}
	p, _, _ := pipeBuild(t, behaviors, specs...)

	if p.RequiresBodyBuffering() {
		t.Fatal("全 metadata-only 的链不应要求缓冲")
	}
	if got := p.MaxBodyAccess(); got != policy.BodyMetadataOnly {
		t.Fatalf("MaxBodyAccess = %s", got)
	}
	res, err := p.RunRequest(context.Background(), pipeRequest(t, "sw1", NewBodyReader(pipePanicReader{}, 12)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Buffered || res.Body != nil {
		t.Fatal("metadata-only 请求路径不该产出缓冲")
	}

	// 响应侧：没有 after-upstream 阶段的链，WrapStream 只是取过底层读者，不消费。
	resp := pipeResponse("sw2", NewBodyReader(pipePanicReader{}, 12))
	s, err := p.WrapStream(context.Background(), resp)
	if err != nil {
		t.Fatal(err)
	}
	if s.HasProcessors() {
		t.Fatal("链上没有流式处理器")
	}
	rec := s.Audit()
	if rec.Buffered {
		t.Error("透传路径的审计不得标记 buffered")
	}
}

func TestStreamFilterNeverBuffersWholeResponse(t *testing.T) {
	payload := []byte(strings.Repeat("abcdefghijklmnopqrstuvwxyz", 2048)) // 73728 字节
	src := &pipeSource{data: payload}
	behaviors := map[string]pipeBehavior{"filt": {stream: func(_ context.Context, in *Input, r io.Reader) (io.Reader, error) {
		if !in.Stream {
			return nil, errors.New("Stream 标志未透传")
		}
		if in.body != nil {
			return nil, errors.New("流式路径上 Input 不该再持有原始正文句柄")
		}
		return &pipeUpcase{src: r}, nil
	}}}
	spec := pipeSpec("filt", PhaseAfterUpstream, policy.BodyInspect)
	p, _, _ := pipeBuild(t, behaviors, spec)
	resp := pipeResponse("st1", NewBodyReader(src, int64(len(payload))))
	s, err := p.WrapStream(context.Background(), resp)
	if err != nil {
		t.Fatal(err)
	}
	if !s.HasProcessors() {
		t.Fatal("应有流式处理器参与")
	}
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != strings.ToUpper(string(payload)) {
		t.Fatal("增量过滤结果不正确")
	}
	// 可证伪的「没缓冲整段」：高水位远小于响应总长。
	if hw := s.MaxBufferedBytes(); hw >= len(payload) {
		t.Fatalf("流式过滤器缓冲了整段响应（高水位 %d / 总长 %d）", hw, len(payload))
	}
	if s.Err() != nil {
		t.Errorf("Err 应把 EOF 记 nil: %v", s.Err())
	}
	rec := s.Audit()
	if rec.Buffered {
		t.Error("流式路径审计不得标记 buffered")
	}
	if len(rec.Entries) != 1 {
		t.Fatalf("流式审计条目数 = %d", len(rec.Entries))
	}
	e := rec.Entries[0]
	if e.InputBytes != int64(len(payload)) || e.OutputBytes != int64(len(payload)) {
		t.Errorf("流式计量 InputBytes=%d OutputBytes=%d", e.InputBytes, e.OutputBytes)
	}
	if !strings.HasPrefix(e.InputHash, "sha256:") || !strings.HasPrefix(e.OutputHash, "sha256:") {
		t.Error("流式哈希摘要缺失")
	}
	// 增量哈希与整段哈希必须一致（规则 6：哈希是允许的内容指纹）。
	if e.OutputHash != sha256Hex([]byte(strings.ToUpper(string(payload)))) {
		t.Error("增量输出哈希与整段计算不一致")
	}
}

// ------------------------------------------------------------------ 并发复用

func TestPipelineConcurrentReuse(t *testing.T) {
	// 同一实例被多条请求并发复用（DoD 4）：结果必须逐条对号入座，串一条都算跨请求泄漏。
	stamp := func(_ context.Context, in *Input) (*Output, error) {
		data, err := in.Body()
		if err != nil {
			return nil, err
		}
		out := make([]byte, 0, len(in.RequestID)+1+len(data))
		out = append(out, in.RequestID...)
		out = append(out, '|')
		out = append(out, data...)
		return &Output{Body: out}, nil
	}
	spec := pipeSpec("stamp", PhaseBeforeUpstream, policy.BodyTransform)
	p, rec, _ := pipeBuild(t, map[string]pipeBehavior{"stamp": {fn: stamp}}, spec)

	const workers, rounds = 8, 25
	var wg sync.WaitGroup
	errCh := make(chan string, workers*rounds)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				id := fmt.Sprintf("w%d-r%d", w, i)
				req := &Request{
					RequestID: id,
					Model:     "gpt-test",
					Body:      NewBufferedBody([]byte("payload-" + id)),
					Policy:    pipeCtxNoT(id),
					Chain:     pipeChain("alice"),
					Now:       pipeBaseNow,
				}
				res, err := p.RunRequest(context.Background(), req)
				if err != nil {
					errCh <- fmt.Sprintf("%s: %v", id, err)
					continue
				}
				want := id + "|payload-" + id
				if string(res.Body) != want {
					errCh <- fmt.Sprintf("结果串号: got %q want %q", res.Body, want)
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for msg := range errCh {
		t.Error(msg)
	}
	if rec.calls("stamp") != workers*rounds {
		t.Errorf("调用次数 = %d", rec.calls("stamp"))
	}
}

func pipeCtxNoT(string) policy.PolicyContext {
	id, err := policy.NewIdentity("alice", "oidc-test")
	if err != nil {
		panic(err)
	}
	ctx, err := policy.NewPolicyContext(id, "qa", policy.LevelInternal)
	if err != nil {
		panic(err)
	}
	return ctx
}

// ------------------------------------------------------------------ 审计不泄露

func TestAuditSurfaceCarriesNoBodyFields(t *testing.T) {
	// 反射口径与 internal/policy/leak_test.go、internal/identity/leak_test.go 一致：
	// 审计面结构体连字段名都不许出现正文/凭证类词。
	for _, value := range []any{
		AuditEntry{}, AuditRecord{}, Rewrite{}, NameVersion{},
	} {
		pipeAssertNoLeakFields(t, value)
	}
}

func TestSerializedAuditCarriesNoSentinelContent(t *testing.T) {
	const ssn = "canary-SSN-000-11-2222"
	const key = "sk-live-LEAKME-canary"
	sentinelBody := []byte(`{"note":"` + ssn + `","key":"` + key + `"}`)

	readAndBlock := func(_ context.Context, in *Input) (*Output, error) {
		data, err := in.Body()
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(data), ssn) {
			// 处理器「看过」了内容（这是 inspect 档的本职），但结论只能是原因码。
			return nil, Errorf(ErrContentBlocked, "命中拦截")
		}
		return &Output{}, nil
	}
	upcaseAll := func(_ context.Context, in *Input) (*Output, error) {
		data, err := in.Body()
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(data))
		for i := range data {
			out[i] = data[i]
			if out[i] >= 'a' && out[i] <= 'z' {
				out[i] -= 32
			}
		}
		return &Output{Body: out}, nil
	}

	cases := []struct {
		name string
		spec Spec
	}{
		{"inspect-拒绝", pipeSpec("watch", PhaseBeforeUpstream, policy.BodyInspect)},
		{"transform-放行", pipeSpec("up", PhaseBeforeUpstream, policy.BodyTransform)},
	}
	for i, tc := range cases {
		fn := readAndBlock
		if i == 1 {
			fn = upcaseAll
		}
		p, _, _ := pipeBuild(t, map[string]pipeBehavior{tc.spec.Name: {fn: fn}}, tc.spec)
		res, _ := p.RunRequest(context.Background(), pipeRequest(t, "leak-1", NewBufferedBody(sentinelBody)))
		blob := auditJSON(res.Audit)
		for _, secret := range []string{ssn, key, "canary-SSN"} {
			if strings.Contains(blob, secret) {
				t.Fatalf("%s: 审计序列化含原文 %q", tc.name, secret)
			}
		}
		// 内容只能以「量 + 摘要」的形态存在（规则 6）。
		entry := res.Entries[0]
		if !strings.HasPrefix(entry.InputHash, "sha256:") {
			t.Errorf("%s: InputHash 形态不对: %q", tc.name, entry.InputHash)
		}
		if entry.InputBytes != int64(len(sentinelBody)) {
			t.Errorf("%s: InputBytes = %d", tc.name, entry.InputBytes)
		}
	}
}

// pipeFrozenClock 固定时间源：审计里的 Elapsed 参与序列化，不钉住就没法逐字节比对。
func pipeFrozenClock() func() time.Time {
	return func() time.Time { return pipeBaseNow }
}

func TestReasonChainsAreDeterministic(t *testing.T) {
	// 同一输入两次跑：原因链、改写合并、审计 JSON 必须逐字节相同（回放前提）。
	crash := func(context.Context, *Input) (*Output, error) {
		return &Output{}, Errorf(ErrProcessFailed, "依赖故障")
	}
	mk := func() (string, []Rewrite) {
		specA := pipeSpec("a", PhaseBeforeUpstream, policy.BodyTransform)
		specB := pipeSpec("b", PhaseBeforeUpstream, policy.BodyTransform)
		specB.FailClosed = false
		rec := pipeNewRecorder()
		reg := NewRegistry()
		if err := reg.RegisterType(pipeTypeFake, pipeFactory(rec, map[string]pipeBehavior{
			"a": {fn: func(context.Context, *Input) (*Output, error) {
				return &Output{Body: []byte("X"), Rewrites: []Rewrite{{Kind: "pii:phone", Count: 2}, {Kind: "filter:a", Count: 1}}}, nil
			}},
			"b": {fn: crash},
		})); err != nil {
			t.Fatal(err)
		}
		for _, s := range []Spec{specA, specB} {
			if err := reg.Register(s, nil); err != nil {
				t.Fatal(err)
			}
		}
		p, err := reg.Build([]Spec{specA, specB}, &BuildOptions{Clock: pipeFrozenClock(), PolicyVersion: "det@1"})
		if err != nil {
			t.Fatal(err)
		}
		res, err := p.RunRequest(context.Background(), pipeRequest(t, "det", NewBufferedBody([]byte("src"))))
		if err != nil {
			t.Fatal(err)
		}
		return auditJSON(res.Audit), res.Rewrites
	}
	first, firstRew := mk()
	for i := 0; i < 3; i++ {
		got, gotRew := mk()
		if got != first {
			t.Fatalf("第 %d 次审计与首次不一致:\n%s\n%s", i, first, got)
		}
		if fmt.Sprint(gotRew) != fmt.Sprint(firstRew) {
			t.Fatalf("第 %d 次改写合并与首次不一致: %v vs %v", i, gotRew, firstRew)
		}
	}
	// 合并后的改写按 Kind 排序、同名计数合并（回放前提）。
	want := []Rewrite{{Kind: "filter:a", Count: 1}, {Kind: "pii:phone", Count: 2}}
	if fmt.Sprint(firstRew) != fmt.Sprint(want) {
		t.Fatalf("改写合并结果 = %v，期望 %v", firstRew, want)
	}
}
