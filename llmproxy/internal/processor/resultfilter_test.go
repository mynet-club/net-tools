package processor

// 补测试（内置结果过滤器 result-filter）：本文件覆盖的不变量 ——
// ① redact 命中即替换、未命中内容**逐字节**不动（响应缓存与内容摘要吃这份字节，
// 且它按文本处理，所以数字字面量与 HTML 符号也不会被 JSON 重序列化悄悄改写）；
// ② 配置非法在**构造期**就被拒（非法正则、空/超长关键词、脏规则名、规则数与行缓冲越界），
// 档位与阶段不一致在注册期被拒；
// ③ 输入超限、输出超限、ctx 取消、单行超限四类失败各有稳定原因码，违规类无视 fail_open；
// ④ 流式是**增量**的（WrapStream 建立时一个字节都不读、高水位远小于响应总长、
// 半条 data 行跨任意块边界仍能复原、`[DONE]` 收尾不被破坏），block 模式在流式上显式拒绝
// 而不是静默降级成 redact；⑤ 审计面（Result / Audit / 改写元数据）不得出现被剥离掉的正文内容。
// 助手统一 rf 前缀；流水线侧复用 pipeline_test.go 的 pipe* 与 auditJSON。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// rfPhone / rfCard 是 fixture 里被过滤的两段内容（明显虚构，不是真实号码或卡号）。
const (
	rfPhone = "13800138000"
	rfCard  = "4111111111111111"
)

// rfSpecAt 是一条真实的结果过滤声明（阶段可调，用于测注册期的阶段门）。
func rfSpecAt(name string, phase Phase, access policy.BodyAccess) Spec {
	spec := pipeSpec(name, phase, access)
	spec.Type = TypeResultFilter
	return spec
}

// rfSpec 是合规形态的结果过滤声明：结果过滤只能跑在 after-upstream（spec.validateType 强制）。
func rfSpec(name string, access policy.BodyAccess) Spec {
	return rfSpecAt(name, PhaseAfterUpstream, access)
}

// rfRule 造一条规则：pattern 与 keywords 至少给一个（另一个留空）。
func rfRule(name, pattern string, keywords ...string) FilterRule {
	return FilterRule{Name: name, Pattern: pattern, Keywords: keywords}
}

func rfCfg(rules ...FilterRule) *Config { return &Config{FilterRules: rules} }

// rfBuild 用真注册表装配一条链（注册期就跑一次构造，配置非法在这里直接 t.Fatal）。
func rfBuild(t *testing.T, spec Spec, cfg *Config) *Pipeline {
	t.Helper()
	reg := NewRegistry()
	if err := reg.Register(spec, cfg); err != nil {
		t.Fatalf("注册 %s 失败: %v", spec.Name, err)
	}
	p, err := reg.Build([]Spec{spec}, &BuildOptions{PolicyVersion: "test-bundle@1", Clock: pipeFrozenClock()})
	if err != nil {
		t.Fatalf("装配失败: %v", err)
	}
	return p
}

// rfProcess 直接跑缓冲路径（不经流水线）：Output 里有没有回 Body、计数怎么归集，
// 只能在处理器自己的产出上取证。
func rfProcess(t *testing.T, spec Spec, cfg *Config, ctx context.Context, body string) (*Output, error) {
	t.Helper()
	proc, err := newResultFilter(spec, cfg)
	if err != nil {
		t.Fatalf("构造结果过滤器失败: %v", err)
	}
	in := &Input{RequestID: spec.Name, Phase: spec.Phase, Model: "gpt-test", Spec: spec,
		StatusCode: 200, ContentType: "application/json", access: spec.BodyAccess,
		body: NewBufferedBody([]byte(body))}
	return proc.Process(ctx, in)
}

func rfRun(t *testing.T, spec Spec, cfg *Config, body string) (*Output, error) {
	t.Helper()
	return rfProcess(t, spec, cfg, context.Background(), body)
}

// rfMustRejectConfig 断言配置在构造期就被拒（错误绝不活到第一条真实请求）。
func rfMustRejectConfig(t *testing.T, spec Spec, cfg *Config, want error) {
	t.Helper()
	_, err := newResultFilter(spec, cfg)
	if err == nil {
		t.Fatalf("这份配置本该构造期被拒: %+v", cfg)
	}
	if want != nil && !errors.Is(err, want) {
		t.Errorf("构造期错误哨兵不符，期望 %v，实得 %v", want, err)
	}
}

// rfStreamDirect 绕开流水线直接拿增量读者：分块边界、错误时序、缓冲高水位只能在作者身上取证。
// in.body 留空与 WrapStream 的流式路径一致（流式唯一的正文入口是那个包进来的读者）。
func rfStreamDirect(t *testing.T, spec Spec, cfg *Config, ctx context.Context, src io.Reader) (io.Reader, error) {
	t.Helper()
	proc, err := newResultFilter(spec, cfg)
	if err != nil {
		t.Fatalf("构造结果过滤器失败: %v", err)
	}
	in := &Input{RequestID: spec.Name, Phase: spec.Phase, Model: "gpt-test", Stream: true,
		Spec: spec, StatusCode: 200, ContentType: "text/event-stream", access: spec.BodyAccess}
	return proc.(StreamProcessor).ProcessStream(ctx, in, src)
}

// rfCountOf 按规则名取回写计数（类别形如 filter:tel）。
func rfCountOf(list []Rewrite, name string) (int, bool) {
	for _, r := range list {
		if r.Kind == "filter:"+name {
			return r.Count, true
		}
	}
	return 0, false
}

func rfCount(out *Output, name string) (int, bool) {
	if out == nil {
		return 0, false
	}
	return rfCountOf(out.Rewrites, name)
}

// rfChunkSource 每次最多交出 size 个字节：跨块边界的半条 data 行是**可控输入**而不是巧合。
type rfChunkSource struct {
	data  []byte
	size  int
	pos   int
	bytes atomic.Int64
}

func (s *rfChunkSource) Read(p []byte) (int, error) {
	if s.pos >= len(s.data) {
		return 0, io.EOF
	}
	n := s.size
	if n > len(p) {
		n = len(p)
	}
	if s.pos+n > len(s.data) {
		n = len(s.data) - s.pos
	}
	copy(p, s.data[s.pos:s.pos+n])
	s.pos += n
	s.bytes.Add(int64(n))
	return n, nil
}

func (s *rfChunkSource) readBytes() int64 { return s.bytes.Load() }

// rfErrWithData 一次调用里同时交出「数据 + 错误」—— Go 明确允许这种读者，
// 过滤器必须说清它怎么处理这种形态（上游真断流时就是这种形态）。
type rfErrWithData struct {
	head []byte
	err  error
	sent bool
}

func (r *rfErrWithData) Read(p []byte) (int, error) {
	if r.sent {
		return 0, r.err
	}
	r.sent = true
	return copy(p, r.head), r.err
}

// rfFrame 是一条 SSE data 帧。
func rfFrame(text string) string {
	return `data: {"choices":[{"delta":{"content":"` + text + `"}}]}` + "\n\n"
}

// rfExpected 按规则顺序（tel 先、acct 后）手工算出期望产物：
// 测试自己独立实现一遍口径，实现的口径漂移才会被看见（否则等于拿实现的输出断言实现）。
func rfExpected(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, rfPhone, "[TEL]"), rfCard, "[filtered]")
}

// rfSSE 造 n 帧的响应流，以 [DONE] 收尾；want 是「两处内容都被替换」的期望产物。
func rfSSE(n int) (payload, want string) {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(rfFrame(fmt.Sprintf("第%d帧 来电 %s 刷卡 %s 结束", i, rfPhone, rfCard)))
	}
	b.WriteString("data: [DONE]\n\n")
	payload = b.String()
	return payload, rfExpected(payload)
}

// rfRules 是贯穿本文件的两条规则：一条正则（手机号 → [TEL]）、一条关键词（卡号 → [filtered]）。
func rfRules() []FilterRule {
	return []FilterRule{
		{Name: "tel", Pattern: `1[3-9]\d{9}`, Replacement: "[TEL]"},
		{Name: "acct", Keywords: []string{rfCard}},
	}
}

// rfResponse 是响应侧调用的输入（pipeResponse 只填基础字段，策略上下文按链条要求补齐）。
func rfResponse(t *testing.T, id string, body *Body) *Response {
	t.Helper()
	resp := pipeResponse(id, body)
	resp.Policy = pipeCtx(t, "alice")
	resp.Chain = pipeChain("alice")
	resp.Now = pipeBaseNow
	return resp
}

// rfResponseNoT 是 goroutine 里用的同形态输入（子线程不能用 t.Fatalf，所以走 panic 版助手）。
func rfResponseNoT(id string, body *Body) *Response {
	resp := pipeResponse(id, body)
	resp.Policy = pipeCtxNoT("alice")
	resp.Chain = pipeChain("alice")
	resp.Now = pipeBaseNow
	return resp
}

func rfMarshalResult(res *Result) ([]byte, error) { return json.Marshal(res) }

// ------------------------------------------------------------------ 正常路径

func TestRfRedactsHitsAndLeavesEverythingElseUntouched(t *testing.T) {
	body := `{"answer":"拨打 ` + rfPhone + ` 或 12800138000 两个号，卡号 ` + rfCard + ` 与无关文本 OK","cost":1e5,"html":"a<b>&c"}`
	out, err := rfRun(t, rfSpec("rf-redact", policy.BodyTransform), rfCfg(rfRules()...), body)
	if err != nil {
		t.Fatal(err)
	}
	// 未命中的部分必须逐字节不动：多吃掉一个空格都会让下游按偏移解析的客户端坏掉；
	// 而 1e5 被写成 100000、< 被转义成 < 这类「重排」会让人以为正文没变，
	// 实际已经换了一套字节 —— 响应缓存、内容摘要、Etag 全都对不上。
	want := `{"answer":"拨打 [TEL] 或 12800138000 两个号，卡号 [filtered] 与无关文本 OK","cost":1e5,"html":"a<b>&c"}`
	if got := string(out.Body); got != want {
		t.Errorf("过滤产物不符:\n got=%s\nwant=%s", got, want)
	}
	if out.Reason != ReasonOK {
		t.Errorf("Reason = %s", out.Reason)
	}
	// 计数按规则名归集并排序（回放与告警聚合都按类别读）。
	if tel, ok := rfCount(out, "tel"); !ok || tel != 1 {
		t.Errorf("filter:tel 计数 = %d(%v)", tel, ok)
	}
	if acct, ok := rfCount(out, "acct"); !ok || acct != 1 {
		t.Errorf("filter:acct 计数 = %d(%v)", acct, ok)
	}
	if got := fmt.Sprint(out.Rewrites); got != "[{filter:acct 1} {filter:tel 1}]" {
		t.Errorf("改写元数据排序不符: %s", got)
	}

	// 无命中 = 静默：不回 Body（正文原样继续走）、不留计数。
	// 「没有命中」与「处理器没跑」在审计里必须能分清，但两者都不是错误。
	quiet, qerr := rfRun(t, rfSpec("rf-quiet", policy.BodyTransform), rfCfg(rfRules()...), `{"answer":"无关内容"}`)
	if qerr != nil || len(quiet.Body) != 0 || len(quiet.Rewrites) != 0 {
		t.Errorf("无命中不该有产出或计数: %v %+v", qerr, quiet)
	}
	// 缺字段、空对象、空正文都是「没东西可过滤」，不是错误：
	// 上游返回 {} 时把请求打成失败，等于让增强处理决定可用性。
	for _, empty := range []string{"", "{}", `{"choices":[]}`} {
		eo, eerr := rfRun(t, rfSpec("rf-empty", policy.BodyTransform), rfCfg(rfRules()...), empty)
		if eerr != nil || len(eo.Body) != 0 || len(eo.Rewrites) != 0 {
			t.Errorf("空对象/空正文 %q 被当成错误或产生了改写: %v %+v", empty, eerr, eo)
		}
	}

	// 「$」在两种规则里语义不同：正则规则的替换文本按捕获组展开（和 field-replace 一致），
	// 关键词规则是字面量。写策略的人很容易以为两处都能写字面量，
	// 于是「$0」「$1」这类文本被静默解释成引用，占位符变成空串 —— 命中等于被抹掉，
	// 审计里数字还在，正文内容却已经消失。这里把差异钉住而不是让它静默生效。
	tmpl, terr := rfRun(t, rfSpec("rf-tmpl", policy.BodyTransform),
		rfCfg(FilterRule{Name: "u", Pattern: `用户(\d+)号`, Replacement: "账号$1"},
			FilterRule{Name: "lit", Keywords: []string{"孤立X"}, Replacement: "$1"}),
		`{"v":"请看 用户42号 与 用户7号，另有 孤立X 一处"}`)
	if terr != nil {
		t.Fatal(terr)
	}
	if got := string(tmpl.Body); got != `{"v":"请看 账号42 与 账号7，另有 $1 一处"}` {
		t.Errorf("两种规则的替换语义不符: %s", got)
	}
	if c, _ := rfCount(tmpl, "u"); c != 2 {
		t.Errorf("filter:u 计数 = %d，期望 2（同一条规则命中两处）", c)
	}
	if c, _ := rfCount(tmpl, "lit"); c != 1 {
		t.Errorf("filter:lit 计数 = %d，期望 1", c)
	}

	// 结果过滤器**不解析 JSON**（流式分块根本拼不出合法文档，解析就得先在内存凑整段，
	// 违反 §2.9 规则 7）：所以畸形 JSON 不是错误路径，而是被当普通文本逐字节过滤。
	broken, berr := rfRun(t, rfSpec("rf-broken", policy.BodyTransform), rfCfg(rfRules()...),
		`{"answer":"`+rfPhone+` ← 这段 JSON 少了右括号`)
	if berr != nil {
		t.Fatalf("非法 JSON 不该让结果过滤报错（它按文本处理）: %v", berr)
	}
	if string(broken.Body) != `{"answer":"[TEL] ← 这段 JSON 少了右括号` {
		t.Errorf("畸形 JSON 的文本过滤形态不符: %s", broken.Body)
	}
	// 键名一个字节都没动（它不做 JSON 规范化，也就不会重排键序）。
	if n := strings.Count(string(broken.Body), `"answer"`); n != 1 {
		t.Errorf("键名被改动（出现 %d 次）: %s", n, broken.Body)
	}
}

func TestRfFilterReplacementIsConfiguredButNeverApplied(t *testing.T) {
	// 钉一个**生产缺口**（不当场改）：Config.FilterReplacement 被读进结构体、还参与构造期长度校验，
	// 但 maskBytes 用的是每条规则自己的 repl（缺省硬编码 "[filtered]"），
	// 于是「全局替换文本」配了完全不生效 —— 而它超长时却能把整条注册挡下来。
	// 这是「配了没用、还能报错」的最坏组合：策略作者会以为占位符已经统一换过，
	// 而下游按占位符做的内容核对与告警聚类全部对不上，日志里却一条错误都没有。
	//
	// 不当场修的理由有两种且都必须主线定夺：① 让规则级缺省回落到实例级 replacement，
	// 会静默改变所有现网规则的输出文本（占位符是下游解析与审计对账的依据，属 §7 破坏性变更）；
	// ② 删掉这个配置字段是接口破坏性变更，要升版本并写迁移说明。
	cfg := &Config{FilterRules: []FilterRule{rfRule("acct", "", rfCard)}, FilterReplacement: "[统一占位]"}
	out, err := rfRun(t, rfSpec("rf-repl", policy.BodyTransform), cfg, `{"v":"刷卡 `+rfCard+`"}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out.Body); got != `{"v":"刷卡 [filtered]"}` {
		t.Errorf("规则级缺省占位符形态不符（若此断言变红，说明缺口已被修复，请同步重写本用例说明）: %s", got)
	}
	// 反向取证：一个根本不进正文的字段，却能因为长度超标把整条注册拒掉。
	tooLong := &Config{FilterRules: []FilterRule{rfRule("acct", "", rfCard)},
		FilterReplacement: strings.Repeat("长", MaxKeywordLen)}
	if _, err := newResultFilter(rfSpec("rf-repl-bad", policy.BodyTransform), tooLong); !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("超长（但不会被用到）的替换文本理应仍被长度校验拒掉，实得 %v", err)
	}
}

// ------------------------------------------------------------------ 动作与档位

func TestRfBlockModeIsVerdictOnBufferedPathOnly(t *testing.T) {
	hit := `{"answer":"刷卡 ` + rfCard + `"}`
	miss := `{"answer":"无关内容"}`
	cfg := &Config{FilterRules: rfRules(), FilterMode: FilterBlock}

	// 命中即整段拒收，且这是**判定成立**（classVerdict）：fail_open 不许把它降级成「跳过」。
	out, err := rfRun(t, rfSpec("rf-block", policy.BodyTransform), cfg, hit)
	if !errors.Is(err, ErrContentBlocked) {
		t.Fatalf("block 模式命中必须拒收: %v", err)
	}
	if out != nil {
		t.Errorf("拒收不得带产出: %+v", out)
	}
	if reason, class := classify(err); reason != ReasonContentBlocked || class != classVerdict {
		t.Errorf("归类应为 (content_blocked, verdict)，实得 (%s, %s)", reason, class)
	}

	// 未命中：正常放行且**不产出计数**（block 只回答放/拦，不做替换）。
	okOut, okErr := rfRun(t, rfSpec("rf-block-miss", policy.BodyTransform), cfg, miss)
	if okErr != nil || len(okOut.Body) != 0 || len(okOut.Rewrites) != 0 {
		t.Errorf("block 未命中应干净放行: %v %+v", okErr, okOut)
	}

	// inspect-body 档也能用 block：判定不需要写权限。
	// 这条很重要 —— 否则「只想拦不想改」的策略会被迫申请 transform-body（多拿一份正文写权）。
	if _, err := rfRun(t, rfSpec("rf-block-inspect", policy.BodyInspect), cfg, hit); !errors.Is(err, ErrContentBlocked) {
		t.Errorf("inspect 档的 block 判定同样要生效: %v", err)
	}

	// 流式上 block 无法成立（已发出的字节收不回来），必须**显式拒绝**而不是静默降级成 redact：
	// 静默降级会让策略作者以为拦住了，而内容已经一段一段发给客户端。
	rd, serr := rfStreamDirect(t, rfSpec("rf-block-stream", policy.BodyTransform), cfg,
		context.Background(), strings.NewReader(rfFrame("刷卡 "+rfCard)))
	if !errors.Is(serr, ErrStreamUnsupported) || rd != nil {
		t.Fatalf("block 模式的流式路径必须被拒: %v (%v)", serr, rd)
	}
	if reason, class := classify(serr); reason != ReasonStreamUnsupported || class != classViolation {
		t.Errorf("归类应为 (stream_unsupported, violation)，实得 (%s, %s)", reason, class)
	}

	// 链条取证（fail_open 关掉也一样拒）：违规类无视 FailClosed。
	spec := rfSpec("rf-block-chain", policy.BodyTransform)
	spec.FailClosed = false
	p := rfBuild(t, spec, cfg)
	res, rerr := p.RunResponse(context.Background(), rfResponse(t, "rf-block-chain", NewBufferedBody([]byte(hit))))
	if rerr == nil || res.Outcome != ReasonContentBlocked {
		t.Fatalf("fail_open 不得冲掉命中拦截: %v / %s", rerr, res.Outcome)
	}
	if pipeEntry(t, res, "rf-block-chain").Outcome != ReasonContentBlocked {
		t.Errorf("审计条目结论码不对: %+v", pipeEntry(t, res, "rf-block-chain"))
	}

	// 同一份链在流式上必须在**读第一个字节之前**就失败：调用方此时还没发状态码，可以干净回落。
	// 如果先读走若干字节再报错，客户端已经收到半截正文，网关再也无法改判。
	src := &rfChunkSource{data: []byte(rfFrame("刷卡 " + rfCard)), size: 4096}
	_, werr := p.WrapStream(context.Background(), rfResponse(t, "rf-block-stream", NewBodyReader(src, int64(len(src.data)))))
	if !errors.Is(werr, ErrStreamUnsupported) {
		t.Fatalf("流式包装必须拒: %v", werr)
	}
	if got := src.readBytes(); got != 0 {
		t.Errorf("WrapStream 失败路径读走了 %d 字节，必须一字节都不碰", got)
	}
}

func TestRfInspectBodyCountsButNeverReplaces(t *testing.T) {
	body := `{"answer":"来电 ` + rfPhone + ` 刷卡 ` + rfCard + `"}`
	cfg := rfCfg(rfRules()...)

	// inspect-body：只统计不替换。产出交给流水线会被判越权，所以处理器自己就不回 Body。
	out, err := rfRun(t, rfSpec("rf-insp", policy.BodyInspect), cfg, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Body) != 0 {
		t.Errorf("inspect 档不得产出替换正文: %s", out.Body)
	}
	if tel, ok := rfCount(out, "tel"); !ok || tel != 1 {
		t.Errorf("inspect 档照常计数：filter:tel = %d(%v)", tel, ok)
	}

	// 链条对照：正文原样（未被替换）返回，但这次调用确实进了缓冲形态。
	p := rfBuild(t, rfSpec("rf-insp-chain", policy.BodyInspect), cfg)
	res, rerr := p.RunResponse(context.Background(), rfResponse(t, "rf-insp-chain", NewBufferedBody([]byte(body))))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(res.Body) != body || !res.Buffered {
		t.Errorf("inspect 档链条正文被改动了: %s (buffered=%v)", res.Body, res.Buffered)
	}
	if len(res.Rewrites) != 2 {
		t.Errorf("链条合并后的计数 = %+v，期望两类各一处", res.Rewrites)
	}
	// 读正文本身合规，所以 DeniedReads 必须是 0（inspect 的越权风险在「写」，不在「读」）。
	if entry := pipeEntry(t, res, "rf-insp-chain"); entry.DeniedReads != 0 || !entry.Buffered || entry.ReleaseOrigin {
		t.Errorf("inspect 档审计形态不符: %+v", entry)
	}

	// transform 档才替换，并且替换完就把原文释放掉（§2.9 规则 2）：
	// 原文留在内存里等于「脱敏只是显示层的事」，进程被 dump 时命中的的内容照旧外泄。
	tp := rfBuild(t, rfSpec("rf-tr-chain", policy.BodyTransform), cfg)
	tres, terr := tp.RunResponse(context.Background(), rfResponse(t, "rf-tr-chain", NewBufferedBody([]byte(body))))
	if terr != nil {
		t.Fatal(terr)
	}
	if strings.Contains(string(tres.Body), rfPhone) || !strings.Contains(string(tres.Body), "[TEL]") {
		t.Errorf("transform 档过滤没生效: %s", tres.Body)
	}
	if !pipeEntry(t, tres, "rf-tr-chain").ReleaseOrigin {
		t.Error("替换后的原始正文释放必须留痕")
	}
}

// ------------------------------------------------------------------ 构造期与注册期拒绝

func TestRfRejectsInvalidConfigAtConstructionTime(t *testing.T) {
	spec := rfSpec("rf-bad", policy.BodyTransform)

	// 一条规则都没有：过滤器等于「什么都不做但声称在做」，装配期不拦就会变成策略空气 ——
	// 而审计里它是一条成功记录，没人看得出这段响应其实没被过滤过。
	rfMustRejectConfig(t, spec, nil, ErrConfigInvalid)
	rfMustRejectConfig(t, spec, &Config{}, ErrConfigInvalid)
	rfMustRejectConfig(t, spec, &Config{FilterRules: nil}, ErrConfigInvalid)

	// 规则本体不合法的每一条都必须在构造期炸：错配置绝不允许活到第一条真实请求。
	rfMustRejectConfig(t, spec, rfCfg(rfRule("rx", `(`)), ErrConfigInvalid) // 非法正则
	// 模式/关键词/替换文本各自的长度上限：超限文本会打爆审计与日志行，也助长 DoS。
	rfMustRejectConfig(t, spec, rfCfg(rfRule("rx", strings.Repeat("k", MaxPatternLen+1))), ErrConfigInvalid)
	rfMustRejectConfig(t, spec, rfCfg(rfRule("kw", "", "")), ErrConfigInvalid) // 空关键词命中所有位置
	rfMustRejectConfig(t, spec, rfCfg(rfRule("kw", "", strings.Repeat("长", MaxKeywordLen+1))), ErrConfigInvalid)
	rfMustRejectConfig(t, spec, rfCfg(FilterRule{Name: "ghost"}), ErrConfigInvalid) // 既无 pattern 也无 keywords
	// 规则名要进审计（filter:<name> 直接拼成 JSON 字段值），必须是安全标识符：
	// 允许中文/空格/引号就等于让规则名注入审计行，按字段切分的日志管道会错位。
	rfMustRejectConfig(t, spec, rfCfg(rfRule("含中文", "", rfCard)), ErrConfigInvalid)
	rfMustRejectConfig(t, spec, rfCfg(rfRule("has space", "", rfCard)), ErrConfigInvalid)
	rfMustRejectConfig(t, spec, rfCfg(FilterRule{Name: strings.Repeat("n", MaxNameLen+1), Pattern: `x`}), ErrConfigInvalid)

	// 「规则名/替换文本留空」是有兜底的（rule / [filtered]），不能被当成配置错误 ——
	// 否则一份合法配置会因为风格问题被拒，运维就会绕过校验器直接改策略。
	for _, lenient := range []FilterRule{
		{Pattern: `x`},
		{Keywords: []string{rfCard}},
		{Name: "ok", Pattern: `x`, Replacement: ""},
	} {
		if _, err := newResultFilter(spec, rfCfg(lenient)); err != nil {
			t.Errorf("留空字段应有兜底默认值，实得 %v（规则 %+v）", err, lenient)
		}
	}

	// 规模上限：规则条数有绝对天花板，超限是 limit_exceeded（违规类）。
	many := make([]FilterRule, 0, MaxFilterRules+1)
	for i := 0; i <= MaxFilterRules; i++ {
		many = append(many, rfRule(fmt.Sprintf("r%02d", i), "", "x"))
	}
	rfMustRejectConfig(t, spec, rfCfg(many...), ErrTooManyRules)
	if _, err := newResultFilter(spec, rfCfg(many[:MaxFilterRules]...)); err != nil {
		t.Errorf("恰好 %d 条必须在限额内: %v", MaxFilterRules, err)
	}
	words := make([]string, 0, MaxKeywordCount+1)
	for i := 0; i <= MaxKeywordCount; i++ {
		words = append(words, fmt.Sprintf("w%d", i))
	}
	rfMustRejectConfig(t, spec, rfCfg(rfRule("many-words", "", words...)), ErrConfigInvalid)

	// 行缓冲上限：流式按行处理，单行上限必须有绝对天花板；
	// 0/负数落到默认值，绝不允许被解释成「不限」（一个「不限」就是无上限内存驻留）。
	rfMustRejectConfig(t, spec, &Config{FilterRules: rfRules(), MaxLineBytes: AbsoluteMaxLineBytes + 1}, ErrConfigInvalid)
	for _, zero := range []int{0, -1} {
		if _, err := newResultFilter(spec, &Config{FilterRules: rfRules(), MaxLineBytes: zero}); err != nil {
			t.Errorf("max_line_bytes=%d 应落到默认值而不是报错: %v", zero, err)
		}
	}

	// 注册期的两道门：档位与阶段。写错的声明在这里拒，而不是请求期静默不生效。
	if err := NewRegistry().Register(rfSpec("rf-meta", policy.BodyMetadataOnly), rfCfg(rfRules()...)); !errors.Is(err, ErrBodyAccessNotForType) {
		t.Errorf("metadata-only 的结果过滤必须注册失败（它看不到响应内容）: %v", err)
	}
	if err := NewRegistry().Register(rfSpecAt("rf-req", PhaseBeforeUpstream, policy.BodyTransform), rfCfg(rfRules()...)); !errors.Is(err, ErrPhaseNotForType) {
		// 结果过滤的是**上游响应**，跑在请求侧等于没东西可过滤，但审计会写「已过滤」。
		t.Errorf("请求侧阶段的 result-filter 必须注册失败: %v", err)
	}
	// 合规声明（after-upstream + inspect）必须能注册，否则上面几条拒得太宽。
	if err := NewRegistry().Register(rfSpec("rf-ok", policy.BodyInspect), rfCfg(rfRules()...)); err != nil {
		t.Errorf("合规声明注册失败: %v", err)
	}
}

// ------------------------------------------------------------------ 超限与超时

func TestRfEnforcesInputOutputLimitsAndContext(t *testing.T) {
	t.Run("输入超限", func(t *testing.T) {
		// 超大正文必须在**处理器自己这一层**就被拒（读正文的硬上限），
		// 而不是「读进来再截断」：截断后的正文看起来像一份合法响应。
		spec := rfSpec("rf-in", policy.BodyTransform)
		spec.MaxInputBytes = 32
		cfg := rfCfg(rfRule("tel", `1[3-9]\d{9}`))
		if _, err := rfRun(t, spec, cfg, strings.Repeat("x", 64)); !errors.Is(err, ErrInputTooLarge) {
			t.Fatalf("超过 max_input_bytes 必须拒绝: %v", err)
		}
		// 超限是违规类：fail_open 不许把它跳过去（跳过 = 把没过滤的响应放给客户端）。
		chainSpec := spec
		chainSpec.FailClosed = false
		p := rfBuild(t, chainSpec, cfg)
		res, rerr := p.RunResponse(context.Background(), rfResponse(t, "rf-in", NewBufferedBody([]byte(strings.Repeat("x", 64)))))
		if rerr == nil || res.Outcome != ReasonInputTooLarge {
			t.Errorf("fail_open 不得跳过输入超限: %v / %s", rerr, res.Outcome)
		}
	})

	t.Run("输出超限", func(t *testing.T) {
		// 占位符比命中片段长是常态：过滤后正文可能变大，必须在处理器自己这一层就拒，
		// 不能等流水线 checkReplacement（那时一份越界产出已经离开了处理器的职责边界）。
		spec := rfSpec("rf-out", policy.BodyTransform)
		spec.MaxInputBytes = 64
		spec.MaxOutputBytes = 16
		cfg := rfCfg(FilterRule{Name: "tel", Pattern: `1[3-9]\d{9}`, Replacement: "[REDACTED-PHONE]"})
		_, err := rfRun(t, spec, cfg, rfPhone+" "+rfPhone)
		if !errors.Is(err, ErrOutputTooLarge) {
			t.Fatalf("过滤后 %d 字节应超过 max_output_bytes=16: %v", len("[REDACTED-PHONE] [REDACTED-PHONE]"), err)
		}
		if reason, class := classify(err); reason != ReasonOutputTooLarge || class != classViolation {
			t.Errorf("归类应为 (output_too_large, violation)，实得 (%s, %s)", reason, class)
		}
	})

	t.Run("ctx 已取消", func(t *testing.T) {
		// 取消/超时是**基础设施类**（唯一可被 fail_open 跳过的一类）：
		// 增强处理挂了不该让请求整体失败，但它必须先于任何正文读取被检查。
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := rfProcess(t, rfSpec("rf-ctx", policy.BodyTransform), rfCfg(rfRules()...), ctx, "无关"); !errors.Is(err, ErrTimeout) {
			t.Errorf("缓冲路径必须先查 ctx: %v", err)
		}
		_, err := rfStreamDirect(t, rfSpec("rf-ctx", policy.BodyTransform), rfCfg(rfRules()...), ctx, strings.NewReader("x"))
		if !errors.Is(err, ErrTimeout) {
			t.Errorf("流式包装也必须先查 ctx（已取消还建立过滤器 = 白占一条流）: %v", err)
		}
		if reason, class := classify(err); reason != ReasonTimeout || class != classInfrastructure {
			t.Errorf("超时应为 (processor_timeout, infrastructure)，实得 (%s, %s)", reason, class)
		}
	})

	t.Run("档位不许读正文时流式也拒", func(t *testing.T) {
		// 注册期已经拦过一次；这里是运行期的第二道闸（手搭 Input 绕过 Validate 时也读不到正文）。
		spec := rfSpec("rf-nobody", policy.BodyMetadataOnly)
		_, err := rfStreamDirect(t, spec, rfCfg(rfRules()...), context.Background(), strings.NewReader("x"))
		if !errors.Is(err, ErrBodyAccessDenied) {
			t.Fatalf("metadata-only 档不能过滤响应流: %v", err)
		}
		if reason, class := classify(err); reason != ReasonBodyAccessDenied || class != classViolation {
			t.Errorf("归类应为 (body_access_denied, violation)，实得 (%s, %s)", reason, class)
		}
	})
}

// ------------------------------------------------------------------ 流式

func TestRfStreamFiltersEachFrameAndNeverBuffersWholeResponse(t *testing.T) {
	payload, want := rfSSE(400) // 约 41KB 的响应流
	spec := rfSpec("rf-stream", policy.BodyTransform)
	cfg := rfCfg(rfRules()...)
	src := &rfChunkSource{data: []byte(payload), size: 4096}

	p := rfBuild(t, spec, cfg)
	s, err := p.WrapStream(context.Background(), rfResponse(t, "rf-stream", NewBodyReader(src, int64(len(payload)))))
	if err != nil {
		t.Fatal(err)
	}
	// 建立包装时一个字节都不读：§2.9 规则 7 要求「接了 pipeline 不等于把响应缓存进内存」，
	// 而 forwarder 的流式透传（边收边写 + 空闲看门狗）正是靠这一点才成立。
	if got := src.readBytes(); got != 0 {
		t.Fatalf("WrapStream 建立阶段就读走了 %d 字节", got)
	}
	if !s.HasProcessors() {
		t.Fatal("结果过滤器应作为流式处理器参与")
	}
	// 更尖锐的一侧：换成「一被读取就 panic」的读者，建立包装照样要成功。
	// 计数只能证明「读得少」，这个证明的是「一个字节都没读」——
	// 接线方据此才能先建包装、再决定要不要开始转发。
	if _, err := p.WrapStream(context.Background(), rfResponse(t, "rf-stream-notouch",
		NewBodyReader(pipePanicReader{}, int64(len(payload))))); err != nil {
		t.Fatalf("建立包装不该需要正文: %v", err)
	}

	// 只读 1 个字节就停下：源侧最多只被消费掉一个 4096 字节的块。
	// 这是「按需读取」最直接的取证 —— 缓冲整段的实现在这里会一次性读走 41KB。
	// 这一字节同样是交付给客户端的内容，所以要留着参与最后的整体比对（丢掉它就等于
	// 自己制造一个「少了一个 d」的假故障）。
	head := make([]byte, 1)
	if n, rerr := s.Read(head); n != 1 || rerr != nil {
		t.Fatalf("首字节读取失败: %d %v", n, rerr)
	}
	if got := src.readBytes(); got == 0 || got > 4096 {
		t.Errorf("读 1 字节却从源侧取走了 %d 字节（不是按需增量）", got)
	}

	rest, rerr := io.ReadAll(s)
	if rerr != nil {
		t.Fatal(rerr)
	}
	got := append(head, rest...)
	if string(got) != want {
		t.Errorf("逐帧过滤结果不符（前 200 字节）:\n got=%.200s\nwant=%.200s", got, want)
	}
	// 高水位远小于响应总长：可证伪的「没缓存整段」断言（一次内部块 + 当前未完成行）。
	if hw := s.MaxBufferedBytes(); hw <= 0 || hw > 3*4096 || hw >= len(payload)/4 {
		t.Errorf("流式缓冲高水位 %d 相对响应总长 %d 过大", hw, len(payload))
	}
	// [DONE] 是 OpenAI 流式的收尾哨兵：把它吃掉或改形，客户端永远等不到正常结束，
	// 表现为「回答断了但连接没断」这种最难查的故障。
	if !strings.HasSuffix(string(got), "data: [DONE]\n\n") {
		t.Errorf("[DONE] 收尾被破坏: %q", got[max(0, len(got)-40):])
	}
	if strings.Contains(string(got), rfPhone) || strings.Contains(string(got), rfCard) {
		t.Error("流式过滤有残留")
	}
	if s.Err() != nil {
		t.Errorf("EOF 应记 nil: %v", s.Err())
	}

	// 跨块边界的半条 data 行必须被复原：分块 1 / 7 / 999 / 4096 字节（任意切断）
	// 给出**逐字节相同**的产物。若实现按块独立过滤，跨块切断的手机号就会一半留一半换，
	// 未过滤的残段直接发给客户端 —— 而按块统计的命中数还会显得「一切正常」。
	for _, chunk := range []int{1, 7, 999, 4096} {
		rd, derr := rfStreamDirect(t, spec, cfg, context.Background(), &rfChunkSource{data: []byte(payload), size: chunk})
		if derr != nil {
			t.Fatal(derr)
		}
		out, ierr := io.ReadAll(rd)
		if ierr != nil {
			t.Fatalf("chunk=%d 读取失败: %v", chunk, ierr)
		}
		if string(out) != want {
			t.Errorf("chunk=%d 的产物与预期不符（半条行没被复原）", chunk)
		}
		sf, ok := rd.(*sseFilter)
		if !ok {
			t.Fatalf("流式读者不是 sseFilter: %T", rd)
		}
		counts := sf.Counts()
		if len(counts) != 2 {
			t.Errorf("chunk=%d 的内部计数不齐: %+v", chunk, counts)
		}
		if n, had := rfCountOf(counts, "tel"); !had || n != 400 {
			t.Errorf("chunk=%d 的 filter:tel 计数 = %d(%v)，期望 400（每帧一处）", chunk, n, had)
		}
		if n, had := rfCountOf(counts, "acct"); !had || n != 400 {
			t.Errorf("chunk=%d 的 filter:acct 计数 = %d(%v)", chunk, n, had)
		}
	}

	// 收尾没有换行符的最后一行也要过滤后吐出：上游断流前常见这种半截帧，
	// 丢掉它等于把未过滤内容留在 carry 里悄悄消失（客户端看不出少了什么）。
	tail := `data: {"delta":"最后半帧 ` + rfPhone + `"}`
	rd, terr := rfStreamDirect(t, spec, cfg, context.Background(), strings.NewReader(tail))
	if terr != nil {
		t.Fatal(terr)
	}
	got2, _ := io.ReadAll(rd)
	if string(got2) != `data: {"delta":"最后半帧 [TEL]"}` {
		t.Errorf("无换行收尾处理不符: %q", got2)
	}
}

func TestRfStreamLineLimitAndMidStreamErrorSemantics(t *testing.T) {
	cfg := &Config{FilterRules: rfRules(), MaxLineBytes: 64}
	spec := rfSpec("rf-line", policy.BodyTransform)
	longLine := "data: " + strings.Repeat("y", 200)

	t.Run("单行超限拒绝整条流", func(t *testing.T) {
		rd, err := rfStreamDirect(t, spec, cfg, context.Background(), strings.NewReader(longLine))
		if err != nil {
			t.Fatal(err)
		}
		_, rerr := io.ReadAll(rd)
		if !errors.Is(rerr, ErrLineTooLarge) {
			t.Fatalf("单行超过 max_line_bytes 必须拒绝而不是无限攒着: %v", rerr)
		}
		// 归类是「输入超限」（不是「这条规则没命中」）：运维要按它决定调 max_line_bytes 还是
		// 换上游；原因码漂成 invalid_input 就等于把处置方向指错。
		if reason, class := classify(rerr); reason != ReasonInputTooLarge || class != classViolation {
			t.Errorf("归类应为 (input_too_large, violation)，实得 (%s, %s)", reason, class)
		}
	})

	t.Run("报错时已过滤但未交付的字节被扣住", func(t *testing.T) {
		// 钉一个**生产缺口**（不当场改）：源码注释写「有数据但读出错：先把数据过滤出去，
		// 错误下一轮再报」，实际两处错误返回（超长行、读出错）都是 `return 0, err`，
		// 把已经过滤好的 pending 一起扣在内部。
		// 方向上是 fail-safe 的（不会有未过滤内容溜出去），所以不当场改：
		// 要修就得同时决定「报错之后还许不许继续给数据」，那是跨包的语义决策
		// （forwarder 的空闲看门狗与错误上报时序都受影响），不属于补测试这一包。
		// 危害是可用性而不是合规：客户端/接线方丢掉前几帧完整内容，表现为回答开头缺一段。
		payload := rfFrame("甲") + rfFrame("乙") + longLine
		rd, err := rfStreamDirect(t, spec, cfg, context.Background(), strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		got, rerr := io.ReadAll(rd)
		if !errors.Is(rerr, ErrLineTooLarge) {
			t.Fatalf("应报单行超限: %v", rerr)
		}
		if len(got) != 0 {
			t.Errorf("当前实现是先报错、把已过滤字节扣到下一次 Read；若已改为随错误交付请同步重写本用例: %q", got)
		}
		buf := make([]byte, 4096)
		n2, rerr2 := rd.Read(buf)
		if n2 == 0 || rerr2 != nil {
			t.Fatalf("被扣住的字节仍在 pending 里（第二次 Read 才给出）: %d %v", n2, rerr2)
		}
		if string(buf[:n2]) != rfFrame("甲")+rfFrame("乙") {
			t.Errorf("迟到批次的形态不符: %q", buf[:n2])
		}
	})

	t.Run("已交付的字节收不回来", func(t *testing.T) {
		// 同一件事在**已经交付**的一侧：分块读取时前面的帧已经吐给调用方，
		// 之后才碰到超长行报错。接线方此时必须**作废整条响应**，
		// 而不是继续转发剩余部分或只记一条错误 —— 因为客户端已经收到内容，
		// 「这条响应被拦下了」与事实不符（审计与用户所见不一致才是事故源）。
		payload := rfFrame("甲") + rfFrame("乙") + longLine
		rd, err := rfStreamDirect(t, spec, cfg, context.Background(),
			&rfChunkSource{data: []byte(payload), size: len(rfFrame("甲"))})
		if err != nil {
			t.Fatal(err)
		}
		got, rerr := io.ReadAll(rd)
		if !errors.Is(rerr, ErrLineTooLarge) {
			t.Fatalf("应报单行超限: %v", rerr)
		}
		if string(got) != rfFrame("甲")+rfFrame("乙") {
			t.Errorf("报错前已交付的字节不符: %q", got)
		}
	})

	t.Run("数据与错误同批返回时数据被扣住", func(t *testing.T) {
		// Go 明确允许 Read 一次调用里同时给出 n>0 与 err；上游真断流就是这个形态。
		// 当前实现：本批数据被过滤进 pending，但 Read 直接返回 (0, err)，
		// 数据要到下一次 Read 才出现（且带着 nil）。同上属 fail-safe 的可用性缺口，不当场改。
		head := rfFrame("刷卡 "+rfCard) + rfFrame("来电 "+rfPhone)
		boom := errors.New("上游在首批就断了")
		rd, err := rfStreamDirect(t, spec, rfCfg(rfRules()...), context.Background(), &rfErrWithData{head: []byte(head), err: boom})
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, rerr := rd.Read(buf)
		if n != 0 || !errors.Is(rerr, boom) {
			t.Fatalf("同批数据+错误时首次 Read = (%d, %v)，当前实现是丢掉数据先报错", n, rerr)
		}
		n2, rerr2 := rd.Read(buf)
		if n2 == 0 || rerr2 != nil {
			t.Fatalf("错误之后仍应能把扣住的已过滤字节读出来: %d %v", n2, rerr2)
		}
		if string(buf[:n2]) != rfExpected(head) {
			t.Errorf("迟到批次的过滤形态不符: %q", buf[:n2])
		}
	})

	t.Run("错误在数据之后单独到达时不吞已交付内容", func(t *testing.T) {
		// 对照形态（pipeFlakySource：先给数据、下一轮才报错）：已交付的字节必须保留，
		// 错误如实上抛，且不把 EOF 伪装成成功（否则客户端以为收到了完整响应）。
		payload := rfFrame("刷卡 " + rfCard)
		rd, err := rfStreamDirect(t, spec, rfCfg(rfRules()...), context.Background(),
			&pipeFlakySource{head: []byte(payload)})
		if err != nil {
			t.Fatal(err)
		}
		got, rerr := io.ReadAll(rd)
		if rerr == nil {
			t.Fatal("中途断流必须上抛，不许伪装成正常收尾")
		}
		if !strings.Contains(rerr.Error(), "上游连接中断") {
			t.Errorf("断流错误未被如实上抛: %v", rerr)
		}
		if string(got) != rfExpected(payload) {
			t.Errorf("已交付部分的过滤形态不符: %q", got)
		}
	})
}

// ------------------------------------------------------------------ 审计面与并发

func TestRfStreamLimitsArePerLineOnlyNotTotalBytes(t *testing.T) {
	// 钉一个**生产缺口**（不当场改）：流式路径上 Spec 的 max_input_bytes / max_output_bytes
	// 完全不生效，唯一的量纲约束是 max_line_bytes。doc.go 写着 transform-body 受这三个上限
	// 约束，而缓冲路径（Input.Body → body.buffer）与流式路径（WrapStream → streamMeter →
	// sseFilter）是两套代码，后者一处都没做总量夹取。
	// 危害：策略作者按 max_input_bytes 写了限额，实际能过滤一份任意长的 SSE；
	// 内存与带宽的兜底只剩接线方（forwarder）自己的上限，而审计里看不出这个差别。
	// 不当场修的理由：总量上限要么加在 sseFilter 里（先要回答「超限是拒绝还是截断」，
	// 而拒绝意味着已交付的字节收不回来），要么加在 streamMeter 里（那是流水线侧对所有
	// 流式处理器的统一策略）。两种都是跨模块决策，不属于补测试这一包。
	spec := rfSpec("rf-stream-limit", policy.BodyTransform)
	spec.MaxInputBytes = 1024
	spec.MaxOutputBytes = 1024
	payload, want := rfSSE(40) // 约 4KB，远超声明的两个上限
	src := &rfChunkSource{data: []byte(payload), size: 512}
	p := rfBuild(t, spec, rfCfg(rfRules()...))
	s, err := p.WrapStream(context.Background(), rfResponse(t, "rf-stream-limit", NewBodyReader(src, int64(len(payload)))))
	if err != nil {
		t.Fatalf("装配流式包装失败: %v", err)
	}
	got, rerr := io.ReadAll(s)
	if rerr != nil {
		t.Fatalf("当前实现不因总量超限报错（若已改动请同步重写本用例与缺口说明）: %v", rerr)
	}
	if string(got) != want {
		t.Errorf("过滤形态不符: %.80s", got)
	}
	// 对照：同一份声明在缓冲路径上直接拒绝 —— 两个形态的限额口径确实不一致。
	if _, err := rfRun(t, spec, rfCfg(rfRules()...), payload); !errors.Is(err, ErrInputTooLarge) {
		t.Errorf("对照失败：缓冲路径本该报输入超限，实得 %v", err)
	}
}

func TestRfAuditSurfaceCarriesNoStrippedContent(t *testing.T) {
	body := `{"answer":"来电 ` + rfPhone + `，邮箱 alice.zhang@example.com，卡号 ` + rfCard + `"}`
	rules := []FilterRule{rfRule("tel", `1[3-9]\d{9}`), rfRule("acct", "", rfCard),
		rfRule("mail", `[\w.+-]+@[\w-]+\.[\w.-]+`)}
	cfg := rfCfg(rules...)
	originals := []string{rfPhone, rfCard, "alice.zhang@example.com"}
	assertNoLeak := func(t *testing.T, where, haystack string) {
		t.Helper()
		for _, value := range originals {
			if strings.Contains(haystack, value) {
				t.Errorf("%s 里出现被剥离的正文 %q（§2.9 规则 6 只允许 id/类型/范围/指纹/策略版本）", where, value)
			}
		}
	}

	// 缓冲链条：Result 三面（正文、改写元数据、审计记录序列化）都不许带原文。
	p := rfBuild(t, rfSpec("rf-audit", policy.BodyTransform), cfg)
	res, err := p.RunResponse(context.Background(), rfResponse(t, "rf-audit", NewBufferedBody([]byte(body))))
	if err != nil {
		t.Fatal(err)
	}
	audit := auditJSON(res.Audit)
	assertNoLeak(t, "Result.Body", string(res.Body))
	assertNoLeak(t, "审计记录", audit+fmt.Sprintf("|%v|%s", res.Rewrites, res.Metadata))
	// 反过来也要有内容：只留「处理过了」而不留类别，出事时没人能回答「哪条规则命中了几处」。
	if !strings.Contains(audit, "filter:tel") || !strings.Contains(audit, "filter:mail") {
		t.Errorf("审计里缺少改写类别: %s", audit)
	}
	entry := pipeEntry(t, res, "rf-audit")
	if !strings.HasPrefix(entry.InputHash, "sha256:") || !strings.HasPrefix(entry.OutputHash, "sha256:") ||
		entry.InputBytes <= 0 || entry.OutputBytes <= 0 {
		t.Errorf("审计条目应只含量与指纹: %+v", entry)
	}
	pipeAssertAuditReasonsSane(t, res)

	// 整份 Result 序列化（接线方可能直接把它扔进日志）。
	blob, jerr := rfMarshalResult(res)
	if jerr != nil {
		t.Fatal(jerr)
	}
	assertNoLeak(t, "Result 序列化", string(blob))

	// 拦截路径：命中 block 的响应，审计里也只能有结论码。
	bp := rfBuild(t, rfSpec("rf-block-audit", policy.BodyTransform),
		&Config{FilterRules: rules, FilterMode: FilterBlock})
	bres, berr := bp.RunResponse(context.Background(), rfResponse(t, "rf-block-audit", NewBufferedBody([]byte(body))))
	if berr == nil {
		t.Fatal("block 应拒收")
	}
	assertNoLeak(t, "拦截审计", auditJSON(bres.Audit)+fmt.Sprintf("|%v|%v", bres.Reasons, bres.Body))

	// 流式路径：审计同样不含原文，但**命中计数进不了审计** —— 钉这个已知缺口（不当场改）：
	// WrapStream 只在建立阶段填条目，逐块读取阶段的过滤器计数无处回填（EOF 之后也没有回填点），
	// 而 sseFilter.Counts() 是有的。当场接上需要先决定「流式改写在哪个时机进 AuditRecord」
	// （Stream.Audit() 现在没有 rewrites 通道，只有 Result 那一侧有），属审计字段层面的接线决策。
	// 危害：流式响应的合规报表会系统性低估命中量，运维按条数核对时得出「过滤没生效」的错误结论。
	payload, _ := rfSSE(3)
	src := &rfChunkSource{data: []byte(payload), size: 4096}
	sp := rfBuild(t, rfSpec("rf-stream-audit", policy.BodyTransform), cfg)
	stream, serr := sp.WrapStream(context.Background(), rfResponse(t, "rf-stream-audit", NewBodyReader(src, int64(len(payload)))))
	if serr != nil {
		t.Fatal(serr)
	}
	filtered, _ := io.ReadAll(stream)
	assertNoLeak(t, "流式正文", string(filtered))
	rec := stream.Audit()
	assertNoLeak(t, "流式审计", auditJSON(rec))
	if got := rec.Entries[0].Rewrites; len(got) != 0 {
		t.Errorf("流式审计的改写元数据通道当前是空的，若已回填请同步改用例: %+v", got)
	}
	sf, ok := stream.reader.(*sseFilter)
	if !ok {
		t.Fatalf("流式链上的读者不是 sseFilter: %T", stream.reader)
	}
	if counts := sf.Counts(); len(counts) != 2 {
		t.Errorf("过滤器内部确实统计了（Counts 非空），缺口只在审计回填: %+v", counts)
	} else if n, _ := rfCountOf(counts, "tel"); n != 3 {
		t.Errorf("filter:tel 计数 = %d，期望 3", n)
	}
}

func TestRfConcurrentReuseKeepsPerRequestStateLocal(t *testing.T) {
	// 处理器实例被多条请求并发复用（DoD 4）：命中计数是调用局部状态，
	// 一旦挂在结构体字段上就会跨请求累加，审计给出的处数变成一锅粥；
	// 更糟的是「A 请求的计数被解释成 B 请求的处理结果」—— 合规报表会据此判定某次
	// 泄露事件的规模，串号会直接把调查方向带偏。
	const workers, rounds = 8, 20
	p := rfBuild(t, rfSpec("rf-conc", policy.BodyTransform), rfCfg(rfRules()...))

	var wg sync.WaitGroup
	problems := make(chan string, workers*rounds)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				id := fmt.Sprintf("w%d-r%d", w, i)
				// 每条请求的正文不同：只有自己的手机号被替换，卡号一处都不许少。
				text := `{"answer":"` + id + ` 来电 ` + rfPhone + ` 刷卡 ` + rfCard + `"}`
				res, err := p.RunResponse(context.Background(), rfResponseNoT(id, NewBufferedBody([]byte(text))))
				if err != nil {
					problems <- fmt.Sprintf("%s: %v", id, err)
					continue
				}
				if want := `{"answer":"` + id + ` 来电 [TEL] 刷卡 [filtered]"}`; string(res.Body) != want {
					problems <- fmt.Sprintf("结果串号: got %s want %s", res.Body, want)
					continue
				}
				if merged := fmt.Sprintf("%v", res.Rewrites); merged != "[{filter:acct 1} {filter:tel 1}]" {
					problems <- fmt.Sprintf("计数被跨请求污染: %s", merged)
				}
			}
		}(w)
	}
	wg.Wait()
	close(problems)
	for msg := range problems {
		t.Error(msg)
	}
}
