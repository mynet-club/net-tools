package processor

// 第二波补测试（内置字段替换处理器 field-replace）：JSON 路径匹配（数组下标、通配段）、深度与规则数上限、
// 替换值形态（字面量 / $1 模板 / 映射表 / 规则链）、目标缺失与类型不符的静默放过、逐字节的正文守恒
// （键序与数字字面量是缓存与回放摘要的命门）、审计零原文，以及「只许看不许改」的档位强制。
// 助手统一 fr 前缀，流水线侧复用 pipeline_test.go 的 pipe*。

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// frSpec / frRule / frCfg 造出真实的 field-replace 声明、正则规则与规则表配置。
func frSpec(name string, access policy.BodyAccess) Spec {
	spec := pipeSpec(name, PhaseBeforeUpstream, access)
	spec.Type = TypeFieldReplace
	return spec
}

func frRule(name, path, pattern, replacement string) ReplaceRule {
	return ReplaceRule{Name: name, Path: path, Pattern: pattern, Replacement: replacement}
}

func frCfg(rules ...ReplaceRule) *Config { return &Config{Rules: rules} }

// frRun 按声明的档位跑一次正文替换；构造期配置非法即 t.Fatal（越权用例直连工厂）。
func frRun(t *testing.T, spec Spec, cfg *Config, body string) (*Output, error) {
	t.Helper()
	proc, err := newFieldReplace(spec, cfg)
	if err != nil {
		t.Fatalf("构造字段替换失败: %v", err)
	}
	in := &Input{RequestID: spec.Name, Phase: spec.Phase, Spec: spec,
		access: spec.BodyAccess, body: NewBufferedBody([]byte(body))}
	return proc.Process(context.Background(), in)
}

// frMustRun 要求规则确实命中并产出新正文。
func frMustRun(t *testing.T, rules []ReplaceRule, body string) *Output {
	t.Helper()
	out, err := frRun(t, frSpec("fr-run", policy.BodyTransform), &Config{Rules: rules}, body)
	if err != nil || len(out.Body) == 0 {
		t.Fatalf("规则未命中或未产出新正文: %v", err)
	}
	return out
}

// frCount 按规则名取回写计数。
func frCount(out *Output, name string) (int, bool) {
	for _, r := range out.Rewrites {
		if r.Kind == "field:"+name {
			return r.Count, true
		}
	}
	return 0, false
}

// ------------------------------------------------------------------ 路径匹配

func TestFrMatchesNestedPathsAndNoOpsOnMisses(t *testing.T) {
	body := `{"system":"OLD top","content":"OLD 顶层","messages":[{"content":"OLD a","role":"user"},` +
		`{"content":"OLD b"}],"choices":[{"text":"hit0"},{"text":"hit1"}],` +
		`"meta":{"note":"wild note","other":"wild other"},"count":7,"arr":["OLD in array"]}`
	rules := []ReplaceRule{
		frRule("sys", "system", "OLD", "NEW"), frRule("msg", `messages.[*].content`, "OLD", "X"),
		frRule("first", "choices[0].text", "hit", "HIT"), frRule("anykey", "meta.*", "wild", "KW"),
		frRule("ghost", "absent.deep.deeper", "whatever", "N"),                     // 目标不存在
		frRule("wrongtype", "count", "7", "Z"), frRule("obj", "meta", "wild", "Z"), // 目标是数字/对象
		{Name: "mapmiss", Path: "messages.[0].content", Mapping: map[string]string{"根本不存在": "zzz"}},
	}
	out := frMustRun(t, rules, body)

	// 路径必须与走过的步**完全对齐**（等长匹配）：通配不递归、下标不越界、类型不符的叶子静默放过。
	// 逐条按产出字节取证：顶层 content 不许被 messages.[*] 顺走、[0] 不许溢出到 [1]、
	// 对象键通配 * 覆盖两个键、数字叶子仍是数字、无规则指向的 arr 原样。
	for _, want := range []string{
		`"system":"NEW top"`, `"content":"OLD 顶层"`, `"content":"X a"`, `"content":"X b"`,
		`"role":"user"`, `"text":"HIT0"`, `"text":"hit1"`, `"note":"KW note"`,
		`"count":7`, `"arr":["OLD in array"]`,
	} {
		if !strings.Contains(string(out.Body), want) {
			t.Errorf("正文缺少 %s:\n%s", want, out.Body)
		}
	}
	if leaked := string(out.Body); strings.Contains(leaked, "deep") || strings.Contains(leaked, "Z") || strings.Contains(leaked, "zzz") {
		t.Errorf("未命中/类型不符的规则竟改动了正文: %s", out.Body)
	}
	// 命中计数按规则名归集；未命中的四条规则一个都不许留下计数（0 = 不许出现）。
	for name, want := range map[string]int{"sys": 1, "msg": 2, "first": 1, "anykey": 2, "ghost": 0, "wrongtype": 0, "obj": 0, "mapmiss": 0} {
		if count, ok := frCount(out, name); count != want || ok != (want > 0) {
			t.Errorf("field:%s 计数 = %d(%v)，期望 %d", name, count, ok, want)
		}
	}

	// 非 JSON 正文：字段替换的语义依赖路径，只能整体拒绝，不能当纯文本整块替换。
	if _, err := frRun(t, frSpec("fr-plain", policy.BodyTransform), frCfg(rules...), "把 OLD 换掉"); !errors.Is(err, ErrInvalidJSON) {
		t.Errorf("纯文本正文必须按非法输入拒绝: %v", err)
	}
}

// ------------------------------------------------------------------ 规模上限

func TestFrEnforcesDepthAndRuleCountLimits(t *testing.T) {
	spec := frSpec("fr-limits", policy.BodyTransform)
	// 构造期的路径深度不合规是配置问题（processor_config_invalid），与运行期文档嵌套超限的
	// depth_too_deep 不同源；两者都归违规类，fail_open 一样跳不过。
	deep := frRule("deep", "a.b.c.d", "x", "y")
	// 2 层被 Config.MaxPathDepth 夹住；0 落到默认 8 层；绝对上限 16 是 max_path_depth 自己越不过的天花板。
	for _, tc := range []struct {
		maxDepth int
		wantErr  bool
	}{
		{2, true}, {AbsoluteMaxPathDepth + 1, true}, {0, false},
	} {
		_, err := newFieldReplace(spec, &Config{Rules: []ReplaceRule{deep}, MaxPathDepth: tc.maxDepth})
		if tc.wantErr != (err != nil) || tc.wantErr && !errors.Is(err, ErrConfigInvalid) {
			t.Errorf("max_path_depth=%d: 期望报错=%v，实得 %v", tc.maxDepth, tc.wantErr, err)
		}
	}

	// 规则数：恰好到上限要能用，多一条就按违规拒（静默截断等于少做改写）。
	many := make([]ReplaceRule, 0, MaxReplaceRules+1)
	for i := 0; i <= MaxReplaceRules; i++ {
		many = append(many, frRule(fmt.Sprintf("r%02d", i), "v", "a", "b"))
	}
	if _, err := newFieldReplace(spec, &Config{Rules: many}); !errors.Is(err, ErrTooManyRules) {
		t.Errorf("%d 条规则应超过上限 %d 被拒: %v", len(many), MaxReplaceRules, err)
	}
	if _, err := newFieldReplace(spec, &Config{Rules: many[:MaxReplaceRules]}); err != nil {
		t.Errorf("恰好 %d 条规则必须在限额内: %v", MaxReplaceRules, err)
	}
	if _, err := newFieldReplace(spec, frCfg()); !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("一条规则都没有必须拒: %v", err)
	}
	if _, err := newFieldReplace(spec, frCfg(ReplaceRule{Path: "v"})); err == nil { // 既无 pattern 也无 mapping
		t.Errorf("空规则必须被拒")
	}

	// 路径语法与非法正则在构造期就炸：错配置绝不允许活到第一条真实请求。
	for _, bad := range []string{"", "a..b", "a[", "a[x]", "a[*", "a.*b", "a.[1].", "choices[-1].text"} {
		if _, err := newFieldReplace(spec, frCfg(frRule("bad", bad, "a", "b"))); err == nil {
			t.Errorf("路径 %q 语法不合法却编译通过了", bad)
		}
	}
	if _, err := newFieldReplace(spec, frCfg(frRule("rx", "v", "(", "b"),
		ReplaceRule{Name: "map", Path: "v", Mapping: map[string]string{strings.Repeat("k", MaxKeywordLen+1): "v"}})); !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("非法正则/超长映射项必须构造期报错: %v", err)
	}

	// 文档嵌套超限同样是违规（而不是「这条规则匹配不到」）。
	deepDoc := strings.Repeat("[", MaxDocDepth+2) + `"x"` + strings.Repeat("]", MaxDocDepth+2)
	_, err := frRun(t, spec, frCfg(frRule("named-rule", "v", "x", "y")), deepDoc)
	if !errors.Is(err, ErrDepthTooDeep) {
		t.Fatalf("超过 %d 层的文档必须被拒: %v", MaxDocDepth, err)
	}
	if reason, class := classify(err); reason != ReasonLimitExceeded || class != classViolation {
		t.Errorf("深度超限应为 (limit_exceeded, violation)，实得 (%s, %s)", reason, class)
	}
}

// ------------------------------------------------------------------ 替换值形态

func TestFrReplacementValueFormsAndRuleChaining(t *testing.T) {
	// $1 模板：把命中片段结构化地搬进替换值，而不是只能写死一个字面量。
	out := frMustRun(t, []ReplaceRule{frRule("tmpl", "content", `用户(\d+)号`, "账号[$1]")},
		`{"content":"请看 用户42号 与 用户7号 两段","other":"用户99号 不在此路径"}`)
	if !strings.Contains(string(out.Body), "请看 账号[42] 与 账号[7] 两段") ||
		!strings.Contains(string(out.Body), "用户99号 不在此路径") {
		t.Errorf("$1 展开或路径隔离不对: %s", out.Body)
	}
	if count, _ := frCount(out, "tmpl"); count != 1 {
		t.Errorf("同一条规则命中多处应记 1 次改写，实得 %d", count)
	}

	// 映射表是「整值精确替换」：命中就整体换成映射值，不命中才轮到 pattern 回落。
	mixed := []ReplaceRule{{
		Name: "mix", Path: "role", Pattern: "x", Replacement: "Y",
		Mapping: map[string]string{"xyz": "MAP", "admin": "user"},
	}}
	for value, want := range map[string]string{"xyz": `"role":"MAP"`, "admin": `"role":"user"`, "abcx": `"role":"abcY"`} {
		res := frMustRun(t, mixed, `{"role":"`+value+`"}`)
		if !strings.Contains(string(res.Body), want) {
			t.Errorf("%q 的映射/正则回落结果不对: 期望 %s，实得 %s", value, want, res.Body)
		}
	}
	// 两者都不命中 = 静默放过（正文不变、无计数），不是错误。
	missOut, missErr := frRun(t, frSpec("fr-miss", policy.BodyTransform), frCfg(mixed...), `{"role":"no-match"}`)
	if missErr != nil || len(missOut.Body) != 0 || len(missOut.Rewrites) != 0 {
		t.Errorf("未命中不该报错也不该产出新正文: %v %+v", missErr, missOut)
	}

	// 同一路径上的多条规则按声明次序串联（后一条在前一条的产出上匹配），各自计数；
	// 同输入两次必须逐字节相同（可复现性是回放的前提）。
	chained := frMustRun(t, []ReplaceRule{frRule("step1", "v", "A", "B"), frRule("step2", "v", "B", "C")}, `{"v":"A"}`)
	if !strings.Contains(string(chained.Body), `"v":"C"`) {
		t.Errorf("规则链次序不对: %s", chained.Body)
	}
	for _, name := range []string{"step1", "step2"} {
		if count, ok := frCount(chained, name); !ok || count != 1 {
			t.Errorf("链上每条规则各自计数：field:%s = %d(%v)", name, count, ok)
		}
	}
}

// ------------------------------------------------------------------ 逐字节正文守恒

func TestFrBytePreservesUnrelatedFieldsAndDropsOriginals(t *testing.T) {
	// 一条 "*" 规则只吃掉**根层**字符串叶子（通配不递归），深层 SECRET 原样留下。
	// 逐字节断言同时钉住三件容易悄悄坏掉的事：键序按字典序重排（实现的已知副作用）、
	// 数字字面量原样、HTML 符号不被转义（< 变成 < 会让替换痕迹不可见）。
	body := `{"zeta":"保留","alpha":"有 SECRET 在这","pi":"3.14","exp":1e5,` +
		`"big":123456789012345678901234567890,"num":42,"esc":"<a> & \"引号\"",` +
		`"beta":"SECRET 第二处","gamma":"SECRET 第三处",` +
		`"list":[3,"SECRET",0.30000000000000004],"nested":{"k2":"v2","k1":"SECRET"}}`
	want := `{"alpha":"有 [REDACTED] 在这","beta":"[REDACTED] 第二处",` +
		`"big":123456789012345678901234567890,"esc":"<a> & \"引号\"","exp":1e5,` +
		`"gamma":"[REDACTED] 第三处","list":[3,"SECRET",0.30000000000000004],` +
		`"nested":{"k1":"SECRET","k2":"v2"},"num":42,"pi":"3.14","zeta":"保留"}`

	secretRule := frRule("secret", "*", "SECRET", "[REDACTED]")
	out := frMustRun(t, []ReplaceRule{secretRule}, body)
	if got := string(out.Body); got != want {
		t.Errorf("正文逐字节不符：\n got=%s\nwant=%s", got, want)
	}
	if count, _ := frCount(out, "secret"); count != 3 {
		t.Errorf("field:secret 计数 = %d，期望 3（%+v）", count, out.Rewrites)
	}

	// 深层字段要各自显式声明路径才会被换掉：补齐 list.[*] 与 nested.* 后替换前的值一处不剩。
	deep := []ReplaceRule{secretRule,
		frRule("listitem", "list.[*]", "SECRET", "[REDACTED]"),
		frRule("nestedkey", "nested.*", "SECRET", "[REDACTED]")}
	if all := frMustRun(t, deep, body); strings.Contains(string(all.Body), "SECRET") {
		t.Errorf("补上深层路径后仍有残留: %s", all.Body)
	}

	// 审计面同样不许带替换前的值（只留类别与处数、量与指纹）。
	p, _, _ := pipeBuildCfg(t, frCfg(deep...), nil, frSpec("fr-chain", policy.BodyTransform))
	res, rerr := p.RunRequest(context.Background(), pipeRequest(t, "fr-chain", NewBufferedBody([]byte(body))))
	if rerr != nil {
		t.Fatalf("合规链条不该失败: %v", rerr)
	}
	audit := auditJSON(res.Audit)
	if strings.Contains(string(res.Body), "SECRET") || strings.Contains(audit, "SECRET") || !strings.Contains(audit, "field:secret") {
		t.Errorf("审计面出现替换前的值或缺少改写类别: %s / %s", res.Body, audit)
	}
	if entry := pipeEntry(t, res, "fr-chain"); entry.OutputBytes <= 0 || !strings.HasPrefix(entry.OutputHash, "sha256:") {
		t.Errorf("审计条目应只含量与指纹: %+v", entry)
	}
}

// ------------------------------------------------------------------ 档位强制

func TestFrInspectBodyCannotWriteEvenWhenFailOpen(t *testing.T) {
	rules := []ReplaceRule{frRule("secret", "content", "SECRET", "[REDACTED]")}
	body := `{"content":"SECRET 必须被换掉","keep":"其它内容"}`

	// 注册期闸门：产出是新正文的处理器，档位低于 transform-body 直接拒装配。
	inspectSpec := frSpec("fr-insp", policy.BodyInspect)
	inspectSpec.FailClosed = false
	reg := NewRegistry()
	for _, s := range []Spec{inspectSpec, frSpec("fr-meta", policy.BodyMetadataOnly)} {
		if err := reg.Register(s, frCfg(rules...)); !errors.Is(err, ErrBodyAccessNotForType) {
			t.Fatalf("%v 档的 field-replace 必须注册失败: %v", s.BodyAccess, err)
		}
	}

	// 运行期闸门：手搭一条越权链，证明 FailClosed=false 也放不过档位越权。
	proc, err := newFieldReplace(inspectSpec, frCfg(rules...))
	if err != nil {
		t.Fatal(err)
	}
	p := &Pipeline{stages: []stage{{spec: inspectSpec, proc: proc}}, clock: func() time.Time { return pipeBaseNow }}
	res, rerr := p.RunRequest(context.Background(), pipeRequest(t, "fr-insp-1", NewBufferedBody([]byte(body))))
	if rerr == nil || !errors.Is(rerr, ErrBodyReplaceDenied) {
		t.Fatalf("inspect-body 产出替换正文必须被拒: %v", rerr)
	}
	if reason, class := classify(rerr); reason != ReasonBodyReplaceDenied || class != classViolation {
		t.Errorf("归类应为 (body_replace_denied, violation)，实得 (%s, %s)", reason, class)
	}
	if res.Outcome != ReasonBodyReplaceDenied || strings.Contains(string(res.Body), "[REDACTED]") {
		t.Errorf("越权替换不得放行，且结论码要能审出来: %s / %s", res.Outcome, res.Body)
	}
	// inspect 档读正文本身是合规的，所以 DeniedReads 必须是 0（越权的是写，不是读）。
	if entry := pipeEntry(t, res, "fr-insp"); entry.DeniedReads != 0 || !entry.Buffered {
		t.Errorf("DeniedReads/Buffered 不对: %+v", entry)
	}

	// 对照：合规档位（transform-body）正常生效。
	okOut, oerr := frRun(t, frSpec("fr-ok", policy.BodyTransform), frCfg(rules...), body)
	if oerr != nil || !strings.Contains(string(okOut.Body), `"content":"[REDACTED] 必须被换掉"`) {
		t.Errorf("transform-body 下替换没生效: %v / %s", oerr, okOut.Body)
	}
}
