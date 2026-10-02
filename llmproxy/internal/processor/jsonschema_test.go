package processor

// 补测试（受限 JSON Schema 校验器 json-schema）：本文件覆盖的不变量 ——
// ① 关键字集合是**封闭**的：任何不在受限子集内的关键字都在构造期被拒，绝不静默通过
// （静默通过等于「策略作者以为校验了 minItems，实际没校验」，合规声明变成空气）；
// ② 每个受支持关键字的接受/拒绝路径都对，且拒绝错误**点名具体实例路径**（$.a.b[0]）——
// 只说「不符合 schema」的报错无法修策略；同时错误文本里不许出现被校验的取值本身（规则 6）；
// ③ 非法 schema（类型写错、边界为负、enum 为空、items 用元组形式……）一律在构造期被拒，
// 而且报错与 JSON map 的遍历顺序无关（确定性）；
// ④ 档位决定校验对象：metadata-only 的校验器一个字节都不碰正文（§2.9 规则 7 的快速路径）；
// ⑤ 判定类（schema 不符、非 JSON）与违规类（超限、无输入）失败**无视 fail_open**，
// 只有基础设施类可以被跳过；
// ⑥ 输入大小、嵌套深度、非 JSON 输入的边界行为（含深度上限只由解析器兜住这一事实）。
// 助手统一 js 前缀；流水线侧复用 pipeline_test.go 的 pipe* 与 auditJSON。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// jsPhone 是 fixture 里的敏感取值（明显虚构，不是真实号码）：
// 用它取证「拒绝错误与审计里不许出现被校验的内容」。
const jsPhone = "13800138000"

// jsSchema 把 schema 原文包成 Config（Config 是注册期绑定的类型专有参数）。
func jsSchema(raw string) *Config { return &Config{Schema: json.RawMessage(raw)} }

// jsSpecAt 是一条真实的 json-schema 声明（阶段与档位可调，用于测注册期的两道门）。
func jsSpecAt(name string, phase Phase, access policy.BodyAccess) Spec {
	spec := pipeSpec(name, phase, access)
	spec.Type = TypeJSONSchema
	return spec
}

// jsSpec 是校验请求正文的常见形态（请求侧阶段 + inspect-body）。
func jsSpec(name string, access policy.BodyAccess) Spec {
	return jsSpecAt(name, PhaseBeforeUpstream, access)
}

// jsInput 直接跑处理器（不经流水线）：校验对象是正文还是元数据、Rewrites 长什么样，
// 只能在处理器自己的产出上取证。
func jsInput(t *testing.T, spec Spec, cfg *Config, ctx context.Context, body *Body, meta string) (*Output, error) {
	t.Helper()
	proc, err := newSchemaValidator(spec, cfg)
	if err != nil {
		t.Fatalf("构造校验器失败: %v", err)
	}
	in := &Input{RequestID: spec.Name, Phase: spec.Phase, Model: "gpt-test", Spec: spec,
		Metadata: json.RawMessage(meta), access: spec.BodyAccess, body: body}
	return proc.Process(ctx, in)
}

func jsRun(t *testing.T, spec Spec, cfg *Config, body string) (*Output, error) {
	t.Helper()
	return jsInput(t, spec, cfg, context.Background(), NewBufferedBody([]byte(body)), "")
}

// jsMustCompileReject 断言这份 schema 在**构造期**就被拒（错误绝不允许活到第一条真实请求）。
func jsMustCompileReject(t *testing.T, schema string) error {
	t.Helper()
	_, err := newSchemaValidator(jsSpec("js-bad", policy.BodyInspect), jsSchema(schema))
	if err == nil {
		t.Fatalf("这份 schema 本该构造期被拒: %s", schema)
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("构造期错误必须带 ErrConfigInvalid 哨兵，实得 %v", err)
	}
	return err
}

// jsMustViolate 断言实例被判违规，并检查错误里点了哪个实例路径。
func jsMustViolate(t *testing.T, schema, instance, wantPath string) error {
	t.Helper()
	out, err := jsRun(t, jsSpec("js-kw", policy.BodyInspect), jsSchema(schema), instance)
	if !errors.Is(err, ErrSchemaViolation) {
		t.Fatalf("实例 %s 本该违反 %s，实得 %v", instance, schema, err)
	}
	if out != nil {
		t.Errorf("违规不得带产出: %+v", out)
	}
	if wantPath != "" && !strings.Contains(err.Error(), wantPath+":") {
		t.Errorf("拒绝错误必须点出实例路径 %s，实得 %v", wantPath, err)
	}
	return err
}

// jsMustAccept 断言实例通过，并且「通过」这件事在产出里留了痕
// （审计要靠 schema:valid 区分「校验过且合格」与「压根没跑」）。
func jsMustAccept(t *testing.T, schema, instance string) {
	t.Helper()
	out, err := jsRun(t, jsSpec("js-ok", policy.BodyInspect), jsSchema(schema), instance)
	if err != nil {
		t.Fatalf("实例 %s 本该通过 %s: %v", instance, schema, err)
	}
	if out.Reason != ReasonOK {
		t.Errorf("Reason = %s", out.Reason)
	}
	if got := fmt.Sprint(out.Rewrites); got != "[{schema:valid 1}]" {
		t.Errorf("通过标记不符: %s", got)
	}
}

// jsNest 造 n 层嵌套数组（每层一个字节，深度是可控输入而不是巧合）。
func jsNest(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }

// jsItemsSchema 造 n 层嵌套的 items schema，用于取证 schema 自身没有深度上限。
func jsItemsSchema(n int, inner string) string {
	return strings.Repeat(`{"items":`, n) + inner + strings.Repeat("}", n)
}

// jsBuild 用真注册表装配一条链（注册期就跑一次构造，配置非法在这里直接 t.Fatal）。
func jsBuild(t *testing.T, spec Spec, cfg *Config) *Pipeline {
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

// jsNoBodyTouch 把「metadata-only 不许读正文」的取证集中一处：
// 正文用 pipePanicReader 供给，实现一旦去读就是 panic，这里翻成清晰的用例失败。
func jsNoBodyTouch(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("metadata-only 档位的校验器读取了请求正文: %v", r)
		}
	}()
	fn()
}

// ------------------------------------------------------------------ 受支持关键字

func TestJsSupportedKeywordsAcceptAndReject(t *testing.T) {
	// 一张表跑完封闭子集的全部 12 个关键字。wantPath 非空表示期望违规，
	// 并且错误里必须出现那个实例路径 —— 运维拿到报错要能直接定位到出问题的字段，
	// 一句「不符合 schema」等于让人把整份请求体重读一遍。
	cases := []struct{ name, schema, instance, wantPath string }{
		{"type 字符串接受", `{"type":"string"}`, `"hello"`, ""},
		{"type 字符串拒绝数字", `{"type":"string"}`, `1`, "$"},
		{"type 对象接受", `{"type":"object"}`, `{"a":1}`, ""},
		{"type 数组拒绝对象", `{"type":"array"}`, `{"a":1}`, "$"},
		{"type 布尔", `{"type":"boolean"}`, `"true"`, "$"},
		{"type null", `{"type":"null"}`, `null`, ""},
		{"type null 拒绝 0", `{"type":"null"}`, `0`, "$"},
		{"type number 接受整数与小数", `{"type":"number"}`, `1.50`, ""},
		{"type 联合接受", `{"type":["string","null"]}`, `null`, ""},
		{"type 联合拒绝数字", `{"type":["string","null"]}`, `1`, "$"},
		{"required 齐备", `{"required":["a","b"]}`, `{"a":1,"b":2}`, ""},
		{"required 缺字段", `{"required":["a","b"]}`, `{"a":1}`, "$"},
		{"enum 命中", `{"enum":["a","b"]}`, `"b"`, ""},
		{"enum 未命中", `{"enum":["a","b"]}`, `"c"`, "$"},
		{"const 相等", `{"const":"only"}`, `"only"`, ""},
		{"const 不等", `{"const":"only"}`, `"other"`, "$"},
		{"pattern 命中", `{"pattern":"^AB"}`, `"AB7"`, ""},
		{"pattern 未命中", `{"pattern":"^AB"}`, `"zz"`, "$"},
		{"minLength 恰好", `{"minLength":3}`, `"abc"`, ""},
		{"minLength 不足", `{"minLength":3}`, `"ab"`, "$"},
		{"maxLength 恰好", `{"maxLength":2}`, `"ab"`, ""},
		{"maxLength 超出", `{"maxLength":2}`, `"abc"`, "$"},
		{"minimum 恰好", `{"minimum":5}`, `5`, ""},
		{"minimum 不足", `{"minimum":5}`, `3`, "$"},
		{"maximum 超出", `{"maximum":5}`, `9`, "$"},
		{"items 齐备", `{"items":{"type":"string"}}`, `["a","b"]`, ""},
		{"items 第二元素违规", `{"items":{"type":"string"}}`, `["a",2]`, "$[1]"},
		{"items 空数组通过", `{"items":{"type":"string"}}`, `[]`, ""},
		{"properties 嵌套", `{"properties":{"a":{"properties":{"b":{"type":"string"}}}}}`, `{"a":{"b":"ok"}}`, ""},
		{"properties 嵌套违规", `{"properties":{"a":{"properties":{"b":{"type":"string"}}}}}`, `{"a":{"b":1}}`, "$.a.b"},
		{"未声明属性默认放过", `{"properties":{"a":{}}}`, `{"a":1,"b":2}`, ""},
		{"additionalProperties false 拒绝多余键", `{"properties":{"a":{}},"additionalProperties":false}`, `{"a":1}`, ""},
		{"additionalProperties false 命中多余键", `{"properties":{"a":{}},"additionalProperties":false}`, `{"a":1,"b":2}`, "$"},
		{"对象数组里的违规", `{"items":{"properties":{"n":{"type":"integer"}}}}`, `[{"n":1},{"n":"x"}]`, "$[1].n"},
		{"空 schema 什么都接受", `{}`, jsNest(3), ""},
		// 约束只在「自己的类型」上生效（Draft-07 语义，也是子集的实现口径）：
		// 写策略的人如果只写 {"pattern":"^a"} 而没写 "type":"string"，数字与对象会一路放行。
		// 这不是缺口，但必须写成断言 —— 否则「配了却没生效」只能靠读实现才知道。
		{"pattern 对非字符串不生效", `{"pattern":"^a"}`, `123`, ""},
		{"minLength 对数字不生效", `{"minLength":5}`, `1`, ""},
		{"maximum 对字符串不生效", `{"maximum":5}`, `"9"`, ""},
		{"required 对非对象不生效", `{"required":["a"]}`, `"x"`, ""},
		{"items 对非数组不生效", `{"items":{"type":"string"}}`, `{"a":1}`, ""},
		{"properties 对非对象不生效", `{"properties":{"a":{"type":"string"}}}`, `[1,2]`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.wantPath == "" {
				jsMustAccept(t, c.schema, c.instance)
				return
			}
			jsMustViolate(t, c.schema, c.instance, c.wantPath)
		})
	}
}

func TestJsRejectionIdentifiesInstancePathAndCarriesNoInstanceValue(t *testing.T) {
	// 被校验的内容本身就是敏感数据（这正是它进网关的原因），而校验失败的错误会被接线方
	// 写进日志、回给调用方。错误文本只许含路径、关键字名与量（长度、允许值个数）：
	// 「取值不在 enum 允许的 2 个值内」足够定位问题，而「取值 X 不在允许集合 [secret-a, secret-b]」
	// 会把候选集本身与实例值一起复制进日志。
	leaks := []struct{ name, schema, instance, path, forbidden string }{
		{"maxLength 不带回原文", `{"properties":{"id":{"maxLength":1}}}`, `{"id":"` + jsPhone + `"}`, "$.id", jsPhone},
		{"enum 不回候选值", `{"enum":["alice.zhang@example.com","bob.zhang@example.com"]}`, `"carol.zhang@example.com"`, "$", "alice.zhang@example.com"},
		{"enum 不回实例值", `{"enum":["a"]}`, `"` + jsPhone + `"`, "$", jsPhone},
		{"const 不回声明值", `{"const":"sk-fake-abcdef"}`, `"other"`, "$", "sk-fake-abcdef"},
		{"pattern 不回内容", `{"pattern":"^[0-9]{11}$"}`, `"alice.zhang@example.com"`, "$", "alice.zhang@example.com"},
		{"类型违规不回内容", `{"type":"integer"}`, `"` + jsPhone + `"`, "$", jsPhone},
		{"数组里的违规不回内容", `{"items":{"properties":{"ssn":{"type":"null"}}}}`, `[{"ssn":"` + jsPhone + `"}]`, "$[0].ssn", jsPhone},
	}
	for _, c := range leaks {
		t.Run(c.name, func(t *testing.T) {
			err := jsMustViolate(t, c.schema, c.instance, c.path)
			if strings.Contains(err.Error(), c.forbidden) {
				t.Errorf("拒绝错误里出现了实例/声明内容 %q: %v", c.forbidden, err)
			}
		})
	}

	// 长度数字是 §2.9 规则 6 明确允许的「范围」信息，留着它才能让人判断「超了一点点还是超了一倍」。
	err := jsMustViolate(t, `{"maxLength":2}`, `"`+strings.Repeat("x", 9)+`"`, "$")
	if !strings.Contains(err.Error(), "长度 9") {
		t.Errorf("违规错误应保留长度信息: %v", err)
	}

	// 钉一个当前行为（不当场改）：additionalProperties:false 的报错会**带出键名**。
	// 保留它是可用的必要代价 —— 调用方不知道哪个键多余就没法修请求；
	// 但键名同样可能带内容（客户端完全可以把令牌当键名发），日志侧要按「键名可含敏感信息」处理。
	// 不当场改成脱敏键名：改法要么丢信息（报错没用了），要么做部分遮蔽（引入新的口径与长度规则），
	// 两者都属于错误文本规范的决策，不属于补测试这一包。
	err = jsMustViolate(t, `{"properties":{"a":{}},"additionalProperties":false}`,
		`{"a":1,"sk-fake-key":"value-`+jsPhone+`"}`, "$")
	if !strings.Contains(err.Error(), `"sk-fake-key"`) {
		t.Errorf("当前实现会带出多余键名，若已改动请同步重写本用例与缺口说明: %v", err)
	}
	// 但只带键名，不带那个键对应的值。
	if strings.Contains(err.Error(), "value-"+jsPhone) {
		t.Errorf("多余键的值被复制进错误: %v", err)
	}
}

func TestJsIntegerIsJudgedByLiteralForm(t *testing.T) {
	// integer 单独一档（回落成 number 会让 1.5 通过）；判定按**字面量**（含 . e E 就不是整数）。
	// 这与 Draft-07「值为整数即算 integer」有出入：1.0 在标准里是整数，这里不是。
	// 钉住字面量口径的理由是实现可解释（不引入浮点比较），后果必须让策略作者知道 ——
	// 一个把数值序列化成 1.0 的上游会在这里被整片拒掉，而报错只说「类型不符合 [integer]」。
	for _, ok := range []string{"5", "-5", "0", "123456789012345678901234567890"} {
		jsMustAccept(t, `{"type":"integer"}`, ok)
	}
	for _, bad := range []string{"1.0", "1.50", "1e5", "1E5", `"5"`, "true"} {
		jsMustViolate(t, `{"type":"integer"}`, bad, "$")
	}
	// 同一个字面量在 number 档下通过：档位差异要在错误文本里能看出来（types 列表被回显）。
	err := jsMustViolate(t, `{"type":"integer"}`, "1.0", "$")
	if !strings.Contains(err.Error(), "[integer]") {
		t.Errorf("类型违规应回显声明的类型集合（不含实例内容）: %v", err)
	}
	jsMustAccept(t, `{"type":"number"}`, "1.0")
}

func TestJsLengthLimitsCountRunes(t *testing.T) {
	// minLength/maxLength 按**码点**计数：用字节数的话，一句中文短语会被判成三倍长，
	// 规则写成 maxLength:20 实际只能放六个汉字 —— 策略作者完全看不出校验口径变了。
	jsMustAccept(t, `{"maxLength":3}`, `"中文中"`)       // 9 字节 / 3 码点
	jsMustViolate(t, `{"maxLength":2}`, `"中文中"`, "$") // 3 码点 > 2
	jsMustAccept(t, `{"minLength":2}`, `"🙂🙂"`)        // 码点计数含星平面字符
	jsMustViolate(t, `{"minLength":3}`, `"🙂🙂"`, "$")
	// 长度信息进错误时也是码点，审计与人工核对同一口径。
	if err := jsMustViolate(t, `{"maxLength":1}`, `"中文中"`, "$"); !strings.Contains(err.Error(), "长度 3") {
		t.Errorf("错误里的长度必须按码点报: %v", err)
	}
}

func TestJsEnumAndConstCompareCanonicalValues(t *testing.T) {
	// enum/const 比较的是**规范化后的值**而不是字节：上游把 1 序列化成 1.0 或 1e0
	// 都是同一个 JSON 数值，按字节比会让一份合法请求随机被拒（取决于客户端怎么格式化数字）。
	for _, one := range []string{"1", "1.0", "1e0", "1.00", "0.1e1"} {
		jsMustAccept(t, `{"enum":[1]}`, one)
		jsMustAccept(t, `{"const":1}`, one)
	}
	jsMustViolate(t, `{"enum":[1]}`, `2`, "$")
	jsMustViolate(t, `{"enum":[1]}`, `true`, "$")
	// 容器类同样规范化（键序按字典序，同值必同串）。
	jsMustAccept(t, `{"enum":[{"x":1,"y":2}]}`, `{"y":2,"x":1}`)
	jsMustViolate(t, `{"enum":[{"x":1,"y":2}]}`, `{"x":1,"y":3}`, "$")
	// null / 布尔 走 JSON 字面量比较。
	jsMustAccept(t, `{"const":null}`, `null`)
	jsMustViolate(t, `{"const":null}`, `0`, "$")
	jsMustAccept(t, `{"enum":[true,"true"]}`, `"true"`)
	// 超大整数走 float64 规范化：这条是**当前口径**，钉住它以免以后被「顺手修成精确比较」
	// 时没人注意到语义变了（两个不同的大整数在 float64 下会塌成同一个值）。
	jsMustAccept(t, `{"enum":[123456789012345678901234567890]}`, `123456789012345678901234567891`)
}

// ------------------------------------------------------------------ 封闭关键字集

func TestJsRejectsKeywordsOutsideClosedSubset(t *testing.T) {
	// 核心不变量：不认识的关键字一律拒绝装配，**绝不静默通过**。
	// 这里既覆盖「已知未实现」清单里的（带「已知未实现」标注），也覆盖清单外的任意拼写
	// —— 后者证明实现没有「只挡清单」的漏洞：新增一个 Draft 关键字名同样会被拒。
	for _, kw := range []string{"format", "minItems", "maxItems", "uniqueItems", "anyOf",
		"oneOf", "allOf", "not", "$ref", "definitions", "patternProperties",
		"exclusiveMinimum", "multipleOf", "title", "description", "nullable"} {
		err := jsMustCompileReject(t, fmt.Sprintf(`{"%s":"x","type":"string"}`, kw))
		// 钉一个当前行为（不当场改）：newSchemaValidator 用 Errorf(ErrConfigInvalid, "%s: %v", ...)
		// 重包一层，而 %v 会把内层哨兵降成纯文本 —— 于是注册路径上
		// errors.Is(err, ErrSchemaUnsupported) 恒为假，管理 API 想按「关键字不支持」与
		// 「其它配置错误」分流回答时只能去匹配错误文案。
		// registry.Register 自己已经用 fmt.Errorf("%w") 示范了正确做法（哨兵透传），
		// 所以这条属于「统一哨兵透传」的整理工作，要先决定对外承诺哪一层哨兵，不在本包当场改。
		if errors.Is(err, ErrSchemaUnsupported) {
			t.Errorf("关键字 %s 的内层哨兵现在会被 %v 降级掉；若已修复请同步重写本用例与缺口说明", kw, err)
		}
		// 注解类关键字（title/description）同样要显式拒绝：
		// 「允许且忽略」是一个需要写进策略规范的决策，不能由实现偷偷决定。
		if !strings.Contains(err.Error(), "已知未实现") {
			t.Errorf("已知未实现的关键字应在报错里标注，方便区分「拼错」与「没支持」: %v", err)
		}
		if !strings.Contains(err.Error(), "minLength") {
			t.Errorf("报错必须列出可用关键字集合，否则作者只能猜: %v", err)
		}
	}
	for _, typo := range []string{"maxlength", "MaxLength", "requird", "必填"} {
		err := jsMustCompileReject(t, fmt.Sprintf(`{"%s":1}`, typo))
		if !strings.Contains(err.Error(), "不在受限子集内") {
			t.Errorf("拼错的关键字 %s 应被拒（静默通过等于校验消失）: %v", typo, err)
		}
		if strings.Contains(err.Error(), "已知未实现") {
			t.Errorf("拼错的关键字不该被标成「已知未实现」（误导成「实现会补」）: %v", err)
		}
	}

	// 形式受限的三处必须显式拒绝而不是半实现：半实现比不实现更危险。
	jsMustCompileReject(t, `{"items":[{"type":"string"},{"type":"integer"}]}`) // 元组形式
	jsMustCompileReject(t, `{"additionalProperties":{"type":"string"}}`)       // schema 形式
	for _, bad := range []string{`{"properties":{"a":"不是对象"}}`, `{"items":"不是对象"}`} {
		if err := jsMustCompileReject(t, bad); !strings.Contains(err.Error(), "对象") {
			t.Errorf("子 schema 必须是对象: %v", err)
		}
	}
	// additionalProperties 显式 true 与不写等价：接受但不产生约束（写策略的人常用它表达「放开」）。
	jsMustAccept(t, `{"properties":{"a":{"type":"integer"}},"additionalProperties":true}`, `{"a":1,"zzz":"随便"}`)
}

func TestJsIllegalSchemaIsRejectedAtConstructionTime(t *testing.T) {
	// 每一条都要在**注册/装配期**炸掉，绝不允许活到第一条真实请求：
	// 一份编译不过的 schema 如果在请求期才报错，表现为「上线时校验通过、上线后流量全挂」。
	for _, bad := range []string{
		`[]`,                              // schema 本身必须是对象
		`"string"`,                        // 同上
		`{"type":3}`,                      // 类型必须是字符串或字符串数组
		`{"type":"int"}`,                  // 未知类型名（拼错不能被当成「不校验」）
		`{"type":[]}`,                     // 空类型列表等价于「什么都不接受」，几乎一定是笔误
		`{"type":["string","numberish"]}`, // 联合里的未知项同样拒
		`{"required":"a"}`,                // 必须是字符串数组
		`{"enum":[]}`,                     // 空 enum 恒假：等价于「拒绝一切」
		`{"enum":{}}`,                     // 必须是数组
		`{"minLength":-1}`,                // 负数边界没有意义
		`{"maxLength":"abc"}`,             // 必须是数字
		`{"maxLength":1.5}`,               // 带小数不是合法长度
		`{"minimum":"x"}`,                 // 数值边界必须是数字
		`{"pattern":"("}`,                 // 非法正则
		`{"pattern":123}`,                 // 必须是字符串
		`{"pattern":"` + strings.Repeat("a", MaxPatternLen+1) + `"}`, // 模式长度上限
		`{"properties":3}`,                 // 子 schema 表必须是对象
		`{"additionalProperties":"false"}`, // 布尔形式才有意义
		`{"type":"string"`,                 // 截断的 JSON
	} {
		jsMustCompileReject(t, bad)
	}
	// 恰好在上限内的必须放行，否则上面的门拒得太宽（限额写成「一律拒」是常见实现事故）。
	if _, err := newSchemaValidator(jsSpec("js-edge", policy.BodyInspect),
		jsSchema(`{"pattern":"`+strings.Repeat("a", MaxPatternLen)+`"}`)); err != nil {
		t.Errorf("恰好 %d 长度的模式应在上限内: %v", MaxPatternLen, err)
	}
	// nil Config / 没有 Schema：判定型处理器没有 schema 就等于「什么都放过」，必须拒。
	for _, cfg := range []*Config{nil, {}, &Config{Schema: nil}} {
		_, err := newSchemaValidator(jsSpec("js-noschema", policy.BodyInspect), cfg)
		pipeWantErr(t, err, ErrConfigInvalid)
		if !strings.Contains(err.Error(), "缺少 schema") {
			t.Errorf("缺 schema 的报错应直说原因（而不是「schema 必须是对象」这种绕弯说法）: %v", err)
		}
	}
	// 空白但非空的 schema 文本走解析失败那条路：同样是构造期拒，不能当成 `{}` 接受一切。
	_, err := newSchemaValidator(jsSpec("js-blank", policy.BodyInspect), jsSchema("   "))
	pipeWantErr(t, err, ErrConfigInvalid)
	if strings.Contains(err.Error(), "缺少 schema") {
		t.Errorf("有字节但解析不动，报错应是解析失败而不是「缺少」: %v", err)
	}
}

func TestJsCompileErrorsAreDeterministic(t *testing.T) {
	// 编译期按键排序遍历：同一份非法 schema 每次启动报的必须是**同一个**关键字，
	// 否则运维无法按报错文本做告警聚合（Go 的 map 遍历顺序是随机的，这条只能靠实现保证）。
	a := `{"minItems":1,"format":"email","zzz":1}`
	b := `{"zzz":1,"format":"email","minItems":1}`
	errA := jsMustCompileReject(t, a)
	errB := jsMustCompileReject(t, b)
	if errA.Error() != errB.Error() {
		t.Errorf("报错与键的书写顺序有关: %q vs %q", errA, errB)
	}
	if !strings.Contains(errA.Error(), "format") {
		t.Errorf("应按字典序先报 format（可预期才可聚合），实得 %v", errA)
	}
	// 同一份 schema 反复编译，报错文本逐字节相同（不是只「看起来一样」）。
	// 名字与 jsMustCompileReject 内部保持一致，否则比对的是两个不同的前缀。
	for i := 0; i < 20; i++ {
		_, err := newSchemaValidator(jsSpec("js-bad", policy.BodyInspect), jsSchema(a))
		if err == nil {
			t.Fatalf("第 %d 次编译本该失败", i)
		}
		if err.Error() != errA.Error() {
			t.Fatalf("第 %d 次编译报错文本漂移: %v vs %v", i, err, errA)
		}
	}
	// 子 schema 位置要出现在报错里：一份大 schema 里只说「pattern 不合法」等于让人全文搜索。
	deep := `{"properties":{"user":{"properties":{"email":{"pattern":"("}}}}}`
	err := jsMustCompileReject(t, deep)
	if !strings.Contains(err.Error(), "properties.user") || !strings.Contains(err.Error(), "pattern") {
		t.Errorf("编译错误应指出出错位置与关键字: %v", err)
	}
	// 编译错误只带 schema 位置与关键字，不带别的东西。
	if strings.Contains(err.Error(), jsPhone) {
		t.Errorf("编译错误里出现了正文内容: %v", err)
	}
}

// ------------------------------------------------------------------ 档位与注册门

func TestJsBodyAccessTierSelectsValidationTarget(t *testing.T) {
	// metadata-only：校验的是**元数据文档**，并且一个字节都不读正文。
	// 这条同时兜住两件事：§2.9 规则 7 的「不缓存正文」快速路径，和
	// 「档位声明为 metadata-only 却能看正文」的越权 —— 后者会让档位声明失去意义。
	schema := `{"properties":{"model":{"type":"string"}},"required":["model"]}`
	meta := `{"model":"gpt-test"}`
	body := `{"model":12345}` // 正文违规：metadata-only 档根本不该看到它
	jsNoBodyTouch(t, func() {
		out, err := jsInput(t, jsSpec("js-meta", policy.BodyMetadataOnly), jsSchema(schema),
			context.Background(), NewBodyReader(pipePanicReader{}, int64(len(body))), meta)
		if err != nil {
			t.Fatalf("metadata-only 应按元数据校验通过: %v", err)
		}
		if got := fmt.Sprint(out.Rewrites); got != "[{schema:valid 1}]" {
			t.Errorf("通过标记不符: %s", got)
		}
	})
	// 元数据缺失时不能退回去读正文，也不能当成「没有内容可校验 = 通过」：
	// 后者等于「调用方少传一个字段就让校验消失」。
	_, err := jsInput(t, jsSpec("js-meta", policy.BodyMetadataOnly), jsSchema(schema),
		context.Background(), NewBufferedBody([]byte(body)), "")
	if !errors.Is(err, ErrNoBody) {
		t.Fatalf("metadata-only 但没有元数据必须报错: %v", err)
	}
	if reason, class := classify(err); reason != ReasonNoInput || class != classViolation {
		t.Errorf("归类应为 (no_input, violation)，实得 (%s, %s)", reason, class)
	}
	// 元数据本身违规 → 正常判定，与正文内容无关。
	if _, err := jsInput(t, jsSpec("js-meta", policy.BodyMetadataOnly), jsSchema(schema),
		context.Background(), nil, `{"model":1}`); !errors.Is(err, ErrSchemaViolation) {
		t.Errorf("元数据违规必须判失败: %v", err)
	}

	// inspect-body：校验的是正文，元数据被完全忽略（同一个 Input 两份内容只有一份被校验）。
	ipSpec := jsSpec("js-insp", policy.BodyInspect)
	if _, err := jsInput(t, ipSpec, jsSchema(schema), context.Background(),
		NewBufferedBody([]byte(meta)), body); err != nil {
		t.Errorf("inspect 档应按正文校验，而正文此刻是合法的: %v", err)
	}
	if _, err := jsInput(t, ipSpec, jsSchema(schema), context.Background(),
		NewBufferedBody([]byte(body)), meta); !errors.Is(err, ErrSchemaViolation) {
		t.Errorf("inspect 档必须校验正文（违规的正文不能被合法的元数据掩护过去）: %v", err)
	}

	// 链条对照：metadata-only 的链不该把请求缓冲起来（规则 7 的接线前提）。
	p := jsBuild(t, jsSpec("js-meta-chain", policy.BodyMetadataOnly), jsSchema(schema))
	src := &pipeSource{data: []byte(body)}
	req := pipeRequest(t, "js-meta-chain", NewBodyReader(src, int64(len(body))))
	req.Metadata = json.RawMessage(meta)
	res, rerr := p.RunRequest(context.Background(), req)
	if rerr != nil {
		t.Fatalf("metadata-only 链条应通过: %v", rerr)
	}
	if res.Buffered || res.BufferingNotice != "" {
		t.Errorf("metadata-only 链条不该进入缓冲形态: buffered=%v notice=%q", res.Buffered, res.BufferingNotice)
	}
	if got := src.readBytes(); got != 0 {
		t.Errorf("metadata-only 链条读走了 %d 字节正文", got)
	}
	if pipeEntry(t, res, "js-meta-chain").DeniedReads != 0 {
		t.Errorf("档位合规时 DeniedReads 必须为 0: %+v", pipeEntry(t, res, "js-meta-chain"))
	}
	// 反过来：正文违规但没被看（档位不够）—— 结论必须是通过，且审计里看得出只做了元数据校验。
	// 这条是「档位声明与真实行为一致」的取证：策略写了 metadata-only 就是只校验元数据，
	// 合规报表不能把它当成「请求体已通过 schema」。
	if res.Outcome != ReasonOK || pipeEntry(t, res, "js-meta-chain").Access != policy.BodyMetadataOnly {
		t.Errorf("元数据链结论/档位留痕不符: %+v", pipeEntry(t, res, "js-meta-chain"))
	}
}

func TestJsRegistrationRejectsMismatchedTierAndPhase(t *testing.T) {
	schema := jsSchema(`{"type":"object"}`)

	// 档位：校验器是判定型，给它 transform-body 等于允许「校验失败就顺手改写正文」，
	// 把判定与改写混进一个处理器（§2.9 规则 1 的分工）。
	if err := NewRegistry().Register(jsSpec("js-tr", policy.BodyTransform), schema); !errors.Is(err, ErrBodyAccessNotForType) {
		t.Errorf("transform-body 的 json-schema 必须注册失败: %v", err)
	}
	// 阶段：结果侧阶段没有「待校验的请求」。
	if err := NewRegistry().Register(jsSpecAt("js-resp", PhaseAfterUpstream, policy.BodyInspect), schema); !errors.Is(err, ErrPhaseNotForType) {
		t.Errorf("after-upstream 的 json-schema 必须注册失败: %v", err)
	}
	// 两个合规档位都必须能注册，否则上面的门拒得太宽。
	for _, access := range []policy.BodyAccess{policy.BodyMetadataOnly, policy.BodyInspect} {
		if err := NewRegistry().Register(jsSpec("js-ok-"+string(access), access), schema); err != nil {
			t.Errorf("%s 档位应可注册: %v", access, err)
		}
	}
	// 非法 schema 在注册期就炸（工厂在 Register 里跑一次）。
	if err := NewRegistry().Register(jsSpec("js-badschema", policy.BodyInspect), jsSchema(`{"minItems":1}`)); !errors.Is(err, ErrRegistry) {
		t.Errorf("非法 schema 必须注册失败: %v", err)
	}
}

// ------------------------------------------------------------------ 边界与失败类

func TestJsInputLimitsNonJSONAndDepth(t *testing.T) {
	// 非 JSON 正文：判定为「输入不合法」而不是「处理器故障」。
	// 两者在告警里的处置方向完全不同（前者是客户端/上游问题，后者是网关问题）。
	_, err := jsRun(t, jsSpec("js-plain", policy.BodyInspect), jsSchema(`{"type":"object"}`), "hello 世界")
	if !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("非 JSON 输入必须报 ErrInvalidJSON: %v", err)
	}
	if reason, class := classify(err); reason != ReasonInvalidInput || class != classVerdict {
		t.Errorf("归类应为 (invalid_input, verdict)，实得 (%s, %s)", reason, class)
	}
	// 空正文同样不是「没有内容可校验 = 通过」。
	if _, err := jsRun(t, jsSpec("js-empty", policy.BodyInspect), jsSchema(`{}`), ""); !errors.Is(err, ErrInvalidJSON) {
		t.Errorf("空正文必须报非法输入而不是静默通过: %v", err)
	}
	// 尾部多余内容：放过去就等于允许「正文 + 垃圾」被当成合法输入（重序列化会静默丢尾部）。
	if _, err := jsRun(t, jsSpec("js-tail", policy.BodyInspect), jsSchema(`{}`), `{"a":1} {"b":2}`); !errors.Is(err, ErrInvalidJSON) {
		t.Errorf("两个文档拼一起必须被拒: %v", err)
	}
	// 不是合法 JSON 的顶层标量（例如裸单词）与截断文档也要拒。
	for _, bad := range []string{`{"a":1`, `{"a":}`, `[1,`, `undefined`} {
		if _, err := jsRun(t, jsSpec("js-cut", policy.BodyInspect), jsSchema(`{}`), bad); !errors.Is(err, ErrInvalidJSON) {
			t.Errorf("畸形输入 %q 应被拒: %v", bad, err)
		}
	}

	// 输入大小：超限在**读正文**这一步就被拒（不解析、不校验），原因码是违规类。
	big := jsSpec("js-big", policy.BodyInspect)
	big.MaxInputBytes = 64
	if _, err := jsRun(t, big, jsSchema(`{}`), `{"v":"`+strings.Repeat("x", 200)+`"}`); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("超过 max_input_bytes 必须拒绝: %v", err)
	}
	// 正好等于上限要放行（截断式的「差不多就行」在这里是数据损坏）。
	if _, err := jsRun(t, big, jsSchema(`{"type":"object"}`), `{"v":"`+strings.Repeat("x", 64-len(`{"v":""}`))+`"}`); err != nil {
		t.Errorf("恰好等于上限的正文应被接受: %v", err)
	}

	// 深度：钉一个当前行为（不当场改）—— 校验器**不使用** MaxDocDepth。
	// 崩溃风险其实由解析器自己的嵌套上限兜住（见下），所以不当场补不是留一个可远程触发的 DoS；
	// 真正的代价是**同一条策略在链上口径不一致**：一份 200 层嵌套的正文会被 json-schema
	// 判为「校验通过」，紧接着的 pii-mask / field-replace 却在 rewriteStrings 里报
	// limit_exceeded —— 策略作者看到「校验过了但处理失败」，排查方向会被带偏。
	// 当场把深度加进 validate 会改变通过集（原来通过的文档开始被拒），属 §7 破坏性变更，
	// 且要先决定「深度算判定还是违规」，那是主线的一致性决策。
	deep := jsNest(200)
	if _, err := jsRun(t, jsSpec("js-deep", policy.BodyInspect), jsSchema(`{}`), deep); err != nil {
		t.Errorf("当前实现不限制实例深度（若已改动请同步重写本用例与缺口说明）: %v", err)
	}
	// 同一份文档在 rewriteStrings 那里是超限：两份实现的深度口径确实不一致。
	value, derr := decodeJSON([]byte(deep))
	if derr != nil {
		t.Fatalf("200 层嵌套应能被解析（解析器上限远高于此）: %v", derr)
	}
	if _, _, rerr := rewriteStrings(value, "$", 0, func(string, string) (string, bool, error) {
		return "", false, nil
	}); !errors.Is(rerr, ErrDepthTooDeep) {
		t.Errorf("对照失败：rewriteStrings 应在 %d 层上限处拒绝，实得 %v", MaxDocDepth, rerr)
	}

	// 极深文档不能把网关搞崩：解析阶段的嵌套上限是最后的兜底，报错形态仍是「非法输入」。
	if _, err := jsRun(t, jsSpec("js-crazy", policy.BodyInspect), jsSchema(`{}`), jsNest(10002)); !errors.Is(err, ErrInvalidJSON) {
		t.Errorf("超出解析器嵌套上限应报 ErrInvalidJSON（而不是 panic 或静默通过）: %v", err)
	}

	// 钉第二个当前行为（不当场改）：**schema 自身没有深度上限**。
	// 危害有限但真实：Config 是控制面/管理侧在注册期绑定的（不是请求期下发的 Spec），
	// 所以触发者是管理员而非外部客户端，代价是启动/热更新时的一次编译开销与内存。
	// 不当场加限制的理由：上限该定多少（MaxDocDepth？独立的 MaxSchemaDepth？）
	// 属于策略规范，需要与 instance 深度口径一起定。
	if _, err := newSchemaValidator(jsSpec("js-deepschema", policy.BodyInspect),
		jsSchema(jsItemsSchema(2000, `{"type":"array"}`))); err != nil {
		t.Errorf("当前实现不限 schema 深度（若已改动请同步重写本用例与缺口说明）: %v", err)
	}
	// 配套事实：深层 schema 会按 schema 深度递归 validate（实例更深的那部分不再往下比）。
	// 这条同时说明「校验成本取决于 schema 而不是实例」—— 深层实例不会被无限遍历。
	shallow := jsItemsSchema(3, `{"type":"array"}`)
	if _, err := jsRun(t, jsSpec("js-items", policy.BodyInspect), jsSchema(shallow), jsNest(50)); err != nil {
		t.Errorf("schema 比实例浅时应按 schema 深度收敛并放行: %v", err)
	}

	// ctx 取消/超时是基础设施类（唯一可被 fail_open 跳过的一类）。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, ctxErr := jsInput(t, jsSpec("js-ctx", policy.BodyInspect), jsSchema(`{}`), ctx,
		NewBufferedBody([]byte(`{}`)), "")
	if !errors.Is(ctxErr, ErrTimeout) {
		t.Fatalf("必须先查 ctx: %v", ctxErr)
	}
	if reason, class := classify(ctxErr); reason != ReasonTimeout || class != classInfrastructure {
		t.Errorf("超时应为 (processor_timeout, infrastructure)，实得 (%s, %s)", reason, class)
	}
	// 档位不许读正文、又没有元数据：报「本次调用没有输入」而不是「校验通过」。
	_, noIn := jsInput(t, jsSpecAt("js-denied", PhaseBeforeUpstream, policy.BodyMetadataOnly),
		jsSchema(`{"type":"object"}`), context.Background(), nil, "")
	if !errors.Is(noIn, ErrNoBody) {
		t.Errorf("没有元数据也没有可读档位必须报 ErrNoBody: %v", noIn)
	}
	// 反过来：正文违规但档位读不到正文时，绝不能退回去读正文（上面用 pipePanicReader 证过），
	// 这里证它连 in.Body() 都不调 —— 手搭 nil 正文也不会被绕开。
	if _, err := jsInput(t, jsSpec("js-insp-nil", policy.BodyInspect), jsSchema(`{"type":"object"}`),
		context.Background(), nil, `{"a":1}`); !errors.Is(err, ErrNoBody) {
		t.Errorf("inspect 档但没有正文必须报 ErrNoBody: %v", err)
	}
}

func TestJsFailOpenHasNoExemptionForVerdictOrViolation(t *testing.T) {
	// §2.9 规则 5 的落点：**只有基础设施类**失败可以按 fail_open 跳过。
	// 判定类（schema 不符、非 JSON）与违规类（超限、无输入）都必须无视 FailClosed 一律拒绝 ——
	// 「把跳过安全检查做成一个可配置的兜底」等于允许运营用一个布尔值关掉入口校验。
	cases := []struct {
		name   string
		spec   Spec
		schema string
		body   string
		meta   string
		want   Reason
		// skipable 标记这一类是唯一允许被 fail_open 跳过的（基础设施类）。
		skipable bool
		mut      func(*Spec)
	}{
		{name: "判定：实例违规", spec: jsSpec("js-fo-violation", policy.BodyInspect),
			schema: `{"type":"object"}`, body: `[1,2]`, want: ReasonSchemaViolation},
		{name: "判定：正文不是 JSON", spec: jsSpec("js-fo-json", policy.BodyInspect),
			schema: `{"type":"object"}`, body: "hello", want: ReasonInvalidInput},
		{name: "违规：输入超限", spec: jsSpec("js-fo-large", policy.BodyInspect),
			schema: `{"type":"object"}`, body: strings.Repeat("x", 400), want: ReasonInputTooLarge,
			mut: func(s *Spec) { s.MaxInputBytes = 64 }},
		{name: "违规：元数据缺失", spec: jsSpec("js-fo-meta", policy.BodyMetadataOnly),
			schema: `{"type":"object"}`, want: ReasonNoInput},
		{name: "判定：元数据违规", spec: jsSpec("js-fo-meta-verdict", policy.BodyMetadataOnly),
			schema: `{"type":"object"}`, meta: `[1,2]`, want: ReasonSchemaViolation},
		{name: "基础设施：ctx 取消", spec: jsSpec("js-fo-timeout", policy.BodyInspect),
			schema: `{"type":"object"}`, body: `{}`, want: ReasonTimeout, skipable: true},
	}
	for _, c := range cases {
		for _, failClosed := range []bool{true, false} {
			spec := c.spec
			spec.FailClosed = failClosed
			if c.mut != nil {
				c.mut(&spec)
			}
			p := jsBuild(t, spec, jsSchema(c.schema))
			ctx := context.Background()
			if c.skipable {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			req := pipeRequest(t, spec.Name, NewBufferedBody([]byte(c.body)))
			if c.meta != "" {
				req.Metadata = json.RawMessage(c.meta)
			}
			res, err := p.RunRequest(ctx, req)
			if c.skipable && !failClosed {
				// 逃生口只留在这里：跳过 + 原因码留痕
				// （否则「增强挂了但请求成功」在审计里与「真的处理过了」看不出区别）。
				if err != nil {
					t.Fatalf("%s：基础设施类 + fail_open 应跳过: %v", c.name, err)
				}
				if res.Outcome != ReasonFailOpenSkipped {
					t.Errorf("跳过要留结论码，实得 %s", res.Outcome)
				}
				pipeHasReason(t, res, ReasonTimeout)
				continue
			}
			if err == nil {
				t.Fatalf("%s（fail_closed=%v）本该拒绝，实际通过（结论 %s）", c.name, failClosed, res.Outcome)
			}
			if res.Outcome != c.want {
				t.Errorf("%s（fail_closed=%v）结论码 = %s，期望 %s", c.name, failClosed, res.Outcome, c.want)
			}
			// 直接证据：判定/违规类绝不能被写成 fail_open_skipped。
			for _, e := range res.Entries {
				if e.Outcome == ReasonFailOpenSkipped {
					t.Errorf("%s 被 fail_open 跳过了：%+v", c.name, e)
				}
			}
			pipeAssertAuditReasonsSane(t, res)
		}
	}

	// 审计面不许出现被校验内容：错误文本不进审计，只有原因码与量。
	// 注意 Result.Body 在被拒绝时**仍然装着原文**（它是转发通道而不是审计字段：
	// 见 finish 与 BufferingNotice —— 校验型处理器没改正文，链条就没有「脱敏后的那份」可给），
	// 所以漏检面只看审计、条目与错误文本；接线方在拒绝路径上必须丢掉 Body 而不是转发出去。
	p := jsBuild(t, jsSpec("js-fo-audit", policy.BodyInspect), jsSchema(`{"properties":{"token":{"type":"string"}}}`))
	res, err := p.RunRequest(context.Background(), pipeRequest(t, "js-fo-audit",
		NewBufferedBody([]byte(`{"token":`+jsPhone+`}`))))
	if err == nil {
		t.Fatal("违规必须拒绝")
	}
	if !strings.Contains(string(res.Body), jsPhone) {
		t.Errorf("对照失败：拒绝路径的 Result.Body 本该仍是原正文（转发通道），实得 %q", res.Body)
	}
	blob := auditJSON(res.Audit) + fmt.Sprintf("%v|%+v", res.Reasons, res.Entries) +
		fmt.Sprint(res.Rewrites) + res.BufferingNotice + err.Error()
	if strings.Contains(blob, jsPhone) {
		t.Errorf("审计面/错误文本出现被校验的内容: %s", blob)
	}
	// 但返回给调用方的错误要能定位字段（否则用户无法自修，只会反复重试）。
	if !strings.Contains(err.Error(), "$.token") {
		t.Errorf("返回给调用方的错误要能定位字段: %v", err)
	}
}
