package processor

// 第二波补测试（内置脱敏处理器 pii-mask）：四种内置形态的命中与近似误伤、占位符稳定性（含 PseudonymKey
// 的跨请求语义）、§2.8/§2.9 规则 6 的「审计面零原文」不变量、多字节安全，以及 metadata-only 越权声明在
// 注册期与运行期两道闸门上都读不到正文。助手统一 pii 前缀，流水线侧复用 pipeline_test.go 的 pipe*。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// piiTestKey 是显式注入的假名子密钥（≥ 16 字节），让占位符跨请求可预期；
// 不注入密钥的用例特意走随机 salt 路径。piiPhRe 抓出占位符供稳定性断言。
var piiTestKey = []byte("0123456789abcdef0123456789abcdef")
var piiPhRe = regexp.MustCompile(`<(?:masked|pii):[a-z_]+:[0-9a-f]+>`)

// piiSpec 造一份真实的 pii-mask 声明（档位/阶段/配额由调用方按需要改）。
func piiSpec(name string, access policy.BodyAccess) Spec {
	spec := pipeSpec(name, PhaseBeforeClassify, access)
	spec.Type = TypePIIMask
	return spec
}

// piiDirect 用内置工厂直接跑一次 Process，拿到未经流水线包装的 Output ——
// 「审计零原文」必须落在处理器自己的产出上，而不是流水线复制后的副本上。
func piiDirect(t *testing.T, cfg *Config, body string) *Output {
	t.Helper()
	spec := piiSpec("pii-direct", policy.BodyTransform)
	proc, err := newPIIMask(spec, cfg)
	if err != nil {
		t.Fatalf("构造脱敏处理器失败: %v", err)
	}
	in := &Input{RequestID: "pii-direct", Phase: spec.Phase, Spec: spec,
		access: spec.BodyAccess, body: NewBufferedBody([]byte(body))}
	out, perr := proc.Process(context.Background(), in)
	if perr != nil {
		t.Fatalf("%q 脱敏失败: %v", body, perr)
	}
	return out
}

// piiChain 走完整链条（注册 + 装配 + RunRequest），审计面断言用它。
func piiChain(t *testing.T, cfg *Config, body string) (*Result, error) {
	t.Helper()
	p, _, _ := pipeBuildCfg(t, cfg, nil, piiSpec("pii-chain", policy.BodyTransform))
	return p.RunRequest(context.Background(), pipeRequest(t, "pii-chain", NewBufferedBody([]byte(body))))
}

// piiRun 跑一次并返回新正文；wantMasked 决定「必须命中」还是「必须原样不动」。
func piiRun(t *testing.T, cfg *Config, text string, wantMasked bool) string {
	t.Helper()
	out := piiDirect(t, cfg, text)
	if wantMasked && len(out.Body) == 0 {
		t.Fatalf("%q 期望被脱敏，处理器却没产出新正文", text)
	}
	if !wantMasked && len(out.Body) != 0 {
		t.Fatalf("不该命中的内容被改了: %q -> %q", text, out.Body)
	}
	return string(out.Body)
}

func piiMustMasked(t *testing.T, cfg *Config, text string) string { return piiRun(t, cfg, text, true) }

func piiMustUntouched(t *testing.T, cfg *Config, text string) { piiRun(t, cfg, text, false) }

// piiRewrite 按类别取回写计数，piiHaystack 把审计面三面（正文、元数据、计数）摊平成可搜索串。
func piiRewrite(out *Output, kind string) (int, bool) {
	for _, r := range out.Rewrites {
		if r.Kind == kind {
			return r.Count, true
		}
	}
	return 0, false
}

func piiHaystack(body []byte, rewrites []Rewrite, metadata []byte) string {
	var b strings.Builder
	b.Write(body)
	b.Write(metadata)
	for _, r := range rewrites {
		b.WriteString("|" + r.Kind)
	}
	return b.String()
}

// ------------------------------------------------------------------ 命中形态与近似误伤

func TestPiiMasksEveryBuiltinTypeAndSparesNearMisses(t *testing.T) {
	cases := []struct {
		name, text, value string // value 是命中时必被抹掉的原文；空串表示必须原样不动
		kind              string
	}{
		{"email 命中", "请发给 bob.smith+tag@corp.example.co.uk 谢谢", "bob.smith+tag@corp.example.co.uk", "email"},
		{"id_card 18 位", "身份证号 11010119900307721X 已核验", "11010119900307721X", "id_card"},
		{"id_card 15 位", "旧版证件 110101900307001 归档", "110101900307001", "id_card"},
		{"证件号与卡号同形时证件优先", "证件兼卡号 110101199003070013 备案", "110101199003070013", "id_card"},
		{"phone 命中", "回电 13800138000 即可", "13800138000", "phone"},
		{"bank_card 命中", "卡号 4111111111111111 已验证", "4111111111111111", "bank_card"},
		{"邮箱缺点分 TLD", "详见 user@localhost 与 a@b.c 两处", "", ""},
		{"证件号嵌在长编号里", "流水号 51101011990030772188 完成", "", ""},
		{"手机号首位段不合法", "编号 12800138000 归档", "", ""},
		{"卡号 Luhn 校验不过", "参考号 4111111111111112 无关", "", ""},
		{"普通结构化数字", "温度 36.5，编号 A100200300，共 12 项", "", ""},
	}
	cfg := &Config{PseudonymKey: piiTestKey}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value == "" {
				piiMustUntouched(t, cfg, tc.text) // 近似误伤：一个字都不许动
				return
			}
			got := piiMustMasked(t, cfg, tc.text)
			if strings.Contains(got, tc.value) || !strings.Contains(got, "<masked:"+tc.kind+":") {
				t.Errorf("原值未被 <%s 占位符> 替换: %q", tc.kind, got)
			}
			// 邻近文本必须逐字保留：脱敏只吃掉命中区间，误伤会打断下游 JSON。
			for _, frag := range strings.Split(tc.text, tc.value) {
				if frag != "" && !strings.Contains(got, frag) {
					t.Errorf("邻近文本被吃掉: %q -> %q", frag, got)
				}
			}
		})
	}

	// 重叠命中只许留下一条类别计数：裁决靠显式优先级而不是正则次序，否则同一输入的占位符会跟着次序漂。
	out := piiDirect(t, cfg, "证件兼卡号 110101199003070013 备案")
	if len(out.Rewrites) != 1 {
		t.Fatalf("重叠命中必须只留一条改写元数据，实得 %+v", out.Rewrites)
	}
	if count, _ := piiRewrite(out, "pii:id_card"); count != 1 {
		t.Errorf("pii:id_card 计数 = %d: %+v", count, out.Rewrites)
	}

	// PIITypes 子集：只开手机号时其余形态原样放过（漏由下一个处理器补）。
	subset := &Config{PseudonymKey: piiTestKey, PIITypes: []string{PIIPhone}}
	piiMustMasked(t, subset, "回电 13800138000 即可")
	piiMustUntouched(t, subset, "身份证号 11010119900307721X 已核验")

	// 太短的假名密钥可以被穷举反查原值（等于没脱敏）、未知类型是配置写错，两者都在构造期拒。
	for _, bad := range []*Config{{PseudonymKey: []byte("short")}, {PIITypes: []string{"ip"}}} {
		if _, err := newPIIMask(piiSpec("pii-badcfg", policy.BodyTransform), bad); !errors.Is(err, ErrConfigInvalid) {
			t.Errorf("弱密钥/未知类型必须构造期被拒: %v", err)
		}
	}
}

// ------------------------------------------------------------------ 已知覆盖边界：数值叶子

// TestPiiOnlyMasksStringLeaves 钉住一个**已知缺口**而不是缺陷：脱敏只遍历 JSON 的字符串叶子，
// 手机号/证件号写成 JSON 数字时原样放过。不当场修的理由是占位符是字符串 ——
// 一旦把 `"phone":13800138000` 换成 `"phone":"<masked:phone:..>"`，字段类型就从 number
// 漂成 string，按类型解析的下游直接坏掉；那是 §7 说的接口破坏性变更，要单独决策与升版本。
// 现在要覆盖数值形态：策略里用 field-replace 先把值规范成字符串，或要求上游按字符串传。
func TestPiiOnlyMasksStringLeaves(t *testing.T) {
	cfg := &Config{PseudonymKey: piiTestKey}
	body := `{"phone":13800138000,"id_card":110101199003070013,"text":"拨打 13800138000"}`
	out := piiDirect(t, cfg, body)
	got := string(out.Body)

	for _, raw := range []string{`"phone":13800138000`, `"id_card":110101199003070013`} {
		if !strings.Contains(got, raw) {
			t.Errorf("数值叶子不该被改动（实现只遍历字符串叶子）: %s -> %s", body, got)
		}
	}
	if !strings.Contains(got, `<masked:phone:`) {
		t.Fatalf("字符串叶子上的同一个手机号必须被脱敏: %s", got)
	}
	if count, _ := piiRewrite(out, "pii:phone"); count != 1 {
		t.Errorf("pii:phone 计数 = %d，只有字符串那一处算命中: %+v", count, out.Rewrites)
	}
	// 数字字面量逐字节存活：脱敏不能顺手把 1e5 之类重写成另一种写法（缓存与回放摘要吃这个）。
	if strings.Contains(got, "1.3800138e+10") {
		t.Errorf("数字字面量被重写了: %s", got)
	}
}

// ------------------------------------------------------------------ 占位稳定性

func TestPiiPlaceholderStabilityFollowsPseudonymKey(t *testing.T) {
	cfg := &Config{PseudonymKey: piiTestKey}
	body := `{"a":"13800138000","b":"13800138000","c":"拨打13800138000"}`

	// 同一次请求内：同一个值必须同一个占位符，且三处都算进计数。
	out := piiDirect(t, cfg, body)
	phones := piiPhRe.FindAllString(string(out.Body), -1)
	if len(phones) != 3 || phones[0] != phones[1] || phones[1] != phones[2] {
		t.Fatalf("三处同一个手机号必须同码同计数，实得 %v", phones)
	}
	if count, ok := piiRewrite(out, "pii:phone"); !ok || count != 3 {
		t.Errorf("pii:phone 计数应为 3，实得 %+v", out.Rewrites)
	}

	// 注入了密钥：跨请求逐字节稳定（同一组织内的假名映射才谈得上连贯）。
	if second := piiMustMasked(t, cfg, body); second != string(out.Body) {
		t.Errorf("同一 PseudonymKey 下两次调用必须逐字节相同:\n%s\n%s", out.Body, second)
	}
	// 没注入密钥：salt 每次随机，跨请求必须不同；跨请求同码等于建了一张可离线穷举的字典。
	unkeyed := []string{piiMustMasked(t, &Config{}, body), piiMustMasked(t, &Config{}, body)}
	if unkeyed[0] == unkeyed[1] || strings.Contains(unkeyed[0], "13800138000") || strings.Contains(unkeyed[1], "13800138000") {
		t.Errorf("随机 salt 下两次结果不该相同、更不许留原文: %s / %s", unkeyed[0], unkeyed[1])
	}
	// 类型与原值一起进摘要：不同原值不许共用占位符。
	if a, b := piiMustMasked(t, cfg, "13800138000"), piiMustMasked(t, cfg, "4111111111111111"); a == b {
		t.Errorf("不同原值却有相同占位符: %s", a)
	}
}

// ------------------------------------------------------------------ 审计零原文

func TestPiiAuditTrailCarriesNoOriginalValues(t *testing.T) {
	// 「王小明」是文档声明的未覆盖形态（姓名需要分词，误伤风险高），留在正文里是预期行为，
	// 所以只把四种受支持形态列入「不得出现在审计面」的清单。
	originals := []string{"alice.zhang@example.com", "11010119900307721X", "13800138000", "4111111111111111"}
	body := `{"user":{"name":"王小明","email":"alice.zhang@example.com","id":"11010119900307721X"},` +
		`"messages":[{"content":"拨打 13800138000 或刷卡 4111111111111111"}],"meta":{"seq":42}}`
	assertNoLeak := func(t *testing.T, where, haystack string) {
		t.Helper()
		for _, value := range originals {
			if strings.Contains(haystack, value) {
				t.Errorf("%s 里出现原值 %q：脱敏把刚抹掉的东西又写进了审计", where, value)
			}
		}
	}

	// 处理器自己的产出：Body / Metadata / Rewrites 三面都要查。
	cfg := &Config{PseudonymKey: piiTestKey}
	out := piiDirect(t, cfg, body)
	assertNoLeak(t, "Output", piiHaystack(out.Body, out.Rewrites, out.Metadata))
	if !strings.Contains(string(out.Body), "<masked:") {
		t.Fatalf("正文里没有占位符，脱敏其实没发生: %s", out.Body)
	}

	// 流水线与审计记录：合并后的改写元数据、原因链、条目、整条审计序列化同样不许带原文。
	res, err := piiChain(t, cfg, body)
	if err != nil {
		t.Fatalf("合规链条不该失败: %v", err)
	}
	auditHay := auditJSON(res.Audit) + "|" + string(res.Metadata) + fmt.Sprintf("|%v", res.Reasons)
	assertNoLeak(t, "审计面", piiHaystack(res.Body, res.Rewrites, []byte(auditHay)))

	// 结构必须仍是合法 JSON，且非敏感部分原样保留（下游缓存与解析靠这个）。
	var doc map[string]any
	if derr := json.Unmarshal(res.Body, &doc); derr != nil {
		t.Fatalf("脱敏后的正文不是合法 JSON: %v", derr)
	}
	if !strings.Contains(string(res.Body), "王小明") || !strings.Contains(string(res.Body), `"seq":42`) {
		t.Errorf("非命中内容被改动: %s", res.Body)
	}
	if entry := pipeEntry(t, res, "pii-chain"); entry.OutputBytes <= 0 || !strings.HasPrefix(entry.OutputHash, "sha256:") {
		t.Errorf("审计里只该有量与指纹: %+v", entry)
	}
}

// ------------------------------------------------------------------ 多字节安全

func TestPiiMaskKeepsUtf8AndRunesIntact(t *testing.T) {
	cfg := &Config{PseudonymKey: piiTestKey}

	// 纯文本：中文、书名号、emoji 逐字存活，占位符只吃掉 ASCII 数字段。
	got := piiMustMasked(t, cfg, "客户「王先生」来电 13800138000 请在 2026 年回拨，备注：🙂🎉")
	if !utf8.ValidString(got) || strings.ContainsRune(got, utf8.RuneError) {
		t.Fatalf("脱敏产出非法 UTF-8 或劈开了码点: %q", got)
	}
	for _, frag := range []string{"客户「王先生」来电 ", " 请在 2026 年回拨，备注：🙂🎉"} {
		if !strings.Contains(got, frag) {
			t.Errorf("多字节邻近文本被截坏: 缺 %q，实得 %q", frag, got)
		}
	}

	// JSON 文档：多字节键与值一起走，重新序列化后仍是合法 UTF-8 的 JSON。
	out := piiDirect(t, cfg, `{"提示词":"我的手机号是13800138000","表情":"🙂🙂","邮箱":"a@b.co"}`)
	if !utf8.Valid(out.Body) {
		t.Fatalf("JSON 分支产出非法 UTF-8: %q", out.Body)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Body, &doc); err != nil {
		t.Fatalf("重新序列化失败: %v (%s)", err, out.Body)
	}
	if doc["表情"] != "🙂🙂" || !strings.HasPrefix(doc["提示词"].(string), "我的手机号是<masked:phone:") {
		t.Errorf("中文字段被改动或命中位置不对: %s", out.Body)
	}

	// 边界：区间端点只按 ASCII 数字判定，汉字与全角数字都不构成数字邻接。
	piiMustMasked(t, cfg, "手机号13800138000已确认")
	piiMustUntouched(t, cfg, "１３８００１３８０００")
}

// ------------------------------------------------------------------ 档位越权

func TestPiiMetadataOnlyCannotReadBodyEvenWhenFailOpen(t *testing.T) {
	// 两道闸门都要拦：注册期按类型与档位的一致性拒装配，运行期按档位拒读正文，
	// 且 FailClosed=false 对违规类失败没有豁免权（否则「跳过安全检查」就成了配置项）。
	spec := piiSpec("pii-meta", policy.BodyMetadataOnly)
	spec.FailClosed = false
	reg := NewRegistry()
	if err := reg.Register(spec, nil); !errors.Is(err, ErrBodyAccessNotForType) {
		t.Fatalf("metadata-only 的 pii-mask 必须注册失败: %v", err)
	}

	proc, err := newPIIMask(spec, &Config{PseudonymKey: piiTestKey})
	if err != nil {
		t.Fatal(err)
	}
	p := &Pipeline{stages: []stage{{spec: spec, proc: proc}}, clock: func() time.Time { return pipeBaseNow }}
	res, rerr := p.RunRequest(context.Background(), pipeRequest(t, "pii-meta-1", NewBodyReader(pipePanicReader{}, 4096)))
	if rerr == nil || !errors.Is(rerr, ErrBodyAccessDenied) {
		t.Fatalf("metadata-only 的脱敏必须被硬拒（即使 FailClosed=false）: %v", rerr)
	}
	if reason, class := classify(rerr); reason != ReasonBodyAccessDenied || class != classViolation {
		t.Errorf("归类应为 (body_access_denied, violation)，实得 (%s, %s)", reason, class)
	}
	if res.Outcome != ReasonBodyAccessDenied || len(res.Reasons) != 1 {
		t.Errorf("结论码与原因链不对: %s / %v（fail_open 不得冲掉违规）", res.Outcome, res.Reasons)
	}
	if res.Buffered || res.Body != nil {
		t.Error("被拒的链不得进入缓冲形态")
	}
	if entry := pipeEntry(t, res, "pii-meta"); entry.DeniedReads != 1 {
		t.Errorf("DeniedReads = %d，被挡住的读正文尝试必须留痕", entry.DeniedReads)
	}
}
