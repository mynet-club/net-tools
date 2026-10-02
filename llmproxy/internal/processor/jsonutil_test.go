package processor

// 补测试（JSON 工具集 jsonutil.go）：本文件钉住三个 JSON 类处理器共同地基的四条不变量 ——
// ① 字节守恒（数字字面量、HTML 符号、多字节文本解码再编码后逐字节不变；键序重排是实现文档承认的
// 唯一副作用，这里把它钉成唯一方向）；② 尾部多余内容判为非法（放过就是「静默丢掉尾部字节」= 数据
// 损坏，而不是清洗）；③ 非法 UTF-8 只退化成替换符，绝不让原字节溜进产出，也不牵连文档其余部分；
// ④ rewriteStrings 只访问字符串叶子（改键等于破坏协议字段名）、深度超限报错、中途失败时不交出
// 半成品文档。助手统一 ju 前缀；本文件只打工具集本身，不涉及流水线，
// 因此不重复定义 pipeline_test.go 里的任何 pipe* 助手。

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// juRoundTrip 解码再编码，返回产物字节串。字节守恒类断言全部走这条路：
// 「处理器没动正文」与「处理器动了正文」必须只差在预期的那几处，
// 而响应缓存键、内容指纹与回放摘要吃的就是这份字节。
func juRoundTrip(t *testing.T, in string) string {
	t.Helper()
	value, err := decodeJSON([]byte(in))
	if err != nil {
		t.Fatalf("decodeJSON(%q) 失败: %v", in, err)
	}
	out, err := encodeJSON(value)
	if err != nil {
		t.Fatalf("encodeJSON 失败: %v", err)
	}
	return string(out)
}

// juMustReject 断言这份输入根本不该被解码成功。
func juMustReject(t *testing.T, in string) {
	t.Helper()
	if _, err := decodeJSON([]byte(in)); err == nil {
		t.Fatalf("%q 本该被拒，却解码成功了", in)
	}
}

// juLeaf 是一次 rewriteStrings 访问到的字符串叶子（路径 + 原值）。
// 「有没有访问键名 / 数字 / 布尔 / null」这种问题只能靠访问留痕回答，
// 从产出反推会被「值恰好长得一样」的巧合骗过去。
type juLeaf struct {
	path  string
	value string
}

// juTrace 把访问记录压成排序后的可读串（map 遍历顺序随机，所以不断言次序，只断言集合）。
func juTrace(leaves []juLeaf) string {
	parts := make([]string, 0, len(leaves))
	for _, l := range leaves {
		parts = append(parts, l.path+"="+l.value)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

var errJuMapper = errors.New("ju mapper 故障")

// juRewrite 跑一次 rewriteStrings：含 SECRET 的叶子被替换成 [MASKED]，
// 值等于 failAt 的叶子让 mapper 报错。返回（产物或空串, 改动数, 访问留痕, 错误）——
// 错误路径下产物必须是空串，调用方拿到 err 就一个字节的正文都不该有。
func juRewrite(t *testing.T, in, failAt string) (string, int, []juLeaf, error) {
	t.Helper()
	value, err := decodeJSON([]byte(in))
	if err != nil {
		t.Fatalf("decodeJSON(%q) 失败: %v", in, err)
	}
	var leaves []juLeaf
	rewritten, changed, werr := rewriteStrings(value, "", 0, func(path, s string) (string, bool, error) {
		leaves = append(leaves, juLeaf{path: path, value: s})
		if failAt != "" && s == failAt {
			return "", false, errJuMapper
		}
		if !strings.Contains(s, "SECRET") {
			return s, false, nil
		}
		return strings.ReplaceAll(s, "SECRET", "[MASKED]"), true, nil
	})
	if werr != nil {
		return "", changed, leaves, werr
	}
	out, eerr := encodeJSON(rewritten)
	if eerr != nil {
		t.Fatalf("encodeJSON 失败: %v", eerr)
	}
	return string(out), changed, leaves, nil
}

// juNest 造一个 n 层嵌套的 JSON 数组文档（最深处是一个字符串叶子）。
func juNest(n int) string {
	return strings.Repeat("[", n) + `"x"` + strings.Repeat("]", n)
}

// ------------------------------------------------------------------ 字节守恒

func TestJuRoundTripPreservesNumberLiteralsAndRawText(t *testing.T) {
	// 每条 want 都等于输入（键序类用例除外）。这些形态只要有一条被悄悄改写，
	// 表现就不是「报文有点不一样」，而是缓存命中失效、内容摘要对不上，
	// 以及按字面量解析的下游（大整数、高精度小数、科学计数法）拿到另一个数值。
	cases := []struct{ name, in, want string }{
		{"指数与小数写法不归一化", `{"a":1e5,"b":1E5,"c":1.0,"d":-0,"e":0.30000000000000004}`,
			`{"a":1e5,"b":1E5,"c":1.0,"d":-0,"e":0.30000000000000004}`},
		{"超长整数不降成浮点", `{"n":123456789012345678901234567890}`, `{"n":123456789012345678901234567890}`},
		{"溢出浮点的指数原样保留", `{"n":1e309}`, `{"n":1e309}`},
		{"HTML 符号不转义", `{"s":"<a> & \"引号\""}`, `{"s":"<a> & \"引号\""}`},
		{"多字节文本不转 \\u", `{"k":"中文🙂"}`, `{"k":"中文🙂"}`},
		{"字符串内的转义复原", `{"s":"a\nb\tc"}`, `{"s":"a\nb\tc"}`},
		{"嵌套数组", `{"m":[[1,2],[3],["x"]]}`, `{"m":[[1,2],[3],["x"]]}`},
		{"顶层标量：字符串", `"just"`, `"just"`},
		{"顶层标量：数字字面量", `1e2`, `1e2`},
		{"顶层标量：null", `null`, `null`},
		{"顶层标量：布尔", `true`, `true`},
		{"空对象与空数组", `{"o":{},"a":[]}`, `{"a":[],"o":{}}`},
		// 键序重排是 encodeJSON 文档承认的副作用（Go 的 map 序列化行为）：
		// 钉成**唯一方向**，免得某天换成插入序后同义文档的摘要又对不上而没人看得出改动过。
		{"对象键按字典序重排", `{"z":1,"a":{"y":1,"b":2}}`, `{"a":{"b":2,"y":1},"z":1}`},
		{"重复键取后者", `{"a":1,"a":2}`, `{"a":2}`},
		{"首尾空白被规范化", "  \n\t{\"a\":1}  ", `{"a":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := juRoundTrip(t, tc.in); got != tc.want {
				t.Errorf("字节守恒被破坏:\n got=%s\nwant=%s", got, tc.want)
			}
		})
	}

	// 上面的守恒全靠「数字以 json.Number 形态停在树里」这一条撑着：
	// 一旦哪天换成 map[string]any 的默认解码（float64），全部断言都会以「看起来还是数字」的方式坏掉。
	value, err := decodeJSON([]byte(`{"n":1e5,"m":123456789012345678901234567890}`))
	if err != nil {
		t.Fatal(err)
	}
	doc, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("顶层解码形态不对: %T", value)
	}
	for key, want := range map[string]string{"n": "1e5", "m": "123456789012345678901234567890"} {
		num, isNumber := doc[key].(json.Number)
		if !isNumber || num.String() != want {
			t.Errorf("%s 解码成 %T，期望保留字面量 %s", key, doc[key], want)
		}
	}
}

func TestJuDecodeRejectsTrailingContentButNotTrailingWhitespace(t *testing.T) {
	// 「一个文档 + 尾巴」被放过的后果是重新序列化时尾巴被静默丢掉 —— 那是数据损坏，
	// 而且客户端完全看不出来（HTTP 状态还是 200）。
	for _, in := range []string{
		`{"a":1} {"b":2}`,      // 两个文档拼一起：第二个的结论会被当成不存在
		`{"a":1} junk`,         // 文档 + 垃圾
		`[1,2] [3]`,            // 数组后面拖数组
		`{"a":1},`,             // 多一个逗号
		`{"a":1} ]`,            // 文档 + 孤立闭括号
		``,                     // 空输入
		strings.Repeat(" ", 8), // 只有空白：没有任何文档可言
	} {
		juMustReject(t, in)
	}

	// 反向：尾部只有空白必须仍然合法。pretty-printed JSON 与 SSE 帧都以换行收尾，
	// 把「有换行」判成「有第二个文档」会让整条正常报文被当成非法输入拒掉。
	for _, in := range []string{"{\"a\":1}\n", "{\"a\":1}  \t\r\n", "[1,2] "} {
		if _, err := decodeJSON([]byte(in)); err != nil {
			t.Errorf("尾部空白不该影响判定: %q -> %v", in, err)
		}
	}
}

func TestJuInvalidUTF8DegradesToReplacementChars(t *testing.T) {
	// 非法字节来自客户端或上游，不是我们能选的。要求分两层：
	// ① 产出必须是合法 UTF-8 —— 把 0xff 原样吐回去会让浏览器/SDK 报「坏文档」，
	//    比替换符难排查得多；② 坏字节只影响它所在的那个字符串叶子，
	//    文档其余部分照常守恒（一处坏字节不该让整个请求变成「无法处理」）。
	broken := append(append([]byte(`{"s":"ab`), 0xff, 0xfe), `"}`...)
	value, err := decodeJSON(broken)
	if err != nil {
		t.Fatalf("非法 UTF-8 不该让整个文档解码失败: %v", err)
	}
	out, err := encodeJSON(value)
	if err != nil {
		t.Fatalf("重新编码失败: %v", err)
	}
	if !utf8.Valid(out) {
		t.Errorf("产出不是合法 UTF-8: %q", out)
	}
	// 命中位置确实留下了替换符，且邻近文本一个字符没丢（退化只吃掉坏字节本身）。
	if !bytes.ContainsRune(out, utf8.RuneError) || !strings.Contains(string(out), "ab") {
		t.Errorf("非法字节既没退化成替换符、或邻近文本被牵连: %q", out)
	}
	if bytes.IndexByte(out, 0xff) >= 0 || bytes.IndexByte(out, 0xfe) >= 0 {
		t.Errorf("原始非法字节溜进了产出: %q", out)
	}
	// 两个非法字节各退化为一个 U+FFFD（解码时就地替换，编码时它是合法码点，不再转义）。
	if want := `{"s":"ab` + string(rune(utf8.RuneError)) + string(rune(utf8.RuneError)) + `"}`; string(out) != want {
		t.Errorf("退化形态不符:\n got=%q\nwant=%q", out, want)
	}
	// 同一条坏文档在「合法对照」下不受牵连：邻近字段与结构照常逐字节守恒（键按字典序）。
	good := `{"s":"ab","ok":1e5}`
	if got := juRoundTrip(t, good); got != `{"ok":1e5,"s":"ab"}` {
		t.Errorf("对照文档守恒失败: %s", got)
	}
	// isJSONDocument 只看首字节，不承担合法性判定（合法性由 decodeJSON 负责）。
	if !isJSONDocument(broken) {
		t.Error("坏字节文档仍应被认作 JSON 文档（探测只看首字节）")
	}
}

// ------------------------------------------------------------------ rewriteStrings

func TestJuRewriteStringsVisitsOnlyStringLeaves(t *testing.T) {
	in := `{"content":"SECRET 一处","count":7,"flag":true,"none":null,"list":["SECRET",1,"b"],` +
		`"nested":{"deep":{"leaf":"SECRET"},"n":1.50},"keySECRET":"v","empty":{},"ea":[]}`
	got, changed, leaves, err := juRewrite(t, in, "")
	if err != nil {
		t.Fatal(err)
	}

	// 访问集合必须**恰好**是字符串叶子。键名不是叶子（改键 = 破坏协议字段名，
	// 上游与客户端一起坏）；数字/布尔/null 更不是（当字符串改写会把 7 变成 "7"，
	// 按类型解析的下游直接坏掉）。
	trace := juTrace(leaves)
	for _, must := range []string{"content=SECRET 一处", "list[0]=SECRET", "list[2]=b",
		"nested.deep.leaf=SECRET", "keySECRET=v"} {
		if !strings.Contains(trace, must) {
			t.Errorf("字符串叶子 %s 未被访问（或路径形态不对）: %s", must, trace)
		}
	}
	for _, mustNot := range []string{"count", "flag", "none", "empty", "ea", "nested.n", "list[1]"} {
		if strings.Contains(trace, mustNot+"=") {
			t.Errorf("非字符串叶子 %s 被访问了: %s", mustNot, trace)
		}
	}
	for _, l := range leaves {
		if l.value == "keySECRET" || l.value == "nested" || l.value == "content" {
			t.Errorf("键名被当成叶子值送进了 mapper: %+v", l)
		}
	}

	// 只改值、不改形态：未命中的叶子逐字节原样，数字字面量仍是那个字面量（1.50 不能变成 1.5）。
	wantBody := `{"content":"[MASKED] 一处","count":7,"ea":[],"empty":{},"flag":true,"keySECRET":"v",` +
		`"list":["[MASKED]",1,"b"],"nested":{"deep":{"leaf":"[MASKED]"},"n":1.50},"none":null}`
	if got != wantBody {
		t.Errorf("改写产物不符:\n got=%s\nwant=%s", got, wantBody)
	}
	if changed != 3 {
		t.Errorf("changed = %d，期望 3（三处命中的字符串叶子）", changed)
	}

	// 路径形态：根是数组时前缀为空串；对象段用点、数组段用下标。
	// field-replace 的规则匹配与审计路径都按这个口径写，漂一格就全错位。
	if root, _, rl, rerr := juRewrite(t, `[["SECRET"]]`, ""); rerr != nil {
		t.Fatal(rerr)
	} else if juTrace(rl) != "[0][0]=SECRET" || root != `[["[MASKED]"]]` {
		t.Errorf("嵌套数组的路径/产物不符: %s / %s", juTrace(rl), root)
	}
	if top, _, tl, terr := juRewrite(t, `"SECRET 顶层"`, ""); terr != nil {
		t.Fatal(terr)
	} else if juTrace(tl) != "=SECRET 顶层" || top != `"[MASKED] 顶层"` {
		t.Errorf("顶层字符串叶子的路径应为空串: %s / %s", juTrace(tl), top)
	}

	// 未命中时 changed=0 且产物与输入等价：上游靠这个计数决定要不要重新序列化，
	// 虚报会让毫无改动的报文白过一遍编解码（并顺带把键序重排的副作用施加上去）。
	if untouched, count, _, _ := juRewrite(t, `{"a":"无关"}`, ""); count != 0 || untouched != `{"a":"无关"}` {
		t.Errorf("无命中时 changed=%d 或产物被重写: %s", count, untouched)
	}

	// joinPath 的两个分支：根层不带前导点，否则路径匹配会多出一个空段。
	if joinPath("", "k") != "k" || joinPath("a", "b") != "a.b" {
		t.Errorf("joinPath 形态不符: %q / %q", joinPath("", "k"), joinPath("a", "b"))
	}
}

func TestJuRewriteStringsDepthLimitAndAbortedRewriteIsNotHalfApplied(t *testing.T) {
	// 深度上限防的是「递归没有边界」：一个精心构造的深层嵌套会在遍历阶段就把网关栈跑爆，
	// 那是可远程触发的崩溃。超限必须是**报错**，而不是「这一层不看了」——
	// 静默少看一层等于让脱敏漏掉深层字段。
	if _, count, _, err := juRewrite(t, juNest(MaxDocDepth), ""); err != nil || count != 0 {
		t.Fatalf("恰好 %d 层必须在限额内: %v (changed=%d)", MaxDocDepth, err, count)
	}
	out, changed, _, err := juRewrite(t, juNest(MaxDocDepth+1), "")
	if !errors.Is(err, ErrDepthTooDeep) {
		t.Fatalf("超过 %d 层必须被拒: %v", MaxDocDepth, err)
	}
	if out != "" || changed != 0 {
		t.Errorf("超限路径不得有任何产出: %q changed=%d", out, changed)
	}
	// 超限同样是违规类（不是「这条规则没匹配到」）：fail_open 不许把它当可跳过的故障，
	// 否则「拒绝深文档」退化成「深文档直通且谁都不处理」。
	if reason, class := classify(err); reason != ReasonLimitExceeded || class != classViolation {
		t.Errorf("深度超限应为 (limit_exceeded, violation)，实得 (%s, %s)", reason, class)
	}

	// 中途报错：返回值必须是 nil —— 调用方绝无半成品文档可用。
	// 用数组而不是对象定序：map 遍历顺序随机，用对象的话「改到第几个」不可断言。
	in := `["SECRET-1","SECRET-2","BOOM","SECRET-4"]`
	value, derr := decodeJSON([]byte(in))
	if derr != nil {
		t.Fatal(derr)
	}
	arr := value.([]any)
	rewritten, count, rerr := rewriteStrings(value, "", 0, func(_, s string) (string, bool, error) {
		if s == "BOOM" {
			return "", false, errJuMapper
		}
		if !strings.Contains(s, "SECRET") {
			return s, false, nil
		}
		return strings.ReplaceAll(s, "SECRET", "[MASKED]"), true, nil
	})
	if !errors.Is(rerr, errJuMapper) {
		t.Fatalf("mapper 的错误必须原样上抛（被包成别的哨兵，调用方就没法按它分流了）: %v", rerr)
	}
	if rewritten != nil || count != 0 {
		t.Errorf("失败路径带产出: %v (changed=%d)", rewritten, count)
	}
	// 这就是「半成品」的真实形态：改写是**就地**发生在已解码树上的，已走过的叶子确实变了。
	// 不当场改成 copy-on-write 的理由：所有生产调用点（pii-mask / field-replace / json-schema）
	// 在 err 分支都直接 return，绝不复用这棵树；而给递归加拷贝会让每一次正常改写都多复制整棵树。
	// 这条 hazard 真正需要的是「拿到 err 就把树丢掉」——用测试把它标出来，比悄悄加一份拷贝更稳
	// （加拷贝还会让人误以为树可以复用）。若以后新增调用点想在失败后回看树，必须先看这条断言。
	if arr[0] != "[MASKED]-1" || arr[1] != "[MASKED]-2" || arr[2] != "BOOM" || arr[3] != "SECRET-4" {
		t.Errorf("就地改写留痕与预期不符（实现若改成非就地，这条要同步改）: %v", arr)
	}
}

// ------------------------------------------------------------------ 其余小工具

func TestJuSortedCountsIsStableAndCarriesNoContent(t *testing.T) {
	// 改写元数据是审计里唯一能看出「改了什么」的地方：它必须可聚合（排序稳定，
	// 否则回放对不上账）并且只含类别与处数 —— 「脱敏了 2 处手机号」是合规信息，
	// 「脱敏了 138…」就是泄漏（§2.9 规则 6）。
	if got := sortedCounts("filter:", nil); got != nil {
		t.Errorf("空计数表应返回 nil 而不是空切片: %+v", got)
	}
	counts := map[string]int{"phone": 2, "acct": 1, "zeta": 9, "alpha": 0}
	want := "filter:acct=1,filter:alpha=0,filter:phone=2,filter:zeta=9"
	if joined := juJoinRewrites(sortedCounts("filter:", counts)); joined != want {
		t.Errorf("排序不符（回放要逐字节一致）:\n got=%s\nwant=%s", joined, want)
	}
	// 反复调用必须给出同一个串：map 遍历序一旦漏进审计，同一次处理两次回放就给出两份账。
	for i := 0; i < 32; i++ {
		if got := juJoinRewrites(sortedCounts("filter:", counts)); got != want {
			t.Fatalf("第 %d 次排序不稳定: %s", i, got)
		}
	}
	// 计数为 0 的类别也留在表里：调用方自己塞进去的，「评估过但没命中」与「这条规则不存在」
	// 在审计里是两回事，前者说明策略生效了、后者说明策略根本没装配。
	if got := sortedCounts("filter:", counts); len(got) != 4 {
		t.Errorf("条目数 = %d，期望 4: %+v", len(got), got)
	}

	// 类别名要过 kindFor 的清洗：脏名字不许把原文或换行带进审计字段。
	if k := kindFor("filter:", "phone"); k != "filter:phone" {
		t.Errorf("kindFor 正常形态不符: %q", k)
	}
	if k := kindFor("filter:", "含中文的名字"); k != "filter:" {
		t.Errorf("非 ASCII 规则名应退化成只剩前缀（绝不带原文进审计），实得 %q", k)
	}
}

// juJoinRewrites 把改写元数据压成可读串，供排序断言用。
func juJoinRewrites(in []Rewrite) string {
	parts := make([]string, 0, len(in))
	for _, r := range in {
		parts = append(parts, r.Kind+"="+strconv.Itoa(r.Count))
	}
	return strings.Join(parts, ",")
}

func TestJuRuneLenCountsCodepointsNotBytes(t *testing.T) {
	// minLength/maxLength 按码点计：按字节数的话一个中文短语会被判成超长，
	// 规则作者怎么写都拦不住；而报错信息只报长度数字，人根本看不出是按什么算的。
	for _, tc := range []struct {
		s   string
		len int
	}{
		{"", 0},
		{"abcde", 5},
		{"手机号", 3},     // 9 字节 / 3 码点
		{"🙂🙂", 2},      // 8 字节 / 2 码点
		{"e\u0301", 2}, // 组合字符：码点 2、字素 1 —— 规则作者要按码点写长度
		{"中文a🙂", 4},
	} {
		if got := runeLen(tc.s); got != tc.len {
			t.Errorf("runeLen(%q) = %d，期望 %d（字节数 %d）", tc.s, got, tc.len, len(tc.s))
		}
	}
}

func TestJuIsJSONDocumentOnlyPeeksFirstByte(t *testing.T) {
	// 这个探测的唯一用途是「要不要走 JSON 分支」：判严了会让合法报文被当纯文本处理
	// （那是另一套语义：整段文本替换 vs 按路径替换），判松了也只是多走一次真解析。
	// 所以它必须只看首个非空白字节，并且绝不声称文档合法 —— 合法性是 decodeJSON 的职责。
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{`{"a":1}`, true},
		{`[1,2]`, true},
		{"  \n\r\t {\"a\":1}", true},
		{`{只有开头像 JSON`, true},     // 畸形 JSON 放行给解析器判，不在探测层拦
		{`{"a":1} {"b":2}`, true}, // 「尾部多余内容」不由探测负责
		{``, false},
		{`   `, false},   // 空输入不是文档
		{`"字符串"`, false}, // 顶层标量：脱敏走纯文本分支
		{`123`, false},   // 裸数字不是 JSON 文档
		{`null`, false},
		{`true`, false},
		{`x{`, false}, // 首字节决定一切
	} {
		if got := isJSONDocument([]byte(tc.in)); got != tc.want {
			t.Errorf("isJSONDocument(%q) = %v，期望 %v", tc.in, got, tc.want)
		}
	}
}
