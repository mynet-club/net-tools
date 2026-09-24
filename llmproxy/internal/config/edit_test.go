package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// 一份贴近真实的配置：providers 前后都有注释与别的配置项，
// 用来验证「写回只动 providers 段」。
const editSample = `# llmproxy 配置
server:
  host: 0.0.0.0
  port: 8787
  api_keys:
    - sk-local        # 下游凭证
  admin_token: sk-admin

routing:
  retry: 2

# 下面这段是维护信息，绝不能被写回抹掉
providers:
  - name: deepseek
    enabled: true
    base_url: https://api.deepseek.com/v1
    api_key: ${DEEPSEEK_API_KEY}
    weight: 1
    proxy: direct
    models: ["*"]

# providers 段之后、下一段之前的注释，也要活着
database:
  path: ""
  retain_days: 90

log:
  level: info
`

func providerNamed(name, base, key string) ProviderRaw {
	p := ProviderRaw{Name: name, BaseURL: base, APIKey: key}
	p.Enabled.Set = true
	p.Enabled.Value = true
	return p
}

// 段外内容必须逐字节不变 —— 这是整个设计的前提。
func TestEditProvidersKeepsEverythingOutside(t *testing.T) {
	newSrc, err := EditProviders([]byte(editSample), []ProviderRaw{
		providerNamed("dashscope", "https://dashscope.aliyuncs.com/compatible-mode/v1", "sk-new"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(newSrc)

	// 前段：一直到 providers: 这一行为止，原样
	head := editSample[:strings.Index(editSample, "providers:")]
	if !strings.HasPrefix(got, head) {
		t.Errorf("providers 之前的内容被改动了：\n--- 期望前缀 ---\n%s\n--- 实际 ---\n%s", head, got[:min(len(got), len(head)+80)])
	}
	// 后段：从 database 开始原样（含那段注释）
	tail := editSample[strings.Index(editSample, "# providers 段之后"):]
	if !strings.HasSuffix(got, tail) {
		t.Errorf("providers 之后的内容被改动了：\n期望后缀:\n%s\n实际:\n%s", tail, got)
	}
	// 关键的那句维护注释还在
	if !strings.Contains(got, "# 下面这段是维护信息，绝不能被写回抹掉") {
		t.Error("段前注释丢了")
	}
	if !strings.Contains(got, "sk-local        # 下游凭证") {
		t.Error("别处的行内注释丢了")
	}
	// 新供应商进来了，旧的没了
	if !strings.Contains(got, "dashscope") || strings.Contains(got, "deepseek") {
		t.Errorf("替换结果不对:\n%s", got)
	}
}

// 写回的结果必须仍然是一份能加载的合法配置。
func TestEditProvidersResultIsLoadable(t *testing.T) {
	newSrc, err := EditProviders([]byte(editSample), []ProviderRaw{
		providerNamed("dashscope", "https://dashscope.aliyuncs.com/compatible-mode/v1", "sk-a"),
		providerNamed("deepseek", "https://api.deepseek.com/v1", "${DEEPSEEK_API_KEY}"),
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, newSrc, 0o600); err != nil {
		t.Fatal(err)
	}
	// 用宽松通道校验：配置里写 ${ENV} 是推荐做法，环境变量没设不该算错
	cfg, err := LoadFileLenient(path)
	if err != nil {
		t.Fatalf("写回后的配置加载失败: %v\n--- 文件内容 ---\n%s", err, newSrc)
	}
	if len(cfg.Normalized) != 2 {
		t.Fatalf("应有 2 个供应商，实际 %d", len(cfg.Normalized))
	}
	if cfg.Normalized[1].APIKey != "${DEEPSEEK_API_KEY}" {
		t.Errorf("${ENV} 写法没被保住: %q", cfg.Normalized[1].APIKey)
	}
	if !cfg.Normalized[0].Models.Passthrough {
		t.Errorf("默认 models 应当是直通: %+v", cfg.Normalized[0].Models)
	}
}

// models 的两种写法都要保住形态。
func TestEditProvidersKeepsModelsShape(t *testing.T) {
	// 流式：["*"]
	a := providerNamed("p1", "https://a.example/v1", "k")
	var err error
	if a.Models, err = ModelsNode([]string{"*"}); err != nil {
		t.Fatal(err)
	}
	// 映射写法
	b := providerNamed("p2", "https://b.example/v1", "k")
	if b.Models, err = ModelsNode(map[string]string{"gpt-4o": "gpt-4o-2024-11-20"}); err != nil {
		t.Fatal(err)
	}
	out, err := EditProviders([]byte(editSample), []ProviderRaw{a, b})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	// 只要还在一行上（流式）就行 —— 引号用单还是双由 YAML 编码器决定
	if !strings.Contains(got, "models: [") {
		t.Errorf("流式写法没保住（被拆成多行了）:\n%s", got)
	}
	if !strings.Contains(got, "models: {") || !strings.Contains(got, "gpt-4o: gpt-4o-2024-11-20") {
		t.Errorf("映射写法没保住:\n%s", got)
	}
	// 长内容才退回块状
	long := map[string]string{}
	for i := 0; i < 12; i++ {
		long[fmt.Sprintf("downstream-model-%02d", i)] = fmt.Sprintf("upstream-model-%02d", i)
	}
	ln, err := ModelsNode(long)
	if err != nil {
		t.Fatal(err)
	}
	if ln.Style == yaml.FlowStyle {
		t.Error("长内容不该用流式（会拖成很长一行）")
	}

	// 而且解析出来语义一致
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFileLenient(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Normalized[0].Models.Passthrough {
		t.Error("第一个应当是直通")
	}
	if up, ok := cfg.Normalized[1].UpstreamModel("gpt-4o"); !ok || up != "gpt-4o-2024-11-20" {
		t.Errorf("第二个的映射丢了: %q %v", up, ok)
	}
}

// 幂等：再写一次结果不变（否则每次保存都会往文件里堆垃圾）。
func TestEditProvidersIsIdempotent(t *testing.T) {
	ps := []ProviderRaw{providerNamed("a", "https://a.example/v1", "k")}
	once, err := EditProviders([]byte(editSample), ps)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := EditProviders(once, ps)
	if err != nil {
		t.Fatal(err)
	}
	if string(once) != string(twice) {
		t.Errorf("不幂等：\n--- 第一次 ---\n%s\n--- 第二次 ---\n%s", once, twice)
	}
}

// providers 在文件末尾（后面没有别的配置项）。
func TestEditProvidersAtEOF(t *testing.T) {
	src := "server:\n  host: 127.0.0.1\n\nproviders:\n  - name: old\n    base_url: https://old.example/v1\n    api_key: k\n    models: [\"*\"]\n"
	out, err := EditProviders([]byte(src), []ProviderRaw{providerNamed("new", "https://new.example/v1", "k")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), "server:\n  host: 127.0.0.1\n\nproviders:\n") {
		t.Errorf("前缀被动过:\n%s", out)
	}
	if strings.Contains(string(out), "old") || !strings.Contains(string(out), "new") {
		t.Errorf("替换不对:\n%s", out)
	}
	if _, err := LoadFileLenient(writeTemp(t, out)); err != nil {
		t.Fatalf("写回后无法加载: %v", err)
	}
}

// 流式写法：providers: [] （空列表）也要能被替换掉。
func TestEditProvidersFlowStyle(t *testing.T) {
	src := "server:\n  host: 127.0.0.1\nproviders: []\ndatabase:\n  path: \"\"\n"
	out, err := EditProviders([]byte(src), []ProviderRaw{providerNamed("a", "https://a.example/v1", "k")})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if strings.Contains(got, "providers: []") {
		t.Errorf("流式空列表没被替换:\n%s", got)
	}
	if !strings.Contains(got, "providers:\n  - name: a\n") {
		t.Errorf("替换结果不对:\n%s", got)
	}
	if !strings.Contains(got, "database:\n  path: \"\"") {
		t.Errorf("后段丢了:\n%s", got)
	}
}

// 原文件没有 providers 段：追加，且不动已有内容。
func TestEditProvidersAppendWhenMissing(t *testing.T) {
	src := "server:\n  host: 127.0.0.1\n"
	out, err := EditProviders([]byte(src), []ProviderRaw{providerNamed("a", "https://a.example/v1", "k")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), src) {
		t.Errorf("追加应当保留原内容:\n%s", out)
	}
	if !strings.Contains(string(out), "providers:\n  - name: a") {
		t.Errorf("没追加成功:\n%s", out)
	}
}

func TestEditProvidersRejectsEmptyAndBadInput(t *testing.T) {
	if _, err := EditProviders([]byte(editSample), nil); err == nil {
		t.Error("空列表应当报错")
	}
	if _, err := EditProviders([]byte("server: [\n"), []ProviderRaw{providerNamed("a", "u", "k")}); err == nil {
		t.Error("原文件语法错误应当报错")
	}
	bad := providerNamed("", "https://a.example/v1", "k")
	if _, err := EditProviders([]byte(editSample), []ProviderRaw{bad}); err == nil {
		t.Error("供应商名为空应当报错")
	}
}

// 标量引号：URL 与 ${ENV} 不该被加引号（保持可读），怪名字才加。
//
// 引号与转义现在一律交给 yaml.v3，所以这里只钉住两件事：
// 常见值保持裸写（否则 config.yaml 会变得难读），以及**该加引号的一定加**。
func TestYAMLScalarQuoting(t *testing.T) {
	// 这些必须裸写：它们是 config.yaml 里最常见的值，加引号纯属噪音
	for _, val := range []string{
		"https://api.deepseek.com/v1",
		"${DEEPSEEK_API_KEY}",
		"${DEEPSEEK_API_KEY:-default}",
		"sk-not-a-real-key",
		"direct",
		"http://192.168.0.3:7890",
		"socks5://user:password@127.0.0.1:1081",
		"有中文",
		"openai-main",
	} {
		got, err := yamlScalar(val)
		if err != nil {
			t.Errorf("yamlScalar(%q) 不该报错: %v", val, err)
			continue
		}
		if got != val {
			t.Errorf("yamlScalar(%q) = %q；这个常见值应当裸写、不加引号", val, got)
		}
	}

	// 这些必须被引号包住，否则 YAML 会把它们解析成别的东西
	for _, val := range []string{
		"",        // 空
		"- 破折号开头", // 序列指示符
		"带: 冒号空格", // 映射指示符
		"结尾有空格 ",  // 尾随空格会被吃掉
		"*",       // 别名指示符
		"有 # 井号",  // 注释
		"123",     // 会被解析成整数
		"true",    // 会被解析成布尔
		"null",    // 会被解析成 null
		"1.5",     // 会被解析成浮点
	} {
		got, err := yamlScalar(val)
		if err != nil {
			t.Errorf("yamlScalar(%q) 不该报错: %v", val, err)
			continue
		}
		if got == val && val != "" {
			t.Errorf("yamlScalar(%q) 裸写了，YAML 会把它解析成别的类型", val)
		}
	}
	// 注：`quote"inside` 与 `back\slash` 在 YAML 里是合法的**裸**标量
	// （引号在中间不是指示符、反斜杠在裸标量里是字面量），所以不要求加引号 ——
	// 它们的正确性由下面的往返测试保证。
}

// 把标量交给 YAML 解析器验证：不管加没加引号，解回来都必须是同一个字符串。
func TestYAMLScalarRoundTrip(t *testing.T) {
	for _, val := range []string{
		"https://api.deepseek.com/v1", "${DEEPSEEK_API_KEY}", "sk-abc123",
		"http://192.168.0.3:7890", "带: 冒号", "- 开头", "结尾空格 ", "有 # 井号",
		"123", "true", "null", "1.5", "*", `quote"inside`, "back\\slash", "",
	} {
		got, err := yamlScalar(val)
		if err != nil {
			t.Errorf("yamlScalar(%q): %v", val, err)
			continue
		}
		src := "k: " + got + "\n"
		var m map[string]string
		if err := yaml.Unmarshal([]byte(src), &m); err != nil {
			t.Errorf("值 %q 渲染成 %q 后解析失败: %v", val, got, err)
			continue
		}
		if m["k"] != val {
			t.Errorf("往返不一致: %q → %q → %q", val, got, m["k"])
		}
	}
}

// 含换行或控制字符的值必须被**响亮拒绝**，不能被渲染出去。
//
// 两个真实危害：
//
//   - lone CR（U+000D）、U+2028、U+0085 在 YAML 里都是换行，而旧的手写规则只看 `\n`。
//     于是一个带 CR 的供应商名能逃出 providers 段、在 config.yaml 里注入一个全新的
//     顶层段（实测过可落盘的 PoC：注入 pricing 段把所有单价变成 0，配额于是永不触发）。
//   - 裸换行放进双引号标量后，YAML 的「折叠」语义会把它变成空格 ——
//     api_key 被静默改成 `sk-line1 line2`，校验通过、落盘成功、界面毫无提示，
//     之后那家供应商每个请求都 401。
func TestYAMLScalarRejectsControlCharacters(t *testing.T) {
	for _, val := range []string{
		"line1\nline2",
		"carriage\rreturn",
		"cr\r\nlf",
		"tab\there",
		"nul\x00byte",
		"u0085\u0085sep",
		"u2028\u2028sep",
		"u2029\u2029sep",
		"vertical\vtab",
		// 审阅里那个可落盘 PoC 的形状：用 CR 当换行、冒号后紧跟 CR 以避开 ": " 判断
		"openai-main\r    base_url:\r      https://evil/v1\rpricing:\r  currency:\r    |",
	} {
		if got, err := yamlScalar(val); err == nil {
			t.Errorf("%q 应当被拒绝，却渲染成了 %q", val, got)
		}
	}
}

// 端到端：带 CR 的供应商名不能逃出 providers 段。
//
// 这是上面那条单元测试的实际后果 —— 旧实现下这个载荷能通过校验并落盘，
// 在 config.yaml 里多出一个顶层 pricing 段。
func TestEditProvidersRejectsSegmentEscape(t *testing.T) {
	payload := "openai-main\r    base_url:\r      https://api.openai.com/v1\r" +
		"    api_key:\r      ${OPENAI_API_KEY}\r    models:\r      - \"*\"\r" +
		"pricing:\r  models:\r    \"*\":\r      cache_miss:\r        0\r  currency:\r    |"

	_, err := renderProviders([]ProviderRaw{{
		Name:    payload,
		BaseURL: "https://api.openai.com/v1",
		APIKey:  "${OPENAI_API_KEY}",
		Weight:  1,
	}})
	if err == nil {
		t.Fatal("带 CR 的供应商名应当被拒绝（它能逃出 providers 段注入新的顶层段）")
	}
	if !strings.Contains(err.Error(), "控制字符") {
		t.Errorf("错误信息该说清是控制字符的问题，实际：%v", err)
	}
}

func writeTemp(t *testing.T, b []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SetConfigScalar 只动指定段下的一行标量，其余字节逐字节不变。
//
// 动的是生产配置文件，所以「注释、空行、缩进、别的键一个都不能被顺手改掉」
// 是硬要求 —— 与 EditProviders 同一条底线。
func TestSetConfigScalarOnlyTouchesOneLine(t *testing.T) {
	src := `# 段前注释，必须保留
server:
  host: 127.0.0.1        # 监听地址
  port: 8787
  api_keys:
    - sk-x
  admin_token: sk-old
  block_local_upstream: true

routing: {retry: 2}
providers:
  - name: p
    enabled: true
    base_url: https://api.example.com/v1
    api_key: k
    models: ["*"]
log:
  level: info
`
	out, err := SetConfigScalar([]byte(src), "server", "admin_token", "sk-new-token")
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)

	// 新值生效
	if !strings.Contains(got, "admin_token: sk-new-token") {
		t.Errorf("新值没写进去:\n%s", got)
	}
	if strings.Contains(got, "sk-old") {
		t.Errorf("旧值仍在:\n%s", got)
	}
	// 其余内容一个字节都不能变
	for _, must := range []string{
		"# 段前注释，必须保留",
		"  host: 127.0.0.1        # 监听地址",
		"  port: 8787",
		"  api_keys:",
		"    - sk-x",
		"  block_local_upstream: true",
		"",
		"routing: {retry: 2}",
		"providers:",
		"  - name: p",
		"    base_url: https://api.example.com/v1",
		"    api_key: k",
		"    models: [\"*\"]",
		"log:",
		"  level: info",
	} {
		if must != "" && !strings.Contains(got, must) {
			t.Errorf("不该被动的内容丢了: %q\n%s", must, got)
		}
	}
	// 替换后的配置必须仍然可加载，且新值生效
	cfg, err := Parse([]byte(got))
	if err != nil {
		t.Fatalf("写回后的配置解析失败: %v\n%s", err, got)
	}
	if cfg.Server.AdminToken != "sk-new-token" {
		t.Errorf("新值未生效: %q", cfg.Server.AdminToken)
	}
}

// 行末注释要保住；行数与除目标行外的每一行都要完全一致。
func TestSetConfigScalarKeepsLineComment(t *testing.T) {
	src := "server:\n  port: 8787          # 监听端口\n  host: 127.0.0.1\n"
	out, err := SetConfigScalar([]byte(src), "server", "port", "9000")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "port: 9000          # 监听端口") {
		t.Errorf("行末注释没保住:\n%s", out)
	}
	before := strings.Split(src, "\n")
	after := strings.Split(string(out), "\n")
	if len(before) != len(after) {
		t.Fatalf("行数变了: %d → %d\n%s", len(before), len(after), out)
	}
	for i := range before {
		if i == 1 {
			continue // 目标行
		}
		if before[i] != after[i] {
			t.Errorf("第 %d 行不该变: %q → %q", i+1, before[i], after[i])
		}
	}
}

func TestSetConfigScalarErrors(t *testing.T) {
	src := "server:\n  port: 8787\n  ports: 1\n"
	cases := []struct {
		name, section, key string
	}{
		{"段不存在", "nonexistent", "port"},
		{"键不存在", "server", "admin_token"},
		{"前缀匹配但不是同一个键（ports ≠ port）", "server", "port_"},
		{"section 为空", "", "port"},
		{"key 为空", "server", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if out, err := SetConfigScalar([]byte(src), c.section, c.key, "1"); err == nil {
				t.Errorf("应当报错，却输出了 %q", out)
			}
		})
	}
}

// SetOrInsertConfigScalar：键存在就替换（与 SetConfigScalar 一致），不存在就插入一行。
//
// 需要插入是因为 `config.example.yaml` 里 `admin_token` 是被注释掉的，
// 新建的配置很可能压根没这个键。只报「键不存在」等于把「不想手改文件」又推回给用户。
func TestSetOrInsertConfigScalar(t *testing.T) {
	// 1) 键不存在 → 插在段标题下一行，其余逐字节不变
	src := "# 顶注\nserver:\n  host: 127.0.0.1   # 保留注释\n  port: 8787\n\nlog:\n  level: info\n"
	out, err := SetOrInsertConfigScalar([]byte(src), "server", "admin_token", "sk-new")
	if err != nil {
		t.Fatal(err)
	}
	want := "# 顶注\nserver:\n  admin_token: sk-new\n  host: 127.0.0.1   # 保留注释\n  port: 8787\n\nlog:\n  level: info\n"
	if string(out) != want {
		t.Errorf("插入结果不对:\ngot:\n%s\nwant:\n%s", out, want)
	}

	// 2) 键已存在 → 行为与 SetConfigScalar 一致（替换，不重复插入）
	out2, err := SetOrInsertConfigScalar(out, "server", "admin_token", "sk-second")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(out2), "admin_token:") != 1 {
		t.Errorf("不该出现第二个 admin_token:\n%s", out2)
	}
	if !strings.Contains(string(out2), "admin_token: sk-second") {
		t.Errorf("替换没生效:\n%s", out2)
	}

	// 3) 段里一个键都没有 → 用两个空格的默认缩进
	empty := "server:\n\nlog:\n  level: info\n"
	out3, err := SetOrInsertConfigScalar([]byte(empty), "server", "admin_token", "sk-3")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out3), "  admin_token: sk-3") {
		t.Errorf("空段里没插入对:\n%s", out3)
	}

	// 4) 段不存在 → 仍然报错（不给它无中生有一个段）
	if _, err := SetOrInsertConfigScalar([]byte(src), "nope", "k", "v"); err == nil {
		t.Error("段不存在时应当报错")
	}
}
