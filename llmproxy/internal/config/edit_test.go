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
func TestYAMLScalarQuoting(t *testing.T) {
	cases := map[string]bool{ // 值 → 是否应当被引号包住
		"https://api.deepseek.com/v1": true, // 含 ": " 才算需要引号，这里不含 → 不加
		"${DEEPSEEK_API_KEY}":         true,
		"sk-not-a-real-key":           true,
		"direct":                      true,
		"http://192.168.0.3:7890":     true,
		"有中文":                         true,
		"- 破折号开头":                     false,
		"带: 冒号空格":                     false,
		"结尾有空格 ":                      false,
	}
	for val, wantPlain := range cases {
		got := yamlScalar(val)
		plain := got == val
		if plain != wantPlain {
			t.Errorf("yamlScalar(%q) = %q；期望%s引号", val, got, map[bool]string{true: "不加", false: "加"}[wantPlain])
		}
	}
}

// 把标量交给 YAML 解析器验证：加了引号的必须还是同一个字符串。
func TestYAMLScalarRoundTrip(t *testing.T) {
	for _, val := range []string{
		"https://api.deepseek.com/v1", "${DEEPSEEK_API_KEY}", "sk-abc123",
		"http://192.168.0.3:7890", "带: 冒号", "- 开头", "结尾空格 ", "有 # 井号",
	} {
		src := "k: " + yamlScalar(val) + "\n"
		var m map[string]string
		if err := yaml.Unmarshal([]byte(src), &m); err != nil {
			t.Errorf("值 %q 渲染成 %q 后解析失败: %v", val, yamlScalar(val), err)
			continue
		}
		if m["k"] != val {
			t.Errorf("往返不一致: %q → %q → %q", val, yamlScalar(val), m["k"])
		}
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
