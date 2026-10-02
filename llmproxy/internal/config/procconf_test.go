package config

// 处理器与知识源声明表的加载校验与编辑层测试（§3.H）。
//
// 三条主线：
//  1. 校验判据来自领域包本身（processor.Spec.Validate / knowledge 的端点与库 ID 规则），
//     所以这里的断言写的是「哪条规则拒的」而不是「配置层自己认不认」；
//  2. 必填项没有隐含默认：body_access / fail_closed / scope 留空必须报错；
//  3. 编辑层守恒：段外字节与注释原样、Raw→Edit→Raw 值等价、未知键即拒、
//     编辑基线本身也要过领域校验（手改坏的一条不能原样回到界面上再写回磁盘）。

import (
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/processor"
)

// procProvider 是一段合法的供应商配置。带上 max_data_level 是为了让同一份正文
// 在 legacy 与 enforce 下都能加载 —— 否则「切到 enforce」这件事会先炸在供应商上，
// 而不是炸在本文件要测的那两段声明上。
const procProvider = "providers:\n" +
	"  - name: p1\n" +
	"    base_url: https://a.example/v1\n" +
	"    api_key: sk-test\n" +
	"    max_data_level: internal\n" +
	"    models: [\"*\"]\n"

// procYAML 给一份最小可用的配置（带注释，用来验证段外内容不被抹掉）。
func procYAML(body string) string {
	return "# 顶部维护注释：这一行必须活过任何一次段替换\n" +
		"server:\n  port: 18787   # 行内注释也要留着\n" + procProvider + body +
		"\nrouting:\n  retry: 2\n"
}

// loadSrc 走正式加载通道（含 normalize）—— 校验发生在加载期，
// 只调 normalize 会漏掉「这一段在整份配置里是不是还成立」。
func loadSrc(t *testing.T, src string) (*Config, error) {
	t.Helper()
	return parseWithOpts([]byte(src), LoadOptions{})
}

// policyBlock 是一份自洽的 3.0 接线块，用来切换 mode 看声明的生不生效。
func policyBlock(mode string) string {
	return "config_schema_version: 3\npolicy:\n  mode: " + mode +
		"\n  active_bundle: b1\n  data_level: internal\n" +
		"  bundles:\n    - id: b1\n      version: 1\n      scope: organization:university\n"
}

func goodProcessor(name string) ProcessorDef {
	yes := true
	return ProcessorDef{
		Name: name, Type: processor.TypePIIMask, Phase: "before-upstream",
		Scope: "organization:university", TimeoutMs: 800,
		MaxInputBytes: 1 << 20, MaxOutputBytes: 2 << 20,
		FailClosed: &yes, BodyAccess: "transform-body", Version: "1",
	}
}

// procItemText 手写一条声明正文。刻意不走 EditProcessors：它写之前就会查重，
// 而有些用例要测的正是「磁盘上已经躺着一条坏声明」时读侧与加载侧的反应。
func procItemText(name, version, phase string) string {
	return "    - name: " + name + "\n      type: pii-mask\n      phase: " + phase + "\n" +
		"      scope: \"*\"\n      version: \"" + version + "\"\n" +
		"      body_access: transform-body\n      fail_closed: true\n" +
		"      timeout_ms: 800\n      max_input_bytes: 4096\n      max_output_bytes: 8192\n"
}

// ── 加载校验 ───────────────────────────────────────────────

func TestProcessorLoadDelegatesToDomainSpec(t *testing.T) {
	cfg, err := loadSrc(t, procYAML(
		"processors:\n"+
			"  - name: pii-cn\n    type: pii-mask\n    phase: before-upstream\n"+
			"    scope: organization:university\n    version: \"1\"\n"+
			"    body_access: transform-body\n    fail_closed: true\n"+
			"    timeout_ms: 800\n    max_input_bytes: 1048576\n    max_output_bytes: 2097152\n"))
	if err != nil {
		t.Fatalf("一条自洽的声明不该加载失败: %v", err)
	}
	specs := cfg.ProcessorSpecsView()
	if len(specs) != 1 {
		t.Fatalf("应该有 1 条声明: %+v", specs)
	}
	got := specs[0]
	if got.Name != "pii-cn" || got.Phase != processor.PhaseBeforeUpstream ||
		got.Timeout != 800*time.Millisecond || got.MaxInputBytes != 1<<20 ||
		!got.FailClosed || got.Scope != "organization:university" {
		t.Errorf("声明还原不符: %+v", got)
	}
	// nil 接收者也要能问（legacy 部署根本没有派生值）
	var none *Config
	if none.ProcessorSpecsView() != nil {
		t.Error("空配置不该返回非 nil 声明集")
	}
	if none.KnowledgeSourcesView() != nil {
		t.Error("空配置不该返回非 nil 知识源集")
	}
}

// TestProcessorUnknownKeyRejectedAtLoad 保证 KnownFields(true) 那条总闸
// 对新增的两段同样有效：写了不认识的键就是错，不是忽略。
func TestProcessorUnknownKeyRejectedAtLoad(t *testing.T) {
	src := procYAML("processors:\n" + procItemText("p", "1", "before-route") + "      max_retries: 3\n")
	if _, err := loadSrc(t, src); err == nil {
		t.Fatal("未知键必须让加载失败（忽略它等于允许一条线上不存在的开关）")
	} else if !strings.Contains(err.Error(), "max_retries") {
		t.Errorf("错误该指认未知键: %v", err)
	}
}

func TestProcessorRequiredFieldsHaveNoDefaults(t *testing.T) {
	for _, tc := range []struct{ why, key string }{
		{"档位不能缺省", "body_access"},
		{"失败策略不能缺省", "fail_closed"},
		{"范围不能缺省", "scope"},
	} {
		body := "processors:\n  - name: p\n    type: pii-mask\n    phase: before-upstream\n" +
			"    scope: \"*\"\n    version: \"1\"\n    body_access: transform-body\n" +
			"    fail_closed: true\n    timeout_ms: 500\n" +
			"    max_input_bytes: 4096\n    max_output_bytes: 8192\n"
		switch tc.key {
		case "body_access":
			body = strings.Replace(body, "    body_access: transform-body\n", "", 1)
		case "fail_closed":
			body = strings.Replace(body, "    fail_closed: true\n", "", 1)
		case "scope":
			body = strings.Replace(body, "    scope: \"*\"\n", "    scope: \"\"\n", 1)
		}
		_, err := loadSrc(t, procYAML(body))
		if err == nil {
			t.Errorf("%s：缺了 %s 竟然加载通过", tc.why, tc.key)
			continue
		}
		if !strings.Contains(err.Error(), tc.key) {
			t.Errorf("%s 的错误应该指认 %s，实际: %v", tc.why, tc.key, err)
		}
		if !strings.Contains(err.Error(), "processors[0]") {
			t.Errorf("错误该指认是第几条（一段里十几条声明时这是唯一的定位信息）: %v", err)
		}
	}
}

func TestProcessorDomainRulesReject(t *testing.T) {
	cases := []struct {
		why    string
		mutate func(*ProcessorDef)
		want   string
	}{
		{"阶段是闭集", func(d *ProcessorDef) { d.Phase = "before-upstram" }, "未知的处理阶段"},
		{"阶段不能缺省", func(d *ProcessorDef) { d.Phase = "" }, "未知的处理阶段"},
		{"档位与类型要一致", func(d *ProcessorDef) { d.BodyAccess = "metadata-only" }, "transform-body"},
		{"请求侧类型不能跑在 audit", func(d *ProcessorDef) { d.Phase = "audit" }, "请求侧阶段"},
		{"超时禁止 0 = 不限", func(d *ProcessorDef) { d.TimeoutMs = 0 }, "timeout_ms"},
		{"超时有绝对上限", func(d *ProcessorDef) { d.TimeoutMs = 999999 }, "timeout"},
		{"输入上限有绝对上限", func(d *ProcessorDef) { d.MaxInputBytes = 1 << 40 }, "max_input_bytes"},
		{"输入上限不能为 0", func(d *ProcessorDef) { d.MaxInputBytes = 0 }, "max_input_bytes"},
		{"输出上限相对输入不能过小", func(d *ProcessorDef) { d.MaxOutputBytes = 1024 }, "相对"},
		{"版本必填", func(d *ProcessorDef) { d.Version = "" }, "version 缺失"},
		{"sidecar 必须枚举出网目标", func(d *ProcessorDef) { d.Type = processor.TypeSidecar }, "allowed_endpoints"},
		{"原文出网必须有白名单", func(d *ProcessorDef) {
			d.Type = processor.TypeSidecar
			d.AllowRawBody = true
			d.BodyAccess = "inspect-body"
		}, "allowed_endpoints"},
		{"白名单不能含通配", func(d *ProcessorDef) {
			d.Type = processor.TypeSidecar
			d.BodyAccess = "inspect-body"
			d.AllowedEndpoints = []string{"https://*.internal/v1"}
		}, "通配"},
		{"范围要写成选择器", func(d *ProcessorDef) { d.Scope = "university" }, "scope"},
		{"名字不是标识符", func(d *ProcessorDef) { d.Name = "有 空格" }, "name"},
	}
	for _, tc := range cases {
		def := goodProcessor("pii-cn")
		tc.mutate(&def)
		_, err := def.Spec()
		if err == nil {
			t.Errorf("%s：本该报错", tc.why)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s 的错误该含 %q，实际: %v", tc.why, tc.want, err)
		}
	}
}

func TestProcessorCustomTypeWarnsNotFails(t *testing.T) {
	def := goodProcessor("org-rewrite")
	def.Type = "org-rewrite" // 部署在注册期 RegisterType 注入的自定义类型
	cfg, err := loadSrc(t, procYAML(renderOneProcessor(t, []ProcessorDef{def})))
	if err != nil {
		t.Fatalf("自定义类型不该被配置层判死（类型集合刻意不封闭）: %v", err)
	}
	if len(cfg.Warnings) == 0 {
		t.Fatal("自定义类型必须有告警：拼错一个字母的内置类型会一路过到装配期")
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "|"), "org-rewrite") {
		t.Errorf("告警该指认类型名: %q", cfg.Warnings)
	}
	// 内置类型必须能加载且没有这条告警
	cfg2, err := loadSrc(t, procYAML(renderOneProcessor(t, []ProcessorDef{goodProcessor("pii-cn")})))
	if err != nil {
		t.Fatalf("内置类型加载失败: %v", err)
	}
	for _, w := range cfg2.Warnings {
		if strings.Contains(w, "不在内置类型里") {
			t.Errorf("内置类型不该有不认识类型的告警: %q", w)
		}
	}
}

func TestProcessorDuplicateNameRejected(t *testing.T) {
	body := "processors:\n" + procItemText("pii-cn", "1", "before-route") + procItemText("pii-cn", "2", "before-upstream")
	_, err := loadSrc(t, procYAML(body))
	if err == nil {
		t.Fatal("同名处理器必须报错（名字是注册表的键）")
	}
	if !strings.Contains(err.Error(), "出现多次") {
		t.Errorf("错误该指认重复: %v", err)
	}
}

// TestProcessorSpecsSortedByName 固定派生视图的顺序：装配期按名字挂处理器，
// 顺序如果跟着声明写法走，两份语义相同的配置会产出两份不同的运行形态。
func TestProcessorSpecsSortedByName(t *testing.T) {
	b := goodProcessor("zeta")
	a := goodProcessor("alpha")
	cfg, err := loadSrc(t, procYAML(renderOneProcessor(t, []ProcessorDef{b, a})))
	if err != nil {
		t.Fatal(err)
	}
	specs := cfg.ProcessorSpecsView()
	if len(specs) != 2 || specs[0].Name != "alpha" || specs[1].Name != "zeta" {
		t.Errorf("派生视图应按名字排序: %+v", specs)
	}
}

func TestProcessorInactiveUnlessEnforce(t *testing.T) {
	body := procYAML(renderOneProcessor(t, []ProcessorDef{goodProcessor("pii-cn")}) +
		"knowledge_sources:\n  - name: campus-rag\n    endpoint: https://rag.internal/retrieve\n" +
		"    knowledge_bases: [campus-policy]\n    timeout_ms: 1500\n    max_response_bytes: 1048576\n")

	for _, mode := range []string{"legacy", "shadow"} {
		cfg, err := loadSrc(t, body+policyBlock(mode))
		if err != nil {
			t.Fatalf("%s 下声明处理器不该拦住加载: %v", mode, err)
		}
		joined := strings.Join(cfg.Warnings, "|")
		if !strings.Contains(joined, "policy.mode="+mode) {
			t.Errorf("%s 下必须警告「声明不会生效」: %q", mode, cfg.Warnings)
		}
		// 两段都要点出来：只报处理器会让人以为知识源是另一回事
		if !strings.Contains(joined, "1 个处理器声明") || !strings.Contains(joined, "1 个知识源声明") {
			t.Errorf("%s 下告警该同时点数两段: %q", mode, cfg.Warnings)
		}
	}

	cfg, err := loadSrc(t, body+policyBlock("enforce"))
	if err != nil {
		t.Fatalf("enforce 下加载失败: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "这些声明现在不会生效") {
			t.Errorf("enforce 下不该有不生效告警: %q", w)
		}
	}
	if len(cfg.ProcessorSpecsView()) != 1 || len(cfg.KnowledgeSourcesView()) != 1 {
		t.Errorf("enforce 下两段声明都该在视图里: %v %v", cfg.ProcessorSpecsView(), cfg.KnowledgeSourcesView())
	}
}

// ── 知识源 ─────────────────────────────────────────────────

func goodSource(name, endpoint string, kbs ...string) KnowledgeSourceDef {
	return KnowledgeSourceDef{Name: name, Endpoint: endpoint, KnowledgeBases: kbs,
		TimeoutMs: 1500, MaxResponseBytes: 1 << 20}
}

func TestKnowledgeSourceValidation(t *testing.T) {
	ok := []KnowledgeSourceDef{goodSource("campus-rag", "https://rag.internal/retrieve", "campus-policy")}
	if err := (&Config{KnowledgeSources: ok}).normalizeKnowledgeSources(); err != nil {
		t.Fatalf("一条自洽的知识源声明不该报错: %v", err)
	}

	cases := []struct {
		why    string
		mutate func(*KnowledgeSourceDef)
		want   string
	}{
		{"端点禁凭证", func(s *KnowledgeSourceDef) { s.Endpoint = "https://u:p@rag.internal/retrieve" }, "凭证"},
		{"端点禁查询串", func(s *KnowledgeSourceDef) { s.Endpoint = "https://rag.internal/r?a=1" }, "查询串"},
		{"端点禁 fragment", func(s *KnowledgeSourceDef) { s.Endpoint = "https://rag.internal/r#x" }, "fragment"},
		{"端点必填", func(s *KnowledgeSourceDef) { s.Endpoint = "" }, "不能为空"},
		{"端点只允许 http(s)", func(s *KnowledgeSourceDef) { s.Endpoint = "grpc://rag.internal:9000" }, "http/https"},
		{"端点要有主机名", func(s *KnowledgeSourceDef) { s.Endpoint = "https://" }, "主机名"},
		{"不服务任何库就是死配置", func(s *KnowledgeSourceDef) { s.KnowledgeBases = nil }, "不能为空"},
		{"库 ID 要过委托协议那关", func(s *KnowledgeSourceDef) { s.KnowledgeBases = []string{"bad id"} }, "知识库 ID"},
		{"超时必须为正", func(s *KnowledgeSourceDef) { s.TimeoutMs = 0 }, "timeout_ms"},
		{"超时有上限", func(s *KnowledgeSourceDef) { s.TimeoutMs = 60000 }, "上限"},
		{"响应体积必须为正", func(s *KnowledgeSourceDef) { s.MaxResponseBytes = 0 }, "max_response_bytes"},
		{"名字不能含空白", func(s *KnowledgeSourceDef) { s.Name = "campus rag" }, "name"},
		{"名字必填", func(s *KnowledgeSourceDef) { s.Name = "  " }, "name"},
		{"名字不能有路径分隔符", func(s *KnowledgeSourceDef) { s.Name = "a/b" }, "name"},
	}
	for _, tc := range cases {
		list := []KnowledgeSourceDef{goodSource("campus-rag", "https://rag.internal/retrieve", "campus-policy")}
		tc.mutate(&list[0])
		err := (&Config{KnowledgeSources: list}).normalizeKnowledgeSources()
		if err == nil {
			t.Errorf("%s：本该报错", tc.why)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s 的错误该含 %q，实际: %v", tc.why, tc.want, err)
		}
		if !strings.Contains(err.Error(), "campus-rag") && !strings.Contains(err.Error(), "name") {
			t.Errorf("%s 的错误该指认是哪一条: %v", tc.why, err)
		}
	}
}

func TestKnowledgeBaseCannotBeServedByTwoSources(t *testing.T) {
	list := []KnowledgeSourceDef{
		goodSource("a", "https://a.internal/retrieve", "shared-kb"),
		goodSource("b", "https://b.internal/retrieve", "shared-kb", "own-kb"),
	}
	err := (&Config{KnowledgeSources: list}).normalizeKnowledgeSources()
	if err == nil {
		t.Fatal("同一个库被两个源声明必须报错")
	}
	if !strings.Contains(err.Error(), "shared-kb") || !strings.Contains(err.Error(), "同时被") {
		t.Errorf("错误该指认冲突的库与两个源: %v", err)
	}
}

func TestKnowledgeDuplicateSourceNameRejected(t *testing.T) {
	list := []KnowledgeSourceDef{
		goodSource("dup", "https://a.internal/retrieve", "kb-a"),
		goodSource("dup", "https://b.internal/retrieve", "kb-b"),
	}
	if err := (&Config{KnowledgeSources: list}).normalizeKnowledgeSources(); err == nil ||
		!strings.Contains(err.Error(), "name=dup") {
		t.Fatalf("同名知识源必须报错（审计里分不清是哪个入口）: %v", err)
	}
}

// TestKnowledgeSourceLoadThroughConfig 端到端确认这一段在整份配置里也成立
// （normalizeKnowledgeSources 单测过不了 KnownFields 与 lint 那两关）。
func TestKnowledgeSourceLoadThroughConfig(t *testing.T) {
	src := procYAML("knowledge_sources:\n" +
		"  - name: campus-rag\n    endpoint: https://rag.internal/retrieve\n" +
		"    knowledge_bases:\n      - campus-policy\n      - course-outline\n" +
		"    timeout_ms: 2000\n    max_response_bytes: 524288\n")
	cfg, err := loadSrc(t, src)
	if err != nil {
		t.Fatalf("自洽的知识源声明不该加载失败: %v", err)
	}
	list := cfg.KnowledgeSourcesView()
	if len(list) != 1 || len(list[0].KnowledgeBases) != 2 || list[0].TimeoutMs != 2000 {
		t.Fatalf("知识源视图不符: %+v", list)
	}
}

// ── 编辑层 ─────────────────────────────────────────────────

func renderOneProcessor(t *testing.T, list []ProcessorDef) string {
	t.Helper()
	out, err := EditProcessors([]byte("processors: []\n"), list)
	if err != nil {
		t.Fatalf("渲染 processors 失败: %v", err)
	}
	return string(out)
}

func TestEditProcessorsKeepsBytesOutsideSection(t *testing.T) {
	src := []byte(procYAML("processors:\n" + procItemText("old", "1", "before-route")))
	out, err := EditProcessors(src, []ProcessorDef{goodProcessor("pii-cn")})
	if err != nil {
		t.Fatalf("写回失败: %v", err)
	}
	text := string(out)
	for _, want := range []string{"顶部维护注释", "port: 18787", "行内注释也要留着", "name: p1", "routing:"} {
		if !strings.Contains(text, want) {
			t.Errorf("段外内容 %q 被改掉了:\n%s", want, text)
		}
	}
	if strings.Contains(text, "name: old") {
		t.Errorf("旧正文没被替换干净:\n%s", text)
	}
}

func TestProcessorsRawEditRoundTrip(t *testing.T) {
	list := []ProcessorDef{
		goodProcessor("pii-cn"),
		func() ProcessorDef {
			d := goodProcessor("sidecar-1")
			d.Type = processor.TypeSidecar
			d.BodyAccess = "inspect-body"
			d.AllowedEndpoints = []string{"https://sidecar.internal/v1/rewrite"}
			d.AllowRawBody = true
			d.Scope = "project:cs-lab-7"
			return d
		}(),
	}
	// 从「磁盘形态」出发走一遍：Edit 写出来 → Raw 读回来，值必须等价。
	out, err := EditProcessors([]byte("processors: []\n"), list)
	if err != nil {
		t.Fatalf("写回失败: %v", err)
	}
	back, err := RawProcessors(out)
	if err != nil {
		t.Fatalf("读回失败: %v\n%s", err, out)
	}
	if len(back) != 2 {
		t.Fatalf("应该读回 2 条: %+v", back)
	}
	again, err := EditProcessors(out, back)
	if err != nil {
		t.Fatalf("再写一次失败: %v", err)
	}
	if string(again) != string(out) {
		t.Errorf("同一意图必须写出同一份文本（diff 才有意义）:\n第一遍:\n%s\n第二遍:\n%s", out, again)
	}
	// 读回来的形态再过一次加载校验：控制台的基线不能是一条装配不过的声明。
	cfg, err := loadSrc(t, procYAML(string(out)))
	if err != nil {
		t.Fatalf("写出来的段在整份配置里加载失败: %v\n%s", err, out)
	}
	if len(cfg.ProcessorSpecsView()) != 2 {
		t.Errorf("加载后应有 2 条声明: %+v", cfg.ProcessorSpecsView())
	}
}

// TestProcessorsEndpointsWrittenTrimmed 确认写盘的是清理过的端点：
// 文件里那份必须与 Spec.Validate 判过、运行时逐条比对的那份是同一个字符串
// （粘来的行尾空格不该让「白名单里有它」和「命中它」两件事分开）。
func TestProcessorsEndpointsWrittenTrimmed(t *testing.T) {
	d := goodProcessor("sidecar-1")
	d.Type = processor.TypeSidecar
	d.BodyAccess = "inspect-body"
	d.AllowedEndpoints = []string{"  https://sidecar.internal/v1/rewrite\t", "https://other.internal/"}
	out, err := EditProcessors([]byte("processors: []\n"), []ProcessorDef{d})
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, "- https://sidecar.internal/v1/rewrite\n") {
		t.Errorf("端点应去掉首尾空白后写盘:\n%s", text)
	}
	back, err := RawProcessors(out)
	if err != nil {
		t.Fatalf("读回失败: %v\n%s", err, text)
	}
	if len(back[0].AllowedEndpoints) != 2 || back[0].AllowedEndpoints[0] != "https://sidecar.internal/v1/rewrite" {
		t.Errorf("端点读回不符: %+v", back[0].AllowedEndpoints)
	}
	// 大小写与非默认端口按领域包的规则原样保留（比对时才归一化，不在这里改写真值）。
	if !strings.Contains(text, "- https://other.internal/") {
		t.Errorf("白名单不该在写盘时补端口:\n%s", text)
	}
}

func TestRawProcessorsUnknownKeyRejected(t *testing.T) {
	src := []byte("processors:\n" + procItemText("p", "1", "before-route") + "      max_retries: 3\n")
	_, err := RawProcessors(src)
	if err == nil {
		t.Fatal("未知键必须报错")
	}
	if !strings.Contains(err.Error(), "max_retries") {
		t.Errorf("错误该指认未知键: %v", err)
	}
}

func TestRawProcessorsRejectsBrokenBaseline(t *testing.T) {
	// 手改坏的 phase（少一个 e）必须被读出来当场指认，而不是原样回到界面上再写回磁盘。
	src := []byte("processors:\n" + procItemText("p", "1", "before-upstram"))
	_, err := RawProcessors(src)
	if err == nil || !strings.Contains(err.Error(), "未知的处理阶段") {
		t.Fatalf("编辑基线必须过领域校验: %v", err)
	}
}

func TestEditProcessorsEmptyClearsSection(t *testing.T) {
	src := []byte(procYAML(renderOneProcessor(t, []ProcessorDef{goodProcessor("pii-cn")})))
	out, err := EditProcessors(src, nil)
	if err != nil {
		t.Fatalf("清空声明必须一次做完: %v", err)
	}
	text := string(out)
	if strings.Contains(text, "pii-cn") {
		t.Errorf("清空后旧声明还在:\n%s", text)
	}
	if !strings.Contains(text, "processors:") || strings.Contains(text, "processors: []\nprocessors:") {
		t.Errorf("清空后要留一个空段（重复的顶层键会让整份配置解不开）:\n%s", text)
	}
	back, err := RawProcessors(out)
	if err != nil || len(back) != 0 {
		t.Fatalf("清空后读回必须是空: %+v %v", back, err)
	}
	// 整份配置也要能加载（空段不是「没配」的错误形态）。
	if _, err := loadSrc(t, text); err != nil {
		t.Errorf("清空后配置加载失败: %v", err)
	}
	// 再清一次得到同一份文本：空段的写法只能有一种。
	again, err := EditProcessors(out, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != text {
		t.Errorf("清空操作不幂等:\n%s\n---\n%s", text, again)
	}
	// 手写的「只挂 key、没有正文」与「[]」同义，都得读成空声明。
	for _, hand := range []string{"processors:\n  # 还没填\n", "processors: []\n"} {
		got, err := RawProcessors([]byte(hand))
		if err != nil || len(got) != 0 {
			t.Errorf("空段 %q 应读成没有声明: %+v %v", hand, got, err)
		}
	}
}

func TestKnowledgeSourcesRoundTrip(t *testing.T) {
	list := []KnowledgeSourceDef{
		goodSource("campus-rag", "https://rag.internal/retrieve", "campus-policy", "course-outline"),
		goodSource("lab-rag", "http://127.0.0.1:8080/retrieve", "lab-kb"),
	}
	src := []byte("# 维护注释\nserver:\n  port: 18787\n" + procProvider + "knowledge_sources: []\nrouting:\n  retry: 2\n")
	out, err := EditKnowledgeSources(src, list)
	if err != nil {
		t.Fatalf("写回失败: %v", err)
	}
	text := string(out)
	for _, want := range []string{"维护注释", "port: 18787", "routing:"} {
		// 注意：knowledge_sources 段以流式写法存在时会连那一行一起替换，
		// 段外的注释与 routing 段必须原样。
		if !strings.Contains(text, want) {
			t.Errorf("段外内容 %q 被改掉了:\n%s", want, text)
		}
	}
	back, err := RawKnowledgeSources(out)
	if err != nil {
		t.Fatalf("读回失败: %v\n%s", err, out)
	}
	if len(back) != 2 || back[0].Name != "campus-rag" || len(back[0].KnowledgeBases) != 2 {
		t.Fatalf("读回不符: %+v", back)
	}
	if back[1].Endpoint != "http://127.0.0.1:8080/retrieve" {
		t.Errorf("端点没原样回来: %q", back[1].Endpoint)
	}
	// 再写一次得到同一份文本
	again, err := EditKnowledgeSources(out, back)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(out) {
		t.Errorf("同一意图写出两份文本:\n%s\n---\n%s", out, again)
	}
	if _, err := loadSrc(t, string(out)); err != nil {
		t.Errorf("写出来的段在整份配置里加载失败: %v", err)
	}
}

func TestRawKnowledgeUnknownKey(t *testing.T) {
	src := []byte("knowledge_sources:\n  - name: s\n    endpoint: https://a.internal/r\n" +
		"    knowledge_bases: [kb]\n    timeout_ms: 1000\n    max_response_bytes: 4096\n    api_key: sk-xxx\n")
	_, err := RawKnowledgeSources(src)
	if err == nil || !strings.Contains(err.Error(), "api_key") {
		t.Fatalf("未知键必须报错（凭证本来就不该出现在这一段）: %v", err)
	}
}

func TestRawKnowledgeRejectsBrokenBaseline(t *testing.T) {
	// 把凭证写进 URL 是这一屏最容易犯的错：读侧就要拒，不能等运行时构造 retriever。
	src := []byte("knowledge_sources:\n  - name: s\n    endpoint: https://tok:sk-xxx@a.internal/r\n" +
		"    knowledge_bases: [kb]\n    timeout_ms: 1000\n    max_response_bytes: 4096\n")
	_, err := RawKnowledgeSources(src)
	if err == nil || !strings.Contains(err.Error(), "凭证") {
		t.Fatalf("编辑基线必须过端点校验: %v", err)
	}
}

// TestEditKnowledgeRejectsBrokenInput 确认写侧不会因为「先落盘再说」而放过坏声明。
func TestEditKnowledgeRejectsBrokenInput(t *testing.T) {
	_, err := EditKnowledgeSources([]byte("knowledge_sources: []\n"),
		[]KnowledgeSourceDef{goodSource("s", "https://a.internal/r", "kb", "kb two")})
	if err == nil || !strings.Contains(err.Error(), "知识库 ID") {
		t.Fatalf("坏知识源必须在写之前就被拒: %v", err)
	}
	// 拒绝写回时原文一个字都不能变（错误路径不留半成品）。
	src := []byte("knowledge_sources: []\nrouting:\n  retry: 2\n")
	out, err := EditKnowledgeSources(src, []KnowledgeSourceDef{goodSource("s", "not-a-url", "kb")})
	if err == nil {
		t.Fatalf("非法端点必须拒绝: %v", err)
	}
	if out != nil {
		t.Errorf("拒绝写回时不该返回内容: %q", out)
	}
}

func TestSectionSpliceKeepsStreamAndBlockForms(t *testing.T) {
	// 段以流式写法存在（processors: []）时，替换必须连那一行一起吃掉，不留半截旧正文。
	block := []byte(procYAML("processors:\n" + procItemText("pii-cn", "9", "before-route")))
	out, err := EditProcessors(block, []ProcessorDef{goodProcessor("pii-cn")})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(out), "pii-cn"); n != 1 {
		t.Errorf("块写法替换后残留旧条目（pii-cn 出现 %d 次）:\n%s", n, out)
	}
	stream := []byte(procYAML("processors: []\n"))
	out2, err := EditProcessors(stream, []ProcessorDef{goodProcessor("pii-cn")})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out2), "processors: []") {
		t.Errorf("流式写法的旧行没被替换:\n%s", out2)
	}
	if _, err := loadSrc(t, string(out2)); err != nil {
		t.Errorf("流式写法替换后加载失败: %v", err)
	}
	// 段完全不存在时追加到末尾。
	appended, err := EditProcessors([]byte("server:\n  port: 1\n"), []ProcessorDef{goodProcessor("pii-cn")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(appended), "\nprocessors:\n") {
		t.Errorf("缺段时要追加:\n%s", appended)
	}
	back, err := RawProcessors(appended)
	if err != nil || len(back) != 1 {
		t.Fatalf("追加的段读不回来: %+v %v", back, err)
	}
}

// TestSectionSpliceKeepsTrailingComments 保证段后**顶格**的注释归下一段而不是被吃掉：
// 那些注释通常是「为什么下面那段别动」的现场记录。
// 注意缩进更深（两格）的注释按约定属于本段正文，替换时会被重渲染掉 ——
// 这正是每次写回都先备份的原因（见 internal/server/configedit.go）。
func TestSectionSpliceKeepsTrailingComments(t *testing.T) {
	src := []byte("processors:\n" + procItemText("pii-cn", "1", "before-route") +
		"# 这段说明别动 providers\nproviders:\n  - name: p1\n    base_url: https://a/v1\n    api_key: k\n    models: [\"*\"]\n")
	out, err := EditProcessors(src, []ProcessorDef{goodProcessor("pii-cn")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "这段说明别动 providers") {
		t.Errorf("段后顶格注释被吃掉了:\n%s", out)
	}
	if _, err := loadSrc(t, string(out)); err != nil {
		t.Errorf("替换后加载失败: %v", err)
	}
}
