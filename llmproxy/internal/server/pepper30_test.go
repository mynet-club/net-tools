package server

// P12（裁决 18′）的接线判据：master.key 派生出的两把专用子密钥，
// 一把给 pii-mask 的跨请求稳定假名，一把给知识检索词摘要的密钥位。
// 「派生只依赖主密钥 + 用途域 + 版本串」这条性质在 internal/secrets 测；
// 这里只测**接线有没有把它接到对的地方** —— 也就是网关进程真跑起来时，
// 一个自然人两个请求拿到的是同一个假名、一次检索的摘要是带密钥的那一个值。
//
// 反方向的守卫同样重要，因为它们各自锁住一种会静默通过的破法：
//   - 没有主密钥时**必须**退回每请求随机 salt（旧行为），而不是拿一个全零密钥当 pepper 用；
//   - 假名密钥**必须**不能被运行参数文件注入，否则「密钥不接受文件注入」那条锁就漏了一处，
//     而漏掉的后果是密钥被写进一份会被备份、被同步、可能贴进工单的 JSON。

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/processor"
	"github.com/mynet-club/net-tools/llmproxy/internal/secrets"
)

// piiPlaceholderRe 抓上游收到的占位符。
//
// 只抓「masked:类型:12 位十六进制」这一段，不带尖括号：网关转发前重新序列化过正文，
// 尖括号会写成 <，逐字节匹配外壳等于把序列化口径也一起钉进本用例。
var piiPlaceholderRe = regexp.MustCompile(`masked:(?:email|phone|id_card|bank_card):[0-9a-f]{12}`)

// mustPlaceholders 取上游最后一次收到的全部占位符，并要求正好 want 个。
// 多一个也算失败：那说明正则被正文里的别的东西撞上了，断言就不再等于「这两条是假名」。
func mustPlaceholders(t *testing.T, sent string, want int) []string {
	t.Helper()
	all := piiPlaceholderRe.FindAllString(sent, -1)
	if len(all) != want {
		t.Fatalf("上游收到的占位符 = %v（期望正好 %d 个），整段：%s",
			all, want, truncateMsg(sent, 300))
	}
	return all
}

// procPseudonymDecl 是一条最小可用的 pii-mask 声明（before-upstream + transform-body）。
func procPseudonymDecl() string {
	return procDecl("pii", processor.TypePIIMask, "before-upstream", "transform-body", nil)
}

// TestPseudonym30StableAcrossRequestsWithMasterKey 是这一包买到的东西本身：
// 同一个人、同一句原话，两个请求里邮箱与手机号的占位符逐字节相同。
//
// 它会在这些改动下失效，每一条都是真会发生的：
//   - 装配时忘了注入 PseudonymKey（回到每请求随机 salt）；
//   - 派生用途域被打错、或换成了别的常量（值全变，而且重启前后不再一致）；
//   - 把主密钥原值直接当假名密钥递下去（那等于给主密钥开一条可被外部观察的 MAC 使用面）。
func TestPseudonym30StableAcrossRequestsWithMasterKey(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	// 多用户夹具 = 带 master.key 的夹具，也正是生产形态。
	h := newMUHarnessWith(t, procYAML(up.url(), "enforce", procPseudonymDecl()))
	writePolicyBundle(t, h.harness, policyBundleOpen)
	if h.cipher == nil {
		t.Fatal("夹具没有主密钥，本用例无从测起")
	}

	resp1, body1 := procChat(t, h.harness, "req-pseudo-1", piiSample, false)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("第一次请求应当正常转发: %d %s", resp1.StatusCode, truncateMsg(string(body1), 200))
	}
	first := mustPlaceholders(t, up.last(t), 2)

	resp2, body2 := procChat(t, h.harness, "req-pseudo-2", piiSample, false)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("第二次请求应当正常转发: %d %s", resp2.StatusCode, truncateMsg(string(body2), 200))
	}
	second := mustPlaceholders(t, up.last(t), 2)

	if first[0] != second[0] || first[1] != second[1] {
		t.Errorf("同一个原值两次请求拿到了不同假名（跨请求稳定是本裁决唯一买到的东西）:\n%v\n%v",
			first, second)
	}
	// 稳定假名不是把脱敏换成可逆编码：原文仍然不许出网关。
	sent := up.last(t)
	if strings.Contains(sent, "someone@example.com") || strings.Contains(sent, "13800138000") {
		t.Errorf("上游收到了未脱敏正文: %s", truncateMsg(sent, 300))
	}
	// 两个不同原值不能撞成同一个假名（同一条请求内两个占位符必须互不相同）。
	if first[0] == first[1] {
		t.Errorf("邮箱与手机号拿到了同一个占位符: %v", first)
	}
}

// TestPseudonym30FallsBackWithoutMasterKey 锁住「没密钥就说没密钥」：
// 主密钥不可用时必须继续每请求随机 salt，而不是拿一个固定值假装稳定 ——
// 后者会让全网关所有部署的身份证号落进同一张可离线穷举的表。
func TestPseudonym30FallsBackWithoutMasterKey(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	// procHarness 是单用户夹具：没有 WithSecrets 那一步，s.secrets 为 nil。
	h := procHarness(t, up.url(), "enforce", procPseudonymDecl())

	resp1, body1 := procChat(t, h, "req-pseudo-nk-1", piiSample, false)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("第一次请求: %d %s", resp1.StatusCode, truncateMsg(string(body1), 200))
	}
	first := mustPlaceholders(t, up.last(t), 2)

	resp2, body2 := procChat(t, h, "req-pseudo-nk-2", piiSample, false)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("第二次请求: %d %s", resp2.StatusCode, truncateMsg(string(body2), 200))
	}
	second := mustPlaceholders(t, up.last(t), 2)

	if first[0] == second[0] && first[1] == second[1] {
		t.Errorf("没有主密钥却拿到了跨请求相同的假名 —— salt 被写成了常量:\n%v\n%v", first, second)
	}
}

// TestPseudonymKeyNotFileInjectable 守住「不新增密钥面」的另一半：
// 假名密钥只能由接线从主密钥派生，**不能**从 processor_params/<名>.json 读进来。
//
// 这条一旦漏，最短路径就是运营者把密钥写进那个 JSON —— 一份会被备份、被同步的文件，
// 而 pii-mask 恰好是「看起来配好了」最没声音的那类声明。参数键表与 DisallowUnknownFields
// 一起把它挡在装配期，两道门（启动期检查与运行态装配）口径必须一致。
func TestPseudonymKeyNotFileInjectable(t *testing.T) {
	const badParam = `{"pii_types":["email"],"pseudonym_key":"deadbeefdeadbeefdeadbeefdeadbeef"}`

	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce", procPseudonymDecl())
	writeProcParam(t, h, "pii", badParam)

	// 运行态那一关：坏文件让这条声明装不起来，enforce 据此拒绝命中它的请求，
	// 而不是「参数文件读失败就当没读」把原文发出去。
	resp, body := procChat(t, h, "req-pseudo-inject", piiSample, false)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("带密钥键的参数文件被接受了，请求照常转发: %s", truncateMsg(string(body), 200))
	}
	if got := errorKind(t, body); got != "processor_unavailable" {
		t.Errorf("回话错误类型 = %q，应为 processor_unavailable（装配失败要在回话里可读）", got)
	}
	if strings.Contains(string(body), "someone@example.com") || strings.Contains(string(body), "13800138000") {
		t.Errorf("回话里带了原文: %s", truncateMsg(string(body), 200))
	}
	// 一次出网都没有：拒绝发生在转发之前，未处理正文不许离开网关。
	if n := up.count(); n != 0 {
		t.Errorf("上游收到了 %d 个请求，装配失败时应该一个都不发", n)
	}

	// 红灯这一格要点名同一句话（裁决 17′ 与 18′ 在这里对上）：
	// 界面读到的是**装配当时**记下的那个字符串，而不是另编的一份 ——
	// 「日志里一套、面板上一套」正是 17′ 冲着的那类故障。
	// 这里现装一次（buildProcRuntime 读的正是磁盘上此刻那份文件），
	// 而不是去读缓存运行态：缓存里那条红灯在补好文件后**故意不灭**（17′ 的另一半），
	// 拿它当「现在磁盘上是什么」的读数会把两件事混成一件。
	cfg := h.cfgStore.Current()
	pr := h.srv.buildProcRuntime(cfg, h.srv.policyFor(cfg))
	if pr == nil {
		t.Fatal("夹具没有装配出 procRuntime")
	}
	blk := h.srv.assemblyInspect(cfg, &policyRuntime{proc: pr})
	sec, ok := blk["processors"].(assemblySection)
	if !ok {
		t.Fatalf("assembly.processors 形状不对: %T", blk["processors"])
	}
	if len(sec.Declarations) != 1 {
		t.Fatalf("逐条读数 = %d 条，want 1：%v", len(sec.Declarations), sec.Declarations)
	}
	if sec.Declarations[0].Status != assemblyFailed || !strings.Contains(sec.Declarations[0].Reason, "不接受参数键") {
		t.Errorf("红灯没点名密钥键: %+v", sec.Declarations[0])
	}

	// 启动期那一关（main.go 在 serve 之前跑的那道硬拒）必须给出同一条结论：
	// 两道门口径不一致时，「编辑着配好、重启才炸」是最费时间的一种形态。
	if err := CheckProcessorParams(cfg); err == nil {
		t.Error("启动期检查没有拒掉含密钥键的参数文件")
	} else if !strings.Contains(err.Error(), "pseudonym_key") {
		t.Errorf("启动期拒因没点名那个键，运营者只能猜: %v", err)
	}

	// 对照：把密钥键去掉，同一条声明就该正常装配 —— 否则上面几条断言
	// 可能只是「夹具坏了」，而不是「密钥键被挡住了」。
	writeProcParam(t, h, "pii", `{"pii_types":["email"]}`)
	if err := CheckProcessorParams(h.cfgStore.Current()); err != nil {
		t.Errorf("合法参数文件被拒: %v", err)
	}
	pr2 := h.srv.buildProcRuntime(cfg, h.srv.policyFor(cfg))
	if len(pr2.regErrs) != 0 {
		t.Errorf("合法参数文件下仍有装配失败: %v", pr2.regErrs)
	}
}

// TestKbPepperAndPseudonymPepperAreDistinct 从检索那一侧钉住「一把主密钥、多把互不相干的子密钥」：
// 取的是两个真实注入点各自拿到的串（Server.kbQuery 与 withSecrets 走的是同一个 Derive），
// 而不是在测试里重新拼一遍字面量 —— 后者会跟着拼错的那一侧一起绿。
func TestKbPepperAndPseudonymPepperAreDistinct(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := newMUHarnessWith(t, procYAML(up.url(), "enforce", procPseudonymDecl()))
	writePolicyBundle(t, h.harness, policyBundleOpen)

	kbPepper := h.srv.kbQuery("张三 绩效", false).Pepper
	if len(kbPepper) != 32 {
		t.Fatalf("kb 摘要密钥位长度 = %d，应为 32", len(kbPepper))
	}
	if want := h.cipher.Derive(secrets.PurposeKBQueryDigest, secrets.DeriveVersionV1); string(kbPepper) != string(want) {
		t.Error("kbQuery 拿到的不是主密钥在 kb 域下的派生值：用途域或版本串在某一处被改写了")
	}
	piiPepper := h.cipher.Derive(secrets.PurposePIIPseudonym, secrets.DeriveVersionV1)
	if string(kbPepper) == string(piiPepper) {
		t.Error("两个用途拿到了同一把子密钥：一处可观测的使用面就摊开了另一处")
	}
}

// TestKbQueryPepperAbsentMeansNoPepper 是 nil 那一侧：主密钥不可用时 kbQuery 必须给出
// 空 pepper（于是摘要退回无密钥口径，并由装配期那条 WARN 点名），
// 而不是一个全零串 —— 后者在界面上和「有 pepper」长得一模一样。
func TestKbQueryPepperAbsentMeansNoPepper(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce", procPseudonymDecl())
	if h.srv.secrets != nil {
		t.Fatal("单用户夹具不该带主密钥")
	}
	if len(h.srv.kbQuery("张三 绩效", false).Pepper) != 0 {
		t.Error("没有主密钥时 kbQuery 仍然给出了 pepper：那把「退回旧口径」变成了不可读的形态")
	}
}
