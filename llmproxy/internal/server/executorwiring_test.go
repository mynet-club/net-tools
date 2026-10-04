package server

// §3.F/§3.I 的**生产接线**证据（不是执行器自身的功能测试，也不是注册表单元测试）。
//
// 这里要回答的只有主线排障时会问的那几句，而每句都得靠一次**真实请求**取证：
//   - 配置里的执行器声明 → 计划里的执行器名 → 本网关注册表 → 真正出网，
//     这四段是不是同一根线（中间任何一段是硬编码或"顺手猜一个"，这里就会断）；
//   - 一次委托的时限、响应上限、状态与失败类型落在哪里 —— 响应头只有承载者，
//     指标只有累计数，而这两样都回答不了「这一发到底用了什么时限」；
//   - 名字注册不上时是不是**真的**一个字节都没出网，而不是"回落一下再看看"；
//   - fake 执行器有没有可能从生产配置里被拿到（它只该活在测试与高校示例里）。
//
// 断言刻意不重复 internal/executor 已测过的执行器行为：那会让两处断言跟着接口一起烂。

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/executor"
	"github.com/mynet-club/net-tools/llmproxy/internal/logx"
)

// ---------------------------------------------------------------- 夹具

// execLogFile 把网关日志换成「另开一个文件、级别放到 info」的那份，返回读全文的闭包。
//
// 为什么要换而不是读 stdout：默认夹具用 LevelError（测试输出别淹在转发日志里），
// 而 `event=executor_exchange` 是 Info 级 —— 级别不放开就根本不会有这一行，
// 那「没有记录」和「记录没写全」在断言里会长得一模一样。
func execLogFile(t *testing.T, h *harness) func() string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wiring.log")
	lg := logx.New(logx.LevelInfo, path, 1, 1)
	old := h.srv.log
	h.srv.log = lg
	t.Cleanup(func() {
		_ = lg.Close()
		h.srv.log = old
	})
	return func() string {
		raw, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		return string(raw)
	}
}

// execRecord 取出日志里最后一条指定 event 的结构化行，折算成字段表。
//
// 取最后一条：一次请求可能跨多家候选，而"最后一发"才是客户端真正收到的那次交换。
// 返回 nil 表示这个事件根本没出现 —— 调用方必须把它当失败处理，不能当成空字段表。
// 行尾可能跟着中文归因（带空格），这里只认 `key=value` 形态的字段，其余原样丢掉。
func execRecord(t *testing.T, logs, event string) map[string]string {
	t.Helper()
	marker := "event=" + event + " "
	var hit string
	for _, line := range strings.Split(logs, "\n") {
		if i := strings.Index(line, marker); i >= 0 {
			hit = line[i:]
		}
	}
	if hit == "" {
		return nil
	}
	out := map[string]string{}
	for _, tok := range strings.Fields(hit) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok || k == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// execUpStatus 是一个「固定返回某个状态码」的上游。
func execUpStatus(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	}
}

// execPlanOf 用线上同一个判定核取「这次请求的计划」，并核对它确实声明了执行器。
//
// 这一步是整根线的起点：如果计划里没有执行器名，后面「从注册表取到执行器」
// 就只是测试自己造出来的场景，而不是生产会走的路径。
func execPlanOf(t *testing.T, h *harness, model string) (policyCandidateSnapshot, executor.Protocol) {
	t.Helper()
	cfg := h.cfgStore.Current()
	rt := h.srv.policyFor(cfg)
	if rt == nil {
		t.Fatal("enforce 下应有策略运行态，却没有 —— 后面的断言全部失去意义")
	}
	providers, _ := h.srv.providersFor("", model)
	shot := h.srv.policyJudge(rt, "", model, "req-wire-plan", "/v1/chat/completions", providers, "", time.Now())
	if shot == nil || shot.PlanErr != nil || len(shot.Plan.Fallbacks) == 0 {
		t.Fatalf("计划应当有候选，实际: %+v", shot)
	}
	cand := shot.Plan.Fallbacks[0]
	if strings.TrimSpace(cand.Executor) == "" {
		t.Fatalf("计划候选没声明执行器名，委托根本无从核对（provider=%s）", cand.Provider)
	}
	proto, ok := rt.exec.protocolOf(cand.Executor)
	if !ok {
		t.Fatalf("计划声明的执行器 %q 在本网关注册表里解析不出来", cand.Executor)
	}
	return policyCandidateSnapshot{Executor: cand.Executor, Provider: cand.Provider, UpstreamModel: cand.UpstreamModel}, proto
}

// policyCandidateSnapshot 是从计划里抄出来的三个事实，测试用它比对日志字段。
type policyCandidateSnapshot struct {
	Executor      string
	Provider      string
	UpstreamModel string
}

// ---------------------------------------------------------------- 正常路径

// 一次真实请求把四段线串起来：配置声明 → 计划执行器名 → 运行态注册表 → 真出网，
// 并且这一次交换的时限/上限/状态/失败类型**逐字段**落在同一条执行记录上。
func TestExecutor30ProductionChainWritesExecutionRecord(t *testing.T) {
	up := startExecUp(t, procJSON("wired-answer"))
	h := execHarness(t, up.url(), "enforce", 3000)
	read := execLogFile(t, h)

	// 1) 配置 → 计划 → 注册表（还没发请求，先确认这三段本来就接得上）
	plan, proto := execPlanOf(t, h, "gpt-4o")
	if plan.Executor != executorNameOpenAI {
		t.Errorf("计划声明的执行器名与本网关注册名同源才对，实际 %q vs %q", plan.Executor, executorNameOpenAI)
	}

	// 2) 真请求：客户端拿到答复，观测头认出入托者
	resp, body := procChat(t, h, "req-wire-rec", "wiresentinel-canary", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("接了线的请求应照常 200，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if got := resp.Header.Get("X-Llmproxy-Executor"); got != plan.Executor {
		t.Errorf("观测头里的承载者与计划不一致: %q vs %q", got, plan.Executor)
	}

	// 3) 真出网：上游确实收到了这一发，而且带的是供应商密钥
	//    （fake 回放做不到这一点 —— 这就是 real/fake 的运行期分界）
	if up.hits() != 1 {
		t.Fatalf("上游应恰好收到 1 个请求，实际 %d", up.hits())
	}
	sent, head := up.last(t)
	if !strings.Contains(sent, "wiresentinel-canary") {
		t.Errorf("上游收到的正文里没有本次请求的哨兵串: %s", truncateMsg(sent, 300))
	}
	if got := head.Get("Authorization"); got != "Bearer sk-vendorA" {
		t.Errorf("委托交换必须带供应商密钥（缺它上游会 401 而记账照常）: %q", got)
	}

	// 4) 执行记录：字段逐个核对，值必须来自计划与配置，不是日志里现编的字面量
	rec := execRecord(t, read(), "executor_exchange")
	if rec == nil {
		t.Fatalf("日志里没有 event=executor_exchange —— 委托跑过了却没记录，等于排障时只能猜:\n%s",
			truncateMsg(read(), 800))
	}
	want := map[string]string{
		"request_id": "req-wire-rec",
		"executor":   plan.Executor,
		"provider":   plan.Provider,
		"model":      "gpt-4o",
		"protocol":   string(proto),
		// 时限取自 provider.timeout_ms（配置事实），上限与 relay 的非流式缓冲上限同源。
		"timeout_ms":         "3000",
		"max_response_bytes": fmt.Sprint(maxUpstreamResponseBytes),
		"status":             "200",
		"reason":             exchangeReasonNone,
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("执行记录 %s = %q，期望 %q（整行字段：%v）", k, rec[k], v, rec)
		}
	}
	if rec["upstream_model"] != plan.UpstreamModel {
		t.Errorf("执行记录里的 upstream_model=%q 与计划里的 %q 不是同一个目标",
			rec["upstream_model"], plan.UpstreamModel)
	}

	// 5) 密钥与正文不得跨出这一跳（§2.9）：记录只点名字段，不是把 attempt 打出来。
	line := strings.Join(sortedLine(rec), " ")
	if strings.Contains(line, "sk-vendorA") {
		t.Errorf("执行记录里出现上游密钥明文: %s", line)
	}
	if strings.Contains(line, "wiresentinel-canary") {
		t.Errorf("执行记录里出现请求正文: %s", line)
	}

	// 6) 指标面同步：日志有行、累计数也要有，否则「委托率」和「这一发」对不上账
	if _, raw := h.get(t, "/metrics", ""); !strings.Contains(string(raw),
		`llmproxy_executor_exchanges_total{executor="`+plan.Executor+`"} 1`) {
		t.Errorf("/metrics 里没有这次委托的序列:\n%s", truncateMsg(string(raw), 600))
	}
}

// sortedLine 把字段表拼成一行，只给泄漏断言用（顺序无关紧要，内容才要紧）。
func sortedLine(rec map[string]string) []string {
	out := make([]string, 0, len(rec))
	for k, v := range rec {
		out = append(out, k+"="+v)
	}
	return out
}

// 流式那一发的执行记录：`timeout_ms=0 max_response_bytes=0` 是**显式声明**
// 「时限在调用方 ctx 里 / 不缓存、逐段透传」（2026-10-04 裁决第 2 条：B 方案）。
// 这条要证明的是运维面上读得出来：同一份配置、同一家上游，非流式那行带着正的时限与
// 上限，流式那行才是两个 0 —— 否则「0 是声明」与「接线漏填」在日志里长得一模一样。
// 字段形状与非流式那行刻意不变（§3.I 观测面稳定：不因裁决扩字段）。
func TestExecutor30StreamingExecutionRecordDeclaresZeroes(t *testing.T) {
	up := startExecUp(t, procSSE("one", " two"))
	h := execHarness(t, up.url(), "enforce", 3000)
	read := execLogFile(t, h)

	nonStream, body := procChat(t, h, "req-wire-stream-off", "hello", false)
	if nonStream.StatusCode != http.StatusOK {
		t.Fatalf("非流式该 200，实际 %d: %s", nonStream.StatusCode, truncateMsg(string(body), 200))
	}
	off := execRecord(t, read(), "executor_exchange")
	if off == nil {
		t.Fatalf("非流式那发的执行记录缺席:\n%s", truncateMsg(read(), 800))
	}
	if off["timeout_ms"] != "3000" || off["max_response_bytes"] != fmt.Sprint(maxUpstreamResponseBytes) {
		t.Fatalf("前提不成立：非流式那发的时限/上限就不是正数，后面的 0 无从对照（字段：%v）", off)
	}

	stream, body := procChat(t, h, "req-wire-stream-on", "hello", true)
	if stream.StatusCode != http.StatusOK {
		t.Fatalf("流式委托该 200，实际 %d: %s", stream.StatusCode, truncateMsg(string(body), 200))
	}
	if got := stream.Header.Get("X-Llmproxy-Executor"); got != executorNameOpenAI {
		t.Fatalf("前提不成立：这条流式没走执行器（委托头 %q）", got)
	}
	on := execRecord(t, read(), "executor_exchange")
	if on == nil {
		t.Fatalf("日志里没有流式那发的 event=executor_exchange:\n%s", truncateMsg(read(), 800))
	}
	for _, c := range []struct{ field, want string }{
		{"request_id", "req-wire-stream-on"},
		{"executor", executorNameOpenAI},
		{"provider", "vendorA"},
		{"timeout_ms", "0"},
		{"max_response_bytes", "0"},
		{"status", "200"},
		{"reason", exchangeReasonNone},
	} {
		if on[c.field] != c.want {
			t.Errorf("流式执行记录 %s = %q，期望 %q（整行字段：%v）", c.field, on[c.field], c.want, on)
		}
	}
	// 除那两个 0 以外，两行的字段面必须完全同形：观测面不能按请求形态长出新列。
	if len(off) != len(on) {
		t.Errorf("两条执行记录的字段数不一致（%d vs %d）：%v / %v", len(off), len(on), off, on)
	}
	for k := range off {
		if _, ok := on[k]; !ok {
			t.Errorf("流式那发少了字段 %s（观测面按请求形态变形，报表读法就散了）", k)
		}
	}
	// 密钥与正文照旧不得跨出这一跳。
	if line := strings.Join(sortedLine(on), " "); strings.Contains(line, "sk-vendorA") {
		t.Errorf("执行记录里出现上游密钥明文: %s", line)
	}
}

// 失败类型必须进执行记录：「有这一次交换」与「这一次交换成了没有」是排障时的两个不同问题。
func TestExecutor30ExecutionRecordCarriesFailureType(t *testing.T) {
	up := startExecUp(t, execUpStatus(http.StatusInternalServerError,
		`{"error":{"message":"upstream exploded"}}`))
	h := execHarness(t, up.url(), "enforce", 0)
	read := execLogFile(t, h)

	procChat(t, h, "req-wire-fail", "hello", false)

	rec := execRecord(t, read(), "executor_exchange")
	if rec == nil {
		t.Fatalf("上游 5xx 也是一次完成了的交换，记录不能缺席:\n%s", truncateMsg(read(), 800))
	}
	if rec["status"] != "500" {
		t.Errorf("记录里的 status 应当是上游给的状态码，实际 %q", rec["status"])
	}
	got := rec["reason"]
	if got == exchangeReasonNone || got == "" {
		t.Fatalf("失败交换的记录不能把失败类型写成「没有失败码」（字段：%v）", rec)
	}
	// 标签空间封闭：reason 必须是 executor 包注册表里的码，接线侧不新造按内容取的码。
	if !executor.ReasonCode(got).Valid() {
		t.Errorf("记录里的 reason=%q 不在执行器注册码表内", got)
	}
	if got != string(executor.ReasonUpstreamServerStatus) {
		t.Errorf("上游 5xx 应记成 %s，实际 %s",
			executor.ReasonUpstreamServerStatus, got)
	}
}

// 记录只属于委托面：legacy / shadow 下 2.x 原样跑，就一个字都不该写（边界 2）。
// 少了这一条，"影子一旦能换传输层"（§3.0 线 2）会以日志行的形式偷偷发生。
func TestExecutor30NoExecutionRecordOutsideEnforce(t *testing.T) {
	for _, mode := range []string{"", "shadow"} {
		up := startExecUp(t, procJSON("legacy-path"))
		h := execHarness(t, up.url(), mode, 0)
		read := execLogFile(t, h)

		resp, body := procChat(t, h, "req-wire-norec", "hello", false)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("mode=%q 下应照常 200，实际 %d: %s", mode, resp.StatusCode, truncateMsg(string(body), 200))
		}
		if rec := execRecord(t, read(), "executor_exchange"); rec != nil {
			t.Errorf("mode=%q 不该有委托执行记录，实际有: %v", mode, rec)
		}
		if got := resp.Header.Get("X-Llmproxy-Executor"); got != "" {
			t.Errorf("mode=%q 下不该报承载者，实际 %q", mode, got)
		}
	}
}

// ---------------------------------------------------------------- 拒绝路径

// 未注册的执行器名在**真实请求**上必须 fail closed：客户端拿到指名的错误、
// 上游一次都没收到、没有委托记录、通道一条都没装配、指标记的是"被拒"而不是"交换失败"。
//
// 单元测试（executor30_test.go 里那条）只证明判定函数会返回错误；这一条证明的是一整条
// 请求链拿到那个错误之后**没有**去猜一个执行器、也没有悄悄回到 2.x 再打一次。
func TestExecutor30UnregisteredNameFailsClosedOnRealRequest(t *testing.T) {
	up := startExecUp(t, procJSON("must-never-leave"))
	h := execHarness(t, up.url(), "enforce", 0)
	read := execLogFile(t, h)

	// 把运行态注册表换成「注册的是别的名字」：这就是生产里策略包声明了本网关
	// 装配不出来的执行器时的情形，而计划里的名字仍来自判定核。
	cfg := h.cfgStore.Current()
	rt := h.srv.policyFor(cfg)
	if rt == nil {
		t.Fatal("enforce 下应有策略运行态")
	}
	planName := rt.exec.sortedNames()
	rt.exec = execRT(config.PolicyModeEnforce, map[string]executor.Protocol{
		"http-anthropic": executor.ProtocolOpenAIChat,
	}).exec

	resp, body := procChat(t, h, "req-wire-unreg", "hello", false)

	// 1) 明确错误：客户端拿到的那句必须指名是哪个执行器名注册不上，
	//    而不是「所有上游供应商均不可用」后面跟一句猜不出来原因的空话。
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("名字注册不上却跑通了，说明回落发生了：\n%s", truncateMsg(string(body), 300))
	}
	msg := string(body)
	if !strings.Contains(msg, planName[0]) {
		t.Errorf("错误文案要指名计划里那个注册不上的执行器名 %q，实际: %s", planName[0], truncateMsg(msg, 300))
	}
	if strings.Contains(msg, "sk-vendorA") {
		t.Errorf("错误文案里出现上游密钥明文: %s", truncateMsg(msg, 300))
	}

	// 2) 真的没出网：一次都没有。
	if up.hits() != 0 {
		t.Errorf("被拒的候选不该出网，上游却收到 %d 个请求", up.hits())
	}
	if rec := execRecord(t, read(), "executor_exchange"); rec != nil {
		t.Errorf("没出网却写了委托记录，审计会描述一次没发生的交换: %v", rec)
	}
	// 3) 通道一条都没装配（装配失败会留下实例，拒在装配之前不该有）。
	if len(rt.exec.entries) != 0 {
		t.Errorf("拒候选不该装配任何出网通道，实际 %d 条", len(rt.exec.entries))
	}
	// 4) 观测头缺席：客户端与排障工具都不该看到"承载者"。
	if got := resp.Header.Get("X-Llmproxy-Executor"); got != "" {
		t.Errorf("被拒时不该有 X-Llmproxy-Executor，实际 %q", got)
	}
	// 5) 拒绝这一侧要留痕：只看 200 数量分不出「真的没出网」和「出网了但没记录」。
	rej := execRecord(t, read(), "executor_rejected")
	if rej == nil {
		t.Fatalf("日志里没有 event=executor_rejected:\n%s", truncateMsg(read(), 800))
	}
	if rej["request_id"] != "req-wire-unreg" {
		t.Errorf("拒绝留痕的 request_id 不对: %v", rej)
	}
	// 6) 指标记的是「被拒」，且标签是封闭的阶段名而不是计划里那个名字。
	metricsRaw := func() string {
		_, raw := h.get(t, "/metrics", "")
		return string(raw)
	}()
	if !strings.Contains(metricsRaw,
		`llmproxy_executor_rejected_total{stage="`+executorRejectUnregistered+`"} 1`) {
		t.Errorf("/metrics 里没有 rejected 序列:\n%s", truncateMsg(metricsRaw, 800))
	}
	if strings.Contains(metricsRaw, "http-anthropic") {
		t.Errorf("注册不上的执行器名不该进指标标签（它本身就是被拒原因，进标签等于让被观测者决定基数）:\n%s",
			truncateMsg(metricsRaw, 800))
	}
}

// ---------------------------------------------------------------- fake / real 边界

// 生产注册表只有一个名字、一种协议形态。这条断言盯着「顺手多注册一个」：
// 每多一个名字就多一条出网解释，而 §2.7 规则 4 要求新语义带版本与迁移说明。
func TestExecutor30ProductionRegistryIsOneName(t *testing.T) {
	er := (&Server{}).buildExecutorRuntime()
	names := er.sortedNames()
	if len(names) != 1 || names[0] != executorNameOpenAI {
		t.Fatalf("生产注册表应当只有 %q，实际 %v（新增执行器要先过配置面裁决）", executorNameOpenAI, names)
	}
	proto, ok := er.protocolOf(executorNameOpenAI)
	if !ok || proto != executor.ProtocolOpenAIChat {
		t.Errorf("注册名 %q 的协议形态不对: %q ok=%v", executorNameOpenAI, proto, ok)
	}
}

// fake 执行器只允许活在测试与高校示例里。
//
// 这条是"不允许因为 executor 未注册而静默回落 fake"的结构面：接线代码里连那个标识符
// 都不出现，回落就无从写起。判定用源码扫描而不是运行时断言，因为**没写的代码**
// 才是这条约束的对象，运行时看不出"没写"。
func TestExecutor30FakeExecutorStaysOutOfProductionCode(t *testing.T) {
	root := filepath.Join("..", "..")
	dirs := []string{"cmd", "internal", "examples"}
	re := regexp.MustCompile(`executor\.(NewFake\b|Fake[A-z]*)`)

	var hits []string
	for _, d := range dirs {
		err := filepath.WalkDir(filepath.Join(root, d), func(path string, ent fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if ent.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			// _test.go 里的 fake 是夹具本身，正是允许存在的两种场合之一。
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if loc := re.FindIndex(raw); loc != nil {
				rel, _ := filepath.Rel(root, path)
				hits = append(hits, rel)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	for _, hit := range hits {
		if !strings.HasPrefix(filepath.ToSlash(hit), "examples/university/") {
			t.Errorf("fake 执行器出现在非测试、非高校示例的生产代码里：%s", hit)
		}
	}
}
