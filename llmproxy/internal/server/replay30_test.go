package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/replay"
	"github.com/mynet-club/net-tools/llmproxy/internal/routing"
)

// §2.8 证据链的最后一段：线上真的跑过的判定，如何变成另一个进程能重跑的记录。
//
// 断言的重心是三件事，每一件都对应一种「证据链看起来闭合、实际骗人」的失败：
//  1. **导出的记录能被独立加载的策略包重跑并逐字段复现**。这是整包的交付判据：
//     只在网关进程里自证「我记下了」不算闭合，必须真的换一份策略集、换一个时钟。
//  2. **策略变了绝不静默通过**。喂进不同版本的包时回放要拒绝，而不是让 Evaluate
//     现算一条结论冒充「复现成功」—— 那等于把「策略改过」这件最需要报警的事抹平。
//  3. **不该采的绝不采**：影子、legacy、管理口的路由模拟都不进窗口；计划没真的
//     驱动选路时不写选路记录。半个痕迹比没痕迹更坏，掺进人为流量的证据更坏。
//
// 另有一条诚实口径要钉住，它分两段（2026-10-04 裁决第 5 条 B 落地前后两段都在测）：
//   - 线上抽样算法与回放缺省抽样器**不同名**（routing-seeded-splitmix64-v1 vs
//     replay-sampling-v1）。把两个标识合并成一个，首选顺序的 diff 会立刻冒出来。
//   - 首选顺序能不能逐位复现，取决于记录带不带 replay_snapshot：带 ⇒ 报告必须报出
//     逐位复现；把快照摘掉 ⇒ 同一份文件必须退回「只做解释性回放」并说出来。
//     逐位的凭据来自现场，不来自文件里写了个像样的算法名。

// openReplayWindow 把窗口打开并全采。
//
// 走 configure 而不是直接改字段：那是管理口用的同一条通道，指针语义本身也要被跑到。
func openReplayWindow(t *testing.T, h *muHarness) {
	t.Helper()
	on := true
	full := replayPermilleFull
	h.srv.replayWin.configure(&on, &full, nil, nil)
}

// replayExport 取导出接口，返回状态码与原始字节。
func replayExport(t *testing.T, h *muHarness, query string) (int, []byte) {
	t.Helper()
	resp, raw := h.get(t, "/v1/_admin/replay/export"+query, adminToken)
	return resp.StatusCode, raw
}

// adminPostRaw 用管理凭证 POST，返回状态码与原始字节。
func adminPostRaw(t *testing.T, h *muHarness, path string, body map[string]any) (int, []byte) {
	t.Helper()
	resp, raw := h.post(t, path, adminToken, body)
	return resp.StatusCode, raw
}

// mustDecodeRecords 解出记录文件。
//
// 用 Decode 而不是直接看 JSON：Decode 的「未知字段与被禁键一律拒绝」就是这条链的
// 内容边界。导出侧多写一个禁字段，这里要当场失败，而不是留到回放里变成谜。
func mustDecodeRecords(t *testing.T, raw []byte) replay.File {
	t.Helper()
	f, err := replay.Decode(raw)
	if err != nil {
		t.Fatalf("导出的记录解不开: %v\n%s", err, raw)
	}
	return f
}

// replayFromDisk 换一份**独立从磁盘加载**的策略集来回放，模拟另一台机器上的运维。
func replayFromDisk(t *testing.T, set *policy.BundleSet, data []byte, now time.Time) replay.Report {
	t.Helper()
	rp, err := replay.New(set, replay.Options{Now: now})
	if err != nil {
		t.Fatalf("构造回放器失败: %v", err)
	}
	report, err := rp.Run(mustDecodeRecords(t, data))
	if err != nil {
		t.Fatalf("回放失败: %v", err)
	}
	return report
}

// loadBundlesAt 按 CLI 的同一条路径加载策略包：配置文件 → policy.bundles 引用 → 内容目录。
func loadBundlesAt(t *testing.T, cfgPath string) *policy.BundleSet {
	t.Helper()
	cfg, err := config.LoadFileLenient(cfgPath)
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	set, err := cfg.Policy.LoadBundles(cfg.BundleBaseDir())
	if err != nil {
		t.Fatalf("加载策略包失败: %v", err)
	}
	if set == nil || set.Len() == 0 {
		t.Fatalf("配置里没有可回放的策略包")
	}
	return set
}

func mustBundles(t *testing.T, h *muHarness) *policy.BundleSet {
	t.Helper()
	return loadBundlesAt(t, h.configPath)
}

// routingNotes 把选路回放条目的备注拼成一段，便于断言降级口径。
func routingNotes(r replay.Report) string {
	var parts []string
	for _, o := range r.Outcomes {
		if o.Kind == replay.KindRouting {
			parts = append(parts, o.Notes...)
		}
	}
	return strings.Join(parts, "｜")
}

// stripSnapshot 把导出文件里选路记录的 replay_snapshot 摘掉，其余字段一字不动。
//
// 走 Decode/Encode 而不是字符串删键：那会让「摘掉快照」这件事本身成为一次可能被
// JSON 结构误导的操作（删错一层、删掉别人的字段），对照实验的自变量必须只有一个。
func stripSnapshot(t *testing.T, data []byte) []byte {
	t.Helper()
	f := mustDecodeRecords(t, data)
	for i := range f.Routings {
		f.Routings[i].Replay = nil
	}
	out, err := replay.Encode(f)
	if err != nil {
		t.Fatalf("摘快照后重新编码失败: %v", err)
	}
	return out
}

// policyBundleDenyAllV2 是 t-open 的 v2：整池拒绝。
// 引用与内容同时升版（加载器以引用为准，只改一边会直接报错），
// 所以它就是「运维发了新版、策略真的变了」那个形态。
const policyBundleDenyAllV2 = `
id: t-open
version: 2
scope: system:gateway
entitlements:
  - subject: "*"
    resource: "model:*"
    action: use
    effect: deny
`

// ── 闭合：导出 → 独立策略包 → 逐字段复现 ──────────────────────────────────

func TestReplay30ExportReplaysClosedLoop(t *testing.T) {
	h := policyAdminHarness(t, "enforce")
	openReplayWindow(t, h)

	if code, raw := chatWith(t, h.harness, "sk-static", "closed-1", "gpt-x"); code != http.StatusOK {
		t.Fatalf("请求应 200，实际 %d: %s", code, raw)
	}

	code, raw := replayExport(t, h, "")
	if code != http.StatusOK {
		t.Fatalf("导出应 200，实际 %d: %s", code, raw)
	}
	f := mustDecodeRecords(t, raw)
	if len(f.Decisions) != 1 {
		t.Fatalf("应恰好 1 条判定记录，实际 %d", len(f.Decisions))
	}
	if len(f.Routings) != 1 {
		t.Fatalf("计划真的驱动了选路，应有 1 条选路记录，实际 %d", len(f.Routings))
	}

	rec := f.Decisions[0]
	if rec.RequestID != "closed-1" || rec.Resource != "model:gpt-x" || rec.Action != "use" {
		t.Fatalf("判定记录的定位不对: %+v", rec)
	}
	if rec.Effect != policy.EffectAllow {
		t.Errorf("开放策略包下 gpt-x 应记成 allow，实际 %s", rec.Effect)
	}
	if rec.Ctx.WiringMode != replay.ModeEnforce {
		t.Errorf("接线模式必须记成 enforce（窗口只采 enforce），实际 %s", rec.Ctx.WiringMode)
	}
	if rec.Ctx.Purpose != "chat" {
		t.Errorf("用途必须是从请求路径推出来的事实，实际 %q", rec.Ctx.Purpose)
	}
	if rec.Subject.Subject != "gateway" {
		t.Errorf("静态 key 的归属应当是网关自己，实际 %q", rec.Subject.Subject)
	}
	// 原文出网：这套夹具没有 body_raw 授权，结论必须是不允许 —— 而且是**现算**出来的
	// （写死 false 会让真有授权的部署也报「没授权」，写死 true 更是不许发生的）。
	if rec.ExternalPlaintextAllowed {
		t.Errorf("无 body_raw 授权时不该记 external_plaintext_allowed=true")
	}

	if f.SchemaVersion != replay.SchemaVersion {
		t.Errorf("导出的文件必须是当前写出版本 %d，实际 %d", replay.SchemaVersion, f.SchemaVersion)
	}
	rr := f.Routings[0]
	if rr.SamplingAlgo != replaySamplingAlgoOnline {
		t.Errorf("记录必须如实声明线上用的抽样算法，实际 %q", rr.SamplingAlgo)
	}
	if rr.SamplingAlgo != routing.SamplingAlgoSeededSplitmix64V1 {
		t.Errorf("接线侧的算法标识必须就是 D 那个常量的取值，否则「线上与回放同一条实现」没有证据")
	}
	// 完整现场：裁决 2026-10-04 第 5 条 B 落地的直接证据 —— 采集侧把规划用过的
	// 那份输入原样带走，导出文件里就得有它。
	if rr.Replay == nil {
		t.Fatalf("选路记录必须带 replay_snapshot（缺它首选顺序只能解释、不能复现）")
	}
	if _, _, err := rr.BitExactReplay(); err != nil {
		t.Errorf("这条记录应有资格声称首选逐位复现，实际被拒: %v", err)
	}
	trace := traceOf(t, h.harness, "closed-1")
	if rr.RoutingSeed != trace.RoutingSeed || rr.RoutingEpoch != trace.RoutingEpoch ||
		rr.PolicyVersion != trace.PolicyVersion {
		t.Errorf("选路记录与落库痕迹不是同一组事实: 记录 seed=%s epoch=%s ver=%s / 痕迹 seed=%s epoch=%s ver=%s",
			rr.RoutingSeed, rr.RoutingEpoch, rr.PolicyVersion,
			trace.RoutingSeed, trace.RoutingEpoch, trace.PolicyVersion)
	}
	// 候选摘要必须与请求表那一列相等：这是「导出的记录能与线上落库痕迹对上」最基本的证据。
	// 它只在看得到计划、且候选按**有效权重**写的时候成立。
	if rr.CandidatesDigest != trace.CandidatesDigest {
		t.Errorf("候选摘要对不上（记录里的权重不是有效权重？）: 记录 %s / 落库 %s",
			rr.CandidatesDigest, trace.CandidatesDigest)
	}
	// 快照里的候选与记录顶层必须是同一个池子（跨字段核对在 Validate 里，这里对痕迹）。
	if snapDigest, err := rr.Replay.CandidatesDigest(); err != nil || snapDigest != trace.CandidatesDigest {
		t.Errorf("快照候选池与落库摘要不符: %v %s / %s", err, snapDigest, trace.CandidatesDigest)
	}

	report := replayFromDisk(t, mustBundles(t, h), raw, time.Now().UTC().Add(time.Minute))
	if !report.Clean() {
		t.Fatalf("同版本回放应逐字段复现:\n%s", report)
	}
	if passed, mismatch, rejected := report.Counts(); passed != 2 || mismatch != 0 || rejected != 0 {
		t.Errorf("1 条判定 + 1 条选路都应通过，实际 %d/%d/%d\n%s", passed, mismatch, rejected, report)
	}
	// 首选顺序这次是**逐位比对过且一致**（§2.8 那句「不比对」从今天起只对旧文件成立）。
	if n := report.BitExactCount(); n != 1 {
		t.Errorf("带快照的选路记录回放应报 1 条逐位复现，实际 %d\n%s", n, report)
	}
	if n := routingNotes(report); strings.Contains(n, "只做解释性回放") {
		t.Errorf("这条记录有逐位凭据，报告里不该出现降级备注：%q", n)
	}

	// A/B 对照：把同一份文件里的快照摘掉再回放，结论必须退回「解释性」并说出来。
	// 这一条钉的是「逐位声称的来源是快照，不是文件里写了个像样的算法名」。
	without := stripSnapshot(t, raw)
	compare := replayFromDisk(t, mustBundles(t, h), without, time.Now().UTC().Add(time.Minute))
	if got := compare.BitExactCount(); got != 0 {
		t.Errorf("摘掉快照后仍报 %d 条逐位复现 —— 那等于用配置级投影冒充运行时事实", got)
	}
	if n := routingNotes(compare); !strings.Contains(n, "只做解释性回放") {
		t.Errorf("缺快照必须在报告里明说降级，实际备注：%q", n)
	}

	// 导出面自己就是新的泄露面：密钥、上游地址、正文一个都不许出现。
	for _, banned := range []string{"sk-", "base_url", "api_key", "Bearer"} {
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(banned)) {
			t.Errorf("导出内容里出现了 %q", banned)
		}
	}
}

func TestReplay30ChangedPolicyIsNeverSilentPass(t *testing.T) {
	h := policyAdminHarness(t, "enforce")
	openReplayWindow(t, h)
	if code, raw := chatWith(t, h.harness, "sk-static", "changed-1", "gpt-x"); code != http.StatusOK {
		t.Fatalf("请求应 200，实际 %d: %s", code, raw)
	}
	_, raw := replayExport(t, h, "")

	// 造「另一台机器上的策略已经换版」：配置引用与内容文件同时升到 v2、改成整池拒绝。
	// 两处一起改是加载器的硬要求，所以这里喂的是一套**合法**的新策略 ——
	// 拒绝回放的理由只能是版本对不上，不能是「包读坏了」。
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	newCfg := strings.Replace(h.cfgYAML, "      version: 1\n", "      version: 2\n", 1)
	if newCfg == h.cfgYAML {
		t.Fatal("夹具配置里没找到要改的版本引用")
	}
	if err := os.WriteFile(cfgPath, []byte(newCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	bundleDir := filepath.Join(dir, config.DefaultBundleDir)
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "t-open.yaml"), []byte(policyBundleDenyAllV2), 0o600); err != nil {
		t.Fatal(err)
	}

	report := replayFromDisk(t, loadBundlesAt(t, cfgPath), raw, time.Now().UTC().Add(time.Minute))
	if report.Clean() {
		t.Fatalf("策略换版后绝不能报「复现成功」:\n%s", report)
	}
	passed, mismatch, rejected := report.Counts()
	if passed != 0 {
		t.Errorf("换版后不该有任何一条被当成复现，实际 passed=%d", passed)
	}
	if rejected == 0 {
		t.Errorf("版本不匹配必须走拒绝回放（fail_closed），实际只有差异 %d 条\n%s", mismatch, report)
	}
	text := report.String()
	if !strings.Contains(text, "t-open@1") || !strings.Contains(text, "t-open@2") {
		t.Errorf("报告必须把两个版本都摊出来，否则运维无从判断是喂错了包还是策略真变了:\n%s", text)
	}
}

// ── 不该采的一个都不采 ──────────────────────────────────

func TestReplay30ShadowAndLegacyCaptureNothing(t *testing.T) {
	for _, tc := range []struct{ name, mode string }{
		{"shadow", "shadow"},
		{"legacy", "legacy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := policyAdminHarness(t, tc.mode)
			openReplayWindow(t, h)
			// 影子的判定确实跑了、请求也真的成了；legacy 下 3.0 根本不参与。
			// 两种都不许进窗口：前者没作用到任何请求上，后者连版本都没有。
			if code, raw := chatWith(t, h.harness, "sk-static", "off-mode-1", "gpt-x"); code != http.StatusOK {
				t.Fatalf("请求应 200，实际 %d: %s", code, raw)
			}
			_, raw := replayExport(t, h, "")
			f := mustDecodeRecords(t, raw)
			if len(f.Decisions) != 0 || len(f.Routings) != 0 {
				t.Fatalf("%s 模式采到了记录: %d 判定 / %d 选路", tc.name, len(f.Decisions), len(f.Routings))
			}
			// 空窗口导出的是合法的空文件，而不是 404 或半截 JSON。
			if err := f.Validate(time.Now().UTC()); err != nil {
				t.Fatalf("空导出应仍是合法文件: %v", err)
			}
		})
	}
}

func TestReplay30SimulateLeavesNoTrace(t *testing.T) {
	h := policyAdminHarness(t, "enforce")
	openReplayWindow(t, h)

	// 模拟比影子更要「一点痕迹都不留」：它复用同一个判定核，一旦进窗口，
	// 证据链里就掺进了从未发生的授权。
	for i := 0; i < 3; i++ {
		code, body := simulate(t, h, map[string]any{"scope": "", "model": "gpt-x", "request_id": fmt.Sprintf("sim-%d", i)})
		if code != http.StatusOK {
			t.Fatalf("模拟应 200，实际 %d: %v", code, body)
		}
	}
	if got := h.srv.replayWin.stats()["entries"]; got != 0 {
		t.Fatalf("路由模拟留了痕迹：entries=%v", got)
	}
	_, raw := replayExport(t, h, "")
	if f := mustDecodeRecords(t, raw); len(f.Decisions) != 0 {
		t.Fatalf("模拟记录被导出了: %d 条", len(f.Decisions))
	}

	if code, _ := chatWith(t, h.harness, "sk-static", "real-1", "gpt-x"); code != http.StatusOK {
		t.Fatalf("真实请求应 200，实际 %d", code)
	}
	if got := h.srv.replayWin.stats()["entries"]; got != 1 {
		t.Fatalf("真实请求应采到 1 条，实际 %v", got)
	}
}

func TestReplay30DeniedRequestLeavesDenyEvidenceOnly(t *testing.T) {
	h := policyAdminHarness(t, "enforce")
	openReplayWindow(t, h)

	// 策略拒绝是一次**真的发生过**的结论：必须留证据，但绝不能有选路记录
	// （请求根本没进选路）。
	code, _ := chatWith(t, h.harness, "sk-static", "denied-1", "secret-model")
	if code != http.StatusForbidden {
		t.Fatalf("secret-model 应被策略拒绝（403），实际 %d", code)
	}
	_, raw := replayExport(t, h, "")
	f := mustDecodeRecords(t, raw)
	if len(f.Decisions) != 1 {
		t.Fatalf("拒绝也要留 1 条判定证据，实际 %d", len(f.Decisions))
	}
	if len(f.Routings) != 0 {
		t.Fatalf("被拒绝的请求没有计划作用过，不该有选路记录，实际 %d", len(f.Routings))
	}
	rec := f.Decisions[0]
	if rec.Effect != policy.EffectDeny || rec.Resource != "model:secret-model" {
		t.Fatalf("判定记录应记成对 secret-model 的 deny，实际 %+v", rec)
	}
	// 拒绝的结论不可能同时授予原文出网（DecisionRecord.Validate 钉的不变量），
	// 而这条不变量必须在导出前真的跑过一遍 —— Decode 之外还要能进 Run。
	if rec.ExternalPlaintextAllowed {
		t.Fatalf("deny 记录里 external_plaintext_allowed=true")
	}

	report := replayFromDisk(t, mustBundles(t, h), raw, time.Now().UTC().Add(time.Minute))
	if !report.Clean() {
		t.Fatalf("同版本下这次拒绝应当复现:\n%s", report)
	}
	if len(report.Outcomes) != 1 || report.Outcomes[0].Kind != replay.KindDecision {
		t.Fatalf("只该有一条判定回放: %+v", report.Outcomes)
	}
}

// ── 窗口的开关、过滤与有界性 ──────────────────────────────────

func TestReplay30WindowDefaultOffAndScopeFilter(t *testing.T) {
	h := policyAdminHarness(t, "enforce")
	// 不碰 configure：缺省关闭就是缺省关闭。「忘了开」与「忘了关」都不该意外聚合出
	// 一批带用户名的记录。
	if code, raw := chatWith(t, h.harness, "sk-static", "off-1", "gpt-x"); code != http.StatusOK {
		t.Fatalf("请求应 200，实际 %d: %s", code, raw)
	}
	if got := h.srv.replayWin.stats()["entries"]; got != 0 {
		t.Fatalf("缺省应当不采，实际 entries=%v", got)
	}

	// 开着但千分率为 0：等价于关，只是把开关状态留着。
	on := true
	zero := 0
	h.srv.replayWin.configure(&on, &zero, nil, nil)
	if code, _ := chatWith(t, h.harness, "sk-static", "zero-1", "gpt-x"); code != http.StatusOK {
		t.Fatalf("请求应 200，实际 %d", code)
	}
	if got := h.srv.replayWin.stats()["entries"]; got != 0 {
		t.Fatalf("permille=0 不该采，实际 entries=%v", got)
	}

	// 范围过滤：只采 alice。bob 与静态 key（scope 空）都不进窗口。
	alice := h.addUser(t, "alice")
	h.addProvider(t, "alice", "own", "http://127.0.0.1:9/v1", "sk-alice-key", `["*"]`)
	bob := h.addUser(t, "bob")
	h.addProvider(t, "bob", "own", "http://127.0.0.1:9/v1", "sk-bob-key", `["*"]`)

	full := replayPermilleFull
	onlyAlice := "alice"
	h.srv.replayWin.configure(&on, &full, &onlyAlice, nil)
	if got := h.srv.replayWin.stats()["scope_filter"]; got != "alice" {
		t.Fatalf("范围过滤没配进去: %v", got)
	}

	chatWith(t, h.harness, bob, "s-2", "gpt-x")
	chatWith(t, h.harness, "sk-static", "s-3", "gpt-x")
	if got := h.srv.replayWin.stats()["entries"]; got != 0 {
		t.Fatalf("范围过滤失效：别人的请求也进了窗口，entries=%v", got)
	}
	// alice 这条的上游必然连不上（502），但记录在判定那一刻就采好了 ——
	// 「证据描述判定，不描述转发结果」正是这条链成立的前提。
	chatWith(t, h.harness, alice, "s-1", "gpt-x")
	if got := h.srv.replayWin.stats()["entries"]; got != 1 {
		t.Fatalf("alice 那条应进窗口，entries=%v", got)
	}

	// 导出侧的过滤同样按范围取。
	code, raw := replayExport(t, h, "?scope=user:alice")
	if code != http.StatusOK {
		t.Fatalf("按范围导出应 200，实际 %d: %s", code, raw)
	}
	f := mustDecodeRecords(t, raw)
	if len(f.Decisions) != 1 || f.Decisions[0].RequestID != "s-1" {
		t.Fatalf("导出过滤不对: %+v", f.Decisions)
	}
	if f.Decisions[0].Subject.Subject != "alice" {
		t.Errorf("记录里的归属应是 alice，实际 %q", f.Decisions[0].Subject.Subject)
	}
	// 不过滤时也能拿到同一条（窗口里只有它）。
	if _, all := replayExport(t, h, ""); !strings.Contains(string(all), "s-1") {
		t.Errorf("整体导出漏了记录")
	}
	// 非 user 范围今天还进不了窗口（旧链路的池子按用户分），要明说而不是静默导空。
	if code, body := replayExport(t, h, "?scope=organization:university"); code != http.StatusBadRequest {
		t.Errorf("组织范围导出应 400，实际 %d: %s", code, body)
	}
}

func TestReplay30WindowEvictsOldestAndCountsDrops(t *testing.T) {
	w := newReplayWindow()
	on := true
	full := replayPermilleFull
	capacity := 2
	who := "alice"
	w.configure(&on, &full, &who, &capacity)

	for i := 0; i < 5; i++ {
		w.add(replayEntry{
			scope:    "alice",
			decision: replay.DecisionRecord{RequestID: fmt.Sprintf("r-%d", i)},
		})
	}
	st := w.stats()
	if st["entries"] != 2 || st["captured"] != int64(5) || st["dropped"] != int64(3) {
		t.Fatalf("淘汰与计数不对: %+v", st)
	}
	// 留的是最新的两条，而不是随机两条。
	f, dropped, failed := w.file("")
	if len(f.Decisions) != 2 || f.Decisions[0].RequestID != "r-3" || f.Decisions[1].RequestID != "r-4" {
		t.Fatalf("窗口留错了记录: %+v", f.Decisions)
	}
	if dropped != 3 || failed != 0 {
		t.Fatalf("导出要带上窗口的丢弃/失败计数，实际 %d/%d", dropped, failed)
	}

	// 调小容量是运维常态（内存吃紧）：溢出同样计入丢弃，不能悄悄扔。
	small := 1
	w.configure(nil, nil, nil, &small)
	if st := w.stats(); st["entries"] != 1 || st["dropped"] != int64(4) {
		t.Fatalf("缩容量没按淘汰走: %+v", st)
	}

	w.clear()
	if st := w.stats(); st["entries"] != 0 || st["captured"] != int64(0) || st["dropped"] != int64(0) {
		t.Fatalf("clear 之后计数没归零: %+v", st)
	}
	// clear 只动记录与计数，开关与过滤保留（那由 sampling 那一条通道管）。
	if st := w.stats(); st["enabled"] != true || st["scope_filter"] != "alice" {
		t.Fatalf("clear 动了开关或过滤: %+v", st)
	}
}

func TestReplay30SamplingIsDeterministicPerRequestID(t *testing.T) {
	// 抽样按 request_id 哈希而不是计数器：同一条请求在重启前后、并发之下都必须给出
	// 同一个答案，否则「这次为什么没记录」没有回答。
	for _, id := range []string{"a", "b", "c", "d", "e", "f"} {
		want := replaySampleHit(id, 500)
		for i := 0; i < 20; i++ {
			if got := replaySampleHit(id, 500); got != want {
				t.Fatalf("request_id=%s 的抽样结论会飘: %v vs %v", id, want, got)
			}
		}
	}
	if replaySampleHit("x", 0) || !replaySampleHit("x", replayPermilleFull) {
		t.Fatal("0‰ 与 1000‰ 的短路不对")
	}
	// 既不能全采也不能全不采（那说明哈希退化了）。
	var hits int
	for i := 0; i < 200; i++ {
		if replaySampleHit(fmt.Sprintf("req-%d", i), 100) {
			hits++
		}
	}
	if hits == 0 || hits == 200 {
		t.Fatalf("100‰ 抽样退化成了固定答案: %d/200", hits)
	}
}

// ── 管理口自身：鉴权、入参、状态、审计 ──────────────────────────────────

func TestReplay30AdminSurfaceAuthArgsAndAudit(t *testing.T) {
	h := policyAdminHarness(t, "enforce")

	for _, path := range []string{"/v1/_admin/replay", "/v1/_admin/replay/export"} {
		resp, raw := h.get(t, path, "sk-wrong")
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s 用错 token 应 403，实际 %d: %s", path, resp.StatusCode, raw)
		}
	}
	// 多用户没启用时整套管理口关闭（与其它端点同口径）。
	plain := newHarness(t, cfgYAML(map[string]string{"a": "http://127.0.0.1:9/v1"}, []string{"sk-local"}))
	if resp, raw := plain.get(t, "/v1/_admin/replay", adminToken); resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("未启用多用户应 501，实际 %d: %s", resp.StatusCode, raw)
	}

	// 入参边界：千分率与容量都是运维会打错的数，必须当场拒而不是静默截断。
	if code, body := adminPostRaw(t, h, "/v1/_admin/replay/sampling",
		map[string]any{"enabled": true, "sample_permille": 1001}); code != http.StatusBadRequest {
		t.Errorf("sample_permille=1001 应 400，实际 %d: %v", code, body)
	}
	if code, body := adminPostRaw(t, h, "/v1/_admin/replay/sampling",
		map[string]any{"capacity": 0}); code != http.StatusBadRequest {
		t.Errorf("capacity=0 应 400，实际 %d: %v", code, body)
	}
	if code, body := adminPostRaw(t, h, "/v1/_admin/replay/sampling",
		map[string]any{"scope": "user:*"}); code != http.StatusBadRequest {
		t.Errorf("通配范围应 400（窗口按精确范围匹配，通配会静默空采），实际 %d: %v", code, body)
	}
	// 未声明的字段一律拒：留兼容层等于给「拼错的字段名」留一个不报警的后门。
	if code, _ := adminPostRaw(t, h, "/v1/_admin/replay/sampling",
		map[string]any{"enabled": true, "sample_percent": 50}); code != http.StatusBadRequest {
		t.Errorf("未知字段应 400，实际 %d", code)
	}
	// 只有 POST 能改开关；GET 到 sampling 上是「看起来像查询的写」，拒掉。
	if resp, raw := h.get(t, "/v1/_admin/replay/sampling", adminToken); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET sampling 应 405，实际 %d: %s", resp.StatusCode, raw)
	}

	// 指针语义：只调比例时，已开的开关与已设的范围过滤都不动。
	enabled := true
	permille := 50
	scope := "alice"
	h.srv.replayWin.configure(&enabled, &permille, &scope, nil)
	if code, body := adminPostRaw(t, h, "/v1/_admin/replay/sampling",
		map[string]any{"sample_permille": 70}); code != http.StatusOK {
		t.Fatalf("改比例应 200，实际 %d: %v", code, body)
	}
	if st := h.srv.replayWin.stats(); st["enabled"] != true || st["sample_permille"] != 70 ||
		st["scope_filter"] != "alice" {
		t.Fatalf("只改比例却动了别的开关: %+v", st)
	}

	// 状态口只报计数与配置：记录级的归属（subject）与 request_id 都不出。
	// scope_filter 里那个名字是管理员自己设的过滤条件，属于 §2.9 允许出现的「范围」；
	// 会泄露的是「窗口里那条记录描述了谁」——那只有导出那份文件知道。
	pop := policyAdminHarness(t, "enforce")
	openReplayWindow(t, pop)
	mallory := pop.addUser(t, "mallory")
	pop.addProvider(t, "mallory", "own", "http://127.0.0.1:9/v1", "sk-mallory", `["*"]`)
	chatWith(t, pop.harness, mallory, "leak-check-1", "gpt-x") // 上游必然连不上，判定照样发生
	if _, st := adminJSON(t, pop, "/v1/_admin/replay"); st["entries"] != float64(1) {
		t.Fatalf("窗口里应有那条记录: %+v", st)
	}
	code, status := adminJSON(t, pop, "/v1/_admin/replay")
	if code != http.StatusOK {
		t.Fatalf("状态口应 200，实际 %d", code)
	}
	rawStatus, _ := json.Marshal(status)
	for _, banned := range []string{"mallory", "leak-check-1", `"subject"`} {
		if strings.Contains(string(rawStatus), banned) {
			t.Errorf("状态口暴露了记录级内容 %q: %s", banned, rawStatus)
		}
	}
	if status["bit_exact_primary_order"] != true {
		t.Errorf("带快照的记录已能逐位复现，状态口还声称不能: %v", status["bit_exact_primary_order"])
	}
	if status["sampling_algo_declared"] != replaySamplingAlgoOnline ||
		status["sampling_algo_replay_default"] != replay.SamplingAlgoReplayV1 {
		t.Errorf("两个抽样算法标识都要摊开: %s", rawStatus)
	}
	// 「能逐位」必须附条件：逐位只属于 v2 带快照的记录，窗口里混进 v1 或导入的老记录时
	// 那一条照样只能解释性回放。只回一个 true 会比原来的 false 更误导。
	cond, _ := status["bit_exact_condition"].(string)
	for _, want := range []string{"schema_version", "replay_snapshot", "只做解释性回放", replaySamplingAlgoOnline} {
		if !strings.Contains(cond, want) {
			t.Errorf("逐位条件里少了 %q: %q", want, cond)
		}
	}
	if algos, _ := status["bit_exact_algos"].([]any); len(algos) != 1 ||
		algos[0] != replaySamplingAlgoOnline {
		t.Errorf("逐位算法集合应当由 D 摊开且只含线上那条: %v", status["bit_exact_algos"])
	}
	// 版本口径：写出的是 v2，可读的是 v1+v2 —— 运维据此判断旧文件还能不能直接回放。
	if status["record_schema_version"] != float64(replay.SchemaVersion) {
		t.Errorf("写出版本应是 %d: %v", replay.SchemaVersion, status["record_schema_version"])
	}
	readable, _ := status["record_schema_version_readable"].([]any)
	if len(readable) != len(replay.ReadableSchemaVersions()) {
		t.Fatalf("可读版本清单和解码器口径不一致: %v vs %v",
			readable, replay.ReadableSchemaVersions())
	}

	// 非 enforce 时状态口要说破「窗口不会采到东西」，而不是让运维盯着空窗口猜原因。
	shadow := policyAdminHarness(t, "shadow")
	if _, st := adminJSON(t, shadow, "/v1/_admin/replay"); st["warning"] == nil {
		t.Errorf("shadow 下状态口缺 warning")
	}

	// 三个写侧动作都落审计并带范围（§2.7 规则 2）。
	// 这里顺带把上面为测指针语义设上的 alice 过滤清掉：清过滤同样是显式传字段。
	if code, body := adminPostRaw(t, h, "/v1/_admin/replay/sampling",
		map[string]any{"enabled": true, "sample_permille": 1000, "scope": ""}); code != http.StatusOK {
		t.Fatalf("开采集应 200，实际 %d: %v", code, body)
	}
	if st := h.srv.replayWin.stats(); st["scope_filter"] != "" {
		t.Fatalf("显式传空 scope 应清掉过滤: %+v", st)
	}
	if code, raw := chatWith(t, h.harness, "sk-static", "audit-1", "gpt-x"); code != http.StatusOK {
		t.Fatalf("请求应 200，实际 %d: %s", code, raw)
	}
	if _, exportRaw := replayExport(t, h, ""); !strings.Contains(string(exportRaw), "audit-1") {
		t.Fatalf("导出里没有那条请求: %s", exportRaw)
	}
	if code, body := adminPostRaw(t, h, "/v1/_admin/replay/clear", nil); code != http.StatusOK {
		t.Fatalf("清空应 200，实际 %d: %v", code, body)
	}
	by := auditByAction(t, h)
	for _, action := range []string{"replay.sampling.set", "replay.export", "replay.clear"} {
		entries := by[action]
		if len(entries) == 0 {
			t.Fatalf("%s 没落审计", action)
		}
		for _, e := range entries {
			// 采集配置是全局面，归属取 policy.SystemScope（system:global），
			// 断言跟着常量走而不是钉字符串：将来范围口径调整时这里要一起红。
			if e.Scope != policy.SystemScope {
				t.Errorf("%s 的审计范围应是 %s，实际 %s", action, policy.SystemScope.Display(), e.Scope.Display())
			}
			if strings.Contains(strings.ToLower(e.Detail), "sk-") {
				t.Errorf("%s 的审计说明里出现了密钥: %s", action, e.Detail)
			}
		}
	}
	// clear 只清记录与计数，不动开关：拿走这批证据不该顺手关掉观测面。
	if st := h.srv.replayWin.stats(); st["enabled"] != true || st["sample_permille"] != 1000 {
		t.Fatalf("clear 动了开关: %+v", st)
	}
	// 未知子路径要给出可用路径清单，而不是空 body 的 404。
	resp, raw := h.get(t, "/v1/_admin/replay/whatever", adminToken)
	if resp.StatusCode != http.StatusNotFound ||
		!strings.Contains(string(raw), "/v1/_admin/replay/export") {
		t.Errorf("未知子路径处理不对: %d %s", resp.StatusCode, raw)
	}
}

func TestReplay30StatusReportsAsOfAndCounters(t *testing.T) {
	h := policyAdminHarness(t, "enforce")
	fixed := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	h.srv.nowFn = func() time.Time { return fixed }

	on := true
	permille := 100
	h.srv.replayWin.configure(&on, &permille, nil, nil)
	code, st := adminJSON(t, h, "/v1/_admin/replay")
	if code != http.StatusOK {
		t.Fatalf("状态口应 200，实际 %d", code)
	}
	if st["as_of"] != fixed.Format("2006-01-02T15:04:05Z07:00") {
		t.Errorf("as_of 没跟着服务时钟走: %v", st["as_of"])
	}
	if st["enabled"] != true || st["sample_permille"] != float64(100) {
		t.Errorf("状态口没如实报出配置: %v", st)
	}
	if st["mode"] != "enforce" || st["running"] != true {
		t.Errorf("状态口要能看出 3.0 此刻确实在参与判定: %v", st)
	}
	if st["note"] == nil || !strings.Contains(st["note"].(string), "enforce") {
		t.Errorf("状态口要说明这批记录采集自哪个接线阶段: %v", st["note"])
	}

	// 采集失败是要数得出来的数：静默失败时运维看到的是「比线上少几条」，
	// 而没有任何地方说为什么。所以「构造记录失败」必须一路数到状态口。
	rt := h.srv.policyFor(h.srv.cfgStore.Current())
	if rt == nil {
		t.Fatal("enforce 夹具应有 3.0 运行态")
	}
	chain, err := policyChainFor("")
	if err != nil {
		t.Fatal(err)
	}
	res, _, err := rt.resolverFor(chain)
	if err != nil {
		t.Fatal(err)
	}
	full := replayPermilleFull
	h.srv.replayWin.configure(&on, &full, nil, nil)
	// 故意喂一个没有身份的现场：DecisionRecordFrom 必然拒绝（subject 为空），
	// 而请求结果绝不能因此变差 —— 采集只是观测面。
	h.srv.captureReplay(rt, "alice", "bad-1", &policyShot{
		Version:  "t-open@1",
		Applied:  true,
		res:      res,
		judgeNow: fixed,
	})
	if got := h.srv.replayWin.stats()["failed"]; got != int64(1) {
		t.Fatalf("构造失败没进 failed 计数: %v", got)
	}
	if _, st := adminJSON(t, h, "/v1/_admin/replay"); st["failed"] != float64(1) {
		t.Errorf("failed 计数没进状态口: %v", st["failed"])
	}
}

// ── A 包不变量与回放比对的冲突位（登记给主线裁决，不伪装成已完成） ──────────

// policyBundleDenyWithRawGrant 拒绝 secret-model，却同时授了一条**带期限**的原文出网。
// 两者按 A 包是不同资源的独立判定（model:<名>/use 与 body.raw/read），所以这套包合法，
// 而它正好落在记录 schema 与回放比对的冲突点上。
const policyBundleDenyWithRawGrant = `
id: t-open
version: 1
scope: system:gateway
entitlements:
  - subject: "*"
    resource: "model:*"
    action: use
    effect: allow
  - subject: "*"
    resource: "model:secret-model"
    action: use
    effect: deny
  - subject: gateway
    resource: "body.raw"
    action: read
    effect: allow
    expires_at: "2030-01-01T00:00:00Z"
`

// TestReplay30DenyEvidenceAndRawBodyGrantConflict 把那条冲突钉成会失败的断言。
//
// 冲突的两端都是冻结口径：DecisionRecord.Validate 钉死「拒绝的结论不可能授予原文出网」，
// 所以采集侧对一次 deny 只能写 false（replay30.go 里那个 if 不是偷懒）；而
// ReplayDecision 无条件重跑 AllowsRawBody 并把这一位比进差异。AllowsRawBody 判的是
// **另一个资源**，它与本次结论允许与否无关 —— 于是「带原文授权的范围里发生的一次真实拒绝」
// 在回放里必然报成差异，而这份差异既不是策略变了也不是记录坏了。
//
// 这不是接线能单方面修的：改 A 的不变量会放宽 §2.9 的隐私闸门，改比对要动冻结的回放核。
// 断言锁住**今天的真实形态**（差异、且只有这一位差），将来主线给出「拒绝时跳过这一位」
// 或「拒绝记录不得进入比对」的口径时，这条会红并要求重写，而不是让一个假差异长期混在
// 回放报告里被当成「策略动过」。
func TestReplay30DenyEvidenceAndRawBodyGrantConflict(t *testing.T) {
	h := policyAdminHarnessBundles(t, "enforce", "t-open", "system:gateway", 1, policyBundleDenyWithRawGrant)
	openReplayWindow(t, h)

	if code, _ := chatWith(t, h.harness, "sk-static", "conflict-1", "secret-model"); code != http.StatusForbidden {
		t.Fatalf("secret-model 应被拒绝（403），实际 %d", code)
	}
	_, raw := replayExport(t, h, "")
	f := mustDecodeRecords(t, raw)
	if len(f.Decisions) != 1 {
		t.Fatalf("应恰好 1 条判定证据，实际 %d", len(f.Decisions))
	}
	rec := f.Decisions[0]
	if rec.Effect != policy.EffectDeny {
		t.Fatalf("该记成 deny，实际 %s", rec.Effect)
	}
	// 采集侧现算的那一位在 deny 上被不变量压成 false（否则 Decode 之前就 Validate 失败）。
	if rec.ExternalPlaintextAllowed {
		t.Fatalf("deny 记录里不能带原文出网授权")
	}

	// 同一套包（版本对得上，所以不会被拒绝回放）重跑：AllowsRawBody 判 body.raw，
	// 与 model:secret-model 的 deny 无关，于是算出 true —— 差异只出现在这一位。
	report := replayFromDisk(t, mustBundles(t, h), raw, time.Now().UTC().Add(time.Minute))
	passed, mismatch, rejected := report.Counts()
	if rejected != 0 {
		t.Fatalf("版本一致，不该走拒绝回放: %d\n%s", rejected, report)
	}
	if mismatch != 1 || passed != 0 {
		t.Fatalf("今天的形态是「只有这一位报差异」，实际 passed=%d mismatch=%d\n%s", passed, mismatch, report)
	}
	var fields []string
	for _, o := range report.Outcomes {
		for _, d := range o.Diffs {
			fields = append(fields, d.Field)
		}
	}
	if strings.Join(fields, ",") != "external_plaintext_allowed" {
		t.Fatalf("差异字段应只有 external_plaintext_allowed，实际 %v\n%s", fields, report)
	}
}
