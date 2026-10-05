package server

// 裁决 17′ 的红灯：状态接口逐条端出「这条声明到底装起来没有」。
//
// 这一包要钉住的故障形态很具体 —— 声明写得合法（能过配置校验）、但运行参数文件缺失，
// 于是它进了配置、进了界面，却从没进注册表；过去这个缺口只有一行 ERROR 日志，
// 要到第一次命中它的请求才被拒。断言因此集中在三件事：
//   1. 装不起来的**那一条**被点名（名字 + 装配当时记下的拒因），别的条不受牵连；
//   2. 补上缺的东西、热加载之后同一条读数变绿（不是新增一条记录）；
//   3. 3.0 运行态根本没建立时**不给每条声明盖「失败」**——那是段级原因。

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// assemblyOf 从 /v1/_admin/policy 的响应里取 assembly 块，并校验它的形状。
//
// 用 JSON 往返而不是类型断言链：这一格的全部价值就是「界面读得到」，
// 断言走一遍序列化正好把管理台实际读到的那个形状钉住。
func assemblyOf(t *testing.T, h *muHarness) map[string]any {
	t.Helper()
	code, out, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/policy", adminToken, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/_admin/policy = %d: %s", code, raw)
	}
	a, ok := out["assembly"]
	if !ok {
		t.Fatalf("状态接口没有 assembly 块（裁决 17′ 的红灯没接线）: %s", raw)
	}
	buf, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var blk map[string]any
	if err := json.Unmarshal(buf, &blk); err != nil {
		t.Fatal(err)
	}
	return blk
}

// sectionOf 取某一段的装配汇总；absent 为 true 表示这段压根没有逐条读数。
func sectionOf(t *testing.T, blk map[string]any, key string) map[string]any {
	t.Helper()
	sec, ok := blk[key]
	if !ok {
		t.Fatalf("assembly 缺 %s 段", key)
	}
	buf, _ := json.Marshal(sec)
	var out map[string]any
	if err := json.Unmarshal(buf, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func declByName(t *testing.T, sec map[string]any, name string) map[string]any {
	t.Helper()
	list, _ := sec["declarations"].([]any)
	for _, item := range list {
		d, _ := item.(map[string]any)
		if d["name"] == name {
			return d
		}
	}
	t.Fatalf("%s 段里没有名为 %s 的声明读数：%v", sec, name, list)
	return nil
}

func countOf(sec map[string]any, key string) int {
	n, _ := sec[key].(float64)
	return int(n)
}

// 一条合法但装不起来的声明 ⇒ 红灯 + 点名拒因；补上参数文件 ⇒ 绿。
func TestAssembly30NamesFailedDeclarationAndRecovers(t *testing.T) {
	h := publishHarness(t, "enforce")

	// 两条声明：pii-mask 有内置默认（不需要参数文件），http-sidecar 必须有。
	// 只让 sidecar 缺文件 —— 「一条坏声明不该让整条链消失」正是这里要的形态。
	body := map[string]any{"processors": []any{
		declProc("pii-cn", "before-upstream"),
		declSidecar("sc-1"),
	}}
	if code, out, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken, body); code != http.StatusOK {
		t.Fatalf("PUT processors = %d: %s（%v）", code, raw, out)
	}
	reloadConfig(t, h)

	blk := assemblyOf(t, h)
	if blk["running"] != true {
		t.Fatalf("running = %v，want true（%v）", blk["running"], blk)
	}
	proc := sectionOf(t, blk, "processors")
	if countOf(proc, "declared") != 2 {
		t.Errorf("processors.declared = %d，want 2", countOf(proc, "declared"))
	}
	if countOf(proc, "failed") != 1 || countOf(proc, "assembled") != 1 {
		t.Errorf("装配汇总 = 好 %d / 坏 %d，want 1/1", countOf(proc, "assembled"), countOf(proc, "failed"))
	}

	bad := declByName(t, proc, "sc-1")
	if bad["status"] != assemblyFailed {
		t.Errorf("sc-1 status = %v，want %s（缺参数文件必须点名）", bad["status"], assemblyFailed)
	}
	reason, _ := bad["reason"].(string)
	// 拒因必须指到能动手的地方：装配当时记下的那句话带着参数文件路径。
	if !strings.Contains(reason, "sc-1.json") || !strings.Contains(reason, procParamDirName) {
		t.Errorf("sc-1 拒因没点名到运行参数文件: %q", reason)
	}
	if got := declByName(t, proc, "pii-cn"); got["status"] != assemblyAssembled {
		t.Errorf("pii-cn status = %v，want %s（一条坏声明不该牵连别的）", got["status"], assemblyAssembled)
	}

	// 先只补参数文件、不动配置：运行态没换修订，读数必须**仍然红**。
	// 这一条不是缺陷汇报，是把语义钉住 —— 红灯跟着「进程真的重装配过」走，
	// 不跟着磁盘上多出来的一个文件走。让它看一眼文件就变绿，等于界面说「装好了」
	// 而注册表里还是空的，那正是这一包要消灭的那类误差。
	paramsDir := filepath.Join(filepath.Dir(h.configPath), procParamDirName)
	if err := os.MkdirAll(paramsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// sidecar 的端点必须与声明里的出网白名单逐字对上（E 包在注册期核对）。
	if err := os.WriteFile(filepath.Join(paramsDir, "sc-1.json"),
		[]byte(`{"endpoint":"https://sidecar.internal/v1/rewrite"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if sec := sectionOf(t, assemblyOf(t, h), "processors"); countOf(sec, "failed") != 1 {
		t.Errorf("只补参数文件、配置修订未变时就该还是红的，实际 failed=%d", countOf(sec, "failed"))
	}

	// 修好：走一次真正的重装配（改一下配置让修订换代，与运营者补完文件后的动作一致）。
	// 同一个声明名从 failed 变 assembled，而不是新增一条读数 —— 这也是「不落库」的反面证据。
	fixed := declSidecar("sc-1")
	fixed["timeout_ms"] = 1300
	body2 := map[string]any{"processors": []any{declProc("pii-cn", "before-upstream"), fixed}}
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken, body2); code != http.StatusOK {
		t.Fatalf("第二次 PUT processors = %d: %s", code, raw)
	}
	reloadConfig(t, h)

	proc = sectionOf(t, assemblyOf(t, h), "processors")
	if countOf(proc, "failed") != 0 || countOf(proc, "assembled") != 2 {
		t.Errorf("补好参数文件后 = 好 %d / 坏 %d，want 2/0（%v）",
			countOf(proc, "assembled"), countOf(proc, "failed"), proc["declarations"])
	}
	if got := declByName(t, proc, "sc-1"); got["status"] != assemblyAssembled {
		t.Errorf("sc-1 status = %v，want %s", got["status"], assemblyAssembled)
	}
	// 这一句是 §7 完成判据里「要写在面板说明里」的那条，接口上也得能读出来：
	// 面板文案会随界面改，读数语义不该跟着漂。
	note, _ := blk["note"].(string)
	if !strings.Contains(note, "不落库") || !strings.Contains(note, "重启") {
		t.Errorf("assembly.note 没写清运行态语义: %q", note)
	}
}

// legacy 下不给每条声明盖「失败」：那是段级原因，不是 N 条各自的毛病。
func TestAssembly30NotRunReportsSectionLevelReason(t *testing.T) {
	h := publishHarness(t, "") // 没有 policy 段 = legacy
	body := map[string]any{"processors": []any{declProc("pii-cn", "before-upstream"), declSidecar("sc-1")}}
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken, body); code != http.StatusOK {
		t.Fatalf("PUT processors = %d: %s", code, raw)
	}
	reloadConfig(t, h)

	blk := assemblyOf(t, h)
	if blk["running"] != false {
		t.Fatalf("running = %v，want false（legacy 没有运行态）", blk["running"])
	}
	if blk["reason"] != "policy_mode_legacy" {
		t.Errorf("reason = %v，want policy_mode_legacy（复用已有状态词，不新造）", blk["reason"])
	}
	for _, key := range []string{"processors", "knowledge_sources"} {
		sec := sectionOf(t, blk, key)
		if _, bad := sec["declarations"]; bad {
			t.Errorf("%s 在没装配时给出了逐条读数：%v（段级原因不该复制成每条声明的结论）", key, sec["declarations"])
		}
	}
	// 声明条数仍然要说得出：legacy 下运营者要知道「磁盘上有几条等着生效」。
	if got := countOf(sectionOf(t, blk, "processors"), "declared"); got != 2 {
		t.Errorf("legacy 下 processors.declared = %d，want 2", got)
	}
}

// 知识源那一段与处理器共用同一套读数形状（名字 + 两态 + 拒因）。
//
// 端点形态在配置加载期就被 knowledge.ValidateEndpoint 拒掉了，所以「声明合法却装不起来」
// 这一支在真配置里只剩 transport 不可用那条路；那条要造出网状态，代价与收益不成比，
// 这里直接钉视图映射：src.err 非空 ⇒ failed + 原话，空 ⇒ assembled。
func TestAssembly30KnowledgeSectionMapping(t *testing.T) {
	rt := &policyRuntime{kb: &knowledgeRuntime{sources: []*knowledgeSource{
		{name: "campus-rag"},
		{name: "broken", err: "委托客户端装配失败: 示例原因"},
	}}}
	sec := knowledgeAssemblySection(&config.Config{}, rt)
	if sec.Declared != 2 || sec.Assembled != 1 || sec.Failed != 1 {
		t.Errorf("汇总 = %+v/%+v/%+v，want 2/1/1", sec.Declared, sec.Assembled, sec.Failed)
	}
	for _, d := range sec.Declarations {
		switch d.Name {
		case "broken":
			if d.Status != assemblyFailed || !strings.Contains(d.Reason, "示例原因") {
				t.Errorf("broken 读数 = %+v，want failed + 装配当时的原话", d)
			}
		case "campus-rag":
			if d.Status != assemblyAssembled || d.Reason != "" {
				t.Errorf("campus-rag 读数 = %+v，want assembled 且无拒因", d)
			}
		default:
			t.Errorf("多出一条声明读数：%+v", d)
		}
	}

	// 没有 kb 段时是零声明，而不是「全失败」—— 最常见形态必须读起来是空的。
	if got := knowledgeAssemblySection(&config.Config{}, &policyRuntime{}); got.Declared != 0 ||
		got.Failed != 0 || got.Declarations != nil {
		t.Errorf("无知识源 = %+v，want 空汇总", got)
	}
	// cfg 里有声明而运行态没建立时，只报条数不报逐条结果。
	if got := knowledgeAssemblySection(&config.Config{KnowledgeSources: []config.KnowledgeSourceDef{{Name: "x"}}}, nil); got.Declared != 1 ||
		got.Failed != 0 || got.Declarations != nil {
		t.Errorf("运行态未建立 = %+v，want declared 1 且无逐条读数", got)
	}
}

// 状态接口不新增暴露面：assembly 与其余字段一样只认 admin_token。
//
// 拒因里带着运行参数目录的绝对路径与内部端点，这些不是给普通 API key 看的 ——
// 裁决要的是「管理台看得见」，不是「所有人都看得见」。
func TestAssembly30StaysAdminOnly(t *testing.T) {
	h := publishHarness(t, "enforce")
	for _, token := range []string{"sk-wrong", ""} {
		code, _, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/policy", token, nil)
		if code != http.StatusForbidden {
			t.Errorf("token=%q 时 GET /v1/_admin/policy = %d，want 403: %s", token, code, raw)
		}
	}
}

// 「不落库」是判据，不是一句注释：读三次状态接口，库里一行都不许多。
//
// 最省事的破法是在装配失败那几条上「顺手落一条审计」—— 看起来更安全，实际把
// 一个每次刷新都会读的只读面变成了写面（管理台自动刷新 = 持续往 audit_log 灌行，
// 而这张表按裁决 15′ 永久保留）。这条用例就是那句「顺手」的锁。
func TestAssemblyInspectWritesNothing(t *testing.T) {
	h := publishHarness(t, "enforce")
	body := map[string]any{"processors": []any{declSidecar("sc-1")}}
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken, body); code != http.StatusOK {
		t.Fatalf("PUT processors = %d: %s", code, raw)
	}
	reloadConfig(t, h)

	// 先落一条已知的审计行，免得「空表读三次还是空表」被误当成通过。
	if err := h.db.AuditScope(policy.SystemScope, "admin", "policy.inspect", "scope:gateway", `{"why":"baseline"}`); err != nil {
		t.Fatal(err)
	}
	before, err := h.db.AuditVolume()
	if err != nil {
		t.Fatal(err)
	}

	// 故意读装配失败的那一版：最容易「顺手记一笔」的就是这条路径。
	for i := 0; i < 3; i++ {
		blk := assemblyOf(t, h)
		if sec := sectionOf(t, blk, "processors"); countOf(sec, "failed") != 1 {
			t.Fatalf("第 %d 次读到的装配失败条数 = %d，want 1", i+1, countOf(sec, "failed"))
		}
	}

	after, err := h.db.AuditVolume()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("读状态接口把审计写出了变化：%+v → %+v（assembly 是运行态读数，不落库）", before, after)
	}
}
