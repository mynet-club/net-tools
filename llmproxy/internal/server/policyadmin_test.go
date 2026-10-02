package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/secrets"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// §3.H 管理口第一步（策略查看 / 路由模拟 / 决策痕迹）的测试。
//
// 断言的重心在两件事：
//  1. **无副作用**：模拟比影子更要「一点痕迹都不留」。§3.0 的线 1 一旦被违反，
//     差异报告里的一致率就掺进人为流量，整个 shadow→enforce 的判据失效。
//  2. **不外泄**：可见性端点自己就是新的泄露面。Conditions 的值、上游 base_url、
//     密钥都不该出现在响应里（§2.9 规则 6、§5）。

// policyAdminHarness 起一个多用户 + 带策略包的网关。
//
// 上游用 mock 替掉 multiUserYAML 里那家「永远连不上」的：痕迹落库要一条**成功**请求，
// 而失败请求的 seed 同样该被记录 —— 两种都能测，但先用成功的那条把主路径钉住。
// mode 为空表示不写 policy 段（整套按 legacy 跑）。
func policyAdminHarness(t *testing.T, mode string) *muHarness {
	t.Helper()
	if mode == "" {
		return policyAdminHarnessBundles(t, "", "", "", 1, "")
	}
	return policyAdminHarnessBundles(t, mode, "t-open", "system:gateway", 1, policyBundleOpen)
}

// policyAdminHarnessBundles 是上面那个的完整版：策略段的 id / 范围 / 内容都可以换，
// 因为「哪个范围没被任何包覆盖」只能用组织范围的包来造（system 包按定义覆盖所有链）。
func policyAdminHarnessBundles(t *testing.T, mode, id, scope string, version int, content string) *muHarness {
	t.Helper()
	up := startMockUpstream(t, &mockUpstream{name: "live", apiKey: "sk-global"})
	src := strings.ReplaceAll(multiUserYAML, "http://127.0.0.1:9/v1", up.baseURL)
	if mode != "" {
		// 启用 3.0 后配置加载会逐家要求声明分级上限（§2.3：未声明不能按最宽松处理），
		// 夹具必须给出这一事实，否则整套测试连配置都读不进来。
		src = strings.ReplaceAll(src, `    models: ["*"]`,
			"    max_data_level: internal\n    models: [\"*\"]")
		src += policySection(mode, id, scope, version)
	}
	h := newHarness(t, src)
	cipher, err := secrets.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h.srv.WithSecrets(cipher)
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}
	if content != "" {
		writePolicyBundle(t, h, content)
	}
	return &muHarness{harness: h, cipher: cipher}
}

// chatWith 发一条真实转发请求（token 可换：自助用户用各自的 token，静态 key 用 api_keys 里的）。
func chatWith(t *testing.T, h *harness, token, requestID, model string) (int, []byte) {
	t.Helper()
	payload := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}]}`, model)
	req, err := http.NewRequest(http.MethodPost, h.gateway.URL+"/v1/chat/completions", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Request-Id", requestID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func jsonMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("响应不是 JSON: %v\n%s", err, raw)
	}
	return out
}

// simulate 跑一次路由模拟并返回响应。
func simulate(t *testing.T, h *muHarness, body map[string]any) (int, map[string]any) {
	t.Helper()
	resp, raw := h.post(t, "/v1/_admin/policy/simulate", adminToken, body)
	return resp.StatusCode, jsonMap(t, raw)
}

// adminJSON 走 GET 管理口（adminGet 返回的是原始字节，这里统一解码）。
func adminJSON(t *testing.T, h *muHarness, path string) (int, map[string]any) {
	t.Helper()
	code, raw := adminGet(t, h, path)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return code, nil
	}
	return code, out
}

func TestAdminPolicyRequiresAdminToken(t *testing.T) {
	h := policyAdminHarness(t, "shadow")
	for _, path := range []string{"/v1/_admin/policy", "/v1/_admin/policy/trace?request_id=x"} {
		resp, raw := h.get(t, path, "sk-wrong")
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s 用错 token 应 403，实际 %d: %s", path, resp.StatusCode, raw)
		}
	}
	// POST 到没有写侧的路径上必须是 405 而不是「静默成功」：可见性端点一旦被
	// 当成配置入口，运维就会信一个根本不落库的 PUT。
	resp, raw := h.post(t, "/v1/_admin/policy", adminToken, map[string]any{"mode": "enforce"})
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT 策略应 405（写侧不在这里），实际 %d: %s", resp.StatusCode, raw)
	}
	resp, raw = h.post(t, "/v1/_admin/policy/unknown", adminToken, map[string]any{})
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(raw), "/v1/_admin/policy/simulate") {
		t.Errorf("未知子路径应 404 并列出可用路径，实际 %d: %s", resp.StatusCode, raw)
	}
}

func TestAdminPolicyInspectLegacy(t *testing.T) {
	h := policyAdminHarness(t, "")
	code, body := adminJSON(t, h, "/v1/_admin/policy")
	if code != http.StatusOK {
		t.Fatalf("GET /policy = %d: %v", code, body)
	}
	if body["mode"] != "legacy" {
		t.Errorf("mode = %v，want legacy", body["mode"])
	}
	if body["running"] != false {
		t.Errorf("legacy 下 running 必须为 false，实际 %v", body["running"])
	}
	if body["inactive_reason"] != "policy_mode_legacy" {
		t.Errorf("要说清为什么没在效，实际 %v", body["inactive_reason"])
	}
	if v, ok := body["policy_version"]; !ok || v != "" {
		t.Errorf("legacy 下策略版本必须是空串，实际 %v (present=%v)", v, ok)
	}
	if body["config_schema_version"] != float64(config.SchemaVersionLegacy) {
		t.Errorf("config_schema_version = %v，want %d（没写过就按 2 处理）",
			body["config_schema_version"], config.SchemaVersionLegacy)
	}
}

// 显式停在 legacy 与「根本没有 policy 段」是两件事，declared_data_level 就是用来
// 把它们分开的：legacy 下参与判定的分级必然是 unknown（服务端不许替配置猜一级），
// 但配置里那一行确实写着 internal。只报生效值，管理台会对已经决定过分级的部署
// 说「unknown」，于是运维去重填一个本已定好的值。
func TestAdminPolicyInspectDistinguishesTwoLegacyFlavors(t *testing.T) {
	h := policyAdminHarnessBundles(t, "legacy", "t-open", "system:gateway", 1, policyBundleOpen)
	code, body := adminJSON(t, h, "/v1/_admin/policy")
	if code != http.StatusOK {
		t.Fatalf("GET /policy = %d: %v", code, body)
	}
	if body["running"] != false || body["inactive_reason"] != "policy_mode_legacy" {
		t.Fatalf("legacy 下不该在跑，实际 running=%v reason=%v",
			body["running"], body["inactive_reason"])
	}
	if body["configured_mode"] != "legacy" {
		t.Errorf("configured_mode = %v，want legacy（YAML 里写了这一行）", body["configured_mode"])
	}
	if body["data_level"] != "unknown" {
		t.Errorf("data_level = %v，want unknown：legacy 没有判定输入，不许按声明值假装在分级",
			body["data_level"])
	}
	if body["declared_data_level"] != "internal" {
		t.Errorf("declared_data_level = %v，want internal：配置里声明的那一行要如实报出",
			body["declared_data_level"])
	}

	// 核对视图与只读口同口径 —— 发布表单预置的「不改（当前 X）」读的就是这一份。
	_, pb := adminJSON(t, h, "/v1/_admin/policy/bundles")
	if pb["declared_data_level"] != "internal" {
		t.Errorf("bundles 视图 declared_data_level = %v，want internal", pb["declared_data_level"])
	}

	// 真的没写 policy 段时声明值是 '-'：两种 legacy 必须能从字段上分得开。
	_, none := adminJSON(t, policyAdminHarness(t, ""), "/v1/_admin/policy")
	if none["declared_data_level"] != "-" || none["configured_mode"] != "-" {
		t.Errorf("没有 policy 段的部署应两个字段都是 '-'，实际 %v / %v",
			none["declared_data_level"], none["configured_mode"])
	}
}

func TestAdminPolicyInspectShadow(t *testing.T) {
	h := policyAdminHarness(t, "shadow")
	code, body := adminJSON(t, h, "/v1/_admin/policy")
	if code != http.StatusOK {
		t.Fatalf("GET /policy = %d: %v", code, body)
	}
	if body["running"] != true || body["mode"] != "shadow" {
		t.Fatalf("running/mode = %v/%v", body["running"], body["mode"])
	}
	if body["policy_version"] != "t-open@1" {
		t.Errorf("policy_version = %v，want t-open@1", body["policy_version"])
	}
	if body["data_level"] != "internal" {
		t.Errorf("data_level = %v，want internal（部署显式声明的那一级）", body["data_level"])
	}
	if body["routing_epoch"] != "rev-1" {
		t.Errorf("routing_epoch = %v，want rev-1（seed 的第三个输入，缺了就没人能复现）", body["routing_epoch"])
	}
	// 写了 policy 段不等于结构版本就是 3：版本是运维显式声明的升级动作（缺省按 2 加载，
	// 见 config.normalizeSchemaVersion），查看口必须如实报出「文件里写的是几」而不是猜。
	if body["config_schema_version"] != float64(config.SchemaVersionLegacy) {
		t.Errorf("config_schema_version = %v，want %d（没显式写就还是 2）",
			body["config_schema_version"], config.SchemaVersionLegacy)
	}
	refs, _ := body["declared_bundles"].([]any)
	if len(refs) != 1 {
		t.Fatalf("declared_bundles = %v", body["declared_bundles"])
	}
	bundles, _ := body["bundles"].([]any)
	if len(bundles) != 1 {
		t.Fatalf("bundles = %v", body["bundles"])
	}
	first := bundles[0].(map[string]any)
	if first["stamp"] != "t-open@1" || first["scope_kind"] != "system" || first["scope_id"] != "gateway" {
		t.Errorf("包视图不完整: %v", first)
	}
	rules, _ := first["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("规则数 = %d，want 2: %v", len(rules), rules)
	}
	// 规则只以选择器现身
	if r := rules[1].(map[string]any); r["effect"] != "deny" || r["resource"] != "model:secret-model" {
		t.Errorf("deny 规则视图不对: %v", r)
	}
	if _, ok := body["shadow"]; !ok {
		t.Error("查看口要能一眼看到影子计数")
	}
}

// 策略包坏了不能只报「没在效」：mode 仍然是 shadow，请求路径按 legacy 静默跑，
// 运维必须能在管理台看到那一句加载错误。
func TestAdminPolicyInspectReportsLoadFailure(t *testing.T) {
	h := policyAdminHarness(t, "shadow")
	dir := filepath.Join(filepath.Dir(h.configPath), config.DefaultBundleDir)
	// version: 0 过不了 PolicyBundle.Validate（版本从 1 起，回放要靠它确认同一份内容）
	if err := os.WriteFile(filepath.Join(dir, "t-open.yaml"),
		[]byte("id: t-open\nversion: 0\nscope: system:gateway\nentitlements: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 换配置修订：旧修订的失败结论是按修订号记住的（policyFor），改一次修订才会重读目录。
	// 修订号只在配置内容真的变了才前进（configEqual），而策略包内容不在配置里 ——
	// 这里改一行无关字段来触发重读，真实运维同样是「改配置 → 热加载」。
	if err := os.WriteFile(h.configPath,
		[]byte(strings.Replace(h.cfgYAML, "retry: 1", "retry: 2", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, _, err := h.cfgStore.Reload()
	if err != nil {
		t.Fatalf("Reload 应容忍坏的策略包内容（内容加载在运行态做）: %v", err)
	}
	if !changed {
		t.Fatal("Reload 没换修订，看不到新的加载结论")
	}
	code, body := adminJSON(t, h, "/v1/_admin/policy")
	if code != http.StatusOK {
		t.Fatalf("GET /policy = %d: %v", code, body)
	}
	if body["running"] != false || body["inactive_reason"] != "policy_load_failed" {
		t.Fatalf("加载失败要如实报出：running=%v reason=%v", body["running"], body["inactive_reason"])
	}
	errStr, _ := body["load_error"].(string)
	if errStr == "" {
		t.Error("load_error 必须带原因串，否则运维只能去翻日志")
	}
	if body["policy_version"] != "" {
		t.Errorf("加载失败却报着版本号 = %v，健康检查与查看必须一致地清零", body["policy_version"])
	}
}

func TestAdminPolicySimulateAllowAndDeny(t *testing.T) {
	h := policyAdminHarness(t, "shadow")
	before := shadowStats(t, h.harness)

	code, ok := simulate(t, h, map[string]any{"scope": "", "model": "gpt-x", "request_id": "sim-1"})
	if code != http.StatusOK {
		t.Fatalf("simulate = %d: %v", code, ok)
	}
	decision, _ := ok["decision"].(map[string]any)
	if decision["allowed"] != true {
		t.Errorf("gpt-x 应被放行: %v", decision)
	}
	if ok["policy_version"] != "t-open@1" || ok["mode"] != "shadow" {
		t.Errorf("版本/模式 = %v/%v", ok["policy_version"], ok["mode"])
	}
	if ok["scope_chain"] != "system:gateway" {
		t.Errorf("scope_chain = %v", ok["scope_chain"])
	}
	if ok["purpose"] != "chat" || ok["identity"] != policySourceStatic {
		t.Errorf("purpose/identity = %v/%v", ok["purpose"], ok["identity"])
	}
	// 候选池与计划必须都摆出来：只给结论不给池子的话，「为什么选了它」还是没法回答。
	cands, _ := ok["candidates"].([]any)
	if len(cands) == 0 {
		t.Fatal("候选池为空，模拟等于没跑")
	}
	seed, _ := ok["routing_seed"].(string)
	if len(seed) != 64 {
		t.Errorf("routing_seed = %q，want 64 位十六进制", seed)
	}
	preview, _ := ok["enforce_preview"].(map[string]any)
	if preview["blocked"] != "" {
		t.Errorf("放行的模型不该有 blocked 预览: %v", preview)
	}
	plan, _ := ok["plan"].(map[string]any)
	if plan == nil || plan["policy_version"] != "t-open@1" {
		t.Errorf("plan 缺版本（回放要靠它对齐规则）: %v", plan)
	}

	code, denied := simulate(t, h, map[string]any{"scope": "", "model": "secret-model"})
	if code != http.StatusOK {
		t.Fatalf("被策略拒绝的模型模拟本身应 200（它是查询不是请求）= %d: %v", code, denied)
	}
	d, _ := denied["decision"].(map[string]any)
	if d["allowed"] != false {
		t.Fatalf("secret-model 必须被 deny: %v", d)
	}
	if explain, _ := d["explain"].(string); explain == "" || !strings.Contains(explain, "拒绝") {
		t.Errorf("决策解释缺失: %v", d["explain"])
	}
	if denied["verdict"] != shadowDecisionDenied {
		t.Errorf("verdict = %v，want %s", denied["verdict"], shadowDecisionDenied)
	}
	// enforce 预览要说「会拦」——这正是模拟最该回答的问题，而线上此刻还没拦。
	p2, _ := denied["enforce_preview"].(map[string]any)
	if blocked, _ := p2["blocked"].(string); blocked == "" {
		t.Error("enforce 预览应给出会拒绝的理由")
	}
	// 被拒的请求没有候选次序，seed 也就没有可复现的对象：这里报一个，
	// 同一个 request_id 就会在「路由模拟」里有 seed、在「决策痕迹」里没有 ——
	// 而痕迹那一屏才是线上真正落库的口径（forwarder 只在计划跑过时写）。
	if s, _ := denied["routing_seed"].(string); s != "" {
		t.Errorf("被策略拒掉的模拟不该报 seed: %q", s)
	}
	if dg, _ := denied["digest"].(string); dg != "" {
		t.Errorf("没有候选次序时不该报摘要: %q", dg)
	}

	after := shadowStats(t, h.harness)
	if after["evaluated"] != before["evaluated"] {
		t.Fatalf("模拟把影子计数动了：%v -> %v（§3.0 线 1：差异报告不能掺人为流量）",
			before["evaluated"], after["evaluated"])
	}
}

// 泄露面自证：响应里既不能有上游地址与密钥，也不能有授权条件的值。
func TestAdminPolicyEndpointsDoNotLeakSecrets(t *testing.T) {
	h := policyAdminHarness(t, "shadow")
	_, body := simulate(t, h, map[string]any{"scope": "", "model": "gpt-x"})
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"sk-global", "127.0.0.1", upstreamHostForTest(t, h)} {
		if banned != "" && strings.Contains(string(raw), banned) {
			t.Errorf("模拟响应泄露了 %q", banned)
		}
	}
	code, inspect := adminJSON(t, h, "/v1/_admin/policy")
	if code != http.StatusOK {
		t.Fatalf("inspect = %d", code)
	}
	for _, banned := range []string{"sk-global", "sk-admin", "sk-local", "api_key", "base_url"} {
		if strings.Contains(string(inspectJSON(t, inspect)), banned) {
			t.Errorf("查看口泄露了 %q", banned)
		}
	}
}

// upstreamHostForTest 从运行态里取出上游地址，让断言不依赖夹具的具体字面量。
func upstreamHostForTest(t *testing.T, h *muHarness) string {
	t.Helper()
	cfg := h.srv.cfgStore.Current()
	if len(cfg.Normalized) == 0 {
		return ""
	}
	return cfg.Normalized[0].BaseURL
}

func inspectJSON(t *testing.T, body map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// 范围链上没有包可用时，必须报「这个范围没启用 3.0」而不是「判定拒绝」。
// 前者是按 scope 回滚（§3.0 的退出通道），后者会让人去改一条根本不存在的规则。
//
// 只能用组织范围的包来造这个形态：system 范围的包按定义覆盖所有链（PolicyBundle.Covers），
// 所以「网关自己或普通用户没被覆盖」在只配了 system 包的世界里不可能发生。
func TestAdminPolicySimulateScopeWithoutBundleRollsBack(t *testing.T) {
	h := policyAdminHarnessBundles(t, "shadow", "t-uni", "organization:university", 4, policyBundleUniOnly)
	h.addUser(t, "alice")

	code, body := simulate(t, h, map[string]any{"scope": "alice", "model": "gpt-x"})
	if code != http.StatusOK {
		t.Fatalf("simulate = %d: %v", code, body)
	}
	if body["verdict"] != shadowNotEvaluated {
		t.Errorf("verdict = %v，want %s", body["verdict"], shadowNotEvaluated)
	}
	if body["policy_version"] != "" {
		t.Errorf("没有包覆盖时不该报版本号：%v", body["policy_version"])
	}
	preview, _ := body["enforce_preview"].(map[string]any)
	if preview["blocked"] != "" || preview["applied"] != false {
		t.Errorf("未覆盖范围不得有 enforce 作用：%v", preview)
	}
	// 顶层 note 必须是「这个范围没启用 3.0」，不能被 enforce 预览的「无可用计划」盖掉：
	// 后者会让人去找一条根本不存在的规则，前者是在说这里没有规则可找。
	if note, _ := body["note"].(string); !strings.Contains(note, "没有生效的策略包") {
		t.Errorf("note 要说清按 scope 退出：%q", note)
	}
}

func TestAdminPolicySimulateValidatesInput(t *testing.T) {
	h := policyAdminHarness(t, "shadow")
	if code, body := simulate(t, h, map[string]any{"scope": ""}); code != http.StatusBadRequest {
		t.Errorf("缺 model 应 400，实际 %d: %v", code, body)
	}
	if code, body := simulate(t, h, map[string]any{"model": "m", "scope": "nosuchuser"}); code != http.StatusNotFound {
		t.Errorf("不存在的用户应 404（而不是读不懂的空池），实际 %d: %v", code, body)
	}
	// 用户名规则与 store 一致：带斜杠的名字既进不了路径也进不了范围键。
	if code, body := simulate(t, h, map[string]any{"model": "m", "scope": "a/b"}); code != http.StatusBadRequest {
		t.Errorf("非法 scope 应 400，实际 %d: %v", code, body)
	}

	// legacy / 加载失败下模拟没有意义，必须显式拒绝而不是给一份「全是空结论」的 200。
	off := policyAdminHarness(t, "")
	resp, raw := off.post(t, "/v1/_admin/policy/simulate", adminToken, map[string]any{"model": "m"})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("legacy 下 simulate 应 409，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "没有在跑") {
		t.Errorf("409 要说清原因：%s", raw)
	}
}

// 同一 (request_id, 版本, 代) 必须派生同一个 seed（§2.8），否则「按 seed 复现」是空话。
func TestAdminPolicySimulateSeedIsReproducible(t *testing.T) {
	h := policyAdminHarness(t, "shadow")
	_, a := simulate(t, h, map[string]any{"scope": "", "model": "gpt-x", "request_id": "same-id"})
	_, b := simulate(t, h, map[string]any{"scope": "", "model": "gpt-x", "request_id": "same-id"})
	if a["routing_seed"] != b["routing_seed"] || a["routing_seed"] == "" {
		t.Fatalf("同 request_id 的 seed 必须一致：%v vs %v", a["routing_seed"], b["routing_seed"])
	}
	if fmt.Sprint(a["plan"]) != fmt.Sprint(b["plan"]) {
		t.Errorf("同 seed 下计划应当一样：%v vs %v", a["plan"], b["plan"])
	}
	_, c := simulate(t, h, map[string]any{"scope": "", "model": "gpt-x", "request_id": "other-id"})
	if c["routing_seed"] == a["routing_seed"] {
		t.Error("不同 request_id 派生出同一个 seed")
	}
	// 不给 request_id 时端点自己生成一个唯一的：每次模拟的 seed 不同，
	// 但界面拿到的那一次是可以复现的。
	_, d := simulate(t, h, map[string]any{"scope": "", "model": "gpt-x"})
	if d["routing_seed"] == a["routing_seed"] || len(fmt.Sprint(d["request_id"])) < 8 {
		t.Errorf("缺省 request_id 形态不对: %v", d["request_id"])
	}
}

// 痕迹查询是「决策解释」里唯一诚实的一半：它回答当时判成了什么。
// 逐位复现只在 enforce 且计划生效时成立 —— 影子写的 seed 会引导人去复现一次
// 没发生的决策，所以 exactly_replayable 必须跟着变。
func TestAdminPolicyTraceReplayability(t *testing.T) {
	shadow := policyAdminHarness(t, "shadow")
	if code, raw := chatWith(t, shadow.harness, "sk-static", "req-shadow-trace", "m"); code != http.StatusOK {
		t.Fatalf("shadow 下的请求应 200：%d %s", code, raw)
	}
	code, body := adminJSON(t, shadow, "/v1/_admin/policy/trace?request_id=req-shadow-trace")
	if code != http.StatusOK {
		t.Fatalf("trace = %d: %v", code, body)
	}
	if body["exactly_replayable"] != false {
		t.Errorf("影子请求不该声称可逐位复现: %v", body)
	}
	if body["routing_seed"] != "" {
		t.Errorf("影子不写 seed，实际 %v", body["routing_seed"])
	}
	if body["policy_version"] != "t-open@1" {
		t.Errorf("影子必须写版本号（§3.0）: %v", body["policy_version"])
	}
	if note, _ := body["note"].(string); !strings.Contains(note, "解释性回放") {
		t.Errorf("没 seed 时必须写明只能解释性回放: %q", note)
	}

	strict := policyAdminHarness(t, "enforce")
	if code, raw := chatWith(t, strict.harness, "sk-static", "req-enforce-trace", "m"); code != http.StatusOK {
		t.Fatalf("enforce 下的请求应 200：%d %s", code, raw)
	}
	_, body = adminJSON(t, strict, "/v1/_admin/policy/trace?request_id=req-enforce-trace")
	if body["exactly_replayable"] != true {
		t.Fatalf("enforce 生效的计划必须留下可复现输入: %v", body)
	}
	seed, _ := body["routing_seed"].(string)
	if len(seed) != 64 {
		t.Errorf("routing_seed = %q", seed)
	}
	if body["routing_epoch"] != "rev-1" || body["candidates_digest"] == "" {
		t.Errorf("seed/epoch/digest 要成组：%v", body)
	}
	// 静态 key 的请求没有范围归属（store 既有口径：零值落 NULL，不猜一个范围），
	// 所以这里必须显式说明判定链怎么重建，而不是让它看起来像缺了两个字段。
	if body["scope_kind"] != "" || body["scope_id"] != "" {
		t.Errorf("静态 key 不该被安上一个范围: %v/%v", body["scope_kind"], body["scope_id"])
	}
	if note, _ := body["scope_note"].(string); !strings.Contains(note, "没有范围归属") {
		t.Errorf("无归属要说清回放输入怎么重建: %q", note)
	}

	// 有归属的请求（用户 token）必须两列成对落库 —— 按范围回放与按范围审计都读这一对。
	alice := strict.addUser(t, "alice")
	baseURL := strict.srv.cfgStore.Current().Normalized[0].BaseURL
	strict.addProvider(t, "alice", "own", baseURL, "sk-global", `["m"]`)
	if code, raw := chatWith(t, strict.harness, alice, "req-enforce-byo", "m"); code != http.StatusOK {
		t.Fatalf("BYO 用户下的请求应 200：%d %s", code, raw)
	}
	_, body = adminJSON(t, strict, "/v1/_admin/policy/trace?request_id=req-enforce-byo")
	if body["scope_kind"] != "user" || body["scope_id"] != "alice" {
		t.Errorf("范围两列应成对落库: %v/%v", body["scope_kind"], body["scope_id"])
	}
	if _, ok := body["scope_note"]; ok {
		t.Errorf("有归属时不该再无归属说明: %v", body["scope_note"])
	}
	// 这条钉的是 enforce 的一条真实后果，不是测试妥协：用户自配的上游声明不出分级上限，
	// 分级门就按最严处理（§2.3），于是 3.0 计划里没有候选、回落旧路由，seed 自然不写。
	// 界面若把「enforce 模式」一律显示成「有可复现计划」，运营就会以为 BYO 流量也在 3.0 上。
	if body["exactly_replayable"] != false {
		t.Errorf("BYO 池被分级门清空时不该声称可复现: %v", body)
	}

	// 另一位用户走消费模式：候选池是网关的系统池（夹具里逐家声明了 internal），
	// 分级门放行，计划真的作用到请求上，此时「归属 + 可复现输入」必须同时成立。
	// 不复用 alice：她的自有上游点名声明了 m，旧链路的档序规则会把只报通配的系统上游
	// 整档挤出池子（router.bucketize 的 hasNamed），那是选路语义而不是本节要钉的东西。
	bob := strict.addUser(t, "bob")
	if err := strict.db.SetUserMode("bob", store.ModeConsumption); err != nil {
		t.Fatal(err)
	}
	// 模式存在库里，选路读的是快照；不同步就会拿旧模式去判，测出来的「没生效」是夹具的错。
	if err := strict.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}
	if code, raw := chatWith(t, strict.harness, bob, "req-enforce-user", "m"); code != http.StatusOK {
		t.Fatalf("消费模式下的请求应 200：%d %s", code, raw)
	}
	_, body = adminJSON(t, strict, "/v1/_admin/policy/trace?request_id=req-enforce-user")
	if body["scope_kind"] != "user" || body["scope_id"] != "bob" {
		t.Errorf("消费模式下的归属: %v/%v", body["scope_kind"], body["scope_id"])
	}
	if body["exactly_replayable"] != true {
		t.Errorf("用户请求在计划生效时同样要留可复现输入: %v", body)
	}
	seed, _ = body["routing_seed"].(string)
	if len(seed) != 64 || body["routing_epoch"] == "" || body["candidates_digest"] == "" {
		t.Errorf("归属请求的 seed/epoch/digest 也要成组: %v", body)
	}

	if code, _ := adminGet(t, strict, "/v1/_admin/policy/trace?request_id=nope"); code != http.StatusNotFound {
		t.Errorf("查不到的痕迹应 404，实际 %d", code)
	}
	if code, _ := adminGet(t, strict, "/v1/_admin/policy/trace"); code != http.StatusBadRequest {
		t.Errorf("缺 request_id 应 400，实际 %d", code)
	}
}
