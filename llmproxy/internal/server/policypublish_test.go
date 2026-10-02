package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

// §3.H 写侧（发布 / 撤下 / 回滚 / 生效版 / 模式开关）的测试。
//
// 断言重心是三件事，因为它们决定这套接口敢不敢对着生产配置开：
//  1. **原子**：一次发布要么引用与内容同时改，要么两边一字未动 —— 半成品状态
//     （磁盘上躺着一份配置没引用的新版）会让下一次发布的「旧内容」变成它。
//  2. **越权即无痕**：没有 admin token 的写请求必须 403，且配置文件字节不变。
//  3. **不外泄**：内容文件本来就带 Conditions 的**值**，而上面的接口是新的泄露面
//     （§2.9 规则 6）—— 视图只能出选择器与条件键名，密钥一律不出。

// publishHarness 起一个带策略段的网关，并把「等热加载」压成 0：
// 测试里没有轮询协程，revision 永远不变，等待只会拖慢用例（见 configedit_test 同款处理）。
func publishHarness(t *testing.T, mode string) *muHarness {
	t.Helper()
	h := policyAdminHarness(t, mode)
	h.srv.configApplyWait = 0
	return h
}

// policyReq 发一个写请求（PUT/POST/DELETE），body 为 nil 时不带体。
func policyReq(t *testing.T, h *muHarness, method, path, token string, body any) (int, map[string]any, []byte) {
	t.Helper()
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	req, err := http.NewRequest(method, h.gateway.URL+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, raw
}

func bundleBody(version int, scope string, rules []map[string]any) map[string]any {
	return map[string]any{
		"version":      version,
		"scope":        scope,
		"entitlements": rules,
	}
}

func teacherRule(sentinel string) map[string]any {
	return map[string]any{
		"subject": "role:teacher", "resource": "model:gpt-4o", "action": "use",
		"effect": "allow", "conditions": map[string]string{"project": sentinel},
		"source": "实验室批复", "version": "v2", "expires_at": "2027-01-01T00:00:00Z",
	}
}

func bundleDir(h *muHarness) string {
	return filepath.Join(filepath.Dir(h.configPath), config.DefaultBundleDir)
}

// reloadConfig 把写回磁盘的配置装进运行态：测试里没有热加载轮询协程，
// 而发布接口只负责「写得下去且能加载」，运行态换版是 Watch 的活。
// 要看「加载后的样子」就必须显式走一次 Reload —— 与 policyadmin_test 同一口径。
func reloadConfig(t *testing.T, h *muHarness) {
	t.Helper()
	if _, _, err := h.cfgStore.Reload(); err != nil {
		t.Fatalf("写回的配置加载不进来: %v", err)
	}
}

// ── 权限与形状 ─────────────────────────────────────────────

func TestAdminPolicyWriteRequiresAdminToken(t *testing.T) {
	h := publishHarness(t, "shadow")
	before, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodPut, "/v1/_admin/policy/bundles/x", bundleBody(1, "system:gateway", nil)},
		{http.MethodDelete, "/v1/_admin/policy/bundles/t-open", nil},
		{http.MethodPost, "/v1/_admin/policy/bundles/t-open/rollback", map[string]any{}},
		{http.MethodPost, "/v1/_admin/policy/bundles/t-open/reference", map[string]any{}},
		{http.MethodPost, "/v1/_admin/policy/active", map[string]any{"bundle": "t-open"}},
		{http.MethodPost, "/v1/_admin/policy/mode", map[string]any{"mode": "legacy"}},
	}
	for _, c := range calls {
		code, _, raw := policyReq(t, h, c.method, c.path, "sk-wrong", c.body)
		if code != http.StatusForbidden {
			t.Errorf("%s %s 用错 token 应 403，实际 %d: %s", c.method, c.path, code, raw)
		}
	}
	// 鉴权失败必须一个字节都没写：否则「试了一下没通过」就会留下半份配置。
	after, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("鉴权失败的写请求改动了配置文件")
	}
	if _, err := os.Stat(filepath.Join(bundleDir(h), "x.yaml")); !os.IsNotExist(err) {
		t.Error("鉴权失败的发布竟然写了内容文件")
	}
}

func TestAdminPolicyWriteMethodShapes(t *testing.T) {
	h := publishHarness(t, "shadow")
	// GET /bundles 是列表；GET /bundles/{id} 没有实现（要单包看就读整个列表）。
	if code, _, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/policy/bundles", adminToken, nil); code != 200 {
		t.Errorf("GET bundles 应 200，实际 %d: %s", code, raw)
	}
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles", adminToken, map[string]any{}); code != http.StatusMethodNotAllowed {
		t.Errorf("POST bundles 应 405（发布必须点名到 id），实际 %d: %s", code, raw)
	}
	if code, _, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/policy/active", adminToken, nil); code != http.StatusMethodNotAllowed {
		t.Errorf("GET active 应 405，实际 %d: %s", code, raw)
	}
	if code, _, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/policy/mode", adminToken, nil); code != http.StatusMethodNotAllowed {
		t.Errorf("GET mode 应 405，实际 %d: %s", code, raw)
	}
	// 三段式子路径只认自己那一个方法：写侧不留「看起来能读」的口子。
	if code, _, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/policy/bundles/t-open/reference", adminToken, nil); code != http.StatusMethodNotAllowed {
		t.Errorf("GET reference 应 405，实际 %d: %s", code, raw)
	}
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/t-open/backups", adminToken, map[string]any{}); code != http.StatusMethodNotAllowed {
		t.Errorf("POST backups 应 405，实际 %d: %s", code, raw)
	}
	// 四段以上根本不存在：404 里要带上新加的 reference 路径。
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/t-open/reference/deeper", adminToken, map[string]any{}); code != http.StatusNotFound ||
		!strings.Contains(string(raw), "/reference") {
		t.Errorf("深路径应 404 并列出含 reference 的可用路径，实际 %d: %s", code, raw)
	}
	// 未知子路径 404 且列出可用路径 —— 界面拼错一个字母时该拿到地图而不是空白 200。
	code, out, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/policy/bundles/t-open/unknown", adminToken, nil)
	if code != http.StatusNotFound || !strings.Contains(string(raw), "/v1/_admin/policy/bundles") {
		t.Errorf("未知子路径应 404 并列出路径，实际 %d: %s", code, raw)
	}
	if out["error"] == nil {
		t.Errorf("404 应带 error 字段: %s", raw)
	}
	// id 会当文件名用：凡过不了 validName 的写法必须在写盘之前就被拒。
	// （`..` 这类走不到这里 —— ServeMux 会先把路径里的 `.`/`..` 清掉再分发，
	// 所以目录穿越由 config.BundleFilePath 那一层守（见 config 包的同名测试），
	// 这里守的是「带空格/带分隔符的 id 绝不能变成一次发布」。）
	for _, id := range []string{"bad id", "a@b", "nested/deep"} {
		code, out, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/"+id, adminToken,
			bundleBody(1, "system:gateway", nil))
		if code < http.StatusBadRequest || code > http.StatusNotFound {
			t.Errorf("id=%q 应是 4xx 的拒绝，实际 %d: %s", id, code, raw)
		}
		if out["written"] != nil {
			t.Errorf("id=%q 竟然写成了: %s", id, raw)
		}
		assertNothingWritten(t, h, filepath.Base(id))
	}
}

// ── 发布 ───────────────────────────────────────────────────

func TestAdminPublishBundleWritesBothSides(t *testing.T) {
	h := publishHarness(t, "shadow")
	const sentinel = "topsecret-project-value"

	code, out, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/lab-restricted", adminToken,
		bundleBody(2, "project:cs-lab-7", []map[string]any{teacherRule(sentinel),
			{"subject": "*", "resource": "model:secret-model", "action": "use", "effect": "deny"}},
		))
	if code != http.StatusOK {
		t.Fatalf("发布应 200，实际 %d: %s", code, raw)
	}
	if out["written"] != true || out["strict_ok"] != true {
		t.Errorf("响应形态不对: %s", raw)
	}
	version, _ := out["policy_version"].(string)
	// 版本串来自**实际加载**的集合：这一步证明引用与内容当场对上了。
	if !strings.Contains(version, "lab-restricted@2") || !strings.Contains(version, "t-open@1") {
		t.Errorf("policy_version = %q，想同时含新包与原有包", version)
	}

	saved, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), "id: lab-restricted") || !strings.Contains(string(saved), "version: 2") {
		t.Errorf("引用没写进配置:\n%s", saved)
	}
	if !strings.Contains(string(saved), "active_bundle: lab-restricted") {
		t.Errorf("默认应当把新包设为生效包:\n%s", saved)
	}
	// 内容文件落盘，且键名是 JSON 形态（加载器靠它做未知键拒绝）。
	content, err := os.ReadFile(filepath.Join(bundleDir(h), "lab-restricted.yaml"))
	if err != nil {
		t.Fatalf("内容文件没写出来: %v", err)
	}
	if !strings.Contains(string(content), "subject:") || !strings.Contains(string(content), "expires_at") {
		t.Errorf("内容文件键名不对:\n%s", content)
	}
	// 配置文件其余部分（providers 的密钥、api_keys）原样。
	if !strings.Contains(string(saved), "api_key: sk-global") || !strings.Contains(string(saved), "- sk-static") {
		t.Errorf("policy 段外的内容被动过:\n%s", saved)
	}
	// 备份存在且带时间戳。
	if entries, _ := filepath.Glob(h.configPath + ".bak-*"); len(entries) != 1 {
		t.Errorf("配置备份 = %v", entries)
	}

	// 只读口现在能看见两个包。
	reloadConfig(t, h)
	_, body := adminGet(t, h, "/v1/_admin/policy")
	var info map[string]any
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatal(err)
	}
	if info["running"] != true {
		t.Errorf("发布后 3.0 应该在跑: %s", body)
	}
	bundles, _ := info["bundles"].([]any)
	if len(bundles) != 2 {
		t.Errorf("加载的包数 = %d，想要 2: %s", len(bundles), body)
	}
	if info["active_bundle"] != "lab-restricted" {
		t.Errorf("生效包不对: %s", body)
	}

	// 再发一版但明确不动生效包：active:false 不该顺手改掉「现在哪一版在判定」。
	code, _, raw = policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/t-open", adminToken,
		map[string]any{"version": 5, "scope": "system:gateway", "active": false,
			"entitlements": []map[string]any{{"subject": "*", "resource": "model:*", "action": "use", "effect": "allow"}}})
	if code != http.StatusOK {
		t.Fatalf("republish 应 200: %s", raw)
	}
	saved, _ = os.ReadFile(h.configPath)
	if !strings.Contains(string(saved), "active_bundle: lab-restricted") {
		t.Errorf("active:false 却改掉了生效包:\n%s", saved)
	}
	if !strings.Contains(string(saved), "version: 5") {
		t.Errorf("新版本号没写进去:\n%s", saved)
	}
	// 内容文件现在有了上一版可回滚。
	if backups, err := filepath.Glob(filepath.Join(bundleDir(h), "t-open.yaml.bak-*")); err != nil || len(backups) != 1 {
		t.Errorf("t-open 备份 = %v err=%v", backups, err)
	}
}

func TestAdminPublishUnknownConditionKeyLeavesNothing(t *testing.T) {
	h := publishHarness(t, "shadow")
	// conditions 的键必须是保留键：下划线写法在判定阶段是 fail-closed（规则不生效），
	// 静默接受就等于发出一条「看起来收紧了实际没收紧」的 deny/allow。
	code, out, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/bad-cond", adminToken,
		bundleBody(1, "system:gateway", []map[string]any{{
			"subject": "*", "resource": "model:*", "action": "use", "effect": "deny",
			"conditions": map[string]string{"max_data_level": "internal"},
		}}))
	if code != http.StatusBadRequest {
		t.Fatalf("应 400，实际 %d: %s", code, raw)
	}
	if !strings.Contains(fmt.Sprint(out["error"]), "max_data_level") ||
		!strings.Contains(fmt.Sprint(out["error"]), "max-data-level") {
		t.Errorf("错误应点名写错的键并给出正确写法: %v", out["error"])
	}
	assertNothingWritten(t, h, "bad-cond")
}

func TestAdminPublishBodyShape(t *testing.T) {
	h := publishHarness(t, "shadow")
	for name, body := range map[string]any{
		// 未知顶层键必须拒：拼错的字段如果被丢掉，发布出去的就不是界面上那条策略。
		"顶层未知键": map[string]any{"version": 1, "scope": "system:gateway", "entitlementss": []any{}},
		"规则未知键": bundleBody(1, "system:gateway", []map[string]any{{
			"subject": "*", "resource": "model:*", "action": "use", "effect": "allow", "expire_at": "2027-01-01T00:00:00Z"}}),
		"版本 0":     bundleBody(0, "system:gateway", nil),
		"范围缺 kind": bundleBody(1, "gateway", nil),
		"效果非法": bundleBody(1, "system:gateway", []map[string]any{{
			"subject": "*", "resource": "model:*", "action": "use", "effect": "maybe"}}),
		"主体选择器错": bundleBody(1, "system:gateway", []map[string]any{{
			"subject": "depart:cs", "resource": "model:*", "action": "use", "effect": "allow"}}),
	} {
		code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/shape-check", adminToken, body)
		if code != http.StatusBadRequest {
			t.Errorf("%s 应 400，实际 %d: %s", name, code, raw)
		}
		assertNothingWritten(t, h, "shape-check")
	}
}

// assertNothingWritten 断言「这次失败一个痕迹都没留」：配置未变、内容文件不存在、
// 也没有为这个包生成过备份。半成品的策略包内容比一次失败的请求危险得多。
func assertNothingWritten(t *testing.T, h *muHarness, id string) {
	t.Helper()
	now, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(now), "id: "+id) {
		t.Errorf("失败发布却改了配置引用:\n%s", now)
	}
	dir := bundleDir(h)
	for _, pattern := range []string{id + ".yaml", id + ".yaml.bak-*", id + ".yaml.new"} {
		if matches, _ := filepath.Glob(filepath.Join(dir, pattern)); len(matches) != 0 {
			t.Errorf("失败发布留下了 %s：%v", pattern, matches)
		}
	}
}

func TestAdminPublishRollsBackContentWhenRefsDisagree(t *testing.T) {
	// 造一个「发布动作本身没问题、但整份配置读不出策略集」的现场：
	// 有人手工改过另一个包的内容文件，让它的版本与引用不一致。
	// 这时新包的内容文件已经写进线上目录了，必须被还原掉。
	h := publishHarness(t, "shadow")
	path := filepath.Join(bundleDir(h), "t-open.yaml")
	edited := strings.Replace(policyBundleOpen, "version: 1", "version: 99", 1)
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	// 先确认现场成立：磁盘上这一条引用与内容对不上（只读列表会点名）。
	// 注意 running 此刻仍是 true —— 内存里是上一次成功加载的集合，而热加载只看配置文件
	// 的 mtime，改坏内容文件不会立刻触发重读；这个「同时为真」正是 drift_warning 存在的原因。
	_, _, drift := policyReq(t, h, http.MethodGet, "/v1/_admin/policy/bundles", adminToken, nil)
	if !strings.Contains(string(drift), `"matches":false`) ||
		!strings.Contains(string(drift), "drift_warning") {
		t.Fatalf("夹具没造出漂移现场: %s", drift)
	}

	before, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	code, out, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/newcomer", adminToken,
		bundleBody(3, "project:ai", []map[string]any{teacherRule("p-ai")}))
	if code != http.StatusConflict {
		t.Fatalf("两边对不上时应 409，实际 %d: %s", code, raw)
	}
	if !strings.Contains(fmt.Sprint(out["error"]), "发新版要同时改引用与内容文件") {
		t.Errorf("错误要指出可执行的下一步: %v", out["error"])
	}
	after, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("校验失败却改动了配置文件")
	}
	assertNothingWritten(t, h, "newcomer")
	// 那个被手工改坏的包也必须原样还在（我们不该顺手「修好」别人的现场）。
	kept, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(kept), "version: 99") {
		t.Errorf("回滚把别的包的内容也动了:\n%s", kept)
	}
}

func TestAdminPublishBeforePolicySectionIsRefused(t *testing.T) {
	// legacy 部署（配置里根本没有 policy 段）上直接发布：不能替它选一个 mode。
	h := publishHarness(t, "")
	// 夹具只在启用 3.0 的形态下给供应商声明分级上限（那是 3.0 才要求的）。
	// 这里补上：否则后面「切 shadow」会先撞在分级门上，测不到本用例要测的启用顺序。
	src, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.configPath,
		[]byte(strings.ReplaceAll(string(src), `    models: ["*"]`,
			"    max_data_level: internal\n    models: [\"*\"]")), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/first", adminToken,
		bundleBody(1, "system:gateway", nil))
	if code != http.StatusConflict {
		t.Fatalf("应 409，实际 %d: %s", code, raw)
	}
	if !strings.Contains(fmt.Sprint(out["error"]), "/v1/_admin/policy/mode") {
		t.Errorf("要给出下一步该做什么: %v", out["error"])
	}
	assertNothingWritten(t, h, "first")

	// 显式开 shadow 时，缺分级/缺包/缺生效指针都要指名道姓，而不是笼统「配置不合法」。
	code, out, raw = policyReq(t, h, http.MethodPost, "/v1/_admin/policy/mode", adminToken,
		map[string]any{"mode": "shadow"})
	if code != http.StatusBadRequest ||
		!strings.Contains(fmt.Sprint(out["error"]), "data_level") {
		t.Errorf("缺分级时应点名 data_level，实际 %d: %s", code, raw)
	}
	assertNothingWritten(t, h, "first")
	code, _, raw = policyReq(t, h, http.MethodPost, "/v1/_admin/policy/mode", adminToken,
		map[string]any{"mode": "shadow", "data_level": "internal"})
	if code != http.StatusBadRequest || !strings.Contains(string(raw), "至少一个策略包") {
		t.Errorf("没有包时该指出来，实际 %d: %s", code, raw)
	}

	// 于是正确的启用顺序是：mode(带分级) → 发布包 → 切生效包。
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/mode", adminToken,
		map[string]any{"mode": "shadow", "data_level": "internal"}); code == http.StatusOK {
		t.Fatalf("这一步本该因为没包而失败: %s", raw)
	}
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/first", adminToken,
		bundleBody(1, "system:gateway", []map[string]any{{
			"subject": "*", "resource": "model:*", "action": "use", "effect": "allow"}})); code != http.StatusConflict {
		t.Errorf("mode 还没落下去（上一步失败），发布应继续 409，实际 %d: %s", code, raw)
	}
	// 先只写 mode 与分级：用 mode=legacy 落段（legacy 不要求包），再发布，再切 shadow。
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/mode", adminToken,
		map[string]any{"mode": "legacy"}); code != http.StatusOK {
		t.Fatalf("写 legacy 段应 200，实际 %d: %s", code, raw)
	}
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/first", adminToken,
		bundleBody(1, "system:gateway", []map[string]any{{
			"subject": "*", "resource": "model:*", "action": "use", "effect": "allow"}})); code != http.StatusOK {
		t.Fatalf("legacy 段下发布应 200，实际 %d: %s", code, raw)
	}
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/mode", adminToken,
		map[string]any{"mode": "shadow", "data_level": "internal"}); code != http.StatusOK {
		t.Fatalf("齐了之后切 shadow 应 200，实际 %d: %s", code, raw)
	}
	reloadConfig(t, h)
	_, body := adminGet(t, h, "/v1/_admin/policy")
	if !strings.Contains(string(body), `"running":true`) || !strings.Contains(string(body), "first@1") {
		t.Errorf("启用后只读口状态不对: %s", body)
	}
}

// ── 生效版 / 模式 ──────────────────────────────────────────

func TestAdminPolicySetActiveAndMode(t *testing.T) {
	h := publishHarness(t, "shadow")
	// 先发第二个包，且不动生效包。
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/second", adminToken,
		map[string]any{"version": 1, "scope": "system:gateway", "active": false,
			"entitlements": []map[string]any{{"subject": "*", "resource": "model:*", "action": "use", "effect": "allow"}}}); code != http.StatusOK {
		t.Fatalf("发布应 200: %s", raw)
	}
	if _, body := adminGet(t, h, "/v1/_admin/policy"); !strings.Contains(string(body), "active_bundle") {
		t.Fatalf("只读口缺字段: %s", body)
	}

	// 指向不存在的包：错误里要列出可用的，否则运维只能猜。
	code, out, _ := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/active", adminToken,
		map[string]any{"bundle": "ghost"})
	if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(out["error"]), "t-open") {
		t.Errorf("应 400 并列出可用包，实际 %d: %v", code, out["error"])
	}
	if code, out, _ := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/active", adminToken, map[string]any{}); code != http.StatusBadRequest ||
		!strings.Contains(fmt.Sprint(out["error"]), "bundle 必填") {
		t.Errorf("空 body 应说清缺什么: %d %v", code, out["error"])
	}

	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/active", adminToken,
		map[string]any{"bundle": "second"}); code != http.StatusOK {
		t.Fatalf("切生效包应 200: %s", raw)
	}
	saved, _ := os.ReadFile(h.configPath)
	if !strings.Contains(string(saved), "active_bundle: second") {
		t.Errorf("生效指针没写下去:\n%s", saved)
	}
	// 切生效包**不该**动任何内容文件：它只换「哪一版参与判定」。
	if _, err := os.Stat(filepath.Join(bundleDir(h), "second.yaml")); err != nil {
		t.Errorf("内容文件被误动: %v", err)
	}

	// 应急开关：mode=legacy 一行就停，引用必须原样保留（切回时不用重抄）。
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/mode", adminToken,
		map[string]any{"mode": "legacy"}); code != http.StatusOK {
		t.Fatalf("切 legacy 应 200: %s", raw)
	}
	saved, _ = os.ReadFile(h.configPath)
	if !strings.Contains(string(saved), "mode: legacy") || !strings.Contains(string(saved), "id: second") ||
		!strings.Contains(string(saved), "active_bundle: second") {
		t.Errorf("legacy 切换把引用也吃了:\n%s", saved)
	}
	reloadConfig(t, h)
	if _, body := adminGet(t, h, "/v1/_admin/policy"); !strings.Contains(string(body), `"running":false`) ||
		!strings.Contains(string(body), "policy_mode_legacy") {
		t.Errorf("legacy 后只读口应说清为什么没在跑: %s", body)
	}
	// 切回 enforce 时分级还在（原值保留），不需要重抄。
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/mode", adminToken,
		map[string]any{"mode": "enforce"}); code != http.StatusOK {
		t.Fatalf("切 enforce 应 200: %s", raw)
	}
	reloadConfig(t, h)
	if _, body := adminGet(t, h, "/v1/_admin/policy"); !strings.Contains(string(body), `"running":true`) {
		t.Errorf("切回 enforce 后应该在跑: %s", body)
	}
	// enforce 下关掉回落是显式 fail-closed，要能写进去；shadow 下写 false 必须被拒。
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/mode", adminToken,
		map[string]any{"mode": "enforce", "fallback_to_legacy": false}); code != http.StatusOK {
		t.Fatalf("enforce 关回落应 200: %s", raw)
	}
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/mode", adminToken,
		map[string]any{"mode": "shadow", "fallback_to_legacy": false}); code != http.StatusBadRequest {
		t.Errorf("shadow 关回落应 400（那个开关在影子里没有作用点），实际 %d: %s", code, raw)
	}
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/mode", adminToken,
		map[string]any{"mode": "canary"}); code != http.StatusBadRequest {
		t.Errorf("拼错模式应 400，实际 %d: %s", code, raw)
	}
}

// ── 撤下与回滚 ─────────────────────────────────────────────

func TestAdminWithdrawBundle(t *testing.T) {
	h := publishHarness(t, "shadow")
	addSecond := func() {
		if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/second", adminToken,
			map[string]any{"version": 1, "scope": "system:gateway", "active": false,
				"entitlements": []map[string]any{{"subject": "*", "resource": "model:*", "action": "use", "effect": "allow"}}}); code != http.StatusOK {
			t.Fatalf("发布第二个包应 200: %s", raw)
		}
	}
	addSecond()

	// 撤非生效包：直接成功，内容文件保留（重新引用就能立刻回来）。
	if code, _, raw := policyReq(t, h, http.MethodDelete, "/v1/_admin/policy/bundles/second", adminToken, nil); code != http.StatusOK {
		t.Fatalf("撤下应 200: %s", raw)
	}
	saved, _ := os.ReadFile(h.configPath)
	if strings.Contains(string(saved), "id: second") {
		t.Errorf("引用没被撤掉:\n%s", saved)
	}
	if _, err := os.Stat(filepath.Join(bundleDir(h), "second.yaml")); err != nil {
		t.Errorf("内容文件被误删: %v", err)
	}
	// 现在它是 orphan：加载不参与，但内容还在磁盘上 —— 必须看得见。
	_, _, body := policyReq(t, h, http.MethodGet, "/v1/_admin/policy/bundles", adminToken, nil)
	if !strings.Contains(string(body), "orphans") || !strings.Contains(string(body), "second") {
		t.Errorf("撤下的包应出现在 orphans 里: %s", body)
	}
	addSecond()

	// 撤生效包但不给接棒的：400 并列出可用。
	if code, out, raw := policyReq(t, h, http.MethodDelete, "/v1/_admin/policy/bundles/t-open", adminToken, nil); code != http.StatusBadRequest ||
		!strings.Contains(fmt.Sprint(out["error"]), "?active=") {
		t.Errorf("应 400 并提示 ?active=，实际 %d: %v", code, raw)
	}
	if code, _, raw := policyReq(t, h, http.MethodDelete, "/v1/_admin/policy/bundles/t-open?active=ghost", adminToken, nil); code != http.StatusBadRequest {
		t.Errorf("接棒的包不存在应 400，实际 %d: %s", code, raw)
	}
	if code, _, raw := policyReq(t, h, http.MethodDelete, "/v1/_admin/policy/bundles/t-open?active=second", adminToken, nil); code != http.StatusOK {
		t.Fatalf("带接棒者的撤下应 200: %s", raw)
	}
	saved, _ = os.ReadFile(h.configPath)
	if strings.Contains(string(saved), "id: t-open") || !strings.Contains(string(saved), "active_bundle: second") {
		t.Errorf("撤下后引用/指针不对:\n%s", saved)
	}
	// 被撤的包不再参与判定，但它的名字还在磁盘上：必须看得见，否则运维会以为
	// 「撤下了」等于「内容也没了」，重新引用时找不到那份文件。
	_, _, body = policyReq(t, h, http.MethodGet, "/v1/_admin/policy/bundles", adminToken, nil)
	if !strings.Contains(string(body), "t-open") {
		t.Errorf("撤下的包应出现在 orphans 里: %s", body)
	}

	// 撤掉最后一条引用必须被拒，并指向应急开关：
	// shadow/enforce 没有引用就是整段策略不生效，而那从来不是「撤一个包」想要的效果。
	if code, _, raw := policyReq(t, h, http.MethodDelete, "/v1/_admin/policy/bundles/second", adminToken, nil); code != http.StatusConflict {
		t.Errorf("唯一的包应 409，实际 %d: %s", code, raw)
	} else if !strings.Contains(string(raw), "/v1/_admin/policy/mode") {
		t.Errorf("409 应指向 mode=legacy 那条路: %s", raw)
	}
	reloadConfig(t, h)
	if _, body := adminGet(t, h, "/v1/_admin/policy"); !strings.Contains(string(body), `"running":true`) {
		t.Errorf("被拒的撤下不该停掉策略: %s", body)
	}
	// 撤一个根本没被引用的包：404。
	if code, _, raw := policyReq(t, h, http.MethodDelete, "/v1/_admin/policy/bundles/never", adminToken, nil); code != http.StatusNotFound {
		t.Errorf("没引用的包应 404，实际 %d: %s", code, raw)
	}
}

func TestAdminReferenceBundleReUsesOnDiskContent(t *testing.T) {
	// 撤下的逆操作。它存在的理由很具体：条件值不经 GET 外泄，所以「重新启用」如果
	// 只能走 PUT 发布，运维就得把带条件值的规则手抄回来 —— 那既是误抄的来源，
	// 也把泄露面引到了剪贴板。这里服务端直接读那份已在受校验目录里的文件。
	h := publishHarness(t, "shadow")
	const sentinel = "topsecret-project-value"

	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/lab-cond", adminToken,
		map[string]any{"version": 3, "scope": "project:cs-lab-7", "active": false,
			"entitlements": []map[string]any{teacherRule(sentinel)}}); code != http.StatusOK {
		t.Fatalf("发布应 200: %s", raw)
	}
	// 撤掉刚发的那个非生效包，制造「磁盘有内容、配置没引用」的 orphan 现场。
	if code, _, raw := policyReq(t, h, http.MethodDelete, "/v1/_admin/policy/bundles/lab-cond", adminToken, nil); code != http.StatusOK {
		t.Fatalf("撤下应 200: %s", raw)
	}
	_, _, body := policyReq(t, h, http.MethodGet, "/v1/_admin/policy/bundles", adminToken, nil)
	if !strings.Contains(string(body), "orphans") || !strings.Contains(string(body), "lab-cond") {
		t.Fatalf("撤下的包应出现在 orphans 里: %s", body)
	}

	// 重新引用：体里一个字的内容都不带。
	code, out, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/lab-cond/reference",
		adminToken, map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("重新引用应 200: %s", raw)
	}
	if strings.Contains(string(raw), sentinel) {
		t.Errorf("响应里出现了条件值: %s", raw)
	}
	info, _ := out["bundle"].(map[string]any)
	if info == nil || info["version"] != float64(3) || info["scope"] != "project:cs-lab-7" {
		t.Fatalf("回显的包视图不对: %v", out["bundle"])
	}
	rulesJSON, _ := json.Marshal(info["rules"])
	if !strings.Contains(string(rulesJSON), "project") || !strings.Contains(string(rulesJSON), "condition_keys") {
		t.Errorf("规则视图应给出条件键名: %s", rulesJSON)
	}
	saved, _ := os.ReadFile(h.configPath)
	if !strings.Contains(string(saved), "id: lab-cond") || !strings.Contains(string(saved), "version: 3") {
		t.Errorf("引用没回来:\n%s", saved)
	}
	if !strings.Contains(string(saved), "active_bundle: lab-cond") {
		t.Errorf("缺省应把重新引用的包设为生效包（与发布同一口径）:\n%s", saved)
	}
	// 内容文件必须还是原来那一份：这个端点只改配置，重写内容就等于凭空多一版历史。
	content, err := os.ReadFile(filepath.Join(bundleDir(h), "lab-cond.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), sentinel) || !strings.Contains(string(content), "version: 3") {
		t.Errorf("内容文件被改写了:\n%s", content)
	}
	if backups, _ := filepath.Glob(filepath.Join(bundleDir(h), "lab-cond.yaml.bak-*")); len(backups) != 0 {
		t.Errorf("重新引用不该产生内容备份: %v", backups)
	}
	// 引用与内容当场对得上，加载器才认这条包。
	reloadConfig(t, h)
	if _, body := adminGet(t, h, "/v1/_admin/policy"); !strings.Contains(string(body), `"running":true`) {
		t.Errorf("重新引用后 3.0 应该在跑: %s", body)
	}

	// 再引用一次没有意义（磁盘上只有一份当前内容）：必须点名挡住，指去真正的动作。
	if code, out, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/lab-cond/reference",
		adminToken, map[string]any{}); code != http.StatusConflict ||
		!strings.Contains(fmt.Sprint(out["error"]), "PUT /v1/_admin/policy/bundles/lab-cond") {
		t.Errorf("重复引用应 409 并指向发布接口，实际 %d: %v", code, raw)
	}

	// 已经引用着时，撤下→重新引用这条路径也不能抢生效包：active:false 与发布同语义。
	if code, _, raw := policyReq(t, h, http.MethodDelete, "/v1/_admin/policy/bundles/lab-cond?active=t-open",
		adminToken, nil); code != http.StatusOK {
		t.Fatalf("带接棒者的撤下应 200: %s", raw)
	}
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/lab-cond/reference",
		adminToken, map[string]any{"active": false}); code != http.StatusOK {
		t.Fatalf("active:false 的引用应 200: %s", raw)
	}
	saved, _ = os.ReadFile(h.configPath)
	if !strings.Contains(string(saved), "id: lab-cond") || !strings.Contains(string(saved), "active_bundle: t-open") {
		t.Errorf("active:false 却改掉了生效包:\n%s", saved)
	}
}

func TestAdminReferenceBundleRefusesBadGround(t *testing.T) {
	h := publishHarness(t, "shadow")
	// 磁盘上根本没有这份内容：不能写出一条读不出来的引用。
	if code, out, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/never/reference",
		adminToken, map[string]any{}); code != http.StatusConflict ||
		!strings.Contains(fmt.Sprint(out["error"]), "没有可读且校验通过的内容") {
		t.Errorf("没有内容文件应 409 并说清原因，实际 %d: %v", code, raw)
	}

	// 文件名与文件里的 id 不一致：加载器核对的是内容里的 id，以路径为准拒掉，
	// 否则会写出一条「挂在 foo 名下、内容却自称 bar」的引用。
	dir := bundleDir(h)
	if err := os.WriteFile(filepath.Join(dir, "ghost.yaml"),
		[]byte("id: not-ghost\nversion: 1\nscope: system:gateway\nentitlements:\n"+
			"- subject: \"*\"\n  resource: \"model:*\"\n  action: use\n  effect: allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/ghost/reference",
		adminToken, map[string]any{}); code != http.StatusConflict ||
		!strings.Contains(fmt.Sprint(out["error"]), "not-ghost") {
		t.Errorf("id 不一致应 409 并点名两个 id，实际 %d: %v", code, raw)
	}
	saved, _ := os.ReadFile(h.configPath)
	if strings.Contains(string(saved), "id: ghost") {
		t.Errorf("被拒的引用却写进了配置:\n%s", saved)
	}

	// 指定版本与磁盘那一版不符：停下来问，而不是替对方引用另一版。
	// （version 是给「我要的那一版」当闸门用的，不是让服务端猜版本的。）
	if err := os.WriteFile(filepath.Join(dir, "older.yaml"),
		[]byte("id: older\nversion: 2\nscope: system:gateway\nentitlements:\n"+
			"- subject: \"*\"\n  resource: \"model:*\"\n  action: use\n  effect: allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/older/reference",
		adminToken, map[string]any{"version": 9}); code != http.StatusConflict ||
		!strings.Contains(fmt.Sprint(out["error"]), "v2") ||
		!strings.Contains(fmt.Sprint(out["error"]), "v9") {
		t.Errorf("版本闸门应 409 并给出两边版本，实际 %d: %v", code, raw)
	}
	// 不指定版本就按磁盘那一版引用 —— 这正是「重新引用同一版」的意思。
	codeOk, outOk, rawOk := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/older/reference",
		adminToken, map[string]any{"active": false})
	if codeOk != http.StatusOK {
		t.Fatalf("按磁盘那一版引用应 200: %s", rawOk)
	}
	if info, _ := outOk["bundle"].(map[string]any); info["version"] != float64(2) {
		t.Errorf("应回显磁盘上的 v2: %v", outOk["bundle"])
	}

	// 未知方法：写侧路径不接受 GET（读整个列表就行，单包视图不给 200 的空壳）。
	if code, _, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/policy/bundles/t-open/reference", adminToken, nil); code != http.StatusMethodNotAllowed {
		t.Errorf("GET reference 应 405，实际 %d: %s", code, raw)
	}
	// 未知键必须拒：active 写成 is_active 时，静默接受等于按缺省抢了生效包。
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/t-open/reference",
		adminToken, map[string]any{"is_active": true}); code != http.StatusBadRequest {
		t.Errorf("未知键应 400，实际 %d: %s", code, raw)
	}
}

func TestAdminReferenceBeforePolicySectionIsRefused(t *testing.T) {
	// 还没有 policy.mode 的部署：加引用会让加载直接拒（「配了 bundles 却没写 mode」），
	// 所以这里必须提前指路，而不是把那条加载错误原样丢过来。
	h := publishHarness(t, "")
	before, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if code, out, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/t-open/reference",
		adminToken, map[string]any{}); code != http.StatusConflict ||
		!strings.Contains(fmt.Sprint(out["error"]), "/v1/_admin/policy/mode") {
		t.Errorf("无 policy 段应 409 并指向 mode 接口，实际 %d: %v", code, raw)
	}
	after, _ := os.ReadFile(h.configPath)
	if string(after) != string(before) {
		t.Error("被拒的引用改动了配置文件")
	}
	assertNothingWritten(t, h, "t-open")
}

func TestAdminRollbackBundle(t *testing.T) {
	h := publishHarness(t, "shadow")
	rule := func(effect string) []map[string]any {
		return []map[string]any{{"subject": "*", "resource": "model:*", "action": "use", "effect": effect}}
	}
	// 夹具已经把 t-open@1 写进磁盘与配置；这里发两版，制造可回滚的历史。
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/t-open", adminToken,
		map[string]any{"version": 2, "scope": "system:gateway", "entitlements": rule("deny")}); code != http.StatusOK {
		t.Fatalf("发 v2 应 200: %s", raw)
	}
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/t-open", adminToken,
		map[string]any{"version": 3, "scope": "system:gateway", "entitlements": rule("allow")}); code != http.StatusOK {
		t.Fatalf("发 v3 应 200: %s", raw)
	}

	// 回滚不指定来源 = 最近一份备份（也就是 v2 被 v3 替换掉的那份内容）。
	code, out, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/t-open/rollback", adminToken,
		map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("回滚应 200: %s", raw)
	}
	if !strings.Contains(fmt.Sprint(out["note"]), "回滚到 v2") {
		t.Errorf("响应该说清回到哪一版: %v", out["note"])
	}
	version, _ := out["policy_version"].(string)
	if !strings.Contains(version, "t-open@2") {
		t.Errorf("policy_version = %q，想让引用跟到 v2", version)
	}
	saved, _ := os.ReadFile(h.configPath)
	if !strings.Contains(string(saved), "version: 2") {
		t.Errorf("引用没跟着回去:\n%s", saved)
	}
	content, err := os.ReadFile(filepath.Join(bundleDir(h), "t-open.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "version: 2") || !strings.Contains(string(content), "effect: deny") {
		t.Errorf("内容文件没回到 v2（那一版是 deny）:\n%s", content)
	}
	// 回滚本身也必须可回滚：v3 此刻是最新备份。
	_, _, body := policyReq(t, h, http.MethodGet, "/v1/_admin/policy/bundles/t-open/backups", adminToken, nil)
	if strings.Count(string(body), "version") < 2 {
		t.Errorf("备份列表该含被回滚掉的那一版: %s", body)
	}

	// 指定版本回滚：只认这个包自己的历史。
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/t-open/rollback", adminToken,
		map[string]any{"version": 1}); code != http.StatusOK {
		t.Fatalf("回到 v1 应 200: %s", raw)
	}
	_, _, body = policyReq(t, h, http.MethodGet, "/v1/_admin/policy/bundles", adminToken, nil)
	if !strings.Contains(string(body), "t-open@1") || !strings.Contains(string(body), `"matches":true`) {
		t.Errorf("回滚后引用与内容应重新一致: %s", body)
	}
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/t-open/rollback", adminToken,
		map[string]any{"backup": "../config.yaml"}); code != http.StatusBadRequest {
		t.Errorf("别处的路径应 400，实际 %d: %s", code, raw)
	}
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/t-open/rollback", adminToken,
		map[string]any{"version": 424}); code != http.StatusNotFound {
		t.Errorf("没有这一版历史应 404，实际 %d: %s", code, raw)
	}
	// 没被引用的包无从「回滚内容」：那其实是重新发布。
	if code, _, raw := policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/ghost/rollback", adminToken,
		map[string]any{}); code != http.StatusNotFound && code != http.StatusConflict {
		t.Errorf("未引用的包应 404/409，实际 %d: %s", code, raw)
	}
}

// ── 泄露面 ─────────────────────────────────────────────────

func TestAdminPolicyWriteEndpointsLeakNoConditionValuesOrKeys(t *testing.T) {
	// 内容文件**必然**带着 Conditions 的值（那是判定输入）；
	// 管理口是新增的泄露面，视图必须只出选择器与条件键名。
	h := publishHarness(t, "shadow")
	const sentinel = "sentinel-project-value-8f2c"
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/leaky", adminToken,
		map[string]any{"version": 1, "scope": "system:gateway", "active": false,
			"entitlements": []map[string]any{teacherRule(sentinel)}}); code != http.StatusOK {
		t.Fatalf("发布应 200: %s", raw)
	}
	// 磁盘上确实在（否则这条测试什么都没证明）。
	onDisk, err := os.ReadFile(filepath.Join(bundleDir(h), "leaky.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(onDisk), sentinel) {
		t.Fatalf("夹具没把条件值写进内容文件:\n%s", onDisk)
	}

	reloadConfig(t, h)
	paths := []string{
		"/v1/_admin/policy",
		"/v1/_admin/policy/bundles",
	}
	for _, path := range paths {
		_, body, raw := policyReq(t, h, http.MethodGet, path, adminToken, nil)
		_ = body
		for _, forbidden := range []string{sentinel, "sk-global", "sk-admin", "sk-static", "http://127.0.0.1:"} {
			if strings.Contains(string(raw), forbidden) {
				t.Errorf("%s 外泄了 %q", path, forbidden)
			}
		}
		// 条件键名可以给（它说明这条规则要看什么），值不行。
		if !strings.Contains(string(raw), "condition_keys") {
			t.Errorf("%s 应列出条件键名: %s", path, raw)
		}
	}
	// 备份列表只出标识与条数：它连规则视图都不给，值自然更出不来。
	_, _, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/policy/bundles/leaky/backups", adminToken, nil)
	for _, forbidden := range []string{sentinel, "sk-global", "实验室批复"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("备份列表外泄了 %q", forbidden)
		}
	}

	// 发第二版，制造可回滚的历史；回滚成功的响应体同样不能带出值。
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/policy/bundles/leaky", adminToken,
		map[string]any{"version": 2, "scope": "system:gateway", "active": false,
			"entitlements": []map[string]any{teacherRule(sentinel)}}); code != http.StatusOK {
		t.Fatalf("发第二版应 200: %s", raw)
	}
	_, _, raw = policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/leaky/rollback", adminToken,
		map[string]any{})
	for _, forbidden := range []string{sentinel, "sk-global", "实验室批复"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("回滚响应外泄了 %q", forbidden)
		}
	}
	if !strings.Contains(string(raw), "已回滚到 v1") {
		t.Errorf("回滚响应没说到哪一版: %s", raw)
	}

	// 重新引用走的是「服务端读磁盘那份内容」，回显复用读侧同一个视图：
	// 选择器与条件键名可以给，条件值与上游地址、密钥不给。
	if code, _, raw := policyReq(t, h, http.MethodDelete, "/v1/_admin/policy/bundles/leaky", adminToken, nil); code != http.StatusOK {
		t.Fatalf("撤下应 200: %s", raw)
	}
	_, _, raw = policyReq(t, h, http.MethodPost, "/v1/_admin/policy/bundles/leaky/reference", adminToken,
		map[string]any{"active": false})
	for _, forbidden := range []string{sentinel, "sk-global", "sk-admin", "sk-static", "http://127.0.0.1:"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("重新引用响应外泄了 %q: %s", forbidden, raw)
		}
	}
	if !strings.Contains(string(raw), "condition_keys") {
		t.Errorf("重新引用应回显条件键名，好让人核对引用的是哪一份: %s", raw)
	}
}

// ── 漂移可见性 ─────────────────────────────────────────────

func TestAdminPolicyBundlesInspectShowsDrift(t *testing.T) {
	h := publishHarness(t, "shadow")
	// 有人手工把内容文件的版本改了：加载会整体失败，界面必须点名是哪一条。
	path := filepath.Join(bundleDir(h), "t-open.yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(policyBundleOpen, "version: 1", "version: 8", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/policy/bundles", adminToken, nil)
	if code != http.StatusOK {
		t.Fatalf("列表本身不该因为漂了就 500: %d %s", code, raw)
	}
	refs, _ := out["refs"].([]any)
	if len(refs) != 1 {
		t.Fatalf("refs = %v", out["refs"])
	}
	first := refs[0].(map[string]any)
	if first["matches"] != false {
		t.Errorf("漂了却报 matches=true: %v", first)
	}
	if first["content_version"] != float64(8) {
		t.Errorf("content_version = %v，想看到磁盘上那一版", first["content_version"])
	}
	if !strings.Contains(fmt.Sprint(first["drift"]), "引用") {
		t.Errorf("drift 该说清两边各是什么: %v", first["drift"])
	}
	// 漂移必须有一句独立的预告：热加载只看配置文件的 mtime，改坏内容文件不一定当场
	// 反映到 running 上（本用例里第一次读时才去加载，所以是 false；
	// 一个正在服务、内存里留着上一版的网关则是 true —— 那种「同时为真」更危险）。
	if !strings.Contains(fmt.Sprint(out["drift_warning"]), "下一次热加载") {
		t.Errorf("漂移必须给出下一次加载的预告: %s", raw)
	}
	if out["running"] != false {
		t.Errorf("本夹具在漂移之后第一次加载，应报告没在跑: %s", raw)
	}
	if !strings.Contains(fmt.Sprint(out["inactive_reason"]), "policy_load_failed") {
		t.Errorf("应给出加载失败的原因: %s", raw)
	}
	// 读不回来的内容文件也要列出来，并带错误串（不是静默跳过）。
	if err := os.WriteFile(path, []byte("id: [\n  bad: : yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, _ = policyReq(t, h, http.MethodGet, "/v1/_admin/policy/bundles", adminToken, nil)
	refs, _ = out["refs"].([]any)
	if len(refs) != 1 || refs[0].(map[string]any)["file_error"] == nil {
		t.Errorf("坏文件应带 file_error: %v", refs)
	}
}
