package server

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

// 处理器与知识源声明段的管理接口测试（§3.H）。
//
// 这一屏最坏的结果不是「改不动」，而是「改错了看不出来」和「以为生效了」，
// 所以断言集中在四件事上：权限门（未授权一个字节都不写）、坏声明拒写且原文件不动、
// 缺字段不等于清空、以及每次写都把「现在到底生不生效」说在响应里。

// declProc 是一条最小可用的处理器声明（JSON 形态，字段名与配置文件完全一致）。
func declProc(name, phase string) map[string]any {
	return map[string]any{
		"name": name, "type": "pii-mask", "phase": phase,
		"scope": "organization:university", "version": "1",
		"body_access": "transform-body", "fail_closed": true,
		"timeout_ms": 800, "max_input_bytes": 4096, "max_output_bytes": 8192,
	}
}

// declSidecar 是一条会出网的声明：白名单必须逐条枚举，原文出网要显式开。
func declSidecar(name string) map[string]any {
	return map[string]any{
		"name": name, "type": "http-sidecar", "phase": "before-upstream",
		"scope": "project:cs-lab-7", "version": "1",
		"body_access": "inspect-body", "fail_closed": true,
		"timeout_ms": 1200, "max_input_bytes": 65536, "max_output_bytes": 65536,
		"allowed_endpoints": []any{"https://sidecar.internal/v1/rewrite"},
	}
}

func declSource(name, endpoint string, kbs ...string) map[string]any {
	return map[string]any{
		"name": name, "endpoint": endpoint, "knowledge_bases": toAny(kbs),
		"timeout_ms": 1500, "max_response_bytes": 1048576,
	}
}

func toAny(list []string) []any {
	out := make([]any, 0, len(list))
	for _, s := range list {
		out = append(out, s)
	}
	return out
}

// ── 权限门 ─────────────────────────────────────────────────

func TestAdminDeclarationsRequireAdminToken(t *testing.T) {
	h := publishHarness(t, "shadow")
	before, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/v1/_admin/config/processors", nil},
		{http.MethodGet, "/v1/_admin/config/knowledge_sources", nil},
		{http.MethodPut, "/v1/_admin/config/processors", map[string]any{"processors": []any{declProc("pii-cn", "before-upstream")}}},
		{http.MethodPut, "/v1/_admin/config/knowledge_sources", map[string]any{"knowledge_sources": []any{}}},
	}
	for _, c := range calls {
		for _, token := range []string{"sk-wrong", ""} {
			code, _, raw := policyReq(t, h, c.method, c.path, token, c.body)
			if code != http.StatusForbidden {
				t.Errorf("%s %s（token=%q）应 403，实际 %d: %s", c.method, c.path, token, code, raw)
			}
		}
	}
	// 连读都要 admin_token：声明里带着内部端点与出网白名单，不是给普通 key 看的。
	after, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("未授权的请求改动了配置文件")
	}
}

func TestAdminDeclarationRouteShapes(t *testing.T) {
	h := publishHarness(t, "shadow")
	// 没有 DELETE 这条路：整段写回就是删除的唯一形态（半删状态不该存在于磁盘上）。
	if code, _, raw := policyReq(t, h, http.MethodDelete, "/v1/_admin/config/processors", adminToken, nil); code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE processors 应 405，实际 %d: %s", code, raw)
	}
	// 不认识的段名要在 404 里把可用段名说全。
	code, out, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/config/handlers", adminToken, nil)
	if code != http.StatusNotFound {
		t.Fatalf("未知段应 404，实际 %d: %s", code, raw)
	}
	msg, _ := out["error"].(map[string]any)
	if msg == nil || !strings.Contains(asString(msg["message"]), "knowledge_sources") {
		t.Errorf("404 该列出可用段名: %+v", out)
	}
	// 顶层 GET 不受影响（回归：新增分支不该吃掉 providers 的路）。
	if code, _, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/config", adminToken, nil); code != 200 {
		t.Errorf("GET /config 应 200，实际 %d: %s", code, raw)
	}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

// ── 读侧：取值域 + 当前形态 ────────────────────────────────

func TestAdminDeclarationShowVocabulary(t *testing.T) {
	h := publishHarness(t, "shadow")
	code, out, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/config/processors", adminToken, nil)
	if code != 200 {
		t.Fatalf("GET processors 应 200: %d %s", code, raw)
	}
	// 空段回 [] 而不是 null（界面不必为「没有声明」写第二套判断）。
	if list, ok := out["processors"].([]any); !ok || len(list) != 0 {
		t.Errorf("没有该段时应回空数组: %+v", out["processors"])
	}
	if out["applies"] != false || out["mode"] != "shadow" {
		t.Errorf("影子模式下要说「不生效」: %v %v", out["mode"], out["applies"])
	}
	vocab, ok := out["vocabulary"].(map[string]any)
	if !ok {
		t.Fatalf("取值域没下发: %+v", out)
	}
	for key, want := range map[string]int{
		// 类型数跟着注册表走：内置类型从 5 个变成 6 个（加了 kb-context-inject），
		// 这里必须与 processor.NewRegistry().KnownTypes() 同步，否则界面词表与运行时脱节。
		"processor_types": 6, "phases": 5, "body_accesses": 3, "scope_kinds": 4,
	} {
		if got, _ := vocab[key].([]any); len(got) != want {
			t.Errorf("取值域 %s 应有 %d 项，实际 %+v", key, want, vocab[key])
		}
	}
	// 上限也来自服务端：前端不抄常量，界面上就写不出「绝对上限是 32MiB」这句话。
	if got, _ := vocab["max_timeout_ms"].(float64); got != 120000 {
		t.Errorf("max_timeout_ms = %v，想要 120000", vocab["max_timeout_ms"])
	}
	if got, _ := vocab["absolute_max_input_bytes"].(float64); got != 32<<20 {
		t.Errorf("absolute_max_input_bytes = %v", vocab["absolute_max_input_bytes"])
	}
	if got, _ := vocab["max_knowledge_budget_ms"].(float64); got != 30000 {
		t.Errorf("max_knowledge_budget_ms = %v", vocab["max_knowledge_budget_ms"])
	}
	types := strings.ToLower(fmt.Sprint(vocab["processor_types"]))
	for _, want := range []string{"pii-mask", "http-sidecar", "result-filter", "kb-context-inject"} {
		if !strings.Contains(types, want) {
			t.Errorf("类型词表缺 %s: %s", want, types)
		}
	}
}

// ── 写侧 ───────────────────────────────────────────────────

func TestAdminProcessorsWriteRoundTrip(t *testing.T) {
	h := publishHarness(t, "shadow")
	body := map[string]any{"processors": []any{declProc("pii-cn", "before-upstream"), declSidecar("sidecar-1")}}
	code, out, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken, body)
	if code != 200 {
		t.Fatalf("合法声明应写成功: %d %s", code, raw)
	}
	if out["written"] != true || out["count"].(float64) != 2 {
		t.Errorf("响应形态不对: %+v", out)
	}
	// 写完必须当场说「现在还不生效」：影子模式不碰正文，这是这一屏最容易被误读的一点。
	if out["applies"] != false || out["mode"] != "shadow" {
		t.Errorf("写响应要带模式: %v %v", out["mode"], out["applies"])
	}
	if !strings.Contains(fmt.Sprint(out["warnings"]), "不会生效") {
		t.Errorf("加载告警要原样回给用户: %+v", out["warnings"])
	}
	if out["strict_ok"] != true {
		t.Errorf("写回的文件必须严格模式也能加载: %+v", out)
	}
	text, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"processors:", "pii-cn", "http-sidecar", "providers:", "api_key: sk-global", "admin_token: sk-admin", "policy:"} {
		if !strings.Contains(string(text), want) {
			t.Errorf("文件里该有 %q（段外内容必须原样）:\n%s", want, text)
		}
	}
	// 读回来的形态与提交的值等价（界面回填靠这一次 GET，不能填出另一套值）。
	code, got, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/config/processors", adminToken, nil)
	if code != 200 {
		t.Fatalf("GET 失败: %d %s", code, raw)
	}
	list := got["processors"].([]any)
	if len(list) != 2 {
		t.Fatalf("应读回 2 条: %+v", list)
	}
	// 读回来的顺序就是文件里的写法顺序（渲染按提交顺序出正文，排序只发生在派生视图里）。
	first := list[0].(map[string]any)
	if first["name"] != "pii-cn" || first["phase"] != "before-upstream" ||
		first["scope"] != "organization:university" || first["fail_closed"] != true ||
		first["body_access"] != "transform-body" {
		t.Errorf("读回的声明与提交的不等价: %+v", first)
	}
	second := list[1].(map[string]any)
	if second["allow_raw_body"] != nil && second["allow_raw_body"] != false {
		t.Errorf("没开的原文出网不该被填成 true: %+v", second)
	}
	if eps, _ := second["allowed_endpoints"].([]any); len(eps) != 1 || eps[0] != "https://sidecar.internal/v1/rewrite" {
		t.Errorf("出网白名单读回不符: %+v", second["allowed_endpoints"])
	}
	// 同一意图再写一次：文件字节不变（否则每次保存都在制造无意义的 diff）。
	before := string(text)
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken, body); code != 200 {
		t.Fatalf("重复写应 200: %d %s", code, raw)
	}
	after, _ := os.ReadFile(h.configPath)
	if string(after) != before {
		t.Errorf("同一意图写出两份文本:\n%s\n---\n%s", before, after)
	}
}

// TestAdminProcessorsBadDeclarationLeavesFileUntouched 是本包最重要的一条：
// 坏声明必须在落盘之前被拒，而且错误要指认是哪一条、哪条规则。
func TestAdminProcessorsBadDeclarationLeavesFileUntouched(t *testing.T) {
	h := publishHarness(t, "shadow")
	// 先落一份合法基线，再验证坏写不会破坏它。
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken,
		map[string]any{"processors": []any{declProc("pii-cn", "before-upstream")}}); code != 200 {
		t.Fatalf("基线写入失败: %d %s", code, raw)
	}
	good, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		why  string
		list []any
		want string
	}{
		{"阶段拼错", []any{declProc("p", "before-upstram")}, "未知的处理阶段"},
		{"档位与类型不符", []any{func() map[string]any {
			d := declProc("p", "before-upstream")
			d["body_access"] = "metadata-only"
			return d
		}()}, "transform-body"},
		{"缺 fail_closed", []any{func() map[string]any {
			d := declProc("p", "before-upstream")
			delete(d, "fail_closed")
			return d
		}()}, "fail_closed"},
		{"请求侧类型跑到 audit", []any{declProc("p", "audit")}, "请求侧阶段"},
		{"sidecar 没有白名单", []any{func() map[string]any {
			d := declSidecar("s")
			delete(d, "allowed_endpoints")
			return d
		}()}, "allowed_endpoints"},
		{"同名两条", []any{declProc("dup", "before-route"), declProc("dup", "before-upstream")}, "出现多次"},
		{"超时无限", []any{func() map[string]any {
			d := declProc("p", "before-upstream")
			d["timeout_ms"] = 0
			return d
		}()}, "timeout_ms"},
		{"正文上限越界", []any{func() map[string]any {
			d := declProc("p", "before-upstream")
			d["max_input_bytes"] = 1 << 40
			return d
		}()}, "max_input_bytes"},
	}
	for _, tc := range cases {
		code, out, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken,
			map[string]any{"processors": tc.list})
		if code != http.StatusBadRequest {
			t.Errorf("%s：应 400，实际 %d: %s", tc.why, code, raw)
			continue
		}
		if !strings.Contains(fmt.Sprint(out), tc.want) {
			t.Errorf("%s：错误该指认 %q，实际: %s", tc.why, tc.want, raw)
		}
		now, _ := os.ReadFile(h.configPath)
		if string(now) != string(good) {
			t.Errorf("%s：坏写动了磁盘\n%s", tc.why, now)
		}
	}
	// 请求体里的未知键同样拒（DisallowUnknownFields）：静默丢字段在安全项上等于放过一条宽松声明。
	code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken,
		map[string]any{"processors": []any{func() map[string]any {
			d := declProc("p", "before-upstream")
			d["max_retries"] = 3
			return d
		}()}})
	if code != http.StatusBadRequest {
		t.Errorf("未知键应 400，实际 %d: %s", code, raw)
	}
	if now, _ := os.ReadFile(h.configPath); string(now) != string(good) {
		t.Errorf("未知键的写动了磁盘:\n%s", now)
	}
	// 失败的写不留审计（审计回答「发生了什么」，不是「有人试过什么」）：
	// 上面只有基线那一次成功写，所以这一族动作总共只能有 1 条。
	if n := len(auditByAction(t, h)["processor.config.write"]); n != 1 {
		t.Errorf("被拒的写不该留审计，实际 %d 条", n)
	}
}

func TestAdminDeclarationsClearNeedsExplicitEmptyArray(t *testing.T) {
	h := publishHarness(t, "shadow")
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken,
		map[string]any{"processors": []any{declProc("pii-cn", "before-upstream")}}); code != 200 {
		t.Fatalf("基线写入失败: %d %s", code, raw)
	}
	good, _ := os.ReadFile(h.configPath)

	// 漏带字段 = 拒，不是清空。
	code, out, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken, map[string]any{})
	if code != http.StatusBadRequest {
		t.Fatalf("空请求体应 400，实际 %d: %s", code, raw)
	}
	if !strings.Contains(fmt.Sprint(out), "不会被当成清空") {
		t.Errorf("错误要把「缺字段 ≠ 清空」说破: %s", raw)
	}
	// 键名写错（processor 少个 s）同样拒：严格解码在这条路上不留「大概是笔误」的余地。
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken,
		map[string]any{"processor": []any{}}); code != http.StatusBadRequest {
		t.Errorf("键名笔误应 400，实际 %d: %s", code, raw)
	}
	// 带错段的键也拒：两段各写各的，一个请求不该只改一段却带着另一段的意图。
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken,
		map[string]any{"knowledge_sources": []any{declSource("s", "https://a.internal/r", "kb")}}); code != http.StatusBadRequest {
		t.Errorf("带错段应 400，实际 %d: %s", code, raw)
	}
	now, _ := os.ReadFile(h.configPath)
	if string(now) != string(good) {
		t.Errorf("被拒的写动了磁盘:\n%s", now)
	}

	// 显式空数组 = 清空，一次做完。
	code, out, raw = policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken,
		map[string]any{"processors": []any{}})
	if code != 200 {
		t.Fatalf("清空应 200: %d %s", code, raw)
	}
	if out["count"].(float64) != 0 {
		t.Errorf("清空后 count 应为 0: %+v", out)
	}
	if _, err := config.LoadFile(h.configPath); err != nil {
		t.Errorf("清空后的文件必须仍然能严格加载: %v", err)
	}
	_, got, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/config/processors", adminToken, nil)
	if list, ok := got["processors"].([]any); !ok || len(list) != 0 {
		t.Errorf("清空后 GET 要回空数组: %+v %s", got["processors"], raw)
	}
	// 段名还在文件里（清空不是删段：下一次写仍走同一条整段替换）。
	text, _ := os.ReadFile(h.configPath)
	if !strings.Contains(string(text), "processors:") {
		t.Errorf("清空后要留一个空段:\n%s", text)
	}
}

func TestAdminKnowledgeWriteAndScopedAudit(t *testing.T) {
	h := publishHarness(t, "shadow")
	body := map[string]any{"knowledge_sources": []any{
		declSource("campus-rag", "https://rag.internal/retrieve", "campus-policy", "course-outline"),
		declSource("lab-rag", "http://127.0.0.1:8080/retrieve", "lab-kb"),
	}}
	code, out, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/knowledge_sources", adminToken, body)
	if code != 200 {
		t.Fatalf("合法知识源应写成功: %d %s", code, raw)
	}
	if out["applies"] != false {
		t.Errorf("影子模式下 applies 应为 false: %+v", out)
	}
	gcode, got, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/config/knowledge_sources", adminToken, nil)
	if gcode != 200 {
		t.Fatalf("GET 失败: %d %s", gcode, raw)
	}
	list := got["knowledge_sources"].([]any)
	if len(list) != 2 {
		t.Fatalf("应读回 2 个入口: %+v", list)
	}
	first := list[0].(map[string]any)
	if first["name"] != "campus-rag" || len(first["knowledge_bases"].([]any)) != 2 ||
		first["endpoint"] != "https://rag.internal/retrieve" || first["timeout_ms"].(float64) != 1500 {
		t.Errorf("读回的知识源与提交的不等价: %+v", first)
	}

	by := auditByAction(t, h)
	sc, detail := mustScopeOf(t, by, "knowledge.config.write")
	if sc != "system:global" {
		t.Errorf("整段配置改动的归属应是系统范围，实际 %s", sc)
	}
	if !strings.Contains(detail, "campus-rag(2 个库)") || !strings.Contains(detail, "2 条") {
		t.Errorf("审计要能回答「改成几条、哪几个入口」: %q", detail)
	}
	// 端点与库名不进审计：审计库会被导出，而委托端点是内部拓扑信息。
	for _, forbidden := range []string{"rag.internal", "127.0.0.1", "https://", "http://"} {
		if strings.Contains(detail, forbidden) {
			t.Errorf("审计 detail 不该含 %q: %q", forbidden, detail)
		}
	}

	// 把凭证写进 URL 的入口必须被拒，而且错误里那句「不能携带凭证」要说得出口；
	// 拒掉的写不留审计，也不把别人写错的凭证搬到别处去。
	before, _ := os.ReadFile(h.configPath)
	code, _, raw = policyReq(t, h, http.MethodPut, "/v1/_admin/config/knowledge_sources", adminToken,
		map[string]any{"knowledge_sources": []any{declSource("leaky", "https://tok:sk-secret@rag.internal/retrieve", "kb")}})
	if code != http.StatusBadRequest {
		t.Fatalf("带凭证的端点应 400，实际 %d: %s", code, raw)
	}
	if after, _ := os.ReadFile(h.configPath); string(after) != string(before) {
		t.Errorf("坏知识源动了磁盘:\n%s", after)
	}
	for _, e := range auditByAction(t, h)["knowledge.config.write"] {
		if strings.Contains(e.Detail, "sk-secret") || strings.Contains(e.Detail, "leaky") {
			t.Errorf("被拒的写不该进审计（更不该把凭证搬进去）: %q", e.Detail)
		}
	}
	if n := len(auditByAction(t, h)["knowledge.config.write"]); n != 1 {
		t.Errorf("被拒的写留了审计，实际 %d 条", n)
	}
}

// TestAdminDeclarationsEnforceApplies 是另一半天：切到 enforce 后要如实说「生效」。
func TestAdminDeclarationsEnforceApplies(t *testing.T) {
	h := publishHarness(t, "enforce")
	code, out, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken,
		map[string]any{"processors": []any{declProc("pii-cn", "before-upstream")}})
	if code != 200 {
		t.Fatalf("enforce 下写入应 200: %d %s", code, raw)
	}
	if out["applies"] != true || out["mode"] != "enforce" {
		t.Errorf("enforce 下要说生效: %+v", out)
	}
	for _, w := range asStrings(out["warnings"]) {
		if strings.Contains(w, "不会生效") {
			t.Errorf("enforce 下不该有不生效告警: %q", w)
		}
	}
	// 生效之后，配置文件里那份声明必须就是加载进来的那一份（视图与磁盘同源）。
	cfg, err := config.LoadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ProcessorSpecsView()) != 1 {
		t.Errorf("加载后应有 1 条已校验声明: %+v", cfg.ProcessorSpecsView())
	}
}

// TestAdminDeclarationsBadBaselineStillReadable 覆盖「磁盘上已经有一条手改坏的声明」：
// GET 必须 still 200 并带 baseline_error，而不是让面板打不开。
func TestAdminDeclarationsBadBaselineStillReadable(t *testing.T) {
	h := publishHarness(t, "shadow")
	src, err := os.ReadFile(h.configPath)
	if err != nil {
		t.Fatal(err)
	}
	broken := string(src) + "\nprocessors:\n  - name: p\n    type: pii-mask\n    phase: before-upstram\n" +
		"    scope: \"*\"\n    version: \"1\"\n    body_access: transform-body\n    fail_closed: true\n" +
		"    timeout_ms: 300\n    max_input_bytes: 4096\n    max_output_bytes: 8192\n"
	if err := os.WriteFile(h.configPath, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, raw := policyReq(t, h, http.MethodGet, "/v1/_admin/config/processors", adminToken, nil)
	if code != 200 {
		t.Fatalf("基线坏掉时 GET 仍要能答: %d %s", code, raw)
	}
	if msg := asString(out["baseline_error"]); !strings.Contains(msg, "未知的处理阶段") {
		t.Errorf("要指认基线坏在哪: %q", msg)
	}
	// 想把它改回去：合法整段写回仍然可走（不被坏基线卡死）。
	if code, _, raw := policyReq(t, h, http.MethodPut, "/v1/_admin/config/processors", adminToken,
		map[string]any{"processors": []any{declProc("pii-cn", "before-upstream")}}); code != 200 {
		t.Fatalf("修好坏基线应 200: %d %s", code, raw)
	}
	_, got, _ := policyReq(t, h, http.MethodGet, "/v1/_admin/config/processors", adminToken, nil)
	if _, bad := got["baseline_error"]; bad {
		t.Errorf("修好后不该再有基线错误: %+v", got)
	}
	if list, _ := got["processors"].([]any); len(list) != 1 {
		t.Errorf("修好后应读到 1 条: %+v", got["processors"])
	}
}

// ── 夹具辅助 ───────────────────────────────────────────────

func asStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, asString(item))
	}
	return out
}
