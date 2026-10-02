package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

const adminToken = "sk-admin"

// adminGet 用 admin_token 取 JSON。
func adminGet(t *testing.T, h *muHarness, path string) (int, []byte) {
	t.Helper()
	resp, body := h.get(t, path, adminToken)
	return resp.StatusCode, body
}

// 列表要能看到「谁在用、什么模式、配额用了多少」——管理员看的是整台网关。
func TestAdminListUsersShowsModeQuotaAndUsage(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "sys-model")
	setQuota(t, h, "carol", 1_000_000, 10, 60, 4)
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}

	// 打一条真实请求，让配额里有用量
	if resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "fast", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}); resp.StatusCode != 200 {
		t.Fatalf("请求应当成功，实际 %d: %s", resp.StatusCode, raw)
	}

	code, body := adminGet(t, h, "/v1/_admin/users")
	if code != http.StatusOK {
		t.Fatalf("列表应 200，实际 %d: %s", code, body)
	}
	var out struct {
		Users []struct {
			Name   string   `json:"name"`
			Mode   string   `json:"mode"`
			Models []string `json:"models"`
			Quota  struct {
				MonthTokens int64   `json:"month_tokens"`
				MonthCost   float64 `json:"month_cost"`
				UsedTokens  int64   `json:"used_tokens"`
				UsedCost    float64 `json:"used_cost"`
			} `json:"quota"`
			Limits struct {
				RPM  int `json:"rpm"`
				Conc int `json:"max_concurrent"`
			} `json:"limits"`
		} `json:"users"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	var carol *struct {
		Name   string   `json:"name"`
		Mode   string   `json:"mode"`
		Models []string `json:"models"`
		Quota  struct {
			MonthTokens int64   `json:"month_tokens"`
			MonthCost   float64 `json:"month_cost"`
			UsedTokens  int64   `json:"used_tokens"`
			UsedCost    float64 `json:"used_cost"`
		} `json:"quota"`
		Limits struct {
			RPM  int `json:"rpm"`
			Conc int `json:"max_concurrent"`
		} `json:"limits"`
	}
	_ = carol
	for i := range out.Users {
		if out.Users[i].Name == "carol" {
			carol = &out.Users[i]
		}
	}
	if carol == nil {
		t.Fatalf("列表里没有 carol: %s", body)
	}
	if carol.Mode != store.ModeConsumption {
		t.Errorf("模式应为 consumption，实际 %q", carol.Mode)
	}
	if len(carol.Models) != 1 || carol.Models[0] != "fast" {
		t.Errorf("模型列表不对: %+v", carol.Models)
	}
	if carol.Quota.MonthTokens != 1_000_000 || carol.Quota.MonthCost != 10 {
		t.Errorf("配额不对: %+v", carol.Quota)
	}
	if carol.Quota.UsedTokens != 1500 || carol.Quota.UsedCost <= 0 {
		t.Errorf("已用量/金额不对（应统计系统付费的那次）: %+v", carol.Quota)
	}
	if carol.Limits.RPM != 60 || carol.Limits.Conc != 4 {
		t.Errorf("限流不对: %+v", carol.Limits)
	}
}

// 部分更新：只传的字段才改，没传的必须原样保留 —— 否则界面改个配额就把模式重置了。
func TestAdminUpdateUserIsPartial(t *testing.T) {
	h := newConsumptionHarness(t, newUsageStub(t, 0), testPricing)
	h.addUser(t, "carol")
	setQuota(t, h, "carol", 500, 5, 30, 2)
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}

	// 只改模式
	resp, raw := h.put(t, "/v1/_admin/users/carol", adminToken, map[string]any{"mode": "consumption"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("改模式失败 %d: %s", resp.StatusCode, raw)
	}
	// 只改配额
	resp, raw = h.put(t, "/v1/_admin/users/carol", adminToken, map[string]any{"quota_month_tokens": 42})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("改配额失败 %d: %s", resp.StatusCode, raw)
	}

	u, err := h.db.GetUser("carol")
	if err != nil || u == nil {
		t.Fatal(err)
	}
	if !u.IsConsumption() {
		t.Error("改配额不该把模式重置回 byo")
	}
	// 配额与限流读 scope_quota（§2.7 规则 2）：users 行上已经没有这些列。
	q, err := h.db.GetScopeQuota(policy.MustScope(policy.ScopeUser, "carol"))
	if err != nil || q == nil {
		t.Fatalf("GetScopeQuota: %v", err)
	}
	if q.QuotaMonthTokens != 42 || q.QuotaMonthCost != 5 {
		t.Errorf("配额应只改 token 那一项: tokens=%d cost=%v", q.QuotaMonthTokens, q.QuotaMonthCost)
	}
	if q.RPM != 30 || q.MaxConcurrent != 2 {
		t.Errorf("限流不该被动到: rpm=%d conc=%d", q.RPM, q.MaxConcurrent)
	}

	// 非法输入要挡住
	resp, _ = h.put(t, "/v1/_admin/users/carol", adminToken, map[string]any{"mode": "whatever"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("非法模式应 400，实际 %d", resp.StatusCode)
	}
	resp, _ = h.put(t, "/v1/_admin/users/carol", adminToken, map[string]any{"quota_month_tokens": -1})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("负配额应 400，实际 %d", resp.StatusCode)
	}
	resp, _ = h.put(t, "/v1/_admin/users/nobody", adminToken, map[string]any{"mode": "byo"})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("不存在的用户应 404，实际 %d", resp.StatusCode)
	}
}

// 代用户配模型映射：这是管理员最常用的动作。
func TestAdminModelMappingCRUD(t *testing.T) {
	h := newConsumptionHarness(t, newUsageStub(t, 0), testPricing)
	h.addUser(t, "carol")

	resp, raw := h.put(t, "/v1/_admin/users/carol/models", adminToken, map[string]any{
		"model": "fast", "upstream": "sys-model",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("加映射失败 %d: %s", resp.StatusCode, raw)
	}
	// byo 用户加映射要给出提示（加了但暂时不生效）
	if !strings.Contains(string(raw), "byo") {
		t.Errorf("byo 用户加映射应当提示暂不生效: %s", raw)
	}

	// 模型名里带 / 也要能加（这就是不放路径里的原因）
	resp, raw = h.put(t, "/v1/_admin/users/carol/models", adminToken, map[string]any{
		"model": "qwen/qwen-max", "upstream": "qwen-max", "provider": "sys-a",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("带斜杠的模型名失败 %d: %s", resp.StatusCode, raw)
	}

	code, body := adminGet(t, h, "/v1/_admin/users/carol/models")
	if code != http.StatusOK {
		t.Fatalf("列映射失败 %d", code)
	}
	if !strings.Contains(string(body), "qwen/qwen-max") {
		t.Errorf("列不出带斜杠的映射: %s", body)
	}

	// 删除用 ?model=，同样因为模型名可能含 /
	resp, raw = h.del(t, "/v1/_admin/users/carol/models?model="+`qwen/qwen-max`, adminToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("删映射失败 %d: %s", resp.StatusCode, raw)
	}
	if ms, _ := h.db.ListUserModels("carol"); len(ms) != 1 {
		t.Errorf("删除后应剩 1 条: %+v", ms)
	}

	// 缺 model / 删不存在的
	resp, _ = h.put(t, "/v1/_admin/users/carol/models", adminToken, map[string]any{"upstream": "x"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("缺 model 应 400，实际 %d", resp.StatusCode)
	}
	resp, _ = h.del(t, "/v1/_admin/users/carol/models?model=nope", adminToken)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("删不存在的映射应 404，实际 %d", resp.StatusCode)
	}
}

// 按用户看用量：管理员视角要和用户自助看到的一致。
func TestAdminUserUsage(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "sys-model")

	h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "fast", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	})

	code, body := adminGet(t, h, "/v1/_admin/users/carol/usage?days=7")
	if code != http.StatusOK {
		t.Fatalf("用量应 200，实际 %d: %s", code, body)
	}
	var out struct {
		Days int `json:"days"`
		Rows []struct {
			Model      string   `json:"model"`
			SystemPaid bool     `json:"system_paid"`
			Cost       *float64 `json:"cost"`
		} `json:"rows"`
		Cost struct {
			MonthSystem float64 `json:"month_system"`
			Priced      bool    `json:"priced"`
		} `json:"cost"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Days != 7 || len(out.Rows) != 1 {
		t.Fatalf("用量行不对: %+v", out)
	}
	if !out.Rows[0].SystemPaid || out.Rows[0].Cost == nil {
		t.Errorf("系统付费的行使应有金额: %+v", out.Rows[0])
	}
	if !out.Cost.Priced || out.Cost.MonthSystem <= 0 {
		t.Errorf("本月系统消费金额不对: %+v", out.Cost)
	}

	// 不存在的用户
	code, _ = adminGet(t, h, "/v1/_admin/users/nobody/usage")
	if code != http.StatusNotFound {
		t.Errorf("不存在的用户应 404，实际 %d", code)
	}
	// 非法 days
	code, _ = adminGet(t, h, "/v1/_admin/users/carol/usage?days=9999")
	if code != http.StatusBadRequest {
		t.Errorf("非法 days 应 400，实际 %d", code)
	}
}

// 系统上游列表 + 探测：管理员代用户配映射时要能看到「系统池里有哪些模型」。
func TestAdminSystemProvidersAndDiscover(t *testing.T) {
	stub := newModelsStub(t, 200, `{"data":[{"id":"sys-model-a"},{"id":"sys-model-b"}]}`)
	h := newMUHarnessWith(t, consumptionYAML(stub.srv.URL, testPricing))

	code, body := adminGet(t, h, "/v1/_admin/providers")
	if code != http.StatusOK {
		t.Fatalf("系统上游列表应 200，实际 %d: %s", code, body)
	}
	if !strings.Contains(string(body), "sys-a") {
		t.Errorf("列表里应有 sys-a: %s", body)
	}

	resp, raw := h.post(t, "/v1/_admin/providers/sys-a/discover", adminToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("探测应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "sys-model-a") || !strings.Contains(string(raw), "sys-model-b") {
		t.Errorf("探测结果不对: %s", raw)
	}

	resp, raw = h.post(t, "/v1/_admin/providers/ghost/discover", adminToken, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("不存在的系统上游应 404，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "/v1/_admin/providers") {
		t.Errorf("404 里应提示去哪看有哪些系统上游: %s", raw)
	}
}

// 管理接口必须只认 admin_token：用户 token 与乱填都不行。
func TestAdminRequiresAdminToken(t *testing.T) {
	h := newConsumptionHarness(t, newUsageStub(t, 0), testPricing)
	userToken := h.addUser(t, "carol")

	for _, tok := range []string{userToken, "sk-wrong", ""} {
		resp, _ := h.get(t, "/v1/_admin/users", tok)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("token=%q 应 403，实际 %d", tok, resp.StatusCode)
		}
		resp, _ = h.put(t, "/v1/_admin/users/carol", tok, map[string]any{"mode": "consumption"})
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("写操作 token=%q 应 403，实际 %d", tok, resp.StatusCode)
		}
	}
	// 用户 token 更不能用来删用户
	resp, _ := h.del(t, "/v1/_admin/users/carol", userToken)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("删用户应 403，实际 %d", resp.StatusCode)
	}
	if u, _ := h.db.GetUser("carol"); u == nil {
		t.Error("用户被误删了")
	}
}

// 记账：管理接口改配额后，用户侧立刻生效（同一个来源）。
func TestAdminQuotaTakesEffectForUser(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "sys-model")

	// 管理员把配额压到 1：第一条放行（软限额），第二条必须被挡
	if resp, raw := h.put(t, "/v1/_admin/users/carol", adminToken, map[string]any{
		"quota_month_tokens": 1,
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("设配额失败 %d: %s", resp.StatusCode, raw)
	}

	body := map[string]any{"model": "fast", "messages": []map[string]any{{"role": "user", "content": "hi"}}}
	if resp, _ := h.post(t, "/v1/chat/completions", token, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("第一条应放行，实际 %d", resp.StatusCode)
	}
	if resp, raw := h.post(t, "/v1/chat/completions", token, body); resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("第二条应 402，实际 %d: %s", resp.StatusCode, raw)
	}
	_ = time.Now
}

// 导出 CSV：字段齐全、金额与 rowCharge 同一口径。
func TestAdminUsageExportCSV(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "sys-model", "")
	if resp, body := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "sys-model", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	}); resp.StatusCode != 200 {
		t.Fatalf("请求失败: %d %s", resp.StatusCode, body)
	}

	code, body := adminGet(t, h, "/v1/_admin/usage/export")
	if code != 200 {
		t.Fatalf("export = %d %s", code, body)
	}
	text := string(body)
	for _, col := range []string{"day", "user_name", "amount", "currency", "charge_frozen"} {
		if !strings.Contains(text, col) {
			t.Errorf("CSV 缺列 %q: %s", col, text)
		}
	}
	if !strings.Contains(text, "carol") {
		t.Errorf("应当含 carol 的行: %s", text)
	}

	code, body = adminGet(t, h, "/v1/_admin/usage/export?monthly=1")
	if code != 200 {
		t.Fatalf("monthly export = %d %s", code, body)
	}
	if !strings.Contains(string(body), "month") {
		t.Errorf("月合计 CSV 缺 month 列: %s", body)
	}
}

// 审计：建用户、改价都要留下记录，且不回显密钥。
func TestAdminAuditLog(t *testing.T) {
	h := newMUHarness(t)
	// 建用户
	resp, body := h.post(t, "/v1/_admin/users", adminToken, map[string]any{"name": "auditee"})
	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		t.Fatalf("建用户: %d %s", resp.StatusCode, body)
	}
	// 删用户
	req, _ := http.NewRequest(http.MethodDelete, h.gateway.URL+"/v1/_admin/users/auditee", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}

	code, body := adminGet(t, h, "/v1/_admin/audit")
	if code != 200 {
		t.Fatalf("audit = %d %s", code, body)
	}
	text := string(body)
	if !strings.Contains(text, "user.create") || !strings.Contains(text, "user.delete") {
		t.Errorf("审计应含 create/delete: %s", text)
	}
	if strings.Contains(text, "sk-") {
		t.Errorf("审计不得含密钥明文: %s", text)
	}
}

// OpenAPI spec 可访问且像份 OpenAPI 3。
func TestOpenAPISpec(t *testing.T) {
	h := newMUHarness(t)
	resp, raw := h.get(t, "/v1/openapi.yaml", "")
	if resp.StatusCode != 200 {
		t.Fatalf("openapi = %d %s", resp.StatusCode, raw)
	}
	text := string(raw)
	for _, want := range []string{"openapi: 3", "paths:", "/v1/chat/completions", "/v1/_admin/usage/export"} {
		if !strings.Contains(text, want) {
			t.Errorf("spec 缺 %q", want)
		}
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "yaml") {
		t.Errorf("content-type = %q", ct)
	}
}

// 审计归属 + 按范围查询（§2.7 规则 2）：一条动作落在哪个范围，取决于它**关于**谁，
// 而不是谁按下了按钮 —— 管理员给别人建用户、录分发价，归属都在那个范围里。
func TestAdminAuditScopedQuery(t *testing.T) {
	h := newMUHarness(t)
	if resp, raw := h.post(t, "/v1/_admin/users", adminToken, map[string]any{"name": "auditee"}); resp.StatusCode >= 300 {
		t.Fatalf("建用户: %d %s", resp.StatusCode, raw)
	}
	base := hourFloor(time.Now().Add(-time.Hour))
	putPrice := func(scope, model string) {
		t.Helper()
		resp, raw := h.put(t, "/v1/_admin/prices/user", adminToken, map[string]any{
			"scope": scope, "model": model,
			"valid_from": base.Format(time.RFC3339),
			"in_miss":    1.0, "out": 4.0,
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("录分发价 %s/%s: %d %s", scope, model, resp.StatusCode, raw)
		}
	}
	putPrice("user:auditee", "per-user-model")
	putPrice("default", "default-model")

	entries := func(query string) []map[string]any {
		t.Helper()
		code, body := adminGet(t, h, "/v1/_admin/audit"+query)
		if code != http.StatusOK {
			t.Fatalf("audit%s = %d %s", query, code, body)
		}
		var out struct {
			Entries []map[string]any `json:"entries"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("解析审计响应: %v\n%s", err, body)
		}
		return out.Entries
	}
	actionsWith := func(list []map[string]any, action string) []map[string]any {
		var hit []map[string]any
		for _, e := range list {
			if e["action"] == action {
				hit = append(hit, e)
			}
		}
		return hit
	}
	scopeOf := func(e map[string]any) (string, string) {
		m, _ := e["scope"].(map[string]any)
		s, _ := m["kind"].(string)
		i, _ := m["id"].(string)
		return s, i
	}

	// 每条都带归属：无范围的读接口已经退役，「全量列一下」也不该把归属读丢。
	all := entries("?n=200")
	if len(all) == 0 {
		t.Fatal("全量审计为空")
	}
	for _, e := range all {
		if k, _ := scopeOf(e); k == "" {
			t.Errorf("审计条目缺 scope: %+v", e)
		}
	}

	// 建用户归那个用户，不归 admin 按钮所在的系统范围。
	own := entries("?n=200&scope=user:auditee")
	created := actionsWith(own, "user.create")
	if len(created) != 1 {
		t.Fatalf("user:auditee 下应有 1 条 user.create，实际 %+v", created)
	}
	if k, i := scopeOf(created[0]); k != "user" || i != "auditee" {
		t.Errorf("user.create 归属错: %s:%s", k, i)
	}
	// 单用户覆盖价进用户范围，全局默认价进系统范围。
	if got := actionsWith(own, "price.user"); len(got) != 1 {
		t.Fatalf("user:auditee 下应有 1 条 price.user，实际 %+v", got)
	} else if !strings.Contains(stringified(got[0]), "per-user-model") {
		t.Errorf("用户覆盖价的审计没指到那条价: %+v", got[0])
	}
	sys := entries("?n=200&scope=system:global")
	def := actionsWith(sys, "price.user")
	if len(def) != 1 || !strings.Contains(stringified(def[0]), "default-model") {
		t.Errorf("default 分发价应落在 system:global，实际 %+v", def)
	}
	// 两个范围的并集 = 各自之和，且不掺别人的。
	both := entries("?n=200&scope=user:auditee&scope=system:global")
	if len(actionsWith(both, "price.user")) != 2 {
		t.Errorf("并集应含 2 条 price.user: %+v", actionsWith(both, "price.user"))
	}
	if len(actionsWith(both, "user.create")) != 1 {
		t.Error("并集里的 user.create 数量不对")
	}
	// 没配过的范围：200 空集，而不是「读不到就返回全量」。
	if got := entries("?n=200&scope=organization:nobody-here"); len(got) != 0 {
		t.Errorf("无关范围应返回空集，实际 %+v", got)
	}
	// 裸用户名与通配都不认：前者是 3.0 要清掉的歧义旧形式，后者服务端没有对应语义。
	for _, bad := range []string{"auditee", "organization:*", "*", "bogus:x"} {
		code, _ := adminGet(t, h, "/v1/_admin/audit?scope="+url.QueryEscape(bad))
		if code != http.StatusBadRequest {
			t.Errorf("scope=%q 应 400，实际 %d", bad, code)
		}
	}
}

// stringified 把一条审计响应序列化回文本，便于做包含性断言。
func stringified(e map[string]any) string {
	b, _ := json.Marshal(e)
	return string(b)
}
