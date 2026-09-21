package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

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
	if err := h.db.SetUserQuota("carol", 1_000_000, 10); err != nil {
		t.Fatal(err)
	}
	if err := h.db.SetUserLimits("carol", 60, 4); err != nil {
		t.Fatal(err)
	}
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
	if err := h.db.SetUserQuota("carol", 500, 5); err != nil {
		t.Fatal(err)
	}
	if err := h.db.SetUserLimits("carol", 30, 2); err != nil {
		t.Fatal(err)
	}
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
	if u.QuotaMonthTokens != 42 || u.QuotaMonthCost != 5 {
		t.Errorf("配额应只改 token 那一项: tokens=%d cost=%v", u.QuotaMonthTokens, u.QuotaMonthCost)
	}
	if u.RPM != 30 || u.MaxConcurrent != 2 {
		t.Errorf("限流不该被动到: rpm=%d conc=%d", u.RPM, u.MaxConcurrent)
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
