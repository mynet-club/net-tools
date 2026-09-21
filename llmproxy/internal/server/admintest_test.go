package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

func testOutcomeOf(t *testing.T, raw []byte) testOutcome {
	t.Helper()
	var out testOutcome
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("解析测试结果失败: %v\n%s", err, raw)
	}
	return out
}

// 按用户测一条映射：真发请求，回报是哪个上游接的、耗时、回复内容。
func TestAdminTestUserMapping(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "sys-model")

	resp, raw := h.post(t, "/v1/_admin/users/carol/test", adminToken, map[string]any{"model": "fast"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("测试应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	out := testOutcomeOf(t, raw)
	if !out.OK {
		t.Fatalf("应当成功: %s", raw)
	}
	if out.Provider != "sys-a" || out.UpstreamModel != "sys-model" {
		t.Errorf("回报的上游/模型不对: %+v", out)
	}
	if out.Content == "" || out.LatencyMs < 0 {
		t.Errorf("应当带回内容与耗时: %+v", out)
	}
	if stub.hitCount() != 1 {
		t.Errorf("应当真的打了一次上游，实际 %d", stub.hitCount())
	}
}

// 测试不该写记账、不该动熔断：它是探针，不是替用户跑业务。
func TestAdminTestDoesNotAccountOrTripBreaker(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "sys-model")

	before, err := h.db.TotalByUser(time.Time{}, "carol")
	if err != nil {
		t.Fatal(err)
	}
	code, raw := adminGet(t, h, "/v1/_admin/users/carol") // 只为确认存在
	if code != 200 {
		t.Fatal(string(raw))
	}

	if resp, raw := h.post(t, "/v1/_admin/users/carol/test", adminToken, map[string]any{"model": "fast"}); resp.StatusCode != 200 {
		t.Fatalf("测试失败 %d: %s", resp.StatusCode, raw)
	}
	after, err := h.db.TotalByUser(time.Time{}, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if after.Requests != before.Requests || after.TotalTokens != before.TotalTokens {
		t.Errorf("探测不该写记账：前 %+v 后 %+v", before, after)
	}

	// 熔断状态也不该被动：换一家必然失败的供应商再测
	dead := newModelsStub(t, http.StatusInternalServerError, `{"error":"boom"}`)
	h2 := newMUHarnessWith(t, strings.Replace(consumptionYAML(dead.srv.URL, testPricing), "models: [\"*\"]", "models: {sys-model: sys-model}", 1))
	h2.addUser(t, "dave")
	if err := h2.db.SetUserMode("dave", store.ModeConsumption); err != nil {
		t.Fatal(err)
	}
	if err := h2.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}
	before2 := h2.srv.router.SnapshotFor("dave")
	resp, raw2 := h2.post(t, "/v1/_admin/users/dave/test", adminToken, map[string]any{"model": "sys-model"})
	if resp.StatusCode != 200 {
		t.Fatalf("测试应 200，实际 %d: %s", resp.StatusCode, raw2)
	}
	if out := testOutcomeOf(t, raw2); out.OK {
		t.Errorf("上游 500 时应当报 ok=false: %+v", out)
	}
	after2 := h2.srv.router.SnapshotFor("dave")
	if len(before2) != len(after2) {
		t.Fatalf("快照大小变了: %d → %d", len(before2), len(after2))
	}
	for name, st := range after2 {
		b := before2[name]
		if st.ConsecutiveFailures != b.ConsecutiveFailures || !st.UnhealthyUntil.Equal(b.UnhealthyUntil) {
			t.Errorf("探测改了 %s 的熔断状态: %+v → %+v", name, b, st)
		}
	}
}

// 被收窄的模型：测试要给出一致的解释（与真实请求同样的归因）。
func TestAdminTestNarrowedModelExplains(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "sys-model")

	resp, raw := h.post(t, "/v1/_admin/users/carol/test", adminToken, map[string]any{"model": "outside"})
	if resp.StatusCode != 200 {
		t.Fatalf("应 200，实际 %d", resp.StatusCode)
	}
	out := testOutcomeOf(t, raw)
	if out.OK {
		t.Fatal("范围外的模型不该测成功")
	}
	if !strings.Contains(out.Error, "收窄") || !strings.Contains(out.Error, "outside") {
		t.Errorf("解释不对: %q", out.Error)
	}
	if stub.hitCount() != 0 {
		t.Error("范围外的模型不该打到上游")
	}
}

func TestAdminTestBadInput(t *testing.T) {
	h := newConsumptionHarness(t, newUsageStub(t, 0), testPricing)
	h.addUser(t, "carol")

	resp, _ := h.post(t, "/v1/_admin/users/nobody/test", adminToken, map[string]any{"model": "x"})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("不存在的用户应 404，实际 %d", resp.StatusCode)
	}
	resp, _ = h.post(t, "/v1/_admin/users/carol/test", adminToken, map[string]any{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("缺 model 应 400，实际 %d", resp.StatusCode)
	}
	resp, _ = h.get(t, "/v1/_admin/users/carol/test", adminToken)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET 应 405，实际 %d", resp.StatusCode)
	}
}

// 直接测一家系统上游：用不着用户名，模型名取它自己声明的第一个。
func TestAdminTestProvider(t *testing.T) {
	stub := newUsageStub(t, 0)
	yamlSrc := strings.Replace(consumptionYAML(stub.srv.URL, testPricing), "models: [\"*\"]", "models: {m-one: m-one, m-two: m-two}", 1)
	h := newMUHarnessWith(t, yamlSrc)

	resp, raw := h.post(t, "/v1/_admin/providers/sys-a/test", adminToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	out := testOutcomeOf(t, raw)
	if !out.OK || out.UpstreamModel != "m-one" {
		t.Errorf("应当用声明的第一个模型测通: %+v", out)
	}

	// 直通型（没声明具体名字）又不给 model：去问上游要一份模型列表，拿第一个真实名字来测。
	// 上游不给列表时要说清「测不了」以及怎么办，而不是拿个瞎编的名字打过去换 404。
	stub2 := newUsageStub(t, 0) // 默认不提供 /v1/models
	h2 := newMUHarnessWith(t, consumptionYAML(stub2.srv.URL, testPricing))
	resp, raw = h2.post(t, "/v1/_admin/providers/sys-a/test", adminToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应 200，实际 %d", resp.StatusCode)
	}
	out = testOutcomeOf(t, raw)
	if out.OK || !strings.Contains(out.Error, "没给出模型列表") {
		t.Errorf("上游不给模型列表时应当说清原因: %+v", out)
	}
	if stub2.hitCount() != 0 {
		t.Errorf("连模型名都没有就不该打对话接口，实际打了 %d 次", stub2.hitCount())
	}

	resp, _ = h.post(t, "/v1/_admin/providers/ghost/test", adminToken, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("不存在的上游应 404，实际 %d", resp.StatusCode)
	}
}

// 直通型 + 上游提供 /v1/models：不用给 model 也能测通 —— 服务端自己挑一个真实名字。
func TestAdminTestPassthroughPicksRealModel(t *testing.T) {
	stub := newUsageStub(t, 0).withModels("m-alpha", "m-beta")
	h := newMUHarnessWith(t, consumptionYAML(stub.srv.URL, testPricing)) // 系统池是 ["*"]，即直通

	resp, raw := h.post(t, "/v1/_admin/providers/sys-a/test", adminToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	out := testOutcomeOf(t, raw)
	if !out.OK {
		t.Fatalf("直通型不给 model 也应当测通（自动挑第一个真实模型）: %+v", out)
	}
	if out.UpstreamModel != "m-alpha" {
		t.Errorf("应当用列表里第一个模型 m-alpha，实际 %q", out.UpstreamModel)
	}
	if !strings.Contains(stub.lastModel(), "m-alpha") {
		t.Errorf("上游收到的模型名不对: %q", stub.lastModel())
	}
}

// 不给 model 时取声明的**上游**名（映射的右边），不能拿下游名去打上游。
func TestAdminTestProviderUsesUpstreamName(t *testing.T) {
	stub := newUsageStub(t, 0)
	yamlSrc := strings.Replace(consumptionYAML(stub.srv.URL, testPricing), "models: [\"*\"]", "models: {alias-x: real-y}", 1)
	h := newMUHarnessWith(t, yamlSrc)

	resp, raw := h.post(t, "/v1/_admin/providers/sys-a/test", adminToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	out := testOutcomeOf(t, raw)
	if !out.OK {
		t.Fatalf("应当测通: %+v", out)
	}
	if out.UpstreamModel != "real-y" {
		t.Errorf("应当上游名 real-y，实际 %q（拿下游名 alias-x 打过去就是错的名字）", out.UpstreamModel)
	}
	if !strings.Contains(stub.lastModel(), "real-y") {
		t.Errorf("上游收到的模型名不对: %q", stub.lastModel())
	}
}

// 测一个「映射表里还没有」的模型名，也得真的打到上游 ——
// 这正是「选模型」弹窗里逐条测试的用法：先确认它通不通，再决定要不要加进映射。
func TestAdminTestProviderProbesUnmappedModel(t *testing.T) {
	stub := newUsageStub(t, 0)
	yamlSrc := strings.Replace(consumptionYAML(stub.srv.URL, testPricing), "models: [\"*\"]", "models: {m-one: m-one}", 1)
	h := newMUHarnessWith(t, yamlSrc)

	resp, raw := h.post(t, "/v1/_admin/providers/sys-a/test", adminToken, map[string]any{"model": "m-nine"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	out := testOutcomeOf(t, raw)
	if !out.OK || out.UpstreamModel != "m-nine" {
		t.Fatalf("映射里没有的名字也应当原样打给上游: %+v", out)
	}
	if !strings.Contains(stub.lastModel(), "m-nine") {
		t.Errorf("上游收到的模型名不对: %q", stub.lastModel())
	}
}

// 还没保存的供应商也要能逐条测试（界面里内联当前编辑区的地址与密钥）。
func TestAdminTestProviderWithInlineCreds(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newMUHarnessWith(t, consumptionYAML("http://127.0.0.1:1", testPricing)) // 系统池指向一个死地址

	resp, raw := h.post(t, "/v1/_admin/providers/fresh-unsaved/test", adminToken, map[string]any{
		"model": "m-inline", "base_url": stub.srv.URL, "api_key": "sk-inline",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("内联测试应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	if out := testOutcomeOf(t, raw); !out.OK {
		t.Fatalf("应当测通: %s", raw)
	}
	if got := stub.authHeader(); got != "Bearer sk-inline" {
		t.Errorf("内联密钥没被用上: %q", got)
	}

	// 没带 base_url 又没有这家：明确 404，而不是猜一个地址去打
	resp, _ = h.post(t, "/v1/_admin/providers/fresh-unsaved/test", adminToken, map[string]any{"model": "m"})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("既没保存也没带 base_url 应 404，实际 %d", resp.StatusCode)
	}
	// 带了地址但没密钥：报清楚缺什么，别拿空 Bearer 去打上游
	resp, raw = h.post(t, "/v1/_admin/providers/fresh-unsaved/test", adminToken, map[string]any{
		"model": "m-inline", "base_url": stub.srv.URL,
	})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "api_key") {
		t.Errorf("缺密钥应 400 且说明原因，实际 %d: %s", resp.StatusCode, raw)
	}
}

// 还没保存的供应商也要能先探测模型列表（界面里「选模型」弹窗依赖它）。
func TestAdminDiscoverWithInlineBeforeSave(t *testing.T) {
	stub := newModelsStub(t, 200, `{"data":[{"id":"aaa"},{"id":"bbb"}]}`)
	h := newMUHarnessWith(t, consumptionYAML("http://127.0.0.1:1", testPricing)) // 系统池指向一个死地址

	resp, raw := h.post(t, "/v1/_admin/providers/fresh-unsaved/discover", adminToken, map[string]any{
		"base_url": stub.srv.URL, "api_key": "sk-inline",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("内联探测应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "aaa") || !strings.Contains(string(raw), "bbb") {
		t.Errorf("没拿到模型列表: %s", raw)
	}
	if got := stub.authHeader(); got != "Bearer sk-inline" {
		t.Errorf("内联密钥没被用上: %q", got)
	}
}
