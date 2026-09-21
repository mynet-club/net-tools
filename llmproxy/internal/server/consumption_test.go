package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/secrets"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// newMUHarnessWith 用指定配置搭多用户环境（newMUHarness 用的是固定那份 YAML）。
func newMUHarnessWith(t *testing.T, yamlSrc string) *muHarness {
	t.Helper()
	h := newHarness(t, yamlSrc)
	cipher, err := secrets.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatalf("生成主密钥失败: %v", err)
	}
	h.srv.WithSecrets(cipher)
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatalf("SyncUsers: %v", err)
	}
	return &muHarness{harness: h, cipher: cipher}
}

// 消费模式的端到端测试：系统池是一个**能连上**的假上游（和别处那个必然连不上的不同），
// 这样才验证得了「真的走了系统池、真的被计量」。
type usageStub struct {
	srv   *httptest.Server
	delay time.Duration

	mu   sync.Mutex
	hits int
	// started 在每次开始处理时发一个信号，用来做并发测试的同步点
	started chan struct{}
}

func newUsageStub(t *testing.T, delay time.Duration) *usageStub {
	t.Helper()
	s := &usageStub{delay: delay, started: make(chan struct{}, 8)}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits++
		s.mu.Unlock()
		select {
		case s.started <- struct{}{}:
		default:
		}
		var probe struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&probe)
		if s.delay > 0 {
			time.Sleep(s.delay)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "cmpl-x", "object": "chat.completion", "model": probe.Model,
			"choices": []map[string]any{{
				"index": 0, "message": map[string]string{"role": "assistant", "content": "ok"},
				"finish_reason": "stop",
			}},
			"usage": map[string]int{
				"prompt_tokens": 1000, "completion_tokens": 500, "total_tokens": 1500,
				// 命中 800、未命中 200：单价差 50 倍，计费必须区分
				"prompt_cache_hit_tokens": 800, "prompt_cache_miss_tokens": 200,
			},
		})
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *usageStub) hitCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

func consumptionYAML(stubURL string, pricing string) string {
	return fmt.Sprintf(`
server:
  host: 127.0.0.1
  port: 0
  api_keys:
    - sk-static
  admin_token: sk-admin
routing:
  retry: 1
  failure_threshold: 3
  cooldown_seconds: 60
providers:
  - name: sys-a
    enabled: true
    base_url: %s/v1
    api_key: sk-sys
    weight: 1
    models: ["*"]
%s
database:
  path: ""
  retain_days: 30
log:
  level: error
`, stubURL, pricing)
}

const testPricing = `pricing:
  currency: CNY
  models:
    sys-model: {cache_hit: 0.04, cache_miss: 2.0, output: 8.0}
    "*": {cache_hit: 0, cache_miss: 0, output: 0}`

// newConsumptionHarness 搭一个「系统池可连通」的多用户环境。
func newConsumptionHarness(t *testing.T, stub *usageStub, pricing string) *muHarness {
	t.Helper()
	return newMUHarnessWith(t, consumptionYAML(stub.srv.URL, pricing))
}

// setConsumption 把用户切成消费模式并配一条模型映射。
func setConsumption(t *testing.T, h *muHarness, user, model, upstream string) {
	t.Helper()
	if err := h.db.SetUserMode(user, store.ModeConsumption); err != nil {
		t.Fatal(err)
	}
	if err := h.db.UpsertUserModel(store.UserModel{
		UserName: user, Model: model, Upstream: upstream, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}
}

// 消费用户走系统池：请求要真的打到系统上游，且按上游模型名计费。
func TestConsumptionUsesSystemPoolAndMeters(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "sys-model")

	resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "fast", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("消费用户应当成功，实际 %d: %s", resp.StatusCode, raw)
	}
	if stub.hitCount() != 1 {
		t.Fatalf("系统上游应被调用 1 次，实际 %d", stub.hitCount())
	}

	// 计量：按上游模型名 sys-model 的价格算
	// 800 命中 × 0.04/M + 200 未命中 × 2/M + 500 输出 × 8/M
	wantCost := 800.0/1e6*0.04 + 200.0/1e6*2.0 + 500.0/1e6*8.0
	_, cost := h.srv.meters.Snapshot("carol")
	if diff := cost - wantCost; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("金额算错：期望 %.8f，实际 %.8f", wantCost, cost)
	}

	// 自助接口里能看到模式、配额与金额
	_, body := h.get(t, "/v1/_me", token)
	var me map[string]any
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatal(err)
	}
	if me["mode"] != store.ModeConsumption {
		t.Errorf("/v1/_me 应报 mode=consumption，实际 %v", me["mode"])
	}
	if me["quota"] == nil {
		t.Error("/v1/_me 应带上配额信息")
	}

	// 库里那条用量必须标成系统付费，否则配额统计不到
	su, err := h.db.SystemUsageSince("carol", store.MonthStart(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if su.Requests != 1 || su.TotalTokens != 1500 {
		t.Fatalf("系统付费用量不对: %+v", su)
	}
	if su.CacheHitTokens != 800 || su.CacheMissTokens != 200 {
		t.Fatalf("缓存拆分没记上: %+v", su)
	}
}

// 白名单：没映射的模型直接 403，不去打系统上游。
func TestConsumptionModelNotAllowed(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "sys-model")

	resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "expensive-model", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("没映射的模型应 403，实际 %d: %s", resp.StatusCode, raw)
	}
	if stub.hitCount() != 0 {
		t.Fatal("被拒的请求不该打到系统上游")
	}

	// /v1/models 要如实列出白名单里的模型
	_, body := h.get(t, "/v1/models", token)
	if !strings.Contains(string(body), "fast") || strings.Contains(string(body), "sys-model") {
		t.Fatalf("/v1/models 应只列白名单里的下游名: %s", body)
	}
}

// 配额用尽后拒绝，并且是「软限额」：跨过上限的那一条放行，之后的挡掉。
func TestConsumptionQuotaExceeded(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "sys-model")

	// 配额 1000 token，而一次请求就要 1500 —— 第一条放行，第二条就必须挡住
	if err := h.db.SetUserQuota("carol", 1000, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}

	resp, _ := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "fast", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("第一条应放行（软限额），实际 %d", resp.StatusCode)
	}

	resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "fast", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("超配额应 402，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "配额") {
		t.Fatalf("错误信息应当说清是配额问题: %s", raw)
	}
	if stub.hitCount() != 1 {
		t.Fatalf("第二条不该打到上游，实际命中 %d", stub.hitCount())
	}
}

// RPM 限流。
func TestConsumptionRateLimit(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "sys-model")

	// rpm=6 → 桶容量 1、每秒补 0.1，连发必然被挡
	if err := h.db.SetUserLimits("carol", 6, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}

	first, _ := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "fast", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	second, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "fast", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	if first.StatusCode != http.StatusOK {
		t.Fatalf("第一条应通过，实际 %d", first.StatusCode)
	}
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("第二条应 429，实际 %d: %s", second.StatusCode, raw)
	}
}

// 并发上限：第一条还挂着的时候，第二条必须被挡。
func TestConsumptionConcurrencyLimit(t *testing.T) {
	stub := newUsageStub(t, 400*time.Millisecond)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "sys-model")
	if err := h.db.SetUserLimits("carol", 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}

	body := map[string]any{"model": "fast", "messages": []map[string]any{{"role": "user", "content": "hi"}}}
	first := make(chan int, 1)
	go func() {
		resp, _ := h.post(t, "/v1/chat/completions", token, body)
		first <- resp.StatusCode
	}()

	// 等上游确实开始处理了，此时并发位被占住
	select {
	case <-stub.started:
	case <-time.After(3 * time.Second):
		t.Fatal("上游没有被调用")
	}

	resp, raw := h.post(t, "/v1/chat/completions", token, body)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("超过并发上限应 429，实际 %d: %s", resp.StatusCode, raw)
	}
	if got := <-first; got != http.StatusOK {
		t.Fatalf("被占位的那条应当正常完成，实际 %d", got)
	}
}

// byo 用户没配上游时不再回退系统池 —— 否则等于白嫖网关主人的上游。
// 这条是相对早先版本的行为变更，钉在这里。
func TestBYOWithoutProvidersDoesNotFallBackToSystem(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "dave") // 默认 byo，没配任何上游

	resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "fast", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("应明确失败，实际 %d: %s", resp.StatusCode, raw)
	}
	if stub.hitCount() != 0 {
		t.Fatal("byo 用户没有上游时不该打到系统池")
	}
	if !strings.Contains(string(raw), "consumption") {
		t.Fatalf("报错要提示可以改走消费模式: %s", raw)
	}
}

// 方案 A：消费用户没配模型映射时，继承系统池声明的全部模型（开箱可用）。
func TestConsumptionInheritsSystemPoolWhenNoMapping(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing) // 系统池 sys-a 是 models: ["*"] 直通
	token := h.addUser(t, "carol")
	// 只切成消费模式，不配任何映射
	if err := h.db.SetUserMode("carol", store.ModeConsumption); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}

	// 任意模型名都该能用（继承 = 不拦）
	resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "whatever-name", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("继承模式下应当开箱可用，实际 %d: %s", resp.StatusCode, raw)
	}
	if stub.hitCount() != 1 {
		t.Fatalf("应当打到系统上游，实际命中 %d", stub.hitCount())
	}

	// /v1/_me 要说清来源是继承
	_, body := h.get(t, "/v1/_me", token)
	var me map[string]any
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatal(err)
	}
	if me["models_source"] != "inherit" {
		t.Errorf("models_source 应为 inherit，实际 %v", me["models_source"])
	}
	if me["models_passthrough"] != true {
		t.Errorf("系统池有直通供应商时应当标出来，实际 %v", me["models_passthrough"])
	}
}

// 系统池声明了具体模型名（非直通）时：继承列出这些名字；
// 打一个池子里没有的模型 —— 那是池子的问题，不该报 403（不能让人以为是自己没权限）。
func TestConsumptionInheritListAndPoolMissAttribution(t *testing.T) {
	stub := newUsageStub(t, 0)
	yamlSrc := strings.Replace(consumptionYAML(stub.srv.URL, testPricing), "models: [\"*\"]",
		"models: {m-one: m-one, m-two: m-two}", 1)
	h := newMUHarnessWith(t, yamlSrc)
	token := h.addUser(t, "carol")
	if err := h.db.SetUserMode("carol", store.ModeConsumption); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}

	// /v1/models 应当列出池子声明的两个名字
	_, body := h.get(t, "/v1/models", token)
	if !strings.Contains(string(body), "m-one") || !strings.Contains(string(body), "m-two") {
		t.Errorf("/v1/models 应当列出继承来的模型名: %s", body)
	}

	// 池子里没有的模型 → 502（上游无候选），且报错里带上可用模型
	resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "not-in-pool", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("池子里没有 ≠ 用户没权限，不该 403: %s", raw)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("应当 502，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "m-one") {
		t.Errorf("报错里应当列出可用模型: %s", raw)
	}
}

// 有映射 = 收窄：范围外的模型 403，并且话术要指向管理员。
func TestConsumptionNarrowedStillForbidden(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "sys-model")

	resp, raw := h.post(t, "/v1/chat/completions", token, map[string]any{
		"model": "outside", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("被收窄的模型应当 403，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "管理员") {
		t.Errorf("403 的话术要指向管理员: %s", raw)
	}
	_, body := h.get(t, "/v1/_me", token)
	if !strings.Contains(string(body), `"models_source":"own"`) {
		t.Errorf("配了映射时来源应为 own: %s", body)
	}
}

// 清空映射 = 放开回继承（管理端的「改为继承系统池」）。
func TestClearMappingsReturnsToInherit(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	token := h.addUser(t, "carol")
	setConsumption(t, h, "carol", "fast", "sys-model")

	// 收窄状态下，范围外的模型被拒
	body := map[string]any{"model": "outside", "messages": []map[string]any{{"role": "user", "content": "hi"}}}
	if resp, _ := h.post(t, "/v1/chat/completions", token, body); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("前置条件不成立：应当先被拒，实际 %d", resp.StatusCode)
	}

	// 清空全部映射
	resp, raw := h.del(t, "/v1/_admin/users/carol/models", adminToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("清空映射失败 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), `"models_source":"inherit"`) {
		t.Errorf("清空后应回到继承: %s", raw)
	}
	if ms, _ := h.db.ListUserModels("carol"); len(ms) != 0 {
		t.Errorf("库里应当没有映射了: %+v", ms)
	}

	// 现在同样的请求应当放行
	if resp, raw := h.post(t, "/v1/chat/completions", token, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("清空后应当可用，实际 %d: %s", resp.StatusCode, raw)
	}
}

// 管理端列表要能看出「继承」还是「收窄」。
func TestAdminSummaryShowsModelSource(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	h.addUser(t, "inherit-user")
	h.addUser(t, "narrow-user")
	for _, n := range []string{"inherit-user", "narrow-user"} {
		if err := h.db.SetUserMode(n, store.ModeConsumption); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.db.UpsertUserModel(store.UserModel{UserName: "narrow-user", Model: "fast", Upstream: "sys-model", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}

	code, body := adminGet(t, h, "/v1/_admin/users")
	if code != 200 {
		t.Fatalf("列表应 200，实际 %d", code)
	}
	var out struct {
		Users []struct {
			Name         string `json:"name"`
			ModelsSource string `json:"models_source"`
		} `json:"users"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, u := range out.Users {
		got[u.Name] = u.ModelsSource
	}
	if got["inherit-user"] != "inherit" || got["narrow-user"] != "own" {
		t.Errorf("来源标注不对: %+v", got)
	}
}
