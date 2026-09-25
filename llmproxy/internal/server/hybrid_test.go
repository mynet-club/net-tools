package server

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// hybridYAML：系统池有一家直通上游（指向 stub），routing.retry=2 留出「自有失败 → 回落系统」的余量。
func hybridYAML(stubURL string) string {
	return fmt.Sprintf(`
server:
  host: 127.0.0.1
  port: 0
  api_keys:
    - sk-static
  admin_token: sk-admin
routing:
  retry: 2
  failure_threshold: 3
  cooldown_seconds: 60
providers:
  - name: sys-a
    enabled: true
    base_url: %s/v1
    api_key: sk-sys
    weight: 1
    models: ["*"]
database:
  path: ""
  retain_days: 30
log:
  level: error
`, stubURL)
}

// 消费用户同时配了自有上游：自有命中时走自己的，且**不计网关的账**。
func TestHybridPrefersOwnUpstream(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newMUHarnessWith(t, hybridYAML(stub.srv.URL))
	own := startMockUpstream(t, &mockUpstream{name: "my-deepseek", apiKey: "sk-mine"})

	token := h.addUser(t, "arthur")
	setConsumption(t, h, "arthur", "fast", "sys-model") // 系统池也能接
	// 自有上游点名声明 fast
	h.addProvider(t, "arthur", "my-deepseek", own.baseURL+"/v1", "sk-mine", `{"fast": "fast"}`)

	resp, raw := h.post(t, "/v1/chat/completions", token, chatBody("fast"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应当成功，实际 %d: %s", resp.StatusCode, raw)
	}
	if own.Count() != 1 {
		t.Fatalf("自有上游应被调用 1 次，实际 %d", own.Count())
	}
	if stub.hitCount() != 0 {
		t.Errorf("自有上游命中时不该动系统池，stub 被调 %d 次", stub.hitCount())
	}
	if got := resp.Header.Get("X-LLMProxy-Provider"); got != "my-deepseek" {
		t.Errorf("应当走 my-deepseek，实际 %q", got)
	}

	// 账：自有上游的那笔**不算**系统付费，配额不涨
	su, err := h.db.SystemUsageSince("arthur", store.MonthStart(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if su.Requests != 0 {
		t.Errorf("走自有上游不该计入系统付费用量，实际 %d 条", su.Requests)
	}
}

// 自有上游全挂 → 回落系统池，这时才算网关的账。
func TestHybridFallsBackToSystemPool(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newMUHarnessWith(t, hybridYAML(stub.srv.URL))
	// 自有上游一直 500
	own := startMockUpstream(t, &mockUpstream{name: "my-deepseek", apiKey: "sk-mine", failStatus: 500, failTimes: -1})

	token := h.addUser(t, "arthur")
	setConsumption(t, h, "arthur", "fast", "sys-model")
	h.addProvider(t, "arthur", "my-deepseek", own.baseURL+"/v1", "sk-mine", `{"fast": "fast"}`)

	resp, raw := h.post(t, "/v1/chat/completions", token, chatBody("fast"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("自有失败后应当回落到系统池并成功，实际 %d: %s", resp.StatusCode, raw)
	}
	if own.Count() == 0 {
		t.Error("应当先试过自有上游")
	}
	if stub.hitCount() == 0 {
		t.Fatal("自有全挂后应当打到系统池")
	}
	if got := resp.Header.Get("X-LLMProxy-Provider"); got != "sys-a" {
		t.Errorf("回落时应当走 sys-a，实际 %q", got)
	}
	// 回落到系统池的这一笔要计网关的账
	su, err := h.db.SystemUsageSince("arthur", store.MonthStart(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if su.Requests != 1 {
		t.Errorf("回落系统池的那笔应计入系统付费用量，实际 %d", su.Requests)
	}
}

// 额度用完不该连用户自己的上游一起挡住。
func TestHybridQuotaDoesNotBlockOwnUpstream(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newMUHarnessWith(t, hybridYAML(stub.srv.URL))
	own := startMockUpstream(t, &mockUpstream{name: "my-deepseek", apiKey: "sk-mine"})

	token := h.addUser(t, "arthur")
	setConsumption(t, h, "arthur", "fast", "sys-model")
	// 配额 1 个 token，并先垫一笔系统付费的用量把它撑满
	if err := h.db.SetUserQuota("arthur", 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}
	h.srv.meters.Add("arthur", "sys-model", 100, 0, 100, 0, time.Now(), nil)
	h.addProvider(t, "arthur", "my-deepseek", own.baseURL+"/v1", "sk-mine", `{"fast": "fast"}`)

	// 自有上游承接 → 放行
	resp, raw := h.post(t, "/v1/chat/completions", token, chatBody("fast"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("额度用完但自有上游能接时应当放行，实际 %d: %s", resp.StatusCode, raw)
	}
	if own.Count() != 1 {
		t.Errorf("应当走自有上游，实际调用 %d 次", own.Count())
	}

	// 换一个只有系统池承接的模型 → 应当 402
	setConsumption(t, h, "arthur", "sys-only", "sys-model")
	resp2, _ := h.post(t, "/v1/chat/completions", token, chatBody("sys-only"))
	if resp2.StatusCode != http.StatusPaymentRequired {
		t.Errorf("只有系统池承接且额度用完时应当 402，实际 %d", resp2.StatusCode)
	}
}

// 自有上游是「全部直通」时**不该**抢走系统池里点名声明过的模型：
// 直通上游根本没那个模型，抢过去只会 400。
func TestHybridPassthroughOwnDoesNotStealDeclaredModel(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newMUHarnessWith(t, hybridYAML(stub.srv.URL))
	// 自有上游是直通（`["*"]`），指向一个「没有 gpt-5-sol」的假上游
	own := startMockUpstream(t, &mockUpstream{name: "my-deepseek", apiKey: "sk-mine", failStatus: 404, failTimes: -1})

	token := h.addUser(t, "arthur")
	// 系统池：点名声明 gpt-5-sol
	setConsumption(t, h, "arthur", "gpt-5-sol", "sys-model")
	h.addProvider(t, "arthur", "my-deepseek", own.baseURL+"/v1", "sk-mine", `["*"]`)

	resp, raw := h.post(t, "/v1/chat/completions", token, chatBody("gpt-5-sol"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应当由系统池承接 gpt-5-sol，实际 %d: %s", resp.StatusCode, raw)
	}
	if got := resp.Header.Get("X-LLMProxy-Provider"); got != "sys-a" {
		t.Errorf("点名声明的系统池应当优先于自有直通，实际走了 %q", got)
	}
	if own.Count() != 0 {
		t.Errorf("自有直通不该被尝试（它没有这个模型），实际调用 %d 次", own.Count())
	}
}
