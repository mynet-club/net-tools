package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// 假上游：只提供 /v1/models，用来验证「同步模型列表」。
type modelsStub struct {
	srv    *httptest.Server
	mu     sync.Mutex
	auth   string
	hits   int
	status int
	body   string
}

func newModelsStub(t *testing.T, status int, body string) *modelsStub {
	t.Helper()
	s := &modelsStub{status: status, body: body}
	if s.status == 0 {
		s.status = http.StatusOK
	}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits++
		s.auth = r.Header.Get("Authorization")
		s.mu.Unlock()
		if !strings.HasSuffix(r.URL.Path, "/models") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *modelsStub) authHeader() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.auth
}

func discover(t *testing.T, h *muHarness, token, path string, body map[string]any) (*http.Response, []byte) {
	t.Helper()
	return h.post(t, path, token, body)
}

// 已保存的上游：应当用存的地址与（解密后的）密钥去拉列表。
func TestDiscoverFromStoredProvider(t *testing.T) {
	stub := newModelsStub(t, 200, `{"object":"list","data":[{"id":"deepseek-flash"},{"id":"deepseek-v4-pro"}]}`)
	h := newConsumptionHarness(t, newUsageStub(t, 0), testPricing)
	token := h.addUser(t, "carol")
	h.addProvider(t, "carol", "mine", stub.srv.URL, "sk-carol-upstream", `["*"]`)

	resp, raw := discover(t, h, token, "/v1/_me/providers/mine/discover", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("同步失败 %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		Models []string `json:"models"`
		Count  int      `json:"count"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 2 || len(out.Models) != 2 {
		t.Fatalf("模型列表不对: %+v", out)
	}
	// 必须用用户自己的密钥去探测，不是系统密钥
	if got := stub.authHeader(); got != "Bearer sk-carol-upstream" {
		t.Fatalf("探测用的密钥不对: %q", got)
	}
	if out.Models[0] != "deepseek-flash" {
		t.Fatalf("模型名没解析对: %+v", out.Models)
	}
}

// 还没保存的新上游：允许内联 base_url / api_key 同步（否则「填好先看看有哪些模型」做不到）。
func TestDiscoverInlineBeforeSave(t *testing.T) {
	stub := newModelsStub(t, 200, `{"data":[{"id":"m1"},{"id":"m2"}]}`)
	h := newConsumptionHarness(t, newUsageStub(t, 0), testPricing)
	token := h.addUser(t, "carol")

	resp, raw := discover(t, h, token, "/v1/_me/providers/fresh/discover", map[string]any{
		"base_url": stub.srv.URL, "api_key": "sk-inline",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("内联同步失败 %d: %s", resp.StatusCode, raw)
	}
	if got := stub.authHeader(); got != "Bearer sk-inline" {
		t.Fatalf("内联密钥没被用上: %q", got)
	}
}

// 上游不给列表时，要引导到「手动添加」，而不是给个没用的报错。
func TestDiscoverUnparseableGuidesToManual(t *testing.T) {
	stub := newModelsStub(t, 200, `<html>not json at all</html>`)
	h := newConsumptionHarness(t, newUsageStub(t, 0), testPricing)
	token := h.addUser(t, "carol")
	h.addProvider(t, "carol", "weird", stub.srv.URL, "sk-x", `["*"]`)

	resp, raw := discover(t, h, token, "/v1/_me/providers/weird/discover", nil)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("应返回 422，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "手动添加") {
		t.Fatalf("报错要引导手动添加: %s", raw)
	}
}

// 上游根本没有 /v1/models（404）是常态而非故障：要引导到手动添加。
func TestDiscoverNoModelsEndpoint(t *testing.T) {
	stub := newModelsStub(t, http.StatusNotFound, `404 page not found`)
	h := newConsumptionHarness(t, newUsageStub(t, 0), testPricing)
	token := h.addUser(t, "carol")
	h.addProvider(t, "carol", "chatonly", stub.srv.URL, "sk-x", `["*"]`)

	resp, raw := discover(t, h, token, "/v1/_me/providers/chatonly/discover", nil)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("应返回 422（不是故障，是这家没这个接口），实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "手动添加") {
		t.Fatalf("要引导到手动添加: %s", raw)
	}
}

func TestDiscoverUpstreamDenied(t *testing.T) {
	stub := newModelsStub(t, http.StatusUnauthorized, `{"error":"bad key"}`)
	h := newConsumptionHarness(t, newUsageStub(t, 0), testPricing)
	token := h.addUser(t, "carol")
	h.addProvider(t, "carol", "mine", stub.srv.URL, "sk-wrong", `["*"]`)

	resp, raw := discover(t, h, token, "/v1/_me/providers/mine/discover", nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("上游 401 应转成 502，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "密钥") {
		t.Fatalf("报错要指向密钥: %s", raw)
	}
}

func TestDiscoverUnknownProviderWithoutInline(t *testing.T) {
	h := newConsumptionHarness(t, newUsageStub(t, 0), testPricing)
	token := h.addUser(t, "carol")

	resp, raw := discover(t, h, token, "/v1/_me/providers/nope/discover", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("应 404，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "base_url") {
		t.Fatalf("报错要说清可以先保存或内联: %s", raw)
	}
}

// 上游的原始响应体绝不能被回传：那会把这个接口变成「带鉴权的通用 GET 代理」。
func TestDiscoverDoesNotEchoUpstreamBody(t *testing.T) {
	stub := newModelsStub(t, 200, `{"data":[{"id":"m1"}],"internal_secret_field":"TOP-SECRET-VALUE"}`)
	h := newConsumptionHarness(t, newUsageStub(t, 0), testPricing)
	token := h.addUser(t, "carol")
	h.addProvider(t, "carol", "mine", stub.srv.URL, "sk-x", `["*"]`)

	resp, raw := discover(t, h, token, "/v1/_me/providers/mine/discover", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("同步失败 %d: %s", resp.StatusCode, raw)
	}
	if strings.Contains(string(raw), "TOP-SECRET-VALUE") {
		t.Fatal("上游响应体被原样回传了")
	}
}

// 兼容几种非标准形态：{models:[{name}]} 与裸数组。
func TestParseModelIDsShapes(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{`{"data":[{"id":"a"},{"id":"b"}]}`, []string{"a", "b"}},
		{`{"models":[{"name":"c"},{"id":"d"}]}`, []string{"c", "d"}},
		{`["x","y"]`, []string{"x", "y"}},
		{`[{"id":"z"}]`, []string{"z"}},
		{`{"data":[{"id":"dup"},{"id":"dup"}]}`, []string{"dup"}},
		{`{"data":[{"id":"b"},{"id":"a"}]}`, []string{"a", "b"}}, // 排序稳定
		{`garbage`, nil},
		{`{}`, nil},
	}
	for _, c := range cases {
		got := parseModelIDs([]byte(c.raw))
		if len(got) != len(c.want) {
			t.Fatalf("%s → %v，期望 %v", c.raw, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s → %v，期望 %v", c.raw, got, c.want)
			}
		}
	}
}
