package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/secrets"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// 多用户测试用的配置：
//   - 全局只有一个「必然连不上」的供应商（127.0.0.1:9），用来证明用户流量确实走的是自己的上游
//   - 配了静态 key 和 admin_token，同时下面会建 DB 用户
const multiUserYAML = `
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
  - name: global-dead
    enabled: true
    base_url: http://127.0.0.1:9/v1
    api_key: sk-global
    weight: 1
    models: ["*"]
database:
  path: ""
  retain_days: 30
log:
  level: error
`

type muHarness struct {
	*harness
	cipher *secrets.Cipher
}

func newMUHarness(t *testing.T) *muHarness {
	t.Helper()
	h := newHarness(t, multiUserYAML)
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

// addUser 建一个用户并返回它的明文 token。
func (h *muHarness) addUser(t *testing.T, name string) string {
	t.Helper()
	token, err := store.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.db.CreateUser(name, store.TokenHash(token)); err != nil {
		t.Fatalf("CreateUser(%s): %v", name, err)
	}
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatalf("SyncUsers: %v", err)
	}
	return token
}

// addProvider 给用户配一个上游（密钥按运行时的方式加密）。
func (h *muHarness) addProvider(t *testing.T, user, name, baseURL, apiKey, modelsJSON string) {
	t.Helper()
	enc, err := h.cipher.Encrypt(apiKey)
	if err != nil {
		t.Fatal(err)
	}
	// 与生产同一条路径：先按用户的写法解析，再按存储形态落库
	spec, err := config.ParseModelsJSON([]byte(modelsJSON))
	if err != nil {
		t.Fatalf("models %q 解析失败: %v", modelsJSON, err)
	}
	normalized, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.db.UpsertUserProvider(store.UserProvider{
		UserName: user, Name: name, BaseURL: baseURL, APIKeyEnc: enc,
		Weight: 1, Enabled: true, TimeoutMs: 5000, ModelsJSON: string(normalized),
	}); err != nil {
		t.Fatalf("UpsertUserProvider: %v", err)
	}
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatalf("SyncUsers: %v", err)
	}
}

func (h *harness) put(t *testing.T, path, token string, body map[string]any) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		payload, _ := json.Marshal(body)
		rd = bytes.NewReader(payload)
	}
	req, _ := http.NewRequest(http.MethodPut, h.gateway.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, raw
}

func (h *harness) del(t *testing.T, path, token string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, h.gateway.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, raw
}

func chatBody(model string) map[string]any {
	return map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": "ping"}},
	}
}

// 用户流量必须走自己的上游，并且用的是自己的密钥。
func TestUserTrafficGoesToOwnUpstream(t *testing.T) {
	h := newMUHarness(t)
	aliceUp := startMockUpstream(t, &mockUpstream{name: "alice-up", apiKey: "sk-alice-key"})
	token := h.addUser(t, "alice")
	h.addProvider(t, "alice", "alice-up", aliceUp.baseURL+"/v1", "sk-alice-key", `["*"]`)

	resp, raw := h.post(t, "/v1/chat/completions", token, chatBody("deepseek-flash"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 %d，body=%s", resp.StatusCode, raw)
	}
	calls := aliceUp.Calls()
	if len(calls) != 1 {
		t.Fatalf("用户自己的上游应当被调用 1 次，实际 %d", len(calls))
	}
	if calls[0].Auth != "Bearer sk-alice-key" {
		t.Errorf("上游收到的凭证应来自用户自己的配置，实际 %q", calls[0].Auth)
	}

	// 网关自己的响应头应当标出实际使用的上游
	if got := resp.Header.Get("X-LLMProxy-Provider"); got != "alice-up" {
		t.Errorf("X-LLMProxy-Provider = %q，期望 alice-up", got)
	}

	// 记账：用户维度要有数据
	tot, err := h.db.TotalByUser(time.Time{}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if tot.Requests != 1 || tot.TotalTokens != 12 {
		t.Errorf("用户维度用量不对: %+v", tot)
	}
	// 全局维度也照记（providers 维度仍可用）
	st, err := h.db.Stats(time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if st.TotalRequests != 1 {
		t.Errorf("全局统计应仍为 1 条，实际 %d", st.TotalRequests)
	}
}

// 两个用户各走各的上游，互不干扰；没配上游的用户回退到全局配置。
func TestUsersAreIsolated(t *testing.T) {
	h := newMUHarness(t)
	aliceUp := startMockUpstream(t, &mockUpstream{name: "alice-up", apiKey: "sk-a"})
	bobUp := startMockUpstream(t, &mockUpstream{name: "bob-up", apiKey: "sk-b"})

	alice := h.addUser(t, "alice")
	bob := h.addUser(t, "bob")
	carol := h.addUser(t, "carol") // 故意不配上游

	h.addProvider(t, "alice", "alice-up", aliceUp.baseURL+"/v1", "sk-a", `["*"]`)
	h.addProvider(t, "bob", "bob-up", bobUp.baseURL+"/v1", "sk-b", `["*"]`)

	if resp, raw := h.post(t, "/v1/chat/completions", alice, chatBody("m")); resp.StatusCode != 200 {
		t.Fatalf("alice 请求失败: %d %s", resp.StatusCode, raw)
	}
	if resp, raw := h.post(t, "/v1/chat/completions", bob, chatBody("m")); resp.StatusCode != 200 {
		t.Fatalf("bob 请求失败: %d %s", resp.StatusCode, raw)
	}

	if aliceUp.Count() != 1 || bobUp.Count() != 1 {
		t.Errorf("两个上游各应被调用 1 次，实际 alice=%d bob=%d", aliceUp.Count(), bobUp.Count())
	}

	// carol 没有自己的上游 → 回退到全局（那个连不上）→ 502
	resp, _ := h.post(t, "/v1/chat/completions", carol, chatBody("m"))
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("没配上游的用户应回退到全局并失败(502)，实际 %d", resp.StatusCode)
	}
}

// 熔断按用户隔离：alice 把自己的上游打挂，不影响 bob。
func TestCircuitBreakerIsolatedPerUser(t *testing.T) {
	h := newMUHarness(t)
	aliceUp := startMockUpstream(t, &mockUpstream{name: "alice-up", apiKey: "sk-a", failStatus: 500, failTimes: -1})
	bobUp := startMockUpstream(t, &mockUpstream{name: "bob-up", apiKey: "sk-b"})

	alice := h.addUser(t, "alice")
	bob := h.addUser(t, "bob")
	h.addProvider(t, "alice", "same-name", aliceUp.baseURL+"/v1", "sk-a", `["*"]`)
	h.addProvider(t, "bob", "same-name", bobUp.baseURL+"/v1", "sk-b", `["*"]`)

	// alice 连续失败，触发 failure_threshold=3
	for i := 0; i < 3; i++ {
		if resp, _ := h.post(t, "/v1/chat/completions", alice, chatBody("m")); resp.StatusCode == 200 {
			t.Fatalf("第 %d 次应当失败", i+1)
		}
	}

	// alice 的 same-name 进熔断
	_, raw := h.get(t, "/v1/_providers", alice)
	var aliceView struct {
		Scope     string `json:"scope"`
		Providers []struct {
			Name                string `json:"name"`
			Healthy             bool   `json:"healthy"`
			ConsecutiveFailures int    `json:"consecutive_failures"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(raw, &aliceView); err != nil {
		t.Fatal(err)
	}
	if aliceView.Scope != "alice" {
		t.Errorf("scope 应为 alice，实际 %q", aliceView.Scope)
	}
	found := false
	for _, p := range aliceView.Providers {
		if p.Name == "same-name" {
			found = true
			if p.Healthy {
				t.Error("alice 的上游应处于熔断")
			}
			if p.ConsecutiveFailures < 3 {
				t.Errorf("连续失败数应 ≥3，实际 %d", p.ConsecutiveFailures)
			}
		}
	}
	if !found {
		t.Fatalf("alice 的视图里没有 same-name: %s", raw)
	}

	// bob 的同名上游完全不受影响
	if resp, raw := h.post(t, "/v1/chat/completions", bob, chatBody("m")); resp.StatusCode != 200 {
		t.Fatalf("bob 不应受影响，实际 %d %s", resp.StatusCode, raw)
	}
	_, raw2 := h.get(t, "/v1/_providers", bob)
	if strings.Contains(string(raw2), `"healthy":false`) {
		t.Errorf("bob 的视图里出现了不健康的上游: %s", raw2)
	}
}

// 静态 key 走全局作用域，且没有用户身份，不能用自助接口。
func TestStaticKeyKeepsGlobalScope(t *testing.T) {
	h := newMUHarness(t)
	_, raw := h.get(t, "/v1/_providers", "sk-static")
	var view struct {
		Scope     string `json:"scope"`
		Providers []struct {
			Name string `json:"name"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	if view.Scope != "" {
		t.Errorf("静态 key 的作用域应为空，实际 %q", view.Scope)
	}
	if len(view.Providers) != 1 || view.Providers[0].Name != "global-dead" {
		t.Errorf("静态 key 应看到全局供应商: %s", raw)
	}

	resp, body := h.get(t, "/v1/_me", "sk-static")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("静态 key 用自助接口应 403，实际 %d %s", resp.StatusCode, body)
	}
}

// 自助接口：看自己的信息、配上游、密钥不回显明文、删掉。
func TestSelfServiceProviders(t *testing.T) {
	h := newMUHarness(t)
	alice := h.addUser(t, "alice")
	up := startMockUpstream(t, &mockUpstream{name: "my-up", apiKey: "sk-self-key"})

	// 初始：没有上游
	resp, raw := h.get(t, "/v1/_me", alice)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /v1/_me: %d %s", resp.StatusCode, raw)
	}
	var me struct {
		Name          string `json:"name"`
		ProviderCount int    `json:"provider_count"`
	}
	if err := json.Unmarshal(raw, &me); err != nil {
		t.Fatal(err)
	}
	if me.Name != "alice" || me.ProviderCount != 0 {
		t.Errorf("初始状态不对: %+v", me)
	}

	// 配一个只属于自己的上游
	r, raw := h.put(t, "/v1/_me/providers/my-up", alice, map[string]any{
		"base_url": up.baseURL + "/v1",
		"api_key":  "sk-self-key",
		"models":   []string{"*"},
	})
	if r.StatusCode != 200 {
		t.Fatalf("配上游失败: %d %s", r.StatusCode, raw)
	}
	if strings.Contains(string(raw), "sk-self-key") {
		t.Error("响应里回显了上游密钥明文")
	}

	// 列表：密钥只显示尾部
	_, listRaw := h.get(t, "/v1/_me/providers", alice)
	if strings.Contains(string(listRaw), "sk-self-key") {
		t.Error("列表里回显了上游密钥明文")
	}
	if !strings.Contains(string(listRaw), "****") {
		t.Errorf("列表应显示掩码后的密钥: %s", listRaw)
	}

	// 配好之后请求应当走这个上游
	if resp, body := h.post(t, "/v1/chat/completions", alice, chatBody("m")); resp.StatusCode != 200 {
		t.Fatalf("配好上游后请求应成功: %d %s", resp.StatusCode, body)
	}
	if up.Count() != 1 {
		t.Errorf("自助配的上游应被调用，实际 %d 次", up.Count())
	}

	// 更新时可以省略 api_key（沿用旧的）
	r2, raw2 := h.put(t, "/v1/_me/providers/my-up", alice, map[string]any{"weight": 5})
	if r2.StatusCode != 200 {
		t.Fatalf("省略 api_key 的更新应当成功: %d %s", r2.StatusCode, raw2)
	}
	provs, _ := h.db.ListUserProviders("alice")
	if len(provs) != 1 || provs[0].Weight != 5 {
		t.Errorf("更新后权重应为 5: %+v", provs)
	}

	// 非法 models 应当被拒绝
	r3, raw3 := h.put(t, "/v1/_me/providers/bad", alice, map[string]any{
		"base_url": up.baseURL + "/v1", "api_key": "x", "models": []string{},
	})
	if r3.StatusCode != http.StatusBadRequest {
		t.Errorf("空 models 应当 400，实际 %d %s", r3.StatusCode, raw3)
	}

	// 删除
	if dr, _ := h.del(t, "/v1/_me/providers/my-up", alice); dr.StatusCode != 200 {
		t.Errorf("删除应当成功，实际 %d", dr.StatusCode)
	}
	if provs, _ := h.db.ListUserProviders("alice"); len(provs) != 0 {
		t.Errorf("删除后仍有记录: %+v", provs)
	}
}

// 用户可控的 provider 数量必须有上限：每条背后是 base_url + 连接池，
// 没有上限就能靠堆上游把网关内存吃光。
func TestUserProviderCountCapped(t *testing.T) {
	h := newMUHarness(t)
	alice := h.addUser(t, "alice")
	up := startMockUpstream(t, &mockUpstream{name: "cap", apiKey: "sk"})

	for i := 0; i < maxUserProviders; i++ {
		r, raw := h.put(t, fmt.Sprintf("/v1/_me/providers/p%02d", i), alice, map[string]any{
			"base_url": up.baseURL + "/v1",
			"api_key":  "sk",
			"models":   []string{"*"},
		})
		if r.StatusCode != 200 {
			t.Fatalf("第 %d 个上游应当能建: %d %s", i+1, r.StatusCode, raw)
		}
	}
	// 第 maxUserProviders+1 个必须被拒
	r, raw := h.put(t, "/v1/_me/providers/overflow", alice, map[string]any{
		"base_url": up.baseURL + "/v1",
		"api_key":  "sk",
		"models":   []string{"*"},
	})
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("超出上限应当 400，实际 %d %s", r.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "上限") {
		t.Errorf("错误应说明是数量上限: %s", raw)
	}
	// 更新已有条目不受上限影响
	r2, raw2 := h.put(t, "/v1/_me/providers/p00", alice, map[string]any{"weight": 2})
	if r2.StatusCode != 200 {
		t.Errorf("更新已有上游不该被上限拦住: %d %s", r2.StatusCode, raw2)
	}
}

// 停用的用户一律 403，且错误类型可区分。
func TestDisabledUserRejected(t *testing.T) {
	h := newMUHarness(t)
	alice := h.addUser(t, "alice")
	if err := h.db.SetUserEnabled("alice", false); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}

	resp, raw := h.post(t, "/v1/chat/completions", alice, chatBody("m"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("停用用户应 403，实际 %d %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "account_disabled") {
		t.Errorf("错误类型应是 account_disabled: %s", raw)
	}
}

// 未知 token 依然 401。
func TestUnknownTokenRejected(t *testing.T) {
	h := newMUHarness(t)
	h.addUser(t, "alice")
	resp, raw := h.post(t, "/v1/chat/completions", "sk-not-a-real-token", chatBody("m"))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("未知 token 应 401，实际 %d %s", resp.StatusCode, raw)
	}
}

// 管理接口：未配 admin_token 时关闭；配了之后能建用户、发 token、轮换、停用、删除。
func TestAdminAPI(t *testing.T) {
	h := newMUHarness(t)

	// 没有凭证 → 403
	resp, raw := h.get(t, "/v1/_admin/users", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("缺管理凭证应 403，实际 %d %s", resp.StatusCode, raw)
	}
	// 拿用户 token 冒充管理员 → 403
	alice := h.addUser(t, "alice")
	if resp, _ := h.get(t, "/v1/_admin/users", alice); resp.StatusCode != http.StatusForbidden {
		t.Errorf("普通用户访问管理接口应 403，实际 %d", resp.StatusCode)
	}

	// 管理员建用户，返回的 token 立即可用
	resp, raw = h.post(t, "/v1/_admin/users", "sk-admin", map[string]any{"name": "dave"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("建用户失败: %d %s", resp.StatusCode, raw)
	}
	var created struct {
		Name  string `json:"name"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatal(err)
	}
	if created.Name != "dave" || !strings.HasPrefix(created.Token, "sk-") {
		t.Fatalf("返回内容不对: %s", raw)
	}
	// 重名 → 409
	if resp, _ := h.post(t, "/v1/_admin/users", "sk-admin", map[string]any{"name": "dave"}); resp.StatusCode != http.StatusConflict {
		t.Errorf("重名建用户应 409，实际 %d", resp.StatusCode)
	}
	// 非法名字 → 400
	if resp, _ := h.post(t, "/v1/_admin/users", "sk-admin", map[string]any{"name": "bad name"}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("非法用户名应 400，实际 %d", resp.StatusCode)
	}

	// 列表里能看到 dave
	_, listRaw := h.get(t, "/v1/_admin/users", "sk-admin")
	if !strings.Contains(string(listRaw), "dave") {
		t.Errorf("用户列表里没有 dave: %s", listRaw)
	}

	// 轮换 token：旧的失效、新的可用
	resp, raw = h.post(t, "/v1/_admin/users/dave/token", "sk-admin", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("轮换 token 失败: %d %s", resp.StatusCode, raw)
	}
	var rotated struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Token == created.Token {
		t.Error("轮换后 token 没变")
	}
	if u, _ := h.db.GetUserByTokenHash(store.TokenHash(created.Token)); u != nil {
		t.Error("旧 token 仍然可用")
	}
	if u, _ := h.db.GetUserByTokenHash(store.TokenHash(rotated.Token)); u == nil {
		t.Error("新 token 不可用")
	}

	// 停用 / 启用
	if resp, _ := h.post(t, "/v1/_admin/users/dave/disable", "sk-admin", nil); resp.StatusCode != 200 {
		t.Errorf("停用失败: %d", resp.StatusCode)
	}
	if resp, _ := h.post(t, "/v1/chat/completions", rotated.Token, chatBody("m")); resp.StatusCode != http.StatusForbidden {
		t.Errorf("停用后应 403，实际 %d", resp.StatusCode)
	}
	if resp, _ := h.post(t, "/v1/_admin/users/dave/enable", "sk-admin", nil); resp.StatusCode != 200 {
		t.Errorf("启用失败: %d", resp.StatusCode)
	}

	// 详情
	if resp, raw := h.get(t, "/v1/_admin/users/dave", "sk-admin"); resp.StatusCode != 200 || !strings.Contains(string(raw), "dave") {
		t.Errorf("查看用户详情失败: %d %s", resp.StatusCode, raw)
	}

	// 删除
	if dr, _ := h.del(t, "/v1/_admin/users/dave", "sk-admin"); dr.StatusCode != 200 {
		t.Errorf("删除用户失败: %d", dr.StatusCode)
	}
	if u, _ := h.db.GetUser("dave"); u != nil {
		t.Error("删除后仍能查到 dave")
	}
	// 已删除用户的 token 立刻失效
	if resp, _ := h.post(t, "/v1/chat/completions", rotated.Token, chatBody("m")); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("已删除用户的 token 应 401，实际 %d", resp.StatusCode)
	}
}

// 上游密钥在库里必须是密文。
func TestUpstreamKeyEncryptedAtRest(t *testing.T) {
	h := newMUHarness(t)
	h.addUser(t, "alice")
	h.addProvider(t, "alice", "up", "https://api.example.com/v1", "sk-must-be-encrypted", `["*"]`)

	var blob []byte
	if err := h.db.DB().QueryRow(
		`SELECT api_key_enc FROM user_providers WHERE user_name='alice' AND name='up'`).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "sk-must-be-encrypted") {
		t.Fatal("库里的上游密钥是明文")
	}
	// 用主密钥应当能解回来
	got, err := h.cipher.Decrypt(blob)
	if err != nil || got != "sk-must-be-encrypted" {
		t.Fatalf("解密失败: %q %v", got, err)
	}

	// 换一把主密钥后，该上游应被跳过（记进 broken）而不是让整个用户挂掉
	other, err := secrets.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h.srv.WithSecrets(other)
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}
	_, raw := h.get(t, "/v1/_me", h.mustToken(t, "alice"))
	if !strings.Contains(string(raw), "broken_providers") {
		t.Errorf("主密钥换了之后应报告 broken_providers: %s", raw)
	}
	_ = fmt.Sprint(raw)
}

// mustToken 重新给已有用户发一个已知 token（测试用）。
func (h *muHarness) mustToken(t *testing.T, name string) string {
	t.Helper()
	token, err := store.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.db.SetUserToken(name, store.TokenHash(token)); err != nil {
		t.Fatal(err)
	}
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatal(err)
	}
	return token
}

// 同一个用户把同一下游名映射到两家上游：第一家失败后自动落到第二家。
// 这是「上游 A / B 都有 deepseek-flash，A 花完了不用自己切」的那条链路。
func TestSameModelAcrossOwnUpstreamsFailsOver(t *testing.T) {
	h := newMUHarness(t)
	// A 一直失败（模拟额度花完/不可用），B 正常
	upA := startMockUpstream(t, &mockUpstream{name: "up-a", apiKey: "sk-a", failStatus: 500, failTimes: -1})
	upB := startMockUpstream(t, &mockUpstream{name: "up-b", apiKey: "sk-b"})

	token := h.addUser(t, "arthur")
	// 同一下游名 deepseek-flash：A 指到 upstream-a，B 指到 upstream-b
	h.addProvider(t, "arthur", "up-a", upA.baseURL+"/v1", "sk-a",
		`{"deepseek-flash": "upstream-a"}`)
	h.addProvider(t, "arthur", "up-b", upB.baseURL+"/v1", "sk-b",
		`{"deepseek-flash": "upstream-b"}`)

	// 连发几次：应当全部 200，且都落到 B（A 全失败）
	sawB := 0
	for i := 0; i < 4; i++ {
		resp, raw := h.post(t, "/v1/chat/completions", token, chatBody("deepseek-flash"))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("第 %d 次请求应当经 B 成功，实际 %d %s", i+1, resp.StatusCode, raw)
		}
		if resp.Header.Get("X-LLMProxy-Provider") == "up-b" {
			sawB++
		}
	}
	if sawB == 0 {
		t.Fatalf("应当至少有一次落到 up-b；A 上游调用 %d 次，B %d 次", upA.Count(), upB.Count())
	}
	if upB.Count() == 0 {
		t.Errorf("up-b 从未被调用，切换没发生")
	}
}

// 模型目录的写法：下游名两家相同、上游名各自不同（别名），照样能切换。
func TestSameDownstreamNameDifferentUpstreamNames(t *testing.T) {
	h := newMUHarness(t)
	upA := startMockUpstream(t, &mockUpstream{name: "up-a", apiKey: "sk-a", failStatus: 502, failTimes: -1})
	upB := startMockUpstream(t, &mockUpstream{name: "up-b", apiKey: "sk-b"})

	token := h.addUser(t, "arthur")
	h.addProvider(t, "arthur", "plan-a", upA.baseURL+"/v1", "sk-a",
		`{"my-df": "deepseek-chat"}`)
	h.addProvider(t, "arthur", "plan-b", upB.baseURL+"/v1", "sk-b",
		`{"my-df": "ds-v3-flash"}`)

	resp, raw := h.post(t, "/v1/chat/completions", token, chatBody("my-df"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("别名模型请求失败: %d %s", resp.StatusCode, raw)
	}
	// B 应当收到的是它自己的上游名 ds-v3-flash
	calls := upB.Calls()
	if len(calls) == 0 {
		// 可能先打到 A 重试到 B
		t.Fatalf("up-b 未被调用；A 调用 %d 次", upA.Count())
	}
	last := calls[len(calls)-1]
	if last.Body["model"] != "ds-v3-flash" {
		t.Errorf("up-b 应收到 ds-v3-flash，实际 %v", last.Body["model"])
	}
}
