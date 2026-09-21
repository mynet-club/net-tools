package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 控制台编辑配置文件：四条底线各有一个用例 ——
// 不下发密钥、留空不清空密钥、段外字节不动、校验不过就不落盘。

// configHarness 给一个带真实配置文件的 harness，并把热加载等待置 0（测试里没有 watcher）。
func configHarness(t *testing.T, extra string) *muHarness {
	t.Helper()
	yamlSrc := `
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
  - name: keepme
    enabled: true
    base_url: https://api.example.com/v1
    api_key: sk-keepme-plaintext
    weight: 1
    proxy: direct
    timeout_ms: 10000
    models: ["*"]
` + extra + `
log:
  level: error
`
	h := newMUHarnessWith(t, yamlSrc)
	h.srv.configApplyWait = 0
	return h
}

func adminGetConfig(t *testing.T, h *muHarness) map[string]any {
	t.Helper()
	code, body := adminGet(t, h, "/v1/_admin/config")
	if code != 200 {
		t.Fatalf("读配置应 200，实际 %d: %s", code, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// 读接口不能下发密钥，但要给出「有没有密钥」和可核对的提示。
func TestAdminConfigNeverLeaksKey(t *testing.T) {
	h := configHarness(t, "")
	info := adminGetConfig(t, h)

	raw, _ := json.Marshal(info)
	if strings.Contains(string(raw), "sk-keepme-plaintext") {
		t.Error("明文密钥被下发了")
	}
	provers, _ := info["providers"].([]any)
	if len(provers) != 1 {
		t.Fatalf("应当有 1 个供应商: %v", info["providers"])
	}
	p := provers[0].(map[string]any)
	if p["name"] != "keepme" {
		t.Errorf("名字不对: %v", p["name"])
	}
	if p["api_key"] != "" {
		t.Errorf("api_key 必须下发空串，实际 %v", p["api_key"])
	}
	if p["has_key"] != true {
		t.Error("has_key 应为 true")
	}
	if hint, _ := p["api_key_hint"].(string); !strings.Contains(hint, "…") && !strings.Contains(hint, "*") {
		t.Errorf("明文密钥应当只显示尾 4 位的脱敏提示，实际 %q", hint)
	}
	if _, ok := p["models"]; !ok {
		t.Error("应当带 models 描述")
	}
}

// 最关键的一条：保存时留空 = 沿用原值。
// 界面上拿到的是脱敏值，要是把脱敏值（或空串）当新密钥写回去，一次保存就清空所有密钥。
func TestAdminConfigEmptyKeyKeepsExisting(t *testing.T) {
	h := configHarness(t, "")
	path := h.configPath

	body := map[string]any{"providers": []map[string]any{{
		"name": "keepme", "enabled": true, "base_url": "https://api.example.com/v1",
		"api_key": "", "weight": 5, "proxy": "direct", "timeout_ms": 20000,
		"models": []string{"*"},
	}}}
	resp, raw := h.put(t, "/v1/_admin/config/providers", adminToken, body)
	if resp.StatusCode != 200 {
		t.Fatalf("保存应 200，实际 %d: %s", resp.StatusCode, raw)
	}

	// 文件里必须还是原来的 ${MY_ENV_KEY}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), "sk-keepme-plaintext") {
		t.Fatalf("密钥被清掉或改写了:\n%s", saved)
	}
	if !strings.Contains(string(saved), "weight: 5") {
		t.Errorf("改动没写进去:\n%s", saved)
	}
	// 段外内容与注释原样
	if !strings.Contains(string(saved), "    - sk-static") {
		t.Errorf("段外内容被动过:\n%s", saved)
	}
	// 备份存在
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), filepath.Base(path)+".bak-")); err == nil {
		t.Error("备份文件名不对（不该是固定名）")
	}
	entries, _ := filepath.Glob(path + ".bak-*")
	if len(entries) != 1 {
		t.Errorf("应当生成 1 份备份，实际 %d", len(entries))
	}
}

// 新供应商必须给密钥（否则启用后每个请求都会 401）。
func TestAdminConfigNewProviderNeedsKey(t *testing.T) {
	h := configHarness(t, "")
	body := map[string]any{"providers": []map[string]any{
		{"name": "keepme", "base_url": "https://api.example.com/v1", "models": []string{"*"}},
		{"name": "fresh", "base_url": "https://fresh.example/v1", "models": []string{"*"}},
	}}
	resp, raw := h.put(t, "/v1/_admin/config/providers", adminToken, body)
	if resp.StatusCode != 400 {
		t.Fatalf("新供应商缺密钥应 400，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "api_key") {
		t.Errorf("报错要点出缺 api_key: %s", raw)
	}
	// 原文件不能被改动
	saved, _ := os.ReadFile(h.configPath)
	if !strings.Contains(string(saved), "keepme") {
		t.Error("失败的写入动了原文件")
	}
}

// 校验不过就不落盘，且原文件一字不动。
func TestAdminConfigRejectsInvalidAndKeepsFile(t *testing.T) {
	h := configHarness(t, "")
	before, _ := os.ReadFile(h.configPath)

	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"空列表", map[string]any{"providers": []any{}}, "不能为空"},
		{"没名字", map[string]any{"providers": []map[string]any{
			{"base_url": "https://a.example/v1", "api_key": "k", "models": []string{"*"}}}}, "没有名字"},
		{"名字重复", map[string]any{"providers": []map[string]any{
			{"name": "a", "base_url": "https://a.example/v1", "api_key": "k", "models": []string{"*"}},
			{"name": "a", "base_url": "https://b.example/v1", "api_key": "k", "models": []string{"*"}}}}, "重复"},
		{"缺 base_url", map[string]any{"providers": []map[string]any{
			{"name": "a", "api_key": "k", "models": []string{"*"}}}}, "base_url"},
		{"base_url 协议不对", map[string]any{"providers": []map[string]any{
			{"name": "a", "base_url": "ftp://a.example/v1", "api_key": "k", "models": []string{"*"}}}}, "http"},
	}
	for _, c := range cases {
		resp, raw := h.put(t, "/v1/_admin/config/providers", adminToken, c.body)
		if resp.StatusCode != 400 {
			t.Errorf("%s：应 400，实际 %d: %s", c.name, resp.StatusCode, raw)
			continue
		}
		if !strings.Contains(string(raw), c.want) {
			t.Errorf("%s：报错里该出现 %q，实际 %s", c.name, c.want, raw)
		}
	}
	after, _ := os.ReadFile(h.configPath)
	if string(before) != string(after) {
		t.Error("有非法请求改动了原文件")
	}
	entries, _ := filepath.Glob(h.configPath + ".bak-*")
	if len(entries) != 0 {
		t.Errorf("失败的写入不该产生备份，实际 %d 份", len(entries))
	}
}

// 试算（dry-run）只校验不落盘。
func TestAdminConfigValidateDoesNotWrite(t *testing.T) {
	h := configHarness(t, "")
	before, _ := os.ReadFile(h.configPath)

	body := map[string]any{"providers": []map[string]any{{
		"name": "keepme", "base_url": "https://api.example.com/v1", "weight": 2, "models": []string{"*"},
	}}}
	resp, raw := h.post(t, "/v1/_admin/config/validate", adminToken, body)
	if resp.StatusCode != 200 {
		t.Fatalf("试算应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out["dry_run"] != true || out["providers"] != float64(1) {
		t.Errorf("试算结果不对: %s", raw)
	}
	after, _ := os.ReadFile(h.configPath)
	if string(before) != string(after) {
		t.Error("试算动到了原文件")
	}
	entries, _ := filepath.Glob(h.configPath + ".bak-*")
	if len(entries) != 0 {
		t.Errorf("试算不该产生备份，实际 %d 份", len(entries))
	}
}

// 加一家供应商：段外逐字节不变，且解析后运行时配置跟着更新。
func TestAdminConfigAddProviderKeepsRestByteIdentical(t *testing.T) {
	h := configHarness(t, "")
	before, _ := os.ReadFile(h.configPath)
	head := string(before[:strings.Index(string(before), "providers:")])
	tail := string(before[strings.Index(string(before), "log:"):])

	body := map[string]any{"providers": []map[string]any{
		{"name": "keepme", "enabled": true, "base_url": "https://api.example.com/v1",
			"weight": 1, "proxy": "direct", "timeout_ms": 10000, "models": []string{"*"}},
		{"name": "extra", "enabled": true, "base_url": "https://extra.example/v1",
			"api_key": "sk-extra-secret", "weight": 3, "proxy": "http://192.168.0.3:7890",
			"timeout_ms": 30000, "models": map[string]string{"fast": "real-model"}},
	}}
	resp, raw := h.put(t, "/v1/_admin/config/providers", adminToken, body)
	if resp.StatusCode != 200 {
		t.Fatalf("保存应 200，实际 %d: %s", resp.StatusCode, raw)
	}

	after, _ := os.ReadFile(h.configPath)
	if !strings.HasPrefix(string(after), head) {
		t.Errorf("providers 段之前被改动:\n%s", after)
	}
	if !strings.HasSuffix(string(after), tail) {
		t.Errorf("providers 段之后被改动:\n%s", after)
	}
	if !strings.Contains(string(after), "extra") || !strings.Contains(string(after), "fast: real-model") {
		t.Errorf("新供应商没写进去:\n%s", after)
	}
	if !strings.Contains(string(after), `proxy: http://192.168.0.3:7890`) {
		t.Errorf("代理配置没写对（URL 不该被加引号）:\n%s", after)
	}
	if !strings.Contains(string(after), "sk-keepme-plaintext") {
		t.Errorf("原有密钥应当被沿用:\n%s", after)
	}

	// 运行时配置跟着更新（harness 的 cfgStore 会重新加载）
	if _, err := h.cfgStore.Load(); err != nil {
		t.Fatal(err)
	}
	cfg := h.cfgStore.Current()
	if len(cfg.Normalized) != 2 {
		t.Fatalf("运行时应有 2 个供应商，实际 %d", len(cfg.Normalized))
	}
	if up, ok := cfg.Normalized[1].UpstreamModel("fast"); !ok || up != "real-model" {
		t.Errorf("映射没生效: %q %v", up, ok)
	}
}

// 非管理员一律拒绝。
func TestAdminConfigRequiresAdmin(t *testing.T) {
	h := configHarness(t, "")
	userToken := h.addUser(t, "carol")
	before, _ := os.ReadFile(h.configPath)

	for _, tok := range []string{userToken, "sk-wrong", ""} {
		resp0, _ := h.get(t, "/v1/_admin/config", tok)
		if resp0.StatusCode != 403 {
			t.Errorf("读配置 token=%q 应 403，实际 %d", tok, resp0.StatusCode)
		}
		resp, _ := h.put(t, "/v1/_admin/config/providers", tok, map[string]any{
			"providers": []map[string]any{{"name": "x", "base_url": "https://x.example/v1", "api_key": "k", "models": []string{"*"}}},
		})
		if resp.StatusCode != 403 {
			t.Errorf("写配置 token=%q 应 403，实际 %d", tok, resp.StatusCode)
		}
	}
	after, _ := os.ReadFile(h.configPath)
	if string(before) != string(after) {
		t.Error("未授权的请求改动了配置")
	}
}

// 备份只留最近若干份（配置里可能有明文密钥，不能无限堆）。
func TestBackupConfigKeepsLimited(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	for i := 0; i < 8; i++ {
		if _, err := backupConfig(path, []byte(fmt.Sprintf("v%d\n", i))); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := filepath.Glob(path + ".bak-*")
	if len(entries) > configBackupKeep {
		t.Errorf("备份应当只留 %d 份，实际 %d", configBackupKeep, len(entries))
	}
}

// ${ENV} 的间接引用必须原样保住。
//
// 这条防的是一个很隐蔽的事故：加载后的 Config 里 api_key 已被环境变量展开，
// 如果拿那个值当「原值」写回，文件里就会从 ${MY_ENV_KEY} 变成明文密钥 ——
// 既把密钥落进了文件，又丢掉了环境变量注入这条设计。
func TestAdminConfigKeepsEnvIndirection(t *testing.T) {
	h := configHarness(t, "")
	path := h.configPath

	// 把文件改写成 ${ENV} 形态（harness 的严格加载已经跑完，这里只动文件）
	saved, _ := os.ReadFile(path)
	envForm := strings.Replace(string(saved), "sk-keepme-plaintext", "${MY_ENV_KEY}", 1)
	if err := os.WriteFile(path, []byte(envForm), 0o600); err != nil {
		t.Fatal(err)
	}

	// 模拟环境变量被设上的情况：这时 Config.Providers 里会是展开后的值
	t.Setenv("MY_ENV_KEY", "sk-expanded-value")
	if _, err := h.cfgStore.Load(); err != nil {
		t.Fatalf("重新加载失败: %v", err)
	}
	if got := h.cfgStore.Current().Providers[0].APIKey; got != "sk-expanded-value" {
		t.Fatalf("前置条件不成立：加载后的值应当是展开的，实际 %q", got)
	}

	// 界面留空保存（只改权重）
	resp, raw := h.put(t, "/v1/_admin/config/providers", adminToken, map[string]any{
		"providers": []map[string]any{{
			"name": "keepme", "enabled": true, "base_url": "https://api.example.com/v1",
			"weight": 9, "proxy": "direct", "timeout_ms": 10000, "models": []string{"*"},
		}},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("保存失败 %d: %s", resp.StatusCode, raw)
	}

	after, _ := os.ReadFile(path)
	if strings.Contains(string(after), "sk-expanded-value") {
		t.Fatalf("密钥被展开成明文写进文件了（丢了 ${ENV} 间接引用）:\n%s", after)
	}
	if !strings.Contains(string(after), "${MY_ENV_KEY}") {
		t.Fatalf("${ENV} 引用丢了:\n%s", after)
	}
	if !strings.Contains(string(after), "weight: 9") {
		t.Errorf("改动没写进去:\n%s", after)
	}
}

// 宽松能过、严格过不了的配置：要写下去，但必须明确警告「服务加载不了、改动不会生效」。
func TestAdminConfigWarnsWhenStrictLoadFails(t *testing.T) {
	h := configHarness(t, "")
	// 这家启用了但环境变量没设 → 热加载（严格模式）会失败
	resp, raw := h.put(t, "/v1/_admin/config/providers", adminToken, map[string]any{
		"providers": []map[string]any{{
			"name": "needs-env", "enabled": true, "base_url": "https://x.example/v1",
			"api_key": "${DEFINITELY_NOT_SET_KEY}", "models": []string{"*"},
		}},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("应当写入成功（配置本身合法），实际 %d: %s", resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out["strict_ok"] != false {
		t.Errorf("应当报出严格加载失败，实际 %v", out["strict_ok"])
	}
	if w, _ := out["warning"].(string); !strings.Contains(w, "不会生效") {
		t.Errorf("警告要说清改动不生效，实际 %q", w)
	}
	// 文件确实写下去了
	saved, _ := os.ReadFile(h.configPath)
	if !strings.Contains(string(saved), "DEFINITELY_NOT_SET_KEY") {
		t.Error("配置应当被写入文件")
	}
}
