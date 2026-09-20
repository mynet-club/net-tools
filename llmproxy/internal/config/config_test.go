package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAndNormalize(t *testing.T) {
	t.Setenv("TEST_KEY_A", "sk-from-env-A")
	t.Setenv("TEST_KEY_B", "sk-from-env-B")

	src := `
server:
  host: 127.0.0.1
  port: 8787
  api_keys:
    - sk-a
    - key: sk-b
      label: laptop
routing:
  retry: 2
  failure_threshold: 3
  cooldown_seconds: 60
proxies:
  - name: us
    url: http://127.0.0.1:7890
providers:
  - name: p1
    base_url: https://a.example/v1/
    api_key: ${TEST_KEY_A}
    weight: 10
    proxy: us
    models:
      gpt-4o: gpt-4o-2024-11-20
      gpt-4o-mini: gpt-4o-mini
  - name: p2
    base_url: https://b.example/v1
    api_key: ${TEST_KEY_B}
    weight: 3
    proxy: direct
    models: ["*"]
`
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if cfg.Server.Port != 8787 {
		t.Errorf("port = %d, want 8787", cfg.Server.Port)
	}
	if len(cfg.Server.APIKeys) != 2 {
		t.Fatalf("api_keys len = %d, want 2", len(cfg.Server.APIKeys))
	}
	if cfg.Server.APIKeys[0].Key != "sk-a" || cfg.Server.APIKeys[0].Label != "" {
		t.Errorf("api_keys[0] = %+v", cfg.Server.APIKeys[0])
	}
	if cfg.Server.APIKeys[1].Label != "laptop" {
		t.Errorf("api_keys[1].label = %q, want laptop", cfg.Server.APIKeys[1].Label)
	}
	if cfg.Normalized[0].APIKey != "sk-from-env-A" {
		t.Errorf("环境变量未展开: %q", cfg.Normalized[0].APIKey)
	}
	if cfg.Normalized[0].BaseURL != "https://a.example/v1" {
		t.Errorf("base_url 末尾斜杠未去掉: %q", cfg.Normalized[0].BaseURL)
	}
	if cfg.Normalized[0].Proxy.Mode != "named" || cfg.Normalized[0].Proxy.Name != "us" {
		t.Errorf("p1.proxy = %+v", cfg.Normalized[0].Proxy)
	}
	if cfg.Normalized[1].Proxy.Mode != "direct" {
		t.Errorf("p2.proxy = %+v", cfg.Normalized[1].Proxy)
	}
	if !cfg.Normalized[1].Models.Passthrough {
		t.Error("p2 应为 passthrough")
	}
	if cfg.Normalized[0].Models.Map["gpt-4o"] != "gpt-4o-2024-11-20" {
		t.Errorf("模型映射错误: %+v", cfg.Normalized[0].Models.Map)
	}
	if cfg.Server.MaxBodyBytes() != 16*1024*1024 {
		t.Errorf("max body = %d", cfg.Server.MaxBodyBytes())
	}
	if !cfg.Server.RequiresAuth() {
		t.Error("应要求鉴权")
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`
providers:
  - name: x
    base_url: https://x/v1
    api_key: k
    models: ["*"]
`))
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if cfg.Server.Host != "127.0.0.1" || cfg.Server.Port != 8787 {
		t.Errorf("默认 server = %s:%d", cfg.Server.Host, cfg.Server.Port)
	}
	if cfg.Server.RequiresAuth() {
		t.Error("未配置密钥时不应要求鉴权")
	}
	if cfg.Routing.Retry != 2 || cfg.Routing.FailureThreshold != 3 || cfg.Routing.CooldownSeconds != 60 {
		t.Errorf("默认 routing = %+v", cfg.Routing)
	}
	if cfg.Normalized[0].Weight != 1 || cfg.Normalized[0].TimeoutMs != 120000 {
		t.Errorf("默认 provider = %+v", cfg.Normalized[0])
	}
	if cfg.Database.RetainDays != 90 {
		t.Errorf("默认 retain_days = %d", cfg.Database.RetainDays)
	}
}

func TestDisabledProviderAllowsMissingEnv(t *testing.T) {
	cfg, err := Parse([]byte(`
providers:
  - name: ok
    base_url: https://x/v1
    api_key: k
    models: ["*"]
  - name: off
    enabled: false
    base_url: https://y/v1
    api_key: ${NOT_SET_ANYWHERE}
    models: ["*"]
`))
	if err != nil {
		t.Fatalf("停用供应商缺环境变量不应报错: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "NOT_SET_ANYWHERE") {
			found = true
		}
	}
	if !found {
		t.Errorf("应给出停用供应商的警告, warnings=%v", cfg.Warnings)
	}
	if cfg.Normalized[1].Enabled {
		t.Error("off 应为停用")
	}
}

func TestEnabledProviderMissingEnvFails(t *testing.T) {
	_, err := Parse([]byte(`
providers:
  - name: x
    base_url: https://x/v1
    api_key: ${NOPE_MISSING}
    models: ["*"]
`))
	if err == nil || !strings.Contains(err.Error(), "NOPE_MISSING") {
		t.Fatalf("应报错提示缺失环境变量, got %v", err)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"providers 空", `providers: []`, "至少包含一个"},
		{"缺 name", `providers:
  - base_url: https://x/v1
    api_key: k
    models: ["*"]`, "name 必填"},
		{"缺 base_url", `providers:
  - name: a
    api_key: k
    models: ["*"]`, "base_url 必填"},
		{"非法协议", `providers:
  - name: a
    base_url: ftp://x/v1
    api_key: k
    models: ["*"]`, "http/https"},
		{"空 models", `providers:
  - name: a
    base_url: https://x/v1
    api_key: k
    models: []`, "models 不能是空列表"},
		{"重名", `providers:
  - name: a
    base_url: https://x/v1
    api_key: k
    models: ["*"]
  - name: a
    base_url: https://y/v1
    api_key: k
    models: ["*"]`, "重复"},
		{"未知代理", `providers:
  - name: a
    base_url: https://x/v1
    api_key: k
    models: ["*"]
    proxy: nope`, "既不是 \"direct\""},
		{"端口越界", `server:
  port: 99999
providers:
  - name: a
    base_url: https://x/v1
    api_key: k
    models: ["*"]`, "server.port"},
		{"api_keys 非列表", `server:
  api_keys: x
providers:
  - name: a
    base_url: https://x/v1
    api_key: k
    models: ["*"]`, "api_keys 需要是列表"},
		{"api_keys 重复", `server:
  api_keys: [a, a]
providers:
  - name: a
    base_url: https://x/v1
    api_key: k
    models: ["*"]`, "重复项"},
		{"enabled 非法", `providers:
  - name: a
    base_url: https://x/v1
    api_key: k
    models: ["*"]
    enabled: maybe`, "enabled 只能是 true 或 false"},
		{"日志级别非法", `log:
  level: verbose
providers:
  - name: a
    base_url: https://x/v1
    api_key: k
    models: ["*"]`, "log.level"},
		{"全部停用", `providers:
  - name: a
    enabled: false
    base_url: https://x/v1
    api_key: k
    models: ["*"]`, "没有任何已启用"},
		{"公开监听无密钥", `server:
  host: 0.0.0.0
providers:
  - name: a
    base_url: https://x/v1
    api_key: k
    models: ["*"]`, "api_keys"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.src))
			if err == nil {
				t.Fatalf("应报错")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("错误信息 %q 不含 %q", err.Error(), tc.want)
			}
		})
	}
}

func TestLoadFileAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	src := `
providers:
  - name: x
    base_url: https://x/v1
    api_key: k
    models: ["*"]
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("0600 权限不应有警告: %v", cfg.Warnings)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "chmod 600") {
			found = true
		}
	}
	if !found {
		t.Errorf("宽松权限应警告: %v", cfg.Warnings)
	}

	if _, err := LoadFile(filepath.Join(dir, "nope.yaml")); err == nil ||
		!strings.Contains(err.Error(), "不存在") {
		t.Errorf("缺文件应报错, got %v", err)
	}
}

func TestStoreHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	src := `
providers:
  - name: p1
    base_url: https://x/v1
    api_key: k
    weight: 10
    models: ["*"]
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewStore(path)
	cfg, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.Revision() != 1 {
		t.Errorf("revision = %d, want 1", s.Revision())
	}
	if cfg.Normalized[0].Weight != 10 {
		t.Errorf("weight = %v", cfg.Normalized[0].Weight)
	}

	changed, cfg2, err := s.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("内容没变不应算变更")
	}
	if cfg2.Normalized[0].Weight != 10 {
		t.Errorf("weight = %v", cfg2.Normalized[0].Weight)
	}

	if err := os.WriteFile(path, []byte(strings.Replace(src, "weight: 10", "weight: 7", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, cfg2, err = s.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("内容变了应算变更")
	}
	if cfg2.Normalized[0].Weight != 7 {
		t.Errorf("weight = %v", cfg2.Normalized[0].Weight)
	}
	if s.Revision() != 2 {
		t.Errorf("revision = %d, want 2", s.Revision())
	}

	// 写坏配置：保留旧配置
	if err := os.WriteFile(path, []byte("providers:\n  - name: x\n    bad_indent: 1\n   oops: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, cfg3, err := s.Reload()
	if err == nil {
		t.Error("坏配置应失败")
	}
	if cfg3.Normalized[0].Weight != 7 {
		t.Errorf("坏配置不应破坏当前生效配置, weight=%v", cfg3.Normalized[0].Weight)
	}
	s.Stop()
}

func TestExampleConfigParses(t *testing.T) {
	path := filepath.Join("..", "..", "config", "config.example.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("示例配置不存在: %v", err)
	}
	// 示例里用了若干 ${ENV}，设置它们以便校验通过
	t.Setenv("OPENAI_API_KEY", "sk-test-a")
	t.Setenv("OPENAI_API_KEY_BACKUP", "sk-test-b")
	t.Setenv("DEEPSEEK_API_KEY", "sk-test-c")

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("示例配置解析失败: %v", err)
	}
	enabled := 0
	for _, p := range cfg.Normalized {
		if p.Enabled {
			enabled++
		}
	}
	if enabled < 2 {
		t.Errorf("示例配置应至少有 2 个已启用供应商, got %d", enabled)
	}
	hasProxy := false
	for _, p := range cfg.Normalized {
		if p.Proxy.Mode != "direct" {
			hasProxy = true
		}
	}
	if !hasProxy {
		t.Error("示例配置应演示代理用法")
	}
}
