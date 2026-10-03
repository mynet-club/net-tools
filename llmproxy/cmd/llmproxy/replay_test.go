package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/replay"
)

// replay CLI 的判据是「不肯猜」：缺时钟、缺记录、没有策略包、没有凭据，
// 每一条都要当场报错，而不是带着一个看起来跑通了的结果退出 0。
// 回放报告一旦在 CI 里当门禁，静默的「空通过」比一次红更危险。

const replayCfgYAML = `server:
  host: 127.0.0.1
  port: 8787
  api_keys: [sk-x]
  admin_token: sk-admin-local
providers:
  - name: p
    enabled: true
    base_url: https://api.example.com/v1
    api_key: k
    max_data_level: internal
    models: ["*"]
policy:
  mode: enforce
  data_level: internal
  active_bundle: t-open
  bundles:
    - id: t-open
      version: 1
      scope: system:gateway
database:
  retain_days: 30
`

const replayBundleYAML = `id: t-open
version: 1
scope: system:gateway
entitlements:
  - subject: "*"
    resource: "model:*"
    action: use
    effect: allow
`

func replayHarness(t *testing.T, cfgSrc string) config.Paths {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	bundleDir := filepath.Join(dir, config.DefaultBundleDir)
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "t-open.yaml"), []byte(replayBundleYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Paths{RuntimeDir: dir, ConfigFile: cfgPath, PIDFile: filepath.Join(dir, "llmproxy.pid")}
}

// writeRecords 落一份记录文件，返回路径。
func writeRecords(t *testing.T, f replay.File) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "records.json")
	if err := os.WriteFile(path, []byte(replay.MustEncode(f)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReplayUsageWithoutArgs(t *testing.T) {
	paths := replayHarness(t, replayCfgYAML)
	if err := cmdReplay(paths, nil); err != nil {
		t.Fatalf("无参数应打印用法并返回 nil: %v", err)
	}
	if err := cmdReplay(paths, []string{"nope"}); err == nil ||
		!strings.Contains(err.Error(), "未知的 replay 子命令") {
		t.Fatalf("未知子命令应报错: %v", err)
	}
}

// -records 与 -now 都是必填：空记录不算通过，缺时钟不予回放。
func TestReplayRunFailsClosedOnMissingInputs(t *testing.T) {
	paths := replayHarness(t, replayCfgYAML)

	err := cmdReplay(paths, []string{"run"})
	if err == nil || !strings.Contains(err.Error(), "-records 必填") {
		t.Fatalf("缺 -records 应报错: %v", err)
	}

	rec := writeRecords(t, replay.NewFile(nil, nil))
	if err := cmdReplay(paths, []string{"run", "-records", rec}); err == nil ||
		!strings.Contains(err.Error(), "-now 必填") {
		t.Fatalf("缺 -now 必须报错而不是用当前时间兜底: %v", err)
	}
	if err := cmdReplay(paths, []string{"run", "-records", rec, "-now", "前天"}); err == nil ||
		!strings.Contains(err.Error(), "RFC3339") {
		t.Fatalf("-now 不合法应报错: %v", err)
	}
	if err := cmdReplay(paths, []string{"run", "-records", "/nonexistent/x.json",
		"-now", "2026-10-03T12:00:00Z"}); err == nil ||
		!strings.Contains(err.Error(), "读取记录文件失败") {
		t.Fatalf("记录文件读不到应报错: %v", err)
	}
	// 不是记录文件的 JSON 也当场说破（不许当成「空记录」放过）。
	bogus := filepath.Join(t.TempDir(), "bogus.json")
	if err := os.WriteFile(bogus, []byte(`{"decisions":[{"body":"悄悄塞进来的正文"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdReplay(paths, []string{"run", "-records", bogus,
		"-now", "2026-10-03T12:00:00Z"}); err == nil ||
		!strings.Contains(err.Error(), "记录文件不合法") {
		t.Fatalf("含正文字段的记录必须被拒: %v", err)
	}
}

// 空记录不算通过：门禁在记录没落下来时最容易静默变绿。
func TestReplayRunRejectsEmptyRecords(t *testing.T) {
	paths := replayHarness(t, replayCfgYAML)
	rec := writeRecords(t, replay.NewFile(nil, nil))
	err := cmdReplay(paths, []string{"run", "-records", rec, "-now", "2026-10-03T12:00:00Z"})
	if err == nil || !strings.Contains(err.Error(), "没有任何可回放的条目") {
		t.Fatalf("空记录应报错: %v", err)
	}
}

// legacy 配置（没有 policy 段）手里没有可回放的策略包 —— 必须明说，
// 而不是「跑了一遍、0 条差异」这种看着像成功的输出。
func TestReplayRunNeedsLoadedBundles(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	legacy := strings.Replace(replayCfgYAML, `policy:
  mode: enforce
  data_level: internal
  active_bundle: t-open
  bundles:
    - id: t-open
      version: 1
      scope: system:gateway
`, "", 1)
	if err := os.WriteFile(cfgPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := config.Paths{RuntimeDir: dir, ConfigFile: cfgPath}
	rec := writeRecords(t, replay.NewFile(nil, nil))
	err := cmdReplay(paths, []string{"run", "-records", rec, "-now", "2026-10-03T12:00:00Z"})
	if err == nil || !strings.Contains(err.Error(), "没有可回放的策略包") {
		t.Fatalf("legacy 配置应报错: %v", err)
	}
}

// 管理凭证是「查/用两条通道」里的那一条：CLI 从配置文件读它，
// 但既不打印也不接受环境变量残留的 ${...}。
func TestReplayAdminCallRequiresUsableToken(t *testing.T) {
	noToken := strings.Replace(replayCfgYAML, "  admin_token: sk-admin-local\n", "", 1)
	paths := replayHarness(t, noToken)
	err := cmdReplay(paths, []string{"status"})
	if err == nil || !strings.Contains(err.Error(), "admin_token") {
		t.Fatalf("没有管理凭证应报错: %v", err)
	}

	envRef := strings.Replace(replayCfgYAML, "  admin_token: sk-admin-local\n",
		"  admin_token: ${LLMPROXY_TEST_TOKEN_MISSING}\n", 1)
	paths = replayHarness(t, envRef)
	os.Unsetenv("LLMPROXY_TEST_TOKEN_MISSING")
	if err := cmdReplay(paths, []string{"status"}); err == nil ||
		!strings.Contains(err.Error(), "环境变量引用") {
		t.Fatalf("未展开的环境变量引用应报错而不是拿去发请求: %v", err)
	}
}

// host 是通配时不能拿 0.0.0.0 去连（macOS 上连不通），要落到回环。
func TestReplayAdminBaseURLNormalizesWildcardHost(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.Port = 18787
	cfg.Server.AdminToken = "sk-admin-local"
	if got := adminBaseURL(cfg); got != "http://127.0.0.1:18787" {
		t.Fatalf("通配 host 没归一成回环: %s", got)
	}
	cfg.Server.Host = "127.0.0.1"
	if got := adminBaseURL(cfg); got != "http://127.0.0.1:18787" {
		t.Fatalf("显式地址不该被改写: %s", got)
	}
	cfg.Server.Host = ""
	cfg.Server.Port = 0
	if got := adminBaseURL(cfg); got != "http://127.0.0.1:8787" {
		t.Fatalf("端口缺省没落到 8787: %s", got)
	}
}
