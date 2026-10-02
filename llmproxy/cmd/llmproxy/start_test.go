package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

// 坏策略配置必须在 cmdStart 里当场挡住。
//
// 挡不住的后果不是「启动失败」而是「启动成功但一条规则都没加载」：网关照常应答、
// 健康检查照常绿，唯独 enforce 的禁令全部不存在，而管理台里的 mode 仍写着 enforce。
// 这一段是 §3.0「影子之前先排除配了但没生效」在启动路径上的落点 ——
// CheckPolicyRuntime 早就有了并有包内测试，缺的正是这条接线（本测试把它钉住）。
func TestCmdStartRefusesBrokenPolicyBundle(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	yaml := "server:\n  host: 127.0.0.1\n  port: 8787\n  api_keys: [sk-x]\n" +
		"routing: {retry: 1}\n" +
		"providers:\n  - name: p\n    enabled: true\n    base_url: https://api.example.com/v1\n" +
		"    api_key: k\n    max_data_level: internal\n    models: [\"*\"]\n" +
		"database:\n  path: \"" + filepath.Join(dir, "data", "llmproxy.db") + "\"\n" +
		"log:\n  level: info\n" +
		"config_schema_version: 3\n" +
		"policy:\n  mode: enforce\n  data_level: internal\n  active_bundle: missing-bundle\n" +
		"  bundles:\n    - id: missing-bundle\n      version: 1\n      scope: system:gateway\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := config.Paths{
		RuntimeDir: dir,
		ConfigFile: cfgPath,
		PIDFile:    filepath.Join(dir, "llmproxy.pid"),
		LogDir:     filepath.Join(dir, "logs"),
		DataDir:    filepath.Join(dir, "data"),
	}

	err := cmdStart(paths)
	if err == nil {
		t.Fatal("策略包缺内容文件时必须拒绝启动")
	}
	if !strings.Contains(err.Error(), "拒绝启动") || !strings.Contains(err.Error(), "missing-bundle.yaml") {
		t.Errorf("错误要说清「拒绝启动」和缺哪个文件: %v", err)
	}
	// 挡住必须发生在开库、写 PID、监听端口之前 —— 否则一个改错的策略段会在
	// 服务管理脚本那里留下半套运行态，下次 start 还会撞上「已在运行」。
	if _, statErr := os.Stat(paths.PIDFile); statErr == nil {
		t.Error("拒绝启动后不该留下 PID 文件")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "data", "llmproxy.db")); statErr == nil {
		t.Error("拒绝启动后不该打开数据库")
	}
}
