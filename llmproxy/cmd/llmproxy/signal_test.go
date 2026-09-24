package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

func cfgWith(host string, port int) *config.Config {
	return &config.Config{Server: config.ServerConfig{Host: host, Port: port}}
}

// healthURL 要处理两件容易静默出错的事：IPv6 地址必须加方括号，
// 而通配监听地址（0.0.0.0 / ::）不能直接拿去连 —— 探测要的是一个能连的具体地址，
// 通配地址在 macOS 上连不通，于是「服务明明在跑」会被判成「没在跑」，
// 进而让 stop / reload 拒绝发信号。
func TestHealthURL(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"普通 IPv4", cfgWith("127.0.0.1", 8787), "http://127.0.0.1:8787/healthz"},
		{"局域网地址", cfgWith("192.168.1.50", 8787), "http://192.168.1.50:8787/healthz"},
		{"IPv6 要加方括号", cfgWith("::1", 8787), "http://[::1]:8787/healthz"},
		{"通配 0.0.0.0 换成回环", cfgWith("0.0.0.0", 8787), "http://127.0.0.1:8787/healthz"},
		{"通配 :: 换成回环", cfgWith("::", 8787), "http://127.0.0.1:8787/healthz"},
		{"通配 [::] 换成回环", cfgWith("[::]", 8787), "http://127.0.0.1:8787/healthz"},
		{"host 为空", cfgWith("", 9000), "http://127.0.0.1:9000/healthz"},
		{"port 为 0 用默认", cfgWith("127.0.0.1", 0), "http://127.0.0.1:8787/healthz"},
		{"cfg 为 nil", nil, "http://127.0.0.1:8787/healthz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := healthURL(tc.cfg); got != tc.want {
				t.Errorf("healthURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

// serviceResponding 是「要不要往这个 pid 发信号」的判据。
//
// readPID 只用 kill(pid, 0) 探活，它证明的是「有这么个进程」，不是「这个进程是
// llmproxy」。服务被 SIGKILL 或崩溃时不会清 PID 文件，那个 pid 之后可能被系统
// 分配给完全无关的进程 —— 于是 stop 会给它发 SIGTERM、CLI 写操作后的通知会给它发
// SIGHUP，而这两个信号的默认动作都是终止。所以必须再确认一次「确实有 llmproxy 在服务」。
func TestServiceResponding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	if !serviceResponding(cfgWith(host, port)) {
		t.Error("服务在应答时应当返回 true")
	}

	// 非 200 不算「在服务」
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	badHost, badPortStr, _ := net.SplitHostPort(strings.TrimPrefix(bad.URL, "http://"))
	badPort, _ := strconv.Atoi(badPortStr)
	if serviceResponding(cfgWith(badHost, badPort)) {
		t.Error("健康端点返回 500 时不该判为在服务")
	}

	// 没人监听 → false。这正是「PID 文件陈旧、不该发信号」的那一档。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // 立刻关掉，这个端口上就没人听了
	if serviceResponding(cfgWith("127.0.0.1", deadPort)) {
		t.Error("端口上没人监听时应当返回 false")
	}

	// cfg 为 nil 也不该炸（配置读不出来时的退路）
	if serviceResponding(nil) {
		t.Error("cfg 为 nil 时应当返回 false")
	}
}

func TestFmtDur(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{47 * time.Second, "47s"},
		{90 * time.Second, "1m30s"},
		{3*time.Hour + 12*time.Minute, "3h12m"},
		{50 * time.Hour, "2d02h"},
	}
	for _, c := range cases {
		if got := fmtDur(c.d); got != c.want {
			t.Errorf("fmtDur(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestHumanCount(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1,000"},
		{12345, "12,345"},
		{307425279, "307,425,279"},
		{-5, "0"}, // 负数（余量算成负的）不输出负号，交给调用方判断
	}
	for _, c := range cases {
		if got := humanCount(c.n); got != c.want {
			t.Errorf("humanCount(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestHumanMoney(t *testing.T) {
	cases := []struct {
		v    float64
		want string
	}{
		{0, "0"},
		{0.0017, "0.001700"},
		{1.5, "1.50"},
		{2999.998, "3000.00"},
	}
	for _, c := range cases {
		if got := humanMoney(c.v); got != c.want {
			t.Errorf("humanMoney(%v) = %q, want %q", c.v, got, c.want)
		}
	}
}

// admin rotate 要在写生产配置时走完安全链：备份、原文件可回退、只动 admin_token 那一行、
// 写回后仍可加载且新值生效。
func TestAdminRotate(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/config.yaml"
	orig := "# 顶注，必须保留\n" +
		"server:\n  host: 127.0.0.1\n  port: 8787\n  api_keys: [sk-x]\n" +
		"routing: {retry: 2}\n" +
		"providers:\n  - name: p\n    enabled: true\n    base_url: https://api.example.com/v1\n    api_key: k\n    models: [\"*\"]\n" +
		"log:\n  level: info\n"
	if err := os.WriteFile(cfgPath, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := config.Paths{ConfigFile: cfgPath, PIDFile: dir + "/x.pid", RuntimeDir: dir}

	// 第一次 rotate：admin_token 原本不存在，应当被插入
	if err := adminRotate(paths); err != nil {
		t.Fatalf("rotate 失败: %v", err)
	}
	after1, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg1, err := config.LoadFileLenient(cfgPath)
	if err != nil {
		t.Fatalf("写回后配置解析失败: %v\n%s", err, after1)
	}
	if cfg1.Server.AdminToken == "" {
		t.Fatal("rotate 后 admin_token 为空")
	}
	if !strings.Contains(string(after1), "admin_token: "+cfg1.Server.AdminToken) {
		t.Errorf("文件里的 token 与加载到的不一致:\n%s", after1)
	}
	// 段外内容一个字节不能变
	for _, must := range []string{"# 顶注，必须保留", "  host: 127.0.0.1", "  port: 8787",
		"  api_keys: [sk-x]", "  base_url: https://api.example.com/v1", "  level: info"} {
		if !strings.Contains(string(after1), must) {
			t.Errorf("不该被动的内容丢了: %q\n%s", must, after1)
		}
	}
	// 备份应当留着原样
	baks, _ := filepath.Glob(cfgPath + ".bak-*")
	if len(baks) != 1 {
		t.Fatalf("应当有 1 份备份，实际 %d", len(baks))
	}
	if b, _ := os.ReadFile(baks[0]); string(b) != orig {
		t.Errorf("备份内容与原文件不一致:\n%s", b)
	}

	// 第二次 rotate：换成另一个值，不重复插入
	if err := adminRotate(paths); err != nil {
		t.Fatal(err)
	}
	after2, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(after2), "admin_token:"); n != 1 {
		t.Errorf("应当只有 1 处 admin_token，实际 %d:\n%s", n, after2)
	}
	cfg2, _ := config.LoadFileLenient(cfgPath)
	if cfg2.Server.AdminToken == cfg1.Server.AdminToken {
		t.Error("第二次 rotate 应当换成不同的 token")
	}
	// 两份备份都留着（最多 5 份）
	if baks, _ := filepath.Glob(cfgPath + ".bak-*"); len(baks) != 2 {
		t.Errorf("应当有 2 份备份，实际 %d", len(baks))
	}
}

// admin token：已配置时打印出来；未配置时给出可操作的提示，而不是一个空行。
func TestAdminTokenShowsAndSays(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/config.yaml"
	if err := os.WriteFile(cfgPath, []byte(
		"server:\n  host: 127.0.0.1\n  port: 8787\n  api_keys: [sk-x]\n  admin_token: sk-abc\n"+
			"providers:\n  - name: p\n    enabled: true\n    base_url: https://api.example.com/v1\n    api_key: k\n    models: [\"*\"]\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	paths := config.Paths{ConfigFile: cfgPath, PIDFile: dir + "/x.pid", RuntimeDir: dir}
	if err := adminToken(paths); err != nil {
		t.Fatal(err)
	}

	// 未配置时
	if err := os.WriteFile(cfgPath, []byte(
		"server:\n  host: 127.0.0.1\n  port: 8787\n  api_keys: [sk-x]\n"+
			"providers:\n  - name: p\n    enabled: true\n    base_url: https://api.example.com/v1\n    api_key: k\n    models: [\"*\"]\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	if err := adminToken(paths); err != nil {
		t.Fatal(err)
	}
}

// config set：白名单外的拒、值写进去、其余内容不动、备份留好、非法值被加载器拦下。
func TestConfigSet(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/config.yaml"
	orig := "# 顶注\n" +
		"server:\n  host: 127.0.0.1   # 监听地址\n  port: 8787\n  api_keys: [sk-x]\n  max_body_mb: 16\n" +
		"routing: {retry: 2, failure_threshold: 3, cooldown_seconds: 60}\n" +
		"providers:\n  - name: p\n    enabled: true\n    base_url: https://api.example.com/v1\n    api_key: k\n    models: [\"*\"]\n" +
		"database: {path: \"\", retain_days: 90}\n" +
		"log:\n  level: info\n"
	if err := os.WriteFile(cfgPath, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := config.Paths{ConfigFile: cfgPath, PIDFile: dir + "/x.pid", RuntimeDir: dir}

	// 白名单外的键拒掉，文件不动
	for _, bad := range [][]string{
		{"server.api_keys", "x"},      // 列表，刻意不放开
		{"server.admin_token", "x"},   // 密钥，走 admin rotate
		{"providers.p.base_url", "x"}, // providers 走管理台
		{"server.nonexistent", "1"},   // 白名单里没有
		{"badformat", "1"},            // 没有段.键 形状
	} {
		before, _ := os.ReadFile(cfgPath)
		if err := configSet(paths, bad); err == nil {
			t.Errorf("config set %v 应当被拒", bad)
		}
		if after, _ := os.ReadFile(cfgPath); string(after) != string(before) {
			t.Errorf("被拒的 set 不该改文件: %v", bad)
		}
	}

	// 合法 set：值写进去，其余不动
	if err := configSet(paths, []string{"log.level", "debug"}); err != nil {
		t.Fatalf("config set 失败: %v", err)
	}
	got, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(got), "level: debug") {
		t.Errorf("新值没写进去:\n%s", got)
	}
	if !strings.Contains(string(got), "# 顶注") || !strings.Contains(string(got), "  host: 127.0.0.1   # 监听地址") {
		t.Errorf("不该被动的内容变了:\n%s", got)
	}
	cfg, err := config.LoadFileLenient(cfgPath)
	if err != nil {
		t.Fatalf("写回后解析失败: %v\n%s", err, got)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("新值未生效: %q", cfg.Log.Level)
	}

	// 非法值：加载器会拒，原文件不动
	before, _ := os.ReadFile(cfgPath)
	if err := configSet(paths, []string{"log.level", "verbose"}); err == nil {
		t.Error("log.level=verbose 应当被加载器拒掉")
	}
	after, _ := os.ReadFile(cfgPath)
	if string(after) != string(before) {
		t.Errorf("校验失败时原文件不该动:\n%s", after)
	}

	// 备份存在
	if baks, _ := filepath.Glob(cfgPath + ".bak-*"); len(baks) < 2 {
		t.Errorf("应当留下至少 2 份备份（一次成功 + 一次失败的写入前备份），实际 %d", len(baks))
	}
}
