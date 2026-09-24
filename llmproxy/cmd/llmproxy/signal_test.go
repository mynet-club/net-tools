package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

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
		{"局域网地址", cfgWith("192.168.0.4", 8787), "http://192.168.0.4:8787/healthz"},
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
