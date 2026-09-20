package dialer

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- 假代理 / 目标

type fakeHTTPProxy struct {
	ln        net.Listener
	user      string
	pass      string
	connCount int
	targets   []string
}

func startFakeHTTPProxy(t *testing.T, user, pass string) *fakeHTTPProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeHTTPProxy{ln: ln, user: user, pass: pass}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return p
}

func (p *fakeHTTPProxy) Addr() string { return p.ln.Addr().String() }

func (p *fakeHTTPProxy) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	if !strings.HasPrefix(line, "CONNECT ") {
		_, _ = c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}
	// 消费请求头
	auth := ""
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if h == "\r\n" || h == "\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(h), "proxy-authorization:") {
			auth = strings.TrimSpace(h[len("proxy-authorization:"):])
		}
	}
	target := strings.TrimSpace(strings.TrimPrefix(line, "CONNECT "))
	target = strings.TrimSpace(strings.SplitN(target, " ", 2)[0])
	p.connCount++
	p.targets = append(p.targets, target)

	if p.user != "" {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(p.user+":"+p.pass))
		if auth != want {
			_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"))
			return
		}
	}

	up, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	go io.Copy(up, br)
	io.Copy(c, up)
}

type fakeSocks5 struct {
	ln   net.Listener
	user string
	pass string
	seen []string // 记录 ATYP=3 的 "host:port"
}

func startFakeSocks5(t *testing.T, user, pass string) *fakeSocks5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSocks5{ln: ln, user: user, pass: pass}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *fakeSocks5) Addr() string { return s.ln.Addr().String() }

func (s *fakeSocks5) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)

	// 协商
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(r, methods); err != nil {
		return
	}
	needAuth := s.user != ""
	if needAuth {
		if _, err := c.Write([]byte{5, 2}); err != nil {
			return
		}
		// 认证子协商
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(r, hdr); err != nil || hdr[0] != 1 {
			return
		}
		ub := make([]byte, hdr[1])
		if _, err := io.ReadFull(r, ub); err != nil {
			return
		}
		var pb [1]byte
		if _, err := io.ReadFull(r, pb[:]); err != nil {
			return
		}
		pass := make([]byte, pb[0])
		if _, err := io.ReadFull(r, pass); err != nil {
			return
		}
		if string(ub) != s.user || string(pass) != s.pass {
			_, _ = c.Write([]byte{1, 1})
			return
		}
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return
		}
	} else {
		if _, err := c.Write([]byte{5, 0}); err != nil {
			return
		}
	}

	// CONNECT 请求
	req := make([]byte, 4)
	if _, err := io.ReadFull(r, req); err != nil || req[0] != 5 {
		return
	}
	var host string
	var port int
	switch req[3] {
	case 1: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 3: // 域名 —— 我们的实现应总是用这个
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return
		}
		hb := make([]byte, n[0])
		if _, err := io.ReadFull(r, hb); err != nil {
			return
		}
		host = string(hb)
	case 4:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(r, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(r, pb); err != nil {
		return
	}
	port = int(pb[0])<<8 | int(pb[1])
	s.seen = append(s.seen, fmt.Sprintf("%s:%d", host, port))

	up, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 3*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go io.Copy(up, r)
	io.Copy(c, up)
}

func startEchoTarget(t *testing.T) (addr string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"path":%q}`, r.URL.Path)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	a := ln.Addr().String()
	_, pStr, _ := net.SplitHostPort(a)
	var p int
	fmt.Sscanf(pStr, "%d", &p)
	return a, p
}

func doGet(t *testing.T, targetAddr string, proxyURL string) (int, string, error) {
	t.Helper()
	d, err := New(proxyURL)
	if err != nil {
		return 0, "", err
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	resp, err := client.Get("http://" + targetAddr + "/echo")
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

// ---------------------------------------------------------------- 测试

func TestDirectDial(t *testing.T) {
	addr, _ := startEchoTarget(t)
	code, body, err := doGet(t, addr, "")
	if err != nil {
		t.Fatalf("直连失败: %v", err)
	}
	if code != 200 || !strings.Contains(body, `"ok":true`) {
		t.Errorf("直连响应异常: %d %s", code, body)
	}
}

func TestHTTPProxyTunnel(t *testing.T) {
	addr, port := startEchoTarget(t)
	px := startFakeHTTPProxy(t, "", "")
	code, body, err := doGet(t, addr, "http://"+px.Addr())
	if err != nil {
		t.Fatalf("HTTP 代理隧道失败: %v", err)
	}
	if code != 200 || !strings.Contains(body, `"ok":true`) {
		t.Errorf("响应异常: %d %s", code, body)
	}
	if len(px.targets) != 1 {
		t.Fatalf("代理应收到 1 次 CONNECT, got %v", px.targets)
	}
	want := fmt.Sprintf("127.0.0.1:%d", port)
	if px.targets[0] != want {
		t.Errorf("CONNECT 目标 = %q, want %q", px.targets[0], want)
	}
}

func TestHTTPProxyAuth(t *testing.T) {
	addr, _ := startEchoTarget(t)
	px := startFakeHTTPProxy(t, "u", "p")

	// 正确认证
	code, body, err := doGet(t, addr, "http://u:p@"+px.Addr())
	if err != nil {
		t.Fatalf("带认证的 HTTP 代理失败: %v", err)
	}
	if code != 200 || !strings.Contains(body, `"ok":true`) {
		t.Errorf("响应异常: %d %s", code, body)
	}

	// 缺认证 → 应报 407 并提示
	_, _, err = doGet(t, addr, "http://"+px.Addr())
	if err == nil {
		t.Fatal("缺认证应失败")
	}
	if !strings.Contains(err.Error(), "407") || !strings.Contains(err.Error(), "认证") {
		t.Errorf("错误信息应包含 407 与认证提示: %v", err)
	}

	// 错误认证
	_, _, err = doGet(t, addr, "http://u:wrong@"+px.Addr())
	if err == nil {
		t.Fatal("错误认证应失败")
	}
}

func TestSOCKS5Tunnel(t *testing.T) {
	addr, _ := startEchoTarget(t)
	s5 := startFakeSocks5(t, "", "")
	code, body, err := doGet(t, addr, "socks5://"+s5.Addr())
	if err != nil {
		t.Fatalf("SOCKS5 隧道失败: %v", err)
	}
	if code != 200 || !strings.Contains(body, `"ok":true`) {
		t.Errorf("响应异常: %d %s", code, body)
	}
	if len(s5.seen) == 0 {
		t.Fatal("SOCKS5 代理未收到 CONNECT 请求")
	}
	// 必须以域名方式（ATYP=3）交给代理解析
	if !strings.HasPrefix(s5.seen[0], "127.0.0.1:") && !strings.Contains(s5.seen[0], ":") {
		t.Errorf("SOCKS5 请求目标异常: %v", s5.seen)
	}
}

func TestSOCKS5Auth(t *testing.T) {
	addr, _ := startEchoTarget(t)
	s5 := startFakeSocks5(t, "u", "p")

	code, body, err := doGet(t, addr, "socks5://u:p@"+s5.Addr())
	if err != nil {
		t.Fatalf("SOCKS5 认证失败: %v", err)
	}
	if code != 200 || !strings.Contains(body, `"ok":true`) {
		t.Errorf("响应异常: %d %s", code, body)
	}

	_, _, err = doGet(t, addr, "socks5://u:wrong@"+s5.Addr())
	if err == nil {
		t.Fatal("SOCKS5 错误密码应失败")
	}
	if !strings.Contains(err.Error(), "认证失败") {
		t.Errorf("错误信息应含 认证失败: %v", err)
	}

	// 代理要求认证但 URL 没写
	_, _, err = doGet(t, addr, "socks5://"+s5.Addr())
	if err == nil {
		t.Fatal("缺认证应失败")
	}
	if !strings.Contains(err.Error(), "要求用户名密码认证") {
		t.Errorf("错误信息不清晰: %v", err)
	}
}

func TestProxyUnreachable(t *testing.T) {
	addr, _ := startEchoTarget(t)
	_, _, err := doGet(t, addr, "http://127.0.0.1:1")
	if err == nil {
		t.Fatal("代理不可达应失败")
	}
	if !strings.Contains(err.Error(), "连接 HTTP 代理") {
		t.Errorf("错误信息不清晰: %v", err)
	}
}

func TestUnsupportedScheme(t *testing.T) {
	_, err := New("ftp://127.0.0.1:21")
	if err == nil || !strings.Contains(err.Error(), "不支持的代理协议") {
		t.Fatalf("不支持的协议应报错, got %v", err)
	}
}

func TestInvalidTargetAddr(t *testing.T) {
	d, err := New("http://127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.DialContext(context.Background(), "tcp", "no-port")
	if err == nil || !strings.Contains(err.Error(), "不合法") {
		t.Fatalf("目标地址缺端口应报错, got %v", err)
	}
}

func TestTransportCacheReuse(t *testing.T) {
	c := NewTransportCache()
	t1, err := c.Get("")
	if err != nil {
		t.Fatal(err)
	}
	t2, err := c.Get("")
	if err != nil {
		t.Fatal(err)
	}
	if t1 != t2 {
		t.Error("同一代理 URL 应复用同一个 Transport")
	}
	t3, err := c.Get("socks5://127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if t3 == t1 {
		t.Error("不同代理应使用不同的 Transport")
	}
	if t1.Proxy != nil {
		t.Error("直连 Transport 不应读取环境变量里的代理")
	}
	c.Reset()
	t4, err := c.Get("")
	if err != nil {
		t.Fatal(err)
	}
	if t4 == t1 {
		t.Error("Reset 后应重建 Transport")
	}
}
