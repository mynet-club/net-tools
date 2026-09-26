// Package dialer 提供上游连接的出口选择：直连 / HTTP(S) 代理 / SOCKS5。
//
// 被代理的上游一律走 CONNECT 隧道（HTTP 代理用 CONNECT 方法，SOCKS5 用 CONNECT 命令），
// https 目标在隧道上再做一次 TLS 握手。这样只有一条代码路径。
// 代价：代理必须允许 CONNECT 到上游端口（Clash / squid / tinyproxy 默认都允许）。
package dialer

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Dialer 与 net.Dialer 接口对齐。
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// DefaultTimeout 是直连与代理握手的默认超时。
const DefaultTimeout = 30 * time.Second

// ------------------------------------------------------------------ HTTP CONNECT

type httpConnectDialer struct {
	proxyURL *url.URL
	base     *net.Dialer
	check    IPCheck
}

func newHTTPConnectDialer(u *url.URL, check IPCheck) *httpConnectDialer {
	return &httpConnectDialer{
		proxyURL: u,
		base:     baseDialer(check),
		check:    check,
	}
}

func (d *httpConnectDialer) proxyAddr() (string, error) {
	host := d.proxyURL.Hostname()
	if host == "" {
		return "", errors.New("代理 URL 缺少 host")
	}
	if port := d.proxyURL.Port(); port != "" {
		return net.JoinHostPort(host, port), nil
	}
	if strings.EqualFold(d.proxyURL.Scheme, "https") {
		return net.JoinHostPort(host, "443"), nil
	}
	return net.JoinHostPort(host, "80"), nil
}

// bufferedConn 让 Read 优先从 bufio.Reader 取数据，避免隧道响应头之后
// 已被读进缓冲区的字节丢失。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (d *httpConnectDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("HTTP 代理只支持 tcp，当前是 %q", network)
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("目标地址 %q 不合法（需要 host:port）: %w", addr, err)
	}
	// 目标出网判定：代理只负责转发，最终连到哪是这里说了算的「意图」，
	// 必须在建隧道之前判掉。base Dialer 的 Control 判的是代理地址。
	if err := checkTarget(addr, d.check); err != nil {
		return nil, err
	}

	proxyAddr, err := d.proxyAddr()
	if err != nil {
		return nil, err
	}

	conn, err := d.base.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("连接 HTTP 代理 %s 失败: %w", proxyAddr, err)
	}

	closeWith := func(e error) (net.Conn, error) {
		_ = conn.Close()
		return nil, e
	}

	// https:// 代理：到代理这一段本身就是 TLS
	if strings.EqualFold(d.proxyURL.Scheme, "https") {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: d.proxyURL.Hostname(),
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return closeWith(fmt.Errorf("HTTP 代理 %s 的 TLS 握手失败: %w", proxyAddr, err))
		}
		conn = tlsConn
	}

	var req strings.Builder
	fmt.Fprintf(&req, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if d.proxyURL.User != nil {
		pass, _ := d.proxyURL.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(d.proxyURL.User.Username() + ":" + pass))
		fmt.Fprintf(&req, "Proxy-Authorization: Basic %s\r\n", token)
	}
	req.WriteString("\r\n")

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(DefaultTimeout))
	}
	if _, err := conn.Write([]byte(req.String())); err != nil {
		return closeWith(fmt.Errorf("向 HTTP 代理 %s 发送 CONNECT 失败: %w", proxyAddr, err))
	}

	// 刻意不用 http.ReadResponse：CONNECT 200 之后是隧道数据，
	// 若被当成 response body 读走就会污染连接。
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return closeWith(fmt.Errorf("读取 HTTP 代理 CONNECT 响应失败: %w", err))
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return closeWith(fmt.Errorf("HTTP 代理返回了无法解析的响应: %s", truncate(statusLine, 120)))
	}
	code, convErr := strconv.Atoi(parts[1])
	if convErr != nil {
		return closeWith(fmt.Errorf("HTTP 代理返回了无法解析的状态码: %s", truncate(statusLine, 120)))
	}
	// 消费剩余响应头，直到空行
	for {
		line, rerr := br.ReadString('\n')
		if rerr != nil {
			return closeWith(fmt.Errorf("读取 HTTP 代理 CONNECT 响应头失败: %w", rerr))
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	_ = conn.SetDeadline(time.Time{})

	if code != 200 {
		hint := ""
		if code == 407 {
			hint = "（代理需要认证，请在 url 里写 user:pass@host）"
		}
		return closeWith(fmt.Errorf("HTTP 代理 %s 拒绝建立到 %s 的隧道: %s%s", proxyAddr, addr, statusLine, hint))
	}

	// 缓冲区里若已有隧道数据，必须经 bufferedConn 交还给调用方
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
