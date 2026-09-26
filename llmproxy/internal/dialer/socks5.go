package dialer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"
)

// newSOCKS5Dialer 构造 SOCKS5 拨号器。
//
// 实现细节：目标主机名一律以 ATYP=3（域名）交给代理解析，行为等价 socks5h。
// 这样上游域名不会泄漏到本地 DNS，也避免域名解析结果与代理出口地理位置不一致。
// 出网判定在本地做一次（checkTarget），见 egress.go 对代理路径 TOCTOU 的说明。
type socks5Dialer struct {
	proxyURL *url.URL
	base     *net.Dialer
	check    IPCheck
}

func newSOCKS5Dialer(u *url.URL, check IPCheck) *socks5Dialer {
	return &socks5Dialer{
		proxyURL: u,
		base:     baseDialer(check),
		check:    check,
	}
}

func (d *socks5Dialer) proxyAddr() string {
	host := d.proxyURL.Hostname()
	if port := d.proxyURL.Port(); port != "" {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(host, "1080")
}

func (d *socks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("SOCKS5 只支持 tcp，当前是 %q", network)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("目标地址 %q 不合法（需要 host:port）: %w", addr, err)
	}
	// 目标出网判定：见 egress.go。base Dialer 的 Control 判的是代理地址。
	if err := checkTarget(addr, d.check); err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("目标端口 %q 不合法", portStr)
	}

	proxyAddr := d.proxyAddr()
	conn, err := d.base.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("连接 SOCKS5 代理 %s 失败: %w", proxyAddr, err)
	}
	fail := func(e error) (net.Conn, error) {
		_ = conn.Close()
		return nil, e
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(DefaultTimeout))
	}

	user := ""
	pass := ""
	if d.proxyURL.User != nil {
		user = d.proxyURL.User.Username()
		pass, _ = d.proxyURL.User.Password()
	}
	needAuth := user != "" || pass != ""

	// ---- 方法协商
	if needAuth {
		_, err = conn.Write([]byte{0x05, 0x02, 0x00, 0x02}) // 无认证 + 用户名密码
	} else {
		_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	}
	if err != nil {
		return fail(fmt.Errorf("向 SOCKS5 代理 %s 发送协商失败: %w", proxyAddr, err))
	}

	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		return fail(fmt.Errorf("读取 SOCKS5 代理 %s 协商响应失败: %w", proxyAddr, err))
	}
	if sel[0] != 0x05 {
		return fail(fmt.Errorf("SOCKS5 代理 %s 返回了不支持的协议版本 %d", proxyAddr, sel[0]))
	}

	switch sel[1] {
	case 0x00:
		// 无需认证
	case 0x02:
		if !needAuth {
			return fail(fmt.Errorf("SOCKS5 代理 %s 要求用户名密码认证，但 URL 里没写 user:pass@", proxyAddr))
		}
		uBytes := []byte(user)
		pBytes := []byte(pass)
		if len(uBytes) > 255 || len(pBytes) > 255 {
			return fail(errors.New("SOCKS5 用户名或密码超过 255 字节"))
		}
		buf := make([]byte, 0, 3+len(uBytes)+len(pBytes))
		buf = append(buf, 0x01, byte(len(uBytes)))
		buf = append(buf, uBytes...)
		buf = append(buf, byte(len(pBytes)))
		buf = append(buf, pBytes...)
		if _, err := conn.Write(buf); err != nil {
			return fail(fmt.Errorf("SOCKS5 认证请求发送失败: %w", err))
		}
		var authResp [2]byte
		if _, err := io.ReadFull(conn, authResp[:]); err != nil {
			return fail(fmt.Errorf("读取 SOCKS5 认证响应失败: %w", err))
		}
		if authResp[1] != 0x00 {
			return fail(fmt.Errorf("SOCKS5 代理 %s 认证失败（用户名或密码错误）", proxyAddr))
		}
	case 0xFF:
		return fail(fmt.Errorf("SOCKS5 代理 %s 不接受任何认证方式", proxyAddr))
	default:
		return fail(fmt.Errorf("SOCKS5 代理 %s 选择的认证方式 %d 不受支持", proxyAddr, sel[1]))
	}

	// ---- CONNECT 请求：一律 ATYP=3（域名），让代理解析 DNS
	hostBytes := []byte(host)
	if len(hostBytes) == 0 || len(hostBytes) > 255 {
		return fail(fmt.Errorf("目标主机名长度不合法：%q", host))
	}
	req := make([]byte, 0, 7+len(hostBytes))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(hostBytes)))
	req = append(req, hostBytes...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return fail(fmt.Errorf("SOCKS5 CONNECT 请求发送失败: %w", err))
	}

	// ---- CONNECT 响应：VER REP RSV ATYP ...
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fail(fmt.Errorf("读取 SOCKS5 CONNECT 响应失败: %w", err))
	}
	if head[1] != 0x00 {
		return fail(fmt.Errorf("SOCKS5 无法连接 %s:%d：%s", host, port, socks5ErrorText(head[1])))
	}

	var addrLen int
	switch head[3] {
	case 0x01:
		addrLen = 4
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return fail(fmt.Errorf("读取 SOCKS5 响应域名长度失败: %w", err))
		}
		addrLen = int(n[0])
	case 0x04:
		addrLen = 16
	default:
		return fail(fmt.Errorf("SOCKS5 返回了未知的地址类型 %d", head[3]))
	}
	// 消费 BND.ADDR + BND.PORT
	if addrLen > 0 {
		if _, err := io.CopyN(io.Discard, conn, int64(addrLen)); err != nil {
			return fail(fmt.Errorf("读取 SOCKS5 响应地址失败: %w", err))
		}
	}
	var bndPort [2]byte
	if _, err := io.ReadFull(conn, bndPort[:]); err != nil {
		return fail(fmt.Errorf("读取 SOCKS5 响应端口失败: %w", err))
	}

	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func socks5ErrorText(code byte) string {
	switch code {
	case 0x01:
		return "代理内部错误"
	case 0x02:
		return "规则不允许"
	case 0x03:
		return "网络不可达"
	case 0x04:
		return "主机不可达"
	case 0x05:
		return "连接被拒绝"
	case 0x06:
		return "TTL 超时"
	case 0x07:
		return "命令不支持"
	case 0x08:
		return "地址类型不支持"
	}
	return fmt.Sprintf("未知错误码 %d", code)
}
