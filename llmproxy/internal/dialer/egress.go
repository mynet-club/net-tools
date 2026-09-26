package dialer

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// IPCheck 判定一个已解析 IP 能否作为拨号目标。返回非 nil 表示拒绝。
//
// 典型实现是 config.CheckResolvedIP 的闭包：用户可控上游用它做「配置校验 +
// 实际拨号再校验」的第二层，挡住配置通过后 DNS 被改指到内网的 rebinding。
type IPCheck func(ip net.IP) error

// baseDialer 带上出网校验的 net.Dialer：Control 在真正 connect 之前对
// **最终解析出的 IP** 再判一次。配置层的 CheckUpstreamEgress 只能看到校验
// 那一刻的 DNS 结果，这一层才把 rebinding 的窗口关掉。
func baseDialer(check IPCheck) *net.Dialer {
	d := &net.Dialer{Timeout: DefaultTimeout, KeepAlive: 30 * time.Second}
	if check != nil {
		d.Control = controlWithCheck(check)
	}
	return d
}

func controlWithCheck(check IPCheck) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("拨号地址 %q 不合法: %w", address, err)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			// Control 拿到的应当已是解析后的 IP；不是的话没法判，交给 connect 自己失败
			return nil
		}
		if err := check(ip); err != nil {
			return fmt.Errorf("拒绝拨号到 %s: %w", host, err)
		}
		return nil
	}
}

// checkTarget 在建立代理隧道之前对**目标主机**做一次出网判定。
//
// 代理路径上 base Dialer 的 Control 只看得到代理地址，目标是代理去连的，
// 所以目标必须在这里单独判。注意：通过代理时最终 IP 由代理解析，我们判的是
// 本地解析结果 —— 若代理自己重新解析，窗口比直连大（直连由 Control 封死）。
// 用户可控上游若要求彻底闭环，应避免再叠一层会重解析的代理。
func checkTarget(addr string, check IPCheck) error {
	if check == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("目标地址 %q 不合法（需要 host:port）: %w", addr, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		if err := check(ip); err != nil {
			return fmt.Errorf("拒绝连接 %s: %w", host, err)
		}
		return nil
	}
	addrs, err := net.LookupIP(host)
	if err != nil {
		// 解析失败不在这里报错 —— 后面拨号会再失败一次，那里的错误更准确
		return nil
	}
	for _, ip := range addrs {
		if err := check(ip); err != nil {
			return fmt.Errorf("拒绝连接 %s（解析所得 %s）: %w", host, ip, err)
		}
	}
	return nil
}

// New 按代理 URL 构造 Dialer。proxyURL 为空表示直连。不做额外出网校验。
func New(proxyURL string) (Dialer, error) {
	return NewChecked(proxyURL, nil)
}

// NewChecked 按代理 URL 构造 Dialer，并对拨号目标做 check 判定。
// check 为 nil 时与 New 等价（系统池等运营者自管路径）。
func NewChecked(proxyURL string, check IPCheck) (Dialer, error) {
	if strings.TrimSpace(proxyURL) == "" || strings.EqualFold(proxyURL, "direct") {
		return baseDialer(check), nil
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("代理 URL 不合法 %q: %w", proxyURL, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return newHTTPConnectDialer(u, check), nil
	case "socks5", "socks5h", "socks":
		return newSOCKS5Dialer(u, check), nil
	default:
		return nil, fmt.Errorf("不支持的代理协议 %q（支持 http/https/socks5/socks5h）", u.Scheme)
	}
}
