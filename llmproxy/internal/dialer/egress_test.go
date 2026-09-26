package dialer

import (
	"context"
	"net"
	"strings"
	"testing"
)

// 拨号层出网判定：配置校验时的 DNS 结果可能在真正 connect 前被改掉（rebinding），
// 所以 Control / CONNECT 前还要对最终 IP 再判一次。这里钉住第二层真的会拦。
func TestCheckTargetBlocksResolvedIP(t *testing.T) {
	deny := func(ip net.IP) error {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return &net.AddrError{Err: "blocked", Addr: ip.String()}
		}
		return nil
	}

	// IP 字面量直接判
	if err := checkTarget("169.254.169.254:80", deny); err == nil {
		t.Error("link-local 字面量应当被拒")
	}
	if err := checkTarget("127.0.0.1:80", deny); err == nil {
		t.Error("回环字面量应当被拒")
	}
	if err := checkTarget("8.8.8.8:443", deny); err != nil {
		t.Errorf("公网 IP 不该被拒: %v", err)
	}

	// 主机名：解析到回环的 localhost 必须被拒 —— 这就是 rebinding 场景的替身
	if err := checkTarget("localhost:80", deny); err == nil {
		t.Error("localhost 解析到回环，应当被拒")
	} else if !strings.Contains(err.Error(), "localhost") {
		t.Errorf("错误信息应点名主机，实际 %v", err)
	}

	// check 为 nil = 不校验（系统池路径）
	if err := checkTarget("169.254.169.254:80", nil); err != nil {
		t.Errorf("nil check 不该拦: %v", err)
	}
}

// 直连路径：net.Dialer.Control 必须在 connect 前判最终 IP。
// 用一个解析到回环的主机名 + deny 回环，拨号应当在 TCP 握手前失败。
func TestDirectDialBlockedByControl(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	denyLoopback := func(ip net.IP) error {
		if ip.IsLoopback() {
			return &net.AddrError{Err: "loopback blocked", Addr: ip.String()}
		}
		return nil
	}

	d, err := NewChecked("", denyLoopback)
	if err != nil {
		t.Fatal(err)
	}
	// 连的是回环上的真监听，若 Control 生效则 Dial 会被拒
	if conn, err := d.DialContext(context.Background(), "tcp", addr); err == nil {
		conn.Close()
		t.Error("回环地址应当被 Control 拒掉，却拨通了")
	}

	// 对照：不带 check 时能拨通
	d2, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d2.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("无 check 时应当能连上回环假上游: %v", err)
	}
	conn.Close()
}

// 代理路径：目标判定在建隧道之前，代理自己不该被牵连成「没连上」。
func TestProxyDialBlockedBeforeConnect(t *testing.T) {
	p := startFakeHTTPProxy(t, "", "")
	d, err := NewChecked("http://"+p.Addr(), func(ip net.IP) error {
		// 只拒目标里的 link-local，代理本身在回环上、要放行
		if ip.IsLinkLocalUnicast() {
			return &net.AddrError{Err: "metadata blocked", Addr: ip.String()}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.DialContext(context.Background(), "tcp", "169.254.169.254:80")
	if err == nil {
		t.Fatal("目标是云元数据时应当被拒")
	}
	if !strings.Contains(err.Error(), "拒绝") && !strings.Contains(err.Error(), "blocked") {
		t.Errorf("错误应当说明是出网判定拒绝，实际 %v", err)
	}
	// 代理不该收到 CONNECT（判定发生在建隧道之前）
	if p.connCount != 0 {
		t.Errorf("不该向代理发起 CONNECT，实际 %d 次", p.connCount)
	}
}

// Transport 缓存：带 check 与不带 check 的条目不能混用，且总数有上限。
func TestTransportCacheCheckedSeparateAndBounded(t *testing.T) {
	c := NewTransportCache()
	plain, err := c.Get("")
	if err != nil {
		t.Fatal(err)
	}
	checked, err := c.GetChecked("", func(ip net.IP) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if plain == checked {
		t.Error("带出网校验与不带的 Transport 不能是同一个（连接池行为不同）")
	}
	if c.Len() != 2 {
		t.Errorf("应当缓存 2 条，实际 %d", c.Len())
	}

	// 同一 key 复用
	again, err := c.GetChecked("", func(ip net.IP) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if again != checked {
		t.Error("同 key 应当命中缓存")
	}

	// 容量上限：不同 proxyURL 各占一条，超过 max 的按 LRU 丢掉
	c.Reset()
	c.SetMax(2)
	for i := 0; i < 5; i++ {
		u := "http://127.0.0.1:" + string(rune('1'+i))
		if _, err := c.GetChecked(u, func(ip net.IP) error { return nil }); err != nil {
			t.Fatalf("GetChecked(%s): %v", u, err)
		}
	}
	if c.Len() > 2 {
		t.Errorf("缓存上限 2，实际 %d", c.Len())
	}
}
