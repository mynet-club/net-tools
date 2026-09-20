package dialer

import (
	"crypto/tls"
	"net/http"
	"sync"
	"time"
)

// TransportCache 按代理 URL 缓存 http.Transport，避免每个请求都新建 TCP 连接池。
type TransportCache struct {
	mu         sync.Mutex
	transports map[string]*http.Transport
}

func NewTransportCache() *TransportCache {
	return &TransportCache{transports: make(map[string]*http.Transport)}
}

// Get 返回该代理 URL 对应的 Transport；proxyURL 为空表示直连。
//
// 直连时显式把 t.Proxy 置为 nil：Go 默认会读 HTTP_PROXY/HTTPS_PROXY 环境变量，
// 而这个工具的代理完全由配置文件决定，不应该被环境变量悄悄改道。
func (c *TransportCache) Get(proxyURL string) (*http.Transport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.transports[proxyURL]; ok {
		return t, nil
	}
	d, err := New(proxyURL)
	if err != nil {
		return nil, err
	}
	t := &http.Transport{
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	t.Proxy = nil
	c.transports[proxyURL] = t
	return t, nil
}

// Reset 丢弃全部缓存的 Transport（配置热重载后调用）。
func (c *TransportCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, t := range c.transports {
		t.CloseIdleConnections()
	}
	c.transports = make(map[string]*http.Transport)
}
