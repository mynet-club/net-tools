package dialer

import (
	"container/list"
	"crypto/tls"
	"net/http"
	"sync"
	"time"
)

// maxCachedTransports 是 Transport 缓存条数上限。每个条目背后是一套连接池，
// 用户可控的代理 URL 会不断造出新 key —— 没有上限就能吃内存。
const maxCachedTransports = 64

// TransportCache 按「代理 URL + 是否带出网校验」缓存 http.Transport，
// 避免每个请求都新建 TCP 连接池。
type TransportCache struct {
	mu         sync.Mutex
	max        int
	order      *list.List // *transportEntry，Front = 最近使用
	transports map[string]*list.Element
}

type transportEntry struct {
	key string
	tr  *http.Transport
}

func NewTransportCache() *TransportCache {
	return &TransportCache{
		max:        maxCachedTransports,
		order:      list.New(),
		transports: make(map[string]*list.Element),
	}
}

// SetMax 调整缓存上限（测试或配置热重载用）。小于 1 时忽略。
func (c *TransportCache) SetMax(n int) {
	if n < 1 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.max = n
	c.evictLocked()
}

// Len 返回当前缓存的 Transport 数量。
func (c *TransportCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.transports)
}

// Get 返回该代理 URL 对应的 Transport；proxyURL 为空表示直连。
// 不做出网校验（系统池等运营者自管路径）。
func (c *TransportCache) Get(proxyURL string) (*http.Transport, error) {
	return c.GetChecked(proxyURL, nil)
}

// GetChecked 返回带出网校验的 Transport。check 为 nil 时与 Get 等价，
// 但缓存 key 不同 —— 带校验与不带校验的连接池不能混用。
//
// 直连时显式把 t.Proxy 置为 nil：Go 默认会读 HTTP_PROXY/HTTPS_PROXY 环境变量，
// 而这个工具的代理完全由配置文件决定，不应该被环境变量悄悄改道。
func (c *TransportCache) GetChecked(proxyURL string, check IPCheck) (*http.Transport, error) {
	key := proxyURL
	if check != nil {
		key = "checked\x00" + proxyURL
	}

	c.mu.Lock()
	if el, ok := c.transports[key]; ok {
		c.order.MoveToFront(el)
		c.mu.Unlock()
		return el.Value.(*transportEntry).tr, nil
	}
	c.mu.Unlock()

	d, err := NewChecked(proxyURL, check)
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

	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.transports[key]; ok {
		// 并发构造撞车：用先到的那个，丢掉多余的连接池
		c.order.MoveToFront(el)
		return el.Value.(*transportEntry).tr, nil
	}
	el := c.order.PushFront(&transportEntry{key: key, tr: t})
	c.transports[key] = el
	c.evictLocked()
	return t, nil
}

// evictLocked 把缓存压回上限以内（LRU 从队尾丢）。调用方须持锁。
func (c *TransportCache) evictLocked() {
	for len(c.transports) > c.max {
		el := c.order.Back()
		if el == nil {
			return
		}
		entry := el.Value.(*transportEntry)
		entry.tr.CloseIdleConnections()
		c.order.Remove(el)
		delete(c.transports, entry.key)
	}
}

// Reset 丢弃全部缓存的 Transport（配置热重载后调用）。
func (c *TransportCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, el := range c.transports {
		el.Value.(*transportEntry).tr.CloseIdleConnections()
	}
	c.order.Init()
	c.transports = make(map[string]*list.Element)
}
