package server

import (
	"sync"
	"time"
)

// usageReportTTL 是用量报表的缓存有效期。
//
// 用量接口是界面轮询的热点：每次打开页面/切标签都会打一遍 UsageByUser +
// TotalByUser + SystemUsageRowsSince，再对每一行做 rowCharge。这些查询抢的是
// store 那条唯一 SQLite 连接，轮询一密就把转发路径的落库也堵在后面。
//
// 5 秒的陈旧度对「看今天花了多少」完全够用；配额判断**不走这份缓存**
// （那是 meters 的实时计数），所以不会因为缓存而少扣或多扣。
const usageReportTTL = 5 * time.Second

type usageReportKey struct {
	scope string
	days  int
}

type usageReportEntry struct {
	expires time.Time
	payload map[string]any
}

// usageReportCache 按 (用户, 天数) 缓存拼好的用量报表。
type usageReportCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	now     func() time.Time
	entries map[usageReportKey]*usageReportEntry
	max     int
}

func newUsageReportCache() *usageReportCache {
	return &usageReportCache{
		ttl:     usageReportTTL,
		now:     time.Now,
		entries: make(map[usageReportKey]*usageReportEntry),
		max:     256,
	}
}

// Get 取缓存；未命中或已过期返回 nil。
func (c *usageReportCache) Get(key usageReportKey) map[string]any {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[key]
	if e == nil {
		return nil
	}
	if !c.now().Before(e.expires) {
		delete(c.entries, key)
		return nil
	}
	return e.payload
}

// Put 写入缓存。payload 会被调用方直接 writeJSON 序列化，之后不要再改。
func (c *usageReportCache) Put(key usageReportKey, payload map[string]any) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.max {
		// 仅新增条目才淘汰；先清过期报表，仍满时只丢最早到期的一条。
		var oldest usageReportKey
		var earliest time.Time
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
				continue
			}
			if earliest.IsZero() || e.expires.Before(earliest) {
				oldest, earliest = k, e.expires
			}
		}
		if len(c.entries) >= c.max {
			delete(c.entries, oldest)
		}
	}
	c.entries[key] = &usageReportEntry{
		expires: now.Add(c.ttl),
		payload: payload,
	}
}

// InvalidateUser 丢掉某用户的全部缓存（删用户时调用）。
func (c *usageReportCache) InvalidateUser(scope string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		if k.scope == scope {
			delete(c.entries, k)
		}
	}
}

// Flush 清空全部缓存（改价目时调用 —— 估算段的金额跟着单价走，所有用户都受影响）。
func (c *usageReportCache) Flush() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[usageReportKey]*usageReportEntry)
}

// Len 返回当前缓存条目数（观测用）。
func (c *usageReportCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
