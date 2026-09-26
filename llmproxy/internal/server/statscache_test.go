package server

import (
	"testing"
	"time"
)

// 用量报表缓存：命中后不再打库；过期后重新计算；改价/删用户能清掉。
func TestUsageReportCacheTTLAndInvalidate(t *testing.T) {
	c := newUsageReportCache()
	fixed := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return fixed }
	c.ttl = 5 * time.Second

	key := usageReportKey{scope: "alice", days: 7}
	payload := map[string]any{"days": 7, "totals": "v1"}
	c.Put(key, payload)

	if got := c.Get(key); got == nil {
		t.Fatal("未过期应当命中")
	}

	// 过期
	c.now = func() time.Time { return fixed.Add(6 * time.Second) }
	if got := c.Get(key); got != nil {
		t.Error("过期后不该命中")
	}

	// 按用户失效
	c.now = func() time.Time { return fixed }
	c.Put(key, payload)
	c.Put(usageReportKey{scope: "bob", days: 7}, map[string]any{"days": 7})
	c.InvalidateUser("alice")
	if c.Get(key) != nil {
		t.Error("InvalidateUser 应当清掉 alice 的条目")
	}
	if c.Get(usageReportKey{scope: "bob", days: 7}) == nil {
		t.Error("不该误删别的用户")
	}

	// 全清
	c.Flush()
	if c.Get(usageReportKey{scope: "bob", days: 7}) != nil {
		t.Error("Flush 之后应当全空")
	}

	// nil 接收者安全
	var nilCache *usageReportCache
	if nilCache.Get(key) != nil {
		t.Error("nil 缓存 Get 应当返回 nil")
	}
	nilCache.Put(key, payload)
	nilCache.InvalidateUser("alice")
	nilCache.Flush()
}
