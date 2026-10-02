package server

import (
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 用量报表缓存：命中后不再打库；过期后重新计算；改价/删用户能清掉。
// 缓存键是 (范围, 天数)：范围用 policy.ScopeRef 原形当键，
// 不经过 Display() 串 —— 那是 §2.7 规则 1 禁止的「折成单一字符串」形式。
func TestUsageReportCacheTTLAndInvalidate(t *testing.T) {
	c := newUsageReportCache()
	fixed := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return fixed }
	c.ttl = 5 * time.Second

	alice := policy.MustScope(policy.ScopeUser, "alice")
	key := usageReportKey{scope: alice, days: 7}
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

	// 按范围失效
	c.now = func() time.Time { return fixed }
	c.Put(key, payload)
	bob := policy.MustScope(policy.ScopeUser, "bob")
	c.Put(usageReportKey{scope: bob, days: 7}, map[string]any{"days": 7})
	c.InvalidateScope(alice)
	if c.Get(key) != nil {
		t.Error("InvalidateScope 应当清掉 alice 的条目")
	}
	if c.Get(usageReportKey{scope: bob, days: 7}) == nil {
		t.Error("不该误删别的范围")
	}

	// 零范围是拒绝，不是「清全部」：它匹配不上任何写入过的条目，
	// 按零值遍历删除等于给「归属不明」开一条批量清理路径。
	c.Put(usageReportKey{scope: bob, days: 7}, map[string]any{"days": 7})
	c.InvalidateScope(policy.ScopeRef{})
	if c.Get(usageReportKey{scope: bob, days: 7}) == nil {
		t.Error("零范围的失效不该动任何条目")
	}

	// 全清
	c.Flush()
	if c.Get(usageReportKey{scope: bob, days: 7}) != nil {
		t.Error("Flush 之后应当全空")
	}

	// nil 接收者安全
	var nilCache *usageReportCache
	if nilCache.Get(key) != nil {
		t.Error("nil 缓存 Get 应当返回 nil")
	}
	nilCache.Put(key, payload)
	nilCache.InvalidateScope(policy.MustScope(policy.ScopeUser, "alice"))
	nilCache.Flush()
}

func TestUsageReportCacheUpdateDoesNotEvictOtherEntries(t *testing.T) {
	c := newUsageReportCache()
	c.max = 2
	keyA := usageReportKey{scope: policy.MustScope(policy.ScopeUser, "a"), days: 7}
	keyB := usageReportKey{scope: policy.MustScope(policy.ScopeProject, "b"), days: 7}
	c.Put(keyA, map[string]any{"v": 1})
	c.Put(keyB, map[string]any{"v": 2})
	c.Put(keyA, map[string]any{"v": 3})
	if got := c.Get(keyB); got == nil || got["v"] != 2 {
		t.Fatalf("更新已有条目不应清掉其它条目，got=%v", got)
	}
	if got := c.Get(keyA); got == nil || got["v"] != 3 {
		t.Fatalf("更新后的条目未生效，got=%v", got)
	}
}
