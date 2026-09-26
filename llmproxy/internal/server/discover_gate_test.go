package server

import (
	"fmt"
	"testing"
	"time"
)

// /discover 闸门：全局并发与单用户频率都要钉住，否则用户侧探测就是免费内网扫描器。
func TestDiscoverGateRateAndConcurrency(t *testing.T) {
	g := newDiscoverGate()
	fixed := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	g.nowFn = func() time.Time { return fixed }

	// 单用户频率：每次占完立刻放，避免和全局并发上限搅在一起
	for i := 0; i < discoverPerUserPerMin; i++ {
		rel, err := g.Acquire("alice")
		if err != nil {
			t.Fatalf("第 %d 次应当放行: %v", i+1, err)
		}
		rel()
	}
	if _, err := g.Acquire("alice"); err == nil {
		t.Error("超出每分钟上限后应当被拒")
	}
	// 另一个用户不受影响
	rel, err := g.Acquire("bob")
	if err != nil {
		t.Fatalf("别的用户不该被牵连: %v", err)
	}
	rel()

	// 跨分钟后计数归零
	g.nowFn = func() time.Time { return fixed.Add(time.Minute) }
	rel2, err := g.Acquire("alice")
	if err != nil {
		t.Fatalf("新的分钟窗口应当放行: %v", err)
	}
	rel2()

	// 全局并发：占满 discoverMaxConcurrent 个且不释放，下一个必须被拒
	g2 := newDiscoverGate()
	held := make([]func(), 0, discoverMaxConcurrent)
	for i := 0; i < discoverMaxConcurrent; i++ {
		rel, err := g2.Acquire("u")
		if err != nil {
			t.Fatalf("并发 %d/%d 应当放行: %v", i+1, discoverMaxConcurrent, err)
		}
		held = append(held, rel)
	}
	if _, err := g2.Acquire("other"); err == nil {
		t.Error("全局并发占满后应当被拒")
	}
	// 释放一个就又能进
	held[0]()
	rel, err = g2.Acquire("other")
	if err != nil {
		t.Fatalf("释放一个位之后应当放行: %v", err)
	}
	rel()
}

// 闸门被拒时不得漏掉并发位：频率超限发生在占到信号量之后，必须原样还回去，
// 否则一次超频就永久吃掉一个槽，攒几次就把 /discover 整个卡死。
func TestDiscoverGateRejectDoesNotLeakSlot(t *testing.T) {
	g := newDiscoverGate()
	fixed := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	g.nowFn = func() time.Time { return fixed }

	for i := 0; i < discoverPerUserPerMin; i++ {
		rel, err := g.Acquire("carol")
		if err != nil {
			t.Fatal(err)
		}
		rel()
	}
	rel, err := g.Acquire("carol")
	if err == nil {
		t.Fatal("超频应当被拒")
	}
	rel() // 失败路径的 release 是 no-op

	// 超频之后全局并发位必须还是满额可用 —— 漏一个这里就会少一个
	for i := 0; i < discoverMaxConcurrent; i++ {
		rel, err := g.Acquire(fmt.Sprintf("u%d", i)) // 别的用户，只撞全局并发
		if err != nil {
			t.Fatalf("超频之后并发位 %d/%d 应当还在: %v", i+1, discoverMaxConcurrent, err)
		}
		defer rel()
	}
	if _, err := g.Acquire("z"); err == nil {
		t.Error("占满后下一个应当被拒（证明上面确实占到了全部槽位）")
	}
}
