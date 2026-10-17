package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

// TestTokenRateLimit 60 秒窗口：窗口内烧满就拒，窗口翻篇后放行。
func TestTokenRateLimit(t *testing.T) {
	m := newMeterSet(nil, func() *config.PricingConfig { return &config.PricingConfig{} })
	now := time.Now()
	m.now = func() time.Time { return now }

	rel, err := m.Acquire("alice", 0, 0, 100)
	if err != nil {
		t.Fatalf("第一次不该被拒: %v", err)
	}
	rel()
	m.Add("alice", "m", 60, 0, 0, 40, now, nil) // 窗口内 100 token，正好打满

	if _, err := m.Acquire("alice", 0, 0, 100); err == nil {
		t.Fatal("窗口内已满应拒新请求")
	} else if le, ok := err.(*limitedError); !ok || le.kind != "token_rate_limited" {
		t.Fatalf("失败类型不对: %v", err)
	}

	// 窗口翻篇（>60s）后放行
	now = now.Add(61 * time.Second)
	if _, err := m.Acquire("alice", 0, 0, 100); err != nil {
		t.Fatalf("窗口翻篇后不该拒: %v", err)
	}
}

// TestTokenRateLimitUnlimited tokensPerMin=0 完全不设门。
func TestTokenRateLimitUnlimited(t *testing.T) {
	m := newMeterSet(nil, func() *config.PricingConfig { return &config.PricingConfig{} })
	m.Add("alice", "m", 1_000_000, 0, 0, 1_000_000, time.Now(), nil)
	for i := 0; i < 5; i++ {
		rel, err := m.Acquire("alice", 0, 0, 0)
		if err != nil {
			t.Fatalf("不限时不该拒: %v", err)
		}
		rel()
	}
}

// TestProviderSlots 排队不丢：满员时排队等槽，ctx 到期报错；释放后能续用。
func TestProviderSlots(t *testing.T) {
	slots := newProviderSlots()
	p := &config.Provider{Name: "up", MaxConcurrent: 1}

	r1, err := slots.acquire(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	// 满员 + 短期限 → 报错（不静默换家）
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := slots.acquire(ctx, p); err == nil {
		t.Fatal("满员时应等到期限并报错")
	}
	// 释放后能再拿
	r1()
	r2, err := slots.acquire(context.Background(), p)
	if err != nil {
		t.Fatalf("释放后应能再拿: %v", err)
	}
	r2()

	// 不限的供应商不占槽
	p2 := &config.Provider{Name: "free"}
	for i := 0; i < 10; i++ {
		rel, err := slots.acquire(context.Background(), p2)
		if err != nil {
			t.Fatal(err)
		}
		rel()
	}
}

// TestProviderSlotsCapChange 帽改了换新通道：旧通道持有者归还到旧通道，新请求按新帽走。
func TestProviderSlotsCapChange(t *testing.T) {
	slots := newProviderSlots()
	p := &config.Provider{Name: "up", MaxConcurrent: 1}
	r1, err := slots.acquire(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	p2 := &config.Provider{Name: "up", MaxConcurrent: 3}
	// 新帽下并发 2 个都该拿得到（旧的那 1 个还在旧通道上占着）
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := slots.acquire(context.Background(), p2)
			if err == nil {
				rel()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("新帽下不该排队失败: %v", err)
		}
	}
	r1() // 归还到旧通道，不许崩
}
