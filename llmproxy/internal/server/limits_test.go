package server

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

func newTestMeterSet() *meterSet {
	return newMeterSet(nil, func() *config.PricingConfig { return nil })
}

// inflightOf 读某个用户当前占用的并发位（-1 = 还没有桶）。
func (m *meterSet) inflightOf(user string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if um := m.users[user]; um != nil {
		return um.inflight
	}
	return -1
}

// 释放并发位时要减**当初自增的那个桶**，不是「当前这个 user 名下的桶」。
//
// 桶是会被换掉的：跨月时 meterForLocked 建一个新的，删用户会触发 Forget。
// 按 user 重新查的话，这次释放就会去减**新桶**的 inflight —— 新桶凭空少一个计数，
// 并发上限被悄悄放松，而且从外面完全看不出来（要等到并发真的超限才发现）。
func TestAcquireReleaseDecrementsOriginalMeter(t *testing.T) {
	m := newTestMeterSet()

	release1, err := m.Acquire("alice", 0, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.inflightOf("alice"); got != 1 {
		t.Fatalf("占用后 inflight = %d, want 1", got)
	}

	// 把桶换掉：Forget 模拟删用户，下一次 Acquire 会建一个全新的桶
	m.Forget("alice")
	release2, err := m.Acquire("alice", 0, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.inflightOf("alice"); got != 1 {
		t.Fatalf("新桶占用后 inflight = %d, want 1", got)
	}

	// 旧桶的释放不该动新桶
	release1()
	if got := m.inflightOf("alice"); got != 1 {
		t.Errorf("释放旧桶之后新桶的 inflight = %d, want 1（被减掉就说明并发上限被悄悄放松了）", got)
	}

	release2()
	if got := m.inflightOf("alice"); got != 0 {
		t.Errorf("释放自己的桶之后 inflight = %d, want 0", got)
	}

	// release 幂等（sync.Once）：重复调用不该把计数减成负数
	release2()
	release2()
	if got := m.inflightOf("alice"); got != 0 {
		t.Errorf("重复释放后 inflight = %d, want 0", got)
	}
}

// 并发上限要真的挡住，而且释放之后要放出来。
func TestAcquireConcurrencyLimit(t *testing.T) {
	m := newTestMeterSet()
	var releases []func()
	for i := 0; i < 3; i++ {
		rel, err := m.Acquire("bob", 0, 3)
		if err != nil {
			t.Fatalf("第 %d 次占用不该被拒: %v", i, err)
		}
		releases = append(releases, rel)
	}
	if _, err := m.Acquire("bob", 0, 3); err == nil {
		t.Error("第 4 次应当被并发上限挡住")
	} else if le, ok := err.(*limitedError); !ok || le.kind != "concurrency_limited" {
		t.Errorf("应当是 concurrency_limited，实际 %v", err)
	}
	releases[0]()
	if _, err := m.Acquire("bob", 0, 3); err != nil {
		t.Errorf("释放一个之后应当能再占: %v", err)
	}
}

// 没配限流（rpm 与 maxConcurrent 都是 0）时不该建桶、也不该挡。
func TestAcquireNoLimitsIsNoop(t *testing.T) {
	m := newTestMeterSet()
	rel, err := m.Acquire("carol", 0, 0)
	if err != nil {
		t.Fatalf("不该被拒: %v", err)
	}
	rel()
	if got := m.inflightOf("carol"); got != -1 {
		t.Errorf("没配限流时不该建桶，实际 inflight=%d", got)
	}
	// 空用户名同样直接放过
	if _, err := m.Acquire("", 60, 8); err != nil {
		t.Errorf("空用户名不该被拒: %v", err)
	}
}

// 装载当月用量时的 DB 读必须在**锁外**做。
//
// 这条用一个会「顺手抢一次 m.mu」的 price 钩子来钉住：loadMonth 内部会调 m.price()，
// 所以装载如果是在持锁状态下做的，这里就会自锁死（sync.Mutex 不可重入）。
//
// 之所以要在意：这条查询要抢唯一那条 SQLite 连接（store 是 SetMaxOpenConns(1)），
// 持锁读库期间**所有用户**的 Acquire / CheckQuota / Add / Snapshot 全堵在后面。
// 触发时机是「某用户当月首次请求」与「跨月后的第一批请求」—— 后者会让所有活跃用户
// 在跨月瞬间同时命中，磁盘一慢就是整条请求路径的集体停顿。
func TestEnsureMonthLoadedDoesNotHoldLockWhileLoading(t *testing.T) {
	m := newTestMeterSet()
	deadlock := make(chan struct{})
	m.price = func() *config.PricingConfig {
		got := make(chan struct{})
		go func() {
			m.mu.Lock()
			m.mu.Unlock()
			close(got)
		}()
		select {
		case <-got:
		case <-time.After(2 * time.Second):
			close(deadlock) // 拿不到锁 = 装载是在持锁状态下做的
		}
		return nil
	}

	// 任一热路径都会触发装载：Snapshot 进 meterFor → loadMonthLocked
	m.Snapshot("dave")

	select {
	case <-deadlock:
		t.Fatal("装载当月用量时握着 m.mu —— 持锁读库会把所有用户的限流/配额判断堵在后面")
	default:
	}
	if got := m.inflightOf("dave"); got != 0 {
		t.Errorf("装载后应当有一个空的当月桶，实际 inflight=%d", got)
	}
}

// 跨月要换桶：上个月的计数不该带进新月。
func TestMeterRolloverOnNewMonth(t *testing.T) {
	m := newTestMeterSet()
	base := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	now := base
	m.now = func() time.Time { return now }

	m.Add("erin", "m", 1000, 0, 1000, 500, now, nil)
	if tok, _ := m.Snapshot("erin"); tok != 1500 {
		t.Fatalf("3 月用量 = %d, want 1500", tok)
	}

	now = time.Date(2026, 4, 1, 0, 30, 0, 0, time.UTC) // 跨到 4 月
	if tok, _ := m.Snapshot("erin"); tok != 0 {
		t.Errorf("跨月后应当从 0 开始，实际 %d", tok)
	}
	m.Add("erin", "m", 10, 0, 10, 5, now, nil)
	if tok, _ := m.Snapshot("erin"); tok != 15 {
		t.Errorf("4 月用量 = %d, want 15", tok)
	}
}

// 并发读写不能炸，也不能让 map 与桶失同步（-race 会抓住无保护的读写）。
// 刻意混进 Forget 来制造「桶被换掉」的情况。
func TestMeterSetConcurrent(t *testing.T) {
	m := newTestMeterSet()
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			user := fmt.Sprintf("u%d", g%4)
			for i := 0; i < 300; i++ {
				if rel, err := m.Acquire(user, 0, 64); err == nil {
					m.Add(user, "m", 10, 0, 10, 5, time.Now(), nil)
					m.CheckQuota(user, 1<<62, 0)
					m.Snapshot(user)
					rel()
				}
				if i%97 == 0 {
					m.Forget(user)
				}
			}
		}(g)
	}
	wg.Wait()

	// 所有并发位都该被释放干净
	for u := 0; u < 4; u++ {
		user := fmt.Sprintf("u%d", u)
		if got := m.inflightOf(user); got > 0 {
			t.Errorf("%s 结束后仍占着 %d 个并发位（释放泄漏）", user, got)
		}
	}
}
