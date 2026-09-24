package server

import (
	"fmt"
	"sync"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// 并发建用户 + 并发重建快照的冒烟测试（配合 -race 跑）。
//
// **这条测试不声称能抓住 buildRegistry 里 rev 读取顺序那个竞态** —— 那个窗口
// （ListUsers 返回到 Revision 调用之间）太窄，撞不上；我试过写一个"确定性"版本，
// 把修复回退之后它照样通过，那种测试只会制造假信心，所以删了。
// rev 顺序的正确性靠代码里的注释与推理保证：先读 rev 时，并发写只会让 reg.rev 偏小，
// 下一轮 2 秒轮询必然发现不一致并重建 —— 失败方向是安全的。
//
// 这条测试真正覆盖的是：多个 goroutine 同时写库、同时调 SyncUsersIfChanged 时，
// 快照的 atomic.Value 读写、map 构建、以及逐条 AES-GCM 解密没有数据竞争，
// 并且最终所有用户都可见。
func TestSyncUsersUnderConcurrentWrites(t *testing.T) {
	h := newMUHarness(t)

	const creators = 40
	var wg sync.WaitGroup

	for i := 0; i < creators; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("u%02d", i)
			if err := h.db.CreateUser(name, store.TokenHash("sk-"+name)); err != nil {
				t.Errorf("CreateUser(%s): %v", name, err)
			}
		}(i)
	}
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 80; k++ {
				h.srv.SyncUsersIfChanged()
			}
		}()
	}
	wg.Wait()

	// 写全部结束后再同步一次，所有用户都必须可见
	h.srv.SyncUsersIfChanged()
	snap := h.srv.usersSnapshot()
	var missing []string
	for i := 0; i < creators; i++ {
		name := fmt.Sprintf("u%02d", i)
		if _, ok := snap.byName[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("同步后仍有 %d/%d 个用户不可见: %v", len(missing), creators, missing)
	}
}
