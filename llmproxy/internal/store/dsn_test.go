package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// 连接级参数必须对**每一条**连接生效，而不只是对跑过 schema 的那一条。
//
// busy_timeout 与 synchronous 是每连接属性（只有 journal_mode=WAL 写进库文件头是持久的）。
// 把它们写在 schema 的 PRAGMA 里，只在「池里恰好只有一条永不回收的连接」时成立；
// 驱动一旦因 I/O 错误丢弃并重开连接（driver.ErrBadConn），新连接就静默降级成
// busy_timeout=0 + synchronous=FULL，而且没有任何日志。所以它们走 DSN —— 这条测试钉住结果。
func TestOpenAppliesConnectionPragmas(t *testing.T) {
	s := openTestStore(t)

	var busyTimeout, journalMode, synchronous string
	if err := s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`PRAGMA synchronous`).Scan(&synchronous); err != nil {
		t.Fatal(err)
	}
	if busyTimeout != "5000" {
		t.Errorf("busy_timeout = %s, want 5000（CLI 与服务端并发写要靠它等待，而不是立刻 SQLITE_BUSY）", busyTimeout)
	}
	if journalMode != "wal" {
		t.Errorf("journal_mode = %s, want wal", journalMode)
	}
	if synchronous != "1" {
		t.Errorf("synchronous = %s, want 1/NORMAL（2/FULL 会让每次 commit 都 fsync，吞吐掉一个量级）", synchronous)
	}
}

// DSN 用 file: URI 形式，路径部分由 url.URL 转义。
//
// 「裸路径 + ?query」的形式下，驱动按第一个 '?' 切分 DSN —— 路径里真带 '?' 就会切错，
// 把库建到别的地方去（而且是静默的：Open 照样成功）。这三种路径都验证过能落在预期位置。
func TestOpenHandlesAwkwardPaths(t *testing.T) {
	for _, name := range []string{"plain.db", "with space.db", "with?question.db", "with#hash.db"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			s, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer s.Close()

			// 库文件必须真的落在预期路径上，而不是被 URI 解析跑偏。
			// 注意不能用 filepath.Glob 判存在：'?' 与 '#' 在 glob 里是元字符，
			// 而这个测试恰恰要覆盖带这些字符的路径。
			if _, err := os.Stat(path); err != nil {
				t.Errorf("数据库文件没落在 %q: %v", path, err)
			}
			// 并且确实可写
			if err := s.SaveProviderStatus([]ProviderStatus{
				{Name: "p", Enabled: true, TotalRequests: 1},
			}); err != nil {
				t.Errorf("写不进去: %v", err)
			}
		})
	}
}

// _txlock=immediate 的意义：SQLite 的 busy_timeout **不覆盖**「deferred 事务内读锁升级成
// 写锁」—— 那种冲突会立刻返回 SQLITE_BUSY / SQLITE_BUSY_SNAPSHOT 而不是等待
// （这是 SQLite 刻意的防死锁设计）。价目收口与用户上游 upsert 都是「先 SELECT 再 UPDATE」，
// 所以 CLI 与服务端并发时会随机报 database is locked，而全代码库没有任何 BUSY 重试。
// 让事务一开头就拿写锁，就落回 busy_timeout 的等待路径。
//
// 这里用两个独立的 *Store（= 两条独立连接，等价于 CLI 与服务端两个进程的形状）对撞。
// 每条事务写**不同**的 (provider, model)，所以冲突只可能来自写锁本身，
// 不会与「同一价目只追加」的业务规则搅在一起。
func TestConcurrentPriceInsertsAcrossConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.db")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	// valid_from 必须是整点，否则被校验拒掉 —— 那是另一条规则，不该混进这个测试
	from := time.Now().UTC().Truncate(time.Hour)

	const perConn = 40
	var wg sync.WaitGroup
	errs := make(chan error, 2*perConn)
	for ci, s := range []*Store{a, b} {
		for i := 0; i < perConn; i++ {
			wg.Add(1)
			go func(s *Store, model string) {
				defer wg.Done()
				p := ProviderPrice{
					Provider: "p", UpstreamModel: model,
					ValidFrom: from, Out: 1, Currency: "CNY",
				}
				if err := s.InsertProviderPrice(&p); err != nil {
					errs <- err
				}
			}(s, fmt.Sprintf("m-%d-%d", ci, i))
		}
	}
	wg.Wait()
	close(errs)

	var failed int
	for err := range errs {
		failed++
		if failed <= 5 {
			t.Errorf("并发录价失败: %v", err)
		}
	}
	if failed > 5 {
		t.Errorf("（另有 %d 条同类失败省略）", failed-5)
	}
}
