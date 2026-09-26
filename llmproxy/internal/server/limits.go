package server

import (
	"fmt"
	"sync"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// 消费模式的运行时状态：当月用量计数 + 限流。
//
// 为什么放在内存里：配额判断在请求路径上，而 usage_user_daily 走的是单连接 SQLite
// （SetMaxOpenConns(1)），每请求查一次库会把网关的吞吐直接压到那条连接上。
// 所以：
//   - 计数在内存累加，只在「当月首次用到某个用户」时从库里装载一次；
//   - 那次装载的 DB 读**在任何锁外**做（见 ensureMonthLoaded）—— 否则持锁抢唯一那条
//     连接期间，所有用户的限流与配额判断全堵在后面，跨月瞬间就是一次集体停顿；
//   - 落库照旧走 usage_user_daily，内存计数只为快速判断。
//
// 锁的两层，是为了别让 A 用户的请求把 B 用户的限流也堵住：
//   - meterSet.mu（RWMutex）只护 map 的读写，临界区里不碰计数、更不读库；
//   - 每个 userMeter 自带一把锁，护 tokens/cost/inflight/令牌桶。
//
// 以前整张表一把互斥锁，高并发多用户时 Acquire/CheckQuota/Add 全串行。
//
// 两个刻意的取舍，都写在这里以免以后当成 bug：
//  1. 配额是**软限制**：判断发生在请求之前，并发请求最多可能超出「同时在飞」的那几条。
//  2. 重启后金额从库里重建，口径是**冻结优先**（store.RowCharge）：已冻结的请求用它当时
//     写死的金额，只有还没录价目的那部分才按 legacy 单价表估算兜底。所以改价不会
//     重写历史 —— 这与「读取时用当前价现算」的旧行为不同。
type meterSet struct {
	mu    sync.RWMutex
	users map[string]*userMeter

	db    *store.Store
	price func() *config.PricingConfig
	now   func() time.Time
}

// userMeter 是一个用户当月的计数桶。字段由 mu 保护（meterSet.mu 只护 map）。
type userMeter struct {
	mu       sync.Mutex
	user     string
	month    string
	loaded   bool // 是否已从库里装载过当月基数（meterFor 建的空壳为 false）
	tokens   int64
	cost     float64
	inflight int
	bucket   *tokenBucket
}

func newMeterSet(db *store.Store, price func() *config.PricingConfig) *meterSet {
	return &meterSet{users: map[string]*userMeter{}, db: db, price: price, now: time.Now}
}

// limitedError 表示被限流拒绝，带上给客户端看的话术。
type limitedError struct {
	status int
	kind   string
	msg    string
}

func (e *limitedError) Error() string { return e.msg }

// Acquire 做速率与并发检查，通过则占一个并发位。
// 返回的 release 必须调用（用 defer），否则并发位会泄漏。
func (m *meterSet) Acquire(user string, rpm, maxConcurrent int) (func(), error) {
	if user == "" || (rpm <= 0 && maxConcurrent <= 0) {
		return func() {}, nil
	}
	um := m.meterFor(user)
	um.mu.Lock()
	defer um.mu.Unlock()
	m.loadMonthLocked(um)

	if rpm > 0 {
		if um.bucket == nil || um.bucket.capacity != bucketCapacity(rpm) {
			um.bucket = newTokenBucket(rpm, m.now())
		}
		if !um.bucket.allow(m.now()) {
			return nil, &limitedError{
				status: 429, kind: "rate_limited",
				msg: fmt.Sprintf("请求过于频繁（上限 %d 次/分钟），请稍后再试", rpm),
			}
		}
	}
	if maxConcurrent > 0 && um.inflight >= maxConcurrent {
		return nil, &limitedError{
			status: 429, kind: "concurrency_limited",
			msg: fmt.Sprintf("同时进行的请求已达上限（%d），请等前面的请求结束", maxConcurrent),
		}
	}
	um.inflight++

	var once sync.Once
	// 闭包捕获 **um 指针**而不是 user 字符串：释放时要减的必须是当初自增的那个桶。
	// 按 user 重新查的话，如果中途桶被换掉了（跨月、或删用户触发 Forget），
	// 这次释放就会去减**另一个**桶的 inflight —— 新桶凭空少一个计数，
	// 并发上限被悄悄放松，而且看不出来。
	return func() {
		once.Do(func() {
			um.mu.Lock()
			if um.inflight > 0 {
				um.inflight--
			}
			um.mu.Unlock()
		})
	}, nil
}

// CheckQuota 判断当月配额是否已用尽。0 表示不限。
func (m *meterSet) CheckQuota(user string, quotaTokens int64, quotaCost float64) (usedTokens int64, usedCost float64, exceeded bool, msg string) {
	if user == "" || (quotaTokens <= 0 && quotaCost <= 0) {
		return 0, 0, false, ""
	}
	um := m.meterFor(user)
	um.mu.Lock()
	defer um.mu.Unlock()
	m.loadMonthLocked(um)

	if quotaTokens > 0 && um.tokens >= quotaTokens {
		return um.tokens, um.cost, true, fmt.Sprintf(
			"本月 token 配额已用完（已用 %d / %d），下个自然月自动恢复", um.tokens, quotaTokens)
	}
	if quotaCost > 0 && um.cost >= quotaCost {
		return um.tokens, um.cost, true, fmt.Sprintf(
			"本月金额配额已用完（已用 %.2f / %.2f），下个自然月自动恢复", um.cost, quotaCost)
	}
	return um.tokens, um.cost, false, ""
}

// Add 累加一次系统付费的消耗。
//
// frozen 是这次请求**冻结**的分发金额（nil = 没冻上，按 legacy 单价表估算兜底）。
// 两个口径都要能用：配额必须一直有效，不能因为"还没录价目"就整段失效；
// 而内存计数与跨月重载（loadMonth 从库里读）必须用同一套口径，否则两边会对不上。
func (m *meterSet) Add(user, upstreamModel string, prompt, cacheHit, cacheMiss, output int64, at time.Time, frozen *float64) {
	if user == "" {
		return
	}
	if cacheHit+cacheMiss == 0 && prompt > 0 {
		cacheMiss = prompt
	}
	um := m.meterFor(user)
	um.mu.Lock()
	defer um.mu.Unlock()
	m.loadMonthLocked(um)

	um.tokens += prompt + output
	if frozen != nil {
		um.cost += *frozen
		return
	}
	if p := m.price(); p.Enabled() {
		if c, ok := p.Cost(upstreamModel, cacheHit, cacheMiss, output, at); ok {
			um.cost += c
		}
	}
}

// Snapshot 返回该用户当月已用量（会按需从库里装载）。
func (m *meterSet) Snapshot(user string) (tokens int64, cost float64) {
	if user == "" {
		return 0, 0
	}
	um := m.meterFor(user)
	um.mu.Lock()
	defer um.mu.Unlock()
	m.loadMonthLocked(um)
	return um.tokens, um.cost
}

// Forget 丢弃某个用户的计数（删用户时调用，避免内存里留下幽灵）。
func (m *meterSet) Forget(user string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.users, user)
}

// meterFor 取（或建）当月计数桶。只碰 map，**不读库** ——
// 持 map 锁抢 SQLite 唯一连接，就是全用户停顿。
func (m *meterSet) meterFor(user string) *userMeter {
	month := m.now().Format("2006-01")

	m.mu.RLock()
	um := m.users[user]
	m.mu.RUnlock()
	if um != nil && um.month == month {
		return um
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if um := m.users[user]; um != nil && um.month == month {
		return um
	}
	fresh := &userMeter{user: user, month: month}
	m.users[user] = fresh
	return fresh
}

// loadMonthLocked 在**已持有 um.mu** 的前提下，按需把当月基数从库里装载进来。
//
// 读库发生在 um.mu 里而不是 meterSet.mu 里：只会挡住这一个用户的并发请求，
// 别人的限流/配额判断照常走。触发时机是「该用户当月首次请求」与「跨月后首个请求」，
// 装载完 loaded=true，同一桶内再进来就走纯内存。
func (m *meterSet) loadMonthLocked(um *userMeter) {
	if um.loaded {
		return
	}
	tokens, cost := m.loadMonth(um.user, m.now())
	um.tokens += tokens
	um.cost += cost
	um.loaded = true
}

// loadMonth 从库里读出某用户当月的已用量。
func (m *meterSet) loadMonth(user string, now time.Time) (tokens int64, cost float64) {
	if m.db == nil {
		return 0, 0
	}
	rows, err := m.db.SystemUsageRowsSince(user, store.MonthStart(now))
	if err != nil {
		return 0, 0
	}
	// 逐条按各自的上游模型定价：不同模型单价不同，先汇总再定价会算错
	p := m.price()
	for _, r := range rows {
		tokens += r.PromptTokens + r.CompletionTokens
		cost += rowCharge(r, p, now)
	}
	return tokens, cost
}

// ------------------------------------------------------------------ 令牌桶

// 速率用桶来实现：容量是整个一分钟的量会太松（开局就能打满一分钟），
// 所以容量取 10 秒的量，等于允许短促突发、但不允许持续打满。
func bucketCapacity(rpm int) float64 {
	c := float64(rpm) / 6
	if c < 1 {
		c = 1
	}
	return c
}

type tokenBucket struct {
	capacity float64
	rate     float64 // 每秒补充
	tokens   float64
	last     time.Time
}

func newTokenBucket(rpm int, now time.Time) *tokenBucket {
	cap := bucketCapacity(rpm)
	return &tokenBucket{
		capacity: cap,
		rate:     float64(rpm) / 60,
		tokens:   cap, // 起步给满，避免刚上线就被自己的限流挡住
		last:     now,
	}
}

func (b *tokenBucket) allow(now time.Time) bool {
	if now.After(b.last) {
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
