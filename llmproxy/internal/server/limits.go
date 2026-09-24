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
//   - 那次装载的 DB 读**在锁外**做（见 ensureMonthLoaded）—— 否则持锁抢唯一那条
//     连接期间，所有用户的限流与配额判断全堵在后面，跨月瞬间就是一次集体停顿；
//   - 落库照旧走 usage_user_daily，内存计数只为快速判断。
//
// 两个刻意的取舍，都写在这里以免以后当成 bug：
//  1. 配额是**软限制**：判断发生在请求之前，并发请求最多可能超出「同时在飞」的那几条。
//  2. 重启后金额从库里重建，口径是**冻结优先**（rowCharge）：已冻结的请求用它当时
//     写死的金额，只有还没录价目的那部分才按 legacy 单价表估算兜底。所以改价不会
//     重写历史 —— 这与「读取时用当前价现算」的旧行为不同。
type meterSet struct {
	mu    sync.Mutex
	users map[string]*userMeter

	db    *store.Store
	price func() *config.PricingConfig
	now   func() time.Time
}

type userMeter struct {
	month    string
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
	m.ensureMonthLoaded(user) // 可能读库，必须在持锁之前做

	m.mu.Lock()
	defer m.mu.Unlock()

	um := m.meterForLocked(user)
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
			m.mu.Lock()
			if um.inflight > 0 {
				um.inflight--
			}
			m.mu.Unlock()
		})
	}, nil
}

// CheckQuota 判断当月配额是否已用尽。0 表示不限。
func (m *meterSet) CheckQuota(user string, quotaTokens int64, quotaCost float64) (usedTokens int64, usedCost float64, exceeded bool, msg string) {
	if user == "" || (quotaTokens <= 0 && quotaCost <= 0) {
		return 0, 0, false, ""
	}
	m.ensureMonthLoaded(user) // 可能读库，必须在持锁之前做

	m.mu.Lock()
	defer m.mu.Unlock()

	um := m.meterForLocked(user)
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

// Add 记一笔系统付费的消耗。
//
// upstreamModel 用来查单价；hit/miss 为 0 而 prompt>0 时按「输入全部未命中」计，
// 这是上游不回报缓存拆分时的保守口径 —— 宁可高估，不要漏计。
// Add 累加一次系统付费的消耗。
//
// frozen 是这次请求**冻结**的分发金额（nil = 没冻上，按 legacy 单价表估算兜底）。
// 两个口径都要能用：配额必须一直有效，不能因为"还没录价目"就整段失效；
// 而内存计数与跨月重载（meterForLocked 从库里读）必须用同一套口径，否则两边会对不上。
func (m *meterSet) Add(user, upstreamModel string, prompt, cacheHit, cacheMiss, output int64, at time.Time, frozen *float64) {
	if user == "" {
		return
	}
	if cacheHit+cacheMiss == 0 && prompt > 0 {
		cacheMiss = prompt
	}
	m.ensureMonthLoaded(user) // 可能读库，必须在持锁之前做

	m.mu.Lock()
	defer m.mu.Unlock()

	um := m.meterForLocked(user)
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
	m.ensureMonthLoaded(user) // 可能读库，必须在持锁之前做
	m.mu.Lock()
	defer m.mu.Unlock()
	um := m.meterForLocked(user)
	return um.tokens, um.cost
}

// Forget 丢弃某个用户的计数（删用户时调用，避免内存里留下幽灵）。
func (m *meterSet) Forget(user string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.users, user)
}

// meterForLocked 取当月计数桶。调用方必须持有 m.mu。
//
// 正常情况下桶已经由 ensureMonthLoaded 在**锁外**装载好了，这里只是取出来。
// 只有「ensureMonthLoaded 之后正好跨了月」这个极窄的窗口才会走到下面那条读库分支 ——
// 那时宁可在持锁状态下读一次，也不要建个空桶：空桶会被后续请求当成「本月已装载」
// 而再也不刷新，整月的配额都会少算。
func (m *meterSet) meterForLocked(user string) *userMeter {
	now := m.now()
	month := now.Format("2006-01")
	if um := m.users[user]; um != nil && um.month == month {
		return um
	}
	tokens, cost := m.loadMonth(user, now)
	um := &userMeter{month: month, tokens: tokens, cost: cost}
	m.users[user] = um
	return um
}

// loadMonth 从库里读出某用户当月的已用量。**不持锁** —— 见 ensureMonthLoaded。
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

// ensureMonthLoaded 确保 user 的当月计数桶已在内存里，必要时从库里装载。
//
// 装载分三步：持锁查一下 → 没有就**放锁**读库 → 重新持锁并复查。
//
// 为什么不能在持锁时读库：这条查询要抢唯一那条 SQLite 连接（store 是
// SetMaxOpenConns(1)），而抢连接期间 m.mu 一直被握着，于是**所有用户**的
// Acquire / CheckQuota / Add / Snapshot 全堵在后面。触发时机是「某用户当月首次
// 请求」和「跨月后的第一批请求」—— 后者会让所有活跃用户在跨月瞬间同时命中，
// 磁盘一慢就是整条请求路径的集体停顿。
//
// 复查是必须的：放锁期间别的协程可能已经把同一个用户的桶装载好、甚至累加过新请求了，
// 这时要用它那份，不能拿自己读到的旧值覆盖掉。
func (m *meterSet) ensureMonthLoaded(user string) {
	if user == "" {
		return
	}
	m.mu.Lock()
	now := m.now()
	month := now.Format("2006-01")
	if um := m.users[user]; um != nil && um.month == month {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	tokens, cost := m.loadMonth(user, now)

	m.mu.Lock()
	defer m.mu.Unlock()
	if um := m.users[user]; um != nil && um.month == month {
		return // 别人已经装载好了，用它那份
	}
	m.users[user] = &userMeter{month: month, tokens: tokens, cost: cost}
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
