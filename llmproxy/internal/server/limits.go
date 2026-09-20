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
//   - 落库照旧走 usage_user_daily，内存计数只为快速判断。
//
// 两个刻意的取舍，都写在这里以免以后当成 bug：
//  1. 配额是**软限制**：判断发生在请求之前，并发请求最多可能超出「同时在飞」的那几条。
//  2. 重启后金额按当时的单价从库里重算一遍；如果中途改过价，计数会与新单价对齐，
//     而不是保留历史价。要精确到分就不是估算，那是支付系统的活。
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
	m.mu.Lock()
	defer m.mu.Unlock()

	um := m.meterForLocked(user, rpm)
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
	return func() {
		once.Do(func() {
			m.mu.Lock()
			if cur := m.users[user]; cur != nil && cur.inflight > 0 {
				cur.inflight--
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
	m.mu.Lock()
	defer m.mu.Unlock()

	um := m.meterForLocked(user, 0)
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
func (m *meterSet) Add(user, upstreamModel string, prompt, cacheHit, cacheMiss, output int64, at time.Time) {
	if user == "" {
		return
	}
	if cacheHit+cacheMiss == 0 && prompt > 0 {
		cacheMiss = prompt
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	um := m.meterForLocked(user, 0)
	um.tokens += prompt + output
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
	m.mu.Lock()
	defer m.mu.Unlock()
	um := m.meterForLocked(user, 0)
	return um.tokens, um.cost
}

// Forget 丢弃某个用户的计数（删用户时调用，避免内存里留下幽灵）。
func (m *meterSet) Forget(user string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.users, user)
}

// meterForLocked 取当月计数桶；跨月或首次使用时装载。调用方必须持有 m.mu。
func (m *meterSet) meterForLocked(user string, rpm int) *userMeter {
	now := m.now()
	month := now.Format("2006-01")
	if um := m.users[user]; um != nil && um.month == month {
		return um
	}

	um := &userMeter{month: month}
	if m.db != nil {
		// 逐条按各自的上游模型定价：不同模型单价不同，先汇总再定价会算错
		if rows, err := m.db.SystemUsageRowsSince(user, store.MonthStart(now)); err == nil {
			p := m.price()
			for _, r := range rows {
				um.tokens += r.PromptTokens + r.CompletionTokens
				hit, miss := r.CacheHitTokens, r.CacheMissTokens
				if hit+miss == 0 && r.PromptTokens > 0 {
					miss = r.PromptTokens
				}
				if p.Enabled() {
					if c, ok := p.Cost(r.UpstreamModel, hit, miss, r.CompletionTokens, now); ok {
						um.cost += c
					}
				}
			}
		}
	}
	m.users[user] = um
	return um
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
