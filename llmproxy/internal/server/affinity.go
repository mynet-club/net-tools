package server

import (
	"sync"
	"time"
)

// affinityKey 是会话粘性的键，必须带上两个维度：
//
//   - **用户**（scope）：会话 id 是下游生成的，不按用户隔离的话，两个用户的同名会话
//     会互相把对方引到一个不属于自己的后端上 —— 多用户共享同一个系统上游账号时尤其危险。
//   - **模型**：上游的前缀缓存本来就是按（上游账号 + 模型）分区的，而一个会话往往
//     会调多个模型（MiMo 有 model / small_model / vision_model）。只按会话记的话，
//     调完模型 A 再调模型 B 会把这条记录改写掉，回头调 A 时 prefer 已经指着一家
//     不承接它的供应商 —— 于是每次换模型都要漂移一次，缓存照样被拆。
type affinityKey struct {
	scope   string // "" = 全局作用域（静态 key / 单用户时代），否则是用户名
	session string
	model   string
}

type affinityEntry struct {
	provider string
	lastUsed time.Time
}

// affinityStore 记住「某个会话的某个模型上次用的是哪家供应商」，
// 用来把一段对话钉在同一个后端。
//
// 目的不是负载均衡，而是**保住上游的前缀缓存**：缓存按（上游账号 + 模型）分区，
// 换一次家就等于从冷缓存重来 —— 实测命中与未命中的输入价差着几十倍。
//
// 两条约束：
//   - 会过期：超过 ttl 没动静的条目当作「没粘过」。清理是**懒**的 ——
//     在 Get 命中那条 key、或某次 Set 把容量推过 max 时才删；内存始终被 max 钉死。
//   - 有容量上限：超了先清已过期的，还不够就丢最久没用过的（近似 LRU）。
//
// 刻意不持久化：重启后粘性全丢，代价只是每个活跃会话迁移一次（一轮缓存）；
// 换来的好处是每次请求都不用落盘 —— 为一个"省一次换家"的优化去写库，不值。
//
// ttl <= 0 表示整体关闭：Get 一律返回空、Set 不记（读作"没有粘性"）。
type affinityStore struct {
	mu      sync.Mutex
	entries map[affinityKey]affinityEntry
	ttl     time.Duration
	max     int
	now     func() time.Time
}

const defaultAffinityMax = 8192

// defaultAffinityTTL 是粘性默认保留多久。
//
// 取得长，是因为会话可能隔夜还在继续，而上游的前缀缓存通常也活那么久 ——
// 粘性过期太早等于每个回合边界都换一次家，缓存照样保不住。
// 条目本身很小且有 max 钉死内存，留久不会有额外成本：过期条目即便留着，
// 也只是被路由忽略（那家不在候选里就不生效）。
// 可配置项（开关 / TTL）留到 T40。
const defaultAffinityTTL = 24 * time.Hour

// maxAffinityPartLen 是粘性键每一项（会话 id、模型名）的长度上限。
//
// 这两项都是**客户端发来的**（`x-session-affinity` 请求头、请求体里的 model），
// 内容不受我们控制：不设上限的话，每个请求带上一个 1MB 的值，容量上限那 8192 条
// 能吃掉好几 GB —— 这是 DoS 路径。超长的值一律当作「没有粘性」：粘性只是个提示，
// 丢掉它只是多一次缓存失效，而悄悄截断会把两个不同的会话/模型并到一起。
// 正常的会话 id 形如 `ses_` + 26 个字符，模型名也远不到这个量级，128 字节余量充足。
const maxAffinityPartLen = 128

func newAffinityStore(ttl time.Duration, max int) *affinityStore {
	if max <= 0 {
		max = defaultAffinityMax
	}
	return &affinityStore{
		entries: make(map[affinityKey]affinityEntry),
		ttl:     ttl,
		max:     max,
		now:     time.Now,
	}
}

// Get 返回该会话该模型上次用的供应商；没粘过、已过期、或功能关闭时返回空串。
// 命中会刷新「最近使用」，让淘汰更接近真 LRU。
func (s *affinityStore) Get(scope, session, model string) string {
	if !affinityPartOK(session) || !affinityPartOK(model) || s == nil || s.ttl <= 0 {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := affinityKey{scope: scope, session: session, model: model}
	e, ok := s.entries[k]
	if !ok {
		return ""
	}
	if s.expired(e) {
		delete(s.entries, k)
		return ""
	}
	e.lastUsed = s.now()
	s.entries[k] = e
	return e.provider
}

// Set 记录该会话该模型这次用的是哪家。provider 为空表示"忘掉它"
// （例如那家已经不再承接这个模型）。
func (s *affinityStore) Set(scope, session, model, provider string) {
	if !affinityPartOK(session) || !affinityPartOK(model) || s == nil || s.ttl <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := affinityKey{scope: scope, session: session, model: model}
	if provider == "" {
		delete(s.entries, k)
		return
	}
	s.entries[k] = affinityEntry{provider: provider, lastUsed: s.now()}
	s.evictLocked()
}

// Len 是当前记着的会话×模型条目数（观测/测试用）。
func (s *affinityStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Enabled 报告粘性是否开着（ttl <= 0 表示整体关闭）。转发路径用它决定
// 要不要读头、要不要写观测字段 —— 关着时应当完全不可见，而不是留一条
// 永远是 new 的观测头来混淆排障。
func (s *affinityStore) Enabled() bool {
	return s != nil && s.ttl > 0
}

// affinityPartOK 判断粘性键里的一项是否可用：非空且不超过长度上限。
// 超长或为空都当作「没有粘性」。
func affinityPartOK(v string) bool {
	return v != "" && len(v) <= maxAffinityPartLen
}

func (s *affinityStore) expired(e affinityEntry) bool {
	return s.now().Sub(e.lastUsed) >= s.ttl
}

// evictLocked 把表压回上限以内。先清已过期的（它们本来就该走了），
// 再不够就丢最久没用过的。调用方须持锁。
//
// 注意这是懒清理：只在 Set 时进来，且低于上限直接返回。所以「过期且再没被访问」
// 的条目可能在表里留很久 —— 内存仍被 max 钉死，不是泄漏。
func (s *affinityStore) evictLocked() {
	if len(s.entries) <= s.max {
		return
	}
	for k, e := range s.entries {
		if s.expired(e) {
			delete(s.entries, k)
		}
	}
	for len(s.entries) > s.max {
		var (
			oldestKey affinityKey
			oldest    time.Time
			found     bool
		)
		for k, e := range s.entries {
			if !found || e.lastUsed.Before(oldest) {
				oldestKey, oldest, found = k, e.lastUsed, true
			}
		}
		if !found {
			return // 表是空的，没什么可淘汰（理论上到不了这里）
		}
		delete(s.entries, oldestKey)
	}
}
