package config

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Store 持有当前生效的配置快照，并在文件变化时原子替换。
//
// 轮询而不是 fsnotify：跨编辑器（含 vim 的"写临时文件再 rename"）行为更一致，
// 也少一个第三方依赖。校验失败时保留旧配置继续服务，把原因交给回调。
type Store struct {
	path     string
	current  atomic.Value // *Config
	revision atomic.Int64

	mu       sync.Mutex
	mtimeNs  int64
	stopCh   chan struct{}
	stopOnce sync.Once
	onReload func(ok bool, changed bool, cfg *Config, err error)
}

func NewStore(path string) *Store {
	return &Store{path: path, stopCh: make(chan struct{})}
}

func (s *Store) Path() string { return s.path }

func (s *Store) Current() *Config {
	v := s.current.Load()
	if v == nil {
		return nil
	}
	return v.(*Config)
}

func (s *Store) Revision() int64 { return s.revision.Load() }

// Load 读取并校验配置。失败时不改动 current。
func (s *Store) Load() (*Config, error) {
	cfg, err := LoadFile(s.path)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	prev := s.current.Load()
	changed := true
	if prev != nil {
		changed = !configEqual(prev.(*Config), cfg)
	}
	if changed {
		s.revision.Add(1)
	}
	s.current.Store(cfg)
	if st, err := os.Stat(s.path); err == nil {
		s.mtimeNs = st.ModTime().UnixNano()
	}
	s.mu.Unlock()
	return cfg, nil
}

// Reload 尝试重新加载；失败时保留旧配置。
func (s *Store) Reload() (changed bool, cfg *Config, err error) {
	before := s.revision.Load()
	prev := s.Current()
	newCfg, loadErr := LoadFile(s.path)
	if loadErr != nil {
		if prev != nil {
			return false, prev, loadErr
		}
		return false, nil, loadErr
	}
	s.mu.Lock()
	if st, e := os.Stat(s.path); e == nil {
		s.mtimeNs = st.ModTime().UnixNano()
	}
	if prev != nil && configEqual(prev, newCfg) {
		s.current.Store(newCfg) // 刷新 warnings 等
		s.mu.Unlock()
		return false, newCfg, nil
	}
	s.revision.Add(1)
	s.current.Store(newCfg)
	s.mu.Unlock()
	_ = before
	return true, newCfg, nil
}

// Watch 开始轮询；interval 为轮询间隔。
func (s *Store) Watch(interval time.Duration, onReload func(ok bool, changed bool, cfg *Config, err error)) {
	s.mu.Lock()
	s.onReload = onReload
	s.mu.Unlock()
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-t.C:
				s.mu.Lock()
				var mtimeNs int64
				if st, err := os.Stat(s.path); err == nil {
					mtimeNs = st.ModTime().UnixNano()
				} else {
					s.mu.Unlock()
					continue
				}
				if mtimeNs == s.mtimeNs {
					s.mu.Unlock()
					continue
				}
				s.mtimeNs = mtimeNs
				cb := s.onReload
				s.mu.Unlock()
				changed, cfg, err := s.Reload()
				if cb != nil {
					cb(err == nil, changed, cfg, err)
				}
			}
		}
	}()
}

func (s *Store) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// configEqual 比较会影响运行时行为的字段；日志级别/警告等不算变更。
func configEqual(a, b *Config) bool {
	if a == nil || b == nil {
		return a == b
	}
	if !serverEqual(a.Server, b.Server) {
		return false
	}
	if a.Routing != b.Routing {
		return false
	}
	if !databaseEqual(a.Database, b.Database) {
		return false
	}
	if len(a.Proxies) != len(b.Proxies) {
		return false
	}
	for i := range a.Proxies {
		if a.Proxies[i] != b.Proxies[i] {
			return false
		}
	}
	if len(a.Normalized) != len(b.Normalized) {
		return false
	}
	for i := range a.Normalized {
		if !providerEqual(a.Normalized[i], b.Normalized[i]) {
			return false
		}
	}
	if !policyEqual(a.Policy, b.Policy) {
		return false
	}
	return true
}

// policyEqual 比较 policy 段的生效语义 —— 它是热加载能「按 scope 回滚」的前提。
//
// 漏掉这段的后果不是少打一行日志：§3.0 的回滚动作就是改 policy.mode（或改引用
// 的 version / bundle_dir / data_level），比不出变更 → revision 不推进 →
// server.policyFor 继续返回缓存着的旧 policyRuntime，运维改完配置一切照旧，
// 而审计里的策略版本还会一直报着回滚前那一版。回滚开关按下去没反应，
// 比没有开关更糟。
//
// 一律比**解析后的值**而不是原始字段：「没写 fallback」与「显式写 true」行为完全
// 一致就该判等（同 databaseEqual 的理由），而 mode/data_level 在加载期已被归一化成
// 派生的枚举值（TrimSpace + 解析），比派生值才能同时躲开指针身份和「写法不同、
// 语义相同」两个坑。
func policyEqual(a, b PolicyConfig) bool {
	if a.ModeResolved() != b.ModeResolved() ||
		a.DataLevelResolved() != b.DataLevelResolved() ||
		a.FallbackToLegacyEnabled() != b.FallbackToLegacyEnabled() ||
		strings.TrimSpace(a.BundleDir) != strings.TrimSpace(b.BundleDir) ||
		strings.TrimSpace(a.ActiveBundle) != strings.TrimSpace(b.ActiveBundle) {
		return false
	}
	if len(a.Bundles) != len(b.Bundles) {
		return false
	}
	for i := range a.Bundles {
		if a.Bundles[i] != b.Bundles[i] {
			return false
		}
	}
	return true
}

// databaseEqual 逐字段比较，**不能**直接写 a != b。
//
// DatabaseConfig 里的 RetainDays 是 *int（用来区分「没配」与「显式 0 = 永久」），
// 而结构体含指针字段时 `!=` 比的是**指针身份**：两次 Parse 各自分配一个 int，
// 于是哪怕配置一字未改，a.Database != b.Database 也恒为真。后果是每次保存配置
// 都被判成「变了」→ 重载回调白跑一遍 → srv.Transports().Reset() 把上游连接池
// 全部丢掉（管理台的「就近保存」会让这件事频繁发生）。
func databaseEqual(a, b DatabaseConfig) bool {
	return a.Path == b.Path && a.EffectiveRetainDays() == b.EffectiveRetainDays()
}

// serverEqual 比较会影响运行时行为的 server 字段。
//
// 指针型的可选字段（StreamIdleTimeoutMs / AffinityTTLMs）一律**通过访问器比值**，
// 理由与 databaseEqual 相同：直接比指针会因为「两次 Parse 各分配一个 int」而恒不等。
// 用访问器还顺带得到正确的语义 —— 「没配」与「显式写成默认值」行为完全一致，
// 就该判为相等，不该触发一次无谓的重载。
func serverEqual(a, b ServerConfig) bool {
	if a.Host != b.Host || a.Port != b.Port ||
		a.MaxBodyMB != b.MaxBodyMB || a.RequestTimeoutMs != b.RequestTimeoutMs {
		return false
	}
	// affinity_ttl_ms 必须参与比较：它被缓存在 affinityStore 里、不是每请求实时读，
	// 漏比的话改了这个值 configEqual 会返回 true → 重载回调直接 return →
	// 连「配置已热加载」的日志都不打，而粘性行为一点没变。
	if a.StreamIdleMs() != b.StreamIdleMs() || a.AffinityTTL() != b.AffinityTTL() {
		return false
	}
	if a.AdminToken != b.AdminToken || a.BlockLocalUpstream != b.BlockLocalUpstream {
		return false
	}
	if len(a.APIKeys) != len(b.APIKeys) {
		return false
	}
	for i := range a.APIKeys {
		if a.APIKeys[i] != b.APIKeys[i] {
			return false
		}
	}
	return true
}

// providerEqual 逐字段比较归一化后的供应商。
//
// MaxDataLevel 必须在列：它是 3.0 分级门的事实来源，把一家上游从 confidential 降
// 到 internal 是一次**降敏动作**，静默不生效等于让敏感流量继续留在已经声明「不接」
// 的上游里。漏比一个字段在这个函数里没有编译器提示，只能靠测试钉住
// （TestConfigEqualDetectsPolicyFacts）。
func providerEqual(a, b Provider) bool {
	if a.Name != b.Name || a.Enabled != b.Enabled || a.BaseURL != b.BaseURL ||
		a.APIKey != b.APIKey || a.Weight != b.Weight || a.TimeoutMs != b.TimeoutMs ||
		a.Proxy != b.Proxy || a.MaxDataLevel != b.MaxDataLevel ||
		a.Models.Passthrough != b.Models.Passthrough ||
		a.Models.CatchAll != b.Models.CatchAll {
		return false
	}
	if len(a.Models.Map) != len(b.Models.Map) {
		return false
	}
	for k, v := range a.Models.Map {
		if b.Models.Map[k] != v {
			return false
		}
	}
	if len(a.ExtraHeaders) != len(b.ExtraHeaders) {
		return false
	}
	for k, v := range a.ExtraHeaders {
		if b.ExtraHeaders[k] != v {
			return false
		}
	}
	return true
}
