package config

import (
	"os"
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
	if a.Database != b.Database {
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
	return true
}

func serverEqual(a, b ServerConfig) bool {
	if a.Host != b.Host || a.Port != b.Port ||
		a.MaxBodyMB != b.MaxBodyMB || a.RequestTimeoutMs != b.RequestTimeoutMs {
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

func providerEqual(a, b Provider) bool {
	if a.Name != b.Name || a.Enabled != b.Enabled || a.BaseURL != b.BaseURL ||
		a.APIKey != b.APIKey || a.Weight != b.Weight || a.TimeoutMs != b.TimeoutMs ||
		a.Proxy != b.Proxy || a.Models.Passthrough != b.Models.Passthrough ||
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
