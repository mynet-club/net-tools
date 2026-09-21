package server

import (
	"strings"
	"testing"
	"time"
)

// 测试用的假时钟：粘性表的过期与淘汰都按它算，不用真的 sleep。
func newTestAffinity(ttl time.Duration, max int) (*affinityStore, func(time.Duration)) {
	s := newAffinityStore(ttl, max)
	base := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	now := base
	s.now = func() time.Time { return now }
	return s, func(d time.Duration) { now = now.Add(d) }
}

const (
	sc = "arthur"
	se = "ses_1"
	mo = "m-one"
)

func TestAffinitySetGet(t *testing.T) {
	s, _ := newTestAffinity(time.Hour, 16)
	if got := s.Get(sc, se, mo); got != "" {
		t.Errorf("没粘过应当是空，实际 %q", got)
	}
	s.Set(sc, se, mo, "neolink")
	if got := s.Get(sc, se, mo); got != "neolink" {
		t.Errorf("应当粘住 neolink，实际 %q", got)
	}
	if got := s.Get(sc, "ses_other", mo); got != "" {
		t.Errorf("别的会话不该被影响，实际 %q", got)
	}
}

// 必须按用户隔离：不同用户的同名会话不能互相指路。
// 会话 id 是下游生成的，多用户共享同一个上游账号时这条尤其重要。
func TestAffinityIsolatedByScope(t *testing.T) {
	s, _ := newTestAffinity(time.Hour, 16)
	s.Set("arthur", "ses_same", mo, "alpha")
	s.Set("bob", "ses_same", mo, "beta")
	if got := s.Get("arthur", "ses_same", mo); got != "alpha" {
		t.Errorf("arthur 应当是 alpha，实际 %q", got)
	}
	if got := s.Get("bob", "ses_same", mo); got != "beta" {
		t.Errorf("bob 应当是 beta，实际 %q", got)
	}
	s.Set("", "ses_same", mo, "gamma")
	if got := s.Get("", "ses_same", mo); got != "gamma" {
		t.Errorf("全局作用域应当是 gamma，实际 %q", got)
	}
	if got := s.Get("arthur", "ses_same", mo); got != "alpha" {
		t.Errorf("全局的写入不该影响 arthur，实际 %q", got)
	}
}

// 必须按模型隔离。
//
// 这条是核心：上游的前缀缓存按（上游账号 + 模型）分区，而一个会话会调多个模型
// （MiMo 有 model / small_model / vision_model）。只按会话记的话，调完模型 A 再调
// 模型 B 会把这条记录改写掉，回头调 A 时 prefer 已经指着一家不承接它的供应商 ——
// 于是每次换模型都要漂移一次，缓存照样被拆。
func TestAffinityIsolatedByModel(t *testing.T) {
	s, _ := newTestAffinity(time.Hour, 16)
	s.Set(sc, se, "gpt-5-sol", "neolink")
	s.Set(sc, se, "deepseek-flash", "deepseek")

	if got := s.Get(sc, se, "gpt-5-sol"); got != "neolink" {
		t.Errorf("gpt-5-sol 应当粘在 neolink，实际 %q", got)
	}
	if got := s.Get(sc, se, "deepseek-flash"); got != "deepseek" {
		t.Errorf("deepseek-flash 应当粘在 deepseek，实际 %q", got)
	}
	// 换模型来回读写几次，谁都不该改写掉谁
	s.Set(sc, se, "deepseek-flash", "deepseek")
	s.Set(sc, se, "gpt-5-sol", "neolink")
	if got := s.Get(sc, se, "gpt-5-sol"); got != "neolink" {
		t.Errorf("反复调用之后 gpt-5-sol 的粘性被改写了，实际 %q", got)
	}
	if n := s.Len(); n != 2 {
		t.Errorf("两个模型应当是两条记录，实际 %d 条", n)
	}
}

// 没有会话 id、或没有模型名（下游没带这个头/请求体里没 model）时，
// 粘性整个不参与，读写都是空操作 —— 否则一个空键会把所有请求并到一起。
func TestAffinityIgnoresEmptyParts(t *testing.T) {
	s, _ := newTestAffinity(time.Hour, 16)
	s.Set(sc, "", mo, "alpha")
	s.Set(sc, se, "", "alpha")
	if n := s.Len(); n != 0 {
		t.Errorf("空会话或空模型都不该被记下来，实际记了 %d 条", n)
	}
	if got := s.Get(sc, "", mo); got != "" {
		t.Errorf("空会话应当返回空，实际 %q", got)
	}
	if got := s.Get(sc, se, ""); got != "" {
		t.Errorf("空模型应当返回空，实际 %q", got)
	}
}

// 记空供应商 = 忘掉这条粘性（该家已经不再承接这个模型时用）。
func TestAffinitySetEmptyForgets(t *testing.T) {
	s, _ := newTestAffinity(time.Hour, 16)
	s.Set(sc, se, mo, "alpha")
	s.Set(sc, se, mo, "")
	if got := s.Get(sc, se, mo); got != "" {
		t.Errorf("应当已被忘掉，实际 %q", got)
	}
	if n := s.Len(); n != 0 {
		t.Errorf("忘掉后不该还占着位置，实际 %d 条", n)
	}
}

// 超过 ttl 没动静就当没粘过；期间有读写就续期。
func TestAffinityExpires(t *testing.T) {
	s, advance := newTestAffinity(time.Hour, 16)
	s.Set(sc, se, mo, "alpha")

	advance(59 * time.Minute)
	if got := s.Get(sc, se, mo); got != "alpha" {
		t.Fatalf("59 分钟还在 ttl 内，不该过期，实际 %q", got)
	}
	// Get 命中会刷新最近使用时间，所以再等 59 分钟仍然有效
	advance(59 * time.Minute)
	if got := s.Get(sc, se, mo); got != "alpha" {
		t.Errorf("命中期之后不该过期，实际 %q", got)
	}
	advance(time.Hour)
	if got := s.Get(sc, se, mo); got != "" {
		t.Errorf("超过 ttl 应当过期，实际 %q", got)
	}
	if n := s.Len(); n != 0 {
		t.Errorf("过期条目应当被顺手清掉，实际还剩 %d 条", n)
	}
}

// ttl <= 0 = 整体关闭：读永远空、写不记。
func TestAffinityDisabledWhenTTLZero(t *testing.T) {
	s, _ := newTestAffinity(0, 16)
	s.Set(sc, se, mo, "alpha")
	if got := s.Get(sc, se, mo); got != "" {
		t.Errorf("关闭时应当返回空，实际 %q", got)
	}
	if n := s.Len(); n != 0 {
		t.Errorf("关闭时不该记任何东西，实际 %d 条", n)
	}
}

// 超出容量时丢最久没用过的，且表不会只涨不落。
func TestAffinityEvictsLeastRecentlyUsed(t *testing.T) {
	s, advance := newTestAffinity(time.Hour, 3)
	for _, sess := range []string{"s1", "s2", "s3"} {
		s.Set(sc, sess, mo, "alpha")
		advance(time.Minute) // 拉开 lastUsed，让 LRU 有确定的顺序
	}
	// s1 最久没用；先碰一下 s3，再插 s4 触发淘汰
	_ = s.Get(sc, "s3", mo)
	s.Set(sc, "s4", mo, "alpha")

	if n := s.Len(); n > 3 {
		t.Fatalf("超出容量后应当被压回 3，实际 %d", n)
	}
	if got := s.Get(sc, "s1", mo); got != "" {
		t.Errorf("最久没用过的 s1 应当被淘汰，实际还留着 %q", got)
	}
	for _, sess := range []string{"s2", "s3", "s4"} {
		if got := s.Get(sc, sess, mo); got != "alpha" {
			t.Errorf("%s 应当还在，实际 %q", sess, got)
		}
	}
}

// 淘汰时优先清已过期的，别为了腾位置丢掉还活着的会话。
func TestAffinityEvictionPrefersExpired(t *testing.T) {
	s, advance := newTestAffinity(10*time.Minute, 3)
	s.Set(sc, "old1", mo, "alpha")
	s.Set(sc, "old2", mo, "alpha")
	advance(20 * time.Minute) // 上面两条过期
	s.Set(sc, "live1", mo, "alpha")
	s.Set(sc, "live2", mo, "alpha")
	if n := s.Len(); n != 2 {
		t.Fatalf("应当只剩两条活着的，实际 %d 条", n)
	}
	for _, sess := range []string{"live1", "live2"} {
		if got := s.Get(sc, sess, mo); got != "alpha" {
			t.Errorf("%s 不该被淘汰，实际 %q", sess, got)
		}
	}
}

// 键里的会话 id 与模型名都是客户端给的，必须有长度上限：不设上限的话一个 1MB 的值
// 就能借容量上限吃掉好几 GB（8192 条 × 1MB）。超长的一律当作「没有粘性」——
// 粘性只是提示，丢掉它只是多一次缓存失效；悄悄截断则会把两个不同会话/模型并到一起。
func TestAffinityRejectsOversizedParts(t *testing.T) {
	s, _ := newTestAffinity(time.Hour, 16)
	huge := strings.Repeat("x", 1024*1024)
	s.Set(sc, huge, mo, "alpha")
	s.Set(sc, se, huge, "alpha")
	if n := s.Len(); n != 0 {
		t.Errorf("超长的键不该被记下来，实际记了 %d 条", n)
	}
	if got := s.Get(sc, huge, mo); got != "" {
		t.Errorf("超长会话 id 读出来应当是空，实际 %q", got)
	}
	if got := s.Get(sc, se, huge); got != "" {
		t.Errorf("超长模型名读出来应当是空，实际 %q", got)
	}
	// 边界：恰好等于上限的要用，超一个字节的要拒
	ok := strings.Repeat("y", maxAffinityPartLen)
	bad := strings.Repeat("y", maxAffinityPartLen+1)
	s.Set(sc, ok, ok, "alpha")
	if got := s.Get(sc, ok, ok); got != "alpha" {
		t.Errorf("长度恰好等于上限的应当可用，实际 %q", got)
	}
	s.Set(sc, bad, mo, "alpha")
	s.Set(sc, se, bad, "alpha")
	if got := s.Get(sc, bad, mo); got != "" {
		t.Errorf("会话 id 超一个字节的应当被拒，实际 %q", got)
	}
	if got := s.Get(sc, se, bad); got != "" {
		t.Errorf("模型名超一个字节的应当被拒，实际 %q", got)
	}
}

// 构造器的兜底与 nil 接收者安全：转发路径可以写成无脑 store.Get(...)，
// 不必在每个调用点判空。
func TestAffinityDefaultsAndNilSafety(t *testing.T) {
	s := newAffinityStore(time.Hour, 0)
	if s.max != defaultAffinityMax {
		t.Errorf("max<=0 时应当用默认值 %d，实际 %d", defaultAffinityMax, s.max)
	}
	var n *affinityStore
	if n.Get(sc, se, mo) != "" || n.Len() != 0 {
		t.Error("nil 接收者的读方法应当返回空值")
	}
	n.Set(sc, se, mo, "alpha") // 不该 panic
}

// 并发读写不能炸（转发路径是多协程的）。
func TestAffinityConcurrent(t *testing.T) {
	s, _ := newTestAffinity(time.Hour, 64)
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				s.Set(sc, "ses", mo, "alpha")
				_ = s.Get(sc, "ses", mo)
				s.Set(sc, "ses_other", "m-two", "beta")
				_ = s.Len()
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if got := s.Get(sc, "ses", mo); got != "alpha" {
		t.Errorf("并发之后应当仍是 alpha，实际 %q", got)
	}
}
