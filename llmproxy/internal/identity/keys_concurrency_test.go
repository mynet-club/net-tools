package identity

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// keys.go 的 CachedKeys 是并发对象：缓存层做错方向（失败后继续用旧 key、
// 空集合被当成有效缓存、事后改时钟字段）在单次请求里看不出来，
// 只在密钥轮换或 IdP 抖动时暴露。本文件把 TTL 边界、失败清缓存、轮换生效
// 与并发复用四件事钉住（手册 §6「并发或重复调用测试」+ §8 的 -race 门槛）。

// advanceableClock 是可推进的测试时钟。带锁是因为并发用例会在别的 goroutine 里读它。
type advanceableClock struct {
	mu sync.RWMutex
	at time.Time
}

func (c *advanceableClock) now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.at
}

func (c *advanceableClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// countingKeys 是可切换内容/错误的上游，并记录被拉取次数。
// 拉取次数是「缓存到底命中没有」的唯一可观测量，本文件反复用它。
type countingKeys struct {
	mu       sync.Mutex
	calls    int
	material []JWK
	fail     error
}

func (s *countingKeys) Keys(_ context.Context) ([]JWK, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.fail != nil {
		return nil, s.fail
	}
	if len(s.material) == 0 {
		return nil, nil
	}
	out := make([]JWK, len(s.material))
	copy(out, s.material)
	return out, nil
}

func (s *countingKeys) set(material []JWK, fail error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.material = material
	s.fail = fail
}

func (s *countingKeys) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// authorityKeys 取测试签发方的真公钥作为缓存内容。
// 必须与签 token 用的是同一个 authority，否则验签用例会在 kid 之下再撞上 key 不符。
func authorityKeys(t *testing.T, authority *FakeAuthority) []JWK {
	t.Helper()
	material, err := authority.Keys(context.Background())
	if err != nil {
		t.Fatalf("取测试公钥失败: %v", err)
	}
	if len(material) != 2 {
		t.Fatalf("测试签发方应有 RSA + EC 两把公钥，实际 %d", len(material))
	}
	return material
}

// mustStudentToken 签一份「当前有效」的学生 token，时刻固定在 baseNow。
// Provider 与 token 都锚定 baseNow，用例才不会跟着机器日期漂（真实时间早于 baseNow）。
func mustStudentToken(t *testing.T, authority *FakeAuthority, kid string) Credential {
	t.Helper()
	token, err := authority.Sign(SignRequest{Profile: studentProfile(), At: baseNow, Kid: kid})
	if err != nil {
		t.Fatalf("签发测试 token 失败: %v", err)
	}
	return oidcCredential(t, token)
}

func mustCacheKeysErr(t *testing.T, source KeySource) error {
	t.Helper()
	_, err := source.Keys(context.Background())
	if err == nil {
		t.Fatal("取公钥应当失败")
	}
	return err
}

func TestNewCachedKeysRejectsNilSource(t *testing.T) {
	cached, err := NewCachedKeys(nil, time.Minute)
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("空公钥来源必须被拒，实际: %v", err)
	}
	if cached != nil {
		t.Fatal("配置不合法时不能返回可用的缓存对象")
	}
	// 原因码必须是 config_invalid：构造期失败属于接线错误，
	// 落成 internal_error 会让运维以为是本包缺陷而不是配置问题。
	assertReason(t, err, ReasonConfigInvalid)
}

func TestNewCachedKeysFallsBackToDefaultTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second} {
		src := &countingKeys{material: authorityKeys(t, testAuthority(t))}
		clock := &advanceableClock{at: baseNow}
		cached, err := NewCachedKeysAt(src, ttl, clock.now)
		if err != nil {
			t.Fatalf("ttl=%v 构造失败: %v", ttl, err)
		}
		if cached.ttl != DefaultKeysTTL {
			t.Fatalf("ttl=%v 应回落到默认 %v，实际 %v", ttl, DefaultKeysTTL, cached.ttl)
		}
		// 字段对了还不算：行为上必须真的按默认时长缓存，
		// 否则「回落到默认」只是把 0 当成「永不缓存」用了。
		if _, err := cached.Keys(context.Background()); err != nil {
			t.Fatalf("首轮拉取失败: %v", err)
		}
		clock.advance(DefaultKeysTTL - time.Nanosecond)
		if _, err := cached.Keys(context.Background()); err != nil {
			t.Fatalf("默认 TTL 内应命中缓存: %v", err)
		}
		if got := src.callCount(); got != 1 {
			t.Fatalf("ttl=%v 时默认 TTL 内不该再打上游，实际拉取 %d 次", ttl, got)
		}
		clock.advance(time.Nanosecond)
		if _, err := cached.Keys(context.Background()); err != nil {
			t.Fatalf("越过默认 TTL 后应刷新: %v", err)
		}
		if got := src.callCount(); got != 2 {
			t.Fatalf("ttl=%v 越过 DefaultKeysTTL 必须刷新，实际拉取 %d 次", ttl, got)
		}
	}
}

func TestCachedKeysServesCacheWithinTTL(t *testing.T) {
	material := authorityKeys(t, testAuthority(t))
	src := &countingKeys{material: material}
	clock := &advanceableClock{at: baseNow}
	cached, err := NewCachedKeysAt(src, time.Hour, clock.now)
	if err != nil {
		t.Fatalf("构造缓存层失败: %v", err)
	}
	ctx := context.Background()

	first, err := cached.Keys(ctx)
	if err != nil {
		t.Fatalf("首轮拉取失败: %v", err)
	}
	if src.callCount() != 1 {
		t.Fatalf("首轮应恰好拉取一次，实际 %d", src.callCount())
	}
	if !reflect.DeepEqual(first, material) {
		t.Fatalf("首轮返回内容应与上游一致\n期望 %+v\n实际 %+v", material, first)
	}

	// 未到期一律命中缓存；边界是「严格小于」，跨过整点才刷新。
	for _, step := range []time.Duration{0, time.Second, time.Hour - time.Second - time.Nanosecond} {
		clock.advance(step)
		got, err := cached.Keys(ctx)
		if err != nil {
			t.Fatalf("推进 %v 后取公钥失败: %v", step, err)
		}
		if len(got) != len(material) {
			t.Fatalf("缓存内容被改写: 期望 %d 把，实际 %d", len(material), len(got))
		}
		if src.callCount() != 1 {
			t.Fatalf("推进 %v 后仍在 TTL 内，不该再打上游（已拉取 %d 次）", step, src.callCount())
		}
	}
	clock.advance(time.Nanosecond)
	if _, err := cached.Keys(ctx); err != nil {
		t.Fatalf("越过 TTL 后刷新失败: %v", err)
	}
	if src.callCount() != 2 {
		t.Fatalf("越过 TTL 必须刷新一次，实际拉取 %d 次", src.callCount())
	}

	// 返回副本：调用方（或某个后续改动）改写切片内容不能污染缓存。
	beforeTamper := src.callCount()
	got, err := cached.Keys(ctx)
	if err != nil {
		t.Fatalf("取公钥失败: %v", err)
	}
	got[0].KeyID = "被调用方改写的 kid"
	afterTamper, err := cached.Keys(ctx)
	if err != nil {
		t.Fatalf("取公钥失败: %v", err)
	}
	if afterTamper[0].KeyID != material[0].KeyID {
		t.Fatalf("缓存被调用方的写入污染: %q", afterTamper[0].KeyID)
	}
	if src.callCount() != beforeTamper {
		t.Fatalf("副本被写坏不该触发刷新，拉取次数从 %d 变成 %d", beforeTamper, src.callCount())
	}
}

func TestCachedKeysRejectsEmptyKeySet(t *testing.T) {
	material := authorityKeys(t, testAuthority(t))
	src := &countingKeys{material: nil}
	clock := &advanceableClock{at: baseNow}
	cached, err := NewCachedKeysAt(src, time.Hour, clock.now)
	if err != nil {
		t.Fatalf("构造缓存层失败: %v", err)
	}

	err = mustCacheKeysErr(t, cached)
	if !errors.Is(err, ErrKeySourceUnavailable) {
		t.Fatalf("空公钥集合必须报来源不可用，实际: %v", err)
	}
	assertReason(t, err, ReasonKeyUnavailable)

	// 空结果不许被当成一次有效缓存：否则上游恢复后仍要等一整个 TTL 才可用。
	src.set(material, nil)
	got, err := cached.Keys(context.Background())
	if err != nil {
		t.Fatalf("上游恢复后应立即拉到公钥: %v", err)
	}
	if len(got) != len(material) {
		t.Fatalf("期望 %d 把公钥，实际 %d", len(material), len(got))
	}
	if src.callCount() != 2 {
		t.Fatalf("空集合与成功各打一次上游，实际 %d 次", src.callCount())
	}
	// 成功填充后才有缓存：第二次调用命中。
	if _, err := cached.Keys(context.Background()); err != nil {
		t.Fatalf("取公钥失败: %v", err)
	}
	if src.callCount() != 2 {
		t.Fatalf("成功填充后应命中缓存，实际拉取 %d 次", src.callCount())
	}
}

func TestCachedKeysDropsCacheWhenRefreshFails(t *testing.T) {
	authority := testAuthority(t)
	material := authorityKeys(t, authority)
	src := &countingKeys{material: material}
	clock := &advanceableClock{at: baseNow}
	cached, err := NewCachedKeysAt(src, time.Hour, clock.now)
	if err != nil {
		t.Fatalf("构造缓存层失败: %v", err)
	}
	ctx := context.Background()

	if _, err := cached.Keys(ctx); err != nil {
		t.Fatalf("首轮拉取失败: %v", err)
	}
	// 先确认「TTL 未到时的失败根本碰不到缓存层」：否则下面的断言
	// 会被误读成「失败被吞掉了」，而这里要测的是刷新那一刻的行为。
	src.set(nil, errors.New("上游此刻还不该被调用"))
	if _, err := cached.Keys(ctx); err != nil {
		t.Fatalf("TTL 内应命中缓存、不打上游，实际报错: %v", err)
	}

	// 越过 TTL 触发刷新，此时上游失败：缓存必须被清掉。
	// 留着旧条目会让「刷新失败」退化成无限期使用旧 key —— 轮换窗口里
	// 等于把已下线的 key 又扶正，这是明确的安全方向选择（宁可短暂不可用）。
	failure := errors.New("上游返回了非哨兵错误")
	clock.advance(time.Hour)
	src.set(nil, failure)
	err = mustCacheKeysErr(t, cached)
	if !errors.Is(err, failure) {
		t.Fatalf("缓存层应原样透传上游错误（细节留给接线层日志），实际: %v", err)
	}
	// 清缓存的证据：时间没再推进，本可以「无限期把旧 key 端出来」，
	// 但实现必须重新去打上游 —— 而不是命中那份已经作废的缓存。
	callsAfterFailure := src.callCount()
	src.set(nil, failure)
	_ = mustCacheKeysErr(t, cached)
	if src.callCount() <= callsAfterFailure {
		t.Fatalf("刷新失败后缓存必须被清空（时间不推进仍要重取），拉取次数停在 %d", callsAfterFailure)
	}
	// 恢复后立即能重新拉到，不需要再等一个 TTL。
	src.set(material, nil)
	got, err := cached.Keys(ctx)
	if err != nil {
		t.Fatalf("上游恢复后取公钥失败: %v", err)
	}
	if len(got) != len(material) {
		t.Fatalf("期望 %d 把公钥，实际 %d", len(material), len(got))
	}
	// 恢复后重新进缓存：后续调用命中。
	callsAfterRecovery := src.callCount()
	if _, err := cached.Keys(ctx); err != nil {
		t.Fatalf("取公钥失败: %v", err)
	}
	if src.callCount() != callsAfterRecovery {
		t.Fatalf("恢复后应重建缓存，拉取次数从 %d 变成 %d", callsAfterRecovery, src.callCount())
	}
}

// TestKeySourceFailureIsAuditedAsDependencyError 走完整验签链路：
// 非哨兵的上游错误必须被归成「依赖不可用」（原因码 key_source_unavailable、
// Outcome error），而不是 denied —— IdP 抖动不是调用方的错，
// 混成一档会让值班把依赖故障读成「攻击增多」。
func TestKeySourceFailureIsAuditedAsDependencyError(t *testing.T) {
	authority := testAuthority(t)
	material := authorityKeys(t, authority)
	cachingSrc := &countingKeys{material: material}
	cache, err := NewCachedKeysAt(cachingSrc, time.Hour, fixedClock(baseNow))
	if err != nil {
		t.Fatalf("构造缓存层失败: %v", err)
	}
	recorder := NewAuditRecorder(0)
	provider := newOIDC(t, cache, oidcOptions{audit: recorder})
	cred := mustStudentToken(t, authority, "")

	cachingSrc.set(nil, errors.New("对端 500"))
	err = resolveErr(t, provider, cred, ErrKeySourceUnavailable)
	assertReason(t, err, ReasonKeyUnavailable)
	var sawErrorEvent bool
	for _, event := range recorder.Events() {
		if event.Outcome == OutcomeError && event.Reason == ReasonKeyUnavailable {
			sawErrorEvent = true
		}
	}
	if !sawErrorEvent {
		t.Fatalf("公钥来源失败应记 error/key_source_unavailable 事件，实际: %+v", recorder.Events())
	}
	// 上游恢复后同一条凭证必须立刻可用（失败没被缓存成「永久不可用」）。
	cachingSrc.set(material, nil)
	resolveOK(t, provider, cred)
}

// TestCachedKeysRotationThroughOIDC 覆盖密钥轮换的三个方向：
// ① 缓存窗口内旧集合仍有效（轮换不会瞬间打断登录）；
// ② 越过 TTL 后新 key 生效；
// ③ 越过 TTL 后已下线的旧 key 必须不再被接受（不能无限期扶正）。
func TestCachedKeysRotationThroughOIDC(t *testing.T) {
	authority := testAuthority(t)
	oldKeys := []JWK{{KeyID: "kid-old", Algorithm: AlgRS256, Public: testRSAPublic(t, authority)}}
	newKeys := []JWK{{KeyID: "kid-new", Algorithm: AlgRS256, Public: testRSAPublic(t, authority)}}

	src := &countingKeys{material: oldKeys}
	clock := &advanceableClock{at: baseNow}
	cached, err := NewCachedKeysAt(src, time.Hour, clock.now)
	if err != nil {
		t.Fatalf("构造缓存层失败: %v", err)
	}
	// Provider 的判定时刻固定住：轮换用例只关心公钥集合何时换，
	// 两处都跟着真实时间走时 token 有效期会跟着机器日期漂。
	provider := newOIDC(t, cached, oidcOptions{})
	oldCred := mustStudentToken(t, authority, "kid-old")
	newCred := mustStudentToken(t, authority, "kid-new")

	if _, err := cached.Keys(context.Background()); err != nil {
		t.Fatalf("预取公钥失败: %v", err)
	}
	resolveOK(t, provider, oldCred)

	// ① 缓存窗口内：来源已换成新 key，但缓存还指着旧集合，新 kid 找不到。
	src.set(newKeys, nil)
	err = resolveErr(t, provider, newCred, ErrKeyNotFound)
	assertReason(t, err, ReasonKeyMissing)
	resolveOK(t, provider, oldCred)

	// ② 越过 TTL：刷新发生，新 key 生效。
	clock.advance(time.Hour)
	src.set([]JWK{newKeys[0], oldKeys[0]}, nil)
	resolveOK(t, provider, newCred)

	// ③ 再次轮换：把旧 key 彻底下线，越过 TTL 后旧 token 必须被拒。
	clock.advance(time.Hour)
	src.set(newKeys, nil)
	resolveErr(t, provider, oldCred, ErrKeyNotFound)
	resolveOK(t, provider, newCred)
}

func TestCachedKeysConcurrentFetch(t *testing.T) {
	// 并发数取非 2 的幂：24 个 worker × 40 轮既能撞锁又不至于把 CI 拖慢。
	const workers = 24
	const iterations = 40
	material := authorityKeys(t, testAuthority(t))
	src := &countingKeys{material: material}
	clock := &advanceableClock{at: baseNow}
	cached, err := NewCachedKeysAt(src, time.Hour, clock.now)
	if err != nil {
		t.Fatalf("构造缓存层失败: %v", err)
	}
	ctx := context.Background()

	var wg sync.WaitGroup
	failures := make(chan string, workers*iterations)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				keys, err := cached.Keys(ctx)
				switch {
				case err != nil:
					failures <- fmt.Sprintf("worker %d 取公钥失败: %v", worker, err)
				case len(keys) != len(material):
					failures <- fmt.Sprintf("worker %d 拿到 %d 把公钥，期望 %d",
						worker, len(keys), len(material))
				}
			}
		}(i)
	}
	wg.Wait()
	close(failures)
	var joined []string
	for msg := range failures {
		joined = append(joined, msg)
	}
	if len(joined) > 0 {
		t.Fatalf("并发取公钥出现失败:\n%s", strings.Join(joined, "\n"))
	}
	// 时钟冻结 ⇒ 960 次调用最多只能打上游一次。首轮会因互斥串行，
	// 其余全部命中缓存；变成每次都拉就等于没有缓存，IdP 会被打成瓶颈。
	if got := src.callCount(); got != 1 {
		t.Fatalf("并发下缓存必须命中，实际拉取 %d 次", got)
	}
}

// TestProvidersAndMapperAreConcurrencySafe 验证 Provider 契约第 1 条
// （构造后配置不可变、可并发复用）：同一凭证并发解析必须得到与基准完全一致的结论，
// 且并发期间存在合法的写入口（FakeProvider 的 fixture 表、公钥来源的集合切换）时仍成立。
func TestProvidersAndMapperAreConcurrencySafe(t *testing.T) {
	const workers = 16
	const iterations = 25

	authority := testAuthority(t)
	mapper := defaultMapper(t)
	claims := mapClaims("uid-stu-1001", map[string]any{
		"name":         "Sample Student",
		"organization": []any{"university", "cs-college"},
		"roles":        []any{"student"},
		"groups":       []any{"undergraduate", "cs-college"},
		"projects":     []any{"cs-101", "math-201"},
		"amr":          []any{"pwd", "otp"},
	})
	// 基准结果在主线程先算好：并发用例里不能调 t.Fatalf，只能把失败投递到 channel。
	want, wantErr := mapper.Map(claims, "campus-oidc")
	if wantErr != nil {
		t.Fatalf("基准映射失败: %v", wantErr)
	}

	cachedSrc := &countingKeys{material: authorityKeys(t, authority)}
	cached, err := NewCachedKeysAt(cachedSrc, time.Hour, fixedClock(baseNow))
	if err != nil {
		t.Fatalf("构造公钥缓存失败: %v", err)
	}
	oidcProvider := newOIDC(t, cached, oidcOptions{})
	oidcCred := mustStudentToken(t, authority, "")

	fakeProvider, err := NewFakeProvider(FakeOptions{
		Source: "campus-oidc",
		Name:   "fake-university",
		Mapper: mapper,
		Fixtures: map[string]Claims{
			studentProfile().FixtureName(): studentProfile().Claims(baseNow),
		},
	}, WithClock(fixedClock(baseNow)))
	if err != nil {
		t.Fatalf("构造 FakeProvider 失败: %v", err)
	}
	fakeCred := FakeCredential(studentProfile().FixtureName())

	// OIDC 与 Fake 共用同一套校验 + 映射管线、同一份画像，
	// 基准一致必须在并发之前成立，否则下面的相等断言是在比两个不同的期望。
	oidcWant, err := oidcProvider.Resolve(context.Background(), oidcCred)
	if err != nil {
		t.Fatalf("并发基准（OIDC）解析失败: %v", err)
	}
	fakeWant, err := fakeProvider.Resolve(context.Background(), fakeCred)
	if err != nil {
		t.Fatalf("并发基准（Fake）解析失败: %v", err)
	}
	if fakeWant.Provider == oidcWant.Provider {
		t.Fatal("两个来源的 provider 名本应不同，否则用例没在比两条管线")
	}
	aligned := fakeWant
	aligned.Provider = oidcWant.Provider
	if !reflect.DeepEqual(aligned, oidcWant) {
		t.Fatalf("并发基准两条管线结论应一致（只差 provider 名）\nOIDC %+v\nFake %+v", oidcWant, fakeWant)
	}

	stop := make(chan struct{})
	// 写侧要用的公钥集合在主线程先取好：t.Fatalf 不能从别的 goroutine 调。
	writerMaterial := authorityKeys(t, authority)
	var writers sync.WaitGroup
	writers.Add(2)
	go func() {
		defer writers.Done()
		clone := studentProfile().Claims(baseNow)
		for {
			select {
			case <-stop:
				return
			default:
			}
			// AddFixture 存的是副本，反复写入同一画像不该改变被解析的 fixture；
			// 它存在的意义是让读侧真的撞上写锁。间隔极短但非零：
			// 忙等会把 CPU 全吃掉，让读侧的失败变成调度噪声而不是竞争。
			fakeProvider.AddFixture("temp-fixture", clone)
			fakeProvider.AddFailure("temp-fixture", ErrInternal)
			time.Sleep(200 * time.Microsecond)
		}
	}()
	go func() {
		defer writers.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// 只换集合的内容实例、不换公钥语义：让缓存层与来源真的并发。
			cachedSrc.set(writerMaterial, nil)
			time.Sleep(200 * time.Microsecond)
		}
	}()

	type result struct {
		worker int
		msg    string
	}
	results := make(chan result, workers*iterations*3)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(3)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				mapped, mapErr := mapper.Map(claims, "campus-oidc")
				switch {
				case mapErr != nil:
					results <- result{worker, fmt.Sprintf("映射失败: %v", mapErr)}
				case mapped.Chain.Display() != want.Chain.Display():
					results <- result{worker, fmt.Sprintf("范围链从 %q 变成 %q",
						want.Chain.Display(), mapped.Chain.Display())}
				case mapped.Identity.Subject != want.Identity.Subject:
					results <- result{worker, fmt.Sprintf("主体从 %q 变成 %q",
						want.Identity.Subject, mapped.Identity.Subject)}
				}
			}
		}(i)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				principal, resolveFailure := oidcProvider.Resolve(context.Background(), oidcCred)
				switch {
				case resolveFailure != nil:
					results <- result{worker, fmt.Sprintf("OIDC 并发解析失败: %v", resolveFailure)}
				case !reflect.DeepEqual(principal, oidcWant):
					results <- result{worker, fmt.Sprintf("OIDC 并发解析结果与基准不一致: %+v vs %+v",
						principal, oidcWant)}
				}
			}
		}(i)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				principal, resolveFailure := fakeProvider.Resolve(context.Background(), fakeCred)
				switch {
				case resolveFailure != nil:
					results <- result{worker, fmt.Sprintf("Fake 并发解析失败: %v", resolveFailure)}
				case !reflect.DeepEqual(principal, fakeWant):
					results <- result{worker, fmt.Sprintf("Fake 并发解析结果与基准不一致: %+v vs %+v",
						principal, fakeWant)}
				}
			}
		}(i)
	}
	wg.Wait()
	close(results)
	close(stop)
	writers.Wait()

	var faults []string
	for item := range results {
		faults = append(faults, fmt.Sprintf("worker %d: %s", item.worker, item.msg))
	}
	if len(faults) > 0 {
		t.Fatalf("并发复用出现不一致:\n%s", strings.Join(faults, "\n"))
	}
}

// 编译期断言：并发用例依赖的接口实现关系不能漂。
var (
	_ KeySource = (*CachedKeys)(nil)
	_ KeySource = (*countingKeys)(nil)
	_ AuditSink = (*AuditRecorder)(nil)
)
