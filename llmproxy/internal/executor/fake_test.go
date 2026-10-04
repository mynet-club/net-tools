package executor

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
)

// 本测试是 §9 合入前置条件的最小自证：
// 「D、F 合并前必须提供 deterministic replay」——F 侧的底线是
// fake 在同一 Seed + 同一输入下逐字节稳定，且任何可序列化产物
// 不含正文与密钥标记串。完整超时/超限/失败/重试矩阵由后续派发补。

const (
	markSecret = "ZZSECRET_DO_NOT_LEAK"
	markBody   = "ZZBODY_MARK_SHOULD_NOT_APPEAR_IN_SNAPSHOT"
)

// sseScript 是一份 OpenAI SSE 形态的脚本正文：两帧 content + usage 末帧 + [DONE]。
const sseScript = "data: {\"choices\":[{\"delta\":{\"content\":\"xxxxxx\"}}]}\n" +
	"data: {\"choices\":[{\"delta\":{\"content\":\"yyyy\"}}]}\n" +
	"data: {\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18,\"prompt_cache_hit_tokens\":3,\"prompt_cache_miss_tokens\":8}}\n" +
	"data: [DONE]\n"

func baseAttempt() Attempt {
	return Attempt{
		RequestID:        "req-alpha",
		Provider:         "prov-a",
		Protocol:         ProtocolOpenAIChat,
		BaseURL:          "https://upstream.invalid",
		APIKey:           markSecret,
		Path:             "/v1/chat/completions",
		Model:            "gpt-x",
		UpstreamModel:    "gpt-x-real",
		Body:             []byte(`{"model":"gpt-x","messages":[{"role":"user","content":"hi"}],"stream":true}`),
		IsStream:         true,
		Timeout:          5e9,
		MaxResponseBytes: 1 << 20,
	}
}

func newScriptedFake() *Fake {
	return NewFake("11cf57b2b3c8e0a4de1a35f2c8b0a7d64f9e2c1b0a7d6e5f4c3b2a1908f7e6d5", FakeRule{
		Match:  FakeMatch{ProviderExact: "prov-a"},
		Status: 200,
		Stream: true,
		Body:   []byte(sseScript),
	})
}

// consumeOutcome 完整消费 Body 并返回逐字节内容 + 观测快照。
func consumeOutcome(t *testing.T, o Outcome) (string, string) {
	t.Helper()
	data, err := io.ReadAll(o.Body)
	if err != nil {
		t.Fatalf("读取 Body 失败: %v", err)
	}
	if err := o.Body.Close(); err != nil {
		t.Fatalf("关闭 Body 失败: %v", err)
	}
	snapJSON, err := o.Snapshot().JSON()
	if err != nil {
		t.Fatalf("快照序列化失败: %v", err)
	}
	return string(data), string(snapJSON)
}

// TestFakeDeterministicSameInput 验证同 Seed + 同输入逐字节稳定：
// 响应体、观测、快照三个通道都要一致（§2.8 / §9）。
func TestFakeDeterministicSameInput(t *testing.T) {
	f := newScriptedFake()
	ctx := context.Background()

	body1, snap1 := consumeOutcome(t, mustExecute(t, f, ctx, baseAttempt()))
	// 换一次进程内时序（重新构造 Attempt 值相同的副本），结果必须一致。
	body2, snap2 := consumeOutcome(t, mustExecute(t, f, ctx, baseAttempt()))

	if body1 != body2 {
		t.Fatalf("同一输入两次执行的响应体不一致:\n%q\n%q", body1, body2)
	}
	if snap1 != snap2 {
		t.Fatalf("同一输入两次执行的观测快照不一致:\n%s\n%s", snap1, snap2)
	}
	// 观测口径本身也要对得上脚本（不是「稳定地错」）。
	var snap Snapshot
	if err := json.Unmarshal([]byte(snap1), &snap); err != nil {
		t.Fatalf("快照不可解析: %v", err)
	}
	obs := snap.Observation
	if !obs.HasUsage || !obs.SawDone {
		t.Fatalf("usage/done 观测缺失: %+v", obs)
	}
	if int64p(obs.Usage.PromptTokens) != 11 || int64p(obs.Usage.CompletionTokens) != 7 || int64p(obs.Usage.TotalTokens) != 18 {
		t.Fatalf("usage 折算错误: %+v", obs.Usage)
	}
	if !obs.Usage.HasCache || obs.Usage.CacheHit != 3 || obs.Usage.CacheMiss != 8 {
		t.Fatalf("缓存拆分错误: %+v", obs.Usage)
	}
	if obs.ContentBytes != 10 {
		t.Fatalf("content 字节计数错误: got %d want 10", obs.ContentBytes)
	}
}

// TestFakeDeterministicUnderConcurrency 并发重放同一 Attempt 也必须拿到同一输出
// （fake 无消耗语义，规则选择只看输入）。
func TestFakeDeterministicUnderConcurrency(t *testing.T) {
	f := newScriptedFake()
	ctx := context.Background()
	const n = 16
	results := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body, _ := consumeOutcome(t, mustExecute(t, f, ctx, baseAttempt()))
			results[i] = body
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		if r != results[0] {
			t.Fatalf("第 %d 个并发重放与第 0 个不一致", i)
		}
	}
}

// TestSnapshotNoBodyNoSecret Outcome 的可序列化产物不得携带正文与密钥。
// 这是 §2.9 / 测试 fixture 纪律的编译后可执行版。
func TestSnapshotNoBodyNoSecret(t *testing.T) {
	f := newScriptedFake()
	// 往脚本头里塞一个逐跳头验证过滤（口径与真实执行器同一函数）。
	f.Rules[0].Headers = map[string][]string{
		"X-Trace":           {"trace-zzfake"},
		"Transfer-Encoding": {"chunked"},
	}
	a := baseAttempt()
	a.Headers = map[string]string{"X-Custom": "ok", "Authorization": "Bearer " + markSecret}

	out := mustExecute(t, f, context.Background(), a)
	body, snapJSON := consumeOutcome(t, out)

	// 正文本身在流里（这是它的唯一容身处），但快照里不许出现。
	if !strings.Contains(body, "data:") {
		t.Fatalf("流式脚本正文应原样可读到")
	}
	if strings.Contains(snapJSON, "data:") {
		t.Fatalf("快照泄漏了响应体: %s", snapJSON)
	}
	if strings.Contains(snapJSON, markSecret) || strings.Contains(snapJSON, markBody) {
		t.Fatalf("快照泄漏了密钥/正文标记: %s", snapJSON)
	}
	if _, ok := out.Headers["Transfer-Encoding"]; ok {
		t.Fatalf("逐跳头未被过滤")
	}
}

// TestFakeErrorTextNoSecret 失败脚本的错误文本只能由稳定码与稳定 ID 构成。
func TestFakeErrorTextNoSecret(t *testing.T) {
	f := NewFake("seed-x", FakeRule{
		Match:   FakeMatch{RequestIDExact: "req-alpha"},
		Failure: ReasonTimeout,
	})
	a := baseAttempt()
	a.APIKey = markSecret
	_, err := f.Execute(context.Background(), a)
	if err == nil {
		t.Fatalf("失败脚本必须报错")
	}
	if !strings.Contains(err.Error(), ReasonTimeout.String()) {
		t.Fatalf("错误文本缺少稳定码: %v", err)
	}
	if strings.Contains(err.Error(), markSecret) || strings.Contains(err.Error(), a.BaseURL) {
		t.Fatalf("错误文本泄漏了密钥或目标: %v", err)
	}
	var ee *ExecutionError
	if !asExecutionError(err, &ee) || ee.Code != ReasonTimeout {
		t.Fatalf("错误未收敛为 *ExecutionError: %#v", err)
	}
}

// TestSeedPoolDeterministic 无规则命中时按 H(Seed||指纹) 定值抽签：
// 同 seed 同输入恒中同一条，换 seed 结果可复现地变化。
func TestSeedPoolDeterministic(t *testing.T) {
	pool := []FakeRule{
		{Status: 200, Body: []byte("pool-0")},
		{Status: 200, Body: []byte("pool-1")},
		{Status: 200, Body: []byte("pool-2")},
	}
	f1 := NewFake("seed-one")
	f1.SeedPool = pool
	f2 := NewFake("seed-one")
	f2.SeedPool = pool

	a := baseAttempt()
	a.RequestID = "req-pool"
	b1 := mustExecute(t, f1, context.Background(), a)
	b2 := mustExecute(t, f2, context.Background(), a)
	s1, _ := consumeOutcome(t, b1)
	s2, _ := consumeOutcome(t, b2)
	if s1 != s2 {
		t.Fatalf("同 seed 同输入抽签不一致: %q vs %q", s1, s2)
	}
}

// TestUnmatchedFailsClosed 配过规则但未命中必须显式失败（不静默编造）。
func TestUnmatchedFailsClosed(t *testing.T) {
	f := NewFake("seed-y", FakeRule{Match: FakeMatch{ProviderExact: "other"}})
	f.FailUnmatched = true
	_, err := f.Execute(context.Background(), baseAttempt())
	var ee *ExecutionError
	if !asExecutionError(err, &ee) || ee.Code != ReasonNoScript {
		t.Fatalf("未命中应报 executor_no_script，got %v", err)
	}
}

// TestAttemptValidationFailClosed 缺超时/缺上限/坏目标一律不出网。
//
// 零值这一栏的闸门是 IsStream（2026-10-04 裁决第 2 条）：非流式的 0 仍然是「缺」，
// 流式的 0 是「显式声明不限」，两者都必须在出网**之前**分得清 —— 这里的用例所以都
// 显式写成非流式，而放宽那一侧的正例见 http_test.go 的同名形态测试。
func TestAttemptValidationFailClosed(t *testing.T) {
	e, err := NewHTTPExecutor(Options{Name: "http"})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	ctx := context.Background()

	a := baseAttempt()
	a.IsStream, a.Timeout = false, 0
	if _, err := e.Execute(ctx, a); err == nil {
		t.Fatalf("非流式缺超时必须报错")
	}

	a = baseAttempt()
	a.IsStream, a.MaxResponseBytes = false, 0
	if _, err := e.Execute(ctx, a); err == nil {
		t.Fatalf("非流式缺响应体上限时必须报错")
	}

	a = baseAttempt()
	a.BaseURL = "https://user:" + markSecret + "@upstream.invalid"
	_, err = e.Execute(ctx, a)
	var ee *ExecutionError
	if !asExecutionError(err, &ee) || ee.Code != ReasonTargetRejected {
		t.Fatalf("内嵌凭证必须被目标约束拒绝，got %v", err)
	}
	if strings.Contains(err.Error(), markSecret) {
		t.Fatalf("目标拒绝的错误文本泄漏了凭证: %v", err)
	}
}

func mustExecute(t *testing.T, e Executor, ctx context.Context, a Attempt) Outcome {
	t.Helper()
	out, err := e.Execute(ctx, a)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	return out
}

func asExecutionError(err error, target **ExecutionError) bool {
	for err != nil {
		if ee, ok := err.(*ExecutionError); ok {
			*target = ee
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func int64p(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// TestFakeZeroLimitMatchesRealExecutor 锁「同一处放宽在两个实现里同形」（裁决第 2 条）：
// fake 与 HTTPExecutor 共用 Validate，但体积执法各写一处 —— 这里如果只改了真实侧，
// 回放就会在限额为 0 的流式 Attempt 上报 body_too_large，而线上是好的。
func TestFakeZeroLimitMatchesRealExecutor(t *testing.T) {
	f := newScriptedFake()

	a := baseAttempt()
	a.MaxResponseBytes = 0
	body, snap := consumeOutcome(t, mustExecute(t, f, context.Background(), a))
	if body != sseScript || strings.Contains(snap, markSecret) {
		t.Fatalf("限额为 0 必须整条交付脚本正文: got %d 字节 want %d 字节, snap=%s",
			len(body), len(sseScript), snap)
	}

	// 对照组：限额小于脚本长度时仍然执法，「0 = 不限」不能顺手把正数限额也免掉。
	b := baseAttempt()
	b.MaxResponseBytes = int64(len(sseScript) - 1)
	_, err := f.Execute(context.Background(), b)
	var ee *ExecutionError
	if !asExecutionError(err, &ee) || ee.Code != ReasonBodyTooLarge {
		t.Fatalf("正数限额必须照常执法，got %v", err)
	}
}
