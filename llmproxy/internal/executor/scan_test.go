package executor

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// 本文件钉的是旁路观测的两条底线：(1) 透传保真 —— 观测器只能「看」，改一个字节就等于
// 让下游拿到与上游不同的响应；(2) 体积执法必须是显式失败 —— 绝不能读着读着变成「干净
// EOF + 零用量」，那是白送一次上游调用却不记账的形状。全程不碰网络：直接给 scanReader
// 喂一个按指定切片吐字节的 io.ReadCloser。

// scanExSSE：unicode 正文两帧 + 末帧 usage（cached_tokens=6）+ [DONE]，content 合计 20 字节。
const scanExSSE = "data: {\"choices\":[{\"delta\":{\"content\":\"你好，\"}}]}\n\n" +
	"data: {\"choices\":[{\"delta\":{\"content\":\"世界 🌍\"}}]}\n\n" +
	"data: {\"usage\":{\"prompt_tokens\":21,\"completion_tokens\":5,\"total_tokens\":26,\"prompt_tokens_details\":{\"cached_tokens\":6}}}\n\n" +
	"data: [DONE]\n\n"

// scanExNoUsage 只有 content 帧，既没有 usage 也没有收尾标记：观测必须是零值而不是报错。
const scanExNoUsage = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
	"data: {\"choices\":[{\"delta\":{\"content\":\"there\"}}]}\n"

// scanExOllama 是原生协议的 JSON 行：用量只在 done:true 那行平铺出现。
const scanExOllama = "{\"message\":{\"content\":\"zz你好\"},\"done\":false}\n" +
	"{\"message\":{\"content\":\"zztail\"},\"done\":true,\"prompt_eval_count\":12,\"eval_count\":9}\n"

const scanExDeepSeekJSON = `{"choices":[{"message":{"content":"zz"}}],"usage":{"prompt_tokens":8,"completion_tokens":4,"total_tokens":12,"prompt_cache_hit_tokens":2,"prompt_cache_miss_tokens":6}}`

// scanExSource 按给定的切片逐块吐出（模拟上游 TCP 分片），块用尽后给 EOF。
type scanExSource struct {
	chunks [][]byte
	i      int
	buf    []byte
}

func (s *scanExSource) Read(p []byte) (int, error) {
	for len(s.buf) == 0 && s.i < len(s.chunks) {
		s.buf, s.i = s.chunks[s.i], s.i+1
	}
	if len(s.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

func (s *scanExSource) Close() error { return nil }

// scanExDrain 用 bufSize 字节的下游缓冲读到底：切片边界与下游节奏都可控。
// 干净 EOF 归一成 nil（「读完」本身不是错误），其它错误原样交给调用方断言。
func scanExDrain(r io.Reader, bufSize int) (string, error) {
	p, out := make([]byte, bufSize), strings.Builder{}
	for {
		n, err := r.Read(p)
		out.Write(p[:n])
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return out.String(), nil
		}
		return out.String(), err
	}
}

func scanExChunks(s string, size int) [][]byte {
	out := make([][]byte, 0, len(s)/size+1)
	for i := 0; i < len(s); i += size {
		end := i + size
		if end > len(s) {
			end = len(s)
		}
		out = append(out, []byte(s[i:end]))
	}
	return out
}

// scanExObs 摊平成可比较的观测值（Usage 的三个计数是指针，整体 == 比不了）。
func scanExObs(p, c, total, hit, miss, write int64, content int, usage, cache, done bool) Observation {
	u := Usage{HasCache: cache, CacheHit: hit, CacheMiss: miss, CacheWrite: write}
	if usage {
		u.PromptTokens, u.CompletionTokens, u.TotalTokens = &p, &c, &total
	}
	return Observation{Usage: u, HasUsage: usage, SawDone: done, ContentBytes: content}
}

func scanExEqObs(a, b Observation) bool {
	return a.HasUsage == b.HasUsage && a.SawDone == b.SawDone && a.ContentBytes == b.ContentBytes &&
		a.Usage.HasCache == b.Usage.HasCache && a.Usage.CacheHit == b.Usage.CacheHit && a.Usage.CacheMiss == b.Usage.CacheMiss && a.Usage.CacheWrite == b.Usage.CacheWrite &&
		int64p(a.Usage.PromptTokens) == int64p(b.Usage.PromptTokens) && int64p(a.Usage.CompletionTokens) == int64p(b.Usage.CompletionTokens) && int64p(a.Usage.TotalTokens) == int64p(b.Usage.TotalTokens)
}

// TestScanExByteForByteAcrossChunkPatterns 锁「透传保真 + 观测与分块方式无关」：
// 同一份流，无论上游怎么切片、下游用多大的缓冲，读到的字节必须逐一相同，扫出来的
// 数字也必须相同（chunk 边界把 usage JSON 切成半截是最容易漏数的地方）。
func TestScanExByteForByteAcrossChunkPatterns(t *testing.T) {
	want := scanExObs(21, 5, 26, 6, 15, 0, 20, true, true, true)
	cut := strings.Index(scanExSSE, `"prompt_tokens":`) + len(`"prompt_tokens":`)
	cases := []struct {
		name   string
		chunks [][]byte
		buf    int
	}{
		{"整块一次给", [][]byte{[]byte(scanExSSE)}, 4096},
		{"逐字节给（1 字节 1 块）", scanExChunks(scanExSSE, 1), 4096},
		{"usage 的数字被切在 token 中间", [][]byte{[]byte(scanExSSE[:cut]), []byte(scanExSSE[cut:])}, 4096},
		{"按帧切", [][]byte{[]byte(scanExSSE[:64]), []byte(scanExSSE[64:128]), []byte(scanExSSE[128:])}, 4096},
		{"定长 3 字节切", scanExChunks(scanExSSE, 3), 4096},
		{"整块给但下游只有 7 字节缓冲", [][]byte{[]byte(scanExSSE)}, 7},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ob := newObserver(scanOpenAISSE)
			r := newScanReader(&scanExSource{chunks: c.chunks}, ob, 1<<20)
			got, err := scanExDrain(r, c.buf)
			_ = r.Close()
			if err != nil || got != scanExSSE {
				t.Fatalf("透传字节被改动: err=%v\ngot  %q\nwant %q", err, got, scanExSSE)
			}
			if obs := ob.observation(); !scanExEqObs(obs, want) {
				t.Fatalf("分块方式改变了观测: got %+v want %+v", obs, want)
			}
		})
	}
}

// TestScanExUsageExtractionPerDialect 锁三种方言的取数口径，以及「上游没报」与
// 「报 0」的差别：缺 usage 只留零值，绝不报错、也不硬造数字。
func TestScanExUsageExtractionPerDialect(t *testing.T) {
	cases := []struct {
		name string
		mode scanMode
		body string
		want Observation
	}{
		{"SSE：usage 只在末帧", scanOpenAISSE, scanExSSE, scanExObs(21, 5, 26, 6, 15, 0, 20, true, true, true)},
		{"SSE：缺 usage 只留零值，垃圾帧不报错", scanOpenAISSE, scanExNoUsage + "data: {\"x\":1}\n", scanExObs(0, 0, 0, 0, 0, 0, 7, false, false, false)},
		{"整体 JSON：DeepSeek 显式 hit/miss", scanOpenAIJSON, scanExDeepSeekJSON, scanExObs(8, 4, 12, 2, 6, 0, 2, true, true, false)},
		{"整体 JSON：cached 大于 prompt 要夹住", scanOpenAIJSON, `{"usage":{"prompt_tokens":3,"prompt_tokens_details":{"cached_tokens":9,"cache_write_tokens":1}}}`, scanExObs(3, 0, 0, 3, 0, 1, 0, true, true, false)},
		{"整体 JSON：中间设备插了 HTML", scanOpenAIJSON, "<html>zz</html>", scanExObs(0, 0, 0, 0, 0, 0, 0, false, false, false)},
		{"Ollama：done 行平铺 eval 计数", scanOllamaNDJSON, scanExOllama, scanExObs(12, 9, 21, 0, 0, 0, 14, true, false, true)},
		{"Ollama：没有 done 行", scanOllamaNDJSON, "{\"message\":{\"content\":\"zz\"}}\n", scanExObs(0, 0, 0, 0, 0, 0, 2, false, false, false)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ob := newObserver(c.mode)
			r := newScanReader(&scanExSource{chunks: scanExChunks(c.body, 5)}, ob, 1<<20)
			got, err := scanExDrain(r, 64)
			if err != nil || got != c.body {
				t.Fatalf("观测不许改动透传: err=%v got=%q", err, got)
			}
			if obs := ob.observation(); !scanExEqObs(obs, c.want) {
				t.Fatalf("取数口径错误: got %+v want %+v", obs, c.want)
			}
			_ = r.Close()
		})
	}
}

// TestScanExLimitIsExplicitFailure 锁体积执法：读满限额必须报出 executor_body_too_large
// （可 errors.Is 到 ErrBodyLimit）而不是伪装成干净 EOF —— 「没错误 + 零用量」等于白送
// 一次上游调用不记账。限额内的字节一个不少，且错误是粘性的（再读还是同一个失败）。
func TestScanExLimitIsExplicitFailure(t *testing.T) {
	payload := scanExSSE + "data: [DONE]\n\n"
	cut := len(payload) / 2
	// 两行的期望都按读器语义钉住：Read 里 budget<=0 即报越限，所以「恰好等于限额」也要在读完后多挨一次错误（scan.go:393-397）。
	for _, c := range []struct {
		name      string
		src       string
		limit     int64
		wantBytes string
		want      Observation
	}{
		{"越过上限：只给得出限额内的前缀", payload, int64(cut), payload[:cut], scanExObs(0, 0, 0, 0, 0, 0, 20, false, false, false)},
		{"恰好等于上限：整份给完，仍报越限", payload, int64(len(payload)), payload, scanExObs(21, 5, 26, 6, 15, 0, 20, true, true, true)},
	} {
		t.Run(c.name, func(t *testing.T) {
			ob := newObserver(scanOpenAISSE)
			r := newScanReader(&scanExSource{chunks: [][]byte{[]byte(c.src)}}, ob, c.limit)
			got, err := scanExDrain(r, 4096)
			var ee *ExecutionError
			if !asExecutionError(err, &ee) || ee.Code != ReasonBodyTooLarge || !errors.Is(err, ErrBodyLimit) {
				t.Fatalf("越限必须报显式截断错误，got %v", err)
			}
			if got != c.wantBytes {
				t.Fatalf("限额内的字节没给全: got %q want %q", got, c.wantBytes)
			}
			if _, err2 := r.Read(make([]byte, 8)); err2 == nil || !errors.Is(err2, ErrBodyLimit) {
				t.Fatalf("越限之后的读取必须恒返回截断错误（不能变成 EOF）: %v", err2)
			}
			_ = r.Close()
			if obs := ob.observation(); !scanExEqObs(obs, c.want) {
				t.Fatalf("截断后的观测不对: got %+v want %+v", obs, c.want)
			}
		})
	}
	// 对照组：限额够用时必须是干净 EOF，一个错误都不报。
	ob := newObserver(scanOpenAISSE)
	r := newScanReader(&scanExSource{chunks: [][]byte{[]byte(scanExSSE)}}, ob, int64(len(scanExSSE))+1)
	got, err := scanExDrain(r, 4096)
	if err != nil || got != scanExSSE {
		t.Fatalf("限额内必须干净收尾: %q %v", got, err)
	}
	_ = r.Close()
}

// TestScanExOversizedBuffersKeepPassthrough 锁两个防御性缓冲：行缓冲只留尾部 4096、
// 整体 JSON 观测缓冲只攒 512KiB —— 截尾的后果最多是「usage 读不到」，绝不允许改透传
// 字节，也不允许报错（§2.9 第 7 条：不能为了观测把整条流缓存在内存里）。
func TestScanExOversizedBuffersKeepPassthrough(t *testing.T) {
	huge := "data: {\"x\":\"" + strings.Repeat("a", maxLineBuffer+4096) + "\"}" // 没有换行的巨帧
	payload := huge + "\n\n" + scanExSSE
	t.Run("半行越界之后仍能认出收尾", func(t *testing.T) {
		ob := newObserver(scanOpenAISSE)
		r := newScanReader(&scanExSource{chunks: [][]byte{[]byte(huge), []byte("\n\n"), []byte(scanExSSE)}}, ob, 1<<20)
		got, err := scanExDrain(r, 4096)
		_ = r.Close()
		if err != nil || got != payload {
			t.Fatalf("越界截尾改了透传字节: err=%v len=%d want=%d", err, len(got), len(payload))
		}
		if obs := ob.observation(); !obs.HasUsage || !obs.SawDone || obs.ContentBytes != 20 {
			t.Fatalf("巨帧之后的 usage 帧必须仍被扫到: %+v", obs)
		}
	})
	t.Run("整体 JSON 越过观测缓冲只丢观测", func(t *testing.T) {
		body := `{"choices":[{"message":{"content":"` + strings.Repeat("x", maxObservationBuffer+1024) + `"}}],"usage":{"prompt_tokens":3,"total_tokens":3}}`
		ob := newObserver(scanOpenAIJSON)
		r := newScanReader(&scanExSource{chunks: scanExChunks(body, 8192)}, ob, 4<<20)
		got, err := scanExDrain(r, 16384)
		_ = r.Close()
		if err != nil || got != body {
			t.Fatalf("超大响应体被改动: err=%v len=%d", err, len(got))
		}
		if obs := ob.observation(); obs.HasUsage {
			t.Fatalf("截尾允许读不到 usage，但不许读错: %+v", obs)
		}
	})
}

// TestScanExDetectStreamAndModeFor 锁「怎么扫」的唯一真相：请求体的 stream 布尔与
// 协议/流式标志到方言的映射，未知协议一律 scanNone（不猜方言）。
func TestScanExDetectStreamAndModeFor(t *testing.T) {
	for _, c := range []struct {
		body string
		want bool
	}{
		{`{"stream":true}`, true},
		{`{"stream":true,"model":"zz"}`, true},
		{`{"stream":false}`, false},
		{`{"model":"zz"}`, false},
		{`{"stream":tru`, false},     // 坏 JSON 不瞎猜：留给正文改写去报错
		{`[{"stream":true}]`, false}, // 不是对象
		{`{"stream":"true"}`, false},
		{`{"options":{"stream":true}}`, false}, // 嵌套里的不算
		{`{"zz":"stream", "stream":1}`, false},
	} {
		if got := DetectStream([]byte(c.body)); got != c.want {
			t.Errorf("DetectStream(%q) = %v，期望 %v", c.body, got, c.want)
		}
	}
	for _, c := range []struct {
		p      Protocol
		stream bool
		want   scanMode
	}{
		{ProtocolOpenAIChat, true, scanOpenAISSE},
		{ProtocolOpenAIChat, false, scanOpenAIJSON},
		{ProtocolOllamaNative, true, scanOllamaNDJSON},
		{ProtocolOllamaNative, false, scanOllamaNDJSON},
		{Protocol("zz_unknown"), true, scanNone},
	} {
		if got := modeFor(c.p, c.stream); got != c.want {
			t.Errorf("modeFor(%q, %v) = %v，期望 %v", c.p, c.stream, got, c.want)
		}
	}
	// scanNone 不给观测器（未启用正文处理时不攒任何缓冲），读取器仍须原样透传。
	ob := newObserver(scanNone)
	r := newScanReader(&scanExSource{chunks: [][]byte{[]byte(scanExSSE)}}, ob, 1<<20)
	got, err := scanExDrain(r, 128)
	_ = r.Close()
	if err != nil || got != scanExSSE {
		t.Fatalf("无观测模式下透传被改动: %q %v", got, err)
	}
	if o := (Outcome{obs: ob}).Observed(); o != (Observation{}) {
		t.Fatalf("无观测模式必须给出零值观测: %+v", o)
	}
}

// TestScanExConcurrentReadersIndependent 是两个 goroutine 同时扫两条独立流：
// observer/lineBuf 都是每次交换各一份，结论必须互不串（配合 -race 跑）。
func TestScanExConcurrentReadersIndependent(t *testing.T) {
	type res struct {
		body string
		obs  Observation
		err  error
	}
	want := scanExObs(21, 5, 26, 6, 15, 0, 20, true, true, true)
	done := make(chan res, 2)
	for i := 0; i < 2; i++ {
		go func() {
			ob := newObserver(scanOpenAISSE)
			r := newScanReader(&scanExSource{chunks: scanExChunks(scanExSSE, 1)}, ob, 1<<20)
			body, err := scanExDrain(r, 5)
			_ = r.Close()
			done <- res{body, ob.observation(), err}
		}()
	}
	for i := 0; i < 2; i++ {
		got := <-done
		if got.err != nil || got.body != scanExSSE {
			t.Errorf("第 %d 条并发流透传被改动: %v", i, got.err)
		}
		if !scanExEqObs(got.obs, want) {
			t.Errorf("第 %d 条并发流观测串了: %+v", i, got.obs)
		}
	}
}
