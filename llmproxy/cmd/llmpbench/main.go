// Command llmpbench 是 llmproxy 的并发压测工具：回答「网关同时能扛多少请求」。
//
// 两种模式：
//
//	stub（默认）  自建一个假上游，并用**独立的运行时目录**拉起一个 llmproxy 实例，
//	              全程本机、不消耗任何上游额度，用来测「网关自身」的并发承载能力。
//	live         直接压一个已经在跑的 llmproxy，会真的打到上游（花钱、可能触发限速）。
//
// 设计要点：
//
//   - 绝不碰正在运行的服务：stub 模式用临时 LLMPROXY_HOME、独立端口、独立 SQLite，
//     跑完即删（-keep 可保留排查）。
//   - 假上游自己统计「同时正在处理的请求数峰值」，这个数直接回答「网关真正并发转发了多少路」，
//     而不是只看压测端发出去多少。
//   - 客户端连接池按并发档位放大，避免压测端自己先成为瓶颈。
//   - 每档重置计数，梯度加压，失败率超过阈值就停 —— 找到拐点而不是把机器打爆。
//   - 压测结束、子进程退出后再读它的数据库，校验「客户端成功数 / 假上游收到数 / 网关记账数」
//     三者是否一致，顺带验证单连接 SQLite 记账路径在并发下没丢数据。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// benchKey 是 stub 模式下压测端与临时实例约定的下游密钥，与真实配置无关。
const benchKey = "sk-bench-local"

type options struct {
	mode          string
	target        string
	key           string
	model         string
	concLevels    []int
	perLevel      int
	stubDelay     time.Duration
	stream        bool
	timeout       time.Duration
	promptBytes   int
	proxyBin      string
	childLogLevel string
	stopErrRate   float64
	cooldown      time.Duration
	keep          bool
	asJSON        bool
	yes           bool
}

// levelResult 是一个并发档位的测量结果。
type levelResult struct {
	Conc     int            `json:"conc"`
	Total    int            `json:"total"`
	OK       int            `json:"ok"`
	Fail     int            `json:"fail"`
	RPS      float64        `json:"rps"`
	WallMs   float64        `json:"wall_ms"`
	P50      float64        `json:"p50_ms"`
	P90      float64        `json:"p90_ms"`
	P99      float64        `json:"p99_ms"`
	Max      float64        `json:"max_ms"`
	PeakUp   int64          `json:"peak_upstream_inflight"`
	Upstream int64          `json:"upstream_served"`
	RSSMB    float64        `json:"gateway_rss_mb,omitempty"`
	ErrKinds map[string]int `json:"errors,omitempty"`
}

type report struct {
	Mode        string        `json:"mode"`
	Target      string        `json:"target"`
	Model       string        `json:"model"`
	Stream      bool          `json:"stream"`
	StubDelayMs int64         `json:"stub_delay_ms"`
	PromptBytes int           `json:"prompt_bytes"`
	Levels      []levelResult `json:"levels"`
	BaseRSSMB   float64       `json:"gateway_rss_baseline_mb,omitempty"`
	Accounted   string        `json:"gateway_accounting,omitempty"`
	ChildLog    string        `json:"child_log,omitempty"`
}

// harness 持有一次压测用到的全部资源；teardown 负责按顺序收摊。
type harness struct {
	stub      *stubUpstream
	child     *childProc
	home      string
	target    string
	key       string
	dbPath    string
	keep      bool
	baseRSSMB float64 // 空闲基线，用来算「每路并发增量内存」
}

func (h *harness) teardown() {
	if h.child != nil {
		h.child.stop()
	}
	if h.stub != nil {
		h.stub.close()
	}
	if h.home != "" {
		if h.keep {
			fmt.Printf("\n临时运行时目录已保留（排查用）：%s\n", h.home)
		} else {
			_ = os.RemoveAll(h.home)
		}
	}
}

func main() {
	var (
		mode        = flag.String("mode", "stub", "测试目标：stub=本机假上游（默认，不花钱）| live=已在运行的真实网关")
		target      = flag.String("target", "", "live 模式的网关地址，默认 http://127.0.0.1:8787")
		key         = flag.String("key", "", "下游 API key（live 模式默认读 $LLMPROXY_KEY）")
		model       = flag.String("model", "deepseek-flash", "下游模型名")
		concList    = flag.String("concurrency", "10,50,100,200,400,800", "并发档位，逗号分隔（梯度加压）")
		perLevel    = flag.Int("n", 200, "每档总请求数")
		stubDelay   = flag.Int("stub-delay", 0, "假上游处理延迟（毫秒），模拟真实模型延迟")
		stream      = flag.Bool("stream", false, "使用流式（SSE）请求")
		timeoutS    = flag.Int("timeout", 120, "单请求超时（秒）")
		promptBytes = flag.Int("prompt-bytes", 64, "prompt 正文的字节数")
		proxyBin    = flag.String("proxy-bin", "./llmproxy", "stub 模式要拉起的 llmproxy 可执行文件")
		childLog    = flag.String("child-log-level", "info", "stub 模式子进程日志级别（warn 可减少 IO 干扰）")
		stopErr     = flag.Float64("stop-error-rate", 0.05, "某档失败率超过该值即停止加压")
		cooldownS   = flag.Int("cooldown", 10, "档位之间的冷却秒数（等上一档的临时端口回收，避免后一档被 TIME_WAIT 拖累）")
		keep        = flag.Bool("keep", false, "保留临时运行时目录")
		asJSON      = flag.Bool("json", false, "以 JSON 输出结果")
		yes         = flag.Bool("yes", false, "live 模式确认：真的会打到上游并可能触发熔断")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `llmpbench — llmproxy 并发压测

用法:
  llmpbench [选项]

示例:
  # 默认：假上游起量，测网关自身并发能力（免费、安全）
  go run ./cmd/llmpbench -concurrency 50,200,500,1000 -n 300

  # 模拟真实模型延迟（每请求 2 秒），看网关能同时挂住多少路
  go run ./cmd/llmpbench -stub-delay 2000 -concurrency 100,400,800 -n 100

  # 压真实网关（会花钱、可能触发 60 秒熔断，务必想清楚再跑）
  go run ./cmd/llmpbench -mode live -key $LLMPROXY_KEY -concurrency 4,8 -n 16 -yes

选项:
`)
		flag.PrintDefaults()
	}
	flag.Parse()

	levels, err := parseLevels(*concList)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(2)
	}
	o := options{
		mode:          strings.ToLower(strings.TrimSpace(*mode)),
		target:        *target,
		key:           *key,
		model:         *model,
		concLevels:    levels,
		perLevel:      *perLevel,
		stubDelay:     time.Duration(*stubDelay) * time.Millisecond,
		stream:        *stream,
		timeout:       time.Duration(*timeoutS) * time.Second,
		promptBytes:   *promptBytes,
		proxyBin:      *proxyBin,
		childLogLevel: *childLog,
		stopErrRate:   *stopErr,
		cooldown:      time.Duration(*cooldownS) * time.Second,
		keep:          *keep,
		asJSON:        *asJSON,
		yes:           *yes,
	}

	rep, err := run(o)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
	if o.asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return
	}
	printReport(rep)
}

func parseLevels(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("并发档位 %q 不是整数", part)
		}
		if v < 1 || v > 100000 {
			return nil, fmt.Errorf("并发档位 %d 超出合理范围 1~100000", v)
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("至少需要一个并发档位")
	}
	sort.Ints(out)
	return out, nil
}

// run 按模式准备环境，然后跑完整个梯度。
func run(o options) (*report, error) {
	h := &harness{target: o.target, keep: o.keep}
	defer h.teardown()

	switch o.mode {
	case "stub":
		stub, err := startStub(o.stubDelay)
		if err != nil {
			return nil, fmt.Errorf("启动假上游失败: %w", err)
		}
		h.stub = stub

		home, err := os.MkdirTemp("", "llmpbench-")
		if err != nil {
			return nil, err
		}
		h.home = home

		port, err := freePort()
		if err != nil {
			return nil, err
		}
		if err := writeChildConfig(home, port, stub.url, o.childLogLevel); err != nil {
			return nil, err
		}
		cp, err := startChild(o.proxyBin, home, port)
		if err != nil {
			return nil, err
		}
		h.child = cp
		h.target = fmt.Sprintf("http://127.0.0.1:%d/v1/chat/completions", port)
		h.key = benchKey
		h.dbPath = filepath.Join(home, "data", "llmproxy.db")
		// 基线内存：刚起来、没请求时的常驻内存
		time.Sleep(300 * time.Millisecond)
		h.baseRSSMB = readRSSMB(cp.pid)

		fmt.Printf("模式       stub（本机假上游 + 独立实例，不消耗上游额度）\n")
		fmt.Printf("网关实例   pid=%d  %s\n", cp.pid, h.target)
		fmt.Printf("运行时目录 %s\n", home)
		fmt.Printf("假上游     %s  人为延迟=%s\n", stub.url, o.stubDelay)
		fmt.Printf("重要       以上都是临时实例，与正在运行的服务（默认 8787）完全隔离\n")

	case "live":
		if h.target == "" {
			h.target = "http://127.0.0.1:8787"
		}
		if !strings.HasSuffix(h.target, "/chat/completions") {
			h.target = strings.TrimSuffix(h.target, "/") + "/v1/chat/completions"
		}
		h.key = o.key
		if h.key == "" {
			h.key = os.Getenv("LLMPROXY_KEY")
		}
		if h.key == "" {
			return nil, fmt.Errorf("live 模式需要 -key 或环境变量 LLMPROXY_KEY")
		}
		if !o.yes {
			return nil, fmt.Errorf("live 模式会真的打到上游（花钱、可能触发限速与 60 秒熔断，影响共用该网关的其它客户端）。确认无碍后加 -yes")
		}
		fmt.Printf("模式       live（真实上游，会产生费用）\n")
		fmt.Printf("目标       %s\n", h.target)
		fmt.Printf("警告       失败累计到 routing.failure_threshold 会把这家供应商摘掉 cooldown_seconds 秒，\n")
		fmt.Printf("           共用该网关的其它客户端（包括正在跑的对话）会一起失败\n")

	default:
		return nil, fmt.Errorf("未知模式 %q（支持 stub / live）", o.mode)
	}

	rep := &report{
		Mode:        o.mode,
		Target:      h.target,
		Model:       o.model,
		Stream:      o.stream,
		StubDelayMs: o.stubDelay.Milliseconds(),
		PromptBytes: o.promptBytes,
		BaseRSSMB:   h.baseRSSMB,
		Levels:      []levelResult{},
	}

	fmt.Printf("请求       模型=%s 流式=%v prompt=%dB 每档 %d 次 超时=%s\n\n",
		o.model, o.stream, o.promptBytes, o.perLevel, o.timeout)

	// 预热：建连 + 触发一次真实请求，避免把首连开销算进第一档
	if err := warmup(h.target, h.key, o); err != nil {
		fmt.Printf("预热请求失败（继续跑，但第一档可能偏高）：%v\n", err)
	}

	for i, conc := range o.concLevels {
		if h.stub != nil {
			h.stub.reset()
		}
		// 档位之间冷却：上一档的 TIME_WAIT 连接会占着临时端口，不回收会污染下一档
		if i > 0 && o.cooldown > 0 {
			fmt.Printf("（冷却 %s，等上一档的临时端口回收）\n", o.cooldown)
			time.Sleep(o.cooldown)
		}
		lr := runLevel(h, o, conc)
		rep.Levels = append(rep.Levels, lr)
		printLevel(lr)

		if lr.Total > 0 && o.stopErrRate >= 0 {
			if rate := float64(lr.Fail) / float64(lr.Total); rate > o.stopErrRate {
				fmt.Printf("\n失败率 %.1f%% 超过阈值 %.1f%%，停止加压（拐点已找到）\n",
					rate*100, o.stopErrRate*100)
				break
			}
		}
	}

	// 子进程还在跑时不要去开它的库；先收掉实例，再校验记账
	if h.child != nil {
		rep.ChildLog = h.child.logPath
		h.child.stop()
		h.child = nil
		if acct, err := verifyAccounting(h.dbPath, rep.Levels); err == nil {
			rep.Accounted = acct
		} else {
			rep.Accounted = fmt.Sprintf("（读取网关数据库失败: %v）", err)
		}
	}
	if rep.ChildLog == "" && h.home != "" {
		rep.ChildLog = filepath.Join(h.home, "child.out")
	}
	return rep, nil
}

// ------------------------------------------------------------------ 假上游

// stubUpstream 是最小的 OpenAI 兼容上游：睡一会儿（模拟模型延迟）、回一个合法响应，
// 并统计「同时在处理的请求数峰值」—— 这个数就是网关真实并发转发的路数。
type stubUpstream struct {
	srv   *http.Server
	url   string
	delay time.Duration

	inflight int64
	peak     int64
	served   int64
}

func startStub(delay time.Duration) (*stubUpstream, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &stubUpstream{delay: delay}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", s.handleChat)
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
	})
	s.srv = &http.Server{Handler: mux}
	s.url = "http://" + ln.Addr().String() + "/v1"
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

func (s *stubUpstream) close() {
	if s != nil && s.srv != nil {
		_ = s.srv.Close()
	}
}

// reset 清空计数，让每一档的峰值只反映该档。
func (s *stubUpstream) reset() {
	atomic.StoreInt64(&s.peak, 0)
	atomic.StoreInt64(&s.served, 0)
}

func (s *stubUpstream) handleChat(w http.ResponseWriter, r *http.Request) {
	cur := atomic.AddInt64(&s.inflight, 1)
	for {
		p := atomic.LoadInt64(&s.peak)
		if cur <= p || atomic.CompareAndSwapInt64(&s.peak, p, cur) {
			break
		}
	}
	defer atomic.AddInt64(&s.inflight, -1)
	atomic.AddInt64(&s.served, 1)

	// 必须把请求体读干净，否则下游会拿到 broken pipe
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var probe struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	_ = json.Unmarshal(body, &probe)

	if s.delay > 0 {
		time.Sleep(s.delay)
	}

	// token 数按字节粗估，只用于让网关记账路径有真实数据可写
	prompt := int64(len(body)/4 + 1)
	completion := int64(16)
	total := prompt + completion

	if probe.Stream {
		s.writeSSE(w, probe.Model, prompt, completion, total)
		return
	}
	resp := map[string]any{
		"id":      "chatcmpl-bench",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   probe.Model,
		"choices": []map[string]any{{
			"index":         0,
			"message":       map[string]string{"role": "assistant", "content": "ok"},
			"finish_reason": "stop",
		}},
		"usage": map[string]int64{
			"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": total,
		},
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

// writeSSE 产出合法的流式响应，末尾 chunk 带 usage —— 网关正是靠它提取 token 数。
func (s *stubUpstream) writeSSE(w http.ResponseWriter, model string, prompt, completion, total int64) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	write := func(v any) {
		b, _ := json.Marshal(v)
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(b)
		_, _ = w.Write([]byte("\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}

	for i := 0; i < 4; i++ {
		write(map[string]any{
			"id": "chatcmpl-bench", "object": "chat.completion.chunk",
			"created": time.Now().Unix(), "model": model,
			"choices": []map[string]any{{
				"index": 0, "delta": map[string]string{"content": "ok"}, "finish_reason": nil,
			}},
		})
	}
	write(map[string]any{
		"id": "chatcmpl-bench", "object": "chat.completion.chunk",
		"created": time.Now().Unix(), "model": model,
		"choices": []map[string]any{{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}},
		"usage": map[string]int64{
			"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": total,
		},
	})
	_, _ = w.Write([]byte("data: [DONE]\n\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

// ------------------------------------------------------------------ 临时实例

type childProc struct {
	cmd     *exec.Cmd
	pid     int
	home    string
	logPath string
	file    *os.File
}

// startChild 用独立运行时目录拉起一个 llmproxy 实例。
//
// 子进程的 stdout/stderr 一律重定向到文件：如果接的是管道又不读，
// 高并发下日志写满管道缓冲区会把子进程整个卡死，测量结果就废了。
func startChild(bin, home string, port int) (*childProc, error) {
	abs, err := filepath.Abs(bin)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(abs); err != nil || st.IsDir() {
		return nil, fmt.Errorf("找不到 llmproxy 可执行文件 %s（先执行 go build -o llmproxy ./cmd/llmproxy）", abs)
	}
	logPath := filepath.Join(home, "child.out")
	f, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(abs, "start")
	cmd.Env = envWith("LLMPROXY_HOME", home)
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("拉起 llmproxy 失败: %w", err)
	}
	cp := &childProc{cmd: cmd, pid: cmd.Process.Pid, home: home, logPath: logPath, file: f}
	if err := waitReady(port, 20*time.Second); err != nil {
		cp.stop()
		return nil, fmt.Errorf("临时实例未就绪: %w（日志见 %s）", err, logPath)
	}
	return cp, nil
}

func (c *childProc) stop() {
	if c == nil || c.cmd == nil || c.cmd.Process == nil {
		return
	}
	_ = c.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _, _ = c.cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = c.cmd.Process.Kill()
		<-done
	}
	if c.file != nil {
		_ = c.file.Close()
	}
	c.cmd = nil
}

// sampleRSS 周期性采样子进程常驻内存。停止采样后读 peak，得到这一档的峰值。
func (c *childProc) sampleRSS() (stop func(), peakMB func() float64) {
	var peak int64
	done := make(chan struct{})
	finished := make(chan struct{})
	pid := c.pid
	go func() {
		defer close(finished)
		t := time.NewTicker(150 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if v := readRSSKB(pid); v > atomic.LoadInt64(&peak) {
					atomic.StoreInt64(&peak, v)
				}
			}
		}
	}()
	return func() { close(done); <-finished }, func() float64 {
		return float64(atomic.LoadInt64(&peak)) / 1024
	}
}

func readRSSKB(pid int) int64 {
	if pid <= 0 {
		return 0
	}
	out, err := exec.Command("/bin/ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

func readRSSMB(pid int) float64 { return float64(readRSSKB(pid)) / 1024 }

func waitReady(port int, timeout time.Duration) error {
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("等待 %s 就绪超时", url)
}

// envWith 覆盖式设置环境变量（去掉已有的同名项，避免重复项语义不确定）。
func envWith(key, val string) []string {
	prefix := key + "="
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, prefix) {
			continue
		}
		out = append(out, kv)
	}
	return append(out, prefix+val)
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// writeChildConfig 生成压测专用配置：只有一个指向假上游的供应商。
//
// routing.retry 设成 1（只尝试一次）：重试会把一次失败放大成多次上游调用，
// 掩盖真实容量。failure_threshold 拉满，避免假上游偶发抖动触发熔断。
func writeChildConfig(home string, port int, stubURL, logLevel string) error {
	cfg := fmt.Sprintf(`# llmpbench 自动生成 —— 仅用于并发压测，用完即删
server:
  host: 127.0.0.1
  port: %d
  api_keys:
    - %s
  max_body_mb: 16
  request_timeout_ms: 600000
routing:
  retry: 1
  failure_threshold: 1000
  cooldown_seconds: 1
providers:
  - name: bench-stub
    enabled: true
    base_url: %s
    api_key: sk-bench-upstream
    weight: 10
    proxy: direct
    timeout_ms: 600000
    models: ["*"]
database:
  path: ""
  retain_days: 1
log:
  level: %s
  max_mb: 10
  keep: 1
`, port, benchKey, stubURL, logLevel)
	return os.WriteFile(filepath.Join(home, "config.yaml"), []byte(cfg), 0o600)
}

// ------------------------------------------------------------------ 加压

// warmup 先打一发，把建连、DNS、TLS 等一次性开销挪出测量区间。
func warmup(target, key string, o options) error {
	client := &http.Client{Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()
	return doRequest(client, target, key, o, -1)
}

// runLevel 用 workers 个协程同时打 total 个请求，返回这一档的完整测量结果。
func runLevel(h *harness, o options, conc int) levelResult {
	total := o.perLevel
	if total < 1 {
		total = 1
	}
	workers := conc
	if workers > total {
		workers = total
	}

	client := &http.Client{
		Timeout: o.timeout,
		Transport: &http.Transport{
			// 压测端连接池必须比目标并发大，否则瓶颈会在我们自己身上
			MaxIdleConns:        workers + 64,
			MaxIdleConnsPerHost: workers + 64,
			MaxConnsPerHost:     0,
			ForceAttemptHTTP2:   true,
			IdleConnTimeout:     30 * time.Second,
		},
	}
	defer client.CloseIdleConnections()

	lat := make([]float64, total)
	var (
		mu       sync.Mutex
		errKinds = map[string]int{}
		okN      int64
		failN    int64
	)

	jobs := make(chan int, total)
	for i := 0; i < total; i++ {
		jobs <- i
	}
	close(jobs)

	stopSample := func() {}
	rss := func() float64 { return 0 }
	if h.child != nil {
		stopSample, rss = h.child.sampleRSS()
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // 起跑线：让这一档的请求尽量同时压出去
			for idx := range jobs {
				t0 := time.Now()
				err := doRequest(client, h.target, h.key, o, idx)
				lat[idx] = float64(time.Since(t0).Milliseconds())
				if err != nil {
					atomic.AddInt64(&failN, 1)
					kind := classifyErr(err)
					mu.Lock()
					errKinds[kind]++
					mu.Unlock()
					continue
				}
				atomic.AddInt64(&okN, 1)
			}
		}()
	}

	wallStart := time.Now()
	close(start)
	wg.Wait()
	wall := time.Since(wallStart)
	stopSample()

	sorted := append([]float64(nil), lat...)
	sort.Float64s(sorted)

	lr := levelResult{
		Conc:     workers,
		Total:    total,
		OK:       int(atomic.LoadInt64(&okN)),
		Fail:     int(atomic.LoadInt64(&failN)),
		WallMs:   float64(wall.Milliseconds()),
		P50:      pct(sorted, 50),
		P90:      pct(sorted, 90),
		P99:      pct(sorted, 99),
		Max:      pct(sorted, 100),
		RSSMB:    rss(),
		ErrKinds: errKinds,
	}
	if wall > 0 {
		lr.RPS = float64(total) / wall.Seconds()
	}
	if h.stub != nil {
		lr.PeakUp = atomic.LoadInt64(&h.stub.peak)
		lr.Upstream = atomic.LoadInt64(&h.stub.served)
	}
	return lr
}

func doRequest(client *http.Client, target, key string, o options, idx int) error {
	content := "ping"
	if o.promptBytes > 0 {
		content = strings.Repeat("x", o.promptBytes)
	}
	payload := map[string]any{
		"model":    o.model,
		"messages": []map[string]string{{"role": "user", "content": fmt.Sprintf("%s#%d", content, idx)}},
	}
	if o.stream {
		payload["stream"] = true
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	if o.stream {
		req.Header.Set("Accept", "text/event-stream")
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		var e struct {
			Error struct {
				Type string `json:"type"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error.Type != "" {
			return fmt.Errorf("HTTP %d %s", resp.StatusCode, e.Error.Type)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// 必须读完：不读完连接不会归还连接池，压测端自己会先崩
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func classifyErr(err error) string {
	if err == nil {
		return "ok"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "too many open files"):
		return "EMFILE：文件描述符耗尽"
	case strings.Contains(msg, "assign requested address"):
		return "本地端口耗尽（压测端限制，不是网关问题）"
	case strings.Contains(msg, "connection refused"):
		return "连接被拒（对端 accept 队列满或没在监听）"
	case strings.HasPrefix(msg, "HTTP "):
		return msg
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return "超时"
	case strings.Contains(msg, "EOF"), strings.Contains(msg, "reset by peer"):
		return "连接被重置 / EOF"
	default:
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		return msg
	}
}

func pct(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ------------------------------------------------------------------ 输出

// topErrors 按出现次数从多到少返回失败原因，保证输出稳定可对比。
func topErrors(kinds map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	all := make([]kv, 0, len(kinds))
	for k, v := range kinds {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	out := []string{}
	for i, e := range all {
		if i >= n {
			break
		}
		out = append(out, fmt.Sprintf("%s ×%d", e.k, e.v))
	}
	return out
}

func printLevel(lr levelResult) {
	peak := "-"
	if lr.PeakUp > 0 {
		peak = strconv.FormatInt(lr.PeakUp, 10)
	}
	rss := "-"
	if lr.RSSMB > 0 {
		rss = fmt.Sprintf("%.0fM", lr.RSSMB)
	}
	fmt.Printf("conc=%-6d req=%-5d ok=%-5d fail=%-4d rps=%-8.1f p50=%-6.0f p90=%-6.0f p99=%-7.0f max=%-7.0f upstream_peak=%-6s rss=%-6s\n",
		lr.Conc, lr.Total, lr.OK, lr.Fail, lr.RPS, lr.P50, lr.P90, lr.P99, lr.Max, peak, rss)
	for _, s := range topErrors(lr.ErrKinds, 3) {
		fmt.Printf("          └ 失败: %s\n", s)
	}
}

func printReport(rep *report) {
	fmt.Printf("\n%-6s %-7s %-7s %-6s %10s %8s %8s %8s %8s %10s %8s\n",
		"conc", "reqs", "ok", "fail", "rps", "p50ms", "p90ms", "p99ms", "maxms", "up_peak", "rss")
	for _, l := range rep.Levels {
		peak := "-"
		if l.PeakUp > 0 {
			peak = strconv.FormatInt(l.PeakUp, 10)
		}
		rss := "-"
		if l.RSSMB > 0 {
			rss = fmt.Sprintf("%.0fM", l.RSSMB)
		}
		fmt.Printf("%-6d %-7d %-7d %-6d %10.1f %8.0f %8.0f %8.0f %8.0f %10s %8s\n",
			l.Conc, l.Total, l.OK, l.Fail, l.RPS, l.P50, l.P90, l.P99, l.Max, peak, rss)
	}
	fmt.Printf("\n（p50/p90/p99 是客户端观测的端到端耗时；up_peak = 假上游同时在处理的请求数峰值，\n")
	fmt.Printf("  即网关真正并发转发了多少路；rss = 网关进程常驻内存峰值）\n")

	printConclusion(rep)

	if rep.Accounted != "" {
		fmt.Printf("记账校验   %s\n", rep.Accounted)
	}
	if rep.ChildLog != "" {
		fmt.Printf("子进程日志 %s\n", rep.ChildLog)
	}
}

func printConclusion(rep *report) {
	fmt.Printf("\n结论\n")
	if len(rep.Levels) == 0 {
		fmt.Printf("  没有采集到任何档位数据\n")
		return
	}
	// 零失败的最大档位
	var clean *levelResult
	for i := range rep.Levels {
		if rep.Levels[i].Fail == 0 {
			clean = &rep.Levels[i]
		}
	}
	if clean != nil {
		fmt.Printf("  零失败的最大并发：%d（RPS %.1f，p99 %.0fms，max %.0fms）\n",
			clean.Conc, clean.RPS, clean.P99, clean.Max)
	} else {
		fmt.Printf("  第一档就有失败：网关或上游在这个并发下已经不稳，先看上面的失败原因\n")
	}

	// 出现失败的档位
	for _, l := range rep.Levels {
		if l.Fail > 0 {
			fmt.Printf("  首次出现失败的档位：conc=%d，失败 %d/%d（%.1f%%）\n",
				l.Conc, l.Fail, l.Total, float64(l.Fail)/float64(l.Total)*100)
			for _, s := range topErrors(l.ErrKinds, 2) {
				fmt.Printf("      %s\n", s)
			}
			break
		}
	}
	connStormNote(rep.Levels)

	// 延迟拐点：p99 相比最小档位放大 5 倍以上
	if len(rep.Levels) >= 2 {
		base := rep.Levels[0].P99
		if base <= 0 {
			base = 1
		}
		for _, l := range rep.Levels[1:] {
			if l.P99 > base*5 {
				fmt.Printf("  延迟拐点：conc=%d 时 p99 放大到 %.0fms（最低档 %.0fms 的 %.1f 倍），已接近饱和\n",
					l.Conc, l.P99, base, l.P99/base)
				break
			}
		}
	}

	// 真并行 vs 排队。注意两种会让这个比值失去意义的情况：
	//   1) 上游延迟接近 0 —— 请求根本来不及重叠，峰值只反映调度噪声
	//   2) 本档有失败 —— 并发峰值被「连不上」的请求压低了，不是网关在排队
	last := rep.Levels[len(rep.Levels)-1]
	if last.PeakUp > 0 {
		switch {
		case rep.StubDelayMs < 50:
			fmt.Printf("  注：假上游延迟≈0，请求来不及重叠，「上游并发峰值」这一档不作数；\n")
			fmt.Printf("      它测到的是吞吐上限（%.1f RPS）。要看并发承载能力请加 -stub-delay 2000 再跑一次\n", last.RPS)
		case last.Fail > 0:
			fmt.Printf("  注：本档有 %d 个请求失败，上游并发峰值 %d 是被失败连接压低的，\n", last.Fail, last.PeakUp)
			fmt.Printf("      不能据此判断网关是否排队；真正到达应用层的数量见下面「记账校验」的网关落库数\n")
		default:
			ratio := float64(last.PeakUp) / float64(last.Conc)
			verdict := "说明网关是真正并行转发，没有内部排队"
			if ratio < 0.9 {
				verdict = "明显小于发出的并发，说明存在排队/串行点（闸门在别处）"
			}
			fmt.Printf("  并行度：conc=%d 时上游并发峰值=%d（%.0f%%），%s\n",
				last.Conc, last.PeakUp, ratio*100, verdict)
		}

		// 每路并发占多少内存：决定了「还能再挂多少路」
		if last.RSSMB > 0 && rep.BaseRSSMB > 0 {
			incr := last.RSSMB - rep.BaseRSSMB
			if incr < 0 {
				incr = 0
			}
			fmt.Printf("  内存：空闲基线 %.0fMB，conc=%d 时峰值 %.0fMB，增量 %.0fMB",
				rep.BaseRSSMB, last.Conc, last.RSSMB, incr)
			if last.PeakUp > 0 {
				perConn := incr / float64(last.PeakUp)
				fmt.Printf("（上游峰值 %d 路，约 %.2fMB/路）", last.PeakUp, perConn)
				if perConn > 0 && last.Fail == 0 {
					fmt.Printf("\n        按 1GB 可用内存估算，大致还能挂 %.0f 路并发",
						(1024-rep.BaseRSSMB)/perConn)
				}
			}
			fmt.Printf("\n")
		}
	}
}

// connStormNote 在失败原因是「压测端自身资源不够」时明确指出来，
// 避免把测试装置的限制误读成网关的并发上限。
func connStormNote(levels []levelResult) {
	var ports, refused, upstream int
	for _, l := range levels {
		for k, v := range l.ErrKinds {
			if strings.Contains(k, "端口耗尽") {
				ports += v
			}
			if strings.Contains(k, "连接被拒") {
				refused += v
			}
			if strings.Contains(k, "upstream_unavailable") {
				upstream += v
			}
		}
	}
	if ports == 0 && refused == 0 && upstream == 0 {
		return
	}
	if ports > 0 {
		fmt.Printf("\n关于「本地端口耗尽」：这是压测端的问题，不是网关的问题。\n")
		fmt.Printf("  connect() 报 can't assign requested address — 本机临时端口池用光了。\n")
		fmt.Printf("  macOS 默认只有 49152~65535 共 16384 个，且 TIME_WAIT 要留 30 秒左右；\n")
		fmt.Printf("  同一个进程里连跑几档高并发，前几档的连接还没回收，后一档就没有端口可用了。\n")
		fmt.Printf("  想压更高：① 档位之间等一会儿再跑（本工具 -cooldown 就是干这个的）\n")
		fmt.Printf("            ② 由人手动扩大端口池（需要 sudo，属于改系统参数，工具不代劳）：\n")
		fmt.Printf("               sudo sysctl -w net.inet.ip.portrange.first=16384\n")
		fmt.Printf("            ③ 把压测端和网关分到两台机器上跑\n")
	}
	if refused > 0 {
		fmt.Printf("\n关于「连接被拒」：内核直接回的 RST，连接没进到应用层。\n")
		fmt.Printf("  Go 在 macOS 上的 listen backlog 只有 128，瞬时建连风暴超过接受队列深度就会被拒。\n")
	}
	if upstream > 0 {
		fmt.Printf("\n关于「HTTP 502 upstream_unavailable」：假上游跑在压测进程里，会被压测端自己拖累，\n")
		fmt.Printf("  这部分失败属于测试装置的固有缺陷，不能算到网关头上。\n")
	}
}

// verifyAccounting 读临时实例的 SQLite，核对「客户端成功 / 上游收到 / 网关落库」三者。
// 子进程退出后再读，避免与运行中的写事务抢锁。
func verifyAccounting(dbPath string, levels []levelResult) (string, error) {
	if dbPath == "" {
		return "", fmt.Errorf("没有数据库路径")
	}
	if _, err := os.Stat(dbPath); err != nil {
		return "", fmt.Errorf("数据库不存在: %w", err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = st.Close() }()

	sum, err := st.Stats(time.Time{}, 0)
	if err != nil {
		return "", err
	}
	var clientOK, upstream int64
	for _, l := range levels {
		clientOK += int64(l.OK)
		upstream += l.Upstream
	}
	return fmt.Sprintf("客户端成功 %d / 假上游收到 %d / 网关落库 %d 条、token 合计 %d（落库数含 1 条预热请求）",
		clientOK, upstream, sum.TotalRequests, sum.TotalTokens), nil
}
