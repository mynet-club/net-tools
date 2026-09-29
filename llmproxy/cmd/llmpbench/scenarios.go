package main

// 场景压测：粘性、重试、多用户限流。默认的梯度加压回答「能扛多少」，
// 这里补的是「行为对不对」—— 用同一套 stub 网关，按场景出一张对比表。
//
//	llmpbench -scenario sticky
//	llmpbench -scenario retry
//	llmpbench -scenario multiuser
//	llmpbench -scenario all
//
// 只跑 stub 模式：场景断言依赖可预期的假上游，live 模式不适用。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type scenarioResult struct {
	Name    string         `json:"name"`
	Passed  bool           `json:"passed"`
	Detail  string         `json:"detail"`
	Numbers map[string]any `json:"numbers,omitempty"`
}

func runScenarios(names []string, o options) ([]scenarioResult, error) {
	if o.mode != "stub" {
		return nil, fmt.Errorf("-scenario 只支持 stub 模式（场景需要可预期的假上游）")
	}
	var out []scenarioResult
	for _, n := range names {
		switch n {
		case "sticky":
			r := scenarioSticky(o)
			out = append(out, r)
		case "retry":
			r, err := scenarioRetry(o)
			if err != nil {
				return out, err
			}
			out = append(out, r)
		case "multiuser":
			r, err := scenarioMultiUser(o)
			if err != nil {
				return out, err
			}
			out = append(out, r)
		default:
			return out, fmt.Errorf("未知场景 %q（支持 sticky / retry / multiuser / all）", n)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- sticky

// scenarioSticky：同一会话钉在同一家；不同会话可以漂移。
// 用两个假上游，断言 X-Llmproxy-Affinity 的 sticky 占比。
func scenarioSticky(o options) scenarioResult {
	const reqs = 40
	h := &harness{keep: o.keep}
	defer h.teardown()

	s1, err := startStub(0)
	if err != nil {
		return scenarioResult{Name: "sticky", Passed: false, Detail: "起假上游失败: " + err.Error()}
	}
	s2, err := startStub(0)
	if err != nil {
		return scenarioResult{Name: "sticky", Passed: false, Detail: "起假上游失败: " + err.Error()}
	}
	h.stub = s1
	home, port, cp, err := startStubGateway(o, stickyConfig(portOr(0), s1.url, s2.url, 0))
	if err != nil {
		return scenarioResult{Name: "sticky", Passed: false, Detail: err.Error()}
	}
	h.home, h.child = home, cp
	target := fmt.Sprintf("http://127.0.0.1:%d/v1/chat/completions", port)

	client := &http.Client{Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()

	counts := map[string]int{}
	for i := 0; i < reqs; i++ {
		// 前一半固定会话，后一半每题一个新会话
		sess := "ses-fixed"
		if i >= reqs/2 {
			sess = "ses-" + strconv.Itoa(i)
		}
		aff, err := postSession(client, target, benchKey, o.model, sess)
		if err != nil {
			counts["error"]++
			continue
		}
		if aff == "" {
			aff = "none"
		}
		counts[aff]++
	}

	fixedSticky := counts["sticky"]
	// 固定会话那半：应当几乎全是 sticky（第一次是 new/cheapest）
	ok := fixedSticky >= reqs/2-2 && counts["error"] == 0
	detail := fmt.Sprintf("固定会话 sticky=%d/%d；漂移/新会话 new+drift=%d",
		fixedSticky, reqs/2, counts["new"]+counts["drift"]+counts["cheapest"]+counts["none"])
	return scenarioResult{
		Name: "sticky", Passed: ok, Detail: detail,
		Numbers: map[string]any{"affinity": counts, "requests": reqs},
	}
}

// ---------------------------------------------------------------- retry

// scenarioRetry：第一家全挂时，重试应落到第二家并成功。
func scenarioRetry(o options) (scenarioResult, error) {
	h := &harness{keep: o.keep}
	defer h.teardown()

	good, err := startStub(0)
	if err != nil {
		return scenarioResult{}, err
	}
	bad, err := startStub(0)
	if err != nil {
		return scenarioResult{}, err
	}
	bad.failAll = true // 全部 500
	h.stub = good

	// 权重：坏的高权重，保证先撞上它；retry: 2 允许换一家
	home, port, cp, err := startStubGateway(o, retryConfig(portOr(0), bad.url, good.url, 0))
	if err != nil {
		return scenarioResult{}, err
	}
	h.home, h.child = home, cp
	target := fmt.Sprintf("http://127.0.0.1:%d/v1/chat/completions", port)

	client := &http.Client{Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()

	const n = 30
	ok, fail := 0, 0
	var latSum float64
	for i := 0; i < n; i++ {
		t0 := time.Now()
		err := doRequest(client, target, benchKey, o, i)
		latSum += float64(time.Since(t0).Milliseconds())
		if err != nil {
			fail++
		} else {
			ok++
		}
	}
	// 全部应当成功：坏的那家会 500，重试到好的那家
	passed := fail == 0 && ok == n
	return scenarioResult{
		Name: "retry", Passed: passed,
		Detail:  fmt.Sprintf("%d/%d 成功（第一家全 500，靠重试落到第二家）；平均 %.1fms", ok, n, latSum/float64(n)),
		Numbers: map[string]any{"ok": ok, "fail": fail, "avg_ms": latSum / float64(n)},
	}, nil
}

// ---------------------------------------------------------------- multiuser

// scenarioMultiUser：多用户并发 + 单用户 RPM 限流。
// 经 admin API 建 3 个真实用户（每人 RPM=10），各打 20 次并发：
// 期望每人有成功也有 429，且互不抢额度。
func scenarioMultiUser(o options) (scenarioResult, error) {
	h := &harness{keep: o.keep}
	defer h.teardown()

	stub, err := startStub(0)
	if err != nil {
		return scenarioResult{}, err
	}
	h.stub = stub

	admin := "sk-bench-admin"
	home, port, cp, err := startStubGateway(o, multiUserConfig(portOr(0), stub.url, admin))
	if err != nil {
		return scenarioResult{}, err
	}
	h.home, h.child = home, cp
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	target := base + "/v1/chat/completions"

	// 建用户 + 设 RPM
	client := &http.Client{Timeout: 15 * time.Second}
	keys := make([]string, 0, 3)
	for _, name := range []string{"ua", "ub", "uc"} {
		token, err := adminCreateUser(client, base, admin, name, 10)
		if err != nil {
			return scenarioResult{}, fmt.Errorf("建用户 %s: %w", name, err)
		}
		keys = append(keys, token)
	}

	var (
		mu     sync.Mutex
		byUser = map[string]map[string]int{}
	)
	record := func(ui int, err error) {
		mu.Lock()
		defer mu.Unlock()
		id := fmt.Sprintf("user%d", ui)
		if byUser[id] == nil {
			byUser[id] = map[string]int{}
		}
		if err != nil {
			byUser[id][classifyErr(err)]++
		} else {
			byUser[id]["ok"]++
		}
	}

	// 阶段 1：串行打 2 发 —— 落在令牌桶突发容量内，应当成功
	startAt := time.Now()
	for ui, key := range keys {
		for i := 0; i < 2; i++ {
			record(ui, doRequest(client, target, key, o, i))
		}
	}
	// 阶段 2：并发轰击 —— 桶已空，应当看到 429
	var wg sync.WaitGroup
	for ui, key := range keys {
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(ui int, key string, i int) {
				defer wg.Done()
				record(ui, doRequest(client, target, key, o, i))
			}(ui, key, i)
		}
	}
	wg.Wait()
	wall := time.Since(startAt)

	totalOK, totalLimited := 0, 0
	sawLimited := false
	allHaveOK := true
	for _, m := range byUser {
		totalOK += m["ok"]
		n429 := m["HTTP 429 rate_limited"] + m["HTTP 429 concurrency_limited"] + m["HTTP 429"]
		totalLimited += n429
		if n429 > 0 {
			sawLimited = true
		}
		if m["ok"] == 0 {
			allHaveOK = false
		}
	}
	// 串行阶段应当每人至少 1 次成功；并发阶段应当出现 429
	passed := allHaveOK && sawLimited
	return scenarioResult{
		Name: "multiuser", Passed: passed,
		Detail: fmt.Sprintf("3 用户 × 20 并发 RPM=10：ok=%d 限流=%d 用时 %s（要有成功也要有 429）",
			totalOK, totalLimited, wall.Round(time.Millisecond)),
		Numbers: map[string]any{"by_user": byUser, "ok": totalOK, "rate_limited": totalLimited},
	}, nil
}

// adminCreateUser 用 admin token 建用户、设 RPM，返回下游 token。
func adminCreateUser(client *http.Client, base, admin, name string, rpm int) (string, error) {
	body, _ := json.Marshal(map[string]any{"name": name})
	req, err := http.NewRequest(http.MethodPost, base+"/v1/_admin/users", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+admin)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Token == "" {
		return "", fmt.Errorf("创建响应里没有 token: %s", raw)
	}
	// 设 RPM，并切到 consumption（默认 byo 没有自有上游会 502；
	// consumption 走系统池，正好是场景里的假上游）
	ub, _ := json.Marshal(map[string]any{"rpm": rpm, "max_concurrent": 4, "mode": "consumption"})
	ureq, _ := http.NewRequest(http.MethodPut, base+"/v1/_admin/users/"+name, bytes.NewReader(ub))
	ureq.Header.Set("Authorization", "Bearer "+admin)
	ureq.Header.Set("Content-Type", "application/json")
	uresp, err := client.Do(ureq)
	if err != nil {
		return "", err
	}
	defer uresp.Body.Close()
	if uresp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(uresp.Body, 4096))
		return "", fmt.Errorf("设限流 HTTP %d: %s", uresp.StatusCode, b)
	}
	return out.Token, nil
}

// ---------------------------------------------------------------- 工具

func portOr(_ int) int { return 0 } // 占位，实际端口由 startStubGateway 分配

// startStubGateway 起一套临时网关，configFn 用已分配的端口生成 YAML。
// 子进程起不来时**保留** home（日志是排查的唯一线索），错误里带上 child.out 尾部。
func startStubGateway(o options, configFn func(port int) string) (home string, port int, cp *childProc, err error) {
	home, err = os.MkdirTemp("", "llmpbench-scen-")
	if err != nil {
		return "", 0, nil, err
	}
	port, err = freePort()
	if err != nil {
		return home, 0, nil, err
	}
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(configFn(port)), 0o600); err != nil {
		return home, 0, nil, err
	}
	cp, err = startChild(o.proxyBin, home, port)
	if err != nil {
		tail := ""
		if b, rerr := os.ReadFile(filepath.Join(home, "child.out")); rerr == nil {
			lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
			if len(lines) > 12 {
				lines = lines[len(lines)-12:]
			}
			tail = "\n" + strings.Join(lines, "\n")
		}
		return home, 0, nil, fmt.Errorf("%w%s（配置/日志保留在 %s）", err, tail, home)
	}
	return home, port, cp, nil
}

func stickyConfig(_ int, stub1, stub2 string, _ int) func(int) string {
	return func(port int) string {
		return fmt.Sprintf(`# llmpbench sticky scenario
server:
  host: 127.0.0.1
  port: %d
  api_keys: [%s]
  affinity_ttl_ms: 3600000
routing: {retry: 1, failure_threshold: 1000, cooldown_seconds: 1}
providers:
  - {name: s1, enabled: true, base_url: %s, api_key: k, weight: 10, proxy: direct, timeout_ms: 30000, models: ["*"]}
  - {name: s2, enabled: true, base_url: %s, api_key: k, weight: 10, proxy: direct, timeout_ms: 30000, models: ["*"]}
database: {path: "", retain_days: 1}
log: {level: warn, max_mb: 5, keep: 1}
`, port, benchKey, stub1, stub2)
	}
}

func retryConfig(_ int, badURL, goodURL string, _ int) func(int) string {
	return func(port int) string {
		return fmt.Sprintf(`# llmpbench retry scenario
server:
  host: 127.0.0.1
  port: %d
  api_keys: [%s]
routing: {retry: 2, failure_threshold: 1000, cooldown_seconds: 1}
providers:
  - {name: bad, enabled: true, base_url: %s, api_key: k, weight: 100, proxy: direct, timeout_ms: 10000, models: ["*"]}
  - {name: good, enabled: true, base_url: %s, api_key: k, weight: 1, proxy: direct, timeout_ms: 10000, models: ["*"]}
database: {path: "", retain_days: 1}
log: {level: warn, max_mb: 5, keep: 1}
`, port, benchKey, badURL, goodURL)
	}
}

func multiUserConfig(_ int, stubURL, admin string) func(int) string {
	return func(port int) string {
		return fmt.Sprintf(`# llmpbench multiuser scenario
server:
  host: 127.0.0.1
  port: %d
  api_keys: [%s]
  admin_token: %s
routing: {retry: 1, failure_threshold: 1000, cooldown_seconds: 1}
providers:
  - {name: p, enabled: true, base_url: %s, api_key: k, weight: 1, proxy: direct, timeout_ms: 30000, models: ["*"]}
database: {path: "", retain_days: 1}
log: {level: warn, max_mb: 5, keep: 1}
`, port, benchKey, admin, stubURL)
	}
}

// postSession 发一发请求，返回 X-Llmproxy-Affinity 头。
func postSession(client *http.Client, target, key, model, session string) (string, error) {
	payload := map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-Affinity", session)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp.Header.Get("X-Llmproxy-Affinity"), nil
}

func printScenarioResults(list []scenarioResult) {
	fmt.Printf("\n场景结果\n")
	fmt.Printf("%-12s %-6s %s\n", "场景", "结果", "说明")
	fmt.Printf("%s\n", strings.Repeat("-", 72))
	failed := 0
	for _, r := range list {
		mark := "OK"
		if !r.Passed {
			mark = "NG"
			failed++
		}
		fmt.Printf("%-12s %-6s %s\n", r.Name, mark, r.Detail)
	}
	fmt.Printf("%s\n", strings.Repeat("-", 72))
	if failed == 0 {
		fmt.Printf("全部通过（%d 个场景）\n", len(list))
	} else {
		fmt.Printf("%d / %d 个场景未通过\n", failed, len(list))
	}
}
