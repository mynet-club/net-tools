package server

// §3.F 接线的三类必测（正常路径 / 拒绝路径 / 失败路径）。
//
// 断言全部盯「接线会犯的错」，而不是执行器自己的功能 —— 后者在 internal/executor
// 已经测过，这里重复审只会让两处断言跟着接口一起烂。接线能犯的错是这几类：
//   - 委托没有真的换掉承载者，或反过来在**不该委托**的时候换了（边界 2/3）；
//   - 计量语义被顺手改了（边界 1）：同一条请求在两条链路下账必须逐字段一致；
//   - 计划声明的执行器注册不上时回落到 2.x 通道 —— 那等于让「计划说用谁」变成注释，
//     而这正是 §8 点名的绕过出网控制的快捷路径；
//   - 装配失败不指名、或指名时把上游密钥端出来；
//   - 一次正常超时被归因成「客户端走了」：那样既不给这家记失败，又让熔断口径跟着抖。
//
// 流式进来之后（2026-10-04 裁决第 2 条：B 方案），最后两类各多了一条同形用例：委托侧的
// 流式既不能长出总时限，也不能把「看门狗掐的 / 客户端真的走了 / 我们的时限到了」这三行
// 归因搅成一份 —— 那三分原来只有 2.x 覆盖，现在两条路都要能答。

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/executor"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// ---------------------------------------------------------------- 夹具

// execUp 是「把每个请求的头与正文都逐字记下来」的上游。
// 委托与否的判据有两个来源：网关侧的观测头，和上游侧真正收到的字节 —— 后者才证明
// 请求装配（模型名改写、鉴权头、UA、Content-Type）真的换了人做且结果同形。
type execUp struct {
	srv     *httptest.Server
	mu      sync.Mutex
	bodies  []string
	headers []http.Header
}

func startExecUp(t *testing.T, handler http.HandlerFunc) *execUp {
	t.Helper()
	u := &execUp{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		// Header 要 Clone：它是请求生命周期内的对象，测试里留着原对象会读到别的请求。
		head := r.Header.Clone()
		u.mu.Lock()
		u.bodies = append(u.bodies, string(raw))
		u.headers = append(u.headers, head)
		u.mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *execUp) url() string { return u.srv.URL }

func (u *execUp) hits() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.bodies)
}

func (u *execUp) last(t *testing.T) (string, http.Header) {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.bodies) == 0 {
		t.Fatal("上游一次都没收到请求，而断言要看它收到了什么")
	}
	return u.bodies[len(u.bodies)-1], u.headers[len(u.headers)-1]
}

// execYAML 拼一份「一家上游 + 指定接线模式」的配置，可选覆盖 timeout_ms。
// 走 cfgYAML 而不是自己拼供应商段：供应商的必填项（max_data_level 等）一变，
// 夹具应该跟着变，而不是在这里多养一份口径。
func execYAML(t *testing.T, upstreamURL, mode string, timeoutMs int) string {
	t.Helper()
	return execYAMLIdle(t, upstreamURL, mode, timeoutMs, 0)
}

// execYAMLIdle 比 execYAML 多一项可选的 stream_idle_timeout_ms。
// 它单独立一个入口是有原因的：流式委托的三分归因里「空闲看门狗掐的」那一支，
// 只有配了空闲上限才会出现；不配（0）时流式仍受总时限管，那是另一种行为。
func execYAMLIdle(t *testing.T, upstreamURL, mode string, timeoutMs, idleMs int) string {
	t.Helper()
	src := cfgYAML(map[string]string{"vendorA": upstreamURL}, []string{"sk-local"})
	if timeoutMs > 0 {
		src = strings.Replace(src, "    weight: 1\n",
			fmt.Sprintf("    timeout_ms: %d\n    weight: 1\n", timeoutMs), 1)
	}
	if idleMs > 0 {
		src = strings.Replace(src, "  port: 0\n",
			fmt.Sprintf("  port: 0\n  stream_idle_timeout_ms: %d\n", idleMs), 1)
	}
	if mode != "" {
		src += policySection(mode, "t-open", "system:gateway", 1)
	}
	return src
}

// execHarness 建网关并摆上策略包内容文件（理由见 procHarness：缺内容文件会让
// 「没委托」和「委托没生效」在断言里长得一模一样）。
func execHarness(t *testing.T, upstreamURL, mode string, timeoutMs int) *harness {
	t.Helper()
	return execHarnessIdle(t, upstreamURL, mode, timeoutMs, 0)
}

// execHarnessIdle 同 execHarness，多带一个空闲看门狗上限（见 execYAMLIdle）。
func execHarnessIdle(t *testing.T, upstreamURL, mode string, timeoutMs, idleMs int) *harness {
	t.Helper()
	h := newHarness(t, execYAMLIdle(t, upstreamURL, mode, timeoutMs, idleMs))
	if mode != "" {
		writePolicyBundle(t, h, policyBundleOpen)
	}
	return h
}

// execProvider 取配置里那家上游（函数级用例要拿它填 executorAsk）。
func execProvider(t *testing.T, h *harness, name string) *config.Provider {
	t.Helper()
	cfg, err := h.cfgStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	for i := range cfg.Normalized {
		if cfg.Normalized[i].Name == name {
			p := cfg.Normalized[i]
			return &p
		}
	}
	t.Fatalf("配置里没有供应商 %s，夹具拼错了", name)
	return nil
}

// execPlan 拼一份「这家上游 / 用某个执行器名 / 上游模型名」的计划。
func execPlan(provider, execName, upstreamModel string) policy.RoutingPlan {
	return policy.RoutingPlan{Fallbacks: []policy.RouteCandidate{{
		Executor:      execName,
		Provider:      provider,
		Model:         "gpt-4o",
		UpstreamModel: upstreamModel,
		MaxDataLevel:  policy.LevelInternal,
	}}}
}

// execRT 拼一份最小运行态：模式 + 执行器声明表。names 为 nil 时用默认那张表。
func execRT(mode config.PolicyMode, names map[string]executor.Protocol) *policyRuntime {
	er := (&Server{}).buildExecutorRuntime()
	if names != nil {
		er.names = names
	}
	return &policyRuntime{mode: mode, exec: er}
}

func execShot(applied bool, plan policy.RoutingPlan) *policyShot {
	return &policyShot{Mode: config.PolicyModeEnforce, Applied: applied, Plan: plan}
}

// ---------------------------------------------------------------- 正常路径

// 委托确实承载了一次非流式交换：观测头在场、上游收到的装配结果与 2.x 同形。
func TestExecutor30DelegationCarriesTheExchange(t *testing.T) {
	up := startExecUp(t, procJSON("delegated-answer"))
	h := execHarness(t, up.url(), "enforce", 0)

	resp, body := procChat(t, h, "req-exec-del", "hello from downstream", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("委托后应照常 200，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if !strings.Contains(string(body), "delegated-answer") {
		t.Errorf("响应该原样回到客户端: %s", truncateMsg(string(body), 200))
	}
	if got := resp.Header.Get("X-Llmproxy-Executor"); got != policyExecutorOpenAI {
		t.Errorf("上线验证要靠这个头认出「委托生效了」，实际 %q（空 = 根本没走执行器）", got)
	}

	sent, head := up.last(t)
	if !strings.Contains(sent, `"model":"gpt-4o"`) {
		t.Errorf("上游看到的 model 不对: %s", truncateMsg(sent, 300))
	}
	if strings.Contains(sent, "stream_options") {
		t.Errorf("非流式交换不该被注入 stream_options: %s", truncateMsg(sent, 300))
	}
	if got := head.Get("Authorization"); got != "Bearer sk-vendorA" {
		t.Errorf("执行器要带上供应商密钥（缺它上游会 401，而记账照常）: %q", got)
	}
	if ua := head.Get("User-Agent"); !strings.HasPrefix(ua, "llmproxy/") {
		t.Errorf("UA 必须与 2.x 一致，上游侧不该看出网关身份变化: %q", ua)
	}
	if ct := head.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type 不对: %q", ct)
	}
	// §2.9 规则 6 的接线侧：观测头只说「谁承载了」，不含正文与密钥。
	if strings.Contains(resp.Header.Get("X-Llmproxy-Executor"), "sk-") {
		t.Errorf("观测头不该出现密钥")
	}
}

// 边界 1（计量语义一个字不改）：同一条请求在「委托」与「2.x 传输」两条链路下，
// 账必须逐字段一致。这一条是 §3.F 禁止项的直接体现 —— 执行器顺手算钱会出现
// 第二套计价口径，而 relay 那套是现网账本的事实来源。
func TestExecutor30MeteringMatchesLegacyPath(t *testing.T) {
	up := startExecUp(t, procJSON("same-usage"))

	delH := execHarness(t, up.url(), "enforce", 0)
	legH := execHarness(t, up.url(), "", 0)
	seedProviderPrice(t, delH)
	seedProviderPrice(t, legH)
	delResp, _ := procChat(t, delH, "req-exec-meter-del", "meter me", false)
	legResp, _ := procChat(t, legH, "req-exec-meter-leg", "meter me", false)

	// 前提先钉住：两条链路确实各走各的承载者，否则「账一致」是两句空话。
	if got := delResp.Header.Get("X-Llmproxy-Executor"); got != policyExecutorOpenAI {
		t.Fatalf("前提不成立：这条请求没走执行器（委托头 %q）", got)
	}
	if got := legResp.Header.Get("X-Llmproxy-Executor"); got != "" {
		t.Fatalf("前提不成立：legacy 侧不该委托，实际 %q", got)
	}

	del := recentRecord(t, delH, "req-exec-meter-del")
	leg := recentRecord(t, legH, "req-exec-meter-leg")
	mDel, mLeg := meterOf(del), meterOf(leg)
	if mDel != mLeg {
		t.Errorf("同一条请求在两条链路下的账不一致：\n委托 %+v\n2.x  %+v", mDel, mLeg)
	}
	// 时延不进等式（它是墙钟读数），但两条路都必须**量到了**：委托侧漏测 TTFT 的表现为
	// 「账完全一致、报表却少一列」，只有这一条能把它抓出来。
	if del.TTFTMs == nil || *del.TTFTMs < 0 || leg.TTFTMs == nil || *leg.TTFTMs < 0 {
		t.Errorf("两条链路都要记录 TTFT（可以为 0，不能没有）：委托 %+v / 2.x %+v", del.TTFTMs, leg.TTFTMs)
	}
	// 数值本身也要对得上上游回报：一致但不等于 5/7/12 说明两条路一起错了。
	if mDel.total != 12 || mDel.prompt != 5 || mDel.completion != 7 {
		t.Errorf("usage 应为 5/7/12，实际 %d/%d/%d", mDel.prompt, mDel.completion, mDel.total)
	}
	if mDel.provider != "vendorA" || mDel.upstream != "gpt-4o" {
		t.Errorf("归属上游不对： %+v", mDel)
	}

	// 冻结金额比的是 usage_daily 的合计 —— 请求行的 cost/charge 只有写侧，
	// 而「两条链路算出同一个钱」必须比真正入账的那个数。
	cDel := frozenCost(t, delH, "vendorA", "gpt-4o")
	cLeg := frozenCost(t, legH, "vendorA", "gpt-4o")
	if cDel != cLeg {
		t.Errorf("冻结的上游成本不一致：委托 %v，2.x %v —— 出现了第二套计价", cDel, cLeg)
	}
	// 价目按 InMiss=1 / Out=2 每百万 token，上游报 5 输入 7 输出：
	// 金额为 0 说明两边都没冻住，那上面那条「一致」也是空的。
	if want := (5*1 + 7*2) / 1e6; cDel <= 0 || math.Abs(cDel-want) > 1e-9 {
		t.Errorf("冻结成本应为 %v（价目 1/2 每百万），实际 %v —— 前提不成立，比较无意义", want, cDel)
	}

	// 委托侧仍然带着策略痕迹：接线不该把 3.0 的观测面摘掉。
	// legacy 侧的对照口径是「痕迹行为空」而不是「没有痕迹行」—— 请求行与痕迹行
	// 是同一次写入的，比字段比行更符合实际形态。
	if tr := traceOf(t, delH, "req-exec-meter-del"); tr.PolicyVersion == "" {
		t.Errorf("委托请求的策略版本为空：3.0 生效却记不出是谁的决策")
	}
	if tr := traceOf(t, legH, "req-exec-meter-leg"); tr.PolicyVersion != "" {
		t.Errorf("legacy 侧不该有策略版本，实际 %q", tr.PolicyVersion)
	}
}

// frozenCost 读 usage_daily 里某个 (provider, model) 的合计上游成本。
func frozenCost(t *testing.T, h *harness, provider, model string) float64 {
	t.Helper()
	st, err := h.db.Stats(time.Time{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range st.ByProvider {
		if r.Provider == provider && r.Model == model {
			return r.CostUpstream
		}
	}
	t.Fatalf("用量聚合里没有 %s/%s 的行", provider, model)
	return 0
}

// seedProviderPrice 给 (vendorA, gpt-4o) 录一条上游价目：输入每百万 1、输出每百万 2。
// 没有价目时冻结路径根本不产金额，「两条链路账一致」就成了比两个零。
func seedProviderPrice(t *testing.T, h *harness) {
	t.Helper()
	if err := h.db.InsertProviderPrice(&store.ProviderPrice{
		Provider: "vendorA", UpstreamModel: "gpt-4o", Currency: "CNY",
		InMiss: 1, InHit: 1, Out: 2, ValidFrom: hourFloor(time.Now().Add(-3 * time.Hour)),
	}); err != nil {
		t.Fatal(err)
	}
}

// meterView 是一次交换里「请求行读得出的账」（loadRecent 的列面），不含时延。
// 指针字段用 -1 表示「上游没报」，好让整张表能用 == 一次比完。
//
// TTFT 刻意不在这里：它是两次独立请求各自的墙钟读数，不是账。把它比进等式，
// 「两条链路的账一致」就变成「两条链路的耗时恰好相等」，`-race` 下必然抖 1ms。
// 时延仍然单独断言「两条路都真的量到了」（见 TestExecutor30MeteringMatchesLegacyPath）。
type meterView struct {
	prompt, completion, total int64
	status                    int
	ok, stream, systemPaid    bool
	attempts                  int
	provider, upstream, model string
}

func meterOf(r store.RequestRecord) meterView {
	return meterView{
		prompt: ptr64(r.PromptTokens), completion: ptr64(r.CompletionTokens), total: ptr64(r.TotalTokens),
		status: r.StatusCode, ok: r.OK, stream: r.Stream,
		systemPaid: r.SystemPaid, attempts: r.Attempts,
		provider: r.Provider, upstream: r.UpstreamModel, model: r.Model,
	}
}

func ptr64(v *int64) int64 {
	if v == nil {
		return -1
	}
	return *v
}

// ---------------------------------------------------------------- 边界 3（流式）

// 2026-10-04 裁决第 2 条走 B 方案后，流式也交给执行器承载，但 Attempt 用
// `Timeout = 0` / `MaxResponseBytes = 0` 如实表达「时限在调用方 ctx 里 / 不缓存、
// 逐段透传」。这条钉住换承载者之后流式的四件事实没被接线改坏：
//   - 逐段透传还在（响应类型没变、[DONE] 没被吃掉）；
//   - 计量照旧（usage 末帧仍由 relay 自己的扫描器从透传流里读出，边界 1）；
//   - 上游收到的正文与 2.x 的改写结果同形（include_usage 由调用方点名才注入 ——
//     少了它上游不回 usage 末帧，表现是「账全变 0」而不是报错）；
//   - 那两个 0 落在执行记录上读得出（见 executorwiring_test.go）。
func TestExecutor30StreamingDelegatesWithoutBuffering(t *testing.T) {
	up := startExecUp(t, procSSE("alpha", " beta"))
	h := execHarness(t, up.url(), "enforce", 0)

	resp, body := procChat(t, h, "req-exec-stream", piiSample, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("流式应照常 200，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if got := resp.Header.Get("X-Llmproxy-Executor"); got != policyExecutorOpenAI {
		t.Errorf("流式也该由计划声明的执行器承载（裁决第 2 条：B 方案），实际委托头 %q", got)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("流式响应类型不该变，实际 %q", ct)
	}
	if !strings.Contains(string(body), "[DONE]") {
		t.Errorf("流式收尾不该被吃掉（缓存整包再发就会吃在最后）: %s", truncateMsg(string(body), 200))
	}
	for _, part := range []string{"alpha", "beta"} {
		if !strings.Contains(string(body), part) {
			t.Errorf("正文片段 %q 没原样透传到客户端: %s", part, truncateMsg(string(body), 200))
		}
	}

	sent, _ := up.last(t)
	if !strings.Contains(sent, `"stream":true`) || !strings.Contains(sent, `"include_usage":true`) {
		t.Errorf("委托侧的流式正文必须与 2.x 改写后的形状同形，否则上游不回 usage 末帧: %s",
			truncateMsg(sent, 300))
	}

	rec := recentRecord(t, h, "req-exec-stream")
	// usage 仍扫得到 = 计量那条路一个字没动（relay 在读透传流时自己扫）。
	if rec.TotalTokens == nil || *rec.TotalTokens != 33 {
		t.Errorf("流式 usage 应仍被记账，实际 %+v", rec.TotalTokens)
	}
	if !rec.Stream {
		t.Errorf("这条该记成流式请求")
	}
}

// 委托不得把流式拉回「总时限掐断长回答」的旧行为 —— 那是 B 方案明确拒绝的功能回退。
// 形状与 idle_test.go 那条「慢但活着」相同，差别在于这一发是执行器承载的：接线如果
// 给流式填了正时限，执行器会在 provider.timeout_ms 处自己掐表，客户端拿到的是失败
// 而不是跑完的流。
func TestExecutor30StreamingKeepsNoExecutorDeadline(t *testing.T) {
	const chunks = 10
	up := startExecUp(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		f, _ := w.(http.Flusher)
		for i := 0; i < chunks; i++ {
			fmt.Fprintf(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"c%d\"}}]}\n\n", i)
			if f != nil {
				f.Flush()
			}
			time.Sleep(150 * time.Millisecond)
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		if f != nil {
			f.Flush()
		}
	})
	// 总时限 1000ms（配置下界）而整条约 1.5s：执行器一掐表就断，
	// 空闲上限 5s 排除看门狗干扰（chunk 间隔 150ms 远小于它）。
	h := execHarnessIdle(t, up.url(), "enforce", 1000, 5000)

	resp, body := procChat(t, h, "req-exec-slow-stream", "hi", true)
	if got := resp.Header.Get("X-Llmproxy-Executor"); got != policyExecutorOpenAI {
		t.Fatalf("前提不成立：这条流式没走执行器（委托头 %q）", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("慢但一直有数据的流不该被委托侧掐断，实际 %d: %s",
			resp.StatusCode, truncateMsg(string(body), 200))
	}
	for i := 0; i < chunks; i++ {
		if !strings.Contains(string(body), fmt.Sprintf("c%d", i)) {
			t.Fatalf("第 %d 个 chunk 没转发出去，流被提前掐断了（收到 %d 字节）", i, len(body))
		}
	}
	if !strings.Contains(string(body), "[DONE]") {
		t.Errorf("流没走完（缺 [DONE]，收到 %d 字节）", len(body))
	}
}

// 空闲看门狗掐的流（委托侧）：执行器只会报「调用方 ctx 被取消」，而网关必须靠
// wd.Fired() 认出这是空闲超时 —— 误判成客户端走了就不给这家记失败，熔断口径跟着抖。
// 2.x 那条覆盖在 idle_test.go，这条把同一支归因在委托路径上重跑一遍。
func TestExecutor30StreamingIdleAttributionStaysUpstreamIdle(t *testing.T) {
	stall := make(chan struct{})
	up := startExecUp(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"}}]}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-stall:
		case <-r.Context().Done():
		}
	})
	defer close(stall)

	h := execHarnessIdle(t, up.url(), "enforce", 600000, 1000)
	resp, _ := procChat(t, h, "req-exec-idle-del", "hi", true)
	if got := resp.Header.Get("X-Llmproxy-Executor"); got != policyExecutorOpenAI {
		t.Fatalf("前提不成立：这条卡死的流没走执行器（委托头 %q）", got)
	}
	rec := recentRecord(t, h, "req-exec-idle-del")
	if rec.ErrorType != "upstream_idle" {
		t.Errorf("委托侧空闲超时的错误类型应当是 upstream_idle，实际 %q（%s）", rec.ErrorType, rec.ErrorMsg)
	}
	if !strings.Contains(rec.ErrorMsg, "空闲") {
		t.Errorf("错误信息该说清是空闲超时: %q", rec.ErrorMsg)
	}
	if strings.Contains(rec.ErrorMsg, "客户端") {
		t.Errorf("看门狗掐的不该归因成客户端走了: %s", rec.ErrorMsg)
	}
	if rec.OK {
		t.Errorf("卡死的流不该记成成功: %+v", rec)
	}
}

// 客户端在上游返回前断开（委托侧，三分归因的第三支）：执行器报的是 caller_canceled，
// 而 r.Context() 已经先一步到期 —— 那既不是供应商慢（不该说成超时），也不该给这家
// 记连续失败，更不该换一家白打一次。
func TestExecutor30ClientGoneIsNotBlamedOnProvider(t *testing.T) {
	release := make(chan struct{})
	up := startExecUp(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
			procJSON("too late")(w, r)
		case <-r.Context().Done():
		}
	})
	defer close(release)
	h := execHarness(t, up.url(), "enforce", 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		h.gateway.URL+"/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-local")
	req.Header.Set("X-Request-Id", "req-exec-clientgone")
	done := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}()

	// 等上游确实收到这一发再断开，否则测的是「还没出网就取消」。
	deadline := time.Now().Add(5 * time.Second)
	for up.hits() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if up.hits() == 0 {
		t.Fatal("上游没收到请求，委托路径的前提不成立")
	}
	cancel()
	if err := <-done; err == nil {
		t.Errorf("客户端已断开，客户端侧却拿到了成功响应")
	}
	time.Sleep(400 * time.Millisecond) // 给网关处理这次断开的时间

	if n := up.hits(); n != 1 {
		t.Errorf("客户端已经走了，不该再打第二家上游，实际 %d 次", n)
	}
	st := h.router.Snapshot()
	if got := st["vendorA"].ConsecutiveFailures; got != 0 {
		t.Errorf("客户端断开不该给 vendorA 记连续失败，实际 %d（cfgYAML 里 failure_threshold=3）", got)
	}
	rec := recentRecord(t, h, "req-exec-clientgone")
	if rec.ErrorType != "client_gone" {
		t.Errorf("错误类型应当是 client_gone，实际 %q（%s）", rec.ErrorType, rec.ErrorMsg)
	}
	if strings.Contains(rec.ErrorMsg, "请求超时") {
		t.Errorf("客户端走了不该说成供应商超时: %s", rec.ErrorMsg)
	}
	if rec.OK {
		t.Errorf("客户端断开的请求不该记成成功: %+v", rec)
	}
}

// 流式委托的计量与 2.x 逐字段一致（边界 1 的流式版）。非流式那条
// （TestExecutor30MeteringMatchesLegacyPath）已经证明「共用 relay 计量」不是纸面承诺，
// 而流式才是风险所在：读上游的人换了，usage 末帧与首字节时刻都得原样到达 relay。
func TestExecutor30StreamingMeteringMatchesLegacyPath(t *testing.T) {
	up := startExecUp(t, procSSE("one", " two"))

	delH := execHarness(t, up.url(), "enforce", 0)
	legH := execHarness(t, up.url(), "", 0)
	seedProviderPrice(t, delH)
	seedProviderPrice(t, legH)
	delResp, _ := procChat(t, delH, "req-exec-smeter-del", "meter stream", true)
	legResp, _ := procChat(t, legH, "req-exec-smeter-leg", "meter stream", true)

	if got := delResp.Header.Get("X-Llmproxy-Executor"); got != policyExecutorOpenAI {
		t.Fatalf("前提不成立：这条流式没走执行器（委托头 %q）", got)
	}
	if got := legResp.Header.Get("X-Llmproxy-Executor"); got != "" {
		t.Fatalf("前提不成立：legacy 侧不该委托，实际 %q", got)
	}

	del := recentRecord(t, delH, "req-exec-smeter-del")
	leg := recentRecord(t, legH, "req-exec-smeter-leg")
	mDel, mLeg := meterOf(del), meterOf(leg)
	if mDel != mLeg {
		t.Errorf("同一条流式请求在两条链路下的账不一致：\n委托 %+v\n2.x  %+v", mDel, mLeg)
	}
	if mDel.prompt != 11 || mDel.completion != 22 || mDel.total != 33 {
		t.Errorf("流式 usage 应为 11/22/33，实际 %d/%d/%d —— 一致但一起错，等于两条路都没扫到",
			mDel.prompt, mDel.completion, mDel.total)
	}
	if !mDel.stream || !mLeg.stream {
		t.Errorf("两条链路都要记成流式: 委托 %v / 2.x %v", mDel.stream, mLeg.stream)
	}
	if del.TTFTMs == nil || *del.TTFTMs < 0 || leg.TTFTMs == nil || *leg.TTFTMs < 0 {
		t.Errorf("两条链路都要记录 TTFT（可以为 0，不能没有）：委托 %+v / 2.x %+v", del.TTFTMs, leg.TTFTMs)
	}
	if cDel, cLeg := frozenCost(t, delH, "vendorA", "gpt-4o"), frozenCost(t, legH, "vendorA", "gpt-4o"); cDel != cLeg {
		t.Errorf("冻结的上游成本不一致：委托 %v，2.x %v —— 出现了第二套计价", cDel, cLeg)
	}
}

// ---------------------------------------------------------------- 拒绝路径

// 边界 2：legacy / shadow 下 2.x 传输原样跑。影子一旦能换传输层，
// 差异报告里就掺进了被观测者自己的改动。
func TestExecutor30DoesNotDelegateOutsideEnforce(t *testing.T) {
	for _, mode := range []string{"", "shadow"} {
		up := startExecUp(t, procJSON("legacy-shape"))
		h := execHarness(t, up.url(), mode, 0)

		resp, body := procChat(t, h, "req-exec-off-"+mode, "not delegated", false)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("mode=%q 应 200，实际 %d: %s", mode, resp.StatusCode, truncateMsg(string(body), 200))
		}
		if got := resp.Header.Get("X-Llmproxy-Executor"); got != "" {
			t.Errorf("mode=%q 下不该出现委托头，实际 %q", mode, got)
		}
		if up.hits() != 1 {
			t.Errorf("mode=%q 下上游应只收到一次请求，实际 %d", mode, up.hits())
		}
	}
}

// 计划声明的执行器本网关注册不上 → 拒掉这个候选，不出网、不回落 2.x。
// 回落等于把「计划说用哪个执行器」降级成注释（§8 快捷路径）。
func TestExecutor30UnregisteredExecutorRefusesCandidate(t *testing.T) {
	up := startExecUp(t, procJSON("should-never-be-called"))
	h := execHarness(t, up.url(), "enforce", 0)
	prov := execProvider(t, h, "vendorA")

	rt := execRT(config.PolicyModeEnforce, nil) // 默认表：只注册了 http-openai
	shot := execShot(true, execPlan("vendorA", "http-anthropic", "gpt-4o"))

	call, err := h.srv.executorCallFor(rt, shot, executorAsk{
		prov: prov, model: "gpt-4o", upstreamModel: "gpt-4o",
		requestID: "req-exec-unreg", path: "/chat/completions",
		timeout: time.Minute, body: []byte(`{"model":"gpt-4o","messages":[]}`),
	})
	if err == nil {
		t.Fatalf("注册不上的执行器名必须让候选不可用，实际 call=%v err=nil", call)
	}
	if call != nil {
		t.Errorf("拒绝时不该给出调用现场")
	}
	if !strings.Contains(err.Error(), "http-anthropic") {
		t.Errorf("错误要指名是哪个执行器名，实际: %v", err)
	}
	if !strings.Contains(err.Error(), policyExecutorOpenAI) {
		t.Errorf("错误应列出已注册的执行器名，实际: %v", err)
	}
	if strings.Contains(err.Error(), prov.APIKey) {
		t.Errorf("错误文本里出现了上游密钥明文: %v", err)
	}
	// 「不出网」的直接证据：连 transport 都没装配，一次拨号都没发生。
	if len(rt.exec.entries) != 0 {
		t.Errorf("拒候选时不该装配任何通道，实际 %d 条", len(rt.exec.entries))
	}
	if up.hits() != 0 {
		t.Errorf("一次都没该出网，上游却收到 %d 个请求", up.hits())
	}
}

// 判定分支表：三种结论（不委托 / 拒候选 / 委托）必须在代码里各有其位，
// 而「不委托」的每一条理由都得是接线说得出来的那三条边界之一。
func TestExecutor30DecisionBranches(t *testing.T) {
	up := startExecUp(t, procJSON("branch"))
	h := execHarness(t, up.url(), "enforce", 0)
	prov := execProvider(t, h, "vendorA")

	base := func() executorAsk {
		return executorAsk{
			prov: prov, model: "gpt-4o", upstreamModel: "gpt-4o",
			requestID: "req-exec-branch", path: "/chat/completions",
			timeout: time.Minute, body: []byte(`{"model":"gpt-4o","messages":[]}`),
		}
	}
	okPlan := execPlan("vendorA", policyExecutorOpenAI, "gpt-4o")

	t.Run("委托成功", func(t *testing.T) {
		call, err := h.srv.executorCallFor(execRT(config.PolicyModeEnforce, nil), execShot(true, okPlan), base())
		if err != nil || call == nil {
			t.Fatalf("enforce+Applied+已注册名应委托，实际 call=%v err=%v", call, err)
		}
		// Attempt 的必填形态：时限原样取自这一跳，上限与 relay 同源，
		// 出网校验刻意留空（绑在 transport 里，再填一份就是两个校验点）。
		if call.attempt.Timeout != time.Minute {
			t.Errorf("Attempt.Timeout 应等于这一跳的时限，实际 %v", call.attempt.Timeout)
		}
		if call.attempt.MaxResponseBytes != maxUpstreamResponseBytes {
			t.Errorf("Attempt 上限必须与 relay 同源，实际 %d vs %d",
				call.attempt.MaxResponseBytes, maxUpstreamResponseBytes)
		}
		if call.attempt.EgressCheck != nil {
			t.Errorf("出网校验不该在 Attempt 里再填一份（两个校验点必然漂移）")
		}
		if call.attempt.IsStream || call.attempt.WantUsage {
			t.Errorf("非流式委托不该声明 stream/usage：IsStream=%v WantUsage=%v",
				call.attempt.IsStream, call.attempt.WantUsage)
		}
		if call.attempt.APIKey != prov.APIKey || call.attempt.BaseURL != prov.BaseURL {
			t.Errorf("Attempt 要如实带目标与凭证，实际 %s / %q", call.attempt.BaseURL, call.attempt.APIKey)
		}
		if call.attempt.RequestID != "req-exec-branch" || call.attempt.Provider != "vendorA" {
			t.Errorf("Attempt 要带得上本次请求与供应商的身份，实际 %q / %q",
				call.attempt.RequestID, call.attempt.Provider)
		}
		if call.name != policyExecutorOpenAI || call.proto != executor.ProtocolOpenAIChat {
			t.Errorf("调用现场要如实记录承载者，实际 name=%q proto=%q", call.name, call.proto)
		}
	})

	// 裁决第 2 条（B 方案）落进 Attempt 的那两个 0：判定要证明「0 是显式声明」而不是
	// 「接线忘了填」。两个证据缺一不可 —— IsStream 必须同时为真，且这份 Attempt 要能
	// 过执行器自家的 Validate（闸门在包里，不在注释里）；把 IsStream 摘掉后必须不过，
	// 否则 0 就成了一条「忘了填也能跑」的通道。
	t.Run("流式委托", func(t *testing.T) {
		ask := base()
		ask.isStream = true
		ask.timeout = 0 // 流式的时限本来就在调用方 ctx 里，这一跳没配也不该挡委托
		call, err := h.srv.executorCallFor(execRT(config.PolicyModeEnforce, nil), execShot(true, okPlan), ask)
		if err != nil || call == nil {
			t.Fatalf("enforce+Applied 下流式也该委托，实际 call=%v err=%v", call, err)
		}
		if !call.attempt.IsStream {
			t.Fatalf("Attempt 要如实声明这是流式交换（0 的合法性靠它把关）")
		}
		if call.attempt.Timeout != 0 {
			t.Errorf("流式委托不该带执行器侧总时限，实际 %v —— 长回答会被正常掐断", call.attempt.Timeout)
		}
		if call.attempt.MaxResponseBytes != 0 {
			t.Errorf("流式委托不该设响应体上限，实际 %d —— 有上限就要缓存", call.attempt.MaxResponseBytes)
		}
		if !call.attempt.WantUsage {
			t.Errorf("OpenAI 方言的流式委托要声明 usage 注入，否则上游不回 usage 末帧、计量集体归零")
		}
		if call.attempt.EgressCheck != nil {
			t.Errorf("出网校验不该在 Attempt 里再填一份（两个校验点必然漂移）")
		}
		if err := call.attempt.Validate(); err != nil {
			t.Fatalf("流式 Attempt 过不了自家校验，执行器会在出网前拒掉: %v", err)
		}
		notStream := call.attempt
		notStream.IsStream = false
		if err := notStream.Validate(); err == nil {
			t.Errorf("摘掉 IsStream 后这两个 0 必须不合法，否则「忘了填」和「显式不限」分不开")
		}
	})

	cases := []struct {
		name   string
		mutate func(rt *policyRuntime, shot *policyShot, ask *executorAsk)
	}{
		{"运行态缺失", func(rt *policyRuntime, _ *policyShot, _ *executorAsk) { rt.exec = nil }},
		{"计划没生效", func(_ *policyRuntime, shot *policyShot, _ *executorAsk) { shot.Applied = false }},
		{"shadow 模式", func(rt *policyRuntime, _ *policyShot, _ *executorAsk) { rt.mode = config.PolicyModeShadow }},
		// 这条只钉非流式：流式的时限由调用方 ctx 持有，Attempt 用 0 如实表达，
		// 不吃「时限不可表达」这一票（见下面的「流式委托」子用例）。
		{"非流式时限不可表达", func(_ *policyRuntime, _ *policyShot, ask *executorAsk) {
			ask.timeout = 0
		}},
		{"计划没描述这家", func(_ *policyRuntime, shot *policyShot, _ *executorAsk) {
			shot.Plan = execPlan("vendorZ", policyExecutorOpenAI, "gpt-4o")
		}},
		{"候选没有执行器名", func(_ *policyRuntime, shot *policyShot, _ *executorAsk) {
			shot.Plan = execPlan("vendorA", "", "gpt-4o")
		}},
		{"计划与真实目标漂移", func(_ *policyRuntime, shot *policyShot, ask *executorAsk) {
			shot.Plan = execPlan("vendorA", policyExecutorOpenAI, "gpt-4o-mini")
			ask.upstreamModel = "gpt-4o"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, shot, ask := execRT(config.PolicyModeEnforce, nil), execShot(true, okPlan), base()
			tc.mutate(rt, shot, &ask)
			call, err := h.srv.executorCallFor(rt, shot, ask)
			if err != nil {
				t.Fatalf("%s 应是「不委托」而不是「拒候选」: %v", tc.name, err)
			}
			if call != nil {
				t.Errorf("%s 下不该委托，实际给出 %v", tc.name, call.name)
			}
		})
	}

	t.Run("没有供应商就不判", func(t *testing.T) {
		ask := base()
		ask.prov = nil
		call, err := h.srv.executorCallFor(execRT(config.PolicyModeEnforce, nil), execShot(true, okPlan), ask)
		if call != nil || err != nil {
			t.Errorf("ask 缺供应商时应直接不委托，实际 call=%v err=%v", call, err)
		}
	})
}

// ---------------------------------------------------------------- 失败路径

// 通道装不起来（这里是代理 URL 写坏）：错误要在请求上指名、要缓存、
// 且不得端出密钥，也不能顺手出一趟网。
func TestExecutor30AssemblyFailureNamesCauseWithoutSecrets(t *testing.T) {
	up := startExecUp(t, procJSON("unreachable-by-design"))
	h := execHarness(t, up.url(), "enforce", 0)
	prov := execProvider(t, h, "vendorA")
	rt := execRT(config.PolicyModeEnforce, nil)
	shot := execShot(true, execPlan("vendorA", policyExecutorOpenAI, "gpt-4o"))

	ask := executorAsk{
		prov: prov, model: "gpt-4o", upstreamModel: "gpt-4o",
		requestID: "req-exec-assembly", path: "/chat/completions",
		proxyURL: "http://%zz", timeout: time.Minute,
		body: []byte(`{"model":"gpt-4o","messages":[]}`),
	}
	call, err := h.srv.executorCallFor(rt, shot, ask)
	if err == nil {
		t.Fatalf("代理 URL 写坏时该在请求上端出原因，实际 call=%v", call)
	}
	if call != nil {
		t.Errorf("装配失败不该给出调用现场")
	}
	if !strings.Contains(err.Error(), prov.Name) && !strings.Contains(err.Error(), policyExecutorOpenAI) {
		t.Errorf("错误要指名失败的环节，实际: %v", err)
	}
	if strings.Contains(err.Error(), prov.APIKey) {
		t.Errorf("错误文本里出现了上游密钥明文: %v", err)
	}
	// 坏 URL 是配置事实：第二次调用必须吃到缓存，而不是每请求重撞一次 transport。
	if _, err2 := h.srv.executorCallFor(rt, shot, ask); err2 == nil {
		t.Errorf("第二次仍该失败（缓存了原因），实际 err=nil")
	}
	if len(rt.exec.entries) != 1 {
		t.Errorf("失败也该只留一条通道缓存，实际 %d 条", len(rt.exec.entries))
	}
	var cachedErr error
	for _, e := range rt.exec.entries {
		cachedErr = e.err
	}
	if cachedErr == nil {
		t.Errorf("缓存条目没记下失败原因，下一个请求会重撞 transport")
	}
	if up.hits() != 0 {
		t.Errorf("装配失败不该出网，上游收到 %d 个请求", up.hits())
	}
}

// 一次正常超时的归因：必须还是「供应商请求超时」，既不是「客户端走了」，
// 也不留正文（§2.9 规则 6）。委托与 2.x 两条路的超时文案必须同形。
func TestExecutor30TimeoutAttributionMatchesLegacy(t *testing.T) {
	slow := func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(1600 * time.Millisecond):
			procJSON("too slow to matter")(w, r)
		case <-r.Context().Done():
		}
	}

	delUp := startExecUp(t, slow)
	delH := execHarness(t, delUp.url(), "enforce", 1000)
	legUp := startExecUp(t, slow)
	legH := execHarness(t, legUp.url(), "", 1000)

	resp, body := procChat(t, delH, "req-exec-timeout-del", piiSample, false)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("委托侧超时应 502，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if got := resp.Header.Get("X-Llmproxy-Executor"); got != policyExecutorOpenAI {
		t.Fatalf("前提不成立：这条超时没走执行器（委托头 %q）", got)
	}
	rec := recentRecord(t, delH, "req-exec-timeout-del")
	if !strings.Contains(rec.ErrorMsg, "请求超时") {
		t.Errorf("委托侧超时应归因成「请求超时」，实际: %s", rec.ErrorMsg)
	}
	if strings.Contains(rec.ErrorMsg, "客户端") {
		t.Errorf("一次正常超时不该归因成客户端走了: %s", rec.ErrorMsg)
	}
	if strings.Contains(rec.ErrorMsg, "someone@example.com") || strings.Contains(rec.ErrorMsg, "13800138000") {
		t.Errorf("§2.9 规则 6：失败记录里不该出现正文: %s", rec.ErrorMsg)
	}
	if rec.OK || rec.Provider != "vendorA" {
		t.Errorf("失败记录该归属到这家上游，实际 ok=%v provider=%q", rec.OK, rec.Provider)
	}

	respLeg, _ := procChat(t, legH, "req-exec-timeout-leg", piiSample, false)
	recLeg := recentRecord(t, legH, "req-exec-timeout-leg")
	if respLeg.StatusCode != http.StatusBadGateway {
		t.Fatalf("2.x 侧超时也应 502，实际 %d", respLeg.StatusCode)
	}
	if !strings.Contains(recLeg.ErrorMsg, "请求超时") {
		t.Errorf("2.x 侧超时应归因成「请求超时」，实际: %s", recLeg.ErrorMsg)
	}
}

// 上游返回 4xx（不可重试那类）：委托路径把它当**这次交换的事实**透传，
// 而不是当执行器自己的故障 —— 状态码与错误体照原样回到客户端，且不重复打上游。
func TestExecutor30UpstreamErrorStatusPassesThrough(t *testing.T) {
	up := startExecUp(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":{"type":"invalid_request_error","message":"model not found"}}`)
	})
	h := execHarness(t, up.url(), "enforce", 0)

	resp, body := procChat(t, h, "req-exec-400", "ask something", false)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("上游 400 该原样回到客户端，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if !strings.Contains(string(body), "model not found") {
		t.Errorf("上游的错误体该透传给客户端（换一套词就等于替上游编造原因）: %s", truncateMsg(string(body), 200))
	}
	if up.hits() != 1 {
		t.Errorf("400 不是可重试状态，不该再打第二次上游，实际 %d 次", up.hits())
	}
	rec := recentRecord(t, h, "req-exec-400")
	if rec.StatusCode != http.StatusBadRequest || rec.OK {
		t.Errorf("库里该如实记成 400 失败，实际 %d ok=%v", rec.StatusCode, rec.OK)
	}
	if rec.Provider != "vendorA" {
		t.Errorf("失败要归属到真正跑过的这家，实际 %q", rec.Provider)
	}
	// 执行器不该把上游的 4xx 变成自己的故障码：回话里没有 executor_* 字样。
	if strings.Contains(string(body), "executor_") {
		t.Errorf("回话泄漏了执行器内部码: %s", truncateMsg(string(body), 200))
	}
}

// 上游持续 5xx：换下一家的行为与 2.x 一致，最终状态码用上游那个而不是笼统 502。
func TestExecutor30Upstream503StillSurfacesUpstreamStatus(t *testing.T) {
	up := startExecUp(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"error":{"type":"server_error","message":"no capacity"}}`)
	})
	h := execHarness(t, up.url(), "enforce", 0)

	resp, body := procChat(t, h, "req-exec-503", "retry me", false)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("只有一家上游且它一直 503，最终该透出 503，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	// 503 是可重试状态：这家被排除后没有下一家，选路自然结束 —— 但重试判定本身要发生。
	if got := resp.Header.Get("X-Llmproxy-Executor"); got != policyExecutorOpenAI {
		t.Errorf("这条的前提是走执行器，实际委托头 %q", got)
	}
	rec := recentRecord(t, h, "req-exec-503")
	if rec.OK || rec.Provider != "vendorA" {
		t.Errorf("失败该归属到跑过的这家，实际 ok=%v provider=%q", rec.OK, rec.Provider)
	}
}

// §3.I：委托面长在指标上，而且四种形态分得开 —— 跑成功、上游明确说不行、
// 候选压根没出网、本该委托却退回 2.x。
//
// 为什么值得单独立一条：委托与否线上已经有一个响应头（X-Llmproxy-Executor），
// 而头只在客户端看得见那一发。指标要回答的是「这一小时里委托真的发生过吗」，
// 所以断言必须同时吃两个面：头说有、指标也得说同一件事。
func TestExecutor30MetricsRecordDelegationOutcomes(t *testing.T) {
	// 1) 正常委托：一次交换、零失败。
	okUp := startExecUp(t, procJSON("fine"))
	okH := execHarness(t, okUp.url(), "enforce", 0)
	resp, body := procChat(t, okH, "req-exec-m-ok", "hello", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("正常委托该 200，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if got := resp.Header.Get("X-Llmproxy-Executor"); got != policyExecutorOpenAI {
		t.Fatalf("前提不成立：这条没走执行器（头 %q）", got)
	}
	sec := execMetrics(t, okH)
	if got := int64Map(sec["exchanges"])[policyExecutorOpenAI]; got != 1 {
		t.Errorf("exchanges[%s] = %d，want 1 —— 响应头说承载者换成了执行器而指标说没发生过，两个面必然有一个在说谎",
			policyExecutorOpenAI, got)
	}
	if len(nestedInt64Map(sec["failures_by_reason"])) != 0 {
		t.Errorf("成功不该长出失败维度: %v", sec["failures_by_reason"])
	}
	// 抓取面展开成带标签的序列（不是只存在于 /healthz 的 JSON 里）。
	if _, raw := okH.get(t, "/metrics", ""); !strings.Contains(string(raw),
		`llmproxy_executor_exchanges_total{executor="`+policyExecutorOpenAI+`"} 1`) {
		t.Errorf("/metrics 里没有展开的委托序列:\n%s", truncateMsg(string(raw), 600))
	}

	// 2) 上游一直 503：交换次数与失败次数必须相等 —— 每条委托交换要么没有失败码，
	// 要么有且仅有一个（这条不变量只有按标签拆开才看得见）。
	badUp := startExecUp(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"error":{"type":"server_error","message":"no capacity"}}`)
	})
	badH := execHarness(t, badUp.url(), "enforce", 0)
	if resp503, _ := procChat(t, badH, "req-exec-m-503", "retry me", false); resp503.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("上游 503 该透出去，实际 %d", resp503.StatusCode)
	}
	badSec := execMetrics(t, badH)
	exchanged := int64Map(badSec["exchanges"])[policyExecutorOpenAI]
	if exchanged < 1 {
		t.Fatalf("一条 503 都没记进交换数: %v", badSec["exchanges"])
	}
	failed := nestedInt64Map(badSec["failures_by_reason"])[policyExecutorOpenAI][string(executor.ReasonUpstreamServerStatus)]
	if failed != exchanged {
		t.Errorf("failures(server_status)=%d 而 exchanges=%d，一次委托交换只能有一个结论", failed, exchanged)
	}

	// 3) 计划声明了本网关注册不上的名字：拒候选计数，且**不带**那个名字（标签空间
	// 封闭；那个值本身就是被拒原因，让它进标签等于让被观测的东西决定基数）。
	prov := execProvider(t, okH, "vendorA")
	rt := execRT(config.PolicyModeEnforce, map[string]executor.Protocol{})
	shot := execShot(true, execPlan("vendorA", "ollama-native", "gpt-4o"))
	if _, err := okH.srv.executorCallFor(rt, shot, executorAsk{
		prov: prov, model: "gpt-4o", upstreamModel: "gpt-4o",
		requestID: "req-exec-m-reject", path: "/chat/completions",
		timeout: time.Minute, body: []byte(`{"model":"gpt-4o","messages":[]}`),
	}); err == nil {
		t.Fatal("注册不上的名字该拒候选")
	}
	rejected := int64Map(execMetrics(t, okH)["rejected_by_stage"])
	if rejected[executorRejectUnregistered] != 1 {
		t.Errorf("rejected_by_stage = %v", rejected)
	}
	for stage := range rejected {
		if strings.Contains(stage, "ollama-native") {
			t.Errorf("计划里的执行器名不该进标签: %q", stage)
		}
	}
	// 被拒的候选一次都没出网，所以交换数不变（第 1 步那发之后仍是 1）。
	if got := int64Map(execMetrics(t, okH)["exchanges"])[policyExecutorOpenAI]; got != 1 {
		t.Errorf("拒候选不该算成交换，实际 exchanges=%d", got)
	}

	// 4) 计划与真实目标漂移：这是唯一「本该委托却静默回到 2.x」的路径，必须单独可见。
	driftRT := execRT(config.PolicyModeEnforce, nil)
	driftShot := execShot(true, execPlan("vendorA", policyExecutorOpenAI, "gpt-4o-mini"))
	call, err := okH.srv.executorCallFor(driftRT, driftShot, executorAsk{
		prov: prov, model: "gpt-4o", upstreamModel: "gpt-4o",
		requestID: "req-exec-m-drift", path: "/chat/completions",
		timeout: time.Minute, body: []byte(`{"model":"gpt-4o","messages":[]}`),
	})
	if err != nil || call != nil {
		t.Fatalf("漂移应「不委托」而不是报错或委托，实际 call=%v err=%v", call, err)
	}
	if got := int64Map(execMetrics(t, okH)["skipped"])[executorSkipPlanDrift]; got != 1 {
		t.Errorf("skipped[%s] = %d，want 1", executorSkipPlanDrift, got)
	}
}

// execMetrics 取这份运行态的执行器段（缺失即失败，不允许「段没出来」被读成「都是 0」）。
func execMetrics(t *testing.T, h *harness) map[string]any {
	t.Helper()
	sec, ok := h.srv.metrics.snapshot()["executor"].(map[string]any)
	if !ok {
		t.Fatal("metrics 快照里没有 executor 段")
	}
	return sec
}
