package server

// §3.0 执行期接线的三类必测（手册要求：正常路径 / 拒绝路径 / 失败路径）。
//
// 断言全部盯「越界」而不是「功能」—— 功能对不对 E 包自己测过了，这里要守的是接线会犯的错：
//   - 影子/legacy 顺手读了正文（§3.0 线 1 要求影子只读）；
//   - 为了统一接口把流式/元数据路径缓存住（§2.9 规则 7）；
//   - 装配失败时放行未处理正文（§2.9 规则 5）；
//   - 改写正文后忘了修 Content-Length；
//   - 把处理器的失败记成供应商失败（一家健康上游被打进冷却）；
//   - 日志/审计/回话里出现正文（§2.9 规则 6）。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/processor"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// ---------------------------------------------------------------- 夹具

// procUpstream 是「把每个请求体原样记下来」的上游。
// 接线测试的关键证据都是「上游到底收到了什么字节」，所以记录必须逐字。
type procUpstream struct {
	srv     *httptest.Server
	mu      sync.Mutex
	bodies  []string
	handler http.HandlerFunc
}

func startProcUpstream(t *testing.T, handler http.HandlerFunc) *procUpstream {
	t.Helper()
	u := &procUpstream{handler: handler}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.bodies = append(u.bodies, string(raw))
		u.mu.Unlock()
		u.handler(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *procUpstream) url() string { return u.srv.URL }

func (u *procUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.bodies)
}

// last 返回上游收到的最后一个请求体（逐字）。
func (u *procUpstream) last(t *testing.T) string {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.bodies) == 0 {
		t.Fatal("上游一次都没收到请求，而断言要看它收到了什么")
	}
	return u.bodies[len(u.bodies)-1]
}

// procJSON 是普通非流式上游响应；content 会出现在助手消息里。
func procJSON(content string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":7,"total_tokens":12}}`, content)
	}
}

// procSSE 是流式上游响应：把 parts 逐块发出去，中间留一次 flush 让「逐段」可观测。
func procSSE(parts ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, p := range parts {
			fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":%q}}]}\n\n", p)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":22,\"total_tokens\":33}}\n\n")
		fmt.Fprintf(w, "data: [DONE]\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

// procDecl 拼一条 processors 声明。默认值是「能用」的那一套，
// 每个用例只写自己要偏离的字段，读起来才看得出这个用例在测什么。
func procDecl(name, typ, phase, access string, extra map[string]string) string {
	fields := map[string]string{
		"name":             name,
		"type":             typ,
		"phase":            phase,
		"scope":            `"*"`,
		"version":          `"1"`,
		"body_access":      access,
		"timeout_ms":       "2000",
		"max_input_bytes":  "65536",
		"max_output_bytes": "65536",
		"fail_closed":      "true",
	}
	for k, v := range extra {
		fields[k] = v
	}
	order := []string{"name", "type", "phase", "scope", "version", "body_access",
		"timeout_ms", "max_input_bytes", "max_output_bytes", "fail_closed",
		"allow_raw_body", "allowed_endpoints"}
	seen := map[string]bool{}
	var lines []string
	for _, k := range order {
		seen[k] = true
		if v, ok := fields[k]; ok {
			lines = append(lines, k+": "+v)
		}
	}
	// 表外的键按字典序补上：夹具写错字段名时要在加载配置时报错，而不是被静默丢掉
	// （丢掉的表现为「声明看着在、参数没生效」，正是这一整段接线要防的那类错）。
	extras := make([]string, 0, len(fields))
	for k := range fields {
		if !seen[k] {
			extras = append(extras, k)
		}
	}
	sort.Strings(extras)
	for _, k := range extras {
		lines = append(lines, k+": "+fields[k])
	}
	if len(lines) == 0 {
		return ""
	}
	out := "  - " + lines[0] + "\n"
	for _, l := range lines[1:] {
		out += "    " + l + "\n"
	}
	return out
}

// procYAML 拼「一个上游 + 3.0 模式 + 若干声明」。mode 传空串即 legacy。
func procYAML(upstreamURL, mode string, decls ...string) string {
	src := cfgYAML(map[string]string{"vendorA": upstreamURL}, []string{"sk-local"})
	if mode != "" {
		src += policySection(mode, "t-open", "system:gateway", 1)
	}
	if len(decls) > 0 {
		src += "processors:\n" + strings.Join(decls, "")
	}
	return src
}

// procHarness 建网关，并把策略包的**内容文件**一起摆上。
//
// 3.0 的运行态要「配置里的引用 + 磁盘上的内容」两样都在：只写 policy 段而没有
// t-open.yaml，策略包加载就失败 → 没有 policyRuntime → 处理器一次也不会跑。
// 那种夹具故障在断言里长得跟「脱敏没生效」一模一样，所以补齐内容文件是夹具的责任。
// mode 为空即 legacy：那一档本来就不加载策略包。
func procHarness(t *testing.T, upstreamURL, mode string, decls ...string) *harness {
	t.Helper()
	h := newHarness(t, procYAML(upstreamURL, mode, decls...))
	if mode != "" {
		writePolicyBundle(t, h, policyBundleOpen)
	}
	return h
}

// writeProcParam 写运行参数文件。目录基准与 procruntime.go 一致（配置同级）。
func writeProcParam(t *testing.T, h *harness, name, body string) {
	t.Helper()
	dir := filepath.Join(filepath.Dir(h.configPath), procParamDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// procChat 发一条真实转发请求，正文内容完全由用例给（要测的就是内容）。
func procChat(t *testing.T, h *harness, requestID, content string, stream bool) (*http.Response, []byte) {
	t.Helper()
	payload := fmt.Sprintf(`{"model":"gpt-4o","stream":%t,"messages":[{"role":"user","content":%q}]}`, stream, content)
	req, err := http.NewRequest(http.MethodPost, h.gateway.URL+"/v1/chat/completions", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-local")
	req.Header.Set("X-Request-Id", requestID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

// recentRecord 按 request id 取一条落库的请求记录。
// 落库是异步的，所以这里等到有为止 —— 断言「记成什么」之前得先确定「记了」。
func recentRecord(t *testing.T, h *harness, requestID string) store.RequestRecord {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		st, err := h.db.Stats(time.Time{}, 50)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range st.Recent {
			if r.RequestID == requestID {
				return r
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("request_id=%s 不在近期记录里", requestID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func errorKind(t *testing.T, body []byte) string {
	t.Helper()
	var out struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("回话不是 JSON: %v\n%s", err, truncateMsg(string(body), 200))
	}
	return out.Error.Type
}

const piiSample = "我的邮箱是 someone@example.com，手机 13800138000"

// ---------------------------------------------------------------- 正常路径

// enforce 下的脱敏必须真的到达上游：这是整条接线的存在理由。
// 同时钉住「显式声明缓冲」（§2.9 规则 8）与「记录里有策略版本」。
func TestProcessorEnforceMasksBodyBeforeUpstream(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("pii", processor.TypePIIMask, "before-upstream", "transform-body", nil))

	resp, body := procChat(t, h, "req-proc-mask", piiSample, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("脱敏成功应照常转发，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	sent := up.last(t)
	if strings.Contains(sent, "someone@example.com") || strings.Contains(sent, "13800138000") {
		t.Errorf("上游收到了未脱敏正文: %s", truncateMsg(sent, 300))
	}
	// 占位符外形是 <masked:类型:哈希>，而网关转发前重新 marshal 过正文，尖括号会写成
	// Unicode 转义，所以这里只钉 `masked:` 这段（缺它才是「脱敏没跑」的信号）。
	if !strings.Contains(sent, "masked:") {
		t.Errorf("上游收到的正文里该有占位符: %s", truncateMsg(sent, 300))
	}
	if got := resp.Header.Get("X-Llmproxy-Body-Pipeline"); got != "buffered" {
		t.Errorf("§2.9 规则 8：进了缓冲管道要显式声明，实际头=%q", got)
	}
	if !bytes.Contains(body, []byte("pong")) {
		t.Errorf("响应该照常回到客户端: %s", body)
	}
}

// 只有 after-upstream 的链不能把请求侧变成缓冲：
// §2.9 规则 7 要求「未启用正文处理时继续流式透传」，而启用的是**响应**处理。
func TestProcessorAfterUpstreamLeavesRequestUnbuffered(t *testing.T) {
	up := startProcUpstream(t, procJSON("here is PASSWORD please ignore"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("filter", processor.TypeResultFilter, "after-upstream", "transform-body", nil))
	writeProcParam(t, h, "filter", `{"filter_rules":[{"name":"secret","keywords":["PASSWORD"]}]}`)

	resp, body := procChat(t, h, "req-proc-resp", piiSample, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应 200，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	// 请求侧一字未动（链上没有请求阶段的处理器）
	if got := up.last(t); !strings.Contains(got, "someone@example.com") {
		t.Errorf("after-upstream 不该改写请求正文，上游收到: %s", truncateMsg(got, 300))
	}
	// 响应侧改写了，且 Content-Length 跟着新长度走
	if strings.Contains(string(body), "PASSWORD") {
		t.Errorf("响应里的关键词该被过滤掉: %s", body)
	}
	if !strings.Contains(string(body), "[filtered]") {
		t.Errorf("过滤要留占位痕迹: %s", body)
	}
	if cl := resp.Header.Get("Content-Length"); cl != fmt.Sprintf("%d", len(body)) {
		t.Errorf("改写后 Content-Length 必须重算，头=%s 实际=%d", cl, len(body))
	}
	if got := resp.Header.Get("X-Llmproxy-Body-Pipeline"); got != "buffered" {
		t.Errorf("非流式响应进了缓冲管道要声明，实际=%q", got)
	}
}

// 流式：after-upstream 的过滤器必须逐段包装，而不是把整条流缓存住。
// 同时看门狗触达层要在包装链的**上游**（这里用「照常出 usage 并正常收尾」验链没插反）。
func TestProcessorStreamWrapsChunksWithoutBuffering(t *testing.T) {
	up := startProcUpstream(t, procSSE("alpha SECRET", " beta", " gamma"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("filter", processor.TypeResultFilter, "after-upstream", "transform-body", nil))
	writeProcParam(t, h, "filter", `{"filter_rules":[{"name":"secret","keywords":["SECRET"]}],"max_line_bytes":4096}`)

	resp, body := procChat(t, h, "req-proc-stream", piiSample, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("流式应照常 200，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("流式响应类型不该变，实际 %q", ct)
	}
	if strings.Contains(string(body), "SECRET") {
		t.Errorf("流式分块里的关键词该被逐段过滤: %s", body)
	}
	if !strings.Contains(string(body), "[DONE]") {
		t.Errorf("包装链不该把流的结尾吃掉: %s", body)
	}
	if got := resp.Header.Get("X-Llmproxy-Body-Pipeline"); got != "stream" {
		t.Errorf("流式包装要声明 stream，实际=%q", got)
	}
	// usage 仍然扫得到（scanner 在包装链下游、dest 之前）—— 记账没被处理器打断
	rec := recentRecord(t, h, "req-proc-stream")
	if rec.TotalTokens == nil || *rec.TotalTokens != 33 {
		t.Errorf("流式 usage 应仍被记账，实际 %+v", rec.TotalTokens)
	}
}

// 两侧同时参与时两个事实都要说出来。
//
// 覆盖式写法会把「请求正文被整段读过并改写过」抹成一个 stream，而 buffered 恰恰是
// max_input_bytes / timeout_ms 生效的那一段 —— 声明头只报「响应是流式」就等于把
// 唯一那条有信息量的事实丢掉了。
func TestProcessorBodyPipelineHeaderReportsBothSides(t *testing.T) {
	up := startProcUpstream(t, procSSE("alpha SECRET", " beta"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("pii", processor.TypePIIMask, "before-upstream", "transform-body", nil),
		procDecl("filter", processor.TypeResultFilter, "after-upstream", "transform-body", nil))
	writeProcParam(t, h, "filter", `{"filter_rules":[{"name":"secret","keywords":["SECRET"]}]}`)

	resp, body := procChat(t, h, "req-proc-both", piiSample, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("应 200，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if got := resp.Header.Get("X-Llmproxy-Body-Pipeline"); got != "buffered,stream" {
		t.Errorf("两侧管道要各自留名，实际=%q", got)
	}
	if got := up.last(t); strings.Contains(got, "13800138000") {
		t.Errorf("请求侧仍应脱敏: %s", truncateMsg(got, 300))
	}
	if strings.Contains(string(body), "SECRET") {
		t.Errorf("响应侧仍应逐段过滤: %s", body)
	}
}

// 这是 §2.9 规则 7 最容易破的地方：接线的冲动就是「反正都调 RunRequest 了，先缓存一份省事」。
func TestProcessorMetadataOnlyNeverBuffers(t *testing.T) {
	okSchema := `{"schema":{"type":"object","required":["path","bytes"],"properties":{"path":{"type":"string"},"bytes":{"type":"integer"}}}}`
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("meta", processor.TypeJSONSchema, "before-route", "metadata-only", nil))
	writeProcParam(t, h, "meta", okSchema)

	resp, body := procChat(t, h, "req-proc-meta", piiSample, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("元数据校验通过应照常转发，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	sent := up.last(t)
	if !strings.Contains(sent, "someone@example.com") {
		t.Errorf("metadata-only 不得改写正文，上游收到: %s", truncateMsg(sent, 300))
	}
	if got := resp.Header.Get("X-Llmproxy-Body-Pipeline"); got != "" {
		t.Errorf("metadata-only 不该进缓冲管道，实际声明=%q", got)
	}
}

// 计划里的处理器链必须来自同一份装配结果（§3.H 界面「会不会生效」的唯一判据）。
// 这里直接查判定核，因为路由模拟与线上走的是同一个 policyJudge。
func TestProcessorChainFeedsRoutingPlan(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("pii", processor.TypePIIMask, "before-upstream", "transform-body", nil))

	cfg := h.cfgStore.Current()
	rt := h.srv.policyFor(cfg)
	if rt == nil {
		t.Fatal("enforce 下应有策略运行态")
	}
	providers, _ := h.srv.providersFor("", "gpt-4o")
	shot := h.srv.policyJudge(rt, "", "gpt-4o", "req-plan-chain", "/v1/chat/completions", providers, "", time.Now())
	if shot == nil || shot.PlanErr != nil {
		t.Fatalf("应出计划: %+v", shot)
	}
	if got := strings.Join(shot.Plan.ProcessorChain, ","); got != "pii" {
		t.Errorf("计划里的 processor_chain = %q，want pii", got)
	}
}

// 范围选择器不参与本请求时，声明一个字都不该跑。
// 「配置说这条声明只管另一个组织，运行时对全量流量生效」是最贵的一类错。
func TestProcessorScopeSelectorSkipsRequest(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("pii-other", processor.TypePIIMask, "before-upstream", "transform-body",
			map[string]string{"scope": `"organization:university"`}))

	resp, body := procChat(t, h, "req-proc-scope", piiSample, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("范围不匹配时不该有影响，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if got := up.last(t); !strings.Contains(got, "13800138000") {
		t.Errorf("不匹配本范围的声明不该改写正文，上游收到: %s", truncateMsg(got, 300))
	}
}

// ---------------------------------------------------------------- 拒绝路径

// 影子模式一个字都不读正文（§3.0 线 1）。
// 与上面那条正常路径用例成对：同样的配置，只差 mode。
func TestProcessorShadowLeavesBodyUntouched(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "shadow",
		procDecl("pii", processor.TypePIIMask, "before-upstream", "transform-body", nil))

	resp, body := procChat(t, h, "req-proc-shadow", piiSample, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("影子不得改变请求结果: %d %s", resp.StatusCode, body)
	}
	sent := up.last(t)
	if !strings.Contains(sent, "someone@example.com") || !strings.Contains(sent, "13800138000") {
		t.Errorf("影子阶段正文必须原样透传，上游收到: %s", truncateMsg(sent, 300))
	}
	if got := resp.Header.Get("X-Llmproxy-Body-Pipeline"); got != "" {
		t.Errorf("影子不该声明缓冲管道，实际=%q（§3.0 影子不读正文）", got)
	}
	// 版本照出：影子不改行为，但要能审出「当时是哪一版策略在旁边看着」
	if got := traceOf(t, h, "req-proc-shadow").PolicyVersion; got == "" {
		t.Error("影子也要落 policy_version")
	}
}

// legacy 模式下声明存在但完全不参与 —— 回滚开关必须真的能一刀切。
func TestProcessorLegacyModeDoesNotRun(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "",
		procDecl("pii", processor.TypePIIMask, "before-upstream", "transform-body", nil))

	resp, body := procChat(t, h, "req-proc-legacy", piiSample, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("legacy 下应照常服务: %d %s", resp.StatusCode, body)
	}
	if got := up.last(t); !strings.Contains(got, "13800138000") {
		t.Errorf("legacy 下处理器不该参与: %s", truncateMsg(got, 300))
	}
}

// schema 违规：400，且一个字节都不送去上游（拒绝发生在选路之前）。
func TestProcessorSchemaViolationRejects400(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("schema", processor.TypeJSONSchema, "before-upstream", "inspect-body", nil))
	writeProcParam(t, h, "schema", `{"schema":{"type":"object","required":["tenant_id"]}}`)

	resp, body := procChat(t, h, "req-proc-schema", piiSample, false)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("不合 schema 应 400，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if got := errorKind(t, body); got != "processor_rejected" {
		t.Errorf("错误类型 = %q，want processor_rejected", got)
	}
	if strings.Contains(string(body), "someone@example.com") {
		t.Errorf("回话里不得出现正文: %s", body)
	}
	if n := up.count(); n != 0 {
		t.Errorf("被处理器拒掉的请求不该打到上游，实际 %d 次", n)
	}
}

// 超大小：413，并指向上限来源（max_input_bytes）。
func TestProcessorInputTooLargeRejects413(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("pii", processor.TypePIIMask, "before-upstream", "transform-body",
			map[string]string{"max_input_bytes": "48", "max_output_bytes": "4096"}))

	resp, body := procChat(t, h, "req-proc-large", piiSample, false)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("超上限应 413，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if got := errorKind(t, body); got != "processor_input_too_large" {
		t.Errorf("错误类型 = %q", got)
	}
	if !strings.Contains(string(body), "max_input_bytes") {
		t.Errorf("回话要指出可操作的上限字段: %s", body)
	}
	if n := up.count(); n != 0 {
		t.Errorf("413 不该打到上游，实际 %d 次", n)
	}
}

// 声明了 allow_raw_body 却没有管理员授权：403，而且**不退化成摘要**。
// 退化会让策略作者以为原文送到了 sidecar，那是用「请求成功」掩盖合规缺口。
func TestProcessorRawBodyWithoutGrantRejects403(t *testing.T) {
	sidecarHits := 0
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sidecarHits++
		fmt.Fprint(w, `{"allowed":true}`)
	}))
	t.Cleanup(sidecar.Close)

	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("scan", processor.TypeSidecar, "before-upstream", "inspect-body", map[string]string{
			"allow_raw_body":    "true",
			"allowed_endpoints": fmt.Sprintf(`[%q]`, sidecar.URL+"/v1/scan"),
		}))
	writeProcParam(t, h, "scan", fmt.Sprintf(`{"endpoint":%q}`, sidecar.URL+"/v1/scan"))

	resp, body := procChat(t, h, "req-proc-grant", piiSample, false)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("无授权的原文出网应 403，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if got := errorKind(t, body); got != "processor_grant_denied" {
		t.Errorf("错误类型 = %q，want processor_grant_denied", got)
	}
	if sidecarHits != 0 {
		t.Errorf("未获授权时一个字节都不该出网，sidecar 收到 %d 次", sidecarHits)
	}
	if n := up.count(); n != 0 {
		t.Errorf("拒绝不该继续转发，实际 %d 次", n)
	}
}

// sidecar 正常判定通过：内容送到白名单端点、请求照常转发。
// 送出去的是**摘要**（没开 allow_raw_body），这是 §2.9 规则 3 的默认形态。
func TestProcessorSidecarSendsSummaryNotRawBody(t *testing.T) {
	var got []byte
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		fmt.Fprint(w, `{"allowed":true,"short_code":"ok"}`)
	}))
	t.Cleanup(sidecar.Close)

	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("scan", processor.TypeSidecar, "before-route", "inspect-body", map[string]string{
			"allowed_endpoints": fmt.Sprintf(`[%q]`, sidecar.URL+"/v1/scan"),
		}))
	writeProcParam(t, h, "scan", fmt.Sprintf(`{"endpoint":%q}`, sidecar.URL+"/v1/scan"))

	resp, body := procChat(t, h, "req-proc-sidecar", piiSample, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sidecar 放行时应正常转发，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if n := up.count(); n != 1 {
		t.Errorf("上游应收到 1 次，实际 %d", n)
	}
	var payload map[string]any
	if err := json.Unmarshal(got, &payload); err != nil {
		t.Fatalf("sidecar 收到的不是 JSON: %v\n%s", err, got)
	}
	if payload["content_mode"] != processor.SidecarContentNone {
		t.Errorf("默认只送摘要，content_mode = %v", payload["content_mode"])
	}
	if strings.Contains(string(got), "someone@example.com") {
		t.Errorf("未授权时原文不得出网: %s", truncateMsg(string(got), 300))
	}
	if payload["request_id"] != "req-proc-sidecar" {
		t.Errorf("投递要带 request_id，实际 %v", payload["request_id"])
	}
}

// 坏声明（缺运行参数文件）在 enforce 下必须拒掉命中它的请求，而不是放行未处理正文。
// 同时：坏声明不能让整条策略链路消失 —— 不匹配本范围的声明照常服务。
func TestProcessorBadDeclarationFailsClosed(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("schema", processor.TypeJSONSchema, "before-upstream", "inspect-body", nil),
		// 另一条声明只管别的范围：它的缺失不该波及本请求之外的判定
		procDecl("other", processor.TypePIIMask, "before-upstream", "transform-body",
			map[string]string{"scope": `"organization:university"`}))

	resp, body := procChat(t, h, "req-proc-bad", piiSample, false)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("装配不起来的声明应让请求被拒（不放行未处理正文），实际 %d: %s",
			resp.StatusCode, truncateMsg(string(body), 200))
	}
	if got := errorKind(t, body); got != "processor_unavailable" {
		t.Errorf("错误类型 = %q", got)
	}
	if n := up.count(); n != 0 {
		t.Errorf("被拒的请求不该打到上游（白花钱还白付额度），实际 %d 次", n)
	}
	// 策略判定仍然在：路由痕迹照出版本
	if got := traceOf(t, h, "req-proc-bad").PolicyVersion; got == "" {
		t.Error("坏声明不该让策略版本一起消失")
	}
}

// 同一条坏声明在影子下必须零影响：§3.0 要求影子阶段绝不因为 3.0 报错让请求变差。
func TestProcessorBadDeclarationIgnoredInShadow(t *testing.T) {
	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "shadow",
		procDecl("schema", processor.TypeJSONSchema, "before-upstream", "inspect-body", nil))

	resp, body := procChat(t, h, "req-proc-bad-shadow", piiSample, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("影子下坏声明不得影响请求: %d %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
}

// ---------------------------------------------------------------- 失败路径

// sidecar 故障 + fail_closed：503，且不落到供应商（网关自己的依赖坏了）。
func TestProcessorSidecarFailureFailClosedRejects(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(sidecar.Close)

	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("scan", processor.TypeSidecar, "before-route", "inspect-body", map[string]string{
			"allowed_endpoints": fmt.Sprintf(`[%q]`, sidecar.URL+"/v1/scan"),
			"fail_closed":       "true",
		}))
	writeProcParam(t, h, "scan", fmt.Sprintf(`{"endpoint":%q}`, sidecar.URL+"/v1/scan"))

	resp, body := procChat(t, h, "req-proc-failclosed", piiSample, false)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("fail_closed 的依赖故障应 503，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if got := errorKind(t, body); got != "processor_unavailable" {
		t.Errorf("错误类型 = %q", got)
	}
	if n := up.count(); n != 0 {
		t.Errorf("不该转发到上游，实际 %d 次", n)
	}
}

// sidecar 故障 + fail_open：跳过并照常转发。
// 「跳过」是 E 包的结论（fail_open_skipped），接线的职责是不许它变成「静默当没事发生」——
// 所以留痕必须带上原因码，这里用日志字段的结构断言守着（见 TestProcessorLogFieldsCarryNoBody）。
func TestProcessorSidecarFailureFailOpenSkips(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(sidecar.Close)

	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("scan", processor.TypeSidecar, "before-route", "inspect-body", map[string]string{
			"allowed_endpoints": fmt.Sprintf(`[%q]`, sidecar.URL+"/v1/scan"),
			"fail_closed":       "false",
		}))
	writeProcParam(t, h, "scan", fmt.Sprintf(`{"endpoint":%q}`, sidecar.URL+"/v1/scan"))

	resp, body := procChat(t, h, "req-proc-failopen", piiSample, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fail_open 应放行，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if n := up.count(); n != 1 {
		t.Errorf("跳过后应照常转发，实际 %d 次", n)
	}
}

// sidecar 判定拒绝（allowed=false）是**结论**，fail_open 冲不掉。
// 否则接这个处理器毫无意义：sidecar 说拦下、网关照样转发。
func TestProcessorSidecarVerdictRejectsEvenWithFailOpen(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"allowed":false,"short_code":"policy-block"}`)
	}))
	t.Cleanup(sidecar.Close)

	up := startProcUpstream(t, procJSON("pong"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("scan", processor.TypeSidecar, "before-route", "inspect-body", map[string]string{
			"allowed_endpoints": fmt.Sprintf(`[%q]`, sidecar.URL+"/v1/scan"),
			"fail_closed":       "false",
		}))
	writeProcParam(t, h, "scan", fmt.Sprintf(`{"endpoint":%q}`, sidecar.URL+"/v1/scan"))

	resp, body := procChat(t, h, "req-proc-verdict", piiSample, false)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("判定拒绝应 400，实际 %d: %s", resp.StatusCode, truncateMsg(string(body), 200))
	}
	if got := errorKind(t, body); got != "processor_rejected" {
		t.Errorf("错误类型 = %q", got)
	}
	if n := up.count(); n != 0 {
		t.Errorf("被拦下就不该花钱，实际转发 %d 次", n)
	}
}

// 处理器失败不能算到供应商头上：熔断与粘性看的是 relayOutcome。
// 这里验语义面：响应侧处理器拒收时，客户端拿到的是一个干净错误而不是 200 + 原文，
// 且库里那次请求的归因是 processor 而不是 upstream_*。
//
// 拒收形态选 result-filter 的 block 模式：它是响应侧唯一「按结论拦下」的声明
// （redact 只改写、永不失败）。结论类（classVerdict）无视 fail_closed 一律拒，
// 所以这里特意把 fail_closed 写成 false —— 钉住「跳过开关冲不掉一条拦截结论」。
func TestProcessorResponseFailureAttributesToProcessor(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"allowed":true}`)
	}))
	t.Cleanup(sidecar.Close)

	up := startProcUpstream(t, procJSON("bad PASSWORD token"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("filter", processor.TypeResultFilter, "after-upstream", "inspect-body", map[string]string{
			"fail_closed": "false",
		}),
		// 请求侧还有一条照常放行的 sidecar：响应失败不该把已完成的请求侧判定一起抹掉
		procDecl("scan", processor.TypeSidecar, "before-route", "inspect-body", map[string]string{
			"allowed_endpoints": fmt.Sprintf(`[%q]`, sidecar.URL+"/v1/scan"),
		}))
	writeProcParam(t, h, "filter",
		`{"filter_rules":[{"name":"secret","keywords":["PASSWORD"]}],"filter_mode":"block"}`)
	writeProcParam(t, h, "scan", fmt.Sprintf(`{"endpoint":%q}`, sidecar.URL+"/v1/scan"))

	resp, body := procChat(t, h, "req-proc-attr", piiSample, false)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		t.Fatalf("block 命中必须拒收，实际 %d %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "PASSWORD") {
		t.Errorf("拒掉的响应不得漏给客户端: %s", body)
	}
	rec := recentRecord(t, h, "req-proc-attr")
	if rec.ErrorType != "processor" {
		t.Errorf("归因应是 processor，实际 %q（%s）", rec.ErrorType, rec.ErrorMsg)
	}
	if rec.OK {
		t.Error("被处理器拒收的请求不该记成成功")
	}
	// 供应商没有被记失败：一家正常返回 200 的上游不该因为我们的链子起不来而进冷却
	if h.router.Cooling(policy.SystemScope, "vendorA") {
		t.Error("处理器失败不该让供应商进冷却")
	}
}

// 流式 + 链子起不来：必须在 WriteHeader **之前**判出来，
// 客户端拿到的是一个干净错误，而不是 200 + 一条截断的流。
//
// 触发条件选 result-filter 的 block 模式：拦截按定义要求「发出任何字节之前判定完成」，
// 而 E 包的 ProcessStream 在读第一个字节之前就返回 ErrStreamUnsupported。
// 这里要验的是接线有没有把那次提前失败变成干净改判，而不是拖到流中途断掉。
func TestProcessorStreamRejectionHappensBeforeHeader(t *testing.T) {
	up := startProcUpstream(t, procSSE("alpha PASSWORD", "beta"))
	h := procHarness(t, up.url(), "enforce",
		procDecl("filter", processor.TypeResultFilter, "after-upstream", "transform-body", nil))
	writeProcParam(t, h, "filter",
		`{"filter_rules":[{"name":"secret","keywords":["PASSWORD"]}],"filter_mode":"block"}`)

	resp, body := procChat(t, h, "req-proc-stream-bad", piiSample, true)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("还没发过字节就该干净拒绝，实际 200 + %s", truncateMsg(string(body), 200))
	}
	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "text/event-stream") {
		t.Errorf("改判后的回话不该挂着上游的 SSE 类型: %q", ct)
	}
	if strings.Contains(string(body), "PASSWORD") {
		t.Errorf("拒收的正文不得漏给客户端: %s", body)
	}
	// 归因同样是 processor：上游正常返回了 200，坏的是我们的拦截方式
	rec := recentRecord(t, h, "req-proc-stream-bad")
	if rec.ErrorType != "processor" {
		t.Errorf("归因应是 processor，实际 %q（%s）", rec.ErrorType, rec.ErrorMsg)
	}
}

// ---------------------------------------------------------------- 留痕口径

// 进处理器的元数据与给审计阶段的元数据，字段集合必须停在 §2.9 规则 6 允许的范围内。
// 这两份文档会被 sidecar 原样投递出去，多一个字段就是多一条泄漏路径 ——
// 「请求头」看着无害，实为 Authorization/Cookie 的通道。
func TestProcessorLogFieldsCarryNoBody(t *testing.T) {
	reqMeta := string(procRequestMetadata("/v1/chat/completions", 1234))
	for _, want := range []string{`"path"`, `"bytes"`, "1234"} {
		if !strings.Contains(reqMeta, want) {
			t.Errorf("请求元数据缺 %s: %s", want, reqMeta)
		}
	}
	for _, forbidden := range []string{"authorization", "cookie", "content", "messages", "api_key"} {
		if strings.Contains(strings.ToLower(reqMeta), forbidden) {
			t.Errorf("请求元数据不得含 %s: %s", forbidden, reqMeta)
		}
	}

	rec := &store.RequestRecord{
		RequestID: "r1", Model: "gpt-4o", Provider: "vendorA", StatusCode: 200,
		Stream: true, OK: true, Attempts: 1, PolicyVersion: "t-open@1",
		ErrorMsg: "上游返回了 <原文片段>",
	}
	audit := string(procAuditMetadata(rec))
	for _, want := range []string{`"request_id"`, `"policy_version"`, `"ok"`} {
		if !strings.Contains(audit, want) {
			t.Errorf("审计元数据缺 %s: %s", want, audit)
		}
	}
	if strings.Contains(audit, "原文片段") {
		t.Errorf("错误原文一律不进审计: %s", audit)
	}
}

// 回话归类只认原因码：错误原文可能含实例路径与规则表片段，一律留在日志里。
func TestProcessorHTTPClassificationUsesReasonCodes(t *testing.T) {
	cases := []struct {
		err    error
		status int
		kind   string
	}{
		{processor.Errorf(processor.ErrSchemaViolation, "实例不合 schema"), http.StatusBadRequest, "processor_rejected"},
		{processor.Errorf(processor.ErrRawBodyDenied, "未获授权"), http.StatusForbidden, "processor_grant_denied"},
		{processor.Errorf(processor.ErrInputTooLarge, "超限"), http.StatusRequestEntityTooLarge, "processor_input_too_large"},
		{processor.Errorf(processor.ErrTimeout, "超时"), http.StatusServiceUnavailable, "processor_unavailable"},
		{fmt.Errorf("包装过的 %w", processor.ErrRetryExhausted), http.StatusServiceUnavailable, "processor_unavailable"},
	}
	for _, c := range cases {
		status, kind, msg := processorHTTP(c.err)
		if status != c.status || kind != c.kind {
			t.Errorf("%v -> %d/%s，want %d/%s", c.err, status, kind, c.status, c.kind)
		}
		if strings.Contains(msg, "实例不合 schema") || strings.Contains(msg, "未获授权") {
			t.Errorf("回话文案不得带上错误原文: %s", msg)
		}
	}
}

// ---------------------------------------------------------------- 启动期校验

// 参数文件的错误与策略包缺文件是同一类事故：等到第一个请求才暴露，
// 表现就是「界面说这条声明存在，运行时没人跑它」。
func TestCheckProcessorParamsRejectsBadFiles(t *testing.T) {
	load := func(t *testing.T, decls string) *config.Config {
		t.Helper()
		up := startProcUpstream(t, procJSON("pong"))
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		src := procYAML(up.url(), "enforce", decls)
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.NewStore(path).Load()
		if err != nil {
			t.Fatalf("配置加载失败: %v", err)
		}
		return cfg
	}
	writeAt := func(t *testing.T, cfg *config.Config, name, body string) {
		t.Helper()
		dir := filepath.Join(filepath.Dir(cfg.ConfigPath), procParamDirName)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	schemaDecl := procDecl("schema", processor.TypeJSONSchema, "before-upstream", "inspect-body", nil)
	piiDecl := procDecl("pii", processor.TypePIIMask, "before-upstream", "transform-body", nil)

	// 1) 该有文件的类型缺文件
	if err := CheckProcessorParams(load(t, schemaDecl)); err == nil {
		t.Error("json-schema 缺参数文件应在启动期就拒")
	}
	// 2) pii-mask 可以没有文件（内置词表 + 每请求随机 salt）
	if err := CheckProcessorParams(load(t, piiDecl)); err != nil {
		t.Errorf("pii-mask 无参数文件应放行: %v", err)
	}
	// 3) 文件不是合法 JSON（writeAt 会补 .json，这里只给声明名 —— 给成 "pii.json"
	//    会写出 pii.json.json，于是「坏文件」根本没被读到，断言就空转了）
	bad := load(t, piiDecl)
	writeAt(t, bad, "pii", `{"pii_types": ["email"`)
	if err := CheckProcessorParams(bad); err == nil {
		t.Error("参数文件不是合法 JSON 时应拒")
	}
	// 4) 键属于别的类型：写在这里等于「配了 schema 而它从来没跑」
	wrong := load(t, piiDecl)
	writeAt(t, wrong, "pii", `{"schema":{"type":"object"}}`)
	err := CheckProcessorParams(wrong)
	if err == nil {
		t.Fatal("pii-mask 的参数文件里写 schema 必须当场炸")
	}
	for _, want := range []string{"pii-mask", "schema", "pii_types"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误信息该点出类型、坏键与可用键（缺 %q）: %v", want, err)
		}
	}
	// 5) 合法文件通过
	ok := load(t, piiDecl)
	writeAt(t, ok, "pii", `{"pii_types":["email","phone"]}`)
	if err := CheckProcessorParams(ok); err != nil {
		t.Errorf("合法参数文件应通过: %v", err)
	}
}
