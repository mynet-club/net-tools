package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// §3.0 接线的三类必测（手册原文：「负责接线的 agent 必须增加三类测试：shadow 与
// legacy 的差异报告、enforce 下的策略影响、回滚后行为恢复」）。
//
// 断言全部盯「越界」而不是「功能」：影子阶段最容易犯的错不是算错，而是顺手改了
// 线上状态；强制阶段最容易犯的错不是拒绝，而是把技术性排除当禁令、或者一个开关
// 就能绕过 deny-first。所以每组都同时断言「该发生的发生了」和「不该发生的没发生」。

// policyBundleOpen 放行任意模型、显式禁止 secret-model。
// 键名写成 JSON 形态（subject/resource/…）：加载器走 yaml→json→领域对象，
// 领域结构只带 json tag（见 internal/config/policybundle.go 的注释）。
const policyBundleOpen = `
id: t-open
version: 1
scope: system:gateway
entitlements:
  - subject: "*"
    resource: "model:*"
    action: use
    effect: allow
  - subject: "*"
    resource: "model:secret-model"
    action: use
    effect: deny
`

// policyBundleUniOnly 只作用于组织范围：网关与用户的范围链都不含它，
// 于是它就是「按 scope 退出 3.0」的那个形态 —— 包能加载、版本可审计，但一条判定都不做。
const policyBundleUniOnly = `
id: t-uni
version: 4
scope: organization:university
entitlements:
  - subject: "*"
    resource: "model:*"
    action: use
    effect: deny
`

// policySection 拼出 policy 段。内容文件放在与 config.yaml 同级的 policy-bundles/
// （config.DefaultBundleDir），所以这里不写 bundle_dir，缺省路径本身也要被跑到。
func policySection(mode, id, scope string, version int) string {
	return fmt.Sprintf(`
policy:
  mode: %s
  data_level: internal
  active_bundle: %s
  bundles:
    - id: %s
      version: %d
      scope: %s
`, mode, id, id, version, scope)
}

func writePolicyBundle(t *testing.T, h *harness, content string) {
	t.Helper()
	dir := filepath.Join(filepath.Dir(h.configPath), config.DefaultBundleDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	name := "t-open.yaml"
	if strings.Contains(content, "id: t-uni") {
		name = "t-uni.yaml"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// postID 显式带 X-Request-Id：回读路由痕迹要靠它（失败响应不回传自动生成的 id，
// 而策略拒绝恰恰是失败响应）。
func postID(t *testing.T, h *harness, requestID, model string) (*http.Response, []byte) {
	t.Helper()
	payload := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}]}`, model)
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

func mustOK(t *testing.T, h *harness, requestID, model string) {
	t.Helper()
	resp, body := postID(t, h, requestID, model)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("请求 %s 应 200，实际 %d: %s", requestID, resp.StatusCode, body)
	}
}

func traceOf(t *testing.T, h *harness, requestID string) *store.RoutingTrace {
	t.Helper()
	tr, err := h.db.RoutingTraceForRequest(requestID)
	if err != nil {
		t.Fatalf("查路由痕迹失败: %v", err)
	}
	if tr == nil {
		t.Fatalf("request_id=%s 没有落库", requestID)
	}
	return tr
}

// shadowStats 读影子的对外计数（差异报告的数字面）；它同时出现在 /healthz 的
// policy_shadow 块里，所以这里顺手把「对外可见」也钉住。
func shadowStats(t *testing.T, h *harness) map[string]any {
	t.Helper()
	snap := h.srv.metrics.shadowSnapshot()
	if snap == nil {
		t.Fatal("影子计数不可用")
	}
	return snap
}

func verdictOf(snap map[string]any, kind string) int64 {
	by, _ := snap["by_verdict"].(map[string]int64)
	return by[kind]
}

// ---------------------------------------------------------------- 第一类：差异报告

// shadow 必须「只看不动」：产出策略版本与差异计数，但不改选路、不拒请求、不写回放输入。
//
// 「不写 seed/digest」单独钉住是有原因的：那两个字段描述的是真正跑过的计划，
// 影子的计划没跑。写进去之后 internal/replay 会把一次没发生的决策当成事实复现，
// 而 §2.8 要的逐位复现最不该出错的地方就是这里。
func TestPolicy30ShadowObservesWithoutChangingRouting(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"})+
		policySection("shadow", "t-open", "system:gateway", 1))
	writePolicyBundle(t, h, policyBundleOpen)

	// 1) 被放行的模型：照常成功，版本落库，回放输入不落库。
	resp, body := postID(t, h, "req-shadow-ok", "m")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("影子模式不得改变结果: %d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-LLMProxy-Provider"); got != "a" {
		t.Errorf("选路仍应由旧链路决定，实际 provider=%q", got)
	}
	tr := traceOf(t, h, "req-shadow-ok")
	if tr.PolicyVersion != "t-open@1" {
		t.Errorf("policy_version = %q，影子也必须出版本（§3.0）", tr.PolicyVersion)
	}
	if tr.RoutingSeed != "" || tr.CandidatesDigest != "" || tr.RoutingEpoch != "" {
		t.Errorf("影子不得写回放输入，实际 seed=%q digest=%q epoch=%q",
			tr.RoutingSeed, tr.CandidatesDigest, tr.RoutingEpoch)
	}

	// 2) 被策略禁止的模型：影子不能把它变成 403。
	resp, body = postID(t, h, "req-shadow-deny", "secret-model")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("影子里 secret-model 仍应成功（只记差异），实际 %d: %s", resp.StatusCode, body)
	}
	if n := up.Count(); n != 2 {
		t.Errorf("上游应收到 2 次（两次都没被影子拦下），实际 %d", n)
	}
	if got := traceOf(t, h, "req-shadow-deny").PolicyVersion; got != "t-open@1" {
		t.Errorf("被拒那次也要出版本（差异要说明是哪一版不同意），实际 %q", got)
	}

	// 3) 计数里要同时看得到一致与不一致，一致率算得出来。
	snap := shadowStats(t, h)
	if got := snap["evaluated"]; got != int64(2) {
		t.Fatalf("shadow evaluated = %v，want 2", got)
	}
	if v := verdictOf(snap, shadowAgreed); v != 1 {
		t.Errorf("agreed = %d，want 1", v)
	}
	if v := verdictOf(snap, shadowDecisionDenied); v != 1 {
		t.Errorf("decision_denied = %d，want 1", v)
	}
	if v := verdictOf(snap, shadowPolicyDenied); v != 0 {
		t.Errorf("policy_denied = %d，want 0（放行模型上不该出现逐家策略排除）", v)
	}
	if pct, ok := snap["agree_percent"].(float64); !ok || pct != 50 {
		t.Errorf("agree_percent = %v，want 50", snap["agree_percent"])
	}
	if v, ok := snap["policy_version"].(string); !ok || v != "t-open@1" {
		t.Errorf("影子快照里的 policy_version = %v", snap["policy_version"])
	}
	if _, ok := snap["avg_eval_ms"]; !ok {
		t.Error("§3.0 要求影子同时记性能，avg_eval_ms 必须在")
	}

	// 4) 数字必须对外可见，否则「攒一致率」这件事没法交给监控。
	// 位置在 healthz 的 metrics 块里（与熔断/配额同一层），所以取两层。
	_, health := h.get(t, "/healthz", "")
	var parsed map[string]any
	if err := json.Unmarshal(health, &parsed); err != nil {
		t.Fatalf("healthz 不是 JSON: %v\n%s", err, health)
	}
	metrics, _ := parsed["metrics"].(map[string]any)
	block, ok := metrics["policy_shadow"].(map[string]any)
	if !ok {
		t.Fatalf("healthz 的 metrics 里应有 policy_shadow: %s", health)
	}
	if block["evaluated"] != float64(2) {
		t.Errorf("healthz 的 evaluated = %v，want 2", block["evaluated"])
	}
}

// 没做成结论的请求（范围没覆盖 / 上下文不合法）不能进一致率分母：
// 那会把「3.0 没参与」说成「3.0 有差异」。
func TestClassifyShadowDiffSeparatesNoConclusionFromDisagreement(t *testing.T) {
	agreed := &policyShot{
		Version:     "t@1",
		Decision:    policy.Decision{Allowed: true, PolicyVersion: "t@1"},
		LegacyFirst: []string{"a"},
		Primary:     "a",
	}
	if got := classifyShadowDiff(agreed); got != shadowAgreed {
		t.Errorf("一致路径 = %q", got)
	}

	moved := *agreed
	moved.Primary = "b"
	if got := classifyShadowDiff(&moved); got != shadowPrimaryMoved {
		t.Errorf("首选移出首档 = %q", got)
	}

	denied := *agreed
	denied.Decision = policy.Decision{Allowed: false, PolicyVersion: "t@1", Reason: policy.ReasonModelNotAllowed}
	if got := classifyShadowDiff(&denied); got != shadowDecisionDenied {
		t.Errorf("授权拒绝 = %q", got)
	}

	noVerdict := *agreed
	noVerdict.Decision = policy.Decision{Allowed: false}
	if got := classifyShadowDiff(&noVerdict); got != shadowNotEvaluated {
		t.Errorf("判定本身没出版本 = %q，want not_evaluated", got)
	}

	noBundle := *agreed
	noBundle.Version = ""
	noBundle.Note = "范围 user:alice 没有生效的策略包，走旧路由"
	if got := classifyShadowDiff(&noBundle); got != shadowNotEvaluated {
		t.Errorf("范围无包 = %q，want not_evaluated", got)
	}

	excluded := *agreed
	excluded.Excluded = map[string]policy.Reason{"b": policy.ReasonCandidateRegionExcluded}
	if got := classifyShadowDiff(&excluded); got != shadowPolicyDenied {
		t.Errorf("逐家策略排除 = %q", got)
	}

	empty := *agreed
	empty.PlanErr = errors.New("no_candidate")
	if got := classifyShadowDiff(&empty); got != shadowNoCandidate {
		t.Errorf("没有候选 = %q", got)
	}
}

// ---------------------------------------------------------------- 第二类：enforce 影响

// enforce 下被策略拒绝的模型必须短路成 403：不碰上游、不产影子计数。
//
// 「不碰上游」是这条测试的全部意义：拒绝发生在选路之前。如果先选再拒，
// 熔断计数与配额都被动过，一次误配的策略回滚之后线上状态是脏的。
func TestPolicy30EnforceBlocksDeniedModel(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"})+
		policySection("enforce", "t-open", "system:gateway", 1))
	writePolicyBundle(t, h, policyBundleOpen)

	resp, body := postID(t, h, "req-enforce-deny", "secret-model")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("enforce 应 403，实际 %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "policy_denied") {
		t.Errorf("错误类型应是 policy_denied: %s", body)
	}
	if n := up.Count(); n != 0 {
		t.Errorf("策略拒绝不得碰上游，实际打了 %d 次", n)
	}
	tr := traceOf(t, h, "req-enforce-deny")
	if tr.PolicyVersion != "t-open@1" {
		t.Errorf("拒绝也要出策略版本（审计要说明是哪一版拒的），实际 %q", tr.PolicyVersion)
	}
	if tr.RoutingSeed != "" {
		t.Errorf("被拒请求没跑计划，不该有 routing_seed: %q", tr.RoutingSeed)
	}
	st, err := h.db.Stats(time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if st.TotalRequests != 1 || st.TotalOK != 0 {
		t.Fatalf("stats = %+v，策略拒绝应记为一次失败请求", st)
	}

	// 同一份策略下放行的模型照常工作 —— 拒绝必须精确，不能连带。
	mustOK(t, h, "req-enforce-ok", "m")

	// enforce 不产差异报告：影子计数留在 0，否则一致率会混进两个阶段的数。
	if got := shadowStats(t, h)["evaluated"]; got != int64(0) {
		t.Errorf("enforce 不该写影子计数，实际 %v", got)
	}
}

// enforce 在选路上的第二个作用面：被分级门排除的上游不再进候选池（逐家收窄）。
//
// 这一条专门钉「收窄只收策略类原因」。两家上游都健康、都承接这个模型名，
// 差别只在声明的分级上限 —— 那是合规事实，不是优化偏好，所以 enforce 下
// 声明为 public 的那家一次都不该被打到；而在 shadow 下同一条排除只进差异报告。
func TestPolicy30EnforceNarrowsPoolByDataLevel(t *testing.T) {
	tight := startMockUpstream(t, &mockUpstream{name: "tight", apiKey: "sk-tight"})
	loose := startMockUpstream(t, &mockUpstream{name: "loose", apiKey: "sk-loose"})
	src := func(mode string) string {
		return fmt.Sprintf(`server:
  api_keys: [sk-local]
routing:
  retry: 0
  failure_threshold: 3
  cooldown_seconds: 60
providers:
  - name: tight
    base_url: %s
    api_key: sk-tight
    weight: 1
    max_data_level: public
    models: ["*"]
  - name: loose
    base_url: %s
    api_key: sk-loose
    weight: 1
    max_data_level: internal
    models: ["*"]
log:
  level: error
`, tight.baseURL, loose.baseURL) + policySection(mode, "t-open", "system:gateway", 1)
	}

	// 1) shadow：排除只进报告，两家照旧都可能被选中，一次请求都不该被拦。
	shadowH := newHarness(t, src("shadow"))
	writePolicyBundle(t, shadowH, policyBundleOpen)
	for i := 0; i < 6; i++ {
		mustOK(t, shadowH, fmt.Sprintf("req-narrow-shadow-%d", i), "m")
	}
	if got := verdictOf(shadowStats(t, shadowH), shadowPolicyDenied); got != 6 {
		t.Errorf("shadow policy_denied = %d，want 6（每次判定都该报出这条逐家排除）", got)
	}
	if tight.Count()+loose.Count() != 6 {
		t.Errorf("shadow 不该改变选路，上游合计 %d 次", tight.Count()+loose.Count())
	}

	// 2) enforce：分级不够的那家彻底不进池子。等权重下哪怕一次打到 tight 都是漏。
	// 用新的 mockUpstream 而不是复用上面的计数：计数是进程内的，跨夹具只能比增量。
	tightStrict := startMockUpstream(t, &mockUpstream{name: "tight", apiKey: "sk-tight"})
	looseStrict := startMockUpstream(t, &mockUpstream{name: "loose", apiKey: "sk-loose"})
	enforceSrc := strings.ReplaceAll(src("enforce"), tight.baseURL, tightStrict.baseURL)
	enforceSrc = strings.ReplaceAll(enforceSrc, loose.baseURL, looseStrict.baseURL)
	enforceH := newHarness(t, enforceSrc)
	writePolicyBundle(t, enforceH, policyBundleOpen)
	for i := 0; i < 8; i++ {
		resp, body := postID(t, enforceH, fmt.Sprintf("req-narrow-enforce-%d", i), "m")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("收窄后仍有可用上游，请求 %d 却失败: %d %s", i, resp.StatusCode, body)
		}
		if got := resp.Header.Get("X-LLMProxy-Provider"); got != "loose" {
			t.Fatalf("第 %d 次落到 %q，public 声明的上游在 internal 请求下不该被选中", i, got)
		}
	}
	if n := tightStrict.Count(); n != 0 {
		t.Errorf("enforce 下 tight 仍被调用 %d 次，收窄没生效", n)
	}
	if n := looseStrict.Count(); n != 8 {
		t.Errorf("enforce 下 loose 应承接全部 8 次，实际 %d", n)
	}
	if v := verdictOf(shadowStats(t, enforceH), shadowPolicyDenied); v != 0 {
		t.Errorf("enforce 不该写影子计数，实际 %d", v)
	}
}

// 排除原因为「没有别的了」时必须不动池子：全被分级门挡住属于「3.0 给不出可用计划」，
// 由 fallback_to_legacy 决定回落或拒绝，而不是让收窄把最后一家也删掉。
//
// 挡的是「回滚开关变成一把能关掉所有上游的刀」：data_level 写高一级就全站 503，
// 而那是一个配置字段本该有的最坏结果。
func TestPolicy30EnforceNarrowKeepsPoolWhenAllExcluded(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "only", apiKey: "sk-only"})
	src := fmt.Sprintf(`server:
  api_keys: [sk-local]
routing:
  retry: 0
  failure_threshold: 3
  cooldown_seconds: 60
providers:
  - name: only
    base_url: %s
    api_key: sk-only
    weight: 1
    max_data_level: public
    models: ["*"]
log:
  level: error
`, up.baseURL) + `
policy:
  mode: enforce
  data_level: confidential
  active_bundle: t-open
  bundles:
    - id: t-open
      version: 1
      scope: system:gateway
`
	h := newHarness(t, src)
	writePolicyBundle(t, h, policyBundleOpen)

	// 唯一的上游分级不够 → 计划无候选 → 缺省回落旧路由 → 请求照常成功。
	mustOK(t, h, "req-all-excluded", "m")
	if n := up.Count(); n != 1 {
		t.Errorf("回落时上游应被打 1 次，实际 %d", n)
	}
	if got := traceOf(t, h, "req-all-excluded").PolicyVersion; got != "t-open@1" {
		t.Errorf("回落也要出策略版本（审计要说明是哪一版没给出计划），实际 %q", got)
	}
}

// enforce 在选路上的作用面：粘性 > 比价 > 计划首选，且只有 enforce 才交出首选。
//
// 这个次序是硬约束而不是风格：计划的目标函数是 default（档序 + 权重随机），
// 不带成本事实；让信息更少的结论盖掉规则 B 的当前价目，等于把 mode: enforce
// 变成一个涨价开关。等价格/区域/分级事实进候选构造后这个次序才该反过来。
func TestPolicy30RoutingPreferOrder(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "shared"})
	h := newHarness(t, cfgYAML(map[string]string{"alpha": up.baseURL, "beta": up.baseURL},
		[]string{"sk-local"}))
	providers, _ := h.srv.providersFor("", "m")
	if len(providers) != 2 {
		t.Fatalf("候选池应有 2 家，实际 %d", len(providers))
	}
	enforced := func(primary string) *policyShot {
		return &policyShot{Mode: config.PolicyModeEnforce, Applied: true, Primary: primary}
	}

	if got := h.srv.routingPrefer("", "m", "", enforced("beta"), providers); got != "beta" {
		t.Errorf("无价目 + enforce 应把新会话交给计划，实际 %q", got)
	}
	shadow := &policyShot{Mode: config.PolicyModeShadow, Primary: "beta"}
	if got := h.srv.routingPrefer("", "m", "", shadow, providers); got != "" {
		t.Errorf("影子不该交出任何偏好，实际 %q", got)
	}
	if got := h.srv.routingPrefer("", "m", "alpha", enforced("beta"), providers); got != "alpha" {
		t.Errorf("粘性必须压过计划（换家会打掉前缀缓存），实际 %q", got)
	}
	// 计划首选不在池里时不能照抄：旧链路会静默地「谁都不优先」，
	// 把权重随机与比价一起丢掉。
	if got := h.srv.routingPrefer("", "m", "", enforced("ghost"), providers); got != "" {
		t.Errorf("计划首选不在池里应回落无偏好，实际 %q", got)
	}

	// 有了价目：比价排在计划之前（alpha 便宜，计划指向 beta）。
	from := hourFloor(time.Now().Add(-2 * time.Hour))
	for _, row := range []store.ProviderPrice{
		{Provider: "alpha", UpstreamModel: "m", ValidFrom: from, InMiss: 1, Out: 2},
		{Provider: "beta", UpstreamModel: "m", ValidFrom: from, InMiss: 9, Out: 90},
	} {
		p := row
		if err := h.db.InsertProviderPrice(&p); err != nil {
			t.Fatal(err)
		}
	}
	if got := h.srv.routingPrefer("", "m", "", enforced("beta"), providers); got != "alpha" {
		t.Errorf("有价目时应先按当前上游价，实际 %q", got)
	}
	// 粘性仍然在最前：省钱不该以打掉缓存为代价。
	if got := h.srv.routingPrefer("", "m", "beta", enforced("alpha"), providers); got != "beta" {
		t.Errorf("粘性应压过比价，实际 %q", got)
	}
}

// enforce 算不出计划时的两条路（允许回落 / fail-closed），以及唯一不许回落的情况：
// 授权本身就不同意。
//
// 最后这条最要紧：fallback_to_legacy 是运维开关，如果它能豁免 deny，
// 一个开关就能绕过整条 deny-first 语义 —— 那 3.0 的授权就只是建议了。
func TestPolicy30FinishPolicyFallbackCannotOverrideDeny(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}))

	newNoPlan := func() *policyShot {
		return &policyShot{
			Version:  "t@1",
			Decision: policy.Decision{Allowed: true, PolicyVersion: "t@1"},
			PlanErr:  errors.New("routing: 没有可用候选"),
		}
	}
	newDenied := func() *policyShot {
		return &policyShot{
			Version:  "t@1",
			Decision: policy.Decision{Allowed: false, PolicyVersion: "t@1", Reason: policy.ReasonModelNotAllowed},
		}
	}

	strict := &policyRuntime{mode: config.PolicyModeEnforce}
	if got := h.srv.finishPolicy(strict, newNoPlan()); got.Blocked == "" {
		t.Error("fail-closed 配置下没有计划必须拒绝")
	}
	soft := &policyRuntime{mode: config.PolicyModeEnforce, fallback: true}
	got := h.srv.finishPolicy(soft, newNoPlan())
	if got.Blocked != "" || got.Applied {
		t.Errorf("允许回落时应照常走旧路由，实际 blocked=%q applied=%v", got.Blocked, got.Applied)
	}
	if !strings.Contains(got.Note, "回落") {
		t.Errorf("回落必须留痕: %q", got.Note)
	}
	if out := h.srv.finishPolicy(soft, newDenied()); out.Blocked == "" {
		t.Error("fallback_to_legacy 不得豁免策略拒绝")
	}

	shadow := &policyRuntime{mode: config.PolicyModeShadow}
	out := h.srv.finishPolicy(shadow, newDenied())
	if out.Blocked != "" || out.Applied {
		t.Errorf("影子不得改变结果: blocked=%q applied=%v", out.Blocked, out.Applied)
	}
	if got := shadowStats(t, h)["evaluated"]; got != int64(1) {
		t.Errorf("影子必须记差异，实际计数 %v", got)
	}
}

// ---------------------------------------------------------------- 第三类：回滚恢复

// 全局回滚：mode 改成 legacy 之后，同一条被策略拒绝的请求必须恢复 2.x 行为，
// 而且记录里不能再有策略版本 —— 否则审计会以为「3.0 参与过这次请求」。
func TestPolicy30RollbackToLegacyRestoresBehavior(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	enforce := cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}) +
		policySection("enforce", "t-open", "system:gateway", 1)
	h := newHarness(t, enforce)
	writePolicyBundle(t, h, policyBundleOpen)

	if resp, body := postID(t, h, "req-rb-enforce", "secret-model"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("前提不成立：enforce 应 403，实际 %d: %s", resp.StatusCode, body)
	}

	legacySrc := strings.Replace(enforce, "mode: enforce", "mode: legacy", 1)
	if err := os.WriteFile(h.configPath, []byte(legacySrc), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, cfg, err := h.cfgStore.Reload()
	if err != nil {
		t.Fatalf("热加载失败: %v", err)
	}
	if !changed {
		t.Fatal("配置应被识别为变更")
	}
	h.router.ApplyConfig(cfg.Routing, cfg.Normalized)
	h.srv.Transports().Reset()

	mustOK(t, h, "req-rb-legacy", "secret-model")
	if got := traceOf(t, h, "req-rb-legacy").PolicyVersion; got != "" {
		t.Errorf("legacy 下不得有策略版本（实际 %q），回放会以为有 3.0 判定参与", got)
	}
	// /healthz 报的策略版本也必须清空：留着旧版本号等于说「策略在效」而实际没跑。
	if v, _ := shadowStats(t, h)["policy_version"].(string); v != "" {
		t.Errorf("回滚后 metrics 的策略版本 = %q，want 空", v)
	}
}

// 按 scope 回滚：加载了一个与本次范围链无关的包时，这条链上没有规则可用，
// 请求必须照常走旧路由 —— 这就是「某个范围退出 3.0」的开关，不用动全局 mode。
func TestPolicy30RollbackPerScopeWithoutCoveringBundle(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"})+
		policySection("enforce", "t-uni", "organization:university", 4))
	writePolicyBundle(t, h, policyBundleUniOnly)

	// 那个包写的是「所有模型都 deny」，但它不覆盖网关的范围链，所以什么都不能拒。
	mustOK(t, h, "req-scope-rb", "m")
	if got := traceOf(t, h, "req-scope-rb").PolicyVersion; got != "" {
		t.Errorf("没有生效的包时不该出策略版本，实际 %q", got)
	}
	if v := verdictOf(shadowStats(t, h), shadowNotEvaluated); v != 0 {
		t.Errorf("enforce 下不该有影子计数，实际 %d", v)
	}
	// 整集版本仍然可查：启动日志与 /healthz 要说得出「加载了什么」。
	if v, _ := shadowStats(t, h)["policy_version"].(string); v != "t-uni@4" {
		t.Errorf("metrics 的整集策略版本 = %q，want t-uni@4", v)
	}
}

// 坏配置：启动时必须拒绝（CheckPolicyRuntime），运行期继续按 legacy 服务但**不出版本**，
// 同一修订只撞一次磁盘，修订一变就重新加载。
//
// 这三条各自挡一种事故：带半套规则上线（版本串正常而规则没加载）、
// 坏配置把在跑的网关打挂、以及修好之后还要重启才生效。
func TestPolicy30BrokenBundleFailsLoudlyAndRecoversOnNextRevision(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	src := cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}) +
		policySection("enforce", "t-open", "system:gateway", 1)
	h := newHarness(t, src) // 故意不写内容文件

	if err := CheckPolicyRuntime(h.cfgStore.Current()); err == nil {
		t.Fatal("引用了不存在的策略包内容必须拒绝启动")
	} else if !strings.Contains(err.Error(), "t-open.yaml") {
		t.Errorf("错误要说清缺哪个文件: %v", err)
	}

	mustOK(t, h, "req-broken-1", "m")
	if got := traceOf(t, h, "req-broken-1").PolicyVersion; got != "" {
		t.Errorf("加载失败时不得有策略版本，实际 %q", got)
	}

	// 补上内容文件但配置没变 → 仍按坏配置处理（不把每个请求都变成一次磁盘重试）。
	writePolicyBundle(t, h, policyBundleOpen)
	mustOK(t, h, "req-broken-2", "m")
	if got := traceOf(t, h, "req-broken-2").PolicyVersion; got != "" {
		t.Errorf("修订号没变时不该重试加载，实际 policy_version=%q", got)
	}

	// 修订一变立刻重新加载。改 policy 段的 data_level：这一版加载成功后计划应当
	// **正常给出**（public 请求 + internal 声明的上游），这样断言到的版本来自一份
	// 跑通的判定，而不是「没结论也照旧落版本」的回落路径。
	// 注意必须整段换而不是就地替换字段名 —— provider 行里也有一个
	// "max_data_level: internal"，按子串替换会先命中它。
	fixed := cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"}) +
		strings.Replace(policySection("enforce", "t-open", "system:gateway", 1),
			"data_level: internal", "data_level: public", 1)
	if err := os.WriteFile(h.configPath, []byte(fixed), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, _, err := h.cfgStore.Reload()
	if err != nil {
		t.Fatalf("热加载失败: %v", err)
	}
	if !changed {
		t.Fatal("改了 policy.data_level 必须被识别为变更，否则修订号不动、策略运行态永远停在坏的那一版")
	}
	mustOK(t, h, "req-fixed", "m")
	if got := traceOf(t, h, "req-fixed").PolicyVersion; got != "t-open@1" {
		t.Errorf("修订变化后应重新加载，实际 policy_version=%q", got)
	}
}

// ---------------------------------------------------------------- 词汇映射

// 用途从请求路径推出而不是配置常量：用途参与 deny 条件，做成常量会让
// 所有 purpose 条件整批失配。未识别的路径一律 inference（保守档），
// 不许猜成 chat —— 那会把新接口的流量记成问答流量。
func TestPolicyPurposeForCoversForwardedPaths(t *testing.T) {
	cases := map[string]string{
		"/v1/chat/completions": "chat",
		"/v1/completions":      "chat",
		"/v1/messages":         "chat",
		"/v1/responses":        "chat",
		"/v1/embeddings":       "embedding",
		"/api/v1/generate":     "chat",
		"/v1/models":           "inference",
		"/v1/audio/transcribe": "inference",
		"":                     "inference",
	}
	for path, want := range cases {
		if got := policyPurposeFor(path); got != want {
			t.Errorf("policyPurposeFor(%q) = %q，want %q", path, got, want)
		}
	}
}

// 静态 key 归 system 范围而不是「user:空串」那种假身份：后者会让 user 级规则
// 命中网关主人自己的流量。邮箱形态的用户名必须在判定前显式失败（§2.1 稳定 ID），
// 悄悄换个「看起来能用」的键会让历史授权跟着走偏。
func TestPolicy30ScopeChainAndIdentityForStaticKey(t *testing.T) {
	chain, err := policyChainFor("")
	if err != nil {
		t.Fatal(err)
	}
	if !chain.Includes(policy.MustScope(policy.ScopeSystem, policySystemScope)) {
		t.Errorf("静态 key 的范围链 = %s，应含 system:%s", chain.Display(), policySystemScope)
	}
	id, err := policyIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != policySystemScope || id.Source != policySourceStatic {
		t.Errorf("静态 key 的身份 = %+v", id)
	}
	uid, err := policyIdentity("alice")
	if err != nil {
		t.Fatal(err)
	}
	if uid.Subject != "alice" || uid.Source != policySourceUser {
		t.Errorf("用户身份 = %+v", uid)
	}
	if _, err := policyIdentity("alice@example.com"); err == nil {
		t.Error("邮箱形态的用户名不该被当成稳定 ID")
	}
}

// 网关侧有两个 system 范围 id，它们不打架**只靠一条不变量**，这里把它钉住。
//
//	判定链：静态 key 的请求落在 system:gateway（policySystemScope，§3.0 线 1）
//	审计/发布归属：system 级策略写侧落在 system:global（policy.SystemScope）
//
// 于是「在管理台以 system:global 的名义发布的那一版」能作用到 system:gateway 的链上，
// 唯一原因是 PolicyBundle.Covers 对**任意** system 包按 Kind 放行、不看 ID。
// 这条哪天被改窄（按 id 精确匹配），失败方向是「策略静默不生效」而不是报错 ——
// 审计里照常写着发布成功，判定却回到旧链路，是整条链上最难查的那种分叉。
// 反向也要守住：非 system 包仍然必须精确命中，放宽只留给 Kind==system 这一格。
func TestSystemBundleCoversGatewayChainRegardlessOfID(t *testing.T) {
	chain, err := policy.NewScopeChain(policy.MustScope(policy.ScopeSystem, policySystemScope))
	if err != nil {
		t.Fatal(err)
	}

	global := policy.PolicyBundle{ID: "g", Version: 1, Scope: policy.SystemScope}
	if global.Scope.ID != "global" || policySystemScope != "gateway" {
		t.Fatalf("前置条件变了：两个 id 分别应当是 global 与 gateway，实际 %q 与 %q",
			global.Scope.ID, policySystemScope)
	}
	if !global.Covers(chain) {
		t.Error("system 范围的包必须覆盖 system:gateway 的链（Covers 按 Kind 不按 ID）")
	}

	project := policy.PolicyBundle{ID: "p", Version: 1,
		Scope: policy.MustScope(policy.ScopeProject, "cs-lab")}
	if project.Covers(chain) {
		t.Error("项目包不该命中只含 system 的链：放宽只能留在 Kind==system 那一格")
	}
}

// 粘性必须如实传给 D：不传的话计划永远按「新会话」算，
// 差异报告里的 primary_moved 大半是假的。
func TestPolicy30StickyStateOnlyForNamedProvider(t *testing.T) {
	if got := stickyState("", "t@1"); got != nil {
		t.Errorf("空粘性应返回 nil（代码里只有一种「没有粘性」的写法），实际 %+v", got)
	}
	got := stickyState("beta", "t@1")
	if got == nil || got.Provider != "beta" || got.PolicyVersion != "t@1" {
		t.Errorf("粘性输入 = %+v", got)
	}
}
