package server

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// 运行指标（/healthz）。刻意不引 Prometheus 客户端：本项目的观测对象是
// 「机器可读的一份 JSON」，不是一套抓取生态。热路径只做 atomic 累加，
// 延迟百分位在查询时对环形样本现算。
//
// 字段一旦进 /healthz 就是接口：删改要写 CHANGELOG。
type runtimeMetrics struct {
	inflight     atomic.Int64
	requests     atomic.Int64
	ok           atomic.Int64
	clientErr    atomic.Int64 // 4xx：客户端问题
	upstreamErr  atomic.Int64 // 5xx：上游/网关问题
	clientGone   atomic.Int64
	rateLimited  atomic.Int64
	retries      atomic.Int64 // attempts > 1 的请求
	circuitCools atomic.Int64 // 熔断/冷却次数
	dbWriteMs    atomic.Int64 // InsertRequest 累计耗时
	dbWriteFail  atomic.Int64

	latMu   sync.Mutex
	lat     []int64 // 环形缓冲，毫秒
	latPos  int
	latFull bool

	// 影子运行统计（§3.0：shadow 必须记录决策差异和性能）。
	// 单独一组计数而不是塞进请求计数：影子判定不是请求终态，混在一起会让
	// 「一致率」看起来像成功率。
	shadowMu    sync.Mutex
	shadowBy    map[string]int64
	shadowMs    int64
	shadowCount int64
	// policyVersion 是当前生效的策略内容版本串（legacy 时为空）。
	policyVersion atomic.Value

	// 执行器委托统计（§3.I）。三个轴各自回答一个排障问题：
	// exchanges=「真的按计划的执行器跑了几次」，failures=「跑_failed_成什么码」，
	// rejected/skipped=「本该委托却没成」。
	execMu        sync.Mutex
	execExchanges map[string]int64            // 执行器名 → 交换次数
	execFailures  map[string]map[string]int64 // 执行器名 → 稳定失败码 → 次数
	execRejected  map[string]int64            // 拒候选阶段 → 次数
	execSkipped   map[string]int64            // 退回 2.x 的原因 → 次数

	// 知识检索委托统计（§3.I）：源级一次检索 = 一条 query 计数，失败带注册原因码。
	kbMu        sync.Mutex
	kbQueries   map[string]int64            // 源名 → 被问到的次数（含网关侧失败）
	kbFailures  map[string]map[string]int64 // 源名 → 注册原因码 → 次数
	kbByReason  map[string]int64            // 原因码 → 次数（跨源汇总，看「最近是不是都在超时」）
	kbMeasured  int64                       // 有耗时的检索次数（网关侧失败没有耗时，不占样本）
	kbMs        int64
	kbCitations int64
	kbTruncated int64

	// 外部身份绑定统计（§9 P8）。这一组回答「这次到底有没有把 IdP token 绑上」——
	// 请求记录里只留最终范围链，看不出链里的 org/project 是自己带的还是没带上。
	// 四种没绑上的原因各自指向不同处置，不能混成一个「未绑定」数：
	//   no_token=客户端没带（推广期正常）、invalid=验签/时效失败、subject_mismatch=
	//   拿的是别人的 token、static_key=静态 key 没有用户归属（永远绑不上）。
	idnBound     atomic.Int64
	idnNoToken   atomic.Int64
	idnInvalid   atomic.Int64
	idnMismatch  atomic.Int64
	idnStaticKey atomic.Int64

	// injectDenied 记「用户级范围想替自己开正文注入」被运行期判掉的次数（P8-5）。
	// 单列一格而不是并进通用拒绝数：这是一个安全结论（谁想越权开闸），
	// 处置动作与「声明装配不起来」完全不同 —— 前者要收紧策略包，后者要修配置文件。
	injectDenied atomic.Int64
}

// latRingSize 足够估出 p99，又不至于在高 QPS 下变成延迟采样器的内存负担。
const latRingSize = 4096

func newRuntimeMetrics() *runtimeMetrics {
	return &runtimeMetrics{lat: make([]int64, latRingSize)}
}

func (m *runtimeMetrics) beginRequest() func() {
	if m == nil {
		return func() {}
	}
	m.inflight.Add(1)
	m.requests.Add(1)
	return func() { m.inflight.Add(-1) }
}

// observe 记一次请求的终态。rec.OK / LatencyMs / Attempts / StatusCode 已填好。
func (m *runtimeMetrics) observe(rec *store.RequestRecord) {
	if m == nil || rec == nil {
		return
	}
	switch {
	case rec.OK:
		m.ok.Add(1)
	case rec.ErrorType == "client_gone":
		m.clientGone.Add(1)
	case rec.StatusCode >= 500 || rec.StatusCode == 0:
		m.upstreamErr.Add(1)
	default:
		m.clientErr.Add(1)
	}
	if rec.Attempts > 1 {
		m.retries.Add(1)
	}
	m.observeLatency(rec.LatencyMs)
}

func (m *runtimeMetrics) observeLatency(latMs int64) {
	if latMs < 0 {
		latMs = 0
	}
	m.latMu.Lock()
	m.lat[m.latPos] = latMs
	m.latPos++
	if m.latPos >= len(m.lat) {
		m.latPos = 0
		m.latFull = true
	}
	m.latMu.Unlock()
}

func (m *runtimeMetrics) noteRateLimited() {
	if m != nil {
		m.rateLimited.Add(1)
	}
}

func (m *runtimeMetrics) noteCircuitCool() {
	if m != nil {
		m.circuitCools.Add(1)
	}
}

// observeShadow 累计一次影子判定。kind 是 classifyShadowDiff 的结论，
// d 是这次判定自身花掉的时间（§3.0 要求影子同时记差异和性能）。
func (m *runtimeMetrics) observeShadow(kind string, d time.Duration) {
	if m == nil {
		return
	}
	m.shadowMu.Lock()
	if m.shadowBy == nil {
		m.shadowBy = map[string]int64{}
	}
	m.shadowBy[kind]++
	m.shadowCount++
	m.shadowMs += d.Milliseconds()
	m.shadowMu.Unlock()
}

// setPolicyVersion 记下当前生效的策略版本串，供 /healthz 直接读出「现在是哪一版」。
func (m *runtimeMetrics) setPolicyVersion(v string) {
	if m == nil {
		return
	}
	m.policyVersion.Store(v)
}

// noteIdentity 累计一次外部身份绑定结论。reason 取值空间是封闭的（见 requestIdentity30）：
// 传入未知取值不 panic 也不计数 —— 指标标签跟着请求内容长等于让一次配错把序列数打爆。
func (m *runtimeMetrics) noteIdentity(reason string) {
	if m == nil {
		return
	}
	switch reason {
	case "bound":
		m.idnBound.Add(1)
	case "unbound_no_token":
		m.idnNoToken.Add(1)
	case "unbound_invalid":
		m.idnInvalid.Add(1)
	case "unbound_subject_mismatch":
		m.idnMismatch.Add(1)
	case "unbound_static_key":
		m.idnStaticKey.Add(1)
	}
}

// identitySnapshot 给出外部身份绑定的读数。
func (m *runtimeMetrics) identitySnapshot() map[string]any {
	if m == nil {
		return nil
	}
	return map[string]any{
		"bound": m.idnBound.Load(),
		"unbound": map[string]int64{
			"no_token":         m.idnNoToken.Load(),
			"invalid":          m.idnInvalid.Load(),
			"subject_mismatch": m.idnMismatch.Load(),
			"static_key":       m.idnStaticKey.Load(),
		},
	}
}

// noteInjectEnableDenied 累计一次「用户级范围不得自助开启注入」的运行期拒绝（P8-5）。
//
// 与 noteIdentity 同一条纪律：这是个结论计数，没有可传的标签 ——
// 谁想开、哪条链，已经在拒绝那一刻的 WARN 日志里点名，指标只回答「发生过几次」。
func (m *runtimeMetrics) noteInjectEnableDenied() {
	if m != nil {
		m.injectDenied.Add(1)
	}
}

// injectionSnapshot 给出正文注入启用权判定的读数。
//
// 只有一格 denied 是有意的：正常形态（平台/组织级授权、或这条链上没有注入声明）
// 不计数 —— 把「没被拦」也记一笔等于把指标养成第二张请求表（§6 体积），
// 而「拦了几次」才是要长期看得见的那个安全信号。
func (m *runtimeMetrics) injectionSnapshot() map[string]any {
	if m == nil {
		return nil
	}
	return map[string]any{
		"enable_denied": m.injectDenied.Load(),
	}
}

// shadowSnapshot 给出影子统计的一致率与均耗时。
//
// 单独一组计数而不是塞进请求计数：影子判定不是请求终态，混在一起会让
// 「一致率」看起来像成功率。
func (m *runtimeMetrics) shadowSnapshot() map[string]any {
	if m == nil {
		return nil
	}
	m.shadowMu.Lock()
	defer m.shadowMu.Unlock()
	by := make(map[string]int64, len(m.shadowBy))
	for k, v := range m.shadowBy {
		by[k] = v
	}
	version, _ := m.policyVersion.Load().(string)
	out := map[string]any{
		"evaluated":      m.shadowCount,
		"by_verdict":     by,
		"policy_version": version,
	}
	if m.shadowCount > 0 {
		out["agree_percent"] = float64(by["agreed"]) * 100 / float64(m.shadowCount)
		out["avg_eval_ms"] = m.shadowMs / m.shadowCount
	}
	return out
}

// observeExecutorExchange 记一次「确实交给 F 执行器」的上游交换（§3.I）。
//
// reason 为空表示这次交换没有失败码。非空时取值空间是封闭的：executor 包的注册码
// （reasons.go）或接线侧的 wiring_unclassified。**不能**把注册表外的东西当 name 或
// reason 传进来 —— /metrics 与 /healthz 都不鉴权，标签跟着请求内容长就等于让一次
// 配错的策略包把序列数打爆。
func (m *runtimeMetrics) observeExecutorExchange(name, reason string) {
	if m == nil || name == "" {
		return
	}
	m.execMu.Lock()
	defer m.execMu.Unlock()
	if m.execExchanges == nil {
		m.execExchanges = map[string]int64{}
		m.execFailures = map[string]map[string]int64{}
	}
	m.execExchanges[name]++
	if reason == "" {
		return
	}
	by := m.execFailures[name]
	if by == nil {
		by = map[string]int64{}
		m.execFailures[name] = by
	}
	by[reason]++
}

// noteExecutorRejection 记一次「候选在网关侧被拒、一次都没出网」。
//
// stage 是接线侧的固定阶段名，不带计划里那个执行器名：名字注册不上本来就是被拒的
// 原因，让它进标签等于让被观测的东西决定观测的基数。
func (m *runtimeMetrics) noteExecutorRejection(stage string) {
	if m == nil || stage == "" {
		return
	}
	m.execMu.Lock()
	defer m.execMu.Unlock()
	if m.execRejected == nil {
		m.execRejected = map[string]int64{}
	}
	m.execRejected[stage]++
}

// noteExecutorSkip 记一次「本该委托却退回 2.x 传输」。
//
// 只有异常的那一种退回进这里（计划与真实目标对不上）。正常不委托的那几种情形
// （模式不对、流式、时限不可表达、计划没描述）都不记 —— 它们是 §3.F 的边界，
// 不是故障，记进同一个计数器会让「委托率」读起来像失败率。
func (m *runtimeMetrics) noteExecutorSkip(reason string) {
	if m == nil || reason == "" {
		return
	}
	m.execMu.Lock()
	defer m.execMu.Unlock()
	if m.execSkipped == nil {
		m.execSkipped = map[string]int64{}
	}
	m.execSkipped[reason]++
}

// noteKnowledgeQuery 记一次源级检索被问到（含委托根本没发出去的路径）。
func (m *runtimeMetrics) noteKnowledgeQuery(source string) {
	if m == nil || source == "" {
		return
	}
	m.kbMu.Lock()
	defer m.kbMu.Unlock()
	if m.kbQueries == nil {
		m.kbQueries = map[string]int64{}
		m.kbFailures = map[string]map[string]int64{}
	}
	m.kbQueries[source]++
}

// noteKnowledgeFailure 记一次源级检索的失败结论。
//
// reason 必须是 knowledge 包注册过的原因码（审计写入侧已经强制这一点），这里只是
// 把它抄成一条可抓取的维度。source 来自配置声明的知识源名，基数由运维决定，
// 不随请求内容长。
func (m *runtimeMetrics) noteKnowledgeFailure(source, reason string) {
	if m == nil || source == "" || reason == "" {
		return
	}
	m.kbMu.Lock()
	defer m.kbMu.Unlock()
	if m.kbFailures == nil {
		m.kbQueries = map[string]int64{}
		m.kbFailures = map[string]map[string]int64{}
	}
	if m.kbByReason == nil {
		m.kbByReason = map[string]int64{}
	}
	m.kbByReason[reason]++
	by := m.kbFailures[source]
	if by == nil {
		by = map[string]int64{}
		m.kbFailures[source] = by
	}
	by[reason]++
}

// observeKnowledgeResult 记一次「源侧真的跑过」的检索：耗时、命中数、是否截断。
//
// 网关侧失败（委托没发出去）不进这里 —— 那些路径连耗时都不能假造
// （口径同 minKBAudit：编出来的数字会被算成一次真实的零命中检索）。
func (m *runtimeMetrics) observeKnowledgeResult(durationMS int64, citations int, truncated bool) {
	if m == nil {
		return
	}
	if durationMS < 0 {
		// 负耗时不是「0 毫秒」，是「这条事件本身不对」，记成样本会把坏数据算进均值。
		return
	}
	m.kbMu.Lock()
	defer m.kbMu.Unlock()
	m.kbMeasured++
	m.kbMs += durationMS
	if citations > 0 {
		m.kbCitations += int64(citations)
	}
	if truncated {
		m.kbTruncated++
	}
}

// executorSnapshot 出执行器委托面的快照（§3.I）。
//
// 全部是拷贝：这份 map 会被 /healthz 序列化、也被 /metrics 逐条展开，而请求热路径
// 还在往里加数。
func (m *runtimeMetrics) executorSnapshot() map[string]any {
	if m == nil {
		return nil
	}
	m.execMu.Lock()
	defer m.execMu.Unlock()
	ex := make(map[string]int64, len(m.execExchanges))
	for k, v := range m.execExchanges {
		ex[k] = v
	}
	byName := make(map[string]map[string]int64, len(m.execFailures))
	for name, by := range m.execFailures {
		cp := make(map[string]int64, len(by))
		for r, v := range by {
			cp[r] = v
		}
		byName[name] = cp
	}
	rej := make(map[string]int64, len(m.execRejected))
	for k, v := range m.execRejected {
		rej[k] = v
	}
	skip := make(map[string]int64, len(m.execSkipped))
	for k, v := range m.execSkipped {
		skip[k] = v
	}
	return map[string]any{
		"exchanges":          ex,
		"failures_by_reason": byName,
		"rejected_by_stage":  rej,
		"skipped":            skip,
	}
}

// knowledgeSnapshot 出知识检索委托面的快照（§3.I）。
func (m *runtimeMetrics) knowledgeSnapshot() map[string]any {
	if m == nil {
		return nil
	}
	m.kbMu.Lock()
	defer m.kbMu.Unlock()
	q := make(map[string]int64, len(m.kbQueries))
	for k, v := range m.kbQueries {
		q[k] = v
	}
	bySrc := make(map[string]map[string]int64, len(m.kbFailures))
	for src, by := range m.kbFailures {
		cp := make(map[string]int64, len(by))
		for r, v := range by {
			cp[r] = v
		}
		bySrc[src] = cp
	}
	byReason := make(map[string]int64, len(m.kbByReason))
	for k, v := range m.kbByReason {
		byReason[k] = v
	}
	out := map[string]any{
		"queries_by_source":  q,
		"failures_by_source": bySrc,
		"failures_by_reason": byReason,
		"measured":           m.kbMeasured,
		"duration_ms_total":  m.kbMs,
		"citations":          m.kbCitations,
		"truncated":          m.kbTruncated,
	}
	if m.kbMeasured > 0 {
		out["avg_duration_ms"] = m.kbMs / m.kbMeasured
	}
	return out
}

func (m *runtimeMetrics) noteDBWrite(d time.Duration, err error) {
	if m == nil {
		return
	}
	m.dbWriteMs.Add(d.Milliseconds())
	if err != nil {
		m.dbWriteFail.Add(1)
	}
}

// snapshot 出一份给 /healthz 的 map。延迟分位对环形样本排序后现算。
func (m *runtimeMetrics) snapshot() map[string]any {
	if m == nil {
		return map[string]any{}
	}
	m.latMu.Lock()
	n := m.latPos
	if m.latFull {
		n = len(m.lat)
	}
	samples := make([]int64, n)
	copy(samples, m.lat[:n])
	m.latMu.Unlock()
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return map[string]any{
		"inflight":       m.inflight.Load(),
		"requests":       m.requests.Load(),
		"ok":             m.ok.Load(),
		"client_err":     m.clientErr.Load(),
		"upstream_err":   m.upstreamErr.Load(),
		"client_gone":    m.clientGone.Load(),
		"rate_limited":   m.rateLimited.Load(),
		"retries":        m.retries.Load(),
		"circuit_cools":  m.circuitCools.Load(),
		"db_write_ms":    m.dbWriteMs.Load(),
		"db_write_fail":  m.dbWriteFail.Load(),
		"latency_ms":     latencyPercentiles(samples),
		"latency_sample": n,
		"policy_shadow":  m.shadowSnapshot(),
		"executor":       m.executorSnapshot(),
		"knowledge":      m.knowledgeSnapshot(),
		"identity":       m.identitySnapshot(),
		"injection":      m.injectionSnapshot(),
	}
}

func latencyPercentiles(sorted []int64) map[string]int64 {
	if len(sorted) == 0 {
		return map[string]int64{"p50": 0, "p95": 0, "p99": 0, "max": 0}
	}
	pick := func(q float64) int64 {
		i := int(q * float64(len(sorted)-1))
		if i < 0 {
			i = 0
		}
		if i >= len(sorted) {
			i = len(sorted) - 1
		}
		return sorted[i]
	}
	return map[string]int64{
		"p50": pick(0.50),
		"p95": pick(0.95),
		"p99": pick(0.99),
		"max": sorted[len(sorted)-1],
	}
}
