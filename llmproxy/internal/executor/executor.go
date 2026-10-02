package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/dialer"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/routing"
)

// Protocol 是一种上游在线协议形态，决定请求体形状与响应旁路扫描的方言。
//
// 为什么按协议而不是按「远程/本地」分：本地 Ollama 与 vLLM 的差异不在「本地」这个
// 位置，而在**它讲哪种协议**（原生 JSON 行 vs OpenAI 兼容）。按协议分，本地形态
// 就能复用同一套传输层，把差异关进一个 shape 适配器（local.go）。
type Protocol string

const (
	// ProtocolOpenAIChat 是 OpenAI 兼容 /v1/chat/completions：流式为 SSE（data: 行 + [DONE]），
	// 非流式为整体 JSON 对象。远程上游与 vLLM 走这一档。
	ProtocolOpenAIChat Protocol = "openai_chat"
	// ProtocolOllamaNative 是 Ollama 原生 /api/chat：流式与非流式都是 JSON 行
	// （NDJSON，每行一个对象，收尾行带 done:true 与 eval 计数）。
	ProtocolOllamaNative Protocol = "ollama_native"
)

// validProtocols 是封闭集合：未注册的协议值一律拒绝，不能让拼错的字符串
// 悄悄退化成默认方言（那会把 Ollama 的 JSON 行按 SSE 扫，usage 全记 0）。
var validProtocols = map[Protocol]bool{
	ProtocolOpenAIChat:   true,
	ProtocolOllamaNative: true,
}

func (p Protocol) valid() bool { return validProtocols[p] }

// 能力名直接复用 routing 侧的常量（§2.5 / Offer.Capabilities），本包不再自造一套：
// 两份能力词表迟早走偏。
const (
	CapabilityStreaming = routing.CapabilityStreaming
	CapabilityTools     = routing.CapabilityTools
	CapabilityVision    = routing.CapabilityVision
	CapabilityJSON      = routing.CapabilityJSON
)

// Executor 把「一次对某个上游的实际调用」抽象成一个接口。
//
// 为什么入参是一个显式的 Attempt 而不是让执行器去读配置：现网 forwarder 在选路
// 循环里同时握着 config.Provider、router 的熔断状态、store 的记账闭包，
// 「调用上游」和「记账」在同一个函数里，于是本地后端与远程后端没法共用一条链路，
// 回放也无处插入假执行器。把目标拆成纯数据传进来之后，执行器是这一层的唯一变量，
// fake（fake.go）与真实实现可以互换。
//
// 为什么出参是结构化的 Outcome 而不是 (io.ReadCloser, error)：调用方需要状态码、
// 过滤后的响应头、观测到的用量与稳定失败码，而这些都必须是「这次实际发生了什么」
// 的回报，不是执行器的主观结论。error 非 nil 只表示**连一次完整交换都没发生**
// （超时、连不上、目标被拒）；上游返回 4xx/5xx 是一次成功的交换，失败码进 Outcome。
type Executor interface {
	// Name 是稳定标识，与 policy.RouteCandidate.Executor / RoutingPlan.Executor 对得上。
	Name() string

	// Capabilities 声明这个执行器确实具备的能力名（取值词汇同 routing.Capability*）。
	// 调用方构造 Offer 时用它填能力表，D 的匹配（offer.hasCapabilities）才有着落。
	Capabilities() []string

	// Execute 打一次上游。**不重试、不换家、不记费**：预算与换家是计划层的事
	// （policy.RoutingPlan.Attempts 决定试几次），本函数一次调用只对应一次交换。
	//
	// 返回的 Outcome.Body 若为非 nil，调用方**必须 Close**（流式响应下 cancel 挂在
	// 它上面，见 http.go）。ctx 由调用方给：到期或取消即中止，方向是 fail_closed。
	Execute(ctx context.Context, attempt Attempt) (Outcome, error)
}

// Attempt 是一次执行的完整输入：目标、凭证、正文、约束，全是显式数据。
//
// 这个结构是短生命周期的：它带着请求体与密钥，因此**不得**被缓存、序列化进审计、
// 或打进日志。所有可日志字段都在注释里标了 (log-ok)，凭证与正文标了 (secret)。
type Attempt struct {
	// RequestID 是关联用的稳定 ID (log-ok)。可为空（回放里不强制）。
	RequestID string

	// Provider 是稳定供应商标识 (log-ok)。只进错误码与日志，不进 URL 拼装。
	Provider string

	// Protocol 是这次的在线协议形态。空值取执行器构造时声明的默认协议。
	Protocol Protocol

	// BaseURL 是上游基址 (log-ok)。必须 http/https，禁止内嵌凭证（见 validateTarget）。
	BaseURL string

	// APIKey 是上游密钥 (secret)。只在拼装 Authorization 头的一瞬出现；
	// 为空表示无需认证（本地 Ollama/vLLM、或凭证由 ExtraHeaders 承担的形态）。
	APIKey string

	// Path 是请求路径（如 /v1/chat/completions）(log-ok)。必须以 / 开头、
	// 不含 query/fragment/百分号解码歧义字符 —— 端点白名单在入口层判（server.go
	// 的 allowedPostPaths，约 :689-693），这里只保证拼出来的 URL 不越界。
	Path string

	// Model 是下游请求的模型名 (log-ok)，仅用于关联日志。
	Model string

	// UpstreamModel 是上游真名 (log-ok)。非空时执行前把请求体里的 model 字段
	// 改写成它（口径同 forwarder.go rewriteModelBody :800-820，见 body.go）。
	UpstreamModel string

	// Body 是最终请求体 (secret)。执行器不复制它进任何导出字段；
	// 只按 UpstreamModel / WantUsage 的显式要求改写，改写后的新切片同样只在
	// 发请求的一瞬存在。
	Body []byte

	// IsStream 声明这次交换是不是流式 (log-ok)。它决定旁路扫描的方言，
	// 也决定 WantUsage 是否有意义。由调用方从正文里探出（DetectStream），
	// 执行器不为了分流而重新解析全文（§2.9 第 7 条）。
	IsStream bool

	// WantUsage 是「请在流式请求里强制注入 stream_options.include_usage」的显式开关。
	// 计量是网关自己的需求、不该由下游客户端决定（forwarder.go :822-827 的理由），
	// 但注入这件事必须由调用方点名 —— 执行器不自作主张改正文。
	WantUsage bool

	// Timeout 是单次交换的总时限 (log-ok)。必填且为正（§5：所有外部调用必须设超时）。
	// 流式的「空闲超时」不在本包：那是需要看门狗 goroutine 的策略（现网在
	// forwarder 的 idleWatchdog），接线层可以用 ctx 自己实现。
	Timeout time.Duration

	// MaxResponseBytes 是响应体硬上限 (log-ok)。必填且为正（§5：body limit）。
	// 流式与非流式同样受限；越限即断流并回报体积超限码，绝不「读到哪算哪」。
	MaxResponseBytes int64

	// Headers 是附加请求头 (secret-adjacent：可能含凭证)。绝不允许覆盖
	// Authorization / Host / 逐跳头（口径同 forwarder.go :347-352）。
	Headers map[string]string

	// Accept 是下游的 Accept 透传 (log-ok)。空则不下发。
	Accept string

	// ProxyURL 是本跳使用的代理（http/https/socks5，语义同 dialer.NewChecked :87）。
	// 空串 = 直连；直连时显式禁掉环境代理（见 http.go newTransport 的注释）。
	ProxyURL string

	// EgressCheck 是出网校验闭包（通常是 config.CheckResolvedIP 的包装），
	// 在实际拨号的最终 IP 上再判一次，关掉 DNS rebinding 窗口（dialer/egress.go :12-27）。
	// nil = 不校验（运营者自管路径，如系统池）。
	EgressCheck dialer.IPCheck
}

var (
	// ErrAttempt 表示调用方构造的 Attempt 不合法。这是接线方的 bug，
	// 不是上游的失败：一律不出网（fail_closed），也不回退到任何默认值 ——
	// 缺超时就当不限、缺上限就当无限，正是 2.x 事故清单上的两条。
	ErrAttempt = errors.New("executor: 执行输入不合法")

	// ErrTarget 表示目标 URL 越界（非法 scheme / 内嵌凭证 / 路径不合法）。
	// 与「连不上」区分开：这是执行器自己的安全边界在拒绝，不是网络故障。
	ErrTarget = errors.New("executor: 目标被拒绝")
)

// Validate 做纯字段的入参校验（不碰 URL 语义，那些在 validateTarget 里做）。
func (a Attempt) Validate() error {
	if strings.TrimSpace(a.BaseURL) == "" {
		return fmt.Errorf("%w: BaseURL 为空", ErrAttempt)
	}
	if strings.TrimSpace(a.Path) == "" {
		return fmt.Errorf("%w: Path 为空", ErrAttempt)
	}
	if a.Timeout <= 0 {
		return fmt.Errorf("%w: Timeout 必须为正（缺超时的上游调用是一次挂起的连接池事故）", ErrAttempt)
	}
	if a.MaxResponseBytes <= 0 {
		return fmt.Errorf("%w: MaxResponseBytes 必须为正（缺响应体上限的读取是一次 OOM 事故）", ErrAttempt)
	}
	if a.Protocol != "" && !a.Protocol.valid() {
		return fmt.Errorf("%w: 未知协议 %q", ErrAttempt, string(a.Protocol))
	}
	return nil
}

// Outcome 是一次交换的**结构化回报**。
//
// 字段表里没有正文字段，这是设计而不是巧合（§2.9 / doc.go 的正文访问契约）：
// 响应字节只存在于 Body 这条流里，观测只从旁路扫描里长出**数字**。任何实现都
// 不得把响应体片段塞进 Detail、错误文本或自定义字段 —— 那是最容易发生泄露的位置。
type Outcome struct {
	// StatusCode 是上游返回的 HTTP 状态码（原样，不改写）。0 表示没拿到响应头
	// （此时 Execute 应返回 error 而不是本结构）。
	StatusCode int

	// Headers 是**过滤掉逐跳头**后的响应头副本，可直接透传给下游。
	Headers http.Header

	// Body 是响应体流：字节原样、经体积上限保护的读取器。可能为 nil
	// （执行器在拿到响应前就失败时）。调用方必须 Close。
	Body io.ReadCloser

	// IsStream 回填自 Attempt，方便下游按语义处理而不必再探正文。
	IsStream bool

	// Failure 是稳定失败码（reasons.go 的封闭集合）；空串表示「这次交换没有失败」。
	// 上游 4xx/5xx 会同时有 StatusCode 和一个 Failure 码 —— 那是「上游明确说了不行」，
	// 不是执行器的故障，两者都要在回报里出现。
	Failure ReasonCode

	// ContentLength 是响应头声明的体积（-1 = 未知）。仅作信息回报，
	// 体积执法看 Body 的实际读取（声明值不可信）。
	ContentLength int64

	// obs 是旁路扫描状态（scan.go）。非导出：观测只能经 Observed() 读出数字，
	// 它持有的也只有数字，没有正文。
	obs *observer
}

// Usage 是观测到的用量（token 计数）。
//
// 它是**观测**不是**账目**：字段可空表示「上游没报」，「没报」和「报 0」在计费上
// 差很多（现网按保守口径折算是 store 的职责，见 forwarder.go cacheSplit :55-97 的
// 夹取注释 —— 数字的可信度处理同样不该在执行器里做决策，只做归一化搬运）。
type Usage struct {
	PromptTokens     *int64 `json:"prompt_tokens,omitempty"`
	CompletionTokens *int64 `json:"completion_tokens,omitempty"`
	TotalTokens      *int64 `json:"total_tokens,omitempty"`

	// 输入缓存三档拆分（DeepSeek 显式 hit/miss 风格与 OpenAI cached_tokens 风格的
	// 归一化结果）。HasCache=false 表示上游压根没报，由计量侧按保守口径处理。
	HasCache   bool  `json:"has_cache"`
	CacheHit   int64 `json:"cache_hit"`
	CacheMiss  int64 `json:"cache_miss"`
	CacheWrite int64 `json:"cache_write"`
}

// Observation 是流读完后从 Outcome 里取出的观测结果。
type Observation struct {
	Usage    Usage `json:"usage"`
	HasUsage bool  `json:"has_usage"`
	// SawDone 表示流里见过正常收尾标记（SSE 的 [DONE] / Ollama 的 done:true）。
	// IsStream 且未见收尾标记 = 流被掐断，接线层据此决定是否按中断计费口径处理。
	SawDone bool `json:"saw_done"`
	// ContentBytes 是累计的 content 字符串字节数（判断「模型到底有没有说话」）。
	// 只有长度没有内容 —— 口径同 forwarder.go noteContent :996-1031。
	ContentBytes int `json:"content_bytes"`
}

// Observed 读出旁路观测。必须在 Body 读完（或 Close）之后调用：之前调用拿到的是
// 半成品观测，那是比拿不到更容易误记的状态。未流经过扫描器（如 fake 的纯错误
// 脚本）时返回零值。
func (o Outcome) Observed() Observation {
	if o.obs == nil {
		return Observation{}
	}
	return o.obs.observation()
}

// Snapshot 是 Outcome 的可序列化元数据（不含 Body、不含任何正文字节）。
// 审计与回放对账用它，不给任何人「把 Outcome 整个 marshal 进日志」的机会 ——
// 直接 marshal Outcome 会得到一个带 http.Header 的庞然大物，头里可能有对端凭证回显。
type Snapshot struct {
	StatusCode  int         `json:"status_code"`
	IsStream    bool        `json:"is_stream"`
	Failure     ReasonCode  `json:"failure,omitempty"`
	HeaderKeys  []string    `json:"header_keys,omitempty"`
	Observation Observation `json:"observation"`
}

// Snapshot 抽取元数据。调用方（接线层）决定进不进审计表；本包不 import store。
func (o Outcome) Snapshot() Snapshot {
	keys := make([]string, 0, len(o.Headers))
	for k := range o.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	snap := Snapshot{
		StatusCode:  o.StatusCode,
		IsStream:    o.IsStream,
		Failure:     o.Failure,
		HeaderKeys:  keys,
		Observation: o.Observed(),
	}
	return snap
}

// JSON 给 Snapshot 一个明确的序列化入口（失败只可能是调用方塞了不可编码的东西，
// 本结构里没有那种字段）。
func (s Snapshot) JSON() ([]byte, error) {
	return json.Marshal(s)
}

// DetectStream 从请求体里探「stream 字段是否为 true」。
//
// 为什么不解析整个 JSON：现网 bodyProbe（forwarder.go :21-26）就是只读路由所需的
// 三个字段，正文其余部分不归执行器看。这里更收敛 —— 模型名调用方已经传了，
// 只剩一个布尔需要探。用 json.Decoder 只解到目标键，坏 JSON 返回 false，
// 让后续的正文改写报出协议形态不符，错误点更诚实。
func DetectStream(body []byte) bool {
	var probe struct {
		Stream bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	return probe.Stream
}

// AttemptFromProvider 把现网 config.Provider 折算成一次 Attempt 的目标部分。
//
// 为什么需要这层胶水而不是让执行器直接收 Provider：Provider 是 2.x 的运行期配置
// 结构（带模型映射表、权重、索引），执行器只需要其中六个字段；整包塞进来会让
// 「执行器不读配置」的边界（doc.go 第 2 条）名存实亡。这个函数由接线方调用，
// 拆完就丢，Provider 不进任何执行器内部状态。
//
// proxies 是命名代理索引（config.ProxyRef.Resolve 需要），没有命名代理时传 nil。
func AttemptFromProvider(p *config.Provider, model string, path string, proxies map[string]config.ProxyDef) (Attempt, error) {
	if p == nil {
		return Attempt{}, fmt.Errorf("%w: provider 为 nil", ErrAttempt)
	}
	proxyURL, err := p.Proxy.Resolve(proxies)
	if err != nil {
		return Attempt{}, fmt.Errorf("%w: %v", ErrAttempt, err)
	}
	// 映射口径整个交给 config.Provider.UpstreamModel（:381-392，含 passthrough/
	// catch-all 兜底），本包不再推一遍模型映射规则 —— 那是第二个事实源。
	upstream := model
	if mapped, ok := p.UpstreamModel(model); ok {
		upstream = mapped
	}
	timeout := time.Duration(p.TimeoutMs) * time.Millisecond
	headers := make(map[string]string, len(p.ExtraHeaders))
	for k, v := range p.ExtraHeaders {
		headers[k] = v
	}
	a := Attempt{
		Provider:      p.Name,
		BaseURL:       p.BaseURL,
		APIKey:        p.APIKey,
		Path:          path,
		Model:         model,
		UpstreamModel: upstream,
		Timeout:       timeout,
		Headers:       headers,
		ProxyURL:      proxyURL,
	}
	if a.Timeout <= 0 {
		// 配置层没有兜底超时就直接报错，不在这里私设一个：默认值属于接线策略。
		return Attempt{}, fmt.Errorf("%w: provider %s 未配置 timeout_ms", ErrAttempt, p.Name)
	}
	return a, nil
}

// AttemptFromPlan 把 D 包产出的候选结论并进调用方构造的基础 Attempt。
//
// 为什么只并三个字段而不是从 plan 造整个 Attempt：计划是**决策结论**
// （executor/provider/model/upstream_model），凭证、超时、正文是**执行输入**，
// 后者不归 D 拥有也不该从审计数据里反推。provider 不一致时报错 ——
// 那是接线层拿错候选的症状，静默覆盖会让审计与实际打的靶子对不上。
func AttemptFromPlan(plan policy.RoutingPlan, cand policy.RouteCandidate, base Attempt) (Attempt, error) {
	if cand.Executor == "" {
		return Attempt{}, fmt.Errorf("%w: 候选缺少 executor 字段", ErrAttempt)
	}
	if base.Provider != "" && cand.Provider != "" && base.Provider != cand.Provider {
		return Attempt{}, fmt.Errorf("%w: Attempt.Provider=%q 与候选 %q 不一致，疑似拿错候选",
			ErrAttempt, base.Provider, cand.Provider)
	}
	a := base
	if a.RequestID == "" {
		a.RequestID = plan.RoutingSeed // 不是真 ID，但回放关联时 seed 是唯一的可关联量
	}
	a.Provider = cand.Provider
	a.Model = cand.Model
	a.UpstreamModel = cand.UpstreamModel
	return a, nil
}

// Registry 是「名字 → 执行器」的并发安全注册表。
//
// 为什么要有它而不是让调用方 if/switch 选实现：计划里的候选带 Executor 字符串
// （policy.RouteCandidate.Executor，§2.5），执行侧需要一个**纯查表**的落点；
// 散在各处的 switch 会变成第二个「谁用什么执行器」的事实源。
// 内部用 map 做键查找（不是遍历），List/Names 输出前排序 —— §2.8 禁的是
// 依赖 map 遍历顺序做决策，查表不受遍历序影响。
type Registry struct {
	mu     sync.RWMutex
	byName map[string]Executor
}

// NewRegistry 构造空注册表。
func NewRegistry() *Registry {
	return &Registry{byName: make(map[string]Executor)}
}

// Register 登记执行器。重名拒绝：静默覆盖会让「接线时登记的」与「实际跑的」
// 不是同一个实现，这类漂移在 2.x 靠人肉排查过不止一次。
func (r *Registry) Register(e Executor) error {
	if e == nil {
		return fmt.Errorf("%w: 注册了 nil 执行器", ErrAttempt)
	}
	name := e.Name()
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: 执行器缺少 Name", ErrAttempt)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.byName[name]; dup {
		return fmt.Errorf("%w: 执行器 %q 重复注册", ErrAttempt, name)
	}
	r.byName[name] = e
	return nil
}

// Get 按名字取执行器。
func (r *Registry) Get(name string) (Executor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.byName[name]
	return e, ok
}

// Names 返回稳定排序的名字清单（供管理台/健康巡检列举，不参与任何决策）。
func (r *Registry) Names() []string {
	r.mu.RLock()
	names := make([]string, 0, len(r.byName))
	for n := range r.byName {
		names = append(names, n)
	}
	r.mu.RUnlock()
	sort.Strings(names)
	return names
}

// ResolvePlanPrimary 按计划首选候选定位执行器。
// 计划没有候选或执行器未注册时返回明确错误（fail_closed：宁可不跑也不猜一个）。
func (r *Registry) ResolvePlanPrimary(plan policy.RoutingPlan) (Executor, policy.RouteCandidate, error) {
	cand, ok := plan.Primary()
	if !ok {
		return nil, policy.RouteCandidate{}, fmt.Errorf("%w: 计划没有可执行候选", ErrAttempt)
	}
	e, ok := r.Get(cand.Executor)
	if !ok {
		return nil, cand, fmt.Errorf("%w: 执行器 %q 未注册", ErrAttempt, cand.Executor)
	}
	return e, cand, nil
}
