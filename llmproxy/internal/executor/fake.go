package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Fake 是确定性回放（§2.8）与测试用的假执行器。
//
// # 确定性的三条硬纪律（这是它区别于「随手写的 mock」的地方）
//
//   - **不读 wall clock**：没有 time.Now、没有超时模拟、没有延迟注入。
//     观测（usage/content 计数）由脚本正文即时算出，与执行时刻无关。
//     回放契约里「不能依赖当前时间」这一条，只有在 fake 里根本没有时钟
//     才算真正被验证过——装了可注入时钟的 fake 仍然会写出依赖时序的测试。
//   - **不依赖 map 遍历顺序**：脚本是有序切片，首个命中生效；seed 派生
//     走 sha256 + splitmix64（与 routing 的 SeededSource 同一族算法），
//     输入是指纹字符串，与任何 map 无关。
//   - **不读全局随机源**：math/rand 全局源一概不碰；同一 (Seed, Attempt)
//     恒产出同一结果，包括响应头（头的顺序由构造决定，不在运行期乱序）。
//
// 每次 Execute 都重新从脚本复制一份正文再包流：Outcome.Body 被消费不会影响
// 下一次同输入执行（现网很多「mock 第二次调用行为变了」的根源就在这）。
type Fake struct {
	// Seed 是回放的确定性随机源根（policy.DeriveRoutingSeed 的产物或任意稳定串）。
	Seed string
	// Rules 是按序匹配的脚本；第一个命中的规则生效（顺序即优先级，可审计）。
	Rules []FakeRule
	// SeedPool 在没有任何 Rule 命中时启用：按 H(Seed||指纹) 在池内定值选一条。
	// 用于「N 家候选都返回类似响应」的回放压测脚本，避免为每个 provider 写规则。
	SeedPool []FakeRule
	// FailUnmatched 为 true 时，规则和 SeedPool 都不命中直接报 ReasonNoScript
	// （默认 fail_closed：没脚本必须显式失败，静默编造会让回放结论无法复现）。
	FailUnmatched bool

	mu      sync.Mutex
	records []FakeRecord // 调用留痕仅供断言，不参与任何响应决策
}

// FakeRule 是一条脚本化响应。
type FakeRule struct {
	// Match 是命中条件（空值 = 不限制）。只匹配**非正文**字段：
	// 拿正文片段当匹配键会让回放脚本隐式依赖内容，绕过 §2.9 的正文纪律。
	Match FakeMatch

	// Failure 非空时这次执行「连交换都没发生」：Execute 返回对应错误。
	// 取值必须是 reasons.go 注册码（构造期校验，见 Fake.Validate）。
	Failure ReasonCode

	// Status 是回放的 HTTP 状态码，0 视为 200。
	Status int
	// Headers 是回放响应头（会经过与真实执行器同一道逐跳过滤，口径不分叉）。
	Headers http.Header
	// Body 是响应体 fixture (测试标记串，禁真实数据)。
	Body []byte
	// Protocol 声明脚本正文属于哪种方言，决定旁路扫描语义；空值取 Fake 默认协议。
	Protocol Protocol
	// Stream 声明为流式回放（同时决定 Outcome.IsStream 与扫描方言）。
	Stream bool
	// ChunkSize >0 时把 Body 切成固定大小的读块（测 flush 路径的分块行为；
	// 分块完全确定：按字节位置切，与读时机无关）。
	ChunkSize int
}

// FakeMatch 是脚本命中条件。全部为稳定标识字段。
type FakeMatch struct {
	// RequestIDExact 精确匹配 Attempt.RequestID。
	RequestIDExact string
	// ProviderExact 精确匹配 Attempt.Provider。
	ProviderExact string
	// ModelPrefix 匹配 Attempt.UpstreamModel（缺省回退 Model）的前缀。
	ModelPrefix string
	// PathExact 精确匹配 Attempt.Path。
	PathExact string
	// StreamOnly 限制规则只命中流式请求。非流式过滤用「不配 StreamOnly 的
	// 规则放后面」表达（顺序即优先级）。
	StreamOnly bool
}

// FakeRecord 是一次调用的留痕（不含正文，可安全打日志/断言）。
type FakeRecord struct {
	RequestID string
	Provider  string
	Path      string
	Model     string
	Matched   int // 命中的规则下标；-1 = 未命中走了 SeedPool 或失败
}

// NewFake 构造 fake。seed 允许任意稳定串；回放场景务必传
// policy.DeriveRoutingSeed 的产物，让「同一请求的回放」与「同一 routing 决策」
// 共享同一个可关联随机根。
func NewFake(seed string, rules ...FakeRule) *Fake {
	return &Fake{Seed: seed, Rules: append([]FakeRule(nil), rules...)}
}

var _ Executor = (*Fake)(nil)

// Name 实现 Executor。默认实例名固定，方便测试与高校示例对表。
func (f *Fake) Name() string { return "fake" }

// Capabilities 实现 Executor：fake 声明它演示上必然用到的能力。
func (f *Fake) Capabilities() []string {
	return []string{CapabilityStreaming}
}

// Validate 在启动期挡下非法脚本（Failure 码未注册等属于构造 bug，
// 不能等到回放跑到那条规则才以网络错误的形态冒出来）。
func (f *Fake) Validate() error {
	check := func(i int, r FakeRule) error {
		if r.Failure != "" && !r.Failure.Valid() {
			return newError(ReasonAttemptInvalid, "", "脚本包含未注册的失败码", nil)
		}
		if r.Failure == "" && r.Stream && len(r.Body) == 0 {
			return newError(ReasonAttemptInvalid, "", "流式脚本没有响应体", nil)
		}
		return nil
	}
	for i, r := range f.Rules {
		if err := check(i, r); err != nil {
			return err
		}
	}
	for i, r := range f.SeedPool {
		if err := check(i, r); err != nil {
			return err
		}
	}
	return nil
}

// Execute 实现 Executor。对同一 (Seed, Attempt) 恒产出同一结果。
func (f *Fake) Execute(_ context.Context, a Attempt) (Outcome, error) {
	if err := a.Validate(); err != nil {
		return Outcome{}, newError(ReasonAttemptInvalid, a.Provider, "执行入参未通过校验", err)
	}
	// fake 不消费 ctx：没有时钟、没有看门狗（见类型注释第一条纪律）。
	// 「调用方取消也照样交付」不是 bug —— 取消语义的执行属于真实传输层，
	// 回放在乎的只有「输入 → 输出」的函数性。

	rule, idx, matched := f.selectRule(a)
	f.note(a, idx)
	if !matched {
		return Outcome{}, newError(ReasonNoScript, a.Provider, "没有脚本命中且 SeedPool 为空", nil)
	}
	if rule.Failure != "" {
		return Outcome{}, newError(rule.Failure, a.Provider, "fake 脚本注入的失败", nil)
	}

	status := rule.Status
	if status == 0 {
		status = http.StatusOK
	}
	proto := rule.Protocol
	if proto == "" {
		proto = a.Protocol
	}
	if proto == "" {
		proto = ProtocolOpenAIChat
	}
	if !proto.valid() {
		return Outcome{}, newError(ReasonAttemptInvalid, a.Provider, "脚本协议未注册", nil)
	}

	body := append([]byte(nil), rule.Body...)
	// 体积执法与真实执行器同一口径：上限为 0（流式的显式「不设上限」）时不判超限，
	// 超限是失败而不是截断后照常交付；且与 HTTPExecutor 一致，失败路径不交付半截 Outcome。
	if a.MaxResponseBytes > 0 && int64(len(body)) > a.MaxResponseBytes {
		return Outcome{}, newError(ReasonBodyTooLarge, a.Provider, "脚本响应体超过 Attempt 上限", ErrBodyLimit)
	}

	obs := newObserver(modeFor(proto, rule.Stream))
	// 观测在构造时一次性完成：数据都在内存里，先扫完再交流，
	// 逐字节结果与消费时序无关（真实路径的 scanReader 是边读边扫，两者
	// 共用同一个 observer 实现，口径不分叉）。
	if obs != nil {
		obs.feed(body)
		obs.finish()
	}
	var rc io.ReadCloser = nopCloser{bytes.NewReader(body)}
	if rule.ChunkSize > 0 {
		rc = &chunkReader{data: body, size: rule.ChunkSize}
	}
	return Outcome{
		StatusCode:    status,
		Headers:       filterHopByHop(rule.Headers),
		IsStream:      rule.Stream,
		Failure:       reasonForStatus(status),
		ContentLength: int64(len(body)),
		Body:          rc,
		obs:           obs,
	}, nil
}

// nopCloser 让 bytes.Reader 满足 io.ReadCloser（fake 的 body 无需真正释放资源）。
type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

// chunkReader 按固定字节数分块交付（确定性与读时机无关）。
type chunkReader struct {
	data []byte
	size int
	pos  int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n := c.size
	if n > len(p) {
		n = len(p)
	}
	if c.pos+n > len(c.data) {
		n = len(c.data) - c.pos
	}
	copy(p[:n], c.data[c.pos:c.pos+n])
	c.pos += n
	return n, nil
}

func (c *chunkReader) Close() error { return nil }

// selectRule 定出本次生效的脚本：Rules 顺序优先 → SeedPool 定值抽签 → 未命中。
//
// 刻意**无消耗语义**：规则不看历史调用次数就永远命中同一条 —— 「同一输入
// 同一输出」是 §9 要求 F 提供的回放底线，任何依赖调用时序的脚本（前 N 次失败）
// 都会把它破掉（并发重放时尤其不稳定）。需要失败-恢复序列时，用显式不同的
// RequestID 各配一条规则来表达，序列进数据而不是进状态机。
func (f *Fake) selectRule(a Attempt) (FakeRule, int, bool) {
	fingerprint := attemptFingerprint(a)

	f.mu.Lock()
	defer f.mu.Unlock()

	for i, r := range f.Rules {
		if r.Match.matches(a) {
			return r, i, true
		}
	}
	if len(f.SeedPool) > 0 {
		i := deriveIndex(f.Seed, fingerprint, len(f.SeedPool))
		return f.SeedPool[i], i, true
	}
	if !f.FailUnmatched && len(f.Rules) == 0 {
		// 完全没配规则的裸 fake：按协议造一个最小合规响应（usage 全 0 的收尾流），
		// 让「接线冒烟」不必先写脚本。一旦配过任何规则，未命中就必须显式失败。
		return FakeRule{Status: http.StatusOK, Body: minimalScriptedBody(a.Protocol)}, -2, true
	}
	return FakeRule{}, -1, false
}

// note 记录留痕（供 Calls 断言）。
func (f *Fake) note(a Attempt, ruleIdx int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, FakeRecord{
		RequestID: a.RequestID,
		Provider:  a.Provider,
		Path:      a.Path,
		Model:     a.UpstreamModel,
		Matched:   ruleIdx,
	})
}

// Calls 返回调用留痕的副本（按调用到达顺序，切片序即记录序）。
func (f *Fake) Calls() []FakeRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]FakeRecord(nil), f.records...)
}

// Reset 清空留痕（回放脚本换轮次时用；不触碰规则与 Seed）。
func (f *Fake) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = nil
}

// matches 判定命中条件。全部是稳定标识比较，不看正文、不看时钟。
func (m FakeMatch) matches(a Attempt) bool {
	if m.RequestIDExact != "" && a.RequestID != m.RequestIDExact {
		return false
	}
	if m.ProviderExact != "" && a.Provider != m.ProviderExact {
		return false
	}
	if m.PathExact != "" && a.Path != m.PathExact {
		return false
	}
	if m.ModelPrefix != "" {
		target := a.UpstreamModel
		if target == "" {
			target = a.Model
		}
		if !strings.HasPrefix(target, m.ModelPrefix) {
			return false
		}
	}
	if m.StreamOnly && !a.IsStream {
		return false
	}
	return true
}

// attemptFingerprint 是 seed 抽签与消耗判定的稳定输入：只由确定性字段拼成。
// 用长度前缀拼接（口径同 policy.DeriveRoutingSeed :245-252），避免字段内容
// 里的分隔符与另一个 Attempt 撞出同一指纹。
func attemptFingerprint(a Attempt) string {
	model := a.UpstreamModel
	if model == "" {
		model = a.Model
	}
	var b strings.Builder
	writeFp := func(s string) { b.WriteString(lenPrefix(s)); b.WriteString(s); b.WriteByte(';') }
	writeFp("llmproxy-fake-fp-v1")
	writeFp(a.RequestID)
	writeFp(a.Provider)
	writeFp(model)
	writeFp(a.Path)
	if a.IsStream {
		writeFp("stream")
	}
	return b.String()
}

func lenPrefix(s string) string {
	// 十进制长度前缀：无歧义、跨语言可重算。
	return itoa(len(s)) + ":"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// deriveIndex 用 sha256(seed||fingerprint) 的高 64 位喂 splitmix64 再取模。
//
// 不直接用 sha256 % n（有模偏差），也不碰 math/rand 全局源；
// 与 routing.SeededSource 同族（sha256 + splitmix64），跨 Go 版本稳定。
func deriveIndex(seed, fingerprint string, n int) int {
	if n <= 1 {
		return 0
	}
	h := sha256.Sum256([]byte(seed + "|" + fingerprint))
	x := binary.LittleEndian.Uint64(h[:8])
	// splitmix64 一步输出混合，取模（2^64 对常见小 n 的偏差 < 2^-32，回放足够；
	// 这里不做拒绝采样：fake 的选择不是资金决策，偏差量级写清楚即可）。
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	x ^= x >> 31
	return int(x % uint64(n))
}

// minimalScriptedBody 给裸 fake 一个协议合规的最小响应。
// 正文只含结构性字段与测试标记串，不含任何真实内容。
func minimalScriptedBody(p Protocol) []byte {
	switch p {
	case ProtocolOllamaNative:
		return []byte(`{"model":"fake-local","message":{"role":"assistant","content":"ZZFAKE_BODY"},"done":true,"prompt_eval_count":0,"eval_count":0}` + "\n")
	default:
		return []byte(`{"id":"chatcmpl-zzfake","object":"chat.completion","model":"fake","choices":[{"index":0,"message":{"role":"assistant","content":"ZZFAKE_BODY"},"finish_reason":"stop"}],"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}`)
	}
}
