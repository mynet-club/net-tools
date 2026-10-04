package processor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// Processor 是一个数据处理单元。
//
// 实现必须是**可复用的**：同一实例会被多条请求并发调用（DoD 4 的 -race 测试覆盖这点），
// 所以任何请求态（脱敏的占位表、计数、缓存）只能放在 Process 的局部变量里，
// 不能挂在结构体字段上。挂在字段上会跨请求串内容 —— 那是跨用户泄漏，不是竞态噪音。
type Processor interface {
	// Spec 返回装配时生效的声明。审计里的处理器版本从这里来，
	// 而不是从策略里的 Spec 抄一份：两者不一致时 Build 会直接拒绝装配。
	Spec() Spec

	// Process 处理一次调用。out.Body 非 nil 表示替换正文，
	// Pipeline 会按档位、MaxOutputBytes 与释放规则校验它。
	//
	// ctx 已带上 Spec.Timeout 的 deadline；忽略它的处理器会在超时后继续占着请求。
	Process(ctx context.Context, in *Input) (*Output, error)
}

// StreamProcessor 是响应流上的增量处理能力（§2.9 规则 7）。
//
// 刻意与 Process 分开而不是「统一接口 + 内部缓冲」：后者为了实现方便会把整段响应
// 读进内存，正是规则 7 禁止的做法。只有 after-upstream 档位的处理器需要实现它。
type StreamProcessor interface {
	Processor

	// ProcessStream 包装 src，返回一个边读边过滤的读者。
	// 实现不得缓存整段响应，也不得把 src 一次性 ReadAll。
	ProcessStream(ctx context.Context, in *Input, src io.Reader) (io.Reader, error)
}

// Factory 按 Spec + Config 造一个处理器。
//
// Config 由注册表持有，不由装配调用方在 Build 时传入 —— 见 Registry.Build 的说明。
type Factory func(Spec, *Config) (Processor, error)

// RawBodyGrantChecker 是原文出网的管理员授权判定入口。
//
// *policy.Resolver 天然满足这个接口（方法签名一致），所以 E 不需要 import 具体的
// 判定实现，也不需要自己重做一遍 deny > explicit_allow > group_allow 的次序 ——
// 判定次序的唯一业务源是 A 包（手册 §5、A 文档 §1）。
type RawBodyGrantChecker interface {
	AllowsRawBody(ctx policy.PolicyContext, chain policy.ScopeChain, now time.Time) (bool, policy.Reason)
}

// Input 是单次处理器调用的输入。
//
// 字段全部由 Pipeline 填充，处理器无法自行构造一个绕过档位检查的 Input
// （body、access 与下面的留痕字段都是未导出的，只有同包的 Pipeline 能赋值）。
type Input struct {
	RequestID         string
	Phase             Phase
	Model             string
	Purpose           string
	Stream            bool
	StatusCode        int
	ContentType       string
	Metadata          json.RawMessage
	DeclaredBodyBytes int64
	Policy            policy.PolicyContext
	Chain             policy.ScopeChain
	Now               time.Time
	Spec              Spec

	access      policy.BodyAccess
	body        *Body
	read        bool // 本次调用真的读了正文（Pipeline 据此写 Buffered 与哈希）
	deniedReads int  // 被档位挡住的取正文次数（留痕用，见 DeniedReads）

	// transformed 表示当前正文已由链上更早的处理器产出（原文已被替换）。
	// sidecar 靠它区分「送脱敏正文」与「送的就是客户端原文」—— §2.9 规则 3 的分界。
	transformed bool

	grantReason policy.Reason // 策略侧的原文授权原因码，透传进审计
	summaryOnly bool          // 因缺授权而退化成只送摘要
}

// TransformedBody 报告当前正文是否已由链上更早的处理器产出。
//
// 外部调用类处理器需要这个信息：链上没有脱敏时它拿到的仍是客户端原文，
// 而「把原文发给第三方」必须有管理员授权，不能只看档位允许读正文就发。
func (in *Input) TransformedBody() bool { return in.transformed }

// NoteGrantReason 让处理器把**策略侧**（A 包）的原文授权原因码留在审计里。
//
// 单独一个字段而不是混进 Reason：审计里必须能分清「管理员没授权」和「sidecar 超时」，
// 前者是合规事件，后者是可用性事件，处置人完全不同。
func (in *Input) NoteGrantReason(reason policy.Reason) { in.grantReason = reason }

// NoteSummaryOnlyFallback 记录「本该送正文、实际只送了摘要」这次退化。
//
// 必须留痕：一个依赖脱敏结果做判定的 sidecar 收到摘要时，判定质量会悄悄下降；
// 不留痕就等于运维只能从「效果变差」反推配置问题。
func (in *Input) NoteSummaryOnlyFallback() { in.summaryOnly = true }

// CanReadBody 报告当前档位能否取正文。处理器可以先问再走快路径，
// 这样在 metadata-only 下连 Body() 的调用都不会发生。
func (in *Input) CanReadBody() bool { return in.access.CanReadBody() }

// CanReplaceBody 报告当前档位能否产出新正文。
func (in *Input) CanReplaceBody() bool { return in.access.CanReplaceBody() }

// Body 返回正文字节。metadata-only 档位下调用它一定失败 ——
// 这是 §2.9 三档的核心强制点：不是「请别读」，而是「读不到」。
//
// 被挡住时也要留痕（deniedReads）：处理器可能忽略这个错误继续走完，
// 那时审计里必须还能看出「有一个 metadata-only 的处理器试图读正文」。
func (in *Input) Body() ([]byte, error) {
	if !in.access.CanReadBody() {
		in.deniedReads++
		return nil, Errorf(ErrBodyAccessDenied, "%s 在 %s 档位声明为 %s，禁止读取正文",
			in.Spec.Name, in.Spec.Phase, in.access)
	}
	data, err := in.body.buffer(in.Spec.MaxInputBytes)
	if err != nil {
		return nil, err
	}
	in.read = true
	return data, nil
}

// StreamReader 返回正文字水流，供流式增量处理使用。同样先过档位检查。
func (in *Input) StreamReader() (io.Reader, error) {
	if !in.access.CanReadBody() {
		in.deniedReads++
		return nil, Errorf(ErrBodyAccessDenied, "%s 在 %s 档位声明为 %s，禁止读取正文",
			in.Spec.Name, in.Spec.Phase, in.access)
	}
	r, err := in.body.stream()
	if err != nil {
		return nil, err
	}
	in.read = true
	return r, nil
}

// Output 是处理器的产出。
type Output struct {
	// Body 非 nil 表示用这份字节替换当前正文；nil 表示正文不变。
	Body []byte
	// Rewrites 是改写元数据：只写类型与处数，绝不写原文（规则 6）。
	Rewrites []Rewrite
	// Attempts 是外部调用次数（sidecar 用），属于计数而非内容。
	Attempts int
	// Reason 是本次调用的结论码；留空按正常处理。
	Reason Reason
	// Metadata 是处理器想留在审计里的结构化摘要（可选，
	// 只允许类型/计数/长度这类不含内容的字段）。
	Metadata json.RawMessage
}

// Config 是处理器专有参数。
//
// 为什么不塞进 Spec：Spec 的字段表被手册 §2.6 冻结，扩充它属于破坏性变更（§9）。
// 更重要的是安全边界 —— HTTP 客户端、端点、规则表都在注册期绑定，
// 请求期下发的 Spec 只能按名字引用它们。
type Config struct {
	// Clock 用于测试期固定时间；nil 时用 time.Now。
	Clock func() time.Time

	// --- pii-mask ---
	// PseudonymKey 是假名化哈希的密钥。留空则每次请求随机 salt
	// （占位只在同一次请求内稳定，符合任务要求）。
	// **明确不允许**接 internal/secrets 的主密钥：主密钥同时用于凭证加解密，
	// 拿它的输出形态做公开可见的占位符，等于给密钥开了一个可观测的使用面，
	// 而且轮换主密钥会静默改变历史假名映射。要跨请求稳定，请显式注入专用派生子密钥。
	PseudonymKey []byte
	// PIITypes 限定脱敏的类型子集；留空 = 全部内置类型。
	PIITypes []string

	// --- field-replace ---
	Rules        []ReplaceRule
	MaxPathDepth int

	// --- json-schema ---
	Schema json.RawMessage

	// --- result-filter ---
	FilterRules       []FilterRule
	FilterMode        FilterMode
	FilterReplacement string
	MaxLineBytes      int

	// --- http-sidecar ---
	// HTTPClient 由接线方注入，且必须是走 internal/dialer 出网策略的那个客户端。
	// 本包绝不自己构造连接、也不提供默认值：缺了就拒绝注册。
	// 理由与 forwarder 的 dialContextFunc 相同 —— 目标白名单必须在传输层执行，
	// 否则一次 DNS 重绑定或一个 302 就把 Spec 里的 allowed_endpoints 变成装饰。
	HTTPClient *http.Client
	// Grants 是原文出网的管理员授权判定器，通常就是 *policy.Resolver（方法签名兼容）。
	// 声明了 allow_raw_body 却没注入它 → 构造期 ErrGrantCheckerBlank。
	Grants RawBodyGrantChecker
	// Endpoint 是实际调用地址，注册期绑定并与 AllowedEndpoints 交叉校验。
	Endpoint string
	Headers  map[string]string
	// MaxRetries 是**额外**尝试次数；0 表示不重试。上限 AbsoluteMaxRetries。
	MaxRetries int
	// Idempotent 声明该调用可安全重放。false 时**一次都不重试**：
	// 一个非幂等的 sidecar（比如已经落了一次判定结果）重试会产生重复副作用。
	Idempotent bool

	// --- kb-context-inject ---
	// KnowledgeContent 是正文获取的实现，由接线方注入且必须走受出网策略管的那条路。
	// 本包绝不自己连知识源：缺了就拒绝注册（理由同 HTTPClient ——
	// 目标白名单必须在传输层执行，否则一次重绑定就把 allowed_endpoints 变成装饰）。
	KnowledgeContent KnowledgeContentDeliverer
	// ContentGrants 是「文档正文能否进上下文」的管理员授权判定器（knowledge.content + read）。
	// 它与 Grants 是**两道独立**的门：前者管取回内容、后者管送出去检索词。
	// 缺一半的注册等于「声明说这条会取正文，运行时没人能回答管理员授没授权」，
	// 所以两者都在构造期校验（ErrGrantCheckerBlank）。
	ContentGrants KnowledgeContentGrantChecker
	// ContentMaxPassages / ContentMaxBytes 是这条声明愿意带进 prompt 的篇数与字节上限。
	// 越界或留空回落到保守缺省，不存在「不限」这种取值（见 content.go 的 clampContentInt）。
	ContentMaxPassages int
	ContentMaxBytes    int
}
