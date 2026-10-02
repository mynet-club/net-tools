package processor

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 处理器类型（内置四种 + HTTP sidecar）。
//
// 这个集合**不封闭**：注册表允许通过 RegisterType 追加自定义类型（主线/后续工作包），
// 封闭的是阶段集合（见 Phase）—— 阶段是 Pipeline 的执行次序，扩充它等于改运行时语义。
const (
	TypePIIMask      = "pii-mask"      // 脱敏：transform-body
	TypeFieldReplace = "field-replace" // 字段替换：transform-body
	TypeJSONSchema   = "json-schema"   // Schema 校验：metadata-only 或 inspect-body
	TypeResultFilter = "result-filter" // 结果过滤：after-upstream
	TypeSidecar      = "http-sidecar"  // 外部 HTTP sidecar
)

// Phase 是处理器运行的阶段（§2.6 的固定五个值）。
//
// 封闭集合 + 解析函数：未知阶段直接报错而不是回落到某个默认阶段。
// 回落会让「写错一个字母」变成「在错误的阶段跑了正确的处理器」——
// 比如 before-upstream 误写成 before-upstram 时若回落到 audit，脱敏就变成了事后记录。
type Phase string

const (
	PhaseBeforeClassify Phase = "before-classify"
	PhaseBeforeRoute    Phase = "before-route"
	PhaseBeforeUpstream Phase = "before-upstream"
	PhaseAfterUpstream  Phase = "after-upstream"
	PhaseAudit          Phase = "audit"
)

// phaseOrder 是请求侧 → 响应侧 → 审计的固定执行次序，也是 Phases() 的返回顺序。
var phaseOrder = []Phase{PhaseBeforeClassify, PhaseBeforeRoute, PhaseBeforeUpstream, PhaseAfterUpstream, PhaseAudit}

// ParsePhase 解析阶段。空串报错：阶段必须显式声明，
// 与 policy.ParseBodyAccess 把空串落到最严档不同 —— 档位有安全默认值，阶段没有。
func ParsePhase(s string) (Phase, error) {
	p := Phase(strings.TrimSpace(s))
	if !p.Valid() {
		return "", fmt.Errorf("%w: %q（可用值：%s）", ErrPhase, s, strings.Join(phaseStrings(), "、"))
	}
	return p, nil
}

func (p Phase) Valid() bool {
	for _, item := range phaseOrder {
		if item == p {
			return true
		}
	}
	return false
}

func (p Phase) String() string { return string(p) }

// IsRequestPhase 报告该阶段是否作用于请求正文（在离开网关之前）。
func (p Phase) IsRequestPhase() bool {
	return p == PhaseBeforeClassify || p == PhaseBeforeRoute || p == PhaseBeforeUpstream
}

// Phases 返回固定五个阶段，按执行次序排列。
func Phases() []Phase {
	out := make([]Phase, len(phaseOrder))
	copy(out, phaseOrder)
	return out
}

// phaseRank 返回阶段在固定执行次序（§2.6）中的位置；未知阶段排在最后。
// 只用于 Registry.Build 装配时的稳定排序，不参与任何判定。
func phaseRank(p Phase) int {
	for i, item := range phaseOrder {
		if item == p {
			return i
		}
	}
	return len(phaseOrder)
}

func phaseStrings() []string {
	out := make([]string, 0, len(phaseOrder))
	for _, p := range phaseOrder {
		out = append(out, string(p))
	}
	return out
}

// 资源上限。这些是**绝对**上限，写配置时越不过去：
// 一个把 MaxInputBytes 误写成 0 或 1<<60 的 Spec，如果按「0 = 不限」解释，
// 就等于允许把任意大的正文缓存在内存里 —— 现网 forwarder 对非流式响应
// 已经吃过这个教训（见 internal/server/forwarder.go 的 maxUpstreamResponseBytes）。
const (
	AbsoluteMaxInputBytes  int64 = 32 << 20
	AbsoluteMaxOutputBytes int64 = 32 << 20
	MaxTimeout                   = 2 * time.Minute
	MaxNameLen                   = 128
	MaxVersionLen                = 64
	MaxAllowedEndpoints          = 32

	DefaultMaxPathDepth  = 8
	AbsoluteMaxPathDepth = 16
	MaxDocDepth          = 64

	MaxReplaceRules        = 64
	MaxMappingPerRule      = 64
	MaxPatternLen          = 1024
	MaxKeywordCount        = 128
	MaxKeywordLen          = 256
	DefaultMaxLineBytes    = 64 << 10
	AbsoluteMaxLineBytes   = 1 << 20
	AbsoluteMaxRetries     = 5
	DefaultSidecarMaxRetry = 2
	MaxPIISpans            = 200000
)

// Spec 是一个处理器的完整声明（§2.6）。
//
// 结构体归 E 包所有：A 包只冻结了 BodyAccess 的三档词汇，手册把 ProcessorSpec 放在
// §2.6 而没有放进 internal/policy，所以这里按手册的字段表逐条实现，两处按任务要求收紧：
//   - BodyAccess 用 policy.BodyAccess 而不是裸 string —— 档位词表由 A 唯一持有，
//     这里复制一份字符串集合就会出现「E 认得但 A 不认」的第四档；
//   - Phase 用封闭枚举而不是裸 string，理由见 ParsePhase。
//
// 字段**不扩充**：处理器专有参数（规则表、schema、sidecar 客户端等）走 Config，
// 由注册表在 Register 时绑定。这样装配时拿到的是策略里的 Spec（数据），
// 运行参数却来自受控的注册项 —— 写策略的人没法靠改 JSON 注入一个出网地址。
type Spec struct {
	Name             string            `json:"name"`
	Type             string            `json:"type"`
	Phase            Phase             `json:"phase"`
	Scope            string            `json:"scope,omitempty"`
	Timeout          time.Duration     `json:"timeout_ns,omitempty"`
	MaxInputBytes    int64             `json:"max_input_bytes"`
	MaxOutputBytes   int64             `json:"max_output_bytes"`
	FailClosed       bool              `json:"fail_closed"`
	BodyAccess       policy.BodyAccess `json:"body_access"`
	AllowRawBody     bool              `json:"allow_raw_body,omitempty"`
	AllowedEndpoints []string          `json:"allowed_endpoints,omitempty"`
	Version          string            `json:"version"`
}

// ProcessorSpec 是手册 §2.6 的名字别名，只为文档对齐，不另立一套字段。
type ProcessorSpec = Spec

// 类型一致性相关的哨兵。都包着 ErrSpec，所以 errors.Is(err, ErrSpec) 仍然成立，
// 同时调用点可以按具体子因分支（装配错误要把「阶段写错」和「档位写错」区分开报给运营）。
var (
	ErrVersionMissing       = fmt.Errorf("%w: version 缺失", ErrSpec)
	ErrEndpointInvalid      = fmt.Errorf("%w: 端点声明不合法", ErrSpec)
	ErrPhaseNotForType      = fmt.Errorf("%w: 阶段与处理器类型不符", ErrSpec)
	ErrBodyAccessNotForType = fmt.Errorf("%w: 正文档位与处理器类型不符", ErrSpec)
)

// Validate 校验 Spec 的必填项与跨字段一致性。
//
// 校验放在注册/装配期而不是请求期：一条自相矛盾的 Spec 如果等到请求期才发现，
// 表现是「策略下发了但处理器静默不生效」，现场排查成本极高（同 A 包 entitlement 的理由）。
func (s Spec) Validate() error {
	if !safeIdentifier(s.Name) {
		return Errorf(ErrSpec, "name %q 不合法（只允许字母数字与 -_.:/，长度 ≤ %d）", s.Name, MaxNameLen)
	}
	if strings.TrimSpace(s.Type) == "" || len(s.Type) > MaxNameLen {
		return Errorf(ErrSpec, "%s: type %q 不合法", s.Name, s.Type)
	}
	if !s.Phase.Valid() {
		return Errorf(ErrPhase, "%s: 未知阶段 %q（可用值：%s）", s.Name, string(s.Phase), strings.Join(phaseStrings(), "、"))
	}
	if s.Version == "" {
		return ErrVersionMissing
	}
	if len(s.Version) > MaxVersionLen {
		return Errorf(ErrSpec, "%s: version 长度 %d 超过上限 %d", s.Name, len(s.Version), MaxVersionLen)
	}
	if s.Timeout <= 0 {
		return Errorf(ErrSpec, "%s: timeout 必须为正（禁止 0 = 不限）", s.Name)
	}
	if s.Timeout > MaxTimeout {
		return Errorf(ErrSpec, "%s: timeout %s 超过绝对上限 %s", s.Name, s.Timeout, MaxTimeout)
	}
	if s.MaxInputBytes <= 0 || s.MaxInputBytes > AbsoluteMaxInputBytes {
		return Errorf(ErrSpec, "%s: max_input_bytes %d 必须落在 (0, %d]", s.Name, s.MaxInputBytes, AbsoluteMaxInputBytes)
	}
	if s.MaxOutputBytes <= 0 || s.MaxOutputBytes > AbsoluteMaxOutputBytes {
		return Errorf(ErrSpec, "%s: max_output_bytes %d 必须落在 (0, %d]", s.Name, s.MaxOutputBytes, AbsoluteMaxOutputBytes)
	}
	if s.MaxOutputBytes < s.MaxInputBytes/4 {
		// 脱敏后的正文通常比原文略长（占位符比手机号长）。输出上限设得比输入小太多，
		// 结果是每个正常请求都撞 output_too_large —— 这是配错，不是策略，装配期就拦住。
		return Errorf(ErrSpec, "%s: max_output_bytes %d 相对 max_input_bytes %d 过小", s.Name, s.MaxOutputBytes, s.MaxInputBytes)
	}
	if !s.BodyAccess.Valid() {
		return Errorf(policy.ErrBodyAccess, "%s: 未知的正文访问档位 %q", s.Name, string(s.BodyAccess))
	}
	if s.Scope != "" {
		if _, err := policy.ParseScopeSelector(s.Scope); err != nil {
			return Errorf(ErrSpec, "%s: scope %q 不合法（写成 * 或 kind:id）", s.Name, s.Scope)
		}
	}
	if len(s.AllowedEndpoints) > MaxAllowedEndpoints {
		return Errorf(ErrSpec, "%s: allowed_endpoints %d 条超过上限 %d", s.Name, len(s.AllowedEndpoints), MaxAllowedEndpoints)
	}
	for _, ep := range s.AllowedEndpoints {
		if _, err := canonicalEndpoint(ep); err != nil {
			return err
		}
	}
	if s.AllowRawBody {
		// 原文出网只在「真的会把字节发出去」时才有意义，而且必须有一组白名单可审。
		if len(s.AllowedEndpoints) == 0 {
			return Errorf(ErrSpec, "%s: allow_raw_body 必须同时给出 allowed_endpoints，否则无法审出原文会流向哪里", s.Name)
		}
		if s.BodyAccess == policy.BodyMetadataOnly {
			return Errorf(ErrSpec, "%s: metadata-only 档位下没有原文可给，allow_raw_body 是自相矛盾的声明", s.Name)
		}
	}
	if err := s.validateType(); err != nil {
		return err
	}
	return nil
}

// validateType 给内置类型加上档位与阶段的一致性约束。自定义类型只受通用规则约束。
func (s Spec) validateType() error {
	switch s.Type {
	case TypePIIMask, TypeFieldReplace:
		// 脱敏与字段替换的产出是新正文，档位必须是 transform-body。
		// 允许它跑在 inspect-body 上会让「配了脱敏但看不到效果」变成静默放行原文。
		if !s.BodyAccess.CanReplaceBody() {
			return Errorf(ErrBodyAccessNotForType, "%s: %s 必须是 transform-body，当前 %s", s.Name, s.Type, s.BodyAccess)
		}
		if !s.Phase.IsRequestPhase() {
			return Errorf(ErrPhaseNotForType, "%s: %s 只能跑在请求侧阶段，当前 %s", s.Name, s.Type, s.Phase)
		}
	case TypeJSONSchema:
		// 校验器不产出新正文：给它 transform-body 等于允许「校验失败就顺手改写正文」，
		// 那是把判定与改写两件事混进一个处理器（§2.9 规则 1 的分工）。
		if s.BodyAccess.CanReplaceBody() {
			return Errorf(ErrBodyAccessNotForType, "%s: %s 是判定型处理器，档位不得高于 %s", s.Name, s.Type, policy.BodyInspect)
		}
		if !s.Phase.IsRequestPhase() {
			return Errorf(ErrPhaseNotForType, "%s: %s 只能跑在请求侧阶段，当前 %s", s.Name, s.Type, s.Phase)
		}
	case TypeResultFilter:
		// 过滤的是上游响应，只有 after-upstream 才有意义。
		if s.Phase != PhaseAfterUpstream {
			return Errorf(ErrPhaseNotForType, "%s: %s 只能跑在 after-upstream，当前 %s", s.Name, s.Type, s.Phase)
		}
		if !s.BodyAccess.CanReadBody() {
			return Errorf(ErrBodyAccessNotForType, "%s: %s 至少需要 inspect-body 才能看到响应内容，当前 %s",
				s.Name, s.Type, s.BodyAccess)
		}
	case TypeSidecar:
		// sidecar 是一次同步网络往返，只放在请求侧：
		// after-upstream 上它会把每条流式分块变成一次外部调用（延迟与故障面都不可控），
		// audit 阶段则根本没有正文可送（审计输入按结构就不带 Body）。
		if !s.Phase.IsRequestPhase() {
			return Errorf(ErrPhaseNotForType, "%s: %s 只能跑在请求侧阶段，当前 %s", s.Name, s.Type, s.Phase)
		}
		if len(s.AllowedEndpoints) == 0 {
			return Errorf(ErrSpec,
				"%s: %s 必须给出 allowed_endpoints —— 出网目标必须可枚举、可审，注册期注入的 endpoint 不能是唯一凭据",
				s.Name, s.Type)
		}
	}
	return nil
}

// canonicalEndpoint 把白名单条目和目标地址归一化成可比较的形式（scheme://host:port/path）。
//
// 不做归一化就会留下经典绕过：白名单写 `sidecar.example.com`，请求用
// `https://sidecar.example.com:443@evil.test/` 或大小写/默认端口差异绕过。
// 这里拒绝 userinfo、通配与非 http(s) 方案，宁可让配置报错。
func canonicalEndpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", Errorf(ErrEndpointInvalid, "端点不能为空")
	}
	if strings.ContainsAny(raw, "*?") {
		return "", Errorf(ErrEndpointInvalid, "端点 %q 不能含通配（白名单必须可枚举）", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", Errorf(ErrEndpointInvalid, "端点 %q 解析失败: %v", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", Errorf(ErrEndpointInvalid, "端点 %q 必须是 http/https 绝对地址", raw)
	}
	if u.User != nil {
		return "", Errorf(ErrEndpointInvalid, "端点 %q 不能带 userinfo", raw)
	}
	if u.Host == "" {
		return "", Errorf(ErrEndpointInvalid, "端点 %q 缺少主机名", raw)
	}
	if strings.ContainsRune(u.Host, '%') || strings.ContainsAny(u.Host, "@ \t") {
		return "", Errorf(ErrEndpointInvalid, "端点 %q 的主机部分不合法", raw)
	}
	host := strings.ToLower(u.Host)
	// 补齐默认端口：否则白名单里的 :443 挡不住不带端点的同一个目标。
	if u.Port() == "" {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	path := u.EscapedPath()
	if path == "" || path == "/" {
		path = "/"
	}
	if strings.Contains(path, "..") {
		return "", Errorf(ErrEndpointInvalid, "端点 %q 不能含 .. 路径段", raw)
	}
	return u.Scheme + "://" + host + path, nil
}

// endpointAllowed 报告目标是否命中白名单（按条目声明的路径前缀匹配）。
func endpointAllowed(target string, list []string) bool {
	for _, item := range list {
		canon, err := canonicalEndpoint(item)
		if err != nil {
			continue // 已在 Validate 期拒绝，这里再防一次：脏条目按不匹配处理
		}
		if sameOriginPrefix(target, canon) {
			return true
		}
	}
	return false
}

// sameOriginPrefix 要求协议+主机端口完全一致，且路径在白名单声明的目录下。
func sameOriginPrefix(target, allowed string) bool {
	if target == allowed {
		return true
	}
	if !strings.HasPrefix(target, allowed) {
		return false
	}
	// 前缀匹配必须落在路径边界上，否则 /svc 会放过 /svc-secret。
	rest := target[len(allowed):]
	if strings.HasSuffix(allowed, "/") {
		return true
	}
	return strings.HasPrefix(rest, "/")
}
