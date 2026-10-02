package processor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// Rewrite 是一条改写元数据：改了什么类别、几处。
//
// 只有类别与计数。§2.9 规则 6 规定处理器输出与日志不得包含原文，
// 「脱敏了 3 处手机号」是合规信息，「脱敏了 138… 」就是泄漏。
type Rewrite struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// AuditEntry 是一个处理器一次调用的审计条目。
//
// 允许出现的内容被 §2.9 规则 6 限定为：request ID、类型、范围、哈希、策略版本。
// 这里在此之外只放**不含内容的量**（字节数、耗时、尝试次数、档位）与**封闭枚举**
// （原因码），并且刻意不放：
//   - sidecar 的目标 URL：出网地址不在规则 6 的允许清单里，且它本身是可定位信息；
//   - 处理器名以外的任何用户输入；
//   - 任何金额、token 计量字段（§2.6：处理器不得修改费用/计量/审计结论，
//     连读都不该读 —— 字段不存在比「存在但不用」更难被误用，leak 测试会断言这点）。
type AuditEntry struct {
	Processor string            `json:"processor"`
	Type      string            `json:"type"`
	Version   string            `json:"version"`
	Phase     Phase             `json:"phase"`
	Scope     string            `json:"scope,omitempty"`
	Access    policy.BodyAccess `json:"access"`
	Outcome   Reason            `json:"outcome"`
	Reasons   []Reason          `json:"reasons,omitempty"`
	// GrantReason 是策略侧的原文出网原因码，直接透传 policy.Reason（可为空）。
	GrantReason policy.Reason `json:"grant_reason,omitempty"`
	// DeniedReads 是本处理器被档位挡住的取正文次数。
	// 留这个数字而不是只留错误码：处理器可能吞掉那个错误继续走完，
	// 那时审计里仍要能看出「metadata-only 的处理器试过读正文」。
	DeniedReads int `json:"denied_reads,omitempty"`
	// SummaryOnly 表示外部调用本该带正文、实际只带了摘要（原文未授权时的退化）。
	SummaryOnly   bool          `json:"summary_only,omitempty"`
	InputBytes    int64         `json:"input_bytes"`
	OutputBytes   int64         `json:"output_bytes"`
	InputHash     string        `json:"input_hash,omitempty"`
	OutputHash    string        `json:"output_hash,omitempty"`
	Elapsed       time.Duration `json:"elapsed_ns"`
	Buffered      bool          `json:"buffered"`
	ReleaseOrigin bool          `json:"released_original"`
	Attempts      int           `json:"attempts,omitempty"`
	Rewrites      []Rewrite     `json:"rewrites,omitempty"`
}

// AuditRecord 是一次 Pipeline 调用的审计视图（可序列化、可回放）。
type AuditRecord struct {
	RequestID     string        `json:"request_id"`
	PolicyVersion string        `json:"policy_version,omitempty"`
	Phase         Phase         `json:"phase,omitempty"`
	Buffered      bool          `json:"buffered"`
	Untouched     bool          `json:"input_untouched"`
	Elapsed       time.Duration `json:"elapsed_ns"`
	Entries       []AuditEntry  `json:"entries,omitempty"`
	Versions      []NameVersion `json:"processor_versions,omitempty"`
}

// NameVersion 是「哪个版本的处理器参与了这次处理」，供版本变更回归使用。
type NameVersion struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Version string `json:"version"`
}

// newEntry 从 Spec 起一条审计条目：名字/类型/版本/阶段/范围/档位来自声明，
// 其余字段随处理过程填充。
func newEntry(spec Spec) AuditEntry {
	return AuditEntry{
		Processor: spec.Name,
		Type:      spec.Type,
		Version:   spec.Version,
		Phase:     spec.Phase,
		Scope:     spec.Scope,
		Access:    spec.BodyAccess,
		Outcome:   ReasonOK,
	}
}

// versionsOf 按声明顺序给出参与处理器的版本清单（不排序，保持执行次序）。
func versionsOf(specs []Spec) []NameVersion {
	if len(specs) == 0 {
		return nil
	}
	out := make([]NameVersion, 0, len(specs))
	for _, s := range specs {
		out = append(out, NameVersion{Name: s.Name, Type: s.Type, Version: s.Version})
	}
	return out
}

// sha256Hex 返回数据的 sha256 摘要（带算法前缀，便于以后换摘要函数时审计可自解释）。
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// mergeRewrites 合并多个处理器产出的改写元数据。
//
// 先按键排序再合并，结果与 map 遍历顺序无关（与 A 包 conditionsMet 的取舍同理）：
// 同一份输入两次跑必须产出逐字节相同的审计，否则回放对不上。
func mergeRewrites(in []Rewrite) []Rewrite {
	if len(in) == 0 {
		return nil
	}
	sums := make(map[string]int, len(in))
	for _, r := range in {
		if !safeIdentifier(r.Kind) {
			continue // 类别名必须是安全标识符，脏值不进审计
		}
		sums[r.Kind] += r.Count
	}
	keys := make([]string, 0, len(sums))
	for k := range sums {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Rewrite, 0, len(keys))
	for _, k := range keys {
		out = append(out, Rewrite{Kind: k, Count: sums[k]})
	}
	return out
}

// auditJSON 序列化审计记录。失败时返回一个只含原因码的最小记录 ——
// 审计输出绝不能因为序列化错误而把内容带出来。
func auditJSON(rec AuditRecord) string {
	data, err := json.Marshal(rec)
	if err != nil {
		return `{"outcome":"` + string(ReasonFailed) + `"}`
	}
	return string(data)
}

// piiKindPrefix 是脱敏改写元数据的键前缀，审计里读作 pii:phone。
const piiKindPrefix = "pii:"

// kindFor 拼出改写类别名，并保证它是安全标识符。
func kindFor(prefix, name string) string {
	kind := prefix + sanitizeShortCode(name)
	if !safeIdentifier(kind) {
		return prefix + "other"
	}
	return kind
}

// splitKind 拆类别名成（前缀, 名称），只用于测试与展示。
func splitKind(kind string) (string, string) {
	if i := strings.LastIndexByte(kind, ':'); i >= 0 {
		return kind[:i+1], kind[i+1:]
	}
	return kind, ""
}
