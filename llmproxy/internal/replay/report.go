package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// Kind 是回放的记录类型。
type Kind string

const (
	KindDecision Kind = "decision"
	KindRouting  Kind = "routing"
)

// Valid 报告类型取值。
func (k Kind) Valid() bool { return k == KindDecision || k == KindRouting }

// Status 是一条回放的结论状态。
//
// 这里刻意把「不通过」拆成两种：
//   - Mismatch：记录能回放，但当前策略集给出的结论和记录不一样（策略变了、
//     规则过期了、候选池变了）——这是 §3.0 影响面报告要看的东西；
//   - Rejected：记录根本无法被可信地回放（缺时钟、缺 seed、策略包不覆盖该范围、
//     结构自相矛盾）。跨组织喂错包必须落在这里，而不是被 Evaluate 静默算成一条 deny
//     ——「没有授权」和「没有资格参与这次判定」是完全不同的运维结论。
type Status string

const (
	StatusPassed   Status = "passed"
	StatusMismatch Status = "mismatch"
	StatusRejected Status = "rejected"
)

// FieldDiff 是一处结构化差异：哪个字段、期望（记录里的值）、实际（回放算出的值）。
//
// 只返回 bool 的回放在排障时毫无价值：影子运行对不上时，运维必须一眼看出
// 是策略版本变了还是某条规则的 TTL 到期了。
type FieldDiff struct {
	Field    string `json:"field"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
}

// Outcome 是一条记录的回放结果。
type Outcome struct {
	Kind      Kind          `json:"kind"`
	RequestID string        `json:"request_id"`
	Status    Status        `json:"status"`
	Reason    policy.Reason `json:"reason,omitempty"`
	Diffs     []FieldDiff   `json:"diffs,omitempty"`
	Notes     []string      `json:"notes,omitempty"`
}

// Passed 报告这条记录是否逐字段复现了。
func (o Outcome) Passed() bool { return o.Status == StatusPassed }

// normalize 把差异与备注按字段名稳定排序去重：同一批记录乱序输入也必须产出同样的输出。
func (o *Outcome) normalize() {
	sort.SliceStable(o.Diffs, func(i, j int) bool {
		if o.Diffs[i].Field != o.Diffs[j].Field {
			return o.Diffs[i].Field < o.Diffs[j].Field
		}
		if o.Diffs[i].Expected != o.Diffs[j].Expected {
			return o.Diffs[i].Expected < o.Diffs[j].Expected
		}
		return o.Diffs[i].Actual < o.Diffs[j].Actual
	})
	seen := make(map[string]bool, len(o.Diffs))
	deduped := o.Diffs[:0]
	for _, d := range o.Diffs {
		key := d.Field + "\x00" + d.Expected + "\x00" + d.Actual
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, d)
	}
	o.Diffs = deduped

	sort.Strings(o.Notes)
	seenNote := make(map[string]bool, len(o.Notes))
	notes := o.Notes[:0]
	for _, n := range o.Notes {
		if n == "" || seenNote[n] {
			continue
		}
		seenNote[n] = true
		notes = append(notes, n)
	}
	o.Notes = notes
}

func (o Outcome) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s/%s %s", o.Kind, o.RequestID, o.Status)
	if o.Reason != "" {
		fmt.Fprintf(&b, " reason=%s", string(o.Reason))
	}
	for _, d := range o.Diffs {
		fmt.Fprintf(&b, "\n    - %s: 记录=%s 回放=%s", d.Field, d.Expected, d.Actual)
	}
	for _, n := range o.Notes {
		fmt.Fprintf(&b, "\n    · %s", n)
	}
	return b.String()
}

// Report 是一次回放的完整结果。
type Report struct {
	Clock time.Time `json:"clock"`

	// LoadedPolicyVersion 是本次回放喂进来的**整集**版本串（BundleSet.PolicyVersion）。
	// 逐条记录比对的是按范围过滤后的子集版本，两者都留在报告里，
	// 才能区分「喂错策略集」和「该范围的策略变了」。
	LoadedPolicyVersion string    `json:"loaded_policy_version"`
	Outcomes            []Outcome `json:"outcomes"`
}

// Counts 给出各状态条数。
func (r Report) Counts() (passed, mismatch, rejected int) {
	for _, o := range r.Outcomes {
		switch o.Status {
		case StatusPassed:
			passed++
		case StatusMismatch:
			mismatch++
		case StatusRejected:
			rejected++
		}
	}
	return passed, mismatch, rejected
}

// Clean 报告是否全部逐字段复现。任何 Mismatch / Rejected 都算不干净（fail-closed）。
func (r Report) Clean() bool {
	for _, o := range r.Outcomes {
		if o.Status != StatusPassed {
			return false
		}
	}
	return true
}

// Empty 报告报告里没有任何结果（例如喂了空记录集）。
// 空结果不能被视为「回放通过」——那会让门禁在记录没落库时静默变绿。
func (r Report) Empty() bool { return len(r.Outcomes) == 0 }

// Failures 返回所有未通过的条目，供脚本逐条打印。
func (r Report) Failures() []Outcome {
	out := make([]Outcome, 0, len(r.Outcomes))
	for _, o := range r.Outcomes {
		if o.Status != StatusPassed {
			out = append(out, o)
		}
	}
	return out
}

// Digest 是报告的规范摘要：固定输入必须得到固定摘要（§6「固定输入得到固定输出」）。
// 有了它，CI 可以把一次回放的结论钉成一个哈希，任何策略/候选变动都会改变它。
func (r Report) Digest() (string, error) {
	type wire struct {
		Clock               string    `json:"clock"`
		LoadedPolicyVersion string    `json:"loaded_policy_version"`
		Outcomes            []Outcome `json:"outcomes"`
	}
	clone := Report{Clock: r.Clock, LoadedPolicyVersion: r.LoadedPolicyVersion, Outcomes: sortedOutcomes(r.Outcomes)}
	data, err := json.Marshal(wire{
		Clock:               nowUTC(clone.Clock).Format(time.RFC3339),
		LoadedPolicyVersion: clone.LoadedPolicyVersion,
		Outcomes:            clone.Outcomes,
	})
	if err != nil {
		return "", fmt.Errorf("replay: 报告序列化失败: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Summary 给人看的统计行。
func (r Report) Summary() string {
	passed, mismatch, rejected := r.Counts()
	return fmt.Sprintf("时钟 %s｜记录 %d 条：通过 %d，差异 %d，拒绝回放 %d",
		nowUTC(r.Clock).Format(time.RFC3339), len(r.Outcomes), passed, mismatch, rejected)
}

// String 给出可直接打进 CI 日志的多行输出（按稳定顺序）。
func (r Report) String() string {
	var b strings.Builder
	b.WriteString(r.Summary())
	for _, o := range sortedOutcomes(r.Outcomes) {
		b.WriteString("\n")
		b.WriteString(o.String())
	}
	return b.String()
}

// sortedOutcomes 按 (kind, request_id) 稳定排序，与输入顺序无关。
func sortedOutcomes(in []Outcome) []Outcome {
	out := append([]Outcome(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].RequestID < out[j].RequestID
	})
	return out
}
