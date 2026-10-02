package policy

import (
	"errors"
	"fmt"
	"strings"
)

// DataLevel 是数据分级（§2.3）。
//
// 顺序由整数常量定义，比较一律走 AtLeast/Exceeds，**禁止用字符串字典序**：
// 字典序下 confidential < internal < public < restricted，用它判定会把
// restricted 判成比 confidential 宽松，属于直接越权。
//
// 四级取值固定，新增等级或调整排序是破坏性变更，必须升级策略版本并走主线评审。
type DataLevel int

const (
	// LevelUnknown 是零值，表示「没判定」。它故意不是 public：
	// 漏配分级检测时必须显式处理，不能静默按最宽松的一档放行。
	LevelUnknown DataLevel = iota
	LevelPublic
	LevelInternal
	LevelConfidential
	LevelRestricted
)

// dataLevelNames 的顺序必须与上面的常量一致。
var dataLevelNames = []string{"public", "internal", "confidential", "restricted"}

// ErrDataLevel 表示等级字符串或取值不在固定四级内。
var ErrDataLevel = errors.New("policy: 未知的数据分级")

// ParseDataLevel 解析等级名（大小写不敏感，允许首尾空白）。
func ParseDataLevel(s string) (DataLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "public":
		return LevelPublic, nil
	case "internal":
		return LevelInternal, nil
	case "confidential":
		return LevelConfidential, nil
	case "restricted":
		return LevelRestricted, nil
	}
	return LevelUnknown, fmt.Errorf("%w: %q（可用值：public、internal、confidential、restricted）", ErrDataLevel, s)
}

func (l DataLevel) Valid() bool { return l >= LevelPublic && l <= LevelRestricted }

func (l DataLevel) String() string {
	if !l.Valid() {
		return "unknown"
	}
	return dataLevelNames[int(l)-1]
}

// Rank 返回 1..4 的序数，供序列化和审计记录使用。
func (l DataLevel) Rank() int { return int(l) }

// AtLeast 报告 l 是否不低于 other（含相等）。任一级为 Unknown 时返回 false，
// 让调用方走错误分支而不是当作「满足」。
func (l DataLevel) AtLeast(other DataLevel) bool {
	if !l.Valid() || !other.Valid() {
		return false
	}
	return l >= other
}

// Exceeds 报告 l 是否严格高于 other。
func (l DataLevel) Exceeds(other DataLevel) bool {
	if !l.Valid() || !other.Valid() {
		return false
	}
	return l > other
}

// EffectiveLevel 实现 §2.3 的组合规则：
//
//	effective = max(user_level, detected_level, knowledge_level)
//
// 三个入参都必须显式给定。没有正文检测器时传 LevelPublic，而不是留零值 ——
// 零值在这里是错误，不是「宽松」，这样漏接检测器会立刻暴露出来。
func EffectiveLevel(user, detected, knowledge DataLevel) (DataLevel, error) {
	for name, l := range map[string]DataLevel{
		"user_level":      user,
		"detected_level":  detected,
		"knowledge_level": knowledge,
	} {
		if !l.Valid() {
			return LevelUnknown, fmt.Errorf("%w: %s 未指定", ErrDataLevel, name)
		}
	}
	out := user
	for _, l := range []DataLevel{detected, knowledge} {
		if l > out {
			out = l
		}
	}
	return out, nil
}

// Levels 返回固定四级，按从严到宽排列，供配置校验和界面下拉使用。
func Levels() []DataLevel {
	return []DataLevel{LevelRestricted, LevelConfidential, LevelInternal, LevelPublic}
}
