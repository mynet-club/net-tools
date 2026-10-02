package knowledge

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// Reason 是本包结论的稳定原因码（手册 §5：所有安全决策必须返回 reason code）。
//
// 它是**独立词表**，不直接复用 policy.Reason 的取值（identity 包同理）：
// policy 的原因码解释「这次使用为什么被允许/拒绝」，这里的原因码解释
// 「检索委托这一步发生了什么、哪一篇被兜底丢弃」。合成一张表会让审计查询
// 把「知识源超时」和「模型未授权」当成同一类事件统计，值班读错结论。
//
// 但对网关侧硬约束里的分级与范围，语义与策略内核同源，
// 因此下面用 PolicyMirror 显式登记映射：审计可以按策略语义聚合，
// 事实来源仍然分得清（A 判定 vs C 兜底）。
//
// 取值一旦发布就进审计表：只能追加，禁止重命名或用旧值表达新语义。
type Reason string

const (
	// 检索结果档位（AuditEvent.ResultCode 用）。
	ReasonOK               Reason = "retrieval_ok"
	ReasonNoHits           Reason = "retrieval_no_hits"
	ReasonNoKnowledgeAllow Reason = "no_knowledge_base_allowed"
	ReasonContextExpired   Reason = "request_context_expired"

	// 委托失败档位（一律 fail_closed：失败即「不可读」，绝不是「放行」）。
	ReasonTimeout                Reason = "retrieval_timeout"
	ReasonCancelled              Reason = "retrieval_cancelled"
	ReasonUpstreamStatus         Reason = "retrieval_upstream_status"
	ReasonResponseTooLarge       Reason = "retrieval_response_too_large"
	ReasonProtocolInvalid        Reason = "retrieval_protocol_invalid"
	ReasonTransportNotConfigured Reason = "retrieval_transport_not_configured"
	ReasonUnavailable            Reason = "retrieval_dependency_unavailable"

	// 兜底丢弃档位（Filter 逐篇给出的 reason code）。
	ReasonNotReadableAtSource Reason = "document_not_readable_at_source"
	ReasonEvidenceMissing     Reason = "document_acl_evidence_missing"
	ReasonKBNotAllowed        Reason = "knowledge_base_not_allowed"
	ReasonLevelExceeded       Reason = "knowledge_level_exceeded"
	ReasonLevelUnknown        Reason = "document_level_unknown"
	ReasonCrossOrg            Reason = "cross_organization_denied"
	ReasonSubjectMismatch     Reason = "document_subject_mismatch"
	ReasonACLExpired          Reason = "document_acl_expired"
	ReasonDuplicate           Reason = "document_duplicate"
	ReasonOverResultLimit     Reason = "document_over_result_limit"
	ReasonDigestInvalid       Reason = "document_digest_invalid"
	ReasonProtocolMissing     Reason = "document_protocol_field_missing"
)

// reasonRegistry 是注册表。未注册的原因码在构造审计时直接失败，
// 这样「临时编一个字符串塞进审计」会在测试里变成失败而不是静默通过。
var reasonRegistry = map[Reason]bool{}

func init() {
	for _, r := range []Reason{
		ReasonOK, ReasonNoHits, ReasonNoKnowledgeAllow, ReasonContextExpired,
		ReasonTimeout, ReasonCancelled, ReasonUpstreamStatus, ReasonResponseTooLarge,
		ReasonProtocolInvalid, ReasonTransportNotConfigured, ReasonUnavailable,
		ReasonNotReadableAtSource, ReasonEvidenceMissing, ReasonKBNotAllowed,
		ReasonLevelExceeded, ReasonLevelUnknown, ReasonCrossOrg, ReasonSubjectMismatch, ReasonACLExpired,
		ReasonDuplicate, ReasonOverResultLimit, ReasonDigestInvalid, ReasonProtocolMissing,
	} {
		reasonRegistry[r] = true
	}
}

// Valid 报告原因码是否注册过。
func (r Reason) Valid() bool { return reasonRegistry[r] }

func (r Reason) String() string { return string(r) }

// policyMirrors 登记「与策略内核语义同源」的兜底原因码。
//
// 只有这三条参与映射：其余都是委托协议自己的事实（超时、响应超限、判定依据缺失），
// 策略层根本不知道，硬映射等于给审计造假。
var policyMirrors = map[Reason]policy.Reason{
	ReasonLevelExceeded: policy.ReasonDataLevelDenied,
	ReasonCrossOrg:      policy.ReasonScopeMismatch,
	ReasonKBNotAllowed:  policy.ReasonScopeMismatch,
}

// PolicyMirror 返回对应的策略层原因码（无映射时返回空值）。
// 用途是把「网关兜底丢弃」在审计大盘上并回策略语义统计，不改变事实来源的区分。
func (r Reason) PolicyMirror() policy.Reason { return policyMirrors[r] }

// Reasons 去重并按稳定顺序排列，供审计与回放使用。
//
// 排序是必要的：丢弃记录来自切片遍历，未排序会让同一个输入在两次运行里
// 产生不同的审计 JSON，摘要对不上（手册 §2.8 同一口径）。
func Reasons(in []Reason) []Reason {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[Reason]bool, len(in))
	out := make([]Reason, 0, len(in))
	for _, r := range in {
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ValidateReasons 断言每个原因码都注册过。
func ValidateReasons(in []Reason) error {
	for i, r := range in {
		if !r.Valid() {
			return fmt.Errorf("knowledge: 第 %d 个原因码 %q 未注册", i, string(r))
		}
	}
	return nil
}

// reasonStyleOK 是原因码的字形检查：只许小写字母、数字与下划线，长度受限。
// 原因码会拼进日志键值对与查询串，任何空格或分隔符都会把一条结论截成两段。
func reasonStyleOK(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isLowerAlpha := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		if !isLowerAlpha && !isDigit && c != '_' {
			return false
		}
	}
	return true
}

// 稳定 ID 的长度上限。请求 ID 更短：它要进日志行、指标标签和上游关联头。
const (
	maxStableIDLen  = 256
	maxRequestIDLen = 128
)

// validateStableID 校验稳定 ID 字段（请求 ID、主体、知识库 ID、文档来源 ID）。
//
// 拒首尾空白：这些值进日志键值对和数据库主键，带空白的值在清洗后会撞成重复行；
// 拒控制字符：日志注入的最小防线；
// 拒冒号：范围在协议里写成 kind + id 两段（手册 §2.7），ID 自身含冒号会让它无法唯一还原。
func validateStableID(field, value string, maxLen int) error {
	if value == "" {
		return fmt.Errorf("knowledge: %s 不能为空", field)
	}
	if len(value) > maxLen {
		return fmt.Errorf("knowledge: %s 长度 %d 超过上限 %d", field, len(value), maxLen)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("knowledge: %s 首尾不能是空白字符", field)
	}
	if strings.ContainsAny(value, " \t\r\n:") {
		return fmt.Errorf("knowledge: %s 不能含空白或冒号: %q", field, value)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return fmt.Errorf("knowledge: %s 不能含控制字符", field)
		}
	}
	return nil
}

// validateSubjectID 在稳定 ID 之上再挡一层 PII 形态。
//
// 手册 §2.1 禁止邮箱当主键（那是 B 包的职责），但检索审计由本包直接写主体值，
// 所以这里也要拒绝：邮箱一旦进了审计，「被拒的理由」本身就成了个人信息落库。
func validateSubjectID(value string) error {
	if err := validateStableID("subject", value, maxStableIDLen); err != nil {
		return err
	}
	if strings.ContainsAny(value, "@+") {
		return fmt.Errorf("knowledge: subject %q 形如邮箱或手机号，不能进检索审计", value)
	}
	return nil
}

// containsControl 报告字符串里是否含控制字符（含 TAB/CR/LF/DEL 与 NUL）。
func containsControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// sortUniqueStrings 排序去重并返回副本。协议与审计里的 ID 列表一律走它，
// 保证同一个集合在任何进程里序列化出同一个 JSON。
func sortUniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	sort.Strings(out)
	j := 0
	for i := range out {
		if i == 0 || out[i] != out[i-1] {
			out[j] = out[i]
			j++
		}
	}
	return out[:j]
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
