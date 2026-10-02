package identity

import (
	"errors"
	"strings"
)

// 本包的错误语义：每个哨兵错误都对应一个稳定原因码（见 ReasonFor）。
//
// 错误文案里**不允许**出现 token 原文、公钥/私钥材料、claims 里的邮箱手机号等个人信息。
// 需要关联具体请求时带上调用方注入的 RequestID，或本包算出的单向摘要 SubjectRef。
var (
	ErrCredential           = errors.New("identity: 凭证不合法")
	ErrCredentialKind       = errors.New("identity: 不支持的凭证类型")
	ErrCredentialTooLarge   = errors.New("identity: 凭证超过大小上限")
	ErrTokenMalformed       = errors.New("identity: token 不是合法的 compact JWS")
	ErrSignature            = errors.New("identity: 签名校验失败")
	ErrAlgorithmDenied      = errors.New("identity: 签名算法不在允许集合内")
	ErrTokenTypeDenied      = errors.New("identity: typ 不在允许集合内")
	ErrCriticalDenied       = errors.New("identity: JWS 含未支持的 crit 头")
	ErrKeyNotFound          = errors.New("identity: 没有匹配 kid 的验签公钥")
	ErrKeySourceUnavailable = errors.New("identity: 公钥来源不可用")
	ErrKeyMaterial          = errors.New("identity: 公钥材料不合法")
	ErrClaimsInvalid        = errors.New("identity: claims 解析失败")
	ErrIssuerMismatch       = errors.New("identity: iss 与配置不符")
	ErrAudienceMismatch     = errors.New("identity: aud 与配置不符")
	ErrExpired              = errors.New("identity: token 已过期")
	ErrExpiryMissing        = errors.New("identity: token 缺少 exp")
	ErrNotYetValid          = errors.New("identity: nbf 尚未到达")
	ErrIssuedInFuture       = errors.New("identity: iat 晚于当前时间")
	ErrLifetimeTooLong      = errors.New("identity: token 生命周期超过上限")
	ErrSubjectMissing       = errors.New("identity: claims 里没有可用的 subject")
	ErrSubjectUnstable      = errors.New("identity: subject 不能作为稳定关联键")
	ErrClaimShape           = errors.New("identity: claim 结构与映射表不符")
	ErrClaimOverflow        = errors.New("identity: claim 取值数量超过上限")
	ErrScopeUnmapped        = errors.New("identity: claim 值无法换成稳定的范围 ID")
	ErrMembershipTTL        = errors.New("identity: 成员关系缺少过期时间")
	// ErrFixtureNotFound 只属于 FakeProvider：请求了一个没预置的 fixture 名。
	// 与 ErrSubjectMissing 分开是必须的 —— 影子运行的失败统计如果看到 subject_missing
	// 会去查 IdP 有没有给 sub claim，而真正该做的是补 fixture。
	ErrFixtureNotFound = errors.New("identity: 没有这个名字的 claims fixture")
	ErrConfig          = errors.New("identity: 身份来源配置不合法")
	ErrNotImplemented  = errors.New("identity: 该身份来源尚未实现")
	ErrInternal        = errors.New("identity: 内部错误")
)

// ReasonCode 是身份解析结论的稳定原因码（手册 §5：所有安全决策必须返回 reason code）。
//
// 与 policy.Reason 是两个独立词表：policy 的原因码解释「为什么允许/拒绝这次使用」，
// 这里的原因码解释「身份这一步发生了什么」。混用会让审计查询把「token 过期」和
// 「模型未授权」当成同一类事件统计，值班时会读错结论。
//
// 取值一旦发布就进审计表，只能追加、不能重命名或改语义。
type ReasonCode string

const (
	ReasonSuccess ReasonCode = "success"

	// 凭证与传输层。
	ReasonCredentialInvalid ReasonCode = "credential_invalid"
	ReasonCredentialTooLong ReasonCode = "credential_too_long"
	ReasonTokenMalformed    ReasonCode = "token_malformed"
	ReasonConfigInvalid     ReasonCode = "config_invalid"
	ReasonInternalError     ReasonCode = "internal_error"

	// 签名与密钥。
	ReasonSignatureInvalid   ReasonCode = "signature_invalid"
	ReasonAlgorithmDenied    ReasonCode = "algorithm_denied"
	ReasonTypeDenied         ReasonCode = "type_denied"
	ReasonCriticalDenied     ReasonCode = "critical_denied"
	ReasonKeyMissing         ReasonCode = "key_missing"
	ReasonKeyUnavailable     ReasonCode = "key_source_unavailable"
	ReasonKeyMaterialInvalid ReasonCode = "key_material_invalid"

	// claims 校验。
	ReasonClaimsInvalid     ReasonCode = "claims_invalid"
	ReasonIssuerMismatch    ReasonCode = "issuer_mismatch"
	ReasonAudienceMismatch  ReasonCode = "audience_mismatch"
	ReasonTokenExpired      ReasonCode = "token_expired"
	ReasonExpiryMissing     ReasonCode = "expiry_missing"
	ReasonNotYetValid       ReasonCode = "not_yet_valid"
	ReasonIssuedInFuture    ReasonCode = "issued_in_future"
	ReasonLifetimeExceeded  ReasonCode = "lifetime_exceeded"
	ReasonSubjectMissing    ReasonCode = "subject_missing"
	ReasonSubjectUnstable   ReasonCode = "subject_unstable"
	ReasonClaimShapeInvalid ReasonCode = "claim_shape_invalid"
	ReasonClaimOverflow     ReasonCode = "claim_overflow"
	ReasonScopeUnmapped     ReasonCode = "scope_unmapped"
	ReasonMembershipTTL     ReasonCode = "membership_ttl_missing"
	ReasonFixtureNotFound   ReasonCode = "fixture_not_found"

	// stub。
	ReasonNotImplemented ReasonCode = "not_implemented"
)

var registeredReasons = map[ReasonCode]bool{}

func init() {
	for _, r := range []ReasonCode{
		ReasonSuccess,
		ReasonCredentialInvalid, ReasonCredentialTooLong, ReasonTokenMalformed,
		ReasonConfigInvalid, ReasonInternalError,
		ReasonSignatureInvalid, ReasonAlgorithmDenied, ReasonTypeDenied,
		ReasonCriticalDenied, ReasonKeyMissing, ReasonKeyUnavailable, ReasonKeyMaterialInvalid,
		ReasonClaimsInvalid, ReasonIssuerMismatch, ReasonAudienceMismatch,
		ReasonTokenExpired, ReasonExpiryMissing, ReasonNotYetValid, ReasonIssuedInFuture,
		ReasonLifetimeExceeded, ReasonSubjectMissing, ReasonSubjectUnstable,
		ReasonClaimShapeInvalid, ReasonClaimOverflow, ReasonScopeUnmapped, ReasonMembershipTTL,
		ReasonFixtureNotFound,
		ReasonNotImplemented,
	} {
		registeredReasons[r] = true
	}
}

// Valid 报告原因码是否在注册表内。测试用它挡住自然语言与拼错的取值。
func (r ReasonCode) Valid() bool { return registeredReasons[r] }

// String 让原因码能直接进格式化输出。
func (r ReasonCode) String() string { return string(r) }

// sentinelReasons 把哨兵错误映射到原因码。
//
// 顺序敏感：errors.Is 只取第一个命中，前置的错误必须比包装错误更具体，
// 所以这里按「本包自己的哨兵」逐条判断，不再解包装链。
var sentinelReasons = []struct {
	err    error
	reason ReasonCode
}{
	{ErrCredentialKind, ReasonCredentialInvalid},
	{ErrCredentialTooLarge, ReasonCredentialTooLong},
	{ErrCredential, ReasonCredentialInvalid},
	{ErrTokenMalformed, ReasonTokenMalformed},
	{ErrSignature, ReasonSignatureInvalid},
	{ErrAlgorithmDenied, ReasonAlgorithmDenied},
	{ErrTokenTypeDenied, ReasonTypeDenied},
	{ErrCriticalDenied, ReasonCriticalDenied},
	{ErrKeyNotFound, ReasonKeyMissing},
	{ErrKeySourceUnavailable, ReasonKeyUnavailable},
	{ErrKeyMaterial, ReasonKeyMaterialInvalid},
	{ErrClaimsInvalid, ReasonClaimsInvalid},
	{ErrIssuerMismatch, ReasonIssuerMismatch},
	{ErrAudienceMismatch, ReasonAudienceMismatch},
	{ErrExpired, ReasonTokenExpired},
	{ErrExpiryMissing, ReasonExpiryMissing},
	{ErrNotYetValid, ReasonNotYetValid},
	{ErrIssuedInFuture, ReasonIssuedInFuture},
	{ErrLifetimeTooLong, ReasonLifetimeExceeded},
	{ErrSubjectMissing, ReasonSubjectMissing},
	{ErrSubjectUnstable, ReasonSubjectUnstable},
	{ErrClaimShape, ReasonClaimShapeInvalid},
	{ErrClaimOverflow, ReasonClaimOverflow},
	{ErrScopeUnmapped, ReasonScopeUnmapped},
	{ErrMembershipTTL, ReasonMembershipTTL},
	{ErrFixtureNotFound, ReasonFixtureNotFound},
	{ErrConfig, ReasonConfigInvalid},
	{ErrNotImplemented, ReasonNotImplemented},
	{ErrInternal, ReasonInternalError},
}

// ReasonFor 给出错误对应的原因码；未知错误归 internal_error。
//
// 兜底值必须是「失败方向」的码而不是 success：漏登记一个新错误时，
// 审计里出现成功结论比出现未知结论危险得多。
func ReasonFor(err error) ReasonCode {
	if err == nil {
		return ReasonSuccess
	}
	for _, item := range sentinelReasons {
		if errors.Is(err, item.err) {
			return item.reason
		}
	}
	return ReasonInternalError
}

// dependencyReasons 是「不是调用方的错，是依赖的错」那一类原因码。
// 审计的 Outcome 用它区分 denied 与 error（手册 §5：失败策略必须显式表态）。
var dependencyReasons = map[ReasonCode]bool{
	ReasonKeyUnavailable: true,
	ReasonInternalError:  true,
	// 尚未实现（LDAP/SAML 的 stub 路径）既不是调用方的错，也不是权限判定结论：
	// 是本包还没提供那块能力。归进依赖失败，Outcome 才是 error 而不是 denied，
	// 大盘上「这个来源压根没接通」与「这个人被拒了」才分得开。
	ReasonNotImplemented: true,
}

func isDependencyFailure(reason ReasonCode) bool { return dependencyReasons[reason] }

// looksLikeEmail 报告字符串是否是邮箱形态。
//
// 邮箱既不能当 subject（人事改地址就把历史用量和授权断在新地址上，policy §2.1 同此），
// 也不能进审计事件（属于个人信息）。
func looksLikeEmail(s string) bool {
	return strings.Contains(s, "@")
}

// looksLikePhoneOrStudentID 报告字符串是否形如手机号或纯数字学号。
//
// 判断口径偏保守：宁可误伤一个真实工号（只是登录失败，换一个 claim 就能修），
// 也不放过一个手机号（那会把它当稳定主键写进审计表和用量记录，扩散出去收不回）。
// 只接受数字与分隔连字符、且数字位数落在 7..15 才算命中；带字母的工号不受影响。
func looksLikePhoneOrStudentID(s string) bool {
	if s == "" {
		return false
	}
	digits := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return digits >= 7 && digits <= 15
}

// isPIIShape 汇总「形态上属于个人信息」的判断，供审计脱敏使用。
func isPIIShape(s string) bool {
	return looksLikeEmail(s) || looksLikePhoneOrStudentID(s)
}
