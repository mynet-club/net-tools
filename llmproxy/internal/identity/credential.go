package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// CredentialKind 是凭证的来源类型。取值集合封闭：新增要同步补 Provider 实现和测试。
type CredentialKind string

const (
	// CredentialOIDCToken：JWT（compact JWS）形式的 OIDC ID token。
	CredentialOIDCToken CredentialKind = "oidc-jwt"
	// CredentialSAMLAssertion：Base64 编码的 SAML 2.0 Response/Assertion。
	CredentialSAMLAssertion CredentialKind = "saml-assertion"
	// CredentialLDAPBind：DN + 口令的目录绑定。值是 "dn\npassword" 形式。
	CredentialLDAPBind CredentialKind = "ldap-bind"
	// CredentialFakeFixture：FakeProvider 的 fixture 名，只在测试与影子演练里出现。
	CredentialFakeFixture CredentialKind = "fake-fixture"
)

// maxCredentialBytes 是凭证原文的长度上限。
//
// 上限必须有但不能太紧：IdP 把 groups、affiliations 全塞进 token 时几 KB 很常见，
// 卡太小会让正常的院系教师登录失败；放开不管则给「超大 token 打爆内存」留了口子。
const maxCredentialBytes = 64 * 1024

// Credential 是一段外部凭证。
//
// 原文只放在未导出字段里，是为了让「不许记录 token」这条规则由类型系统兜住：
// 一旦有导出的 Token 字段，它就必然会顺着 json.Marshal 走进审计表、
// 管理台响应或者某次 t.Errorf 的输出。这里 MarshalJSON 与 String 都只输出脱敏形式，
// 想要原文只能显式调 Value()，代码评审时一眼就能看到取原文的那一行。
type Credential struct {
	kind      CredentialKind
	value     string
	requestID string
}

// NewCredential 构造凭证。空值与超长在这里就拒掉，不留到验签阶段。
func NewCredential(kind CredentialKind, value string) (Credential, error) {
	if !knownCredentialKind(kind) {
		return Credential{}, fmt.Errorf("%w: %q", ErrCredentialKind, kind)
	}
	if value == "" {
		return Credential{}, fmt.Errorf("%w: 凭证内容为空", ErrCredential)
	}
	if len(value) > maxCredentialBytes {
		return Credential{}, fmt.Errorf("%w: %d 字节，上限 %d 字节", ErrCredentialTooLarge, len(value), maxCredentialBytes)
	}
	return Credential{kind: kind, value: value}, nil
}

// WithRequestID 附上调用方的关联 ID。
//
// 关联 ID 由上层（server/handler）生成，本包不自己造：审计要能和请求日志对得上。
func (c Credential) WithRequestID(requestID string) Credential {
	out := c
	out.requestID = requestID
	return out
}

func (c Credential) Kind() CredentialKind { return c.kind }

func (c Credential) RequestID() string { return c.requestID }

// Value 返回凭证原文。
//
// 唯一正当的用途是把原文交给验签/绑定实现。绝不允许把它赋给结构体字段、
// 写进 error 或 AuditEvent —— credential_test.go 与 leak_test.go 会盯住这一点。
func (c Credential) Value() string { return c.value }

// String 是脱敏形式，供日志和 %v 使用。
func (c Credential) String() string {
	return fmt.Sprintf("Credential(%s,%s)", c.kind, SubjectRef(c.value))
}

// GoString 让 %#v 也拿不到原文：调试输出常常就是一次 %#v。
func (c Credential) GoString() string { return c.String() }

// MarshalJSON 保证凭证被整体序列化时（例如某处把请求上下文打进日志）也只剩摘要。
func (c Credential) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"` + string(c.kind) + `","ref":"` + SubjectRef(c.value) + `"}`), nil
}

// SubjectRef 给出原文的单向摘要前缀，用于跨日志关联同一个凭证而不出原文。
//
// 取 12 个十六进制字符（48 bit）：在单租户的登录量级下碰撞概率可忽略，
// 而完整 64 字符的摘要放进日志只会淹没真正有用的字段。
func SubjectRef(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:12]
}

func knownCredentialKind(k CredentialKind) bool {
	switch k {
	case CredentialOIDCToken, CredentialSAMLAssertion, CredentialLDAPBind, CredentialFakeFixture:
		return true
	}
	return false
}
