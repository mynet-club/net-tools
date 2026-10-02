package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// 凭证是「唯一携带原文的对象」，它的脱敏行为决定了一件事：
// 任何人把凭证塞进日志、JSON 或 t.Errorf，泄露的都只是摘要。

func TestNewCredentialAcceptsEveryDeclaredKind(t *testing.T) {
	for _, kind := range []CredentialKind{
		CredentialOIDCToken, CredentialSAMLAssertion, CredentialLDAPBind, CredentialFakeFixture,
	} {
		cred, err := NewCredential(kind, "some-value")
		if err != nil {
			t.Fatalf("%q 应是合法凭证类型: %v", kind, err)
		}
		if cred.Kind() != kind || cred.Value() != "some-value" {
			t.Fatalf("%q 构造结果不符: %+v", kind, cred)
		}
	}
}

func TestNewCredentialRejections(t *testing.T) {
	cases := []struct {
		name  string
		kind  CredentialKind
		value string
		want  error
	}{
		{"未知类型（对称凭证不该有入口）", CredentialKind("bearer"), "x", ErrCredentialKind},
		{"空类型", CredentialKind(""), "x", ErrCredentialKind},
		{"HS256 之类的自造类型", CredentialKind("jwt-hs256"), "x", ErrCredentialKind},
		{"空内容", CredentialOIDCToken, "", ErrCredential},
		{"超大内容", CredentialOIDCToken, strings.Repeat("a", maxCredentialBytes+1), ErrCredentialTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewCredential(tc.kind, tc.value)
			if !errors.Is(err, tc.want) {
				t.Fatalf("期望 %v，实际 %v", tc.want, err)
			}
			if got := ReasonFor(err); !got.Valid() {
				t.Fatalf("凭证错误必须有注册过的原因码，实际 %q", got)
			}
		})
	}
	// 边界：正好到上限要放过（真实 IdP 塞满 groups 的 token 就在这个量级）。
	if _, err := NewCredential(CredentialOIDCToken, strings.Repeat("a", maxCredentialBytes)); err != nil {
		t.Fatalf("等于上限必须放过: %v", err)
	}
}

// 任何形式的格式化输出都拿不到原文：这是「绝不记录 token」的类型层保证。
func TestCredentialFormattingNeverLeaksRawValue(t *testing.T) {
	raw := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1aWQtc3R1LTEwMDEifQ.fake-signature-material"
	cred, err := NewCredential(CredentialOIDCToken, raw)
	if err != nil {
		t.Fatal(err)
	}
	probes := map[string]string{
		"%s":       fmt.Sprintf("%s", cred),
		"%v":       fmt.Sprintf("%v", cred),
		"%+v":      fmt.Sprintf("%+v", cred),
		"%#v":      fmt.Sprintf("%#v", cred),
		"String()": cred.String(),
		"GoString": cred.GoString(),
	}
	encoded, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("凭证必须可序列化: %v", err)
	}
	probes["json"] = string(encoded)
	if pointer, err := json.Marshal(&cred); err != nil {
		t.Fatal(err)
	} else {
		probes["json-ptr"] = string(pointer)
	}
	for name, out := range probes {
		if strings.Contains(out, raw) {
			t.Fatalf("%s 泄露了凭证原文: %s", name, out)
		}
		// 原文的任何一段连续片段都不能出现（截断输出同样是泄露）。
		for _, chunk := range []string{raw[:24], raw[len(raw)-24:], "fake-signature"} {
			if strings.Contains(out, chunk) {
				t.Fatalf("%s 泄露了凭证片段 %q: %s", name, chunk, out)
			}
		}
	}
	if !strings.Contains(probes["String()"], SubjectRef(raw)) {
		t.Fatal("脱敏输出必须带上可供关联的摘要")
	}
}

func TestSubjectRefProperties(t *testing.T) {
	raw := "some-token-value"
	ref := SubjectRef(raw)
	if len(ref) != 12 {
		t.Fatalf("摘要长度应是 12 个十六进制字符，实际 %d", len(ref))
	}
	if ref != SubjectRef(raw) {
		t.Fatal("同一原文的摘要必须稳定，否则跨日志对不上")
	}
	if ref == SubjectRef(raw+"x") {
		t.Fatal("不同原文必须给出不同摘要")
	}
	if strings.Contains(ref, raw) || strings.Contains(strings.ToLower(ref), "token") {
		t.Fatalf("摘要不得回显原文: %s", ref)
	}
	for _, c := range ref {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("摘要必须是十六进制小写，遇到 %q", c)
		}
	}
}

// RequestID 是值语义的附加：不能改原对象，否则并发复用的凭证会互相污染。
func TestCredentialWithRequestIDIsCopyOnWrite(t *testing.T) {
	base, err := NewCredential(CredentialOIDCToken, "token-a")
	if err != nil {
		t.Fatal(err)
	}
	withID := base.WithRequestID("req-1")
	if base.RequestID() != "" {
		t.Fatal("派生不能影响原凭证")
	}
	if withID.RequestID() != "req-1" {
		t.Fatal("RequestID 没带上")
	}
	if withID.Value() != base.Value() || withID.Kind() != base.Kind() {
		t.Fatal("派生必须保留凭证内容")
	}
	// 零值凭证不能panic：接线阶段可能构造了一半。
	var zero Credential
	if zero.Kind() != "" || zero.Value() != "" || zero.RequestID() != "" {
		t.Fatal("零值凭证应全部为空")
	}
	if !strings.HasPrefix(zero.String(), "Credential(,") {
		t.Fatalf("零值凭证的脱敏输出异常: %s", zero.String())
	}
}
