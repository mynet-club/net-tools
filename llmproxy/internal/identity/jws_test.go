package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"testing"
)

// compact JWS 的拆包：段数、字符集、规范化编码。
func TestParseJWSRejectsMalformedTokens(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		want   error
		reason ReasonCode
	}{
		{"空串", "", ErrTokenMalformed, ReasonTokenMalformed},
		{"只有两段", "aGVsbG8.dGVzdA", ErrTokenMalformed, ReasonTokenMalformed},
		{"四段", "aGVsbG8.dGVzdA.YXNk.Zm9v", ErrTokenMalformed, ReasonTokenMalformed},
		{"签名段为空（alg:none 形态）", "aGVsbG8.dGVzdA.", ErrTokenMalformed, ReasonTokenMalformed},
		{"含 base64 标准字符 +/", "aGVsbG8+.dGVzdA.YXNk", ErrTokenMalformed, ReasonTokenMalformed},
		{"含填充 =", "aGVsbG8=.dGVzdA.YXNk", ErrTokenMalformed, ReasonTokenMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseJWS(tc.input)
			if !errors.Is(err, tc.want) {
				t.Fatalf("期望 %v，实际 %v", tc.want, err)
			}
			if got := ReasonFor(err); got != tc.reason {
				t.Fatalf("原因码期望 %q 实际 %q", tc.reason, got)
			}
		})
	}
}

// 非规范的 base64url 文本（等价表示）必须拒绝：宽松解码会让同一个 payload 有两种文本，
// 破坏「按原文匹配」的缓存键与黑名单。
func TestDecodeBase64URLRejectsNonCanonicalForms(t *testing.T) {
	// 两个字节只有 16 位，base64 的第三个字符有 2 位是补位，
	// 于是同一段字节存在多个「能解回原值但文本不同」的写法。
	raw := []byte{0xff, 0x00}
	canonical := base64.RawURLEncoding.EncodeToString(raw)
	if got, err := decodeBase64URL(canonical); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("规范形式应能解出原值: %v", err)
	}

	variants := []string{
		canonical + "=", // 带填充
		"",              // 空段
		"++/",           // 标准字母表字符
	}
	// 找出「解码结果相同、文本不同」的等价表示。
	var equivalent string
	for _, letter := range urlAlphabet {
		alt := canonical[:len(canonical)-1] + string(letter)
		if alt == canonical {
			continue
		}
		decoded, err := base64.RawURLEncoding.DecodeString(alt)
		if err == nil && bytes.Equal(decoded, raw) {
			equivalent = alt
			break
		}
	}
	if equivalent == "" {
		t.Fatal("测试前提失效：无法构造等价的非规范表示")
	}
	variants = append(variants, equivalent)

	for _, variant := range variants {
		if _, err := decodeBase64URL(variant); err == nil {
			t.Fatalf("%q 必须被拒绝（等价表示会破坏按原文匹配的缓存键）", variant)
		}
	}
}

// 保护头校验：算法集合、typ 集合、crit。
func TestValidateHeaderPolicy(t *testing.T) {
	algorithms := DefaultAlgorithms()
	types := DefaultAllowedTypes

	if err := validateHeader(JWSHeader{Algorithm: AlgRS256, Type: "JWT"}, algorithms, types); err != nil {
		t.Fatalf("RS256/JWT 应通过: %v", err)
	}
	// typ 大小写不敏感：IdP 之间写法不一（JWT / jwt / at+JWT）。
	if err := validateHeader(JWSHeader{Algorithm: AlgES256, Type: "at+jwt"}, algorithms, types); err != nil {
		t.Fatalf("at+jwt 应通过: %v", err)
	}
	// alg:none —— 历史上最经典的绕过。
	if err := validateHeader(JWSHeader{Algorithm: "none", Type: "JWT"}, algorithms, types); !errors.Is(err, ErrAlgorithmDenied) {
		t.Fatalf("alg=none 必须拒: %v", err)
	}
	// HS256：对称算法根本不进允许集合。
	if err := validateHeader(JWSHeader{Algorithm: "HS256", Type: "JWT"}, algorithms, types); !errors.Is(err, ErrAlgorithmDenied) {
		t.Fatalf("HS256 必须拒: %v", err)
	}
	if err := validateHeader(JWSHeader{Algorithm: AlgRS256, Type: ""}, algorithms, types); !errors.Is(err, ErrTokenTypeDenied) {
		t.Fatalf("typ 缺失必须拒: %v", err)
	}
	if err := validateHeader(JWSHeader{Algorithm: AlgRS256, Type: "device-attestation"}, algorithms, types); !errors.Is(err, ErrTokenTypeDenied) {
		t.Fatalf("未知 typ 必须拒: %v", err)
	}
	if err := validateHeader(JWSHeader{Algorithm: AlgRS256, Type: "JWT", Critical: []string{"b64"}}, algorithms, types); !errors.Is(err, ErrCriticalDenied) {
		t.Fatalf("未支持的 crit 必须拒: %v", err)
	}
	// 收紧后的允许集合要真的生效。
	if err := validateHeader(JWSHeader{Algorithm: AlgES256, Type: "JWT"}, []Alg{AlgRS256}, types); !errors.Is(err, ErrAlgorithmDenied) {
		t.Fatal("配置只放 RS256 时 ES256 必须拒")
	}
}

// 签名与算法的对应关系不能错拿：拿 EC 公钥去验 RSA 签名必须报「公钥材料」而不是「签名不符」。
func TestVerifyKeyTypeMismatchIsConfigErrorNotSignatureFailure(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewFakeAuthority()
	if err != nil {
		t.Fatal(err)
	}

	rsaToken := mustToken(t, authority, SignRequest{Profile: studentProfile(), At: baseNow, Algorithm: AlgRS256})
	ecToken := mustToken(t, authority, SignRequest{Profile: studentProfile(), At: baseNow, Algorithm: AlgES256})

	jwsRSA, err := parseJWS(rsaToken)
	if err != nil {
		t.Fatal(err)
	}
	jwsEC, err := parseJWS(ecToken)
	if err != nil {
		t.Fatal(err)
	}

	if err := verifyJWS(jwsRSA, JWK{KeyID: "k", Algorithm: AlgRS256, Public: &ecKey.PublicKey}); !errors.Is(err, ErrKeyMaterial) {
		t.Fatalf("RS256 配 EC 公钥应报公钥材料问题: %v", err)
	}
	if err := verifyJWS(jwsEC, JWK{KeyID: "k", Algorithm: AlgES256, Public: &rsaKey.PublicKey}); !errors.Is(err, ErrKeyMaterial) {
		t.Fatalf("ES256 配 RSA 公钥应报公钥材料问题: %v", err)
	}
	if err := verifyJWS(jwsRSA, JWK{KeyID: "k", Algorithm: AlgRS256, Public: &rsaKey.PublicKey}); !errors.Is(err, ErrSignature) {
		t.Fatalf("用别人的 RSA 公钥验必须落到签名不符: %v", err)
	}
}

// ES256 的定长 R||S 切分：长度不对要报错，不能当 ASN.1 蒙混。
func TestJoseSignatureToRS(t *testing.T) {
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i + 1)
	}
	r, s, err := joseSignatureToRS(sig, 256)
	if err != nil {
		t.Fatal(err)
	}
	if r.BitLen() == 0 || s == nil {
		t.Fatal("r/s 解析异常")
	}
	// 每个坐标 32 字节：前 32 是 r、后 32 是 s，切错一位签名就全废。
	if r.Bytes()[0] != sig[0] {
		t.Fatalf("r 应取自签名前段：r=%x 前字节=%x", r.Bytes(), sig[:8])
	}
	for _, bad := range [][]byte{nil, {}, sig[:32], sig[:63], append(append([]byte{}, sig...), 0)} {
		if _, _, err := joseSignatureToRS(bad, 256); err == nil {
			t.Fatalf("长度 %d 的签名必须报错", len(bad))
		}
	}
	// 全零坐标（r=0 不是合法椭圆坐标标量）。
	if _, _, err := joseSignatureToRS(make([]byte, 64), 256); err == nil {
		t.Fatal("r/s 为零必须报错")
	}
}

// SignJWS 与 parseJWS/verifyJWS 构成一个闭环：自签的 token 自己能验过。
func TestSignJWSRoundTrip(t *testing.T) {
	authority := testAuthority(t)
	payload := []byte(`{"sub":"uid-1","iss":"https://a.invalid"}`)

	for _, algorithm := range []Alg{AlgRS256, AlgES256} {
		t.Run(string(algorithm), func(t *testing.T) {
			var signer any
			var key JWK
			if algorithm == AlgRS256 {
				signer = testRSAPrivate(t, authority)
				key = JWK{KeyID: "k", Algorithm: AlgRS256, Public: testRSAPublic(t, authority)}
			} else {
				signer = testECPrivate(t, authority)
				key = JWK{KeyID: "k", Algorithm: AlgES256, Public: testECPublic(t, authority)}
			}
			token, err := SignJWS(signer, JWSHeader{Algorithm: algorithm, Type: "JWT", KeyID: "k"}, payload)
			if err != nil {
				t.Fatal(err)
			}
			jws, err := parseJWS(token)
			if err != nil {
				t.Fatal(err)
			}
			if string(jws.Payload) != string(payload) {
				t.Fatal("payload 必须逐字节还原")
			}
			if err := verifyJWS(jws, key); err != nil {
				t.Fatalf("自签的 token 应能验过: %v", err)
			}
		})
	}

	// 密钥与算法不匹配要在签名时就报错，不能产出一个「看起来是 JWT」的废串。
	if _, err := SignJWS(testRSAPrivate(t, authority), JWSHeader{Algorithm: AlgES256, Type: "JWT"}, payload); !errors.Is(err, ErrConfig) {
		t.Fatalf("RSA 私钥签 ES256 应报配置错误: %v", err)
	}
	if _, err := SignJWS(nil, JWSHeader{Algorithm: AlgRS256, Type: "JWT"}, payload); !errors.Is(err, ErrConfig) {
		t.Fatalf("nil 密钥应报配置错误: %v", err)
	}
}
