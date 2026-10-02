package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Alg 是本包支持的 JWS 签名算法。集合封闭，只有非对称两种：
//
// HS256 一类对称算法被排除是有意的 —— 验签密钥和签发密钥同源，
// 一旦有人把对称密钥当作「公钥」通过 JWKS 分发出去，任何人都能自签 token。
// 这是历史上最经典的 JWT 实现缺陷之一，配置层面不给它入口比运行时判断更可靠。
type Alg string

const (
	AlgRS256 Alg = "RS256"
	AlgES256 Alg = "ES256"
)

// DefaultAlgorithms 是默认允许的算法集合。
func DefaultAlgorithms() []Alg { return []Alg{AlgRS256, AlgES256} }

func (a Alg) valid() bool { return a == AlgRS256 || a == AlgES256 }

// DefaultAllowedTypes 是默认允许的 JWS typ 取值（比较时统一转小写）。
//
// 校验 typ 不是形式主义：同一个 compact 三段串既可能是 ID token 也可能是 access token，
// 而两者的 claims 结构、可信字段完全不同。把 access token 当 ID token 解析，
// 常见的后果是拿到一份没有角色、但 subject 合法的 claims —— 直接绕过角色相关的 deny。
// at+jwt 是 RFC 9068 给 access token 注册的 typ，有些 IdP 会在 ID token 上也写 JWT。
var DefaultAllowedTypes = []string{"jwt", "at+jwt"}

// hashFor 给出算法对应的摘要。
//
// 目前两种算法都是 SHA-256，仍然保留这层映射：新增算法时漏改摘要口径
// 会让验签「看起来能过」，那类缺陷一旦上线就只能靠事故发现。
func hashFor(a Alg) (crypto.Hash, error) {
	switch a {
	case AlgRS256, AlgES256:
		return crypto.SHA256, nil
	}
	return 0, fmt.Errorf("%w: %q 无对应摘要", ErrAlgorithmDenied, string(a))
}

// JWSHeader 是 compact JWS 的保护头。
type JWSHeader struct {
	Algorithm Alg      `json:"alg"`
	Type      string   `json:"typ"`
	KeyID     string   `json:"kid"`
	Critical  []string `json:"crit"`
}

// parsedJWS 是一次拆包的结果。
//
// signingInput 保留原始 base64url 文本而不是解码后的字节：JWS 的签名输入定义就是
// 「ASCII('.') 连接的两个 base64url 段」，用解码后的字节去验签会验不过（也是实现缺陷的高发点）。
type parsedJWS struct {
	Header       JWSHeader
	HeaderJSON   []byte
	Payload      []byte
	signingInput string
	signature    []byte
}

// parseJWS 把 compact 序列化（header.payload.signature）拆成三段并解出保护头。
//
// 不做签名校验，那是 verifyJWS 的事；拆包阶段先拒掉结构性问题，
// 可以让「结构不对」和「签名不对」在审计里分成两个原因码。
func parseJWS(compact string) (*parsedJWS, error) {
	trimmed := strings.TrimSpace(compact)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: 空凭证", ErrTokenMalformed)
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: 段数 %d，compact JWS 必须是 3 段", ErrTokenMalformed, len(parts))
	}
	headerRaw, err := decodeBase64URL(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: 保护头 %v", ErrTokenMalformed, err)
	}
	payload, err := decodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload %v", ErrTokenMalformed, err)
	}
	signature, err := decodeBase64URL(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: 签名段 %v", ErrTokenMalformed, err)
	}
	if len(signature) == 0 {
		// 空签名段是 alg:none 的典型形态；即使 alg 写了别的值也要拒，
		// 否则「头写 RS256 + 空签名」这种畸形 token 会走到验签里靠运气失败。
		return nil, fmt.Errorf("%w: 签名段为空（alg:none 形态）", ErrTokenMalformed)
	}

	var header JWSHeader
	dec := json.NewDecoder(strings.NewReader(string(headerRaw)))
	if err := dec.Decode(&header); err != nil {
		return nil, fmt.Errorf("%w: 保护头不是 JSON 对象（%s）", ErrTokenMalformed, plainReason(err))
	}
	if header.Algorithm == "" {
		return nil, fmt.Errorf("%w: 保护头缺少 alg", ErrTokenMalformed)
	}
	return &parsedJWS{
		Header:       header,
		HeaderJSON:   headerRaw,
		Payload:      payload,
		signingInput: parts[0] + "." + parts[1],
		signature:    signature,
	}, nil
}

// decodeBase64URL 严格解 base64url（无填充）。
//
// 解完还要再编码一次比对原文：base64 存在「一个字节序列有多种合法文本表示」的特性，
// 宽松解码会让同一个 payload 有两种文本形式，攻击者可以用它绕过按原文匹配的
// 缓存键、WAF 规则和黑名单。
func decodeBase64URL(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("段为空")
	}
	if strings.ContainsAny(s, "+/=") {
		return nil, errors.New("含非 base64url 字符（+/ 或填充 =）")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if base64.RawURLEncoding.EncodeToString(raw) != s {
		return nil, errors.New("非规范编码（存在等价表示）")
	}
	return raw, nil
}

// validateHeader 检查 alg 与 typ 是否在允许集合内，并挡住未支持的 crit。
//
// 必须在验签**之前**完成：alg 混淆攻击（把 alg 改成 none 或 HS256）利用的正是
// 「先按头里的算法走一遍」的实现的顺序漏洞。
func validateHeader(h JWSHeader, algorithms []Alg, types []string) error {
	if len(h.Critical) > 0 {
		return fmt.Errorf("%w: %v 未被实现支持", ErrCriticalDenied, h.Critical)
	}
	if !h.Algorithm.valid() {
		return fmt.Errorf("%w: token 声明用 %q 签名", ErrAlgorithmDenied, string(h.Algorithm))
	}
	if !containsAlg(algorithms, h.Algorithm) {
		return fmt.Errorf("%w: 本来源只允许 %v", ErrAlgorithmDenied, algorithms)
	}
	normalizedType := strings.ToLower(strings.TrimSpace(h.Type))
	if normalizedType == "" {
		return fmt.Errorf("%w: typ 缺失（无法区分 ID token 与 access token）", ErrTokenTypeDenied)
	}
	allowed := types
	if len(allowed) == 0 {
		allowed = DefaultAllowedTypes
	}
	isKnownType := false
	for _, t := range allowed {
		if strings.ToLower(strings.TrimSpace(t)) == normalizedType {
			isKnownType = true
		}
	}
	if !isKnownType {
		return fmt.Errorf("%w: typ=%q 不在允许集合", ErrTokenTypeDenied, h.Type)
	}
	return nil
}

// verifyJWS 用公钥验证签名。任何失败都归到同一个哨兵 ErrSignature：
// 细节（摘要不符 / 长度不符 / 曲线不符）只写进日志级别的原因码，
// 不回显给调用方 —— 签名失败的细节对攻击者是免费的分析反馈。
func verifyJWS(jws *parsedJWS, key JWK) error {
	hash, err := hashFor(jws.Header.Algorithm)
	if err != nil {
		return err
	}
	hasher := hash.New()
	if _, writeErr := hasher.Write([]byte(jws.signingInput)); writeErr != nil {
		return fmt.Errorf("%w: 摘要计算失败", ErrInternal)
	}
	digest := hasher.Sum(nil)
	switch jws.Header.Algorithm {
	case AlgRS256:
		pub, ok := key.Public.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: RS256 需要 RSA 公钥", ErrKeyMaterial)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, jws.signature); err != nil {
			return fmt.Errorf("%w: RSA 验签未通过: %v", ErrSignature, err)
		}
		return nil
	case AlgES256:
		pub, ok := key.Public.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: ES256 需要 ECDSA 公钥", ErrKeyMaterial)
		}
		if pub.Curve != elliptic.P256() {
			return fmt.Errorf("%w: ES256 只接受 P-256 曲线", ErrKeyMaterial)
		}
		r, s, err := joseSignatureToRS(jws.signature, pub.Curve.Params().BitSize)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrSignature, err)
		}
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return fmt.Errorf("%w: ECDSA 验签未通过", ErrSignature)
		}
		return nil
	}
	return fmt.Errorf("%w: %q", ErrAlgorithmDenied, string(jws.Header.Algorithm))
}

// joseSignatureToRS 把 JWS 的 R||S 定长拼接转成 ECDSA 需要的两个大整数。
//
// JOSE 用固定长度串联，OpenSSL 用 ASN.1；直接把签名段当 ASN.1 解会得到错误的 r/s，
// 而按位长切分才能保证「同一个签名在两边解析结果一致」。
func joseSignatureToRS(sig []byte, bitSize int) (r, s *big.Int, err error) {
	keyBytes := (bitSize + 7) / 8
	if len(sig) != 2*keyBytes {
		return nil, nil, fmt.Errorf("签名长度 %d 与曲线不匹配（期望 %d）", len(sig), 2*keyBytes)
	}
	r = new(big.Int).SetBytes(sig[:keyBytes])
	s = new(big.Int).SetBytes(sig[keyBytes:])
	// JOSE 规定 r、s 落在 [1, n-1]：全零段（或只填了高位补零的段）不是合法签名。
	// ecdsa.Verify 也会拒，但在这里先判能让错误停在「签名段形态」这一层，
	// 不会把「畸形签名」和「签名不符」混成同一个结论。
	if r.Sign() == 0 || s.Sign() == 0 {
		return nil, nil, errors.New("签名的 r/s 段为零")
	}
	return r, s, nil
}

// SignJWS 用私钥产出 compact JWS。
//
// 为什么要在这个包里提供签名能力：FakeAuthority（测试签发方）和工作包 G 的端到端场景
// 都需要「不联网也能造出真 token」。没有它，测试就只能覆盖 FakeProvider 这一条路，
// OIDCProvider 的验签分支永远没有真实输入 —— 那正是最容易藏 bug 的地方。
// 生产代码路径不会调它：验签方拿不到私钥。
func SignJWS(key any, header JWSHeader, payload []byte) (string, error) {
	if header.Algorithm == "" {
		return "", fmt.Errorf("%w: 签名必须指定 alg", ErrConfig)
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("%w: 保护头序列化失败: %v", ErrInternal, err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	var signature []byte
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		if header.Algorithm != AlgRS256 {
			return "", fmt.Errorf("%w: RSA 私钥只能签 %q", ErrConfig, AlgRS256)
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, typed, crypto.SHA256, digest[:])
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrInternal, err)
		}
		signature = sig
	case *ecdsa.PrivateKey:
		if header.Algorithm != AlgES256 {
			return "", fmt.Errorf("%w: ECDSA 私钥只能签 %q", ErrConfig, AlgES256)
		}
		if typed.Curve != elliptic.P256() {
			return "", fmt.Errorf("%w: ES256 只接受 P-256 曲线", ErrConfig)
		}
		r, sv, err := ecdsa.Sign(rand.Reader, typed, digest[:])
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrInternal, err)
		}
		if signature, err = rsToJoseSignature(r, sv, typed.Curve.Params().BitSize); err != nil {
			return "", fmt.Errorf("%w: %v", ErrInternal, err)
		}
	default:
		return "", fmt.Errorf("%w: 不支持的私钥类型 %T", ErrConfig, key)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func rsToJoseSignature(r, s *big.Int, bitSize int) ([]byte, error) {
	keyBytes := (bitSize + 7) / 8
	if r.BitLen() > bitSize || s.BitLen() > bitSize {
		return nil, errors.New("r/s 超出曲线位长")
	}
	out := make([]byte, 2*keyBytes)
	r.FillBytes(out[:keyBytes])
	s.FillBytes(out[keyBytes:])
	return out, nil
}

func containsAlg(list []Alg, v Alg) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
