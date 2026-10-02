package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// JWK 是一把验签公钥的最小视图。
//
// 只放公钥，类型上就不可能把私钥材料带进 Provider：私钥一旦顺着这个结构进了
// 某个 JSON 输出，泄露面就不再是「token 被验」而是「token 可被伪造」。
type JWK struct {
	KeyID     string `json:"key_id"`
	Algorithm Alg    `json:"algorithm"`
	Public    any    `json:"-"` // *rsa.PublicKey 或 *ecdsa.PublicKey
}

// Validate 检查公钥材料是否够用于验签，并挡住「弱密钥当配置错误塞进来」的情况。
//
// 密钥长度下限是运维口径（不是协议要求）：低于 2048 位的 RSA 与 P-256 以外的曲线，
// 在这个平台上应当视为配置错误而不是可接受的兼容模式。
func (k JWK) Validate() error {
	if k.KeyID == "" {
		return fmt.Errorf("%w: 缺少 kid", ErrKeyMaterial)
	}
	if !k.Algorithm.valid() {
		return fmt.Errorf("%w: %q", ErrAlgorithmDenied, string(k.Algorithm))
	}
	switch typed := k.Public.(type) {
	case *rsa.PublicKey:
		if typed == nil || typed.N == nil {
			return fmt.Errorf("%w: RSA 公钥为空", ErrKeyMaterial)
		}
		if typed.N.BitLen() < 2048 {
			return fmt.Errorf("%w: RSA 模长 %d 位，低于 2048", ErrKeyMaterial, typed.N.BitLen())
		}
		if k.Algorithm != AlgRS256 {
			return fmt.Errorf("%w: RSA 公钥只能配 %q", ErrKeyMaterial, AlgRS256)
		}
		return nil
	case *ecdsa.PublicKey:
		if typed == nil || typed.Curve == nil {
			return fmt.Errorf("%w: ECDSA 公钥为空", ErrKeyMaterial)
		}
		if typed.Curve != elliptic.P256() {
			return fmt.Errorf("%w: 只接受 P-256 曲线", ErrKeyMaterial)
		}
		if k.Algorithm != AlgES256 {
			return fmt.Errorf("%w: ECDSA 公钥只能配 %q", ErrKeyMaterial, AlgES256)
		}
		return nil
	case nil:
		return fmt.Errorf("%w: 公钥为空", ErrKeyMaterial)
	default:
		return fmt.Errorf("%w: 不支持的公钥类型 %T", ErrKeyMaterial, k.Public)
	}
}

// KeySource 是「从哪儿拿验签公钥」的注入点。
//
// 本包不 import net/http、也不自己 new http.Client：公钥来源的出网策略、超时、
// 目标白名单都属于接线层（手册 §5「所有外部调用必须设置 timeout、body limit 和目标约束」）。
// 把边界留成接口，是为了让实现方去负责约束，而不是让身份层默认放开一条出网通路。
type KeySource interface {
	// Keys 返回当前可用的验签公钥。实现必须可并发调用，并尊重 ctx 的取消。
	Keys(ctx context.Context) ([]JWK, error)
}

// KeySourceFunc 把函数适配成 KeySource。
type KeySourceFunc func(ctx context.Context) ([]JWK, error)

func (f KeySourceFunc) Keys(ctx context.Context) ([]JWK, error) {
	if f == nil {
		return nil, fmt.Errorf("%w: KeySourceFunc 为 nil", ErrKeySourceUnavailable)
	}
	return f(ctx)
}

// StaticKeys 是固定公钥集合，用于内置样例与测试（不联网）。
type StaticKeys struct {
	Material []JWK
	// Err 非空时 Keys 直接返回该错误，用于测试「来源不可用」这条失败路径。
	Err error
}

func (s *StaticKeys) Keys(_ context.Context) ([]JWK, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	out := make([]JWK, len(s.Material))
	copy(out, s.Material)
	return out, nil
}

// lookupKey 按 kid 取公钥。
//
// kid 缺失时不做「只用一把 key 就猜」的宽松回落，而是走配置里的
// AllowSingleKeyWithoutKid：真实 IdP 轮换密钥期间，猜错的后果是
// 拿旧 key 验过本该失败的新 token（或反之），运维排查时会一脸莫名。
func lookupKey(keys []JWK, kid string, allowSingleWithoutKid bool) (JWK, error) {
	if kid == "" {
		if allowSingleWithoutKid && len(keys) == 1 {
			return keys[0], nil
		}
		return JWK{}, fmt.Errorf("%w: token 未带 kid", ErrKeyNotFound)
	}
	var matched []JWK
	for _, k := range keys {
		if k.KeyID == kid {
			matched = append(matched, k)
		}
	}
	if len(matched) == 0 {
		return JWK{}, fmt.Errorf("%w: kid 不在当前公钥集合里", ErrKeyNotFound)
	}
	if len(matched) > 1 {
		// 同一个 kid 两把 key 意味着来源侧的 JWKS 已经自相矛盾，
		// 随便挑一把验过都可能是在用错key，交给实现方修数据而不是在这里猜。
		return JWK{}, fmt.Errorf("%w: kid=%q 出现 %d 份重复公钥", ErrKeyMaterial, kid, len(matched))
	}
	return matched[0], nil
}

// CachedKeys 给任意 KeySource 套一层 TTL 缓存（线程安全）。
//
// 每个请求都去拉一次 JWKS 会把 IdP 打成瓶颈，也会在 IdP 抖动的瞬间让全员登录失败；
// 缓存过期后**不**继续用旧 key：密钥轮换窗口里拿过期公钥继续验签，
// 等于把已经下线的 key 又扶正一段时间，这是明确的安全方向选择（宁可短暂不可用）。
type CachedKeys struct {
	source    KeySource
	ttl       time.Duration
	now       func() time.Time
	mu        sync.Mutex
	cached    []JWK
	fetchedAt time.Time
	hasCache  bool
}

// NewCachedKeys 构造缓存层（用真实时钟）。ttl ≤ 0 时取 DefaultKeysTTL。
func NewCachedKeys(source KeySource, ttl time.Duration) (*CachedKeys, error) {
	return NewCachedKeysAt(source, ttl, nil)
}

// NewCachedKeysAt 允许注入时钟。
//
// 时钟只能在建库时给，不提供 SetClock：缓存对象一旦并发共享后再改字段就是数据竞争，
// 而这类竞争通常只在 -race 的偶发运行里出现，比业务 bug 更难复现。
func NewCachedKeysAt(source KeySource, ttl time.Duration, now func() time.Time) (*CachedKeys, error) {
	if source == nil {
		return nil, fmt.Errorf("%w: KeySource 不能为空", ErrConfig)
	}
	if ttl <= 0 {
		ttl = DefaultKeysTTL
	}
	if now == nil {
		now = time.Now
	}
	return &CachedKeys{source: source, ttl: ttl, now: now}, nil
}

// Keys 实现 KeySource。
func (c *CachedKeys) Keys(ctx context.Context) ([]JWK, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hasCache && c.now().Sub(c.fetchedAt) < c.ttl {
		out := make([]JWK, len(c.cached))
		copy(out, c.cached)
		return out, nil
	}
	keys, err := c.source.Keys(ctx)
	if err != nil {
		// 失败时清空缓存：留着旧条目会让「刷新失败」退化成无限期使用旧 key。
		c.cached = nil
		c.hasCache = false
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: 公钥集合为空", ErrKeySourceUnavailable)
	}
	c.cached = make([]JWK, len(keys))
	copy(c.cached, keys)
	c.fetchedAt = c.now()
	c.hasCache = true
	out := make([]JWK, len(keys))
	copy(out, keys)
	return out, nil
}

// DefaultKeysTTL 是公钥缓存的默认有效期。
//
// 太短等于没缓存；太长会让密钥轮换后的一段窗口里新 key 不生效（用户反复登录失败）。
// 5 分钟是这两个方向的折中，实现方可以按 IdP 的轮换节奏覆盖。
const DefaultKeysTTL = 5 * time.Minute

// ParseJWKS 解析标准 JWKS 文档（{"keys":[...]}）。
//
// 本包不做网络请求，但解析必须是标准库实现：把 JWKS 解析也交给接线层的话，
// 「x5c 里的证书链被当成公钥」「kty 拼错被静默忽略」这类问题就会散落到每个适配层。
// 明确拒绝不认识的 kty 与 use=enc 的密钥，而不是跳过 —— 跳过会让配置错误表现为
// 「今天偶尔验签失败」，几乎查不到根因。
func ParseJWKS(doc []byte) ([]JWK, error) {
	var envelope struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(doc, &envelope); err != nil {
		return nil, fmt.Errorf("%w: JWKS 文档解析失败（%s）", ErrKeyMaterial, plainReason(err))
	}
	if len(envelope.Keys) == 0 {
		return nil, fmt.Errorf("%w: JWKS 文档没有 keys", ErrKeyMaterial)
	}
	out := make([]JWK, 0, len(envelope.Keys))
	for i, item := range envelope.Keys {
		if item.Use != "" && item.Use != "sig" {
			return nil, fmt.Errorf("%w: 第 %d 项 use=%q 不是签名密钥", ErrKeyMaterial, i, item.Use)
		}
		switch item.Kty {
		case "RSA":
			n, err := decodeBase64URLInt(item.N)
			if err != nil {
				return nil, fmt.Errorf("%w: 第 %d 项 RSA 模数非法: %v", ErrKeyMaterial, i, err)
			}
			e, err := decodeBase64URLInt(item.E)
			if err != nil {
				return nil, fmt.Errorf("%w: 第 %d 项 RSA 指数非法: %v", ErrKeyMaterial, i, err)
			}
			if !e.IsInt64() || e.Int64() <= 0 {
				return nil, fmt.Errorf("%w: 第 %d 项 RSA 指数非法", ErrKeyMaterial, i)
			}
			out = append(out, JWK{
				KeyID:     item.Kid,
				Algorithm: pickAlg(item.Alg, AlgRS256),
				Public:    &rsa.PublicKey{N: n, E: int(e.Int64())},
			})
		case "EC":
			if item.Crv != "P-256" {
				return nil, fmt.Errorf("%w: 第 %d 项曲线 crv=%q", ErrKeyMaterial, i, item.Crv)
			}
			x, err := decodeBase64URLBytes(item.X)
			if err != nil {
				return nil, fmt.Errorf("%w: 第 %d 项 x 非法: %v", ErrKeyMaterial, i, err)
			}
			y, err := decodeBase64URLBytes(item.Y)
			if err != nil {
				return nil, fmt.Errorf("%w: 第 %d 项 y 非法: %v", ErrKeyMaterial, i, err)
			}
			curve := elliptic.P256()
			pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			if !curve.IsOnCurve(pub.X, pub.Y) {
				return nil, fmt.Errorf("%w: 第 %d 项公钥点不在曲线上", ErrKeyMaterial, i)
			}
			out = append(out, JWK{KeyID: item.Kid, Algorithm: pickAlg(item.Alg, AlgES256), Public: pub})
		default:
			return nil, fmt.Errorf("%w: 第 %d 项 kty=%q 不受支持", ErrKeyMaterial, i, item.Kty)
		}
	}
	for _, k := range out {
		if err := k.Validate(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func pickAlg(declared string, fallback Alg) Alg {
	if declared == "" {
		return fallback
	}
	return Alg(declared)
}

func decodeBase64URLInt(s string) (*big.Int, error) {
	raw, err := decodeBase64URLBytes(s)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: 空整数", ErrKeyMaterial)
	}
	return new(big.Int).SetBytes(raw), nil
}

func decodeBase64URLBytes(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("%w: 段为空", ErrKeyMaterial)
	}
	if strings.ContainsAny(s, "+/=") {
		return nil, fmt.Errorf("%w: 非 base64url 字符", ErrKeyMaterial)
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyMaterial, err)
	}
	return raw, nil
}
