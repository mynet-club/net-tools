package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Claims 是 token 的声明集合。
//
// 标准字段拆成强类型（校验和映射都要用它们，字符串再解析一次只会引入歧义），
// 非标准字段留在 Extra 里供映射器读取。
//
// Extra 只在内存里活着：从解析到映射结束就结束生命周期。
// 它不进 Principal、不进 AuditEvent、不进错误文本 —— 里面有各校自定义的
// 邮箱、手机号、院系命名，一旦跟着审计落库，身份层就变成了个人信息库。
type Claims struct {
	Issuer    string    `json:"-"`
	Audience  []string  `json:"-"`
	Subject   string    `json:"-"`
	Expiry    time.Time `json:"-"`
	NotBefore time.Time `json:"-"`
	IssuedAt  time.Time `json:"-"`
	JWTID     string    `json:"-"`
	// HasExpiry 区分「exp 数值非法」与「根本没有 exp」：前者是 claims 损坏，
	// 后者是缺时效，两者的错误与原因码必须不同，否则运营看不懂大盘。
	HasExpiry bool `json:"-"`
	// Extra 是全部 claims（标准字段也在内），键为 claim 名。
	// 值只允许 map[string]any / []any / string / json.Number / bool / nil。
	Extra map[string]any `json:"-"`
}

// maxClaimsDepth 限制嵌套 claim 的层数。
//
// token 是攻击者可控输入，映射器会沿 claim 路径下钻；不设深度的话，
// 一个几千层嵌套的 payload 就能把栈打爆（还没走到验签之后）。
const maxClaimsDepth = 8

// NumericDate 的可接受区间。
//
// 上限不是为了精度，而是为了让一次配置错误（把毫秒当秒、随手写 99999999999999）
// 明确报错，而不是变成一个「2286 年才过期」的永久身份。
const (
	minNumericDate int64 = 946_684_800     // 2000-01-01
	maxNumericDate int64 = 253_402_300_800 // 约 9999-12-31
)

// ParseClaims 把 JWT payload（JSON）解成 Claims。
//
// 数字一律先落成 json.Number：exp 是 NumericDate，允许带小数秒，
// 用 any 再 type-switch 成 float64 会在 10 位秒值上丢精度。
func ParseClaims(payload []byte) (Claims, error) {
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return Claims{}, fmt.Errorf("%w: payload 不是 JSON 对象（%s）", ErrClaimsInvalid, plainReason(err))
	}
	if depth := mapDepth(raw, 1); depth > maxClaimsDepth {
		return Claims{}, fmt.Errorf("%w: 嵌套 %d 层，超过上限 %d", ErrClaimsInvalid, depth, maxClaimsDepth)
	}
	c := Claims{Extra: raw}

	if v, ok := raw["iss"]; ok {
		s, isStr := v.(string)
		if !isStr {
			return Claims{}, fmt.Errorf("%w: iss 必须是字符串，实际 %s", ErrClaimsInvalid, typeName(v))
		}
		c.Issuer = s
	}
	aud, err := claimAudience(raw["aud"])
	if err != nil {
		return Claims{}, err
	}
	c.Audience = aud

	if v, ok := raw["sub"]; ok {
		s, isStr := v.(string)
		if !isStr {
			// 数字型 sub 在部分 IdP 里确实存在，但 JSON 解出来是 json.Number：
			// 与其在这里偷偷转成字符串（同一主体可能因此出现两个键），不如拒掉让 IdP 加前缀。
			return Claims{}, fmt.Errorf("%w: sub 必须是字符串，实际 %s", ErrClaimsInvalid, typeName(v))
		}
		c.Subject = s
	}
	if v, ok := raw["jti"]; ok {
		s, isStr := v.(string)
		if !isStr {
			return Claims{}, fmt.Errorf("%w: jti 必须是字符串，实际 %s", ErrClaimsInvalid, typeName(v))
		}
		c.JWTID = s
	}

	if v, ok := raw["exp"]; ok {
		t, parsed := numericDateToTime(v)
		if !parsed {
			return Claims{}, fmt.Errorf("%w: exp 数值非法或超出可接受区间", ErrClaimsInvalid)
		}
		c.HasExpiry = true
		c.Expiry = t
	}
	nbf, err := optionalTime(raw, "nbf")
	if err != nil {
		return Claims{}, err
	}
	c.NotBefore = nbf
	iat, err := optionalTime(raw, "iat")
	if err != nil {
		return Claims{}, err
	}
	c.IssuedAt = iat
	return c, nil
}

func optionalTime(raw map[string]any, key string) (time.Time, error) {
	v, ok := raw[key]
	if !ok {
		return time.Time{}, nil
	}
	t, parsed := numericDateToTime(v)
	if !parsed {
		return time.Time{}, fmt.Errorf("%w: %s 数值非法或超出可接受区间", ErrClaimsInvalid, key)
	}
	return t, nil
}

// claimAudience 接受规范允许的两种 aud 形态：单字符串与字符串数组。
func claimAudience(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	switch typed := v.(type) {
	case string:
		if typed == "" {
			return nil, nil
		}
		return []string{typed}, nil
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%w: aud 数组含非字符串项（%s）", ErrClaimsInvalid, typeName(item))
			}
			if s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: aud 类型不支持（%s）", ErrClaimsInvalid, typeName(v))
	}
}

// ValidateClaims 是 claims 层的校验配置（签发方、受众、时钟、时长上限）。
type ValidateClaims struct {
	// Issuer 必须与 token 的 iss 精确相等。大小写敏感：OIDC 的 iss 是 URI，
	// 在这里做折叠会和 IdP 侧的校验不一致，等于两边各有各的通过集合。
	Issuer string
	// Audience 是本服务在 IdP 注册的 client 标识；token 的 aud 必须包含它。
	Audience string
	// ExtraAudiences 是额外可接受的 aud 值（同一服务多 client 时用）。
	ExtraAudiences []string
	// AllowMultiAudience 放开「aud 含多值即拒」的严格规则。
	AllowMultiAudience bool
	// Skew 是容忍的时钟偏移；0 走 DefaultClockSkew，负数按 0。
	Skew time.Duration
	// StrictClock 关闭偏移容忍（把 Skew 强制成 0）。
	// 用显式开关而不是「Skew=0 表示严格」：0 同时是零值，
	// 靠它表达严格语义会让所有没写这个字段的配置悄悄变成最严格模式。
	StrictClock bool
	// Now 注入时钟；nil 用 time.Now。
	Now func() time.Time
	// MaxLifetime 限制 exp-iat；0 表示不校验。
	// 有些校内 IdP 把 token 签成 24 小时，泄露后可用窗口太长，
	// 这里给运营者一个「比 IdP 更严」的口子。
	MaxLifetime time.Duration
	// RequiredScopes 是 OIDC scope claim 必须包含的项（可选，空表示不校验）。
	RequiredScopes []string
}

func (v ValidateClaims) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v ValidateClaims) audiences() []string {
	out := make([]string, 0, 1+len(v.ExtraAudiences))
	if v.Audience != "" {
		out = append(out, v.Audience)
	}
	out = append(out, v.ExtraAudiences...)
	return out
}

// Validate 执行 iss/aud/exp/nbf/iat 的时效校验（手册 §3.B「claims TTL 和失效」）。
//
// 边界一律按「now 到达 exp 即失效」判定。混用开闭区间会让正好卡在过期点的请求
// 在不同机器上结论不同 —— 这类一秒级的不一致最难查，回放对不上时没人会怀疑到边界。
func (v ValidateClaims) Validate(c Claims) error {
	now := v.now()
	skew := normalizeSkew(v.Skew, v.StrictClock)

	if v.Issuer == "" {
		return fmt.Errorf("%w: 未配置期望的 issuer", ErrConfig)
	}
	if c.Issuer == "" {
		return fmt.Errorf("%w: token 未携带 iss", ErrIssuerMismatch)
	}
	if c.Issuer != v.Issuer {
		return fmt.Errorf("%w: 期望 %q 实际 %q", ErrIssuerMismatch, v.Issuer, c.Issuer)
	}

	accepted := v.audiences()
	if len(accepted) == 0 {
		return fmt.Errorf("%w: 未配置期望的 audience", ErrConfig)
	}
	if len(c.Audience) == 0 {
		return fmt.Errorf("%w: token 未携带 aud", ErrAudienceMismatch)
	}
	hasMatch := false
	for _, want := range accepted {
		for _, got := range c.Audience {
			if want == got {
				hasMatch = true
			}
		}
	}
	if !hasMatch {
		return fmt.Errorf("%w: token 的 aud 与本服务的 client 标识无交集", ErrAudienceMismatch)
	}
	// aud 含多值时，这个 token 很可能是签给同 IdP 下别的 client 的（横向越权方向）。
	// OIDC 要求接受多值 aud 必须显式，这里默认从严。
	if len(c.Audience) > 1 && !v.AllowMultiAudience {
		return fmt.Errorf("%w: aud 含 %d 个值且未显式允许（默认拒绝签给其它 client 的 token）",
			ErrAudienceMismatch, len(c.Audience))
	}

	if len(v.RequiredScopes) > 0 {
		granted := strings.Fields(stringClaim(c.Extra, "scope"))
		for _, want := range v.RequiredScopes {
			if !containsString(granted, want) {
				return fmt.Errorf("%w: scope claim 缺少 %q", ErrAudienceMismatch, want)
			}
		}
	}

	if !c.HasExpiry {
		return fmt.Errorf("%w: 身份层要求 token 必带 exp（角色会随人事变动回收，无期限身份等于永久授权）", ErrExpiryMissing)
	}
	if !now.Before(c.Expiry.Add(skew)) {
		return fmt.Errorf("%w: 过期点 %s，判定时刻 %s", ErrExpired,
			c.Expiry.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if !c.NotBefore.IsZero() && now.Add(skew).Before(c.NotBefore) {
		return fmt.Errorf("%w: nbf %s，判定时刻 %s", ErrNotYetValid,
			c.NotBefore.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if !c.IssuedAt.IsZero() {
		// iat 落在「now + 容忍度」之后才算未来：签发方与本机的时钟不可能完全同步，
		// 拿 now 直接比会把刚签出来的 token 全判成伪造。
		if now.Add(skew).Before(c.IssuedAt) {
			return fmt.Errorf("%w: iat %s 晚于判定时刻（签发方时钟异常或伪造）", ErrIssuedInFuture,
				c.IssuedAt.UTC().Format(time.RFC3339))
		}
		if v.MaxLifetime > 0 {
			lifetime := c.Expiry.Sub(c.IssuedAt)
			if lifetime > v.MaxLifetime+skew {
				return fmt.Errorf("%w: %s 超过上限 %s", ErrLifetimeTooLong, lifetime, v.MaxLifetime)
			}
		}
	}
	return nil
}

// normalizeSkew 把「未设置」（0）解释成默认容忍度。
//
// 想要真正不容偏移必须用 WithStrictClock()，不能靠传 0：0 同时是零值，
// 所有没写这个字段的配置都会跟着变成最严格模式，升级当天就是全员登录失败。
// strict 为真时一律 0，忽略 Skew —— 显式意图优先于数值配置。
func normalizeSkew(d time.Duration, strict bool) time.Duration {
	if strict {
		return 0
	}
	if d == 0 {
		return DefaultClockSkew
	}
	if d < 0 {
		return 0
	}
	return d
}

// numericDateToTime 把 NumericDate（秒，可带小数）转成 UTC 时间。
func numericDateToTime(v any) (time.Time, bool) {
	switch typed := v.(type) {
	case json.Number:
		sec, nsec, ok := parseNumericDate(typed.String())
		if !ok {
			return time.Time{}, false
		}
		return secondsToTime(sec, nsec)
	case int64:
		return secondsToTime(typed, 0)
	case int:
		return secondsToTime(int64(typed), 0)
	default:
		return time.Time{}, false
	}
}

func secondsToTime(sec int64, nsec int32) (time.Time, bool) {
	if sec < minNumericDate || sec > maxNumericDate {
		return time.Time{}, false
	}
	return time.Unix(sec, int64(nsec)).UTC(), true
}

// parseNumericDate 手工拆整数与小数部分，避免 float64 在 10 位秒值上丢精度。
func parseNumericDate(s string) (sec int64, nsec int32, ok bool) {
	if s == "" {
		return 0, 0, false
	}
	intPart, fracPart := s, ""
	dots := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			dots++
			if dots == 1 {
				intPart, fracPart = s[:i], s[i+1:]
			}
		}
	}
	if dots > 1 {
		return 0, 0, false
	}
	whole, err := strconv.ParseInt(intPart, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	nano := int64(0)
	if fracPart != "" {
		if len(fracPart) > 9 {
			fracPart = fracPart[:9]
		}
		n, err := strconv.ParseInt(fracPart, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		for i := len(fracPart); i < 9; i++ {
			n *= 10
		}
		nano = n
	}
	return whole, int32(nano), true
}

// Payload 把 Claims 序列化成 JWT payload。
//
// 标准字段一律从强类型字段写，而不是从 Extra 里捞：FakeAuthority 与测试夹具构造的
// Claims 只有强类型是可信来源，Extra 里残留的旧值会静默覆盖签发意图
// （典型翻车：改了 Expiry 忘了改 Extra["exp"]，测出来的是「过期时间没生效」的假象）。
// Extra 里与标准字段同名的键会被忽略。
func (c Claims) Payload() ([]byte, error) {
	standard := map[string]any{}
	if c.Issuer != "" {
		standard["iss"] = c.Issuer
	}
	if c.Subject != "" {
		standard["sub"] = c.Subject
	}
	switch len(c.Audience) {
	case 0:
	case 1:
		standard["aud"] = c.Audience[0]
	default:
		standard["aud"] = append([]string(nil), c.Audience...)
	}
	if c.HasExpiry && !c.Expiry.IsZero() {
		standard["exp"] = c.Expiry.Unix()
	}
	if !c.NotBefore.IsZero() {
		standard["nbf"] = c.NotBefore.Unix()
	}
	if !c.IssuedAt.IsZero() {
		standard["iat"] = c.IssuedAt.Unix()
	}
	if c.JWTID != "" {
		standard["jti"] = c.JWTID
	}
	doc := make(map[string]any, len(c.Extra)+len(standard))
	for k, v := range c.Extra {
		if _, isStandard := standardKeySet[k]; isStandard {
			continue
		}
		doc[k] = v
	}
	for k, v := range standard {
		doc[k] = v
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: claims 序列化失败: %v", ErrInternal, err)
	}
	return out, nil
}

var standardKeySet = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true,
}

// Clone 返回深 copies 的 Claims，供签发方在不改调用方数据的前提下补默认值。
// 目前只用于测试夹具，生产解析路径不做复制（解析出来的 map 本来就是新建的）。
func (c Claims) Clone() Claims {
	out := c
	out.Audience = append([]string(nil), c.Audience...)
	out.Extra = cloneClaimTree(c.Extra)
	return out
}

func cloneClaimTree(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch typed := v.(type) {
		case map[string]any:
			out[k] = cloneClaimTree(typed)
		case []any:
			items := make([]any, len(typed))
			for i, item := range typed {
				if nested, ok := item.(map[string]any); ok {
					items[i] = cloneClaimTree(nested)
				} else {
					items[i] = item
				}
			}
			out[k] = items
		default:
			out[k] = v
		}
	}
	return out
}

// mapDepth 计算 claims 的嵌套层数，用于挡住深嵌套 payload。
func mapDepth(m map[string]any, depth int) int {
	max := depth
	for _, v := range m {
		child, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if d := mapDepth(child, depth+1); d > max {
			max = d
		}
	}
	return max
}

func stringClaim(extra map[string]any, key string) string {
	if extra == nil {
		return ""
	}
	if s, ok := extra[key].(string); ok {
		return s
	}
	return ""
}

func containsString(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "bool"
	case json.Number:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// plainReason 只给错误类别词，不带原始错误文本。
//
// encoding/json 的报错会把出处的字节片段写进 message，而 payload 里就是 claims 原文；
// 直接 %v 上去等于把 claims 送进 HTTP 响应和审计。
func plainReason(err error) string {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return "type"
	}
	var synErr *json.SyntaxError
	if errors.As(err, &synErr) {
		return "syntax"
	}
	return "invalid"
}
