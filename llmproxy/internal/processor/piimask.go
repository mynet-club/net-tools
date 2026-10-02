package processor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

// 内置脱敏类型。新增形态必须同时补测试，否则它只是「看起来会被脱敏」的字符串。
const (
	PIIEmail    = "email"
	PIIIDCard   = "id_card"
	PIIPhone    = "phone"
	PIIBankCard = "bank_card"
)

// piiKinds 是封闭的类型集合（顺序固定，用于校验与稳定输出）。
var piiKinds = []string{PIIEmail, PIIIDCard, PIIPhone, PIIBankCard}

// 已知限制（TODO）：港澳台证件号、统一社会信用代码、IP 地址、MAC 地址、
// 经纬度、姓名（需要分词与词典，风险是把普通词误打码）都不在本子集内。
// 覆盖形态由注册方按组织需要扩，但每加一种都要重新审视误报率与占位稳定性。

// 这些表达式刻意保持保守：宁可漏（下一个处理器还能补）也不要误伤语义，
// 但身份证/手机号这类是「宁可多打码」的方向 —— 判据有歧义时按敏感处理。
var (
	piiEmailRe   = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	piiIDCard18  = regexp.MustCompile(`[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}(?:\d|[Xx])`)
	piiIDCard15  = regexp.MustCompile(`[1-9]\d{5}(?:\d{2})(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}`)
	piiDigitRun  = regexp.MustCompile(`\d+`)
	piiPhoneHead = regexp.MustCompile(`^1[3-9]\d{9}$`)
)

const (
	// 占位符前缀。带尖括号是为了让人一眼看出这是替换值而不是原文，
	// 同时它不含引号与反斜杠，插进 JSON 字符串值里不会破坏语法。
	piiPlaceholderPrefix = "<masked:"
	// piiHashLen 是占位符里摘要的十六进制长度（48 bit）。
	// 同一次请求内碰撞概率可忽略；跨请求不承诺不碰撞，因为默认 salt 每次随机。
	piiHashLen = 12
)

// piiSpan 是一次命中：区间 + 类型 + 原文。
type piiSpan struct {
	start int
	end   int
	kind  string
	value string
	rank  int // 优先级，小者优先
}

// piiKindRank 给出重叠命中的裁决次序。
//
// 必须显式定义：一段 18 位数字同时可能是身份证号和银行卡号，
// 靠 regexp 匹配顺序决定会让「同一份输入两次跑出不同占位符」，
// 那会直接破坏模型上下文连贯性 —— 而这正是稳定占位存在的全部理由。
var piiKindRank = map[string]int{PIIEmail: 0, PIIIDCard: 1, PIIBankCard: 2, PIIPhone: 3}

// piiMask 是内置脱敏处理器（transform-body）。
type piiMask struct {
	spec    Spec
	key     []byte
	enabled map[string]bool
}

func newPIIMask(spec Spec, cfg *Config) (Processor, error) {
	p := &piiMask{spec: spec, enabled: make(map[string]bool, len(piiKinds))}
	for _, kind := range piiKinds {
		p.enabled[kind] = true
	}
	if cfg != nil {
		if len(cfg.PseudonymKey) > 0 {
			// 显式注入的子密钥：用于「同一组织内跨请求稳定占位」的需求。
			// 校验长度是为了挡住把短口令直接当密钥的用法 —— 32 bit 的密钥
			// 可以被穷举出原值，那等于没脱敏。
			if len(cfg.PseudonymKey) < 16 {
				return nil, Errorf(ErrConfigInvalid, "%s: pseudonym key 至少 16 字节，当前 %d", spec.Name, len(cfg.PseudonymKey))
			}
			p.key = append([]byte(nil), cfg.PseudonymKey...)
		}
		if len(cfg.PIITypes) > 0 {
			p.enabled = make(map[string]bool, len(cfg.PIITypes))
			for _, name := range cfg.PIITypes {
				if !isPIIKind(name) {
					return nil, Errorf(ErrConfigInvalid, "%s: 未知脱敏类型 %q（可用：%s）",
						spec.Name, name, strings.Join(piiKinds, "、"))
				}
				p.enabled[name] = true
			}
		}
	}
	return p, nil
}

func isPIIKind(name string) bool {
	for _, k := range piiKinds {
		if k == name {
			return true
		}
	}
	return false
}

func (m *piiMask) Spec() Spec { return m.spec }

// Process 脱敏一次正文。
//
// 请求态（占位表、计数、salt）全部是局部变量：挂在结构体上会让 A 用户的原值
// 与 B 用户的原值共享同一张映射表，那是跨请求泄漏，比竞态更糟。
func (m *piiMask) Process(ctx context.Context, in *Input) (*Output, error) {
	if err := ctx.Err(); err != nil {
		return nil, Errorf(ErrTimeout, "%s: %v", m.spec.Name, err)
	}
	data, err := in.Body()
	if err != nil {
		return nil, err
	}
	// salt：注入了密钥就用注入的；否则每次请求随机。
	// 不用主密钥（Config 的注释解释了为什么），也不固定成常量 ——
	// 固定 salt 让占位符变成可离线穷举的 HMAC 表，等于给身份证号建了字典。
	salt := m.key
	if len(salt) == 0 {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			return nil, Errorf(ErrProcessFailed, "生成假名 salt 失败: %v", err)
		}
		salt = buf
	}
	state := &piiState{
		salt:    salt,
		enabled: m.enabled,
		packed:  make(map[string]string, 16),
		counts:  make(map[string]int, 4),
	}

	out := data
	if isJSONDocument(data) {
		value, derr := decodeJSON(data)
		if derr != nil {
			// 声明是 JSON 但解析不了：这是客户端的输入问题，按 verdict 拒绝，
			// 不能「就当纯文本处理」——那会让一个畸形请求带着原文出网。
			return nil, Errorf(ErrInvalidJSON, "%s: 正文形似 JSON 但解析失败: %v", m.spec.Name, derr)
		}
		rewritten, changed, rerr := rewriteStrings(value, "", 0, func(path string, s string) (string, bool, error) {
			_ = path // 脱敏不区分字段：所有字符串值一视同仁，路径只在字段替换器里才有意义
			return state.maskString(s)
		})
		if rerr != nil {
			return nil, rerr
		}
		if changed == 0 {
			return &Output{Reason: ReasonOK}, nil
		}
		encoded, eerr := encodeJSON(rewritten)
		if eerr != nil {
			return nil, Errorf(ErrProcessFailed, "重新序列化失败: %v", eerr)
		}
		out = encoded
	} else {
		masked, changed, merr := state.maskString(string(data))
		if merr != nil {
			return nil, merr
		}
		if !changed {
			return &Output{Reason: ReasonOK}, nil
		}
		out = []byte(masked)
	}
	if int64(len(out)) > m.spec.MaxOutputBytes {
		return nil, Errorf(ErrOutputTooLarge, "%s 脱敏后 %d 字节，超过 max_output_bytes %d",
			m.spec.Name, len(out), m.spec.MaxOutputBytes)
	}
	return &Output{
		Body:     out,
		Rewrites: sortedCounts(piiKindPrefix, state.counts),
		Reason:   ReasonOK,
	}, nil
}

// piiState 是一次调用内的脱敏状态。
type piiState struct {
	salt    []byte
	enabled map[string]bool
	packed  map[string]string // 原值 → 占位符（同一次请求内稳定）
	counts  map[string]int    // 类型 → 命中处数
}

// maskString 把一个字符串里的敏感形态替换成稳定占位符。
func (st *piiState) maskString(s string) (string, bool, error) {
	spans, has, err := st.findSpans(s)
	if err != nil {
		return s, false, err
	}
	if !has {
		return s, false, nil
	}
	var b strings.Builder
	b.Grow(len(s) + len(spans)*24)
	last := 0
	for _, sp := range spans {
		b.WriteString(s[last:sp.start])
		b.WriteString(st.placeholder(sp))
		last = sp.end
	}
	b.WriteString(s[last:])
	return b.String(), true, nil
}

// findSpans 找出字符串里的敏感区间，重叠时按显式优先级裁决。
// 命中数量超过上限时返回错误：静默放过剩余敏感串比拒绝整次请求更糟。
func (st *piiState) findSpans(s string) ([]piiSpan, bool, error) {
	candidates := make([]piiSpan, 0, 8)

	if st.enabled[PIIEmail] {
		for _, m := range piiEmailRe.FindAllStringSubmatchIndex(s, -1) {
			candidates = append(candidates, piiSpan{start: m[0], end: m[1], kind: PIIEmail, value: s[m[0]:m[1]]})
		}
	}
	if st.enabled[PIIIDCard] {
		for _, re := range []*regexp.Regexp{piiIDCard18, piiIDCard15} {
			for _, m := range re.FindAllStringIndex(s, -1) {
				// 前后不能贴着数字：证件号必须是独立的一段，
				// 否则一个长编号的中间 18 位会被当成身份证号打掉。
				if digitsBefore(s, m[0]) || digitsAfter(s, m[1]) {
					continue
				}
				candidates = append(candidates, piiSpan{start: m[0], end: m[1], kind: PIIIDCard, value: s[m[0]:m[1]]})
			}
		}
	}
	if st.enabled[PIIPhone] || st.enabled[PIIBankCard] {
		// 数字段按**极大段**分类：Go 的 RE2 没有前后断言，用 \d+ 取整段再判长度，
		// 这样 11 位手机号不会从 19 位卡号里被切出来，反之亦然。
		for _, m := range piiDigitRun.FindAllStringIndex(s, -1) {
			run := s[m[0]:m[1]]
			switch {
			case st.enabled[PIIBankCard] && len(run) >= 13 && len(run) <= 19 && luhnValid(run):
				candidates = append(candidates, piiSpan{start: m[0], end: m[1], kind: PIIBankCard, value: run})
			case st.enabled[PIIPhone] && len(run) == 11 && piiPhoneHead.MatchString(run):
				candidates = append(candidates, piiSpan{start: m[0], end: m[1], kind: PIIPhone, value: run})
			}
		}
	}
	if len(candidates) == 0 {
		return nil, false, nil
	}

	for i := range candidates {
		candidates[i].rank = piiKindRank[candidates[i].kind]
	}
	// 起点升序；同起点按优先级、再按长度降序（优先吃掉更长的命中）。
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.start != b.start {
			return a.start < b.start
		}
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		return a.end > b.end
	})

	out := make([]piiSpan, 0, len(candidates))
	end := -1
	for _, sp := range candidates {
		if sp.start < end {
			continue // 与已采纳的命中重叠：低优先级的一方让位
		}
		if len(out) >= MaxPIISpans {
			// 命中多到需要上限时，说明这不是正常文本（或在攻击计数开销）。
			// 报错而不是带半成品出网：截断会漏掉剩余敏感串，那是泄漏不是降级。
			return nil, false, Errorf(ErrTooManyRules, "单串命中数达到上限 %d", MaxPIISpans)
		}
		out = append(out, sp)
		end = sp.end
		st.counts[sp.kind]++
	}
	return out, true, nil
}

// placeholder 返回（并记住）某个原值在本次请求内的占位符。
func (st *piiState) placeholder(sp piiSpan) string {
	key := sp.kind + "\x00" + sp.value
	if cached, ok := st.packed[key]; ok {
		return cached
	}
	ph := st.pseudonym(sp.kind, sp.value)
	st.packed[key] = ph
	return ph
}

// pseudonym = 前缀 + 类型 + keyed-hash 摘要。
// 用 keyed hash（salt 前置）而不是裸 sha256：裸摘要可以被离线穷举反查原值
// —— 身份证号的取值空间小到可以直接遍历，那会让「脱敏后的正文」仍可复原敏感信息。
func (st *piiState) pseudonym(kind, value string) string {
	h := sha256.New()
	h.Write(st.salt)
	h.Write([]byte{0})
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(value))
	sum := h.Sum(nil)
	return piiPlaceholderPrefix + kind + ":" + hex.EncodeToString(sum[:])[:piiHashLen] + ">"
}

func digitsBefore(s string, i int) bool {
	return i > 0 && s[i-1] >= '0' && s[i-1] <= '9'
}

func digitsAfter(s string, i int) bool {
	return i < len(s) && s[i] >= '0' && s[i] <= '9'
}

// luhnValid 是 ISO/IEC 7812 的 Luhn 校验（从右往左奇数位翻倍）。
// 用它把「一串 16 位数字」和真正的卡号区分开，误伤会打断正常内容。
func luhnValid(digits string) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0 && sum > 0
}
