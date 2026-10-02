package processor

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ReplaceRule 是一条字段替换规则：按 JSON 路径定位字符串，再按正则或映射表替换。
//
// Path 语法（见 parsePath）：`messages.[*].content`、`system`、`messages[0].role`。
type ReplaceRule struct {
	Name        string            `json:"name"`
	Path        string            `json:"path"`
	Pattern     string            `json:"pattern,omitempty"`
	Replacement string            `json:"replacement,omitempty"`
	Mapping     map[string]string `json:"mapping,omitempty"`
}

// fieldReplace 是内置字段替换处理器（transform-body）。
type fieldReplace struct {
	spec  Spec
	rules []compiledRule
}

// compiledRule 是编译后的规则：路径分段 + 已校验的正则 + 映射表副本。
//
// 正则在构造期编译：请求期 compile 一条正则的成本远高于执行，
// 而且非法正则必须在注册期就炸（同 Spec.Validate 的取舍）。
type compiledRule struct {
	name        string
	path        string
	tokens      []pathToken
	pattern     *regexp.Regexp
	replacement string
	mapping     map[string]string
}

func newFieldReplace(spec Spec, cfg *Config) (Processor, error) {
	p := &fieldReplace{spec: spec}
	var rules []ReplaceRule
	maxDepth := DefaultMaxPathDepth
	if cfg != nil {
		rules = cfg.Rules
		if cfg.MaxPathDepth > 0 {
			maxDepth = cfg.MaxPathDepth
		}
	}
	if maxDepth > AbsoluteMaxPathDepth {
		return nil, Errorf(ErrConfigInvalid, "%s: max_path_depth %d 超过绝对上限 %d",
			spec.Name, maxDepth, AbsoluteMaxPathDepth)
	}
	if len(rules) == 0 {
		return nil, Errorf(ErrConfigInvalid, "%s: 字段替换至少需要一条规则", spec.Name)
	}
	if len(rules) > MaxReplaceRules {
		return nil, Errorf(ErrTooManyRules, "%s: 规则 %d 条，超过上限 %d", spec.Name, len(rules), MaxReplaceRules)
	}
	p.rules = make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		compiled, err := compileRule(rule, maxDepth)
		if err != nil {
			return nil, Errorf(ErrConfigInvalid, "%s: %v", spec.Name, err)
		}
		p.rules = append(p.rules, compiled)
	}
	return p, nil
}

// compileRule 校验并编译单条规则。
func compileRule(rule ReplaceRule, maxDepth int) (compiledRule, error) {
	name := rule.Name
	if name == "" {
		name = sanitizeShortCode(rule.Path)
	}
	if !safeIdentifier(name) {
		return compiledRule{}, fmt.Errorf("规则名 %q 不是安全标识符", rule.Name)
	}
	tokens, err := parsePath(rule.Path, maxDepth)
	if err != nil {
		return compiledRule{}, err
	}
	if rule.Pattern == "" && len(rule.Mapping) == 0 {
		return compiledRule{}, fmt.Errorf("规则 %s 既没有 pattern 也没有 mapping", name)
	}
	out := compiledRule{name: name, path: rule.Path, tokens: tokens, replacement: rule.Replacement}
	if len(rule.Pattern) > MaxPatternLen {
		return compiledRule{}, fmt.Errorf("规则 %s 的模式长度 %d 超过上限 %d", name, len(rule.Pattern), MaxPatternLen)
	}
	if rule.Pattern != "" {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return compiledRule{}, fmt.Errorf("规则 %s 的正则不合法: %v", name, err)
		}
		out.pattern = re
	}
	if len(rule.Mapping) > 0 {
		if len(rule.Mapping) > MaxMappingPerRule {
			return compiledRule{}, fmt.Errorf("规则 %s 的映射表 %d 项，超过上限 %d", name, len(rule.Mapping), MaxMappingPerRule)
		}
		out.mapping = make(map[string]string, len(rule.Mapping))
		for k, v := range rule.Mapping {
			// 键长度受限：映射表是「精确值替换」，一个几千字的键说明配置写错了，
			// 而错配的映射表在请求期会被当成正常规则执行。
			if len(k) == 0 || len(k) > MaxKeywordLen || len(v) > MaxKeywordLen {
				return compiledRule{}, fmt.Errorf("规则 %s 的映射项长度不合法（键长 %d，值长 %d，上限 %d）",
					name, len(k), len(v), MaxKeywordLen)
			}
			out.mapping[k] = v
		}
	}
	return out, nil
}

// pathToken 是路径的一段：对象键、任意键通配、数组下标、数组通配。
type pathToken struct {
	key      string
	kind     pathTokenKind
	index    int
	ruleName string
}

type pathTokenKind int

const (
	tokenKey pathTokenKind = iota
	tokenAnyKey
	tokenIndex
	tokenAnyIndex
)

// parsePath 解析路径语法并限制深度。
//
// 深度必须有上限：路径是运营者写的配置，但「messages.[*].*...*content」这种
// 200 段的规则会让每条请求做 200 层递归匹配，而匹配本身是**指数级回溯**风险的载体。
func parsePath(path string, maxDepth int) ([]pathToken, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("路径不能为空")
	}
	if len(path) > 512 {
		return nil, fmt.Errorf("路径长度 %d 超过上限 512", len(path))
	}
	var tokens []pathToken
	for _, seg := range strings.Split(path, ".") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			return nil, fmt.Errorf("路径 %q 含空的段（多余的点）", path)
		}
		// 段内可以有多个下标：choices[0][1].text
		for len(seg) > 0 {
			if seg[0] == '[' {
				closing := strings.IndexByte(seg, ']')
				if closing < 0 {
					return nil, fmt.Errorf("路径 %q 的下标没有闭合", path)
				}
				inner := seg[1:closing]
				seg = seg[closing+1:]
				if inner == "*" {
					tokens = append(tokens, pathToken{kind: tokenAnyIndex})
					continue
				}
				idx, err := parseIndex(inner)
				if err != nil {
					return nil, fmt.Errorf("路径 %q: %v", path, err)
				}
				tokens = append(tokens, pathToken{kind: tokenIndex, index: idx})
				continue
			}
			next := strings.IndexByte(seg, '[')
			name := seg
			if next >= 0 {
				name = seg[:next]
				seg = seg[next:]
			} else {
				seg = ""
			}
			if name == "" {
				return nil, fmt.Errorf("路径 %q 含空的名字段", path)
			}
			if name == "*" {
				tokens = append(tokens, pathToken{kind: tokenAnyKey})
				continue
			}
			if strings.ContainsAny(name, "*[]") {
				return nil, fmt.Errorf("路径 %q 的段 %q 含非法字符（通配只许写成整段 *）", path, name)
			}
			tokens = append(tokens, pathToken{kind: tokenKey, key: name})
		}
		if len(tokens) > maxDepth {
			return nil, fmt.Errorf("路径 %q 深度 %d 超过上限 %d", path, len(tokens), maxDepth)
		}
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("路径 %q 解析后为空", path)
	}
	return tokens, nil
}

func parseIndex(raw string) (int, error) {
	if raw == "" || raw == "-" {
		return 0, fmt.Errorf("下标 %q 不合法", raw)
	}
	idx := 0
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("下标 %q 只能是十进制非负整数或 *", raw)
		}
		idx = idx*10 + int(c-'0')
		if idx > 1<<20 {
			return 0, fmt.Errorf("下标 %q 过大", raw)
		}
	}
	return idx, nil
}

func (f *fieldReplace) Spec() Spec { return f.spec }

// Process 按规则替换字段值。产出一定是新正文（没有命中时返回 unchanged）。
func (f *fieldReplace) Process(ctx context.Context, in *Input) (*Output, error) {
	if err := ctx.Err(); err != nil {
		return nil, Errorf(ErrTimeout, "%s: %v", f.spec.Name, err)
	}
	data, err := in.Body()
	if err != nil {
		return nil, err
	}
	if !isJSONDocument(data) {
		// 字段替换的语义依赖 JSON 路径，非 JSON 正文只能整体拒绝：
		// 把它当纯文本整块替换会静默改掉客户端的提示词结构。
		return nil, Errorf(ErrInvalidJSON, "%s: 正文不是 JSON 对象/数组，无法按路径替换", f.spec.Name)
	}
	value, derr := decodeJSON(data)
	if derr != nil {
		return nil, Errorf(ErrInvalidJSON, "%s: 解析 JSON 失败: %v", f.spec.Name, derr)
	}
	counts := make(map[string]int, len(f.rules))
	rewritten, total, werr := f.rewriteValue(value, nil, 0, counts)
	if werr != nil {
		return nil, werr
	}
	if total == 0 {
		return &Output{Reason: ReasonOK}, nil
	}
	encoded, eerr := encodeJSON(rewritten)
	if eerr != nil {
		return nil, Errorf(ErrProcessFailed, "%s: 重新序列化失败: %v", f.spec.Name, eerr)
	}
	if int64(len(encoded)) > f.spec.MaxOutputBytes {
		return nil, Errorf(ErrOutputTooLarge, "%s 替换后 %d 字节，超过 max_output_bytes %d",
			f.spec.Name, len(encoded), f.spec.MaxOutputBytes)
	}
	return &Output{
		Body:     encoded,
		Rewrites: sortedCounts("field:", counts),
		Reason:   ReasonOK,
	}, nil
}

// applyRule 在 value 上按 tokens 定位并改写命中的字符串叶子。
//
// 遍历是一次性的、按实例结构走，路径匹配靠**已走过的步**与规则 token 对齐：
// 每条规则各自递归会把复杂度变成 O(规则数 × 节点数)，而一次遍历是 O(节点数 × 规则数)
// 但共享遍历成本 —— 差别在于深文档 + 多规则时后者不会放大成拒绝服务面。
func (f *fieldReplace) rewriteValue(value any, steps []observedStep, depth int, counts map[string]int) (any, int, error) {
	// 不点名任何规则：嵌套超限是**这份请求正文**的形状问题，跟规则路径无关（遍历本身不看规则）。
	// 带上规则名会把管理员引去改规则表，而真实原因是请求体，改了也没用。
	if depth > MaxDocDepth {
		return nil, 0, Errorf(ErrDepthTooDeep, "请求正文的 JSON 嵌套超过上限 %d，字段替换不在超限文档上定位路径", MaxDocDepth)
	}
	switch typed := value.(type) {
	case string:
		total := 0
		current := typed
		for i := range f.rules {
			rule := f.rules[i]
			if !matchTokens(rule.tokens, steps) {
				continue
			}
			next, changed := rule.applyTo(current)
			if !changed {
				continue
			}
			current = next
			counts[rule.name]++
			total++
		}
		return current, total, nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for k := range typed {
			keys = append(keys, k)
		}
		sort.Strings(keys) // 只为可复现的计数顺序；命中集合与遍历顺序无关
		total := 0
		for _, k := range keys {
			sub, changed, err := f.rewriteValue(typed[k], append(steps, observedStep{key: k}), depth+1, counts)
			if err != nil {
				return nil, 0, err
			}
			if changed > 0 {
				typed[k] = sub
				total += changed
			}
		}
		return typed, total, nil
	case []any:
		total := 0
		for i := range typed {
			sub, changed, err := f.rewriteValue(typed[i], append(steps, observedStep{index: i, isIndex: true}), depth+1, counts)
			if err != nil {
				return nil, 0, err
			}
			if changed > 0 {
				typed[i] = sub
				total += changed
			}
		}
		return typed, total, nil
	}
	return value, 0, nil
}

// observedStep 是遍历已走的一步（对象键或数组下标）。
type observedStep struct {
	key     string
	index   int
	isIndex bool
}

// matchTokens 报告规则的 token 序列是否与走过的路径完全对齐。
func matchTokens(tokens []pathToken, steps []observedStep) bool {
	if len(tokens) != len(steps) {
		return false
	}
	for i := range tokens {
		switch tokens[i].kind {
		case tokenKey:
			if steps[i].isIndex || steps[i].key != tokens[i].key {
				return false
			}
		case tokenAnyKey:
			if steps[i].isIndex {
				return false
			}
		case tokenIndex:
			if !steps[i].isIndex || steps[i].index != tokens[i].index {
				return false
			}
		case tokenAnyIndex:
			if !steps[i].isIndex {
				return false
			}
		}
	}
	return true
}

// applyTo 对单个字符串套用映射或正则。
func (r compiledRule) applyTo(s string) (string, bool) {
	if r.mapping != nil {
		if next, ok := r.mapping[s]; ok {
			return next, true
		}
	}
	if r.pattern != nil && r.pattern.MatchString(s) {
		return r.pattern.ReplaceAllString(s, r.replacement), true
	}
	return s, false
}
