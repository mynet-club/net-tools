package processor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// FilterMode 是结果过滤的动作。
const (
	// FilterRedact 把命中片段替换成占位文本，流式与非流式都可用。
	FilterRedact FilterMode = "redact"
	// FilterBlock 命中即整段拒收。只对已缓冲的响应有意义：
	// 流式已经按块发出去了，「命中后再拦截」在协议上做不到（除非把整段缓存住，
	// 而那正是 §2.9 规则 7 禁止的）。
	FilterBlock FilterMode = "block"
)

// FilterMode 是结果过滤的动作类型。
type FilterMode string

// FilterRule 是一条过滤规则：命名 + 正则 + 关键词表。
type FilterRule struct {
	Name        string   `json:"name"`
	Pattern     string   `json:"pattern,omitempty"`
	Keywords    []string `json:"keywords,omitempty"`
	Replacement string   `json:"replacement,omitempty"`
}

// resultFilter 是内置结果过滤器（after-upstream）。
type resultFilter struct {
	spec        Spec
	rules       []compiledFilter
	mode        FilterMode
	replacement string
	maxLine     int
}

type compiledFilter struct {
	name    string
	pattern *regexp.Regexp
	keyword string
	repl    string
}

func newResultFilter(spec Spec, cfg *Config) (Processor, error) {
	p := &resultFilter{spec: spec, mode: FilterRedact, replacement: "[filtered]", maxLine: DefaultMaxLineBytes}
	if cfg != nil {
		if cfg.FilterMode != "" {
			p.mode = cfg.FilterMode
		}
		if cfg.FilterReplacement != "" {
			p.replacement = cfg.FilterReplacement
		}
		if cfg.MaxLineBytes > 0 {
			p.maxLine = cfg.MaxLineBytes
		}
	}
	if p.maxLine > AbsoluteMaxLineBytes {
		return nil, Errorf(ErrConfigInvalid, "%s: max_line_bytes %d 超过绝对上限 %d", spec.Name, p.maxLine, AbsoluteMaxLineBytes)
	}
	if len(p.replacement) > MaxKeywordLen {
		return nil, Errorf(ErrConfigInvalid, "%s: 替换文本过长（%d > %d）", spec.Name, len(p.replacement), MaxKeywordLen)
	}
	rules := []FilterRule(nil)
	if cfg != nil {
		rules = cfg.FilterRules
	}
	if len(rules) == 0 {
		return nil, Errorf(ErrConfigInvalid, "%s: 结果过滤至少需要一条规则", spec.Name)
	}
	if len(rules) > MaxFilterRules {
		return nil, Errorf(ErrTooManyRules, "%s: 规则 %d 条，超过上限 %d", spec.Name, len(rules), MaxFilterRules)
	}
	p.rules = make([]compiledFilter, 0, len(rules))
	for _, rule := range rules {
		compiled, err := compileFilterRule(rule)
		if err != nil {
			return nil, Errorf(ErrConfigInvalid, "%s: %v", spec.Name, err)
		}
		p.rules = append(p.rules, compiled...)
	}
	if len(p.rules) == 0 {
		return nil, Errorf(ErrConfigInvalid, "%s: 规则表展开后为空", spec.Name)
	}
	return p, nil
}

const MaxFilterRules = 64

// compileFilterRule 把一个声明展开成若干条已编译规则（一条声明可以带多个关键词）。
func compileFilterRule(rule FilterRule) ([]compiledFilter, error) {
	name := rule.Name
	if name == "" {
		name = "rule"
	}
	if !safeIdentifier(name) {
		return nil, errTextf("规则名 %q 不是安全标识符", rule.Name)
	}
	out := make([]compiledFilter, 0, len(rule.Keywords)+1)
	repl := rule.Replacement
	if repl == "" {
		repl = "[filtered]"
	}
	if len(repl) > MaxKeywordLen {
		return nil, errTextf("规则 %s 的替换文本过长", name)
	}
	if rule.Pattern != "" {
		if len(rule.Pattern) > MaxPatternLen {
			return nil, errTextf("规则 %s 的模式长度超过上限 %d", name, MaxPatternLen)
		}
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, errTextf("规则 %s 的正则不合法: %v", name, err)
		}
		out = append(out, compiledFilter{name: name, pattern: re, repl: repl})
	}
	if len(rule.Keywords) > MaxKeywordCount {
		return nil, errTextf("规则 %s 的关键词 %d 个，超过上限 %d", name, len(rule.Keywords), MaxKeywordCount)
	}
	for _, kw := range rule.Keywords {
		if kw == "" {
			return nil, errTextf("规则 %s 含空关键词（空串会命中所有位置）", name)
		}
		if len(kw) > MaxKeywordLen {
			return nil, errTextf("规则 %s 的关键词长度 %d 超过上限 %d", name, len(kw), MaxKeywordLen)
		}
		out = append(out, compiledFilter{name: name, keyword: kw, repl: repl})
	}
	if len(out) == 0 {
		return nil, errTextf("规则 %s 既没有 pattern 也没有 keywords", name)
	}
	return out, nil
}

func errTextf(format string, args ...any) error {
	return &configTextError{msg: fmt.Sprintf(format, args...)}
}

// hits 报告一段文本是否命中本规则（关键词或正则）。
func (c compiledFilter) hits(s string) bool {
	if c.pattern != nil {
		return c.pattern.MatchString(s)
	}
	return c.keyword != "" && strings.Contains(s, c.keyword)
}

// configTextError 让构造期错误统一带上 ErrConfigInvalid 语义。
type configTextError struct{ msg string }

func (e *configTextError) Error() string { return e.msg }
func (e *configTextError) Unwrap() error { return ErrConfigInvalid }

func (f *resultFilter) Spec() Spec { return f.spec }

// Process 处理已缓冲的响应正文。
func (f *resultFilter) Process(ctx context.Context, in *Input) (*Output, error) {
	if err := ctx.Err(); err != nil {
		return nil, Errorf(ErrTimeout, "%s: %v", f.spec.Name, err)
	}
	data, err := in.Body()
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int, len(f.rules))
	blocked := f.anyHit(data)
	if f.mode == FilterBlock {
		if blocked {
			return nil, Errorf(ErrContentBlocked, "%s: 响应命中拦截规则", f.spec.Name)
		}
		return &Output{Reason: ReasonOK}, nil
	}
	out := f.maskBytes(data, counts)
	if int64(len(out)) > f.spec.MaxOutputBytes {
		return nil, Errorf(ErrOutputTooLarge, "%s 过滤后 %d 字节，超过 max_output_bytes %d",
			f.spec.Name, len(out), f.spec.MaxOutputBytes)
	}
	changed := !bytes.Equal(out, data)
	if !changed {
		return &Output{Reason: ReasonOK, Rewrites: sortedCounts("filter:", counts)}, nil
	}
	// inspect-body 档位只统计不替换：产出交给 Pipeline 判为越权，所以这里直接不回 Body。
	if !f.spec.BodyAccess.CanReplaceBody() {
		return &Output{Reason: ReasonOK, Rewrites: sortedCounts("filter:", counts)}, nil
	}
	return &Output{Body: out, Reason: ReasonOK, Rewrites: sortedCounts("filter:", counts)}, nil
}

func (f *resultFilter) anyHit(data []byte) bool {
	for _, rule := range f.rules {
		if rule.hits(string(data)) {
			return true
		}
	}
	return false
}

// maskBytes 按规则替换命中片段。
//
// 档位为 inspect-body 时不产出新正文，因此计数照常做、正文原样返回。
func (f *resultFilter) maskBytes(data []byte, counts map[string]int) []byte {
	if !f.spec.BodyAccess.CanReplaceBody() {
		f.countHits(string(data), counts)
		return data
	}
	current := string(data)
	for _, rule := range f.rules {
		before := counts[rule.name]
		switch {
		case rule.pattern != nil:
			matches := rule.pattern.FindAllStringIndex(current, -1)
			if len(matches) == 0 {
				continue
			}
			counts[rule.name] = before + len(matches)
			current = rule.pattern.ReplaceAllString(current, rule.repl)
		case rule.keyword != "":
			hits := strings.Count(current, rule.keyword)
			if hits == 0 {
				continue
			}
			counts[rule.name] = before + hits
			current = strings.ReplaceAll(current, rule.keyword, rule.repl)
		}
	}
	return []byte(current)
}

func (f *resultFilter) countHits(s string, counts map[string]int) {
	for _, rule := range f.rules {
		if rule.pattern != nil {
			counts[rule.name] += len(rule.pattern.FindAllStringIndex(s, -1))
			continue
		}
		if rule.keyword != "" {
			counts[rule.name] += strings.Count(s, rule.keyword)
		}
	}
}

// ProcessStream 是流式的增量过滤（§2.9 规则 7 的直接要求）。
//
// 内存约束：任何时刻只持有「未完成的当前行 + 一块已过滤待吐出的字节」。
// 高水位通过 streamMaxBuffered() 暴露给测试，所以「没缓存整段」是可断言的事实。
func (f *resultFilter) ProcessStream(ctx context.Context, in *Input, src io.Reader) (io.Reader, error) {
	if f.mode == FilterBlock {
		// 拦截语义要求「在发出任何字节之前判定完成」，流式做不到，显式拒绝而不是
		// 悄悄降级成 redact —— 静默降级会让策略作者以为拦住了。
		return nil, Errorf(ErrStreamUnsupported,
			"%s: block 模式无法增量执行（已发出的字节收不回来），流式响应请改用 redact 模式或走缓冲路径", f.spec.Name)
	}
	if !in.CanReadBody() {
		return nil, Errorf(ErrBodyAccessDenied, "%s 档位为 %s，不能过滤响应流", f.spec.Name, f.spec.BodyAccess)
	}
	if err := ctx.Err(); err != nil {
		return nil, Errorf(ErrTimeout, "%s: %v", f.spec.Name, err)
	}
	counts := make(map[string]int, len(f.rules))
	return &sseFilter{
		src:     src,
		filter:  f,
		counts:  counts,
		maxLine: f.maxLine,
	}, nil
}

// sseFilter 是逐行（SSE 帧）的增量过滤器。
//
// 为什么按行：SSE 的边界就是换行，`data:` 帧不会跨行；按行处理天然把
// 「跨块的部分匹配」问题收敛成「当前未完成的行」，残留量有上限。
type sseFilter struct {
	src     io.Reader
	filter  *resultFilter
	counts  map[string]int
	maxLine int

	carry   []byte // 未完成的当前行
	pending []byte // 已过滤、待交给下游的字节
	high    int    // 内部同时持有的最大字节数（不含交给下游的 pending 的累计量）
	seenEOF bool
}

func (s *sseFilter) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(s.pending) == 0 {
		if s.seenEOF {
			return 0, io.EOF
		}
		chunk := make([]byte, 4096)
		n, err := s.src.Read(chunk)
		if n > 0 {
			s.carry = append(s.carry, chunk[:n]...)
			if err != nil && err != io.EOF {
				// 有数据但读出错：先把数据过滤出去，错误下一轮再报。
			}
			if s.consumeLines() {
				// 单行超长：拒绝整条流，而不是无限攒着。
				return 0, s.finishErr(Errorf(ErrLineTooLarge, "%s: 单行超过流式缓冲上限 %d 字节",
					s.filter.spec.Name, s.maxLine))
			}
		}
		if err != nil {
			s.seenEOF = true
			if err != io.EOF {
				return 0, s.finishErr(err)
			}
			// 收尾：没有换行符结尾的最后一行也要过滤后吐出。
			if len(s.carry) > 0 {
				s.emit(s.carry)
				s.carry = nil
			}
			if len(s.pending) == 0 {
				return 0, io.EOF
			}
		}
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	s.track()
	return n, nil
}

// consumeLines 把 carry 里完整的行交给 emit，返回「是否发现超长行」。
func (s *sseFilter) consumeLines() bool {
	for {
		i := bytes.IndexByte(s.carry, '\n')
		if i < 0 {
			break
		}
		line := s.carry[:i+1]
		s.emit(line)
		s.carry = s.carry[i+1:]
	}
	return len(s.carry) > s.maxLine
}

// emit 过滤一行并把它排进待吐出的队列。
//
// 这里**不能**碰 s.carry：调用方（consumeLines / EOF 收尾）负责推进或清空 carry。
// 若在 emit 里清 carry，consumeLines 的下一轮就从空切片里找下一个换行，
// 同一块里剩下的行会被静默丢掉 —— 丢内容比丢过滤更糟，因为客户端看不出来。
func (s *sseFilter) emit(line []byte) {
	out := s.filter.maskBytes(line, s.counts)
	s.pending = append(s.pending, out...)
	s.track()
}

func (s *sseFilter) track() {
	if used := len(s.carry) + len(s.pending); used > s.high {
		s.high = used
	}
}

func (s *sseFilter) finishErr(err error) error {
	s.seenEOF = true
	return err
}

// streamMaxBuffered 报告本层与内层的高水位最大值。
func (s *sseFilter) streamMaxBuffered() int {
	if inner := maxBufferedOf(s.src); inner > s.high {
		return inner
	}
	return s.high
}

// Counts 返回命中计数（给测试与审计回填用）。
func (s *sseFilter) Counts() []Rewrite { return sortedCounts("filter:", s.counts) }
