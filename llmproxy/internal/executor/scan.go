package executor

import (
	"bytes"
	"encoding/json"
	"io"
)

// scanMode 是旁路观测器的方言。三种方言的语义全部抽自现网
// internal/server/forwarder.go 的 usageScanner（:887-1034）与 usageInfo/cacheSplit
// （:28-97）—— 刻意「抽取」而不是「重新发明」：SSE 的行切分、64KiB 防御性截尾、
// usage 只在含 `"usage"` 字样的帧上才 Unmarshal、content 用轻量字节扫描计数，
// 这些都是现网跑出来的口径，重发明一次就等于引入第二份可能不一致的计量语义。
type scanMode int

const (
	scanNone scanMode = iota
	// scanOpenAISSE：逐行找 `data:` 前缀，[DONE] 为收尾，usage 在帧内。
	scanOpenAISSE
	// scanOpenAIJSON：整体一个 JSON 对象（非流式 OpenAI 兼容响应）。
	scanOpenAIJSON
	// scanOllamaNDJSON：每行一个完整 JSON 对象；done:true 收尾，
	// prompt_eval_count/eval_count 只在收尾行出现（Ollama 原生 /api/chat）。
	// 非流式响应是单行 JSON，同一个模式即可覆盖两种形态，不必为它另设缓冲。
	scanOllamaNDJSON
)

// modeFor 依据协议与流式标志选方言。执行器与 fake 共用这一个函数，
// 「怎么扫」只有一处真相。
func modeFor(p Protocol, isStream bool) scanMode {
	switch p {
	case ProtocolOpenAIChat:
		if isStream {
			return scanOpenAISSE
		}
		return scanOpenAIJSON
	case ProtocolOllamaNative:
		return scanOllamaNDJSON
	}
	return scanNone
}

// Usage 观测的落点。observer 只持有数字与布尔，任何时候都不保留正文字节
// （行缓冲处理完即弃，见 feed 的语义）。
type observer struct {
	mode scanMode

	lineBuf []byte // SSE/NDJSON 的半行缓冲；处理完立即前移丢弃
	jsonBuf []byte // scanOpenAIJSON 的完整缓冲（响应体已被 MaxResponseBytes 限界）

	usage     Usage
	hasUsage  bool
	sawDone   bool
	truncated bool // 内部缓冲被防御性截尾：帧太大，观测可能不全（只影响解释，不改透传字节）

	contentLen int
}

func newObserver(mode scanMode) *observer {
	if mode == scanNone {
		return nil
	}
	return &observer{mode: mode}
}

// 缓冲区防御参数，语义同 usageScanner.Write :911-919。
const (
	// maxLineBuffer 是无换行半行的保留上限：一条超长「行」说明对端根本不是
	// 行协议，继续吞只会白占内存（usage 总在流末尾，砍掉中间不损失观测目标）。
	maxLineBuffer = 64 * 1024
	// keepTailOnOverflow 是越限后保留的尾部字节数。
	keepTailOnOverflow = 4096
)

// feed 吃进一块**透传给下游的同一批字节**，只观测、不修改、不另存。
func (ob *observer) feed(p []byte) {
	if ob == nil || len(p) == 0 {
		return
	}
	switch ob.mode {
	case scanOpenAIJSON:
		// 非流式整体 JSON：先攒着（体积已被响应读取器限界，这里只是二道防御），
		// finish 时一次解析。口径同 usageScanner.consumeJSON :957-986。
		ob.jsonBuf = append(ob.jsonBuf, p...)
		if len(ob.jsonBuf) > maxObservationBuffer {
			ob.jsonBuf = ob.jsonBuf[:maxObservationBuffer]
			ob.truncated = true
		}
	default:
		ob.feedLines(p)
	}
}

// maxObservationBuffer 是给整体 JSON 观测缓冲的独立上限。
// 响应体上限管「透传多少」，这个管「为解析攒多少」：usage 字段前后的正文
// 没有观测价值，攒够上限后丢弃其余（截尾只可能让 usage 读不到，绝不会读错）。
const maxObservationBuffer = 512 * 1024

// feedLines 按行切分并逐行处置，处理完的字节立即丢弃 —— 「只处理完整的
// data: 行；处理完立即丢弃，不累积全文」（forwarder.go :910 注释的原始语义）。
func (ob *observer) feedLines(p []byte) {
	ob.lineBuf = append(ob.lineBuf, p...)
	for {
		i := bytes.IndexByte(ob.lineBuf, '\n')
		if i < 0 {
			if len(ob.lineBuf) > maxLineBuffer {
				// 防御：与现网同款——异常增长的半行只保留尾部。
				rest := make([]byte, keepTailOnOverflow)
				copy(rest, ob.lineBuf[len(ob.lineBuf)-keepTailOnOverflow:])
				ob.lineBuf = rest
				ob.truncated = true
			}
			return
		}
		line := ob.lineBuf[:i]
		ob.lineBuf = ob.lineBuf[i+1:]
		ob.noteLine(line)
	}
}

// finish 收尾：冲掉没有换行符的尾行、解析攒下的整体 JSON，并释放缓冲。
func (ob *observer) finish() {
	if ob == nil {
		return
	}
	switch ob.mode {
	case scanOpenAIJSON:
		if len(ob.jsonBuf) > 0 {
			ob.noteWholeJSON(ob.jsonBuf)
		}
		ob.jsonBuf = nil
	default:
		if len(ob.lineBuf) > 0 {
			ob.noteLine(ob.lineBuf)
			ob.lineBuf = nil
		}
	}
}

// observation 产出对外观测。注意：正文不在返回值的任何字段里。
func (ob *observer) observation() Observation {
	if ob == nil {
		return Observation{}
	}
	return Observation{
		Usage:        ob.usage,
		HasUsage:     ob.hasUsage,
		SawDone:      ob.sawDone,
		ContentBytes: ob.contentLen,
	}
}

// ------------------------------------------------------------------ 方言实现

// noteLine 处置一行完整输入（SSE 与 NDJSON 共用入口，方言在前缀判断处分岔）。
func (ob *observer) noteLine(line []byte) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return
	}
	switch ob.mode {
	case scanOllamaNDJSON:
		ob.noteOllamaChunk(trimmed)
	default:
		ob.noteSSEData(trimmed)
	}
}

// noteSSEData 是 OpenAI SSE 的一帧：语义逐条对应 usageScanner.Write :911-953。
func (ob *observer) noteSSEData(trimmed []byte) {
	if bytes.Contains(trimmed, []byte("[DONE]")) {
		ob.sawDone = true
	}
	if !bytes.HasPrefix(trimmed, []byte("data:")) {
		return
	}
	data := bytes.TrimSpace(trimmed[5:])
	ob.noteContent(data)
	if !bytes.Contains(data, []byte(`"usage"`)) {
		// 与现网同一道短路：usage 出现在流的末尾几帧，为每一帧 Unmarshal
		// 不值得；扫描「有没有说话」用字节计数就够了。
		return
	}
	var chunk struct {
		Usage *usageWire `json:"usage"`
	}
	if err := json.Unmarshal(data, &chunk); err != nil || chunk.Usage == nil {
		return
	}
	ob.mergeUsage(chunk.Usage)
}

// noteWholeJSON 处理非流式整体响应（consumeJSON :957-986 的同语义：
// 先量 content，再找 usage）。
func (ob *observer) noteWholeJSON(data []byte) {
	if !looksLikeJSONObject(data) {
		return
	}
	ob.noteContent(data)
	var obj struct {
		Usage *usageWire `json:"usage"`
	}
	if err := json.Unmarshal(data, &obj); err != nil || obj.Usage == nil {
		return
	}
	ob.mergeUsage(obj.Usage)
}

// looksLikeJSONObject 是一个宽容探测：整体 JSON 解析得动且是对象。
// 解析不动多半是中间设备插了 HTML —— 观测器不报错（透传的字节不改），
// 协议形态的判断留给调用方看 StatusCode/Content-Type。
func looksLikeJSONObject(data []byte) bool {
	var keys map[string]json.RawMessage
	return json.Unmarshal(data, &keys) == nil
}

// noteOllamaChunk 处理 Ollama 原生协议的一行。
//
// 与 OpenAI 的形态差异集中在这里收敛：
//   - content 在 message.content（对象嵌套）而不是 choices[0].delta.content ——
//     noteContent 的字节扫描只认 `"content":"`，两种嵌套都能量，不需要方言分叉；
//   - 收尾是 {"done":true} 而不是 data: [DONE]；
//   - 用量不在 usage 对象里，而是收尾行平铺的 prompt_eval_count / eval_count。
func (ob *observer) noteOllamaChunk(line []byte) {
	ob.noteContent(line)
	var chunk ollamaUsageLine
	if err := json.Unmarshal(line, &chunk); err != nil {
		return
	}
	if chunk.Done {
		ob.sawDone = true
		// 收尾行是 Ollama 用量的唯一落点，直接整体落账（不存在多帧合并问题）。
		ob.usage = usageFromOllamaLine(chunk)
		ob.hasUsage = true
	}
}

// noteContent 从一帧里量 content 字符串的字节数并累加：
// 轻量字符串扫描版，逐字对应 forwarder.go noteContent :996-1031 ——
// 只认 `"content":"..."` 形态、跳过转义、单帧最多扫 256KiB。
// 注释里的原始理由同样成立：量个长度而已，不值得为它把每帧 Unmarshal 一遍。
func (ob *observer) noteContent(data []byte) {
	if len(data) == 0 {
		return
	}
	const maxScan = 256 << 10
	scan := data
	if len(scan) > maxScan {
		scan = scan[:maxScan]
	}
	key := []byte(`"content":"`)
	rest := scan
	for {
		i := bytes.Index(rest, key)
		if i < 0 {
			return
		}
		rest = rest[i+len(key):]
		for j := 0; j < len(rest); j++ {
			c := rest[j]
			if c == '\\' {
				j++
				continue
			}
			if c == '"' {
				ob.contentLen += j
				rest = rest[j+1:]
				break
			}
		}
	}
}

// ------------------------------------------------------------------ usage 归一化

// usageWire 覆盖两套上游 usage 方言的字段形状，结构逐字对应
// forwarder.go usageInfo :28-45（DeepSeek 显式 hit/miss 与 OpenAI
// prompt_tokens_details.cached_tokens 两套字段）。
type usageWire struct {
	PromptTokens     *int64 `json:"prompt_tokens"`
	CompletionTokens *int64 `json:"completion_tokens"`
	TotalTokens      *int64 `json:"total_tokens"`
	// DeepSeek 等：输入里命中/未命中缓存的两档，单价差很远，计费必须区分。
	PromptCacheHitTokens  *int64 `json:"prompt_cache_hit_tokens"`
	PromptCacheMissTokens *int64 `json:"prompt_cache_miss_tokens"`
	// OpenAI/Azure 及兼容实现：cached_tokens 是命中部分，未命中要从
	// prompt_tokens 里减出来；cache_write_tokens 是第三档。
	PromptTokensDetails *struct {
		CachedTokens     *int64 `json:"cached_tokens"`
		CacheWriteTokens *int64 `json:"cache_write_tokens"`
	} `json:"prompt_tokens_details"`
}

// mergeUsage 把一帧 usage 并进观测。指针字段只在非 nil 时覆盖（后到的
// 权威帧赢），与 usageScanner :941-952 的合并语义一致。
func (ob *observer) mergeUsage(u *usageWire) {
	if u.PromptTokens != nil {
		v := *u.PromptTokens
		ob.usage.PromptTokens = &v
	}
	if u.CompletionTokens != nil {
		v := *u.CompletionTokens
		ob.usage.CompletionTokens = &v
	}
	if u.TotalTokens != nil {
		v := *u.TotalTokens
		ob.usage.TotalTokens = &v
	}
	if c := cacheSplit(u); c.ok {
		ob.usage.HasCache = true
		ob.usage.CacheHit = c.hit
		ob.usage.CacheMiss = c.miss
		ob.usage.CacheWrite = c.write
	}
	ob.hasUsage = true
}

// cacheSplit 把两套字段归一化成三档，翻译自 forwarder.go cacheSplit :55-97。
// 负数夹 0、cached 大于 prompt 时夹到 prompt —— 原注释的理由（「上游报的数字
// 不可全信」）原样成立，这里不重复发明。
func cacheSplit(u *usageWire) usageCache {
	if u == nil {
		return usageCache{}
	}
	clamp := func(v int64) int64 {
		if v < 0 {
			return 0
		}
		return v
	}
	var write int64
	if u.PromptTokensDetails != nil && u.PromptTokensDetails.CacheWriteTokens != nil {
		write = clamp(*u.PromptTokensDetails.CacheWriteTokens)
	}
	if u.PromptCacheHitTokens != nil || u.PromptCacheMissTokens != nil {
		c := usageCache{write: write, ok: true}
		if u.PromptCacheHitTokens != nil {
			c.hit = clamp(*u.PromptCacheHitTokens)
		}
		if u.PromptCacheMissTokens != nil {
			c.miss = clamp(*u.PromptCacheMissTokens)
		}
		return c
	}
	if u.PromptTokensDetails != nil && u.PromptTokensDetails.CachedTokens != nil && u.PromptTokens != nil {
		c := usageCache{write: write, ok: true}
		c.hit = clamp(*u.PromptTokensDetails.CachedTokens)
		if c.hit > *u.PromptTokens {
			c.hit = *u.PromptTokens
		}
		c.miss = *u.PromptTokens - c.hit - write
		if c.miss < 0 {
			c.miss = 0
		}
		return c
	}
	return usageCache{}
}

type usageCache struct {
	hit   int64
	write int64
	miss  int64
	ok    bool
}

// ------------------------------------------------------------------ 透传读取器

// scanReader 把「原样透传」与「旁路观测」「体积执法」缝在一个 io.ReadCloser 上：
// 上层（接线层，通常是 flushWriter）每次 Read 到的字节与上游吐出的字节逐一相同；
// 观测器吃的是同一批字节的**引用**，只数数、不留存。
//
// 为什么不缓冲全量再扫描：§2.9 第 7 条 —— 未启用正文处理时继续流式透传，
// 不能为了统一接口把请求缓存在内存里。首字延迟（TTFT）也是用户可感的指标，
// 缓冲全量等于把它杀死。
type scanReader struct {
	src      io.ReadCloser
	ob       *observer
	limit    int64
	seen     int64
	fin      bool // observer 已收尾（幂等保护）
	limitErr bool // 越限已发生：之后的 Read 恒返回截断错误
}

func newScanReader(src io.ReadCloser, ob *observer, limit int64) *scanReader {
	return &scanReader{src: src, ob: ob, limit: limit}
}

func (r *scanReader) Read(p []byte) (int, error) {
	if r.limitErr {
		return 0, newError(ReasonBodyTooLarge, "", "响应体读取已因体积上限截断", ErrBodyLimit)
	}
	budget := r.limit - r.seen
	if budget <= 0 {
		r.limitErr = true
		return 0, newError(ReasonBodyTooLarge, "", "响应体达到 Attempt.MaxResponseBytes 上限", ErrBodyLimit)
	}
	if int64(len(p)) > budget {
		// 收缩本次读窗而不是直接报错：让下游先完整拿到限额内的最后一块字节，
		// 越限信号留在下一次 Read。透传保真度优先。
		p = p[:budget]
	}
	n, err := r.src.Read(p)
	if n > 0 {
		r.seen += int64(n)
		r.ob.feed(p[:n])
	}
	if err == io.EOF {
		r.finish()
	}
	if err == nil && r.seen >= r.limit {
		// 恰好读满限额且对端还活着：下一次 Read 才报截断 —— 这里如果直接报
		// EOF，「读满限额」与「干净收尾」就分不开了。
		return n, nil
	}
	return n, err
}

// Close 关闭底层流并保证观测收尾（没读到 EOF 就 Close 也算收尾，
// 调用方拿到的 SawDone 如实反映「没见收尾标记」）。
func (r *scanReader) Close() error {
	err := r.src.Close()
	r.finish()
	return err
}

func (r *scanReader) finish() {
	if r.fin {
		return
	}
	r.fin = true
	r.ob.finish()
}

// 接口自检：编译期钉住 scanReader 的契约形状。
var (
	_ io.ReadCloser = (*scanReader)(nil)
	_ error         = (*ExecutionError)(nil)
)
