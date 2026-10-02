package processor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"
)

// 本文件是三个 JSON 类处理器共用的受限工具集。
//
// 为什么不用第三方库、也不图省事用 map[string]any：
//   - 任务边界要求零新增依赖；
//   - json.Number 保留数字字面量，改写字符串字段后重新序列化不会把
//     1e309、超长整数或 1.0 这类形态悄悄改成别的值（现网 forwarder 的
//     rewriteModelBody 用 json.RawMessage 也是同一个理由）。

// decodeJSON 解析任意 JSON 值，数字保留字面量。
func decodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	// 尾部还有内容就不是一个完整 JSON 文档。放过去会让「正文 + 垃圾」被当成合法输入，
	// 于是重新序列化时静默丢掉尾部字节 —— 那是数据损坏，不是清洗。
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errIsEOF(err) {
		return nil, fmt.Errorf("JSON 文档尾部有多余内容")
	}
	return v, nil
}

func errIsEOF(err error) bool { return err == io.EOF }

// encodeJSON 序列化回字节。
//
// 已知副作用：对象键会被按字典序重排（Go 的 map 序列化行为）。JSON 语义不依赖键顺序，
// 上游与客户端都不该因此改变行为；如果以后要逐字节保序，得换 tokenizer 级改写，
// 那是独立的工作量，这里显式记录而不是假装没有。
func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// 不转义 <>&：脱敏占位符要原样可见，默认转义会把 "<masked:" 变成 "<masked:"，
	// 让审计与人工核对都难以判断正文里到底有没有替换痕迹。
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// isJSONDocument 粗判正文是否 JSON（只做首字节探测，真正的判定交给解析）。
// 探测本身不算「读取正文内容」吗？算 —— 但它只碰第一个非空白字节，
// 而且调用点全在已获授权（CanReadBody）之后。
func isJSONDocument(data []byte) bool {
	for _, c := range data {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return true
		}
		return false
	}
	return false
}

// stringMapper 是叶子字符串的改写函数：返回新值、是否变化、以及错误。
// 错误一路往上抛，调用方绝不带着半成品正文继续走。
type stringMapper func(path string, value string) (string, bool, error)

// rewriteStrings 递归遍历 JSON 值，对每个**字符串叶子**调用 mapper。
//
// 只改值不改键：键是协议字段名，改它等于破坏请求。
// depth 超过 MaxDocDepth 直接报错 —— 递归没有上限时，一个精心构造的深层嵌套
// 会让网关栈溢出，那是可远程触发的崩溃（比拒绝服务更糟的是它在解析阶段就发生）。
func rewriteStrings(value any, path string, depth int, mapper stringMapper) (any, int, error) {
	if depth > MaxDocDepth {
		return nil, 0, Errorf(ErrDepthTooDeep, "JSON 嵌套深度超过上限 %d", MaxDocDepth)
	}
	switch typed := value.(type) {
	case string:
		next, changed, err := mapper(path, typed)
		if err != nil {
			return nil, 0, err
		}
		if !changed {
			return typed, 0, nil
		}
		return next, 1, nil
	case map[string]any:
		total := 0
		for key, item := range typed {
			sub, changed, err := rewriteStrings(item, joinPath(path, key), depth+1, mapper)
			if err != nil {
				return nil, 0, err
			}
			if changed > 0 {
				typed[key] = sub
				total += changed
			}
		}
		return typed, total, nil
	case []any:
		total := 0
		for i, item := range typed {
			sub, changed, err := rewriteStrings(item, fmt.Sprintf("%s[%d]", path, i), depth+1, mapper)
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

// joinPath 拼出 JSON 路径显示串（messages[0].content 这种形态）。
func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

// sortedCounts 把计数表转成稳定排序的改写元数据（按 key 排序，保证回放一致）。
func sortedCounts(prefix string, counts map[string]int) []Rewrite {
	if len(counts) == 0 {
		return nil
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Rewrite, 0, len(keys))
	for _, k := range keys {
		out = append(out, Rewrite{Kind: kindFor(prefix, k), Count: counts[k]})
	}
	return out
}

// runeLen 按码点计数，与 JSON Schema 的 minLength/maxLength 口径一致。
// 用字节数会让一个中文短语被判成超长，规则写成什么样都拦不住。
func runeLen(s string) int { return utf8.RuneCountInString(s) }
