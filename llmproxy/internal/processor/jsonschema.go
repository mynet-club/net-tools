package processor

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 本文件是一个**受限子集**的 JSON Schema 验证器，自己实现而不引入第三方库（任务边界：
// 零新增依赖）。支持的关键字集合是封闭的，见 supportedSchemaKeywords。
//
// 最重要的一条设计决定：遇到不认识的关键字一律返回 ErrSchemaUnsupported，
// **绝不静默通过**。静默通过的后果是「策略作者以为校验了 minItems，实际没校验」，
// 那是把合规声明变成空气。未覆盖的关键字逐条列在 knownKeywordsUnsupported。

// 支持的关键字。
const (
	kwType          = "type"
	kwRequired      = "required"
	kwEnum          = "enum"
	kwConst         = "const"
	kwPattern       = "pattern"
	kwMinLength     = "minLength"
	kwMaxLength     = "maxLength"
	kwMinimum       = "minimum"
	kwMaximum       = "maximum"
	kwItems         = "items"
	kwProperties    = "properties"
	kwAddPropsFalse = "additionalProperties"
)

var supportedSchemaKeywords = map[string]bool{
	kwType: true, kwRequired: true, kwEnum: true, kwConst: true,
	kwPattern: true, kwMinLength: true, kwMaxLength: true,
	kwMinimum: true, kwMaximum: true, kwItems: true,
	kwProperties: true, kwAddPropsFalse: true,
}

// knownKeywordsUnsupported 是**已知未覆盖**的 Draft-07 关键字清单（TODO）。
// 每一项都会在编译期被拒绝，列在这里是为了让「为什么拒绝」可查，
// 也方便主线按需扩充时逐条打勾。
//
// TODO(E-followup) 按优先级建议补：minItems/maxItems/uniqueItems（数组约束，
// 结果过滤与请求校验都常用）、anyOf/oneOf/allOf/not（组合语义，多策略并存时需要）、
// format（日期/邮箱校验，注意它需要额外语义）、dependencies/if-then-else、
// propertyNames、patternProperties、exclusiveMinimum/exclusiveMaximum、
// multipleOf、nullable、$ref/definitions（引用会让校验不再是纯函数，要谨慎）、
// $defs、title/description（纯注解类，可以直接忽略但必须显式声明为「允许且忽略」）。
var knownKeywordsUnsupported = []string{
	"format", "minItems", "maxItems", "uniqueItems", "contains",
	"patternProperties", "propertyNames", "dependentSchemas", "dependentRequired",
	"allOf", "anyOf", "oneOf", "not", "if", "then", "else",
	"exclusiveMinimum", "exclusiveMaximum", "multipleOf",
	"$ref", "$defs", "definitions", "nullable", "contentEncoding", "contentMediaType",
	"title", "description", "default", "examples", "readOnly", "writeOnly", "$id", "$schema",
}

// schemaNode 是编译后的 schema 节点。
type schemaNode struct {
	types        []string
	hasTypes     bool
	required     []string
	enum         []string // 规范化后的 JSON 字面量，用于精确比较
	hasEnum      bool
	constValue   string
	hasConst     bool
	pattern      *regexp.Regexp
	minLength    *int
	maxLength    *int
	minimum      *float64
	maximum      *float64
	items        *schemaNode
	properties   map[string]*schemaNode
	noExtraProps bool
	path         string // 编译期位置，只用于错误信息（不含实例内容）
}

type schemaValidator struct {
	spec   Spec
	root   *schemaNode
	target schemaTarget
}

// schemaTarget 决定校验的是元数据还是请求正文。
//
// 这一档划分正是 §2.9「按输入来源定档」的落点：校验元数据时处理器完全可以
// metadata-only（一个字节都不碰正文）；校验请求正文就必须是 inspect-body。
// 用错档位会被 Validate 期拒绝，而不是请求期静默降级。
type schemaTarget int

const (
	targetMetadata schemaTarget = iota
	targetBody
)

func newSchemaValidator(spec Spec, cfg *Config) (Processor, error) {
	p := &schemaValidator{spec: spec, target: targetBody}
	if cfg == nil || len(cfg.Schema) == 0 {
		return nil, Errorf(ErrConfigInvalid, "%s: 缺少 schema", spec.Name)
	}
	root, err := compileSchema(cfg.Schema, "")
	if err != nil {
		return nil, Errorf(ErrConfigInvalid, "%s: %v", spec.Name, err)
	}
	p.root = root
	if spec.BodyAccess == policy.BodyMetadataOnly {
		p.target = targetMetadata
	}
	return p, nil
}

func (v *schemaValidator) Spec() Spec { return v.spec }

// Process 校验一次。错误信息只含路径与关键字，绝不含实例值：
// enum/const 的取值可能就是被校验的敏感内容本身。
func (v *schemaValidator) Process(ctx context.Context, in *Input) (*Output, error) {
	if err := ctx.Err(); err != nil {
		return nil, Errorf(ErrTimeout, "%s: %v", v.spec.Name, err)
	}
	var data []byte
	switch v.target {
	case targetMetadata:
		if len(in.Metadata) == 0 {
			return nil, Errorf(ErrNoBody, "%s: 档位为 metadata-only 但本次没有元数据文档可校验", v.spec.Name)
		}
		// metadata-only 走这条路，**永远不会**调用 in.Body()。
		data = in.Metadata
	case targetBody:
		body, err := in.Body()
		if err != nil {
			return nil, err
		}
		data = body
	}
	value, derr := decodeJSON(data)
	if derr != nil {
		return nil, Errorf(ErrInvalidJSON, "%s: 待校验文档不是合法 JSON: %v", v.spec.Name, derr)
	}
	if err := v.root.validate(value, "$"); err != nil {
		return nil, err
	}
	return &Output{
		Reason:   ReasonOK,
		Rewrites: []Rewrite{{Kind: kindFor("schema:", "valid"), Count: 1}},
	}, nil
}

// compileSchema 递归编译并校验关键字集合。
func compileSchema(raw json.RawMessage, path string) (*schemaNode, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: schema 必须是对象: %v", path, err)
	}
	node := &schemaNode{path: path}

	// 按键排序遍历：报错信息必须与 map 遍历顺序无关，否则同一条非法 schema
	// 每次启动报的关键字不一样，运维无法按报错做告警聚合。
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !supportedSchemaKeywords[key] {
			unsupported := key
			for _, known := range knownKeywordsUnsupported {
				if known == key {
					unsupported = key + "（已知未实现）"
					break
				}
			}
			return nil, Errorf(ErrSchemaUnsupported, "%s 关键字 %s 不在受限子集内（可用：%s）",
				path, unsupported, strings.Join(supportedKeywordList(), "、"))
		}
	}

	if raw, ok := doc[kwType]; ok {
		types, err := parseSchemaTypes(raw, path)
		if err != nil {
			return nil, err
		}
		node.types, node.hasTypes = types, true
	}
	if raw, ok := doc[kwRequired]; ok {
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("%s.%s: 必须是字符串数组", path, kwRequired)
		}
		node.required = list
	}
	if raw, ok := doc[kwEnum]; ok {
		var list []any
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("%s.%s: 解析失败: %v", path, kwEnum, err)
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("%s.%s: 不能是空数组", path, kwEnum)
		}
		node.hasEnum = true
		for _, item := range list {
			node.enum = append(node.enum, canonicalJSON(item))
		}
	}
	if raw, ok := doc[kwConst]; ok {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("%s.%s: 解析失败: %v", path, kwConst, err)
		}
		node.hasConst = true
		node.constValue = canonicalJSON(v)
	}
	if raw, ok := doc[kwPattern]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("%s.%s: 必须是字符串", path, kwPattern)
		}
		if len(s) > MaxPatternLen {
			return nil, fmt.Errorf("%s.%s: 模式长度 %d 超过上限 %d", path, kwPattern, len(s), MaxPatternLen)
		}
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: 正则不合法: %v", path, kwPattern, err)
		}
		node.pattern = re
	}
	if n, err := parseNonNegativeInt(doc, kwMinLength, path); err != nil {
		return nil, err
	} else if n >= 0 {
		node.minLength = &n
	}
	if n, err := parseNonNegativeInt(doc, kwMaxLength, path); err != nil {
		return nil, err
	} else if n >= 0 {
		node.maxLength = &n
	}
	if f, err := parseNumberBound(doc, kwMinimum, path); err != nil {
		return nil, err
	} else if f != nil {
		node.minimum = f
	}
	if f, err := parseNumberBound(doc, kwMaximum, path); err != nil {
		return nil, err
	} else if f != nil {
		node.maximum = f
	}
	if raw, ok := doc[kwItems]; ok {
		// 元组形式（items 为数组）不在子集内：它要求位置化校验与 minItems 配套，
		// 半实现比不实现更危险。这里显式拒绝。
		var asArray []json.RawMessage
		if err := json.Unmarshal(raw, &asArray); err == nil {
			return nil, Errorf(ErrSchemaUnsupported, "%s.%s: 只支持单一 schema 形式，元组形式不在受限子集内", path, kwItems)
		}
		sub, err := compileSchema(raw, path+"."+kwItems)
		if err != nil {
			return nil, err
		}
		node.items = sub
	}
	if raw, ok := doc[kwProperties]; ok {
		var props map[string]json.RawMessage
		if err := json.Unmarshal(raw, &props); err != nil {
			return nil, fmt.Errorf("%s.%s: 必须是对象", path, kwProperties)
		}
		node.properties = make(map[string]*schemaNode, len(props))
		for _, name := range sortedKeys(props) {
			sub, err := compileSchema(props[name], path+"."+kwProperties+"."+name)
			if err != nil {
				return nil, err
			}
			node.properties[name] = sub
		}
	}
	if raw, ok := doc[kwAddPropsFalse]; ok {
		var allow bool
		if err := json.Unmarshal(raw, &allow); err != nil {
			// additionalProperties 接 schema 时是「对额外属性再校验」，本子集不实现。
			return nil, Errorf(ErrSchemaUnsupported, "%s.%s: 只支持布尔 false，其余形式不在受限子集内", path, kwAddPropsFalse)
		}
		if allow {
			// 显式 true 与不写等价，接受但不产生约束。
			node.noExtraProps = false
		} else {
			node.noExtraProps = true
		}
	}
	return node, nil
}

func supportedKeywordList() []string {
	out := make([]string, 0, len(supportedSchemaKeywords))
	for k := range supportedSchemaKeywords {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// parseSchemaTypes 解析 type（字符串或字符串数组），取值集合封闭。
func parseSchemaTypes(raw json.RawMessage, path string) ([]string, error) {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if !isSchemaType(single) {
			return nil, fmt.Errorf("%s.%s: 未知的类型 %q", path, kwType, single)
		}
		return []string{single}, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("%s.%s: 必须是字符串或字符串数组", path, kwType)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%s.%s: 类型列表不能为空", path, kwType)
	}
	for _, t := range list {
		if !isSchemaType(t) {
			return nil, fmt.Errorf("%s.%s: 未知的类型 %q", path, kwType, t)
		}
	}
	return list, nil
}

// schemaTypes 是子集承认的类型名。integer 单独一档（不只按 number 判），
// 因为「必须是整数」是常见约束，回落成 number 会让 1.5 通过。
var schemaTypes = []string{"object", "array", "string", "number", "integer", "boolean", "null"}

func isSchemaType(t string) bool {
	for _, item := range schemaTypes {
		if item == t {
			return true
		}
	}
	return false
}

func parseNonNegativeInt(doc map[string]json.RawMessage, key, path string) (int, error) {
	raw, ok := doc[key]
	if !ok {
		return -1, nil
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return -1, fmt.Errorf("%s.%s: 必须是非负整数", path, key)
	}
	i, err := strconv.Atoi(n.String())
	if err != nil || i < 0 {
		return -1, fmt.Errorf("%s.%s: 必须是非负整数，当前 %s", path, key, n.String())
	}
	return i, nil
}

func parseNumberBound(doc map[string]json.RawMessage, key, path string) (*float64, error) {
	raw, ok := doc[key]
	if !ok {
		return nil, nil
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return nil, fmt.Errorf("%s.%s: 必须是数字", path, key)
	}
	f, err := n.Float64()
	if err != nil {
		return nil, fmt.Errorf("%s.%s: 数字解析失败: %v", path, key, err)
	}
	return &f, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// canonicalJSON 把值规范化成可比较的字面量。
//
// 数字统一走 float64 的最短表示，避免 enum 里写 1、实例里是 1.0 时被判成两个取值；
// 字符串/布尔/null/容器直接用 JSON 字面量，键顺序由 Go 的 map 序列化固定为字典序，
// 因此同值必同串（比较语义是「值相等」而不是「字节相等」）。
func canonicalJSON(v any) string {
	switch typed := v.(type) {
	case json.Number:
		f, err := typed.Float64()
		if err != nil {
			return typed.String()
		}
		return strconv.FormatFloat(f, 'g', -1, 64)
	case float64:
		return strconv.FormatFloat(typed, 'g', -1, 64)
	}
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(data)
}

// validate 校验一个实例值。err 里只出现路径与关键字。
func (n *schemaNode) validate(value any, path string) error {
	if n.hasTypes {
		matched := false
		for _, t := range n.types {
			if typeMatches(t, value) {
				matched = true
				break
			}
		}
		if !matched {
			return Errorf(ErrSchemaViolation, "%s: 类型不符合 %v", path, n.types)
		}
	}
	if n.hasEnum {
		got := canonicalJSON(value)
		found := false
		for _, want := range n.enum {
			if want == got {
				found = true
				break
			}
		}
		if !found {
			return Errorf(ErrSchemaViolation, "%s: 取值不在 enum 允许的 %d 个值内", path, len(n.enum))
		}
	}
	if n.hasConst && canonicalJSON(value) != n.constValue {
		return Errorf(ErrSchemaViolation, "%s: 取值不等于 const 声明", path)
	}
	switch typed := value.(type) {
	case string:
		if n.pattern != nil && !n.pattern.MatchString(typed) {
			return Errorf(ErrSchemaViolation, "%s: 字符串不匹配 pattern", path)
		}
		length := runeLen(typed)
		if n.minLength != nil && length < *n.minLength {
			return Errorf(ErrSchemaViolation, "%s: 长度 %d 小于 minLength %d", path, length, *n.minLength)
		}
		if n.maxLength != nil && length > *n.maxLength {
			return Errorf(ErrSchemaViolation, "%s: 长度 %d 超过 maxLength %d", path, length, *n.maxLength)
		}
	case json.Number:
		f, err := typed.Float64()
		if err != nil {
			return Errorf(ErrSchemaViolation, "%s: 数值无法解析", path)
		}
		if n.minimum != nil && f < *n.minimum {
			return Errorf(ErrSchemaViolation, "%s: 数值小于 minimum", path)
		}
		if n.maximum != nil && f > *n.maximum {
			return Errorf(ErrSchemaViolation, "%s: 数值大于 maximum", path)
		}
	case map[string]any:
		for _, name := range n.required {
			if _, ok := typed[name]; !ok {
				return Errorf(ErrSchemaViolation, "%s: 缺少必需属性 %q", path, name)
			}
		}
		for _, key := range sortedKeys(typed) {
			sub, ok := n.properties[key]
			if !ok {
				if n.noExtraProps {
					return Errorf(ErrSchemaViolation, "%s: 含未声明的属性 %q（additionalProperties:false）", path, key)
				}
				continue
			}
			if err := sub.validate(typed[key], path+"."+key); err != nil {
				return err
			}
		}
	case []any:
		if n.items != nil {
			for i, item := range typed {
				if err := n.items.validate(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// typeMatches 按子集的类型语义判定实例。
func typeMatches(want string, value any) bool {
	switch typed := value.(type) {
	case nil:
		return want == "null"
	case string:
		return want == "string"
	case bool:
		return want == "boolean"
	case map[string]any:
		return want == "object"
	case []any:
		return want == "array"
	case json.Number:
		switch want {
		case "number":
			return true
		case "integer":
			// 整数字面量才算 integer：1.0 在 JSON 里通常是浮点语义，
			// 这里按字面量判（含小数点或指数就不算），与 Draft 的「值为整数」一致但可解释。
			return isIntegerLiteral(typed.String())
		}
		return false
	}
	return false
}

func isIntegerLiteral(raw string) bool {
	return !strings.ContainsAny(raw, ".eE")
}
