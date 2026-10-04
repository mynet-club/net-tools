package config

// 两张声明表的编辑层（§3.H 的写侧地基，与 editpolicy.go 同一条底线）。
//
// 为什么走 spliceSection 而不是整体 marshal：那份文件里的注释是维护信息（谁在什么时候
// 为什么把这个处理器挂在哪个范围上），整体重排会把它们全抹掉。段**内部**的注释会被
// 重渲染掉，所以调用方一律先备份。
//
// 为什么 Raw 也要跑一遍领域校验：控制台的编辑基线必须是「当前磁盘上那份真的能用」。
// 只解结构不校验的话，一个手改坏的字段（比如把 phase 写成 before-upstram）会原样
// 回到界面上，界面再把它写回磁盘 —— 一次保存就把错误固化成了「配置里就是这么写的」。

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/mynet-club/net-tools/llmproxy/internal/knowledge"
)

// 段内合法键名：未知键即报错，与 policyKnownKeys 同一取舍。
//
// 漏一个键名的后果是「新加的键在控制台路径上被误报成未知键」，
// 那比静默丢掉一个安全字段（body_access、fail_closed）早暴露得多。
var (
	processorKeys = []string{"name", "type", "phase", "scope", "timeout_ms", "max_input_bytes", "max_output_bytes", "fail_closed", "body_access", "allow_raw_body", "allowed_endpoints", "version"}
	// return_raw_body / delivery_endpoint 必须在这里登记：漏掉一个键名，控制台的读侧
	// 会把「已经能写的正文开关」报成未知键，而写侧会静默丢掉它（等于把开关关掉）。
	knowledgeSourceKeys = []string{"name", "endpoint", "knowledge_bases", "timeout_ms", "max_response_bytes", "return_raw_body", "delivery_endpoint"}
)

const (
	processorsSectionComment = "  # 本段是处理器的声明表（阶段/档位/上限/失败策略/出网白名单）；\n" +
		"  # 运行参数在同级 processor_params/<声明名>.json（kb-context-inject 只需可选的预算键），\n" +
		"  # HTTP 客户端、正文交付器与两道授权判定器由网关注入，都不在这里。\n"
	knowledgeSectionComment = "  # 本段是知识检索的委托入口；transport 由接线方从出网策略注入，凭证不进 URL。\n" +
		"  # 正文交付（return_raw_body）默认关；打开必须同时写独立的 delivery_endpoint，\n" +
		"  # 且逐篇仍要管理员的 knowledge.content 授权与源侧再判定，三道锁缺一道都不交正文。\n"
)

// RawProcessors 从配置文件**原文**读出 processors 段并逐条过领域校验。
//
// 段不存在时返回空切片而不是报错：还没启用 3.0 的部署根本没有这一段，
// 「第一次声明处理器」与「改已有声明」必须走同一个接口。
func RawProcessors(src []byte) ([]ProcessorDef, error) {
	val, err := sectionNode(src, "processors")
	if err != nil || val == nil || sectionIsNull(val) {
		return nil, err
	}
	list, err := sequenceItems(val, "processors", processorKeys)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}
	var out []ProcessorDef
	if err := val.Decode(&out); err != nil {
		return nil, fmt.Errorf("processors 段形态不对（每条需要 name/type/phase/… 这些键）: %w", err)
	}
	// 与加载期同一条约束（逐条过领域校验 + 名字唯一）：编辑层要能在**整份配置还没
	// 拼好**的时候就把错误指出来，否则界面上的基线本身可能就是一条装配不过的声明。
	probe := Config{Processors: out}
	if err := probe.normalizeProcessors(); err != nil {
		return nil, err
	}
	return out, nil
}

// EditProcessors 把 src 里的 processors 段替换成 list，返回新的文件内容。
//
// 空列表是合法值：撤掉全部声明（回到「没有任何处理器参与」）必须能一次做完，
// 否则「先删一个再改一个」的两步中间态会留在磁盘上。
func EditProcessors(src []byte, list []ProcessorDef) ([]byte, error) {
	probe := Config{Processors: list}
	if err := probe.normalizeProcessors(); err != nil {
		return nil, err
	}
	rendered, err := renderProcessors(list)
	if err != nil {
		return nil, err
	}
	return spliceSection(src, "processors", rendered)
}

// RawKnowledgeSources 从配置文件**原文**读出 knowledge_sources 段。
func RawKnowledgeSources(src []byte) ([]KnowledgeSourceDef, error) {
	val, err := sectionNode(src, "knowledge_sources")
	if err != nil || val == nil || sectionIsNull(val) {
		return nil, err
	}
	list, err := sequenceItems(val, "knowledge_sources", knowledgeSourceKeys)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}
	var out []KnowledgeSourceDef
	if err := val.Decode(&out); err != nil {
		return nil, fmt.Errorf("knowledge_sources 段形态不对（每条需要 name/endpoint/knowledge_bases/…）: %w", err)
	}
	// 与加载期同一套跨条约束（名字唯一、库不重叠）：这里单独判一遍，
	// 因为编辑层要能在**整份配置还没拼好**的时候就把错误指出来。
	probe := Config{KnowledgeSources: out}
	if err := probe.normalizeKnowledgeSources(); err != nil {
		return nil, err
	}
	return out, nil
}

// EditKnowledgeSources 把 src 里的 knowledge_sources 段替换成 list。
func EditKnowledgeSources(src []byte, list []KnowledgeSourceDef) ([]byte, error) {
	probe := Config{KnowledgeSources: list}
	if err := probe.normalizeKnowledgeSources(); err != nil {
		return nil, err
	}
	rendered, err := renderKnowledgeSources(list)
	if err != nil {
		return nil, err
	}
	return spliceSection(src, "knowledge_sources", rendered)
}

// sectionNode 取顶层某个段的值节点；段不存在返回 (nil, nil)。
func sectionNode(src []byte, key string) (*yaml.Node, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(src, &root); err != nil {
		return nil, fmt.Errorf("原配置解析失败: %w", err)
	}
	_, val := findTopLevelKey(&root, key)
	return val, nil
}

// sectionIsNull 报告段的值节点是否等价于「没有声明」。
//
// 只写了 key（`processors:`）在 YAML 里是 null 值，与 `processors: []` 同义：
// 清空一段的写回形态就是它，手写的「先占个位、还没填」也长这样。
// 把它当列表错误拒掉，运维会遇到「界面上清空之后再也读不回来」。
func sectionIsNull(val *yaml.Node) bool {
	return val.Kind == yaml.ScalarNode && (val.Tag == "!!null" || strings.TrimSpace(val.Value) == "")
}

// sequenceItems 核对一个列表段的形态与每条项的键名（未知键即拒）。
//
// 只查键名、不取值：类型与必填项交给结构体解码与领域校验，两处各管一段，
// 免得这里再抄一份「哪个字段是什么类型」。
func sequenceItems(val *yaml.Node, key string, allowed []string) ([]*yaml.Node, error) {
	switch val.Kind {
	case yaml.SequenceNode:
	default:
		return nil, fmt.Errorf("%s 段要是列表，当前是 %s", key, nodeKindName(val.Kind))
	}
	for i, item := range val.Content {
		if item.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s 第 %d 条不是映射（每条要写成 name: … 这样的键值对）", key, i+1)
		}
		for j := 0; j+1 < len(item.Content); j += 2 {
			name := item.Content[j].Value
			if !containsString(allowed, name) {
				return nil, fmt.Errorf("%s 第 %d 条有未知键 %q（可用：%s）",
					key, i+1, name, strings.Join(allowed, "、"))
			}
		}
	}
	return val.Content, nil
}

func nodeKindName(k yaml.Kind) string {
	switch k {
	case yaml.MappingNode:
		return "映射"
	case yaml.ScalarNode:
		return "标量"
	}
	return fmt.Sprintf("节点种类 %d", k)
}

// renderProcessors 渲染 processors 段正文（每行已带两格缩进）。
//
// 字段顺序固定：name → type → phase → scope → version → body_access → fail_closed →
// timeout_ms → 两个字节上限 → allow_raw_body → allowed_endpoints。
// 同一个意图在任何机器上写出同一份文本，diff 才有意义（与 renderPolicy 同一条理由）。
// allow_raw_body 与 allowed_endpoints 只在为真/非空时写：默认形态就是最严形态
// （不带原文、不出网），把它们摊成 `false` / `[]` 只会让真正的那一条被淹没。
func renderProcessors(list []ProcessorDef) ([]byte, error) {
	// 空列表只留下 key 那行与说明注释：spliceSection 已经输出了「processors:」，
	// 正文里再写一遍 `processors: []` 就成了重复的顶层键（YAML 直接拒）。
	// 「key 挂着、值为空」与「[]」在这两段里是同一个意思，读回来都走 sectionIsNull。
	var b bytes.Buffer
	b.WriteString(processorsSectionComment)
	if len(list) == 0 {
		return b.Bytes(), nil
	}
	for _, d := range list {
		spec, err := d.Spec()
		if err != nil {
			return nil, err
		}
		fields := [][2]string{
			{"name", spec.Name}, {"type", spec.Type}, {"phase", string(spec.Phase)},
			{"scope", spec.Scope}, {"version", spec.Version},
			{"body_access", string(spec.BodyAccess)},
		}
		for i, kv := range fields {
			v, err := yamlScalar(kv[1])
			if err != nil {
				return nil, fmt.Errorf("处理器 %s 的 %s %w", spec.Name, kv[0], err)
			}
			indent := "      "
			if i == 0 {
				indent = "    - "
			}
			fmt.Fprintf(&b, "%s%s: %s\n", indent, kv[0], v)
		}
		fmt.Fprintf(&b, "      fail_closed: %v\n", spec.FailClosed)
		fmt.Fprintf(&b, "      timeout_ms: %d\n      max_input_bytes: %d\n      max_output_bytes: %d\n",
			spec.Timeout.Milliseconds(), spec.MaxInputBytes, spec.MaxOutputBytes)
		if spec.AllowRawBody {
			b.WriteString("      allow_raw_body: true\n")
		}
		if len(spec.AllowedEndpoints) > 0 {
			b.WriteString("      allowed_endpoints:\n")
			for _, ep := range spec.AllowedEndpoints {
				v, err := yamlScalar(ep)
				if err != nil {
					return nil, fmt.Errorf("处理器 %s 的 allowed_endpoints %w", spec.Name, err)
				}
				fmt.Fprintf(&b, "        - %s\n", v)
			}
		}
	}
	return b.Bytes(), nil
}

// renderKnowledgeSources 渲染 knowledge_sources 段正文。
func renderKnowledgeSources(list []KnowledgeSourceDef) ([]byte, error) {
	// 空列表的渲染规则与 renderProcessors 一致：只留 key 行与说明注释。
	var b bytes.Buffer
	b.WriteString(knowledgeSectionComment)
	if len(list) == 0 {
		return b.Bytes(), nil
	}
	for _, d := range list {
		// 写进文件的是**归一化后的**端点（validateEndpoint 做空白清理与尾部 ? 修剪）。
		// 原样回显未归一化的串会让文件里那份和运行时真正使用的那份不是同一个字符串，
		// 而审计比对、回放和「这条委托打到了哪」都按那个字符串认。
		endpoint, err := knowledge.ValidateEndpoint(d.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("知识源 %s 的 endpoint %w", d.Name, err)
		}
		name, err := yamlScalar(strings.TrimSpace(d.Name))
		if err != nil {
			return nil, fmt.Errorf("知识源 %s 的 name %w", d.Name, err)
		}
		epVal, err := yamlScalar(endpoint)
		if err != nil {
			return nil, fmt.Errorf("知识源 %s 的 endpoint %w", d.Name, err)
		}
		// 交付入口同样只写归一化后的形态，理由与 endpoint 相同（审计按字符串认入口）。
		// 这里的报错不只是「渲染失败」：EditKnowledgeSources 已经跑过领域校验，
		// 走到这一步还失败说明两个校验点口径不一致，那种不一致必须红着暴露。
		deliveryVal := ""
		if strings.TrimSpace(d.DeliveryEndpoint) != "" {
			dv, err := knowledge.ValidateEndpoint(d.DeliveryEndpoint)
			if err != nil {
				return nil, fmt.Errorf("知识源 %s 的 delivery_endpoint %w", d.Name, err)
			}
			v, err := yamlScalar(dv)
			if err != nil {
				return nil, fmt.Errorf("知识源 %s 的 delivery_endpoint %w", d.Name, err)
			}
			deliveryVal = v
		}
		fmt.Fprintf(&b, "    - name: %s\n      endpoint: %s\n", name, epVal)
		b.WriteString("      knowledge_bases:\n")
		for _, kb := range d.KnowledgeBases {
			v, err := yamlScalar(strings.TrimSpace(kb))
			if err != nil {
				return nil, fmt.Errorf("知识源 %s 的 knowledge_bases %w", d.Name, err)
			}
			fmt.Fprintf(&b, "        - %s\n", v)
		}
		fmt.Fprintf(&b, "      timeout_ms: %d\n      max_response_bytes: %d\n",
			d.TimeoutMs, d.MaxResponseBytes)
		// 正文开关写在段尾，且只在为真/非空时落盘：默认形态就是最严形态
		// （不交正文、没有第二条出网入口），把 `false` 摊在每一条上都一样。
		if d.ReturnRawBody {
			b.WriteString("      return_raw_body: true\n")
		}
		if deliveryVal != "" {
			fmt.Fprintf(&b, "      delivery_endpoint: %s\n", deliveryVal)
		}
	}
	return b.Bytes(), nil
}
