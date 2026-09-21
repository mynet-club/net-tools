package config

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// 配置文件的结构化编辑：只替换 providers 段的正文，其余字节一动不动。
//
// 为什么不用「整体 marshal 再写回」：yaml.v3 编码时会丢掉所有注释，
// 而这份文件里的注释是维护信息（比如「海外上游要写 192.168.0.3:7890」）。
// 所以走「解析定位 → 只重渲染目标段 → 按行拼接」这条路：
// 段外的内容（其它配置项、它们的注释、空行、缩进风格）完全保持原样。
//
// 代价说清楚：providers 段**内部**的注释会被重渲染掉（只保留一行段首说明）。
// 所以写回前一律先备份，注释真丢了还能从备份里捞回来。

// providersSectionComment 是重渲染时写进 providers 段的第一行说明。
const providersSectionComment = "  # 本段由控制台或手工编辑维护；写回时只会替换这一段的内容。\n"

// EditProviders 把 src 里的 providers 段替换成 ps，返回新的文件内容。
// src 必须是能解析的 YAML，否则报错（不改动任何东西）。
func EditProviders(src []byte, ps []ProviderRaw) ([]byte, error) {
	if len(ps) == 0 {
		return nil, fmt.Errorf("providers 不能为空：至少保留一个供应商")
	}
	rendered, err := renderProviders(ps)
	if err != nil {
		return nil, err
	}

	var root yaml.Node
	if err := yaml.Unmarshal(src, &root); err != nil {
		return nil, fmt.Errorf("原配置解析失败: %w", err)
	}
	keyNode, valNode := findTopLevelKey(&root, "providers")
	if keyNode == nil {
		// 原文件里没有 providers 段：追加到末尾
		out := append([]byte{}, src...)
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, '\n')
		}
		out = append(out, []byte("\nproviders:\n")...)
		out = append(out, rendered...)
		return out, nil
	}

	lines := strings.SplitAfter(string(src), "\n")
	keyLine := keyNode.Line - 1 // 1-based → 0-based
	if keyLine < 0 || keyLine >= len(lines) {
		return nil, fmt.Errorf("providers 的行号（%d）超出文件范围", keyNode.Line)
	}
	keyIndent := keyNode.Column - 1

	if valNode != nil && valNode.Line-1 == keyLine {
		// 值就在 key 那一行（流式写法，如 providers: []）：连这一行一起替换
		end := sectionEnd(lines, keyLine, keyIndent)
		out := strings.Join(lines[:keyLine], "")
		out += "providers:\n" + string(rendered) + strings.Join(lines[end:], "")
		return []byte(out), nil
	}

	// 常见情形：值从下一行开始的分块写法，只替换正文，key 那行原样留着
	end := sectionEnd(lines, keyLine, keyIndent)
	out := strings.Join(lines[:keyLine+1], "") + string(rendered) + strings.Join(lines[end:], "")
	return []byte(out), nil
}

// sectionEnd 返回 providers 段正文结束的行号（不含）。
//
// 判据：从 keyLine 之后开始，遇到第一个「非空、非注释、缩进不深于 key」的行就结束。
// 这样段后紧跟的注释与空行都会保留下来。
func sectionEnd(lines []string, keyLine, keyIndent int) int {
	for i := keyLine + 1; i < len(lines); i++ {
		raw := strings.TrimRight(lines[i], "\r\n")
		trimmed := strings.TrimLeft(raw, " ")
		if trimmed == "" { // 空行：先跳过，可能还在段内
			continue
		}
		if strings.HasPrefix(trimmed, "#") { // 注释：缩进不深于 key 就归下一段
			if len(raw)-len(trimmed) <= keyIndent {
				return i
			}
			continue
		}
		if len(raw)-len(trimmed) <= keyIndent {
			return i
		}
	}
	return len(lines)
}

// findTopLevelKey 在顶层映射里找指定键，返回（键节点, 值节点）；找不到返回 (nil, nil)。
func findTopLevelKey(root *yaml.Node, name string) (*yaml.Node, *yaml.Node) {
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == name {
			return root.Content[i], root.Content[i+1]
		}
	}
	return nil, nil
}

// renderProviders 渲染 providers 段的正文（每行已带两格缩进）。
//
// 字段顺序写死在这里，为的是输出稳定、可读：name / enabled / base_url / api_key /
// weight / proxy / timeout_ms / models / extra_headers。
// models 用 yaml.Node 原样编码 —— `["*"]` 这种流式写法能被保住。
func renderProviders(ps []ProviderRaw) ([]byte, error) {
	var b bytes.Buffer
	for _, p := range ps {
		if strings.TrimSpace(p.Name) == "" {
			return nil, fmt.Errorf("供应商名不能为空")
		}
		fmt.Fprintf(&b, "  - name: %s\n", yamlScalar(p.Name))
		if p.Enabled.Set {
			fmt.Fprintf(&b, "    enabled: %v\n", p.Enabled.Value)
		}
		if p.BaseURL != "" {
			fmt.Fprintf(&b, "    base_url: %s\n", yamlScalar(p.BaseURL))
		}
		if p.APIKey != "" {
			fmt.Fprintf(&b, "    api_key: %s\n", yamlScalar(p.APIKey))
		}
		if p.Weight != 0 {
			fmt.Fprintf(&b, "    weight: %v\n", p.Weight)
		}
		if p.Proxy != "" {
			fmt.Fprintf(&b, "    proxy: %s\n", yamlScalar(p.Proxy))
		}
		if p.TimeoutMs != 0 {
			fmt.Fprintf(&b, "    timeout_ms: %d\n", p.TimeoutMs)
		}
		models, err := renderModels(&p.Models)
		if err != nil {
			return nil, fmt.Errorf("供应商 %s 的 models 渲染失败: %w", p.Name, err)
		}
		b.WriteString(models)
		if len(p.ExtraHeaders) > 0 {
			hdr, err := yaml.Marshal(p.ExtraHeaders)
			if err != nil {
				return nil, err
			}
			b.WriteString("    extra_headers:\n")
			for _, line := range strings.Split(strings.TrimRight(string(hdr), "\n"), "\n") {
				b.WriteString("      " + line + "\n")
			}
		}
	}
	return b.Bytes(), nil
}

// renderModels 把一个 models 节点渲染成 models: 那几行。
//
// 内联还是换行**看节点的 style，不看渲染结果里有没有换行** ——
// 块状写法即使只有一个元素（`- '*'`）也只产出一行，按「有没有换行」判断
// 会把 `- '*'` 直接拼到 `models:` 后面，写出非法 YAML。
func renderModels(n *yaml.Node) (string, error) {
	if n == nil || n.Kind == 0 {
		return "    models: [\"*\"]\n", nil // 没给就按直通处理，与解析侧的默认一致
	}
	out, err := yaml.Marshal(n)
	if err != nil {
		return "", err
	}
	text := strings.TrimRight(string(out), "\n")
	if text == "" {
		return "    models: [\"*\"]\n", nil
	}

	// 标量与流式（["*"] / {a: b}）都能安全内联；块状必须另起一行并缩进
	inline := n.Kind == yaml.ScalarNode || n.Style&yaml.FlowStyle != 0
	if inline && !strings.Contains(text, "\n") {
		return "    models: " + text + "\n", nil
	}
	var b strings.Builder
	b.WriteString("    models:\n")
	for _, line := range strings.Split(text, "\n") {
		b.WriteString("      " + line + "\n")
	}
	return b.String(), nil
}

// yamlScalar 决定一个字符串要不要加引号。
// 只在确实会被 YAML 误解析时才加 —— URL 和 ${ENV} 都能裸写，加了反而难读。
func yamlScalar(s string) string {
	if s == "" {
		return `""`
	}
	needs := strings.ContainsAny(s, "\n") ||
		strings.Contains(s, ": ") || strings.Contains(s, " #") ||
		strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ") ||
		strings.ContainsAny(s[:1], "-?:,[]{}#&*!|>'\"%@`")
	if !needs {
		return s
	}
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

// ModelsNode 把接口传来的值编成 models 节点。
//
// 短内容用流式（`["*"]`、`{a: b}`）而不是块状 —— 与 config.example.yaml 里的写法一致，
// 写回后文件看起来没变样；内容长了（>100 字符）才退回块状，免得一行拖得很长。
func ModelsNode(v any) (yaml.Node, error) {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return n, err
	}
	if one, err := yaml.Marshal(&n); err == nil {
		text := strings.TrimRight(string(one), "\n")
		if !strings.Contains(text, "\n") && len(text) <= 100 {
			n.Style = yaml.FlowStyle
		}
	}
	return n, nil
}

// ParseModelsNode 把一个 models 节点解析成 ModelSpec。
//
// 复用配置加载时的那套判断（normalizeModels），这样界面看到的「直通 / 映射 / 其余直通」
// 与运行时实际的行为永远一致 —— 两处各写一遍迟早会漂移。
func ParseModelsNode(n *yaml.Node) (ModelSpec, error) {
	if n == nil || n.Kind == 0 {
		return ModelSpec{Passthrough: true}, nil
	}
	return normalizeModels(n, "models")
}

// RawProviders 从文件内容里读出**未展开**的 providers。
//
// 一定要用它来取「原来的 api_key」，不能用加载后的 Config.Providers ——
// 后者里的 api_key 已经被环境变量展开过了，拿它写回文件会把 ${ENV} 的
// 间接引用替换成明文密钥：既把密钥落进了文件，又丢掉了环境变量注入这条设计。
func RawProviders(src []byte) ([]ProviderRaw, error) {
	var doc struct {
		Providers []ProviderRaw `yaml:"providers"`
	}
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, fmt.Errorf("解析 providers 失败: %w", err)
	}
	return doc.Providers, nil
}
