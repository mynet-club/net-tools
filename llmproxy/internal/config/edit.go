package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
		// 每个可能来自界面的字符串都走 yamlScalar：它负责引号/转义，
		// 并在值含控制字符时**报错**而不是静默写出一个会被 YAML 折叠或越段的标量。
		name, err := yamlScalar(p.Name)
		if err != nil {
			return nil, fmt.Errorf("供应商名 %w", err)
		}
		fmt.Fprintf(&b, "  - name: %s\n", name)
		if p.Enabled.Set {
			fmt.Fprintf(&b, "    enabled: %v\n", p.Enabled.Value)
		}
		if p.BaseURL != "" {
			v, err := yamlScalar(p.BaseURL)
			if err != nil {
				return nil, fmt.Errorf("供应商 %s 的 base_url %w", p.Name, err)
			}
			fmt.Fprintf(&b, "    base_url: %s\n", v)
		}
		if p.APIKey != "" {
			v, err := yamlScalar(p.APIKey)
			if err != nil {
				return nil, fmt.Errorf("供应商 %s 的 api_key %w", p.Name, err)
			}
			fmt.Fprintf(&b, "    api_key: %s\n", v)
		}
		if p.Weight != 0 {
			fmt.Fprintf(&b, "    weight: %v\n", p.Weight)
		}
		if p.Proxy != "" {
			v, err := yamlScalar(p.Proxy)
			if err != nil {
				return nil, fmt.Errorf("供应商 %s 的 proxy %w", p.Name, err)
			}
			fmt.Fprintf(&b, "    proxy: %s\n", v)
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

// yamlScalar 把一个字符串渲染成**单行** YAML 标量。
//
// 引号与转义一律交给 yaml.v3，不再手写判断规则。手写那版只看 `\n`，漏掉了
// lone CR（U+000D）、U+2028、U+0085 —— 而 YAML 把这三个都当换行，于是一个带 CR 的
// 供应商名能逃出 providers 段、在 config.yaml 里注入一个全新的顶层段
// （实测过可落盘的 PoC：注入一个 pricing 段把所有单价变成 0，配额于永不触发）。
// 交给 yaml.v3 之后它会把 CR 编成双引号转义 `"a\rb"`，注入就不成立了。
//
// 顺带修掉旧实现的另一个坑：`123` / `true` / `null` / `1.5` 这类值旧代码会裸写，
// 而 YAML 会把它们解析成整数/布尔/null 而不是字符串；yaml.v3 会自动加引号。
//
// 含控制字符的值**直接拒绝**，而不是想办法渲染，两个理由：
//
//   - yaml.v3 对含换行的值会输出多行块标量（`|-`），而 renderProviders 是按
//     「一个字段一行」拼的，多行标量塞进去缩进就对不上了；
//   - 更根本的是，供应商名 / base_url / api_key / proxy 里出现换行或控制字符
//     本身就一定是错误输入（多半是从表格软件或 Windows 环境粘来的）。
//     旧实现会把裸换行放进双引号标量里 —— 而 YAML 双引号标量的裸换行是「折叠」语义，
//     于是 api_key 被静默改成 `sk-line1 line2`：校验通过、落盘成功、界面毫无提示，
//     之后那家供应商每个请求都 401。响亮地拒绝远好于静默改坏。
func yamlScalar(s string) (string, error) {
	if i := strings.IndexFunc(s, unsafeYAMLRune); i >= 0 {
		return "", fmt.Errorf("值里含控制字符或行分隔符（%q 处），不能写进配置文件；"+
			"多半是从表格或别处粘来的，请去掉换行再试", s[i:])
	}
	n := yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
	out, err := yaml.Marshal(&n)
	if err != nil {
		return "", fmt.Errorf("编码 YAML 标量失败: %w", err)
	}
	text := strings.TrimRight(string(out), "\n")
	if strings.ContainsAny(text, "\r\n") {
		return "", fmt.Errorf("%q 无法写成单行 YAML 标量", s)
	}
	// 往返校验：解回来必须逐字节相同。这一道不依赖我枚举全所有危险字符 ——
	// 任何「写下去再读回来就变了」的值都会在这里被挡住。
	var back string
	if err := yaml.Unmarshal(out, &back); err != nil {
		return "", fmt.Errorf("%q 写成的 YAML 解不回来: %w", s, err)
	}
	if back != s {
		return "", fmt.Errorf("%q 无法被安全地写成 YAML（往返不一致，读回来是 %q）", s, back)
	}
	return text, nil
}

// unsafeYAMLRune 报告 r 是否是「不能出现在单行 YAML 标量里」的字符：
// C0 控制字符（含 \t \n \r）、DEL、C1 控制字符（含 U+0085 NEL），
// 以及 YAML 当作行分隔符的 U+2028 / U+2029。
func unsafeYAMLRune(r rune) bool {
	switch {
	case r < 0x20 || r == 0x7f:
		return true
	case r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x2028 || r == 0x2029:
		return true
	}
	return false
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

// sectionTitleLine 找到顶层段标题所在的行号（0-based）。
//
// 先用 AST 确认这个段真的存在（比文本搜索可靠：注释里、字符串里的 "server:" 都骗不到它），
// 再用行扫描找 `section:` 这一行。之所以不能直接用 yaml.Node.Line：段里一个键都没有时
// yaml.v3 给出的值节点 Line 是 0，反推不到标题行。
func sectionTitleLine(lines []string, section string, doc *yaml.Node) (int, error) {
	if _, val := findTopLevelKey(doc, section); val == nil {
		return -1, fmt.Errorf("配置里没有 %s 段", section)
	}
	for i, ln := range lines {
		if strings.TrimRight(ln, "\r\n") == section+":" {
			return i, nil
		}
	}
	return -1, fmt.Errorf("定位 %s 段失败", section)
}

// SetConfigScalar 把 config.yaml 里某个顶层段下的**标量键**的值替换成新的，
// 其余内容（注释、空行、缩进、别的键）逐字节不变。
//
// 只支持「已经存在的标量键」：想新增键请用别的方式。这条限制是刻意的 ——
// 动的是生产配置文件，要能保证「只动我要动的那一行」，否则一次保存就能把
// 注释、缩进风格和别的键一起改掉。行末的 `# 注释` 会保留下来。
//
// 调用方负责「校验不过不落盘」：先写临时文件、用加载器校验、再原子改名（见
// configedit.go 的做法）。这里只负责生成字节。
func SetConfigScalar(src []byte, section, key, value string) ([]byte, error) {
	section = strings.TrimSpace(section)
	key = strings.TrimSpace(key)
	if section == "" || key == "" {
		return nil, errors.New("section 与 key 不能为空")
	}
	// 用 AST 找到段的起始行（yaml.Node.Line 是 1-based）
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, fmt.Errorf("解析现有配置失败: %w", err)
	}
	lines := strings.Split(string(src), "\n")
	titleLine, err := sectionTitleLine(lines, section, &doc)
	if err != nil {
		return nil, err
	}
	end := sectionEnd(lines, titleLine, 0)

	// 在段内找 `  key:`
	prefix := key + ":"
	for i := titleLine + 1; i < end; i++ {
		raw := strings.TrimRight(lines[i], "\r\n")
		trimmed := strings.TrimLeft(raw, " ")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		// 必须是 `key:` 后跟空格或行尾，避免把 keyx: 误认成 key:
		rest := trimmed[len(prefix):]
		if rest != "" && !strings.HasPrefix(rest, " ") && !strings.HasPrefix(rest, "\t") {
			continue
		}
		indent := raw[:len(raw)-len(trimmed)]
		// 保留行末注释与它前面的**对齐空白**（`port: 8787          # 监听端口`）——
		// 「只动值」的意思是连那段空白都不动。注释只在值是裸标量时能这么切分：
		// 这里只处理标量键（token / 数字 / 布尔 / 主机名），它们的值里不会带 ` #`。
		comment, gap := "", ""
		valuePart := rest
		if idx := strings.Index(rest, " #"); idx >= 0 {
			comment = rest[idx:]
			valuePart = strings.TrimRight(rest[:idx], " \t")
			gap = rest[len(valuePart):idx]
		}
		lines[i] = indent + prefix + " " + value + gap + comment
		out := strings.Join(lines, "\n")
		return []byte(out), nil
	}
	return nil, fmt.Errorf("%s 段里没有 %s 这个键（只支持替换已存在的键）", section, key)
}

// SetOrInsertConfigScalar 与 SetConfigScalar 一样，区别是**键不存在时插入一行**。
//
// 什么时候需要插入：`config.example.yaml` 里 `admin_token` 是被注释掉的，
// 所以新建的配置里很可能压根没有这个键。如果这时只报「键不存在，请自己加」，
// 就等于把「不想改配置文件」这个初衷又推回给用户了。
//
// 插入位置是段标题的下一行（`server:` 之后）。插入的那行是本函数唯一新增的字节，
// 其余内容与 SetConfigScalar 一样逐字节不变。
func SetOrInsertConfigScalar(src []byte, section, key, value string) ([]byte, error) {
	out, err := SetConfigScalar(src, section, key, value)
	if err == nil {
		return out, nil
	}
	if !strings.Contains(err.Error(), "只支持替换已存在的键") {
		return nil, err
	}

	// 键不存在：定位段标题行，插在它下面
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	lines := strings.Split(string(src), "\n")
	titleLine, err := sectionTitleLine(lines, section, &doc)
	if err != nil {
		return nil, err
	}
	// 用段内已有键的缩进，段里一个键都没有就用两个空格
	indent := "  "
	if end := sectionEnd(lines, titleLine, 0); titleLine+1 < end {
		for i := titleLine + 1; i < end; i++ {
			raw := strings.TrimRight(lines[i], "\r\n")
			if trimmed := strings.TrimLeft(raw, " "); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				indent = raw[:len(raw)-len(trimmed)]
				break
			}
		}
	}
	insertAt := titleLine + 1
	newLines := append([]string{}, lines[:insertAt]...)
	newLines = append(newLines, indent+key+": "+value)
	newLines = append(newLines, lines[insertAt:]...)
	return []byte(strings.Join(newLines, "\n")), nil
}

// WriteFileSafely 把新的配置字节落盘，走与管理台写回 providers 段同一条安全底线：
//
//  1. 先把原文件备份成 `config.yaml.bak-<时间戳>`（0600，只留最近 5 份）；
//  2. 写进临时文件 `config.yaml.new`（0600）；
//  3. 用加载器校验——**校验不过就删掉临时文件、原文件一字不动**；
//  4. 通过才 `os.Rename` 原子覆盖。
//
// 这四步缺一不可：动的是生产配置文件，一次手滑不能把网关搞挂。
// 这个函数放在 config 包是为了让 server（管理台写回）与 cmd（CLI 改配置）共用一份；
// 目前 server 的 configedit.go 仍保留自己的实现，等下一轮再迁过来。
func WriteFileSafely(path string, newSrc []byte) error {
	orig, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// 1) 备份。名字必须带**微秒**：只精确到秒的话，同一秒内连着保存两次会互相覆盖、
	// 少一代备份（审阅里的 L4，实测过：测试里连着 rotate 两次就只剩 1 份备份）。
	backup := fmt.Sprintf("%s.bak-%s", path, time.Now().Format("20060102-150405.000000"))
	if err := os.WriteFile(backup, orig, 0o600); err != nil {
		return fmt.Errorf("写备份失败: %w", err)
	}
	// 只留最近 5 份
	if baks, err := filepath.Glob(path + ".bak-*"); err == nil {
		sort.Strings(baks)
		if over := len(baks) - 5; over > 0 {
			for _, old := range baks[:over] {
				_ = os.Remove(old)
			}
		}
	}

	// 2) 临时文件
	tmp := path + ".new"
	if err := os.WriteFile(tmp, newSrc, 0o600); err != nil {
		return err
	}
	// 3) 校验：用与线上同一条加载通道（含 ${ENV} 展开与全部校验）
	if _, err := LoadFileLenient(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("新配置校验不通过，原文件未改动: %w", err)
	}
	// 4) 原子覆盖
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
