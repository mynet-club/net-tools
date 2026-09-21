// Package config 负责配置的结构定义、加载、环境变量展开与校验。
//
// 配置文件是 YAML，存放在运行时目录（默认 ~/.config/llmproxy/config.yaml）。
// 密钥支持 ${ENV_VAR} / ${ENV_VAR:-default} 展开，避免明文写进文件。
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

const ToolName = "llmproxy"

// Version 是发行版本号。刻意用 var 而不是 const：交叉编译脚本与 CI 用
// -ldflags "-X .../internal/config.Version=v1.2.3" 把 git tag 注进来。
//
// 下面这个默认值只对「直接 go build」的裸构建可见，它表达的是「这不是发行版」，
// 不是一个版本号 —— 所以刻意不写成某个真实版本，免得本地构建报出一个
// 永远追不上 tag 的过期版本号。发行版号只有一个来源：git tag。
var Version = "v0.0.0-dev"

var loopbackHosts = map[string]bool{
	"127.0.0.1":        true,
	"localhost":        true,
	"::1":              true,
	"::ffff:127.0.0.1": true,
}

// Config 是一次加载完成、已校验的完整配置快照。
type Config struct {
	ConfigPath string   `yaml:"-"`
	Warnings   []string `yaml:"-"`

	Server    ServerConfig   `yaml:"server"`
	Routing   RoutingConfig  `yaml:"routing"`
	Proxies   []ProxyDef     `yaml:"proxies"`
	Providers []ProviderRaw  `yaml:"providers"`
	Database  DatabaseConfig `yaml:"database"`
	Log       LogConfig      `yaml:"log"`
	// Pricing 是消费模式的单价表；不配则消费模式只按 token 记量、不算钱。
	Pricing PricingConfig `yaml:"pricing"`

	// 下面是校验后的派生结构，供运行期直接使用
	ProxyIndex map[string]ProxyDef `yaml:"-"`
	Normalized []Provider          `yaml:"-"`
}

// APIKeyList 在解码阶段就给出可读的错误（否则 yaml 会报 "cannot unmarshal into []APIKey"）。
type APIKeyList []APIKey

func (l *APIKeyList) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.SequenceNode {
		return fmt.Errorf("server.api_keys 需要是列表")
	}
	out := make(APIKeyList, 0, len(value.Content))
	for _, item := range value.Content {
		var k APIKey
		if err := k.UnmarshalYAML(item); err != nil {
			return err
		}
		out = append(out, k)
	}
	*l = out
	return nil
}

// FlexibleBool 接受真正的布尔值或 "true"/"false" 字符串，其余给出可读错误。
type FlexibleBool struct {
	Set   bool
	Value bool
}

func (f *FlexibleBool) UnmarshalYAML(value *yaml.Node) error {
	f.Set = true
	switch value.Tag {
	case "!!bool":
		var b bool
		if err := value.Decode(&b); err != nil {
			return fmt.Errorf("enabled 只能是 true 或 false")
		}
		f.Value = b
		return nil
	case "!!str":
		s := strings.ToLower(strings.TrimSpace(value.Value))
		switch s {
		case "true":
			f.Value = true
			return nil
		case "false":
			f.Value = false
			return nil
		}
		return fmt.Errorf("enabled 只能是 true 或 false，当前是 %q", value.Value)
	}
	return fmt.Errorf("enabled 只能是 true 或 false，当前是 %s", value.Tag)
}

type ServerConfig struct {
	Host    string     `yaml:"host"`
	Port    int        `yaml:"port"`
	APIKeys APIKeyList `yaml:"api_keys"`
	// AdminToken 是多用户管理接口的凭证；为空则管理接口整体关闭。
	// 支持 ${ENV} 展开，建议用环境变量注入而不是写在文件里。
	AdminToken       string `yaml:"admin_token"`
	MaxBodyMB        int    `yaml:"max_body_mb"`
	RequestTimeoutMs int    `yaml:"request_timeout_ms"`
	// StreamIdleTimeoutMs 是**流式**请求的空闲上限：连续这么久没收到任何字节就判失败。
	//
	// 流式不能用「总时限」来管：一次长回答可能跑几分钟，按总时限掐会把正常的流切断；
	// 而上游卡住不动时，又该早点失败（否则要耗满总时限）。所以流式改成看「有没有动静」，
	// 且不设总时限 —— 客户端断开本来就会取消上游。
	//
	// 指针是为了区分「没配」（用默认 2 分钟）和「显式写 0」（关闭，退回总时限行为）——
	// 用普通 int 的话这两者都是 0，没法表达「关掉它」。
	StreamIdleTimeoutMs *int `yaml:"stream_idle_timeout_ms"`
}

// StreamIdleMs 给出流式空闲上限（毫秒）。没配 = 默认 2 分钟；显式 0 = 关闭。
func (c ServerConfig) StreamIdleMs() int {
	if c.StreamIdleTimeoutMs == nil {
		return 120000
	}
	return *c.StreamIdleTimeoutMs
}

// APIKey 既支持纯字符串，也支持 {key, label} 对象形式；label 只用于日志，不参与鉴权。
type APIKey struct {
	Key   string `yaml:"key"`
	Label string `yaml:"label"`
}

func (a *APIKey) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		a.Key = value.Value
		return nil
	}
	type alias APIKey
	var tmp alias
	if err := value.Decode(&tmp); err != nil {
		return fmt.Errorf("api_keys 项需要是字符串或 {key, label} 对象: %w", err)
	}
	*a = APIKey(tmp)
	return nil
}

type RoutingConfig struct {
	Retry            int `yaml:"retry"`
	FailureThreshold int `yaml:"failure_threshold"`
	CooldownSeconds  int `yaml:"cooldown_seconds"`
}

type ProxyDef struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

// ProviderRaw 是 YAML 里的原始供应商条目。
type ProviderRaw struct {
	Name         string            `yaml:"name"`
	Enabled      FlexibleBool      `yaml:"enabled"`
	BaseURL      string            `yaml:"base_url"`
	APIKey       string            `yaml:"api_key"`
	Weight       float64           `yaml:"weight"`
	Proxy        string            `yaml:"proxy"`
	TimeoutMs    int               `yaml:"timeout_ms"`
	Models       yaml.Node         `yaml:"models"`
	ExtraHeaders map[string]string `yaml:"extra_headers"`
}

func (p *ProviderRaw) IsEnabled() bool {
	if !p.Enabled.Set {
		return true
	}
	return p.Enabled.Value
}

type DatabaseConfig struct {
	Path       string `yaml:"path"`
	RetainDays int    `yaml:"retain_days"`
}

type LogConfig struct {
	Level string `yaml:"level"`
	MaxMB int    `yaml:"max_mb"`
	Keep  int    `yaml:"keep"`
}

// ProxyRef 是校验后的代理引用：direct / named / inline。
type ProxyRef struct {
	Mode string // "direct" | "named" | "inline"
	Name string // Mode=named 时有效
	URL  string // Mode=inline 时有效
}

func (p ProxyRef) Resolve(index map[string]ProxyDef) (string, error) {
	switch p.Mode {
	case "direct", "":
		return "", nil
	case "inline":
		return p.URL, nil
	case "named":
		def, ok := index[p.Name]
		if !ok {
			return "", fmt.Errorf("供应商引用的代理 %q 不存在", p.Name)
		}
		return def.URL, nil
	}
	return "", fmt.Errorf("未知的代理模式 %q", p.Mode)
}

// ModelSpec 描述供应商承接哪些下游模型，以及如何映射到上游模型名。
//
// 三种写法：
//
//	models: ["*"]                     → Passthrough，全部直通，不贡献 /v1/models 条目
//	models: {a: b}                    → 只服务 a，映射到 b
//	models: {a: b, "*": "*"}          → 服务 a→b；未声明的模型名也直通（CatchAll），
//	                                    且 a 仍会出现在 /v1/models 里
//
// CatchAll 是为客户端「模型选择器里是固定名单」这种情况准备的：既让 /v1/models
// 有内容可列，又不会因为客户端要了个没声明的名字就直接失败。
type ModelSpec struct {
	Passthrough bool              `json:"passthrough,omitempty"` // 列表形式的 ["*"]：全部直通
	Map         map[string]string `json:"map,omitempty"`         // 下游名 -> 上游名
	CatchAll    bool              `json:"catch_all,omitempty"`   // Map 里含 "*"：未声明的模型名也原样直通
}

// ParseModelsJSON 解析用户自助接口传来的 models 声明。
// JSON 是 YAML 的子集，所以这里直接复用配置文件那套解析与校验逻辑，
// 保证「用户在接口里写的 models」和「管理员写在 config.yaml 里的 models」语义完全一致。
func ParseModelsJSON(raw []byte) (ModelSpec, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return ModelSpec{}, errors.New("models 不能为空（用 [\"*\"] 表示任意模型直通）")
	}
	var node yaml.Node
	if err := yaml.Unmarshal(raw, &node); err != nil {
		return ModelSpec{}, fmt.Errorf("models 不是合法的 JSON/YAML: %w", err)
	}
	root := &node
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return ModelSpec{}, errors.New("models 不能为空")
		}
		root = root.Content[0]
	}
	return normalizeModels(root, "provider")
}

// NormalizeProxy 把 proxy 字段解析成 ProxyRef（direct / 引用 proxies 里的名字 / 内联 URL）。
func NormalizeProxy(raw string, index map[string]ProxyDef) (ProxyRef, error) {
	return normalizeProxyRef(raw, index, "provider")
}

// Provider 是校验后的供应商，运行期直接使用。
type Provider struct {
	Name         string
	Enabled      bool
	BaseURL      string
	APIKey       string
	Weight       float64
	TimeoutMs    int
	ExtraHeaders map[string]string
	Proxy        ProxyRef
	Models       ModelSpec
	Index        int
}

// Serves 报告该供应商是否承接下游模型 model。
func (p *Provider) Serves(model string) bool {
	if !p.Enabled {
		return false
	}
	if p.Models.Passthrough || p.Models.CatchAll {
		return true
	}
	_, ok := p.Models.Map[model]
	return ok
}

// UpstreamModel 返回下游模型名在该供应商处对应的上游模型名。
func (p *Provider) UpstreamModel(model string) (string, bool) {
	if p.Models.Passthrough {
		return model, true
	}
	if up, ok := p.Models.Map[model]; ok {
		return up, true
	}
	if p.Models.CatchAll {
		return model, true
	}
	return "", false
}

// Declares 报告该供应商是否**点名**承接了这个模型（`models` 里有这一条），
// 而不是靠 `["*"]` / catch-all 通配兜底。
//
// 选路用它区分「明确指定」和「兜底」：一家写 `models: ["*"]` 的供应商声明「任何模型名我都接」，
// 于是它也会成为那些**别人点名声明过**的模型名的候选。两者若平权，一次请求走对还是走错
// 就全看随机 —— 表现为同一个模型名时而正常、时而 400（兜底那家其实不认这个名字）。
func (p *Provider) Declares(model string) bool {
	if model == "" || model == "*" {
		return false
	}
	_, ok := p.Models.Map[model]
	return ok
}

// ------------------------------------------------------------------ 路径

func GetRuntimeDir() string {
	if h := os.Getenv("LLMPROXY_HOME"); h != "" {
		abs, err := filepath.Abs(h)
		if err == nil {
			return abs
		}
		return h
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("APPDATA")
		if base == "" {
			base = filepath.Join(homeDir(), "AppData", "Roaming")
		}
		return filepath.Join(base, ToolName)
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, ToolName)
	}
	return filepath.Join(homeDir(), ".config", ToolName)
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return h
}

type Paths struct {
	RuntimeDir string
	ConfigFile string
	PIDFile    string
	LogDir     string
	DataDir    string
	Template   string
}

func DefaultPaths() Paths {
	rt := GetRuntimeDir()
	return Paths{
		RuntimeDir: rt,
		ConfigFile: filepath.Join(rt, "config.yaml"),
		PIDFile:    filepath.Join(rt, ToolName+".pid"),
		LogDir:     filepath.Join(rt, "logs"),
		DataDir:    filepath.Join(rt, "data"),
	}
}

func (p Paths) Ensure() error {
	for _, d := range []string{p.RuntimeDir, p.LogDir, p.DataDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("创建目录 %s 失败: %w", d, err)
		}
	}
	return nil
}

// ------------------------------------------------------------------ 环境变量展开

func expandEnv(s string, missing *[]string, trail string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '$' || i+1 >= len(s) || s[i+1] != '{' {
			b.WriteByte(s[i])
			i++
			continue
		}
		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			b.WriteByte(s[i])
			i++
			continue
		}
		inner := s[i+2 : i+end]
		name, def, hasDef := inner, "", false
		if k := strings.Index(inner, ":-"); k >= 0 {
			name, def, hasDef = inner[:k], inner[k+2:], true
		}
		if v := os.Getenv(name); v != "" {
			b.WriteString(v)
		} else if hasDef {
			b.WriteString(def)
		} else {
			*missing = append(*missing, fmt.Sprintf("%s 引用了未设置的环境变量 ${%s}", trail, name))
			b.WriteString(s[i : i+end+1])
		}
		i += end + 1
	}
	return b.String()
}

// ------------------------------------------------------------------ 校验

// LoadOptions 控制配置加载的严格程度。
type LoadOptions struct {
	// Strict 为 true 时，已启用供应商的 api_key 里若还留着未展开的 ${VAR} 会直接报错。
	// start / service 安装必须用严格模式；status / providers / stats / logs 等只读命令
	// 用宽松模式，否则没 export 环境变量就连状态都看不了。
	Strict bool
}

func LoadFile(path string) (*Config, error) {
	return LoadFileWithOptions(path, LoadOptions{Strict: true})
}

// LoadFileLenient 用于只读 CLI 命令：允许供应商 api_key 保留 ${VAR} 占位。
func LoadFileLenient(path string) (*Config, error) {
	return LoadFileWithOptions(path, LoadOptions{Strict: false})
}

func LoadFileWithOptions(path string, opts LoadOptions) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("配置文件不存在：%s\n  先执行 llmproxy init 生成", path)
		}
		return nil, fmt.Errorf("读取配置文件失败：%w", err)
	}
	cfg, err := parseWithOpts(raw, opts)
	if err != nil {
		return nil, err
	}
	cfg.ConfigPath = path
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
		cfg.Warnings = append(cfg.Warnings,
			fmt.Sprintf("配置文件权限是 %04o，组/其他用户可读 —— 里面可能有上游密钥，建议 chmod 600 %s",
				st.Mode().Perm(), path))
	}
	return cfg, nil
}

func Parse(raw []byte) (*Config, error) {
	return parseWithOpts(raw, LoadOptions{Strict: true})
}

func parseWithOpts(raw []byte, opts LoadOptions) (*Config, error) {
	cfg := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		if err.Error() == "EOF" {
			return nil, fmt.Errorf("配置文件是空的")
		}
		return nil, fmt.Errorf("配置文件解析失败：%w", err)
	}
	if err := cfg.normalize(opts); err != nil {
		return nil, err
	}
	return cfg, nil
}
func (c *Config) normalize(opts LoadOptions) error {
	// 环境变量展开：只在 providers[].api_key 等字符串字段上做
	var missing []string
	c.Server.Host = expandEnv(c.Server.Host, &missing, "server.host")
	c.Server.AdminToken = expandEnv(c.Server.AdminToken, &missing, "server.admin_token")
	if c.Server.Host == "" {
		c.Server.Host = "127.0.0.1"
	}
	if c.Server.Port == 0 {
		c.Server.Port = 8787
	}
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port 需要在 1~65535 之间，当前是 %d", c.Server.Port)
	}
	if c.Server.MaxBodyMB == 0 {
		c.Server.MaxBodyMB = 16
	}
	if c.Server.MaxBodyMB < 1 || c.Server.MaxBodyMB > 512 {
		return fmt.Errorf("server.max_body_mb 需要在 1~512 之间，当前是 %d", c.Server.MaxBodyMB)
	}
	if c.Server.RequestTimeoutMs == 0 {
		c.Server.RequestTimeoutMs = 300000
	}
	if c.Server.RequestTimeoutMs < 1000 || c.Server.RequestTimeoutMs > 86400000 {
		return fmt.Errorf("server.request_timeout_ms 需要在 1000~86400000 之间，当前是 %d", c.Server.RequestTimeoutMs)
	}
	if v := c.Server.StreamIdleTimeoutMs; v != nil && *v != 0 && (*v < 1000 || *v > 86400000) {
		return fmt.Errorf("server.stream_idle_timeout_ms 需要是 0（关闭）或 1000~86400000 之间，当前是 %d", *v)
	}

	seenKey := map[string]bool{}
	for i := range c.Server.APIKeys {
		k := strings.TrimSpace(c.Server.APIKeys[i].Key)
		if k == "" {
			return fmt.Errorf("server.api_keys[%d] 必须是非空字符串", i)
		}
		if seenKey[k] {
			return fmt.Errorf("server.api_keys 存在重复项")
		}
		seenKey[k] = true
		c.Server.APIKeys[i].Key = k
	}
	if !loopbackHosts[c.Server.Host] && len(c.Server.APIKeys) == 0 {
		return fmt.Errorf("server.host 是 %s（非本机回环），但 server.api_keys 为空 —— 这会把上游密钥暴露给任何人。请至少配置一个 api_keys，或把 host 改回 127.0.0.1", c.Server.Host)
	}

	if c.Routing.Retry == 0 {
		c.Routing.Retry = 2
	}
	if c.Routing.Retry < 0 || c.Routing.Retry > 10 {
		return fmt.Errorf("routing.retry 需要在 0~10 之间，当前是 %d", c.Routing.Retry)
	}
	if c.Routing.FailureThreshold == 0 {
		c.Routing.FailureThreshold = 3
	}
	if c.Routing.FailureThreshold < 1 || c.Routing.FailureThreshold > 1000 {
		return fmt.Errorf("routing.failure_threshold 需要在 1~1000 之间，当前是 %d", c.Routing.FailureThreshold)
	}
	if c.Routing.CooldownSeconds == 0 {
		c.Routing.CooldownSeconds = 60
	}
	if c.Routing.CooldownSeconds < 0 || c.Routing.CooldownSeconds > 86400 {
		return fmt.Errorf("routing.cooldown_seconds 需要在 0~86400 之间，当前是 %d", c.Routing.CooldownSeconds)
	}

	// 代理池
	c.ProxyIndex = make(map[string]ProxyDef, len(c.Proxies))
	for i, p := range c.Proxies {
		if strings.TrimSpace(p.Name) == "" {
			return fmt.Errorf("proxies[%d].name 必填", i)
		}
		if _, dup := c.ProxyIndex[p.Name]; dup {
			return fmt.Errorf("proxies[%d].name %q 重复", i, p.Name)
		}
		u, err := url.Parse(p.URL)
		if err != nil {
			return fmt.Errorf("proxies[%d].url %q 不是合法 URL: %w", i, p.URL, err)
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "socks5", "socks5h", "socks":
		default:
			return fmt.Errorf("proxies[%d].url 不支持的协议 %s（支持 http/https/socks5/socks5h）", i, u.Scheme)
		}
		c.ProxyIndex[p.Name] = p
	}

	// 供应商
	if len(c.Providers) == 0 {
		return fmt.Errorf("providers 需要至少包含一个供应商")
	}
	seenName := map[string]bool{}
	c.Normalized = make([]Provider, 0, len(c.Providers))
	// 供应商自己的缺失环境变量：停用的不要求存在
	var provMissing []string
	for i := range c.Providers {
		p := &c.Providers[i]
		where := fmt.Sprintf("providers[%d]", i)
		if strings.TrimSpace(p.Name) == "" {
			return fmt.Errorf("%s.name 必填", where)
		}
		if seenName[p.Name] {
			return fmt.Errorf("%s.name %q 重复", where, p.Name)
		}
		seenName[p.Name] = true

		enabled := p.IsEnabled()
		if !enabled {
			// 停用供应商：api_key 可以是未展开的环境变量
			var m2 []string
			p.APIKey = expandEnv(p.APIKey, &m2, where+".api_key")
			provMissing = append(provMissing, m2...)
		} else {
			p.APIKey = expandEnv(p.APIKey, &missing, where+".api_key")
		}

		if p.BaseURL == "" {
			return fmt.Errorf("%s.base_url 必填", where)
		}
		u, err := url.Parse(p.BaseURL)
		if err != nil {
			return fmt.Errorf("%s.base_url %q 不是合法 URL: %w", where, p.BaseURL, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("%s.base_url 只支持 http/https，当前是 %s", where, u.Scheme)
		}
		if enabled && p.APIKey == "" && !opts.Strict {
			// 宽松模式：密钥留空/未展开只记警告，方便 status 等命令
		} else if enabled && p.APIKey == "" {
			return fmt.Errorf("%s (\"%s\") 已启用但缺少 api_key", where, p.Name)
		}
		if enabled && strings.Contains(p.APIKey, "${") {
			if opts.Strict {
				return fmt.Errorf("%s (\"%s\") 的 api_key 里还有未展开的环境变量：%s", where, p.Name, p.APIKey)
			}
			c.Warnings = append(c.Warnings,
				fmt.Sprintf("%s (\"%s\") 的 api_key 未展开（%s）——启动服务前请先设置该环境变量", where, p.Name, p.APIKey))
		}

		if p.Weight == 0 {
			p.Weight = 1
		}
		if p.Weight < 0 {
			return fmt.Errorf("%s.weight 必须大于 0（当前 %v）", where, p.Weight)
		}
		if p.TimeoutMs == 0 {
			p.TimeoutMs = 120000
		}
		if p.TimeoutMs < 1000 || p.TimeoutMs > 3600000 {
			return fmt.Errorf("%s.timeout_ms 需要在 1000~3600000 之间，当前是 %d", where, p.TimeoutMs)
		}

		proxyRef, err := normalizeProxyRef(p.Proxy, c.ProxyIndex, where)
		if err != nil {
			return err
		}
		spec, err := normalizeModels(&p.Models, where)
		if err != nil {
			return err
		}

		c.Normalized = append(c.Normalized, Provider{
			Name:         p.Name,
			Enabled:      enabled,
			BaseURL:      strings.TrimRight(p.BaseURL, "/"),
			APIKey:       p.APIKey,
			Weight:       p.Weight,
			TimeoutMs:    p.TimeoutMs,
			ExtraHeaders: p.ExtraHeaders,
			Proxy:        proxyRef,
			Models:       spec,
			Index:        i,
		})
	}

	anyEnabled := false
	for _, p := range c.Normalized {
		if p.Enabled {
			anyEnabled = true
			break
		}
	}
	if !anyEnabled {
		return fmt.Errorf("没有任何已启用的供应商（providers[].enabled 全为 false）")
	}

	// missing 里既有 server.host 之类的全局字段，也有已启用供应商的 api_key。
	// 供应商那部分上面已按 Strict 处理（报错或警告），这里只收尾非 provider 的项。
	var nonProv []string
	for _, m := range missing {
		if !strings.Contains(m, "providers[") {
			nonProv = append(nonProv, m)
		}
	}
	if opts.Strict && len(nonProv) > 0 {
		return fmt.Errorf("%s", strings.Join(nonProv, "\n"))
	}
	for _, m := range nonProv {
		c.Warnings = append(c.Warnings, m)
	}
	for _, m := range provMissing {
		c.Warnings = append(c.Warnings, m+"（该供应商已停用，忽略）")
	}

	// database / log
	if c.Database.Path == "" {
		c.Database.Path = filepath.Join(GetRuntimeDir(), "data", ToolName+".db")
	} else {
		c.Database.Path = expandTilde(c.Database.Path)
	}
	// 单价表：消费模式用它估算金额。不配不算错，只是没金额可看。
	if err := c.Pricing.normalize(); err != nil {
		return err
	}
	if c.Database.RetainDays == 0 {
		c.Database.RetainDays = 90
	}
	if c.Database.RetainDays < 0 {
		return fmt.Errorf("database.retain_days 不能为负数，当前是 %d", c.Database.RetainDays)
	}

	switch c.Log.Level {
	case "":
		c.Log.Level = "info"
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level 只能是 debug/info/warn/error，当前是 %q", c.Log.Level)
	}
	if c.Log.MaxMB == 0 {
		c.Log.MaxMB = 10
	}
	if c.Log.Keep == 0 {
		c.Log.Keep = 5
	}

	return nil
}

func normalizeProxyRef(raw string, index map[string]ProxyDef, where string) (ProxyRef, error) {
	v := strings.TrimSpace(raw)
	if v == "" || v == "direct" || v == "none" || v == "false" {
		return ProxyRef{Mode: "direct"}, nil
	}
	if _, ok := index[v]; ok {
		return ProxyRef{Mode: "named", Name: v}, nil
	}
	u, err := url.Parse(v)
	if err == nil && u.Scheme != "" {
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "socks5", "socks5h", "socks":
			return ProxyRef{Mode: "inline", URL: v}, nil
		}
		return ProxyRef{}, fmt.Errorf("%s.proxy 不支持的协议 %s（支持 http/https/socks5/socks5h，或引用 proxies 里的名字）", where, u.Scheme)
	}
	names := make([]string, 0, len(index))
	for n := range index {
		names = append(names, n)
	}
	return ProxyRef{}, fmt.Errorf("%s.proxy 是 %q，但它既不是 \"direct\"、也不是 proxies 里定义的名字、也不是合法代理 URL。已定义的代理名：%s",
		where, v, strings.Join(names, ", "))
}

func normalizeModels(node *yaml.Node, where string) (ModelSpec, error) {
	if node == nil || node.Kind == 0 || node.Tag == "!!null" {
		return ModelSpec{}, fmt.Errorf("%s.models 必填（用 [\"*\"] 表示任意模型直通）", where)
	}
	switch node.Kind {
	case yaml.SequenceNode:
		if len(node.Content) == 0 {
			return ModelSpec{}, fmt.Errorf("%s.models 不能是空列表（用 [\"*\"] 表示任意模型直通）", where)
		}
		for _, item := range node.Content {
			if item.Value == "*" {
				return ModelSpec{Passthrough: true}, nil
			}
		}
		m := make(map[string]string, len(node.Content))
		for _, item := range node.Content {
			name := strings.TrimSpace(item.Value)
			if name == "" {
				return ModelSpec{}, fmt.Errorf("%s.models 里的模型名必须是非空字符串", where)
			}
			m[name] = name
		}
		return ModelSpec{Map: m}, nil
	case yaml.MappingNode:
		if len(node.Content) < 2 {
			return ModelSpec{}, fmt.Errorf("%s.models 不能为空（用 [\"*\"] 表示任意模型直通）", where)
		}
		m := make(map[string]string, len(node.Content)/2)
		catchAll := false
		for i := 0; i+1 < len(node.Content); i += 2 {
			down := strings.TrimSpace(node.Content[i].Value)
			up := strings.TrimSpace(node.Content[i+1].Value)
			if down == "" {
				return ModelSpec{}, fmt.Errorf("%s.models 里有空模型名", where)
			}
			// "*" 作为键 = 兜底：未声明的模型名也原样直通
			if down == "*" {
				catchAll = true
				continue
			}
			if up == "" {
				return ModelSpec{}, fmt.Errorf("%s.models.%s 需要是非空的字符串（上游真实模型名）", where, down)
			}
			m[down] = up
		}
		if len(m) == 0 && !catchAll {
			return ModelSpec{}, fmt.Errorf("%s.models 不能为空（用 [\"*\"] 表示任意模型直通）", where)
		}
		return ModelSpec{Map: m, CatchAll: catchAll}, nil
	default:
		return ModelSpec{}, fmt.Errorf("%s.models 需要是映射（下游名: 上游名）或列表（[\"*\"] 或模型名列表）", where)
	}
}

func expandTilde(p string) string {
	if p == "~" {
		return homeDir()
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~\\") {
		return filepath.Join(homeDir(), p[2:])
	}
	return p
}

// MaxBodyBytes 返回字节单位的请求体上限。
func (s *ServerConfig) MaxBodyBytes() int64 {
	return int64(s.MaxBodyMB) * 1024 * 1024
}

// HasAdminToken 报告是否启用了多用户管理接口。
func (s *ServerConfig) HasAdminToken() bool {
	return strings.TrimSpace(s.AdminToken) != ""
}

// RequiresAuth 报告是否配置了下游凭证。
func (s *ServerConfig) RequiresAuth() bool {
	return len(s.APIKeys) > 0
}
