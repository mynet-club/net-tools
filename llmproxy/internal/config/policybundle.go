package config

// 本文件是 §3.0 的策略包**内容**加载层：YAML → policy.PolicyBundle → BundleSet。
//
// 为什么在 config 包：手册把这块明确划给「H/接线包」（docs/3.0-policy-domain.md
// 的「本包不管」清单），而它本质是一次带校验的读文件 —— 和配置文件同一类活。
// 放这里而不是 internal/server，H 的管理 API、回放工具与网关启动走的是同一个加载器；
// 出现第二份加载逻辑，就会出现「界面发布的版本和运行时加载的版本不是同一套规则」。
//
// 内容为什么不在主配置里：主配置只有引用（id/version/scope）。把 entitlements 也塞进
// 主配置，策略发布就同时存在文件与库两个真值来源，回滚时两边互相打脸。

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// ErrPolicyBundle 是策略包内容加载失败的哨兵。
//
// 单独一个哨兵而不是直接抛 os 错误：调用方要能区分「配置文件写坏了」和
// 「磁盘读不到」—— 前者必须让网关起不来，后者是运维事故，两者的告警路径不同。
var ErrPolicyBundle = errors.New("config: 策略包加载失败")

// bundleFileWire 是 <id>.yaml 的磁盘形态。
//
// 字段用 **JSON tag** 而不是 YAML tag：授权规则的结构属于 policy 包（领域对象只有一个
// 定义，见手册 §5），而 policy.Entitlement 只带 json tag。这里靠
// 「YAML → map[string]any → JSON → 领域对象」把两种表示接起来，代价是零结构复制。
// 键名因此一律写 JSON 形态（subject / resource / effect / expires_at）。
type bundleFileWire struct {
	ID           string               `json:"id"`
	Version      int                  `json:"version"`
	Scope        string               `json:"scope"`
	Entitlements []policy.Entitlement `json:"entitlements"`
}

// ParseScopeRef 把 "organization:university" 解析成范围引用（导出版，供加载器与 H 复用）。
func ParseScopeRef(raw string) (policy.ScopeRef, error) {
	return parseConfigScope(raw)
}

// BundleBaseDir 返回策略包内容目录的**相对基准**：配置文件所在目录。
// 没有配置文件路径（内存里 parse 出来的配置）时返回 "."，由调用方显式给目录。
func (c *Config) BundleBaseDir() string {
	if c == nil || strings.TrimSpace(c.ConfigPath) == "" {
		return "."
	}
	return filepath.Dir(c.ConfigPath)
}

// LoadBundles 按引用加载策略包内容，返回实际加载的集合（§3.0 里 policy version 的唯一来源）。
//
// baseDir 用于解析相对路径的 BundleDir；整段是 legacy 时返回 (nil, nil) —— legacy
// 不加载内容，回滚开关才谈得上「改一行 mode 就立刻停」。
//
// 加载是**全有或全无**：引用了 3 个包却只读到 2 个内容文件时必须报错，不能带着
// 半个策略集上线 —— 少一个包少一批规则，而审计里的版本串看着完全正常，
// 事后回放会以为当时的判定是完整的。
func (p *PolicyConfig) LoadBundles(baseDir string) (*policy.BundleSet, error) {
	if p == nil || !p.UsesPolicy() {
		return nil, nil
	}
	refs := p.BundleRefs()
	dir := strings.TrimSpace(p.BundleDir)
	if dir == "" {
		// 缺省目录跟着配置文件走：一次 init 就能跑，不需要每个部署抄一遍绝对路径。
		dir = DefaultBundleDir
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(baseDir, dir)
	}

	set := make([]policy.PolicyBundle, 0, len(refs))
	for _, ref := range refs {
		id := strings.TrimSpace(ref.ID)
		path := filepath.Join(dir, id+".yaml")
		b, err := p.loadOneBundle(id, path, ref)
		if err != nil {
			return nil, err
		}
		set = append(set, b)
	}
	s, err := policy.NewBundleSet(set...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicyBundle, err)
	}
	return s, nil
}

// DefaultBundleDir 是 policy.bundle_dir 的缺省值。
const DefaultBundleDir = "policy-bundles"

// loadOneBundle 读一个内容文件并核对它与引用一致。
func (p *PolicyConfig) loadOneBundle(id, path string, ref PolicyBundleRef) (policy.PolicyBundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return policy.PolicyBundle{}, fmt.Errorf(
				"%w: 策略包 %s 的内容文件不存在：%s（policy.bundles 里的每个引用都要有对应文件；%s）",
				ErrPolicyBundle, id, path, "文件名必须是 <id>.yaml")
		}
		return policy.PolicyBundle{}, fmt.Errorf("%w: 读取 %s 失败: %v", ErrPolicyBundle, path, err)
	}

	var wire bundleFileWire
	if err := decodeYAMLStrict(raw, &wire); err != nil {
		return policy.PolicyBundle{}, fmt.Errorf("%w: %s: %v", ErrPolicyBundle, path, err)
	}

	// 内容与引用逐字段核对。**以引用为准**：配置里那一条才是运维明确生效的版本，
	// 内容文件里写着另一版说明两边有人改了没改另一边 —— 这时候猜哪一侧都是错的，
	// 必须让人来选（错误信息里把两侧都报出来）。
	if got := strings.TrimSpace(wire.ID); got != id {
		return policy.PolicyBundle{}, bundleMismatch(path, "id", id, got)
	}
	if wire.Version != ref.Version {
		return policy.PolicyBundle{}, bundleMismatch(path, "version",
			fmt.Sprint(ref.Version), fmt.Sprint(wire.Version))
	}
	refScope, ok := p.ScopeOf(id)
	if !ok {
		return policy.PolicyBundle{}, fmt.Errorf(
			"%w: %s: 配置里没有 %s 的范围（policy.bundles 与 policy.mode 的解析结果不一致）",
			ErrPolicyBundle, path, id)
	}
	contentScope, err := parseConfigScope(wire.Scope)
	if err != nil {
		return policy.PolicyBundle{}, fmt.Errorf("%w: %s: %v", ErrPolicyBundle, path, err)
	}
	if contentScope != refScope {
		return policy.PolicyBundle{}, bundleMismatch(path, "scope",
			refScope.Display(), contentScope.Display())
	}

	b := policy.PolicyBundle{ID: id, Version: ref.Version, Scope: refScope,
		Entitlements: wire.Entitlements}
	if err := b.Validate(); err != nil {
		return policy.PolicyBundle{}, fmt.Errorf("%w: %s: %v", ErrPolicyBundle, path, err)
	}
	return b, nil
}

func bundleMismatch(path, field, want, got string) error {
	return fmt.Errorf("%w: %s 的 %s 与 policy.bundles 引用不一致（引用=%s，内容=%s）："+
		"发新版要同时改引用与内容文件，只改一边等于两个真值来源",
		ErrPolicyBundle, filepath.Base(path), field, want, got)
}

// decodeYAMLStrict 把 YAML 解进目标结构：未知键一律报错。
//
// 为什么绕一圈 JSON：领域对象只带 json tag，而这里要的严格性（写错一个键名就加载失败）
// 和配置文件其余部分用 `dec.KnownFields(true)` 拿到的完全一样。走
// yaml → map[string]any → json 能在不复制领域结构体的前提下拿到同一份严格性
// （json.DisallowUnknownFields）。
func decodeYAMLStrict(raw []byte, target any) error {
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("不是合法的 YAML 映射: %w", err)
	}
	if doc == nil {
		return errors.New("内容为空")
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("转成 JSON 失败: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(encoded))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("结构不合法（未知键、类型不符或必填缺失）: %w", err)
	}
	return nil
}
