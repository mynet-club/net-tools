package config

// policy 段与控制台策略包的编辑层（§3.H 的写侧地基）。
//
// 为什么和 EditProviders 走同一条路（解析定位 → 只重渲染目标段 → 按行拼接）：
// 那份文件里的注释是维护信息，整体 marshal 会把它们全抹掉。段**内部**的注释会
// 被重渲染掉，所以调用方一律先备份 —— 与 providers 同一套取舍与同一套事故半径。
//
// 为什么引用（id/version/scope）必须由这里改、内容文件由这里写：
// loadOneBundle 逐字段核对引用与内容，只改一边等于制造两个真值来源，
// 而错误信息会直接指认「发新版要同时改引用与内容文件」。写侧把两边收在同一个
// 流程里（先写内容、再校验整份配置、最后原子替换），让「只改了一边」在这条路上
// 根本不可表达。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// policySectionComment 是重渲染时写进 policy 段的第一行说明。
const policySectionComment = "  # 本段由控制台或手工编辑维护；写回时只会替换这一段的内容。\n"

// policyKnownKeys 是 policy 段的合法键名，用于 RawPolicy 的「未知键即报错」。
//
// 为什么手写这张表而不是复用加载器的 KnownFields：这里只解出一个**段**，
// 而 dec.KnownFields 作用在整份文档上。漏掉一个键名不会让解析变松，
// 只会让新加的键在控制台路径上被误报成未知键 —— 那比静默丢字段更早暴露。
var policyKnownKeys = []string{"mode", "active_bundle", "bundle_dir", "data_level", "fallback_to_legacy", "bundles"}

// bundleRefKeys 是 policy.bundles 一条引用的合法键名。
var bundleRefKeys = []string{"id", "version", "scope"}

// RawPolicy 从配置文件**原文**里读出 policy 段。
//
// 从原文读而不是从加载后的 Config 读：控制台要改的是文件里那一份，
// 而加载后的对象已经补上了派生值（refIndex/scopeRefs），拿它当编辑基线会把
// 运行时推导结果误当成用户写过的东西。
//
// 段不存在时返回零值（Mode 为空）而不是报错：legacy 部署根本没有这一段，
// 「第一次启用 3.0」与「改已有配置」必须走同一个接口。
func RawPolicy(src []byte) (PolicyConfig, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(src, &root); err != nil {
		return PolicyConfig{}, fmt.Errorf("原配置解析失败: %w", err)
	}
	_, val := findTopLevelKey(&root, "policy")
	if val == nil {
		return PolicyConfig{}, nil
	}
	var doc map[string]any
	if err := val.Decode(&doc); err != nil {
		return PolicyConfig{}, fmt.Errorf("policy 段不是合法的 YAML 映射: %w", err)
	}
	if doc == nil {
		return PolicyConfig{}, nil
	}
	for key := range doc {
		if !containsString(policyKnownKeys, key) {
			return PolicyConfig{}, fmt.Errorf("policy 段有未知键 %q（可用：%s）", key, strings.Join(policyKnownKeys, "、"))
		}
	}
	refs, err := rawBundleRefs(doc["bundles"])
	if err != nil {
		return PolicyConfig{}, err
	}
	p := PolicyConfig{
		Mode:         scalarString(doc["mode"]),
		ActiveBundle: scalarString(doc["active_bundle"]),
		BundleDir:    scalarString(doc["bundle_dir"]),
		DataLevel:    scalarString(doc["data_level"]),
		Bundles:      refs,
	}
	if v := doc["fallback_to_legacy"]; v != nil {
		enabled, ok := v.(bool)
		if !ok {
			return PolicyConfig{}, fmt.Errorf("policy.fallback_to_legacy 要是 true 或 false，当前是 %T", v)
		}
		p.FallbackToLegacy = &enabled
	}
	return p, nil
}

// EditPolicy 把 src 里的 policy 段替换成 p，返回新的文件内容。
// src 必须能解析，否则报错且不改动任何东西。
//
// 写之前先过加载期那份校验（normalize）：让「写不进去的配置」和
// 「加载不过的配置」永远是同一批，而不是让运维在热加载日志里才发现。
func EditPolicy(src []byte, p PolicyConfig) ([]byte, error) {
	if strings.TrimSpace(p.Mode) == "" {
		return nil, fmt.Errorf("policy.mode 不能为空（可用值：legacy、shadow、enforce）")
	}
	var warnings []string
	if err := p.normalize(nil, &warnings); err != nil {
		return nil, err
	}
	rendered, err := renderPolicy(p)
	if err != nil {
		return nil, err
	}
	return spliceSection(src, "policy", rendered)
}

// renderPolicy 渲染 policy 段正文（每行已带两格缩进）。
//
// 字段顺序固定：mode → data_level → fallback_to_legacy → bundle_dir → active_bundle →
// bundles。同一个意图在任何机器上写出同一份文本，diff 才有意义。
func renderPolicy(p PolicyConfig) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(policySectionComment)
	for _, kv := range [][2]string{{"mode", p.Mode}, {"data_level", p.DataLevel}, {"bundle_dir", p.BundleDir}, {"active_bundle", p.ActiveBundle}} {
		if strings.TrimSpace(kv[1]) == "" {
			continue
		}
		v, err := yamlScalar(kv[1])
		if err != nil {
			return nil, fmt.Errorf("policy.%s %w", kv[0], err)
		}
		fmt.Fprintf(&b, "  %s: %s\n", kv[0], v)
	}
	if p.FallbackToLegacy != nil {
		fmt.Fprintf(&b, "  fallback_to_legacy: %v\n", *p.FallbackToLegacy)
	}
	if len(p.Bundles) == 0 {
		fmt.Fprintf(&b, "  bundles: []\n")
		return b.Bytes(), nil
	}
	fmt.Fprintf(&b, "  bundles:\n")
	for _, r := range p.Bundles {
		id, err := yamlScalar(r.ID)
		if err != nil {
			return nil, fmt.Errorf("策略包 id %w", err)
		}
		scope, err := yamlScalar(r.Scope)
		if err != nil {
			return nil, fmt.Errorf("策略包 %s 的 scope %w", r.ID, err)
		}
		fmt.Fprintf(&b, "    - id: %s\n      version: %d\n      scope: %s\n", id, r.Version, scope)
	}
	return b.Bytes(), nil
}

// rawBundleRefs 解出 policy.bundles 的引用列表，逐条核对键名。
func rawBundleRefs(v any) ([]PolicyBundleRef, error) {
	if v == nil {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("policy.bundles 要是列表，当前是 %T", v)
	}
	out := make([]PolicyBundleRef, 0, len(list))
	for i, item := range list {
		doc, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("policy.bundles 第 %d 条不是映射", i+1)
		}
		for key := range doc {
			if !containsString(bundleRefKeys, key) {
				return nil, fmt.Errorf("policy.bundles 第 %d 条有未知键 %q（可用：%s）",
					i+1, key, strings.Join(bundleRefKeys, "、"))
			}
		}
		ref := PolicyBundleRef{ID: scalarString(doc["id"]), Scope: scalarString(doc["scope"])}
		switch n := doc["version"].(type) {
		case int:
			ref.Version = n
		case float64:
			ref.Version = int(n)
		case nil:
		default:
			return nil, fmt.Errorf("policy.bundles 第 %d 条的 version 要是整数", i+1)
		}
		out = append(out, ref)
	}
	return out, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// scalarString 取一个 YAML 标量的字符串形态。
//
// 只用于「这里本该是字符串」的位置：非字符串走 fmt.Sprint 而不是拒绝，是因为
// YAML 会把 unquoted 的 internal、t-open 一律解成 string，能落到非 string 分支的
// 都是写错了类型，而那由 normalize 与加载器的类型校验负责指认。
func scalarString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

// ── 策略包内容文件 ─────────────────────────────────────────

// BundleFilePath 返回某个包 id 的内容文件路径。
//
// 报错而不是清洗：id 会变成文件名的一段，含 / 或 .. 就等于让请求体挑路径，
// 而静默替换会让「发布到 t-open」和「写到别处」变成同一件事。
func BundleFilePath(dir, id string) (string, error) {
	name, err := bundleFileName(id)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

func bundleFileName(id string) (string, error) {
	v := strings.TrimSpace(id)
	switch {
	case v == "":
		return "", fmt.Errorf("策略包 id 不能为空")
	case v == "." || v == "..":
		return "", fmt.Errorf("策略包 id 不能是 %q（它要当文件名用）", v)
	case strings.ContainsAny(v, `/\`):
		return "", fmt.Errorf("策略包 id %q 不能含路径分隔符（内容文件固定放在 bundle_dir 下）", id)
	case strings.ContainsAny(v, "\x00\n\r"):
		return "", fmt.Errorf("策略包 id %q 含控制字符", id)
	}
	return v + ".yaml", nil
}

// RenderBundle 把策略包写成内容文件的磁盘形态（与 loadOneBundle 读的严格同构）。
//
// 走「领域对象 → JSON → map → YAML」而不是直接 yaml.Marshal：领域对象只带 json tag，
// 而加载器也是靠这条链拿到键名的。换任何一条路都会出现「写得出来、读不回来」。
func RenderBundle(b policy.PolicyBundle) ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	if _, err := bundleFileName(b.ID); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(map[string]any{
		"id": strings.TrimSpace(b.ID), "version": b.Version,
		"scope": b.Scope.Display(), "entitlements": b.Entitlements,
	})
	if err != nil {
		return nil, err
	}
	// 不用 dec.UseNumber()：json.Number 是字符串类型，yaml 会把它编码成
	// **带引号的**数字（version: "3"），而加载器按 int 读它 —— 于是写出一个
	// 自己读不回来的文件。版本号是整数且远小于 2^53，走默认 float64 不会失精度。
	var doc map[string]any
	if err := json.Unmarshal(encoded, &doc); err != nil {
		return nil, err
	}
	dropZeroExpiry(doc["entitlements"])
	rendered, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var head bytes.Buffer
	head.WriteString("# 由控制台或手工维护的策略包内容文件；配置里的引用必须与这里的 id/version/scope 一致。\n")
	head.Write(rendered)
	return head.Bytes(), nil
}

// dropZeroExpiry 去掉「没有期限」的规则里那个零值时间戳。
//
// time.Time 上的 omitempty 不生效（结构体不算空值），零值会被写成
// 0001-01-01T00:00:00Z。它能被读回成零值，但出现在文件里会被当成
// 「这条早就过期了」—— 而真实含义是「没有期限」。
func dropZeroExpiry(v any) {
	list, ok := v.([]any)
	if !ok {
		return
	}
	for _, item := range list {
		rule, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if at, ok := rule["expires_at"].(string); ok && strings.HasPrefix(at, "0001-01-01") {
			delete(rule, "expires_at")
		}
	}
}

// ReadBundleFile 读一个内容文件并还原成领域对象。
//
// 不做引用一致性核对（那是 loadOneBundle 的事）：发布流程要先看内容再改引用，
// 而回滚要读的是一份还没进配置的备份。
func ReadBundleFile(path string) (policy.PolicyBundle, error) {
	wire, err := readBundleWire(path)
	if err != nil {
		return policy.PolicyBundle{}, err
	}
	scope, err := parseConfigScope(wire.Scope)
	if err != nil {
		return policy.PolicyBundle{}, fmt.Errorf("%w: %s: %v", ErrPolicyBundle, path, err)
	}
	b := policy.PolicyBundle{ID: wire.ID, Version: wire.Version, Scope: scope, Entitlements: wire.Entitlements}
	if err := b.Validate(); err != nil {
		return policy.PolicyBundle{}, fmt.Errorf("%w: %s: %v", ErrPolicyBundle, path, err)
	}
	return b, nil
}

// bundleBackupKeep 是每个内容文件保留的历史份数。
//
// 回滚靠的就是这些备份：只保留最新一份等于「发错了就只能手写回去」。
const bundleBackupKeep = 10

// WriteBundleFile 写内容文件，返回被替换掉的旧文件备份路径（没有旧文件时为空）。
//
// 写完立刻回读一次并核对领域对象自洽：写到一半被截断、或者渲染出的文本读不回来，
// 都必须在这一步失败，而不是等到网关热加载时才发现整段策略没了。
func WriteBundleFile(dir string, b policy.PolicyBundle) (string, error) {
	path, err := BundleFilePath(dir, b.ID)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建策略包目录失败: %w", err)
	}
	rendered, err := RenderBundle(b)
	if err != nil {
		return "", err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, rendered, 0o600); err != nil {
		return "", fmt.Errorf("写策略包临时文件失败: %w", err)
	}
	got, err := ReadBundleFile(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if got.Stamp() != b.Stamp() || len(got.Entitlements) != len(b.Entitlements) {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("%w: 写出的 %s 回读后是 %s（%d 条规则），与要发布的 %s（%d 条）不一致",
			ErrPolicyBundle, filepath.Base(path), got.Stamp(), len(got.Entitlements),
			b.Stamp(), len(b.Entitlements))
	}
	backup := ""
	old, err := os.ReadFile(path)
	switch {
	case err == nil:
		// 时间戳带微秒：同一秒内连发两版会把前一份备份盖掉，等于少一代可回滚历史。
		backup = fmt.Sprintf("%s.bak-%s", path, time.Now().Format("20060102-150405.000000"))
		if err := os.WriteFile(backup, old, 0o600); err != nil {
			_ = os.Remove(tmp)
			return "", fmt.Errorf("备份旧策略包失败，已放弃写入: %w", err)
		}
		pruneBundleBackups(path)
	case !os.IsNotExist(err):
		_ = os.Remove(tmp)
		return "", fmt.Errorf("读取旧策略包失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("替换策略包失败: %w", err)
	}
	return backup, nil
}

// ListBundleBackups 返回某个包的可回滚备份，按时间升序（最新在最后）。
func ListBundleBackups(dir, id string) ([]string, error) {
	path, err := BundleFilePath(dir, id)
	if err != nil {
		return nil, err
	}
	entries, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)
	return entries, nil
}

// RestoreBundleFrom 把某个包换回指定备份的内容，返回恢复出来的内容与本次新产生的备份路径。
//
// 只认「这个包自己的备份」：路径必须由 ListBundleBackups 给出来且落在 bundle_dir 下，
// 否则这个接口就退化成了任意文件读取。
func RestoreBundleFrom(dir, id, backupPath string) (policy.PolicyBundle, string, error) {
	path, err := BundleFilePath(dir, id)
	if err != nil {
		return policy.PolicyBundle{}, "", err
	}
	want := filepath.Clean(backupPath)
	prefix := filepath.Clean(path) + ".bak-"
	if !strings.HasPrefix(want, prefix) || want == filepath.Clean(path) {
		return policy.PolicyBundle{}, "", fmt.Errorf("回滚来源 %q 不是策略包 %s 自己的备份文件", backupPath, id)
	}
	b, err := ReadBundleFile(want)
	if err != nil {
		return policy.PolicyBundle{}, "", err
	}
	// 备份里的 id 必须与要回滚的那个包一致：ReadBundleFile 只保证内容自洽。
	if strings.TrimSpace(b.ID) != strings.TrimSpace(id) {
		return policy.PolicyBundle{}, "", fmt.Errorf("%w: %s 的内容属于包 %s，与要回滚的 %s 不一致",
			ErrPolicyBundle, filepath.Base(want), b.ID, id)
	}
	newBackup, err := WriteBundleFile(dir, b)
	if err != nil {
		return policy.PolicyBundle{}, "", err
	}
	return b, newBackup, nil
}

func pruneBundleBackups(path string) {
	entries, err := filepath.Glob(path + ".bak-*")
	if err != nil || len(entries) <= bundleBackupKeep {
		return
	}
	sort.Strings(entries)
	for _, old := range entries[:len(entries)-bundleBackupKeep] {
		_ = os.Remove(old)
	}
}
