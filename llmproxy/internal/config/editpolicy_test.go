package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// §3.H 写侧（策略发布 / 回滚）的地基测试。
//
// 断言重心只有两件事，因为它们决定这个接口能不能碰生产配置：
//  1. **只动目标段**：policy 段之外的字节必须逐位不变（注释是维护信息）。
//  2. **写进去的必须加载得回来**：引用与内容文件是一件事的两半，
//     任何一侧单独可写就意味着热加载时才炸出「两个真值来源」。

// editPolicyBase 是一份没有 policy 段的最小可用配置，注释刻意放在会被替换的位置附近。
const editPolicyBase = `server:
  port: 8787
  # 这行注释属于 server 段，编辑 policy 时不能把它抹掉

providers:
  - name: p1
    base_url: https://a.example/v1
    api_key: sk-not-real-for-tests
    max_data_level: internal
    models: ["*"]

# 文件末尾的注释也不许被牵连
`

func editPolicyShadow(bundleID string, version int) PolicyConfig {
	return PolicyConfig{
		Mode:         "shadow",
		DataLevel:    "internal",
		BundleDir:    "policy-bundles",
		ActiveBundle: bundleID,
		Bundles: []PolicyBundleRef{{
			ID: bundleID, Version: version, Scope: "organization:university",
		}},
	}
}

func TestEditPolicyKeepsBytesOutsideSection(t *testing.T) {
	// 先用加载器认一次基线：这段文本本身必须是一份能跑的 legacy 配置。
	if _, err := parseWithOpts([]byte(editPolicyBase), LoadOptions{Strict: true}); err != nil {
		t.Fatalf("基线配置本身加载不过: %v", err)
	}

	out, err := EditPolicy([]byte(editPolicyBase), editPolicyShadow("university-default", 1))
	if err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	src := string(out)

	// 段外的字节必须一个都没变：前缀是原文，末尾注释还在。
	if !strings.HasPrefix(src, editPolicyBase) {
		t.Errorf("新内容不是「原文 + 追加段」，段前字节被改动了：\n%s", src)
	}
	if !strings.Contains(src, "# 文件末尾的注释也不许被牵连") ||
		!strings.Contains(src, "# 这行注释属于 server 段") {
		t.Errorf("注释被抹掉了：\n%s", src)
	}

	// 写进去的必须加载得回来，而且拿到的就是我们要的那些事实。
	cfg, err := parseWithOpts(out, LoadOptions{Strict: true})
	if err != nil {
		t.Fatalf("写入后的配置加载失败: %v", err)
	}
	if got := cfg.Policy.ModeResolved(); got != PolicyModeShadow {
		t.Errorf("mode = %s", got)
	}
	if got := cfg.Policy.PolicyVersion(); got != "university-default@1" {
		t.Errorf("PolicyVersion = %q，想要引用里的 id@version", got)
	}
	ref, ok := cfg.Policy.ActiveRef()
	if !ok || ref.Version != 1 || ref.ID != "university-default" {
		t.Errorf("ActiveRef = %+v ok=%v", ref, ok)
	}

	// 再写一次同一意图：文本必须逐位相同，否则每次保存都产生一个假 diff。
	again, err := EditPolicy(out, editPolicyShadow("university-default", 1))
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != src {
		t.Errorf("重复写入不幂等：\n--- 第一次\n%s\n--- 第二次\n%s", src, again)
	}

	// 替换而非追加：段只能有一份，否则 YAML 后一份覆盖前一份而 diff 里看不见。
	if n := strings.Count(src, "\npolicy:\n"); n != 1 {
		t.Errorf("policy: 出现 %d 次", n)
	}
}

func TestEditPolicyReplacesExistingSection(t *testing.T) {
	// policy 段夹在中间才有意义：段**后**的键与注释是 EditProviders 那套按行拼接
	// 最容易吃错边界的地方（sectionEnd 找的是第一个缩进不深于 key 的行）。
	const src = `server:
  port: 8787

policy:
  mode: legacy
  # 段内的注释会被重渲染掉 —— 所以调用方一律先备份

routing:
  # 这一段整段都不该被 policy 的编辑碰到
  retry: 2

providers:
  - name: p1
    base_url: https://a.example/v1
    api_key: sk-not-real-for-tests
    max_data_level: internal
    models: ["*"]
`
	out, err := EditPolicy([]byte(src), editPolicyShadow("b1", 2))
	if err != nil {
		t.Fatalf("%v", err)
	}
	got := string(out)
	if strings.Contains(got, "mode: legacy") {
		t.Errorf("旧段没被替换：\n%s", got)
	}
	if !strings.Contains(got, "# 这一段整段都不该被 policy 的编辑碰到") ||
		!strings.Contains(got, "  retry: 2") {
		t.Errorf("段后的 routing 段被吃了：\n%s", got)
	}
	if strings.Contains(got, "段内的注释会被重渲染掉") {
		t.Error("段内注释按设计会被替换掉（所以调用方必须先备份）；留着说明没替换")
	}
	if !strings.HasPrefix(got, "server:\n  port: 8787\n\npolicy:\n") {
		t.Errorf("段前的字节变了：\n%q", got)
	}
	cfg, err := parseWithOpts(out, LoadOptions{Strict: true})
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if cfg.Policy.ModeResolved() != PolicyModeShadow {
		t.Error("替换后的模式不对")
	}
	if len(cfg.Providers) != 1 || cfg.Routing.Retry != 2 {
		t.Errorf("段后的内容变了形: providers=%d retry=%d", len(cfg.Providers), cfg.Routing.Retry)
	}
}

func TestRawPolicyRoundTrip(t *testing.T) {
	want := PolicyConfig{
		Mode:         "enforce",
		DataLevel:    "confidential",
		BundleDir:    "custom-bundles",
		ActiveBundle: "second",
		Bundles: []PolicyBundleRef{
			{ID: "first", Version: 7, Scope: "organization:university"},
			{ID: "second", Version: 12, Scope: "project:cs-lab-7"},
		},
	}
	enabled := false
	want.FallbackToLegacy = &enabled

	src, err := EditPolicy([]byte(editPolicyBase), want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := RawPolicy(src)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if got.Mode != want.Mode || got.DataLevel != want.DataLevel ||
		got.BundleDir != want.BundleDir || got.ActiveBundle != want.ActiveBundle {
		t.Errorf("标量字段回读不一致: %+v", got)
	}
	if !reflect.DeepEqual(got.Bundles, want.Bundles) {
		t.Errorf("Bundles = %+v，want %+v", got.Bundles, want.Bundles)
	}
	// *bool 必须读出「显式 false」而不是「没写」：把 false 读成 nil 等于
	// 一次编辑就把 fail-closed 的决定悄悄改回允许回落。
	if got.FallbackToLegacy == nil || *got.FallbackToLegacy {
		t.Errorf("FallbackToLegacy = %v，想要显式 false", got.FallbackToLegacy)
	}
	// 读→写必须原样回去（控制台的每次保存都以 RawPolicy 为基线）。
	again, err := EditPolicy(src, got)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(src) {
		t.Errorf("RawPolicy→EditPolicy 不闭合：\n--- 原\n%s\n--- 回写\n%s", src, again)
	}
}

func TestRawPolicyEdgeCases(t *testing.T) {
	t.Run("整段缺省返回零值", func(t *testing.T) {
		p, err := RawPolicy([]byte(editPolicyBase))
		if err != nil {
			t.Fatal(err)
		}
		if p.Mode != "" || len(p.Bundles) != 0 || p.FallbackToLegacy != nil {
			t.Errorf("想要零值，实际 %+v", p)
		}
	})

	t.Run("未知键报错而不是静默丢字段", func(t *testing.T) {
		// 这里如果静默丢掉 bundles，界面「保存成功」而策略一条没写进去。
		for _, src := range []string{
			editPolicyBase + "\npolicy:\n  modes: shadow\n",
			editPolicyBase + "\npolicy:\n  mode: shadow\n  bundles:\n    - id: b\n      version: 1\n      scope: organization:u\n      entttlments: []\n",
		} {
			if _, err := RawPolicy([]byte(src)); err == nil {
				t.Errorf("未知键必须失败：\n%s", src)
			} else if !strings.Contains(err.Error(), "未知键") {
				t.Errorf("错误应指出未知键: %v", err)
			}
		}
	})

	t.Run("version 不是整数要失败", func(t *testing.T) {
		src := editPolicyBase + "\npolicy:\n  mode: shadow\n  bundles:\n    - id: b\n      version: three\n      scope: organization:u\n"
		if _, err := RawPolicy([]byte(src)); err == nil || !strings.Contains(err.Error(), "version 要是整数") {
			t.Errorf("想要整数错误，实际 %v", err)
		}
	})

	t.Run("fallback_to_legacy 非布尔要失败", func(t *testing.T) {
		src := editPolicyBase + "\npolicy:\n  mode: shadow\n  fallback_to_legacy: \"no\"\n"
		if _, err := RawPolicy([]byte(src)); err == nil || !strings.Contains(err.Error(), "true 或 false") {
			t.Errorf("实际 %v", err)
		}
	})

	t.Run("原文件不是 YAML 就报错", func(t *testing.T) {
		if _, err := RawPolicy([]byte("\tpolicy: [")); err == nil {
			t.Error("想要解析错误")
		}
	})
}

func TestEditPolicyRefusesUnloadableSection(t *testing.T) {
	// 每一条都必须「写之前就失败」：写进磁盘再靠热加载报错，等于让网关
	// 在一次保存动作之后进入配置不一致的状态。
	cases := []struct {
		name string
		p    PolicyConfig
		want string
	}{
		{
			name: "mode 为空",
			p:    PolicyConfig{Bundles: []PolicyBundleRef{{ID: "b", Version: 1, Scope: "organization:u"}}},
			want: "policy.mode 不能为空",
		},
		{
			name: "shadow 缺分级",
			p:    PolicyConfig{Mode: "shadow", ActiveBundle: "b", Bundles: []PolicyBundleRef{{ID: "b", Version: 1, Scope: "organization:u"}}},
			want: "data_level 必须显式写成",
		},
		{
			// active 必须指向 bundles 里存在的条目：拼错一个字母的 active_bundle
			// 会让整个策略集失效，而配置文本上看起来只是「多了一条引用」。
			name: "active 指向不存在的包",
			p: PolicyConfig{Mode: "shadow", DataLevel: "internal", ActiveBundle: "ghost",
				Bundles: []PolicyBundleRef{{ID: "real", Version: 1, Scope: "organization:university"}}},
			want: "不在 policy.bundles 里",
		},
		{
			name: "版本 0",
			p:    editPolicyShadow("b1", 0),
			want: "version 需要 ≥ 1",
		},
		{
			// | 与 @ 是版本串的分节符：进了 id 之后审计里的版本串就无法还原，
			// 而这条包在界面上完全正常。
			name: "id 含分节符",
			p:    editPolicyShadow("b@1", 1),
			want: "不能含 | 或 @",
		},
		{
			name: "范围缺 kind",
			p: PolicyConfig{Mode: "enforce", DataLevel: "internal", ActiveBundle: "b",
				Bundles: []PolicyBundleRef{{ID: "b", Version: 1, Scope: "university"}}},
			want: "需要写成 kind:id",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := EditPolicy([]byte(editPolicyBase), tc.p)
			if err == nil {
				t.Fatalf("应当拒绝写入: %+v", tc.p)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("错误里没有 %q：\n%v", tc.want, err)
			}
		})
	}

	// mode 为空是唯一由 EditPolicy 自己判的那条（normalize 会把「整段空」当 legacy）。
	if _, err := EditPolicy([]byte(editPolicyBase), PolicyConfig{}); err == nil ||
		!strings.Contains(err.Error(), "policy.mode 不能为空") {
		t.Errorf("实际 %v", err)
	}
	// legacy 是应急开关：只改 mode 也必须写得进去（回滚不该要求先删配置）。
	out, err := EditPolicy([]byte(editPolicyBase), PolicyConfig{Mode: "legacy"})
	if err != nil {
		t.Fatalf("legacy 应可单独写入: %v", err)
	}
	if _, err := parseWithOpts(out, LoadOptions{Strict: true}); err != nil {
		t.Errorf("legacy 段加载失败: %v", err)
	}
}

// ── 内容文件 ───────────────────────────────────────────────

func sampleBundle(id string, version int) policy.PolicyBundle {
	return policy.PolicyBundle{
		ID: id, Version: version,
		Scope: policy.MustScope(policy.ScopeOrganization, "university"),
		Entitlements: []policy.Entitlement{
			{Subject: "*", Resource: "model:*", Action: "chat", Effect: policy.EffectDeny,
				Conditions: map[string]string{"purpose": "chat"}, Source: "handbook §2.4", Version: "v1"},
			{Subject: "role:teacher", Resource: "model:gpt-4o", Action: "chat", Effect: policy.EffectAllow,
				ExpiresAt:  time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
				Conditions: map[string]string{"max-data-level": "internal"}, Source: "目录批复", Version: "v2"},
			{Subject: "uid-alice", Resource: "body:raw", Action: "read", Effect: policy.EffectAllow,
				ExpiresAt: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC), Version: "v3"},
		},
	}
}

func TestRenderBundleReadBundleFileFidelity(t *testing.T) {
	want := sampleBundle("university-default", 3)
	rendered, err := RenderBundle(want)
	if err != nil {
		t.Fatalf("%v", err)
	}
	text := string(rendered)
	// 键名必须是 JSON 形态（加载器靠 json.DisallowUnknownFields 校验）。
	for _, k := range []string{"subject:", "expires_at:", "max_data_level", "conditions:"} {
		if k == "max_data_level" {
			if strings.Contains(text, k) {
				t.Errorf("磁盘形态不该出现下划线条件键（那是会被加载期拒的写法）:\n%s", text)
			}
			continue
		}
		if !strings.Contains(text, k) {
			t.Errorf("渲染结果里没有 %q:\n%s", k, text)
		}
	}
	// 零值 expires_at 必须被去掉：留在文件里会被读成「这条早就过期了」。
	if strings.Contains(text, "0001-01-01") {
		t.Errorf("零值时间戳被写进了磁盘形态:\n%s", text)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "university-default.yaml")
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadBundleFile(path)
	if err != nil {
		t.Fatalf("回读失败: %v\n---\n%s", err, rendered)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("回读与源对象不一致:\n got %+v\nwant %+v", got, want)
	}
}

func TestRenderBundleRejectsIllegalDomain(t *testing.T) {
	// 磁盘形态不能承载一个领域上非法的包：那会让「发布成功」与「加载失败」并存。
	bad := sampleBundle("bad|id", 1)
	if _, err := RenderBundle(bad); err == nil {
		t.Error("id 含分节符必须被拒")
	}
	traversal := sampleBundle("../escape", 1)
	if _, err := RenderBundle(traversal); err == nil {
		t.Error("id 含路径分隔符必须被拒（它是文件名）")
	} else if !strings.Contains(err.Error(), "路径分隔符") {
		t.Errorf("错误应点名文件名规则: %v", err)
	}
}

func TestBundleFilePathRejectsTraversal(t *testing.T) {
	for _, id := range []string{"", " ", "../etc/passwd", "a/b", `a\b`, ".", "..", "a\x00b"} {
		if got, err := BundleFilePath("/tmp/bundles", id); err == nil {
			t.Errorf("id=%q 竟被接受: %s", id, got)
		}
	}
	got, err := BundleFilePath("/tmp/bundles", "t-open")
	if err != nil || got != "/tmp/bundles/t-open.yaml" {
		t.Errorf("正常 id 也要给出确定路径: %s %v", got, err)
	}
}

func TestWriteBundleFileBackupPruneAndLoad(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "policy-bundles")

	// 首版没有旧文件可备份：返回空串而不是假路径。
	if backup, err := WriteBundleFile(dir, sampleBundle("university-default", 1)); err != nil {
		t.Fatal(err)
	} else if backup != "" {
		t.Errorf("首次发布不该有备份，实际 %s", backup)
	}

	for v := 2; v <= bundleBackupKeep+3; v++ {
		backup, err := WriteBundleFile(dir, sampleBundle("university-default", v))
		if err != nil {
			t.Fatalf("v%d: %v", v, err)
		}
		if backup == "" {
			t.Fatalf("v%d 应当产生备份", v)
		}
	}
	entries, err := ListBundleBackups(dir, "university-default")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != bundleBackupKeep {
		t.Errorf("备份留了 %d 份，上限是 %d", len(entries), bundleBackupKeep)
	}
	// 时间戳升序：回滚取「最后一份」的前提就是排序稳定。
	if entries[len(entries)-1] <= entries[0] {
		t.Errorf("备份排序不对: %v", entries)
	}
	// 备份目录里不该留下半成品临时文件。
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "*.new")); len(leftovers) != 0 {
		t.Errorf("残留临时文件: %v", leftovers)
	}

	got, err := ReadBundleFile(BundleFilePathMust(t, dir, "university-default"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != bundleBackupKeep+3 {
		t.Errorf("当前内容版本 = %d", got.Version)
	}
}

func BundleFilePathMust(t *testing.T, dir, id string) string {
	t.Helper()
	p, err := BundleFilePath(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRestoreBundleFrom(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "policy-bundles")
	if _, err := WriteBundleFile(dir, sampleBundle("university-default", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteBundleFile(dir, sampleBundle("university-default", 2)); err != nil {
		t.Fatal(err)
	}
	entries, err := ListBundleBackups(dir, "university-default")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("备份数 = %d，想要 1", len(entries))
	}
	got, newBackup, err := RestoreBundleFrom(dir, "university-default", entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 {
		t.Errorf("回滚出来的版本 = %d，想要 1", got.Version)
	}
	if newBackup == "" {
		t.Error("回滚本身也必须留一份可再回滚的备份")
	}
	// 当前文件已经是 v1，而刚被替换掉的 v2 进了新备份。
	current, err := ReadBundleFile(BundleFilePathMust(t, dir, "university-default"))
	if err != nil {
		t.Fatal(err)
	}
	if current.Version != 1 {
		t.Errorf("磁盘当前版本 = %d", current.Version)
	}

	// 回滚来源必须属于这个包：否则这个接口就是任意文件读取。
	other := filepath.Join(t.TempDir(), "policy-bundles")
	if _, err := WriteBundleFile(other, sampleBundle("another-bundle", 5)); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteBundleFile(other, sampleBundle("another-bundle", 6)); err != nil {
		t.Fatal(err)
	}
	otherBackups, err := ListBundleBackups(other, "another-bundle")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := RestoreBundleFrom(other, "university-default", otherBackups[0]); err == nil {
		t.Error("用别的包的备份回滚必须失败")
	}
	secret := filepath.Join(dir, "config.yaml.bak-20260101-000000.000000")
	if err := os.WriteFile(secret, []byte("providers:\n  - api_key: sk-not-real\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RestoreBundleFrom(dir, "university-default", secret); err == nil {
		t.Error("非本包备份（哪怕后缀像）必须被拒")
	}
	if _, _, err := RestoreBundleFrom(dir, "university-default", "/etc/passwd"); err == nil {
		t.Error("任意路径必须被拒")
	}
}

// ── 引用 + 内容：一次发布必须两边一致 ──────────────────────

// publishToTempDir 模拟控制台的发布动作：写内容文件、改配置引用，然后按
// server 的加载通道（LoadFileWithOptions + BundleBaseDir）验一遍整份配置。
func publishToTempDir(t *testing.T, bundleID string, version int, src []byte) *Config {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	bundleDir := filepath.Join(dir, "policy-bundles")
	if _, err := WriteBundleFile(bundleDir, sampleBundle(bundleID, version)); err != nil {
		t.Fatalf("写内容文件失败: %v", err)
	}
	p := editPolicyShadow(bundleID, version)
	out, err := EditPolicy(src, p)
	if err != nil {
		t.Fatalf("改引用失败: %v", err)
	}
	if err := os.WriteFile(cfgPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFileWithOptions(cfgPath, LoadOptions{Strict: true})
	if err != nil {
		t.Fatalf("整份配置加载失败: %v", err)
	}
	if _, err := cfg.Policy.LoadBundles(cfg.BundleBaseDir()); err != nil {
		t.Fatalf("按引用加载内容失败: %v", err)
	}
	return cfg
}

func TestPublishRoundTripLoadsAsBundleSet(t *testing.T) {
	cfg := publishToTempDir(t, "university-default", 3, []byte(editPolicyBase))
	set, err := cfg.Policy.LoadBundles(cfg.BundleBaseDir())
	if err != nil {
		t.Fatal(err)
	}
	// 版本串来自实际加载的集合（§3.0：它是 policy version 的唯一来源）。
	got, err := set.PolicyVersion()
	if err != nil {
		t.Fatal(err)
	}
	if got != "university-default@3" {
		t.Errorf("PolicyVersion = %q", got)
	}
	if set.Len() != 1 {
		t.Errorf("包数 = %d", set.Len())
	}
	// 加载出来的规则必须与发布的那批逐字一致（条件键、分级、有效期都不许变形）。
	want := sampleBundle("university-default", 3)
	if !reflect.DeepEqual(set.Bundles()[0], want) {
		t.Errorf("加载内容与发布内容不一致:\n got %+v\nwant %+v", set.Bundles()[0], want)
	}
}

func TestOneSidedPublishFailsLoudly(t *testing.T) {
	// 这是写侧最要紧的一条：只改引用或只改内容，都必须以加载失败收场，
	// 而不是带着半个真值来源上线。
	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "policy-bundles")
	if _, err := WriteBundleFile(bundleDir, sampleBundle("b1", 1)); err != nil {
		t.Fatal(err)
	}

	// 引用说 v2，内容还是 v1。
	p := editPolicyShadow("b1", 2)
	out, err := EditPolicy([]byte(editPolicyBase), p)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFileWithOptions(cfgPath, LoadOptions{Strict: true})
	if err != nil {
		t.Fatalf("配置段本身应可加载: %v", err)
	}
	if _, err := cfg.Policy.LoadBundles(cfg.BundleBaseDir()); err == nil {
		t.Fatal("引用与内容不一致时必须加载失败")
	} else if !strings.Contains(err.Error(), "发新版要同时改引用与内容文件") {
		t.Errorf("错误要给出可执行的下一步，实际: %v", err)
	}

	// 反过来：配置根本没这条引用。
	p2 := editPolicyShadow("ghost", 1)
	out2, err := EditPolicy([]byte(editPolicyBase), p2)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath2 := filepath.Join(dir, "config2.yaml")
	if err := os.WriteFile(cfgPath2, out2, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg2, err := LoadFileWithOptions(cfgPath2, LoadOptions{Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg2.Policy.LoadBundles(cfg2.BundleBaseDir()); err == nil ||
		!strings.Contains(err.Error(), "内容文件不存在") {
		t.Errorf("想要缺内容文件的错误，实际 %v", err)
	}
}

func TestLoadBundlesRejectsUnsafeIDAndEmptySet(t *testing.T) {
	// id 当文件名用：配置里写 ../escape 不能让加载器去读目录外的文件。
	p := PolicyConfig{
		Mode:         "enforce",
		DataLevel:    "internal",
		ActiveBundle: "../escape",
		Bundles:      []PolicyBundleRef{{ID: "../escape", Version: 1, Scope: "organization:university"}},
	}
	var warnings []string
	if err := p.normalize(nil, &warnings); err != nil {
		t.Fatalf("领域上这个引用是合法的（id 只禁 |@）: %v", err)
	}
	if _, err := p.LoadBundles(t.TempDir()); err == nil {
		t.Fatal("含路径分隔符的 id 必须被拒")
	} else if !strings.Contains(err.Error(), "路径分隔符") {
		t.Errorf("实际 %v", err)
	}

	// legacy 不加载内容：回滚开关必须能做到「改一行 mode 就立刻停」。
	var legacy PolicyConfig
	if err := legacy.normalize(nil, &warnings); err != nil {
		t.Fatal(err)
	}
	set, err := legacy.LoadBundles(".")
	if set != nil || err != nil {
		t.Errorf("legacy 应返回 (nil, nil)，实际 set=%v err=%v", set, err)
	}
}

func TestLoadBundlesIsAllOrNothing(t *testing.T) {
	// 引用了 2 个包、磁盘上只有 1 个内容文件：必须整体失败。
	// 放过它等于带着半个策略集上线，而版本串看起来完全正常。
	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "policy-bundles")
	if _, err := WriteBundleFile(bundleDir, sampleBundle("present", 1)); err != nil {
		t.Fatal(err)
	}
	p := PolicyConfig{
		Mode:         "shadow",
		DataLevel:    "internal",
		BundleDir:    "policy-bundles",
		ActiveBundle: "present",
		Bundles: []PolicyBundleRef{
			{ID: "present", Version: 1, Scope: "organization:university"},
			{ID: "missing", Version: 1, Scope: "organization:university"},
		},
	}
	var warnings []string
	if err := p.normalize(nil, &warnings); err != nil {
		t.Fatal(err)
	}
	if _, err := p.LoadBundles(dir); err == nil {
		t.Fatal("缺一个内容文件必须整体失败")
	} else if !strings.Contains(err.Error(), "missing") {
		t.Errorf("错误应点名缺的那个包: %v", err)
	}
}
