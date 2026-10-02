package config

import (
	"strings"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 3.0 接线块（§3.0）的加载测试。这里的每一条都对应一个「配错之后的后果」：
// 缺省语义、模式拼写、策略版本来源、范围 lint —— 都是接线时最容易靠猜的地方。

// cfg30Base 是一份最小的可用配置：policy 段由用例自己拼上去。
//
// max_data_level 一律带上：3.0 参与判定（mode ≠ legacy）时它是已启用供应商的必填项，
// 而这份底座同时被 legacy 与 shadow/enforce 的用例用着。legacy 下它不参与任何判定。
const cfg30Base = `
server:
  port: 8787
providers:
  - name: p1
    base_url: https://a.example/v1
    api_key: sk-not-real-for-tests
    max_data_level: internal
    models: ["*"]
`

func cfg30(t *testing.T, policySection string) (*Config, error) {
	t.Helper()
	src := cfg30Base
	if policySection != "" {
		src += "\n" + policySection + "\n"
	}
	return parseWithOpts([]byte(src), LoadOptions{Strict: true})
}

func cfg30With(t *testing.T, policySection string, known KnownScopes) (*Config, error) {
	t.Helper()
	src := cfg30Base
	if policySection != "" {
		src += "\n" + policySection + "\n"
	}
	return parseWithOpts([]byte(src), LoadOptions{Strict: true, KnownScopes: known})
}

func mustCfg30(t *testing.T, policySection string) *Config {
	t.Helper()
	cfg, err := cfg30(t, policySection)
	if err != nil {
		t.Fatalf("加载失败: %v\n---\n%s", err, policySection)
	}
	return cfg
}

// cfg30KnownScopes 是一副最小目录：只认列出来的那几个范围。
type cfg30KnownScopes struct{ refs []policy.ScopeRef }

func (k cfg30KnownScopes) HasScope(s policy.ScopeRef) bool {
	for _, r := range k.refs {
		if r == s {
			return true
		}
	}
	return false
}

const cfg30ValidShadow = `
config_schema_version: 3
policy:
  mode: shadow
  data_level: internal
  active_bundle: university-default-v1
  bundles:
    - id: university-default-v1
      version: 3
      scope: organization:university
`

func TestPolicyAbsentMeansLegacy(t *testing.T) {
	cfg := mustCfg30(t, "")
	if got := cfg.Policy.ModeResolved(); got != PolicyModeLegacy {
		t.Errorf("mode = %s，整段缺省必须是 legacy（升级二进制不动配置）", got)
	}
	if cfg.Policy.UsesPolicy() {
		t.Error("legacy 下 UsesPolicy 不该为真")
	}
	// legacy 不产策略版本：空串表示「当时根本没有 3.0 判定」，
	// 比编一个 legacy@0 诚实，回放时也不会误以为有一份可复现的策略。
	if got := cfg.Policy.PolicyVersion(); got != "" {
		t.Errorf("PolicyVersion = %q，legacy 应为空串", got)
	}
	if !cfg.Policy.FallbackToLegacyEnabled() {
		t.Error("fallback_to_legacy 缺省必须是 true（新路径必须可回滚）")
	}
	if *cfg.SchemaVersion != SchemaVersionLegacy {
		t.Errorf("config_schema_version 缺省 = %d，想要 %d", *cfg.SchemaVersion, SchemaVersionLegacy)
	}
}

func TestPolicyShadowProducesVersion(t *testing.T) {
	cfg := mustCfg30(t, cfg30ValidShadow)
	if !cfg.Policy.UsesPolicy() {
		t.Fatal("shadow 也是「3.0 参与」：它产出计划，只是不改路由")
	}
	if cfg.Policy.EnforcesPolicy() {
		t.Error("shadow 不该被报告为 enforce")
	}
	// shadow 也必须产生 policy version（§3.0）：否则事后无法复现当时算出了什么。
	if got := cfg.Policy.PolicyVersion(); got != "university-default-v1@3" {
		t.Errorf("PolicyVersion = %q，想要 id@version 形态", got)
	}
	scope, ok := cfg.Policy.ActiveScope()
	if !ok {
		t.Fatal("生效范围必须解析出来")
	}
	if scope != policy.MustScope(policy.ScopeOrganization, "university") {
		t.Errorf("ActiveScope = %s", scope.Display())
	}
	if *cfg.SchemaVersion != SchemaVersion3 {
		t.Errorf("schema = %d", *cfg.SchemaVersion)
	}
}

func TestPolicyLegacyKeepsBundlesButWarns(t *testing.T) {
	// 回滚开关要能「改成 legacy 就立刻停」，删掉整段配置不该是回滚的前置动作。
	src := `
policy:
  mode: legacy
  active_bundle: university-default-v1
  bundles:
    - id: university-default-v1
      version: 3
      scope: organization:university
`
	cfg := mustCfg30(t, src)
	if cfg.Policy.PolicyVersion() != "" {
		t.Error("legacy 下不得产出策略版本，否则审计会以为 3.0 参与过")
	}
	if len(cfg.Warnings) == 0 || !strings.Contains(cfg.Warnings[0], "不会生效") {
		t.Errorf("应留一条「bundles 不生效」的告警，实际 %v", cfg.Warnings)
	}
}

func TestPolicyValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "模式拼错",
			src:  "policy:\n  mode: SHADOW\n  active_bundle: b\n  bundles:\n    - id: b\n      version: 1\n      scope: organization:university\n",
			want: "只能是 shadow、enforce 或 legacy",
		},
		{
			name: "未知模式",
			src:  "policy:\n  mode: canary\n",
			want: "只能是 shadow、enforce 或 legacy",
		},
		{
			// 配了包却不写模式：既不能猜 legacy（那些包静默不生效），
			// 也不能猜 shadow（运维会以为差异报告已经有了）。
			name: "缺模式但配了包",
			src:  "policy:\n  bundles:\n    - id: b\n      version: 1\n      scope: organization:university\n",
			want: "policy.mode 必须显式写",
		},
		{
			name: "shadow 没有包",
			src:  "policy:\n  mode: shadow\n",
			want: "至少一个 policy.bundles",
		},
		{
			name: "shadow 没有 active 指针",
			src:  "policy:\n  mode: shadow\n  bundles:\n    - id: b\n      version: 1\n      scope: organization:university\n",
			want: "必须写 policy.active_bundle",
		},
		{
			name: "active 指向不存在的包",
			src:  "policy:\n  mode: enforce\n  active_bundle: ghost\n  bundles:\n    - id: b\n      version: 1\n      scope: organization:university\n",
			want: "不在 policy.bundles 里（可用：b）",
		},
		{
			name: "版本从 1 起",
			src:  "policy:\n  mode: enforce\n  active_bundle: b\n  bundles:\n    - id: b\n      version: 0\n      scope: organization:university\n",
			want: "version 需要 ≥ 1",
		},
		{
			// id 里的 | 与 @ 是版本串的分节符，进了 id 就会让审计里的版本无法还原。
			name: "id 含分节符",
			src:  "policy:\n  mode: enforce\n  active_bundle: b@1\n  bundles:\n    - id: b@1\n      version: 1\n      scope: organization:university\n",
			want: "不能含 | 或 @",
		},
		{
			name: "范围必须带 kind",
			src:  "policy:\n  mode: enforce\n  active_bundle: b\n  bundles:\n    - id: b\n      version: 1\n      scope: university\n",
			want: "需要写成 kind:id",
		},
		{
			name: "未知范围类型",
			src:  "policy:\n  mode: enforce\n  active_bundle: b\n  bundles:\n    - id: b\n      version: 1\n      scope: college:university\n",
			want: "可用值：user、organization、project、system",
		},
		{
			name: "范围 ID 含冒号",
			src:  "policy:\n  mode: enforce\n  active_bundle: b\n  bundles:\n    - id: b\n      version: 1\n      scope: organization:a:b\n",
			want: "不能含冒号",
		},
		{
			// 同 id 两版意味着加载逻辑出错，而不是「策略叠加」：
			// 若这里放过，active_bundle 到底指哪一版就不确定了。
			name: "重复 id",
			src:  "policy:\n  mode: enforce\n  active_bundle: b\n  bundles:\n    - id: b\n      version: 1\n      scope: organization:u1\n    - id: b\n      version: 2\n      scope: organization:u1\n",
			want: "出现多次",
		},
		{
			// shadow 不改 provider，这个开关在影子模式没有作用点；
			// 让它通过就等于发出一份「看起来 fail-closed」的假象配置。
			name: "shadow 关回落",
			src:  "policy:\n  mode: shadow\n  data_level: internal\n  fallback_to_legacy: false\n  active_bundle: b\n  bundles:\n    - id: b\n      version: 1\n      scope: organization:university\n",
			want: "fallback_to_legacy 无意义",
		},
		{
			// 分级不给缺省值：猜 public 会把敏感流量当公开流量放行，
			// 猜 restricted 会让每条 deny 规则都命中。两种猜法都让差异报告失去意义，
			// 而错误的方式是「看起来配好了」。
			name: "shadow 缺 data_level",
			src:  "policy:\n  mode: shadow\n  active_bundle: b\n  bundles:\n    - id: b\n      version: 1\n      scope: organization:university\n",
			want: "policy.data_level 必须显式写成",
		},
		{
			name: "data_level 拼错",
			src:  "policy:\n  mode: enforce\n  data_level: sensative\n  active_bundle: b\n  bundles:\n    - id: b\n      version: 1\n      scope: organization:university\n",
			want: "未知的数据分级",
		},
		{
			name: "字段名拼错必须炸",
			src:  "policy:\n  modes: shadow\n",
			want: "field modes not found",
		},
		{
			name: "比二进制新的结构版本",
			src:  "config_schema_version: 4\n",
			want: "比本二进制支持的",
		},
		{
			name: "结构版本过小",
			src:  "config_schema_version: 1\n",
			want: "需要是 2 或 3",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cfg30(t, tc.src)
			if err == nil {
				t.Fatalf("应当加载失败，配置：\n%s", tc.src)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("错误里没有 %q：\n%v", tc.want, err)
			}
		})
	}
}

func TestProviderDataLevelFact(t *testing.T) {
	// 分级门要比的是「这家上游最多能承接哪一级」，而 2.x 的配置里没有这个事实。
	// 启用 3.0 时必须在加载期逐家要到手：留到运行期只有两种下场 ——
	// 接线替它猜一个（审计里就出现一份「经过合规判定」的假计划），
	// 或者整池 candidate_level_excluded（运维看到 0% 一致率却查不出是漏配）。
	const undeclared = `
server:
  port: 8787
providers:
  - name: declared
    base_url: https://a.example/v1
    api_key: sk-not-real-for-tests
    max_data_level: confidential
    models: ["*"]
  - name: undeclared
    base_url: https://b.example/v1
    api_key: sk-not-real-for-tests
    models: ["*"]
`
	if _, err := parseWithOpts([]byte(undeclared+cfg30ValidShadow), LoadOptions{Strict: true}); err == nil {
		t.Fatal("shadow 下未声明分级的供应商必须让加载失败")
	} else {
		msg := err.Error()
		// 点名到具体哪一家：两份供应商配置里只有一家漏配时，报错要能直接指向它。
		if !strings.Contains(msg, "max_data_level") || !strings.Contains(msg, "undeclared") {
			t.Errorf("错误应点名缺配的供应商: %v", err)
		}
		if strings.Contains(msg, "declared、") {
			t.Errorf("已声明的供应商不该被牵连: %v", err)
		}
	}

	// 同一个缺配在 legacy 下不报错：回滚开关不该附带一次配置迁移。
	legacy, err := parseWithOpts([]byte(undeclared), LoadOptions{Strict: true})
	if err != nil {
		t.Fatalf("legacy 下不该要求分级声明: %v", err)
	}
	if got := legacy.Normalized[1].MaxDataLevel; got.Valid() {
		t.Errorf("未声明应留零值 LevelUnknown（让调用方看得出没依据），实际 %s", got)
	}
	// 取判定用的上限时按最低级：用户自配上游就是这条路径（他们没有申报渠道）。
	if got := legacy.Normalized[1].DataLevelCeiling(); got != policy.LevelPublic {
		t.Errorf("未声明的上限 = %s，want public（缺依据时收紧而不是放开）", got)
	}
	if got := legacy.Normalized[0].DataLevelCeiling(); got != policy.LevelConfidential {
		t.Errorf("已声明的上限 = %s，want confidential", got)
	}

	// 停用的供应商不要求声明：它不参与任何判定，逼运维给一条死配置填合规事实，
	// 只会让人把 mode 改回 legacy 来「先跑起来」。
	if _, err := parseWithOpts([]byte(strings.Replace(undeclared,
		"  - name: undeclared\n", "  - name: undeclared\n    enabled: false\n", 1)+cfg30ValidShadow),
		LoadOptions{Strict: true}); err != nil {
		t.Errorf("停用供应商缺分级声明不该失败: %v", err)
	}

	// 拼错等级在任何模式下都炸：把拼错降级成「当作没配」会让一条本来想收紧的
	// 声明静默变成不收紧，那是最难查的一类合规漏洞。
	typo := strings.Replace(undeclared, "max_data_level: confidential", "max_data_level: sensative", 1)
	if _, err := parseWithOpts([]byte(typo), LoadOptions{Strict: true}); err == nil ||
		!strings.Contains(err.Error(), "max_data_level") {
		t.Errorf("拼错的分级必须报错并点名 max_data_level: %v", err)
	}
}

func TestPolicyFallbackToLegacyExplicit(t *testing.T) {
	// enforce 下显式关掉回落是合法的 fail-closed 决定，必须原样保留，
	// 不能被「默认 true」的规范化悄悄改掉。
	src := `
policy:
  mode: enforce
  data_level: internal
  fallback_to_legacy: false
  active_bundle: b
  bundles:
    - id: b
      version: 1
      scope: organization:university
`
	cfg := mustCfg30(t, src)
	if cfg.Policy.FallbackToLegacyEnabled() {
		t.Error("显式 false 必须生效")
	}
	cfg2 := mustCfg30(t, `
policy:
  mode: enforce
  data_level: confidential
  active_bundle: b
  bundles:
    - id: b
      version: 1
      scope: organization:university
`)
	if !cfg2.Policy.FallbackToLegacyEnabled() {
		t.Error("缺省应允许回落")
	}
	// 分级是 PolicyContext 的输入（§2.3 的 user_level 项），必须原样传下去：
	// 这里若被规范化成别的值，deny 条件会整批失配，而配置文本上看不出错。
	if got := cfg2.Policy.DataLevelResolved(); got != policy.LevelConfidential {
		t.Errorf("DataLevelResolved = %s，想要 confidential", got)
	}
	// legacy 下没有 PolicyContext，不要求填分级：留零值表示「没有分级依据」，
	// 接线方据此跳过 3.0，而不是拿一个猜出来的等级去判定。
	legacy := mustCfg30(t, "policy:\n  mode: legacy\n")
	if got := legacy.Policy.DataLevelResolved(); got != policy.LevelUnknown {
		t.Errorf("legacy 的分级 = %s，想要 unknown（没填就是没依据）", got)
	}
}

func TestPolicyScopeLintAgainstDirectory(t *testing.T) {
	known := cfg30KnownScopes{refs: []policy.ScopeRef{
		policy.MustScope(policy.ScopeOrganization, "university"),
	}}
	src := `
policy:
  mode: shadow
  data_level: internal
  active_bundle: typo-bundle
  bundles:
    - id: good-bundle
      version: 1
      scope: organization:university
    - id: typo-bundle
      version: 1
      scope: organization:universyty
`
	// 目录里没有的范围只 warn 不 fail：最可能是目录还没同步完，
	// 让配置加载失败会在同步窗口里把网关直接拒之门外。
	cfg, err := cfg30With(t, src, known)
	if err != nil {
		t.Fatalf("lint 不该让加载失败: %v", err)
	}
	var hit string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "不在目录的已知范围内") {
			hit += w
		}
	}
	if !strings.Contains(hit, "typo-bundle") || !strings.Contains(hit, "organization:universyty") {
		t.Errorf("拼错的范围必须被点名（包名 + 范围都带上）：%q", hit)
	}
	if strings.Contains(hit, "good-bundle") {
		t.Error("目录里存在的范围不该告警")
	}

	// 没有目录可对照时跳过 lint，但其它校验一律不降级。
	if _, err := cfg30With(t, src, nil); err != nil {
		t.Errorf("无目录时仍应加载成功: %v", err)
	}
	bad, err := cfg30With(t, "policy:\n  mode: shadow\n", known)
	if err == nil {
		t.Fatal("无 bundle 的 shadow 在带目录的加载里也必须失败")
	}
	if bad != nil {
		t.Error("失败时不该返回半成品配置")
	}
}

func TestPolicyNilSafe(t *testing.T) {
	// 接线方会拿着「未加载 3.0」的 nil 指针问这些开关：
	// 每个都必须在 nil 上给出 legacy 的答案，而不是 panic 在请求路径上。
	var p *PolicyConfig
	if p.UsesPolicy() || p.EnforcesPolicy() {
		t.Error("nil 必须等价于 legacy")
	}
	if p.ModeResolved() != PolicyModeLegacy || p.PolicyVersion() != "" {
		t.Error("nil 的模式或版本不对")
	}
	if !p.FallbackToLegacyEnabled() {
		t.Error("nil 应允许回落")
	}
	if _, ok := p.ActiveRef(); ok {
		t.Error("nil 不该有生效引用")
	}
	if len(p.LintScopes(cfg30KnownScopes{})) != 0 {
		t.Error("nil 不该产出告警")
	}
}

// configEqual 必须比出 3.0 的两类事实：某一家的分级上限，和 policy 段本身。
//
// 漏任何一侧的表现都同样是「改完配置、热加载说没变」：revision 不推进 →
// server.policyFor 继续返回缓存着的旧运行态。前者让一次降敏（internal → public）
// 根本不上效，敏感流量还留在那家已经声明「不接」的上游里；
// 后者直接废掉 §3.0 的回滚开关。这两处比较都是新加的，编译器不会提醒漏比，
// 所以只能由这条测试来兜 —— 加下一个 policy 字段时同样要来这里补一例。
func TestConfigEqualDetectsPolicyFacts(t *testing.T) {
	base := mustCfg30(t, cfg30ValidShadow)
	if !configEqual(base, mustCfg30(t, cfg30ValidShadow)) {
		t.Fatal("同一份 3.0 配置解析两次必须判为相等，否则每次保存都会重建策略运行态并丢掉上游连接池")
	}

	lowered := mustCfg30(t, cfg30ValidShadow)
	lowered.Normalized[0].MaxDataLevel = policy.LevelPublic
	if configEqual(base, lowered) {
		t.Error("供应商 max_data_level 改了必须判为变更（降敏是安全相关动作）")
	}
	if configEqual(lowered, base) {
		t.Error("比较必须对称")
	}

	// policy 段的每个可改字段都是某个运维开关：mode 是总闸，data_level 是判定入参，
	// active_bundle 与 bundles 决定加载哪一份授权。这里走「改配置文本再解析」而不是
	// 直接改结构体字段：热加载比的就是两次 Parse 的结果，只改派生值会绕过归一化，
	// 测出来的相等/不等都不是运维真实按下的那个开关。
	for _, tc := range []struct{ name, old, new string }{
		{"mode", "  mode: shadow", "  mode: legacy"},
		{"data_level", "  data_level: internal", "  data_level: public"},
		// active_bundle 必须指向 bundles 里存在的那一条，所以引用与条目一起换。
		{"active_bundle", "  active_bundle: university-default-v1\n  bundles:\n    - id: university-default-v1",
			"  active_bundle: another-bundle\n  bundles:\n    - id: another-bundle"},
		{"bundle_version", "      version: 3", "      version: 4"},
		{"bundle_scope", "      scope: organization:university", "      scope: project:ai"},
	} {
		after := mustCfg30(t, replaceOnce(t, cfg30ValidShadow, tc.old, tc.new))
		if configEqual(base, after) {
			t.Errorf("%s 改了却判为相等 —— 这个开关按下去不会有反应", tc.name)
		}
		if configEqual(after, base) {
			t.Errorf("%s 的比较不对称", tc.name)
		}
	}

	// 加一条 bundle 引用同样必须是变更：不逐元素比就等于没换（PolicyConfig 含 map，
	// 整体 != 不可用）。
	withExtra := cfg30ValidShadow + "    - id: second\n      version: 1\n      scope: project:ai\n"
	if configEqual(base, mustCfg30(t, withExtra)) {
		t.Error("bundles 多了一条却判为相等")
	}

	// 「没写 fallback_to_legacy」与「显式写 true」行为完全一致，必须判为相等：
	// FallbackToLegacy 是 *bool，两次 Parse 各有自己的指针，比指针身份会让每次保存
	// 配置都白白重建策略运行态并 Reset 上游连接池（同 databaseEqual 的理由）。
	withExplicitTrue := cfg30ValidShadow + "  fallback_to_legacy: true\n"
	if !configEqual(base, mustCfg30(t, withExplicitTrue)) {
		t.Error("显式写 fallback_to_legacy: true 与不写应当判为相等（*bool 必须按值比）")
	}
	enforce := replaceOnce(t, cfg30ValidShadow, "  mode: shadow", "  mode: enforce")
	if configEqual(mustCfg30(t, enforce), mustCfg30(t, enforce+"  fallback_to_legacy: false\n")) {
		// 关掉回落是 fail-closed 的决定，比不出变更就等于这个开关按下去没反应。
		// 用 enforce 而不是 base：shadow 下写 false 会被加载期拒（影子不改路由，
		// 这个开关在影子里没有作用点）。
		t.Error("enforce 下关掉 fallback_to_legacy 必须判为变更")
	}
}

// replaceOnce 做一次必须命中的替换：命不中就直接失败，避免用例因为「找不到子串」
// 而静默地比较两份相同配置。
func replaceOnce(t *testing.T, src, old, new string) string {
	t.Helper()
	out := strings.Replace(src, old, new, 1)
	if out == src {
		t.Fatalf("替换没生效（源里没有 %q）:\n%s", old, src)
	}
	return out
}
