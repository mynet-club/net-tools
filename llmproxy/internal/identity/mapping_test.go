package identity

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 本文件直接对 mapping.go 下针：它是 B 的核心交付（外部身份 → Identity + 完整 ScopeChain），
// 640 行里没有一行要靠验签才能跑到，所以这里一律绕开 OIDC 路径，用直接构造的 Claims 喂映射器，
// 让「哪一层没展开」这类问题定位到映射表本身而不是签名链路上。验签分支由 oidc_test.go 负责。

// mapClaims 造一份只喂给映射器的 claims：签发方与时效固定，业务 claim 由用例给。
// exp 取 baseNow+1h，保证映射出的身份在 baseNow 时刻对 policy 内核仍然有效。
func mapClaims(subject string, extra map[string]any) Claims {
	if extra == nil {
		extra = map[string]any{}
	}
	return Claims{
		Issuer:    FakeDefaultIssuer,
		Audience:  []string{FakeDefaultAudience},
		Subject:   subject,
		Expiry:    baseNow.Add(time.Hour),
		IssuedAt:  baseNow,
		HasExpiry: true,
		Extra:     extra,
	}
}

func mustMapper(t *testing.T, cfg MapperConfig) *ClaimMapper {
	t.Helper()
	mapper, err := NewClaimMapper(cfg)
	if err != nil {
		t.Fatalf("构造映射表失败: %v", err)
	}
	return mapper
}

func defaultMapper(t *testing.T) *ClaimMapper {
	t.Helper()
	return mustMapper(t, DefaultMapperConfig())
}

func mustMap(t *testing.T, mapper *ClaimMapper, claims Claims) Mapped {
	t.Helper()
	mapped, err := mapper.Map(claims, "campus-oidc")
	if err != nil {
		t.Fatalf("映射应当成功，实际失败: %v", err)
	}
	return mapped
}

// mustMapErr 断言映射失败，并且顺手钉住「失败时绝不返回半映射身份」：
// 半映射的 chain 少掉的那一层可能恰好是唯一 deny 它的范围（mapping.go 的 Map 注释）。
func mustMapErr(t *testing.T, mapper *ClaimMapper, claims Claims, want error) error {
	t.Helper()
	mapped, err := mapper.Map(claims, "campus-oidc")
	if err == nil {
		t.Fatalf("映射应当失败（期望 %v），实际成功: %+v", want, mapped)
	}
	if err.Error() == "" {
		t.Fatal("错误必须有可读文本")
	}
	if !errors.Is(err, want) {
		t.Fatalf("错误链应认出 %v，实际: %v", want, err)
	}
	if mapped.Identity.Subject != "" || mapped.Identity.Source != "" || len(mapped.Chain) != 0 ||
		mapped.Organization != "" || mapped.Project != "" {
		t.Fatalf("失败时不得返回半映射身份: %+v", mapped)
	}
	return err
}

// mappedDecision 用映射结果跑一次真实判定。
// 「展开出来的每一层都能被规则命中」只能由 policy 内核来证明，光看 chain 内容是看不出问题的。
func mappedDecision(t *testing.T, mapped Mapped) policy.Decision {
	t.Helper()
	rules := []policy.Entitlement{
		{Subject: "*", Resource: "model:*", Action: policy.ActionUse, Effect: policy.EffectAllow},
		{Subject: "*", Scope: "organization:cs-college", Resource: "model:*", Action: policy.ActionUse, Effect: policy.EffectDeny},
	}
	resolver, err := policy.NewResolver("mapping-test@1", rules...)
	if err != nil {
		t.Fatalf("构造策略内核失败: %v", err)
	}
	ctx := policy.PolicyContext{
		Identity:     mapped.Identity,
		Purpose:      "qa",
		Organization: mapped.Organization,
		Project:      mapped.Project,
		DataLevel:    policy.LevelInternal,
	}
	ctx = ctx.Normalize()
	if err := ctx.Validate(); err != nil {
		t.Fatalf("映射结果必须能填出合法的策略上下文: %v", err)
	}
	return resolver.Evaluate(ctx, mapped.Chain, "model:sample-model", policy.ActionUse, baseNow)
}

// --- SlugDirectory ----------------------------------------------------------

// 归一化：大小写、空格、下划线、点、斜杠都要折成同一个小写短横线形态，
// 否则「同一个院系的两种写法」会变成两个范围，策略只命中其中一个。
func TestSlugDirectoryCanonicalizesClaimValues(t *testing.T) {
	directory := DefaultSlugDirectory()
	cases := []struct {
		raw  string
		want string
	}{
		{"CS_College", "cs-college"},
		{"  CS College  ", "cs-college"},
		{"CS.College", "cs-college"},
		{"信息学部/计算机学院", "信息学部-计算机学院"},
		{"CS101-2024F", "cs101-2024f"},
		{"MixedCASE", "mixedcase"},
		{"--trim--", "trim"},
		{"a__b..c", "a-b-c"},
		{"proj  lab  7", "proj-lab-7"},
	}
	for _, item := range cases {
		got, ok := directory.Canonical(policy.ScopeOrganization, item.raw)
		if !ok {
			t.Fatalf("%q 应当能换成稳定 ID", item.raw)
		}
		if got != item.want {
			t.Fatalf("%q 归一化成 %q，期望 %q", item.raw, got, item.want)
		}
		// 产出的 ID 必须直接能当 policy 的范围键用，不需要再加工。
		if _, err := policy.NewScopeRef(policy.ScopeOrganization, got); err != nil {
			t.Fatalf("%q → %q 不是合法范围 ID: %v", item.raw, got, err)
		}
	}

	// 反路：全部字符都会被丢弃的取值只能报错，不能编出一个 ID 来。
	for _, raw := range []string{"", "   ", ":::", "。。。", "...", "___", "!!! ???"} {
		if got, ok := directory.Canonical(policy.ScopeOrganization, raw); ok {
			t.Fatalf("取值 %q 无法承载稳定标识，必须 ok=false，实际给了 %q", raw, got)
		}
	}

	// 同一个逻辑范围的多种写法必须并成一个 ID（正向重复），
	// 而不同逻辑范围不许并成一个（负向重复）—— 后者才是越权方向。
	sameA, _ := directory.Canonical(policy.ScopeProject, "Proj_Lab7")
	sameB, _ := directory.Canonical(policy.ScopeProject, "proj lab7")
	if sameA != sameB {
		t.Fatalf("同一项目的两种写法没并成同一 ID: %q vs %q", sameA, sameB)
	}
	diffA, _ := directory.Canonical(policy.ScopeProject, "proj-lab-7")
	diffB, _ := directory.Canonical(policy.ScopeProject, "proj-lab-8")
	if diffA == diffB {
		t.Fatalf("不同项目被并成同一 ID: %q", diffA)
	}
}

// 冒号是范围 Display() 的分隔符，绝不能出现在 ID 里。
//
// mapping.go:102 有一道「产出含冒号就判失败」的守卫，但 slugify 在默认分支里
// 已经把冒号丢弃了，所以那道守卫按当前实现不可达：含冒号的取值会被静默去掉冒号后接受。
// 后果是「info:sci」和「infosci」并成同一个范围 ID —— 与 MaxLenBytes 那条注释
// 明确排斥的「合并越权」是同一类问题，所以这里断言的是不变量而不是实现细节。
func TestSlugDirectoryDoesNotMergeColonSeparatedNames(t *testing.T) {
	directory := DefaultSlugDirectory()

	// 任何产出都不许带冒号（这条与实现无关，必须长期成立）。
	for _, raw := range []string{"信息学部:计算机学院", "a:b", "org:alpha", "x:y:z"} {
		got, ok := directory.Canonical(policy.ScopeOrganization, raw)
		if ok && strings.Contains(got, ":") {
			t.Fatalf("%q 换出的 ID 含冒号，Display() 无法还原: %q", raw, got)
		}
	}

	// 核心不变量：去掉冒号后的同名字段不许与含冒号的原值并成同一范围。
	withColon, okWith := directory.Canonical(policy.ScopeOrganization, "info:sci")
	withoutColon, okWithout := directory.Canonical(policy.ScopeOrganization, "infosci")
	if !okWith {
		return // 含冒号的取值被拒（fail-closed），不变量成立。
	}
	if !okWithout {
		t.Fatalf("不带冒号的合法取值不该被拒: %v", withoutColon)
	}
	if withColon == withoutColon {
		t.Fatalf("两个逻辑不同的组织被并成同一 ID %q：含冒号取值必须拒绝或换成不可歧义的编码", withColon)
	}
}

// 超长不静默截断：截断会把两个长名字并成同一 ID（合并越权方向）。
func TestSlugDirectoryDoesNotTruncateOversizedValues(t *testing.T) {
	directory := SlugDirectory{MaxLenBytes: 8}

	if got, ok := directory.Canonical(policy.ScopeOrganization, "abcdefgh"); !ok || got != "abcdefgh" {
		t.Fatalf("正好等于上限的取值应当可用，实际 %q ok=%v", got, ok)
	}
	// 两个共享前缀的长名字：如果实现是截断，它们会得到同一个 ID。
	first, okFirst := directory.Canonical(policy.ScopeOrganization, "abcdefgh-1")
	second, okSecond := directory.Canonical(policy.ScopeOrganization, "abcdefgh-2")
	if okFirst || okSecond {
		t.Fatalf("超长取值必须报错而不是截断，实际 %q/%q", first, second)
	}
	if first != "" || second != "" {
		t.Fatal("拒绝时不得返回部分 ID")
	}

	// MaxLenBytes 未配置（≤0）时回落到默认 128 字节，而不是「不限」。
	fallback := SlugDirectory{}
	long := strings.Repeat("a", 129)
	if _, ok := fallback.Canonical(policy.ScopeOrganization, long); ok {
		t.Fatal("超过默认上限 128 字节的取值必须被拒")
	}
	if _, ok := fallback.Canonical(policy.ScopeOrganization, strings.Repeat("a", 128)); !ok {
		t.Fatal("正好 128 字节的取值应当可用")
	}
	negative := SlugDirectory{MaxLenBytes: -5}
	if _, ok := negative.Canonical(policy.ScopeOrganization, long); ok {
		t.Fatal("负的 MaxLenBytes 应回落到默认上限而不是放开")
	}
	// policy 的 scope ID 上限是 256 字节：目录的上限配得再宽也不许把非法 ID 放给下游。
	overPolicyCap := SlugDirectory{MaxLenBytes: 300}
	if _, ok := overPolicyCap.Canonical(policy.ScopeOrganization, strings.Repeat("b", 260)); ok {
		t.Fatal("超过 policy 256 字节上限的取值不许通过目录")
	}
}

// 中文显示名走 slug 的后果：slug 不翻译、不转写，中文原样成为 ID 的一部分。
// 也就是说「显示名当关联键」这条 §5 禁令在中文上完全没有被 slug 挡住，
// 改名当天历史授权就会断掉 —— 所以中文院系名必须配默认 fail-closed 的 StaticDirectory。
func TestSlugDirectoryKeepsChineseDisplayNamesAsKeys(t *testing.T) {
	directory := DefaultSlugDirectory()

	got, ok := directory.Canonical(policy.ScopeOrganization, "计算机学院")
	if !ok {
		t.Fatalf("中文取值当前会被接受（这正是需要显式钉住的后果）: %v", got)
	}
	if got != "计算机学院" {
		t.Fatalf("slug 对中文不做转写，ID 就是显示名本身，实际 %q", got)
	}
	// 换个说法（同义改名）就是另一个范围：证明它不能当稳定键。
	renamed, _ := directory.Canonical(policy.ScopeOrganization, "计算机科学与技术学院")
	if renamed == got {
		t.Fatal("改名后应当产生不同的 ID —— 否则说明目录在做猜测性归一")
	}

	// 中文字符按 UTF-8 计 3 字节，同样的名字比 ASCII 更早撞上字节上限。
	longChinese := strings.Repeat("院", 45) // 135 字节 > 128
	if _, ok := directory.Canonical(policy.ScopeOrganization, longChinese); ok {
		t.Fatal("超字节上限的中文名必须被拒")
	}
	if _, ok := directory.Canonical(policy.ScopeOrganization, strings.Repeat("院", 40)); !ok {
		t.Fatal("120 字节的中文名应当可用")
	}

	// 正解：默认 fail-closed 的别名表会把未登记的中文名挡掉。
	strict := StaticDirectory{
		Entries: map[policy.ScopeKind]map[string]string{policy.ScopeOrganization: {"计算机学院": "cs-college"}},
	}
	if id, ok := strict.Canonical(policy.ScopeOrganization, "计算机学院"); !ok || id != "cs-college" {
		t.Fatalf("别名表命中时应给出稳定 ID，实际 %q ok=%v", id, ok)
	}
	if _, ok := strict.Canonical(policy.ScopeOrganization, "医学院"); ok {
		t.Fatal("未登记又没开 AllowUnknown 的中文名必须报错")
	}
}

// --- StaticDirectory --------------------------------------------------------

// 别名表是推荐的产形态：claim 原值 → 稳定 ID，按范围类型分桶。
func TestStaticDirectoryResolvesAliasTable(t *testing.T) {
	directory := StaticDirectory{
		Entries: map[policy.ScopeKind]map[string]string{
			policy.ScopeOrganization: {"信息学部/计算机学院": "cs-college", "大学": "university"},
			policy.ScopeProject:      {"科研项目 7 号": "proj-lab-7"},
		},
	}
	for _, item := range []struct {
		kind policy.ScopeKind
		raw  string
		want string
	}{
		{policy.ScopeOrganization, "信息学部/计算机学院", "cs-college"},
		{policy.ScopeOrganization, "  信息学部/计算机学院 ", "cs-college"}, // 查表前裁剪首尾空白
		{policy.ScopeOrganization, "大学", "university"},
		{policy.ScopeProject, "科研项目 7 号", "proj-lab-7"},
	} {
		got, ok := directory.Canonical(item.kind, item.raw)
		if !ok || got != item.want {
			t.Fatalf("%v %q → %q ok=%v，期望 %q", item.kind, item.raw, got, ok, item.want)
		}
	}

	// 反路 1：分桶隔离 —— 组织桶里的别名不许在项目类型下被当成别名命中。
	if got, ok := directory.Canonical(policy.ScopeProject, "信息学部/计算机学院"); ok && got == "cs-college" {
		t.Fatalf("组织别名在项目类型下命中了组织桶的 ID: %q", got)
	}
	// 反路 2：表里配了空目标时不许退化成显示名（§5 禁止用显示名当关联键）。
	broken := StaticDirectory{Entries: map[policy.ScopeKind]map[string]string{
		policy.ScopeOrganization: {"university": ""},
	}}
	if _, ok := broken.Canonical(policy.ScopeOrganization, "university"); ok {
		t.Fatal("别名表把取值映射成空 ID 必须判失败")
	}
	// 反路 3：别名表配出的 ID 本身非法（含冒号）时也必须判失败，而不是让下游炸。
	badID := StaticDirectory{Entries: map[policy.ScopeKind]map[string]string{
		policy.ScopeOrganization: {"university": "org:university"},
	}}
	if _, ok := badID.Canonical(policy.ScopeOrganization, "university"); ok {
		t.Fatal("含冒号的目标 ID 必须被拒")
	}
	// 反路 4：表未命中时默认 fail-closed —— 原值不会被当成稳定编码放行。
	// 要放行必须显式写 AllowUnknown，代价见那个字段的注释（把 claim 原文当授权键）。
	if got, ok := directory.Canonical(policy.ScopeOrganization, "医学院"); ok {
		t.Fatalf("默认状态下未登记的取值必须被拒，实际给了 %q", got)
	}
	lenient := directory
	lenient.AllowUnknown = true
	if got, ok := lenient.Canonical(policy.ScopeOrganization, "医学院"); !ok || got != "医学院" {
		t.Fatalf("AllowUnknown 打开时应保留原值，实际 %q ok=%v", got, ok)
	}
}

// 零值目录是 fail-closed 的：未登记、又没配 Fallback 的取值一律拒（§5 的显式口径）。
// Fallback 是运营显式选择的合成路径，不受 AllowUnknown 影响 —— 选了 slug 目录就是
// 选了它的口径，中文显示名当键的风险由 TestSlugDirectoryKeepsChineseDisplayNamesAsKeys 钉。
func TestStaticDirectoryDefaultsFailsClosed(t *testing.T) {
	entries := map[policy.ScopeKind]map[string]string{policy.ScopeOrganization: {"university": "university"}}

	strict := StaticDirectory{Entries: entries}
	if _, ok := strict.Canonical(policy.ScopeOrganization, "university"); !ok {
		t.Fatal("命中的取值不受默认影响")
	}
	if got, ok := strict.Canonical(policy.ScopeOrganization, "计算机学院"); ok {
		t.Fatalf("默认必须拒绝未登记的取值，实际退回了 %q", got)
	}

	withFallback := StaticDirectory{Entries: entries, Fallback: DefaultSlugDirectory()}
	if got, ok := withFallback.Canonical(policy.ScopeOrganization, "计算机学院"); !ok || got != "计算机学院" {
		t.Fatalf("显式配置的 Fallback 应参与未命中，实际 %q ok=%v", got, ok)
	}

	open := StaticDirectory{Entries: entries, AllowUnknown: true}
	if got, ok := open.Canonical(policy.ScopeOrganization, "计算机学院"); !ok || got != "计算机学院" {
		t.Fatalf("AllowUnknown 打开后应保留原值，实际 %q ok=%v", got, ok)
	}

	if _, ok := (StaticDirectory{}).Canonical(policy.ScopeProject, "anything"); ok {
		t.Fatal("空表且零配置的目录必须一律拒绝")
	}
}

// AllowUnknown 打开时，原值本身就是稳定编码可以直接用，但冒号与空白仍然要拒。
func TestStaticDirectoryLoosePathRejectsUnstableRawValues(t *testing.T) {
	directory := StaticDirectory{AllowUnknown: true}
	for _, raw := range []string{"proj-lab-7", "university", "CS-101"} {
		if _, ok := directory.Canonical(policy.ScopeOrganization, raw); !ok {
			t.Fatalf("%q 本身就是稳定编码，应当可用", raw)
		}
	}
	for _, raw := range []string{"", "   ", "org:id", "::"} {
		if got, ok := directory.Canonical(policy.ScopeOrganization, raw); ok {
			t.Fatalf("宽松路径也必须拒掉 %q，实际给了 %q", raw, got)
		}
	}
	// 首尾空白会被裁掉后再判：裁完为空就是空。
	if _, ok := directory.Canonical(policy.ScopeOrganization, "  \t "); ok {
		t.Fatal("只有空白的取值必须被拒")
	}
}

// --- NewClaimMapper 构造期校验 ---------------------------------------------

// 范围规则的类型必须是封闭集合：user 由 subject 自动产生，system 不许由 token 声明。
// 让 token 能自封 system 范围等于自封管理员（system 策略包对任意 chain 生效）。
func TestNewClaimMapperRejectsUserAndSystemScopeRules(t *testing.T) {
	for _, kind := range []policy.ScopeKind{policy.ScopeUser, policy.ScopeSystem, policy.ScopeKind(""), policy.ScopeKind("tenant")} {
		cfg := DefaultMapperConfig()
		cfg.ScopeRules = []ScopeRule{{Claim: "organization", Kind: kind, Primary: true}}
		mapper, err := NewClaimMapper(cfg)
		if err == nil {
			t.Fatalf("Kind=%q 必须在构造期就失败（拿不到映射器就不会有 system 范围）", kind)
		}
		if !errors.Is(err, ErrConfig) {
			t.Fatalf("应是配置错误语义，实际: %v", err)
		}
		assertReason(t, err, ReasonConfigInvalid)
		if mapper != nil {
			t.Fatal("构造失败不得返回部分可用的映射器")
		}
	}

	// 正路：organization + project 两类都在，且各有一条 primary。
	ok := DefaultMapperConfig()
	ok.ScopeRules = []ScopeRule{
		{Claim: "organization", Kind: policy.ScopeOrganization, Primary: true},
		{Claim: "department", Kind: policy.ScopeOrganization},
		{Claim: "projects", Kind: policy.ScopeProject, Primary: true},
	}
	mustMapper(t, ok)
}

// 主组织/主项目必须唯一：两条同 Kind 的 primary 会让「谁填 PolicyContext」取决于规则顺序，
// 回放和审计就会飘。
func TestNewClaimMapperRejectsDuplicatePrimaryRules(t *testing.T) {
	dupOrg := DefaultMapperConfig()
	dupOrg.ScopeRules = []ScopeRule{
		{Claim: "organization", Kind: policy.ScopeOrganization, Primary: true},
		{Claim: "department", Kind: policy.ScopeOrganization, Primary: true},
	}
	err := mustMapperConfigErr(t, dupOrg)
	if !strings.Contains(err.Error(), "organization") {
		t.Fatalf("错误要指出是哪一类重复: %v", err)
	}

	dupProject := DefaultMapperConfig()
	dupProject.ScopeRules = []ScopeRule{
		{Claim: "projects", Kind: policy.ScopeProject, Primary: true},
		{Claim: "course", Kind: policy.ScopeProject, Primary: true},
	}
	mustMapperConfigErr(t, dupProject)

	// 正路：一类各一条 primary + 多条非 primary 完全合法。
	both := DefaultMapperConfig()
	both.ScopeRules = []ScopeRule{
		{Claim: "organization", Kind: policy.ScopeOrganization, Primary: true},
		{Claim: "department", Kind: policy.ScopeOrganization},
		{Claim: "college", Kind: policy.ScopeOrganization},
		{Claim: "projects", Kind: policy.ScopeProject, Primary: true},
		{Claim: "course", Kind: policy.ScopeProject},
	}
	mustMapper(t, both)
}

func mustMapperConfigErr(t *testing.T, cfg MapperConfig) error {
	t.Helper()
	mapper, err := NewClaimMapper(cfg)
	if err == nil {
		t.Fatalf("该配置必须在构造期失败，实际通过了: %+v", cfg.ScopeRules)
	}
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("应是配置错误语义，实际: %v", err)
	}
	assertReason(t, err, ReasonConfigInvalid)
	if mapper != nil {
		t.Fatal("构造失败不得返回映射器")
	}
	return err
}

// claim 路径写错必须在启动期报错：路径拼错的运行期表现是「静默取不到值」，
// 而取不到值等于少展开一层范围或一个角色 —— 那是最难查的失败方向。
func TestNewClaimMapperRejectsInvalidClaimPaths(t *testing.T) {
	cases := []struct {
		name    string
		patch   func(cfg *MapperConfig)
		wantMsg string
	}{
		{"subject 为空段", func(cfg *MapperConfig) { cfg.SubjectClaims = []string{""} }, ""},
		{"subject 首尾有空白", func(cfg *MapperConfig) { cfg.SubjectClaims = []string{" sub"} }, ""},
		{"角色路径含空段", func(cfg *MapperConfig) { cfg.RoleClaims = []string{"realm_access..roles"} }, ""},
		{"角色路径尾点多", func(cfg *MapperConfig) { cfg.RoleClaims = []string{"roles."} }, ""},
		{"组路径为空", func(cfg *MapperConfig) { cfg.GroupClaims = []string{"  "} }, ""},
		{"项目路径非法", func(cfg *MapperConfig) { cfg.ProjectClaims = []string{"projects."} }, ""},
		{"认证方式路径非法", func(cfg *MapperConfig) { cfg.AuthMethodClaims = []string{".amr"} }, ""},
		{"范围规则路径非法", func(cfg *MapperConfig) {
			cfg.ScopeRules = []ScopeRule{{Claim: "organization.", Kind: policy.ScopeOrganization}}
		}, ""},
		{"显示名路径非法", func(cfg *MapperConfig) { cfg.DisplayNameClaims = []string{"name."} }, ""},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			cfg := DefaultMapperConfig()
			item.patch(&cfg)
			mustMapperConfigErr(t, cfg)
		})
	}

	// 正路：点号下钻的嵌套路径是合法写法。
	nested := DefaultMapperConfig()
	nested.RoleClaims = []string{"realm_access.roles", "resource_access.llmproxy.roles"}
	nested.ScopeRules = []ScopeRule{{Claim: "authorization.colleges", Kind: policy.ScopeOrganization, Primary: true}}
	mustMapper(t, nested)
}

// --- ClaimMapper.Map：范围展开 ---------------------------------------------

// organization + department + college + projects + course + lab 同时存在时，
// chain 里三层组织归属和三层项目归属必须一个不少。
func TestClaimMapperExpandsEveryOrganizationAndProjectLevel(t *testing.T) {
	mapper := defaultMapper(t)
	claims := mapClaims("uid-stu-1001", map[string]any{
		"organization": "university",
		"department":   "cs-college",
		"college":      "ai-college",
		"projects":     []any{"proj-lab-7"},
		"course":       []any{"CS 101"},
		"lab":          "Lab-3",
	})
	mapped := mustMap(t, mapper, claims)

	assertScopeChain(t, mapped.Chain,
		"organization:ai-college",
		"organization:cs-college",
		"organization:university",
		"project:cs-101",
		"project:lab-3",
		"project:proj-lab-7",
		"user:uid-stu-1001",
	)
	if !mapped.Chain.Includes(policy.MustScope(policy.ScopeUser, "uid-stu-1001")) {
		t.Fatal("user 范围必须始终在集合里")
	}
	// 主组织只由 primary 规则填，取值是排序后的第一个（这里是 organization claim 本身）。
	if mapped.Organization != "university" {
		t.Fatalf("主组织实际 %q", mapped.Organization)
	}
	if mapped.Project != "proj-lab-7" {
		t.Fatalf("主项目实际 %q", mapped.Project)
	}
	// 同一份 claims 重复映射必须逐字节相同（§6 固定输入固定输出）。
	again := mustMap(t, mapper, claims)
	if again.Chain.Display() != mapped.Chain.Display() || again.Organization != mapped.Organization ||
		again.Project != mapped.Project {
		t.Fatal("重复映射的结果不一致")
	}
}

// 「漏一层组织 → 那一级策略对这个请求永不生效」只能由真实判定证明。
// 这里把 cs-college 从映射表里摘掉，同一条院系级 deny 就悄悄不参与了。
func TestMappedDepartmentLevelMakesPolicyRuleEffective(t *testing.T) {
	claims := mapClaims("uid-stu-1001", map[string]any{
		"organization": "university",
		"department":   "cs-college",
		"roles":        []any{"student"},
	})

	mapped := mustMap(t, defaultMapper(t), claims)
	decision := mappedDecision(t, mapped)
	if decision.Allowed {
		t.Fatalf("院系级 deny 必须参与判定，实际放行: %s", decision.Explain())
	}
	if len(decision.Matched) == 0 || decision.Matched[0].Effect != policy.EffectDeny ||
		decision.Matched[0].Scope != "organization:cs-college" {
		t.Fatalf("决定性规则必须就是那条院系级 deny: %+v", decision.Matched)
	}

	// 反路：映射表漏配 department 规则 —— 同一条规则静默不命中，表现为「配了没生效」。
	blindCfg := DefaultMapperConfig()
	blindCfg.ScopeRules = []ScopeRule{{Claim: "organization", Kind: policy.ScopeOrganization, Primary: true}}
	blind := mustMap(t, mustMapper(t, blindCfg), claims)
	for _, scope := range []policy.ScopeRef{policy.MustScope(policy.ScopeOrganization, "cs-college")} {
		if blind.Chain.Includes(scope) {
			t.Fatal("漏配的规则不该凭空造出范围")
		}
	}
	if allowed := mappedDecision(t, blind); !allowed.Allowed {
		t.Fatalf("院系规则漏配后 deny 不再参与（这正是该缺陷的隐蔽之处）: %s", allowed.Explain())
	}
}

// 主组织/主项目取「排序后的第一个」而不是 claims 数组的第一个：
// IdP 不保证数组顺序，否则同一个人两次请求的判定与审计会飘。
func TestClaimMapperPrimaryScopeIsArrayOrderIndependent(t *testing.T) {
	mapper := defaultMapper(t)
	first := mapClaims("uid-pi-3001", map[string]any{
		"organization": []any{"university", "affiliate-institute"},
		"projects":     []any{"proj-lab-7", "proj-grant-2026"},
	})
	second := mapClaims("uid-pi-3001", map[string]any{
		"organization": []any{"affiliate-institute", "university"},
		"projects":     []any{"proj-grant-2026", "proj-lab-7"},
	})

	a := mustMap(t, mapper, first)
	b := mustMap(t, mapper, second)
	if a.Organization != "affiliate-institute" || b.Organization != a.Organization {
		t.Fatalf("主组织必须是排序后的第一个且与数组顺序无关: %q vs %q", a.Organization, b.Organization)
	}
	if a.Project != "proj-grant-2026" || b.Project != a.Project {
		t.Fatalf("主项目必须是排序后的第一个: %q vs %q", a.Project, b.Project)
	}
	if a.Chain.Display() != b.Chain.Display() {
		t.Fatalf("范围集合受数组顺序影响:\n%s\n%s", a.Chain.Display(), b.Chain.Display())
	}
	if !equalStrings(a.Identity.Projects, b.Identity.Projects) {
		t.Fatalf("成员关系列表必须归一化后再输出: %v vs %v", a.Identity.Projects, b.Identity.Projects)
	}
}

// project 有值但 organization 为空：项目范围仍进 chain（项目级 deny 必须参与判定），
// 但不填 PolicyContext.Project —— 否则 §2.2 会把整次解析判成失败。
func TestClaimMapperProjectWithoutOrganization(t *testing.T) {
	mapper := defaultMapper(t)
	claims := mapClaims("uid-fee-1", map[string]any{
		"projects": []any{"proj-lab-7"},
		"course":   "CS 101",
	})
	mapped := mustMap(t, mapper, claims)

	if mapped.Organization != "" {
		t.Fatalf("没有组织 claim 时主组织必须为空，实际 %q", mapped.Organization)
	}
	if mapped.Project != "" {
		t.Fatalf("没有主组织时不得填主项目（policy §2.2 会拒绝该上下文）: %q", mapped.Project)
	}
	for _, want := range []policy.ScopeRef{
		policy.MustScope(policy.ScopeProject, "proj-lab-7"),
		policy.MustScope(policy.ScopeProject, "cs-101"),
	} {
		if !mapped.Chain.Includes(want) {
			t.Fatalf("项目范围必须留在 chain 里，否则项目级 deny 永不参与: %s", mapped.Chain.Display())
		}
	}
	// 上下文必须仍然合法（没有主组织就不能填主项目），同时项目级 deny 要能命中。
	ctx := policy.PolicyContext{Identity: mapped.Identity, Purpose: "qa", DataLevel: policy.LevelInternal}.Normalize()
	if err := ctx.Validate(); err != nil {
		t.Fatalf("主项目留空才填得出合法上下文: %v", err)
	}
	resolver, err := policy.NewResolver("project-only@1",
		policy.Entitlement{Subject: "*", Resource: "model:*", Action: policy.ActionUse, Effect: policy.EffectAllow},
		policy.Entitlement{Subject: "*", Scope: "project:proj-lab-7", Resource: "model:*", Action: policy.ActionUse, Effect: policy.EffectDeny},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolver.Evaluate(ctx, mapped.Chain, "model:sample-model", policy.ActionUse, baseNow); got.Allowed {
		t.Fatalf("项目级 deny 必须参与判定: %s", got.Explain())
	}

	// 反路：组织有值时主项目必须照常填写。
	withOrg := mapClaims("uid-fee-1", map[string]any{
		"organization": "university",
		"projects":     []any{"proj-lab-7"},
	})
	full := mustMap(t, mapper, withOrg)
	if full.Organization != "university" || full.Project != "proj-lab-7" {
		t.Fatalf("主组织/主项目应同时填出: %+v", full)
	}
}

// claim 里的项目列表（ProjectClaims）必须并进 chain：
// 否则规则里的 project: 选择器命中不到 —— 只有 course/lab 而没有项目范围 claim 的
// token 会绕过全部「按项目授权」的规则。
func TestClaimMapperProjectClaimsReachProjectSelectors(t *testing.T) {
	cfg := DefaultMapperConfig()
	// 只留组织类范围规则：项目范围只能靠 ProjectClaims 的并入逻辑出现。
	cfg.ScopeRules = []ScopeRule{{Claim: "organization", Kind: policy.ScopeOrganization, Primary: true}}
	mapper := mustMapper(t, cfg)
	claims := mapClaims("uid-stu-2002", map[string]any{
		"organization": "university",
		"projects":     []any{"proj-secret", "proj-visible"},
	})
	mapped := mustMap(t, mapper, claims)

	if !equalStrings(mapped.Identity.Projects, []string{"proj-secret", "proj-visible"}) {
		t.Fatalf("Identity.Projects 应保留 claim 取值: %v", mapped.Identity.Projects)
	}
	for _, want := range []string{"project:proj-secret", "project:proj-visible"} {
		if !strings.Contains(mapped.Chain.Display(), want) {
			t.Fatalf("claim 项目未并进范围集合: %s", mapped.Chain.Display())
		}
	}

	deny := policy.Entitlement{
		Subject:  "*",
		Scope:    "project:proj-secret",
		Resource: "model:*",
		Action:   policy.ActionUse,
		Effect:   policy.EffectDeny,
	}
	other := policy.Entitlement{
		Subject:  "*",
		Scope:    "project:proj-other",
		Resource: "model:*",
		Action:   policy.ActionUse,
		Effect:   policy.EffectDeny,
	}
	allowed, err := policy.NewResolver("probe@1",
		policy.Entitlement{Subject: "*", Resource: "model:*", Action: policy.ActionUse, Effect: policy.EffectAllow}, deny)
	if err != nil {
		t.Fatal(err)
	}
	notApplied, err := policy.NewResolver("probe@1",
		policy.Entitlement{Subject: "*", Resource: "model:*", Action: policy.ActionUse, Effect: policy.EffectAllow}, other)
	if err != nil {
		t.Fatal(err)
	}
	ctx := policy.PolicyContext{Identity: mapped.Identity, Purpose: "qa", DataLevel: policy.LevelInternal}.Normalize()
	if got := allowed.Evaluate(ctx, mapped.Chain, "model:sample-model", policy.ActionUse, baseNow); got.Allowed {
		t.Fatalf("project: 选择器必须能命中并入的项目范围: %s", got.Explain())
	}
	if got := notApplied.Evaluate(ctx, mapped.Chain, "model:sample-model", policy.ActionUse, baseNow); !got.Allowed {
		t.Fatalf("别的项目的 deny 不该波及本请求: %s", got.Explain())
	}
}

// --- ClaimMapper.Map：失败路径 ---------------------------------------------

// 任何一步失败都不许产出半映射身份。这里挑「前面几步已经成功」的失败点：
// 组织已经换成 ID、department 换不出来 —— 此时 chain 里少的那一层恰好是唯一 deny 它的层。
func TestClaimMapperNeverReturnsPartialIdentity(t *testing.T) {
	strict := DefaultMapperConfig()
	strict.Directory = StaticDirectory{
		Entries: map[policy.ScopeKind]map[string]string{policy.ScopeOrganization: {"university": "university"}},
	}
	strictMapper := mustMapper(t, strict)
	claims := mapClaims("uid-stu-1001", map[string]any{
		"organization": "university",
		"department":   "计算机学院",
	})
	err := mustMapErr(t, strictMapper, claims, ErrScopeUnmapped)
	assertReason(t, err, ReasonScopeUnmapped)

	// 角色 claim 类型不符：同样是「已经读到一半」的失败点。
	shape := mapClaims("uid-stu-1001", map[string]any{
		"organization": "university",
		"roles":        map[string]any{"items": []any{"student"}},
	})
	err = mustMapErr(t, defaultMapper(t), shape, ErrClaimShape)
	assertReason(t, err, ReasonClaimShapeInvalid)

	// 项目 claim 换不出稳定 ID。
	overflow := mapClaims("uid-stu-1001", map[string]any{
		"organization": "university",
		"projects":     []any{"::::"},
	})
	mustMapErr(t, defaultMapper(t), overflow, ErrScopeUnmapped)

	// 成员关系带 roles 但 token 没有 exp：必须整体失败，而不是给一个无期限身份。
	noExpiry := Claims{
		Issuer:   FakeDefaultIssuer,
		Audience: []string{FakeDefaultAudience},
		Subject:  "uid-stu-1001",
		IssuedAt: baseNow,
		Extra:    map[string]any{"organization": "university", "roles": []any{"student"}},
	}
	err = mustMapErr(t, defaultMapper(t), noExpiry, ErrMembershipTTL)
	assertReason(t, err, ReasonMembershipTTL)
}

// subject 必须是稳定 ID：邮箱、纯数字学号都要拒；显式配置才放开数字形态。
func TestClaimMapperSubjectShapes(t *testing.T) {
	mapper := defaultMapper(t)

	email := mapClaims("real.student@example.edu", map[string]any{"organization": "university"})
	err := mustMapErr(t, mapper, email, ErrSubjectUnstable)
	assertReason(t, err, ReasonSubjectUnstable)
	if strings.Contains(err.Error(), "example.edu") || strings.Contains(err.Error(), "@") {
		t.Fatalf("错误不得回显邮箱原文（它会顺着错误链进审计）: %v", err)
	}
	if !strings.Contains(err.Error(), "sub") {
		t.Fatalf("错误必须指出是哪个 claim: %v", err)
	}

	numeric := mapClaims("20210101234", map[string]any{"organization": "university"})
	err = mustMapErr(t, mapper, numeric, ErrSubjectUnstable)
	assertReason(t, err, ReasonSubjectUnstable)
	if strings.Contains(err.Error(), "20210101234") {
		t.Fatalf("错误不得回显学号: %v", err)
	}

	lenient := mustMapper(t, MapperConfig{AllowNumericSubject: true})
	if got := mustMap(t, lenient, numeric); got.Identity.Subject != "20210101234" {
		t.Fatalf("显式放开后应按 IdP 的 claim 使用: %+v", got.Identity)
	}

	// 带字母的工号形态不受「纯数字」规则影响。
	if got := mustMap(t, mapper, mapClaims("uid-stu-1001", nil)); got.Identity.Subject != "uid-stu-1001" {
		t.Fatalf("正常 subject 不该被误伤: %+v", got.Identity)
	}

	// 没有任何候选 claim 有值：与「形态不合格」必须是不同结论。
	missing := Claims{Issuer: FakeDefaultIssuer, Audience: []string{FakeDefaultAudience}, Extra: map[string]any{"organization": "university"}}
	err = mustMapErr(t, mapper, missing, ErrSubjectMissing)
	assertReason(t, err, ReasonSubjectMissing)

	// 空白形态的 subject 在稳定 ID 检查里漏过，但绝不能穿过身份校验。
	spacey := mapClaims("uid stu 1001", map[string]any{"organization": "university"})
	err = mustMapErr(t, mapper, spacey, ErrSubjectUnstable)
	assertReason(t, err, ReasonSubjectUnstable)

	// 显示名当 subject：A 包会拒，B 必须给出同向结论而不是放行。
	sameAsDisplay := mapClaims("sample-student", map[string]any{"name": "sample-student"})
	err = mustMapErr(t, mapper, sameAsDisplay, ErrSubjectUnstable)
	assertReason(t, err, ReasonSubjectUnstable)

	// 数字型 sub（json.Number）不是字符串：结构不符，绝不偷偷转成字符串。
	typed := mapClaims("", map[string]any{"sub": jsonNumber(20210101234)})
	err = mustMapErr(t, mapper, typed, ErrClaimShape)
	assertReason(t, err, ReasonClaimShapeInvalid)
}

// 强类型字段优先于 Extra：改了 Subject 但 Extra 里残留旧值时，必须以强类型为准，
// 否则会出现「测试以为在改 subject，实际映射到旧值」的假绿。
func TestClaimMapperPrefersTypedStandardClaimOverExtra(t *testing.T) {
	claims := mapClaims("uid-new", map[string]any{"sub": "uid-stale"})
	mapped := mustMap(t, defaultMapper(t), claims)
	if mapped.Identity.Subject != "uid-new" {
		t.Fatalf("必须以强类型字段为准，实际 %q", mapped.Identity.Subject)
	}
	assertScopeChain(t, mapped.Chain, "user:uid-new")

	// exp 同理：Extra 里的旧 exp 不许覆盖强类型时效。
	claims = mapClaims("uid-new", map[string]any{"exp": jsonNumber(baseNow.Add(99 * time.Hour).Unix())})
	mapped = mustMap(t, defaultMapper(t), claims)
	if !mapped.Identity.ExpiresAt.Equal(baseNow.Add(time.Hour)) {
		t.Fatalf("ExpiresAt 必须来自强类型 Expiry，实际 %v", mapped.Identity.ExpiresAt)
	}
}

// MaxValuesPerClaim 是热路径上的 DoS 闸门：上限判在取值阶段，边界是「等于上限可用」。
func TestClaimMapperCapsValuesPerClaim(t *testing.T) {
	cfg := DefaultMapperConfig()
	cfg.MaxValuesPerClaim = 3
	mapper := mustMapper(t, cfg)

	atLimit := mapClaims("uid-stu-1001", map[string]any{"groups": []any{"a", "b", "c"}})
	mapped := mustMap(t, mapper, atLimit)
	if !equalStrings(mapped.Identity.Groups, []string{"a", "b", "c"}) {
		t.Fatalf("正好等于上限必须可用: %v", mapped.Identity.Groups)
	}

	over := mapClaims("uid-stu-1001", map[string]any{"groups": []any{"a", "b", "c", "d"}})
	err := mustMapErr(t, mapper, over, ErrClaimOverflow)
	assertReason(t, err, ReasonClaimOverflow)

	// 范围规则的取值同样受闸门管：漏掉它就能用一条超大 organization claim 撑爆 chain。
	overScope := mapClaims("uid-stu-1001", map[string]any{
		"organization": []any{"o1", "o2", "o3", "o4"},
	})
	mustMapErr(t, mapper, overScope, ErrClaimOverflow)

	// 单个字符串取值不数组化，不受上限影响（但也不能被静默丢掉）。
	single := mapClaims("uid-stu-1001", map[string]any{"groups": "only-group"})
	if got := mustMap(t, mapper, single); !equalStrings(got.Identity.Groups, []string{"only-group"}) {
		t.Fatalf("字符串型 claim 应作为单项处理: %v", got.Identity.Groups)
	}
}

// --- ClaimMapper.Map：成员关系 claim ---------------------------------------

// 各校角色 claim 名不同：roles / realm_access.roles / resource_access.llmproxy.roles
// 三条别名都要能取到；同时「别的 client 的 resource_access」不许串过来。
func TestClaimMapperRoleClaimAliases(t *testing.T) {
	mapper := defaultMapper(t)
	cases := []struct {
		name   string
		extra  map[string]any
		roles  []string
		groups []string
		auths  []string
	}{
		{"roles", map[string]any{"roles": []any{"teacher", "student"}}, []string{"student", "teacher"}, nil, nil},
		{"realm_access.roles", map[string]any{"realm_access": map[string]any{"roles": []any{"teacher"}}}, []string{"teacher"}, nil, nil},
		{"resource_access.llmproxy.roles", map[string]any{
			"resource_access": map[string]any{"llmproxy": map[string]any{"roles": []any{"course-staff"}}},
		}, []string{"course-staff"}, nil, nil},
		{"字符串单项", map[string]any{"roles": "student"}, []string{"student"}, nil, nil},
		{"memberOf", map[string]any{"memberOf": []any{"faculty", "faculty"}}, nil, []string{"faculty"}, nil},
		{"affiliation", map[string]any{"affiliation": []any{"student"}}, nil, []string{"student"}, nil},
		{"amr", map[string]any{"amr": []any{"pwd", "otp"}}, nil, nil, []string{"otp", "pwd"}},
		{"acr 回退", map[string]any{"acr": "urn:mace:incommon:user"}, nil, nil, []string{"urn:mace:incommon:user"}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			claims := mapClaims("uid-alias-1", item.extra)
			mapped := mustMap(t, mapper, claims)
			if !equalStrings(mapped.Identity.Roles, item.roles) {
				t.Fatalf("Roles 期望 %v，实际 %v", item.roles, mapped.Identity.Roles)
			}
			if !equalStrings(mapped.Identity.Groups, item.groups) {
				t.Fatalf("Groups 期望 %v，实际 %v", item.groups, mapped.Identity.Groups)
			}
			if !equalStrings(mapped.Identity.AuthMethods, item.auths) {
				t.Fatalf("AuthMethods 期望 %v，实际 %v", item.auths, mapped.Identity.AuthMethods)
			}
		})
	}

	// 别的 client 的角色不许命中：那是横向越权方向。
	foreign := mapClaims("uid-alias-1", map[string]any{
		"resource_access": map[string]any{"other-client": map[string]any{"roles": []any{"admin"}}},
	})
	mapped := mustMap(t, mapper, foreign)
	if len(mapped.Identity.Roles) != 0 {
		t.Fatalf("未授权的 client 角色串进来了: %v", mapped.Identity.Roles)
	}

	// 多条别名同时存在时合并去重排序（不是「第一条命中就停」）。
	both := mapClaims("uid-alias-1", map[string]any{
		"roles":        []any{"student"},
		"realm_access": map[string]any{"roles": []any{"teacher", "student"}},
	})
	mapped = mustMap(t, mapper, both)
	if !equalStrings(mapped.Identity.Roles, []string{"student", "teacher"}) {
		t.Fatalf("别名取值应合并去重排序，实际 %v", mapped.Identity.Roles)
	}
}

// 「角色 claim 名猜错时不会静默产出无角色身份」这条防线到底在哪里生效：
// 映射器本身不判（Roles 为空是合法结果），防线在审计计数 + 判定方向。
// 本用例把两件事都钉住：① 猜错时审计里 RoleCount 可见为 0；② 猜错会让靠 role 匹配的
// deny 规则整体失效（放行方向），所以接线期必须核对 RoleCount。
func TestClaimMapperRoleClaimMismatchIsObservableNotSilent(t *testing.T) {
	claims := mapClaims("uid-stu-1001", map[string]any{
		"organization": "university",
		"roles":        []any{"student"},
		"exp":          jsonNumber(baseNow.Add(time.Hour).Unix()),
	})

	correct := mustMap(t, defaultMapper(t), claims)
	if !equalStrings(correct.Identity.Roles, []string{"student"}) {
		t.Fatalf("配对了就该取到角色: %v", correct.Identity.Roles)
	}

	typoCfg := DefaultMapperConfig()
	typoCfg.RoleClaims = []string{"user_role"} // 猜错的 claim 名
	typo := mustMap(t, mustMapper(t, typoCfg), claims)
	if len(typo.Identity.Roles) != 0 {
		t.Fatalf("猜错时不该凭空造角色: %v", typo.Identity.Roles)
	}

	// 防线 ①：审计里 RoleCount 与正确映射不同，运维能在影子期发现。
	authority := testAuthority(t)
	token := mustToken(t, authority, SignRequest{Profile: studentProfile(), At: baseNow})
	for _, item := range []struct {
		name     string
		mapper   *ClaimMapper
		wantRole int
	}{{"配对", defaultMapper(t), 1}, {"猜错", mustMapper(t, typoCfg), 0}} {
		recorder := NewAuditRecorder(0)
		provider := newOIDC(t, authority, oidcOptions{mapper: item.mapper, audit: recorder})
		principal := resolveOK(t, provider, oidcCredential(t, token))
		event, ok := recorder.Last()
		if !ok {
			t.Fatalf("%s：成功解析必须有审计", item.name)
		}
		if event.RoleCount != item.wantRole {
			t.Fatalf("%s：审计 RoleCount 期望 %d，实际 %d（principal=%+v）", item.name, item.wantRole, event.RoleCount, principal)
		}
	}

	// 防线 ②：靠 role 匹配的 deny 在猜错时静默不生效 —— 这是必须靠 RoleCount 盯住的原因。
	byRole := []policy.Entitlement{
		{Subject: "*", Resource: "model:*", Action: policy.ActionUse, Effect: policy.EffectAllow},
		{Subject: "role:student", Resource: "model:*", Action: policy.ActionUse, Effect: policy.EffectDeny},
	}
	resolver, err := policy.NewResolver("alias-probe@1", byRole...)
	if err != nil {
		t.Fatal(err)
	}
	eval := func(mapped Mapped) policy.Decision {
		ctx := policy.PolicyContext{Identity: mapped.Identity, Purpose: "qa", Organization: mapped.Organization, DataLevel: policy.LevelInternal}.Normalize()
		return resolver.Evaluate(ctx, mapped.Chain, "model:sample-model", policy.ActionUse, baseNow)
	}
	if got := eval(correct); got.Allowed {
		t.Fatalf("角色配对时 role:student 的 deny 必须生效: %s", got.Explain())
	}
	if got := eval(typo); !got.Allowed {
		t.Fatalf("角色 claim 猜错时 deny 会整体失效（该结论必须由审计 RoleCount 暴露）: %s", got.Explain())
	}
}

// 只有装饰性字段可以宽松：显示名取不出来只是界面上少个名字；
// 角色/组/项目类型不符一律报错（见 TestClaimMapperNeverReturnsPartialIdentity）。
func TestClaimMapperDisplayNameIsOnlyDecorative(t *testing.T) {
	mapper := defaultMapper(t)

	claims := mapClaims("uid-stu-1001", map[string]any{"name": map[string]any{"zh": "张三"}})
	mapped := mustMap(t, mapper, claims)
	if mapped.Identity.DisplayName != "" {
		t.Fatalf("显示名不是字符串时应回落为空，而不是报错或猜测: %q", mapped.Identity.DisplayName)
	}
	if mapped.Identity.Subject != "uid-stu-1001" {
		t.Fatal("显示名解析失败不能影响身份本身")
	}

	// 候选顺序：name 空 → preferred_username；且首尾空白会被裁掉。
	claims = mapClaims("uid-stu-1001", map[string]any{"name": "   ", "preferred_username": "  sample.student  "})
	mapped = mustMap(t, mapper, claims)
	if mapped.Identity.DisplayName != "sample.student" {
		t.Fatalf("显示名应回退到下一个候选并裁剪空白，实际 %q", mapped.Identity.DisplayName)
	}

	// 完全没有显示名 claim：成功，DisplayName 为空。
	bare := mustMap(t, mapper, mapClaims("uid-stu-1001", nil))
	if bare.Identity.DisplayName != "" {
		t.Fatalf("无显示名 claim 时保持为空: %q", bare.Identity.DisplayName)
	}
}

// 成员关系必须带过期时间（手册 §2.1）：token 没有 exp 时整个映射失败。
// 同时钉住「无成员关系的纯 subject 身份」不受该规则影响，否则机器凭证会被误伤。
func TestClaimMapperMembershipRequiresExpiry(t *testing.T) {
	mapper := defaultMapper(t)

	withMembers := Claims{
		Issuer:   FakeDefaultIssuer,
		Audience: []string{FakeDefaultAudience},
		Subject:  "uid-stu-1001",
		Extra:    map[string]any{"groups": []any{"undergraduate"}},
	}
	err := mustMapErr(t, mapper, withMembers, ErrMembershipTTL)
	assertReason(t, err, ReasonMembershipTTL)

	plain := Claims{
		Issuer:   FakeDefaultIssuer,
		Audience: []string{FakeDefaultAudience},
		Subject:  "machine-1",
		Extra:    map[string]any{},
	}
	mapped := mustMap(t, mapper, plain)
	if !mapped.Identity.ExpiresAt.IsZero() {
		t.Fatalf("无成员关系的身份允许不过期，实际 %v", mapped.Identity.ExpiresAt)
	}

	// exp 早于 iat 是 claims 损坏，不能被当成一个「已经可用」的身份。
	broken := mapClaims("uid-stu-1001", map[string]any{"roles": []any{"student"}})
	broken.Expiry = baseNow.Add(-time.Minute)
	mustMapErr(t, mapper, broken, ErrMembershipTTL)
}

// Identity.Projects 保留 claim 原值（仅供控制台展示），chain 与主项目字段才是规范化 ID。
//
// 主体选择器 `project:` 只比结构化范围（ctx.Project 与 chain），**不比 claim 原值**：
// 归属判定必须只有一个键（§2.7），否则 IdP 里一个恰好叫 <别人项目 ID> 的组就能绕过
// 规范映射命中规则。规则的 Scope 同样只吃 chain。这条分道必须钉住 —— 两侧任一改回
// 「吃原值」都会多出第二个授权入口。
func TestClaimMapperKeepsRawProjectsAlongsideCanonicalScopes(t *testing.T) {
	mapper := defaultMapper(t)
	allow := policy.Entitlement{Subject: "*", Resource: "model:*", Action: policy.ActionUse, Effect: policy.EffectAllow}

	// deny 只给一条规则，命中与否完全由它的键形态决定。
	denyBy := func(t *testing.T, rule policy.Entitlement, mapped Mapped, organization, project string) policy.Decision {
		t.Helper()
		resolver, err := policy.NewResolver("raw-vs-canonical@1", allow, rule)
		if err != nil {
			t.Fatalf("构造策略内核失败: %v", err)
		}
		ctx := policy.PolicyContext{
			Identity: mapped.Identity, Purpose: "qa",
			Organization: organization, Project: project, DataLevel: policy.LevelInternal,
		}.Normalize()
		return resolver.Evaluate(ctx, mapped.Chain, "model:sample-model", policy.ActionUse, baseNow)
	}

	mapped := mustMap(t, mapper, mapClaims("uid-stu-1001", map[string]any{
		"organization": "university",
		"projects":     []any{"Proj Lab7"},
	}))
	if !equalStrings(mapped.Identity.Projects, []string{"Proj Lab7"}) {
		t.Fatalf("Identity.Projects 是 claim 原值（仅裁边空白）: %v", mapped.Identity.Projects)
	}
	if mapped.Project != "proj-lab7" {
		t.Fatalf("主项目是规范化 ID: %q", mapped.Project)
	}
	if !mapped.Chain.Includes(policy.MustScope(policy.ScopeProject, "proj-lab7")) {
		t.Fatalf("范围集合用规范化 ID: %s", mapped.Chain.Display())
	}

	scopeRule := policy.Entitlement{Subject: "*", Scope: "project:proj-lab7", Resource: "model:*", Action: policy.ActionUse, Effect: policy.EffectDeny}
	rawSubjectRule := policy.Entitlement{Subject: "project:Proj Lab7", Resource: "model:*", Action: policy.ActionUse, Effect: policy.EffectDeny}
	canonicalSubjectRule := policy.Entitlement{Subject: "project:proj-lab7", Resource: "model:*", Action: policy.ActionUse, Effect: policy.EffectDeny}

	for _, item := range []struct {
		name    string
		rule    policy.Entitlement
		project string
		denies  bool
	}{
		{"规则 Scope 吃规范化范围", scopeRule, mapped.Project, true},
		{"主体选择器吃上下文里的规范化主项目", canonicalSubjectRule, mapped.Project, true},
		// claim 原值形态的显示名不再是授权键：这条规则**不会**生效。
		// 加载期不会报错（"Proj Lab7" 是合法的范围 ID 形态），所以策略编写侧必须
		// 只用目录产出的规范 ID —— 这条约束由 H 包的规则编辑校验负责（已知限制）。
		{"主体选择器不再吃 claim 原值", rawSubjectRule, mapped.Project, false},
	} {
		got := denyBy(t, item.rule, mapped, mapped.Organization, item.project)
		if got.Allowed == item.denies {
			t.Fatalf("%s：期望 deny 生效=%v，实际 %s", item.name, item.denies, got.Explain())
		}
	}

	// 关键分道：没有主组织时主项目不填（mapping.go 的既定行为，见 §2.2 的
	// 「有 project 必须有 organization」），但项目范围照样进 chain ——
	// 于是主体选择器与规则 Scope 都仍能从链上命中，项目级 deny 不会因为
	// 主归属缺失而失效。放行方向（ctx.Project 为空就不再命中）才是危险的。
	orphan := mustMap(t, mapper, mapClaims("uid-stu-1001", map[string]any{"projects": []any{"Proj Lab7"}}))
	if orphan.Project != "" {
		t.Fatalf("无主组织时不得填主项目: %q", orphan.Project)
	}
	if got := denyBy(t, canonicalSubjectRule, orphan, "", orphan.Project); got.Allowed {
		t.Fatalf("项目范围在 chain 上，主体选择器必须命中: %s", got.Explain())
	}
	if got := denyBy(t, scopeRule, orphan, "", orphan.Project); got.Allowed {
		t.Fatalf("项目范围仍进 chain，项目级 deny 必须继续参与判定: %s", got.Explain())
	}
}
