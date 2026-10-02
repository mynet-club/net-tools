package policy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// forbiddenFieldWords 是本包任何领域对象都不得携带的字段名子串。
//
// A 包是纯领域层：正文、上游地址、凭证这些运行期数据一旦进了这些结构，
// 就必然会顺着 JSON 落进审计表和管理台响应。用反射把它挡在编译产物之外，
// 比靠评审时盯字段可靠。
var forbiddenFieldWords = []string{
	"body", "payload", "content", "apikey", "api_key", "secret", "token",
	"baseurl", "base_url", "password", "credential", "raw",
}

func assertNoForbiddenFields(t *testing.T, value any) {
	t.Helper()
	typ := reflect.TypeOf(value)
	for typ != nil && typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ == nil || typ.Kind() != reflect.Struct {
		t.Fatalf("只对结构体做字段审查，当前是 %v", typ)
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue // 未导出字段不参与序列化
		}
		name := strings.ToLower(field.Name)
		tag := strings.ToLower(field.Tag.Get("json"))
		tagName := tag
		if i := strings.Index(tag, ","); i >= 0 {
			tagName = tag[:i]
		}
		haystack := name + "|" + tagName
		for _, word := range forbiddenFieldWords {
			if strings.Contains(haystack, word) {
				t.Errorf("%s.%s（json=%q）含被禁字段词 %q：领域对象不得携带正文或凭证", typ.Name(), field.Name, tag, word)
			}
		}
	}
}

func TestDomainObjectsCarryNoBodyOrCredentials(t *testing.T) {
	for _, value := range []any{
		Identity{}, PolicyContext{}, Entitlement{}, Decision{}, MatchedRule{},
		RoutingPlan{}, RouteCandidate{}, Rejection{}, ScopeRef{}, PolicyBundle{},
	} {
		assertNoForbiddenFields(t, value)
	}
}

// 正文访问三档的缺省必须是最严格的一档（§2.9：正文访问必须显式声明）。
func TestBodyAccessDefaultsToMetadataOnly(t *testing.T) {
	for _, s := range []string{"", "   ", "METADATA-ONLY"} {
		got, err := ParseBodyAccess(s)
		if err != nil {
			t.Fatalf("%q 解析失败: %v", s, err)
		}
		if got != BodyMetadataOnly {
			t.Fatalf("%q 应落到 metadata-only，实际 %s", s, got)
		}
	}
	for _, s := range []string{"read-body", "raw", "transform", "metadata"} {
		if _, err := ParseBodyAccess(s); err == nil {
			t.Fatalf("%q 必须被拒绝，档位是封闭集合", s)
		}
	}
	if BodyMetadataOnly.CanReadBody() || BodyMetadataOnly.CanReplaceBody() {
		t.Fatal("metadata-only 不应能读或改正文")
	}
	if !BodyInspect.CanReadBody() || BodyInspect.CanReplaceBody() {
		t.Fatal("inspect-body 只能读不能替换")
	}
	if !BodyTransform.CanReadBody() || !BodyTransform.CanReplaceBody() {
		t.Fatal("transform-body 应同时具备读与替换")
	}
}

// 判定结果里不能出现 Conditions 的取值：那些是运营者写的组织内部命名
// （项目代号、内部组名），一旦随 Decision 落进请求级审计就扩散了。
func TestDecisionDoesNotLeakConditionValues(t *testing.T) {
	const codename = "internal-codename-XYZ"
	rule := allowRule("alice", "model:gpt-5", "use").withCondition(CondProject, codename)
	r := mustResolver(t, "core@1", rule)
	id := student(t, "alice", []string{"student"}, []string{"cs"})
	ctx, err := NewPolicyContext(id, "qa", LevelInternal)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Organization = "university"
	ctx.Project = codename
	d := r.Evaluate(ctx, chain(MustScope(ScopeUser, "alice")), "model:gpt-5", "use", baseNow)
	if !d.Allowed {
		t.Fatalf("应放行: %+v", d)
	}
	blob, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{d.Explain(), string(blob)} {
		if strings.Contains(s, codename) {
			t.Fatalf("判定输出泄露了 Conditions 取值: %s", s)
		}
	}
	// Conditions 本身只该出现在策略包（配置）里，不该出现在判定输出里。
	if strings.Contains(string(blob), CondProject) {
		t.Fatalf("判定输出不应含条件键: %s", blob)
	}
}

// 原因码必须是稳定标识符，不能被人塞进一句带业务信息的话。
func TestReasonCodesAreStableIdentifiers(t *testing.T) {
	for r := range allReasons {
		s := string(r)
		if strings.ContainsAny(s, " :;,") {
			t.Errorf("原因码 %q 含分隔符或空格", s)
		}
		if len(s) > 40 {
			t.Errorf("原因码 %q 过长", s)
		}
		if s != strings.ToLower(s) {
			t.Errorf("原因码 %q 必须全小写", s)
		}
	}
}

// 跨组织隔离：A 组织的 deny/allow 不能参与 B 组织范围的判定。
func TestCrossOrganizationIsolation(t *testing.T) {
	set := MustBundleSet(
		bundle("org-a", 1, MustScope(ScopeOrganization, "hospital-a"),
			allowRule("role:doctor", "model:*", "use"),
			denyRule("role:doctor", "model:public-demo", "use"),
		),
		bundle("base", 1, MustScope(ScopeSystem, "global"),
			allowRule("*", "model:public-demo", "use"),
		),
	)
	other := chainOf(t, "alice", "university", "")
	rules := set.EntitlementsFor(other)
	for _, rule := range rules {
		if strings.Contains(rule.Subject, "doctor") {
			t.Fatalf("hospital-a 的规则泄漏进了 university 范围: %+v", rule)
		}
	}
	// 判定层面同样不能借用邻组织的授权。
	r, err := FromBundles(set, other)
	if err != nil {
		t.Fatal(err)
	}
	doctor := student(t, "alice", []string{"doctor"}, []string{"cs"})
	if d := r.Evaluate(ctxOf(t, doctor, "qa", LevelInternal), other, "model:private-mri", "use", baseNow); d.Allowed {
		t.Fatalf("hospital-a 的医生授权不应扩散到 university: %+v", d)
	}
	// 版本串按范围出具：整集版本含两个包，university 范围只能含 base。
	fullVersion, err := set.PolicyVersion()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fullVersion, "org-a@") || !strings.Contains(fullVersion, "base@") {
		t.Fatalf("整集版本应含所有已加载包: %s", fullVersion)
	}
	filtered, err := set.Filter(other)
	if err != nil {
		t.Fatal(err)
	}
	scopedVersion, err := filtered.PolicyVersion()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(scopedVersion, "org-a@") || scopedVersion == fullVersion {
		t.Fatalf("按范围出具版本时必须剔除无关包: %s vs %s", scopedVersion, fullVersion)
	}
	if r.Version() != scopedVersion {
		t.Fatalf("内核版本必须与实际生效的子集一致: %s vs %s", r.Version(), scopedVersion)
	}
	// hospital-a 自己的 chain 才拿得到 org-a 包。
	inOrg, err := FromBundles(set, chainOf(t, "bob", "hospital-a", ""))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inOrg.Version(), "org-a@1") {
		t.Fatalf("本组织 chain 应含本组织包: %s", inOrg.Version())
	}
}
