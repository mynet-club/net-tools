package replay

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/routing"
)

// 记录结构是审计表的行、是回放的输入，也是别人接手时最容易往里加字段的地方。
// 「不得含正文、正文摘要、prompt、messages、密钥、token、个人信息」这句话只要有一次
// 靠评审时盯字段来保证，就一定会漏。这里把它变成会失败的断言（对齐 A 包 leak_test.go）。

func recordStructs() []any {
	return []any{
		File{}, DecisionRecord{}, RoutingRecord{}, SubjectSnapshot{}, ContextSnapshot{},
		RuleRef{}, DecisionCapture{}, RoutingCapture{}, Outcome{}, FieldDiff{}, Report{}, Options{},
	}
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
		tag := field.Tag.Get("json")
		name := tag
		if j := strings.Index(tag, ","); j >= 0 {
			name = tag[:j]
		}
		if name == "-" {
			continue
		}
		haystack := strings.ToLower(field.Name) + "|" + strings.ToLower(name)
		for _, word := range forbiddenFieldWords {
			if strings.Contains(haystack, word) {
				t.Errorf("%s.%s（json=%q）命中被禁词 %q：记录不得携带正文或凭证", typ.Name(), field.Name, tag, word)
			}
		}
	}
}

func TestRecordStructsCarryNoBodyOrCredentials(t *testing.T) {
	for _, v := range recordStructs() {
		assertNoForbiddenFields(t, v)
	}
	// 记录里内嵌了 A 包的路由结构，一并审查：候选与排除原因都不许带 base_url / 密钥。
	for _, v := range []any{
		policy.RoutingPlan{}, policy.RouteCandidate{}, policy.Rejection{},
		policy.MatchedRule{}, policy.Decision{}, policy.PolicyContext{}, policy.Identity{},
	} {
		assertNoForbiddenFields(t, v)
	}
	// v2 起记录内嵌 D 的完整回放快照（RoutingRecord.Replay），它是记录的一部分，
	// 审查口径必须跟着走：快照里除了运行时事实，一个正文/凭证类字段都不许出现。
	// 这条断言同时也是那道窄接口的边界——有人想往里加个 *http.Client 或 provider 配置，
	// 先在这里撞墙，而不是等到「这份快照不再能跨进程复现」时才被发现。
	for _, v := range []any{
		routing.ReplayInput{}, routing.ReplayOffer{}, routing.Requirement{}, routing.StickyState{},
	} {
		assertNoForbiddenFields(t, v)
	}
}

func TestForbiddenWordsCoverTheContract(t *testing.T) {
	// §2.8 / §2.9 点名的东西必须在词表里，否则这条纪律是空的。
	for _, word := range []string{"body", "prompt", "messages", "secret", "api_key", "token", "password", "raw"} {
		found := false
		for _, w := range ForbiddenFieldWords() {
			if w == word {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("被禁词表缺 %q", word)
		}
	}
	for _, name := range []string{"request_body", "bodyDigest", "Prompt", "messages", "api_key", "AccessToken", "password", "rawText", "base_url"} {
		if forbiddenWordHit(name) == "" {
			t.Fatalf("字段名 %q 应该被拦下", name)
		}
	}
	for _, name := range []string{"request_id", "policy_version", "sort_key", "external_plaintext_allowed", "candidates_digest"} {
		if hit := forbiddenWordHit(name); hit != "" {
			t.Fatalf("合法字段 %q 被误伤（命中 %q）", name, hit)
		}
	}
}

// 序列化产物侧再兜一道：反射管住本包结构，键扫描管住嵌套与将来的字段变化。
func TestEncodedRecordsHaveNoForbiddenKeys(t *testing.T) {
	data, err := Encode(baselineFile(t))
	if err != nil {
		t.Fatal(err)
	}
	if hit := scanForbiddenKeys(data); hit != "" {
		t.Fatalf("导出结果含被禁键: %s", hit)
	}
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	collectJSONKeys(root, keys)
	for _, want := range []string{"request_id", "policy_version", "routing_seed", "candidates_digest", "scope_chain", "external_plaintext_allowed"} {
		if !keys[want] {
			t.Fatalf("记录里应有 %q 字段，实际键集 %+v", want, sortedKeys(keys))
		}
	}
}

// 显示名属于个人信息，判定不需要它：记录里绝不能出现。
func TestRecordOmitsDisplayName(t *testing.T) {
	const canary = "张三-Alice-展示名"
	set := testBundles(t)
	chain := chainOf(t, "alice", "university", "")
	id := identityOf(t, "alice", []string{"student"}, []string{"cs"})
	id.DisplayName = canary
	rec := captureDecision(t, set, "req-display", baseNow, chain, id, ctxOf(t, id, "university", policy.LevelInternal),
		"model:gpt-5", policy.ActionUse)
	data := MustEncode(NewFile([]DecisionRecord{rec}, nil))
	if strings.Contains(data, canary) {
		t.Fatalf("记录携带了显示名: %s", data)
	}
	// SubjectSnapshot 根本没有 DisplayName 字段：结构上就没法把它塞进去（上面的键扫描是第二道门）。
	snapshot := reflect.ValueOf(rec.Subject)
	for i := 0; i < snapshot.NumField(); i++ {
		if strings.Contains(strings.ToLower(snapshot.Type().Field(i).Name), "display") {
			t.Fatalf("身份快照不该保留显示名字段: %s", snapshot.Type().Field(i).Name)
		}
	}
}

// 规则的 Conditions 不进记录：那是运营者写的内部命名（A 包对 Decision 输出同口径）。
//
// 判定需要的事实（purpose / organization / project / 成员关系）本来就存在 subject 与
// context 快照里，所以规则侧的条件映射完全可以从策略包复原 —— 记录只留规则标识。
func TestRecordOmitsConditionValues(t *testing.T) {
	const codename = "proj-internal-codename-XYZ"
	set := policy.MustBundleSet(
		bundleOf("system-default", 1, policy.MustScope(policy.ScopeSystem, "global"),
			withScope(withCondition(allowRule("alice", "model:gpt-5", policy.ActionUse), policy.CondProject, codename), "organization:university")),
	)
	chain := chainOf(t, "alice", "university", "")
	id := identityOf(t, "alice", []string{"student"}, []string{"cs"})
	ctx := ctxOf(t, id, "university", policy.LevelInternal)
	r, err := policy.FromBundles(set, chain)
	if err != nil {
		t.Fatal(err)
	}
	// ctx.Project 不等于代号：条件不成立 → 规则不参与，结论是拒绝。
	d := r.Evaluate(ctx, chain, "model:gpt-5", policy.ActionUse, baseNow)
	if d.Allowed {
		t.Fatalf("条件不成立时规则不该生效: %+v", d)
	}
	rec, err := DecisionRecordFrom(DecisionCapture{
		RequestID: "req-cond", RecordedAt: baseNow, Chain: chain, Subject: id, Ctx: ctx,
		Resource: "model:gpt-5", Action: policy.ActionUse, Decision: d, WiringMode: ModeShadow,
	})
	if err != nil {
		t.Fatal(err)
	}
	data := MustEncode(NewFile([]DecisionRecord{rec}, nil))
	if strings.Contains(data, codename) {
		t.Fatalf("记录泄露了条件取值: %s", data)
	}

	// 结构侧：条件成立的那条路径也不允许出现 conditions 键。
	ctx.Project = codename
	if d := r.Evaluate(ctx, chain, "model:gpt-5", policy.ActionUse, baseNow); !d.Allowed {
		t.Fatalf("条件应成立: %+v", d)
	}
	matched, err := DecisionRecordFrom(DecisionCapture{
		RequestID: "req-cond-allow", RecordedAt: baseNow, Chain: chain, Subject: id, Ctx: ctx,
		Resource: "model:gpt-5", Action: policy.ActionUse, Decision: d, WiringMode: ModeShadow,
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	collectKeys([]byte(MustEncode(NewFile([]DecisionRecord{matched}, nil))), keys)
	for _, banned := range []string{"conditions", "condition", "rule_text", "rule_body"} {
		if keys[banned] {
			t.Fatalf("记录里出现了 %q 键", banned)
		}
	}
	for _, rule := range matched.Matched {
		if rule.SortKey == "" {
			t.Fatal("规则引用必须带可复核的标识")
		}
	}
	ref := reflect.ValueOf(RuleRef{})
	for i := 0; i < ref.NumField(); i++ {
		if strings.Contains(strings.ToLower(ref.Type().Field(i).Name), "condition") {
			t.Fatalf("规则引用不该有 conditions 字段: %s", ref.Type().Field(i).Name)
		}
	}
}

func collectJSONKeys(node any, out map[string]bool) {
	switch v := node.(type) {
	case map[string]any:
		for k, val := range v {
			out[k] = true
			collectJSONKeys(val, out)
		}
	case []any:
		for _, item := range v {
			collectJSONKeys(item, out)
		}
	}
}

func sortedKeys(in map[string]bool) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func withCondition(e policy.Entitlement, key, value string) policy.Entitlement {
	cond := map[string]string{}
	for k, v := range e.Conditions {
		cond[k] = v
	}
	cond[key] = value
	e.Conditions = cond
	return e
}
