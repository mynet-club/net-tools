package replay

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// baselineFile 构造一份小记录集：两条判定 + 一条路由，全部来自合成主体。
func baselineFile(t *testing.T) File {
	t.Helper()
	set := testBundles(t)
	chain := chainOf(t, "alice", "university", "")
	id := identityOf(t, "alice", []string{"student"}, []string{"cs"})
	ctx := ctxOf(t, id, "university", policy.LevelInternal)

	allowed := captureDecision(t, set, "req-allow", baseNow, chain, id, ctx, "model:gpt-5", policy.ActionUse)
	denied := captureDecision(t, set, "req-deny", baseNow, chain, id, ctx, "model:gpt-max", policy.ActionUse)
	if denied.Effect != policy.EffectDeny {
		t.Fatalf("gpt-max 对学生应被 deny 压住，实际 %+v", denied)
	}
	routing := routingFixture(t, "req-allow", allowed.PolicyVersion, baseNow,
		[]policy.RouteCandidate{
			candidate("gpt-mini", "gpt-mini", 1),
			candidate("gpt-5", "gpt-5", 3),
			candidate("public-demo", "public-demo", 1),
		},
		[]policy.Rejection{rejection("public-demo", policy.ReasonCandidateLevelExcluded)}, 1)
	return NewFile([]DecisionRecord{allowed, denied}, []RoutingRecord{routing})
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	f := baselineFile(t)
	data, err := Encode(f)
	if err != nil {
		t.Fatalf("导出失败: %v", err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatalf("导入失败: %v", err)
	}
	if len(got.Decisions) != len(f.Decisions) || len(got.Routings) != len(f.Routings) {
		t.Fatalf("往返后记录数变了: %d/%d vs %d/%d", len(got.Decisions), len(got.Routings), len(f.Decisions), len(f.Routings))
	}
	// 逐条比较用回放结果，而不是结构体 ==：time.Time 用 == 会连单调时钟一起比。
	r, err := New(testBundles(t), Options{Now: baseNow})
	if err != nil {
		t.Fatal(err)
	}
	before, err := r.Run(f)
	if err != nil {
		t.Fatalf("原记录集回放失败: %v", err)
	}
	after, err := r.Run(got)
	if err != nil {
		t.Fatalf("往返记录集回放失败: %v", err)
	}
	d1, _ := before.Digest()
	d2, _ := after.Digest()
	if d1 != d2 {
		t.Fatalf("序列化往返改变了回放结论:\n%s\n%s", before.String(), after.String())
	}
}

func TestTimesSerializeAsRFC3339(t *testing.T) {
	data, err := Encode(baselineFile(t))
	if err != nil {
		t.Fatal(err)
	}
	times := collectTimeFields(t, data)
	if len(times) == 0 {
		t.Fatal("记录里应至少有一个时间字段")
	}
	for _, s := range times {
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			t.Fatalf("时间 %q 不是 RFC3339（§5）: %v", s, err)
		}
		if strings.Contains(s, ".") {
			t.Fatalf("时间 %q 带亚秒尾巴：记录一律 UTC 秒级，否则跨语言侧按 RFC3339 重算会对不上", s)
		}
		if !strings.HasSuffix(s, "Z") {
			t.Fatalf("时间 %q 未归一到 UTC", s)
		}
	}
}

// collectTimeFields 走 JSON 结构取所有 *_at 字段的字符串值，避免按行切字符串时把
// 引号和逗号也算进值里。
func collectTimeFields(t *testing.T, data []byte) []string {
	t.Helper()
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("导出结果不是合法 JSON: %v", err)
	}
	var out []string
	walkTimes(root, &out)
	return out
}

func walkTimes(node any, out *[]string) {
	switch v := node.(type) {
	case map[string]any:
		for k, val := range v {
			if s, ok := val.(string); ok && strings.HasSuffix(k, "_at") {
				*out = append(*out, s)
				continue
			}
			walkTimes(val, out)
		}
	case []any:
		for _, item := range v {
			walkTimes(item, out)
		}
	}
}

func TestFieldNamesAreSnakeCase(t *testing.T) {
	data, err := Encode(baselineFile(t))
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	collectKeys(data, keys)
	if len(keys) == 0 {
		t.Fatal("没解析出任何键")
	}
	for name := range keys {
		if name == "" {
			continue
		}
		if strings.Contains(name, " ") || strings.Contains(name, "\t") {
			t.Fatalf("字段 %q 含空白", name)
		}
		for _, part := range strings.Split(name, "_") {
			if part != strings.ToLower(part) {
				t.Fatalf("字段 %q 不是 snake_case（§5）", name)
			}
		}
	}
}

// collectKeys 按 JSON 结构收集所有键名：按行切会把时间值里的冒号误当成键值分隔。
func collectKeys(data []byte, out map[string]bool) {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return
	}
	var walk func(node any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			for k, val := range v {
				out[k] = true
				walk(val)
			}
		case []any:
			for _, item := range v {
				walk(item)
			}
		}
	}
	walk(root)
}

func TestDecodeRejectsUnknownFieldsAndBadSchema(t *testing.T) {
	data, err := Encode(baselineFile(t))
	if err != nil {
		t.Fatal(err)
	}
	// 未知字段必须拒绝：多出来的键意味着有人在记录里塞没被契约承认的东西（最典型是正文）。
	withExtra := bytes.Replace(data, []byte(`"schema_version": 1,`), []byte(`"schema_version": 1, "note": "x",`), 1)
	if bytes.Equal(withExtra, data) {
		t.Fatal("测试注入失败：没找到 schema_version 锚点")
	}
	if _, err := Decode(withExtra); err == nil {
		t.Fatal("未知字段必须被拒绝")
	}

	for _, bad := range []string{`{"schema_version": 2, "decisions": []}`, `{"schema_version": 0}`, `not json`} {
		if _, err := Decode([]byte(bad)); err == nil {
			t.Fatalf("必须拒绝: %s", bad)
		}
	}
	if _, err := Decode(nil); err == nil {
		t.Fatal("空文件必须报错，不能被当成「零条记录，回放全绿」")
	}
}

func TestDecodeRejectsForbiddenKeysEvenWhenNested(t *testing.T) {
	// 手工构造一份「看起来合法但带了正文字段」的 JSON：加载侧必须靠键名扫描拦住，
	// 而不是指望结构体里没有对应字段就万事大吉。
	raw := `{"schema_version":1,"decisions":[{"request_id":"req-1","recorded_at":"2026-03-01T12:00:00Z",` +
		`"policy_version":"x@1","prompt_excerpt":"你好"}]}`
	if _, err := Decode([]byte(raw)); err == nil {
		t.Fatal("含 prompt 键的记录必须被拒绝")
	} else if !strings.Contains(err.Error(), "被禁字段") {
		t.Fatalf("错误应指向被禁字段，实际 %v", err)
	}

	// 导出侧同样扫一遍，防止将来加字段时手滑。
	f := baselineFile(t)
	f.Decisions[0].Reasons = []policy.Reason{policy.ReasonDenyRule}
	if _, err := Encode(f); err != nil {
		t.Fatalf("正常记录不应触发键扫描: %v", err)
	}
}

func TestReadAndWriteStream(t *testing.T) {
	var buf bytes.Buffer
	f := baselineFile(t)
	if err := WriteTo(&buf, f); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrom(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != SchemaVersion || len(got.Decisions) != 2 || len(got.Routings) != 1 {
		t.Fatalf("流式读写结果不对: %+v", got)
	}
}

func TestFileValidateUsesReplayClock(t *testing.T) {
	f := baselineFile(t)
	if err := f.Validate(baseNow); err != nil {
		t.Fatalf("基线记录应自洽: %v", err)
	}
	f.SchemaVersion = 99
	if err := f.Validate(baseNow); err == nil {
		t.Fatal("未知结构版本必须拒绝")
	}
}
