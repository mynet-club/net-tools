package policy

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"
)

func candidate(provider, upstream string, weight float64) RouteCandidate {
	return RouteCandidate{
		Executor:      "http-openai",
		Provider:      provider,
		Model:         "gpt-5",
		UpstreamModel: upstream,
		Weight:        weight,
		MaxDataLevel:  LevelInternal,
	}
}

func validPlan() RoutingPlan {
	return RoutingPlan{
		Executor:       "http-openai",
		Model:          "gpt-5",
		UpstreamModel:  "gpt-5-2026",
		Fallbacks:      []RouteCandidate{candidate("prov-a", "gpt-5-2026", 3), candidate("prov-b", "gpt-5-mini", 1)},
		ProcessorChain: []string{"pii-redact", "json-schema"},
		MaxRetries:     2,
		ReasonCodes:    []Reason{ReasonWeightedChoice, ReasonAffinityHit},
		PolicyVersion:  "uni@2",
		ExpiresAt:      hoursAfter(1),
	}
}

func TestPlanValidation(t *testing.T) {
	if err := validPlan().Validate(baseNow); err != nil {
		t.Fatalf("合法计划不应报错: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(p *RoutingPlan)
	}{
		{"缺 executor", func(p *RoutingPlan) { p.Executor = "" }},
		{"缺 model", func(p *RoutingPlan) { p.Model = "" }},
		{"缺 upstream_model", func(p *RoutingPlan) { p.UpstreamModel = "" }},
		{"缺策略版本", func(p *RoutingPlan) { p.PolicyVersion = "" }},
		{"缺 TTL", func(p *RoutingPlan) { p.ExpiresAt = time.Time{} }},
		{"TTL 已过", func(p *RoutingPlan) { p.ExpiresAt = baseNow.Add(-time.Second) }},
		{"负重试", func(p *RoutingPlan) { p.MaxRetries = -1 }},
		{"候选重复", func(p *RoutingPlan) {
			p.Fallbacks = []RouteCandidate{candidate("prov-a", "x", 1), candidate("prov-a", "y", 1)}
		}},
		{"候选缺等级", func(p *RoutingPlan) { p.Fallbacks[0].MaxDataLevel = LevelUnknown }},
		{"未注册原因码", func(p *RoutingPlan) { p.ReasonCodes = []Reason{"随便写的自然语言"} }},
		{"未注册排除码", func(p *RoutingPlan) { p.Rejections = []Rejection{{Provider: "prov-c", Reason: "oops"}} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := validPlan()
			c.mutate(&p)
			if err := p.Validate(baseNow); err == nil {
				t.Fatalf("%s 必须被拒绝", c.name)
			}
		})
	}
}

func TestPlanAttempts(t *testing.T) {
	p := validPlan()
	if got := p.Attempts(); got != 2 {
		t.Fatalf("候选只有 2 个时最多试 2 次，实际 %d", got)
	}
	p.MaxRetries = 0
	if got := p.Attempts(); got != 1 {
		t.Fatalf("MaxRetries=0 应只试一次，实际 %d", got)
	}
	p = validPlan()
	p.MaxRetries = 99
	if got := p.Attempts(); got != 2 {
		t.Fatalf("重试次数不能超候选数，实际 %d", got)
	}
	if _, ok := p.Primary(); !ok {
		t.Fatal("Primary 应给出首选")
	}
	empty := validPlan()
	empty.Fallbacks = nil
	if _, ok := empty.Primary(); ok {
		t.Fatal("空候选列表应返回 false")
	}
}

// 摘要必须与候选书写顺序无关：回放断言靠的就是这一点。
func TestPlanDigestIsOrderIndependent(t *testing.T) {
	p := validPlan()
	first, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	shuffled := validPlan()
	for i := 0; i < 20; i++ {
		reversed := RoutingPlan(shuffled)
		reversed.Fallbacks = []RouteCandidate{shuffled.Fallbacks[1], shuffled.Fallbacks[0]}
		reversed.ReasonCodes = []Reason{ReasonAffinityHit, ReasonWeightedChoice}
		got, err := reversed.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if got != first {
			t.Fatalf("顺序抖动导致摘要变化: %s vs %s", first, got)
		}
	}
	// 换一个 provider 必须变摘要。
	changed := validPlan()
	changed.Fallbacks[0].Provider = "prov-z"
	if d, _ := changed.Digest(); d == first {
		t.Fatal("候选改变后摘要必须改变")
	}
	// 策略版本改变也要能看出来。
	bumped := validPlan()
	bumped.PolicyVersion = "uni@3"
	if d, _ := bumped.Digest(); d == first {
		t.Fatal("策略版本改变后摘要必须改变")
	}
}

func TestCandidatesDigestExcludesNonIdentityFields(t *testing.T) {
	// 摘要只覆盖稳定标识与权重：区域、执行器实现名不参与，
	// 这样同一家换 IP/换协议实现不会让历史审计的候选摘要全部对不上。
	a, err := CandidatesDigest([]RouteCandidate{candidate("prov-a", "gpt-5-2026", 3)})
	if err != nil {
		t.Fatal(err)
	}
	withRegion := candidate("prov-a", "gpt-5-2026", 3)
	withRegion.Region = "cn-north"
	withRegion.Executor = "http-openai-v2"
	b, err := CandidatesDigest([]RouteCandidate{withRegion})
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("候选摘要不应受区域/执行器实现名影响")
	}
	other, err := CandidatesDigest([]RouteCandidate{candidate("prov-a", "gpt-5-2026", 1)})
	if err != nil {
		t.Fatal(err)
	}
	if a == other {
		t.Fatal("权重变化必须反映到摘要里 —— 回放输入要含有效权重")
	}
}

func TestSortCandidatesStable(t *testing.T) {
	in := []RouteCandidate{
		candidate("prov-b", "m2", 1),
		candidate("prov-a", "m9", 1),
		candidate("prov-a", "m1", 1),
	}
	out := SortCandidates(in)
	var names []string
	for _, c := range out {
		names = append(names, c.Provider+"/"+c.UpstreamModel)
	}
	want := "prov-a/m1,prov-a/m9,prov-b/m2"
	if strings.Join(names, ",") != want {
		t.Fatalf("排序结果不对: %v", names)
	}
	// 原切片不动（调用方可能还在用）。
	if in[0].Provider != "prov-b" {
		t.Fatal("SortCandidates 必须返回副本")
	}
}

// §2.8：seed 由 request_id / policy_version / routing_epoch 派生，
// 三项任一变化都要换 seed，否则回放会把两次不同的决策当成同一次。
func TestDeriveRoutingSeed(t *testing.T) {
	base, err := DeriveRoutingSeed("req-1", "uni@2", "7")
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != sha256HexLen {
		t.Fatalf("seed 应是 %d 位十六进制，实际 %d", sha256HexLen, len(base))
	}
	if err := ParseRoutingSeed(base); err != nil {
		t.Fatalf("派生出的 seed 应可校验: %v", err)
	}
	again, _ := DeriveRoutingSeed("req-1", "uni@2", "7")
	if again != base {
		t.Fatal("同输入必须同 seed")
	}
	for _, variant := range [][3]string{
		{"req-2", "uni@2", "7"},
		{"req-1", "uni@3", "7"},
		{"req-1", "uni@2", "8"},
	} {
		got, err := DeriveRoutingSeed(variant[0], variant[1], variant[2])
		if err != nil {
			t.Fatal(err)
		}
		if got == base {
			t.Fatalf("输入 %v 与基线撞出同一个 seed", variant)
		}
	}
	// 长度前缀防止拼接歧义：("a|b","c") 与 ("a","b|c") 不能同 seed。
	x, _ := DeriveRoutingSeed("a|b", "c", "1")
	y, _ := DeriveRoutingSeed("a", "b|c", "1")
	if x == y {
		t.Fatal("seed 输入存在拼接歧义")
	}
	if _, err := DeriveRoutingSeed("", "uni@2", "7"); err == nil {
		t.Fatal("空 request_id 必须拒绝")
	}
	if _, err := DeriveRoutingSeed("req-1", "", "7"); err == nil {
		t.Fatal("空策略版本必须拒绝")
	}
	for _, bad := range []string{"", "abc", strings.Repeat("z", sha256HexLen), strings.Repeat("0", sha256HexLen-1) + "g"} {
		if err := ParseRoutingSeed(bad); err == nil {
			t.Fatalf("非法 seed 必须拒绝: %q", bad)
		}
	}
}

const sha256HexLen = 64

// §5：时间统一 RFC3339 序列化 —— 跨语言侧按同一结构重算摘要才能对齐。
func TestPlanJSONRoundTripUsesRFC3339(t *testing.T) {
	p := validPlan()
	p.RoutingSeed = strings.Repeat("ab", sha256HexLen/2)
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	expiry, ok := wire["expires_at"].(string)
	if !ok || !strings.HasPrefix(expiry, "2026-03-01T13:00:00Z") {
		t.Fatalf("expires_at 必须是 RFC3339: %v", wire["expires_at"])
	}
	if !strings.Contains(string(data), `"max_data_level"`) {
		// 候选里的等级要参与序列化，否则回放拿不到数据约束。
		t.Fatalf("计划序列化缺少等级字段: %s", data)
	}
	var back RoutingPlan
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if err := back.Validate(baseNow); err != nil {
		t.Fatalf("反序列化后应仍合法: %v", err)
	}
	if back.RoutingSeed != p.RoutingSeed || back.PolicyVersion != p.PolicyVersion {
		t.Fatal("回放输入字段必须完整往返")
	}
	d1, _ := p.Digest()
	d2, _ := back.Digest()
	if d1 != d2 {
		t.Fatal("往返后摘要必须一致")
	}
}

func TestReasonRegistryIsClosed(t *testing.T) {
	// 每个已注册原因码都要能通过校验；未注册的必须失败（防止把自然语言写进审计）。
	for r := range allReasons {
		if !r.Valid() {
			t.Fatalf("注册表自相矛盾: %s", r)
		}
	}
	if Reason("model not allowed because user is a student").Valid() {
		t.Fatal("自然语言不能当原因码")
	}
	if Reason("").Valid() {
		t.Fatal("空原因码不合法")
	}
	// Reasons 去重排序：审计字段顺序不能随判定过程抖动。
	got := Reasons([]Reason{ReasonDenyRule, ReasonExplicitAllow, ReasonDenyRule})
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i] < got[j] }) {
		t.Fatalf("原因链未排序: %v", got)
	}
	if len(got) != 2 {
		t.Fatalf("原因链未去重: %v", got)
	}
	if Reasons(nil) != nil {
		t.Fatal("空原因链应序列化为缺省")
	}
}
