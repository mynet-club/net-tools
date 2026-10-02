package routing

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// replayFixture 走一遍「线上带 seed 规划 → 落快照 → 回放」的完整链路。
func replayFixture(t *testing.T, gate Gate, offers []Offer, requestID, version string) (policy.RoutingPlan, ReplayInput) {
	t.Helper()
	ctx := ctxFor(t, policy.LevelInternal)
	ctx.PolicyVersion = version
	chain := orgChain(t)
	in := inputFor(gate, ObjectiveFixedOrder, offers...)
	in.RequestID = requestID
	in.PolicyVersion = version
	in.Seed = deriveSeed(t, requestID, version)
	plan, snapshot, err := NewPlanner().PlanWithReplay(ctx, chain, in)
	if err != nil {
		t.Fatalf("规划失败: %v", err)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("快照自身不合法: %v", err)
	}
	return plan, snapshot
}

var replayOffers = []Offer{
	offerFor("alpha", 0, 3, testModel),
	offerFor("beta", 0, 1, testModel),
	offerFor("gamma", 1, 2, testModel),
}

// 线上带 seed 的规划必须能被逐位复现（§2.8 的整个动机就在这条）。
func TestOnlinePlanReplaysBitForBit(t *testing.T) {
	online, snapshot := replayFixture(t, &allowAllGate{}, replayOffers, "req-replay", "core@1")
	replayed, err := PlanFromReplay(snapshot)
	if err != nil {
		t.Fatalf("回放失败: %v", err)
	}
	if got, want := mustDigest(t, replayed), mustDigest(t, online); got != want {
		t.Fatalf("回放摘要与线上不同: %s vs %s", got, want)
	}
	if !reflect.DeepEqual(orderOf(replayed), orderOf(online)) {
		t.Fatalf("回放顺序抖动: %v vs %v", orderOf(replayed), orderOf(online))
	}
	if !reflect.DeepEqual(replayed, online) {
		t.Fatalf("回放结果整体不同:\n 线上 %+v\n 回放 %+v", online, replayed)
	}
	if replayed.RoutingSeed != snapshot.Seed {
		t.Errorf("回放计划必须带回同一个 seed")
	}
}

// Replay 断言函数：同一份输入连续重算必须得到同一个 Digest。
func TestReplayAssertsReproducibility(t *testing.T) {
	_, snapshot := replayFixture(t, &allowAllGate{}, replayOffers, "req-assert", "core@1")
	first, digestA, err := Replay(snapshot)
	if err != nil {
		t.Fatalf("Replay 断言失败: %v", err)
	}
	if c, _ := first.Primary(); c.Provider == "" {
		t.Fatal("Replay 没给出可执行计划")
	}
	second, digestB, err := Replay(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if digestA != digestB || joinOrder(first) != joinOrder(second) {
		t.Fatalf("同一份输入两次 Replay 结论不同: %s/%s vs %s/%s", digestA, joinOrder(first), digestB, joinOrder(second))
	}
	// 改一个数（权重）→ 结论必须跟着变，否则说明回放没在用输入里记的权重，
	// 而是在重新派生（那等于把「默认值改了」这种无关变更变成历史决策变更）。
	tampered := snapshot
	tampered.Offers[0].Weight = 99
	if _, changed, err := Replay(tampered); err != nil {
		t.Fatal(err)
	} else if changed == digestA {
		t.Error("篡改有效权重却得到同一个摘要：权重没被当成回放输入")
	}
}

// 策略版本必须参与 seed（§2.8 的 H(request_id || policy_version || routing_epoch)）。
// 同 requestID、不同版本 → 不同 seed → 不同结论；各自回放各自一致。
func TestPolicyVersionParticipatesInSeed(t *testing.T) {
	seedV1 := deriveSeed(t, "req-versioned", "core@1")
	seedV2 := deriveSeed(t, "req-versioned", "core@2")
	if seedV1 == seedV2 {
		t.Fatal("版本变了 seed 却没变：策略升级不会刷新回放结论，等于版本不参与 seed")
	}
	planV1, snapV1 := replayFixture(t, &allowAllGate{}, replayOffers, "req-versioned", "core@1")
	planV2, snapV2 := replayFixture(t, &allowAllGate{}, replayOffers, "req-versioned", "core@2")
	if planV1.PolicyVersion == planV2.PolicyVersion {
		t.Fatal("计划上的版本串没区分开")
	}
	// 版本变化后，旧请求的回放仍与当初结论一致。
	for _, tc := range []struct {
		name    string
		online  policy.RoutingPlan
		snap    ReplayInput
		version string
	}{
		{"v1", planV1, snapV1, "core@1"},
		{"v2", planV2, snapV2, "core@2"},
	} {
		got, err := PlanFromReplay(tc.snap)
		if err != nil {
			t.Fatalf("%s 回放失败: %v", tc.name, err)
		}
		if mustDigest(t, got) != mustDigest(t, tc.online) {
			t.Errorf("%s 的回放与当初不同", tc.name)
		}
		if got.PolicyVersion != tc.version {
			t.Errorf("%s 回放出的版本串 = %s，应为 %s", tc.name, got.PolicyVersion, tc.version)
		}
	}
}

// 回放不得依赖当前 provider 配置、活的策略、活的时钟、活的随机源（§2.8）。
//
// 做法：拿到快照之后，把外部世界**全部换成相反的样子**。先用反转后的世界做一次
// 线上规划确认干扰是真实有效的（它必须规划失败），再回放同一份快照 ——
// 结论必须一动不动。只比「回放成功」没有区分力：一个忽略输入的桩也能通过。
func TestReplayIgnoresLiveWorld(t *testing.T) {
	online, snapshot := replayFixture(t, &allowAllGate{}, replayOffers, "req-dead-world", "core@1")
	before, err := snapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}

	denyAll := newStubGate(map[string]policy.Reason{
		"alpha": policy.ReasonDenyRule, "beta": policy.ReasonDenyRule, "gamma": policy.ReasonDenyRule,
	})
	interference := inputFor(denyAll, ObjectiveFixedOrder, replayOffers...)
	interference.Seed = snapshot.Seed
	strictCtx := ctxFor(t, policy.LevelRestricted) // 分级也抬高：让候选更易被排除
	if _, err := NewPlanner().Plan(strictCtx, orgChain(t), interference); err == nil {
		t.Fatal("干扰用的线上规划应当失败，否则这条断言没有区分力")
	}
	if len(denyAll.asks) == 0 {
		t.Fatal("活的 gate 没被问到，干扰路径没走到判定")
	}

	replayed, err := PlanFromReplay(snapshot)
	if err != nil {
		t.Fatalf("活的策略反转后回放竟失败: %v", err)
	}
	if mustDigest(t, replayed) != mustDigest(t, online) {
		t.Error("活的策略/分级/时钟影响了回放结论：回放没有只吃输入里记下的事实")
	}
	// PlanFromReplay 的签名里没有 Gate、RandomSource、time.Now —— 上面那段
	// 「换掉整个世界」就是把这条结构性事实变成会失败的断言。
	if got, _ := snapshot.Digest(); got != before {
		t.Error("回放输入被规划过程改动了：快照必须是不变数据")
	}
	if snapshot.RequestID != "req-dead-world" {
		t.Errorf("快照应带回 request_id 以便与那次请求对上，实际 %q", snapshot.RequestID)
	}
}

// 排除原因也要能回放：被 gate 拒的候选在回放里仍进 Rejections、仍不进 Fallbacks。
func TestReplayPreservesRejections(t *testing.T) {
	gate := newStubGate(map[string]policy.Reason{"beta": policy.ReasonDenyRule})
	offers := append([]Offer(nil), replayOffers...)
	online, snapshot := replayFixture(t, gate, offers, "req-rej", "core@1")

	r, ok := rejectionOf(online, "beta")
	if !ok || r != policy.ReasonDenyRule {
		t.Fatalf("线上就没记下策略拒绝: %+v", online.Rejections)
	}
	replayed, err := PlanFromReplay(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := rejectionOf(replayed, "beta"); !ok || got != policy.ReasonDenyRule {
		t.Errorf("回放丢了策略拒绝原因: %+v", replayed.Rejections)
	}
	if containsProviderName(replayed, "beta") {
		t.Errorf("被拒候选在回放里又进了 Fallbacks: %s", joinOrder(replayed))
	}
	if mustDigest(t, replayed) != mustDigest(t, online) {
		t.Errorf("含 Rejections 的计划回放不一致")
	}
}

// 没有 seed 的回放输入必须被拒绝：那是「解释性回放」，不能声称逐位复现（§2.8）。
// 其余「缺了就无法解释当时结论」的字段同理，全部在入口挡掉。
func TestReplayRequiresSeed(t *testing.T) {
	_, base := replayFixture(t, &allowAllGate{}, replayOffers, "req-noseed", "core@1")

	cases := []struct {
		name    string
		tamper  func(*ReplayInput)
		wantErr string
	}{
		{"缺 seed", func(r *ReplayInput) { r.Seed = "" }, "解释性回放"},
		{"seed 格式不对", func(r *ReplayInput) { r.Seed = "不够长" }, "routing_seed"},
		{"缺策略版本", func(r *ReplayInput) { r.PolicyVersion = "" }, "policy_version"},
		{"缺时间戳", func(r *ReplayInput) { r.Now = time.Time{} }, "自带"},
		{"TTL 非正", func(r *ReplayInput) { r.TTL = 0 }, "ttl"},
		{"候选清单为空", func(r *ReplayInput) { r.Offers = nil }, "候选清单"},
		{"候选重复", func(r *ReplayInput) {
			cp := append([]ReplayOffer(nil), r.Offers...)
			r.Offers = append(cp, cp[0])
		}, "出现两次"},
		{"gate 拒绝却不记码", func(r *ReplayInput) {
			cp := append([]ReplayOffer(nil), r.Offers...)
			cp[0].GateAllows = false
			cp[0].GateReason = ""
			r.Offers = cp
		}, "原因码"},
		{"分级未判定", func(r *ReplayInput) { r.DataLevel = policy.LevelUnknown }, "data_level"},
		{"缺主体", func(r *ReplayInput) { r.Subject = "" }, "subject"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := base
			tc.tamper(&snapshot)
			_, err := PlanFromReplay(snapshot)
			if err == nil {
				t.Fatalf("%s 竟被接受", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("错误信息应含 %q，实际 %q", tc.wantErr, err.Error())
			}
		})
	}

	// 缺 seed 的错误必须带原因码，管理台才分得清「这条审计根本不可回放」和「回放失败」。
	snapshot := base
	snapshot.Seed = ""
	_, err := PlanFromReplay(snapshot)
	var pe *PlanError
	if !errors.As(err, &pe) {
		t.Fatalf("应返回 *PlanError，实际 %T", err)
	}
	if pe.Reason != policy.ReasonReplaySeedMissing {
		t.Errorf("原因码 = %s，应为 replay_seed_missing", pe.Reason)
	}
}

// 快照必须能跨进程搬运：JSON 往返后回放结论不变（RFC3339 时间 + 纯数据字段）。
func TestReplayInputSurvivesJSONRoundTrip(t *testing.T) {
	online, snapshot := replayFixture(t, &allowAllGate{}, replayOffers, "req-wire", "core@1")
	blob, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("快照序列化失败: %v", err)
	}
	var decoded ReplayInput
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("快照反序列化失败: %v", err)
	}
	if !reflect.DeepEqual(decoded, snapshot) {
		t.Fatalf("JSON 往返改变了回放输入:\n got  %+v\n want %+v", decoded, snapshot)
	}
	replayed, err := PlanFromReplay(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if mustDigest(t, replayed) != mustDigest(t, online) {
		t.Error("跨进程搬运后的回放结论与线上不一致")
	}
	// 候选摘要也自带（§2.8 在线至少要记这四样）。
	if _, err := decoded.CandidatesDigest(); err != nil {
		t.Errorf("候选摘要失败: %v", err)
	}
}

// 回放出的计划带着**当时**的失效点：拿今天的时钟去看必然已过期，
// 这正是期望行为——历史计划不该被当成仍然有效。
func TestReplayedPlanKeepsHistoricalExpiry(t *testing.T) {
	online, snapshot := replayFixture(t, &allowAllGate{}, replayOffers, "req-ttl", "core@1")
	replayed, err := PlanFromReplay(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.ExpiresAt.Equal(online.ExpiresAt) {
		t.Errorf("失效点被改写: %s vs %s", replayed.ExpiresAt, online.ExpiresAt)
	}
	if err := CheckFresh(replayed, snapshot.Now.Add(1)); err != nil {
		t.Errorf("以当时的时刻看仍在 TTL 内: %v", err)
	}
	if err := CheckFresh(replayed, snapshot.Now.Add(snapshot.TTL)); !errors.Is(err, ErrPlanStale) {
		t.Errorf("TTL 到点后必须判过期，实际 %v", err)
	}
}

// 未知 provider 出现在回放候选里之外时（人为拼快照），recordedGate 一律按拒绝处理。
func TestRecordedGateFailsClosed(t *testing.T) {
	g := recordedGate{verdicts: map[string]gateVerdict{"known": {Allowed: true}}}
	if ok, r := g.Allows(policy.PolicyContext{}, nil, offerFor("stranger", 0, 1, testModel), testNow); ok {
		t.Errorf("没记过的候选不该被放开，reason=%s", r)
	} else if r != policy.ReasonCandidatePolicyExcluded {
		t.Errorf("回落码应为 candidate_policy_excluded，实际 %s", r)
	}
	if ok, _ := g.Allows(policy.PolicyContext{}, nil, offerFor("known", 0, 1, testModel), testNow); !ok {
		t.Error("记过允许的不该被翻案")
	}
}
