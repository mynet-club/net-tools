package replay

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// goldenPath 是钉住「同输入同输出」的样例记录。
//
// 它同时是 §7 要求的手册附录：别人接手时不必读代码就能看清记录长什么样。
const goldenPath = "testdata/replay-baseline.json"

// goldenDigest 是一次基线回放的规范摘要。改动策略包、记录字段或抽样算法都会让它变化 ——
// 这正是它的作用：任何一条会让「历史决策复现不出来」的变化都必须被显式承认。
const goldenDigest = "61dd8998a1e87e399e27376de1349d619455c2d40db683e86569f0cc323a78be"

func TestGoldenFixtureReplaysClean(t *testing.T) {
	f := readGolden(t)
	r := newReplayer(t, testBundles(t), baseNow, false)
	report, err := r.Run(f)
	if err != nil {
		t.Fatalf("基线记录回放失败: %v", err)
	}
	if !report.Clean() {
		t.Fatalf("基线记录必须逐字段复现:\n%s", report.String())
	}
	digest, err := report.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digest != goldenDigest {
		t.Fatalf("回放摘要发生变化（说明记录结构、策略包或抽样算法被改动，需要显式承认并更新基线）:\n期望 %s\n实际 %s\n%s",
			goldenDigest, digest, report.String())
	}
	t.Logf("基线回放摘要: %s", digest)
}

// 外部导入的记录集也必须能回放：文件与内存构造走的是同一套校验。
func TestGoldenFixtureEqualsInMemoryBuild(t *testing.T) {
	fromFile := readGolden(t)
	fromMemory := baselineFileForFixture(t)
	if MustEncode(fromFile) != MustEncode(fromMemory) {
		t.Fatalf("测试样例与代码构造不一致：记录文件已经腐坏或 fixture 忘了更新\n%s", goldenPath)
	}
}

// TestWriteGoldenFixture 重新生成测试样例。
//
// 只有显式 LLMPROXY_WRITE_GOLDEN=1 才写文件：默认路径必须只读，
// 否则一次实现改动会顺手把「期望」改成「实际」，回归断言就废了。
func TestWriteGoldenFixture(t *testing.T) {
	if os.Getenv("LLMPROXY_WRITE_GOLDEN") != "1" {
		t.Skip("需要 LLMPROXY_WRITE_GOLDEN=1 才写样例文件")
	}
	data, err := Encode(baselineFileForFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("testdata", "replay-baseline.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// baselineFileForFixture 用合成主体构造基线记录集：
// 两条放行、一条被 deny 压住、一条因范围不匹配无授权，外加一条配对的路由记录。
func baselineFileForFixture(t *testing.T) File {
	t.Helper()
	set := testBundles(t)
	aliceChain := chainOf(t, "alice", "university", "")
	alice := identityOf(t, "alice", []string{"student"}, []string{"cs"})
	aliceCtx := ctxOf(t, alice, "university", policy.LevelInternal)

	allowed := captureDecision(t, set, "req-allow-gpt5", baseNow, aliceChain, alice, aliceCtx, "model:gpt-5", policy.ActionUse)
	group := captureDecision(t, set, "req-allow-mini", baseNow, aliceChain, alice, aliceCtx, "model:gpt-mini", policy.ActionUse)
	denied := captureDecision(t, set, "req-deny-gptmax", baseNow, aliceChain, alice, aliceCtx, "model:gpt-max", policy.ActionUse)

	doctor := identityOf(t, "bob", []string{"doctor"}, []string{"radiology"})
	doctorCtx := ctxOf(t, doctor, "hospital-a", policy.LevelConfidential)
	mri := captureDecision(t, set, "req-allow-mri", baseNow, chainOf(t, "bob", "hospital-a", ""), doctor, doctorCtx,
		"model:private-mri", policy.ActionUse)

	routing := routingFixture(t, "req-allow-mini", group.PolicyVersion, baseNow, []policy.RouteCandidate{
		candidate("p-demo", "public-demo", 1),
		candidate("p-gpt5", "gpt-5", 3),
		candidate("p-mini", "gpt-mini", 1),
	}, []policy.Rejection{rejection("p-demo", policy.ReasonCandidateLevelExcluded)}, 1)

	return NewFile([]DecisionRecord{allowed, group, denied, mri}, []RoutingRecord{routing})
}

func readGolden(t *testing.T) File {
	t.Helper()
	f, err := os.Open(goldenPath)
	if err != nil {
		t.Fatalf("读测试样例失败: %v", err)
	}
	defer f.Close()
	got, err := ReadFrom(f)
	if err != nil {
		t.Fatalf("测试样例解析失败: %v", err)
	}
	return got
}
