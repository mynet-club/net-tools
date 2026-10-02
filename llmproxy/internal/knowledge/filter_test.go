package knowledge

import (
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// docForFilter 造一篇形态合规、归属本组织、内部可读的返回文档。
func docForFilter(sourceID, kb string, level policy.DataLevel, owner policy.ScopeRef) ReturnedDocument {
	return ReturnedDocument{
		SourceID:      sourceID,
		KnowledgeBase: kb,
		OwnerKind:     string(owner.Kind),
		OwnerID:       owner.ID,
		DataLevel:     level.String(),
		Digest:        DigestString("正文-" + sourceID),
		TitleDigest:   TitleDigest("标题-" + sourceID),
		Allowed:       true,
		RuleID:        "acl-" + sourceID,
	}
}

func ownerOrg() policy.ScopeRef { return policy.MustScope(policy.ScopeOrganization, orgExample) }

func TestFilterHappyPath(t *testing.T) {
	req := mustRequest(t)
	resp := RetrieveResponse{
		ProtocolVersion: ProtocolVersion,
		RequestID:       req.RequestID,
		AclVersion:      "example-acl@7",
		EvaluatedAt:     baseNow,
		ExpiresAt:       after(time.Minute),
		Documents: []ReturnedDocument{
			docForFilter("doc-2", kbHandbook, policy.LevelInternal, ownerOrg()),
			docForFilter("doc-1", kbHandbook, policy.LevelPublic, policy.MustScope(policy.ScopeUser, subjectAlice)),
		},
	}
	got, err := Filter(resp, req, baseNow)
	if err != nil {
		t.Fatalf("合法响应不应报错: %v", err)
	}
	if got.HitCount != 2 || len(got.dropped) != 0 {
		t.Fatalf("期望 2 篇 0 丢弃，实际 %d/%+v", got.HitCount, got.dropped)
	}
	// 兜底后按稳定键排序：来源 ID 小的在前
	if got.citations[0].SourceID != "doc-1" {
		t.Fatalf("引用顺序必须稳定: %+v", got.citations)
	}
	if got.MaxDataLevel != policy.LevelInternal {
		t.Fatalf("命中集最高分级应为 internal，实际 %s", got.MaxDataLevel)
	}
	if got.Truncated || len(got.Reasons) != 0 {
		t.Fatalf("正常路径不该有截断或原因码: %+v", got)
	}
	for _, c := range got.citations {
		if c.RuleID == "" {
			t.Fatal("引用必须带知识源侧判定依据")
		}
	}
}

func TestFilterDropsUnreadableDocuments(t *testing.T) {
	req := mustRequest(t)
	good := docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg())
	// 知识源自己判不可读，却因为配置错误把它返回了
	bad := good
	bad.SourceID = "doc-2"
	bad.Allowed = false
	bad.Digest = DigestString(secretBody)
	bad.TitleDigest = TitleDigest(secretTitle)

	resp := RetrieveResponse{
		ProtocolVersion: ProtocolVersion, RequestID: req.RequestID,
		Documents: []ReturnedDocument{good, bad},
	}
	got, err := Filter(resp, req, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if got.HitCount != 1 {
		t.Fatalf("未授权文档必须被丢弃: %+v", got.citations)
	}
	if got.citations[0].SourceID != "doc-1" {
		t.Fatalf("留下的必须是可读那篇: %+v", got.citations)
	}
	dropped := got.Dropped()
	if len(dropped) != 1 || dropped[0].Reason != ReasonNotReadableAtSource {
		t.Fatalf("丢弃原因码应为 %s，实际 %+v", ReasonNotReadableAtSource, dropped)
	}
	// 未授权文档的摘要也不该出现在引用里（它连被引用的资格都没有）
	for _, c := range got.citations {
		if c.Digest == bad.Digest {
			t.Fatal("不可读文档的摘要泄进了引用集合")
		}
	}
}

func TestFilterDropsCrossOrganizationDocuments(t *testing.T) {
	req := mustRequest(t)
	rivalOrg := docForFilter("doc-9", kbHandbook, policy.LevelPublic, policy.MustScope(policy.ScopeOrganization, orgRival))
	rivalOrg.Digest = DigestString(rivalBody)
	otherProject := docForFilter("doc-8", kbHandbook, policy.LevelPublic, policy.MustScope(policy.ScopeProject, "example-proj-9"))
	otherUser := docForFilter("doc-7", kbHandbook, policy.LevelPublic, policy.MustScope(policy.ScopeUser, subjectRival))
	own := docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg())
	globalPublic := docForFilter("doc-0", kbHandbook, policy.LevelPublic, policy.SystemScope)

	resp := RetrieveResponse{
		ProtocolVersion: ProtocolVersion, RequestID: req.RequestID,
		Documents: []ReturnedDocument{rivalOrg, otherProject, otherUser, own, globalPublic},
	}
	got, err := Filter(resp, req, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	wantReasons := map[string]Reason{
		"doc-9": ReasonCrossOrg,
		"doc-8": ReasonCrossOrg,
		"doc-7": ReasonSubjectMismatch,
	}
	for _, d := range got.Dropped() {
		if wantReasons[d.SourceID] != d.Reason {
			t.Fatalf("文档 %s 的丢弃原因码期望 %s 实际 %s", d.SourceID, wantReasons[d.SourceID], d.Reason)
		}
	}
	if got.HitCount != 2 {
		t.Fatalf("本组织文档 + system 归属文档应留下 2 篇，实际 %d", got.HitCount)
	}
	for _, c := range got.citations {
		if c.Digest == rivalOrg.Digest {
			t.Fatal("邻组织文档的摘要出现在引用里，跨组织隔离失败")
		}
	}
}

func TestFilterDropsLevelExceedingCeiling(t *testing.T) {
	req := mustRequest(t) // 上限 internal
	confidential := docForFilter("doc-3", kbHandbook, policy.LevelConfidential, ownerOrg())
	confidential.Digest = DigestString(secretBody)
	restricted := docForFilter("doc-4", kbHandbook, policy.LevelRestricted, ownerOrg())
	internal := docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg())
	public := docForFilter("doc-0", kbHandbook, policy.LevelPublic, ownerOrg())

	resp := RetrieveResponse{
		ProtocolVersion: ProtocolVersion, RequestID: req.RequestID,
		Documents: []ReturnedDocument{confidential, restricted, internal, public},
	}
	got, err := Filter(resp, req, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if got.HitCount != 2 || got.MaxDataLevel != policy.LevelInternal {
		t.Fatalf("只应留下不超过上限的两篇: %d %s", got.HitCount, got.MaxDataLevel)
	}
	for _, d := range got.Dropped() {
		if d.Reason != ReasonLevelExceeded {
			t.Fatalf("分级超限的原因码应为 %s，实际 %s", ReasonLevelExceeded, d.Reason)
		}
	}
	// 上限本身可放：把上下文抬到 confidential 后，confidential 那篇应留下
	rc := mustContext(t, subjectAlice, orgExample, policy.LevelConfidential)
	widerScope := mustScope(t, rc.Chain, policy.LevelConfidential, kbHandbook)
	widerReq, err := BuildRequest(rc, widerScope, Query{Terms: "报销"}, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := Filter(resp, widerReq, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if got2.HitCount != 3 || got2.MaxDataLevel != policy.LevelConfidential {
		t.Fatalf("上限抬到 confidential 后应留 3 篇，实际 %d/%s", got2.HitCount, got2.MaxDataLevel)
	}
}

func TestFilterDropsExpiredDecisions(t *testing.T) {
	req := mustRequest(t)

	t.Run("单篇判定过期", func(t *testing.T) {
		expired := docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg())
		expired.ExpiresAt = after(-time.Second)
		fresh := docForFilter("doc-2", kbHandbook, policy.LevelInternal, ownerOrg())
		fresh.ExpiresAt = after(time.Minute)
		resp := RetrieveResponse{
			ProtocolVersion: ProtocolVersion, RequestID: req.RequestID,
			Documents: []ReturnedDocument{expired, fresh},
		}
		got, err := Filter(resp, req, baseNow)
		if err != nil {
			t.Fatal(err)
		}
		if got.HitCount != 1 || got.citations[0].SourceID != "doc-2" {
			t.Fatalf("过期判定必须作废: %+v", got.citations)
		}
		if got.Dropped()[0].Reason != ReasonACLExpired {
			t.Fatalf("原因码应为 %s，实际 %s", ReasonACLExpired, got.Dropped()[0].Reason)
		}
	})

	t.Run("整份判定过期时一条都不留", func(t *testing.T) {
		resp := RetrieveResponse{
			ProtocolVersion: ProtocolVersion, RequestID: req.RequestID,
			ExpiresAt: after(-time.Minute),
			Documents: []ReturnedDocument{
				docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg()),
				docForFilter("doc-2", kbHandbook, policy.LevelInternal, ownerOrg()),
			},
		}
		got, err := Filter(resp, req, baseNow)
		if err != nil {
			t.Fatal(err)
		}
		if got.HitCount != 0 || len(got.dropped) != 2 {
			t.Fatalf("整份过期时不能留任何一条: %+v", got)
		}
		if got.MaxDataLevel != policy.LevelPublic {
			t.Fatalf("零命中的分级应是 public，实际 %s", got.MaxDataLevel)
		}
	})
}

func TestFilterDropsMalformedDocuments(t *testing.T) {
	req := mustRequest(t)
	valid := docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg())

	cases := map[string]struct {
		mutate   func(*ReturnedDocument)
		wantDrop Reason
	}{
		"缺判定依据":      {func(d *ReturnedDocument) { d.RuleID = "" }, ReasonEvidenceMissing},
		"依据含空白":      {func(d *ReturnedDocument) { d.RuleID = "acl 1" }, ReasonEvidenceMissing},
		"缺内容摘要":      {func(d *ReturnedDocument) { d.Digest = "" }, ReasonDigestInvalid},
		"内容摘要被截断":    {func(d *ReturnedDocument) { d.Digest = d.Digest[:10] }, ReasonDigestInvalid},
		"缺标题摘要":      {func(d *ReturnedDocument) { d.TitleDigest = "" }, ReasonDigestInvalid},
		"分级名非法":      {func(d *ReturnedDocument) { d.DataLevel = "secret-plus" }, ReasonLevelUnknown},
		"缺来源 ID":     {func(d *ReturnedDocument) { d.SourceID = "" }, ReasonProtocolMissing},
		"归属类型非法":     {func(d *ReturnedDocument) { d.OwnerKind = "department" }, ReasonProtocolMissing},
		"知识库 ID 含冒号": {func(d *ReturnedDocument) { d.KnowledgeBase = "kb:sub" }, ReasonProtocolMissing},
		"补充码是自由文本":   {func(d *ReturnedDocument) { d.DecisionReason = "他在部门里" }, ReasonProtocolMissing},
		"分数为负":       {func(d *ReturnedDocument) { d.Score = -1 }, ReasonProtocolMissing},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			broken := valid
			c.mutate(&broken)
			resp := RetrieveResponse{
				ProtocolVersion: ProtocolVersion, RequestID: req.RequestID,
				Documents: []ReturnedDocument{broken, valid},
			}
			got, err := Filter(resp, req, baseNow)
			if err != nil {
				t.Fatalf("坏数据不应让整次检索失败（应逐条丢弃）: %v", err)
			}
			if got.HitCount != 1 || got.citations[0].SourceID != "doc-1" {
				t.Fatalf("合法那篇必须留下: %+v", got.citations)
			}
			found := false
			for _, d := range got.Dropped() {
				if d.Reason == c.wantDrop {
					found = true
				}
			}
			if !found {
				t.Fatalf("丢弃原因码里应含 %s，实际 %+v", c.wantDrop, got.Dropped())
			}
		})
	}
}

func TestFilterRejectsUntrustedEnvelope(t *testing.T) {
	req := mustRequest(t)
	valid := docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg())

	t.Run("串号响应", func(t *testing.T) {
		resp := RetrieveResponse{ProtocolVersion: ProtocolVersion, RequestID: "req-别的请求",
			Documents: []ReturnedDocument{valid}}
		if _, err := Filter(resp, req, baseNow); err == nil {
			t.Fatal("并发扇出时串号必须整份拒绝")
		}
	})
	t.Run("协议版本不符", func(t *testing.T) {
		resp := RetrieveResponse{ProtocolVersion: "unknown-v9", RequestID: req.RequestID,
			Documents: []ReturnedDocument{valid}}
		if _, err := Filter(resp, req, baseNow); err == nil {
			t.Fatal("必须拒绝")
		}
	})
	t.Run("文档条数超硬上限", func(t *testing.T) {
		resp := RetrieveResponse{ProtocolVersion: ProtocolVersion, RequestID: req.RequestID}
		for i := 0; i <= maxProtocolDocs; i++ {
			resp.Documents = append(resp.Documents, valid)
		}
		if _, err := Filter(resp, req, baseNow); err == nil {
			t.Fatal("必须拒绝异常膨胀的响应")
		}
	})
	t.Run("请求本身不合法", func(t *testing.T) {
		broken := req
		broken.Purpose = ""
		resp := RetrieveResponse{ProtocolVersion: ProtocolVersion, RequestID: req.RequestID,
			Documents: []ReturnedDocument{valid}}
		if _, err := Filter(resp, broken, baseNow); err == nil {
			t.Fatal("上下文不完整的请求不能用来做兜底判定")
		}
	})
}

func TestFilterCapsResultsAndTruncates(t *testing.T) {
	rc := mustContext(t, subjectAlice, orgExample, policy.LevelInternal)
	rc, err := rc.WithMaxResults(2)
	if err != nil {
		t.Fatal(err)
	}
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	req, err := BuildRequest(rc, scope, Query{Terms: "报销"}, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	resp := RetrieveResponse{
		ProtocolVersion: ProtocolVersion, RequestID: req.RequestID,
		Documents: []ReturnedDocument{
			docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg()),
			docForFilter("doc-2", kbHandbook, policy.LevelInternal, ownerOrg()),
			docForFilter("doc-3", kbHandbook, policy.LevelPublic, ownerOrg()),
		},
	}
	got, err := Filter(resp, req, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if got.HitCount != 2 || !got.Truncated {
		t.Fatalf("必须截到 max_results: %d truncated=%v", got.HitCount, got.Truncated)
	}
	// 被截掉的是排序后的尾部（稳定键 doc-3），且留原因码
	last := got.Dropped()[len(got.Dropped())-1]
	if last.SourceID != "doc-3" || last.Reason != ReasonOverResultLimit {
		t.Fatalf("截断记录不正确: %+v", got.Dropped())
	}
}

func TestFilterDeduplicatesCitations(t *testing.T) {
	req := mustRequest(t)
	a := docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg())
	b := a // 完全相同的一条
	resp := RetrieveResponse{ProtocolVersion: ProtocolVersion, RequestID: req.RequestID,
		Documents: []ReturnedDocument{a, b}}
	got, err := Filter(resp, req, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if got.HitCount != 1 {
		t.Fatalf("同一篇重复只留一条: %+v", got.citations)
	}
	if got.Dropped()[0].Reason != ReasonDuplicate {
		t.Fatalf("应留重复码: %+v", got.Dropped())
	}

	// 同来源 ID 但摘要不同：两篇都不能留
	conflict := a
	conflict.Digest = DigestString("另一个版本")
	resp.Documents = []ReturnedDocument{a, conflict}
	got, err = Filter(resp, req, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if got.HitCount != 0 {
		t.Fatalf("同来源两版本必须一起丢（无从判断哪版可信）: %+v", got.citations)
	}
	if len(got.Dropped()) != 2 {
		t.Fatalf("两条都应记丢弃: %+v", got.Dropped())
	}
}

func TestFilterIsDeterministicRegardlessOfInputOrder(t *testing.T) {
	req := mustRequest(t)
	docs := []ReturnedDocument{
		docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg()),
		docForFilter("doc-2", kbHandbook, policy.LevelPublic, ownerOrg()),
		docForFilter("doc-3", kbHandbook, policy.LevelConfidential, ownerOrg()),
	}
	first, err := Filter(RetrieveResponse{ProtocolVersion: ProtocolVersion, RequestID: req.RequestID, Documents: docs}, req, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	reversed := []ReturnedDocument{docs[2], docs[1], docs[0]}
	second, err := Filter(RetrieveResponse{ProtocolVersion: ProtocolVersion, RequestID: req.RequestID, Documents: reversed}, req, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.citations) != len(second.citations) {
		t.Fatalf("引用条数应一致: %d vs %d", len(first.citations), len(second.citations))
	}
	for i := range first.citations {
		if first.citations[i] != second.citations[i] {
			t.Fatalf("返回顺序抖动导致结果不同: %d", i)
		}
	}
	if first.MaxDataLevel != second.MaxDataLevel {
		t.Fatal("命中集最高分级必须一致")
	}
}

func TestFilterNeverWidensTheResultSet(t *testing.T) {
	// 兜底过滤只能变小：把「源侧给了 3 篇」的集合过一遍，
	// 结果条数不可能超过 3，也不可能出现请求白名单之外的知识库。
	req := mustRequest(t)
	docs := []ReturnedDocument{
		docForFilter("doc-1", kbHandbook, policy.LevelInternal, ownerOrg()),
		docForFilter("doc-2", kbHandbook, policy.LevelPublic, ownerOrg()),
		docForFilter("doc-3", kbHR, policy.LevelPublic, ownerOrg()),
	}
	got, err := Filter(RetrieveResponse{ProtocolVersion: ProtocolVersion, RequestID: req.RequestID, Documents: docs}, req, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.citations) > len(docs) {
		t.Fatalf("结果集合被放大: %d > %d", len(got.citations), len(docs))
	}
	for _, c := range got.citations {
		if !strings.Contains(strings.Join(req.KnowledgeBases, ","), c.KnowledgeBase) {
			t.Fatalf("引用里出现请求之外的知识库 %s", c.KnowledgeBase)
		}
		if c.Level().Exceeds(req.MaxDataLevelValue()) {
			t.Fatalf("引用里出现超过上限的分级 %s", c.DataLevel)
		}
	}
}
