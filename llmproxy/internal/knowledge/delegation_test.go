package knowledge

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

func TestBuildRequestCarriesAuthorizationContextOnly(t *testing.T) {
	rc := mustContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook, kbHR)

	req, err := BuildRequest(rc, scope, Query{Terms: "如何提交报销"}, baseNow)
	if err != nil {
		t.Fatalf("装配请求失败: %v", err)
	}
	if req.ProtocolVersion != ProtocolVersion {
		t.Fatalf("协议版本不正确: %s", req.ProtocolVersion)
	}
	if req.RequestID != rc.RequestID || req.Subject != rc.Subject || req.Purpose != rc.Purpose {
		t.Fatal("上下文标识必须原样传给知识源，否则源侧无从鉴权")
	}
	if len(req.Chain) != len(rc.Chain) {
		t.Fatal("范围集合必须完整传下去")
	}
	if req.MaxDataLevel != policy.LevelInternal.String() {
		t.Fatalf("分级上限没传下去: %s", req.MaxDataLevel)
	}
	if req.PolicyVersion != policyVersionV1 {
		t.Fatal("策略版本必须随请求传递，审计与源侧判定要能对齐")
	}
	if req.MaxResults != DefaultMaxResults || req.BudgetMS != rc.Budget.Milliseconds() {
		t.Fatalf("结果数与预算没传对: %d %d", req.MaxResults, req.BudgetMS)
	}
	if req.QueryDigest != (Query{Terms: "如何提交报销"}).Digest() {
		t.Fatal("检索词摘要必须存在")
	}
	if req.SearchTerms != "" {
		t.Fatal("未显式授权时不得携带检索词原文")
	}
	if req.Organization != orgExample {
		t.Fatalf("主归属提示不正确: %s", req.Organization)
	}
	// 时间序列化必须是 RFC3339（§5）
	blob, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if !strings.Contains(string(blob), "\"issued_at\":\"2026-04-01T12:00:00") {
		t.Fatalf("时间必须按 RFC3339 编码: %s", blob)
	}
	// 切片必须被复制：调用方后续改动不应影响已发出的请求语义
	scope.KnowledgeBases[0] = "mutated"
	if req.KnowledgeBases[0] == "mutated" {
		t.Fatal("请求里的知识库切片是共享的")
	}
}

func TestBuildRequestRawTermsGate(t *testing.T) {
	rc := mustContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)

	req, err := BuildRequest(rc, scope, Query{Terms: secretBody, AllowRawTerms: true}, baseNow)
	if err != nil {
		t.Fatalf("授权后装配失败: %v", err)
	}
	if req.SearchTerms != secretBody {
		t.Fatal("显式授权时应携带原文检索词")
	}
	if !req.AllowRawTerms {
		t.Fatal("授权标志必须传给源侧")
	}

	denied, err := BuildRequest(rc, scope, Query{Terms: secretBody}, baseNow)
	if err != nil {
		t.Fatalf("未授权装配失败: %v", err)
	}
	blob, err := json.Marshal(denied)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), secretBody) {
		t.Fatalf("未授权时序列化请求里出现了检索词原文: %s", blob)
	}
}

func TestBuildRequestRejectsBadInputs(t *testing.T) {
	rc := mustContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)

	if _, err := BuildRequest(rc, scope, Query{}, rc.Deadline.Add(time.Second)); err == nil {
		t.Fatal("过期上下文不能再装配请求")
	}
	brokenScope := scope
	brokenScope.KnowledgeBases = []string{"bad kb"}
	if _, err := BuildRequest(rc, brokenScope, Query{}, baseNow); err == nil {
		t.Fatal("非法知识库 ID 必须被拒绝")
	}
	emptyLevel := scope
	emptyLevel.MaxDataLevel = policy.LevelUnknown
	if _, err := BuildRequest(rc, emptyLevel, Query{}, baseNow); err == nil {
		t.Fatal("分级上限未判定时不能发出委托")
	}
}

func TestRetrieveRequestValidate(t *testing.T) {
	rc := mustContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	req, err := BuildRequest(rc, scope, Query{Terms: "x"}, baseNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("合法请求校验失败: %v", err)
	}
	if !req.KnowledgeBaseAllowed(kbHandbook) || req.KnowledgeBaseAllowed("kb-nope") {
		t.Fatal("知识库白名单判定不正确")
	}

	cases := map[string]func(*RetrieveRequest){
		"协议版本不符": func(r *RetrieveRequest) { r.ProtocolVersion = "old-v0" },
		"缺请求 ID": func(r *RetrieveRequest) { r.RequestID = "" },
		"主体是邮箱":  func(r *RetrieveRequest) { r.Subject = "alice@example.com" },
		"范围集合为空": func(r *RetrieveRequest) { r.Chain = nil },
		"范围缺主体自身": func(r *RetrieveRequest) {
			r.Chain = policy.MustScopeChain(policy.MustScope(policy.ScopeOrganization, orgExample))
		},
		"缺用途":      func(r *RetrieveRequest) { r.Purpose = "" },
		"分级名非法":    func(r *RetrieveRequest) { r.MaxDataLevel = "secret+" },
		"分级名缺失":    func(r *RetrieveRequest) { r.MaxDataLevel = "" },
		"知识库为空":    func(r *RetrieveRequest) { r.KnowledgeBases = nil },
		"知识库 ID 脏": func(r *RetrieveRequest) { r.KnowledgeBases = []string{"has space"} },
		"结果数为 0":   func(r *RetrieveRequest) { r.MaxResults = 0 },
		"结果数超上限":   func(r *RetrieveRequest) { r.MaxResults = MaxResultsCeiling + 1 },
		"缺截止时间":    func(r *RetrieveRequest) { r.Deadline = time.Time{} },
		"缺查询摘要":    func(r *RetrieveRequest) { r.QueryDigest = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			broken := req
			mutate(&broken)
			if err := broken.Validate(); err == nil {
				t.Fatal("必须拒绝")
			}
		})
	}
}

func TestRetrieveResponseValidate(t *testing.T) {
	req := mustRequest(t)
	valid := ReturnedDocument{
		SourceID: "doc-1", KnowledgeBase: kbHandbook,
		OwnerKind: string(policy.ScopeOrganization), OwnerID: orgExample,
		DataLevel: policy.LevelInternal.String(),
		Digest:    DigestString("body-1"), TitleDigest: TitleDigest("title-1"),
		Allowed: true, RuleID: "acl-1",
	}
	resp := RetrieveResponse{ProtocolVersion: ProtocolVersion, RequestID: req.RequestID, Documents: []ReturnedDocument{valid}}
	if err := resp.Validate(req); err != nil {
		t.Fatalf("合法响应校验失败: %v", err)
	}

	t.Run("协议版本不符", func(t *testing.T) {
		broken := resp
		broken.ProtocolVersion = "unknown-v9"
		if err := broken.Validate(req); err == nil {
			t.Fatal("必须拒绝")
		}
	})
	t.Run("缺请求 ID", func(t *testing.T) {
		broken := resp
		broken.RequestID = ""
		if err := broken.Validate(req); err == nil {
			t.Fatal("必须拒绝：没有 request_id 就无法确认响应属于哪次请求")
		}
	})
	t.Run("请求 ID 串号", func(t *testing.T) {
		broken := resp
		broken.RequestID = "req-另一个请求"
		err := broken.Validate(req)
		if err == nil {
			t.Fatal("并发扇出时串号响应必须被拒")
		}
		if !strings.Contains(err.Error(), "request_id") {
			t.Fatalf("报错应指出串号: %v", err)
		}
	})
	t.Run("白名单不符不在响应校验里拒绝", func(t *testing.T) {
		// 知识库白名单与单篇形态都由 Filter 逐条丢弃（分别给
		// knowledge_base_not_allowed / document_* 原因码）：
		// 整份拒绝只留给「载荷整体不可信」的三种情况（版本、串号、条数膨胀）。
		// 一条范围外的坏文档不该把其它合法可读文档一起废掉——丢弃只会让集合变小。
		broken := resp
		other := valid
		other.KnowledgeBase = kbRivalLab
		broken.Documents = []ReturnedDocument{other}
		if err := broken.ValidateEnvelope(req); err != nil {
			t.Fatalf("ValidateEnvelope 不应因白名单报错: %v", err)
		}
		if err := broken.Validate(req); err != nil {
			t.Fatalf("该篇形态本身合规，Validate 也不应报错: %v", err)
		}
		result, err := Filter(broken, req, baseNow)
		if err != nil {
			t.Fatalf("Filter 不应报错: %v", err)
		}
		if result.HitCount != 0 || len(result.Dropped()) != 1 {
			t.Fatalf("邻库文档必须被兜底丢弃: %+v", result)
		}
		if result.Dropped()[0].Reason != ReasonKBNotAllowed {
			t.Fatalf("丢弃原因码应为 %s，实际 %s", ReasonKBNotAllowed, result.Dropped()[0].Reason)
		}
	})
	t.Run("文档条数超硬上限", func(t *testing.T) {
		broken := resp
		broken.Documents = make([]ReturnedDocument, 0, maxProtocolDocs+2)
		for i := 0; i <= maxProtocolDocs; i++ {
			item := valid
			item.SourceID = fmt.Sprintf("doc-%05d", i)
			broken.Documents = append(broken.Documents, item)
		}
		if err := broken.Validate(req); err == nil {
			t.Fatal("必须拒绝异常膨胀的响应")
		}
	})

	// 逐篇字段缺失
	for name, mutate := range map[string]func(*ReturnedDocument){
		"缺来源 ID": func(d *ReturnedDocument) { d.SourceID = "" },
		"缺知识库":   func(d *ReturnedDocument) { d.KnowledgeBase = "" },
		"归属类型非法": func(d *ReturnedDocument) { d.OwnerKind = "department" },
		"缺归属 ID": func(d *ReturnedDocument) { d.OwnerID = "" },
		"分级非法":   func(d *ReturnedDocument) { d.DataLevel = "internal-ish" },
		"缺内容摘要":  func(d *ReturnedDocument) { d.Digest = "" },
		"摘要被截断":  func(d *ReturnedDocument) { d.Digest = d.Digest[:20] },
		"缺标题摘要":  func(d *ReturnedDocument) { d.TitleDigest = "not-a-digest" },
		"缺判定依据":  func(d *ReturnedDocument) { d.RuleID = "" },
		"依据串含空格": func(d *ReturnedDocument) { d.RuleID = "acl rule" },
		"分数为负":   func(d *ReturnedDocument) { d.Score = -0.5 },
	} {
		t.Run(name, func(t *testing.T) {
			broken := resp
			item := valid
			mutate(&item)
			broken.Documents = []ReturnedDocument{item}
			if err := broken.Validate(req); err == nil {
				t.Fatal("必须拒绝：缺依据或形态不符的响应不能部分采信")
			}
		})
	}

	t.Run("补充原因码必须是稳定码", func(t *testing.T) {
		broken := resp
		item := valid
		item.DecisionReason = "因为他在部门里"
		broken.Documents = []ReturnedDocument{item}
		if err := broken.Validate(req); err == nil {
			t.Fatal("自由文本原因码必须被拒")
		}
		item.DecisionReason = "acl_hit"
		broken.Documents = []ReturnedDocument{item}
		if err := broken.Validate(req); err != nil {
			t.Fatalf("稳定码应通过: %v", err)
		}
	})
}

// mustRequest 装配一份合法委托请求，供响应校验类用例复用。
func mustRequest(t *testing.T) RetrieveRequest {
	t.Helper()
	rc := mustContext(t, subjectAlice, orgExample, policy.LevelInternal)
	scope := mustScope(t, rc.Chain, policy.LevelInternal, kbHandbook)
	req, err := BuildRequest(rc, scope, Query{Terms: "报销"}, baseNow)
	if err != nil {
		t.Fatalf("装配请求失败: %v", err)
	}
	return req
}
