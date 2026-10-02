package knowledge

import (
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 测试基线时间：过期判定一律显式传 now，不吃 wall clock，回放与断言才谈得上确定。
var baseNow = time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

func after(d time.Duration) time.Time { return baseNow.Add(d) }

// 虚构标识：全部带 example- / doc- / u- 前缀，绝不出现真实个人信息或真实密钥（§5、§8）。
const (
	subjectAlice    = "u-alice"
	subjectRival    = "u-mallory"
	orgExample      = "example-org"
	orgRival        = "example-rival-org"
	projExample     = "example-proj-1"
	kbHandbook      = "example-handbook"
	kbHR            = "example-hr"
	kbRivalLab      = "example-rival-lab"
	policyVersionV1 = "example-default@1"

	// 正文与标题的泄露标记：断言「任何输出里都不出现它们」时按这两个串查。
	secretBody  = "ZZSECRET_BODY_MARKER_doc3"
	secretTitle = "ZZSECRET_TITLE_MARKER_doc3"
	rivalBody   = "ZZRIVAL_BODY_MARKER_doc9"
)

func chainOf(t *testing.T, subject, org, project string) policy.ScopeChain {
	t.Helper()
	scopes := []policy.ScopeRef{policy.MustScope(policy.ScopeUser, subject)}
	if org != "" {
		scopes = append(scopes, policy.MustScope(policy.ScopeOrganization, org))
	}
	if project != "" {
		scopes = append(scopes, policy.MustScope(policy.ScopeProject, project))
	}
	return policy.MustScopeChain(scopes...)
}

// mustContext 构造一份合法上下文，用例只在需要破坏它时改动字段。
func mustContext(t *testing.T, subject, org string, level policy.DataLevel) RequestContext {
	t.Helper()
	rc, err := NewRequestContext("req-"+subject, subject, chainOf(t, subject, org, projExample), "qa", level, policyVersionV1, baseNow)
	if err != nil {
		t.Fatalf("构造检索上下文失败: %v", err)
	}
	return rc
}

func mustScope(t *testing.T, chain policy.ScopeChain, level policy.DataLevel, kbs ...string) KnowledgeScope {
	t.Helper()
	scope, err := NewKnowledgeScope(chain, level, kbs)
	if err != nil {
		t.Fatalf("构造知识范围失败: %v", err)
	}
	return scope
}

// fakeDoc 是知识源侧的索引条目构造器（默认公开可读、带判定依据）。
func fakeDoc(sourceID, kb string, owner policy.ScopeRef, level policy.DataLevel, body string, readers ...string) FakeDocument {
	if len(readers) == 0 {
		readers = []string{"*"}
	}
	return FakeDocument{
		SourceID:      sourceID,
		KnowledgeBase: kb,
		OwnerScope:    owner,
		Level:         level,
		IndexedTitle:  "标题-" + sourceID,
		IndexedText:   body,
		ReadableBy:    readers,
		RuleID:        "acl-" + sourceID,
	}
}

func TestKnowledgeScopeValidation(t *testing.T) {
	chain := chainOf(t, subjectAlice, orgExample, projExample)

	if _, err := NewKnowledgeScope(nil, policy.LevelInternal, []string{kbHandbook}); err == nil {
		t.Fatal("空范围集合必须被拒绝：漏传 scope 不能被解释成不限范围")
	}
	if _, err := NewKnowledgeScope(chain, policy.LevelUnknown, []string{kbHandbook}); err == nil {
		t.Fatal("分级上限未指定必须被拒绝：零值不是 public")
	}
	if _, err := NewKnowledgeScope(chain, policy.LevelInternal, []string{"bad kb"}); err == nil {
		t.Fatal("含空白的知识库 ID 必须被拒绝")
	}
	if _, err := NewKnowledgeScope(chain, policy.LevelInternal, []string{"a:b"}); err == nil {
		t.Fatal("知识库 ID 含冒号必须被拒绝：资源名 knowledge:<id> 只允许一个分隔符")
	}

	scope, err := NewKnowledgeScope(chain, policy.LevelConfidential, []string{kbHR, kbHandbook, kbHR})
	if err != nil {
		t.Fatalf("合法构造失败: %v", err)
	}
	if len(scope.KnowledgeBases) != 2 {
		t.Fatalf("知识库集合应去重: %v", scope.KnowledgeBases)
	}
	if scope.KnowledgeBases[0] != kbHandbook {
		t.Fatalf("知识库集合应排序去重保证可序列化: %v", scope.KnowledgeBases)
	}
	if !scope.AllowsKB(kbHandbook) || scope.AllowsKB("kb-nope") {
		t.Fatal("AllowsKB 判定不正确")
	}
	if !scope.LevelAllows(policy.LevelConfidential) || scope.LevelAllows(policy.LevelRestricted) {
		t.Fatal("LevelAllows 必须在超过上限时为 false")
	}
	if scope.LevelAllows(policy.LevelUnknown) {
		t.Fatal("未判分级的文档不能被当作满足上限")
	}
	if got := scope.Organizations(); len(got) != 1 || got[0] != orgExample {
		t.Fatalf("组织集合不正确: %v", got)
	}
}

func TestKnowledgeScopeCoversOwner(t *testing.T) {
	scope := mustScope(t, chainOf(t, subjectAlice, orgExample, projExample), policy.LevelInternal, kbHandbook)

	cases := []struct {
		name    string
		owner   policy.ScopeRef
		isOK    bool
		reason  Reason
		subject string
	}{
		{"本组织文档", policy.MustScope(policy.ScopeOrganization, orgExample), true, "", subjectAlice},
		{"本项目文档", policy.MustScope(policy.ScopeProject, projExample), true, "", subjectAlice},
		{"本人文档", policy.MustScope(policy.ScopeUser, subjectAlice), true, "", subjectAlice},
		{"他人 user 归属", policy.MustScope(policy.ScopeUser, subjectRival), false, ReasonSubjectMismatch, subjectAlice},
		{"邻组织文档", policy.MustScope(policy.ScopeOrganization, orgRival), false, ReasonCrossOrg, subjectAlice},
		{"别的项目文档", policy.MustScope(policy.ScopeProject, "example-proj-9"), false, ReasonCrossOrg, subjectAlice},
		{"system 归属不适用", policy.SystemScope, true, "", subjectAlice},
		{"非法归属形态", policy.ScopeRef{Kind: policy.ScopeKind("tenant"), ID: "x"}, false, ReasonSubjectMismatch, subjectAlice},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason := scope.CoversOwner(c.owner, c.subject)
			if ok != c.isOK {
				t.Fatalf("CoversOwner 期望 %v 实际 %v（reason=%s）", c.isOK, ok, reason)
			}
			if !ok && reason != c.reason {
				t.Fatalf("期望原因码 %s 实际 %s", c.reason, reason)
			}
			if mirror := reason.PolicyMirror(); mirror != "" && !mirror.Valid() {
				t.Fatalf("映射出的策略原因码未注册: %s", mirror)
			}
		})
	}
}

func TestRequestContextValidation(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*RequestContext)
		wantErr string
	}{
		{"空请求 ID", func(rc *RequestContext) { rc.RequestID = "" }, "request_id"},
		{"请求 ID 含空白", func(rc *RequestContext) { rc.RequestID = "req 1" }, "request_id"},
		{"邮箱主体", func(rc *RequestContext) { rc.Subject = "alice@example.com" }, "邮箱"},
		{"缺用户范围", func(rc *RequestContext) {
			rc.Chain = policy.MustScopeChain(policy.MustScope(policy.ScopeOrganization, orgExample))
		}, "缺少主体自身"},
		{"空用途", func(rc *RequestContext) { rc.Purpose = "" }, "purpose"},
		{"分级未判定", func(rc *RequestContext) { rc.EffectiveLevel = policy.LevelUnknown }, "生效分级"},
		{"策略版本缺失", func(rc *RequestContext) { rc.PolicyVersion = "" }, "policy_version"},
		{"零预算", func(rc *RequestContext) { rc.Budget = 0; rc.Deadline = rc.IssuedAt }, "预算"},
		{"预算超上限", func(rc *RequestContext) { rc.Budget = MaxBudget + time.Second }, "超过上限"},
		{"结果数为零", func(rc *RequestContext) { rc.MaxResults = 0 }, "max_results"},
		{"结果数超上限", func(rc *RequestContext) { rc.MaxResults = MaxResultsCeiling + 1 }, "超过上限"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rc := mustContext(t, subjectAlice, orgExample, policy.LevelInternal)
			c.mutate(&rc)
			err := rc.Validate(baseNow)
			if err == nil {
				t.Fatalf("必须拒绝：%s", c.name)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("报错文案应含 %q，实际: %v", c.wantErr, err)
			}
		})
	}

	t.Run("过期上下文", func(t *testing.T) {
		rc := mustContext(t, subjectAlice, orgExample, policy.LevelInternal)
		if rc.Expired(rc.Deadline.Add(-time.Millisecond)) {
			t.Fatal("预算内不应判过期")
		}
		if !rc.Expired(rc.Deadline) {
			t.Fatal("now 等于 deadline 必须判过期（与 A 包同一口径）")
		}
		if err := rc.Validate(rc.Deadline.Add(time.Second)); err == nil {
			t.Fatal("过期上下文必须被拒绝，不能复用旧判定")
		} else if !strings.Contains(err.Error(), ErrContextExpired.Error()) {
			t.Fatalf("应报过期错误，实际: %v", err)
		}
	})

	t.Run("预算只允许收窄", func(t *testing.T) {
		rc := mustContext(t, subjectAlice, orgExample, policy.LevelInternal)
		narrower, err := rc.WithDeadline(rc.Deadline.Add(-time.Second), baseNow)
		if err != nil {
			t.Fatalf("收窄预算应成功: %v", err)
		}
		if narrower.Budget >= rc.Budget {
			t.Fatal("预算没有被收窄")
		}
		if _, err := rc.WithDeadline(rc.IssuedAt.Add(-time.Hour), baseNow); err == nil {
			t.Fatal("截止时间早于签发时间必须报错")
		}
		if _, err := rc.WithBudget(MaxBudget * 2); err == nil {
			t.Fatal("预算超上限必须报错而不是静默夹紧")
		}
	})

	t.Run("剩余预算不为负", func(t *testing.T) {
		rc := mustContext(t, subjectAlice, orgExample, policy.LevelInternal)
		if got := rc.Remaining(rc.Deadline.Add(time.Hour)); got != 0 {
			t.Fatalf("过期后剩余预算应为 0，实际 %s", got)
		}
	})
}

func TestDigestAndTitleDigest(t *testing.T) {
	const sample = "doc body sample"
	got := Digest([]byte(sample))
	if err := ValidateDigest(got); err != nil {
		t.Fatalf("摘要形态不合法: %v", err)
	}
	if got != DigestString(sample) {
		t.Fatal("两种入口必须得到同一摘要")
	}
	if got == sample {
		t.Fatal("摘要不能等于输入")
	}
	// 稳定与抗拼接歧义
	if Digest([]byte("ab")) == Digest([]byte("ba")) {
		t.Fatal("不同内容必须得到不同摘要")
	}
	if TitleDigest("a b") == TitleDigest("ab") {
		t.Fatal("标题摘要必须带长度前缀，避免拼接歧义")
	}
	if TitleDigest(strings.TrimSpace(secretTitle)) == "" {
		t.Fatal("标题摘要不能为空")
	}
	// 归一化：首尾空白不影响标题摘要（同一标题两次索引要能对上）
	if TitleDigest("  hello  ") != TitleDigest("hello") {
		t.Fatal("标题摘要应忽略首尾空白")
	}
	// 跨域隔离：同一段明文出现在正文位、标题位、检索词位必须得到三个不同摘要，
	// 否则审计里可以拿一处的命中去猜另一处（见 citation.go 的域常量注释）。
	if (Query{Terms: sample}).Digest() == got || (Query{Terms: sample}).Digest() == TitleDigest(sample) {
		t.Fatal("三类摘要必须按用途分域")
	}
	// 检索词与标题同样要抗拼接歧义、忽略首尾空白
	if (Query{Terms: "a b"}).Digest() == (Query{Terms: "ab"}).Digest() {
		t.Fatal("检索词摘要必须带长度前缀")
	}
	if (Query{Terms: "  hello "}).Digest() != (Query{Terms: "hello"}).Digest() {
		t.Fatal("检索词摘要应忽略首尾空白")
	}

	for _, bad := range []string{"", "abc", strings.Repeat("g", 64), strings.Repeat("A", 64)} {
		if err := ValidateDigest(bad); err == nil {
			t.Fatalf("非法摘要必须被拒绝: %q", bad)
		}
	}

	short := ShortDigest(got)
	if len(short) != shortDigestLen || !strings.HasPrefix(got, short) {
		t.Fatalf("截断摘要形态不正确: %q", short)
	}
	if ShortDigest("short") != "short" {
		t.Fatal("短输入应原样返回，不 panic")
	}
}

func TestCitationValidation(t *testing.T) {
	doc := ReturnedDocument{
		SourceID:      "doc-3",
		KnowledgeBase: kbHandbook,
		OwnerKind:     string(policy.ScopeOrganization),
		OwnerID:       orgExample,
		DataLevel:     policy.LevelInternal.String(),
		Digest:        DigestString(secretBody),
		TitleDigest:   TitleDigest(secretTitle),
		RuleID:        "acl-doc-3",
	}
	citation, err := NewCitation(doc, baseNow)
	if err != nil {
		t.Fatalf("合法引用构造失败: %v", err)
	}
	if err := citation.Validate(); err != nil {
		t.Fatalf("引用校验失败: %v", err)
	}
	if citation.Level() != policy.LevelInternal {
		t.Fatalf("分级解析不正确: %s", citation.Level())
	}
	if citation.OwnerScope() != policy.MustScope(policy.ScopeOrganization, orgExample) {
		t.Fatal("归属范围还原不正确")
	}
	if citation.Key() != kbHandbook+"\x00doc-3" {
		t.Fatalf("引用键不正确: %q", citation.Key())
	}
	display := citation.Display()
	if !strings.Contains(display, kbHandbook) || !strings.Contains(display, ShortDigest(doc.Digest)) {
		t.Fatalf("展示形式缺少标识: %s", display)
	}
	if strings.Contains(display, secretBody) || strings.Contains(display, secretTitle) {
		t.Fatalf("展示形式泄露了内容: %s", display)
	}
	// 等值判定必须用完整摘要
	other := citation
	other.Digest = DigestString("另一个正文")
	if citation.SameDocument(other) {
		t.Fatal("摘要不同的两条引用不能当成同一篇")
	}
	other.Digest = citation.Digest
	if !citation.SameDocument(other) {
		t.Fatal("同一篇文档的两条引用应判为相同")
	}

	// 逐项破坏必填字段
	for name, mutate := range map[string]func(*Citation){
		"缺来源 ID":  func(c *Citation) { c.SourceID = "" },
		"缺知识库":    func(c *Citation) { c.KnowledgeBase = "" },
		"归属类型非法":  func(c *Citation) { c.OwnerKind = "tenant" },
		"缺归属 ID":  func(c *Citation) { c.OwnerID = "" },
		"分级非法":    func(c *Citation) { c.DataLevel = "top-secret" },
		"摘要算法不支持": func(c *Citation) { c.DigestAlgorithm = "md5" },
		"缺内容摘要":   func(c *Citation) { c.Digest = "" },
		"缺标题摘要":   func(c *Citation) { c.TitleDigest = "" },
		"缺判定依据":   func(c *Citation) { c.RuleID = "" },
		"分数为负":    func(c *Citation) { c.Score = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			broken := citation
			mutate(&broken)
			if err := broken.Validate(); err == nil {
				t.Fatal("必须被拒绝")
			}
		})
	}
}

func TestSortCitationsIsStable(t *testing.T) {
	base := Citation{SourceID: "doc-2", KnowledgeBase: kbHandbook, OwnerKind: string(policy.ScopeOrganization),
		OwnerID: orgExample, DataLevel: policy.LevelInternal.String(), DigestAlgorithm: DigestAlgorithm,
		Digest: DigestString("b"), TitleDigest: TitleDigest("t2"), RuleID: "r"}
	other := base
	other.SourceID = "doc-1"
	rival := base
	rival.KnowledgeBase = kbHR
	rival.SourceID = "doc-0"

	first := SortCitations([]Citation{base, other, rival})
	second := SortCitations([]Citation{rival, other, base})
	if len(first) != 3 || len(second) != 3 {
		t.Fatalf("排序不应丢条目: %d %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("排序结果必须与输入顺序无关: %d", i)
		}
	}
	if first[0].KnowledgeBase != kbHandbook || first[1].SourceID != "doc-2" {
		t.Fatalf("应先按知识库、再按来源 ID 排序: %+v", first)
	}
	if first[2].KnowledgeBase != kbHR {
		t.Fatalf("字典序靠后的知识库应在末尾: %+v", first)
	}
}

func TestEffectiveLevelFor(t *testing.T) {
	cases := []struct {
		name      string
		user      policy.DataLevel
		knowledge policy.DataLevel
		want      policy.DataLevel
		wantErr   bool
	}{
		{"知识高于用户", policy.LevelInternal, policy.LevelConfidential, policy.LevelConfidential, false},
		{"用户高于知识", policy.LevelRestricted, policy.LevelInternal, policy.LevelRestricted, false},
		{"相等", policy.LevelInternal, policy.LevelInternal, policy.LevelInternal, false},
		{"零命中按 public 参与", policy.LevelInternal, policy.LevelPublic, policy.LevelInternal, false},
		{"知识分级未判定必须报错", policy.LevelInternal, policy.LevelUnknown, policy.LevelUnknown, true},
		{"用户分级未判定必须报错", policy.LevelUnknown, policy.LevelPublic, policy.LevelUnknown, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := EffectiveLevelFor(c.user, c.knowledge)
			if c.wantErr {
				if err == nil {
					t.Fatal("必须报错：未判定的分级不能被当成放行")
				}
				return
			}
			if err != nil {
				t.Fatalf("意外错误: %v", err)
			}
			if got != c.want {
				t.Fatalf("期望 %s 实际 %s", c.want, got)
			}
		})
	}
	// §2.3 的组合规则：knowledge_level 是入参之一，detected 由分类器另算
	maxLevel, err := EffectiveLevelFor(policy.LevelPublic, policy.LevelRestricted)
	if err != nil || maxLevel != policy.LevelRestricted {
		t.Fatalf("命中 restricted 文档必须把生效分级抬到 restricted: %v %v", maxLevel, err)
	}
}

func TestMaxKnowledgeLevel(t *testing.T) {
	if got := MaxKnowledgeLevel(nil); got != policy.LevelPublic {
		t.Fatalf("零命中必须是 public 而不是 unknown: %s", got)
	}
	high := Citation{SourceID: "doc-1", KnowledgeBase: kbHandbook, OwnerKind: string(policy.ScopeUser),
		OwnerID: subjectAlice, DataLevel: policy.LevelConfidential.String(), DigestAlgorithm: DigestAlgorithm,
		Digest: DigestString("a"), TitleDigest: TitleDigest("a"), RuleID: "r"}
	low := high
	low.DataLevel = policy.LevelInternal.String()
	if got := MaxKnowledgeLevel([]Citation{low, high}); got != policy.LevelConfidential {
		t.Fatalf("应取最高分级: %s", got)
	}
	broken := low
	broken.DataLevel = "no-such-level"
	if got := MaxKnowledgeLevel([]Citation{low, broken}); got != policy.LevelRestricted {
		t.Fatalf("非法分级必须按最严的一档处理: %s", got)
	}
}

func TestReasonCodesAreStableAndMirrorsRegistered(t *testing.T) {
	for r := range reasonRegistry {
		s := string(r)
		if !reasonStyleOK(s) {
			t.Errorf("原因码 %q 字形不合规（只许小写字母/数字/下划线，长度 ≤40）", s)
		}
	}
	for local, mirrored := range policyMirrors {
		if !mirrored.Valid() {
			t.Errorf("%s 映射到未注册的策略原因码 %s", local, mirrored)
		}
	}
	// 未映射的原因码不该假装自己对应策略结论
	if ReasonTimeout.PolicyMirror() != "" {
		t.Error("检索超时不属于策略层语义，不应有映射")
	}
	if err := ValidateReasons([]Reason{ReasonOK, ReasonCrossOrg}); err != nil {
		t.Fatalf("合法原因码校验失败: %v", err)
	}
	if err := ValidateReasons([]Reason{Reason("made_up_code")}); err == nil {
		t.Fatal("未注册原因码必须被拒绝")
	}
	if got := Reasons([]Reason{ReasonCrossOrg, ReasonOK, ReasonCrossOrg}); len(got) != 2 || got[0] != ReasonCrossOrg {
		t.Fatalf("原因码应去重并排序: %v", got)
	}
}
