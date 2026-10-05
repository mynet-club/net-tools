package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// auditVolumeWant 按 Go 侧的 UTF-8 字节数算出期望体积。
//
// 期望值不来自被测算的那条 SQL —— 拿 SQL 自证会正好漏掉「数的是字符还是字节」这一层，
// 而中文 detail 特意用来跨这一层：字符数会把体积低估三倍。
func auditVolumeWant(rows []ScopedAuditEntry) int64 {
	var total int64
	for _, r := range rows {
		total += int64(len(string(r.Scope.Kind)) + len(r.Scope.ID) +
			len(r.Actor) + len(r.Action) + len(r.Target) + len(r.Detail))
	}
	return total
}

// 审计表规模读数：空表报 0（不是报错），写进去的行按**字节**累计。
func TestAuditVolumeEmptyThenGrows(t *testing.T) {
	s := openTestStore(t)

	got, err := s.AuditVolume()
	if err != nil {
		t.Fatalf("空表也该读得出来: %v", err)
	}
	if got.Rows != 0 || got.Bytes != 0 {
		t.Errorf("空表 = %+v，want 0/0（SUM 在零行上是 NULL，必须被 COALESCE 成 0）", got)
	}

	// detail 用中文：这一条正是「字节 not 字符」的受力点。
	entries := []ScopedAuditEntry{
		{Scope: policy.SystemScope, Actor: "admin", Action: "policy.deny",
			Target: "model:secret-model", Detail: `{"reason":"model_not_allowed","说明":"中文按字节算"}`},
		{Scope: policy.MustScope(policy.ScopeUser, "alice"), Actor: "alice", Action: "egress.allow",
			Target: "provider:openai", Detail: `{"why":"raw_body"}`},
	}
	for _, e := range entries {
		if err := s.AuditScope(e.Scope, e.Actor, e.Action, e.Target, e.Detail); err != nil {
			t.Fatalf("AuditScope: %v", err)
		}
	}

	got, err = s.AuditVolume()
	if err != nil {
		t.Fatalf("AuditVolume: %v", err)
	}
	want := auditVolumeWant(entries)
	if got.Rows != int64(len(entries)) {
		t.Errorf("rows = %d，want %d", got.Rows, len(entries))
	}
	if got.Bytes != want {
		t.Errorf("bytes = %d，want %d（按字节算；按字符算会少算中文那部分）", got.Bytes, want)
	}
	// 自证夹具没退化：中文那条按字符数确实比按字节数少。
	var asChars int64
	for _, e := range entries {
		asChars += int64(len([]rune(string(e.Scope.Kind))) + len([]rune(e.Scope.ID)) +
			len([]rune(e.Actor)) + len([]rune(e.Action)) + len([]rune(e.Target)) + len([]rune(e.Detail)))
	}
	if asChars >= got.Bytes {
		t.Errorf("夹具没含多字节字符：字符数 %d 不该 ≥ 字节数 %d", asChars, got.Bytes)
	}
}

// 裁决 15′ 的行为面：retain_days 只清请求明细，审计行一条都不动。
//
// 「审计表没有清理器」本来只是一句 grep 出来的事实（在 internal/ 里搜「删除 audit_log 的
// SQL」为空），而这句话现在得由这条用例来说，不能靠 grep —— 用例本身写了那条语句的话，
// 判据就先被自己污染了。事实会变成缺陷的最省事的写法就是在 Prune 里顺手加一句删除。
// 这条用例是那句裁决的锁。
func TestPruneDoesNotTouchAudit(t *testing.T) {
	s := openTestStore(t)

	old := time.Now().AddDate(0, 0, -400)
	if err := s.InsertRequest(RequestRecord{Ts: old, RequestID: "r-old", Model: "gpt-4o",
		Provider: "p1", UpstreamModel: "gpt-4o", OK: true, LatencyMs: 10, Attempts: 1}); err != nil {
		t.Fatalf("InsertRequest: %v", err)
	}
	if err := s.AuditScope(policy.SystemScope, "admin", "policy.deny", "model:x", `{"old":true}`); err != nil {
		t.Fatalf("AuditScope: %v", err)
	}
	// 把审计行也做成「按天数看早该被扫到」的时刻 —— 真实部署里这张表就是这么长起来的。
	// 不钉住这一条的话，「Prune 顺手也按 retain_days 清一下审计」那种写法抓不到：
	// 新建的审计行永远比 retain_days 新，删除语句空跑一趟，测试照样绿。
	if _, err := s.db.Exec(s.rebind(`UPDATE audit_log SET ts = ?`), old.UnixMilli()); err != nil {
		t.Fatalf("把审计行改成旧时刻: %v", err)
	}
	before, err := s.AuditVolume()
	if err != nil {
		t.Fatalf("AuditVolume: %v", err)
	}

	deleted, err := s.Prune(30)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 1 {
		t.Errorf("Prune 应当清掉那条 400 天前的请求明细，实际清 %d 条", deleted)
	}
	after, err := s.AuditVolume()
	if err != nil {
		t.Fatalf("AuditVolume(清理后): %v", err)
	}
	if after.Rows != before.Rows || after.Bytes != before.Bytes {
		t.Errorf("审计规模被清理动了：%+v → %+v（裁决 15′ 认永久保留）", before, after)
	}

	// 缺省参数不能把这条口径改掉：retain_days=0（永久）时同样不许碰审计。
	if _, err := s.Prune(0); err != nil {
		t.Fatalf("Prune(0): %v", err)
	}
	if again, err := s.AuditVolume(); err != nil || again.Rows != before.Rows {
		t.Errorf("Prune(0) 之后审计规模 = %+v (%v)", again, err)
	}
}

// MySQL / PostgreSQL 走的是同一条聚合语句：方言差异只允许住在 Dialect 层。
//
// 这里不连真库（那是 scripts/test-matrix.sh 在有 DSN 时干的活），只钉住表达式本身 ——
// 「三家都用 length()」看起来最整齐，而它在 SQLite/PG 上数的是字符，中文 detail 会被低估。
func TestTextBytesStaysByteCountingPerDialect(t *testing.T) {
	cases := []struct {
		d      Dialect
		expr   string
		reason string
	}{
		{SQLiteDialect{}, "LENGTH(CAST(detail AS BLOB))", "sqlite 的 length() 数字符，要先 CAST 成 BLOB"},
		{MySQLDialect{}, "LENGTH(detail)", "mysql 的 length() 本来就是字节"},
		{PostgresDialect{}, "OCTET_LENGTH(detail)", "pg 的 length() 数字符，字节数在 octet_length"},
	}
	for _, tc := range cases {
		if got := tc.d.TextBytes("detail"); got != tc.expr {
			t.Errorf("%s: TextBytes = %q，want %q（%s）", tc.d.Name(), got, tc.expr, tc.reason)
		}
	}
}

// 换库重开之后读数仍在：永久保留的承诺不能只在一个进程里成立。
func TestAuditVolumeSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reopen.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.AuditScope(policy.SystemScope, "admin", "egress.allow", "provider:openai", `{"why":"raw_body"}`); err != nil {
		t.Fatalf("AuditScope: %v", err)
	}
	want, err := s.AuditVolume()
	if err != nil {
		t.Fatalf("AuditVolume: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("重开: %v", err)
	}
	defer s2.Close()
	got, err := s2.AuditVolume()
	if err != nil {
		t.Fatalf("重开后的 AuditVolume: %v", err)
	}
	if got != want {
		t.Errorf("重开后 = %+v，want %+v", got, want)
	}
}
