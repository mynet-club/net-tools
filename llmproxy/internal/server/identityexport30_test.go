package server

// §9 P8-4 的接线测试：导出侧「按范围的显式授权」（裁决 14′ 并入 P8）。
//
// 这一格只需钉住一条边界：X-Identity-Token **只会把导出范围收窄，绝不会放宽**。
// 所以两种「看起来都行」的实现必须在同一条测试里被拆开：
//
//   - 「带了 token 就自动收窄到它的链」——不去测它收窄得对不对，而是测
//     **没点名 scope 时不能当没带**：不写 scope 等于要全部范围，那超出 token 能证明的范围；
//   - 「校验不了就退回没带 token」——那等于按自报约束之外的范围给数据，
//     与「任何降级不得绕过权限」相反。
//
// 不带 token 的那一路必须逐字节不变：管理凭证即够是这条裁决的前提，不是退路。
//
// 另一条被同一条测试顺带钉住的：回话里绝不能出现 token 原文（哪怕它已经无效）。

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/identity"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// adminGetWithIdentity30 用管理凭证 GET，并可选带上一枚 IdP token。
func adminGetWithIdentity30(t *testing.T, h *harness, path, idToken string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.gateway.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	if idToken != "" {
		req.Header.Set(IdentityHeaderName, idToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// TestExport30IdentityTokenNarrowsScope 是 P8-4 的主用例：两处导出共用同一道闸门，
// 逐格覆盖「不带 / 链内 / 链外 / 不点名 / 无有效 token / 未配身份」。
func TestExport30IdentityTokenNarrowsScope(t *testing.T) {
	auth, err := identity.NewFakeAuthority()
	if err != nil {
		t.Fatal(err)
	}
	h := newIdentityHarness(t, auth)
	idToken, err := auth.SignUniversityToken(sampleProfile(t, "teacher-2001"), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	paths := []struct{ name, path string }{
		{"用量导出", "/v1/_admin/usage/export"},
		{"证据链导出", "/v1/_admin/replay/export"},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			// 1) 不带 token：管理凭证即够，链外范围与「导全部」都照旧。
			for _, q := range []string{"?scope=organization:university", "?scope=organization:hospital-a", ""} {
				if code, body := adminGetWithIdentity30(t, h.harness, p.path+q, ""); code != http.StatusOK {
					t.Fatalf("不带 token 应 200（%s），实际 %d: %s", q, code, body)
				}
			}

			// 2) 带 token、范围落在链内：放行。
			for _, q := range []string{
				"?scope=organization:university",
				"?scope=user:uid-tea-2001",
				"?scope=project:proj-curriculum",
			} {
				if code, body := adminGetWithIdentity30(t, h.harness, p.path+q, idToken); code != http.StatusOK {
					t.Fatalf("链内范围 %s 应 200，实际 %d: %s", q, code, body)
				}
			}

			// 3) 带 token、范围在链外：拒，且原因类别是 export_scope_denied。
			for _, q := range []string{
				"?scope=organization:hospital-a",
				"?scope=user:someone-else",
			} {
				code, body := adminGetWithIdentity30(t, h.harness, p.path+q, idToken)
				if code != http.StatusForbidden {
					t.Fatalf("链外范围 %s 应 403，实际 %d: %s", q, code, body)
				}
				if k := errorKind(t, body); k != "export_scope_denied" {
					t.Errorf("拒绝类型 = %q，want export_scope_denied", k)
				}
			}

			// 4) 带 token 但没点名 scope（= 导全部）：拒。这一格是「自动收窄」那种宽解释
			//    的照妖镜 —— 它会在这里回 200。
			code, body := adminGetWithIdentity30(t, h.harness, p.path, idToken)
			if code != http.StatusForbidden {
				t.Fatalf("带 token 不点名范围应 403，实际 %d: %s", code, body)
			}
			if k := errorKind(t, body); k != "export_scope_denied" {
				t.Errorf("拒绝类型 = %q，want export_scope_denied", k)
			}

			// 5) token 无效：拒，且回话里不留它的原文。
			bogus := "not-a-jwt-at-all"
			code, body = adminGetWithIdentity30(t, h.harness, p.path+"?scope=organization:university", bogus)
			if code != http.StatusForbidden {
				t.Fatalf("无效 token 应 403，实际 %d: %s", code, body)
			}
			if strings.Contains(string(body), bogus) {
				t.Errorf("拒绝回话里出现了 token 原文: %s", body)
			}
			if strings.Contains(string(body), idToken) {
				t.Errorf("拒绝回话里泄漏了另一枚 token 原文")
			}
		})
	}
}

// TestExport30IdentityTokenUnconfiguredFailsClosed 钉住「校验不了就退回没带」这条反路：
// 网关根本没配 identity 段时，一枚自报 token 不能把范围放宽成「管理凭证即够」。
func TestExport30IdentityTokenUnconfiguredFailsClosed(t *testing.T) {
	h := policyAdminHarness(t, "enforce")
	// 前提：这套夹具确实没有外部身份运行态。
	if rt := h.srv.policyFor(h.cfgStore.Current()); rt == nil || rt.idn != nil {
		t.Fatalf("夹具不该有 identity 段（rt=%v）", rt)
	}
	for _, path := range []string{"/v1/_admin/usage/export", "/v1/_admin/replay/export"} {
		code, body := adminGetWithIdentity30(t, h.harness, path+"?scope=organization:university", "sk-looks-like-a-token")
		if code != http.StatusForbidden {
			t.Fatalf("未配身份时带 token 应 403（%s），实际 %d: %s", path, code, body)
		}
		if k := errorKind(t, body); k != "export_scope_denied" {
			t.Errorf("拒绝类型 = %q，want export_scope_denied", k)
		}
		// 不带 token 时这一路照旧 200：fail-closed 只针对「带了 token」。
		if code, body := adminGetWithIdentity30(t, h.harness, path+"?scope=organization:university", ""); code != http.StatusOK {
			t.Fatalf("不带 token 不该被牵连（%s），实际 %d: %s", path, code, body)
		}
	}
}

// TestReplay30OrgExportFindsIdentityBoundRecords 是 P8-4 的**收益**用例：
// org 级导出从此有真数据。它不额外写任何记录，只是把 P8-3（链里真有 org）与
// P7（过滤按链匹配）两件事合起来跑一条真流量，再看导出的条数。
//
// 这里只用不带 token 的导出：收益的成立**不依赖**那枚 token —— token 只负责收窄，
// 授权口径本身是「管理凭证即够」（裁决 14′）。另附一格带 token 导链内范围，
// 证明收窄之后仍然拿得到同一批记录。
func TestReplay30OrgExportFindsIdentityBoundRecords(t *testing.T) {
	auth, err := identity.NewFakeAuthority()
	if err != nil {
		t.Fatal(err)
	}
	h := newIdentityHarness(t, auth)
	token := addConsumptionUser(t, h, "uid-tea-2001")
	openReplayWindow(t, h)

	idToken, err := auth.SignUniversityToken(sampleProfile(t, "teacher-2001"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// 一条带外部身份的真实请求：链里因此含 organization:university 与 project:proj-curriculum。
	resp, body := postIdentity(t, h.harness, "/v1/chat/completions", token, idToken, "base-model", "req-org-1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("带外部身份的 base-model 应 200，实际 %d: %s", resp.StatusCode, body)
	}
	if got := h.srv.replayWin.stats()["entries"]; got != 1 {
		t.Fatalf("窗口应采到 1 条，实际 entries=%v", got)
	}

	cases := []struct {
		scope string
		want  int
	}{
		{"?scope=organization:university", 1}, // 链里有它
		{"?scope=project:proj-curriculum", 1}, // 同上
		{"?scope=user:uid-tea-2001", 1},       // 请求范围就是它
		{"?scope=organization:hospital-a", 0}, // 链外：不是「窗口为空」，是没这个范围
	}
	for _, tc := range cases {
		code, raw := adminGetWithIdentity30(t, h.harness, "/v1/_admin/replay/export"+tc.scope, "")
		if code != http.StatusOK {
			t.Fatalf("导出 %s 应 200，实际 %d: %s", tc.scope, code, raw)
		}
		f := mustDecodeRecords(t, raw)
		if len(f.Decisions) != tc.want {
			t.Errorf("导出 %s 命中 %d 条，want %d", tc.scope, len(f.Decisions), tc.want)
		}
		if tc.want == 1 && f.Decisions[0].RequestID != "req-org-1" {
			t.Errorf("导出 %s 拿到的不是那条身份绑定请求: %+v", tc.scope, f.Decisions[0])
		}
	}

	// 收窄之后仍然拿得到同一批：带 token 导链内范围 → 200 且 1 条。
	code, raw := adminGetWithIdentity30(t, h.harness, "/v1/_admin/replay/export?scope=organization:university", idToken)
	if code != http.StatusOK {
		t.Fatalf("带 token 导链内范围应 200，实际 %d: %s", code, raw)
	}
	if f := mustDecodeRecords(t, raw); len(f.Decisions) != 1 || f.Decisions[0].RequestID != "req-org-1" {
		t.Errorf("带 token 导出结果不对: %+v", f.Decisions)
	}
	// 同一枚 token 导链外范围 → 403，且不给任何记录（连空文件都不给）。
	if code, raw := adminGetWithIdentity30(t, h.harness,
		"/v1/_admin/replay/export?scope=organization:hospital-a", idToken); code != http.StatusForbidden {
		t.Fatalf("带 token 导链外范围应 403，实际 %d: %s", code, raw)
	}
}

// TestUsageExportWritesAudit30 钉住 P8-4 的出口留痕：usage.export 之前是唯一一个
// 没有审计的导出口。留痕的 target 是范围全串（不过滤写 "usage"），一次 200 一条。
func TestUsageExportWritesAudit30(t *testing.T) {
	h := policyAdminHarness(t, "enforce")

	if code, body := adminGetWithIdentity30(t, h.harness, "/v1/_admin/usage/export?scope=user:alice", ""); code != http.StatusOK {
		t.Fatalf("按用户导出应 200，实际 %d: %s", code, body)
	}
	rows := auditRows(t, h.harness, policy.SystemScope, "usage.export")
	if len(rows) != 1 {
		t.Fatalf("按范围导出应落一条审计，实际 %d 条", len(rows))
	}
	if rows[0].Target != "user:alice" {
		t.Errorf("导出审计 target = %q，want user:alice", rows[0].Target)
	}
	if !strings.Contains(rows[0].Detail, "daily") || !strings.Contains(rows[0].Detail, "user:alice") {
		t.Errorf("导出审计 detail 没说清范围与形态: %s", rows[0].Detail)
	}

	// 不带 scope（= 全部范围）：target 用 "usage" 这个占位，而不是空串。
	if code, body := adminGetWithIdentity30(t, h.harness, "/v1/_admin/usage/export", ""); code != http.StatusOK {
		t.Fatalf("全量导出应 200，实际 %d: %s", code, body)
	}
	rows = auditRows(t, h.harness, policy.SystemScope, "usage.export")
	if len(rows) != 2 {
		t.Fatalf("全量导出应再落一条审计，实际 %d 条", len(rows))
	}
	// AuditRecentByScope 是 id DESC，第一条是刚才那次。
	if rows[0].Target != "usage" {
		t.Errorf("全量导出的 target = %q，want usage", rows[0].Target)
	}

	// 被闸门挡下的导出不落「成功导出」的痕：403 不是一次导出。
	if code, _ := adminGetWithIdentity30(t, h.harness,
		"/v1/_admin/usage/export?scope=organization:x", "bad-token"); code != http.StatusForbidden {
		t.Fatalf("无效 token 应 403，实际 %d", code)
	}
	if rows = auditRows(t, h.harness, policy.SystemScope, "usage.export"); len(rows) != 2 {
		t.Errorf("被拒的导出不该落导出审计，实际 %d 条", len(rows))
	}
}
