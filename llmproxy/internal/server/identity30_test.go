package server

// §9 P8 的接线测试：外部 IdP token → org/project 进请求路径。
//
// 断言全部盯「边界」而不是「功能」：身份接线最容易犯的错不是「没读出 org」，
// 而是「读错人的 org」或者「没读到就干脆拒请求」。所以每组都同时钉住
//
//   - 该绑上的绑上了（链里出现 org/project，ctx 有主组织）；
//   - 不该发生的没发生（缺 token / 签名错 / 过期 / 主体不符 / 静态 key 一律**退回**
//     网关自身范围，绝不失败、绝不并进任何外部范围）。
//
// 真 token 由 identity.FakeAuthority 现场签（不联网、不提交密钥材料），JWKS 文件由
// 它的 RSA 公钥现场拼出：这样走的是与生产逐字相同的 OIDCProvider 验签路径。

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/identity"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// ---------------------------------------------------------------- 配置与夹具

// identityYAML 是「系统池可连通 + 可计费」的多用户环境，供 enforce + 外部身份用。
//
// 与 cfgYAML 的差别：带 pricing（消费用户走系统池要能算账）与 max_data_level
// （3.0 参与时它是已启用供应商的必填项）。
func identityYAML(upstreamURL string) string {
	return fmt.Sprintf(`
server:
  host: 127.0.0.1
  port: 0
  api_keys:
    - sk-static
  admin_token: sk-admin
routing:
  retry: 1
  failure_threshold: 3
  cooldown_seconds: 60
providers:
  - name: sys-a
    enabled: true
    base_url: %s/v1
    api_key: sk-sys
    weight: 1
    models: ["*"]
    max_data_level: internal
pricing:
  currency: CNY
  models:
    "*": {cache_hit: 0, cache_miss: 0, output: 0}
database:
  path: ""
  retain_days: 30
log:
  level: error
`, upstreamURL)
}

// identitySection 拼出 identity 段（§9 P8-1 的配置面）。
func identitySection(issuer, audience, jwksFile string) string {
	return fmt.Sprintf(`
identity:
  provider: oidc
  source: campus-oidc
  issuer: "%s"
  audience: "%s"
  jwks_file: %s
`, issuer, audience, jwksFile)
}

// policyBundleIdentity 是身份用例的策略包：把「组织条件」写成三条规则，
// 让「链里有没有 org」这件事直接表现为 200/403。
//
//   - base-model：任何主体都能用（对照组：不受身份影响）；
//   - org-model：仅 university 组织可用（条件命中才放行 → 没有 org 就 403）；
//   - org-banned：默认放行，但 university 组织被 deny（deny-first → 有 org 才 403）。
const policyBundleIdentity = `
id: t-idn
version: 1
scope: system:gateway
entitlements:
  - subject: "*"
    resource: "model:base-model"
    action: use
    effect: allow
  - subject: "*"
    resource: "model:org-model"
    action: use
    effect: allow
    conditions:
      organization: university
  - subject: "*"
    resource: "model:org-banned"
    action: use
    effect: allow
  - subject: "*"
    resource: "model:org-banned"
    action: use
    effect: deny
    conditions:
      organization: university
`

// policyBundleOrgScope 是**按范围生效**的组织包：它只覆盖链里含 organization:university
// 的请求。这一条是用来把「链里到底有没有 org」从「ctx 里有没有 org」里分出来的 ——
// entitlement 的 conditions 看的是 ctx，而包/规则是否参与判定看的是链。
// 少了这条，一个只改 ctx 不改链的实现也能骗过「真实流量」用例。
const policyBundleOrgScope = `
id: t-org
version: 1
scope: organization:university
entitlements:
  - subject: "*"
    resource: "model:org-scope-model"
    action: use
    effect: allow
`

// identityPolicySection 声明两个包：系统包（所有请求）+ 组织包（仅 university）。
func identityPolicySection() string {
	return `
policy:
  mode: enforce
  data_level: internal
  active_bundle: t-idn
  bundles:
    - id: t-idn
      version: 1
      scope: system:gateway
    - id: t-org
      version: 1
      scope: organization:university
`
}

// writeBundleFile 按 <id>.yaml 落盘（加载器只认这个文件名）。
func writeBundleFile(t *testing.T, h *harness, name, content string) {
	t.Helper()
	dir := filepath.Join(filepath.Dir(h.configPath), "policy-bundles")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeRS256JWKS 用公钥材料拼一份标准 JWKS（本包只解析、没有序列化，所以手拼）。
func writeRS256JWKS(t *testing.T, path, kid string, pub *rsa.PublicKey) {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	doc := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"alg":"RS256","use":"sig","n":%q,"e":%q}]}`, kid, n, e)
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

func authRSAPublic(t *testing.T, auth *identity.FakeAuthority) *rsa.PublicKey {
	t.Helper()
	keys, err := auth.Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.Algorithm == identity.AlgRS256 {
			pub, ok := k.Public.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("RS256 公钥类型不符: %T", k.Public)
			}
			return pub
		}
	}
	t.Fatal("FakeAuthority 没有 RS256 公钥")
	return nil
}

func sampleProfile(t *testing.T, fixture string) identity.UniversityProfile {
	t.Helper()
	for _, p := range identity.UniversitySampleProfiles() {
		if p.FixtureName() == fixture {
			return p
		}
	}
	t.Fatalf("样例画像 %q 不存在", fixture)
	return identity.UniversityProfile{}
}

// newIdentityHarness 搭一个「enforce + identity 段 + 真 JWKS 文件」的环境。
// 返回的 runtime 尚未构造（首次判定时才建），但 JWKS 已就位。
func newIdentityHarness(t *testing.T, auth *identity.FakeAuthority) *muHarness {
	t.Helper()
	up := startMockUpstream(t, &mockUpstream{name: "sys-a", apiKey: "sk-sys"})
	yaml := identityYAML(up.baseURL) +
		identityPolicySection() +
		identitySection(auth.Issuer(), auth.Audience(), "jwks.json")
	h := newMUHarnessWith(t, yaml)
	writeBundleFile(t, h.harness, "t-idn.yaml", policyBundleIdentity)
	writeBundleFile(t, h.harness, "t-org.yaml", policyBundleOrgScope)
	writeRS256JWKS(t, filepath.Join(filepath.Dir(h.configPath), "jwks.json"),
		auth.RSAKeyID(), authRSAPublic(t, auth))
	return h
}

// addConsumptionUser 建一个消费模式用户并返回它的明文 token：只有消费用户才会落到
// 系统池（providersFor 对普通用户返回自有上游，这里是空的）。
func addConsumptionUser(t *testing.T, h *muHarness, name string) string {
	t.Helper()
	token := h.addUser(t, name)
	if err := h.db.SetUserMode(name, store.ModeConsumption); err != nil {
		t.Fatalf("SetUserMode(%s): %v", name, err)
	}
	if err := h.srv.SyncUsers(); err != nil {
		t.Fatalf("SyncUsers: %v", err)
	}
	return token
}

// runtimeOf 构造（或取到）当前修订的策略运行态。
func runtimeOf(t *testing.T, h *harness) *policyRuntime {
	t.Helper()
	rt := h.srv.policyFor(h.cfgStore.Current())
	if rt == nil {
		t.Fatal("enforce 配置下应存在策略运行态")
	}
	return rt
}

// idnCounts 读身份绑定计数（对外的 identity 读数）。
func idnCounts(t *testing.T, h *harness) (int64, map[string]int64) {
	t.Helper()
	snap := h.srv.metrics.identitySnapshot()
	bound, _ := snap["bound"].(int64)
	unbound, _ := snap["unbound"].(map[string]int64)
	return bound, unbound
}

// ---------------------------------------------------------------- 绑定：链变宽、身份换人

// 有效 token + subject 与网关认定一致：org/project 并进范围链，身份换成 token 的身份。
//
// 这一条是 P8 的唯一作用点 —— org 级规则、org 级采集、org 级导出都靠它才有数据。
func TestIdentity30BindsOrgProjectAndMergesChain(t *testing.T) {
	auth, err := identity.NewFakeAuthority()
	if err != nil {
		t.Fatal(err)
	}
	h := newIdentityHarness(t, auth)
	rt := runtimeOf(t, h.harness)

	token, err := auth.SignUniversityToken(sampleProfile(t, "teacher-2001"), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	idn := h.srv.requestIdentity30(rt, "uid-tea-2001", token, "req-bind")
	if idn.err != nil {
		t.Fatalf("有效 token 不该构造失败: %v", idn.err)
	}
	if !idn.bound {
		t.Fatalf("应绑定成功，实际 reason=%q", idn.reason)
	}
	if idn.org != "university" || idn.project != "proj-curriculum" {
		t.Fatalf("主组织/主项目 = %q/%q，want university/proj-curriculum", idn.org, idn.project)
	}
	if idn.identity.Source != "campus-oidc" {
		t.Errorf("身份来源 = %q，want campus-oidc", idn.identity.Source)
	}

	// 链是并集：网关自己的 user:<名> 不能被外部链顶掉（否则按 subject 写的规则全失配）。
	for _, want := range []policy.ScopeRef{
		policy.MustScope(policy.ScopeUser, "uid-tea-2001"),
		policy.MustScope(policy.ScopeOrganization, "university"),
		policy.MustScope(policy.ScopeProject, "proj-curriculum"),
	} {
		if !idn.chain.Includes(want) {
			t.Errorf("范围链缺 %s（实际 %s）", want.Display(), idn.chain.Display())
		}
	}

	bound, _ := idnCounts(t, h.harness)
	if bound != 1 {
		t.Errorf("bound 计数 = %d，want 1", bound)
	}
}

// ---------------------------------------------------------------- 退回：绝不放宽、绝不失败

// 五种「拿不到可信外部身份」的形态都必须退回网关自身范围：不绑、不失败、不并任何外部范围。
func TestIdentity30WithoutValidTokenNeverWidensScope(t *testing.T) {
	auth, err := identity.NewFakeAuthority()
	if err != nil {
		t.Fatal(err)
	}
	h := newIdentityHarness(t, auth)
	rt := runtimeOf(t, h.harness)

	teacher := sampleProfile(t, "teacher-2001")
	good, err := auth.SignUniversityToken(teacher, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	expired := teacher
	expired.Lifetime = -time.Hour
	expiredToken, err := auth.SignUniversityToken(expired, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	forged, err := auth.Sign(identity.SignRequest{Profile: teacher, SignWithForeign: true})
	if err != nil {
		t.Fatal(err)
	}
	studentToken, err := auth.SignUniversityToken(sampleProfile(t, "student-1001"), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	noOrg := policy.MustScope(policy.ScopeOrganization, "university")
	cases := []struct {
		name    string
		scope   string
		token   string
		reason  string
		counter string
	}{
		{"没带 token", "uid-tea-2001", "", "missing", "no_token"},
		{"主体与网关认定不符", "uid-tea-2001", studentToken, "subject_mismatch", "subject_mismatch"},
		{"签名对不上", "uid-tea-2001", forged, "invalid", "invalid"},
		{"token 已过期", "uid-tea-2001", expiredToken, "invalid", "invalid"},
		{"静态 key 无用户归属", "", good, "static_key", "static_key"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before, beforeUnbound := idnCounts(t, h.harness)
			idn := h.srv.requestIdentity30(rt, tc.scope, tc.token, "req-fallback")
			if idn.err != nil {
				t.Fatalf("外部身份问题不得让请求失败，实际 err=%v", idn.err)
			}
			if idn.bound {
				t.Fatalf("不该绑定，实际绑上了（org=%q）", idn.org)
			}
			if idn.reason != tc.reason {
				t.Errorf("reason = %q，want %q", idn.reason, tc.reason)
			}
			if idn.org != "" || idn.project != "" {
				t.Errorf("退回时不得填主组织/主项目，实际 %q/%q", idn.org, idn.project)
			}
			if idn.chain.Includes(noOrg) {
				t.Errorf("退回的链里混进了外部范围: %s", idn.chain.Display())
			}
			base, baseErr := policyChainFor(tc.scope)
			if baseErr != nil {
				t.Fatal(baseErr)
			}
			if idn.chain.Display() != base.Display() {
				t.Errorf("退回后链 = %s，want 与网关自身一致 %s", idn.chain.Display(), base.Display())
			}

			after, afterUnbound := idnCounts(t, h.harness)
			if after != before {
				t.Errorf("退回不该计入 bound（%d -> %d）", before, after)
			}
			if afterUnbound[tc.counter] != beforeUnbound[tc.counter]+1 {
				t.Errorf("unbound[%s] 应 +1，实际 %d -> %d",
					tc.counter, beforeUnbound[tc.counter], afterUnbound[tc.counter])
			}
		})
	}
}

// identity 段未配置时，行为与今天逐字节相同：直通网关自身范围，且一个身份计数都不动。
func TestIdentity30AbsentConfigIsUnchanged(t *testing.T) {
	up := startMockUpstream(t, &mockUpstream{name: "a", apiKey: "sk-a"})
	h := newHarness(t, cfgYAML(map[string]string{"a": up.baseURL}, []string{"sk-local"})+
		policySection("enforce", "t-idn", "system:gateway", 1))
	writeBundleFile(t, h, "t-idn.yaml", policyBundleIdentity)

	rt := runtimeOf(t, h)
	if rt.idn != nil {
		t.Fatal("没配 identity 段时不该有外部身份运行态")
	}

	idn := h.srv.requestIdentity30(rt, "uid-tea-2001", "随便一个 token", "req-absent")
	if idn.err != nil || idn.bound || idn.reason != "" || idn.org != "" {
		t.Fatalf("未配置时应当直通网关范围，实际 bound=%v reason=%q err=%v", idn.bound, idn.reason, idn.err)
	}
	bound, unbound := idnCounts(t, h)
	if bound != 0 {
		t.Errorf("未配置时 bound = %d，want 0", bound)
	}
	for k, v := range unbound {
		if v != 0 {
			t.Errorf("未配置时 unbound[%s] = %d，want 0", k, v)
		}
	}
}

// ---------------------------------------------------------------- 真实流量：org 级规则命中

// 通过 HTTP 走完整链路：org 级 allow/deny 是否在真实流量上生效，以及缺 token 时是否照旧。
func TestIdentity30OrgRulesApplyToRealTraffic(t *testing.T) {
	auth, err := identity.NewFakeAuthority()
	if err != nil {
		t.Fatal(err)
	}
	h := newIdentityHarness(t, auth)
	token := addConsumptionUser(t, h, "uid-tea-2001")

	idToken, err := auth.SignUniversityToken(sampleProfile(t, "teacher-2001"), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// 1) 不带外部 token：org 条件不满足 → org-model 403，base-model 照常 200。
	resp, body := postIdentity(t, h.harness, "/v1/chat/completions", token, "", "org-model", "req-no-idn")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("无外部身份时 org-model 应 403，实际 %d: %s", resp.StatusCode, body)
	}
	resp, body = postIdentity(t, h.harness, "/v1/chat/completions", token, "", "base-model", "req-no-idn-base")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("base-model 应 200（不受身份影响），实际 %d: %s", resp.StatusCode, body)
	}
	// 组织包（scope: organization:university）不覆盖这条链 → 它那条 allow 不参与 →
	// 系统包默认拒绝 → 403。这一格是「链」而不是「ctx」的证据。
	resp, body = postIdentity(t, h.harness, "/v1/chat/completions", token, "", "org-scope-model", "req-no-idn-scope")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("无外部身份时组织包不该生效，org-scope-model 应 403，实际 %d: %s", resp.StatusCode, body)
	}

	// 2) 带上有效 token：org 条件命中 → org-model 200，org-banned 被 deny 403，
	//    且链里出现 organization:university → 组织包生效 → org-scope-model 200。
	resp, body = postIdentity(t, h.harness, "/v1/chat/completions", token, idToken, "org-model", "req-with-idn")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("带外部身份后 org-model 应 200，实际 %d: %s", resp.StatusCode, body)
	}
	resp, body = postIdentity(t, h.harness, "/v1/chat/completions", token, idToken, "org-banned", "req-with-idn-ban")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("university 组织的 org-banned 应 403，实际 %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "policy_denied") {
		t.Errorf("拒绝类型应是 policy_denied: %s", body)
	}
	resp, body = postIdentity(t, h.harness, "/v1/chat/completions", token, idToken, "org-scope-model", "req-with-idn-scope")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("带外部身份后组织包应覆盖这条链，org-scope-model 应 200，实际 %d: %s", resp.StatusCode, body)
	}

	// 3) 读数对外可见：至少绑成过一次。
	bound, _ := idnCounts(t, h.harness)
	if bound < 1 {
		t.Errorf("bound 计数 = %d，want ≥1", bound)
	}
}

// postIdentity 发一条带 X-Identity-Token 的 chat 请求。
func postIdentity(t *testing.T, h *harness, path, token, idToken, model, requestID string) (*http.Response, []byte) {
	t.Helper()
	payload := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}]}`, model)
	req, err := http.NewRequest(http.MethodPost, h.gateway.URL+path, strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if idToken != "" {
		req.Header.Set(IdentityHeaderName, idToken)
	}
	if requestID != "" {
		req.Header.Set("X-Request-Id", requestID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, raw
}
