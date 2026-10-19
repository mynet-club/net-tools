package server

// P0 基建的接口级测试：
//   - 登录方式清单是公开的、顺序稳定，LDAP 是否可用跟 identity 配置走；
//   - 两个 SPA 的静态服务在 /spa/ 下可用，运行时覆盖目录优先于嵌入产物。

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// spaTestConfig 给这几条用例一份最小可用配置（配置校验要求至少一个供应商；
// 这些用例都不会真的往上游发请求）。
func spaTestConfig() string {
	return cfgYAML(map[string]string{"a": "http://127.0.0.1:9/v1"}, []string{"sk-local"})
}

func TestAuthMethodsListsFour(t *testing.T) {
	h := newHarness(t, spaTestConfig())
	resp, raw := h.get(t, authMethodsPath, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", authMethodsPath, resp.StatusCode, raw)
	}
	var payload struct {
		Methods []AuthMethod `json:"methods"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("响应不是 JSON: %v\n%s", err, raw)
	}
	want := []struct {
		id      string
		enabled bool
	}{
		{"password", false}, // 没有主密钥 = 多用户模式未启用
		{"token", true},
		{"oauth", false},
		{"ldap", false},
	}
	if len(payload.Methods) != len(want) {
		t.Fatalf("方法数 = %d，期望 %d: %s", len(payload.Methods), len(want), raw)
	}
	for i, w := range want {
		if payload.Methods[i].ID != w.id || payload.Methods[i].Enabled != w.enabled {
			t.Errorf("第 %d 项 = %+v，期望 id=%s enabled=%v", i, payload.Methods[i], w.id, w.enabled)
		}
		if payload.Methods[i].Label == "" {
			t.Errorf("%s 缺少文案", w.id)
		}
	}
}

func TestAuthMethodsLDAPEnabledByConfig(t *testing.T) {
	yaml := spaTestConfig() + `
identity:
  provider: ldap
  source: campus-ldap
  ldap:
    url: ldaps://ldap.example.edu:636
    bind_dn: cn=svc,dc=example,dc=edu
    bind_password: svc
    base_dn: ou=people,dc=example,dc=edu
    user_attr: uid
    allowed_targets: ["ldap.example.edu:636"]
`
	h := newHarness(t, yaml)
	resp, raw := h.get(t, authMethodsPath, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", authMethodsPath, resp.StatusCode, raw)
	}
	var payload struct {
		Methods []AuthMethod `json:"methods"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("响应不是 JSON: %v\n%s", err, raw)
	}
	for _, m := range payload.Methods {
		if m.ID == "ldap" && !m.Enabled {
			t.Fatalf("identity.provider=ldap 时 ldap tab 应启用: %s", raw)
		}
	}
}

func TestSPAOverrideServesFromDisk(t *testing.T) {
	h := newHarness(t, spaTestConfig())
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "user", "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "user", "index.html"),
		[]byte("<!doctype html><title>override-index</title>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "user", "assets", "x.js"),
		[]byte("console.log('override')"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.srv.WithUIOverrideDir(dir)

	resp, raw := h.get(t, "/spa/user/", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "override-index") {
		t.Fatalf("覆盖目录没生效：%d %s", resp.StatusCode, raw)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "style-src 'self' 'unsafe-inline'") {
		t.Errorf("SPA 的 CSP 必须允许内联 style（Element Plus 定位需要）: %q", csp)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("index.html 不能缓存: %q", cc)
	}

	resp, raw = h.get(t, "/spa/user/assets/x.js", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "override") {
		t.Fatalf("覆盖目录的资源没生效：%d %s", resp.StatusCode, raw)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("带哈希的静态资源应长缓存: %q", cc)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q，期望 javascript", ct)
	}
}

func TestSPARejectsNonGet(t *testing.T) {
	h := newHarness(t, spaTestConfig())
	resp, _ := h.post(t, "/spa/user/", "", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /spa/user/ = %d，期望 405", resp.StatusCode)
	}
}

func TestSPARedirectsBarePrefix(t *testing.T) {
	h := newHarness(t, spaTestConfig())
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(h.gateway.URL + "/spa/admin")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("/spa/admin = %d，期望 301", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/spa/admin/" {
		t.Fatalf("Location = %q，期望 /spa/admin/", loc)
	}
}
