package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// identity 段（§9 P8 / 决策包 §0.1 第 11′–14′ 行）的加载测试。
// 每一条都对应一个「配错之后的后果」：整段缺省的逐字节不变、只填一半、
// provider 非 oidc 被静默忽略、以及保留词冲突。

// 一份可用的 identity 段，用 enforce 把它带进「真正参与」的模式。
const identityOIDCBlock = `
policy:
  mode: enforce
  data_level: internal
  active_bundle: b1
  bundles:
    - id: b1
      version: 1
      scope: system:global
identity:
  provider: oidc
  source: university-idp
  issuer: https://idp.university.example
  audience: llmproxy-gateway
  jwks_file: keys/jwks.json
`

func TestIdentity30AbsentMeansDisabled(t *testing.T) {
	cfg := mustCfg30(t, "")
	if cfg.Identity.Enabled() {
		t.Fatal("整段缺省的 identity 不该启用")
	}
	if got := cfg.Identity.ResolveJWKS(cfg.BundleBaseDir()); got != "" {
		t.Fatalf("缺省时不该解析出 JWKS 路径，得到 %q", got)
	}
}

func TestIdentity30OIDCBlockEnables(t *testing.T) {
	cfg := mustCfg30(t, identityOIDCBlock)
	if !cfg.Identity.Enabled() {
		t.Fatal("完整的 oidc 段应当启用")
	}
	if cfg.Identity.Provider != "oidc" {
		t.Fatalf("provider 规范化后应是 oidc，得到 %q", cfg.Identity.Provider)
	}
	want := filepath.Join(cfg.BundleBaseDir(), "keys", "jwks.json")
	if got := cfg.Identity.ResolveJWKS(cfg.BundleBaseDir()); got != want {
		t.Fatalf("JWKS 相对路径没按配置目录解析：得到 %q，期望 %q", got, want)
	}
}

func TestIdentity30AbsoluteJWKSPath(t *testing.T) {
	cfg := mustCfg30(t, identityOIDCBlock+`
`)
	abs := filepath.Join(string(filepath.Separator), "etc", "llmproxy", "jwks.json")
	cfg.Identity.JWKSFile = abs
	if got := cfg.Identity.ResolveJWKS(cfg.BundleBaseDir()); got != abs {
		t.Fatalf("绝对路径不该被拼接：得到 %q，期望 %q", got, abs)
	}
}

func TestIdentity30PartialBlockRejected(t *testing.T) {
	_, err := cfg30(t, `
policy:
  mode: enforce
  data_level: internal
  active_bundle: b1
  bundles:
    - id: b1
      version: 1
      scope: system:global
identity:
  source: university-idp
  issuer: https://idp.university.example
`)
	if err == nil || !strings.Contains(err.Error(), "identity.provider 必填") {
		t.Fatalf("只填一半应当报「provider 必填」，得到 %v", err)
	}
}

func TestIdentity30RejectsNonOIDCProvider(t *testing.T) {
	_, err := cfg30(t, `
policy:
  mode: enforce
  data_level: internal
  active_bundle: b1
  bundles:
    - id: b1
      version: 1
      scope: system:global
identity:
  provider: saml
  source: university-idp
  issuer: https://idp.university.example
  audience: llmproxy-gateway
  jwks_file: keys/jwks.json
`)
	if err == nil || !strings.Contains(err.Error(), "只实现 oidc") {
		t.Fatalf("非 oidc 的 provider 必须显式报错，得到 %v", err)
	}
}

func TestIdentity30RejectsHTTPJWKS(t *testing.T) {
	_, err := cfg30(t, `
policy:
  mode: enforce
  data_level: internal
  active_bundle: b1
  bundles:
    - id: b1
      version: 1
      scope: system:global
identity:
  provider: oidc
  source: university-idp
  issuer: https://idp.university.example
  audience: llmproxy-gateway
  jwks_file: https://idp.university.example/.well-known/jwks.json
`)
	if err == nil || !strings.Contains(err.Error(), "只接受本机文件路径") {
		t.Fatalf("http(s) JWKS 必须被拒，得到 %v", err)
	}
}

func TestIdentity30RejectsReservedSource(t *testing.T) {
	_, err := cfg30(t, `
policy:
  mode: enforce
  data_level: internal
  active_bundle: b1
  bundles:
    - id: b1
      version: 1
      scope: system:global
identity:
  provider: oidc
  source: llmproxy-user-token
  issuer: https://idp.university.example
  audience: llmproxy-gateway
  jwks_file: keys/jwks.json
`)
	if err == nil || !strings.Contains(err.Error(), "不能是网关保留值") {
		t.Fatalf("source 撞上网关保留词必须报错，得到 %v", err)
	}
}

func TestIdentity30LegacyWarns(t *testing.T) {
	cfg := mustCfg30(t, `
identity:
  provider: oidc
  source: university-idp
  issuer: https://idp.university.example
  audience: llmproxy-gateway
  jwks_file: keys/jwks.json
`)
	if !cfg.Identity.Enabled() {
		t.Fatal("配置完整时 Enabled 应为真（是否参与由 server 的 UsesPolicy 门槛决定）")
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "identity 段不会参与任何判定") {
			found = true
		}
	}
	if !found {
		t.Fatalf("legacy 下配了 identity 应当有告警，得到 %v", cfg.Warnings)
	}
}

func TestIdentity30UnknownFieldRejected(t *testing.T) {
	_, err := cfg30(t, `
policy:
  mode: enforce
  data_level: internal
  active_bundle: b1
  bundles:
    - id: b1
      version: 1
      scope: system:global
identity:
  provider: oidc
  source: university-idp
  issuer: https://idp.university.example
  audience: llmproxy-gateway
  jwks_file: keys/jwks.json
  max_lifetime: 1h
`)
	if err == nil {
		t.Fatal("identity.max_lifetime 不在词表内（裁决 13′ 不加网关侧 TTL 上限），KnownFields 应当拒绝")
	}
}
