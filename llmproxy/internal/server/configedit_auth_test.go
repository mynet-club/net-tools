package server

// auth 段的管理端读写：开关、OAuth 客户端、密钥不下发/留空不清空、段外不动。

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestAdminAuthConfigRoundTrip(t *testing.T) {
	h := configHarness(t, "")
	admin := map[string]string{"Authorization": "Bearer sk-admin"}

	// 1) 读：没有 auth 段时四个方式默认全开，密钥不下发
	code, _, raw := reqJSON(t, http.MethodGet, h.gateway.URL+"/v1/_admin/config/auth", admin, nil)
	if code != http.StatusOK {
		t.Fatalf("GET auth = %d: %s", code, raw)
	}
	var got struct {
		Methods map[string]bool `json:"methods"`
		OAuth   map[string]any  `json:"oauth"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"password", "token", "oauth", "ldap"} {
		if !got.Methods[m] {
			t.Errorf("%s 默认应启用: %s", m, raw)
		}
	}
	if strings.Contains(string(raw), "sec-1") {
		t.Errorf("响应不得包含 client_secret 明文: %s", raw)
	}

	// 2) 写：配 OAuth 客户端并启用
	body := map[string]any{
		"session_ttl_ms": 3600000,
		"methods":        map[string]any{"password": true, "token": true, "oauth": true, "ldap": false},
		"oauth": map[string]any{
			"provider_name": "学校 SSO",
			"client_id":     "cid",
			"client_secret": "sec-1",
			"auth_url":      "https://sso.example.edu/a",
			"token_url":     "https://sso.example.edu/t",
			"userinfo_url":  "https://sso.example.edu/u",
			"redirect_url":  "https://llm.example.edu/v1/_auth/oauth/callback",
		},
	}
	code, _, raw = reqJSON(t, http.MethodPut, h.gateway.URL+"/v1/_admin/config/auth", admin, body)
	if code != http.StatusOK {
		t.Fatalf("PUT auth = %d: %s", code, raw)
	}
	if _, _, err := h.cfgStore.Reload(); err != nil {
		t.Fatalf("重载失败: %v", err)
	}
	code, _, raw = reqJSON(t, http.MethodGet, h.gateway.URL+"/v1/_admin/config/auth", admin, nil)
	if code != http.StatusOK {
		t.Fatalf("回读 = %d: %s", code, raw)
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Methods["oauth"] || got.Methods["ldap"] {
		t.Errorf("开关没写对: %s", raw)
	}
	if hs, _ := got.OAuth["has_secret"].(bool); !hs {
		t.Errorf("has_secret 应为 true: %s", raw)
	}
	if s, _ := got.OAuth["client_secret"].(string); s != "" {
		t.Errorf("client_secret 不应下发: %q", s)
	}

	src, _ := os.ReadFile(h.configPath)
	if !strings.Contains(string(src), "sec-1") {
		t.Fatal("密钥没有写进配置文件")
	}
	if !strings.Contains(string(src), "keepme") || !strings.Contains(string(src), "admin_token: sk-admin") {
		t.Fatal("auth 段之外的内容被改动了")
	}

	// 公共登录方式端点应反映开关
	code, _, raw = reqJSON(t, http.MethodGet, h.gateway.URL+authMethodsPath, nil, nil)
	if code != http.StatusOK {
		t.Fatalf("methods = %d: %s", code, raw)
	}
	var methods struct {
		Methods []AuthMethod `json:"methods"`
	}
	if err := json.Unmarshal(raw, &methods); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range methods.Methods {
		if m.ID == "oauth" {
			found = true
			if !m.Enabled || m.Label != "学校 SSO" {
				t.Errorf("oauth tab 应启用且用配置文案: %+v", m)
			}
		}
		if m.ID == "ldap" && m.Enabled {
			t.Errorf("ldap 已显式关闭，不该启用")
		}
	}
	if !found {
		t.Fatalf("methods 里没有 oauth: %s", raw)
	}

	// 3) 密钥留空 = 沿用原值
	body["oauth"].(map[string]any)["client_secret"] = ""
	code, _, raw = reqJSON(t, http.MethodPut, h.gateway.URL+"/v1/_admin/config/auth", admin, body)
	if code != http.StatusOK {
		t.Fatalf("第二次 PUT = %d: %s", code, raw)
	}
	src, _ = os.ReadFile(h.configPath)
	if !strings.Contains(string(src), "sec-1") {
		t.Fatal("留空保存不能把已有密钥清掉")
	}
}
