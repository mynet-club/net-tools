package server

// 登录方式清单：登录页据此渲染 tab，管理员后台据此显示开关。
//
// 这是公开端点（登录前就要能读），所以只能回「有哪些方式、是否启用」，
// 不能带任何凭据、目录地址或 IdP 参数。标签文案是给人看的默认值，
// 机构可以按自己的叫法改（后续接配置）。

import "net/http"

const authMethodsPath = "/v1/_auth/methods"

// AuthMethod 是一种登录方式。id 是稳定的机器标识，label 是界面文案。
type AuthMethod struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Enabled bool   `json:"enabled"`
}

// handleAuthMethods 处理 GET /v1/_auth/methods。
//
// 四种方式的口径：
//   - password：本地账号密码（users.password_hash，需要主密钥/多用户模式）；
//   - token：下游 token（sk-），始终可用 —— 它不依赖任何外部系统；
//   - oauth：浏览器授权码登录（auth.oauth 配齐才出现）；
//   - ldap：由 identity.provider=ldap 决定；
//   - auth.methods 里显式 false 的一律不下发为可用。
func (s *Server) handleAuthMethods(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
			"只支持 GET /v1/_auth/methods")
		return
	}
	cfg := s.cfgStore.Current()
	oauthLabel := "统一身份认证"
	if cfg.Auth.OAuth.Configured() && cfg.Auth.OAuth.ProviderName != "" {
		oauthLabel = cfg.Auth.OAuth.ProviderName
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"methods": []AuthMethod{
			{ID: "password", Label: "账号密码", Enabled: s.MultiUserEnabled() && cfg.Auth.Methods.PasswordEnabled()},
			{ID: "token", Label: "Token 登录", Enabled: cfg.Auth.Methods.TokenEnabled()},
			{ID: "oauth", Label: oauthLabel, Enabled: cfg.Auth.OAuth.Configured() && cfg.Auth.Methods.OAuthEnabled()},
			{ID: "ldap", Label: "校园网账号", Enabled: cfg.Identity.Provider == "ldap" && cfg.Auth.Methods.LDAPEnabled()},
		},
	})
}
