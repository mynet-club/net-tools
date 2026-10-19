package server

// 身份登录后的自助 token 端点：拿外部身份令牌（LDAP 会话 token / OIDC JWT）换网关
// 下游 token 的**创建**或**轮换**。
//
// 补的是登录链路的下半场。/v1/_identity/ldap/login 只换到短时会话令牌（外部身份证明），
// 而调 /v1/chat/completions 与 /v1/_me 要的是网关下游 token（sk-…）；此前那枚 token 只能
// 由管理员下发（POST /v1/_admin/users），目录用户登录后拿不到自己的第一枚 —— 首次自助
// 入口就是这里。
//
// 口径：
//   - 鉴权凭据是 X-Identity-Token（与请求路径同一条验签链），不是下游 token —— 否则又是
//     「先有鸡还是先有蛋」；
//   - subject 必须能当网关用户名，且不许改名：token 的 subject 就是网关用户名
//     （requestIdentity30 的绑定规则），任何改写出来的名字都会让后续绑定永久失配；
//   - 用户不存在就按 subject 开号（默认 byo：只能带自己的上游，不能消费系统上游 ——
//     那要管理员显式改 consumption 并配模型白名单），已停用的账号一律拒绝；
//   - 一个用户只有一枚下游 token：语义是「有则轮换（旧的立即失效），无则创建」，
//     明文只在这一次返回。

import (
	"errors"
	"net/http"
	"strings"

	"github.com/mynet-club/net-tools/llmproxy/internal/identity"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// identityTokenPath 是自助创建/轮换下游 token 的端点。
const identityTokenPath = "/v1/_identity/me/token"

// handleIdentityMintToken 处理 POST /v1/_identity/me/token。
func (s *Server) handleIdentityMintToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
			"只支持 POST /v1/_identity/me/token")
		return
	}
	if !s.MultiUserEnabled() {
		writeJSONError(w, http.StatusNotImplemented, "not_configured",
			"多用户模式未启用（服务端缺少主密钥）")
		return
	}
	cfg := s.cfgStore.Current()
	rt := s.policyFor(cfg)
	if rt == nil || rt.idn == nil {
		writeJSONError(w, http.StatusNotFound, "not_found",
			"本网关没有启用外部身份（identity 段）")
		return
	}

	identityToken := strings.TrimSpace(r.Header.Get(IdentityHeaderName))
	if identityToken == "" {
		writeJSONError(w, http.StatusUnauthorized, "authentication_error",
			"缺少 "+IdentityHeaderName+"：先用 POST /v1/_identity/ldap/login 换会话令牌")
		return
	}
	requestID := strings.TrimSpace(r.Header.Get("X-Request-Id"))
	principal, err := rt.idn.resolve(r.Context(), identityToken, requestID)
	if err != nil {
		if errors.Is(err, identity.ErrExpired) {
			writeJSONError(w, http.StatusUnauthorized, "authentication_error",
				"身份令牌已过期，请重新登录")
			return
		}
		s.log.Warnf("身份令牌校验失败 ip=%s request_id=%s: %v", clientIP(r), requestID, err)
		writeJSONError(w, http.StatusUnauthorized, "authentication_error",
			"身份令牌无效，请重新登录")
		return
	}

	subject := principal.Identity.Subject
	if !validName(subject) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"身份 subject 不能作网关用户名（只允许字母、数字、点、下划线、连字符，1~64 位）；"+
				"请调整目录属性映射（identity.ldap.user_attr）后重试")
		return
	}

	token, err := store.NewToken()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	hash := store.TokenHash(token)

	created := false
	e := s.usersSnapshot().byName[subject]
	if e == nil {
		if err := s.db.CreateUser(subject, hash); err != nil {
			// 并发首登：另一个请求刚建好同名账号。退化成轮换，而不是回一个冲突让用户重试。
			e = s.usersSnapshot().byName[subject]
			if e == nil {
				writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
				return
			}
		} else {
			created = true
		}
	}
	if !created {
		if !e.Enabled {
			writeJSONError(w, http.StatusForbidden, "account_disabled",
				"账号 "+subject+" 已停用")
			return
		}
		if err := s.db.SetUserToken(subject, hash); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	_ = s.SyncUsers()

	action, detail := "user.rotate_token", "身份自助轮换"
	verb := "轮换"
	if created {
		action, detail = "user.create", "身份自助创建"
		verb = "创建"
	}
	s.auditUser(subject, action, subject, detail)
	s.log.Warnf("用户 %s 通过身份令牌自助%s下游 token ip=%s", subject, verb, clientIP(r))

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{
		"name":       subject,
		"token":      token,
		"token_type": "Bearer",
		"created":    created,
		"note":       "明文只在这里返回一次；已有旧 token 的，旧 token 已立即失效",
		"usage":      "Authorization: Bearer <token> 调 /v1/chat/completions；X-Identity-Token 继续带在请求上做身份绑定",
	})
}
