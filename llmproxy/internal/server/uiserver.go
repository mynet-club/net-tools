package server

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/mynet-club/net-tools/llmproxy/ui"
)

// 两个界面，两套独立页面：
//
//	GET /ui/     用户控制台 —— 用「用户 token」登录，管自己的上游与用量
//	GET /admin/  管理控制台 —— 用 server.admin_token 登录，管系统上游与用户
//
// 刻意不做「同一个页面按 token 猜身份」：那会让人分不清该拿哪个凭证登录，
// 也把两类权限混在一个入口里。这里各自只放行自己的文件 ——
// 用户台里拿不到 admin.js，管理台里也拿不到 user.js。
//
// 同源托管是另一个刻意选择：页面要带着 token 调 API，同源就不需要 CORS、
// 也不担心别的站点跨源读取用量。
var (
	userAppFiles = map[string]bool{
		"user.html": true, "user.js": true, "common.js": true, "app.css": true,
	}
	adminAppFiles = map[string]bool{
		"admin.html": true, "admin.js": true, "common.js": true, "app.css": true,
	}
)

// newUIHandler 返回嵌在二进制里的静态文件服务（不做前缀剥离，路径由调用方决定）。
func (s *Server) newUIHandler() http.Handler {
	sub, err := fs.Sub(ui.FS, ".")
	if err != nil {
		// 只可能是 embed 路径写错，属于打包期错误，这里返回 500 而不是静默不出
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSONError(w, http.StatusInternalServerError, "internal", "界面资源不可用: "+err.Error())
		})
	}
	return http.FileServer(http.FS(sub))
}

func (s *Server) handleUserUI(w http.ResponseWriter, r *http.Request) {
	s.serveApp(w, r, "/ui/", "user.html", userAppFiles)
}

func (s *Server) handleAdminUI(w http.ResponseWriter, r *http.Request) {
	s.serveApp(w, r, "/admin/", "admin.html", adminAppFiles)
}

// serveApp 服务一个界面的静态资源：只有 allow 里列出的文件能被取到。
func (s *Server) serveApp(w http.ResponseWriter, r *http.Request, prefix, index string, allow map[string]bool) {
	if r.URL.Path == strings.TrimSuffix(prefix, "/") {
		http.Redirect(w, r, prefix, http.StatusMovedPermanently)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "界面资源只支持 GET")
		return
	}

	name := strings.TrimPrefix(r.URL.Path, prefix)
	if name == "" {
		name = index
	}
	if !allow[name] {
		writeJSONError(w, http.StatusNotFound, "invalid_request_error",
			prefix+" 下没有这个文件。入口是 "+index)
		return
	}

	h := w.Header()
	// 页面里存着 token，任何中间层都不该缓存
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
			"connect-src 'self' http: https:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

	// 路径由白名单决定，不把用户输入拼进文件路径，也就没有目录遍历的问题
	rr := r.Clone(r.Context())
	rr.URL.Path = "/" + name
	s.uiHandler.ServeHTTP(w, rr)
}
