package server

import (
	"io/fs"
	"net/http"

	"github.com/mynet-club/net-tools/llmproxy/ui"
)

// 用户控制台：静态资源由二进制自带，与 API 同源。
//
// 同源是刻意的选择：页面要带着 token 调 /v1/_me*，同源就不需要开 CORS、
// 不担心其它站点跨源读取用户的用量；代价是这个界面必须由网关自己托管。
func (s *Server) newUIHandler() http.Handler {
	sub, err := fs.Sub(ui.FS, ".")
	if err != nil {
		// 只可能是 embed 路径写错，属于打包期错误，这里返回 500 而不是静默不出
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSONError(w, http.StatusInternalServerError, "internal", "界面资源不可用: "+err.Error())
		})
	}
	return http.StripPrefix("/ui/", http.FileServer(http.FS(sub)))
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ui" {
		http.Redirect(w, r, "/ui/", http.StatusMovedPermanently)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "界面资源只支持 GET")
		return
	}
	h := w.Header()
	// 页面里存着用户 token，任何中间层都不该缓存
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
			"connect-src 'self' http: https:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	s.uiHandler.ServeHTTP(w, r)
}
