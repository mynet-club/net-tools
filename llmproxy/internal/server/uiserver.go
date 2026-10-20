package server

import (
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/mynet-club/net-tools/llmproxy/ui"
)

// 两个界面，两个独立 SPA：
//
//	GET /ui/     用户控制台 —— 登录后管自己的上游、用量与 token
//	GET /admin/  管理控制台 —— 用 server.admin_token 登录，管用户/上游/登录方式/审计
//
// 迁移期把旧版管理台留在 /admin/legacy/：策略、处理器、知识源、回放、价格这几个
// 交互较重的面板还没迁到 SPA，删掉旧页会让这些能力直接从界面上消失。
//
// 刻意不做「同一个页面按 token 猜身份」：那会让人分不清该拿哪个凭证登录，
// 也把两类权限混在一个入口里。两个 SPA 各自只服务自己的静态目录。
//
// 同源托管是另一个刻意选择：页面要带着 token 调 API，同源就不需要 CORS、
// 也不担心别的站点跨源读取用量。
const legacyAdminPrefix = "/admin/legacy/"

// 旧版管理台只放行它自己的文件（用户端旧页已删除）。
var adminAppFiles = map[string]bool{
	"admin.html": true, "admin.js": true, "common.js": true, "app.css": true,
	"openapi.yaml": true,
}

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

// handleUserUI / handleAdminUI 是正式入口：两个 SPA。
func (s *Server) handleUserUI(w http.ResponseWriter, r *http.Request) {
	s.serveSPA(w, r, "/ui/", userSPAEmbed)
}

func (s *Server) handleAdminUI(w http.ResponseWriter, r *http.Request) {
	s.serveSPA(w, r, "/admin/", adminSPAEmbed)
}

// handleLegacyAdminUI 服务旧版管理台（只保留高级面板所需的页面）。
func (s *Server) handleLegacyAdminUI(w http.ResponseWriter, r *http.Request) {
	s.serveApp(w, r, legacyAdminPrefix, "admin.html", adminAppFiles)
}

// redirectPrefix 把旧挂载点原样搬到新路径（保留子路径，静态资源也跟着走）。
func redirectPrefix(oldPrefix, newPrefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, oldPrefix)
		http.Redirect(w, r, newPrefix+rest, http.StatusMovedPermanently)
	}
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

// handleOpenAPI 提供 OpenAPI 3 描述（嵌在二进制里）。
// 可直接贴进 Swagger UI / Redoc；也方便脚本生成客户端。
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	b, err := ui.FS.ReadFile("openapi.yaml")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(b)
}

// ------------------------------------------------------------------ 两个 SPA
//
// /ui/、/admin/ 是正式入口；旧的 /spa/{user,admin}/ 只做 301 兼容跳转。
//
// 嵌入与覆盖的关系：嵌入产物是「开箱即用」的默认值；<RuntimeDir>/ui/{user,admin}
// 存在同名文件时优先用磁盘上的版本 —— 机构可以只替换前端，不动二进制。

const (
	userSPAEmbed  = "spa/user"
	adminSPAEmbed = "spa/admin"
)

// WithUIOverrideDir 设置运行时界面覆盖根目录（通常是 <RuntimeDir>/ui）。
func (s *Server) WithUIOverrideDir(dir string) *Server {
	s.uiOverrideDir = dir
	return s
}

// serveSPA 服务一个 SPA 的静态资源。
//
// 用 hash 路由，所以不存在「前端路径回退到 index.html」的问题：请求路径只有
// 前缀本身与 assets/*，不会出现 /overview 这种需要 rewrite 的地址。
func (s *Server) serveSPA(w http.ResponseWriter, r *http.Request, prefix, embeddedDir string) {
	if r.URL.Path == strings.TrimSuffix(prefix, "/") {
		http.Redirect(w, r, prefix, http.StatusMovedPermanently)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "界面资源只支持 GET")
		return
	}

	name := strings.Trim(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if name == "" {
		name = "index.html"
	}
	// 只接受干净的相对路径：挡掉 ../、绝对路径与空段
	if !fs.ValidPath(name) {
		writeJSONError(w, http.StatusNotFound, "invalid_request_error", "界面资源路径不合法")
		return
	}

	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	// style-src 需要 'unsafe-inline'：Element Plus 的弹层/定位靠内联 style 属性，
	// 旧页面的 CSSOM 写法不受影响。script-src 仍严格只允许本站脚本。
	h.Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; connect-src 'self' http: https:; base-uri 'none'; "+
			"form-action 'none'; frame-ancestors 'none'")
	if name == "index.html" {
		h.Set("Cache-Control", "no-store")
	} else {
		// 构建产物文件名带内容哈希，长缓存是安全的
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	}

	sub, err := fs.Sub(ui.FS, embeddedDir)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "界面资源不可用: "+err.Error())
		return
	}

	if s.uiOverrideDir != "" {
		root := os.DirFS(filepath.Join(s.uiOverrideDir, path.Base(embeddedDir)))
		if _, statErr := fs.Stat(root, name); statErr == nil {
			http.ServeFileFS(w, r, root, name)
			return
		}
	}
	if _, statErr := fs.Stat(sub, name); statErr != nil {
		if name == "index.html" {
			writeSPAMissing(w, embeddedDir)
			return
		}
		writeJSONError(w, http.StatusNotFound, "invalid_request_error", "界面资源不存在")
		return
	}
	http.ServeFileFS(w, r, sub, name)
}

// writeSPAMissing 在「源码运行但没构建前端」时给一句可操作的说明，
// 而不是一个没有线索的 404。
func writeSPAMissing(w http.ResponseWriter, embeddedDir string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	app := path.Base(embeddedDir)
	_, _ = io.WriteString(w, `<!doctype html><meta charset="utf-8"><title>llmproxy 界面未构建</title>
<body style="font:14px/1.6 -apple-system,BlinkMacSystemFont,'PingFang SC',sans-serif;padding:40px;color:#0f172a">
<h2>前端资源未构建</h2>
<p>发行包自带构建产物。从源码运行时先执行：</p>
<pre style="background:#f6f7fb;padding:12px;border-radius:8px">cd web &amp;&amp; npm ci &amp;&amp; npm run build</pre>
<p>或把机构的静态包放到运行时目录的 <code>ui/`+app+`</code> 下。</p>`)
}
