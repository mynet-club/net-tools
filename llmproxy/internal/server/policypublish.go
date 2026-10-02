package server

// 本文件是 §3.H 管理口第二步：策略**写侧** —— 版本发布、生效版切换、撤下与重新引用、
// 按备份回滚、应急切回 legacy。
//
// 四条约束决定了这里的形态：
//
//  1. **一次发布同时改引用与内容文件**。loadOneBundle 逐字段核对两边，
//     只改一边就是「两个真值来源」；所以这里把「写内容 → 改引用 → 校验整份配置 →
//     原子替换」收成一条通道，任何一步失败都回滚内容文件，不留下半成品。
//  2. **写之前先校验**：与 providers 同一套 —— 临时文件 → 宽松通道 → 严格通道 →
//     按引用加载策略包（这才是「改完真的能加载」的判据）→ 备份 → rename。
//     校验不过原文件一字未动，返回 400 并说清是哪一条。
//  3. **不猜运维没写的东西**：版本必须显式给（它是审计与回放的输入），
//     配置里还没有 policy 段时发布直接 400 并指向 /policy/mode，而不是替对方选一个
//     shadow —— 后者会让一份没被任何人批准过的策略集立刻开始判定。
//  4. **响应不外泄规则条件值**：磁盘上的内容文件本来就带 Conditions 的值，
//     GET 视图一律复用只读口那套 bundleViews（只列条件键名），不在这里另开一面。

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// adminPolicyBundlesRoute 分发 /v1/_admin/policy/bundles[/...]。
//
// 写侧刻意不挂在 /v1/_admin/policy 上：那条路径已经被测试钉成 405
// （可见性端点不能被当成配置入口，否则运维会信一个根本不落库的 PUT）。
func (s *Server) adminPolicyBundlesRoute(w http.ResponseWriter, r *http.Request, tail string) {
	tail = strings.Trim(tail, "/")
	if tail == "" {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.adminPolicyBundlesInspect(w)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
				"发布用 PUT /v1/_admin/policy/bundles/{id}，撤下用 DELETE，切换生效版用 POST /v1/_admin/policy/active")
		}
		return
	}

	parts := strings.Split(tail, "/")
	id := parts[0]
	if !validName(id) || id == "." || id == ".." {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"策略包 id 只能是 1~64 位的字母、数字、点、下划线或短横（它会当文件名用）")
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodPut:
			s.adminPublishBundle(w, r, id)
		case http.MethodDelete:
			s.adminWithdrawBundle(w, r, id)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
				"这个路径支持 PUT（发布这一版）和 DELETE（撤下引用）")
		}
		return
	}
	if len(parts) == 2 && parts[1] == "rollback" {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 POST")
			return
		}
		s.adminRollbackBundle(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "backups" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET")
			return
		}
		s.adminBundleBackups(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "reference" {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 POST")
			return
		}
		s.adminReferenceBundle(w, r, id)
		return
	}
	writeJSONError(w, http.StatusNotFound, "invalid_request_error",
		"可用路径：/v1/_admin/policy/bundles、/v1/_admin/policy/bundles/{id}、"+
			"/v1/_admin/policy/bundles/{id}/backups、/v1/_admin/policy/bundles/{id}/rollback、"+
			"/v1/_admin/policy/bundles/{id}/reference")
}

// ── 发布 ───────────────────────────────────────────────────

// auditScopeOfRef 把配置里那条引用的 scope 串落成审计范围。
//
// 手改过的配置文件可能写着解析不了的 scope：那种情况下记到系统范围，
// 让 note（就是 detail）里的原串继续可查 —— 一条归属可疑的审计胜过没有这一条。
func auditScopeOfRef(raw string) policy.ScopeRef {
	scope, err := config.ParseScopeRef(raw)
	if err != nil {
		return policy.SystemScope
	}
	return scope
}

// adminPolicyBundlesInspect 把「配置里的引用」与「磁盘上的内容文件」并排列出来。
//
// 为什么值得单独一屏：加载是「引用与内容逐字段核对、全有或全无」，所以两边任何
// 一处漂了，网关的表现都是**整段策略不生效**，而 mode 字段仍然写着 shadow。
// 只报配置引用看不到磁盘真相，只报磁盘文件看不到哪一版在效 —— 运维需要的正是
// 「对不上的是哪一条」。
func (s *Server) adminPolicyBundlesInspect(w http.ResponseWriter) {
	path := s.cfgStore.Path()
	src, err := os.ReadFile(path)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "读取配置文件失败: "+err.Error())
		return
	}
	p, err := config.RawPolicy(src)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "config_unreadable", err.Error())
		return
	}
	cfg := s.cfgStore.Current()
	rt := s.policyFor(cfg)
	dir := policyBundleDir(path, p)

	referenced := map[string]bool{}
	refs := make([]map[string]any, 0, len(p.Bundles))
	allMatched := true
	for _, ref := range p.Bundles {
		referenced[ref.ID] = true
		item := map[string]any{
			"id": ref.ID, "version": ref.Version, "scope": ref.Scope,
			"stamp":  fmt.Sprintf("%s@%d", ref.ID, ref.Version),
			"active": strings.TrimSpace(p.ActiveBundle) == ref.ID,
		}
		file, err := config.BundleFilePath(dir, ref.ID)
		if err != nil {
			allMatched = false
			item["file_error"] = err.Error()
			refs = append(refs, item)
			continue
		}
		item["file"] = file
		content, err := config.ReadBundleFile(file)
		switch {
		case errors.Is(err, config.ErrPolicyBundle) && strings.Contains(err.Error(), "不存在"):
			item["file_exists"] = false
			item["matches"] = false
			item["drift"] = "内容文件不存在：按这条引用加载会整体失败"
			allMatched = false
		case err != nil:
			// 读不回来也要报出来，且不能把文件原文塞进响应（那可能带着条件值）。
			allMatched = false
			item["file_exists"] = true
			item["matches"] = false
			item["file_error"] = err.Error()
		default:
			item["file_exists"] = true
			item["content_version"] = content.Version
			item["content_scope"] = content.Scope.Display()
			item["matches"] = content.ID == strings.TrimSpace(ref.ID) &&
				content.Version == ref.Version &&
				content.Scope.Display() == strings.TrimSpace(ref.Scope)
			if !item["matches"].(bool) {
				allMatched = false
				item["drift"] = fmt.Sprintf("引用是 %s@v%d（scope=%s），内容文件是 %s@v%d（scope=%s）："+
					"发新版要同时改引用与内容文件", ref.ID, ref.Version, ref.Scope,
					content.ID, content.Version, content.Scope.Display())
			}
			// 规则视图与只读口同一构造函数：只出选择器与条件键名。
			view := bundleView(content)
			item["rules"] = view["rules"]
			item["rules_count"] = view["count"]
		}
		if backups, err := config.ListBundleBackups(dir, ref.ID); err == nil {
			item["backups"] = len(backups)
		}
		refs = append(refs, item)
	}

	// 磁盘上有、配置没引用的那些：它们不参与任何判定，但确实占着「策略包」的名字。
	var orphans []map[string]any
	if entries, err := filepath.Glob(filepath.Join(dir, "*.yaml")); err == nil {
		for _, e := range entries {
			b, err := config.ReadBundleFile(e)
			if err != nil {
				orphans = append(orphans, map[string]any{
					"file": e, "file_error": err.Error(),
				})
				continue
			}
			if referenced[strings.TrimSpace(b.ID)] {
				continue
			}
			view := bundleView(b)
			view["orphan"] = true
			view["file"] = e
			orphans = append(orphans, view)
		}
	}

	bundleDirDisplay := strings.TrimSpace(p.BundleDir)
	if bundleDirDisplay == "" {
		bundleDirDisplay = config.DefaultBundleDir
	}
	out := map[string]any{
		"revision":        s.cfgStore.Revision(),
		"config_path":     path,
		"configured_mode": orDash(p.Mode),
		"mode":            cfg.Policy.ModeResolved().String(),
		"active_bundle":   orDash(p.ActiveBundle),
		"bundle_dir":      bundleDirDisplay,
		"bundle_dir_abs":  dir,
		"data_level":      orDash(cfg.Policy.DataLevelResolved().String()),
		// 与只读口同一件事：legacy 下生效分级是 unknown，但配置里声明的那一行不是。
		// 发布表单的「数据分级：不改（当前 X）」要按声明值预置，否则会把已经配好的
		// 那一行显示成没配，而按下应用模式时它恰恰是「不改」的那个值。
		"declared_data_level": orDash(p.DataLevel),
		"refs":                refs,
		"running":             rt != nil,
	}
	if len(orphans) > 0 {
		out["orphans"] = orphans
	}
	// 引用与内容对不上时必须单独说一句。两种情形都要覆盖：
	//  - 内存里仍是上一次成功加载的集合（热加载只看配置文件 mtime，改坏内容文件不会立刻触发
	//    重读）—— 于是「现在照旧在跑」与「下一次加载会整体失败」同时为真，只报前者会被当成安全状态；
	//  - 内存里已经加载失败（running=false + inactive_reason）—— 请求此刻按 legacy 走。
	if !allMatched {
		out["drift_warning"] = "按现在磁盘上的引用与内容文件重读会整体失败：下一次热加载或重启后 3.0 " +
			"不参与判定（内存里若仍是上一次成功加载的集合，那只是还没触发重读）。" +
			"请按 refs[].drift 点名的一条把两边对齐（PUT /v1/_admin/policy/bundles/{id} 会同时改两边）"
	}
	if rt != nil {
		out["policy_version"] = rt.Version()
		out["loaded_bundles"] = bundleViews(rt.set)
	} else if reason, why := s.policyInactiveReason(cfg); reason != "" {
		out["inactive_reason"] = reason
		if why != "" {
			out["load_error"] = why
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminPublishBundle(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Version      int                  `json:"version"`
		Scope        string               `json:"scope"`
		Entitlements []policy.Entitlement `json:"entitlements"`
		Active       *bool                `json:"active"`
	}
	if err := readJSONBodyStrict(w, r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	if body.Version < 1 {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"version 必填且要 ≥ 1：策略版本串是审计与回放的输入，不能由服务端替这次发布猜一版")
		return
	}
	scope, err := config.ParseScopeRef(body.Scope)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			fmt.Sprintf("scope %q 不合法: %v", body.Scope, err))
		return
	}
	bundle := policy.PolicyBundle{
		ID: id, Version: body.Version, Scope: scope, Entitlements: body.Entitlements,
	}
	// 领域校验必须在落盘之前：一条写错的规则（未知条件键、选择器形态不对）如果
	// 进了磁盘，配置加载就会整体失败 —— 那不是「这条规则不生效」，是整段策略没了。
	if err := bundle.Validate(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}

	path := s.cfgStore.Path()
	src, err := os.ReadFile(path)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "读取配置文件失败: "+err.Error())
		return
	}
	p, err := config.RawPolicy(src)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "config_unreadable", err.Error())
		return
	}
	if strings.TrimSpace(p.Mode) == "" {
		// 这份部署还没有 policy 段。这里替它写一个 mode 就等于让一份刚发布的策略集
		// 立刻开始判定，而「先影子观察」这一步是被跳过的那个人做的决定。
		writeJSONError(w, http.StatusConflict, "policy_not_configured",
			"配置里还没有 policy.mode：先用 POST /v1/_admin/policy/mode 显式选定模式"+
				"（新上 3.0 请从 shadow 开始），再发布策略包")
		return
	}

	// 引用与内容一起改：以引用为准的那套核对（loadOneBundle）意味着只改一边必然加载失败。
	old := findBundleRef(p.Bundles, id)
	p.Bundles = setBundleRef(p.Bundles, config.PolicyBundleRef{
		ID: id, Version: bundle.Version, Scope: scope.Display(),
	})
	// active 缺省不动：发布一条新包不该顺手改掉「现在哪一版在生效」——
	// 那是一个独立的、需要明确按下的动作（POST /policy/active）。
	if body.Active == nil || *body.Active {
		p.ActiveBundle = id
	}

	dir := policyBundleDir(path, p)
	contentPath, err := config.BundleFilePath(dir, id)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	contentBackup, err := config.WriteBundleFile(dir, bundle)
	if err != nil {
		if errors.Is(err, config.ErrPolicyBundle) || errors.Is(err, policy.ErrBundle) {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	// 内容已经落到线上目录了，之后的每一步都可能失败 —— 每一次都必须把它还原回去，
	// 否则磁盘上留着一份配置根本没引用的新版本，而下一次发布看到的「旧内容」是它。
	undo := func() {
		if contentBackup == "" {
			_ = os.Remove(contentPath)
			return
		}
		_ = os.Rename(contentBackup, contentPath)
	}

	newSrc, err := config.EditPolicy(src, p)
	if err != nil {
		undo()
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	note := fmt.Sprintf("策略包 %s 已发布为 v%d（scope=%s，%d 条规则）；生效包 = %s",
		id, bundle.Version, scope.Display(), len(bundle.Entitlements), p.ActiveBundle)
	if old != nil && old.Version != bundle.Version {
		note += fmt.Sprintf("（原引用是 v%d）", old.Version)
	}
	resp, ok := s.commitPolicyConfig(w, path, src, newSrc, note, undo,
		policyAudit{action: "policy.bundle.publish", scope: scope, target: id})
	if !ok {
		return
	}
	resp["bundle"] = map[string]any{
		"id": id, "version": bundle.Version, "scope": scope.Display(),
		"rules": len(bundle.Entitlements), "file": contentPath,
		"content_backup": filepath.Base(contentBackup),
	}
	writeJSON(w, http.StatusOK, resp)
}

// ── 撤下引用（按范围回滚的一种）────────────────────────────

func (s *Server) adminWithdrawBundle(w http.ResponseWriter, r *http.Request, id string) {
	path := s.cfgStore.Path()
	src, err := os.ReadFile(path)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "读取配置文件失败: "+err.Error())
		return
	}
	p, err := config.RawPolicy(src)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "config_unreadable", err.Error())
		return
	}
	ref := findBundleRef(p.Bundles, id)
	if ref == nil {
		writeJSONError(w, http.StatusNotFound, "not_found",
			fmt.Sprintf("配置里没有对 %s 的引用（当前引用：%s）", id, refIDs(p.Bundles)))
		return
	}
	wasActive := strings.TrimSpace(p.ActiveBundle) == id
	if wasActive {
		successor := strings.TrimSpace(r.URL.Query().Get("active"))
		if len(p.Bundles) <= 1 {
			// 撤掉唯一一条引用会让 shadow/enforce 没有内容版本 —— 加载必然失败，
			// 而运维此刻想要的是「这条路先别按策略走」。那条路有专门的开关。
			writeJSONError(w, http.StatusConflict, "last_bundle",
				fmt.Sprintf("%s 是 %s 下唯一的策略包：要停用 3.0 请改用 POST /v1/_admin/policy/mode 设 mode=legacy（应急开关，改一行即可），"+
					"而不是删掉最后一条引用（当前 mode=%s）", id, p.Mode, p.Mode))
			return
		}
		if successor == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
				fmt.Sprintf("要撤的正是生效包：请在查询里指定接棒的包，例如 ?active=%s（当前可用：%s）",
					otherID(p.Bundles, id), refIDs(p.Bundles)))
			return
		}
		if successor == id || findBundleRef(p.Bundles, successor) == nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
				fmt.Sprintf("接棒的包 %q 不在引用里（可用：%s）", successor, refIDs(p.Bundles)))
			return
		}
		p.ActiveBundle = successor
	}
	p.Bundles = removeBundleRef(p.Bundles, id)

	newSrc, err := config.EditPolicy(src, p)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	note := fmt.Sprintf("已撤下对 %s 的引用（v%d）；生效包 = %s。内容文件仍留在 %s —— 它不再被任何引用加载，"+
		"重新引用同一版就能立刻回来", id, ref.Version, p.ActiveBundle, policyBundleDir(path, p))
	resp, ok := s.commitPolicyConfig(w, path, src, newSrc, note, nil,
		policyAudit{action: "policy.bundle.withdraw", scope: auditScopeOfRef(ref.Scope), target: id})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ── 重新引用磁盘上已有的内容文件 ───────────────────────────

// adminReferenceBundle 是撤下的逆操作：按磁盘上那份 <id>.yaml 写回一条引用。
//
// 为什么必须专门有一条这样的接口：撤下刻意只删引用、把内容文件留在原地（那正是
// 「先撤下来观察几天、随时撤回」的前提），而 GET 视图只回显选择器与条件**键名** ——
// 条件值不经读侧外泄（§2.9 规则 6）。于是「重新启用」如果只能走 PUT 发布，运维就得
// 手抄一份带条件值的规则回来或直接改 YAML：前者把泄露面引到了剪贴板里，后者绕过了
// 整份配置的加载校验。这里让服务端读那份已经躺在受校验目录里的文件，两边天然一致。
func (s *Server) adminReferenceBundle(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Version *int  `json:"version"`
		Active  *bool `json:"active"`
	}
	if err := readJSONBodyStrict(w, r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}

	path := s.cfgStore.Path()
	src, err := os.ReadFile(path)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "读取配置文件失败: "+err.Error())
		return
	}
	p, err := config.RawPolicy(src)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "config_unreadable", err.Error())
		return
	}
	if cur := findBundleRef(p.Bundles, id); cur != nil {
		writeJSONError(w, http.StatusConflict, "already_referenced",
			fmt.Sprintf("配置里已经有对 %s 的引用（v%d，scope=%s）：换一版用 PUT /v1/_admin/policy/bundles/%s，"+
				"只换生效包用 POST /v1/_admin/policy/active", id, cur.Version, cur.Scope, id))
		return
	}
	if strings.TrimSpace(p.Mode) == "" {
		// 与发布同一判断：没有 policy.mode 时加引用，配置加载会直接拒（「配了 bundles 却没写 mode」）。
		// 与其把那条加载错误原样丢过来，不如先说清缺的是哪一个开关。
		writeJSONError(w, http.StatusConflict, "policy_not_configured",
			"配置里还没有 policy.mode：先用 POST /v1/_admin/policy/mode 显式选定模式，再引用策略包")
		return
	}

	dir := policyBundleDir(path, p)
	file, err := config.BundleFilePath(dir, id)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	content, err := config.ReadBundleFile(file)
	if err != nil {
		if errors.Is(err, config.ErrPolicyBundle) {
			writeJSONError(w, http.StatusConflict, "bundle_unreadable",
				fmt.Sprintf("磁盘上的 %s 没有可读且校验通过的内容（引用它会让整段策略加载失败）: %v", file, err))
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	// 文件名与文件里的 id 可以不一致（foo.yaml 里写 id: bar）。加载器按引用核对的是内容里的
	// id，所以这里以路径上那个 id 为准拒一次，否则会写出一条「引用 bar 却挂在 foo 名下」的包。
	if strings.TrimSpace(content.ID) != id {
		writeJSONError(w, http.StatusConflict, "id_mismatch",
			fmt.Sprintf("%s 里的 id 是 %q，与路径上指定的 %q 不一致：先修好文件名或改发布（PUT /v1/_admin/policy/bundles/%s）",
				file, content.ID, id, id))
		return
	}
	// 给了 version 就当核对闸门用：磁盘这一版不是你要的那一版时，停下来比替对方猜一版安全。
	if body.Version != nil && *body.Version != content.Version {
		writeJSONError(w, http.StatusConflict, "version_mismatch",
			fmt.Sprintf("磁盘上的 %s 是 v%d，与请求里指定的 v%d 不符（要发新版用 PUT /v1/_admin/policy/bundles/%s）",
				id, content.Version, *body.Version, id))
		return
	}

	p.Bundles = setBundleRef(p.Bundles, config.PolicyBundleRef{
		ID: id, Version: content.Version, Scope: content.Scope.Display(),
	})
	if body.Active == nil || *body.Active {
		p.ActiveBundle = id
	}
	newSrc, err := config.EditPolicy(src, p)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	note := fmt.Sprintf("已按磁盘上的 %s 重新建立引用（v%d，scope=%s，%d 条规则）；生效包 = %s",
		id, content.Version, content.Scope.Display(), len(content.Entitlements), p.ActiveBundle)
	resp, ok := s.commitPolicyConfig(w, path, src, newSrc, note, nil,
		policyAudit{action: "policy.bundle.reference", scope: content.Scope, target: id})
	if !ok {
		return
	}
	// 内容文件这次没动过，所以没有 undo；回显走读侧同一个 bundleView：只有选择器与条件键名。
	resp["bundle"] = bundleView(content)
	writeJSON(w, http.StatusOK, resp)
}

// ── 内容回滚 ───────────────────────────────────────────────

func (s *Server) adminBundleBackups(w http.ResponseWriter, r *http.Request, id string) {
	path := s.cfgStore.Path()
	src, err := os.ReadFile(path)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "读取配置文件失败: "+err.Error())
		return
	}
	p, err := config.RawPolicy(src)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "config_unreadable", err.Error())
		return
	}
	entries, err := s.listBackups(path, p, id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		item := map[string]any{"name": filepath.Base(e), "path": e}
		if b, err := config.ReadBundleFile(e); err != nil {
			// 备份读不回来也要列出来：它至少证明「那一次发布确实发生过」，
			// 而静默跳过会让人以为从来没有历史版本。
			item["error"] = err.Error()
		} else {
			item["version"] = b.Version
			item["scope"] = b.Scope.Display()
			item["rules"] = len(b.Entitlements)
		}
		if st, err := os.Stat(e); err == nil {
			item["mtime"] = st.ModTime().Format(time.RFC3339)
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": id, "bundle_dir": policyBundleDir(path, p), "backups": out,
		"note": "backups 按时间升序，最后一份是最近一次发布替换掉的旧内容",
	})
}

func (s *Server) adminRollbackBundle(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Backup  string `json:"backup"`
		Version int    `json:"version"`
	}
	if err := readJSONBodyStrict(w, r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	path := s.cfgStore.Path()
	src, err := os.ReadFile(path)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "读取配置文件失败: "+err.Error())
		return
	}
	p, err := config.RawPolicy(src)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "config_unreadable", err.Error())
		return
	}
	if findBundleRef(p.Bundles, id) == nil {
		writeJSONError(w, http.StatusConflict, "not_referenced",
			fmt.Sprintf("%s 当前没有被引用，回滚内容没有意义：要重新启用请用 PUT /v1/_admin/policy/bundles/%s 发布", id, id))
		return
	}
	dir := policyBundleDir(path, p)
	entries, err := s.listBackups(path, p, id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if len(entries) == 0 {
		writeJSONError(w, http.StatusNotFound, "not_found",
			fmt.Sprintf("策略包 %s 没有可回滚的历史内容（%s 下没有备份）", id, dir))
		return
	}
	target := entries[len(entries)-1]
	switch {
	case strings.TrimSpace(body.Backup) != "":
		// 只认文件名：请求体里给路径就等于让这个接口去读任意文件。
		base := filepath.Base(strings.TrimSpace(body.Backup))
		found := ""
		for _, e := range entries {
			if filepath.Base(e) == base {
				found = e
				break
			}
		}
		if found == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
				fmt.Sprintf("备份 %q 不属于这个包（可用：%s）", base, backupNames(entries)))
			return
		}
		target = found
	case body.Version > 0:
		found := ""
		for _, e := range entries {
			if b, err := config.ReadBundleFile(e); err == nil && b.Version == body.Version {
				found = e
				break
			}
		}
		if found == "" {
			writeJSONError(w, http.StatusNotFound, "not_found",
				fmt.Sprintf("没有 v%d 的历史备份（可用版本：%s）", body.Version, backupVersions(entries)))
			return
		}
		target = found
	}

	restored, contentBackup, err := config.RestoreBundleFrom(dir, id, target)
	if err != nil {
		if errors.Is(err, config.ErrPolicyBundle) {
			writeJSONError(w, http.StatusConflict, "backup_unreadable", err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	contentPath, err := config.BundleFilePath(dir, id)
	if err != nil {
		_ = os.Rename(contentBackup, contentPath)
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	undo := func() {
		if contentBackup == "" {
			_ = os.Remove(contentPath)
			return
		}
		_ = os.Rename(contentBackup, contentPath)
	}

	// 引用必须跟着回到那一版：只换内容不改引用，两边就当场打脸（加载失败）。
	scope := restored.Scope.Display()
	if ref := findBundleRef(p.Bundles, id); ref != nil {
		scope = ref.Scope
	}
	p.Bundles = setBundleRef(p.Bundles, config.PolicyBundleRef{ID: id, Version: restored.Version, Scope: scope})
	newSrc, err := config.EditPolicy(src, p)
	if err != nil {
		undo()
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	note := fmt.Sprintf("策略包 %s 已回滚到 v%d（来源备份 %s），引用同步改到 v%d",
		id, restored.Version, filepath.Base(target), restored.Version)
	resp, ok := s.commitPolicyConfig(w, path, src, newSrc, note, undo,
		policyAudit{action: "policy.bundle.rollback", scope: auditScopeOfRef(scope), target: id})
	if !ok {
		return
	}
	resp["rolled_back_from"] = filepath.Base(contentPath) + " 的替换前内容已存为 " + filepath.Base(contentBackup)
	resp["rules"] = len(restored.Entitlements)
	writeJSON(w, http.StatusOK, resp)
}

// ── 生效版切换 / 模式开关 ──────────────────────────────────

func (s *Server) adminPolicySetActive(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Bundle string `json:"bundle"`
	}
	if err := readJSONBodyStrict(w, r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	id := strings.TrimSpace(body.Bundle)
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"bundle 必填：要生效的那个策略包 id（必须是 policy.bundles 里已有的一条）")
		return
	}
	s.editPolicySection(w, r, "policy.active.set", id, func(p *config.PolicyConfig) (string, error) {
		if findBundleRef(p.Bundles, id) == nil {
			return "", fmt.Errorf("包 %q 不在 policy.bundles 里（可用：%s）—— 先发布它，再切生效版",
				id, refIDs(p.Bundles))
		}
		prev := p.ActiveBundle
		p.ActiveBundle = id
		return fmt.Sprintf("生效包从 %s 切到 %s（引用与内容都没改，只换了「哪一版参与判定」）",
			orDash(prev), id), nil
	})
}

func (s *Server) adminPolicySetMode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode             string `json:"mode"`
		DataLevel        string `json:"data_level"`
		FallbackToLegacy *bool  `json:"fallback_to_legacy"`
	}
	if err := readJSONBodyStrict(w, r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	mode := strings.TrimSpace(body.Mode)
	switch mode {
	case "legacy", "shadow", "enforce":
	case "":
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"mode 必填：legacy（停用 3.0，应急开关）、shadow（只观察不改路由）、enforce（允许策略改路由）")
		return
	default:
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			fmt.Sprintf("mode 是 %q，只能是 legacy、shadow 或 enforce", body.Mode))
		return
	}
	s.editPolicySection(w, r, "policy.mode.set", mode, func(p *config.PolicyConfig) (string, error) {
		prev := p.Mode
		if prev == "" {
			prev = "legacy（配置里还没有 policy 段）"
		}
		p.Mode = mode
		if strings.TrimSpace(body.DataLevel) != "" {
			p.DataLevel = strings.TrimSpace(body.DataLevel)
		}
		if body.FallbackToLegacy != nil {
			enabled := *body.FallbackToLegacy
			p.FallbackToLegacy = &enabled
		}
		// 第一次启用 3.0 时，段里只有 mode 是不够的：没有 data_level 判定就没有分级依据，
		// 没有引用就没有内容版本。这里不替对方填 —— 而是把缺的那一步指名道姓说出来。
		if mode != "legacy" {
			if strings.TrimSpace(p.DataLevel) == "" {
				return "", errors.New("mode=" + mode + " 需要 data_level：请在请求体里带上本部署声明的数据分级" +
					"（public、internal、confidential、restricted 之一）。影子与强制都不读正文，" +
					"分级只能由部署声明")
			}
			if len(p.Bundles) == 0 {
				return "", errors.New("mode=" + mode + " 需要至少一个策略包：请先 PUT /v1/_admin/policy/bundles/{id} 发布")
			}
			if strings.TrimSpace(p.ActiveBundle) == "" {
				return "", errors.New("mode=" + mode + " 需要生效包指针：请再 POST /v1/_admin/policy/active")
			}
		}
		note := fmt.Sprintf("mode 从 %s 切到 %s", prev, mode)
		if mode == "legacy" {
			note += "（应急开关：3.0 立刻停止参与判定，已配置的引用原样保留，切回时不用重抄）"
		}
		return note, nil
	})
}

// policyAudit 是一次策略写操作要落的审计描述。
//
// 它是 commitPolicyConfig 的**必填**参数，不是可选项：改判定规则是这台网关上后果最大
// 的一类动作（一次误发布能让整个组织的模型可用性变掉），而 §3.H 要的是「谁在什么时候
// 把哪一版换成了哪一版」事后查得回来。放在落盘通道上而不是各调用点里，是为了让
// 「新增一个写接口却忘了记审计」在编译期就不成立。
type policyAudit struct {
	action string          // 动作标识，如 policy.bundle.publish
	scope  policy.ScopeRef // 这条动作**关于**哪个范围（§2.7 规则 2）
	target string          // 被操作的对象标识，如策略包 id
}

// editPolicySection 是「只改 policy 段本身、不动内容文件」那类动作的公共通道。
// 这类动作（切生效包、切模式）都是全局开关，所以归属固定在系统范围。
func (s *Server) editPolicySection(w http.ResponseWriter, r *http.Request, action, target string,
	mutate func(*config.PolicyConfig) (string, error)) {
	path := s.cfgStore.Path()
	src, err := os.ReadFile(path)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "读取配置文件失败: "+err.Error())
		return
	}
	p, err := config.RawPolicy(src)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "config_unreadable", err.Error())
		return
	}
	note, err := mutate(&p)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	newSrc, err := config.EditPolicy(src, p)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	resp, ok := s.commitPolicyConfig(w, path, src, newSrc, note, nil,
		policyAudit{action: action, scope: policy.SystemScope, target: target})
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ── 落盘通道 ───────────────────────────────────────────────

// sectionGuard 是「新配置能加载」与「真的落盘」之间那一段特有的判据。
//
// 返回 failMsg 非空 = 放弃写入（原文件不动、undo 已经跑过）；
// 返回 extra 会并进成功响应，让各段把自己的字段（比如 policy_version）带出去。
// 为什么做成回调而不是各段自己复制一遍落盘代码：备份、chmod 0600、严格模式试读、
// 审计与热加载确认这五件事缺任何一件都会留下「改坏了说不清」的现场，
// 而复制两份迟早只改一份。
type sectionGuard func(parsed *config.Config) (extra map[string]any, status int, code, failMsg string)

// commitSectionConfig 把 newSrc 落到 path，走 providers 写回同一条安全底线：
// 先临时文件校验、再备份、再原子改名，全程失败都不碰原文件。
//
// 返回的 resp 只到「写成功」为止，调用方补自己的字段后再 writeJSON。
func (s *Server) commitSectionConfig(w http.ResponseWriter, path string, src, newSrc []byte,
	note string, undo func(), pa policyAudit, guard sectionGuard) (map[string]any, bool) {
	fail := func(status int, code, msg string) (map[string]any, bool) {
		if undo != nil {
			undo()
		}
		writeJSONError(w, status, code, msg)
		return nil, false
	}

	tmp := path + ".new"
	if err := os.WriteFile(tmp, newSrc, 0o600); err != nil {
		return fail(http.StatusInternalServerError, "internal", "写临时文件失败: "+err.Error())
	}
	// 宽松通道：允许 api_key 保留 ${ENV} 占位（与线上一致的读法）。
	parsed, err := config.LoadFileLenient(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return fail(http.StatusBadRequest, "invalid_request_error",
			"写回后的配置校验不通过，原文件未改动: "+err.Error())
	}
	var extra map[string]any
	if guard != nil {
		var status int
		var code, msg string
		extra, status, code, msg = guard(parsed)
		if msg != "" {
			_ = os.Remove(tmp)
			return fail(status, code, msg)
		}
	}
	strictErr := ""
	if _, err := config.LoadFile(tmp); err != nil {
		strictErr = err.Error()
	}

	backup, err := backupConfig(path, src)
	if err != nil {
		_ = os.Remove(tmp)
		return fail(http.StatusInternalServerError, "internal", "备份失败，已放弃写入: "+err.Error())
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fail(http.StatusInternalServerError, "internal", "写入失败: "+err.Error())
	}
	if err := os.Chmod(path, 0o600); err != nil {
		s.log.Warnf("收紧配置文件权限失败: %v", err)
	}
	s.log.Warnf("管理员通过控制台改写了配置文件（%s）：%s（配置备份 %s）", pa.action, note, filepath.Base(backup))
	// 审计与日志同一条落盘点：detail 就是那句 note（说了从哪版换到哪版、改了几条），
	// 不含密钥也不含规则条件值。actor 固定 "admin" —— 这一族端点只认 admin_token，
	// 目前不存在「哪个管理员」的身份，编一个名字比不写更糟。
	s.auditAt(pa.scope, "admin", pa.action, pa.target, note)

	resp := map[string]any{
		"written":  true,
		"applied":  s.waitForConfigApply(),
		"revision": s.cfgStore.Revision(),
		"backup":   filepath.Base(backup),
		"path":     path,
		"note":     note,
	}
	for k, v := range extra {
		resp[k] = v
	}
	if !resp["applied"].(bool) {
		resp["note"] = note + "；热加载尚未完成（最多 2 秒），稍后刷新看结果"
	}
	if strictErr != "" {
		// 文件写得进去但服务加载不了：改动不会生效，必须说破。
		resp["strict_ok"] = false
		resp["strict_error"] = strictErr
		resp["warning"] = "文件已写入，但服务加载它会失败，改动不会生效；先确认这条错误：" + strictErr
	} else {
		resp["strict_ok"] = true
	}
	if len(parsed.Warnings) > 0 {
		resp["warnings"] = parsed.Warnings
	}
	return resp, true
}

// commitPolicyConfig 落盘 policy 段，多做一步**按引用加载策略包**：
// 那是「改完真的能加载」的唯一判据（引用与内容又回到两个真值来源时当场拒写）。
//
// undo 在这里被调用：临时文件校验不过时，已经写进线上目录的内容文件必须还原，
// 否则磁盘上留下一份配置没引用的新内容 —— 下一次发布的「旧内容」就成了它。
func (s *Server) commitPolicyConfig(w http.ResponseWriter, path string, src, newSrc []byte,
	note string, undo func(), pa policyAudit) (map[string]any, bool) {
	return s.commitSectionConfig(w, path, src, newSrc, note, undo, pa, func(parsed *config.Config) (map[string]any, int, string, string) {
		set, err := parsed.Policy.LoadBundles(parsed.BundleBaseDir())
		if err != nil {
			return nil, http.StatusConflict, "bundle_mismatch",
				"配置能加载，但按引用读策略包内容失败（原文件未改动）: " + err.Error()
		}
		version := ""
		if set != nil {
			if v, err := set.PolicyVersion(); err == nil {
				version = v
			}
		}
		return map[string]any{
			"mode":                  parsed.Policy.ModeResolved().String(),
			"configured_bundles":    bundleRefViews(parsed.Policy.BundleRefs()),
			"policy_version":        version,
			"declared_bundles":      bundleRefViews(parsed.Policy.BundleRefs()),
			"policy_config_comment": "只替换了 policy 段，文件其余部分与注释保持原样",
		}, 0, "", ""
	})
}

// waitForConfigApply 等热加载轮询把新配置装进去，让界面能拿到确定答复。
func (s *Server) waitForConfigApply() bool {
	before := s.cfgStore.Revision()
	deadline := time.Now().Add(s.configApplyWait)
	for time.Now().Before(deadline) {
		if s.cfgStore.Revision() != before {
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return false
}

// ── 小工具 ─────────────────────────────────────────────────

// readJSONBodyStrict 与 readJSONBody 同一份 1MB 上限，但未知键直接拒。
//
// 为什么策略体必须严格：conditions 写成 condition、expires_at 写成 expire_at 时，
// 宽松解码会得到一条「没有期限、没有条件」的规则并把它发布出去 ——
// 而界面上回显的正是用户填的那一条。静默丢字段在策略上等于静默改判定。
func readJSONBodyStrict(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("请求体不合法（未知键、类型不符或不是 JSON）: %w", err)
	}
	return nil
}

// policyBundleDir 把 policy.bundle_dir 解析成绝对路径，基准与加载器一致：
// 配置文件所在目录。留空时按缺省目录（DefaultBundleDir）。
func policyBundleDir(cfgPath string, p config.PolicyConfig) string {
	dir := strings.TrimSpace(p.BundleDir)
	if dir == "" {
		dir = config.DefaultBundleDir
	}
	if filepath.IsAbs(dir) {
		return dir
	}
	return filepath.Join(filepath.Dir(cfgPath), dir)
}

func (s *Server) listBackups(cfgPath string, p config.PolicyConfig, id string) ([]string, error) {
	return config.ListBundleBackups(policyBundleDir(cfgPath, p), id)
}

func findBundleRef(refs []config.PolicyBundleRef, id string) *config.PolicyBundleRef {
	for i := range refs {
		if strings.TrimSpace(refs[i].ID) == id {
			return &refs[i]
		}
	}
	return nil
}

// setBundleRef 替换同 id 的那条引用，没有就追加到末尾。
func setBundleRef(refs []config.PolicyBundleRef, ref config.PolicyBundleRef) []config.PolicyBundleRef {
	out := append([]config.PolicyBundleRef(nil), refs...)
	for i := range out {
		if strings.TrimSpace(out[i].ID) == ref.ID {
			out[i] = ref
			return out
		}
	}
	return append(out, ref)
}

func removeBundleRef(refs []config.PolicyBundleRef, id string) []config.PolicyBundleRef {
	out := make([]config.PolicyBundleRef, 0, len(refs))
	for _, r := range refs {
		if strings.TrimSpace(r.ID) != id {
			out = append(out, r)
		}
	}
	return out
}

func refIDs(refs []config.PolicyBundleRef) string {
	if len(refs) == 0 {
		return "无"
	}
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		ids = append(ids, fmt.Sprintf("%s@%d", r.ID, r.Version))
	}
	return strings.Join(ids, "、")
}

func otherID(refs []config.PolicyBundleRef, id string) string {
	for _, r := range refs {
		if strings.TrimSpace(r.ID) != id {
			return r.ID
		}
	}
	return "其它包名"
}

func backupNames(entries []string) string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, filepath.Base(e))
	}
	return strings.Join(names, "、")
}

func backupVersions(entries []string) string {
	seen := map[int]bool{}
	var parts []string
	for _, e := range entries {
		b, err := config.ReadBundleFile(e)
		if err != nil || seen[b.Version] {
			continue
		}
		seen[b.Version] = true
		parts = append(parts, fmt.Sprintf("v%d", b.Version))
	}
	if len(parts) == 0 {
		return "无"
	}
	return strings.Join(parts, "、")
}
