package server

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// adminUsageExport：GET /v1/_admin/usage/export?scope=kind:id[&since=&until=&monthly=1]
//
// 输出 CSV（text/csv），给管理台下载或脚本拉账。金额口径与配额一致
// （store.RowCharge 冻结优先），所以导出的数能和 /usage、status 对上。
//
// scope 省略 = 全部范围，每行带着自己的归属（运营者的账单总览）；要给某个主体单出一份
// 就写精确的 kind:id。旧接口那个「裸用户名 = 用户范围」的参数随 §2.7 规则 8 删除 ——
// 同名不同种类（用户 alice / 组织 alice）在裸串下无法区分，而导出的是钱。
func (s *Server) adminUsageExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET")
		return
	}
	q := r.URL.Query()
	var scope *policy.ScopeRef
	if raw := strings.TrimSpace(q.Get("scope")); raw != "" {
		ref, err := parseScopeParam(raw)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "scope: "+err.Error())
			return
		}
		scope = &ref
	}
	if !s.exportScopeGuard30(w, r, scope) {
		return
	}
	since, err := parseExportDay(q.Get("since"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "since: "+err.Error())
		return
	}
	until, err := parseExportDay(q.Get("until"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "until: "+err.Error())
		return
	}
	monthly := q.Get("monthly") == "1" || q.Get("monthly") == "true"

	name := "usage"
	if scope != nil {
		name += "-" + scope.Display() // 只进文件名：Display 是渲染形式，不是存储键
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if monthly {
		rows, err := s.monthlyRollupRows(scope, since, until)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		s.auditUsageExport30(scope, "monthly", len(rows))
		if err := cw.Write([]string{
			"month", "scope_kind", "scope_id", "requests", "ok", "failed",
			"total_tokens", "charge", "frozen_charges",
		}); err != nil {
			return
		}
		for _, r := range rows {
			_ = cw.Write([]string{
				r.Month, string(r.Scope.Kind), r.Scope.ID,
				fmt.Sprint(r.Requests), fmt.Sprint(r.OK), fmt.Sprint(r.Failed), fmt.Sprint(r.Tokens),
				fmt.Sprintf("%.6f", r.Charge), fmt.Sprint(r.Frozen),
			})
		}
		return
	}

	rows, err := s.usageExportRows(scope, since, until)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	pricing := s.cfgStore.Current().Pricing
	now := time.Now()
	s.auditUsageExport30(scope, "daily", len(rows))
	if err := cw.Write([]string{
		"day", "scope_kind", "scope_id", "provider", "model", "upstream_model", "system_paid",
		"requests", "ok", "failed",
		"prompt_tokens", "completion_tokens", "total_tokens",
		"cache_hit_tokens", "cache_miss_tokens",
		"charge_frozen", "frozen_charges", "amount", "currency",
	}); err != nil {
		return
	}
	for _, r := range rows {
		amount := rowCharge(r.UsageRow, &pricing, now)
		_ = cw.Write([]string{
			r.Day, string(r.Scope.Kind), r.Scope.ID, r.Provider, r.Model, r.UpstreamModel,
			map[bool]string{true: "1", false: "0"}[r.SystemPaid],
			fmt.Sprint(r.Requests), fmt.Sprint(r.OK), fmt.Sprint(r.Failed),
			fmt.Sprint(r.PromptTokens), fmt.Sprint(r.CompletionTokens), fmt.Sprint(r.TotalTokens),
			fmt.Sprint(r.CacheHitTokens), fmt.Sprint(r.CacheMissTokens),
			fmt.Sprintf("%.6f", r.Charge), fmt.Sprint(r.FrozenCharges),
			fmt.Sprintf("%.6f", amount), pricing.Currency,
		})
	}
}

// usageExportRows / monthlyRollupRows 把「给了范围就只导那个范围」这一句选择收在
// 一处：调用方不需要（也不该）为「空 = 全部」再写一遍分支。
func (s *Server) usageExportRows(scope *policy.ScopeRef, since, until time.Time) ([]store.ScopeUsageRow, error) {
	if scope == nil {
		return s.db.AllScopesUsageExportRows(since, until)
	}
	return s.db.ScopeUsageExportRows(*scope, since, until)
}

func (s *Server) monthlyRollupRows(scope *policy.ScopeRef, since, until time.Time) ([]store.ScopeMonthlyRollupRow, error) {
	if scope == nil {
		return s.db.AllScopesMonthlyRollup(since, until)
	}
	return s.db.ScopeMonthlyRollup(*scope, since, until)
}

func parseExportDay(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	return time.ParseInLocation("2006-01-02", s, time.Local)
}

// exportScopeGuard30 是「按范围的显式授权」——裁决 14′ 把它并入 P8，落点就是决策包 §7
// 点名的那个位置：parseScopeParam 之后、读数据之前。两处导出（量、证据链）共用它。
//
// 语义是**只收窄、不放开**，所以它只在一件事上说话：
//   - 没带 X-Identity-Token：返回 true（管理凭证即够，今天的行为逐字节不变）；
//   - 带了：请求的精确 scope 必须落在这枚 token 的范围链里；没点名 scope（= 导全部）
//     在这条路径上等于「要链外的数据」，拒；token 校验不了（未配身份 / 无效 / 过期）也拒。
//
// 为什么不做「带了 token 就自动收窄到它的链」那种更宽的解释：那是替调用方猜它想要什么，
// 而这里没有可猜的默认 —— token 是调用方自报的约束，网关能做的是「要么照它收窄、要么不服务」。
// 把自报约束当可选项忽略，等于让一枚本该只覆盖一个组织的凭据能导出整个网关的记录，
// 与「任何降级不得绕过权限」相反。
//
// 回话只有原因类别与范围串，绝不含 token 原文、claims 或用户的其它数据。
func (s *Server) exportScopeGuard30(w http.ResponseWriter, r *http.Request, scope *policy.ScopeRef) bool {
	token := strings.TrimSpace(r.Header.Get(IdentityHeaderName))
	if token == "" {
		return true
	}
	requestID := strings.TrimSpace(r.Header.Get("X-Request-Id"))
	chain, err := s.exportIdentityChain30(token, requestID)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "export_scope_denied",
			"导出请求带了 "+IdentityHeaderName+" 但无法据此授权（"+exportIdentityErrText(err)+"）；"+
				"要么去掉该头、改用管理凭证导出，要么换一枚可校验的 token")
		return false
	}
	if scope == nil {
		writeJSONError(w, http.StatusForbidden, "export_scope_denied",
			"带 "+IdentityHeaderName+" 时必须显式指定 scope，且它要落在这枚 token 的范围链里"+
				"（不写 scope 等于导出全部范围，那超出 token 能证明的范围）")
		return false
	}
	if !chain.Includes(*scope) {
		writeJSONError(w, http.StatusForbidden, "export_scope_denied",
			fmt.Sprintf("请求的导出范围 %s 不在这枚 %s 的范围链内", scope.Display(), IdentityHeaderName))
		return false
	}
	return true
}

// auditUsageExport30 给用量导出的出口留痕。与 replay.export 同一口径：
// target 是范围全串（不过滤写 "usage"），一次 200 就一条痕。
//
// 为什么这条不能省：导出的 CSV 带金额，是「谁在什么时候导了哪个范围的账」这件事本身；
// 之前 usage.export 是唯一一个没有出口留痕的导出口（replay.export 早就有），
// 一个能被脚本批量拉账而不留痕的口，在事后追责里是一段空白。
func (s *Server) auditUsageExport30(scope *policy.ScopeRef, kind string, rows int) {
	target := "usage"
	desc := "全部范围"
	if scope != nil {
		target = scope.Display()
		desc = "范围 " + target
	}
	s.auditAt(policy.SystemScope, "admin", "usage.export", target,
		fmt.Sprintf("导出用量（%s，%s）：%d 行", kind, desc, rows))
}

// auditAt 记一条带范围的审计（密钥/令牌永不进 detail）。
//
// scope 的口径是「这条动作**关于**哪个范围」，不是「谁按下的按钮」：管理员给别人
// 建用户、改价、停用，动作的归属都在那个范围里 —— §2.7 规则 2 要的是「按范围导得出去」，
// 而 actor 那一列本来就单独记着谁。
// 无范围的 store.Audit 已随规则 8 删除，所以这里没有「忘了给范围」这条路可走。
func (s *Server) auditAt(scope policy.ScopeRef, actor, action, target, detail string) {
	if s.db == nil {
		return
	}
	if err := s.db.AuditScope(scope, actor, action, target, detail); err != nil {
		s.log.Errorf("写审计日志失败: %v", err)
	}
}

// auditUser 记一条「关于某个用户」的动作。
//
// 用户名是运行期输入，不能 panic 也不能靠 MustScope（那是给编译期常量用的）。
// 真遇到不能成形的 id（老库里留下的脏名字），记到系统范围并把原值写进 detail：
// 一条归属可疑的记录远比一条被静默丢弃的记录有用。
func (s *Server) auditUser(actor, action, user, detail string) {
	scope, err := policy.NewScopeRef(policy.ScopeUser, user)
	if err != nil {
		s.auditAt(policy.SystemScope, actor, action, user, detail+" （名字无法成为范围："+err.Error()+"）")
		return
	}
	s.auditAt(scope, actor, action, user, detail)
}

// adminAuditLog：GET /v1/_admin/audit?n=100[&scope=kind:id&scope=kind:id…]
//
// 不带 scope = 全量（网关管理员的面板）；带 scope = 只看这些范围的并集，
// 组织管理员要的是「本组织 + 名下项目」。范围一律写成 kind:id ——
// 裸用户名那种有歧义的旧形式不认（§2.7 规则 1）。
func (s *Server) adminAuditLog(w http.ResponseWriter, r *http.Request) {
	n := 100
	if v := r.URL.Query().Get("n"); v != "" {
		if x, err := strconv.Atoi(v); err == nil && x > 0 && x <= 1000 {
			n = x
		}
	}
	var list []store.ScopedAuditEntry
	var err error
	if raw := r.URL.Query()["scope"]; len(raw) > 0 {
		scopes := make([]policy.ScopeRef, 0, len(raw))
		for _, sv := range raw {
			ref, perr := parseScopeParam(sv)
			if perr != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_request_error", perr.Error())
				return
			}
			scopes = append(scopes, ref)
		}
		list, err = s.db.AuditRecentForScopes(scopes, n)
	} else {
		list, err = s.db.AuditRecentAll(n)
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": list})
}

// parseScopeParam 把一个查询参数落成一个精确范围引用。
//
// 审计面板与用量导出用的是同一份解析：两处各写一遍就会各认各的形式。
// 只认 kind:id 的精确形式：通配选择器（organization:*）在服务端没有对应索引，
// 与其静默返回半集，不如让调用方显式列出关心的范围。
func parseScopeParam(s string) (policy.ScopeRef, error) {
	sel, err := policy.ParseScopeSelector(s)
	if err != nil {
		return policy.ScopeRef{}, err
	}
	if sel.All || sel.ID == "*" {
		return policy.ScopeRef{}, fmt.Errorf(
			"scope 需要是精确的 kind:id（通配请逐个列出范围），当前是 %q", s)
	}
	return policy.NewScopeRef(sel.Kind, sel.ID)
}
