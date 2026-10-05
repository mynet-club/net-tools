package server

// 本文件是 §2.8 证据链的**导出面**：把采集窗口开起来、把记录取出去、把窗口清空。
//
// 三条约束决定了这里的形态：
//  1. 全部端点走管理凭证，且**写侧落审计**（带范围）。采集开关决定「谁的判定被聚合成
//     一份可离线读取的文件」，那是一个需要事后查得回来的动作（§2.7 规则 2）。
//  2. 导出的是**记录本身**，不是重新算一遍：响应体直接是 replay.Encode 的产物，
//     另一个进程拿它 + 当时那套策略包就能重跑判定（docs/3.0-verification.md §7 那条缺口
//     要闭合的正是「跨进程的现场」，所以这里不许加任何包装字段 —— 包一层就多了
//     一个「界面里的记录」与「文件里的记录」两份真相）。
//  3. 缺省关闭、有界、可清空。记录里带 subject（用户名），这使它不同于 /usage 之类
//     只出聚合数的只读口：能不长期开着就不开着，取完就能清。

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/replay"
	"github.com/mynet-club/net-tools/llmproxy/internal/routing"
)

// adminReplayRoute 分发 /v1/_admin/replay[/sampling|/export|/clear]。
func (s *Server) adminReplayRoute(w http.ResponseWriter, r *http.Request, tail string) {
	tail = strings.Trim(tail, "/")
	switch {
	case tail == "":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
				"只支持 GET；改采集开关用 POST /v1/_admin/replay/sampling")
			return
		}
		s.adminReplayStatus(w)
	case tail == "sampling":
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
				"只支持 POST /v1/_admin/replay/sampling")
			return
		}
		s.adminReplaySampling(w, r)
	case tail == "export":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
				"只支持 GET /v1/_admin/replay/export")
			return
		}
		s.adminReplayExport(w, r)
	case tail == "clear":
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
				"只支持 POST /v1/_admin/replay/clear")
			return
		}
		s.adminReplayClear(w)
	default:
		writeJSONError(w, http.StatusNotFound, "invalid_request_error",
			"可用路径：/v1/_admin/replay、/v1/_admin/replay/sampling、"+
				"/v1/_admin/replay/export[?scope=kind:id]、/v1/_admin/replay/clear")
	}
}

// adminReplayStatus 报出窗口的当前配置与计数。
//
// 不含任何 subject：状态口回答「采了多少」，谁被采到是导出那份文件的事，
// 两个面的暴露程度不一样（§2.9 规则 6）。
func (s *Server) adminReplayStatus(w http.ResponseWriter) {
	cfg := s.cfgStore.Current()
	rt := s.policyFor(cfg)
	out := s.replayWin.stats()
	out["as_of"] = s.replayClock().Format("2006-01-02T15:04:05Z07:00")
	out["mode"] = orDash(cfg.Policy.ModeResolved().String())
	out["running"] = rt != nil
	if rt != nil {
		out["policy_version"] = rt.Version()
	} else {
		out["policy_version"] = ""
	}
	out["sampling_algo_declared"] = replaySamplingAlgoOnline
	out["sampling_algo_replay_default"] = replay.SamplingAlgoReplayV1
	// 逐位这件事的口径必须说清「在什么条件下成立」，只回一个 true 会比 false 更误导：
	// 窗口里既可能有 v2 带快照的新记录，也可能有导入的 v1 历史记录，
	// 后者永远只能做解释性回放。条件写在这里，界面与 CLI 都不用各自猜。
	out["bit_exact_primary_order"] = true
	out["bit_exact_algos"] = routing.BitExactAlgos()
	out["bit_exact_condition"] = fmt.Sprintf(
		"仅对 schema_version>=%d、sampling_algo=%q 且带 replay_snapshot 的选路记录成立；"+
			"v1 或无快照的记录只做解释性回放（§2.8）",
		replay.SchemaVersion, replaySamplingAlgoOnline)
	out["record_schema_version"] = replay.SchemaVersion
	out["record_schema_version_readable"] = replay.ReadableSchemaVersions()
	out["note"] = replayWiringModeNote()
	if rt != nil && rt.mode != config.PolicyModeEnforce {
		out["warning"] = fmt.Sprintf(
			"当前 mode=%s：窗口不会采集任何记录。回放证据要求判定真的作用到请求上（§3.0 线 1）", rt.mode)
	}
	if rt == nil {
		out["warning"] = "3.0 当前不参与判定（legacy 或策略包加载失败）：窗口不会采集任何记录"
	}
	writeJSON(w, http.StatusOK, out)
}

// adminReplaySampling 改采集开关。
//
// 指针语义（缺省项不动）而不是「读一份再整体写回」：调用方只想把比例调到 50‰ 时，
// 不应该被要求先 GET 一次再原样带上 scope —— 少带一个字段就静默改掉了另一个开关，
// 而这是一个决定「谁被聚合进离线文件」的开关。
func (s *Server) adminReplaySampling(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled  *bool   `json:"enabled"`
		Permille *int    `json:"sample_permille"`
		Scope    *string `json:"scope"`
		Capacity *int    `json:"capacity"`
	}
	if err := readJSONBodyStrict(w, r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	if body.Permille != nil && (*body.Permille < 0 || *body.Permille > replayPermilleFull) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			fmt.Sprintf("sample_permille 是千分率（0~%d，1000 = 全采），当前 %d", replayPermilleFull, *body.Permille))
		return
	}
	if body.Capacity != nil && (*body.Capacity < 1 || *body.Capacity > replayWindowMaxCapacity) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			fmt.Sprintf("capacity 是窗口保留的请求数（1~%d），当前 %d", replayWindowMaxCapacity, *body.Capacity))
		return
	}
	// scope 过滤要精确：范围选择器带通配时按字符串相等匹配，会一个都匹配不上而静默空采。
	// 种类不再限制（裁决 7=C）：窗口与导出都用结构化范围，org/project 命中的是
	// 当时那次判定的范围链，不是「请求范围等于它」。
	var scopeRef *policy.ScopeRef
	if body.Scope != nil {
		raw := strings.TrimSpace(*body.Scope)
		if raw == "" {
			none := policy.ScopeRef{}
			scopeRef = &none
		} else {
			ref, err := parseScopeParam(raw)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "scope: "+err.Error())
				return
			}
			scopeRef = &ref
		}
	}

	stats := s.replayWin.configure(body.Enabled, body.Permille, scopeRef, body.Capacity)
	note := fmt.Sprintf("回放记录采集开关已改：enabled=%v，sample_permille=%d，scope=%s，capacity=%d",
		stats["enabled"], stats["sample_permille"], orDashAny(stats["scope_filter"]), stats["capacity"])
	s.auditAt(policy.SystemScope, "admin", "replay.sampling.set", "replay", note)
	s.log.Warnf("管理员改写了回放采集配置：%s", note)
	stats["note"] = note + "；记录只在 enforce 且判定出版本时采集，选路记录另要求计划真的作用到请求上"
	if rt := s.policyFor(s.cfgStore.Current()); rt == nil || rt.mode != config.PolicyModeEnforce {
		stats["warning"] = "3.0 当前不在 enforce：开关已生效但不会采集到记录（切模式用 POST /v1/_admin/policy/mode）"
	}
	writeJSON(w, http.StatusOK, stats)
}

// adminReplayExport 导出窗口里的记录（replay.File 的原始 JSON 字节）。
//
// 空窗口也导出一个只含 schema_version 的合法文件，而不是 404：
// 「没有记录」与「这个端点不存在」是两件事，前者交给回放侧报「记录为空、拒绝判定」
// （replay.Report.Empty 的既有口径），比在这里造一个只有管理台才懂的错误码好。
//
// scope 接受任意种类（2026-10-04 裁决第 7 条 C）：user / organization / project / system
// 都认，命中条件是「这次判定的请求范围等于它，或当时的范围链里有它」。放开的代价要摊开说：
// 一次导出的暴露面从一个人涨到一个组织，而响应体带 subject 与规则标识 —— 这是 §2.9
// 规则 6 意义上的暴露等级变化。授权口径：管理凭证即够（裁决 14′），**若请求另带
// X-Identity-Token 则按它的范围链收窄**（同一裁决的「按范围显式授权」并入 P8，
// 见 exportScopeGuard30）；不带 token 时与放开当初逐字节相同。
func (s *Server) adminReplayExport(w http.ResponseWriter, r *http.Request) {
	var filterPtr *policy.ScopeRef
	if raw := strings.TrimSpace(r.URL.Query().Get("scope")); raw != "" {
		ref, err := parseScopeParam(raw)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "scope: "+err.Error())
			return
		}
		filterPtr = &ref
	}
	// 按范围的显式授权（裁决 14′ 并入 P8，落点就是这一段）：带了 IdP token 时，
	// 请求的精确范围必须落在它的链里，且必须点名范围。不带 token 时与今天逐字节相同。
	if !s.exportScopeGuard30(w, r, filterPtr) {
		return
	}
	var filter policy.ScopeRef
	if filterPtr != nil {
		filter = *filterPtr
	}
	f, dropped, failed := s.replayWin.file(filter)
	data, err := replay.Encode(f)
	if err != nil {
		// 编码失败意味着记录里出现了被禁字段名 —— 那是采集侧的缺陷，必须当场说破，
		// 而不是导出一份「看起来正常」的文件。
		writeJSONError(w, http.StatusInternalServerError, "internal", "记录导出失败: "+err.Error())
		return
	}
	// 过滤条件进了审计而不是只进 note：事后查「这次事故当时导过什么范围」，
	// 靠的是这一行的 target（kind:id 全串），不是某条日志文案。
	target := "replay"
	note := fmt.Sprintf("导出 %d 条判定 / %d 条选路（不过滤，窗口累计丢弃 %d，采集失败 %d）",
		len(f.Decisions), len(f.Routings), dropped, failed)
	if filter != (policy.ScopeRef{}) {
		target = filter.Display()
		note = fmt.Sprintf("导出 %d 条判定 / %d 条选路（范围 %s：请求范围等于它或当时的范围链含它；"+
			"窗口累计丢弃 %d，采集失败 %d）",
			len(f.Decisions), len(f.Routings), target, dropped, failed)
		if len(f.Decisions) == 0 {
			// 0 条要自己说破：按组织导的时候，「链里没有这个范围」和「窗口本来就是空的」
			// 是两件完全不同的事，只回一个空文件会让人去查后者。
			note += "；命中 0 条 —— 窗口里没有一条记录的请求范围或范围链是这个范围"
		}
	}
	s.auditAt(policy.SystemScope, "admin", "replay.export", target, note)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="llmproxy-replay-records.json"`)
	if _, err := w.Write(data); err != nil {
		s.log.Warnf("回放记录导出写响应失败: %v", err)
	}
}

// adminReplayClear 丢掉窗口里的记录并把计数归零。
func (s *Server) adminReplayClear(w http.ResponseWriter) {
	before := s.replayWin.stats()
	s.replayWin.clear()
	note := fmt.Sprintf("已清空回放记录窗口（清掉 %v 条判定 / %v 条选路，累计丢弃 %v、采集失败 %v）",
		before["entries"], before["routings"], before["dropped"], before["failed"])
	s.auditAt(policy.SystemScope, "admin", "replay.clear", "replay", note)
	s.log.Warnf("%s", note)
	out := s.replayWin.stats()
	out["note"] = note + "；开关与过滤条件保持不变，只有记录和计数归零"
	writeJSON(w, http.StatusOK, out)
}

// orDashAny 给 map[string]any 里的字符串值补一个「没配」显示。
func orDashAny(v any) string {
	if s, ok := v.(string); ok {
		return orDash(s)
	}
	return fmt.Sprint(v)
}
