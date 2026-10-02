package server

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 处理器声明表与知识源委托入口的管理接口（§3.H）。
//
// 这个文件只负责三件事：读配置文件**原文**、拒绝坏输入、把合法的整段落盘并记审计。
// 判据一条都不在这里重抄 —— 每条声明由 config 层交给所属领域包校验
// （processor.Spec.Validate、knowledge 的端点与库 ID 规则）。这里再写一份判定，
// 就会出现「界面放行而装配期拒收」这种两头都对不上的错。
//
// 三条底线：
//  1. **整段提交**：改一条也要把整段发回来。配置文件里段是整体替换的，
//     做成增量写只会让「谁最后写」决定线上形态，而 diff 里看不出中间态。
//  2. **缺字段 ≠ 空段**：请求体必须带本段的键（清空请传空数组）。
//     否则一个漏带字段的请求就把整段声明删掉了 —— 而那正是最容易被点错的一次写操作。
//  3. **写之前先校验、写之前先备份**：走 commitSectionConfig 同一条通道 ——
//     临时文件宽松+严格两次试读、备份、原子改名、审计落库，
//     缺任一件都会留下「改坏了说不清」的现场。
const (
	sectionProcessors = "processors"
	sectionKnowledge  = "knowledge_sources"
)

// adminShowDeclarations 返回某一声明段的当前形态 + 取值域。
//
// 视图一律从**文件原文**构建（与 adminShowConfig 同一条理由）：加载后的 Config 里
// 有些值已被展开或清洗过，把那份发给界面会让「界面上看到的」和「磁盘上写的」分开。
func (s *Server) adminShowDeclarations(w http.ResponseWriter, section string) {
	cfg := s.cfgStore.Current()
	path := s.cfgStore.Path()
	src, err := os.ReadFile(path)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "读取配置文件失败: "+err.Error())
		return
	}
	mode := cfg.Policy.ModeResolved()
	info := map[string]any{
		"section":  section,
		"path":     path,
		"revision": s.cfgStore.Revision(),
		"mode":     mode.String(),
		// applies = 这些声明会不会真的参与请求。§3.0 规则 2 只有 enforce 允许
		// 新策略影响路由与处理器，影子与 legacy 都不碰正文。
		"applies":    mode == config.PolicyModeEnforce,
		"vocabulary": config.Vocabulary(),
		"warnings":   cfg.Warnings,
		"boundary": "这一段声明的是约束（阶段/档位/上限/失败策略/出网白名单）；" +
			"运行参数（规则表、Schema、sidecar 客户端）由部署在注册期绑定，不在这里配",
	}
	if st, statErr := os.Stat(path); statErr == nil {
		info["mtime"] = st.ModTime().Format("2006-01-02T15:04:05Z07:00")
		info["size"] = st.Size()
	}
	switch section {
	case sectionKnowledge:
		list, rawErr := config.RawKnowledgeSources(src)
		if rawErr != nil {
			// 基线读不回来时不硬失败：管理员要能看到「磁盘上那条到底哪里不对」，
			// 而不是连 GET 都 500 —— 那会让人以为服务挂了。
			info["baseline_error"] = rawErr.Error()
			list = cfg.KnowledgeSources
		}
		if list == nil {
			// 空段回成 [] 而不是 null：界面拿到 null 要额外判一次，
			// 而「没有声明」和「没这个字段」在 JSON 里本就不该分不清。
			list = []config.KnowledgeSourceDef{}
		}
		info[sectionKnowledge] = list
	default:
		list, rawErr := config.RawProcessors(src)
		if rawErr != nil {
			info["baseline_error"] = rawErr.Error()
			list = cfg.Processors
		}
		if list == nil {
			list = []config.ProcessorDef{}
		}
		info[sectionProcessors] = list
	}
	writeJSON(w, http.StatusOK, info)
}

// adminSaveDeclarations 整段写回某一声明段。
func (s *Server) adminSaveDeclarations(w http.ResponseWriter, r *http.Request, section string) {
	// 一次配置里两段各自成键；请求体只准带本端点那一段，而且必须带。
	// 带错段/漏字段都在读磁盘之前拒掉：拒绝的路径不留任何半成品。
	var req struct {
		Processors       *[]config.ProcessorDef       `json:"processors"`
		KnowledgeSources *[]config.KnowledgeSourceDef `json:"knowledge_sources"`
	}
	if err := readJSONBodyStrict(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	switch section {
	case sectionProcessors:
		if req.KnowledgeSources != nil || req.Processors == nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error", declarationBodyHint(section))
			return
		}
	case sectionKnowledge:
		if req.Processors != nil || req.KnowledgeSources == nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error", declarationBodyHint(section))
			return
		}
	default:
		writeJSONError(w, http.StatusNotFound, "invalid_request_error",
			"可用段："+sectionProcessors+"、"+sectionKnowledge)
		return
	}

	path := s.cfgStore.Path()
	src, err := os.ReadFile(path)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "读取配置文件失败: "+err.Error())
		return
	}

	// Edit* 内部就先跑领域校验（与加载期同一套判据），所以这里唯一可能的失败
	// 是声明本身不合法 —— 原文件一个字节都没动。
	var (
		newSrc []byte
		note   string
		count  int
		pa     policyAudit
	)
	if section == sectionKnowledge {
		defs := *req.KnowledgeSources
		prev, prevErr := config.RawKnowledgeSources(src)
		newSrc, err = config.EditKnowledgeSources(src, defs)
		note = knowledgeNote(len(prev), prevErr != nil, defs)
		count = len(defs)
		pa = policyAudit{action: "knowledge.config.write", scope: policy.SystemScope, target: sectionKnowledge}
	} else {
		defs := *req.Processors
		prev, prevErr := config.RawProcessors(src)
		newSrc, err = config.EditProcessors(src, defs)
		note = processorsNote(len(prev), prevErr != nil, defs)
		count = len(defs)
		pa = policyAudit{action: "processor.config.write", scope: policy.SystemScope, target: sectionProcessors}
	}
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"声明不合法，原文件未改动: "+err.Error())
		return
	}

	resp, ok := s.commitSectionConfig(w, path, src, newSrc, note, nil, pa, declarationGuard(section))
	if !ok {
		return
	}
	resp["count"] = count
	writeJSON(w, http.StatusOK, resp)
}

// declarationBodyHint 说清请求体的形状。之所以把「清空」单独点名：
// 缺键与空数组在语义上差了一整个段的声明，不能让调用方靠猜。
func declarationBodyHint(section string) string {
	return fmt.Sprintf("请求体需要且只需要 %s 字段（整段提交；清空请显式传 []，缺字段不会被当成清空）", section)
}

// declarationGuard 给这两段补上「加载之外」的答复：模式与是否生效。
//
// 为什么 mode 要回在写响应里：shadow/legacy 下这些声明不参与请求（§3.0 规则 2），
// 保存成功却不提这一层，运维会以为脱敏已经在线上跑了 —— 这是这一屏最不能有的误解。
func declarationGuard(section string) sectionGuard {
	return func(parsed *config.Config) (map[string]any, int, string, string) {
		mode := parsed.Policy.ModeResolved()
		return map[string]any{
			"section":         section,
			"mode":            mode.String(),
			"applies":         mode == config.PolicyModeEnforce,
			"section_comment": "只替换了 " + section + " 段，文件其余部分与注释保持原样",
		}, 0, "", ""
	}
}

// processorsNote 组织一条审计 detail：从几条改成几条、各自挂在哪个范围上。
//
// 刻意不写端点与阈值数值：detail 会进审计库并可能被导出，而「基线读不回来」时
// 领域错误信息里可能带着 URL（含凭证的端点正是被这条规则拒掉的），
// 把它抄进审计等于把别人写错的凭证搬进另一个持久化位置。
func processorsNote(prevCount int, prevBad bool, defs []config.ProcessorDef) string {
	items := make([]string, 0, len(defs))
	for _, d := range defs {
		items = append(items, strings.TrimSpace(d.Name)+"@"+strings.TrimSpace(d.Scope))
	}
	return declarationNote("处理器声明", prevCount, prevBad, items)
}

// knowledgeNote 同上，知识源按「名字 + 它服务的库数」表述（数量够用，端点不进审计）。
func knowledgeNote(prevCount int, prevBad bool, defs []config.KnowledgeSourceDef) string {
	items := make([]string, 0, len(defs))
	for _, d := range defs {
		items = append(items, fmt.Sprintf("%s(%d 个库)", strings.TrimSpace(d.Name), len(d.KnowledgeBases)))
	}
	return declarationNote("知识源委托入口", prevCount, prevBad, items)
}

func declarationNote(what string, prevCount int, prevBad bool, items []string) string {
	from := fmt.Sprintf("%d 条", prevCount)
	if prevBad {
		from = "一份读不回的基线"
	}
	detail := strings.Join(items, "、")
	if detail == "" {
		detail = "已清空"
	}
	return fmt.Sprintf("%s：%s → %d 条（%s）", what, from, len(items), detail)
}
