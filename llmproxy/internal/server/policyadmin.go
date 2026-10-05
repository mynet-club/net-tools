package server

// 本文件是 §3.H 的管理口第一步：**只读**的策略可见性 —— 现在加载了什么、
// 换成 enforce 会怎么判、一次真实请求当时判成了什么样。
//
// 三条约束决定了这里的形态：
//  1. 全部端点无副作用：不写库、不改配置、不碰熔断/粘性/计量，也不进影子计数。
//     写侧（策略发布与回滚）落在配置文件与策略包目录上，是另一步，不混在这里。
//  2. 判定一律复用接线层的判定核（policyJudge + applyPolicyVerdict）。这里不拼规则、
//     不算费用、不做权限合并 —— §H 的禁止事项就是冲着「管理台自己算一套」来的：
//     界面上说「会通过」而线上拒了，这种误差会让人彻底放弃策略包。
//  3. 响应里不出现授权规则的 Conditions **值**、上游 base_url、密钥或任何正文
//     （§2.9 规则 6、§5）。规则只以选择器（subject/resource/action/effect）现身，
//     条件只列键名 —— 键名足以让人看出「这条规则要看分级」，值不需要外泄。

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/routing"
)

// adminPolicyRoute 分发 /v1/_admin/policy[/simulate|/trace|/bundles…|/active|/mode]。
//
// 读侧在本文件，写侧在 policypublish.go：两者共用同一套视图构造（bundleViews），
// 所以「界面看到的」与「发布后能读回的」不会是两副面孔。
func (s *Server) adminPolicyRoute(w http.ResponseWriter, r *http.Request, tail string) {
	switch {
	case tail == "":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
				"只支持 GET；发布请用 PUT /v1/_admin/policy/bundles/{id}")
			return
		}
		s.adminPolicyInspect(w)
	case tail == "simulate":
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 POST")
			return
		}
		s.adminPolicySimulate(w, r)
	case tail == "trace":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET")
			return
		}
		s.adminPolicyTrace(w, r)
	case tail == "active":
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
				"切换生效包只支持 POST /v1/_admin/policy/active")
			return
		}
		s.adminPolicySetActive(w, r)
	case tail == "mode":
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
				"切换接线模式只支持 POST /v1/_admin/policy/mode（含应急切回 legacy）")
			return
		}
		s.adminPolicySetMode(w, r)
	case tail == "bundles" || strings.HasPrefix(tail, "bundles/"):
		s.adminPolicyBundlesRoute(w, r, strings.TrimPrefix(tail, "bundles"))
	default:
		writeJSONError(w, http.StatusNotFound, "invalid_request_error",
			"可用路径：/v1/_admin/policy、/v1/_admin/policy/simulate、"+
				"/v1/_admin/policy/trace?request_id=、/v1/_admin/policy/bundles[/{id}[/backups|/rollback|/reference]]、"+
				"/v1/_admin/policy/active、/v1/_admin/policy/mode")
	}
}

// adminPolicyInspect 报出「3.0 现在到底在什么状态」。
//
// 为什么要把 running / inactive_reason 单独摊开：mode 写 shadow 却读不到策略包时，
// 请求路径按 legacy 静默运行（见 policyFor），此时 mode 字段仍然是 shadow ——
// 只报 mode 的管理台会说「策略在效」，而实际一条规则都没生效。健康检查那里已经把
// 版本清零，这里必须把「为什么」也说出来。
func (s *Server) adminPolicyInspect(w http.ResponseWriter) {
	cfg := s.cfgStore.Current()
	rt := s.policyFor(cfg)
	pc := &cfg.Policy

	bundleDir := strings.TrimSpace(pc.BundleDir)
	if bundleDir == "" {
		bundleDir = config.DefaultBundleDir
	}

	out := map[string]any{
		"config_schema_version": schemaVersionOf(cfg),
		"revision":              s.cfgStore.Revision(),
		"configured_mode":       orDash(pc.Mode),
		"mode":                  pc.ModeResolved().String(),
		"active_bundle":         orDash(pc.ActiveBundle),
		// 报**生效**目录而不是配置里的原值：留空时加载用的是默认目录，
		// 显示成 "-" 会让人以为策略包根本没地方读。
		"bundle_dir":         bundleDir,
		"fallback_to_legacy": pc.FallbackToLegacyEnabled(),
		"data_level":         pc.DataLevelResolved().String(),
		// 声明值与生效值分开发：legacy 下 DataLevelResolved 是 LevelUnknown（判定根本没有
		// PolicyContext，不许替它猜一级），但 config.yaml 里写的那一行仍然在那儿。
		// 只报生效值，管理台会对一个已经写好 internal 的部署说「unknown」，
		// 运维就会以为还没配。
		"declared_data_level": orDash(pc.DataLevel),
		"declared_bundles":    bundleRefViews(pc.BundleRefs()),
		"running":             rt != nil,
		"shadow":              s.metrics.shadowSnapshot(),
		// 运行态红灯（裁决 17′）：每条处理器/知识源声明到底装配起来没有。
		"assembly": s.assemblyInspect(cfg, rt),
	}
	if rt == nil {
		out["policy_version"] = ""
		out["bundles"] = []any{}
		if reason, why := s.policyInactiveReason(cfg); reason != "" {
			out["inactive_reason"] = reason
			if why != "" {
				out["load_error"] = why
			}
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	out["policy_version"] = rt.Version()
	out["routing_epoch"] = rt.epoch
	out["bundles"] = bundleViews(rt.set)
	writeJSON(w, http.StatusOK, out)
}

// assemblyStatus* 是每条声明仅有的两种装配结果。
//
// 刻意没有「部分装配」「未知」这类第三种话：这个读数的全部价值在于它来自本进程
// 真的跑过的那段装配代码，而不是对配置文件的推测。答不出来就不摆出来。
const (
	assemblyAssembled = "assembled"
	assemblyFailed    = "failed"
)

// assemblyDecl 是一条声明的装配结果。
type assemblyDecl struct {
	Name   string `json:"name"`
	Type   string `json:"type,omitempty"`
	Scope  string `json:"scope,omitempty"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// assemblySection 是一段声明（processors 或 knowledge_sources）的装配汇总。
//
// declarations 在这个修订根本没装配时**缺席**（而不是给每条都盖一个「失败」）：
// 策略运行态没建立时「为什么没跑」只有一句话，而且是段级的，
// 把它复制成 N 条声明级结论，等于让界面把「整个 3.0 没在跑」说成「这 N 条各自有毛病」。
type assemblySection struct {
	Declared     int            `json:"declared"`
	Assembled    int            `json:"assembled"`
	Failed       int            `json:"failed"`
	Declarations []assemblyDecl `json:"declarations,omitempty"`
}

// assemblyInspect 端出「这个配置修订上，每条声明到底装起来没有」。
//
// 为什么要有这个面（裁决 17′ 冲着的那个故障形态）：一条声明装配失败时，
// 装配代码只把它记在 procRuntime 上并打一行 ERROR 日志，命中它的请求要到**请求期**才拒。
// 于是运营者会看到「配置文件里有这四条、界面也列出了这四条，而正文根本没被脱敏」——
// 最省事的破法就是让这条缺口永远只在日志里。
//
// 三条边界：
//  1. **不落库**：这是运行态读数，不是历史。重启后只反映重启后的装配结果，
//     note 字段把这句写在接口上，而不是只写在面板文案里。
//  2. **不新建真值源**：全部字段取装配已经算出来的东西（procRuntime.regErrs、
//     knowledgeSource.err），一个判据都不在这里重算。写坏的 scope 之类根本进不到这里 ——
//     配置加载期就按 processor.Spec.Validate 拒掉了，能进到运行态的声明只剩
//     「形状合法但装不起来」那一种（参数文件缺失、类型没注册、委托端点建不起来）。
//  3. **不含密钥与正文**：只有声明名、类型、范围与拒因文本。
func (s *Server) assemblyInspect(cfg *config.Config, rt *policyRuntime) map[string]any {
	out := map[string]any{
		"running": rt != nil,
		"note": "运行态读数：只反映本进程当前配置修订的装配结果，不落库；重启后只反映重启之后的状态。" +
			"运行参数文件不在配置里，只补 processor_params/<声明名>.json 不会换配置修订、也就不会重装配 —— " +
			"要改一次配置或重启，这一格的读数才跟着变。",
		"processors":        procAssemblySection(cfg, rt),
		"knowledge_sources": knowledgeAssemblySection(cfg, rt),
	}
	if rt == nil {
		if reason, why := s.policyInactiveReason(cfg); reason != "" {
			out["reason"] = reason
			if why != "" {
				out["load_error"] = why
			}
		}
	}
	return out
}

// procAssemblySection 汇总 processors 段。
func procAssemblySection(cfg *config.Config, rt *policyRuntime) assemblySection {
	if rt == nil {
		return assemblySection{Declared: len(cfg.ProcessorSpecs)}
	}
	pr := rt.proc
	if pr == nil {
		return assemblySection{}
	}
	sec := assemblySection{Declared: len(pr.specs), Declarations: make([]assemblyDecl, 0, len(pr.specs))}
	for _, spec := range pr.specs {
		d := assemblyDecl{Name: spec.Name, Type: string(spec.Type), Scope: spec.Scope, Status: assemblyAssembled}
		// 拒因直接取装配当时记下的那句话：请求期据此拒绝，界面据此点名，
		// 两边是同一个字符串，不会出现「日志里一套、面板上一套」。
		if reason, bad := pr.regErrs[spec.Name]; bad {
			d.Status, d.Reason = assemblyFailed, reason
		}
		if d.Status == assemblyFailed {
			sec.Failed++
		} else {
			sec.Assembled++
		}
		sec.Declarations = append(sec.Declarations, d)
	}
	return sec
}

// knowledgeAssemblySection 汇总 knowledge_sources 段。
func knowledgeAssemblySection(cfg *config.Config, rt *policyRuntime) assemblySection {
	if rt == nil {
		return assemblySection{Declared: len(cfg.KnowledgeSources)}
	}
	kr := rt.kb
	if kr == nil {
		return assemblySection{}
	}
	sec := assemblySection{Declared: len(kr.sources), Declarations: make([]assemblyDecl, 0, len(kr.sources))}
	for _, src := range kr.sources {
		d := assemblyDecl{Name: src.name, Status: assemblyAssembled}
		if src.err != "" {
			d.Status, d.Reason = assemblyFailed, src.err
			sec.Failed++
		} else {
			sec.Assembled++
		}
		sec.Declarations = append(sec.Declarations, d)
	}
	return sec
}

// policyInactiveReason 区分「没启用 3.0」与「启用了但这一版加载失败」。
func (s *Server) policyInactiveReason(cfg *config.Config) (string, string) {
	if !cfg.Policy.UsesPolicy() {
		return "policy_mode_legacy", ""
	}
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	if s.policyBadRev != 0 && s.policyBadRev == s.cfgStore.Revision() {
		return "policy_load_failed", s.policyBadErr
	}
	return "", ""
}

// adminPolicySimulate 用当前配置跑一次判定，把结论如实端出来。
//
// 与线上请求的唯一区别是它不落到任何请求上：候选池、粘性、判定核、enforce 作用面
// 全部走同一批函数，所以「模拟通过」和「线上通过」是同一个答案。
func (s *Server) adminPolicySimulate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Scope     string `json:"scope"`
		Model     string `json:"model"`
		Path      string `json:"path"`
		SessionID string `json:"session_id"`
		RequestID string `json:"request_id"`
	}
	if err := readJSONBody(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	model := strings.TrimSpace(req.Model)
	if model == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"model 必填：要模拟的下游模型名（与客户端请求里的写法一致）")
		return
	}
	scope := strings.TrimSpace(req.Scope)
	if scope != "" && !validName(scope) {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"scope 为空表示网关自身（system 范围）；给用户模拟时要填用户名")
		return
	}
	if scope != "" && s.usersSnapshot().byName[scope] == nil {
		// 不先问一句的话，providersFor 交回空池，模拟结果是一条读不懂的「候选池为空」——
		// 而那其实是「没有这个用户」。这两种原因必须分开报。
		writeJSONError(w, http.StatusNotFound, "not_found", fmt.Sprintf("用户 %q 不存在", scope))
		return
	}

	cfg := s.cfgStore.Current()
	rt := s.policyFor(cfg)
	if rt == nil {
		reason, why := s.policyInactiveReason(cfg)
		msg := "3.0 判定链路没有在跑，模拟不出结论"
		if why != "" {
			msg += "：" + why
		}
		writeJSONError(w, http.StatusConflict, reason, msg)
		return
	}

	providers, poolHasSystem := s.providersFor(scope, model)
	path := strings.TrimSpace(req.Path)
	if path == "" {
		path = "/v1/chat/completions"
	}
	requestID := strings.TrimSpace(req.RequestID)
	if requestID == "" {
		// seed 由 (request_id, policy_version, routing_epoch) 派生（§2.8），
		// 所以这里给个唯一的 id：每次模拟的 seed 都不同，但同一次的结果可复现。
		requestID = fmt.Sprintf("simulate-%d", s.now().UnixNano())
	}
	sticky := ""
	if req.SessionID != "" && s.affinity.Enabled() {
		sticky = s.affinity.Get(scope, req.SessionID, model)
	}

	shot := s.policyJudge(rt, scope, model, requestID, path, providers, sticky, s.now())
	// enforce 作用面单独算一次：shadow 下线上请求不受影响，而运维要看的正是
	// 「明天切成 enforce 会发生什么」。这一步不写任何东西，见 applyPolicyVerdict。
	// enforce 作用面在**副本**上算：applyPolicyVerdict 会写 Note，而「这个范围没有生效的
	// 策略包」（按 scope 回滚，§3.0）这条真实结论必须原样端出来，不能被「无可用计划，
	// 回落旧路由」盖掉 —— 后者会让人去找一条根本不存在的规则。
	preview := *shot
	if shot.Version != "" {
		s.applyPolicyVerdict(rt, &preview)
	}

	chain, chainErr := policyChainFor(scope)
	// seed 只在计划真跑过时才报：§2.8 的逐位复现凭据是 (seed, 候选摘要) 一对，
	// 被策略拒掉的请求压根没有候选次序可复现。线上记录同理（forwarder 只在
	// Applied 时写）；模拟这里多报一个 seed，同一个 request_id 就会在
	// 「路由模拟」和「决策痕迹」两屏给出两个答案。
	seed := shot.Seed
	if shot.CandidatesDigest == "" {
		seed = ""
	}
	out := map[string]any{
		"request_id":   requestID,
		"scope":        scope,
		"scope_chain":  chain.Display(),
		"identity":     identitySourceOf(scope),
		"model":        model,
		"path":         path,
		"purpose":      policyPurposeFor(path),
		"mode":         rt.mode.String(),
		"policy_epoch": rt.epoch,
		"sticky":       sticky,
		"pool_system":  poolHasSystem,
		"verdict":      classifyShadowDiff(shot),
		"elapsed_ms":   shot.Elapsed.Milliseconds(),
		"decision":     decisionView(shot.Decision),
		"note":         shot.Note,
		"enforce_preview": map[string]any{
			"applied": preview.Applied,
			"blocked": preview.Blocked,
			"note":    preview.Note,
		},
		"candidates":     offerViews(shot.Candidates),
		"legacy_first":   shot.LegacyFirst,
		"plan_order":     shot.PlanOrder,
		"excluded":       excludedView(shot.Excluded),
		"routing_seed":   seed,
		"digest":         shot.CandidatesDigest,
		"policy_version": shot.Version,
	}
	if chainErr != nil {
		out["scope_chain"] = ""
	}
	if shot.PlanErr != nil {
		out["plan_error"] = shot.PlanErr.Error()
	} else {
		out["plan"] = planView(shot.Plan)
	}
	writeJSON(w, http.StatusOK, out)
}

// adminPolicyTrace 查一次真实请求当时留下的路由痕迹（§2.8 的最小可复现输入）。
//
// 这是「决策解释」里唯一诚实的一半：模拟给的是「现在会怎么判」，痕迹给的是
// 「当时判成了什么」。没有 routing_seed 的老请求只能做解释性回放，响应里必须这么说，
// 否则一个摘要会被当成可逐位复现的凭据。
func (s *Server) adminPolicyTrace(w http.ResponseWriter, r *http.Request) {
	requestID := strings.TrimSpace(r.URL.Query().Get("request_id"))
	if requestID == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"request_id 必填：/v1/_admin/policy/trace?request_id=xxx")
		return
	}
	tr, err := s.db.RoutingTraceForRequest(requestID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if tr == nil {
		writeJSONError(w, http.StatusNotFound, "not_found",
			"没有这条请求的路由痕迹：它可能早于 3.0 接线、来自未启用策略的范围，或已被裁剪")
		return
	}
	out := map[string]any{
		"request_id":        tr.RequestID,
		"scope_kind":        string(tr.Scope.Kind),
		"scope_id":          tr.Scope.ID,
		"policy_version":    tr.PolicyVersion,
		"routing_epoch":     tr.RoutingEpoch,
		"routing_seed":      tr.RoutingSeed,
		"candidates_digest": tr.CandidatesDigest,
		// 有 seed 才谈得上逐位复现（§2.8）；没 seed 时这个字段为 false，
		// 界面就不能写「可精确重放」。
		"exactly_replayable": tr.RoutingSeed != "",
	}
	if tr.RoutingSeed == "" {
		out["note"] = "这条请求没记录 routing_seed，只能做解释性回放（看当时的版本与摘要），" +
			"不能声称逐位复现同一次选择"
	}
	if tr.Scope.Kind == "" {
		// 静态 key 的请求没有范围归属（store 的既有口径：零值落 NULL，不猜一个范围）。
		// 回放仍然成立 —— 判定链就是由「没有归属」这一事实推出的 system:gateway
		// （policyChainFor），但界面不能把它当成一个缺失字段。
		out["scope_note"] = "这条请求没有范围归属（静态 key）；判定链按 system:" + policySystemScope +
			" 重建，回放输入不受影响"
	}
	writeJSON(w, http.StatusOK, out)
}

// ── 视图构造：全部只取标识与结论 ────────────────────────────

// decisionView 把一次授权判定摊开。Matched 里的 MatchedRule 本身只含选择器与档位，
// 不含 Conditions，可以原样给出。
func decisionView(d policy.Decision) map[string]any {
	matched := make([]map[string]any, 0, len(d.Matched))
	for _, m := range d.Matched {
		matched = append(matched, map[string]any{
			"subject": m.Subject, "resource": m.Resource, "action": m.Action,
			"effect": string(m.Effect), "precedence": m.Precedence.String(),
			"source": orDash(m.Source), "version": orDash(m.Version),
			"scope": orDash(m.Scope),
		})
	}
	return map[string]any{
		"allowed":        d.Allowed,
		"reason":         string(d.Reason),
		"reasons":        reasonStrings(d.Reasons),
		"matched_rules":  matched,
		"policy_version": orDash(d.PolicyVersion),
		"explain":        d.Explain(),
	}
}

// planView 摊开路由计划：候选次序 + 每家被排除的原因（决策解释的数据源）。
func planView(p policy.RoutingPlan) map[string]any {
	fallbacks := make([]map[string]any, 0, len(p.Fallbacks))
	for i, c := range p.Fallbacks {
		fallbacks = append(fallbacks, map[string]any{
			"position": i, "provider": c.Provider, "model": c.Model,
			"upstream_model": c.UpstreamModel, "executor": c.Executor,
			"weight": c.Weight, "max_data_level": c.MaxDataLevel.String(),
		})
	}
	rejections := make([]map[string]any, 0, len(p.Rejections))
	for _, rej := range p.Rejections {
		rejections = append(rejections, map[string]any{
			"provider": rej.Provider, "reason": string(rej.Reason),
		})
	}
	return map[string]any{
		"executor":        p.Executor,
		"model":           p.Model,
		"upstream_model":  p.UpstreamModel,
		"fallbacks":       fallbacks,
		"processor_chain": p.ProcessorChain,
		"max_retries":     p.MaxRetries,
		"reason_codes":    reasonStrings(p.ReasonCodes),
		"rejections":      rejections,
		"policy_version":  orDash(p.PolicyVersion),
		"routing_seed":    orDash(p.RoutingSeed),
		"expires_at":      p.ExpiresAt.Format(time.RFC3339),
		"ttl_ms":          time.Until(p.ExpiresAt).Milliseconds(),
	}
}

// offerViews 列出喂给判定核的候选池。
//
// 不含 base_url 与密钥：routing.Offer 本来就只带标识与健康度，这里如实转出去。
func offerViews(offers routing.Offers) []map[string]any {
	out := make([]map[string]any, 0, len(offers))
	for _, o := range offers {
		cooldown := ""
		if !o.CooldownUntil.IsZero() && time.Now().Before(o.CooldownUntil) {
			cooldown = o.CooldownUntil.Format(time.RFC3339)
		}
		out = append(out, map[string]any{
			"provider":        o.Candidate.Provider,
			"model":           o.Candidate.Model,
			"upstream_model":  o.Candidate.UpstreamModel,
			"tier":            o.Tier,
			"healthy":         o.Healthy,
			"cooldown_until":  cooldown,
			"weight":          o.Candidate.Weight,
			"max_data_level":  o.Candidate.MaxDataLevel.String(),
			"declared_models": o.DeclaredModels,
		})
	}
	return out
}

// excludedView 列出被策略排除的候选与原因码（provider 名 + 原因，无正文）。
func excludedView(excluded map[string]policy.Reason) []map[string]any {
	names := make([]string, 0, len(excluded))
	for name := range excluded {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]any{"provider": n, "reason": string(excluded[n])})
	}
	return out
}

// bundleViews 列出实际加载的策略包。
//
// 规则只给选择器与条件**键名**：Conditions 的值可能是某个具体项目 id 或分级上界，
// 它们参与判定，但没有必要经由一个 HTTP 端点外泄（§2.9 规则 6）。
func bundleViews(set *policy.BundleSet) []map[string]any {
	if set == nil {
		return []map[string]any{}
	}
	bundles := set.Bundles()
	out := make([]map[string]any, 0, len(bundles))
	for _, b := range bundles {
		out = append(out, bundleView(b))
	}
	return out
}

// bundleView 是单个策略包的外显形态：只给标识与规则选择器，不给条件值。
//
// 读侧（已加载的集合）与写侧（磁盘上的内容文件）共用它，这样「界面看到的」和
// 「发布后读回的」是同一副面孔 —— 而磁盘文件本来就带着 Conditions 的值，
// 少一处收敛就多一个泄露面（§2.9 规则 6）。
func bundleView(b policy.PolicyBundle) map[string]any {
	rules := make([]map[string]any, 0, len(b.Entitlements))
	for _, e := range b.Entitlements {
		rules = append(rules, map[string]any{
			"subject":        e.Subject,
			"resource":       e.Resource,
			"action":         e.Action,
			"effect":         string(e.Effect),
			"scope":          orDash(e.Scope),
			"source":         orDash(e.Source),
			"version":        orDash(e.Version),
			"condition_keys": conditionKeys(e),
			"expires_at":     absoluteTime(e.ExpiresAt),
		})
	}
	return map[string]any{
		"id": b.ID, "version": b.Version, "stamp": b.Stamp(),
		"scope_kind": string(b.Scope.Kind), "scope_id": b.Scope.ID,
		"scope": b.Scope.Display(),
		"rules": rules,
		"count": len(b.Entitlements),
	}
}

// bundleRefViews 列出配置里的包引用（还没加载的那部分也要看得见 ——
// 「配了但没生效」是推进 shadow→enforce 时最常见的一类事故）。
func bundleRefViews(refs []config.PolicyBundleRef) []map[string]any {
	out := make([]map[string]any, 0, len(refs))
	for _, r := range refs {
		out = append(out, map[string]any{
			"id": r.ID, "version": r.Version, "scope": r.Scope,
		})
	}
	return out
}

func conditionKeys(e policy.Entitlement) []string {
	if len(e.Conditions) == 0 {
		return nil
	}
	keys := make([]string, 0, len(e.Conditions))
	for k := range e.Conditions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func reasonStrings(rs []policy.Reason) []string {
	if len(rs) == 0 {
		return nil
	}
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, string(r))
	}
	return out
}

// absoluteTime 把零值时间写成空串：零值在 JSON 里是 0001-01-01，
// 界面会把它当成「早已过期」，而真实含义是「没有期限」。
func absoluteTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// identitySourceOf 报出模拟用的身份来源（与 policyIdentity 同一套判据）。
func identitySourceOf(scope string) string {
	if strings.TrimSpace(scope) == "" {
		return policySourceStatic
	}
	return policySourceUser
}

// schemaVersionOf 读配置结构版本。指针为 nil 时按缺省值回答（config 加载期已归一，
// 这里只是不把「没填」留给界面去猜）。
func schemaVersionOf(cfg *config.Config) int {
	if cfg != nil && cfg.SchemaVersion != nil {
		return *cfg.SchemaVersion
	}
	return config.SchemaVersionLegacy
}
