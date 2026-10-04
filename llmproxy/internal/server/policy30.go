package server

// 本文件是 §3.0 的接线层：把 3.0 的判定（policy + routing）挂到 2.x 的转发链路上，
// 按 shadow → enforce → 全量替换 三阶段推进。
//
// 三条不可越过的线（§3.0）：
//  1. shadow **只读**：不选 provider、不碰熔断/粘性/计量，只产出差异报告。
//     影子运行一旦能改线上状态，观测行为就改变了被观测对象，差异报告随即失去意义。
//  2. 只有 enforce 才允许新策略影响路由与处理器。对选路的影响面是两类 ——
//     「模型未授权直接拒绝整条请求」与「计划首选优先」，重试与熔断机制原样保留。
//     逐家排除里「分级」这一维今天已经有事实来源（providers[].max_data_level），
//     区域还没有（config.Provider 不带 region），所以接线不执行只有区域能触发的那条收窄。
//  3. policy version 一律来自实际加载的 BundleSet（按本次请求的范围链过滤后的子集版本），
//     任何 handler 都不许自己拼 —— 拼出来的版本没法回放，也没法按 scope 回滚。
//
// 落库口径：shadow 只把 policy_version 写进请求记录（§3.0 要求影子也出版本），
// routing_seed / routing_epoch / candidates_digest **不写**，因为那三个字段描述的是
// 「真正跑的计划」，而影子的计划没跑。它们进差异报告和日志，不进回放输入 —— 否则
// internal/replay 会把一次没发生的决策当成事实复现。
//
// enforce 且计划确实生效（shot.Applied）时三个字段一起写：§2.8 要求在线请求至少能
// 被逐位复现，缺了 seed 就只剩「解释性回放」，而缺了 epoch 连 seed 是从哪一代随机源
// 派生的都无从判断。三者必须成组出现，半个痕迹比没痕迹更坏 —— 它会让人以为能复现。

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/routing"
)

const (
	// policySystemScope 是静态 key（没有用户归属）请求的范围 ID。
	// 用固定字面量而不是主机名：范围 ID 是策略引用的键，主机名会变（换机器、改容器名），
	// 而「这条规则给了谁」必须是能查的。
	policySystemScope = "gateway"
	// policyExecutorOpenAI 是 2.x 转发链路的执行器名：OpenAI 兼容 HTTP 直通。
	// 计划里带执行器名是 §2.5 的要求（同一候选池将来可能混本地 vLLM 与云端兼容口）。
	policyExecutorOpenAI = "http-openai"
	// policySourceUser / policySourceStatic 进 Identity.Source，
	// 供 `source:` 条件区分「目录里的人」和「网关主人自己」。
	policySourceUser   = "llmproxy-user-token"
	policySourceStatic = "llmproxy-api-key"
	// policyPlanTTL 是计划有效期。计划必须带 ExpiresAt（§2.5），否则下游会把一次
	// 决策缓存到策略回滚之后。60 秒比会话粘性的 TTL 短：粘性负责保缓存命中，
	// 计划负责授权，授权口径变得比粘性更快时应当以授权为准。
	policyPlanTTL = 60 * time.Second
)

// policyRuntime 是一份配置修订对应的 3.0 运行态。
//
// 它按配置修订号整体替换（见 Server.policyFor），所以内部不需要「策略改了但缓存没清」
// 这类修补：resolver 缓存的生命周期就是这份配置的生命周期。
type policyRuntime struct {
	mode      config.PolicyMode
	dataLevel policy.DataLevel
	set       *policy.BundleSet
	version   string // 整集版本串（日志/健康检查用；判定用的是按范围过滤后的子集串）
	fallback  bool
	planner   *routing.Planner
	epoch     string // routing_epoch：配置每修订一次就换一代，seed 跟着变

	// proc 是本修订对应的处理器链装配态（nil = 这个配置没声明任何处理器）。
	// 挂在策略运行态上而不是单独一份缓存：声明的生效面由「mode + 范围链 + 策略版本」
	// 共同决定，两套缓存必然出现「策略改了而链没跟着重建」。
	proc *procRuntime

	// kb 是本修订对应的知识源装配态（nil = 这个配置没声明知识源）。与 proc 同一条理由：
	// 知识库准入吃的是范围链与策略版本，单独缓存必然和策略改动对不上。
	kb *knowledgeRuntime

	// exec 是本修订对应的执行器装配态（§3.F 接线，见 executor30.go）。同一条理由：
	// 「哪个执行器名算注册上了」由这份修订决定，而它跟着候选池与计划一起换，
	// 单独缓存会让「计划说用 X 执行器」与「本网关注册了什么」对不上。
	exec *executorRuntime

	mu        sync.Mutex
	resolvers map[string]*policy.Resolver // chain.Display() → 判定内核
}

// newPolicyRuntime 从配置构造运行态。返回 (nil, nil) 表示 3.0 不参与（legacy）。
//
// 策略包内容加载失败是真错误而不是警告：mode 写了 shadow/enforce 却读不到内容，
// 意味着网关会以「有策略版本」的姿态服务而实际没有任何规则生效 ——
// 那比启动失败糟得多（§2.7 的「禁止带着半迁移状态启动」是同一个道理）。
func newPolicyRuntime(cfg *config.Config, epoch string) (*policyRuntime, error) {
	pc := &cfg.Policy
	if !pc.UsesPolicy() {
		return nil, nil
	}
	set, err := pc.LoadBundles(cfg.BundleBaseDir())
	if err != nil {
		return nil, err
	}
	version, err := set.PolicyVersion()
	if err != nil {
		return nil, fmt.Errorf("已加载策略包却取不出版本串: %w", err)
	}
	return &policyRuntime{
		mode:      pc.ModeResolved(),
		dataLevel: pc.DataLevelResolved(),
		set:       set,
		version:   version,
		fallback:  pc.FallbackToLegacyEnabled(),
		planner:   routing.NewPlanner(),
		epoch:     epoch,
		resolvers: map[string]*policy.Resolver{},
	}, nil
}

// Version 返回整集版本串。
func (rt *policyRuntime) Version() string {
	if rt == nil {
		return ""
	}
	return rt.version
}

// policyFor 返回与当前配置修订对应的运行态；3.0 不参与或加载失败时返回 nil（走 legacy）。
//
// 加载失败只在第一个请求上做一次磁盘读，之后按修订号记住「这一版试过且坏了」——
// 热加载坏配置不该让每个请求都去撞一次文件系统，也不该把已经在跑的网关打挂
// （启动时的强校验在 main 里，见 checkPolicyRuntime）。
func (s *Server) policyFor(cfg *config.Config) *policyRuntime {
	if cfg == nil {
		return nil
	}
	rev := s.cfgStore.Revision()
	s.policyMu.Lock()
	defer s.policyMu.Unlock()

	if !cfg.Policy.UsesPolicy() {
		if s.policyRun != nil {
			s.log.Infof("3.0 策略链路已停用（policy.mode=legacy，修订 %d）—— 回滚完成", rev)
			// 版本清零：回滚后还报着旧版本，健康检查会把「已经不受策略管」的
			// 现网说成「策略在效」，这比缺一个字段危险得多。
			s.metrics.setPolicyVersion("")
		}
		s.policyRun, s.policyRunRev, s.policyBadRev = nil, rev, 0
		return nil
	}
	if s.policyRun != nil && s.policyRunRev == rev {
		return s.policyRun
	}
	if s.policyBadRev == rev {
		return nil
	}
	rt, err := newPolicyRuntime(cfg, fmt.Sprintf("rev-%d", rev))
	if err != nil {
		s.log.Errorf("策略包加载失败（修订 %d），本次配置按 legacy 运行且不再重试直到修订变化: %v", rev, err)
		// 这一版按 legacy 跑，报出的策略版本必须是空：留着上一版的版本号，
		// 健康检查会说「策略 vX 在效」而实际一条规则都没生效。
		s.metrics.setPolicyVersion("")
		s.policyBadRev = rev
		s.policyBadErr = err.Error()
		s.policyRun, s.policyRunRev = nil, rev
		return nil
	}
	if s.policyRun != nil && s.policyRun.mode != rt.mode {
		// 模式切换必须留痕：差异报告与审计的解释都靠「当时是什么模式」。
		s.log.Infof("3.0 接线模式切换 %s -> %s（修订 %d，策略版本 %s）",
			s.policyRun.mode, rt.mode, rev, rt.version)
	} else {
		s.log.Infof("3.0 策略链路就绪（模式 %s，修订 %d，策略版本 %s，代 %s）", rt.mode, rev, rt.version, rt.epoch)
	}
	// 知识源先装配：kb-context-inject 的正文交付器在**注册期**就要枚举得出网端点
	// （E 那道「报不出端点即拒绝注册」的门），而端点来自这一版的 knowledge_sources。
	// 反过来装配就会出现「声明写得完全正确，注册表说交付端点不可枚举」这种指错方向的错。
	// 坏端点仍然不丢掉策略运行态：原因记在源上，命中它的检索请求据此报错。
	rt.kb = s.buildKnowledgeRuntime(cfg, rt)
	// 处理器声明跟着这一版配置装配（同一修订、同一生命周期）。装配失败不丢掉运行态：
	// 策略判定仍然有效，而坏声明的错误文案要在命中它的那条请求上原样端出来。
	rt.proc = s.buildProcRuntime(cfg, rt)
	// 执行器声明表跟着同一版配置换：新修订下注册不上的执行器名必须立刻变成
	// 「拒候选」，而不是继续用旧修订那张表。
	rt.exec = s.buildExecutorRuntime()
	// 健康检查/指标要能报出「当前在效的策略版本」：运维判断差异率是不是新配置带来的，
	// 靠的就是这一眼。版本在这里取整集版本（不是子集）—— 它回答的是「加载了什么」，
	// 而请求记录里的版本回答的是「这次判定用了哪几条」。
	s.metrics.setPolicyVersion(rt.version)
	s.policyRun, s.policyRunRev, s.policyBadRev = rt, rev, 0
	s.policyBadErr = ""
	return rt
}

// CheckPolicyRuntime 在启动时验证 3.0 配置可用（main 调用；失败即拒绝启动）。
func CheckPolicyRuntime(cfg *config.Config) error {
	if !cfg.Policy.UsesPolicy() {
		return nil
	}
	rt, err := newPolicyRuntime(cfg, "rev-startup")
	if err != nil {
		return err
	}
	_ = rt
	return nil
}

// resolverFor 取（或构造）作用于这条范围链的判定内核。
//
// 版本串取自 Filter(chain) 之后的子集而不是整集：§6「RoutingPlan.PolicyVersion 与
// 审计版本必须取子集版本」。整集里有 5 个包、本次请求只被 2 个覆盖时，审计写整集
// 版本会让回放去加载与本次判定无关的规则。
func (rt *policyRuntime) resolverFor(chain policy.ScopeChain) (*policy.Resolver, string, error) {
	key := chain.Display()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if res, ok := rt.resolvers[key]; ok {
		sub, err := rt.set.Filter(chain)
		if err != nil {
			return nil, "", err
		}
		version, err := sub.PolicyVersion()
		if err != nil {
			return nil, "", err
		}
		return res, version, nil
	}
	res, err := policy.FromBundles(rt.set, chain)
	if err != nil {
		return nil, "", err
	}
	rt.resolvers[key] = res
	return res, res.Version(), nil
}

// policyShot 是一次请求的 3.0 判定结果（nil = 3.0 没参与这次请求）。
type policyShot struct {
	// Version 是作用于本次范围链的策略版本串，直接进请求记录。
	Version string
	// Mode 是当时的接线模式（差异日志与请求记录都要能看出是谁的决策）。
	Mode config.PolicyMode
	// Decision 是对 `model:<名>` + `use` 的授权判定。
	Decision policy.Decision
	// Plan 是路由计划（可能为零候选的空计划）。
	Plan policy.RoutingPlan
	// PlanErr 是计划失败的原因（no_candidate 等）。非空不代表越权，只代表没结论。
	PlanErr error
	// Primary 是计划首选 provider。
	Primary string
	// Applied 表示 enforce 下结论确实生效（把计划首选指定为 prefer）。
	Applied bool
	// Blocked 非空表示整条请求被策略拒绝，调用方要短路返回 403。
	Blocked string
	// Note 是没生效的原因（回落 legacy / 范围无包覆盖），只进日志。
	Note string
	// Excluded 是计划里被**策略类**原因排除的候选（授权、区域、分级），只进差异报告。
	// 技术性排除（能力不符、健康度、无价目）不列：旧链路自己会判，而且把
	// 「D 看不到实时熔断」的结论当成禁令会让一次抖动变成全站 502。
	// Candidates 是喂给 D 的完整候选集（含档序与健康度），**只给管理口的路由模拟用**：
	// 差异报告不列它，因为一份没跑的池子进报告就等于把「可能」写成「事实」。
	Candidates routing.Offers
	Excluded   map[string]policy.Reason
	// Seed / CandidatesDigest 进差异报告；Epoch 是 seed 的第三个派生输入，
	// 落库时三者要能凑齐，否则回放拿着 seed 却不知道用的是哪一代随机源（§2.8）。
	// 它们只在计划真正作用到本请求时才进请求记录（理由见文件头）。
	Epoch            string
	Seed             string
	CandidatesDigest string
	// LegacyFirst / PlanOrder 是两条链路的首选与次序，差异报告的数据源。
	LegacyFirst []string
	PlanOrder   []string
	Elapsed     time.Duration

	// 下面这组是 §2.8 记录导出要的**现场**：只在判定函数里赋值、只被 captureReplay 读。
	// 它们不进任何响应、不参与任何结论 —— 差异报告与 enforce 的作用面全在上面那些
	// 导出字段里。为什么要把当时已经算过的东西留在 shot 上：记录必须描述「当时」，
	// 采集时再去问一遍活的策略就已经不是当时那份结论了（范围链、身份、上下文同理）。
	chain    policy.ScopeChain
	subject  policy.Identity
	judgeCtx policy.PolicyContext
	res      *policy.Resolver
	resource string
	action   string
	judgeNow time.Time
	// replaySnapshot 是这次规划用过的完整回放输入（nil = 组不出，记录退化成解释性回放）。
	// 它是「首选顺序逐位复现」唯一凭据的那一半（另一半是 sampling_algo），
	// 也只被回放采集读：不进响应、不参与结论。
	replaySnapshot *routing.ReplayInput
}

// excludedByPolicy 报告一个排除原因是否属于「策略说了算」的那一类。
//
// 这里刻意只认**授权口径本身**能给出的原因：接线给候选的 resource 是
// `model:<下游模型名>`，同一请求的所有候选拿的是同一个判定入参，所以网关（Gate）
// 的结论对整池一致 —— 要么全放行，要么整条请求在 Decision 那一步就被拒。
// 能逐家区分开来的只有区域与数据分级（候选自带事实 vs 上下文）：分级今天已经带上
// （providers[].max_data_level，用户自配上游按最低级），区域还没有事实来源 ——
// config.Provider 没有 region 字段，所以那一条在这张表里永远不命中，
// 留着它是因为将来补上候选事实时这里不加代码也能把差异报出来。
func excludedByPolicy(r policy.Reason) bool {
	switch r {
	case policy.ReasonCandidatePolicyExcluded, policy.ReasonCandidateRegionExcluded,
		policy.ReasonCandidateLevelExcluded, policy.ReasonModelNotAllowed,
		policy.ReasonDataLevelDenied, policy.ReasonRegionDenied, policy.ReasonScopeMismatch:
		return true
	}
	return false
}

// policyEvaluate 是线上请求的入口：判定 + 决定它对这次请求的作用面 + 采集回放记录。
//
// 采集挂在这一层而不是判定核里：管理口的路由模拟（policyJudge + applyPolicyVerdict）
// 复用同一个判定核，却必须一点痕迹都不留 —— 模拟请求进了窗口，证据链里就掺进了
// 人为流量（§3.0 线 1 禁止模拟进影子计数，同一条理由）。
func (s *Server) policyEvaluate(rt *policyRuntime, scope, model, requestID, path string,
	providers []config.Provider, sticky string, now time.Time) *policyShot {
	shot := s.policyJudge(rt, scope, model, requestID, path, providers, sticky, now)
	if shot == nil {
		return nil
	}
	shot = s.finishPolicy(rt, shot)
	s.captureReplay(rt, scope, requestID, shot)
	return shot
}

// policyJudge 只跑一次 3.0 判定，不落任何统计、不改任何运行态。
//
// 拆成两层是为了让管理口的路由模拟（/v1/_admin/policy/simulate）能复用同一个判定核：
// §3.0 的线 1 要求影子只读，而模拟比影子更要「一点痕迹都不留」。如果模拟另写一份判定，
// 它就是第二个真值源 —— 界面上「会通过」而线上拒了，这种误差足以让人放弃策略包。
//
// 顺序与 §3.0 一致：范围链 → 身份 → 授权判定 → 候选集 → 计划。
// 任何一步拿不到结论都不硬失败：影子模式绝不能因为 3.0 报错而让用户的请求变差；
// enforce 下则由 fallback_to_legacy 决定回落还是拒绝（缺省回落，§3.0 要求可按 scope 回滚）。
func (s *Server) policyJudge(rt *policyRuntime, scope, model, requestID, path string,
	providers []config.Provider, sticky string, now time.Time) *policyShot {
	if rt == nil {
		return nil
	}
	started := time.Now()
	shot := &policyShot{Mode: rt.mode, Excluded: map[string]policy.Reason{}}

	chain, err := policyChainFor(scope)
	if err != nil {
		shot.Note = fmt.Sprintf("范围链不合法: %v", err)
		shot.elapsedFrom(started)
		return shot
	}
	shot.chain = chain
	shot.judgeNow = now
	shot.resource = "model:" + model
	shot.action = "use"
	res, version, err := rt.resolverFor(chain)
	if err != nil {
		// 没有任何包覆盖这条链 —— 该范围没启用 3.0，继续走旧路由（就是按 scope 回滚）。
		shot.Note = fmt.Sprintf("范围 %s 没有生效的策略包，走旧路由", chain.Display())
		shot.elapsedFrom(started)
		return shot
	}
	shot.res = res
	shot.Version = version

	id, err := policyIdentity(scope)
	if err != nil {
		shot.Note = fmt.Sprintf("身份不可构造: %v", err)
		shot.elapsedFrom(started)
		return shot
	}
	shot.subject = id
	ctx, err := policy.NewPolicyContext(id, policyPurposeFor(path), rt.dataLevel)
	if err != nil {
		shot.Note = fmt.Sprintf("策略上下文不合法: %v", err)
		shot.elapsedFrom(started)
		return shot
	}
	ctx.PolicyVersion = version
	shot.judgeCtx = ctx

	// 授权判定：deny-first。这一步在候选集之前 —— 模型本身不被授权时，
	// 「池子里有没有这家」与「能不能用这家」是两个问题，答案必须是「不能用」。
	shot.Decision = res.Evaluate(ctx, chain, shot.resource, shot.action, now)

	offers, err := s.policyOffers(scope, providers, model, now)
	if err != nil {
		shot.Note = fmt.Sprintf("候选构造失败: %v", err)
		shot.elapsedFrom(started)
		return shot
	}
	shot.LegacyFirst = s.legacyFirstTier(scope, providers, model)
	shot.Candidates = offers

	seed, err := policy.DeriveRoutingSeed(requestID, version, rt.epoch)
	if err != nil {
		shot.Note = fmt.Sprintf("seed 派生失败: %v", err)
		shot.elapsedFrom(started)
		return shot
	}
	shot.Seed = seed
	shot.Epoch = rt.epoch

	in := routing.Input{
		RequestID:   requestID,
		Offers:      offers,
		Gate:        policyGate{res: res},
		Requirement: routing.Requirement{Model: model},
		MaxRetries:  s.router.RetryLimit(),
		// 目标函数取 default（与现网同分布的固定档序），成本/延迟目标留到全量替换阶段：
		// 那要求把规则 B 的峰谷系数与币种口径整体搬进候选构造，
		// 在这里另算一份价格等于制造第二套计费规则（§5 禁止）。
		Now:  now,
		TTL:  policyPlanTTL,
		Seed: seed,
		// 粘性如实传给 D：不传的话计划永远按「新会话」算，差异报告里的
		// primary_moved 大半是假的。D 内部粘性命中时不消耗随机数（§2.8）。
		Sticky: stickyState(sticky, version),
	}
	// 处理器链如实进计划（§2.5 要求计划带它，而 D 只原样携带、不推导）。
	// 这里取的是「这条范围链上会跑什么」，与 forwarder 执行用的是同一次 pipelineFor：
	// 模拟界面里的 processor_chain 因此不是猜的，而 enforce 真跑的那条链与它一致。
	// 装配失败（perr 非空）时留空而不是编一条：计划描述的是路由，
	// 「处理器装不起来」由执行侧拒请求，影子/模拟不该把它伪装成一条链。
	if pipe, perr := rt.proc.pipelineFor(chain, version); perr == nil && pipe != nil {
		for _, spec := range pipe.Specs() {
			in.ProcessorChain = append(in.ProcessorChain, spec.Name)
		}
	}
	plan, snap, err := rt.planner.PlanWithReplay(ctx, chain, in)
	if err != nil {
		shot.PlanErr = err
	} else {
		shot.Plan = plan
		shot.Primary = plan.Fallbacks[0].Provider
		for _, c := range plan.Fallbacks {
			shot.PlanOrder = append(shot.PlanOrder, c.Provider)
		}
		if digest, derr := snap.CandidatesDigest(); derr == nil {
			shot.CandidatesDigest = digest
		}
		// 完整现场快照留在 shot 上，供 §2.8 的记录采集直接带走（裁决 2026-10-04 第 5 条 B）：
		// 它就是刚才那次规划**用过**的那份输入，采集时再问一遍活的策略得到的已经不是当时那次。
		//
		// 只带 D 自己吃得下去的那份：Validate 不通过（缺 seed、运行时事实不齐）时留 nil，
		// 记录于是退化成解释性回放 —— 宁缺毋假。写进一份自相矛盾的快照，
		// 换来的是「导出侧 500」或一条永远只能降级、却看起来证据齐全的记录。
		if snap.Validate() == nil {
			clone := snap
			shot.replaySnapshot = &clone
		}
		// 排除结论取自计划的 Rejections：那里既有网关（授权）的结论，也有区域/分级
		// 这类候选事实比对的结论，而计划的 ReasonCodes 混着技术性排除（能力、健康、
		// 无价目）。影子阶段要单独端出「策略会新拒谁」，混在一起就没法解读。
		for _, r := range plan.Rejections {
			if excludedByPolicy(r.Reason) {
				shot.Excluded[r.Provider] = r.Reason
			}
		}
	}
	shot.elapsedFrom(started)
	return shot
}

func (sh *policyShot) elapsedFrom(started time.Time) { sh.Elapsed = time.Since(started) }

// finishPolicy 决定这次判定的作用面：影子只记差异，enforce 才改路由。
func (s *Server) finishPolicy(rt *policyRuntime, shot *policyShot) *policyShot {
	if rt.mode != config.PolicyModeEnforce {
		s.recordShadowDiff(shot)
		return shot
	}
	return s.applyPolicyVerdict(rt, shot)
}

// applyPolicyVerdict 算出「如果这次判定作用到请求上会怎样」。无副作用：不写库、
// 不碰熔断/粘性/计量，也不进影子统计 —— 管理口的路由模拟靠它给出 enforce 下的结论，
// 而模拟请求一旦进影子计数，差异报告里的「一致率」就掺进了人为流量（§3.0 线 1）。
func (s *Server) applyPolicyVerdict(rt *policyRuntime, shot *policyShot) *policyShot {
	// 授权层面已经拒绝整个请求：这是策略结论，不是「3.0 算不出来」，
	// fallback_to_legacy 对它没有豁免权 —— 否则一个开关就能绕过 deny-first。
	if !shot.Decision.Allowed && shot.Version != "" {
		shot.Blocked = shot.Decision.Explain()
		return shot
	}
	if shot.PlanErr != nil || shot.Primary == "" {
		if rt.fallback {
			shot.Note = fmt.Sprintf("3.0 无可用计划，回落旧路由: %v", shot.PlanErr)
			return shot
		}
		shot.Blocked = fmt.Sprintf("策略 %s 下没有可用候选: %v", shot.Version, shot.PlanErr)
		return shot
	}
	shot.Applied = true
	return shot
}

// policyChainFor 把 2.x 的路由作用域翻译成范围链。
//
// 静态 key（scope 为空）归 system 范围：网关主人自己的流量不该被"user:空串"
// 这种假身份命中用户级规则。
func policyChainFor(scope string) (policy.ScopeChain, error) {
	if strings.TrimSpace(scope) == "" {
		return policy.NewScopeChain(policy.MustScope(policy.ScopeSystem, policySystemScope))
	}
	return policy.UserChain(scope)
}

// policyIdentity 构造本次请求的身份。用户名必须是稳定 ID（§2.1），
// 邮箱形态的用户名会在这里被拒 —— 那是数据问题，必须在判定前显式失败，
// 不能悄悄换个「看起来能用」的键，让历史授权跟着走偏。
func policyIdentity(scope string) (policy.Identity, error) {
	if strings.TrimSpace(scope) == "" {
		return policy.NewIdentity(policySystemScope, policySourceStatic)
	}
	return policy.NewIdentity(scope, policySourceUser)
}

// policyPurposeFor 从请求路径推出用途。
//
// 用可观测事实而不是配置里的常量：用途参与 deny 条件（问答与批量作业的费用与
// 合规口径完全不同），把它做成全局常量会让所有 purpose 条件都失配。
// 取值集合固定为 chat / embedding / inference（新路径要在此追加并进策略文档）。
//
// 知识检索委托不走这里：它的用途是 knowledge-search（见 knowledge30.go 的 kbPurpose）。
// 模型调用与检索的费用口径、正文处理规则都不一样，两边共用一个值的话，
// 按 purpose 写的 deny 条件会在其中一侧静默失配。
func policyPurposeFor(path string) string {
	switch {
	case strings.Contains(path, "embeddings"):
		return "embedding"
	case strings.Contains(path, "completions"), strings.Contains(path, "messages"),
		strings.Contains(path, "responses"), strings.Contains(path, "generate"):
		return "chat"
	default:
		return "inference"
	}
}

// policyGate 用判定内核回答 D 的「这次能不能用这家」。
//
// D 刻意不自带权限规则（§3.D），映射词汇（资源=model:<名>、动作=use）归接线方；
// 结论必须对同一入参稳定，所以这里不读时钟、不查库。
type policyGate struct{ res *policy.Resolver }

func (g policyGate) Allows(ctx policy.PolicyContext, chain policy.ScopeChain,
	offer routing.Offer, now time.Time) (bool, policy.Reason) {
	d := g.res.Evaluate(ctx, chain, "model:"+offer.Candidate.Model, "use", now)
	if d.Allowed {
		return true, ""
	}
	return false, d.Reason
}

// policyOffers 把 2.x 的候选池翻译成 D 的 Offers，档序与旧链路逐格对齐。
//
// 档序是接线方的规则（routing 包明确「档序不归 D」），这里直接读 router.PlanFor ——
// 它和真实选路共用同一份 bucketize/priorityTiers 分类，抄一份档序表就会出现
// 「影子算的次序和线上走的次序不是一回事」这种根本没法解读的差异报告。
func (s *Server) policyOffers(scope string, providers []config.Provider, model string, now time.Time) (routing.Offers, error) {
	tiers := s.router.PlanFor(userBucket(scope), providers, model)
	byName := make(map[string]providerFacts, len(providers))
	for i := range providers {
		p := &providers[i]
		up, ok := p.UpstreamModel(model)
		if !ok {
			continue
		}
		byName[p.Name] = providerFacts{upstream: up, weight: p.Weight,
			declared: p.Declares(model), maxLevel: p.DataLevelCeiling()}
	}
	states := s.router.SnapshotFor(userBucket(scope))

	seen := map[string]bool{}
	offers := make(routing.Offers, 0, len(providers))
	for tier, group := range tiers {
		for _, e := range group.Providers {
			if seen[e.Name] {
				// 同一家在多个档都出现时只留第一格：D 要求 provider 唯一
				// （policy.RoutingPlan.Validate 直接拒绝重复候选），而旧链路的档序
				// 本来就是「取第一个可用档」，不会因为少一份副本而改变结论。
				continue
			}
			seen[e.Name] = true
			facts := byName[e.Name]
			declared := facts.declared
			var cooldown time.Time
			if st, ok := states[e.Name]; ok {
				cooldown = st.UnhealthyUntil
			}
			offers = append(offers, routing.Offer{
				Candidate: policy.RouteCandidate{
					Executor:      policyExecutorOpenAI,
					Provider:      e.Name,
					Model:         model,
					UpstreamModel: facts.upstream,
					Weight:        facts.weight,
					// 分级上限来自供应商声明；用户自配上游没有声明，按最低级处理
					// （config.Provider.DataLevelCeiling）。未声明不能留零值：
					// policy.RouteCandidate.Validate 会直接拒掉整池，
					// 那会让每次判定都变成「候选构造失败」而不是一条能解读的差异。
					MaxDataLevel: facts.maxLevel,
				},
				Tier:           tier,
				Healthy:        e.Healthy,
				CooldownUntil:  cooldown,
				DeclaredModels: declaredModels(model, declared),
			})
		}
	}
	if len(offers) == 0 {
		return nil, fmt.Errorf("候选池为空（模型 %q 没有任何启用的上游承接）", model)
	}
	return offers, nil
}

type providerFacts struct {
	upstream string
	weight   float64
	declared bool
	maxLevel policy.DataLevel
}

// declaredModels 给 D 的声明集。D 用「声明了这个名字或通配」判承接，
// 而旧链路的点名/通配已经体现在档序里，这里只需如实报出这一家对外的声明。
func declaredModels(model string, declared bool) []string {
	if declared {
		return []string{model}
	}
	return []string{"*"}
}

// stickyState 把 2.x 的粘性结论（一个 provider 名）如实包成 D 的粘性输入。
//
// 名字为空时返回 nil 而不是「Provider 为空串的结构」：显式 nil 让「这次没有粘性」
// 在代码里只有一种写法。PolicyVersion 带上本次的子集版本，粘性跨策略版本时能被解释（§2.8）。
func stickyState(provider, version string) *routing.StickyState {
	if provider == "" {
		return nil
	}
	return &routing.StickyState{Provider: provider, PolicyVersion: version}
}

// routingPrefer 决定这次请求带给旧选路的偏好，次序是粘性 → 比价 → 3.0 计划首选。
//
// 计划为什么排在比价**之后**（这与「3.0 的计划是最终决策」的直觉相反）：
// 接线给 D 的目标函数是 default（档序 + 权重随机），它不带任何成本事实，
// 而规则 B 看的是当前在效价目（含峰谷系数与币种折算）。让一个信息更少的结论
// 盖掉信息更多的结论，等于把 mode: enforce 变成一个**涨价开关** ——
// 那不是「3.0 权威」，是回归。
//
// 所以 enforce 今天在选路上的作用面是：把没有任何偏好的新会话交给计划。
// 等价目事实（region / max_data_level / 单价）进了候选构造，目标函数换成
// cheapest 或 cost-aware 之后，这个次序要反过来 —— 那时计划才是唯一决策源。
// 差异报告（shadow 阶段的一致率与 primary_moved）就是用来观察这件事的。
func (s *Server) routingPrefer(scope, model, affinityPrefer string, shot *policyShot,
	providers []config.Provider) string {
	if affinityPrefer != "" {
		return affinityPrefer
	}
	if cheap := s.cheapestProvider(scope, providers, model); cheap != "" {
		return cheap
	}
	if shot != nil && shot.Applied && providerNamed(providers, shot.Primary) {
		return shot.Primary
	}
	return ""
}

// providerNamed 报告池子里有没有这一家（enforce 指定首选前的存在性检查）。
//
// 把不在池里的名字设成 prefer，旧链路的选路逻辑会静默地「谁都不优先」，
// 于是比价与权重随机都被丢掉 —— 与其错得安静，不如按没结论处理。
func providerNamed(providers []config.Provider, name string) bool {
	if name == "" {
		return false
	}
	for _, p := range providers {
		if p.Name == name {
			return true
		}
	}
	return false
}

// withoutPolicyExcluded 去掉被**策略**排除的候选，返回新切片与被去掉的条数。
//
// 必须返回新切片而不是就地过滤：providers 是 providersFor 交出来的池子，调用方随后
// 还要拿它算配额、比价和实际选路；就地收窄会让一次判定泄漏进别的判定，
// 而「同一份池子在不同判定下成员不同」正是差异报告没法解读的头号来源。
//
// 只收策略类原因（见 excludedByPolicy）：能力不符、健康度、无价目这些技术性排除
// 旧链路自己会判，而 D 看不到实时熔断状态 —— 把「这一刻不健康」当成禁令，
// 一次上游抖动就会被执行成整站 502。
func withoutPolicyExcluded(providers []config.Provider, excluded map[string]policy.Reason) ([]config.Provider, int) {
	if len(excluded) == 0 {
		return providers, 0
	}
	out := make([]config.Provider, 0, len(providers))
	dropped := 0
	for _, p := range providers {
		if _, bad := excluded[p.Name]; bad {
			dropped++
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		// 全被排除时不动池子：这属于「3.0 给不出可用计划」，由 fallback_to_legacy
		// 或 Blocked 处理，而不是在这里把回滚开关变成一把能关掉所有上游的刀。
		return providers, 0
	}
	return out, dropped
}

// namesOf 列出池子里的供应商名（日志用，只含标识，不含 base_url 与密钥）。
func namesOf(providers []config.Provider) string {
	out := make([]string, 0, len(providers))
	for _, p := range providers {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// legacyFirstTier 返回旧链路第一档的成员（差异报告的「线上本来会先用谁」）。
//
// 档内按权重随机，所以首选是**一组**而不是一个 —— 拿单个随机结果去比会天天「不一致」。
func (s *Server) legacyFirstTier(scope string, providers []config.Provider, model string) []string {
	for _, group := range s.router.PlanFor(userBucket(scope), providers, model) {
		if len(group.Providers) == 0 {
			continue
		}
		out := make([]string, 0, len(group.Providers))
		for _, e := range group.Providers {
			out = append(out, e.Name)
		}
		sort.Strings(out)
		return out
	}
	return nil
}

// shadowVerdict 是差异的分类名（进日志与计数，取值集合固定）。
const (
	shadowAgreed         = "agreed"
	shadowPrimaryMoved   = "primary_moved"
	shadowPolicyDenied   = "policy_denied"
	shadowNoCandidate    = "no_candidate"
	shadowNotEvaluated   = "not_evaluated"
	shadowDecisionDenied = "decision_denied"
)

// classifyShadowDiff 给一次影子判定归类。
func classifyShadowDiff(shot *policyShot) string {
	switch {
	case shot.Note != "" && shot.Version == "":
		return shadowNotEvaluated
	case shot.Decision.PolicyVersion == "" && !shot.Decision.Allowed:
		// 判定本身没出版本：上下文或身份不合法，差异报告不该把它当成「策略会拒绝」。
		return shadowNotEvaluated
	case !shot.Decision.Allowed:
		return shadowDecisionDenied
	case shot.PlanErr != nil:
		return shadowNoCandidate
	case len(shot.Excluded) > 0:
		return shadowPolicyDenied
	case !containsName(shot.LegacyFirst, shot.Primary):
		return shadowPrimaryMoved
	default:
		return shadowAgreed
	}
}

// recordShadowDiff 把一次影子判定落成一行结构化日志 + 一组计数。
//
// 只写标识与结论，绝不写正文、模型参数或用户内容（§2.9 规则 6）。
func (s *Server) recordShadowDiff(shot *policyShot) {
	kind := classifyShadowDiff(shot)
	s.metrics.observeShadow(kind, shot.Elapsed)
	if kind == shadowAgreed {
		// 一致路径不写日志：影子阶段的目标是攒「一致率」，把每条请求都写一行
		// 会让差异信号淹在日志海里。
		return
	}
	fields := []string{
		"event=policy_shadow",
		"verdict=" + kind,
		"policy_version=" + orDash(shot.Version),
		"primary=" + orDash(shot.Primary),
		"legacy_first=" + strings.Join(shot.LegacyFirst, ","),
		"plan_order=" + strings.Join(shot.PlanOrder, ","),
		fmt.Sprintf("elapsed_ms=%d", shot.Elapsed.Milliseconds()),
	}
	if len(shot.Excluded) > 0 {
		fields = append(fields,
			fmt.Sprintf("excluded=%d", len(shot.Excluded)),
			"excluded_detail="+describeExcluded(shot.Excluded))
	}
	if shot.Note != "" {
		fields = append(fields, "note="+shot.Note)
	}
	if shot.PlanErr != nil {
		fields = append(fields, "plan_err="+shot.PlanErr.Error())
	}
	s.log.Warnf("%s", strings.Join(fields, " "))
}

// describeExcluded 展开被策略排除的候选（provider 名 + 原因码，不含任何正文）。
func describeExcluded(excluded map[string]policy.Reason) string {
	names := make([]string, 0, len(excluded))
	for name := range excluded {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s:%s", n, excluded[n]))
	}
	return strings.Join(parts, ",")
}

func containsName(list []string, v string) bool {
	if v == "" {
		return false
	}
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
