package server

// 请求期取证的两条审计动作（2026-10-04 决策包第 6 条，接线侧按「不为省成本牺牲可审计性」取 C）。
//
// 这一档补的是原来的不对称：管理员改了哪个开关查得回来（管理写侧早就逐条落审计），
// 而「这条请求为什么被拒（哪条规则拒的）」「凭什么这份内容能出网」在回放窗口之外
// 问不回来 —— 窗口是有界内存、缺省关闭、重启即空，被挤掉就没了（§6 现状）。
//
// 两条动作的 detail 都是**结构体编码**，不是手拼字符串。理由不是省代码，是
// 「detail 是审计表里唯一的自由文本位」：一旦允许塞进人话，一条带正文的 detail
// 就是隐私事故的入口，而那时守不住的不是纪律而是运气。字段集合 = 能进 detail 的东西。

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

const (
	auditActionPolicyDeny30  = "policy.deny"
	auditActionEgressAllow30 = "egress.allow"
)

// denyReasonsCap30 限制命中链进 detail 的条数。
//
// 不封顶的话一条被十条规则命中的请求就能写进一条比正文还长的审计行，而「大量拒绝
// 不拖垮请求路径」正是 §6 测试影响点名要保住的那一条。截断是显式字段，不是悄悄少写。
const denyReasonsCap30 = 8

// ruleBrief30 是一条命中规则的标识（选择器 + 出处），不含条件值。
//
// 条件值不经这条路外泄：策略管理口的回显同样只给选择器与键名，理由是一样的 ——
// 条件键的值可能是「哪个项目代号被禁了」这种本身就是信息的内容。
type ruleBrief30 struct {
	Subject    string `json:"subject"`
	Resource   string `json:"resource"`
	Action     string `json:"action"`
	Effect     string `json:"effect"`
	Source     string `json:"source,omitempty"`
	Version    string `json:"version,omitempty"`
	Precedence string `json:"precedence,omitempty"`
}

// denyDetail30 是 policy.deny 的 detail。
type denyDetail30 struct {
	RequestID     string       `json:"request_id"`
	Resource      string       `json:"resource"`
	Reason        string       `json:"reason"`
	Reasons       []string     `json:"reasons,omitempty"`
	ReasonsCut    bool         `json:"reasons_truncated,omitempty"`
	Winner        *ruleBrief30 `json:"winner,omitempty"`
	PolicyVersion string       `json:"policy_version"`
	Mode          string       `json:"mode"`
}

// egressDetail30 是 egress.allow 的 detail。
//
// Why 这一位决定这条为什么存在：raw_body 是「未脱敏正文被交给了一个声明的外部端点」，
// data_level 是「高于 public 的内容出网到某家上游」。缺省形态（public、无原文授权）
// 不出这一条 —— 那一半 requests 表逐条记着，重复写只是把审计表变成第二张流量表。
type egressDetail30 struct {
	RequestID string `json:"request_id"`
	// Why 是这条留痕的分类字段：raw_body 还是 data_level。
	Why string `json:"why"`
	// DataLevel 是**这次内容**被判成的档；ProviderMaxLevel 是这家上游被允许承接的上限。
	// 两个字段各说一件事，混成一个就回答不了「是内容本来就低，还是上游上限高」。
	DataLevel        string `json:"data_level"`
	Provider         string `json:"provider,omitempty"`
	ProviderMaxLevel string `json:"provider_max_data_level,omitempty"`
	Executor         string `json:"executor,omitempty"`
	Processor        string `json:"processor,omitempty"`
	// AllowRawBody 只可能是 true，因为原文授权的拒绝态没有行（缺省即未授权）。
	// 它不承担「false 也算一种结论」的职责 —— 那是 why 的职责。
	AllowRawBody  bool   `json:"allow_raw_body,omitempty"`
	GrantReason   string `json:"grant_reason,omitempty"`
	PolicyVersion string `json:"policy_version,omitempty"`
}

const (
	egressWhyRawBody    = "raw_body"
	egressWhyDataLevel  = "data_level"
	exchangeLegacyXport = "legacy-transport"
)

// errAuditTrace30 标的是「这次留痕写不进去」。它必须和「处理器链起不来」「上游坏了」
// 分得开：三者的排查方向完全不同，而缺了它的话原文授权的 fail closed 会经由
// processorHTTP 归成 processor_unavailable —— 运维去查 sidecar，真正坏的是审计库。
//
// 它不是 policy.Reason：这一位不出现在任何判定结论里（判定已经通过了，是记录环节失败），
// 所以没有理由去动 A 包那份封闭的原因码注册表。
var errAuditTrace30 = errors.New("审计留痕不可用")

// auditUnavailableMsg30 是给客户端的回话。它必须和 fail 的 error type 同名同义，
// 两处各写一份的话，改了一处就等于对外承诺了一个不存在的原因。
const auditUnavailableMsg30 = "本次请求需要的授权留痕写不进审计库，请求不予处理（这不是上游故障，查审计库）"

// auditDetail30 把结构体编成 detail 并落一条带范围的审计，**把失败交给调用方**。
//
// 与 auditAt 的分工是刻意的：管理写侧的动作已经发生了，写不进留痕不该把它改成失败
// （回滚反而更糟），所以 auditAt 只记日志；而这里两条都有调用方要按结果改变行为 ——
// 原文授权写不进留痕时必须**不出网**（锁定口径：任何降级不得绕过权限或隐私策略）。
func (s *Server) auditDetail30(scope policy.ScopeRef, actor, action, target string, detail any) error {
	if s.db == nil {
		return fmt.Errorf("%w: 审计库不可用", errAuditTrace30)
	}
	data, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("%w: 审计 detail 编码失败: %v", errAuditTrace30, err)
	}
	if err := s.db.AuditScope(scope, actor, action, target, string(data)); err != nil {
		return fmt.Errorf("%w: 审计写入失败: %v", errAuditTrace30, err)
	}
	return nil
}

// auditPolicyDeny30 给一次「策略在 enforce 下拒掉的请求」留一条按范围可导出的证据。
//
// 只在 shot.Blocked 那一处调用 —— 也就是判定真的作用到请求上的时候。影子的拒绝
// 不落这里：那次拒绝没有作用到任何请求上，落进审计等于把观察数据当成处置事实，
// 与 §2.8「影子的判定不构成回放证据」是同一条口径。
//
// 写失败只记错误日志：这条请求已经被拒了，留痕写不进去不会让它变成放行，
// 所以没有 fail closed 的对象。但错误必须点名，否则「审计表怎么是空的」又会查一天。
func (s *Server) auditPolicyDeny30(scope policy.ScopeRef, actor, requestID string, shot *policyShot) {
	detail := denyDetail30{
		RequestID:     requestID,
		Resource:      shot.resource,
		Reason:        string(shot.Decision.Reason),
		PolicyVersion: shot.Version,
		Mode:          string(shot.Mode),
	}
	if reasons := shot.Decision.Reasons; len(reasons) > 0 {
		codes := make([]string, 0, len(reasons))
		for _, r := range reasons {
			if len(codes) >= denyReasonsCap30 {
				detail.ReasonsCut = true
				break
			}
			codes = append(codes, string(r))
		}
		detail.Reasons = codes
	}
	if matched := shot.Decision.Matched; len(matched) > 0 {
		// 取第 0 条而不是最后一条：A 包把 Matched 按优先级排成「第 0 条即决定性规则」，
		// 而 DecisionRecord.Winner 用的也是 Matched[0]（record.go）。审计与回放必须
		// 指着同一条规则说「是谁拒的」，否则两份证据会在一次事故复盘里互相打脸。
		first := matched[0]
		detail.Winner = &ruleBrief30{
			Subject:    first.Subject,
			Resource:   first.Resource,
			Action:     first.Action,
			Effect:     string(first.Effect),
			Source:     first.Source,
			Version:    first.Version,
			Precedence: first.Precedence.String(),
		}
	}
	target := detail.Resource
	if target == "" {
		target = "-"
	}
	if err := s.auditDetail30(scope, actor, auditActionPolicyDeny30, target, detail); err != nil {
		s.log.Errorf("event=policy_deny_audit_failed request_id=%s err=%s", requestID, err)
	}
}

// auditEgressDataLevel30 给一次「高于 public 的内容真的出网到某家上游」留痕。
//
// 排在 transport 与委托分支之前：那是「这一发要出网」的最后确定点，而它必须在出网**之前**
// 判完 —— 出网之后再写审计，写失败就只剩道歉的余地。返回错误时调用方**照发**还是
// 拒发？这里选拒发（fail closed），与检索侧「审计落不进去就不交付结果」同形。
//
// 但它只在这条请求的授权结论非缺省时才写：public 内容出网是流量本身，
// requests 表逐条记着 provider 与结果码，再写一遍只是把审计表撑成第二张流量表。
func (s *Server) auditEgressDataLevel30(scope policy.ScopeRef, actor, requestID string, shot *policyShot,
	provider, providerMax, executor string) error {
	detail := egressDetail30{
		RequestID:        requestID,
		Why:              egressWhyDataLevel,
		DataLevel:        shot.judgeCtx.DataLevel.String(),
		PolicyVersion:    shot.Version,
		Provider:         provider,
		ProviderMaxLevel: providerMax,
		Executor:         executor,
	}
	return s.auditDetail30(scope, actor, auditActionEgressAllow30, "provider:"+provider, detail)
}

// requestAuditScope30 给请求期留痕定归属：**三条动作（拒绝、原文授权、分级出网）共用**
// 这一条规则，DB 用户落 user:<名>、静态 key 落 system:global。
//
// 为什么不跟策略包的 scope：包挂在 system:gateway 上是**判定的输入**，而 §2.7 规则 2
// 要的是「这条动作关于谁」—— 管理员查 alice 的拒绝记录时，不该还得知道这条包挂在哪个
// scope 上。为什么不跟 auth.Bucket：那个字段在遇到库里旁路写进来的坏名字时是零值，
// 而零值范围写不进审计（checkScope 直接报错）—— 于是「一个脏名字」会变成
// 「这条证据根本没有」。退到 system:global 至少留下一条带 actor 原值的记录。
func requestAuditScope30(scope string) policy.ScopeRef {
	if strings.TrimSpace(scope) == "" {
		return policy.SystemScope
	}
	ref, err := policy.NewScopeRef(policy.ScopeUser, scope)
	if err != nil {
		return policy.SystemScope
	}
	return ref
}
