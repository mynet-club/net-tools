package executor

import (
	"fmt"
	"sort"
)

// ReasonCode 是本包的稳定传输失败码。
//
// # 为什么不复用 internal/policy 的 Reason 注册表
//
// 两个轴回答的是不同的问题：policy.Reason 回答「**允许吗**」——它是权限与
// 路由规划阶段的主观结论，进的是策略审计；ReasonCode 回答「**实际发生了什么**」——
// 一次物理交换的客观故障形态，进的是失败归因。混在一个注册表里的直接后果是
// 审计聚合看不出「这家最近 500 次失败」到底是「500 个人无权」还是「500 次连不上」，
// 而这两种情况的现场动作完全相反（补授权 vs 查网络）。
//
// 因此本包定义自己的**封闭**码集合（§5「所有安全决策必须返回 reason code」在
// 传输轴的落地），并且：
//   - 不 import policy 的注册表来 Valid()：两边码空间独立，互不注册；
//   - 不改 internal/policy 的任何文件（那是 A 包领地）；将来若审计侧要求
//     统一映射表，应由主线在接线层建一张显式的 code→归因映射，而不是让
//     两个包共享枚举。
//
// 字符串发布后不改（同 policy.Reason 的纪律）：新增只追加，重命名等于作废历史归因。
type ReasonCode string

const (
	// —— 输入与目标（不出网就失败，fail_closed）——

	// ReasonAttemptInvalid 表示 Attempt 字段校验未过（缺超时、缺体积上限、协议未知…）。
	// 这是接线方的构造 bug，与网络无关，重试同一份 Attempt 不会有好结果。
	ReasonAttemptInvalid ReasonCode = "executor_attempt_invalid"

	// ReasonTargetRejected 表示目标越界：非法 scheme、URL 内嵌凭证、路径含
	// 编码歧义/穿越片段。与「连不上」分开记：这是本包安全边界主动拒绝，
	// 出现即意味着有人在试图（或错配到）让网关带着密钥打非法地址。
	ReasonTargetRejected ReasonCode = "executor_target_rejected"

	// ReasonNotConfigured 表示执行器缺少工作前提（未注入 transport 等）。
	// 回落到不受出网约束的默认通道之前必须先报这个码（§8 禁止快捷路径）。
	ReasonNotConfigured ReasonCode = "executor_not_configured"

	// ReasonRequestShapeInvalid 表示请求体不满足协议形态要求：不是 JSON 对象、
	// 无法安全改写 model/stream_options。错误文本只报形态问题，不带正文。
	ReasonRequestShapeInvalid ReasonCode = "executor_request_shape_invalid"

	// —— 传输（网络事实）——

	// ReasonTimeout 表示本次交换超出 Attempt.Timeout（含响应体读取阶段）。
	ReasonTimeout ReasonCode = "executor_timeout"

	// ReasonCallerCanceled 表示调用方上下文先到期/取消（客户端断开等）。
	// 单独成码：这不是上游的错，不该计入上游失败阈值（现网 forwarder 对
	// client_gone 不重试不换家，同一理由）。
	ReasonCallerCanceled ReasonCode = "executor_caller_canceled"

	// ReasonConnectFailed 表示连接层失败（DNS、TCP、代理握手、TLS）。
	ReasonConnectFailed ReasonCode = "executor_connect_failed"

	// ReasonEgressDenied 表示出网校验在最终拨号 IP 上拒绝了目标
	// （dialer.IPCheck 命中）。与 connect_failed 分开：一个要改网络，一个要查配置。
	ReasonEgressDenied ReasonCode = "executor_egress_denied"

	// —— 响应（拿到了交换，但形态或体积不对）——

	// ReasonBodyTooLarge 表示响应体读取越过 MaxResponseBytes，流已断。
	// 半截流绝不冒充完整响应：调用方必须按失败处理（fail_closed）。
	ReasonBodyTooLarge ReasonCode = "executor_body_too_large"

	// ReasonUpstreamClientStatus 表示上游返回 4xx。上游明确说不行，
	// 但这是一次完成了的交换：StatusCode 与 Body 都照常回报。
	ReasonUpstreamClientStatus ReasonCode = "executor_upstream_client_status"

	// ReasonUpstreamServerStatus 表示上游返回 5xx（同上报但不算执行器故障；
	// 换不换家是计划层按 RoutingPlan.Attempts 决定的）。
	ReasonUpstreamServerStatus ReasonCode = "executor_upstream_server_status"

	// ReasonStreamInterrupted 表示流式交换未见正常收尾标记（SSE 的 [DONE]、
	// Ollama 的 done:true）就读到了 EOF。由接线层在消费完 Body 后用
	// Outcome.Observed().SawDone 判定并回填，本包不主动掐流。
	ReasonStreamInterrupted ReasonCode = "executor_stream_interrupted"

	// ReasonProtocolMismatch 表示响应形态与声明的协议不符（如对端返回 HTML、
	// JSON 行协议里混进非 JSON 行）。多半是中间设备插了登录页/错误页。
	ReasonProtocolMismatch ReasonCode = "executor_protocol_mismatch"

	// ReasonNoScript 表示 fake（fake.go）没有任何脚本命中这次 Attempt。
	// 「没脚本」必须显式失败而不是随机编一个响应：静默编造会让回放结论无法复现。
	ReasonNoScript ReasonCode = "executor_no_script"
)

// allReasonCodes 是封闭注册表。Valid() 以它为准，测试用它挡住自然语言或拼错的值。
var allReasonCodes = map[ReasonCode]bool{}

func init() {
	for _, r := range []ReasonCode{
		ReasonAttemptInvalid, ReasonTargetRejected, ReasonNotConfigured,
		ReasonRequestShapeInvalid, ReasonTimeout, ReasonCallerCanceled,
		ReasonConnectFailed, ReasonEgressDenied, ReasonBodyTooLarge,
		ReasonUpstreamClientStatus, ReasonUpstreamServerStatus,
		ReasonStreamInterrupted, ReasonProtocolMismatch, ReasonNoScript,
	} {
		allReasonCodes[r] = true
	}
}

// Valid 报告码是否在注册表内。空串不算有效码（「失败了但说不出为什么」不可审计）。
func (c ReasonCode) Valid() bool { return allReasonCodes[c] }

// String 便于格式化输出；未注册的码原样显示并带标记，防止在日志里伪装成已知归因。
func (c ReasonCode) String() string {
	if c == "" {
		return ""
	}
	if !c.Valid() {
		return fmt.Sprintf("executor_unregistered(%s)", string(c))
	}
	return string(c)
}

// AllReasonCodes 返回排序后的全部注册码（供文档与「码表漂移」测试使用）。
func AllReasonCodes() []ReasonCode {
	out := make([]ReasonCode, 0, len(allReasonCodes))
	for r := range allReasonCodes {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// reasonForStatus 把 HTTP 状态码折算成失败码；2xx/3xx 返回空串。
//
// 只按类分（4xx/5xx），不逐码建表：429 要不要冷却、402 要不要换家，是现网
// forwarder 里熔断策略的判断（forwarder.go :393-412），不归传输层。
// 接线层拿着 StatusCode 自己细分。
func reasonForStatus(code int) ReasonCode {
	switch {
	case code >= 400 && code < 500:
		return ReasonUpstreamClientStatus
	case code >= 500:
		return ReasonUpstreamServerStatus
	}
	return ""
}
