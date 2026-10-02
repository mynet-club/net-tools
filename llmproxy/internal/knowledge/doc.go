// Package knowledge 是 llmproxy 3.0 的知识权限与检索委托层（工作包 C）。
//
// 本包只做一件事：把「一次请求能触达哪些知识库、上限是哪一级数据」这件事结构化，
// 然后**把这些信息交给外部知识源，由知识源自己完成文档级鉴权并返回它判定可读的文档**。
// 网关侧永不判定单篇文档的权限（手册 §3.C 的禁止项）：
// 文档 ACL 的事实（谁在哪个部门、哪个项目里、哪份合同归档在哪个库）只在知识源那一侧完整存在，
// 网关若靠客户端传来的标签自行判定，等于把最不完整的一份数据当成权威来源。
//
// 分层职责（对应 docs/3.0-agent-playbook.md §1、§3.C）：
//
//	KnowledgeScope   一次请求可触达的知识库集合 + 分级上限（派生自 policy.ScopeChain + policy.DataLevel）
//	RequestContext   委托检索必须携带的上下文（请求 ID、主体、范围、用途、生效分级、策略版本、超时预算、结果上限）
//	DelegatedRetriever 检索委托协议：调用方交身份与范围，知识源返回它自己判定可读的文档
//	Citation         引用摘要（sha256 + 来源 ID + 分级 + 标题摘要）——任何结构都不持有文档正文
//	Filter/Resolve   网关侧硬约束兜底（不放大权限），不是替知识源判定权限
//	AuditEvent       不记录正文的检索审计
//
// 三条设计约束，改动前请先读懂：
//  1. **权限判定只有一个来源**。知识库这一级的准入走 internal/policy 的 Resolver
//     （资源 `knowledge:<id>` + 动作 `read`，见领域文档 §8）；单篇文档的准入走知识源。
//     本包的 Filter 只做「不放大权限」的兜底丢弃，见 filter.go 顶部的区别说明。
//  2. **失败一律 fail_closed**。检索超时、响应超限、协议字段缺失、知识源返回非 2xx、
//     判定依据缺失——全部按「不可读」处理（Outcome.Citations 为空），
//     绝不因为「拿不到 ACL 就按公开处理」。见 reason.go 与 resolve.go。
//  3. **正文不进任何本包结构体**。文档只以摘要形式存在（citation.go）。
//     正文只在构造摘要的一瞬作为参数出现；标题同样摘要化，因为标题经常含人名与项目代号。
//
// 本包不 import internal/config、internal/store、internal/server、internal/router：
// 那些是 2.x 的转发网关运行期结构，3.0 的知识权限层不依赖它们，接线由主线负责。
// 时钟一律显式传参（now 参数），与 policy 包保持同一口径：否则过期边界写不出确定性测试，
// 影子运行与回放也对不齐。
package knowledge
