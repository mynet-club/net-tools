// Package policy 是 llmproxy 3.0 的领域模型与策略内核（工作包 A）。
//
// 这里只有领域对象和纯函数：不碰 HTTP、不碰数据库、不读配置文件、不依赖 UI，
// 也不依赖 internal/config —— 供应商、用户行这些运行期结构由各适配器转换进来。
//
// 分层职责见 docs/3.0-agent-playbook.md：
//
//	Identity      证明是谁          —— 由 internal/identity 从外部 IdP 解析产出
//	ScopeRef      属于哪个范围      —— user | organization | project | system
//	PolicyContext 一次判定的完整上下文
//	Entitlement   允许/禁止做什么   —— deny > explicit_allow > group_allow > default
//	DataLevel     数据分级          —— public < internal < confidential < restricted
//	RoutingPlan   选了哪个执行计划  —— 可序列化、可审计、可回放
//	Decision      一次安全判定      —— 必带 reason code，不接受只有自然语言的结论
//
// 三条跨包契约在本包定义，其他包只引用、不复制结构体：
//   - §2.7 scope 迁移契约：结构化 scope，禁止把 kind 与 id 拼回一个字符串当键；
//   - §2.8 确定性回放契约：DeriveRoutingSeed 的算法（抽样算法本身在 internal/routing）；
//   - §2.9 正文访问契约：BodyAccess 的三档词汇（是否授予走 Entitlement）。
package policy
