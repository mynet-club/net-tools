// Package identity 是 llmproxy 3.0 的身份适配层（工作包 B）。
//
// 职责边界（手册 §3.B）只有一句话：**证明是谁、属于哪些范围**，到此为止。
// 模型权限一律由 internal/policy 的 Resolver 决定，本包既不 import 也不调用它做判定，
// 只引用它的领域对象（Identity / ScopeRef / ScopeChain / PolicyContext）。
// 一旦在本包里写出「这个角色可以用 gpt-5」这类分支，3.0 的唯一业务规则源就碎了：
// deny 优先、跨组织隔离、策略版本回放都会失去意义。
//
// 分层：
//
//	Credential      外部凭证（原文只在内存存活，绝不进审计与错误信息）
//	Provider        身份来源抽象：OIDC（已实现）、SAML/LDAP（stub，见 §stub 说明）
//	Claims          JWT payload 的标准字段 + 全部 claim 的查找视图
//	ClaimMapper     各校 claim 命名 → Identity 字段 + 范围集合的映射表
//	Principal       一次成功解析的产物：Identity + ScopeChain + 主组织/主项目
//	AuditEvent      身份来源审计（只有主体、来源、结论、原因码、时间）
//
// 三条设计约束，改动前请先读懂：
//  1. 验签自己做（crypto/rsa + crypto/ecdsa + encoding/base64），不引入任何 JWT 库：
//     依赖链越短，供应链上出「alg:none / 算法混淆」这类实现缺陷的概率越低。
//  2. 时钟一律可注入（WithClock），求值不吃真实时间：否则 TTL 边界写不出确定性测试，
//     影子运行与回放也对不齐。
//  3. 范围层级由本包展开成完整 ScopeChain（领域文档 §5：policy 包故意不猜层级）。
//     漏展开的后果是组织级、项目级策略对个体请求永不生效。
//
// 尚未实现的部分（SAML 断言解析、LDAP 目录查询）以 ErrNotImplemented 显式失败，
// 不伪装成完成能力；映射点在 saml.go、ldap.go 的注释里逐条列出。
package identity
