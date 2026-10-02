// Package processor 是 llmproxy 3.0 的处理器运行时（工作包 E）。
//
// 职责边界见 docs/3.0-agent-playbook.md §2.6、§2.9、§3-E：这里只做**受控的**数据
// 变换 —— 注册表 + 阶段 + 超时/大小限制 + fail-open/fail-closed + 正文访问档位。
// 现网 forwarder 里的 rewriteModelBody / withIncludeUsage / usageScanner 是内联的
// 一次性代码，本包不替换它们：接线归主线/H 包，E 只提供可被接进去的运行时。
//
// 本包**不做**的事（手册 §3-E 的禁止项，落到 import 层面）：
//
//	不执行 shell、不加载任何脚本、不动态下载代码 —— 可执行体只有已注册的 Go 工厂；
//	不访问 SQLite / internal/store —— 输入输出里没有费用与计量字段；
//	不读 internal/secrets 的主密钥 —— 假名哈希用调用方注入的密钥或每次请求随机的 salt；
//	不自己造 http.Client —— sidecar 的客户端由外部注入，那才是 internal/dialer
//	  的出网校验生效的地方，本包内置默认客户端等于把出网策略绕过去。
//
// 只依赖标准库与 internal/policy（A 包已冻结的契约，只引用不修改）。
//
// 三档正文访问（§2.9）在本包是被结构性强制的，而不是靠约定：
//
//	metadata-only   —— 处理器拿到的 Input 里正文句柄不可读，Body() 直接返回错误；
//	 inspect-body   —— 可以读，但产出的新正文会被 Pipeline 判为越权；
//	transform-body —— 读与替换都允许，且受 MaxInputBytes / MaxOutputBytes / Timeout 约束。
//
// 未启用正文处理时，Pipeline 一个字节都不会去碰正文流（有专门的测试用「读即 panic
// 的 reader」证明），因此 §2.9 规则 7 的流式透传语义在接进 forwarder 后仍然成立。
package processor
