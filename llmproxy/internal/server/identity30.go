package server

// 本文件是 §9 P8 的**外部身份运行态**：把 IdP 签发的 token 验开、取出 org/project
// 归属，并决定这次请求的范围链与身份。
//
// 边界（决策包 §0.1 第 11′–13′ 行）：
//   - 现有网关 key / 用户 token 继续管「能不能调」；外部 token 只管「属于哪些范围」；
//   - 每请求带 IdP token（请求头 X-Identity-Token），网关校验；
//   - 到期**只认 claims 自带的 `exp`**（identity 包已按此实现，这里不另加 TTL 上限）；
//   - 拿不到范围就退回 user:/system:，**不会多给权限**；
//   - 没有任何外部身份数据时行为与今天逐字节相同。
//
// 归属事实由外部权威持有，网关不复制副本（裁决 11′ C）：所以本文件没有成员关系表，
// 只有「这一枚 token 说它在哪些范围里」。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/identity"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// IdentityHeaderName 是下游携带 IdP token 的请求头。
//
// 单独起一个名字而不是复用 Authorization：前者是外部身份（属于哪些范围），
// 后者是网关自己的凭证（能不能调）。两者语义不同，混在一个头里就会出现
// 「拿外部 token 当网关 key」这种要么全拒、要么误开的形态。
const IdentityHeaderName = "X-Identity-Token"

// identityRuntime 是一份配置修订对应的外部身份运行态。
//
// 跟着 policyRuntime 一起按修订号整体替换：issuer/audience/JWKS 路径改了而旧
// provider 还在用，就会出现「配置说 A、验签按 B」的静默错配。
type identityRuntime struct {
	provider identity.Provider
	source   string
}

// newIdentityRuntime 从配置构造运行态；identity 段未启用时返回 (nil, nil)。
//
// 构造期**读一次 JWKS 文件并解析**：路径写错、文件不是合法 JWKS 属于
// 「配置引用缺文件」这一类事故，启动期就该炸（与 CheckPolicyRuntime 同口径）。
// 之后每次验签仍按 TTL 重读文件（identity.NewCachedKeys），所以轮换密钥不必重启 ——
// 构造期的这一次读只是「确认这个东西现在存在且能解析」，不是缓存。
func newIdentityRuntime(cfg *config.Config) (*identityRuntime, error) {
	ic := &cfg.Identity
	if !ic.Enabled() {
		return nil, nil
	}
	path := ic.ResolveJWKS(cfg.BundleBaseDir())
	if _, err := readJWKSFile(path); err != nil {
		return nil, err
	}
	src := identity.KeySourceFunc(func(_ context.Context) ([]identity.JWK, error) {
		return readJWKSFile(path)
	})
	cached, err := identity.NewCachedKeys(src, identity.DefaultKeysTTL)
	if err != nil {
		return nil, fmt.Errorf("identity 公钥缓存构造失败: %w", err)
	}
	algos := make([]identity.Alg, 0, len(ic.Algorithms))
	for _, a := range ic.Algorithms {
		algos = append(algos, identity.Alg(strings.TrimSpace(a)))
	}
	provider, err := identity.NewOIDCProvider(identity.OIDCConfig{
		Name:                     "oidc",
		Source:                   ic.Source,
		Issuer:                   ic.Issuer,
		Audience:                 ic.Audience,
		ExtraAudiences:           ic.ExtraAudiences,
		AllowMultiAudience:       ic.AllowMultiAudience,
		Algorithms:               algos,
		AllowSingleKeyWithoutKid: ic.AllowSingleKeyWithoutKid,
	}, cached)
	if err != nil {
		return nil, fmt.Errorf("identity 段不可用: %w", err)
	}
	return &identityRuntime{provider: provider, source: ic.Source}, nil
}

// readJWKSFile 读本机 JWKS 文件并解析成公钥集合。
//
// **只读本机文件**：出网取键要走受约束的 dialer 与出网策略，属另一个包
// （identity.KeySource 的接口注释就写明「本包不 import net/http」）。HTTP JWKS
// 是已知限制，写在文档里等需要时按 §5 的对称接口补。
func readJWKSFile(path string) ([]identity.JWK, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 identity.jwks_file（%s）失败: %w", path, err)
	}
	keys, err := identity.ParseJWKS(raw)
	if err != nil {
		return nil, fmt.Errorf("identity.jwks_file（%s）不是合法的 JWKS: %w", path, err)
	}
	return keys, nil
}

// resolve 验开一枚 token。
//
// ctx 用调用方给的：公钥来源是本机文件、不发网络请求，所以这里不需要请求 ctx 的取消；
// 但四个链构造点里有两个拿不到请求 ctx（processorCall/knowledgeFor 只有 requestID），
// 为了让绑定口径只有一份，统一由调用方传 ctx（真实请求传 context.Background()，见
// requestIdentity30）。
func (r *identityRuntime) resolve(ctx context.Context, token, requestID string) (identity.Principal, error) {
	cred, err := identity.NewCredential(identity.CredentialOIDCToken, token)
	if err != nil {
		return identity.Principal{}, err
	}
	if requestID != "" {
		cred = cred.WithRequestID(requestID)
	}
	return r.provider.Resolve(ctx, cred)
}

// requestIdentity 是一次请求定下来的范围与身份。
type requestIdentity struct {
	chain    policy.ScopeChain
	identity policy.Identity
	org      string
	project  string
	// bound 表示这枚外部 token 真的并进了链（subject 与网关认定一致）。
	bound bool
	// reason 是未绑定原因（"missing"/"invalid"/"subject_mismatch"/"static_key"；空 = 绑上或未配置）。
	reason string
	// err 仅在网关自身的范围链/身份构造不出来时非空（用户名不合法等）。
	// 外部身份的任何问题都**不**走它 —— 那些一律退回网关自身范围，不让请求失败。
	err error
}

// requestIdentity30 把这次请求的范围链与身份定下来。
//
// 输入形态与对策：
//   - 外部身份未配置（rt.idn == nil，或这次配置按 legacy 跑）：**与今天逐字节相同**，
//     直接返回 policyChainFor / policyIdentity 的结果；
//   - 带了 token、验签通过、且 token 的 subject 与网关认定的用户名一致：把 token 里的
//     org/project 并进链、身份换成 token 的身份；
//   - 其余（没带 token / 验签失败 / subject 不一致 / 静态 key 无用户归属）：退回网关自身的
//     范围与身份，把原因记进指标并留 WARN 日志。
//
// 两个不可越过的方向：
//  1. **绝不因为外部身份缺席或对不上而让请求失败**（裁决 12′：拿不到范围就退回 user:/system:）。
//  2. **绝不用别人的 token 扩散权限**：subject 必须与网关认定的 scope 相等 ——
//     这是「这枚 token 就是这个用户」的唯一凭据。少这一条，任何持有效 token 的人都能
//     把别人的组织范围挂到自己头上。
func (s *Server) requestIdentity30(rt *policyRuntime, scope, token, requestID string) requestIdentity {
	baseChain, chainErr := policyChainFor(scope)
	baseID, idErr := policyIdentity(scope)
	if chainErr != nil || idErr != nil {
		// 构造不出来时把错误原样带回：上层会把它当「范围链/身份不合法」处理
		// （沿用今天的 Note 口径）。这里不替它兜底，否则一次非法用户名会被悄悄当成有效链。
		err := chainErr
		if err == nil {
			err = idErr
		}
		return requestIdentity{err: err}
	}
	out := requestIdentity{chain: baseChain, identity: baseID}
	if rt == nil || rt.idn == nil {
		return out
	}
	token = strings.TrimSpace(token)
	if token == "" {
		out.reason = "missing"
		s.metrics.noteIdentity("unbound_no_token")
		return out
	}
	if strings.TrimSpace(scope) == "" {
		// 静态 key 没有用户归属：网关没有可比的 subject，绑定无从谈起。
		out.reason = "static_key"
		s.metrics.noteIdentity("unbound_static_key")
		return out
	}
	principal, err := rt.idn.resolve(context.Background(), token, requestID)
	if err != nil {
		out.reason = "invalid"
		s.metrics.noteIdentity("unbound_invalid")
		// 只记原因，不记 token 明文：日志泄漏凭证与「记录里带 subject」是两回事。
		s.log.Warnf("外部身份校验失败 user=%s request_id=%s: %v", scope, requestID, err)
		return out
	}
	if principal.Identity.Subject != scope {
		out.reason = "subject_mismatch"
		s.metrics.noteIdentity("unbound_subject_mismatch")
		s.log.Warnf("外部身份与网关身份不一致 user=%s subject=%s request_id=%s —— 退回网关自身范围",
			scope, principal.Identity.Subject, requestID)
		return out
	}
	merged, err := mergeScopeChains(baseChain, principal.Chain)
	if err != nil {
		out.reason = "invalid"
		s.metrics.noteIdentity("unbound_invalid")
		s.log.Warnf("外部身份范围链合并失败 user=%s request_id=%s: %v", scope, requestID, err)
		return out
	}
	out.chain = merged
	out.identity = principal.Identity
	out.org = principal.Organization
	out.project = principal.Project
	if out.project != "" && out.org == "" {
		// policy.PolicyContext.Validate 的口径：指定了 project 就必须指定 organization。
		// 外部映射没给主组织时只能丢掉主项目 —— 不能编一个组织出来，那是拿判定去猜。
		out.project = ""
	}
	out.bound = true
	s.metrics.noteIdentity("bound")
	return out
}

// mergeScopeChains 求两条链的并集（去重、稳定排序由 NewScopeChain 负责）。
//
// 为什么是并集而不是「用外部链替换」：网关链里的 user:<名> 是「谁在调」的事实，
// 外部链里的 org/project 是「属于哪些范围」的事实，两者是不同来源的真相。
// 替换会丢掉前者，而策略规则里按 subject 写的那半就会失配。
func mergeScopeChains(base, extra policy.ScopeChain) (policy.ScopeChain, error) {
	all := make([]policy.ScopeRef, 0, len(base)+len(extra))
	all = append(all, base...)
	all = append(all, extra...)
	return policy.NewScopeChain(all...)
}

// errExportIdentityUnconfigured 表示「导出请求带了 token，但网关没配外部身份可校验它」。
// 它是 fail-closed 的依据：没法证明这枚 token 允许的范围时，不能当作「没带 token」放行
// （那等于按自报约束之外的范围给数据）。
var errExportIdentityUnconfigured = errors.New("identity 段未配置，无法校验导出用的外部身份")

// exportIdentityChain30 验开一枚导出请求携带的 IdP token，返回它能证明的范围链。
//
// 与 requestIdentity30 的两点不同，都因为管理口没有「网关主体」：
//   - **不做 subject 匹配**。调用方拿的是 admin_token（不是一个用户名），网关没有可与
//     claims.subject 相比的东西；这枚 token 本身就是「我在哪些范围里」的凭据
//     （裁决 14′：按范围的显式授权）。请求路径上的那条不许省略 subject 比对，
//     因为那里的 token 是拿去**扩**一个已有主体的链；这里是**收窄**一次管理员导出，
//     方向相反，凭据的角色也就不同。
//   - 只回范围链，不回身份：这个判定的输入只有链，不给它编一个 PolicyContext。
//
// identity 段未配置或这枚配置按 legacy 跑（rt/rt.idn 为 nil）时返回
// errExportIdentityUnconfigured —— 调用方据此 fail closed，而不是退回「没带 token」。
func (s *Server) exportIdentityChain30(token, requestID string) (policy.ScopeChain, error) {
	rt := s.policyFor(s.cfgStore.Current())
	if rt == nil || rt.idn == nil {
		return nil, errExportIdentityUnconfigured
	}
	principal, err := rt.idn.resolve(context.Background(), strings.TrimSpace(token), requestID)
	if err != nil {
		return nil, err
	}
	return principal.Chain, nil
}

// exportIdentityErrText 把导出身份校验的失败归成一句可对外的原因（不含 token 原文与 claims）。
//
// 刻意不返回 err.Error()：验签库的错误文案可能带上 token 片段或 claims 值，
// 而这是回给调用方与可能进浏览器的一句 —— 归成两类就够定位（没配 / 这枚不可用）。
func exportIdentityErrText(err error) string {
	if errors.Is(err, errExportIdentityUnconfigured) {
		return "网关未配置外部身份（identity 段），无法校验这枚 token"
	}
	return "token 无效、已过期，或与本网关的 issuer/audience 不符"
}
