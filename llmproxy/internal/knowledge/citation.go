package knowledge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// DigestAlgorithm 是摘要算法的固定取值，写进引用结构而不是靠约定。
//
// 为什么带上算法名：摘要本身没有自描述能力。哪天要迁到更强的哈希（或知识源侧
// 用了别的算法），不带算法名的历史审计就再也分不清是哪套算法算的，
// 「同一文档的两次引用是不是同一个」这个基本问题就无法回答。
const DigestAlgorithm = "sha256"

// digestHexLen 是 sha256 的十六进制长度。
const digestHexLen = sha256.Size * 2

// shortDigestLen 是展示用截断摘要的十六进制长度（48 bit）。
const shortDigestLen = 12

// titleDigestDomain 是标题摘要的域分隔前缀。
//
// 标题长度短、词汇可枚举（「Q3 预算评审」「张三离职面谈记录」），
// 直接 sha256(title) 可以被字典攻击离线还原出标题明文。加域前缀只挡住
// 「跨系统复用同一份彩虹表」这一条路，**不能**当成加密手段，所以：
//   - 展示一律走 ShortTitle()（截断到 48 bit，字典命中后也无法确认）；
//   - 需要精确等值关联（同一文档的两次引用）时才用完整 TitleDigest；
//   - 标题明文永不出网关：知识源侧就摘要化（见 docs/3.0-knowledge-delegation.md §6「引用摘要 Citation」）。
const titleDigestDomain = "llmproxy-kb-title-v1"

// queryDigestDomain 是检索词摘要的域分隔前缀。
//
// 检索词与标题是同一类风险面：用户会搜「张三 绩效」这种低熵短语。更要紧的是
// 口径必须与标题一致 —— 一个裸 sha256、一个带域前缀，跨字段撞库时反而看不出哪个
// 摘要对应哪种输入，审计里同一串明文在 query 位和 title 位会产出两个可辨认的形态。
const queryDigestDomain = "llmproxy-kb-query-v1"

// domainDigest 产出「域前缀 + 内容」的长度前缀摘要。
//
// 长度前缀不是冗余：没有它，域 "llmproxy-kb-" + 内容 "query-v1abc" 与
// 域 "llmproxy-kb-query" + 内容 "-v1abc" 会喂进哈希器同样的字节流。
func domainDigest(domain, normalized string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d:%s;%d:%s;", len(domain), domain, len(normalized), normalized)
	return hex.EncodeToString(h.Sum(nil))
}

// Digest 返回入参的 sha256 摘要（小写十六进制，64 位）。
//
// content 参数是**唯一**允许文档正文出现的地方，而且只在这一次调用的栈上存活：
// 返回值只是摘要，本包任何结构体与字段都不保存它，也不保存切片视图。
// 如果不这么做——比如把正文留在 Citation 里「方便后面拼提示词」——
// 正文就会顺着 JSON 进审计表、进错误日志、进管理台响应，
// 手册 §2.9「正文不落库、不进普通日志」的默认前提当场就破了。
func Digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// DigestString 是 Digest 的字符串便捷形式，用于检索词这类本来就是 string 的输入。
func DigestString(s string) string { return Digest([]byte(s)) }

// TitleDigest 返回标题的域分隔摘要。
func TitleDigest(title string) string {
	return domainDigest(titleDigestDomain, strings.TrimSpace(title))
}

// ShortDigest 截断摘要，只用于展示（界面、日志、提示词里的引用标记）。
//
// 取舍说明：完整摘要可以被「已知候选标题集合」离线命中（标题熵低），
// 截断到 48 bit 后命中者无法确认是哪一条，展示面就小得多；
// 代价是理论上可能碰撞，所以**等值判定必须比完整摘要**，绝不能用截断形式。
func ShortDigest(s string) string {
	if len(s) <= shortDigestLen {
		return s
	}
	return s[:shortDigestLen]
}

// ValidateDigest 断言值是合法的 sha256 十六进制摘要。
//
// 空值、截断值、大写值都要拒：审计里出现「半截摘要」时，
// 事后无法判断是被截断还是原始就是短值，回放和取证都失去依据。
func ValidateDigest(s string) error {
	if s == "" {
		return fmt.Errorf("knowledge: 摘要不能为空")
	}
	if len(s) != digestHexLen {
		return fmt.Errorf("knowledge: 摘要应为 %d 位十六进制，当前 %d 位", digestHexLen, len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("knowledge: 摘要不是合法十六进制")
	}
	if strings.ToLower(s) != s {
		return fmt.Errorf("knowledge: 摘要必须是小写十六进制")
	}
	return nil
}

// Citation 是一条文档引用：来源 ID + 知识库 + 归属范围 + 分级 + 内容摘要 + 标题摘要。
//
// **它不持有文档正文，也不持有标题明文。**这是本包的核心约束（手册 §3.C：
// 禁止将未授权文档原文写日志；§2.9：正文不落库、不进普通日志）。
// 下游要展示引用时凭 SourceID 回源知识源取内容，由知识源重新做一次鉴权——
// 而不是把内容缓存在网关里：文档权限会变，网关里的副本不会跟着变，
// 于是「已撤销的文档」还能被翻出来，这是最典型的越权残留。
type Citation struct {
	// SourceID 是知识源侧的稳定文档 ID，不是标题、不是 URL。
	SourceID        string `json:"source_id"`
	KnowledgeBase   string `json:"knowledge_base"`
	OwnerKind       string `json:"owner_kind"`
	OwnerID         string `json:"owner_id"`
	DataLevel       string `json:"data_level"`
	DigestAlgorithm string `json:"digest_algorithm"`
	// Digest 是文档内容摘要，由知识源侧计算并随响应返回。
	// 网关不重算：网关没有正文可算，这正是「不持有正文」的证据。
	Digest      string  `json:"digest"`
	TitleDigest string  `json:"title_digest"`
	Score       float64 `json:"score,omitempty"`
	// RuleID 是知识源判定「本篇可读」的规则标识（手册 §3.C 要求可审计的判定依据）。
	RuleID      string    `json:"rule_id"`
	AclVersion  string    `json:"acl_version,omitempty"`
	RetrievedAt time.Time `json:"retrieved_at,omitempty"`
}

// NewCitation 把知识源返回的一条文档换成引用。
//
// doc 必须已经过 Filter 的兜底校验；这里再校验一次字段形态，
// 因为引用也可能由测试或外部直接构造，缺依据的引用一旦进了审计就无从追认。
func NewCitation(doc ReturnedDocument, retrievedAt time.Time) (Citation, error) {
	c := Citation{
		SourceID:        strings.TrimSpace(doc.SourceID),
		KnowledgeBase:   strings.TrimSpace(doc.KnowledgeBase),
		OwnerKind:       strings.TrimSpace(doc.OwnerKind),
		OwnerID:         strings.TrimSpace(doc.OwnerID),
		DataLevel:       strings.ToLower(strings.TrimSpace(doc.DataLevel)),
		DigestAlgorithm: DigestAlgorithm,
		Digest:          strings.ToLower(strings.TrimSpace(doc.Digest)),
		TitleDigest:     strings.ToLower(strings.TrimSpace(doc.TitleDigest)),
		Score:           doc.Score,
		RuleID:          strings.TrimSpace(doc.RuleID),
		AclVersion:      strings.TrimSpace(doc.AclVersion),
		RetrievedAt:     retrievedAt.UTC(),
	}
	if err := c.Validate(); err != nil {
		return Citation{}, err
	}
	return c, nil
}

// Validate 校验引用的完整性：任何一项缺失都会让审计无法复盘。
func (c Citation) Validate() error {
	if err := validateStableID("source_id", c.SourceID, maxStableIDLen); err != nil {
		return err
	}
	if err := validateStableID("knowledge_base", c.KnowledgeBase, maxStableIDLen); err != nil {
		return err
	}
	kind, err := policy.ParseScopeKind(c.OwnerKind)
	if err != nil {
		return fmt.Errorf("knowledge: 引用 %s 的 owner_kind 不合法: %w", c.SourceID, err)
	}
	if kind != policy.ScopeSystem {
		if err := validateStableID("owner_id", c.OwnerID, maxStableIDLen); err != nil {
			return fmt.Errorf("knowledge: 引用 %s: %w", c.SourceID, err)
		}
	}
	if !c.Level().Valid() {
		return fmt.Errorf("knowledge: 引用 %s 的 data_level %q 不在固定四级内", c.SourceID, c.DataLevel)
	}
	if c.DigestAlgorithm != DigestAlgorithm {
		return fmt.Errorf("knowledge: 引用 %s 的摘要算法 %q 不受支持（当前只允许 %s）",
			c.SourceID, c.DigestAlgorithm, DigestAlgorithm)
	}
	if err := ValidateDigest(c.Digest); err != nil {
		return fmt.Errorf("knowledge: 引用 %s 的内容摘要不合法: %w", c.SourceID, err)
	}
	if err := ValidateDigest(c.TitleDigest); err != nil {
		return fmt.Errorf("knowledge: 引用 %s 的标题摘要不合法: %w", c.SourceID, err)
	}
	if c.RuleID == "" {
		// 没有判定依据的引用等于「网关不知道这篇为什么可读」。
		// 放行它，事后取证就无从证明「当初确实有权读」，手册 §3.C 要的审计链断在这里。
		return fmt.Errorf("knowledge: 引用 %s 缺少知识源侧的判定依据 rule_id", c.SourceID)
	}
	if c.Score < 0 {
		return fmt.Errorf("knowledge: 引用 %s 的 score 为负", c.SourceID)
	}
	return nil
}

// Level 把分级名换回 policy.DataLevel（零值 LevelUnknown 表示取值非法）。
func (c Citation) Level() policy.DataLevel {
	level, err := policy.ParseDataLevel(c.DataLevel)
	if err != nil {
		return policy.LevelUnknown
	}
	return level
}

// OwnerScope 还原成结构化范围引用（非法时返回零值）。
func (c Citation) OwnerScope() policy.ScopeRef {
	kind, err := policy.ParseScopeKind(c.OwnerKind)
	if err != nil {
		return policy.ScopeRef{}
	}
	return policy.ScopeRef{Kind: kind, ID: c.OwnerID}
}

// Key 是「同一篇文档」的稳定标识键：知识库 + 来源 ID。
//
// 用 \x00 分隔而不是冒号：知识库 ID 与来源 ID 都由协议约束不含冒号，但仍用不可能
// 出现在标识里的字节做分隔，避免「a:b + c」与「a + b:c」撞键（去重撞键会把两篇不同
// 文档当成一篇，进而把 A 篇的授权当成 B 篇的授权）。
func (c Citation) Key() string { return c.KnowledgeBase + "\x00" + c.SourceID }

// SameDocument 报告两条引用是否指向同一篇文档。
//
// 等值判定必须用完整摘要（不是 ShortDigest）：标题低熵、截断可碰撞，
// 用截断形式会把两篇不同文档当成一篇，进而把 A 篇的授权当成 B 篇的授权。
func (c Citation) SameDocument(o Citation) bool {
	if c.SourceID != o.SourceID || c.KnowledgeBase != o.KnowledgeBase {
		return false
	}
	return c.Digest == o.Digest
}

// Display 给人在日志和界面上看的最小形式：知识库 / 来源 ID / 截断摘要。
//
// 只出现摘要与稳定 ID，永远没有标题明文和正文——这两样在结构体里根本不存在。
func (c Citation) Display() string {
	return fmt.Sprintf("%s/%s@%s:%s", c.KnowledgeBase, c.SourceID, DigestAlgorithm, ShortDigest(c.Digest))
}

// SortCitations 按稳定顺序排序引用：知识库 → 来源 ID → 摘要。
//
// 排序函数必须唯一：引用集合的摘要和回放都依赖它，
// 依赖知识源的返回顺序会让「同一输入同一输出」在第一次顺序抖动时失效。
// 相关性排序属于呈现层，由调用方在落审计之前自己决定。
func SortCitations(in []Citation) []Citation {
	out := append([]Citation(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].KnowledgeBase != out[j].KnowledgeBase {
			return out[i].KnowledgeBase < out[j].KnowledgeBase
		}
		if out[i].SourceID != out[j].SourceID {
			return out[i].SourceID < out[j].SourceID
		}
		return out[i].Digest < out[j].Digest
	})
	return out
}
