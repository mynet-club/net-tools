package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const maxSubjectLen = 256

// Identity 是一次已认证主体的稳定快照（§2.1）。
//
// 它由 internal/identity 从外部身份系统产出，本包只消费：身份层不参与模型权限判定，
// 权限判定一律走 Resolver。
type Identity struct {
	Subject     string    `json:"subject"`
	Source      string    `json:"source"`
	DisplayName string    `json:"display_name,omitempty"`
	Roles       []string  `json:"roles,omitempty"`
	Groups      []string  `json:"groups,omitempty"`
	Projects    []string  `json:"projects,omitempty"`
	AuthMethods []string  `json:"auth_methods,omitempty"`
	IssuedAt    time.Time `json:"issued_at,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

var (
	ErrSubjectRequired = errors.New("policy: subject 缺失")
	ErrSubjectUnstable = errors.New("policy: subject 不能作为稳定关联键")
	ErrIdentityExpired = errors.New("policy: 身份已过期")
	ErrIdentityNotYet  = errors.New("policy: 身份尚未生效")
	ErrMembershipTTL   = errors.New("policy: 成员关系必须带过期时间")
)

// NewIdentity 构造并校验身份；成员关系列表会被归一化。
func NewIdentity(subject, source string) (Identity, error) {
	id := Identity{Subject: subject, Source: source}
	id = id.Normalize()
	if err := id.Validate(); err != nil {
		return Identity{}, err
	}
	return id, nil
}

// Validate 落实 §2.1 的两条硬约定。
//
// 第一，subject 是稳定 ID，不接受邮箱 —— 邮箱会随人事变动改地址，一旦当主键，
// 历史用量和策略授权就断在新的地址上；同理禁止用显示名当键（§5）。
// 第二，角色/组/项目来自 token，就必须带 ExpiresAt，否则一次越权提权可以永久生效。
func (id Identity) Validate() error {
	if id.Subject == "" {
		return fmt.Errorf("%w: 不能为空", ErrSubjectRequired)
	}
	if len(id.Subject) > maxSubjectLen {
		return fmt.Errorf("%w: 长度 %d 超过上限 %d", ErrSubjectUnstable, len(id.Subject), maxSubjectLen)
	}
	if strings.ContainsAny(id.Subject, " \t\r\n") {
		return fmt.Errorf("%w: 含空白字符", ErrSubjectUnstable)
	}
	if strings.Contains(id.Subject, "@") {
		return fmt.Errorf("%w: 形如邮箱（%s）；姓名、邮箱、学号都不能作主键", ErrSubjectUnstable, id.Subject)
	}
	if id.DisplayName != "" && id.Subject == id.DisplayName {
		return fmt.Errorf("%w: 与显示名相同", ErrSubjectUnstable)
	}
	if (len(id.Roles) > 0 || len(id.Groups) > 0 || len(id.Projects) > 0) && id.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: roles/groups/projects 来自 token，必须设置 ExpiresAt", ErrMembershipTTL)
	}
	if !id.IssuedAt.IsZero() && !id.ExpiresAt.IsZero() && id.ExpiresAt.Before(id.IssuedAt) {
		return fmt.Errorf("%w: ExpiresAt 早于 IssuedAt", ErrMembershipTTL)
	}
	return nil
}

// Normalize 返回切片排序去重、首尾空白清理后的副本。
//
// 判定和审计摘要都依赖成员关系的稳定顺序，不归一化会让同一个人两次请求
// 产生不同的 Digest，回放就对不上。
func (id Identity) Normalize() Identity {
	out := id
	out.Subject = strings.TrimSpace(out.Subject)
	out.Source = strings.TrimSpace(out.Source)
	out.DisplayName = strings.TrimSpace(out.DisplayName)
	out.Roles = sortedUnique(out.Roles)
	out.Groups = sortedUnique(out.Groups)
	out.Projects = sortedUnique(out.Projects)
	out.AuthMethods = sortedUnique(out.AuthMethods)
	return out
}

// HasRole / HasGroup / HasProject：成员关系判定。大小写敏感 —— 外部 IdP 的
// 组名常常区分大小写，这里做折叠会把两个不同的组当成一个，属于越权方向的风险。
func (id Identity) HasRole(r string) bool    { return contains(id.Roles, r) }
func (id Identity) HasGroup(g string) bool   { return contains(id.Groups, g) }
func (id Identity) HasProject(p string) bool { return contains(id.Projects, p) }
func (id Identity) HasAuthMethod(m string) bool {
	return contains(id.AuthMethods, m)
}

// Expired 报告身份是否已过期。未设置 ExpiresAt 的纯 subject 身份（例如静态 API key
// 映射出的机器身份）视为不过期；带成员关系时 Validate 已经强制要求该字段。
func (id Identity) Expired(now time.Time) bool {
	return !id.ExpiresAt.IsZero() && !now.Before(id.ExpiresAt)
}

// ValidAt 报告身份在 now 时刻是否可用（已生效且未过期）。
func (id Identity) ValidAt(now time.Time) error {
	if id.Subject == "" {
		return ErrSubjectRequired
	}
	if !id.IssuedAt.IsZero() && now.Before(id.IssuedAt) {
		return ErrIdentityNotYet
	}
	if id.Expired(now) {
		return ErrIdentityExpired
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	sort.Strings(out)
	j := 0
	for i := range out {
		if i == 0 || out[i] != out[i-1] {
			out[j] = out[i]
			j++
		}
	}
	return out[:j]
}
