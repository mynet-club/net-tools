package policy

import (
	"errors"
	"fmt"
	"strings"
)

// BodyAccess 是处理器对请求正文的访问档位（§2.9）。
//
// 默认转发路径保持「正文不落库、不进普通日志」。这一档不会因为 DataLevel
// 或处理器存在而被自动打开：DataLevel 只是策略结果，能不能看正文由这里决定。
type BodyAccess string

const (
	// BodyMetadataOnly 只能看模型、用户、请求体大小和头部摘要。
	BodyMetadataOnly BodyAccess = "metadata-only"
	// BodyInspect 可以在内存里读正文做判定，但不得出网、不得持久化。
	BodyInspect BodyAccess = "inspect-body"
	// BodyTransform 可以读正文并产出替换后的正文，受大小、超时和脱敏规则约束。
	BodyTransform BodyAccess = "transform-body"
)

// ErrBodyAccess 表示档位字符串不在固定三档内。
var ErrBodyAccess = errors.New("policy: 未知的正文访问档位")

// ParseBodyAccess 解析档位；空串按最严格的 metadata-only 处理。
//
// 这里不默认成 inspect-body：正文访问必须显式声明（§2.9）。
func ParseBodyAccess(s string) (BodyAccess, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch BodyAccess(s) {
	case "", BodyMetadataOnly:
		return BodyMetadataOnly, nil
	case BodyInspect, BodyTransform:
		return BodyAccess(s), nil
	}
	return "", fmt.Errorf("%w: %q（可用值：metadata-only、inspect-body、transform-body）", ErrBodyAccess, s)
}

func (a BodyAccess) Valid() bool {
	switch a {
	case BodyMetadataOnly, BodyInspect, BodyTransform:
		return true
	}
	return false
}

// CanReadBody 报告该档位是否允许在内存中读取正文。
func (a BodyAccess) CanReadBody() bool { return a == BodyInspect || a == BodyTransform }

// CanReplaceBody 报告该档位是否允许产出替换后的正文。
func (a BodyAccess) CanReplaceBody() bool { return a == BodyTransform }

// 正文原文出网授权（§2.9 规则 3、4）。
//
// 外部 HTTP sidecar 默认只收脱敏后的正文或摘要；allow_raw_body=true 必须由管理员
// 策略授予，且绑定组织/项目 scope、期限和审计记录 —— 在领域模型里就是一条
// Resource=body.raw、Action=read 的显式 allow Entitlement，带 Conditions 和 ExpiresAt。
const (
	ResourceBodyRaw = "body.raw"
)

// 资源命名空间（§2.4）：Entitlement.Resource 一律写成 `<命名空间>:<标识>`，
// 允许用尾部通配（`model:*`）。裸字符串（不含冒号）只有 "*" 一种合法形式。
const (
	NamespaceModel      = "model"
	NamespaceCapability = "capability"
	NamespaceKnowledge  = "knowledge"
	NamespaceProcessor  = "processor"
	NamespaceBudget     = "budget"
	NamespaceBody       = "body"
)

// 动作词汇表（§2.4）。新增动作同样要走主线评审。
const (
	ActionUse    = "use"
	ActionRead   = "read"
	ActionInvoke = "invoke"
	ActionSpend  = "spend"
)

// ResourceOf 返回资源的命名空间部分；无冒号时返回空串（即通配资源）。
func ResourceOf(resource string) string {
	if i := strings.IndexByte(resource, ':'); i > 0 {
		return resource[:i]
	}
	return ""
}
