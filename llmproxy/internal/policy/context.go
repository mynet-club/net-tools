package policy

import (
	"errors"
	"fmt"
	"strings"
)

// PolicyContext 是一次判定所需的完整上下文（§2.2）。
//
// 字段与手册保持一一对应，不夹带运行期对象：HTTP 请求、数据库行、供应商配置
// 都由各自的适配层转成这几个字段再进来。
type PolicyContext struct {
	Identity       Identity  `json:"identity"`
	Purpose        string    `json:"purpose"`
	Organization   string    `json:"organization,omitempty"`
	Project        string    `json:"project,omitempty"`
	DataLevel      DataLevel `json:"data_level"`
	AllowedRegions []string  `json:"allowed_regions,omitempty"`
	PolicyVersion  string    `json:"policy_version,omitempty"`
}

var (
	ErrContext        = errors.New("policy: 策略上下文不合法")
	ErrPurposeMissing = errors.New("policy: purpose 不能为空")
)

// NewPolicyContext 校验并归一化上下文。
func NewPolicyContext(id Identity, purpose string, level DataLevel) (PolicyContext, error) {
	ctx := PolicyContext{Identity: id, Purpose: purpose, DataLevel: level}
	ctx = ctx.Normalize()
	if err := ctx.Validate(); err != nil {
		return PolicyContext{}, err
	}
	return ctx, nil
}

// Normalize 清理空白并对区域列表排序去重，保证判定与摘要的可重现性。
func (ctx PolicyContext) Normalize() PolicyContext {
	out := ctx
	out.Identity = ctx.Identity.Normalize()
	out.Purpose = strings.TrimSpace(out.Purpose)
	out.Organization = strings.TrimSpace(out.Organization)
	out.Project = strings.TrimSpace(out.Project)
	out.PolicyVersion = strings.TrimSpace(out.PolicyVersion)
	out.AllowedRegions = sortedUnique(ctx.AllowedRegions)
	return out
}

// Validate 要求身份合法、分级已判定、purpose 非空。
//
// purpose 是必填的：配额、出网和保留策略都要按用途区分（问答、代码补全、
// 批量离线作业的费用与合规口径完全不同），留空会让 deny 规则整体失配。
func (ctx PolicyContext) Validate() error {
	if err := ctx.Identity.Validate(); err != nil {
		return err
	}
	if ctx.Purpose == "" {
		return ErrPurposeMissing
	}
	if !ctx.DataLevel.Valid() {
		return fmt.Errorf("%w: %v", ErrContext, ctx.DataLevel)
	}
	if ctx.Project != "" && ctx.Organization == "" {
		return fmt.Errorf("%w: 指定了 project 却没指定 organization", ErrContext)
	}
	return nil
}

// RestrictsRegions 报告上下文是否带区域约束。
//
// 空列表按「不做区域限制」处理，这是显式约定：区域白名单需要运营者主动配置，
// 不能靠漏配来收紧，否则升级到这版会让所有既有单区域部署选不出候选。
func (ctx PolicyContext) RestrictsRegions() bool { return len(ctx.AllowedRegions) > 0 }

// RegionAllowed 报告区域是否在允许集合内。region 为空表示提供方未声明区域，
// 只有在上下文不做区域限制时才放行。
func (ctx PolicyContext) RegionAllowed(region string) bool {
	if !ctx.RestrictsRegions() {
		return true
	}
	if region == "" {
		return false
	}
	return contains(ctx.AllowedRegions, region)
}
