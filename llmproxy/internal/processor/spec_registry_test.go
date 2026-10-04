package processor

// 第一波补测试（Spec 与注册表，C 类）：ParsePhase/Phases 封闭集、Spec.Validate
// 的构造期拒绝表与边界接受表、内置类型的档位/阶段一致性、端点归一化与白名单前缀
// 绕过、注册表生命周期（重复注册/注销/升级）、工厂在构造期跑一次、AssemblyError
// 指认到具体处理器、版本变更流、copyConfig 隔离、并发注册。
// 共享助手（pipeSpec / pipeFactory / pipePlain 等）统一定义在 pipeline_test.go。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// ------------------------------------------------------------------ 工厂捕获助手

type pipeCapturedCall struct {
	spec Spec
	cfg  *Config
}

// pipeCaptureFactory 记录工厂每次被调用时看到的 Spec/Config：
// 「注册期跑一次工厂」「copyConfig 隔离」两类断言都靠它取证。
type pipeCaptureFactory struct {
	mu      sync.Mutex
	calls   int
	seen    []pipeCapturedCall
	fail    error  // 非空时工厂对所有 Spec 报错
	failFor string // 仅对该名字的 Spec 报错（指认单点故障用）
	nilProc bool   // true 时工厂返回 (nil, nil)（坏工厂）
	rec     *pipeRecorder
}

func pipeNewCaptureFactory() *pipeCaptureFactory {
	return &pipeCaptureFactory{rec: pipeNewRecorder()}
}

func (c *pipeCaptureFactory) factory() Factory {
	return func(spec Spec, cfg *Config) (Processor, error) {
		c.mu.Lock()
		c.calls++
		c.seen = append(c.seen, pipeCapturedCall{spec: spec, cfg: cfg})
		fail, failFor, nilProc, rec := c.fail, c.failFor, c.nilProc, c.rec
		if failFor != "" && failFor == spec.Name {
			fail = Errorf(ErrConfigInvalid, "运行参数坏了: %s", spec.Name)
		}
		c.mu.Unlock()
		if fail != nil {
			return nil, fail
		}
		if nilProc {
			return nil, nil
		}
		return &pipePlain{spec: spec, cfg: cfg, rec: rec}, nil
	}
}

func (c *pipeCaptureFactory) snapshot() (int, []pipeCapturedCall) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, append([]pipeCapturedCall(nil), c.seen...)
}

func (c *pipeCaptureFactory) setFailure(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fail = err
}

func (c *pipeCaptureFactory) setFailureFor(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failFor = name
}

func (c *pipeCaptureFactory) setNilProc(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nilProc = v
}

// ------------------------------------------------------------------ 阶段封闭集

func TestParsePhaseClosedSet(t *testing.T) {
	valid := map[string]Phase{
		"before-classify": PhaseBeforeClassify,
		"before-route":    PhaseBeforeRoute,
		"before-upstream": PhaseBeforeUpstream,
		"after-upstream":  PhaseAfterUpstream,
		"audit":           PhaseAudit,
	}
	for s, want := range valid {
		got, err := ParsePhase(s)
		if err != nil || got != want {
			t.Errorf("ParsePhase(%q) = %q, %v，期望 %q", s, got, err, want)
		}
		// 首尾空白容错（与 policy 各 Parse* 同口径）。
		got, err = ParsePhase("  " + s + " ")
		if err != nil || got != want {
			t.Errorf("ParsePhase(带空白 %q) = %q, %v", s, got, err)
		}
	}
	// 封闭集外一律报错，绝不回落到默认阶段：尤其空串 —— 档位有安全默认值
	// （ParseBodyAccess("") 落 metadata-only），阶段没有。
	for _, s := range []string{"", "   ", "before-upstram", "BEFORE-ROUTE", "Before-Route", "beforeclassify", "read-body", "audit;drop", "audit phase"} {
		got, err := ParsePhase(s)
		if err == nil {
			t.Errorf("ParsePhase(%q) 竟成功返回 %q", s, got)
			continue
		}
		if !errors.Is(err, ErrPhase) {
			t.Errorf("ParsePhase(%q) 错误未包 ErrPhase: %v", s, err)
		}
		if got != "" {
			t.Errorf("ParsePhase(%q) 出错时仍返回阶段 %q", s, got)
		}
	}
	// 与 BodyAccess 的默认值差异本身就是契约，钉在这里防止「顺手改成回落」。
	if _, err := policy.ParseBodyAccess(""); err != nil {
		t.Errorf("policy.ParseBodyAccess(\"\") 应落最严档，实际报错: %v", err)
	}

	// Phases()：固定五个、按执行次序、返回副本（改副本污染不了真源）。
	list := Phases()
	wantOrder := []Phase{PhaseBeforeClassify, PhaseBeforeRoute, PhaseBeforeUpstream, PhaseAfterUpstream, PhaseAudit}
	if fmt.Sprint(list) != fmt.Sprint(wantOrder) {
		t.Fatalf("Phases() = %v，期望 %v", list, wantOrder)
	}
	list[0] = "tampered"
	if Phases()[0] != PhaseBeforeClassify {
		t.Fatal("Phases() 返回了内部切片的引用")
	}
	for _, p := range Phases() {
		if !p.Valid() {
			t.Errorf("Phases() 含不合法阶段 %q", p)
		}
		again, err := ParsePhase(p.String())
		if err != nil || again != p {
			t.Errorf("String/ParsePhase 往返失败: %q", p)
		}
	}
	for _, p := range wantOrder {
		if got := p.IsRequestPhase(); got != (p == PhaseBeforeClassify || p == PhaseBeforeRoute || p == PhaseBeforeUpstream) {
			t.Errorf("%s.IsRequestPhase() = %v", p, got)
		}
	}
	if Phase("zzz").Valid() || Phase("").Valid() || Phase("AUDIT").Valid() {
		t.Error("Valid() 放过了集合外的值")
	}
	if Phase("zzz").IsRequestPhase() {
		t.Error("未知阶段不得报告为请求侧")
	}
}

// ------------------------------------------------------------------ Spec.Validate

// pipeWantErr 断言错误链上带齐所有期望哨兵。
func pipeWantErr(t *testing.T, err error, wants ...error) {
	t.Helper()
	if err == nil {
		t.Fatalf("期望报错（%v），实际通过", wants)
	}
	for _, w := range wants {
		if !errors.Is(err, w) {
			t.Fatalf("错误 %v 未包期望哨兵 %v", err, w)
		}
	}
}

func pipeLongString(n int) string { return strings.Repeat("v", n) }

func TestSpecValidateRejectsBadDeclarations(t *testing.T) {
	base := func() Spec { return pipeSpec("ok-spec", PhaseBeforeUpstream, policy.BodyTransform) }
	cases := []struct {
		title string
		mut   func(*Spec)
		want  []error
	}{
		{"名字为空", func(s *Spec) { s.Name = "" }, []error{ErrSpec}},
		{"名字含空格", func(s *Spec) { s.Name = "bad name" }, []error{ErrSpec}},
		{"名字含换行（日志注入面）", func(s *Spec) { s.Name = "bad\nname" }, []error{ErrSpec}},
		{"名字超长", func(s *Spec) { s.Name = pipeLongString(MaxNameLen + 1) }, []error{ErrSpec}},
		{"类型为空的字符串", func(s *Spec) { s.Type = "   " }, []error{ErrSpec}},
		{"类型超长", func(s *Spec) { s.Type = pipeLongString(MaxNameLen + 1) }, []error{ErrSpec}},
		{"阶段为空（无默认档）", func(s *Spec) { s.Phase = "" }, []error{ErrPhase}},
		{"阶段拼错", func(s *Spec) { s.Phase = "before-upstram" }, []error{ErrPhase}},
		{"版本缺失", func(s *Spec) { s.Version = "" }, []error{ErrVersionMissing, ErrSpec}},
		{"版本超长", func(s *Spec) { s.Version = pipeLongString(MaxVersionLen + 1) }, []error{ErrSpec}},
		{"超时为 0（禁止 0=不限）", func(s *Spec) { s.Timeout = 0 }, []error{ErrSpec}},
		{"超时为负", func(s *Spec) { s.Timeout = -time.Second }, []error{ErrSpec}},
		{"超时超绝对上限", func(s *Spec) { s.Timeout = MaxTimeout + time.Nanosecond }, []error{ErrSpec}},
		{"输入上限为 0", func(s *Spec) { s.MaxInputBytes = 0 }, []error{ErrSpec}},
		{"输入上限为负", func(s *Spec) { s.MaxInputBytes = -1 }, []error{ErrSpec}},
		{"输入上限超绝对天花板", func(s *Spec) { s.MaxInputBytes = AbsoluteMaxInputBytes + 1 }, []error{ErrSpec}},
		{"输出上限为 0", func(s *Spec) { s.MaxOutputBytes = 0 }, []error{ErrSpec}},
		{"输出上限相对输入过小", func(s *Spec) { s.MaxInputBytes = 1024; s.MaxOutputBytes = 255 }, []error{ErrSpec}},
		{"档位为空串", func(s *Spec) { s.BodyAccess = "" }, []error{policy.ErrBodyAccess}},
		{"档位越集（E 不许私设第四档）", func(s *Spec) { s.BodyAccess = "read-body" }, []error{policy.ErrBodyAccess}},
		{"档位大小写（词表按 A 的规范值）", func(s *Spec) { s.BodyAccess = "TRANSFORM-BODY" }, []error{policy.ErrBodyAccess}},
		{"scope 裸用户名", func(s *Spec) { s.Scope = "alice" }, []error{ErrSpec}},
		{"scope 有 kind 无 ID", func(s *Spec) { s.Scope = "user:" }, []error{ErrSpec}},
		{"scope 未知 kind", func(s *Spec) { s.Scope = "team:alice" }, []error{ErrSpec}},
		{"端点条数超限", func(s *Spec) {
			eps := make([]string, MaxAllowedEndpoints+1)
			for i := range eps {
				eps[i] = fmt.Sprintf("https://h%02d.example.test/", i)
			}
			s.AllowedEndpoints = eps
		}, []error{ErrSpec}},
		{"端点为空串", func(s *Spec) { s.AllowedEndpoints = []string{""} }, []error{ErrEndpointInvalid, ErrSpec}},
		{"端点非 http(s)", func(s *Spec) { s.AllowedEndpoints = []string{"ftp://h.example/"} }, []error{ErrEndpointInvalid, ErrSpec}},
		{"端点含通配", func(s *Spec) { s.AllowedEndpoints = []string{"https://*.example.com/"} }, []error{ErrEndpointInvalid, ErrSpec}},
		{"端点含 userinfo", func(s *Spec) { s.AllowedEndpoints = []string{"https://u@h.example/"} }, []error{ErrEndpointInvalid, ErrSpec}},
		{"allow_raw_body 无端点可审", func(s *Spec) { s.AllowRawBody = true }, []error{ErrSpec}},
		{"metadata-only 却声明原文出网", func(s *Spec) {
			s.AllowRawBody = true
			s.BodyAccess = policy.BodyMetadataOnly
			s.AllowedEndpoints = []string{"https://h.example/"}
		}, []error{ErrSpec}},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			s := base()
			tc.mut(&s)
			pipeWantErr(t, s.Validate(), tc.want...)
		})
	}
}

func TestSpecValidateAcceptsBoundaries(t *testing.T) {
	base := func() Spec { return pipeSpec("ok-spec", PhaseBeforeUpstream, policy.BodyTransform) }
	cases := []struct {
		title string
		mut   func(*Spec)
	}{
		{"安全字符集全用上", func(s *Spec) { s.Name = "pii.mask:v2/prod-a_B" }},
		{"名字正好 128 字节", func(s *Spec) { s.Name = pipeLongString(MaxNameLen) }},
		{"版本正好 64 字节", func(s *Spec) { s.Version = pipeLongString(MaxVersionLen) }},
		{"超时正好等于绝对上限", func(s *Spec) { s.Timeout = MaxTimeout }},
		{"输入输出正好打到天花板", func(s *Spec) {
			s.MaxInputBytes = AbsoluteMaxInputBytes
			s.MaxOutputBytes = AbsoluteMaxOutputBytes
		}},
		{"输出正好等于输入四分之一", func(s *Spec) { s.MaxInputBytes = 1024; s.MaxOutputBytes = 256 }},
		{"端点正好 32 条", func(s *Spec) {
			eps := make([]string, MaxAllowedEndpoints)
			for i := range eps {
				eps[i] = fmt.Sprintf("https://h%02d.example.test/", i)
			}
			s.AllowedEndpoints = eps
		}},
		{"scope 通配", func(s *Spec) { s.Scope = "*" }},
		{"scope kind:id", func(s *Spec) { s.Scope = "organization:university" }},
		{"allow_raw_body 配 inspect + 端点自洽", func(s *Spec) {
			s.AllowRawBody = true
			s.BodyAccess = policy.BodyInspect
			s.AllowedEndpoints = []string{"https://h.example/v1"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			s := base()
			tc.mut(&s)
			if err := s.Validate(); err != nil {
				t.Fatalf("边界内声明被误拒: %v", err)
			}
		})
	}
}

func TestSpecValidateTypeConsistency(t *testing.T) {
	// 内置类型的档位/阶段约束：错配必须在构造期炸，
	// 否则「配了脱敏但档位只给 inspect」会静默放行原文。
	sidecarEP := []string{"https://sidecar.example.test/v1"}
	cases := []struct {
		title  string
		typ    string
		phase  Phase
		access policy.BodyAccess
		eps    []string
		want   error // nil = 期望通过
	}{
		{"pii-mask transform 请求侧", TypePIIMask, PhaseBeforeClassify, policy.BodyTransform, nil, nil},
		{"pii-mask 只给 inspect（静默放行原文）", TypePIIMask, PhaseBeforeUpstream, policy.BodyInspect, nil, ErrBodyAccessNotForType},
		{"pii-mask 跑 after-upstream", TypePIIMask, PhaseAfterUpstream, policy.BodyTransform, nil, ErrPhaseNotForType},
		{"field-replace transform 请求侧", TypeFieldReplace, PhaseBeforeRoute, policy.BodyTransform, nil, nil},
		{"field-replace metadata-only", TypeFieldReplace, PhaseBeforeRoute, policy.BodyMetadataOnly, nil, ErrBodyAccessNotForType},
		{"field-replace 跑 audit", TypeFieldReplace, PhaseAudit, policy.BodyTransform, nil, ErrPhaseNotForType},
		{"json-schema metadata-only（判定不读正文）", TypeJSONSchema, PhaseBeforeUpstream, policy.BodyMetadataOnly, nil, nil},
		{"json-schema inspect", TypeJSONSchema, PhaseBeforeUpstream, policy.BodyInspect, nil, nil},
		{"json-schema 给 transform（判定改写正文）", TypeJSONSchema, PhaseBeforeUpstream, policy.BodyTransform, nil, ErrBodyAccessNotForType},
		{"json-schema 跑响应侧", TypeJSONSchema, PhaseAfterUpstream, policy.BodyInspect, nil, ErrPhaseNotForType},
		{"result-filter after-upstream inspect", TypeResultFilter, PhaseAfterUpstream, policy.BodyInspect, nil, nil},
		{"result-filter 读不到内容", TypeResultFilter, PhaseAfterUpstream, policy.BodyMetadataOnly, nil, ErrBodyAccessNotForType},
		{"result-filter 跑请求侧", TypeResultFilter, PhaseBeforeUpstream, policy.BodyInspect, nil, ErrPhaseNotForType},
		{"sidecar transform 请求侧 + 端点", TypeSidecar, PhaseBeforeUpstream, policy.BodyTransform, sidecarEP, nil},
		{"sidecar 无端点（出网不可枚举）", TypeSidecar, PhaseBeforeUpstream, policy.BodyInspect, nil, ErrSpec},
		{"sidecar 跑 after-upstream（分块变外呼）", TypeSidecar, PhaseAfterUpstream, policy.BodyInspect, sidecarEP, ErrPhaseNotForType},
		{"sidecar 跑 audit（无正文可送）", TypeSidecar, PhaseAudit, policy.BodyInspect, sidecarEP, ErrPhaseNotForType},
		// 自定义类型不受内置档位/阶段约束（扩充类型集合是 RegisterType 的职责）。
		{"自定义类型阶段自由", pipeTypeFake, PhaseAudit, policy.BodyMetadataOnly, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			s := pipeSpec("typed", tc.phase, tc.access)
			s.Type = tc.typ
			s.AllowedEndpoints = tc.eps
			err := s.Validate()
			if tc.want == nil {
				if err != nil {
					t.Fatalf("合法组合被误拒: %v", err)
				}
				return
			}
			pipeWantErr(t, err, tc.want, ErrSpec)
		})
	}
}

// ------------------------------------------------------------------ 端点归一化与白名单

func TestCanonicalEndpointNormalization(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"https://API.Example.COM", "https://api.example.com:443/"},
		{"http://h.example", "http://h.example:80/"},
		{"HTTPS://H.Example:8443/V1", "https://h.example:8443/V1"},
		{"  https://h.example/p  ", "https://h.example:443/p"},
		{"https://h.example/v1/", "https://h.example:443/v1/"},
		// 片段不属于身份，归一化后被丢弃。
		{"https://h.example/p#x", "https://h.example:443/p"},
	}
	for _, tc := range cases {
		got, err := canonicalEndpoint(tc.raw)
		if err != nil {
			t.Errorf("canonicalEndpoint(%q) 报错: %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("canonicalEndpoint(%q) = %q，期望 %q", tc.raw, got, tc.want)
		}
	}
	// 每个拒绝案例都对应一种真实绕过手法，报错必须带 ErrEndpointInvalid（进而 ErrSpec）。
	rejects := []string{
		"", "   ",
		"*", "https://*.example.com/",
		"ftp://h.example/", "h.example/path", "://nope",
		"https:", "https:///only-path",
		"https://sidecar.example.com:443@evil.test/", // userinfo 伪装白名单主机
		"https://h%2e.example/",                      // 百分号编码主机名
		"https://h.example:abc/",                     // 非法端口
		"https://h.example/p/../b",                   // 路径穿越
		"https://h.example/p?q=1",                    // 查询串：宁可报错也不给「部分匹配」留口子
	}
	for _, raw := range rejects {
		got, err := canonicalEndpoint(raw)
		if err == nil {
			t.Errorf("canonicalEndpoint(%q) 竟通过，产出 %q", raw, got)
			continue
		}
		pipeWantErr(t, err, ErrEndpointInvalid, ErrSpec)
	}
}

func TestEndpointAllowedPrefixBoundary(t *testing.T) {
	cases := []struct {
		target string
		list   []string
		want   bool
	}{
		{"https://h.example:443/svc", []string{"https://h.example/svc"}, true},
		{"https://h.example:443/svc/deep", []string{"https://h.example/svc"}, true},
		// 前缀必须落在路径边界：/svc 放不过 /svc-secret、/svcx。
		{"https://h.example:443/svc-secret", []string{"https://h.example/svc"}, false},
		{"https://h.example:443/svcx", []string{"https://h.example/svc"}, false},
		{"https://h.example:443/", []string{"https://h.example/svc"}, false},
		{"https://evil.example:443/svc", []string{"https://h.example/svc"}, false},
		// 白名单条目补默认端口后，不带端点的目标也拦得住（:443 差异不是绕过面）。
		{"https://h.example:443/svc", []string{"https://h.example:443/svc"}, true},
		{"https://h.example/svc", []string{"https://h.example:443/svc"}, false}, // 目标未归一化按不匹配处理
		// 带尾斜杠的条目覆盖整个子树。
		{"https://h.example:443/svc/anything", []string{"https://h.example/svc/"}, true},
		{"https://h.example:443/svc", []string{"https://h.example/svc/"}, false},
		// 脏条目按不匹配跳过（防一手），其余条目照常参与匹配。
		{"https://good.example:443/v", []string{"https://*.example.com/", "https://good.example/v"}, true},
		{"https://good.example:443/v", []string{"https://*.example.com/"}, false},
		{"https://good.example:443/v", nil, false}, // 空白名单 = 谁都不许去
	}
	for _, tc := range cases {
		if got := endpointAllowed(tc.target, tc.list); got != tc.want {
			t.Errorf("endpointAllowed(%q, %v) = %v，期望 %v", tc.target, tc.list, got, tc.want)
		}
	}
}

// ------------------------------------------------------------------ 注册表生命周期

func TestRegistryRegistrationLifecycle(t *testing.T) {
	reg := NewRegistry()
	// 六个内置类型 + 排序稳定（管理台按字典序展示）。
	wantTypes := []string{TypeFieldReplace, TypeSidecar, TypeJSONSchema,
		TypeKnowledgeContextInject, TypePIIMask, TypeResultFilter}
	if fmt.Sprint(reg.KnownTypes()) != fmt.Sprint(wantTypes) {
		t.Fatalf("KnownTypes() = %v，期望按字典序 %v", reg.KnownTypes(), wantTypes)
	}
	if len(reg.Names()) != 0 {
		t.Fatal("新注册表不该有条目")
	}

	// RegisterType 输入卫生。
	cap1 := pipeNewCaptureFactory()
	if err := reg.RegisterType("bad type", cap1.factory()); err == nil || !errors.Is(err, ErrRegistry) {
		t.Errorf("非安全标识符的类型名应被拒: %v", err)
	}
	if err := reg.RegisterType("fine-type", nil); err == nil || !errors.Is(err, ErrRegistry) {
		t.Errorf("空工厂应被拒: %v", err)
	}
	if err := reg.RegisterType(pipeTypeFake, cap1.factory()); err != nil {
		t.Fatal(err)
	}

	spec := pipeSpec("alpha", PhaseBeforeUpstream, policy.BodyMetadataOnly)
	// 无效声明必须进不了注册表（构造期拦截，不留到第一条请求）。
	broken := spec
	broken.Version = ""
	if err := reg.Register(broken, nil); !errors.Is(err, ErrSpec) {
		t.Errorf("无效 Spec 注册应报 ErrSpec: %v", err)
	}
	if _, ok := reg.Lookup("alpha"); ok {
		t.Error("注册失败的条目不得入库")
	}
	// 类型没工厂。
	ghost := spec
	ghost.Type = "no-such-type"
	if err := reg.Register(ghost, nil); !errors.Is(err, ErrRegistry) {
		t.Errorf("未知类型注册应报 ErrRegistry: %v", err)
	}

	if err := reg.Register(spec, nil); err != nil {
		t.Fatal(err)
	}
	gotSpec, ok := reg.Lookup("alpha")
	if !ok || gotSpec.Version != "v1" {
		t.Fatalf("Lookup 失败: %v %+v", ok, gotSpec)
	}
	if names := reg.Names(); len(names) != 1 || names[0] != "alpha" {
		t.Errorf("Names() = %v", names)
	}
	// 同名重复注册直接拒绝（覆盖式注册 = 谁最后写谁决定线上行为）。
	up := spec
	up.Version = "v2"
	if err := reg.Register(up, nil); err == nil || !errors.Is(err, ErrRegistryDuplicate) {
		t.Errorf("重复注册应报 ErrRegistryDuplicate: %v", err)
	}
	if again, _ := reg.Lookup("alpha"); again.Version != "v1" {
		t.Errorf("被拒的重复注册改动了原条目: %s", again.Version)
	}
	// 改类型也算被拒注册的一部分：注册项不可变。
	if _, ok := reg.Lookup("alpha"); !ok {
		t.Fatal("条目被误删")
	}
	// Lookup 返回副本语义抽查：改返回值污染不了注册表。
	gotSpec.Version = "tampered"
	if again, _ := reg.Lookup("alpha"); again.Version != "v1" {
		t.Error("Lookup 返回了内部 Spec 引用")
	}

	// 升级的正确姿势：先 Deregister 再 Register。
	if v, ok := reg.Deregister("nope"); ok || v != "" {
		t.Errorf("注销不存在的名字应返回空: %q %v", v, ok)
	}
	if v, ok := reg.Deregister("alpha"); !ok || v != "v1" {
		t.Fatalf("Deregister 应返回旧版本 v1: %q %v", v, ok)
	}
	if _, ok := reg.Lookup("alpha"); ok {
		t.Error("注销后仍可 Lookup")
	}
	if err := reg.Register(up, nil); err != nil {
		t.Fatalf("注销后应可注册新版本: %v", err)
	}
	if now, _ := reg.Lookup("alpha"); now.Version != "v2" {
		t.Errorf("升级后版本 = %s", now.Version)
	}
}

func TestFactoryRunsAtConstructionTime(t *testing.T) {
	// 「配置错误必须在注册期炸，而不是等第一条真实请求」（registry.go 注释承诺）。
	reg := NewRegistry()
	capf := pipeNewCaptureFactory()
	if err := reg.RegisterType(pipeTypeFake, capf.factory()); err != nil {
		t.Fatal(err)
	}
	spec := pipeSpec("mask-x", PhaseBeforeUpstream, policy.BodyMetadataOnly)

	// 无效 Spec：连工厂都不该碰。
	broken := spec
	broken.Timeout = 0
	if err := reg.Register(broken, nil); !errors.Is(err, ErrSpec) {
		t.Fatalf("注册无效 Spec 应报 ErrSpec: %v", err)
	}
	if calls, _ := capf.snapshot(); calls != 0 {
		t.Fatalf("无效 Spec 竟惊动工厂 %d 次", calls)
	}

	// 有效 Spec：注册期恰好跑一次。
	if err := reg.Register(spec, nil); err != nil {
		t.Fatal(err)
	}
	if calls, seen := capf.snapshot(); calls != 1 || seen[0].spec.Name != "mask-x" {
		t.Fatalf("注册期工厂调用轨迹异常: calls=%d", calls)
	}

	// 工厂报错：注册失败且条目不入库。
	capf.setFailure(Errorf(ErrConfigInvalid, "坏规则表"))
	bad := pipeSpec("bad-x", PhaseBeforeUpstream, policy.BodyMetadataOnly)
	err := reg.Register(bad, nil)
	pipeWantErr(t, err, ErrRegistry)
	if !strings.Contains(err.Error(), "坏规则表") {
		t.Errorf("注册错误应带上工厂原话: %v", err)
	}
	if _, ok := reg.Lookup("bad-x"); ok {
		t.Error("构造失败的条目不得入库")
	}
	capf.setFailure(nil)

	// 内置类型实证：pii-mask 的短假名密钥在注册期就被 newPIIMask 拒掉。
	pii := pipeSpec("pii-live", PhaseBeforeClassify, policy.BodyTransform)
	pii.Type = TypePIIMask
	if err := reg.Register(pii, &Config{PseudonymKey: []byte("1234567")}); err == nil {
		t.Fatal("不足 16 字节的 PseudonymKey 必须在注册期被拒")
	} else if !errors.Is(err, ErrRegistry) || !strings.Contains(err.Error(), "16 字节") {
		t.Errorf("注册期拒绝信息不对: %v", err)
	}
	if _, ok := reg.Lookup("pii-live"); ok {
		t.Error("构造失败的内置条目不得入库")
	}
	if err := reg.Register(pii, &Config{PseudonymKey: []byte(pipeLongString(32))}); err != nil {
		t.Fatalf("合法密钥的 pii-mask 应注册成功: %v", err)
	}
}

// ------------------------------------------------------------------ Build 装配

func TestBuildAssemblyErrors(t *testing.T) {
	newReg := func(t *testing.T) (*Registry, *pipeCaptureFactory, Spec) {
		t.Helper()
		reg := NewRegistry()
		capf := pipeNewCaptureFactory()
		if err := reg.RegisterType(pipeTypeFake, capf.factory()); err != nil {
			t.Fatal(err)
		}
		spec := pipeSpec("alpha", PhaseBeforeUpstream, policy.BodyMetadataOnly)
		if err := reg.Register(spec, nil); err != nil {
			t.Fatal(err)
		}
		return reg, capf, spec
	}
	pipeAssembly := func(t *testing.T, err error, wantProc string, wantReason Reason) *AssemblyError {
		t.Helper()
		var ae *AssemblyError
		if !errors.As(err, &ae) {
			t.Fatalf("装配错误应为 *AssemblyError，实际 %T: %v", err, err)
		}
		if ae.Processor != wantProc {
			t.Errorf("AssemblyError.Processor = %q，期望指认 %q", ae.Processor, wantProc)
		}
		if ae.Reason != wantReason {
			t.Errorf("AssemblyError.Reason = %s，期望 %s", ae.Reason, wantReason)
		}
		if !strings.Contains(ae.Error(), wantProc) || !strings.Contains(ae.Error(), string(wantReason)) {
			t.Errorf("AssemblyError.Error() 缺名字或原因码（管理台按码聚合）: %v", ae)
		}
		if ae.Err == nil {
			t.Error("AssemblyError 必须携带底层错误")
		}
		return ae
	}

	t.Run("未注册的名字", func(t *testing.T) {
		reg, _, spec := newReg(t)
		_, err := reg.Build([]Spec{spec, pipeSpec("ghost", PhaseBeforeUpstream, policy.BodyMetadataOnly)}, nil)
		// 必须指认到出错的那一个，而不是笼统失败。
		pipeAssembly(t, err, "ghost", ReasonNotRegistered)
	})
	t.Run("版本不符（拒绝静默换实现）", func(t *testing.T) {
		reg, _, spec := newReg(t)
		want := spec
		want.Version = "v9"
		ae := pipeAssembly(t, func() error { _, e := reg.Build([]Spec{want}, nil); return e }(), "alpha", ReasonVersionReject)
		if !strings.Contains(ae.Error(), "v9") || !strings.Contains(ae.Error(), "v1") {
			t.Errorf("版本错误必须同时报出两侧版本: %v", ae)
		}
	})
	t.Run("类型不符", func(t *testing.T) {
		reg, _, spec := newReg(t)
		want := spec
		want.Type = "someone-elses-type"
		ae := pipeAssembly(t, func() error { _, e := reg.Build([]Spec{want}, nil); return e }(), "alpha", ReasonVersionReject)
		if !strings.Contains(ae.Error(), "someone-elses-type") {
			t.Errorf("类型错误没报出实际类型: %v", ae)
		}
	})
	t.Run("Build 期再校验（注册后声明被篡改）", func(t *testing.T) {
		reg, _, spec := newReg(t)
		bad := spec
		bad.Version = ""
		pipeAssembly(t, func() error { _, e := reg.Build([]Spec{bad}, nil); return e }(), "alpha", ReasonConfigInvalid)
	})
	t.Run("工厂在 Build 期报错", func(t *testing.T) {
		reg, capf, spec := newReg(t)
		capf.setFailure(Errorf(ErrConfigInvalid, "运行参数坏了"))
		pipeAssembly(t, func() error { _, e := reg.Build([]Spec{spec}, nil); return e }(), "alpha", ReasonConfigInvalid)
	})
	t.Run("工厂返回空处理器", func(t *testing.T) {
		reg, capf, spec := newReg(t)
		capf.setNilProc(true)
		pipeAssembly(t, func() error { _, e := reg.Build([]Spec{spec}, nil); return e }(), "alpha", ReasonConfigInvalid)
	})
	t.Run("失败即整体失败（无半装配管道）", func(t *testing.T) {
		reg, capf, spec := newReg(t)
		second := pipeSpec("beta", PhaseBeforeUpstream, policy.BodyMetadataOnly)
		if err := reg.Register(second, nil); err != nil {
			t.Fatal(err)
		}
		capf.setFailureFor("beta")
		p, err := reg.Build([]Spec{spec, second}, nil)
		ae := pipeAssembly(t, err, "beta", ReasonConfigInvalid)
		if p != nil {
			t.Error("装配失败不得返回半成品 Pipeline")
		}
		// alpha 的工厂确实跑过了，但整链作废：错误定位仍指认 beta。
		if calls, _ := capf.snapshot(); calls < 2 {
			t.Errorf("工厂调用次数 = %d", calls)
		}
		_ = ae
	})
	t.Run("实现自报声明与策略不一致", func(t *testing.T) {
		// Spec() 是审计里的处理器版本与 §2.9 档位判定的来源。实现回显一份提了权的声明，
		// 策略文本与真实行为就脱钩了 —— 装配必须直接拒，不能等到请求路径上才发现。
		reg := NewRegistry()
		drift := func(s Spec, _ *Config) (Processor, error) {
			s.BodyAccess = policy.BodyTransform
			s.Version = "v9-drifted"
			return &pipePlain{spec: s, rec: pipeNewRecorder()}, nil
		}
		if err := reg.RegisterType(pipeTypeFake, drift); err != nil {
			t.Fatal(err)
		}
		spec := pipeSpec("drift", PhaseBeforeUpstream, policy.BodyMetadataOnly)
		if err := reg.Register(spec, nil); err != nil {
			t.Fatal(err)
		}
		ae := pipeAssembly(t, func() error { _, e := reg.Build([]Spec{spec}, nil); return e }(), "drift", ReasonVersionReject)
		msg := ae.Error()
		if !strings.Contains(msg, "transform-body") || !strings.Contains(msg, "metadata-only") || !strings.Contains(msg, "v9-drifted") {
			t.Errorf("不一致的声明必须两侧都报出来（管理员要看得出差在哪）: %v", ae)
		}
	})
	t.Run("空链与缺省选项", func(t *testing.T) {
		reg, _, _ := newReg(t)
		p, err := reg.Build(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.Len() != 0 || p.PolicyVersion() != "" {
			t.Fatalf("空链异常: len=%d policyVersion=%q", p.Len(), p.PolicyVersion())
		}
		res, err := p.RunRequest(context.Background(), pipeRequest(t, "empty", nil))
		if err != nil || res.Outcome != ReasonOK || res.Buffered {
			t.Fatalf("空链应原样放行: %v %+v", err, res)
		}
	})
}

// ------------------------------------------------------------------ 版本变更（§6：同名新版本）

func TestProcessorVersionUpgradeFlow(t *testing.T) {
	rec := pipeNewRecorder()
	reg := NewRegistry()
	if err := reg.RegisterType(pipeTypeFake, pipeFactory(rec, nil)); err != nil {
		t.Fatal(err)
	}
	v1 := pipeSpec("mask2", PhaseBeforeUpstream, policy.BodyMetadataOnly)
	if err := reg.Register(v1, nil); err != nil {
		t.Fatal(err)
	}
	p1, err := reg.Build([]Spec{v1}, &BuildOptions{PolicyVersion: "bundle-1"})
	if err != nil {
		t.Fatal(err)
	}

	// 升级：先注销再注册 v2。
	if got, ok := reg.Deregister("mask2"); !ok || got != "v1" {
		t.Fatalf("注销应返回 v1: %q %v", got, ok)
	}
	v2 := v1
	v2.Version = "v2"
	if err := reg.Register(v2, nil); err != nil {
		t.Fatal(err)
	}

	// 旧策略文本（v1）此后再装配必须被拒 —— 不静默换成新实现。
	_, err = reg.Build([]Spec{v1}, nil)
	var ae *AssemblyError
	if !errors.As(err, &ae) || ae.Reason != ReasonVersionReject || ae.Processor != "mask2" {
		t.Fatalf("升级后旧版本装配应被拒: %v", err)
	}
	p2, err := reg.Build([]Spec{v2}, &BuildOptions{PolicyVersion: "bundle-2"})
	if err != nil {
		t.Fatal(err)
	}

	// 已装配的 p1 是冻结快照：注册表升级不影响在途管道的行为与审计版本。
	res, err := p1.RunRequest(context.Background(), pipeRequest(t, "up-old", nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Versions) != 1 || res.Versions[0] != (NameVersion{Name: "mask2", Type: pipeTypeFake, Version: "v1"}) {
		t.Errorf("p1 审计版本 = %+v，期望冻结在 v1", res.Versions)
	}
	if res.PolicyVersion != "bundle-1" || res.Audit.PolicyVersion != "bundle-1" {
		t.Errorf("p1 策略版本 = %q / %q", res.PolicyVersion, res.Audit.PolicyVersion)
	}
	if got := res.Entries[0].Version; got != "v1" {
		t.Errorf("p1 条目版本 = %s", got)
	}
	res2, err := p2.RunRequest(context.Background(), pipeRequest(t, "up-new", nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Versions) != 1 || res2.Versions[0].Version != "v2" {
		t.Errorf("p2 审计版本 = %+v，期望 v2", res2.Versions)
	}
	if res2.Audit.PolicyVersion != "bundle-2" {
		t.Errorf("p2 策略版本 = %q", res2.Audit.PolicyVersion)
	}
}

// ------------------------------------------------------------------ copyConfig 隔离

func TestRegistryConfigCopyIsolation(t *testing.T) {
	capf := pipeNewCaptureFactory()
	reg := NewRegistry()
	if err := reg.RegisterType(pipeTypeFake, capf.factory()); err != nil {
		t.Fatal(err)
	}
	spec := pipeSpec("cfgx", PhaseBeforeUpstream, policy.BodyMetadataOnly)
	if err := reg.Register(spec, nil); err != nil {
		t.Fatal(err) // nil cfg 注册必须可行
	}
	_, seen := capf.snapshot()
	if seen[0].cfg != nil {
		t.Fatal("nil Config 应原样传 nil（不许替换成凭空造的空配置）")
	}

	cfg := &Config{
		PseudonymKey: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		PIITypes:     []string{"phone"},
		Rules:        []ReplaceRule{{Name: "r1", Pattern: "p", Replacement: "x", Mapping: map[string]string{"k": "v"}}},
		FilterRules:  []FilterRule{{Name: "f1", Keywords: []string{"bad-word"}, Replacement: "[FILTERED]"}},
		Schema:       json.RawMessage(`{"type":"object"}`),
		Headers:      map[string]string{"X-Test": "original"},
	}
	spec2 := pipeSpec("cfgy", PhaseBeforeUpstream, policy.BodyMetadataOnly)
	if err := reg.Register(spec2, cfg); err != nil {
		t.Fatal(err)
	}

	// 注册之后调用方就地改自己的切片/映射/字节 —— 一条请求不得能改另一条请求的策略。
	cfg.PIITypes[0] = "email"
	cfg.PseudonymKey[0] = 99
	cfg.Rules[0].Name = "hijacked"
	cfg.Rules[0].Mapping["k"] = "evil"
	cfg.FilterRules[0].Name = "hijacked"
	cfg.FilterRules[0].Keywords[0] = "worse-word"
	cfg.Schema[0] = '['
	cfg.Headers["X-Test"] = "mutated"

	if _, err := reg.Build([]Spec{spec2}, nil); err != nil {
		t.Fatal(err)
	}
	_, seen = capf.snapshot()
	got := seen[len(seen)-1].cfg
	if got == cfg {
		t.Fatal("Build 把调用方的 Config 指针原样交给了工厂")
	}
	if got.PIITypes[0] != "phone" {
		t.Errorf("PIITypes 未隔离: %v", got.PIITypes)
	}
	if got.PseudonymKey[0] != 1 {
		t.Errorf("PseudonymKey 未隔离: %v", got.PseudonymKey)
	}
	if got.Rules[0].Name != "r1" || got.Rules[0].Mapping["k"] != "v" {
		t.Errorf("Rules/Mapping 未隔离: %+v", got.Rules)
	}
	if got.FilterRules[0].Name != "f1" || got.FilterRules[0].Keywords[0] != "bad-word" {
		t.Errorf("FilterRules/Keywords 未隔离: %+v", got.FilterRules)
	}
	if string(got.Schema) != `{"type":"object"}` {
		t.Errorf("Schema 未隔离: %s", got.Schema)
	}
	if got.Headers["X-Test"] != "original" {
		t.Errorf("Headers 未隔离: %v", got.Headers)
	}
	// 标量参数按值复制即可。
	if got.MaxRetries != cfg.MaxRetries || got.Idempotent != cfg.Idempotent {
		t.Error("标量字段复制丢失")
	}
}

// ------------------------------------------------------------------ 并发注册与装配

func TestRegistryConcurrentAccess(t *testing.T) {
	// 注册发生在启动/热更新期、装配发生在每条请求上：两路并发必须 -race 干净。
	rec := pipeNewRecorder()
	reg := NewRegistry()
	if err := reg.RegisterType(pipeTypeFake, pipeFactory(rec, nil)); err != nil {
		t.Fatal(err)
	}
	fixed := []Spec{
		pipeSpec("a", PhaseBeforeRoute, policy.BodyMetadataOnly),
		pipeSpec("b", PhaseBeforeUpstream, policy.BodyInspect),
	}
	for _, s := range fixed {
		if err := reg.Register(s, nil); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	bad := make(chan string, 64)

	// 读路径：Lookup/Names/KnownTypes/Build + 跑装配出的管道。
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				if _, ok := reg.Lookup("a"); !ok {
					bad <- fmt.Sprintf("worker %d: 常驻条目 a 查不到", w)
					return
				}
				reg.Names()
				reg.KnownTypes()
				p, err := reg.Build(fixed, &BuildOptions{PolicyVersion: "conc@1"})
				if err != nil {
					bad <- fmt.Sprintf("worker %d: 装配失败 %v", w, err)
					return
				}
				// goroutine 里不碰 *testing.T：失败一律走 bad 通道汇总。
				req := &Request{
					RequestID: fmt.Sprintf("cw%d-%d", w, i),
					Model:     "gpt-test",
					Policy:    pipeCtxNoT(""),
					Chain:     pipeChain("alice"),
					Now:       pipeBaseNow,
				}
				if _, err := p.RunRequest(context.Background(), req); err != nil {
					bad <- fmt.Sprintf("worker %d: 运行失败 %v", w, err)
					return
				}
			}
		}(w)
	}
	// 写路径：注册-注销自己名下的一次性条目，不碰 fixed。
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				name := fmt.Sprintf("bg-%d-%d", w, i)
				s := pipeSpec(name, PhaseAudit, policy.BodyMetadataOnly)
				if err := reg.Register(s, nil); err != nil {
					bad <- fmt.Sprintf("writer %d: 注册 %s 失败 %v", w, name, err)
					return
				}
				if _, ok := reg.Lookup(name); !ok {
					bad <- fmt.Sprintf("writer %d: 刚注册的 %s 查不到", w, name)
					return
				}
				if _, ok := reg.Deregister(name); !ok {
					bad <- fmt.Sprintf("writer %d: 注销 %s 失败", w, name)
					return
				}
			}
		}(w)
	}
	// 同名并发注册：只能有一个赢（ErrRegistryDuplicate 是原子的，不是最后写入者通吃）。
	var wins atomic.Int64
	var dupWG sync.WaitGroup
	for i := 0; i < 8; i++ {
		dupWG.Add(1)
		go func() {
			defer dupWG.Done()
			if err := reg.Register(pipeSpec("duelist", PhaseBeforeUpstream, policy.BodyMetadataOnly), nil); err == nil {
				wins.Add(1)
			}
		}()
	}
	dupWG.Wait()
	if got := wins.Load(); got != 1 {
		t.Errorf("同名并发注册成功 %d 次，期望恰好 1 次", got)
	}
	wg.Wait()
	close(bad)
	for msg := range bad {
		t.Error(msg)
	}
	// 收尾稳态：常驻条目 a/b 仍在，一次性 bg 条目全部注销，只剩 duelist 的胜者。
	if names := reg.Names(); len(names) != 3 || names[0] != "a" || names[1] != "b" || names[2] != "duelist" {
		t.Errorf("收尾 Names() = %v，期望 [a b duelist]", names)
	}
}
