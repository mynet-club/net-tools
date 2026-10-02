package processor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// sidecar 是本包唯一的出网处理器，也是唯一「正文可能离开进程」的那一个。
// 其余测试都用 fake 类型走管线，所以注册期那几道门（客户端注入、端点白名单、
// 原文授权判定器）与投递形态必须在这里用真实现跑一遍 —— 它们全是安全门，
// 而安全门最坏的失效方式是「只有注释说它存在」。

// scTransport 直接替掉 transport：断言「出网几次、发了什么字节」不能靠真连接，
// 而 httptest 会引入 loopback 地址 —— 白名单要验的是「只认声明的那个端点」，
// 用假 transport 才能把「根本没出网」和「出网到别处」分清楚。
type scTransport struct {
	calls  int
	bodies []string
	urls   []string
	hdrs   []http.Header
	// reply 按第几次尝试（从 1 起）决定响应；nil 时恒 200 + allowed:true。
	reply func(attempt int) (int, string)
}

func (tr *scTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tr.calls++
	data, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	tr.bodies = append(tr.bodies, string(data))
	tr.urls = append(tr.urls, req.URL.String())
	tr.hdrs = append(tr.hdrs, req.Header.Clone())
	code, body := http.StatusOK, `{"allowed":true}`
	if tr.reply != nil {
		code, body = tr.reply(tr.calls)
	}
	return &http.Response{
		StatusCode:    code,
		Body:          io.NopCloser(strings.NewReader(body)),
		Header:        make(http.Header),
		ContentLength: int64(len(body)),
	}, nil
}

// scSpec 是一条合法的 sidecar 声明：请求侧阶段 + 端点白名单。
func scSpec(name string, access policy.BodyAccess) Spec {
	s := pipeSpec(name, PhaseBeforeUpstream, access)
	s.Type = TypeSidecar
	s.AllowedEndpoints = []string{"https://sidecar.test/"}
	return s
}

// scConfig 造注册期配置，并把那个假 transport 一并交回：
// 断言「发了什么、发了几次」只能凭它，不能凭 Result 里的推测字段。
func scConfig(grants RawBodyGrantChecker) (*Config, *scTransport) {
	tr := &scTransport{}
	return &Config{
		HTTPClient: &http.Client{Transport: tr},
		Endpoint:   "https://sidecar.test/v1/check",
		Grants:     grants,
	}, tr
}

func scRegister(spec Spec, cfg *Config) error {
	reg := NewRegistry()
	return reg.Register(spec, cfg)
}

// scRun 装配并跑一次请求侧处理。cfg 必须自带 transport（scConfig 给的那份）。
func scRun(t *testing.T, spec Spec, cfg *Config, req *Request) (*Result, error) {
	t.Helper()
	reg := NewRegistry()
	if err := reg.Register(spec, cfg); err != nil {
		t.Fatalf("注册 %s 失败: %v", spec.Name, err)
	}
	p, err := reg.Build([]Spec{spec}, &BuildOptions{PolicyVersion: "test-bundle@1"})
	if err != nil {
		t.Fatalf("装配失败: %v", err)
	}
	return p.RunRequest(context.Background(), req)
}

// scGrant 是授权判定器的记录型替身。
type scGrant struct {
	allowed   bool
	reason    policy.Reason
	gotNow    time.Time
	gotPolicy policy.PolicyContext
	gotChain  policy.ScopeChain
	calls     int
}

func (g *scGrant) AllowsRawBody(ctx policy.PolicyContext, chain policy.ScopeChain, now time.Time) (bool, policy.Reason) {
	g.calls++
	g.gotPolicy, g.gotChain, g.gotNow = ctx, chain, now
	return g.allowed, g.reason
}

func scPayloadOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("投递文档不是合法 JSON: %v\n%s", err, raw)
	}
	return m
}

// scHashOf 是投递文档里 content_hash 的期望形态：**带 sha256: 前缀**，
// 与审计条目的 InputHash 同形态 —— sidecar 侧要拿它对上账，
// 前缀一旦在两处不一致，关联就静默失效（哈希本身看着还是「对的」）。
func scHashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TestSidecarConstructionGates 钉住注册期那几道门：任何一道都不许把请求放到路上。
func TestSidecarConstructionGates(t *testing.T) {
	base := scSpec("gate", policy.BodyInspect)
	okCfg, _ := scConfig(nil)

	t.Run("缺客户端就拒绝注册", func(t *testing.T) {
		// 本包绝不自己建连接：默认 transport 会绕过 dialer 的目标白名单。
		cfg := *okCfg
		cfg.HTTPClient = nil
		if err := scRegister(base, &cfg); !errors.Is(err, ErrConfigInvalid) {
			t.Fatalf("应当 ErrConfigInvalid，实际 %v", err)
		}
	})
	t.Run("缺配置整体也拒绝注册", func(t *testing.T) {
		if err := scRegister(base, nil); !errors.Is(err, ErrConfigInvalid) {
			t.Fatalf("应当 ErrConfigInvalid，实际 %v", err)
		}
	})
	t.Run("端点必须落在白名单内", func(t *testing.T) {
		cfg := *okCfg
		cfg.Endpoint = "https://evil.test/v1"
		if err := scRegister(base, &cfg); !errors.Is(err, ErrEndpointDenied) {
			t.Fatalf("白名单外的端点应当注册即拒，实际 %v", err)
		}
	})
	t.Run("原文授权判定器缺位时不许注册", func(t *testing.T) {
		// 这一条是主线复核补上的：原来要到第一个真实请求才发现没注入判定器，
		// 而那时原文已经在请求路径上了。
		raw := scSpec("raw-gate", policy.BodyTransform)
		raw.AllowRawBody = true
		if err := scRegister(raw, okCfg); !errors.Is(err, ErrGrantCheckerBlank) {
			t.Fatalf("声明 allow_raw_body 而无 Grants 应当拒注册，实际 %v", err)
		}
		// 不送原文的 sidecar 不需要判定器：不能顺手把这道门变成必填。
		if err := scRegister(base, okCfg); err != nil {
			t.Fatalf("未声明 allow_raw_body 不该被判定器门挡住: %v", err)
		}
	})
	t.Run("非幂等声明不许带重试", func(t *testing.T) {
		cfg := *okCfg
		cfg.MaxRetries = 2
		cfg.Idempotent = false
		if err := scRegister(base, &cfg); !errors.Is(err, ErrConfigInvalid) {
			t.Fatalf("非幂等 + 重试应当直接报错而不是静默归零，实际 %v", err)
		}
	})
	t.Run("头值含换行拒绝注册", func(t *testing.T) {
		// 含 CR/LF 的头值能在请求里插出一行任意内容（响应走私的入口）。
		cfg := *okCfg
		cfg.Headers = map[string]string{"X-Trace": "ok\r\nX-Injected: 1"}
		if err := scRegister(base, &cfg); !errors.Is(err, ErrConfigInvalid) {
			t.Fatalf("应当拒带换行的头，实际 %v", err)
		}
	})
}

// TestSidecarContentModeFollowsGrant 验 §2.9 规则 3、4 的三种投递形态，
// 以及「未授权原文」这条路径**一个字节都不许出网**。
func TestSidecarContentModeFollowsGrant(t *testing.T) {
	const secret = "客户的原始问题：我的化验单怎么办"

	t.Run("未声明原文且无脱敏结果时只送摘要", func(t *testing.T) {
		spec := scSpec("s1", policy.BodyInspect)
		cfg, tr := scConfig(nil)
		res, err := scRun(t, spec, cfg, pipeRequest(t, "r-sum", NewBufferedBody([]byte(secret))))
		if err != nil {
			t.Fatal(err)
		}
		payload := scPayloadOf(t, tr.bodies[0])
		if payload["content_mode"] != SidecarContentNone {
			t.Errorf("content_mode = %v", payload["content_mode"])
		}
		// omitempty 的语义要真成立：字段必须**不存在**。
		// 空串会被 sidecar 读成「正文是空的」，那是另一种误判。
		if _, present := payload["content"]; present {
			t.Error("摘要形态不得带 content 字段（哪怕是空串）")
		}
		if strings.Contains(tr.bodies[0], secret) {
			t.Error("原文出现在投递文档里")
		}
		if !pipeEntry(t, res, "s1").SummaryOnly {
			t.Error("必须留 summary_only 痕迹，好让运营看出送出去的不是脱敏正文")
		}
		// 摘要形态仍然给出 hash：审计要能对上「送出去的是哪一份」，
		// 哪怕内容本身没送。
		if payload["content_hash"] != scHashOf(secret) {
			t.Errorf("content_hash 与原文不符: %v", payload["content_hash"])
		}
	})

	t.Run("链上已脱敏时送 masked 正文", func(t *testing.T) {
		// 前一个处理器产出新正文后，sidecar 送的就是这份脱敏结果（默认形态）。
		maskSpec := pipeSpec("sc-mask", PhaseBeforeUpstream, policy.BodyTransform)
		maskSpec.Type = scMaskerType
		spec := scSpec("s-masked", policy.BodyTransform)
		cfg, tr := scConfig(nil)
		reg := NewRegistry()
		if err := reg.RegisterType(scMaskerType, func(s Spec, _ *Config) (Processor, error) {
			return &scMasker{spec: s}, nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := reg.Register(maskSpec, nil); err != nil {
			t.Fatalf("注册替身失败: %v", err)
		}
		if err := reg.Register(spec, cfg); err != nil {
			t.Fatalf("注册失败: %v", err)
		}
		p, err := reg.Build([]Spec{maskSpec, spec}, &BuildOptions{PolicyVersion: "test-bundle@1"})
		if err != nil {
			t.Fatalf("装配失败: %v", err)
		}
		if _, err := p.RunRequest(context.Background(),
			pipeRequest(t, "r-masked", NewBufferedBody([]byte(secret)))); err != nil {
			t.Fatal(err)
		}
		payload := scPayloadOf(t, tr.bodies[0])
		if payload["content_mode"] != SidecarContentMasked {
			t.Errorf("content_mode = %v，期望 masked", payload["content_mode"])
		}
		if payload["content"] != scMaskedBody {
			t.Errorf("送出的正文不是链上产物: %v", payload["content"])
		}
		if strings.Contains(tr.bodies[0], secret) {
			t.Error("masked 形态里出现了原文")
		}
	})

	t.Run("声明原文但未获授权时拒绝且不出网", func(t *testing.T) {
		spec := scSpec("s2", policy.BodyTransform)
		spec.AllowRawBody = true
		grant := &scGrant{allowed: false, reason: policy.ReasonRawBodyGrantMissing}
		cfg, tr := scConfig(grant)
		res, err := scRun(t, spec, cfg, pipeRequest(t, "r-deny", NewBufferedBody([]byte(secret))))
		if !errors.Is(err, ErrRawBodyDenied) {
			t.Fatalf("未授权必须拒绝，实际 %v", err)
		}
		if tr.calls != 0 {
			t.Errorf("未授权却出网 %d 次", tr.calls)
		}
		if grant.calls != 1 {
			t.Errorf("必须查过一次授权，实际 %d", grant.calls)
		}
		// 违规（不是故障）：fail_open 也冲不掉它。
		if got := pipeEntry(t, res, "s2").Outcome; got != ReasonGrantMissing {
			t.Errorf("Outcome = %s", got)
		}
		if got := pipeEntry(t, res, "s2").GrantReason; got != policy.ReasonRawBodyGrantMissing {
			t.Errorf("GrantReason = %q", got)
		}
	})

	t.Run("授权成立才送原文", func(t *testing.T) {
		spec := scSpec("s3", policy.BodyTransform)
		spec.AllowRawBody = true
		grant := &scGrant{allowed: true, reason: policy.ReasonExplicitAllow}
		cfg, tr := scConfig(grant)
		res, err := scRun(t, spec, cfg, pipeRequest(t, "r-raw", NewBufferedBody([]byte(secret))))
		if err != nil {
			t.Fatalf("有效授权应放行: %v", err)
		}
		payload := scPayloadOf(t, tr.bodies[0])
		if payload["content_mode"] != SidecarContentRaw || payload["content"] != secret {
			t.Errorf("应送原文: mode=%v content=%v", payload["content_mode"], payload["content"])
		}
		if payload["content_hash"] != scHashOf(secret) {
			t.Errorf("content_hash 与原文不符: %v", payload["content_hash"])
		}
		if got := pipeEntry(t, res, "s3").GrantReason; got != policy.ReasonExplicitAllow {
			t.Errorf("GrantReason = %q，策略侧原因码必须留在审计里", got)
		}
		if pipeEntry(t, res, "s3").SummaryOnly {
			t.Error("原文已直发，不该标记 summary_only")
		}
	})

	t.Run("投递文档带契约版本与策略版本", func(t *testing.T) {
		// 接线方换字段时 sidecar 侧要能按版本区分含义（否则加字段就是改协议）。
		spec := scSpec("s4", policy.BodyInspect)
		cfg, tr := scConfig(nil)
		req := pipeRequest(t, "r-ver", NewBufferedBody([]byte("abc")))
		// 策略版本走的是请求自带的策略上下文（A 包在解析时盖上 bundle 版本），
		// 不是 BuildOptions 里那个 —— 两条来源必须各归各位，否则「身份适用的策略」
		// 与「网关装配用的策略」混淆，sidecar 侧就无法复现判定。
		req.Policy.PolicyVersion = "university-bundle@3"
		if _, err := scRun(t, spec, cfg, req); err != nil {
			t.Fatal(err)
		}
		payload := scPayloadOf(t, tr.bodies[0])
		if payload["version"] != float64(SidecarPayloadVersion) {
			t.Errorf("version = %v", payload["version"])
		}
		if payload["policy_version"] != "university-bundle@3" {
			t.Errorf("policy_version = %v", payload["policy_version"])
		}
		if payload["request_id"] != "r-ver" || payload["processor"] != "s4" {
			t.Errorf("文档没对上这次调用: %v / %v", payload["request_id"], payload["processor"])
		}
		// 正文长度与范围链也必须在：sidecar 侧要靠它们做尺寸与归属判定。
		if payload["content_len"] != float64(len("abc")) {
			t.Errorf("content_len = %v", payload["content_len"])
		}
		if payload["body_access"] != string(policy.BodyInspect) {
			t.Errorf("body_access = %v", payload["body_access"])
		}
		if payload["scopes"] == "" || payload["scopes"] == nil {
			t.Errorf("scopes 必须带上范围链: %v", payload["scopes"])
		}
	})

	t.Run("无策略版本时该字段缺席", func(t *testing.T) {
		// omitempty：缺席比空串好读，sidecar 不会把「没版本」当成「版本是空」。
		spec := scSpec("s5", policy.BodyInspect)
		cfg, tr := scConfig(nil)
		if _, err := scRun(t, spec, cfg, pipeRequest(t, "r-nover", NewBufferedBody([]byte("abc")))); err != nil {
			t.Fatal(err)
		}
		if _, present := scPayloadOf(t, tr.bodies[0])["policy_version"]; present {
			t.Error("策略上下文没带版本时，policy_version 字段必须缺席")
		}
	})
}

// scMasker 是一个把正文替换成固定串的前置处理器，只用来制造「链上已脱敏」形态。
const (
	scMaskerType = "sc-masker"
	scMaskedBody = "已脱敏"
)

type scMasker struct{ spec Spec }

func (m *scMasker) Spec() Spec { return m.spec }

func (m *scMasker) Process(_ context.Context, in *Input) (*Output, error) {
	data, err := in.Body()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return &Output{}, nil
	}
	return &Output{Body: []byte(scMaskedBody)}, nil
}

// TestSidecarGrantClockIsInjectable 钉住「拿不到请求时间时退回注册期的时间源」。
//
// 授权自带过期：退回墙上时钟会让同一请求的两次判定跨不过同一秒，
// 回放就不再可复现（§2.8），测试也没法固定它。
func TestSidecarGrantClockIsInjectable(t *testing.T) {
	frozen := pipeBaseNow.Add(72 * time.Hour)
	spec := scSpec("clk", policy.BodyTransform)
	spec.AllowRawBody = true
	grant := &scGrant{allowed: true, reason: policy.ReasonExplicitAllow}

	cfg, _ := scConfig(grant)
	cfg.Clock = func() time.Time { return frozen }

	req := pipeRequest(t, "r-clk", NewBufferedBody([]byte("x")))
	req.Now = time.Time{} // 接线方漏了时间：这是本用例要验的那条兜底
	if _, err := scRun(t, spec, cfg, req); err != nil {
		t.Fatal(err)
	}
	if !grant.gotNow.Equal(frozen) {
		t.Errorf("授权判定时刻应当是注入的时间源，拿到 %v", grant.gotNow)
	}

	t.Run("有请求时间时以请求时间为准", func(t *testing.T) {
		g2 := &scGrant{allowed: true, reason: policy.ReasonExplicitAllow}
		cfg2, _ := scConfig(g2)
		cfg2.Clock = func() time.Time { return frozen }
		if _, err := scRun(t, spec, cfg2, pipeRequest(t, "r-clk2", NewBufferedBody([]byte("x")))); err != nil {
			t.Fatal(err)
		}
		if !g2.gotNow.Equal(pipeBaseNow) {
			t.Errorf("判定时刻应为请求自带的时间，拿到 %v", g2.gotNow)
		}
	})

	// 顺带钉住「判定用的是本次请求的策略上下文与范围链」：
	// 传错对象会让授权按别人的范围算出来，而结果看起来完全正常。
	if grant.gotPolicy.Identity.Subject != req.Policy.Identity.Subject {
		t.Errorf("判定的主体与请求不符: %q vs %q", grant.gotPolicy.Identity.Subject, req.Policy.Identity.Subject)
	}
	if grant.gotPolicy.Purpose != req.Policy.Purpose ||
		grant.gotPolicy.Organization != req.Policy.Organization ||
		grant.gotPolicy.PolicyVersion != req.Policy.PolicyVersion {
		t.Errorf("判定的策略上下文与请求不符: %+v", grant.gotPolicy)
	}
	// Display() 把每个范围的 kind+id 都带出来，比只比长度强：
	// 传错一个 ref（比如把上一个请求的链拿来判定）长度不变，归属却变了。
	if grant.gotChain.Display() != req.Chain.Display() {
		t.Errorf("判定的范围链与请求不符: %q vs %q", grant.gotChain.Display(), req.Chain.Display())
	}
}

// TestSidecarRetryOnlyWhenIdempotent 验重试预算：非幂等一次都不重放，
// 幂等则按 MaxRetries 重放，且所有尝试共享同一份超时。
func TestSidecarRetryOnlyWhenIdempotent(t *testing.T) {
	flake := func(attempt int) (int, string) {
		if attempt < 3 {
			return http.StatusBadGateway, `{"error":"boom"}`
		}
		return http.StatusOK, `{"allowed":true}`
	}

	t.Run("非幂等一次都不重试", func(t *testing.T) {
		spec := scSpec("rc1", policy.BodyInspect)
		spec.FailClosed = true
		cfg, tr := scConfig(nil)
		cfg.Idempotent = false
		tr.reply = func(int) (int, string) { return http.StatusBadGateway, `{}` }
		res, err := scRun(t, spec, cfg, pipeRequest(t, "r-nr", NewBufferedBody([]byte("y"))))
		if !errors.Is(err, ErrSidecarFailed) {
			t.Fatalf("依赖故障 + fail_closed 必须失败，实际 %v", err)
		}
		// 失败路径上没有 Output 可带 Attempts，尝试次数只能凭 transport 的留痕。
		if tr.calls != 1 {
			t.Errorf("非幂等出网 %d 次，想要 1", tr.calls)
		}
		if got := pipeEntry(t, res, "rc1").Outcome; got != ReasonFailed {
			t.Errorf("Outcome = %s", got)
		}
	})

	t.Run("幂等按预算重放到成功", func(t *testing.T) {
		spec := scSpec("rc2", policy.BodyInspect)
		cfg, tr := scConfig(nil)
		cfg.Idempotent = true
		cfg.MaxRetries = 2 // 额外两次 = 最多 3 次尝试
		tr.reply = flake
		res, err := scRun(t, spec, cfg, pipeRequest(t, "r-rt", NewBufferedBody([]byte("y"))))
		if err != nil {
			t.Fatalf("第三次应当成功: %v", err)
		}
		if tr.calls != 3 {
			t.Errorf("出网 %d 次，想要 3", tr.calls)
		}
		if got := pipeEntry(t, res, "rc2").Attempts; got != 3 {
			t.Errorf("审计里的尝试次数 = %d，想要 3（重试必须可审）", got)
		}
		// 每次尝试送的是同一份载荷：重放不能重新构造正文。
		if tr.bodies[0] != tr.bodies[2] {
			t.Error("重放的载荷与原请求不一致")
		}
	})

	t.Run("4xx 不重放", func(t *testing.T) {
		// 4xx 表示「这个请求本身不被接受」，重放同一个请求不会变好。
		spec := scSpec("rc-4xx", policy.BodyInspect)
		cfg, tr := scConfig(nil)
		cfg.Idempotent = true
		cfg.MaxRetries = 3
		tr.reply = func(int) (int, string) { return http.StatusUnprocessableEntity, `{"error":"bad"}` }
		if _, err := scRun(t, spec, cfg, pipeRequest(t, "r-4xx", NewBufferedBody([]byte("y")))); err == nil {
			t.Fatal("4xx 应失败")
		}
		if tr.calls != 1 {
			t.Errorf("4xx 重放了 %d 次，想要 1", tr.calls)
		}
	})

	t.Run("重试用尽报 ErrRetryExhausted", func(t *testing.T) {
		spec := scSpec("rc3", policy.BodyInspect)
		spec.FailClosed = true
		cfg, tr := scConfig(nil)
		cfg.Idempotent = true
		cfg.MaxRetries = 1
		tr.reply = func(int) (int, string) { return http.StatusServiceUnavailable, `{}` }
		if _, err := scRun(t, spec, cfg, pipeRequest(t, "r-ex", NewBufferedBody([]byte("y")))); err == nil {
			t.Fatal("重试用尽应失败")
		} else if !errors.Is(err, ErrRetryExhausted) {
			t.Errorf("应包 ErrRetryExhausted: %v", err)
		}
		if tr.calls != 2 {
			t.Errorf("出网 %d 次，想要 2（1 次原始 + 1 次重试）", tr.calls)
		}
	})

	t.Run("依赖故障在 fail_open 下降级为跳过", func(t *testing.T) {
		// §2.9 规则 5：只有基础设施故障允许被 fail_open 跳过 —— 判定与违规不行。
		spec := scSpec("rc4", policy.BodyInspect)
		spec.FailClosed = false
		cfg, tr := scConfig(nil)
		cfg.Idempotent = false
		tr.reply = func(int) (int, string) { return http.StatusBadGateway, `{}` }
		res, err := scRun(t, spec, cfg, pipeRequest(t, "r-fo", NewBufferedBody([]byte("y"))))
		if err != nil {
			t.Fatalf("fail_open 的依赖故障不该让请求失败: %v", err)
		}
		if got := pipeEntry(t, res, "rc4").Outcome; got != ReasonFailOpenSkipped {
			t.Errorf("Outcome = %s", got)
		}
		pipeHasReason(t, res, ReasonFailed)
	})
}

// TestSidecarVerdictAndReplaceConflicts 验两件事：判定拒绝是结论（fail_open 冲不掉），
// 以及 sidecar 给了新正文但档位不许替换时报错而不是二选一。
func TestSidecarVerdictAndReplaceConflicts(t *testing.T) {
	t.Run("判定拒绝无视 fail_open", func(t *testing.T) {
		spec := scSpec("v1", policy.BodyInspect)
		spec.FailClosed = false // 故意留 fail_open：结论不该被降级成「跳过」
		cfg, tr := scConfig(nil)
		tr.reply = func(int) (int, string) {
			return http.StatusOK, `{"allowed":false,"short_code":"policy:block;ignore-this"}`
		}
		res, err := scRun(t, spec, cfg, pipeRequest(t, "r-rj", NewBufferedBody([]byte("y"))))
		if !errors.Is(err, ErrSidecarReject) {
			t.Fatalf("sidecar 说拦下就必须拦下，实际 %v", err)
		}
		if got := pipeEntry(t, res, "v1").Outcome; got != ReasonSidecarReject {
			t.Errorf("Outcome = %s", got)
		}
		// 短码里的分隔符必须已被清洗 —— 原样拼进错误串等于让第三方伪造审计字段。
		if strings.Contains(err.Error(), "policy:block;") {
			t.Errorf("拒绝原因码未经清洗就进了错误信息: %v", err)
		}
	})

	t.Run("档位不许替换时拒绝而非猜", func(t *testing.T) {
		// inspect-body 档位的处理器拿到新正文：丢掉可能放走该被打码的内容，
		// 接受又越过档位 —— 只有失败是可审计的行为。
		spec := scSpec("v2", policy.BodyInspect)
		cfg, tr := scConfig(nil)
		tr.reply = func(int) (int, string) {
			return http.StatusOK, `{"allowed":true,"body":"替换后的正文"}`
		}
		_, err := scRun(t, spec, cfg, pipeRequest(t, "r-rp", NewBufferedBody([]byte("y"))))
		if !errors.Is(err, ErrBodyReplaceDenied) {
			t.Fatalf("应当 ErrBodyReplaceDenied，实际 %v", err)
		}
	})

	t.Run("档位允许时替换正文并释放原文", func(t *testing.T) {
		spec := scSpec("v2b", policy.BodyTransform)
		cfg, tr := scConfig(nil)
		tr.reply = func(int) (int, string) {
			return http.StatusOK, `{"allowed":true,"body":"替换后的正文","rewrites":[" pii "],"rewrites_extra":"ignored"}`
		}
		res, err := scRun(t, spec, cfg, pipeRequest(t, "r-rp2", NewBufferedBody([]byte("y"))))
		if err != nil {
			t.Fatalf("transform-body 应接受新正文: %v", err)
		}
		if string(res.Body) != "替换后的正文" {
			t.Errorf("Result.Body = %q", res.Body)
		}
		if !res.Buffered {
			t.Error("替换过正文必须标记 buffered（§2.9 规则 8 的接线契约）")
		}
		if !pipeEntry(t, res, "v2b").ReleaseOrigin {
			t.Error("原始正文应已释放")
		}
		if len(res.Rewrites) != 1 || res.Rewrites[0].Kind != "sidecar:pii" {
			t.Errorf("Rewrites = %+v，期望清洗后恰好一条 sidecar:pii", res.Rewrites)
		}
	})

	t.Run("缺少 allowed 字段不放行", func(t *testing.T) {
		// 「没说不行」不等于「行」：回复里缺判定结论时必须当成失败，
		// 否则一个改坏了的 sidecar（或一个空响应）就能让所有请求直通。
		spec := scSpec("v-noallowed", policy.BodyInspect)
		spec.FailClosed = true
		cfg, tr := scConfig(nil)
		tr.reply = func(int) (int, string) { return http.StatusOK, `{"action":"pass"}` }
		if _, err := scRun(t, spec, cfg, pipeRequest(t, "r-na", NewBufferedBody([]byte("y")))); err == nil {
			t.Fatal("缺 allowed 的回复不应放行")
		}
	})

	t.Run("响应尾部有多余内容按失败处理", func(t *testing.T) {
		spec := scSpec("v-tail", policy.BodyInspect)
		cfg, tr := scConfig(nil)
		tr.reply = func(int) (int, string) {
			return http.StatusOK, `{"allowed":true}{"allowed":false}`
		}
		if _, err := scRun(t, spec, cfg, pipeRequest(t, "r-tail", NewBufferedBody([]byte("y")))); err == nil {
			t.Fatal("多文档响应应失败（否则会静默采用第一个结论）")
		}
	})

	t.Run("外部字段进审计前必须过清洗", func(t *testing.T) {
		// 第三方服务的任何字段都是不可信输入：不清洗等于让它往我们日志里写任意串。
		spec := scSpec("v3", policy.BodyInspect)
		cfg, tr := scConfig(nil)
		tr.reply = func(int) (int, string) {
			return http.StatusOK, `{"allowed":true,"short_code":"a` + strings.Repeat("z", 400) +
				`;drop","action":"ok|audit"}`
		}
		res, err := scRun(t, spec, cfg, pipeRequest(t, "r-cl", NewBufferedBody([]byte("y"))))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Metadata) == 0 {
			t.Fatal("sidecar 的结论摘要必须留在 Result.Metadata 里供审计")
		}
		var meta map[string]string
		if uErr := json.Unmarshal(res.Metadata, &meta); uErr != nil {
			t.Fatalf("Result.Metadata 不是合法 JSON: %v (%s)", uErr, res.Metadata)
		}
		// 48 字节上限 + 只留 [A-Za-z0-9-_.]：外部输入被压回可审计的形态。
		if meta["short_code"] != "a"+strings.Repeat("z", 47) {
			t.Errorf("short_code 未截断/清洗: %q", meta["short_code"])
		}
		if meta["action"] != "okaudit" {
			t.Errorf("action 未清洗: %q", meta["action"])
		}
		// 整份 Result 里都不许出现未清洗的原始串（序列化后再查一次，防的是
		// 未来有人把外部字段原样塞进别的审计位）。
		blob, mErr := json.Marshal(res)
		if mErr != nil {
			t.Fatal(mErr)
		}
		if strings.Contains(string(blob), strings.Repeat("z", 400)) {
			t.Error("外部 short_code 未清洗就进了审计")
		}
	})
}
