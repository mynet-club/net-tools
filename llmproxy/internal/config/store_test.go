package config

import (
	"strings"
	"testing"
)

// equalBaseSrc 是不含任何 3.0 声明段的最小可用配置，供 configEqual 的比较测试用。
const equalBaseSrc = `
server:
  host: 127.0.0.1
  port: 8787
  api_keys: [sk-x]

routing: {retry: 2, failure_threshold: 3, cooldown_seconds: 60}
providers:
  - name: p
    enabled: true
    base_url: https://api.example.com/v1
    api_key: k
    models: ["*"]
database: {path: ""}
log: {level: info}
`

// parseForEqual 解析一份最小可用配置，供 configEqual 的比较测试用。
func parseForEqual(t *testing.T, serverExtra, dbExtra string) *Config {
	t.Helper()
	src := `
server:
  host: 127.0.0.1
  port: 8787
  api_keys: [sk-x]
` + serverExtra + `
routing: {retry: 2, failure_threshold: 3, cooldown_seconds: 60}
providers:
  - name: p
    enabled: true
    base_url: https://api.example.com/v1
    api_key: k
    models: ["*"]
database: {path: ""` + dbExtra + `}
log: {level: info}
`
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("解析失败: %v\n%s", err, src)
	}
	return cfg
}

// 同一份配置解析两次必须判为相等。
//
// 这条钉住的是一个很容易踩的坑：Config 里有指针型的可选字段
// （DatabaseConfig.RetainDays、ServerConfig.StreamIdleTimeoutMs / AffinityTTLMs，
// 用指针是为了区分「没配」与「显式写 0」），而**结构体含指针字段时 `!=` 比的是
// 指针身份**。两次 Parse 各自分配一个 int，于是直接写 `a.Database != b.Database`
// 会恒为真 —— 任何一次配置保存都会被判成「变了」，重载回调白跑一遍，
// 并且 srv.Transports().Reset() 把上游连接池全部丢掉。
func TestConfigEqualIdenticalReparses(t *testing.T) {
	a := parseForEqual(t, "", "")
	b := parseForEqual(t, "", "")
	if !configEqual(a, b) {
		t.Error("同一份配置解析两次应当判为相等（指针型字段必须按值比较，不能比指针身份）")
	}
	// 带显式值的也要相等：这时两边各有自己的 *int，同样不能比指针
	c := parseForEqual(t, "  affinity_ttl_ms: 3600000\n  stream_idle_timeout_ms: 90000\n", ", retain_days: 30")
	d := parseForEqual(t, "  affinity_ttl_ms: 3600000\n  stream_idle_timeout_ms: 90000\n", ", retain_days: 30")
	if !configEqual(c, d) {
		t.Error("显式给了指针型字段的同一份配置也应当判为相等")
	}
}

// 「没配」与「显式写成默认值」行为完全一致，就该判为相等，
// 不该触发一次无谓的重载（那会白白丢掉连接池）。
func TestConfigEqualUnsetMatchesExplicitDefault(t *testing.T) {
	unset := parseForEqual(t, "", "")
	explicit := parseForEqual(t, "  affinity_ttl_ms: 86400000\n  stream_idle_timeout_ms: 120000\n", ", retain_days: 90")
	if !configEqual(unset, explicit) {
		t.Error("「没配」与「显式写默认值」应当判为相等（两者运行时行为一致）")
	}
}

// 会影响运行时行为的字段改了，必须被判为「变了」——
// 否则重载回调直接 return，改动静默不生效。
func TestConfigEqualDetectsRuntimeRelevantChanges(t *testing.T) {
	base := parseForEqual(t, "", "")

	cases := []struct {
		name        string
		serverExtra string
		dbExtra     string
	}{
		// affinity_ttl_ms 被缓存在 affinityStore 里、不是每请求实时读，
		// 漏比它的话「改成 0 关掉粘性」这个操作会完全无效且毫无提示
		{"affinity_ttl_ms", "  affinity_ttl_ms: 0\n", ""},
		{"affinity_ttl_ms 改值", "  affinity_ttl_ms: 3600000\n", ""},
		{"stream_idle_timeout_ms", "  stream_idle_timeout_ms: 30000\n", ""},
		{"admin_token", "  admin_token: sk-admin\n", ""},
		{"block_local_upstream", "  block_local_upstream: true\n", ""},
		{"max_body_mb", "  max_body_mb: 32\n", ""},
		{"request_timeout_ms", "  request_timeout_ms: 60000\n", ""},
		{"retain_days", "", ", retain_days: 7"},
		{"retain_days 归零", "", ", retain_days: 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := parseForEqual(t, tc.serverExtra, tc.dbExtra)
			if configEqual(base, changed) {
				t.Errorf("%s 改了却判为相等 —— 重载回调会直接 return，这个改动静默不生效", tc.name)
			}
			if configEqual(changed, base) {
				t.Errorf("%s 的比较不对称", tc.name)
			}
		})
	}
}

// 日志级别与警告不参与「是否变更」的判定：它们不影响转发行为，
// 为它们丢一次连接池不值。
func TestConfigEqualIgnoresLogLevel(t *testing.T) {
	a := parseForEqual(t, "", "")
	b := parseForEqual(t, "", "")
	b.Log.Level = "debug"
	if !configEqual(a, b) {
		t.Error("只改日志级别不该被判为配置变更")
	}
}

// 两段声明表（§3.H）必须进「是否变更」的比较。
//
// 漏掉它们的表现和 policyEqual 那段记的同一类事故，而且更难查：只改处理器或知识源声明
// 会被判成「配置没变」→ revision 不推进 → 重载回调直接 return → 管理台一直报
// 「还在等热加载」，而运维无法判断那份脱敏声明到底进没进运行时。
// 反向也一样要紧：同一份声明解析两次必须判等，否则每次保存配置都白丢一次上游连接池
// （fail_closed 是 *bool，ProcessorDef 直接 `!=` 会比指针身份）。
func TestConfigEqualIdenticalDeclarationsReparses(t *testing.T) {
	decl := "processors:\n" +
		"  - name: pii-out\n    type: result-filter\n    phase: after-upstream\n    scope: organization:u1\n" +
		"    version: \"2\"\n    body_access: inspect-body\n    fail_closed: true\n" +
		"    timeout_ms: 2000\n    max_input_bytes: 65536\n    max_output_bytes: 65536\n" +
		"knowledge_sources:\n" +
		"  - name: campus-rag\n    endpoint: https://rag.internal.example/v1/retrieve\n" +
		"    knowledge_bases: [kb-course, kb-lab]\n    timeout_ms: 3000\n    max_response_bytes: 1048576\n"
	a, err := Parse(append([]byte(equalBaseSrc), []byte(decl)...))
	if err != nil {
		t.Fatalf("带声明的基线解析失败: %v", err)
	}
	b, err := Parse(append([]byte(equalBaseSrc), []byte(decl)...))
	if err != nil {
		t.Fatalf("同一份内容第二次解析失败: %v", err)
	}
	if !configEqual(a, b) {
		t.Error("同一份声明解析两次应当判为相等（指针型与切片字段都得按值比）")
	}
	// 写法不同、语义相同：知识库 ID 末尾多一个空格，加载期都会清理，不该触发重载
	c, err := Parse(append([]byte(equalBaseSrc), []byte(strings.Replace(decl, "kb-course,", "kb-course ,", 1))...))
	if err != nil {
		t.Fatalf("清理写法解析失败: %v", err)
	}
	if !configEqual(a, c) {
		t.Error("「kb-course」与「kb-course 」是同一个知识库 ID，不该判为变更")
	}
}

// 声明表的每一处语义变化都要被判成「变了」：这些字段决定的正是
// 「正文能不能离开网关」「处理器出错时放行还是拒」。
func TestConfigEqualDetectsDeclarationChanges(t *testing.T) {
	const oneProc = "processors:\n" +
		"  - name: pii-out\n    type: pii-mask\n    phase: before-upstream\n    scope: \"*\"\n" +
		"    version: \"1\"\n    body_access: transform-body\n    fail_closed: true\n" +
		"    timeout_ms: 2000\n    max_input_bytes: 65536\n    max_output_bytes: 65536\n"
	base, err := Parse([]byte(equalBaseSrc))
	if err != nil {
		t.Fatalf("无声明的基线解析失败: %v", err)
	}
	withOne, err := Parse(append([]byte(equalBaseSrc), []byte(oneProc)...))
	if err != nil {
		t.Fatalf("一条声明的解析失败: %v", err)
	}
	if configEqual(base, withOne) {
		t.Error("从无到有加了一条处理器声明却判为相等 —— 重载回调会直接 return")
	}
	if configEqual(withOne, base) {
		t.Error("删空整段声明却判为相等")
	}

	cases := []struct{ name, text string }{
		{"换阶段", strings.Replace(oneProc, "before-upstream", "before-route", 1)},
		{"换类型", strings.Replace(oneProc, "type: pii-mask", "type: field-replace", 1)},
		{"翻转失败策略", strings.Replace(oneProc, "fail_closed: true", "fail_closed: false", 1)},
		{"换范围", strings.Replace(oneProc, "scope: \"*\"", "scope: user:alice", 1)},
		{"改超时", strings.Replace(oneProc, "timeout_ms: 2000", "timeout_ms: 3000", 1)},
		{"改版本", strings.Replace(oneProc, "version: \"1\"", "version: \"2\"", 1)},
		{"加出网白名单", strings.Replace(oneProc, "    timeout_ms: 2000",
			"    allowed_endpoints: [https://sidecar.internal/v1/scan]\n    timeout_ms: 2000", 1)},
		{"加知识源", oneProc + "knowledge_sources:\n  - name: rag\n    endpoint: https://rag.internal/v1\n" +
			"    knowledge_bases: [kb-1]\n    timeout_ms: 3000\n    max_response_bytes: 1048576\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed, err := Parse(append([]byte(equalBaseSrc), []byte(tc.text)...))
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if configEqual(withOne, changed) {
				t.Errorf("%s 改了却判为相等 —— revision 不推进，界面会说「还在等热加载」", tc.name)
			}
			if configEqual(changed, withOne) {
				t.Errorf("%s 的比较不对称", tc.name)
			}
		})
	}
}
