package config

import (
	"net/url"
	"strings"
	"testing"
)

// base_url 里一个 `?` 就能把下游路径吃进 query：转发时上游 URL 是
// `base_url + 下游路径后缀` 直接拼出来的，所以 `http://host/_search?x=` 拼上
// `/chat/completions` 之后，真正打出去的是 `/_search?x=/chat/completions`。
// 下游的 POST 路径白名单管不住这个 —— 那条路径是 base_url 自己带的。
func TestParseBaseURLRejectsQueryAndFragment(t *testing.T) {
	bad := []string{
		"http://10.0.0.5:9200/_search?x=",
		"http://api.example.com/v1?a=1",
		"https://api.example.com/v1#frag",
		"https://api.example.com/v1?",
	}
	for _, raw := range bad {
		if _, err := ParseBaseURL(raw); err == nil {
			t.Errorf("%q 应当被拒（带 query/anchor 就能绕过下游路径白名单）", raw)
		} else if !strings.Contains(err.Error(), "?") {
			t.Errorf("%q 的错误该说清是 ? / # 的问题，实际：%v", raw, err)
		}
	}

	good := []string{
		"https://api.openai.com/v1",
		"http://127.0.0.1:11434/v1",
		"https://api.example.com/v1/",
	}
	for _, raw := range good {
		if _, err := ParseBaseURL(raw); err != nil {
			t.Errorf("%q 不该被拒: %v", raw, err)
		}
	}
}

func TestParseBaseURLSchemeAndHost(t *testing.T) {
	for _, raw := range []string{"", "   ", "ftp://x/v1", "file:///etc/passwd", "gopher://x:1/", "not a url", "api.example.com/v1"} {
		if _, err := ParseBaseURL(raw); err == nil {
			t.Errorf("%q 应当被拒", raw)
		}
	}
}

// 出网校验的两档界线：link-local（云元数据所在）一律拒绝、没有开关；
// 回环与私网段只在 strict 时拒绝 —— 否则「上游是本机 ollama」这类正当用法会被打断，
// 而本项目的测试与 e2e 也全靠回环上的假上游。
func TestCheckUpstreamEgress(t *testing.T) {
	mustURL := func(raw string) *url.URL {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("解析 %q: %v", raw, err)
		}
		return u
	}

	// 一律拒绝：link-local（含云元数据 169.254.169.254）与未指定地址
	alwaysBlocked := []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/role",
		"http://169.254.1.1/v1",
		"http://[fe80::1]/v1",
		"http://0.0.0.0:8080/v1",
		"http://[::]/v1",
		// IPv4-mapped IPv6：不还原成点分十进制就会漏判
		"http://[::ffff:169.254.169.254]/v1",
	}
	for _, raw := range alwaysBlocked {
		for _, strict := range []bool{false, true} {
			if err := CheckUpstreamEgress(mustURL(raw), strict); err == nil {
				t.Errorf("%q 在 strict=%v 下应当被拒（云元数据永远不是合法上游）", raw, strict)
			}
		}
	}

	// 默认放行、strict 时拒绝：回环与私网段
	strictOnly := []string{
		"http://127.0.0.1:11434/v1",
		"http://[::1]/v1",
		"http://10.0.0.5:9200/v1",
		"http://192.168.1.1/v1",
		"http://172.16.0.1/v1",
		"http://[fd00::1]/v1",
		"http://[::ffff:127.0.0.1]/v1",
	}
	for _, raw := range strictOnly {
		if err := CheckUpstreamEgress(mustURL(raw), false); err != nil {
			t.Errorf("%q 默认不该被拒（本机/同网段的推理服务器是正当用法）: %v", raw, err)
		}
		if err := CheckUpstreamEgress(mustURL(raw), true); err == nil {
			t.Errorf("%q 在 strict 下应当被拒", raw)
		}
	}

	// 公网地址两档都放行
	for _, raw := range []string{"https://api.openai.com/v1", "http://8.8.8.8/v1", "https://api.deepseek.com/v1"} {
		for _, strict := range []bool{false, true} {
			if err := CheckUpstreamEgress(mustURL(raw), strict); err != nil {
				t.Errorf("%q 在 strict=%v 下不该被拒: %v", raw, strict, err)
			}
		}
	}
}

// 主机名解析到内网地址时也要拦住 —— 只判 IP 字面量的话，
// 攻击者用一个指向 169.254.169.254 的域名就绕过去了。
func TestCheckUpstreamEgressResolvesHostname(t *testing.T) {
	u, err := url.Parse("http://localhost/v1")
	if err != nil {
		t.Fatal(err)
	}
	// localhost 解析到 127.0.0.1（可能还有 ::1），strict 下必须被拒
	if err := CheckUpstreamEgress(u, true); err == nil {
		t.Error("localhost 在 strict 下应当被拒（它解析到回环地址）")
	}
	// 默认档下放行，与直接写 127.0.0.1 的行为一致
	if err := CheckUpstreamEgress(u, false); err != nil {
		t.Errorf("localhost 默认不该被拒: %v", err)
	}
}
