package config

import "testing"

// TestParseProviderProtocol protocol 是封闭集：缺省 openai_chat、拼错即报错
// （不静默退化 —— 那会把「以为在打 Anthropic 端点」变成「实际在打 /chat/completions」）。
func TestParseProviderProtocol(t *testing.T) {
	cases := []struct {
		raw  string
		want string
		bad  bool
	}{
		{"", ProtocolOpenAIChat, false},
		{"  ", ProtocolOpenAIChat, false},
		{"openai_chat", ProtocolOpenAIChat, false},
		{"ollama_native", ProtocolOllamaNative, false},
		{"anthropic_messages", ProtocolAnthropicMessages, false},
		{"anthropci", "", true},
		{"openai", "", true}, // 只认全名，别让近似值混过去
	}
	for _, tc := range cases {
		got, err := ParseProviderProtocol(tc.raw, "providers[0]")
		if tc.bad {
			if err == nil {
				t.Fatalf("protocol=%q 应报错，拿到 %q", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("protocol=%q 不该报错: %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("protocol=%q → %q，想要 %q", tc.raw, got, tc.want)
		}
	}
}
