package server

import (
	"net/http"
	"strings"
	"testing"
)

// 浏览器里的客户端（桌面设置页的「测试连接」）会先发 OPTIONS 预检。
// 没有这一层时预检拿到 405 且缺 Access-Control-Allow-*，浏览器把真请求掐掉，
// 前端只看到 `fetch failed` —— 而 curl 不走预检，于是「curl 通、界面失败」。
func TestCORSPreflightAllowsBrowserClients(t *testing.T) {
	h := newHarness(t, cfgYAML(map[string]string{"p": "http://127.0.0.1:9/v1"}, []string{"sk-static"}))

	req, err := http.NewRequest(http.MethodOptions, h.gateway.URL+"/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "app://mimo-desktop")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("预检请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		t.Fatalf("预检应当 204/200，实际 %d", resp.StatusCode)
	}
	for _, hname := range []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
	} {
		if resp.Header.Get(hname) == "" {
			t.Errorf("预检响应缺 %s", hname)
		}
	}
	if !strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Errorf("Allow-Headers 应当放行 Authorization，实际 %q", resp.Header.Get("Access-Control-Allow-Headers"))
	}
	if !strings.Contains(resp.Header.Get("Access-Control-Allow-Methods"), http.MethodGet) {
		t.Errorf("Allow-Methods 应当含 GET，实际 %q", resp.Header.Get("Access-Control-Allow-Methods"))
	}
}

// 真请求也要带 CORS 头，否则浏览器读不到响应体。
func TestCORSHeadersOnRealRequest(t *testing.T) {
	h := newHarness(t, cfgYAML(map[string]string{"p": "http://127.0.0.1:9/v1"}, []string{"sk-static"}))

	resp, _ := h.get(t, "/v1/models", "sk-static")
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got == "" {
		t.Error("真请求响应缺 Access-Control-Allow-Origin")
	}
	// 鉴权不受影响：没 key 仍然是 401
	resp2, body := h.get(t, "/v1/models", "")
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("无 key 应当 401，实际 %d body=%s", resp2.StatusCode, body)
	}
	if resp2.Header.Get("Access-Control-Allow-Origin") == "" {
		t.Error("401 响应也应当带 CORS 头，否则浏览器读不到错误正文")
	}
}

// OPTIONS 不该落到各 handler 的「只支持 GET」上。
func TestCORSOptionsDoesNotHitMethodCheck(t *testing.T) {
	h := newHarness(t, cfgYAML(map[string]string{"p": "http://127.0.0.1:9/v1"}, []string{"sk-static"}))

	req, _ := http.NewRequest(http.MethodOptions, h.gateway.URL+"/v1/chat/completions", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusMethodNotAllowed {
		t.Fatalf("OPTIONS 不该 405，实际 %d", resp.StatusCode)
	}
}
