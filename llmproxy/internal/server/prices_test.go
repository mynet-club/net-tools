package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// hourFloor 把时刻按其所在 Location 的钟面截到整点，用于造合法的 valid_from。
func hourFloor(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location())
}

func priceHarness(t *testing.T) *muHarness {
	t.Helper()
	stub := newUsageStub(t, 0)
	return newMUHarnessWith(t, consumptionYAML(stub.srv.URL, testPricing))
}

func providerPriceBody(provider, model, validFrom string, out float64) map[string]any {
	return map[string]any{
		"provider": provider, "upstream_model": model,
		"valid_from": validFrom,
		"in_hit":     0.04, "in_miss": 2.0, "in_write": 2.5, "out": out,
		"note": "官网报价",
	}
}

func TestAdminProviderPriceRoundTrip(t *testing.T) {
	h := priceHarness(t)
	base := hourFloor(time.Now().Add(-2 * time.Hour))
	later := base.Add(time.Hour)

	resp, raw := h.put(t, "/v1/_admin/prices/provider", adminToken,
		providerPriceBody("neolink", "gp-5.6-so", base.Format(time.RFC3339), 9.0))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("写入价目应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "CNY") {
		t.Errorf("币种留空时应当默认 CNY: %s", raw)
	}
	if !strings.Contains(string(raw), "gp-5.6-so") {
		t.Errorf("返回体应当含插入的行: %s", raw)
	}

	// 查历史：应当只有这一条
	resp, raw = h.get(t, "/v1/_admin/prices/provider?provider=neolink&upstream_model=gp-5.6-so", adminToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("查历史应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), `"out":9`) {
		t.Errorf("历史里应当能看到 out=9: %s", raw)
	}

	// 插入更晚的一条 → 历史变成两条，旧的那条被收口
	resp, raw = h.put(t, "/v1/_admin/prices/provider", adminToken,
		providerPriceBody("neolink", "gp-5.6-so", later.Format(time.RFC3339), 7.0))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("写入第二条价目应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	resp, raw = h.get(t, "/v1/_admin/prices/provider?provider=neolink&upstream_model=gp-5.6-so", adminToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatal(string(raw))
	}
	var hist struct {
		Prices []map[string]any `json:"prices"`
	}
	if err := json.Unmarshal(raw, &hist); err != nil {
		t.Fatalf("解析历史失败: %v\n%s", err, raw)
	}
	if len(hist.Prices) != 2 {
		t.Fatalf("历史应当保留两条，实际 %d 条: %s", len(hist.Prices), raw)
	}
	if _, closed := hist.Prices[0]["valid_to"]; !closed {
		t.Errorf("旧行应当被收口（带 valid_to）: %v", hist.Prices[0])
	}
	if _, open := hist.Prices[1]["valid_to"]; open {
		t.Errorf("新行不该有 valid_to: %v", hist.Prices[1])
	}
	if v, _ := hist.Prices[0]["out"].(float64); v != 9 {
		t.Errorf("旧行 out 应当是 9，实际 %v", hist.Prices[0]["out"])
	}
	if v, _ := hist.Prices[1]["out"].(float64); v != 7 {
		t.Errorf("新行 out 应当是 7，实际 %v", hist.Prices[1]["out"])
	}

	// 当前在效价目：路由读的就是这份
	resp, raw = h.get(t, "/v1/_admin/prices/effective", adminToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("查在效价目应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), `"out":7`) {
		t.Errorf("在效价目应当是新价 out=7: %s", raw)
	}
}

func TestAdminPriceValidation(t *testing.T) {
	h := priceHarness(t)
	// 非整点：价格只在整点生效，拒绝、不静默取整
	resp, raw := h.put(t, "/v1/_admin/prices/provider", adminToken,
		map[string]any{"provider": "p", "upstream_model": "m",
			"valid_from": "2026-09-21T09:30:00+08:00", "out": 1})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("非整点 valid_from 应 400，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "整点") {
		t.Errorf("错误信息应当说明要整点: %s", raw)
	}
	// 时间格式非法
	resp, raw = h.put(t, "/v1/_admin/prices/provider", adminToken,
		map[string]any{"provider": "p", "upstream_model": "m", "valid_from": "昨晚九点", "out": 1})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "RFC3339") {
		t.Errorf("非法时间格式应 400 且说明 RFC3339，实际 %d: %s", resp.StatusCode, raw)
	}
	// 缺关键字段
	resp, raw = h.put(t, "/v1/_admin/prices/provider", adminToken,
		map[string]any{"upstream_model": "m", "valid_from": "2026-09-21T09:00:00+08:00"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("缺 provider 应 400，实际 %d: %s", resp.StatusCode, raw)
	}
	// 回填历史（只追加）
	base := hourFloor(time.Now().Add(-2 * time.Hour))
	if _, raw := h.put(t, "/v1/_admin/prices/provider", adminToken,
		providerPriceBody("append", "m", base.Add(time.Hour).Format(time.RFC3339), 2)); !strings.Contains(string(raw), "inserted") {
		t.Fatalf("前置插入失败: %s", raw)
	}
	resp, raw = h.put(t, "/v1/_admin/prices/provider", adminToken,
		providerPriceBody("append", "m", base.Format(time.RFC3339), 1))
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "只追加") {
		t.Errorf("插入更早的价目应 400 且说明只追加，实际 %d: %s", resp.StatusCode, raw)
	}
	// 查历史缺参数
	resp, raw = h.get(t, "/v1/_admin/prices/provider", adminToken)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("查历史缺参数应 400，实际 %d: %s", resp.StatusCode, raw)
	}
	// 未知路径
	resp, _ = h.get(t, "/v1/_admin/prices/nope", adminToken)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("未知路径应 404，实际 %d", resp.StatusCode)
	}
}

func TestAdminUserPriceAPI(t *testing.T) {
	h := priceHarness(t)
	base := hourFloor(time.Now().Add(-2 * time.Hour))
	body := func(scope, model string) map[string]any {
		return map[string]any{
			"scope": scope, "model": model,
			"valid_from": base.Format(time.RFC3339),
			"in_hit":     0.02, "in_miss": 1.0, "out": 4.0,
		}
	}
	// default + 单用户覆盖都能写
	resp, raw := h.put(t, "/v1/_admin/prices/user", adminToken, body("default", "fast"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("写 default 分发价应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	resp, raw = h.put(t, "/v1/_admin/prices/user", adminToken, body("user:arthur", "fast"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("写 user:arthur 分发价应 200，实际 %d: %s", resp.StatusCode, raw)
	}
	// 查历史
	resp, raw = h.get(t, "/v1/_admin/prices/user?scope=user:arthur&model=fast", adminToken)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"scope":"user:arthur"`) {
		t.Errorf("查 user:arthur 的价目失败: %d %s", resp.StatusCode, raw)
	}
	// 非法 scope
	resp, raw = h.put(t, "/v1/_admin/prices/user", adminToken, body("everyone", "fast"))
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "scope") {
		t.Errorf("非法 scope 应 400 且指出 scope，实际 %d: %s", resp.StatusCode, raw)
	}
	// 非管理员
	resp, _ = h.put(t, "/v1/_admin/prices/user", adminToken+"x", body("default", "nope"))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("非管理员应 403，实际 %d", resp.StatusCode)
	}
	// 路径里的冒号（user:arthur）要能安全传递 —— 用查询参数，不进路径
	resp, raw = h.get(t, "/v1/_admin/prices/user?scope=user%3Aarthur&model=fast", adminToken)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("URL 编码后的 scope 应能查询，实际 %d: %s", resp.StatusCode, raw)
	}
}

// 币种护栏：录价时与基准币不符要被拒，留空则填成基准币。
//
// 两张价目表都带 currency 列，但聚合、比价、报表都不看它 —— 换算还没实现。
// 在实现之前必须把混币种挡在门外，否则规则 B 会比出完全错误的结果
// （见 TestRuleBSkipsForeignCurrency），而报表的币种标签也会撒谎。
func TestPriceCurrencyGuard(t *testing.T) {
	h := priceHarness(t)
	base := hourFloor(time.Now().Add(-2 * time.Hour))

	// 1) 异币种被拒（上游价）
	body := providerPriceBody("neolink", "gp-5.6-so", base.Format(time.RFC3339), 9.0)
	body["currency"] = "USD"
	resp, raw := h.put(t, "/v1/_admin/prices/provider", adminToken, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("异币种应当被拒（400），实际 %d: %s", resp.StatusCode, raw)
	} else if !strings.Contains(string(raw), "基准币") {
		t.Errorf("错误信息该说清是币种与基准币不一致，实际：%s", raw)
	}

	// 2) 分发价一侧同样被拒
	resp, raw = h.put(t, "/v1/_admin/prices/user", adminToken, map[string]any{
		"scope": "default", "model": "sys-model",
		"valid_from": base.Format(time.RFC3339),
		"in_miss":    2.0, "out": 8.0, "currency": "USD",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("分发价的异币种也应当被拒，实际 %d: %s", resp.StatusCode, raw)
	}

	// 3) 留空 → 填成基准币（testPricing 里是 CNY）。
	//    必须在这一层填，不能留给 store 去填它硬编码的 "CNY" ——
	//    那样在基准币不是 CNY 时会存进一个与基准币不符的值，再被比价护栏悄悄排除掉。
	body = providerPriceBody("neolink", "gp-5.6-so", base.Format(time.RFC3339), 9.0)
	resp, raw = h.put(t, "/v1/_admin/prices/provider", adminToken, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("留空币种不该被拒，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), `"currency":"CNY"`) {
		t.Errorf("留空时应当填成基准币 CNY，实际：%s", raw)
	}

	// 4) 大小写不同但是同一个币种 → 接受，并归一成基准币的写法
	//    （不归一的话后续 sameCurrency 之外的直接字符串比较会对不上）
	body = providerPriceBody("neolink", "gp-5.6-so", base.Add(time.Hour).Format(time.RFC3339), 9.0)
	body["currency"] = "cny"
	resp, raw = h.put(t, "/v1/_admin/prices/provider", adminToken, body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("cny 与 CNY 是同一个币种，不该被拒，实际 %d: %s", resp.StatusCode, raw)
	} else if !strings.Contains(string(raw), `"currency":"CNY"`) {
		t.Errorf("应当归一成基准币的写法 CNY，实际：%s", raw)
	}
}
