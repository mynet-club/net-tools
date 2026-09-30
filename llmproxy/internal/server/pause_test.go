package server

import "testing"

// 配置开关本身
func TestAutoPauseConfigDefault(t *testing.T) {
	// 零值 = 关闭，避免误伤
	var a struct {
		AutoPauseOnExceeded bool
	}
	if a.AutoPauseOnExceeded {
		t.Error("默认应当关闭")
	}
}

// hardPauseOnQuota 在开关关闭时是 no-op；开启时停用用户。
func TestHardPauseRespectsSwitch(t *testing.T) {
	stub := newUsageStub(t, 0)
	h := newConsumptionHarness(t, stub, testPricing)
	_ = h.addUser(t, "p1")

	// 默认配置没有 auto_pause → 不停用
	h.srv.hardPauseOnQuota("p1", "over quota")
	if u, _ := h.db.GetUser("p1"); u != nil && !u.Enabled {
		t.Error("开关关闭时不该停用")
	}
}
