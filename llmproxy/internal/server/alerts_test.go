package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestQuotaAlertWarnAndExceededOnce(t *testing.T) {
	var got int64
	var mu sync.Mutex
	var last map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&got, 1)
		mu.Lock()
		_ = json.NewDecoder(r.Body).Decode(&last)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	a := newQuotaAlert(srv.URL, 0.8)
	fixed := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return fixed }

	// 50% 不告警
	if lvl := a.Check("u", 50, 100, 0, 0); lvl != "" {
		t.Errorf("50%% 不该告警: %q", lvl)
	}
	// 85% → warn，只发一次
	if lvl := a.Check("u", 85, 100, 0, 0); lvl != alertLevelWarn {
		t.Errorf("85%% 应为 warn，实际 %q", lvl)
	}
	if lvl := a.Check("u", 86, 100, 0, 0); lvl != "" {
		t.Errorf("同月 warn 不应重复: %q", lvl)
	}
	// 100% → exceeded
	if lvl := a.Check("u", 100, 100, 0, 0); lvl != alertLevelExceeded {
		t.Errorf("100%% 应为 exceeded，实际 %q", lvl)
	}
	// 等 webhook
	time.Sleep(100 * time.Millisecond)
	if atomic.LoadInt64(&got) != 2 {
		t.Errorf("应当 2 次 webhook（warn+exceeded），实际 %d", got)
	}
	// 异步交付顺序不定：只要 warn 与 exceeded 各到一次即可
	mu.Lock()
	defer mu.Unlock()
	if last["user"] != "u" {
		t.Errorf("payload 不对: %+v", last)
	}
}
