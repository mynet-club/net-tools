package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// 配额预警：用量越过 warn 比例或 100% 时告警一次（每用户每档每自然月一次）。
// 外呼在 goroutine 里做，**绝不阻塞**转发路径；失败只记日志。
type quotaAlert struct {
	webhook string
	ratio   float64
	now     func() time.Time

	mu    sync.Mutex
	fired map[string]bool // key: user|level|month
}

const (
	alertLevelWarn     = "quota_warn"
	alertLevelExceeded = "quota_exceeded"
)

func newQuotaAlert(webhook string, ratio float64) *quotaAlert {
	if ratio <= 0 || ratio > 1 {
		ratio = 0.8
	}
	return &quotaAlert{
		webhook: webhook,
		ratio:   ratio,
		now:     time.Now,
		fired:   map[string]bool{},
	}
}

// Check 在配额判断之后调用。used/limit ≤ 0 表示该项不限。
// level 为空表示未越线。
func (a *quotaAlert) Check(user string, usedTokens, limitTokens int64, usedCost, limitCost float64) (level string) {
	if a == nil || user == "" {
		return ""
	}
	ratio, hitTokens, hitCost := a.ratio, false, false
	var tokenRatio, costRatio float64
	if limitTokens > 0 {
		tokenRatio = float64(usedTokens) / float64(limitTokens)
		hitTokens = true
	}
	if limitCost > 0 {
		costRatio = usedCost / limitCost
		hitCost = true
	}
	if !hitTokens && !hitCost {
		return ""
	}

	switch {
	case (hitTokens && tokenRatio >= 1) || (hitCost && costRatio >= 1):
		level = alertLevelExceeded
	case (hitTokens && tokenRatio >= ratio) || (hitCost && costRatio >= ratio):
		level = alertLevelWarn
	default:
		return ""
	}

	key := fmt.Sprintf("%s|%s|%s", user, level, a.now().Format("2006-01"))
	a.mu.Lock()
	already := a.fired[key]
	if !already {
		a.fired[key] = true
	}
	a.mu.Unlock()
	if already {
		return ""
	}

	payload := map[string]any{
		"event":        level,
		"user":         user,
		"month":        a.now().Format("2006-01"),
		"used_tokens":  usedTokens,
		"limit_tokens": limitTokens,
		"used_cost":    usedCost,
		"limit_cost":   limitCost,
		"warn_ratio":   ratio,
		"ts":           a.now().UTC().Format(time.RFC3339),
	}
	go a.deliver(payload)
	return level
}

// Emit 发一条通用事件（fire-and-forget）。事件名见 roadmap：request.failed /
// quota.exceeded / circuit.open / user.auto_pause。
func (s *Server) Emit(event string, fields map[string]any) {
	if s == nil {
		return
	}
	cfg := s.cfgStore.Current()
	url := ""
	if cfg != nil {
		url = cfg.Alerts.WebhookURL
	}
	payload := map[string]any{"event": event, "ts": time.Now().UTC().Format(time.RFC3339)}
	for k, v := range fields {
		payload[k] = v
	}
	// 没配 webhook 就只记日志（与配额预警同一约定）
	if url == "" {
		b, _ := json.Marshal(payload)
		s.log.Infof("事件 %s: %s", event, b)
		return
	}
	go (&quotaAlert{webhook: url}).deliver(payload)
}

func (a *quotaAlert) deliver(payload map[string]any) {
	body, _ := json.Marshal(payload)
	if a.webhook == "" {
		return // 只靠调用方日志
	}
	req, err := http.NewRequest(http.MethodPost, a.webhook, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "llmproxy-alerts/1")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("配额告警 webhook 失败: %v\n", err)
		return
	}
	_ = resp.Body.Close()
}

// hardPauseOnQuota：配额用尽时按配置自动停用用户（硬熔断）。
// 停用后下个请求走「账号已停用」，管理员 llmproxy user enable 一键恢复。
func (s *Server) hardPauseOnQuota(user, msg string) {
	if s == nil || s.db == nil {
		return
	}
	cfg := s.cfgStore.Current()
	if cfg == nil || !cfg.Alerts.AutoPauseOnExceeded {
		return
	}
	if err := s.db.SetUserEnabled(user, false); err != nil {
		s.log.Errorf("配额硬熔断停用用户 %s 失败: %v", user, err)
		return
	}
	s.auditUser("system", "user.auto_pause", user, msg)
	_ = s.SyncUsers()
	if s.meters != nil {
		s.meters.Forget(user)
	}
	s.log.Warnf("配额硬熔断：已停用用户 %s（%s），管理员 user enable 可恢复", user, msg)
}
