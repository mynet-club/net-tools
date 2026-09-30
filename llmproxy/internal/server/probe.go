package server

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// activeProbe 定时探活系统池上游：只发一次极轻的 GET /models，
// 失败就 ReportFailureFor，成功就 ReportSuccessFor —— 熔断不必等真实用户请求撞上去。
//
// 刻意：
//   - 只探**系统池**（运营者自己的机器）；用户 BYO 上游不探 —— 那是用户的资产，
//     网关定期打他家 API 既费钱又奇怪。
//   - 失败**只记熔断计数**，不改配置、不摘供应商。
//   - 间隔内并发上限 2，超时 5s，绝不拖慢转发。
type activeProbe struct {
	interval time.Duration
	client   *http.Client
	stop     chan struct{}
	once     sync.Once
}

func newActiveProbe(interval time.Duration) *activeProbe {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &activeProbe{
		interval: interval,
		client:   &http.Client{Timeout: 5 * time.Second},
		stop:     make(chan struct{}),
	}
}

// Start 起探活循环；Stop 幂等。
func (p *activeProbe) Start(s *Server) {
	if p == nil {
		return
	}
	go func() {
		t := time.NewTicker(p.interval)
		defer t.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-t.C:
				p.round(s)
			}
		}
	}()
}

func (p *activeProbe) Stop() {
	if p == nil {
		return
	}
	p.once.Do(func() { close(p.stop) })
}

func (p *activeProbe) round(s *Server) {
	provs := s.globalProviders()
	sem := make(chan struct{}, 2)
	var wg sync.WaitGroup
	for _, prov := range provs {
		if !prov.Enabled || prov.BaseURL == "" {
			continue
		}
		prov := prov
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			p.one(s, prov.Name, prov.BaseURL, prov.APIKey)
		}()
	}
	wg.Wait()
}

func (p *activeProbe) one(s *Server, name, baseURL, apiKey string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/models", nil)
	if err != nil {
		return
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		s.router.ReportFailureFor("", name, err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		s.router.ReportFailureFor("", name, errHTTP(resp.StatusCode))
		return
	}
	// 401/403/404 也算「活着」：服务在应答，只是这个探针姿势不对
	s.router.ReportSuccessFor("", name)
}

type errHTTP int

func (e errHTTP) Error() string { return "probe got HTTP " + itoaHTTP(int(e)) }

func itoaHTTP(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
