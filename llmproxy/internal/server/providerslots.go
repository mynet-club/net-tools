package server

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

// providerSlots 是按供应商的并发信号量表（providers[].max_concurrent，0 = 不限）。
//
// 语义是**排队不丢**：拿不到槽就在请求自己的 ctx 期限内等，到期即这次交换失败 ——
// 「这家忙」不能被记成「这家挂了」，静默换下一家更糟（会把限流摊给无辜的上游，
// 还会让熔断把一家健康但忙的后端误判成故障）。帽在配置里改了就换新通道生效，
// 旧通道的持有者照旧归还到旧通道（release 闭包捕获的是当时的通道）。
type providerSlots struct {
	mu    sync.Mutex
	chans map[string]chan struct{}
	caps  map[string]int
}

func newProviderSlots() *providerSlots {
	return &providerSlots{chans: map[string]chan struct{}{}, caps: map[string]int{}}
}

// acquire 占一个槽；返回的 release 必须调用（挂在响应体 Close 上，见 releaseOnClose）。
func (p *providerSlots) acquire(ctx context.Context, prov *config.Provider) (func(), error) {
	if prov == nil || prov.MaxConcurrent <= 0 {
		return func() {}, nil
	}
	p.mu.Lock()
	ch := p.chans[prov.Name]
	if ch == nil || p.caps[prov.Name] != prov.MaxConcurrent {
		ch = make(chan struct{}, prov.MaxConcurrent)
		p.chans[prov.Name] = ch
		p.caps[prov.Name] = prov.MaxConcurrent
	}
	p.mu.Unlock()

	select {
	case ch <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-ch }) }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("上游 %s 并发已满（上限 %d），排队等到请求期限: %w",
			prov.Name, prov.MaxConcurrent, ctx.Err())
	}
}

// releaseOnClose 在响应体 Close 的一瞬归还并发槽：非流式在 relay 读完关、
// 流式在整个流转发完关 —— 槽的占用期与「这次交换」严格同长，不多占也不早放。
type releaseOnClose struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (r *releaseOnClose) Close() error {
	err := r.ReadCloser.Close()
	r.once.Do(r.release)
	return err
}
