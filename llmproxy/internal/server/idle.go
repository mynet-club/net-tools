package server

import (
	"context"
	"sync"
	"time"
)

// idleWatchdog 是流式请求的「没动静就判失败」看门狗。
//
// 为什么流式不能用总时限：一次长回答可以正常跑好几分钟，按总时限掐会把好端端的流切断；
// 反过来上游卡死不动时，又希望早点失败而不是耗满总时限。所以流式只问「多久没收到数据」。
//
// 用法：Touch() 每次收到字节就调一次（响应头到达也算），超时则 cancel 掉上游请求；
// Fired() 用来在错误信息里区分「空闲超时」和「客户端断开」——两者都会让读操作返回
// context canceled，不看这个标记就没法归因。
type idleWatchdog struct {
	idle   time.Duration
	cancel context.CancelFunc

	touch chan struct{}
	stop  chan struct{}

	mu      sync.Mutex
	fired   bool
	stopped bool
}

func newIdleWatchdog(idle time.Duration, cancel context.CancelFunc) *idleWatchdog {
	w := &idleWatchdog{
		idle:   idle,
		cancel: cancel,
		touch:  make(chan struct{}, 1),
		stop:   make(chan struct{}),
	}
	go w.run()
	return w
}

func (w *idleWatchdog) run() {
	t := time.NewTimer(w.idle)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-w.touch:
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
			t.Reset(w.idle)
		case <-t.C:
			w.mu.Lock()
			w.fired = true
			w.mu.Unlock()
			w.cancel()
			return
		}
	}
}

// Touch 报告「有数据在动」。非阻塞：信号通道满就说明看门狗马上会重置，不必排队。
func (w *idleWatchdog) Touch() {
	if w == nil {
		return
	}
	select {
	case w.touch <- struct{}{}:
	default:
	}
}

// Stop 结束看门狗。重复调用安全。
func (w *idleWatchdog) Stop() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	w.stopped = true
	close(w.stop)
}

func (w *idleWatchdog) Fired() bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fired
}

func (w *idleWatchdog) Idle() time.Duration {
	if w == nil {
		return 0
	}
	return w.idle
}

// activityReader 把「读到字节」这件事报给看门狗。包一层比改 io.Copy 循环干净：
// 流式与非流式共用同一条转发路径，只有带看门狗时才有这个包装。
type activityReader struct {
	r     interface{ Read([]byte) (int, error) }
	touch func()
}

func (a *activityReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if n > 0 && a.touch != nil {
		a.touch()
	}
	return n, err
}
