// llmproxy 是自用的 LLM 转发网关 CLI。
//
// 下游选模型，上游按权重与可用性选供应商；供应商写在 YAML 里，支持热加载。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/logx"
	"github.com/mynet-club/net-tools/llmproxy/internal/router"
	"github.com/mynet-club/net-tools/llmproxy/internal/secrets"
	"github.com/mynet-club/net-tools/llmproxy/internal/server"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

const usageText = `llmproxy %s — 自用 LLM 转发网关

用法:
  llmproxy <命令> [参数]

命令:
  init                初始化运行时目录并生成配置文件（已存在则不覆盖）
  start               前台启动服务
  stop                停止后台运行的服务
  restart             重启
  status              查看运行状态与各供应商可用性
  reload              热加载配置（向运行中的进程发 SIGHUP）
  providers           列出配置中的供应商与运行期状态
  user add <名字>      建一个用户并打印 token（明文只显示一次）
  user list           列出全部用户与累计用量
  user show <名字>     看某个用户的详情（上游、用量）
  user add-provider <用户> <上游名>   代用户配一个上游
  user rm-provider <用户> <上游名>    删掉某个上游
  user providers <名字> 列出某用户的上游（密钥只显示尾 4 位）
  user token <名字>    轮换 token（旧 token 立即失效）
  user enable|disable <名字>  启用 / 停用
  user usage <名字>    看某个用户的按日消耗
  user rm <名字>       删除用户及其全部上游
  stats [-days N] [-recent N]   查看消耗统计
  logs [-n N] [-f]    查看日志
  test [-model M] [-stream]     通过本机网关发一条测试请求
  admin token         打印管理凭证（管理台 /admin/ 用）
  admin rotate        轮换管理凭证并写回 config.yaml
  config get          列出可设置项的当前值
  config set <段.键> <值>  改一项（备份 → 校验 → 原子改名，2 秒内热加载）
  price list           列出当前生效的价目 / 指定键的全部历史
  price set provider <供应商> <上游模型> [选项]   录一条上游价
  price set user <scope> <模型> [选项]            录一条分发价
  service install     安装系统服务（macOS launchd / Linux systemd）
  service uninstall   卸载系统服务
  version             显示版本

环境变量:
  LLMPROXY_HOME       覆盖运行时目录（默认 ~/.config/llmproxy）

配置文件:
  <运行时目录>/config.yaml
`

func main() {
	if len(os.Args) < 2 {
		fmt.Printf(usageText, config.Version)
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	paths := config.DefaultPaths()

	var err error
	switch cmd {
	case "init":
		err = cmdInit(paths)
	case "start":
		err = cmdStart(paths)
	case "stop":
		err = cmdStop(paths)
	case "restart":
		if e := cmdStop(paths); e != nil && !os.IsNotExist(e) {
			fmt.Fprintf(os.Stderr, "停止失败: %v\n", e)
		} else {
			time.Sleep(400 * time.Millisecond)
		}
		err = cmdStart(paths)
	case "status":
		err = cmdStatus(paths)
	case "reload":
		err = cmdReload(paths)
	case "providers":
		err = cmdProviders(paths)
	case "stats":
		err = cmdStats(paths, args)
	case "logs":
		err = cmdLogs(paths, args)
	case "test":
		err = cmdTest(paths, args)
	case "user", "users":
		err = cmdUser(paths, args)
	case "admin":
		err = cmdAdmin(paths, args)
	case "config":
		err = cmdConfig(paths, args)
	case "price", "prices":
		err = cmdPrice(paths, args)
	case "service":
		if len(args) < 1 {
			err = fmt.Errorf("用法: llmproxy service install|uninstall")
			break
		}
		switch args[0] {
		case "install":
			err = cmdServiceInstall(paths)
		case "uninstall":
			err = cmdServiceUninstall(paths)
		default:
			err = fmt.Errorf("未知的 service 子命令 %q", args[0])
		}
	case "version", "-v", "--version":
		fmt.Println(config.Version)
	case "help", "-h", "--help":
		fmt.Printf(usageText, config.Version)
	default:
		fmt.Fprintf(os.Stderr, "未知命令 %q\n\n", cmd)
		fmt.Printf(usageText, config.Version)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

// ------------------------------------------------------------------ init

func cmdInit(paths config.Paths) error {
	if err := paths.Ensure(); err != nil {
		return err
	}
	if _, err := os.Stat(paths.ConfigFile); err == nil {
		fmt.Printf("配置文件已存在，未覆盖：%s\n", paths.ConfigFile)
		return nil
	}
	// 模板在源码树里；已安装到 /usr/local/bin 时回退到内置默认内容
	src := findTemplate(paths)
	var content []byte
	var err error
	if src != "" {
		content, err = os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("读取模板失败: %w", err)
		}
	} else {
		content = []byte(defaultConfigYAML)
	}
	if err := os.WriteFile(paths.ConfigFile, content, 0o600); err != nil {
		return fmt.Errorf("写入配置文件失败: %w", err)
	}
	fmt.Printf("已生成配置文件：%s\n", paths.ConfigFile)
	fmt.Printf("请编辑其中的 api_keys 与 providers，然后执行 llmproxy start\n")
	return nil
}

func findTemplate(paths config.Paths) string {
	// 相对本可执行文件的 ../config/config.example.yaml（开发/仓库内运行）
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "..", "config", "config.example.yaml")
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand
		}
	}
	// 相对工作目录
	cands := []string{
		"config/config.example.yaml",
		filepath.Join(filepath.Dir(paths.RuntimeDir), "config", "config.example.yaml"),
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

const defaultConfigYAML = `# llmproxy 配置
server:
  host: 127.0.0.1
  port: 8787
  api_keys:
    - sk-local-change-me
  max_body_mb: 16
  request_timeout_ms: 300000
  # 多用户（中转器）模式的管理凭证：设了才有 /v1/_admin，留空则管理接口整体关闭。
  # 用户本身用 llmproxy user add 管理（存在数据库里），不写在这份配置里。
  # admin_token: ${LLMPROXY_ADMIN_TOKEN}

routing:
  retry: 2
  failure_threshold: 3
  cooldown_seconds: 60

proxies:
  - name: local
    url: http://127.0.0.1:7890

providers:
  - name: openai-main
    enabled: true
    base_url: https://api.openai.com/v1
    api_key: ${OPENAI_API_KEY}
    weight: 10
    proxy: direct
    timeout_ms: 120000
    models:
      gpt-4o: gpt-4o
      gpt-4o-mini: gpt-4o-mini
  - name: any-model
    enabled: true
    base_url: https://api.deepseek.com/v1
    api_key: ${DEEPSEEK_API_KEY}
    weight: 3
    proxy: direct
    models: ["*"]

database:
  path: ""
  retain_days: 90

log:
  level: info
  max_mb: 10
  keep: 5
`

// ------------------------------------------------------------------ start

func cmdStart(paths config.Paths) error {
	if err := paths.Ensure(); err != nil {
		return err
	}

	// 已在运行则拒绝
	if pid, running := readPID(paths.PIDFile); running {
		return fmt.Errorf("已在运行（pid=%d）。先执行 llmproxy stop", pid)
	}

	storeCfg := config.NewStore(paths.ConfigFile)
	cfg, err := storeCfg.Load()
	if err != nil {
		return err
	}
	for _, w := range cfg.Warnings {
		fmt.Fprintf(os.Stderr, "警告: %s\n", w)
	}

	db, err := store.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer db.Close()

	r := router.New(cfg.Routing, cfg.Normalized)
	if persisted, err := db.LoadProviderStatus(); err == nil && len(persisted) > 0 {
		// 必须按作用域恢复：熔断状态是**分桶**的（全局池是 ""，每个用户自己的上游是用户名）。
		// 只写全局作用域的话，用户级熔断会被当成一个名叫 "alice/my-up" 的全局供应商恢复 ——
		// 既永远匹配不到真实供应商（重启即丢用户级熔断），又会被 30 秒后的
		// PersistProviderStatus 写回库，在 provider_stats 里长出幽灵行。
		scoped := make([]router.ScopedState, 0, len(persisted))
		for _, st := range persisted {
			scoped = append(scoped, router.ScopedState{
				Scope: st.Scope,
				Name:  st.Name,
				State: router.State{
					ConsecutiveFailures: st.ConsecutiveFailures,
					UnhealthyUntil:      st.UnhealthyUntil,
					TotalRequests:       st.TotalRequests,
					TotalFailures:       st.TotalFailures,
					LastError:           st.LastError,
					LastSuccessAt:       st.LastSuccessAt,
					LastFailureAt:       st.LastFailureAt,
				},
			})
		}
		r.RestoreScoped(scoped)
	}

	logPath := filepath.Join(paths.LogDir, config.ToolName+".log")
	lg := logx.New(logx.ParseLevel(cfg.Log.Level), logPath, cfg.Log.MaxMB, cfg.Log.Keep)
	defer lg.Close()

	srv := server.New(storeCfg, db, r, lg)

	// 多用户能力依赖主密钥（用户自带的上游密钥要加密落库）
	cipher, secErr := secrets.LoadOrCreate(paths.RuntimeDir)
	if secErr != nil {
		// 库里已经有用户却拿不到主密钥：拒绝启动。否则这些用户会莫名其妙地全部 401。
		if existing, _ := db.ListUsers(); len(existing) > 0 {
			return fmt.Errorf("库里已有 %d 个用户，但主密钥不可用（%s）: %w",
				len(existing), secrets.Path(paths.RuntimeDir), secErr)
		}
		lg.Warnf("多用户能力未启用（主密钥不可用: %v）", secErr)
	} else {
		srv.WithSecrets(cipher)
		if err := srv.SyncUsers(); err != nil {
			return fmt.Errorf("加载用户配置失败: %w", err)
		}
		if n := srv.UserCount(); n > 0 {
			lg.Infof("多用户模式已启用：%d 个用户（主密钥 %s）", n, secrets.Path(paths.RuntimeDir))
		}
	}

	// 三处重载路径（2 秒轮询回调、首个 SIGHUP、后续 SIGHUP）要做的事完全一样，
	// 所以抽成一个闭包 —— 之前正是因为抄了三份，affinity_ttl_ms 在三份里全漏了：
	// 它被缓存在 affinityStore 里、不像 stream_idle_timeout_ms 那样每请求实时读，
	// 于是运维改了这个值、SIGHUP 也发了、日志还说重载了，粘性行为却一点没变。
	applyCfg := func(newCfg *config.Config) {
		r.ApplyConfig(newCfg.Routing, newCfg.Normalized)
		srv.Transports().Reset() // 代理设置可能变了，丢弃旧连接池
		srv.SetAffinityTTL(time.Duration(newCfg.Server.AffinityTTL()) * time.Millisecond)
		lg.SetLevel(logx.ParseLevel(newCfg.Log.Level))
	}

	// 监听地址在启动时就绑定了、之后不会重绑，所以「需要重启才生效」的比较基准
	// 永远是**启动时**的值。用不可变的局部量而不是一个会被重载回调改写的共享 cfg ——
	// 后者既语义不对（该比的是进程实际在听的地址），又是跨 goroutine 的数据竞争。
	startHost, startPort := cfg.Server.Host, cfg.Server.Port

	// 配置热重载
	storeCfg.Watch(2*time.Second, func(ok, changed bool, newCfg *config.Config, err error) {
		if !ok {
			lg.Errorf("配置热加载失败，继续使用旧配置: %v", err)
			return
		}
		if !changed {
			return
		}
		lg.Infof("配置已热加载（供应商 %d 个）", len(newCfg.Normalized))
		for _, w := range newCfg.Warnings {
			lg.Warnf("配置警告: %s", w)
		}
		applyCfg(newCfg)
		if newCfg.Server.Host != startHost || newCfg.Server.Port != startPort {
			lg.Warnf("server.host/port 变更（%s:%d → %s:%d）需要重启才生效",
				startHost, startPort, newCfg.Server.Host, newCfg.Server.Port)
		}
	})
	defer storeCfg.Stop()

	// 信号处理
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// 周期性把供应商状态落库 + 清理过期日志 + 发现 CLI 在别的进程里改的用户配置
	stopHousekeep := make(chan struct{})
	go func() {
		slow := time.NewTicker(30 * time.Second)
		fast := time.NewTicker(2 * time.Second)
		defer slow.Stop()
		defer fast.Stop()
		for {
			select {
			case <-stopHousekeep:
				return
			case <-fast.C:
				// 用户/上游是由 CLI 或管理接口写进库的，这里按修订号增量刷新
				srv.SyncUsersIfChanged()
			case <-slow.C:
				if err := srv.PersistProviderStatus(); err != nil {
					lg.Warnf("保存供应商状态失败: %v", err)
				}
				// 走 storeCfg.Current()（atomic.Value）而不是闭包捕获的 cfg：
				// 这个 goroutine 与重载回调并发，读一个会被别处改写的局部变量是数据竞争。
				retainDays := 90
				if cur := storeCfg.Current(); cur != nil {
					retainDays = cur.Database.EffectiveRetainDays()
				}
				if n, err := db.Prune(retainDays); err == nil && n > 0 {
					lg.Debugf("清理 %d 条过期请求日志", n)
				}
			}
		}
	}()

	if err := writePID(paths.PIDFile); err != nil {
		lg.Warnf("写入 PID 文件失败: %v", err)
	}

	lg.Infof("llmproxy %s 启动，配置 %s，数据库 %s", config.Version, paths.ConfigFile, cfg.Database.Path)
	lg.Infof("供应商: %s", providerSummary(cfg.Normalized))

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start() }()

	select {
	case sig := <-sigCh:
		if sig == syscall.SIGHUP {
			// SIGHUP：热重载后继续运行
			lg.Infof("收到 SIGHUP，尝试热加载配置")
			changed, newCfg, err := storeCfg.Reload()
			if err != nil {
				lg.Errorf("SIGHUP 配置重载失败，继续使用旧配置: %v", err)
			} else if changed {
				applyCfg(newCfg)
				lg.Infof("SIGHUP 配置已重载（供应商 %d 个）", len(newCfg.Normalized))
			} else {
				lg.Infof("SIGHUP：配置无变化")
			}
			// 用户表一并刷新：CLI 的写操作与 `llmproxy reload` 都发 SIGHUP。
			// 不在这里同步的话，"改完立刻能用"就只能等下面那个 2 秒一次的轮询，
			// 而窗口期内的请求会吃到 401 —— 看起来像"用户没建成"。
			srv.SyncUsersIfChanged()
			srv.InvalidateUsageCache() // CLI 也可能刚改过价目，报表不能继续吐旧缓存
			// 继续等下一个信号
			for sig = range sigCh {
				if sig == syscall.SIGHUP {
					changed, newCfg, err := storeCfg.Reload()
					if err != nil {
						lg.Errorf("SIGHUP 配置重载失败: %v", err)
					} else if changed {
						applyCfg(newCfg)
						lg.Infof("SIGHUP 配置已重载")
					}
					srv.SyncUsersIfChanged()
					srv.InvalidateUsageCache()
					continue
				}
				break
			}
		}
		lg.Infof("收到 %v，开始优雅退出", sig)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			_ = os.Remove(paths.PIDFile)
			return err
		}
	}

	close(stopHousekeep)
	if err := srv.PersistProviderStatus(); err != nil {
		lg.Warnf("保存供应商状态失败: %v", err)
	}
	srv.Shutdown(10 * time.Second)
	_ = os.Remove(paths.PIDFile)
	lg.Infof("已退出")
	return nil
}

func providerSummary(ps []config.Provider) string {
	var parts []string
	for _, p := range ps {
		mark := "off"
		if p.Enabled {
			mark = fmt.Sprintf("w=%v", p.Weight)
		}
		scope := "any"
		if !p.Models.Passthrough {
			scope = fmt.Sprintf("%d models", len(p.Models.Map))
		}
		parts = append(parts, fmt.Sprintf("%s(%s,%s,proxy=%s)", p.Name, mark, scope, p.Proxy.Mode))
	}
	return strings.Join(parts, ", ")
}

// ------------------------------------------------------------------ pid / status

func writePID(path string) error {
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o600)
}

func readPID(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	// 通过信号 0 探测进程是否还在
	if err := syscall.Kill(pid, 0); err != nil {
		return pid, false
	}
	return pid, true
}

// healthURL 拼出健康端点地址。host 是通配（0.0.0.0 / :: / 空）时换成回环 ——
// 探测要的是一个能连的具体地址，而通配地址在 macOS 上连不通。
func healthURL(cfg *config.Config) string {
	host := "127.0.0.1"
	if cfg != nil {
		switch cfg.Server.Host {
		case "", "0.0.0.0", "::", "[::]", "*":
		default:
			host = cfg.Server.Host
		}
	}
	port := "8787"
	if cfg != nil && cfg.Server.Port != 0 {
		port = strconv.Itoa(cfg.Server.Port)
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz"
}

// serviceResponding 探测是否真的有一个 llmproxy 在应答。
//
// 这是给「要不要往这个 pid 发信号」把关的。readPID 只用 kill(pid, 0) 探活，
// 它证明的是「有这么个进程」，**不是**「这个进程是 llmproxy」：服务被 SIGKILL
// 或崩溃时不会清 PID 文件，那个 pid 之后可能被系统分配给完全无关的进程 ——
// 于是 `llmproxy stop` 会给它发 SIGTERM、CLI 写操作后的通知会给它发 SIGHUP，
// 而这两个信号的默认动作都是终止。
//
// 用健康端点而不是 /proc/<pid>/comm：后者在 macOS 上不存在，健康端点两个平台一样。
// 判据也不是「证明这个 pid 是 llmproxy」，而是「确实有一个 llmproxy 在服务」——
// 如果没有，那 PID 文件就是陈旧的，谁都不该发信号。
//
// cfg 为 nil 时直接报「不在服务」，不去猜默认地址：配置读不出来时无从知道该探
// 哪个端口，而 8787 上随便一个回 200 的服务都会被当成 llmproxy，进而给一个
// 可能无关的 pid 发终止信号。与 notifyRunningService 的「宁可不发」同一立场。
func serviceResponding(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(healthURL(cfg))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode == http.StatusOK
}

// cfgForSignal 读一份配置出来，只为了知道该探哪个地址。
// 读不出来就返回 nil —— serviceResponding(nil) 恒为 false，于是不发信号
// （宁可不发，也不要打错进程）。
func cfgForSignal(paths config.Paths) *config.Config {
	cfg, err := config.LoadFileLenient(paths.ConfigFile)
	if err != nil {
		return nil
	}
	return cfg
}

func cmdStop(paths config.Paths) error {
	pid, running := readPID(paths.PIDFile)
	if !running {
		_ = os.Remove(paths.PIDFile)
		fmt.Println("服务未在运行")
		return nil
	}
	cfg := cfgForSignal(paths)
	if !serviceResponding(cfg) {
		// 进程在、但服务不应答：可能是 llmproxy 卡死了，也可能是这个 pid 已经被
		// 别的进程复用。SIGTERM 会杀掉后者，所以不动手 —— 也不删 PID 文件
		// （万一那真是个卡死的 llmproxy，删了就再也找不回它了）。
		return fmt.Errorf("pid %d 存在，但 %s 没有应答，已跳过发信号\n"+
			"这个 pid 可能已被别的进程复用（服务被 SIGKILL 或崩溃时不会清 PID 文件）。\n"+
			"先确认它到底是谁：ps -p %d -o args=   ；确认是 llmproxy 再手动 kill %d",
			pid, healthURL(cfg), pid, pid)
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("发送 SIGTERM 给 pid %d 失败: %w", pid, err)
	}
	fmt.Printf("已发送停止信号给 pid %d\n", pid)
	// 等待退出
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if _, still := readPID(paths.PIDFile); !still {
			fmt.Println("已停止")
			return nil
		}
	}
	fmt.Fprintf(os.Stderr, "警告: pid %d 在 5 秒内未退出\n", pid)
	return nil
}

// fmtDur 把时长写成人看的形态（3h12m / 47s），不用读一个 180000 的数字。
func fmtDur(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd%02dh", int(d.Hours())/24, int(d.Hours())%24)
}

// cmdStatus 回答「这台网关现在到底是什么状态」。
//
// 以前它只报版本 / 供应商数 / 健康，而运维真正想知道的是四件事：跑着的是哪个版本、
// 各家供应商健不健康、这个月花了多少还剩多少配额、价目配齐了没有。这四件数据后端全都有
// （/healthz、/v1/_providers、usage_user_daily、user_prices），只是没拼在一起。
func cmdStatus(paths config.Paths) error {
	pid, running := readPID(paths.PIDFile)
	cfg, err := config.LoadFileLenient(paths.ConfigFile)
	if err != nil {
		fmt.Printf("配置   加载失败 — %v\n", err)
	} else {
		fmt.Printf("配置   %s\n", paths.ConfigFile)
		fmt.Printf("       供应商 %d 个，已启用 %d 个\n", len(cfg.Providers), countEnabled(cfg.Normalized))
		if cfg.Server.HasAdminToken() {
			fmt.Printf("       管理接口已开启（admin_token 已设）；用 `llmproxy admin token` 取值\n")
		} else {
			fmt.Printf("       管理接口未启用（server.admin_token 为空）\n")
		}
		if cfg.Server.BlockLocalUpstream {
			fmt.Printf("       出网校验：严格（用户自配上游不许指向回环/私网）\n")
		}
	}
	if !running {
		fmt.Println("服务   未运行")
		return nil
	}

	// 健康端点：版本、已运行多久、记账有没有丢
	uptime, version, persistFail := "未知", "未知", int64(-1)
	if cfg != nil {
		url := healthURL(cfg)
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			fmt.Printf("服务   pid %d 在，但 %s 连不上 —— 可能已卡死，也可能这个 pid 已被别的进程复用。\n",
				pid, url)
			fmt.Printf("       先 ps -p %d -o args= 确认它是谁，再决定要不要 kill。\n", pid)
			return nil
		}
		defer resp.Body.Close()
		var h struct {
			Version       string `json:"version"`
			UptimeS       int    `json:"uptime_s"`
			PersistFail   *int64 `json:"persist_failures"`
			ProviderCount int    `json:"providers"`
			Revision      int64  `json:"revision"`
			Status        string `json:"status"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err := json.Unmarshal(raw, &h); err == nil {
			version = h.Version
			uptime = fmtDur(time.Duration(h.UptimeS) * time.Second)
			if h.PersistFail != nil {
				persistFail = *h.PersistFail
			}
		}
	}
	fmt.Printf("服务   pid=%d  %s  已运行 %s", pid, version, uptime)
	if persistFail >= 0 {
		if persistFail > 0 {
			fmt.Printf("  ⚠ 记账失败 %d 次", persistFail)
		} else {
			fmt.Printf("  记账失败 0 次")
		}
	}
	fmt.Println()

	// 各供应商运行期状态（走实时接口，含刚发生的熔断）
	if cfg != nil {
		if live, err := fetchLiveProviders(cfg); err == nil && len(live) > 0 {
			fmt.Println("供应商")
			for _, p := range live {
				state := "健康"
				if !p.Enabled {
					state = "停用"
				} else if !p.Healthy {
					state = "冷却中"
				}
				models := "any(*)"
				if len(p.Models) > 0 {
					models = fmt.Sprintf("%d 个映射", len(p.Models))
				}
				fmt.Printf("  %-22s %-4s %s  权重 %g  代理 %s  模型 %-10s 请求 %d  失败 %d  连续失败 %d\n",
					p.Name, map[bool]string{true: "启用", false: "停用"}[p.Enabled], state,
					p.Weight, p.Proxy, models, p.TotalRequests, p.TotalFailures, p.ConsecutiveFailures)
				if !p.Healthy && p.Enabled && p.UnhealthyUntil != "" {
					fmt.Printf("  %-22s   冷却至 %s\n", "", p.UnhealthyUntil)
				}
			}
		}
	}

	// 本月用量与配额 + 价目覆盖
	if cfg != nil {
		db, err := openReadOnly(cfg.Database.Path)
		if err != nil {
			fmt.Printf("（读不到数据库：%v）\n", err)
			return nil
		}
		defer db.Close()
		now := time.Now()
		printUsageAndQuota(db, now, &cfg.Pricing)
		printPriceCoverage(db, now)
	}
	return nil
}

// printUsageAndQuota 打印每个用户当月的已用与配额。
func printUsageAndQuota(db *store.Store, now time.Time, pricing *config.PricingConfig) {
	users, err := db.ListUsers()
	if err != nil || len(users) == 0 {
		return
	}
	fmt.Println("本月用量（只算走系统上游的）")
	for _, u := range users {
		var tokens int64
		var cost float64
		if rows, err := db.SystemUsageRowsSince(u.Name, store.MonthStart(now)); err == nil {
			for _, r := range rows {
				tokens += r.PromptTokens + r.CompletionTokens
				cost += rowChargeOf(r, pricing, now)
			}
		}
		mode := "byo 自带上游"
		if u.IsConsumption() {
			mode = "consumption 消费系统上游"
		}
		fmt.Printf("  %-12s %-26s token %s  金额 ¥%s\n",
			u.Name, mode, humanCount(tokens), humanMoney(cost))
		qt := "token 不限"
		if u.QuotaMonthTokens > 0 {
			qt = fmt.Sprintf("token 上限 %s（剩 %s）", humanCount(u.QuotaMonthTokens),
				humanCount(u.QuotaMonthTokens-tokens))
		}
		qc := "金额 不限"
		if u.QuotaMonthCost > 0 {
			qc = fmt.Sprintf("金额上限 ¥%s（剩 ¥%s）", humanMoney(u.QuotaMonthCost),
				humanMoney(u.QuotaMonthCost-cost))
		}
		fmt.Printf("             配额: %s  %s\n", qt, qc)
	}
}

// printPriceCoverage 打印当前生效的价目，以及「用量里出现过、但没有价目」的模型。
func printPriceCoverage(db *store.Store, now time.Time) {
	ps, err := db.ProviderPricesEffective(now)
	if err != nil {
		return
	}
	us, _ := db.UserPricesEffective(now)
	fmt.Println("价目（当前生效）")
	if len(ps) == 0 {
		fmt.Printf("  上游价   无 —— 成本报表只能是估算段\n")
	} else {
		var keys []string
		for _, p := range ps {
			keys = append(keys, p.Provider+"/"+p.UpstreamModel)
		}
		fmt.Printf("  上游价   %d 条: %s\n", len(ps), strings.Join(keys, "、"))
	}
	if len(us) == 0 {
		fmt.Printf("  分发价   无 —— 金额配额会走估算兜底\n")
	} else {
		var keys []string
		for _, u := range us {
			keys = append(keys, u.Scope+"/"+u.Model)
		}
		fmt.Printf("  分发价   %d 条: %s\n", len(us), strings.Join(keys, "、"))
	}
	fmt.Println("  （要录入/改价：llmproxy price set --help）")
}

// humanCount 把 token 数写成带千分位的形态，307425279 比 307425279 好读。
func humanCount(n int64) string {
	if n < 0 {
		return "0"
	}
	s := strconv.FormatInt(n, 10)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// humanMoney 金额保留 4 位有效小数（¥0.0017 这种小额也有意义）。
func humanMoney(v float64) string {
	if v == 0 {
		return "0"
	}
	if v < 0.01 {
		return fmt.Sprintf("%.6f", v)
	}
	return fmt.Sprintf("%.2f", v)
}

// rowChargeOf 让 CLI 与服务端走同一份算法（store.RowCharge）。
// 以前这里是简化副本，两边一旦漂移就「CLI 报一个数、API 报另一个数」。
func rowChargeOf(r store.UsageRow, p *config.PricingConfig, now time.Time) float64 {
	return store.RowCharge(r, func(model string, hit, miss, out int64, at time.Time) (float64, bool) {
		if p == nil || !p.Enabled() {
			return 0, false
		}
		return p.Cost(model, hit, miss, out, at)
	}, now)
}

func countEnabled(ps []config.Provider) int {
	n := 0
	for _, p := range ps {
		if p.Enabled {
			n++
		}
	}
	return n
}

func cmdReload(paths config.Paths) error {
	pid, running := readPID(paths.PIDFile)
	if !running {
		return fmt.Errorf("服务未在运行，无需重载")
	}
	cfg := cfgForSignal(paths)
	if !serviceResponding(cfg) {
		// 同 cmdStop：进程在但服务不应答，这个 pid 可能已经是别人的了
		return fmt.Errorf("pid %d 存在，但 %s 没有应答，已跳过发 SIGHUP"+
			"（这个 pid 可能已被别的进程复用）", pid, healthURL(cfg))
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("发送 SIGHUP 给 pid %d 失败: %w", pid, err)
	}
	fmt.Printf("已向 pid %d 发送 SIGHUP，配置将热加载\n", pid)
	return nil
}

// ------------------------------------------------------------------ providers

func cmdProviders(paths config.Paths) error {
	cfg, err := config.LoadFileLenient(paths.ConfigFile)
	if err != nil {
		return err
	}

	// 优先问运行中的进程（实时状态，含刚发生的熔断）；没起则回落到 SQLite
	if live, err := fetchLiveProviders(cfg); err == nil {
		printLiveProviders(live)
		return nil
	}

	db, err := openReadOnly(cfg.Database.Path)
	if err != nil {
		return fmt.Errorf("打开数据库失败: %w", err)
	}
	defer db.Close()

	// 这张表列的是 config.yaml 里的系统池，所以只取全局作用域（scope == ""）的状态；
	// 各用户自己上游的熔断按用户名分桶，不属于这里。
	global := map[string]store.ProviderStatus{}
	if loaded, err := db.LoadProviderStatus(); err == nil {
		for _, st := range loaded {
			if st.Scope == "" {
				global[st.Name] = st
			}
		}
	}

	fmt.Printf("%-22s %-8s %-8s %-10s %-12s %s\n",
		"NAME", "ENABLED", "WEIGHT", "PROXY", "MODELS", "STATUS（来自数据库，可能滞后）")
	for _, p := range cfg.Normalized {
		models := "any(*)"
		if !p.Models.Passthrough {
			models = fmt.Sprintf("%d", len(p.Models.Map))
		}
		st := "无历史状态"
		if s, ok := global[p.Name]; ok {
			healthy := s.UnhealthyUntil.IsZero() || time.Now().After(s.UnhealthyUntil)
			state := "健康"
			if !healthy {
				state = fmt.Sprintf("熔断中(至 %s)", s.UnhealthyUntil.Format("15:04:05"))
			}
			st = fmt.Sprintf("%s 连续失败=%d 累计=%d/%d",
				state, s.ConsecutiveFailures, s.TotalFailures, s.TotalRequests)
			if s.LastError != "" {
				st += " last_err=" + truncate(s.LastError, 40)
			}
		}
		fmt.Printf("%-22s %-8v %-8v %-10s %-12s %s\n",
			p.Name, p.Enabled, p.Weight, p.Proxy.Mode, models, st)
	}
	return nil
}

type liveProviderJSON struct {
	Name                string   `json:"name"`
	Enabled             bool     `json:"enabled"`
	Weight              float64  `json:"weight"`
	Proxy               string   `json:"proxy"`
	ProxyMode           string   `json:"proxy_mode"`
	BaseURL             string   `json:"base_url"`
	Models              []string `json:"models"`
	Healthy             bool     `json:"healthy"`
	ConsecutiveFailures int      `json:"consecutive_failures"`
	UnhealthyUntil      string   `json:"unhealthy_until"`
	TotalRequests       int64    `json:"total_requests"`
	TotalFailures       int64    `json:"total_failures"`
	LastError           string   `json:"last_error"`
	LastSuccessAt       string   `json:"last_success_at"`
	LastFailureAt       string   `json:"last_failure_at"`
}

func fetchLiveProviders(cfg *config.Config) ([]liveProviderJSON, error) {
	if len(cfg.Server.APIKeys) == 0 {
		return nil, fmt.Errorf("api_keys 为空，无法查询实时状态")
	}
	url := fmt.Sprintf("http://%s/v1/_providers",
		net.JoinHostPort(cfg.Server.Host, fmt.Sprint(cfg.Server.Port)))
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Server.APIKeys[0].Key)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("实时状态接口返回 %d", resp.StatusCode)
	}
	var parsed struct {
		Revision  int64              `json:"revision"`
		Providers []liveProviderJSON `json:"providers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	if parsed.Providers == nil {
		return nil, fmt.Errorf("实时状态为空")
	}
	return parsed.Providers, nil
}

func printLiveProviders(list []liveProviderJSON) {
	fmt.Printf("%-22s %-8s %-8s %-12s %-10s %-8s %s\n",
		"NAME", "ENABLED", "WEIGHT", "PROXY", "MODELS", "HEALTH", "状态")
	for _, p := range list {
		models := "any(*)"
		if len(p.Models) > 0 {
			models = fmt.Sprintf("%d", len(p.Models))
		}
		health := "健康"
		if !p.Enabled {
			health = "已停用"
		} else if !p.Healthy {
			health = "熔断中"
		}
		line := fmt.Sprintf("%-22s %-8v %-8v %-12s %-10s %-8s 连续失败=%d 累计=%d/%d",
			p.Name, p.Enabled, p.Weight, fmt.Sprintf("%s", p.Proxy), models, health,
			p.ConsecutiveFailures, p.TotalFailures, p.TotalRequests)
		if p.UnhealthyUntil != "" && p.Healthy == false && p.Enabled {
			if t, err := time.Parse(time.RFC3339, p.UnhealthyUntil); err == nil {
				line += fmt.Sprintf(" 恢复于 %s", t.Format("15:04:05"))
			}
		}
		if p.LastError != "" {
			line += " last_err=" + truncate(p.LastError, 48)
		}
		fmt.Println(line)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ------------------------------------------------------------------ stats / logs

func openReadOnly(path string) (*store.Store, error) {
	if path == "" {
		return nil, fmt.Errorf("数据库路径未配置")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("数据库文件不存在：%s（服务启动后会自动创建）", path)
	}
	return store.Open(path)
}

func cmdStats(paths config.Paths, args []string) error {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	days := fs.Int("days", 0, "只统计最近 N 天（0=全部）")
	recent := fs.Int("recent", 10, "显示最近 N 条请求明细")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.LoadFileLenient(paths.ConfigFile)
	if err != nil {
		return err
	}
	db, err := openReadOnly(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer db.Close()

	var since time.Time
	if *days > 0 {
		since = time.Now().AddDate(0, 0, -*days)
	}
	st, err := db.Stats(since, *recent)
	if err != nil {
		return err
	}

	fmt.Printf("总计: 请求 %d  成功 %d  失败 %d  token %d\n",
		st.TotalRequests, st.TotalOK, st.TotalFailed, st.TotalTokens)

	fmt.Printf("\n按供应商/模型消耗:\n")
	// COST 是**冻结**的上游成本（按请求开始时刻的价目算好写死的）；FROZEN 是其中已冻结的
	// 请求数，与 REQ 相减就是还没冻结的行 —— 那部分只能估算，别和冻结值混着看。
	fmt.Printf("%-20s %-24s %8s %8s %8s %12s %10s %10s %8s\n",
		"PROVIDER", "MODEL", "REQ", "OK", "FAIL", "TOKENS", "AVG_MS", "COST", "FROZEN")
	for _, r := range st.ByProvider {
		fmt.Printf("%-20s %-24s %8d %8d %8d %12d %10.0f %10.4f %8d\n",
			r.Provider, r.Model, r.Requests, r.OK, r.Failed, r.TotalTokens, r.AvgLatencyMs,
			r.CostUpstream, r.FrozenRequests)
	}

	fmt.Printf("\n按日消耗:\n")
	fmt.Printf("%-12s %8s %8s %8s %12s\n", "DAY", "REQ", "OK", "FAIL", "TOKENS")
	for _, r := range st.ByDay {
		fmt.Printf("%-12s %8d %8d %8d %12d\n", r.Day, r.Requests, r.OK, r.Failed, r.TotalTokens)
	}

	if len(st.Recent) > 0 {
		fmt.Printf("\n最近 %d 条请求（不含内容）:\n", len(st.Recent))
		for _, r := range st.Recent {
			status := "OK"
			if !r.OK {
				status = fmt.Sprintf("FAIL/%d", r.StatusCode)
			}
			ttft := "-"
			if r.TTFTMs != nil {
				ttft = fmt.Sprintf("%dms", *r.TTFTMs)
			}
			tokens := "-"
			if r.TotalTokens != nil {
				tokens = fmt.Sprint(*r.TotalTokens)
			}
			fmt.Printf("  %s  %-22s -> %-16s %-4s %6dms ttft=%-7s tok=%-8s try=%d  %s\n",
				r.Ts.Format("01-02 15:04:05"),
				r.Model, r.Provider, status, r.LatencyMs, ttft, tokens, r.Attempts,
				r.ClientLabel)
			if r.ErrorMsg != "" {
				fmt.Printf("      err: %s\n", truncate(r.ErrorMsg, 80))
			}
		}
	}
	return nil
}

func cmdLogs(paths config.Paths, args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	n := fs.Int("n", 50, "显示最后 N 行")
	follow := fs.Bool("f", false, "持续跟踪")
	if err := fs.Parse(args); err != nil {
		return err
	}
	logFile := filepath.Join(paths.LogDir, config.ToolName+".log")
	if _, err := os.Stat(logFile); err != nil {
		return fmt.Errorf("日志文件不存在：%s", logFile)
	}

	printTail := func() (int64, error) {
		data, err := os.ReadFile(logFile)
		if err != nil {
			return 0, err
		}
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		start := 0
		if len(lines) > *n {
			start = len(lines) - *n
		}
		for _, l := range lines[start:] {
			fmt.Println(l)
		}
		return int64(len(data)), nil
	}

	off, err := printTail()
	if err != nil {
		return err
	}
	if !*follow {
		return nil
	}
	for {
		time.Sleep(500 * time.Millisecond)
		st, err := os.Stat(logFile)
		if err != nil {
			continue
		}
		if st.Size() < off {
			off = 0 // 被轮转截断
		}
		if st.Size() == off {
			continue
		}
		f, err := os.Open(logFile)
		if err != nil {
			continue
		}
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			f.Close()
			continue
		}
		buf, _ := io.ReadAll(f)
		f.Close()
		if len(buf) > 0 {
			fmt.Print(string(buf))
			off += int64(len(buf))
		}
	}
}

// ------------------------------------------------------------------ test

func cmdTest(paths config.Paths, args []string) error {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	model := fs.String("model", "", "要测试的模型名（默认取配置里第一个已启用供应商的第一个模型）")
	stream := fs.Bool("stream", false, "使用流式请求")
	prompt := fs.String("prompt", "请用一句话回复：你好", "测试提示词（只发给上游，不落库）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.LoadFileLenient(paths.ConfigFile)
	if err != nil {
		return err
	}
	if *model == "" {
		*model = firstModel(cfg)
	}
	if *model == "" {
		return fmt.Errorf("配置里找不到可测试的模型，请用 -model 指定")
	}
	if len(cfg.Server.APIKeys) == 0 {
		return fmt.Errorf("server.api_keys 为空，无法构造测试请求")
	}

	body := map[string]any{
		"model": *model,
		"messages": []map[string]string{
			{"role": "user", "content": *prompt},
		},
		"max_tokens": 32,
	}
	if *stream {
		body["stream"] = true
	}
	payload, _ := json.Marshal(body)

	url := fmt.Sprintf("http://%s/v1/chat/completions",
		net.JoinHostPort(cfg.Server.Host, fmt.Sprint(cfg.Server.Port)))
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Server.APIKeys[0].Key)

	fmt.Printf("测试: POST %s  model=%s stream=%v\n", url, *model, *stream)
	start := time.Now()
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	elapsed := time.Since(start)

	fmt.Printf("状态: %s  耗时: %s\n", resp.Status, elapsed.Round(time.Millisecond))
	if p := resp.Header.Get("X-LLMProxy-Provider"); p != "" {
		fmt.Printf("路由到供应商: %s\n", p)
	}
	fmt.Printf("响应:\n%s\n", strings.TrimSpace(string(raw)))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("测试请求返回 %d", resp.StatusCode)
	}
	return nil
}

func firstModel(cfg *config.Config) string {
	for _, p := range cfg.Normalized {
		if !p.Enabled {
			continue
		}
		if p.Models.Passthrough {
			continue
		}
		for name := range p.Models.Map {
			return name
		}
	}
	// 全是直通型时随便给一个常见模型名
	return "gpt-4o"
}

// ------------------------------------------------------------------ service

func cmdServiceInstall(paths config.Paths) error {
	if err := paths.Ensure(); err != nil {
		return err
	}
	if _, err := os.Stat(paths.ConfigFile); err != nil {
		return fmt.Errorf("配置文件不存在，请先执行 llmproxy init")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.EvalSymlinks(exe)

	switch {
	case fileExists("/run/systemd/system") || fileExists("/etc/systemd/system"):
		unit := fmt.Sprintf(`[Unit]
Description=llmproxy LLM forwarding gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s start
Restart=on-failure
RestartSec=3
WorkingDirectory=%s
# 不把系统代理环境变量带进来：代理完全由配置文件决定
Environment=HTTP_PROXY=
Environment=HTTPS_PROXY=
Environment=ALL_PROXY=
Environment=http_proxy=
Environment=https_proxy=
Environment=all_proxy=
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, exe, paths.RuntimeDir)
		dst := "/etc/systemd/system/llmproxy.service"
		if err := os.WriteFile(dst, []byte(unit), 0o644); err != nil {
			return fmt.Errorf("写入 %s 失败（可能需要 sudo）: %w", dst, err)
		}
		fmt.Printf("已写入 %s\n", dst)
		fmt.Println("接下来执行: sudo systemctl daemon-reload && sudo systemctl enable --now llmproxy")
		return nil
	default:
		// macOS launchd
		label := "com.llmproxy.service"
		plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>start</string>
  </array>
  <key>WorkingDirectory</key><string>%s</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key><false/>
  </dict>
  <key>StandardOutPath</key><string>%s/launchd.out.log</string>
  <key>StandardErrorPath</key><string>%s/launchd.err.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HTTP_PROXY</key><string></string>
    <key>HTTPS_PROXY</key><string></string>
    <key>ALL_PROXY</key><string></string>
    <key>http_proxy</key><string></string>
    <key>https_proxy</key><string></string>
    <key>all_proxy</key><string></string>
  </dict>
</dict>
</plist>
`, label, exe, paths.RuntimeDir, paths.LogDir, paths.LogDir)
		dst := filepath.Join(homeDir(), "Library", "LaunchAgents", label+".plist")
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, []byte(plist), 0o644); err != nil {
			return fmt.Errorf("写入 %s 失败: %w", dst, err)
		}
		fmt.Printf("已写入 %s\n", dst)
		fmt.Printf("接下来执行:\n  launchctl unload %s 2>/dev/null; launchctl load %s\n", dst, dst)
		return nil
	}
}

func cmdServiceUninstall(paths config.Paths) error {
	switch {
	case fileExists("/etc/systemd/system/llmproxy.service"):
		dst := "/etc/systemd/system/llmproxy.service"
		if err := os.Remove(dst); err != nil {
			return fmt.Errorf("删除 %s 失败（可能需要 sudo）: %w", dst, err)
		}
		fmt.Printf("已删除 %s\n", dst)
		fmt.Println("接下来执行: sudo systemctl daemon-reload && sudo systemctl disable llmproxy 2>/dev/null || true")
		return nil
	default:
		dst := filepath.Join(homeDir(), "Library", "LaunchAgents", "com.llmproxy.service.plist")
		if !fileExists(dst) {
			fmt.Println("未找到已安装的系统服务")
			return nil
		}
		_ = runIgnoreErr("launchctl", "unload", dst)
		if err := os.Remove(dst); err != nil {
			return err
		}
		fmt.Printf("已卸载并删除 %s\n", dst)
		return nil
	}
}

func runIgnoreErr(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return h
}
