package main

// cmdReplay 是 §2.8 证据链的命令行入口：开采集 → 导出记录 → 换个进程把当时的
// 判定与选路重跑一遍。
//
// 为什么必须有 CLI，而不是只留管理接口：回放的前提是「换一台机器、钉住一个时钟、
// 喂当时那套策略包」，这一步天然发生在网关进程之外。让运维手搓 curl 拼 JSON，
// 证据链的最后一环就变成口口相传的教程；它本该是一条能在门禁里自动跑的命令。
//
// -now 必填、拒绝为空：策略与身份的过期语义只有钉住时钟才能复现（§2.8）。
// 用 time.Now() 兜底会让「昨天拒绝的授权」在今天变成通过，而报告看起来完全正常 ——
// 宁可让人多打一个参数。
//
// 记录文件里的 subject 是用户名。CLI 不落库、不上传，只把字节从管理口搬到本地文件，
// 采集开不开、留多久都由运维当场决定（§2.9 的三段式正文口径同样管着这份导出）。

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/replay"
)

const replayUsage = `llmproxy replay — 线上决策记录的导出与跨进程回放（§2.8 证据链）

  llmproxy replay status                     看采集窗口的配置与计数
  llmproxy replay on   [-permille N] [-scope kind:id] [-capacity N]
                                             开启采集（缺省全采 = 1000‰）
  llmproxy replay off                        关闭采集（已采到的记录留在窗口里）
  llmproxy replay collect [-scope user:名字] [-out f.json]
                                             把窗口里的记录导出成文件
  llmproxy replay run -records f.json -now <RFC3339> [-strict-reasons] [-bundles 目录]
                                             用**当前磁盘上**的策略包重跑那份记录

说明：
  记录只在 policy.mode=enforce 且判定出了版本时才采集；影子的判定没有作用到任何
  请求上，不构成回放证据。选路记录另要求计划真的驱动了这次选路。

  采集窗口是**进程内**的有界缓冲：重启即空，溢出丢最旧并计入 dropped。所以流程是
  「要证据时打开 → 跑一批流量 → collect 取走 → off 或 clear」，而不是长期开着。

  replay run 的判据是「逐字段复现」。首选顺序今天**不**比对：线上抽样用的是
  routing 包的 seeded-splitmix64 随机源，回放侧的缺省抽样器是另一个算法，两者在同一条
  seed 下会得出不同的尝试顺序。硬把它们算成同一个算法，回放就会把「顺序不同」报成
  策略差异，或者更糟 —— 让人以为逐位复现了。

  凭据来自 config.yaml 的 server.admin_token。它是管理凭证，只在这里被读出来用一次，
  不会出现在命令输出或日志里。
`

func cmdReplay(paths config.Paths, args []string) error {
	if len(args) == 0 {
		fmt.Print(replayUsage)
		return nil
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "status":
		return replayStatus(paths)
	case "on":
		return replayOn(paths, rest)
	case "off":
		return replayOff(paths)
	case "collect":
		return replayCollect(paths, rest)
	case "run":
		return replayRun(paths, rest)
	case "help", "-h", "--help":
		fmt.Print(replayUsage)
		return nil
	default:
		return fmt.Errorf("未知的 replay 子命令 %q\n\n%s", sub, replayUsage)
	}
}

// ------------------------------------------------------------------ 采集开关与状态

func replayStatus(paths config.Paths) error {
	cfg, err := config.LoadFileLenient(paths.ConfigFile)
	if err != nil {
		return err
	}
	raw, err := adminCall(cfg, http.MethodGet, "/v1/_admin/replay", nil)
	if err != nil {
		return err
	}
	return printReplayStats(raw, true)
}

func replayOff(paths config.Paths) error {
	cfg, err := config.LoadFileLenient(paths.ConfigFile)
	if err != nil {
		return err
	}
	raw, err := adminCall(cfg, http.MethodPost, "/v1/_admin/replay/sampling",
		map[string]any{"enabled": false})
	if err != nil {
		return err
	}
	fmt.Println("已关闭回放记录采集（窗口里已有的记录不会消失，取走用 collect）。")
	return printReplayStats(raw, false)
}

func replayOn(paths config.Paths, args []string) error {
	fs := flag.NewFlagSet("replay on", flag.ContinueOnError)
	permille := fs.Int("permille", -1, "千分率采样（0~1000，缺省 1000 = 全采）")
	scope := fs.String("scope", "", "只采该范围（kind:id，如 user:alice；空 = 全部）")
	capacity := fs.Int("capacity", -1, "窗口保留的请求数（1~4096，缺省不动）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// 显式传过才算「要改这一项」：-scope ""（去掉范围过滤）与「根本没写 -scope」
	// 在 flag 包里都是空串，靠 Visit 才能分开。窗口那侧是指针语义，
	// CLI 不该把「清除过滤」折叠成「保持原过滤」。
	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	body := map[string]any{"enabled": true}
	if set["permille"] {
		body["sample_permille"] = *permille
	} else {
		body["sample_permille"] = 1000
	}
	if set["scope"] {
		body["scope"] = *scope
	}
	if set["capacity"] {
		body["capacity"] = *capacity
	}

	cfg, err := config.LoadFileLenient(paths.ConfigFile)
	if err != nil {
		return err
	}
	raw, err := adminCall(cfg, http.MethodPost, "/v1/_admin/replay/sampling", body)
	if err != nil {
		return err
	}
	fmt.Println("已开启回放记录采集。")
	return printReplayStats(raw, true)
}

// printReplayStats 把窗口快照按人看的顺序打出来。
//
// 用固定字段名 + 兜底整段输出，而不是结构体解码：窗口的字段由服务端决定，CLI 里再
// 抄一份结构体就等于把两处的契约钉在一起，加一个观测字段就要发一版 CLI。
func printReplayStats(raw []byte, withNote bool) error {
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("管理口返回的不是 JSON: %v\n%s", err, bytes.TrimSpace(raw))
	}
	order := []string{
		"enabled", "sample_permille", "scope_filter", "capacity",
		"entries", "decisions", "routings", "captured", "dropped", "failed",
		"as_of", "mode", "running", "policy_version",
		"sampling_algo_declared", "sampling_algo_replay_default", "bit_exact_primary_order",
	}
	for _, k := range order {
		v, ok := out[k]
		if !ok {
			continue
		}
		fmt.Printf("%-28s %s\n", k, statValue(v))
	}
	if withNote {
		for _, k := range []string{"note", "warning"} {
			if v, ok := out[k]; ok {
				fmt.Printf("\n%s: %s\n", k, statValue(v))
			}
		}
	}
	return nil
}

func statValue(v any) string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return "-"
		}
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

// ------------------------------------------------------------------ 导出

func replayCollect(paths config.Paths, args []string) error {
	fs := flag.NewFlagSet("replay collect", flag.ContinueOnError)
	scope := fs.String("scope", "", "只导出该范围（user:名字；空 = 全部）")
	out := fs.String("out", "", "输出文件（省略 = 写到标准输出）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.LoadFileLenient(paths.ConfigFile)
	if err != nil {
		return err
	}
	query := ""
	if s := strings.TrimSpace(*scope); s != "" {
		query = "?scope=" + s
	}
	data, err := adminCall(cfg, http.MethodGet, "/v1/_admin/replay/export"+query, nil)
	if err != nil {
		return err
	}
	// 导出前在本机再解一次：管理口写坏了字段名（replay.Encode 的禁用词扫描在 server
	// 侧已经跑过），这里拿到的就是一堆没法回放的字节。当场报错比让 run 阶段才发现好。
	f, err := replay.Decode(data)
	if err != nil {
		return fmt.Errorf("导出的记录不可解析（这份证据不能用）: %w", err)
	}
	if *out == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			return err
		}
	} else {
		// 0600：文件里是「谁在什么时候被授权用了哪个模型」，比配置文件更容易被顺手分享。
		if err := os.WriteFile(*out, data, 0o600); err != nil {
			return err
		}
		fmt.Printf("已写入 %s\n", *out)
	}
	fmt.Fprintf(os.Stderr, "导出 %d 条判定 / %d 条选路（schema v%d）\n",
		len(f.Decisions), len(f.Routings), f.SchemaVersion)
	if len(f.Decisions) == 0 && len(f.Routings) == 0 {
		fmt.Fprintln(os.Stderr, "窗口里没有记录：确认采集已开（replay status）、mode 是 enforce，且期间真的有请求进来。")
	}
	return nil
}

// ------------------------------------------------------------------ 回放

func replayRun(paths config.Paths, args []string) error {
	fs := flag.NewFlagSet("replay run", flag.ContinueOnError)
	records := fs.String("records", "", "记录文件（replay collect 的产物，必填）")
	nowRaw := fs.String("now", "", "回放时钟 RFC3339（如 2026-10-03T12:00:00Z），必填")
	strict := fs.Bool("strict-reasons", false, "额外比对完整原因链（默认只比主原因码）")
	bundles := fs.String("bundles", "", "策略包目录的基准路径（省略 = 配置文件所在目录）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*records) == "" {
		return fmt.Errorf("-records 必填：回放必须有记录文件\n\n%s", replayUsage)
	}
	nowT, err := parseReplayNow(*nowRaw)
	if err != nil {
		return err
	}

	data, err := os.ReadFile(*records)
	if err != nil {
		return fmt.Errorf("读取记录文件失败: %w", err)
	}
	file, err := replay.Decode(data)
	if err != nil {
		return fmt.Errorf("记录文件不合法: %w", err)
	}

	cfg, err := config.LoadFileLenient(paths.ConfigFile)
	if err != nil {
		return err
	}
	baseDir := cfg.BundleBaseDir()
	if strings.TrimSpace(*bundles) != "" {
		baseDir = *bundles
	}
	set, err := cfg.Policy.LoadBundles(baseDir)
	if err != nil {
		return fmt.Errorf("加载策略包失败: %w", err)
	}
	if set == nil || set.Len() == 0 {
		return fmt.Errorf("没有可回放的策略包（policy.mode 是 legacy，或 policy.bundles 没引用任何包）\n" +
			"  回放的输入之一是**当时那套策略内容**，它只在 policy-bundles 目录里")
	}

	rp, err := replay.New(set, replay.Options{Now: nowT, StrictReasonChain: *strict})
	if err != nil {
		return err
	}
	report, err := rp.Run(file)
	if err != nil {
		return fmt.Errorf("回放失败: %w", err)
	}
	fmt.Println(report.String())
	if d, derr := report.Digest(); derr == nil {
		fmt.Printf("\n报告摘要: %s\n", d)
	}
	if report.Empty() {
		return fmt.Errorf("记录里没有任何可回放的条目（空记录不算通过）")
	}
	passed, mismatch, rejected := report.Counts()
	if !report.Clean() {
		return fmt.Errorf("回放未通过：通过 %d，差异 %d，拒绝回放 %d", passed, mismatch, rejected)
	}
	fmt.Printf("\n全部逐字段复现（通过 %d 条）。\n", passed)
	return nil
}

// parseReplayNow 解析 -now，空值直接报错而不是取当前时间（理由见文件头）。
func parseReplayNow(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("-now 必填（RFC3339，例如 2026-10-03T12:00:00Z）：" +
			"策略与身份的过期语义只有钉住回放时钟才能复现")
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("-now 不是合法的 RFC3339 时间: %w", err)
	}
	return t, nil
}

// ------------------------------------------------------------------ 管理口调用

// adminCall 向本机网关发一次带管理凭证的请求，返回响应字节。
//
// 复用 healthURL 那套 host 归一化：配置里 bind 到 0.0.0.0 时，那个地址在 macOS 上
// 连不通，而 CLI 的调用对象永远是回环上的自己。
// body 为 nil 时不发请求体（GET / HEAD），非 nil 时 POST JSON。
func adminCall(cfg *config.Config, method, path string, body map[string]any) ([]byte, error) {
	token := strings.TrimSpace(cfg.Server.AdminToken)
	if token == "" {
		return nil, fmt.Errorf("config.yaml 里没有 server.admin_token：管理接口整体关闭\n" +
			"  用 llmproxy admin rotate 生成一个")
	}
	if strings.HasPrefix(token, "${") {
		return nil, fmt.Errorf("server.admin_token 是环境变量引用（%s），当前环境取不到它\n"+
			"  先 export 那个变量，或用 llmproxy admin rotate 换成写在文件里的值", token)
	}

	url := adminBaseURL(cfg) + path

	var rdr io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连不上本机网关（%s）: %w", url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("网关返回 %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

// adminBaseURL 拼出管理口的访问地址（不含路径）。
func adminBaseURL(cfg *config.Config) string {
	host, port := "127.0.0.1", "8787"
	switch cfg.Server.Host {
	case "", "0.0.0.0", "::", "[::]", "*":
	default:
		host = cfg.Server.Host
	}
	if cfg.Server.Port != 0 {
		port = strconv.Itoa(cfg.Server.Port)
	}
	return "http://" + net.JoinHostPort(host, port)
}
