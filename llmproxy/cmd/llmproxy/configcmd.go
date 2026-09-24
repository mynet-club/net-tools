package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

const configUsage = `llmproxy config — 读写 config.yaml 里的常用标量

  llmproxy config get                列出全部可设置项的当前值
  llmproxy config get <段.键>        只看某一项
  llmproxy config set <段.键> <值>   改一项（走备份 → 校验 → 原子改名，2 秒内热加载）

可设置项（刻意只放开标量，且**只放已经存在的键**）:
  server.host                   监听地址（改后需重启；非回环必须同时配 api_keys）
  server.port                   监听端口（改后需重启）
  server.max_body_mb            请求体上限（MB）
  server.request_timeout_ms     非流式请求的总时长上限
  server.stream_idle_timeout_ms 流式空闲上限（0 = 关闭）
  server.affinity_ttl_ms        会话粘性保留时长（0 = 关闭）
  server.block_local_upstream   收紧用户自配上游的出网范围（true/false）
  routing.retry                 首次失败后再换多少个供应商
  routing.failure_threshold     连续失败几次后临时摘除
  routing.cooldown_seconds      摘除多久后自动恢复
  database.retain_days          请求明细保留天数（0 = 永久）
  log.level                     debug / info / warn / error
  log.max_mb                    单个日志文件上限（MB）
  log.keep                      日志轮转保留份数

刻意不放开的:
  server.admin_token   → 用 ` + "`llmproxy admin rotate`" + `（那是密钥，不该走通用通道）
  server.api_keys      → 列表不是标量，改它请直接编辑 config.yaml
  providers            → 用管理台（那是它唯一的写入面，且有「就近保存/选模型/测试」配套）
  proxies              → 供应商引用的名字，改错了会让上游全挂，直接编辑更稳妥

host / port 变更**需要重启**（监听地址启动时就绑定了），其余项 2 秒内自动热加载。
`

// settableConfigKeys 是 config set 的白名单：键 → 一句话说明。
// 刻意只放标量、且只放「已经存在的键」（要新增键请直接编辑配置文件）。
var settableConfigKeys = map[string]string{
	"server.host":                   "监听地址（改后需重启；非回环必须同时配 api_keys）",
	"server.port":                   "监听端口（改后需重启）",
	"server.max_body_mb":            "请求体上限（MB）",
	"server.request_timeout_ms":     "非流式请求的总时长上限",
	"server.stream_idle_timeout_ms": "流式空闲上限（0 = 关闭）",
	"server.affinity_ttl_ms":        "会话粘性保留时长（0 = 关闭）",
	"server.block_local_upstream":   "收紧用户自配上游的出网范围（true/false）",
	"routing.retry":                 "首次失败后再换多少个供应商",
	"routing.failure_threshold":     "连续失败几次后临时摘除",
	"routing.cooldown_seconds":      "摘除多久后自动恢复",
	"database.retain_days":          "请求明细保留天数（0 = 永久）",
	"log.level":                     "debug / info / warn / error",
	"log.max_mb":                    "单个日志文件上限（MB）",
	"log.keep":                      "日志轮转保留份数",
}

// splitConfigKey 把 "server.host" 拆成 ("server", "host")。
func splitConfigKey(key string) (section, field string, ok bool) {
	i := strings.IndexByte(key, '.')
	if i <= 0 || i == len(key)-1 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
}

func cmdConfig(paths config.Paths, args []string) error {
	if len(args) == 0 {
		fmt.Print(configUsage)
		return nil
	}
	switch args[0] {
	case "get":
		return configGet(paths, args[1:])
	case "set":
		return configSet(paths, args[1:])
	case "help", "-h", "--help":
		fmt.Print(configUsage)
		return nil
	default:
		return fmt.Errorf("未知的 config 子命令 %q\n\n%s", args[0], configUsage)
	}
}

// configValue 取某个可设置项的当前值。用 switch 而不是反射：
// 这里只需要展示，写清每一项从哪读比上反射直观得多。
func configValue(cfg *config.Config, key string) string {
	s := cfg.Server
	r := cfg.Routing
	d := cfg.Database
	l := cfg.Log
	switch key {
	case "server.host":
		return s.Host
	case "server.port":
		return fmt.Sprint(s.Port)
	case "server.max_body_mb":
		return fmt.Sprint(s.MaxBodyMB)
	case "server.request_timeout_ms":
		return fmt.Sprint(s.RequestTimeoutMs)
	case "server.stream_idle_timeout_ms":
		return fmt.Sprint(s.StreamIdleMs())
	case "server.affinity_ttl_ms":
		return fmt.Sprint(s.AffinityTTL())
	case "server.block_local_upstream":
		return fmt.Sprint(s.BlockLocalUpstream)
	case "routing.retry":
		return fmt.Sprint(r.Retry)
	case "routing.failure_threshold":
		return fmt.Sprint(r.FailureThreshold)
	case "routing.cooldown_seconds":
		return fmt.Sprint(r.CooldownSeconds)
	case "database.retain_days":
		return fmt.Sprint(d.EffectiveRetainDays())
	case "log.level":
		return l.Level
	case "log.max_mb":
		return fmt.Sprint(l.MaxMB)
	case "log.keep":
		return fmt.Sprint(l.Keep)
	}
	return "?"
}

func configGet(paths config.Paths, args []string) error {
	cfg, err := config.LoadFileLenient(paths.ConfigFile)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		keys := make([]string, 0, len(settableConfigKeys))
		for k := range settableConfigKeys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Println("可设置项的当前值（llmproxy config set <键> <值> 改）:")
		for _, k := range keys {
			fmt.Printf("  %-30s %-12s %s\n", k, configValue(cfg, k), settableConfigKeys[k])
		}
		fmt.Println()
		fmt.Println("不走这条通道的:")
		fmt.Printf("  server.admin_token            %s\n", map[bool]string{true: "已设（用 admin token 查看）", false: "未设"}[cfg.Server.HasAdminToken()])
		fmt.Printf("  server.api_keys               %d 个（改它请直接编辑 config.yaml）\n", len(cfg.Server.APIKeys))
		return nil
	}
	key := args[0]
	if _, ok := settableConfigKeys[key]; !ok {
		return fmt.Errorf("%q 不在可设置项里\n\n%s", key, configUsage)
	}
	fmt.Printf("%-30s %s\n", key, configValue(cfg, key))
	return nil
}

func configSet(paths config.Paths, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("用法: llmproxy config set <段.键> <值>\n\n%s", configUsage)
	}
	key, value := args[0], args[1]
	if _, ok := settableConfigKeys[key]; !ok {
		return fmt.Errorf("%q 不在可设置项里\n\n%s", key, configUsage)
	}
	section, field, ok := splitConfigKey(key)
	if !ok {
		return fmt.Errorf("键 %q 形状不对，应为 <段.键>，例如 server.port", key)
	}
	src, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		return err
	}
	newSrc, err := config.SetOrInsertConfigScalar(src, section, field, value)
	if err != nil {
		return err
	}
	// 走同一条安全链：备份 → 临时文件 → 用加载器校验（值不合法在这里就会被拒）→ 原子改名
	if err := config.WriteFileSafely(paths.ConfigFile, newSrc); err != nil {
		return err
	}
	notifyRunningService(paths)
	fmt.Printf("%s = %s\n", key, value)
	if key == "server.host" || key == "server.port" {
		fmt.Println("⚠ 监听地址/端口变更需要重启才生效（llmproxy restart）")
	} else {
		fmt.Println("已写入 config.yaml 并备份；2 秒内自动热加载，无需重启。")
	}
	return nil
}
