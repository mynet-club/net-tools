package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/secrets"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

const userUsage = `用法: llmproxy user <子命令> [参数]

  add <名字>                       建用户并打印 token（明文只显示这一次）
  list                             列出全部用户与累计用量
  show <名字>                      用户详情（上游、累计用量）
  rm <名字>                        删除用户及其全部上游
  enable <名字> / disable <名字>   启用 / 停用（停用后该 token 一律 403）
  token <名字>                     轮换 token（旧 token 立即失效）
  providers <名字>                 列出该用户的上游（密钥只显示尾 4 位）
  usage <名字> [-days N]           按日 / 按模型看消耗（消费用户带金额估算）

消费模式（让用户消费「系统上游」，网关主人付费）：
  mode <名字> byo|consumption      切换模式（byo = 自带上游；consumption = 用系统上游）
  quota <名字> [-tokens N] [-cost N]    月度配额，0 = 不限（只统计走系统上游的消耗）
  limits <名字> [-rpm N] [-concurrent N] 限流，0 = 不限
  models <名字>                    该用户的可用模型（既是白名单也是映射）
  add-model <用户> <下游名> [-upstream 名] [-provider 供应商]
  rm-model <用户> <下游名>
  add-provider <用户> <上游名>     代用户配一个上游（见下面的参数）
  rm-provider <用户> <上游名>      删掉一个上游

add-provider 的参数：
  -base-url URL       上游 OpenAI 兼容根地址，例如 https://api.deepseek.com/v1
  -api-key KEY        上游密钥；写 "-" 表示从 stdin 读一行
  -api-key-env NAME   从环境变量读上游密钥（避免密钥进 shell 历史）
  -models '["*"]'     承接的模型：'["*"]' 表示任意模型直通，或 '{"下游名":"上游名"}'
  -proxy direct       direct / proxies 里定义的名字 / 内联代理 URL
  -weight 1           权重（用户配了多个上游时按权重分摊）
  -timeout-ms 120000  上游超时
  -disabled           配好但先不启用

说明：这些都是直接改数据库；正在运行的服务会在 2 秒内自动加载。
`

func cmdUser(paths config.Paths, args []string) error {
	if len(args) == 0 {
		fmt.Print(userUsage)
		return nil
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "add":
		return userAdd(paths, rest)
	case "list", "ls":
		return userList(paths)
	case "show":
		return userShow(paths, rest)
	case "rm", "del", "remove":
		return userRemove(paths, rest)
	case "enable", "disable":
		return userToggle(paths, rest, sub == "enable")
	case "token", "rotate":
		return userRotate(paths, rest)
	case "providers":
		return userProviders(paths, rest)
	case "usage":
		return userUsageCmd(paths, rest)
	case "mode":
		return userMode(paths, rest)
	case "quota":
		return userQuota(paths, rest)
	case "limits":
		return userLimits(paths, rest)
	case "models":
		return userModels(paths, rest)
	case "add-model":
		return userAddModel(paths, rest)
	case "rm-model":
		return userRemoveModel(paths, rest)
	case "add-provider":
		return userAddProvider(paths, rest)
	case "rm-provider":
		return userRemoveProvider(paths, rest)
	case "help", "-h", "--help":
		fmt.Print(userUsage)
		return nil
	default:
		return fmt.Errorf("未知的 user 子命令 %q\n\n%s", sub, userUsage)
	}
}

// openUserStore 打开运行时数据库（可写）。用户管理都属于本地运维操作。
func openUserStore(paths config.Paths) (*store.Store, *config.Config, error) {
	if _, err := os.Stat(paths.ConfigFile); err != nil {
		return nil, nil, fmt.Errorf("配置文件不存在：%s（先执行 llmproxy init）", paths.ConfigFile)
	}
	// 用宽松模式加载：管理用户不该被「某个上游的密钥还没配」卡住
	cfg, err := config.LoadFileLenient(paths.ConfigFile)
	if err != nil {
		return nil, nil, err
	}
	db, err := store.Open(cfg.Database.Path)
	if err != nil {
		return nil, nil, err
	}
	return db, cfg, nil
}

func requireName(rest []string, what string) (string, error) {
	if len(rest) < 1 || strings.TrimSpace(rest[0]) == "" {
		return "", fmt.Errorf("缺少%s", what)
	}
	return strings.TrimSpace(rest[0]), nil
}

// runningHint 提醒：改完最多 2 秒生效。
func runningHint() {
	fmt.Println("（正在运行的服务会在 2 秒内自动加载这次变更）")
}

func userAdd(paths config.Paths, rest []string) error {
	name, err := requireName(rest, "用户名")
	if err != nil {
		return err
	}
	db, _, err := openUserStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	token, err := store.NewToken()
	if err != nil {
		return err
	}
	if err := db.CreateUser(name, store.TokenHash(token)); err != nil {
		return err
	}

	fmt.Printf("已创建用户 %s\n\n", name)
	fmt.Printf("  下游 token: %s\n\n", token)
	fmt.Println("明文只显示这一次（库里只存 SHA-256 摘要）。把 token 交给用户后，他可以：")
	fmt.Printf("  1) 把 base URL 指向本网关、用这个 token 调用 /v1/chat/completions\n")
	fmt.Printf("  2) 用 PUT /v1/_me/providers/{上游名} 配置自己的上游\n")
	runningHint()
	return nil
}

func userList(paths config.Paths) error {
	db, _, err := openUserStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	users, err := db.ListUsers()
	if err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Println("还没有用户。用 llmproxy user add <名字> 建一个。")
		return nil
	}
	allProv, err := db.ListAllUserProviders()
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tENABLED\tUPSTREAMS\tREQUESTS\tTOKENS\tCREATED")
	for _, u := range users {
		tot, err := db.TotalByUser(time.Time{}, u.Name)
		if err != nil {
			return err
		}
		names := []string{}
		for _, p := range allProv[u.Name] {
			mark := p.Name
			if !p.Enabled {
				mark += "(off)"
			}
			names = append(names, mark)
		}
		up := "-"
		if len(names) > 0 {
			up = strings.Join(names, ",")
		}
		fmt.Fprintf(w, "%s\t%v\t%s\t%d\t%d\t%s\n",
			u.Name, u.Enabled, up, tot.Requests, tot.TotalTokens,
			u.CreatedAt.Format("2006-01-02 15:04"))
	}
	return w.Flush()
}

func userShow(paths config.Paths, rest []string) error {
	name, err := requireName(rest, "用户名")
	if err != nil {
		return err
	}
	db, cfg, err := openUserStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	u, err := db.GetUser(name)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("用户 %q 不存在", name)
	}
	tot, err := db.TotalByUser(time.Time{}, name)
	if err != nil {
		return err
	}

	fmt.Printf("用户 %s\n", u.Name)
	fmt.Printf("  状态      %v\n", map[bool]string{true: "启用", false: "已停用"}[u.Enabled])
	printUserMode(db, cfg, u)
	fmt.Printf("  token     %s（库里存的是摘要，看不到明文）\n", u.TokenHash[:16]+"…")
	fmt.Printf("  创建时间  %s\n", u.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  累计用量  请求 %d（成功 %d / 失败 %d）  prompt %d / completion %d / 合计 %d tokens\n",
		tot.Requests, tot.OK, tot.Failed, tot.PromptTokens, tot.OutputTokens, tot.TotalTokens)
	if tot.FirstDay != "" {
		fmt.Printf("  时间范围  %s ~ %s\n", tot.FirstDay, tot.LastDay)
	}
	return userProviders(paths, rest)
}

func userProviders(paths config.Paths, rest []string) error {
	name, err := requireName(rest, "用户名")
	if err != nil {
		return err
	}
	db, _, err := openUserStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	list, err := db.ListUserProviders(name)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Printf("\n用户 %s 还没配上游（没配的话会用全局配置里的供应商）\n", name)
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "\nNAME\tENABLED\tBASE_URL\tAPI_KEY\tWEIGHT\tTIMEOUT\tPROXY\tMODELS")
	for _, p := range list {
		models := p.ModelsJSON
		if len(models) > 34 {
			models = models[:34] + "…"
		}
		proxy := p.Proxy
		if proxy == "" {
			proxy = "direct"
		}
		fmt.Fprintf(w, "%s\t%v\t%s\t%s\t%v\t%dms\t%s\t%s\n",
			p.Name, p.Enabled, p.BaseURL, "(已加密)", p.Weight, p.TimeoutMs, proxy, models)
	}
	return w.Flush()
}

func userRemove(paths config.Paths, rest []string) error {
	name, err := requireName(rest, "用户名")
	if err != nil {
		return err
	}
	db, _, err := openUserStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.DeleteUser(name); err != nil {
		return err
	}
	fmt.Printf("已删除用户 %s（含其全部上游配置）\n", name)
	runningHint()
	return nil
}

func userToggle(paths config.Paths, rest []string, enable bool) error {
	name, err := requireName(rest, "用户名")
	if err != nil {
		return err
	}
	db, _, err := openUserStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.SetUserEnabled(name, enable); err != nil {
		return err
	}
	act := map[bool]string{true: "已启用", false: "已停用（该 token 现在一律 403）"}[enable]
	fmt.Printf("%s用户 %s\n", act, name)
	runningHint()
	return nil
}

func userRotate(paths config.Paths, rest []string) error {
	name, err := requireName(rest, "用户名")
	if err != nil {
		return err
	}
	db, _, err := openUserStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	token, err := store.NewToken()
	if err != nil {
		return err
	}
	if err := db.SetUserToken(name, store.TokenHash(token)); err != nil {
		return err
	}
	fmt.Printf("已轮换用户 %s 的 token（旧 token 立即失效）\n\n", name)
	fmt.Printf("  新 token: %s\n\n", token)
	fmt.Println("明文只显示这一次，请立刻交给用户。")
	runningHint()
	return nil
}

func userUsageCmd(paths config.Paths, rest []string) error {
	fs := flag.NewFlagSet("user usage", flag.ContinueOnError)
	days := fs.Int("days", 30, "统计最近 N 天")
	if len(rest) == 0 {
		return fmt.Errorf("用法: llmproxy user usage <名字> [-days N]")
	}
	name := rest[0]
	if err := fs.Parse(rest[1:]); err != nil {
		return err
	}
	db, cfg, err := openUserStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	since := time.Now().AddDate(0, 0, -*days)
	rows, err := db.UsageByUser(since, name)
	if err != nil {
		return err
	}
	tot, err := db.TotalByUser(since, name)
	if err != nil {
		return err
	}

	fmt.Printf("用户 %s 最近 %d 天：请求 %d（成功 %d / 失败 %d），prompt %d / completion %d / 合计 %d tokens\n",
		name, *days, tot.Requests, tot.OK, tot.Failed, tot.PromptTokens, tot.OutputTokens, tot.TotalTokens)
	if len(rows) == 0 {
		fmt.Println("（没有记录）")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "\nDAY\tPROVIDER\tMODEL\tUPSTREAM\tREQ\tOK\tFAIL\tPROMPT\tCACHE_HIT\tCACHE_MISS\tCOMPLETION\tTOTAL\tAVG_MS\tCOST")
	now := time.Now()
	for _, r := range rows {
		hit, miss := r.CacheHitTokens, r.CacheMissTokens
		// 上游没报缓存拆分时按「输入全部未命中」估，宁可高估不漏计
		if hit+miss == 0 && r.PromptTokens > 0 {
			miss = r.PromptTokens
		}
		costStr := "—"
		if cfg != nil && cfg.Pricing.Enabled() {
			if c, ok := cfg.Pricing.Cost(r.UpstreamModel, hit, miss, r.CompletionTokens, now); ok {
				costStr = fmt.Sprintf("%.4f", c)
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%.0f\t%s\n",
			r.Day, r.Provider, r.Model, orDash(r.UpstreamModel),
			r.Requests, r.OK, r.Failed,
			r.PromptTokens, r.CacheHitTokens, r.CacheMissTokens, r.CompletionTokens, r.TotalTokens,
			r.AvgLatencyMs, costStr)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if cfg != nil && cfg.Pricing.Enabled() {
		fmt.Printf("\n金额按 config.yaml 的 pricing 估算，单位 %s；按当前时段单价计算（非历史价）。\n",
			cfg.Pricing.Currency)
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func userAddProvider(paths config.Paths, rest []string) error {
	if len(rest) < 2 {
		return fmt.Errorf("用法: llmproxy user add-provider <用户> <上游名> -base-url URL -api-key KEY -models '[\"*\"]'")
	}
	userName, provName := rest[0], rest[1]

	fs := flag.NewFlagSet("user add-provider", flag.ContinueOnError)
	baseURL := fs.String("base-url", "", "上游 OpenAI 兼容根地址（必填）")
	apiKey := fs.String("api-key", "", "上游密钥；写 - 从 stdin 读")
	apiKeyEnv := fs.String("api-key-env", "", "从该环境变量读上游密钥")
	models := fs.String("models", `["*"]`, "承接的模型，JSON 形态")
	proxy := fs.String("proxy", "", "direct / proxies 里的名字 / 内联代理 URL")
	weight := fs.Float64("weight", 1, "权重")
	timeoutMs := fs.Int("timeout-ms", 120000, "上游超时（毫秒）")
	disabled := fs.Bool("disabled", false, "配好但先不启用")
	if err := fs.Parse(rest[2:]); err != nil {
		return err
	}

	if strings.TrimSpace(*baseURL) == "" {
		return fmt.Errorf("-base-url 必填")
	}
	key, err := resolveAPIKey(*apiKey, *apiKeyEnv)
	if err != nil {
		return err
	}
	if key == "" {
		return fmt.Errorf("缺少上游密钥：用 -api-key、-api-key-env，或 -api-key - 从 stdin 读")
	}

	// 复用与接口、配置文件同一套校验，避免三个入口行为不一致
	spec, err := config.ParseModelsJSON([]byte(*models))
	if err != nil {
		return err
	}
	modelsJSON, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	db, cfg, err := openUserStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	if _, err := config.NormalizeProxy(*proxy, cfg.ProxyIndex); err != nil {
		return err
	}
	u, err := db.GetUser(userName)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("用户 %q 不存在", userName)
	}

	cipher, err := secrets.LoadOrCreate(paths.RuntimeDir)
	if err != nil {
		return fmt.Errorf("加载主密钥失败: %w", err)
	}
	enc, err := cipher.Encrypt(key)
	if err != nil {
		return fmt.Errorf("加密上游密钥失败: %w", err)
	}

	cleanURL := strings.TrimRight(strings.TrimSpace(*baseURL), "/")
	if err := db.UpsertUserProvider(store.UserProvider{
		UserName: userName, Name: provName, BaseURL: cleanURL, APIKeyEnc: enc,
		Weight: *weight, Enabled: !*disabled, TimeoutMs: *timeoutMs,
		Proxy: *proxy, ModelsJSON: string(modelsJSON),
	}); err != nil {
		return err
	}
	fmt.Printf("已为用户 %s 配置上游 %s → %s（密钥已用 %s 加密后落库）\n",
		userName, provName, cleanURL, secrets.FileName)
	runningHint()
	return nil
}

func userRemoveProvider(paths config.Paths, rest []string) error {
	if len(rest) < 2 {
		return fmt.Errorf("用法: llmproxy user rm-provider <用户> <上游名>")
	}
	db, _, err := openUserStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	ok, err := db.DeleteUserProvider(rest[0], rest[1])
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("用户 %q 没有名为 %q 的上游", rest[0], rest[1])
	}
	fmt.Printf("已删除 %s 的上游 %s\n", rest[0], rest[1])
	runningHint()
	return nil
}

// resolveAPIKey 按优先级取上游密钥：环境变量 > 字面值 > stdin（值为 "-"）。
func resolveAPIKey(literal, envName string) (string, error) {
	if envName != "" {
		v := os.Getenv(envName)
		if v == "" {
			return "", fmt.Errorf("环境变量 %s 为空", envName)
		}
		return strings.TrimSpace(v), nil
	}
	if literal == "-" {
		sc := bufio.NewScanner(os.Stdin)
		if !sc.Scan() {
			return "", fmt.Errorf("从 stdin 读取密钥失败")
		}
		return strings.TrimSpace(sc.Text()), nil
	}
	return strings.TrimSpace(literal), nil
}
