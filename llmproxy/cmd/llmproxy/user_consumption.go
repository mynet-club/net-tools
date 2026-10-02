package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// ------------------------------------------------------------------ 模式

func userMode(paths config.Paths, rest []string) error {
	if len(rest) < 2 {
		return fmt.Errorf("用法: llmproxy user mode <名字> byo|consumption\n\n" +
			"  byo          用户自带上游（自己配 base_url + api_key），网关不替他付钱\n" +
			"  consumption  允许消费系统上游（用 providers 里的全局供应商），受模型白名单与配额约束")
	}
	name, mode := rest[0], strings.ToLower(rest[1])
	if mode != store.ModeBYO && mode != store.ModeConsumption {
		return fmt.Errorf("模式只能是 byo 或 consumption，当前是 %q", mode)
	}
	db, _, err := openUserStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.SetUserMode(name, mode); err != nil {
		return err
	}
	fmt.Printf("用户 %s 的模式已设为 %s\n", name, mode)
	if mode == store.ModeConsumption {
		fmt.Println("注意：消费模式要靠模型白名单收口，用 llmproxy user add-model 给他加能用的模型；")
		fmt.Println("      没加之前他一个模型都调不了（不会自动获得系统池的全部模型）。")
	} else {
		fmt.Println("注意：byo 用户只能用自己配的上游；一个都没配时请求会失败，不再回退到系统上游。")
	}
	runningHint()
	return nil
}

// ------------------------------------------------------------------ 配额与限流

// userScopeOf 把用户名折成 (user, 名) 范围（§2.7 规则 3）。
//
// 用 NewScopeRef 而不是 MustScope：CLI 的输入来自命令行，名字里可能有非法字符，
// 这里要给出「用户名的错」而不是 panic。CreateUser 建号时已经拦过一轮，
// 但老库里可能存在改规则之前建的名字，报错信息得说清是这个名字当不了范围键。
func userScopeOf(name string) (policy.ScopeRef, error) {
	scope, err := policy.NewScopeRef(policy.ScopeUser, name)
	if err != nil {
		return policy.ScopeRef{}, fmt.Errorf("用户名 %q 不能用作范围键: %w", name, err)
	}
	return scope, nil
}

// userTotals 读一个用户名的累计用量。
//
// §2.7 规则 8 之后用量只有 scope 形状的阅读口，所以「按用户名查累计」这一句
// 在 CLI 里出现三处（列表、详情、usage），收在这儿而不是各写一遍范围拼装。
func userTotals(db *store.Store, name string, since, until time.Time) (store.UsageTotals, error) {
	scope, err := userScopeOf(name)
	if err != nil {
		return store.UsageTotals{}, err
	}
	return db.ScopeUsageTotals([]policy.ScopeRef{scope}, since, until)
}

// quotaOfUser 读一个用户的配额与限流行。
//
// 缺行报错而不是按「不限」显示：store.Open 里的 scope 迁移保证每个用户都有一行，
// 读不到说明库还没迁到 3.0。把这种状态显示成「没有额度限制」，
// 管理员看到的就是一个假的「一切正常」。
func quotaOfUser(db *store.Store, name string) (store.ScopeQuota, error) {
	scope, err := userScopeOf(name)
	if err != nil {
		return store.ScopeQuota{}, err
	}
	q, err := db.GetScopeQuota(scope)
	if err != nil {
		return store.ScopeQuota{}, err
	}
	if q == nil {
		return store.ScopeQuota{}, fmt.Errorf("用户 %s 没有 scope_quota 配额行（scope 迁移未完成）", name)
	}
	return *q, nil
}

// requireUser 确认用户存在。写配额之前必须先查这一步：
// 配额行是按范围键 upsert 的，名字打错时 PatchScopeQuota 会照样给一个不存在的用户
// 建出一行孤儿配额，而「每个 user 范围恰好一行配额」是收口校验要查的不变量 ——
// 报错要在管理员面前报，不要把库改坏留到下次体检。
func requireUser(db *store.Store, name string) error {
	u, err := db.GetUser(name)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("用户 %q 不存在", name)
	}
	return nil
}

func userQuota(paths config.Paths, rest []string) error {
	fs := flag.NewFlagSet("user quota", flag.ContinueOnError)
	tokens := fs.Int64("tokens", -1, "每月 token 上限（0 = 不限）")
	cost := fs.Float64("cost", -1, "每月金额上限（0 = 不限）")
	if len(rest) == 0 {
		return fmt.Errorf("用法: llmproxy user quota <名字> [-tokens N] [-cost N]（0 表示不限）")
	}
	name := rest[0]
	if err := fs.Parse(rest[1:]); err != nil {
		return err
	}
	if *tokens < 0 && *cost < 0 {
		return fmt.Errorf("至少给一个 -tokens 或 -cost")
	}
	db, _, err := openUserStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := requireUser(db, name); err != nil {
		return err
	}
	scope, err := userScopeOf(name)
	if err != nil {
		return err
	}
	// 只把「这次给到的那一项」交给 PatchScopeQuota：没给的项保持原值，
	// 所以改 token 上限不会顺手把金额上限清零（那等于给用户放开额度）。
	patch := store.QuotaPatch{}
	if *tokens >= 0 {
		patch.Tokens = tokens
	}
	if *cost >= 0 {
		patch.Cost = cost
	}
	if err := db.PatchScopeQuota(scope, patch); err != nil {
		return err
	}
	q, err := quotaOfUser(db, name)
	if err != nil {
		return err
	}
	fmt.Printf("用户 %s 的月度配额：token %s，金额 %s\n", name, limitText(q.QuotaMonthTokens), costText(q.QuotaMonthCost))
	fmt.Println("说明：配额只统计「走系统上游」的消耗；用户用自己的上游时不占额度。")
	fmt.Println("      判定在请求之前做，属于软限额 —— 并发请求最多可能超出同时在飞的那几条。")
	runningHint()
	return nil
}

func userLimits(paths config.Paths, rest []string) error {
	fs := flag.NewFlagSet("user limits", flag.ContinueOnError)
	rpm := fs.Int("rpm", -1, "每分钟请求上限（0 = 不限）")
	conc := fs.Int("concurrent", -1, "同时进行的请求上限（0 = 不限）")
	if len(rest) == 0 {
		return fmt.Errorf("用法: llmproxy user limits <名字> [-rpm N] [-concurrent N]（0 表示不限）")
	}
	name := rest[0]
	if err := fs.Parse(rest[1:]); err != nil {
		return err
	}
	if *rpm < 0 && *conc < 0 {
		return fmt.Errorf("至少给一个 -rpm 或 -concurrent")
	}
	db, _, err := openUserStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := requireUser(db, name); err != nil {
		return err
	}
	scope, err := userScopeOf(name)
	if err != nil {
		return err
	}
	patch := store.QuotaPatch{}
	if *rpm >= 0 {
		patch.RPM = rpm
	}
	if *conc >= 0 {
		patch.MaxConcurrent = conc
	}
	if err := db.PatchScopeQuota(scope, patch); err != nil {
		return err
	}
	q, err := quotaOfUser(db, name)
	if err != nil {
		return err
	}
	fmt.Printf("用户 %s 的限流：%d 次/分钟，并发 %d\n", name, q.RPM, q.MaxConcurrent)
	runningHint()
	return nil
}

// ------------------------------------------------------------------ 模型映射

func userModels(paths config.Paths, rest []string) error {
	name, err := requireName(rest, "用户名")
	if err != nil {
		return err
	}
	db, _, err := openUserStore(paths)
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
	ms, err := db.ListUserModels(name)
	if err != nil {
		return err
	}
	if !u.IsConsumption() {
		if len(ms) == 0 {
			fmt.Printf("用户 %s 是 byo 模式（自带上游），没有也不需要模型映射。\n", name)
			return nil
		}
	}
	if len(ms) == 0 {
		fmt.Printf("用户 %s 还没有可用模型 —— 消费模式下他会一个模型都调不了。\n", name)
		fmt.Println("用 llmproxy user add-model 加一条。")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "MODEL（下游名）\tUPSTREAM（系统模型）\tPROVIDER（限定供应商）\tENABLED")
	for _, m := range ms {
		up, pv := m.Upstream, m.Provider
		if up == "" {
			up = "（同名）"
		}
		if pv == "" {
			pv = "（系统池按权重）"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%v\n", m.Model, up, pv, m.Enabled)
	}
	return w.Flush()
}

func userAddModel(paths config.Paths, rest []string) error {
	fs := flag.NewFlagSet("user add-model", flag.ContinueOnError)
	upstream := fs.String("upstream", "", "系统里的真实模型名（留空 = 与下游名相同）")
	provider := fs.String("provider", "", "限定走哪个系统供应商（留空 = 在系统池里按权重选）")
	disabled := fs.Bool("disabled", false, "先加上但停用")
	if len(rest) < 2 {
		return fmt.Errorf("用法: llmproxy user add-model <用户> <下游模型名> [-upstream 名字] [-provider 供应商] [-disabled]")
	}
	name, model := rest[0], rest[1]
	if err := fs.Parse(rest[2:]); err != nil {
		return err
	}

	db, _, err := openUserStore(paths)
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
	if !u.IsConsumption() {
		return fmt.Errorf("用户 %s 是 byo 模式，模型映射只对 consumption 用户有意义。"+
			"先执行: llmproxy user mode %s consumption", name, name)
	}
	if err := db.UpsertUserModel(store.UserModel{
		UserName: name, Model: model, Upstream: *upstream, Provider: *provider, Enabled: !*disabled,
	}); err != nil {
		return err
	}
	target := *upstream
	if target == "" {
		target = model + "（同名）"
	}
	fmt.Printf("已为 %s 加上模型 %s → %s\n", name, model, target)
	runningHint()
	return nil
}

func userRemoveModel(paths config.Paths, rest []string) error {
	if len(rest) < 2 {
		return fmt.Errorf("用法: llmproxy user rm-model <用户> <下游模型名>")
	}
	name, model := rest[0], rest[1]
	db, _, err := openUserStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	ok, err := db.DeleteUserModel(name, model)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("用户 %s 没有模型 %q 的映射", name, model)
	}
	fmt.Printf("已删除 %s 的模型映射 %s\n", name, model)
	runningHint()
	return nil
}

// ------------------------------------------------------------------ 展示

func limitText(v int64) string {
	if v <= 0 {
		return "不限"
	}
	return fmt.Sprintf("%d", v)
}

func costText(v float64) string {
	if v <= 0 {
		return "不限"
	}
	return fmt.Sprintf("%.2f", v)
}

// printUserMode 打印模式、配额、限流与系统付费用量，供 user show 复用。
//
// 模式读 users 行（身份事实），配额与限流读 scope_quota 行（范围事实）——
// §2.7 规则 2：这两件事各自只有一处真值，这里不能再去 users 的旧列里找。
func printUserMode(db *store.Store, cfg *config.Config, u *store.User) {
	fmt.Printf("  模式      %s\n", map[bool]string{true: "consumption（消费系统上游）", false: "byo（自带上游）"}[u.IsConsumption()])
	q, err := quotaOfUser(db, u.Name)
	if err != nil {
		fmt.Printf("  配额      %v\n", err)
		return
	}
	fmt.Printf("  月度配额  token %s / 金额 %s\n", limitText(q.QuotaMonthTokens), costText(q.QuotaMonthCost))
	fmt.Printf("  限流      %d 次/分钟，并发 %d\n", q.RPM, q.MaxConcurrent)

	// 系统付费用量按范围读（§2.7 规则 8：usage_user_daily 已经不再写，读侧只留 scope 形状）
	scope, err := userScopeOf(u.Name)
	if err != nil {
		fmt.Printf("  用量      %v\n", err)
		return
	}
	su, err := db.ScopeSystemUsage(scope, store.MonthStart(time.Now()))
	if err != nil {
		return
	}
	rows, err := db.ScopeSystemUsageRows(scope, store.MonthStart(time.Now()))
	if err != nil {
		return
	}
	cur := "CNY"
	if cfg != nil && cfg.Pricing.Currency != "" {
		cur = cfg.Pricing.Currency
	}
	var cost float64
	now := time.Now()
	for _, r := range rows {
		hit, miss := r.CacheHitTokens, r.CacheMissTokens
		if hit+miss == 0 && r.PromptTokens > 0 {
			miss = r.PromptTokens
		}
		if cfg != nil && cfg.Pricing.Enabled() {
			if c, ok := cfg.Pricing.Cost(r.UpstreamModel, hit, miss, r.CompletionTokens, now); ok {
				cost += c
			}
		}
	}
	fmt.Printf("  本月消费  请求 %d，token %d（输入 %d：缓存命中 %d / 未命中 %d，输出 %d），估算 %.2f %s\n",
		su.Requests, su.TotalTokens, su.PromptTokens, su.CacheHitTokens, su.CacheMissTokens,
		su.CompletionTokens, cost, cur)
	if cfg == nil || !cfg.Pricing.Enabled() {
		fmt.Println("  提示      没有配置 pricing，金额无法估算（只统计 token）")
	}
}
