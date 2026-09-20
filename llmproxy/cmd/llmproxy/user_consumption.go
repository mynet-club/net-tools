package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
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

	u, err := db.GetUser(name)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("用户 %q 不存在", name)
	}
	t, c := u.QuotaMonthTokens, u.QuotaMonthCost
	if *tokens >= 0 {
		t = *tokens
	}
	if *cost >= 0 {
		c = *cost
	}
	if err := db.SetUserQuota(name, t, c); err != nil {
		return err
	}
	fmt.Printf("用户 %s 的月度配额：token %s，金额 %s\n", name, limitText(t), costText(c))
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

	u, err := db.GetUser(name)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("用户 %q 不存在", name)
	}
	r, c := u.RPM, u.MaxConcurrent
	if *rpm >= 0 {
		r = *rpm
	}
	if *conc >= 0 {
		c = *conc
	}
	if err := db.SetUserLimits(name, r, c); err != nil {
		return err
	}
	fmt.Printf("用户 %s 的限流：%d 次/分钟，并发 %d\n", name, r, c)
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
func printUserMode(db *store.Store, cfg *config.Config, u *store.User) {
	fmt.Printf("  模式      %s\n", map[bool]string{true: "consumption（消费系统上游）", false: "byo（自带上游）"}[u.IsConsumption()])
	fmt.Printf("  月度配额  token %s / 金额 %s\n", limitText(u.QuotaMonthTokens), costText(u.QuotaMonthCost))
	fmt.Printf("  限流      %d 次/分钟，并发 %d\n", u.RPM, u.MaxConcurrent)

	su, err := db.SystemUsageSince(u.Name, store.MonthStart(time.Now()))
	if err != nil {
		return
	}
	rows, err := db.SystemUsageRowsSince(u.Name, store.MonthStart(time.Now()))
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
