package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// cmdExport 出用量 CSV：对账 / 报销 / 给用户看账单。
// 金额口径与配额一致（store.RowCharge 冻结优先），所以导出的数能和 `status` 对上。
//
// 归属一律写成 kind:id：导出的是钱，而「alice」在 3.0 里同时可能是用户、组织或项目 ——
// 旧的 -user 参数连同那套裸串约定一起随 §2.7 规则 8 退役了。
func cmdExport(paths config.Paths, args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	scopeFlag := fs.String("scope", "", "只导出该范围（kind:id，如 user:alice；空 = 全部）")
	since := fs.String("since", "", "起始日 YYYY-MM-DD（含）")
	until := fs.String("until", "", "结束日 YYYY-MM-DD（含）")
	monthly := fs.Bool("monthly", false, "按月×范围合计（账单口径），而不是按日明细")
	out := fs.String("out", "", "输出文件（省略 = 写到标准输出）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	scope, err := parseExportScope(*scopeFlag)
	if err != nil {
		return fmt.Errorf("-scope: %w", err)
	}

	cfg, err := config.LoadFileLenient(paths.ConfigFile)
	if err != nil {
		return err
	}
	db, err := openReadOnly(cfg.Database)
	if err != nil {
		return err
	}
	defer db.Close()

	sinceT, err := parseDay(*since)
	if err != nil {
		return fmt.Errorf("-since: %w", err)
	}
	untilT, err := parseDay(*until)
	if err != nil {
		return fmt.Errorf("-until: %w", err)
	}

	var w io.Writer = os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if *monthly {
		var rows []store.ScopeMonthlyRollupRow
		if scope == nil {
			rows, err = db.AllScopesMonthlyRollup(sinceT, untilT)
		} else {
			rows, err = db.ScopeMonthlyRollup(*scope, sinceT, untilT)
		}
		if err != nil {
			return err
		}
		if err := cw.Write([]string{
			"month", "scope_kind", "scope_id", "requests", "ok", "failed",
			"total_tokens", "charge", "frozen_charges",
		}); err != nil {
			return err
		}
		for _, r := range rows {
			if err := cw.Write([]string{
				r.Month, string(r.Scope.Kind), r.Scope.ID,
				itoa(r.Requests), itoa(r.OK), itoa(r.Failed), itoa(r.Tokens),
				f64s(r.Charge), itoa(r.Frozen),
			}); err != nil {
				return err
			}
		}
	} else {
		var rows []store.ScopeUsageRow
		if scope == nil {
			rows, err = db.AllScopesUsageExportRows(sinceT, untilT)
		} else {
			rows, err = db.ScopeUsageExportRows(*scope, sinceT, untilT)
		}
		if err != nil {
			return err
		}
		pricing := cfg.Pricing
		now := time.Now()
		if err := cw.Write([]string{
			"day", "scope_kind", "scope_id", "provider", "model", "upstream_model", "system_paid",
			"requests", "ok", "failed",
			"prompt_tokens", "completion_tokens", "total_tokens",
			"cache_hit_tokens", "cache_miss_tokens",
			"charge_frozen", "frozen_charges", "amount", "currency",
		}); err != nil {
			return err
		}
		for _, r := range rows {
			amount := store.RowCharge(r.UsageRow, pricingCostFunc(&pricing), now)
			if err := cw.Write([]string{
				r.Day, string(r.Scope.Kind), r.Scope.ID,
				r.Provider, r.Model, r.UpstreamModel, boolY(r.SystemPaid),
				itoa(r.Requests), itoa(r.OK), itoa(r.Failed),
				itoa(r.PromptTokens), itoa(r.CompletionTokens), itoa(r.TotalTokens),
				itoa(r.CacheHitTokens), itoa(r.CacheMissTokens),
				f64s(r.Charge), itoa(r.FrozenCharges), f64s(amount), pricing.Currency,
			}); err != nil {
				return err
			}
		}
	}
	if *out != "" {
		fmt.Printf("已写入 %s\n", *out)
	}
	return cw.Error()
}

// parseExportScope 把 -scope 落成范围指针：空串 = 全部范围（nil），
// 而不是「传个零值 ScopeRef」—— 后者会被 store 的守卫拒掉，正是它该拒的样子。
func parseExportScope(s string) (*policy.ScopeRef, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	ref, err := parseExactScope(s)
	if err != nil {
		return nil, err
	}
	return &ref, nil
}

// parseExactScope 把一个命令行/查询参数解析成**精确**的范围键（kind:id）。
//
// 通配（* 与 kind:*）在这儿就拒掉：这些调用点要的是「某一个范围的账/价目」，
// 收下通配等于让「全部」成为一个可选的默认值，而导出的文件名与审计目标都按单范围算。
func parseExactScope(s string) (policy.ScopeRef, error) {
	sel, err := policy.ParseScopeSelector(s)
	if err != nil {
		return policy.ScopeRef{}, err
	}
	if sel.All || sel.ID == "*" {
		return policy.ScopeRef{}, fmt.Errorf("需要精确的 kind:id（通配请逐个范围各来一次），当前是 %q", s)
	}
	return policy.NewScopeRef(sel.Kind, sel.ID)
}

// pricingCostFunc 把 PricingConfig 适配成 store.CostFunc。
func pricingCostFunc(p *config.PricingConfig) store.CostFunc {
	return func(model string, hit, miss, out int64, at time.Time) (float64, bool) {
		if p == nil || !p.Enabled() {
			return 0, false
		}
		return p.Cost(model, hit, miss, out, at)
	}
}

func parseDay(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	return time.ParseInLocation("2006-01-02", s, time.Local)
}

func itoa(v int64) string { return fmt.Sprintf("%d", v) }

func f64s(v float64) string { return fmt.Sprintf("%.6f", v) }

func boolY(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
