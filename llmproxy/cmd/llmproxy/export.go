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
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// cmdExport 出用量 CSV：对账 / 报销 / 给用户看账单。
// 金额口径与配额一致（store.RowCharge 冻结优先），所以导出的数能和 `status` 对上。
func cmdExport(paths config.Paths, args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	user := fs.String("user", "", "只导出该用户（空 = 全部）")
	since := fs.String("since", "", "起始日 YYYY-MM-DD（含）")
	until := fs.String("until", "", "结束日 YYYY-MM-DD（含）")
	monthly := fs.Bool("monthly", false, "按月×用户合计（账单口径），而不是按日明细")
	out := fs.String("out", "", "输出文件（省略 = 写到标准输出）")
	if err := fs.Parse(args); err != nil {
		return err
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
		rows, err := db.MonthlyRollup(sinceT, untilT, *user)
		if err != nil {
			return err
		}
		if err := cw.Write([]string{
			"month", "user_name", "requests", "ok", "failed",
			"total_tokens", "charge", "frozen_charges",
		}); err != nil {
			return err
		}
		for _, r := range rows {
			if err := cw.Write([]string{
				r.Month, r.UserName,
				itoa(r.Requests), itoa(r.OK), itoa(r.Failed), itoa(r.Tokens),
				f64s(r.Charge), itoa(r.Frozen),
			}); err != nil {
				return err
			}
		}
	} else {
		f := store.UsageExportFilter{UserName: *user, Since: sinceT, Until: untilT}
		rows, err := db.UsageExportRows(f)
		if err != nil {
			return err
		}
		pricing := cfg.Pricing
		now := time.Now()
		if err := cw.Write([]string{
			"day", "user_name", "provider", "model", "upstream_model", "system_paid",
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
				r.Day, r.UserName, r.Provider, r.Model, r.UpstreamModel, boolY(r.SystemPaid),
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
