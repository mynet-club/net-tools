package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

const priceUsage = `llmproxy price — 录入与查看价目（provider_prices / user_prices）

  llmproxy price list                                 当前生效的全部价目
  llmproxy price list -provider P -upstream-model M   该 (供应商,模型) 的全部历史
  llmproxy price list -scope S -model M               该 (scope,模型) 的全部历史
  llmproxy price set provider <供应商> <上游模型> [选项]    录一条上游价
  llmproxy price set user <scope> <模型> [选项]            录一条分发价

选项（单价单位都是「每百万 token」，CNY）:
  -in-miss X        未命中缓存的输入（必填）
  -in-hit Y         命中缓存的输入（缺省 = 0）
  -in-write W       写入缓存的输入（留空 = 与 in_miss 同价）
  -out Z            输出（必填）
  -fee F            每请求固定费（缺省 0，不随峰谷浮动）
  -peak-hours "09:00-12:00,14:00-18:00"   高峰时段（逗号分隔）
  -off-peak-ratio R 空闲时段系数（如 0.5 = 半价）
  -peak-tz "+08:00" 时段按哪个时区判（固定偏移，不要写 Asia/Shanghai）
  -valid-from T     RFC3339 整点，如 2026-09-24T16:00:00Z；缺省 = 下一个整点
  -note N           备注（折扣来源、依据的官网报价等）

说明:
  * **价目只在整点生效**，所以 valid_from 必须整点；缺省取下一个整点而不是现在。
  * **按时间只追加**：插入新价时，此前有效的那条自动收口成 [旧.valid_from, 新.valid_from)，
    历史不会被改写，可以随时回溯「这一笔当时用的是哪一档」。
  * 币种必须与基准币（config.yaml 的 pricing.currency，缺省 CNY）一致 ——
    目前不做汇率换算，混币种会让规则 B 比错价（能差好几倍）。
  * scope 只能是 default 或 user:<用户名>。
`

// priceFlags 是 provider 与 user 两种录价共用的一套参数。
type priceFlags struct {
	inMiss, inHit, inWrite, out, fee, offPeak float64
	hasInWrite, hasOffPeak                    bool
	peakHours                                 string
	peakTZ                                    string
	validFrom                                 string
	note                                      string
	currency                                  string
}

func registerPriceFlags(fs *flag.FlagSet, p *priceFlags) {
	fs.Float64Var(&p.inMiss, "in-miss", 0, "未命中缓存的输入")
	fs.Float64Var(&p.inHit, "in-hit", 0, "命中缓存的输入")
	fs.Float64Var(&p.inWrite, "in-write", 0, "写入缓存的输入（留空 = 与 in_miss 同价）")
	fs.Float64Var(&p.out, "out", 0, "输出")
	fs.Float64Var(&p.fee, "fee", 0, "每请求固定费")
	fs.Float64Var(&p.offPeak, "off-peak-ratio", 0, "空闲时段系数")
	fs.StringVar(&p.peakHours, "peak-hours", "", "高峰时段，逗号分隔")
	fs.StringVar(&p.peakTZ, "peak-tz", "", "时段按哪个时区判（固定偏移）")
	fs.StringVar(&p.validFrom, "valid-from", "", "RFC3339 整点；缺省下一个整点")
	fs.StringVar(&p.note, "note", "", "备注")
	fs.StringVar(&p.currency, "currency", "", "币种；缺省 = 基准币")
}

// markExplicit 标出哪些参数是**显式传了**的。
//
// 必须在 fs.Parse 之后调 —— Visit 只报告「被设置过」的标志，注册时调用永远是空的。
// 这两个区分很要紧：in-write 显式传 0 表示「与 in_miss 同价」，而「没传」也是这个意思，
// 但 off-peak-ratio 显式传 0 表示「空闲时段免费」，与「没传（回落全局）」语义完全不同。
func (p *priceFlags) markExplicit(fs *flag.FlagSet) {
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "in-write":
			p.hasInWrite = true
		case "off-peak-ratio":
			p.hasOffPeak = true
		}
	})
}

// toPeakRule 组装价目行自带的峰谷规则。三项都可空，为空则回落全局。
func (p *priceFlags) peakHoursList() []string {
	if strings.TrimSpace(p.peakHours) == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(p.peakHours, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func cmdPrice(paths config.Paths, args []string) error {
	if len(args) == 0 {
		fmt.Print(priceUsage)
		return nil
	}
	switch args[0] {
	case "list":
		return priceList(paths, args[1:])
	case "set":
		return priceSet(paths, args[1:])
	case "help", "-h", "--help":
		fmt.Print(priceUsage)
		return nil
	default:
		return fmt.Errorf("未知的 price 子命令 %q\n\n%s", args[0], priceUsage)
	}
}

func openPriceStore(paths config.Paths) (*store.Store, *config.Config, error) {
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

func priceList(paths config.Paths, args []string) error {
	fs := flag.NewFlagSet("price list", flag.ContinueOnError)
	provider := fs.String("provider", "", "供应商名")
	upstream := fs.String("upstream-model", "", "上游模型名")
	scope := fs.String("scope", "", "default 或 user:<名>")
	model := fs.String("model", "", "下游模型名")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, _, err := openPriceStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()
	now := time.Now()

	// 指定了键 → 打它的全部历史；否则打「当前生效」的全部
	if *provider != "" && *upstream != "" {
		rows, err := db.ListProviderPrices(*provider, *upstream)
		if err != nil {
			return err
		}
		fmt.Printf("上游价 %s/%s 的全部历史（%d 条）\n", *provider, *upstream, len(rows))
		for _, r := range rows {
			fmt.Printf("  id=%-3d %s → %s  hit=%g miss=%g write=%g out=%g fee=%g %s\n",
				r.ID, fmtTime(r.ValidFrom), fmtTime(r.ValidTo),
				r.InHit, r.InMiss, r.InWrite, r.Out, r.PerRequestFee, peakSuffix(r.PeakHours, r.OffPeakRatio, r.PeakTZ))
			if r.Note != "" {
				fmt.Printf("       note: %s\n", r.Note)
			}
		}
		return nil
	}
	if *scope != "" && *model != "" {
		rows, err := db.ListUserPrices(*scope, *model)
		if err != nil {
			return err
		}
		fmt.Printf("分发价 %s/%s 的全部历史（%d 条）\n", *scope, *model, len(rows))
		for _, r := range rows {
			fmt.Printf("  id=%-3d %s → %s  hit=%g miss=%g write=%g out=%g fee=%g %s\n",
				r.ID, fmtTime(r.ValidFrom), fmtTime(r.ValidTo),
				r.InHit, r.InMiss, r.InWrite, r.Out, r.PerRequestFee, peakSuffix(r.PeakHours, r.OffPeakRatio, r.PeakTZ))
			if r.Note != "" {
				fmt.Printf("       note: %s\n", r.Note)
			}
		}
		return nil
	}

	ps, err := db.ProviderPricesEffective(now)
	if err != nil {
		return err
	}
	us, err := db.UserPricesEffective(now)
	if err != nil {
		return err
	}
	fmt.Printf("当前生效（%s）\n", now.UTC().Format(time.RFC3339))
	if len(ps) == 0 && len(us) == 0 {
		fmt.Println("  （一条都没有 —— 金额报表只能是估算段）")
	}
	if len(ps) > 0 {
		fmt.Println("上游价（provider_prices）")
		for _, r := range ps {
			fmt.Printf("  %-22s %-16s hit=%-8g miss=%-8g write=%-8g out=%-8g %s\n",
				r.Provider, r.UpstreamModel, r.InHit, r.InMiss, r.InWrite, r.Out,
				peakSuffix(r.PeakHours, r.OffPeakRatio, r.PeakTZ))
		}
	}
	if len(us) > 0 {
		fmt.Println("分发价（user_prices）")
		for _, r := range us {
			fmt.Printf("  %-22s %-16s hit=%-8g miss=%-8g write=%-8g out=%-8g %s\n",
				r.Scope, r.Model, r.InHit, r.InMiss, r.InWrite, r.Out,
				peakSuffix(r.PeakHours, r.OffPeakRatio, r.PeakTZ))
		}
	}
	return nil
}

func priceSet(paths config.Paths, args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("用法: llmproxy price set provider <供应商> <上游模型> [选项]\n" +
			"      llmproxy price set user <scope> <模型> [选项]\n\n" + priceUsage)
	}
	kind, a, b := args[0], args[1], args[2]
	if kind != "provider" && kind != "user" {
		return fmt.Errorf("第一个参数要是 provider 或 user，实际是 %q", kind)
	}

	fs := flag.NewFlagSet("price set", flag.ContinueOnError)
	var p priceFlags
	registerPriceFlags(fs, &p)
	if err := fs.Parse(args[3:]); err != nil {
		return err
	}
	p.markExplicit(fs)

	db, cfg, err := openPriceStore(paths)
	if err != nil {
		return err
	}
	defer db.Close()

	// valid_from 缺省 = 下一个整点。取「下一个」而不是「现在」是为了避开
	// 「只追加」校验：同一 (供应商,模型) 插入与已有行相同的 valid_from 会被拒。
	validFrom := time.Now().UTC().Truncate(time.Hour).Add(time.Hour)
	if p.validFrom != "" {
		validFrom, err = time.Parse(time.RFC3339, p.validFrom)
		if err != nil {
			return fmt.Errorf("valid_from 需要 RFC3339（如 2026-09-24T16:00:00Z）: %w", err)
		}
	}

	// 币种：留空 = 基准币（与服务端 normalizePriceCurrency 同一口径）
	currency := strings.TrimSpace(p.currency)
	if currency == "" {
		currency = cfg.Pricing.Currency
		if currency == "" {
			currency = "CNY"
		}
	}

	note := p.note
	var out *float64 // off_peak_ratio，nil = 回落全局
	if p.hasOffPeak {
		v := p.offPeak
		out = &v
	}

	switch kind {
	case "provider":
		if p.inMiss <= 0 && p.out <= 0 {
			return fmt.Errorf("至少给一个 -in-miss 或 -out（单位：每百万 token）")
		}
		rec := &store.ProviderPrice{
			Provider: a, UpstreamModel: b, Currency: currency,
			InMiss: p.inMiss, InHit: p.inHit, Out: p.out, PerRequestFee: p.fee,
			PeakHours: p.peakHoursList(), OffPeakRatio: out, PeakTZ: p.peakTZ,
			ValidFrom: validFrom, Note: note,
		}
		if p.hasInWrite {
			rec.InWrite = p.inWrite
		}
		if err := db.InsertProviderPrice(rec); err != nil {
			return err
		}
		fmt.Printf("已录上游价 %s/%s\n  valid_from %s  hit=%g miss=%g write=%g out=%g fee=%g\n",
			a, b, validFrom.Format(time.RFC3339), rec.InHit, rec.InMiss, rec.InWrite, rec.Out, rec.PerRequestFee)
	case "user":
		if p.inMiss <= 0 && p.out <= 0 {
			return fmt.Errorf("至少给一个 -in-miss 或 -out（单位：每百万 token）")
		}
		rec := &store.UserPrice{
			Scope: a, Model: b, Currency: currency,
			InMiss: p.inMiss, InHit: p.inHit, Out: p.out, PerRequestFee: p.fee,
			PeakHours: p.peakHoursList(), OffPeakRatio: out, PeakTZ: p.peakTZ,
			ValidFrom: validFrom, Note: note,
		}
		if p.hasInWrite {
			rec.InWrite = p.inWrite
		}
		if err := db.InsertUserPrice(rec); err != nil {
			return err
		}
		fmt.Printf("已录分发价 %s/%s\n  valid_from %s  hit=%g miss=%g write=%g out=%g fee=%g\n",
			a, b, validFrom.Format(time.RFC3339), rec.InHit, rec.InMiss, rec.InWrite, rec.Out, rec.PerRequestFee)
	}
	if hs := p.peakHoursList(); len(hs) > 0 {
		fmt.Printf("  峰谷: %s ×%g @ %s（空闲时段系数；0 表示回落全局）\n",
			strings.Join(hs, ","), p.offPeak, p.peakTZ)
	}
	fmt.Println("  （价目只在整点生效；此前有效的那条已自动收口，历史保留）")
	return nil
}

// fmtTime 把时刻打成简短形态，零值打成「（开放）」（valid_to=0 表示一直有效）。
func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "（开放）"
	}
	return t.UTC().Format("2006-01-02 15:04Z")
}

// peakSuffix 给价目行补一段峰谷说明。
func peakSuffix(hours []string, ratio *float64, tz string) string {
	if len(hours) == 0 {
		return "平峰"
	}
	r := "回落全局"
	if ratio != nil {
		r = fmt.Sprintf("×%g", *ratio)
	}
	if tz != "" {
		return fmt.Sprintf("峰谷 %s %s @%s", strings.Join(hours, ","), r, tz)
	}
	return fmt.Sprintf("峰谷 %s %s", strings.Join(hours, ","), r)
}
