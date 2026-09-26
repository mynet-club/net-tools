package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/store"
)

// 价目的管理接口（B1 的写入入口）。
//
// 设计见 docs/pricing-design.md。没有这个入口，生产上就没有任何办法录价，
// B2「落库时冻结」也就无从谈起 —— 所以它属于数据层，不属于"以后再说"的界面。
//
// 三条约束在 store 层保证，这里只是把它们暴露出来：
//   - valid_from 必须整点（价格只在整点生效，拒绝非整点、不静默取整）
//   - 价目按时间只追加，插入时自动收口此前的有效行（历史天然保留）
//   - 分发价的 scope 只能是 "default" 或 "user:<用户名>"

// providerPriceIn / userPriceIn 是接口的入参形状。
// 时间用 RFC3339 字符串（例如 "2026-09-21T09:00:00+08:00"），**必须带时区偏移**
// （`Z` 也算）—— 解析走 time.Parse(time.RFC3339, …)，不带偏移会直接失败。
// 时刻本身还**必须是整点**，校验在 store 层。
type providerPriceIn struct {
	Provider      string   `json:"provider"`
	UpstreamModel string   `json:"upstream_model"`
	Currency      string   `json:"currency"`
	InMiss        float64  `json:"in_miss"`
	InHit         float64  `json:"in_hit"`
	InWrite       float64  `json:"in_write"`
	Out           float64  `json:"out"`
	ReasoningOut  float64  `json:"reasoning_out"`
	PerRequestFee float64  `json:"per_request_fee"`
	PeakHours     []string `json:"peak_hours"`
	OffPeakRatio  *float64 `json:"off_peak_ratio"`
	PeakTZ        string   `json:"peak_tz"`
	ValidFrom     string   `json:"valid_from"`
	ValidTo       string   `json:"valid_to"`
	Note          string   `json:"note"`
}

type userPriceIn struct {
	Scope         string   `json:"scope"`
	Model         string   `json:"model"`
	Currency      string   `json:"currency"`
	InMiss        float64  `json:"in_miss"`
	InHit         float64  `json:"in_hit"`
	InWrite       float64  `json:"in_write"`
	Out           float64  `json:"out"`
	ReasoningOut  float64  `json:"reasoning_out"`
	PerRequestFee float64  `json:"per_request_fee"`
	PeakHours     []string `json:"peak_hours"`
	OffPeakRatio  *float64 `json:"off_peak_ratio"`
	PeakTZ        string   `json:"peak_tz"`
	ValidFrom     string   `json:"valid_from"`
	ValidTo       string   `json:"valid_to"`
	Note          string   `json:"note"`
}

// parsePriceTime 解析 RFC3339 时间；空串 = 零值（一直有效 / 由校验决定）。
func parsePriceTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("时间需要是 RFC3339（例如 2026-09-21T09:00:00+08:00），当前是 %q", s)
	}
	return t, nil
}

func providerPriceJSON(p store.ProviderPrice) map[string]any {
	out := map[string]any{
		"id": p.ID, "provider": p.Provider, "upstream_model": p.UpstreamModel,
		"currency": p.Currency,
		"in_miss":  p.InMiss, "in_hit": p.InHit, "in_write": p.InWrite,
		"out": p.Out, "reasoning_out": p.ReasoningOut, "per_request_fee": p.PerRequestFee,
		"note": p.Note, "created_at": p.CreatedAt,
	}
	if len(p.PeakHours) > 0 {
		out["peak_hours"] = p.PeakHours
	}
	if p.OffPeakRatio != nil {
		out["off_peak_ratio"] = *p.OffPeakRatio
	}
	if p.PeakTZ != "" {
		out["peak_tz"] = p.PeakTZ
	}
	out["valid_from"] = p.ValidFrom
	if !p.ValidTo.IsZero() {
		out["valid_to"] = p.ValidTo
	}
	return out
}

func userPriceJSON(p store.UserPrice) map[string]any {
	out := map[string]any{
		"id": p.ID, "scope": p.Scope, "model": p.Model, "currency": p.Currency,
		"in_miss": p.InMiss, "in_hit": p.InHit, "in_write": p.InWrite,
		"out": p.Out, "reasoning_out": p.ReasoningOut, "per_request_fee": p.PerRequestFee,
		"note": p.Note, "created_at": p.CreatedAt, "valid_from": p.ValidFrom,
	}
	if len(p.PeakHours) > 0 {
		out["peak_hours"] = p.PeakHours
	}
	if p.OffPeakRatio != nil {
		out["off_peak_ratio"] = *p.OffPeakRatio
	}
	if p.PeakTZ != "" {
		out["peak_tz"] = p.PeakTZ
	}
	if !p.ValidTo.IsZero() {
		out["valid_to"] = p.ValidTo
	}
	return out
}

// adminPricesRoute 分发 /v1/_admin/prices/**。
//
//	PUT  /v1/_admin/prices/provider        写入一条上游价目
//	GET  /v1/_admin/prices/provider?provider=&upstream_model=   查该键的全部历史
//	PUT  /v1/_admin/prices/user            写入一条分发价目
//	GET  /v1/_admin/prices/user?scope=&model=                    查该键的全部历史
//	GET  /v1/_admin/prices/effective       当前仍然生效的全部上游价目（路由用）
func (s *Server) adminPricesRoute(w http.ResponseWriter, r *http.Request, tail string) {
	switch {
	case tail == "provider":
		switch r.Method {
		case http.MethodPut:
			s.adminPutProviderPrice(w, r)
		case http.MethodGet:
			s.adminListProviderPrices(w, r)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET / PUT")
		}
	case tail == "user":
		switch r.Method {
		case http.MethodPut:
			s.adminPutUserPrice(w, r)
		case http.MethodGet:
			s.adminListUserPrices(w, r)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 GET / PUT")
		}
	case tail == "effective" && r.Method == http.MethodGet:
		s.adminEffectivePrices(w, r)
	default:
		writeJSONError(w, http.StatusNotFound, "invalid_request_error",
			"可用路径：/v1/_admin/prices/provider[?provider=&upstream_model=]、"+
				"/v1/_admin/prices/user[?scope=&model=]、/v1/_admin/prices/effective")
	}
}

// baseCurrency 是当前配置的基准币（pricing.currency；未配时 normalize 会填成 CNY）。
func (s *Server) baseCurrency() string {
	if c := s.cfgStore.Current(); c != nil && c.Pricing.Currency != "" {
		return c.Pricing.Currency
	}
	return "CNY"
}

// normalizePriceCurrency 校验并归一价目行的币种，返回应当落库的值。
//
// 两张价目表都带 currency 列，但聚合、比价、报表**都不看它** —— 设计文档 §3 写了
// 「多供应商后可能混币种；聚合前换算到基准币」，而换算还没实现。在实现之前必须先把
// 混币种挡在门外，否则全是静默算错：
//
//   - 规则 B 会**比错价**：一家报 USD `in_miss=2.5 / out=10`、另一家报 CNY `2 / 8`，
//     数值上后者(10)胜出，而前者约合 ¥18 / ¥72 其实更便宜 —— 选错供应商，成本差 3~7 倍。
//   - `requests.currency` 只有一列却装两层金额：上游价 USD、分发价 CNY 时，
//     charge（CNY 数值）会被存在 currency='USD' 的行里。
//   - 用量报表一律贴全局 currency 标签，录了 USD 的行也会被标成 CNY。
//
// 留空 = 跟随基准币。这里就把空值填成基准币、并把大小写统一，而不是留给 store 层去填
// 它自己硬编码的 "CNY" —— 那样在基准币不是 CNY 时会存进一个与基准币不符的值，
// 再被下面的比价护栏悄悄排除掉。
//
// 这是把「静默算错」换成「响亮报错」，不是支持多币种 —— 真要混币种得先做换算。
func (s *Server) normalizePriceCurrency(got string) (string, error) {
	base := s.baseCurrency()
	got = strings.TrimSpace(got)
	if got == "" || strings.EqualFold(got, base) {
		return base, nil
	}
	return "", fmt.Errorf("currency %q 与基准币 %q 不一致，已拒绝：目前不做汇率换算，"+
		"混币种会让规则 B 比错价（可能选出贵几倍的供应商）、报表的币种标签也会撒谎。"+
		"请先按 %s 换算好再录，或把 pricing.currency 改成 %s",
		got, base, base, got)
}

// sameCurrency 报告价目行的币种能否与基准币放在一起比较/聚合。
// 供选路侧做防御性判断（库里可能有早于写入校验的行，或被直接 SQL 插进来的）。
func sameCurrency(priceCurrency, base string) bool {
	priceCurrency = strings.TrimSpace(priceCurrency)
	return priceCurrency == "" || strings.EqualFold(priceCurrency, strings.TrimSpace(base))
}

func (s *Server) adminPutProviderPrice(w http.ResponseWriter, r *http.Request) {
	var in providerPriceIn
	if err := readJSONBody(w, r, &in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	currency, err := s.normalizePriceCurrency(in.Currency)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	validFrom, err := parsePriceTime(in.ValidFrom)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "valid_from: "+err.Error())
		return
	}
	validTo, err := parsePriceTime(in.ValidTo)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "valid_to: "+err.Error())
		return
	}
	p := &store.ProviderPrice{
		Provider: in.Provider, UpstreamModel: in.UpstreamModel, Currency: currency,
		InMiss: in.InMiss, InHit: in.InHit, InWrite: in.InWrite, Out: in.Out,
		ReasoningOut: in.ReasoningOut, PerRequestFee: in.PerRequestFee,
		PeakHours: in.PeakHours, OffPeakRatio: in.OffPeakRatio, PeakTZ: in.PeakTZ,
		ValidFrom: validFrom, ValidTo: validTo, Note: in.Note,
	}
	if err := s.db.InsertProviderPrice(p); err != nil {
		// 校验类错误（非整点、回填历史、字段缺失）都是调用方的问题
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	s.usageCache.Flush() // 估算段金额跟着单价走
	s.log.Infof("写入上游价目 %s / %s（自 %s，out=%v %s）",
		p.Provider, p.UpstreamModel, p.ValidFrom.Format(time.RFC3339), p.Out, p.Currency)
	writeJSON(w, http.StatusOK, map[string]any{"inserted": providerPriceJSON(*p)})
}

func (s *Server) adminPutUserPrice(w http.ResponseWriter, r *http.Request) {
	var in userPriceIn
	if err := readJSONBody(w, r, &in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	currency, err := s.normalizePriceCurrency(in.Currency)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	validFrom, err := parsePriceTime(in.ValidFrom)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "valid_from: "+err.Error())
		return
	}
	validTo, err := parsePriceTime(in.ValidTo)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "valid_to: "+err.Error())
		return
	}
	p := &store.UserPrice{
		Scope: in.Scope, Model: in.Model, Currency: currency,
		InMiss: in.InMiss, InHit: in.InHit, InWrite: in.InWrite, Out: in.Out,
		ReasoningOut: in.ReasoningOut, PerRequestFee: in.PerRequestFee,
		PeakHours: in.PeakHours, OffPeakRatio: in.OffPeakRatio, PeakTZ: in.PeakTZ,
		ValidFrom: validFrom, ValidTo: validTo, Note: in.Note,
	}
	if err := s.db.InsertUserPrice(p); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	s.usageCache.Flush() // 估算段金额跟着单价走
	s.log.Infof("写入分发价目 %s / %s（自 %s，out=%v %s）",
		p.Scope, p.Model, p.ValidFrom.Format(time.RFC3339), p.Out, p.Currency)
	writeJSON(w, http.StatusOK, map[string]any{"inserted": userPriceJSON(*p)})
}

func (s *Server) adminListProviderPrices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	provider := strings.TrimSpace(q.Get("provider"))
	model := strings.TrimSpace(q.Get("upstream_model"))
	if provider == "" || model == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "需要 provider 与 upstream_model 两个查询参数")
		return
	}
	rows, err := s.db.ListProviderPrices(provider, model)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	list := make([]map[string]any, 0, len(rows))
	for _, p := range rows {
		list = append(list, providerPriceJSON(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"provider": provider, "upstream_model": model, "prices": list,
		"note": "按 valid_from 升序，含历史；valid_to 缺省表示一直有效",
	})
}

func (s *Server) adminListUserPrices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scope := strings.TrimSpace(q.Get("scope"))
	model := strings.TrimSpace(q.Get("model"))
	if scope == "" || model == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", "需要 scope 与 model 两个查询参数")
		return
	}
	rows, err := s.db.ListUserPrices(scope, model)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	list := make([]map[string]any, 0, len(rows))
	for _, p := range rows {
		list = append(list, userPriceJSON(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scope": scope, "model": model, "prices": list,
	})
}

// adminEffectivePrices 给出**当前**仍然生效的全部上游价目。
// 规则 B 的路由（新会话/漂移时按价格排序）读的就是这份。
func (s *Server) adminEffectivePrices(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.ProviderPricesEffective(time.Now())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	list := make([]map[string]any, 0, len(rows))
	for _, p := range rows {
		list = append(list, providerPriceJSON(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"prices": list, "as_of": time.Now()})
}
