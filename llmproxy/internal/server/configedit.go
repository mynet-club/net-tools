package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
	"github.com/mynet-club/net-tools/llmproxy/internal/secrets"
)

// 配置文件的控制台编辑（仅管理员）。
//
// 三条不能破的规矩：
//
//  1. **只替换 providers 段的正文**，段外字节一律不动 —— 那份文件里的注释是维护信息
//     （比如「海外上游要写 192.168.0.3:7890」），整体 marshal 会把它们全抹掉。
//  2. **请求里 api_key 为空 = 沿用原值**。界面上拿到的一律是脱敏值，
//     要是把脱敏值当密钥写回去，一次保存就把所有密钥清空了。
//  3. **写之前先校验、写之前先备份**。校验不过就原文件不动；
//     备份文件名带时间戳，段内注释万一被重渲染掉，还能从备份里捞回来。
const configBackupKeep = 5

// handleAdminConfig 处理 /v1/_admin/config*
func (s *Server) handleAdminConfig(w http.ResponseWriter, r *http.Request, rest string) {
	switch strings.Trim(rest, "/") {
	case "":
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.adminShowConfig(w)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
				"配置文件用 GET 读、PUT 写（/v1/_admin/config/providers）")
		}
	case "providers":
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			s.adminSaveProviders(w, r, false)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error",
				"只支持 PUT（要试算用 POST /v1/_admin/config/validate）")
		}
	case "validate":
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "invalid_request_error", "只支持 POST")
			return
		}
		s.adminSaveProviders(w, r, true)
	default:
		writeJSONError(w, http.StatusNotFound, "invalid_request_error",
			"可用路径：/v1/_admin/config、/v1/_admin/config/providers、/v1/_admin/config/validate")
	}
}

// configProviderView 是给界面看的供应商形态：密钥永不下发。
func configProviderView(p config.ProviderRaw) map[string]any {
	models := map[string]any{"passthrough": true}
	if spec, err := config.ParseModelsNode(&p.Models); err == nil {
		switch {
		case spec.Passthrough:
			models = map[string]any{"passthrough": true}
		case spec.CatchAll:
			models = map[string]any{"map": spec.Map, "catch_all": true}
		default:
			models = map[string]any{"map": spec.Map}
		}
	}
	hint := ""
	switch {
	case p.APIKey == "":
		hint = ""
	case strings.Contains(p.APIKey, "${"):
		hint = p.APIKey + "（环境变量）" // 变量名不是机密，显示出来便于核对
	default:
		hint = secrets.Mask(p.APIKey)
	}
	return map[string]any{
		"name":         p.Name,
		"enabled":      p.IsEnabled(),
		"base_url":     p.BaseURL,
		"api_key":      "", // 永不下发；保存时留空 = 沿用原值
		"has_key":      p.APIKey != "",
		"api_key_hint": hint,
		"weight":       p.Weight,
		"proxy":        p.Proxy,
		"timeout_ms":   p.TimeoutMs,
		"models":       models,
	}
}

func (s *Server) adminShowConfig(w http.ResponseWriter) {
	cfg := s.cfgStore.Current()
	path := s.cfgStore.Path()
	src, _ := os.ReadFile(path)
	info := map[string]any{
		"path":      path,
		"revision":  s.cfgStore.Revision(),
		"reload_s":  2, // 热加载轮询间隔
		"providers": []map[string]any{},
		"warnings":  cfg.Warnings,
	}
	if st, err := os.Stat(path); err == nil {
		info["mtime"] = st.ModTime().Format(time.RFC3339)
		info["size"] = st.Size()
	}
	// 视图要从**文件原文**构建，不能用加载后的 Config：后者里的 api_key 已被环境变量
	// 展开，于是 ${MYTEST_KEY} 会显示成 ****alue —— 泄漏了环境变量里那把密钥的尾巴，
	// 而管理员本来只看得到文件（文件里压根没有明文）。
	rawList, rawErr := config.RawProviders(src)
	if rawErr != nil {
		rawList = cfg.Providers
	}
	out := make([]map[string]any, 0, len(rawList))
	for _, p := range rawList {
		out = append(out, configProviderView(p))
	}
	info["providers"] = out
	info["routing"] = cfg.Routing
	info["pricing_priced"] = cfg.Pricing.Enabled()
	info["pricing_currency"] = s.pricingCurrency()
	info["server"] = map[string]any{
		"host": cfg.Server.Host, "port": cfg.Server.Port,
		"api_key_count": len(cfg.Server.APIKeys), "admin_token_set": cfg.Server.HasAdminToken(),
	}
	writeJSON(w, http.StatusOK, info)
}

// adminSaveProviders 写回 providers 段。dryRun=true 时只校验不落盘。
func (s *Server) adminSaveProviders(w http.ResponseWriter, r *http.Request, dryRun bool) {
	var req struct {
		Providers []struct {
			Name      string          `json:"name"`
			Enabled   *bool           `json:"enabled"`
			BaseURL   string          `json:"base_url"`
			APIKey    string          `json:"api_key"`
			Weight    float64         `json:"weight"`
			Proxy     string          `json:"proxy"`
			TimeoutMs int             `json:"timeout_ms"`
			Models    json.RawMessage `json:"models"`
		} `json:"providers"`
	}
	if err := readJSONBody(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	if len(req.Providers) == 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"providers 不能为空：至少保留一个供应商")
		return
	}

	path := s.cfgStore.Path()
	src, err := os.ReadFile(path)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal",
			"读取配置文件失败: "+err.Error())
		return
	}
	// 原来的 api_key 必须从**文件原文**取：加载后的 Config 里那个值已经被环境变量
	// 展开过了，拿它写回会把 ${ENV} 换成明文密钥。
	rawList, err := config.RawProviders(src)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	current := map[string]string{}
	for _, p := range rawList {
		current[p.Name] = p.APIKey
	}

	out := make([]config.ProviderRaw, 0, len(req.Providers))
	seen := map[string]bool{}
	for i, in := range req.Providers {
		name := strings.TrimSpace(in.Name)
		if name == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
				fmt.Sprintf("第 %d 个供应商没有名字", i+1))
			return
		}
		if seen[name] {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
				fmt.Sprintf("供应商名 %q 重复", name))
			return
		}
		seen[name] = true
		if strings.TrimSpace(in.BaseURL) == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
				fmt.Sprintf("供应商 %s 缺少 base_url", name))
			return
		}

		p := config.ProviderRaw{
			Name: name, BaseURL: strings.TrimSpace(in.BaseURL),
			APIKey: in.APIKey, Weight: in.Weight,
			Proxy: strings.TrimSpace(in.Proxy), TimeoutMs: in.TimeoutMs,
		}
		if in.Enabled != nil {
			p.Enabled.Set = true
			p.Enabled.Value = *in.Enabled
		} else {
			p.Enabled.Set = true
			p.Enabled.Value = true
		}
		// 关键：留空 = 沿用原值，绝不等于清空
		if p.APIKey == "" {
			if raw, ok := current[name]; ok {
				p.APIKey = raw
			} else if p.IsEnabled() {
				writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
					fmt.Sprintf("新的供应商 %s 必须填 api_key（否则启用后每个请求都会 401）", name))
				return
			}
		}

		node, err := config.ModelsNode(modelsValue(in.Models))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
				fmt.Sprintf("供应商 %s 的 models 不合法: %v", name, err))
			return
		}
		p.Models = node
		out = append(out, p)
	}

	newSrc, err := config.EditProviders(src, out)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}

	// 先落一个临时文件用宽松模式校验：写回后的文件必须仍然能被正常加载。
	// 用宽松通道是刻意的 —— 配置里写 ${ENV} 是推荐做法，环境变量没设不该算错。
	tmp := path + ".new"
	if err := os.WriteFile(tmp, newSrc, 0o600); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "写临时文件失败: "+err.Error())
		return
	}
	parsed, err := config.LoadFileLenient(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		writeJSONError(w, http.StatusBadRequest, "invalid_request_error",
			"写回后的配置校验不通过，原文件未改动："+err.Error())
		return
	}

	// 宽松通道能过，不代表**服务**能加载：热加载走的是严格模式，
	// 比如「启用的供应商用了 ${ENV} 但环境变量没设」就会让热加载失败。
	// 这种情况文件该写还是写（可能是在提前准备配置），但必须明确告诉用户它不会生效。
	strictErr := ""
	if _, err := config.LoadFile(tmp); err != nil {
		strictErr = err.Error()
	}

	if dryRun {
		_ = os.Remove(tmp)
		out := map[string]any{
			"dry_run":   true,
			"ok":        true,
			"providers": len(parsed.Normalized),
			"warnings":  parsed.Warnings,
			"preview":   string(newSrc),
		}
		if strictErr != "" {
			out["strict_ok"] = false
			out["strict_error"] = strictErr
			out["warning"] = "配置能写进文件，但服务加载不了，改动不会生效：" + strictErr
		} else {
			out["strict_ok"] = true
		}
		writeJSON(w, http.StatusOK, out)
		return
	}

	backup, err := backupConfig(path, src)
	if err != nil {
		_ = os.Remove(tmp)
		writeJSONError(w, http.StatusInternalServerError, "internal", "备份失败，已放弃写入: "+err.Error())
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		writeJSONError(w, http.StatusInternalServerError, "internal", "写入失败: "+err.Error())
		return
	}
	if err := os.Chmod(path, 0o600); err != nil {
		s.log.Warnf("收紧配置文件权限失败: %v", err)
	}
	s.log.Warnf("管理员通过控制台改写了配置文件的 providers 段（备份 %s）", filepath.Base(backup))

	// 等热加载轮询把它装进去，好让界面能给出确定答复（而不是「过一会儿就好了」）
	before := s.cfgStore.Revision()
	applied := false
	// 等待时长在 New 里初始化；测试置 0 即跳过（那时热加载轮询也没在跑）
	deadline := time.Now().Add(s.configApplyWait)
	for time.Now().Before(deadline) {
		if s.cfgStore.Revision() != before {
			applied = true
			break
		}
		time.Sleep(150 * time.Millisecond)
	}

	resp := map[string]any{
		"written": true,
		"applied": applied,
		"backup":  filepath.Base(backup),
		"path":    path,
		"count":   len(out),
		"note":    "只替换了 providers 段，文件其余部分与注释保持原样",
	}
	if applied {
		resp["revision"] = s.cfgStore.Revision()
	} else {
		resp["note"] = resp["note"].(string) + "；热加载尚未完成（最多 2 秒），稍后刷新看结果"
	}
	if strictErr != "" {
		resp["strict_ok"] = false
		resp["strict_error"] = strictErr
		resp["warning"] = "文件已写入，但服务加载它会失败，改动不会生效；" +
			"自己先确认这条错误：" + strictErr
	} else {
		resp["strict_ok"] = true
	}
	if len(parsed.Warnings) > 0 {
		resp["warnings"] = parsed.Warnings
	}
	writeJSON(w, http.StatusOK, resp)
}

// modelsValue 把请求里的 models 规整成可编码的值：空 → 直通。
func modelsValue(raw []byte) any {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return []string{"*"}
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return []string{"*"}
	}
	return v
}

// backupConfig 备份原文件，并只保留最近 N 份。
func backupConfig(path string, src []byte) (string, error) {
	dir := filepath.Dir(path)
	name := fmt.Sprintf("%s.bak-%s", filepath.Base(path), time.Now().Format("20060102-150405"))
	dst := filepath.Join(dir, name)
	if err := os.WriteFile(dst, src, 0o600); err != nil {
		return "", err
	}

	// 清理旧备份（配置里可能有明文密钥，备份别无限堆）
	entries, err := filepath.Glob(filepath.Join(dir, filepath.Base(path)+".bak-*"))
	if err != nil || len(entries) <= configBackupKeep {
		return dst, nil
	}
	sort.Strings(entries)
	for _, old := range entries[:len(entries)-configBackupKeep] {
		_ = os.Remove(old)
	}
	return dst, nil
}
