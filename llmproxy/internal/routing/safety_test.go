package routing

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// forbiddenImports 是本包的依赖禁区，逐条对应交付说明里的硬边界：
//
//	net/http        —— §3.D 禁止在线调用外部 AI 决策路由，规划器里出现网络调用即违规；
//	database/sql    —— 状态一律由调用方作为数据传入（查库归接线方）；
//	internal/config / store / server / router —— 一旦 import，D 就变成现网路由的第二份实现，
//	                    而且再也无法在管理台里拿任意输入试跑（影子运行的前提）；
//	math/rand       —— 全局源不可复现，且别人的 Seed 会作废历史审计（§2.8）。
//
// 写成测试而不是只写在注释里，是因为「顺手 import 一下 config 拿权重」这种改动
// 在评审里最容易看漏，而它会把整个可回放契约悄悄废掉。
var forbiddenImports = []string{
	"net/http",
	"database/sql",
	"math/rand",
	"github.com/mynet-club/net-tools/llmproxy/internal/config",
	"github.com/mynet-club/net-tools/llmproxy/internal/store",
	"github.com/mynet-club/net-tools/llmproxy/internal/server",
	"github.com/mynet-club/net-tools/llmproxy/internal/router",
}

func TestPackageImportsStayInsideTheBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		path := filepath.Join(".", e.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", path, err)
		}
		for _, imp := range file.Imports {
			imported := trimQuotes(imp.Path.Value)
			for _, ban := range forbiddenImports {
				if imported == ban {
					t.Errorf("%s import 了禁区包 %s（见 forbiddenImports 的理由）", path, imported)
				}
			}
			// 出网相关的标准库也一并盯住：规划器不需要任何 socket。
			if imported == "net" || imported == "net/url" || imported == "os" && !strings.HasSuffix(path, "_test.go") {
				t.Errorf("%s import 了 %s：规划器不碰网络与进程环境", path, imported)
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("一个源文件都没扫到，这条边界测试等于没跑")
	}
}

// trimQuotes 去掉 import 路径字面量的引号（parser 给出的是带引号的原文）。
func trimQuotes(s string) string { return strings.Trim(s, "\"") }

// D 的**可序列化**类型不得引用活世界：接口/函数/通道/map 一个都不许出现。
//
// 为什么盯这么紧：§2.8 要求回放不依赖当前 provider 配置与实时数据库状态。
// 只要 ReplayInput 里出现一个 interface 或 func 字段，就有人能往里塞活的 resolver、
// 活的连接池，而快照看起来仍是「数据」，回放结论却跟着今天的配置走 ——
// 那种假复现比不复现更坏。
func TestSerializableTypesCarryNoLiveReferences(t *testing.T) {
	for _, value := range []any{
		Offer{}, ReplayOffer{}, ReplayInput{}, Requirement{}, StickyState{}, Input{}.Requirement,
	} {
		assertLiveReferenceFree(t, reflect.TypeOf(value), "")
	}
}

func assertLiveReferenceFree(t *testing.T, typ reflect.Type, path string) {
	t.Helper()
	for typ != nil && typ.Kind() == reflect.Ptr {
		// 指针只允许指向本包/本域的纯数据结构（StickyState）；指针本身是可搬运的数据，
		// 但指向接口或函数就等价于塞了活依赖。
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Interface, reflect.Func, reflect.Chan, reflect.UnsafePointer, reflect.Map:
		t.Errorf("%s%s 是 %s：可序列化输入里不得出现活依赖或遍历顺序不定的容器", path, typ.Name(), typ.Kind())
	case reflect.Slice:
		assertLiveReferenceFree(t, typ.Elem(), path+"[]")
	case reflect.Struct:
		if typ.PkgPath() == "" {
			return // 内置时间等未导出包路径的类型只由标准库定义，本身就是值
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.PkgPath != "" {
				continue // 未导出字段不参与序列化
			}
			assertLiveReferenceFree(t, f.Type, path+typ.Name()+"."+f.Name)
		}
	}
}

// 不泄露：D 的输出类型不得携带正文 / 端点 / 凭证类字段。
// 与 internal/policy 的反射断言同一口径（词表在这里复制一份是刻意的：
// 本包不能为了复用一张表而 import 测试辅助包，两张表都失败才叫真的挡住）。
func TestRoutingTypesCarryNoBodyOrCredentials(t *testing.T) {
	forbidden := []string{
		"body", "payload", "content", "apikey", "api_key", "secret", "token",
		"baseurl", "base_url", "password", "credential", "raw",
	}
	for _, value := range []any{
		Offer{}, policy.RouteCandidate{}, policy.Rejection{}, policy.RoutingPlan{},
		ReplayOffer{}, ReplayInput{}, Requirement{}, StickyState{}, gateVerdict{},
	} {
		typ := reflect.TypeOf(value)
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.PkgPath != "" {
				continue
			}
			haystack := strings.ToLower(f.Name + "|" + f.Tag.Get("json"))
			for _, word := range forbidden {
				if strings.Contains(haystack, word) {
					t.Errorf("%s.%s（json=%q）含被禁字段词 %q：路由对象不得携带正文、端点或凭证",
						typ.Name(), f.Name, f.Tag.Get("json"), word)
				}
			}
		}
	}
}

// 计划与快照的序列化结果里不得出现端点、密钥或正文痕迹。
// 这里用反射断言之外的口径再查一遍内容：字段名合法不代表有人不往字符串字段里塞 URL。
func TestPlanAndSnapshotJSONHasNoEndpointsOrSecrets(t *testing.T) {
	ctx := ctxFor(t, policy.LevelInternal)
	chain := orgChain(t)
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder, replayOffersForSafety()...)
	in.ProcessorChain = []string{"redact"}
	in.Seed = deriveSeed(t, "req-leak", testPolicyVer)

	plan, snapshot, err := NewPlanner().PlanWithReplay(ctx, chain, in)
	if err != nil {
		t.Fatal(err)
	}
	planJSON, err := marshalString(plan)
	if err != nil {
		t.Fatal(err)
	}
	snapJSON, err := marshalString(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	needle := []string{"http://", "https://", "10.", "sk-", "Bearer", "authorization", "@example.com"}
	for _, blob := range []string{planJSON, snapJSON} {
		for _, n := range needle {
			if strings.Contains(strings.ToLower(blob), strings.ToLower(n)) {
				t.Errorf("序列化结果含可疑内容 %q:\n%s", n, blob)
			}
		}
	}
}

func marshalString(v any) (string, error) {
	data, err := json.Marshal(v)
	return string(data), err
}

func replayOffersForSafety() []Offer {
	return []Offer{
		offerFor("alpha", 0, 3, testModel).withRegion("cn"),
		offerFor("beta", 0, 1, testModel),
		offerFor("gamma", 1, 2, testModel).withCapabilities(),
	}
}

// 计划的 JSON 字段集合是封闭的：多出一个字段就等于往审计里加了新数据源，
// 而那些字段没人评审过（可能含端点、也可能含正文摘要）。
func TestPlanJSONFieldSetIsClosed(t *testing.T) {
	allowed := map[string]bool{
		"executor": true, "model": true, "upstream_model": true, "fallbacks": true,
		"processor_chain": true, "max_retries": true, "reason_codes": true,
		"policy_version": true, "expires_at": true, "routing_seed": true, "rejections": true,
		"provider": true, "weight": true, "region": true, "max_data_level": true, "reason": true,
	}
	ctx := ctxFor(t, policy.LevelInternal)
	in := inputFor(&allowAllGate{}, ObjectiveFixedOrder, replayOffersForSafety()...)
	in.Seed = deriveSeed(t, "req-fields", testPolicyVer)
	plan, _, err := NewPlanner().PlanWithReplay(ctx, orgChain(t), in)
	if err != nil {
		t.Fatal(err)
	}
	typ := reflect.TypeOf(plan)
	for i := 0; i < typ.NumField(); i++ {
		name := jsonTagName(typ.Field(i).Tag.Get("json"))
		if !allowed[name] {
			t.Errorf("计划多出了未评审的字段 %q", name)
		}
	}
}

func jsonTagName(tag string) string {
	if i := strings.Index(tag, ","); i >= 0 {
		return tag[:i]
	}
	return tag
}
