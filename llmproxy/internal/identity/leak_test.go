package identity

import (
	"context"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// forbiddenFieldWords 是身份层**对外产物**结构体不得携带的字段名子串。
//
// 与 A 包的口径一致：B 是身份层，凭证原文、签名、私钥材料、claims 内容一旦成为
// 导出字段，就必然会顺着某次 json.Marshal 进审计表、管理台响应或 CI 日志。
// 用反射在评审之外再挡一层，比人盯字段可靠。
//
// 只扫对外产物（Principal/Mapped/AuditEvent）。配置与 fixture 生成类型
// （OIDCConfig、LDAPTrust、UniversityProfile）故意不扫：它们是输入，
// 名字里出现 password/上限之类是正当的（LDAPTrust.MaxPasswordBytes 只是个长度限制），
// 把它们一起扫只会逼人把字段改成难读的名字，反而降低可读性。
var forbiddenFieldWords = []string{
	"token", "secret", "password", "credential", "privatekey", "private_key",
	"signature", "assertion", "body", "payload", "raw", "email", "phone", "mobile",
	"claims",
}

func assertNoForbiddenFields(t *testing.T, value any) {
	t.Helper()
	typ := reflect.TypeOf(value)
	for typ != nil && typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ == nil || typ.Kind() != reflect.Struct {
		t.Fatalf("只对结构体做字段审查，当前是 %v", typ)
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue // 未导出字段不参与序列化
		}
		name := strings.ToLower(field.Name)
		tag := strings.ToLower(field.Tag.Get("json"))
		tagName := tag
		if idx := strings.Index(tag, ","); idx >= 0 {
			tagName = tag[:idx]
		}
		haystack := name + "|" + tagName
		for _, word := range forbiddenFieldWords {
			if strings.Contains(haystack, word) {
				t.Errorf("%s.%s（json=%q）含被禁字段词 %q：身份层对外产物不得携带凭证或 claims 原文",
					typ.Name(), field.Name, tag, word)
			}
		}
	}
}

func TestExportedProductsCarryNoCredentialOrClaimsMaterial(t *testing.T) {
	audit := NewAuditRecorder(0)
	authority := testAuthority(t)
	provider := newOIDC(t, authority, oidcOptions{audit: audit})
	token := mustToken(t, authority, SignRequest{Profile: studentProfile(), At: baseNow})
	principal := resolveOK(t, provider, oidcCredential(t, token))

	for _, value := range []any{
		Principal{}, Mapped{}, AuditEvent{}, ScopeRule{},
		principal, auditMustLast(t, audit),
	} {
		assertNoForbiddenFields(t, value)
	}
}

func auditMustLast(t *testing.T, recorder *AuditRecorder) AuditEvent {
	t.Helper()
	event, ok := recorder.Last()
	if !ok {
		t.Fatal("应有审计事件")
	}
	return event
}

// sensitiveMaterial 是一件敏感值：只带标签，失败时不回显内容本身
// （把泄漏片段的原文打印到测试输出，等于在 CI 日志里再泄一次）。
type sensitiveMaterial struct {
	label string
	value string
}

// secretFixture 汇总一份样例的所有敏感值。
//
// 值全部是假的（.invalid 保留域 + 现场生成的密钥），但形态是真的 ——
// 只有这样断言才有意义：搜「xxx@xxx」这种占位串，真泄了也测不出来。
type secretFixture struct {
	items []sensitiveMaterial
	// token 单独留着，拼装/复用时需要它。
	token string
}

func newSecretFixture(t *testing.T, authority *FakeAuthority, profile UniversityProfile) secretFixture {
	t.Helper()
	token := mustToken(t, authority, SignRequest{Profile: profile, At: baseNow})
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token 形态异常")
	}
	items := []sensitiveMaterial{{label: "token 原文", value: token}, {label: "签名段", value: parts[2]}}
	if profile.Email != "" {
		items = append(items, sensitiveMaterial{label: "claims 里的邮箱", value: profile.Email})
	}
	if profile.Phone != "" {
		items = append(items, sensitiveMaterial{label: "claims 里的手机号", value: profile.Phone})
	}
	// 密钥材料：现场把 RSA 私钥的模数转出来当探针，断言任何输出都不该带它。
	items = append(items, sensitiveMaterial{label: "私钥模数字节", value: hexKeyModulus(t, authority)})
	return secretFixture{items: items, token: token}
}

func assertNoSecretMaterial(t *testing.T, haystack string, fixture secretFixture) {
	t.Helper()
	for _, item := range fixture.items {
		if item.value == "" {
			continue
		}
		if strings.Contains(haystack, item.value) {
			t.Errorf("输出里出现了 %s", item.label)
		}
	}
}

// hexKeyModulus 取签发方 RSA 模数的十六进制前缀，作为「密钥材料」探针。
//
// 模数本身是公开信息，但它的十六进制串会同时出现在私钥 PEM 里；
// 用它做断言可以在「有人把 key 材料顺手塞进审计」时立刻失败，
// 又不用在测试里保存任何真实私钥。
func hexKeyModulus(t *testing.T, a *FakeAuthority) string {
	t.Helper()
	keys, err := a.Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := keys[0].Public.(*rsa.PublicKey)
	if !ok {
		t.Fatal("测试签发方的第一把 key 应是 RSA")
	}
	return hex.EncodeToString(pub.N.Bytes())[:32]
}
func TestAuditAndErrorsNeverLeakTokenOrKeyMaterial(t *testing.T) {
	authority := testAuthority(t)
	profile := studentProfile() // 样例里刻意带了 email 与 phone
	fixture := newSecretFixture(t, authority, profile)
	audit := NewAuditRecorder(0)
	provider := newOIDC(t, authority, oidcOptions{audit: audit})

	principal := resolveOK(t, provider, oidcCredential(t, fixture.token))

	var sinks []string
	for _, event := range audit.Events() {
		sinks = append(sinks, event.String())
		blob, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		sinks = append(sinks, string(blob))
	}

	// Principal 本身（接线层会把它放进会话缓存或响应体）。
	blob, err := json.Marshal(principal)
	if err != nil {
		t.Fatal(err)
	}
	sinks = append(sinks, string(blob))
	sinks = append(sinks, principal.ScopesDisplay()) // 唯一允许出现范围名的输出，仍不该带 claims 内容

	// 依赖失败路径的审计与错误。
	failing := newOIDC(t, &StaticKeys{Err: context.DeadlineExceeded}, oidcOptions{audit: audit})
	_, badErr := failing.Resolve(context.Background(), oidcCredential(t, fixture.token))
	if badErr == nil {
		t.Fatal("依赖失败应有错误")
	}
	sinks = append(sinks, badErr.Error())
	for _, event := range audit.Events() {
		sinks = append(sinks, event.String())
	}

	// 凭证的三种脱敏出口。
	cred := oidcCredential(t, fixture.token)
	credJSON, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	sinks = append(sinks, cred.String(), cred.GoString(), string(credJSON))

	for _, sink := range sinks {
		assertNoSecretMaterial(t, sink, fixture)
	}
}

// 拒绝路径的错误信息不得回显 claims 内容。
func TestRejectionErrorsDoNotEchoClaimValues(t *testing.T) {
	authority := testAuthority(t)
	provider := newOIDC(t, authority, oidcOptions{})

	const privateOrgCode = "secret-department-code"
	profile := studentProfile()
	claims := profile.Claims(baseNow)
	claims.Subject = "internal.person@example.invalid"
	claims.Extra["sub"] = claims.Subject
	claims.Extra["department"] = privateOrgCode
	token := mustToken(t, authority, SignRequest{Claims: claims, At: baseNow})

	_, err := provider.Resolve(context.Background(), oidcCredential(t, token))
	if err == nil {
		t.Fatal("邮箱形态 subject 必须被拒")
	}
	if strings.Contains(err.Error(), "internal.person") || strings.Contains(err.Error(), "@") {
		t.Fatalf("错误不得回显邮箱: %v", err)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("错误不得回显 token: %v", err)
	}
	if strings.Contains(err.Error(), privateOrgCode) {
		t.Fatalf("错误不得回显院系代号: %v", err)
	}

	// 范围映射失败：错误给 claim 名，不给取值。
	cfg := DefaultMapperConfig()
	cfg.Directory = StaticDirectory{
		Entries: map[policy.ScopeKind]map[string]string{policy.ScopeOrganization: {}},
	}
	mapper, err := NewClaimMapper(cfg)
	if err != nil {
		t.Fatal(err)
	}
	lenient := newOIDC(t, authority, oidcOptions{mapper: mapper})
	normalToken := mustToken(t, authority, SignRequest{Profile: profile, At: baseNow})
	_, err = lenient.Resolve(context.Background(), oidcCredential(t, normalToken))
	if err == nil {
		t.Fatal("目录未命中（默认 fail-closed）必须失败")
	}
	if !strings.Contains(err.Error(), "organization") && !strings.Contains(err.Error(), "department") {
		t.Fatalf("错误应指出是哪条 claim: %v", err)
	}
	if strings.Contains(err.Error(), "cs-college") || strings.Contains(err.Error(), "university") {
		t.Fatalf("错误不得回显 claim 取值: %v", err)
	}
}

// 内置 fixture 必须是可识别为假的合成数据（手册 §8 第 5 条）。
func TestBuiltinFixturesAreSynthetic(t *testing.T) {
	for _, profile := range UniversitySampleProfiles() {
		if profile.Email != "" && !strings.HasSuffix(profile.Email, ".invalid") {
			t.Errorf("%s 的样例邮箱必须用保留域: %s", profile.FixtureName(), profile.Email)
		}
		if strings.Contains(profile.Subject, "@") {
			t.Errorf("%s 的 subject 不该是邮箱形态: %s", profile.FixtureName(), profile.Subject)
		}
		if profile.DisplayName != "" && profile.DisplayName == profile.Subject {
			t.Errorf("%s 的显示名与 subject 相同，会被 A 包判成不稳定键", profile.FixtureName())
		}
		for key, claim := range profile.Claims(time.Now()).Extra {
			if text, ok := claim.(string); ok && strings.Contains(text, "PRIVATE KEY") {
				t.Fatalf("样例 claims 不得含密钥材料: %s", key)
			}
		}
		if strings.Contains(profile.Phone, "13800001111") {
			t.Error("样例手机号也要用可识别为假的号段")
		}
	}
}

// 手构的 AuditEvent 若把邮箱塞进 subject，序列化与校验都要拦下。
func TestAuditEventMarshallingRedactsPIISubject(t *testing.T) {
	event := AuditEvent{
		Subject:    "real.person@example.edu",
		Source:     "campus-oidc",
		Provider:   "oidc",
		Outcome:    OutcomeDenied,
		Reason:     ReasonTokenExpired,
		OccurredAt: baseNow,
	}
	blob, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "real.person") {
		t.Fatalf("序列化没兜住 PII: %s", blob)
	}
	if err := event.Validate(); err == nil {
		t.Fatal("Validate 必须拒绝邮箱形态的 subject")
	}
}
