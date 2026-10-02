package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mynet-club/net-tools/llmproxy/internal/policy"
)

// 3.0 按范围键定的读写 API（§2.7）的行为钉死测试。
//
// 这里覆盖的是 scope_store.go 里配额与熔断桶的导出 API：
// 每条都注明「为什么钉这个」—— 配额行是花钱的闸门，读错方向（多算/少算、
// 把「没配过」当成「不限」）在报表上看不出来，只在超支发生那天才暴露。
// 迁移本体不在这里测（scope_migration_test.go 负责）。

// mustQuota 读一条必然存在的配额，省掉每个用例重复三段 err 处理。
func mustQuota(t *testing.T, s *Store, scope policy.ScopeRef) *ScopeQuota {
	t.Helper()
	q, err := s.GetScopeQuota(scope)
	if err != nil {
		t.Fatalf("GetScopeQuota(%s): %v", scope.Display(), err)
	}
	if q == nil {
		t.Fatalf("GetScopeQuota(%s) 返回 nil，行应当存在", scope.Display())
	}
	return q
}

// findBucket 按 (完整范围, provider 名) 找桶。
// 匹配必须带 kind+id 两腿：只按名字找会把 user:alice 和 system:global 的
// 同名供应商混为一谈 —— 那正是 §2.7 规则 4 要防的熔断状态并桶。
func findBucket(list []ProviderBucketState, scope policy.ScopeRef, name string) (ProviderBucketState, bool) {
	for _, st := range list {
		if st.Scope == scope && st.Name == name {
			return st, true
		}
	}
	return ProviderBucketState{}, false
}

// ------------------------------------------------------------------ 配额读写

// 四种范围各写各读一遍，钉住「(scope_kind, scope_id) 是唯一键」：
// 曾经 user 之外的范围在存储层根本没有落点，组织/项目配额是 3.0 新增能力，
// 任何「组织配额被写进了 user 行」的键错位都要在这里先炸出来。
// 其中 system:global 一行全写 0 —— 0 = 不限是 2.x 沿用下来的口径，
// 「显式不限」必须与「没写过」（下一节的 nil）可区分。
func TestScopeQuotaRoundtripPerKind(t *testing.T) {
	s := openTestStore(t)
	cases := []struct {
		name  string
		scope policy.ScopeRef
		quota ScopeQuota
	}{
		{"user", policy.MustScope(policy.ScopeUser, "alice"), ScopeQuota{
			QuotaMonthTokens: 5_000_000, QuotaMonthCost: 199.5, RPM: 60, MaxConcurrent: 4, Enabled: true}},
		{"organization", policy.MustScope(policy.ScopeOrganization, "university"), ScopeQuota{
			QuotaMonthTokens: 900_000_000, QuotaMonthCost: 8000, RPM: 600, MaxConcurrent: 50, Enabled: true}},
		{"project", policy.MustScope(policy.ScopeProject, "proj-lab-7"), ScopeQuota{
			QuotaMonthTokens: 1000, QuotaMonthCost: 0.01, RPM: 1, MaxConcurrent: 1, Enabled: false}},
		// system:global 全 0 = 不限：读回来必须还是「有一行、值为零」而不是 nil
		{"system-zero-unlimited", policy.SystemScope, ScopeQuota{Enabled: true}},
	}
	for _, c := range cases {
		q := c.quota
		q.Scope = c.scope
		if err := s.SetScopeQuota(q); err != nil {
			t.Fatalf("%s: SetScopeQuota: %v", c.name, err)
		}
		got := mustQuota(t, s, c.scope)
		if got.Scope != c.scope {
			t.Errorf("%s: 读回的范围 = %s，scope 两列被读串了", c.name, got.Scope.Display())
		}
		if got.QuotaMonthTokens != q.QuotaMonthTokens || got.RPM != q.RPM || got.MaxConcurrent != q.MaxConcurrent {
			t.Errorf("%s: 数值没原样存取: %+v", c.name, got)
		}
		if got.QuotaMonthCost != q.QuotaMonthCost || got.Enabled != q.Enabled {
			t.Errorf("%s: cost/enabled 没原样存取: want %v/%v got %v/%v",
				c.name, q.QuotaMonthCost, q.Enabled, got.QuotaMonthCost, got.Enabled)
		}
		// 时间戳由写侧落列，为零说明 SetScopeQuota 漏了 created_at/updated_at
		if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
			t.Errorf("%s: created_at/updated_at 没落库: %+v", c.name, got)
		}
	}

	// ListScopeQuotas 的顺序（kind, id）必须稳定：CLI 表格与 diff 脚本都按它比对。
	all, err := s.ListScopeQuotas()
	if err != nil {
		t.Fatalf("ListScopeQuotas: %v", err)
	}
	wantOrder := []policy.ScopeKind{policy.ScopeOrganization, policy.ScopeProject, policy.ScopeSystem, policy.ScopeUser}
	if len(all) != len(wantOrder) {
		t.Fatalf("ListScopeQuotas 行数 = %d, want %d", len(all), len(wantOrder))
	}
	for i, k := range wantOrder {
		if all[i].Scope.Kind != k {
			t.Errorf("第 %d 行的 kind = %q, want %q（ORDER BY scope_kind 失效）", i, all[i].Scope.Kind, k)
		}
	}
}

// 负数一律拒绝，0 才是「不限」。
// 混进库的负配额会让「已用 - 限额」恒为正，等于静默把主体封死；
// 写侧拦住比读侧兜底可靠，所以四种字段的负值都要单独钉。
func TestScopeQuotaRejectsNegativeFields(t *testing.T) {
	s := openTestStore(t)
	scope := policy.MustScope(policy.ScopeUser, "alice")
	cases := []struct {
		name   string
		mutate func(q *ScopeQuota)
	}{
		{"tokens", func(q *ScopeQuota) { q.QuotaMonthTokens = -1 }},
		{"cost", func(q *ScopeQuota) { q.QuotaMonthCost = -0.01 }},
		{"rpm", func(q *ScopeQuota) { q.RPM = -5 }},
		{"max_concurrent", func(q *ScopeQuota) { q.MaxConcurrent = -1 }},
	}
	for _, c := range cases {
		q := ScopeQuota{Scope: scope, Enabled: true}
		c.mutate(&q)
		err := s.SetScopeQuota(q)
		if err == nil || !strings.Contains(err.Error(), "不能为负") {
			t.Errorf("%s 为负时应报「不能为负」，实际: %v", c.name, err)
		}
	}
}

// ------------------------------------------------------------------ 缺行与补丁

// §2.7 规则 8：users 表上的配额列不再是读路径。这里钉的是「删掉兜底之后」的行为：
//
//   - user 范围没有 scope_quota 行 = (nil, nil)，绝不回读 users 的旧列。
//     留着那条兜底，两张表各持一半真值时没人报错，而配额决定的是「还花不花得起系统池的钱」；
//     一次性迁移会把旧列回填成配额行，收口校验查的正是每个 user 都有一行。
//   - 「没行」与「限额为 0」必须可区分：nil = 从没配过，0 = 管理员显式给的「不限」。
//     把 nil 当 0 显示，org / project 范围会一水儿显示成「额度为零」。
//
// 旧列由测试手工补回来（3.0 的 userSchema 已经不建它们，见 scope_migration_test.go）：
// 要钉的是「读路径不碰它」，那与库里当前有没有这一列无关 —— 上一轮的库、
// 或人工恢复回来的库都可能还带着它。
func TestGetScopeQuotaHasNoUsersFallback(t *testing.T) {
	s := openTestStore(t)
	if err := s.CreateUser("alice", TokenHash("sk-alice")); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	alice := policy.MustScope(policy.ScopeUser, "alice")

	// 造出「迁移前」的形状：删掉配额行，users 上留着旧列的值。
	if _, err := s.db.Exec(`DELETE FROM scope_quota WHERE scope_kind='user' AND scope_id='alice'`); err != nil {
		t.Fatal(err)
	}
	ensureLegacyUsersQuotaCols(t, s.db)
	if _, err := s.db.Exec(`UPDATE users SET quota_month_tokens=1000, quota_month_cost=50.5,
		rpm=30, max_concurrent=3 WHERE name='alice'`); err != nil {
		t.Fatal(err)
	}
	q, err := s.GetScopeQuota(alice)
	if err != nil {
		t.Fatalf("GetScopeQuota: %v", err)
	}
	if q != nil {
		t.Errorf("配额行缺失时应返回 (nil,nil)，不该回读 users 旧列，实际: %+v", q)
	}

	// 补一行之后它说了算，users 的旧值不参与、也不被回写。
	if err := s.SetScopeQuota(ScopeQuota{Scope: alice, QuotaMonthTokens: 7, Enabled: true}); err != nil {
		t.Fatalf("SetScopeQuota: %v", err)
	}
	if got := mustQuota(t, s, alice); got.QuotaMonthTokens != 7 || got.RPM != 0 || !got.Enabled {
		t.Errorf("scope_quota 行是唯一真源，实际: %+v", got)
	}
	var legacy int64
	if err := s.db.QueryRow(`SELECT quota_month_tokens FROM users WHERE name='alice'`).Scan(&legacy); err != nil {
		t.Fatal(err)
	}
	if legacy != 1000 {
		t.Errorf("SetScopeQuota 不该回写 users 旧列（那是双写时代的职责），现在 %d", legacy)
	}

	// 非 user 范围无行同样是 (nil, nil)：org / project 从没配过限额是常态。
	if q, err := s.GetScopeQuota(policy.MustScope(policy.ScopeOrganization, "ghost")); err != nil || q != nil {
		t.Errorf("组织范围无行应返回 (nil,nil)，实际 q=%v err=%v", q, err)
	}
}

// PatchScopeQuota 的契约是「只改给到的那几项」。
//
// 三个写侧（管理界面 PATCH、CLI 改配额、CLI 改限流）都只带自己那两项，
// 如果「没给到的项」落成零值，管理员点一下改 token 上限就顺手清了同一个人的金额上限 ——
// 静默放开额度是这套 API 最贵的一种错，所以 nil 保持原值与零值表示「不限」要分开钉。
func TestPatchScopeQuotaKeepsUnsetFields(t *testing.T) {
	s := openTestStore(t)
	scope := policy.MustScope(policy.ScopeUser, "alice")
	two, zero := int64(2), 0.0
	if err := s.SetScopeQuota(ScopeQuota{
		Scope: scope, QuotaMonthTokens: 5_000_000, QuotaMonthCost: 199.5, RPM: 60, MaxConcurrent: 4, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.PatchScopeQuota(scope, QuotaPatch{Tokens: &two}); err != nil {
		t.Fatalf("PatchScopeQuota: %v", err)
	}
	got := mustQuota(t, s, scope)
	if got.QuotaMonthTokens != 2 {
		t.Errorf("给了的那项该改：tokens=%d", got.QuotaMonthTokens)
	}
	if got.QuotaMonthCost != 199.5 || got.RPM != 60 || got.MaxConcurrent != 4 || !got.Enabled {
		t.Errorf("没给的项该原样保留（清零等于放开额度）: %+v", got)
	}

	// 显式 0 = 不限，和「没给」是两件事。
	if err := s.PatchScopeQuota(scope, QuotaPatch{Cost: &zero}); err != nil {
		t.Fatalf("PatchScopeQuota(cost=0): %v", err)
	}
	got = mustQuota(t, s, scope)
	if got.QuotaMonthCost != 0 || got.QuotaMonthTokens != 2 {
		t.Errorf("cost 应被显式改成不限而 tokens 不动: %+v", got)
	}

	// 负值在写侧拦住（进库的负配额会让「已用 - 限额」恒为正，等于静默封死主体）。
	neg := int64(-1)
	if err := s.PatchScopeQuota(scope, QuotaPatch{Tokens: &neg}); err == nil ||
		!strings.Contains(err.Error(), "不能为负") {
		t.Errorf("负值应报「不能为负」，实际: %v", err)
	}

	// 缺行时按「全 0 = 不限、启用」起步：org / project 第一次设限走的就是这条路，
	// 要求调用方先插空行只会让三个写侧各写一遍起步逻辑。
	proj := policy.MustScope(policy.ScopeProject, "proj-lab-7")
	rpmTwo := 2
	if err := s.PatchScopeQuota(proj, QuotaPatch{RPM: &rpmTwo}); err != nil {
		t.Fatalf("缺行时 PatchScopeQuota: %v", err)
	}
	got = mustQuota(t, s, proj)
	if got.RPM != 2 || !got.Enabled || got.QuotaMonthTokens != 0 {
		t.Errorf("缺行应从「不限、启用」起步且只改给到的项: %+v", got)
	}
}

// ------------------------------------------------------------------ 修订号与删除

// 修订号是「CLI 改了配置 → 运行中的服务轮询发现」的唯一通道，契约有三条：
//   - SetScopeQuota 无论插入还是覆盖都必须 +1（漏了更新这一支，热更新就失效）；
//   - DeleteScopeQuota 删掉了才 +1，没删到东西不 bump（否则空转删除会惊醒所有轮询方）；
//   - 删除幂等：第二次删返回 false 而不是报错。
func TestScopeQuotaDeleteAndRevisionContract(t *testing.T) {
	s := openTestStore(t)
	org := policy.MustScope(policy.ScopeOrganization, "university")
	absent := policy.MustScope(policy.ScopeProject, "never-written")

	rev := func() int64 {
		v, err := s.Revision()
		if err != nil {
			t.Fatalf("Revision: %v", err)
		}
		return v
	}

	r0 := rev()
	if err := s.SetScopeQuota(ScopeQuota{Scope: org, QuotaMonthTokens: 100, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	r1 := rev()
	if r1 <= r0 {
		t.Fatalf("插入配额应 bump 修订号: %d → %d", r0, r1)
	}
	if err := s.SetScopeQuota(ScopeQuota{Scope: org, QuotaMonthTokens: 200, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	r2 := rev()
	if r2 <= r1 {
		t.Fatalf("覆盖配额同样要 bump 修订号: %d → %d", r1, r2)
	}

	// 删一个从没写过的范围：返回 false、不 bump，也不报错。
	ok, err := s.DeleteScopeQuota(absent)
	if err != nil || ok {
		t.Fatalf("删不存在的配额行应返回 (false, nil)，实际 (%v, %v)", ok, err)
	}
	if r := rev(); r != r2 {
		t.Errorf("无行可删不应 bump 修订号: %d → %d", r2, r)
	}

	ok, err = s.DeleteScopeQuota(org)
	if err != nil || !ok {
		t.Fatalf("DeleteScopeQuota: (%v, %v)，want (true, nil)", ok, err)
	}
	r3 := rev()
	if r3 <= r2 {
		t.Errorf("删掉配额行应 bump 修订号: %d → %d", r2, r3)
	}
	// 幂等：再删一次是 false，且配额读取回到「无行」。
	if ok, err = s.DeleteScopeQuota(org); err != nil || ok {
		t.Errorf("重复删除应幂等地返回 (false, nil)，实际 (%v, %v)", ok, err)
	}
	if q, err := s.GetScopeQuota(org); err != nil || q != nil {
		t.Errorf("删除后应读成无行 (nil,nil)，实际 q=%v err=%v", q, err)
	}
}

// ------------------------------------------------------------------ 非法范围拒绝

// checkScope 的拒绝面：六种按范围键定的 API 共用同一套校验，
// 每种都要确认（a）错误能穿透 errors.Is 到 policy/store 的哨兵错误，
// （b）错误文本带上出错位置（where）——调用方拿到「scope ID 不合法」时
// 必须能看出是哪个 API 在哪个范围上炸的。零值 ScopeRef 单独一档：
// 那是「忘了传 scope」，必须报错而不是静默落到全局桶。
func TestScopeAPIRejectsInvalidScopes(t *testing.T) {
	s := openTestStore(t)
	ops := []struct {
		label  string
		marker string // checkScope 的 where 串：SetScopeQuota 落点是「写入 scope_quota」，其余用函数名
		run    func(policy.ScopeRef) error
	}{
		{"GetScopeQuota", "GetScopeQuota", func(sc policy.ScopeRef) error {
			_, err := s.GetScopeQuota(sc)
			return err
		}},
		{"SetScopeQuota", "写入 scope_quota", func(sc policy.ScopeRef) error {
			return s.SetScopeQuota(ScopeQuota{Scope: sc, Enabled: true})
		}},
		{"DeleteScopeQuota", "DeleteScopeQuota", func(sc policy.ScopeRef) error {
			_, err := s.DeleteScopeQuota(sc)
			return err
		}},
		{"SaveProviderBucketStates", "SaveProviderBucketStates", func(sc policy.ScopeRef) error {
			return s.SaveProviderBucketStates([]ProviderBucketState{{Scope: sc, Name: "p"}})
		}},
		{"LoadProviderBucketsForScope", "LoadProviderBucketsForScope", func(sc policy.ScopeRef) error {
			_, err := s.LoadProviderBucketsForScope(sc)
			return err
		}},
		{"DeleteProviderBucketsForScope", "DeleteProviderBucketsForScope", func(sc policy.ScopeRef) error {
			_, err := s.DeleteProviderBucketsForScope(sc)
			return err
		}},
	}
	cases := []struct {
		name   string
		scope  policy.ScopeRef
		wantIs error
	}{
		{"零值 ScopeRef", policy.ScopeRef{}, ErrScopeRequired},
		{"空 ID", policy.ScopeRef{Kind: policy.ScopeUser, ID: ""}, policy.ErrScopeID},
		{"含冒号", policy.ScopeRef{Kind: policy.ScopeUser, ID: "alice:work"}, policy.ErrScopeID},
		{"超长 ID", policy.ScopeRef{Kind: policy.ScopeUser, ID: strings.Repeat("x", 257)}, policy.ErrScopeIDTooLong},
		{"首尾空白", policy.ScopeRef{Kind: policy.ScopeUser, ID: " alice "}, policy.ErrScopeID},
		{"未知类型", policy.ScopeRef{Kind: policy.ScopeKind("tenant"), ID: "t1"}, policy.ErrScopeKind},
	}
	for _, tc := range cases {
		for _, op := range ops {
			err := op.run(tc.scope)
			if err == nil {
				t.Errorf("%s / %s: 非法范围被静默接受", tc.name, op.label)
				continue
			}
			if !errors.Is(err, tc.wantIs) {
				t.Errorf("%s / %s: 错误链丢了哨兵 %v，实际: %v", tc.name, op.label, tc.wantIs, err)
			}
			if !strings.Contains(err.Error(), op.marker) {
				t.Errorf("%s / %s: 错误应指出出错位置 %q，实际: %v", tc.name, op.label, op.marker, err)
			}
		}
	}
}

// ------------------------------------------------------------------ 熔断桶

// 桶字段全量往返一遍（含三个时间列与 Enabled）。
// providerBucketCols 与 scanProviderBucket 是「成对维护、列序改一处必须改另一处」的
// 手工契约，这里就是防它改串的单点网：任一列错位都会让别的列带着错误的值读回来。
func TestProviderBucketFullStateRoundtrip(t *testing.T) {
	s := openTestStore(t)
	scope := policy.MustScope(policy.ScopeUser, "alice")
	// 毫秒级时间戳原样可存，取整到秒避免跨平台毫秒截断干扰断言。
	trunc := func(d time.Duration) time.Time { return time.Now().Add(d).Truncate(time.Second) }
	want := ProviderBucketState{
		Scope: scope, Name: "openai-direct", Enabled: true, ConsecutiveFailures: 3,
		UnhealthyUntil: trunc(time.Minute), LastError: "上游返回 502",
		LastSuccessAt: trunc(-time.Hour), LastFailureAt: trunc(-time.Minute),
		TotalRequests: 100, TotalFailures: 7,
	}
	if err := s.SaveProviderBucketStates([]ProviderBucketState{want}); err != nil {
		t.Fatalf("SaveProviderBucketStates: %v", err)
	}
	got, err := s.LoadProviderBucketsForScope(scope)
	if err != nil || len(got) != 1 {
		t.Fatalf("LoadProviderBucketsForScope: len=%d err=%v", len(got), err)
	}
	b := got[0]
	if b.Name != want.Name || b.Enabled != want.Enabled || b.ConsecutiveFailures != want.ConsecutiveFailures {
		t.Errorf("基础字段错位: %+v", b)
	}
	if b.LastError != want.LastError || b.TotalRequests != want.TotalRequests || b.TotalFailures != want.TotalFailures {
		t.Errorf("统计字段错位: %+v", b)
	}
	if !b.UnhealthyUntil.Equal(want.UnhealthyUntil) || !b.LastSuccessAt.Equal(want.LastSuccessAt) ||
		!b.LastFailureAt.Equal(want.LastFailureAt) {
		t.Errorf("时间列错位: until=%v ok=%v fail=%v", b.UnhealthyUntil, b.LastSuccessAt, b.LastFailureAt)
	}
	// 冷却清零必须能整点写回零值（ON CONFLICT 若漏了某列，旧值会阴魂不散）。
	want.Enabled, want.ConsecutiveFailures, want.UnhealthyUntil, want.LastError = false, 0, time.Time{}, ""
	if err := s.SaveProviderBucketStates([]ProviderBucketState{want}); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.LoadProviderBucketsForScope(scope); !got[0].UnhealthyUntil.IsZero() || got[0].Enabled ||
		got[0].ConsecutiveFailures != 0 || got[0].LastError != "" {
		t.Errorf("覆盖写未清除熔断状态: %+v", got[0])
	}
	// provider 名是桶的另一半主键，空名会造出读不回、删不掉的幽灵行。
	if err := s.SaveProviderBucketStates([]ProviderBucketState{{Scope: scope, Name: ""}}); err == nil {
		t.Error("空 provider 名应报错")
	}
}

// §2.7 规则 4 的桶键不变式：(scope_kind, scope_id, provider) 三腿唯一。
// 这是本文件最要紧的一条——两个租户共用同名上游时若只按名字（或只按 kind+名字前缀）
// 撞键，熔断计数就会跨主体互串：alice 打爆了自己的 openai，bob 的 openai 一上来
// 就是「冷却中」。system:global 与 user 同名供应商也必须互不可见（全局池和
// 用户自有上游是两个物理端点）。
func TestProviderBucketScopeIsolation(t *testing.T) {
	s := openTestStore(t)
	alice := policy.MustScope(policy.ScopeUser, "alice")
	bob := policy.MustScope(policy.ScopeUser, "bob")
	buckets := []ProviderBucketState{
		{Scope: policy.SystemScope, Name: "openai", Enabled: true, TotalRequests: 10},
		{Scope: alice, Name: "openai", Enabled: true, ConsecutiveFailures: 9, TotalRequests: 90},
		{Scope: bob, Name: "openai", Enabled: true, TotalRequests: 20},
	}
	if err := s.SaveProviderBucketStates(buckets); err != nil {
		t.Fatalf("SaveProviderBucketStates: %v", err)
	}
	all, err := s.LoadProviderBucketStates()
	if err != nil || len(all) != 3 {
		t.Fatalf("同名不同范围的桶应各存一行，实际 len=%d err=%v", len(all), err)
	}
	for _, b := range buckets {
		got, ok := findBucket(all, b.Scope, b.Name)
		if !ok || got.TotalRequests != b.TotalRequests || got.ConsecutiveFailures != b.ConsecutiveFailures {
			t.Errorf("桶 %s/openai 取回不对: %+v (ok=%v)", b.Scope.Display(), got, ok)
		}
	}

	// 只重写 alice 的桶：另外两个主体与全局必须分毫不动。
	if err := s.SaveProviderBucketStates([]ProviderBucketState{
		{Scope: alice, Name: "openai", Enabled: false, ConsecutiveFailures: 0, TotalRequests: 91},
	}); err != nil {
		t.Fatal(err)
	}
	all, _ = s.LoadProviderBucketStates()
	if g, _ := findBucket(all, policy.SystemScope, "openai"); g.TotalRequests != 10 {
		t.Errorf("写 alice 的桶污染了全局池: %+v", g)
	}
	if g, _ := findBucket(all, bob, "openai"); g.TotalRequests != 20 {
		t.Errorf("写 alice 的桶污染了 bob: %+v", g)
	}
	if g, ok := findBucket(all, alice, "openai"); !ok || g.Enabled || g.TotalRequests != 91 {
		t.Errorf("alice 自己没被更新: %+v (ok=%v)", g, ok)
	}
}

// DeleteProviderBucketsForScope 是删用户级联的一环（防同名新账号继承熔断计数）。
// 钉三点：返回值是删掉的行数（运维核对用）、重复删返回 0 且不报错不 bump、
// 删除严格按范围两腿收口——alice 的行没了，bob 与全局必须还在。
func TestDeleteProviderBucketsForScope(t *testing.T) {
	s := openTestStore(t)
	alice := policy.MustScope(policy.ScopeUser, "alice")
	bob := policy.MustScope(policy.ScopeUser, "bob")
	if err := s.SaveProviderBucketStates([]ProviderBucketState{
		{Scope: alice, Name: "up1", Enabled: true},
		{Scope: alice, Name: "up2", Enabled: true},
		{Scope: bob, Name: "up1", Enabled: true},
		{Scope: policy.SystemScope, Name: "up1", Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	r0, _ := s.Revision()

	n, err := s.DeleteProviderBucketsForScope(alice)
	if err != nil || n != 2 {
		t.Fatalf("应删掉 alice 的 2 个桶，实际 n=%d err=%v", n, err)
	}
	r1, _ := s.Revision()
	if r1 <= r0 {
		t.Errorf("删掉桶应 bump 修订号（router 要感知桶没了）: %d → %d", r0, r1)
	}
	// 幂等：再删一次 0 行，且不再惊动轮询方。
	if n, err = s.DeleteProviderBucketsForScope(alice); err != nil || n != 0 {
		t.Errorf("重复删应返回 (0, nil)，实际 (%d, %v)", n, err)
	}
	if r2, _ := s.Revision(); r2 != r1 {
		t.Errorf("无行可删不应 bump 修订号: %d → %d", r1, r2)
	}
	// 范围两腿都参与 WHERE：只删了 alice。
	all, _ := s.LoadProviderBucketStates()
	if len(all) != 2 {
		t.Fatalf("其余主体的桶被误伤: %+v", all)
	}
	if _, ok := findBucket(all, bob, "up1"); !ok {
		t.Error("bob 的桶没了")
	}
	if _, ok := findBucket(all, policy.SystemScope, "up1"); !ok {
		t.Error("全局池的桶没了")
	}
}

// ------------------------------------------------------------------ 审计：按范围读写

func TestAuditScopedRoundtripAndIsolation(t *testing.T) {
	s := openTestStore(t)
	alice := policy.MustScope(policy.ScopeUser, "alice")
	org := policy.MustScope(policy.ScopeOrganization, "university")
	proj := policy.MustScope(policy.ScopeProject, "proj-lab-7")

	for _, sc := range []policy.ScopeRef{alice, org, proj, policy.SystemScope} {
		if err := s.AuditScope(sc, "admin", "user.create", sc.Display(), "关于 "+sc.Display()); err != nil {
			t.Fatal(err)
		}
	}
	// 零值范围必须报错而不是落进某个默认桶 —— 「忘了传 scope」变成脏数据最难查。
	if err := s.AuditScope(policy.ScopeRef{}, "admin", "user.create", "x", ""); err == nil {
		t.Fatal("零值 ScopeRef 必须被拒绝")
	}

	all, err := s.AuditRecentAll(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Fatalf("全量应含 4 条，实际 %d", len(all))
	}
	for _, e := range all {
		if e.Scope.Kind == "" || e.Scope.ID == "" {
			t.Errorf("全量读回来的条目丢了归属: %+v", e)
		}
	}

	// 组织管理员要的是「本组织 + 名下项目」的并集，且看不见别人的用户范围。
	list, err := s.AuditRecentForScopes([]policy.ScopeRef{org, proj}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("并集应是 2 条，实际 %d: %+v", len(list), list)
	}
	for _, e := range list {
		if e.Scope.Is(alice) {
			t.Errorf("alice 的审计漏进了组织并集: %+v", e)
		}
	}

	single, err := s.AuditRecentByScope(alice, 10)
	if err != nil || len(single) != 1 || !single[0].Scope.Is(alice) {
		t.Fatalf("单范围查询 = %d 条 err=%v", len(single), err)
	}
	if _, err := s.AuditRecentByScope(alice, 0); err != nil {
		t.Errorf("n<=0 应按缺省条数处理: %v", err)
	}
	if _, err := s.AuditRecentForScopes(nil, 10); err == nil {
		t.Error("空范围集合必须报错，不能退化成全量")
	}
	if _, err := s.AuditRecentByScope(policy.ScopeRef{}, 10); err == nil {
		t.Error("零值范围的单查询必须被拒绝")
	}
}
