package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreateGeneratesAndReuses(t *testing.T) {
	dir := t.TempDir()

	c1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("首次加载失败: %v", err)
	}
	path := filepath.Join(dir, FileName)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("主密钥文件不存在: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("主密钥权限应为 0600，实际 %o", perm)
	}

	blob, err := c1.Encrypt("sk-upstream-secret")
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// 第二次加载应拿到同一把密钥
	c2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("二次加载失败: %v", err)
	}
	got, err := c2.Decrypt(blob)
	if err != nil {
		t.Fatalf("用同一主密钥解密失败: %v", err)
	}
	if got != "sk-upstream-secret" {
		t.Errorf("解密结果 %q，期望 %q", got, "sk-upstream-secret")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{"a", "sk-1234567890", strings.Repeat("x", 4096), "含中文的密钥"}
	for _, in := range cases {
		blob, err := c.Encrypt(in)
		if err != nil {
			t.Fatalf("加密 %q 失败: %v", in, err)
		}
		out, err := c.Decrypt(blob)
		if err != nil {
			t.Fatalf("解密失败: %v", err)
		}
		if out != in {
			t.Errorf("往返不一致: %q → %q", in, out)
		}
	}
}

func TestEncryptEmptyIsNil(t *testing.T) {
	c, _ := LoadOrCreate(t.TempDir())
	blob, err := c.Encrypt("")
	if err != nil {
		t.Fatalf("加密空串报错: %v", err)
	}
	if blob != nil {
		t.Errorf("空串应返回 nil，实际 %d 字节", len(blob))
	}
	got, err := c.Decrypt(nil)
	if err != nil || got != "" {
		t.Errorf("解密 nil 应返回空串，得到 %q err=%v", got, err)
	}
}

func TestCiphertextIsNotPlaintext(t *testing.T) {
	c, _ := LoadOrCreate(t.TempDir())
	const secret = "sk-must-not-appear-in-db"
	blob, err := c.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), secret) {
		t.Fatal("密文里出现了明文密钥")
	}
}

func TestSamePlaintextDifferentCiphertext(t *testing.T) {
	c, _ := LoadOrCreate(t.TempDir())
	a, _ := c.Encrypt("same")
	b, _ := c.Encrypt("same")
	if string(a) == string(b) {
		t.Error("两次加密结果相同，nonce 可能没有随机化")
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	c1, _ := LoadOrCreate(t.TempDir())
	c2, _ := LoadOrCreate(t.TempDir())
	blob, _ := c1.Encrypt("sk-secret")
	if _, err := c2.Decrypt(blob); err == nil {
		t.Fatal("换主密钥后解密应当失败")
	}
}

func TestDecryptTamperedFails(t *testing.T) {
	c, _ := LoadOrCreate(t.TempDir())
	blob, _ := c.Encrypt("sk-secret")
	blob[len(blob)-1] ^= 0xff
	if _, err := c.Decrypt(blob); err == nil {
		t.Fatal("密文被篡改后解密应当失败")
	}
}

func TestLoadRejectsBadFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("not-hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("非法主密钥文件应当报错")
	}

	dir2 := t.TempDir()
	// 长度不对的十六进制
	if err := os.WriteFile(filepath.Join(dir2, FileName), []byte("abcd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir2); err == nil {
		t.Fatal("长度错误的密钥应当报错")
	}
}

func TestMask(t *testing.T) {
	cases := map[string]string{
		"":              "",
		"sk-1234567890": "****7890",
		"abc":           "****",
	}
	for in, want := range cases {
		if got := Mask(in); got != want {
			t.Errorf("Mask(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// TestDeriveStableAcrossReload 是「跨请求稳定假名」与「检索词摘要带密钥位」这两件事的根：
// 派生只依赖主密钥 + 用途域 + 版本串，所以同一个部署进程内两次调用、
// 以及重启后重新读同一个 master.key，拿到的都必须是同一个串。
// 这里换任何一条（改成随机、改成按时间、把 purpose 拼错），下游那两条「同一个人
// 两个请求拿到同一个假名」的断言会当场失效 —— 而那正是裁决 18′ 要买的东西。
func TestDeriveStableAcrossReload(t *testing.T) {
	dir := t.TempDir()
	c1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("首次加载失败: %v", err)
	}
	c2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("二次加载失败: %v", err)
	}

	k1 := c1.Derive(PurposePIIPseudonym, DeriveVersionV1)
	k2 := c1.Derive(PurposePIIPseudonym, DeriveVersionV1)
	k3 := c2.Derive(PurposePIIPseudonym, DeriveVersionV1)
	if len(k1) != 32 {
		t.Fatalf("派生长度 = %d，应为 32（SHA-256 全宽）", len(k1))
	}
	if string(k1) != string(k2) {
		t.Error("同一 Cipher 两次派生不同：跨请求稳定的前提当场没了")
	}
	if string(k1) != string(k3) {
		t.Error("同一 master.key 重启后派生不同：假名与摘要会在每次重启后全变")
	}
	if string(k1) == string(c1.key) {
		t.Error("派生值就是主密钥原值：那等于把主密钥递给可被外部观察的两个使用面")
	}
}

// TestDeriveDomainsAreIndependent 锁住「一把钥匙、多个互不相干的使用面」这条设计：
// 用途域或版本串任何一位不同都必须派生出差得远的值，否则「轮换 pii 假名不影响检索摘要」
// 这种承诺就是假的；而长度前缀缺失时 (ab, c) 与 (a, bc) 会撞成同一路字节流，
// 那是边界挪动造成的跨域碰撞。
func TestDeriveDomainsAreIndependent(t *testing.T) {
	c, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pii := c.Derive(PurposePIIPseudonym, DeriveVersionV1)
	kb := c.Derive(PurposeKBQueryDigest, DeriveVersionV1)
	if string(pii) == string(kb) {
		t.Error("pii 假名与检索摘要拿到了同一个子密钥：一处使用面就摊开了另一处")
	}
	if v2 := c.Derive(PurposePIIPseudonym, "v2"); string(v2) == string(pii) {
		t.Error("版本串不参与派生：那 v2 这个轮转把手是装饰")
	}
	// 边界挪动：两个 (purpose, version) 组合的裸拼接相同，长度前缀必须让它们分开。
	if shifted := c.Derive("ab", "c"); string(shifted) == string(c.Derive("a", "bc")) {
		t.Error("域分隔缺长度前缀：不同用途与版本会撞成同一个派生值")
	}
}

// TestDeriveRotatesWithMasterKey 是 README 里那句轮转代价的可执行版本：
// 换主密钥会**同时**改变所有派生子密钥，所以历史假名与历史摘要一起失效，
// 而且没有「新旧并存对比」这条路（要留就得为每个派生值另存一列，那是另一件事）。
func TestDeriveRotatesWithMasterKey(t *testing.T) {
	c1, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c2, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []string{PurposePIIPseudonym, PurposeKBQueryDigest} {
		if string(c1.Derive(purpose, DeriveVersionV1)) == string(c2.Derive(purpose, DeriveVersionV1)) {
			t.Errorf("%s：两把不同的主密钥派生出同一个子密钥", purpose)
		}
	}
}

// TestDeriveNilCipher 锁住「没密钥就说没密钥」：返回全零串会让调用方以为自己拿到了
// pepper，从而安静地把假名与摘要做成可离线穷举的形态。
func TestDeriveNilCipher(t *testing.T) {
	var c *Cipher
	if got := c.Derive(PurposePIIPseudonym, DeriveVersionV1); got != nil {
		t.Errorf("nil Cipher 派生 = %v，应为 nil", got)
	}
	if got := (&Cipher{}).Derive(PurposePIIPseudonym, DeriveVersionV1); got != nil {
		t.Errorf("空密钥的 Cipher 派生 = %v，应为 nil", got)
	}
}
