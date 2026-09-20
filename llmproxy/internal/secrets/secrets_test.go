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
