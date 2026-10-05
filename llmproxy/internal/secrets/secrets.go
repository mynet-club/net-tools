// Package secrets 负责上游 API key 的本地静态加密。
//
// 多用户之后，库里存的就不再是自己的密钥，而是别人托付给你的密钥 ——
// 数据库被备份、同步或误传走时不能泄漏明文。所以：
//
//   - 主密钥是运行时目录下一个 0600 的 master.key（32 字节随机），首次启动自动生成
//   - 上游 key 用 AES-256-GCM 加密后落 SQLite，每条记录带独立随机 nonce
//   - 明文只在两处出现：master.key 文件本身，以及进程内存（转发时必须用它构造
//     Authorization 头，这一点无法避免）
//
// 刻意不引 KMS/Vault：这是自用工具，引外部密钥服务会让部署复杂度超过工具本身。
// 代价要说清楚：master.key 丢了，库里的上游密钥就解不开了（只能让用户重填）。
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// FileName 是主密钥文件名，位于运行时目录下。
	FileName = "master.key"
	keyLen   = 32 // AES-256
)

// Cipher 用一个主密钥加解密。零值不可用。
type Cipher struct {
	aead cipher.AEAD
	// key 是主密钥原文，只为了派生子密钥而留着（见 Derive）。
	// 加密路径只用 aead，不读这个字段。
	key []byte
}

// LoadOrCreate 读取运行时目录下的主密钥；不存在则生成一个新的（0600）。
//
// 返回的 error 一定意味着「无法安全地存储密钥」，调用方应当拒绝启动，
// 而不是降级成明文存储 —— 静默降级是这类功能最容易犯的错。
func LoadOrCreate(dir string) (*Cipher, error) {
	if dir == "" {
		return nil, errors.New("运行时目录为空")
	}
	path := filepath.Join(dir, FileName)

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		key, decErr := decodeKey(string(raw))
		if decErr != nil {
			return nil, fmt.Errorf("%s 内容非法: %w", path, decErr)
		}
		return newCipher(key)
	case os.IsNotExist(err):
		// 首次运行：生成
	default:
		return nil, fmt.Errorf("读取 %s 失败: %w", path, err)
	}

	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("生成主密钥失败: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建运行时目录失败: %w", err)
	}
	// 先按 0600 创建，再写内容：避免短暂出现宽权限文件
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		// 极少数竞态：另一个进程刚建好
		if os.IsExist(err) {
			return LoadOrCreate(dir)
		}
		return nil, fmt.Errorf("创建 %s 失败: %w", path, err)
	}
	content := hex.EncodeToString(key) + "\n"
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("写入 %s 失败: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("关闭 %s 失败: %w", path, err)
	}
	return newCipher(key)
}

// Path 返回主密钥文件路径，供 CLI 提示用。
func Path(dir string) string { return filepath.Join(dir, FileName) }

func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("文件为空")
	}
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("不是合法的十六进制: %w", err)
	}
	if len(key) != keyLen {
		return nil, fmt.Errorf("密钥长度应为 %d 字节，实际 %d 字节", keyLen, len(key))
	}
	return key, nil
}

func newCipher(key []byte) (*Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead, key: append([]byte(nil), key...)}, nil
}

// Encrypt 加密一段明文。空字符串返回空切片（表示「没有密钥」而不是「加密的空串」）。
func (c *Cipher) Encrypt(plaintext string) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, errors.New("主密钥未加载")
	}
	if plaintext == "" {
		return nil, nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("生成 nonce 失败: %w", err)
	}
	// 输出格式：nonce || ciphertext(+tag)，自包含，不需要额外存 nonce
	return c.aead.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

// Decrypt 解密 Encrypt 的输出。
func (c *Cipher) Decrypt(blob []byte) (string, error) {
	if c == nil || c.aead == nil {
		return "", errors.New("主密钥未加载")
	}
	if len(blob) == 0 {
		return "", nil
	}
	ns := c.aead.NonceSize()
	if len(blob) <= ns {
		return "", errors.New("密文长度异常")
	}
	plain, err := c.aead.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		// 典型原因：master.key 被换过
		return "", fmt.Errorf("解密失败（主密钥可能已更换）: %w", err)
	}
	return string(plain), nil
}

// 派生用途域：**所有**使用面的清单集中在这一处，调用点不许自己写字符串。
//
// 为什么这么放：域名字符串一旦变动（哪怕只是打错一位）就等于把那一类派生值全换了一批
// —— 而运行时看不出任何异常：假名照旧稳定、摘要照旧等长、审计照旧能等值比对，
// 只有历史对不上账了。把它收成一个常量，改名与新增用途都会先在编译期撞一次。
//
// 现在两位用途各自牵着一条被测试钉住的行为：
//   - PurposePIIPseudonym：pii-mask 的跨请求稳定假名（internal/server 的 withSecrets 注入）；
//   - PurposeKBQueryDigest：知识检索词摘要的密钥位（internal/server 的 kbQuery 注入）。
const (
	PurposePIIPseudonym  = "pii-pseudonym"
	PurposeKBQueryDigest = "kb-query-digest"

	// DeriveVersionV1 是当前的派生版本串。将来换算法或换口径时升成 v2，
	// 新旧派生值自然断开，不需要换主密钥。
	// 反过来说：换主密钥会让**所有**用途一起变，代价写在 README。
	DeriveVersionV1 = "v1"
)

// Derive 从主密钥派生一个用途专用的子密钥（32 字节）。
//
// 为什么要有这一位（裁决 18′）：跨请求稳定的假名与检索词摘要都需要一个密钥，
// 而「再发一个密钥文件」会多出一个需要备份、轮换、权限管理的秘密面。
// 主密钥已经是运行时目录里那个 0600 的 master.key，从它派生就够了。
//
// 但**不能直接把主密钥递给这两处**：它同时是 AES-256-GCM 的加密密钥，
// 而假名与摘要会出现在要发给上游的正文里、以及审计表里 —— 那是两个可被外部观察的
// MAC 使用面，直接复用等于让观察者为「能不能还原加密密钥」提供样本。
// 所以这里做一层带域前缀的 HMAC-SHA256，每个用途拿到互不相同的子密钥，
// 而整个体系仍然只有一把需要保管的钥匙。
//
// 域前缀带长度（`<len>:<s>`）是为了防止拼接歧义：两个不同的 (用途, 版本) 组合
// 不应该因为边界挪动而派生出同一个串。
//
// c 为 nil（没加载主密钥）时返回 nil —— 调用方据此退回各自的现状行为，
// 而不是拿一个全零密钥假装「有 pepper」。
func (c *Cipher) Derive(purpose, version string) []byte {
	if c == nil || len(c.key) == 0 {
		return nil
	}
	mac := hmac.New(sha256.New, c.key)
	for _, s := range []string{"llmproxy-derive", purpose, version} {
		_, _ = fmt.Fprintf(mac, "%d:%s;", len(s), s)
	}
	return mac.Sum(nil)
}

// Mask 把密钥渲染成可安全展示的形式，只保留尾部 4 位。
func Mask(key string) string {
	if key == "" {
		return ""
	}
	if len(key) <= 4 {
		return "****"
	}
	return "****" + key[len(key)-4:]
}
