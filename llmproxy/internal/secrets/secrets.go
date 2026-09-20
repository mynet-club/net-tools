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
	"crypto/rand"
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
	return &Cipher{aead: aead}, nil
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
