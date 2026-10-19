package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrUserNotFound 表示按名字操作的用户不存在。
var ErrUserNotFound = errors.New("用户不存在")

// 本地账号密码：users 表加一列 password_hash（bcrypt 文本）。
//
// 只加列不建新表：密码是「这个用户怎么证明自己」的一部分，与账号同生命周期；
// 单独一张 credentials 表会让「删用户」多一个必须记得清的尾巴。
// 空串 = 这个用户没有本地密码（只能用 token 或目录身份登录）。

func migrateAuth(db *sql.DB, d Dialect) error {
	return addColumnsIfMissing(db, d, "users", map[string]string{
		"password_hash": "TEXT NOT NULL DEFAULT ''",
	})
}

// SetUserPassword 写入/替换本地密码摘要。空串表示清除密码（只保留 token 登录）。
func (s *Store) SetUserPassword(name, hash string) error {
	return s.userUpdate("password_hash = ?", []any{strings.TrimSpace(hash)}, name)
}

// GetUserPasswordHash 返回本地密码摘要；用户不存在返回 ErrUserNotFound，没设密码返回空串。
func (s *Store) GetUserPasswordHash(name string) (string, error) {
	var hash string
	err := s.db.QueryRow(s.rebind(`SELECT password_hash FROM users WHERE name = ?`),
		strings.TrimSpace(name)).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrUserNotFound
	}
	if err != nil {
		return "", fmt.Errorf("读取密码失败: %w", err)
	}
	return hash, nil
}
