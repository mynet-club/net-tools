package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/mynet-club/net-tools/llmproxy/internal/config"
)

const adminUsage = `llmproxy admin — 管理凭证（server.admin_token）

  llmproxy admin token              打印当前的管理凭证
  llmproxy admin rotate             轮换一个新的，并写回 config.yaml

说明：
  admin_token 是管理台 /admin/ 与 /v1/_admin/** 的凭证。它只存 config.yaml，
  走「查 / 用」两条通道里的「查」——这里打印给你，是为了让你粘进浏览器登录，
  不是让自动化脚本去读它。

  rotate 会：生成新 token → 备份 config.yaml → 写临时文件 → 用加载器校验 →
  原子改名覆盖 → 通知运行中的服务重载。校验不过则原文件一字不动。
  新 token 只在命令输出里出现这一次；之后可用 ` + "`llmproxy admin token`" + ` 再取。

  建议把 token 放进凭证库（crt set），而不是留在聊天记录或笔记里。
`

func cmdAdmin(paths config.Paths, args []string) error {
	if len(args) == 0 {
		fmt.Print(adminUsage)
		return nil
	}
	switch args[0] {
	case "token":
		return adminToken(paths)
	case "rotate":
		return adminRotate(paths)
	case "help", "-h", "--help":
		fmt.Print(adminUsage)
		return nil
	default:
		return fmt.Errorf("未知的 admin 子命令 %q\n\n%s", args[0], adminUsage)
	}
}

// adminToken 打印当前的管理凭证。
//
// 这是运营者读自己机器上自己的配置文件，与 `grep admin_token config.yaml` 等价；
// CLI 存在的意义是不必手工打开那个含上游密钥的文件。
func adminToken(paths config.Paths) error {
	cfg, err := config.LoadFileLenient(paths.ConfigFile)
	if err != nil {
		return err
	}
	tok := cfg.Server.AdminToken
	if tok == "" {
		fmt.Println("未配置（server.admin_token 为空，管理接口整体关闭）")
		fmt.Println("用 `llmproxy admin rotate` 生成一个。")
		return nil
	}
	// ${ENV} 引用在加载时已展开；如果环境变量没设，展开会原样留下 ${...}
	if len(tok) >= 2 && tok[0] == '$' && tok[1] == '{' {
		fmt.Printf("配置里是环境变量引用（%s），当前环境里取不到它。\n", tok)
		fmt.Println("要么先 export 那个变量，要么用 `llmproxy admin rotate` 换成写在文件里的字面值。")
		return nil
	}
	fmt.Println(tok)
	fmt.Fprintln(os.Stderr, "（这是管理凭证，等同于 root —— 别贴进聊天记录）")
	return nil
}

// adminRotate 生成新管理凭证并写回 config.yaml。
//
// 安全链与管理台写回 providers 段一致（config.WriteFileSafely）：备份 → 临时文件 →
// 校验 → 原子改名。校验不过则原文件一字不动。
func adminRotate(paths config.Paths) error {
	src, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		return err
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("生成随机 token 失败: %w", err)
	}
	token := "sk-llmproxy-admin-" + hex.EncodeToString(raw)

	newSrc, err := config.SetOrInsertConfigScalar(src, "server", "admin_token", token)
	if err != nil {
		return err
	}
	if err := config.WriteFileSafely(paths.ConfigFile, newSrc); err != nil {
		return err
	}
	fmt.Println("已写入 config.yaml 并备份。")
	notifyRunningService(paths) // 借 SIGHUP 让运行中的服务立刻读到新 token
	fmt.Println()
	fmt.Println(token)
	fmt.Fprintln(os.Stderr, "（这是新的管理凭证 —— 别贴进聊天记录；之后随时可用 `llmproxy admin token` 再取）")
	return nil
}
