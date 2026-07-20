# net-tools — Copilot 编码规范

## Ops 核心定位原则（所有 Agent 必须遵守）

**从规范文件入手 → 找到架构文档 → 快速定位 → 尽早排除干扰。**

执行任何运维任务前：
1. 先读 `copilot-instructions.md` / `AGENTS.md` / `README.md` 等规范文件，建立全局认知
2. 通过架构文档中的网络拓扑、服务器清单、服务映射快速定位目标
3. 查阅凭证文件时，参考 `credentials/README.md` 的目录索引，按 IP / 服务名 / 产品名精准匹配
4. 排除无关目录和文件的干扰，只在目标范围内操作

---

## 项目概述

本仓库是一组 **macOS/Linux/BSD 网络工具集合**，根目录下每个子目录为一个独立工具。
工具相互独立，各自拥有完整的源码、安装脚本和配置模板。

---

## 目录结构规范

每个工具目录**必须**遵循以下结构：

```
<工具名>/
  src/          源码（脚本、程序入口）
  scripts/      安装脚本 + platform/ 子目录（各平台启动脚本）
    install.js  统一安装入口（Node.js，自动检测平台）
    platform/
      macos/    macOS LaunchAgent plist
      linux/    systemd .service 文件
      alpine/   Alpine Linux OpenRC 脚本（*.openrc）
      freebsd/  rc.d 脚本
      openwrt/  init.d 脚本
  config/       示例 / 模板配置文件（用 __PLACEHOLDER__ 替代所有敏感信息）
  data/         运行时数据占位目录（GeoIP 等，含 .gitkeep）
  logs/         日志占位目录（含 .gitkeep）
  README.md     工具说明（见下方 README 规范）
```

根目录还包含：

```
node/           Node.js 公共目录，工具 README 的 Node.js 安装说明指向此处
```

- `src/` 中的脚本需有可执行权限（`chmod +x`）并包含正确的 shebang
- `config/` 中的配置文件为**模板**，不提交用户的运行时配置（如 `~/.config/` 下的文件）
- 安装脚本统一命名为 `scripts/install.js`，使用 Node.js 内置模块实现，支持平台自动检测

---

## 工具 README 规范

每个工具的 `README.md` **必须按如下顺序**包含以下章节：

1. **功能特性** — 简述工具能做什么
2. **目录结构** — 用代码块展示本工具的文件树（含 data/、logs/）
3. **前置要求** — 简短说明依赖，**Node.js 工具必须指向 [node/README.md](../node/README.md)**
4. **安装** — `node scripts/install.js` 命令及安装脚本所做的事
5. **用法** — 所有可用命令，按功能分组展示
6. **配置文件说明** — 仓库内配置文件与运行时配置文件的对应关系（含 data/、logs/）

---

## 技术栈规范

### Node.js 工具

- 优先使用 Node.js **内置模块**（`http`、`fs`、`child_process`），避免引入 npm 依赖
- 若必须引入外部包，添加 `package.json` 并在 `scripts/install.sh` 中执行 `npm install`
- 脚本入口文件放在 `src/`，shebang 使用 `#!/usr/bin/env node`
- Node.js 最低版本要求 **v16**

### Shell 脚本

- 安装脚本使用 `#!/usr/bin/env bash`，首行加 `set -euo pipefail`
- 使用彩色输出函数区分 info / success / warn / error 级别
- 安装脚本需要的 sudo 操作要显式说明原因

### 配置文件

- YAML 配置中不得明文写入密码、密钥、UUID 等敏感信息
- 模板中的占位符统一使用 `__变量名__` 格式（如 `__HOME__`）

---

## 安全规范

- 脚本下载二进制文件后**必须验证**可执行性，移除 macOS 检疫属性（`xattr -d com.apple.quarantine`）
- 不在仓库中提交私有代理节点配置（UUID、私钥等）；`config/` 下的示例文件应使用占位值
- `install.sh` 的 curl 下载命令需指定 `--max-time` 防止挂起

---

## 提交规范

- 提交信息格式：`<工具名>: <简短描述>`，例如 `mihomo: 添加 dns-on 命令`
- 新增工具时同步更新根目录 `README.md` 的工具列表
- **每次修改 `mihomo/src/mihomo-ctl` 都必须同步递增 patch 版本号**（`VERSION` 常量的最小位 +1）
- **会话结束前必须将所有改动 `git add` + `git commit` + `git push`**，确保远端与本地始终一致

---

## 新增工具检查清单

- [ ] 已创建 `src/`、`scripts/`、`config/`、`data/`、`logs/` 子目录
- [ ] `data/.gitkeep` 和 `logs/.gitkeep` 已提交
- [ ] `scripts/install.js` 存在且可执行，支持平台自动检测
- [ ] `scripts/platform/{macos,linux,alpine,freebsd,openwrt}/` 均有对应启动脚本
- [ ] `README.md` 包含所有必要章节，Node.js 安装说明指向 `../node/README.md`
- [ ] 根目录 `README.md` 工具列表已更新
- [ ] 配置模板不含敏感信息（UUID、密钥等均使用 `__PLACEHOLDER__` 格式）
