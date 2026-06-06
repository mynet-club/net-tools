# mihomo-ctl

多平台 Mihomo (Clash Meta) 代理管理 CLI 工具，基于 Node.js 编写，无需额外依赖包。  
支持 **macOS · Linux · FreeBSD · Alpine · OpenWrt · Windows**，单脚本跨平台运行。

**Mihomo 项目**: [github.com/MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)

## 功能特性

- 启动 / 停止 / 重启 / **热重载** Mihomo 进程（跨平台）
- 配置文件**语法检查**
- 一键**模式切换**（rule / global / direct）
- **实时流量**速率监控（SSE 流）
- **活跃连接**查看与一键断开
- **GeoIP / GeoSite 数据自动更新**（立即下载 + cron 定时任务）
- 系统代理接管 / 恢复（macOS · **Windows**；其他平台用环境变量）
- DNS 防污染接管（macOS / FreeBSD：pf 重定向 + DoH；**Linux · Alpine：iptables 重定向 53→1053**；Windows：netsh DNS 修改）
- 交互式节点选择（↑↓ 切换 Enter 确认）
- 节点延迟测速
- **无缝升级** Mihomo 二进制（预下载完成后才停机，自动备份+失败回滚，显示版本对比）
- 开机自启管理（各平台使用对应服务管理器）
- 日志开关与实时查看

## 目录结构

```
mihomo/
├── src/
│   └── mihomo-ctl                    # Node.js CLI 主脚本
├── scripts/
│   ├── install.js                    # 安装脚本（自动检测平台）
│   └── platform/
│       ├── macos/
│       │   ├── mihomo.plist          # macOS LaunchAgent 模板
│       │   └── mihomo.5s.sh          # xbar / SwiftBar 菜单栏插件
│       ├── linux/
│       │   └── mihomo.service        # systemd 服务文件
│       ├── alpine/
│       │   └── mihomo.openrc         # Alpine Linux OpenRC 脚本
│       ├── freebsd/
│       │   └── mihomo.rc             # FreeBSD rc.d 脚本
        ├── openwrt/
        │   └── mihomo.init           # OpenWrt init.d 脚本
        └── windows/
            ├── install.bat           # Windows CMD 安装脚本
            └── install.ps1           # Windows PowerShell 安装脚本
├── config/
│   ├── config.yaml                   # 主配置模板
│   └── clash-config.yaml             # ClashX Pro 订阅配置模板
├── ui/
│   └── index.html                    # Web UI 单文件仪表盘
├── data/                             # GeoIP / GeoSite 数据文件目录
├── logs/                             # 日志目录
└── README.md
```

## 获取源码

只需下载 `mihomo/` 子目录，无需克隆整个仓库。

**方式一：Git 稀疏克隆（推荐，macOS / Linux / Windows 均适用）**

```bash
git clone --filter=blob:none --sparse https://github.com/luoyueliang/net-tools.git
cd net-tools
git sparse-checkout set mihomo
cd mihomo
```

**方式二：下载完整仓库 ZIP**

前往 [github.com/luoyueliang/net-tools](https://github.com/luoyueliang/net-tools)，点击 **Code → Download ZIP**，解压后进入 `net-tools-main/mihomo/` 目录即可。

---

## 前置要求

### 安装 Node.js

`mihomo-ctl` 及安装脚本均为 Node.js 编写，运行前需安装 **Node.js v16 或更高版本**。

各平台安装方式请参阅：**[../node/README.md](../node/README.md)**

快速安装（macOS / Linux）：

```bash
# macOS Homebrew
brew install node

# 或 nvm（macOS / Linux 通用）
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
nvm install --lts
```

快速安装（Windows）：

```powershell
# 官方安装包（最简单）：https://nodejs.org → 下载 Windows LTS (.msi) 安装包，一路 Next 即可
# 或通过 winget（Windows 10 1709+）
winget install OpenJS.NodeJS.LTS
```

验证：

```bash
node --version   # v16.x.x 或更高
```

## 安装

> **Windows 用户**：请直接查看本章节的 **Windows（自动安装）** 部分，有专属安装脚本，无需关注下方 Unix 命令。

### 方式一：从 GitHub Release 直接安装（推荐，无需克隆仓库）

前往 [GitHub Releases](https://github.com/luoyueliang/net-tools/releases) 下载最新版  `mihomo-ctl-installer-*.tar.gz`，或使用以下命令（将 `1.4.3` 替换为实际版本号）：

```bash
VER=1.4.3
curl -LO https://github.com/luoyueliang/net-tools/releases/download/mihomo-ctl-v${VER}/mihomo-ctl-installer-${VER}.tar.gz

# 解压并安装（自动检测平台，macOS / Linux / Alpine / FreeBSD / OpenWrt）
tar xzf mihomo-ctl-installer-${VER}.tar.gz
cd mihomo-ctl-installer-${VER}/
node scripts/install.js
```

### 方式二：从本地仓库安装

```bash
# 进入 mihomo 目录（克隆方式见上方"获取源码"章节）
cd mihomo

# 执行安装脚本（Node.js 脚本，自动检测平台）
node scripts/install.js
```

> **下载代理**：脚本启动时会检测 `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` 等环境变量。  
> 若未设置，会交互询问是否配置下载代理（输入 `http://127.0.0.1:7890` 等，留空则跳过），  
> 设置后自动测试连通性。也可在执行前手动导出：  
> ```bash
> export HTTPS_PROXY=http://127.0.0.1:7890
> node scripts/install.js
> ```

安装脚本会完成以下操作：
1. 检查 Node.js 版本（≥ v16）
2. 检测当前平台（macOS / Linux / FreeBSD / OpenWrt / Alpine）和架构（amd64 / arm64）
3. 下载最新版 mihomo 二进制到 `/usr/local/bin/mihomo`
4. 创建配置目录 `~/.config/mihomo/{data,logs}`
5. 将 `config/config.yaml` 复制到 `~/.config/mihomo/config.yaml`（已存在则跳过）
6. 安装对应平台的启动脚本（macOS / Linux systemd / Alpine OpenRC / FreeBSD rc.d / OpenWrt init.d，默认禁用自启）
7. 将 `mihomo-ctl` 安装到 `/usr/local/bin/mihomo-ctl`

安装完成后编辑配置文件，填入你的节点信息：

```bash
nano ~/.config/mihomo/config.yaml
```

### Windows（自动安装）

在仓库 `mihomo\` 目录下，**以管理员身份**打开终端并运行：

```powershell
# PowerShell（推荐）
powershell -ExecutionPolicy Bypass -File scripts\platform\windows\install.ps1
```

```bat
:: CMD（可选）
scripts\platform\windows\install.bat
```

> **下载代理**：同样会检测 `HTTPS_PROXY` / `HTTP_PROXY` 环境变量。未设置时交互询问，  
> 输入代理地址后自动测试连通性。也可提前在 PowerShell 中设置：  
> ```powershell
> $env:HTTPS_PROXY = 'http://127.0.0.1:7890'
> powershell -ExecutionPolicy Bypass -File scripts\platform\windows\install.ps1
> ```

安装脚本自动完成：

1. 检查 Node.js v16+
2. 创建配置目录 `%APPDATA%\mihomo\{data,logs}`
3. 复制 `config\config.yaml` 模板
4. 从 GitHub 下载最新 `mihomo.exe` 到 `C:\Program Files\mihomo\`
5. 安装 `mihomo-ctl`（Node.js 主脚本）
6. 生成 `mihomo-ctl.bat` / `mihomo-ctl.ps1` 包装器（`dns-on` 等命令自动请求 UAC 提权）

安装完成后将 `C:\Program Files\mihomo` 加入系统 PATH：

```powershell
[Environment]::SetEnvironmentVariable('PATH', $env:PATH + ';C:\Program Files\mihomo', 'Machine')
# 重启终端后生效
mihomo-ctl status
mihomo-ctl dns-on    # 自动请求管理员权限（UAC 弹窗）
```

> DNS 接管（`dns-on`）和系统代理（`proxy-on`）在 Windows 上均需管理员权限；`mihomo-ctl.bat` / `mihomo-ctl.ps1` 包装器会自动弹出 UAC，无需手动以管理员身份打开终端。

## 用法

**状态 & 控制**

```
mihomo-ctl                    查看状态（含 GeoIP 新鲜度、连接数）
mihomo-ctl start              启动进程 + 自动开启系统代理
                              （启动前自动互斥：检测并结束 ClashX/Verge 等抢占端口的进程）
mihomo-ctl start --force      启动并强制结束冲突进程（不询问）
mihomo-ctl stop               停止进程 + 自动关闭系统代理
mihomo-ctl restart            重启进程 + 自动恢复系统代理
mihomo-ctl reload             热重载配置文件（不中断连接）
mihomo-ctl conflicts          检测冲突的 Clash/Mihomo 家族进程（ClashX/Verge/Stash 等）
mihomo-ctl conflicts --force  结束所有冲突进程
mihomo-ctl upgrade            无缝升级（预下载完成后才停机，自动备份+失败回滚）
mihomo-ctl check              检查配置文件语法
```

**模式切换**

```
mihomo-ctl mode               查看当前模式
mihomo-ctl mode rule          规则分流（默认）
mihomo-ctl mode global        全局代理（全部走代理）
mihomo-ctl mode direct        全局直连（跳过代理）
```

**GeoIP / GeoSite 数据**

```
mihomo-ctl geo                查看数据文件状态及定时任务
mihomo-ctl geo update         立即下载最新 GeoIP/GeoSite（MMDB 或 DAT，随 geodata-mode 自动选择）
mihomo-ctl geo schedule       设置每周一 03:00 自动更新（cron）
mihomo-ctl geo unschedule     取消自动更新
```

**连接监控**

```
mihomo-ctl traffic            实时流量速率（Ctrl+C 退出）
mihomo-ctl connections        列出活跃连接
mihomo-ctl connections close-all  断开所有连接
```

**Web UI（可切换面板）**

```
mihomo-ctl ui                 查看当前面板与切换提示
mihomo-ctl ui local           切换为内置精简面板（本项目自带，单文件）
mihomo-ctl ui meta            下载并切换为 MetaCubeXD（官方功能完整面板）
mihomo-ctl ui open            浏览器打开 http://127.0.0.1:9090/ui/
```

> 两套面板任选：`ui local` 是本项目自带的轻量单文件页面；`ui meta` 直接从 GitHub
> 下载 MetaCubeXD（gh-pages.zip，走系统代理）。切换后均会设置 `external-ui-url: ''`
> 锁定，阻止内核启动时自动下载覆盖。切换完成执行 `mihomo-ctl reload` 生效。

**菜单栏图标（macOS）**

```
mihomo-ctl tray               输出菜单栏插件内容（由 xbar/SwiftBar 调用渲染）
mihomo-ctl tray install       安装菜单栏插件；未装时自动用 Homebrew 装 SwiftBar
```

> `tray install` 插件脚本由 mihomo-ctl 内联生成，无需仓库源文件（安装后也能用）。
> 若未安装 xbar / SwiftBar，会直接从 GitHub 下载 SwiftBar.dmg 安装（仅靠 curl + hdiutil，无 Homebrew 依赖）并完成插件配置、启动 SwiftBar。
> 菜单栏显示运行状态与当前节点，下拉菜单可一键 启动/停止/重启/切换系统代理或 TUN/打开面板。
> 全部逻辑在 `mihomo-ctl tray` 中，插件脚本仅做转发，零原生编译、零 npm 依赖。

**配置备份 & 恢复**

```
mihomo-ctl backup             备份当前 config.yaml（带时间戳）
mihomo-ctl restore            列出所有备份
mihomo-ctl restore latest     恢复最新备份
mihomo-ctl restore <时间戳>   恢复指定备份
```

**节点管理**

```
mihomo-ctl proxies            列出所有节点及延迟
mihomo-ctl test               测速所有节点（约 10s）
mihomo-ctl select             交互式切换节点 ↑↓Enter
mihomo-ctl select <组> <节点>  直接切换
```

**开机自启（默认禁用）**

```
mihomo-ctl autostart          查看自启状态
mihomo-ctl autostart on       启用开机自启
mihomo-ctl autostart off      禁用开机自启
```

> 各平台服务管理器：macOS → launchd · Linux → systemd · Alpine → OpenRC · FreeBSD → rc.d · OpenWrt → init.d

**系统代理（macOS · Linux · FreeBSD · Alpine · Windows）**

> **macOS**（需 sudo）：`networksetup` 系统级接管，浏览器等 GUI 应用自动生效。  
> **Linux / FreeBSD / Alpine**：写入 `~/.bashrc` / `~/.zshrc` 等 rc 文件，**新终端自动生效**；运行 `eval $(mihomo-ctl proxy-env)` 可让 **当前终端立即生效**。旧内容自动备份到 `~/.config/mihomo/proxy-rc-backup/`。  
> **Windows**（需管理员）：注册表系统代理接管。

```
mihomo-ctl proxy-on           接管系统代理（写入 rc 文件 / 系统级接管）
mihomo-ctl proxy-off          关闭系统代理（从 rc 文件移除 / 系统级关闭）
mihomo-ctl proxy-env          输出可 eval 的代理语句（Linux/FreeBSD/Alpine 专用）
                              eval $(mihomo-ctl proxy-env)  — 当前终端立即生效/清除
```

**DNS 防污染（需管理员/sudo，macOS · FreeBSD · Linux · Alpine · Windows）**

> **macOS / FreeBSD**：pf 端口重定向（53→1053）+ 设置系统 DNS 为 127.0.0.1（FreeBSD 通过 `/etc/resolv.conf`）。  
> **Linux / Alpine**：iptables 重定向（OUTPUT -p udp/tcp --dport 53 → 1053），无需修改 resolv.conf，需 sudo。  
> **Windows**：netsh 修改活跃网络接口 DNS 为 127.0.0.1，需管理员权限（`mihomo-ctl.bat` / `.ps1` 自动 UAC 提权）。

```
mihomo-ctl dns                查看 DNS 接管状态（显示接口名）
mihomo-ctl dns-on             接管当前路由接口 DNS → Mihomo DoH
mihomo-ctl dns-off            恢复系统 DNS（DHCP）
```

**日志（默认关闭）**

```
mihomo-ctl log                查看最近 50 行日志
mihomo-ctl log-on             开启日志 (info)
mihomo-ctl log-off            关闭日志 (silent)
tail -f ~/.config/mihomo/logs/mihomo.log
```

**终端临时代理（所有平台）**

```bash
export https_proxy=http://127.0.0.1:7890 http_proxy=http://127.0.0.1:7890
unset https_proxy http_proxy
```

## 平台支持

| 功能 | macOS | Linux | FreeBSD | Alpine | OpenWrt | Windows |
|------|:---:|:---:|:---:|:---:|:---:|:---:|
| 启动 / 停止 / 重启 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 热重载 / 模式切换 / 节点管理 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| proxy-on / proxy-off（系统代理）| ✓ | ✓ ² | ✓ ² | ✓ ² | — | ✓ |
| dns-on / dns-off（DNS 接管）| ✓ | ✓ | ✓ | ✓ | — | ✓ |
| 开机自启 | launchd | systemd | rc.d | OpenRC | init.d | 任务计划程序 |
| `install.js` 自动安装 | ✓ | ✓ | ✓ | ✓ | ✓ | — |

> 系统代理（proxy-on / proxy-off）：macOS（`networksetup`）和 Windows（注册表）为系统级接管；**² Linux / FreeBSD / Alpine** 写入 `~/.bashrc`/`~/.zshrc` 等 rc 文件（新终端自动生效），`eval $(mihomo-ctl proxy-env)` 可让当前终端立即生效；OpenWrt 为路由器平台不适用（`—`）。  
> DNS 接管：macOS / FreeBSD 使用 **pf**；Linux / Alpine 使用 **iptables**；Windows 使用 **netsh**。  
> OpenWrt 为路由器平台，DNS 接管需在 PREROUTING 链配置，与普通 Linux 桌面用法不同，暂不内置。

## 配置文件说明

| 文件 / 目录 | 说明 |
|------------|------|
| `config/config.yaml` | 主配置模板，安装时复制到 `~/.config/mihomo/config.yaml` |
| `config/clash-config.yaml` | ClashX Pro 订阅配置模板 |
| `scripts/platform/macos/mihomo.plist` | macOS LaunchAgent 模板，安装时复制到 `~/Library/LaunchAgents/` |
| `scripts/platform/linux/mihomo.service` | Linux systemd 服务文件 |
| `scripts/platform/alpine/mihomo.openrc` | Alpine Linux OpenRC 脚本，安装到 `/etc/init.d/mihomo` |
| `scripts/platform/freebsd/mihomo.rc` | FreeBSD rc.d 脚本 |
| `scripts/platform/openwrt/mihomo.init` | OpenWrt init.d 脚本 |
| `data/` | GeoIP / GeoSite 数据占位目录；运行时 mihomo 实际将 `geoip.metadb`（MMDB 模式）/ `geosite.dat` 放在 `~/.config/mihomo/` 根目录 |
| `logs/` | 日志目录占位，运行时日志写入 `~/.config/mihomo/logs/mihomo.log` |

运行时配置位于 `~/.config/mihomo/`，与本仓库相互独立：

```
~/.config/mihomo/
  config.yaml         # 主配置（节点信息在此）
  data/               # GeoIP / GeoSite 数据文件
  logs/               # 日志文件
    mihomo.log
  backups/            # 配置备份（mihomo-ctl backup / upgrade 自动创建）
```

## 端口说明

| 端口 | 用途 |
|------|------|
| `7890` | HTTP/SOCKS5 混合代理端口 |
| `9090` | RESTful API 控制端口 |
| `1053` | DNS 监听端口（dns-on 模式） |
