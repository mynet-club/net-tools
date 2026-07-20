# AGENTS.md

This file provides guidance to Qoder (qoder.com) when working with code in this repository.

## Ops 核心定位原则（所有 Agent 必须遵守）

**从规范文件入手 → 找到架构文档 → 快速定位 → 尽早排除干扰。**

执行任何运维任务前：
1. 先读 `copilot-instructions.md` / `AGENTS.md` / `README.md` 等规范文件，建立全局认知
2. 通过架构文档中的网络拓扑、服务器清单、服务映射快速定位目标
3. 查阅凭证文件时，参考 `credentials/README.md` 的目录索引，按 IP / 服务名 / 产品名精准匹配
4. 排除无关目录和文件的干扰，只在目标范围内操作

---

## Repository Overview

**net-tools** is a monorepo of independent cross-platform (macOS/Linux/FreeBSD/Alpine/OpenWrt/Windows) network proxy management CLI tools. Each top-level directory is a standalone tool with its own `src/`, `scripts/`, `config/`, `data/`, `logs/` directories. Tools are written in Node.js and manage downstream binaries (mihomo, xray-core).

## Tools

| Directory | Tool | Description | Node.js Version |
|-----------|------|-------------|-----------------|
| `mihomo/` | mihomo-ctl | Mihomo (Clash Meta) proxy management CLI — single-file script (3100+ lines), zero npm deps | ≥ v16 |
| `smartxray/` | xray-ctl | Xray server manager — SQLite user DB, dynamic config generation, firewall integration, Web UI | ≥ v18 |
| `toolstpl/` | (template) | Scaffold template for creating new tools — uses `__PLACEHOLDER__` tokens | ≥ v16 |
| `node/` | — | Shared Node.js installation docs for all tools | — |

## Build & Release Commands

```bash
# Install dependencies (smartxray only — mihomo has zero npm deps)
cd smartxray && npm install

# Pack / release (each tool)
cd mihomo    && node scripts/release.js           # → dist/mihomo-ctl-*.gz
cd smartxray && node scripts/release.js           # → dist/xray-ctl-*.gz
cd <tool>    && node scripts/release.js --publish  # build + publish to GitHub Release (requires gh CLI)

# Install a tool locally (downloads binary, sets up service, installs CLI)
cd <tool> && node scripts/install.js
```

There is no test suite or linter configured in this repository.

## Architecture

### mihomo — Single-File CLI Tool

`mihomo/src/mihomo-ctl` is a **single 3100-line Node.js script** with no npm dependencies. It communicates with the running mihomo process via its RESTful API on `http://127.0.0.1:9090`. Key design:

- **Platform adapter pattern**: `PLATFORM_ADAPTERS` object maps each OS (macos/linux/alpine/freebsd/openwrt) to start/stop/autostart/DNS operations
- **Runtime config**: `~/.config/mihomo/` (Unix) or `%APPDATA%\mihomo\` (Windows) — independent from repo templates
- **API secret**: reads `secret` from `config.yaml` for Authorization headers on all mihomo API calls
- **VERSION constant** at line 14 — must be incremented (patch +1) on every modification to this file

### smartxray — Modular Architecture

`smartxray/src/xray-ctl` is the CLI entry point that imports from `src/lib/`:

```
xray-ctl (CLI entry)
├── lib/config.js          — Path constants, port ranges, settings (getSetting/setSetting), version
├── lib/database.js        — SQLite via node-sqlite3-wasm, user CRUD, settings table
├── lib/config-generator.js— Generates xray config.json from DB users + settings
├── lib/api-server.js      — HTTP API server (port 9091), Web UI static files, REST endpoints
│   └── lib/routes/        — Route handlers: auth, users, settings, firewall, selfservice
├── lib/user-manager.js    — User lifecycle (add/del/enable/disable, temp account cleanup)
├── lib/firewall.js        — ufw/firewall-cmd/iptables/pf integration, Lightsail/OpenWrt sync
├── lib/reality.js         — VLESS+XTLS-Reality key generation and config
├── lib/port-allocator.js  — Random port allocation within configured ranges
├── lib/token-cache.js     — Token caching for API auth
├── lib/config-cache.js    — Config caching layer
├── lib/cleanup-manager.js — Periodic cleanup of expired temp accounts
├── lib/logger.js          — Logging utilities
├── lib/validators.js      — Input validation
├── lib/errors.js          — Custom error types
└── lib/utils.js           — Shared helpers (apiResponse, parseBody)
```

- **Runtime data**: `~/.config/smartxray/` — DB, generated config, UI files, logs
- **Base dir detection**: `getBaseDir()` in config.js and database.js checks if running from `/usr/local/lib/` (bundle mode) vs development mode (two levels up from `__dirname`)
- **Command injection pattern**: `api-server.js` exposes `registerCommands(cmds)` — xray-ctl injects `cmdStart`/`cmdStop`/`cmdReload` at startup so the API server can control the xray process

### toolstpl — Scaffold Template

`toolstpl/` is a copy-paste template for new tools. All placeholders use `__TOOL_NAME__`, `__CTL_NAME__`, `__BIN_NAME__`, `__VERSION__`, `__API_PORT__`, `__PLIST_ID__`, `__GITHUB_REPO__`. The `src/tool-ctl` file demonstrates the platform adapter pattern and self-upgrade logic that all tools share.

## Cross-Cutting Patterns

### Platform Adapter Pattern

All tools use a `PLATFORM_ADAPTERS` object mapping OS names to service management operations (start/stop/getPid/autostart/installBin). Detected at runtime via `detectPlatform()` checking `process.platform` + OS-specific release files. The factory `createServiceAdapter()` provides base implementations for systemd/OpenRC/rc.d/procd.

### Installation Flow

Each tool's `scripts/install.js`:
1. Checks Node.js version
2. Detects platform/arch, downloads the managed binary from GitHub releases
3. Creates runtime config directory (`~/.config/<tool>/`)
4. Copies config template if first install
5. Installs platform service script (launchd/systemd/OpenRC/rc.d/init.d)
6. Installs the CLI script to `/usr/local/bin/<ctl-name>`

### Release Flow

`scripts/release.js` in each tool:
1. Bundles source (smartxray uses `@vercel/ncc` to create single-file bundle; mihomo inlines `ui/index.html` as base64)
2. Applies `javascript-obfuscator` (string array base64 + hex variable names)
3. Outputs gzipped binary to `dist/`
4. `--publish` flag triggers GitHub Release creation via `gh` CLI

## Coding Conventions

- **Language**: All source code and comments in Chinese (comments, CLI output, error messages)
- **Style**: 2-space indent, K&R braces, camelCase variables, UPPER_SNAKE_CASE constants, kebab-case filenames
- **Booleans**: prefix with `is`/`has`/`can`/`should`
- **No var**: use `const`/`let`, prefer `const`
- **Node.js builtins first**: avoid npm dependencies unless necessary (mihomo has zero deps)
- **Config placeholders**: use `__VARIABLE__` format in templates, never commit real secrets
- **Shebang**: `#!/usr/bin/env node` for Node.js scripts, `#!/usr/bin/env bash` with `set -euo pipefail` for shell scripts

## Commit Convention

Format: `<tool-name>: <short description>` (e.g., `mihomo: 添加 dns-on 命令`)

**Critical rule**: Every modification to `mihomo/src/mihomo-ctl` MUST increment the patch version in the `VERSION` constant (line 14).

## Directory Structure Rules

Every tool directory must contain: `src/`, `scripts/` (with `install.js` + `platform/`), `config/`, `data/` (with `.gitkeep`), `logs/` (with `.gitkeep`), `README.md`. When adding a new tool, also update the root `README.md` tool list.
