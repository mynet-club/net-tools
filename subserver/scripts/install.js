#!/usr/bin/env node
// subserver installer — Linux (systemd)
// 用法: node scripts/install.js
//
// 安装方式: 使用预构建 bundle（无需 npm install）
// 1. 检查 Node.js 版本
// 2. 安装 bundle 到 /usr/local/lib/subserver/
// 3. 创建 shim 脚本 /usr/local/bin/subserver
// 4. 创建运行时目录 ~/.config/subserver/
// 5. 复制配置模板
// 6. 安装 systemd 服务

'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { execSync } = require('child_process');

// ── ANSI colors ──────────────────────────────────────────────────
const c = {
  green:  s => `\x1b[32m${s}\x1b[0m`,
  red:    s => `\x1b[31m${s}\x1b[0m`,
  yellow: s => `\x1b[33m${s}\x1b[0m`,
  cyan:   s => `\x1b[36m${s}\x1b[0m`,
  bold:   s => `\x1b[1m${s}\x1b[0m`,
  dim:    s => `\x1b[2m${s}\x1b[0m`,
};
const info    = (...a) => console.log(c.cyan('[INFO] ') + a.join(' '));
const success = (...a) => console.log(c.green('[OK]   ') + a.join(' '));
const warn    = (...a) => console.log(c.yellow('[WARN] ') + a.join(' '));
const error   = (...a) => { console.error(c.red('[ERROR]') + ' ' + a.join(' ')); process.exit(1); };

function run(cmd, opts = {}) {
  return (execSync(cmd, { encoding: 'utf8', stdio: 'pipe', ...opts }) ?? '').trim();
}

function needsSudo() {
  try { return run('whoami') !== 'root'; }
  catch { return true; }
}
function sudoPrefix() { return needsSudo() ? 'sudo ' : ''; }

// ── Paths ────────────────────────────────────────────────────────
const REPO_ROOT  = path.join(__dirname, '..');
const SCRIPT_DIR = __dirname;
const HOME       = os.homedir();
const user       = run('whoami');

const configDir  = `${HOME}/.config/subserver`;
const dataDir    = path.join(configDir, 'data');
const logsDir    = path.join(configDir, 'logs');
const LIB_DIR    = '/usr/local/lib/subserver';
const CTL_BIN    = '/usr/local/bin/subserver';

// GitHub 仓库（下载 bundle 用，按需修改）
const REPO = 'your-org/net-tools';

// ── Step 1: Check Node.js ────────────────────────────────────────
function checkNode() {
  const ver = process.versions.node.split('.').map(Number);
  if (ver[0] < 18) error(`Node.js v18+ required, found v${process.versions.node}`);
  success(`Node.js v${process.versions.node}`);
}

// ── Step 2: Install bundle ───────────────────────────────────────
function installBundle() {
  // 优先使用安装包内的 bundle/
  const localBundle = path.join(REPO_ROOT, 'bundle');
  if (!fs.existsSync(path.join(localBundle, 'index.js'))) {
    // 尝试从 GitHub Release 下载
    info('本地 bundle/ 不存在，尝试从 GitHub Release 下载...');
    let latestVer;
    try {
      const out = run(`curl -sf --max-time 10 "https://api.github.com/repos/${REPO}/releases?per_page=50"`);
      const rels = JSON.parse(out);
      const parseV = v => v.split('.').map(Number);
      const cmpV = (a, b) => { for (let i = 0; i < 3; i++) { if (a[i] !== b[i]) return a[i] - b[i]; } return 0; };
      let best = null;
      for (const r of rels) {
        if (!r.tag_name || !r.tag_name.startsWith('subserver-v')) continue;
        const ver = r.tag_name.replace('subserver-v', '');
        if (!best || cmpV(parseV(ver), parseV(best)) > 0) best = ver;
      }
      if (best) latestVer = best;
    } catch {}

    if (!latestVer) {
      error('未找到 bundle 也无法从 GitHub 下载。请先运行: node scripts/release.js');
    }

    const assetName = `subserver-bundle-${latestVer}.tar.gz`;
    const url = `https://github.com/${REPO}/releases/download/subserver-v${latestVer}/${assetName}`;
    const tmpTar = path.join(os.tmpdir(), assetName);
    const tmpExtract = path.join(os.tmpdir(), `subserver-bundle-${latestVer}`);

    info(`下载 bundle v${latestVer}...`);
    try {
      run(`curl -fsSL --max-time 60 -o "${tmpTar}" "${url}"`);
      fs.mkdirSync(tmpExtract, { recursive: true });
      run(`tar xzf "${tmpTar}" -C "${tmpExtract}"`);
      try { fs.unlinkSync(tmpTar); } catch {}

      // 使用下载的 bundle
      run(`${sudoPrefix()}mkdir -p "${LIB_DIR}"`);
      run(`${sudoPrefix()}sh -c 'cd "${tmpExtract}" && for f in *; do case "$f" in .*) ;; *) cp -r "$f" "${LIB_DIR}/" ;; esac; done'`);
      try { fs.rmSync(tmpExtract, { recursive: true, force: true }); } catch {}
    } catch (e) {
      error(`下载 bundle 失败: ${e.message}`);
    }
    return;
  }

  info('使用本地 bundle/ 安装...');
  run(`${sudoPrefix()}mkdir -p "${LIB_DIR}"`);
  // 复制 bundle 文件，排除 macOS 资源分支文件
  run(`${sudoPrefix()}sh -c 'cd "${localBundle}" && for f in *; do case "$f" in .*) ;; *) cp -r "$f" "${LIB_DIR}/" ;; esac; done'`);
  success(`bundle 安装到 ${LIB_DIR}`);
}

// ── Step 3: Create shim script ───────────────────────────────────
function installShim() {
  const shimContent = `#!/bin/sh\ncd "${LIB_DIR}"\nexec node "${LIB_DIR}/index.js" "$@"\n`;
  const tmpShim = path.join(os.tmpdir(), 'subserver-shim');
  fs.writeFileSync(tmpShim, shimContent);
  run(`${sudoPrefix()}install -m 755 "${tmpShim}" "${CTL_BIN}"`);
  try { fs.unlinkSync(tmpShim); } catch {}
  success(`shim 安装到 ${CTL_BIN}`);
}

// ── Step 4: Create runtime directories ───────────────────────────
function createDirs() {
  for (const dir of [configDir, dataDir, logsDir]) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      success(`创建目录: ${dir}`);
    } else {
      info(`目录已存在: ${dir}`);
    }
  }
}

// ── Step 5: Copy config template ─────────────────────────────────
function installConfig() {
  const srcDefault = path.join(REPO_ROOT, 'config', 'default.json');
  const dstConfig  = path.join(configDir, 'config.json');

  if (fs.existsSync(dstConfig)) {
    info(`配置文件已存在: ${dstConfig}（跳过）`);
    return;
  }

  if (fs.existsSync(srcDefault)) {
    const content = fs.readFileSync(srcDefault, 'utf8')
      .replace('__ADMIN_TOKEN__', run('openssl rand -hex 16') || 'changeme');
    // 调整 dbPath 为绝对路径
    const cfg = JSON.parse(content);
    cfg.dbPath = path.join(dataDir, 'subserver.db');
    fs.writeFileSync(dstConfig, JSON.stringify(cfg, null, 2) + '\n');
    success(`配置文件: ${dstConfig}`);
    warn(`请编辑此文件设置 adminToken 和节点信息`);
  } else {
    // 默认配置
    const cfg = {
      port: 3456,
      host: '127.0.0.1',
      adminToken: run('openssl rand -hex 16') || 'changeme',
      dbPath: path.join(dataDir, 'subserver.db'),
    };
    fs.writeFileSync(dstConfig, JSON.stringify(cfg, null, 2) + '\n');
    success(`配置文件: ${dstConfig}`);
  }
}

// ── Step 6: Install systemd service ──────────────────────────────
function installSystemd() {
  const src = path.join(SCRIPT_DIR, 'platform', 'linux', 'subserver.service');
  if (!fs.existsSync(src)) {
    warn('systemd 服务模板不存在，跳过');
    return;
  }

  const dst = '/etc/systemd/system/subserver.service';
  const content = fs.readFileSync(src, 'utf8')
    .replace(/__USER__/g, user)
    .replace(/__INSTALL_DIR__/g, LIB_DIR);

  run(`${sudoPrefix()}tee "${dst}" > /dev/null`, { input: content, stdio: ['pipe', 'inherit', 'inherit'] });
  run(`${sudoPrefix()}systemctl daemon-reload`);
  success(`systemd 服务: ${dst}`);
  info('启动: sudo systemctl start subserver');
  info('自启: sudo systemctl enable subserver');
}

// ── Main ─────────────────────────────────────────────────────────
function main() {
  console.log('\n' + c.bold('='.repeat(50)));
  console.log(c.bold('  subserver installer'));
  console.log(c.bold('  Platform: Linux (systemd)'));
  console.log(c.bold('='.repeat(50)) + '\n');

  // 平台检查
  if (process.platform !== 'linux') {
    warn(`本工具设计为 Linux 服务端部署，当前平台: ${process.platform}`);
    warn('继续安装可能无法正常工作...');
  }

  checkNode();
  installBundle();
  installShim();
  createDirs();
  installConfig();
  installSystemd();

  console.log('\n' + c.bold('='.repeat(50)));
  success('安装完成!');
  console.log(c.dim('\n  快速开始:'));
  console.log(c.dim('    sudo systemctl start subserver     # 启动服务'));
  console.log(c.dim('    curl http://127.0.0.1:3456/health  # 健康检查'));
  console.log(c.dim('    node scripts/seed.js               # 导入示例数据'));
  console.log(c.dim('    curl http://127.0.0.1:3456/sub/<token>  # 获取订阅'));
  console.log(c.bold('='.repeat(50)));
}

main();
