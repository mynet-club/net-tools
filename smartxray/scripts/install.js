#!/usr/bin/env node
// smartxray installer — supports macOS / Linux (systemd) / Alpine (OpenRC) / FreeBSD
// Usage: node scripts/install.js [--no-download]
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

// 检测是否需要 sudo
function needsSudo() {
  try {
    const currentUser = run('whoami');
    return currentUser !== 'root';
  } catch {
    return true;
  }
}

// 获取 sudo 前缀
function sudoPrefix() {
  return needsSudo() ? 'sudo ' : '';
}

// ── Proxy setup ──────────────────────────────────────────────────
async function promptProxy() {
  const existing = process.env.HTTPS_PROXY || process.env.https_proxy ||
                   process.env.HTTP_PROXY  || process.env.http_proxy  ||
                   process.env.ALL_PROXY   || process.env.all_proxy;
  if (existing) { info(`检测到代理环境变量: ${existing}`); return; }

  const rl = require('readline').createInterface({ input: process.stdin, output: process.stdout });
  const proxy = await new Promise(resolve => {
    process.stdout.write(c.cyan('[INFO] ') + '未检测到代理，如访问 GitHub 有问题可设置下载代理\n');
    rl.question('       (输入 http://host:port 或直接回车跳过): ', ans => { rl.close(); resolve(ans.trim()); });
  });
  if (!proxy) { info('跳过代理设置，直接连接'); return; }

  process.env.http_proxy  = proxy;
  process.env.https_proxy = proxy;
  process.env.HTTP_PROXY  = proxy;
  process.env.HTTPS_PROXY = proxy;
  info(`代理已设置: ${proxy}，测试连通性...`);
  try {
    run(`curl -sf --max-time 8 --proxy "${proxy}" "https://www.google.com" -o /dev/null`);
    success('代理连通性测试通过 ✓');
  } catch {
    warn('代理连通性测试未通过，将继续安装（下载失败时请检查代理地址是否正确）');
  }
}

// ── Detect platform ──────────────────────────────────────────────
function detectPlatform() {
  if (fs.existsSync('/etc/alpine-release')) return 'alpine';
  switch (process.platform) {
    case 'darwin':  return 'macos';
    case 'linux':   return 'linux';
    case 'freebsd': return 'freebsd';
    default: error(`Unsupported platform: ${process.platform}`);
  }
}

function detectArch() {
  const a = os.arch();
  if (a === 'x64')   return 'amd64';
  if (a === 'arm64') return 'arm64';
  if (a === 'arm')   return 'arm32-v7a';
  return a;
}

// ── Paths ────────────────────────────────────────────────────────
const PLATFORM   = detectPlatform();
const ARCH       = detectArch();
const HOME       = os.homedir();
const REPO_ROOT  = path.join(__dirname, '..');
const SCRIPT_DIR = __dirname;
const user       = run('whoami');

// Linux 生产环境使用 FHS 路径，其他平台保持 ~/.config/smartxray/
const isLinuxProd = PLATFORM === 'linux' || PLATFORM === 'alpine';
const configDir  = isLinuxProd ? '/etc/smartxray'    : `${HOME}/.config/smartxray`;
const dataDir    = isLinuxProd ? '/var/lib/smartxray' : path.join(HOME, '.config/smartxray', 'data');
const logsDir    = isLinuxProd ? '/var/log/smartxray' : path.join(HOME, '.config/smartxray', 'logs');
const binDir     = '/usr/local/bin';
const LIB_DIR    = '/usr/local/lib/smartxray';  // bundle 安装目录
const XRAY_BIN   = path.join(binDir, 'xray');
const CTL_BIN    = path.join(binDir, 'xray-ctl');

// ── Step 1: Check Node.js version ────────────────────────────────
function checkNode() {
  const ver = process.versions.node.split('.').map(Number);
  if (ver[0] < 18) error(`Node.js v18+ required, found v${process.versions.node}`);
  success(`Node.js v${process.versions.node}`);
}

// ── Step 2: Install npm dependencies ─────────────────────────────
function installDeps() {
  // 使用 bundle 模式时无需 npm install
  if (fs.existsSync(path.join(REPO_ROOT, 'bundle', 'index.js'))) {
    info('检测到 bundle/，跳过 npm install');
    return;
  }
  info('Installing npm dependencies...');
  try {
    execSync('npm install --omit=dev', { cwd: REPO_ROOT, stdio: 'inherit' });
    success('npm install done');
  } catch { error('npm install failed — install manually: npm install --omit=dev'); }
}

// ── Step 3: Download & install xray binary ───────────────────────
async function installXray() {
  if (fs.existsSync(XRAY_BIN)) {
    const ver = run(`${XRAY_BIN} version 2>/dev/null | head -1`);
    success(`xray already installed: ${ver || '(unknown version)'}  (run: xray-ctl upgrade if needed)`);
    return;
  }

  info('Fetching latest xray-core release...');
  let latest;
  try {
    const out = run('curl -sf --max-time 10 "https://api.github.com/repos/XTLS/Xray-core/releases/latest"');
    latest = JSON.parse(out).tag_name;
  } catch { error('Failed to fetch latest version. Check your network.'); }

  const osMap   = { macos: 'macos', linux: 'linux', alpine: 'linux', freebsd: 'freebsd' };
  const archMap = { amd64: 'amd64', arm64: 'arm64', 'arm32-v7a': 'arm32-v7a' };
  const osStr   = osMap[PLATFORM];
  const archStr = archMap[ARCH] || ARCH;
  const zipName = `Xray-${osStr}-${archStr}.zip`;
  const url     = `https://github.com/XTLS/Xray-core/releases/download/${latest}/${zipName}`;

  const tmpDir = path.join(configDir, 'tmp');
  const tmpZip = path.join(tmpDir, 'xray.zip');
  fs.mkdirSync(tmpDir, { recursive: true });

  info(`Downloading ${url}`);
  run(`curl -4 -fL --max-time 120 -o "${tmpZip}" "${url}"`, { stdio: 'inherit' });
  run(`unzip -o "${tmpZip}" xray -d "${tmpDir}"`, { stdio: 'pipe' });

  const tmpBin = path.join(tmpDir, 'xray');
  if (!fs.existsSync(tmpBin)) error('Decompress failed: xray binary not found in archive');

  run(`${sudoPrefix()}install -m 755 "${tmpBin}" "${XRAY_BIN}"`);
  if (PLATFORM === 'macos') run(`xattr -d com.apple.quarantine "${XRAY_BIN}" 2>/dev/null || true`);
  run(`rm -rf "${tmpDir}"`);
  success(`xray ${latest} installed to ${XRAY_BIN}`);
}

// ── Step 4: Create config directories ────────────────────────────
function createDirs() {
  if (isLinuxProd) {
    // FHS 标准路径
    const dirs = [configDir, dataDir, logsDir];
    for (const dir of dirs) {
      run(`${sudoPrefix()}mkdir -p ${dir}`);
      run(`${sudoPrefix()}chmod 755 ${dir}`);
      success(`Created ${dir}`);
    }
  } else {
    // macOS / 开发模式
    for (const dir of [configDir, logsDir, dataDir]) {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        success(`Created ${dir}`);
      } else {
        info(`Directory exists: ${dir}`);
      }
    }
  }
}

// ── Step 5: Install platform startup script ──────────────────────
function installStartup() {
  if (PLATFORM === 'macos') {
    const launchDir = `${HOME}/Library/LaunchAgents`;
    const dstBase   = path.join(launchDir, 'com.smartxray.plist');
    const dstDis    = `${dstBase}.disabled`;
    const src       = path.join(SCRIPT_DIR, 'platform/macos/com.smartxray.plist');

    fs.mkdirSync(launchDir, { recursive: true });
    const content = fs.readFileSync(src, 'utf8').replace(/__HOME__/g, HOME);
    fs.writeFileSync(dstDis, content);
    success(`LaunchAgent installed (autostart disabled): ${dstDis}`);
    info('Enable autostart: xray-ctl autostart on');

  } else if (PLATFORM === 'linux') {
    const src = path.join(SCRIPT_DIR, 'platform/linux/smartxray.service');
    const dst = '/etc/systemd/system/smartxray.service';
    // 服务文件已使用 FHS 硬编码路径，无需替换
    const content = fs.readFileSync(src, 'utf8');
    run(`${sudoPrefix()}tee "${dst}" > /dev/null`, { input: content, stdio: ['pipe', 'inherit', 'inherit'] });
    run(`${sudoPrefix()}systemctl daemon-reload`);
    success(`systemd service installed: ${dst}`);
    info('Enable autostart: xray-ctl autostart on');
    info('Start:            xray-ctl start');

  } else if (PLATFORM === 'alpine') {
    const src = path.join(SCRIPT_DIR, 'platform/alpine/smartxray.openrc');
    const dst = '/etc/init.d/smartxray';
    // OpenRC 脚本已使用 FHS 路径，无需替换
    const content = fs.readFileSync(src, 'utf8');
    run(`${sudoPrefix()}tee "${dst}" > /dev/null`, { input: content, stdio: ['pipe', 'inherit', 'inherit'] });
    run(`${sudoPrefix()}chmod +x "${dst}"`);
    success(`OpenRC init script installed: ${dst}`);
    info('Enable autostart: xray-ctl autostart on');
    info('Start:            xray-ctl start');

  } else if (PLATFORM === 'freebsd') {
    const src = path.join(SCRIPT_DIR, 'platform/freebsd/smartxray');
    const dst = '/usr/local/etc/rc.d/smartxray';
    // /home/__USER__ must be replaced BEFORE __USER__ to handle root (HOME=/root)
    const content = fs.readFileSync(src, 'utf8')
      .replace(/\/home\/__USER__/g, HOME)
      .replace(/__USER__/g, user);
    run(`${sudoPrefix()}tee "${dst}" > /dev/null`, { input: content, stdio: ['pipe', 'inherit', 'inherit'] });
    run(`${sudoPrefix()}chmod 555 "${dst}"`);
    success(`rc.d script installed: ${dst}`);
    info(`Enable: sysrc smartxray_enable=YES`);
  }
}

// ── Step 6: Install xray-ctl (bundle mode) ───────────────────────
async function installCtl() {
  // 1. 查询 GitHub Release 最新版本
  let ctlVer;
  try {
    const out = run(
      'curl -sf --max-time 10 ' +
      '"https://api.github.com/repos/luoyueliang/net-tools/releases?per_page=50"'
    );
    if (out) {
      const rels = JSON.parse(out);
      const parseV = v => v.split('.').map(Number);
      const cmpV = (a, b) => { for (let i = 0; i < 3; i++) { if (a[i] !== b[i]) return a[i] - b[i]; } return 0; };
      let best = null;
      for (const r of rels) {
        if (!r.tag_name || !r.tag_name.startsWith('smartxray-v')) continue;
        const ver = r.tag_name.replace('smartxray-v', '');
        if (!best || cmpV(parseV(ver), parseV(best)) > 0) best = ver;
      }
      if (best) ctlVer = best;
    }
  } catch {}

  // 2. 尝试从 GitHub Release 下载 bundle tar
  let bundleSrc = null;
  if (ctlVer) {
    const assetName  = `xray-ctl-bundle-${ctlVer}.tar.gz`;
    const url        = `https://github.com/luoyueliang/net-tools/releases/download/smartxray-v${ctlVer}/${assetName}`;
    const tmpTar     = path.join(os.tmpdir(), assetName);
    const tmpExtract = path.join(os.tmpdir(), `xray-ctl-bundle-${ctlVer}`);

    info(`Downloading xray-ctl bundle v${ctlVer}...`);
    try {
      run(`curl -fsSL --max-time 60 -o "${tmpTar}" "${url}"`);
      fs.mkdirSync(tmpExtract, { recursive: true });
      run(`tar xzf "${tmpTar}" -C "${tmpExtract}"`);
      try { fs.unlinkSync(tmpTar); } catch {}
      bundleSrc = tmpExtract;
    } catch (e) {
      warn(`GitHub Release download failed: ${e.message}`);
    }
  } else {
    warn('GitHub 上未找到 smartxray release，使用本地 bundle/');
  }

  // 3. 回退：使用安装包内的本地 bundle/
  if (!bundleSrc) {
    const localBundle = path.join(REPO_ROOT, 'bundle');
    if (fs.existsSync(path.join(localBundle, 'index.js'))) {
      info('Using local bundle/ from installer package');
      bundleSrc = localBundle;
    } else {
      // 最终回退：旧版 src/xray-ctl 脚本（legacy）
      warn('未找到 bundle 来源，回退到 legacy src/xray-ctl 脚本模式...');
      try {
        const legacySrc = path.join(REPO_ROOT, 'src', 'xray-ctl');
        execSync(`${sudoPrefix()}cp "${legacySrc}" "${CTL_BIN}" && ${sudoPrefix()}chmod 755 "${CTL_BIN}"`, { stdio: 'pipe' });
        success(`xray-ctl installed to ${CTL_BIN} (legacy mode)`);
      } catch {
        const local = path.join(HOME, '.local/bin/xray-ctl');
        fs.mkdirSync(path.dirname(local), { recursive: true });
        fs.copyFileSync(path.join(REPO_ROOT, 'src', 'xray-ctl'), local);
        fs.chmodSync(local, 0o755);
        success(`xray-ctl installed to ${local} (legacy mode, no sudo)`);
      }
      return;
    }
  }

  // 4. 安装 bundle 到 /usr/local/lib/smartxray/
  run(`${sudoPrefix()}mkdir -p "${LIB_DIR}"`);
  // 复制 bundle 文件，排除 macOS 资源分支文件 (._*)
  run(`${sudoPrefix()}sh -c 'cd "${bundleSrc}" && for f in *; do case "$f" in .*) ;; *) cp -r "$f" "${LIB_DIR}/" ;; esac; done'`);

  // 5. 创建 shim 脚本 /usr/local/bin/xray-ctl
  const shimContent = `#!/bin/sh\nexec node "${LIB_DIR}/index.js" "$@"\n`;
  const tmpShim = path.join(os.tmpdir(), 'xray-ctl-shim');
  fs.writeFileSync(tmpShim, shimContent);
  run(`${sudoPrefix()}install -m 755 "${tmpShim}" "${CTL_BIN}"`);
  try { fs.unlinkSync(tmpShim); } catch {}

  // 6. 清理临时解压目录
  if (bundleSrc !== path.join(REPO_ROOT, 'bundle') && bundleSrc.startsWith(os.tmpdir())) {
    try { fs.rmSync(bundleSrc, { recursive: true, force: true }); } catch {}
  }

  success(`xray-ctl bundle installed to ${LIB_DIR}`);
  success(`xray-ctl shim installed to ${CTL_BIN}`);
}

// ── Step 7: Install Web UI ────────────────────────────────────────
function installUi() {
  const srcDir = path.join(REPO_ROOT, 'ui');
  if (!fs.existsSync(srcDir)) { warn('ui/ not found, skipping Web UI install'); return; }
  // UI 随 bundle 一起安装在 /usr/local/lib/smartxray/ui/
  const uiDst = path.join(LIB_DIR, 'ui');
  run(`${sudoPrefix()}mkdir -p "${uiDst}"`);
  for (const f of fs.readdirSync(srcDir)) {
    run(`${sudoPrefix()}cp -r "${path.join(srcDir, f)}" "${uiDst}/"`);
  }
  success(`Web UI installed to ${uiDst}`);
  info(`Access: http://127.0.0.1:2088/  (after xray-ctl start)`);
}

// ── Main ──────────────────────────────────────────────────────────
async function main() {
  const noDownload = process.argv.includes('--no-download');

  console.log('\n' + c.bold('='.repeat(50)));
  console.log(c.bold('  smartxray installer'));
  console.log(c.bold(`  Platform: ${PLATFORM} / ${ARCH}`));
  console.log(c.bold('='.repeat(50)) + '\n');

  checkNode();
  await promptProxy();
  installDeps();
  if (!noDownload) await installXray();
  createDirs();
  installStartup();
  await installCtl();
  installUi();

  console.log('\n' + c.bold('='.repeat(50)));
  success('Installation complete!');
  console.log(c.dim('\n  Quick start:'));
  console.log(c.dim('    xray-ctl start                   启动 Xray'));
  console.log(c.dim('    xray-ctl user add alice           创建用户（自动分配端口）'));
  console.log(c.dim('    xray-ctl reality init             初始化 VLESS+Reality'));
  console.log(c.dim('    xray-ctl status                  查看状态'));
  console.log(c.dim('    xray-ctl export                  导出 mihomo proxies 配置'));
  console.log(c.bold('='.repeat(50)));
}

main().catch(e => { error(e.message); });
