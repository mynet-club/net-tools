#!/usr/bin/env node
// release.js — 混淆打包 subserver 发行版
// 用法:
//   node scripts/release.js              本地构建（生成 dist/*.gz）
//   node scripts/release.js --publish    构建 + 发布到 GitHub Release（需 gh CLI 已登录）
//
// 输出: dist/subserver-bundle-{ver}.tar.gz      (部署用)
//       dist/subserver-installer-{ver}.tar.gz   (安装用)
//
// 依赖: @vercel/ncc, javascript-obfuscator（npm install 自动安装）
// 步骤:
//   1. ncc bundle → dist/bundle/
//   2. 手动复制 .wasm 文件
//   3. javascript-obfuscator 混淆
//   4. 打包为发行包

'use strict';

const JavaScriptObfuscator = require('javascript-obfuscator');
const { execSync } = require('child_process');
const fs   = require('fs');
const path = require('path');

// ── 颜色 ─────────────────────────────────────────────────────────
const c = {
  g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`,
  b: s => `\x1b[34m${s}\x1b[0m`,
  r: s => `\x1b[31m${s}\x1b[0m`,
};
const ok  = s => console.log(c.g('✓ ') + s);
const log = s => console.log(c.b('» ') + s);
const die = s => { console.error(c.r('✗ ') + s); process.exit(1); };

// ── 路径 ─────────────────────────────────────────────────────────
const rootDir   = path.join(__dirname, '..');
const srcFile   = path.join(rootDir, 'src', 'server.js');
const distDir   = path.join(rootDir, 'dist');
const bundleDir = path.join(distDir, 'bundle');

// GitHub 仓库（发布 Release 用，按需修改）
const REPO = 'your-org/net-tools';

// ── CLI 参数 ─────────────────────────────────────────────────────
const PUBLISH = process.argv.includes('--publish');

// ── 版本号 ───────────────────────────────────────────────────────
function readVersion() {
  const pkgPath = path.join(rootDir, 'package.json');
  const m = fs.readFileSync(pkgPath, 'utf8').match(/"version"\s*:\s*"([^"]+)"/);
  return m ? m[1] : '0.0.0';
}
const VERSION = readVersion();

console.log();
console.log('─'.repeat(52));
log(`subserver release.js — v${VERSION}`);
console.log('─'.repeat(52));

// ── Step 1: npm install ──────────────────────────────────────────
log('npm install (确保依赖就绪)...');
try {
  execSync('npm install', { cwd: rootDir, stdio: 'pipe' });
  ok('npm install done');
} catch (e) { die('npm install failed: ' + e.message); }

// ── Step 2: ncc bundle → dist/bundle/ ────────────────────────────
fs.mkdirSync(distDir, { recursive: true });
if (fs.existsSync(bundleDir)) fs.rmSync(bundleDir, { recursive: true, force: true });

const nccBin = path.join(rootDir, 'node_modules', '.bin', 'ncc');
if (!fs.existsSync(nccBin)) die('找不到 ncc，请确认 @vercel/ncc 已安装 (npm install)');

log('ncc build → dist/bundle/ ...');
try {
  execSync(`"${nccBin}" build "${srcFile}" -o "${bundleDir}" --no-cache -q`, {
    cwd: rootDir, stdio: 'pipe',
  });
} catch (e) {
  die('ncc build 失败: ' + (e.stderr?.toString() || e.message));
}

let totalKB = 0;
for (const f of fs.readdirSync(bundleDir)) {
  const s = fs.statSync(path.join(bundleDir, f)).size;
  totalKB += s / 1024;
  ok(`  bundle/${f}  (${(s / 1024).toFixed(0)} KB)`);
}

// ncc 不会自动复制 .wasm 文件，需手动补齐
const wasmSrc = path.join(rootDir, 'node_modules', 'node-sqlite3-wasm', 'dist', 'node-sqlite3-wasm.wasm');
if (fs.existsSync(wasmSrc)) {
  const wasmDst = path.join(bundleDir, 'node-sqlite3-wasm.wasm');
  fs.copyFileSync(wasmSrc, wasmDst);
  const wasmKB = fs.statSync(wasmDst).size / 1024;
  totalKB += wasmKB;
  ok(`  bundle/node-sqlite3-wasm.wasm  (${wasmKB.toFixed(0)} KB)  [copied]`);
} else {
  console.error('⚠ node-sqlite3-wasm.wasm not found — SQLite will fail at runtime!');
}

// 复制 UI 文件到 bundle 目录（bundle 模式下从 __dirname/ui 加载）
const uiSrc = path.join(rootDir, 'ui');
if (fs.existsSync(uiSrc)) {
  const uiDst = path.join(bundleDir, 'ui');
  fs.mkdirSync(uiDst, { recursive: true });
  for (const f of fs.readdirSync(uiSrc)) {
    const s = path.join(uiSrc, f);
    const d = path.join(uiDst, f);
    if (fs.statSync(s).isFile()) {
      fs.copyFileSync(s, d);
      const fKB = (fs.statSync(d).size / 1024).toFixed(0);
      ok(`  bundle/ui/${f}  (${fKB} KB)  [copied]`);
      totalKB += parseFloat(fKB);
    }
  }
} else {
  console.error('⚠ ui/ 目录不存在 — 部署后前端页面不可用!');
}

ok(`ncc bundle 完成 — 共 ${totalKB.toFixed(0)} KB`);

// ── Step 3: 混淆 bundle/index.js ─────────────────────────────────
const bundleIndex = path.join(bundleDir, 'index.js');
if (fs.existsSync(bundleIndex)) {
  log('混淆中（javascript-obfuscator）...');
  let src = fs.readFileSync(bundleIndex, 'utf8');

  // 剥离 shebang
  const shebang = '#!/usr/bin/env node\n';
  if (src.startsWith('#!')) src = src.slice(src.indexOf('\n') + 1);

  try {
    const result = JavaScriptObfuscator.obfuscate(src, {
      compact: true,
      stringArray: true,
      stringArrayEncoding: ['base64'],
      stringArrayThreshold: 0.85,
      stringArrayRotate: true,
      stringArrayShuffle: true,
      splitStrings: false,
      identifierNamesGenerator: 'hexadecimal',
      renameGlobals: false,
      renameProperties: false,
      numbersToExpressions: true,
      simplify: true,
      controlFlowFlattening: false,
      deadCodeInjection: false,
      selfDefending: false,
      debugProtection: false,
      transformObjectKeys: false,
      disableConsoleOutput: false,
    });
    fs.writeFileSync(bundleIndex, shebang + result.getObfuscatedCode() + '\n', 'utf8');
    ok('混淆完成');
  } catch (e) {
    die(`混淆失败: ${e.message}`);
  }
}

// ── Step 4: bundle tar.gz（部署用）──────────────────────────────
const BUNDLE_TAR = path.join(distDir, `subserver-bundle-${VERSION}.tar.gz`);
if (fs.existsSync(BUNDLE_TAR)) fs.rmSync(BUNDLE_TAR, { force: true });
execSync(`COPYFILE_DISABLE=1 tar czf "${BUNDLE_TAR}" -C "${bundleDir}" .`, { stdio: 'pipe' });
ok(`${path.basename(BUNDLE_TAR)}  (${(fs.statSync(BUNDLE_TAR).size / 1024).toFixed(0)} KB)  ← 部署用`);

// ── Step 5: installer tar.gz（含 bundle/ + scripts/ + config/）──
const installerName = `subserver-installer-${VERSION}`;
const installerTar  = path.join(distDir, `${installerName}.tar.gz`);
const pkgDir        = path.join(distDir, '_pkg', installerName);

log(`构建 installer: ${path.basename(installerTar)}`);

if (fs.existsSync(path.join(distDir, '_pkg'))) {
  fs.rmSync(path.join(distDir, '_pkg'), { recursive: true, force: true });
}

function copyDir(src, dst, exclude = []) {
  fs.mkdirSync(dst, { recursive: true });
  for (const f of fs.readdirSync(src)) {
    if (exclude.includes(f)) continue;
    const s = path.join(src, f);
    const d = path.join(dst, f);
    if (fs.statSync(s).isDirectory()) copyDir(s, d, exclude);
    else fs.copyFileSync(s, d);
  }
}

copyDir(path.join(rootDir, 'scripts'), path.join(pkgDir, 'scripts'), ['release.js']);
copyDir(path.join(rootDir, 'config'),  path.join(pkgDir, 'config'));
copyDir(bundleDir, path.join(pkgDir, 'bundle'));

if (fs.existsSync(installerTar)) fs.rmSync(installerTar, { force: true });
execSync(
  `COPYFILE_DISABLE=1 tar czf "${installerTar}" -C "${path.join(distDir, '_pkg')}" "${installerName}"`,
  { stdio: 'pipe' }
);
fs.rmSync(path.join(distDir, '_pkg'), { recursive: true, force: true });

const tarKB = (fs.statSync(installerTar).size / 1024).toFixed(0);
ok(`${path.basename(installerTar)}  (${tarKB} KB)  ← 安装用`);

// ── Step 6: manifest ─────────────────────────────────────────────
const manifest = {
  version:    VERSION,
  built_at:   new Date().toISOString(),
  bundle_tar: path.basename(BUNDLE_TAR),
  installer:  path.basename(installerTar),
};
fs.writeFileSync(path.join(distDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

// ── Step 7: 可选发布 ─────────────────────────────────────────────
if (PUBLISH) {
  console.log();
  log('发布到 GitHub Release...');
  const tag = `subserver-v${VERSION}`;

  try { execSync('gh --version', { stdio: 'pipe' }); }
  catch { die('gh CLI 未安装，请先安装 GitHub CLI: https://cli.github.com'); }

  try {
    execSync(
      `gh release create "${tag}" --title "subserver v${VERSION}" --generate-notes --repo ${REPO}`,
      { stdio: 'pipe' }
    );
    ok(`Release ${tag} 已创建`);
  } catch (e) {
    if (e.message && e.message.includes('already exists')) {
      console.log(c.y(`⚠ Release ${tag} 已存在，直接上传资产`));
    } else {
      die(`创建 Release 失败: ${e.message}`);
    }
  }

  execSync(
    `gh release upload "${tag}" "${installerTar}" "${BUNDLE_TAR}" --clobber --repo ${REPO}`,
    { stdio: 'inherit' }
  );
  ok(`已上传: ${path.basename(installerTar)}, ${path.basename(BUNDLE_TAR)}`);
}

// ── 完成 ─────────────────────────────────────────────────────────
console.log();
console.log('─'.repeat(52));
ok(`dist/${path.basename(BUNDLE_TAR)}   ← bundle（部署用）`);
ok(`dist/${path.basename(installerTar)}  (${tarKB} KB)   ← 安装用`);
if (!PUBLISH) {
  console.log(c.y(`发布: node scripts/release.js --publish`));
}
console.log();
