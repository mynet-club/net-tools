#!/usr/bin/env node
// release.js — 混淆打包 xray-ctl 发行版
// 用法:
//   node scripts/release.js              本地构建（生成 dist/*.gz）
//   node scripts/release.js --publish    构建 + 发布到 GitHub Release（需 gh CLI 已登录）
//
// 输出: dist/xray-ctl-{ver}.gz                    (自升级用)
//       dist/smartxray-installer-{ver}.tar.gz     (安装用)
//
// 依赖: javascript-obfuscator（npm install 自动安装）
// 步骤:
//   1. ncc bundle → dist/bundle/
//   2. javascript-obfuscator: 字符串数组 base64 编码 + hex 变量名混淆
//   3. 输出 dist/xray-ctl（混淆版），再打包为发行包

'use strict';

const JavaScriptObfuscator = require('javascript-obfuscator');
const { execSync } = require('child_process');
const zlib = require('zlib');
const fs   = require('fs');
const path = require('path');
const os   = require('os');

// ── 颜色 ─────────────────────────────────────────────────────────────────────
const c = {
  g: s => `\x1b[32m${s}\x1b[0m`,
  y: s => `\x1b[33m${s}\x1b[0m`,
  b: s => `\x1b[34m${s}\x1b[0m`,
  r: s => `\x1b[31m${s}\x1b[0m`,
};
const ok   = s => console.log(c.g('✓ ') + s);
const log  = s => console.log(c.b('» ') + s);
const warn = s => console.log(c.y('⚠ ') + s);
const die  = s => { console.error(c.r('✗ ') + s); process.exit(1); };

// ── 路径 ─────────────────────────────────────────────────────────────────────
const rootDir   = path.join(__dirname, '..');
const srcFile   = path.join(rootDir, 'src', 'xray-ctl');
const distDir   = path.join(rootDir, 'dist');
const bundleDir = path.join(distDir, 'bundle');  // ncc 输出目录

// ── CLI 参数 ──────────────────────────────────────────────────────────────────
const PUBLISH = process.argv.includes('--publish');

// ── 版本号（从 config.js 读取）─────────────────────────────────────────────────
function readVersion() {
  const configFile = path.join(rootDir, 'src', 'lib', 'config.js');
  if (fs.existsSync(configFile)) {
    const m = fs.readFileSync(configFile, 'utf8').match(/const VERSION\s*=\s*['"]([^'"]+)['"]/);
    if (m) return m[1];
  }
  // 回退：尝试从 src/xray-ctl 读取
  const m = fs.readFileSync(srcFile, 'utf8').match(/^const VERSION\s*=\s*['"]([^'"]+)['"]/m);
  return m ? m[1] : '0.0.0';
}
const VERSION = readVersion();

console.log();
console.log('─'.repeat(52));
log(`smartxray release.js — v${VERSION}`);
console.log('─'.repeat(52));

// ── Step 1: npm install（确保本地 deps 齐全）─────────────────────────────────
log('npm install (确保依赖就绪)...');
try {
  execSync('npm install', { cwd: rootDir, stdio: 'pipe' });
  ok('npm install done');
} catch (e) { die('npm install failed: ' + e.message); }

// ── Step 2: ncc bundle → dist/bundle/ ────────────────────────────────────────
fs.mkdirSync(distDir, { recursive: true });
if (fs.existsSync(bundleDir)) fs.rmSync(bundleDir, { recursive: true, force: true });

const nccBin = path.join(rootDir, 'node_modules', '.bin', 'ncc');
if (!fs.existsSync(nccBin)) die('找不到 ncc，请确认 @vercel/ncc 已安装 (npm install)');

// 只临时移走 xray-ctl.old 文件（lib/ 目录需要保留给 ncc 打包）
const srcOld    = path.join(rootDir, 'src', 'xray-ctl.old');
const srcOldBak = path.join(rootDir, 'src', '_xray-ctl.old.bak');
const hasOld = fs.existsSync(srcOld);
if (hasOld) fs.renameSync(srcOld, srcOldBak);

log('ncc build → dist/bundle/ ...');
try {
  execSync(`"${nccBin}" build "${srcFile}" -o "${bundleDir}" --no-cache -q`, {
    cwd: rootDir, stdio: 'pipe',
  });
} catch (e) {
  // 恢复临时移走的文件
  if (hasOld && fs.existsSync(srcOldBak)) fs.renameSync(srcOldBak, srcOld);
  die('ncc build 失败: ' + (e.stderr?.toString() || e.message));
} finally {
  if (hasOld && fs.existsSync(srcOldBak)) fs.renameSync(srcOldBak, srcOld);
}

const bundleFiles = fs.readdirSync(bundleDir);
let totalKB = 0;
for (const f of bundleFiles) {
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
  ok(`  bundle/node-sqlite3-wasm.wasm  (${wasmKB.toFixed(0)} KB)  [copied from node_modules]`);
} else {
  console.error('⚠ node-sqlite3-wasm.wasm not found — SQLite will fail at runtime!');
}

ok(`ncc bundle 完成 — 共 ${totalKB.toFixed(0)} KB`);

// ── Step 3: 混淆 bundle/index.js ─────────────────────────────────────────────
const bundleIndex = path.join(bundleDir, 'index.js');
if (fs.existsSync(bundleIndex)) {
  log('混淆中（javascript-obfuscator）...');
  let src = fs.readFileSync(bundleIndex, 'utf8');
  
  // 剥离 shebang（obfuscator 不接受 shebang）
  const shebang = '#!/usr/bin/env node\n';
  if (src.startsWith('#!')) src = src.slice(src.indexOf('\n') + 1);
  
  let obfuscated;
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
    obfuscated = shebang + result.getObfuscatedCode() + '\n';
  } catch (e) {
    die(`混淆失败: ${e.message}`);
  }
  
  fs.writeFileSync(bundleIndex, obfuscated, 'utf8');
  ok('混淆完成');
} else {
  warn('bundle/index.js 不存在，跳过混淆');
}

// ── Step 4: xray-ctl-bundle-{ver}.tar.gz（独立 bundle 包，供直接部署）────────
const BUNDLE_TAR = path.join(distDir, `xray-ctl-bundle-${VERSION}.tar.gz`);
if (fs.existsSync(BUNDLE_TAR)) fs.rmSync(BUNDLE_TAR, { force: true });
execSync(`COPYFILE_DISABLE=1 tar czf "${BUNDLE_TAR}" -C "${bundleDir}" .`, { stdio: 'pipe' });
ok(`${path.basename(BUNDLE_TAR)}  (${(fs.statSync(BUNDLE_TAR).size / 1024).toFixed(0)} KB gz)   ← 部署用`);

// ── Step 5: installer tar.gz（含 bundle/ + scripts/ + config/ + ui/）──────────
const installerName = `smartxray-installer-${VERSION}`;
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

// scripts/（排除 release.js 本身）、config/、ui/、bundle/（ncc 打包结果）
copyDir(path.join(rootDir, 'scripts'), path.join(pkgDir, 'scripts'), ['release.js']);
copyDir(path.join(rootDir, 'config'),  path.join(pkgDir, 'config'));
if (fs.existsSync(path.join(rootDir, 'ui'))) {
  copyDir(path.join(rootDir, 'ui'), path.join(pkgDir, 'ui'));
}
// bundle/ 替代原来的 src/ + package.json（install.js 会从 bundle/ 安装）
copyDir(bundleDir, path.join(pkgDir, 'bundle'));

if (fs.existsSync(installerTar)) fs.rmSync(installerTar, { force: true });
execSync(
  `COPYFILE_DISABLE=1 tar czf "${installerTar}" -C "${path.join(distDir, '_pkg')}" "${installerName}"`,
  { stdio: 'pipe' }
);
fs.rmSync(path.join(distDir, '_pkg'), { recursive: true, force: true });

const tarKB = (fs.statSync(installerTar).size / 1024).toFixed(0);
ok(`${path.basename(installerTar)}  (${tarKB} KB)   ← 安装用`);

// ── Step 6: manifest ──────────────────────────────────────────────────────────
const manifest = {
  version:    VERSION,
  built_at:   new Date().toISOString(),
  bundle_tar: path.basename(BUNDLE_TAR),
  installer:  path.basename(installerTar),
};
fs.writeFileSync(path.join(distDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

// ── Step 7: 可选发布到 GitHub Release ─────────────────────────────────────────
if (PUBLISH) {
  console.log();
  log('发布到 GitHub Release...');
  const tag = `smartxray-v${VERSION}`;

  try { execSync('gh --version', { stdio: 'pipe' }); }
  catch { die('gh CLI 未安装，请先安装 GitHub CLI: https://cli.github.com'); }

  try {
    execSync(
      `gh release create "${tag}" --title "smartxray v${VERSION}" --generate-notes --repo luoyueliang/net-tools`,
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
    `gh release upload "${tag}" "${installerTar}" "${BUNDLE_TAR}" --clobber --repo luoyueliang/net-tools`,
    { stdio: 'inherit' }
  );
  ok(`已上传: ${path.basename(installerTar)}, ${path.basename(BUNDLE_TAR)}`);
}

// ── 完成 ──────────────────────────────────────────────────────────────────────
console.log();
console.log('─'.repeat(52));
ok(`dist/${path.basename(BUNDLE_TAR)}   ← bundle（自升级用）`);
ok(`dist/${path.basename(installerTar)}  (${tarKB} KB)   ← 安装用`);
if (!PUBLISH) {
  console.log(c.y(`发布: node scripts/release.js --publish`));
  console.log(c.b(`或由 GitHub Actions 在 tag push 后自动构建`));
}
console.log();
console.log(`安装验证: ${c.b(`tar xzf dist/${path.basename(installerTar)} && ls ${installerName}/`)}`);
