/**
 * 配置管理模块
 * 封装路径常量、端口范围、工具函数等
 */

const path = require('path');
const fs   = require('fs');
const crypto = require('crypto');
const { execSync } = require('child_process');

// ==================== 路径常量 ====================

// 检测是否在 bundle 模式下运行（ncc 打包后 __dirname 会指向 bundle 目录）
function getBaseDir() {
  // 如果 __dirname 包含 /usr/local/lib/smartxray 或类似系统路径，说明是 bundle 模式
  // 此时使用 HOME 目录下的 .config/smartxray 作为基础目录
  const dir = __dirname;
  if (dir.includes('/usr/local/lib/') || dir.includes('\\AppData\\')) {
    const os = require('os');
    return path.join(os.homedir(), '.config', 'smartxray');
  }
  // 开发模式：向上两级到项目根目录
  return path.join(dir, '..', '..');
}

const BASE_DIR   = getBaseDir();
const DATA_DIR   = path.join(BASE_DIR, 'data');
const LOGS_DIR   = path.join(BASE_DIR, 'logs');
const UI_DIR     = path.join(BASE_DIR, 'ui');
const CONFIG_DIR = path.join(BASE_DIR, 'config');

const XRAY_CONF   = path.join(DATA_DIR, 'config.json');
const MIHOMO_OUT  = path.join(DATA_DIR, 'mihomo-proxies.yaml');
const PID_FILE    = path.join(DATA_DIR, 'xray.pid');
const LOG_FILE    = path.join(LOGS_DIR, 'xray.log');

// 确保目录存在
[DATA_DIR, LOGS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// 兼容旧版：config.json / xray.pid 曾直接放在 BASE_DIR
['config.json', 'xray.pid'].forEach(name => {
  const oldPath = path.join(BASE_DIR, name);
  const newPath = path.join(DATA_DIR, name);
  if (!fs.existsSync(newPath) && fs.existsSync(oldPath)) {
    try { fs.copyFileSync(oldPath, newPath); } catch {}
  }
});

// ==================== 版本和仓库 ====================

const VERSION = '3.0.3';
const GITHUB_REPO = 'luoyueliang/smartxray';
const API_PORT = 2088;

// ==================== 端口范围默认值 ====================

const DEFAULT_PORT_RANGES = {
  fixed_socks_min: 10000,
  fixed_socks_max: 19999,
  fixed_http_min:  20000,
  fixed_http_max:  29999,
  ss_socks_min:    30000,
  ss_socks_max:    39999,
  ss_http_min:     40000,
  ss_http_max:     49999
};

// ==================== 工具函数 ====================

/**
 * 执行 shell 命令
 * @param {string} cmd - 命令
 * @returns {string} 输出
 */
function run(cmd) {
  try {
    return execSync(cmd, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch {
    return '';
  }
}

/**
 * 生成随机字符串
 * @param {number} len - 长度
 * @returns {string}
 */
function randStr(len) {
  return crypto.randomBytes(Math.ceil(len * 0.75))
    .toString('base64')
    .replace(/[+/=]/g, '')
    .slice(0, len);
}

/**
 * 生成随机十六进制字符串
 * @param {number} len - 长度
 * @returns {string}
 */
function randHex(len) {
  return crypto.randomBytes(Math.ceil(len / 2)).toString('hex').slice(0, len);
}

/**
 * 生成 UUID v4
 * @returns {string}
 */
function newUUID() {
  return crypto.randomUUID();
}

/**
 * 获取服务器主机名/IP
 * @param {Function} getSetting - 配置获取函数
 * @returns {string}
 */
function getServerHost(getSetting) {
  return getSetting('public_host', '') || getSetting('server_ip', '') || '127.0.0.1';
}

/**
 * 获取固定端口范围
 * @param {Function} getSetting - 配置获取函数
 * @returns {Object}
 */
function getFixedPortRange(getSetting) {
  return {
    socksMin: parseInt(getSetting('port_fixed_socks_min', String(DEFAULT_PORT_RANGES.fixed_socks_min))) || DEFAULT_PORT_RANGES.fixed_socks_min,
    socksMax: parseInt(getSetting('port_fixed_socks_max', String(DEFAULT_PORT_RANGES.fixed_socks_max))) || DEFAULT_PORT_RANGES.fixed_socks_max,
    httpMin:  parseInt(getSetting('port_fixed_http_min', String(DEFAULT_PORT_RANGES.fixed_http_min))) || DEFAULT_PORT_RANGES.fixed_http_min,
    httpMax:  parseInt(getSetting('port_fixed_http_max', String(DEFAULT_PORT_RANGES.fixed_http_max))) || DEFAULT_PORT_RANGES.fixed_http_max
  };
}

/**
 * 获取自助端口范围
 * @param {Function} getSetting - 配置获取函数
 * @returns {Object}
 */
function getSsPortRange(getSetting) {
  return {
    socksMin: parseInt(getSetting('port_ss_socks_min', String(DEFAULT_PORT_RANGES.ss_socks_min))) || DEFAULT_PORT_RANGES.ss_socks_min,
    socksMax: parseInt(getSetting('port_ss_socks_max', String(DEFAULT_PORT_RANGES.ss_socks_max))) || DEFAULT_PORT_RANGES.ss_socks_max,
    httpMin:  parseInt(getSetting('port_ss_http_min', String(DEFAULT_PORT_RANGES.ss_http_min))) || DEFAULT_PORT_RANGES.ss_http_min,
    httpMax:  parseInt(getSetting('port_ss_http_max', String(DEFAULT_PORT_RANGES.ss_http_max))) || DEFAULT_PORT_RANGES.ss_http_max
  };
}

/**
 * 分配可用端口
 * @param {number} min - 最小端口
 * @param {number} max - 最大端口
 * @param {Function} db - 数据库函数
 * @returns {number}
 */
function allocPort(min, max, db) {
  const rows1 = db().prepare('SELECT port FROM users').all();
  const rows2 = db().prepare('SELECT http_port as port FROM users WHERE http_port IS NOT NULL').all();
  const used = new Set();
  for (const r of rows1) {
    if (r.port) used.add(r.port);
  }
  for (const r of rows2) {
    if (r.port) used.add(r.port);
  }
  for (let p = min; p <= max; p++) {
    if (!used.has(p)) return p;
  }
  throw new Error('端口区间已满');
}

/**
 * 检查端口是否可用
 * @param {number} port - 端口号
 * @returns {boolean}
 */
function isPortAvailable(port) {
  try {
    const result = run(`lsof -i :${port} -t`);
    return !result;
  } catch {
    return true;
  }
}

/**
 * 读取 PID 文件
 * @returns {number|null}
 */
function readPid() {
  try {
    return parseInt(fs.readFileSync(PID_FILE, 'utf8').trim());
  } catch {
    return null;
  }
}

/**
 * 写入 PID 文件
 * @param {number} pid - 进程 ID
 */
function writePid(pid) {
  fs.writeFileSync(PID_FILE, String(pid));
}

/**
 * 删除 PID 文件
 */
function removePid() {
  try { fs.unlinkSync(PID_FILE); } catch {}
}

/**
 * 检查进程是否运行
 * @returns {boolean}
 */
function isRunning() {
  const pid = readPid();
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

module.exports = {
  // 路径常量
  BASE_DIR,
  DATA_DIR,
  LOGS_DIR,
  UI_DIR,
  CONFIG_DIR,
  XRAY_CONF,
  MIHOMO_OUT,
  PID_FILE,
  LOG_FILE,

  // 版本和仓库
  VERSION,
  GITHUB_REPO,
  API_PORT,

  // 端口范围
  DEFAULT_PORT_RANGES,

  // 工具函数
  run,
  randStr,
  randHex,
  newUUID,
  getServerHost,
  getFixedPortRange,
  getSsPortRange,
  allocPort,
  isPortAvailable,
  readPid,
  writePid,
  removePid,
  isRunning
};