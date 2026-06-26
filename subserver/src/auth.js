/**
 * 认证中间件
 * - 会话认证：用户登录后获得 session token，用于 API 访问
 * - Admin Token：向后兼容 CLI/脚本场景
 */

'use strict';

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const { getBaseDir } = require('./paths');
const { getSession } = require('./db');

// ── 配置加载 ────────────────────────────────────────────────────
// 优先级: 环境变量 > ~/.config/subserver/config.json (运行时) > config/local.json > config/default.json
function loadConfig() {
  const baseDir    = getBaseDir();
  const runtimeCfg = path.join(baseDir, 'config.json');          // 运行时配置（install.js 生成）
  const devDir     = path.join(__dirname, '..', 'config');
  const defaultPath = path.join(devDir, 'default.json');
  const localPath   = path.join(devDir, 'local.json');

  let cfg = {};
  // 1. 开发模式默认配置
  try {
    if (fs.existsSync(defaultPath)) {
      cfg = { ...cfg, ...JSON.parse(fs.readFileSync(defaultPath, 'utf8')) };
    }
  } catch (e) {
    console.error(`[config] 读取 default.json 失败: ${e.message}`);
  }
  // 2. 开发模式本地覆盖
  try {
    if (fs.existsSync(localPath)) {
      cfg = { ...cfg, ...JSON.parse(fs.readFileSync(localPath, 'utf8')) };
    }
  } catch (e) {
    console.error(`[config] 读取 local.json 失败: ${e.message}`);
  }
  // 3. 运行时配置（bundle 模式或 install.js 生成）
  try {
    if (fs.existsSync(runtimeCfg)) {
      cfg = { ...cfg, ...JSON.parse(fs.readFileSync(runtimeCfg, 'utf8')) };
    }
  } catch (e) {
    console.error(`[config] 读取运行时配置失败: ${e.message}`);
  }

  // 环境变量覆盖
  if (process.env.SUBSERVER_PORT)       cfg.port = parseInt(process.env.SUBSERVER_PORT);
  if (process.env.SUBSERVER_HOST)       cfg.host = process.env.SUBSERVER_HOST;
  if (process.env.SUBSERVER_ADMIN_TOKEN) cfg.adminToken = process.env.SUBSERVER_ADMIN_TOKEN;
  if (process.env.SUBSERVER_DB_PATH)    cfg.dbPath = process.env.SUBSERVER_DB_PATH;
  if (process.env.SUBSERVER_BASE_URL)   cfg.baseUrl = process.env.SUBSERVER_BASE_URL;
  if (process.env.SUBSERVER_SMTP_HOST) {
    cfg.smtp = cfg.smtp || {};
    cfg.smtp.host = process.env.SUBSERVER_SMTP_HOST;
  }
  if (process.env.SUBSERVER_SMTP_PORT) {
    cfg.smtp = cfg.smtp || {};
    cfg.smtp.port = parseInt(process.env.SUBSERVER_SMTP_PORT);
  }
  if (process.env.SUBSERVER_SMTP_USER) {
    cfg.smtp = cfg.smtp || {};
    cfg.smtp.auth = cfg.smtp.auth || {};
    cfg.smtp.auth.user = process.env.SUBSERVER_SMTP_USER;
  }
  if (process.env.SUBSERVER_SMTP_PASS) {
    cfg.smtp = cfg.smtp || {};
    cfg.smtp.auth = cfg.smtp.auth || {};
    cfg.smtp.auth.pass = process.env.SUBSERVER_SMTP_PASS;
  }
  if (process.env.SUBSERVER_SMTP_FROM) {
    cfg.smtp = cfg.smtp || {};
    cfg.smtp.fromEmail = process.env.SUBSERVER_SMTP_FROM;
  }

  // 默认值
  cfg.port       = cfg.port || 3456;
  cfg.host       = cfg.host || '127.0.0.1';
  cfg.adminToken = cfg.adminToken || '';
  cfg.dbPath     = cfg.dbPath || 'data/subserver.db';
  cfg.baseUrl    = cfg.baseUrl || '';
  cfg.smtp       = cfg.smtp || {};

  return cfg;
}

const config = loadConfig();

/**
 * 从请求头提取 Bearer token
 * @param {Object} req — HTTP 请求对象
 * @returns {string|null}
 */
function extractBearer(req) {
  const auth = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  return auth || null;
}

/**
 * 获取会话用户信息
 * @param {Object} req — HTTP 请求对象
 * @returns {Object|null} { id, username, role, name } 或 null
 */
function getSessionUser(req) {
  const token = extractBearer(req);
  if (!token) return null;
  const session = getSession(token);
  if (!session) return null;
  return {
    id: session.userId,
    username: session.username,
    role: session.role,
    name: session.name,
  };
}

/**
 * 验证 Admin Bearer token（时序安全比较）
 * 向后兼容 CLI/脚本场景
 * @param {Object} req — HTTP 请求对象
 * @returns {boolean} 是否认证通过
 */
function isAuthenticated(req) {
  // 未设置 adminToken 则不启用此认证
  if (!config.adminToken) return false;
  const auth = extractBearer(req);
  if (!auth) return false;
  // 时序安全比较，防止时序攻击
  try {
    const a = Buffer.from(auth);
    const b = Buffer.from(config.adminToken);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * 要求认证（会话或 Admin Token）
 * @param {Object} req — HTTP 请求对象
 * @returns {Object} { ok: true, user } 或 { ok: false, code, error }
 */
function requireAuth(req) {
  // 1. 尝试会话认证
  const user = getSessionUser(req);
  if (user) return { ok: true, user };
  // 2. 尝试 Admin Token（向后兼容）
  if (isAuthenticated(req)) {
    return { ok: true, user: { id: 0, username: 'admin-token', role: 'admin', name: 'Admin Token' } };
  }
  return { ok: false, code: 401, error: '未认证，请登录' };
}

/**
 * 要求管理员权限
 * @param {Object} req — HTTP 请求对象
 * @returns {Object} { ok: true, user } 或 { ok: false, code, error }
 */
function requireAdmin(req) {
  const auth = requireAuth(req);
  if (!auth.ok) return auth;
  if (auth.user.role !== 'admin') {
    return { ok: false, code: 403, error: '需要管理员权限' };
  }
  return auth;
}

module.exports = {
  config,
  isAuthenticated,
  getSessionUser,
  requireAuth,
  requireAdmin,
  loadConfig,
};
