/**
 * 认证中间件
 * - 会话认证：用户登录后获得 session token，用于 API 访问
 * - Admin Token：向后兼容 CLI/脚本场景
 */

'use strict';

const crypto = require('crypto');

const { config } = require('./config');
const { getSession } = require('./db');

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
};
