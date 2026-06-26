/**
 * 用户管理路由
 * GET    /api/users       — 列出所有用户
 * POST   /api/users       — 创建用户
 * POST   /api/users/batch — 批量创建用户
 * GET    /api/users/:id   — 获取单个用户
 * PUT    /api/users/:id   — 更新用户
 * DELETE /api/users/:id   — 删除用户
 */

'use strict';

const { apiResponse, parseBody, sanitizeUsername } = require('../utils');
const {
  getUsers,
  getUserById,
  createUser,
  updateUser,
  updateUserPassword,
  updateUserRole,
  deleteUser,
  batchCreateUsers,
} = require('../db');

/**
 * GET /api/users
 */
function handleList(req, res) {
  const users = getUsers();
  // 过滤掉 password_hash
  const safeUsers = users.map(({ password_hash, ...u }) => u);
  return apiResponse(res, 200, safeUsers);
}

/**
 * POST /api/users
 * body: { name, username, password, note, role }
 */
async function handleCreate(req, res, json) {
  if (!json.name || typeof json.name !== 'string' || json.name.length > 100) {
    return apiResponse(res, 400, { error: '缺少 name 或名称过长（最大 100 字符）' });
  }
  const username = sanitizeUsername(json.username);
  if (!username || username.length < 3 || username.length > 50) {
    return apiResponse(res, 400, { error: '用户名长度需在 3-50 之间' });
  }
  if (!json.password || typeof json.password !== 'string' || json.password.length < 6 || json.password.length > 200) {
    return apiResponse(res, 400, { error: '密码长度需在 6-200 之间' });
  }
  if (json.role && !['admin', 'user'].includes(json.role)) {
    return apiResponse(res, 400, { error: 'role 只能为 admin 或 user' });
  }
  try {
    const user = createUser({
      name: json.name,
      username,
      password: json.password,
      note: json.note || '',
      role: json.role || 'user',
    });
    // 不返回 password_hash
    const { password_hash, ...safeUser } = user;
    return apiResponse(res, 201, safeUser);
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      return apiResponse(res, 409, { error: '用户名已存在' });
    }
    return apiResponse(res, 400, { error: e.message });
  }
}

/**
 * POST /api/users/batch
 * body: { users: [{ name, username, password, note, role }] }
 */
async function handleBatchCreate(req, res, json) {
  if (!Array.isArray(json.users) || json.users.length === 0) {
    return apiResponse(res, 400, { error: '缺少 users 数组' });
  }
  const results = batchCreateUsers(json.users);
  const ok = results.filter(r => r.ok).length;
  const fail = results.filter(r => !r.ok).length;
  return apiResponse(res, 201, { created: ok, failed: fail, results });
}

/**
 * GET /api/users/:id
 */
function handleGet(req, res, id) {
  const user = getUserById(id);
  if (!user) {
    return apiResponse(res, 404, { error: '用户不存在' });
  }
  const { password_hash, ...safeUser } = user;
  return apiResponse(res, 200, safeUser);
}

/**
 * PUT /api/users/:id
 * body: { name, note, enabled, username, role, password }
 */
async function handleUpdate(req, res, id, json) {
  const user = getUserById(id);
  if (!user) {
    return apiResponse(res, 404, { error: '用户不存在' });
  }
  try {
    // 如果提供了 password，单独处理密码更新
    if (json.password) {
      if (typeof json.password !== 'string' || json.password.length < 6 || json.password.length > 200) {
        return apiResponse(res, 400, { error: '密码长度需在 6-200 之间' });
      }
      updateUserPassword(id, json.password);
    }
    // 如果提供了 role，单独处理角色更新
    if (json.role) {
      if (!['admin', 'user'].includes(json.role)) {
        return apiResponse(res, 400, { error: 'role 只能为 admin 或 user' });
      }
      updateUserRole(id, json.role);
    }
    // 更新其他字段
    const fields = {};
    if (json.name !== undefined) fields.name = json.name;
    if (json.note !== undefined) fields.note = json.note;
    if (json.enabled !== undefined) fields.enabled = json.enabled;
    if (json.username !== undefined) {
      const cleanUsername = sanitizeUsername(json.username);
      if (cleanUsername.length < 3 || cleanUsername.length > 50) {
        return apiResponse(res, 400, { error: '用户名长度需在 3-50 之间' });
      }
      fields.username = cleanUsername;
    }
    const updated = updateUser(id, fields);
    const { password_hash, ...safeUser } = updated;
    return apiResponse(res, 200, safeUser);
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      return apiResponse(res, 409, { error: '用户名已存在' });
    }
    return apiResponse(res, 400, { error: e.message });
  }
}

/**
 * DELETE /api/users/:id
 */
function handleDelete(req, res, id) {
  const user = getUserById(id);
  if (!user) {
    return apiResponse(res, 404, { error: '用户不存在' });
  }
  deleteUser(id);
  return apiResponse(res, 200, { ok: true });
}

module.exports = {
  handleList,
  handleCreate,
  handleBatchCreate,
  handleGet,
  handleUpdate,
  handleDelete,
};
