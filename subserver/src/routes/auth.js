/**
 * 认证路由
 * POST /api/auth/login           — 用户登录（用户名 + 密码）
 * POST /api/auth/logout          — 登出
 * GET  /api/auth/me              — 获取当前用户信息
 * POST /api/auth/forgot-password — 忘记密码（发送重置邮件）
 * POST /api/auth/reset-password  — 重置密码（凭令牌设置新密码）
 */

'use strict';

const { apiResponse, sanitizeUsername } = require('../utils');
const {
  getUserByName,
  getUserByEmail,
  verifyPassword,
  createSession,
  deleteSession,
  updateUserPassword,
  createEmailToken,
  getEmailToken,
  useEmailToken,
} = require('../db');
const { getSessionUser } = require('../auth');
const {
  sendResetEmail,
  isMailEnabled,
  getBaseUrl,
} = require('../mailer');

/**
 * POST /api/auth/login
 * body: { username, password }
 */
async function handleLogin(req, res, json) {
  const username = sanitizeUsername(json.username);
  const password = json.password;
  if (!username) {
    return apiResponse(res, 400, { error: '缺少用户名' });
  }
  if (!password || typeof password !== 'string') {
    return apiResponse(res, 400, { error: '缺少密码' });
  }
  if (username.length > 50 || password.length > 200) {
    return apiResponse(res, 400, { error: '用户名或密码过长' });
  }

  const user = getUserByName(username);
  if (!user || !user.password_hash) {
    return apiResponse(res, 401, { error: '用户名或密码错误' });
  }
  if (!user.enabled) {
    return apiResponse(res, 403, { error: '用户已禁用' });
  }

  if (!verifyPassword(json.password, user.password_hash)) {
    return apiResponse(res, 401, { error: '用户名或密码错误' });
  }

  // 邮箱未验证则拒绝登录
  if (user.email && !user.email_verified) {
    return apiResponse(res, 403, { error: '邮箱未验证，请检查邮箱完成激活' });
  }

  // 创建会话
  const sessionToken = createSession(user);

  return apiResponse(res, 200, {
    token: sessionToken,
    user: {
      id: user.id,
      username: user.username,
      role: user.role || 'user',
      name: user.name,
    },
  });
}

/**
 * POST /api/auth/logout
 */
function handleLogout(req, res) {
  const auth = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (auth) {
    deleteSession(auth);
  }
  return apiResponse(res, 200, { ok: true });
}

/**
 * GET /api/auth/me
 */
function handleMe(req, res) {
  const user = getSessionUser(req);
  if (!user) {
    return apiResponse(res, 401, { error: '未认证' });
  }
  return apiResponse(res, 200, user);
}

/**
 * POST /api/auth/forgot-password
 * body: { email }
 * 无论邮箱是否存在都返回相同消息，防止枚举攻击
 */
async function handleForgotPassword(req, res, json) {
  const { email } = json;
  if (!email || typeof email !== 'string') {
    return apiResponse(res, 400, { error: '请输入邮箱地址' });
  }

  if (!isMailEnabled()) {
    return apiResponse(res, 503, { error: '邮件服务未配置，请联系管理员' });
  }

  const user = getUserByEmail(email.toLowerCase().trim());
  if (user && user.enabled && user.username) {
    try {
      const tokenRow = createEmailToken(user.id, 'reset', 1); // 1 小时有效
      const resetUrl = `${getBaseUrl()}/reset-password?token=${tokenRow.token}`;
      await sendResetEmail(user.email, resetUrl, user.username);
    } catch (e) {
      console.error('重置邮件发送失败:', e.message);
    }
  }

  // 统一返回，不暴露邮箱是否存在
  return apiResponse(res, 200, {
    ok: true,
    message: '如果该邮箱已注册，重置密码邮件已发送',
  });
}

/**
 * POST /api/auth/reset-password
 * body: { token, password }
 */
function handleResetPassword(req, res, json) {
  const { token, password } = json;
  if (!token || typeof token !== 'string') {
    return apiResponse(res, 400, { error: '缺少重置令牌' });
  }
  if (!password || typeof password !== 'string' || password.length < 6 || password.length > 200) {
    return apiResponse(res, 400, { error: '密码长度需在 6-200 之间' });
  }

  const tokenRow = getEmailToken(token);
  if (!tokenRow || tokenRow.type !== 'reset') {
    return apiResponse(res, 400, { error: '重置链接无效或已过期' });
  }

  // 使用令牌
  useEmailToken(token);

  // 更新密码
  updateUserPassword(tokenRow.user_id, password);

  return apiResponse(res, 200, {
    ok: true,
    message: '密码重置成功，请登录',
  });
}

module.exports = {
  handleLogin,
  handleLogout,
  handleMe,
  handleForgotPassword,
  handleResetPassword,
};
