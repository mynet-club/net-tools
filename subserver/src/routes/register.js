/**
 * 用户注册路由
 * POST /api/auth/register  — 公开接口，需邀请码 + 邮箱
 * GET  /api/auth/verify    — 公开接口，邮箱验证激活
 */

'use strict';

const { apiResponse, sanitizeUsername } = require('../utils');
const {
  getInviteCode,
  useInviteCode,
  getUserByName,
  getUserByEmail,
  createUser,
  updateUser,
  batchCreateInviteCodes,
  getInviteCodes,
  getInviteCodeStats,
  bulkSetMappings,
  createEmailToken,
  getEmailToken,
  useEmailToken,
  verifyUserEmail,
} = require('../db');
const {
  sendVerificationEmail,
  isMailEnabled,
  getBaseUrl,
} = require('../mailer');

// 邮箱格式校验
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * POST /api/auth/register
 * body: { inviteCode, username, password, email, name? }
 */
async function handleRegister(req, res, json) {
  const inviteCode = json.inviteCode;
  const username = sanitizeUsername(json.username);
  const password = json.password;
  const email = json.email;
  const name = json.name;

  // 输入验证
  if (!inviteCode || typeof inviteCode !== 'string') {
    return apiResponse(res, 400, { error: '缺少邀请码' });
  }
  if (!username || username.length < 3 || username.length > 50) {
    return apiResponse(res, 400, { error: '用户名长度需在 3-50 之间' });
  }
  if (!password || typeof password !== 'string' || password.length < 6 || password.length > 200) {
    return apiResponse(res, 400, { error: '密码长度需在 6-200 之间' });
  }
  if (!email || typeof email !== 'string' || !EMAIL_RE.test(email)) {
    return apiResponse(res, 400, { error: '请输入有效的邮箱地址' });
  }

  // 验证邀请码
  const code = getInviteCode(inviteCode.toUpperCase().trim());
  if (!code) {
    return apiResponse(res, 400, { error: '邀请码无效' });
  }
  if (code.used_by !== null || !code.enabled) {
    return apiResponse(res, 400, { error: '邀请码已被使用' });
  }

  // 检查用户名是否已存在
  const existingUser = getUserByName(username);
  if (existingUser) {
    return apiResponse(res, 409, { error: '用户名已存在' });
  }

  // 检查邮箱是否已存在
  const existingEmail = getUserByEmail(email.toLowerCase().trim());
  if (existingEmail) {
    return apiResponse(res, 409, { error: '邮箱已被使用' });
  }

  // 创建用户
  let user;
  try {
    user = createUser({
      name: name || username,
      username,
      password,
      email: email.toLowerCase().trim(),
      note: '邀请码注册',
      role: 'user',
    });
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      return apiResponse(res, 409, { error: '用户名或邮箱已存在' });
    }
    return apiResponse(res, 500, { error: '注册失败: ' + e.message });
  }

  // 标记邀请码已使用
  useInviteCode(inviteCode.toUpperCase().trim(), user.id);

  // 自动为所有节点生成 UUID 映射
  try {
    bulkSetMappings(user.id);
  } catch (e) {
    console.error('自动映射失败:', e.message);
  }

  // 发送验证邮件
  const mailOk = isMailEnabled();
  if (mailOk) {
    try {
      const tokenRow = createEmailToken(user.id, 'verify', 24);
      const verifyUrl = `${getBaseUrl()}/verify?token=${tokenRow.token}`;
      await sendVerificationEmail(user.email, verifyUrl);
    } catch (e) {
      console.error('验证邮件发送失败:', e.message);
      // 邮件发送失败不阻断注册，用户可联系管理员
      return apiResponse(res, 201, {
        ok: true,
        message: '注册成功，但验证邮件发送失败，请联系管理员手动激活',
      });
    }
  } else {
    // SMTP 未配置，自动激活
    verifyUserEmail(user.id);
  }

  const { password_hash, ...safeUser } = user;
  return apiResponse(res, 201, {
    ok: true,
    user: safeUser,
    message: mailOk
      ? '注册成功，请检查邮箱完成激活'
      : '注册成功，请登录',
  });
}

/**
 * GET /api/auth/verify?token=xxx
 * 邮箱验证激活
 */
function handleVerify(req, res, url) {
  const token = url.searchParams.get('token');
  if (!token) {
    return apiResponse(res, 400, { error: '缺少验证令牌' });
  }

  const tokenRow = getEmailToken(token);
  if (!tokenRow || tokenRow.type !== 'verify') {
    return apiResponse(res, 400, { error: '验证链接无效或已过期' });
  }

  // 标记令牌已使用
  useEmailToken(token);

  // 激活用户邮箱
  verifyUserEmail(tokenRow.user_id);

  return apiResponse(res, 200, {
    ok: true,
    message: '邮箱验证成功，请登录',
  });
}

/**
 * GET /api/invite-codes — 管理员：列出所有邀请码
 */
function handleListCodes(req, res) {
  const codes = getInviteCodes();
  const stats = getInviteCodeStats();
  return apiResponse(res, 200, { stats, codes });
}

/**
 * POST /api/invite-codes — 管理员：批量生成邀请码
 * body: { count }
 */
function handleCreateCodes(req, res, json) {
  const count = parseInt(json.count);
  if (!count || count < 1 || count > 500) {
    return apiResponse(res, 400, { error: '数量需在 1-500 之间' });
  }
  const codes = batchCreateInviteCodes(count);
  return apiResponse(res, 201, { created: codes.length, codes });
}

module.exports = {
  handleRegister,
  handleVerify,
  handleListCodes,
  handleCreateCodes,
};
