/**
 * 用户管理模块
 * 封装用户增删改查、端口分配、UUID 管理等
 */

const {
  getUserById,
  getUserByName,
  getUserByUuid,
  deleteUserByUuid,
  upsertUserByUuid,
  getAllUsers,
  createUser,
  updateUser,
  deleteUser,
  getExpiredUsers,
  getUsersWithoutUuid,
  assignUserUuid,
  getSetting,
  db
} = require('./database');

const {
  getFixedPortRange,
  getSsPortRange,
  allocPort,
  newUUID,
  randStr,
  getServerHost
} = require('./config');

const { userFirewallOpen, userFirewallClose } = require('./firewall');

// ==================== 用户管理 ====================

/**
 * 添加用户
 * @param {Object} options - 用户选项
 * @param {string} options.name - 用户名称
 * @param {string} [options.username] - 登录用户名
 * @param {string} [options.password] - 登录密码
 * @param {number} [options.port] - 指定端口
 * @param {number} [options.httpPort] - HTTP 端口
 * @param {number} [options.hours] - 有效小时数
 * @param {string} [options.note] - 备注
 * @returns {Object} 创建的用户
 */
function addUser(options) {
  const {
    name,
    username = randStr(8),
    password = randStr(12),
    port = null,
    httpPort = null,
    hours = null,
    note = null
  } = options;

  // 检查名称是否已存在
  if (getUserByName(name)) {
    throw new Error(`用户 "${name}" 已存在`);
  }

  // 分配端口
  const portRange = getFixedPortRange(getSetting);
  const socksPort = port || allocPort(portRange.socksMin, portRange.socksMax, db);
  const assignedHttpPort = httpPort || allocPort(portRange.httpMin, portRange.httpMax, db);

  // 生成 UUID
  const uuid = newUUID();

  // 计算过期时间
  let expiresAt = null;
  if (hours && hours > 0) {
    const expireDate = new Date();
    expireDate.setHours(expireDate.getHours() + hours);
    expiresAt = expireDate.toISOString();
  }

  // 创建用户
  const user = createUser({
    name,
    port: socksPort,
    http_port: assignedHttpPort,
    uuid,
    protocol: 'socks',
    username,
    password,
    tag: `user_${name}`,
    expires_at: expiresAt,
    note
  });

  // 开放防火墙端口
  userFirewallOpen(socksPort, assignedHttpPort);

  return user;
}

/**
 * 删除用户
 * @param {string|number} identifier - 用户名称或 ID
 * @returns {boolean} 是否删除成功
 */
function removeUser(identifier) {
  const user = typeof identifier === 'number'
    ? getUserById(identifier)
    : getUserByName(identifier);

  if (!user) {
    throw new Error(`用户 "${identifier}" 不存在`);
  }

  // 关闭防火墙端口
  userFirewallClose(user.port, user.http_port);

  // 删除用户
  return deleteUser(user.id);
}

/**
 * 启用用户
 * @param {string|number} identifier - 用户名称或 ID
 * @returns {Object} 更新后的用户
 */
function enableUser(identifier) {
  const user = typeof identifier === 'number'
    ? getUserById(identifier)
    : getUserByName(identifier);

  if (!user) {
    throw new Error(`用户 "${identifier}" 不存在`);
  }

  // 开放防火墙端口
  userFirewallOpen(user.port, user.http_port);

  // 更新用户状态
  return updateUser(user.id, { enabled: 1 });
}

/**
 * 禁用用户
 * @param {string|number} identifier - 用户名称或 ID
 * @returns {Object} 更新后的用户
 */
function disableUser(identifier) {
  const user = typeof identifier === 'number'
    ? getUserById(identifier)
    : getUserByName(identifier);

  if (!user) {
    throw new Error(`用户 "${identifier}" 不存在`);
  }

  // 关闭防火墙端口
  userFirewallClose(user.port, user.http_port);

  // 更新用户状态
  return updateUser(user.id, { enabled: 0 });
}

/**
 * 修改用户密码
 * @param {string|number} identifier - 用户名称或 ID
 * @param {string} [newPassword] - 新密码（随机生成如果为空）
 * @returns {Object} 更新后的用户
 */
function changePassword(identifier, newPassword = null) {
  const user = typeof identifier === 'number'
    ? getUserById(identifier)
    : getUserByName(identifier);

  if (!user) {
    throw new Error(`用户 "${identifier}" 不存在`);
  }

  const password = newPassword || randStr(12);
  return updateUser(user.id, { password });
}

/**
 * 设置用户固定端口
 * @param {string|number} identifier - 用户名称或 ID
 * @param {number} socksPort - SOCKS 端口
 * @param {number} [httpPort] - HTTP 端口
 * @returns {Object} 更新后的用户
 */
function setUserPort(identifier, socksPort, httpPort = null) {
  const user = typeof identifier === 'number'
    ? getUserById(identifier)
    : getUserByName(identifier);

  if (!user) {
    throw new Error(`用户 "${identifier}" 不存在`);
  }

  // 关闭旧端口
  userFirewallClose(user.port, user.http_port);

  // 更新端口
  const updateData = { port: socksPort };
  if (httpPort !== null) {
    updateData.http_port = httpPort;
  }

  const updatedUser = updateUser(user.id, updateData);

  // 开放新端口
  userFirewallOpen(updatedUser.port, updatedUser.http_port);

  return updatedUser;
}

/**
 * 获取用户列表
 * @param {Object} [options] - 查询选项
 * @param {boolean} [options.enabledOnly=false] - 只返回启用的用户
 * @returns {Array} 用户数组
 */
function listUsers(options = {}) {
  return getAllUsers(options);
}

/**
 * 清理过期用户
 * @returns {number} 清理的用户数量
 */
function cleanupExpiredUsers() {
  const expiredUsers = getExpiredUsers();
  let count = 0;

  for (const user of expiredUsers) {
    try {
      removeUser(user.id);
      count++;
    } catch (e) {
      console.error(`清理用户 ${user.name} 失败:`, e.message);
    }
  }

  return count;
}

/**
 * 为缺少 UUID 的用户分配 UUID
 * @returns {number} 分配的用户数量
 */
function assignMissingUuids() {
  const users = getUsersWithoutUuid();
  let count = 0;

  for (const user of users) {
    const uuid = newUUID();
    assignUserUuid(user.id, uuid);
    count++;
  }

  return count;
}

/**
 * 获取用户统计信息
 * @returns {Object} 统计信息
 */
function getUserStats() {
  const allUsers = getAllUsers();
  const enabledUsers = allUsers.filter(u => u.enabled);
  const expiredUsers = getExpiredUsers();

  return {
    total: allUsers.length,
    enabled: enabledUsers.length,
    disabled: allUsers.length - enabledUsers.length,
    expired: expiredUsers.length
  };
}

// ==================== 上游同步用户管理 ====================

/**
 * 添加上游同步用户（用指定 UUID 创建）
 * @param {Object} options - { uuid, name }
 * @returns {Object} 创建/更新的用户
 */
function addUpstreamUser({ uuid, name }) {
  if (!uuid || !name) throw new Error('uuid 和 name 必填');

  // 分配端口（上游用户使用 30000+ 区间，不实际使用）
  const portRange = getFixedPortRange(getSetting);
  const socksPort = allocPort(portRange.socksMin, portRange.socksMax, db);
  const httpPort = allocPort(portRange.httpMin, portRange.httpMax, db);
  const tag = `upstream-${name}`;

  // 按 UUID 创建或更新
  const user = upsertUserByUuid(uuid, name, tag, socksPort, httpPort);

  // 不开防火墙（VLESS-Reality 共享端口）
  // 重新生成 xray 配置
  const { buildConfig } = require('./config-generator');
  buildConfig();

  return user;
}

/**
 * 删除上游同步用户（按 UUID）
 * @param {string} uuid
 * @returns {boolean}
 */
function removeUpstreamUser(uuid) {
  const user = getUserByUuid(uuid);
  if (!user) return false;

  // 不关防火墙（上游用户无独立端口需关闭）
  const ok = deleteUserByUuid(uuid);

  if (ok) {
    const { buildConfig } = require('./config-generator');
    buildConfig();
  }
  return ok;
}

/**
 * 启用/停用上游同步用户（按 UUID）
 * @param {string} uuid
 * @param {boolean} enabled
 * @returns {Object|null}
 */
function setUserEnabledByUuid(uuid, enabled) {
  const user = getUserByUuid(uuid);
  if (!user) return null;

  updateUser(user.id, { enabled: enabled ? 1 : 0 });

  const { buildConfig } = require('./config-generator');
  buildConfig();

  return getUserById(user.id);
}

module.exports = {
  addUser,
  removeUser,
  enableUser,
  disableUser,
  changePassword,
  setUserPort,
  listUsers,
  cleanupExpiredUsers,
  assignMissingUuids,
  getUserStats,
  // 上游同步
  addUpstreamUser,
  removeUpstreamUser,
  setUserEnabledByUuid,
};