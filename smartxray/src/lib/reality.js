/**
 * Reality 配置管理模块
 * 封装 Reality 密钥生成、配置管理、链接生成等
 */

const fs   = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { getSetting, setSetting } = require('./database');
const { randHex, newUUID, getServerHost } = require('./config');

// ==================== Reality 配置管理 ====================

/**
 * 获取 Reality 配置
 * @returns {Object} Reality 配置对象
 */
function getRealityConfig() {
  const enabled = getSetting('reality_enabled', '0') === '1';
  const port = parseInt(getSetting('reality_port', '443')) || 443;
  const privateKey = getSetting('reality_private_key', '');
  const publicKey = getSetting('reality_public_key', '');
  const serverNames = getSetting('reality_server_names', 'www.cloudflare.com,www.apple.com').split(',');
  const shortIds = getSetting('reality_short_ids', randHex(8)).split(',');
  const dest = getSetting('reality_dest', 'www.cloudflare.com:443');

  return {
    enabled,
    port,
    privateKey,
    publicKey,
    serverNames,
    shortIds,
    dest
  };
}

/**
 * 生成 Reality 密钥对
 * @returns {Object} { privateKey, publicKey }
 */
function generateRealityKeys() {
  try {
    // 使用 xray x25519 生成密钥对
    const output = execSync('xray x25519', { encoding: 'utf8' });
    const lines = output.split('\n');
    let privateKey = '';
    let publicKey = '';

    for (const line of lines) {
      if (line.includes('Private key:')) {
        privateKey = line.split(':')[1].trim();
      } else if (line.includes('Public key:')) {
        publicKey = line.split(':')[1].trim();
      }
    }

    if (!privateKey || !publicKey) {
      throw new Error('无法解析密钥对');
    }

    return { privateKey, publicKey };
  } catch (e) {
    // 如果 xray 命令不可用，使用备用方法
    console.log('⚠ 无法使用 xray 命令生成密钥，使用备用方法');
    const privateKey = randHex(32);
    const publicKey = randHex(32);
    return { privateKey, publicKey };
  }
}

/**
 * 初始化 Reality 配置
 * @param {number} [port=443] - Reality 端口
 * @param {string} [dest='www.cloudflare.com:443'] - 目标地址
 * @returns {Object} 配置结果
 */
function initReality(port = 443, dest = 'www.cloudflare.com:443') {
  const keys = generateRealityKeys();
  const shortId = randHex(8);

  setSetting('reality_enabled', '1');
  setSetting('reality_port', String(port));
  setSetting('reality_private_key', keys.privateKey);
  setSetting('reality_public_key', keys.publicKey);
  setSetting('reality_server_names', 'www.cloudflare.com,www.apple.com');
  setSetting('reality_short_ids', shortId);
  setSetting('reality_dest', dest);

  return {
    success: true,
    port,
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    shortId,
    dest
  };
}

/**
 * 导入现有 Reality 密钥
 * @param {string} privateKey - 私钥
 * @param {string} publicKey - 公钥
 * @param {number} [port=443] - 端口
 * @param {string} [shortId] - Short ID
 * @param {string} [dest] - 目标地址
 * @returns {Object} 配置结果
 */
function importReality(privateKey, publicKey, port = 443, shortId = null, dest = null) {
  if (!privateKey || !publicKey) {
    throw new Error('私钥和公钥不能为空');
  }

  const finalShortId = shortId || randHex(8);
  const finalDest = dest || 'www.cloudflare.com:443';

  setSetting('reality_enabled', '1');
  setSetting('reality_port', String(port));
  setSetting('reality_private_key', privateKey);
  setSetting('reality_public_key', publicKey);
  setSetting('reality_short_ids', finalShortId);
  setSetting('reality_dest', finalDest);

  return {
    success: true,
    port,
    privateKey,
    publicKey,
    shortId: finalShortId,
    dest: finalDest
  };
}

/**
 * 禁用 Reality
 */
function disableReality() {
  setSetting('reality_enabled', '0');
}

/**
 * 生成 Reality 配置片段（用于 Xray 配置）
 * @returns {Object} Reality 配置对象
 */
function generateRealityConfig() {
  const config = getRealityConfig();
  if (!config.enabled) return null;

  return {
    dest: config.dest,
    xver: 0,
    serverNames: config.serverNames,
    privateKey: config.privateKey,
    shortIds: config.shortIds
  };
}

/**
 * 生成 Reality 链接
 * @param {Object} user - 用户对象
 * @param {string} [uuid] - UUID（可选）
 * @returns {string} VLESS Reality 链接
 */
function generateRealityLink(user, uuid = null) {
  const config = getRealityConfig();
  if (!config.enabled) return '';

  const serverHost = getServerHost(getSetting);
  const userUuid = uuid || user.uuid || newUUID();
  const port = config.port;
  const publicKey = config.publicKey;
  const shortId = config.shortIds[0] || '';
  const sni = config.serverNames[0] || 'www.cloudflare.com';

  // 构建 VLESS Reality 链接
  const params = new URLSearchParams({
    type: 'tcp',
    security: 'reality',
    pbk: publicKey,
    sid: shortId,
    fp: 'chrome'
  });

  const link = `vless://${userUuid}@${serverHost}:${port}?${params.toString()}#${encodeURIComponent(user.name + '-reality')}`;
  return link;
}

/**
 * 显示 Reality 配置信息
 * @returns {string} 格式化的配置信息
 */
function showRealityInfo() {
  const config = getRealityConfig();
  if (!config.enabled) {
    return 'Reality 未启用';
  }

  const lines = [
    `Reality 状态: ${config.enabled ? '已启用' : '已禁用'}`,
    `端口: ${config.port}`,
    `公钥: ${config.publicKey}`,
    `Short IDs: ${config.shortIds.join(', ')}`,
    `目标地址: ${config.dest}`,
    `SNI: ${config.serverNames.join(', ')}`
  ];

  return lines.join('\n');
}

module.exports = {
  getRealityConfig,
  generateRealityKeys,
  initReality,
  importReality,
  disableReality,
  generateRealityConfig,
  generateRealityLink,
  showRealityInfo
};