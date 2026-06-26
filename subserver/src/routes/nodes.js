/**
 * 节点管理路由
 * GET    /api/nodes       — 列出所有节点
 * POST   /api/nodes       — 创建节点
 * GET    /api/nodes/:id   — 获取单个节点
 * PUT    /api/nodes/:id   — 更新节点
 * DELETE /api/nodes/:id   — 删除节点
 */

'use strict';

const { apiResponse } = require('../utils');
const {
  getNodes,
  getNodeById,
  getNodeByName,
  createNode,
  updateNode,
  deleteNode,
} = require('../db');

const VALID_TYPES = ['vless-reality', 'vmess'];
const VALID_CIPHERS = ['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none'];
const VALID_NETWORKS = ['tcp', 'ws', 'grpc'];
const VALID_FLOWS = ['xtls-rprx-vision', ''];
const VALID_FINGERPRINTS = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'qlb'];

/**
 * 校验节点数据
 * @returns {string|null} 错误信息，null 表示通过
 */
function validateNodeData(json, isCreate) {
  if (isCreate) {
    if (!json.name || typeof json.name !== 'string') return '缺少或无效的 name';
    if (!json.type || !VALID_TYPES.includes(json.type)) return `type 必须为: ${VALID_TYPES.join(' 或 ')}`;
    if (!json.server || typeof json.server !== 'string') return '缺少或无效的 server';
    if (!json.port || !Number.isInteger(json.port) || json.port < 1 || json.port > 65535) return 'port 必须为 1-65535 的整数';
  }
  if (json.type === 'vless-reality' && (!json.pubkey || !json.sni)) return 'vless-reality 需要 pubkey 和 sni';
  if (json.flow && !VALID_FLOWS.includes(json.flow)) return `flow 必须为: ${VALID_FLOWS.join(' 或 ')}`;
  if (json.fingerprint && !VALID_FINGERPRINTS.includes(json.fingerprint)) return `fingerprint 必须为: ${VALID_FINGERPRINTS.join(' 或 ')}`;
  if (json.cipher && !VALID_CIPHERS.includes(json.cipher)) return `cipher 必须为: ${VALID_CIPHERS.join(' 或 ')}`;
  if (json.network && !VALID_NETWORKS.includes(json.network)) return `network 必须为: ${VALID_NETWORKS.join(' 或 ')}`;
  return null;
}

/**
 * GET /api/nodes
 */
function handleList(req, res) {
  const nodes = getNodes();
  return apiResponse(res, 200, nodes);
}

/**
 * POST /api/nodes
 */
async function handleCreate(req, res, json) {
  const err = validateNodeData(json, true);
  if (err) return apiResponse(res, 400, { error: err });
  try {
    const node = createNode(json);
    return apiResponse(res, 201, node);
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      return apiResponse(res, 409, { error: `节点名 '${json.name}' 已存在` });
    }
    return apiResponse(res, 400, { error: e.message });
  }
}

/**
 * GET /api/nodes/:id
 */
function handleGet(req, res, id) {
  const node = getNodeById(id);
  if (!node) {
    return apiResponse(res, 404, { error: '节点不存在' });
  }
  return apiResponse(res, 200, node);
}

/**
 * PUT /api/nodes/:id
 */
async function handleUpdate(req, res, id, json) {
  const node = getNodeById(id);
  if (!node) {
    return apiResponse(res, 404, { error: '节点不存在' });
  }
  const err = validateNodeData({ ...node, ...json }, false);
  if (err) return apiResponse(res, 400, { error: err });
  try {
    const updated = updateNode(id, json);
    return apiResponse(res, 200, updated);
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      return apiResponse(res, 409, { error: `节点名已存在` });
    }
    return apiResponse(res, 400, { error: e.message });
  }
}

/**
 * DELETE /api/nodes/:id
 */
function handleDelete(req, res, id) {
  const node = getNodeById(id);
  if (!node) {
    return apiResponse(res, 404, { error: '节点不存在' });
  }
  deleteNode(id);
  return apiResponse(res, 200, { ok: true });
}

module.exports = {
  handleList,
  handleCreate,
  handleGet,
  handleUpdate,
  handleDelete,
};
