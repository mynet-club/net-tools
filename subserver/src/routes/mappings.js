/**
 * 用户-节点 UUID 映射路由
 * GET    /api/mappings/:userId         — 列出用户的所有映射
 * POST   /api/mappings/:userId         — 创建或更新单条映射
 * POST   /api/mappings/:userId/bulk    — 批量为用户设置所有节点 UUID
 * DELETE /api/mappings/:userId/:nodeId — 删除单条映射
 */

'use strict';

const { apiResponse } = require('../utils');
const {
  getUserById,
  getNodeById,
  getMappings,
  getMapping,
  upsertMapping,
  deleteMapping,
  bulkSetMappings,
} = require('../db');

/**
 * GET /api/mappings/:userId
 */
function handleList(req, res, userId) {
  const user = getUserById(userId);
  if (!user) {
    return apiResponse(res, 404, { error: '用户不存在' });
  }
  const mappings = getMappings(userId);
  return apiResponse(res, 200, mappings);
}

/**
 * POST /api/mappings/:userId
 * body: { node_id, uuid }
 */
async function handleCreate(req, res, userId, json) {
  const user = getUserById(userId);
  if (!user) {
    return apiResponse(res, 404, { error: '用户不存在' });
  }
  if (!json.node_id || !json.uuid) {
    return apiResponse(res, 400, { error: '缺少 node_id 或 uuid' });
  }
  const node = getNodeById(json.node_id);
  if (!node) {
    return apiResponse(res, 404, { error: '节点不存在' });
  }
  const mapping = upsertMapping(userId, json.node_id, json.uuid);
  return apiResponse(res, 201, mapping);
}

/**
 * POST /api/mappings/:userId/bulk
 * 为用户批量设置所有启用节点的 UUID（已有保留，缺失自动生成）
 */
function handleBulk(req, res, userId) {
  const user = getUserById(userId);
  if (!user) {
    return apiResponse(res, 404, { error: '用户不存在' });
  }
  const results = bulkSetMappings(userId);
  return apiResponse(res, 200, { total: results.length, mappings: results });
}

/**
 * DELETE /api/mappings/:userId/:nodeId
 */
function handleDelete(req, res, userId, nodeId) {
  const user = getUserById(userId);
  if (!user) {
    return apiResponse(res, 404, { error: '用户不存在' });
  }
  const mapping = getMapping(userId, nodeId);
  if (!mapping) {
    return apiResponse(res, 404, { error: '映射不存在' });
  }
  deleteMapping(userId, nodeId);
  return apiResponse(res, 200, { ok: true });
}

module.exports = {
  handleList,
  handleCreate,
  handleBulk,
  handleDelete,
};
