/**
 * 用户-节点 UUID 映射路由
 * GET    /api/mappings/:userId         — 列出用户的所有映射
 * POST   /api/mappings/:userId         — 创建或更新单条映射
 * POST   /api/mappings/:userId/bulk    — 批量为用户设置所有节点 UUID
 * PATCH  /api/mappings/:userId/:nodeId — 启用/禁用单条映射
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
  setMappingEnabled,
  deleteMapping,
  bulkSetMappings,
} = require('../db');

const { syncUserCreate, syncMappingCreate, syncMappingDelete, syncMappingEnabled } = require('../upstream-sync');

/**
 * GET /api/mappings/:userId
 */
async function handleList(req, res, userId) {
  const user = await getUserById(userId);
  if (!user) {
    return apiResponse(res, 404, { error: '用户不存在' });
  }
  const mappings = await getMappings(userId);
  return apiResponse(res, 200, mappings);
}

/**
 * POST /api/mappings/:userId
 * body: { node_id, uuid }
 */
async function handleCreate(req, res, userId, json) {
  const user = await getUserById(userId);
  if (!user) {
    return apiResponse(res, 404, { error: '用户不存在' });
  }
  if (!json.node_id || !json.uuid) {
    return apiResponse(res, 400, { error: '缺少 node_id 或 uuid' });
  }
  const node = await getNodeById(json.node_id);
  if (!node) {
    return apiResponse(res, 404, { error: '节点不存在' });
  }
  const mapping = upsertMapping(userId, json.node_id, json.uuid);
  // 异步同步到上游节点
  syncMappingCreate(userId, json.node_id).catch(e => console.error('[upstream-sync] mappingCreate:', e.message));
  return apiResponse(res, 201, mapping);
}

/**
 * POST /api/mappings/:userId/bulk
 * 为用户批量设置所有启用节点的 UUID（已有保留，缺失自动生成）
 */
async function handleBulk(req, res, userId) {
  const user = await getUserById(userId);
  if (!user) {
    return apiResponse(res, 404, { error: '用户不存在' });
  }
  const results = await bulkSetMappings(userId);
  // 异步同步到上游节点
  syncUserCreate(userId).catch(e => console.error('[upstream-sync] mappingBulk:', e.message));
  return apiResponse(res, 200, { total: results.length, mappings: results });
}

/**
 * PATCH /api/mappings/:userId/:nodeId
 * body: { enabled: 0|1 }
 */
async function handleToggle(req, res, userId, nodeId, json) {
  const user = await getUserById(userId);
  if (!user) {
    return apiResponse(res, 404, { error: '用户不存在' });
  }
  const mapping = await getMapping(userId, nodeId);
  if (!mapping) {
    return apiResponse(res, 404, { error: '映射不存在' });
  }
  const enabled = json && json.enabled ? 1 : 0;
  const updated = setMappingEnabled(userId, nodeId, enabled);
  // 异步同步到上游节点
  syncMappingEnabled(userId, nodeId, enabled).catch(e => console.error('[upstream-sync] mappingToggle:', e.message));
  return apiResponse(res, 200, updated);
}

/**
 * DELETE /api/mappings/:userId/:nodeId
 */
async function handleDelete(req, res, userId, nodeId) {
  const user = await getUserById(userId);
  if (!user) {
    return apiResponse(res, 404, { error: '用户不存在' });
  }
  const mapping = await getMapping(userId, nodeId);
  if (!mapping) {
    return apiResponse(res, 404, { error: '映射不存在' });
  }
  // 先同步删除上游节点用户（需要 mapping 仍存在）
  try { await syncMappingDelete(userId, parseInt(nodeId)); } catch (e) { console.error('[upstream-sync] mappingDelete:', e.message); }
  deleteMapping(userId, parseInt(nodeId));
  return apiResponse(res, 200, { ok: true });
}

module.exports = {
  handleList,
  handleCreate,
  handleBulk,
  handleToggle,
  handleDelete,
};
