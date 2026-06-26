/**
 * 上游同步模块
 * 负责将 subserver 的用户操作同步到各 smartxray 节点
 * 
 * 设计要点：
 * - 异步执行，不阻塞 API 响应
 * - 错误不回滚用户操作，仅记录日志
 * - 单节点失败不影响其他节点
 * - 超时 5 秒/节点
 */

'use strict';

const http = require('http');
const { db, getUserById, getMappings, getMapping } = require('./db');

// ==================== HTTP 请求封装 ====================

/**
 * 向 smartxray API 发送 HTTP 请求
 * @param {string} host - API 主机地址
 * @param {number} port - API 端口
 * @param {string} method - HTTP 方法
 * @param {string} path - 请求路径
 * @param {string} token - Bearer token (smartxray admin 密码)
 * @param {Object} [body] - 请求体
 * @returns {Promise<{status: number, data: Object}>}
 */
function apiCall(host, port, method, path, token, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const options = {
      hostname: host,
      port: port,
      path: path,
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      timeout: 5000,
    };
    if (data) options.headers['Content-Length'] = Buffer.byteLength(data);

    const req = http.request(options, (res) => {
      let responseData = '';
      res.on('data', chunk => responseData += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(responseData);
          resolve({ status: res.statusCode, data: json });
        } catch {
          resolve({ status: res.statusCode, data: { raw: responseData } });
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('timeout'));
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// ==================== 查询辅助 ====================

/**
 * 获取所有启用上游同步的节点
 */
function getUpstreamNodes() {
  return db().prepare(`
    SELECT * FROM nodes WHERE has_upstream_api = 1 AND enabled = 1
    ORDER BY sort_order, id
  `).all();
}

/**
 * 获取用户在上游节点上的映射（UUID + 节点 API 信息）
 */
function getUpstreamMappings(userId) {
  return db().prepare(`
    SELECT m.uuid, m.node_id,
           n.name as node_name, n.server, n.api_host, n.api_port, n.api_token
    FROM user_node_uuids m
    JOIN nodes n ON m.node_id = n.id
    WHERE m.user_id = ? AND n.has_upstream_api = 1 AND n.enabled = 1
    ORDER BY n.sort_order, n.id
  `).all(userId);
}

/**
 * 获取单个节点信息（含 API 字段）
 */
function getUpstreamNode(nodeId) {
  return db().prepare(`
    SELECT * FROM nodes WHERE id = ? AND has_upstream_api = 1 AND enabled = 1
  `).get(nodeId);
}

// ==================== 同步函数 ====================

/**
 * 同步用户创建到所有上游节点
 * 对每个 has_upstream_api=1 的节点，调用 POST /api/upstream/user
 * @param {number} userId - subserver 用户 ID
 * @returns {Promise<{synced: number, failed: number, errors: string[]}>}
 */
async function syncUserCreate(userId) {
  const user = getUserById(userId);
  if (!user) return { synced: 0, failed: 0, errors: ['用户不存在'] };

  const mappings = getUpstreamMappings(userId);
  if (!mappings.length) return { synced: 0, failed: 0, errors: [] };

  const results = await Promise.allSettled(
    mappings.map(async (m) => {
      const host = m.api_host || m.server;
      const port = m.api_port || 2088;
      const token = m.api_token || '';
      if (!token) throw new Error('未配置 api_token');

      const res = await apiCall(host, port, 'POST', '/api/upstream/user', token, {
        uuid: m.uuid,
        name: user.name,
      });
      if (res.status !== 200) {
        throw new Error(res.data.error || `HTTP ${res.status}`);
      }
      return { node: m.node_name, ok: true };
    })
  );

  const errors = [];
  let synced = 0, failed = 0;
  for (const r of results) {
    if (r.status === 'fulfilled') {
      synced++;
    } else {
      failed++;
      const idx = results.indexOf(r);
      errors.push(`${mappings[idx].node_name}: ${r.reason.message}`);
    }
  }

  if (errors.length) {
    console.error(`[upstream-sync] syncUserCreate(${user.name}): ${errors.join('; ')}`);
  } else {
    console.log(`[upstream-sync] syncUserCreate(${user.name}): ${synced} nodes synced`);
  }

  return { synced, failed, errors };
}

/**
 * 同步用户删除到所有上游节点
 * 注意：必须在 deleteUser 之前调用（因为 user_node_uuids 有 ON DELETE CASCADE）
 * @param {number} userId - subserver 用户 ID
 * @returns {Promise<{synced: number, failed: number, errors: string[]}>}
 */
async function syncUserDelete(userId) {
  const user = getUserById(userId);
  if (!user) return { synced: 0, failed: 0, errors: ['用户不存在'] };

  const mappings = getUpstreamMappings(userId);
  if (!mappings.length) return { synced: 0, failed: 0, errors: [] };

  const results = await Promise.allSettled(
    mappings.map(async (m) => {
      const host = m.api_host || m.server;
      const port = m.api_port || 2088;
      const token = m.api_token || '';
      if (!token) throw new Error('未配置 api_token');

      const res = await apiCall(host, port, 'DELETE', `/api/upstream/user/${encodeURIComponent(m.uuid)}`, token);
      // 404 也算成功（用户已不存在）
      if (res.status !== 200 && res.status !== 404) {
        throw new Error(res.data.error || `HTTP ${res.status}`);
      }
      return { node: m.node_name, ok: true };
    })
  );

  const errors = [];
  let synced = 0, failed = 0;
  for (const r of results) {
    if (r.status === 'fulfilled') {
      synced++;
    } else {
      failed++;
      const idx = results.indexOf(r);
      errors.push(`${mappings[idx].node_name}: ${r.reason.message}`);
    }
  }

  if (errors.length) {
    console.error(`[upstream-sync] syncUserDelete(${user.name}): ${errors.join('; ')}`);
  } else {
    console.log(`[upstream-sync] syncUserDelete(${user.name}): ${synced} nodes synced`);
  }

  return { synced, failed, errors };
}

/**
 * 同步用户启停到所有上游节点
 * @param {number} userId - subserver 用户 ID
 * @param {boolean} enabled - 启用/停用
 * @returns {Promise<{synced: number, failed: number, errors: string[]}>}
 */
async function syncUserEnabled(userId, enabled) {
  const user = getUserById(userId);
  if (!user) return { synced: 0, failed: 0, errors: ['用户不存在'] };

  const mappings = getUpstreamMappings(userId);
  if (!mappings.length) return { synced: 0, failed: 0, errors: [] };

  const results = await Promise.allSettled(
    mappings.map(async (m) => {
      const host = m.api_host || m.server;
      const port = m.api_port || 2088;
      const token = m.api_token || '';
      if (!token) throw new Error('未配置 api_token');

      const res = await apiCall(host, port, 'PATCH', `/api/upstream/user/${encodeURIComponent(m.uuid)}`, token, {
        enabled: !!enabled,
      });
      if (res.status !== 200) {
        throw new Error(res.data.error || `HTTP ${res.status}`);
      }
      return { node: m.node_name, ok: true };
    })
  );

  const errors = [];
  let synced = 0, failed = 0;
  for (const r of results) {
    if (r.status === 'fulfilled') {
      synced++;
    } else {
      failed++;
      const idx = results.indexOf(r);
      errors.push(`${mappings[idx].node_name}: ${r.reason.message}`);
    }
  }

  if (errors.length) {
    console.error(`[upstream-sync] syncUserEnabled(${user.name}, ${enabled}): ${errors.join('; ')}`);
  } else {
    console.log(`[upstream-sync] syncUserEnabled(${user.name}, ${enabled}): ${synced} nodes synced`);
  }

  return { synced, failed, errors };
}

/**
 * 同步单条映射创建
 * @param {number} userId - subserver 用户 ID
 * @param {number} nodeId - 节点 ID
 * @returns {Promise<{ok: boolean, error?: string}>}
 */
async function syncMappingCreate(userId, nodeId) {
  const user = getUserById(userId);
  if (!user) return { ok: false, error: '用户不存在' };

  const mapping = getMapping(userId, nodeId);
  if (!mapping) return { ok: false, error: '映射不存在' };

  const node = getUpstreamNode(nodeId);
  if (!node) return { ok: true, skipped: true }; // 非上游节点，跳过

  const host = node.api_host || node.server;
  const port = node.api_port || 2088;
  const token = node.api_token || '';
  if (!token) return { ok: false, error: '未配置 api_token' };

  try {
    const res = await apiCall(host, port, 'POST', '/api/upstream/user', token, {
      uuid: mapping.uuid,
      name: user.name,
    });
    if (res.status !== 200) {
      return { ok: false, error: res.data.error || `HTTP ${res.status}` };
    }
    console.log(`[upstream-sync] syncMappingCreate(${user.name} → ${node.name}): OK`);
    return { ok: true };
  } catch (e) {
    console.error(`[upstream-sync] syncMappingCreate(${user.name} → ${node.name}): ${e.message}`);
    return { ok: false, error: e.message };
  }
}

/**
 * 同步单条映射删除
 * @param {number} userId - subserver 用户 ID
 * @param {number} nodeId - 节点 ID
 * @returns {Promise<{ok: boolean, error?: string}>}
 */
async function syncMappingDelete(userId, nodeId) {
  const mapping = getMapping(userId, nodeId);
  if (!mapping) return { ok: true, skipped: true }; // 映射已不存在

  const node = getUpstreamNode(nodeId);
  if (!node) return { ok: true, skipped: true }; // 非上游节点

  const host = node.api_host || node.server;
  const port = node.api_port || 2088;
  const token = node.api_token || '';
  if (!token) return { ok: false, error: '未配置 api_token' };

  try {
    const res = await apiCall(host, port, 'DELETE', `/api/upstream/user/${encodeURIComponent(mapping.uuid)}`, token);
    // 404 也算成功
    if (res.status !== 200 && res.status !== 404) {
      return { ok: false, error: res.data.error || `HTTP ${res.status}` };
    }
    console.log(`[upstream-sync] syncMappingDelete(${node.name}): OK`);
    return { ok: true };
  } catch (e) {
    console.error(`[upstream-sync] syncMappingDelete(${node.name}): ${e.message}`);
    return { ok: false, error: e.message };
  }
}

/**
 * 全量重新同步（手动触发）
 * 遍历所有用户，对所有上游节点重新创建用户
 * @returns {Promise<{users: number, synced: number, failed: number, errors: string[]}>}
 */
async function syncAll() {
  const users = db().prepare('SELECT id FROM users WHERE enabled = 1 ORDER BY id').all();
  let totalSynced = 0, totalFailed = 0;
  const allErrors = [];

  for (const u of users) {
    const result = await syncUserCreate(u.id);
    totalSynced += result.synced;
    totalFailed += result.failed;
    allErrors.push(...result.errors);
  }

  console.log(`[upstream-sync] syncAll: ${users.length} users, ${totalSynced} synced, ${totalFailed} failed`);
  return { users: users.length, synced: totalSynced, failed: totalFailed, errors: allErrors };
}

// ==================== 流量查询 ====================

/**
 * 查询用户在所有上游节点的流量
 * @param {number} userId - subserver 用户 ID
 * @returns {Promise<{userId: number, nodes: Array}>}
 */
async function getUserTraffic(userId) {
  const user = getUserById(userId);
  if (!user) return { userId, nodes: [] };

  const mappings = getUpstreamMappings(userId);
  if (!mappings.length) return { userId, nodes: [] };

  const results = await Promise.allSettled(
    mappings.map(async (m) => {
      const host = m.api_host || m.server;
      const port = m.api_port || 2088;
      const token = m.api_token || '';
      if (!token) throw new Error('未配置 api_token');

      const res = await apiCall(host, port, 'GET', `/api/traffic/${encodeURIComponent(m.uuid)}`, token);
      if (res.status !== 200) {
        throw new Error(res.data.error || `HTTP ${res.status}`);
      }
      return {
        nodeName: m.node_name,
        server: m.api_host || m.server,
        uuid: m.uuid,
        uplink: res.data.uplink || 0,
        downlink: res.data.downlink || 0,
        total: res.data.total || 0,
      };
    })
  );

  const nodes = [];
  for (let i = 0; i < results.length; i++) {
    if (results[i].status === 'fulfilled') {
      nodes.push(results[i].value);
    } else {
      nodes.push({
        nodeName: mappings[i].node_name,
        server: mappings[i].api_host || mappings[i].server,
        uuid: mappings[i].uuid,
        uplink: 0, downlink: 0, total: 0,
        error: results[i].reason.message,
      });
    }
  }

  return { userId, userName: user.name, nodes };
}

module.exports = {
  apiCall,
  getUpstreamNodes,
  getUpstreamMappings,
  syncUserCreate,
  syncUserDelete,
  syncUserEnabled,
  syncMappingCreate,
  syncMappingDelete,
  syncAll,
  getUserTraffic,
};
