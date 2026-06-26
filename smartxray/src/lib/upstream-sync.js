/**
 * 上游同步模块
 * 中继节点（home/company）通过此模块从上游 smartxray 拉取连接详情，
 * 构造 Xray VLESS+Reality outbounds 并写入 upstream_outbounds 设置。
 *
 * 流程：
 * 1. 读取 upstream_endpoints 设置（JSON 数组）
 * 2. 对每个端点调用 GET /api/upstream/:username（Bearer admin_token）
 * 3. 404 则跳过（无映射不返回上游节点信息）
 * 4. 转为 Xray outbound 对象
 * 5. 写入 upstream_outbounds 设置，启用 use_upstream
 */

'use strict';

const http = require('http');
const { getSetting, setSetting } = require('./database');

/**
 * 发起 HTTP GET 请求
 * @param {string} host — 目标主机
 * @param {number} port — 目标端口
 * @param {string} path — 请求路径
 * @param {string} adminToken — Bearer token
 * @returns {Promise<Object>} 响应 JSON
 */
function httpGet(host, port, path, adminToken) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: host,
      port: port,
      path: path,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${adminToken}`,
      },
      timeout: 10000,
    };

    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        if (res.statusCode === 404) {
          resolve({ __notFound: true });
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode}: ${body}`));
          return;
        }
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          reject(new Error(`JSON 解析失败: ${e.message}`));
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`请求超时: ${host}:${port}${path}`));
    });

    req.on('error', (e) => {
      reject(new Error(`请求失败: ${e.message}`));
    });

    req.end();
  });
}

/**
 * 将上游连接详情转为 Xray VLESS+Reality outbound 对象
 * @param {Object} data — 上游 API 返回的连接详情
 * @param {Object} ep — 端点配置（含 name, public_port 等）
 * @returns {Object} Xray outbound 对象
 */
function buildOutbound(data, ep) {
  return {
    tag: `upstream-${ep.name}`,
    protocol: 'vless',
    settings: {
      vnext: [{
        address: data.server,
        port: ep.public_port || data.port,
        users: [{
          id: data.uuid,
          flow: data.flow || 'xtls-rprx-vision',
          encryption: 'none',
        }],
      }],
    },
    streamSettings: {
      network: data.network || 'tcp',
      security: data.security || 'reality',
      realitySettings: {
        serverName: data.sni,
        publicKey: data.pubkey,
        shortId: data.shortid,
        fingerprint: 'chrome',
      },
    },
  };
}

/**
 * 同步所有上游端点
 * 读取 upstream_endpoints，逐个拉取，构造 outbounds，写入设置
 * @returns {Promise<Object>} 同步结果
 */
async function syncUpstreams() {
  const endpointsRaw = getSetting('upstream_endpoints', '[]');
  let endpoints;
  try {
    endpoints = JSON.parse(endpointsRaw);
  } catch (e) {
    throw new Error(`upstream_endpoints JSON 格式错误: ${e.message}`);
  }

  if (!Array.isArray(endpoints) || endpoints.length === 0) {
    return { synced: 0, skipped: 0, errors: [], outbounds: [] };
  }

  const outbounds = [];
  const errors = [];
  let synced = 0;
  let skipped = 0;

  for (const ep of endpoints) {
    if (!ep.host || !ep.port || !ep.username || !ep.name) {
      errors.push({ endpoint: ep.name || 'unknown', error: '缺少 name/host/port/username 字段' });
      continue;
    }

    const adminToken = ep.admin_token || '';
    const path = `/api/upstream/${encodeURIComponent(ep.username)}`;

    try {
      const data = await httpGet(ep.host, ep.port, path, adminToken);

      // 404 = 用户不存在或无映射，跳过
      if (data.__notFound) {
        skipped++;
        console.log(`[upstream-sync] 跳过 ${ep.name}: 用户 "${ep.username}" 在 ${ep.host}:${ep.port} 无映射`);
        continue;
      }

      const outbound = buildOutbound(data, ep);
      outbounds.push(outbound);
      synced++;
      console.log(`[upstream-sync] 同步 ${ep.name}: ${ep.host}:${ep.port} → ${outbound.tag}`);
    } catch (e) {
      errors.push({ endpoint: ep.name, error: e.message });
      console.error(`[upstream-sync] ${ep.name} 失败: ${e.message}`);
    }
  }

  // 仅在有成功同步或预期跳过时才覆盖 outbounds
  // 全部网络错误时保留已有 outbounds，避免中断正在路由的流量
  if (synced > 0 || skipped > 0) {
    setSetting('upstream_outbounds', JSON.stringify(outbounds));
    if (synced > 0) {
      setSetting('use_upstream', '1');
    }
  } else {
    console.warn('[upstream-sync] 所有端点同步失败，保留已有 outbounds');
  }

  return {
    synced,
    skipped,
    errors,
    outbounds: outbounds.map(o => ({ tag: o.tag, server: o.streamSettings.realitySettings.serverName })),
  };
}

module.exports = {
  syncUpstreams,
  buildOutbound,
};
