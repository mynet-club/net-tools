/**
 * 流量统计模块
 * 通过 xray API (StatsService) 查询 per-user 累计上下行流量
 * xray CLI: xray api stats --server=127.0.0.1:PORT -name="user>>>UUID>>>traffic>>>uplink"
 */

const { execSync } = require('child_process');
const fs = require('fs');
const { getSetting, getAllUsers } = require('./database');

/**
 * 获取 xray 二进制路径
 */
function getXrayBinary() {
  const paths = ['/usr/local/bin/xray', '/usr/bin/xray', '/usr/local/lib/smartxray/xray'];
  for (const p of paths) {
    if (fs.existsSync(p)) return p;
  }
  return 'xray';
}

/**
 * 获取 xray API 端口
 */
function getApiPort() {
  return parseInt(getSetting('xray_api_port', '10085'));
}

/**
 * 查询单个 stat 值
 * @param {string} name - stat 名称，如 "user>>>UUID>>>traffic>>>uplink"
 * @returns {number} 流量字节数
 */
function queryStat(name) {
  const bin = getXrayBinary();
  const port = getApiPort();
  const cmd = `"${bin}" api stats --server=127.0.0.1:${port} -name="${name}"`;
  try {
    const output = execSync(cmd, { encoding: 'utf8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] });
    // 解析格式: name: "user>>>UUID>>>traffic>>>uplink"\nvalue: 12345
    const match = output.match(/value:\s*(\d+)/);
    return match ? parseInt(match[1]) : 0;
  } catch {
    return 0;
  }
}

/**
 * 查询单个用户的累计流量
 * @param {string} uuid - 用户 UUID
 * @returns {Object} { uuid, uplink, downlink, total }
 */
function getUserTraffic(uuid) {
  const uplink = queryStat(`user>>>${uuid}>>>traffic>>>uplink`);
  const downlink = queryStat(`user>>>${uuid}>>>traffic>>>downlink`);
  return { uuid, uplink, downlink, total: uplink + downlink };
}

/**
 * 查询所有用户的流量统计
 * 一次性查询所有 stats，避免多次 CLI 调用
 * @returns {Array} [{ uuid, name, uplink, downlink, total }]
 */
function getAllTraffic() {
  const bin = getXrayBinary();
  const port = getApiPort();
  const cmd = `"${bin}" api stats --server=127.0.0.1:${port}`;
  let output;
  try {
    output = execSync(cmd, { encoding: 'utf8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] });
  } catch {
    // xray 未运行或 API 不可用，返回全零
    return getAllUsers().map(u => ({
      uuid: u.uuid || '', name: u.name, uplink: 0, downlink: 0, total: 0,
    }));
  }

  // 解析所有 stat 条目
  const stats = {};
  const regex = /name:\s*"(user>>>[^"]+>>>traffic>>>(?:uplink|downlink))"\s*\nvalue:\s*(\d+)/g;
  let match;
  while ((match = regex.exec(output)) !== null) {
    const fullName = match[1];
    const value = parseInt(match[2]);
    // 从 fullName 提取 uuid 和方向
    const parts = fullName.match(/user>>>(.+?)>>>traffic>>>(uplink|downlink)/);
    if (parts) {
      const uuid = parts[1];
      const direction = parts[2];
      if (!stats[uuid]) stats[uuid] = { uuid, uplink: 0, downlink: 0, total: 0 };
      stats[uuid][direction] = value;
      stats[uuid].total = stats[uuid].uplink + stats[uuid].downlink;
    }
  }

  // 合并数据库中的用户名
  const users = getAllUsers();
  const userMap = {};
  for (const u of users) {
    if (u.uuid) userMap[u.uuid] = u.name;
  }

  // 返回所有有 UUID 的用户（有流量数据的 + 没有流量数据的）
  const result = [];
  const seenUuids = new Set();
  for (const u of users) {
    if (u.uuid) {
      seenUuids.add(u.uuid);
      const s = stats[u.uuid] || { uplink: 0, downlink: 0, total: 0 };
      result.push({
        uuid: u.uuid,
        name: u.name,
        uplink: s.uplink,
        downlink: s.downlink,
        total: s.total,
      });
    }
  }
  // 如果有 stats 中的 UUID 不在数据库中（已删除用户），也包含
  for (const [uuid, s] of Object.entries(stats)) {
    if (!seenUuids.has(uuid)) {
      result.push({ uuid, name: '(unknown)', ...s });
    }
  }

  return result;
}

module.exports = { getUserTraffic, getAllTraffic, queryStat };
