/**
 * 数据库模块
 * 封装所有 MariaDB/MySQL 数据库操作（mysql2/promise 连接池）
 */

'use strict';

const crypto = require('crypto');
const mysql = require('mysql2/promise');

const { config } = require('./config');

// ── 默认模板内容 ────────────────────────────────────────────────
const DEFAULT_TEMPLATE_CONTENT = `mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:9090

dns:
  enable: true
  ipv6: false
  listen: 127.0.0.1:1053
  enhanced-mode: redir-host
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - tls://1.1.1.1:853
    - https://dns.google/dns-query
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
      - 0.0.0.0/8

tun:
  enable: false
  stack: system
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53

{{PROXIES}}

proxy-groups:
  - name: "自动选择"
    type: url-test
    proxies: [{{PROXY_NAMES}}]
    url: "https://www.gstatic.com/generate_204"
    interval: 120
    tolerance: 50

  - name: "手动选择"
    type: select
    proxies:
      - "自动选择"
{{PROXY_NAMES_INLINE}}
      - DIRECT

  - name: "默认出口"
    type: select
    proxies:
      - "自动选择"
      - "手动选择"
      - DIRECT

rules:
  - IP-CIDR,192.168.0.0/16,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT
  - IP-CIDR,172.16.0.0/12,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT
  - DOMAIN-SUFFIX,luoyueliang.com,DIRECT
  - DOMAIN-SUFFIX,asuscomm.com,DIRECT
  - DOMAIN-SUFFIX,icdn.plus,DIRECT
  - DOMAIN-SUFFIX,19800820.com,DIRECT
  - GEOSITE,telegram,默认出口
  - IP-CIDR,91.108.4.0/22,默认出口
  - IP-CIDR,91.108.56.0/22,默认出口
  - IP-CIDR,149.154.160.0/20,默认出口
  - IP-CIDR,149.154.164.0/22,默认出口
  - GEOSITE,youtube,默认出口
  - GEOSITE,google,默认出口
  - DOMAIN-SUFFIX,googlevideo.com,默认出口
  - DOMAIN-SUFFIX,ytimg.com,默认出口
  - DOMAIN-SUFFIX,ggpht.com,默认出口
  - DOMAIN-SUFFIX,gstatic.com,默认出口
  - DOMAIN-SUFFIX,googleapis.com,默认出口
  - GEOSITE,cn,DIRECT
  - GEOSITE,geolocation-!cn,默认出口
  - GEOIP,CN,DIRECT
  - MATCH,默认出口
`;

// ── 连接池 ──────────────────────────────────────────────────────
let pool = null;

function getPool() {
  if (!pool) {
    const dbCfg = config.db || {};
    pool = mysql.createPool({
      host: dbCfg.host || 'localhost',
      port: dbCfg.port || 3306,
      user: dbCfg.user || 'root',
      password: dbCfg.password || '',
      database: dbCfg.database || 'subserver',
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      charset: 'utf8mb4',
    });
  }
  return pool;
}

/** 快捷查询：返回行数组 */
async function query(sql, params) {
  const [rows] = await getPool().execute(sql, params);
  return rows;
}

/** 快捷查询：返回单行或 null */
async function queryOne(sql, params) {
  const rows = await query(sql, params);
  return rows[0] || null;
}

/** 快捷执行：返回 ResultSetHeader (含 insertId, affectedRows) */
async function execute(sql, params) {
  const [result] = await getPool().execute(sql, params);
  return result;
}

// ── 初始化数据库 schema ─────────────────────────────────────────

let _schemaReady = null; // Promise，确保只初始化一次

function initDb() {
  if (!_schemaReady) {
    _schemaReady = _doInitSchema();
  }
  return _schemaReady;
}

async function _doInitSchema() {
  await getPool().execute(`
    CREATE TABLE IF NOT EXISTS users (
      id             INT AUTO_INCREMENT PRIMARY KEY,
      token          VARCHAR(64) NOT NULL UNIQUE,
      name           VARCHAR(100) NOT NULL,
      note           TEXT,
      enabled        TINYINT(1) DEFAULT 1,
      username       VARCHAR(50) DEFAULT NULL,
      password_hash  VARCHAR(255) DEFAULT NULL,
      role           VARCHAR(10) DEFAULT 'user',
      email          VARCHAR(255) DEFAULT NULL,
      email_verified TINYINT(1) DEFAULT 0,
      created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY idx_users_username (username),
      UNIQUE KEY idx_users_email (email)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await getPool().execute(`
    CREATE TABLE IF NOT EXISTS nodes (
      id              INT AUTO_INCREMENT PRIMARY KEY,
      name            VARCHAR(100) NOT NULL UNIQUE,
      display_name    VARCHAR(100) NOT NULL DEFAULT '',
      type            VARCHAR(20) NOT NULL,
      server          VARCHAR(255) NOT NULL,
      port            INT NOT NULL,
      pubkey          VARCHAR(255) DEFAULT NULL,
      shortid         VARCHAR(64) DEFAULT NULL,
      sni             VARCHAR(255) DEFAULT NULL,
      flow            VARCHAR(50) DEFAULT 'xtls-rprx-vision',
      fingerprint     VARCHAR(20) DEFAULT 'chrome',
      alter_id        INT DEFAULT 0,
      cipher          VARCHAR(20) DEFAULT 'auto',
      network         VARCHAR(10) DEFAULT 'tcp',
      ws_path         VARCHAR(255) DEFAULT '',
      ws_host         VARCHAR(255) DEFAULT '',
      tls             TINYINT(1) DEFAULT 0,
      tls_sni         VARCHAR(255) DEFAULT '',
      skip_cert       TINYINT(1) DEFAULT 0,
      enabled         TINYINT(1) DEFAULT 1,
      sort_order      INT DEFAULT 0,
      api_host        VARCHAR(255) DEFAULT NULL,
      api_port        INT DEFAULT 2088,
      api_token       VARCHAR(255) DEFAULT NULL,
      has_upstream_api TINYINT(1) DEFAULT 0,
      INDEX idx_nodes_sort (sort_order)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await getPool().execute(`
    CREATE TABLE IF NOT EXISTS user_node_uuids (
      id       INT AUTO_INCREMENT PRIMARY KEY,
      user_id  INT NOT NULL,
      node_id  INT NOT NULL,
      uuid     VARCHAR(64) NOT NULL,
      enabled  TINYINT(1) NOT NULL DEFAULT 1,
      UNIQUE KEY uk_user_node (user_id, node_id),
      INDEX idx_user_node_uuids_user (user_id),
      INDEX idx_user_node_uuids_node (node_id),
      CONSTRAINT fk_mapping_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      CONSTRAINT fk_mapping_node FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await getPool().execute(`
    CREATE TABLE IF NOT EXISTS templates (
      id          INT AUTO_INCREMENT PRIMARY KEY,
      name        VARCHAR(100) NOT NULL UNIQUE,
      description TEXT,
      content     MEDIUMTEXT NOT NULL,
      enabled     TINYINT(1) DEFAULT 1,
      created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await getPool().execute(`
    CREATE TABLE IF NOT EXISTS invite_codes (
      id         INT AUTO_INCREMENT PRIMARY KEY,
      code       VARCHAR(16) NOT NULL UNIQUE,
      created_by INT DEFAULT 0,
      used_by    INT DEFAULT NULL,
      used_at    TIMESTAMP NULL DEFAULT NULL,
      enabled    TINYINT(1) DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_invite_codes_code (code)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  await getPool().execute(`
    CREATE TABLE IF NOT EXISTS email_tokens (
      id         INT AUTO_INCREMENT PRIMARY KEY,
      user_id    INT NOT NULL,
      token      VARCHAR(64) NOT NULL UNIQUE,
      type       VARCHAR(10) NOT NULL,
      expires    DATETIME NOT NULL,
      used       TINYINT(1) DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_email_tokens_token (token),
      INDEX idx_email_tokens_user (user_id),
      CONSTRAINT fk_email_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  // 自动插入默认模板
  const existing = await queryOne('SELECT id FROM templates WHERE name = ?', ['default']);
  if (!existing) {
    await execute(
      'INSERT INTO templates (name, description, content) VALUES (?, ?, ?)',
      ['default', '默认完整 Clash.Meta 配置模板', DEFAULT_TEMPLATE_CONTENT]
    );
  }
}

// ── 密码哈希（crypto.scrypt，无外部依赖）──────────────────────────

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 32;

function hashPassword(plain) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(plain, salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P,
  });
  return `scrypt:${SCRYPT_N}:${SCRYPT_R}:${SCRYPT_P}:${salt.toString('hex')}:${hash.toString('hex')}`;
}

function verifyPassword(plain, stored) {
  if (!stored || !stored.startsWith('scrypt:')) return false;
  const parts = stored.split(':');
  if (parts.length !== 6) return false;
  const N = parseInt(parts[1]);
  const r = parseInt(parts[2]);
  const p = parseInt(parts[3]);
  const salt = Buffer.from(parts[4], 'hex');
  const expectedHash = Buffer.from(parts[5], 'hex');
  try {
    const actualHash = crypto.scryptSync(plain, salt, expectedHash.length, { N, r, p });
    if (actualHash.length !== expectedHash.length) return false;
    return crypto.timingSafeEqual(actualHash, expectedHash);
  } catch {
    return false;
  }
}

// ── 会话存储（内存 Map + TTL）──────────────────────────────────────

const SESSION_TTL = 7200 * 1000;
const sessions = new Map();

function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, {
    userId: user.id,
    role: user.role || 'user',
    username: user.username,
    name: user.name,
    expires: Date.now() + SESSION_TTL,
  });
  return token;
}

function getSession(token) {
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() > s.expires) {
    sessions.delete(token);
    return null;
  }
  return s;
}

function deleteSession(token) {
  sessions.delete(token);
}

// ── Users CRUD ──────────────────────────────────────────────────

async function getUsers() {
  return query('SELECT * FROM users ORDER BY id');
}

async function getUserById(id) {
  return queryOne('SELECT * FROM users WHERE id = ?', [id]);
}

async function getUserByToken(token) {
  return queryOne('SELECT * FROM users WHERE token = ?', [token]);
}

async function getUserByName(username) {
  return queryOne('SELECT * FROM users WHERE username = ?', [username]);
}

async function getUserByEmail(email) {
  return queryOne('SELECT * FROM users WHERE email = ?', [email]);
}

async function createUser(opts) {
  if (typeof opts === 'string') {
    opts = { name: opts, note: arguments[1] || '' };
  }
  if (opts.username && typeof opts.username === 'string') {
    opts.username = opts.username.replace(/\s+/g, '');
  }
  const token = crypto.randomBytes(16).toString('hex');
  const passwordHash = opts.password ? hashPassword(opts.password) : null;
  const role = opts.role || 'user';
  const email = opts.email || null;
  const emailVerified = opts.email ? 0 : 1;
  const result = await execute(
    'INSERT INTO users (token, name, note, username, password_hash, role, email, email_verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [token, opts.name, opts.note || '', opts.username || null, passwordHash, role, email, emailVerified]
  );
  return getUserById(result.insertId);
}

async function updateUser(id, fields) {
  const allowed = ['name', 'note', 'enabled', 'username', 'password_hash', 'role', 'email', 'email_verified'];
  const sets = [];
  const vals = [];
  for (const k of allowed) {
    if (fields[k] !== undefined) {
      sets.push(`${k} = ?`);
      vals.push(fields[k]);
    }
  }
  if (sets.length === 0) return getUserById(id);
  vals.push(id);
  await execute(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`, vals);
  return getUserById(id);
}

async function updateUserPassword(id, newPassword) {
  const hash = hashPassword(newPassword);
  await execute('UPDATE users SET password_hash = ? WHERE id = ?', [hash, id]);
  return getUserById(id);
}

async function updateUserRole(id, role) {
  await execute('UPDATE users SET role = ? WHERE id = ?', [role, id]);
  return getUserById(id);
}

async function verifyUserEmail(userId) {
  await execute('UPDATE users SET email_verified = 1 WHERE id = ?', [userId]);
  return getUserById(userId);
}

async function deleteUser(id) {
  await execute('DELETE FROM users WHERE id = ?', [id]);
}

async function batchCreateUsers(users) {
  const results = [];
  for (const u of users) {
    try {
      const created = await createUser(u);
      results.push({ ok: true, user: created });
    } catch (e) {
      results.push({ ok: false, name: u.name, error: e.message });
    }
  }
  return results;
}

// ── Nodes CRUD ──────────────────────────────────────────────────

async function getNodes() {
  return query('SELECT * FROM nodes ORDER BY sort_order, id');
}

async function getNodeById(id) {
  return queryOne('SELECT * FROM nodes WHERE id = ?', [id]);
}

async function getNodeByName(name) {
  return queryOne('SELECT * FROM nodes WHERE name = ?', [name]);
}

async function createNode(data) {
  const allCols = [
    'name', 'display_name', 'type', 'server', 'port',
    'pubkey', 'shortid', 'sni', 'flow', 'fingerprint',
    'alter_id', 'cipher', 'network', 'ws_path', 'ws_host',
    'tls', 'tls_sni', 'skip_cert',
    'enabled', 'sort_order',
    'api_host', 'api_port', 'api_token', 'has_upstream_api',
  ];
  const cols = allCols.filter(c => data[c] !== undefined);
  const vals = cols.map(c => data[c]);
  const placeholders = cols.map(() => '?').join(', ');
  const result = await execute(
    `INSERT INTO nodes (${cols.join(', ')}) VALUES (${placeholders})`, vals
  );
  return getNodeById(result.insertId);
}

async function updateNode(id, fields) {
  const allowed = [
    'name', 'display_name', 'type', 'server', 'port',
    'pubkey', 'shortid', 'sni', 'flow', 'fingerprint',
    'alter_id', 'cipher', 'network', 'ws_path', 'ws_host',
    'tls', 'tls_sni', 'skip_cert',
    'enabled', 'sort_order',
    'api_host', 'api_port', 'api_token', 'has_upstream_api',
  ];
  const sets = [];
  const vals = [];
  for (const k of allowed) {
    if (fields[k] !== undefined) {
      sets.push(`${k} = ?`);
      vals.push(fields[k]);
    }
  }
  if (sets.length === 0) return getNodeById(id);
  vals.push(id);
  await execute(`UPDATE nodes SET ${sets.join(', ')} WHERE id = ?`, vals);
  return getNodeById(id);
}

async function deleteNode(id) {
  await execute('DELETE FROM nodes WHERE id = ?', [id]);
}

// ── User-Node UUID Mappings ─────────────────────────────────────

async function getMappings(userId) {
  return query(`
    SELECT m.*, n.name as node_name, n.display_name, n.type, n.enabled as node_enabled
    FROM user_node_uuids m
    JOIN nodes n ON m.node_id = n.id
    WHERE m.user_id = ?
    ORDER BY n.sort_order, n.id
  `, [userId]);
}

async function getMapping(userId, nodeId) {
  return queryOne(
    'SELECT * FROM user_node_uuids WHERE user_id = ? AND node_id = ?',
    [userId, nodeId]
  );
}

async function upsertMapping(userId, nodeId, uuid) {
  await execute(`
    INSERT INTO user_node_uuids (user_id, node_id, uuid)
    VALUES (?, ?, ?)
    ON DUPLICATE KEY UPDATE uuid = VALUES(uuid)
  `, [userId, nodeId, uuid]);
  return getMapping(userId, nodeId);
}

async function setMappingEnabled(userId, nodeId, enabled) {
  await execute(
    'UPDATE user_node_uuids SET enabled = ? WHERE user_id = ? AND node_id = ?',
    [enabled ? 1 : 0, userId, nodeId]
  );
  return getMapping(userId, nodeId);
}

async function deleteMapping(userId, nodeId) {
  await execute(
    'DELETE FROM user_node_uuids WHERE user_id = ? AND node_id = ?',
    [userId, nodeId]
  );
}

async function getMappingsByNode(nodeId) {
  return query(`
    SELECT m.*, u.name as user_name
    FROM user_node_uuids m
    JOIN users u ON m.user_id = u.id
    WHERE m.node_id = ?
  `, [nodeId]);
}

async function bulkSetMappings(userId) {
  const user = await getUserById(userId);
  if (!user) throw new Error('用户不存在');

  const nodes = await query('SELECT * FROM nodes WHERE enabled = 1 ORDER BY sort_order, id');
  const results = [];

  for (const node of nodes) {
    const existing = await getMapping(userId, node.id);
    if (existing) {
      results.push({ node_id: node.id, node_name: node.name, uuid: existing.uuid, action: 'kept' });
    } else {
      const uuid = crypto.randomUUID();
      await upsertMapping(userId, node.id, uuid);
      results.push({ node_id: node.id, node_name: node.name, uuid, action: 'created' });
    }
  }
  return results;
}

// ── Subscription ────────────────────────────────────────────────

async function getSubscriptionData(userToken) {
  return query(`
    SELECT n.*, m.uuid
    FROM user_node_uuids m
    JOIN nodes n ON m.node_id = n.id
    JOIN users u ON m.user_id = u.id
    WHERE u.token = ? AND u.enabled = 1 AND n.enabled = 1 AND m.enabled = 1
    ORDER BY n.sort_order, n.id
  `, [userToken]);
}

// ── Upstream helpers (供 upstream-sync.js 使用) ─────────────────

async function getUpstreamMappings(userId) {
  return query(`
    SELECT m.uuid, m.node_id,
           n.name as node_name, n.server, n.api_host, n.api_port, n.api_token
    FROM user_node_uuids m
    JOIN nodes n ON m.node_id = n.id
    WHERE m.user_id = ? AND n.has_upstream_api = 1 AND n.enabled = 1
    ORDER BY n.sort_order, n.id
  `, [userId]);
}

async function getUpstreamNode(nodeId) {
  return queryOne(
    'SELECT * FROM nodes WHERE id = ? AND has_upstream_api = 1 AND enabled = 1',
    [nodeId]
  );
}

async function getUpstreamNodes() {
  return query(
    'SELECT * FROM nodes WHERE has_upstream_api = 1 AND enabled = 1 ORDER BY sort_order, id'
  );
}

async function getEnabledUserIds() {
  return query('SELECT id FROM users WHERE enabled = 1 ORDER BY id');
}

// ── Templates CRUD ──────────────────────────────────────────────

async function getTemplates() {
  return query(
    'SELECT id, name, description, enabled, created_at, updated_at FROM templates ORDER BY id'
  );
}

async function getTemplateById(id) {
  return queryOne('SELECT * FROM templates WHERE id = ?', [id]);
}

async function getTemplateByName(name) {
  return queryOne('SELECT * FROM templates WHERE name = ?', [name]);
}

async function createTemplate(data) {
  const result = await execute(
    'INSERT INTO templates (name, description, content) VALUES (?, ?, ?)',
    [data.name, data.description || '', data.content]
  );
  return getTemplateById(result.insertId);
}

async function updateTemplate(id, fields) {
  const allowed = ['name', 'description', 'content', 'enabled'];
  const sets = [];
  const vals = [];
  for (const k of allowed) {
    if (fields[k] !== undefined) {
      sets.push(`${k} = ?`);
      vals.push(fields[k]);
    }
  }
  if (sets.length === 0) return getTemplateById(id);
  vals.push(id);
  await execute(`UPDATE templates SET ${sets.join(', ')} WHERE id = ?`, vals);
  return getTemplateById(id);
}

async function deleteTemplate(id) {
  await execute('DELETE FROM templates WHERE id = ?', [id]);
}

// ── Email Tokens ──────────────────────────────────────────────

async function createEmailToken(userId, type, ttlHours = 24) {
  await execute(
    'UPDATE email_tokens SET used = 1 WHERE user_id = ? AND type = ? AND used = 0',
    [userId, type]
  );
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + ttlHours * 3600 * 1000)
    .toISOString().replace('T', ' ').slice(0, 19);
  await execute(
    'INSERT INTO email_tokens (user_id, token, type, expires) VALUES (?, ?, ?, ?)',
    [userId, token, type, expires]
  );
  return queryOne('SELECT * FROM email_tokens WHERE token = ?', [token]);
}

async function getEmailToken(token) {
  const row = await queryOne('SELECT * FROM email_tokens WHERE token = ?', [token]);
  if (!row) return null;
  if (row.used) return null;
  const exp = new Date(row.expires).getTime();
  if (Date.now() > exp) return null;
  return row;
}

async function useEmailToken(token) {
  const result = await execute(
    'UPDATE email_tokens SET used = 1 WHERE token = ? AND used = 0',
    [token]
  );
  return result.affectedRows > 0;
}

// ── Invite Codes ──────────────────────────────────────────────

const INVITE_CODE_LEN = 8;
const INVITE_CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

async function createInviteCode(createdBy = 0) {
  let code;
  let attempts = 0;
  do {
    code = '';
    const bytes = crypto.randomBytes(INVITE_CODE_LEN);
    for (let i = 0; i < INVITE_CODE_LEN; i++) {
      code += INVITE_CODE_CHARS[bytes[i] % INVITE_CODE_CHARS.length];
    }
    attempts++;
    if (attempts > 10) break;
  } while (await queryOne('SELECT id FROM invite_codes WHERE code = ?', [code]));
  await execute(
    'INSERT INTO invite_codes (code, created_by) VALUES (?, ?)',
    [code, createdBy]
  );
  return queryOne('SELECT * FROM invite_codes WHERE code = ?', [code]);
}

async function batchCreateInviteCodes(count, createdBy = 0) {
  const results = [];
  for (let i = 0; i < count; i++) {
    try {
      results.push(await createInviteCode(createdBy));
    } catch (e) {
      results.push({ error: e.message });
    }
  }
  return results;
}

async function getInviteCode(code) {
  return queryOne('SELECT * FROM invite_codes WHERE code = ?', [code]);
}

async function useInviteCode(code, userId) {
  const result = await execute(
    'UPDATE invite_codes SET used_by = ?, used_at = NOW(), enabled = 0 WHERE code = ? AND used_by IS NULL AND enabled = 1',
    [userId, code]
  );
  return result.affectedRows > 0;
}

async function getInviteCodes() {
  return query('SELECT * FROM invite_codes ORDER BY id DESC');
}

async function getInviteCodeStats() {
  const totalRow = await queryOne('SELECT COUNT(*) as c FROM invite_codes');
  const usedRow = await queryOne('SELECT COUNT(*) as c FROM invite_codes WHERE used_by IS NOT NULL');
  const total = totalRow.c;
  const used = usedRow.c;
  return { total, used, available: total - used };
}

module.exports = {
  initDb,
  getPool,
  query,
  queryOne,
  execute,
  // Password
  hashPassword,
  verifyPassword,
  // Session
  createSession,
  getSession,
  deleteSession,
  // Users
  getUsers,
  getUserById,
  getUserByToken,
  getUserByName,
  getUserByEmail,
  createUser,
  updateUser,
  updateUserPassword,
  updateUserRole,
  verifyUserEmail,
  deleteUser,
  batchCreateUsers,
  // Email Tokens
  createEmailToken,
  getEmailToken,
  useEmailToken,
  // Nodes
  getNodes,
  getNodeById,
  getNodeByName,
  createNode,
  updateNode,
  deleteNode,
  // Mappings
  getMappings,
  getMappingsByNode,
  getMapping,
  upsertMapping,
  setMappingEnabled,
  deleteMapping,
  bulkSetMappings,
  // Subscription
  getSubscriptionData,
  // Upstream helpers
  getUpstreamMappings,
  getUpstreamNode,
  getUpstreamNodes,
  getEnabledUserIds,
  // Templates
  getTemplates,
  getTemplateById,
  getTemplateByName,
  createTemplate,
  updateTemplate,
  deleteTemplate,
  // Invite Codes
  createInviteCode,
  batchCreateInviteCodes,
  getInviteCode,
  useInviteCode,
  getInviteCodes,
  getInviteCodeStats,
};
