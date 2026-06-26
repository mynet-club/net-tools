/**
 * 数据库模块
 * 封装所有 SQLite 数据库操作
 */

'use strict';

const path   = require('path');
const fs     = require('fs');
const crypto = require('crypto');

const { getBaseDir } = require('./paths');

const BASE_DIR  = getBaseDir();
const DATA_DIR  = path.join(BASE_DIR, 'data');
const DB_FILE   = path.join(DATA_DIR, 'subserver.db');

// 确保数据目录存在
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// 清理上次崩溃可能残留的 SQLite 锁目录
const LOCK_DIR = `${DB_FILE}.lock`;
try { if (fs.statSync(LOCK_DIR).isDirectory()) fs.rmdirSync(LOCK_DIR); } catch { }


// ── 加载 node-sqlite3-wasm ──────────────────────────────────────
let Database;
try {
  const sqlite3 = require('node-sqlite3-wasm');
  Database = sqlite3.Database;
} catch {
  console.error('✗ node-sqlite3-wasm 未安装，请运行: cd subserver && npm install');
  process.exit(1);
}

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

// ── 初始化数据库 ────────────────────────────────────────────────
let _db;

function db() {
  if (!_db) {
    _db = new Database(DB_FILE);
    _db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;
    `);
    initSchema();
  }
  return _db;
}

/**
 * 初始化数据库 schema
 */
function initSchema() {
  _db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      token      TEXT NOT NULL UNIQUE,
      name       TEXT NOT NULL,
      note       TEXT DEFAULT '',
      enabled    INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS nodes (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      name          TEXT NOT NULL UNIQUE,
      display_name  TEXT NOT NULL,
      type          TEXT NOT NULL CHECK(type IN ('vless-reality','vmess')),
      server        TEXT NOT NULL,
      port          INTEGER NOT NULL,
      -- VLESS Reality
      pubkey        TEXT,
      shortid       TEXT,
      sni           TEXT,
      flow          TEXT DEFAULT 'xtls-rprx-vision',
      fingerprint   TEXT DEFAULT 'chrome',
      -- VMess
      alter_id      INTEGER DEFAULT 0,
      cipher        TEXT DEFAULT 'auto',
      network       TEXT DEFAULT 'tcp',
      ws_path       TEXT DEFAULT '',
      ws_host       TEXT DEFAULT '',
      tls           INTEGER DEFAULT 0,
      tls_sni       TEXT DEFAULT '',
      skip_cert     INTEGER DEFAULT 0,
      -- 通用
      enabled       INTEGER DEFAULT 1,
      sort_order    INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS user_node_uuids (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      node_id  INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
      uuid     TEXT NOT NULL,
      UNIQUE(user_id, node_id)
    );

    CREATE INDEX IF NOT EXISTS idx_user_node_uuids_user
      ON user_node_uuids(user_id);
    CREATE INDEX IF NOT EXISTS idx_user_node_uuids_node
      ON user_node_uuids(node_id);
    CREATE INDEX IF NOT EXISTS idx_nodes_sort
      ON nodes(sort_order);

    CREATE TABLE IF NOT EXISTS templates (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT NOT NULL UNIQUE,
      description TEXT DEFAULT '',
      content     TEXT NOT NULL,
      enabled     INTEGER DEFAULT 1,
      created_at  TEXT DEFAULT (datetime('now')),
      updated_at  TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS invite_codes (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      code       TEXT NOT NULL UNIQUE,
      created_by INTEGER DEFAULT 0,
      used_by    INTEGER,
      used_at    TEXT,
      enabled    INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_invite_codes_code
      ON invite_codes(code);

    CREATE TABLE IF NOT EXISTS email_tokens (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token      TEXT NOT NULL UNIQUE,
      type       TEXT NOT NULL CHECK(type IN ('verify','reset')),
      expires    TEXT NOT NULL,
      used       INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_email_tokens_token ON email_tokens(token);
    CREATE INDEX IF NOT EXISTS idx_email_tokens_user ON email_tokens(user_id);
  `);

  // ── 迁移：为 users 表新增 username / password_hash / role 列 ──
  const cols = _db.prepare('PRAGMA table_info(users)').all();
  const colNames = cols.map(c => c.name);
  if (!colNames.includes('username')) {
    _db.exec('ALTER TABLE users ADD COLUMN username TEXT');
  }
  if (!colNames.includes('password_hash')) {
    _db.exec('ALTER TABLE users ADD COLUMN password_hash TEXT');
  }
  if (!colNames.includes('role')) {
    _db.exec("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'");
  }
  // 唯一索引（允许 NULL，即旧用户暂无 username 时不冲突）
  _db.exec(
    'CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username) WHERE username IS NOT NULL'
  );

  // ── 迁移：为 users 表新增 email / email_verified 列 ──
  if (!colNames.includes('email')) {
    _db.exec('ALTER TABLE users ADD COLUMN email TEXT');
  }
  if (!colNames.includes('email_verified')) {
    _db.exec('ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0');
  }
  // email 唯一索引（允许 NULL / 空）
  _db.exec(
    'CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL AND email != \'\''
  );

  // ── 迁移：为 nodes 表新增上游 API 字段 ──
  const nodeCols = _db.prepare('PRAGMA table_info(nodes)').all();
  const nodeColNames = nodeCols.map(c => c.name);
  if (!nodeColNames.includes('api_host')) {
    _db.exec('ALTER TABLE nodes ADD COLUMN api_host TEXT');
  }
  if (!nodeColNames.includes('api_port')) {
    _db.exec('ALTER TABLE nodes ADD COLUMN api_port INTEGER DEFAULT 2088');
  }
  if (!nodeColNames.includes('api_token')) {
    _db.exec('ALTER TABLE nodes ADD COLUMN api_token TEXT');
  }
  if (!nodeColNames.includes('has_upstream_api')) {
    _db.exec('ALTER TABLE nodes ADD COLUMN has_upstream_api INTEGER DEFAULT 0');
  }

  // 自动插入默认模板
  const existing = _db.prepare('SELECT id FROM templates WHERE name = ?').get('default');
  if (!existing) {
    _db.prepare(
      'INSERT INTO templates (name, description, content) VALUES (?, ?, ?)'
    ).run(['default', '默认完整 Clash.Meta 配置模板', DEFAULT_TEMPLATE_CONTENT]);
  }
}

// ── 密码哈希（crypto.scrypt，无外部依赖）──────────────────────────

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 32;

/**
 * 哈希密码
 * @param {string} plain — 明文密码
 * @returns {string} 格式: "scrypt:N:r:p:saltHex:hashHex"
 */
function hashPassword(plain) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(plain, salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P,
  });
  return `scrypt:${SCRYPT_N}:${SCRYPT_R}:${SCRYPT_P}:${salt.toString('hex')}:${hash.toString('hex')}`;
}

/**
 * 验证密码（时序安全）
 * @param {string} plain — 明文密码
 * @param {string} stored — 存储的哈希字符串
 * @returns {boolean}
 */
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

const SESSION_TTL = 7200 * 1000; // 2 小时（毫秒）
const sessions = new Map(); // sessionToken → { userId, role, username, name, expires }

/**
 * 创建会话
 * @param {Object} user — 用户对象（含 id, role, username, name）
 * @returns {string} sessionToken
 */
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

/**
 * 获取会话（自动清理过期）
 * @param {string} token — sessionToken
 * @returns {Object|null}
 */
function getSession(token) {
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() > s.expires) {
    sessions.delete(token);
    return null;
  }
  return s;
}

/**
 * 删除会话
 * @param {string} token — sessionToken
 */
function deleteSession(token) {
  sessions.delete(token);
}

// ── Users CRUD ──────────────────────────────────────────────────

function getUsers() {
  return db().prepare('SELECT * FROM users ORDER BY id').all();
}

function getUserById(id) {
  return db().prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function getUserByToken(token) {
  return db().prepare('SELECT * FROM users WHERE token = ?').get(token);
}

function getUserByName(username) {
  return db().prepare('SELECT * FROM users WHERE username = ?').get(username);
}

/**
 * 创建用户
 * @param {Object} opts — { name, username, password, note, role }
 * @returns {Object} 创建的用户
 */
function createUser(opts) {
  // 兼容旧签名 createUser(name, note)
  if (typeof opts === 'string') {
    opts = { name: opts, note: arguments[1] || '' };
  }
  // 防御性清洗：确保用户名不含空白字符
  if (opts.username && typeof opts.username === 'string') {
    opts.username = opts.username.replace(/\s+/g, '');
  }
  const token = crypto.randomBytes(16).toString('hex');
  const passwordHash = opts.password ? hashPassword(opts.password) : null;
  const role = opts.role || 'user';
  const email = opts.email || null;
  const emailVerified = opts.email ? 0 : 1; // 有邮箱则需验证，无邮箱则默认已验证
  // node-sqlite3-wasm 的 .run()/.get() 不支持多位置参数，需传数组
  const info = db().prepare(
    'INSERT INTO users (token, name, note, username, password_hash, role, email, email_verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run([token, opts.name, opts.note || '', opts.username || null, passwordHash, role, email, emailVerified]);
  return getUserById(info.lastInsertRowid);
}

function updateUser(id, fields) {
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
  db().prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(vals);
  return getUserById(id);
}

/**
 * 更新用户密码
 * @param {number} id — 用户 ID
 * @param {string} newPassword — 新明文密码
 */
function updateUserPassword(id, newPassword) {
  const hash = hashPassword(newPassword);
  db().prepare('UPDATE users SET password_hash = ? WHERE id = ?').run([hash, id]);
  return getUserById(id);
}

/**
 * 更新用户角色
 * @param {number} id — 用户 ID
 * @param {string} role — 'admin' 或 'user'
 */
function updateUserRole(id, role) {
  db().prepare('UPDATE users SET role = ? WHERE id = ?').run([role, id]);
  return getUserById(id);
}

function deleteUser(id) {
  db().prepare('DELETE FROM users WHERE id = ?').run(id);
}

/**
 * 批量创建用户
 * @param {Array} users — [{ name, note }] 数组
 * @returns {Array} 创建结果
 */
function batchCreateUsers(users) {
  const results = [];
  for (const u of users) {
    try {
      const created = createUser(u);
      results.push({ ok: true, user: created });
    } catch (e) {
      results.push({ ok: false, name: u.name, error: e.message });
    }
  }
  return results;
}

// ── Nodes CRUD ──────────────────────────────────────────────────

function getNodes() {
  return db().prepare('SELECT * FROM nodes ORDER BY sort_order, id').all();
}

function getNodeById(id) {
  return db().prepare('SELECT * FROM nodes WHERE id = ?').get(id);
}

function getNodeByName(name) {
  return db().prepare('SELECT * FROM nodes WHERE name = ?').get(name);
}

function createNode(data) {
  // 只插入已提供的字段，未提供的字段由 schema DEFAULT 填充
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
  const info = db().prepare(
    `INSERT INTO nodes (${cols.join(', ')}) VALUES (${placeholders})`
  ).run(vals);
  return getNodeById(info.lastInsertRowid);
}

function updateNode(id, fields) {
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
  db().prepare(`UPDATE nodes SET ${sets.join(', ')} WHERE id = ?`).run(vals);
  return getNodeById(id);
}

function deleteNode(id) {
  db().prepare('DELETE FROM nodes WHERE id = ?').run(id);
}

// ── User-Node UUID Mappings ─────────────────────────────────────

function getMappings(userId) {
  return db().prepare(`
    SELECT m.*, n.name as node_name, n.display_name, n.type, n.enabled as node_enabled
    FROM user_node_uuids m
    JOIN nodes n ON m.node_id = n.id
    WHERE m.user_id = ?
    ORDER BY n.sort_order, n.id
  `).all(userId);
}

function getMapping(userId, nodeId) {
  return db().prepare(
    'SELECT * FROM user_node_uuids WHERE user_id = ? AND node_id = ?'
  ).get([userId, nodeId]);
}

function upsertMapping(userId, nodeId, uuid) {
  db().prepare(`
    INSERT INTO user_node_uuids (user_id, node_id, uuid)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id, node_id) DO UPDATE SET uuid = excluded.uuid
  `).run([userId, nodeId, uuid]);
  return getMapping(userId, nodeId);
}

function deleteMapping(userId, nodeId) {
  db().prepare(
    'DELETE FROM user_node_uuids WHERE user_id = ? AND node_id = ?'
  ).run([userId, nodeId]);
}

/**
 * 批量为用户设置所有启用节点的 UUID
 * 已有 UUID 的保留，缺失的自动生成
 */
function bulkSetMappings(userId) {
  const user = getUserById(userId);
  if (!user) throw new Error('用户不存在');

  const nodes = db().prepare('SELECT * FROM nodes WHERE enabled = 1 ORDER BY sort_order, id').all();
  const results = [];

  for (const node of nodes) {
    const existing = getMapping(userId, node.id);
    if (existing) {
      results.push({ node_id: node.id, node_name: node.name, uuid: existing.uuid, action: 'kept' });
    } else {
      const uuid = crypto.randomUUID();
      upsertMapping(userId, node.id, uuid);
      results.push({ node_id: node.id, node_name: node.name, uuid, action: 'created' });
    }
  }
  return results;
}

/**
 * 获取用户订阅所需的所有节点 + UUID
 */
function getSubscriptionData(userToken) {
  return db().prepare(`
    SELECT n.*, m.uuid
    FROM user_node_uuids m
    JOIN nodes n ON m.node_id = n.id
    JOIN users u ON m.user_id = u.id
    WHERE u.token = ? AND u.enabled = 1 AND n.enabled = 1
    ORDER BY n.sort_order, n.id
  `).all(userToken);
}

// ── Templates CRUD ──────────────────────────────────────────────

function getTemplates() {
  return db().prepare(
    'SELECT id, name, description, enabled, created_at, updated_at FROM templates ORDER BY id'
  ).all();
}

function getTemplateById(id) {
  return db().prepare('SELECT * FROM templates WHERE id = ?').get(id);
}

function getTemplateByName(name) {
  return db().prepare('SELECT * FROM templates WHERE name = ?').get(name);
}

function createTemplate(data) {
  const info = db().prepare(
    'INSERT INTO templates (name, description, content) VALUES (?, ?, ?)'
  ).run([data.name, data.description || '', data.content]);
  return getTemplateById(info.lastInsertRowid);
}

function updateTemplate(id, fields) {
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
  sets.push(`updated_at = datetime('now')`);
  vals.push(id);
  db().prepare(`UPDATE templates SET ${sets.join(', ')} WHERE id = ?`).run(vals);
  return getTemplateById(id);
}

function deleteTemplate(id) {
  db().prepare('DELETE FROM templates WHERE id = ?').run(id);
}

// ── Email Tokens ──────────────────────────────────────────────

/**
 * 创建邮箱令牌（验证 / 重置密码）
 * @param {number} userId - 用户 ID
 * @param {string} type - 'verify' | 'reset'
 * @param {number} ttlHours - 有效期（小时）
 * @returns {Object} 含 token 字段的记录
 */
function createEmailToken(userId, type, ttlHours = 24) {
  // 使该用户同类型的旧令牌全部失效
  db().prepare(
    'UPDATE email_tokens SET used = 1 WHERE user_id = ? AND type = ? AND used = 0'
  ).run([userId, type]);

  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + ttlHours * 3600 * 1000)
    .toISOString().replace('T', ' ').slice(0, 19);
  db().prepare(
    'INSERT INTO email_tokens (user_id, token, type, expires) VALUES (?, ?, ?, ?)'
  ).run([userId, token, type, expires]);
  return db().prepare('SELECT * FROM email_tokens WHERE token = ?').get(token);
}

/**
 * 查询令牌（须未使用且未过期）
 * @param {string} token
 * @returns {Object|null}
 */
function getEmailToken(token) {
  const row = db().prepare('SELECT * FROM email_tokens WHERE token = ?').get(token);
  if (!row) return null;
  if (row.used) return null;
  // 检查过期
  const exp = new Date(row.expires.replace(' ', 'T') + 'Z').getTime();
  if (Date.now() > exp) return null;
  return row;
}

/**
 * 使用令牌（标记为已用，返回是否成功）
 * @param {string} token
 * @returns {boolean}
 */
function useEmailToken(token) {
  const info = db().prepare(
    'UPDATE email_tokens SET used = 1 WHERE token = ? AND used = 0'
  ).run([token]);
  return info.changes > 0;
}

/**
 * 按邮箱查找用户
 * @param {string} email
 * @returns {Object|null}
 */
function getUserByEmail(email) {
  return db().prepare('SELECT * FROM users WHERE email = ?').get(email);
}

/**
 * 标记用户邮箱已验证
 * @param {number} userId
 */
function verifyUserEmail(userId) {
  db().prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run([userId]);
  return getUserById(userId);
}

// ── Invite Codes ──────────────────────────────────────────────

const INVITE_CODE_LEN = 8;
const INVITE_CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 去除易混淆字符

/**
 * 生成单个邀请码
 * @returns {string} 8位随机邀请码
 */
function createInviteCode(createdBy = 0) {
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
  } while (db().prepare('SELECT id FROM invite_codes WHERE code = ?').get(code));
  db().prepare(
    'INSERT INTO invite_codes (code, created_by) VALUES (?, ?)'
  ).run([code, createdBy]);
  return db().prepare('SELECT * FROM invite_codes WHERE code = ?').get(code);
}

/**
 * 批量生成邀请码
 * @param {number} count — 生成数量
 * @param {number} createdBy — 创建者用户 ID
 * @returns {Array} 生成的邀请码列表
 */
function batchCreateInviteCodes(count, createdBy = 0) {
  const results = [];
  for (let i = 0; i < count; i++) {
    try {
      results.push(createInviteCode(createdBy));
    } catch (e) {
      results.push({ error: e.message });
    }
  }
  return results;
}

/**
 * 查询邀请码
 * @param {string} code — 邀请码
 * @returns {Object|null}
 */
function getInviteCode(code) {
  return db().prepare('SELECT * FROM invite_codes WHERE code = ?').get(code);
}

/**
 * 使用邀请码（标记为已使用）
 * @param {string} code — 邀请码
 * @param {number} userId — 使用者用户 ID
 * @returns {boolean} 是否成功
 */
function useInviteCode(code, userId) {
  const info = db().prepare(
    'UPDATE invite_codes SET used_by = ?, used_at = datetime(\'now\'), enabled = 0 WHERE code = ? AND used_by IS NULL AND enabled = 1'
  ).run([userId, code]);
  return info.changes > 0;
}

/**
 * 获取所有邀请码
 * @returns {Array}
 */
function getInviteCodes() {
  return db().prepare('SELECT * FROM invite_codes ORDER BY id DESC').all();
}

/**
 * 获取邀请码统计
 * @returns {Object} { total, used, available }
 */
function getInviteCodeStats() {
  const total = db().prepare('SELECT COUNT(*) as c FROM invite_codes').get().c;
  const used = db().prepare('SELECT COUNT(*) as c FROM invite_codes WHERE used_by IS NOT NULL').get().c;
  return { total, used, available: total - used };
}

module.exports = {
  db,
  DB_FILE,
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
  getMapping,
  upsertMapping,
  deleteMapping,
  bulkSetMappings,
  // Subscription
  getSubscriptionData,
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
