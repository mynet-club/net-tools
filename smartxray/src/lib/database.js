/**
 * 数据库模块
 * 封装所有 SQLite 数据库操作
 */

const path = require('path');
const fs = require('fs');

// 检测是否在 bundle 模式下运行
function getBaseDir() {
  const dir = __dirname;
  if (dir.includes('/usr/local/lib/') || dir.includes('\\AppData\\')) {
    const os = require('os');
    return path.join(os.homedir(), '.config', 'smartxray');
  }
  return path.join(dir, '..', '..');
}

// 数据库路径
const DATA_DIR = path.join(getBaseDir(), 'data');
const DB_FILE = path.join(DATA_DIR, 'smartxray.db');

// 兼容旧版：数据库曾直接放在 BASE_DIR 而非 data/ 子目录
// 若新路径无数据库但旧路径有，则自动迁移
const LEGACY_DB = path.join(getBaseDir(), 'smartxray.db');

// 确保数据目录存在
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

if (!fs.existsSync(DB_FILE) && fs.existsSync(LEGACY_DB)) {
  try {
    fs.copyFileSync(LEGACY_DB, DB_FILE);
    console.log(`[database] 已从旧路径迁移数据库: ${LEGACY_DB} → ${DB_FILE}`);
  } catch (e) {
    console.error(`[database] 迁移旧数据库失败: ${e.message}`);
  }
}

// 清理上次崩溃可能残留的 SQLite 锁目录
const LOCK_DIR = `${DB_FILE}.lock`;
try { if (fs.statSync(LOCK_DIR).isDirectory()) fs.rmdirSync(LOCK_DIR); } catch { }

// 加载 node-sqlite3-wasm
let Database;
try {
  const sqlite3 = require('node-sqlite3-wasm');
  Database = sqlite3.Database;
} catch {
  console.error('✗ node-sqlite3-wasm 未安装，请运行: cd smartxray && npm install');
  process.exit(1);
}

// 数据库实例（懒加载）
let _db = null;

/**
 * 获取数据库实例（单例模式）
 * @returns {Database} better-sqlite3 实例
 */
function db() {
  if (!_db) {
    _db = new Database(DB_FILE);
    _db.exec('PRAGMA journal_mode = WAL');
    _db.exec('PRAGMA busy_timeout = 5000');
    initTables();
  }
  return _db;
}

/**
 * 初始化数据库表结构
 */
function initTables() {
  const database = _db;

  // 用户表
  database.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      name       TEXT    NOT NULL UNIQUE,
      port       INTEGER NOT NULL UNIQUE,
      http_port  INTEGER,
      uuid       TEXT,
      protocol   TEXT    DEFAULT 'socks',
      username   TEXT    NOT NULL,
      password   TEXT    NOT NULL,
      tag        TEXT    NOT NULL,
      enabled    INTEGER DEFAULT 1,
      note       TEXT,
      created_at TEXT    DEFAULT (datetime('now')),
      expires_at TEXT
    )
  `);

  // 验证码表（自助申请用）
  database.exec(`
    CREATE TABLE IF NOT EXISTS verifications (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      email      TEXT NOT NULL,
      code       TEXT NOT NULL,
      used       INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL
    )
  `);

  // 设置表
  database.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      key   TEXT PRIMARY KEY,
      value TEXT
    )
  `);
}

/**
 * 获取配置项
 * @param {string} key - 配置键名
 * @param {string} [defaultValue=''] - 默认值
 * @returns {string} 配置值
 */
function getSetting(key, defaultValue = '') {
  const row = db().prepare('SELECT value FROM settings WHERE key=?').get([key]);
  return row ? row.value : defaultValue;
}

/**
 * 设置配置项
 * @param {string} key - 配置键名
 * @param {string} value - 配置值
 */
function setSetting(key, value) {
  db().prepare('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)').run([key, value]);
}

/**
 * 批量获取配置
 * @param {string[]} keys - 配置键名数组
 * @returns {Object} 配置对象
 */
function getSettings(keys) {
  const result = {};
  for (const key of keys) {
    result[key] = getSetting(key);
  }
  return result;
}

/**
 * 批量设置配置
 * @param {Object} settings - 配置对象 { key: value }
 */
function setSettings(settings) {
  const stmt = db().prepare('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)');
  const transaction = db().transaction((items) => {
    for (const [key, value] of Object.entries(items)) {
      stmt.run([key, value]);
    }
  });
  transaction(settings);
}

/**
 * 删除配置项
 * @param {string} key - 配置键名
 */
function deleteSetting(key) {
  db().prepare('DELETE FROM settings WHERE key=?').run([key]);
}

/**
 * 获取所有配置
 * @returns {Object} 所有配置的键值对
 */
function getAllSettings() {
  const rows = db().prepare('SELECT key, value FROM settings').all();
  const result = {};
  for (const row of rows) {
    result[row.key] = row.value;
  }
  return result;
}

// ==================== 用户相关操作 ====================

/**
 * 根据 ID 获取用户
 * @param {number} id - 用户 ID
 * @returns {Object|null} 用户对象
 */
function getUserById(id) {
  return db().prepare('SELECT * FROM users WHERE id=?').get([id]) || null;
}

/**
 * 根据名称获取用户
 * @param {string} name - 用户名称
 * @returns {Object|null} 用户对象
 */
function getUserByName(name) {
  return db().prepare('SELECT * FROM users WHERE name=?').get([name]) || null;
}

/**
 * 根据用户名和密码获取用户
 * @param {string} username - 用户名
 * @param {string} password - 密码
 * @returns {Object|null} 用户对象
 */
function getUserByCredentials(username, password) {
  return db().prepare('SELECT * FROM users WHERE username=? AND password=? AND enabled=1').get([username, password]) || null;
}

/**
 * 获取所有用户
 * @param {Object} [options] - 查询选项
 * @param {string} [options.orderBy='port'] - 排序字段
 * @param {boolean} [options.enabledOnly=false] - 只返回启用的用户
 * @returns {Array} 用户数组
 */
function getAllUsers(options = {}) {
  const { orderBy = 'port', enabledOnly = false } = options;
  let sql = 'SELECT * FROM users';
  if (enabledOnly) sql += ' WHERE enabled=1';
  sql += ` ORDER BY ${orderBy}`;
  return db().prepare(sql).all();
}

/**
 * 创建用户
 * @param {Object} userData - 用户数据
 * @returns {Object} 创建的用户
 */
function createUser(userData) {
  const {
    name, port, http_port, uuid, protocol = 'socks',
    username, password, tag, expires_at = null, note = null
  } = userData;

  const result = db().prepare(`
    INSERT INTO users (name, port, http_port, uuid, protocol, username, password, tag, expires_at, note)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run([name, port, http_port, uuid, protocol, username, password, tag, expires_at, note]);

  return getUserById(result.lastInsertRowid);
}

/**
 * 更新用户
 * @param {number} id - 用户 ID
 * @param {Object} data - 更新数据
 * @returns {Object|null} 更新后的用户
 */
function updateUser(id, data) {
  const fields = [];
  const values = [];

  for (const [key, value] of Object.entries(data)) {
    if (['name', 'port', 'http_port', 'uuid', 'protocol', 'username', 'password', 'tag', 'enabled', 'note', 'expires_at'].includes(key)) {
      fields.push(`${key}=?`);
      values.push(value);
    }
  }

  if (fields.length === 0) return getUserById(id);

  values.push(id);
  db().prepare(`UPDATE users SET ${fields.join(',')} WHERE id=?`).run(values);
  return getUserById(id);
}

/**
 * 删除用户
 * @param {number} id - 用户 ID
 * @returns {boolean} 是否删除成功
 */
function deleteUser(id) {
  const result = db().prepare('DELETE FROM users WHERE id=?').run([id]);
  return result.changes > 0;
}

/**
 * 获取过期用户
 * @returns {Array} 过期用户数组
 */
function getExpiredUsers() {
  const now = new Date().toISOString();
  return db().prepare('SELECT * FROM users WHERE expires_at IS NOT NULL AND expires_at < ?').all([now]);
}

/**
 * 获取需要 UUID 的用户
 * @returns {Array} 用户数组
 */
function getUsersWithoutUuid() {
  return db().prepare("SELECT id, uuid FROM users WHERE uuid IS NULL OR uuid = ''").all();
}

/**
 * 为用户分配 UUID
 * @param {number} id - 用户 ID
 * @param {string} uuid - UUID 值
 */
function assignUserUuid(id, uuid) {
  db().prepare('UPDATE users SET uuid=? WHERE id=?').run([uuid, id]);
}

// ==================== 验证码相关操作 ====================

/**
 * 创建验证码
 * @param {string} email - 邮箱
 * @param {string} code - 验证码
 * @param {string} expiresAt - 过期时间
 */
function createVerification(email, code, expiresAt) {
  // 清理同邮箱旧验证码
  db().prepare('DELETE FROM verifications WHERE email=? AND used=0').run([email]);
  db().prepare('INSERT INTO verifications(email,code,expires_at) VALUES(?,?,?)').run([email, code, expiresAt]);
}

/**
 * 验证验证码
 * @param {string} email - 邮箱
 * @param {string} code - 验证码
 * @returns {Object|null} 验证记录
 */
function verifyCode(email, code) {
  const now = new Date().toISOString();
  const rec = db().prepare(
    'SELECT * FROM verifications WHERE email=? AND code=? AND used=0 AND expires_at>?'
  ).get([email, code, now]);

  if (rec) {
    db().prepare('UPDATE verifications SET used=1 WHERE id=?').run([rec.id]);
  }
  return rec || null;
}

/**
 * 清理过期验证码
 */
function cleanupExpiredVerifications() {
  const now = new Date().toISOString();
  db().prepare('DELETE FROM verifications WHERE expires_at < ?').run([now]);
}

// ==================== 数据库维护 ====================

/**
 * 关闭数据库连接
 */
function closeDb() {
  if (_db) {
    _db.close();
    _db = null;
  }
}

/**
 * 备份数据库
 * @param {string} backupPath - 备份路径
 */
function backupDb(backupPath) {
  if (_db) {
    _db.backup(backupPath);
  }
}

/**
 * 获取数据库统计信息
 * @returns {Object} 统计信息
 */
function getStats() {
  const userCount = db().prepare('SELECT COUNT(*) as count FROM users').get().count;
  const enabledCount = db().prepare('SELECT COUNT(*) as count FROM users WHERE enabled=1').get().count;
  const expiredCount = getExpiredUsers().length;
  const verificationCount = db().prepare('SELECT COUNT(*) as count FROM verifications WHERE used=0').get().count;

  return {
    users: {
      total: userCount,
      enabled: enabledCount,
      disabled: userCount - enabledCount,
      expired: expiredCount
    },
    verifications: {
      pending: verificationCount
    }
  };
}

module.exports = {
  // 数据库实例
  db,
  closeDb,
  backupDb,
  getStats,

  // 配置操作
  getSetting,
  setSetting,
  getSettings,
  setSettings,
  deleteSetting,
  getAllSettings,

  // 用户操作
  getUserById,
  getUserByName,
  getUserByCredentials,
  getAllUsers,
  createUser,
  updateUser,
  deleteUser,
  getExpiredUsers,
  getUsersWithoutUuid,
  assignUserUuid,

  // 验证码操作
  createVerification,
  verifyCode,
  cleanupExpiredVerifications
};