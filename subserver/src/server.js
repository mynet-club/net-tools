#!/usr/bin/env node
/**
 * subserver — 订阅分发服务
 * HTTP 入口 + 路由分发
 */

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

// 版本号（与 package.json 保持一致）
const VERSION = '1.5.2';

const { config, requireAuth, requireAdmin } = require('./auth');
const { apiResponse, parseBody } = require('./utils');
const mailer = require('./mailer');

// UI 静态文件目录
// bundle 模式: __dirname/ui (UI 文件随 bundle 一起安装)
// 开发模式: __dirname/../ui (UI 文件在项目根目录)
const isBundle = __dirname.includes('/usr/local/lib/') || __dirname.includes('\\AppData\\');
const UI_DIR = isBundle ? path.join(__dirname, 'ui') : path.join(__dirname, '..', 'ui');

// 路由模块
const sub = require('./routes/sub');
const authRt = require('./routes/auth');
const me = require('./routes/me');
const users = require('./routes/users');
const nodes = require('./routes/nodes');
const mappings = require('./routes/mappings');
const templates = require('./routes/templates');
const register = require('./routes/register');
const { getUserTraffic, syncAll } = require('./upstream-sync');

// 初始化数据库（确保 schema 就绪）
const { initDb } = require('./db');

// 初始化邮件模块配置
mailer.init(config);

// ── 路由分发 ────────────────────────────────────────────────────
async function handleRequest(req, res) {
  const url = new URL(req.url, `http://localhost:${config.port}`);
  const pathname = url.pathname;
  const method = req.method;

  // CORS 预检
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    });
    return res.end();
  }

  // 解析请求体（非 GET 请求）
  let json = {};
  if (method !== 'GET') {
    try {
      json = await parseBody(req);
    } catch (e) {
      if (e.message === 'BODY_TOO_LARGE') {
        return apiResponse(res, 413, { error: '请求体过大（最大 1MB）' });
      }
      return apiResponse(res, 400, { error: '请求体 JSON 解析失败' });
    }
  }

  // ── 公开接口 ──────────────────────────────────────────────────

  // GET /health
  if (method === 'GET' && pathname === '/health') {
    return sub.handleHealth(req, res);
  }

  // GET /sub/:token — 订阅接口（无需 Admin 认证）
  if (method === 'GET' && pathname.startsWith('/sub/')) {
    return sub.handleSub(req, res, pathname);
  }

  // ── 认证 API ──────────────────────────────────────────────────
  // POST /api/auth/login — 公开接口
  if (method === 'POST' && pathname === '/api/auth/login') {
    return authRt.handleLogin(req, res, json);
  }

  // POST /api/auth/register — 公开接口（需邀请码 + 邮箱）
  if (method === 'POST' && pathname === '/api/auth/register') {
    return register.handleRegister(req, res, json);
  }

  // GET /api/auth/verify?token=xxx — 公开接口（邮箱验证激活）
  if (method === 'GET' && pathname === '/api/auth/verify') {
    return register.handleVerify(req, res, url);
  }

  // POST /api/auth/forgot-password — 公开接口（发送重置邮件）
  if (method === 'POST' && pathname === '/api/auth/forgot-password') {
    return authRt.handleForgotPassword(req, res, json);
  }

  // POST /api/auth/reset-password — 公开接口（凭令牌重置密码）
  if (method === 'POST' && pathname === '/api/auth/reset-password') {
    return authRt.handleResetPassword(req, res, json);
  }

  // 其余 /api/ 路由需要认证
  if (pathname.startsWith('/api/')) {
    // ── Auth（需登录）───────────────────────────────────────
    // POST /api/auth/logout
    if (method === 'POST' && pathname === '/api/auth/logout') {
      const a = requireAuth(req);
      if (!a.ok) return apiResponse(res, a.code, { error: a.error });
      return authRt.handleLogout(req, res);
    }
    // GET /api/auth/me
    if (method === 'GET' && pathname === '/api/auth/me') {
      const a = requireAuth(req);
      if (!a.ok) return apiResponse(res, a.code, { error: a.error });
      return authRt.handleMe(req, res);
    }

    // ── 用户自助路由（需登录）────────────────────────────────
    // GET /api/me/subscription
    if (method === 'GET' && pathname === '/api/me/subscription') {
      const a = requireAuth(req);
      if (!a.ok) return apiResponse(res, a.code, { error: a.error });
      return me.handleSubscription(req, res);
    }
    // GET /api/me/mappings
    if (method === 'GET' && pathname === '/api/me/mappings') {
      const a = requireAuth(req);
      if (!a.ok) return apiResponse(res, a.code, { error: a.error });
      return me.handleMappings(req, res);
    }

    // ── Templates（GET 所有登录用户可用，POST/PUT/DELETE 需管理员）──
    // GET /api/templates
    if (method === 'GET' && pathname === '/api/templates') {
      const a = requireAuth(req);
      if (!a.ok) return apiResponse(res, a.code, { error: a.error });
      return templates.handleList(req, res);
    }
    // POST /api/templates — 需管理员
    if (method === 'POST' && pathname === '/api/templates') {
      const a = requireAdmin(req);
      if (!a.ok) return apiResponse(res, a.code, { error: a.error });
      return templates.handleCreate(req, res, json);
    }

    // /api/templates/:id（含 /content 子路径）
    const tplMatch = pathname.match(/^\/api\/templates\/(\d+)(\/content)?$/);
    if (tplMatch) {
      const id = parseInt(tplMatch[1]);
      // GET 需登录，PUT/DELETE 需管理员
      if (method === 'GET') {
        const a = requireAuth(req);
        if (!a.ok) return apiResponse(res, a.code, { error: a.error });
        if (tplMatch[2] === '/content') return templates.handleContent(req, res, id);
        return templates.handleGet(req, res, id);
      }
      const a = requireAdmin(req);
      if (!a.ok) return apiResponse(res, a.code, { error: a.error });
      if (method === 'PUT') return templates.handleUpdate(req, res, id, json);
      if (method === 'DELETE') return templates.handleDelete(req, res, id);
    }

    // ── 以下路由需管理员权限 ──────────────────────────────────
    const adminAuth = requireAdmin(req);
    if (!adminAuth.ok) {
      return apiResponse(res, adminAuth.code, { error: adminAuth.error });
    }

    // ── Users ──────────────────────────────────────────────────
    // GET /api/users
    if (method === 'GET' && pathname === '/api/users') {
      return users.handleList(req, res);
    }
    // POST /api/users/batch
    if (method === 'POST' && pathname === '/api/users/batch') {
      return users.handleBatchCreate(req, res, json);
    }
    // POST /api/users
    if (method === 'POST' && pathname === '/api/users') {
      return users.handleCreate(req, res, json);
    }

    // /api/users/:id
    const userMatch = pathname.match(/^\/api\/users\/(\d+)$/);
    if (userMatch) {
      const id = parseInt(userMatch[1]);
      if (method === 'GET') return users.handleGet(req, res, id);
      if (method === 'PUT') return users.handleUpdate(req, res, id, json);
      if (method === 'DELETE') return users.handleDelete(req, res, id);
    }

    // ── Nodes ──────────────────────────────────────────────────
    // GET /api/nodes
    if (method === 'GET' && pathname === '/api/nodes') {
      return nodes.handleList(req, res);
    }
    // POST /api/nodes
    if (method === 'POST' && pathname === '/api/nodes') {
      return nodes.handleCreate(req, res, json);
    }

    // /api/nodes/:id
    const nodeMatch = pathname.match(/^\/api\/nodes\/(\d+)$/);
    if (nodeMatch) {
      const id = parseInt(nodeMatch[1]);
      if (method === 'GET') return nodes.handleGet(req, res, id);
      if (method === 'PUT') return nodes.handleUpdate(req, res, id, json);
      if (method === 'DELETE') return nodes.handleDelete(req, res, id);
    }

    // ── Mappings ──────────────────────────────────────────────
    // POST /api/mappings/:userId/bulk
    const bulkMatch = pathname.match(/^\/api\/mappings\/(\d+)\/bulk$/);
    if (method === 'POST' && bulkMatch) {
      return mappings.handleBulk(req, res, parseInt(bulkMatch[1]));
    }

    // GET /api/mappings/:userId
    const mapListMatch = pathname.match(/^\/api\/mappings\/(\d+)$/);
    if (method === 'GET' && mapListMatch) {
      return mappings.handleList(req, res, parseInt(mapListMatch[1]));
    }
    // POST /api/mappings/:userId
    if (method === 'POST' && mapListMatch) {
      return mappings.handleCreate(req, res, parseInt(mapListMatch[1]), json);
    }

    // DELETE /api/mappings/:userId/:nodeId
    const mapDelMatch = pathname.match(/^\/api\/mappings\/(\d+)\/(\d+)$/);
    if (method === 'DELETE' && mapDelMatch) {
      return mappings.handleDelete(req, res, parseInt(mapDelMatch[1]), parseInt(mapDelMatch[2]));
    }
    // PATCH /api/mappings/:userId/:nodeId
    if (method === 'PATCH' && mapDelMatch) {
      return mappings.handleToggle(req, res, parseInt(mapDelMatch[1]), parseInt(mapDelMatch[2]), json);
    }

    // ── Invite Codes（管理员）─────────────────────────────────
    // GET /api/invite-codes
    if (method === 'GET' && pathname === '/api/invite-codes') {
      return register.handleListCodes(req, res);
    }
    // POST /api/invite-codes
    if (method === 'POST' && pathname === '/api/invite-codes') {
      return register.handleCreateCodes(req, res, json);
    }

    // ── 流量查询 ──────────────────────────────────────────────
    // GET /api/traffic/:userId — 单个用户在所有上游节点的流量
    const trafficMatch = pathname.match(/^\/api\/traffic\/(\d+)$/);
    if (method === 'GET' && trafficMatch) {
      const userId = parseInt(trafficMatch[1]);
      const result = await getUserTraffic(userId);
      return apiResponse(res, 200, result);
    }

    // ── 上游同步管理 ──────────────────────────────────────────
    // POST /api/upstream/sync — 手动触发全量重新同步
    if (method === 'POST' && pathname === '/api/upstream/sync') {
      const result = await syncAll();
      return apiResponse(res, 200, result);
    }

    // 404
    return apiResponse(res, 404, { error: 'API 端点不存在' });
  }

  // ── 静态文件：管理界面 ──────────────────────────────────────
  // GET / 或 /admin → 返回 index.html
  if (method === 'GET' && (pathname === '/' || pathname === '/admin' || pathname === '/index.html' || pathname === '/verify' || pathname === '/reset-password')) {
    const htmlFile = path.join(UI_DIR, 'index.html');
    if (fs.existsSync(htmlFile)) {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'X-Content-Type-Options': 'nosniff',
      });
      return res.end(fs.readFileSync(htmlFile));
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end('UI not found');
  }

  // 其他静态资源（css/js/png 等）— 防止路径穿越
  if (method === 'GET' && !pathname.startsWith('/api/') && !pathname.startsWith('/sub/') && !pathname.startsWith('/health')) {
    // 规范化路径，确保解析后在 UI_DIR 内
    const resolved = path.resolve(UI_DIR, pathname);
    if (resolved.startsWith(UI_DIR) && fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
      const ext = path.extname(resolved);
      const ct = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml' }[ext] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': ct, 'X-Content-Type-Options': 'nosniff' });
      return res.end(fs.readFileSync(resolved));
    }
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not Found' }));
}

// ── 启动服务器 ──────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const start = Date.now();
  handleRequest(req, res).catch(err => {
    console.error(`[error] ${req.method} ${req.url}: ${err.message}`);
    apiResponse(res, 500, { error: '服务器内部错误' });
  }).finally(() => {
    const ms = Date.now() - start;
    const code = res.statusCode;
    // 跳过健康检查和静态资源的日志
    if (req.url === '/health') return;
    if (req.url.match(/\.(css|js|png|svg|ico|html)$/)) return;
    console.log(`${req.method} ${req.url} ${code} ${ms}ms`);
  });
});

server.listen(config.port, config.host, async () => {
  try {
    await initDb();
  } catch (e) {
    console.error(`✗ 数据库初始化失败: ${e.message}`);
    process.exit(1);
  }
  console.log(`subserver v${VERSION} listening on ${config.host}:${config.port}`);
  console.log(`  订阅: http://${config.host}:${config.port}/sub/<token>`);
  console.log(`  健康: http://${config.host}:${config.port}/health`);
  if (!config.adminToken) {
    console.log('  ⚠ 未设置 adminToken，旧版 CLI 认证不可用');
  }
});

// 优雅退出
process.on('SIGTERM', () => {
  console.log('\nsubserver shutting down...');
  server.close(() => process.exit(0));
});
process.on('SIGINT', () => {
  console.log('\nsubserver shutting down...');
  server.close(() => process.exit(0));
});
