/**
 * API 服务器模块
 * 封装 Web API 路由和服务器逻辑
 */

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const {
  getSetting,
  setSetting,
  cleanupExpiredVerifications,
  db,
  getUserByCredentials
} = require('./database');

const {
  API_PORT,
  UI_DIR,
  XRAY_CONF,
  MIHOMO_OUT,
  isRunning,
  readPid,
  getServerHost,
  getFixedPortRange,
  getSsPortRange
} = require('./config');

const { getRealityConfig } = require('./reality');

const {
  cleanupExpiredUsers,
  addUpstreamUser,
  removeUpstreamUser,
  setUserEnabledByUuid,
} = require('./user-manager');

const { getUserTraffic, getAllTraffic } = require('./traffic-stats');

// 导入路由模块
const routes = require('./routes');

// 导入工具函数
const { apiResponse, parseBody } = require('./utils');

// ==================== 命令注入 ====================
// xray-ctl 启动前调用 registerCommands() 注入 cmdStart/cmdStop/cmdReload 等
let _commands = {};
function registerCommands(cmds) { _commands = cmds; }

// ==================== 管理员认证（Cookie 方式，与 UI 保持一致）====================

function makeAuthToken(pwd) {
  return crypto.createHash('sha256').update(`smartxray:${pwd}`).digest('hex').slice(0, 32);
}

function isAuthenticated(req) {
  const adminPwd = getSetting('admin_password', '');
  if (!adminPwd) return true;  // 未设置密码则无需认证
  const token = makeAuthToken(adminPwd);
  const cookies = parseCookies(req.headers.cookie);
  if (cookies._sxtoken === token) return true;
  const auth = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (auth === token || auth === adminPwd) return true;
  return false;
}

// ==================== 工具函数 ====================

// 端口分配（与旧版一致：随机策略）
function _allocPort(min, max) {
  const rows1 = db().prepare('SELECT port FROM users').all();
  const rows2 = db().prepare('SELECT http_port as port FROM users WHERE http_port IS NOT NULL').all();
  const used = new Set();
  for (const r of rows1) if (r.port) used.add(r.port);
  for (const r of rows2) if (r.port) used.add(r.port);
  let p, tries = 0;
  do { p = min + Math.floor(Math.random() * (max - min + 1)); tries++; }
  while (used.has(p) && tries < 2000);
  if (used.has(p)) throw new Error('端口区间已满');
  return p;
}

const LOGIN_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SmartXray Login</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#1a1f2e;border:1px solid #2d3748;border-radius:12px;padding:36px;width:100%;max-width:380px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
h1{font-size:1.3rem;color:#63b3ed;margin-bottom:6px}p.sub{font-size:.82rem;color:#718096;margin-bottom:24px}
label{display:block;font-size:.8rem;color:#a0aec0;margin-bottom:4px}
input{width:100%;padding:10px 14px;background:#131720;border:1px solid #2d3748;border-radius:8px;color:#e2e8f0;font-size:.95rem;outline:none;margin-bottom:16px}input:focus{border-color:#63b3ed}
button{width:100%;padding:10px;background:#3182ce;color:#fff;border:none;border-radius:8px;font-size:.9rem;cursor:pointer}button:hover{background:#2b6cb0}
.err{color:#fc8181;font-size:.82rem;margin-top:10px;display:none}</style></head>
<body><div class="card"><h1>SmartXray</h1><p class="sub">请输入管理密码</p>
<label>密码</label><input type="password" id="pwd" placeholder="admin password" autofocus onkeydown="if(event.key==='Enter')doLogin()">
<button onclick="doLogin()">登录</button><p class="err" id="err">密码错误</p></div>
<script>async function doLogin(){const p=document.getElementById('pwd').value;if(!p)return;
const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});
const d=await r.json();if(d.ok){location.href='/admin'}else{const e=document.getElementById('err');e.style.display='block';e.textContent=d.error||'密码错误'}}</script></body></html>`;

/**
 * 解析 Cookie
 */
function parseCookies(str) {
  return (str || '').split(';').reduce((acc, v) => {
    const [k, ...rest] = v.trim().split('=');
    if (k) acc[k] = decodeURIComponent(rest.join('='));
    return acc;
  }, {});
}

function makeUserToken(username, password) {
  return crypto.createHash('sha256').update(`smartxray-user:${username}:${password}`).digest('hex').slice(0, 32);
}

function getUserFromToken(req) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies._sxutoken;
  if (!token) return null;
  const users = db().prepare('SELECT * FROM users WHERE enabled=1').all();
  for (const u of users) {
    if (makeUserToken(u.username, u.password) === token) return u;
  }
  return null;
}

/**
 * 发送邮件
 */
async function sendMail(to, subject, text) {
  const nodemailer = require('nodemailer');
  const transporter = nodemailer.createTransport({
    host: getSetting('smtp_host'),
    port: parseInt(getSetting('smtp_port', '587')),
    secure: getSetting('smtp_secure', '0') === '1',
    auth: { user: getSetting('smtp_user'), pass: getSetting('smtp_pass') }
  });
  await transporter.sendMail({
    from: getSetting('smtp_from', getSetting('smtp_user')),
    to, subject, text
  });
}

/**
 * 检查自助申请条件
 */
function checkSelfserviceConditions() {
  const errors = [];
  if (!getSetting('smtp_host', '')) errors.push('未配置 SMTP');
  const pr = getSsPortRange(getSetting);
  if (pr.socksMin >= pr.socksMax) errors.push('自助端口区间未配置');
  return errors;
}

/**
 * 清理过期账户
 */
function cleanupExpired() {
  const count = cleanupExpiredUsers();
  if (count > 0) {
    console.log(`[cleanup] 清理了 ${count} 个过期用户`);
  }
  cleanupExpiredVerifications();
}


// ==================== API 服务器 ====================

let _apiServerRunning = false;

/**
 * 启动 API 服务器
 */
function startApiServer() {
  if (_apiServerRunning) {
    console.log(`  API server 已在运行 (port ${API_PORT})`);
    return;
  }

  const server = http.createServer(async (req, res) => {
    // 处理 OPTIONS 请求
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization'
      });
      return res.end();
    }

    const url = new URL(req.url, `http://localhost:${API_PORT}`);
    const pathname = url.pathname;
    const method = req.method;

    try {
      // 解析请求体
      const json = method !== 'GET' ? await parseBody(req) : {};

      // 静态文件服务 — 门户页面（公开）
      if (method === 'GET' && (pathname === '/' || pathname === '/portal' || pathname === '/portal.html')) {
        const portalFile = path.join(UI_DIR, 'portal.html');
        if (fs.existsSync(portalFile)) {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          return res.end(fs.readFileSync(portalFile));
        }
        // portal 不存在时 fallback 到管理面板
        if (pathname === '/') {
          if (!isAuthenticated(req)) {
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            return res.end(LOGIN_HTML);
          }
          const indexFile = path.join(UI_DIR, 'index.html');
          if (fs.existsSync(indexFile)) {
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            return res.end(fs.readFileSync(indexFile));
          }
        }
      }

      // 静态文件服务 — 管理面板（需认证）
      if (method === 'GET' && (pathname === '/admin' || pathname === '/admin/' || pathname === '/ui' || pathname === '/ui/' || pathname === '/index.html')) {
        if (!isAuthenticated(req)) {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          return res.end(LOGIN_HTML);
        }
        const htmlFile = path.join(UI_DIR, 'index.html');
        if (fs.existsSync(htmlFile)) {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          return res.end(fs.readFileSync(htmlFile));
        }
        res.writeHead(404); return res.end('UI not found. Run install first.');
      }

      // 自助页面
      if (method === 'GET' && (pathname === '/self' || pathname === '/self/' || pathname === '/self.html')) {
        const htmlFile = path.join(UI_DIR, 'self-service.html');
        if (fs.existsSync(htmlFile)) {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          return res.end(fs.readFileSync(htmlFile));
        }
      }

      // 用户页面
      if (method === 'GET' && (pathname === '/my' || pathname === '/my/' || pathname === '/user' || pathname === '/user.html')) {
        const htmlFile = path.join(UI_DIR, 'user.html');
        if (fs.existsSync(htmlFile)) {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          return res.end(fs.readFileSync(htmlFile));
        }
      }

      // API 路由
      if (pathname.startsWith('/api/')) {
        // POST /api/login — 登录认证（无需已认证）
        if (method === 'POST' && pathname === '/api/login') {
          const adminPwd = getSetting('admin_password', '');
          if (!adminPwd) return apiResponse(res, 200, { ok: true });
          if (json.password !== adminPwd)
            return apiResponse(res, 401, { error: '密码错误' });
          const token = makeAuthToken(adminPwd);
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': `_sxtoken=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`,
            'Access-Control-Allow-Origin': '*',
          });
          return res.end(JSON.stringify({ ok: true }));
        }

        // POST /api/logout — 清除认证
        if (method === 'POST' && pathname === '/api/logout') {
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': '_sxtoken=; Path=/; HttpOnly; Max-Age=0',
            'Access-Control-Allow-Origin': '*',
          });
          return res.end(JSON.stringify({ ok: true }));
        }

        // 公开 API（不需要管理密码）
        const isPublicApi = pathname.startsWith('/api/self/') || pathname.startsWith('/api/user/') || pathname === '/api/shared' || pathname === '/api/public/info' || pathname === '/api/help';

        // 其他 API 需要认证
        if (!isPublicApi && !isAuthenticated(req)) {
          return apiResponse(res, 401, { error: '未认证，请先登录' });
        }

        // GET /api/status — 概览页用
        if (method === 'GET' && pathname === '/api/status') {
          return apiResponse(res, 200, {
            running: isRunning(),
            pid:     readPid(),
            users:   db().prepare('SELECT * FROM users ORDER BY port').all(),
            config:  { server_ip: getSetting('server_ip'), log_level: getSetting('log_level') },
          });
        }

        // 用户列表
        if (method === 'GET' && pathname === '/api/users') {
          return routes.handleUserList(req, res);
        }

        // 添加用户
        if (method === 'POST' && pathname === '/api/users') {
          const name     = json.name || `user-${Date.now()}`;
          const protocol = (json.protocol || 'socks').toLowerCase();
          const username = json.username || crypto.randomBytes(4).toString('hex');
          const password = json.password || crypto.randomBytes(6).toString('hex');
          let socksPort, httpPort;
          try {
            const pr = getFixedPortRange(getSetting);
            socksPort = _allocPort(pr.socksMin, pr.socksMax);
            httpPort  = _allocPort(pr.httpMin,  pr.httpMax);
          } catch { return apiResponse(res, 500, { error: '端口不足' }); }
          const uuid = crypto.randomUUID();
          const tag  = `u-${name}-${socksPort}`;
          try {
            db().prepare(
              `INSERT INTO users (name,port,http_port,uuid,protocol,username,password,tag)
               VALUES (?,?,?,?,?,?,?,?)`
            ).run(name, socksPort, httpPort, uuid, protocol, username, password, tag);
            if (_commands.cmdReload) _commands.cmdReload();
            return apiResponse(res, 201, db().prepare('SELECT * FROM users WHERE name=?').get(name));
          } catch (e) {
            return apiResponse(res, 400, { error: e.message });
          }
        }

        // 删除用户 — DELETE /api/users/:id
        const delMatch = pathname.match(/^\/api\/users\/(\d+)$/);
        if (method === 'DELETE' && delMatch) {
          const user = db().prepare('SELECT * FROM users WHERE id=?').get(parseInt(delMatch[1]));
          if (!user) return apiResponse(res, 404, { error: 'not found' });
          db().prepare('DELETE FROM users WHERE id=?').run(user.id);
          if (_commands.cmdReload) _commands.cmdReload();
          return apiResponse(res, 200, { ok: true });
        }

        // 更新用户 — PATCH /api/users/:id { enabled, password, note }
        const patchMatch = pathname.match(/^\/api\/users\/(\d+)$/);
        if (method === 'PATCH' && patchMatch) {
          const user = db().prepare('SELECT * FROM users WHERE id=?').get(parseInt(patchMatch[1]));
          if (!user) return apiResponse(res, 404, { error: 'not found' });
          if (typeof json.enabled !== 'undefined') {
            db().prepare('UPDATE users SET enabled=? WHERE id=?').run(json.enabled ? 1 : 0, user.id);
          }
          if (json.password) db().prepare('UPDATE users SET password=? WHERE id=?').run(json.password, user.id);
          if (json.note !== undefined) db().prepare('UPDATE users SET note=? WHERE id=?').run(json.note, user.id);
          if (_commands.cmdReload) _commands.cmdReload();
          return apiResponse(res, 200, db().prepare('SELECT * FROM users WHERE id=?').get(user.id));
        }

        // 获取统计信息
        if (method === 'GET' && pathname === '/api/stats') {
          return routes.handleUserStats(req, res);
        }

        // Reality 操作
        if (method === 'POST' && pathname.startsWith('/api/reality/')) {
          const { handleRealityAction } = require('./reality');
          const action = pathname.split('/').pop();
          return await handleRealityAction(req, res, json, action);
        }

        // 自助申请
        if (method === 'POST' && pathname === '/api/selfservice/apply') {
          return await routes.handleSelfserviceApply(req, res, json);
        }

        // 发送验证码
        if (method === 'POST' && pathname === '/api/selfservice/send-code') {
          return await routes.handleSendCode(req, res, json);
        }

        // 自助申请状态
        if (method === 'GET' && pathname === '/api/selfservice/status') {
          return routes.handleSelfserviceStatus(req, res);
        }

        // 获取设置
        if (method === 'GET' && pathname === '/api/settings') {
          return apiResponse(res, 200, {
            server_ip:          getSetting('server_ip', ''),
            public_host:        getSetting('public_host', ''),
            log_level:          getSetting('log_level', 'warning'),
            upstream_outbounds: getSetting('upstream_outbounds', ''),
            upstream_endpoints: getSetting('upstream_endpoints', '[]'),
            use_upstream:       getSetting('use_upstream', '0') === '1',
          });
        }

        // 更新设置
        if (method === 'POST' && pathname === '/api/settings') {
          if (json.server_ip   !== undefined) setSetting('server_ip', json.server_ip);
          if (json.public_host !== undefined) setSetting('public_host', json.public_host);
          if (json.log_level   !== undefined) setSetting('log_level', json.log_level);
          if (json.use_upstream !== undefined) setSetting('use_upstream', json.use_upstream ? '1' : '0');
          if (json.upstream_outbounds !== undefined) {
            if (json.upstream_outbounds) {
              try { JSON.parse(json.upstream_outbounds); }
              catch (e) { return apiResponse(res, 400, { error: 'upstream_outbounds JSON 格式错误: ' + e.message }); }
            }
            setSetting('upstream_outbounds', json.upstream_outbounds);
          }
          if (json.upstream_endpoints !== undefined) {
            if (json.upstream_endpoints) {
              try { JSON.parse(json.upstream_endpoints); }
              catch (e) { return apiResponse(res, 400, { error: 'upstream_endpoints JSON 格式错误: ' + e.message }); }
            }
            setSetting('upstream_endpoints', json.upstream_endpoints);
          }
          if (_commands.cmdReload) _commands.cmdReload();
          return apiResponse(res, 200, { ok: true });
        }

        // 获取单个设置
        if (method === 'GET' && pathname.startsWith('/api/settings/')) {
          const key = pathname.split('/').pop();
          return routes.handleGetSetting(req, res, key);
        }

        // 更新单个设置
        if (method === 'PATCH' && pathname.startsWith('/api/settings/')) {
          const key = pathname.split('/').pop();
          return routes.handleUpdateSetting(req, res, key, json);
        }

        // 防火墙同步
        if (method === 'POST' && pathname === '/api/firewall/sync') {
          return routes.handleFirewallSync(req, res);
        }

        // 防火墙状态
        if (method === 'GET' && pathname === '/api/firewall/status') {
          return routes.handleFirewallStatus(req, res);
        }

        // ── 用户端 API（cookie 认证）────────────────────────
        // POST /api/user/login
        if (method === 'POST' && pathname === '/api/user/login') {
          const { username: uname, password: upwd } = json;
          if (!uname || !upwd) return apiResponse(res, 400, { error: '请输入用户名和密码' });
          const user = getUserByCredentials(uname, upwd);
          if (!user) return apiResponse(res, 401, { error: '用户名或密码错误' });
          const utoken = makeUserToken(uname, upwd);
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': `_sxutoken=${utoken}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`,
            'Access-Control-Allow-Origin': '*',
          });
          return res.end(JSON.stringify({ ok: true, name: user.name }));
        }

        // POST /api/user/logout
        if (method === 'POST' && pathname === '/api/user/logout') {
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': '_sxutoken=; Path=/; HttpOnly; Max-Age=0',
            'Access-Control-Allow-Origin': '*',
          });
          return res.end(JSON.stringify({ ok: true }));
        }

        // GET /api/user/me
        if (method === 'GET' && pathname === '/api/user/me') {
          const user = getUserFromToken(req);
          if (!user) return apiResponse(res, 401, { error: '未登录' });
          const serverIp = getServerHost(getSetting);
          const reality  = getRealityConfig();
          const sharedSocks = parseInt(getSetting('shared_socks_port', '0')) || 0;
          const sharedHttp  = parseInt(getSetting('shared_http_port', '0'))  || 0;
          const socksPort = sharedSocks || user.port;
          const httpPort  = sharedHttp  || user.http_port;
          const proxies = {};
          if (socksPort) {
            proxies.socks5  = `socks5://${encodeURIComponent(user.username)}:${encodeURIComponent(user.password)}@${serverIp}:${socksPort}`;
            proxies.socks5h = `socks5h://${encodeURIComponent(user.username)}:${encodeURIComponent(user.password)}@${serverIp}:${socksPort}`;
          }
          if (httpPort) {
            proxies.http  = `http://${encodeURIComponent(user.username)}:${encodeURIComponent(user.password)}@${serverIp}:${httpPort}`;
            proxies.https = proxies.http;
          }
          if (reality.enabled && reality.publicKey && user.uuid) {
            proxies.vless_link =
              `vless://${user.uuid}@${serverIp}:${reality.port}` +
              `?type=tcp&security=reality` +
              `&sni=${encodeURIComponent(reality.serverNames[0] || '')}` +
              `&pbk=${encodeURIComponent(reality.publicKey)}` +
              `&sid=${encodeURIComponent(reality.shortIds[0] || '')}` +
              `&flow=xtls-rprx-vision#xray-${user.name}`;
            proxies.vless_detail = {
              server: serverIp, port: reality.port, uuid: user.uuid,
              sni: reality.serverNames[0] || '',
              publicKey: reality.publicKey,
              shortId: reality.shortIds[0] || '',
            };
          }
          return apiResponse(res, 200, {
            name: user.name, username: user.username, password: user.password,
            enabled: !!user.enabled, expires_at: user.expires_at, created_at: user.created_at,
            socks_port: socksPort, http_port: httpPort, server_ip: serverIp, proxies,
          });
        }

        // ── 服务控制（需通过 registerCommands 注入）────────
        // POST /api/start
        if (method === 'POST' && pathname === '/api/start') {
          if (!_commands.cmdStart) return apiResponse(res, 500, { error: '命令未注册' });
          try {
            await _commands.cmdStart();
            return apiResponse(res, 200, { running: isRunning() });
          } catch (e) { return apiResponse(res, 500, { error: e.message }); }
        }

        // POST /api/stop
        if (method === 'POST' && pathname === '/api/stop') {
          if (!_commands.cmdStop) return apiResponse(res, 500, { error: '命令未注册' });
          _commands.cmdStop();
          return apiResponse(res, 200, { running: false });
        }

        // POST /api/reload
        if (method === 'POST' && pathname === '/api/reload') {
          if (!_commands.cmdReload) return apiResponse(res, 500, { error: '命令未注册' });
          _commands.cmdReload();
          return apiResponse(res, 200, { ok: true });
        }

        // GET /api/export — 导出 mihomo proxies
        if (method === 'GET' && pathname === '/api/export') {
          const yaml = fs.existsSync(MIHOMO_OUT) ? fs.readFileSync(MIHOMO_OUT, 'utf8') : '# no proxies\n';
          res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
          return res.end(yaml);
        }

        // ── 自助申请（兼容旧路径）────────────────────────────
        // POST /api/self/request
        if (method === 'POST' && pathname === '/api/self/request') {
          return await routes.handleSendCode(req, res, json);
        }

        // POST /api/self/verify
        if (method === 'POST' && pathname === '/api/self/verify') {
          return await routes.handleSelfserviceApply(req, res, json);
        }

        // ── 防火墙配置 ──────────────────────────────────────
        // GET /api/firewall
        if (method === 'GET' && pathname === '/api/firewall') {
          const fpr = getFixedPortRange(getSetting);
          const spr = getSsPortRange(getSetting);
          return apiResponse(res, 200, {
            mode:               getSetting('extfw_mode', 'none'),
            lightsail_instance: getSetting('lightsail_instance', ''),
            openwrt_host:       getSetting('openwrt_host', ''),
            openwrt_user:       getSetting('openwrt_user', 'root'),
            openwrt_ssh_key:    getSetting('openwrt_ssh_key', ''),
            openwrt_dest_ip:    getSetting('openwrt_dest_ip', ''),
            port_fixed_socks_min: fpr.socksMin, port_fixed_socks_max: fpr.socksMax,
            port_fixed_http_min:  fpr.httpMin,  port_fixed_http_max:  fpr.httpMax,
            port_ss_socks_min:    spr.socksMin, port_ss_socks_max:    spr.socksMax,
            port_ss_http_min:     spr.httpMin,  port_ss_http_max:     spr.httpMax,
          });
        }

        // POST /api/firewall
        if (method === 'POST' && pathname === '/api/firewall') {
          const fields = ['extfw_mode','lightsail_instance','openwrt_host','openwrt_user','openwrt_ssh_key','openwrt_dest_ip',
            'port_fixed_socks_min','port_fixed_socks_max','port_fixed_http_min','port_fixed_http_max',
            'port_ss_socks_min','port_ss_socks_max','port_ss_http_min','port_ss_http_max'];
          for (const f of fields) {
            if (json[f] !== undefined) setSetting(f, String(json[f]));
          }
          return apiResponse(res, 200, { ok: true });
        }

        // ── 自助申请管理（管理端）───────────────────────────
        // GET /api/selfservice
        if (method === 'GET' && pathname === '/api/selfservice') {
          const fpr = getFixedPortRange(getSetting);
          const spr = getSsPortRange(getSetting);
          return apiResponse(res, 200, {
            enabled: getSetting('selfservice_enabled') === '1',
            hours:   parseInt(getSetting('selfservice_hours', '2')) || 2,
            conditions: checkSelfserviceConditions(),
            port_ranges: { fixed: fpr, ss: spr },
          });
        }

        // POST /api/selfservice
        if (method === 'POST' && pathname === '/api/selfservice') {
          if (typeof json.enabled !== 'undefined') {
            if (json.enabled) {
              const errors = checkSelfserviceConditions();
              if (errors.length) return apiResponse(res, 400, { error: '无法开启: ' + errors.join('; ') });
            }
            setSetting('selfservice_enabled', json.enabled ? '1' : '0');
          }
          if (json.hours !== undefined) {
            const h = parseInt(json.hours);
            if (h >= 1) setSetting('selfservice_hours', String(h));
          }
          return apiResponse(res, 200, { ok: true });
        }

        // ── 上游同步（中继侧）— 必须在 :username 路由之前 ────
        // POST /api/upstream/sync — 手动触发上游同步
        if (method === 'POST' && pathname === '/api/upstream/sync') {
          const { syncUpstreams } = require('./upstream-sync');
          try {
            const result = await syncUpstreams();
            if (_commands.cmdReload) _commands.cmdReload();
            return apiResponse(res, 200, result);
          } catch (e) {
            return apiResponse(res, 500, { error: e.message });
          }
        }

        // GET /api/upstream/status — 查看上游同步状态
        if (method === 'GET' && pathname === '/api/upstream/status') {
          let endpoints = [];
          let outbounds = [];
          try { endpoints = JSON.parse(getSetting('upstream_endpoints', '[]')); } catch {}
          try { outbounds = JSON.parse(getSetting('upstream_outbounds', '[]')); } catch {}
          return apiResponse(res, 200, {
            endpoints_count: endpoints.length,
            endpoints: endpoints.map(e => ({ name: e.name, host: e.host, port: e.port, username: e.username })),
            outbounds_count: outbounds.length,
            outbounds: outbounds.map(o => ({ tag: o.tag })),
            use_upstream: getSetting('use_upstream', '0') === '1',
          });
        }

        // ── 上游用户管理（供 subserver 同步调用）──────────────
        // POST /api/upstream/user — 用指定 UUID 创建/更新用户
        if (method === 'POST' && pathname === '/api/upstream/user') {
          const { uuid, name } = json;
          if (!uuid || !name) return apiResponse(res, 400, { error: 'uuid 和 name 必填' });
          try {
            const user = addUpstreamUser({ uuid, name });
            return apiResponse(res, 200, { ok: true, user: { id: user.id, name: user.name, uuid: user.uuid, enabled: !!user.enabled } });
          } catch (e) {
            return apiResponse(res, 500, { error: e.message });
          }
        }

        // DELETE /api/upstream/user/:uuid — 删除上游用户
        const upstreamUserDelMatch = pathname.match(/^\/api\/upstream\/user\/([^\/]+)$/);
        if (method === 'DELETE' && upstreamUserDelMatch) {
          const uuid = decodeURIComponent(upstreamUserDelMatch[1]);
          const ok = removeUpstreamUser(uuid);
          return apiResponse(res, ok ? 200 : 404, ok ? { ok: true } : { error: '用户不存在' });
        }

        // PATCH /api/upstream/user/:uuid — 启用/停用上游用户
        const upstreamUserPatchMatch = pathname.match(/^\/api\/upstream\/user\/([^\/]+)$/);
        if (method === 'PATCH' && upstreamUserPatchMatch) {
          const uuid = decodeURIComponent(upstreamUserPatchMatch[1]);
          const { enabled } = json;
          if (typeof enabled === 'undefined') return apiResponse(res, 400, { error: '缺少 enabled 字段' });
          const user = setUserEnabledByUuid(uuid, !!enabled);
          if (!user) return apiResponse(res, 404, { error: '用户不存在' });
          return apiResponse(res, 200, { ok: true, user: { id: user.id, name: user.name, uuid: user.uuid, enabled: !!user.enabled } });
        }

        // ── 流量查询 ─────────────────────────────────────────
        // GET /api/traffic — 所有用户流量列表
        if (method === 'GET' && pathname === '/api/traffic') {
          const traffic = getAllTraffic();
          return apiResponse(res, 200, { traffic });
        }

        // GET /api/traffic/:uuid — 单个用户流量
        const trafficMatch = pathname.match(/^\/api\/traffic\/([^\/]+)$/);
        if (method === 'GET' && trafficMatch) {
          const uuid = decodeURIComponent(trafficMatch[1]);
          const traffic = getUserTraffic(uuid);
          return apiResponse(res, 200, traffic);
        }

        // ── 上游连接详情（供中继节点拉取）────────────────────
        // GET /api/upstream/:username — 返回该用户的上游 VLESS+Reality 连接详情
        const upstreamMatch = pathname.match(/^\/api\/upstream\/(?!sync$|status$|user$)([^\/]+)$/);
        if (method === 'GET' && upstreamMatch) {
          const username = decodeURIComponent(upstreamMatch[1]);
          const user = db().prepare('SELECT * FROM users WHERE name = ? AND enabled = 1').get(username);
          if (!user) {
            return apiResponse(res, 404, { error: '用户不存在或已禁用' });
          }
          const reality = getRealityConfig();
          if (!reality.enabled || !user.uuid) {
            return apiResponse(res, 404, { error: '该用户无上游映射' });
          }
          return apiResponse(res, 200, {
            server:   getServerHost(getSetting),
            port:     reality.port,
            uuid:     user.uuid,
            sni:      reality.serverNames[0] || '',
            pubkey:   reality.publicKey || '',
            shortid:  reality.shortIds[0] || '',
            flow:     'xtls-rprx-vision',
            network:  'tcp',
            security: 'reality',
          });
        }

        // ── 原始配置 ────────────────────────────────────────
        // GET /api/config/raw
        if (method === 'GET' && pathname === '/api/config/raw') {
          const content = fs.existsSync(XRAY_CONF) ? fs.readFileSync(XRAY_CONF, 'utf8') : '{}';
          return apiResponse(res, 200, { content });
        }

        // POST /api/config/raw
        if (method === 'POST' && pathname === '/api/config/raw') {
          if (!json.content) return apiResponse(res, 400, { error: '缺少 content 字段' });
          try {
            JSON.parse(json.content);
            fs.writeFileSync(XRAY_CONF, json.content);
            if (_commands.cmdReload) _commands.cmdReload();
            return apiResponse(res, 200, { ok: true });
          } catch (e) {
            return apiResponse(res, 400, { error: 'JSON 格式错误: ' + e.message });
          }
        }

        // ── 公开 API（无需认证）─────────────────────────────
        // GET /api/help
        if (method === 'GET' && pathname === '/api/help') {
          const helpFile = path.join(UI_DIR, 'help.md');
          const md = fs.existsSync(helpFile) ? fs.readFileSync(helpFile, 'utf8') : '';
          res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
          return res.end(md);
        }

        // GET /api/shared
        if (method === 'GET' && pathname === '/api/shared') {
          return apiResponse(res, 200, {
            shared_socks_port: parseInt(getSetting('shared_socks_port', '0')) || 0,
            shared_http_port:  parseInt(getSetting('shared_http_port', '0'))  || 0,
            server_ip: getServerHost(getSetting),
          });
        }

        // GET /api/public/info
        if (method === 'GET' && pathname === '/api/public/info') {
          const reality = getRealityConfig();
          const result = { reality_enabled: reality.enabled };
          if (reality.enabled) {
            result.reality_port   = reality.port;
            result.reality_sni    = reality.serverNames[0] || '';
            result.reality_pubkey = reality.publicKey || '';
            result.reality_sid    = reality.shortIds[0] || '';
          }
          return apiResponse(res, 200, result);
        }

        // ── SMTP 配置 ───────────────────────────────────────
        // GET /api/smtp
        if (method === 'GET' && pathname === '/api/smtp') {
          return apiResponse(res, 200, {
            smtp_host:   getSetting('smtp_host', ''),
            smtp_port:   parseInt(getSetting('smtp_port', '587')) || 587,
            smtp_secure: getSetting('smtp_secure', '0') === '1',
            smtp_user:   getSetting('smtp_user', ''),
            smtp_pass:   getSetting('smtp_pass', '') ? '••••••' : '',
            smtp_from:   getSetting('smtp_from', ''),
          });
        }

        // POST /api/smtp
        if (method === 'POST' && pathname === '/api/smtp') {
          if (json.smtp_host !== undefined) setSetting('smtp_host', json.smtp_host);
          if (json.smtp_port !== undefined) setSetting('smtp_port', String(json.smtp_port));
          if (json.smtp_secure !== undefined) setSetting('smtp_secure', json.smtp_secure ? '1' : '0');
          if (json.smtp_user !== undefined) setSetting('smtp_user', json.smtp_user);
          if (json.smtp_pass !== undefined && json.smtp_pass !== '••••••') setSetting('smtp_pass', json.smtp_pass);
          if (json.smtp_from !== undefined) setSetting('smtp_from', json.smtp_from);
          return apiResponse(res, 200, { ok: true });
        }

        // POST /api/smtp/test
        if (method === 'POST' && pathname === '/api/smtp/test') {
          if (!json.to) return apiResponse(res, 400, { error: '请填写测试收件地址' });
          try {
            await sendMail(json.to, '【SmartXray】SMTP 测试', '这是一封测试邮件，如果你收到说明 SMTP 配置正确。\n\n— SmartXray');
            return apiResponse(res, 200, { ok: true });
          } catch (e) {
            return apiResponse(res, 500, { error: 'SMTP 发送失败: ' + e.message });
          }
        }

        // 404
        return apiResponse(res, 404, { error: 'API 端点不存在' });
      }

      // 静态资源
      const staticFile = path.join(UI_DIR, pathname);
      if (fs.existsSync(staticFile) && fs.statSync(staticFile).isFile()) {
        const ext = path.extname(staticFile);
        const contentType = {
          '.html': 'text/html',
          '.css': 'text/css',
          '.js': 'application/javascript',
          '.json': 'application/json',
          '.png': 'image/png',
          '.jpg': 'image/jpeg',
          '.gif': 'image/gif',
          '.svg': 'image/svg+xml',
          '.ico': 'image/x-icon'
        }[ext] || 'application/octet-stream';

        res.writeHead(200, { 'Content-Type': contentType });
        return res.end(fs.readFileSync(staticFile));
      }

      // 404
      res.writeHead(404);
      res.end('Not Found');

    } catch (e) {
      console.error('API 错误:', e);
      apiResponse(res, 500, { error: '服务器内部错误' });
    }
  });

  server.on('error', e => {
    if (e.code === 'EADDRINUSE') {
      console.log(`  API server 已在运行 (port ${API_PORT})`);
    } else {
      console.error(`  API server 错误: ${e.message}`);
    }
  });

  server.listen(API_PORT, '0.0.0.0', () => {
    _apiServerRunning = true;
    console.log(`  Web UI: http://0.0.0.0:${API_PORT}/  (or http://<server-ip>:${API_PORT}/)`);

    // 定期清理过期账户
    cleanupExpired();
    setInterval(cleanupExpired, 60 * 1000);
  });
}

/**
 * 停止 API 服务器
 */
function stopApiServer() {
  _apiServerRunning = false;
}

module.exports = {
  startApiServer,
  stopApiServer,
  registerCommands,
  apiResponse,
  isRunning: () => _apiServerRunning
};
