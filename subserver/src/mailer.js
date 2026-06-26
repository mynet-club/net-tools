/**
 * 邮件发送模块
 * 轻量 SMTP 客户端，使用 Node.js 内置 net/tls，零外部依赖
 * 支持: STARTTLS / 隐式 TLS / AUTH LOGIN
 */

'use strict';

// net/tls 懒加载，避免 ncc 将本模块标记为内置模块导致打包冲突
let _net, _tls;
function net() { if (!_net) _net = require('net'); return _net; }
function tls() { if (!_tls) _tls = require('tls'); return _tls; }

const SMTP_TIMEOUT = 15000; // 15 秒超时

// ── 邮件内容构建 ─────────────────────────────────────────────────

/**
 * 构建邮件标题和正文（RFC 5322 格式）
 */
function buildEmail(fromName, fromEmail, mail) {
  const lines = [];
  lines.push(`From: ${fromName} <${fromEmail}>`);
  lines.push(`To: <${mail.to}>`);
  // Subject 用 UTF-8 Base64 编码以支持中文
  const subjB64 = Buffer.from(mail.subject).toString('base64');
  lines.push(`Subject: =?UTF-8?B?${subjB64}?=`);
  lines.push('MIME-Version: 1.0');
  lines.push('Content-Type: text/html; charset=UTF-8');
  lines.push('Content-Transfer-Encoding: base64');
  lines.push('Date: ' + new Date().toUTCString());
  lines.push('');
  // Body 用 base64 编码，避免 8bit 传输问题
  const bodyB64 = Buffer.from(mail.html, 'utf8').toString('base64');
  // base64 每行不超过 76 字符
  for (let i = 0; i < bodyB64.length; i += 76) {
    lines.push(bodyB64.slice(i, i + 76));
  }
  return lines.join('\r\n');
}

// ── SMTP 会话 ───────────────────────────────────────────────────

class SmtpSession {
  constructor(host, port, secure) {
    this.host = host;
    this.port = port;
    this.secure = secure;
    this.socket = null;
    this._buf = '';
    this._lines = [];
    this._waiter = null;
  }

  connect() {
    return new Promise((resolve, reject) => {
      const opts = { host: this.host, port: this.port, rejectUnauthorized: false };
      const onConnect = () => {
        this.socket.setTimeout(SMTP_TIMEOUT);
        this.socket.on('data', c => this._onData(c));
        this.socket.on('error', err => this._fail(err));
        this.socket.on('timeout', () => this._fail(new Error('SMTP 连接超时')));
        this._waiter = { resolve, reject };
      };
      if (this.secure) {
        this.socket = tls().connect(opts, onConnect);
      } else {
        this.socket = net().createConnection(opts, onConnect);
      }
      this.socket.on('error', err => { if (!this._waiter) reject(err); });
    });
  }

  _onData(chunk) {
    this._buf += chunk.toString('utf8');
    const parts = this._buf.split('\r\n');
    this._buf = parts.pop();
    for (const line of parts) {
      this._lines.push(line);
      // 最后一行: 数字后跟空格（非 '-'）
      if (/^\d{3} /.test(line)) {
        if (this._waiter) {
          const code = parseInt(line.slice(0, 3));
          const msg = this._lines.join('\n');
          this._lines = [];
          const w = this._waiter;
          this._waiter = null;
          w.resolve({ code, msg });
        }
      }
    }
  }

  send(cmd) {
    return new Promise((resolve, reject) => {
      this._waiter = { resolve, reject };
      this.socket.write(cmd + '\r\n');
    });
  }

  upgradeTLS() {
    return new Promise((resolve, reject) => {
      const old = this.socket;
      old.removeAllListeners('data');
      old.removeAllListeners('error');
      old.removeAllListeners('timeout');
      const tSocket = tls().connect({ socket: old, rejectUnauthorized: false }, () => {
        this.socket = tSocket;
        this.socket.setTimeout(SMTP_TIMEOUT);
        this.socket.on('data', c => this._onData(c));
        this.socket.on('error', err => this._fail(err));
        this.socket.on('timeout', () => this._fail(new Error('SMTP TLS 超时')));
        resolve();
      });
      tSocket.on('error', reject);
    });
  }

  _fail(err) {
    if (this._waiter) {
      const w = this._waiter;
      this._waiter = null;
      w.reject(err);
    }
  }

  close() {
    if (this.socket) { try { this.socket.destroy(); } catch {} }
  }
}

// ── 发送邮件 ────────────────────────────────────────────────────

/**
 * 发送邮件（低层接口）
 * @param {Object} smtp - { host, port, secure, auth: { user, pass }, fromName, fromEmail }
 * @param {Object} mail - { to, subject, html }
 */
async function sendMail(smtp, mail) {
  if (!smtp || !smtp.host || !smtp.fromEmail) {
    throw new Error('SMTP 配置不完整');
  }
  const { host, port = 587, secure = false, auth, fromName = 'SubServer', fromEmail } = smtp;
  const session = new SmtpSession(host, port, secure);

  try {
    let r = await session.connect();
    if (r.code !== 220) throw new Error(`SMTP 连接被拒: ${r.msg}`);

    r = await session.send('EHLO subserver');
    if (r.code !== 250) throw new Error(`EHLO 失败: ${r.msg}`);

    const hasTLS = r.msg.includes('STARTTLS');
    if (!secure && hasTLS) {
      r = await session.send('STARTTLS');
      if (r.code !== 220) throw new Error(`STARTTLS 失败: ${r.msg}`);
      await session.upgradeTLS();
      r = await session.send('EHLO subserver');
      if (r.code !== 250) throw new Error(`TLS 后 EHLO 失败: ${r.msg}`);
    }

    if (auth && auth.user && auth.pass) {
      r = await session.send('AUTH LOGIN');
      if (r.code !== 334) throw new Error(`AUTH LOGIN 失败: ${r.msg}`);
      r = await session.send(Buffer.from(auth.user).toString('base64'));
      if (r.code !== 334) throw new Error(`SMTP 用户名验证失败: ${r.msg}`);
      r = await session.send(Buffer.from(auth.pass).toString('base64'));
      if (r.code !== 235) throw new Error(`SMTP 密码验证失败: ${r.msg}`);
    }

    r = await session.send(`MAIL FROM:<${fromEmail}>`);
    if (r.code !== 250) throw new Error(`MAIL FROM 失败: ${r.msg}`);

    r = await session.send(`RCPT TO:<${mail.to}>`);
    if (r.code !== 250 && r.code !== 251) throw new Error(`RCPT TO 失败: ${r.msg}`);

    r = await session.send('DATA');
    if (r.code !== 354) throw new Error(`DATA 命令失败: ${r.msg}`);

    const content = buildEmail(fromName, fromEmail, mail);
    r = await session.send(content + '\r\n.');
    if (r.code !== 250) throw new Error(`邮件发送失败: ${r.msg}`);

    try { await session.send('QUIT'); } catch {}
    return true;
  } finally {
    session.close();
  }
}

// ── 高层接口 ────────────────────────────────────────────────────

// 配置由 init() 注入，避免与 auth.js 的循环 require 导致 ncc 打包冲突
let _cfg = null;

/**
 * 初始化邮件模块（server.js 启动时调用）
 * @param {Object} cfg - config 对象
 */
function init(cfg) {
  _cfg = cfg;
}

/**
 * SMTP 是否已配置
 */
function isMailEnabled() {
  return !!(_cfg && _cfg.smtp && _cfg.smtp.host && _cfg.smtp.fromEmail);
}

/**
 * 获取 baseUrl（用于邮件中的链接）
 */
function getBaseUrl() {
  if (!_cfg) return 'http://localhost:3456';
  return _cfg.baseUrl || `http://${_cfg.host}:${_cfg.port}`;
}

/**
 * 发送邮箱验证邮件
 */
async function sendVerificationEmail(email, verifyUrl) {
  const html = `
<div style="font-family:-apple-system,BlinkMacSystemFont,sans-serif;max-width:560px;margin:0 auto;padding:32px">
  <h2 style="color:#3182ce;margin-bottom:8px">邮箱验证</h2>
  <p style="color:#4a5568;font-size:14px;line-height:1.8">您好！请点击下方按钮验证您的邮箱地址以完成账号激活：</p>
  <p style="margin:24px 0">
    <a href="${verifyUrl}" style="display:inline-block;padding:12px 28px;background:#3182ce;color:#fff;text-decoration:none;border-radius:6px;font-size:14px">验证邮箱</a>
  </p>
  <p style="color:#718096;font-size:12px;line-height:1.8">如果按钮无法点击，请复制以下链接到浏览器打开：<br>
  <span style="color:#3182ce;word-break:break-all">${verifyUrl}</span></p>
  <p style="color:#718096;font-size:12px;margin-top:24px">此链接 24 小时内有效。如非本人操作，请忽略此邮件。</p>
</div>`;
  return sendMail(_cfg.smtp, { to: email, subject: '邮箱验证 — SubServer', html });
}

/**
 * 发送密码重置邮件
 */
async function sendResetEmail(email, resetUrl, username) {
  const html = `
<div style="font-family:-apple-system,BlinkMacSystemFont,sans-serif;max-width:560px;margin:0 auto;padding:32px">
  <h2 style="color:#3182ce;margin-bottom:8px">重置密码</h2>
  <p style="color:#4a5568;font-size:14px;line-height:1.8">您好${username ? '，' + username : ''}！我们收到了您的密码重置请求。请点击下方按钮设置新密码：</p>
  <p style="margin:24px 0">
    <a href="${resetUrl}" style="display:inline-block;padding:12px 28px;background:#3182ce;color:#fff;text-decoration:none;border-radius:6px;font-size:14px">重置密码</a>
  </p>
  <p style="color:#718096;font-size:12px;line-height:1.8">如果按钮无法点击，请复制以下链接到浏览器打开：<br>
  <span style="color:#3182ce;word-break:break-all">${resetUrl}</span></p>
  <p style="color:#718096;font-size:12px;margin-top:24px">此链接 1 小时内有效。如非本人操作，请忽略此邮件，您的密码不会被更改。</p>
</div>`;
  return sendMail(_cfg.smtp, { to: email, subject: '重置密码 — SubServer', html });
}

module.exports = {
  init,
  sendMail,
  sendVerificationEmail,
  sendResetEmail,
  isMailEnabled,
  getBaseUrl,
};
