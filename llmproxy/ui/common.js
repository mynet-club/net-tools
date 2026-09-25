'use strict';

/* llmproxy 用户控制台（无框架、无外部资源，随二进制一起分发）
   安全取向：
   - token 只放 sessionStorage，不进 URL、不进日志、不落 localStorage
   - 所有来自接口的字符串一律走 textContent 渲染，不用 innerHTML ——
     上游名、地址、模型名、错误信息都是用户可控的，拼 HTML 就是 XSS */

const $ = (id) => document.getElementById(id);
const state = { base: '', token: '', storageKey: '', me: null, days: 7, editing: null, providers: [] };

/* ── 小工具 ───────────────────────────────────────────────────────── */

function h(tag, props, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2).toLowerCase(), v);
    else n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    n.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return n;
}

const num = (v) => (v == null ? '—' : Number(v).toLocaleString('zh-CN'));
// 金额：小额给 4 位小数，否则 0.00002 会被四舍五入成 0.00，看着像没花钱
const money = (v, cur) => {
  const n = Number(v || 0);
  return (n >= 1 ? n.toFixed(2) : n.toFixed(4)) + (cur ? ' ' + cur : '');
};
const ms = (v) => (v == null || v === 0 ? '—' : Math.round(v) + 'ms');

function defaultBase() {
  if (location.protocol === 'http:' || location.protocol === 'https:') return location.origin;
  return 'http://127.0.0.1:8787';
}

function showErr(node, msg) {
  node.textContent = msg || '';
  node.hidden = !msg;
}

/* ── 接口 ─────────────────────────────────────────────────────────── */

async function api(path, opts = {}) {
  const headers = { Authorization: 'Bearer ' + state.token, ...(opts.headers || {}) };
  if (opts.body) headers['Content-Type'] = 'application/json';
  let res;
  try {
    res = await fetch(state.base + path, { ...opts, headers });
  } catch (e) {
    throw new Error('连不上网关 ' + state.base + '：' + e.message +
      '（若页面是从文件打开的，浏览器会拦跨源请求；建议直接访问网关自带的 /ui/）');
  }
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }
  if (!res.ok) {
    const m = (data && data.error && (data.error.message || data.error.type)) || res.status + ' ' + res.statusText;
    const err = new Error(m);
    err.status = res.status;
    throw err;
  }
  return { data, res };
}

/* ── 会话 ─────────────────────────────────────────────────────────── */
/* 两个界面各存各的：同源下 sessionStorage 是按标签页共享的，
   共用一个键会让两边的 token 互相覆盖（在 /ui/ 登录的用户 token 会把管理台的挤掉）。 */

function sessionSave() {
  sessionStorage.setItem(state.storageKey + '.base', state.base);
  sessionStorage.setItem(state.storageKey + '.token', state.token);
}

function sessionLoad() {
  return {
    base: sessionStorage.getItem(state.storageKey + '.base') || defaultBase(),
    token: sessionStorage.getItem(state.storageKey + '.token') || '',
  };
}

function sessionClear() {
  sessionStorage.removeItem(state.storageKey + '.token');
}
