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
    // style 必须走 CSSOM，不能 setAttribute：本页的 CSP 是 style-src 'self'，
    // 内联 style **属性**会被浏览器静默丢掉（配额条因此一直是 0 宽，界面看着像没数据）。
    // CSSOM 赋值不在 style-src 的管辖范围内，所以这是唯一不动 CSP 就能保住样式的写法。
    else if (k === 'style') n.style.cssText = v;
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

// stat 造一个统计格；title 可选，用来放那句「这个数怎么算的」。
// 放共用的 common.js：用户台与管理台的用量区都用它。
function stat(k, v, cls, title) {
  return h('div', title ? { title } : null,
    h('div', { class: 'k', text: k }),
    h('div', { class: cls ? 'v ' + cls : 'v', text: v }));
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

/* ── 统一反馈组件（管理台与用户台共用）────────────────────────────────
   toast / 确认弹窗 / 输入弹窗 / 详情浮框四件套，两边长成同一套交互。
   两条既有口径继续生效：接口字符串一律 textContent（XSS）；动态定位走
   CSSOM 赋值而不是 style 属性（CSP style-src 'self' 会丢内联 style 属性）。
   确认/输入弹窗只替原生 confirm/prompt —— 表单内的行内错误提示仍在原位
   （回放面板门禁断言 #rp-err 的语义，动了会让夹具假红）。 */

function toastRoot() {
  let r = $('toast-root');
  if (!r) {
    r = h('div', { id: 'toast-root' });
    document.body.append(r);
  }
  return r;
}

// toast：右下角、绿/红、2.5 秒淡出（smartxray 同款节奏）。
function toast(msg, kind) {
  const t = h('div', { class: 'toast ' + (kind === 'err' ? 'err' : 'ok'), text: String(msg == null ? '' : msg) });
  toastRoot().append(t);
  setTimeout(() => {
    t.classList.add('gone');
    setTimeout(() => t.remove(), 350);
  }, 2500);
}

// modalOverlay：遮罩 + ESC 双通道关闭；onClose 只调一次。
function modalOverlay(box, onClose) {
  let closed = false;
  const finish = () => {
    if (closed) return;
    closed = true;
    document.removeEventListener('keydown', esc);
    overlay.remove();
    onClose();
  };
  const esc = (e) => { if (e.key === 'Escape') finish(); };
  const overlay = h('div', {
    class: 'modal',
    onclick: (e) => { if (e.target === overlay) finish(); },
  }, box);
  document.addEventListener('keydown', esc);
  document.body.append(overlay);
  return { close: finish };
}

// confirmDialog：替代原生 confirm，resolve(true)=确定 / resolve(false)=取消、遮罩、ESC。
function confirmDialog(opts = {}) {
  return new Promise((resolve) => {
    let ctl, settled = false;
    const finish = (v) => {
      if (settled) return;
      settled = true;
      ctl.close();
      resolve(v);
    };
    const box = h('div', { class: 'modal-box confirm-box' },
      h('div', { class: 'modal-head' },
        h('strong', { text: opts.title || '确认操作' }),
        h('span', { class: 'grow' }),
        h('button', {
          type: 'button', class: 'ghost sm', text: '✕',
          onclick: () => finish(false),
        })),
      h('p', { class: 'sub confirm-body', text: opts.body || '' }),
      h('div', { class: 'row' },
        h('span', { class: 'grow' }),
        h('button', { type: 'button', class: 'ghost', text: opts.cancelText || '取消', onclick: () => finish(false) }),
        h('button', {
          type: 'button', class: opts.danger ? 'primary danger' : 'primary',
          text: opts.okText || '确定', onclick: () => finish(true),
        })));
    ctl = modalOverlay(box, () => finish(false));
  });
}

// promptDialog：替代原生 prompt，resolve(输入值) / resolve(null)=放弃。
function promptDialog(opts = {}) {
  return new Promise((resolve) => {
    let ctl, settled = false;
    const input = h('input', {
      type: 'text', spellcheck: 'false', autocomplete: 'off',
      placeholder: opts.placeholder || '', value: opts.value || '',
    });
    const finish = (v) => {
      if (settled) return;
      settled = true;
      ctl.close();
      resolve(v);
    };
    const box = h('div', { class: 'modal-box confirm-box' },
      h('div', { class: 'modal-head' },
        h('strong', { text: opts.title || '请输入' }),
        h('span', { class: 'grow' }),
        h('button', {
          type: 'button', class: 'ghost sm', text: '✕',
          onclick: () => finish(null),
        })),
      h('p', { class: 'sub confirm-body', text: opts.body || '' }),
      input,
      h('div', { class: 'row' },
        h('span', { class: 'grow' }),
        h('button', { type: 'button', class: 'ghost', text: opts.cancelText || '取消', onclick: () => finish(null) }),
        h('button', {
          type: 'button', class: 'primary', text: opts.okText || '确定',
          onclick: () => finish(input.value),
        })));
    ctl = modalOverlay(box, () => finish(null));
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') finish(input.value);
    });
    input.focus();
  });
}

// detailPop：列表行点开的详情浮框 —— 跟随点击位置定位，ESC/遮罩关闭。
// content 必须是已按 textContent 口径构造好的节点，这里不再拼任何字符串进 HTML。
function detailPop(anchor, content, opts = {}) {
  let closed = false;
  const veil = h('div', { class: 'pop-veil' });
  const close = () => {
    if (closed) return;
    closed = true;
    document.removeEventListener('keydown', esc);
    veil.remove();
    if (opts.onClose) opts.onClose();
  };
  const esc = (e) => { if (e.key === 'Escape') close(); };
  const box = h('div', { class: 'pop-box' },
    h('div', { class: 'pop-head' },
      h('strong', { text: opts.title || '详情' }),
      h('span', { class: 'grow' }),
      h('button', { type: 'button', class: 'ghost sm', text: '✕', onclick: close })),
    content);
  veil.append(box);
  veil.addEventListener('click', (e) => { if (e.target === veil) close(); });
  document.addEventListener('keydown', esc);
  document.body.append(veil);
  // 定位：贴着点击处展开、不出屏。必须走 CSSOM 赋值 ——
  // CSP style-src 'self' 会把内联 style 属性整个丢掉，浮框就永远停在左上角。
  const r = anchor.getBoundingClientRect();
  const bw = box.offsetWidth, bh = box.offsetHeight;
  const left = Math.min(Math.max(8, r.left), Math.max(8, window.innerWidth - bw - 8));
  let top = r.bottom + 8;
  if (top + bh > window.innerHeight - 8) top = Math.max(8, r.top - bh - 8);
  box.style.left = left + 'px';
  box.style.top = top + 'px';
  return { close };
}

// withBusy：按钮在异步操作期间禁用并转圈，finally 一定还原。
async function withBusy(btn, fn) {
  if (btn) { btn.disabled = true; btn.classList.add('busy'); }
  try {
    return await fn();
  } finally {
    if (btn) { btn.disabled = false; btn.classList.remove('busy'); }
  }
}

// copyText：复制到剪贴板。非安全上下文（http 局域网地址）下 navigator.clipboard
// 不存在，退回 execCommand 兜底 —— 两条路都没有就让调用方报「复制没成功」。
async function copyText(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* 落到兜底 */ }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  } catch {
    return false;
  }
}

// showTokenDialog：一次性凭据（新 token）弹窗展示 + 一键复制。
// 不用 alert —— alert 里的文本选不中也复制不了，而这串值关掉就再也拿不到明文。
function showTokenDialog(token, title) {
  return new Promise((resolve) => {
    let ctl, settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      ctl.close();
      resolve();
    };
    const ta = h('textarea', {
      class: 'token-box', rows: '3', readonly: 'readonly', spellcheck: 'false',
    });
    ta.value = token || '';
    ta.addEventListener('focus', () => ta.select());
    const box = h('div', { class: 'modal-box confirm-box' },
      h('div', { class: 'modal-head' },
        h('strong', { text: title || '新 token' }),
        h('span', { class: 'grow' }),
        h('button', { type: 'button', class: 'ghost sm', text: '✕', onclick: finish })),
      ta,
      h('div', { class: 'row' },
        h('button', {
          type: 'button', class: 'sm', text: '复制',
          onclick: async () => {
            const ok = await copyText(token || '');
            if (ok) toast('已复制到剪贴板');
            else toast('复制没成功，请手动全选上面的文本', 'err');
          },
        }),
        h('span', { class: 'grow' }),
        h('button', { type: 'button', class: 'primary', text: '我已保存', onclick: finish })));
    ctl = modalOverlay(box, finish);
    ta.focus();
  });
}

// tableState：把表格体换成一行占位文字（「加载中…」「还没有记录」）。
function tableState(tb, colSpan, msg) {
  tb.replaceChildren(h('tr', null,
    h('td', { class: 'muted tstate', colspan: String(colSpan), text: msg })));
}
