'use strict';

const ADM = { users: [], sys: [], cfg: { providers: [] }, cands: {}, editing: null, detail: null };

// 管理台的请求都用 state.token（里面存的就是 admin_token），与公共 api() 是同一套
const adminApi = (path, opts) => api(path, opts);

/* ── 登录 / 进入 / 退出 ──────────────────────────────────────────────
   管理台只认 admin_token（server.admin_token）。用户入口在 /ui/，是另一个页面。 */

function renderLogin(msg) {
  $('admin').hidden = true;
  $('login').hidden = false;
  $('login-base').value = state.base || defaultBase();
  $('login-token').value = '';
  showErr($('login-err'), msg);
  $('login-hint').textContent = location.protocol === 'file:'
    ? '从本地文件打开时接口跨源会被拦；请通过网关的 /admin/ 访问。'
    : '地址默认是当前站点来源。用户控制台在同一个网关的 /ui/。';
  $('login-token').focus();
}

async function adminLogin(base, token) {
  state.base = base.replace(/\/+$/, '');
  state.token = token;
  try {
    await api('/v1/_admin/users'); // 只用来验身份
  } catch (e) {
    state.token = '';
    if (e.status === 403) return renderLogin('这个 admin_token 不对；也可能网关没配 server.admin_token（那样管理接口整体关闭）。');
    if (e.status === 501) return renderLogin('网关没启用多用户模式（服务端缺少主密钥）。');
    return renderLogin(e.status ? e.message : '连不上网关：' + e.message);
  }
  sessionSave();
  await enterAdmin();
}

async function enterAdmin() {
  $('login').hidden = true;
  $('admin').hidden = false;
  $('admin-base').textContent = state.base;
  await Promise.all([loadSysProviders(), loadAdminUsers()]);
}

function adminLogout() {
  sessionClear();
  state.token = '';
  ADM.users = [];
  ADM.editing = null;
  $('admin').hidden = true;
  renderLogin('');
}

$('login-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const btn = $('login-btn');
  btn.disabled = true;
  showErr($('login-err'), '');
  adminLogin($('login-base').value.trim() || defaultBase(), $('login-token').value.trim())
    .catch((err) => renderLogin('登录后加载失败：' + err.message))
    .finally(() => { btn.disabled = false; });
});
$('admin-logout').addEventListener('click', adminLogout);

/* ── 系统上游 ────────────────────────────────────────────────────── */

function modelsSummary(m) {
  if (!m) return '—';
  if (m.passthrough) return '任意模型名（直通）';
  const parts = Object.entries(m.map || {}).map(([down, up]) => (down === up ? down : down + ' → ' + up));
  if (m.catch_all) parts.push('+ 其余直通');
  return parts.join('、') || '—';
}

/* 系统上游：直接编辑 config.yaml 的 providers 段。
   编辑动作只改本地副本，点「保存」才写回；密钥永远是空串下发，
   留空即沿用原值 —— 把脱敏值当密钥写回去会一次清空所有密钥。 */
async function loadSysProviders() {
  const { data } = await adminApi('/v1/_admin/config');
  ADM.cfg = {
    path: data.path || 'config.yaml',
    mtime: data.mtime || '',
    providers: (data.providers || []).map((p) => ({
      name: p.name,
      enabled: !!p.enabled,
      base_url: p.base_url || '',
      api_key: '',            // 永远留空；占位符里显示当前值
      keyHint: p.api_key_hint || (p.has_key ? '（已设置）' : '（未设置）'),
      weight: p.weight || 1,
      proxy: p.proxy || 'direct',
      timeout_ms: p.timeout_ms || 120000,
      passthrough: !!(p.models && p.models.passthrough),
      map: Object.entries((p.models && p.models.map) || {}),
      catchAll: !!(p.models && p.models.catch_all),
    })),
  };
  $('sys-path').textContent = ADM.cfg.path;
  renderCfg();

  // 用户详情里「限定供应商」的下拉也跟着更新
  const sel = $('ud-new-provider');
  sel.replaceChildren(h('option', { value: '', text: '（系统池按权重）' }),
    ...ADM.cfg.providers.map((p) => h('option', { value: p.name, text: p.name })));
}

// 表单改动过的标记：探测/选模型之前要先把它存下去，否则新加的供应商在后端根本不存在
function touchCfg() { ADM.dirty = true; }

// 有改动就先保存（就近保存）。返回 true 表示确实存了。
async function ensureSaved() {
  if (!ADM.dirty) return false;
  const { data } = await adminApi('/v1/_admin/config/providers', {
    method: 'PUT', body: JSON.stringify(cfgPayload()),
  });
  ADM.dirty = false;
  await loadSysProviders();
  return data;
}

function renderCfg() {
  const box = $('cfg-list');
  box.replaceChildren(...ADM.cfg.providers.map((p, i) => cfgRow(p, i)));
  $('cfg-hint').textContent = ADM.cfg.providers.length + ' 家供应商';
}

function cfgRow(p, i) {
  const text = (cls, val, ph, on) => {
    const el = h('input', { type: 'text', class: cls, value: val, placeholder: ph || '', spellcheck: 'false', autocomplete: 'off' });
    el.addEventListener('input', () => { on(el.value); touchCfg(); });
    return el;
  };
  const num = (cls, val, on) => {
    const el = h('input', { type: 'number', class: cls, value: val });
    el.addEventListener('input', () => { on(Number(el.value) || 0); touchCfg(); });
    return el;
  };

  const key = h('input', { type: 'password', class: 'mono', value: '', spellcheck: 'false', autocomplete: 'off',
    placeholder: '留空 = 不修改（当前 ' + p.keyHint + '）' });
  key.addEventListener('input', () => { p.api_key = key.value; touchCfg(); });

  const enabled = h('input', { type: 'checkbox' });
  enabled.checked = p.enabled;
  enabled.addEventListener('change', () => { p.enabled = enabled.checked; touchCfg(); });

  const radioAll = h('input', { type: 'radio', name: 'cfgmode' + i });
  const radioPick = h('input', { type: 'radio', name: 'cfgmode' + i });
  radioAll.checked = p.passthrough;
  radioPick.checked = !p.passthrough;
  const mapBox = h('div', { class: 'mmap' });
  const renderMap = () => {
    mapBox.hidden = p.passthrough;
    mapBox.replaceChildren(
      ...p.map.map((pair, j) => {
        const down = text('mono', pair[0], '下游名', (v) => { p.map[j][0] = v; });
        const up = text('mono', pair[1], '上游模型名', (v) => { p.map[j][1] = v; });
        up.setAttribute('list', 'cfg-cands-' + i);
        return h('div', { class: 'mmap-row' }, down, h('span', { class: 'muted', text: '→' }), up,
          h('button', { type: 'button', class: 'link danger', text: '移除',
            onclick: () => { p.map.splice(j, 1); renderMap(); } }));
      }),
      h('div', { class: 'row' },
        h('button', { type: 'button', class: 'ghost sm', text: '+ 映射',
          onclick: () => { p.map.push(['', '']); touchCfg(); renderMap(); } }),
        h('span', { class: 'grow' }),
        h('input', { type: 'text', class: 'mono', placeholder: '过滤候选…', oninput: (e) => filterCands(i, e.target.value) }),
        h('datalist', { id: 'cfg-cands-' + i }),
      ),
      h('label', { class: 'inline mt' }, (() => {
        const cb = h('input', { type: 'checkbox' });
        cb.checked = p.catchAll;
        cb.addEventListener('change', () => { p.catchAll = cb.checked; touchCfg(); });
        return cb;
      })(), '其余模型也放行（catch-all）'),
    );
  };
  radioAll.addEventListener('change', () => { p.passthrough = true; touchCfg(); renderMap(); });
  radioPick.addEventListener('change', () => { p.passthrough = false; touchCfg(); renderMap(); });
  renderMap();

  const head = h('div', { class: 'prow-head' },
    text('pname mono', p.name, '供应商名', (v) => { p.name = v; }),
    h('label', { class: 'inline' }, enabled, '启用'),
    h('span', { class: 'grow' }),
    h('button', { type: 'button', class: 'link', text: '选模型…',
      onclick: () => pickModels(i) }),
    h('button', { type: 'button', class: 'link', text: '测试',
      onclick: () => testProviderRow(i) }),
    h('button', { type: 'button', class: 'link danger', text: '删除',
      onclick: () => { ADM.cfg.providers.splice(i, 1); renderCfg(); } }),
  );

  return h('div', { class: 'prow' },
    head,
    h('div', { class: 'prow-grid' },
      h('div', null, h('label', { text: '地址' }), text('pbase mono', p.base_url, 'https://api.example.com/v1', (v) => { p.base_url = v; })),
      h('div', null, h('label', { text: '密钥' }), key),
      h('div', null, h('label', { text: '权重' }), num('pweight', p.weight, (v) => { p.weight = v; })),
      h('div', null, h('label', { text: '代理' }), text('pproxy mono', p.proxy, 'direct', (v) => { p.proxy = v; })),
      h('div', null, h('label', { text: '超时 (ms)' }), num('ptimeout', p.timeout_ms, (v) => { p.timeout_ms = v; })),
    ),
    h('div', { class: 'prow-models' },
      h('label', { class: 'inline' }, radioAll, '全部直通（任何模型名都转发）'),
      h('label', { class: 'inline' }, radioPick, '指定映射'),
      mapBox,
    ),
  );
}

function filterCands(i, q) {
  const dl = $('cfg-cands-' + i);
  if (!dl) return;
  const all = ADM.cands[i] || [];
  const hit = all.filter((m) => !q || m.toLowerCase().includes(q.toLowerCase()));
  dl.replaceChildren(...hit.slice(0, 200).map((m) => h('option', { value: m })));
}

// ── 选模型弹窗 ───────────────────────────────────────────────────────
// 上游到底有哪些模型，不该让人猜：先（必要时就近保存）取回列表，再勾选。
// 新加的、还没保存的供应商也能用 —— 后端探测接口允许内联 base_url / api_key。
const PICK = { idx: -1, models: [], checked: new Set() };

async function fetchModelsForRow(i) {
  const p = ADM.cfg.providers[i];
  const body = { base_url: p.base_url.trim(), api_key: p.api_key, proxy: p.proxy.trim() };
  const name = p.name.trim() || '-';
  const { data } = await adminApi('/v1/_admin/providers/' + encodeURIComponent(name) + '/discover', {
    method: 'POST', body: JSON.stringify(body),
  });
  return data.models || [];
}

async function pickModels(i) {
  const banner = $('cfg-result');
  banner.hidden = false;
  banner.textContent = '正在读取上游的模型列表…';
  try {
    // 就近保存：新加的供应商还没入库，探测接口虽然支持内联，但先把改动存下来更省事
    const saved = await ensureSaved();
    const models = await fetchModelsForRow(i);
    PICK.idx = i;
    PICK.models = models;
    PICK.checked = new Set(ADM.cfg.providers[i].map.map((pair) => pair[0]).filter(Boolean));
    $('pick-title').textContent = '选择模型 — ' + (ADM.cfg.providers[i].name || '（未命名）');
    $('pick-hint').textContent = saved ? '（已先保存本次改动）' : '';
    $('pick-filter').value = '';
    renderPick();
    $('pick-modal').hidden = false;
    banner.hidden = true;
  } catch (e) {
    banner.textContent = '取模型列表失败：' + e.message;
  }
}

function renderPick() {
  const q = $('pick-filter').value.trim().toLowerCase();
  const list = PICK.models.filter((m) => !q || m.toLowerCase().includes(q));
  const box = $('pick-list');
  box.replaceChildren(...list.map((m) => {
    const cb = h('input', { type: 'checkbox' });
    cb.checked = PICK.checked.has(m);
    // 用 div 而不是 label：label 会把点击**转发**给里面的复选框，
    // 于是「行处理器 + 复选框处理器」各切一次，净效果为零（表现为点了没反应）。
    const row = h('div', { class: 'cand' }, cb, h('span', { class: 'mono', text: m }));
    const toggle = () => {
      if (PICK.checked.has(m)) PICK.checked.delete(m); else PICK.checked.add(m);
      cb.checked = PICK.checked.has(m);
      $('pick-count').textContent = '已选 ' + PICK.checked.size + ' / ' + PICK.models.length;
    };
    // preventDefault 必须有：复选框的「翻转」是默认动作，在本处理器之后执行，
    // 不拦掉的话它会把我设的 checked 又翻回去。
    row.addEventListener('click', (e) => { e.preventDefault(); toggle(); });
    return row;
  }));
  box.hidden = list.length === 0;
  $('pick-empty').hidden = PICK.models.length > 0;
  $('pick-count').textContent = '已选 ' + PICK.checked.size + ' / ' + PICK.models.length;
}

function closePick() { $('pick-modal').hidden = true; PICK.idx = -1; }

function applyPick() {
  const i = PICK.idx;
  if (i < 0) return closePick();
  const p = ADM.cfg.providers[i];
  const exist = new Set(p.map.map((pair) => pair[0]));
  for (const m of PICK.checked) {
    if (!exist.has(m)) p.map.push([m, m]);   // 下游名默认与上游模型同名
  }
  // 勾了模型却还停在「全部直通」上就说不通了，直接切成指定映射
  if (PICK.checked.size > 0) {
    p.passthrough = false;
    $('cfg-list').replaceChildren(...ADM.cfg.providers.map(cfgRow));
  }
  touchCfg();
  closePick();
  const banner = $('cfg-result');
  banner.hidden = false;
  banner.textContent = '已加入 ' + PICK.checked.size + ' 个模型（下游名默认同名，可在表里改）。' +
    '别忘了点右上角「保存」。';
}

// ── 快速测试 ─────────────────────────────────────────────────────────
// 真发一条极小的请求（最多 8 个 token），用来确认「这家上游 / 这条映射通不通」。
async function testProviderRow(i) {
  const p = ADM.cfg.providers[i];
  const banner = $('cfg-result');
  banner.hidden = false;
  banner.textContent = '正在测试 ' + (p.name || '（未命名）') + ' …';
  try {
    await ensureSaved();
    const model = (p.map.find((pair) => pair[0]) || [])[0] || '';
    const { data } = await adminApi('/v1/_admin/providers/' + encodeURIComponent(p.name.trim() || '-') + '/test', {
      method: 'POST', body: JSON.stringify({ model }),
    });
    banner.textContent = describeTest(p.name || '（未命名）', data);
  } catch (e) {
    banner.textContent = '测试失败：' + e.message;
  }
}

function describeTest(label, d) {
  if (!d || !d.ok) {
    return '✗ ' + label + ' 不通：' + ((d && d.error) || '未知错误');
  }
  return '✓ ' + label + ' 通了：上游 ' + d.provider + ' · 模型 ' + d.upstream_model +
    ' · ' + d.latency_ms + 'ms · 回复「' + (d.content || '').slice(0, 20) + '」' +
    (d.tokens ? ' · ' + d.tokens + ' tokens' : '');
}

// 按用户测某条映射（模型名用下游名，走该用户自己的路由）
async function testMapping(userName, model, cell) {
  cell.textContent = '测试中…';
  cell.className = 'testres';
  try {
    const { data } = await adminApi('/v1/_admin/users/' + encodeURIComponent(userName) + '/test', {
      method: 'POST', body: JSON.stringify({ model }),
    });
    if (data.ok) {
      cell.className = 'testres ok';
      cell.textContent = '✓ ' + data.provider + ' · ' + data.latency_ms + 'ms';
      cell.title = '上游模型 ' + data.upstream_model + '，回复：' + (data.content || '');
    } else {
      cell.className = 'testres bad';
      cell.textContent = '✗ ' + (data.error || '失败');
      cell.title = data.error || '';
    }
  } catch (e) {
    cell.className = 'testres bad';
    cell.textContent = '✗ ' + e.message;
  }
}

// 把编辑结果收成接口要的形状
function cfgPayload() {
  return {
    providers: ADM.cfg.providers.map((p) => {
      const body = {
        name: p.name.trim(),
        enabled: !!p.enabled,
        base_url: p.base_url.trim(),
        api_key: p.api_key,     // 空 = 服务端沿用原值（绝不等于清空）
        weight: p.weight,
        proxy: p.proxy.trim(),
        timeout_ms: p.timeout_ms,
      };
      if (p.passthrough) {
        body.models = ['*'];
      } else {
        const m = {};
        for (const [d, u] of p.map) {
          if (d && d.trim()) m[d.trim()] = (u || '').trim() || d.trim();
        }
        if (p.catchAll) m['*'] = '*';
        body.models = Object.keys(m).length ? m : ['*'];
      }
      return body;
    }),
  };
}

function showCfgResult(text, kind) {
  const el = $('cfg-result');
  el.hidden = false;
  el.textContent = text;
  el.className = 'banner' + (kind === 'err' ? ' err-banner' : '');
}

async function saveConfig() {
  const btn = $('cfg-save');
  btn.disabled = true;
  showCfgResult('保存中…');
  try {
    const { data } = await adminApi('/v1/_admin/config/providers', {
      method: 'PUT', body: JSON.stringify(cfgPayload()),
    });
    let msg = '已写入 ' + data.count + ' 家供应商，备份 ' + data.backup + '。';
    msg += data.applied ? '热加载已生效（revision ' + data.revision + '）。' : '热加载最多 2 秒后生效。';
    if (data.warning) msg += '\n⚠ ' + data.warning;
    if (data.warnings && data.warnings.length) msg += '\n注意：' + data.warnings.join('；');
    showCfgResult(msg, data.warning ? 'err' : '');
    await loadSysProviders();
  } catch (e) {
    showCfgResult('保存失败（原文件未改动）：' + e.message, 'err');
  } finally {
    btn.disabled = false;
  }
}

async function validateConfig() {
  const btn = $('cfg-validate');
  btn.disabled = true;
  showCfgResult('校验中…');
  try {
    const { data } = await adminApi('/v1/_admin/config/validate', {
      method: 'POST', body: JSON.stringify(cfgPayload()),
    });
    let msg = '校验通过：' + data.providers + ' 家供应商（未落盘）。';
    if (data.warning) msg += '\n⚠ ' + data.warning;
    showCfgResult(msg, data.warning ? 'err' : '');
  } catch (e) {
    showCfgResult('校验不通过：' + e.message, 'err');
  } finally {
    btn.disabled = false;
  }
}

/* ── 用户列表 ────────────────────────────────────────────────────── */

function moneyShort(v) {
  const n = Number(v || 0);
  return n >= 1 ? n.toFixed(2) : n.toFixed(4);
}

async function loadAdminUsers() {
  const { data } = await adminApi('/v1/_admin/users');
  ADM.users = (data && data.users) || [];
  const cur = (data && data.currency) || 'CNY';

  const tb = $('u-table').querySelector('tbody');
  tb.replaceChildren(...ADM.users.map((u) => {
    const q = u.quota || {};
    const tokCell = q.month_tokens > 0
      ? num(q.used_tokens) + ' / ' + num(q.month_tokens)
      : num(q.used_tokens) + '（不限）';
    const costCell = q.month_cost > 0
      ? moneyShort(q.used_cost) + ' / ' + q.month_cost.toFixed(2)
      : moneyShort(q.used_cost);
    const lim = u.limits || {};
    const limText = [lim.rpm > 0 ? lim.rpm + '/分' : null, lim.max_concurrent > 0 ? '并发 ' + lim.max_concurrent : null]
      .filter(Boolean).join('、') || '不限';
    return h('tr', null,
      h('td', null, h('code', { class: 'k', text: u.name })),
      h('td', null, h('span', { class: 'dot' + (u.enabled ? '' : ' off') }), u.enabled ? '启用' : '停用'),
      h('td', null, h('span', { class: 'tag' + (u.mode === 'consumption' ? ' ok' : ''), text: u.mode })),
      h('td', { class: 'num', text: tokCell }),
      h('td', { class: 'num', text: costCell + ' ' + cur }),
      h('td', { class: 'num', text: String((u.models || []).length) }),
      h('td', null, h('span', { class: 'muted', text: limText })),
      h('td', null, h('button', {
        type: 'button', class: 'link', text: '编辑',
        onclick: () => openUser(u.name),
      })),
    );
  }));
  $('u-empty').hidden = ADM.users.length > 0;

  // 详情开着的话跟着刷新（改完设置要立刻看到新值）
  if (ADM.editing) await openUser(ADM.editing, true);
}

/* ── 用户详情 ────────────────────────────────────────────────────── */

async function openUser(name, quiet) {
  ADM.editing = name;
  $('u-detail').hidden = false;
  showErr($('ud-err'), '');
  if (!quiet) $('u-detail').scrollIntoView({ block: 'start', behavior: 'smooth' });

  const { data } = await adminApi('/v1/_admin/users/' + encodeURIComponent(name));
  ADM.detail = data;

  $('ud-title').textContent = '用户 ' + name;
  const q = data.quota || {}, lim = data.limits || {};
  $('ud-byo').checked = data.mode !== 'consumption';
  $('ud-cons').checked = data.mode === 'consumption';
  $('ud-enabled').checked = !!data.enabled;
  $('ud-qtokens').value = q.month_tokens || 0;
  $('ud-qcost').value = q.month_cost || 0;
  $('ud-rpm').value = lim.rpm || 0;
  $('ud-conc').value = lim.max_concurrent || 0;

  const banner = $('admin-banner');
  if (data.warning) {
    banner.hidden = false;
    banner.textContent = data.warning;
  } else {
    banner.hidden = true;
  }

  renderModelScope(data);
  await Promise.all([loadUserModels(name), loadUserUsage(name)]);
}

// 模型范围：继承系统池 还是 指定收窄。这是消费模式最常调的一项 ——
// 默认继承，所以新用户不需要管理员逐条配模型。
function renderModelScope(data) {
  const inherit = data.models_source !== 'own';
  $('ud-inherit').checked = inherit;
  $('ud-narrow').checked = !inherit;
  $('ud-models-box').hidden = inherit;
  $('ud-inherit-box').hidden = !inherit;
  if (inherit) renderInheritedModels(ADM.editing, data.models || []);

  const pool = systemModelNames();
  $('ud-models-note').textContent = inherit
    ? '该用户继承系统池声明的全部模型' + (pool.length ? '：' + pool.join('、') : '') +
      (pool.length ? '' : '（系统池当前没有声明具体模型名）')
    : '该用户被收窄到下面这张表里的模型。要放开就切回「继承系统池」。';
}

// 继承模式下列出「他会继承到的模型」并逐个可测。
// 继承是默认路径（方案 A），这里不列出来的话快速测试对绝大多数用户都够不着。
function renderInheritedModels(name, models) {
  const tb = $('ud-inherit-models').querySelector('tbody');
  tb.replaceChildren(...models.map((m) => {
    const res = h('span', { class: 'testres', text: '—' });
    return h('tr', null,
      h('td', null, h('code', { class: 'k', text: m })),
      h('td', null,
        h('button', { type: 'button', class: 'link', text: '测试',
          onclick: () => testMapping(name, m, res) }),
        ' ', res),
    );
  }));
  $('ud-inherit-empty').hidden = models.length > 0;
}

// 系统池当前声明了哪些逻辑模型名（供上面那句提示用）
function systemModelNames() {
  const names = [];
  for (const p of ADM.cfg.providers || []) {
    if (!p.passthrough) {
      for (const [down] of p.map || []) {
        if (down && !names.includes(down)) names.push(down);
      }
    }
  }
  return names.sort();
}

// 切到「继承」= 清空全部映射（服务端语义：没有映射就是继承）
async function switchToInherit() {
  const name = ADM.editing;
  if (!name) return;
  const n = $('ud-models').querySelectorAll('tbody tr').length;
  if (n && !confirm('改为继承系统池？会清空该用户现有的 ' + n + ' 条模型映射。')) {
    renderModelScope(ADM.detail || {});
    return;
  }
  try {
    await adminApi('/v1/_admin/users/' + encodeURIComponent(name) + '/models', { method: 'DELETE' });
    await openUser(name, true);
  } catch (e) {
    showErr($('ud-err'), e.message);
  }
}

// 切到「指定」：先把编辑区露出来，映射要至少加一条才真正生效
function switchToNarrow() {
  $('ud-models-box').hidden = false;
  $('ud-models-note').textContent = '收窄模式：下面这张表里的模型才可用。至少要加一条，否则该用户什么模型都用不了。';
}

async function saveUser() {
  const name = ADM.editing;
  if (!name) return;
  const btn = $('ud-save');
  btn.disabled = true;
  try {
    await adminApi('/v1/_admin/users/' + encodeURIComponent(name), {
      method: 'PUT',
      body: JSON.stringify({
        mode: $('ud-cons').checked ? 'consumption' : 'byo',
        enabled: $('ud-enabled').checked,
        quota_month_tokens: Number($('ud-qtokens').value) || 0,
        quota_month_cost: Number($('ud-qcost').value) || 0,
        rpm: Number($('ud-rpm').value) || 0,
        max_concurrent: Number($('ud-conc').value) || 0,
      }),
    });
    showErr($('ud-err'), '');
    await loadAdminUsers();
  } catch (e) {
    showErr($('ud-err'), e.message);
  } finally {
    btn.disabled = false;
  }
}

async function toggleUser() {
  const name = ADM.editing;
  if (!name) return;
  const next = !($('ud-enabled').checked);
  try {
    await adminApi('/v1/_admin/users/' + encodeURIComponent(name) + '/' + (next ? 'enable' : 'disable'), { method: 'POST' });
    await loadAdminUsers();
  } catch (e) {
    showErr($('ud-err'), e.message);
  }
}

async function rotateToken() {
  const name = ADM.editing;
  if (!name) return;
  if (!confirm('轮换 ' + name + ' 的 token？旧 token 立即失效，要用新 token 重新登录。')) return;
  try {
    const { data } = await adminApi('/v1/_admin/users/' + encodeURIComponent(name) + '/token', { method: 'POST' });
    showToken(data.token, '新 token（只显示这一次）');
  } catch (e) {
    showErr($('ud-err'), e.message);
  }
}

async function deleteUser() {
  const name = ADM.editing;
  if (!name) return;
  if (!confirm('删除用户 ' + name + ' 及其全部模型映射与上游？不可恢复。')) return;
  try {
    await adminApi('/v1/_admin/users/' + encodeURIComponent(name), { method: 'DELETE' });
    $('u-detail').hidden = true;
    ADM.editing = null;
    await loadAdminUsers();
  } catch (e) {
    showErr($('ud-err'), e.message);
  }
}

/* ── 模型映射 ────────────────────────────────────────────────────── */

async function loadUserModels(name) {
  const { data } = await adminApi('/v1/_admin/users/' + encodeURIComponent(name) + '/models');
  const list = (data && data.models) || [];
  const tb = $('ud-models').querySelector('tbody');
  tb.replaceChildren(...list.map((m) => {
    const res = h('span', { class: 'testres', text: '—' });
    return h('tr', null,
      h('td', null, h('code', { class: 'k', text: m.model })),
      h('td', null, h('code', { class: 'k', text: m.upstream || '（同名）' })),
      h('td', null, h('code', { class: 'k', text: m.provider || '（系统池）' })),
      h('td', null, h('span', { class: 'dot' + (m.enabled ? '' : ' off') }), m.enabled ? '启用' : '停用'),
      // 每条映射都有个「测试」：加完立刻知道通不通，不用等用户来报错
      h('td', null,
        h('button', { type: 'button', class: 'link', text: '测试',
          onclick: () => testMapping(name, m.model, res) }),
        ' ', res),
      h('td', null, h('button', {
        type: 'button', class: 'link danger', text: '删除',
        onclick: () => deleteModel(name, m.model),
      })),
    );
  }));
  $('ud-models-empty').hidden = list.length > 0;
}

// 代用户配映射时，上游模型名得填真实存在的 —— 探测选中的那家系统上游
async function probeForMapping() {
  const picked = $('ud-new-provider').value;
  const fallback = (ADM.cfg.providers[0] || {}).name;
  const name = picked || fallback;
  if (!name) return showErr($('ud-err'), '先在右边选一个系统上游');
  showErr($('ud-err'), '正在探测 ' + name + ' …');
  try {
    const { data } = await adminApi('/v1/_admin/providers/' + encodeURIComponent(name) + '/discover', { method: 'POST' });
    $('ud-cands').replaceChildren(...(data.models || []).map((m) => h('option', { value: m })));
    showErr($('ud-err'), '');
    const banner = $('admin-banner');
    banner.hidden = false;
    banner.textContent = name + ' 返回 ' + data.count + ' 个模型，已填成「上游模型」的候选：' +
      (data.models || []).slice(0, 6).join('、') + (data.count > 6 ? ' …' : '');
  } catch (e) {
    showErr($('ud-err'), '探测失败：' + e.message);
  }
}

async function addModel() {
  const name = ADM.editing;
  if (!name) return;
  const model = $('ud-new-model').value.trim();
  if (!model) return showErr($('ud-err'), '先填下游模型名');
  try {
    const { data } = await adminApi('/v1/_admin/users/' + encodeURIComponent(name) + '/models', {
      method: 'PUT',
      body: JSON.stringify({
        model,
        upstream: $('ud-new-upstream').value.trim(),
        provider: $('ud-new-provider').value,
      }),
    });
    $('ud-new-model').value = '';
    $('ud-new-upstream').value = '';
    showErr($('ud-err'), data.note || '');
    await Promise.all([loadUserModels(name), loadAdminUsers()]);
    if (ADM.detail) renderModelScope({ models_source: 'own' });
  } catch (e) {
    showErr($('ud-err'), e.message);
  }
}

async function deleteModel(name, model) {
  if (!confirm('删除映射 ' + model + '？')) return;
  try {
    // 模型名可能含 /，所以走 query 不走路径
    await adminApi('/v1/_admin/users/' + encodeURIComponent(name) + '/models?model=' + encodeURIComponent(model), {
      method: 'DELETE',
    });
    await Promise.all([loadUserModels(name), loadAdminUsers()]);
  } catch (e) {
    showErr($('ud-err'), e.message);
  }
}

/* ── 用量 ────────────────────────────────────────────────────────── */

async function loadUserUsage(name) {
  const { data } = await adminApi('/v1/_admin/users/' + encodeURIComponent(name) + '/usage?days=7');
  const rows = (data && data.rows) || [];
  const tb = $('ud-usage').querySelector('tbody');
  tb.replaceChildren(...rows.map((r) => h('tr', null,
    h('td', null, h('code', { class: 'k', text: r.day })),
    h('td', null, h('code', { class: 'k', text: r.provider })),
    h('td', null, h('code', { class: 'k', text: r.model })),
    h('td', { class: 'num', text: num(r.requests) }),
    h('td', { class: 'num', text: num(r.ok) }),
    h('td', { class: 'num', text: num(r.failed) }),
    h('td', { class: 'num', text: num(r.prompt_tokens) }),
    h('td', { class: 'num', text: num(r.cache_hit_tokens) }),
    h('td', { class: 'num', text: num(r.completion_tokens) }),
    h('td', { class: 'num', text: num(r.total_tokens) }),
    h('td', { class: 'num', text: r.cost != null ? r.cost.toFixed(4) : '—' }),
  )));
  $('ud-usage-empty').hidden = rows.length > 0;
}

/* ── 新建用户 ────────────────────────────────────────────────────── */

async function createUser(ev) {
  ev.preventDefault();
  const name = $('nu-name').value.trim();
  if (!name) return showErr($('nu-err'), '用户名必填');
  try {
    const { data } = await adminApi('/v1/_admin/users', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
    $('nu-name').value = '';
    $('u-add-form').hidden = true;
    showErr($('nu-err'), '');
    showToken(data.token, '用户 ' + name + ' 的 token（只显示这一次，请立刻交给他）');
    if ($('nu-mode').value === 'consumption') {
      await adminApi('/v1/_admin/users/' + encodeURIComponent(name), {
        method: 'PUT', body: JSON.stringify({ mode: 'consumption' }),
      });
      $('u-add-form').hidden = true;
    }
    await loadAdminUsers();
  } catch (e) {
    showErr($('nu-err'), e.message);
  }
}

function showToken(token, title) {
  const box = $('new-token');
  box.hidden = false;
  box.textContent = title + '\n\n' + token;
}

/* ── 事件绑定 ────────────────────────────────────────────────────── */

$('admin-logout').addEventListener('click', adminLogout);
$('u-add').addEventListener('click', () => {
  $('u-add-form').hidden = !$('u-add-form').hidden;
  $('nu-name').focus();
});
$('nu-cancel').addEventListener('click', () => { $('u-add-form').hidden = true; });
$('u-add-form').addEventListener('submit', createUser);
$('ud-close').addEventListener('click', () => { $('u-detail').hidden = true; ADM.editing = null; });
$('ud-save').addEventListener('click', saveUser);
$('ud-enable').addEventListener('click', toggleUser);
$('ud-token').addEventListener('click', rotateToken);
$('ud-delete').addEventListener('click', deleteUser);
$('ud-add-model').addEventListener('click', addModel);
$('ud-inherit').addEventListener('change', switchToInherit);
$('ud-narrow').addEventListener('change', switchToNarrow);
$('ud-probe').addEventListener('click', probeForMapping);
$('ud-new-model').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); addModel(); } });
$('ud-new-upstream').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); addModel(); } });
$('cfg-save').addEventListener('click', saveConfig);
$('cfg-validate').addEventListener('click', validateConfig);
$('pick-close').addEventListener('click', closePick);
$('pick-ok').addEventListener('click', applyPick);
$('pick-filter').addEventListener('input', renderPick);
$('pick-all').addEventListener('click', () => { PICK.models.forEach((m) => PICK.checked.add(m)); renderPick(); });
$('pick-none').addEventListener('click', () => { PICK.checked.clear(); renderPick(); });
$('pick-modal').addEventListener('click', (e) => { if (e.target === $('pick-modal')) closePick(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('pick-modal').hidden) closePick(); });
$('cfg-add').addEventListener('click', () => {
  ADM.cfg.providers.push({
    name: '', enabled: true, base_url: '', api_key: '', keyHint: '（未设置）',
    weight: 1, proxy: 'direct', timeout_ms: 120000, passthrough: true, map: [], catchAll: false,
  });
  renderCfg();
});

/* 启动：管理台只认 admin_token */
(function boot() {
  state.storageKey = 'llmproxy.admin';
  const s = sessionLoad();
  if (s.token) {
    adminLogin(s.base, s.token).catch((e) => renderLogin('启动失败：' + e.message));
  } else {
    renderLogin('');
  }
})();
