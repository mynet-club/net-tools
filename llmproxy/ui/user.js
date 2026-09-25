'use strict';

/* ── 登录 ─────────────────────────────────────────────────────────── */

function renderLogin(msg) {
  $('app').hidden = true;
  $('login').hidden = false;
  $('login-base').value = state.base || defaultBase();
  showErr($('login-err'), msg);
  $('login-hint').textContent = location.protocol === 'file:'
    ? '当前是从本地文件打开的：接口调用需要跨源，浏览器通常会拦。要用真实数据请访问网关的 /ui/。'
    : '地址默认就是当前站点的来源（同源，不需要 CORS）。';
  $('login-token').focus();
}

// 用户台只有「用户」这一个身份，不做任何身份猜测：管理员入口在 /admin/，是另一个页面。
async function login(base, token) {
  state.base = base.replace(/\/+$/, '');
  state.token = token;
  try {
    const { data } = await api('/v1/_me');
    state.me = data;
    sessionSave();
    renderApp();
    await Promise.all([loadProviders(), loadModelOverview(), loadUsage()]);
  } catch (e) {
    state.token = '';
    if (e.status === 401) renderLogin('token 无效。');
    else if (e.status === 403) {
      renderLogin('这个 token 没有用户身份。注意：config.yaml 里的 api_keys 是给 ' +
        '/v1/chat/completions 用的静态 key，登录不了这里；请用 llmproxy user add 建的 token。');
    } else if (e.status === 501) renderLogin('网关没启用多用户模式（服务端缺少主密钥）。');
    else renderLogin(e.status ? e.message : '连不上网关：' + e.message);
  }
}

function logout() {
  sessionClear();
  state.token = '';
  state.me = null;
  renderLogin('');
}

/* ── 概览 ─────────────────────────────────────────────────────────── */

function stat(k, v, cls) {
  return h('div', null,
    h('div', { class: 'k', text: k }),
    h('div', { class: cls ? 'v ' + cls : 'v', text: v }));
}

function renderApp() {
  $('login').hidden = true;
  $('app').hidden = false;
  const me = state.me || {};
  const u = me.usage || {};

  $('who').textContent = me.name || '';
  $('base-label').textContent = state.base;

  const consumption = me.mode === 'consumption';
  const badge = $('badge');
  badge.hidden = false;
  badge.textContent = (consumption ? '消费模式 · ' : '') + (me.enabled ? '已启用' : '已停用');
  badge.className = 'badge' + (me.enabled ? '' : ' off');

  const broken = $('broken');
  if (me.broken_providers && me.broken_providers.length) {
    broken.textContent = '这些上游当前不可用：' + me.broken_providers.join('、') +
      '（常见原因：master.key 被换过导致解密失败，或地址/模型配置非法）。';
    broken.hidden = false;
  } else {
    broken.hidden = true;
  }

  $('overview').replaceChildren(
    stat('请求总数', num(u.requests)),
    stat('成功 / 失败', num(u.ok) + ' / ' + num(u.failed)),
    stat('token 合计', num(u.total_tokens)),
    stat('记录区间', (u.first_day || '—') + ' ~ ' + (u.last_day || '—'), 'sm'),
  );

  renderMode(me);

  $('t-model').value = $('t-model').value || 'deepseek-chat';
}

// 两种模式看到的卡片不同，但「我的上游 / 我的模型」都保留、都可配：
// 消费模式下它们是**混合**的一半 —— 自有上游优先命中（自己结算），
// 没命中或全挂才回落系统池（走网关的账与配额）。
function renderMode(me) {
  const consumption = me.mode === 'consumption';
  $('quota-card').hidden = !consumption;
  $('models-card').hidden = !consumption;

  const note = $('byo-notice');
  const sub = $('my-providers-sub');
  if (consumption) {
    note.textContent = '当前是「消费模式」：下面「我的上游 / 我的模型」里的模型会**优先**使用' +
      '（花你自己的额度，自己的上游结算）；它们没承接、或全部不可用时，才回落到网关的系统上游，' +
      '那部分才计入上面的配额。';
    note.hidden = false;
    sub.textContent = '自有上游优先；承接不到这个模型、或全部不可用时，回落到网关的系统上游。';
  } else {
    note.hidden = true;
    sub.textContent = '自己配了上游，请求就只走自己的 —— 不会落到网关的系统上游上。';
  }
  const myp = $('my-providers-card');
  if (myp) myp.classList.remove('dim');
  const mym = $('my-models-card');
  if (mym) mym.classList.remove('dim');
  if (!consumption) return;

  const q = me.quota || {};
  const cur = q.currency || 'CNY';
  const lim = (v) => (v > 0 ? v : null);

  const tokLim = lim(q.month_tokens);
  const costLim = lim(q.month_cost);
  $('quota').replaceChildren(
    stat('可用模型', String((me.models || []).length)),
    stat('本月已用 token', num(q.used_tokens) + (tokLim ? ' / ' + num(tokLim) : '（不限）')),
    stat('本月估算金额', (costLim
      ? money(q.used_cost) + ' / ' + costLim.toFixed(2)
      : money(q.used_cost)) + ' ' + cur),
    stat('剩余额度', tokLim ? num(q.left_tokens) + ' token' : (costLim ? money(q.left_cost, cur) : '不限'), 'sm'),
  );

  // 有上限时给一条细进度条：数字看不出「还剩多少」，条看得出来
  const bars = [];
  if (tokLim) bars.push(bar('token', q.used_tokens, tokLim));
  if (costLim) bars.push(bar('金额 ' + cur, q.used_cost, costLim));
  $('quota-bars').replaceChildren(...bars);

  const ms = me.models || [];
  const box = $('models');
  box.replaceChildren(...ms.map((m) => h('span', { class: 'chip', text: m })));
  $('models-empty').hidden = ms.length > 0;

  // 说清这些模型从哪来：继承系统池，还是管理员给你单独收窄了 —— 决定你该不该找人
  $('models-note').textContent = me.models_source === 'own'
    ? '管理员为你指定了模型范围。范围外的模型会被直接拒绝（403），请求不会打到上游；需要放开请联系管理员。'
    : '这些是网关主人开放的模型，直接就能用（不用自己配）。需要只给你开一部分、或换个名字，让管理员指定即可。';
  const pass = $('models-pass');
  if (me.models_passthrough) {
    pass.textContent = '注意：上游里有一家接受任意模型名（直通），所以实际可用的不止上面这些。';
    pass.hidden = false;
  } else {
    pass.hidden = true;
  }

  // 「试一下」的默认模型必须是白名单里的，否则用户一点就吃 403
  const t = $('t-model');
  if (ms.length && !ms.includes(t.value.trim())) t.value = ms[0];
}

function bar(label, used, limit) {
  const pct = Math.min(100, limit > 0 ? (used / limit) * 100 : 0);
  return h('div', { class: 'barrow' },
    h('div', { class: 'barlabel', text: label }),
    h('div', { class: 'bartrack' }, h('div', {
      class: 'barfill' + (pct >= 100 ? ' full' : pct >= 80 ? ' warn' : ''),
      style: 'width:' + pct.toFixed(1) + '%',
    })),
    h('div', { class: 'barpct', text: pct.toFixed(0) + '%' }),
  );
}

/* ── 我的上游 ─────────────────────────────────────────────────────── */

function modelsChips(m) {
  if (!m) return [h('span', { class: 'muted', text: '—' })];
  if (m.passthrough) return [h('code', { class: 'k', text: '* 全部直通' })];
  const out = Object.entries(m.map || {}).map(([down, up]) =>
    h('span', { class: 'chip', text: down === up ? down : down + ' → ' + up }));
  if (m.catch_all) out.push(h('span', { class: 'chip', text: '其余直通' }));
  return out.length ? out : [h('span', { class: 'muted', text: '—' })];
}

async function loadProviders() {
  const { data } = await api('/v1/_me/providers');
  const list = (data && data.providers) || [];
  state.providers = list;
  const tb = $('ptable').querySelector('tbody');
  tb.replaceChildren();
  $('pempty').hidden = list.length > 0;

  for (const p of list) {
    tb.append(h('tr', null,
      h('td', null, h('code', { class: 'k', text: p.name })),
      h('td', null, h('code', { class: 'k', text: p.base_url })),
      h('td', null, modelsChips(p.models)),
      h('td', { class: 'num', text: String(p.weight) }),
      h('td', null, h('code', { class: 'k', text: p.proxy || 'direct' })),
      h('td', { class: 'num', text: ms(p.timeout_ms) }),
      h('td', null, h('code', { class: 'k', text: p.api_key || '—' })),
      h('td', null, h('span', { class: 'dot' + (p.enabled ? '' : ' off') }), p.enabled ? '启用' : '停用'),
      h('td', null,
        h('button', { type: 'button', class: 'link', text: '编辑', onclick: () => openForm(p) }),
        h('button', { type: 'button', class: 'link danger', text: '删除', onclick: () => delProvider(p) })),
    ));
  }
}

function openForm(p) {
  state.editing = p || null;
  $('pform').hidden = false;
  $('pform-err').hidden = true;
  $('f-name').value = p ? p.name : '';
  $('f-name').disabled = !!p;
  $('f-base').value = p ? p.base_url : '';
  $('f-key').value = '';
  $('f-key').placeholder = p ? '留空 = 不修改（当前 ' + (p.api_key || '已设置') + '）' : 'sk-…';
  mmReset(p ? p.models : null, p ? p.name : $('f-name').value.trim());
  $('f-weight').value = p ? p.weight : 1;
  $('f-timeout').value = p ? p.timeout_ms : 120000;
  $('f-proxy').value = p ? (p.proxy || 'direct') : 'direct';
  $('f-enabled').checked = p ? !!p.enabled : true;
  ($('f-base').value ? $('f-key') : $('f-name')).focus();
  $('f-name').scrollIntoView({ block: 'center', behavior: 'smooth' });
}

function closeForm() {
  $('pform').hidden = true;
  state.editing = null;
}

async function saveProvider(ev) {
  ev.preventDefault();
  const name = $('f-name').value.trim();
  if (!name) return showErr($('pform-err'), '上游名必填');

  const models = mmCollect();
  if (models === null) return;

  const body = {
    base_url: $('f-base').value.trim(),
    models,
    weight: Number($('f-weight').value) || 1,
    timeout_ms: Number($('f-timeout').value) || 120000,
    proxy: $('f-proxy').value.trim() || 'direct',
    enabled: $('f-enabled').checked,
  };
  // 编辑时留空表示「不修改」：绝不能把页面上的脱敏值 ****1234 当成新密钥提交上去
  const key = $('f-key').value;
  if (key) body.api_key = key;
  else if (!state.editing) return showErr($('pform-err'), '新建上游必须填上游密钥');

  const btn = $('pform').querySelector('button[type=submit]');
  btn.disabled = true;
  try {
    await api('/v1/_me/providers/' + encodeURIComponent(name), {
      method: 'PUT',
      body: JSON.stringify(body),
    });
    closeForm();
    await Promise.all([loadProviders(), loadModelOverview(), refreshMe()]);
  } catch (e) {
    showErr($('pform-err'), e.message);
  } finally {
    btn.disabled = false;
  }
}

async function delProvider(p) {
  if (!confirm('删除上游 ' + p.name + '？之后使用它承接的模型会失败。')) return;
  try {
    await api('/v1/_me/providers/' + encodeURIComponent(p.name), { method: 'DELETE' });
    await Promise.all([loadProviders(), loadModelOverview(), refreshMe()]);
  } catch (e) {
    alert(e.message);
  }
}

async function refreshMe() {
  const { data } = await api('/v1/_me');
  state.me = data;
  renderApp();
}

/* ── 模型编辑器：同步 + 勾选 + 别名 ───────────────────────────────────
   参照的理念：不让人手写映射 JSON，而是从上游把模型列表同步下来勾选。
   三条必须守住的：
     1. 已选但不在候选列表里的目标要**保留**（上游没同步、或名字是自定义的），
        否则「编辑一次就丢映射」；
     2. 别名（下游名）在已选表里直接改，改完即时反映到 chip 上；
     3. 同步失败不能把已选清空 —— 候选到底只是「候选」。 */

function mmReset(models, providerName) {
  // 候选列表按上游名缓存在本次会话里：编辑已有上游时勾选框能立刻回来，
  // 不用每打开一次表单就去打一次上游；要刷新点「同步」。
  let cached = null;
  try {
    const raw = sessionStorage.getItem('llmproxy.cands.' + (providerName || ''));
    if (raw) cached = JSON.parse(raw);
  } catch { cached = null; }

  const mm = (state.mm = {
    passthrough: !!(models && models.passthrough),
    catchAll: !!(models && models.catch_all),
    selected: [],
    candidates: cached || [],
    synced: !!cached,
    filter: '',
  });
  const map = (models && models.map) || {};
  for (const [down, up] of Object.entries(map)) {
    if (down === '*') { mm.catchAll = true; continue; }   // "*" 是 catch-all 的存储形态
    mm.selected.push({ up, down });
  }
  $('m-all').checked = mm.passthrough;
  $('m-pick').checked = !mm.passthrough;
  $('m-catchall').checked = mm.catchAll;
  $('m-filter').value = '';
  $('m-manual').value = '';
  mmRender();
}

// 当前是用「全部直通」还是「指定模型」
function mmMode() { return $('m-all').checked ? 'all' : 'pick'; }

function mmHas(up) { return state.mm.selected.some((x) => x.up === up); }

function mmRender() {
  const mm = state.mm;
  const pick = mmMode() === 'pick';
  $('mpick').hidden = !pick;
  if (!pick) return;

  // 候选勾选列表
  const q = mm.filter.trim().toLowerCase();
  const cands = mm.candidates.filter((m) => !q || m.toLowerCase().includes(q));
  const box = $('m-cands');
  box.replaceChildren(...cands.map((m) => {
    const cb = h('input', { type: 'checkbox' });
    cb.checked = mmHas(m);
    cb.addEventListener('change', () => {
      if (cb.checked) {
        if (!mmHas(m)) mm.selected.push({ up: m, down: m });
      } else {
        mm.selected = mm.selected.filter((x) => x.up !== m);
      }
      mmRender();
    });
    return h('label', { class: 'cand' }, cb, h('span', { class: 'mono', text: m }));
  }));
  box.hidden = cands.length === 0;
  $('m-cands-empty').hidden = mm.candidates.length > 0;

  // 同步状态
  $('m-sync-state').textContent = mm.synced
    ? '已同步 ' + mm.candidates.length + ' 个模型'
    : '还没同步（候选为空不影响已选）';

  // 已选表：别名在这里改
  const tb = $('m-picked').querySelector('tbody');
  tb.replaceChildren();
  const inCands = (up) => mm.candidates.includes(up);
  for (const item of mm.selected) {
    const alias = h('input', { type: 'text', class: 'mono alias', value: item.down, spellcheck: 'false' });
    alias.addEventListener('input', () => {
      item.down = alias.value.trim() || item.up;
    });
    const tag = mm.synced && !inCands(item.up)
      ? h('span', { class: 'tag', title: '不在同步到的候选列表里（自定义名或那家还没同步），不会被丢掉' , text: '手动' })
      : null;
    tb.append(h('tr', null,
      h('td', null, h('code', { class: 'k', text: item.up }), tag),
      h('td', null, alias),
      h('td', null, h('button', {
        type: 'button', class: 'link danger', text: '移除',
        onclick: () => { mm.selected = mm.selected.filter((x) => x !== item); mmRender(); },
      })),
    ));
  }
  $('m-picked-wrap').hidden = mm.selected.length === 0;
  $('m-picked-head').hidden = mm.selected.length === 0;
  $('m-picked-count').textContent = String(mm.selected.length);
}

// 产出 models 声明；校验不过返回 null 并提示在表单上
function mmCollect() {
  if (mmMode() === 'all') return ['*'];
  const mm = state.mm;
  const map = {};
  for (const it of mm.selected) {
    const down = (it.down || it.up).trim();
    if (!down) continue;
    map[down] = it.up;
  }
  if (mm.catchAll) map['*'] = '*';
  if (Object.keys(map).length === 0) {
    showErr($('pform-err'), '至少选一个模型，或者把模式改成「全部直通」');
    return null;
  }
  return map;
}

async function mmSync() {
  const name = $('f-name').value.trim();
  if (!name) return showErr($('pform-err'), '先填上游名，再同步模型列表');
  const base = $('f-base').value.trim();
  if (!base) return showErr($('pform-err'), '先填上游地址，再同步模型列表');

  const btn = $('m-sync');
  btn.disabled = true;
  const prev = $('m-sync-state').textContent;
  $('m-sync-state').textContent = '同步中…';
  try {
    // 已保存过的上游可以不重复传密钥；刚填还没保存的要带上
    const body = { base_url: base };
    const key = $('f-key').value;
    if (key) body.api_key = key;
    const { data } = await api('/v1/_me/providers/' + encodeURIComponent(name) + '/discover', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    // 已经在用「全部直通」的话，同步完就切到指定模式：用户点同步显然是想挑模型
    $('m-pick').checked = true;
    state.mm.candidates = data.models || [];
    state.mm.synced = true;
    try {
      sessionStorage.setItem('llmproxy.cands.' + name, JSON.stringify(state.mm.candidates));
    } catch { /* 存不下就算了，只影响下次打开的勾选回显 */ }
    showErr($('pform-err'), '');
    mmRender();
  } catch (e) {
    // 同步失败只提示，绝不动已选 —— 候选失败不该影响用户已有的配置
    $('m-sync-state').textContent = prev;
    showErr($('pform-err'), '同步失败：' + e.message);
  } finally {
    btn.disabled = false;
  }
}

function mmAddManual() {
  const input = $('m-manual');
  const v = input.value.trim();
  if (!v) return;
  if (!mmHas(v)) state.mm.selected.push({ up: v, down: v });
  input.value = '';
  $('m-pick').checked = true;
  mmRender();
}

/* ── 我的模型：按下游模型名，看它挂在哪些上游上 ─────────────────────── */
//
// 这一节同时是**模型目录**的入口：客户端要填的下游名写在这里，一家或多家上游
// 各自认一个上游模型名。同名多家 = 粘性优先 + 失败自动切换（见路由）。

// 从各上游的 models 声明收出「下游名 → [{provider, up, passthrough?}]」。
function collectModelMap(list) {
  const byModel = new Map();
  const passthrough = [];
  for (const p of list) {
    const m = p.models || {};
    if (m.passthrough) { passthrough.push(p.name); continue; }
    for (const [down, up] of Object.entries(m.map || {})) {
      if (down === '*') continue;
      if (!byModel.has(down)) byModel.set(down, []);
      byModel.get(down).push({ provider: p.name, up });
    }
  }
  return { byModel, passthrough };
}

async function loadModelOverview() {
  const { data } = await api('/v1/_me/providers');
  const list = (data && data.providers) || [];
  state.providers = list;
  const { byModel, passthrough } = collectModelMap(list);

  const rows = [];
  for (const [down, ups] of [...byModel.entries()].sort()) {
    rows.push(h('tr', null,
      h('td', null, h('code', { class: 'k', text: down })),
      h('td', null, ...ups.map((u) => h('span', {
        class: 'chip',
        title: u.provider + ' → ' + u.up,
        text: u.provider + ' → ' + u.up,
      }))),
      // 多路就是「同一模型挂多个上游」：粘性 + 失败自动切换
      h('td', null,
        ups.length > 1 ? h('span', { class: 'tag ok', text: '粘性 + 失败切换' }) : h('span', { class: 'muted', text: '单路' }),
        ' ',
        h('button', {
          type: 'button', class: 'link', text: '编辑',
          onclick: () => openModelForm(down),
        }),
        ' ',
        h('button', {
          type: 'button', class: 'link danger', text: '移除',
          onclick: () => removeModel(down),
        })),
    ));
  }

  // 显示与否交给 renderMode（消费模式整卡藏起）；这里只填内容
  const tb = $('my-models').querySelector('tbody');
  tb.replaceChildren(...rows);
  const note = $('my-models-pass');
  if (passthrough.length) {
    note.textContent = '这些上游目前是「全部直通」（接受任意模型名，不进上表）：' +
      passthrough.join('、') + '。要让它参与同名切换，在「映射模型」里给它选一个具体模型名。';
    note.hidden = false;
  } else {
    note.hidden = true;
  }
  $('my-models-empty').hidden = rows.length > 0;
}

// 打开模型映射表单：down 为空 = 新建。
function openModelForm(down) {
  const list = state.providers || [];
  if (!list.length) {
    showErr($('mm-err'), '还没有上游。先在上面「我的上游」里加一个。');
    $('mmform').hidden = false;
    return;
  }
  $('mmform').hidden = false;
  $('mm-err').hidden = true;
  $('mm-name').value = down || '';
  $('mm-name').disabled = !!down;

  const tb = $('mm-rows').querySelector('tbody');
  tb.replaceChildren();
  list.forEach((p, i) => {
    const m = p.models || {};
    const current = down && !m.passthrough ? ((m.map || {})[down] || '') : '';
    // 候选：session 同步过的 + 当前值 + 这家已有的上游名
    const cands = new Set();
    try {
      const raw = sessionStorage.getItem('llmproxy.cands.' + p.name);
      if (raw) for (const c of JSON.parse(raw)) cands.add(c);
    } catch { /* 没有就算了 */ }
    if (current) cands.add(current);
    if (!m.passthrough) {
      for (const up of Object.values(m.map || {})) if (up !== '*') cands.add(up);
    } else if (down) {
      // 直通上游在映射一个具体名字时，最省事的是同名
      cands.add(down);
    }

    const dl = h('datalist', { id: 'mm-cands-' + i });
    for (const c of [...cands].sort()) dl.append(h('option', { value: c }));
    const inp = h('input', {
      type: 'text', class: 'mono mm-up', list: 'mm-cands-' + i,
      placeholder: m.passthrough ? '留空 = 保持直通' : '留空 = 不使用这家',
      autocomplete: 'off', spellcheck: 'false', value: current,
    });

    const tag = m.passthrough
      ? h('span', { class: 'tag', text: '直通', title: '现在接受任意模型名' })
      : null;
    tb.append(h('tr', null,
      h('td', null, h('code', { class: 'k', text: p.name }), tag ? ' ' : '', tag),
      h('td', null, inp, dl),
    ));
  });
  $('mm-name').focus();
  $('mm-name').scrollIntoView({ block: 'center', behavior: 'smooth' });
}

function closeModelForm() {
  $('mmform').hidden = true;
  $('mm-err').hidden = true;
}

// 读表单：返回 [{provider, up}]，up 为空串表示这家不承接。
function collectModelForm() {
  const tb = $('mm-rows').querySelector('tbody');
  const out = [];
  for (const tr of tb.rows) {
    const provider = tr.cells[0].querySelector('code')?.textContent?.trim();
    const inp = tr.cells[1].querySelector('input.mm-up');
    if (!provider) continue;
    out.push({ provider, up: (inp && inp.value.trim()) || '' });
  }
  return out;
}

// 把「下游名 → 各上游的上游名」写回每家上游的 models 声明。
// 只动这一个下游键，别家的映射、catch_all、其它字段一律原样。
async function saveModelMap(ev) {
  ev.preventDefault();
  const down = $('mm-name').value.trim();
  if (!down) return showErr($('mm-err'), '下游模型名必填');
  const assigns = collectModelForm();
  const touched = assigns.filter((a) => a.up);
  if (!touched.length) return showErr($('mm-err'), '至少给一家上游选一个模型名');

  const btn = $('mmform').querySelector('button[type=submit]');
  btn.disabled = true;
  showErr($('mm-err'), '');
  try {
    for (const a of assigns) {
      const p = (state.providers || []).find((x) => x.name === a.provider);
      if (!p) continue;
      const m = p.models || {};
      const oldMap = m.passthrough ? {} : { ...(m.map || {}) };
      const newMap = { ...oldMap };
      if (a.up) newMap[down] = a.up;
      else delete newMap[down];

      // 没动就不 PUT：省得无谓写库，也避免顺手改掉别的字段
      const had = oldMap[down] || '';
      const now = a.up || '';
      if (had === now && !(m.passthrough && a.up)) continue;

      // 完全没映射了：回退成直通，否则服务端会拒「models 为空」
      let models;
      if (!a.up && Object.keys(newMap).length === 0 && !m.catch_all) {
        models = ['*'];
      } else if (a.up && m.passthrough) {
        // 从直通改成指定模型：保留 catch_all 会让人以为「还接任意名」，这里明确收窄
        models = newMap;
      } else {
        if (m.catch_all) newMap['*'] = '*';
        models = newMap;
      }

      await api('/v1/_me/providers/' + encodeURIComponent(a.provider), {
        method: 'PUT',
        body: JSON.stringify({ models }),
      });
    }
    closeModelForm();
    await Promise.all([loadProviders(), loadModelOverview(), refreshMe()]);
  } catch (e) {
    showErr($('mm-err'), e.message);
  } finally {
    btn.disabled = false;
  }
}

// 从所有上游上摘掉这个下游名。
async function removeModel(down) {
  if (!confirm('从所有上游上移除模型 ' + down + '？之后用它发请求会失败。')) return;
  try {
    for (const p of state.providers || []) {
      const m = p.models || {};
      if (m.passthrough) continue;
      const map = { ...(m.map || {}) };
      if (!(down in map)) continue;
      delete map[down];
      let models;
      if (Object.keys(map).length === 0 && !m.catch_all) models = ['*'];
      else {
        if (m.catch_all) map['*'] = '*';
        models = map;
      }
      await api('/v1/_me/providers/' + encodeURIComponent(p.name), {
        method: 'PUT', body: JSON.stringify({ models }),
      });
    }
    await Promise.all([loadProviders(), loadModelOverview(), refreshMe()]);
  } catch (e) {
    alert('移除失败：' + e.message);
  }
}

/* ── 用量 ─────────────────────────────────────────────────────────── */

async function loadUsage() {
  const { data } = await api('/v1/_me/usage?days=' + state.days);
  const rows = (data && data.rows) || [];
  const t = (data && data.totals) || {};

  const c = (data && data.cost) || {};
  $('utotals').replaceChildren(
    stat('请求', num(t.requests)),
    stat('成功 / 失败', num(t.ok) + ' / ' + num(t.failed)),
    stat('输入 / 输出 tok', num(t.prompt_tokens) + ' / ' + num(t.completion_tokens)),
    c.priced
      ? stat('本月系统消费', money(c.month_system, c.currency || 'CNY'), 'sm')
      : stat('token 合计', num(t.total_tokens)),
  );

  const tb = $('utable').querySelector('tbody');
  tb.replaceChildren();
  $('uempty').hidden = rows.length > 0;

  for (const r of rows) {
    tb.append(h('tr', null,
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
      h('td', { class: 'num', text: ms(r.avg_latency_ms) }),
      // 只有系统付费的行才有金额；用自己的上游时是你和供应商之间的事，这里显示 —
      h('td', { class: 'num', text: r.cost != null ? r.cost.toFixed(4) : '—' }),
    ));
  }
}

/* ── 试一下 ───────────────────────────────────────────────────────── */

async function trySend() {
  const out = $('t-out');
  const btn = $('t-send');
  out.hidden = false;
  out.textContent = '请求中…';
  $('t-meta').textContent = '';
  btn.disabled = true;
  const t0 = performance.now();
  try {
    const { data, res } = await api('/v1/chat/completions', {
      method: 'POST',
      headers: { Accept: 'application/json' },
      body: JSON.stringify({
        model: $('t-model').value.trim() || 'deepseek-chat',
        messages: [{ role: 'user', content: $('t-prompt').value }],
      }),
    });
    const elapsed = Math.round(performance.now() - t0);
    const content = data && data.choices && data.choices[0] &&
      data.choices[0].message && data.choices[0].message.content;

    $('t-meta').textContent =
      '上游 ' + (res.headers.get('X-LLMProxy-Provider') || '?') +
      ' · ' + elapsed + 'ms' +
      (res.headers.get('X-LLMProxy-Request-Id') ? ' · id ' + res.headers.get('X-LLMProxy-Request-Id') : '');
    out.textContent = content != null ? content : JSON.stringify(data, null, 2);
    await Promise.all([loadUsage(), refreshMe()]);
  } catch (e) {
    out.textContent = '失败：' + e.message;
  } finally {
    btn.disabled = false;
  }
}

/* ── 事件绑定 ─────────────────────────────────────────────────────── */

$('login-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const btn = $('login-btn');
  btn.disabled = true;
  showErr($('login-err'), '');
  login($('login-base').value.trim() || defaultBase(), $('login-token').value.trim())
    .finally(() => { btn.disabled = false; });
});

$('logout').addEventListener('click', logout);
$('add-open').addEventListener('click', () => openForm(null));
$('add-cancel').addEventListener('click', closeForm);
$('pform').addEventListener('submit', saveProvider);
$('mm-open').addEventListener('click', () => openModelForm(''));
$('mm-cancel').addEventListener('click', closeModelForm);
$('mmform').addEventListener('submit', saveModelMap);
$('t-send').addEventListener('click', trySend);
$('m-sync').addEventListener('click', mmSync);
$('m-manual-add').addEventListener('click', mmAddManual);
$('m-manual').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); mmAddManual(); } });
$('m-filter').addEventListener('input', () => { state.mm.filter = $('m-filter').value; mmRender(); });
$('m-catchall').addEventListener('change', () => { state.mm.catchAll = $('m-catchall').checked; });
for (const id of ['m-all', 'm-pick']) {
  $(id).addEventListener('change', () => { state.mm.passthrough = $('m-all').checked; mmRender(); });
}
$('t-prompt').addEventListener('keydown', (e) => { if (e.key === 'Enter') trySend(); });

$('days').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-days]');
  if (!b) return;
  state.days = Number(b.dataset.days);
  for (const x of $('days').querySelectorAll('button')) x.classList.toggle('on', x === b);
  loadUsage().catch((err) => alert(err.message));
});


/* 启动：用户台只认用户 token */
(function boot() {
  state.storageKey = 'llmproxy.user';
  const s = sessionLoad();
  if (s.token) {
    login(s.base, s.token).catch((e) => renderLogin('启动失败：' + e.message));
  } else {
    renderLogin('');
  }
})();
