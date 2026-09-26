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
  const [{ data: provData }, { data: plan }] = await Promise.all([
    api('/v1/_me/providers'),
    api('/v1/_me/routing'),
  ]);
  const list = (provData && provData.providers) || [];
  state.providers = list;
  const { passthrough } = collectModelMap(list);

  // 消费顺序直接用服务端算好的计划（router.PlanFor，与真实选路同一份档序定义）——
  // 界面不自己推导，免得「看到的顺序」和「实际会走的顺序」两份代码各走各的。
  const models = (plan && plan.models) || [];
  const rows = [];
  for (const m of models) {
    const tiers = m.tiers || [];
    const seq = [];
    tiers.forEach((t, i) => {
      if (i > 0) seq.push(h('span', { class: 'seq-arrow', text: '→' }));
      for (const it of t.items) {
        seq.push(h('span', {
          class: 'chip' + (it.healthy ? '' : ' cooling'),
          title: t.label + ' · 上游模型 ' + it.upstream_model +
            ' · 权重 ' + it.weight + (it.healthy ? '' : ' · 冷却中'),
          text: (it.source === 'own' ? '' : '系统·') + it.provider +
            (it.upstream_model && it.upstream_model !== m.model ? ' → ' + it.upstream_model : ''),
        }));
      }
    });
    if (!seq.length) seq.push(h('span', { class: 'muted', text: '没有上游承接' }));

    // 多档 = 会按顺序回落；只有一档多成员 = 档内按权重分担
    let note = h('span', { class: 'muted', text: '单路' });
    if (tiers.length > 1) {
      note = h('span', { class: 'tag ok', text: tiers.length + ' 档 · 依次回落' });
    } else if (tiers.length === 1 && tiers[0].items.length > 1) {
      note = h('span', { class: 'tag ok', text: '同档 ' + tiers[0].items.length + ' 家 · 粘性分担' });
    }

    rows.push(h('tr', null,
      h('td', null, h('code', { class: 'k', text: m.model })),
      h('td', null, h('div', { class: 'seq' }, ...seq)),
      h('td', null, note, ' ',
        h('button', { type: 'button', class: 'link', text: '编辑', onclick: () => openModelForm(m.model) }),
        ' ',
        h('button', { type: 'button', class: 'link danger', text: '移除', onclick: () => removeModel(m.model) })),
    ));
  }

  const tb = $('my-models').querySelector('tbody');
  tb.replaceChildren(...rows);
  const note = $('my-models-pass');
  if (passthrough.length) {
    note.textContent = '这些上游目前是「全部直通」（接受任意模型名，不在上表逐个列出）：' +
      passthrough.join('、') + '。要让它参与同名切换，在「映射模型」里给它选一个具体模型名。';
    note.hidden = false;
  } else {
    note.hidden = true;
  }
  $('my-models-empty').hidden = rows.length > 0;
}

// 映射目标的四种模式 —— 界面四选一，语义刻意拆开，不再用「留空」一词两义。
const MM_NONE = '';          // 不映射（默认）：这家不接这个下游名
const MM_SAME = '__same__';  // 直通：原名转发（下游名 = 上游名）
const MM_CUSTOM = '__custom__'; // 自定义：手填这家认的模型名
// 其余 value = 列表里选中的具体上游模型名

// 拉一家上游认得的模型名。优先用本会话缓存（编辑上游时「同步」写进去的那份），
// 没有就现问 /discover —— 映射表单不能只靠缓存，否则从没同步过的家一条候选都没有。
async function loadProviderCands(p) {
  const key = 'llmproxy.cands.' + p.name;
  try {
    const raw = sessionStorage.getItem(key);
    if (raw) return JSON.parse(raw);
  } catch { /* 缓存坏了就当没有 */ }
  try {
    const { data } = await api('/v1/_me/providers/' + encodeURIComponent(p.name) + '/discover', {
      method: 'POST',
      body: JSON.stringify({}),
    });
    const models = data.models || [];
    try { sessionStorage.setItem(key, JSON.stringify(models)); } catch { /* 存不下只影响下次 */ }
    return models;
  } catch {
    return [];
  }
}

// 从控件读出「这家对这个下游名怎么接」。
// 返回 { mode, up }：up 只在 mode=list/custom 时是真正要写库的上游名；
// mode=same 表示同名直通，up 由调用方填下游名。
function readUpRow(tr) {
  const sel = tr.querySelector('select.mm-up-sel');
  const customInp = tr.querySelector('input.mm-up-custom');
  if (!sel) return { mode: MM_NONE, up: '' };
  const v = sel.value;
  if (v === MM_NONE) return { mode: MM_NONE, up: '' };
  if (v === MM_SAME) return { mode: MM_SAME, up: '' };
  if (v === MM_CUSTOM) return { mode: MM_CUSTOM, up: (customInp && customInp.value.trim()) || '' };
  return { mode: 'list', up: v };
}

function syncUpRow(sel, customInp) {
  const isCustom = sel.value === MM_CUSTOM;
  customInp.hidden = !isCustom;
  if (isCustom) customInp.focus();
  else customInp.value = '';
}

// 把候选刷进「列表」分组，保持当前选中。
// current: { mode, up }；down 用于「直通」选项的文案。
function fillUpSelect(sel, customInp, cands, current, down) {
  const dn = down || '（下游名）';
  const mode = current.mode || MM_NONE;
  const up = current.up || '';

  const set = new Set();
  for (const c of cands) {
    if (!c || c === MM_SAME || c === MM_CUSTOM || c === MM_NONE) continue;
    set.add(c);
  }
  // 同名走「直通」那一项，不往列表里塞下游名 —— 否则打字过程的中间值会被
  // 一帧帧累进候选（x / xi / xia / …），列表被前缀碎片刷爆。
  if (mode === 'list' && up) set.add(up);

  sel.replaceChildren();
  sel.append(h('option', { value: MM_NONE, text: '不映射 —— 这家不接' }));
  sel.append(h('option', { value: MM_SAME, text: '直通 —— 原名 ' + dn + ' 转发' }));

  const listGroup = h('optgroup', { label: '列表 —— 这家认的模型名' });
  for (const c of [...set].sort()) {
    listGroup.append(h('option', { value: c, text: c }));
  }
  if ([...set].length) sel.append(listGroup);

  sel.append(h('option', { value: MM_CUSTOM, text: '自定义 —— 手填模型名' }));

  if (mode === MM_SAME) {
    sel.value = MM_SAME;
  } else if (mode === MM_CUSTOM || (mode === 'list' && up && !set.has(up))) {
    // 列表里没有的当前值落到自定义，绝不丢映射
    sel.value = MM_CUSTOM;
    customInp.value = up;
  } else if (mode === 'list' && up) {
    sel.value = up;
  } else {
    sel.value = MM_NONE;
  }
  syncUpRow(sel, customInp);
}

// 打开模型映射表单：down 为空 = 新建。
// mmFormGen 用来丢弃过期的异步候选回填（表单已关/已换目标时不要写进来）。
let mmFormGen = 0;

function openModelForm(down) {
  const list = state.providers || [];
  if (!list.length) {
    showErr($('mm-err'), '还没有上游。先在上面「我的上游」里加一个。');
    $('mmform').hidden = false;
    return;
  }
  const gen = ++mmFormGen;
  $('mmform').hidden = false;
  $('mm-err').hidden = true;
  $('mm-name').value = down || '';
  $('mm-name').disabled = !!down;

  const tb = $('mm-rows').querySelector('tbody');
  tb.replaceChildren();
  list.forEach((p) => {
    const m = p.models || {};
    // 当前值：有点名映射就是 list/custom/same；没有就是「不映射」
    // （直通型上游对任意名字都接，但那是「万能匹配」，不是对这个下游名的点名映射）
    let current = { mode: MM_NONE, up: '' };
    if (down && !m.passthrough) {
      const up = (m.map || {})[down];
      if (up === down) current = { mode: MM_SAME, up: '' };
      else if (up) current = { mode: 'list', up };
    }

    // baseCands：这家真正认得的模型名（缓存 + 已有映射里的上游名）。
    // 不从 select.options 反读 —— 那里混着「直通/自定义」哨兵和下游名文案，会污染候选。
    const baseCands = new Set();
    try {
      const raw = sessionStorage.getItem('llmproxy.cands.' + p.name);
      if (raw) for (const c of JSON.parse(raw)) baseCands.add(c);
    } catch { /* 没有就算了 */ }
    if (!m.passthrough) {
      for (const up of Object.values(m.map || {})) if (up && up !== '*') baseCands.add(up);
    }

    const sel = h('select', { class: 'mm-up-sel' });
    const customInp = h('input', {
      type: 'text', class: 'mono mm-up-custom', placeholder: '输入这家认得的模型名',
      autocomplete: 'off', spellcheck: 'false', hidden: true,
    });
    sel.addEventListener('change', () => syncUpRow(sel, customInp));
    fillUpSelect(sel, customInp, [...baseCands], current, down);

    // 万能匹配标记：这家当前是「任意模型名都接」，只在没有点名映射时兜底
    const tag = m.passthrough
      ? h('span', { class: 'tag', text: '万能匹配', title: '这家当前接受任意模型名；只有没被点名映射的模型才会走到它' })
      : null;
    const st = h('span', { class: 'mm-cand-st muted', text: '' });
    tb.append(h('tr', { 'data-provider': p.name },
      h('td', null, h('code', { class: 'k', text: p.name }), tag ? ' ' : '', tag),
      h('td', null,
        h('div', { class: 'mm-pick' }, sel, customInp),
        st),
    ));

    loadProviderCands(p).then((models) => {
      if (gen !== mmFormGen) return;
      for (const c of models) baseCands.add(c);
      const cur = readUpRow(trOf(tb, p.name));
      fillUpSelect(sel, customInp, [...baseCands], cur, $('mm-name').value.trim() || down);
      st.textContent = models.length ? '' : '这家没拉到模型列表，可用「自定义」手填';
    });
  });

  // 下游名后填：只改「直通 —— 原名 xxx」那条文案。
  // 不把中间态塞进列表、也不从 options 反读候选 —— 否则每个按键都会
  // 多留一条 x/xi/xia/… 的前缀碎片。
  const onDownInput = () => {
    const dn = $('mm-name').value.trim();
    const label = '直通 —— 原名 ' + (dn || '（下游名）') + ' 转发';
    for (const tr of tb.rows) {
      const sel = tr.querySelector('select.mm-up-sel');
      if (!sel) continue;
      for (const o of sel.options) {
        if (o.value === MM_SAME) o.textContent = label;
      }
    }
  };
  if (state.mmDownInput) $('mm-name').removeEventListener('input', state.mmDownInput);
  state.mmDownInput = onDownInput;
  $('mm-name').addEventListener('input', onDownInput);
  if (down) onDownInput();

  $('mm-name').focus();
  $('mm-name').scrollIntoView({ block: 'center', behavior: 'smooth' });
}

function trOf(tb, name) {
  for (const tr of tb.rows) {
    if (tr.dataset.provider === name) return tr;
  }
  return null;
}

function closeModelForm() {
  mmFormGen++;
  if (state.mmDownInput) {
    $('mm-name').removeEventListener('input', state.mmDownInput);
    state.mmDownInput = null;
  }
  $('mmform').hidden = true;
  $('mm-err').hidden = true;
}

// 读表单：返回 [{provider, up, mode}]，up 为空串表示这家不承接。
function collectModelForm() {
  const tb = $('mm-rows').querySelector('tbody');
  const out = [];
  for (const tr of tb.rows) {
    const provider = tr.dataset.provider || tr.cells[0].querySelector('code')?.textContent?.trim();
    if (!provider) continue;
    out.push({ provider, ...readUpRow(tr) });
  }
  return out;
}

// 把「下游名 → 各上游的上游名」写回每家上游的 models 声明。
// 只动这一个下游键，别家的映射、catch_all、其它字段一律原样。
//
// 保存语义对齐心智模型：
//   不映射        → 从这家的映射表里删掉该下游名（这家不点名接它）
//   直通          → map[down] = down（点名同名，不是万能匹配）
//   列表 / 自定义 → map[down] = 选定的上游名
// 万能匹配（passthrough / catch_all）是另一层：没被点名映射的模型才靠它兜底。
// 给万能匹配的家加点名映射时，**保留**它的 catch_all —— 其它模型仍可走万能匹配。
async function saveModelMap(ev) {
  ev.preventDefault();
  const down = $('mm-name').value.trim();
  if (!down) return showErr($('mm-err'), '下游模型名必填');
  // 「直通」= 同名点名映射
  const assigns = collectModelForm().map((a) => ({
    ...a,
    up: a.mode === MM_SAME ? down : (a.up || ''),
  }));
  const touched = assigns.filter((a) => a.up);
  if (!touched.length) return showErr($('mm-err'), '至少给一家选「直通 / 列表 / 自定义」');

  const btn = $('mmform').querySelector('button[type=submit]');
  btn.disabled = true;
  showErr($('mm-err'), '');
  try {
    for (const a of assigns) {
      const p = (state.providers || []).find((x) => x.name === a.provider);
      if (!p) continue;
      const m = p.models || {};
      // 纯万能匹配（passthrough）时映射表是空的；catch_all 存在 map['*']
      const oldMap = m.passthrough ? {} : { ...(m.map || {}) };
      const newMap = { ...oldMap };
      if (a.up) newMap[down] = a.up;
      else delete newMap[down];

      // 没动就不 PUT：省得无谓写库，也避免顺手改掉别的字段
      const had = oldMap[down] || '';
      const now = a.up || '';
      if (had === now && !(m.passthrough && a.up)) continue;

      let models;
      if (!a.up && Object.keys(newMap).length === 0 && !m.catch_all) {
        // 点名映射全删光了：退回纯万能匹配，否则服务端会拒「models 为空」
        models = ['*'];
      } else if (m.passthrough && a.up) {
        // 原来是纯万能匹配，现在给这个下游名加了点名映射。
        // 万能匹配要**留住**：其它没点名的模型仍靠它兜底（有映射走映射，没映射走万能匹配）。
        newMap['*'] = '*';
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
  // 输入缓存命中率：命中 /（命中+未命中）。两边都为 0 表示**上游没回报**（有的聚合商
  // 只给 cached_tokens 甚至什么都不给），那是「不知道」而不是「0%」—— 两者必须分清，
  // 否则会让人以为缓存完全没生效，去查一个不存在的问题。
  const hit = t.cache_hit_tokens || 0;
  const miss = t.cache_miss_tokens || 0;
  const rate = hit + miss > 0 ? ((hit * 100) / (hit + miss)).toFixed(1) + '%' : '—';
  const rateTitle = hit + miss > 0
    ? '输入命中 ' + num(hit) + ' / 输入合计 ' + num(hit + miss) + ' token'
    : '上游没回报缓存拆分（不是命中率 0%）';

  $('utotals').replaceChildren(
    stat('请求', num(t.requests)),
    stat('成功 / 失败', num(t.ok) + ' / ' + num(t.failed)),
    stat('输入 / 输出 tok', num(t.prompt_tokens) + ' / ' + num(t.completion_tokens)),
    stat('输入缓存命中率', rate, 'sm', rateTitle),
    c.priced
      ? stat('本月系统消费', money(c.month_system, c.currency || 'CNY'), 'sm',
        '只算走系统上游的那部分；自有上游是你自己和供应商结算')
      : stat('token 合计', num(t.total_tokens)),
  );

  const tb = $('utable').querySelector('tbody');
  tb.replaceChildren();
  $('uempty').hidden = rows.length > 0;

  for (const r of rows) {
    // 每行的命中率 = 命中 /（命中+未命中）。都 0 就是上游没回报，显示 — 而不是 0%。
    const hit = r.cache_hit_tokens || 0;
    const miss = r.cache_miss_tokens || 0;
    const rate = hit + miss > 0 ? ((hit * 100) / (hit + miss)).toFixed(1) + '%' : '—';
    tb.append(h('tr', null,
      h('td', null, h('code', { class: 'k', text: r.day })),
      h('td', null, h('code', { class: 'k', text: r.provider })),
      h('td', null, h('code', { class: 'k', text: r.model })),
      h('td', { class: 'num', text: num(r.requests) }),
      h('td', { class: 'num', text: num(r.ok) }),
      h('td', { class: 'num', text: num(r.failed) }),
      h('td', { class: 'num', text: num(r.prompt_tokens) }),
      h('td', { class: 'num', text: num(r.cache_hit_tokens) }),
      h('td', { class: 'num' + (rate === '—' ? ' dim' : ''), text: rate }),
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
