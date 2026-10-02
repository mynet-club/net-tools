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
  await Promise.all([loadSysProviders(), loadAdminUsers(), loadPolicy()]);
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
  // 池子一变，「策略下有没有可用候选」就跟着变（分级门逐家收窄用的是同一批声明）。
  // 读不到不该挡住保存结果本身，所以这里吞掉错误——那一屏自己会显示为什么读不到。
  await loadPolicy().catch(() => {});
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
// 新加的、还没保存的供应商也能用 —— 后端探测/测试接口允许内联 base_url / api_key。
const PICK = { idx: -1, models: [], checked: new Set() };

// 探测与测试都用「当前编辑区」的地址与密钥；密钥留空交给服务端沿用已保存的那把
function provCreds(p) {
  return { base_url: p.base_url.trim(), api_key: p.api_key, proxy: p.proxy.trim() };
}

async function fetchModelsForRow(i) {
  const p = ADM.cfg.providers[i];
  const { data } = await adminApi('/v1/_admin/providers/' + encodeURIComponent(p.name.trim() || '-') + '/discover', {
    method: 'POST', body: JSON.stringify(provCreds(p)),
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
    // ensureSaved() 会重建 ADM.cfg.providers，所以索引之后才取，免得拿到旧的
    const p = ADM.cfg.providers[i];
    const models = await fetchModelsForRow(i);
    PICK.idx = i;
    PICK.models = models;
    PICK.checked = new Set(p.map.map((pair) => pair[0]).filter(Boolean));
    $('pick-title').textContent = '选择模型 — ' + (p.name || '（未命名）');
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
    const row = h('div', { class: 'cand' }, cb, h('span', { class: 'mono', text: m }));
    // 勾选只有这一个来源：复选框自己的 change 事件。
    // 不要在 click 里 preventDefault 再手动翻转 —— 勾选是复选框的默认动作，
    // 拦掉之后浏览器还会执行「取消激活步骤」把它翻回去，结果是「记下来了但没勾上」。
    cb.addEventListener('change', () => {
      if (cb.checked) PICK.checked.add(m); else PICK.checked.delete(m);
      paintCand(row, cb.checked);
      updPickCount();
    });
    // 整行可点：点复选框以外的地方就等价于点复选框
    row.addEventListener('click', (e) => { if (e.target !== cb) cb.click(); });
    paintCand(row, cb.checked);
    return row;
  }));
  box.hidden = list.length === 0;
  $('pick-empty').hidden = PICK.models.length > 0;
  $('pick-no-hit').hidden = !(PICK.models.length > 0 && list.length === 0);
  updPickCount();
}

// 选中效果不能只靠那个小方框：整行加底色，扫一眼就知道选了哪些
function paintCand(row, on) { row.classList.toggle('on', on); }

function updPickCount() {
  $('pick-count').textContent = '已选 ' + PICK.checked.size + ' / ' + PICK.models.length;
}

function closePick() {
  $('pick-modal').hidden = true;
  PICK.idx = -1;
  PICK.name = '';
  PICK.creds = {};
}

// 弹窗里那份勾选就是「这家上游的映射表」，所以取消勾选要真的移除 ——
// 只加不减的话，复选框说「没选」而映射表里还在，两边对不上。
// 唯一的例外：不在候选列表里的既有映射原样保留（下游名是自定义的，或上游这次没返回它），
// 候选只是候选，不能因为「这次没列出来」就删掉用户已经配好的东西。
function applyPick() {
  const i = PICK.idx;
  if (i < 0) return closePick();
  const p = ADM.cfg.providers[i];
  const cand = new Set(PICK.models);
  const before = p.map.map((pair) => pair[0]);
  const beforeSet = new Set(before);

  const next = p.map.filter((pair) => !cand.has(pair[0]));
  const keptDown = new Set(next.map((pair) => pair[0]));
  for (const m of PICK.checked) {
    if (!keptDown.has(m)) next.push([m, m]);   // 下游名默认与上游模型同名
  }
  p.map = next;

  const added = [...PICK.checked].filter((m) => !beforeSet.has(m));
  const removed = before.filter((m) => cand.has(m) && !PICK.checked.has(m));
  const keptAside = next.filter((pair) => !cand.has(pair[0])).map((pair) => pair[0]);

  // 有映射却还停在「全部直通」上就说不通了，直接切成指定映射
  if (p.map.length > 0) p.passthrough = false;
  touchCfg();
  closePick();
  $('cfg-list').replaceChildren(...ADM.cfg.providers.map(cfgRow));

  const parts = [];
  if (added.length) parts.push('已加入 ' + added.length + ' 个模型');
  if (removed.length) parts.push('已移除 ' + removed.length + ' 个');
  if (!parts.length) parts.push('映射没有变化');
  let msg = parts.join('，');
  if (keptAside.length) {
    msg += '。另有 ' + keptAside.length + ' 条不在这次的候选列表里，已原样保留：' +
      keptAside.slice(0, 3).join('、') + (keptAside.length > 3 ? ' …' : '');
  }
  msg += p.map.length === 0
    ? '这条供应商现在一条映射都没有 —— 保存后会变成「全部直通」（任何模型名都转发）。'
    : '（下游名默认同名，可在表里改）。别忘了点右上角「保存」。';
  const banner = $('cfg-result');
  banner.hidden = false;
  banner.textContent = msg;
}

// ── 快速测试 ─────────────────────────────────────────────────────────
// 每家供应商**一次**就够：这里的目标是「选模型」，不是「输入模型名」。
// 一次探针证明这家服务正常（连得上、密钥认不认），模型名交给服务端自己挑：
// 有映射就用映射里的上游名，直通型就问上游要一份列表、拿第一个真实名字。
// 结果写在上方横幅里（错误信息可能很长，放行内会把那一行撑变形）。
async function testProviderRow(i) {
  const p = ADM.cfg.providers[i];
  const label = p.name || '（未命名）';
  const banner = $('cfg-result');
  banner.hidden = false;
  banner.className = 'banner';
  banner.textContent = '正在测试 ' + label + ' …';
  try {
    // 有映射就报第一条映射的上游名（哪怕还没保存，免得测试用的是别的模型）；
    // 没有映射（直通）就不给，让服务端自己问上游要一个真实的模型名
    const first = p.map.find((pair) => (pair[1] || pair[0] || '').trim());
    const body = Object.assign({}, provCreds(p));
    if (first) body.model = (first[1] || first[0]).trim();
    // 内联当前编辑区的地址与密钥：刚改完还没保存也能测，而且测试本身不改配置
    const { data } = await adminApi('/v1/_admin/providers/' + encodeURIComponent(p.name.trim() || '-') + '/test', {
      method: 'POST', body: JSON.stringify(body),
    });
    banner.textContent = describeTest(label, data);
    if (!data.ok) banner.className = 'banner err-banner';
  } catch (e) {
    banner.className = 'banner err-banner';
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
// 上游的错误常常是一大坨 JSON —— 比如 404 时它会把「令牌可用的分组」全列出来。
// 那样一坨塞进表格单元格会把整张表撑变形，所以单元格里只放一句短的，
// 完整内容挂到 title 上（鼠标停一下就能看全），信息没丢、表也不会散。
function shortErr(msg) {
  const s = String(msg || '失败').replace(/\s+/g, ' ').trim();
  const m = /^上游返回 HTTP (\d{3})/.exec(s);
  if (m) return '上游返回 HTTP ' + m[1];
  return s.length > 40 ? s.slice(0, 40) + '…' : s;
}

// 按用户测某个模型（用在「模型范围」的模型列表上：继承来的每个模型、以及每条自己的映射）
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
      cell.textContent = '✗ ' + shortErr(data.error);
      cell.title = data.error || '';
    }
  } catch (e) {
    cell.className = 'testres bad';
    cell.textContent = '✗ ' + shortErr(e.message);
    cell.title = e.message || '';
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

/* ── 策略与路由（§3.H：只读可见性）──────────────────────────────
   数据来源只有 /v1/_admin/policy[/simulate|/trace] 三个只读端点。
   界面不参与任何判定：结论由接线层的判定核给出 —— 界面上说「会通过」而线上拒了，
   这种误差会让人彻底放弃策略包。响应里也不会有条件值、上游地址或密钥。 */

const VERDICT = {
  agreed: ['与旧链路一致', 'ok'],
  primary_moved: ['首选会变', ''],
  policy_denied: ['策略会排除上游', ''],
  no_candidate: ['策略下没有可用候选', ''],
  decision_denied: ['策略会拒绝请求', ''],
  policy_would_deny: ['策略会拒绝请求', ''],
  not_evaluated: ['未判定（该范围按旧路由跑）', ''],
};

function showPlStatus(msg, kind) {
  const el = $('pl-status');
  el.textContent = msg || '';
  el.className = 'banner' + (kind === 'err' ? ' err-banner' : '');
  el.hidden = !msg;
}

async function loadPolicy() {
  showPlStatus('');
  let data;
  try {
    ({ data } = await adminApi('/v1/_admin/policy'));
  } catch (e) {
    showPlStatus('读不到策略状态：' + e.message, 'err');
    return;
  }
  ADM.policy = data;
  $('pl-rev').textContent = '配置修订 ' + num(data.revision) + ' · schema v' + num(data.config_schema_version);
  // 「配了但没生效」必须比任何统计都先看见：mode 写着 shadow、策略包却加载失败时，
  // 请求其实按旧路由静默运行，只报 mode 的界面会说谎。
  if (!data.running) {
    const head = data.inactive_reason === 'policy_load_failed'
      ? '3.0 判定链路没有在跑：配置里启用了策略，但这一版加载失败，请求按旧路由静默运行。'
      : '没启用 3.0：配置里没有 policy 段（config_schema_version=2 的缺省），整套按旧路由运行。';
    showPlStatus(head + (data.load_error ? '\n加载失败原因：' + data.load_error : ''), 'err');
  }
  renderPolicyStats(data);
  renderPolicyBundles(data);
  fillSimScopes();
}

function renderPolicyStats(d) {
  const sh = d.shadow || {};
  // agree_percent 只在有影子流量时才有；缺字段也别让整屏崩掉——这一屏是推进
  // shadow→enforce 的唯一依据，读不到时宁可显示「—」并保留其它统计。
  const rate = sh.evaluated > 0 && typeof sh.agree_percent === 'number'
    ? sh.agree_percent.toFixed(1) + '%' : '—';
  const by = sh.by_verdict || {};
  const moved = (by.primary_moved || 0) + (by.policy_denied || 0)
    + (by.no_candidate || 0) + (by.decision_denied || 0);
  $('pl-stats').replaceChildren(
    stat('配置的模式', d.configured_mode + ' → ' + d.mode, 'sm',
      'configured_mode 是 YAML 里写的，mode 是归一后的实际口径'),
    stat('是否在跑', d.running ? '是' : '否', 'sm',
      '「否」意味着请求按旧路由运行，哪怕 mode 写着 shadow；此时顶部横幅会连带给出加载失败原因'),
    stat('生效版本', d.policy_version || '—', 'sm'),
    stat('路由代', d.routing_epoch || '—', 'sm',
      'seed 由 (request_id, 版本, 代) 派生；代一变，同一 request_id 的 seed 也变'),
    stat('数据分级', d.data_level, 'sm', '请求的分级高于某家上游上限时，那家不进 3.0 候选池'),
    stat('回落旧路由', d.fallback_to_legacy ? '开' : '关', 'sm',
      '只对「3.0 算不出计划」生效；策略本身拒绝请求时不会被它绕过'),
    stat('影子已判定', num(sh.evaluated), 'sm'),
    stat('影子一致率', rate, 'sm',
      sh.evaluated > 0 ? '分母是已判定次数；不一致 ' + num(moved) + ' 次' : '还没有影子流量'),
  );
}

// 声明的包与加载成功的包并排：只列一边就是让「引用改了、内容文件没改」这类事故
// 只能从日志里读出来。
function renderPolicyBundles(d) {
  const loaded = {};
  (d.bundles || []).forEach((b) => { loaded[b.id] = b; });
  const refs = d.declared_bundles || [];
  const box = $('pl-bundles');
  if (!refs.length && !(d.bundles || []).length) {
    box.replaceChildren(h('p', { class: 'muted', text: '配置里没有引用任何策略包。' }));
    return;
  }
  const tb = h('tbody', null,
    ...refs.map((r) => {
      const b = loaded[r.id];
      return h('tr', null,
        h('td', null, h('code', { class: 'k', text: r.id + '.yaml' })),
        h('td', { class: 'num', text: String(r.version) }),
        h('td', null, h('code', { class: 'k', text: r.scope })),
        h('td', null, b
          ? h('span', { class: 'tag ok', text: '已加载 v' + b.version })
          : h('span', { class: 'tag', text: '未加载' })),
        h('td', { class: 'num', text: b ? String((b.rules || []).length) : '—' }));
    }));
  box.replaceChildren(h('div', { class: 'tablewrap' },
    h('table', null,
      h('thead', null, h('tr', null,
        h('th', { text: '策略包' }), h('th', { text: '引用版本' }), h('th', { text: '范围' }),
        h('th', { text: '加载' }), h('th', { text: '规则数' }))),
      tb),
    ...refs.filter((r) => loaded[r.id]).map((r) => bundleRules(loaded[r.id]))));
}

// 规则只以选择器现身，条件只列键名：键名足以让人看出「这条规则要看分级」，值不外泄。
function bundleRules(b) {
  return h('details', { class: 'mt' },
    h('summary', { class: 'muted', text: b.id + ' 的规则（' + (b.rules || []).length + ' 条）' }),
    h('div', { class: 'tablewrap' }, h('table', null,
      h('thead', null, h('tr', null,
        h('th', { text: '主体' }), h('th', { text: '资源' }), h('th', { text: '动作' }),
        h('th', { text: '效果' }), h('th', { text: '范围' }), h('th', { text: '条件键' }),
        h('th', { text: '到期' }))),
      h('tbody', null, ...(b.rules || []).map((e) => h('tr', null,
        h('td', null, h('code', { class: 'k', text: e.subject })),
        h('td', null, h('code', { class: 'k', text: e.resource })),
        h('td', null, h('code', { class: 'k', text: e.action })),
        h('td', null, h('span', { class: 'tag' + (e.effect === 'allow' ? ' ok' : ''), text: e.effect })),
        h('td', null, h('code', { class: 'k', text: e.scope || '—' })),
        h('td', null, (e.condition_keys || []).length
          ? h('span', { class: 'chips' }, ...(e.condition_keys || []).map((k) => h('span', { class: 'chip', text: k })))
          : h('span', { class: 'muted', text: '—' })),
        h('td', { class: 'muted', text: e.expires_at || '不限' })))))));
}

// 模拟的范围下拉跟着用户表走：scope 留空就是网关自身（system 范围）。
function fillSimScopes() {
  const sel = $('sim-scope');
  const cur = sel.value;
  sel.replaceChildren(
    h('option', { value: '', text: '网关自身（system 范围）' }),
    ...(ADM.users || []).map((u) => h('option', {
      value: u.name, text: u.name + '（' + u.mode + '）',
    })));
  sel.value = (cur && (ADM.users || []).some((u) => u.name === cur)) ? cur : '';
}

async function runSimulate() {
  const model = $('sim-model').value.trim();
  if (!model) return showErr($('sim-err'), '模型名必填（与客户端请求里写的一致）');
  const btn = $('sim-run');
  btn.disabled = true;
  showErr($('sim-err'), '');
  try {
    const { data } = await adminApi('/v1/_admin/policy/simulate', {
      method: 'POST',
      body: JSON.stringify({
        scope: $('sim-scope').value, model,
        request_id: $('sim-rid').value.trim() || undefined,
      }),
    });
    renderSimulate(data);
  } catch (e) {
    $('sim-out').hidden = true;
    showErr($('sim-err'), e.message);
  } finally {
    btn.disabled = false;
  }
}

function renderSimulate(d) {
  const box = $('sim-out');
  box.hidden = false;
  const v = VERDICT[d.verdict] || [String(d.verdict || '—'), ''];
  const kids = [];

  kids.push(h('div', { class: 'row' },
    h('span', { class: 'tag' + (v[1] ? ' ' + v[1] : ''), text: v[0] }),
    h('span', { class: 'muted', text: d.mode + ' · ' + (d.policy_version || '无版本') + ' · ' + d.elapsed_ms + 'ms' }),
    h('span', { class: 'muted mono', text: 'request_id ' + d.request_id }),
    h('span', { class: 'grow' }),
    d.sticky ? h('span', { class: 'muted', text: '粘性偏好：' + d.sticky }) : null));

  // enforce 作用面单列一行：shadow 下线上不受影响，而运维要看的正是「明天切了会怎样」。
  // 已经是 enforce 时这句要换成「真实作用」，否则读起来像是在说明一个假设。
  const ep = d.enforce_preview || {};
  kids.push(h('p', { class: 'sub' },
    d.mode === 'enforce' ? '这条请求的真实作用：' : '如果切到 enforce：',
    ep.blocked ? h('span', { class: 'tag', text: '会被拦截' })
      : ep.applied ? h('span', { class: 'tag ok', text: '计划生效' })
        : h('span', { class: 'tag', text: '不作用（回落旧路由）' }),
    h('span', { class: 'muted', text: ep.blocked || ep.note || '' })));
  if (d.note) kids.push(h('p', { class: 'sub', text: '判定说明：' + d.note }));

  const dec = d.decision || {};
  kids.push(h('div', { class: 'gridn' },
    stat('授权', dec.allowed ? '允许' : '拒绝', 'sm'),
    stat('结论', String(dec.reason || '—'), 'sm'),
    stat('命中规则', String((dec.matched_rules || []).length)),
    stat('候选数', String((d.candidates || []).length)),
    stat('被策略排除', String((d.excluded || []).length))));
  if (dec.explain) kids.push(h('p', { class: 'sub', text: dec.explain }));

  const planOrder = d.plan_order || [];
  if (planOrder.length) {
    const seq = [];
    planOrder.forEach((name, i) => {
      if (i > 0) seq.push(h('span', { class: 'seq-arrow', text: '→' }));
      seq.push(h('span', { class: 'chip', text: name }));
    });
    kids.push(h('p', { class: 'sub' }, '3.0 计划次序：', h('span', { class: 'seq' }, ...seq)));
  } else if (d.plan_error) {
    kids.push(h('p', { class: 'sub', text: '3.0 给不出计划：' + d.plan_error }));
  }
  const legacy = (d.legacy_first || []).map((n) => h('span', { class: 'chip', text: n }));
  kids.push(h('p', { class: 'sub' },
    '旧链路第一档本来会用：',
    h('span', { class: 'chips' }, ...(legacy.length ? legacy : [h('span', { class: 'muted', text: '（空池）' })]))));

  kids.push(h('div', { class: 'tablewrap' }, h('table', null,
    h('thead', null, h('tr', null,
      h('th', { text: '上游' }), h('th', { text: '上游模型名' }), h('th', { text: '档' }),
      h('th', { text: '健康' }), h('th', { text: '权重' }), h('th', { text: '分级上限' }),
      h('th', { text: '排除原因' }))),
    h('tbody', null, ...(d.candidates || []).map((c) => {
      const ex = (d.excluded || []).find((e) => e.provider === c.provider);
      return h('tr', null,
        h('td', null, h('code', { class: 'k', text: c.provider })),
        h('td', null, h('code', { class: 'k', text: c.upstream_model })),
        h('td', { class: 'num', text: String(c.tier) }),
        h('td', null, h('span', { class: 'dot' + (c.healthy ? '' : ' off') }), c.healthy ? '可用' : '冷却'),
        h('td', { class: 'num', text: String(c.weight) }),
        h('td', null, h('span', { class: 'tag', text: c.max_data_level })),
        h('td', null, ex ? h('span', { class: 'tag', text: ex.reason }) : h('span', { class: 'muted', text: '—' })));
    })))));

  // 有 seed 才谈得上逐位复现：计划没跑过就没有 seed（§2.8），空 seed 后面再写
  // 「同 request_id 可复现」等于界面自己造了一个做不到的承诺。
  kids.push(h('p', { class: 'sub mono' },
    'routing_seed ' + (d.routing_seed || '—'),
    d.digest ? ' · 候选摘要 ' + d.digest : '',
    d.routing_seed ? ' · 同 request_id + 同版本 + 同代可复现' : ' · 本次没有计划，无逐位复现'));

  box.replaceChildren(...kids.filter(Boolean));
}

async function runTrace() {
  const rid = $('tr-rid').value.trim();
  if (!rid) return showErr($('tr-err'), 'request_id 必填');
  showErr($('tr-err'), '');
  try {
    const { data } = await adminApi('/v1/_admin/policy/trace?request_id=' + encodeURIComponent(rid));
    const box = $('tr-out');
    box.hidden = false;
    box.replaceChildren(
      h('div', { class: 'gridn' },
        stat('范围', (data.scope_kind || '—') + ':' + (data.scope_id || '—'), 'sm'),
        stat('策略版本', data.policy_version || '—', 'sm'),
        stat('路由代', data.routing_epoch || '—', 'sm'),
        stat('逐位可复现', data.exactly_replayable ? '是' : '否', 'sm')),
      h('p', { class: 'sub mono' },
        'seed ' + (data.routing_seed || '—'),
        data.candidates_digest ? ' · 候选摘要 ' + data.candidates_digest : ''),
      h('p', { class: 'sub', text: data.note || '' }),
      h('p', { class: 'sub', text: data.scope_note || '' }));
  } catch (e) {
    $('tr-out').hidden = true;
    showErr($('tr-err'), e.message);
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
  // 模拟的范围下拉要用这份名单；两处都调一次是因为进台时它们是并发加载的，
  // 谁先回来都不能让下拉空着。
  fillSimScopes();

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

// 系统池里哪些是「全部直通」。它们在 config.yaml 里**不声明任何模型名**，
// 所以继承列表里天然看不到它们 —— 不是漏了，是声明里就没有。
function passthroughProviders() {
  return (ADM.cfg.providers || []).filter((p) => p.passthrough && p.enabled);
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
  const pass = passthroughProviders();
  $('ud-models-note').textContent = inherit
    ? (pool.length
        ? '他继承系统池声明的全部模型：' + pool.join('、')
        : '系统池没有声明任何具体模型名，所以上表是空的。') +
      (pass.length
        ? ' 另有 ' + pass.length + ' 家是「全部直通」（' + pass.map((p) => p.name || '未命名').join('、') +
          '）：它们不声明模型名，任何模型名都原样转发，因此不在上表里 —— 见下面第二块。'
        : '')
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

  // 直通型上游：声明里没有模型名，所以继承列表里看不到它们的模型 —— 说清楚为什么，
  // 再给一个按钮把它们实际提供什么列出来。免得让人以为「deepseek 的模型丢了」。
  const pass = passthroughProviders();
  const box = $('ud-inherit-pass');
  box.hidden = pass.length === 0;
  if (!pass.length) return;
  $('ud-inherit-pass-note').textContent =
    '系统池里有 ' + pass.length + ' 家是「全部直通」：' +
    pass.map((p) => p.name || '未命名').join('、') +
    '。它们在 config.yaml 里没有声明具体模型名，所以上表里看不到它们的模型。' +
    '对这个用户来说，任何模型名都会原样转给它们。点下面的按钮可以列出它们实际提供什么。';
  $('ud-inherit-probe-state').textContent = '';
  $('ud-inherit-probe-wrap').hidden = true;
  $('ud-inherit-probe-list').querySelector('tbody').replaceChildren();
}

// 探测直通型上游实际提供的模型。这是参考信息，不是白名单 ——
// 直通上游接受它认得的任何名字，不只是列出来的这些。
async function probePassthrough() {
  const pass = passthroughProviders();
  const user = ADM.editing;
  const state = $('ud-inherit-probe-state');
  const wrap = $('ud-inherit-probe-wrap');
  const tb = $('ud-inherit-probe-list').querySelector('tbody');
  if (!pass.length) return;
  state.textContent = '正在探测 ' + pass.length + ' 家…';
  tb.replaceChildren();
  wrap.hidden = true;

  const rows = [];
  for (const p of pass) {
    try {
      const { data } = await adminApi('/v1/_admin/providers/' + encodeURIComponent(p.name.trim() || '-') + '/discover', {
        method: 'POST', body: JSON.stringify(provCreds(p)),
      });
      for (const m of (data.models || [])) rows.push({ prov: p.name || '未命名', model: m });
    } catch (e) {
      rows.push({ prov: p.name || '未命名', model: '（探测失败：' + e.message + '）', err: true });
    }
  }
  tb.replaceChildren(...rows.map((r) => {
    const res = h('span', { class: 'testres', text: '—' });
    return h('tr', null,
      h('td', null, h('code', { class: 'k', text: r.prov })),
      h('td', null, h('code', { class: 'k', text: r.model })),
      h('td', null, r.err ? res :
        h('button', { type: 'button', class: 'link', text: '测试',
          onclick: () => testMapping(user, r.model, res) }), ' ', res),
    );
  }));
  wrap.hidden = rows.length === 0;
  state.textContent = rows.length
    ? '共 ' + rows.length + ' 条。这是参考信息，不是白名单 —— 直通上游接受它认得的任何名字。'
    : '这些上游都没有给出模型列表（它们可能只支持对话接口）。';
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

// 「供应商侧模型名」这一列要填的是：某家供应商在它自己的 models 里**声明过的**名字。
// 所以候选来源是「这家的声明」，而不是它上游 /v1/models 的真实列表 ——
// 后者是写进那家 models 里的东西，不是这一列要填的。
async function probeForMapping() {
  const picked = $('ud-new-provider').value;
  const fallback = (ADM.cfg.providers[0] || {}).name;
  const name = picked || fallback;
  if (!name) return showErr($('ud-err'), '先在右边选一个系统上游');
  const p = (ADM.cfg.providers || []).find((x) => x.name === name);
  if (!p) return showErr($('ud-err'), '系统池里没有 ' + name);
  const names = (p.map || []).map((pair) => pair[0]).filter(Boolean);
  $('ud-cands').replaceChildren(...names.map((m) => h('option', { value: m })));
  showErr($('ud-err'), '');
  const banner = $('admin-banner');
  banner.hidden = false;
  banner.textContent = p.passthrough
    ? name + ' 是「全部直通」：没声明任何模型名，任何名字都会原样转给它（这一列留空即可）。'
    : name + ' 声明了 ' + names.length + ' 个模型名，已填成候选：' +
      names.slice(0, 8).join('、') + (names.length > 8 ? ' …' : '');
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

  // 汇总 + 输入缓存命中率。hit+miss 都为 0 = 上游没回报缓存拆分，
  // 那是「不知道」而不是 0%（有的聚合商压根不给这个字段）。
  const t = (data && data.totals) || {};
  const hit = t.cache_hit_tokens || 0;
  const miss = t.cache_miss_tokens || 0;
  const rate = hit + miss > 0 ? ((hit * 100) / (hit + miss)).toFixed(1) + '%' : '—';
  const rateTitle = hit + miss > 0
    ? '输入命中 ' + num(hit) + ' / 输入合计 ' + num(hit + miss) + ' token'
    : '上游没回报缓存拆分（不是命中率 0%）';
  $('ud-totals').replaceChildren(
    stat('请求', num(t.requests)),
    stat('成功 / 失败', num(t.ok) + ' / ' + num(t.failed)),
    stat('输入 / 输出 tok', num(t.prompt_tokens) + ' / ' + num(t.completion_tokens)),
    stat('输入缓存命中率', rate, 'sm', rateTitle),
  );

  const tb = $('ud-usage').querySelector('tbody');
  tb.replaceChildren(...rows.map((r) => {
    const hit = r.cache_hit_tokens || 0;
    const miss = r.cache_miss_tokens || 0;
    const rate = hit + miss > 0 ? ((hit * 100) / (hit + miss)).toFixed(1) + '%' : '—';
    return h('tr', null,
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
      h('td', { class: 'num', text: r.cost != null ? r.cost.toFixed(4) : '—' }),
    );
  }));
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
$('ud-token').addEventListener('click', rotateToken);
$('ud-delete').addEventListener('click', deleteUser);
$('ud-add-model').addEventListener('click', addModel);
$('ud-inherit').addEventListener('change', switchToInherit);
$('ud-narrow').addEventListener('change', switchToNarrow);
$('ud-inherit-probe').addEventListener('click', probePassthrough);
$('ud-probe').addEventListener('click', probeForMapping);
$('ud-new-model').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); addModel(); } });
$('ud-new-upstream').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); addModel(); } });
$('cfg-save').addEventListener('click', saveConfig);
$('cfg-validate').addEventListener('click', validateConfig);
$('pl-refresh').addEventListener('click', () => loadPolicy());
$('sim-run').addEventListener('click', runSimulate);
$('sim-model').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runSimulate(); } });
$('sim-rid').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runSimulate(); } });
$('tr-run').addEventListener('click', runTrace);
$('tr-rid').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runTrace(); } });
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
