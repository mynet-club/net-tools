'use strict';

const ADM = { users: [], sys: [], cfg: { providers: [] }, cands: {}, editing: null, detail: null,
  policy: null, plb: null, plbErr: '', plDraft: null,
  decl: null, declDraft: { p: '', kn: '' }, declDisk: { p: '', kn: '' }, declDirty: { p: false, kn: false } };

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
  await Promise.all([loadSysProviders(), loadAdminUsers(), loadPolicy(), loadReplay()]);
  // 用户列表与策略包是并行拉回来的，范围选项此时才完整（列表本身 loadPolicy 已经查过）。
  fillAuditScopes();
}

function adminLogout() {
  sessionClear();
  state.token = '';
  ADM.users = [];
  ADM.editing = null;
  // 声明段的草稿是上一个部署的配置文本；留着它，下次登录会把旧内容当成待保存的编辑。
  ADM.decl = null;
  ADM.declDraft = { p: '', kn: '' };
  ADM.declDisk = { p: '', kn: '' };
  ADM.declDirty = { p: false, kn: false };
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
      max_data_level: p.max_data_level || '',
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

  // 分级声明是 3.0 分级门的事实来源：启用 shadow/enforce 时每家已启用的上游都必须选它。
  // 「（未声明）」只在 legacy 下合法，选中它发出去等价于「不改本行」。
  const level = h('select', { class: 'plevel' });
  level.replaceChildren(
    h('option', { value: '', text: '（留空 = 不改）' }),
    ...['public', 'internal', 'confidential', 'restricted'].map((v) => h('option', { value: v, text: v })),
  );
  level.value = p.max_data_level || '';
  level.addEventListener('change', () => { p.max_data_level = level.value; touchCfg(); });

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
      h('div', null, h('label', { text: '可承接最高分级' }), level),
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
        max_data_level: p.max_data_level || '',
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

/* ── 策略与路由（§3.H：可见性 + 版本发布/回滚）─────────────────────
   读的是 /v1/_admin/policy[/simulate|/trace|/bundles…]，写的是
   /v1/_admin/policy[/bundles/{id}[/rollback]|/active|/mode]。
   界面不参与任何判定，也不在前端复算权限：结论由接线层的判定核给出，
   写侧的校验由服务端整份配置的加载通道给出 —— 界面上说「会通过」而线上拒了，
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

async function loadPolicy(keepMsg) {
  if (!keepMsg) showPlStatus('');
  let data;
  try {
    ({ data } = await adminApi('/v1/_admin/policy'));
  } catch (e) {
    showPlStatus('读不到策略状态：' + e.message, 'err');
    return;
  }
  ADM.policy = data;
  // 引用与内容文件的核对视图：它直接读磁盘，带 matches/drift/orphans 与每包的备份数。
  // 这一步失败不拦整屏 —— 运行态那一半仍然要说得出口，只是发布/回滚那几列暂时空着。
  try {
    ADM.plb = (await adminApi('/v1/_admin/policy/bundles')).data;
    ADM.plbErr = '';
  } catch (e) {
    ADM.plb = null;
    ADM.plbErr = e.message;
  }
  $('pl-rev').textContent = '配置修订 ' + num(data.revision) + ' · schema v' + num(data.config_schema_version);
  // 「配了但没生效」必须比任何统计都先看见：mode 写着 shadow、策略包却加载失败时，
  // 请求其实按旧路由静默运行，只报 mode 的界面会说谎。
  if (!data.running) {
    // 两种 legacy 必须分开说：显式停在 legacy 的部署是「知道自己在干什么」，
    // 还没有 policy 段的部署是「还没上 3.0」。把前者报成后者，运维会去补一个
    // 本该由他决定的模式，而应急开关刚刚被人按下去过。
    const noSection = !data.configured_mode || data.configured_mode === '-';
    const head = data.inactive_reason === 'policy_load_failed'
      ? '3.0 判定链路没有在跑：配置里启用了策略，但这一版加载失败，请求按旧路由静默运行。'
      : (noSection
        ? '没启用 3.0：配置里还没有 policy 段（config_schema_version=2 的缺省），整套按旧路由运行。'
        : '没启用 3.0：配置里 policy.mode = ' + data.configured_mode +
          '，这是显式停在旧路由（legacy 就是那个应急开关）。要开始判定见下面「模式、生效包与版本发布」。');
    showPlStatus(head + (data.load_error ? '\n加载失败原因：' + data.load_error : ''), 'err');
  } else if (ADM.plb && ADM.plb.drift_warning) {
    // 「现在照旧在跑」与「下一次加载会整体失败」可以同时为真（热加载只看配置文件 mtime）。
    showPlStatus(ADM.plb.drift_warning, 'err');
  }
  renderPolicyStats(data);
  renderPolicyBundles(data);
  renderPolicyWrite();
  fillSimScopes();
  // 声明段的「参与/不参与请求」完全由 policy.mode 决定，所以模式一变就要跟着重读。
  // 它失败不该挡住策略这一屏（两边是不同的段），自己会说明为什么读不到。
  loadDeclarations(true).catch(() => {});
  // 同理，采集窗口只在 enforce 下收记录：模式一按下去，回放那一屏的横幅必须跟着变，
  // 否则「开关是开的、窗口是空的」就没人解释了。它也失败不挡这一屏。
  loadReplay(true).catch(() => {});
  // 策略写侧每次都落审计（policypublish.go 的落盘通道），所以这一屏刷新过之后
  // 审计列表也要跟着刷新：面板停在改动前的记录，等于把刚按下的按钮记的那条藏起来。
  fillAuditScopes();
  loadAudit();
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
  // legacy 下生效分级只能是 unknown（没有 PolicyContext，服务端不许替配置猜一级），
  // 但配置里那一行确实写着值。只报生效值，这一屏就会对已经声明了 internal 的部署
  // 说「unknown」，于是运维以为还没配。
  const declared = d.declared_data_level && d.declared_data_level !== '-'
    && d.declared_data_level !== d.data_level ? d.declared_data_level : '';
  $('pl-stats').replaceChildren(
    stat('配置的模式', d.configured_mode + ' → ' + d.mode, 'sm',
      'configured_mode 是 YAML 里写的，mode 是归一后的实际口径'),
    stat('是否在跑', d.running ? '是' : '否', 'sm',
      '「否」意味着请求按旧路由运行，哪怕 mode 写着 shadow；此时顶部横幅会连带给出加载失败原因'),
    stat('生效版本', d.policy_version || '—', 'sm'),
    stat('路由代', d.routing_epoch || '—', 'sm',
      'seed 由 (request_id, 版本, 代) 派生；代一变，同一 request_id 的 seed 也变'),
    stat('数据分级', declared ? d.data_level + '（声明 ' + declared + '）' : d.data_level, 'sm',
      '请求的分级高于某家上游上限时，那家不进 3.0 候选池'
      + (declared ? '；括号里是 config.yaml 声明的那一级 —— ' + d.mode + ' 下它不参与判定' : '')),
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
  const box = $('pl-bundles');
  const pb = ADM.plb;
  if (!pb) return renderPolicyBundlesFromRuntime(box, d);
  const refs = pb.refs || [];
  const orphans = pb.orphans || [];
  if (!refs.length && !orphans.length) {
    box.replaceChildren(h('p', {
      class: 'muted',
      text: pb.bundle_dir_abs
        ? '配置里没有引用任何策略包（包目录：' + pb.bundle_dir + '；磁盘上也没有可读的 <id>.yaml）。'
        : '配置里没有引用任何策略包。',
    }));
    return;
  }
  const loaded = {};
  (d.bundles || []).forEach((b) => { loaded[b.id] = b; });
  const rows = refs.map((r) => policyRefRow(r, loaded[r.id], pb));
  const orphanRows = orphans.map((o) => h('tr', null,
    h('td', null, h('code', { class: 'k', text: (o.id || '—') + '.yaml' })),
    h('td', { class: 'num', text: String(o.version == null ? '—' : o.version) }),
    h('td', null, h('code', { class: 'k', text: o.scope || '—' })),
    h('td', null, o.file_error
      ? h('span', { class: 'tag err', text: '读不回来', title: o.file_error })
      : h('span', { class: 'tag', text: '没被引用', title: '内容文件在磁盘上，但配置里没有任何引用指向它：它不参与任何判定。「引用它」会按这一版重新建立引用。' })),
    h('td', { class: 'num', text: String(o.count == null ? '—' : o.count) }),
    h('td', null, o.file_error ? '' : h('button', {
      type: 'button', class: 'link', text: '引用它',
      title: '按磁盘上这一版的 id/version/scope 补回配置引用（内容文件一个字不改）。条件值不经读侧下发，所以这里不重抄规则。',
      onclick: () => referenceBundle(o),
    }))));
  box.replaceChildren(h('div', { class: 'tablewrap' },
    h('table', null,
      h('thead', null, h('tr', null,
        h('th', { text: '策略包' }), h('th', { text: '引用版本' }), h('th', { text: '范围' }),
        h('th', { text: '状态' }), h('th', { text: '规则数' }), h('th', { text: '操作' }))),
      h('tbody', null, ...rows, ...orphanRows)),
    // 规则明细来自核对视图（读磁盘），legacy 下运行态没有包也能看到内容。
    ...refs.filter((r) => (r.rules || []).length).map((r) => bundleRules(r))));
}

// 核对视图（/policy/bundles，直接读磁盘）读不到时的降级画法：只按运行态那一半列，
// 并且必须写明少了什么 —— 发布/回滚/撤下都靠核对视图点名，不能装作那几列还在。
function renderPolicyBundlesFromRuntime(box, d) {
  const loaded = {};
  (d.bundles || []).forEach((b) => { loaded[b.id] = b; });
  const refs = d.declared_bundles || [];
  const note = h('p', { class: 'hint' },
    '上面只按运行态画：引用与内容文件的核对视图这次读不到（' + (ADM.plbErr || '未知原因') +
    '）。发布、回滚、撤下要先看清「磁盘上是哪一版」，所以那一侧恢复之前这一屏当作只读。');
  if (!refs.length && !(d.bundles || []).length) {
    box.replaceChildren(h('p', { class: 'muted', text: '配置里没有引用任何策略包。' }), note);
    return;
  }
  box.replaceChildren(h('div', { class: 'tablewrap' },
    h('table', null,
      h('thead', null, h('tr', null,
        h('th', { text: '策略包' }), h('th', { text: '引用版本' }), h('th', { text: '范围' }),
        h('th', { text: '加载' }), h('th', { text: '规则数' }))),
      h('tbody', null, ...refs.map((r) => {
        const b = loaded[r.id];
        return h('tr', null,
          h('td', null, h('code', { class: 'k', text: r.id + '.yaml' }),
            r.id === d.active_bundle ? h('span', { class: 'tag act', text: '生效包' }) : null),
          h('td', { class: 'num', text: String(r.version) }),
          h('td', null, h('code', { class: 'k', text: r.scope })),
          h('td', null, b
            ? h('span', { class: 'tag ok', text: '已加载 v' + b.version })
            : h('span', { class: 'tag err', text: '未加载',
              title: '配置引用了它，运行态却没加载成功 —— 请求此刻按旧路由走' })),
          h('td', { class: 'num', text: b ? String((b.rules || []).length) : '—' }));
      }))),
    ...refs.filter((r) => loaded[r.id]).map((r) => bundleRules(loaded[r.id])),
    note));
}

// policyRefRow 把「配置里的这一条引用」与「磁盘上的那个内容文件」并排成一行。
// 状态列只回答一个问题：按现在两边重读，加载器会不会点头。
function policyRefRow(r, live, pb) {
  let status;
  if (r.file_error) {
    status = h('span', { class: 'tag err', text: r.file_exists ? '读不回来' : '路径不合法', title: r.file_error });
  } else if (!r.file_exists) {
    status = h('span', { class: 'tag err', text: '内容文件缺失', title: r.drift || '文件名必须是 <id>.yaml' });
  } else if (!r.matches) {
    status = h('span', { class: 'tag err', text: '引用与内容不一致', title: r.drift || '' });
  } else if (live) {
    status = h('span', { class: 'tag ok', text: '一致 · 已加载 v' + live.version });
  } else {
    status = h('span', { class: 'tag', text: '一致 · 未加载',
      title: '两边对得上，但当前运行态没加载它（mode=legacy 时这是正常状态）' });
  }
  return h('tr', null,
    h('td', null, h('code', { class: 'k', text: r.id + '.yaml' }),
      r.active ? h('span', { class: 'tag act', text: '生效包' }) : null),
    h('td', { class: 'num', text: String(r.version) }),
    h('td', null, h('code', { class: 'k', text: r.scope })),
    h('td', null, status),
    h('td', { class: 'num', text: r.rules_count == null ? '—' : String(r.rules_count) }),
    h('td', { class: 'row' },
      r.active ? null : h('button', {
        type: 'button', class: 'link', text: '设为生效',
        title: '只换 policy.active_bundle：引用与内容文件都不动，切回上一版就是这么切',
        onclick: () => plCall('POST', '/v1/_admin/policy/active', { bundle: r.id }),
      }),
      backupBox(r.id, r.backups),
      h('button', {
        type: 'button', class: 'link danger', text: '撤下',
        title: '只删配置里的这条引用；内容文件留在磁盘上，那一行会变成「没被引用」，点「引用它」就原样回来。撤生效包时要指定接棒者。',
        onclick: () => withdrawBundle(r, pb),
      })));
}

// backupBox 展开时才去读备份列表：一屏可能有十几个包，逐个预取没必要。
// toggle 只会在 <details> 上触发 —— 挂到内层 div 就等于「备份看得见但永远点不开」。
function backupBox(id, count) {
  const box = h('div', { class: 'muted', text: '展开后读取。' });
  const det = h('details', { class: 'inline-backup' },
    h('summary', { class: 'muted', text: '备份（' + num(count || 0) + '）' }), box);
  let loaded = false;
  det.addEventListener('toggle', async () => {
    if (loaded || !det.open) return;
    loaded = true;
    try {
      const { data } = await adminApi('/v1/_admin/policy/bundles/' + encodeURIComponent(id) + '/backups');
      const list = data.backups || [];
      box.replaceChildren(...(list.length ? list.map((b) => h('div', { class: 'row' },
        h('span', { class: 'mono muted', text: b.name }),
        h('span', { text: b.version ? 'v' + b.version : '—' }),
        b.error ? h('span', { class: 'tag err', text: '读不回来', title: b.error }) : h('button', {
          type: 'button', class: 'link', text: '回到这版',
          title: '内容文件与引用一起回到那一版；当前内容先存成新备份，所以回滚本身也能回滚',
          onclick: () => plCall('POST', '/v1/_admin/policy/bundles/' + encodeURIComponent(id) + '/rollback',
            { backup: b.name }),
        })))
        : [h('span', { text: '这个包还没有历史内容：第一次替换时才会生成备份。' })]));
    } catch (e) {
      loaded = false;
      box.replaceChildren(h('span', { class: 'err', text: '读备份失败：' + e.message }));
    }
  });
  return det;
}

function withdrawBundle(r, pb) {
  const others = (pb.refs || []).filter((x) => x.id !== r.id);
  if (r.active && others.length === 0) {
    return showPlStatus('这是唯一的策略包：停用 3.0 请在下面「模式」里选 legacy（应急开关，改一行即可），'
      + '撤掉最后一条引用会让 shadow/enforce 加载失败。', 'err');
  }
  let path = '/v1/_admin/policy/bundles/' + encodeURIComponent(r.id);
  if (r.active) {
    const pick = prompt('要撤的正是生效包，接棒者的包 id：', others[0] ? others[0].id : '');
    if (!pick) return showPlStatus('没给接棒者，已取消。', 'err');
    path += '?active=' + encodeURIComponent(pick.trim());
  } else if (!confirm('撤下对 ' + r.id + ' 的引用？内容文件会留在磁盘上（变成「没被引用」，随时能引回来）。')) {
    return;
  }
  return plCall('DELETE', path);
}

// plCall 是写侧唯一的出口：做完一次写就整屏重读，让界面说的永远是加载器认过的那份。
// 发布表单的草稿存在 ADM.plDraft 里，重读之后原样填回去 —— 校验失败时不该让人重抄规则。
async function plCall(method, path, body) {
  showPlStatus(method + ' ' + path + ' 处理中…');
  let res;
  try {
    res = await adminApi(path, { method, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch (e) {
    showPlStatus('失败：' + e.message, 'err');
    // 失败时配置没动过（服务端每一步失败都还原），所以仍要把磁盘那一侧刷新一次。
    await loadPolicy(true);
    return null;
  }
  const d = res.data || {};
  let msg = d.note || '已完成。';
  if (d.backup) msg += '（配置备份 ' + d.backup + '）';
  if (d.applied === false) msg += '\n⚠ 还在等热加载：下一次轮询才会装进运行态，可以先点刷新。';
  if (d.strict_error) msg += '\n⚠ 文件写入了但服务加载它会失败：' + d.strict_error;
  if ((d.warnings || []).length) msg += '\n提示：' + d.warnings.join('；');
  showPlStatus(msg, d.strict_error || d.applied === false ? 'err' : '');
  await loadPolicy(true);
  return d;
}

// 引用它 = POST …/reference：把磁盘上那份内容重新写回配置引用。
// 这里刻意不重发规则 —— 条件值不经读侧下发，界面手里本来就只有键名；
// 让服务端读那份已经在受校验目录里的文件，才是这个动作的真实语义。
function referenceBundle(o) {
  if (!o.id) {
    return showPlStatus('这个文件连 id 都读不出来（坏在文件里），要用 PUT 重新发布覆盖它。', 'err');
  }
  if (!confirm('按磁盘上的 ' + o.id + '.yaml（v' + o.version + '，scope=' + o.scope + '，'
    + num(o.count || 0) + ' 条规则）重新建立引用，并设为生效包？')) return;
  return plCall('POST', '/v1/_admin/policy/bundles/' + encodeURIComponent(o.id) + '/reference', {});
}

/* 写侧面板：模式、生效包、发布新版。三块都只把运维填进去的原文交给服务端，
   界面不复算权限（§9H）：这里挡的只有 JSON 语法和必填项 ——
   条件键、选择器形态、分级取值一律由服务端领域校验判，因为它才是真值来源。 */

const LEVELS = ['public', 'internal', 'confidential', 'restricted'];

// 规则示例只给形状与保留键名；条件值要由运维从自己的策略源文件带进来。
// （上面那张表只回显键名，拿界面回显当原件发布会把条件值丢掉 —— 这不是提示，是接口契约。）
const RULE_EXAMPLE = JSON.stringify([
  { subject: 'role:teacher', resource: 'model:gpt-4o', action: 'use', effect: 'allow',
    conditions: { 'max-data-level': 'internal' } },
  { subject: '*', resource: 'model:secret-model', action: 'use', effect: 'deny',
    expires_at: '2027-01-01T00:00:00Z' },
], null, 2);

// plDraft 让发布表单活得过整屏重读：校验失败时该看到的是自己刚写的那份，不是空框。
function plDraft() {
  if (!ADM.plDraft) {
    ADM.plDraft = { id: '', version: '', scope: '', active: true, rules: '' };
  }
  return ADM.plDraft;
}

// 占位符不能是 RULE_EXAMPLE 本身：整段示例当水印会把「还没粘贴规则」的空框衬得像已经
// 填好了，而空框发布出去就是一个零授权的包。
const RULES_PLACEHOLDER = '在这里粘贴规则 JSON 数组（从你自己的策略源文件带进来）。\n'
  + '不确定形状就先点「填入示例形状」。';

function renderPolicyWrite() {
  const box = $('pl-write');
  const d = ADM.policy || {};
  const refs = (ADM.plb && ADM.plb.refs) || [];
  const draft = plDraft();

  // ── 模式 ──
  const mode = h('select', { style: 'max-width:300px' },
    h('option', { value: 'legacy', text: 'legacy —— 3.0 不参与判定（应急开关）' }),
    h('option', { value: 'shadow', text: 'shadow —— 只观察，不改路由' }),
    h('option', { value: 'enforce', text: 'enforce —— 允许策略改路由' }));
  // 预置的是 YAML 里写的那个值；'-' 表示这份部署还没有 policy 段。
  mode.value = (d.configured_mode && d.configured_mode !== '-') ? d.configured_mode : 'legacy';

  // 「不改」保住的是配置里声明的那一级，所以预置值必须取声明值：legacy 下生效值是
  // unknown，用它当「当前」会把已经写了 internal 的部署显示成没配。
  const levelCur = d.declared_data_level && d.declared_data_level !== '-'
    ? d.declared_data_level : (d.data_level || '—');
  const level = h('select', { style: 'max-width:220px' },
    h('option', { value: '', text: '数据分级：不改（当前 ' + levelCur + '）' }),
    ...LEVELS.map((v) => h('option', { value: v, text: '改为 ' + v })));

  const fallback = h('select', { style: 'max-width:260px' },
    h('option', { value: '', text: '回落旧路由：不改（当前 ' + (d.fallback_to_legacy ? '开' : '关') + '）' }),
    h('option', { value: 'true', text: '开：3.0 算不出计划时回落旧路由' }),
    h('option', { value: 'false', text: '关：算不出计划就不放行' }));

  const activeSel = activeSelector(refs);

  // ── 发布表单：草稿住在 ADM.plDraft，所以整屏重读之后填的内容还在 ──
  const rulesBox = h('textarea', { class: 'pl-rules', rows: '10', spellcheck: 'false',
    placeholder: RULES_PLACEHOLDER, oninput: (e) => { draft.rules = e.target.value; } });
  rulesBox.value = draft.rules;
  const activeCb = h('input', { type: 'checkbox' });
  activeCb.checked = !!draft.active;
  activeCb.addEventListener('change', () => { draft.active = activeCb.checked; });

  box.replaceChildren(
    h('div', { class: 'row' },
      mode, level, fallback,
      h('button', {
        type: 'button', class: 'primary sm', text: '应用模式',
        title: '只改 policy 段的 mode / data_level / fallback_to_legacy；段外内容与注释原样',
        onclick: () => {
          const body = { mode: mode.value };
          if (level.value) body.data_level = level.value;
          if (fallback.value) body.fallback_to_legacy = fallback.value === 'true';
          return plCall('POST', '/v1/_admin/policy/mode', body);
        },
      })),
    // 从 legacy 起步的部署只有一条诚实的启用序列，这里把它写出来，
    // 而不是让人从三个 400 的原文里反推。
    h('p', { class: 'hint', text: '新上 3.0 的顺序：先在下面发布策略包（模式仍是 legacy，发布不会开始判定）→'
      + ' 再把模式切到 shadow 观察一致率 → 最后切 enforce。反过来做会被服务端拒掉并点名缺哪一步。' }),

    h('div', { class: 'row' },
      activeSel,
      h('button', {
        type: 'button', class: 'sm', text: '设为生效',
        title: '只换 policy.active_bundle：引用与内容都不动，所以「切回上一版」就是这个动作',
        onclick: () => {
          if (!activeSel.value) {
            return showPlStatus('还没有可切的包：先用下面的发布表单发一个策略包。', 'err');
          }
          return plCall('POST', '/v1/_admin/policy/active', { bundle: activeSel.value });
        },
      }),
      h('span', { class: 'hint', text: '切生效包不改任何内容文件，是 A/B 与回退的最小动作。' })),

    h('div', { class: 'pform' },
      h('div', { class: 'pform-grid' },
        h('div', null, h('label', { text: '策略包 id（会当文件名用）' }),
          h('input', { type: 'text', class: 'mono', placeholder: 'cs-lab-open',
            autocomplete: 'off', spellcheck: 'false', value: draft.id,
            oninput: (e) => { draft.id = e.target.value; } })),
        h('div', null, h('label', { text: '版本号（显式给，服务端不替你猜）' }),
          h('input', { type: 'number', class: 'mono', min: '1', step: '1', placeholder: '2',
            value: draft.version, oninput: (e) => { draft.version = e.target.value; } })),
        h('div', { class: 'wide' }, h('label', { text: '范围 scope（kind:id）' }),
          h('input', { type: 'text', class: 'mono', placeholder: 'system:gateway、project:cs-lab-7、organization:cs',
            autocomplete: 'off', spellcheck: 'false', value: draft.scope,
            oninput: (e) => { draft.scope = e.target.value; } })),
        h('div', { class: 'wide' },
          h('label', { class: 'inline' }, activeCb, '发布后立刻设为生效包'),
          h('label', { text: '规则（JSON 数组，从你自己的策略源文件粘贴；条件值不经读侧下发）' }),
          rulesBox,
          h('div', { class: 'row' },
            h('button', {
              type: 'button', class: 'ghost sm', text: '填入示例形状',
              title: '只给字段与保留键名，条件值仍要你从原件带进来',
              onclick: () => {
                draft.rules = RULE_EXAMPLE;
                rulesBox.value = RULE_EXAMPLE;
              },
            }),
            h('span', { class: 'grow' }),
            h('button', {
              type: 'button', class: 'primary', text: '发布这一版',
              title: '一次调用同时改引用与 policy-bundles/<id>.yaml；任何一步校验不过就整笔还原',
              onclick: () => publishDraft(draft),
            }))))));
}

function activeSelector(refs) {
  const sel = h('select', { style: 'max-width:300px' },
    h('option', { value: '', text: refs.length ? '（选一个已引用的包）' : '还没有引用的策略包 —— 先在下面发布一个' }));
  refs.forEach((r) => {
    sel.append(h('option', { value: r.id, text: r.id + ' @v' + r.version + (r.active ? '（现行生效）' : '') }));
  });
  return sel;
}

// publishDraft 只做形状检查（必填 + JSON 语法）：条件的键与值是不是合法判定输入，
// 是服务端领域校验的事 —— 前端算一套就会出现「界面说会过、线上拒了」的分叉。
function publishDraft(draft) {
  const id = (draft.id || '').trim();
  if (!id) return showPlStatus('策略包 id 必填：它会当文件名用（<id>.yaml）。', 'err');
  const version = Number(draft.version);
  if (!draft.version || !Number.isInteger(version) || version < 1) {
    return showPlStatus('version 要显式给且 ≥ 1：策略版本串是审计与回放的输入。', 'err');
  }
  const scope = (draft.scope || '').trim();
  if (!scope) return showPlStatus('scope 必填，写成 kind:id（例如 system:gateway）。', 'err');
  const raw = (draft.rules || '').trim();
  // 空白 = 忘了粘贴，不是「要发一个零授权的包」。后者是合法意图，所以显式写 [] 就放行；
  // 但服务端无从知道运维是不是想清楚了的，这一眼只能由下笔的人给。
  if (!raw) {
    return showPlStatus('规则正文是空的：那会发成一个零授权的包（enforce 下什么都放行不了）。'
      + '忘了粘贴就点「填入示例形状」再改；确实要发空包就显式写 []。', 'err');
  }
  let rules;
  try {
    rules = JSON.parse(raw);
  } catch (e) {
    return showPlStatus('规则正文不是合法 JSON：' + e.message, 'err');
  }
  if (!Array.isArray(rules)) return showPlStatus('规则必须是一个 JSON 数组，每条一个授权对象。', 'err');
  return plCall('PUT', '/v1/_admin/policy/bundles/' + encodeURIComponent(id),
    { version, scope, active: !!draft.active, entitlements: rules });
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

/* ── 处理器与知识库声明（§3.H） ─────────────────────────────────────
   这两段是 config.yaml 里的原文段，接口是整段读写，所以这一屏的形状就是
   「把磁盘上那一段交给人改」。界面上只挡两件事：JSON 语法、顶层必须是数组。
   条目里任何一条规则都不在这里判（阶段配了什么档位、上限之间怎么互相约束、
   端点形态、知识库 ID）—— 那全是服务端领域校验的活，抄一份到前端就会在领域包
   扩充那天变成「界面不让你填、配置其实能写」。 */

const DECL = [
  {
    which: 'p', key: 'processors', path: '/v1/_admin/config/processors',
    box: 'pc-p-json', err: 'pc-p-err', hint: 'pc-p-hint', save: 'pc-p-save',
    example: 'pc-p-example', disk: 'pc-p-disk', noun: '处理器声明',
  },
  {
    which: 'kn', key: 'knowledge_sources', path: '/v1/_admin/config/knowledge_sources',
    box: 'pc-kn-json', err: 'pc-kn-err', hint: 'pc-kn-hint', save: 'pc-kn-save',
    example: 'pc-kn-example', disk: 'pc-kn-disk', noun: '知识源委托入口',
  },
];

// 最小示例只给形状：它用的是内置类型 pii-mask（合法组合：请求侧阶段 + transform-body）。
// 换类型时按下面的取值域表改阶段与档位，最终判据仍以服务端为准。
const DECL_EXAMPLE = {
  p: [{
    name: 'pii-request', type: 'pii-mask', phase: 'before-upstream', scope: '*',
    timeout_ms: 5000, max_input_bytes: 1048576, max_output_bytes: 1048576,
    fail_closed: true, body_access: 'transform-body', version: '1',
  }],
  kn: [{
    name: 'campus-rag', endpoint: 'https://rag.internal.example/v1/retrieve',
    knowledge_bases: ['course-materials'], timeout_ms: 3000, max_response_bytes: 1048576,
  }],
};

const declSection = (which) => DECL.filter((s) => s.which === which)[0];

function showPcStatus(msg, kind) {
  const el = $('pc-status');
  el.textContent = msg || '';
  el.className = 'banner' + (kind === 'err' ? ' err-banner' : '');
  el.hidden = !msg;
}

async function loadDeclarations(keepMsg) {
  const got = {};
  for (const s of DECL) {
    try {
      got[s.which] = (await adminApi(s.path)).data;
    } catch (e) {
      // 一侧读不到就整屏说明读不到：两段各自带 mode/applies，拼一半的显示更容易误导。
      showPcStatus('读不到 ' + s.key + ' 段：' + e.message, 'err');
      return;
    }
  }
  ADM.decl = got;
  for (const s of DECL) {
    const disk = JSON.stringify(got[s.which][s.key] || [], null, 2);
    ADM.declDisk[s.which] = disk;
    // 编辑过的那一侧不覆盖：一次刷新抹掉刚填的声明，比多一个按钮糟得多。
    if (!ADM.declDirty[s.which]) ADM.declDraft[s.which] = disk;
  }
  renderDeclarations(keepMsg);
}

function renderDeclarations(keepMsg) {
  const d = ADM.decl || {};
  const p = d.p || {};
  const k = d.kn || {};
  const v = p.vocabulary || k.vocabulary || {};
  $('pc-rev').textContent = '配置修订 ' + num(p.revision) + ' · ' + (p.path || 'config.yaml');
  $('pc-stats').replaceChildren(
    // 「保存成功」与「正在生效」是两件事：§3.0 规则 2 只让 enforce 影响路由与处理器，
    // 不把这一层写在最上面，脱敏就会在 legacy 下被当成已经上线。
    stat('policy.mode', (p.mode || '—') + ' → ' + (p.applies ? '参与请求' : '暂不参与'), 'sm',
      '只有 enforce 允许 3.0 影响路由与处理器。legacy / shadow 下这两段是提前备好的配置，不碰正文。'),
    stat('处理器', num((p.processors || []).length) + ' 条', 'sm'),
    stat('知识源', num((k.knowledge_sources || []).length) + ' 条', 'sm'),
    stat('磁盘时间', p.mtime || '—', 'sm',
      '文件大小 ' + num(p.size) + ' 字节 · 每次写回先备份再原子改名，段外内容与注释原样'),
  );
  DECL.forEach((s) => {
    const one = (ADM.decl || {})[s.which] || {};
    $(s.hint).textContent = num((one[s.key] || []).length) + ' 条在磁盘上 · '
      + (ADM.declDirty[s.which] ? '编辑中（未保存）' : '与磁盘一致');
    $(s.box).value = ADM.declDraft[s.which];
  });
  renderVocab(v);

  const be = p.baseline_error || k.baseline_error || '';
  if (be) {
    // 基线坏了不能把 GET 变成 500：管理员要看清「磁盘上那条哪里不对」，
    // 而列表显示的是服务当前加载着的那一份 —— 整段保存合法声明就能修好它。
    showPcStatus('磁盘上的这一版读不回来：' + be
      + '\n上面的条数列显示的是服务当前加载着的那一份。修好它的办法是整段保存一份合法声明 —— 在校验通过之前原文件一个字节都不会动。', 'err');
  } else if (!keepMsg) {
    const w = p.warnings || [];
    showPcStatus(w.length ? '提示：' + w.join('；') : '');
  }
}

// 取值域表：服务端下发什么就显示什么，界面不补一项、不减一项。
function renderVocab(v) {
  const box = $('pc-vocab');
  if (!v || !v.processor_types) {
    box.replaceChildren(h('p', { class: 'muted', text: '这次没拿到取值域（接口没回 vocabulary）。' }));
    return;
  }
  const row = (k, list, note) => h('tr', null,
    h('th', { text: k }),
    h('td', null, h('code', { class: 'k', text: (list || []).join('、') || '—' }),
      h('span', { class: 'hint', text: note || '' })));
  const boundary = ((ADM.decl || {}).p || {}).boundary || '';
  box.replaceChildren(
    h('div', { class: 'tablewrap' }, h('table', null, h('tbody', null,
      row('处理器类型', v.processor_types, '类型集合不封闭：自定义类型由部署在注册期 RegisterType 注入。写了没注入的类型会告警并在装配期失败。'),
      row('阶段', v.phases, '闭集，执行次序固定：请求侧三个阶段 → after-upstream → audit。'),
      row('正文档位', v.body_accesses, 'metadata-only（不读正文）< inspect-body（读，不改）< transform-body（可改写正文）。'),
      row('范围写法', (v.scope_kinds || []).map((x) => x + ':id').concat(['*']), 'scope 必须显式写：* 是不限范围，kind:id 只对该范围生效。'),
    ))),
    h('p', { class: 'hint', text: '上限：timeout ≤ ' + num(v.max_timeout_ms) + ' ms；max_input_bytes ≤ '
      + num(v.absolute_max_input_bytes) + '、max_output_bytes ≤ ' + num(v.absolute_max_output_bytes)
      + ' 字节（且输出不得小于输入的 1/4）；name ≤ ' + num(v.max_name_len) + ' 字符；allowed_endpoints ≤ '
      + num(v.max_allowed_endpoints) + ' 条；知识源预算默认 ' + num(v.default_budget_ms)
      + ' ms、上限 ' + num(v.max_knowledge_budget_ms) + ' ms。' }),
    h('p', { class: 'hint', text: boundary }),
  );
}

// pcCall 是声明写侧唯一的出口：写完就整屏重读，让界面说的永远是加载器认过的那份。
async function pcCall(method, path, body, s) {
  showPcStatus(method + ' ' + path + ' 处理中…');
  let res;
  try {
    res = await adminApi(path, { method, body: JSON.stringify(body) });
  } catch (e) {
    showPcStatus('失败：' + e.message + '\n原文件未改动（服务端在校验不过时整笔还原，也不留审计）。', 'err');
    await loadDeclarations(true);
    return null;
  }
  const d = res.data || {};
  let msg = d.note || '已完成。';
  if (d.backup) msg += '（配置备份 ' + d.backup + '）';
  msg += d.applies
    ? '\nmode=' + d.mode + '：这些声明现在参与请求。'
    : '\n⚠ mode=' + d.mode + '：声明已写进配置，但现在还不参与请求（§3.0 规则 2）。要生效见「策略与路由」的模式。';
  if (d.applied === false) msg += '\n⚠ 还在等热加载：下一次轮询才会装进运行态，可以先点刷新。';
  if (d.strict_error) msg += '\n⚠ 文件写入了但服务加载它会失败：' + d.strict_error;
  if ((d.warnings || []).length) msg += '\n提示：' + d.warnings.join('；');
  showPcStatus(msg, d.strict_error || d.applied === false ? 'err' : '');
  // 磁盘现在就是刚提交的这一份，所以编辑标记清掉；重读会把规范化后的文本填回框里
  // （端点会去空白、条目按 name 排序）—— 那是加载器真正看到的形态，比原样留着更有用。
  ADM.declDirty[s.which] = false;
  ADM.declDraft[s.which] = '';
  await loadDeclarations(true);
  return d;
}

function saveDeclarations(s) {
  showErr($(s.err), '');
  let arr;
  try {
    arr = JSON.parse($(s.box).value.trim() || '[]');
  } catch (e) {
    return showErr($(s.err), 'JSON 语法不过：' + e.message);
  }
  if (!Array.isArray(arr)) {
    return showErr($(s.err), '这一段是一个数组：顶层要写成 […]（清空请显式保存 []）');
  }
  const onDisk = (((ADM.decl || {})[s.which] || {})[s.key] || []).length;
  // 整段替换意味着「保存空数组」= 删掉全部声明，而配置文件的段是整体写的，
  // 事后逐条撤销做不到 —— 所以这一笔单独确认，其余条数变化直接落。
  if (!arr.length && onDisk && !confirm('清空 ' + s.key + ' 段？磁盘上现在有 ' + onDisk
    + ' 条。整段替换是一次写完的，撤销只能靠那次写的配置备份文件。')) return;
  return pcCall('PUT', s.path, { [s.key]: arr }, s);
}

function fillDeclExample(which) {
  const s = declSection(which);
  showErr($(s.err), '');
  ADM.declDirty[which] = true;
  ADM.declDraft[which] = JSON.stringify(DECL_EXAMPLE[which], null, 2);
  $(s.box).value = ADM.declDraft[which];
  $(s.hint).textContent = '已填入示例（未保存）—— 名字、类型、端点都要改成你自己的。';
}

function rereadDeclDisk(which) {
  const s = declSection(which);
  showErr($(s.err), '');
  ADM.declDirty[which] = false;
  ADM.declDraft[which] = ADM.declDisk[which];
  $(s.box).value = ADM.declDraft[which];
  $(s.hint).textContent = '已读回磁盘上的那一份。';
}

// 编辑只动草稿。dirty 标记的作用是让「因为模式变了而重读」不抹掉没保存的内容 ——
// 一次误刷新丢掉整段声明，代价是有人重新手抄一遍规则。
function markDeclInput(which, text) {
  ADM.declDirty[which] = true;
  ADM.declDraft[which] = text;
  const s = declSection(which);
  $(s.hint).textContent = '编辑中（未保存）· 保存的是整段';
  showErr($(s.err), '');
}

/* ── 回放证据链（§2.8 的管理台面）──────────────────────────────────
   读 GET /v1/_admin/replay，写 POST …/sampling 与 POST …/clear，取件 GET …/export。
   这四个端点是 §2.8 那一包交付的，OpenAPI 里已有，这一屏不新增契约也不改字段语义。
   界面不跑判定、不跑回放、不复算权限：回放是另一个进程拿这份文件加当时那套策略包做的事，
   这里的数字全部是服务端窗口报出来的原值。 */

function showRpStatus(msg, kind) {
  const el = $('rp-status');
  el.textContent = msg || '';
  el.className = 'banner' + (kind === 'err' ? ' err-banner' : '');
  el.hidden = !msg;
}

async function loadReplay(keepMsg, forceEcho) {
  if (!keepMsg) showRpStatus('');
  let data;
  try {
    ({ data } = await adminApi('/v1/_admin/replay'));
  } catch (e) {
    showRpStatus('读不到采集窗口状态：' + e.message, 'err');
    return;
  }
  renderReplay(data, !!keepMsg, !!forceEcho);
}

function renderReplay(d, keepMsg, forceEcho) {
  $('rp-asof').textContent = '窗口快照 ' + (d.as_of || '—');
  // 「配了开关但一条都不收」是这一屏最容易被误读的状态：非 enforce 下窗口恒空，
  // 而开关看起来是开着的。服务端把这句话放在 warning 字段里，界面照实顶到最上面。
  if (d.warning) showRpStatus(d.warning, 'err');
  else if (!keepMsg) showRpStatus('');
  const filter = d.scope_filter && d.scope_filter !== '-' ? d.scope_filter : '';
  $('rp-enabled').checked = !!d.enabled;
  // 输入框只回显、不覆盖别人正在打的字：这四个字段是指针语义，误清一个就等于改一个。
  // forceEcho 是给「这次提交被服务端拒了」那条路用的 —— 那时框里那串已经是**确定没生效**
  // 的值，留着它会让下一屏说「千分率 500‰」而框里写着 2000，于是没人说得清哪个是真的。
  if (forceEcho || !rpDirty.permille) $('rp-permille').value = d.sample_permille == null ? '' : String(d.sample_permille);
  if (forceEcho || !rpDirty.filter) $('rp-filter').value = filter;
  if (forceEcho || !rpDirty.capacity) $('rp-capacity').value = d.capacity == null ? '' : String(d.capacity);
  $('rp-hint').textContent = '当前：' + (d.enabled ? '采集中' : '未采集')
    + ' · 千分率 ' + num(d.sample_permille) + '‰'
    + ' · 过滤 ' + (filter || '无') + ' · 上限 ' + num(d.capacity) + ' 条'
    + ' · mode=' + (d.mode || '—') + (d.running ? '' : '（3.0 没在跑）');
  $('rp-stats').replaceChildren(
    stat('窗口内判定', num(d.decisions), 'sm', '当前还在窗口里的判定记录条数（溢出会丢最旧的）'),
    stat('窗口内选路', num(d.routings), 'sm', '带路由计划记录的条数 —— 只有计划真的作用到请求上才有'),
    stat('累计收到', num(d.captured), 'sm'),
    stat('累计丢弃', num(d.dropped), 'sm', '容量越界丢最旧：这个数字非零就说明窗口小了或取走得太晚'),
    stat('采集失败', num(d.failed), 'sm', '判定发生了但组不出记录（缺版本/缺分级），数字本身就是要查的东西'),
    stat('回放默认抽样', d.sampling_algo_replay_default || '—', 'sm',
      '线上用 ' + (d.sampling_algo_declared || '—') + '，回放缺省用这个 —— 两者是不同实现。' +
      '逐位复现不靠缺省抽样器，而是按记录自己声明的算法重跑：今天承诺逐位的只有 ' +
      ((d.bit_exact_algos || []).join('/') || '—')),
    stat('首选顺序逐位复现', d.bit_exact_primary_order ? '是（有前提）' : '否', 'sm',
      // 只回「是」会比回「否」更误导：窗口里混着导入的 v1 记录时那一条永远只能解释性回放，
      // 前提由服务端一处给出，界面不自己拼条件。
      d.bit_exact_condition || '状态口没报出前提，界面就不声称逐位'),
    stat('记录结构版本', num(d.record_schema_version), 'sm',
      '本进程写出的版本；可读版本 ' +
      ((d.record_schema_version_readable || []).join('/') || '—') +
      ' —— 逐位凭据（replay_snapshot）只存在于 v2 记录里'),
  );
  rpDirty = { permille: false, filter: false, capacity: false };
}

let rpDirty = { permille: false, filter: false, capacity: false };

/* rpInt 只管「这是不是一个整数」这一件格式上的事；取值域（千分率 0~1000、
   容量 1~上限）仍然只由服务端判 —— 界面复算业务规则就会和注册表版本赛跑。
   留空 = 这个字段不动（服务端是指针语义）。 */
function rpInt(id) {
  const raw = $(id).value.trim();
  if (raw === '') return {};
  const n = Number(raw);
  if (!Number.isInteger(n)) return { bad: raw };
  return { value: n };
}

/* rpBody 组的是「这一屏看得见什么就提交什么」：
   - enabled 永远带上（复框没有「没填」这个状态）；
   - 千分率与上限留空 = 这个字段不动；
   - scope 永远带上，包括空串 —— 清空过滤框就是要清掉过滤，留着不动的话
     「我明明清空了怎么还在按 alice 采」会变成查不出来的状态。 */
function rpBody() {
  const body = { enabled: $('rp-enabled').checked, scope: $('rp-filter').value.trim() };
  const pm = rpInt('rp-permille');
  if (pm.value !== undefined) body.sample_permille = pm.value;
  const cp = rpInt('rp-capacity');
  if (cp.value !== undefined) body.capacity = cp.value;
  return { body, bad: pm.bad || cp.bad };
}

async function rpSave() {
  const btn = $('rp-save');
  const { body, bad } = rpBody();
  if (bad) {
    // 不把「abc」静默丢掉：那会让人以为改过了，而窗口里还是上一个千分率。
    showErr($('rp-err'), '「' + bad + '」不是整数 —— 千分率与窗口上限都只收整数，本次没有提交。');
    return;
  }
  btn.disabled = true;
  showErr($('rp-err'), '');
  try {
    const { data } = await adminApi('/v1/_admin/replay/sampling', {
      method: 'POST', body: JSON.stringify(body),
    });
    showRpStatus(data.note || '开关已改。', data.warning ? 'err' : '');
    await loadReplay(true);
  } catch (e) {
    showErr($('rp-err'), e.message);
    await loadReplay(true, e.status === 400);
  } finally {
    btn.disabled = false;
  }
}

async function rpClear() {
  const btn = $('rp-clear');
  btn.disabled = true;
  showErr($('rp-exp-err'), '');
  try {
    const { data } = await adminApi('/v1/_admin/replay/clear', { method: 'POST' });
    showRpStatus(data.note || '窗口已清空。');
    await loadReplay(true);
  } catch (e) {
    showErr($('rp-exp-err'), e.message);
  } finally {
    btn.disabled = false;
  }
}

/* 导出：拿的是记录文件**本身**那串字节，不做二次序列化。
   客户端把 JSON 解析后再拼回去，字段顺序与数字格式都可能变，而那份文件要交给另一个
   进程逐字段重跑 —— 「界面里导出的文件」和「磁盘上的记录文件」必须是一串字节。 */
async function rpExport() {
  const btn = $('rp-export');
  btn.disabled = true;
  showErr($('rp-exp-err'), '');
  const scope = $('rp-export-scope').value.trim();
  const q = scope ? ('?scope=' + encodeURIComponent(scope)) : '';
  try {
    const res = await fetch(state.base + '/v1/_admin/replay/export' + q, {
      headers: { Authorization: 'Bearer ' + state.token },
    });
    const text = await res.text();
    if (!res.ok) {
      let msg = res.status + ' ' + res.statusText;
      try {
        const j = JSON.parse(text);
        msg = (j && j.error && (j.error.message || j.error.type)) || msg;
      } catch { /* 非 JSON 的错误体就按状态码说 */ }
      throw new Error(msg);
    }
    let counted = '';
    try {
      const f = JSON.parse(text);
      counted = ' ' + ((f.decisions || []).length) + ' 条判定 / '
        + ((f.routings || []).length) + ' 条选路，' + new Blob([text]).size + ' 字节';
    } catch { counted = ' （这份文件读不出结构，仍按原样交付）'; }
    const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    const a = h('a', { href: url, download: 'llmproxy-replay-records.json' });
    document.body.append(a);
    a.click();
    a.remove();
    // 延迟释放：Safari 在 click 之后异步取件，立刻 revoke 会拿到一个空文件。
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
    $('rp-exp-hint').textContent = '已导出' + counted + '。拿它去另一个进程重跑：'
      + 'llmproxy replay run -records <这份文件> -now <当时时刻>。';
    await loadReplay(true);
  } catch (e) {
    showErr($('rp-exp-err'), e.message);
  } finally {
    btn.disabled = false;
  }
}

$('rp-refresh').addEventListener('click', () => loadReplay().catch(() => {}));
$('rp-save').addEventListener('click', rpSave);
$('rp-clear').addEventListener('click', rpClear);
$('rp-export').addEventListener('click', rpExport);
$('rp-permille').addEventListener('input', () => { rpDirty.permille = true; });
$('rp-filter').addEventListener('input', () => { rpDirty.filter = true; });
$('rp-capacity').addEventListener('input', () => { rpDirty.capacity = true; });

/* ── 操作审计 ────────────────────────────────────────────────────── */

// 范围下拉只列这个网关真的会写出的归属：全局开关与上游价目（system:global）、
// 每个用户、策略包自己声明的范围（组织/项目）。选项从已有状态里拼，不另开接口 ——
// 精确的 kind:id 可以直接敲在 URL 上，界面没必要把参数空间穷举一遍。
function fillAuditScopes() {
  const sel = $('ad-scope');
  const cur = sel.value;
  const opts = [
    { v: '', t: '（全部范围）' },
    { v: 'system:global', t: 'system:global（全局开关、上游价目）' },
  ];
  const seen = new Set(opts.map((o) => o.v));
  (ADM.users || []).forEach((u) => {
    const v = 'user:' + u.name;
    if (!seen.has(v)) { seen.add(v); opts.push({ v, t: v }); }
  });
  ((ADM.policy && ADM.policy.bundles) || []).forEach((b) => {
    if (b && b.scope && !seen.has(b.scope)) {
      seen.add(b.scope);
      opts.push({ v: b.scope, t: b.scope + '（策略包范围）' });
    }
  });
  sel.replaceChildren(...opts.map((o) => h('option', { value: o.v, text: o.t })));
  sel.value = opts.some((o) => o.v === cur) ? cur : '';
}

async function loadAudit() {
  showErr($('ad-err'), '');
  const btn = $('ad-run');
  btn.disabled = true;
  try {
    const scope = $('ad-scope').value;
    const n = $('ad-n').value.trim() || '100';
    const q = '/v1/_admin/audit?n=' + encodeURIComponent(n) +
      (scope ? '&scope=' + encodeURIComponent(scope) : '');
    const { data } = await adminApi(q);
    const list = (data && data.entries) || [];
    const tb = $('ad-table').querySelector('tbody');
    tb.replaceChildren(...list.map((e) => h('tr', null,
      h('td', { class: 'mono', text: e.ts ? new Date(e.ts).toLocaleString('zh-CN', { hour12: false }) : '—' }),
      h('td', null, h('code', { class: 'k', text: (e.scope && e.scope.kind ? e.scope.kind + ':' + e.scope.id : '—') })),
      h('td', null, e.actor || '—'),
      h('td', null, h('span', { class: 'tag' + (String(e.action || '').startsWith('policy.') ? ' ok' : ''), text: e.action || '' })),
      h('td', { class: 'mono', text: e.target || '—' }),
      h('td', { class: 'muted', text: e.detail || '' }))));
    $('ad-empty').hidden = list.length > 0;
  } catch (e) {
    tbClear();
    showErr($('ad-err'), e.message);
  } finally {
    btn.disabled = false;
  }
}

function tbClear() { $('ad-table').querySelector('tbody').replaceChildren(); $('ad-empty').hidden = true; }

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
  fillAuditScopes(); // 新建/删除的用户要立刻能在审计的归属筛选里选到
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
$('pc-refresh').addEventListener('click', () => loadDeclarations());
$('pc-p-save').addEventListener('click', () => saveDeclarations(declSection('p')));
$('pc-p-example').addEventListener('click', () => fillDeclExample('p'));
$('pc-p-disk').addEventListener('click', () => rereadDeclDisk('p'));
$('pc-p-json').addEventListener('input', (e) => markDeclInput('p', e.target.value));
$('pc-kn-save').addEventListener('click', () => saveDeclarations(declSection('kn')));
$('pc-kn-example').addEventListener('click', () => fillDeclExample('kn'));
$('pc-kn-disk').addEventListener('click', () => rereadDeclDisk('kn'));
$('pc-kn-json').addEventListener('input', (e) => markDeclInput('kn', e.target.value));
$('sim-run').addEventListener('click', runSimulate);
$('sim-model').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runSimulate(); } });
$('sim-rid').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runSimulate(); } });
$('tr-run').addEventListener('click', runTrace);
$('ad-refresh').addEventListener('click', () => { fillAuditScopes(); loadAudit(); });
$('ad-run').addEventListener('click', loadAudit);
$('ad-scope').addEventListener('change', loadAudit);
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
    weight: 1, proxy: 'direct', timeout_ms: 120000, max_data_level: '', passthrough: true, map: [], catchAll: false,
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
