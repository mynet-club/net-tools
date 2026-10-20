// 回放面板的 UI 层驱动夹具（§4 第 16 条）。
//
// 为什么需要它：本仓库对界面过去只有 `check-ui-refs.sh` 这一道**静态**门禁（查 id 引用）。
// 「保存开关 / 非法值拒绝 / 导出逐字节对账 / 清空 / 模式联动」这五件事以前是**浏览器手工路径
// + 命令行对账**，重跑要人再点一遍 —— 静态检查看不见 §14.2 抓到的两个真缺陷（非法值被静默
// 丢掉、控件被挤成四行），只有真在 DOM 上点一次才现形。
//
// 这一层刻意**不引第三方依赖**（与 llmproxy「Go 仅标准库、脚本零 npm」一致）：直接用 Node 内建
// 的 `fetch` + 全局 `WebSocket` 走 Chrome DevTools Protocol，操控一个真实的无头 Chrome。
// 它只驱动**已发布的界面代码**（ui/admin.html + admin.js），不复算任何业务规则 ——
// 界面的对错由界面自己到服务端跑一圈来判，夹具只负责点与读。
//
// 环境变量（由 scripts/ui-panel-fixture.sh 传）：
//   GW_BASE         网关地址，如 http://127.0.0.1:19123（页面从它的 /admin/legacy/ 加载，同源）
//   ADMIN_TOKEN     server.admin_token
//   EXPORT_DIR      浏览器下载目录（导出落这里，交给 shell 与 CLI 产物比 sha256）
//   EXPECT_EXPORT_SHA  期望的导出文件 sha256（shell 用 `llmproxy replay collect -out` 先算出来）
//   EXPORT_SCOPE    导出过滤（空=全窗口）
//   CHROME_PATH     可选，无头 Chrome 可执行文件；不给就自动探测
//
// 退出码：0 全过 / 1 有用例失败 / 3 环境缺外部条件（找不到 Chrome 等）。
// 末行固定打印 `RESULT <通过> <失败>`，供 shell 汇总。

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';

const GW = (process.env.GW_BASE || '').replace(/\/$/, '');
const ADMIN = process.env.ADMIN_TOKEN || '';
const EXPORT_DIR = process.env.EXPORT_DIR || '';
const EXPECT_SHA = process.env.EXPECT_EXPORT_SHA || '';
const EXPORT_SCOPE = process.env.EXPORT_SCOPE || '';

let PASS = 0, FAIL = 0;
const pass = (m) => { console.log('  [OK] ' + m); PASS++; };
const fail = (m) => { console.log('  [NG] ' + m); FAIL++; };
const chk = (m, got, want) => (String(got) === String(want)) ? pass(`${m}（${got}）`) : fail(`${m}：期望 ${want}，实际 ${got}`);

function die(code, msg) { console.log(msg); console.log(`RESULT ${PASS} ${FAIL}`); process.exit(code); }

if (!GW || !ADMIN) die(3, '  [环境] 缺 GW_BASE / ADMIN_TOKEN —— 本夹具需要网关地址与 admin_token');

function findChrome() {
  if (process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const cands = [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium', '/usr/bin/chromium-browser', '/snap/bin/chromium',
  ];
  return cands.find((p) => existsSync(p)) || '';
}
const CHROME = findChrome();
if (!CHROME) die(3, '  [环境] 找不到无头 Chrome —— 设 CHROME_PATH 或装 google-chrome/chromium（本夹具用它跑真实 DOM）');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((resolve) => {
  const s = net.createServer();
  s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
});

// ── CDP 极简客户端 ────────────────────────────────────────────────
class CDP {
  constructor(ws) { this.ws = ws; this.id = 0; this.pending = new Map(); this.events = []; this.subs = []; }
  static async attach(wsUrl) {
    const ws = new WebSocket(wsUrl);
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('CDP ws 连接失败')); });
    const c = new CDP(ws);
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data);
      if (m.id && c.pending.has(m.id)) { c.pending.get(m.id)(m); c.pending.delete(m.id); return; }
      c.events.push(m);
      for (const s of c.subs) s(m);
    };
    return c;
  }
  send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = ++this.id;
      this.pending.set(id, (m) => m.error ? reject(new Error(`${method}: ${m.error.message}`)) : resolve(m.result));
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  on(fn) { this.subs.push(fn); }
  async eval(expression) {
    const r = await this.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error('页面求值炸了: ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
    return r.result?.value;
  }
}

async function waitFor(cdp, expr, timeoutMs = 8000, label = expr) {
  const t0 = Date.now();
  for (;;) {
    try { if (await cdp.eval(expr)) return true; } catch { /* 页面切换期可能短暂取不到，继续等 */ }
    if (Date.now() - t0 > timeoutMs) { fail(`等待超时（${timeoutMs}ms）：${label}`); return false; }
    await sleep(80);
  }
}

const sel = (id) => `document.getElementById(${JSON.stringify(id)})`;
// 设值并派发 input 事件，让面板的 rpDirty* 监听器真的跑起来（直接赋 .value 不会触发挥）
const setVal = (id, v) => `(()=>{const e=${sel(id)};e.value=${JSON.stringify(v)};e.dispatchEvent(new Event('input',{bubbles:true}));return e.value;})()`;
const setChecked = (id, v) => `(()=>{const e=${sel(id)};e.checked=${v};e.dispatchEvent(new Event('change',{bubbles:true}));return e.checked;})()`;
const click = (id) => `${sel(id)}.click()`;
const text = (id) => `(${sel(id)}?.textContent||'')`;
const hidden = (id) => `${sel(id)}?.hidden`;
const visible = (id) => `!!${sel(id)} && !${sel(id)}.hidden && (${sel(id)}.offsetParent!==null || getComputedStyle(${sel(id)}).display!=='none')`;

// 从 Node 直连网关读服务端真值（同源页面之外的第二条腿：面板说的与服务端记的要一致）
async function api(path, method = 'GET', body) {
  const res = await fetch(GW + path, {
    method,
    headers: { Authorization: 'Bearer ' + ADMIN, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const t = await res.text();
  let j = null; try { j = JSON.parse(t); } catch {}
  return { status: res.status, json: j, text: t };
}

async function main() {
  const profile = mkdtempSync(join(tmpdir(), 'ui-panel-fixture-'));
  const debugPort = await freePort();
  const chrome = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--disable-background-networking', '--mute-audio',
    `--user-data-dir=${profile}`, `--remote-debugging-port=${debugPort}`, 'about:blank',
  ], { stdio: 'ignore' });

  let cdp;
  try {
    // 等 Chrome 起来（最多 10s）
    let ver = null;
    for (let i = 0; i < 100 && !ver; i++) {
      try { const r = await fetch(`http://127.0.0.1:${debugPort}/json/version`); if (r.ok) ver = await r.json(); } catch {}
      if (!ver) await sleep(100);
    }
    if (!ver) die(3, '  [环境] 无头 Chrome 起不来（/json/version 无响应）');
    console.log(`  无头浏览器：${ver.Browser}`);

    const tab = await (await fetch(`http://127.0.0.1:${debugPort}/json/new?about:blank`, { method: 'PUT' })).json();
    cdp = await CDP.attach(tab.webSocketDebuggerUrl);
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: EXPORT_DIR });

    // 收集页面控制台报错：界面在运行时炸了（如 §14 那类 null 引用）必须红，不能只当噪音。
    const consoleErrs = [];
    cdp.on((m) => {
      if (m.method === 'Runtime.exceptionThrown') {
        consoleErrs.push(m.params?.exceptionDetails?.exception?.description || m.params?.exceptionDetails?.text || 'exception');
      }
      if (m.method === 'Runtime.consoleAPICalled' && m.params?.type === 'error') {
        consoleErrs.push((m.params.args || []).map((a) => a.value ?? a.description ?? '').join(' '));
      }
    });

    // ── 登录：走真实登录表单，不预置 sessionStorage ──────────────────
    await cdp.send('Page.navigate', { url: GW + '/admin/legacy/' });
    await waitFor(cdp, `${visible('login')}`, 8000, '登录页渲染出来');
    await cdp.eval(setVal('login-base', GW));
    await cdp.eval(setVal('login-token', ADMIN));
    await cdp.eval(click('login-btn'));
    if (!await waitFor(cdp, `${visible('admin')}`, 10000, '登录后进入管理视图')) {
      fail('登录失败（管理视图一直没出现）');
      console.log(`RESULT ${PASS} ${FAIL}`); process.exit(1);
    }
    pass('登录表单登入管理台');
    await waitFor(cdp, `(${text('rp-hint')}).trim()!==''`, 8000, '回放面板渲染出 hint');

    // 面板初值（供「非法值不改动」那条对照）
    const before = (await api('/v1/_admin/replay')).json || {};
    const beforePM = before.sample_permille;

    // ── 1. 保存开关（合法值）───────────────────────────────────────
    console.log('\n=== 1. 保存开关 ===');
    await cdp.eval(setChecked('rp-enabled', true));
    await cdp.eval(setVal('rp-permille', '500'));
    await cdp.eval(setVal('rp-capacity', '50'));
    await cdp.eval(click('rp-save'));
    const savedOk = await waitFor(cdp, `(${text('rp-hint')}).includes('500‰') && (${text('rp-hint')}).includes('50 条')`, 8000, '保存后 hint 回显 500‰ / 50 条');
    const afterSave = (await api('/v1/_admin/replay')).json || {};
    chk('服务端 sample_permille 落成 500', afterSave.sample_permille, 500);
    chk('服务端 capacity 落成 50', afterSave.capacity, 50);
    chk('服务端 enabled 落成 true', afterSave.enabled, true);
    chk('客户端 #rp-err 保持隐藏', await cdp.eval(hidden('rp-err')), true);
    if (savedOk) pass('界面回显与服务端一致');

    // ── 2. 非法值拒绝（客户端格式门）────────────────────────────────
    console.log('\n=== 2. 非法值拒绝 ===');
    await cdp.eval(setVal('rp-permille', 'abc'));
    await cdp.eval(click('rp-save'));
    const badShown = await waitFor(cdp, `!(${hidden('rp-err')}) && (${text('rp-err')}).includes('不是整数')`, 5000, '#rp-err 报「不是整数」');
    if (badShown) pass('非整数被界面当场说破，没有静默吞掉');
    const afterBad = (await api('/v1/_admin/replay')).json || {};
    chk('服务端 sample_permille 未被子虚乌有的提交改动', afterBad.sample_permille, 500);
    chk('服务端没因这一下多出坏值（仍等于保存后的 500，而非初值 ' + beforePM + '）', afterBad.sample_permille, 500);

    // ── 3. 导出逐字节对账（面板下载 == CLI 产物）────────────────────
    console.log('\n=== 3. 导出逐字节对账 ===');
    await cdp.eval(setVal('rp-permille', '500')); // 还原一个干净值，避免残留 abc
    await cdp.eval(setVal('rp-export-scope', EXPORT_SCOPE));
    await cdp.eval(click('rp-export'));
    const dlFile = join(EXPORT_DIR, 'llmproxy-replay-records.json');
    let got = false;
    for (let i = 0; i < 100; i++) { if (existsSync(dlFile)) { got = true; break; } await sleep(100); }
    if (!got) {
      // 有些 Chrome 给下载文件加序号/guid；退一步找目录里最新的 .json
      const js = readdirSync(EXPORT_DIR).filter((f) => f.endsWith('.json'));
      if (js.length) { fail(`导出文件没落成期望名，目录里有：${js.join(', ')}`); }
      else fail('点导出后下载目录里没有任何文件');
    } else {
      const bytes = readFileSync(dlFile);
      const sha = createHash('sha256').update(bytes).digest('hex');
      pass(`浏览器导出落了 ${bytes.length} 字节`);
      chk('浏览器导出的 sha256 == CLI 产物 sha256', sha, EXPECT_SHA);
      // 记录文件里的键是 routing（单数，见 internal/replay/codec.go），状态接口才用 routings。
      // 读混了不会报错，只会安静地给 0 —— 所以这里要求「选路 ≥1」，不许 0 冒充正常。
      try {
        const f = JSON.parse(bytes.toString('utf8'));
        const nd = (f.decisions || []).length, nr = (f.routing || []).length;
        if (nd >= 1) pass(`导出文件里 ${nd} 条判定`); else fail('导出文件里判定为 0 条 —— 窗口本应有记录');
        if (nr >= 1) pass(`导出文件里 ${nr} 条选路（routing 键读对了）`);
        else fail('导出文件里选路为 0 条：要么请求没走通，要么正好踩中「读成 routings 恒为 0」那类键名 bug');
      } catch (e) {
        fail('导出文件解析不了：' + e.message);
      }
      const expHint = await cdp.eval(text('rp-exp-hint'));
      if (/\d+ 条判定 \/ \d+ 条选路，\d+ 字节/.test(expHint)) pass('面板回报的条数/字节格式正确（读的是 routing 键）');
      else fail('面板未回报条数/字节：' + expHint);
    }

    // ── 4. 清空窗口 ────────────────────────────────────────────────
    console.log('\n=== 4. 清空窗口 ===');
    const preClear = (await api('/v1/_admin/replay')).json || {};
    await cdp.eval(click('rp-clear'));
    const cleared = await waitFor(cdp, `(${text('rp-hint')}).includes('未采集') || (${text('rp-status')}).length>0`, 8000, '清空后有状态/回显更新');
    await sleep(300);
    const postClear = (await api('/v1/_admin/replay')).json || {};
    chk('服务端 captured 归零', postClear.captured, 0);
    chk('服务端 decisions 归零', postClear.decisions, 0);
    if (cleared && (preClear.captured || 0) >= 1) pass(`清空前窗口里确有记录（captured=${preClear.captured}），清空真的清掉了`);

    // ── 5. 模式联动（enforce → legacy 面板要顶出警告）────────────────
    console.log('\n=== 5. 模式联动 ===');
    await api('/v1/_admin/policy/mode', 'POST', { mode: 'legacy' });
    await cdp.eval(click('rp-refresh'));
    const warned = await waitFor(cdp,
      `!(${hidden('rp-status')}) && (${text('rp-status')}).length>0 && (${text('rp-hint')}).includes('没在跑')`,
      8000, 'legacy 下面板顶出警告 + hint 标注 3.0 没在跑');
    if (warned) pass('非 enforce 下「窗口恒空」被顶到最上面，没有被误读成「开关开着在收」');
    // 还原回 enforce，别把夹具自己留下的状态带出边界
    await api('/v1/_admin/policy/mode', 'POST', { mode: 'enforce', data_level: 'public' });

    // ── 页面控制台不能有运行时炸裂 ────────────────────────────────
    console.log('\n=== 6. 页面无运行时异常 ===');
    if (consoleErrs.length === 0) pass('整个夹具跑完，页面控制台没有未捕获异常 / console.error');
    else fail('页面控制台出现运行时错误：\n       ' + consoleErrs.slice(0, 5).join('\n       '));
  } finally {
    try { if (cdp) await cdp.send('Browser.close'); } catch {}
    try { chrome.kill('SIGKILL'); } catch {}
  }

  console.log(`\nRESULT ${PASS} ${FAIL}`);
  process.exit(FAIL > 0 ? 1 : 0);
}

main().catch((e) => {
  console.log('  [NG] 夹具自身异常：' + (e && e.stack || e));
  console.log(`RESULT ${PASS} ${FAIL}`);
  process.exit(1);
});
