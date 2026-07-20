/**
 * Xray 配置生成模块
 * 根据数据库中的用户、Reality、LAN 入站等信息生成完整的 Xray config.json
 */

const fs   = require('fs');
const path = require('path');

const { getSetting } = require('./database');
const { XRAY_CONF, LOG_FILE, MIHOMO_OUT, getServerHost } = require('./config');
const { getRealityConfig } = require('./reality');

const { db } = require('./database');

// ==================== Mihomo Proxies YAML 生成 ====================

/**
 * YAML 字符串转义
 * 包含特殊字符的值需要用双引号包裹
 */
function yamlStr(val) {
  if (val === null || val === undefined) return '""';
  const s = String(val);
  if (s.includes('\n') || s.includes('\r') || s.includes('---')) {
    throw new Error(`YAML 值包含非法字符: ${s.slice(0, 20)}...`);
  }
  if (/[:#\[\]{}&*!|>'"%@`,\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '\\"')}"`;
  }
  return s;
}

/**
 * 生成 mihomo proxies YAML 并写入 MIHOMO_OUT 文件
 * 为每个启用且有 UUID 的 VLESS+Reality 用户生成一个 proxy 条目
 */
function generateMihomoProxies() {
  const reality = getRealityConfig();
  if (!reality.enabled || !reality.publicKey) {
    try { fs.writeFileSync(MIHOMO_OUT, '# Reality 未启用，无可用 proxies\n'); } catch (e) { console.error(`[config] 写入 mihomo-proxies.yaml 失败: ${e.message}`); }
    return;
  }

  const users = db().prepare('SELECT * FROM users WHERE enabled=1 AND uuid IS NOT NULL ORDER BY port').all();
  if (!users.length) {
    try { fs.writeFileSync(MIHOMO_OUT, '# 无启用用户\n'); } catch (e) { console.error(`[config] 写入 mihomo-proxies.yaml 失败: ${e.message}`); }
    return;
  }

  const serverHost = getServerHost(getSetting);
  const sni = reality.serverNames[0] || '';
  const pubkey = reality.publicKey;
  const shortId = reality.shortIds[0] || '';
  const port = reality.port;

  const entries = users.map(u => {
    const lines = [
      `  - name: ${yamlStr(u.name)}`,
      `    type: vless`,
      `    server: ${yamlStr(serverHost)}`,
      `    port: ${port}`,
      `    uuid: ${yamlStr(u.uuid)}`,
      `    network: tcp`,
      `    tls: true`,
      `    udp: true`,
      `    flow: xtls-rprx-vision`,
      `    servername: ${yamlStr(sni)}`,
      `    reality-opts:`,
      `      public-key: ${yamlStr(pubkey)}`,
      `      short-id: ${yamlStr(shortId)}`,
      `    client-fingerprint: chrome`,
    ];
    return lines.join('\n');
  });

  const yaml = `proxies:\n${entries.join('\n')}\n`;
  try {
    fs.writeFileSync(MIHOMO_OUT, yaml);
  } catch (e) {
    console.error(`[config] 生成 mihomo-proxies.yaml 失败: ${e.message}`);
  }
}

/**
 * 构建完整的 Xray 配置并写入文件
 * @returns {Object} 生成的配置对象
 */
function buildConfig() {
  const users    = db().prepare('SELECT * FROM users WHERE enabled=1 ORDER BY port').all();
  const reality  = getRealityConfig();
  const listen   = '0.0.0.0';
  const inbounds = [];

  // ── VLESS + XTLS-Reality 共享入站 ──
  if (reality.enabled && reality.privateKey) {
    const vlessClients = users.filter(u => u.uuid).map(u => ({
      id:   u.uuid,
      flow: 'xtls-rprx-vision',
      level: 0,  // 启用 per-user stats
    }));
    if (vlessClients.length) {
      inbounds.push({
        tag:      'vless-reality',
        port:     reality.port,
        listen,
        protocol: 'vless',
        settings: { clients: vlessClients, decryption: 'none' },
        streamSettings: {
          network:  'tcp',
          security: 'reality',
          realitySettings: {
            show:        false,
            dest:        reality.dest,
            xver:        0,
            serverNames: reality.serverNames,
            privateKey:  reality.privateKey,
            shortIds:    reality.shortIds.length ? reality.shortIds : [''],
          },
        },
        sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: false },
      });
    }
  }

  // ── 共享端口模式 ──
  const sharedSocksPort = parseInt(getSetting('shared_socks_port', '0')) || 0;
  const sharedHttpPort  = parseInt(getSetting('shared_http_port', '0'))  || 0;

  if (sharedSocksPort && users.length) {
    const accounts = users.map(u => ({ user: u.username, pass: u.password }));
    inbounds.push({
      tag:      'shared-socks',
      port:     sharedSocksPort,
      listen,
      protocol: 'socks',
      settings: { auth: 'password', accounts, udp: true },
      sniffing: { enabled: true, destOverride: ['http', 'tls'] },
    });
  }
  if (sharedHttpPort && users.length) {
    const accounts = users.map(u => ({ user: u.username, pass: u.password }));
    inbounds.push({
      tag:      'shared-http',
      port:     sharedHttpPort,
      listen,
      protocol: 'http',
      settings: { accounts, allowTransparent: false },
    });
  }

  // ── 每用户独立 SOCKS5 + HTTP 入站（仅在未配置共享端口时创建）──
  if (!sharedSocksPort && !sharedHttpPort) {
    for (const u of users) {
      inbounds.push({
        tag:      u.tag || `user_${u.name}`,
        port:     u.port,
        listen,
        protocol: 'socks',
        settings: { auth: 'password', accounts: [{ user: u.username, pass: u.password }], udp: true },
        sniffing: { enabled: true, destOverride: ['http', 'tls'] },
      });
      if (u.http_port) {
        inbounds.push({
          tag:      (u.tag || `user_${u.name}`) + '-http',
          port:     u.http_port,
          listen,
          protocol: 'http',
          settings: { accounts: [{ user: u.username, pass: u.password }], allowTransparent: false },
        });
      }
    }
  }

  // ── 无认证 LAN 入站 ──
  const lanEntries = (() => {
    try {
      const parsed = JSON.parse(getSetting('lan_inbounds', '[]'));
      return Array.isArray(parsed) ? parsed : [];
    } catch { return []; }
  })();
  for (const b of lanEntries) inbounds.push(b);

  // ── xray API 入站（dokodemo-door，用于查询流量统计）──
  const apiPort = parseInt(getSetting('xray_api_port', '10085'));
  inbounds.push({
    tag: 'api',
    listen: '127.0.0.1',
    port: apiPort,
    protocol: 'dokodemo-door',
    settings: { address: '127.0.0.1' },
  });

  // ── 基础配置 ──
  const config = {
    log:    { loglevel: getSetting('log_level', 'warning'), access: LOG_FILE, error: LOG_FILE },
    stats:  {},
    api: {
      tag: 'api',
      services: ['StatsService'],
    },
    policy: {
      system: { statsInboundUplink: true, statsInboundDownlink: true },
      levels: { '0': { statsUserUplink: true, statsUserDownlink: true } },
    },
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: [
        { type: 'field', inboundTag: ['api'], outboundTag: 'api' },
        { type: 'field', ip: ['geoip:private'], outboundTag: 'direct' },
      ],
    },
    inbounds,
    outbounds: [
      { tag: 'direct', protocol: 'freedom',   settings: {} },
      { tag: 'block',  protocol: 'blackhole',  settings: {} },
    ],
  };

  // ── 上游出站注入 ──
  // upstream_outbounds 由 POST /api/upstream/sync 异步拉取后写入设置
  // buildConfig 同步读取已同步的 upstream_outbounds 设置并注入
  const upstreamJson = getSetting('upstream_outbounds', '');
  if (upstreamJson) {
    try {
      const upstreamOutbounds = JSON.parse(upstreamJson);
      if (Array.isArray(upstreamOutbounds) && upstreamOutbounds.length) {
        config.outbounds.push(...upstreamOutbounds);
        if (getSetting('use_upstream', '0') === '1') {
          config.routing.rules.push({
            type: 'field', network: 'tcp,udp',
            outboundTag: upstreamOutbounds[0].tag,
          });
        }
      }
    } catch { /* JSON 解析失败忽略 */ }
  }

  // ── merge_inbounds 模式：只替换 inbounds，保留现有 outbounds/routing ──
  const mergeMode = getSetting('merge_inbounds', '0') === '1' && fs.existsSync(XRAY_CONF);
  if (mergeMode) {
    let existing = {};
    try { existing = JSON.parse(fs.readFileSync(XRAY_CONF, 'utf8')); } catch {}

    // 仅当现有配置有实质内容时才做 merge（空 inbounds 不算）
    const hasRealContent = existing.outbounds?.length > 2 ||
                           existing.routing?.rules?.length > 1 ||
                           existing.balancers?.length > 0 ||
                           existing.routing?.balancers?.length > 0;
    if (hasRealContent) {
      const preservedRules = [];
      const catchAllRules  = [];
      for (const r of (existing.routing?.rules || [])) {
        if (!r.inboundTag) {
          preservedRules.push(r);
        } else if (r.balancerTag) {
          const { inboundTag, ...rest } = r;
          catchAllRules.push(rest);
        }
      }

      // merge 模式下：保留旧的 non-upstream outbounds，但用新的 upstream outbounds 替换旧的
      const existingNonUpstream = (existing.outbounds || []).filter(
        o => !o.tag?.startsWith('upstream-')
      );
      const newUpstream = config.outbounds.filter(
        o => o.tag?.startsWith('upstream-')
      );
      const mergedOutbounds = existingNonUpstream.length
        ? [...existingNonUpstream, ...newUpstream]
        : config.outbounds;

      const merged = {
        log:    { loglevel: getSetting('log_level', 'warning'), access: LOG_FILE, error: LOG_FILE },
        stats:  {},
        policy: {
          system: { statsInboundUplink: true, statsInboundDownlink: true },
          levels: { '0': { statsUserUplink: true, statsUserDownlink: true } },
        },
        routing: {
          domainStrategy: existing.routing?.domainStrategy || 'IPIfNonMatch',
          rules: [
            { type: 'field', inboundTag: ['api'], outboundTag: 'api' },
            ...preservedRules,
            ...catchAllRules,
          ],
        },
        inbounds,
        outbounds: mergedOutbounds,
      };
      if (existing.balancers?.length)             merged.balancers              = existing.balancers;
      if (existing.routing?.balancers?.length)    merged.routing.balancers      = existing.routing.balancers;
      if (existing.observatory)                   merged.observatory            = existing.observatory;
      if (existing.burstObservatory)              merged.burstObservatory       = existing.burstObservatory;
      if (existing.api)                           merged.api                    = existing.api;

      fs.mkdirSync(path.dirname(XRAY_CONF), { recursive: true });
      fs.writeFileSync(XRAY_CONF, JSON.stringify(merged, null, 2));
      generateMihomoProxies();
      return merged;
    }
  }

  fs.mkdirSync(path.dirname(XRAY_CONF), { recursive: true });
  fs.writeFileSync(XRAY_CONF, JSON.stringify(config, null, 2));
  generateMihomoProxies();
  return config;
}

module.exports = { buildConfig, generateMihomoProxies };
