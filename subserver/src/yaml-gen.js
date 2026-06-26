/**
 * YAML 生成模块
 * 将节点数据序列化为 mihomo proxies YAML 格式
 */

'use strict';

/**
 * YAML 字符串转义
 * 包含特殊字符的值需要用双引号包裹
 * 拒绝含换行符的值（防止 YAML 注入）
 */
function yamlStr(val) {
  if (val === null || val === undefined) return '""';
  const s = String(val);
  // 拒绝换行符和 YAML 文档分隔符，防止注入
  if (s.includes('\n') || s.includes('\r') || s.includes('---')) {
    throw new Error(`YAML 值包含非法字符: ${s.slice(0, 20)}...`);
  }
  // 含有特殊字符时用双引号包裹并转义内部双引号
  if (/[:#\[\]{}&*!|>'"%@`,\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '\\"')}"`;
  }
  return s;
}

/**
 * 生成 VLESS-Reality proxy 条目
 */
function genVlessReality(node, uuid) {
  const lines = [
    `  - name: ${yamlStr(node.display_name)}`,
    `    type: vless`,
    `    server: ${yamlStr(node.server)}`,
    `    port: ${node.port}`,
    `    uuid: ${yamlStr(uuid)}`,
    `    network: tcp`,
    `    tls: true`,
    `    udp: true`,
    `    flow: ${yamlStr(node.flow || 'xtls-rprx-vision')}`,
    `    servername: ${yamlStr(node.sni || '')}`,
    `    reality-opts:`,
    `      public-key: ${yamlStr(node.pubkey || '')}`,
    `      short-id: ${yamlStr(node.shortid || '')}`,
    `    client-fingerprint: ${yamlStr(node.fingerprint || 'chrome')}`,
  ];
  return lines.join('\n');
}

/**
 * 生成 VMess proxy 条目
 */
function genVmess(node, uuid) {
  const lines = [
    `  - name: ${yamlStr(node.display_name)}`,
    `    type: vmess`,
    `    server: ${yamlStr(node.server)}`,
    `    port: ${node.port}`,
    `    uuid: ${yamlStr(uuid)}`,
    `    alterId: ${node.alter_id || 0}`,
    `    cipher: ${yamlStr(node.cipher || 'auto')}`,
    `    udp: true`,
    `    network: ${yamlStr(node.network || 'tcp')}`,
  ];

  // WebSocket 选项
  if (node.network === 'ws') {
    lines.push(`    ws-opts:`);
    lines.push(`      path: ${yamlStr(node.ws_path || '/')}`);
    if (node.ws_host) {
      lines.push(`      headers:`);
      lines.push(`        Host: ${yamlStr(node.ws_host)}`);
    }
  }

  // TLS 选项
  if (node.tls) {
    lines.push(`    tls: true`);
    if (node.tls_sni) lines.push(`    servername: ${yamlStr(node.tls_sni)}`);
    if (node.skip_cert) lines.push(`    skip-cert-verify: true`);
  }

  return lines.join('\n');
}

/**
 * 根据节点类型生成对应的 proxy 条目
 */
function genProxyEntry(node, uuid) {
  switch (node.type) {
    case 'vless-reality':
      return genVlessReality(node, uuid);
    case 'vmess':
      return genVmess(node, uuid);
    default:
      return `  - name: ${yamlStr(node.display_name)}\n    type: ${yamlStr(node.type)}`;
  }
}

/**
 * 生成完整的 proxies YAML
 * @param {Array} nodes — 节点数组（含 uuid 字段）
 * @returns {string} YAML 字符串
 */
function generateProxiesYaml(nodes) {
  if (!nodes || nodes.length === 0) {
    return 'proxies: []\n';
  }

  const entries = nodes.map(n => genProxyEntry(n, n.uuid));
  return `proxies:\n${entries.join('\n')}\n`;
}

/**
 * 生成完整 Clash.Meta 配置 YAML（导出模式）
 * 将节点数据填充到模板的占位符中
 * @param {Array} nodes — 节点数组（含 uuid 字段）
 * @param {string} templateContent — 模板 YAML 内容（含占位符）
 * @returns {string} 完整 YAML 字符串
 */
function generateFullConfigYaml(nodes, templateContent) {
  // 1. 生成 proxies 段
  const proxiesYaml = generateProxiesYaml(nodes);

  // 2. 生成节点名列表
  const names = (nodes || []).map(n => yamlStr(n.display_name));

  // {{PROXY_NAMES}} — 逗号分隔（用于 url-test 组的 proxies: [a, b, c]）
  const proxyNames = names.join(', ');

  // {{PROXY_NAMES_INLINE}} — 换行 + 缩进的 - "名" 列表（用于 select 组）
  const proxyNamesInline = names.map(n => `      - ${n}`).join('\n');

  // 3. 替换模板中的占位符
  let result = templateContent;
  result = result.replace(/\{\{PROXIES\}\}/g, proxiesYaml.trimEnd());
  result = result.replace(/\{\{PROXY_NAMES\}\}/g, proxyNames);
  result = result.replace(/\{\{PROXY_NAMES_INLINE\}\}/g, proxyNamesInline);

  return result + '\n';
}

module.exports = {
  generateProxiesYaml,
  generateFullConfigYaml,
  genProxyEntry,
};
