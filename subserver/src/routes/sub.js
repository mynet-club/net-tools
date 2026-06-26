/**
 * 订阅接口路由
 * GET /sub/:token                  — 订阅模式，返回 mihomo proxies YAML
 * GET /sub/:token/:template/full   — 导出模式，返回完整 Clash.Meta 配置 YAML
 * GET /health                      — 健康检查
 */

'use strict';

const { apiResponse } = require('../utils');
const { getSubscriptionData, getUserByToken, getTemplateByName } = require('../db');
const { generateProxiesYaml, generateFullConfigYaml } = require('../yaml-gen');

/**
 * GET /sub/:token 或 /sub/:token/:template/full
 */
function handleSub(req, res, pathname) {
  // 解析路径段: /sub/:token 或 /sub/:token/:template/full
  const parts = pathname.replace(/^\/sub\//, '').split('/');
  const token = parts[0];

  if (!token) {
    return apiResponse(res, 400, { error: '缺少 token' });
  }

  // 验证用户
  const user = getUserByToken(token);
  if (!user) {
    return apiResponse(res, 404, { error: 'token 无效' });
  }
  if (!user.enabled) {
    return apiResponse(res, 403, { error: '用户已禁用' });
  }

  // 获取订阅数据（仅返回用户已建立 UUID 映射的节点）
  const nodes = getSubscriptionData(token);

  // 判断模式：订阅模式 vs 导出模式
  const isExportMode = parts.length === 3 && parts[2] === 'full';

  let yaml;
  try {
    if (isExportMode) {
      // 导出模式: /sub/:token/:template/full
      const templateName = parts[1];
      const template = getTemplateByName(templateName);
      if (!template) {
        return apiResponse(res, 404, { error: `模板 "${templateName}" 不存在` });
      }
      if (!template.enabled) {
        return apiResponse(res, 403, { error: `模板 "${templateName}" 已禁用` });
      }
      yaml = generateFullConfigYaml(nodes, template.content);
    } else {
      // 订阅模式: /sub/:token
      yaml = generateProxiesYaml(nodes);
    }
  } catch (e) {
    console.error(`[yaml] 生成失败: ${e.message}`);
    return apiResponse(res, 500, { error: '订阅生成失败' });
  }

  res.writeHead(200, {
    'Content-Type': 'text/yaml; charset=utf-8',
    'Content-Disposition': 'inline',
    'Cache-Control': 'no-cache',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(yaml);
}

/**
 * GET /health
 */
function handleHealth(req, res) {
  return apiResponse(res, 200, { status: 'ok' });
}

module.exports = {
  handleSub,
  handleHealth,
};
