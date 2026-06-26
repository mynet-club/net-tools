/**
 * 用户自助路由
 * GET /api/me/subscription  — 获取自己的订阅信息 + 可用模板列表
 * GET /api/me/mappings      — 获取自己的节点映射列表（只读）
 */

'use strict';

const { apiResponse } = require('../utils');
const { getSessionUser } = require('../auth');
const {
  getUserById,
  getMappings,
  getTemplates,
  getSubscriptionData,
} = require('../db');

/**
 * GET /api/me/subscription
 * 返回当前用户的订阅地址、可用模板及各模板的完整配置导出地址
 */
function handleSubscription(req, res) {
  const sessionUser = getSessionUser(req);
  if (!sessionUser) {
    return apiResponse(res, 401, { error: '未认证' });
  }

  const user = getUserById(sessionUser.id);
  if (!user) {
    return apiResponse(res, 404, { error: '用户不存在' });
  }
  if (!user.enabled) {
    return apiResponse(res, 403, { error: '用户已禁用' });
  }

  // 获取可用模板
  const templates = getTemplates();
  const subUrl = `/sub/${user.token}`;

  // 构建各模板的完整配置导出地址
  const exportUrls = {};
  for (const tpl of templates) {
    if (tpl.enabled) {
      exportUrls[tpl.name] = `/sub/${user.token}/${tpl.name}/full`;
    }
  }

  // 获取已分配的节点数据
  const nodes = getSubscriptionData(user.token);

  return apiResponse(res, 200, {
    token: user.token,
    subscriptionUrl: subUrl,
    templates: templates.filter(t => t.enabled).map(t => ({
      id: t.id,
      name: t.name,
      description: t.description,
    })),
    exportUrls,
    nodeCount: nodes.length,
    nodes: nodes.map(n => ({
      name: n.name,
      display_name: n.display_name,
      type: n.type,
      server: n.server,
      port: n.port,
    })),
  });
}

/**
 * GET /api/me/mappings
 * 返回当前用户的节点映射列表（只读）
 */
function handleMappings(req, res) {
  const sessionUser = getSessionUser(req);
  if (!sessionUser) {
    return apiResponse(res, 401, { error: '未认证' });
  }

  const user = getUserById(sessionUser.id);
  if (!user) {
    return apiResponse(res, 404, { error: '用户不存在' });
  }

  const mappings = getMappings(sessionUser.id);
  return apiResponse(res, 200, mappings);
}

module.exports = {
  handleSubscription,
  handleMappings,
};
