/**
 * 模板管理路由
 * GET    /api/templates         — 列出所有模板
 * POST   /api/templates         — 创建模板
 * GET    /api/templates/:id     — 获取模板详情
 * GET    /api/templates/:id/content — 返回模板 YAML 原文
 * PUT    /api/templates/:id     — 更新模板
 * DELETE /api/templates/:id     — 删除模板
 */

'use strict';

const { apiResponse } = require('../utils');
const {
  getTemplates,
  getTemplateById,
  createTemplate,
  updateTemplate,
  deleteTemplate,
} = require('../db');

/**
 * GET /api/templates — 列出所有模板（不含 content）
 */
function handleList(req, res) {
  const list = getTemplates();
  return apiResponse(res, 200, list);
}

/**
 * POST /api/templates — 创建模板
 */
function handleCreate(req, res, json) {
  if (!json.name || !json.content) {
    return apiResponse(res, 400, { error: '缺少 name 或 content 字段' });
  }
  try {
    const tpl = createTemplate({
      name: json.name,
      description: json.description || '',
      content: json.content,
    });
    return apiResponse(res, 201, tpl);
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      return apiResponse(res, 409, { error: '模板名已存在' });
    }
    return apiResponse(res, 400, { error: e.message });
  }
}

/**
 * GET /api/templates/:id — 获取模板（含 content）
 */
function handleGet(req, res, id) {
  const tpl = getTemplateById(id);
  if (!tpl) {
    return apiResponse(res, 404, { error: '模板不存在' });
  }
  return apiResponse(res, 200, tpl);
}

/**
 * GET /api/templates/:id/content — 返回模板 YAML 原文
 */
function handleContent(req, res, id) {
  const tpl = getTemplateById(id);
  if (!tpl) {
    return apiResponse(res, 404, { error: '模板不存在' });
  }
  res.writeHead(200, {
    'Content-Type': 'text/yaml; charset=utf-8',
    'Content-Disposition': 'inline',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(tpl.content);
}

/**
 * PUT /api/templates/:id — 更新模板
 */
function handleUpdate(req, res, id, json) {
  const tpl = getTemplateById(id);
  if (!tpl) {
    return apiResponse(res, 404, { error: '模板不存在' });
  }
  try {
    const updated = updateTemplate(id, {
      name: json.name,
      description: json.description,
      content: json.content,
      enabled: json.enabled,
    });
    return apiResponse(res, 200, updated);
  } catch (e) {
    if (e.message.includes('UNIQUE')) {
      return apiResponse(res, 409, { error: '模板名已存在' });
    }
    return apiResponse(res, 400, { error: e.message });
  }
}

/**
 * DELETE /api/templates/:id — 删除模板
 */
function handleDelete(req, res, id) {
  const tpl = getTemplateById(id);
  if (!tpl) {
    return apiResponse(res, 404, { error: '模板不存在' });
  }
  deleteTemplate(id);
  return apiResponse(res, 200, { ok: true });
}

module.exports = {
  handleList,
  handleCreate,
  handleGet,
  handleContent,
  handleUpdate,
  handleDelete,
};
