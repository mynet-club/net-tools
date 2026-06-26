/**
 * 工具函数
 */

'use strict';

// 请求体最大大小（1MB），防止内存耗尽 DoS
const MAX_BODY_SIZE = 1024 * 1024;

/**
 * 发送 JSON 响应（含安全响应头）
 */
function apiResponse(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(JSON.stringify(data));
}

/**
 * 清洗用户名：去除所有空白字符
 * 用户名不允许包含空格、制表符等空白字符
 * @param {string} raw — 原始用户名
 * @returns {string} 清洗后的用户名
 */
function sanitizeUsername(raw) {
  if (typeof raw !== 'string') return '';
  return raw.replace(/\s+/g, '');
}

/**
 * 解析请求体（带大小限制）
 */
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let tooLarge = false;
    req.on('data', chunk => {
      body += chunk;
      if (body.length > MAX_BODY_SIZE) {
        tooLarge = true;
        req.destroy();
      }
    });
    req.on('end', () => {
      if (tooLarge) return reject(new Error('BODY_TOO_LARGE'));
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error('JSON 解析失败'));
      }
    });
    req.on('error', reject);
  });
}

module.exports = {
  apiResponse,
  parseBody,
  sanitizeUsername,
  MAX_BODY_SIZE,
};
