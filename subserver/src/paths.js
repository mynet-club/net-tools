/**
 * 共享路径工具
 * 统一 bundle 模式与开发模式的路径检测逻辑
 */

'use strict';

const path = require('path');
const os   = require('os');

/**
 * 获取项目根目录
 * - bundle 模式：__dirname 为 /usr/local/lib/subserver，运行时目录为 ~/.config/subserver
 * - 开发模式：__dirname 为 src/，项目根目录为上一级
 * @returns {string} 项目根目录路径
 */
function getBaseDir() {
  const dir = __dirname;
  // bundle 模式：__dirname 指向 /usr/local/lib/subserver 或 Windows AppData
  if (dir.includes('/usr/local/lib/') || dir.includes('\\AppData\\')) {
    return path.join(os.homedir(), '.config', 'subserver');
  }
  // 开发模式：向上一级到项目根目录（src/ → subserver/）
  return path.join(dir, '..');
}

module.exports = {
  getBaseDir,
};
