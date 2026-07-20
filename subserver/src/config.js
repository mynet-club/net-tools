/**
 * 配置加载模块（独立，无循环依赖）
 * 优先级: 环境变量 > ~/.config/subserver/config.json (运行时) > config/local.json > config/default.json
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { getBaseDir } = require('./paths');

function loadConfig() {
    const baseDir = getBaseDir();
    const runtimeCfg = path.join(baseDir, 'config.json');          // 运行时配置（install.js 生成）
    const devDir = path.join(__dirname, '..', 'config');
    const defaultPath = path.join(devDir, 'default.json');
    const localPath = path.join(devDir, 'local.json');

    let cfg = {};
    // 1. 开发模式默认配置
    try {
        if (fs.existsSync(defaultPath)) {
            cfg = { ...cfg, ...JSON.parse(fs.readFileSync(defaultPath, 'utf8')) };
        }
    } catch (e) {
        console.error(`[config] 读取 default.json 失败: ${e.message}`);
    }
    // 2. 开发模式本地覆盖
    try {
        if (fs.existsSync(localPath)) {
            cfg = { ...cfg, ...JSON.parse(fs.readFileSync(localPath, 'utf8')) };
        }
    } catch (e) {
        console.error(`[config] 读取 local.json 失败: ${e.message}`);
    }
    // 3. 运行时配置（bundle 模式或 install.js 生成）
    try {
        if (fs.existsSync(runtimeCfg)) {
            cfg = { ...cfg, ...JSON.parse(fs.readFileSync(runtimeCfg, 'utf8')) };
        }
    } catch (e) {
        console.error(`[config] 读取运行时配置失败: ${e.message}`);
    }

    // 环境变量覆盖
    if (process.env.SUBSERVER_PORT) cfg.port = parseInt(process.env.SUBSERVER_PORT);
    if (process.env.SUBSERVER_HOST) cfg.host = process.env.SUBSERVER_HOST;
    if (process.env.SUBSERVER_ADMIN_TOKEN) cfg.adminToken = process.env.SUBSERVER_ADMIN_TOKEN;
    if (process.env.SUBSERVER_BASE_URL) cfg.baseUrl = process.env.SUBSERVER_BASE_URL;
    if (process.env.SUBSERVER_SMTP_HOST) {
        cfg.smtp = cfg.smtp || {};
        cfg.smtp.host = process.env.SUBSERVER_SMTP_HOST;
    }
    if (process.env.SUBSERVER_SMTP_PORT) {
        cfg.smtp = cfg.smtp || {};
        cfg.smtp.port = parseInt(process.env.SUBSERVER_SMTP_PORT);
    }
    if (process.env.SUBSERVER_SMTP_USER) {
        cfg.smtp = cfg.smtp || {};
        cfg.smtp.auth = cfg.smtp.auth || {};
        cfg.smtp.auth.user = process.env.SUBSERVER_SMTP_USER;
    }
    if (process.env.SUBSERVER_SMTP_PASS) {
        cfg.smtp = cfg.smtp || {};
        cfg.smtp.auth = cfg.smtp.auth || {};
        cfg.smtp.auth.pass = process.env.SUBSERVER_SMTP_PASS;
    }
    if (process.env.SUBSERVER_SMTP_FROM) {
        cfg.smtp = cfg.smtp || {};
        cfg.smtp.fromEmail = process.env.SUBSERVER_SMTP_FROM;
    }

    // 数据库配置
    cfg.db = cfg.db || {};
    if (process.env.SUBSERVER_DB_HOST) cfg.db.host = process.env.SUBSERVER_DB_HOST;
    if (process.env.SUBSERVER_DB_PORT) cfg.db.port = parseInt(process.env.SUBSERVER_DB_PORT);
    if (process.env.SUBSERVER_DB_USER) cfg.db.user = process.env.SUBSERVER_DB_USER;
    if (process.env.SUBSERVER_DB_PASS) cfg.db.password = process.env.SUBSERVER_DB_PASS;
    if (process.env.SUBSERVER_DB_NAME) cfg.db.database = process.env.SUBSERVER_DB_NAME;

    // 默认值
    cfg.port = cfg.port || 3456;
    cfg.host = cfg.host || '127.0.0.1';
    cfg.adminToken = cfg.adminToken || '';
    cfg.baseUrl = cfg.baseUrl || '';
    cfg.smtp = cfg.smtp || {};
    cfg.db = {
        host: '127.0.0.1',
        port: 3306,
        user: 'root',
        password: '',
        database: 'subserver',
        ...cfg.db,
    };

    return cfg;
}

const config = loadConfig();

module.exports = { config, loadConfig };
