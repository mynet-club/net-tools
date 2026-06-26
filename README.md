# net-tools

macOS / Linux / FreeBSD / Alpine / OpenWrt 网络工具集合，每个子目录为一个独立的网络工具。

## 工具列表

| 目录 | 描述 | 技术栈 |
|------|------|--------|
| [mihomo](./mihomo/) | Mihomo (Clash Meta) 代理管理 CLI 工具 | Node.js |
| [smartxray](./smartxray/) | Xray 服务端管理（SQLite 用户库 + 动态配置 + 防火墙 + Web UI） | Node.js |
| [subserver](./subserver/) | 订阅分发服务（节点集中管理 + 按用户动态生成 mihomo 订阅 YAML） | Node.js |
| [toolstpl](./toolstpl/) | 跨平台网络工具脚手架模板（平台适配器模式 + 安装框架） | Node.js |

## 根目录结构

```
net-tools/
  node/           Node.js 公共目录（各平台安装说明、版本要求）
  <工具名>/       各工具独立目录
    src/          源码
    scripts/      安装脚本 / platform/ 平台启动脚本
    config/       示例配置模板（不含敏感信息）
    data/         运行时数据目录（GeoIP 等）
    logs/         日志目录
    README.md     工具说明文档
```

## Node.js 工具前置要求

使用 Node.js 工具前，请先阅读 [node/README.md](./node/README.md) 了解如何在各平台安装 Node.js。

## 添加新工具

1. 在根目录创建以工具名命名的子目录
2. 按照上述结构规范组织文件
3. 在子目录下创建 `README.md`（Node.js 工具指向 [node/README.md](./node/README.md)）
4. 更新本文件的工具列表

