# subserver

订阅分发服务 — 集中管理代理节点信息，按用户 token 动态生成 mihomo proxies YAML 订阅配置。

## 功能特性

- **节点集中管理**：统一维护所有上游代理节点（VLESS-Reality / VMess），管理员更新后客户端自动拉取最新配置
- **管理界面**：内置 Web UI，支持节点/用户/映射的可视化管理
- **按用户分发**：每个用户拥有独立 token，各节点有独立 UUID，订阅时动态组装
- **mihomo proxy-providers 兼容**：输出标准 `proxies:` YAML，可直接作为 mihomo `proxy-providers` 数据源
- **Admin API**：完整的用户/节点/映射 CRUD 接口，支持批量用户创建
- **安全设计**：时序安全的 token 认证、请求体大小限制、YAML 注入防护、路径穿越防护
- **零运行时依赖**：bundle 模式部署，无需 `npm install`

## 目录结构

```
subserver/
├── src/
│   ├── server.js          # HTTP 入口 + 路由分发 + 静态文件
│   ├── db.js              # SQLite 初始化 + schema + CRUD
│   ├── yaml-gen.js        # 节点 → mihomo proxy YAML 序列化
│   ├── auth.js            # 配置加载 + Bearer token 认证
│   ├── paths.js           # 共享路径检测（bundle/开发模式）
│   ├── utils.js           # 工具函数（apiResponse, parseBody）
│   └── routes/
│       ├── sub.js         # GET /sub/:token — 订阅接口
│       ├── users.js       # /api/users CRUD + 批量创建
│       ├── nodes.js       # /api/nodes CRUD
│       └── mappings.js    # /api/mappings CRUD + 批量
├── ui/
│   └── index.html         # 管理界面（单页应用）
├── scripts/
│   ├── install.js         # 安装脚本（bundle 模式，无需 npm）
│   ├── release.js         # 打包发布脚本（ncc + 混淆）
│   ├── seed.js            # 初始数据导入（占位符）
│   └── platform/
│       └── linux/
│           └── subserver.service  # systemd 服务文件
├── config/
│   └── default.json       # 配置模板（端口、adminToken、DB路径）
├── data/                  # 运行时数据（.gitkeep）
├── logs/                  # 日志（.gitkeep）
├── LICENSE                # MIT
└── package.json
```

运行时数据目录：`~/.config/subserver/`

## 前置要求

- **Node.js ≥ v18** → 参见 [node/README.md](../node/README.md)
- **Linux**（服务端部署，systemd 管理）

## 安装

### 方式一：从 GitHub Release 安装（推荐）

```bash
# 下载 installer 包
VER=1.0.0
curl -LO https://github.com/your-org/net-tools/releases/download/subserver-v${VER}/subserver-installer-${VER}.tar.gz
tar xzf subserver-installer-${VER}.tar.gz
cd subserver-installer-${VER}
node scripts/install.js
```

### 方式二：从本地仓库安装

```bash
cd subserver
# 先构建 bundle
npm install
node scripts/release.js

# 安装
node scripts/install.js
```

安装脚本完成以下操作：
1. 检查 Node.js 版本（≥ v18）
2. 安装预构建 bundle 到 `/usr/local/lib/subserver/`
3. 创建 shim 脚本 `/usr/local/bin/subserver`
4. 创建运行时目录 `~/.config/subserver/{data,logs}`
5. 生成配置文件 `~/.config/subserver/config.json`（含随机 adminToken）
6. 安装 systemd 服务（默认禁用自启）

## 用法

### 启动服务

```bash
sudo systemctl start subserver    # 启动
sudo systemctl enable subserver   # 开机自启
sudo systemctl status subserver   # 查看状态
```

或直接运行：

```bash
subserver    # 前台运行
```

### 初始数据导入

```bash
cd /usr/local/lib/subserver
node scripts/seed.js              # 导入示例节点 + 创建 admin 用户
node scripts/seed.js --clear      # 清空后重新导入
```

> seed.js 中的节点数据全部为 `__PLACEHOLDER__` 占位符，需替换为实际节点信息。

### 订阅接口（公开）

```bash
# 健康检查
curl http://127.0.0.1:3456/health
# → {"status":"ok"}

# 获取订阅（返回 mihomo proxies YAML）
curl http://127.0.0.1:3456/sub/<token>
# → proxies:
#     - name: SG-1
#       type: vless
#       ...
```

### Admin API（Bearer token 认证）

```bash
TOKEN="<adminToken>"  # 从 config.json 读取
AUTH="Authorization: Bearer $TOKEN"

# 用户管理
curl -H "$AUTH" http://127.0.0.1:3456/api/users                    # 列出用户
curl -X POST -H "$AUTH" -H 'Content-Type: application/json' \
     -d '{"name":"alice"}' http://127.0.0.1:3456/api/users          # 创建用户
curl -X POST -H "$AUTH" -H 'Content-Type: application/json' \
     -d '{"users":[{"name":"bob"},{"name":"carol"}]}' \
     http://127.0.0.1:3456/api/users/batch                          # 批量创建

# 节点管理
curl -H "$AUTH" http://127.0.0.1:3456/api/nodes                    # 列出节点
curl -X POST -H "$AUTH" -H 'Content-Type: application/json' \
     -d '{"name":"sg-1","display_name":"SG-1","type":"vless-reality",...}' \
     http://127.0.0.1:3456/api/nodes                                # 添加节点

# UUID 映射
curl -H "$AUTH" http://127.0.0.1:3456/api/mappings/1               # 列出用户1的所有映射
curl -X POST -H "$AUTH" http://127.0.0.1:3456/api/mappings/1/bulk  # 批量生成所有节点UUID
```

### mihomo 客户端配置

将 mihomo `config.yaml` 的 proxies 来源改为 proxy-providers 模式：

```yaml
proxy-providers:
  my-sub:
    type: http
    url: "http://<server>:3456/sub/<token>"
    interval: 86400
    path: ./my-sub.yaml
    health-check:
      enable: true
      interval: 600
      url: https://www.gstatic.com/generate_204

proxy-groups:
  - name: "auto-select"
    type: url-test
    use:
      - my-sub
    url: https://www.gstatic.com/generate_204
    interval: 120
    tolerance: 50
```

## 配置文件说明

| 文件 | 说明 |
|------|------|
| `config/default.json` | 配置模板（端口 3456、adminToken 占位符、DB 路径） |
| `~/.config/subserver/config.json` | 运行时配置（安装时自动生成，含随机 adminToken） |
| `~/.config/subserver/data/subserver.db` | SQLite 数据库（运行时） |
| `~/.config/subserver/logs/` | 日志目录 |
| `data/.gitkeep` | 运行时数据占位 |
| `logs/.gitkeep` | 日志占位 |

配置加载优先级（高 → 低）：环境变量 > `~/.config/subserver/config.json`（运行时） > `config/local.json`（开发） > `config/default.json`（默认模板）

环境变量：`SUBSERVER_PORT`、`SUBSERVER_HOST`、`SUBSERVER_ADMIN_TOKEN`、`SUBSERVER_DB_PATH`

### 管理界面

浏览器访问 `http://<server>:3456/`，输入 adminToken 登录。

- **节点管理**：新增/编辑/删除节点，表单字段按类型（VLESS-Reality / VMess）自动切换
- **用户管理**：创建用户自动生成 token，查看/复制订阅链接
- **UUID 映射**：按用户查看节点 UUID 映射，支持批量分配

### 安全注意事项

- **生产环境必须设置 `adminToken`**：未设置时 Admin API 无认证保护
- `config/local.json` 已在 `.gitignore` 中排除，不会提交到仓库
- 所有 API 响应包含 `X-Content-Type-Options: nosniff` 头
- 请求体大小限制为 1MB，防止 DoS
- Token 比较使用时序安全算法，防止时序攻击

## API 端点

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/health` | 无 | 健康检查 |
| GET | `/sub/:token` | 无 | 获取订阅 YAML |
| GET/POST | `/api/users` | Bearer | 用户列表 / 创建用户 |
| POST | `/api/users/batch` | Bearer | 批量创建用户 |
| GET/PUT/DELETE | `/api/users/:id` | Bearer | 单个用户操作 |
| GET/POST | `/api/nodes` | Bearer | 节点列表 / 创建节点 |
| GET/PUT/DELETE | `/api/nodes/:id` | Bearer | 单个节点操作 |
| GET/POST | `/api/mappings/:userId` | Bearer | 用户映射列表 / 创建映射 |
| POST | `/api/mappings/:userId/bulk` | Bearer | 批量生成 UUID |
| DELETE | `/api/mappings/:userId/:nodeId` | Bearer | 删除单条映射 |
