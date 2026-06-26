# 订阅分发服务 (subserver)

## Context

节点 IP/port 因封锁定期变更，手动维护客户端配置效率低且易中断。需要一个集中订阅分发服务：管理员更新节点信息后，所有客户端自动拉取最新配置。每个用户（token）在上游各节点有独立 UUID，分发时按 token 动态组装。

---

## Task 1: 项目骨架

**位置**: `net-tools/subserver/`

```
subserver/
├── src/
│   ├── server.js          # HTTP 入口 + 路由分发
│   ├── db.js              # SQLite 初始化 + schema
│   ├── yaml-gen.js        # 节点 → mihomo proxy YAML
│   ├── auth.js            # Admin Bearer token 中间件
│   └── routes/
│       ├── sub.js         # GET /sub/:token
│       ├── users.js       # /api/users CRUD
│       ├── nodes.js       # /api/nodes CRUD
│       └── mappings.js    # /api/mappings CRUD
├── scripts/
│   ├── seed.js            # 初始数据导入
│   └── subserver.service  # systemd unit
├── config/
│   └── default.json       # 端口(3456)、adminToken、DB路径
├── data/                  # SQLite DB (.gitignore)
├── logs/                  # (.gitignore)
├── package.json
└── .gitignore
```

**技术选型**:
- Node.js 内置 `http` 模块（无 Express，路由少且简单）
- `node-sqlite3-wasm`（与 smartxray 一致，纯 WASM 无需编译工具链）
- UUID 生成用 `crypto.randomUUID()`
- YAML 输出手写序列化（结构固定，无需 js-yaml 库）

---

## Task 2: 数据库 Schema

```sql
CREATE TABLE users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  token      TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL,
  note       TEXT DEFAULT '',
  enabled    INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE nodes (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL UNIQUE,
  display_name  TEXT NOT NULL,
  type          TEXT NOT NULL CHECK(type IN ('vless-reality','vmess')),
  server        TEXT NOT NULL,
  port          INTEGER NOT NULL,
  -- VLESS Reality
  pubkey        TEXT, shortid TEXT, sni TEXT,
  flow          TEXT DEFAULT 'xtls-rprx-vision',
  fingerprint   TEXT DEFAULT 'chrome',
  -- VMess
  alter_id      INTEGER DEFAULT 0, cipher TEXT DEFAULT 'auto',
  network       TEXT DEFAULT 'tcp',
  ws_path       TEXT DEFAULT '', ws_host TEXT DEFAULT '',
  tls           INTEGER DEFAULT 0, tls_sni TEXT DEFAULT '', skip_cert INTEGER DEFAULT 0,
  -- 通用
  enabled       INTEGER DEFAULT 1,
  sort_order    INTEGER DEFAULT 0
);

CREATE TABLE user_node_uuids (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  node_id  INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  uuid     TEXT NOT NULL,
  UNIQUE(user_id, node_id)
);
```

---

## Task 3: 核心 API

**订阅接口（公开）**:
- `GET /sub/:token` → 返回 `proxies:` YAML（Content-Type: text/yaml）
- `GET /health` → `{"status":"ok"}`

**Admin API（Bearer token 认证）**:
- Users: `GET/POST /api/users`, `GET/PUT/DELETE /api/users/:id`
- Nodes: `GET/POST /api/nodes`, `GET/PUT/DELETE /api/nodes/:id`
- Mappings: `GET/POST /api/mappings`, `DELETE /api/mappings/:id`
- Bulk: `POST /api/mappings/bulk`（为某用户批量设置所有节点 UUID）

**订阅输出逻辑**:
1. token → 查 users 表 → 验证 enabled
2. JOIN user_node_uuids + nodes → 取该用户所有已启用节点 + 对应 UUID
3. 按 sort_order 排序
4. yaml-gen.js 根据 node.type 生成对应 mihomo proxy 条目
5. 组装 `proxies:` YAML 输出

---

## Task 4: seed.js 初始数据

从现有凭据导入 9 个节点：

| name | display_name | type | server:port |
|------|-------------|------|-------------|
| direct-sg | sg-direct | vless-reality | 52.221.22.241:18443 |
| qingwei | sg-qingwei | vless-reality | 54.251.198.173:18443 |
| mantou-sg | sg-mantou | vless-reality | 47.236.76.195:443 |
| home | home | vless-reality | home.luoyueliang.com:8443 |
| company-mtedu | company-mtedu | vless-reality | 222.128.34.15:8443 |
| liuren | proxy-liuren-sg | vmess | ppio-ren.asuscomm.com:8080 |
| tempco | proxy-sg-tempco | vmess | 6500127.icdn.plus:10086 |
| kl01 | proxy-kl01 | vmess | 6000064.icdn.plus:10086 |
| 19800820 | proxy-19800820 | vmess | 19800820.com:443 |

创建 1 个 admin 用户（arthur），自动分配各节点 UUID。

---

## Task 5: 部署到 mynet.club

1. SCP subserver 到服务器 `/opt/subserver/`
2. `npm install --production`
3. `node scripts/seed.js` 初始化 DB
4. 安装 systemd 服务，监听 127.0.0.1:3456
5. nginx 反代 `sub.mynet.club` → 127.0.0.1:3456（复用现有通配符证书）
6. DNS 添加 sub.mynet.club A 记录 → 52.77.179.176

**nginx 配置** (`/etc/nginx/sites-available/sub.mynet.club.conf`):
```nginx
server {
    listen 443 ssl http2;
    server_name sub.mynet.club;
    ssl_certificate     /etc/letsencrypt/live/mynet.club/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mynet.club/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3456;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
server {
    listen 80;
    server_name sub.mynet.club;
    return 301 https://$host$request_uri;
}
```

---

## Task 6: 客户端迁移

mihomo 配置改为 proxy-providers 模式：

```yaml
proxy-providers:
  my-sub:
    type: http
    url: "https://sub.mynet.club/sub/<token>"
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

本地 rules 保持不变，仅 proxies 来源从手写改为订阅。

---

## Task 7: 验证

1. `curl https://sub.mynet.club/health` → 200
2. `curl https://sub.mynet.club/sub/<token>` → 返回正确 YAML
3. mihomo 加载 proxy-providers → 所有节点可见
4. 代理测试 Google/GitHub → 200
5. 修改某节点 port → 等待客户端刷新 → 新 port 生效

---

## 关键文件

- 新建: `net-tools/subserver/` 整个目录
- 修改: `~/.config/mihomo/config.yaml`（proxy-providers 模式）
- 修改: `~/.config/clash.meta/config.yaml`（同步）
- 服务器: mynet.club (52.77.179.176) nginx + systemd
