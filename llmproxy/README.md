# llmproxy

自用的 LLM 转发网关。下游选模型，上游按**权重 + 可用性**选供应商。

与同仓库的 `litellm-proxy` 相比：那个是 Docker/Python 的完整 LiteLLM，功能多、依赖重；`llmproxy` 是零运行时依赖的单二进制，定位是「自己机上的轻量转发」。

## 特性

- **下游 OpenAI 兼容**：`POST /v1/chat/completions`、`GET /v1/models`
- **上游全部是 OpenAI 兼容端点**：`base_url` + `api_key` + 模型名映射
- **权重路由**：同一模型可配多个供应商，按 `weight` 随机分摊
- **可用性**：连续失败达到阈值后临时摘除，冷却后自动恢复；失败请求自动换下一个供应商重试
- **YAML 配置热加载**：保存后自动生效（2 秒轮询），也可 `llmproxy reload` / `kill -HUP`；校验失败时保留旧配置继续服务
- **按供应商配置代理**：`direct` / `http(s)://` / `socks5(h)://`，也可在 `proxies` 里起名字复用
- **SQLite 记账**：请求明细 + 供应商状态 + 按日消耗汇总；**不记录任何请求/响应内容**
- **流式 SSE 透传**：自动注入 `stream_options.include_usage`，从末尾 chunk 提取 token 数
- **多用户中转器（可选）**：每个用户带自己的 token 和**自己的上游**（自带 `base_url` / `api_key`），
  网关只负责鉴权、转发、按用户记账；上游密钥 AES-256-GCM 加密落库，熔断按用户隔离
- **两种用户模式**：`byo`（用户自带上游，网关不掏钱）与 `consumption`（用户消费系统上游，
  带模型白名单、月度配额与金额估算、RPM 与并发上限）
- **网页控制台**：`GET /ui/` 自带一个单页界面，用户用自己的 token 登录即可管自己的上游、
  看自己的用量、发一条请求验证链路；静态资源编在二进制里，不需要额外部署

## 安全约定

这些是刻意的设计，不是遗漏：

| 措施 | 说明 |
|------|------|
| 默认只监听 `127.0.0.1` | 改成非本机回环且未配置 `api_keys` 时拒绝启动 |
| 下游凭证常数时间比较 | 先 SHA-256 摘要再比，不通过响应时间泄漏长度 |
| 日志只存凭证哈希前缀 | `SHA-256(key)[:6]`，数据库与日志里都没有明文密钥 |
| 不转发下游 Authorization | 上游收到的永远是**该供应商自己的** `api_key` |
| 不记录请求/响应内容 | 只落模型名、延迟、token 数、状态码、错误类型 |
| 配置/数据库文件 0600 | 权限过宽会在启动时警告 |
| 代理完全由配置决定 | 直连时显式忽略 `HTTP_PROXY`/`HTTPS_PROXY` 环境变量 |
| 被代理的请求走 CONNECT 隧道 | 代理不允许 CONNECT 时会明确报错，而不是静默直连 |
| 用户上游密钥加密落库 | AES-256-GCM，主密钥是运行时目录下 0600 的 `master.key`；库里没有明文 |
| 自助接口只认自己的身份 | 用户的 token 只能看和改自己的上游；静态 key 无用户身份，自助接口直接 403 |
| 用户自带上游时不回退全局 | 他配的上游全挂了会明确失败，绝不静默改用你的全局上游（那等于替你付费） |
| 消费额度只算系统掏钱的部分 | 用户用自己的上游时不计入配额；白名单外的模型直接 403 |
| 单价按上游模型名计 | 用户把下游名映射到哪个上游模型，就按哪个模型的价格算，不会串价 |
| 主密钥不可用则拒绝启动 | 库里已有用户却读不到 `master.key` 时直接不启动，而不是让这些用户莫名其妙全部 401 |

## 构建

```bash
cd llmproxy
go build -o llmproxy ./cmd/llmproxy      # 本机平台
```

依赖：Go ≥ 1.22。模块依赖只有两个：`gopkg.in/yaml.v3` 与 `modernc.org/sqlite`（纯 Go，不需要 cgo）。

国内拉模块建议：

```bash
export GOPROXY=https://goproxy.cn,direct
```

### 交叉编译四平台

```bash
cd llmproxy
./scripts/build.sh            # 版本号取自最近的 llmproxy-v* tag，没有则 dev-<sha>
./scripts/build.sh 1.2.3      # 或指定版本
```

产出 `dist/`：

```
llmproxy-v1.2.3-darwin-arm64.tar.gz     # 每个包里是 llmproxy + config/config.example.yaml + README.md
llmproxy-v1.2.3-darwin-amd64.tar.gz
llmproxy-v1.2.3-linux-arm64.tar.gz
llmproxy-v1.2.3-linux-amd64.tar.gz
SHA256SUMS
```

三点值得说明：

- **不需要交叉工具链**：`CGO_ENABLED=0`，因为 SQLite 用的是 `modernc.org/sqlite`（纯 Go 实现）。
  一条命令就能出四个平台，脚本还会把 `GOOS/GOARCH/CGO_ENABLED` 从二进制里读回来核对一遍。
- **脚本先 `go vet` + `go test` 再编译**：宁可在这里失败，也不要产出一个跑不起来的发行包。
- **版本号由构建注入**：`config.Version` 是 `var`，脚本用
  `-ldflags "-X .../internal/config.Version=v1.2.3"` 把 tag 写进去，
  所以 `llmproxy version` 报的永远是发布时的 tag，不用手工改源码。
  工作区有未提交改动时会自动标成 `1.2.3-dirty`，防止把半成品当正式版发出去。

### 发布

推一个 `llmproxy-vX.Y.Z` 标签即可，`.github/workflows/release-llmproxy.yml` 会：
先跑测试 → 交叉编译四平台 → 建 Release → 上传四个 tar.gz 与 `SHA256SUMS`。

```bash
git tag llmproxy-v1.2.3 && git push origin llmproxy-v1.2.3
```

也可以在 Actions 页面手动触发（`workflow_dispatch`）：只构建、不发 Release，
产物作为 workflow artifact 下载。

macOS 上从浏览器/curl 下载的二进制会带隔离标记，首次运行若被拦下：

```bash
xattr -d com.apple.quarantine ./llmproxy
```

## 快速开始

```bash
# 1. 初始化：生成 ~/.config/llmproxy/config.yaml
./llmproxy init

# 2. 编辑配置：填好 api_keys 与 providers

# 3. 前台启动
./llmproxy start

# 4. 另开一个终端测试
./llmproxy test -model gpt-4o
```

客户端把 base URL 指到网关即可：

```bash
curl http://127.0.0.1:8787/v1/chat/completions \
  -H "Authorization: Bearer sk-local-change-me" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"你好"}]}'
```

## 配置

运行时目录默认 `~/.config/llmproxy/`（可用 `LLMPROXY_HOME` 覆盖），示例模板在 [`config/config.example.yaml`](./config/config.example.yaml)。

```yaml
server:
  host: 127.0.0.1
  port: 8787
  api_keys:
    - sk-local-change-me              # 纯字符串
    - key: sk-another                 # 或带标签（标签只进日志，方便区分客户端）
      label: laptop

routing:
  retry: 2                 # 首次失败后再换多少个供应商
  failure_threshold: 3     # 连续失败几次后临时摘除
  cooldown_seconds: 60     # 摘除多久后自动恢复

proxies:                   # 代理池，供应商按名字引用
  - name: us-http
    url: http://127.0.0.1:7890
  - name: jp-socks
    url: socks5://user:password@127.0.0.1:1081

providers:
  - name: openai-main
    enabled: true
    base_url: https://api.openai.com/v1
    api_key: ${OPENAI_API_KEY}        # 支持 ${ENV} / ${ENV:-default}
    weight: 10                        # 相对权重
    proxy: us-http                    # direct / 留空 = 直连；也可写代理名或内联 URL
    timeout_ms: 120000
    models:                           # 下游模型名 → 上游真实模型名
      gpt-4o: gpt-4o-2024-11-20
      gpt-4o-mini: gpt-4o-mini

  - name: deepseek
    enabled: true
    base_url: https://api.deepseek.com/v1
    api_key: ${DEEPSEEK_API_KEY}
    weight: 3
    proxy: direct
    models: ["*"]                     # "*" = 任意模型名直通上游
    extra_headers:                    # 可选：附加到上游请求头
      X-Title: llmproxy

database:
  path: ""                # 留空 = 运行时目录下 data/llmproxy.db
  retain_days: 90         # 请求明细保留天数，0 = 永久

log:
  level: info             # debug | info | warn | error
  max_mb: 10
  keep: 5
```

### 模型路由语义

- `models` 是**映射**时：只有列出的下游模型名会被路由到该供应商，上游收到映射后的名字
- `models: ["*"]` 时：任意下游模型名都会路由到该供应商，上游收到原名（直通）
- `GET /v1/models` 只列出**映射型**供应商声明的模型名；直通型无法枚举，所以不列出

### 重试与熔断

```
请求 → 按权重选中供应商 A
        ↓ 失败（网络错误 / 401 / 403 / 404 / 408 / 429 / 5xx）
      排除 A，再按权重选供应商 B
        ↓ 失败
      ……直到 retry 次数用尽 → 返回最后一次错误
```

- 400/422 等「请求本身有问题」的状态码**不重试**，直接返回给客户端
- 同一供应商连续失败达到 `failure_threshold` 后，`cooldown_seconds` 内不再被选中
- 冷却结束后自动恢复；若所有候选供应商都在冷却中，仍会按权重选一个（宁可重试也不要硬失败）
- 运行期状态持久化在 SQLite 里，重启后熔断计数不会归零

### 代理说明

被代理的上游**一律走 CONNECT 隧道**：

- `http(s)://` 代理：发送 `CONNECT host:port`，https 目标在隧道上再做 TLS
- `socks5(h)://`：SOCKS5 CONNECT 命令；目标主机名以域名形式交给代理解析（行为等价 `socks5h`），上游域名不会泄漏到本地 DNS

因此代理需要允许 CONNECT 到上游端口。Clash / squid / tinyproxy 默认都允许。

## 多用户（中转器模式）

默认它就是「你自己机上的转发网关」：用 `server.api_keys` 里的静态 key 访问，请求走 `providers`
里的全局上游。**多用户模式**是叠加在这之上的第二种用法 —— 每个用户带自己的 token，并且
**自带自己的上游**（自己的 `base_url` 与 `api_key`）。网关只做鉴权、转发、记账，
不再替别人付上游的钱，这就是「纯中转器」的形态。

用户不写在 YAML 里，而是存在 SQLite 里（用 `llmproxy user` 管理），因为要保存加密后的上游密钥。
配置里的 `providers` 仍然保留，作为「没有自带上游」时的兜底。

### 启用

```bash
# 1) 给管理接口设一个凭证（不设则 /v1/_admin 整体关闭）
#    在 config.yaml 的 server 段加：admin_token: ${LLMPROXY_ADMIN_TOKEN}

# 2) 直接启动：首次启动会自动生成 0600 的 master.key，用来加密用户的上游密钥
./llmproxy start
```

主密钥是运行时目录下的 `master.key`（32 字节随机）。**它丢了，库里已有的上游密钥就解不开**，
只能让用户重填 —— 这是这套设计唯一的硬代价。别把它弄丢，也别和数据库放在一起。

### 用户与上游（本地运维）

```bash
# 建用户：明文 token 只打印这一次
./llmproxy user add alice

# 代用户配上游（也可以让用户用下面的自助接口自己配）
./llmproxy user add-provider alice alice-deepseek \
  -base-url https://api.deepseek.com/v1 \
  -api-key-env ALICE_DEEPSEEK_KEY \    # 或 -api-key -  从 stdin 读，避免密钥进 shell 历史
  -models '["*"]'

./llmproxy user list                   # 全部用户 + 累计用量
./llmproxy user show alice             # 用户详情（上游、用量）
./llmproxy user providers alice        # 该用户的上游，密钥只显示「(已加密)」
./llmproxy user usage alice -days 7    # 按日 / 按模型看消耗
./llmproxy user disable alice          # 停用后该 token 一律 403
./llmproxy user token alice            # 轮换 token，旧 token 立即失效
./llmproxy user rm-provider alice alice-deepseek
./llmproxy user rm alice               # 删用户及其全部上游
```

这些都是直接改数据库的本地运维操作；正在运行的服务会在 **2 秒内**自动加载。
`add-provider` 还支持 `-weight`、`-timeout-ms`、`-proxy`、`-disabled`（配好先不启用）。

### 自助接口（用户自己配自己的上游）

用户拿自己的 token 调，只能看见和改动自己的东西：

| 方法 | 路径 | 用途 |
|------|------|------|
| GET | `/v1/_me` | 身份、上游名列表、累计用量 |
| GET | `/v1/_me/providers` | 自己的上游详情（密钥脱敏到尾 4 位，如 `****9999`） |
| PUT | `/v1/_me/providers/{name}` | 新增或覆盖一个上游（只传要改的字段，密钥不必重传） |
| DELETE | `/v1/_me/providers/{name}` | 删掉一个上游 |
| POST | `/v1/_me/providers/{name}/discover` | 用这个上游的地址与密钥拉一次 `/v1/models`，拿模型名列表给界面做勾选候选 |
| GET | `/v1/_me/usage?days=N` | 按日 / 按模型的消耗 |

### 管理接口（用 `server.admin_token` 鉴权）

| 方法 | 路径 | 用途 |
|------|------|------|
| GET | `/v1/_admin/users` | 用户列表（含各用户上游与用量） |
| POST | `/v1/_admin/users` | 建用户，返回明文 token（只此一次） |
| GET / DELETE | `/v1/_admin/users/{name}` | 用户详情 / 删用户 |
| POST | `/v1/_admin/users/{name}/token` | 轮换 token |
| POST | `/v1/_admin/users/{name}/enable\|disable` | 启用 / 停用 |
| GET | `/v1/_admin/users/{name}/providers` | 该用户的上游 |

管理接口走在下游鉴权**前面**，用 `admin_token` 单独校验；没配 `admin_token` 时整体关闭（403）。

### 两条要么想清楚、要么别动的规则

1. **用户配了自己的上游，就只用他自己的。** 哪怕他配的上游全部不可用，也**不会**悄悄回退到
   全局 `providers` —— 那等于网关替他付费。这种情况明确返回 502，并在错误信息里说明原因。
   只有「一个上游都没配」的用户才落到全局兜底。
2. **熔断按 (用户, 上游) 分桶。** 一个用户把自己的上游打成 429，只影响他自己，
   不会再连累其他人 —— 单用户时代的「一家抖动、全体失败」在用户自带上游后不再存在。

### 记账

请求明细里带 `client_key_hash` / `client_label`；按用户、按上游、按日的累计用量存在
`usage_user_daily` 表（`llmproxy user usage` 读的就是它）。用户的 token 只存 SHA-256 摘要，
上游密钥只存 AES-GCM 密文，库里没有明文。

## 网页控制台

浏览器打开网关自带的 `/ui/` 即可：

```
http://127.0.0.1:8787/ui/
```

用**用户自己的 token** 登录（不是 `admin_token`）。token 只存这个标签页的会话里，
关掉标签就失效，不进 URL、Cookie 或 localStorage。

页面上能做四件事：

| 区块 | 作用 |
|------|------|
| 概览 | 身份、上游数量、累计请求与 token |
| 我的上游 | 增删改自己的上游；密钥加密落库，页面只显示尾 4 位；编辑时密钥留空表示不修改 |
| 我的模型 | 按客户端请求的 `model` 名字汇总，看它挂在哪些上游上；挂两家以上就是负载均衡 + 失败切换 |
| 我的用量 | 按 7/30/90 天看逐日逐模型的消耗与平均耗时 |
| 试一下 | 用你的 token 从网关发一条请求，直接看到是**哪个上游接走的**、耗时多少 |

### 模型怎么配：同步 + 勾选，不写 JSON

「承接的模型」不是让你手写 `{"下游名":"上游名"}`，而是：**点一下「从上游同步模型列表」**，
网关拿这个上游的地址和密钥去拉一次 `/v1/models`，把模型名列出来给你勾。

- **勾选即加入**，下游名默认与上游模型同名；
- 想给客户端换个名字，就在「已选」表里改**下游名**那一列（`qwen-max` → `fast`）；
- 「其余模型也放行」对应 `{"*":"*"}`，即上面没列出的模型名也原样转发；
- **上游不提供 `/v1/models` 也不挡路**：那就在「手动添加」里把模型名写上，
  探测失败不会动你已经选好的映射；
- **已选但不在候选里的目标会保留**：编辑一个上游时，上游模型名是自定义的、
  或者那家还没同步过，都不会因为「列表里没有」而被丢掉。

候选列表按上游名缓存在**这个标签页的会话里**，所以编辑已有上游时勾选状态会立刻回来，
不用每打开一次表单就打一次上游；要刷新点「同步」。

这件事的取舍写在 `internal/server/discover.go` 里：探测接口**只回模型名**，
上游的响应体原样丢弃、不回传 —— 否则它就变成了一个「带鉴权的通用 GET 代理」。

几个刻意的选择：

- **同源托管**，不额外起服务：页面要带着 token 调 `/v1/_me*`，同源就没有 CORS 问题，
  也不用多开端口、多管一个进程。静态资源 `go:embed` 进二进制，部署时不用分发文件。
- **它不跳过网关**：页面上的每个动作都走同一套 HTTP 接口，所以你在浏览器里看到的能力，
  和你用 curl 调接口看到的能力完全一致 —— 界面只是接口的一层皮。
- **静态资源不需要鉴权**（登录页本身也得能打开），但它不含任何数据；真正的数据都在
  `/v1/_me*` 后面，必须有用户 token。
- 想从别的机器访问：把 `server.host` 改成非回环地址**并配好 `api_keys`**（配置校验会强制这一点）。

### 消费模式：让用户消费「系统上游」

上面的多用户模式里，用户是**自带**上游的（自己的 base_url 和 api_key），网关不替他付钱。
消费模式是另一种：用户用**系统上游**（`providers` 里那些全局供应商），账单归网关主人，
因此必须可计量、可限额。

```bash
# 1) 把用户切成消费模式
./llmproxy user mode alice consumption

# 2) 给他能用的模型（这既是白名单，也是「下游名 → 系统模型」的映射）
./llmproxy user add-model alice fast -upstream deepseek-flash
./llmproxy user add-model alice pro  -upstream deepseek-v4-pro -provider deepseek   # 限定某家供应商

# 3) 配额与限流（0 或省略 = 不限）
./llmproxy user quota  alice -tokens 50000000 -cost 100
./llmproxy user limits alice -rpm 120 -concurrent 8

./llmproxy user models alice      # 看白名单
./llmproxy user show   alice      # 模式 / 配额 / 限流 / 本月消费
```

**没在白名单里的模型会被 403 直接拒绝，请求根本不打到上游。** 这是刻意的：
不限模型的话，配额挡不住「专挑最贵的那个调」。所以新切到消费模式的用户**一个模型都调不了**，
要先 `add-model` —— 不做「默认放开全部模型」这种方便但失控的事。

三条语义，用之前先看清楚：

1. **只有走系统上游的消耗才算进配额**。用户自己配了上游并且某个模型走了自己的上游，
   那部分是他自己和供应商结算，不占额度（每次请求用哪边由模型的映射决定）。
2. **配额是软限制**。判定发生在请求之前，并发请求最多可能超出「同时在飞」的那几条；
   跨过上限的那一条会放行，之后的才拒。要精确到分就不是估算，那是支付系统的活。
3. **金额是估算**，不做预付款、不做扣款、不做对账。按 `pricing` 里的单价算，
   用**当前**单价而非历史价（改过价的话，历史用量会按新价重算）。

### 单价表 `pricing`

不配也能用消费模式，只是没有金额可看（只统计 token）。

```yaml
pricing:
  currency: CNY
  off_peak_ratio: 0.5                  # 空闲时段 = 高峰价 × 系数；不写就不分时段
  peak_hours: ["09:00-12:00", "14:00-18:00"]   # 高峰时段，仅周一~周五（不识别法定节假日）
  models:
    # 单价单位是「每百万 token」，和各家官网报价口径一致
    deepseek-flash:  {cache_hit: 0.04, cache_miss: 2.0, output: 8.0}
    deepseek-v4-pro: {cache_hit: 0.30, cache_miss: 9.0, output: 27.0}
    "*":             {cache_hit: 0,    cache_miss: 0,   output: 0}    # 兜底：未列出的模型按 0 算
```

**为什么输入要分命中/未命中**：DeepSeek 的缓存命中价只有未命中的 **1/50**
（0.04 元 vs 2 元每百万 token）。不区分的话，agent 这类「长前缀反复复用」的负载
金额能高估一个量级。网关会从上游响应的 `usage` 里提取 `prompt_cache_hit_tokens` /
`prompt_cache_miss_tokens`；上游不回报这两个字段时，按**输入全部未命中**算，
属于偏保守的口径 —— 宁可高估，不要漏计。

单价表按**上游模型名**计价（供应商真正收钱的那个名字），不是下游的别名 ——
所以每个用户可以把同一个下游名映射到不同的上游模型而不会算错价。

### 一个行为变更

**byo 模式的用户如果没配任何上游，请求会直接失败，不再回退到系统上游。**

早先版本会静默回退，那等于让用户白嫖网关主人的上游密钥。现在要用系统上游就走
`consumption` 模式（有计量、有配额），报错信息里也会这么提示。

## CLI

```
llmproxy init                初始化运行时目录并生成配置
llmproxy start               前台启动
llmproxy stop                停止
llmproxy restart             重启
llmproxy status              运行状态 + 健康检查
llmproxy reload              热加载配置（SIGHUP）
llmproxy providers           各供应商配置与运行期状态（含熔断）
llmproxy stats [-days N] [-recent N]   消耗统计
llmproxy logs [-n N] [-f]   查看 / 跟踪日志
llmproxy test [-model M] [-stream]     通过网关发一条测试请求
llmproxy user add|list|show|rm <名字>  用户管理（多用户模式，详见上一节）
llmproxy user providers|usage <名字>   该用户的上游 / 消耗
llmproxy user mode|quota|limits <名字> 消费模式的模式 / 配额 / 限流
llmproxy user models|add-model <名字>  消费模式的模型白名单（也是模型映射）
llmproxy user add-provider <用户> <上游名>   代用户配上游
llmproxy service install     安装为 launchd / systemd 服务
llmproxy service uninstall   卸载系统服务
llmproxy version
```

`stats` 输出示例：

```
总计: 请求 128  成功 121  失败 7  token 402133

按供应商/模型消耗:
PROVIDER             MODEL                      REQ       OK     FAIL        TOKENS      AVG_MS
openai-main          gpt-4o-2024-11-20           80       78        2        288400       2100
deepseek             deepseek-chat               41       38        3         99300       1500
```

## 作为系统服务

```bash
./llmproxy init          # 先把配置写好
./llmproxy service install
```

- **macOS**：写入 `~/Library/LaunchAgents/com.llmproxy.service.plist`
- **Linux**：写入 `/etc/systemd/system/llmproxy.service`（可能需要 sudo）

服务模板会显式清空 `HTTP_PROXY`/`HTTPS_PROXY` 等环境变量，确保出口完全由配置文件决定。

## 目录结构

```
llmproxy/
  cmd/llmproxy/        CLI 入口
  internal/
    config/            配置加载 / 校验 / 热重载
    dialer/            direct / HTTP CONNECT / SOCKS5 拨号
    router/            权重选择 + 熔断 + 重试
    server/            下游 HTTP 服务 + 上游转发（含 SSE）
    store/             SQLite：请求日志 / 供应商状态 / 消耗汇总
    logx/              日志（stdout + 轮转文件）
  config/
    config.example.yaml
  ui/                网页控制台的源文件（index.html / app.css / app.js），编译时嵌入二进制
  scripts/           交叉编译脚本（build.sh）与端到端验证脚本（e2e-multiuser.sh）
  data/                运行时数据（.gitkeep）
  logs/                日志目录（.gitkeep）
  go.mod / go.sum
```

> 本工具是 Go 项目，目录布局遵循 Go 惯例（`cmd/` + `internal/`），
> 与仓库里 Node.js 工具的 `src/` + `scripts/` 结构不同。

## 开发

```bash
# 全部单元测试 + 端到端测试
go test ./internal/...

# 静态检查
go vet ./...

# 多用户全链路端到端验证（三个假上游，不花上游额度、不碰正在运行的实例）
bash scripts/e2e-multiuser.sh

# 改网页控制台：源文件在 ui/，改完重新编译即可（静态资源是 go:embed 进二进制的）
# 想在浏览器里改完即见，用 go run 起一个临时实例：
#   LLMPROXY_HOME=/tmp/llmproxy-dev go run ./cmd/llmproxy start

# 指定运行时目录跑（不影响真实配置）
LLMPROXY_HOME=/tmp/llmproxy-dev go run ./cmd/llmproxy start
```

测试覆盖：YAML 解析与配置校验、权重分布、熔断与恢复、HTTP CONNECT / SOCKS5 隧道与认证、
SQLite 统计与清理、下游鉴权、模型映射、失败重试、SSE 透传与 usage 提取、热加载（含坏配置回退）、
以及「内容/密钥不落库」的泄漏检查。

## 并发压测

`cmd/llmpbench` 用来回答「这个网关同时能扛多少请求」。

默认 `stub` 模式：自己起一个假上游，再用**独立的运行时目录**拉起一个 llmproxy 实例
（独立端口、独立 SQLite），全程本机、不消耗任何上游额度，也绝不碰正在运行的服务。

```bash
# 吞吐上限：假上游零延迟，看每秒能过多少请求
go run ./cmd/llmpbench -concurrency 20,100,300,700,1500 -n 2000

# 并发承载：模拟模型延迟 1.5s，看能同时挂住多少路
go run ./cmd/llmpbench -stub-delay 1500 -concurrency 500,2000,4000 -n 4000 -cooldown 30

# 流式（SSE）路径
go run ./cmd/llmpbench -stream -stub-delay 1500 -concurrency 500 -n 1000

# 压已在运行的真实网关（会花钱、可能触发熔断，务必想清楚再跑）
go run ./cmd/llmpbench -mode live -key $LLMPROXY_KEY -concurrency 4 -n 8 -yes
```

输出里两个关键列：

- `up_peak`：假上游**同时在处理**的请求数峰值。它与发出并发之比接近 100%，说明网关在真并行转发、
  没有内部排队；明显偏低则说明有串行点（或本档有连接失败把它压低了）。
- `rss`：网关进程常驻内存峰值。差值除以 `up_peak` 就是每路并发的内存开销 ——
  非流式请求会把整段响应体缓存在内存里，这是决定「还能再挂多少路」的那个数。

跑完还会核对三个数字：客户端成功数 / 假上游收到数 / 网关数据库落库数。三者一致，说明
单连接 SQLite 记账路径在并发下没有丢数据。

### 压测时的几个坑

| 现象 | 原因 | 怎么办 |
|------|------|--------|
| `can't assign requested address` | 压测端临时端口耗尽（macOS 只有 16384 个，且 TIME_WAIT 占 30 秒），与网关无关 | 档位之间加 `-cooldown 30`；或人工 `sudo sysctl -w net.inet.ip.portrange.first=16384`；或压测端与网关分开机器 |
| `connection refused`，且网关日志里查不到这条 | Go 在 macOS 的 listen backlog 只有 128，瞬时建连风暴超过接受队列深度 | 降低瞬时建连速率。这是平台特性，不是 llmproxy 的限制 |
| `502 upstream_unavailable` | 假上游与压测端同进程，会被压测端自己拖累 | 属于测试装置的限制，不算网关的问题 |

> 本机实测（M 系列 Mac、本机环回、单实例）：4000 路并发稳定零失败，6000 路全通过；
> 上游并发峰值与发出并发之比 92%~100%（无内部排队）；每路并发约 0.06~0.12 MB；
> 零上游延迟时吞吐约 9000 RPS（300 并发见顶）。
> 代码里没有任何入向并发上限，真正的约束是内存和上游限速 —— 不是网关的并发数。

## 依赖

| 模块 | 用途 |
|------|------|
| `gopkg.in/yaml.v3` | YAML 配置解析 |
| `modernc.org/sqlite` | 纯 Go SQLite 驱动（无 cgo） |

网络栈（HTTP 服务、TLS、SOCKS5、CONNECT 隧道）全部基于标准库自己实现，没有引入 `x/net` 等网络依赖。
