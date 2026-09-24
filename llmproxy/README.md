# llmproxy

自用的 LLM 转发网关。下游选模型，上游按**权重 + 可用性**选供应商。

与同仓库的 `litellm-proxy` 相比：那个是 Docker/Python 的完整 LiteLLM，功能多、依赖重；`llmproxy` 是零运行时依赖的单二进制，定位是「自己机上的轻量转发」。

## 特性

- **下游 OpenAI 兼容**：`POST /v1/chat/completions`、`POST /v1/completions`、`POST /v1/embeddings`、
  `GET /v1/models`。POST 侧是**白名单**，其余路径一律 404（理由见「安全约定」）
- **上游全部是 OpenAI 兼容端点**：`base_url` + `api_key` + 模型名映射
- **权重路由**：同一模型可配多个供应商，按 `weight` 随机分摊
- **可用性**：连续失败达到阈值后临时摘除，冷却后自动恢复；失败请求自动换下一个供应商重试
- **YAML 配置热加载**：保存后自动生效（2 秒轮询），也可 `llmproxy reload` / `kill -HUP`；校验失败时保留旧配置继续服务
- **按供应商配置代理**：`direct` / `http(s)://` / `socks5(h)://`，也可在 `proxies` 里起名字复用
- **SQLite 记账**：请求明细 + 供应商状态 + 按日消耗汇总；**不记录任何请求/响应内容**
- **流式 SSE 透传**：**强制打开** `stream_options.include_usage`（客户端自带的其他子字段保留），
  从末尾 chunk 提取 token 数。计量是网关自己的需求，不该由下游客户端决定 ——
  否则客户端发一个 `{"include_usage":false}` 就能让这条请求记 0、配额一分不扣，
  而上游照样向我们收钱
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
| 不记录请求/响应正文 | 只落模型名、延迟、token 数、状态码、错误类型。**例外**：上游报错时响应体前 300 字节会进日志与 `provider_stats.last_error`，并随 `/v1/_providers` 下发（排障要用）—— 见下面「已知例外」 |
| 下游 POST 只放行推理端点 | `chat/completions`、`completions`、`embeddings` 三条；其余一律 404。否则任何持有效 token 的用户都能让网关带着**你的上游密钥**去 POST 上游主机的任意路径（`/v1/files`、`/v1/fine_tuning/jobs`…），而且完全不进计量 |
| `base_url` 不许带 query / 锚点 | 转发时上游 URL 是 `base_url + 下游路径` 直接拼的，一个 `?` 就能把路径吃进 query，从而绕过上面那条白名单 |
| 用户自配上游做出网校验 | link-local（含云元数据 `169.254.169.254`）与未指定地址**一律拒绝**；回环与私网段由 `server.block_local_upstream` 控制（默认放行，见配置一节）。系统池是你自己写的，不受限 |
| 配置/数据库文件 0600 | 权限过宽会在启动时警告 |
| 代理完全由配置决定 | 直连时显式忽略 `HTTP_PROXY`/`HTTPS_PROXY` 环境变量 |
| 被代理的请求走 CONNECT 隧道 | 代理不允许 CONNECT 时会明确报错，而不是静默直连 |
| 用户上游密钥加密落库 | AES-256-GCM，主密钥是运行时目录下 0600 的 `master.key`；库里没有明文 |
| 自助接口只认自己的身份 | 用户的 token 只能看和改自己的上游；静态 key 无用户身份，自助接口直接 403 |
| 用户自带上游时不回退全局 | 他配的上游全挂了会明确失败，绝不静默改用你的全局上游（那等于替你付费） |
| 消费额度只算系统掏钱的部分 | 用户用自己的上游时不计入配额；白名单外的模型直接 403 |
| 单价按上游模型名计 | 用户把下游名映射到哪个上游模型，就按哪个模型的价格算，不会串价 |
| 主密钥不可用则拒绝启动 | 库里已有用户却读不到 `master.key` 时直接不启动，而不是让这些用户莫名其妙全部 401 |
| 控制台写回 config.yaml 拒绝控制字符 | 供应商名 / base_url / api_key / proxy 里出现换行或控制字符时**报错**而不是写下去 —— YAML 把 lone CR、U+2028、U+0085 也当换行，一个带 CR 的值能逃出 `providers` 段注入新的顶层段；而双引号标量里的裸换行会被「折叠」成空格，把 api_key 静默改坏 |

### 已知例外

**上游错误响应体会被留下来。** 上游返回可重试的错误状态码时，响应体前 300 字节会写进日志、
存进 `provider_stats.last_error`，并通过 `GET /v1/_providers` 下发给下游（管理台与用户台都用它排障）。
很多上游的错误体里会回显请求片段，所以这一条与上面「不记录请求/响应正文」是冲突的 ——
它是刻意的取舍（不知道上游为什么 4xx 就没法排障），但**要知道它存在**：
消费模式用户能从 `/v1/_providers` 读到系统供应商返回的错误正文。
要收紧就把 `last_error` 改成只存归一化的错误类别、原文只进日志。

**出网校验挡不住 DNS rebinding。** 主机名是在校验时解析的，校验通过后域名被改指到
`169.254.169.254`，拨号时就会打过去。要彻底堵住得在 `net.Dialer.Control` 里对**解析后的 IP**
再判一次。当前挡住的是「直接写 IP」和「解析结果就是内网」这两种绝大多数情况。

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
  block_local_upstream: false         # 打开后用户自配的上游不许指向回环/私网（见「安全约定」）

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
  retain_days: 90         # 请求明细保留天数；**显式 0 = 永久**，留空 = 90 天
                          # 这张表就是计价冻结账本，要长期对账就设成 0

log:
  level: info             # debug | info | warn | error
  max_mb: 10
  keep: 5
```

### 模型路由语义

- `models` 是**映射**时：只有列出的下游模型名会被路由到该供应商，上游收到映射后的名字
- `models: ["*"]` 时：任意下游模型名都会路由到该供应商，上游收到原名（直通）
- `GET /v1/models` 只列出**映射型**供应商声明的模型名；直通型无法枚举，所以不列出

**点名声明优先于通配兜底。** 一家写 `models: ["*"]` 的供应商等于声明「任何模型名我都接」，
所以它也会成为那些**别人点名声明过**的模型名的候选。如果两者平权、各自按权重随机，
同一个模型名就会时而正常、时而报错 —— 这正是踩过的坑：`deepseek`（直通）与
`neolink`（点名 `gpt-5-sol`）权重都是 1，实测十次里七次把 `gpt-5-sol` 送去了
`deepseek`，而那边只认 `deepseek-flash` / `deepseek-v4-pro`，于是一半请求 400。

所以选路的次序是：

```
任务名被点名声明过吗？
  ├─ 是 → 只在「点名声明它」的供应商里按权重选（它们全进冷却了，也仍旧在这里面选一个硬打）
  └─ 否 → 才轮到「通配兜底」的那些（同样先健康、再不健康）
```

一个推论值得记住：**只要有人点名声明了某个模型名，兜底那家就再也不会拿到它。**
想让某个名字重新回到兜底，就得把点名那条删掉；想让它多走几家，就给这几家都写上这条映射。

### 会话粘性：同一个会话钉在同一个后端

一个模型名背后有多家供应商时，权重随机选路会把一段对话打散到多家 ——
而上游的前缀缓存按（账号 + 模型）分区，换一家等于从冷缓存重来。
实测数据：一路只走 `deepseek-flash` 时命中率 **98.5%**（136 次请求、5983 万 prompt token）；
一旦被摊到多家，单家的复用次数就被摊薄，命中率随之下降。

下游（MiMoCode）会在请求头 `x-session-affinity: ses_...` 里带会话 id，网关据此粘住：

| 请求情况 | 网关怎么做 | 观测头 |
|---|---|---|
| 带会话头，且那家在候选池里、健康 | 一直用它（规则 A） | `sticky` |
| 那家挂了 / 返回 4xx（这家用不了） | 本次漂到别家，并**把粘性更新成新家** | `drift` |
| 带会话头但这个会话还没粘性（新会话） | **按当前上游价挑最便宜的**（规则 B，见下） | `cheapest` |
| 没有价目可挑 / 没有会话头 | 照旧按权重随机，不碰粘性表 | `new` |
| 全部候选都失败 | 忘掉粘性，下一个请求重新选 | — |

**键是三维的：`(用户, 会话, 模型)`。**
模型必须进键 —— 一个会话会调多个模型（MiMo 有 model / small_model / vision_model），
而缓存本来就按模型分区；只按会话记的话，模型之间会互相改写这条记录，调完 B 再调 A
时粘性已经指着一家不承接 A 的供应商，于是每次换模型都要漂移一次。
不同用户的同名会话 id 也互不影响。

**粘性是软约束，两条边界**：

- 它只在**最终候选池**里生效 —— 粘性决定的是"这批合法候选里挑哪一家"，
  不能绕过上面那条「点名声明优先于通配兜底」。代价是：某个模型的声明方集合变化时，
  会话可能迁移一次（罕见，且只发生一次）。
- 那家**正在冷却**时不粘，直接漂移（后端不能用就换家）。

**为什么 4xx 也要忘掉粘性**：4xx 不触发熔断，如果不主动忘掉，会话会被钉在一家只会报错的
后端上死循环。所以判据不是熔断，而是"这家对这个名字报错了"。

**观测**：响应头 `X-Llmproxy-Affinity` 四个值 —— `new`（没粘性也没价目，按权重随机）/
`cheapest`（规则 B 按价格挑的）/ `sticky`（按粘性选中）/ `drift`（漂移过来的）。
排障与上线验证都看这一列。

**开关与保留时长**：`server.affinity_ttl_ms`。没配 = 24 小时（会话可能隔夜还在继续，
而上游的缓存通常也活那么久）；显式写 `0` = 关闭，请求照旧按权重随机、连观测头都不写。
条目不持久化：重启后粘性全丢，代价只是每个活跃会话迁移一次，换来的是每次请求都不落盘。

### 规则 B：新会话按当前价挑最便宜的

粘性只管"已有的会话继续用哪家"。**新起一个会话**（或粘性那家已经不适用）时，按**当前上游价**
从低到高挑候选，而不是权重随机 —— 这时还没有缓存要保，就该省钱。

三条边界都是刻意的：

- **只按有价目的候选比价**。没录价目的候选不参与（不知道价不等于便宜）；**全都没价目就退场**，
  行为与以前完全一致 —— 所以这个功能没录价之前是静默的，不会悄悄改变选路。
- **跳过冷却中的候选**。上游回 **402（额度不足）/ 429（被限流）** 时，一次就给这家压一段
  短期冷却（5 分钟，比常规熔断的 `cooldown_seconds` 长）—— 攒够失败次数再冷却太慢，
  规则 B 会一遍遍把请求送到已经没额度的家。压完之后新会话自然落到次便宜的家。
- **排序键是 `in_miss + out`**（每百万 token 的两档相加）。粗糙但透明：输入输出都贵的家一定靠后。
  真要精确得按实测 token 混合比加权，那需要历史数据，留待以后。

**规则 A 压过规则 B**：会话一旦粘住，就不为省价而迁移 —— 缓存省下的输入价（命中与未命中
差几十倍）远大于供应商之间的价差。

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

### 超时：非流式看总时长，流式看有没有动静

同一个 `timeout` 落到两种请求上是两回事，所以拆成两个：

| 请求类型 | 管什么 | 配置 |
|---|---|---|
| 非流式 | 整条请求-响应的**总时长** | `request_timeout_ms`（全局上限）与供应商的 `timeout_ms` 取较小值 |
| 流式 (SSE) | **连续多久没收到字节** | `stream_idle_timeout_ms`（默认 2 分钟，显式 `0` = 关闭） |

为什么流式不能用总时限：一次长回答正常就要跑几分钟，按总时限掐会把好端端的流切断；
而「上游卡住不动」又该早点失败，不该耗满总时限。改成空闲判据之后两种情况都对：
每个 chunk（以及响应头到达）都会重置计时，所以「慢但活着」不会被误杀，
「一动不动」会在空闲上限处断开，日志与记库里标成 `upstream_idle`（而不是含混的
`context canceled`，后者和「客户端主动断开」长得一样，没法归因）。

代价是流式**不设总时限**了 —— 一个一直慢速吐字节的上游理论上可以挂很久，
由客户端断开兜底。要退回旧行为就把 `stream_idle_timeout_ms` 显式设成 `0`。

阈值要大于上游的正常 TTFT：DeepSeek 系常见 10~30s，默认的 2 分钟留了足够余量。

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

这些都是直接改数据库的本地运维操作；改完会主动通知正在运行的服务重新加载，
所以**立刻**就能用，不用等（通知推不动时，服务每 2 秒一次的修订号轮询仍是兜底）。
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
| GET | `/v1/_admin/users` | 用户列表（含模式、配额与本月已用、限流、模型数） |
| POST | `/v1/_admin/users` | 建用户，返回明文 token（只此一次） |
| GET / PUT / DELETE | `/v1/_admin/users/{name}` | 用户详情 / **改设置** / 删用户 |
| POST | `/v1/_admin/users/{name}/token` | 轮换 token |
| POST | `/v1/_admin/users/{name}/enable\|disable` | 启用 / 停用 |
| GET | `/v1/_admin/users/{name}/providers` | 该用户自己配的上游（脱敏） |
| GET / PUT / DELETE | `/v1/_admin/users/{name}/models` | 该用户的模型映射（增删改查） |
| GET | `/v1/_admin/users/{name}/usage?days=N` | 该用户的用量（含金额与缓存命中） |
| POST | `/v1/_admin/users/{name}/test` | **快速测试**：按这个用户的路由发一条极小请求（body `{"model":"<下游名>"}`） |
| GET / PUT | `/v1/_admin/config` · `/v1/_admin/config/providers` | 读配置（密钥不下发）/ 写回 providers 段 |
| POST | `/v1/_admin/config/validate` | 试算：校验但不落盘 |
| GET | `/v1/_admin/providers` | 系统上游列表（含各自声明的模型） |
| POST | `/v1/_admin/providers/{name}/discover` | 探测某个系统上游的模型列表（body 可内联 `base_url`/`api_key`/`proxy`） |
| POST | `/v1/_admin/providers/{name}/test` | **快速测试**：直接打这家系统上游（body 可内联 `base_url`/`api_key`/`proxy`；`model` 省略时用它声明的第一个**上游**名，直通型则问上游要列表取第一个真实名字） |

两个 `/test` 端点**都返回 200**，通没通看响应体里的 `ok`：

```json
{"ok":true,"provider":"deepseek","upstream_model":"deepseek-flash","status":200,
 "latency_ms":412,"ttft_ms":390,"content":"…","tokens":9}
```

失败时 `ok:false` 且带 `error`，而且**归因与真实请求一致** —— 模型被管理员收窄挡掉了，
报的是「不在这个用户的可用范围内（管理员给他收窄了）」，而不是含糊的「没有可用上游」。

`/discover` 允许在请求里内联 `base_url` / `api_key` / `proxy`，是为了配合**还没保存的供应商**：
界面刚填好地址就点探测，此时后端还没有这条配置。这不扩大权限，因为调用方本来就能把同一个
地址配成上游、让网关拿同一把密钥去请求。

#### 在控制台里改 config.yaml 是安全的吗

这块功能会动你服务器上的**生产配置文件**，所以四条底线都做了，也都有测试钉住：

| 底线 | 做法 |
|------|------|
| **只动 providers 段** | 按行定位、只替换该段正文；段外的配置项、注释、空行、缩进风格逐字节不变（e2e 里比对段前/段后的 sha256） |
| **密钥不会被清空** | 界面拿到的一律是空串（只给 `has_key` 与脱敏提示），**留空 = 沿用原值**。而且原值从**文件原文**取 —— 从加载后的配置取会把 `${ENV}` 展开成明文，等于把密钥写进文件 |
| **校验不过不落盘** | 先写临时文件、用配置加载器校验、通过才原子改名覆盖；失败时原文件一字不动 |
| **随时能回退** | 每次保存前备份成 `config.yaml.bak-<时间戳>`，只保留最近 5 份 |

一个必须知道的边界：**「能写进文件」≠「服务会加载它」**。热加载走的是**严格**模式，
比如「启用的供应商用了 `${ENV}` 但环境变量没设」这种配置，编辑器会放行（那是推荐写法），
但热加载会失败、改动不生效 —— 这种情况接口会明确回一个 `strict_ok: false` 与警告，界面会红字显示。

代价说清楚：**`providers` 段内部的注释会被重渲染掉**（保留一行段首说明）。
段外的注释不受影响。所以写回前一律先备份 —— 注释真丢了能从备份里捞回来。

`PUT /v1/_admin/users/{name}` 是**部分更新**：只应用请求里给到的字段，
没给的保持原值 —— 否则界面上改个配额就会把模式一起重置掉。

模型映射的**模型名走请求体或 `?model=`，不走 URL 路径**：模型名里可能带 `/`
（比如 `qwen/qwen-max`），塞进路径就得处理转义。

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

网关自带**两个独立界面**，各自登录、互不感知：

| 入口 | 给谁 | 用什么登录 | 能做什么 |
|------|------|-----------|---------|
| `/ui/` | 普通用户 | 用户 token（`llmproxy user add` 建的） | 管自己的上游、看可用模型与用量、发一条请求试链路 |
| `/admin/` | 网关主人 | `server.admin_token` | 编辑系统上游（config.yaml）、管用户与配额、配模型范围 |

刻意**不做「同一个页面按 token 猜身份」**：那会让人分不清该拿哪个凭证，也把两类权限混在一个入口里。
两个界面各自只放行自己的静态文件（`/ui/` 取不到 `admin.js`，反之亦然），共用 `common.js` 与 `app.css`。

token 只存这个标签页的会话里，关掉标签就失效，不进 URL、Cookie 或 localStorage；
两个界面用**不同的会话键**，同一个标签页里互不覆盖。

**用户台 `/ui/`** 上能做四件事：

| 区块 | 作用 |
|------|------|
| 概览 | 身份、上游数量、累计请求与 token |
| 我的上游 | 增删改自己的上游；密钥加密落库，页面只显示尾 4 位；编辑时密钥留空表示不修改 |
| 我的模型 | 按客户端请求的 `model` 名字汇总，看它挂在哪些上游上；挂两家以上就是负载均衡 + 失败切换 |
| 我的用量 | 按 7/30/90 天看逐日逐模型的消耗与平均耗时 |
| 试一下 | 用你的 token 从网关发一条请求，直接看到是**哪个上游接走的**、耗时多少 |

**管理台 `/admin/`** 是三块：系统上游（编辑 `providers` 段）、用户（建号 / 配额 / 模型范围）、
全局用量与计价设置。

### 用户台：模型怎么配（同步 + 勾选，不写 JSON）

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

### 管理台：改完就能立刻验，不让人猜

管理员配的是**生产 config.yaml**，所以这里的三处设计都是冲着「少一步去猜」去的：

**1. 就近保存 —— 探测之前先自动把改动存下来。**
新加一家供应商、填好地址和密钥，此时它在后端还不存在，直接点探测只能报错。
所以「选模型…」会先把你这一屏的改动**保存一次**，再拿保存后的配置去探测，
并在弹窗上写明「（已先保存本次改动）」—— 不写这一句，你就不知道刚才那次点击顺手改了文件。

**2. 选模型弹窗 —— 把上游实际提供的模型列出来勾选。**
点「选模型…」，网关拿这家上游的地址和密钥去拉一次 `/v1/models`，把结果列成可勾选的清单
（带搜索、全选、清空）。勾完点「加入已选」，勾中的模型进映射表，行模式自动切到「指定映射」。
**手写模型名是兜底，不是主路径**：上游没提供 `/v1/models` 时才需要手填。

**3. 快速测试 —— 每家上游旁边有「测试」，按一次就够。**
按下去就真发一条 `max_tokens=8` 的极小请求，回报**哪家上游接的、真正打出去的上游模型名、
耗时、以及上游回的那句话**。密钥过期、地址配错、这家整个不可用，当场就能看出来。

粒度刻意是**每家一次**，不是每条映射一次：这一步的目标是「确认这家能用」，不是让人在这里
输入模型名。模型名由服务端自己挑 —— 有映射就用第一条映射的上游名，直通型就先去问上游要一份
模型列表、拿第一个真实名字（编一个名字打过去只会换回 404，那不叫测试）。
测试用的是**当前编辑区**的地址与密钥，所以刚改完还没保存也能测，而且测试本身不改配置。

这套探针有三条刻意的约束，e2e 里有断言钉住：

| 约束 | 为什么 |
|------|--------|
| **不写记账、不落请求日志** | 管理员的探测不该出现在用量报表里，否则对账时会对不上 |
| **不计入任何用户配额** | 探测花的是网关主人的钱（几个 token），但绝不能吃掉用户的额度 |
| **不影响熔断状态** | 否则「点几次测试」就能把一家上游打进冷却，甚至被误判成真实故障 |

用户详情里的「模型范围」是另一回事，那里粒度就是**逐个模型**（继承来的每个模型、以及每条
自己的映射，各带一个「测试」），因为要回答的是「这个模型**对他**通不通」。两个细节：

- **继承模式下也会把继承到的模型逐个列出来**。继承是默认路径（见下一节），不列出来的话
  这里的测试对绝大多数用户根本够不着 —— 而且「继承」不等于「上游一定可用」。
- 报错只占一格：上游的错误常常是一大坨 JSON（404 时它会把可用分组全列出来），
  单元格里只放一句短的（如「上游返回 HTTP 404」），完整内容挂在 `title` 上（鼠标停一下看全），
  单元格自身也有 `max-width` 兜底。否则一行报错就能把整张表撑变形。

### 消费模式：让用户消费「系统上游」

上面的多用户模式里，用户是**自带**上游的（自己的 base_url 和 api_key），网关不替他付钱。
消费模式是另一种：用户用**系统上游**（`providers` 里那些全局供应商），账单归网关主人，
因此必须可计量、可限额。

```bash
# 1) 把用户切成消费模式
./llmproxy user mode alice consumption

# 2) 给他能用的模型（这既是白名单，也是「下游名 → 供应商侧模型名」的映射）
./llmproxy user add-model alice fast -upstream deepseek-flash
./llmproxy user add-model alice pro  -upstream deepseek-v4-pro -provider deepseek   # 限定某家供应商

# 3) 配额与限流（0 或省略 = 不限）
./llmproxy user quota  alice -tokens 50000000 -cost 100
./llmproxy user limits alice -rpm 120 -concurrent 8

./llmproxy user models alice      # 看白名单
./llmproxy user show   alice      # 模式 / 配额 / 限流 / 本月消费
```

**模型范围默认是「继承系统池」**：用户没配自己的映射时，能用的就是他所在系统池声明的全部模型 ——
所以新建一个消费用户，管理员只要建号 + 设配额，**不必逐用户配模型**，用户开箱可用。

只有需要「给他收窄」或「给他换个名字」时，才用 `add-model` 给他一份自己的列表：

```bash
./llmproxy user add-model alice fast -upstream deepseek-flash   # 从此他只能用 fast 这一个
./llmproxy user models alice                                     # 看他的模型范围
```

要放开回继承，清空映射即可（控制台里把「模型范围」切回「继承系统池」，或 `DELETE /v1/_admin/users/{name}/models`）。

**收窄模式下的一条映射是三层里的前两层**，第三层由供应商自己那层负责：

```
第 1 层  客户端发来的名字        user_models.model      ← 白名单，必须命中，否则 403
第 2 层  供应商侧的模型名        user_models.upstream   ← 留空 = 与第 1 层同名
第 3 层  真正打出去的上游模型名  供应商 models 映射的值   ← 各供应商可以各不相同
```

**候选资格由「这家自己声明了没有」决定**：某家供应商的 `models` 里点名了第 2 层那个名字
（或它是直通 / catch-all），它才是候选；没声明的直接出局，**不会**被硬套上一个模型名转发出去。
映射完再把这家收成「只承接这一个模型」，交给统一的选路逻辑按权重分流 + 失败切换。

所以「让一个名字同时走多家」的写法是：**每家各自声明同名映射**，行里不限供应商：

```yaml
providers:
  - name: deepseek-official
    models: { deepseek: deepseek-chat }     # 第 2→3 层：deepseek 在这家叫 deepseek-chat
  - name: neolink
    models: { deepseek: gp-5.6-so }         # 同一个第 2 层名字，在这家叫 gp-5.6-so
```

```bash
./llmproxy user add-model arthur deepseek      # 两家都是候选，按权重分流
./llmproxy user add-model arthur deepseek -provider neolink   # 只想走一家就点名
```

`deepseek` 这个下游名客户端直接发；到了供应商那层仍是 `deepseek`（第 2 层留空=同名），
再被各家映射成自己的真实名（第 3 层）。要**真三层**就显式写第 2 层：
`add-model arthur fast -upstream deepseek` —— 客户端发 `fast`，供应商侧看的是 `deepseek`。

**没人声明就明确失败。** 如果池子里一家都没声明这个名字（也没有直通兜底的那家），
请求会返回 `502 upstream_unavailable` 并说清「系统池里没有一家供应商声明了模型 X」，
而不是硬转发出去、让上游回一个 400。这是刻意的：错误更早、更清楚，代价是映射要写全。

**继承列表里只会出现「系统池里显式声明过」的模型名**，所以直通型上游（`models: ["*"]`）
的模型天然不在里面 —— 它们在 config.yaml 里一个名字都没声明，不是漏了，是声明里就没有。
对这个用户来说，任何模型名仍然会原样转给它们，**他的可用范围比这张表看起来的要宽**。
管理台在「模型范围」下面会单独列出这几家直通型上游并说明原因，再给一个按钮去探测它们
`/v1/models` 实际提供什么（那份列表是参考信息，不是白名单）。
想知道某个用户到底能不能用某个名字，直接在他详情里点那个名字的「测试」最可靠。

> ⚠️ 语义变更（v1.2）：`user_models` 为空**从「一个模型都不能用」变成「继承系统池的全部」**。
> 已有用户（配过映射的）行为不变，但新建用户的行为完全不同 —— 别再以为「没配就是坏的」。
>
> 护栏也随之转移：想限制用户用哪些模型，**最直接的做法是系统池不暴露那个模型**（在控制台里编辑
> `providers` 那一段），再加上配额兜底 —— 权限写在你看得见的一份 config.yaml 里，而不是散在 N 个用户的映射表里。

三条语义，用之前先看清楚：

1. **只有走系统上游的消耗才算进配额**。用户自己配了上游并且某个模型走了自己的上游，
   那部分是他自己和供应商结算，不占额度（每次请求用哪边由模型的映射决定）。
2. **配额是软限制**。判定发生在请求之前，并发请求最多可能超出「同时在飞」的那几条；
   跨过上限的那一条会放行，之后的才拒。要精确到分就不是估算，那是支付系统的活。
3. **金额分清两层**（设计见 `docs/pricing-design.md`）：
   - **上游成本**（我们付给供应商多少）已经**按请求冻结**：每条请求落库时用「该请求开始时刻」
     生效的价目行（`provider_prices`）把金额算好写死，之后改价不影响历史 ——
     `llmproxy stats` 的 `COST` 列就是它，`FROZEN` 列是其中已冻结的请求数
     （与 `REQ` 相减就是还没冻结的「估算段」，两段别混着看）。价目**只在整点生效**，
     跨点请求整单按开始时刻的价。写价目：`PUT /v1/_admin/prices/provider`。
   - **向用户收多少**（分发价 `user_prices`）同样**按请求冻结**：报价取 `user:<用户名>`
     优先、没有则回落 `default`，算好写进请求行。配额与用量报表读的都是它。

   两条口径的关系：**冻结优先，未冻结的部分按下面那张 `pricing` 表估算兜底**。
   兜底是刻意的 —— 配额必须一直有效，不能因为"还没给某个模型录价目"就整段失效；
   切换期的同一天聚合行可能一半冻结一半没冻结，这时按请求数把估算部分摊出来。
   纯成本的报表（`stats`）则严格分段：`FROZEN` 列告诉你哪些请求的成本是冻结的。

   两种口径都只做计量，不做预付款、不做扣款、不做对账 —— 那是支付系统的活。

### 价目从哪来：`provider_prices` / `user_prices`

`config.yaml` 里的 `pricing` 是**单用户时代的估算表**（按模型名、无供应商维度、无历史），
现在退居为「没有价目行时的兜底估算」。真正的价目存在库里，带历史：

| 表 | 是什么 | 用在哪 |
|---|---|---|
| `provider_prices` | 上游价：供应商 × 上游模型 × 生效期 | 冻结上游成本；规则 B 的路由择廉 |
| `user_prices` | 分发价：`default` 或 `user:<名>` × 下游模型 × 生效期 | 冻结向用户收多少；配额与用量报表 |

三条规则：

- **只在整点生效**：`valid_from` 必须是整点，接口会**拒绝**非整点（不静默取整 ——
  静默取整会让"我以为立即生效"的账对不上）。
- **按时间只追加**：同一 (供应商, 模型) 插入新价时，此前有效的行自动收口成
  `[旧.valid_from, 新.valid_from)`，历史天然保留，随时可回溯。
- **折扣不单独建模**：改价时插一条新行、`note` 里写明折扣来源即可（路由只关心有效价）。
- **分时段计价**：价目行自带峰谷规则。DeepSeek 明码标价「空闲时段是高峰价的一半」，
  所以单价是「供应商 × 模型 × 时段」的函数：

  ```json
  {"peak_hours": ["09:00-12:00", "14:00-18:00"], "off_peak_ratio": 0.5, "peak_tz": "+08:00"}
  ```

  填进去的单价是**高峰价**，落在空闲时段时乘 `off_peak_ratio`。三个字段都可空，
  为空则**逐字段**沿用 `config.yaml` 的 `pricing` 段（只填时段、时区仍用全局的，
  这种混着写是支持的）。

  `peak_tz` 最好显式给：时段是按**供应商所在时区**解释的，而服务器多半跑在 UTC ——
  把 DeepSeek 的 `09:00-12:00` 当本地时间用会错位 8 小时，正好把高峰判成空闲，账差一倍。
  取值是**固定偏移**（`"+08:00"`、`"-05:30"`）而不是 `Asia/Shanghai` 这类名字：
  固定偏移不依赖系统 tzdata，而 Alpine/musl 的精简镜像里常常没有 zoneinfo。

  判哪一档用的是**请求开始时刻** —— 与上面「取哪条价目行」同一个时刻，
  一个请求一个价，可审计。只认「周一~周五」，**不识别中国法定节假日**：
  法定节假日会按高峰价算，属偏高估（不会低估）。

```bash
# 录一条上游价（时间是 RFC3339，必须整点）：单价单位是「每百万 token」
curl -X PUT http://127.0.0.1:8787/v1/_admin/prices/provider \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"provider":"deepseek","upstream_model":"deepseek-flash",
       "valid_from":"2026-09-22T00:00:00+08:00",
       "in_hit":0.04,"in_miss":2.0,"in_write":2.0,"out":8.0,
       "peak_hours":["09:00-12:00","14:00-18:00"],"off_peak_ratio":0.5,"peak_tz":"+08:00",
       "note":"官网高峰价，空闲×0.5"}'

curl "http://127.0.0.1:8787/v1/_admin/prices/provider?provider=deepseek&upstream_model=deepseek-flash" \
  -H "Authorization: Bearer $ADMIN"     # 看历史（含被收口的旧行）
curl http://127.0.0.1:8787/v1/_admin/prices/effective -H "Authorization: Bearer $ADMIN"   # 当前在效的全部价目
```

### 单价表 `pricing`（兜底估算）

这张表是单用户时代的遗留：按模型名、无供应商维度、无历史，**改价会重算历史**。
现在它只在"某个模型还没录 `user_prices` 价目行"时兜底估算 —— 正式报价请录到价目表里。

不配也能用消费模式，只是没有金额可看（只统计 token）。

```yaml
pricing:
  currency: CNY
  off_peak_ratio: 0.5                  # 空闲时段 = 高峰价 × 系数；不写就不分时段
  peak_hours: ["09:00-12:00", "14:00-18:00"]   # 高峰时段，仅周一~周五（不识别法定节假日）
  peak_tz: "+08:00"                    # 时段按哪个时区判（固定偏移）；不写按 UTC —— 服务器在 UTC，务必显式给
  models:
    # 单价单位是「每百万 token」，和各家官网报价口径一致
    deepseek-flash:  {cache_hit: 0.04, cache_miss: 2.0, output: 8.0}
    deepseek-v4-pro: {cache_hit: 0.30, cache_miss: 9.0, output: 27.0}
    "*":             {cache_hit: 0,    cache_miss: 0,   output: 0}    # 兜底：未列出的模型按 0 算
```

**为什么输入要分命中/未命中**：DeepSeek 的缓存命中价只有未命中的 **1/50**
（0.04 元 vs 2 元每百万 token）。不区分的话，agent 这类「长前缀反复复用」的负载
金额能高估一个量级。网关两种形状都认：

- DeepSeek 风格：`usage.prompt_cache_hit_tokens` / `prompt_cache_miss_tokens`（显式两个数）
- OpenAI / Azure 风格：`usage.prompt_tokens_details.cached_tokens`（只有命中数，
  未命中由 `prompt_tokens - cached_tokens` 减出来）—— 不少聚合商是这一种

**两套都不回报时**，按「输入全部未命中」算，属于偏保守的口径 —— 宁可高估，不要漏计。

只认第一种的话，第二类上游的命中会被记成 0：**命中率凭空消失、金额按全未命中高估**。
所以看到某家供应商的命中/未命中都是 0 而 prompt 不为 0，先确认它到底报的是哪种形状。

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
  ui/                网页控制台的源文件，编译时 go:embed 进二进制
                     admin.html / admin.js（管理台）、user.html / user.js（用户台）、
                     common.js / app.css（两边共用）、embed.go（嵌入声明）
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
