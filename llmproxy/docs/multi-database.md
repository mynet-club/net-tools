# 多数据库支持（v2.2）

> 状态：方言层已落地（sqlite / mysql / postgres）；本文件是运维侧的对照与回滚说明。
>
> 与 §3.2「SQLite 唯一事实存储」的关系：**有意放宽**——只做存储可替换，
> 不做分布式、不做连接池中间件、不改计费语义。

## 配置形状

```yaml
database:
  driver: sqlite          # sqlite | mysql | postgres；省略 = sqlite
  path: ""                # sqlite 的文件路径（默认 <runtime>/data/llmproxy.db）
  dsn: ""                 # mysql / postgres 连接串，支持 ${ENV}
  retain_days: 90         # 0 = 永久保留请求明细（计价冻结账本）
```

示例：

```yaml
# MySQL
database:
  driver: mysql
  dsn: "llmproxy:${MYSQL_PASSWORD}@tcp(127.0.0.1:3306)/llmproxy?parseTime=true&charset=utf8mb4"

# PostgreSQL
database:
  driver: postgres
  dsn: "postgres://llmproxy:${PG_PASSWORD}@127.0.0.1:5432/llmproxy?sslmode=disable"
```

## 通用数据库操作界面

业务包（server / CLI / UI）只认 `store.DB` 接口，**不写 SQL**。
方言差异关在 `store.Dialect`：

| 职责 | SQLite | MySQL | PostgreSQL |
|---|---|---|---|
| 占位符 | `?` | `?` | `$1…$n`（`Rebind`） |
| Upsert | `ON CONFLICT … DO UPDATE` | `ON DUPLICATE KEY UPDATE` | `ON CONFLICT … DO UPDATE` |
| 自增主键 | `INTEGER PRIMARY KEY AUTOINCREMENT` | `BIGINT AUTO_INCREMENT` | `BIGSERIAL` |
| 浮点 | `REAL` | `DOUBLE` | `DOUBLE PRECISION` |
| 连接池 | `MaxOpenConns(1)`（单文件语义） | 8 / 4 | 8 / 4 |
| 表/列探测 | `sqlite_master` / `pragma_table_info` | `information_schema` | `information_schema` |

schema 常量只维护 **SQLite 一份**，`RewriteDDL` 负责翻译；
`execSchema` 拆开逐条执行，避开各驱动对多语句 Exec 的差异。

## 字段与语义不变

换驱动**不改**这些口径（有回归测试钉住）：

- 金额：`store.RowCharge` 冻结优先，失败请求不进摊分分母
- 价目：请求开始时刻冻结，改价不重算历史
- `retain_days: 0` = 永久保留
- 熔断状态按 `(scope, name)` 分桶

时间戳一律存 Unix 毫秒（INTEGER/BIGINT），不依赖各库的 DATETIME 语义。

## 从 SQLite 迁出

**不自动搬数据**（避免半迁移状态）。步骤：

1. 停服务（`llmproxy stop`，确认 WAL 已 checkpoint）；
2. 在目标库建空库，起一次服务让 `OpenDialect` 跑完 DDL；
3. 用 `sqlite3 .dump` / `pgloader` / 自写脚本把表按对照搬过去；
4. 改 `database.driver` + `dsn`，重启；
5. 用 `llmproxy status` 与 `llmproxy stats` 对账：用户数、请求明细数、冻结金额合计。

表清单（主键与冻结列必须原样）：

- `requests` — 计价冻结账本（`price_upstream_id` / `cost_upstream` / `charge` / `currency`）
- `usage_daily` / `usage_user_daily` — 聚合用量
- `users` / `user_models` / `user_providers` — 多用户
- `provider_prices` / `user_prices` — 两层价目（带 `valid_from`/`valid_to` 历史）
- `provider_stats` — 熔断状态
- `meta` — `revision` 计数

## 回滚

1. **改配置回 sqlite + 原 path**，重启 —— schema 无破坏性变更，旧二进制也能读；
2. 若已经写入 MySQL/PG 一段时间，需要把这段时间的数据导回 SQLite（反向搬迁）；
3. 任何 schema 变更必须：加列/加表，不删不改语义；回滚前 `sqlite3 .dump` 留一份。

## 测试矩阵

| 层 | 覆盖 | 怎么跑 |
|---|---|---|
| 单测 | `dialect_test.go`：Rebind / Upsert / RewriteDDL / splitStatements | `go test ./internal/store` |
| 集成（SQLite） | `integration_test.go` 业务语义套件，**始终跑** | 同上 |
| 集成（MySQL / PG） | 同一套断言打真库 | 见下 |

真库由环境变量驱动，没配就 `t.Skip`（绝不静默假绿）：

```bash
export LLMPROXY_TEST_MYSQL_DSN='user:pass@tcp(127.0.0.1:3306)/llmproxy_test?parseTime=true'
export LLMPROXY_TEST_PG_DSN='postgres://user:pass@127.0.0.1:5432/llmproxy_test?sslmode=disable'
go test ./internal/store -run Integration -v
```

一键脚本：

```bash
./scripts/test-matrix.sh              # 只 SQLite
./scripts/test-matrix.sh --docker     # 起一次性 mysql:8.0 / postgres:16 容器再跑
./scripts/test-matrix.sh --all        # docker + 已有 *_DSN
```
