# llmproxy 路线图

> 起点：v2.2.0（多数据库，默认 sqlite）
> 边界不变：OpenAI 兼容、单二进制、自托管。不做支付通道、不做通用多租户 SaaS。

## 总览

| 版本 | 主题 | 状态 |
|---|---|---|
| v2.3 | 计费与运营闭环 | 完成 |
| v2.4 | 用户与开发者体验 | 完成 |
| v2.5 | 规模与生态 | 完成 |

---

## v2.3 — 计费与运营闭环

钱花在哪、快超了没有、怎么对账、怎么给用户一个说法。

| # | 提交 | 内容 | 验收 |
|---|---|---|---|
| 1 | `store: usage export rows + monthly rollup` | 按用户/模型/日导出查询；月合计 | store 测试 |
| 2 | `cli: llmproxy export csv + admin download` | CLI 导出 CSV；管理台 `/usage.csv` | 与 API 金额一致 |
| 3 | `alerts: quota threshold webhook` | 用量 80%/100% 触发 webhook 或日志 | 可配置 URL |
| 4 | `audit: admin action log` | 改价/建删用户等落审计表 | 可查、不记密钥 |
| 5 | `quota: hard spend cap + auto-pause` | 月花费到阈值自动停用，可一键恢复 | 与软配额互补 |

**不做**：充值、发票、支付。

---

## v2.4 — 用户与开发者体验

| # | 提交 | 内容 | 验收 |
|---|---|---|---|
| 1 | `docs: OpenAPI spec for gateway APIs` | `/v1` 与 `/v1/_admin` 的 OpenAPI 3 | 可被 Swagger UI 加载 |
| 2 | `ui: playground in user console` | 试模型、看路由、看预估花费 | 用户台只读 + 发一次请求 |
| 3 | `ui: model catalog with prices` | 下游名→各上游名/单价/说明 | 与 `/v1/_me/routing` 同源 |
| 4 | `ui: token rotate + usage curve` | 用户自助换 token、看月用量曲线 | 密钥只回显一次 |
| 5 | `events: webhook for failures and quota` | `request.failed` / `quota.exceeded` / `circuit.open` | 失败可重试、不阻塞主路径 |

---

## v2.5 — 规模与生态

| # | 提交 | 内容 | 验收 |
|---|---|---|---|
| 1 | `metrics: prometheus text exposition` | `/metrics` 文本（JSON 已有） | 可被 Prometheus 抓 |
| 2 | `probe: active upstream health` | 定时探活，不只靠请求失败 | 熔断恢复更快 |
| 3 | `grafana: dashboard json` | 延迟/错误/熔断/花费面板 | 导入即用 |
| 4 | `docs: multi-instance notes` | 粘性/限流共享存储的取舍说明 | 不引入 Redis 默认路径 |

多实例共享存储（Redis 等）**不进默认路径**，只写清取舍。

---

## 节奏

```
v2.3  导出 → 告警 → 审计 → 硬配额
v2.4  OpenAPI → Playground → 目录 → token → webhook
v2.5  /metrics → 探活 → Grafana → 文档
```

每笔一个提交，`release-check.sh` 全绿再进下一笔。
