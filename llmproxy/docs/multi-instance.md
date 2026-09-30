# 多实例部署备忘

> 单二进制默认是**单实例**。多实例不是做不了，而是粘性、限流、配额的共享状态
> 会把「零外部依赖」这条卖点搭进去。本文只写取舍，**不引入 Redis 默认路径**。

## 什么在多实例下会漂

| 状态 | 现在放哪 | 多实例会怎样 |
|---|---|---|
| 会话粘性 `(用户, 会话, 模型)` | 内存 | 各实例各自钉，同一会话可能在实例间漂 → 上游前缀缓存打冷 |
| 限流 / 当月用量 | 内存 + SQLite | 各实例各算，实际额度 × 实例数 |
| 熔断状态 | 内存 + 周期落库 | 各实例独立熔断，恢复不同步 |
| 用量报表缓存 | 内存 TTL | 无害 |
| 账本 / 价目 / 用户 | SQLite 或 MySQL/PG | **共享库时正确**（v2.2 已支持） |

## 建议姿势

### 1. 小团队：一主一备，不并行扛流量

```
        ┌─ 健康检查 ─┐
客户端 ─┤  main     ├─ SQLite/MySQL ─┐
        │  (冷备)   │               │
        └───────────┘               └─ 共享库
```

备机只在切换时启动。粘性/限流不丢，语义与单机一致。

### 2. 真要水平扩：共享库 + 粘性会话

- `database` 指向 MySQL/PG（v2.2）；
- 上游负载均衡对 `x-session-affinity` 做会话保持（或 IP 哈希）；
- 接受「限流是每实例近似」—— 或者在网关前再加一层全局限流。

### 3. 将来若做共享存储（不在默认路径）

候选是 Redis，只放：粘性表、限流桶、熔断状态。**账本与价目仍走 SQL**。

需要的接口形状（写在这里免得下次重新论证）：

```go
type SharedState interface {
    AffinityGet(user, session, model string) (provider string, ok bool)
    AffinitySet(user, session, model, provider string, ttl time.Duration)
    AllowRate(user string, rpm int) bool
    AddUsage(user string, tokens int64, cost float64) error
    MarkFailure(scope, provider string, cool time.Duration) bool
}
```

内存实现是默认；Redis 实现用 build tag 或配置开关引入。

## 不做的事

- 不把 SQLite 放到 NFS 上「假装多实例」（锁与延迟会很难看）
- 不为多实例改计费语义（冻结、失败不进分母，这些和部署形态无关）
- 不在 2.x 强依赖 Redis
