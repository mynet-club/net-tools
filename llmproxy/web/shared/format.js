// 两个 SPA 共用的数字/单位格式化。

export const num = (v) => (v == null ? '—' : Number(v).toLocaleString('zh-CN'))

export const money = (v, cur) => {
  const n = Number(v || 0)
  return (n >= 1 ? n.toFixed(2) : n.toFixed(4)) + (cur ? ' ' + cur : '')
}

export const ms = (v) => (v == null || v === 0 ? '—' : Math.round(v) + 'ms')

// 缓存命中率：两边都是 0 表示上游没回报拆分，是「不知道」而不是 0%。
export const hitRate = (hit, miss) => {
  const h = Number(hit || 0)
  const m = Number(miss || 0)
  return h + m > 0 ? ((h * 100) / (h + m)).toFixed(1) + '%' : '—'
}
