// 两个 SPA 共用的 API 客户端。
//
// 凭证形态只有两种，互不混用：
//   - bearer：下游 token（sk-…），调模型与自助接口都用它；
//   - identity：登录换到的短时会话令牌（X-Identity-Token），只用于身份相关端点。
// 具体哪个页面带哪个由调用方决定，客户端不做「猜身份」。

export class ApiError extends Error {
  constructor(message, status, body) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.body = body
  }
}

const cfg = { base: '', bearer: '', identity: '' }

export function configure(next) {
  if (next.base !== undefined) cfg.base = String(next.base || '').replace(/\/+$/, '')
  if (next.bearer !== undefined) cfg.bearer = next.bearer || ''
  if (next.identity !== undefined) cfg.identity = next.identity || ''
}

export function currentBase() {
  return cfg.base
}

export async function api(path, opts = {}) {
  const { method = 'GET', body, headers = {} } = opts
  const h = { ...headers }
  if (cfg.bearer) h.Authorization = 'Bearer ' + cfg.bearer
  if (cfg.identity) h['X-Identity-Token'] = cfg.identity
  if (body !== undefined) h['Content-Type'] = 'application/json'

  let res
  try {
    res = await fetch(cfg.base + path, {
      method,
      headers: h,
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch (e) {
    throw new ApiError('连不上网关 ' + cfg.base + '：' + e.message, 0)
  }

  const text = await res.text()
  let data = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = null
    }
  }
  if (!res.ok) {
    const msg = data?.error?.message || data?.error?.type || `${res.status} ${res.statusText}`
    throw new ApiError(msg, res.status, data)
  }
  return data
}
