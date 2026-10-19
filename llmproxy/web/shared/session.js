// 会话存储：只进 sessionStorage（关闭标签即失效），不进 URL / Cookie / localStorage。
// 两个界面各用各的前缀，同源下不会互相覆盖。

export function createSession(key) {
  const k = (name) => key + '.' + name
  return {
    load() {
      return {
        base: sessionStorage.getItem(k('base')) || '',
        bearer: sessionStorage.getItem(k('bearer')) || '',
        identity: sessionStorage.getItem(k('identity')) || '',
        who: sessionStorage.getItem(k('who')) || '',
      }
    },
    save({ base, bearer, identity, who }) {
      if (base !== undefined) sessionStorage.setItem(k('base'), base)
      if (bearer !== undefined) sessionStorage.setItem(k('bearer'), bearer)
      if (identity !== undefined) sessionStorage.setItem(k('identity'), identity || '')
      if (who !== undefined) sessionStorage.setItem(k('who'), who || '')
    },
    clear() {
      for (const n of ['base', 'bearer', 'identity', 'who']) sessionStorage.removeItem(k(n))
    },
  }
}
