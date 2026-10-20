import { createRouter, createWebHashHistory } from 'vue-router'
import { configure } from '@shared/api'
import { createSession } from '@shared/session'

// hash 路由：静态包可以被机构原样替换/托管，不需要服务端 rewrite。
export const session = createSession('llmproxy.user')

const routes = [
  { path: '/login', name: 'login', component: () => import('./views/Login.vue'), meta: { public: true } },
  { path: '/oauth-callback', name: 'oauth-callback', component: () => import('./views/OAuthCallback.vue'), meta: { public: true } },
  { path: '/', redirect: '/overview' },
  { path: '/overview', name: 'overview', component: () => import('./views/Overview.vue'), meta: { title: '概览' } },
  { path: '/token', name: 'token', component: () => import('./views/Token.vue'), meta: { title: '我的 API Token' } },
  { path: '/providers', name: 'providers', component: () => import('./views/Providers.vue'), meta: { title: '我的上游' } },
  { path: '/models', name: 'models', component: () => import('./views/Models.vue'), meta: { title: '我的模型' } },
  { path: '/usage', name: 'usage', component: () => import('./views/Usage.vue'), meta: { title: '我的用量' } },
  { path: '/try', name: 'try', component: () => import('./views/Try.vue'), meta: { title: '试一下' } },
  { path: '/knowledge', name: 'knowledge', component: () => import('./views/Knowledge.vue'), meta: { title: '知识检索' } },
  { path: '/:pathMatch(.*)*', redirect: '/overview' },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

router.beforeEach((to) => {
  const s = session.load()
  if (s.base) configure({ base: s.base })
  const authed = Boolean(s.bearer || s.identity)
  if (!to.meta.public && !authed) return { name: 'login' }
  if (to.name === 'login' && authed) return { name: 'overview' }
  return true
})

export default router
