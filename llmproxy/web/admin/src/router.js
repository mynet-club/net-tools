import { createRouter, createWebHashHistory } from 'vue-router'
import { configure } from '@shared/api'
import { createSession } from '@shared/session'

export const session = createSession('llmproxy.admin')

const routes = [
  { path: '/login', name: 'login', component: () => import('./views/Login.vue'), meta: { public: true } },
  { path: '/', redirect: '/overview' },
  { path: '/overview', name: 'overview', component: () => import('./views/Overview.vue'), meta: { title: '概览' } },
  { path: '/users', name: 'users', component: () => import('./views/Users.vue'), meta: { title: '用户' } },
  { path: '/config', name: 'config', component: () => import('./views/Config.vue'), meta: { title: '配置' } },
  { path: '/audit', name: 'audit', component: () => import('./views/Audit.vue'), meta: { title: '操作审计' } },
  { path: '/legacy', name: 'legacy', component: () => import('./views/Legacy.vue'), meta: { title: '高级面板' } },
  { path: '/:pathMatch(.*)*', redirect: '/overview' },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

router.beforeEach((to) => {
  const s = session.load()
  if (s.base) configure({ base: s.base })
  const authed = Boolean(s.bearer)
  if (!to.meta.public && !authed) return { name: 'login' }
  if (to.name === 'login' && authed) return { name: 'overview' }
  return true
})

export default router
