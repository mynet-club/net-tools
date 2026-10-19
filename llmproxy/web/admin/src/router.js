import { createRouter, createWebHashHistory } from 'vue-router'
import { configure } from '@shared/api'
import { createSession } from '@shared/session'

export const session = createSession('llmproxy.admin')

const routes = [
  { path: '/login', name: 'login', component: () => import('./views/Login.vue'), meta: { public: true } },
  { path: '/', redirect: '/home' },
  { path: '/home', name: 'home', component: () => import('./views/Home.vue'), meta: { title: '概览' } },
  { path: '/:pathMatch(.*)*', redirect: '/home' },
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
  if (to.name === 'login' && authed) return { name: 'home' }
  return true
})

export default router
