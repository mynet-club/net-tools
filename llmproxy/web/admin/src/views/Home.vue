<script setup>
import { useRouter } from 'vue-router'
import FLayout from '@shared/layout/FLayout.vue'
import { session } from '../router'

const router = useRouter()
const navItems = [
  { to: '/home', label: '概览' },
  { to: '/home#users', label: '用户' },
  { to: '/home#config', label: '配置' },
  { to: '/home#policy', label: '策略' },
  { to: '/home#pricing', label: '价格' },
  { to: '/home#audit', label: '审计' },
  { to: '/home#replay', label: '回放' },
]

function logout() {
  session.clear()
  router.push('/login')
}
</script>

<template>
  <FLayout title="概览" :nav-items="navItems" subtitle="管理控制台">
    <template #head>
      <el-button text @click="logout">退出</el-button>
    </template>
    <template #foot>llmproxy admin</template>
    <h2 class="f-page-title">管理控制台</h2>
    <p class="f-page-sub">
      P0 只交付骨架与构建链路；用户/配置/策略/价格/审计/回放在 P3 按 F 型布局逐页迁移。
    </p>
    <div class="f-grid">
      <div class="f-card"><div class="f-muted">状态</div><div style="font-size: 22px; font-weight: 700">骨架已就绪</div></div>
      <div class="f-card"><div class="f-muted">下一步</div><div style="font-size: 22px; font-weight: 700">P1 登录后端</div></div>
    </div>
  </FLayout>
</template>
