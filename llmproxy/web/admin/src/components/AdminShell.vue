<script setup>
import { useRouter } from 'vue-router'
import FLayout from '@shared/layout/FLayout.vue'
import { session } from '../router'

defineProps({ title: { type: String, default: '' } })

const router = useRouter()
const navItems = [
  { to: '/overview', label: '概览' },
  { to: '/users', label: '用户' },
  { to: '/config', label: '配置' },
  { to: '/audit', label: '操作审计' },
  { to: '/legacy', label: '高级面板' },
]

function logout() {
  session.clear()
  router.push('/login')
}
</script>

<template>
  <FLayout :title="title" :nav-items="navItems" subtitle="管理控制台">
    <template #head>
      <el-button text @click="logout">退出</el-button>
    </template>
    <template #foot>llmproxy admin</template>
    <slot />
  </FLayout>
</template>
