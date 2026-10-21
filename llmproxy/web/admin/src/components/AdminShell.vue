<script setup>
import { useRouter } from 'vue-router'
import FLayout from '@shared/layout/FLayout.vue'
import { session } from '../router'

defineProps({ title: { type: String, default: '' } })

const router = useRouter()
const navItems = [
  { to: '/overview', label: '概览', group: '看板' },
  { to: '/config', label: '配置', group: '配置' },
  { to: '/policy-view', label: '策略观测', group: '高级配置' },
  { to: '/policy-write', label: '策略发布', group: '高级配置' },
  { to: '/processors', label: '处理器', group: '高级配置' },
  { to: '/knowledge', label: '知识源', group: '高级配置' },
  { to: '/replay', label: '回放证据链', group: '高级配置' },
  { to: '/users', label: '用户', group: '运营' },
  { to: '/audit', label: '操作审计', group: '运营' },
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
