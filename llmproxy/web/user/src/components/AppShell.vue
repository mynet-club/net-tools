<script setup>
import { useRouter } from 'vue-router'
import FLayout from '@shared/layout/FLayout.vue'
import { session } from '../router'

defineProps({ title: { type: String, default: '' } })

const router = useRouter()
const who = session.load().who

const navItems = [
  { to: '/overview', label: '概览' },
  { to: '/token', label: '我的 API Token' },
  { to: '/providers', label: '我的上游' },
  { to: '/models', label: '我的模型' },
  { to: '/usage', label: '我的用量' },
  { to: '/try', label: '试一下' },
  { to: '/knowledge', label: '知识检索' },
]

function logout() {
  session.clear()
  router.push('/login')
}
</script>

<template>
  <FLayout :title="title" :nav-items="navItems" subtitle="用户控制台">
    <template #head>
      <span class="f-muted">{{ who }}</span>
      <el-button text @click="logout">退出</el-button>
    </template>
    <template #foot>llmproxy</template>
    <slot />
  </FLayout>
</template>
