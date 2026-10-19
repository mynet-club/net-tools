<script setup>
import { useRoute } from 'vue-router'
import AppShell from '../components/AppShell.vue'

const route = useRoute()
</script>

<template>
  <AppShell :title="route.meta.title || ''">
    <h2 class="f-page-title">{{ route.meta.title }}</h2>
    <p class="f-page-sub">这个页面在 P2 按 F 型布局与 UX 重做，当前先保留导航骨架。</p>
  </AppShell>
</template>
