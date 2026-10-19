<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@shared/api'
import AppShell from '../components/AppShell.vue'

const me = ref(null)
const busy = ref(true)

async function load() {
  busy.value = true
  try {
    me.value = await api('/v1/_me')
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <AppShell title="概览">
    <div v-loading="busy">
      <h2 class="f-page-title">你好，{{ me?.name || '—' }}</h2>
      <p class="f-page-sub">
        当前模式：{{ me?.mode === 'consumption' ? '消费模式（可用系统上游）' : '自带上游（byo）' }}
        · {{ me?.enabled ? '账号已启用' : '账号已停用' }}
      </p>

      <div class="f-grid">
        <div class="f-card">
          <div class="f-muted">请求总数</div>
          <div style="font-size: 28px; font-weight: 700">{{ me?.usage?.requests ?? '—' }}</div>
        </div>
        <div class="f-card">
          <div class="f-muted">成功 / 失败</div>
          <div style="font-size: 28px; font-weight: 700">
            {{ me?.usage?.ok ?? '—' }} / {{ me?.usage?.failed ?? '—' }}
          </div>
        </div>
        <div class="f-card">
          <div class="f-muted">Token 合计</div>
          <div style="font-size: 28px; font-weight: 700">{{ me?.usage?.total_tokens ?? '—' }}</div>
        </div>
        <div class="f-card">
          <div class="f-muted">我的上游</div>
          <div style="font-size: 28px; font-weight: 700">{{ me?.provider_count ?? 0 }}</div>
        </div>
      </div>
    </div>
  </AppShell>
</template>
