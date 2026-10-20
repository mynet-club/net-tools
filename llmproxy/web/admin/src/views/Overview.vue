<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@shared/api'
import { money, num } from '@shared/format'
import AdminShell from '../components/AdminShell.vue'

const days = ref(7)
const stats = ref(null)
const config = ref(null)
const busy = ref(false)

const totals = computed(() => stats.value?.totals || {})
const bars = computed(() => {
  const rows = stats.value?.by_day || []
  const max = Math.max(1, ...rows.map((r) => r.total_tokens || 0))
  return rows.slice(-14).map((r) => ({
    day: r.day,
    tokens: r.total_tokens || 0,
    h: Math.max(4, Math.round(((r.total_tokens || 0) / max) * 100)),
  }))
})
const currency = computed(() => config.value?.pricing_currency || 'CNY')

async function load() {
  busy.value = true
  try {
    const [st, cfg] = await Promise.all([
      api('/v1/_admin/stats?days=' + days.value),
      api('/v1/_admin/config'),
    ])
    stats.value = st
    config.value = cfg
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    busy.value = false
  }
}

function pick(n) {
  days.value = n
  load()
}

onMounted(load)
</script>

<template>
  <AdminShell title="概览">
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 6px">
      <h2 class="f-page-title" style="margin: 0">概览</h2>
      <el-radio-group :model-value="days" size="small" @change="pick">
        <el-radio-button :value="7">7 天</el-radio-button>
        <el-radio-button :value="30">30 天</el-radio-button>
        <el-radio-button :value="90">90 天</el-radio-button>
      </el-radio-group>
    </div>
    <p class="f-page-sub">整台网关的请求、token 与系统付费金额（窗口 {{ days }} 天）。</p>

    <div v-loading="busy">
      <div class="f-grid" style="margin-bottom: 18px">
        <div class="f-card"><div class="f-muted">请求</div><div class="f-big">{{ num(totals.requests) }}</div></div>
        <div class="f-card"><div class="f-muted">成功 / 失败</div><div class="f-big">{{ num(totals.ok) }} / {{ num(totals.failed) }}</div></div>
        <div class="f-card"><div class="f-muted">Token 合计</div><div class="f-big">{{ num(totals.total_tokens) }}</div></div>
        <div class="f-card"><div class="f-muted">系统付费</div><div class="f-big">{{ money(totals.charge, currency) }}</div></div>
      </div>

      <div v-if="bars.length" class="f-card" style="margin-bottom: 18px">
        <h3 style="margin-top: 0">按天 token</h3>
        <div style="display: flex; align-items: flex-end; gap: 6px; height: 120px">
          <div v-for="b in bars" :key="b.day" style="flex: 1; text-align: center" :title="b.day + ' · ' + num(b.tokens) + ' token'">
            <div style="height: 96px; display: flex; align-items: flex-end">
              <div style="width: 100%; background: #4f46e5; border-radius: 4px 4px 0 0" :style="{ height: b.h + '%' }" />
            </div>
            <div class="f-muted" style="font-size: 11px">{{ b.day.slice(5) }}</div>
          </div>
        </div>
      </div>

      <div v-if="config?.providers?.length" class="f-card" style="margin-bottom: 18px">
        <h3 style="margin-top: 0">系统上游</h3>
        <el-table :data="config.providers" size="small" border>
          <el-table-column prop="name" label="名称" width="150" />
          <el-table-column prop="base_url" label="地址" min-width="240" />
          <el-table-column label="状态" width="90">
            <template #default="{ row }">
              <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '启用' : '停用' }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="api_key_hint" label="密钥" width="140" />
          <el-table-column prop="max_data_level" label="分级上限" width="100" />
        </el-table>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px">
        <div class="f-card">
          <h3 style="margin-top: 0">按模型</h3>
          <el-table :data="stats?.by_model || []" size="small" border>
            <el-table-column prop="provider" label="上游" width="120" />
            <el-table-column prop="model" label="模型" min-width="130" />
            <el-table-column prop="requests" label="请求" width="70" align="right" />
            <el-table-column label="token" width="90" align="right">
              <template #default="{ row }">{{ num(row.total_tokens) }}</template>
            </el-table-column>
            <el-table-column label="金额" width="90" align="right">
              <template #default="{ row }">{{ money(row.charge, currency) }}</template>
            </el-table-column>
          </el-table>
        </div>
        <div class="f-card">
          <h3 style="margin-top: 0">按范围</h3>
          <el-table :data="stats?.by_scope || []" size="small" border>
            <el-table-column label="范围" min-width="140">
              <template #default="{ row }">{{ row.scope?.kind }}:{{ row.scope?.id }}</template>
            </el-table-column>
            <el-table-column prop="requests" label="请求" width="80" align="right" />
            <el-table-column label="token" width="100" align="right">
              <template #default="{ row }">{{ num(row.total_tokens) }}</template>
            </el-table-column>
            <el-table-column label="金额" width="90" align="right">
              <template #default="{ row }">{{ money(row.charge, currency) }}</template>
            </el-table-column>
          </el-table>
        </div>
      </div>
    </div>
  </AdminShell>
</template>

<style scoped>
.f-big {
  font-size: 26px;
  font-weight: 700;
  margin-top: 4px;
}
</style>
