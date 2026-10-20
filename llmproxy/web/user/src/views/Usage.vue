<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@shared/api'
import { hitRate, money, ms, num } from '@shared/format'
import AppShell from '../components/AppShell.vue'

const days = ref(7)
const rows = ref([])
const totals = ref({})
const cost = ref({})
const busy = ref(false)

const bars = computed(() => {
  const byDay = {}
  for (const r of rows.value) byDay[r.day] = (byDay[r.day] || 0) + (r.total_tokens || 0)
  const keys = Object.keys(byDay).sort().slice(-14)
  const max = Math.max(1, ...keys.map((d) => byDay[d]))
  return keys.map((d) => ({ day: d, tokens: byDay[d], h: Math.max(4, Math.round((byDay[d] / max) * 100)) }))
})

async function load() {
  busy.value = true
  try {
    const data = await api('/v1/_me/usage?days=' + days.value)
    rows.value = data.rows || []
    totals.value = data.totals || {}
    cost.value = data.cost || {}
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
  <AppShell title="我的用量">
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 6px">
      <h2 class="f-page-title" style="margin: 0">我的用量</h2>
      <el-radio-group :model-value="days" size="small" @change="pick">
        <el-radio-button :value="7">近 7 天</el-radio-button>
        <el-radio-button :value="30">近 30 天</el-radio-button>
        <el-radio-button :value="90">近 90 天</el-radio-button>
      </el-radio-group>
    </div>
    <p class="f-page-sub">只统计经过本网关的请求；自有上游的消耗也会计入用量，但金额只系统付费的那部分。</p>

    <div class="f-grid" style="margin-bottom: 18px">
      <div class="f-card"><div class="f-muted">请求</div><div class="f-big">{{ num(totals.requests) }}</div></div>
      <div class="f-card"><div class="f-muted">成功 / 失败</div><div class="f-big">{{ num(totals.ok) }} / {{ num(totals.failed) }}</div></div>
      <div class="f-card"><div class="f-muted">输入 / 输出 token</div><div class="f-big">{{ num(totals.prompt_tokens) }} / {{ num(totals.completion_tokens) }}</div></div>
      <div class="f-card">
        <div class="f-muted">输入缓存命中率</div>
        <div class="f-big">{{ hitRate(totals.cache_hit_tokens, totals.cache_miss_tokens) }}</div>
      </div>
      <div class="f-card">
        <div class="f-muted">{{ cost.priced ? '本月系统消费' : 'Token 合计' }}</div>
        <div class="f-big">
          {{ cost.priced ? money(cost.month_system, cost.currency || 'CNY') : num(totals.total_tokens) }}
        </div>
      </div>
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

    <el-table v-loading="busy" :data="rows" border style="width: 100%">
      <el-table-column prop="day" label="日期" width="110" />
      <el-table-column prop="provider" label="上游" min-width="140" />
      <el-table-column prop="model" label="模型" min-width="160" />
      <el-table-column prop="requests" label="请求" width="80" align="right" />
      <el-table-column prop="ok" label="成功" width="80" align="right" />
      <el-table-column prop="failed" label="失败" width="80" align="right" />
      <el-table-column label="输入" width="110" align="right">
        <template #default="{ row }">{{ num(row.prompt_tokens) }}</template>
      </el-table-column>
      <el-table-column label="缓存命中" width="100" align="right">
        <template #default="{ row }">{{ num(row.cache_hit_tokens) }}</template>
      </el-table-column>
      <el-table-column label="命中率" width="90" align="right">
        <template #default="{ row }">{{ hitRate(row.cache_hit_tokens, row.cache_miss_tokens) }}</template>
      </el-table-column>
      <el-table-column label="输出" width="110" align="right">
        <template #default="{ row }">{{ num(row.completion_tokens) }}</template>
      </el-table-column>
      <el-table-column label="合计" width="110" align="right">
        <template #default="{ row }">{{ num(row.total_tokens) }}</template>
      </el-table-column>
      <el-table-column label="平均延迟" width="100" align="right">
        <template #default="{ row }">{{ ms(row.avg_latency_ms) }}</template>
      </el-table-column>
      <el-table-column label="金额" width="100" align="right">
        <template #default="{ row }">{{ row.cost != null ? row.cost.toFixed(4) : '—' }}</template>
      </el-table-column>
      <template #empty><el-empty description="这段时间还没有用量" :image-size="70" /></template>
    </el-table>
  </AppShell>
</template>

<style scoped>
.f-big {
  font-size: 22px;
  font-weight: 700;
  margin-top: 2px;
}
</style>
