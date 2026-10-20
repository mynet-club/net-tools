<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@shared/api'
import { num, money } from '@shared/format'
import AppShell from '../components/AppShell.vue'

const me = ref(null)
const busy = ref(true)

const consumption = computed(() => me.value?.mode === 'consumption')
const quota = computed(() => me.value?.quota || {})
const usage = computed(() => me.value?.usage || {})
const limits = computed(() => me.value?.limits || {})

const quotaPct = computed(() => {
  const q = quota.value
  if (!q.month_tokens || q.month_tokens <= 0) return null
  return Math.min(100, Math.round(((q.used_tokens || 0) / q.month_tokens) * 100))
})

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
        {{ consumption ? '消费模式：可用系统上游（受配额约束），自有上游优先' : '自带上游：请求只走你自己配的上游' }}
        · {{ me?.enabled ? '账号已启用' : '账号已停用' }}
      </p>

      <el-alert
        v-if="me?.broken_providers?.length"
        type="warning"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
        :title="'这些上游当前不可用：' + me.broken_providers.join('、') + '（常见原因：master.key 换过、地址或模型配置非法）'"
      />

      <div class="f-grid" style="margin-bottom: 20px">
        <div class="f-card">
          <div class="f-muted">请求总数</div>
          <div class="f-big">{{ num(usage.requests) }}</div>
        </div>
        <div class="f-card">
          <div class="f-muted">成功 / 失败</div>
          <div class="f-big">{{ num(usage.ok) }} / {{ num(usage.failed) }}</div>
        </div>
        <div class="f-card">
          <div class="f-muted">Token 合计</div>
          <div class="f-big">{{ num(usage.total_tokens) }}</div>
        </div>
        <div class="f-card">
          <div class="f-muted">我的上游</div>
          <div class="f-big">{{ me?.provider_count ?? 0 }}</div>
        </div>
      </div>

      <div v-if="consumption" class="f-card" style="margin-bottom: 20px">
        <h3 style="margin-top: 0">本月额度</h3>
        <div class="f-grid">
          <div>
            <div class="f-muted">已用 token</div>
            <div v-if="quota.month_tokens" class="f-mid">{{ num(quota.used_tokens) }} / {{ num(quota.month_tokens) }}</div>
            <div v-else class="f-mid">{{ num(quota.used_tokens) }}</div>
            <el-progress v-if="quotaPct !== null" :percentage="quotaPct" :stroke-width="8" style="margin-top: 8px" />
            <div v-else class="f-muted" style="font-size: 12px">不限 token</div>
          </div>
          <div>
            <div class="f-muted">已用金额</div>
            <div v-if="quota.month_cost" class="f-mid">{{ money(quota.used_cost, quota.currency) }} / {{ money(quota.month_cost, quota.currency) }}</div>
            <div v-else class="f-mid">{{ money(quota.used_cost, quota.currency) }}</div>
            <div v-if="!quota.month_cost" class="f-muted" style="font-size: 12px">不限金额</div>
          </div>
          <div>
            <div class="f-muted">可用模型</div>
            <div class="f-mid">{{ (me?.models || []).length }}{{ me?.models_passthrough ? ' + 全部直通' : '' }}</div>
            <div class="f-muted" style="font-size: 12px">来源：{{ me?.models_source || '—' }}</div>
          </div>
        </div>
      </div>

      <div v-if="limits.rpm || limits.max_concurrent || limits.tokens_per_min" class="f-card" style="margin-bottom: 20px">
        <h3 style="margin-top: 0">限流</h3>
        <div class="f-muted">
          <span v-if="limits.rpm">每分钟 {{ limits.rpm }} 次请求</span>
          <span v-if="limits.tokens_per_min"> · 每分钟 {{ num(limits.tokens_per_min) }} token</span>
          <span v-if="limits.max_concurrent"> · 最多 {{ limits.max_concurrent }} 个并发</span>
        </div>
      </div>

      <div class="f-card">
        <h3 style="margin-top: 0">快捷入口</h3>
        <div style="display: flex; gap: 10px; flex-wrap: wrap">
          <router-link to="/token"><el-button>创建 / 轮换 API Token</el-button></router-link>
          <router-link to="/providers"><el-button>配置我的上游</el-button></router-link>
          <router-link to="/models"><el-button>看看模型怎么路由</el-button></router-link>
          <router-link to="/try"><el-button type="primary">试一条请求</el-button></router-link>
        </div>
      </div>
    </div>
  </AppShell>
</template>

<style scoped>
.f-big {
  font-size: 28px;
  font-weight: 700;
}
.f-mid {
  font-size: 20px;
  font-weight: 600;
  margin-top: 4px;
}
</style>
