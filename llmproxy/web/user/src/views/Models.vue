<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@shared/api'
import { money } from '@shared/format'
import AppShell from '../components/AppShell.vue'

const models = ref([])
const mode = ref('')
const busy = ref(true)

async function load() {
  busy.value = true
  try {
    const plan = await api('/v1/_me/routing')
    models.value = plan.models || []
    mode.value = plan.mode || ''
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    busy.value = false
  }
}

function priceText(p) {
  if (!p) return ''
  return '输入未命中 ' + p.in_miss + ' / 命中 ' + p.in_hit + ' / 输出 ' + p.out + ' ' + p.currency + '（每百万 token）'
}

onMounted(load)
</script>

<template>
  <AppShell title="我的模型">
    <h2 class="f-page-title">我的模型</h2>
    <p class="f-page-sub">
      下面是真实选路顺序（与实际请求同一份计划）：同一档内按权重分担，多档按箭头依次回落。
      {{ mode === 'consumption' ? '消费模式下自有上游优先，承接不到才走系统池。' : '当前是自带上游模式。' }}
    </p>

    <div v-loading="busy">
      <el-empty v-if="!busy && !models.length" description="还没有可用模型：先配置上游，或让管理员开通消费模式白名单" />

      <div v-for="m in models" :key="m.model" class="f-card" style="margin-bottom: 14px">
        <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap">
          <strong class="mono" style="font-size: 15px">{{ m.model }}</strong>
          <el-tag v-if="m.price" size="small" type="warning">{{ priceText(m.price) }}</el-tag>
        </div>

        <div style="margin-top: 12px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap">
          <template v-if="m.tiers && m.tiers.length">
            <template v-for="(t, ti) in m.tiers" :key="t.rank">
              <span v-if="ti > 0" class="f-muted">→</span>
              <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap">
                <span class="f-muted" style="font-size: 12px">{{ t.label }}</span>
                <el-tag
                  v-for="it in t.items"
                  :key="it.provider"
                  :type="it.healthy ? 'success' : 'info'"
                  size="small"
                  :title="'上游模型 ' + it.upstream_model + ' · 权重 ' + it.weight + (it.healthy ? '' : ' · 冷却中')"
                >
                  {{ (it.source === 'own' ? '' : '系统·') + it.provider
                  }}{{ it.upstream_model && it.upstream_model !== m.model ? ' → ' + it.upstream_model : '' }}
                </el-tag>
              </div>
            </template>
          </template>
          <span v-else class="f-muted">没有上游承接</span>
        </div>
      </div>
    </div>
  </AppShell>
</template>
