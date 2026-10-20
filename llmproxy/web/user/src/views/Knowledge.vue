<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@shared/api'
import AppShell from '../components/AppShell.vue'

const bases = ref([])
const sources = ref([])
const note = ref('')
const version = ref('')
const unavailable = ref('')
const query = ref('')
const result = ref(null)
const busy = ref(false)
const searching = ref(false)

async function load() {
  busy.value = true
  try {
    const data = await api('/v1/_me/knowledge')
    bases.value = data.knowledge_bases || []
    sources.value = data.sources || []
    note.value = data.note || ''
    version.value = data.policy_version || ''
  } catch (e) {
    unavailable.value = e.message
  } finally {
    busy.value = false
  }
}

async function search() {
  const q = query.value.trim()
  if (!q) return
  searching.value = true
  result.value = null
  try {
    result.value = await api('/v1/_me/knowledge/search', {
      method: 'POST',
      body: { query: q },
    })
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    searching.value = false
  }
}

onMounted(load)
</script>

<template>
  <AppShell title="知识检索">
    <h2 class="f-page-title">知识检索</h2>
    <p class="f-page-sub">准入由策略内核判定；引用只含摘要与文档 ID，正文请凭它回源知识源取。</p>

    <el-alert
      v-if="unavailable"
      type="info"
      :closable="false"
      show-icon
      :title="'知识检索未启用或当前不可用：' + unavailable"
      style="margin-bottom: 16px"
    />

    <div v-loading="busy">
      <div class="f-grid" style="margin-bottom: 16px">
        <div class="f-card">
          <div class="f-muted">可访问知识库</div>
          <div class="f-big">{{ bases.filter((b) => b.allowed).length }} / {{ bases.length }}</div>
          <div v-if="version" class="f-muted" style="font-size: 12px">策略版本 {{ version }}</div>
        </div>
        <div class="f-card">
          <div class="f-muted">知识源</div>
          <div class="f-big">{{ sources.length }}</div>
          <div class="f-muted" style="font-size: 12px">{{ sources.map((s) => s.name).join('、') || '—' }}</div>
        </div>
      </div>

      <div v-if="bases.length" class="f-card" style="margin-bottom: 16px">
        <h3 style="margin-top: 0">知识库准入</h3>
        <el-table :data="bases" size="small" border>
          <el-table-column prop="knowledge_base" label="知识库" min-width="160" />
          <el-table-column prop="source" label="来源" min-width="140" />
          <el-table-column label="结果" width="110">
            <template #default="{ row }">
              <el-tag :type="row.allowed ? 'success' : 'info'" size="small">{{ row.allowed ? '允许' : '拒绝' }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="reason" label="拒绝原因" min-width="160">
            <template #default="{ row }">{{ row.reason || '—' }}</template>
          </el-table-column>
        </el-table>
      </div>

      <div class="f-card">
        <h3 style="margin-top: 0">检索</h3>
        <div style="display: flex; gap: 8px">
          <el-input v-model="query" placeholder="输入检索词" @keyup.enter="search" />
          <el-button type="primary" :loading="searching" @click="search">检索</el-button>
        </div>

        <template v-if="result">
          <el-divider />
          <div v-if="result.denied_knowledge_bases?.length" class="f-muted" style="font-size: 13px; margin-bottom: 8px">
            被拒绝的库：{{ result.denied_knowledge_bases.map((d) => d.knowledge_base + '（' + d.reason + '）').join('、') }}
          </div>
          <el-table v-if="result.citations?.length" :data="result.citations" size="small" border>
            <el-table-column prop="knowledge_base" label="知识库" width="160" />
            <el-table-column prop="source_id" label="文档 ID" min-width="220">
              <template #default="{ row }"><code class="mono">{{ row.source_id }}</code></template>
            </el-table-column>
            <el-table-column prop="score" label="分数" width="80" align="right" />
          </el-table>
          <el-empty v-else description="没有命中（或全部被策略拒绝）" :image-size="60" />
          <p class="f-muted" style="font-size: 12px; margin-bottom: 0">{{ result.note }}</p>
        </template>
      </div>
    </div>
  </AppShell>
</template>

<style scoped>
.f-big {
  font-size: 24px;
  font-weight: 700;
  margin-top: 4px;
}
</style>
