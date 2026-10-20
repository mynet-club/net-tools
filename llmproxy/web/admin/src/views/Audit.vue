<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@shared/api'
import AdminShell from '../components/AdminShell.vue'

const n = ref(100)
const scope = ref('')
const entries = ref([])
const busy = ref(false)

function fmt(ts) {
  if (!ts) return ''
  const d = new Date(ts)
  return isNaN(d) ? ts : d.toLocaleString('zh-CN')
}

async function load() {
  busy.value = true
  try {
    const q = new URLSearchParams({ n: String(n.value) })
    if (scope.value.trim()) q.append('scope', scope.value.trim())
    const data = await api('/v1/_admin/audit?' + q.toString())
    entries.value = data.entries || []
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <AdminShell title="操作审计">
    <h2 class="f-page-title">操作审计</h2>
    <p class="f-page-sub">管理动作与登录事件。留空范围 = 全部；只看某个范围时按 <code>kind:id</code> 填写。</p>

    <div style="display: flex; gap: 10px; margin-bottom: 14px; flex-wrap: wrap">
      <el-input v-model="scope" placeholder="可选：user:alice / system:global" style="width: 280px" @keyup.enter="load" />
      <el-radio-group v-model="n" size="small" @change="load">
        <el-radio-button :value="100">最近 100</el-radio-button>
        <el-radio-button :value="300">300</el-radio-button>
        <el-radio-button :value="1000">1000</el-radio-button>
      </el-radio-group>
      <el-button @click="load">刷新</el-button>
    </div>

    <el-table v-loading="busy" :data="entries" border style="width: 100%">
      <el-table-column label="时间" width="170">
        <template #default="{ row }">{{ fmt(row.ts) }}</template>
      </el-table-column>
      <el-table-column label="范围" width="160">
        <template #default="{ row }">{{ row.scope?.kind }}:{{ row.scope?.id }}</template>
      </el-table-column>
      <el-table-column prop="actor" label="操作者" width="120" />
      <el-table-column prop="action" label="动作" width="170" />
      <el-table-column prop="target" label="目标" width="150" />
      <el-table-column prop="detail" label="详情" min-width="220" show-overflow-tooltip />
      <template #empty><el-empty description="没有审计记录" :image-size="70" /></template>
    </el-table>
  </AdminShell>
</template>
