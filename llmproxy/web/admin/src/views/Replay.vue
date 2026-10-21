<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessageBox } from 'element-plus'
import { api, currentBase } from '@shared/api'
import { session } from '../router'
import AdminShell from '../components/AdminShell.vue'

const data = ref(null)
const busy = ref(false)
const status = ref('')
const statusErr = ref(false)
const exportHint = ref('')
const exportErr = ref('')
const exporting = ref(false)

const form = reactive({ enabled: false, permille: '', scope: '', capacity: '' })
const exportScope = ref('')
const dirty = reactive({ permille: false, scope: false, capacity: false, export: false })

const stats = computed(() => {
  const d = data.value || {}
  return [
    { label: '窗口内判定', value: d.decisions ?? '—', hint: '溢出会丢最旧的' },
    { label: '窗口内选路', value: d.routings ?? '—', hint: '只有计划真的作用到请求上才有' },
    { label: '累计收到', value: d.captured ?? '—' },
    { label: '累计丢弃', value: d.dropped ?? '—', hint: '非零说明窗口小了或取走得太晚' },
    { label: '采集失败', value: d.failed ?? '—', hint: '判定发生了但组不出记录' },
    { label: '记录结构版本', value: d.record_schema_version ?? '—', hint: '可读 ' + ((d.record_schema_version_readable || []).join('/') || '—') },
    { label: '首选顺序逐位复现', value: d.bit_exact_primary_order ? '是（有前提）' : '否', hint: d.bit_exact_condition || '' },
    { label: '采样算法', value: d.sampling_algo_declared || '—', hint: '回放缺省 ' + (d.sampling_algo_replay_default || '—') },
  ]
})

function setStatus(msg, isErr = false) {
  status.value = msg || ''
  statusErr.value = !!isErr
}

async function load(keepStatus = false) {
  busy.value = true
  if (!keepStatus) setStatus('')
  try {
    data.value = await api('/v1/_admin/replay')
  } catch (e) {
    setStatus('读不到采集窗口状态：' + e.message, true)
    busy.value = false
    return
  }
  const d = data.value
  if (!dirty.permille) form.permille = d.sample_permille == null ? '' : String(d.sample_permille)
  if (!dirty.scope) form.scope = d.scope_filter && d.scope_filter !== '-' ? d.scope_filter : ''
  if (!dirty.capacity) form.capacity = d.capacity == null ? '' : String(d.capacity)
  if (!dirty.export) exportScope.value = d.scope_filter && d.scope_filter !== '-' ? d.scope_filter : ''
  form.enabled = !!d.enabled
  if (d.warning) setStatus(d.warning, true)
  else if (!keepStatus) setStatus('')
  busy.value = false
}

function parseOptionalInt(raw) {
  const s = String(raw ?? '').trim()
  if (s === '') return { ok: true, value: undefined }
  const n = Number(s)
  if (!Number.isInteger(n)) return { ok: false }
  return { ok: true, value: n }
}

async function save() {
  const pm = parseOptionalInt(form.permille)
  const cp = parseOptionalInt(form.capacity)
  if (!pm.ok || !cp.ok) {
    setStatus('千分率与窗口上限只收整数，本次没有提交。', true)
    return
  }
  const body = { enabled: !!form.enabled, scope: form.scope.trim() }
  if (pm.value !== undefined) body.sample_permille = pm.value
  if (cp.value !== undefined) body.capacity = cp.value
  try {
    const d = await api('/v1/_admin/replay/sampling', { method: 'POST', body })
    setStatus(d.note || '采集开关已保存。', !!d.warning)
    dirty.permille = dirty.scope = dirty.capacity = false
    await load(true)
  } catch (e) {
    setStatus('保存失败：' + e.message, true)
    dirty.permille = dirty.scope = dirty.capacity = false
    await load(true)
  }
}

async function clear() {
  try {
    await ElMessageBox.confirm('清空当前回放窗口？取走前清空等于丢弃这批记录。', '清空窗口', {
      confirmButtonText: '清空', cancelButtonText: '取消', type: 'warning',
    })
  } catch {
    return
  }
  try {
    const d = await api('/v1/_admin/replay/clear', { method: 'POST' })
    setStatus(d.note || '窗口已清空。')
    await load(true)
  } catch (e) {
    setStatus('清空失败：' + e.message, true)
  }
}

async function exportRecords() {
  exportErr.value = ''
  exportHint.value = ''
  exporting.value = true
  const scope = exportScope.value.trim()
  const q = scope ? '?scope=' + encodeURIComponent(scope) : ''
  try {
    const res = await fetch(currentBase() + '/v1/_admin/replay/export' + q, {
      headers: { Authorization: 'Bearer ' + session.load().bearer },
    })
    const text = await res.text()
    if (!res.ok) {
      let msg = res.status + ' ' + res.statusText
      try {
        const j = JSON.parse(text)
        msg = j?.error?.message || j?.error?.type || msg
      } catch {}
      throw new Error(msg)
    }
    let counted = ''
    try {
      const f = JSON.parse(text)
      counted = ' ' + (f.decisions || []).length + ' 条判定 / ' + (f.routing || []).length + ' 条选路，' +
        new Blob([text]).size + ' 字节'
    } catch {
      counted = ' （这份文件读不出结构，仍按原样交付）'
    }
    const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'llmproxy-replay-records.json'
    document.body.append(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 60000)
    exportHint.value = '已导出' + counted + '。拿到另一个进程重跑：llmproxy replay run -records <这份文件> -now <当时时刻>。'
    await load(true)
  } catch (e) {
    exportErr.value = e.message
  } finally {
    exporting.value = false
  }
}

onMounted(load)
</script>

<template>
  <AdminShell title="回放证据链">
    <div style="display: flex; align-items: center; gap: 12px">
      <h2 class="f-page-title" style="margin: 0">回放证据链</h2>
      <span class="f-muted" v-if="data">窗口快照 {{ data.as_of || '—' }} · mode {{ data.mode || '—' }}</span>
      <span style="flex: 1" />
      <el-button :loading="busy" @click="load()">刷新</el-button>
    </div>
    <p class="f-page-sub">
      只管三件事：开多大比例的采集、把窗口里的记录取走、取完把窗口清掉。记录里带用户名，缺省是关的。
    </p>

    <el-alert v-if="status" :title="status" :type="statusErr ? 'error' : 'info'" :closable="false" show-icon
      style="white-space: pre-line; margin-bottom: 14px" />

    <div class="f-grid" style="margin-bottom: 16px">
      <div v-for="s in stats" :key="s.label" class="f-card">
        <div class="f-muted">{{ s.label }}</div>
        <div style="font-size: 18px; font-weight: 600; margin: 2px 0">{{ s.value }}</div>
        <div v-if="s.hint" class="f-muted" style="font-size: 12px">{{ s.hint }}</div>
      </div>
    </div>

    <div class="f-card" style="margin-bottom: 16px">
      <h3 style="margin-top: 0">采集开关</h3>
      <p class="f-muted" style="margin-top: 0">
        留空 = 这个字段不动（指针语义）；千分率 1000 = 全采。范围过滤只认精确的 kind:id。
      </p>
      <div style="display: flex; gap: 12px; flex-wrap: wrap; align-items: center">
        <el-checkbox v-model="form.enabled">开启采集</el-checkbox>
        <el-input v-model="form.permille" style="width: 180px" placeholder="千分率，如 50"
          @input="dirty.permille = true" />
        <el-input v-model="form.scope" style="width: 260px" placeholder="范围过滤，如 user:alice（留空=不过滤）"
          @input="dirty.scope = true" />
        <el-input v-model="form.capacity" style="width: 180px" placeholder="窗口条数上限"
          @input="dirty.capacity = true" />
        <el-button type="primary" @click="save">保存开关</el-button>
      </div>
      <p class="f-muted" style="font-size: 12px; margin-bottom: 0">
        当前：{{ data?.enabled ? '采集中' : '未采集' }} · 千分率 {{ data?.sample_permille ?? '—' }}‰ ·
        过滤 {{ data?.scope_filter || '无' }} · 上限 {{ data?.capacity ?? '—' }} 条。
      </p>
    </div>

    <div class="f-card">
      <h3 style="margin-top: 0">导出与清空</h3>
      <p class="f-muted" style="margin-top: 0">
        导出拿到的就是记录文件本身那串字节，不做二次序列化；浏览器存下来的那份直接交给另一个进程重跑。
      </p>
      <div style="display: flex; gap: 10px; flex-wrap: wrap; align-items: center">
        <el-input v-model="exportScope" style="width: 280px" placeholder="导出过滤，如 user:alice（留空=全窗口）"
          @input="dirty.export = true" />
        <el-button :loading="exporting" @click="exportRecords">导出记录文件</el-button>
        <el-button @click="clear">清空窗口</el-button>
      </div>
      <el-alert v-if="exportErr" :title="exportErr" type="error" :closable="false" show-icon style="margin-top: 10px" />
      <p v-if="exportHint" class="f-muted" style="margin-top: 10px; margin-bottom: 0">{{ exportHint }}</p>
      <p v-if="data?.note" class="f-muted" style="font-size: 12px; margin-bottom: 0">{{ data.note }}</p>
    </div>
  </AdminShell>
</template>
