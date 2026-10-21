<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessageBox } from 'element-plus'
import { api } from '@shared/api'
import AdminShell from './AdminShell.vue'

const props = defineProps({
  title: { type: String, required: true },
  section: { type: String, required: true },
  path: { type: String, required: true },
  keyName: { type: String, required: true },
  noun: { type: String, required: true },
  intro: { type: String, default: '' },
  example: { type: Array, required: true },
})

const data = ref(null)
const assembly = ref(null)
const assemblyErr = ref('')
const draft = ref('[]')
const disk = ref('[]')
const dirty = ref(false)
const busy = ref(false)
const status = ref('')
const statusErr = ref(false)

const count = computed(() => (data.value?.[props.keyName] || []).length)
const vocab = computed(() => data.value?.vocabulary || null)

const assemblyState = computed(() => {
  if (!assembly.value) {
    return { text: '读不到', type: 'danger', detail: '装配状态读不到：' + (assemblyErr.value || '未知原因') + '\n读不到时不画成「正常」。' }
  }
  const sec = assembly.value[props.section] || {}
  const declared = Number(sec.declared || 0)
  const failed = Number(sec.failed || 0)
  const assembled = Number(sec.assembled || 0)
  const bad = (sec.declarations || []).filter((d) => d.status === 'failed')
  const note = assembly.value.note || '运行态读数，不落库；重启后只反映重启之后的状态。'
  if (!assembly.value.running) {
    return {
      text: declared ? '未装配 ' + declared + ' 条' : '未装配',
      type: declared ? 'danger' : 'info',
      detail: (assembly.value.reason || '3.0 运行态未建立') + '\n' + note,
    }
  }
  if (failed) {
    return {
      text: failed + ' 条装不起来',
      type: 'danger',
      detail: bad.map((d) => d.name + '：' + (d.reason || '（未给出拒因）')).join('\n') + '\n' + note,
    }
  }
  if (!declared) return { text: '无声明', type: 'info', detail: note }
  return { text: '全部装配 ' + assembled + '/' + declared, type: 'success', detail: note }
})

const stats = computed(() => {
  const d = data.value || {}
  return [
    { label: 'policy.mode', value: (d.mode || '—') + ' → ' + (d.applies ? '参与请求' : '暂不参与'), hint: '只有 enforce 允许 3.0 影响路由与处理器' },
    { label: props.noun, value: count.value + ' 条', hint: '磁盘上的声明数' },
    { label: '装配', value: assemblyState.value.text, hint: '运行态读数，不落库' },
    { label: '磁盘时间', value: d.mtime || '—', hint: '大小 ' + (d.size ?? '—') + ' 字节' },
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
    data.value = await api(props.path)
  } catch (e) {
    setStatus('读不到 ' + props.keyName + ' 段：' + e.message, true)
    busy.value = false
    return
  }
  try {
    assembly.value = (await api('/v1/_admin/policy')).assembly || null
    assemblyErr.value = ''
  } catch (e) {
    assembly.value = null
    assemblyErr.value = e.message
  }
  const text = JSON.stringify(data.value?.[props.keyName] || [], null, 2)
  disk.value = text
  if (!dirty.value) draft.value = text
  if (data.value?.baseline_error) {
    setStatus('磁盘上的这一版读不回来：' + data.value.baseline_error + '\n条数列显示的是服务当前加载着的那一份。', true)
  } else if (assembly.value && !assembly.value.running && count.value) {
    setStatus('3.0 运行态未建立：' + (assembly.value.reason || '未在跑') + '，这些声明暂时不参与请求。', true)
  } else if (!keepStatus && (data.value?.warnings || []).length) {
    setStatus('提示：' + data.value.warnings.join('；'))
  }
  busy.value = false
}

function onInput() {
  dirty.value = true
  setStatus('')
}

function fillExample() {
  draft.value = JSON.stringify(props.example, null, 2)
  dirty.value = true
  setStatus('已填入示例（未保存）—— 名字、类型、端点都要改成你自己的。')
}

function reloadDisk() {
  draft.value = disk.value
  dirty.value = false
  setStatus('已读回磁盘上的那一份。')
}

async function save() {
  setStatus('')
  let arr
  try {
    arr = JSON.parse(draft.value.trim() || '[]')
  } catch (e) {
    setStatus('JSON 语法不过：' + e.message, true)
    return
  }
  if (!Array.isArray(arr)) {
    setStatus('这一段是一个数组：顶层要写成 […]（清空请显式保存 []）。', true)
    return
  }
  if (!arr.length && count.value) {
    try {
      await ElMessageBox.confirm(
        '清空 ' + props.keyName + ' 段？磁盘上现在有 ' + count.value + ' 条。整段替换一次写完，撤销只能靠那次写的配置备份。',
        '清空整段',
        { confirmButtonText: '清空并保存', cancelButtonText: '取消', type: 'warning' },
      )
    } catch {
      return
    }
  }
  setStatus('PUT ' + props.path + ' 处理中…')
  try {
    const d = await api(props.path, { method: 'PUT', body: { [props.keyName]: arr } })
    let msg = d.note || '已完成。'
    if (d.backup) msg += '（配置备份 ' + d.backup + '）'
    msg += d.applies
      ? '\nmode=' + d.mode + '：这些声明现在参与请求。'
      : '\n⚠ mode=' + d.mode + '：声明已写进配置，但现在还不参与请求。'
    if (d.applied === false) msg += '\n⚠ 还在等热加载，可以先点刷新。'
    if (d.strict_error) msg += '\n⚠ 文件写入了但服务加载会失败：' + d.strict_error
    if ((d.warnings || []).length) msg += '\n提示：' + d.warnings.join('；')
    setStatus(msg, !!(d.strict_error || d.applied === false))
    dirty.value = false
    await load(true)
  } catch (e) {
    setStatus('失败：' + e.message + '\n原文件未改动（服务端在校验不过时整笔还原）。', true)
    await load(true)
  }
}

onMounted(load)
</script>

<template>
  <AdminShell :title="title">
    <div style="display: flex; align-items: center; gap: 12px">
      <h2 class="f-page-title" style="margin: 0">{{ title }}</h2>
      <span class="f-muted" v-if="data">配置修订 {{ data.revision }} · {{ data.path || 'config.yaml' }}</span>
      <span style="flex: 1" />
      <el-button :loading="busy" @click="load()">刷新</el-button>
    </div>
    <p class="f-page-sub" v-if="intro">{{ intro }}</p>

    <el-alert v-if="status" :title="status" :type="statusErr ? 'error' : 'info'" :closable="false" show-icon
      style="white-space: pre-line; margin-bottom: 14px" />

    <div class="f-grid" style="margin-bottom: 16px">
      <div v-for="s in stats" :key="s.label" class="f-card">
        <div class="f-muted">{{ s.label }}</div>
        <div style="font-size: 18px; font-weight: 600; margin: 2px 0">{{ s.value }}</div>
        <div v-if="s.hint" class="f-muted" style="font-size: 12px">{{ s.hint }}</div>
      </div>
    </div>

    <el-alert v-if="assemblyState.type === 'danger'" :title="assemblyState.detail" type="error" :closable="false" show-icon
      style="white-space: pre-line; margin-bottom: 14px" />

    <div class="f-card" style="margin-bottom: 16px">
      <h3 style="margin-top: 0">{{ noun }}（{{ keyName }} 段）</h3>
      <p class="f-muted" style="margin-top: 0">
        整段提交：改一条也要把整个数组发回来。<b>清空请显式保存 []</b>。
      </p>
      <el-input v-model="draft" type="textarea" :rows="14" spellcheck="false" class="mono" @input="onInput" />
      <div style="display: flex; gap: 10px; align-items: center; margin-top: 10px">
        <el-button type="primary" @click="save">整段保存</el-button>
        <el-button @click="fillExample">填入最小示例</el-button>
        <el-button link @click="reloadDisk">放弃修改，读回磁盘</el-button>
        <span class="f-muted" style="font-size: 12px">
          {{ count }} 条在磁盘上 · {{ dirty ? '编辑中（未保存）' : '与磁盘一致' }}
        </span>
      </div>
    </div>

    <div class="f-card">
      <h3 style="margin-top: 0">取值域（服务端下发）</h3>
      <p class="f-muted" style="margin-top: 0">这一屏能填什么由服务端注册表与领域上限决定；界面不校验业务规则。</p>
      <div v-if="!vocab" class="f-muted">这次没拿到取值域（接口没回 vocabulary）。</div>
      <template v-else>
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="处理器类型" v-if="vocab.processor_types">
            <span class="mono">{{ (vocab.processor_types || []).join('、') || '—' }}</span>
          </el-descriptions-item>
          <el-descriptions-item label="阶段" v-if="vocab.phases">
            <span class="mono">{{ (vocab.phases || []).join('、') || '—' }}</span>
          </el-descriptions-item>
          <el-descriptions-item label="正文档位" v-if="vocab.body_accesses">
            <span class="mono">{{ (vocab.body_accesses || []).join('、') || '—' }}</span>
          </el-descriptions-item>
          <el-descriptions-item label="范围写法" v-if="vocab.scope_kinds">
            <span class="mono">{{ (vocab.scope_kinds || []).map((x) => x + ':id').concat(['*']).join('、') }}</span>
          </el-descriptions-item>
        </el-descriptions>
        <p class="f-muted" style="font-size: 12px; margin-bottom: 0">
          上限：timeout ≤ {{ vocab.max_timeout_ms ?? '—' }} ms；max_input_bytes ≤
          {{ vocab.absolute_max_input_bytes ?? '—' }}、max_output_bytes ≤
          {{ vocab.absolute_max_output_bytes ?? '—' }} 字节；name ≤ {{ vocab.max_name_len ?? '—' }} 字符；
          allowed_endpoints ≤ {{ vocab.max_allowed_endpoints ?? '—' }} 条。
        </p>
        <p v-if="data?.boundary" class="f-muted" style="font-size: 12px; margin-bottom: 0">{{ data.boundary }}</p>
      </template>
    </div>
  </AdminShell>
</template>
