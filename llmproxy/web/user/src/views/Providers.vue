<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '@shared/api'
import { ms } from '@shared/format'
import AppShell from '../components/AppShell.vue'

const list = ref([])
const busy = ref(false)
const dialog = ref(false)
const editing = ref(false)
const err = ref('')
const syncing = ref(false)
const candidates = ref([])

const blank = () => ({
  name: '',
  base_url: '',
  api_key: '',
  weight: 1,
  timeout_ms: 120000,
  proxy: 'direct',
  enabled: true,
  mode: 'all',
  rows: [],
  catchAll: false,
})
const form = reactive(blank())

function modelSummary(p) {
  const m = p.models || {}
  if (m.passthrough) return ['* 全部直通']
  const out = Object.entries(m.map || {})
    .filter(([d]) => d !== '*')
    .map(([down, up]) => (down === up ? down : down + ' → ' + up))
  if (m.catch_all) out.push('其余直通')
  return out.length ? out : ['—']
}

async function load() {
  busy.value = true
  try {
    const data = await api('/v1/_me/providers')
    list.value = data.providers || []
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    busy.value = false
  }
}

function openNew() {
  Object.assign(form, blank())
  editing.value = false
  err.value = ''
  candidates.value = []
  dialog.value = true
}

function openEdit(p) {
  Object.assign(form, blank(), {
    name: p.name,
    base_url: p.base_url,
    weight: p.weight,
    timeout_ms: p.timeout_ms,
    proxy: p.proxy || 'direct',
    enabled: !!p.enabled,
    mode: p.models?.passthrough ? 'all' : 'pick',
    rows: Object.entries(p.models?.map || {})
      .filter(([d]) => d !== '*')
      .map(([down, up]) => ({ down, up })),
    catchAll: !!p.models?.catch_all,
  })
  editing.value = true
  err.value = ''
  candidates.value = []
  dialog.value = true
}

function addRow(up = '') {
  form.rows.push({ down: up, up })
}

function pickCandidate(name) {
  if (!form.rows.some((r) => r.up === name)) addRow(name)
}

function hasCandidate(name) {
  return form.rows.some((r) => r.up === name)
}

async function syncModels() {
  err.value = ''
  if (!form.name.trim() || !form.base_url.trim()) {
    err.value = '先填上游名与地址，再同步模型列表'
    return
  }
  syncing.value = true
  try {
    const body = { base_url: form.base_url.trim() }
    if (form.api_key) body.api_key = form.api_key
    const data = await api('/v1/_me/providers/' + encodeURIComponent(form.name.trim()) + '/discover', {
      method: 'POST',
      body,
    })
    candidates.value = data.models || []
    if (candidates.value.length) form.mode = 'pick'
  } catch (e) {
    // 同步失败不动已选：候选只是候选
    err.value = '同步失败：' + e.message
  } finally {
    syncing.value = false
  }
}

function buildModels() {
  if (form.mode === 'all') return ['*']
  const map = {}
  for (const r of form.rows) {
    const down = (r.down || '').trim()
    if (!down) continue
    map[down] = (r.up || down).trim()
  }
  if (form.catchAll) map['*'] = '*'
  if (Object.keys(map).length === 0) return null
  return map
}

async function save() {
  err.value = ''
  const name = form.name.trim()
  if (!name) {
    err.value = '上游名必填'
    return
  }
  if (!form.base_url.trim()) {
    err.value = '上游地址必填'
    return
  }
  const models = buildModels()
  if (models === null) {
    err.value = '至少选一个模型，或把模式改成「全部直通」'
    return
  }
  const body = {
    base_url: form.base_url.trim(),
    weight: Number(form.weight) || 1,
    timeout_ms: Number(form.timeout_ms) || 120000,
    proxy: (form.proxy || 'direct').trim(),
    enabled: form.enabled,
    models,
  }
  if (form.api_key) body.api_key = form.api_key
  else if (!editing.value) {
    err.value = '新建上游必须填上游密钥'
    return
  }
  try {
    await api('/v1/_me/providers/' + encodeURIComponent(name), { method: 'PUT', body })
    dialog.value = false
    ElMessage.success(editing.value ? '已保存' : '已创建')
    await load()
  } catch (e) {
    err.value = e.message
  }
}

async function remove(p) {
  try {
    await ElMessageBox.confirm(
      '删除上游 ' + p.name + '？之后用它承接的模型会失败。',
      '删除上游',
      { confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    return
  }
  try {
    await api('/v1/_me/providers/' + encodeURIComponent(p.name), { method: 'DELETE' })
    ElMessage.success('已删除')
    await load()
  } catch (e) {
    ElMessage.error(e.message)
  }
}

onMounted(load)
</script>

<template>
  <AppShell title="我的上游">
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 6px">
      <h2 class="f-page-title" style="margin: 0">我的上游</h2>
      <el-button type="primary" @click="openNew">新增上游</el-button>
    </div>
    <p class="f-page-sub">
      自己配了上游，请求就只走自己的（byo）；消费模式下自有上游优先，承接不到才回落系统池。
    </p>

    <el-alert
      type="info"
      :closable="false"
      show-icon
      style="margin-bottom: 14px"
      title="密钥只显示尾号；编辑时留空表示不修改，避免把脱敏值当成新密钥提交。"
    />

    <el-table v-loading="busy" :data="list" border style="width: 100%">
      <el-table-column prop="name" label="名称" width="150">
        <template #default="{ row }"><code class="mono">{{ row.name }}</code></template>
      </el-table-column>
      <el-table-column prop="base_url" label="地址" min-width="220">
        <template #default="{ row }"><code class="mono">{{ row.base_url }}</code></template>
      </el-table-column>
      <el-table-column label="模型" min-width="240">
        <template #default="{ row }">
          <el-tag v-for="m in modelSummary(row)" :key="m" size="small" style="margin: 2px 4px 2px 0">{{ m }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="weight" label="权重" width="70" align="right" />
      <el-table-column prop="proxy" label="代理" width="120">
        <template #default="{ row }"><code class="mono">{{ row.proxy || 'direct' }}</code></template>
      </el-table-column>
      <el-table-column label="超时" width="90" align="right">
        <template #default="{ row }">{{ ms(row.timeout_ms) }}</template>
      </el-table-column>
      <el-table-column prop="api_key" label="密钥" width="120">
        <template #default="{ row }"><code class="mono">{{ row.api_key || '—' }}</code></template>
      </el-table-column>
      <el-table-column label="状态" width="90">
        <template #default="{ row }">
          <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '启用' : '停用' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="140" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" @click="openEdit(row)">编辑</el-button>
          <el-button link type="danger" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
      <template #empty><el-empty description="还没有上游" :image-size="70" /></template>
    </el-table>

    <el-dialog v-model="dialog" :title="editing ? '编辑上游' : '新增上游'" width="760px" destroy-on-close>
      <el-form label-width="96px" label-position="right">
        <el-form-item label="名称">
          <el-input v-model="form.name" :disabled="editing" placeholder="小写字母/数字/点/下划线/连字符" />
        </el-form-item>
        <el-form-item label="地址">
          <el-input v-model="form.base_url" placeholder="https://api.example.com/v1" />
        </el-form-item>
        <el-form-item label="密钥">
          <el-input
            v-model="form.api_key"
            type="password"
            show-password
            :placeholder="editing ? '留空 = 不修改' : 'sk-…'"
          />
        </el-form-item>
        <el-form-item label="模型">
          <el-radio-group v-model="form.mode">
            <el-radio-button value="all">全部直通</el-radio-button>
            <el-radio-button value="pick">指定模型</el-radio-button>
          </el-radio-group>
          <el-button :loading="syncing" style="margin-left: 12px" @click="syncModels">从上游同步模型</el-button>
          <span v-if="candidates.length" class="f-muted" style="margin-left: 8px; font-size: 12px">
            候选 {{ candidates.length }} 个，点一下加入
          </span>
        </el-form-item>

        <template v-if="form.mode === 'pick'">
          <el-form-item v-if="candidates.length" label="候选">
            <div style="max-height: 130px; overflow: auto">
              <el-check-tag
                v-for="c in candidates"
                :key="c"
                :checked="hasCandidate(c)"
                style="margin: 2px 6px 2px 0"
                @change="pickCandidate(c)"
              >
                <code class="mono">{{ c }}</code>
              </el-check-tag>
            </div>
          </el-form-item>

          <el-form-item label="映射">
            <div style="width: 100%">
              <div v-for="(r, i) in form.rows" :key="i" style="display: flex; gap: 8px; margin-bottom: 6px">
                <el-input v-model="r.down" placeholder="下游模型名" />
                <span style="align-self: center">→</span>
                <el-input v-model="r.up" placeholder="上游模型名" />
                <el-button @click="form.rows.splice(i, 1)">移除</el-button>
              </div>
              <el-button @click="addRow()">添加一行</el-button>
              <el-checkbox v-model="form.catchAll" style="margin-left: 16px">其余模型直通</el-checkbox>
            </div>
          </el-form-item>
        </template>

        <el-form-item label="权重">
          <el-input-number v-model="form.weight" :min="0.01" :step="0.5" />
          <span class="f-muted" style="margin-left: 10px; font-size: 12px">同名模型多家承接时按权重分担</span>
        </el-form-item>
        <el-form-item label="超时">
          <el-input-number v-model="form.timeout_ms" :min="1000" :step="10000" />
          <span class="f-muted" style="margin-left: 8px">毫秒</span>
        </el-form-item>
        <el-form-item label="代理">
          <el-input v-model="form.proxy" placeholder="direct 或代理名/地址" />
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="form.enabled" />
        </el-form-item>

        <p v-if="err" class="err" style="color: #dc2626; margin: 0">{{ err }}</p>
      </el-form>
      <template #footer>
        <el-button @click="dialog = false">取消</el-button>
        <el-button type="primary" @click="save">保存</el-button>
      </template>
    </el-dialog>
  </AppShell>
</template>
