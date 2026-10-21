<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { api } from '@shared/api'
import AdminShell from '../components/AdminShell.vue'

const policy = ref(null)
const bundles = ref(null)
const busy = ref(false)
const banner = ref('')
const bannerErr = ref(false)

const modeForm = reactive({ mode: 'legacy', data_level: '', fallback: '' })
const activeId = ref('')
const draft = reactive({ id: '', version: '', scope: '', active: true, rules: '' })

const refs = computed(() => bundles.value?.refs || [])
const currentActive = computed(() => refs.value.find((r) => r.active)?.id || '—')

const RULE_EXAMPLE = JSON.stringify([
  {
    subject: 'role:teacher',
    resource: 'model:gpt-4o',
    action: 'use',
    effect: 'allow',
    conditions: { 'max-data-level': 'internal' },
  },
  { subject: '*', resource: 'model:secret-model', action: 'use', effect: 'deny', expires_at: '2027-01-01T00:00:00Z' },
], null, 2)

function setBanner(msg, isErr = false) {
  banner.value = msg || ''
  bannerErr.value = !!isErr
}

async function load() {
  busy.value = true
  try {
    policy.value = await api('/v1/_admin/policy')
    bundles.value = await api('/v1/_admin/policy/bundles')
  } catch (e) {
    setBanner('读不到策略状态：' + e.message, true)
    busy.value = false
    return
  }
  const d = policy.value || {}
  modeForm.mode = d.configured_mode && d.configured_mode !== '-' ? d.configured_mode : 'legacy'
  modeForm.data_level = ''
  modeForm.fallback = ''
  if (!activeId.value || !refs.value.some((r) => r.id === activeId.value)) {
    activeId.value = d.active_bundle && d.active_bundle !== '-' ? d.active_bundle : (refs.value[0]?.id || '')
  }
  busy.value = false
}

async function call(method, path, body) {
  setBanner(method + ' ' + path + ' 处理中…')
  try {
    const data = await api(path, { method, body })
    let msg = data.note || '已完成。'
    if (data.backup) msg += '（配置备份 ' + data.backup + '）'
    if (data.applied === false) msg += '\n⚠ 还在等热加载，可以先点刷新。'
    if (data.strict_error) msg += '\n⚠ 文件写入了但服务加载会失败：' + data.strict_error
    if ((data.warnings || []).length) msg += '\n提示：' + data.warnings.join('；')
    setBanner(msg, !!(data.strict_error || data.applied === false))
    await load()
    return data
  } catch (e) {
    setBanner('失败：' + e.message, true)
    await load()
    return null
  }
}

async function applyMode() {
  const body = { mode: modeForm.mode }
  if (modeForm.data_level) body.data_level = modeForm.data_level
  if (modeForm.fallback) body.fallback_to_legacy = modeForm.fallback === 'true'
  await call('POST', '/v1/_admin/policy/mode', body)
}

async function applyActive() {
  if (!activeId.value) {
    setBanner('还没有可切的包：先在下面发布一个策略包。', true)
    return
  }
  await call('POST', '/v1/_admin/policy/active', { bundle: activeId.value })
}

async function publish() {
  const id = draft.id.trim()
  if (!id) {
    setBanner('策略包 id 必填：它会当文件名用（<id>.yaml）。', true)
    return
  }
  const version = Number(draft.version)
  if (!draft.version || !Number.isInteger(version) || version < 1) {
    setBanner('version 要显式给且 ≥ 1。', true)
    return
  }
  const scope = draft.scope.trim()
  if (!scope) {
    setBanner('scope 必填，写成 kind:id（例如 system:gateway）。', true)
    return
  }
  const raw = draft.rules.trim()
  if (!raw) {
    setBanner('规则正文是空的：确实要发空包就显式写 []。', true)
    return
  }
  let entitlements
  try {
    entitlements = JSON.parse(raw)
  } catch (e) {
    setBanner('规则正文不是合法 JSON：' + e.message, true)
    return
  }
  if (!Array.isArray(entitlements)) {
    setBanner('规则必须是一个 JSON 数组。', true)
    return
  }
  await call('PUT', '/v1/_admin/policy/bundles/' + encodeURIComponent(id), {
    version,
    scope,
    active: !!draft.active,
    entitlements,
  })
}

function fillExample() {
  draft.rules = RULE_EXAMPLE
}

onMounted(load)
</script>

<template>
  <AdminShell title="策略发布">
    <div style="display: flex; align-items: center; gap: 12px">
      <h2 class="f-page-title" style="margin: 0">策略发布</h2>
      <span class="f-muted" v-if="policy">配置修订 {{ policy.revision }} · 当前生效包 {{ currentActive }}</span>
      <span style="flex: 1" />
      <el-button :loading="busy" @click="load">刷新</el-button>
    </div>
    <p class="f-page-sub">写侧三件事：模式、生效包、发布新版。都会改 config.yaml，改前自动备份，段外内容与注释原样。</p>

    <el-alert v-if="banner" :title="banner" :type="bannerErr ? 'error' : 'info'" :closable="false" show-icon
      style="white-space: pre-line; margin-bottom: 14px" />

    <div class="f-card" style="margin-bottom: 16px">
      <h3 style="margin-top: 0">模式</h3>
      <p class="f-muted" style="margin-top: 0">
        新上 3.0 的顺序：先发布策略包（mode 仍是 legacy）→ 再切 shadow 观察一致率 → 最后 enforce。
      </p>
      <div style="display: flex; gap: 10px; flex-wrap: wrap; align-items: center">
        <el-select v-model="modeForm.mode" style="width: 300px">
          <el-option label="legacy —— 3.0 不参与判定（应急开关）" value="legacy" />
          <el-option label="shadow —— 只观察，不改路由" value="shadow" />
          <el-option label="enforce —— 允许策略改路由" value="enforce" />
        </el-select>
        <el-select v-model="modeForm.data_level" style="width: 240px">
          <el-option label="数据分级：不改" value="" />
          <el-option label="public" value="public" />
          <el-option label="internal" value="internal" />
          <el-option label="confidential" value="confidential" />
          <el-option label="restricted" value="restricted" />
        </el-select>
        <el-select v-model="modeForm.fallback" style="width: 260px">
          <el-option label="回落旧路由：不改" value="" />
          <el-option label="开：算不出计划时回落" value="true" />
          <el-option label="关：算不出计划不放行" value="false" />
        </el-select>
        <el-button type="primary" @click="applyMode">应用模式</el-button>
      </div>
      <p class="f-muted" style="margin-bottom: 0; font-size: 12px">
        当前：{{ policy?.configured_mode || '—' }} → {{ policy?.mode || '—' }}；分级
        {{ policy?.declared_data_level || policy?.data_level || '—' }}；回落
        {{ policy?.fallback_to_legacy ? '开' : '关' }}。
      </p>
    </div>

    <div class="f-card" style="margin-bottom: 16px">
      <h3 style="margin-top: 0">生效包</h3>
      <p class="f-muted" style="margin-top: 0">只换 active_bundle，引用与内容文件都不动；切回上一版就是这个动作。</p>
      <div style="display: flex; gap: 10px; align-items: center">
        <el-select v-model="activeId" style="width: 320px" placeholder="选择已引用的策略包">
          <el-option v-for="r in refs" :key="r.id" :label="r.id + ' @v' + r.version + (r.active ? '（现行生效）' : '')" :value="r.id" />
        </el-select>
        <el-button type="primary" @click="applyActive">设为生效</el-button>
      </div>
    </div>

    <div class="f-card">
      <h3 style="margin-top: 0">发布新版</h3>
      <p class="f-muted" style="margin-top: 0">
        一次调用同时改引用与 policy-bundles/&lt;id&gt;.yaml；任何一步校验不过就整笔还原。
        下表只回显规则的选择器与条件键名，<b>条件值要从你自己的策略源文件粘贴进来</b>。
      </p>
      <el-form label-width="120px">
        <el-form-item label="策略包 id">
          <el-input v-model="draft.id" placeholder="cs-lab-open" />
        </el-form-item>
        <el-form-item label="版本号">
          <el-input v-model="draft.version" type="number" min="1" step="1" placeholder="2" style="width: 180px" />
        </el-form-item>
        <el-form-item label="范围 scope">
          <el-input v-model="draft.scope" placeholder="system:gateway、organization:cs、project:cs-lab-7" />
        </el-form-item>
        <el-form-item label="发布后生效">
          <el-switch v-model="draft.active" />
        </el-form-item>
        <el-form-item label="规则 JSON">
          <el-input v-model="draft.rules" type="textarea" :rows="12" spellcheck="false" class="mono"
            placeholder="在这里粘贴规则 JSON 数组（从你自己的策略源文件带进来）。" />
        </el-form-item>
        <el-form-item>
          <el-button @click="fillExample">填入示例形状</el-button>
          <el-button type="primary" @click="publish">发布这一版</el-button>
        </el-form-item>
      </el-form>
    </div>
  </AdminShell>
</template>
