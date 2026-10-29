<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '@shared/api'
import AdminShell from '../components/AdminShell.vue'

const tab = ref('providers')
const configPath = ref('')
const providers = ref([])
const busy = ref(false)
const saving = ref(false)

const dialog = ref(false)
const editing = ref(false)
const err = ref('')
const candidates = ref([])
const syncing = ref(false)

const blank = () => ({
  name: '',
  enabled: true,
  base_url: '',
  api_key: '',
  has_key: false,
  api_key_hint: '',
  weight: 1,
  proxy: 'direct',
  timeout_ms: 120000,
  max_data_level: '',
  protocol: '',
  max_concurrent: 0,
  mode: 'all',
  rows: [],
  catchAll: false,
})
const form = reactive(blank())

// 登录方式
const auth = reactive({
  session_ttl_ms: 43200000,
  methods: { password: true, token: true, oauth: true, ldap: true },
  oauth: {
    provider_name: '',
    client_id: '',
    client_secret: '',
    has_secret: false,
    auth_url: '',
    token_url: '',
    userinfo_url: '',
    redirect_url: '',
    scopes: '',
    subject_claim: 'sub',
    name_claim: 'name',
    auth_style: 'basic',
    timeout_ms: 10000,
    spa_path: '/ui/',
  },
})
const authBusy = ref(false)

async function loadConfig() {
  busy.value = true
  try {
    const data = await api('/v1/_admin/config')
    configPath.value = data.path || ''
    providers.value = data.providers || []
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    busy.value = false
  }
}

function modelSummary(p) {
  const m = p.models || {}
  if (m.passthrough) return ['* 全部直通']
  const out = Object.entries(m.map || {})
    .filter(([d]) => d !== '*')
    .map(([down, up]) => (down === up ? down : down + ' → ' + up))
  if (m.catch_all) out.push('其余直通')
  return out.length ? out : ['—']
}

function toBody(p) {
  const models = p.models?.passthrough
    ? ['*']
    : { ...(p.models?.map || {}), ...(p.models?.catch_all ? { '*': '*' } : {}) }
  return {
    name: p.name,
    enabled: !!p.enabled,
    base_url: p.base_url,
    api_key: p.api_key || '',
    weight: p.weight,
    proxy: p.proxy,
    timeout_ms: p.timeout_ms,
    max_data_level: p.max_data_level || '',
    protocol: p.protocol || '',
    max_concurrent: p.max_concurrent || 0,
    models,
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
    ...p,
    api_key: '',
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
    err.value = '先填名称与地址，再同步模型列表'
    return
  }
  syncing.value = true
  try {
    const body = { base_url: form.base_url.trim() }
    if (form.api_key) body.api_key = form.api_key
    const data = await api('/v1/_admin/providers/' + encodeURIComponent(form.name.trim()) + '/discover', {
      method: 'POST',
      body,
    })
    candidates.value = data.models || []
    if (candidates.value.length) form.mode = 'pick'
  } catch (e) {
    err.value = '同步失败：' + e.message
  } finally {
    syncing.value = false
  }
}

function buildModels() {
  if (form.mode === 'all') return { passthrough: true }
  const map = {}
  for (const r of form.rows) {
    const down = (r.down || '').trim()
    if (!down) continue
    map[down] = (r.up || down).trim()
  }
  if (form.catchAll) map['*'] = '*'
  if (Object.keys(map).length === 0) return null
  return { map, catch_all: !!form.catchAll }
}

async function saveDialog() {
  if (saving.value || syncing.value) return
  err.value = ''
  const name = form.name.trim()
  if (!name || !form.base_url.trim()) {
    err.value = '名称与地址必填'
    return
  }
  const idx = providers.value.findIndex((p) => p.name === name)
  if (!editing.value && idx >= 0) {
    err.value = '供应商名称已存在，请编辑已有供应商'
    return
  }
  const models = buildModels()
  if (models === null) {
    err.value = '至少选一个模型，或把模式改成「全部直通」'
    return
  }
  if (!editing.value && !form.api_key) {
    err.value = '新供应商必须填 api_key'
    return
  }
  const item = {
    name,
    enabled: form.enabled,
    base_url: form.base_url.trim(),
    api_key: form.api_key,
    has_key: form.has_key || Boolean(form.api_key),
    api_key_hint: form.api_key ? '' : form.api_key_hint,
    weight: Number(form.weight) || 1,
    proxy: (form.proxy || 'direct').trim(),
    timeout_ms: Number(form.timeout_ms) || 120000,
    max_data_level: form.max_data_level || '',
    protocol: form.protocol || '',
    max_concurrent: Number(form.max_concurrent) || 0,
    models,
  }
  const next = [...providers.value]
  if (editing.value) next.splice(idx, 1, item)
  else next.push(item)
  saving.value = true
  try {
    await saveProviders(next)
    form.api_key = ''
    dialog.value = false
  } catch (e) {
    err.value = e.message
  } finally {
    saving.value = false
  }
}

async function saveProviders(next) {
  const body = { providers: next.map(toBody) }
  const data = await api('/v1/_admin/config/providers', { method: 'PUT', body })
  providers.value = next.map((p) => ({ ...p, api_key: '' }))
  ElMessage.success(
    (data.applied ? '已保存并生效' : '已写入（热加载稍后生效）') +
      (data.backup ? ' · 备份 ' + data.backup : ''),
  )
  if (data.warning) ElMessage.warning(data.warning)
  await loadConfig()
}

async function validateAll() {
  const body = { providers: providers.value.map(toBody) }
  try {
    const data = await api('/v1/_admin/config/validate', { method: 'POST', body })
    if (data.strict_ok === false) {
      ElMessage.warning('能写进文件但加载会失败：' + data.strict_error)
    } else {
      ElMessage.success('校验通过（' + data.providers + ' 个供应商）')
    }
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function removeProvider(i) {
  if (saving.value) return
  if (providers.value.length === 1) {
    ElMessage.warning('至少保留一个供应商')
    return
  }
  saving.value = true
  try {
    await ElMessageBox.confirm(`确定移除供应商「${providers.value[i].name}」？`, '移除供应商', {
      type: 'warning',
      confirmButtonText: '移除',
      cancelButtonText: '取消',
    })
    await saveProviders(providers.value.filter((_, index) => index !== i))
  } catch (e) {
    if (e !== 'cancel' && e !== 'close') ElMessage.error(e.message)
  } finally {
    saving.value = false
  }
}

async function loadAuth() {
  try {
    const data = await api('/v1/_admin/config/auth')
    auth.session_ttl_ms = data.session_ttl_ms || 43200000
    Object.assign(auth.methods, data.methods || {})
    const o = data.oauth || {}
    auth.oauth.has_secret = !!o.has_secret
    auth.oauth.provider_name = o.provider_name || ''
    auth.oauth.client_id = o.client_id || ''
    auth.oauth.client_secret = ''
    auth.oauth.auth_url = o.auth_url || ''
    auth.oauth.token_url = o.token_url || ''
    auth.oauth.userinfo_url = o.userinfo_url || ''
    auth.oauth.redirect_url = o.redirect_url || ''
    auth.oauth.scopes = (o.scopes || []).join(' ')
    auth.oauth.subject_claim = o.subject_claim || 'sub'
    auth.oauth.name_claim = o.name_claim || 'name'
    auth.oauth.auth_style = o.auth_style || 'basic'
    auth.oauth.timeout_ms = o.timeout_ms || 10000
    auth.oauth.spa_path = o.spa_path || '/ui/'
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function saveAuth() {
  authBusy.value = true
  try {
    const data = await api('/v1/_admin/config/auth', {
      method: 'PUT',
      body: {
        session_ttl_ms: auth.session_ttl_ms,
        methods: { ...auth.methods },
        oauth: {
          ...auth.oauth,
          scopes: auth.oauth.scopes.split(/[\s,]+/).filter(Boolean),
        },
      },
    })
    ElMessage.success(data.applied ? '登录方式已保存并生效' : '已写入（热加载稍后生效）')
    if (data.warning) ElMessage.warning(data.warning)
    await loadAuth()
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    authBusy.value = false
  }
}

onMounted(async () => {
  await Promise.all([loadConfig(), loadAuth()])
})
</script>

<template>
  <AdminShell title="配置">
    <h2 class="f-page-title">配置</h2>
    <p class="f-page-sub">{{ configPath ? '配置文件：' + configPath : '系统上游来自 config.yaml；保存只替换对应段。' }}</p>

    <el-tabs v-model="tab">
      <el-tab-pane label="系统上游" name="providers">
        <div style="display: flex; gap: 10px; margin-bottom: 12px">
          <el-button type="primary" :disabled="busy || saving" @click="openNew">添加供应商</el-button>
          <el-button :disabled="busy || saving" @click="validateAll">校验</el-button>
          <span class="f-muted" style="align-self: center; font-size: 12px">
            新增、编辑和移除后立即保存；密钥留空 = 沿用原值；保存前自动备份
          </span>
        </div>

        <el-table v-loading="busy" :data="providers" border style="width: 100%">
          <el-table-column prop="name" label="名称" width="140" />
          <el-table-column prop="base_url" label="地址" min-width="220" />
          <el-table-column label="模型" min-width="220">
            <template #default="{ row }">
              <el-tag v-for="m in modelSummary(row)" :key="m" size="small" style="margin: 2px 4px 2px 0">{{ m }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="api_key_hint" label="密钥" width="130" />
          <el-table-column prop="max_data_level" label="分级" width="90" />
          <el-table-column label="协议" width="130">
            <template #default="{ row }">{{ row.protocol || 'openai_chat' }}</template>
          </el-table-column>
          <el-table-column label="状态" width="80">
            <template #default="{ row }">
              <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '启用' : '停用' }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="130" fixed="right">
            <template #default="{ row, $index }">
              <el-button link type="primary" :disabled="busy || saving" @click="openEdit(row)">编辑</el-button>
              <el-button link type="danger" :disabled="busy || saving" @click="removeProvider($index)">移除</el-button>
            </template>
          </el-table-column>
        </el-table>

        <el-dialog v-model="dialog" :title="editing ? '编辑供应商' : '新增供应商'" width="760px" destroy-on-close
          :close-on-click-modal="false" :close-on-press-escape="!saving" :show-close="!saving">
          <el-form label-width="96px" :disabled="saving" @submit.prevent="saveDialog">
            <el-form-item label="名称"><el-input v-model="form.name" :disabled="editing" /></el-form-item>
            <el-form-item label="地址"><el-input v-model="form.base_url" placeholder="https://api.example.com/v1" /></el-form-item>
            <el-form-item label="密钥">
              <el-input v-model="form.api_key" type="password" show-password
                :placeholder="editing ? '留空 = 不修改（当前 ' + (form.api_key_hint || '已设置') + '）' : 'sk-…'" />
            </el-form-item>
            <el-form-item label="模型">
              <el-radio-group v-model="form.mode">
                <el-radio-button value="all">全部直通</el-radio-button>
                <el-radio-button value="pick">指定模型</el-radio-button>
              </el-radio-group>
              <el-button :loading="syncing" style="margin-left: 12px" @click="syncModels">从上游同步</el-button>
            </el-form-item>
            <template v-if="form.mode === 'pick'">
              <el-form-item v-if="candidates.length" label="候选">
                <div style="max-height: 120px; overflow: auto">
                  <el-check-tag v-for="c in candidates" :key="c" :checked="hasCandidate(c)"
                    style="margin: 2px 6px 2px 0" @change="pickCandidate(c)">
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
            <el-form-item label="权重"><el-input-number v-model="form.weight" :min="0.01" :step="0.5" /></el-form-item>
            <el-form-item label="超时"><el-input-number v-model="form.timeout_ms" :min="1000" :step="10000" /><span class="f-muted" style="margin-left: 8px">毫秒</span></el-form-item>
            <el-form-item label="代理"><el-input v-model="form.proxy" placeholder="direct 或代理名/地址" /></el-form-item>
            <el-form-item label="分级上限">
              <el-select v-model="form.max_data_level" placeholder="未声明">
                <el-option label="未声明（沿用原值）" value="" />
                <el-option label="public" value="public" />
                <el-option label="internal" value="internal" />
                <el-option label="confidential" value="confidential" />
                <el-option label="restricted" value="restricted" />
              </el-select>
            </el-form-item>
            <el-form-item label="协议">
              <el-select v-model="form.protocol" placeholder="默认 openai_chat">
                <el-option label="openai_chat（默认）" value="" />
                <el-option label="openai_chat" value="openai_chat" />
                <el-option label="ollama_native" value="ollama_native" />
                <el-option label="anthropic_messages" value="anthropic_messages" />
              </el-select>
            </el-form-item>
            <el-form-item label="并发上限"><el-input-number v-model="form.max_concurrent" :min="0" /><span class="f-muted" style="margin-left: 8px">0 = 不限</span></el-form-item>
            <el-form-item label="启用"><el-switch v-model="form.enabled" /></el-form-item>
            <p v-if="err" style="color: #dc2626; margin: 0">{{ err }}</p>
          </el-form>
          <template #footer>
            <el-button :disabled="saving" @click="dialog = false">取消</el-button>
            <el-button type="primary" :loading="saving" :disabled="syncing" @click="saveDialog">保存</el-button>
          </template>
        </el-dialog>
      </el-tab-pane>

      <el-tab-pane label="登录方式" name="auth">
        <el-form label-width="140px" style="max-width: 760px">
          <el-form-item label="启用的方式">
            <el-checkbox v-model="auth.methods.password">账号密码</el-checkbox>
            <el-checkbox v-model="auth.methods.token">Token 登录</el-checkbox>
            <el-checkbox v-model="auth.methods.oauth">统一身份认证（OAuth）</el-checkbox>
            <el-checkbox v-model="auth.methods.ldap">校园网账号（LDAP）</el-checkbox>
          </el-form-item>
          <el-form-item label="会话时长">
            <el-input-number v-model="auth.session_ttl_ms" :min="60000" :step="3600000" />
            <span class="f-muted" style="margin-left: 8px; font-size: 12px">
              毫秒（默认 12 小时，上限 24 小时）
            </span>
          </el-form-item>

          <el-divider content-position="left">OAuth 客户端（启用「统一身份认证」时必填）</el-divider>
          <el-form-item label="显示名称"><el-input v-model="auth.oauth.provider_name" placeholder="统一身份认证" /></el-form-item>
          <el-form-item label="client_id"><el-input v-model="auth.oauth.client_id" /></el-form-item>
          <el-form-item label="client_secret">
            <el-input v-model="auth.oauth.client_secret" type="password" show-password
              :placeholder="auth.oauth.has_secret ? '留空 = 不修改（已设置）' : '必填'" />
          </el-form-item>
          <el-form-item label="auth_url"><el-input v-model="auth.oauth.auth_url" placeholder="https://sso.example.edu/oauth2/authorize" /></el-form-item>
          <el-form-item label="token_url"><el-input v-model="auth.oauth.token_url" placeholder="https://sso.example.edu/oauth2/token" /></el-form-item>
          <el-form-item label="userinfo_url"><el-input v-model="auth.oauth.userinfo_url" placeholder="https://sso.example.edu/oauth2/userinfo" /></el-form-item>
          <el-form-item label="scopes"><el-input v-model="auth.oauth.scopes" placeholder="openid profile" /></el-form-item>
          <el-form-item label="redirect_url">
            <el-input v-model="auth.oauth.redirect_url" placeholder="https://网关地址/v1/_auth/oauth/callback" />
            <div class="f-muted" style="font-size: 12px">路径必须是 /v1/_auth/oauth/callback（外部可达）</div>
          </el-form-item>
          <el-form-item label="subject_claim"><el-input v-model="auth.oauth.subject_claim" /></el-form-item>
          <el-form-item label="name_claim"><el-input v-model="auth.oauth.name_claim" /></el-form-item>
          <el-form-item label="客户端认证">
            <el-select v-model="auth.oauth.auth_style">
              <el-option label="basic（默认）" value="basic" />
              <el-option label="post" value="post" />
            </el-select>
          </el-form-item>
          <el-form-item label="超时"><el-input-number v-model="auth.oauth.timeout_ms" :min="500" :step="1000" /><span class="f-muted" style="margin-left: 8px">毫秒</span></el-form-item>
          <el-form-item label="登录后跳回">
            <el-input v-model="auth.oauth.spa_path" />
            <div class="f-muted" style="font-size: 12px">默认 /ui/（登录成功后跳回的 SPA 路径）</div>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="authBusy" @click="saveAuth">保存登录方式</el-button>
          </el-form-item>
        </el-form>
      </el-tab-pane>
    </el-tabs>
  </AdminShell>
</template>
