<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api, configure } from '@shared/api'
import { session } from '../router'

const router = useRouter()

const fallbackBase = () =>
  location.protocol === 'http:' || location.protocol === 'https:'
    ? location.origin
    : 'http://127.0.0.1:8787'

const base = ref(location.protocol.startsWith('http') ? location.origin : 'http://127.0.0.1:8787')
const methods = ref([])
const active = ref('token')
const busy = ref(false)

// 各 tab 的输入
const token = ref('')
const username = ref('')
const password = ref('')

// LDAP 登录成功后的「创建/轮换下游 token」步骤（P1 会改成会话令牌直接进控制台）
const identity = ref('')
const identityWho = ref('')
const identityExpires = ref('')

const enabledMethods = computed(() => methods.value.filter((m) => m.enabled))

function normalizeBase(v) {
  return (v || '').trim().replace(/\/+$/, '') || fallbackBase()
}

async function loadMethods() {
  configure({ base: normalizeBase(base.value) })
  try {
    const data = await api('/v1/_auth/methods')
    methods.value = Array.isArray(data?.methods) ? data.methods : []
  } catch {
    // 老网关没有这个端点：至少保住 token 登录
    methods.value = [{ id: 'token', label: 'Token 登录', enabled: true }]
  }
  if (!enabledMethods.value.some((m) => m.id === active.value)) {
    active.value = enabledMethods.value[0]?.id || 'token'
  }
}

async function loginWithToken() {
  const b = normalizeBase(base.value)
  configure({ base: b, bearer: token.value.trim(), identity: '' })
  try {
    const me = await api('/v1/_me')
    session.save({ base: b, bearer: token.value.trim(), identity: '', who: me.name || '' })
    router.push('/overview')
  } catch (e) {
    ElMessage.error(e.status === 401 ? 'token 无效' : e.message)
  }
}

async function loginWithLDAP() {
  const b = normalizeBase(base.value)
  configure({ base: b, bearer: '', identity: '' })
  const data = await api('/v1/_identity/ldap/login', {
    method: 'POST',
    body: { username: username.value.trim(), password: password.value },
  })
  password.value = ''
  identity.value = data.token
  identityWho.value = data.subject || ''
  identityExpires.value = data.expires_at || ''
}

async function mintToken() {
  configure({ identity: identity.value })
  const minted = await api('/v1/_identity/me/token', { method: 'POST', body: {} })
  const b = normalizeBase(base.value)
  configure({ base: b, bearer: minted.token, identity: identity.value })
  const me = await api('/v1/_me')
  session.save({ base: b, bearer: minted.token, identity: identity.value, who: me.name || '' })
  router.push('/overview')
}

async function submit(which) {
  busy.value = true
  try {
    if (which === 'token') await loginWithToken()
    else if (which === 'ldap') await loginWithLDAP()
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    busy.value = false
  }
}

function methodLabel(id) {
  const m = methods.value.find((x) => x.id === id)
  return m?.label || { token: 'Token 登录', ldap: '校园网账号', password: '账号密码', oauth: '统一身份认证' }[id] || id
}

onMounted(loadMethods)
</script>

<template>
  <div class="f-login-wrap">
    <div class="f-login-card">
      <h1>llmproxy</h1>
      <p class="sub">用机构提供的方式登录，管理自己的上游、用量与 API token。</p>

      <div class="f-form-row">
        <label for="net-base">网关地址</label>
        <el-input id="net-base" v-model="base" spellcheck="false" placeholder="http://127.0.0.1:8787" />
      </div>

      <el-tabs v-model="active">
        <el-tab-pane
          v-for="m in methods"
          :key="m.id"
          :label="m.label || methodLabel(m.id)"
          :name="m.id"
          :disabled="!m.enabled"
        >
          <!-- token 登录 -->
          <template v-if="m.id === 'token'">
            <div class="f-form-row">
              <label>下游 token</label>
              <el-input v-model="token" type="password" show-password placeholder="sk-…" @keyup.enter="submit('token')" />
            </div>
            <el-button type="primary" :loading="busy" style="width: 100%" @click="submit('token')">登录</el-button>
          </template>

          <!-- 校园网 / LDAP 账号 -->
          <template v-else-if="m.id === 'ldap'">
            <template v-if="!identity">
              <div class="f-form-row">
                <label>用户名</label>
                <el-input v-model="username" placeholder="学号 / 工号" @keyup.enter="submit('ldap')" />
              </div>
              <div class="f-form-row">
                <label>口令</label>
                <el-input v-model="password" type="password" show-password @keyup.enter="submit('ldap')" />
              </div>
              <el-button type="primary" :loading="busy" style="width: 100%" @click="submit('ldap')">登录</el-button>
            </template>
            <template v-else>
              <el-alert
                :title="`已以 ${identityWho} 登录，会话令牌 ${identityExpires || ''} 前有效`"
                type="success"
                :closable="false"
                show-icon
                style="margin-bottom: 14px"
              />
              <el-button type="primary" style="width: 100%" @click="mintToken">创建 / 轮换 API token</el-button>
              <p class="f-muted" style="font-size: 12px; margin-top: 10px">
                第一次点是创建；如果以前已经有 token，旧 token 会立即失效。新 token 只显示一次。
              </p>
            </template>
          </template>

          <!-- 账号密码（P1 接本地账号库） -->
          <template v-else-if="m.id === 'password'">
            <el-empty description="本地账号登录尚未启用" :image-size="60" />
          </template>

          <!-- OAuth（P1 接授权码流程） -->
          <template v-else-if="m.id === 'oauth'">
            <el-empty description="统一身份认证登录尚未启用" :image-size="60" />
          </template>

          <template v-else>
            <el-empty :description="`未知登录方式：${m.id}`" :image-size="60" />
          </template>
        </el-tab-pane>
      </el-tabs>
    </div>
  </div>
</template>
