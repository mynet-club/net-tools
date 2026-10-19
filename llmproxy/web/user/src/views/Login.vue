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
const active = ref('password')
const busy = ref(false)

const token = ref('')
const username = ref('')
const password = ref('')

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

// 登录成功后统一用「会话令牌」进控制台：X-Identity-Token + /v1/_me。
// 下游 token（sk-）只在 token 页面创建/轮换，不在这里自动动它。
async function enterWithSession(b, identityToken) {
  configure({ base: b, bearer: '', identity: identityToken })
  const me = await api('/v1/_me')
  session.save({ base: b, bearer: '', identity: identityToken, who: me.name || '' })
  router.push('/overview')
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

async function loginWithPassword() {
  const b = normalizeBase(base.value)
  configure({ base: b, bearer: '', identity: '' })
  const data = await api('/v1/_auth/password/login', {
    method: 'POST',
    body: { username: username.value.trim(), password: password.value },
  })
  password.value = ''
  await enterWithSession(b, data.token)
}

async function loginWithLDAP() {
  const b = normalizeBase(base.value)
  configure({ base: b, bearer: '', identity: '' })
  const data = await api('/v1/_identity/ldap/login', {
    method: 'POST',
    body: { username: username.value.trim(), password: password.value },
  })
  password.value = ''
  await enterWithSession(b, data.token)
}

function startOAuth() {
  const b = normalizeBase(base.value)
  // 回调落在网关自己的 SPA 上；把地址先存进会话，回调页才能知道该向哪个网关兑换
  session.save({ base: b })
  location.href = b + '/v1/_auth/oauth/start'
}

async function submit(which) {
  busy.value = true
  try {
    if (which === 'token') await loginWithToken()
    else if (which === 'password') await loginWithPassword()
    else if (which === 'ldap') await loginWithLDAP()
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    busy.value = false
  }
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
          :label="m.label || m.id"
          :name="m.id"
          :disabled="!m.enabled"
        >
          <!-- 本地账号密码 -->
          <template v-if="m.id === 'password'">
            <div class="f-form-row">
              <label>账号</label>
              <el-input v-model="username" autocomplete="username" @keyup.enter="submit('password')" />
            </div>
            <div class="f-form-row">
              <label>口令</label>
              <el-input v-model="password" type="password" show-password autocomplete="current-password" @keyup.enter="submit('password')" />
            </div>
            <el-button type="primary" :loading="busy" style="width: 100%" @click="submit('password')">登录</el-button>
          </template>

          <!-- 下游 token -->
          <template v-else-if="m.id === 'token'">
            <div class="f-form-row">
              <label>下游 token</label>
              <el-input v-model="token" type="password" show-password placeholder="sk-…" @keyup.enter="submit('token')" />
            </div>
            <el-button type="primary" :loading="busy" style="width: 100%" @click="submit('token')">登录</el-button>
          </template>

          <!-- OAuth / OIDC 统一身份认证 -->
          <template v-else-if="m.id === 'oauth'">
            <p class="f-muted" style="margin-top: 0; font-size: 13px">
              会跳转到机构统一认证页，认证完成后回到这里。
            </p>
            <el-button type="primary" style="width: 100%" @click="startOAuth">前往 {{ m.label }}</el-button>
          </template>

          <!-- LDAP / AD 校园网账号 -->
          <template v-else-if="m.id === 'ldap'">
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
            <el-empty :description="`未知登录方式：${m.id}`" :image-size="60" />
          </template>
        </el-tab-pane>
      </el-tabs>
    </div>
  </div>
</template>
