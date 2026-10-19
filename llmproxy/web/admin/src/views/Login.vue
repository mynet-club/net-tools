<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api, configure } from '@shared/api'
import { session } from '../router'

const router = useRouter()
const base = ref(location.protocol.startsWith('http') ? location.origin : 'http://127.0.0.1:8787')
const token = ref('')
const busy = ref(false)

async function submit() {
  const b = (base.value.trim() || location.origin).replace(/\/+$/, '')
  configure({ base: b, bearer: token.value.trim() })
  busy.value = true
  try {
    await api('/v1/_admin/stats')
    session.save({ base: b, bearer: token.value.trim() })
    router.push('/home')
  } catch (e) {
    ElMessage.error(e.status === 403 ? '管理凭证无效' : e.message)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="f-login-wrap">
    <div class="f-login-card">
      <h1>llmproxy 管理台</h1>
      <p class="sub">用 server.admin_token 登录；管理用户、上游、策略与回放。</p>
      <div class="f-form-row">
        <label>网关地址</label>
        <el-input v-model="base" spellcheck="false" />
      </div>
      <div class="f-form-row">
        <label>admin_token</label>
        <el-input v-model="token" type="password" show-password @keyup.enter="submit" />
      </div>
      <el-button type="primary" :loading="busy" style="width: 100%" @click="submit">登录</el-button>
    </div>
  </div>
</template>
