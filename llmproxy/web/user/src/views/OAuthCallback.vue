<script setup>
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, configure } from '@shared/api'
import { session } from '../router'

const route = useRoute()
const router = useRouter()
const err = ref('')

onMounted(async () => {
  const code = String(route.query.code || '')
  if (!code) {
    err.value = '回调缺少登录凭据，请重新登录。'
    return
  }
  const saved = session.load()
  const base = saved.base || location.origin
  configure({ base, bearer: '', identity: '' })
  try {
    const data = await api('/v1/_auth/oauth/exchange', {
      method: 'POST',
      body: { code },
    })
    configure({ identity: data.token })
    const me = await api('/v1/_me')
    session.save({ base, bearer: '', identity: data.token, who: me.name || data.subject || '' })
    router.replace('/overview')
  } catch (e) {
    err.value = e.message || '登录失败'
  }
})
</script>

<template>
  <div class="f-login-wrap">
    <div class="f-login-card">
      <h1>正在完成登录</h1>
      <p v-if="!err" class="sub">正在换取会话令牌…</p>
      <template v-else>
        <p class="sub">{{ err }}</p>
        <router-link to="/login">返回登录页</router-link>
      </template>
    </div>
  </div>
</template>
