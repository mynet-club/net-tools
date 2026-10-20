<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api, configure } from '@shared/api'
import { ms } from '@shared/format'
import { session } from '../router'
import AppShell from '../components/AppShell.vue'

const tokenInput = ref('')
const hasBearer = ref(Boolean(session.load().bearer))
const model = ref('deepseek-chat')
const prompt = ref('用一句话介绍你自己。')
const answer = ref('')
const meta = ref('')
const busy = ref(false)

function saveToken() {
  const t = tokenInput.value.trim()
  if (!t) return
  const s = session.load()
  configure({ bearer: t, identity: s.identity })
  session.save({ bearer: t })
  hasBearer.value = true
  tokenInput.value = ''
  ElMessage.success('已保存到本标签页会话')
}

async function send() {
  if (!hasBearer.value) {
    ElMessage.warning('先填下游 token（只存在本标签页会话里）')
    return
  }
  busy.value = true
  answer.value = ''
  meta.value = ''
  const t0 = performance.now()
  try {
    const data = await api('/v1/chat/completions', {
      method: 'POST',
      headers: { Accept: 'application/json' },
      body: {
        model: model.value.trim() || 'deepseek-chat',
        messages: [{ role: 'user', content: prompt.value }],
      },
    })
    const elapsed = Math.round(performance.now() - t0)
    const u = data?.usage || {}
    answer.value = data?.choices?.[0]?.message?.content || JSON.stringify(data, null, 2)
    meta.value = model.value + ' · ' + ms(elapsed) +
      (u.total_tokens ? ' · ' + u.total_tokens + ' token' : '')
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    busy.value = false
  }
}

onMounted(() => {
  if (!hasBearer.value) ElMessage.info('试一下需要下游 token：先在上面填一次')
})
</script>

<template>
  <AppShell title="试一下">
    <h2 class="f-page-title">试一下</h2>
    <p class="f-page-sub">直接打本网关的 <code>/v1/chat/completions</code>，验证 token 与上游链路。</p>

    <div v-if="!hasBearer" class="f-card" style="max-width: 620px; margin-bottom: 16px">
      <p style="margin-top: 0" class="f-muted">你这次是登录进来的，控制台还没有下游 token。粘贴一次即可（只存在本标签页，关闭即失效）。</p>
      <div style="display: flex; gap: 8px">
        <el-input v-model="tokenInput" type="password" show-password placeholder="sk-…" @keyup.enter="saveToken" />
        <el-button type="primary" @click="saveToken">使用</el-button>
      </div>
      <p class="f-muted" style="font-size: 12px; margin-bottom: 0">
        忘了 token？到 <router-link to="/token">我的 API Token</router-link> 轮换一枚（旧的会失效）。
      </p>
    </div>

    <div class="f-card" style="max-width: 820px">
      <el-form label-width="70px">
        <el-form-item label="模型">
          <el-input v-model="model" placeholder="deepseek-chat" />
        </el-form-item>
        <el-form-item label="输入">
          <el-input v-model="prompt" type="textarea" :rows="4" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="busy" @click="send">发送</el-button>
          <span v-if="meta" class="f-muted" style="margin-left: 12px; font-size: 12px">{{ meta }}</span>
        </el-form-item>
      </el-form>

      <el-input v-if="answer" v-model="answer" type="textarea" :rows="10" readonly />
    </div>
  </AppShell>
</template>
