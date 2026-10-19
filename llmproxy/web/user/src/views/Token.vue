<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '@shared/api'
import AppShell from '../components/AppShell.vue'

const me = ref(null)
const minted = ref('')
const dialog = ref(false)
const busy = ref(false)

async function load() {
  try {
    me.value = await api('/v1/_me')
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function rotate() {
  try {
    await ElMessageBox.confirm(
      '轮换后旧 token 立即失效（正在用它的脚本会断）。新 token 只显示一次。',
      '创建 / 轮换 API Token',
      { confirmButtonText: '继续', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    return
  }
  busy.value = true
  try {
    const data = await api('/v1/_me/token', { method: 'POST' })
    minted.value = data.token || ''
    dialog.value = true
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    busy.value = false
  }
}

async function copy() {
  try {
    await navigator.clipboard.writeText(minted.value)
    ElMessage.success('已复制')
  } catch {
    ElMessage.warning('复制失败，请手动选中复制')
  }
}

onMounted(load)
</script>

<template>
  <AppShell title="我的 API Token">
    <h2 class="f-page-title">下游 API Token</h2>
    <p class="f-page-sub">
      这枚 token 用于调用 <code>/v1/chat/completions</code>。明文只在创建/轮换时显示一次，
      之后无法再取回，只能再轮换。
    </p>

    <div class="f-card" style="max-width: 680px">
      <p style="margin-top: 0">
        当前账号：<strong>{{ me?.name || '—' }}</strong>
      </p>
      <p class="f-muted" style="font-size: 13px">
        一人一枚 token：点一次是「创建」，再点就是「轮换」，旧的立即失效。
      </p>
      <el-button type="primary" :loading="busy" @click="rotate">创建 / 轮换 API Token</el-button>
    </div>

    <el-dialog v-model="dialog" title="你的新 token（只显示这一次）" width="560px">
      <el-input v-model="minted" type="textarea" :rows="3" readonly />
      <template #footer>
        <el-button @click="copy">复制</el-button>
        <el-button type="primary" @click="dialog = false">我已保存</el-button>
      </template>
    </el-dialog>
  </AppShell>
</template>
