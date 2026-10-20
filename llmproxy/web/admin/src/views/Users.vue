<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '@shared/api'
import { money, num } from '@shared/format'
import AdminShell from '../components/AdminShell.vue'

const users = ref([])
const currency = ref('CNY')
const busy = ref(false)

const createOpen = ref(false)
const newName = ref('')
const tokenOpen = ref(false)
const mintedToken = ref('')
const tokenTitle = ref('')

const pwdOpen = ref(false)
const pwdUser = ref('')
const pwdValue = ref('')
const pwdBusy = ref(false)

const drawer = ref(false)
const detail = ref(null)
const edit = reactive({
  mode: 'byo',
  quota_month_tokens: 0,
  quota_month_cost: 0,
  rpm: 0,
  max_concurrent: 0,
  tokens_per_min: 0,
})

async function load() {
  busy.value = true
  try {
    const data = await api('/v1/_admin/users')
    users.value = data.users || []
    currency.value = data.currency || 'CNY'
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    busy.value = false
  }
}

async function createUser() {
  const name = newName.value.trim()
  if (!name) return
  try {
    const data = await api('/v1/_admin/users', { method: 'POST', body: { name } })
    createOpen.value = false
    newName.value = ''
    tokenTitle.value = '用户 ' + name + ' 的下游 token（只显示这一次）'
    mintedToken.value = data.token || ''
    tokenOpen.value = true
    await load()
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function rotate(u) {
  try {
    await ElMessageBox.confirm(
      '轮换 ' + u.name + ' 的 token？旧 token 立即失效。',
      '轮换 token',
      { confirmButtonText: '轮换', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    return
  }
  try {
    const data = await api('/v1/_admin/users/' + encodeURIComponent(u.name) + '/token', { method: 'POST' })
    tokenTitle.value = u.name + ' 的新 token（只显示这一次）'
    mintedToken.value = data.token || ''
    tokenOpen.value = true
  } catch (e) {
    ElMessage.error(e.message)
  }
}

function openPassword(u) {
  pwdUser.value = u.name
  pwdValue.value = ''
  pwdOpen.value = true
}

async function savePassword() {
  if (pwdValue.value.length < 8) {
    ElMessage.warning('口令至少 8 字节')
    return
  }
  pwdBusy.value = true
  try {
    await api('/v1/_admin/users/' + encodeURIComponent(pwdUser.value) + '/password', {
      method: 'PUT',
      body: { password: pwdValue.value },
    })
    pwdOpen.value = false
    pwdValue.value = ''
    ElMessage.success('本地密码已设置')
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    pwdBusy.value = false
  }
}

async function toggle(u) {
  try {
    await api('/v1/_admin/users/' + encodeURIComponent(u.name), {
      method: 'PUT',
      body: { enabled: !u.enabled },
    })
    await load()
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function remove(u) {
  try {
    await ElMessageBox.confirm(
      '删除用户 ' + u.name + ' 及其上游配置？该操作不可撤销。',
      '删除用户',
      { confirmButtonText: '删除', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    return
  }
  try {
    await api('/v1/_admin/users/' + encodeURIComponent(u.name), { method: 'DELETE' })
    ElMessage.success('已删除')
    await load()
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function openDetail(u) {
  try {
    detail.value = await api('/v1/_admin/users/' + encodeURIComponent(u.name))
    const q = detail.value.quota || {}
    const l = detail.value.limits || {}
    Object.assign(edit, {
      mode: detail.value.mode || 'byo',
      quota_month_tokens: q.month_tokens || 0,
      quota_month_cost: q.month_cost || 0,
      rpm: l.rpm || 0,
      max_concurrent: l.max_concurrent || 0,
      tokens_per_min: l.tokens_per_min || 0,
    })
    drawer.value = true
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function saveDetail() {
  try {
    await api('/v1/_admin/users/' + encodeURIComponent(detail.value.name), {
      method: 'PUT',
      body: { ...edit },
    })
    ElMessage.success('已保存')
    await Promise.all([openDetail(detail.value.name), load()])
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function copyToken() {
  try {
    await navigator.clipboard.writeText(mintedToken.value)
    ElMessage.success('已复制')
  } catch {
    ElMessage.warning('复制失败，请手动选中复制')
  }
}

onMounted(load)
</script>

<template>
  <AdminShell title="用户">
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 6px">
      <h2 class="f-page-title" style="margin: 0">用户</h2>
      <el-button type="primary" @click="createOpen = true">新增用户</el-button>
    </div>
    <p class="f-page-sub">用户用自己的下游 token 调模型；消费模式受配额与限流约束，账单归网关。</p>

    <el-table v-loading="busy" :data="users" border style="width: 100%">
      <el-table-column prop="name" label="名称" width="140">
        <template #default="{ row }"><code class="mono">{{ row.name }}</code></template>
      </el-table-column>
      <el-table-column label="模式" width="100">
        <template #default="{ row }">
          <el-tag :type="row.mode === 'consumption' ? 'warning' : 'info'" size="small">
            {{ row.mode === 'consumption' ? '消费' : '自带' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="90">
        <template #default="{ row }">
          <el-tag :type="row.enabled ? 'success' : 'info'" size="small">{{ row.enabled ? '启用' : '停用' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="请求 / 成功 / 失败" width="170" align="right">
        <template #default="{ row }">
          {{ num(row.usage_all?.requests) }} / {{ num(row.usage_all?.ok) }} / {{ num(row.usage_all?.failed) }}
        </template>
      </el-table-column>
      <el-table-column label="Token 合计" width="120" align="right">
        <template #default="{ row }">{{ num(row.usage_all?.total_tokens) }}</template>
      </el-table-column>
      <el-table-column label="本月已用" width="150" align="right">
        <template #default="{ row }">
          {{ num(row.quota?.used_tokens) }} tok
          <span v-if="row.mode === 'consumption'" class="f-muted"> · {{ money(row.quota?.used_cost, currency) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="上游" min-width="140">
        <template #default="{ row }">{{ (row.providers || []).join('、') || '—' }}</template>
      </el-table-column>
      <el-table-column label="操作" width="260" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" @click="openDetail(row)">详情</el-button>
          <el-button link type="primary" @click="rotate(row)">轮换 token</el-button>
          <el-button link type="primary" @click="openPassword(row)">设密码</el-button>
          <el-button link @click="toggle(row)">{{ row.enabled ? '停用' : '启用' }}</el-button>
          <el-button link type="danger" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
      <template #empty><el-empty description="还没有用户" :image-size="70" /></template>
    </el-table>

    <!-- 新增 -->
    <el-dialog v-model="createOpen" title="新增用户" width="420px">
      <el-input v-model="newName" placeholder="用户名（字母/数字/点/下划线/连字符）" @keyup.enter="createUser" />
      <p class="f-muted" style="font-size: 12px">创建后会给出一枚只显示一次的下游 token。</p>
      <template #footer>
        <el-button @click="createOpen = false">取消</el-button>
        <el-button type="primary" @click="createUser">创建</el-button>
      </template>
    </el-dialog>

    <!-- token 只显示一次 -->
    <el-dialog v-model="tokenOpen" :title="tokenTitle" width="560px">
      <el-input v-model="mintedToken" type="textarea" :rows="3" readonly />
      <template #footer>
        <el-button @click="copyToken">复制</el-button>
        <el-button type="primary" @click="tokenOpen = false">我已保存</el-button>
      </template>
    </el-dialog>

    <!-- 设置本地密码 -->
    <el-dialog v-model="pwdOpen" :title="'设置本地密码 · ' + pwdUser" width="440px">
      <el-input v-model="pwdValue" type="password" show-password placeholder="至少 8 字节" />
      <p class="f-muted" style="font-size: 12px">保存后用户可用「账号密码」tab 登录。</p>
      <template #footer>
        <el-button @click="pwdOpen = false">取消</el-button>
        <el-button type="primary" :loading="pwdBusy" @click="savePassword">保存</el-button>
      </template>
    </el-dialog>

    <!-- 详情 -->
    <el-drawer v-model="drawer" :title="detail ? '用户 · ' + detail.name : '用户'" size="520px">
      <template v-if="detail">
        <el-descriptions :column="1" border size="small">
          <el-descriptions-item label="状态">{{ detail.enabled ? '启用' : '停用' }}</el-descriptions-item>
          <el-descriptions-item label="创建时间">{{ detail.created_at }}</el-descriptions-item>
          <el-descriptions-item label="全部流量">
            {{ num(detail.usage_all?.requests) }} 次 · {{ num(detail.usage_all?.total_tokens) }} token
          </el-descriptions-item>
          <el-descriptions-item label="上游">{{ (detail.providers || []).join('、') || '—' }}</el-descriptions-item>
          <el-descriptions-item label="模型">
            {{ (detail.models || []).join('、') || '—' }}
            <span v-if="detail.models_passthrough" class="f-muted">（含全部直通）</span>
            <span v-if="detail.models_source" class="f-muted"> · 来源 {{ detail.models_source }}</span>
          </el-descriptions-item>
          <el-descriptions-item v-if="detail.broken_providers?.length" label="不可用上游">
            {{ detail.broken_providers.join('、') }}
          </el-descriptions-item>
        </el-descriptions>

        <h3 style="margin: 18px 0 10px">设置</h3>
        <el-form label-width="110px">
          <el-form-item label="模式">
            <el-select v-model="edit.mode">
              <el-option label="自带上游（byo）" value="byo" />
              <el-option label="消费系统上游" value="consumption" />
            </el-select>
          </el-form-item>
          <el-form-item label="月 token 配额">
            <el-input-number v-model="edit.quota_month_tokens" :min="0" :step="100000" />
            <span class="f-muted" style="margin-left: 8px; font-size: 12px">0 = 不限</span>
          </el-form-item>
          <el-form-item label="月金额配额">
            <el-input-number v-model="edit.quota_month_cost" :min="0" :step="10" />
            <span class="f-muted" style="margin-left: 8px; font-size: 12px">0 = 不限</span>
          </el-form-item>
          <el-form-item label="RPM">
            <el-input-number v-model="edit.rpm" :min="0" />
          </el-form-item>
          <el-form-item label="最大并发">
            <el-input-number v-model="edit.max_concurrent" :min="0" />
          </el-form-item>
          <el-form-item label="每分钟 token">
            <el-input-number v-model="edit.tokens_per_min" :min="0" :step="1000" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="saveDetail">保存设置</el-button>
          </el-form-item>
        </el-form>
      </template>
    </el-drawer>
  </AdminShell>
</template>
