<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessageBox } from 'element-plus'
import { api } from '@shared/api'
import AdminShell from '../components/AdminShell.vue'

const policy = ref(null)
const bundles = ref(null)
const bundlesErr = ref('')
const users = ref([])
const busy = ref(false)
const banner = ref('')
const bannerErr = ref(false)

const sim = reactive({ scope: '', model: '', request_id: '', result: null, error: '', busy: false })
const trace = reactive({ request_id: '', result: null, error: '', busy: false })

const backupsOpen = ref(false)
const backupsId = ref('')
const backupsTitle = ref('')
const backups = reactive({})

function setBanner(msg, isErr = false) {
  banner.value = msg || ''
  bannerErr.value = !!isErr
}

const shadowRate = computed(() => {
  const sh = policy.value?.shadow || {}
  return sh.evaluated > 0 && typeof sh.agree_percent === 'number'
    ? sh.agree_percent.toFixed(1) + '%'
    : '—'
})

const statCards = computed(() => {
  const d = policy.value || {}
  const sh = d.shadow || {}
  const by = sh.by_verdict || {}
  const moved = (by.primary_moved || 0) + (by.policy_denied || 0) +
    (by.no_candidate || 0) + (by.decision_denied || 0)
  const declared = d.declared_data_level && d.declared_data_level !== '-' &&
    d.declared_data_level !== d.data_level ? d.declared_data_level : ''
  return [
    { label: '配置模式', value: (d.configured_mode || '—') + ' → ' + (d.mode || '—'), hint: 'YAML 声明值 → 归一后的实际口径' },
    { label: '是否在跑', value: d.running ? '是' : '否', hint: d.running ? '' : '请求按旧路由运行' },
    { label: '生效版本', value: d.policy_version || '—' },
    { label: '路由代', value: d.routing_epoch || '—', hint: 'seed 由 request_id + 版本 + 代派生' },
    { label: '数据分级', value: declared ? d.data_level + '（声明 ' + declared + '）' : (d.data_level || '—'), hint: '高于某家上游上限时，该家不进候选池' },
    { label: '回落旧路由', value: d.fallback_to_legacy ? '开' : '关', hint: '只对「算不出计划」生效' },
    { label: '影子已判定', value: String(sh.evaluated || 0), hint: '不一致 ' + moved + ' 次' },
    { label: '影子一致率', value: shadowRate.value, hint: sh.evaluated ? '分母是已判定次数' : '还没有影子流量' },
  ]
})

const bundleRows = computed(() => {
  const pb = bundles.value || {}
  const rows = (pb.refs || []).map((r) => ({ ...r, kind: 'ref' }))
  ;(pb.orphans || []).forEach((o) => rows.push({ ...o, kind: 'orphan' }))
  return rows
})

function refStatus(r) {
  if (r.kind === 'orphan') return { text: '未引用', type: 'info', title: '内容文件在磁盘上，但配置里没有引用' }
  if (r.file_error) return { text: r.file_exists ? '读不回来' : '路径不合法', type: 'danger', title: r.file_error }
  if (!r.file_exists) return { text: '内容文件缺失', type: 'danger', title: r.drift || '' }
  if (!r.matches) return { text: '引用与内容不一致', type: 'danger', title: r.drift || '' }
  return { text: '一致 · 已加载', type: 'success', title: '' }
}

function verdictType(v) {
  if (v === 'agreed') return 'success'
  if (v === 'decision_denied' || v === 'policy_denied') return 'warning'
  if (v === 'no_candidate') return 'danger'
  return 'info'
}

async function load() {
  busy.value = true
  setBanner('')
  try {
    policy.value = await api('/v1/_admin/policy')
  } catch (e) {
    setBanner('读不到策略状态：' + e.message, true)
    busy.value = false
    return
  }
  try {
    bundles.value = await api('/v1/_admin/policy/bundles')
    bundlesErr.value = ''
  } catch (e) {
    bundles.value = null
    bundlesErr.value = e.message
  }
  try {
    const u = await api('/v1/_admin/users')
    users.value = u.users || []
  } catch {
    users.value = []
  }
  const d = policy.value || {}
  if (!d.running) {
    const noSection = !d.configured_mode || d.configured_mode === '-'
    const head = d.inactive_reason === 'policy_load_failed'
      ? '3.0 判定链路没有在跑：配置里启用了策略，但这一版加载失败，请求按旧路由静默运行。'
      : noSection
        ? '没启用 3.0：配置里还没有 policy 段，整套按旧路由运行。'
        : '没启用 3.0：policy.mode = ' + d.configured_mode + '（显式 legacy 就是应急开关）。'
    setBanner(head + (d.load_error ? '\n加载失败原因：' + d.load_error : ''), true)
  } else if (bundles.value?.drift_warning) {
    setBanner(bundles.value.drift_warning, true)
  } else if (bundlesErr.value) {
    setBanner('策略包核对视图读不到：' + bundlesErr.value + '\n发布、回滚、撤下需先恢复这一侧。', true)
  }
  busy.value = false
}

async function call(method, path, body) {
  try {
    const data = await api(path, { method, body })
    setBanner(data.note || '已完成。', !!(data.strict_error || data.applied === false))
    if (data.backup) setBanner((data.note || '已完成。') + '（配置备份 ' + data.backup + '）', !!(data.strict_error || data.applied === false))
    await load()
    return data
  } catch (e) {
    setBanner('失败：' + e.message, true)
    await load()
    return null
  }
}

async function setActive(id) {
  await call('POST', '/v1/_admin/policy/active', { bundle: id })
}

async function withdraw(row) {
  if (row.kind === 'orphan') return
  const others = (bundles.value?.refs || []).filter((x) => x.id !== row.id)
  if (row.active && others.length === 0) {
    setBanner('这是唯一的策略包：停用 3.0 请在「策略发布」里把模式切到 legacy。', true)
    return
  }
  let path = '/v1/_admin/policy/bundles/' + encodeURIComponent(row.id)
  try {
    if (row.active) {
      const { value } = await ElMessageBox.prompt(
        '要撤的正是生效包，接棒者的包 id：',
        '撤生效包：指定接棒者',
        { inputValue: others[0]?.id || '', confirmButtonText: '撤下', cancelButtonText: '取消' },
      )
      if (!value?.trim()) {
        setBanner('没给接棒者，已取消。', true)
        return
      }
      path += '?active=' + encodeURIComponent(value.trim())
    } else {
      await ElMessageBox.confirm(
        '撤下对 ' + row.id + ' 的引用？内容文件会留在磁盘上。',
        '撤下引用',
        { confirmButtonText: '撤下', cancelButtonText: '取消', type: 'warning' },
      )
    }
  } catch {
    return
  }
  await call('DELETE', path)
}

async function reference(orphan) {
  if (!orphan.id) {
    setBanner('这个文件连 id 都读不出来，要用发布表单覆盖它。', true)
    return
  }
  try {
    await ElMessageBox.confirm(
      '按磁盘上的 ' + orphan.id + '.yaml（v' + orphan.version + '，scope=' + orphan.scope + '）重新建立引用？',
      '重建引用',
      { confirmButtonText: '重建引用', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  await call('POST', '/v1/_admin/policy/bundles/' + encodeURIComponent(orphan.id) + '/reference', {})
}

async function openBackups(row) {
  backupsId.value = row.id
  backupsTitle.value = row.id + ' 的历史内容'
  backupsOpen.value = true
  if (!backups[row.id]) {
    backups[row.id] = { list: [], error: '', loading: true }
    try {
      const data = await api('/v1/_admin/policy/bundles/' + encodeURIComponent(row.id) + '/backups')
      backups[row.id] = { list: data.backups || [], error: '', loading: false }
    } catch (e) {
      backups[row.id] = { list: [], error: e.message, loading: false }
    }
  }
}

async function rollback(row, backup) {
  try {
    await ElMessageBox.confirm(
      '内容文件与引用一起回到 ' + backup.name + '？当前内容会先存成新备份。',
      '回滚策略包',
      { confirmButtonText: '回滚', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    return
  }
  backupsOpen.value = false
  await call('POST', '/v1/_admin/policy/bundles/' + encodeURIComponent(row.id) + '/rollback', { backup: backup.name })
}

async function runSimulate() {
  sim.error = ''
  sim.result = null
  if (!sim.model.trim()) {
    sim.error = '模型名必填'
    return
  }
  sim.busy = true
  try {
    sim.result = await api('/v1/_admin/policy/simulate', {
      method: 'POST',
      body: {
        scope: sim.scope,
        model: sim.model.trim(),
        request_id: sim.request_id.trim() || undefined,
      },
    })
  } catch (e) {
    sim.error = e.message
  } finally {
    sim.busy = false
  }
}

async function runTrace() {
  trace.error = ''
  trace.result = null
  if (!trace.request_id.trim()) {
    trace.error = 'request_id 必填'
    return
  }
  trace.busy = true
  try {
    trace.result = await api('/v1/_admin/policy/trace?request_id=' + encodeURIComponent(trace.request_id.trim()))
  } catch (e) {
    trace.error = e.message
  } finally {
    trace.busy = false
  }
}

onMounted(load)
</script>

<template>
  <AdminShell title="策略观测">
    <div style="display: flex; align-items: center; gap: 12px">
      <h2 class="f-page-title" style="margin: 0">策略观测</h2>
      <span class="f-muted" v-if="policy">配置修订 {{ policy.revision }} · schema v{{ policy.config_schema_version }}</span>
      <span style="flex: 1" />
      <el-button :loading="busy" @click="load">刷新</el-button>
    </div>
    <p class="f-page-sub">只读面：判定由服务端判定核给出，界面不复算权限。</p>

    <el-alert v-if="banner" :title="banner" :type="bannerErr ? 'error' : 'info'" :closable="false" show-icon
      style="white-space: pre-line; margin-bottom: 14px" />

    <div class="f-grid" style="margin-bottom: 18px">
      <div v-for="s in statCards" :key="s.label" class="f-card">
        <div class="f-muted">{{ s.label }}</div>
        <div style="font-size: 18px; font-weight: 600; margin: 2px 0">{{ s.value }}</div>
        <div v-if="s.hint" class="f-muted" style="font-size: 12px">{{ s.hint }}</div>
      </div>
    </div>

    <div class="f-card" style="margin-bottom: 18px">
      <h3 style="margin-top: 0">策略包核对</h3>
      <p class="f-muted" style="margin-top: 0">
        引用与内容文件并排看：状态列只回答「按现在两边重读，加载器会不会点头」。
      </p>
      <el-table :data="bundleRows" border size="small" v-loading="busy">
        <el-table-column type="expand">
          <template #default="{ row }">
            <div v-if="row.kind === 'orphan'" class="f-muted" style="padding: 8px 12px">
              未被引用；规则数 {{ row.count ?? '—' }}。点「引用它」会按磁盘上这一版补回配置引用。
            </div>
            <div v-else-if="!(row.rules || []).length" class="f-muted" style="padding: 8px 12px">
              这一版没有规则，或核对视图没有下发规则明细。
            </div>
            <el-table v-else :data="row.rules" size="small" border style="margin: 8px 0">
              <el-table-column prop="subject" label="主体" min-width="130" />
              <el-table-column prop="resource" label="资源" min-width="150" />
              <el-table-column prop="action" label="动作" width="70" />
              <el-table-column label="效果" width="70">
                <template #default="s"><el-tag :type="s.row.effect === 'allow' ? 'success' : 'danger'" size="small">{{ s.row.effect }}</el-tag></template>
              </el-table-column>
              <el-table-column prop="scope" label="范围" min-width="110" />
              <el-table-column label="条件键" min-width="150">
                <template #default="s">
                  <el-tag v-for="k in (s.row.condition_keys || [])" :key="k" size="small" style="margin: 1px 3px 1px 0">{{ k }}</el-tag>
                  <span v-if="!(s.row.condition_keys || []).length" class="f-muted">—</span>
                </template>
              </el-table-column>
              <el-table-column prop="expires_at" label="到期" width="150" />
            </el-table>
          </template>
        </el-table-column>
        <el-table-column label="策略包" min-width="160">
          <template #default="{ row }">
            <code class="mono">{{ row.id || '—' }}.yaml</code>
            <el-tag v-if="row.active" type="success" size="small" style="margin-left: 6px">生效包</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="version" label="版本" width="70" align="right" />
        <el-table-column prop="scope" label="范围" min-width="150" />
        <el-table-column label="状态" min-width="140">
          <template #default="{ row }">
            <el-tooltip :content="refStatus(row).title" :disabled="!refStatus(row).title">
              <el-tag :type="refStatus(row).type" size="small">{{ refStatus(row).text }}</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="规则数" width="80" align="right">
          <template #default="{ row }">{{ row.rules_count ?? row.count ?? '—' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="230" fixed="right">
          <template #default="{ row }">
            <el-button v-if="row.kind === 'ref' && !row.active" link type="primary"
              @click="setActive(row.id)">设为生效</el-button>
            <el-button v-if="row.kind === 'ref'" link type="primary"
              @click="openBackups(row)">备份 {{ row.backups || 0 }}</el-button>
            <el-button v-if="row.kind === 'orphan'" link type="primary"
              @click="reference(row)">引用它</el-button>
            <el-button v-if="row.kind === 'ref'" link type="danger"
              @click="withdraw(row)">撤下</el-button>
          </template>
        </el-table-column>
      </el-table>
      <p v-if="bundlesErr" class="f-muted" style="margin-bottom: 0">核对视图读不到：{{ bundlesErr }}（上面按运行态降级显示）</p>
    </div>

    <div class="f-card" style="margin-bottom: 18px">
      <h3 style="margin-top: 0">路由模拟</h3>
      <p class="f-muted" style="margin-top: 0">与线上请求走同一个判定核；不写统计、不碰熔断/粘性/计量。</p>
      <div style="display: flex; gap: 8px; flex-wrap: wrap; align-items: center">
        <el-select v-model="sim.scope" style="width: 200px" placeholder="网关自身（system 范围）">
          <el-option label="网关自身（system 范围）" value="" />
          <el-option v-for="u in users" :key="u.name" :label="u.name + '（' + u.mode + '）'" :value="u.name" />
        </el-select>
        <el-input v-model="sim.model" style="width: 220px" placeholder="模型名，如 gpt-4o-mini" />
        <el-input v-model="sim.request_id" style="width: 260px" placeholder="request_id（留空=每次新生成）" />
        <el-button type="primary" :loading="sim.busy" @click="runSimulate">模拟</el-button>
      </div>
      <el-alert v-if="sim.error" :title="sim.error" type="error" :closable="false" show-icon style="margin-top: 10px" />
      <div v-if="sim.result" style="margin-top: 14px">
        <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap">
          <el-tag :type="verdictType(sim.result.verdict)" size="small">{{ sim.result.verdict }}</el-tag>
          <span class="f-muted">{{ sim.result.mode }} · {{ sim.result.policy_version || '无版本' }} · {{ sim.result.elapsed_ms }}ms</span>
          <code class="mono f-muted">request_id {{ sim.result.request_id }}</code>
          <span v-if="sim.result.sticky" class="f-muted">粘性偏好：{{ sim.result.sticky }}</span>
        </div>
        <p style="margin: 8px 0 4px">
          {{ sim.result.mode === 'enforce' ? '这条请求的真实作用：' : '如果切到 enforce：' }}
          <el-tag v-if="sim.result.enforce_preview?.blocked" size="small" type="danger">会被拦截</el-tag>
          <el-tag v-else-if="sim.result.enforce_preview?.applied" size="small" type="success">计划生效</el-tag>
          <el-tag v-else size="small">不作用（回落旧路由）</el-tag>
          <span class="f-muted">{{ sim.result.enforce_preview?.blocked || sim.result.enforce_preview?.note || '' }}</span>
        </p>
        <p v-if="sim.result.note" class="f-muted">判定说明：{{ sim.result.note }}</p>
        <el-descriptions :column="4" border size="small" style="margin: 10px 0">
          <el-descriptions-item label="授权">{{ sim.result.decision?.allowed ? '允许' : '拒绝' }}</el-descriptions-item>
          <el-descriptions-item label="结论">{{ sim.result.decision?.reason || '—' }}</el-descriptions-item>
          <el-descriptions-item label="候选数">{{ (sim.result.candidates || []).length }}</el-descriptions-item>
          <el-descriptions-item label="被策略排除">{{ (sim.result.excluded || []).length }}</el-descriptions-item>
        </el-descriptions>
        <p v-if="sim.result.decision?.explain" class="f-muted">{{ sim.result.decision.explain }}</p>
        <p class="f-muted">
          3.0 计划次序：
          <template v-if="(sim.result.plan_order || []).length">
            <el-tag v-for="p in sim.result.plan_order" :key="p" size="small" style="margin-right: 6px">{{ p }}</el-tag>
          </template>
          <span v-else>{{ sim.result.plan_error || '（没有可用计划）' }}</span>
        </p>
        <p class="f-muted">
          旧链路第一档本来会用：
          <el-tag v-for="p in (sim.result.legacy_first || [])" :key="p" size="small" style="margin-right: 6px">{{ p }}</el-tag>
          <span v-if="!(sim.result.legacy_first || []).length">（空池）</span>
        </p>
        <el-table :data="sim.result.candidates || []" border size="small">
          <el-table-column prop="provider" label="上游" width="150" />
          <el-table-column prop="upstream_model" label="上游模型名" min-width="160" />
          <el-table-column prop="tier" label="档" width="60" align="right" />
          <el-table-column label="健康" width="90">
            <template #default="{ row }">
              <el-tag :type="row.healthy ? 'success' : 'info'" size="small">{{ row.healthy ? '可用' : '冷却' }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="weight" label="权重" width="80" align="right" />
          <el-table-column prop="max_data_level" label="分级上限" width="110" />
          <el-table-column label="排除原因" min-width="140">
            <template #default="{ row }">
              <el-tag v-if="(sim.result.excluded || []).find((e) => e.provider === row.provider)" size="small" type="warning">
                {{ (sim.result.excluded || []).find((e) => e.provider === row.provider).reason }}
              </el-tag>
              <span v-else class="f-muted">—</span>
            </template>
          </el-table-column>
        </el-table>
        <p class="f-muted mono" style="font-size: 12px">
          routing_seed {{ sim.result.routing_seed || '—' }}
          <span v-if="sim.result.digest"> · 候选摘要 {{ sim.result.digest }}</span>
          <span v-if="sim.result.routing_seed"> · 同 request_id + 同版本 + 同代可复现</span>
          <span v-else> · 本次没有计划，无逐位复现</span>
        </p>
      </div>
    </div>

    <div class="f-card">
      <h3 style="margin-top: 0">决策痕迹</h3>
      <p class="f-muted" style="margin-top: 0">按 request_id 回当时的策略版本、路由代、seed 与候选摘要。</p>
      <div style="display: flex; gap: 8px">
        <el-input v-model="trace.request_id" style="width: 300px" placeholder="request_id" />
        <el-button :loading="trace.busy" @click="runTrace">查询</el-button>
      </div>
      <el-alert v-if="trace.error" :title="trace.error" type="error" :closable="false" show-icon style="margin-top: 10px" />
      <div v-if="trace.result" style="margin-top: 12px">
        <el-descriptions :column="4" border size="small">
          <el-descriptions-item label="范围">{{ (trace.result.scope_kind || '—') + ':' + (trace.result.scope_id || '—') }}</el-descriptions-item>
          <el-descriptions-item label="策略版本">{{ trace.result.policy_version || '—' }}</el-descriptions-item>
          <el-descriptions-item label="路由代">{{ trace.result.routing_epoch || '—' }}</el-descriptions-item>
          <el-descriptions-item label="逐位可复现">{{ trace.result.exactly_replayable ? '是' : '否' }}</el-descriptions-item>
        </el-descriptions>
        <p class="f-muted mono" style="font-size: 12px">
          seed {{ trace.result.routing_seed || '—' }}
          <span v-if="trace.result.candidates_digest"> · 候选摘要 {{ trace.result.candidates_digest }}</span>
        </p>
        <p v-if="trace.result.note" class="f-muted">{{ trace.result.note }}</p>
        <p v-if="trace.result.scope_note" class="f-muted">{{ trace.result.scope_note }}</p>
      </div>
    </div>

    <el-dialog v-model="backupsOpen" :title="backupsTitle" width="620px">
      <el-table :data="backups[backupsId]?.list || []" size="small" border v-loading="backups[backupsId]?.loading">
        <el-table-column prop="name" label="备份文件" min-width="260" />
        <el-table-column label="版本" width="80">
          <template #default="{ row }">{{ row.version ? 'v' + row.version : '—' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="110">
          <template #default="{ row }">
            <el-button link type="primary" :disabled="!!row.error" @click="rollback(bundleRows.find((b) => b.id === backupsId), row)">回到这版</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-alert v-if="backups[backupsId]?.error" :title="'读备份失败：' + backups[backupsId].error" type="error" :closable="false" show-icon style="margin-top: 10px" />
      <p v-if="!(backups[backupsId]?.list || []).length && !backups[backupsId]?.loading" class="f-muted" style="margin-bottom: 0">
        这个包还没有历史内容：第一次替换时才会生成备份。
      </p>
    </el-dialog>
  </AdminShell>
</template>
