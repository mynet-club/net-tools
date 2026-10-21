<script setup>
import AdminShell from '../components/AdminShell.vue'
</script>

<template>
  <AdminShell title="高级面板">
    <h2 class="f-page-title">高级面板</h2>
    <p class="f-page-sub">
      策略观测、策略发布、处理器、知识源、回放证据链已迁移到左侧「高级配置」。
      这里保留旧版入口作为过渡，方便对照旧交互。
    </p>

    <div class="f-card" style="max-width: 720px">
      <h3 style="margin-top: 0">旧版管理台</h3>
      <p class="f-muted">
        同一台网关、同一个 <code>server.admin_token</code>。打开后需要再粘贴一次 token（旧版存的是另一个会话键）。
      </p>
      <a href="/admin/legacy/" target="_blank" rel="noopener">
        <el-button type="primary">打开旧版管理台</el-button>
      </a>
      <p class="f-muted" style="font-size: 12px; margin-bottom: 0">
        旧版仍包含策略观测 / 策略发布 / 处理器 / 知识源 / 回放证据链。
      </p>
    </div>
  </AdminShell>
</template>
