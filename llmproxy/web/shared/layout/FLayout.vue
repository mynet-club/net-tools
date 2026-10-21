<script setup>
// F 型骨架：左栏导航 + 右侧「页标题 + 顶部操作」+ 内容区。
// 两个 SPA 共用，保证机构换掉 user 端皮肤时结构仍然一致。
defineProps({
  title: { type: String, default: '' },
  subtitle: { type: String, default: '' },
  brand: { type: String, default: 'llmproxy' },
  navItems: { type: Array, default: () => [] },
})
</script>

<template>
  <div class="f-shell">
    <aside class="f-side">
      <div class="f-brand">
        {{ brand }}
        <small v-if="subtitle">{{ subtitle }}</small>
      </div>
      <nav class="f-nav">
        <template v-for="(item, i) in navItems" :key="item.to">
          <span v-if="item.group && (i === 0 || navItems[i - 1].group !== item.group)" class="f-nav-group">
            {{ item.group }}
          </span>
          <router-link :to="item.to">{{ item.label }}</router-link>
        </template>
      </nav>
      <div class="f-side-foot">
        <slot name="foot" />
      </div>
    </aside>

    <section class="f-main">
      <header class="f-head">
        <div class="f-title">{{ title }}</div>
        <div class="f-head-nav">
          <slot name="head" />
        </div>
      </header>
      <main class="f-content">
        <slot />
      </main>
    </section>
  </div>
</template>
