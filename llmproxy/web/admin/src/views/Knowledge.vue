<script setup>
import DeclPage from '../components/DeclPage.vue'

const example = [{
  name: 'campus-rag',
  endpoint: 'https://rag.internal.example/v1/retrieve',
  knowledge_bases: ['course-materials'],
  timeout_ms: 3000,
  max_response_bytes: 1048576,
}]
</script>

<template>
  <DeclPage
    title="知识源"
    section="knowledge_sources"
    path="/v1/_admin/config/knowledge_sources"
    key-name="knowledge_sources"
    noun="知识源委托入口"
    intro="网关不自己实现检索：这一段声明「哪个知识库 ID 交给哪个内部入口」。正文交付默认关（return_raw_body 不写就是关着）。"
    :example="example"
  />
</template>
