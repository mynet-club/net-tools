<script setup>
import DeclPage from '../components/DeclPage.vue'

const example = [{
  name: 'pii-request',
  type: 'pii-mask',
  phase: 'before-upstream',
  scope: '*',
  timeout_ms: 5000,
  max_input_bytes: 1048576,
  max_output_bytes: 1048576,
  fail_closed: true,
  body_access: 'transform-body',
  version: '1',
}]
</script>

<template>
  <DeclPage
    title="处理器"
    section="processors"
    path="/v1/_admin/config/processors"
    key-name="processors"
    noun="处理器声明"
    intro="这里配的是约束（挂在哪个范围、能读正文吗、失败放行还是拒、出网白名单、体积与超时上限）。运行参数在 processor_params/<声明名>.json，不在这一段里。"
    :example="example"
  />
</template>
