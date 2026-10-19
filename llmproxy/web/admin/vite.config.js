import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { keepDirMarker } from '../keep-dir.js'

const outDir = fileURLToPath(new URL('../../ui/spa/admin', import.meta.url))

// admin SPA：构建产物写进 ui/spa/admin；base 用相对路径，挂载点与覆盖目录都不受限制。
export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  base: './',
  plugins: [vue(), keepDirMarker(outDir)],
  resolve: {
    alias: { '@shared': fileURLToPath(new URL('../shared', import.meta.url)) },
  },
  build: {
    outDir,
    emptyOutDir: true,
  },
  server: {
    port: 5174,
    proxy: {
      '/v1': 'http://127.0.0.1:8787',
      '/healthz': 'http://127.0.0.1:8787',
    },
  },
})
