import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { keepDirMarker } from '../keep-dir.js'

const outDir = fileURLToPath(new URL('../../ui/spa/user', import.meta.url))

// user SPA：构建产物直接写进 ui/spa/user，由 go:embed 编进二进制。
// base 用相对路径：同一份产物既能挂在 /ui/，也能被机构放到任意子路径或运行时覆盖目录。
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
    port: 5173,
    proxy: {
      // 开发时直接打本地网关；生产是同源，不需要 CORS
      '/v1': 'http://127.0.0.1:8787',
      '/healthz': 'http://127.0.0.1:8787',
    },
  },
})
