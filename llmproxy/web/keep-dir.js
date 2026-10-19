import fs from 'node:fs'
import path from 'node:path'

// 构建产物目录必须先存在，go:embed（all:spa）才能在干净克隆里编译通过。
// Vite 的 emptyOutDir 会把 .gitkeep 一并删掉，这里在构建结束后补回来。
export function keepDirMarker(outDir) {
  return {
    name: 'llmproxy-keep-dir-marker',
    apply: 'build',
    closeBundle() {
      fs.mkdirSync(outDir, { recursive: true })
      fs.writeFileSync(path.join(outDir, '.gitkeep'), '')
    },
  }
}
