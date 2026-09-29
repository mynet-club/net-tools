#!/usr/bin/env bash
# 发布前检查：一条命令跑完「能测、能建、校验和对得上」。
#
#   ./scripts/release-check.sh           # 完整检查（含 -race 与四平台构建）
#   ./scripts/release-check.sh --quick   # 跳过 -race 与交叉编译（本地快速自检）
#
# 退出码：0 = 可以发；非 0 = 哪一步失败看输出。
# 给 CI 用：不需要任何额外依赖，有 Go 与 git 就能跑。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

QUICK=0
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    -h|--help)
      sed -n '2,10p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *)
      echo "未知参数: $arg（-h 看用法）" >&2
      exit 2
      ;;
  esac
done

step() { printf '\n=== %s ===\n' "$*"; }
fail() { printf '✗ %s\n' "$*" >&2; exit 1; }

step "go vet"
go vet ./... || fail "go vet 未通过"

step "go test ./..."
go test ./... -count=1 || fail "测试未通过"

if [ "$QUICK" -eq 0 ]; then
  step "go test -race ./..."
  go test ./... -count=1 -race || fail "-race 测试未通过"
else
  step "跳过 -race（--quick）"
fi

if [ "$QUICK" -eq 1 ]; then
  step "跳过四平台构建（--quick）"
  echo
  echo "✓ 快速检查通过（未跑 race 与交叉编译）"
  exit 0
fi

step "四平台构建 + SHA256"
./scripts/build.sh || fail "build.sh 失败"

step "校验和自检"
cd dist
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c SHA256SUMS || fail "SHA256SUMS 对不上"
else
  shasum -a 256 -c SHA256SUMS || fail "SHA256SUMS 对不上"
fi
cd "$ROOT"

# 产物个数：4 个 tar.gz
n=$(ls dist/*.tar.gz 2>/dev/null | wc -l | tr -d ' ')
[ "$n" = "4" ] || fail "应当有 4 个 tar.gz，实际 $n"

echo
echo "✓ 发布检查通过：vet / test / race / 四平台构建 / SHA256 全部 OK"
echo "  产物在 dist/，版本号见各文件名。"
