#!/usr/bin/env bash
# 交叉编译 llmproxy：darwin / linux × amd64 / arm64，各打成一个 tar.gz。
#
#   ./scripts/build.sh              # 版本号取自最近的 llmproxy-v* tag，没有则 dev-<sha>
#   ./scripts/build.sh 1.2.3        # 指定版本号
#   VERSION=1.2.3 ./scripts/build.sh
#
# 产物（dist/）：
#   llmproxy-v1.2.3-darwin-arm64.tar.gz   含 llmproxy 可执行文件 + config/config.example.yaml + README.md
#   llmproxy-v1.2.3-darwin-amd64.tar.gz
#   llmproxy-v1.2.3-linux-arm64.tar.gz
#   llmproxy-v1.2.3-linux-amd64.tar.gz
#   SHA256SUMS
#
# 交叉编译能成立的关键：CGO_ENABLED=0。
# SQLite 用的是 modernc.org/sqlite（纯 Go 实现），不需要 cgo —— 所以不用装交叉工具链，
# 一条命令就能出四个平台。网页控制台是 go:embed 编进二进制的，产物是真正的单文件。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DIST="$ROOT/dist"
MODULE="github.com/mynet-club/net-tools/llmproxy"
LDFLAGS_PKG="$MODULE/internal/config.Version"

# ── 版本号 ───────────────────────────────────────────────────────────────────
VERSION="${1:-${VERSION:-}}"
if [ -z "$VERSION" ]; then
  if tag=$(git -C "$ROOT" describe --tags --match 'llmproxy-v*' --abbrev=0 2>/dev/null); then
    VERSION="${tag#llmproxy-v}"
    # 工作区不干净时标出来，免得把「改了没提交」的东西当正式版发出去
    if ! git -C "$ROOT" diff --quiet -- . 2>/dev/null; then
      VERSION="${VERSION}-dirty"
    fi
  else
    VERSION="dev-$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo nogit)"
  fi
fi
# 统一带上 v 前缀（tag 里是 llmproxy-v1.2.3，二进制里报 v1.2.3）
case "$VERSION" in v*) FULL="v${VERSION#v}";; *) FULL="v$VERSION";; esac

PLATFORMS="darwin/amd64 darwin/arm64 linux/amd64 linux/arm64"

echo "版本: $FULL"
echo "平台: $PLATFORMS"
echo

# ── 构建前先确认这棵树是好的 ────────────────────────────────────────────────
# 宁可在这里失败，也不要产出一个跑不起来的发行包。
echo "→ go vet"
go vet ./...
echo "→ go test"
go test ./... >/dev/null
echo

rm -rf "$DIST"
mkdir -p "$DIST"

# ── 交叉编译 ────────────────────────────────────────────────────────────────
for target in $PLATFORMS; do
  GOOS="${target%%/*}"
  GOARCH="${target##*/}"
  name="llmproxy-$FULL-$GOOS-$GOARCH"
  stage="$DIST/$name"
  mkdir -p "$stage/config"

  echo "→ $GOOS/$GOARCH"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build \
    -trimpath \
    -ldflags "-s -w -X $LDFLAGS_PKG=$FULL" \
    -o "$stage/llmproxy" ./cmd/llmproxy

  # 模板与说明一起打包：init 会在工作目录下找 config/config.example.yaml，
  # 所以解包后直接在解出来的目录里跑 ./llmproxy init 就能拿到完整模板。
  cp config/config.example.yaml "$stage/config/"
  cp README.md "$stage/"

  tar -czf "$DIST/$name.tar.gz" -C "$DIST" "$name"
  rm -rf "$stage"
done

# ── 校验和 ──────────────────────────────────────────────────────────────────
# macOS 是 shasum，Linux 是 sha256sum，两个都兜住
cd "$DIST"
# 用裸文件名（不带 ./ 前缀），这样 `shasum -a 256 -c SHA256SUMS` 在本目录直接可用
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum *.tar.gz > SHA256SUMS
else
  shasum -a 256 *.tar.gz > SHA256SUMS
fi

echo
echo "产物："
ls -lh "$DIST" | awk 'NR>1 {printf "  %-46s %s\n", $9, $5}'
echo
echo "校验和："
sed 's/^/  /' "$DIST/SHA256SUMS"
echo
echo "逐个核对架构与关键构建参数（读二进制头，不需要能执行）："
for f in "$DIST"/*.tar.gz; do
  tmp=$(mktemp -d)
  tar -xzf "$f" -C "$tmp"
  bin=$(find "$tmp" -name llmproxy -type f | head -1)
  info=$(go version -m "$bin" 2>/dev/null | awk '$1=="build" && $2 ~ /^(GOOS|GOARCH|CGO_ENABLED)=/ {printf "%s ", $2}')
  printf "  %-42s %s\n" "$(basename "$f")" "${info:-（读不到构建信息）}"
  rm -rf "$tmp"
done
