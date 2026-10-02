#!/usr/bin/env bash
# 发布前检查：一条命令跑完「能测、能建、校验和对得上」。
#
#   ./scripts/release-check.sh           # 完整检查（含 -race 与四平台构建）
#   ./scripts/release-check.sh --quick   # 跳过 -race 与交叉编译（本地快速自检）
#   ./scripts/release-check.sh --3p0     # 只跑 3.0 领域门禁（gofmt/覆盖/按包 vet+test+race）
#   ./scripts/release-check.sh --pkg=./internal/replay/...   # 只检查指定包（可重复给多个）
#
# 退出码：0 = 可以发；非 0 = 哪一步失败看输出。
# 给 CI 用：不需要任何额外依赖，有 Go 与 git 就能跑。
#
# 3.0 门禁的清单与容忍策略见 docs/3.0-verification.md：
# 已合并包（policy/replay）任何一步红都拦停；在途包（identity/knowledge/processor/
# routing/executor）编译不过只提示，因为它们是并行 agent 的地盘，不是发布阻塞项。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# 3.0 领域包清单。分成两类是刻意的：并行期「别人的包编译不过」不能算在发布失败里，
# 但也不能因此静默跳过 —— 输出里必须逐包标 OWNED / INFLIGHT。
DOMAIN_OWNED="internal/policy internal/replay"
DOMAIN_INFLIGHT="internal/identity internal/knowledge internal/processor internal/routing internal/executor"

QUICK=0
ONLY3P0=0
PKGS=()
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    --3p0) ONLY3P0=1 ;;
    --pkg=*) PKGS+=("${arg#--pkg=}") ;;
    -h|--help)
      sed -n '2,16p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *)
      echo "未知参数: ${arg}（-h 看用法）" >&2
      exit 2
      ;;
  esac
done

step() { printf '\n=== %s ===\n' "$*"; }
fail() { printf '✗ %s\n' "$*" >&2; exit 1; }
warn() { printf '⚠ %s\n' "$*"; }

# has_go 判断目录里有没有 .go 文件（含测试）。
has_go() { ls "$1"/*.go >/dev/null 2>&1; }

# has_src 判断目录里有没有非测试的源文件 —— 只有源文件的包才要求配测试。
# 用 glob 而不是管道：pipefail 下 `find | head -1` 会因为下游先关闭管道而误报失败。
has_src() {
  local f
  for f in "$1"/*.go; do
    case "$f" in
      *_test.go) continue ;;
    esac
    if [ -f "$f" ]; then
      return 0
    fi
  done
  return 1
}

# gate_gofmt 检查 3.0 领域包的 gofmt。OWNED 未格式化即失败，INFLIGHT 只警告。
gate_gofmt() {
  step "gofmt -l（3.0 领域包）"
  local dir bad
  for dir in $DOMAIN_OWNED; do
    has_go "$dir" || { echo "  —  ${dir}（包不存在，跳过）"; continue; }
    bad=$(gofmt -l "$dir")
    if [ -n "$bad" ]; then
      printf '%s\n' "$bad"
      fail "gofmt：OWNED 包 $dir 有未格式化文件（见上，gofmt -w 修掉）"
    fi
    echo "  ✓  $dir"
  done
  for dir in $DOMAIN_INFLIGHT; do
    has_go "$dir" || { echo "  —  ${dir}（在途，包尚未落地）"; continue; }
    bad=$(gofmt -l "$dir")
    if [ -n "$bad" ]; then
      warn "INFLIGHT 包 $dir 有未格式化文件（不阻塞发布，交给该包负责 agent）："
      printf '     %s\n' "$bad"
    else
      echo "  ✓  ${dir}（INFLIGHT）"
    fi
  done
}

# gate_tests_present 检查「3.0 关键领域包凡有源文件必须同时有 _test.go」。
# 容忍策略：包目录缺席 = 跳过并提示（该工作包还没派）；OWNED 缺测试 = 失败；
# INFLIGHT 缺测试 = 警告（并行 agent 还没写完测试不能算发布阻塞，但必须可见）。
gate_tests_present() {
  step "3.0 领域包测试覆盖"
  local dir missing=0 srcs tests
  for dir in $DOMAIN_OWNED $DOMAIN_INFLIGHT; do
    local tag=OWNED
    case " $DOMAIN_INFLIGHT " in
      *" $dir "*) tag=INFLIGHT ;;
    esac
    if [ ! -d "$dir" ] || ! has_src "$dir"; then
      echo "  —  ${dir}（${tag}，无源文件，跳过）"
      continue
    fi
    srcs=$(find "$dir" -maxdepth 1 -name '*.go' ! -name '*_test.go' | wc -l | tr -d ' ')
    tests=$(find "$dir" -maxdepth 1 -name '*_test.go' | wc -l | tr -d ' ')
    if [ "$tests" = "0" ]; then
      if [ "$tag" = "OWNED" ]; then
        fail "$dir 有 $srcs 个源文件却没有 _test.go —— 3.0 领域包必须有测试"
      fi
      warn "INFLIGHT 包 $dir 有 $srcs 个源文件、0 个测试文件（不阻塞，记录在案）"
      missing=1
    else
      echo "  ✓  ${dir}（${tag}，源 $srcs / 测试 ${tests}）"
    fi
  done
  return 0
}

# run_pkg_checks 按包跑 vet + test（+ 可选 race），逐包标注归属，在途包不拦停。
run_pkg_checks() {
  local with_race=$1
  shift
  local race_flags="" label="vet + test"
  if [ "$with_race" = "1" ]; then
    race_flags="-race"
    label="vet + test -race"
  fi
  local target tag fails=0 ok bad vetlog testlog
  vetlog=$(mktemp)
  testlog=$(mktemp)
  for target in "$@"; do
    tag=OWNED
    case "$target" in
      ./internal/identity/*|./internal/knowledge/*|./internal/processor/*|./internal/routing/*|./internal/executor/*) tag=INFLIGHT ;;
    esac
    step "按包检查 ${target}（${tag}）"
    ok=1
    bad=""
    if ! go vet "$target" > "$vetlog" 2>&1; then
      ok=0
      bad=$(cat "$vetlog")
    fi
    if [ "$ok" = "1" ]; then
      if go test "$target" -count=1 $race_flags > "$testlog" 2>&1; then
        bad=$(cat "$testlog")
        echo "  ✓  ${target} ${label}"
      else
        ok=0
        bad=$(cat "$testlog")
      fi
    fi
    if [ "$ok" = "0" ]; then
      printf '  %s\n' "$bad"
      if [ "$tag" = "OWNED" ]; then
        fails=1
      else
        warn "INFLIGHT 包 ${target} 未通过（并行在途，不阻塞发布）"
      fi
    fi
  done
  rm -f "$vetlog" "$testlog"
  [ "$fails" = "0" ] || fail "OWNED 包按包检查未通过（见上方输出定位包名）"
}

# ---- 目标模式：--pkg / --3p0 都只做定向检查，不动构建产物 ----
WITH_RACE=0
if [ "$QUICK" -eq 0 ]; then
  WITH_RACE=1
fi

if [ "${#PKGS[@]}" -gt 0 ]; then
  gate_tests_present
  run_pkg_checks "$WITH_RACE" "${PKGS[@]}"
  echo
  echo "✓ 定向包检查通过：${PKGS[*]}（未跑构建矩阵）"
  exit 0
fi

if [ "$ONLY3P0" -eq 1 ]; then
  gate_gofmt
  gate_tests_present
  step "3.0 OWNED 包全量 vet + test"
  # 目标一律从 DOMAIN_OWNED 派生：硬编码包名会让「把某个包升成 OWNED」需要同时改
  # 变量和三行命令，漏改的那一行不会报错，只会让该包从此红也不拦。
  owned_targets=()
  for dir in $DOMAIN_OWNED; do
    owned_targets+=("./${dir}/...")
  done
  go vet "${owned_targets[@]}" || fail "3.0 OWNED 包 go vet 未通过"
  if [ "$QUICK" -eq 0 ]; then
    go test "${owned_targets[@]}" -count=1 -race || fail "3.0 OWNED 包 -race 未通过"
  else
    go test "${owned_targets[@]}" -count=1 || fail "3.0 OWNED 包测试未通过"
  fi
  for dir in $DOMAIN_INFLIGHT; do
    [ -d "$dir" ] || { echo "  —  ${dir}（在途，包尚未落地）"; continue; }
    has_go "$dir" || { echo "  —  ${dir}（在途，无 .go）"; continue; }
    if go test "./${dir}/..." -count=1 2>&1 | sed 's/^/  /'; then
      echo "  ✓  ${dir}（INFLIGHT，已可编译）"
    else
      warn "INFLIGHT 包 $dir 当前不可用（并行在途，不阻塞发布）"
    fi
  done
  echo
  echo "✓ 3.0 门禁通过：gofmt / 测试覆盖 / OWNED 包 vet+test$([ "$QUICK" -eq 0 ] && echo '+race')"
  exit 0
fi

# ---- 完整发布门禁：以下步骤与用法保持原样 ----
gate_gofmt
gate_tests_present

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
echo "✓ 发布检查通过：gofmt / 3.0 测试覆盖 / vet / test / race / 四平台构建 / SHA256 全部 OK"
echo "  产物在 dist/，版本号见各文件名。"
