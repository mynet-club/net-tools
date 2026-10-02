#!/usr/bin/env bash
# 测试矩阵：3.0 领域包按包跑 + 同一套 store 断言跑在 SQLite / MySQL / PostgreSQL 上。
#
#   ./scripts/test-matrix.sh              # 只跑 SQLite（默认，零依赖）
#   ./scripts/test-matrix.sh --docker     # 起一次性 mysql/pg 容器再跑（需要 docker）
#   ./scripts/test-matrix.sh --all        # docker + 已有的 *_DSN 环境变量
#   ./scripts/test-matrix.sh --3p0        # 只跑 3.0 领域包矩阵（按包，不碰数据库）
#   ./scripts/test-matrix.sh --pkg=./internal/replay/...   # 只跑指定包（可重复）
#
# 退出码：0 全绿；非 0 有失败（跳过不算失败）。
# 3.0 在途包（identity/knowledge/processor/routing/executor）编译不过只提示不拦停，
# 因为它们是并行 agent 的地盘；已合并包（policy/replay）任何红都是失败。清单见
# docs/3.0-verification.md。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# 3.0 领域包：OWNED 已合并并冻结，INFLIGHT 并行在途。
DOMAIN_OWNED="./internal/policy/... ./internal/replay/..."
DOMAIN_INFLIGHT="./internal/identity/... ./internal/knowledge/... ./internal/processor/... ./internal/routing/... ./internal/executor/..."

MODE=sqlite
ONLY3P0=0
PKGS=()
for arg in "$@"; do
  case "$arg" in
    --docker) MODE=docker ;;
    --all) MODE=all ;;
    --3p0) ONLY3P0=1 ;;
    --pkg=*) PKGS+=("${arg#--pkg=}") ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "未知参数: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '\n=== %s ===\n' "$*"; }

# domain_tag 给出一个包路径的归属标签。名单只有一处来源（DOMAIN_INFLIGHT）：
# 另写一份 case 清单会让「把包升成 OWNED」需要改两个地方，而漏改的那处不报错，
# 只会让该包继续享受红也不拦 —— 门禁静默失效比没有门禁更危险。
domain_tag() {
  local inflight
  for inflight in $DOMAIN_INFLIGHT; do
    case "$1" in
      "${inflight%/...}"/*) echo INFLIGHT; return ;;
    esac
  done
  echo OWNED
}

# run_domain 按包跑 go test，逐包标 OWNED/INFLIGHT。
# OWNED 失败记 1 并最终以非 0 退出；INFLIGHT 失败只打印 ⚠，不影响退出码 ——
# 并行期「别人的包编译不过」既不能被伪装成通过，也不能算成本包的失败。
run_domain() {
  local targets=("$@") fails=0 tag out
  step "3.0 领域包矩阵（按包，-race -count=1）"
  for target in ${targets[@]+"${targets[@]}"}; do
    tag="$(domain_tag "$target")"
    if out=$(go test "$target" -count=1 -race 2>&1); then
      printf '  ✓  %-34s %s（%s）\n' "$target" "$(printf '%s\n' "$out" | tail -1)" "$tag"
    else
      if [ "$tag" = "OWNED" ]; then
        fails=1
        printf '  ✗  %-34s（OWNED，必须修）\n' "$target"
      else
        printf '  ⚠  %-34s（INFLIGHT，并行在途，不阻塞）\n' "$target"
      fi
      printf '%s\n' "$out" | sed 's/^/       /' | tail -8
    fi
  done
  return "$fails"
}

if [ "${#PKGS[@]}" -gt 0 ]; then
  run_domain "${PKGS[@]}" || { echo; echo "✗ 指定包存在 OWNED 失败"; exit 1; }
  echo
  echo "✓ 指定包矩阵跑完：${PKGS[*]}"
  exit 0
fi

if [ "$ONLY3P0" -eq 1 ]; then
  run_domain $DOMAIN_OWNED $DOMAIN_INFLIGHT || { echo; echo "✗ 3.0 OWNED 包矩阵未通过"; exit 1; }
  echo
  echo "✓ 3.0 领域包矩阵跑完（未跑存储集成）"
  exit 0
fi

step "SQLite 集成（基线，始终跑）"
go test ./internal/store/ -count=1 -run 'TestIntegrationSQLite' -v


start_containers() {
  command -v docker >/dev/null 2>&1 || { echo "没有 docker，跳过真库" >&2; return 1; }
  docker rm -f llmp-it-mysql llmp-it-pg >/dev/null 2>&1 || true
  step "起一次性 MySQL / PostgreSQL 容器"
  docker run -d --name llmp-it-mysql \
    -e MYSQL_ROOT_PASSWORD=llmp -e MYSQL_DATABASE=llmproxy_test \
    -p 127.0.0.1:3307:3306 mysql:8.0 >/dev/null
  docker run -d --name llmp-it-pg \
    -e POSTGRES_PASSWORD=llmp -e POSTGRES_DB=llmproxy_test \
    -p 127.0.0.1:5433:5432 postgres:16 >/dev/null
  export LLMPROXY_TEST_MYSQL_DSN='root:llmp@tcp(127.0.0.1:3307)/llmproxy_test?parseTime=true'
  export LLMPROXY_TEST_PG_DSN='postgres://postgres:llmp@127.0.0.1:5433/llmproxy_test?sslmode=disable'
  # 等就绪
  for i in $(seq 1 60); do
    if docker exec llmp-it-mysql mysqladmin ping -uroot -pllmp --silent 2>/dev/null; then
      break
    fi
    sleep 1
  done
  for i in $(seq 1 60); do
    if docker exec llmp-it-pg pg_isready -U postgres >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
}

cleanup() {
  if [ "${KEEP_IT_CONTAINERS:-0}" != "1" ]; then
    docker rm -f llmp-it-mysql llmp-it-pg >/dev/null 2>&1 || true
  fi
}

case "$MODE" in
  docker|all)
    trap cleanup EXIT
    start_containers || true
    ;;
esac

if [ -n "${LLMPROXY_TEST_MYSQL_DSN:-}" ]; then
  step "MySQL 集成"
  go test ./internal/store/ -count=1 -run 'TestIntegrationMySQL' -v
else
  step "跳过 MySQL（未设 LLMPROXY_TEST_MYSQL_DSN）"
fi

if [ -n "${LLMPROXY_TEST_PG_DSN:-}" ]; then
  step "PostgreSQL 集成"
  go test ./internal/store/ -count=1 -run 'TestIntegrationPostgres' -v
else
  step "跳过 PostgreSQL（未设 LLMPROXY_TEST_PG_DSN）"
fi

echo
echo "✓ 测试矩阵跑完"
