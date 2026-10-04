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
# 3.0 的七个领域包与高校示例都已合并，任何一步红都拦停（并行期口径已收掉）。
# 清单与理由见 docs/3.0-verification.md。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# 3.0 领域包：OWNED 已合并并冻结，INFLIGHT 并行在途。
# 合并一个包就把名字从 INFLIGHT 移到 OWNED，两个脚本都要改（名单各自唯一）。
DOMAIN_OWNED="./internal/policy/... ./internal/replay/... ./internal/identity/... ./internal/knowledge/... ./internal/processor/... ./internal/routing/... ./internal/executor/... ./examples/university/..."
DOMAIN_INFLIGHT=""

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


# wait_container <容器名> <探测命令...>：最多等 60 秒，探测走容器内部执行。
wait_container() {
  local name="$1"; shift
  local _
  for _ in $(seq 1 60); do
    if docker exec "$name" "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

start_containers() {
  command -v docker >/dev/null 2>&1 || { echo "没有 docker，跳过真库" >&2; return 1; }
  docker rm -f llmp-it-mysql llmp-it-pg >/dev/null 2>&1 || true
  step "起一次性 MySQL / PostgreSQL 容器"

  # 两条腿各自独立判「容器起来了 + 探测说它就绪」，只有成立才导出对应 DSN。
  #
  # 为什么要改这一处：本函数是被 `start_containers || true` 调的，errexit 在里面不生效，
  # 所以老写法在 docker run 失败后照样导出两个 DSN —— 集成测试于是红成
  # `dial tcp 127.0.0.1:3307: connect: connection refused`。那句话说的是「结构迁移失败」,
  # 真实原因却是「镜像没拉到」（本机撞过的原文：
  # `error getting credentials - err: exit status 1, out: User canceled the operation.`）。
  # 缺现场就得报成缺现场：跳过要跳过得看得见，且不带退出码，
  # 否则矩阵的「非 0 = 有失败」这一条会被环境问题污染成代码问题。
  local out
  if out=$(docker run -d --name llmp-it-mysql \
      -e MYSQL_ROOT_PASSWORD=llmp -e MYSQL_DATABASE=llmproxy_test \
      -p 127.0.0.1:3307:3306 mysql:8.0 2>&1 >/dev/null); then
    if wait_container llmp-it-mysql mysqladmin ping -uroot -pllmp --silent; then
      export LLMPROXY_TEST_MYSQL_DSN='root:llmp@tcp(127.0.0.1:3307)/llmproxy_test?parseTime=true'
    else
      echo "  [跳过] MySQL 腿：容器起来了，但 60 秒内没就绪" >&2
    fi
  else
    echo "  [跳过] MySQL 腿：容器没起来（缺的是现场，不是代码）。docker 原话：" >&2
    printf '%s\n' "$out" | sed 's/^/         /' >&2
  fi

  if out=$(docker run -d --name llmp-it-pg \
      -e POSTGRES_PASSWORD=llmp -e POSTGRES_DB=llmproxy_test \
      -p 127.0.0.1:5433:5432 postgres:16 2>&1 >/dev/null); then
    if wait_container llmp-it-pg pg_isready -U postgres; then
      export LLMPROXY_TEST_PG_DSN='postgres://postgres:llmp@127.0.0.1:5433/llmproxy_test?sslmode=disable'
    else
      echo "  [跳过] PostgreSQL 腿：容器起来了，但 60 秒内没就绪" >&2
    fi
  else
    echo "  [跳过] PostgreSQL 腿：容器没起来（缺的是现场，不是代码）。docker 原话：" >&2
    printf '%s\n' "$out" | sed 's/^/         /' >&2
  fi
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
  # 手动设了 DSN 却没跑这一腿，与 --docker 起容器失败被跳过，是两种不同的原因；
  # 上面 start_containers 已经把后者按 docker 的原话报出来了。
  step "跳过 MySQL（没有 LLMPROXY_TEST_MYSQL_DSN —— 外部真库请自行导出，--docker 模式下即容器没起来）"
fi

if [ -n "${LLMPROXY_TEST_PG_DSN:-}" ]; then
  step "PostgreSQL 集成"
  go test ./internal/store/ -count=1 -run 'TestIntegrationPostgres' -v
else
  step "跳过 PostgreSQL（没有 LLMPROXY_TEST_PG_DSN —— 同上）"
fi

echo
echo "✓ 测试矩阵跑完"
