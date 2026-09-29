#!/usr/bin/env bash
# 存储测试矩阵：同一套 store 断言跑在 SQLite / MySQL / PostgreSQL 上。
#
#   ./scripts/test-matrix.sh              # 只跑 SQLite（默认，零依赖）
#   ./scripts/test-matrix.sh --docker     # 起一次性 mysql/pg 容器再跑（需要 docker）
#   ./scripts/test-matrix.sh --all        # docker + 已有的 *_DSN 环境变量
#
# 退出码：0 全绿；非 0 有失败（跳过不算失败）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE=sqlite
for arg in "$@"; do
  case "$arg" in
    --docker) MODE=docker ;;
    --all) MODE=all ;;
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "未知参数: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '\n=== %s ===\n' "$*"; }

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
