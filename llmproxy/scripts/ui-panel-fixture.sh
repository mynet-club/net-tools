#!/usr/bin/env bash
# 回放面板 UI 层驱动夹具的跑批入口（§4 第 16 条）。
#
# 干什么：在一个**隔离的临时实例**上（独立 HOME、独立端口、独立数据库，不碰
# ~/.config/llmproxy 下正在用的那份），用真实无头 Chrome 打开 /admin/legacy/（旧版管理台，含回放面板），走真实登录表单，
# 把 §14 那五件事点一遍并到服务端对账 —— 保存开关 / 非法值拒绝 / 导出逐字节对账 /
# 清空窗口 / 模式联动。驱动逻辑在 scripts/ui-panel-fixture.mjs（零第三方依赖，CDP over Node 内建）。
#
# 不干什么：不引任何第三方浏览器驱动（Playwright/Puppeteer）；不复算任何业务规则
# （界面对错由界面自己到服务端跑一圈来判）；不碰正在用的实例。
#
# 用法：
#   bash scripts/ui-panel-fixture.sh                     # 编译网关 + 假上游，起隔离实例
#   LLMPROXY_BIN=/path/to/llmproxy bash scripts/ui-panel-fixture.sh   # 用发行产物跑（推荐）
#   CHROME_PATH=/path/to/chrome bash scripts/ui-panel-fixture.sh      # 指定无头浏览器
#   KEEP=1 bash scripts/ui-panel-fixture.sh              # 跑完不删临时目录，便于排查
#
# 失败按三类分开打标，不混记（缺外部条件 = 环境，不是代码缺陷）：
#   缺外部条件（环境）—— 没有无头 Chrome / node / 端口被占等，退出码 3
#   用例失败（代码）  —— 面板行为不对，退出码 1
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT"
H=$(mktemp -d /tmp/llmproxy-uipanel.XXXXXX)
STUB=$H/uistub
BIN=${LLMPROXY_BIN:-$H/llmproxy}
EXPORT_DIR=$H/downloads
mkdir -p "$EXPORT_DIR"
PASS=0; FAIL=0

# 依赖预检：缺工具按「环境」点名退出，而不是让夹具半路炸成看不懂的样子。
# 放在 freeport 之前（端口分配本身用 python3）。
for t in node python3 curl; do
  command -v "$t" >/dev/null 2>&1 || {
    printf '  [环境] 缺外部命令：%s —— 本夹具需要 node / python3 / curl\n' "$t"
    exit 3
  }
done

freeport() {
  python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
pass() { echo "  [OK] $1"; PASS=$((PASS+1)); }
fail() { echo "  [NG] $1"; FAIL=$((FAIL+1)); }
chk()  { if [ "$2" = "$3" ]; then pass "$1（$2）"; else fail "$1：期望 $3，实际 $2"; fi; }

PPORT=$(freeport); GPORT=$(freeport)
GW="http://127.0.0.1:$PPORT"
ADMIN="sk-ui-admin-$$-$RANDOM"
A_TOKEN=""

cleanup() {
  LLMPROXY_HOME=$H "$BIN" stop >/dev/null 2>&1
  pkill -f "$STUB" >/dev/null 2>&1
  sleep 0.3
  [ "${KEEP:-0}" = "1" ] || rm -rf "$H"
}
trap cleanup EXIT

echo "=== 编译（二进制与假上游都放临时目录，不污染仓库）==="
if [ "${BIN}" = "${H}/llmproxy" ]; then
  (cd "$SRC" && go build -o "$BIN" ./cmd/llmproxy) || exit 1
else
  [ -x "$BIN" ] || { echo "  [NG] LLMPROXY_BIN 不可执行：$BIN"; exit 1; }
  echo "  网关用外部产物：${BIN}（$("${BIN}" --version 2>/dev/null | head -1)）"
fi
(cd "$SRC" && go build -o "$STUB" ./cmd/e2estub) || exit 1

SECRET_MODEL="ui-secret-model"

cat > "$H/config.yaml" <<YAML
# UI 面板夹具专用配置（临时目录，用完即删）
server:
  host: 127.0.0.1
  port: $PPORT
  admin_token: $ADMIN
  max_body_mb: 16
  request_timeout_ms: 60000
routing:
  retry: 1
  failure_threshold: 1000
  cooldown_seconds: 1
providers:
  - name: global-up
    enabled: true
    base_url: http://127.0.0.1:$GPORT/v1
    api_key: sk-global
    weight: 1
    proxy: direct
    timeout_ms: 10000
    models: ["*"]
pricing:
  currency: CNY
  models:
    "*": {cache_hit: 0, cache_miss: 0, output: 0}
database:
  path: ""
  retain_days: 7
log:
  level: info
  max_mb: 10
  keep: 1
YAML

echo "=== 起假上游 + 网关（隔离实例）==="
"$STUB" -name global-up -port "$GPORT" -log "$H/global-up.log" &
sleep 0.6
export LLMPROXY_HOME=$H
"$BIN" start > "$H/svc.log" 2>&1 &
for _ in $(seq 1 40); do
  curl -sf "$GW/healthz" >/dev/null 2>&1 && break
  sleep 0.25
done
code=$(curl -s -o /dev/null -w '%{http_code}' "$GW/v1/_admin/users" -H "Authorization: Bearer $ADMIN")
if [ "$code" != "200" ]; then
  echo "  [NG] $GW 上没有我们的实例（admin 返回 ${code}）"
  sed -n '1,8p' "$H/svc.log" 2>/dev/null | sed 's/^/       /'
  exit 1
fi
pass "隔离实例自证通过（本次独有的 admin_token 命中）"

POLICY_MODE() {
  curl -s -o "$H/mode.json" -w '%{http_code}' -X POST "$GW/v1/_admin/policy/mode" \
    -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d "$1"
}
jget() {
  python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
for p in sys.argv[2].split("."):
    d = d.get(p) if isinstance(d,dict) else None
print("" if d is None else d)' "$1" "$2"
}

echo
echo "=== 前置：用户 + 策略包 + enforce（回放窗口只在 enforce 下产记录）==="
A_TOKEN=$("$BIN" user add alice | sed -n 's/.*下游 token: //p' | tr -d ' ')
[ -n "$A_TOKEN" ] && pass "alice 拿到 token" || { fail "alice 没拿到 token"; exit 1; }
# alice 得有自己的上游，请求才会真的走通 —— 走不通就没有选路记录，
# 导出那一条「选路条数读的是 routing 键」就失去鉴别力（0 条恒等于 0 条）。
"$BIN" user add-provider alice alice-up -base-url http://127.0.0.1:$GPORT/v1 -api-key sk-alice-own >/dev/null
sleep 2.6   # 等运行中的服务同步用户表

chk "模式先落成 legacy" "$(POLICY_MODE '{"mode":"legacy"}')" "200"
code=$(curl -s -o "$H/pub.json" -w '%{http_code}' -X PUT "$GW/v1/_admin/policy/bundles/ui-base" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d "{
  \"version\": 1, \"scope\": \"system:global\", \"entitlements\": [
    {\"subject\":\"*\",\"resource\":\"model:*\",\"action\":\"use\",\"effect\":\"allow\"}
  ]}")
chk "发布一条系统范围策略包" "$code" "200"
# 切 enforce 要求上游逐家声明分级上限（否则会被 400 拦住 —— 这正是 fail-closed 的正常形状）
curl -s -o "$H/putprov.json" -X PUT "$GW/v1/_admin/config/providers" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d "{\"providers\":[
    {\"name\":\"global-up\",\"enabled\":true,\"base_url\":\"http://127.0.0.1:$GPORT/v1\",\"api_key\":\"sk-global\",\"weight\":1,\"proxy\":\"direct\",\"timeout_ms\":10000,\"models\":[\"*\"],\"max_data_level\":\"public\"}]}"
grep -q '"written":true' "$H/putprov.json" && pass "上游补齐分级上限声明" || fail "分级声明没写进去：$(cat "$H/putprov.json")"
sleep 2.2
chk "切到 enforce" "$(POLICY_MODE '{"mode":"enforce","data_level":"public"}')" "200"
sleep 2.2

echo
echo "=== 前置：开采集 + 打一发命中窗口的请求 ==="
curl -s -o "$H/rpset.json" -X POST "$GW/v1/_admin/replay/sampling" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"enabled":true,"sample_permille":1000,"capacity":100}'
grep -q '"note"' "$H/rpset.json" || grep -q 'sampl\|permille\|enabled' "$H/rpset.json" \
  && pass "开启采集窗口" || fail "开启采集的响应意外：$(cat "$H/rpset.json")"
REQ_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/chat/completions" \
  -H "Authorization: Bearer $A_TOKEN" -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-flash","messages":[{"role":"user","content":"hi"}]}')
chk "alice 的请求在 enforce 下正常放行" "$REQ_CODE" "200"
sleep 0.6
CAP=$(curl -s "$GW/v1/_admin/replay" -H "Authorization: Bearer $ADMIN" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("captured",0))')
[ "${CAP:-0}" -ge 1 ] && pass "窗口里已收到记录（captured=${CAP}）" || fail "enforce 下发过请求却没进窗口：captured=$CAP"

echo
echo "=== 前置：CLI 产物的 sha256（面板导出要与之逐字节相同）==="
"$BIN" replay collect -out "$H/cli-records.json" >/dev/null 2>&1
[ -s "$H/cli-records.json" ] || { fail "replay collect 没导出文件"; }
EXPECT_SHA=$(sha256 "$H/cli-records.json")
pass "CLI 产物 ${EXPECT_SHA:0:12}…（$(wc -c < "$H/cli-records.json" | tr -d ' ') 字节）"

echo
echo "=== 跑 UI 驱动夹具（真实无头 Chrome）==="
set +e
GW_BASE="$GW" ADMIN_TOKEN="$ADMIN" EXPORT_DIR="$EXPORT_DIR" \
  EXPECT_EXPORT_SHA="$EXPECT_SHA" EXPORT_SCOPE="" \
  CHROME_PATH="${CHROME_PATH:-}" \
  node "$ROOT/scripts/ui-panel-fixture.mjs" 2>&1 | tee "$H/fixture.out"
NODE_RC=${PIPESTATUS[0]}
set -e

# 把夹具进程里的通过/失败计数并进来（末行 RESULT <通过> <失败>）
F_PASS=$(sed -n 's/^RESULT \([0-9]*\) \([0-9]*\)$/\1/p' "$H/fixture.out" | tail -1)
F_FAIL=$(sed -n 's/^RESULT \([0-9]*\) \([0-9]*\)$/\2/p' "$H/fixture.out" | tail -1)
F_PASS=${F_PASS:-0}; F_FAIL=${F_FAIL:-0}
TOTAL_PASS=$((PASS + F_PASS)); TOTAL_FAIL=$((FAIL + F_FAIL))

echo
if [ "$NODE_RC" = "3" ]; then
  echo "缺外部条件（环境）：缺少无头浏览器等，界面夹具未跑 —— 这不是代码缺陷（装 Chrome 或设 CHROME_PATH）"
fi
echo "================ 结果：通过 $TOTAL_PASS 项，失败 $TOTAL_FAIL 项 ================"
[ "$NODE_RC" = "0" ] && [ "$F_FAIL" = "0" ] && [ "$FAIL" = "0" ]

