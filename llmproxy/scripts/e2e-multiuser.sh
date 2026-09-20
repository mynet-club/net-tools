#!/bin/bash
# llmproxy 多用户（中转器）端到端验证。
#
# 全部在本机跑，用三个假上游（全局兜底 / alice 的 / bob 的）代替真实上游，
# 不消耗任何上游额度，也不碰 ~/.config/llmproxy 下正在用的实例：
# 它自己在一个临时运行时目录里起一个独立实例（独立端口、独立数据库）。
#
# 用法：bash scripts/e2e-multiuser.sh
set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SRC="$ROOT"
H=$(mktemp -d /tmp/llmproxy-e2e.XXXXXX)
STUB=$H/e2estub
BIN=$H/llmproxy
PASS=0; FAIL=0

# 端口全部动态取，避免和上一次运行的残留实例撞车
freeport() {
  python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}
PPORT=$(freeport); GPORT=$(freeport); APORT=$(freeport); BPORT=$(freeport)
GW="http://127.0.0.1:$PPORT"
# admin token 每次运行都不同：只有本次起的实例认这个值，
# 于是“管理接口 200”本身就证明了回答我们的是本次实例，而不是端口上的残留进程
ADMIN="sk-e2e-admin-$$-$RANDOM"

pass() { echo "  [OK] $1"; PASS=$((PASS+1)); }
fail() { echo "  [NG] $1"; FAIL=$((FAIL+1)); }
chk()  { if [ "$2" = "$3" ]; then pass "$1（$2）"; else fail "$1：期望 $3，实际 $2"; fi; }

cleanup() {
  LLMPROXY_HOME=$H "$BIN" stop >/dev/null 2>&1
  # 只杀本次运行的假上游（路径带 $H），不动别的实例
  pkill -f "$STUB" >/dev/null 2>&1
  sleep 0.3
  [ "${KEEP:-0}" = "1" ] || rm -rf "$H"
}
trap cleanup EXIT

echo "=== 编译（二进制与假上游都放临时目录，不污染仓库）==="
(cd "$SRC" && go build -o "$BIN" ./cmd/llmproxy && go build -o "$STUB" ./cmd/e2estub) || exit 1

echo "=== 临时运行时目录 $H ==="
mkdir -p "$H/data" "$H/logs"
cat > "$H/config.yaml" <<YAML
# e2e 专用配置（临时目录，用完即删）
server:
  host: 127.0.0.1
  port: $PPORT
  api_keys:
    - sk-single-user          # 单用户时代的静态 key，用来验证向后兼容
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
    sys-model: {cache_hit: 0.04, cache_miss: 2.0, output: 8.0}
    "*": {cache_hit: 0, cache_miss: 0, output: 0}
database:
  path: ""
  retain_days: 7
log:
  level: info
  max_mb: 10
  keep: 1
YAML

echo "=== 起三个假上游 ==="
for spec in "global-up:$GPORT" "alice-up:$APORT" "bob-up:$BPORT"; do
  n=${spec%%:*}; p=${spec##*:}
  # alice 的上游额外提供 /v1/models，用来验证「从上游同步模型列表」
  if [ "$n" = "alice-up" ]; then
    "$STUB" -name "$n" -port "$p" -log "$H/$n.log" -models "m-one,m-two" &
  else
    "$STUB" -name "$n" -port "$p" -log "$H/$n.log" &
  fi
done
sleep 0.6

echo "=== 起网关（多用户模式）==="
export LLMPROXY_HOME=$H
"$BIN" start > "$H/svc.log" 2>&1 &
for _ in $(seq 1 40); do
  curl -sf "$GW/healthz" >/dev/null 2>&1 && break
  sleep 0.25
done

# 自证：端口上必须是我们刚起的这个实例（admin_token 是本次独有的）
code=$(curl -s -o /dev/null -w '%{http_code}' "$GW/v1/_admin/users" -H "Authorization: Bearer $ADMIN")
if [ "$code" != "200" ]; then
  echo "  [NG] $GW 上没有我们的实例（admin 返回 $code）——可能端口被别的进程占用，或启动失败"
  echo "       启动日志：$H/svc.log"
  sed -n '1,5p' "$H/svc.log" 2>/dev/null | sed 's/^/       /'
  exit 1
fi
echo "  [OK] 实例自证通过（本次独有的 admin_token 命中）"

echo
echo "=== 0. 网页控制台的静态资源可用 ==="
chk "GET /ui/ 返回 200" "$(curl -s -o /dev/null -w '%{http_code}' "$GW/ui/")" "200"
chk "index.html 的 content-type" "$(curl -s -o /dev/null -w '%{content_type}' "$GW/ui/" | cut -d';' -f1)" "text/html"
chk "app.js 可加载" "$(curl -s -o /dev/null -w '%{http_code}' "$GW/ui/app.js")" "200"
chk "app.css 可加载" "$(curl -s -o /dev/null -w '%{http_code}' "$GW/ui/app.css")" "200"
chk "/ui 会跳到 /ui/" "$(curl -s -o /dev/null -w '%{http_code}' "$GW/ui")" "301"
curl -sI "$GW/ui/" | grep -qi "content-security-policy" && pass "带了 CSP 响应头" || fail "没有 CSP 响应头"
# 页面里存着 token，不能被缓存
curl -sI "$GW/ui/" | grep -qi "cache-control: no-store" && pass "index 不被缓存" || fail "缺少 no-store"

echo
echo "=== 1. 建用户 + 各配自己的上游 ==="
A_TOKEN=$("$BIN" user add alice | sed -n 's/.*下游 token: //p' | tr -d ' ')
B_TOKEN=$("$BIN" user add bob   | sed -n 's/.*下游 token: //p' | tr -d ' ')
[ -n "$A_TOKEN" ] && pass "alice 拿到 token（${A_TOKEN:0:12}…）" || fail "alice 没拿到 token"
[ -n "$B_TOKEN" ] && pass "bob 拿到 token（${B_TOKEN:0:12}…）"   || fail "bob 没拿到 token"

"$BIN" user add-provider alice alice-up -base-url http://127.0.0.1:$APORT/v1 -api-key sk-alice-own-1234 >/dev/null
"$BIN" user add-provider bob   bob-up   -base-url http://127.0.0.1:$BPORT/v1 -api-key sk-bob-own-5678   >/dev/null
sleep 2.6   # 等运行中的服务同步用户表

echo
echo "=== 2. 每个用户的请求走自己的上游 ==="
ra=$(curl -s -X POST "$GW/v1/chat/completions" -H "Authorization: Bearer $A_TOKEN" \
     -H 'Content-Type: application/json' -d '{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}')
rb=$(curl -s -X POST "$GW/v1/chat/completions" -H "Authorization: Bearer $B_TOKEN" \
     -H 'Content-Type: application/json' -d '{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}')
echo "$ra" | grep -q "served-by:alice-up" && pass "alice 的请求落到她自己的上游" || fail "alice 的请求没落到自己的上游：$ra"
echo "$rb" | grep -q "served-by:bob-up"   && pass "bob 的请求落到他自己的上游"   || fail "bob 的请求没落到自己的上游：$rb"
chk "全局上游没有被这两个用户碰到" "$(curl -s "http://127.0.0.1:$GPORT/hits")" "0"

echo
echo "=== 2b. 从上游同步模型列表（界面的勾选候选靠它）==="
d=$(curl -s -X POST "$GW/v1/_me/providers/alice-up/discover" -H "Authorization: Bearer $A_TOKEN")
echo "$d" | grep -q '"m-one"' && pass "同步到了上游的模型列表" || fail "同步失败：$d"
echo "$d" | grep -q '"m-two"' && pass "列表完整" || fail "列表不全：$d"

# 上游不提供 /v1/models 时要引导到「手动添加」，而不是甩个状态码
d=$(curl -s -X POST "$GW/v1/_me/providers/bob-up/discover" -H "Authorization: Bearer $B_TOKEN")
echo "$d" | grep -q "手动添加" && pass "上游没有 /v1/models 时引导手动添加" || fail "提示不对：$d"

# 未保存的上游不能探测（除非内联地址）——避免这个接口变成任意地址的探测端点
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/_me/providers/ghost/discover" \
    -H "Authorization: Bearer $A_TOKEN")
chk "未保存且没内联地址的上游 → 404" "$c" "404"

echo
echo "=== 3. 自助接口：只看得到自己的上游，且不回明文密钥 ==="
me=$(curl -s "$GW/v1/_me" -H "Authorization: Bearer $A_TOKEN")
echo "$me" | grep -q "alice-up" && pass "/v1/_me 能列出自己的上游" || fail "/v1/_me 没列出上游：$me"
echo "$me" | grep -q "bob-up"   && fail "/v1/_me 泄漏了别人的上游！" || pass "/v1/_me 看不到别人的上游"
echo "$me" | grep -q "sk-alice-own-1234" && fail "/v1/_me 回传了上游密钥明文！" || pass "/v1/_me 未回传密钥明文"
det=$(curl -s "$GW/v1/_me/providers" -H "Authorization: Bearer $A_TOKEN")
echo "$det" | grep -q "1234" && pass "上游详情把密钥脱敏到尾 4 位" || fail "详情里没看到脱敏尾部：$det"
echo "$det" | grep -q "sk-alice-own-1234" && fail "详情接口泄漏了明文密钥！" || pass "详情接口未泄漏明文"

echo
echo "=== 4. 鉴权边界 ==="
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/chat/completions" \
    -H "Authorization: Bearer sk-wrong-token" -H 'Content-Type: application/json' \
    -d '{"model":"deepseek-chat","messages":[]}')
chk "错误 token 被拒" "$c" "401"
c=$(curl -s -o /dev/null -w '%{http_code}' "$GW/v1/_admin/users" -H "Authorization: Bearer sk-wrong")
chk "管理接口用错凭证被拒（403 而非 401，实现的选择）" "$c" "403"
c=$(curl -s -o /dev/null -w '%{http_code}' "$GW/v1/_admin/users" -H "Authorization: Bearer $ADMIN")
chk "管理接口用 admin_token 通过" "$c" "200"
chk "管理接口看到 2 个用户" "$(curl -s "$GW/v1/_admin/users" -H "Authorization: Bearer $ADMIN" | grep -o '"name"' | wc -l | tr -d ' ')" "2"
c=$(curl -s -o /dev/null -w '%{http_code}' "$GW/v1/_me" -H "Authorization: Bearer sk-single-user")
chk "静态 key 不能使用自助接口" "$c" "403"

echo
echo "=== 5. 向后兼容：单用户时代的静态 key 仍走全局上游 ==="
r=$(curl -s -X POST "$GW/v1/chat/completions" -H "Authorization: Bearer sk-single-user" \
     -H 'Content-Type: application/json' -d '{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}')
echo "$r" | grep -q "served-by:global-up" && pass "静态 key 走全局上游" || fail "静态 key 没走全局：$r"

echo
echo "=== 6. 关键不变量：用户自带上游全挂了，也绝不回退到全局 ==="
pkill -f "$STUB -name alice-up"
sleep 0.5
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/chat/completions" \
    -H "Authorization: Bearer $A_TOKEN" -H 'Content-Type: application/json' \
    -d '{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}')
if [ "$c" != "200" ]; then pass "alice 的上游挂了 → 请求失败（HTTP ${c}），没有静默成功"; else fail "alice 的上游挂了却仍然成功，可能回退了全局"; fi
chk "全局上游命中数没增加（仍是第 5 步那 1 次）" "$(curl -s "http://127.0.0.1:$GPORT/hits")" "1"

echo
echo "=== 7. 停用用户 ==="
"$BIN" user disable bob >/dev/null
sleep 2.6
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/chat/completions" \
    -H "Authorization: Bearer $B_TOKEN" -H 'Content-Type: application/json' \
    -d '{"model":"deepseek-chat","messages":[]}')
chk "停用后的 token 被拒" "$c" "403"

echo
echo "=== 8. 落库的请求带上了用户维度 ==="
sqlite3 "$H/data/llmproxy.db" "SELECT client_label, provider, COUNT(*) FROM requests GROUP BY client_label, provider ORDER BY 1,2;" | sed 's/^/    /'

echo
echo "=== 9. 消费模式：用系统上游、走白名单、进配额 ==="
D_TOKEN=$("$BIN" user add dave | sed -n 's/.*下游 token: //p' | tr -d ' ')
"$BIN" user mode dave consumption >/dev/null
"$BIN" user add-model dave fast -upstream sys-model >/dev/null
sleep 2.6

r=$(curl -s -X POST "$GW/v1/chat/completions" -H "Authorization: Bearer $D_TOKEN" \
    -H 'Content-Type: application/json' -d '{"model":"fast","messages":[{"role":"user","content":"hi"}]}')
echo "$r" | grep -q "served-by:global-up" && pass "消费用户走的是系统上游" || fail "没走系统上游：$r"
echo "$r" | grep -q '"model":"sys-model"' && pass "模型映射生效（fast → sys-model）" || fail "映射没生效：$r"

me=$(curl -s "$GW/v1/_me" -H "Authorization: Bearer $D_TOKEN")
echo "$me" | grep -q '"mode":"consumption"' && pass "/v1/_me 报 consumption 模式" || fail "模式字段不对：$me"
echo "$me" | grep -q '"fast"' && pass "/v1/_me 列出可用模型" || fail "没列出可用模型：$me"
echo "$me" | grep -q '"used_tokens":2' && pass "计量只算系统付费的那次（2 token）" || fail "计量不对：$me"
sqlite3 "$H/data/llmproxy.db" "SELECT COUNT(*) FROM usage_user_daily WHERE user_name='dave' AND system_paid=1;" | grep -q '^1$' \
  && pass "用量标成了 system_paid" || fail "用量没标 system_paid"

echo
echo "=== 10. 白名单：没映射的模型直接拒绝，不打上游 ==="
before=$(curl -s "http://127.0.0.1:$GPORT/hits")
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/chat/completions" \
    -H "Authorization: Bearer $D_TOKEN" -H 'Content-Type: application/json' \
    -d '{"model":"expensive","messages":[{"role":"user","content":"hi"}]}')
chk "白名单外的模型返回 403" "$c" "403"
chk "系统上游命中数没变" "$(curl -s "http://127.0.0.1:$GPORT/hits")" "$before"

echo
echo "=== 11. 配额：跨过上限的那条放行，之后拒绝 ==="
"$BIN" user quota dave -tokens 1 >/dev/null
sleep 2.6
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/chat/completions" \
    -H "Authorization: Bearer $D_TOKEN" -H 'Content-Type: application/json' \
    -d '{"model":"fast","messages":[{"role":"user","content":"hi"}]}')
chk "已超配额的请求返回 402" "$c" "402"

echo
echo "=== 12. byo 用户没配上游：明确失败，不回退系统上游 ==="
E_TOKEN=$("$BIN" user add erin | sed -n 's/.*下游 token: //p' | tr -d ' ')
sleep 2.6
before=$(curl -s "http://127.0.0.1:$GPORT/hits")
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/chat/completions" \
    -H "Authorization: Bearer $E_TOKEN" -H 'Content-Type: application/json' \
    -d '{"model":"fast","messages":[{"role":"user","content":"hi"}]}')
chk "byo 无上游时返回 502" "$c" "502"
chk "没有偷偷走系统上游" "$(curl -s "http://127.0.0.1:$GPORT/hits")" "$before"

echo
echo "================ 结果：通过 $PASS 项，失败 $FAIL 项 ================"
[ "$FAIL" -eq 0 ] || exit 1
