#!/bin/bash
# llmproxy 多用户（中转器）端到端验证。
#
# 全部在本机跑，用三个假上游（全局兜底 / alice 的 / bob 的）代替真实上游，
# 不消耗任何上游额度，也不碰 ~/.config/llmproxy 下正在用的实例：
# 它自己在一个临时运行时目录里起一个独立实例（独立端口、独立数据库）。
#
# 用法：bash scripts/e2e-multiuser.sh
#       LLMPROXY_BIN=/path/to/llmproxy bash scripts/e2e-multiuser.sh
#   给了 LLMPROXY_BIN 就不编译网关 —— 这一跑验的是那个产物本身（§3.I 的发布与回滚演练：
#   要练的是将要发出去的那个文件，不是 `go build` 出来的等价物）。假上游仍从源码编译。
set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SRC="$ROOT"
H=$(mktemp -d /tmp/llmproxy-e2e.XXXXXX)
STUB=$H/e2estub
BIN=${LLMPROXY_BIN:-$H/llmproxy}
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
if [ "${BIN}" = "${H}/llmproxy" ]; then
  (cd "$SRC" && go build -o "$BIN" ./cmd/llmproxy) || exit 1
else
  [ -x "$BIN" ] || { echo "  [NG] LLMPROXY_BIN 不可执行：$BIN"; exit 1; }
  echo "  网关用外部产物：${BIN}（$("${BIN}" --version 2>/dev/null | head -1)）"
fi
(cd "$SRC" && go build -o "$STUB" ./cmd/e2estub) || exit 1

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
# GWLOG = 当前活着那个进程实例的日志面。§22 会停启两次，后面的节要读的是**这一份**：
# 写死 svc.log 会让「记录没落地」与「读错了文件」在断言里长得一模一样。
GWLOG="$H/svc.log"
"$BIN" start > "$GWLOG" 2>&1 &
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
chk "user.js 可加载" "$(curl -s -o /dev/null -w '%{http_code}' "$GW/ui/user.js")" "200"
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
# 这里刻意不等待：CLI 改完会主动通知服务，新用户与映射应当立刻可用。
# 以前靠 sleep 2.6 躲开服务那 2 秒一次的轮询 —— 窗口期内拿新 token 请求会吃 401，
# 看起来像"用户根本没建成"。用只读的 /v1/_me 探，不计量、不打上游。
chk "CLI 建完用户立刻就能认（不等轮询）" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$GW/v1/_me" -H "Authorization: Bearer $D_TOKEN")" "200"

r=$(curl -s -X POST "$GW/v1/chat/completions" -H "Authorization: Bearer $D_TOKEN" \
    -H 'Content-Type: application/json' -d '{"model":"fast","messages":[{"role":"user","content":"hi"}]}')
echo "$r" | grep -q "served-by:global-up" && pass "消费用户走的是系统上游" || fail "没走系统上游：$r"
echo "$r" | grep -q '"model":"sys-model"' && pass "模型映射生效（fast → sys-model）" || fail "映射没生效：$r"

me=$(curl -s "$GW/v1/_me" -H "Authorization: Bearer $D_TOKEN")
echo "$me" | grep -q '"mode":"consumption"' && pass "/v1/_me 报 consumption 模式" || fail "模式字段不对：$me"
echo "$me" | grep -q '"fast"' && pass "/v1/_me 列出可用模型" || fail "没列出可用模型：$me"
echo "$me" | grep -q '"used_tokens":2' && pass "计量只算系统付费的那次（2 token）" || fail "计量不对：$me"
# 用量的真源是**按范围**那张表（§2.7 规则 5/8）：人 = (user, dave) 那一桶。
# usage_user_daily 从 3.0 起不再写入，运行时也没有读路径 —— 这里既断言新表标了
# system_paid（网关替他付上游的钱），也断言老表没有新行：同一笔钱有两个真源，
# 迁移之后两者必然分叉。
sqlite3 "$H/data/llmproxy.db" \
  "SELECT COUNT(*) FROM usage_scope_daily WHERE scope_kind='user' AND scope_id='dave' AND system_paid=1;" \
  | grep -q '^1$' && pass "用量按范围落成 (user,dave) 且标了 system_paid" \
  || fail "usage_scope_daily 里没有这条系统付费的账"
sqlite3 "$H/data/llmproxy.db" "SELECT COUNT(*) FROM usage_user_daily WHERE user_name='dave';" \
  | grep -q '^0$' && pass "2.x 的按用户账本不再双写" \
  || fail "usage_user_daily 又长出新行了（双写没退干净）"

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
echo "=== 14. 管理员接口：看全网关 / 改设置 / 代用户配模型 ==="
code=$(curl -s -o /tmp/adm.json -w '%{http_code}' "$GW/v1/_admin/users" -H "Authorization: Bearer $ADMIN")
chk "管理员能列用户" "$code" "200"
grep -q '"mode"' /tmp/adm.json && pass "列表里带模式" || fail "列表里没有模式字段"
grep -q '"quota"' /tmp/adm.json && pass "列表里带配额与已用量" || fail "列表里没有配额字段"

# 部分更新：只改配额，模式不能被顺带重置
curl -s -X PUT "$GW/v1/_admin/users/dave" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"quota_month_tokens": 4242}' >/dev/null
chk "改配额后模式保持 consumption" "$(sqlite3 "$H/data/llmproxy.db" "SELECT mode FROM users WHERE name='dave';")" "consumption"
# 配额读 scope_quota：users 上那四列是 2.x 的形状，3.0 的迁移会把它回填进配额行再退役（§2.7 规则 2/8）
chk "配额已落库" "$(sqlite3 "$H/data/llmproxy.db" "SELECT quota_month_tokens FROM scope_quota WHERE scope_kind='user' AND scope_id='dave';")" "4242"

# 代用户配一条模型映射（模型名带 / 也要能加，所以走 body 不走路径）
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$GW/v1/_admin/users/dave/models" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"model":"qwen/qwen-max","upstream":"qwen-max"}')
chk "能代用户加映射（模型名含 /）" "$code" "200"
curl -s -X DELETE "$GW/v1/_admin/users/dave/models?model=qwen%2Fqwen-max" -H "Authorization: Bearer $ADMIN" >/dev/null
chk "能删掉这条映射" "$(sqlite3 "$H/data/llmproxy.db" "SELECT COUNT(*) FROM user_models WHERE user_name='dave' AND model='qwen/qwen-max';")" "0"

chk "管理员能看某用户用量" "$(curl -s -o /dev/null -w '%{http_code}' "$GW/v1/_admin/users/dave/usage?days=7" -H "Authorization: Bearer $ADMIN")" "200"
chk "管理员能看到系统上游" "$(curl -s -o /dev/null -w '%{http_code}' "$GW/v1/_admin/providers" -H "Authorization: Bearer $ADMIN")" "200"
chk "用户 token 不能碰管理接口" "$(curl -s -o /dev/null -w '%{http_code}' "$GW/v1/_admin/users" -H "Authorization: Bearer $A_TOKEN")" "403"

echo
echo "=== 15. 控制台编辑 config.yaml（只替换 providers 段，段外不动）==="
code=$(curl -s -o /tmp/cfg.json -w '%{http_code}' "$GW/v1/_admin/config" -H "Authorization: Bearer $ADMIN")
chk "能读配置" "$code" "200"
grep -q '"api_key":""' /tmp/cfg.json && pass "读配置时密钥不下发（空串）" || fail "读了半天把密钥带出来了"
grep -q '"path"' /tmp/cfg.json && pass "返回了配置文件路径" || fail "没返回路径"

# 记录 providers 段之前的内容，稍后逐字节比对
CFGF=$(ls "$H"/config.yaml)
HEAD_BEFORE=$(sed -n '1,/^providers:/p' "$CFGF" | shasum -a 256 | awk '{print $1}')
TAIL_BEFORE=$(sed -n '/^database:/,$p' "$CFGF" | shasum -a 256 | awk '{print $1}')
KEY_BEFORE=$(grep -c 'api_key: sk-global' "$CFGF")

# 加一家 + 原样保留另一家（密钥留空 = 沿用）
cat > /tmp/cfgput.json <<JSON
{"providers":[
  {"name":"global-up","enabled":true,"base_url":"http://127.0.0.1:$GPORT/v1","api_key":"","weight":1,"proxy":"direct","timeout_ms":10000,"models":["*"]},
  {"name":"second-up","enabled":true,"base_url":"http://127.0.0.1:$GPORT/v1","api_key":"sk-second","weight":2,"proxy":"http://192.168.0.3:7890","timeout_ms":20000,"models":{"fast":"m-one"}}
]}
JSON
code=$(curl -s -o /tmp/save.json -w '%{http_code}' -X PUT "$GW/v1/_admin/config/providers" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' --data @/tmp/cfgput.json)
chk "保存成功" "$code" "200"
grep -q '"written":true' /tmp/save.json && pass "返回了写入结果" || fail "没写成功：$(cat /tmp/save.json)"
grep -q '"strict_ok":true' /tmp/save.json && pass "严格加载能过（改动会生效）" || fail "严格加载过不了"

chk "providers 段之前逐字节未变" "$(sed -n '1,/^providers:/p' "$CFGF" | shasum -a 256 | awk '{print $1}')" "$HEAD_BEFORE"
chk "providers 段之后逐字节未变" "$(sed -n '/^database:/,$p' "$CFGF" | shasum -a 256 | awk '{print $1}')" "$TAIL_BEFORE"
chk "原有密钥沿用（没被清空）" "$(grep -c 'api_key: sk-global' "$CFGF")" "$KEY_BEFORE"
grep -q 'proxy: http://192.168.0.3:7890' "$CFGF" && pass "新供应商的代理写对了（URL 未被加引号）" || fail "代理写错"
grep -q 'fast: m-one' "$CFGF" && pass "模型映射写成了块状" || fail "映射没写对"
ls "$H"/config.yaml.bak-* >/dev/null 2>&1 && pass "保存前生成了备份" || fail "没有备份"

sleep 2.5
chk "热加载生效（运行时 2 家供应商）" "$(curl -s "$GW/healthz" | sed 's/.*"providers":\([0-9]*\).*/\1/')" "2"

# 非法内容要被挡住且不动文件
BAD_BEFORE=$(shasum -a 256 "$CFGF" | awk '{print $1}')
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$GW/v1/_admin/config/providers" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"providers":[{"name":"x","base_url":"ftp://bad/v1","api_key":"k","models":["*"]}]}')
chk "非法 base_url 被拒" "$code" "400"
chk "被拒后文件未改动" "$(shasum -a 256 "$CFGF" | awk '{print $1}')" "$BAD_BEFORE"
chk "非管理员不能改配置" "$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$GW/v1/_admin/config/providers" -H "Authorization: Bearer $A_TOKEN" -H 'Content-Type: application/json' -d '{}')" "403"

# 上面往系统池里留下了一家 second-up（weight 2，代理指向一个真的连不上的地址）。
# 选路是**按权重随机**的，池子里留着它，后面凡是走系统池的用例都会随机飘 ——
# 不是每次都飘，所以这种 flaky 最难查。这里把池子收回成只剩 global-up。
curl -s -X PUT "$GW/v1/_admin/config/providers" -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' \
  -d "{\"providers\":[{\"name\":\"global-up\",\"enabled\":true,\"base_url\":\"http://127.0.0.1:$GPORT/v1\",\"api_key\":\"\",\"weight\":1,\"proxy\":\"direct\",\"timeout_ms\":10000,\"models\":[\"*\"]}]}" >/dev/null
sleep 2.5
chk "收尾：系统池恢复成只剩 global-up（后续用例才确定可复现）" \
  "$(curl -s "$GW/healthz" | sed 's/.*"providers":\([0-9]*\).*/\1/')" "1"

echo
echo "=== 16. 两个界面是两套独立页面 ==="
curl -s "$GW/ui/" | grep -q '用户控制台' && pass "/ui/ 是用户台" || fail "/ui/ 页面不对"
curl -s "$GW/admin/" | grep -q 'llmproxy 管理' && pass "/admin/ 是管理台" || fail "/admin/ 页面不对"
chk "/ui/ 取不到 admin.js" "$(curl -s -o /dev/null -w '%{http_code}' "$GW/ui/admin.js")" "404"
chk "/admin/ 取不到 user.js" "$(curl -s -o /dev/null -w '%{http_code}' "$GW/admin/user.js")" "404"
chk "共用资源两边都能取" "$(curl -s -o /dev/null -w '%{http_code}' "$GW/admin/common.js")" "200"
for f in user.html user.js common.js app.css; do
  chk "用户台的资源 $f" "$(curl -s -o /dev/null -w '%{http_code}' "$GW/ui/$f")" "200"
done
for f in admin.html admin.js common.js app.css; do
  chk "管理台的资源 $f" "$(curl -s -o /dev/null -w '%{http_code}' "$GW/admin/$f")" "200"
done

echo
echo "=== 17. 方案 A：消费用户没配映射 = 继承系统池（开箱可用）==="
I_TOKEN=$("$BIN" user add inherit1 | sed -n 's/.*下游 token: //p' | tr -d ' ')
"$BIN" user mode inherit1 consumption >/dev/null
sleep 2.6
r=$(curl -s -X POST "$GW/v1/chat/completions" -H "Authorization: Bearer $I_TOKEN" \
    -H 'Content-Type: application/json' -d '{"model":"sys-model","messages":[{"role":"user","content":"hi"}]}')
echo "$r" | grep -q "served-by:global-up" && pass "继承模式下直接可用（无需逐用户配模型）" || fail "继承模式不可用：$r"
me=$(curl -s "$GW/v1/_me" -H "Authorization: Bearer $I_TOKEN")
echo "$me" | grep -q '"models_source":"inherit"' && pass "/v1/_me 标明来源是继承" || fail "来源标注不对：$me"
sqlite3 "$H/data/llmproxy.db" "SELECT COUNT(*) FROM user_models WHERE user_name='inherit1';" | grep -q '^0$' \
  && pass "库里确实没有他的映射" || fail "不该有映射"

echo "=== 18. 收窄 → 拒绝 → 放开（管理端一键回继承）==="
"$BIN" user add-model inherit1 fast -upstream sys-model >/dev/null
sleep 2.6
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/chat/completions" \
    -H "Authorization: Bearer $I_TOKEN" -H 'Content-Type: application/json' \
    -d '{"model":"sys-model","messages":[{"role":"user","content":"hi"}]}')
chk "收窄后范围外的模型被拒" "$c" "403"
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/chat/completions" \
    -H "Authorization: Bearer $I_TOKEN" -H 'Content-Type: application/json' \
    -d '{"model":"fast","messages":[{"role":"user","content":"hi"}]}')
chk "收窄范围内的模型可用" "$c" "200"
code=$(curl -s -o /tmp/clr.json -w '%{http_code}' -X DELETE "$GW/v1/_admin/users/inherit1/models" \
    -H "Authorization: Bearer $ADMIN")
chk "管理端清空映射（改回继承）" "$code" "200"
grep -q '"models_source":"inherit"' /tmp/clr.json && pass "清空后明确回到继承" || fail "没标回继承"
c=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/chat/completions" \
    -H "Authorization: Bearer $I_TOKEN" -H 'Content-Type: application/json' \
    -d '{"model":"sys-model","messages":[{"role":"user","content":"hi"}]}')
chk "放开后立刻可用" "$c" "200"

echo
echo "=== 19. 管理台「快速测试」：真发一条极小请求，但不写记账、不报熔断 ==="
DB="$H/data/llmproxy.db"
U_BEFORE=$(sqlite3 "$DB" "SELECT COUNT(*) FROM usage_user_daily;")
R_BEFORE=$(sqlite3 "$DB" "SELECT COUNT(*) FROM requests;")
PS_BEFORE=$(sqlite3 "$DB" "SELECT COALESCE(SUM(total_requests),0)||'/'||COALESCE(SUM(consecutive_failures),0) FROM provider_stats;")
USED_BEFORE=$(curl -s "$GW/v1/_admin/users/inherit1" -H "Authorization: Bearer $ADMIN" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["quota"]["used_tokens"])')
t=$(curl -s -X POST "$GW/v1/_admin/providers/global-up/test" -H "Authorization: Bearer $ADMIN" \
    -H 'Content-Type: application/json' -d '{"model":"sys-model"}')
echo "    $t"
echo "$t" | grep -q '"ok":true' && pass "测一家系统上游：ok" || fail "系统上游测试失败：$t"
echo "$t" | grep -q '"provider":"global-up"' && pass "回报了是哪家上游接的" || fail "没回报上游：$t"
echo "$t" | grep -q '"upstream_model":"sys-model"' && pass "回报了真正打出去的上游模型名" || fail "没回报上游模型：$t"
echo "$t" | grep -q 'served-by:global-up' && pass "带回了上游的真实回复（证明确实发了请求）" || fail "没有上游回复：$t"
echo "$t" | grep -q '"tokens"' && pass "带回了 token 数（界面用来确认这是真请求）" || fail "没带 token 数：$t"

tu=$(curl -s -X POST "$GW/v1/_admin/users/inherit1/test" -H "Authorization: Bearer $ADMIN" \
    -H 'Content-Type: application/json' -d '{"model":"sys-model"}')
echo "    $tu"
echo "$tu" | grep -q '"ok":true' && pass "按用户测（继承模式）：ok" || fail "用户测试失败：$tu"

# 这是这套接口最要紧的不变量：探测不该污染账本，也不该动熔断状态
chk "测试不写用量账（usage_user_daily 行数不变）" \
  "$(sqlite3 "$DB" "SELECT COUNT(*) FROM usage_user_daily;")" "$U_BEFORE"
chk "测试不落请求日志（requests 行数不变）" \
  "$(sqlite3 "$DB" "SELECT COUNT(*) FROM requests;")" "$R_BEFORE"
chk "测试不影响熔断统计（provider_stats 不变）" \
  "$(sqlite3 "$DB" "SELECT COALESCE(SUM(total_requests),0)||'/'||COALESCE(SUM(consecutive_failures),0) FROM provider_stats;")" "$PS_BEFORE"
chk "测试不消耗该用户的本月配额" \
  "$(curl -s "$GW/v1/_admin/users/inherit1" -H "Authorization: Bearer $ADMIN" \
     | python3 -c 'import json,sys;print(json.load(sys.stdin)["quota"]["used_tokens"])')" "$USED_BEFORE"

# 参数与边界
chk "缺 model 参数被拒" "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/_admin/users/inherit1/test" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{}')" "400"
chk "不存在的用户" "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/_admin/users/nobody/test" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"model":"x"}')" "404"
chk "不存在的系统上游" "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/_admin/providers/nope/test" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{"model":"x"}')" "404"
chk "非管理员不能调测试接口" "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/_admin/providers/global-up/test" \
  -H "Authorization: Bearer $A_TOKEN" -H 'Content-Type: application/json' -d '{"model":"sys-model"}')" "403"
# 直通型又不给 model：服务端会去问上游要一份模型列表挑一个真名字来测。
# global-up 这个假上游不提供 /v1/models，所以这里应当明确说「测不了、缺什么、怎么办」，
# 而不是拿个空名字或瞎编的名字打过去。
tn=$(curl -s -X POST "$GW/v1/_admin/providers/global-up/test" -H "Authorization: Bearer $ADMIN" \
    -H 'Content-Type: application/json' -d '{}')
echo "    $tn"
echo "$tn" | grep -q '没给出模型列表' && pass "直通型拿不到模型列表时明说原因与出路" || fail "话术不对：$tn"


# 收窄后的归因：和真实请求一样，要能区分「权限不给」而不是「池子没有」
"$BIN" user add-model inherit1 fast -upstream sys-model >/dev/null
sleep 2.6
tn=$(curl -s -X POST "$GW/v1/_admin/users/inherit1/test" -H "Authorization: Bearer $ADMIN" \
    -H 'Content-Type: application/json' -d '{"model":"sys-model"}')
echo "    $tn"
echo "$tn" | grep -q '不在这个用户的可用范围内' && pass "收窄挡住了：报错说明是权限而非故障" || fail "归因不对：$tn"
tf=$(curl -s -X POST "$GW/v1/_admin/users/inherit1/test" -H "Authorization: Bearer $ADMIN" \
    -H 'Content-Type: application/json' -d '{"model":"fast"}')
echo "$tf" | grep -q '"ok":true' && pass "收窄范围内的映射测通" || fail "范围内映射测不通：$tf"
curl -s -X DELETE "$GW/v1/_admin/users/inherit1/models" -H "Authorization: Bearer $ADMIN" >/dev/null

echo
echo "=== 19b. 模型列表探测：还没保存的供应商也能先看模型（内联 base_url）==="
# 这里必须自己起一个假上游：alice 的那台在第 6 节被刻意杀掉了（验证不回退全局），
# 不能拿它当探测目标。
IPORT=$(freeport)
"$STUB" -name inline-up -port "$IPORT" -log "$H/inline-up.log" -models "m-one,m-two" &
for _ in $(seq 1 20); do
  curl -sf "http://127.0.0.1:$IPORT/v1/models" >/dev/null 2>&1 && break
  sleep 0.25
done
d=$(curl -s -X POST "$GW/v1/_admin/providers/never-saved/discover" -H "Authorization: Bearer $ADMIN" \
    -H 'Content-Type: application/json' \
    -d "{\"base_url\":\"http://127.0.0.1:$IPORT/v1\",\"api_key\":\"sk-inline\"}")
echo "    $d"
echo "$d" | grep -q '"count":2' && pass "未保存的供应商凭内联 base_url 也能列出模型" || fail "内联探测失败：$d"
echo "$d" | grep -q 'm-one' && echo "$d" | grep -q 'm-two' && pass "列表内容正确（勾选界面靠它）" || fail "列表内容不对：$d"
chk "既没保存也没带 base_url" "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/_admin/providers/never-saved/discover" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d '{}')" "404"
chk "内联探测也要求 api_key" "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/_admin/providers/never-saved/discover" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d "{\"base_url\":\"http://127.0.0.1:$IPORT/v1\"}")" "400"
chk "非 http(s) 的 base_url 被拒" "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/_admin/providers/some/discover" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"base_url":"ftp://bad/v1","api_key":"k"}')" "400"
chk "非管理员不能探测系统上游" "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/_admin/providers/global-up/discover" \
  -H "Authorization: Bearer $A_TOKEN")" "403"

# 每家一次测试：不给 model 时服务端自己去问上游要列表、挑一个真实的模型名来测。
# 用未保存的 inline-up 顺带验证「内联凭证 + 自动挑名字」这条路。
tp=$(curl -s -X POST "$GW/v1/_admin/providers/inline-up/test" -H "Authorization: Bearer $ADMIN" \
    -H 'Content-Type: application/json' \
    -d "{\"base_url\":\"http://127.0.0.1:$IPORT/v1\",\"api_key\":\"sk-inline\"}")
echo "    $tp"
echo "$tp" | grep -q '"ok":true' && pass "未保存的供应商：内联凭证、不给 model 也能测通" || fail "内联测试失败：$tp"
echo "$tp" | grep -q '"upstream_model":"m-one"' && pass "自动挑的是上游列表里真实的模型名" || fail "挑错模型：$tp"

echo
echo "=== 20. 点名声明优先于直通兜底（同一个模型名不再随机走错上游）==="
# 池子里放一家「全部直通」+ 一家点名声明 {only-here: only-here}。
# 两家都接得住 only-here（直通那家声明「任何名字都接」），权重也都是 1。
# 修之前是按权重随机 → 约一半请求会落到直通那家；修之后必须 100% 走点名的那家。
# 这不是纸上推演：线上就是这么翻的车（deepseek 直通 + neolink 点名 gpt-5-sol，
# 同一个模型名十次里七次被送去 deepseek，那边根本不认这个名字）。
curl -s -X PUT "$GW/v1/_admin/config/providers" -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' \
  -d "{\"providers\":[
    {\"name\":\"global-up\",\"enabled\":true,\"base_url\":\"http://127.0.0.1:$GPORT/v1\",\"api_key\":\"\",\"weight\":1,\"proxy\":\"direct\",\"timeout_ms\":10000,\"models\":[\"*\"]},
    {\"name\":\"declared-up\",\"enabled\":true,\"base_url\":\"http://127.0.0.1:$IPORT/v1\",\"api_key\":\"sk-declared\",\"weight\":1,\"proxy\":\"direct\",\"timeout_ms\":10000,\"models\":{\"only-here\":\"only-here\"}}
  ]}" >/dev/null
sleep 2.5
chk "热加载生效（运行时 2 家供应商）" "$(curl -s "$GW/healthz" | sed 's/.*"providers":\([0-9]*\).*/\1/')" "2"
hit=0
for _ in $(seq 1 20); do
  prov=$(curl -s -D - -o /dev/null -X POST "$GW/v1/chat/completions" \
    -H "Authorization: Bearer sk-single-user" -H 'Content-Type: application/json' \
    -d '{"model":"only-here","messages":[{"role":"user","content":"hi"}]}' \
    | tr -d '\r' | sed -n 's/^[Xx]-[Ll]lmproxy-[Pp]rovider: *//p')
  [ "$prov" = "declared-up" ] && hit=$((hit + 1))
done
chk "20 次请求全部落到点名声明的供应商" "$hit" "20"

# 反过来：没被任何人点名的模型名，仍旧由直通那家接住（兜底没坏）
prov=$(curl -s -D - -o /dev/null -X POST "$GW/v1/chat/completions" \
  -H "Authorization: Bearer sk-single-user" -H 'Content-Type: application/json' \
  -d '{"model":"随便一个没人声明的名字","messages":[{"role":"user","content":"hi"}]}' \
  | tr -d '\r' | sed -n 's/^[Xx]-[Ll]lmproxy-[Pp]rovider: *//p')
chk "没人点名时仍由直通兜底" "$prov" "global-up"

echo
echo "=== 21. 上游价目：录价之后请求的金额被冻结下来（峰谷字段走通）==="
# 时段依赖真实时间，所以这里把 peak_hours 铺满全天、off_peak_ratio=1（系数恒为 1），
# 断言因此与「跑测试时是几点」无关。「按哪个时区判、空闲打几折」由单测覆盖，
# 这一节只验整条链路：录得进、读得回、请求的金额真的按它冻住。
VA=$(python3 -c 'import time;print(time.strftime("%Y-%m-%dT%H:00:00", time.gmtime(time.time()-7200+8*3600))+"+08:00")')
PROBE="e2e-price-probe"
code=$(curl -s -o "$H/p21.json" -w '%{http_code}' -X PUT "$GW/v1/_admin/prices/provider" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d "{\"provider\":\"global-up\",\"upstream_model\":\"$PROBE\",\"valid_from\":\"$VA\",
       \"in_hit\":1,\"in_miss\":2,\"out\":3,
       \"peak_hours\":[\"00:00-24:00\"],\"off_peak_ratio\":1,\"peak_tz\":\"+08:00\",\"note\":\"e2e\"}")
chk "录一条带峰谷的上游价目" "$code" "200"

got=$(curl -s "$GW/v1/_admin/prices/provider?provider=global-up&upstream_model=$PROBE" \
  -H "Authorization: Bearer $ADMIN" \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);p=d["prices"][0];print(p["peak_tz"],float(p["off_peak_ratio"]),len(p["peak_hours"]))')
chk "峰谷字段原样读回" "$got" "+08:00 1.0 1"

# 非法峰谷一律 400：IANA 时区名、越界偏移、坏时段写法、越界系数。
# 每条用不同的 upstream_model，免得某条意外插入后把后面的"只追加"冲突混进来。
i=0
for bad in '"peak_tz":"Asia/Shanghai"' '"peak_tz":"+15:00"' '"peak_hours":["09:00"]' '"peak_hours":["09:00-12:00"],"off_peak_ratio":1.5'; do
  i=$((i + 1))
  code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$GW/v1/_admin/prices/provider" \
    -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
    -d "{\"provider\":\"e2e-bad\",\"upstream_model\":\"bad$i\",\"valid_from\":\"$VA\",$bad}")
  chk "非法峰谷被拒（${bad}）" "$code" "400"
done

# 打一次请求：假上游固定报 prompt=1 / completion=1，全算未命中 →（1×2 + 1×3）/1e6
prov=$(curl -s -D - -o /dev/null -X POST "$GW/v1/chat/completions" \
  -H "Authorization: Bearer sk-single-user" -H 'Content-Type: application/json' \
  -d "{\"model\":\"$PROBE\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}" \
  | tr -d '\r' | sed -n 's/^[Xx]-[Ll]lmproxy-[Pp]rovider: *//p')
chk "请求落到录了价目的那家" "$prov" "global-up"
chk "上游成本已冻结且金额正确" \
  "$(sqlite3 "$DB" "SELECT printf('%.6f', COALESCE(SUM(cost_upstream),0)) FROM requests WHERE upstream_model='$PROBE' AND price_upstream_id>0;")" \
  "0.000005"
chk "冻结行带上了币种" \
  "$(sqlite3 "$DB" "SELECT currency FROM requests WHERE upstream_model='$PROBE' AND price_upstream_id>0 LIMIT 1;")" \
  "CNY"

echo
echo "=== 22. 优雅退出与数据库重开演练 ==="
# 记下重开前的账，用来看有没有丢
USERS_BEFORE=$(sqlite3 "$DB" "SELECT COUNT(*) FROM users;")
REQS_BEFORE=$(sqlite3 "$DB" "SELECT COUNT(*) FROM requests;")
PROVIDERS_BEFORE=$(curl -s "$GW/healthz" | sed 's/.*"providers":\([0-9]*\).*/\1/')

# 22a. 优雅退出（SIGTERM）：进程退干净、库能重开、账不丢
"$BIN" stop >/dev/null 2>&1
sleep 0.4
if curl -sf "$GW/healthz" >/dev/null 2>&1; then
  fail "stop 之后 healthz 还在应答"
else
  pass "stop 之后 healthz 已下线"
fi
# WAL 检查点：优雅退出应当把 -wal 落进主库（残留 -wal 允许存在，但 -shm 不该再有读者）
if [ -f "$DB-wal" ]; then
  WALSZ=$(wc -c < "$DB-wal" | tr -d ' ')
  if [ "$WALSZ" -lt 100000 ]; then
    pass "优雅退出后 WAL 很小（已 checkpoint，$WALSZ 字节）"
  else
    fail "优雅退出后 WAL 仍有 $WALSZ 字节，checkpoint 可能没做"
  fi
else
  pass "优雅退出后 WAL 文件已消失（完全 checkpoint）"
fi

# 22b. 重开：数据原样
GWLOG="$H/svc2.log"
"$BIN" start > "$GWLOG" 2>&1 &
for _ in $(seq 1 40); do
  curl -sf "$GW/healthz" >/dev/null 2>&1 && break
  sleep 0.25
done
if curl -sf "$GW/healthz" >/dev/null 2>&1; then
  pass "重启后 healthz 恢复"
else
  fail "重启后 healthz 起不来；日志："
  sed -n '1,8p' "$H/svc2.log" 2>/dev/null | sed 's/^/       /'
fi
chk "重启后用户数不变" "$(sqlite3 "$DB" "SELECT COUNT(*) FROM users;")" "$USERS_BEFORE"
chk "重启后请求明细数不变" "$(sqlite3 "$DB" "SELECT COUNT(*) FROM requests;")" "$REQS_BEFORE"
chk "重启后供应商数不变" "$(curl -s "$GW/healthz" | sed 's/.*"providers":\([0-9]*\).*/\1/')" "$PROVIDERS_BEFORE"
# 账还在、能读：冻结金额那一行不能因为重启变成估算
chk "冻结行重启后仍在" \
  "$(sqlite3 "$DB" "SELECT COUNT(*) FROM requests WHERE upstream_model='$PROBE' AND price_upstream_id>0 AND cost_upstream>0;")" \
  "1"

# 22c. 硬杀（SIGKILL）再重开：最坏情况也不该丢库（WAL 回放）
PID=$(cat "$H/llmproxy.pid" 2>/dev/null || true)
if [ -z "$PID" ]; then
  PID=$(pgrep -f "$BIN" | head -1)
fi
if [ -n "$PID" ]; then
  kill -9 "$PID" 2>/dev/null
  sleep 0.4
  # 崩溃不会清 PID 文件：先让 stop 把陈旧 pid 抹掉，否则 start 会拒「已在运行」
  LLMPROXY_HOME=$H "$BIN" stop >/dev/null 2>&1 || true
  rm -f "$H/llmproxy.pid"
  GWLOG="$H/svc3.log"
  "$BIN" start > "$GWLOG" 2>&1 &
  for _ in $(seq 1 40); do
    curl -sf "$GW/healthz" >/dev/null 2>&1 && break
    sleep 0.25
  done
  if curl -sf "$GW/healthz" >/dev/null 2>&1; then
    pass "SIGKILL 后重开仍能起（WAL 回放）"
  else
    fail "SIGKILL 后重开失败；日志："
    sed -n '1,8p' "$H/svc3.log" 2>/dev/null | sed 's/^/       /'
  fi
  chk "SIGKILL 后请求明细仍在" "$(sqlite3 "$DB" "SELECT COUNT(*) FROM requests;")" "$REQS_BEFORE"
else
  fail "找不到进程 pid，无法做 SIGKILL 演练"
fi

echo
echo "=== 23. 3.0 接线：发布 → 影子 → 强制 → 跨进程回放 → 回滚 ==="
# 上面每一节都能在 httptest 夹具里等价地跑，这一节不行 —— 它要的是真进程：
# 配置热加载、磁盘上的策略包文件与权限、独立 CLI 进程从磁盘重跑记录、
# 以及「切回 legacy 之后行为真的恢复」。这些只在接线上成立，单元层碰不到（§3.I）。
#
# data_level 用 public：它是最低级，而用户自配上游没有声明承接级别时按最低处理
# （Provider.DataLevelCeiling 的收紧方向）。声明成 internal 会让这些候选在分级门
# 上被排除，于是计划永不生效、执行器永不委托 —— 断言就会因为与本节无关的原因飘红。
SECRET_MODEL="e2e-secret-model"
BDIR="$H/policy-bundles"   # config.DefaultBundleDir 相对配置文件：改默认目录要一起改这里
# alice 的上游在第 6 节被刻意杀掉（那是「不回退全局」那条不变量的前提），这里补回来：
# 本节要证明的是策略会不会改变路由，不该被「上游在不在」这种别的事实决定。
"$STUB" -name alice-up -port "$APORT" -log "$H/alice-up2.log" -models "m-one,m-two" &
for _ in $(seq 1 20); do
  curl -sf "http://127.0.0.1:$APORT/v1/models" >/dev/null 2>&1 && break
  sleep 0.25
done
POLICY_MODE() {
  curl -s -o "$H/mode.json" -w '%{http_code}' -X POST "$GW/v1/_admin/policy/mode" \
    -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d "$1"
}
# 读一份 JSON 文件里的点分路径；缺字段给空串而不是让 python 炸掉整节。
jget() {
  python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
for p in sys.argv[2].split("."):
    d = d.get(p) if isinstance(d,dict) else None
print("" if d is None else d)' "$1" "$2"
}
alice_chat() { # $1=模型 $2=额外 curl 参数…
  local m=$1; shift
  curl -s -o /dev/null -w '%{http_code}' -X POST "$GW/v1/chat/completions" \
    -H "Authorization: Bearer $A_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"model\":\"$m\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}" "$@"
}

# 23a 顺序闸门：policy 段必须先由人显式选定模式，服务端不替刚发布的策略集开门
chk "模式可以先落成 legacy（policy 段由此长出）" "$(POLICY_MODE '{"mode":"legacy"}')" "200"
grep -q '^policy:' "$H/config.yaml" && pass "配置里写出了 policy 段" || fail "policy 段没进配置"
chk "还没有策略包时切 enforce 被拒" \
  "$(POLICY_MODE '{"mode":"enforce","data_level":"public"}')" "400"
grep -q '至少一个策略包' "$H/mode.json" && pass "拒因点名缺的是哪一步" || fail "拒因不指路：$(cat "$H/mode.json")"

# 23b 发布：一条 allow 全部 + 一条 deny 特定模型（deny 优先级由 A 的内核保证）
code=$(curl -s -o "$H/pub.json" -w '%{http_code}' -X PUT "$GW/v1/_admin/policy/bundles/e2e-base" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d "{
  \"version\": 1, \"scope\": \"system:global\", \"entitlements\": [
    {\"subject\":\"*\",\"resource\":\"model:*\",\"action\":\"use\",\"effect\":\"allow\"},
    {\"subject\":\"*\",\"resource\":\"model:$SECRET_MODEL\",\"action\":\"use\",\"effect\":\"deny\"}
  ]}")
chk "发布一条系统范围策略包" "$code" "200"
[ -f "$BDIR/e2e-base.yaml" ] && pass "内容真的落到磁盘（回滚按文件比才成立）" || fail "磁盘上没有策略包内容：$BDIR"
BPERM=$(stat -f '%Lp' "$BDIR/e2e-base.yaml" 2>/dev/null || stat -c '%a' "$BDIR/e2e-base.yaml")
chk "策略包内容文件权限收到 0600" "$BPERM" "600"

# 23c 分级门的 fail-closed 实况：系统池里有人没声明 max_data_level 时启用 3.0 必须被拒。
# 放宽成「未声明按最高级」是这条链上最便宜的通过方式，也是最贵的一次错误。
code=$(POLICY_MODE '{"mode":"shadow","data_level":"public"}')
chk "上游没逐家声明分级上限时切 shadow 被拒" "$code" "400"
grep -q '未声明不能按最宽松处理' "$H/mode.json" && pass "拒因说明为什么不能放宽" || fail "拒因不对：$(cat "$H/mode.json")"

curl -s -o "$H/putprov.json" -X PUT "$GW/v1/_admin/config/providers" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d "{\"providers\":[
    {\"name\":\"global-up\",\"enabled\":true,\"base_url\":\"http://127.0.0.1:$GPORT/v1\",\"api_key\":\"\",\"weight\":1,\"proxy\":\"direct\",\"timeout_ms\":10000,\"models\":[\"*\"],\"max_data_level\":\"public\"},
    {\"name\":\"declared-up\",\"enabled\":true,\"base_url\":\"http://127.0.0.1:$IPORT/v1\",\"api_key\":\"sk-declared\",\"weight\":1,\"proxy\":\"direct\",\"timeout_ms\":10000,\"models\":{\"only-here\":\"only-here\"},\"max_data_level\":\"public\"}]}"
grep -q '"written":true' "$H/putprov.json" && pass "补齐分级上限声明写进了配置" || fail "声明没写进去：$(cat "$H/putprov.json")"
sleep 2.5

# 23d 影子只读：判定照跑、计数照进，但一条路由也不改
chk "声明齐了之后切 shadow" "$(POLICY_MODE '{"mode":"shadow","data_level":"public"}')" "200"
sleep 2.5
chk "影子里被 deny 的模型照样可用（3.0 不参与路由）" "$(alice_chat "$SECRET_MODEL")" "200"
SH1=$(curl -s "$GW/healthz" | python3 -c 'import json,sys;print(json.load(sys.stdin)["metrics"]["policy_shadow"]["evaluated"])')
[ "${SH1:-0}" -ge 1 ] && pass "影子计数进了 /healthz（$SH1 条）" || fail "影子判了却没计数：$SH1"
SIM=$(curl -s -X POST "$GW/v1/_admin/policy/simulate" -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' -d "{\"scope\":\"alice\",\"model\":\"$SECRET_MODEL\"}")
echo "$SIM" | grep -q '"allowed":false' && pass "路由模拟判出 deny（界面据此能说这条会被拒）" || fail "模拟结论不对：$SIM"
SH2=$(curl -s "$GW/healthz" | python3 -c 'import json,sys;print(json.load(sys.stdin)["metrics"]["policy_shadow"]["evaluated"])')
chk "管理口的模拟不进影子计数（§3.0 线 1：只读旁观者）" "$SH2" "$SH1"

# 23e 强制：策略开始影响请求，且观测面跟着落地
chk "切到 enforce" "$(POLICY_MODE '{"mode":"enforce","data_level":"public"}')" "200"
sleep 2.5
chk "enforce 下 deny 生效" "$(alice_chat "$SECRET_MODEL")" "403"
chk "enforce 下范围内的模型照常可用" "$(alice_chat "deepseek-chat")" "200"
EXEC=$(curl -s -D - -o /dev/null -X POST "$GW/v1/chat/completions" \
  -H "Authorization: Bearer $A_TOKEN" -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}' \
  | tr -d '\r' | sed -n 's/^[Xx]-[Ll]lmproxy-[Ee]xecutor: *//p')
chk "非流式那一段真的换执行器承载" "$EXEC" "http-openai"
# §3.I 指标埋点：委托这件事实得在**可抓取的面**上留数 —— 响应头只服务当前那一发，
# 日志会滚，而「这一小时里委托真的发生过吗」是抓取端要答的。
EXCH=$(curl -s "$GW/metrics" | sed -n 's/^llmproxy_executor_exchanges_total{executor="http-openai"} *//p')
HB=$(curl -s "$GW/healthz" | python3 -c 'import json,sys;print(json.load(sys.stdin)["metrics"]["executor"]["exchanges"].get("http-openai",0))')
if [ "${EXCH:-0}" -ge 2 ] && [ "${HB:-0}" -ge 2 ]; then
  pass "执行器交换次数同时进了 /metrics 与 /healthz（$EXCH / ${HB}）"
else
  fail "委托发生了却没长指标：/metrics=$EXCH /healthz=$HB"
fi
# §3.F 执行记录：真进程上「这一发到底用了什么时限」只能从日志里读 —— 响应头只服务
# 当前那一发，指标只有累计数。这一条也在证明记录落的是**这个进程写出去的那份 stdout**：
# e2e 的配置没开日志文件（log.file 缺省），所以 svc.log 就是它唯一的日志面。
REC_RID="e2e-exec-rec-$$"
curl -s -o /dev/null -X POST "$GW/v1/chat/completions" -H "Authorization: Bearer $A_TOKEN" \
  -H "X-Request-Id: $REC_RID" -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}'
sleep 0.4
RECLINE=$(grep "event=executor_exchange" "$GWLOG" | grep "$REC_RID" | tail -1)
if [ -n "$RECLINE" ]; then pass "真实进程的日志里留下了这次委托的执行记录"
else fail "委托跑过了却没写执行记录（$GWLOG 里没有）：$(tail -3 "$GWLOG" | tr '\n' ' ')"; fi
for f in "executor=http-openai" "provider=alice-up" "timeout_ms=" "max_response_bytes=" "status=200" "reason=-"; do
  if [ -n "$RECLINE" ] && echo "$RECLINE" | grep -q "$f"; then pass "执行记录带 ${f%=}"
  else fail "执行记录缺 ${f%=}：$RECLINE"; fi
done
# 泄漏面：记录只点名字段，attempt 里的密钥与正文不得跨出这一跳（§2.9）。
if grep "event=executor_exchange" "$GWLOG" | grep -q "sk-alice-own-1234"; then
  fail "执行记录里出现上游密钥明文"
else
  pass "执行记录不含上游密钥明文"
fi

# §3.F 流式委托（2026-10-04 裁决第 2 条：B 方案）：流式也交给执行器承载，但时限与缓冲
# 由调用方表达，落到执行记录上就是那两个**显式**的 0。真进程上要一次读出四件事 ——
# 承载者换了、流是逐段透传的（正文与 [DONE] 都到了客户端）、网关的正文改写真的到达了
# 进程之外（include_usage）、以及账照旧。少任何一件，"0 是声明"就只是注释里的自律。
STR_RID="e2e-exec-stream-$$"
STRBODY=$(curl -s -N -D "$H/stream.head" -X POST "$GW/v1/chat/completions" \
  -H "Authorization: Bearer $A_TOKEN" -H "X-Request-Id: $STR_RID" -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-chat","stream":true,"messages":[{"role":"user","content":"hi"}]}')
STR_EXEC=$(tr -d '\r' < "$H/stream.head" | sed -n 's/^[Xx]-[Ll]lmproxy-[Ee]xecutor: *//p')
chk "流式那一段也换执行器承载（裁决 2：B 方案）" "$STR_EXEC" "http-openai"
echo "$STRBODY" | grep -q "served-by:" \
  && pass "流式正文透传到客户端" || fail "流式正文没透传：$STRBODY"
# 逐段的直接证据是**帧数**：两个内容分片 + usage 末帧至少三帧，客户端只会看到一帧就说明
# 有人在中间缓存了整包（那是裁决 2 明确不要的形状）。
STR_FRAMES=$(printf '%s' "$STRBODY" | grep -c '^data: {')
if [ "${STR_FRAMES:-0}" -ge 3 ]; then
  pass "流式按 $STR_FRAMES 帧逐段到达（缓在一起就只剩一帧）"
else
  fail "流式没逐段透传，只收到 ${STR_FRAMES:-0} 帧：$STRBODY"
fi
echo "$STRBODY" | grep -q "\[DONE\]" \
  && pass "流式收尾 [DONE] 没被吃掉（缓存整包再发就会丢在最后）" || fail "缺 [DONE]：$STRBODY"
grep -q "stream=true include_usage=true" "$H/alice-up2.log" \
  && pass "上游真实收到流式正文里的 include_usage（改正文由调用方点名才做）" \
  || fail "上游没收到那个形态：$(tail -2 "$H/alice-up2.log" | tr '\n' ' ')"
sleep 0.4
STREAMLINE=$(grep "event=executor_exchange" "$GWLOG" | grep "$STR_RID" | tail -1)
for f in "timeout_ms=0" "max_response_bytes=0" "status=200" "reason=-"; do
  if [ -n "$STREAMLINE" ] && echo "$STREAMLINE" | grep -q "$f"; then pass "流式执行记录带 $f"
  else fail "流式执行记录缺 $f：$STREAMLINE"; fi
done
# 同一个非流式 request 的记录已经证明那两个位置会写正数（上面 6 项里查过字段存在），
# 这里的 0 才是「按形态显式声明」而不是「整条链路压根没填」。
chk "流式委托的用量照旧入账（边界 1：relay 仍从透传流里扫 usage）" \
  "$(sqlite3 "$DB" "SELECT COALESCE(total_tokens,0) FROM requests WHERE request_id='$STR_RID';")" "3"
RID="e2e-trace-$$"
curl -s -o /dev/null -X POST "$GW/v1/chat/completions" -H "Authorization: Bearer $A_TOKEN" \
  -H "X-Request-Id: $RID" -H 'Content-Type: application/json' \
  -d "{\"model\":\"$SECRET_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}"
curl -s -o "$H/trace.json" "$GW/v1/_admin/policy/trace?request_id=$RID" -H "Authorization: Bearer $ADMIN"
# 被拒那条**也要留痕**（失败路径的证据比成功路径更常被问），但它没有路由计划：
# 给它写 seed 就是引导人去逐位复现一次没发生的决策，所以这里两面都要断言。
chk "痕迹按 request_id 读得回当时判用的版本" "$(jget "$H/trace.json" policy_version)" "e2e-base@1"
chk "被拒的请求不声称逐位可复现（没有计划可复现）" "$(jget "$H/trace.json" exactly_replayable)" "False"
grep -q '解释性回放' "$H/trace.json" && pass "没 seed 时痕迹自带说明" || fail "痕迹缺解释: $(cat "$H/trace.json")"
RID2="e2e-trace-ok-$$"
curl -s -o /dev/null -X POST "$GW/v1/chat/completions" -H "Authorization: Bearer $A_TOKEN" \
  -H "X-Request-Id: $RID2" -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}'
curl -s -o "$H/trace2.json" "$GW/v1/_admin/policy/trace?request_id=$RID2" -H "Authorization: Bearer $ADMIN"
chk "放行那条有 seed，因此可逐字段回放" "$(jget "$H/trace2.json" exactly_replayable)" "True"
chk "放行的痕迹也带归属范围（user:alice）" \
  "$(jget "$H/trace2.json" scope_kind):$(jget "$H/trace2.json" scope_id)" "user:alice"

# 23f 回放证据链：CLI 是**另一个进程**，它只认磁盘上的策略包和记录文件
"$BIN" replay on >/dev/null 2>&1 && pass "replay on（走管理口）" || fail "replay on 失败"
alice_chat "deepseek-chat" >/dev/null
alice_chat "$SECRET_MODEL" >/dev/null
"$BIN" replay collect -out "$H/records.json" >/dev/null 2>&1
if [ -f "$H/records.json" ]; then
  RPERM=$(stat -f '%Lp' "$H/records.json" 2>/dev/null || stat -c '%a' "$H/records.json")
  chk "导出的记录文件权限收到 0600" "$RPERM" "600"
  grep -q '"schema_version"' "$H/records.json" && pass "导出的是记录文件本身" || fail "文件不像记录文件"
  # v2 是「逐位凭据有地方放」的前提：写出版本还停在 v1，说明采集侧根本没带快照。
  chk "导出的记录是 schema v2" "$(jget "$H/records.json" schema_version)" "2"
  grep -q '"replay_snapshot"' "$H/records.json" \
    && pass "选路记录带上了当时的完整回放输入（首选顺序有逐位凭据）" \
    || fail "记录里没有 replay_snapshot：首选顺序只剩解释性回放"
  LEAK=""
  for bad in '"body"' 'api_key' 'sk-alice-own' 'Bearer ' 'base_url'; do
    grep -q -- "$bad" "$H/records.json" && LEAK="$LEAK $bad"
  done
  [ -z "$LEAK" ] && pass "记录里没有正文与凭证（禁词逐个查）" || fail "记录里出现了不该有的字段：$LEAK"
  NOW30=$(python3 -c 'import datetime;print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')
  if "$BIN" replay run -records "$H/records.json" -now "$NOW30" > "$H/replay.out" 2>&1; then
    pass "跨进程回放通过（独立进程 + 磁盘策略包 + 钉住的时钟）"
  else
    fail "跨进程回放没通过："
    sed -n '1,12p' "$H/replay.out" | sed 's/^/       /'
  fi
  grep -q '差异 0' "$H/replay.out" && pass "报告里差异为 0" || fail "报告不是干净的：$(head -1 "$H/replay.out")"
  # 逐位这一层必须单独看得见：并进「通过」里就变成「解释性回放冒充逐位证据」（§2.8）。
  grep -q '首选逐位复现 [1-9]' "$H/replay.out" \
    && pass "报告报出首选顺序逐位复现的条数" \
    || fail "报告没声称逐位复现（记录没带快照？）。$(head -1 "$H/replay.out")"
  # 对照实验：把快照摘掉，同一条记录必须**降级且说出来**，而不是静算成复现成功。
  # 这份「宁缺毋假」的口径只在真实文件上才验得出来——单元测试喂的是内存里的夹具。
  python3 - "$H/records.json" "$H/records-nosnap.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
n = 0
for r in d.get("routing", []):          # 记录文件里的键是 routing（单数），别写错成 routings
    if r.pop("replay_snapshot", None) is not None:
        n += 1
print(n, file=sys.stderr)
json.dump(d, open(sys.argv[2], "w"))
PY
  if grep -q '"replay_snapshot"' "$H/records-nosnap.json"; then
    fail "摘快照这一步是空跑（新文件里还有 replay_snapshot），对照实验不成立"
  elif ! "$BIN" replay run -records "$H/records-nosnap.json" -now "$NOW30" > "$H/replay-nosnap.out" 2>&1; then
    fail "摘掉快照的记录应仍能解释性回放，却直接失败了：$(head -3 "$H/replay-nosnap.out")"
  elif grep -q '只做解释性回放' "$H/replay-nosnap.out" && grep -q '首选逐位复现 0' "$H/replay-nosnap.out"; then
    pass "摘掉快照后如实降级（报告明写只做解释性回放，逐位计数归 0）"
  else
    fail "摘掉快照后报告没说清降级：$(head -1 "$H/replay-nosnap.out")"
  fi
else
  fail "replay collect 没导出文件（窗口里应当有 enforce 的记录）"
fi
"$BIN" replay off >/dev/null 2>&1 && pass "replay off（证据链不长期开着采集）" || fail "replay off 失败"

# 23g 回滚：切回 legacy 之后，2.x 行为必须逐条恢复 —— 这是紧急开关的实测，不是推演
chk "切回 legacy" "$(POLICY_MODE '{"mode":"legacy"}')" "200"
sleep 2.5
# 委托计数的基线必须在**回滚之后**现取：切回 legacy 之前那几发 enforce 请求是合法委托，
# 拿切换前的快照去比等于要求计数器忘掉它们真正发生过的那几交换。
EXCH0=$(curl -s "$GW/metrics" | sed -n 's/^llmproxy_executor_exchanges_total{executor="http-openai"} *//p')
chk "回滚后 deny 不再参与路由（行为恢复）" "$(alice_chat "$SECRET_MODEL")" "200"
chk "回滚后范围内的模型照常可用" "$(alice_chat "deepseek-chat")" "200"
EXCH1=$(curl -s "$GW/metrics" | sed -n 's/^llmproxy_executor_exchanges_total{executor="http-openai"} *//p')
chk "切回 legacy 后新请求不再产生委托（legacy 没有计划，也就没有计划声明的执行器）" "$EXCH1" "$EXCH0"
curl -s -o "$H/insp.json" "$GW/v1/_admin/policy" -H "Authorization: Bearer $ADMIN"
chk "回滚后核对表说 3.0 没在跑" "$(jget "$H/insp.json" running)" "False"
chk "并且说清为什么没跑" "$(jget "$H/insp.json" inactive_reason)" "policy_mode_legacy"
PV30=$(curl -s "$GW/healthz" | python3 -c 'import json,sys;print(json.load(sys.stdin)["metrics"]["policy_shadow"]["policy_version"])')
chk "回滚后 /healthz 的策略版本清零（不能留着一个看起来还在效的版本）" "$PV30" ""
# 引用与磁盘内容都还在：回滚不该顺手删掉别人发布的策略集
[ -f "$BDIR/e2e-base.yaml" ] && pass "回滚保留策略包内容（切回时不用重抄）" || fail "回滚把内容删了"

# 23h fail-closed 的实况：legacy 下 replay run 必须报错，而不是「跑了一遍、0 条差异」
if "$BIN" replay run -records "$H/records.json" -now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$H/run2.out" 2>&1; then
  fail "legacy 下 replay run 应当失败（没有可回放的策略包）"
else
  grep -q '没有可回放的策略包' "$H/run2.out" && pass "legacy 下 replay run 明确拒绝并说明原因" \
    || fail "退出码对了但话没说清：$(head -2 "$H/run2.out")"
fi

# 23i 字段稳定性：/metrics 的指标名与审计的范围列是对外契约，改名等于破坏 dashboard
curl -s "$GW/metrics" | grep -q '^llmproxy_requests_total ' && pass "/metrics 仍在暴露稳定指标名" || fail "/metrics 少了 llmproxy_requests_total"
NQ=$(sqlite3 "$DB" "SELECT COUNT(*) FROM audit_log WHERE action LIKE 'policy.%' AND (scope_kind='' OR scope_id='');")
chk "策略写侧审计每条都带范围（§2.7 规则 1）" "$NQ" "0"
sqlite3 "$DB" "SELECT COUNT(*) FROM audit_log WHERE detail LIKE '%sk-%';" | grep -q '^0$' \
  && pass "审计 detail 里没有密钥明文" || fail "审计里翻出了疑似密钥"
echo "    本节的策略/回放写侧审计：$(sqlite3 "$DB" "SELECT group_concat(action||'@'||scope_kind||':'||scope_id, ' | ') FROM audit_log WHERE action LIKE 'policy.%' OR action LIKE 'replay.%';")"

# 23j 执行面摘要列（2026-10-04 裁决第 4 条：B）：落库那一半必须在真进程上读得回。
# 这一节只查三件事，它们各自对应一条「不这么做就会有的读法」：
#   - 委托那发要在明细里留下承载者与结果码 —— 否则「这一发走了执行器」只有会滚的日志知道；
#   - 没委托那发要留**空串**而不是 NULL —— 空串才是「事实是不应用」，NULL 留给版本 4 之前的历史行；
#   - 两列只能装标签，装不下正文与密钥（列宽 64 的上界见 scope_schema.go）。
LEG_RID="e2e-exec-summary-legacy-$$"
curl -s -o /dev/null -X POST "$GW/v1/chat/completions" -H "Authorization: Bearer $A_TOKEN" \
  -H "X-Request-Id: $LEG_RID" -H 'Content-Type: application/json' \
  -d '{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}'
sleep 0.4
chk "委托那发的摘要落进了请求明细" \
  "$(sqlite3 "$DB" "SELECT executor||'|'||exchange_reason FROM requests WHERE request_id='$REC_RID';")" \
  "http-openai|-"
# legacy 模式下没有计划、也就没有计划声明的执行器：这一发走的是 2.x 传输。
# 留着上一发的值，就等于让明细行声称「这次请求由 http-openai 承载」，而答复客户端的那一发不是它打的。
chk "2.x 传输那发显式回到「不应用」（空串，不是 NULL）" \
  "$(sqlite3 "$DB" "SELECT CASE WHEN executor IS NULL THEN 'NULL' WHEN exchange_reason IS NULL THEN 'NULL' ELSE executor||'|'||exchange_reason END FROM requests WHERE request_id='$LEG_RID';")" \
  "|"
# 这个库是本次演练新建的：NULL 那一格只有版本 4 之前的历史行才够得着（迁移一律不回填）。
NULLS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM requests WHERE executor IS NULL OR exchange_reason IS NULL;")
chk "新库的明细里没有「没有这个事实」的那一格" "$NULLS" "0"
LEAKY=$(sqlite3 "$DB" "SELECT COUNT(*) FROM requests WHERE length(executor)>64 OR length(exchange_reason)>64 OR executor LIKE '% %' OR exchange_reason LIKE '% %' OR executor LIKE '%sk-%' OR exchange_reason LIKE '%sk-%' OR exchange_reason LIKE '%Bearer%';")
chk "摘要两列里没有正文、密钥或多于标签的形状" "$LEAKY" "0"
echo "    摘要列读数：$(sqlite3 "$DB" "SELECT group_concat(executor||'/'||exchange_reason, ' | ') FROM (SELECT executor, exchange_reason FROM requests ORDER BY id DESC LIMIT 4);")"

echo
echo "================ 结果：通过 $PASS 项，失败 $FAIL 项 ================"
[ "$FAIL" -eq 0 ] || exit 1
