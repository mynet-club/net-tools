#!/usr/bin/env bash
# 发行件演练记录器（§3.I 发布与回滚演练的补全，任务 #31）。
#
# 干什么：把「练的是发出去的那个文件」这句话落成五项留痕 ——
#   产物 sha256 / 版本 / 启动日志 / 优雅退出 / 数据库重开。
# 不干什么：不复制第 23 节那批断言（那是 e2e-multiuser.sh 的活），不起真上游，
#   不带真密钥 —— 配置里的占位符一律换成合成串，而不是把校验放宽。
#
# 用法：
#   ./scripts/build.sh                 # 或直接 ./scripts/release-check.sh（含四平台构建）
#   ./scripts/drill-release-artifact.sh            # 在本机可执行的那个产物上演练
#   OUT=/tmp/mydrill ./scripts/drill-release-artifact.sh
#
# 失败按三类分开打标，不混记：
#   DRILL_FAIL(代码)     —— 产品行为不对，必须查代码
#   DRILL_FAIL(环境)     —— 本机条件不满足（缺可执行平台、端口被占等）
#   缺外部条件            —— 本来就没这台机器（linux 产物在 macOS 上）
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
D="${OUT:-$(mktemp -d /tmp/llmproxy-drill.XXXXXX)}"
rm -rf "$D"
mkdir -p "$D/app" "$D/home" "$D/other"

# 演练必须与真实使用隔离：LLMPROXY_HOME 指到 $D/home，且这里先自证一次。
# 漏掉这一行时，init / config set / user add 全部落在 ~/.config/llmproxy 上 ——
# 那不是演练，是改用户的线上配置。
export LLMPROXY_HOME="$D/home"
case "$(cd "$LLMPROXY_HOME" && pwd)" in
  "$D/home") : ;;
  *) printf 'DRILL_FAIL(环境): LLMPROXY_HOME 没能指向 %s/home\n' "$D"; exit 1 ;;
esac
if [ "$D/home" = "$HOME/.config/llmproxy" ]; then
  printf 'DRILL_FAIL(环境): 演练目录正好撞上真实配置目录，换 OUT= 再跑\n'; exit 1
fi

# 只挑本机这个平台来跑生命周期；挑错了就是拿 Exec format error 当产品缺陷。
NATIVE="$(uname -s | tr '[:upper:]' '[:lower:]')/$(uname -m)"
case "$NATIVE" in
  darwin/arm64)  PLAT=darwin-arm64 ;;
  darwin/x86_64) PLAT=darwin-amd64 ;;
  linux/aarch64) PLAT=linux-arm64 ;;
  linux/x86_64)  PLAT=linux-amd64 ;;
  *) printf 'DRILL_FAIL(环境): 本机平台 %s 没有对应产物\n' "$NATIVE"; exit 1 ;;
esac

freeport() {
  python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}
sec() { printf '\n=== %s ===\n' "$1"; }
bad() { printf 'DRILL_FAIL(%s): %s\n' "$1" "$2"; }

sec "0. 本机平台与选中的产物"
printf '  uname = %s，用 %s 那个包做生命周期演练\n' "$NATIVE" "$PLAT"
printf '  隔离出来的 home = %s（真实 %s 不动）\n' "$LLMPROXY_HOME" "$HOME/.config/llmproxy"
[ -d "$DIST" ] || { bad 环境 "还没有 dist/，先跑 ./scripts/build.sh"; exit 1; }

sec "1. 四个产物的 sha256 与构建口径（读二进制头，不需要能执行）"
(cd "$DIST" && shasum -a 256 -c SHA256SUMS) || bad 代码 "SHA256SUMS 自检不过"
for f in "$DIST"/llmproxy-*.tar.gz; do
  name=$(basename "$f" .tar.gz)
  d="$D/other/$name"
  mkdir -p "$d" && tar xzf "$f" -C "$d" --strip-components=1
  b="$d/llmproxy"
  printf '  %s\n' "$(basename "$f")"
  printf '    包 sha256：%s\n' "$(shasum -a 256 "$f" | awk '{print $1}')"
  printf '    内层二进制 sha256：%s\n' "$(shasum -a 256 "$b" | awk '{print $1}')"
  printf '    %s\n' "$(file -b "$b")"
  go version -m "$b" | awk '$1=="build" && $2 ~ /^(GOOS|GOARCH|CGO_ENABLED|-trimpath|vcs\.revision|vcs\.modified)=/ {printf "    %s\n", $2}'
done

sec "2. 版本与 embed 的管理台（本机可执行的那一个）"
TGZ=$(ls "$DIST"/llmproxy-*-"${PLAT}".tar.gz | head -1)
APP="$D/other/$(basename "$TGZ" .tar.gz)"
BIN="$APP/llmproxy"
[ -x "$BIN" ] || { bad 环境 "解包后找不到 $BIN"; exit 1; }
# 包名里的版本要连着 -dirty 一起比：把 -dirty 抹掉再比，等于自己造一个假的一致。
PKGVER="$(basename "$APP" | sed -E 's/^llmproxy-//; s/-(darwin|linux)-(amd64|arm64|x86_64|aarch64)$//')"
printf '  --version = %s / version = %s / 包名里 = %s\n' \
  "$("$BIN" --version)" "$("$BIN" version)" "$PKGVER"
[ "$("$BIN" --version)" = "$PKGVER" ] || bad 代码 "二进制版本与包名不符：-dirty 之类的后缀被丢了或多加了"
printf '  管理台 embed：id="replay" 命中 %s 处，「回放证据链」命中 %s 处\n' \
  "$(grep -ac 'id="replay"' "$BIN")" "$(grep -ac '回放证据链' "$BIN")"

sec "3. 全新 home 起步（init → 模板 → 合成密钥）"
cd "$APP" && ./llmproxy init
[ -f "$D/home/config.yaml" ] || bad 代码 "init 没生成 config.yaml"
PORT=$(freeport)
"$BIN" config set server.port "$PORT"
# 模板带 ${OPENAI_API_KEY} 这类占位符，而 start 拒绝带未展开凭证起步 —— 那是既定行为，
# 所以这里补合成串而不是放宽校验。占位符也可能出现在注释里，一并换掉无副作用。
python3 - "$D/home/config.yaml" <<'PY'
import re, sys
p = sys.argv[1]
src = open(p).read()
n = [0]
def rep(_):
    n[0] += 1
    return "sk-drill-synthetic-%04d" % n[0]
open(p, "w").write(re.sub(r"\$\{[A-Z_]+\}", rep, src))
print("  替换占位符 %d 处（值全为合成串，不是真密钥）" % n[0])
PY

sec "4. 启动日志（第一个进程）"
"$BIN" start > "$D/home/boot1.log" 2>&1 &
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 0.25; done
sed 's/^/  /' "$D/home/boot1.log"
HB=$(curl -s "http://127.0.0.1:$PORT/healthz")
if [ -z "$HB" ]; then
  bad 代码 "换了合成密钥仍起不来，见上面的启动日志"
else
  printf '  healthz 里：version=%s providers=%s status=%s\n' \
    "$(printf '%s' "$HB" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("version"))')" \
    "$(printf '%s' "$HB" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("providers"))')" \
    "$(printf '%s' "$HB" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("status"))')"
fi
DB=$(ls "$D/home/data/"*.db 2>/dev/null | head -1)
printf '  运行中的库文件：%s\n' "$(ls -la "$(dirname "$DB")" | tail -n +2 | awk '{printf "%s(%s) ", $9, $5}')"

sec "5. 写一条持久数据 → 优雅退出（SIGTERM）→ checkpoint"
"$BIN" user add drill-user >/dev/null 2>&1 || bad 代码 "user add 没建成"
printf '  停前用户数：%s\n' "$(sqlite3 "$DB" 'SELECT COUNT(*) FROM users;' 2>/dev/null)"
"$BIN" stop > "$D/home/stop1.log" 2>&1
sed 's/^/  stop 输出：/' "$D/home/stop1.log"
sleep 0.5
printf '  服务端收尾日志：\n'; tail -4 "$D/home/boot1.log" | sed 's/^/    /'
curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && bad 代码 "stop 之后仍在应答"
pgrep -f "$BIN" >/dev/null 2>&1 && bad 代码 "stop 之后进程还在"
printf '  退出后 data/：%s\n' "$(ls -la "$(dirname "$DB")" | tail -n +2 | awk '{printf "%s(%s) ", $9, $5}')"
if [ -f "$DB-wal" ] && [ "$(wc -c < "$DB-wal" | tr -d ' ')" -gt 100000 ]; then
  bad 代码 "优雅退出后 WAL 仍有 $(wc -c < "$DB-wal" | tr -d ' ') 字节，checkpoint 可能没做"
fi

sec "6. 数据库重开（第二个进程，同一个文件）"
"$BIN" start > "$D/home/boot2.log" 2>&1 &
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 0.25; done
printf '  二次启动日志：\n'; sed 's/^/    /' "$D/home/boot2.log"
printf '  重开后用户数：%s\n' "$(sqlite3 "$DB" 'SELECT COUNT(*) FROM users;' 2>/dev/null)"
"$BIN" stats 2>&1 | head -3 | sed 's/^/  /'
"$BIN" stop >/dev/null 2>&1

sec "7. 另外三个产物在本机能跑到哪一步"
# 能执行就跑版本，不能执行就明说是「缺外部条件」而不是代码缺陷 —— 本机只有一个 ISA。
for b in "$D"/other/*; do
  n=$(basename "$b")
  [ "$n" = "$(basename "$APP")" ] && continue
  x=$(find "$b" -name llmproxy -type f | head -1)
  out=$("$x" --version 2>&1 | head -1)
  case "$out" in
    *Exec\ format\ error*|*Bad\ CPU\ type*)
      printf '  %s → 本机不可执行（%s）＝ 缺外部条件：需要一台 %s 机器\n' \
        "$n" "$out" "$(printf '%s' "$n" | sed -E 's/.*-(darwin|linux)-(amd64|arm64).*/\1\/\2/')" ;;
    *) printf '  %s → %s\n' "$n" "$out" ;;
  esac
done

sec "8. 留痕位置"
printf '  %s\n' "$D"
printf '  接着跑：LLMPROXY_BIN=%s bash scripts/e2e-multiuser.sh\n' "$BIN"
