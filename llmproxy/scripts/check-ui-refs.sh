#!/usr/bin/env bash
# 管理台/用户页的元素引用自检：JS 里 $('id') 用到的每个 id 必须真的在对应的 HTML 里存在。
#
# 为什么值得单独一步：这一层以前靠人眼。JS 没有类型检查，节点不存在时 getElementById
# 返回 null，然后在**运行时**炸成 "Cannot read properties of null" —— 改个 id 名、
# 或删一段 HTML 忘了删绑定，CI 与 go test 全都不会红，只有点开那个面板的人会发现。
#
# 第二段检查同一条失败链的另一半：面板读**导出记录文件**的字段名。记录文件的键由
# internal/replay/codec.go 的 File 结构体决定（是 `routing` 单数），而状态接口用的是
# `routings`（复数）。把两者写混不会报错 —— `(d.routings || []).length` 安静地给 0，
# 于是「导出成功但选路永远 0 条」，只有在一个真有选路记录的窗口里点一次导出才看得见。
#
# 用法：
#   scripts/check-ui-refs.sh              # 检查所有页面对
#   scripts/check-ui-refs.sh admin        # 只查一组（前缀匹配：admin.html + admin.js）
#
# 动态 id 的规则：JS 里写成 $('cfg-cands-' + i) 这种拼接形态，字面量以 `-` 结尾，
# 它本来就不是完整 id，跳过。规则只有这一条，所以不需要维护白名单。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

step() { printf '\n=== %s ===\n' "$*"; }
fail() { printf '✗ %s\n' "$*" >&2; exit 1; }

[ -d ui ] || fail "找不到 ui/ 目录"

PAGES=()
for f in ui/*.html; do
  PAGES+=("$(basename "$f" .html)")
done
[ "${#PAGES[@]}" -gt 0 ] || fail "ui/ 下没有 HTML 页面"

# 参数过滤：只查名字以参数开头的那几组。
if [ "$#" -gt 0 ]; then
  filtered=()
  for p in "${PAGES[@]}"; do
    case "$p" in
      "$1"*) filtered+=("$p") ;;
    esac
  done
  [ "${#filtered[@]}" -gt 0 ] || fail "没有页面名以 $1 开头（可用：${PAGES[*]}）"
  PAGES=("${filtered[@]}")
fi

total_missing=0
for p in "${PAGES[@]}"; do
  html="ui/${p}.html"
  js="ui/${p}.js"
  step "UI 元素引用：$p"
  if [ ! -f "$js" ]; then
    echo "  —  ${js}（无同名脚本，跳过）"
    continue
  fi
  # HTML 侧：静态 id 全集。
  html_ids=$(grep -o 'id="[^"]*"' "$html" | sed 's/^id="//;s/"$//' | sort -u)
  # JS 侧：$('...') 与 $("...") 的字面量 id，去掉拼接用的前缀（以 - 结尾）。
  js_ids=$(grep -oE "[\$]\([('\\\"][^'\\\")]*['\\\"]" "$js" \
    | tr -d '$("'"'"')' | sort -u | grep -v -- '-$' || true)
  missing=0
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if ! printf '%s\n' "$html_ids" | grep -qxF "$id"; then
      echo "  ✗  ${js} 里的 \$('${id}') 在 ${html} 没有对应元素"
      missing=1
    fi
  done <<< "$js_ids"
  if [ "$missing" = "0" ]; then
    n=$(printf '%s\n' "$js_ids" | grep -c . || true)
    echo "  ✓  ${p}（${n} 个字面量 id 全部对得上）"
  else
    total_missing=1
  fi
done

if [ "$total_missing" = "1" ]; then
  fail "UI 元素引用对不上（见上方 ✗ 行）：补齐 HTML 里的 id，或删掉同名 JS 里对应的 \$() 引用"
fi

# 第二段：面板的导出计数与 OpenAPI 的响应描述，必须按记录文件的真实键名写。
# 认的是提示语里的「条判定 / 条选路」这两个量词 —— 状态面板那两格写的是「窗口内选路」，
# 读的是状态接口的复数键 routings，本来就不该被这条检查约束。
# covered==0 也算失败：措辞一改这条检查就变成空跑，而空跑的门禁比没有更糟。
# openapi 那一行也要对账：面板当初就是照它写的 `routings[]`，文档面写错是缺陷的来源，不是旁支。
step "记录文件字段引用"
record_out=$(python3 - <<'PY'
import pathlib, re

codec = pathlib.Path("internal/replay/codec.go").read_text(encoding="utf-8")
m = re.search(r"type File struct \{(.*?)\n\}", codec, re.S)
if not m:
    print("BAD 读不到 internal/replay/codec.go 的 File 结构体"); raise SystemExit(0)
tags = set(re.findall(r'json:"([^",]+)', m.group(1)))
bad, covered = [], 0

lines = pathlib.Path("ui/admin.js").read_text(encoding="utf-8").splitlines()
for i, line in enumerate(lines, 1):
    if "条判定" not in line and "条选路" not in line:
        continue
    covered += 1
    for key in re.findall(r'\b[a-z]\.([a-z_][a-z_0-9]*)', line):
        if key not in tags:
            bad.append(f"BAD ui/admin.js:{i} 按 {key} 读导出文件，而记录文件的键只有 {', '.join(sorted(tags))}")
if covered == 0:
    bad.append("BAD ui/admin.js 里找不到任何「条判定/条选路」计数行：措辞变了，这条检查现在是空跑")

covered2, api_keys = 0, []
for i, line in enumerate(pathlib.Path("ui/openapi.yaml").read_text(encoding="utf-8").splitlines(), 1):
    if "schema_version /" not in line:
        continue
    covered2 += 1
    api_keys += re.findall(r'([a-z_][a-z_0-9]*)\[\]', line)
if covered2 == 0:
    bad.append("BAD ui/openapi.yaml 里找不到导出响应的那句 schema_version / …：文案变了，这条检查现在是空跑")
for key in api_keys:
    if key not in tags:
        bad.append(f"BAD ui/openapi.yaml 把导出响应体写成 {key}[]，而记录文件的键只有 {', '.join(sorted(tags))}")
print("\n".join(bad))
PY
)
if [ -n "$record_out" ]; then
  printf '%s\n' "$record_out" | sed 's/^/  ✗  /'
  fail "导出计数字段对不上记录文件的 schema（File 结构体 json tag）"
fi
printf '  ✓  面板计数与 OpenAPI 响应描述读的键名在 internal/replay/codec.go 的 File 结构体里\n'
echo
echo "✓ UI 元素引用通过：${PAGES[*]}"
