#!/usr/bin/env bash
# 管理台/用户页的元素引用自检：JS 里 $('id') 用到的每个 id 必须真的在对应的 HTML 里存在。
#
# 为什么值得单独一步：这一层以前靠人眼。JS 没有类型检查，节点不存在时 getElementById
# 返回 null，然后在**运行时**炸成 "Cannot read properties of null" —— 改个 id 名、
# 或删一段 HTML 忘了删绑定，CI 与 go test 全都不会红，只有点开那个面板的人会发现。
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
echo
echo "✓ UI 元素引用通过：${PAGES[*]}"
