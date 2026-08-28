#!/usr/bin/env bash
set -euo pipefail

# convert_release_body_to_gitee.sh
# 将 release body（如 docs/release_bodies/v3.3.0.md）中 “下载 / Downloads” 段落
# 一键转换为 Gitee 站内可用的 raw 链接版本：
#   - 静态多架构 9 个二进制：GitHub Release 直链 / 仓库相对路径 -> Gitee raw
#     https://gitee.com/<owner>/<repo>/raw/<tag>/release/lzispro/whois/<asset>
#   - 标题 “静态多架构 / Static multi-arch (GitHub Release vX.Y.Z):”
#     去掉 “ (GitHub Release vX.Y.Z)”
#   - 标题 “CI glibc 构建 / CI glibc build:”
#     追加 “ (GitHub Release vX.Y.Z)”，变为 “CI glibc 构建 / CI glibc build (GitHub Release vX.Y.Z):”
#   - whois-x86_64-gnu 保持原 GitHub Release 直链不变
#   - SHA256SUMS.txt -> SHA256SUMS-static.txt（指向 Gitee raw release/lzispro/whois）
#
# 仅处理 “下载 / Downloads” 段落内的上述模式，不触碰文档其他部分；
# 对已是 Gitee raw 形式的内容保持幂等（重复运行无变化）。
#
# 用法：
#   ./tools/release/convert_release_body_to_gitee.sh [-t v3.3.0] [-o owner] [-p repo] [-n] <file...>
# 说明：
#   -t/--tag           目标版本 tag（如 v3.3.0，可省略前导 v）。省略且仅传 1 个文件时，
#                      将尝试从文件名或正文推断（vX.Y.Z）。
#   -o/--owner         仓库 owner（默认：larsonzh）
#   -p/--repo          仓库名（默认：whois）
#   -n/--dry-run       仅打印预览差异（未改动文件）
# 预览（不改文件）:
#   ./tools/release/convert_release_body_to_gitee.sh -n -t v3.3.0 docs/release_bodies/v3.3.0.md
# 直接转换（版本可从文件名/正文自动推断，也支持省略前导 v）:
#   ./tools/release/convert_release_body_to_gitee.sh -t v3.3.0 docs/release_bodies/v3.3.0.md

owner=larsonzh
repo=whois
tag=""
dry_run=0

die() { echo "[gitee-convert] $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--tag) tag="$2"; shift 2;;
    -o|--owner) owner="$2"; shift 2;;
    -p|--repo) repo="$2"; shift 2;;
    -n|--dry-run) dry_run=1; shift;;
    -h|--help) sed -n '1,40p' "$0"; exit 0;;
    --) shift; break;;
    -*) die "未知参数: $1";;
    *) break;;
  esac
done

[[ $# -gt 0 ]] || die "请至少指定一个要处理的 .md 文件"

# 若未显式提供 -t，且仅处理单个文件，尝试自动推断 tag
if [[ -z "$tag" && $# -eq 1 ]]; then
  f_candidate="$1"
  bn_candidate="$(basename -- "$f_candidate")"
  inferred_tag="$(printf '%s' "$bn_candidate" | grep -o -E 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
  if [[ -z "$inferred_tag" && -f "$f_candidate" ]]; then
    inferred_tag="$(grep -o -E '/releases/(download|tag)/(v[0-9]+\.[0-9]+\.[0-9]+)' "$f_candidate" | head -n1 | sed -E 's#.*/(v[0-9]+\.[0-9]+\.[0-9]+).*#\1#' || true)"
  fi
  if [[ -n "$inferred_tag" ]]; then
    tag="$inferred_tag"
    echo "[gitee-convert] inferred tag: $tag (from ${bn_candidate:+filename/content})"
  fi
fi

# 允许用户省略前导 v
case "$tag" in
  v*) : ;;
  *) tag="v$tag" ;;
esac
[[ -n "$tag" ]] || die "必须指定 -t/--tag，或在仅处理单文件时可由文件名/正文自动推断（例如 v3.3.0）"

base="https://gitee.com/${owner}/${repo}/raw/${tag}/release/lzispro/whois"

# AWK 程序块内的 $0/$1/ENVIRON 等为 awk 字段/环境变量，需保持字面量，
# 不得由 bash 展开；单引号是有意为之。
# shellcheck disable=SC2016
AWK_PROG='
BEGIN {
  base = ENVIRON["WC_BASE"]
  in_dl = 0
}
/^## [^#]/ { in_dl = ($0 ~ /^## 下载/) ? 1 : 0 }
{
  line = $0
  if (in_dl) {
    # 标题：静态多架构去掉 “ (GitHub Release vX.Y.Z)”，保留末尾冒号
    if (line ~ /^[-*] 静态多架构 \/ Static multi-arch \(GitHub Release v[0-9.]+\):$/) {
      sub(/ \(GitHub Release v[0-9.]+\)/, "", line)
      print line; next
    }
    # 标题：CI glibc 追加 “ (GitHub Release vX.Y.Z)”
    if (line ~ /^[-*] CI glibc 构建 \/ CI glibc build:$/) {
      sub(/:$/, "", line)
      print line " (GitHub Release " ENVIRON["WC_TAG"] "):"; next
    }
    # whois-x86_64-gnu 保持原样
    if (line ~ /whois-x86_64-gnu/) { print line; next }
    # 校验文件：SHA256SUMS.txt -> SHA256SUMS-static.txt（Gitee raw）
    if (line ~ /\[SHA256SUMS\.txt\]\(/) {
      gsub(/SHA256SUMS\.txt/, "SHA256SUMS-static.txt", line)
      sub(/https?:\/\/[^)]*\/releases\/download\/[^\/]*\//, base "/", line)
      sub(/\]\(release\/lzispro\/whois\//, "](" base "/", line)
      print line; next
    }
    # 静态二进制：GitHub Release 直链或仓库相对路径 -> Gitee raw
    if (line ~ /\]\(https?:\/\/[^)]*\/releases\/download\//) {
      sub(/https?:\/\/[^)]*\/releases\/download\/[^\/]*\//, base "/", line)
      print line; next
    }
    if (line ~ /\]\(release\/lzispro\/whois\//) {
      sub(/\]\(release\/lzispro\/whois\//, "](" base "/", line)
      print line; next
    }
  }
  print line
}
'

for f in "$@"; do
  [[ -f "$f" ]] || die "文件不存在: $f"

  tmp="$(mktemp)"
  WC_BASE="$base" WC_TAG="$tag" awk "$AWK_PROG" "$f" > "$tmp"

  if [[ $dry_run -eq 1 ]]; then
    if cmp -s "$f" "$tmp"; then
      echo "[gitee-convert][dry-run] 无变化: $f"
    else
      echo "[gitee-convert][dry-run] 预览差异（未改动）: $f"
      diff -u "$f" "$tmp" | sed -n '1,120p' || true
    fi
    rm -f "$tmp"
  else
    if cmp -s "$f" "$tmp"; then
      echo "[gitee-convert] 无变化（已是 Gitee raw 形式）: $f"
    else
      changes="$(diff -u "$f" "$tmp" | wc -l | tr -d ' ' || true)"
      cat "$tmp" > "$f"
      echo "[gitee-convert] 已处理: $f (diff 行数=${changes})"
    fi
    rm -f "$tmp"
  fi
done

echo "[gitee-convert] 完成：tag=${tag}, repo=${owner}/${repo}, base=${base}"
