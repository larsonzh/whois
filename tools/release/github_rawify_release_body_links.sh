#!/usr/bin/env bash
set -euo pipefail

# github_rawify_release_body_links.sh
# 将 release body 中 9 个静态二进制链接统一转换为 GitHub raw 链接：
#   https://github.com/<owner>/<repo>/raw/<tag>/release/lzispro/whois/<asset>
# 支持输入为：
#   - GitHub Release 直链：https://github.com/<owner>/<repo>/releases/download/<tag>/<asset>
#   - 仓库相对路径：release/lzispro/whois/<asset>
#
# 注意：仅处理 9 个静态二进制，不处理 whois-x86_64-gnu 与 SHA256SUMS.txt。
#
# 用法：
#   ./tools/release/github_rawify_release_body_links.sh [-t v3.2.10] [-o owner] [-p repo] [-n] <file...>
# 说明：
#   -t/--tag           目标版本 tag（如 v3.2.10）。若省略且仅传入 1 个文件：
#                      将尝试从文件名或正文推断（vX.Y.Z）。
#   -o/--owner         仓库 owner（默认：larsonzh）
#   -p/--repo          仓库名（默认：whois）
#   -n/--dry-run       仅打印匹配数，不改文件

owner=larsonzh
repo=whois
tag=""
dry_run=0

assets=(
  whois-x86_64
  whois-x86
  whois-aarch64
  whois-armv7
  whois-mipsel
  whois-mips64el
  whois-loongarch64
  whois-win64.exe
  whois-win32.exe
)

die() { echo "[github-rawify] $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--tag) tag="$2"; shift 2;;
    -o|--owner) owner="$2"; shift 2;;
    -p|--repo) repo="$2"; shift 2;;
    -n|--dry-run) dry_run=1; shift;;
    -h|--help) sed -n '1,80p' "$0"; exit 0;;
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
  if [[ -z "$inferred_tag" && -f "$f_candidate" ]]; then
    inferred_tag="$(grep -o -E '\bwhois[[:space:]]+(v[0-9]+\.[0-9]+\.[0-9]+)\b' "$f_candidate" | head -n1 | sed -E 's#.*\b(v[0-9]+\.[0-9]+\.[0-9]+)\b.*#\1#' || true)"
  fi
  if [[ -n "$inferred_tag" ]]; then
    tag="$inferred_tag"
    echo "[github-rawify] inferred tag: $tag (from ${bn_candidate:+filename/content})"
  fi
fi

[[ -n "$tag" ]] || die "必须指定 -t/--tag，或在仅处理单文件时可由文件名/正文自动推断（例如 v3.2.10）"

base="https://github.com/${owner}/${repo}/raw/${tag}/release/lzispro/whois"

for f in "$@"; do
  [[ -f "$f" ]] || die "文件不存在: $f"

  tmp="${f}.tmp.$$"
  cp "$f" "$tmp"

  for a in "${assets[@]}"; do
    if [[ $dry_run -eq 1 ]]; then
      cnt_rel=$(grep -o -F "(release/lzispro/whois/${a})" "$tmp" | wc -l | tr -d ' ')
      cnt_gh=$(grep -o -E "releases/download/[^)]*/${a}\)" "$tmp" | wc -l | tr -d ' ')
      echo "[github-rawify][dry-run] ${f}: ${a} (rel=${cnt_rel}, gh=${cnt_gh}) -> ${base}/${a}"
    else
      # 相对路径 -> GitHub raw
      sed -E -i "s#\]\(release/lzispro/whois/${a}\)#](${base}/${a})#g" "$tmp"
      # GitHub Release 直链 -> GitHub raw
      sed -E -i "s#\]\(https?://[^)]*/releases/download/[^)]*/${a}\)#](${base}/${a})#g" "$tmp"
    fi
  done

  if [[ $dry_run -eq 1 ]]; then
    rm -f "$tmp"
    echo "[github-rawify] 预览完成（未改动）: $f"
  else
    mv "$tmp" "$f"
    echo "[github-rawify] 已处理: $f"
  fi
done

echo "[github-rawify] 完成：tag=${tag}, repo=${owner}/${repo}"
