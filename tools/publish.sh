#!/usr/bin/env bash
# publish.sh — 提交并推送 Secure-Vibe 到远端仓库（需网络可达）
# 用法:
#   首次:  ./tools/publish.sh https://github.com/you/secure-vibe.git "initial release"
#   日常:  ./tools/publish.sh "" "release v1.1.0"
set -euo pipefail
REMOTE="${1:-}"
MSG="${2:-}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -n "$REMOTE" ]; then
    git remote remove origin 2>/dev/null || true
    git remote add origin "$REMOTE"
    echo "remote origin -> $REMOTE"
fi
if ! git remote get-url origin >/dev/null 2>&1; then
    echo "请先提供远端: ./tools/publish.sh <仓库URL>" >&2
    exit 1
fi
echo "remote origin: $(git remote get-url origin)"

if [ -n "$(git status --porcelain)" ]; then
    git add -A
    [ -z "$MSG" ] && MSG="update $(date '+%F %T')"
    git commit -m "$MSG"
    echo "committed: $MSG"
else
    echo "工作区干净，跳过提交"
fi

if git push -u origin HEAD; then
    echo "推送成功。已安装用户更新: python cli.py update"
else
    echo "推送失败（网络？）" >&2
    exit 1
fi
