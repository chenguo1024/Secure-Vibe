#!/usr/bin/env bash
# secure-vibe: ignore-file - installer legitimately uses rm -rf on its own target dir
# install.sh — 把 Secure-Vibe 安装到用户的 Agent 技能目录（Linux/macOS）
# 用法:
#   ./install.sh                    # 默认 opencode
#   ./install.sh codex              # 安装到 ~/.codex/skills/secure-vibe
#   ./install.sh claude             # 安装到 ~/.claude/skills/secure-vibe
#   ./install.sh /自定义/路径        # 指定目录
set -euo pipefail

TARGET="${1:-opencode}"
case "$TARGET" in
    opencode) TARGET="$HOME/.config/opencode/skill/secure-vibe" ;;
    codex)    TARGET="$HOME/.codex/skills/secure-vibe" ;;
    claude)   TARGET="$HOME/.claude/skills/secure-vibe" ;;
esac

SOURCE="$(cd "$(dirname "$0")" && pwd)"
REPO="${2:-}"   # 传入则使用 git 克隆安装（此后 cli.py update / git pull 更新）

if [ -n "$REPO" ]; then
    if [ -d "$TARGET/.git" ]; then
        echo "目标已是 git 管理安装，执行 git pull 更新:"
        git -C "$TARGET" pull --ff-only
        python3 "$TARGET/cli.py" selftest || python "$TARGET/cli.py" selftest
        exit $?
    fi
    rm -rf "$TARGET"
    git clone "$REPO" "$TARGET"
    echo "git 管理安装完成: $TARGET"
    python3 "$TARGET/cli.py" selftest || python "$TARGET/cli.py" selftest
    echo ""
    echo "此后更新: python \"$TARGET/cli.py\" update"
    exit $?
fi

echo "Secure-Vibe 安装器"
echo "  源:   $SOURCE"
echo "  目标: $TARGET"

mkdir -p "$TARGET"

for item in SKILL.md cli.py main.py config.yaml requirements.txt README.md VERSION core rules blacklist templates docs; do
    if [ -e "$SOURCE/$item" ]; then
        rm -rf "$TARGET/$item"
        cp -r "$SOURCE/$item" "$TARGET/$item"
        echo "  + $item"
    fi
done

echo ""
echo "安装自检:"

# 自动寻找带 pyyaml 的 Python
PY_CMD=""
for candidate in python3 python py; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import yaml" 2>/dev/null; then
        PY_CMD="$candidate"
        break
    fi
done

if [ -n "$PY_CMD" ]; then
    echo "  使用 Python: $PY_CMD"
    # 把选定的解释器绝对路径写入 config.yaml（cli.py 启动时检测解释器错位）
    PY_EXE=$("$PY_CMD" -c 'import sys; print(sys.executable)' 2>/dev/null || true)
    if [ -n "$PY_EXE" ] && [ -f "$TARGET/config.yaml" ]; then
        if grep -q '^interpreter:' "$TARGET/config.yaml"; then
            sed -i.bak "s|^interpreter:.*|interpreter: \"$PY_EXE\"|" "$TARGET/config.yaml" && rm -f "$TARGET/config.yaml.bak"
        else
            printf '\n# Chosen by the install script; cli.py warns at startup when running under a different interpreter\ninterpreter: "%s"\n' "$PY_EXE" >> "$TARGET/config.yaml"
        fi
        echo "  解释器已写入 config.yaml: $PY_EXE"
    fi
    if "$PY_CMD" "$TARGET/cli.py" selftest; then
        echo ""
        echo "安装完成。重启 Agent 后生效。技能名: secure-vibe"
    else
        echo "自检未通过，请检查 pyyaml: pip install pyyaml" >&2
        exit 1
    fi
else
    echo "未找到带 pyyaml 的 Python。请先: pip install pyyaml，然后手动运行:" >&2
    echo "  python3 $TARGET/cli.py selftest" >&2
    exit 1
fi
