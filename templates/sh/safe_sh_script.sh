#!/usr/bin/env bash
# 安全模板：safe_sh_script — Shell 安全脚本（few-shot 示例）
#
# 演示要点：
# - 变量引用始终加双引号 "$var"（防词拆分/元字符注入）
# - 用户输入经白名单/长度校验后使用（CWE-78 防护）
# - 绝不 curl | sh；下载→校验 sha256→执行

set -euo pipefail

usage() {
    echo "usage: $0 <host>"
    exit 64
}

main() {
    local host="${1:-}"
    # 白名单校验：仅允许字母数字/点/连字符的短主机名
    if [[ -z "$host" || ! "$host" =~ ^[A-Za-z0-9.-]+$ || ${#host} -gt 253 ]]; then
        usage
    fi
    # 变量加引号：防止参数拆分/元字符注入
    ping -c 1 "$host"
}

# 外部软件安装：下载→校验→执行，绝不 curl | sh
install_tool() {
    local ver="1.2.3"
    local url="https://downloads.example.com/tool-${ver}.tar.gz"
    local sha="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    curl -fsSL "$url" -o /tmp/tool.tar.gz
    echo "${sha}  /tmp/tool.tar.gz" | sha256sum -c - >/dev/null
    tar -xzf /tmp/tool.tar.gz -C /opt
}

main "$@"
