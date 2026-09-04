# install.ps1 — 把 Secure-Vibe 安装到用户的 Agent 技能目录
# 用法:
#   默认安装到 opencode:  powershell -File install.ps1
#   指定目录:             powershell -File install.ps1 -Target "C:\path\to\agent\skills\secure-vibe"
#   Claude Code 风格:     powershell -File install.ps1 -Target "$env:USERPROFILE\.claude\skills\secure-vibe"
param(
    [string]$Target = "$env:USERPROFILE\.config\opencode\skill\secure-vibe",
    # git 管理安装：从仓库克隆（此后 cli.py update / git pull 即可一键更新）
    [string]$Repo = ""
)

$ErrorActionPreference = "Stop"
$Source = $PSScriptRoot

# 自动寻找带 pyyaml 的 Python（自检用）
$pythonCmd = $null
foreach ($candidate in @("python", "py -3", "python3")) {
    try {
        $check = Invoke-Expression "$candidate -c `"import yaml; print('ok')`"" 2>$null
        if ($check -match "ok") { $pythonCmd = $candidate; break }
    } catch { continue }
}

if ($Repo) {
    # git 克隆安装：目标目录将由 git 管理，更新 = git pull 或 cli.py update
    if (Test-Path $Target) {
        if ((Test-Path (Join-Path $Target ".git"))) {
            Write-Host "目标已是 git 管理安装，执行 git pull 更新:"
            & git -C $Target pull --ff-only
            exit $LASTEXITCODE
        }
        Write-Warning "目标已存在且非 git 管理，将删除重装: $Target"
        Remove-Item -Recurse -Force $Target
    }
    & git clone $Repo $Target
    if ($LASTEXITCODE -ne 0) { Write-Error "git clone 失败"; exit 1 }
    Write-Host "git 管理安装完成: $Target"
    $args = $PythonCmd.Split(" ") + @((Join-Path $Target "cli.py"), "selftest"); & $args[0] $args[1..($args.Count-1)]
    Write-Host "`n此后更新: python `"$Target\cli.py`" update"
    exit $LASTEXITCODE
}

# 需要复制的内容（排除日志/缓存/测试可留可不留）
$items = @(
    "SKILL.md", "cli.py", "main.py", "config.yaml", "requirements.txt", "README.md",
    "core", "rules", "blacklist", "templates", "docs"
)

Write-Host "Secure-Vibe 安装器"
Write-Host "  源:   $Source"
Write-Host "  目标: $Target"

New-Item -ItemType Directory -Force -Path $Target | Out-Null

foreach ($item in $items) {
    $src = Join-Path $Source $item
    if (-not (Test-Path $src)) { Write-Warning "跳过（不存在）: $item"; continue }
    $dst = Join-Path $Target $item
    if (Test-Path $dst) { Remove-Item -Recurse -Force $dst }
    Copy-Item -Recurse -Force $src $dst
    Write-Host "  + $item"
}

# 安装后自检：使用已找到的 Python
Write-Host "`n安装自检:"
if ($pythonCmd) {
    Write-Host "  使用 Python: $pythonCmd"
    Invoke-Expression "$pythonCmd `"$Target\cli.py`" selftest"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n安装完成。重启 Agent 后生效。技能名: secure-vibe"
    } else {
        Write-Warning "自检未通过，请检查 pyyaml: pip install pyyaml"
        exit 1
    }
} else {
    Write-Warning "未找到带 pyyaml 的 Python。请先: pip install pyyaml，然后手动运行:"
    Write-Host "  python `"$Target\cli.py`" selftest"
    exit 1
}

