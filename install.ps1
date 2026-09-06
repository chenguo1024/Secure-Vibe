# install.ps1 — 把 Secure-Vibe 安装到用户的 Agent 技能目录
# 用法:
#   默认安装到 opencode:  powershell -File install.ps1
#   Codex:                powershell -File install.ps1 -Agent codex
#   Claude Code:          powershell -File install.ps1 -Agent claude
#   指定目录:             powershell -File install.ps1 -Target "C:\path\to\agent\skills\secure-vibe"
param(
    # opencode / codex / claude（写入对应技能目录）
    [string]$Agent = "opencode",
    [string]$Target = "",
    # git 管理安装：从仓库克隆（此后 cli.py update / git pull 即可一键更新）
    [string]$Repo = ""
)

$ErrorActionPreference = "Stop"
$Source = $PSScriptRoot

$userHome = $env:USERPROFILE
if (-not $Target) {
    switch ($Agent) {
        "codex"   { $Target = "$userHome\.codex\skills\secure-vibe" }
        "claude"  { $Target = "$userHome\.claude\skills\secure-vibe" }
        default   { $Target = "$userHome\.config\opencode\skill\secure-vibe" }
    }
}

# 自动寻找可用的 Python：优先探测 Python 3.8+ 且带 pip 的解释器（自检用）
# 选定的解释器绝对路径会写入 config.yaml 的 interpreter 字段，后续 cli.py 启动时校验是否一致
$pythonCmd = $null      # command form, e.g. "python" or "py -3"
$pythonExe = $null      # absolute interpreter path written into config.yaml

function Test-Interpreter($cmd) {
    try {
        $check = Invoke-Expression "$cmd -c `"import sys; import yaml; import importlib.util as u; print(sys.version_info >= (3, 8) and (u.find_spec('pip') is not None) and 'ok' or 'no')`"" 2>$null
        return ($check -match "ok")
    } catch { return $false }
}

# 候选命令（常见安装方式）+ py -0p 探测出的绝对路径
$candidates = @("python", "py -3", "python3")
try {
    $listed = & py -0p 2>$null
    foreach ($line in $listed) {
        if ($line -match "([A-Za-z]:\\[^\s*]+python\.exe)") {
            $candidates += ('"' + $Matches[1] + '"')
        }
    }
} catch { }

foreach ($candidate in $candidates) {
    if (Test-Interpreter $candidate) { $pythonCmd = $candidate; break }
}

# 解析出绝对路径写入 config.yaml（cli.py 启动时用它检测解释器错位）
if ($pythonCmd) {
    try {
        $pythonExe = (Invoke-Expression "$pythonCmd -c `"import sys; print(sys.executable)`"" 2>$null)
    } catch { $pythonExe = $null }
}

# 把选定的解释器路径写入 config.yaml 的 interpreter 字段（cli.py 启动时检测解释器错位）
# 注意：Windows 路径含反斜杠，必须用 YAML 单引号（双引号内 \U 会被解析成 unicode 转义）
function Set-InterpreterConfig($configPath) {
    if (-not $pythonExe -or -not (Test-Path $configPath)) { return }
    try {
        $quoted = "'" + ($pythonExe -replace "'", "''") + "'"
        $content = Get-Content $configPath -Raw -Encoding UTF8
        if ($content -match "(?m)^interpreter:") {
            $content = $content -replace "(?m)^interpreter:.*$", ('interpreter: ' + $quoted)
        } else {
            $content = $content + "`n# Chosen by the install script; cli.py warns at startup when running under a different interpreter`ninterpreter: $quoted`n"
        }
        Set-Content -Path $configPath -Value $content -Encoding UTF8 -NoNewline
        Write-Host "  解释器已写入 config.yaml: $pythonExe"
    } catch {
        Write-Warning "写入 config.yaml interpreter 字段失败（不影响使用）: $_"
    }
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
    Set-InterpreterConfig (Join-Path $Target "config.yaml")
    $args = $pythonCmd.Split(" ") + @((Join-Path $Target "cli.py"), "selftest"); & $args[0] $args[1..($args.Count-1)]
    Write-Host "`n此后更新: python `"$Target\cli.py`" update"
    exit $LASTEXITCODE
}

# 需要复制的内容（排除日志/缓存）
$items = @(
    "SKILL.md", "cli.py", "main.py", "config.yaml", "requirements.txt", "README.md",
    "VERSION", "core", "rules", "blacklist", "templates", "docs"
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
    Set-InterpreterConfig (Join-Path $Target "config.yaml")
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

