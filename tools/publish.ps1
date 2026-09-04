# publish.ps1 — 提交并推送 Secure-Vibe 到远端仓库（需网络可达）
# 用法:
#   首次:  powershell -File tools/publish.ps1 -Remote "https://github.com/you/secure-vibe.git"
#   日常:  powershell -File tools/publish.ps1 -Message "release v1.1.0"
param(
    [string]$Remote = "",
    [string]$Message = ""
)

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root

# 1. 远端
if ($Remote) {
    git remote remove origin 2>$null
    git remote add origin $Remote
    Write-Host "remote origin -> $Remote"
}
$existing = git remote get-url origin 2>$null
if (-not $existing) {
    Write-Host "请先提供远端: powershell -File tools/publish.ps1 -Remote <仓库URL>" -ForegroundColor Yellow
    exit 1
}
Write-Host "remote origin: $existing"

# 2. 提交本地变更（若有）
$dirty = git status --porcelain
if ($dirty) {
    git add -A
    if (-not $Message) { $Message = "update $(Get-Date -Format 'yyyy-MM-dd HH:mm')" }
    git commit -m $Message
    Write-Host "committed: $Message"
} else {
    Write-Host "工作区干净，跳过提交"
}

# 3. 推送
Write-Host "推送中..."
git push -u origin HEAD
if ($LASTEXITCODE -eq 0) {
    Write-Host "推送成功。已安装用户更新: python cli.py update"
} else {
    Write-Host "推送失败（网络？）: $existing" -ForegroundColor Red
    exit 1
}
