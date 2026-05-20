param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $repoRoot

Write-Host "[beta-build] checking developer prerequisites..."
& (Join-Path $repoRoot "scripts/install_prereqs.ps1") -ForDeveloperBuild

Write-Host "[beta-build] publishing beta bundle..."
& (Join-Path $repoRoot "build/publish.ps1") -Configuration $Configuration -Runtime $Runtime

$bundleRoot = Join-Path $repoRoot "artifacts/publish/click-run"

Write-Host ""
Write-Host "[beta-build] ready"
Write-Host "[beta-build] bundle : $bundleRoot"
Write-Host "[beta-build] next   : connect a sacrificial APFS drive, launch the tray app, and follow the native-write pilot runbook/manual validation steps."
Write-Host "                $bundleRoot\\Run_APFS_Access.bat"
