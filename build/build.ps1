param(
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
Set-Location -LiteralPath $repoRoot

Write-Host "[build] generating tray icons..."
pwsh -NoProfile -File (Join-Path $repoRoot "scripts/create_tray_icons.ps1")

Write-Host "[build] building native fs host (best-effort)..."
$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if (Test-Path -LiteralPath $vcvars) {
    $cmd = '"' + $vcvars + '" >nul && cd /d "' + $repoRoot + '" && pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration ' + $Configuration + ' -Generator "NMake Makefiles" -SkipIfUnavailable'
    cmd /c $cmd

    Write-Host "[build] building Paragon apfsutil (best-effort)..."
    $cmdApfs = '"' + $vcvars + '" >nul && cd /d "' + $repoRoot + '" && pwsh -NoProfile -File .\scripts\build_paragon_apfsutil.ps1 -BuildType ' + $Configuration + ' -Generator "NMake Makefiles" -SkipIfUnavailable'
    cmd /c $cmdApfs

    Write-Host "[build] building native RW engine scaffold (best-effort)..."
    $cmdRw = '"' + $vcvars + '" >nul && cd /d "' + $repoRoot + '" && pwsh -NoProfile -File .\scripts\build_rw_engine.ps1 -Configuration ' + $Configuration + ' -Generator "NMake Makefiles" -SkipIfUnavailable'
    cmd /c $cmdRw
} else {
    pwsh -NoProfile -File (Join-Path $repoRoot "scripts/build_native_host.ps1") -Configuration $Configuration -SkipIfUnavailable
    pwsh -NoProfile -File (Join-Path $repoRoot "scripts/build_rw_engine.ps1") -Configuration $Configuration -SkipIfUnavailable
}

Write-Host "[build] restoring and building solution..."
dotnet build .\APFSAccess.sln -c $Configuration
