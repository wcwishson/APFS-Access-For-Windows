param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64",
    [bool]$SelfContained = $false
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
Set-Location -LiteralPath $repoRoot

$serviceOut = Join-Path $repoRoot "artifacts/publish/service"
$trayOut = Join-Path $repoRoot "artifacts/publish/tray"
$bundleOut = Join-Path $repoRoot "artifacts/publish/click-run"
$portableOut = Join-Path $repoRoot "artifacts/publish/portable"
$portablePayloadZip = Join-Path $repoRoot "artifacts/publish/click-run-payload.zip"
$nativeOut = Join-Path $repoRoot "artifacts/native/$Configuration"
$bundleSelfContained = $true

New-Item -ItemType Directory -Force -Path $serviceOut, $trayOut, $bundleOut, $portableOut | Out-Null

Write-Host "[publish] generating tray icons..."
pwsh -NoProfile -File (Join-Path $repoRoot "scripts/create_tray_icons.ps1")

Write-Host "[publish] building native fs host (best-effort)..."
$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if (Test-Path -LiteralPath $vcvars) {
    $cmd = '"' + $vcvars + '" >nul && cd /d "' + $repoRoot + '" && pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration ' + $Configuration + ' -Generator "NMake Makefiles" -SkipIfUnavailable'
    cmd /c $cmd

    Write-Host "[publish] building Paragon apfsutil (best-effort)..."
    $cmdApfs = '"' + $vcvars + '" >nul && cd /d "' + $repoRoot + '" && pwsh -NoProfile -File .\scripts\build_paragon_apfsutil.ps1 -BuildType ' + $Configuration + ' -Generator "NMake Makefiles" -SkipIfUnavailable'
    cmd /c $cmdApfs

    Write-Host "[publish] building native RW engine (best-effort)..."
    $cmdRw = '"' + $vcvars + '" >nul && cd /d "' + $repoRoot + '" && pwsh -NoProfile -File .\scripts\build_rw_engine.ps1 -Configuration ' + $Configuration + ' -Generator "NMake Makefiles" -SkipIfUnavailable'
    cmd /c $cmdRw
} else {
    pwsh -NoProfile -File (Join-Path $repoRoot "scripts/build_native_host.ps1") -Configuration $Configuration -SkipIfUnavailable
    pwsh -NoProfile -File (Join-Path $repoRoot "scripts/build_rw_engine.ps1") -Configuration $Configuration -SkipIfUnavailable
}

Write-Host "[publish] publishing service (split output)..."
dotnet publish .\src\ApfsAccess.Service\ApfsAccess.Service.csproj -c $Configuration -r $Runtime --self-contained $SelfContained -o $serviceOut

Write-Host "[publish] publishing tray (split output)..."
dotnet publish .\src\ApfsAccess.Tray\ApfsAccess.Tray.csproj -c $Configuration -r $Runtime --self-contained $SelfContained -o $trayOut

Write-Host "[publish] publishing service (click-run bundle)..."
dotnet publish .\src\ApfsAccess.Service\ApfsAccess.Service.csproj -c $Configuration -r $Runtime --self-contained $bundleSelfContained -o $bundleOut

Write-Host "[publish] publishing tray (click-run bundle)..."
dotnet publish .\src\ApfsAccess.Tray\ApfsAccess.Tray.csproj -c $Configuration -r $Runtime --self-contained $bundleSelfContained -o $bundleOut

$nativeHostExe = Join-Path $nativeOut "ApfsAccess.FsHost.exe"
if (Test-Path -LiteralPath $nativeHostExe) {
    Write-Host "[publish] including native fs host..."
    Copy-Item -LiteralPath $nativeHostExe -Destination (Join-Path $serviceOut "ApfsAccess.FsHost.exe") -Force
    Copy-Item -LiteralPath $nativeHostExe -Destination (Join-Path $bundleOut "ApfsAccess.FsHost.exe") -Force
} else {
    Write-Warning "Native fs host was not found at '$nativeHostExe'. Native Explorer mounting will not work until built."
}

$apfsUtilExe = Join-Path $nativeOut "apfsutil.exe"
if (Test-Path -LiteralPath $apfsUtilExe) {
    Write-Host "[publish] including apfsutil..."
    Copy-Item -LiteralPath $apfsUtilExe -Destination (Join-Path $serviceOut "apfsutil.exe") -Force
    Copy-Item -LiteralPath $apfsUtilExe -Destination (Join-Path $bundleOut "apfsutil.exe") -Force
}

$rwEngineLib = Join-Path $nativeOut "ApfsAccess.ApfsRwEngine.lib"
if (Test-Path -LiteralPath $rwEngineLib) {
    Write-Host "[publish] including native RW engine artifact..."
    Copy-Item -LiteralPath $rwEngineLib -Destination (Join-Path $bundleOut "ApfsAccess.ApfsRwEngine.lib") -Force
}

$winfspDoc = Join-Path $repoRoot "docs/winfsp-setup.md"
if (Test-Path -LiteralPath $winfspDoc) {
    Copy-Item -LiteralPath $winfspDoc -Destination (Join-Path $bundleOut "WINFSP_SETUP.md") -Force
}

$nativeWritePilotDoc = Join-Path $repoRoot "docs/native-write-pilot.md"
if (Test-Path -LiteralPath $nativeWritePilotDoc) {
    Copy-Item -LiteralPath $nativeWritePilotDoc -Destination (Join-Path $bundleOut "NATIVE_WRITE_PILOT.md") -Force
}

$bundleScriptsDir = Join-Path $bundleOut "scripts"
New-Item -ItemType Directory -Force -Path $bundleScriptsDir | Out-Null
$bundleScriptNames = @(
    "configure_native_ce.ps1",
    "evaluate_write_promotion.ps1",
    "import_validation_report.ps1",
    "install_prereqs.ps1",
    "native_probe.ps1",
    "new_validation_report.ps1",
    "run_pilot_validation.ps1",
    "update_write_evidence.ps1"
)
foreach ($scriptName in $bundleScriptNames) {
    $sourcePath = Join-Path $repoRoot "scripts/$scriptName"
    if (Test-Path -LiteralPath $sourcePath) {
        Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $bundleScriptsDir $scriptName) -Force
    }
}

@'
@echo off
setlocal
cd /d "%~dp0"
start "" "ApfsAccess.Tray.exe"
'@ | Set-Content -Path (Join-Path $bundleOut "Run_APFS_Access.bat") -Encoding ascii

@'
@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\run_pilot_validation.ps1" %*
set "EXITCODE=%ERRORLEVEL%"
echo.
if not "%EXITCODE%"=="0" (
  echo Pilot validation failed with exit code %EXITCODE%.
)
pause
exit /b %EXITCODE%
'@ | Set-Content -Path (Join-Path $bundleOut "Run_APFS_Pilot_Validation.bat") -Encoding ascii

@'
@echo off
setlocal
cd /d "%~dp0"
set "APP_DIR=%~dp0artifacts\publish\click-run"
if not exist "%APP_DIR%\ApfsAccess.Tray.exe" (
  echo APFS Access app is not published yet.
  echo Build it with:
  echo   pwsh -NoProfile -File .\build\publish.ps1 -Configuration Release -Runtime win-x64
  pause
  exit /b 1
)
start "" "%APP_DIR%\ApfsAccess.Tray.exe"
'@ | Set-Content -Path (Join-Path $repoRoot "Run_APFS_Access.bat") -Encoding ascii

@'
APFS Access click-run package

How to run
1) Install prerequisites (admin PowerShell):
   pwsh -NoProfile -File .\scripts\install_prereqs.ps1
2) Double-click ApfsAccess.Tray.exe (or Run_APFS_Access.bat).
3) Tray starts and auto-launches ApfsAccess.Service.exe when needed.
4) Right-click tray icon -> Quit to stop.

One-click pilot smoke validation
1) Connect a sacrificial APFS drive.
2) Double-click Run_APFS_Pilot_Validation.bat.
3) The launcher auto-detects APFS media, configures pilot mode for the selected drive, runs a writable smoke/remount check, and creates a feedback archive under .\pilot-feedback\.
4) The feedback archive is intended for bug-report triage only; crash/hot-unplug/power-loss/macOS validation still remains manual.

Native backend setup
1) Build/obtain apfsutil.exe from third_party/paragon_apfs_sdk_ce.
2) Build native host:
   pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration Release
3) Configure appsettings with native paths:
   pwsh -NoProfile -File .\scripts\configure_native_ce.ps1 -ApfsUtilPath "C:\path\apfsutil.exe" -NativeFsHostPath "C:\path\ApfsAccess.FsHost.exe" -DeviceCandidates "\\.\PhysicalDrive1"

Native write policy notes
- Native write remains conservative and fail-closed by default.
- Unsupported volumes (for example encrypted/special-role) are automatically read-only.
- Image-backed/native test media is the supported in-repo validation path.
- Raw physical APFS write remains pilot-only and requires an allow-listed device plus validation evidence thresholds before writable mounts are eligible.
- `Run_APFS_Pilot_Validation.bat` uses a temporary session-local evidence ledger to unlock the automated smoke run on a sacrificial pilot drive; it does not replace real pilot/stable evidence collection.
- Use `NATIVE_WRITE_PILOT.md` and the bundled `scripts\new_validation_report.ps1`, `scripts\import_validation_report.ps1`, `scripts\evaluate_write_promotion.ps1`, and `scripts\update_write_evidence.ps1` helpers for hardware/cross-OS validation and promotion checks.
'@ | Set-Content -Path (Join-Path $bundleOut "README_RUN.txt") -Encoding utf8

if (Test-Path -LiteralPath $portablePayloadZip) {
    Remove-Item -LiteralPath $portablePayloadZip -Force
}

Write-Host "[publish] creating portable payload zip..."
Compress-Archive -Path (Join-Path $bundleOut "*") -DestinationPath $portablePayloadZip -Force

Write-Host "[publish] publishing portable single-file launcher..."
dotnet publish .\src\ApfsAccess.Bootstrap\ApfsAccess.Bootstrap.csproj `
    -c $Configuration `
    -r $Runtime `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:PortablePayloadZip="$portablePayloadZip" `
    -o $portableOut

$portableExe = Join-Path $portableOut "APFSAccess.Portable.exe"
if (Test-Path -LiteralPath $portableExe) {
    Copy-Item -LiteralPath $portableExe -Destination (Join-Path $repoRoot "APFSAccess_Portable.exe") -Force
}

Write-Host "[publish] done"
Write-Host " service   : $serviceOut"
Write-Host " tray      : $trayOut"
Write-Host " click-run : $bundleOut"
Write-Host " portable  : $portableOut"
