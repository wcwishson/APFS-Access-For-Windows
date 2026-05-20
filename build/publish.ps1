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
$probeOut = Join-Path $repoRoot "artifacts/publish/native-probe"
$bundleOut = Join-Path $repoRoot "artifacts/publish/click-run"
$portableOut = Join-Path $repoRoot "artifacts/publish/portable"
$portablePayloadZip = Join-Path $repoRoot "artifacts/publish/click-run-payload.zip"
$nativeOut = Join-Path $repoRoot "artifacts/native/$Configuration"
$bundleSelfContained = $true

New-Item -ItemType Directory -Force -Path $serviceOut, $trayOut, $probeOut, $bundleOut, $portableOut | Out-Null

Write-Host "[publish] generating tray icons..."
pwsh -NoProfile -File (Join-Path $repoRoot "scripts/create_tray_icons.ps1")

Write-Host "[publish] building native fs host (best-effort)..."
$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if (Test-Path -LiteralPath $vcvars) {
    $cmd = '"' + $vcvars + '" >nul && cd /d "' + $repoRoot + '" && pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration ' + $Configuration + ' -Generator "NMake Makefiles" -SkipIfUnavailable'
    cmd /c $cmd

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

Write-Host "[publish] publishing native probe (split output)..."
dotnet publish .\src\ApfsAccess.NativeProbe\ApfsAccess.NativeProbe.csproj -c $Configuration -r $Runtime --self-contained $SelfContained -o $probeOut

Write-Host "[publish] publishing service (click-run bundle)..."
dotnet publish .\src\ApfsAccess.Service\ApfsAccess.Service.csproj -c $Configuration -r $Runtime --self-contained $bundleSelfContained -o $bundleOut

Write-Host "[publish] publishing tray (click-run bundle)..."
dotnet publish .\src\ApfsAccess.Tray\ApfsAccess.Tray.csproj -c $Configuration -r $Runtime --self-contained $bundleSelfContained -o $bundleOut

Write-Host "[publish] publishing native probe (click-run bundle)..."
dotnet publish .\src\ApfsAccess.NativeProbe\ApfsAccess.NativeProbe.csproj -c $Configuration -r $Runtime --self-contained $bundleSelfContained -o $bundleOut

$nativeHostExe = Join-Path $nativeOut "ApfsAccess.FsHost.exe"
if (Test-Path -LiteralPath $nativeHostExe) {
    Write-Host "[publish] including native fs host..."
    Copy-Item -LiteralPath $nativeHostExe -Destination (Join-Path $serviceOut "ApfsAccess.FsHost.exe") -Force
    Copy-Item -LiteralPath $nativeHostExe -Destination (Join-Path $bundleOut "ApfsAccess.FsHost.exe") -Force
} else {
    Write-Warning "Native fs host was not found at '$nativeHostExe'. Native Explorer mounting will not work until built."
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
    "create_test_image.ps1",
    "evaluate_write_promotion.ps1",
    "import_validation_report.ps1",
    "install_prereqs.ps1",
    "native_probe.ps1",
    "new_validation_report.ps1",
    "run_pilot_validation.ps1",
    "run_physical_rw_validation.ps1",
    "run_rw_harness.ps1",
    "update_write_evidence.ps1"
)
foreach ($scriptName in $bundleScriptNames) {
    $sourcePath = Join-Path $repoRoot "scripts/$scriptName"
    if (Test-Path -LiteralPath $sourcePath) {
        Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $bundleScriptsDir $scriptName) -Force
    }
}

@'
Option Explicit

Dim shell, fso, scriptDir, directTray, publishedTray, trayPath, workingDir

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
directTray = fso.BuildPath(scriptDir, "ApfsAccess.Tray.exe")
publishedTray = fso.BuildPath(scriptDir, "artifacts\publish\click-run\ApfsAccess.Tray.exe")

If fso.FileExists(directTray) Then
    trayPath = directTray
ElseIf fso.FileExists(publishedTray) Then
    trayPath = publishedTray
Else
    MsgBox "APFS Access app is not published yet." & vbCrLf & vbCrLf & _
        "Build it with:" & vbCrLf & _
        "pwsh -NoProfile -File .\build\publish.ps1 -Configuration Release -Runtime win-x64", _
        vbExclamation, "APFS Access"
    WScript.Quit 1
End If

workingDir = fso.GetParentFolderName(trayPath)
shell.CurrentDirectory = workingDir
shell.Run """" & trayPath & """", 0, False
'@ | Set-Content -Path (Join-Path $bundleOut "Run_APFS_Access_Silent.vbs") -Encoding ascii

@'
@echo off
setlocal
if /I not "%APFSACCESS_VISIBLE_CONSOLE%"=="1" if exist "%~dp0Run_APFS_Access_Silent.vbs" (
  wscript.exe "%~dp0Run_APFS_Access_Silent.vbs"
  exit /b %ERRORLEVEL%
)
if /I not "%APFSACCESS_VISIBLE_CONSOLE%"=="1" if /I not "%APFSACCESS_LAUNCHED_MINIMIZED%"=="1" (
  set "APFSACCESS_LAUNCHED_MINIMIZED=1"
  start "" /min "%~f0" %*
  exit /b
)
cd /d "%~dp0"
start "" /min "ApfsAccess.Tray.exe"
'@ | Set-Content -Path (Join-Path $bundleOut "Run_APFS_Access.bat") -Encoding ascii
 
Copy-Item -LiteralPath (Join-Path $bundleOut "Run_APFS_Access_Silent.vbs") -Destination (Join-Path $repoRoot "Run_APFS_Access_Silent.vbs") -Force

@'
@echo off
setlocal
if /I not "%APFSACCESS_VISIBLE_CONSOLE%"=="1" if exist "%~dp0Run_APFS_Access_Silent.vbs" (
  wscript.exe "%~dp0Run_APFS_Access_Silent.vbs"
  exit /b %ERRORLEVEL%
)
if /I not "%APFSACCESS_VISIBLE_CONSOLE%"=="1" if /I not "%APFSACCESS_LAUNCHED_MINIMIZED%"=="1" (
  set "APFSACCESS_LAUNCHED_MINIMIZED=1"
  start "" /min "%~f0" %*
  exit /b
)
cd /d "%~dp0"
set "APP_DIR=%~dp0artifacts\publish\click-run"
if not exist "%APP_DIR%\ApfsAccess.Tray.exe" (
  echo APFS Access app is not published yet.
  echo Build it with:
  echo   pwsh -NoProfile -File .\build\publish.ps1 -Configuration Release -Runtime win-x64
  pause
  exit /b 1
)
start "" /min "%APP_DIR%\ApfsAccess.Tray.exe"
'@ | Set-Content -Path (Join-Path $repoRoot "Run_APFS_Access.bat") -Encoding ascii

@'
APFS Access click-run package

How to run
1) Install prerequisites (admin PowerShell):
   pwsh -NoProfile -File .\scripts\install_prereqs.ps1
2) Double-click ApfsAccess.Tray.exe (or Run_APFS_Access.bat).
3) Tray starts and auto-launches ApfsAccess.Service.exe when needed.
4) Right-click tray icon -> Quit to stop.

Quiet launcher
- Use Run_APFS_Access.bat or Run_APFS_Access_Silent.vbs for normal app startup without a visible terminal.
- Set APFSACCESS_VISIBLE_CONSOLE=1 before running the .bat only when you want troubleshooting output.

Native backend setup
1) Build native host:
   pwsh -NoProfile -File .\scripts\build_native_host.ps1 -Configuration Release
2) Configure appsettings with native paths:
   pwsh -NoProfile -File .\scripts\configure_native_ce.ps1 -NativeFsHostPath "C:\path\ApfsAccess.FsHost.exe" -DeviceCandidates "\\.\PhysicalDrive1"

Native write policy notes
- Native write remains conservative and fail-closed by default.
- Raw physical APFS validation defaults to read-only mount/copy/hash checks.
- Unsupported volumes (for example encrypted/special-role) are automatically read-only.
- Image-backed/native test media is the supported in-repo validation path.
- Raw physical APFS write remains blocked unless an operator deliberately passes the destructive pilot switch and the app's allow-list/evidence gates are satisfied.
- After a sacrificial APFS volume is mounted read/write, use scripts\run_physical_rw_validation.ps1 for guarded mounted-volume create/copy/hash/rename/move/delete/storm validation.
- Use `NATIVE_WRITE_PILOT.md` and the bundled `scripts\new_validation_report.ps1`, `scripts\import_validation_report.ps1`, `scripts\evaluate_write_promotion.ps1`, and `scripts\update_write_evidence.ps1` helpers for hardware/cross-OS validation and promotion checks.

Safe image-backed smoke test
1) Create a disposable normal file:
   pwsh -NoProfile -File .\scripts\create_test_image.ps1 -Path .\artifacts\test-images\apfsaccess-test.apfs.img -SizeMiB 64
2) Probe that file through the native backend:
   pwsh -NoProfile -File .\scripts\native_probe.ps1 -DeviceId .\artifacts\test-images\apfsaccess-test.apfs.img -AsJson

This path never formats a physical drive and refuses to overwrite existing files. The image is synthetic APFS Access validation media, not macOS-compatible mkfs.apfs output.
'@ | Set-Content -Path (Join-Path $bundleOut "README_RUN.txt") -Encoding utf8

if (Test-Path -LiteralPath $portablePayloadZip) {
    Remove-Item -LiteralPath $portablePayloadZip -Force
}

Write-Host "[publish] creating portable payload zip..."
$portablePayloadStaging = Join-Path $repoRoot "artifacts/publish/click-run-portable-payload"
if (Test-Path -LiteralPath $portablePayloadStaging) {
    Remove-Item -LiteralPath $portablePayloadStaging -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $portablePayloadStaging | Out-Null
$portablePayloadExcludes = @(
    "pilot-feedback",
    "logs",
    "temp",
    "rw-journal"
)
Get-ChildItem -LiteralPath $bundleOut -Force |
    Where-Object { $portablePayloadExcludes -notcontains $_.Name } |
    ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $portablePayloadStaging -Recurse -Force
    }
Compress-Archive -Path (Join-Path $portablePayloadStaging "*") -DestinationPath $portablePayloadZip -Force
Remove-Item -LiteralPath $portablePayloadStaging -Recurse -Force

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
Write-Host " probe     : $probeOut"
Write-Host " click-run : $bundleOut"
Write-Host " portable  : $portableOut"
