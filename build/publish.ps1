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
$cliOut = Join-Path $repoRoot "artifacts/publish/cli"
$probeDebugSmokeOut = Join-Path $repoRoot "artifacts/publish/native-probe-debug-smoke"
$bundleOut = Join-Path $repoRoot "artifacts/publish/click-run"
$portableOut = Join-Path $repoRoot "artifacts/publish/portable"
$portableExeName = "APFS Access.exe"
$legacyPortableExeNames = @("APFSAccess_Portable.exe", "APFSAccess.Portable.exe")
$portablePayloadZip = Join-Path $repoRoot "artifacts/publish/click-run-payload.zip"
$nativeOut = Join-Path $repoRoot "artifacts/native/$Configuration"
$nativeHostExe = Join-Path $nativeOut "ApfsAccess.FsHost.exe"
$bundleSelfContained = $true
$nativeBuildRoot = if ([string]::IsNullOrWhiteSpace($env:APFSACCESS_NATIVE_BUILD_ROOT)) {
    Join-Path ([System.IO.Path]::GetTempPath()) "apfsaccess_native"
} else {
    [System.IO.Path]::GetFullPath($env:APFSACCESS_NATIVE_BUILD_ROOT)
}

$publishOutputDirs = @($serviceOut, $trayOut, $probeOut, $cliOut, $bundleOut, $portableOut)
foreach ($publishOutputDir in $publishOutputDirs) {
    if (Test-Path -LiteralPath $publishOutputDir) {
        Get-ChildItem -LiteralPath $publishOutputDir -Force |
            Remove-Item -Recurse -Force
    }
}
if (Test-Path -LiteralPath $probeDebugSmokeOut) {
    Remove-Item -LiteralPath $probeDebugSmokeOut -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $serviceOut, $trayOut, $probeOut, $cliOut, $bundleOut, $portableOut | Out-Null

Write-Host "[publish] generating tray icons..."
pwsh -NoProfile -File (Join-Path $repoRoot "scripts/create_tray_icons.ps1")

if (Test-Path -LiteralPath $nativeHostExe) {
    Remove-Item -LiteralPath $nativeHostExe -Force
}

Write-Host "[publish] building native fs host..."
$nativeGenerator = "Visual Studio 17 2022"
pwsh -NoProfile -File (Join-Path $repoRoot "scripts/build_native_host.ps1") `
    -Configuration $Configuration `
    -BuildDir (Join-Path $nativeBuildRoot "publish_host_vs/$Configuration") `
    -Generator $nativeGenerator

Write-Host "[publish] publishing service (split output)..."
dotnet publish .\src\ApfsAccess.Service\ApfsAccess.Service.csproj -c $Configuration -r $Runtime --self-contained $SelfContained -o $serviceOut

Write-Host "[publish] publishing tray (split output)..."
dotnet publish .\src\ApfsAccess.Tray\ApfsAccess.Tray.csproj -c $Configuration -r $Runtime --self-contained $SelfContained -o $trayOut

Write-Host "[publish] publishing native probe (split output)..."
dotnet publish .\src\ApfsAccess.NativeProbe\ApfsAccess.NativeProbe.csproj -c $Configuration -r $Runtime --self-contained $SelfContained -o $probeOut

Write-Host "[publish] publishing CLI (split output)..."
dotnet publish .\src\ApfsAccess.Cli\ApfsAccess.Cli.csproj -c $Configuration -r $Runtime --self-contained $SelfContained -o $cliOut

Write-Host "[publish] publishing service (click-run bundle)..."
dotnet publish .\src\ApfsAccess.Service\ApfsAccess.Service.csproj -c $Configuration -r $Runtime --self-contained $bundleSelfContained -o $bundleOut

Write-Host "[publish] publishing tray (click-run bundle)..."
dotnet publish .\src\ApfsAccess.Tray\ApfsAccess.Tray.csproj -c $Configuration -r $Runtime --self-contained $bundleSelfContained -o $bundleOut

Write-Host "[publish] publishing native probe (click-run bundle)..."
dotnet publish .\src\ApfsAccess.NativeProbe\ApfsAccess.NativeProbe.csproj -c $Configuration -r $Runtime --self-contained $bundleSelfContained -o $bundleOut

Write-Host "[publish] publishing CLI (click-run bundle)..."
dotnet publish .\src\ApfsAccess.Cli\ApfsAccess.Cli.csproj -c $Configuration -r $Runtime --self-contained $bundleSelfContained -o $bundleOut

foreach ($publishOutputDir in @($serviceOut, $trayOut, $probeOut, $cliOut, $bundleOut)) {
    $developmentSettings = Join-Path $publishOutputDir "appsettings.Development.json"
    if (Test-Path -LiteralPath $developmentSettings) {
        Remove-Item -LiteralPath $developmentSettings -Force
    }
}

if (-not (Test-Path -LiteralPath $nativeHostExe)) {
    throw "Native fs host was not produced at '$nativeHostExe'. Refusing to create an incomplete package."
}

Write-Host "[publish] including native fs host..."
Copy-Item -LiteralPath $nativeHostExe -Destination (Join-Path $serviceOut "ApfsAccess.FsHost.exe") -Force
Copy-Item -LiteralPath $nativeHostExe -Destination (Join-Path $bundleOut "ApfsAccess.FsHost.exe") -Force

$winfspDoc = Join-Path $repoRoot "docs/winfsp-setup.md"
if (Test-Path -LiteralPath $winfspDoc) {
    Copy-Item -LiteralPath $winfspDoc -Destination (Join-Path $bundleOut "WINFSP_SETUP.md") -Force
}

$bundleScriptsDir = Join-Path $bundleOut "scripts"
New-Item -ItemType Directory -Force -Path $bundleScriptsDir | Out-Null
$bundleScriptNames = @(
    "install_prereqs.ps1"
)
foreach ($scriptName in $bundleScriptNames) {
    $sourcePath = Join-Path $repoRoot "scripts/$scriptName"
    if (Test-Path -LiteralPath $sourcePath) {
        Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $bundleScriptsDir $scriptName) -Force
    }
}

Get-ChildItem -LiteralPath $bundleOut -Filter "*.pdb" -File -Recurse |
    Remove-Item -Force

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
 
@'
APFS Access click-run package

How to run
1) Double-click Run_APFS_Access.bat.
2) Approve the administrator prompt if Windows asks.
3) If a prerequisite is missing, run scripts\install_prereqs.ps1 as administrator.
4) Plug in an APFS drive and use the dashboard or This PC.
5) Eject the APFS volume before unplugging the drive.
6) Right-click the tray icon and choose Quit to stop APFS Access.

Quiet launcher
- Use Run_APFS_Access.bat or Run_APFS_Access_Silent.vbs for normal app startup without a visible terminal.
- Set APFSACCESS_VISIBLE_CONSOLE=1 before running the .bat only when you want troubleshooting output.

Command-line control
- Run ApfsAccess.Cli.exe from this folder for automation or agent control.
- `status` reports the current service and mount health; `list` discovers connected APFS devices and volumes.
- `mount`, `fix`, `eject`, and `quit` issue the same bounded service commands used by the tray app.
- JSON is the default output. Use `--timeout-ms N`, `--volume-id ID`, `--dry-run`, and `--require-admin` as needed.
- Exit code 0 means success; 2 invalid arguments; 3 service unavailable; 4 timeout; 5 operation failure; 6 elevation required.
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
foreach ($legacyPortableExeName in $legacyPortableExeNames) {
    $legacyPortableExe = Join-Path $portableOut $legacyPortableExeName
    if (Test-Path -LiteralPath $legacyPortableExe) {
        Remove-Item -LiteralPath $legacyPortableExe -Force
    }
}

$bootstrapProjectDir = Join-Path $repoRoot "src/ApfsAccess.Bootstrap"
$bootstrapCacheDirs = @(
    (Join-Path $bootstrapProjectDir "bin/$Configuration"),
    (Join-Path $bootstrapProjectDir "obj/$Configuration")
)
foreach ($cacheDir in $bootstrapCacheDirs) {
    if (Test-Path -LiteralPath $cacheDir) {
        Remove-Item -LiteralPath $cacheDir -Recurse -Force
    }
}

dotnet publish .\src\ApfsAccess.Bootstrap\ApfsAccess.Bootstrap.csproj `
    -c $Configuration `
    -r $Runtime `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:PortablePayloadZip="$portablePayloadZip" `
    -o $portableOut

$portableExe = Join-Path $portableOut $portableExeName
if (Test-Path -LiteralPath $portableExe) {
    foreach ($legacyPortableExeName in $legacyPortableExeNames) {
        $legacyRootPortableExe = Join-Path $repoRoot $legacyPortableExeName
        if (Test-Path -LiteralPath $legacyRootPortableExe) {
            Remove-Item -LiteralPath $legacyRootPortableExe -Force
        }
    }

    Copy-Item -LiteralPath $portableExe -Destination (Join-Path $repoRoot $portableExeName) -Force
} else {
    throw "Published portable launcher was not found at '$portableExe'."
}

Write-Host "[publish] done"
Write-Host " service   : $serviceOut"
Write-Host " tray      : $trayOut"
Write-Host " probe     : $probeOut"
Write-Host " cli       : $cliOut"
Write-Host " click-run : $bundleOut"
Write-Host " portable  : $portableOut"
