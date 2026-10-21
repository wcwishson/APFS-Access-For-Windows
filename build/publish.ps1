param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64",
    [bool]$SelfContained = $false,
    [string]$SMBLibrarySourceRoot = $env:SMBLibrarySourceRoot
)

$ErrorActionPreference = "Stop"
function Invoke-DotNet {
    & dotnet @args "-p:SMBLibrarySourceRoot=$SMBLibrarySourceRoot" "-p:DebugType=None" "-p:DebugSymbols=false"
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet $($args -join ' ') failed with exit code $LASTEXITCODE."
    }
}
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
Set-Location -LiteralPath $repoRoot
if ([string]::IsNullOrWhiteSpace($SMBLibrarySourceRoot)) {
    throw 'Supply -SMBLibrarySourceRoot with the pinned source described in third_party/SMBLibrary/BUILD.md.'
}
$SMBLibrarySourceRoot = (Resolve-Path -LiteralPath $SMBLibrarySourceRoot).Path
foreach ($name in @('SMBLibrary', 'Utilities')) {
    if (!(Test-Path -LiteralPath (Join-Path $SMBLibrarySourceRoot $name) -PathType Container)) {
        throw 'SMBLibrarySourceRoot must contain the pinned SMBLibrary and Utilities source directories.'
    }
}
if ($Runtime -ne 'win-x64') {
    throw 'The normal native package supports win-x64 only.'
}

function Assert-WorkspaceOutputPath {
    param([string]$Path)
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not $fullPath.StartsWith($repoRoot + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clear output outside the workspace: $fullPath"
    }
    $entry = Get-Item -LiteralPath $fullPath -Force -ErrorAction SilentlyContinue
    while ($null -ne $entry -and $entry.FullName -ne $repoRoot) {
        if ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Refusing to clear linked output: $($entry.FullName)"
        }
        $entry = $entry.Parent
    }
}

$serviceOut = Join-Path $repoRoot "artifacts/publish/service"
$trayOut = Join-Path $repoRoot "artifacts/publish/tray"
$probeOut = Join-Path $repoRoot "artifacts/publish/native-probe"
$cliOut = Join-Path $repoRoot "artifacts/publish/cli"
$updaterOut = Join-Path $repoRoot "artifacts/publish/updater"
$probeDebugSmokeOut = Join-Path $repoRoot "artifacts/publish/native-probe-debug-smoke"
$bundleOut = Join-Path $repoRoot "artifacts/publish/click-run"
$portableOut = Join-Path $repoRoot "artifacts/publish/portable"
$portableExeName = "APFS Access.exe"
$legacyPortableExeNames = @("APFSAccess_Portable.exe", "APFSAccess.Portable.exe")
$portablePayloadZip = Join-Path $repoRoot "artifacts/publish/click-run-payload.zip"
$nativeOut = Join-Path $repoRoot "artifacts/native/$Configuration"
$nativeHostExe = Join-Path $nativeOut "ApfsAccess.FsHost.exe"
$nativeObserverExe = Join-Path $nativeOut "ApfsObserver.exe"
$bundleSelfContained = $true
$nativeBuildRoot = if ([string]::IsNullOrWhiteSpace($env:APFSACCESS_NATIVE_BUILD_ROOT)) {
    Join-Path ([System.IO.Path]::GetTempPath()) "apfsaccess_native"
} else {
    [System.IO.Path]::GetFullPath($env:APFSACCESS_NATIVE_BUILD_ROOT)
}

$publishOutputDirs = @($serviceOut, $trayOut, $probeOut, $cliOut, $updaterOut, $bundleOut, $portableOut)
foreach ($publishOutputDir in $publishOutputDirs) {
    Assert-WorkspaceOutputPath $publishOutputDir
    if (Test-Path -LiteralPath $publishOutputDir) {
        Get-ChildItem -LiteralPath $publishOutputDir -Force |
            Remove-Item -Recurse -Force
    }
}
if (Test-Path -LiteralPath $probeDebugSmokeOut) {
    Assert-WorkspaceOutputPath $probeDebugSmokeOut
    Remove-Item -LiteralPath $probeDebugSmokeOut -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $serviceOut, $trayOut, $probeOut, $cliOut, $bundleOut, $portableOut | Out-Null

Write-Host "[publish] generating tray icons..."
pwsh -NoProfile -File (Join-Path $repoRoot "scripts/create_tray_icons.ps1")
if ($LASTEXITCODE -ne 0) {
    throw "Tray icon generation failed with exit code $LASTEXITCODE."
}

Assert-WorkspaceOutputPath $nativeOut
if (Test-Path -LiteralPath $nativeHostExe) {
    Remove-Item -LiteralPath $nativeHostExe -Force
}
if (Test-Path -LiteralPath $nativeObserverExe) {
    Remove-Item -LiteralPath $nativeObserverExe -Force
}
$nativeToolNames = @(
    "ApfsVolumeRepairTool.exe", "VolumeRenameImage.exe", "SnapshotImage.exe",
    "ApfsEncryptedReadTool.exe", "ApfsFusionReadTool.exe", "ApfsAccess.ApfsImageKeyManagementTool.exe",
    "VolumeQuotaReserveImageTool.exe", "VolumeManagementImage.exe", "VolumeResizeImage.exe", "VolumeFormatImage.exe", "VolumePhysicalObserve.exe", "VolumeKeeperInspect.exe"
)
foreach ($toolName in $nativeToolNames) {
    $toolPath = Join-Path $nativeOut $toolName
    if (Test-Path -LiteralPath $toolPath) {
        Remove-Item -LiteralPath $toolPath -Force
    }
}

Write-Host "[publish] building native fs host..."
$nativeGenerator = if (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\18") {
    "Visual Studio 18 2026"
} else {
    "Visual Studio 17 2022"
}
pwsh -NoProfile -File (Join-Path $repoRoot "scripts/build_native_host.ps1") `
    -Configuration $Configuration `
    -BuildDir (Join-Path $nativeBuildRoot "publish_host_vs/$Configuration") `
    -Generator $nativeGenerator
if ($LASTEXITCODE -ne 0) {
    throw "Native build failed with exit code $LASTEXITCODE. Refusing to reuse old native files."
}

Write-Host "[publish] publishing service (split output)..."
Invoke-DotNet publish .\src\ApfsAccess.Service\ApfsAccess.Service.csproj -c $Configuration -r $Runtime --self-contained $SelfContained -o $serviceOut

Write-Host "[publish] publishing tray (split output)..."
Invoke-DotNet publish .\src\ApfsAccess.Tray\ApfsAccess.Tray.csproj -c $Configuration -r $Runtime --self-contained $SelfContained -o $trayOut

Write-Host "[publish] publishing native probe (split output)..."
Invoke-DotNet publish .\src\ApfsAccess.NativeProbe\ApfsAccess.NativeProbe.csproj -c $Configuration -r $Runtime --self-contained $SelfContained -o $probeOut

Write-Host "[publish] publishing CLI (split output)..."
Invoke-DotNet publish .\src\ApfsAccess.Cli\ApfsAccess.Cli.csproj -c $Configuration -r $Runtime --self-contained $SelfContained -o $cliOut

Write-Host "[publish] publishing updater (split output)..."
Invoke-DotNet publish .\src\ApfsAccess.Updater\ApfsAccess.Updater.csproj -c $Configuration -r $Runtime --self-contained $SelfContained -o $updaterOut

Write-Host "[publish] publishing service (click-run bundle)..."
Invoke-DotNet publish .\src\ApfsAccess.Service\ApfsAccess.Service.csproj -c $Configuration -r $Runtime --self-contained $bundleSelfContained -o $bundleOut

Write-Host "[publish] publishing tray (click-run bundle)..."
Invoke-DotNet publish .\src\ApfsAccess.Tray\ApfsAccess.Tray.csproj -c $Configuration -r $Runtime --self-contained $bundleSelfContained -o $bundleOut

Write-Host "[publish] publishing native probe (click-run bundle)..."
Invoke-DotNet publish .\src\ApfsAccess.NativeProbe\ApfsAccess.NativeProbe.csproj -c $Configuration -r $Runtime --self-contained $bundleSelfContained -o $bundleOut

Write-Host "[publish] publishing CLI (click-run bundle)..."
Invoke-DotNet publish .\src\ApfsAccess.Cli\ApfsAccess.Cli.csproj -c $Configuration -r $Runtime --self-contained $bundleSelfContained -o $bundleOut

Write-Host "[publish] publishing updater (click-run bundle)..."
Invoke-DotNet publish .\src\ApfsAccess.Updater\ApfsAccess.Updater.csproj -c $Configuration -r $Runtime --self-contained $bundleSelfContained -o $bundleOut

foreach ($publishOutputDir in @($serviceOut, $trayOut, $probeOut, $cliOut, $updaterOut, $bundleOut)) {
    $developmentSettings = Join-Path $publishOutputDir "appsettings.Development.json"
    if (Test-Path -LiteralPath $developmentSettings) {
        Remove-Item -LiteralPath $developmentSettings -Force
    }
}

if (-not (Test-Path -LiteralPath $nativeHostExe)) {
    throw "Native fs host was not produced at '$nativeHostExe'. Refusing to create an incomplete package."
}
if (-not (Test-Path -LiteralPath $nativeObserverExe)) {
    throw "Native APFS observer was not produced at '$nativeObserverExe'. Refusing to create an incomplete package."
}

Write-Host "[publish] including native fs host and APFS observer..."
foreach ($destination in @($serviceOut, $probeOut, $cliOut, $bundleOut)) {
    Copy-Item -LiteralPath $nativeHostExe -Destination (Join-Path $destination "ApfsAccess.FsHost.exe") -Force
    Copy-Item -LiteralPath $nativeObserverExe -Destination (Join-Path $destination "ApfsObserver.exe") -Force
}
foreach ($toolName in $nativeToolNames) {
    $toolPath = Join-Path $nativeOut $toolName
    if (-not (Test-Path -LiteralPath $toolPath -PathType Leaf)) {
        throw "Native runtime helper is missing: $toolPath. Refusing to create an incomplete package."
    }
    foreach ($destination in @($serviceOut, $cliOut, $bundleOut)) {
        Copy-Item -LiteralPath $toolPath -Destination (Join-Path $destination $toolName) -Force
    }
}

$winfspDoc = Join-Path $repoRoot "docs/winfsp-setup.md"
foreach ($destination in @($serviceOut, $trayOut, $probeOut, $cliOut, $updaterOut, $bundleOut)) {
    & (Join-Path $PSScriptRoot 'copy_package_notices.ps1') -OutputDirectory $destination `
        -RepositoryDirectory $repoRoot -SMBLibrarySourceRoot $SMBLibrarySourceRoot -Runtime $Runtime `
        -AssetsFiles (Join-Path $repoRoot 'src/ApfsAccess.Service/obj/project.assets.json')
}
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

New physical volumes start read-only. For a supported ordinary, unencrypted
APFS data volume, choose Fix or request read/write from the command line to
enable writes. The app remembers permission for that exact volume. Existing
administrator restrictions and safety checks still apply; unsupported volumes
remain read-only.

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
    Assert-WorkspaceOutputPath $portablePayloadStaging
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
        Assert-WorkspaceOutputPath $cacheDir
        Remove-Item -LiteralPath $cacheDir -Recurse -Force
    }
}

Invoke-DotNet publish .\src\ApfsAccess.Bootstrap\ApfsAccess.Bootstrap.csproj `
    -c $Configuration `
    -r $Runtime `
    --self-contained true `
    "-p:PublishSingleFile=true" `
    "-p:IncludeNativeLibrariesForSelfExtract=true" `
    "-p:PortablePayloadZip=$portablePayloadZip" `
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
Write-Host " updater   : $updaterOut"
Write-Host " click-run : $bundleOut"
Write-Host " portable  : $portableOut"
