param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [string]$SourceDir = "",

    [string]$BuildDir = "",

    [string]$OutputDir = "",

    [switch]$SkipIfUnavailable,

    [string]$Generator = "NMake Makefiles"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ([string]::IsNullOrWhiteSpace($SourceDir)) {
    $SourceDir = Join-Path $repoRoot "src-native\ApfsAccess.FsHost"
}

if ([string]::IsNullOrWhiteSpace($BuildDir)) {
    # Use an ASCII-only build path to avoid MSVC/PDB Unicode path issues.
    $BuildDir = "D:\apfsaccess_native\build\$Configuration"
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot "artifacts\native\$Configuration"
}

function Handle-MissingTooling {
    param([string]$Message)
    if ($SkipIfUnavailable) {
        Write-Warning $Message
        return $false
    }

    throw $Message
}

if (!(Test-Path -LiteralPath $SourceDir)) {
    throw "Native host source directory not found: $SourceDir"
}

$cmakeCommand = Get-Command cmake -ErrorAction SilentlyContinue
$cmakeExe = if ($null -ne $cmakeCommand) {
    $cmakeCommand.Source
} elseif (Test-Path -LiteralPath "C:\Program Files\CMake\bin\cmake.exe") {
    "C:\Program Files\CMake\bin\cmake.exe"
} else {
    $null
}

if ([string]::IsNullOrWhiteSpace($cmakeExe)) {
    if (-not (Handle-MissingTooling "cmake is not installed. Install CMake to build ApfsAccess.FsHost.")) {
        return
    }
}

if ($Generator -eq "NMake Makefiles" -and -not (Get-Command nmake -ErrorAction SilentlyContinue)) {
    Write-Warning "nmake was not found in PATH. Falling back to Visual Studio generator."
    $Generator = "Visual Studio 17 2022"
}

New-Item -ItemType Directory -Force -Path $BuildDir, $OutputDir | Out-Null

if (Test-Path -LiteralPath (Join-Path $BuildDir "CMakeCache.txt")) {
    Remove-Item -LiteralPath $BuildDir -Recurse -Force
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
}

Write-Host "[native-build] configuring ApfsAccess.FsHost ($Configuration)..."
$configureArgs = @(
    "-S", $SourceDir,
    "-B", $BuildDir,
    "-G", $Generator
)

if ($Generator -match "NMake|Ninja|Unix Makefiles|MinGW Makefiles") {
    $configureArgs += "-DCMAKE_BUILD_TYPE=$Configuration"
} else {
    $configureArgs += @("-A", "x64")
}

& $cmakeExe @configureArgs
if ($LASTEXITCODE -ne 0) {
    if (-not (Handle-MissingTooling "CMake configure failed for ApfsAccess.FsHost.")) {
        return
    }
}

Write-Host "[native-build] building ApfsAccess.FsHost ($Configuration)..."
& $cmakeExe --build $BuildDir --config $Configuration
if ($LASTEXITCODE -ne 0) {
    if (-not (Handle-MissingTooling "CMake build failed for ApfsAccess.FsHost.")) {
        return
    }
}

$candidatePaths = @(
    (Join-Path $BuildDir "$Configuration\ApfsAccess.FsHost.exe"),
    (Join-Path $BuildDir "ApfsAccess.FsHost.exe")
)

$hostExe = $candidatePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($hostExe)) {
    if (-not (Handle-MissingTooling "ApfsAccess.FsHost.exe was not produced by the build.")) {
        return
    }
}

try {
    Copy-Item -LiteralPath $hostExe -Destination (Join-Path $OutputDir "ApfsAccess.FsHost.exe") -Force
}
catch {
    Write-Warning "ApfsAccess.FsHost.exe could not be copied into the artifacts output directory because the file is locked. The build output is still available at $hostExe."
}

$candidatePdb = [System.IO.Path]::ChangeExtension($hostExe, ".pdb")
if (Test-Path -LiteralPath $candidatePdb) {
    try {
        Copy-Item -LiteralPath $candidatePdb -Destination (Join-Path $OutputDir "ApfsAccess.FsHost.pdb") -Force
    }
    catch {
        Write-Warning "ApfsAccess.FsHost.pdb could not be copied into the artifacts output directory because the file is locked."
    }
}

Write-Host "[native-build] success: $(Join-Path $OutputDir "ApfsAccess.FsHost.exe")"
