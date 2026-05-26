param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [string]$SourceDir = "",

    [string]$BuildDir = "",

    [string]$OutputDir = "",

    [switch]$SkipIfUnavailable,

    [string]$Generator = "NMake Makefiles",

    [switch]$RunTests
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ([string]::IsNullOrWhiteSpace($SourceDir)) {
    $SourceDir = Join-Path $repoRoot "src-native\ApfsAccess.ApfsRwEngine"
}

if ([string]::IsNullOrWhiteSpace($BuildDir)) {
    $BuildDir = "D:\apfsaccess_native\rw_engine\$Configuration"
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
    if (-not (Handle-MissingTooling "RW engine source directory not found: $SourceDir")) {
        return
    }
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
    if (-not (Handle-MissingTooling "cmake is not installed. Install CMake to build ApfsAccess.ApfsRwEngine.")) {
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

Write-Host "[rw-engine] configuring ApfsAccess.ApfsRwEngine ($Configuration)..."
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
    if (-not (Handle-MissingTooling "CMake configure failed for ApfsAccess.ApfsRwEngine.")) {
        return
    }
}

Write-Host "[rw-engine] building ApfsAccess.ApfsRwEngine ($Configuration)..."
& $cmakeExe --build $BuildDir --config $Configuration
if ($LASTEXITCODE -ne 0) {
    if (-not (Handle-MissingTooling "CMake build failed for ApfsAccess.ApfsRwEngine.")) {
        return
    }
}

$candidatePaths = @(
    (Join-Path $BuildDir "$Configuration\ApfsAccess.ApfsRwEngine.lib"),
    (Join-Path $BuildDir "ApfsAccess.ApfsRwEngine.lib")
)

$libPath = $candidatePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($libPath)) {
    if (-not (Handle-MissingTooling "ApfsAccess.ApfsRwEngine.lib was not produced by the build.")) {
        return
    }
}

Copy-Item -LiteralPath $libPath -Destination (Join-Path $OutputDir "ApfsAccess.ApfsRwEngine.lib") -Force
Write-Host "[rw-engine] success: $(Join-Path $OutputDir "ApfsAccess.ApfsRwEngine.lib")"

if ($RunTests) {
    Write-Host "[rw-engine] running native rw-engine tests..."
    $ctestCommand = Get-Command ctest -ErrorAction SilentlyContinue
    $ctestExe = if ($null -ne $ctestCommand) {
        $ctestCommand.Source
    } elseif (Test-Path -LiteralPath "C:\Program Files\CMake\bin\ctest.exe") {
        "C:\Program Files\CMake\bin\ctest.exe"
    } else {
        $null
    }

    if ([string]::IsNullOrWhiteSpace($ctestExe)) {
        if (-not (Handle-MissingTooling "ctest is not installed. Install CMake test tools to run native rw-engine tests.")) {
            return
        }
    }

    $ctestArgs = @("--test-dir", $BuildDir, "--output-on-failure")
    if (-not ($Generator -match "NMake|Ninja|Unix Makefiles|MinGW Makefiles")) {
        $ctestArgs += @("-C", $Configuration)
    }

    & $ctestExe @ctestArgs
    if ($LASTEXITCODE -ne 0) {
        if (-not (Handle-MissingTooling "Native rw-engine tests failed.")) {
            return
        }
    }
}
