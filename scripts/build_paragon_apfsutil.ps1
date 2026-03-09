param(
    [string]$SdkRoot = "",
    [ValidateSet("Debug", "Release")]
    [string]$BuildType = "Release",
    [string]$BuildDir = "",
    [string]$OutputDir = "",
    [string]$Generator = "NMake Makefiles",
    [switch]$SkipIfUnavailable
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ([string]::IsNullOrWhiteSpace($SdkRoot)) {
    $SdkRoot = Join-Path $repoRoot "third_party\paragon_apfs_sdk_ce"
}

if ([string]::IsNullOrWhiteSpace($BuildDir)) {
    # Use an ASCII-only path to avoid MSVC/PDB failures on Unicode workspace roots.
    $BuildDir = "C:\apfsaccess_native\paragon_build\$BuildType"
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot "artifacts\native\$BuildType"
}

function Handle-MissingTooling {
    param([string]$Message)
    if ($SkipIfUnavailable) {
        Write-Warning $Message
        return $false
    }

    throw $Message
}

if (!(Test-Path -LiteralPath $SdkRoot)) {
    throw "SDK root not found: $SdkRoot"
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
    if (-not (Handle-MissingTooling "cmake is not installed. Install CMake first, then rerun this script.")) {
        return
    }
}

if ($Generator -eq "NMake Makefiles" -and -not (Get-Command nmake -ErrorAction SilentlyContinue)) {
    Write-Warning "nmake was not found in PATH. Falling back to Visual Studio generator."
    $Generator = "Visual Studio 17 2022"
}

if (Test-Path -LiteralPath (Join-Path $BuildDir "CMakeCache.txt")) {
    Remove-Item -LiteralPath $BuildDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$configureArgs = @(
    "-S", $SdkRoot,
    "-B", $BuildDir,
    "-G", $Generator,
    "-DCMAKE_POLICY_VERSION_MINIMUM=3.5"
)

if ($Generator -match "NMake|Ninja|Unix Makefiles|MinGW Makefiles") {
    $configureArgs += "-DCMAKE_BUILD_TYPE=$BuildType"
} else {
    $configureArgs += @("-A", "x64")
}

Write-Host "[build] configuring Paragon APFS SDK CE..."
& $cmakeExe @configureArgs
if ($LASTEXITCODE -ne 0) {
    if (-not (Handle-MissingTooling "CMake configure failed for Paragon APFS SDK CE.")) {
        return
    }
}

Write-Host "[build] building apfsutil ($BuildType)..."
& $cmakeExe --build $BuildDir --config $BuildType
if ($LASTEXITCODE -ne 0) {
    if (-not (Handle-MissingTooling "CMake build failed for Paragon APFS SDK CE.")) {
        return
    }
}

$candidateExe = @(
    (Join-Path $BuildDir "bin\apfsutil.exe"),
    (Join-Path $BuildDir "apfsutil.exe"),
    (Join-Path $BuildDir "$BuildType\apfsutil.exe")
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

if ([string]::IsNullOrWhiteSpace($candidateExe)) {
    throw "Build finished but apfsutil.exe was not found under: $BuildDir"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
Copy-Item -LiteralPath $candidateExe -Destination (Join-Path $OutputDir "apfsutil.exe") -Force

Write-Host "[build] success: $candidateExe"
Write-Host "[build] copied to: $(Join-Path $OutputDir "apfsutil.exe")"
