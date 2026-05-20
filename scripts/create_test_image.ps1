param(
    [string]$Path = "",
    [ValidateRange(4, 1024)]
    [int]$SizeMiB = 64,
    [switch]$AsJson
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($Path)) {
    $Path = Join-Path $repoRoot "artifacts/test-images/apfsaccess-test.apfs.img"
}

$fullPath = [System.IO.Path]::GetFullPath($Path)
if ($fullPath -match '^(\\\\\.\\PhysicalDrive|\\\\\?\\PhysicalDrive)') {
    throw "Refusing raw physical device path. This helper only creates normal .apfs.img files."
}

if (-not ($fullPath.ToLowerInvariant().EndsWith(".apfs.img") -or $fullPath.ToLowerInvariant().EndsWith(".img"))) {
    throw "Image path must end with .apfs.img or .img."
}

if (Test-Path -LiteralPath $fullPath) {
    throw "Refusing to overwrite existing file: $fullPath"
}

$parent = Split-Path -Parent $fullPath
if (-not [string]::IsNullOrWhiteSpace($parent)) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
}

$probeCandidates = @(
    (Join-Path $repoRoot "ApfsAccess.NativeProbe.exe"),
    (Join-Path $repoRoot "artifacts/publish/click-run/ApfsAccess.NativeProbe.exe")
)
$projectPath = Join-Path $repoRoot "src/ApfsAccess.NativeProbe/ApfsAccess.NativeProbe.csproj"

$probeExe = $probeCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$probeArgs = @("create-test-image", "--path", $fullPath, "--size-mib", $SizeMiB.ToString())
if ($AsJson) {
    $probeArgs += "--as-json"
}

if (Test-Path -LiteralPath $projectPath) {
    & dotnet run --project $projectPath -- @probeArgs
} elseif ($probeExe) {
    & $probeExe @probeArgs
} else {
    throw "Native probe executable/project was not found. Expected bundled executable at '$($probeCandidates[0])' or project at '$projectPath'."
}

exit $LASTEXITCODE
