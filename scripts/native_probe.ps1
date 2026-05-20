param(
    [string]$DeviceId = "",
    [int]$MaxPhysicalDriveIndex = 8,
    [string]$Configuration = "Release",
    [switch]$AsJson
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$projectPath = Join-Path $repoRoot "src\ApfsAccess.NativeProbe\ApfsAccess.NativeProbe.csproj"
$bundledExeCandidates = @(
    (Join-Path $repoRoot "ApfsAccess.NativeProbe.exe"),
    (Join-Path $repoRoot "artifacts\publish\click-run\ApfsAccess.NativeProbe.exe")
)
$exePath = $bundledExeCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

function Test-RawPhysicalDevicePath {
    param([string]$Value)
    return $Value -match '^(\\\\\.\\PhysicalDrive|\\\\\?\\PhysicalDrive)'
}

$toolArgs = @()
if (-not [string]::IsNullOrWhiteSpace($DeviceId)) {
    $normalizedDeviceId = $DeviceId.Trim()
    if (-not (Test-RawPhysicalDevicePath $normalizedDeviceId) -and
        ($normalizedDeviceId.ToLowerInvariant().EndsWith(".apfs.img") -or
         $normalizedDeviceId.ToLowerInvariant().EndsWith(".img") -or
         $normalizedDeviceId.ToLowerInvariant().EndsWith(".apfs.fixture") -or
         $normalizedDeviceId.ToLowerInvariant().EndsWith(".fixture") -or
         $normalizedDeviceId.ToLowerInvariant().EndsWith(".apfs"))) {
        $normalizedDeviceId = [System.IO.Path]::GetFullPath($normalizedDeviceId)
    }

    $toolArgs += @("--device", $normalizedDeviceId)
}
else {
    $toolArgs += @("--max-physical-drive-index", ([Math]::Max(0, $MaxPhysicalDriveIndex)).ToString())
}
if ($AsJson) {
    $toolArgs += "--as-json"
}

if (Test-Path -LiteralPath $projectPath) {
    $dotnetArgs = @("run", "--project", $projectPath, "-c", $Configuration, "--") + $toolArgs
    $output = & dotnet @dotnetArgs 2>&1 | ForEach-Object { $_.ToString() }
}
elseif ($exePath) {
    $output = & $exePath @toolArgs 2>&1 | ForEach-Object { $_.ToString() }
}
else {
    throw "Native probe executable/project was not found. Expected bundled executable at '$($bundledExeCandidates[0])' or project at '$projectPath'."
}

$text = ($output -join [Environment]::NewLine).Trim()
$exitCode = if ($null -ne $global:LASTEXITCODE) { [int]$global:LASTEXITCODE } else { 0 }
if ($exitCode -ne 0) {
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw "Native probe failed with exit code $exitCode."
    }

    throw $text
}

if ($AsJson) {
    $text
    return
}

if ([string]::IsNullOrWhiteSpace($text)) {
    return
}

$text
