param(
    [Parameter(Mandatory = $true)]
    [string]$ProfileId,

    [string]$VolumeId = "",

    [string]$OutputPath = ".\artifacts\pilot\validation-report.json",

    [switch]$Overwrite
)

$ErrorActionPreference = "Stop"

$resolvedOutputPath = $OutputPath
if ([System.IO.Path]::IsPathRooted($OutputPath)) {
    $resolvedOutputPath = $OutputPath
}
else {
    $resolvedOutputPath = Join-Path (Get-Location).Path $OutputPath
}

if ((Test-Path -LiteralPath $resolvedOutputPath) -and -not $Overwrite) {
    throw "Output file already exists: $resolvedOutputPath (use -Overwrite to replace)"
}

$normalizedProfileId = $ProfileId.Trim()
if ([string]::IsNullOrWhiteSpace($normalizedProfileId)) {
    throw "ProfileId must not be empty."
}

$scenarios = @(
    "CrashFault",
    "CrashStageMatrix",
    "HardwarePilot",
    "HotUnplug",
    "PowerLossReplay",
    "PowerLossVerified",
    "MacOsValidation",
    "MacOsConsistency"
)

$entries = foreach ($scenario in $scenarios) {
    [ordered]@{
        profileId = $normalizedProfileId
        volumeId = if ([string]::IsNullOrWhiteSpace($VolumeId)) { $null } else { $VolumeId.Trim() }
        scenario = $scenario
        passed = $false
        count = 1
        validatedUtc = $null
        notes = "fill after running this scenario"
    }
}

$payload = [ordered]@{
    generatedUtc = [DateTime]::UtcNow.ToString("o")
    profileId = $normalizedProfileId
    results = $entries
}

$parent = Split-Path -Parent $resolvedOutputPath
if (-not [string]::IsNullOrWhiteSpace($parent)) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
}

$payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resolvedOutputPath -Encoding utf8

Write-Host "[new-validation-report] file: $resolvedOutputPath"
Write-Host "[new-validation-report] profile: $normalizedProfileId"
if (-not [string]::IsNullOrWhiteSpace($VolumeId)) {
    Write-Host "[new-validation-report] volume: $($VolumeId.Trim())"
}
