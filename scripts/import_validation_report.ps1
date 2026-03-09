param(
    [Parameter(Mandatory = $true)]
    [string]$ReportPath,

    [string]$EvidenceStorePath = "%ProgramData%\\ApfsAccess\\write-evidence.json",

    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$scenarioMap = @{
    "CrashFault" = "crashFaultPasses"
    "CrashStageMatrix" = "crashStageMatrixPasses"
    "HardwarePilot" = "hardwarePilotPasses"
    "HotUnplug" = "hotUnplugPasses"
    "MacOsValidation" = "macOsValidationPasses"
    "MacOsConsistency" = "macOsConsistencyPasses"
    "PowerLossReplay" = "powerLossReplayPasses"
}

function New-Evidence {
    return [ordered]@{
        crashFaultPasses = 0
        crashStageMatrixPasses = 0
        hardwarePilotPasses = 0
        hotUnplugPasses = 0
        macOsValidationPasses = 0
        macOsConsistencyPasses = 0
        powerLossReplayPasses = 0
        powerLossPassVerified = $false
        lastValidatedUtc = $null
        lastValidationProfileId = $null
    }
}

function Normalize-Evidence {
    param([object]$Value)
    $evidence = New-Evidence
    if ($null -ne $Value) {
        foreach ($k in $evidence.Keys) {
            if ($Value.PSObject.Properties.Name -contains $k) {
                $evidence[$k] = $Value.$k
            }
        }
    }

    foreach ($f in @(
        "crashFaultPasses",
        "crashStageMatrixPasses",
        "hardwarePilotPasses",
        "hotUnplugPasses",
        "macOsValidationPasses",
        "macOsConsistencyPasses",
        "powerLossReplayPasses"))
    {
        $parsed = 0
        if ($null -ne $evidence[$f] -and [int]::TryParse($evidence[$f].ToString(), [ref]$parsed)) {
            $evidence[$f] = [Math]::Max(0, $parsed)
        }
        else {
            $evidence[$f] = 0
        }
    }

    $evidence.powerLossPassVerified = [bool]$evidence.powerLossPassVerified
    if ($null -ne $evidence.lastValidatedUtc) {
        $evidence.lastValidatedUtc = $evidence.lastValidatedUtc.ToString()
    }
    if ($null -ne $evidence.lastValidationProfileId) {
        $evidence.lastValidationProfileId = $evidence.lastValidationProfileId.ToString()
    }
    return $evidence
}

function Read-ReportRecords {
    param([string]$Path)
    $raw = Get-Content -LiteralPath $Path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return @()
    }

    $parsed = $raw | ConvertFrom-Json
    if ($parsed -is [System.Collections.IEnumerable] -and -not ($parsed -is [string])) {
        if ($parsed.PSObject.Properties.Name -contains "results") {
            return @($parsed.results)
        }
        return @($parsed)
    }

    if ($parsed.PSObject.Properties.Name -contains "results") {
        return @($parsed.results)
    }

    return @($parsed)
}

$resolvedStorePath = [Environment]::ExpandEnvironmentVariables($EvidenceStorePath)
$resolvedReportPath = Resolve-Path -LiteralPath $ReportPath | Select-Object -ExpandProperty Path

$storePayload = [ordered]@{
    volumes = [ordered]@{}
    profiles = [ordered]@{}
}

if (Test-Path -LiteralPath $resolvedStorePath) {
    $existingRaw = Get-Content -LiteralPath $resolvedStorePath -Raw
    if (-not [string]::IsNullOrWhiteSpace($existingRaw)) {
        $existing = $existingRaw | ConvertFrom-Json
        if ($existing.PSObject.Properties.Name -contains "volumes" -and $null -ne $existing.volumes) {
            foreach ($p in $existing.volumes.PSObject.Properties) {
                $storePayload.volumes[$p.Name] = Normalize-Evidence $p.Value
            }
        }
        if ($existing.PSObject.Properties.Name -contains "profiles" -and $null -ne $existing.profiles) {
            foreach ($p in $existing.profiles.PSObject.Properties) {
                $storePayload.profiles[$p.Name] = Normalize-Evidence $p.Value
            }
        }
    }
}

$records = Read-ReportRecords -Path $resolvedReportPath
$applied = 0
$skipped = 0

foreach ($record in $records) {
    if ($null -eq $record) {
        continue
    }

    $profileId = if ($record.PSObject.Properties.Name -contains "profileId") { $record.profileId } else { $null }
    $scenario = if ($record.PSObject.Properties.Name -contains "scenario") { $record.scenario } else { $null }
    $passed = if ($record.PSObject.Properties.Name -contains "passed") { [bool]$record.passed } else { $false }
    $volumeId = if ($record.PSObject.Properties.Name -contains "volumeId") { $record.volumeId } else { $null }
    $count = if ($record.PSObject.Properties.Name -contains "count") { $record.count } else { 1 }
    $validatedUtc = if ($record.PSObject.Properties.Name -contains "validatedUtc") { $record.validatedUtc } else { $null }

    if ([string]::IsNullOrWhiteSpace($profileId) -or
        [string]::IsNullOrWhiteSpace($scenario) -or
        -not $passed)
    {
        $skipped++
        continue
    }

    if (-not $scenarioMap.ContainsKey($scenario)) {
        if ($scenario -ne "PowerLossVerified") {
            $skipped++
            continue
        }
    }

    $parsedCount = 1
    if ($null -ne $count -and [int]::TryParse($count.ToString(), [ref]$parsedCount)) {
        $parsedCount = [Math]::Max(1, $parsedCount)
    }

    $normalizedProfileId = $profileId.ToString().Trim()
    $profileEvidence = if ($storePayload.profiles.Contains($normalizedProfileId)) {
        Normalize-Evidence $storePayload.profiles[$normalizedProfileId]
    }
    else {
        New-Evidence
    }

    if ($scenario -eq "PowerLossVerified") {
        $profileEvidence.powerLossPassVerified = $true
    }
    else {
        $targetField = $scenarioMap[$scenario]
        $profileEvidence[$targetField] = [Math]::Max(0, [int]$profileEvidence[$targetField]) + $parsedCount
    }

    $ts = $null
    if ($null -ne $validatedUtc -and -not [string]::IsNullOrWhiteSpace($validatedUtc.ToString())) {
        try {
            $ts = [DateTime]::Parse($validatedUtc.ToString(), [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal).ToUniversalTime().ToString("o")
        }
        catch {
            $ts = $null
        }
    }
    if ($null -eq $ts) {
        $ts = [DateTime]::UtcNow.ToString("o")
    }
    $profileEvidence.lastValidatedUtc = $ts
    $profileEvidence.lastValidationProfileId = $normalizedProfileId
    $storePayload.profiles[$normalizedProfileId] = $profileEvidence

    if ($null -ne $volumeId -and -not [string]::IsNullOrWhiteSpace($volumeId.ToString())) {
        $normalizedVolumeId = $volumeId.ToString().Trim()
        $volumeEvidence = if ($storePayload.volumes.Contains($normalizedVolumeId)) {
            Normalize-Evidence $storePayload.volumes[$normalizedVolumeId]
        }
        else {
            New-Evidence
        }

        foreach ($f in @(
            "crashFaultPasses",
            "crashStageMatrixPasses",
            "hardwarePilotPasses",
            "hotUnplugPasses",
            "macOsValidationPasses",
            "macOsConsistencyPasses",
            "powerLossReplayPasses"))
        {
            $volumeEvidence[$f] = [Math]::Max([int]$volumeEvidence[$f], [int]$profileEvidence[$f])
        }
        $volumeEvidence.powerLossPassVerified = [bool]$volumeEvidence.powerLossPassVerified -or [bool]$profileEvidence.powerLossPassVerified
        $volumeEvidence.lastValidatedUtc = $profileEvidence.lastValidatedUtc
        $volumeEvidence.lastValidationProfileId = $profileEvidence.lastValidationProfileId
        $storePayload.volumes[$normalizedVolumeId] = $volumeEvidence
    }

    $applied++
}

if (-not $DryRun) {
    $parent = Split-Path -Parent $resolvedStorePath
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $storePayload | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $resolvedStorePath -Encoding utf8
}

Write-Host "[import-validation-report] report : $resolvedReportPath"
Write-Host "[import-validation-report] store  : $resolvedStorePath"
Write-Host "[import-validation-report] applied: $applied"
Write-Host "[import-validation-report] skipped: $skipped"
Write-Host "[import-validation-report] dryRun : $($DryRun.IsPresent)"
