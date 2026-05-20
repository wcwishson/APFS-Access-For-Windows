param(
    [Parameter(Mandatory = $true)]
    [string]$ProfileId,

    [string[]]$Scenario = @(),

    [ValidateRange(1, 1000)]
    [int]$Count = 1,

    [string]$VolumeId = "",

    [string]$EvidenceStorePath = "%ProgramData%\\ApfsAccess\\write-evidence.json",

    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function New-EvidenceRecord {
    return @{
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

function ConvertTo-EvidenceRecord {
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]$InputObject
    )

    $record = New-EvidenceRecord
    if ($null -eq $InputObject) {
        return $record
    }

    foreach ($name in @($record.Keys)) {
        if ($InputObject -is [System.Collections.IDictionary] -and $InputObject.Contains($name)) {
            $record[$name] = $InputObject[$name]
        }
        elseif ($InputObject.PSObject.Properties.Name -contains $name) {
            $record[$name] = $InputObject.$name
        }
    }

    $intFields = @(
        "crashFaultPasses",
        "crashStageMatrixPasses",
        "hardwarePilotPasses",
        "hotUnplugPasses",
        "macOsValidationPasses",
        "macOsConsistencyPasses",
        "powerLossReplayPasses"
    )
    foreach ($field in $intFields) {
        $value = 0
        if ($null -ne $record[$field] -and [int]::TryParse($record[$field].ToString(), [ref]$value)) {
            $record[$field] = [Math]::Max(0, $value)
        }
        else {
            $record[$field] = 0
        }
    }

    $record.powerLossPassVerified = [bool]$record.powerLossPassVerified
    if ($null -eq $record.lastValidatedUtc) {
        $record.lastValidatedUtc = $null
    }
    else {
        $record.lastValidatedUtc = $record.lastValidatedUtc.ToString()
    }
    if ($null -eq $record.lastValidationProfileId) {
        $record.lastValidationProfileId = $null
    }
    else {
        $record.lastValidationProfileId = $record.lastValidationProfileId.ToString()
    }

    return $record
}

function Apply-Scenario {
    param(
        [hashtable]$Record,
        [string]$Name,
        [int]$Delta
    )

    switch ($Name) {
        "CrashFault" { $Record.crashFaultPasses += $Delta; break }
        "CrashStageMatrix" { $Record.crashStageMatrixPasses += $Delta; break }
        "HardwarePilot" { $Record.hardwarePilotPasses += $Delta; break }
        "HotUnplug" { $Record.hotUnplugPasses += $Delta; break }
        "MacOsValidation" { $Record.macOsValidationPasses += $Delta; break }
        "MacOsConsistency" { $Record.macOsConsistencyPasses += $Delta; break }
        "PowerLossReplay" { $Record.powerLossReplayPasses += $Delta; break }
        "PowerLossVerified" { $Record.powerLossPassVerified = $true; break }
    }
}

function Expand-ScenarioList {
    param([string[]]$Values)

    $allowed = @(
        "CrashFault",
        "CrashStageMatrix",
        "HardwarePilot",
        "HotUnplug",
        "MacOsValidation",
        "MacOsConsistency",
        "PowerLossReplay",
        "PowerLossVerified"
    )
    $expanded = New-Object System.Collections.Generic.List[string]
    foreach ($value in @($Values)) {
        if ($null -eq $value) {
            continue
        }

        foreach ($token in ($value -split ",")) {
            $trimmed = $token.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                continue
            }

            if ($allowed -notcontains $trimmed) {
                throw "Invalid scenario '$trimmed'. Valid values: $($allowed -join ', ')"
            }

            $expanded.Add($trimmed)
        }
    }

    return $expanded.ToArray()
}

$path = [Environment]::ExpandEnvironmentVariables($EvidenceStorePath)
if ([string]::IsNullOrWhiteSpace($path)) {
    throw "EvidenceStorePath resolved to an empty value."
}

$payload = @{
    volumes = @{}
    profiles = @{}
}

if (Test-Path -LiteralPath $path) {
    $raw = Get-Content -LiteralPath $path -Raw
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
        $parsed = $raw | ConvertFrom-Json
        if ($null -ne $parsed -and $parsed.PSObject.Properties.Name -contains "volumes" -and $null -ne $parsed.volumes) {
            foreach ($property in $parsed.volumes.PSObject.Properties) {
                $payload.volumes[$property.Name] = ConvertTo-EvidenceRecord $property.Value
            }
        }
        if ($null -ne $parsed -and $parsed.PSObject.Properties.Name -contains "profiles" -and $null -ne $parsed.profiles) {
            foreach ($property in $parsed.profiles.PSObject.Properties) {
                $payload.profiles[$property.Name] = ConvertTo-EvidenceRecord $property.Value
            }
        }
    }
}

$normalizedProfileId = $ProfileId.Trim()
if ([string]::IsNullOrWhiteSpace($normalizedProfileId)) {
    throw "ProfileId must not be empty."
}
$normalizedScenarios = Expand-ScenarioList -Values $Scenario

$profileRecord = if ($payload.profiles.ContainsKey($normalizedProfileId)) {
    ConvertTo-EvidenceRecord $payload.profiles[$normalizedProfileId]
}
else {
    New-EvidenceRecord
}

foreach ($item in $normalizedScenarios) {
    Apply-Scenario -Record $profileRecord -Name $item -Delta $Count
}

$now = [DateTime]::UtcNow.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
$profileRecord.lastValidatedUtc = $now
$profileRecord.lastValidationProfileId = $normalizedProfileId
$payload.profiles[$normalizedProfileId] = $profileRecord

if (-not [string]::IsNullOrWhiteSpace($VolumeId)) {
    $normalizedVolumeId = $VolumeId.Trim()
    $volumeRecord = if ($payload.volumes.ContainsKey($normalizedVolumeId)) {
        ConvertTo-EvidenceRecord $payload.volumes[$normalizedVolumeId]
    }
    else {
        New-EvidenceRecord
    }

    $counterFields = @(
        "crashFaultPasses",
        "crashStageMatrixPasses",
        "hardwarePilotPasses",
        "hotUnplugPasses",
        "macOsValidationPasses",
        "macOsConsistencyPasses",
        "powerLossReplayPasses"
    )
    foreach ($field in $counterFields) {
        $volumeRecord[$field] = [Math]::Max([int]$volumeRecord[$field], [int]$profileRecord[$field])
    }
    $volumeRecord.powerLossPassVerified = [bool]$volumeRecord.powerLossPassVerified -or [bool]$profileRecord.powerLossPassVerified
    $volumeRecord.lastValidatedUtc = $profileRecord.lastValidatedUtc
    $volumeRecord.lastValidationProfileId = $profileRecord.lastValidationProfileId
    $payload.volumes[$normalizedVolumeId] = $volumeRecord
}

$json = $payload | ConvertTo-Json -Depth 8
if (-not $DryRun) {
    $dir = Split-Path -Parent $path
    if (-not [string]::IsNullOrWhiteSpace($dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    Set-Content -LiteralPath $path -Value $json -Encoding utf8
}

Write-Host "[write-evidence] path      : $path"
Write-Host "[write-evidence] profile   : $normalizedProfileId"
Write-Host "[write-evidence] scenarios : $($normalizedScenarios -join ',')"
Write-Host "[write-evidence] count     : $Count"
if (-not [string]::IsNullOrWhiteSpace($VolumeId)) {
    Write-Host "[write-evidence] volume    : $($VolumeId.Trim())"
}
Write-Host "[write-evidence] dry-run   : $($DryRun.IsPresent)"
