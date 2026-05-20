param(
    [string]$AppSettingsPath = ".\src\ApfsAccess.Service\appsettings.json",
    [string]$EvidenceStorePath = "",
    [string]$PromotionPolicy = "",
    [string]$ProfileId = "",
    [switch]$AsJson
)

$ErrorActionPreference = "Stop"

function Get-ServiceOptions {
    param([string]$Path)

    $resolved = Resolve-Path -LiteralPath $Path | Select-Object -ExpandProperty Path
    $raw = Get-Content -LiteralPath $resolved -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Appsettings file is empty: $resolved"
    }

    $root = $raw | ConvertFrom-Json
    if ($null -eq $root -or -not ($root.PSObject.Properties.Name -contains "Service")) {
        throw "Missing 'Service' section in appsettings: $resolved"
    }

    return $root.Service
}

function Read-EvidencePayload {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return [ordered]@{ volumes = [ordered]@{}; profiles = [ordered]@{} }
    }

    $raw = Get-Content -LiteralPath $Path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return [ordered]@{ volumes = [ordered]@{}; profiles = [ordered]@{} }
    }

    $parsed = $raw | ConvertFrom-Json
    $payload = [ordered]@{ volumes = [ordered]@{}; profiles = [ordered]@{} }

    if ($parsed.PSObject.Properties.Name -contains "volumes" -and $null -ne $parsed.volumes) {
        foreach ($p in $parsed.volumes.PSObject.Properties) {
            $payload.volumes[$p.Name] = $p.Value
        }
    }
    if ($parsed.PSObject.Properties.Name -contains "profiles" -and $null -ne $parsed.profiles) {
        foreach ($p in $parsed.profiles.PSObject.Properties) {
            $payload.profiles[$p.Name] = $p.Value
        }
    }
    return $payload
}

function To-Int {
    param([object]$Value)

    $n = 0
    if ($null -ne $Value -and [int]::TryParse($Value.ToString(), [ref]$n)) {
        return [Math]::Max(0, $n)
    }
    return 0
}

function To-Bool {
    param([object]$Value)

    if ($null -eq $Value) {
        return $false
    }
    if ($Value -is [bool]) {
        return $Value
    }

    $token = $Value.ToString().Trim()
    if ([string]::IsNullOrWhiteSpace($token)) {
        return $false
    }

    $parsed = $false
    if ([bool]::TryParse($token, [ref]$parsed)) {
        return $parsed
    }
    return $false
}

function Get-OptionInt {
    param(
        [pscustomobject]$Options,
        [string]$Name,
        [int]$DefaultValue
    )

    if ($Options.PSObject.Properties.Name -contains $Name) {
        return To-Int $Options.$Name
    }

    return [Math]::Max(0, $DefaultValue)
}

function Get-OptionBool {
    param(
        [pscustomobject]$Options,
        [string]$Name,
        [bool]$DefaultValue = $false
    )

    if ($Options.PSObject.Properties.Name -contains $Name) {
        return To-Bool $Options.$Name
    }

    return $DefaultValue
}

function Normalize-IsoUtc {
    param([object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    $token = $Value.ToString().Trim()
    if ([string]::IsNullOrWhiteSpace($token)) {
        return $null
    }

    try {
        return [DateTime]::Parse(
            $token,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal
        ).ToUniversalTime()
    }
    catch {
        return $null
    }
}

function Normalize-ProfileToken {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return "unknown"
    }

    $normalized = [System.Text.RegularExpressions.Regex]::Replace(
        $Value.Trim().ToLowerInvariant(),
        "\s+",
        " "
    )

    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return "unknown"
    }

    return $normalized
}

function New-BlankEvidence {
    return [pscustomobject]@{
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

function New-ProfileDescriptor {
    param([string]$Value)

    $trimmed = if ([string]::IsNullOrWhiteSpace($Value)) { "" } else { $Value.Trim() }
    $scope = "unknown"
    $deviceToken = "unknown"
    $volumeToken = "unknown"

    if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
        $parts = $trimmed -split "::", 3
        if ($parts.Count -eq 3) {
            $scope = Normalize-ProfileToken $parts[0]
            $deviceToken = Normalize-ProfileToken $parts[1]
            $volumeToken = Normalize-ProfileToken $parts[2]
        }
    }

    return [pscustomobject]@{
        profileId = $trimmed
        scope = $scope
        deviceToken = $deviceToken
        volumeToken = $volumeToken
        rawPhysical = ($scope -eq "raw")
    }
}

function Test-WriteRolloutEnabled {
    param([string]$Channel)

    if ([string]::IsNullOrWhiteSpace($Channel)) {
        return $false
    }

    return $Channel.Trim().Equals("Pilot", [System.StringComparison]::OrdinalIgnoreCase) -or
           $Channel.Trim().Equals("Enabled", [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-HardwarePilotAllowListed {
    param(
        [object[]]$AllowList,
        [string]$DeviceToken
    )

    foreach ($entry in @($AllowList)) {
        if ($null -eq $entry) {
            continue
        }

        $normalizedEntry = Normalize-ProfileToken $entry.ToString()
        if ($normalizedEntry -eq "unknown") {
            continue
        }

        if ($normalizedEntry.Equals($DeviceToken, [System.StringComparison]::OrdinalIgnoreCase) -or
            $DeviceToken.Contains($normalizedEntry, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Evaluate-ProfileConfiguration {
    param(
        [string]$Policy,
        [pscustomobject]$Profile,
        [pscustomobject]$Options
    )

    $reasons = New-Object System.Collections.Generic.List[string]
    $policyToken = if ([string]::IsNullOrWhiteSpace($Policy)) { "ScaffoldOnly" } else { $Policy.Trim() }
    $writeRolloutChannel = if ($Options.PSObject.Properties.Name -contains "WriteRolloutChannel") {
        [string]$Options.WriteRolloutChannel
    }
    else {
        ""
    }

    if (-not (Get-OptionBool -Options $Options -Name "EnableNativeWrite")) {
        $reasons.Add("NativeWriteDisabled")
    }
    if (-not (Test-WriteRolloutEnabled $writeRolloutChannel)) {
        $reasons.Add("RolloutBlocked")
    }

    $allowListEntries = @(
        if ($Options.PSObject.Properties.Name -contains "NativeWriteHardwarePilotDeviceAllowList" -and
            $null -ne $Options.NativeWriteHardwarePilotDeviceAllowList) {
            $Options.NativeWriteHardwarePilotDeviceAllowList
        }
    )
    $allowListConfigured = ($allowListEntries.Count -gt 0)
    $allowListed = $false

    if ($Profile.rawPhysical) {
        if (-not (Get-OptionBool -Options $Options -Name "NativeWriteAllowRawPhysicalDevices")) {
            $reasons.Add("RawPhysicalWriteBlocked")
        }

        if ($policyToken.Equals("ScaffoldOnly", [System.StringComparison]::OrdinalIgnoreCase)) {
            $reasons.Add("PromotionPolicyBlocked")
        }

        if ($policyToken.Equals("PilotHardware", [System.StringComparison]::OrdinalIgnoreCase) -or
            $policyToken.Equals("Stable", [System.StringComparison]::OrdinalIgnoreCase)) {
            if (-not $allowListConfigured) {
                $reasons.Add("HardwarePilotAllowListMissing")
            }
            else {
                $allowListed = Test-HardwarePilotAllowListed -AllowList $allowListEntries -DeviceToken $Profile.deviceToken
                if (-not $allowListed) {
                    $reasons.Add("HardwarePilotAllowListBlocked")
                }
            }
        }
    }
    elseif ($policyToken.Equals("PilotHardware", [System.StringComparison]::OrdinalIgnoreCase) -or
            $policyToken.Equals("Stable", [System.StringComparison]::OrdinalIgnoreCase)) {
        $reasons.Add("ProfileScopeNotRawPhysical")
    }

    return [pscustomobject]@{
        eligible = ($reasons.Count -eq 0)
        reasons = $reasons.ToArray()
        allowListConfigured = $allowListConfigured
        allowListed = $allowListed
        writeRolloutChannel = $writeRolloutChannel
    }
}

function Evaluate-ProfileEvidence {
    param(
        [string]$Policy,
        [pscustomobject]$Evidence,
        [pscustomobject]$Options
    )

    $reasons = New-Object System.Collections.Generic.List[string]
    $isRaw = $true
    $maxAge = Get-OptionInt -Options $Options -Name "NativeWriteValidationEvidenceMaxAgeDays" -DefaultValue 30
    $lastValidatedUtc = Normalize-IsoUtc $Evidence.lastValidatedUtc
    $stale = $false
    if ($isRaw -and $maxAge -gt 0) {
        if ($null -eq $lastValidatedUtc) {
            $stale = $true
        }
        else {
            $stale = (([DateTime]::UtcNow - $lastValidatedUtc) -gt [TimeSpan]::FromDays($maxAge))
        }
    }

    if ($stale) {
        $reasons.Add("ValidationEvidenceStale")
    }

    $crashRequired = Get-OptionInt -Options $Options -Name "NativeWriteMinCrashFaultPasses" -DefaultValue 1
    $crashMatrixRequired = Get-OptionInt -Options $Options -Name "NativeWriteMinCrashStageMatrixPasses" -DefaultValue 1
    $hardwareRequired = Get-OptionInt -Options $Options -Name "NativeWriteMinHardwarePilotPasses" -DefaultValue 3
    $hotUnplugRequired = Get-OptionInt -Options $Options -Name "NativeWriteMinHotUnplugPasses" -DefaultValue 1
    $macRequired = Get-OptionInt -Options $Options -Name "NativeWriteMinMacOsValidationPasses" -DefaultValue 2
    $macConsistencyRequired = Get-OptionInt -Options $Options -Name "NativeWriteMinMacOsConsistencyPasses" -DefaultValue 2
    $powerReplayRequired = Get-OptionInt -Options $Options -Name "NativeWriteMinPowerLossReplayPasses" -DefaultValue 1

    $crash = To-Int $Evidence.crashFaultPasses
    $crashMatrix = To-Int $Evidence.crashStageMatrixPasses
    $hardware = To-Int $Evidence.hardwarePilotPasses
    $hotUnplug = To-Int $Evidence.hotUnplugPasses
    $mac = To-Int $Evidence.macOsValidationPasses
    $macConsistency = To-Int $Evidence.macOsConsistencyPasses
    $powerReplay = To-Int $Evidence.powerLossReplayPasses
    $powerPass = To-Bool $Evidence.powerLossPassVerified

    $requiresCrashMatrix = Get-OptionBool -Options $Options -Name "NativeWriteCrashFaultMatrixRequired" -DefaultValue $true
    $requiresCrossOs = Get-OptionBool -Options $Options -Name "NativeWriteCrossOsValidationRequired" -DefaultValue $true
    $requiresMacOsForStable = Get-OptionBool -Options $Options -Name "NativeWriteRequireMacOsValidationForStable" -DefaultValue $true
    $requiresPowerLoss = Get-OptionBool -Options $Options -Name "NativeWriteStableRequiresPowerLossPass" -DefaultValue $true

    if ($Policy -eq "PilotHardware" -or $Policy -eq "Stable") {
        if ($requiresCrashMatrix -and $crash -lt $crashRequired) {
            $reasons.Add("ValidationCrashFaultEvidenceInsufficient")
        }
        if ($crashMatrix -lt $crashMatrixRequired) {
            $reasons.Add("ValidationCrashStageMatrixEvidenceInsufficient")
        }
        if ($hardware -lt $hardwareRequired) {
            $reasons.Add("ValidationHardwarePilotEvidenceInsufficient")
        }
        if ($hotUnplug -lt $hotUnplugRequired) {
            $reasons.Add("ValidationHotUnplugEvidenceInsufficient")
        }
    }

    if ($Policy -eq "Stable") {
        if ($requiresCrossOs -and $mac -lt $macRequired) {
            $reasons.Add("ValidationCrossOsEvidenceInsufficient")
        }
        if ($macConsistency -lt $macConsistencyRequired) {
            $reasons.Add("ValidationMacOsConsistencyEvidenceInsufficient")
        }
        if ($requiresMacOsForStable -and $mac -lt $macRequired) {
            $reasons.Add("ValidationMacOsEvidenceInsufficient")
        }
        if ($requiresPowerLoss -and $powerReplay -lt $powerReplayRequired) {
            $reasons.Add("ValidationPowerLossReplayEvidenceInsufficient")
        }
        if ($requiresPowerLoss -and -not $powerPass) {
            $reasons.Add("ValidationPowerLossEvidenceInsufficient")
        }
    }

    return [pscustomobject]@{
        eligible = ($reasons.Count -eq 0)
        reasons = $reasons.ToArray()
        metrics = [ordered]@{
            crash = "$crash/$crashRequired"
            crashMatrix = "$crashMatrix/$crashMatrixRequired"
            hardware = "$hardware/$hardwareRequired"
            hotUnplug = "$hotUnplug/$hotUnplugRequired"
            macos = "$mac/$macRequired"
            macosConsistency = "$macConsistency/$macConsistencyRequired"
            powerLossReplay = "$powerReplay/$powerReplayRequired"
            powerLoss = "$powerPass/$requiresPowerLoss"
            stale = $stale
            lastValidatedUtc = if ($lastValidatedUtc) { $lastValidatedUtc.ToString("o") } else { "n/a" }
            lastValidationProfileId = if ($Evidence.lastValidationProfileId) { $Evidence.lastValidationProfileId } else { "n/a" }
        }
    }
}

$serviceOptions = Get-ServiceOptions -Path $AppSettingsPath
$effectivePolicy = if ([string]::IsNullOrWhiteSpace($PromotionPolicy)) {
    if ($serviceOptions.PSObject.Properties.Name -contains "NativeWritePromotionPolicy" -and
        -not [string]::IsNullOrWhiteSpace($serviceOptions.NativeWritePromotionPolicy)) {
        $serviceOptions.NativeWritePromotionPolicy.Trim()
    }
    else {
        "ScaffoldOnly"
    }
}
else {
    $PromotionPolicy.Trim()
}

$storePath = if ([string]::IsNullOrWhiteSpace($EvidenceStorePath)) {
    if ($serviceOptions.PSObject.Properties.Name -contains "NativeWriteEvidenceStorePath" -and
        -not [string]::IsNullOrWhiteSpace($serviceOptions.NativeWriteEvidenceStorePath)) {
        [Environment]::ExpandEnvironmentVariables($serviceOptions.NativeWriteEvidenceStorePath)
    }
    else {
        [Environment]::ExpandEnvironmentVariables("%ProgramData%\\ApfsAccess\\write-evidence.json")
    }
}
else {
    [Environment]::ExpandEnvironmentVariables($EvidenceStorePath)
}

$payload = Read-EvidencePayload -Path $storePath
$profiles = @()
foreach ($entry in $payload.profiles.GetEnumerator()) {
    $profiles += [pscustomobject]@{
        profileId = $entry.Key
        evidence = $entry.Value
    }
}

$normalizedProfileFilter = if ([string]::IsNullOrWhiteSpace($ProfileId)) { $null } else { $ProfileId.Trim() }
if ($null -ne $normalizedProfileFilter) {
    $profiles = @($profiles | Where-Object { $_.profileId -ieq $normalizedProfileFilter })
    if ($profiles.Count -eq 0) {
        $profiles = @([pscustomobject]@{
            profileId = $normalizedProfileFilter
            evidence = New-BlankEvidence
        })
    }
}

$results = @()
foreach ($profile in $profiles) {
    $descriptor = New-ProfileDescriptor -Value $profile.profileId
    $configEval = Evaluate-ProfileConfiguration -Policy $effectivePolicy -Profile $descriptor -Options $serviceOptions
    $evidenceEval = Evaluate-ProfileEvidence -Policy $effectivePolicy -Evidence $profile.evidence -Options $serviceOptions

    $allReasons = @()
    $allReasons += $configEval.reasons
    $allReasons += $evidenceEval.reasons
    $allReasons = @(
        $allReasons |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )

    $results += [pscustomobject]@{
        profileId = $profile.profileId
        scope = $descriptor.scope
        deviceToken = $descriptor.deviceToken
        volumeToken = $descriptor.volumeToken
        rawPhysical = $descriptor.rawPhysical
        configEligible = $configEval.eligible
        evidenceEligible = $evidenceEval.eligible
        eligible = ($configEval.eligible -and $evidenceEval.eligible)
        configReasons = $configEval.reasons
        reasons = $allReasons
        allowListConfigured = $configEval.allowListConfigured
        allowListed = $configEval.allowListed
        writeRolloutChannel = $configEval.writeRolloutChannel
        metrics = $evidenceEval.metrics
    }
}

$report = [pscustomobject]@{
    generatedUtc = [DateTime]::UtcNow.ToString("o")
    policy = $effectivePolicy
    evidenceStore = $storePath
    profileFilter = $normalizedProfileFilter
    results = $results
    summary = [pscustomobject]@{
        totalProfiles = $results.Count
        rawProfiles = @($results | Where-Object { $_.rawPhysical }).Count
        eligibleProfiles = @($results | Where-Object { $_.eligible }).Count
        blockedProfiles = @($results | Where-Object { -not $_.eligible }).Count
    }
}

if ($AsJson) {
    $report | ConvertTo-Json -Depth 10
    exit 0
}

Write-Host "[evaluate-write-promotion] policy: $effectivePolicy"
Write-Host "[evaluate-write-promotion] evidence store: $storePath"
if ($null -ne $normalizedProfileFilter) {
    Write-Host "[evaluate-write-promotion] profile filter: $normalizedProfileFilter"
}

if ($results.Count -eq 0) {
    Write-Host "[evaluate-write-promotion] no profile evidence records found."
    exit 0
}

foreach ($result in $results) {
    Write-Host ""
    Write-Host "Profile: $($result.profileId)"
    Write-Host "Eligible: $($result.eligible)"
    Write-Host "Config eligible: $($result.configEligible)"
    if ($result.configReasons.Count -gt 0) {
        Write-Host "Config reasons: $($result.configReasons -join ', ')"
    }
    else {
        Write-Host "Config reasons: none"
    }
    Write-Host "Allow-list: configured=$($result.allowListConfigured), allowListed=$($result.allowListed)"
    Write-Host "Evidence eligible: $($result.evidenceEligible)"
    if ($result.reasons.Count -gt 0) {
        Write-Host "Reasons: $($result.reasons -join ', ')"
    }
    else {
        Write-Host "Reasons: none"
    }
    $m = $result.metrics
    Write-Host "Metrics: crash=$($m.crash), crashMatrix=$($m.crashMatrix), hardware=$($m.hardware), hotUnplug=$($m.hotUnplug), macos=$($m.macos), macosConsistency=$($m.macosConsistency), powerLossReplay=$($m.powerLossReplay), powerLoss=$($m.powerLoss), stale=$($m.stale), lastValidatedUtc=$($m.lastValidatedUtc)"
}
