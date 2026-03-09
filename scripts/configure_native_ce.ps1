param(
    [Parameter(Mandatory = $true)]
    [string]$ApfsUtilPath,

    [string]$AppSettingsPath = "",

    [string]$NativeFsHostPath = "",

    [string[]]$DeviceCandidates = @(),

    [switch]$AutoDiscoverPhysicalDrives,

    [int]$MaxPhysicalDriveIndex = 8,

    [switch]$UseRelativeBinaryPaths,

    [switch]$EnableNativeWrite,

    [ValidateSet("Disabled", "Pilot", "Enabled")]
    [string]$WriteRolloutChannel = "Disabled",

    [ValidateSet("Conservative", "Balanced", "Aggressive")]
    [string]$WriteSafetyLevel = "Conservative",

    [ValidateSet("Disabled", "Overlay", "Native")]
    [string]$WriteBackendMode = "Disabled",

    [switch]$AllowWriteOnUnsupportedFeatures,

    [int]$WriteCommitTimeoutSeconds = 15,

    [bool]$NativeWriteStrictMode = $true,

    [int]$NativeWriteMaxDirtyTransactions = 128,

    [ValidateSet("FailClosed", "BestEffort")]
    [string]$NativeWriteRecoveryPolicy = "FailClosed",

    [switch]$NativeWriteAllowRawPhysicalDevices,

    [string[]]$NativeWritePilotVolumeAllowList = @(),

    [bool]$NativeWriteIntegrityCheckOnMount = $true,

    [ValidateSet("FailClosed", "ReplayIfSafe")]
    [string]$NativeWriteCrashReplayMode = "FailClosed",

    [bool]$NativeWriteRequireCanonicalCommit = $true,

    [bool]$NativeWriteAllowLegacyScaffoldForFixtures = $true,

    [string[]]$NativeWriteHardwarePilotDeviceAllowList = @(),

    [bool]$NativeWriteRequireMacOsValidationForStable = $true
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ([string]::IsNullOrWhiteSpace($AppSettingsPath)) {
    $AppSettingsPath = Join-Path $repoRoot "artifacts\publish\click-run\appsettings.json"
}

if (!(Test-Path -LiteralPath $ApfsUtilPath)) {
    throw "apfsutil.exe was not found at: $ApfsUtilPath"
}

if (!(Test-Path -LiteralPath $AppSettingsPath)) {
    throw "appsettings.json was not found at: $AppSettingsPath"
}

$json = Get-Content -Path $AppSettingsPath -Raw | ConvertFrom-Json
if ($null -eq $json.Service) {
    $json | Add-Member -MemberType NoteProperty -Name Service -Value ([pscustomobject]@{})
}

$json.Service.BackendMode = "Native"
$resolvedApfsUtil = (Resolve-Path -LiteralPath $ApfsUtilPath).Path
$resolvedNativeHost = if ([string]::IsNullOrWhiteSpace($NativeFsHostPath)) { "" } else { (Resolve-Path -LiteralPath $NativeFsHostPath).Path }

if ($UseRelativeBinaryPaths) {
    $json.Service.NativeApfsUtilPath = [System.IO.Path]::GetFileName($resolvedApfsUtil)
    $json.Service.NativeFsHostPath = if ([string]::IsNullOrWhiteSpace($resolvedNativeHost)) { "" } else { [System.IO.Path]::GetFileName($resolvedNativeHost) }
} else {
    $json.Service.NativeApfsUtilPath = $resolvedApfsUtil
    $json.Service.NativeFsHostPath = $resolvedNativeHost
}
$json.Service.NativeDeviceCandidates = @($DeviceCandidates)
$json.Service.NativeAutoDiscoverPhysicalDrives = [bool]$AutoDiscoverPhysicalDrives
$json.Service.NativeMaxPhysicalDriveIndex = $MaxPhysicalDriveIndex
$json.Service.MountLetterPool = @("D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z")
$json.Service.SkipEncryptedVolumes = $true
$json.Service.NativeHostStartupTimeoutSeconds = 120
$json.Service.ReadWriteMode = "RwWithRoFallback"
$json.Service.EnableNativeWrite = [bool]$EnableNativeWrite
$json.Service.WriteRolloutChannel = $WriteRolloutChannel
$json.Service.WriteSafetyLevel = $WriteSafetyLevel
$json.Service.WriteBackendMode = $WriteBackendMode
$json.Service.AllowWriteOnUnsupportedFeatures = [bool]$AllowWriteOnUnsupportedFeatures
$json.Service.WriteCommitTimeoutSeconds = [Math]::Max(1, $WriteCommitTimeoutSeconds)
$json.Service.NativeWriteStrictMode = $NativeWriteStrictMode
$json.Service.NativeWriteMaxDirtyTransactions = [Math]::Max(1, $NativeWriteMaxDirtyTransactions)
$json.Service.NativeWriteRecoveryPolicy = $NativeWriteRecoveryPolicy
$json.Service.NativeWriteAllowRawPhysicalDevices = [bool]$NativeWriteAllowRawPhysicalDevices
$json.Service.NativeWritePilotVolumeAllowList = @($NativeWritePilotVolumeAllowList)
$json.Service.NativeWriteIntegrityCheckOnMount = [bool]$NativeWriteIntegrityCheckOnMount
$json.Service.NativeWriteCrashReplayMode = $NativeWriteCrashReplayMode
$json.Service.NativeWriteRequireCanonicalCommit = [bool]$NativeWriteRequireCanonicalCommit
$json.Service.NativeWriteAllowLegacyScaffoldForFixtures = [bool]$NativeWriteAllowLegacyScaffoldForFixtures
$json.Service.NativeWriteHardwarePilotDeviceAllowList = @($NativeWriteHardwarePilotDeviceAllowList)
$json.Service.NativeWriteRequireMacOsValidationForStable = [bool]$NativeWriteRequireMacOsValidationForStable

$json | ConvertTo-Json -Depth 10 | Set-Content -Path $AppSettingsPath -Encoding utf8

Write-Host "Configured Native backend in: $AppSettingsPath"
Write-Host "  BackendMode: Native"
Write-Host "  NativeApfsUtilPath: $($json.Service.NativeApfsUtilPath)"
Write-Host "  NativeFsHostPath: $($json.Service.NativeFsHostPath)"
Write-Host "  NativeDeviceCandidates count: $(@($json.Service.NativeDeviceCandidates).Count)"
Write-Host "  NativeAutoDiscoverPhysicalDrives: $($json.Service.NativeAutoDiscoverPhysicalDrives)"
Write-Host "  EnableNativeWrite: $($json.Service.EnableNativeWrite)"
Write-Host "  WriteRolloutChannel: $($json.Service.WriteRolloutChannel)"
Write-Host "  WriteSafetyLevel: $($json.Service.WriteSafetyLevel)"
Write-Host "  WriteBackendMode: $($json.Service.WriteBackendMode)"
Write-Host "  NativeWriteStrictMode: $($json.Service.NativeWriteStrictMode)"
Write-Host "  NativeWriteMaxDirtyTransactions: $($json.Service.NativeWriteMaxDirtyTransactions)"
Write-Host "  NativeWriteRecoveryPolicy: $($json.Service.NativeWriteRecoveryPolicy)"
Write-Host "  NativeWriteAllowRawPhysicalDevices: $($json.Service.NativeWriteAllowRawPhysicalDevices)"
Write-Host "  NativeWritePilotVolumeAllowList count: $(@($json.Service.NativeWritePilotVolumeAllowList).Count)"
Write-Host "  NativeWriteIntegrityCheckOnMount: $($json.Service.NativeWriteIntegrityCheckOnMount)"
Write-Host "  NativeWriteCrashReplayMode: $($json.Service.NativeWriteCrashReplayMode)"
Write-Host "  NativeWriteRequireCanonicalCommit: $($json.Service.NativeWriteRequireCanonicalCommit)"
Write-Host "  NativeWriteAllowLegacyScaffoldForFixtures: $($json.Service.NativeWriteAllowLegacyScaffoldForFixtures)"
Write-Host "  NativeWriteHardwarePilotDeviceAllowList count: $(@($json.Service.NativeWriteHardwarePilotDeviceAllowList).Count)"
Write-Host "  NativeWriteRequireMacOsValidationForStable: $($json.Service.NativeWriteRequireMacOsValidationForStable)"
