param(
    [string]$BundleRoot = "",
    [string]$DeviceId = "",
    [string]$VolumeName = "",
    [int]$DeviceDiscoveryTimeoutSeconds = 45,
    [int]$MountTimeoutSeconds = 120,
    [int]$RemountTimeoutSeconds = 120,
    [bool]$UseBootstrapEvidence = $false,
    [switch]$AllowDestructiveWriteSmoke,
    [int]$ReadOnlySampleFileLimit = 2048,
    [UInt64]$ReadOnlyCopyByteLimit = 1GB,
    [switch]$SkipReadOnlyCopy,
    [switch]$KeepMounted,
    [switch]$KeepConfiguredAppSettings
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Info {
    param([string]$Message)
    Write-Host "[pilot] $Message"
}

function Normalize-Token {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return "unknown"
    }

    return [regex]::Replace($Value.Trim().ToLowerInvariant(), "\s+", " ")
}

function Normalize-MountPoint {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }

    $trimmed = $Path.Trim()
    if ($trimmed.Length -ge 2 -and $trimmed[1] -eq ":") {
        return ($trimmed.Substring(0, 2).ToUpperInvariant() + "\")
    }

    return $trimmed
}

function ConvertTo-PrettyJson {
    param([object]$InputObject)
    $InputObject | ConvertTo-Json -Depth 20
}

function Write-JsonFile {
    param(
        [string]$Path,
        [object]$InputObject
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }

    ConvertTo-PrettyJson -InputObject $InputObject | Set-Content -LiteralPath $Path -Encoding utf8
}

function Resolve-AppRoot {
    param([string]$RequestedRoot)

    if (-not [string]::IsNullOrWhiteSpace($RequestedRoot)) {
        $resolved = (Resolve-Path -LiteralPath $RequestedRoot).Path
        if (Test-Path -LiteralPath (Join-Path $resolved "ApfsAccess.Tray.exe")) {
            return $resolved
        }

        throw "Bundle root does not contain ApfsAccess.Tray.exe: $resolved"
    }

    $directCandidate = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
    if (Test-Path -LiteralPath (Join-Path $directCandidate "ApfsAccess.Tray.exe")) {
        return $directCandidate
    }

    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
    $publishedCandidate = Join-Path $repoRoot "artifacts\publish\click-run"
    if (Test-Path -LiteralPath (Join-Path $publishedCandidate "ApfsAccess.Tray.exe")) {
        return $publishedCandidate
    }

    throw "APFS Access click-run bundle was not found. Build it first with scripts/build_beta_pilot.ps1 or build/publish.ps1."
}

function Assert-PathExists {
    param(
        [string]$Path,
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Description was not found: $Path"
    }
}

function Convert-SizeLabel {
    param([UInt64]$Bytes)

    if ($Bytes -lt 1GB) {
        return "{0:n0} MB" -f ($Bytes / 1MB)
    }

    return "{0:n2} GB" -f ($Bytes / 1GB)
}

function Get-DiskInventory {
    try {
        return @(Get-Disk | Sort-Object Number)
    }
    catch {
        $fallback = @()
        for ($index = 0; $index -le 8; $index++) {
            $fallback += [pscustomobject]@{
                Number = $index
                FriendlyName = "PhysicalDrive$index"
                SerialNumber = ""
                BusType = "Unknown"
                Size = 0
            }
        }
        return $fallback
    }
}

function Get-PhysicalDriveNumber {
    param([string]$DeviceId)

    if ([string]::IsNullOrWhiteSpace($DeviceId)) {
        return $null
    }

    $match = [regex]::Match($DeviceId.Trim(), '(?i)physicaldrive(?<number>\d+)$')
    if (-not $match.Success) {
        return $null
    }

    [int]$match.Groups['number'].Value
}

function Invoke-NativeProbe {
    param(
        [string]$ProbeScriptPath,
        [string]$DeviceId,
        [int]$MaxPhysicalDriveIndex
    )

    if (-not [string]::IsNullOrWhiteSpace($DeviceId)) {
        $json = (& $ProbeScriptPath -DeviceId $DeviceId.Trim() -AsJson | Out-String).Trim()
    }
    else {
        $json = (& $ProbeScriptPath -MaxPhysicalDriveIndex ([Math]::Max(0, $MaxPhysicalDriveIndex)) -AsJson | Out-String).Trim()
    }
    if ([string]::IsNullOrWhiteSpace($json)) {
        throw "Native probe returned no JSON."
    }

    [pscustomobject]@{
        RawJson = $json
        Payload = $json | ConvertFrom-Json -Depth 20
    }
}

function Get-ApfsDevices {
    param(
        [string]$ProbeScriptPath,
        [int]$DiscoveryTimeoutSeconds,
        [string]$RequestedDeviceId = ""
    )

    $deadline = (Get-Date).AddSeconds([Math]::Max(1, $DiscoveryTimeoutSeconds))
    do {
        $diskInventory = @(Get-DiskInventory)
        $maxDiskNumber = 8
        if ($diskInventory.Count -gt 0) {
            $measuredMax = ($diskInventory | Measure-Object -Property Number -Maximum).Maximum
            if ($null -ne $measuredMax) {
                $maxDiskNumber = [Math]::Max(0, [int]$measuredMax)
            }
        }

        $probe = Invoke-NativeProbe -ProbeScriptPath $ProbeScriptPath -DeviceId $RequestedDeviceId -MaxPhysicalDriveIndex $maxDiskNumber
        $devices = New-Object System.Collections.Generic.List[object]
        foreach ($device in @($probe.Payload.devices)) {
            $diskNumber = Get-PhysicalDriveNumber -DeviceId ([string]$device.deviceId)
            $disk = $null
            if ($null -ne $diskNumber) {
                $disk = @($diskInventory | Where-Object { [int]$_.Number -eq $diskNumber } | Select-Object -First 1)
                if ($disk.Count -gt 0) {
                    $disk = $disk[0]
                }
                else {
                    $disk = $null
                }
            }

            $sizeBytes = if ($null -ne $disk -and $disk.PSObject.Properties.Name -contains "Size") {
                [UInt64]$disk.Size
            }
            else {
                [UInt64]0
            }

            $friendlyName = if ($null -ne $disk -and $disk.PSObject.Properties.Name -contains "FriendlyName" -and -not [string]::IsNullOrWhiteSpace([string]$disk.FriendlyName)) {
                [string]$disk.FriendlyName
            }
            elseif ($device.PSObject.Properties.Name -contains "displayName" -and -not [string]::IsNullOrWhiteSpace([string]$device.displayName)) {
                [string]$device.displayName
            }
            elseif ($null -ne $diskNumber) {
                "PhysicalDrive$diskNumber"
            }
            else {
                [string]$device.deviceId
            }

            $devices.Add([pscustomobject]@{
                DiskNumber = if ($null -ne $diskNumber) { [int]$diskNumber } else { -1 }
                DeviceId = [string]$device.deviceId
                FriendlyName = $friendlyName
                SerialNumber = if ($null -ne $disk -and $disk.PSObject.Properties.Name -contains "SerialNumber") { [string]$disk.SerialNumber } else { "" }
                BusType = if ($null -ne $disk -and $disk.PSObject.Properties.Name -contains "BusType") { [string]$disk.BusType } else { "Unknown" }
                SizeBytes = $sizeBytes
                SizeLabel = Convert-SizeLabel -Bytes $sizeBytes
                Volumes = @($device.volumes)
                ProbeOutput = (ConvertTo-PrettyJson -InputObject $device)
            })
        }

        if ($devices.Count -gt 0) {
            return @($devices | Sort-Object DeviceId)
        }

        if ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 2
        }
    }
    while ((Get-Date) -lt $deadline)

    @()
}

function Get-ApfsVolumes {
    param([pscustomobject]$ResolvedDevice)

    $volumes = @(
        foreach ($volume in @($ResolvedDevice.Volumes)) {
            $volumeName = [string]$volume.volumeName
            [pscustomobject]@{
                VolumeName = $volumeName
                VolumeId = [string]$volume.volumeId
                ProfileId = if ($volume.PSObject.Properties.Name -contains "profileId" -and -not [string]::IsNullOrWhiteSpace([string]$volume.profileId)) {
                    [string]$volume.profileId
                }
                else {
                    "raw::$(Normalize-Token $ResolvedDevice.DeviceId)::$(Normalize-Token $volumeName)"
                }
                SupportsReadWrite = [bool]$volume.supportsReadWrite
                SupportsNativeWrite = [bool]$volume.supportsNativeWrite
                NativeWriteReadiness = [string]$volume.nativeWriteReadiness
                WriteBlockReason = if ($volume.PSObject.Properties.Name -contains "writeBlockReason") { [string]$volume.writeBlockReason } else { "" }
                WriteIncompatibilities = if ($volume.PSObject.Properties.Name -contains "writeIncompatibilities") { @($volume.writeIncompatibilities) } else { @() }
                WriteUnsupportedFeatures = if ($volume.PSObject.Properties.Name -contains "writeUnsupportedFeatures") { @($volume.writeUnsupportedFeatures) } else { @() }
            }
        }
    )

    [pscustomobject]@{
        Volumes = $volumes
        ProbeOutput = ConvertTo-PrettyJson -InputObject ([ordered]@{
            deviceId = $ResolvedDevice.DeviceId
            volumes = $volumes
        })
    }
}

function Select-ListItem {
    param(
        [object[]]$Items,
        [string]$Prompt,
        [scriptblock]$RenderItem
    )

    if ($Items.Count -eq 0) {
        throw "No selectable items were provided."
    }

    if ($Items.Count -eq 1) {
        return $Items[0]
    }

    for ($index = 0; $index -lt $Items.Count; $index++) {
        Write-Host ("  [{0}] {1}" -f ($index + 1), (& $RenderItem $Items[$index]))
    }

    while ($true) {
        $rawSelection = Read-Host $Prompt
        $selection = 0
        if ([int]::TryParse($rawSelection, [ref]$selection) -and $selection -ge 1 -and $selection -le $Items.Count) {
            return $Items[$selection - 1]
        }

        Write-Warning "Please enter a number between 1 and $($Items.Count)."
    }
}

function Get-DriveRoots {
    @(Get-PSDrive -PSProvider FileSystem | ForEach-Object { Normalize-MountPoint $_.Root } | Sort-Object -Unique)
}

function Get-DriveLabel {
    param([string]$MountPoint)

    $normalized = Normalize-MountPoint $MountPoint
    if ([string]::IsNullOrWhiteSpace($normalized) -or $normalized.Length -lt 2) {
        return ""
    }

    $driveLetter = $normalized.Substring(0, 1)
    try {
        $volume = Get-Volume -DriveLetter $driveLetter -ErrorAction Stop
        if ($null -ne $volume -and -not [string]::IsNullOrWhiteSpace([string]$volume.FileSystemLabel)) {
            return [string]$volume.FileSystemLabel
        }
    }
    catch {
    }

    ""
}

function Resolve-MountPointFromStatus {
    param(
        [object]$Status,
        [string[]]$BaselineRoots,
        [string]$PreferredVolumeName
    )

    $mountPoints = @()
    if ($null -ne $Status -and $Status.PSObject.Properties.Name -contains "mountPoints") {
        $mountPoints = @($Status.mountPoints | ForEach-Object { Normalize-MountPoint $_ })
    }

    $mountPoints = @($mountPoints | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    if ($mountPoints.Count -eq 0) {
        return ""
    }

    $newRoots = @($mountPoints | Where-Object { $_ -notin $BaselineRoots })
    $candidates = @(if ($newRoots.Count -gt 0) { $newRoots } else { $mountPoints })

    if ($candidates.Count -eq 1) {
        return $candidates[0]
    }

    if (-not [string]::IsNullOrWhiteSpace($PreferredVolumeName)) {
        foreach ($candidate in $candidates) {
            $label = Get-DriveLabel -MountPoint $candidate
            if ((Normalize-Token $label) -eq (Normalize-Token $PreferredVolumeName)) {
                return $candidate
            }
        }
    }

    $candidates[0]
}

function Connect-StatusPipe {
    param(
        [string]$PipeName,
        [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds([Math]::Max(1, $TimeoutSeconds))
    do {
        $client = $null
        try {
            $client = [System.IO.Pipes.NamedPipeClientStream]::new(
                ".",
                $PipeName,
                [System.IO.Pipes.PipeDirection]::InOut,
                [System.IO.Pipes.PipeOptions]::Asynchronous
            )
            $client.Connect(1000)

            $encoding = [System.Text.UTF8Encoding]::new($false)
            $reader = [System.IO.StreamReader]::new($client, $encoding, $false, 4096, $true)
            $writer = [System.IO.StreamWriter]::new($client, $encoding, 4096, $true)
            $writer.AutoFlush = $true
            $writer.NewLine = "`n"

            return [pscustomobject]@{
                Client = $client
                Reader = $reader
                Writer = $writer
            }
        }
        catch {
            if ($null -ne $client) {
                $client.Dispose()
            }
            Start-Sleep -Milliseconds 700
        }
    }
    while ((Get-Date) -lt $deadline)

    throw "Timed out waiting for the APFS Access status pipe."
}

function Disconnect-StatusPipe {
    param([object]$Pipe)

    if ($null -eq $Pipe) {
        return
    }

    if ($Pipe.PSObject.Properties.Name -contains "Writer" -and $null -ne $Pipe.Writer) {
        try { $Pipe.Writer.Dispose() } catch {}
    }
    if ($Pipe.PSObject.Properties.Name -contains "Reader" -and $null -ne $Pipe.Reader) {
        try { $Pipe.Reader.Dispose() } catch {}
    }
    if ($Pipe.PSObject.Properties.Name -contains "Client" -and $null -ne $Pipe.Client) {
        try { $Pipe.Client.Dispose() } catch {}
    }
}

function Read-PipeEnvelope {
    param(
        [object]$Pipe,
        [int]$TimeoutMilliseconds,
        [string]$LogPath
    )

    try {
        if (-not ($Pipe.PSObject.Properties.Name -contains "PendingReadTask")) {
            $Pipe | Add-Member -NotePropertyName PendingReadTask -NotePropertyValue $null
        }

        if ($null -eq $Pipe.PendingReadTask) {
            $Pipe.PendingReadTask = $Pipe.Reader.ReadLineAsync()
        }

        $task = $Pipe.PendingReadTask
        if (-not $task.Wait($TimeoutMilliseconds)) {
            return $null
        }

        $Pipe.PendingReadTask = $null
        $line = $task.Result
        if ($null -eq $line) {
            return $null
        }

        Add-Content -LiteralPath $LogPath -Value $line -Encoding utf8
        return $line | ConvertFrom-Json -Depth 20
    }
    catch {
        if ($Pipe.PSObject.Properties.Name -contains "PendingReadTask") {
            try {
                if ($null -ne $Pipe.PendingReadTask -and $Pipe.PendingReadTask.IsCompleted) {
                    $Pipe.PendingReadTask = $null
                }
            }
            catch {}
        }
        return $null
    }
}

function Wait-ForMountedStatus {
    param(
        [object]$Pipe,
        [int]$TimeoutSeconds,
        [string]$StatusLogPath
    )

    $deadline = (Get-Date).AddSeconds([Math]::Max(1, $TimeoutSeconds))
    $lastStatus = $null

    while ((Get-Date) -lt $deadline) {
        $envelope = Read-PipeEnvelope -Pipe $Pipe -TimeoutMilliseconds 1000 -LogPath $StatusLogPath
        if ($null -eq $envelope) {
            continue
        }

        if (($envelope.PSObject.Properties.Name -contains "type") -and $envelope.type -eq "StatusChanged") {
            $lastStatus = $envelope.payload
            $mountPoints = @()
            if ($lastStatus.PSObject.Properties.Name -contains "mountPoints" -and $null -ne $lastStatus.mountPoints) {
                $mountPoints = @($lastStatus.mountPoints)
            }

            if ($mountPoints.Count -gt 0) {
                return $lastStatus
            }
        }
    }

    if ($null -ne $lastStatus) {
        $state = if ($lastStatus.PSObject.Properties.Name -contains "state") { [string]$lastStatus.state } else { "unknown" }
        $lastError = if ($lastStatus.PSObject.Properties.Name -contains "lastError") { [string]$lastStatus.lastError } else { "" }
        $warnings = if ($lastStatus.PSObject.Properties.Name -contains "warnings" -and $null -ne $lastStatus.warnings) {
            (@($lastStatus.warnings) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) -join "; "
        }
        else {
            ""
        }
        $details = @("state=$state")
        if (-not [string]::IsNullOrWhiteSpace($lastError)) { $details += "lastError=$lastError" }
        if (-not [string]::IsNullOrWhiteSpace($warnings)) { $details += "warnings=$warnings" }
        throw "Timed out waiting for a mounted APFS volume with a drive letter ($($details -join ', '))."
    }

    throw "Timed out waiting for a mounted APFS volume with a drive letter."
}

function Send-QuitRequest {
    param([object]$Pipe)

    if ($null -eq $Pipe) {
        return
    }

    $payload = [ordered]@{
        type = "QuitRequested"
        requestId = [Guid]::NewGuid().ToString("N")
        payload = [ordered]@{
            requester = "PilotAutomation"
            timestampUtc = [DateTime]::UtcNow.ToString("o")
        }
    }

    $Pipe.Writer.WriteLine((ConvertTo-PrettyJson -InputObject $payload).Replace([Environment]::NewLine, ""))
}

function Stop-ApfsProcesses {
    $expectedRoot = $null
    try {
        $rootVariable = Get-Variable -Name appRoot -Scope Script -ErrorAction SilentlyContinue
        if ($null -ne $rootVariable -and -not [string]::IsNullOrWhiteSpace([string]$rootVariable.Value)) {
            $expectedRoot = (Resolve-Path -LiteralPath ([string]$rootVariable.Value)).Path
        }
    }
    catch {
        $expectedRoot = $null
    }

    $processes = @(
        Get-Process -Name "ApfsAccess.Tray", "ApfsAccess.Service", "ApfsAccess.FsHost" -ErrorAction SilentlyContinue |
            Where-Object {
                [string]::IsNullOrWhiteSpace($expectedRoot) -or
                ($_.Path -and $_.Path.StartsWith($expectedRoot, [System.StringComparison]::OrdinalIgnoreCase))
            }
    )

    foreach ($process in $processes) {
        try {
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
        }
        catch {
        }
    }

    $deadline = (Get-Date).AddSeconds(8)
    do {
        $remaining = @(
            Get-Process -Name "ApfsAccess.Tray", "ApfsAccess.Service", "ApfsAccess.FsHost" -ErrorAction SilentlyContinue |
                Where-Object {
                    [string]::IsNullOrWhiteSpace($expectedRoot) -or
                    ($_.Path -and $_.Path.StartsWith($expectedRoot, [System.StringComparison]::OrdinalIgnoreCase))
                }
        )

        if ($remaining.Count -eq 0) {
            return
        }

        Start-Sleep -Milliseconds 250
    }
    while ((Get-Date) -lt $deadline)
}

function Start-ApfsApplication {
    param([string]$TrayExePath)

    Start-Process -FilePath $TrayExePath -WorkingDirectory (Split-Path -Parent $TrayExePath) -WindowStyle Hidden -PassThru
}

function New-BlankEvidenceRecord {
    [ordered]@{
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

function New-BootstrapEvidenceLedger {
    param(
        [pscustomobject]$ServiceOptions,
        [string]$ProfileId,
        [string]$VolumeId
    )

    $record = New-BlankEvidenceRecord
    $record.crashFaultPasses = [Math]::Max(0, [int]$ServiceOptions.NativeWriteMinCrashFaultPasses)
    $record.crashStageMatrixPasses = if ([bool]$ServiceOptions.NativeWriteCrashFaultMatrixRequired) {
        [Math]::Max(0, [int]$ServiceOptions.NativeWriteMinCrashStageMatrixPasses)
    }
    else {
        0
    }
    $record.hardwarePilotPasses = [Math]::Max(0, [int]$ServiceOptions.NativeWriteMinHardwarePilotPasses)
    $record.hotUnplugPasses = [Math]::Max(0, [int]$ServiceOptions.NativeWriteMinHotUnplugPasses)
    $record.lastValidatedUtc = [DateTime]::UtcNow.ToString("o")
    $record.lastValidationProfileId = $ProfileId

    [ordered]@{
        volumes = [ordered]@{
            $VolumeId = $record
        }
        profiles = [ordered]@{
            $ProfileId = $record
        }
    }
}

function Set-PilotAppSettings {
    param(
        [string]$AppSettingsPath,
        [string]$ResolvedDeviceId,
        [string]$ResolvedVolumeId,
        [string]$EvidenceStorePath,
        [bool]$AllowDestructiveWriteSmoke
    )

    $root = Get-Content -LiteralPath $AppSettingsPath -Raw | ConvertFrom-Json
    if ($null -eq $root.Service) {
        $root | Add-Member -MemberType NoteProperty -Name Service -Value ([pscustomobject]@{})
    }

    $service = $root.Service
    $service.BackendMode = "Native"
    if ($service.PSObject.Properties.Name -contains 'NativeApfsUtilPath') {
        $null = $service.PSObject.Properties.Remove('NativeApfsUtilPath')
    }
    $service.NativeFsHostPath = "ApfsAccess.FsHost.exe"
    $service.NativeDeviceCandidates = @($ResolvedDeviceId)
    $service.NativeAutoDiscoverPhysicalDrives = $false
    $service.EnableNativeWrite = [bool]$AllowDestructiveWriteSmoke
    $service.WriteRolloutChannel = if ($AllowDestructiveWriteSmoke) { "Pilot" } else { "Disabled" }
    $service.WriteSafetyLevel = "Conservative"
    $service.WriteBackendMode = if ($AllowDestructiveWriteSmoke) { "Native" } else { "Disabled" }
    $service.AllowWriteOnUnsupportedFeatures = $false
    $service.NativeWriteAllowRawPhysicalDevices = [bool]$AllowDestructiveWriteSmoke
    $service.NativeWriteCrashReplayMode = if ($AllowDestructiveWriteSmoke) { "ReplayIfSafe" } else { "FailClosed" }
    if ($AllowDestructiveWriteSmoke) {
        $service.NativeWritePilotVolumeAllowList = @($ResolvedVolumeId)
        $service.NativeWritePromotionPolicy = "PilotHardware"
        $service.NativeWriteHardwarePilotDeviceAllowList = @($ResolvedDeviceId)
    }
    else {
        $service.NativeWritePilotVolumeAllowList = @()
        $service.NativeWritePromotionPolicy = "ScaffoldOnly"
        $service.NativeWriteHardwarePilotDeviceAllowList = @()
    }
    $service.NativeWriteEvidenceStorePath = $EvidenceStorePath
    $service.NativeWriteAllowRuntimeEvidenceSeedForRawPhysicalDevices = $false
    $service.NativeWriteEvidenceSeedCrashFaultPasses = 0
    $service.NativeWriteEvidenceSeedCrashStageMatrixPasses = 0
    $service.NativeWriteEvidenceSeedHardwarePilotPasses = 0
    $service.NativeWriteEvidenceSeedHotUnplugPasses = 0
    $service.NativeWriteEvidenceSeedMacOsValidationPasses = 0
    $service.NativeWriteEvidenceSeedMacOsConsistencyPasses = 0
    $service.NativeWriteEvidenceSeedPowerLossReplayPasses = 0
    $service.NativeWriteEvidenceSeedPowerLossPassVerified = $false
    $service.NativeWriteEvidenceSeedLastValidatedUtc = $null
    $service.NativeWriteEvidenceSeedLastValidationProfileId = $null
    $service.SkipEncryptedVolumes = $true
    $service.NativeHostStartupTimeoutSeconds = 120
    $service.ReadWriteMode = "RwWithRoFallback"
    $service.AutoMountEnabled = $true

    ConvertTo-PrettyJson -InputObject $root | Set-Content -LiteralPath $AppSettingsPath -Encoding utf8
    $service
}

function Invoke-PromotionEvaluation {
    param(
        [string]$EvaluateScriptPath,
        [string]$AppSettingsPath,
        [string]$ProfileId,
        [string]$OutputPath
    )

    $json = (& $EvaluateScriptPath -AppSettingsPath $AppSettingsPath -ProfileId $ProfileId -AsJson | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($json)) {
        throw "Promotion evaluation returned no JSON."
    }

    $json | Set-Content -LiteralPath $OutputPath -Encoding utf8
    $json | ConvertFrom-Json -Depth 20
}

function Invoke-SmokeTest {
    param(
        [string]$MountPoint,
        [string]$SessionId
    )

    $normalizedMount = Normalize-MountPoint $MountPoint
    if (-not (Test-Path -LiteralPath $normalizedMount)) {
        throw "Mount point is not accessible: $normalizedMount"
    }

    $rootName = "apfs-access-pilot-$SessionId"
    $rootPath = Join-Path $normalizedMount $rootName
    $filePath = Join-Path $rootPath "smoke.txt"
    $renamedPath = Join-Path $rootPath "smoke-renamed.txt"
    $deletedPath = Join-Path $rootPath "delete-me.txt"
    $fixedTimestampUtc = [DateTime]::Parse(
        "2026-03-06T12:34:56Z",
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AdjustToUniversal
    ).ToUniversalTime()

    New-Item -ItemType Directory -Force -Path $rootPath | Out-Null
    Set-Content -LiteralPath $filePath -Value "alphabet" -NoNewline -Encoding ascii
    Rename-Item -LiteralPath $filePath -NewName "smoke-renamed.txt"

    $stream = [System.IO.File]::Open($renamedPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    try {
        $stream.SetLength(5)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }

    $renamedItem = Get-Item -LiteralPath $renamedPath
    $renamedItem.LastWriteTimeUtc = $fixedTimestampUtc

    Set-Content -LiteralPath $deletedPath -Value "temp" -NoNewline -Encoding ascii
    Remove-Item -LiteralPath $deletedPath -Force

    Start-Sleep -Seconds 2

    [ordered]@{
        rootPath = $rootPath
        renamedFilePath = $renamedPath
        deletedFilePath = $deletedPath
        expectedContent = "alpha"
        expectedLastWriteUtc = $fixedTimestampUtc.ToString("o")
    }
}

function Get-RelativePathSafe {
    param(
        [string]$BasePath,
        [string]$Path
    )

    try {
        return [System.IO.Path]::GetRelativePath($BasePath, $Path)
    }
    catch {
        return [System.IO.Path]::GetFileName($Path)
    }
}

function Get-ReadOnlyFileCandidates {
    param(
        [string]$MountPoint,
        [int]$SampleFileLimit
    )

    $limit = [Math]::Max(1, $SampleFileLimit)
    $timeoutMs = 120000
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $env:ComSpec
    $psi.Arguments = "/d /c dir /a:-d /s /b ""$MountPoint"""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($psi)
    if ($null -eq $process) {
        throw "Read-only enumeration could not start cmd.exe."
    }

    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($timeoutMs)) {
        try { $process.Kill($true) } catch {}
        throw "Read-only enumeration timed out after $([int]($timeoutMs / 1000)) seconds."
    }

    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0 -and -not [string]::IsNullOrWhiteSpace($stderr)) {
        throw "Read-only enumeration failed: $stderr"
    }

    $paths = @(
        $stdout -split "(`r`n|`n|`r)" |
            ForEach-Object { [string]$_ } |
            Where-Object { $_ -notmatch "^(`r`n|`n|`r)$" } |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique |
            Select-Object -First $limit
    )

    @(
        foreach ($path in $paths) {
            try {
                $info = [System.IO.FileInfo]::new($path)
                if ($info.Exists) {
                    [pscustomobject]@{
                        FullName = $info.FullName
                        Length = [UInt64]$info.Length
                    }
                }
            }
            catch {
                throw "Read-only enumeration found an inaccessible file '$path': $($_.Exception.Message)"
            }
        }
    )
}

function Invoke-ReadOnlyValidation {
    param(
        [string]$MountPoint,
        [string]$SessionRoot,
        [int]$SampleFileLimit,
        [UInt64]$CopyByteLimit,
        [bool]$SkipCopy
    )

    $normalizedMount = Normalize-MountPoint $MountPoint
    if (-not (Test-Path -LiteralPath $normalizedMount)) {
        throw "Mount point is not accessible: $normalizedMount"
    }

    $copyRoot = Join-Path $SessionRoot "read-only-copyout"
    Write-Info "Enumerating files from read-only mount $normalizedMount."
    $files = @(Get-ReadOnlyFileCandidates -MountPoint $normalizedMount -SampleFileLimit $SampleFileLimit)
    Write-Info "Enumerated $($files.Count) read-only file candidates."

    $copied = New-Object System.Collections.Generic.List[object]
    $hashChecks = New-Object System.Collections.Generic.List[object]
    [UInt64]$bytesCopied = 0
    $copyLimitReached = $false

    if (-not $SkipCopy) {
        New-Item -ItemType Directory -Force -Path $copyRoot | Out-Null
        Write-Info "Copying read-only sample files and verifying SHA-256 hashes."
        foreach ($file in $files) {
            $length = [UInt64]$file.Length
            if (($bytesCopied + $length) -gt $CopyByteLimit) {
                $copyLimitReached = $true
                break
            }

            $relative = Get-RelativePathSafe -BasePath $normalizedMount -Path $file.FullName
            $destination = Join-Path $copyRoot $relative
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
            Copy-Item -LiteralPath $file.FullName -Destination $destination -Force -ErrorAction Stop
            $bytesCopied += $length

            $sourceHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
            $copyHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
            $hashMatch = [string]::Equals($sourceHash, $copyHash, [System.StringComparison]::OrdinalIgnoreCase)
            if (-not $hashMatch) {
                throw "Read-only copy hash mismatch for '$relative'."
            }

            $copied.Add([ordered]@{
                relativePath = $relative
                sizeBytes = [UInt64]$file.Length
                sha256 = $sourceHash
            })

            if (($copied.Count % 25) -eq 0) {
                Write-Info "Copied and verified $($copied.Count) files so far."
            }
        }
        Write-Info "Copied and verified $($copied.Count) files."
    }

    foreach ($file in @($files | Select-Object -First ([Math]::Min(16, $files.Count)))) {
        $hashChecks.Add([ordered]@{
            relativePath = Get-RelativePathSafe -BasePath $normalizedMount -Path $file.FullName
            sizeBytes = [UInt64]$file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        })
    }

    [ordered]@{
        mode = "ReadOnly"
        mountPoint = $normalizedMount
        enumeratedFileCount = $files.Count
        copiedFileCount = $copied.Count
        copiedBytes = $bytesCopied
        copyLimitBytes = $CopyByteLimit
        copyLimitReached = $copyLimitReached
        copyRoot = if ($SkipCopy) { $null } else { $copyRoot }
        sampleHashes = $hashChecks.ToArray()
        copiedFiles = $copied.ToArray()
    }
}

function Test-SmokePersistence {
    param(
        [string]$MountPoint,
        [hashtable]$SmokeResult
    )

    $rootPath = Join-Path (Normalize-MountPoint $MountPoint) ([System.IO.Path]::GetFileName($SmokeResult.rootPath))
    $renamedPath = Join-Path $rootPath "smoke-renamed.txt"
    $deletedPath = Join-Path $rootPath "delete-me.txt"
    $messages = New-Object System.Collections.Generic.List[string]
    $success = $true

    if (-not (Test-Path -LiteralPath $rootPath)) {
        $success = $false
        $messages.Add("Smoke test directory is missing after remount.")
    }

    if (-not (Test-Path -LiteralPath $renamedPath)) {
        $success = $false
        $messages.Add("Renamed smoke file is missing after remount.")
    }
    else {
        $content = Get-Content -LiteralPath $renamedPath -Raw
        if ($content -ne $SmokeResult.expectedContent) {
            $success = $false
            $messages.Add("Smoke file content mismatch after remount.")
        }

        $item = Get-Item -LiteralPath $renamedPath
        $expectedUtc = [DateTime]::Parse(
            [string]$SmokeResult.expectedLastWriteUtc,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal
        ).ToUniversalTime()
        $delta = [Math]::Abs(($item.LastWriteTimeUtc - $expectedUtc).TotalSeconds)
        if ($delta -gt 2.0) {
            $success = $false
            $messages.Add("Smoke file LastWriteTimeUtc did not survive remount.")
        }
    }

    if (Test-Path -LiteralPath $deletedPath) {
        $success = $false
        $messages.Add("Deleted smoke file reappeared after remount.")
    }

    [ordered]@{
        success = $success
        messages = $messages.ToArray()
        verifiedRootPath = $rootPath
        verifiedFilePath = $renamedPath
    }
}

function New-ValidationReport {
    param(
        [string]$ReportPath,
        [string]$ProfileId,
        [string]$VolumeId,
        [bool]$HardwarePilotPassed,
        [bool]$BootstrapSeeded,
        [bool]$DestructiveWriteSmoke
    )

    $generatedUtc = [DateTime]::UtcNow.ToString("o")
    $hardwareNotes = if (-not $DestructiveWriteSmoke) {
        "Automated read-only mount, enumeration, copy-out, and hash validation succeeded. No APFS writes were attempted."
    }
    elseif ($BootstrapSeeded) {
        "Automated Windows write smoke + remount run succeeded. Session used a temporary local bootstrap evidence ledger to unlock writable testing for feedback only."
    }
    else {
        "Automated Windows write smoke + remount run succeeded without temporary bootstrap evidence."
    }

    Write-JsonFile -Path $ReportPath -InputObject ([ordered]@{
        generatedUtc = $generatedUtc
        profileId = $ProfileId
        volumeId = $VolumeId
        bootstrapSeeded = $BootstrapSeeded
        destructiveWriteSmoke = $DestructiveWriteSmoke
        results = @(
            [ordered]@{ profileId = $ProfileId; volumeId = $VolumeId; scenario = "CrashFault"; passed = $false; count = 1; validatedUtc = $null; notes = "manual crash-fault validation still required" },
            [ordered]@{ profileId = $ProfileId; volumeId = $VolumeId; scenario = "CrashStageMatrix"; passed = $false; count = 1; validatedUtc = $null; notes = "manual crash-stage matrix validation still required" },
            [ordered]@{ profileId = $ProfileId; volumeId = $VolumeId; scenario = "HardwarePilot"; passed = $HardwarePilotPassed; count = 1; validatedUtc = if ($HardwarePilotPassed) { $generatedUtc } else { $null }; notes = if ($HardwarePilotPassed) { $hardwareNotes } else { "automated smoke run did not complete successfully" } },
            [ordered]@{ profileId = $ProfileId; volumeId = $VolumeId; scenario = "HotUnplug"; passed = $false; count = 1; validatedUtc = $null; notes = "manual hot-unplug validation still required" },
            [ordered]@{ profileId = $ProfileId; volumeId = $VolumeId; scenario = "PowerLossReplay"; passed = $false; count = 1; validatedUtc = $null; notes = "manual power-loss replay validation still required" },
            [ordered]@{ profileId = $ProfileId; volumeId = $VolumeId; scenario = "PowerLossVerified"; passed = $false; count = 1; validatedUtc = $null; notes = "manual power-loss verification still required" },
            [ordered]@{ profileId = $ProfileId; volumeId = $VolumeId; scenario = "MacOsValidation"; passed = $false; count = 1; validatedUtc = $null; notes = "manual macOS validation still required" },
            [ordered]@{ profileId = $ProfileId; volumeId = $VolumeId; scenario = "MacOsConsistency"; passed = $false; count = 1; validatedUtc = $null; notes = "manual macOS consistency check still required" }
        )
    })
}

function Copy-IfExists {
    param(
        [string]$SourcePath,
        [string]$DestinationPath
    )

    if (-not (Test-Path -LiteralPath $SourcePath)) {
        return
    }

    $resolvedSource = (Resolve-Path -LiteralPath $SourcePath).Path
    $resolvedDestination = if (Test-Path -LiteralPath $DestinationPath) {
        (Resolve-Path -LiteralPath $DestinationPath).Path
    }
    else {
        [System.IO.Path]::GetFullPath($DestinationPath)
    }
    if ([string]::Equals($resolvedSource, $resolvedDestination, [System.StringComparison]::OrdinalIgnoreCase)) {
        return
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $DestinationPath) | Out-Null
    Copy-Item -LiteralPath $SourcePath -Destination $DestinationPath -Recurse -Force
}

function Export-DiagnosticsBundle {
    param(
        [string]$SessionRoot,
        [string]$EvidenceStorePath
    )

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ApfsAccess"
    Copy-IfExists -SourcePath $EvidenceStorePath -DestinationPath (Join-Path $SessionRoot "write-evidence.json")
    Copy-IfExists -SourcePath (Join-Path $tempRoot "write-diagnostics") -DestinationPath (Join-Path $SessionRoot "temp\write-diagnostics")
    Copy-IfExists -SourcePath (Join-Path $tempRoot "rw-journal") -DestinationPath (Join-Path $SessionRoot "temp\rw-journal")
    Copy-IfExists -SourcePath (Join-Path $tempRoot "rw-state") -DestinationPath (Join-Path $SessionRoot "temp\rw-state")
}

function New-ArchiveFromSession {
    param(
        [string]$SessionRoot,
        [string]$ArchivePath
    )

    if (Test-Path -LiteralPath $ArchivePath) {
        Remove-Item -LiteralPath $ArchivePath -Force
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ArchivePath) | Out-Null
    Compress-Archive -Path (Join-Path $SessionRoot "*") -DestinationPath $ArchivePath -Force
}

$appRoot = Resolve-AppRoot -RequestedRoot $BundleRoot
$appSettingsPath = Join-Path $appRoot "appsettings.json"
$trayExePath = Join-Path $appRoot "ApfsAccess.Tray.exe"
$nativeProbeScriptPath = Join-Path $PSScriptRoot "native_probe.ps1"
$fsHostPath = Join-Path $appRoot "ApfsAccess.FsHost.exe"
$scriptsRoot = Join-Path $appRoot "scripts"
$evaluateScriptPath = Join-Path $scriptsRoot "evaluate_write_promotion.ps1"

Assert-PathExists -Path $appSettingsPath -Description "appsettings.json"
Assert-PathExists -Path $trayExePath -Description "ApfsAccess.Tray.exe"
Assert-PathExists -Path $nativeProbeScriptPath -Description "native_probe.ps1"
Assert-PathExists -Path $fsHostPath -Description "ApfsAccess.FsHost.exe"
Assert-PathExists -Path $evaluateScriptPath -Description "evaluate_write_promotion.ps1"

$feedbackRoot = Join-Path $appRoot "pilot-feedback"
$sessionId = Get-Date -Format "yyyyMMdd-HHmmss"
$sessionRoot = Join-Path $feedbackRoot "runs\$sessionId"
$archivePath = Join-Path $feedbackRoot "$sessionId.zip"
$summaryPath = Join-Path $sessionRoot "summary.json"
$statusLogPath = Join-Path $sessionRoot "status-log.jsonl"
$diskInventoryPath = Join-Path $sessionRoot "disk-inventory.json"
$appSettingsBackupPath = Join-Path $sessionRoot "appsettings.original.json"
$deviceProbePath = Join-Path $sessionRoot "native-probe-devices.json"
$volumeProbePath = Join-Path $sessionRoot "native-probe-volumes.json"
$preflightPath = Join-Path $sessionRoot "preflight.json"
$postflightPath = Join-Path $sessionRoot "postflight.json"
$validationReportPath = Join-Path $sessionRoot "validation-report.json"
$evidenceStorePath = Join-Path $sessionRoot "write-evidence.json"
$pilotAppSettingsPath = Join-Path $sessionRoot "appsettings.pilot.json"
$finalAppSettingsPath = Join-Path $sessionRoot "appsettings.final.json"

New-Item -ItemType Directory -Force -Path $sessionRoot | Out-Null

$summary = [ordered]@{
    sessionId = $sessionId
    generatedUtc = [DateTime]::UtcNow.ToString("o")
    appRoot = $appRoot
    status = "InProgress"
    bootstrapEvidence = $UseBootstrapEvidence
    destructiveWriteSmoke = [bool]$AllowDestructiveWriteSmoke
    keepMounted = [bool]$KeepMounted
    warnings = @(
        "Use only a sacrificial APFS drive for this validation flow.",
        "Default pilot validation is read-only and does not write to APFS media.",
        "The generated validation report does not replace manual crash, hot-unplug, power-loss, or macOS validation."
    )
    manualFollowUps = @(
        "Run the crash fault / crash-stage matrix manually.",
        "Run the hot-unplug scenario manually.",
        "Run the macOS mount/read/integrity checks manually.",
        "If stable promotion is needed later, run the power-loss replay scenario manually."
    )
}

$originalAppSettingsRaw = Get-Content -LiteralPath $appSettingsPath -Raw
$statusPipe = $null
$restoredAppSettings = $false

try {
    Write-Info "APFS pilot automation is starting."
    if ($AllowDestructiveWriteSmoke) {
        Write-Warning "Destructive raw-device write smoke is enabled. This must only be used on sacrificial APFS media after write-safety blockers are cleared."
    }
    else {
        Write-Info "Read-only validation mode is active. The script will not write to the APFS volume."
    }
    Write-Info "This flow will reconfigure the published beta bundle temporarily and collect a feedback archive."

    $summary.originalAppSettingsPath = $appSettingsBackupPath
    $originalAppSettingsRaw | Set-Content -LiteralPath $appSettingsBackupPath -Encoding utf8

    Stop-ApfsProcesses

    $disks = Get-ApfsDevices -ProbeScriptPath $nativeProbeScriptPath -DiscoveryTimeoutSeconds $DeviceDiscoveryTimeoutSeconds -RequestedDeviceId $DeviceId
    if ($disks.Count -eq 0) {
        throw "No APFS raw physical drive was detected. Connect the sacrificial APFS drive and rerun this launcher."
    }

    Write-JsonFile -Path $diskInventoryPath -InputObject @($disks | ForEach-Object {
        [ordered]@{
            diskNumber = $_.DiskNumber
            deviceId = $_.DeviceId
            friendlyName = $_.FriendlyName
            serialNumber = $_.SerialNumber
            busType = $_.BusType
            sizeBytes = $_.SizeBytes
            sizeLabel = $_.SizeLabel
        }
    })

    $selectedDisk = if (-not [string]::IsNullOrWhiteSpace($DeviceId)) {
        $match = @($disks | Where-Object { $_.DeviceId -ieq $DeviceId.Trim() })
        if ($match.Count -eq 0) {
            throw "Requested device was not detected as APFS media: $DeviceId"
        }
        $match[0]
    }
    else {
        Select-ListItem -Items $disks -Prompt "Select the APFS drive" -RenderItem {
            param($item)
            "$($item.DeviceId) | $($item.FriendlyName) | $($item.BusType) | $($item.SizeLabel)"
        }
    }

    $summary.selectedDevice = [ordered]@{
        deviceId = $selectedDisk.DeviceId
        friendlyName = $selectedDisk.FriendlyName
        serialNumber = $selectedDisk.SerialNumber
        busType = $selectedDisk.BusType
        sizeBytes = $selectedDisk.SizeBytes
        sizeLabel = $selectedDisk.SizeLabel
    }
    $selectedDisk.ProbeOutput | Set-Content -LiteralPath $deviceProbePath -Encoding utf8

    $volumeProbe = Get-ApfsVolumes -ResolvedDevice $selectedDisk
    $volumeProbe.ProbeOutput | Set-Content -LiteralPath $volumeProbePath -Encoding utf8

    $selectedVolume = if (-not [string]::IsNullOrWhiteSpace($VolumeName)) {
        $match = @($volumeProbe.Volumes | Where-Object { $_.VolumeName -ieq $VolumeName.Trim() })
        if ($match.Count -eq 0) {
            throw "Requested APFS volume '$VolumeName' was not found on $($selectedDisk.DeviceId)."
        }
        $match[0]
    }
    else {
        Select-ListItem -Items $volumeProbe.Volumes -Prompt "Select the APFS volume" -RenderItem {
            param($item)
            "$($item.VolumeName) | $($item.VolumeId)"
        }
    }

    $summary.selectedVolume = [ordered]@{
        volumeName = $selectedVolume.VolumeName
        volumeId = $selectedVolume.VolumeId
        profileId = $selectedVolume.ProfileId
    }

    $serviceOptions = Set-PilotAppSettings -AppSettingsPath $appSettingsPath -ResolvedDeviceId $selectedDisk.DeviceId -ResolvedVolumeId $selectedVolume.VolumeId -EvidenceStorePath $evidenceStorePath -AllowDestructiveWriteSmoke ([bool]$AllowDestructiveWriteSmoke)
    Copy-Item -LiteralPath $appSettingsPath -Destination $pilotAppSettingsPath -Force
    if ($UseBootstrapEvidence -and $AllowDestructiveWriteSmoke) {
        Write-Info "Seeding a temporary session-local PilotHardware evidence ledger to unlock the writable smoke run."
        Write-JsonFile -Path $evidenceStorePath -InputObject (New-BootstrapEvidenceLedger -ServiceOptions $serviceOptions -ProfileId $selectedVolume.ProfileId -VolumeId $selectedVolume.VolumeId)
    }
    elseif ($UseBootstrapEvidence) {
        Write-Info "Bootstrap evidence was requested but ignored in read-only validation mode."
    }

    $summary.evidenceStorePath = $serviceOptions.NativeWriteEvidenceStorePath
    $summary.preflight = Invoke-PromotionEvaluation -EvaluateScriptPath $evaluateScriptPath -AppSettingsPath $appSettingsPath -ProfileId $selectedVolume.ProfileId -OutputPath $preflightPath

    $baselineRoots = Get-DriveRoots
    $summary.baselineRoots = $baselineRoots

    Write-Info "Launching the beta app and waiting for the APFS volume to mount."
    $null = Start-ApfsApplication -TrayExePath $trayExePath
    $statusPipe = Connect-StatusPipe -PipeName "ApfsAccess.Tray.v1" -TimeoutSeconds 25
    $firstStatus = Wait-ForMountedStatus -Pipe $statusPipe -TimeoutSeconds $MountTimeoutSeconds -StatusLogPath $statusLogPath
    $firstMountPoint = Resolve-MountPointFromStatus -Status $firstStatus -BaselineRoots $baselineRoots -PreferredVolumeName $selectedVolume.VolumeName
    Write-Info "Mounted APFS volume at $firstMountPoint."
    $summary.firstMount = [ordered]@{
        state = $firstStatus.state
        mountPoints = @($firstStatus.mountPoints)
        writeEnabled = [bool]$firstStatus.writeEnabled
        nativeWriteValidationState = $firstStatus.nativeWriteValidationState
        nativeWriteReadiness = $firstStatus.nativeWriteReadiness
        nativeWriteSafetyState = $firstStatus.nativeWriteSafetyState
        lastError = $firstStatus.lastError
        warnings = @($firstStatus.warnings)
        compatibilityWarnings = @($firstStatus.compatibilityWarnings)
        mountPoint = $firstMountPoint
    }

    if ([string]::IsNullOrWhiteSpace($firstMountPoint)) {
        throw "The app mounted an APFS volume but the drive letter could not be resolved."
    }
    if ($AllowDestructiveWriteSmoke) {
        if (-not [bool]$firstStatus.writeEnabled) {
            throw "The APFS volume mounted read-only. Review preflight.json, status-log.jsonl, and diagnostics in the feedback archive."
        }

        $smoke = Invoke-SmokeTest -MountPoint $firstMountPoint -SessionId $sessionId
        $summary.smoke = $smoke

        Disconnect-StatusPipe -Pipe $statusPipe
        $statusPipe = $null

        $rootsBeforeRemount = Get-DriveRoots
        Stop-ApfsProcesses

        Write-Info "Restarting the beta app to verify remount persistence."
        $null = Start-ApfsApplication -TrayExePath $trayExePath
        $statusPipe = Connect-StatusPipe -PipeName "ApfsAccess.Tray.v1" -TimeoutSeconds 25
        $remountStatus = Wait-ForMountedStatus -Pipe $statusPipe -TimeoutSeconds $RemountTimeoutSeconds -StatusLogPath $statusLogPath
        $remountPoint = Resolve-MountPointFromStatus -Status $remountStatus -BaselineRoots $rootsBeforeRemount -PreferredVolumeName $selectedVolume.VolumeName
        $verification = Test-SmokePersistence -MountPoint $remountPoint -SmokeResult $smoke

        $summary.remount = [ordered]@{
            state = $remountStatus.state
            mountPoints = @($remountStatus.mountPoints)
            writeEnabled = [bool]$remountStatus.writeEnabled
            nativeWriteValidationState = $remountStatus.nativeWriteValidationState
            nativeWriteReadiness = $remountStatus.nativeWriteReadiness
            nativeWriteSafetyState = $remountStatus.nativeWriteSafetyState
            lastError = $remountStatus.lastError
            warnings = @($remountStatus.warnings)
            compatibilityWarnings = @($remountStatus.compatibilityWarnings)
            mountPoint = $remountPoint
        }
        $summary.verification = $verification

        New-ValidationReport -ReportPath $validationReportPath -ProfileId $selectedVolume.ProfileId -VolumeId $selectedVolume.VolumeId -HardwarePilotPassed ([bool]$verification.success) -BootstrapSeeded $UseBootstrapEvidence -DestructiveWriteSmoke ([bool]$AllowDestructiveWriteSmoke)
        $summary.postflight = Invoke-PromotionEvaluation -EvaluateScriptPath $evaluateScriptPath -AppSettingsPath $appSettingsPath -ProfileId $selectedVolume.ProfileId -OutputPath $postflightPath

        if (-not [bool]$verification.success) {
            throw (($verification.messages | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join " ")
        }
    }
    else {
        $readOnlyValidation = Invoke-ReadOnlyValidation -MountPoint $firstMountPoint -SessionRoot $sessionRoot -SampleFileLimit $ReadOnlySampleFileLimit -CopyByteLimit $ReadOnlyCopyByteLimit -SkipCopy ([bool]$SkipReadOnlyCopy)
        $summary.readOnlyValidation = $readOnlyValidation
        New-ValidationReport -ReportPath $validationReportPath -ProfileId $selectedVolume.ProfileId -VolumeId $selectedVolume.VolumeId -HardwarePilotPassed $true -BootstrapSeeded $false -DestructiveWriteSmoke $false
        $summary.postflight = Invoke-PromotionEvaluation -EvaluateScriptPath $evaluateScriptPath -AppSettingsPath $appSettingsPath -ProfileId $selectedVolume.ProfileId -OutputPath $postflightPath
    }

    $summary.status = "Complete"
}
catch {
    $summary.status = "Failed"
    $summary.error = $_.Exception.Message
}
finally {
    Disconnect-StatusPipe -Pipe $statusPipe

    if (-not $KeepConfiguredAppSettings) {
        try {
            $originalAppSettingsRaw | Set-Content -LiteralPath $appSettingsPath -Encoding utf8
            $restoredAppSettings = $true
        }
        catch {
            $summary.restoreError = $_.Exception.Message
        }
    }

    Copy-IfExists -SourcePath $appSettingsPath -DestinationPath $finalAppSettingsPath
    if ($KeepMounted -and $summary.status -eq "Complete") {
        $summary.keptMounted = $true
        $summary.keptMountedNote = "APFS Access processes were left running so the mounted APFS drive remains visible in Explorer."
        Write-Info "Keeping APFS Access running so the mounted drive remains visible in Explorer."
    }
    else {
        $summary.keptMounted = $false
        Stop-ApfsProcesses
    }
    Export-DiagnosticsBundle -SessionRoot $sessionRoot -EvidenceStorePath $evidenceStorePath
    $summary.appSettingsRestored = $restoredAppSettings
    $summary.feedbackArchivePath = $archivePath
    $summary.summaryPath = $summaryPath
    Write-JsonFile -Path $summaryPath -InputObject $summary
    New-ArchiveFromSession -SessionRoot $sessionRoot -ArchivePath $archivePath
}

if ($summary.status -eq "Complete") {
    Write-Host ""
    if ($AllowDestructiveWriteSmoke) {
        Write-Info "Write smoke test passed and a feedback archive was created."
    }
    else {
        Write-Info "Read-only validation passed and a feedback archive was created."
    }
    Write-Host "         archive : $archivePath"
    Write-Host "         summary : $summaryPath"
    Write-Host "         note    : crash/hot-unplug/power-loss/macOS validation still remains manual."
    exit 0
}

Write-Host ""
Write-Warning "Pilot automation did not complete successfully."
Write-Host "Feedback archive: $archivePath"
if ($summary.PSObject.Properties.Name -contains "error" -and -not [string]::IsNullOrWhiteSpace([string]$summary.error)) {
    Write-Host "Failure reason : $($summary.error)"
}
exit 1
