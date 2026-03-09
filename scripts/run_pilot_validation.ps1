param(
    [string]$BundleRoot = "",
    [string]$DeviceId = "",
    [string]$VolumeName = "",
    [int]$DeviceDiscoveryTimeoutSeconds = 45,
    [int]$MountTimeoutSeconds = 120,
    [int]$RemountTimeoutSeconds = 120,
    [bool]$UseBootstrapEvidence = $true,
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

function Invoke-ApfsUtilCommand {
    param(
        [string]$ApfsUtilPath,
        [string]$CommandName,
        [string]$Target
    )

    $lines = & $ApfsUtilPath $CommandName $Target 2>&1 | ForEach-Object { $_.ToString() }
    $text = ($lines -join [Environment]::NewLine).Trim()
    $exitCode = if ($null -ne $global:LASTEXITCODE) { [int]$global:LASTEXITCODE } else { 0 }

    [pscustomobject]@{
        CommandName = $CommandName
        Target = $Target
        ExitCode = $exitCode
        Text = $text
        Success = ($exitCode -eq 0) -or ([regex]::IsMatch($text, "APFS:\s*$CommandName\s+returns\s+0\b", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
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

function Get-ApfsDevices {
    param(
        [string]$ApfsUtilPath,
        [int]$DiscoveryTimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds([Math]::Max(1, $DiscoveryTimeoutSeconds))
    do {
        $devices = New-Object System.Collections.Generic.List[object]
        foreach ($disk in Get-DiskInventory) {
            $candidateDeviceId = "\\.\PhysicalDrive$($disk.Number)"
            $probe = Invoke-ApfsUtilCommand -ApfsUtilPath $ApfsUtilPath -CommandName "enumroot" -Target $candidateDeviceId
            if (-not $probe.Success) {
                continue
            }

            $sizeBytes = if ($disk.PSObject.Properties.Name -contains "Size") {
                [UInt64]$disk.Size
            }
            else {
                [UInt64]0
            }

            $devices.Add([pscustomobject]@{
                DiskNumber = [int]$disk.Number
                DeviceId = $candidateDeviceId
                FriendlyName = if ($disk.PSObject.Properties.Name -contains "FriendlyName" -and -not [string]::IsNullOrWhiteSpace([string]$disk.FriendlyName)) { [string]$disk.FriendlyName } else { "PhysicalDrive$($disk.Number)" }
                SerialNumber = if ($disk.PSObject.Properties.Name -contains "SerialNumber") { [string]$disk.SerialNumber } else { "" }
                BusType = if ($disk.PSObject.Properties.Name -contains "BusType") { [string]$disk.BusType } else { "Unknown" }
                SizeBytes = $sizeBytes
                SizeLabel = Convert-SizeLabel -Bytes $sizeBytes
                ProbeOutput = $probe.Text
            })
        }

        if ($devices.Count -gt 0) {
            return @($devices)
        }

        if ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 2
        }
    }
    while ((Get-Date) -lt $deadline)

    @()
}

function Parse-VolumeNames {
    param([string]$RawText)

    $names = New-Object System.Collections.Generic.List[string]
    foreach ($rawLine in ($RawText -split "\r?\n")) {
        $line = $rawLine.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        if ($line -match '^APFS:\s*listsubvolumes\b' -or
            $line -match '^APFS:\s*enumroot\b' -or
            $line -match '^APFS:\s*\w+\s+returns\s+\d+\b') {
            continue
        }

        $candidate = ""
        $quoted = [regex]::Match($line, "'([^']+)'")
        if ($quoted.Success) {
            $candidate = $quoted.Groups[1].Value.Trim()
        }
        else {
            $candidate = [regex]::Replace($line, '^(?:Volume\s*\[\d+\]|\[\d+\]|[-*])\s*:?\s*', '')
            $candidate = [regex]::Replace($candidate, '\([^)]*\)', ' ')
            $candidate = [regex]::Replace($candidate, '\brole\s*=\s*\S+\b', ' ', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $candidate = [regex]::Replace($candidate, '\brole\s+\S+\b', ' ', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $candidate = [regex]::Replace($candidate, '\s+', ' ').Trim()
        }

        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }
        if ($candidate -match '^(subvolumes?|volumes?)\b' -and $candidate -notmatch '\\') {
            continue
        }

        $names.Add($candidate)
    }

    if ($names.Count -eq 0) {
        return @("Main")
    }

    @($names | Sort-Object -Unique)
}

function Get-ApfsVolumes {
    param(
        [string]$ApfsUtilPath,
        [string]$ResolvedDeviceId
    )

    $probe = Invoke-ApfsUtilCommand -ApfsUtilPath $ApfsUtilPath -CommandName "listsubvolumes" -Target $ResolvedDeviceId
    $names = Parse-VolumeNames -RawText $probe.Text

    [pscustomobject]@{
        Volumes = @(
            foreach ($name in $names) {
                [pscustomobject]@{
                    VolumeName = $name
                    VolumeId = "$ResolvedDeviceId|$name"
                    ProfileId = "raw::$(Normalize-Token $ResolvedDeviceId)::$(Normalize-Token $name)"
                }
            }
        )
        ProbeOutput = $probe.Text
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
    $candidates = if ($newRoots.Count -gt 0) { $newRoots } else { $mountPoints }

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
        $Pipe.Writer.Dispose()
    }
    if ($Pipe.PSObject.Properties.Name -contains "Reader" -and $null -ne $Pipe.Reader) {
        $Pipe.Reader.Dispose()
    }
    if ($Pipe.PSObject.Properties.Name -contains "Client" -and $null -ne $Pipe.Client) {
        $Pipe.Client.Dispose()
    }
}

function Read-PipeEnvelope {
    param(
        [object]$Pipe,
        [int]$TimeoutMilliseconds,
        [string]$LogPath
    )

    try {
        $task = $Pipe.Reader.ReadLineAsync()
        if (-not $task.Wait($TimeoutMilliseconds)) {
            return $null
        }

        $line = $task.Result
        if ($null -eq $line) {
            return $null
        }

        Add-Content -LiteralPath $LogPath -Value $line -Encoding utf8
        return $line | ConvertFrom-Json -Depth 20
    }
    catch {
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
        return $lastStatus
    }

    throw "Timed out waiting for a mounted APFS volume."
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
    $pipe = $null
    try {
        $pipe = Connect-StatusPipe -PipeName "ApfsAccess.Tray.v1" -TimeoutSeconds 2
        Send-QuitRequest -Pipe $pipe
        Start-Sleep -Seconds 2
    }
    catch {
    }
    finally {
        Disconnect-StatusPipe -Pipe $pipe
    }

    Get-Process -Name "ApfsAccess.Tray", "ApfsAccess.Service", "ApfsAccess.FsHost" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 2
}

function Start-ApfsApplication {
    param([string]$TrayExePath)

    Start-Process -FilePath $TrayExePath -WorkingDirectory (Split-Path -Parent $TrayExePath) -PassThru
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
        [string]$EvidenceStorePath
    )

    $root = Get-Content -LiteralPath $AppSettingsPath -Raw | ConvertFrom-Json
    if ($null -eq $root.Service) {
        $root | Add-Member -MemberType NoteProperty -Name Service -Value ([pscustomobject]@{})
    }

    $service = $root.Service
    $service.BackendMode = "Native"
    $service.NativeApfsUtilPath = "apfsutil.exe"
    $service.NativeFsHostPath = "ApfsAccess.FsHost.exe"
    $service.NativeDeviceCandidates = @($ResolvedDeviceId)
    $service.NativeAutoDiscoverPhysicalDrives = $false
    $service.EnableNativeWrite = $true
    $service.WriteRolloutChannel = "Pilot"
    $service.WriteSafetyLevel = "Conservative"
    $service.WriteBackendMode = "Native"
    $service.AllowWriteOnUnsupportedFeatures = $false
    $service.NativeWriteAllowRawPhysicalDevices = $true
    $service.NativeWritePilotVolumeAllowList = @($ResolvedVolumeId)
    $service.NativeWritePromotionPolicy = "PilotHardware"
    $service.NativeWriteHardwarePilotDeviceAllowList = @($ResolvedDeviceId)
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
        [bool]$BootstrapSeeded
    )

    $generatedUtc = [DateTime]::UtcNow.ToString("o")
    $hardwareNotes = if ($BootstrapSeeded) {
        "Automated Windows smoke + remount run succeeded. Session used a temporary local bootstrap evidence ledger to unlock writable testing for feedback only."
    }
    else {
        "Automated Windows smoke + remount run succeeded without temporary bootstrap evidence."
    }

    Write-JsonFile -Path $ReportPath -InputObject ([ordered]@{
        generatedUtc = $generatedUtc
        profileId = $ProfileId
        volumeId = $VolumeId
        bootstrapSeeded = $BootstrapSeeded
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
$apfsUtilPath = Join-Path $appRoot "apfsutil.exe"
$fsHostPath = Join-Path $appRoot "ApfsAccess.FsHost.exe"
$scriptsRoot = Join-Path $appRoot "scripts"
$evaluateScriptPath = Join-Path $scriptsRoot "evaluate_write_promotion.ps1"

Assert-PathExists -Path $appSettingsPath -Description "appsettings.json"
Assert-PathExists -Path $trayExePath -Description "ApfsAccess.Tray.exe"
Assert-PathExists -Path $apfsUtilPath -Description "apfsutil.exe"
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
$enumrootPath = Join-Path $sessionRoot "apfsutil-enumroot.txt"
$listsubvolumesPath = Join-Path $sessionRoot "apfsutil-listsubvolumes.txt"
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
    warnings = @(
        "Use only a sacrificial APFS drive for this validation flow.",
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
    Write-Info "This flow will reconfigure the published beta bundle temporarily and collect a feedback archive."

    $summary.originalAppSettingsPath = $appSettingsBackupPath
    $originalAppSettingsRaw | Set-Content -LiteralPath $appSettingsBackupPath -Encoding utf8

    Stop-ApfsProcesses

    $disks = Get-ApfsDevices -ApfsUtilPath $apfsUtilPath -DiscoveryTimeoutSeconds $DeviceDiscoveryTimeoutSeconds
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
    $selectedDisk.ProbeOutput | Set-Content -LiteralPath $enumrootPath -Encoding utf8

    $volumeProbe = Get-ApfsVolumes -ApfsUtilPath $apfsUtilPath -ResolvedDeviceId $selectedDisk.DeviceId
    $volumeProbe.ProbeOutput | Set-Content -LiteralPath $listsubvolumesPath -Encoding utf8

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

    $serviceOptions = Set-PilotAppSettings -AppSettingsPath $appSettingsPath -ResolvedDeviceId $selectedDisk.DeviceId -ResolvedVolumeId $selectedVolume.VolumeId -EvidenceStorePath $evidenceStorePath
    Copy-Item -LiteralPath $appSettingsPath -Destination $pilotAppSettingsPath -Force
    if ($UseBootstrapEvidence) {
        Write-Info "Seeding a temporary session-local PilotHardware evidence ledger to unlock the writable smoke run."
        Write-JsonFile -Path $evidenceStorePath -InputObject (New-BootstrapEvidenceLedger -ServiceOptions $serviceOptions -ProfileId $selectedVolume.ProfileId -VolumeId $selectedVolume.VolumeId)
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

    New-ValidationReport -ReportPath $validationReportPath -ProfileId $selectedVolume.ProfileId -VolumeId $selectedVolume.VolumeId -HardwarePilotPassed ([bool]$verification.success) -BootstrapSeeded $UseBootstrapEvidence
    $summary.postflight = Invoke-PromotionEvaluation -EvaluateScriptPath $evaluateScriptPath -AppSettingsPath $appSettingsPath -ProfileId $selectedVolume.ProfileId -OutputPath $postflightPath

    if (-not [bool]$verification.success) {
        throw (($verification.messages | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join " ")
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
    Stop-ApfsProcesses
    Export-DiagnosticsBundle -SessionRoot $sessionRoot -EvidenceStorePath $evidenceStorePath
    $summary.appSettingsRestored = $restoredAppSettings
    $summary.feedbackArchivePath = $archivePath
    $summary.summaryPath = $summaryPath
    Write-JsonFile -Path $summaryPath -InputObject $summary
    New-ArchiveFromSession -SessionRoot $sessionRoot -ArchivePath $archivePath
}

if ($summary.status -eq "Complete") {
    Write-Host ""
    Write-Info "Smoke test passed and a feedback archive was created."
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
