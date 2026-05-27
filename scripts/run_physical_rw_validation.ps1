param(
    [ValidateSet("Smoke", "Storm", "ExplorerWorkflow", "VerifyManifest", "Performance")]
    [string]$Mode = "Smoke",

    [string]$MountRoot = "E:\",

    [string]$ScratchRoot = "",

    [string]$OutputDir = "",

    [string]$StatusFile = "",

    [string]$ExistingManifest = "",

    [int]$FileCount = 180,

    [UInt64]$LargeFileBytes = 64MB,

    [int]$SmallFileBytes = 16KB,

    [int]$SmallFileHashSampleCount = 100,

    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot "artifacts\physical-rw-validation"
}
if ([string]::IsNullOrWhiteSpace($ScratchRoot)) {
    $scratchBase = if (Test-Path -LiteralPath "D:\") { "D:\" } else { [System.IO.Path]::GetTempPath() }
    $ScratchRoot = Join-Path $scratchBase "ApfsAccessPhysicalRw"
}

function ConvertTo-PrettyJson {
    param([object]$InputObject)
    $InputObject | ConvertTo-Json -Depth 16
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

function Add-Phase {
    param(
        [hashtable]$Results,
        [string]$Name,
        [string]$State,
        [object]$Detail = $null
    )

    $Results.phases += [ordered]@{
        name = $Name
        state = $State
        detail = $Detail
        at = (Get-Date).ToString("o")
    }
}

function Measure-Phase {
    param(
        [scriptblock]$ScriptBlock
    )

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        . $ScriptBlock
    }
    finally {
        $watch.Stop()
    }
    return $watch.Elapsed
}

function Add-BenchmarkMetric {
    param(
        [hashtable]$Results,
        [string]$Name,
        [TimeSpan]$Elapsed,
        [Nullable[double]]$OperationStartLatencyMs = $null,
        [Nullable[double]]$FirstByteLatencyMs = $null,
        [UInt64]$Bytes = 0,
        [int]$Files = 0,
        [object]$Detail = $null,
        [object]$StatusBefore = $null,
        [object]$StatusAfter = $null,
        [int]$Sha256SampleCount = 0,
        [int]$Sha256MismatchCount = 0
    )

    $elapsedSeconds = [Math]::Max($Elapsed.TotalSeconds, 0.001)
    $metric = [ordered]@{
        name = $Name
        elapsedMs = [Math]::Round($Elapsed.TotalMilliseconds, 3)
        operationStartLatencyMs = if ($null -eq $OperationStartLatencyMs) { $null } else { [Math]::Round([double]$OperationStartLatencyMs, 3) }
        firstByteLatencyMs = if ($null -eq $FirstByteLatencyMs) { $null } else { [Math]::Round([double]$FirstByteLatencyMs, 3) }
        bytes = $Bytes
        files = $Files
        megabytesPerSecond = if ($Bytes -gt 0) { [Math]::Round(($Bytes / 1MB) / $elapsedSeconds, 3) } else { $null }
        filesPerSecond = if ($Files -gt 0) { [Math]::Round($Files / $elapsedSeconds, 3) } else { $null }
        statusBefore = $StatusBefore
        statusAfter = $StatusAfter
        sha256SampleCount = $Sha256SampleCount
        sha256MismatchCount = $Sha256MismatchCount
        detail = $Detail
        at = (Get-Date).ToString("o")
    }

    $Results.benchmarks += $metric
}

function Normalize-MountRoot {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "MountRoot must not be empty."
    }

    $root = [System.IO.Path]::GetPathRoot($Path)
    if ([string]::IsNullOrWhiteSpace($root) -or $root.Length -lt 2 -or $root[1] -ne ':') {
        throw "MountRoot must be a local drive path such as E:\. Got: $Path"
    }

    return ($root.Substring(0, 2).ToUpperInvariant() + "\")
}

function Get-ApfsLogicalDisk {
    param([string]$NormalizedMountRoot)

    $deviceId = $NormalizedMountRoot.Substring(0, 2)
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$deviceId'"
    if ($null -eq $disk) {
        throw "$deviceId is not mounted."
    }
    if ($disk.FileSystem -ne "APFS") {
        throw "$deviceId is '$($disk.FileSystem)', not APFS. Refusing mounted-volume write validation."
    }
    return $disk
}

function Assert-HostStatusReady {
    param(
        [string]$Path,
        [int]$TimeoutSeconds = 20,
        [int]$PollMilliseconds = 100
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "StatusFile was not found: $Path"
    }

    $lastStatus = $null
    $deadline = (Get-Date).AddSeconds([Math]::Max(1, $TimeoutSeconds))
    $pollDelay = [Math]::Max(25, $PollMilliseconds)
    do {
        $lastStatus = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        if ($lastStatus.writeBackend -eq "Native" `
            -and $lastStatus.nativeWriteSafetyState -eq "PilotReadWrite" `
            -and $lastStatus.recoveryActive -eq $false `
            -and $lastStatus.dirtyTransactionCount -eq 0) {
            return $lastStatus
        }

        Start-Sleep -Milliseconds $pollDelay
    }
    while ((Get-Date) -lt $deadline)

    throw "Native host is not ready for physical RW validation: $($lastStatus | ConvertTo-Json -Compress)"
}

function Wait-Path {
    param(
        [string]$Path,
        [int]$Seconds = 30
    )

    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $Path) {
            return $true
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for path: $Path"
}

function Wait-Size {
    param(
        [string]$Path,
        [UInt64]$Size,
        [int]$Seconds = 120
    )

    Wait-Path -Path $Path -Seconds $Seconds | Out-Null
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ([UInt64]$item.Length -eq $Size) {
            return $true
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for size $Size at $Path"
}

function Wait-PathDeleted {
    param(
        [string]$Path,
        [string]$StatusFilePath = "",
        [int]$Seconds = 30
    )

    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-Path -LiteralPath $Path)) {
            return $true
        }

        if (-not [string]::IsNullOrWhiteSpace($StatusFilePath)) {
            try {
                Assert-HostStatusReady -Path $StatusFilePath -TimeoutSeconds 1 -PollMilliseconds 50 | Out-Null
            }
            catch {
            }
            if (-not (Test-Path -LiteralPath $Path)) {
                return $true
            }
        }

        Start-Sleep -Milliseconds 100
    }

    throw "Timed out waiting for deleted path to disappear: $Path"
}

function New-PatternFile {
    param(
        [string]$Path,
        [UInt64]$Bytes,
        [int]$Seed
    )

    $dir = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }

    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    try {
        $buffer = New-Object byte[] 65536
        $remaining = $Bytes
        $position = [UInt64]0
        while ($remaining -gt 0) {
            $chunk = [int][Math]::Min([UInt64]$buffer.Length, $remaining)
            for ($index = 0; $index -lt $chunk; $index++) {
                $buffer[$index] = [byte](($Seed + $position + [UInt64]$index) -band 0xff)
            }
            $fs.Write($buffer, 0, $chunk)
            $remaining -= [UInt64]$chunk
            $position += [UInt64]$chunk
        }
    }
    finally {
        $fs.Dispose()
    }
}

function Get-Sha256 {
    param([string]$Path)
    (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
}

function Assert-HashEqual {
    param(
        [string]$ExpectedPath,
        [string]$ActualPath,
        [string]$Label
    )

    $expectedHash = Get-Sha256 -Path $ExpectedPath
    $actualHash = Get-Sha256 -Path $ActualPath
    if ($expectedHash -ne $actualHash) {
        throw "Hash mismatch for ${Label}: $expectedHash vs $actualHash"
    }
    return $expectedHash
}

function Remove-GeneratedApfsTree {
    param(
        [string]$Path,
        [string]$MountRoot,
        [string]$StatusFilePath,
        [int]$Attempts = 6
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or
        -not $Path.StartsWith($MountRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([System.IO.Path]::GetFileName($Path)).StartsWith("apfs-access-", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing cleanup outside generated APFS test root: $Path"
    }

    function Remove-GeneratedFileIfExists {
        param([string]$ItemPath)

        if (-not [string]::IsNullOrWhiteSpace($ItemPath) -and [System.IO.File]::Exists($ItemPath)) {
            [System.IO.File]::SetAttributes($ItemPath, [System.IO.FileAttributes]::Normal)
            [System.IO.File]::Delete($ItemPath)
        }
    }

    function Test-GeneratedDirectoryOpenable {
        param([string]$ItemPath)

        if ([string]::IsNullOrWhiteSpace($ItemPath)) {
            return $false
        }
        if (-not [System.IO.Directory]::Exists($ItemPath)) {
            return $false
        }

        $enumerator = $null
        try {
            $enumerator = [System.IO.Directory]::EnumerateFileSystemEntries($ItemPath).GetEnumerator()
            $null = $enumerator.MoveNext()
            return $true
        }
        catch [System.IO.DirectoryNotFoundException] {
            return $false
        }
        finally {
            if ($null -ne $enumerator) {
                $enumerator.Dispose()
            }
        }
    }

    function Get-GeneratedApfsEntries {
        param([string]$RootPath)

        if (-not (Test-GeneratedDirectoryOpenable -ItemPath $RootPath)) {
            return @()
        }

        try {
            return @([System.IO.Directory]::EnumerateFileSystemEntries($RootPath, "*", [System.IO.SearchOption]::AllDirectories))
        }
        catch [System.IO.DirectoryNotFoundException] {
            return @()
        }
    }

    function Test-GeneratedDirectoryPath {
        param([string]$ItemPath)

        try {
            return (([System.IO.File]::GetAttributes($ItemPath) -band [System.IO.FileAttributes]::Directory) -ne 0)
        }
        catch [System.IO.FileNotFoundException] {
            return $false
        }
        catch [System.IO.DirectoryNotFoundException] {
            return $false
        }
    }

    function Remove-GeneratedEmptyDirectoryIfExists {
        param([string]$ItemPath)

        if (-not [string]::IsNullOrWhiteSpace($ItemPath) -and [System.IO.Directory]::Exists($ItemPath)) {
            $directory = [System.IO.DirectoryInfo]::new($ItemPath)
            $directory.Attributes = [System.IO.FileAttributes]::Directory
            [System.IO.Directory]::Delete($ItemPath, $false)
        }
    }

    $lastError = $null
    for ($attempt = 1; $attempt -le [Math]::Max(1, $Attempts); $attempt++) {
        if (-not (Test-GeneratedDirectoryOpenable -ItemPath $Path)) {
            return $true
        }

        try {
            $items = @(Get-GeneratedApfsEntries -RootPath $Path)

            $items |
                Where-Object { -not (Test-GeneratedDirectoryPath -ItemPath $_) } |
                Sort-Object -Descending |
                ForEach-Object {
                    try {
                        Remove-GeneratedFileIfExists -ItemPath $_
                    }
                    catch {
                        $lastError = $_
                    }
                }
            Assert-HostStatusReady -Path $StatusFilePath | Out-Null

            $items |
                Where-Object { Test-GeneratedDirectoryPath -ItemPath $_ } |
                Sort-Object Length, { $_ } -Descending |
                ForEach-Object {
                    try {
                        Remove-GeneratedEmptyDirectoryIfExists -ItemPath $_
                    }
                    catch {
                        $lastError = $_
                    }
                }
            Assert-HostStatusReady -Path $StatusFilePath | Out-Null

            if (Test-GeneratedDirectoryOpenable -ItemPath $Path) {
                $remainingChildren = @(Get-GeneratedApfsEntries -RootPath $Path)
                if ($remainingChildren.Count -eq 0) {
                    try {
                        Remove-GeneratedEmptyDirectoryIfExists -ItemPath $Path
                    }
                    catch {
                        $lastError = $_
                    }
                    Assert-HostStatusReady -Path $StatusFilePath | Out-Null
                    if (-not (Test-GeneratedDirectoryOpenable -ItemPath $Path)) {
                        return $true
                    }
                }
            }
        }
        catch {
            $lastError = $_
        }

        Start-Sleep -Milliseconds (100 * $attempt)
    }

    if ($null -ne $lastError) {
        throw $lastError
    }
    throw "Timed out cleaning generated APFS test root: $Path"
}

function Assert-HostStatusHealthy {
    param(
        [string]$Path,
        [string]$Label
    )

    $status = Assert-HostStatusReady -Path $Path
    if ($null -eq $status) {
        return $null
    }

    if ($status.PSObject.Properties.Name -contains "mountReady" -and $status.mountReady -eq $false) {
        throw "Native host is not mount-ready after ${Label}: $($status | ConvertTo-Json -Compress)"
    }
    if ($status.PSObject.Properties.Name -contains "writeBackend" -and $status.writeBackend -ne "Native") {
        throw "Native host left native backend after ${Label}: $($status | ConvertTo-Json -Compress)"
    }
    if ($status.PSObject.Properties.Name -contains "nativeWriteReadiness" -and $status.nativeWriteReadiness -ne "CommitReady") {
        throw "Native host is not CommitReady after ${Label}: $($status | ConvertTo-Json -Compress)"
    }

    return $status
}

function New-TextFixtureFile {
    param(
        [string]$Path,
        [string]$Text
    )

    $dir = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }

    Set-Content -LiteralPath $Path -Value $Text -Encoding utf8
}

function New-ValidationResults {
    param(
        [string]$SelectedMode,
        [string]$ApfsRoot,
        [string]$NtfsRoot,
        [string]$ManifestPath
    )

    @{
        mode = $SelectedMode
        generatedUtc = [DateTime]::UtcNow.ToString("o")
        apfsRoot = $ApfsRoot
        ntfsRoot = $NtfsRoot
        manifest = $ManifestPath
        phases = @()
        benchmarks = @()
        operations = @()
        files = @()
        samples = @()
        deletedPaths = @()
        errors = @()
    }
}

function Resolve-AbsolutePath {
    param([string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path -LiteralPath $Path).Path
    }
    return (Resolve-Path -LiteralPath (Join-Path (Get-Location).Path $Path)).Path
}

function Invoke-ManifestVerification {
    param(
        [string]$ManifestPath,
        [string]$StatusFilePath
    )

    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        throw "ExistingManifest was not found: $ManifestPath"
    }

    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    $mount = Normalize-MountRoot -Path $manifest.apfsRoot
    $disk = Get-ApfsLogicalDisk -NormalizedMountRoot $mount
    $status = Assert-HostStatusReady -Path $StatusFilePath

    $verifiedFiles = 0
    foreach ($file in @($manifest.files)) {
        if (-not (Test-Path -LiteralPath $file.path)) {
            throw "Manifest file is missing after remount: $($file.path)"
        }
        $item = Get-Item -LiteralPath $file.path
        if ([UInt64]$item.Length -ne [UInt64]$file.size) {
            throw "Manifest file size mismatch after remount: $($file.path)"
        }
        $hash = Get-Sha256 -Path $file.path
        if ($hash -ne $file.hash) {
            throw "Manifest file hash mismatch after remount: $($file.path)"
        }
        $verifiedFiles++
    }

    $verifiedSamples = 0
    foreach ($sample in @($manifest.samples)) {
        if (@($manifest.deletedPaths) -contains $sample.path) {
            if (Test-Path -LiteralPath $sample.path) {
                throw "Deleted sample unexpectedly exists after remount: $($sample.path)"
            }
            continue
        }
        if (-not (Test-Path -LiteralPath $sample.path)) {
            throw "Sample file is missing after remount: $($sample.path)"
        }
        $item = Get-Item -LiteralPath $sample.path
        if ([UInt64]$item.Length -ne [UInt64]$sample.size) {
            throw "Sample file size mismatch after remount: $($sample.path)"
        }
        $hash = Get-Sha256 -Path $sample.path
        if ($hash -ne $sample.hash) {
            throw "Sample file hash mismatch after remount: $($sample.path)"
        }
        $verifiedSamples++
    }

    foreach ($path in @($manifest.deletedPaths)) {
        if (Test-Path -LiteralPath $path) {
            throw "Deleted path unexpectedly exists after remount: $path"
        }
    }

    [ordered]@{
        status = "passed"
        mode = "VerifyManifest"
        manifest = $ManifestPath
        checkedFiles = $verifiedFiles
        checkedSamples = $verifiedSamples
        checkedDeletedPaths = @($manifest.deletedPaths).Count
        disk = [ordered]@{
            deviceId = $disk.DeviceID
            fileSystem = $disk.FileSystem
            volumeName = $disk.VolumeName
            size = $disk.Size
            freeSpace = $disk.FreeSpace
        }
        hostStatus = $status
        verifiedUtc = [DateTime]::UtcNow.ToString("o")
    }
}

function Invoke-ExplorerWorkflow {
    param(
        [string]$NormalizedMountRoot,
        [string]$ScratchDirectory,
        [string]$ManifestPath,
        [UInt64]$RequestedLargeFileBytes,
        [string]$StatusFilePath
    )

    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $apfsRoot = Join-Path $NormalizedMountRoot ("apfs-access-explorer-{0}" -f $stamp)
    $ntfsRoot = Join-Path $ScratchDirectory ("apfs-access-explorer-{0}" -f $stamp)
    $results = New-ValidationResults -SelectedMode "ExplorerWorkflow" -ApfsRoot $apfsRoot -NtfsRoot $ntfsRoot -ManifestPath $ManifestPath
    $trackedFiles = New-Object System.Collections.Generic.List[object]
    $deletedPaths = New-Object System.Collections.Generic.List[string]
    $requireStatusFile = -not [string]::IsNullOrWhiteSpace($StatusFilePath)

    function Add-TrackedExplorerFile {
        param(
            [string]$Path,
            [UInt64]$Size,
            [string]$Hash,
            [string]$Label
        )

        $trackedFiles.Add([ordered]@{
            path = $Path
            size = $Size
            hash = $Hash
            label = $Label
        })
    }

    function Get-ExplorerStatusSnapshot {
        param([string]$Label)

        if (-not $requireStatusFile) {
            return $null
        }

        return Assert-HostStatusHealthy -Path $StatusFilePath -Label $Label
    }

    function Add-ExplorerOperation {
        param(
            [string]$Name,
            [string]$SourcePath,
            [string]$DestinationPath,
            [UInt64]$Bytes,
            [string]$Sha256Before,
            [string]$Sha256After,
            [TimeSpan]$Elapsed,
            [object]$StatusBefore,
            [object]$StatusAfter,
            [object]$Detail = $null
        )

        $results.operations += [ordered]@{
            name = $Name
            sourcePath = $SourcePath
            destinationPath = $DestinationPath
            bytes = $Bytes
            sha256Before = $Sha256Before
            sha256After = $Sha256After
            elapsedMs = [Math]::Round($Elapsed.TotalMilliseconds, 3)
            statusBefore = $StatusBefore
            statusAfter = $StatusAfter
            detail = $Detail
            at = (Get-Date).ToString("o")
        }
    }

    function Invoke-ExplorerHashOperation {
        param(
            [string]$Name,
            [string]$SourcePath,
            [string]$DestinationPath,
            [scriptblock]$Operation,
            [switch]$SourceRemoved,
            [switch]$CaseOnlyRename,
            [object]$Detail = $null
        )

        if (-not (Test-Path -LiteralPath $SourcePath)) {
            throw "Explorer workflow source is missing before ${Name}: $SourcePath"
        }

        $sourceItem = Get-Item -LiteralPath $SourcePath
        $sourceSize = [UInt64]$sourceItem.Length
        $sourceHash = Get-Sha256 -Path $SourcePath
        $statusBefore = Get-ExplorerStatusSnapshot -Label "${Name} before"
        $elapsed = Measure-Phase {
            . $Operation
        }
        if (-not (Test-Path -LiteralPath $DestinationPath)) {
            throw "Explorer workflow destination is missing after ${Name}: $DestinationPath"
        }
        Wait-Size -Path $DestinationPath -Size $sourceSize | Out-Null
        $destinationHash = Get-Sha256 -Path $DestinationPath
        if ($sourceHash -ne $destinationHash) {
            throw "Explorer workflow hash mismatch for ${Name}: $sourceHash vs $destinationHash"
        }
        if ($SourceRemoved -and (Test-Path -LiteralPath $SourcePath)) {
            throw "Explorer workflow source still exists after ${Name}: $SourcePath"
        }
        if ($CaseOnlyRename) {
            Assert-ExplorerCaseOnlyRename -SourcePath $SourcePath -DestinationPath $DestinationPath -Label $Name
        }
        $statusAfter = Get-ExplorerStatusSnapshot -Label "${Name} after"
        Add-ExplorerOperation `
            -Name $Name `
            -SourcePath $SourcePath `
            -DestinationPath $DestinationPath `
            -Bytes $sourceSize `
            -Sha256Before $sourceHash `
            -Sha256After $destinationHash `
            -Elapsed $elapsed `
            -StatusBefore $statusBefore `
            -StatusAfter $statusAfter `
            -Detail $Detail
        return [ordered]@{
            path = $DestinationPath
            size = $sourceSize
            hash = $destinationHash
            elapsed = $elapsed
        }
    }

    function Assert-ExplorerCaseOnlyRename {
        param(
            [string]$SourcePath,
            [string]$DestinationPath,
            [string]$Label
        )

        $sourceParent = [System.IO.Path]::GetDirectoryName($SourcePath)
        $destinationParent = [System.IO.Path]::GetDirectoryName($DestinationPath)
        if (-not [string]::Equals($sourceParent, $destinationParent, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Explorer workflow case-only rename parent mismatch for ${Label}: $SourcePath -> $DestinationPath"
        }

        $sourceLeaf = [System.IO.Path]::GetFileName($SourcePath)
        $destinationLeaf = [System.IO.Path]::GetFileName($DestinationPath)
        $entries = @(Get-ChildItem -LiteralPath $destinationParent -Force)
        if (-not ($entries | Where-Object { $_.Name -ceq $DestinationLeaf })) {
            throw "Explorer workflow case-only rename destination entry missing for ${Label}: $DestinationPath"
        }
        if ($entries | Where-Object { $_.Name -ceq $SourceLeaf }) {
            throw "Explorer workflow case-only rename source casing still present for ${Label}: $SourcePath"
        }
    }

    function Invoke-ExplorerDeleteOperation {
        param(
            [string]$Name,
            [string]$Path,
            [scriptblock]$Operation,
            [object]$Detail = $null
        )

        if (-not (Test-Path -LiteralPath $Path)) {
            throw "Explorer workflow delete source is missing before ${Name}: $Path"
        }

        $item = Get-Item -LiteralPath $Path
        $bytes = if ($item.PSIsContainer) { [UInt64]0 } else { [UInt64]$item.Length }
        $hash = if ($item.PSIsContainer) { $null } else { Get-Sha256 -Path $Path }
        $statusBefore = Get-ExplorerStatusSnapshot -Label "${Name} before"
        $elapsed = Measure-Phase {
            . $Operation
        }
        if (Test-Path -LiteralPath $Path) {
            throw "Explorer workflow delete target still exists after ${Name}: $Path"
        }
        $statusAfter = Get-ExplorerStatusSnapshot -Label "${Name} after"
        Add-ExplorerOperation `
            -Name $Name `
            -SourcePath $Path `
            -DestinationPath "" `
            -Bytes $bytes `
            -Sha256Before $hash `
            -Sha256After "" `
            -Elapsed $elapsed `
            -StatusBefore $statusBefore `
            -StatusAfter $statusAfter `
            -Detail $Detail
        $deletedPaths.Add($Path)
    }

    try {
        if (-not $requireStatusFile) {
            throw "ExplorerWorkflow mode requires -StatusFile so it can verify native RW health before and after user-facing operations."
        }

        $disk = Get-ApfsLogicalDisk -NormalizedMountRoot $NormalizedMountRoot
        $status = Get-ExplorerStatusSnapshot -Label "explorer preflight"
        Add-Phase -Results $results -Name "preflight" -State "passed" -Detail ([ordered]@{
            deviceId = $disk.DeviceID
            fileSystem = $disk.FileSystem
            volumeName = $disk.VolumeName
            size = $disk.Size
            freeSpace = $disk.FreeSpace
            hostPid = if ($null -eq $status) { $null } else { $status.hostPid }
        })

        New-Item -ItemType Directory -Force -Path $ntfsRoot | Out-Null
        New-Item -ItemType Directory -Force -Path $apfsRoot | Out-Null
        Wait-Path -Path $apfsRoot | Out-Null
        Get-ExplorerStatusSnapshot -Label "root create" | Out-Null

        $unicodeFolder = "unicode-" + [string][char]0x6587 + [string][char]0x4EF6 + "-" + [char]::ConvertFromUtf32(0x1F680)
        foreach ($dir in @("format-copy", "rename-move", "cut-paste", "delete-direct", "recycle", "nested\a\b", "case-test", "long", $unicodeFolder)) {
            $target = Join-Path $apfsRoot $dir
            New-Item -ItemType Directory -Force -Path $target | Out-Null
            Wait-Path -Path $target | Out-Null
        }
        Add-Phase -Results $results -Name "explorer-folder-create" -State "passed"

        $formatFixtures = @(
            @{ Name = "empty.bin"; Bytes = [UInt64]0; Seed = 1 },
            @{ Name = "one-byte.dat"; Bytes = [UInt64]1; Seed = 2 },
            @{ Name = "edge-4095.png"; Bytes = [UInt64]4095; Seed = 3 },
            @{ Name = "edge-4096.docx"; Bytes = [UInt64]4096; Seed = 4 },
            @{ Name = "edge-4097.xlsx"; Bytes = [UInt64]4097; Seed = 5 },
            @{ Name = "archive.zip"; Bytes = [UInt64]65536; Seed = 6 },
            @{ Name = "installer.exe"; Bytes = [UInt64]8388608; Seed = 7 }
        )

        $formatMetric = [ordered]@{ bytes = [UInt64]0; files = 0 }
        $formatElapsed = Measure-Phase {
            foreach ($fixture in $formatFixtures) {
                $source = Join-Path $ntfsRoot ([string]$fixture.Name)
                $destination = Join-Path (Join-Path $apfsRoot "format-copy") ([string]$fixture.Name)
                New-PatternFile -Path $source -Bytes ([UInt64]$fixture.Bytes) -Seed ([int]$fixture.Seed)
                $copyResult = Invoke-ExplorerHashOperation `
                    -Name "copy-in-$($fixture.Name)" `
                    -SourcePath $source `
                    -DestinationPath $destination `
                    -Operation { Copy-Item -LiteralPath $source -Destination $destination -Force } `
                    -Detail ([ordered]@{ extension = [System.IO.Path]::GetExtension([string]$fixture.Name) })
                $roundTrip = Join-Path $ntfsRoot ("roundtrip-" + [string]$fixture.Name)
                Invoke-ExplorerHashOperation `
                    -Name "copy-back-$($fixture.Name)" `
                    -SourcePath $destination `
                    -DestinationPath $roundTrip `
                    -Operation { Copy-Item -LiteralPath $destination -Destination $roundTrip -Force } `
                    -Detail ([ordered]@{ extension = [System.IO.Path]::GetExtension([string]$fixture.Name) }) | Out-Null
                Add-TrackedExplorerFile -Path $destination -Size ([UInt64]$fixture.Bytes) -Hash ([string]$copyResult.hash) -Label ([string]$fixture.Name)
                $formatMetric.bytes += [UInt64](([UInt64]$fixture.Bytes) * 2)
                $formatMetric.files++
            }

            $textSource = Join-Path $ntfsRoot "notes with spaces.txt"
            $textDestination = Join-Path (Join-Path $apfsRoot $unicodeFolder) "notes with spaces.txt"
            New-TextFixtureFile -Path $textSource -Text "APFS Access Explorer workflow text fixture"
            $textResult = Invoke-ExplorerHashOperation `
                -Name "copy-in-text-unicode-path" `
                -SourcePath $textSource `
                -DestinationPath $textDestination `
                -Operation { Copy-Item -LiteralPath $textSource -Destination $textDestination -Force } `
                -Detail ([ordered]@{ unicodeFolder = $unicodeFolder })
            Add-TrackedExplorerFile -Path $textDestination -Size ([UInt64](Get-Item -LiteralPath $textDestination).Length) -Hash ([string]$textResult.hash) -Label "text-unicode-path"
            $formatMetric.bytes += [UInt64]((Get-Item -LiteralPath $textDestination).Length * 2)
            $formatMetric.files++
        }
        Add-BenchmarkMetric -Results $results -Name "explorer-format-copy-hash" -Elapsed $formatElapsed -Bytes $formatMetric.bytes -Files $formatMetric.files
        Add-Phase -Results $results -Name "explorer-format-copy-hash" -State "passed" -Detail ([ordered]@{ files = $formatMetric.files })
        Get-ExplorerStatusSnapshot -Label "format copy hash" | Out-Null

        $renameSource = Join-Path $ntfsRoot "rename-source.bin"
        $renameApfs = Join-Path (Join-Path $apfsRoot "rename-move") "rename-source.bin"
        $renamedApfs = Join-Path (Join-Path $apfsRoot "rename-move") "renamed from explorer.bin"
        $movedApfs = Join-Path (Join-Path $apfsRoot "nested\a\b") "moved from explorer.bin"
        $movedOut = Join-Path $ntfsRoot "moved-out-from-apfs.bin"
        $movedBack = Join-Path (Join-Path $apfsRoot "cut-paste") "moved-back-from-ntfs.bin"
        $renameElapsed = Measure-Phase {
            New-PatternFile -Path $renameSource -Bytes 2097152 -Seed 31
            $renameCopy = Invoke-ExplorerHashOperation `
                -Name "rename-workflow-copy-in" `
                -SourcePath $renameSource `
                -DestinationPath $renameApfs `
                -Operation { Copy-Item -LiteralPath $renameSource -Destination $renameApfs -Force }
            Invoke-ExplorerHashOperation `
                -Name "rename-workflow-rename" `
                -SourcePath $renameApfs `
                -DestinationPath $renamedApfs `
                -Operation { Rename-Item -LiteralPath $renameApfs -NewName ([System.IO.Path]::GetFileName($renamedApfs)) } `
                -SourceRemoved | Out-Null
            Invoke-ExplorerHashOperation `
                -Name "rename-workflow-internal-move" `
                -SourcePath $renamedApfs `
                -DestinationPath $movedApfs `
                -Operation { Move-Item -LiteralPath $renamedApfs -Destination $movedApfs } `
                -SourceRemoved | Out-Null
            Invoke-ExplorerHashOperation `
                -Name "rename-workflow-move-out" `
                -SourcePath $movedApfs `
                -DestinationPath $movedOut `
                -Operation { Move-Item -LiteralPath $movedApfs -Destination $movedOut } `
                -SourceRemoved | Out-Null
            Invoke-ExplorerHashOperation `
                -Name "rename-workflow-move-back" `
                -SourcePath $movedOut `
                -DestinationPath $movedBack `
                -Operation { Move-Item -LiteralPath $movedOut -Destination $movedBack } `
                -SourceRemoved | Out-Null
            Add-TrackedExplorerFile -Path $movedBack -Size 2097152 -Hash ([string]$renameCopy.hash) -Label "rename-move-cut-paste"
        }
        Add-BenchmarkMetric -Results $results -Name "explorer-rename-move-cut-paste" -Elapsed $renameElapsed -Bytes ([UInt64](2097152 * 4)) -Files 1
        Add-Phase -Results $results -Name "explorer-rename-move-cut-paste" -State "passed"
        Get-ExplorerStatusSnapshot -Label "rename move cut paste" | Out-Null

        $caseSource = Join-Path (Join-Path $apfsRoot "case-test") "caseonly.txt"
        New-TextFixtureFile -Path $caseSource -Text "case-only rename fixture"
        $caseRenamed = Join-Path (Join-Path $apfsRoot "case-test") "CaseOnly.txt"
        $caseResult = Invoke-ExplorerHashOperation `
            -Name "case-only-rename" `
            -SourcePath $caseSource `
            -DestinationPath $caseRenamed `
            -Operation { Rename-Item -LiteralPath $caseSource -NewName "CaseOnly.txt" } `
            -CaseOnlyRename
        Add-TrackedExplorerFile -Path $caseRenamed -Size ([UInt64](Get-Item -LiteralPath $caseRenamed).Length) -Hash ([string]$caseResult.hash) -Label "case-only-rename"
        Add-Phase -Results $results -Name "explorer-case-only-rename" -State "passed"

        $directDelete = Join-Path (Join-Path $apfsRoot "delete-direct") "permanent-delete.bin"
        New-PatternFile -Path $directDelete -Bytes 196608 -Seed 41
        Wait-Size -Path $directDelete -Size 196608 | Out-Null
        Invoke-ExplorerDeleteOperation `
            -Name "direct-delete-file" `
            -Path $directDelete `
            -Operation { Remove-Item -LiteralPath $directDelete -Force }
        Add-Phase -Results $results -Name "explorer-direct-delete" -State "passed"

        $recycleRoot = Join-Path $apfsRoot '$RECYCLE.BIN'
        $sidRoot = Join-Path $recycleRoot 'S-1-5-21-1000-1000-1000-1001'
        New-Item -ItemType Directory -Force -Path $sidRoot | Out-Null
        $recycleSource = Join-Path (Join-Path $apfsRoot "recycle") "recycle-me.bin"
        $recycleRestore = Join-Path (Join-Path $apfsRoot "recycle") "recycle-restored.bin"
        $recyclePayload = Join-Path $sidRoot '$RCODEX01.bin'
        $recycleInfo = Join-Path $sidRoot '$ICODEX01.bin'
        $recycleElapsed = Measure-Phase {
            New-PatternFile -Path $recycleSource -Bytes 262144 -Seed 55
            Wait-Size -Path $recycleSource -Size 262144 | Out-Null
            New-TextFixtureFile -Path $recycleInfo -Text "APFS Access recycle metadata placeholder"
            Invoke-ExplorerHashOperation `
                -Name "recycle-move-to-bin" `
                -SourcePath $recycleSource `
                -DestinationPath $recyclePayload `
                -Operation { Move-Item -LiteralPath $recycleSource -Destination $recyclePayload } `
                -SourceRemoved | Out-Null
            $recycleRestoreResult = Invoke-ExplorerHashOperation `
                -Name "recycle-restore" `
                -SourcePath $recyclePayload `
                -DestinationPath $recycleRestore `
                -Operation { Move-Item -LiteralPath $recyclePayload -Destination $recycleRestore } `
                -SourceRemoved
            Invoke-ExplorerDeleteOperation `
                -Name "recycle-delete-metadata" `
                -Path $recycleInfo `
                -Operation { Remove-Item -LiteralPath $recycleInfo -Force }
            Add-TrackedExplorerFile -Path $recycleRestore -Size 262144 -Hash ([string]$recycleRestoreResult.hash) -Label "recycle-restore"
            $deletedPaths.Add($recyclePayload)
        }
        Add-BenchmarkMetric -Results $results -Name "explorer-recycle-delete-restore" -Elapsed $recycleElapsed -Bytes ([UInt64](262144 * 2)) -Files 1
        Add-Phase -Results $results -Name "explorer-recycle-delete-restore" -State "passed"
        Get-ExplorerStatusSnapshot -Label "recycle workflow" | Out-Null

        $smallTreeRoot = Join-Path $apfsRoot "many-small-files"
        $smallTreeSourceRoot = Join-Path $ntfsRoot "many-small-source"
        New-Item -ItemType Directory -Force -Path $smallTreeRoot, $smallTreeSourceRoot | Out-Null
        $smallTreeMetric = [ordered]@{ bytes = [UInt64]0; files = 0 }
        $smallTreeElapsed = Measure-Phase {
            for ($index = 0; $index -lt 48; $index++) {
                $subdir = "bucket_{0:D2}" -f [int]($index / 12)
                $sourceDir = Join-Path $smallTreeSourceRoot $subdir
                $destinationDir = Join-Path $smallTreeRoot $subdir
                New-Item -ItemType Directory -Force -Path $sourceDir, $destinationDir | Out-Null
                $size = [UInt64](($index * 137) % 8192)
                $source = Join-Path $sourceDir ("small_{0:D3}.bin" -f $index)
                $destination = Join-Path $destinationDir ("small_{0:D3}.bin" -f $index)
                New-PatternFile -Path $source -Bytes $size -Seed (80 + $index)
                $smallResult = Invoke-ExplorerHashOperation `
                    -Name ("many-small-copy-{0:D3}" -f $index) `
                    -SourcePath $source `
                    -DestinationPath $destination `
                    -Operation { Copy-Item -LiteralPath $source -Destination $destination -Force } `
                    -Detail ([ordered]@{ bucket = $subdir })
                if (($index % 7) -eq 0) {
                    Add-TrackedExplorerFile -Path $destination -Size $size -Hash ([string]$smallResult.hash) -Label ("many-small-{0:D3}" -f $index)
                }
                $smallTreeMetric.bytes += [UInt64]($size * 2)
                $smallTreeMetric.files++
            }
        }
        Add-BenchmarkMetric -Results $results -Name "explorer-many-small-files" -Elapsed $smallTreeElapsed -Bytes $smallTreeMetric.bytes -Files $smallTreeMetric.files
        Add-Phase -Results $results -Name "explorer-many-small-files" -State "passed" -Detail ([ordered]@{ files = $smallTreeMetric.files })

        $longName = ("long-name-" + ("n" * 150) + ".bin")
        $longSource = Join-Path $ntfsRoot "long-name-source.bin"
        $longDestination = Join-Path (Join-Path $apfsRoot "long") $longName
        New-PatternFile -Path $longSource -Bytes 131072 -Seed 92
        $longResult = Invoke-ExplorerHashOperation `
            -Name "long-name-copy" `
            -SourcePath $longSource `
            -DestinationPath $longDestination `
            -Operation { Copy-Item -LiteralPath $longSource -Destination $longDestination -Force } `
            -Detail ([ordered]@{ fileNameLength = $longName.Length })
        Add-TrackedExplorerFile -Path $longDestination -Size 131072 -Hash ([string]$longResult.hash) -Label "long-name"
        Add-Phase -Results $results -Name "explorer-long-name" -State "passed" -Detail ([ordered]@{ fileNameLength = $longName.Length })

        if ($RequestedLargeFileBytes -gt 0) {
            $largeBytes = [UInt64][Math]::Max([double]$RequestedLargeFileBytes, [double]67108864)
            $largeSource = Join-Path $ntfsRoot ("explorer-large-{0}.bin" -f $largeBytes)
            $largeDestination = Join-Path $apfsRoot ("explorer-large-{0}.bin" -f $largeBytes)
            $largeRoundTrip = Join-Path $ntfsRoot ("explorer-large-{0}-roundtrip.bin" -f $largeBytes)
            $largeMetric = [ordered]@{ hash = $null }
            $largeElapsed = Measure-Phase {
                New-PatternFile -Path $largeSource -Bytes $largeBytes -Seed 71
                $largeResult = Invoke-ExplorerHashOperation `
                    -Name "large-copy-in" `
                    -SourcePath $largeSource `
                    -DestinationPath $largeDestination `
                    -Operation { Copy-Item -LiteralPath $largeSource -Destination $largeDestination -Force }
                Invoke-ExplorerHashOperation `
                    -Name "large-copy-back" `
                    -SourcePath $largeDestination `
                    -DestinationPath $largeRoundTrip `
                    -Operation { Copy-Item -LiteralPath $largeDestination -Destination $largeRoundTrip -Force } | Out-Null
                $largeMetric.hash = [string]$largeResult.hash
                Add-TrackedExplorerFile -Path $largeDestination -Size $largeBytes -Hash $largeMetric.hash -Label "large-file"
            }
            Add-BenchmarkMetric -Results $results -Name "explorer-large-file-roundtrip" -Elapsed $largeElapsed -Bytes ([UInt64]($largeBytes * 2)) -Files 1
            Add-Phase -Results $results -Name "explorer-large-file-roundtrip" -State "passed" -Detail ([ordered]@{ size = $largeBytes; hash = $largeMetric.hash })
        }

        $sweepElapsed = Measure-Phase {
            foreach ($entry in $trackedFiles) {
                if (-not (Test-Path -LiteralPath ([string]$entry.path))) {
                    throw "Tracked Explorer workflow file is missing: $($entry.path)"
                }
                $item = Get-Item -LiteralPath ([string]$entry.path)
                if ([UInt64]$item.Length -ne [UInt64]$entry.size) {
                    throw "Tracked Explorer workflow size mismatch: $($entry.path)"
                }
                $hash = Get-Sha256 -Path ([string]$entry.path)
                if ($hash -ne [string]$entry.hash) {
                    throw "Tracked Explorer workflow SHA-256 mismatch: $($entry.path)"
                }
                $roundTrip = Join-Path $ntfsRoot ("final-sweep-" + [guid]::NewGuid().ToString("N") + ".bin")
                Copy-Item -LiteralPath ([string]$entry.path) -Destination $roundTrip -Force
                if ((Get-Sha256 -Path $roundTrip) -ne [string]$entry.hash) {
                    throw "Final sweep copy-back SHA-256 mismatch: $($entry.path)"
                }
            }
            foreach ($deleted in $deletedPaths) {
                if (Test-Path -LiteralPath $deleted) {
                    throw "Deleted Explorer workflow path unexpectedly exists: $deleted"
                }
            }
        }
        Add-BenchmarkMetric -Results $results -Name "explorer-final-hash-sweep" -Elapsed $sweepElapsed -Files $trackedFiles.Count
        Add-Phase -Results $results -Name "explorer-final-hash-sweep" -State "passed" -Detail ([ordered]@{ files = $trackedFiles.Count; deletedPaths = $deletedPaths.Count })

        $postStatus = Assert-HostStatusHealthy -Path $StatusFilePath -Label "explorer final sweep"
        Add-Phase -Results $results -Name "post-status" -State "passed" -Detail $postStatus
        $results.files = $trackedFiles.ToArray()
        $results.deletedPaths = $deletedPaths.ToArray()
        $results.status = "passed"

        if ($Cleanup) {
            Remove-GeneratedApfsTree -Path $apfsRoot -MountRoot $NormalizedMountRoot -StatusFilePath $StatusFilePath | Out-Null
            $results.cleanup = "removed-apfs-test-root"
        }
    }
    catch {
        $results.status = "failed"
        $results.errors += [ordered]@{
            message = $_.Exception.Message
            at = (Get-Date).ToString("o")
            scriptStack = $_.ScriptStackTrace
        }
        try {
            if (-not [string]::IsNullOrWhiteSpace($StatusFilePath)) {
                $results.hostStatus = Get-Content -LiteralPath $StatusFilePath -Raw | ConvertFrom-Json
            }
        }
        catch {
        }
    }

    return $results
}

function Invoke-PerformanceBenchmark {
    param(
        [string]$NormalizedMountRoot,
        [string]$ScratchDirectory,
        [string]$ManifestPath,
        [int]$RequestedFileCount,
        [UInt64]$RequestedLargeFileBytes,
        [int]$RequestedSmallFileBytes,
        [int]$RequestedSmallFileHashSampleCount,
        [string]$StatusFilePath
    )

    $effectiveFileCount = if ($RequestedFileCount -eq 180) { 1000 } else { [Math]::Max(1, $RequestedFileCount) }
    $effectiveLargeFileBytes = if ($RequestedLargeFileBytes -eq 64MB) { [UInt64]1GB } else { [UInt64][Math]::Max([double]1MB, [double]$RequestedLargeFileBytes) }
    $effectiveSmallFileBytes = [Math]::Max(0, $RequestedSmallFileBytes)
    $effectiveSampleCount = [Math]::Max(0, [Math]::Min($RequestedSmallFileHashSampleCount, $effectiveFileCount))

    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $apfsRoot = Join-Path $NormalizedMountRoot ("apfs-access-performance-{0}" -f $stamp)
    $ntfsRoot = Join-Path $ScratchDirectory ("apfs-access-performance-{0}" -f $stamp)
    $results = New-ValidationResults -SelectedMode "Performance" -ApfsRoot $apfsRoot -NtfsRoot $ntfsRoot -ManifestPath $ManifestPath
    $sampleMap = [ordered]@{}

    function Get-PerformanceStatusSnapshot {
        param([string]$Label)

        if ([string]::IsNullOrWhiteSpace($StatusFilePath)) {
            return $null
        }

        return Assert-HostStatusHealthy -Path $StatusFilePath -Label $Label
    }

    function Add-PerformanceMetric {
        param(
            [string]$Name,
            [TimeSpan]$Elapsed,
            [Nullable[double]]$OperationStartLatencyMs = $null,
            [Nullable[double]]$FirstByteLatencyMs = $null,
            [UInt64]$Bytes = 0,
            [int]$Files = 0,
            [object]$StatusBefore = $null,
            [object]$StatusAfter = $null,
            [int]$Sha256SampleCount = 0,
            [int]$Sha256MismatchCount = 0,
            [object]$Detail = $null
        )

        Add-BenchmarkMetric `
            -Results $results `
            -Name $Name `
            -Elapsed $Elapsed `
            -OperationStartLatencyMs $OperationStartLatencyMs `
            -FirstByteLatencyMs $FirstByteLatencyMs `
            -Bytes $Bytes `
            -Files $Files `
            -StatusBefore $StatusBefore `
            -StatusAfter $StatusAfter `
            -Sha256SampleCount $Sha256SampleCount `
            -Sha256MismatchCount $Sha256MismatchCount `
            -Detail $Detail
    }

    function Measure-ObservableCopy {
        param(
            [string]$SourcePath,
            [string]$DestinationPath,
            [string]$FirstBytePath = "",
            [switch]$Recurse,
            [int]$TimeoutSeconds = 600,
            [int]$PollMilliseconds = 25
        )

        $lengthPath = if ([string]::IsNullOrWhiteSpace($FirstBytePath)) { $DestinationPath } else { $FirstBytePath }
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $operationStartLatencyMs = $null
        $firstByteLatencyMs = $null
        $job = Start-Job -ScriptBlock {
            param(
                [string]$Source,
                [string]$Destination,
                [bool]$Recursive
            )

            if ($Recursive) {
                Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
            }
            else {
                Copy-Item -LiteralPath $Source -Destination $Destination -Force
            }
        } -ArgumentList $SourcePath, $DestinationPath, [bool]$Recurse

        try {
            $deadline = (Get-Date).AddSeconds([Math]::Max(1, $TimeoutSeconds))
            $pollDelay = [Math]::Max(10, $PollMilliseconds)
            while ($job.State -eq "Running" -and (Get-Date) -lt $deadline) {
                if ($null -eq $operationStartLatencyMs -and (Test-Path -LiteralPath $DestinationPath)) {
                    $operationStartLatencyMs = $watch.Elapsed.TotalMilliseconds
                }
                if ($null -eq $firstByteLatencyMs -and (Test-Path -LiteralPath $lengthPath)) {
                    $item = Get-Item -LiteralPath $lengthPath -ErrorAction SilentlyContinue
                    if ($null -ne $item -and -not $item.PSIsContainer -and [UInt64]$item.Length -gt 0) {
                        $firstByteLatencyMs = $watch.Elapsed.TotalMilliseconds
                    }
                }
                Start-Sleep -Milliseconds $pollDelay
            }

            if (-not (Wait-Job -Job $job -Timeout 1)) {
                throw "Timed out waiting for copy operation to finish: $SourcePath -> $DestinationPath"
            }

            Receive-Job -Job $job -ErrorAction Stop | Out-Null
        }
        finally {
            $watch.Stop()
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }

        if ($null -eq $operationStartLatencyMs -and (Test-Path -LiteralPath $DestinationPath)) {
            $operationStartLatencyMs = $watch.Elapsed.TotalMilliseconds
        }
        if ($null -eq $firstByteLatencyMs -and (Test-Path -LiteralPath $lengthPath)) {
            $item = Get-Item -LiteralPath $lengthPath -ErrorAction SilentlyContinue
            if ($null -ne $item -and -not $item.PSIsContainer -and [UInt64]$item.Length -gt 0) {
                $firstByteLatencyMs = $watch.Elapsed.TotalMilliseconds
            }
        }

        return [ordered]@{
            elapsed = $watch.Elapsed
            operationStartLatencyMs = $operationStartLatencyMs
            firstByteLatencyMs = $firstByteLatencyMs
        }
    }

    function Assert-SampledSmallFiles {
        param(
            [string]$SourceRoot,
            [string]$DestinationRoot,
            [string]$Label
        )

        $mismatchCount = 0
        foreach ($entry in $sampleMap.GetEnumerator()) {
            $relativePath = [string]$entry.Key
            $expected = [string]$entry.Value
            $destinationPath = Join-Path $DestinationRoot $relativePath
            if (-not (Test-Path -LiteralPath $destinationPath)) {
                throw "Performance sample missing after ${Label}: $destinationPath"
            }

            $actual = Get-Sha256 -Path $destinationPath
            if ($actual -ne $expected) {
                $mismatchCount++
            }
        }

        if ($mismatchCount -ne 0) {
            throw "Performance sample hash mismatches after ${Label}: $mismatchCount"
        }

        return $mismatchCount
    }

    try {
        if ([string]::IsNullOrWhiteSpace($StatusFilePath)) {
            throw "Performance mode requires -StatusFile so it can verify native RW health before and after benchmarks."
        }

        $disk = Get-ApfsLogicalDisk -NormalizedMountRoot $NormalizedMountRoot
        $status = Get-PerformanceStatusSnapshot -Label "performance preflight"
        Add-Phase -Results $results -Name "preflight" -State "passed" -Detail ([ordered]@{
            deviceId = $disk.DeviceID
            fileSystem = $disk.FileSystem
            volumeName = $disk.VolumeName
            size = $disk.Size
            freeSpace = $disk.FreeSpace
            hostPid = if ($null -eq $status) { $null } else { $status.hostPid }
            fileCount = $effectiveFileCount
            largeFileBytes = $effectiveLargeFileBytes
            smallFileBytes = $effectiveSmallFileBytes
            smallFileHashSampleCount = $effectiveSampleCount
        })

        New-Item -ItemType Directory -Force -Path $ntfsRoot | Out-Null
        New-Item -ItemType Directory -Force -Path $apfsRoot | Out-Null
        Wait-Path -Path $apfsRoot | Out-Null

        $largeSource = Join-Path $ntfsRoot ("large-source-{0}.bin" -f $effectiveLargeFileBytes)
        $largeApfs = Join-Path $apfsRoot ("large-apfs-{0}.bin" -f $effectiveLargeFileBytes)
        $largeRoundTrip = Join-Path $ntfsRoot ("large-roundtrip-{0}.bin" -f $effectiveLargeFileBytes)
        New-PatternFile -Path $largeSource -Bytes $effectiveLargeFileBytes -Seed 301

        $largeCopyInBefore = Get-PerformanceStatusSnapshot -Label "large-copy-in before"
        $largeCopyInTiming = Measure-ObservableCopy -SourcePath $largeSource -DestinationPath $largeApfs
        Wait-Size -Path $largeApfs -Size $effectiveLargeFileBytes -Seconds 600 | Out-Null
        $largeCopyInHash = Assert-HashEqual -ExpectedPath $largeSource -ActualPath $largeApfs -Label "performance large-copy-in"
        $largeCopyInAfter = Get-PerformanceStatusSnapshot -Label "large-copy-in after"
        Add-PerformanceMetric `
            -Name "large-copy-in" `
            -Elapsed $largeCopyInTiming.elapsed `
            -OperationStartLatencyMs $largeCopyInTiming.operationStartLatencyMs `
            -FirstByteLatencyMs $largeCopyInTiming.firstByteLatencyMs `
            -Bytes $effectiveLargeFileBytes `
            -Files 1 `
            -StatusBefore $largeCopyInBefore `
            -StatusAfter $largeCopyInAfter `
            -Sha256SampleCount 1 `
            -Sha256MismatchCount 0 `
            -Detail ([ordered]@{ sha256 = $largeCopyInHash })
        Add-Phase -Results $results -Name "large-copy-in" -State "passed"

        $largeCopyBackBefore = Get-PerformanceStatusSnapshot -Label "large-copy-back before"
        $largeCopyBackTiming = Measure-ObservableCopy -SourcePath $largeApfs -DestinationPath $largeRoundTrip
        Wait-Size -Path $largeRoundTrip -Size $effectiveLargeFileBytes -Seconds 600 | Out-Null
        Assert-HashEqual -ExpectedPath $largeSource -ActualPath $largeRoundTrip -Label "performance large-copy-back" | Out-Null
        $largeCopyBackAfter = Get-PerformanceStatusSnapshot -Label "large-copy-back after"
        Add-PerformanceMetric `
            -Name "large-copy-back" `
            -Elapsed $largeCopyBackTiming.elapsed `
            -OperationStartLatencyMs $largeCopyBackTiming.operationStartLatencyMs `
            -FirstByteLatencyMs $largeCopyBackTiming.firstByteLatencyMs `
            -Bytes $effectiveLargeFileBytes `
            -Files 1 `
            -StatusBefore $largeCopyBackBefore `
            -StatusAfter $largeCopyBackAfter `
            -Sha256SampleCount 1 `
            -Sha256MismatchCount 0 `
            -Detail ([ordered]@{ sourceSha256 = $largeCopyInHash })
        Add-Phase -Results $results -Name "large-copy-back" -State "passed"
        $results.files += [ordered]@{ path = $largeApfs; size = $effectiveLargeFileBytes; hash = $largeCopyInHash; label = "performance-large" }

        $smallNtfsSource = Join-Path $ntfsRoot "small-source"
        $smallApfsDestination = Join-Path $apfsRoot "small-apfs"
        $smallNtfsRoundTrip = Join-Path $ntfsRoot "small-roundtrip"
        $smallApfsMoved = Join-Path $apfsRoot "small-apfs-moved"
        $smallNtfsMovedOut = Join-Path $ntfsRoot "small-moved-out"
        $smallApfsMovedBack = Join-Path $apfsRoot "small-apfs-moved-back"
        New-Item -ItemType Directory -Force -Path $smallNtfsSource | Out-Null

        $smallCreateMetric = [ordered]@{ bytes = [UInt64]0 }
        $smallCreateElapsed = Measure-Phase {
            for ($index = 0; $index -lt $effectiveFileCount; $index++) {
                $bucket = "bucket_{0:D3}" -f [int]($index / 100)
                $bucketPath = Join-Path $smallNtfsSource $bucket
                if (-not (Test-Path -LiteralPath $bucketPath)) {
                    New-Item -ItemType Directory -Force -Path $bucketPath | Out-Null
                }
                $relative = Join-Path $bucket ("small_{0:D5}.bin" -f $index)
                $source = Join-Path $smallNtfsSource $relative
                New-PatternFile -Path $source -Bytes ([UInt64]$effectiveSmallFileBytes) -Seed (401 + $index)
                $smallCreateMetric.bytes += [UInt64]$effectiveSmallFileBytes
                if ($sampleMap.Count -lt $effectiveSampleCount) {
                    $sampleMap[$relative] = Get-Sha256 -Path $source
                }
            }
        }
        Add-PerformanceMetric `
            -Name "small-source-create" `
            -Elapsed $smallCreateElapsed `
            -Bytes $smallCreateMetric.bytes `
            -Files $effectiveFileCount `
            -Sha256SampleCount $sampleMap.Count `
            -Detail ([ordered]@{ sourceRoot = $smallNtfsSource })

        $smallFirstRelativePath = ""
        foreach ($entry in $sampleMap.GetEnumerator()) {
            $smallFirstRelativePath = [string]$entry.Key
            break
        }
        $smallCopyInBefore = Get-PerformanceStatusSnapshot -Label "small-copy-in before"
        $smallCopyInFirstBytePath = if ([string]::IsNullOrWhiteSpace($smallFirstRelativePath)) { "" } else { Join-Path $smallApfsDestination $smallFirstRelativePath }
        $smallCopyInTiming = Measure-ObservableCopy -SourcePath $smallNtfsSource -DestinationPath $smallApfsDestination -FirstBytePath $smallCopyInFirstBytePath -Recurse -TimeoutSeconds 120
        Wait-Path -Path $smallApfsDestination -Seconds 120 | Out-Null
        $smallCopyInMismatchCount = Assert-SampledSmallFiles -SourceRoot $smallNtfsSource -DestinationRoot $smallApfsDestination -Label "small-copy-in"
        $smallCopyInAfter = Get-PerformanceStatusSnapshot -Label "small-copy-in after"
        Add-PerformanceMetric `
            -Name "small-copy-in" `
            -Elapsed $smallCopyInTiming.elapsed `
            -OperationStartLatencyMs $smallCopyInTiming.operationStartLatencyMs `
            -FirstByteLatencyMs $smallCopyInTiming.firstByteLatencyMs `
            -Bytes $smallCreateMetric.bytes `
            -Files $effectiveFileCount `
            -StatusBefore $smallCopyInBefore `
            -StatusAfter $smallCopyInAfter `
            -Sha256SampleCount $sampleMap.Count `
            -Sha256MismatchCount $smallCopyInMismatchCount `
            -Detail ([ordered]@{ smallFileBytes = $effectiveSmallFileBytes })
        Add-Phase -Results $results -Name "small-copy-in" -State "passed" -Detail ([ordered]@{ files = $effectiveFileCount; sampleCount = $sampleMap.Count })

        $smallCopyBackBefore = Get-PerformanceStatusSnapshot -Label "small-copy-back before"
        $smallCopyBackFirstBytePath = if ([string]::IsNullOrWhiteSpace($smallFirstRelativePath)) { "" } else { Join-Path $smallNtfsRoundTrip $smallFirstRelativePath }
        $smallCopyBackTiming = Measure-ObservableCopy -SourcePath $smallApfsDestination -DestinationPath $smallNtfsRoundTrip -FirstBytePath $smallCopyBackFirstBytePath -Recurse -TimeoutSeconds 120
        Wait-Path -Path $smallNtfsRoundTrip -Seconds 120 | Out-Null
        $smallCopyBackMismatchCount = Assert-SampledSmallFiles -SourceRoot $smallNtfsSource -DestinationRoot $smallNtfsRoundTrip -Label "small-copy-back"
        $smallCopyBackAfter = Get-PerformanceStatusSnapshot -Label "small-copy-back after"
        Add-PerformanceMetric `
            -Name "small-copy-back" `
            -Elapsed $smallCopyBackTiming.elapsed `
            -OperationStartLatencyMs $smallCopyBackTiming.operationStartLatencyMs `
            -FirstByteLatencyMs $smallCopyBackTiming.firstByteLatencyMs `
            -Bytes $smallCreateMetric.bytes `
            -Files $effectiveFileCount `
            -StatusBefore $smallCopyBackBefore `
            -StatusAfter $smallCopyBackAfter `
            -Sha256SampleCount $sampleMap.Count `
            -Sha256MismatchCount $smallCopyBackMismatchCount
        Add-Phase -Results $results -Name "small-copy-back" -State "passed"

        $smallMoveInternalBefore = Get-PerformanceStatusSnapshot -Label "small-internal-move before"
        $smallMoveInternalElapsed = Measure-Phase {
            Move-Item -LiteralPath $smallApfsDestination -Destination $smallApfsMoved
            Wait-Path -Path $smallApfsMoved -Seconds 120 | Out-Null
        }
        $smallMoveInternalMismatchCount = Assert-SampledSmallFiles -SourceRoot $smallNtfsSource -DestinationRoot $smallApfsMoved -Label "small-internal-move"
        $smallMoveInternalAfter = Get-PerformanceStatusSnapshot -Label "small-internal-move after"
        Add-PerformanceMetric `
            -Name "small-internal-move" `
            -Elapsed $smallMoveInternalElapsed `
            -Bytes $smallCreateMetric.bytes `
            -Files $effectiveFileCount `
            -StatusBefore $smallMoveInternalBefore `
            -StatusAfter $smallMoveInternalAfter `
            -Sha256SampleCount $sampleMap.Count `
            -Sha256MismatchCount $smallMoveInternalMismatchCount
        Add-Phase -Results $results -Name "small-internal-move" -State "passed"

        $smallMoveOutBackBefore = Get-PerformanceStatusSnapshot -Label "small-move-out-and-back before"
        $smallMoveOutBackElapsed = Measure-Phase {
            Move-Item -LiteralPath $smallApfsMoved -Destination $smallNtfsMovedOut
            Wait-Path -Path $smallNtfsMovedOut -Seconds 120 | Out-Null
            Move-Item -LiteralPath $smallNtfsMovedOut -Destination $smallApfsMovedBack
            Wait-Path -Path $smallApfsMovedBack -Seconds 120 | Out-Null
        }
        $smallMoveOutBackMismatchCount = Assert-SampledSmallFiles -SourceRoot $smallNtfsSource -DestinationRoot $smallApfsMovedBack -Label "small-move-out-and-back"
        $smallMoveOutBackAfter = Get-PerformanceStatusSnapshot -Label "small-move-out-and-back after"
        Add-PerformanceMetric `
            -Name "small-move-out-and-back" `
            -Elapsed $smallMoveOutBackElapsed `
            -Bytes ([UInt64]($smallCreateMetric.bytes * 2)) `
            -Files $effectiveFileCount `
            -StatusBefore $smallMoveOutBackBefore `
            -StatusAfter $smallMoveOutBackAfter `
            -Sha256SampleCount $sampleMap.Count `
            -Sha256MismatchCount $smallMoveOutBackMismatchCount
        Add-Phase -Results $results -Name "small-move-out-and-back" -State "passed"

        $enumerationBefore = Get-PerformanceStatusSnapshot -Label "directory-enumeration before"
        $enumerationMetric = [ordered]@{ files = 0 }
        $enumerationElapsed = Measure-Phase {
            $enumerationMetric.files = @(
                Get-ChildItem -LiteralPath $smallApfsMovedBack -Recurse -Force -File
            ).Count
        }
        if ($enumerationMetric.files -ne $effectiveFileCount) {
            throw "Performance directory enumeration count mismatch: expected $effectiveFileCount, got $($enumerationMetric.files)"
        }
        $enumerationAfter = Get-PerformanceStatusSnapshot -Label "directory-enumeration after"
        Add-PerformanceMetric `
            -Name "directory-enumeration" `
            -Elapsed $enumerationElapsed `
            -Files $enumerationMetric.files `
            -StatusBefore $enumerationBefore `
            -StatusAfter $enumerationAfter
        Add-Phase -Results $results -Name "directory-enumeration" -State "passed" -Detail ([ordered]@{ files = $enumerationMetric.files })

        $deleteBefore = Get-PerformanceStatusSnapshot -Label "delete-tree before"
        $deleteElapsed = Measure-Phase {
            if (-not $smallApfsMovedBack.StartsWith($apfsRoot, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing delete-tree benchmark outside generated APFS test root: $smallApfsMovedBack"
            }
            Remove-Item -LiteralPath $smallApfsMovedBack -Recurse -Force
            Wait-PathDeleted -Path $smallApfsMovedBack -StatusFilePath $StatusFilePath -Seconds 120 | Out-Null
        }
        $deleteAfter = Get-PerformanceStatusSnapshot -Label "delete-tree after"
        Add-PerformanceMetric `
            -Name "delete-tree" `
            -Elapsed $deleteElapsed `
            -Files $effectiveFileCount `
            -StatusBefore $deleteBefore `
            -StatusAfter $deleteAfter
        Add-Phase -Results $results -Name "delete-tree" -State "passed"

        $postStatus = Get-PerformanceStatusSnapshot -Label "performance final"
        Add-Phase -Results $results -Name "post-status" -State "passed" -Detail $postStatus
        $results.status = "passed"

        if ($Cleanup) {
            Remove-GeneratedApfsTree -Path $apfsRoot -MountRoot $NormalizedMountRoot -StatusFilePath $StatusFilePath | Out-Null
            $results.cleanup = "removed-apfs-test-root"
        }
    }
    catch {
        $results.status = "failed"
        $results.errors += [ordered]@{
            message = $_.Exception.Message
            at = (Get-Date).ToString("o")
            scriptStack = $_.ScriptStackTrace
        }
        try {
            if (-not [string]::IsNullOrWhiteSpace($StatusFilePath)) {
                $results.hostStatus = Get-Content -LiteralPath $StatusFilePath -Raw | ConvertFrom-Json
            }
        }
        catch {
        }
    }

    return $results
}

function Invoke-PhysicalWorkload {
    param(
        [string]$SelectedMode,
        [string]$NormalizedMountRoot,
        [string]$ScratchDirectory,
        [string]$ManifestPath,
        [int]$RequestedFileCount,
        [UInt64]$RequestedLargeFileBytes,
        [string]$StatusFilePath
    )

    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $apfsRoot = Join-Path $NormalizedMountRoot ("apfs-access-{0}-{1}" -f $SelectedMode.ToLowerInvariant(), $stamp)
    $ntfsRoot = Join-Path $ScratchDirectory ("apfs-access-{0}-{1}" -f $SelectedMode.ToLowerInvariant(), $stamp)
    $results = New-ValidationResults -SelectedMode $SelectedMode -ApfsRoot $apfsRoot -NtfsRoot $ntfsRoot -ManifestPath $ManifestPath

    try {
        $disk = Get-ApfsLogicalDisk -NormalizedMountRoot $NormalizedMountRoot
        $status = Assert-HostStatusReady -Path $StatusFilePath
        Add-Phase -Results $results -Name "preflight" -State "passed" -Detail ([ordered]@{
            deviceId = $disk.DeviceID
            fileSystem = $disk.FileSystem
            volumeName = $disk.VolumeName
            size = $disk.Size
            freeSpace = $disk.FreeSpace
            hostPid = if ($null -eq $status) { $null } else { $status.hostPid }
        })

        New-Item -ItemType Directory -Force -Path $ntfsRoot | Out-Null
        New-Item -ItemType Directory -Force -Path $apfsRoot | Out-Null
        Wait-Path -Path $apfsRoot | Out-Null

        foreach ($dir in @("alpha", "beta", "gamma nested", "move-source", "delete-me", "long\level1\level2\level3", "unicode-path")) {
            $target = Join-Path $apfsRoot $dir
            New-Item -ItemType Directory -Force -Path $target | Out-Null
            Wait-Path -Path $target | Out-Null
        }
        Add-Phase -Results $results -Name "directory-create" -State "passed"

        $sizes = @(0, 1, 2, 15, 255, 4095, 4096, 4097, 65535, 65536, 262144, 1048576)
        if ($SelectedMode -eq "Storm") {
            $sizes += @(5242880, 8388608, 16777216)
        }

        $copyReadHashMetric = [ordered]@{ bytes = [UInt64]0 }
        $copyReadHashElapsed = Measure-Phase {
            for ($index = 0; $index -lt $sizes.Count; $index++) {
                $size = [UInt64]$sizes[$index]
                $source = Join-Path $ntfsRoot ("src_{0:D2}_{1}.bin" -f $index, $size)
                New-PatternFile -Path $source -Bytes $size -Seed (17 + $index)
                $destination = Join-Path $apfsRoot ("alpha\size_{0:D2}_{1}.bin" -f $index, $size)
                Copy-Item -LiteralPath $source -Destination $destination -Force
                Wait-Size -Path $destination -Size $size | Out-Null
                $hash = Assert-HashEqual -ExpectedPath $source -ActualPath $destination -Label "NTFS to APFS $size"
                $roundTrip = Join-Path $ntfsRoot ("roundtrip_{0:D2}_{1}.bin" -f $index, $size)
                Copy-Item -LiteralPath $destination -Destination $roundTrip -Force
                Wait-Size -Path $roundTrip -Size $size | Out-Null
                Assert-HashEqual -ExpectedPath $source -ActualPath $roundTrip -Label "APFS to NTFS $size" | Out-Null
                $results.files += [ordered]@{ path = $destination; size = $size; hash = $hash }
                $copyReadHashMetric.bytes += [UInt64]($size * 2)
            }
        }
        Add-BenchmarkMetric -Results $results -Name "copy-read-hash" -Elapsed $copyReadHashElapsed -Bytes $copyReadHashMetric.bytes -Files $sizes.Count
        Add-Phase -Results $results -Name "copy-read-hash" -State "passed" -Detail ([ordered]@{ count = $sizes.Count })

        $direct = Join-Path $apfsRoot "beta\direct-write.bin"
        $directRoundTrip = Join-Path $ntfsRoot "direct-write-roundtrip.bin"
        $directMetric = [ordered]@{ hash = $null }
        $directElapsed = Measure-Phase {
            New-PatternFile -Path $direct -Bytes 3145728 -Seed 93
            Wait-Size -Path $direct -Size 3145728 | Out-Null
            Copy-Item -LiteralPath $direct -Destination $directRoundTrip -Force
            Wait-Size -Path $directRoundTrip -Size 3145728 | Out-Null
            $directMetric.hash = Assert-HashEqual -ExpectedPath $direct -ActualPath $directRoundTrip -Label "direct APFS write"
        }
        $results.files += [ordered]@{ path = $direct; size = 3145728; hash = $directMetric.hash }
        Add-BenchmarkMetric -Results $results -Name "direct-apfs-write" -Elapsed $directElapsed -Bytes ([UInt64](3145728 * 2)) -Files 1
        Add-Phase -Results $results -Name "direct-apfs-write" -State "passed"

        $renamed = Join-Path $apfsRoot "beta\renamed direct write.bin"
        Rename-Item -LiteralPath $direct -NewName ([System.IO.Path]::GetFileName($renamed))
        Wait-Path -Path $renamed | Out-Null
        $moved = Join-Path $apfsRoot "gamma nested\moved direct write.bin"
        Move-Item -LiteralPath $renamed -Destination $moved
        Wait-Path -Path $moved | Out-Null
        Assert-HashEqual -ExpectedPath $moved -ActualPath $directRoundTrip -Label "renamed and moved APFS file" | Out-Null
        foreach ($file in $results.files) {
            if ($file.path -eq $direct) {
                $file.path = $moved
            }
        }
        Add-Phase -Results $results -Name "rename-move-internal" -State "passed"

        $cutSource = Join-Path $ntfsRoot "cut-from-ntfs.bin"
        New-PatternFile -Path $cutSource -Bytes 2097152 -Seed 121
        $cutApfs = Join-Path $apfsRoot "move-source\cut-from-ntfs.bin"
        Move-Item -LiteralPath $cutSource -Destination $cutApfs
        Wait-Size -Path $cutApfs -Size 2097152 | Out-Null
        if (Test-Path -LiteralPath $cutSource) {
            throw "Move NTFS to APFS left source behind: $cutSource"
        }
        $cutBack = Join-Path $ntfsRoot "cut-back-from-apfs.bin"
        Move-Item -LiteralPath $cutApfs -Destination $cutBack
        Wait-Size -Path $cutBack -Size 2097152 | Out-Null
        if (Test-Path -LiteralPath $cutApfs) {
            throw "Move APFS to NTFS left source behind: $cutApfs"
        }
        Add-Phase -Results $results -Name "cut-paste-cross-volume" -State "passed"

        $treeSource = Join-Path $ntfsRoot "tree-src"
        New-Item -ItemType Directory -Force -Path (Join-Path $treeSource "a\b") | Out-Null
        New-PatternFile -Path (Join-Path $treeSource "root.bin") -Bytes 12345 -Seed 5
        New-PatternFile -Path (Join-Path $treeSource "a\b\deep.bin") -Bytes 23456 -Seed 6
        "hello apfs access" | Set-Content -LiteralPath (Join-Path $treeSource "a\note.txt") -Encoding utf8
        $treeDestination = Join-Path $apfsRoot "copied-tree"
        $recursiveElapsed = Measure-Phase {
            Copy-Item -LiteralPath $treeSource -Destination $treeDestination -Recurse -Force
            Wait-Path -Path (Join-Path $treeDestination "a\b\deep.bin") | Out-Null
            Assert-HashEqual -ExpectedPath (Join-Path $treeSource "root.bin") -ActualPath (Join-Path $treeDestination "root.bin") -Label "recursive root file" | Out-Null
            Assert-HashEqual -ExpectedPath (Join-Path $treeSource "a\b\deep.bin") -ActualPath (Join-Path $treeDestination "a\b\deep.bin") -Label "recursive deep file" | Out-Null
        }
        Add-BenchmarkMetric -Results $results -Name "recursive-copy" -Elapsed $recursiveElapsed -Bytes ([UInt64](12345 + 23456)) -Files 3
        Add-Phase -Results $results -Name "recursive-copy" -State "passed"

        $deleteFile = Join-Path $apfsRoot "delete-me\delete-this.bin"
        New-PatternFile -Path $deleteFile -Bytes 77777 -Seed 33
        Wait-Path -Path $deleteFile | Out-Null
        Remove-Item -LiteralPath $deleteFile -Force
        Wait-PathDeleted -Path $deleteFile -StatusFilePath $StatusFilePath | Out-Null
        $results.deletedPaths += $deleteFile
        $deleteDir = Join-Path $apfsRoot "delete-me\subdir"
        New-Item -ItemType Directory -Force -Path $deleteDir | Out-Null
        New-PatternFile -Path (Join-Path $deleteDir "inside.bin") -Bytes 88888 -Seed 34
        Remove-Item -LiteralPath $deleteDir -Recurse -Force
        Wait-PathDeleted -Path $deleteDir -StatusFilePath $StatusFilePath | Out-Null
        $results.deletedPaths += $deleteDir
        Add-Phase -Results $results -Name "delete-file-directory" -State "passed"

        $longName = ("n" * 120) + ".bin"
        $longPath = Join-Path (Join-Path $apfsRoot "long\level1\level2\level3") $longName
        New-PatternFile -Path $longPath -Bytes 131072 -Seed 201
        Wait-Size -Path $longPath -Size 131072 | Out-Null
        $longRoundTrip = Join-Path $ntfsRoot "long-name-roundtrip.bin"
        Copy-Item -LiteralPath $longPath -Destination $longRoundTrip -Force
        $longHash = Assert-HashEqual -ExpectedPath $longPath -ActualPath $longRoundTrip -Label "long path APFS file"
        $results.files += [ordered]@{ path = $longPath; size = 131072; hash = $longHash }
        $textPath = Join-Path $apfsRoot "unicode-path\file with spaces.txt"
        "unicode path smoke test" | Set-Content -LiteralPath $textPath -Encoding utf8
        Wait-Path -Path $textPath | Out-Null
        if ((Get-Content -LiteralPath $textPath -Raw) -notmatch "unicode path smoke test") {
            throw "Text path content mismatch: $textPath"
        }
        Add-Phase -Results $results -Name "edge-paths" -State "passed"

        if ($SelectedMode -eq "Storm") {
            $stormRoot = Join-Path $apfsRoot "storm"
            New-Item -ItemType Directory -Force -Path $stormRoot | Out-Null
            $sampleMap = @{}
            $stormCreateMetric = [ordered]@{ bytes = [UInt64]0 }
            $stormCreateElapsed = Measure-Phase {
                for ($index = 0; $index -lt $RequestedFileCount; $index++) {
                    $bucket = "bucket_{0:D2}" -f [int]($index / 25)
                    $bucketPath = Join-Path $stormRoot $bucket
                    if (-not (Test-Path -LiteralPath $bucketPath)) {
                        New-Item -ItemType Directory -Force -Path $bucketPath | Out-Null
                        Wait-Path -Path $bucketPath | Out-Null
                    }
                    $size = [UInt64]((($index * 7919) % 262144) + (($index % 7) * 4096))
                    if (($index % 23) -eq 0) {
                        $size = 0
                    }
                    $source = Join-Path $ntfsRoot ("storm_src_{0:D4}.bin" -f $index)
                    New-PatternFile -Path $source -Bytes $size -Seed (41 + $index)
                    $destination = Join-Path $bucketPath ("f_{0:D4}.bin" -f $index)
                    Copy-Item -LiteralPath $source -Destination $destination -Force
                    Wait-Size -Path $destination -Size $size | Out-Null
                    $stormCreateMetric.bytes += $size
                    if (($index % 19) -eq 0) {
                        $hash = Assert-HashEqual -ExpectedPath $source -ActualPath $destination -Label "storm sample $index"
                        $sampleMap[$destination] = [ordered]@{ size = $size; hash = $hash }
                    }
                    if (($index % 40) -eq 0) {
                        Assert-HostStatusReady -Path $StatusFilePath | Out-Null
                    }
                }
            }
            Add-BenchmarkMetric -Results $results -Name "storm-create-copy" -Elapsed $stormCreateElapsed -Bytes $stormCreateMetric.bytes -Files $RequestedFileCount
            Add-Phase -Results $results -Name "storm-create-copy" -State "passed" -Detail ([ordered]@{ fileCount = $RequestedFileCount; sampleCount = $sampleMap.Count })

            for ($index = 0; $index -lt $RequestedFileCount; $index += 5) {
                $bucket = "bucket_{0:D2}" -f [int]($index / 25)
                $old = Join-Path (Join-Path $stormRoot $bucket) ("f_{0:D4}.bin" -f $index)
                if (Test-Path -LiteralPath $old) {
                    $new = Join-Path (Join-Path $stormRoot $bucket) ("renamed_{0:D4}.dat" -f $index)
                    Rename-Item -LiteralPath $old -NewName ([System.IO.Path]::GetFileName($new))
                    Wait-Path -Path $new | Out-Null
                    if ($sampleMap.Contains($old)) {
                        $sampleMap[$new] = $sampleMap[$old]
                        $sampleMap.Remove($old)
                    }
                }
            }

            $movedDir = Join-Path $stormRoot "moved"
            New-Item -ItemType Directory -Force -Path $movedDir | Out-Null
            for ($index = 1; $index -lt $RequestedFileCount; $index += 11) {
                $bucket = "bucket_{0:D2}" -f [int]($index / 25)
                $old = Join-Path (Join-Path $stormRoot $bucket) ("f_{0:D4}.bin" -f $index)
                if (Test-Path -LiteralPath $old) {
                    $new = Join-Path $movedDir ("moved_{0:D4}.bin" -f $index)
                    Move-Item -LiteralPath $old -Destination $new
                    Wait-Path -Path $new | Out-Null
                    if ($sampleMap.Contains($old)) {
                        $sampleMap[$new] = $sampleMap[$old]
                        $sampleMap.Remove($old)
                    }
                }
            }

            foreach ($entry in @($sampleMap.GetEnumerator())) {
                if (-not (Test-Path -LiteralPath $entry.Key)) {
                    throw "Storm sample is missing: $($entry.Key)"
                }
                if ([UInt64](Get-Item -LiteralPath $entry.Key).Length -ne [UInt64]$entry.Value.size) {
                    throw "Storm sample size changed: $($entry.Key)"
                }
                if ((Get-Sha256 -Path $entry.Key) -ne $entry.Value.hash) {
                    throw "Storm sample hash changed: $($entry.Key)"
                }
                $roundTrip = Join-Path $ntfsRoot ("sample_roundtrip_" + [System.IO.Path]::GetFileName($entry.Key))
                Copy-Item -LiteralPath $entry.Key -Destination $roundTrip -Force
                if ((Get-Sha256 -Path $roundTrip) -ne $entry.Value.hash) {
                    throw "Storm sample round-trip hash mismatch: $($entry.Key)"
                }
                $results.samples += [ordered]@{ path = $entry.Key; size = $entry.Value.size; hash = $entry.Value.hash }
            }
            Add-Phase -Results $results -Name "storm-rename-move-sample-hash" -State "passed" -Detail ([ordered]@{ sampleCount = $sampleMap.Count })

            for ($index = 2; $index -lt $RequestedFileCount; $index += 9) {
                $bucket = "bucket_{0:D2}" -f [int]($index / 25)
                foreach ($leaf in @(("f_{0:D4}.bin" -f $index), ("renamed_{0:D4}.dat" -f $index))) {
                    $path = Join-Path (Join-Path $stormRoot $bucket) $leaf
                    if (Test-Path -LiteralPath $path) {
                        Remove-Item -LiteralPath $path -Force
                        if (Test-Path -LiteralPath $path) {
                            throw "Storm delete failed: $path"
                        }
                        if ($sampleMap.Contains($path)) {
                            $sampleMap.Remove($path)
                        }
                        $results.samples = @($results.samples | Where-Object { $_.path -ne $path })
                        $results.deletedPaths += $path
                    }
                }
            }
            Add-Phase -Results $results -Name "storm-delete-stride" -State "passed"
        }

        if ($RequestedLargeFileBytes -gt 0) {
            $largeSource = Join-Path $ntfsRoot ("large-{0}.bin" -f $RequestedLargeFileBytes)
            $largeDestination = Join-Path $apfsRoot ("large-{0}.bin" -f $RequestedLargeFileBytes)
            $largeRoundTrip = Join-Path $ntfsRoot ("large-{0}-roundtrip.bin" -f $RequestedLargeFileBytes)
            $largeMetric = [ordered]@{ hash = $null }
            $largeElapsed = Measure-Phase {
                New-PatternFile -Path $largeSource -Bytes $RequestedLargeFileBytes -Seed 211
                Copy-Item -LiteralPath $largeSource -Destination $largeDestination -Force
                Wait-Size -Path $largeDestination -Size $RequestedLargeFileBytes -Seconds 300 | Out-Null
                $largeMetric.hash = Assert-HashEqual -ExpectedPath $largeSource -ActualPath $largeDestination -Label "large APFS file"
                Copy-Item -LiteralPath $largeDestination -Destination $largeRoundTrip -Force
                Assert-HashEqual -ExpectedPath $largeSource -ActualPath $largeRoundTrip -Label "large APFS round-trip" | Out-Null
            }
            $results.files += [ordered]@{ path = $largeDestination; size = $RequestedLargeFileBytes; hash = $largeMetric.hash }
            Add-BenchmarkMetric -Results $results -Name "large-file-roundtrip" -Elapsed $largeElapsed -Bytes ([UInt64]($RequestedLargeFileBytes * 2)) -Files 1
            Add-Phase -Results $results -Name "large-file-roundtrip" -State "passed" -Detail ([ordered]@{ size = $RequestedLargeFileBytes; hash = $largeMetric.hash })
        }

        $postStatus = Assert-HostStatusReady -Path $StatusFilePath
        Add-Phase -Results $results -Name "post-status" -State "passed" -Detail $postStatus
        $results.status = "passed"

        if ($Cleanup) {
            if ($apfsRoot.StartsWith($NormalizedMountRoot, [StringComparison]::OrdinalIgnoreCase) -and
                ([System.IO.Path]::GetFileName($apfsRoot)).StartsWith("apfs-access-", [StringComparison]::OrdinalIgnoreCase)) {
                Remove-GeneratedApfsTree -Path $apfsRoot -MountRoot $NormalizedMountRoot -StatusFilePath $StatusFilePath | Out-Null
                $results.cleanup = "removed-apfs-test-root"
            }
            else {
                throw "Refusing cleanup outside generated APFS test root: $apfsRoot"
            }
        }
    }
    catch {
        $results.status = "failed"
        $results.errors += [ordered]@{
            message = $_.Exception.Message
            at = (Get-Date).ToString("o")
            scriptStack = $_.ScriptStackTrace
        }
        try {
            if (-not [string]::IsNullOrWhiteSpace($StatusFilePath)) {
                $results.hostStatus = Get-Content -LiteralPath $StatusFilePath -Raw | ConvertFrom-Json
            }
        }
        catch {
        }
    }

    return $results
}

$normalizedMountRoot = Normalize-MountRoot -Path $MountRoot
New-Item -ItemType Directory -Force -Path $OutputDir, $ScratchRoot | Out-Null

if ($Mode -eq "VerifyManifest") {
    $absoluteManifest = Resolve-AbsolutePath -Path $ExistingManifest
    $verification = Invoke-ManifestVerification -ManifestPath $absoluteManifest -StatusFilePath $StatusFile
    $verificationPath = Join-Path $OutputDir ("verify-{0}.json" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
    Write-JsonFile -Path $verificationPath -InputObject $verification
    Write-Output (ConvertTo-PrettyJson -InputObject $verification)
    if ($verification.status -ne "passed") {
        exit 1
    }
    exit 0
}

$manifestPath = Join-Path $OutputDir ("physical-rw-{0}-{1}.json" -f $Mode.ToLowerInvariant(), (Get-Date -Format "yyyyMMdd-HHmmss"))
if ($Mode -eq "ExplorerWorkflow") {
    $result = Invoke-ExplorerWorkflow `
        -NormalizedMountRoot $normalizedMountRoot `
        -ScratchDirectory $ScratchRoot `
        -ManifestPath $manifestPath `
        -RequestedLargeFileBytes $LargeFileBytes `
        -StatusFilePath $StatusFile
}
elseif ($Mode -eq "Performance") {
    $result = Invoke-PerformanceBenchmark `
        -NormalizedMountRoot $normalizedMountRoot `
        -ScratchDirectory $ScratchRoot `
        -ManifestPath $manifestPath `
        -RequestedFileCount $FileCount `
        -RequestedLargeFileBytes $LargeFileBytes `
        -RequestedSmallFileBytes $SmallFileBytes `
        -RequestedSmallFileHashSampleCount $SmallFileHashSampleCount `
        -StatusFilePath $StatusFile
}
else {
    $result = Invoke-PhysicalWorkload `
        -SelectedMode $Mode `
        -NormalizedMountRoot $normalizedMountRoot `
        -ScratchDirectory $ScratchRoot `
        -ManifestPath $manifestPath `
        -RequestedFileCount $FileCount `
        -RequestedLargeFileBytes $LargeFileBytes `
        -StatusFilePath $StatusFile
}

if ([System.IO.Path]::IsPathRooted($manifestPath)) {
    $result.manifest = [System.IO.Path]::GetFullPath($manifestPath)
}
else {
    $result.manifest = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $manifestPath))
}
Write-JsonFile -Path $manifestPath -InputObject $result
Write-Output (ConvertTo-PrettyJson -InputObject $result)
if ($result.status -ne "passed") {
    exit 1
}
