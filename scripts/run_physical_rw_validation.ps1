param(
    [ValidateSet("Smoke", "Storm", "VerifyManifest")]
    [string]$Mode = "Smoke",

    [string]$MountRoot = "E:\",

    [string]$ScratchRoot = "",

    [string]$OutputDir = "",

    [string]$StatusFile = "",

    [string]$ExistingManifest = "",

    [int]$FileCount = 180,

    [UInt64]$LargeFileBytes = 64MB,

    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot "artifacts\physical-rw-validation"
}
if ([string]::IsNullOrWhiteSpace($ScratchRoot)) {
    $ScratchRoot = Join-Path ([System.IO.Path]::GetTempPath()) "ApfsAccessPhysicalRw"
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
        [UInt64]$Bytes = 0,
        [int]$Files = 0,
        [object]$Detail = $null
    )

    $elapsedSeconds = [Math]::Max($Elapsed.TotalSeconds, 0.001)
    $metric = [ordered]@{
        name = $Name
        elapsedMs = [Math]::Round($Elapsed.TotalMilliseconds, 3)
        bytes = $Bytes
        files = $Files
        megabytesPerSecond = if ($Bytes -gt 0) { [Math]::Round(($Bytes / 1MB) / $elapsedSeconds, 3) } else { $null }
        filesPerSecond = if ($Files -gt 0) { [Math]::Round($Files / $elapsedSeconds, 3) } else { $null }
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
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "StatusFile was not found: $Path"
    }

    $status = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($status.writeBackend -ne "Native" `
        -or $status.nativeWriteSafetyState -ne "PilotReadWrite" `
        -or $status.recoveryActive -ne $false `
        -or $status.dirtyTransactionCount -ne 0) {
        throw "Native host is not ready for physical RW validation: $($status | ConvertTo-Json -Compress)"
    }
    return $status
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
        if (Test-Path -LiteralPath $deleteFile) {
            throw "Deleted file still exists: $deleteFile"
        }
        $results.deletedPaths += $deleteFile
        $deleteDir = Join-Path $apfsRoot "delete-me\subdir"
        New-Item -ItemType Directory -Force -Path $deleteDir | Out-Null
        New-PatternFile -Path (Join-Path $deleteDir "inside.bin") -Bytes 88888 -Seed 34
        Remove-Item -LiteralPath $deleteDir -Recurse -Force
        if (Test-Path -LiteralPath $deleteDir) {
            throw "Deleted directory still exists: $deleteDir"
        }
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
                Remove-Item -LiteralPath $apfsRoot -Recurse -Force
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
$result = Invoke-PhysicalWorkload `
    -SelectedMode $Mode `
    -NormalizedMountRoot $normalizedMountRoot `
    -ScratchDirectory $ScratchRoot `
    -ManifestPath $manifestPath `
    -RequestedFileCount $FileCount `
    -RequestedLargeFileBytes $LargeFileBytes `
    -StatusFilePath $StatusFile

$result.manifest = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $manifestPath))
Write-JsonFile -Path $manifestPath -InputObject $result
Write-Output (ConvertTo-PrettyJson -InputObject $result)
if ($result.status -ne "passed") {
    exit 1
}
