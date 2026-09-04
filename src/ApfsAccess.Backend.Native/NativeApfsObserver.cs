using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

// Task-1 native catalog evidence seam (managed side consumes observer JSON
// opaquely; no managed APFS byte parsing here).
internal sealed record ObserverRunResult(int ExitCode, string StandardOutput, string StandardError);

internal interface IObserverRunner
{
    ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments);
}

internal sealed class ProcessObserverRunner : IObserverRunner
{
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(60);

    public long MaxOutputBytes { get; init; } = 64L * 1024 * 1024;

    public TimeSpan KillGracePeriod { get; init; } = TimeSpan.FromSeconds(5);

    public ObserverRunResult Run(string observerPath, IReadOnlyList<string> arguments)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(observerPath);
        ArgumentNullException.ThrowIfNull(arguments);
        if (MaxOutputBytes < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxOutputBytes), "MaxOutputBytes must be positive.");
        }

        var psi = new ProcessStartInfo
        {
            FileName = observerPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(observerPath) ?? AppContext.BaseDirectory,
        };
        foreach (var argument in arguments)
        {
            psi.ArgumentList.Add(argument);
        }

        // A10: both pipes drain concurrently on pool threads so a chatty
        // child can never wedge the parent in a synchronous ReadToEnd
        // deadlock (stdout full while we block on stderr or vice versa).
        using var process = new Process { StartInfo = psi };
        process.Start();
        var pid = TryGetProcessId(process);
        var stdoutEncoding = process.StandardOutput.CurrentEncoding;
        var stderrEncoding = process.StandardError.CurrentEncoding;
        var overrun = new OutputOverrunFlag();
        var stdoutDrain = Task.Run(() => DrainPipe(process.StandardOutput.BaseStream, process, overrun));
        var stderrDrain = Task.Run(() => DrainPipe(process.StandardError.BaseStream, process, overrun));

        var exited = process.WaitForExit((int)Math.Min(Timeout.TotalMilliseconds, int.MaxValue));
        if (!exited || overrun.IsSet)
        {
            if (!exited)
            {
                KillProcessTree(process);
                exited = process.WaitForExit((int)Math.Min(KillGracePeriod.TotalMilliseconds, int.MaxValue));
            }

            if (overrun.IsSet)
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe (pid {pid}) exceeded MaxOutputBytes ({MaxOutputBytes} bytes); output truncated and process tree killed.");
            }

            if (!exited || IsProcessAlive(process, pid))
            {
                throw new TimeoutException(
                    $"ApfsObserver.exe (pid {pid}) did not exit within {Timeout.TotalSeconds} seconds " +
                    $"and remained alive after the kill grace period.");
            }

            throw new TimeoutException(
                $"ApfsObserver.exe (pid {pid}) did not exit within {Timeout.TotalSeconds} seconds.");
        }

        try
        {
            Task.WaitAll([stdoutDrain, stderrDrain], KillGracePeriod);
        }
        catch
        {
            throw new TimeoutException(
                $"ApfsObserver.exe (pid {pid}) exited but its output pipes did not drain within {KillGracePeriod.TotalSeconds} seconds.");
        }

        if (overrun.IsSet)
        {
            throw new InvalidOperationException(
                $"ApfsObserver.exe (pid {pid}) exceeded MaxOutputBytes ({MaxOutputBytes} bytes); output truncated and process tree killed.");
        }

        return new ObserverRunResult(
            process.ExitCode,
            stdoutEncoding.GetString(stdoutDrain.Result),
            stderrEncoding.GetString(stderrDrain.Result));
    }

    // Reads one redirected pipe to end, enforcing the per-stream byte cap.
    // On overrun the whole tree is killed once (idempotent) and the flag is
    // set; the reader returns its prefix so the sibling drain can finish.
    private byte[] DrainPipe(Stream pipe, Process process, OutputOverrunFlag overrun)
    {
        try
        {
            using var buffer = new MemoryStream();
            var chunk = new byte[16 * 1024];
            while (true)
            {
                int read;
                try
                {
                    read = pipe.Read(chunk, 0, chunk.Length);
                }
                catch (IOException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }

                if (read <= 0)
                {
                    break;
                }

                buffer.Write(chunk, 0, read);
                if (buffer.Length > MaxOutputBytes)
                {
                    overrun.Set();
                    KillProcessTree(process);
                    break;
                }
            }

            return buffer.ToArray();
        }
        catch (IOException)
        {
            return Array.Empty<byte>();
        }
        catch (ObjectDisposedException)
        {
            return Array.Empty<byte>();
        }
    }

    private static void KillProcessTree(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
        }
        catch (NotSupportedException)
        {
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
    }

    private static bool IsProcessAlive(Process process, int pid)
    {
        try
        {
            if (!process.HasExited)
            {
                return true;
            }
        }
        catch (InvalidOperationException)
        {
            return false;
        }

        if (pid <= 0)
        {
            return false;
        }

        try
        {
            using var probe = Process.GetProcessById(pid);
            return !probe.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private static int TryGetProcessId(Process process)
    {
        try
        {
            return process.Id;
        }
        catch
        {
            return 0;
        }
    }

    private sealed class OutputOverrunFlag
    {
        private int _set;

        public bool IsSet => Volatile.Read(ref _set) != 0;

        public void Set() => Interlocked.Exchange(ref _set, 1);
    }
}

// Opaque catalog attachment selected for one legacy discovered volume.
internal sealed record CatalogAttachment(
    ulong VolumeObjectId,
    string? ContainerUuidHex,
    string CatalogVolumeId,
    ApfsCapabilityDecision Decision,
    IReadOnlyList<string> Reasons,
    bool AutoMountAllowed);

internal static class NativeApfsObserver
{
    public const string ObserverExeName = "ApfsObserver.exe";
    public const string PathOverrideVariable = "APFS_OBSERVER_PATH";
    public const string DiscoveryProfile = "managed-discovery";
    public const string UntrustedObserverSourceReason = "untrusted-observer-source";

    // Search order: APFS_OBSERVER_PATH env (wins) -> configured
    // NativeObserverPath -> AppContext.BaseDirectory/ApfsObserver.exe ->
    // BaseDirectory/native/ -> repo build output
    // build/ApfsAccess.ApfsRwEngine/Release/ -> artifacts/native/Release ->
    // artifacts/native/Debug (ancestor walk, mirroring the FsHost search).
    internal static string? ResolveNativeObserverPath(ServiceHostOptions options, string? baseDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        var fromEnv = FirstExistingPath(Environment.GetEnvironmentVariable(PathOverrideVariable));
        if (fromEnv is not null)
        {
            return fromEnv;
        }

        var configured = FirstExistingPath(options.NativeObserverPath);
        if (configured is not null)
        {
            return configured;
        }

        string baseDir;
        try
        {
            baseDir = Path.GetFullPath(baseDirectory ?? AppContext.BaseDirectory);
        }
        catch
        {
            return null;
        }

        var direct = new[]
        {
            Path.Combine(baseDir, ObserverExeName),
            Path.Combine(baseDir, "native", ObserverExeName),
        };
        foreach (var candidate in direct)
        {
            if (IsExistingFile(candidate))
            {
                return candidate;
            }
        }

        var relativeLayouts = new[]
        {
            Path.Combine("build", "ApfsAccess.ApfsRwEngine", "Release", ObserverExeName),
            Path.Combine("artifacts", "native", "Release", ObserverExeName),
            Path.Combine("artifacts", "native", "Debug", ObserverExeName),
        };
        var ancestor = baseDir;
        for (var level = 0; level < 8 && ancestor is not null; level++)
        {
            foreach (var relative in relativeLayouts)
            {
                var candidate = Path.Combine(ancestor, relative);
                if (IsExistingFile(candidate))
                {
                    return candidate;
                }
            }

            ancestor = Path.GetDirectoryName(ancestor);
        }

        return null;
    }

    // A10 provenance: packaged means the resolved observer ships with the app
    // (a file under the host base directory). Anything resolved from an
    // override source (env var, configured path, repo-build/dev output) is
    // untrusted for writability decisions.
    internal static bool IsPackagedObserverPath(string? observerPath, string? baseDirectory = null)
    {
        if (string.IsNullOrWhiteSpace(observerPath))
        {
            return false;
        }

        string baseDir;
        string fullPath;
        try
        {
            baseDir = Path.GetFullPath(baseDirectory ?? AppContext.BaseDirectory);
            fullPath = Path.GetFullPath(observerPath);
        }
        catch
        {
            return false;
        }

        baseDir = baseDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (fullPath.Length < baseDir.Length)
        {
            return false;
        }

        if (!fullPath.StartsWith(baseDir, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return fullPath.Length == baseDir.Length ||
               fullPath[baseDir.Length] is '\\' or '/' ||
               fullPath[baseDir.Length] == Path.DirectorySeparatorChar ||
               fullPath[baseDir.Length] == Path.AltDirectorySeparatorChar;
    }

    // A10 provenance cap: decisions derived from override-sourced evidence
    // are capped at Readable (never Writable). Packaged evidence keeps the
    // full evaluator decision. Non-writable decisions are already
    // conservative and pass through unchanged either way.
    internal static ApfsVolumeCapability ApplyObserverProvenanceCap(
        ApfsVolumeCapability capability, bool isPackaged)
    {
        ArgumentNullException.ThrowIfNull(capability);
        if (isPackaged || capability.Decision != ApfsCapabilityDecision.Writable)
        {
            return capability;
        }

        return new ApfsVolumeCapability(
            ApfsCapabilityDecision.Readable,
            [UntrustedObserverSourceReason, .. capability.Reasons],
            false);
    }

    internal static string BuildDeviceSlug(string devicePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(devicePath);
        var slash = devicePath.LastIndexOfAny(['/', '\\']);
        var baseName = slash < 0 ? devicePath : devicePath[(slash + 1)..];
        var slug = new string(baseName.Select(ch => IsSlugChar(ch) ? ch : '-').ToArray()).TrimStart('-');
        return IsValidSlug(slug) ? slug : "device";
    }

    internal static IReadOnlyList<string> BuildObserverArguments(
        string devicePath, string profile, string deviceSlug)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(devicePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(profile);
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceSlug);
        // Raw physical devices use --device (hashScope none); image files use
        // --image, mirroring the observer CLI contract.
        var sourceFlag = IsRawPhysicalDevicePath(devicePath) ? "--device" : "--image";
        return [sourceFlag, devicePath, "--profile", profile, "--mode", "collect", "--device-id", deviceSlug];
    }

    internal static ApfsObserverEvidence ParseAndValidateEvidence(string stdout)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stdout);
        ApfsObserverEvidence evidence;
        try
        {
            evidence = ApfsTopology.ParseEvidence(stdout);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"ApfsObserver.exe emitted malformed evidence JSON: {ex.Message}", ex);
        }

        if (!string.Equals(evidence.Format, ApfsTopology.EvidenceFormat, StringComparison.Ordinal) ||
            evidence.Version != ApfsTopology.EvidenceVersion ||
            !string.Equals(evidence.ObserverId, ApfsTopology.ObserverId, StringComparison.Ordinal) ||
            evidence.Synthetic ||
            string.IsNullOrWhiteSpace(evidence.Mode) ||
            string.IsNullOrWhiteSpace(evidence.Profile) ||
            evidence.Source is null ||
            evidence.SecondarySources is null ||
            evidence.Topology is null)
        {
            throw new InvalidOperationException(
                "ApfsObserver.exe emitted an evidence envelope that failed fail-closed validation.");
        }

        ValidateRelationalEvidence(evidence);
        return evidence;
    }

    // A9 managed relational validation: beyond envelope checks, verify full
    // topology consistency fail-closed. Every failure throws
    // InvalidOperationException (never NRE/ArgumentException).
    private static void ValidateRelationalEvidence(ApfsObserverEvidence evidence)
    {
        // ObserverVersion pattern ^1\.[0-9]+\.[0-9]+$ (schema).
        if (string.IsNullOrWhiteSpace(evidence.ObserverVersion) ||
            !Regex.IsMatch(evidence.ObserverVersion, @"^1\.[0-9]+\.[0-9]+$", RegexOptions.CultureInvariant))
        {
            throw new InvalidOperationException(
                "ApfsObserver.exe emitted evidence with invalid observerVersion.");
        }

        // Mode must be collect|fusion; profile non-empty (already) and consistent.
        if (!string.Equals(evidence.Mode, "collect", StringComparison.Ordinal) &&
            !string.Equals(evidence.Mode, "fusion", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"ApfsObserver.exe emitted evidence with invalid mode '{evidence.Mode}'.");
        }

        var topology = evidence.Topology;
        if (topology is null ||
            topology.Disks is null || topology.Partitions is null ||
            topology.Stores is null || topology.Containers is null ||
            topology.Volumes is null || topology.Groups is null)
        {
            throw new InvalidOperationException(
                "ApfsObserver.exe emitted evidence with missing topology collections.");
        }

        // Empty topology: disks/stores/containers/volumes each require >=1.
        if (topology.Disks.Count == 0 || topology.Stores.Count == 0 ||
            topology.Containers.Count == 0 || topology.Volumes.Count == 0)
        {
            throw new InvalidOperationException(
                "ApfsObserver.exe emitted evidence with empty topology.");
        }

        // Fusion mode requires >=2 stores.
        if (string.Equals(evidence.Mode, "fusion", StringComparison.Ordinal) &&
            topology.Stores.Count < 2)
        {
            throw new InvalidOperationException(
                "ApfsObserver.exe emitted fusion mode evidence with fewer than 2 stores.");
        }

        ValidateSources(evidence);

        // Duplicate IDs within each collection.
        RequireUniqueIds(topology.Disks.Select(static d => d?.Id), "disk");
        RequireUniqueIds(topology.Partitions.Select(static p => p?.Id), "partition");
        RequireUniqueIds(topology.Stores.Select(static s => s?.Id), "store");
        RequireUniqueIds(topology.Containers.Select(static c => c?.Id), "container");
        RequireUniqueIds(topology.Volumes.Select(static v => v?.Id), "volume");
        RequireUniqueIds(topology.Groups.Select(static g => g?.Id), "group");

        var diskIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var disk in topology.Disks)
        {
            if (disk is null || string.IsNullOrWhiteSpace(disk.Id) ||
                string.IsNullOrWhiteSpace(disk.DeviceIdentifier) ||
                disk.SizeBytes < 1)
            {
                throw new InvalidOperationException(
                    "ApfsObserver.exe emitted evidence with invalid disk record.");
            }

            if (!ApfsTopology.TryParseDiskId(disk.Id, out _))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid disk id '{disk.Id}'.");
            }

            if (disk.Uuid is not null && !IsLowerGuidD(disk.Uuid))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid disk uuid '{disk.Uuid}'.");
            }

            diskIds.Add(disk.Id);
        }

        var partitionIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var partition in topology.Partitions)
        {
            if (partition is null || string.IsNullOrWhiteSpace(partition.Id) ||
                string.IsNullOrWhiteSpace(partition.Uuid) ||
                string.IsNullOrWhiteSpace(partition.DiskId) ||
                string.IsNullOrWhiteSpace(partition.TypeGuid) ||
                string.IsNullOrWhiteSpace(partition.Usage))
            {
                throw new InvalidOperationException(
                    "ApfsObserver.exe emitted evidence with invalid partition record.");
            }

            if (!ApfsTopology.TryParsePartitionId(partition.Id, out var parsedGuid))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid partition id '{partition.Id}'.");
            }

            // Partition id guid must equal uuid field.
            if (!string.Equals(partition.Id, "apfs-part:" + partition.Uuid, StringComparison.Ordinal) ||
                !IsLowerGuidD(partition.Uuid))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with mismatched partition uuid '{partition.Uuid}'.");
            }

            if (!IsLowerGuidD(partition.TypeGuid))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid partition typeGuid '{partition.TypeGuid}'.");
            }

            if (partition.Index < 1 || partition.StartByte < 0 || partition.SizeBytes < 1)
            {
                throw new InvalidOperationException(
                    "ApfsObserver.exe emitted evidence with invalid partition range.");
            }

            if (!string.Equals(partition.Usage, "apfs", StringComparison.Ordinal) &&
                !string.Equals(partition.Usage, "other", StringComparison.Ordinal) &&
                !string.Equals(partition.Usage, "empty", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid partition usage '{partition.Usage}'.");
            }

            if (!diskIds.Contains(partition.DiskId))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with dangling partition.diskId '{partition.DiskId}'.");
            }

            partitionIds.Add(partition.Id);
        }

        var containerIds = new HashSet<string>(StringComparer.Ordinal);
        var containerById = new Dictionary<string, ApfsContainerRecord>(StringComparer.Ordinal);
        foreach (var container in topology.Containers)
        {
            if (container is null || string.IsNullOrWhiteSpace(container.Id) ||
                string.IsNullOrWhiteSpace(container.Uuid) ||
                container.StoreIds is null || container.VolumeIds is null ||
                container.CompatibleFeatureBits is null ||
                container.UnknownFeatureBits is null ||
                container.IncompatibleFeatureBits is null ||
                string.IsNullOrWhiteSpace(container.CheckpointXid))
            {
                throw new InvalidOperationException(
                    "ApfsObserver.exe emitted evidence with invalid container record.");
            }

            if (!ApfsTopology.TryParseContainerId(container.Id, out var containerHex))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid container id '{container.Id}'.");
            }

            if (!IsHex32(container.Uuid) ||
                !string.Equals(containerHex, container.Uuid, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid container uuid '{container.Uuid}'.");
            }

            if (container.BlockSizeBytes < 512)
            {
                throw new InvalidOperationException(
                    "ApfsObserver.exe emitted evidence with invalid container blockSizeBytes.");
            }

            if (container.StoreIds.Count == 0 || container.VolumeIds.Count == 0)
            {
                throw new InvalidOperationException(
                    "ApfsObserver.exe emitted evidence with empty container membership.");
            }

            if (!AreDistinct(container.StoreIds) || !AreDistinct(container.VolumeIds))
            {
                throw new InvalidOperationException(
                    "ApfsObserver.exe emitted evidence with duplicate container membership.");
            }

            if (!IsCanonicalU64(container.CheckpointXid))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid container checkpointXid '{container.CheckpointXid}'.");
            }

            ValidateFeatureBits(container.CompatibleFeatureBits, "container compatibleFeatureBits");
            ValidateFeatureBits(container.UnknownFeatureBits, "container unknownFeatureBits");
            ValidateFeatureBits(container.IncompatibleFeatureBits, "container incompatibleFeatureBits");
            if (container.ReadonlyFeatureBits is not null)
            {
                ValidateFeatureBits(container.ReadonlyFeatureBits, "container readonlyFeatureBits");
            }

            containerIds.Add(container.Id);
            containerById[container.Id] = container;
        }

        var volumeIds = new HashSet<string>(StringComparer.Ordinal);
        var volumeById = new Dictionary<string, ApfsVolumeRecord>(StringComparer.Ordinal);
        foreach (var volume in topology.Volumes)
        {
            if (volume is null || string.IsNullOrWhiteSpace(volume.Id) ||
                volume.Uuid is null ||
                string.IsNullOrWhiteSpace(volume.ObjectId) ||
                string.IsNullOrWhiteSpace(volume.ContainerId) ||
                volume.Name is null ||
                volume.Roles is null ||
                string.IsNullOrWhiteSpace(volume.CaseMode) ||
                string.IsNullOrWhiteSpace(volume.EncryptionMode) ||
                volume.CompatibleFeatureBits is null ||
                volume.UnknownFeatureBits is null ||
                volume.IncompatibleFeatureBits is null ||
                string.IsNullOrWhiteSpace(volume.SuperblockBlock) ||
                string.IsNullOrWhiteSpace(volume.SuperblockXid))
            {
                throw new InvalidOperationException(
                    "ApfsObserver.exe emitted evidence with invalid volume record.");
            }

            if (!ApfsTopology.TryParseVolumeId(volume.Id, out var volumeHex, out var volumeOid))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid volume id '{volume.Id}'.");
            }

            if (!ApfsTopology.TryParseContainerId(volume.ContainerId, out var volumeContainerHex))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid volume containerId '{volume.ContainerId}'.");
            }

            // Volume id hex must equal its container id hex; OID must equal objectId field.
            if (!string.Equals(volumeHex, volumeContainerHex, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with mismatched volume/container hex '{volume.Id}'.");
            }

            if (!IsCanonicalU64(volume.ObjectId) ||
                !string.Equals(volumeOid.ToString(CultureInfo.InvariantCulture), volume.ObjectId, StringComparison.Ordinal) ||
                volumeOid == 0)
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid volume objectId '{volume.ObjectId}'.");
            }

            // Volume uuid is empty-or-hex32 (schema).
            if (volume.Uuid.Length != 0 && !IsHex32(volume.Uuid))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid volume uuid '{volume.Uuid}'.");
            }

            if (!containerIds.Contains(volume.ContainerId))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with dangling volume.containerId '{volume.ContainerId}'.");
            }

            if (volume.Roles.Count == 0 || !AreDistinct(volume.Roles) ||
                volume.Roles.Any(static r => string.IsNullOrWhiteSpace(r)))
            {
                throw new InvalidOperationException(
                    "ApfsObserver.exe emitted evidence with invalid volume roles.");
            }

            if (volume.RoleRaw < 0)
            {
                throw new InvalidOperationException(
                    "ApfsObserver.exe emitted evidence with invalid volume roleRaw.");
            }

            if (!string.Equals(volume.CaseMode, "sensitive", StringComparison.Ordinal) &&
                !string.Equals(volume.CaseMode, "insensitive", StringComparison.Ordinal) &&
                !string.Equals(volume.CaseMode, "unknown", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid volume caseMode '{volume.CaseMode}'.");
            }

            if (!string.Equals(volume.EncryptionMode, "none", StringComparison.Ordinal) &&
                !string.Equals(volume.EncryptionMode, "password", StringComparison.Ordinal) &&
                !string.Equals(volume.EncryptionMode, "hardware-bound", StringComparison.Ordinal) &&
                !string.Equals(volume.EncryptionMode, "unknown", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid volume encryptionMode '{volume.EncryptionMode}'.");
            }

            if (!IsCanonicalU64(volume.SuperblockBlock) || !IsCanonicalU64(volume.SuperblockXid))
            {
                throw new InvalidOperationException(
                    "ApfsObserver.exe emitted evidence with invalid volume superblock fields.");
            }

            ValidateFeatureBits(volume.CompatibleFeatureBits, "volume compatibleFeatureBits");
            ValidateFeatureBits(volume.UnknownFeatureBits, "volume unknownFeatureBits");
            ValidateFeatureBits(volume.IncompatibleFeatureBits, "volume incompatibleFeatureBits");
            if (volume.ReadonlyFeatureBits is not null)
            {
                ValidateFeatureBits(volume.ReadonlyFeatureBits, "volume readonlyFeatureBits");
            }

            volumeIds.Add(volume.Id);
            volumeById[volume.Id] = volume;
        }

        foreach (var store in topology.Stores)
        {
            if (store is null || string.IsNullOrWhiteSpace(store.Id) ||
                string.IsNullOrWhiteSpace(store.Uuid) ||
                store.PartitionId is null ||
                string.IsNullOrWhiteSpace(store.ContainerId) ||
                store.OffsetBytes < 0 || store.SizeBytes < 1)
            {
                throw new InvalidOperationException(
                    "ApfsObserver.exe emitted evidence with invalid store record.");
            }

            if (!IsHex32(store.Uuid))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid store uuid '{store.Uuid}'.");
            }

            if (!containerIds.Contains(store.ContainerId))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with dangling store.containerId '{store.ContainerId}'.");
            }

            if (store.PartitionId.Length != 0 && !partitionIds.Contains(store.PartitionId))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with dangling store.partitionId '{store.PartitionId}'.");
            }
        }

        // Container.storeIds/volumeIds must exactly match actual members.
        var storesByContainer = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var store in topology.Stores)
        {
            if (store is null) continue;
            if (!storesByContainer.TryGetValue(store.ContainerId, out var set))
            {
                set = new HashSet<string>(StringComparer.Ordinal);
                storesByContainer[store.ContainerId] = set;
            }

            set.Add(store.Id);
        }

        var volumesByContainer = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var volume in topology.Volumes)
        {
            if (volume is null) continue;
            if (!volumesByContainer.TryGetValue(volume.ContainerId, out var set))
            {
                set = new HashSet<string>(StringComparer.Ordinal);
                volumesByContainer[volume.ContainerId] = set;
            }

            set.Add(volume.Id);
        }

        foreach (var container in topology.Containers)
        {
            if (container is null) continue;
            storesByContainer.TryGetValue(container.Id, out var actualStores);
            actualStores ??= new HashSet<string>(StringComparer.Ordinal);
            var declaredStores = new HashSet<string>(container.StoreIds, StringComparer.Ordinal);
            if (!declaredStores.SetEquals(actualStores))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with mismatched container.storeIds for '{container.Id}'.");
            }

            volumesByContainer.TryGetValue(container.Id, out var actualVolumes);
            actualVolumes ??= new HashSet<string>(StringComparer.Ordinal);
            var declaredVolumes = new HashSet<string>(container.VolumeIds, StringComparer.Ordinal);
            if (!declaredVolumes.SetEquals(actualVolumes))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with mismatched container.volumeIds for '{container.Id}'.");
            }
        }

        // Groups: >=2 distinct volumeIds, all naming volumes.
        var groupIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var group in topology.Groups)
        {
            if (group is null || string.IsNullOrWhiteSpace(group.Id) ||
                string.IsNullOrWhiteSpace(group.Uuid) ||
                group.VolumeIds is null)
            {
                throw new InvalidOperationException(
                    "ApfsObserver.exe emitted evidence with invalid group record.");
            }

            if (!ApfsTopology.TryParseGroupId(group.Id, out var groupHex) ||
                !IsHex32(group.Uuid) ||
                !string.Equals(groupHex, group.Uuid, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid group id/uuid '{group.Id}'.");
            }

            if (group.VolumeIds.Count < 2 || !AreDistinct(group.VolumeIds))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid group.volumeIds for '{group.Id}'.");
            }

            foreach (var volumeId in group.VolumeIds)
            {
                if (string.IsNullOrWhiteSpace(volumeId) || !volumeIds.Contains(volumeId))
                {
                    throw new InvalidOperationException(
                        $"ApfsObserver.exe emitted evidence with dangling group.volumeIds '{volumeId}'.");
                }
            }

            groupIds.Add(group.Id);
        }

        // Volume groupId, when present, must name an existing group.
        foreach (var volume in topology.Volumes)
        {
            if (volume is null) continue;
            if (volume.GroupId is not null && volume.GroupId.Length != 0 &&
                !groupIds.Contains(volume.GroupId))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with dangling volume.groupId '{volume.GroupId}'.");
            }
        }
    }

    private static void ValidateSources(ApfsObserverEvidence evidence)
    {
        ValidateSource(evidence.Source, "source");
        foreach (var secondary in evidence.SecondarySources!)
        {
            if (secondary is null)
            {
                throw new InvalidOperationException(
                    "ApfsObserver.exe emitted evidence with null secondarySource.");
            }

            ValidateSource(secondary, "secondarySources");
        }
    }

    private static void ValidateSource(ApfsEvidenceSource source, string where)
    {
        if (source is null || string.IsNullOrWhiteSpace(source.Kind) ||
            string.IsNullOrWhiteSpace(source.Path) ||
            string.IsNullOrWhiteSpace(source.HashScope) ||
            source.SizeBytes < 1)
        {
            throw new InvalidOperationException(
                $"ApfsObserver.exe emitted evidence with invalid {where} record.");
        }

        if (!string.Equals(source.Kind, "image", StringComparison.Ordinal) &&
            !string.Equals(source.Kind, "device", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"ApfsObserver.exe emitted evidence with invalid {where}.kind '{source.Kind}'.");
        }

        if (!string.Equals(source.HashScope, "full", StringComparison.Ordinal) &&
            !string.Equals(source.HashScope, "none", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"ApfsObserver.exe emitted evidence with invalid {where}.hashScope '{source.HashScope}'.");
        }

        var isFull = string.Equals(source.HashScope, "full", StringComparison.Ordinal);
        if (isFull)
        {
            if (string.IsNullOrWhiteSpace(source.Sha256) || !IsHex64(source.Sha256))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid {where}.sha256 for full hashScope.");
            }
        }
        else
        {
            if (source.Sha256 is not null)
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with unexpected {where}.sha256 for none hashScope.");
            }
        }
    }

    private static void RequireUniqueIds(IEnumerable<string?> ids, string what)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var id in ids)
        {
            if (string.IsNullOrWhiteSpace(id) || !seen.Add(id))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with duplicate or missing {what} id.");
            }
        }
    }

    private static bool AreDistinct(IReadOnlyList<string> values)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            if (value is null || !seen.Add(value))
            {
                return false;
            }
        }

        return true;
    }

    private static void ValidateFeatureBits(IReadOnlyList<string> bits, string what)
    {
        if (bits is null)
        {
            throw new InvalidOperationException(
                $"ApfsObserver.exe emitted evidence with null {what}.");
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var bit in bits)
        {
            if (string.IsNullOrWhiteSpace(bit) || bit.Length < 3 ||
                !bit.StartsWith("0x", StringComparison.Ordinal) ||
                !seen.Add(bit))
            {
                throw new InvalidOperationException(
                    $"ApfsObserver.exe emitted evidence with invalid {what} entry '{bit}'.");
            }

            for (var i = 2; i < bit.Length; i++)
            {
                if (!char.IsAsciiHexDigitLower(bit[i]))
                {
                    throw new InvalidOperationException(
                        $"ApfsObserver.exe emitted evidence with invalid {what} entry '{bit}'.");
                }
            }
        }
    }

    private static bool IsHex32(string? value)
    {
        if (value is null || value.Length != 32)
        {
            return false;
        }

        foreach (var ch in value)
        {
            if (!char.IsAsciiHexDigitLower(ch))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsHex64(string? value)
    {
        if (value is null || value.Length != 64)
        {
            return false;
        }

        foreach (var ch in value)
        {
            if (!char.IsAsciiHexDigitLower(ch))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsLowerGuidD(string? value)
    {
        return value is not null &&
               Guid.TryParseExact(value, "D", out var guid) &&
               string.Equals(guid.ToString("D", CultureInfo.InvariantCulture), value, StringComparison.Ordinal);
    }

    private static bool IsCanonicalU64(string? value)
    {
        return value is not null &&
               ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) &&
               string.Equals(parsed.ToString(CultureInfo.InvariantCulture), value, StringComparison.Ordinal);
    }

    // Catalog attach rules (freeze section 6, managed half): the observer
    // snapshot is consumed opaquely. Single-container single-volume snapshots
    // attach to the single legacy volume regardless of name; otherwise legacy
    // volumes match observer volumes by exact (ordinal) name, unique-or-null.
    // Ambiguous or unmatched entries stay null (FsHost enforces at mount).
    // Override-sourced evidence is provenance-capped (Writable -> Readable).
    internal static CatalogAttachment?[] ResolveCatalogAttachments(
        IReadOnlyList<string> legacyVolumeNames, ApfsTopologySnapshot? snapshot, bool observerEvidencePackaged = true)
    {
        ArgumentNullException.ThrowIfNull(legacyVolumeNames);
        var attachments = new CatalogAttachment?[legacyVolumeNames.Count];
        if (snapshot is null)
        {
            return attachments;
        }

        if (snapshot.Containers.Count == 1 &&
            snapshot.Volumes.Count == 1 &&
            legacyVolumeNames.Count == 1)
        {
            attachments[0] = TryBuildAttachment(snapshot.Volumes[0], snapshot, observerEvidencePackaged);
            return attachments;
        }

        for (var index = 0; index < legacyVolumeNames.Count; index++)
        {
            var matches = snapshot.Volumes
                .Where(volume => string.Equals(volume.Name, legacyVolumeNames[index], StringComparison.Ordinal))
                .ToArray();
            attachments[index] = matches.Length == 1
                ? TryBuildAttachment(matches[0], snapshot, observerEvidencePackaged)
                : null;
        }

        return attachments;
    }

    private static CatalogAttachment? TryBuildAttachment(
        ApfsVolumeRecord volume, ApfsTopologySnapshot snapshot, bool observerEvidencePackaged)
    {
        if (!ulong.TryParse(
                volume.ObjectId,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var objectId) ||
            objectId == 0)
        {
            return null;
        }

        var container = snapshot.Containers.FirstOrDefault(
            candidate => string.Equals(candidate.Id, volume.ContainerId, StringComparison.Ordinal));
        if (container is null)
        {
            return null;
        }

        var capability = ApfsVolumeCapabilities.Evaluate(volume, container);
        var capped = ApplyObserverProvenanceCap(capability, observerEvidencePackaged);
        return new CatalogAttachment(
            VolumeObjectId: objectId,
            ContainerUuidHex: container.Uuid,
            CatalogVolumeId: volume.Id,
            Decision: capped.Decision,
            Reasons: capped.Reasons,
            AutoMountAllowed: capped.AutoMountAllowed);
    }

    private static string? FirstExistingPath(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return null;
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(candidate);
        }
        catch
        {
            return null;
        }

        return File.Exists(fullPath) ? fullPath : null;
    }

    private static bool IsExistingFile(string candidate)
    {
        try
        {
            return File.Exists(candidate);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsSlugChar(char ch)
        => char.IsAsciiLetterOrDigit(ch) || ch is '_' or '.' or '-';

    private static bool IsValidSlug(string? slug)
        => !string.IsNullOrWhiteSpace(slug) &&
           slug.Length <= 128 &&
           slug.All(IsSlugChar);

    private static bool IsRawPhysicalDevicePath(string path)
        => !string.IsNullOrWhiteSpace(path) &&
           (path.StartsWith(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"\\?\PhysicalDrive", StringComparison.OrdinalIgnoreCase));
}
