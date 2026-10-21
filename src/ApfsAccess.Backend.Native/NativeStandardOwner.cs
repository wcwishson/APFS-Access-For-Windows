using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ApfsAccess.Core;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

public sealed record NativeStandardSelection(string Image, string SourceIdentity, string VolumeIdentity,
    string ContainerUuid, string VolumeUuid, ulong VolumeObjectId, ulong CheckpointXid, string RecoveryIdentity);
public sealed record NativeStandardOwnerExit(bool ProcessExited, bool JobEmpty, bool NamespaceAbsent, int? ExitCode);

// The native owner grants mutation authority. This factory retains its exact
// launch and original recovery registration, without depending on an SMB provider.
public sealed class NativeStandardOwner : IAsyncDisposable
{
    private readonly SemaphoreSlim retirement = new(1, 1);
    private readonly List<SafeFileHandle> pins = [];
    private readonly string namespacePath;
    private readonly AnonymousPipeServerStream input, output;
    private readonly HostLifetimeSentinel lifetime;
    private readonly HostProcessGuardian.LaunchResult child;
    private readonly NativeOrdinaryImageOwnership.RetainedLaunch registration;
    private bool disposed;
    private NativeStandardOwnerExit? observedExit;
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<Task, Action> FailedLaunchRetentions = new();
    public NativeStandardSelection Selection { get; }
    public Stream ToOwner => input;
    public Stream FromOwner => output;
    public int ProcessId => checked((int)child.Guardian!.ProcessId);
    public long ProcessCreationTimeFileTimeUtc => child.Guardian!.CreationTimeFileTimeUtc;

    private NativeStandardOwner(NativeStandardSelection selection, string namespacePath,
        AnonymousPipeServerStream input, AnonymousPipeServerStream output, HostLifetimeSentinel lifetime,
        HostProcessGuardian.LaunchResult child, NativeOrdinaryImageOwnership.RetainedLaunch registration,
        List<SafeFileHandle> pins)
    {
        Selection = selection; this.namespacePath = namespacePath; this.input = input; this.output = output;
        this.lifetime = lifetime; this.child = child; this.registration = registration; this.pins = pins;
    }

    public static NativeStandardOwner Start(string image, string containerId, string volumeOid,
        string journalRoot, string spoolRoot, string recoveryRoot, string sessionDirectory,
        CancellationToken token = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        NativeApfsSnapshotReader.ValidateRequest(image, containerId, volumeOid);
        image = Path.GetFullPath(image);
        journalRoot = NativeSnapshotBrowseLaunch.ValidateLocalPath(journalRoot);
        spoolRoot = NativeSnapshotBrowseLaunch.ValidateLocalPath(spoolRoot);
        recoveryRoot = NativeSnapshotBrowseLaunch.ValidateLocalPath(recoveryRoot);
        foreach (var root in new[] { journalRoot, spoolRoot, recoveryRoot })
        {
            NativeApfsVolumeManagement.ValidateStoreRoot(root);
            if (root.Length > 140) throw new ArgumentException("Use persistent roots no longer than 140 characters.");
        }
        sessionDirectory = NativeSnapshotBrowseLaunch.ValidateLocalPath(sessionDirectory);
        var roots = new[] { journalRoot, spoolRoot, recoveryRoot, sessionDirectory };
        for (var i = 0; i < roots.Length; ++i)
            for (var j = i + 1; j < roots.Length; ++j)
                if (Within(roots[i], roots[j]) || Within(roots[j], roots[i]))
                    throw new ArgumentException("Use separate persistent roots and a new session directory.");
        if (roots.Any(root => Within(image, root))) throw new ArgumentException("Keep the source image outside the owned roots.");
        var host = Packaged("ApfsAccess.FsHost.exe");
        var observer = Packaged(NativeApfsObserver.ObserverExeName);
        NativeManagementJournalAdmission.RequireImage(journalRoot, image, "0");
        if (!CreateDirectoryW(sessionDirectory, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "The standard-share session directory must be new.");

        var pins = new List<SafeFileHandle>();
        AnonymousPipeServerStream? input = null, output = null;
        HostLifetimeSentinel? lifetime = null;
        NativeOrdinaryImageOwnership.RetainedLaunch? registration = null;
        HostProcessGuardian.LaunchResult? child = null;
        var stage = "PinDirectories";
        try
        {
            foreach (var path in roots.Append(Path.GetDirectoryName(image)!))
                pins.AddRange(PinWritableAncestors(Path.Combine(path, "held")));
            stage = "ObserveSource";
            using var source = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read);
            NativeApfsSnapshotReader.ValidateIdentity(source.SafeFileHandle, image);
            if (source.Length is < 1048576 or > 268435456 || source.Length % 4096 != 0)
                throw new ArgumentException("The initial standard-share profile supports whole ordinary images of 1-256 MiB.");
            var identity = NativeApfsVolumeManagement.SourceIdentity(source.SafeFileHandle, image, "0", false);
            var hash = Convert.ToHexStringLower(SHA256.HashDataAsync(source, token).GetAwaiter().GetResult());
            var result = new ProcessObserverRunner().Run(observer, NativeApfsObserver.BuildObserverArguments(image,
                NativeApfsObserver.DiscoveryProfile, NativeApfsObserver.BuildDeviceSlug(image)), token);
            if (result.ExitCode != 0) throw new IOException("Standard-share catalog observation refused.");
            var evidence = NativeApfsObserver.ParseAndValidateEvidence(result.StandardOutput);
            var selected = Select(evidence, image, source.Length, hash, containerId, volumeOid, identity);
            var recoveryIdentity = selected.RecoveryIdentity;
            // Initial profile reserves one source per root, so cloned UUIDs cannot
            // accidentally enroll another image in this original WAL namespace.
            var expectedRecord = "ordinary-image-" + identity[..64] + ".json";
            if (Directory.EnumerateFiles(journalRoot, "ordinary-image-*.json").Any(path =>
                !Path.GetFileName(path).Equals(expectedRecord, StringComparison.Ordinal)))
                throw new IOException("Standard-share journal root belongs to another ordinary image.");
            using var startup = HostStartupGate.Create(sessionDirectory);
            lifetime = HostLifetimeSentinel.Create(Path.Combine(sessionDirectory, "lifetime"));
            input = new(PipeDirection.Out, HandleInheritability.Inheritable);
            output = new(PipeDirection.In, HandleInheritability.Inheritable);
            var start = new ProcessStartInfo(host) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = sessionDirectory };
            start.Environment["APFSACCESS_SPOOL_ROOT"] = spoolRoot;
            start.Environment["APFSACCESS_RECOVERY_ROOT"] = recoveryRoot;
            var volume = new VolumeInfo(ApfsTopology.BuildVolumeId(selected.ContainerUuid, selected.VolumeObjectId), image,
                evidence.Topology.Volumes.Single(v => v.ContainerId == containerId && v.ObjectId == volumeOid).Name, true,
                SupportsNativeWrite: true, RecoveryIdentity: recoveryIdentity, CatalogVolumeId: ApfsTopology.BuildVolumeId(selected.ContainerUuid, selected.VolumeObjectId),
                CatalogContainerUuid: selected.ContainerUuid, CatalogVolumeObjectId: selected.VolumeObjectId,
                CatalogDecision: ApfsCapabilityDecision.Writable, CatalogVolumeUuid: selected.VolumeUuid);
            stage = "RegisterOriginalOwnership";
            registration = new(NativeOrdinaryImageOwnership.CaptureLaunch(start, journalRoot, image, "0", [volume]), "0");
            var noMount = Path.Combine(sessionDirectory, "no-kernel-mount");
            foreach (var argument in new[] { "--standard-stdio", "--device", image, "--device-offset", "0", "--volume", volume.VolumeName,
                "--container-id", selected.ContainerUuid, "--volume-oid", volumeOid, "--recovery-identity", recoveryIdentity,
                "--management-journal-directory", journalRoot, "--readwrite", "--write-backend", "Native",
                "--write-safety-level", "Strict", "--write-recovery-policy", "FailClosed", "--write-crash-replay-mode", "ReplayIfSafe",
                "--write-require-canonical-commit", "true", "--write-integrity-check-on-mount", "true", "--allow-legacy-scaffold-for-fixtures", "false",
                "--mount", noMount, "--status-file", Path.Combine(sessionDirectory, "native-status.json"),
                "--lifetime-file", lifetime.FilePath, "--startup-gate-file", startup.FilePath, "--startup-gate-token", startup.AuthorizationToken,
                "--parent-pid", Environment.ProcessId.ToString(CultureInfo.InvariantCulture) }) start.ArgumentList.Add(argument);
            registration.RequireBinding();
            if (NativeApfsVolumeManagement.SourceIdentity(source.SafeFileHandle, image, "0", false) != identity)
                throw new IOException("Standard-share source changed before exclusive handoff.");
            token.ThrowIfCancellationRequested();
            source.Dispose();
            stage = "StartGuardedOwner";
            child = HostProcessGuardian.StartWithStreams(start, startup, input.ClientSafePipeHandle, output.ClientSafePipeHandle);
            if (child.Guardian is null) throw new IOException("Standard-share requires the Windows retained owner guardian.");
            input.DisposeLocalCopyOfClientHandle(); output.DisposeLocalCopyOfClientHandle();
            return new(selected, noMount, input, output, lifetime, child, registration, pins);
        }
        catch (Exception error)
        {
            error.Data["StandardShareLaunchStage"] = stage;
            lifetime?.Dispose(); input?.Dispose(); output?.Dispose();
            if (child?.Guardian is {} guardian)
            {
                guardian.Dispose();
                var retainedChild = child; var retainedRegistration = registration;
                error.Data["StandardShareLaunchCleanup"] = ReleaseAfterOwnerAsync(guardian.OwnershipReleased, () => {
                    retainedChild.StartupStderr?.Dispose(); retainedChild.Process.Dispose();
                    retainedRegistration?.Dispose(); foreach (var pin in pins) pin.Dispose();
                });
            }
            else if (stage == "StartGuardedOwner")
            {
                // A failed launch without its retained owner cannot prove that
                // cleanup finished. Keep the original registration reserved.
                var proof = error.Data["HostStartupOwnershipReleased"] as Task ?? new TaskCompletionSource().Task;
                var retainedRegistration = registration;
                error.Data["StandardShareLaunchCleanup"] = ReleaseAfterOwnerAsync(proof, () => {
                    retainedRegistration?.Dispose(); foreach (var pin in pins) pin.Dispose();
                });
            }
            else
            {
                child?.StartupStderr?.Dispose(); child?.Process.Dispose();
                registration?.Dispose(); foreach (var pin in pins) pin.Dispose();
            }
            throw;
        }
    }

    internal static NativeStandardSelection Select(ApfsObserverEvidence evidence, string image, long size, string hash,
        string containerId, string oid, string identity)
    {
        var containers = evidence.Topology.Containers.Where(c => c.Id == containerId).ToArray();
        var volumes = evidence.Topology.Volumes.Where(v => v.ContainerId == containerId && v.ObjectId == oid).ToArray();
        if (evidence.Mode != "collect" || evidence.Profile != NativeApfsObserver.DiscoveryProfile ||
            evidence.Source.Kind != "image" || evidence.Source.Path != image || evidence.Source.SizeBytes != size ||
            evidence.Source.HashScope != "full" || evidence.Source.Sha256 != hash || evidence.SecondarySources!.Count != 0 ||
            evidence.Topology.Containers.Count != 1 || evidence.Topology.Stores.Count != 1 || evidence.Topology.Volumes.Count != 1 || containers.Length != 1 || volumes.Length != 1)
            throw new IOException("Standard-share requires one exact observed whole-image catalog selection.");
        var c = containers[0]; var v = volumes[0]; var store = evidence.Topology.Stores[0];
        if (c.Fusion || store.OffsetBytes != 0 || store.SizeBytes != size || c.StoreIds.Count != 1 || c.StoreIds[0] != store.Id ||
            c.VolumeIds.Count != 1 || c.VolumeIds[0] != v.Id ||
            v.Uuid.Length != 32 || v.Uuid.All(ch => ch == '0') || !v.NameUtf8Valid ||
            !NativeApfsSnapshotReader.IsU64(c.CheckpointXid, false) ||
            ApfsVolumeCapabilities.Evaluate(v, c).Decision != ApfsCapabilityDecision.Writable)
            throw new IOException("Standard-share profile requires an admitted ordinary unencrypted single-store volume.");
        var number = ulong.Parse(oid, CultureInfo.InvariantCulture);
        var recovery = NativeApfsBackend.BuildRecoveryIdentityFromComponents(null, c.Uuid, number, true)
            ?? throw new IOException("Standard-share canonical recovery identity unavailable.");
        return new(image, identity, $"apfs-vol:{c.Uuid}:{oid}:{v.Uuid}", c.Uuid, v.Uuid, number,
            ulong.Parse(c.CheckpointXid, CultureInfo.InvariantCulture), recovery);
    }

    public Task WaitForExitAsync(CancellationToken token = default) => child.Process.WaitForExitAsync(token);

    internal static Task ReleaseAfterOwnerAsync(Task originalOwnershipReleased, Action release)
    {
        var cleanup = ReleaseAsync();
        FailedLaunchRetentions.TryAdd(cleanup, release);
        _ = cleanup.ContinueWith(completed => {
            if (completed.IsCompletedSuccessfully) FailedLaunchRetentions.TryRemove(completed, out _);
        }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        return cleanup;
        async Task ReleaseAsync() { await originalOwnershipReleased.ConfigureAwait(false); release(); }
    }

    public async ValueTask<NativeStandardOwnerExit> ObserveExitAsync(CancellationToken token)
    {
        if (observedExit is {} terminal) return terminal;
        await child.Process.WaitForExitAsync(token).ConfigureAwait(false);
        var guardian = child.Guardian!;
        while (true)
        {
            token.ThrowIfCancellationRequested();
            var exited = guardian.TryObserveProcessExit(out var code);
            var empty = guardian.TryGetActiveProcessCount(out var active) && active == 0;
            var absent = !Directory.Exists(namespacePath) && !File.Exists(namespacePath);
            var result = new NativeStandardOwnerExit(exited, empty, absent, code);
            if (exited && empty && absent) return observedExit = result;
            await Task.Delay(25, token).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await retirement.WaitAsync().ConfigureAwait(false);
        try
        {
            if (disposed) return;
            lifetime.Dispose(); input.Dispose();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var proof = await ObserveExitAsync(deadline.Token).ConfigureAwait(false);
            if (!proof.ProcessExited || !proof.JobEmpty || !proof.NamespaceAbsent)
                throw new IOException("Standard-share original owner retirement remains reserved.");
            child.Guardian!.Dispose();
            await child.Guardian.OwnershipReleased.WaitAsync(deadline.Token).ConfigureAwait(false);
            output.Dispose(); child.StartupStderr?.Dispose(); child.Process.Dispose(); registration.Dispose();
            foreach (var pin in pins) pin.Dispose();
            disposed = true;
        }
        finally { retirement.Release(); }
    }

    private static string Packaged(string name)
    {
        var path = new[] { Path.Combine(AppContext.BaseDirectory, name), Path.Combine(AppContext.BaseDirectory, "native", name) }
            .FirstOrDefault(File.Exists) ?? throw new FileNotFoundException("Package the required native component: " + name);
        NativeApfsSnapshotReader.ValidateLocalFile(path); return path;
    }
    private static bool Within(string path, string root) => path.Equals(root, StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith(root.TrimEnd('\\', '/') + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    internal static List<SafeFileHandle> PinWritableAncestors(string path)
    {
        var result = new List<SafeFileHandle>();
        try
        {
            for (var directory = new FileInfo(path).Directory; directory is not null; directory = directory.Parent)
            {
                // Generic read enforces deny-delete on the directory. Share-write
                // permits atomic child replacement by the original journal owner.
                var handle = CreateFileW(directory.FullName, 0x80000000, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                if (handle.IsInvalid) { handle.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot pin the standard-share directories."); }
                result.Add(handle); NativeSnapshotBrowseLaunch.RequireAttributes(handle, directory: true);
            }
            return result;
        }
        catch { foreach (var handle in result) handle.Dispose(); throw; }
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateDirectoryW(string path, IntPtr security);
}
