using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using ApfsAccess.Cli;
using ApfsAccess.Core;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

internal sealed class NativeEncryptedImageServiceSession
{
    internal sealed record Observation(ulong Checkpoint, ulong Accepted, ulong Durable, ulong Cleaned, int DirtyTransactions, string Label);
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly object observationSync = new();
    private readonly NativeEncryptedImageWriteLaunch launch;
    private readonly HostLifetimeSentinel lifetime;
    private readonly HostProcessGuardian guardian;
    private readonly Process process;
    private readonly HostStartupStderr? stderr;
    private readonly string statusPath;
    private bool released;
    private UnmountResult? retirementProof;
    private UnmountResult? terminalResult;
    private Observation? last;
    public string MountPoint { get; }
    public string VolumeId => launch.Profile.VolumeId;
    public ulong CheckpointXid => LastObserved()?.Checkpoint ?? launch.Profile.CheckpointXid;

    private NativeEncryptedImageServiceSession(NativeEncryptedImageWriteLaunch launch, string directory,
        HostLifetimeSentinel lifetime, HostProcessGuardian.LaunchResult child)
    {
        this.launch = launch; this.lifetime = lifetime;
        guardian = child.Guardian ?? throw new InvalidOperationException("An encrypted writer requires an exact Windows child guardian.");
        process = child.Process; stderr = child.StartupStderr;
        statusPath = Path.Combine(directory, "status.json"); MountPoint = Path.Combine(directory, "mount");
    }

    internal static NativeEncryptedImageServiceSession Start(NativeEncryptedImageWriteLaunch launch,
        string host, string directory, string recovery, SupervisedCredential credential)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        foreach (var path in new[] { host, directory, recovery }) NativeSnapshotBrowseLaunch.ValidateLocalPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(directory)!);
        if (!CreateDirectoryW(directory, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
        using var startup = HostStartupGate.Create(directory);
        var lifetime = HostLifetimeSentinel.Create(Path.Combine(directory, "lifetime"));
        try
        {
            var psi = new ProcessStartInfo(host) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = directory };
            foreach (var arg in launch.BuildHostArguments(Path.Combine(directory, "mount"), recovery,
                Path.Combine(directory, "status.json"), lifetime.FilePath, startup.FilePath, startup.AuthorizationToken, Environment.ProcessId))
                psi.ArgumentList.Add(arg);
            credential.CreateChildPipe();
            return new(launch, directory, lifetime, HostProcessGuardian.StartWithCredential(psi, startup, credential.Reader));
        }
        catch { lifetime.Dispose(); throw; }
    }

    // The backend registers the guardian before sending bytes so every refusal has an owned stop path.
    internal void SendCredential(SupervisedCredential credential, CancellationToken token)
    {
        credential.ReleaseLocalReader();
        credential.Send(token, () => { if (guardian.TryObserveProcessExit(out _)) throw new IOException("Encrypted host exited before credential handoff."); });
    }

    internal async Task WaitReadyAsync(CancellationToken token)
    {
        while (true)
        {
            token.ThrowIfCancellationRequested(); launch.RequireUnchanged();
            if (guardian.TryObserveProcessExit(out _)) throw new IOException("Encrypted native admission refused the selected profile.");
            var status = ReadJson();
            if (status is {} s && TryAdmitObservation(s, false, out var observed) &&
                observed!.Accepted == observed.Cleaned && observed.DirtyTransactions == 0 && ProbeMount(MountPoint))
                return;
            await Task.Delay(50, token).ConfigureAwait(false);
        }
    }

    internal MountedVolumeState ReadState()
    {
        var status = ReadJson();
        Observation? observed = null;
        var healthy = !released && !guardian.TryObserveProcessExit(out _) && status is {} s &&
            TryAdmitObservation(s, false, out observed);
        var current = observed ?? LastObserved();
        var pending = current is null || current.Accepted > current.Cleaned || current.DirtyTransactions > 0;
        var p = launch.Profile;
        return new(p.VolumeId, MountPoint, MountAccessMode.ReadWrite,
            VolumeName: current?.Label ?? "Encrypted image", DeviceId: p.ImagePath, DeviceDisplayName: "Encrypted image",
            WriteBackend: "Native", CommitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            NativeWriteReadiness: healthy ? NativeWriteReadiness.CommitReady : NativeWriteReadiness.RecoveryMode,
            NativeWriteEngineState: NativeWriteEngineState.Transactional,
            NativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            RecoveryActive: !healthy, LastCommitXid: current?.Checkpoint,
            RecoveryReason: healthy ? null : "EncryptedOwnerOrDurabilityNotProven",
            NativeWriteSafetyState: healthy ? NativeWriteSafetyState.PilotReadWrite : NativeWriteSafetyState.RecoveryBlocked,
            DirtyTransactionCount: Math.Max(current?.DirtyTransactions ?? 0, pending || !healthy ? 1 : 0), RecoveryIdentity: p.Contract, MountReady: healthy,
            HostProcessId: checked((int)guardian.ProcessId), HostProcessCreationTimeFileTimeUtc: guardian.CreationTimeFileTimeUtc,
            WalAcceptedSequence: current?.Accepted ?? 0, WalApfsDurableSequence: current?.Durable ?? 0,
            WalCleanupSequence: current?.Cleaned ?? 0, RuntimeWatermarksKnown: healthy, RuntimeMutationPending: pending,
            CatalogVolumeId: p.VolumeId, CatalogContainerUuid: p.ContainerUuid, CatalogVolumeObjectId: p.VolumeObjectId,
            CatalogVolumeUuid: p.VolumeUuid);
    }

    internal async Task<UnmountResult> StopAsync(TimeSpan timeout)
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (released) return terminalResult!;
            lifetime.Dispose();
            if (retirementProof is null)
            {
                var timer = Stopwatch.StartNew();
                while ((!guardian.TryObserveProcessExit(out _) || !guardian.TryGetActiveProcessCount(out var n) || n != 0 || !MountAbsent(MountPoint)) && timer.Elapsed < timeout)
                    await Task.Delay(50).ConfigureAwait(false);
                if (!guardian.TryObserveProcessExit(out var exitCode) || !guardian.TryGetActiveProcessCount(out var active) || active != 0 || !MountAbsent(MountPoint))
                    return new(false, MountPoint, "Encrypted owner or directory namespace remains reserved.");
                var terminal = ReadJson();
                Observation? observed = null;
                var clean = exitCode == 0 && terminal is {} s && TryAdmitObservation(s, true, out observed);
                try { launch.RequireUnchanged(); }
                catch (Exception e) when (e is IOException or Win32Exception or UnauthorizedAccessException) { clean = false; }
                using (var file = new FileStream(Path.Combine(Path.GetDirectoryName(statusPath)!, "retirement.json"),
                    FileMode.Create, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough))
                {
                    JsonSerializer.Serialize(file, new {
                        hostPid = guardian.ProcessId, creationTime = guardian.CreationTimeFileTimeUtc, hostExitCode = exitCode,
                        originalOwnerAbsent = true, mountAbsent = true, durable = clean, checkpointXid = clean ? observed!.Checkpoint : (ulong?)null,
                        profile = launch.Profile, nativeStatus = terminal, utc = DateTime.UtcNow });
                    file.Flush(flushToDisk: true);
                }
                // Guardian disposal may close the job before its asynchronous release
                // finishes. Keep the exact stop proof for the subsequent retry.
                retirementProof = new(clean, MountPoint, clean ? null : "Encrypted durability remains unproved; preserve the original recovery storage.", true, true, clean);
            }
            guardian.Dispose();
            if (!guardian.OwnershipReleased.IsCompletedSuccessfully) return new(false, MountPoint, "Encrypted guardian release remains pending.", true);
            if (!MountAbsent(MountPoint)) return new(false, MountPoint, "Encrypted directory namespace release remains unproven.");
            stderr?.Dispose(); process.Dispose(); released = true;
            return terminalResult = retirementProof;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or Win32Exception)
        { return new(false, MountPoint, "Encrypted retirement remains reserved: " + e.Message); }
        finally { gate.Release(); }
    }

    private Observation? LastObserved()
    { lock (observationSync) return last; }

    internal bool ObserveRetiredOwnerAbsent()
    {
        if (!released || terminalResult is not { Success: true, HostOwnershipReleased: true, MountRemoved: true, PendingDurabilityCleared: true } ||
            !guardian.OwnershipReleased.IsCompletedSuccessfully || !MountAbsent(MountPoint)) return false;
        try
        {
            using var current = Process.GetProcessById(checked((int)guardian.ProcessId));
            return current.HasExited || current.StartTime.ToUniversalTime().ToFileTimeUtc() != guardian.CreationTimeFileTimeUtc;
        }
        catch (ArgumentException) { return true; }
        catch (Exception e) when (e is Win32Exception or InvalidOperationException or NotSupportedException) { return false; }
    }

    private bool TryAdmitObservation(JsonElement status, bool terminal, out Observation? observed)
    {
        lock (observationSync)
        {
            if (!TryObserve(launch.Profile, status, checked((int)guardian.ProcessId), terminal, out observed, last)) return false;
            last = observed;
            return true;
        }
    }

    internal static bool TryObserve(EncryptedImageProfile p, JsonElement s, int hostPid, bool terminal, out Observation? result,
        Observation? prior = null)
    {
        result = null;
        try
        {
            if (!p.Writable || !p.IsValid() || hostPid <= 0 || s.GetProperty("hostPid").GetInt32() != hostPid ||
                s.GetProperty("mountReady").GetBoolean() == terminal || s.GetProperty("explicitReadOnly").GetBoolean() ||
                s.GetProperty("immutableEncryptedImage").GetBoolean() ||
                s.GetProperty("encryptedSourceId").GetString() != p.SourceId ||
                s.GetProperty("encryptedContainerUuid").GetString() != Guid.Parse(p.ContainerUuid).ToString("N") ||
                s.GetProperty("encryptedVolumeUuid").GetString() != Guid.Parse(p.VolumeUuid).ToString("N") ||
                s.GetProperty("encryptedVolumeOid").GetUInt64() != p.VolumeObjectId ||
                s.GetProperty("encryptedSelectionCheckpointXid").GetUInt64() != p.CheckpointXid ||
                s.GetProperty("encryptedFailureReason").GetString() != "None" ||
                s.GetProperty("encryptedFailureTickMs").GetUInt64() != 0 ||
                !s.GetProperty("walRecoveryStateValid").GetBoolean() ||
                s.GetProperty("encryptedHealth").GetString() != (terminal ? "StoppingReadWrite" : "ReadWrite")) return false;
            if (!terminal && (s.GetProperty("writeBackend").GetString() != "Native" ||
                s.GetProperty("commitModel").GetString() != "CanonicalApfsCheckpoint" ||
                s.GetProperty("nativeWriteReadiness").GetString() != "CommitReady")) return false;
            var xid = s.GetProperty("encryptedCheckpointXid").GetUInt64();
            var accepted = s.GetProperty("walAcceptedSequence").GetUInt64();
            var durable = s.GetProperty("walApfsDurableSequence").GetUInt64();
            var cleaned = s.GetProperty("walCleanupSequence").GetUInt64();
            var dirty = s.GetProperty("dirtyTransactionCount").GetInt32();
            if (xid < p.CheckpointXid || accepted < durable || durable < cleaned || dirty < 0 ||
                terminal && (accepted != cleaned || dirty != 0)) return false;
            // Continuation preserves the original sequence space. A stale status
            // file cannot replace a newer observed publication or retirement.
            if (prior is not null && (xid < prior.Checkpoint || accepted < prior.Accepted ||
                durable < prior.Durable || cleaned < prior.Cleaned)) return false;
            result = new(xid, accepted, durable, cleaned, dirty, s.GetProperty("volumeLabel").GetString() ?? "Encrypted image");
            return true;
        }
        catch (Exception e) when (e is KeyNotFoundException or InvalidOperationException or FormatException or OverflowException) { return false; }
    }

    private JsonElement? ReadJson()
    {
        try
        {
            using var file = new FileStream(statusPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (file.Length is <= 0 or > 2 * 1024 * 1024) return null;
            using var doc = JsonDocument.Parse(file); return doc.RootElement.Clone();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException) { return null; }
    }
    private static bool ProbeMount(string path)
    {
        using var file = CreateFileW(path, 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        var fs = new StringBuilder(128);
        return !file.IsInvalid && GetVolumeInformationByHandleW(file, IntPtr.Zero, 0, out _, out _, out var flags, fs, 128) &&
            fs.ToString() == "APFS" && (flags & 0x80000) == 0;
    }
    private static bool MountAbsent(string path)
    {
        using var file = CreateFileW(path, 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (file.IsInvalid) return Marshal.GetLastWin32Error() is 2 or 3;
        var fs = new StringBuilder(128);
        return GetVolumeInformationByHandleW(file, IntPtr.Zero, 0, out _, out _, out _, fs, 128) && fs.ToString() != "APFS";
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string path, IntPtr security);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformationByHandleW(SafeFileHandle file, IntPtr label, uint labelLength,
        out uint serial, out uint componentLength, out uint flags, StringBuilder filesystem, uint filesystemLength);
}
