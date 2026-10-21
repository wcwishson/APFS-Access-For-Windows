using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using ApfsAccess.Core;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Backend.Native;

// Directory mounts have their own namespace proof; generic service drive-letter
// normalization must never turn one of these paths into its backing drive.
internal sealed class NativeFusionServiceSession
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly NativeFusionImageLaunch launch;
    private readonly FusionImageProfile profile;
    private readonly HostLifetimeSentinel lifetime;
    private readonly HostProcessGuardian guardian;
    private readonly Process process;
    private readonly HostStartupStderr? stderr;
    private readonly string statusPath;
    private bool released;
    private UnmountResult? retirementProof;
    private UnmountResult? terminalResult;
    private JsonElement? lastStatus;
    public string MountPoint { get; }
    public string VolumeId => profile.VolumeId;
    public ulong CheckpointXid { get; private set; }
    public bool Admitted { get; private set; }

    private NativeFusionServiceSession(FusionImageProfile profile, NativeFusionImageLaunch launch, string directory,
        HostLifetimeSentinel lifetime, HostProcessGuardian.LaunchResult child)
    {
        this.profile = profile.Snapshot(); this.launch = launch; this.lifetime = lifetime;
        guardian = child.Guardian ?? throw new InvalidOperationException("Fusion requires a pinned Windows host guardian.");
        process = child.Process; stderr = child.StartupStderr; statusPath = Path.Combine(directory, "status.json");
        MountPoint = Path.Combine(directory, "mount"); CheckpointXid = profile.CheckpointXid;
    }

    internal static NativeFusionServiceSession Start(FusionImageProfile profile, NativeFusionImageLaunch launch,
        string host, string directory, string recovery)
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
                Path.Combine(directory, "status.json"), lifetime.FilePath, startup.FilePath, startup.AuthorizationToken, Environment.ProcessId)) psi.ArgumentList.Add(arg);
            launch.ReleaseForNativeOwner();
            var child = HostProcessGuardian.Start(psi, startup);
            return new(profile, launch, directory, lifetime, child);
        }
        catch { lifetime.Dispose(); throw; }
    }

    internal async Task WaitReadyAsync(CancellationToken token)
    {
        while (true)
        {
            token.ThrowIfCancellationRequested();
            if (guardian.TryObserveProcessExit(out _)) throw new IOException("Fusion host refused admission: " + ReadError());
            var state = ReadJson();
            if (state is {} s && launch.MatchesReadyStatus(s, checked((int)guardian.ProcessId)) &&
                ProbeMount(MountPoint, NativeFusionImageLaunch.ExpectedVolumeSerial(s.GetProperty("volumeLabel").GetString()!)))
            { lastStatus = s; CheckpointXid = s.GetProperty("fusionCheckpointXid").GetUInt64(); Admitted = true; return; }
            await Task.Delay(50, token).ConfigureAwait(false);
        }
    }

    internal MountedVolumeState ReadState()
    {
        var state = ReadJson();
        var healthy = !released && !guardian.TryObserveProcessExit(out _) && state is {} s && launch.MatchesReadyStatus(s, checked((int)guardian.ProcessId));
        if (healthy) { lastStatus = state; CheckpointXid = state!.Value.GetProperty("fusionCheckpointXid").GetUInt64(); }
        var current = state ?? lastStatus;
        ulong Water(string key) => current is {} c && c.TryGetProperty(key, out var n) && n.TryGetUInt64(out var v) ? v : 0;
        return new(profile.VolumeId, MountPoint, MountAccessMode.ReadWrite,
            VolumeName: current is {} c && c.TryGetProperty("volumeLabel", out var label) ? label.GetString() : "Fusion image volume",
            DeviceId: profile.DeviceId, DeviceDisplayName: "Fusion image pair", WriteBackend: "Native",
            CommitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
            NativeWriteReadiness: healthy ? NativeWriteReadiness.CommitReady : NativeWriteReadiness.RecoveryMode,
            NativeWriteEngineState: NativeWriteEngineState.Transactional, NativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
            RecoveryActive: !healthy, LastCommitXid: CheckpointXid, RecoveryReason: healthy ? null : "FusionOwnerOrDurabilityNotProven",
            NativeWriteSafetyState: healthy ? NativeWriteSafetyState.PilotReadWrite : NativeWriteSafetyState.RecoveryBlocked,
            DirtyTransactionCount: healthy ? 0 : 1, RecoveryIdentity: profile.Contract, MountReady: healthy,
            HostProcessId: checked((int)guardian.ProcessId), WalAcceptedSequence: Water("fusionAcceptedSequence"),
            WalApfsDurableSequence: Water("fusionDurableSequence"), WalCleanupSequence: Water("fusionCleanupSequence"),
            CatalogVolumeId: profile.VolumeId, CatalogContainerUuid: profile.ContainerUuid, CatalogVolumeObjectId: profile.VolumeOid,
            CatalogVolumeUuid: profile.VolumeUuid, RuntimeWatermarksKnown: healthy, RuntimeMutationPending: !healthy,
            HostProcessCreationTimeFileTimeUtc: guardian.CreationTimeFileTimeUtc);
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
                while ((!guardian.TryObserveProcessExit(out _) || !guardian.TryGetActiveProcessCount(out var count) || count != 0 || !MountAbsent(MountPoint)) && timer.Elapsed < timeout)
                    await Task.Delay(50).ConfigureAwait(false);
                if (!guardian.TryObserveProcessExit(out var exitCode) || !guardian.TryGetActiveProcessCount(out var active) || active != 0 || !MountAbsent(MountPoint))
                    return new(false, MountPoint, "Fusion owner or directory namespace remains reserved.");
                var terminal = ReadJson();
                var durable = exitCode == 0 && terminal is {} s && launch.MatchesTerminalStatus(s, checked((int)guardian.ProcessId));
                if (durable) CheckpointXid = terminal!.Value.GetProperty("fusionCheckpointXid").GetUInt64();
                var receipt = new { hostPid = guardian.ProcessId, creationTime = guardian.CreationTimeFileTimeUtc,
                    hostExitCode = exitCode, originalOwnerAbsent = true, mountAbsent = true, durable, checkpointXid = CheckpointXid,
                    profile, nativeStatus = terminal, utc = DateTime.UtcNow };
                using (var file = new FileStream(Path.Combine(Path.GetDirectoryName(statusPath)!, "retirement.json"),
                    FileMode.Create, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough))
                {
                    JsonSerializer.Serialize(file, receipt);
                    file.Flush(flushToDisk: true);
                }
                // A deferred guardian release closes its job handle. Retain
                // the exact proof before that release so retry never needs a
                // fresh PID handle or a query on the already closed job.
                retirementProof = new(durable, MountPoint, durable ? null : "Fusion durability remains pending; preserve its original journal.", true, true, durable);
            }
            guardian.Dispose();
            if (!guardian.OwnershipReleased.IsCompletedSuccessfully) return new(false, MountPoint, "Fusion guardian release remains pending.", true);
            if (!MountAbsent(MountPoint)) return new(false, MountPoint, "Fusion directory namespace release remains unproven.");
            stderr?.Dispose(); process.Dispose(); launch.Dispose(); released = true;
            return terminalResult = retirementProof;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or Win32Exception)
        { return new(false, MountPoint, "Fusion retirement remains reserved: " + e.Message); }
        finally { gate.Release(); }
    }

    private string ReadError() => ReadJson() is {} state && state.TryGetProperty("fusionLastFailure", out var error) ? error.GetString() ?? "unknown" : "no native admission status";
    private JsonElement? ReadJson()
    {
        try { using var file = new FileStream(statusPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (file.Length is <= 0 or > 2 * 1024 * 1024) return null;
            using var doc = JsonDocument.Parse(file); return doc.RootElement.Clone(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException) { return null; }
    }
    private static bool ProbeMount(string path, uint expected)
    {
        using var handle = CreateFileW(path, 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero); var fs = new StringBuilder(128);
        return !handle.IsInvalid && GetVolumeInformationByHandleW(handle, IntPtr.Zero, 0, out var serial, out _, out var flags, fs, 128) &&
            fs.ToString() == "APFS" && serial == expected && (flags & 0x80000) == 0;
    }
    private static bool MountAbsent(string path)
    {
        using var handle = CreateFileW(path, 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (handle.IsInvalid) return Marshal.GetLastWin32Error() is 2 or 3;
        var fs = new StringBuilder(128);
        return GetVolumeInformationByHandleW(handle, IntPtr.Zero, 0, out _, out _, out _, fs, 128) && fs.ToString() != "APFS";
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string path, IntPtr security);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle, IntPtr label, uint labelLength,
        out uint serial, out uint componentLength, out uint flags, StringBuilder filesystem, uint filesystemLength);
}
