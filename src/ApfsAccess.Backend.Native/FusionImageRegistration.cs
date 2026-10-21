using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public sealed partial class NativeApfsBackend : IFusionImageBackend
{
    private sealed record RegisteredFusion(FusionImageProfile Profile, NativeFusionImageLaunch? Lease);
    private readonly ConcurrentDictionary<string, RegisteredFusion> _fusionImages = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, NativeFusionServiceSession> _fusionSessions = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, UnmountResult> _fusionRetired = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _fusionGate = new(1, 1);
    private int _fusionDraining;
    private static FusionImageSelection FusionSelection(FusionImageProfile p) => new(p.ContainerUuid, p.FusionUuid, p.VolumeUuid,
        p.VolumeOid, p.CheckpointXid, p.Members.Select(m => new FusionImageMemberSelection(m.Path, m.Role, m.StoreId, m.StoreOffset, m.StoreSize)).ToArray());
    private static FusionImageProfile CaptureFusionProfile(FusionImageProfile p, NativeFusionImageLaunch lease) => p with {
        Members = p.Members.Select((m, i) => m with { Identity = lease.Members[i].Identity }).ToArray() };
    private static bool SameFusionFile(string? a, string? b) => a is not null && b is not null &&
        a.Split(':').Length == 5 && b.Split(':').Length == 5 && a.Split(':').Take(4).SequenceEqual(b.Split(':').Take(4));

    public async Task RegisterFusionImageAsync(FusionImageProfile profile, CancellationToken token)
    {
        using var operation = AcquireLifecycleOperationLease();
        if (!profile.IsValid()) throw new ArgumentException("Invalid Fusion pair selectors.");
        // Native status and the retained journal namespace use main/Tier2
        // order even when the selector arrived in the opposite order.
        profile = profile with { Members = profile.Members.OrderBy(m => m.Role == "main" ? 0 : 1).ToArray() };
        await _fusionGate.WaitAsync(token).ConfigureAwait(false);
        NativeFusionImageLaunch? lease = null;
        try
        {
            RequireFusionRoot();
            if (_fusionImages.Count >= 16 || _fusionImages.Values.Any(r => r.Profile.ContainerUuid == profile.ContainerUuid ||
                r.Profile.Members.Any(a => profile.Members.Any(b => string.Equals(a.Path, b.Path, StringComparison.OrdinalIgnoreCase)))) ||
                _volumeCache.ContainsKey(profile.VolumeId) || profile.Members.Any(m => _deviceCandidates.Contains(m.Path, StringComparer.OrdinalIgnoreCase) ||
                    _encryptedImages.Values.Any(r => string.Equals(r.Profile.ImagePath, m.Path, StringComparison.OrdinalIgnoreCase))))
                throw new InvalidOperationException("Fusion pair overlaps an existing registered source.");
            lease = NativeFusionImageLaunch.Prepare(FusionSelection(profile), token);
            for (var i = 0; i < 2; ++i) if (profile.Members[i].Identity is {} expected && expected != lease.Members[i].Identity)
                throw new IOException("Fusion member differs from the selected file identity.");
            if (_fusionImages.Values.Any(r => r.Profile.Members.Any(a =>
                lease.Members.Any(b => SameFusionFile(a.Identity, b.Identity)))))
                throw new IOException("Fusion member aliases an already registered file identity.");
            profile = CaptureFusionProfile(profile, lease);
            if (!_fusionImages.TryAdd(profile.VolumeId, new(profile, lease))) throw new InvalidOperationException("Duplicate Fusion registration.");
            lease = null;
        }
        finally { lease?.Dispose(); _fusionGate.Release(); }
    }

    private VolumeInfo FusionVolume(RegisteredFusion r) => new(r.Profile.VolumeId, r.Profile.DeviceId, "Fusion image volume",
        SupportsReadWrite: true, SupportsNativeWrite: true, RecoveryIdentity: r.Profile.Contract,
        CatalogVolumeId: r.Profile.VolumeId, CatalogContainerUuid: r.Profile.ContainerUuid, CatalogVolumeObjectId: r.Profile.VolumeOid,
        CatalogDecision: ApfsCapabilityDecision.Readable, CatalogReasons: ["registered-fusion-explicit-owner"], CatalogAutoMountAllowed: false,
        CatalogVolumeUuid: r.Profile.VolumeUuid, RegisteredFusion: r.Profile.Snapshot());
    private string RequireFusionRoot()
    {
        var root = _options.ManagementJournalRoot ?? throw new InvalidOperationException("Configure a durable external management journal root before registering Fusion images.");
        root = NativeSnapshotBrowseLaunch.ValidateLocalPath(root);
        if (!Directory.Exists(root) || (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Fusion recovery root must be an existing ordinary local directory.");
        return root;
    }
    private string FusionRecoveryDirectory(FusionImageProfile p)
    {
        var stable = p with { CheckpointXid = 1, Members = p.Members.Select(m => m with { Identity = string.Join(':', m.Identity!.Split(':').Take(4)) }).ToArray() };
        var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(stable))));
        var path = Path.Combine(RequireFusionRoot(), "fusion", hash); Directory.CreateDirectory(path); return path;
    }

    public async Task<MountResult> MountFusionImageAsync(FusionImageProfile profile, CancellationToken token)
    {
        using var operation = AcquireLifecycleOperationLease();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, _disposeCts.Token);
        await _fusionGate.WaitAsync(linked.Token).ConfigureAwait(false);
        NativeFusionServiceSession? session = null;
        NativeFusionImageLaunch? acquired = null;
        try
        {
            if (!profile.IsValid() || !_fusionImages.TryGetValue(profile.VolumeId, out var r) || r.Profile.Contract != profile.Contract ||
                _fusionSessions.Values.Any(s => s.VolumeId == profile.VolumeId)) throw new InvalidOperationException("Fusion selection changed or a previous owner remains reserved.");
            if (string.IsNullOrWhiteSpace(_nativeFsHostPath) || !File.Exists(_nativeFsHostPath)) throw new FileNotFoundException("Native Fusion host is missing.");
            var lease = r.Lease ?? (acquired = NativeFusionImageLaunch.Prepare(FusionSelection(r.Profile), linked.Token));
            if (r.Lease is null)
            {
                for (var i = 0; i < 2; ++i) if (!SameFusionFile(r.Profile.Members[i].Identity, lease.Members[i].Identity))
                { lease.Dispose(); throw new IOException("Fusion member replacement refused before native startup."); }
            }
            var current = CaptureFusionProfile(r.Profile, lease);
            var recovery = FusionRecoveryDirectory(current);
            var directory = Path.Combine(recovery, "sessions", Guid.NewGuid().ToString("N"));
            _fusionImages[profile.VolumeId] = new(r.Profile, null);
            try { session = NativeFusionServiceSession.Start(r.Profile, lease, _nativeFsHostPath, directory, recovery); }
            catch { lease.Dispose(); throw; }
            acquired = null;
            if (!_fusionSessions.TryAdd(session.MountPoint, session)) throw new InvalidOperationException("Duplicate Fusion session directory.");
            using var startup = CancellationTokenSource.CreateLinkedTokenSource(linked.Token);
            startup.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(_options.NativeHostStartupTimeoutSeconds, 2, 60)));
            await session.WaitReadyAsync(startup.Token).ConfigureAwait(false);
            return new(true, session.MountPoint, null, MountAccessMode.ReadWrite, WriteEnabled: true, SafetyGateState: "FusionExactPairOwner",
                WriteBackend: "Native", CommitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint, NativeWriteReadiness: NativeWriteReadiness.CommitReady,
                NativeWriteEngineState: NativeWriteEngineState.Transactional, NativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated,
                NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            if (session is not null) await StopFusionSession_NoLock(session).ConfigureAwait(false);
            return new(false, session?.MountPoint, e.Message, MountAccessMode.ReadWrite, DiagnosticCode: "FusionAdmissionRefused",
                NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked);
        }
        finally { acquired?.Dispose(); _fusionGate.Release(); }
    }

    private async Task<UnmountResult> StopFusionSession_NoLock(NativeFusionServiceSession session)
    {
        var result = await session.StopAsync(GetLifecycleShutdownTimeout()).ConfigureAwait(false);
        if (result.HostOwnershipReleased && result.MountRemoved)
        {
            _fusionSessions.TryRemove(session.MountPoint, out _); _fusionRetired[session.MountPoint] = result;
            if (_fusionImages.TryGetValue(session.VolumeId, out var r))
            {
                var profile = r.Profile with { CheckpointXid = session.CheckpointXid };
                NativeFusionImageLaunch? retained = null;
                try
                {
                    retained = NativeFusionImageLaunch.Prepare(FusionSelection(profile));
                    for (var i = 0; i < 2; ++i) if (!SameFusionFile(profile.Members[i].Identity, retained.Members[i].Identity))
                        throw new IOException("Fusion member changed after owner retirement.");
                    _fusionImages[session.VolumeId] = new(CaptureFusionProfile(profile, retained), retained); retained = null;
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
                { _fusionImages[session.VolumeId] = new(profile, null); }
                finally { retained?.Dispose(); }
            }
        }
        return result;
    }
    private async Task<UnmountResult> UnmountFusionImageAsync(string mount, CancellationToken token)
    {
        using var operation = AcquireLifecycleOperationLease();
        await _fusionGate.WaitAsync(token).ConfigureAwait(false);
        try { return _fusionSessions.TryGetValue(mount, out var session) ? await StopFusionSession_NoLock(session).ConfigureAwait(false) :
            _fusionRetired.GetValueOrDefault(mount, new(false, mount, "Unknown Fusion mount owner.")); }
        finally { _fusionGate.Release(); }
    }
    private async Task<IReadOnlyList<MountedVolumeState>> FusionMountStatesAsync(CancellationToken token)
    {
        await _fusionGate.WaitAsync(token).ConfigureAwait(false);
        try { return _fusionSessions.Values.Select(s => s.ReadState()).ToArray(); }
        finally { _fusionGate.Release(); }
    }
    private void BeginFusionDrain()
    {
        if (Interlocked.Exchange(ref _fusionDraining, 1) != 0) return;
        _ = Task.Run(async () => {
            while (!_fusionSessions.IsEmpty)
            {
                await _fusionGate.WaitAsync().ConfigureAwait(false);
                try
                {
                    foreach (var session in _fusionSessions.Values)
                    {
                        try { await StopFusionSession_NoLock(session).ConfigureAwait(false); }
                        catch (Exception e) when (e is not OutOfMemoryException)
                        {
                            WriteLifecycleDiagnostic("fusion-drain-retry", session.MountPoint, null, e.Message);
                        }
                    }
                }
                finally { _fusionGate.Release(); }
                if (!_fusionSessions.IsEmpty) await Task.Delay(500).ConfigureAwait(false);
            }
            lock (_disposeFinalizationSync) CompleteDisposeIfNoHosts_NoLock();
        });
    }
}
