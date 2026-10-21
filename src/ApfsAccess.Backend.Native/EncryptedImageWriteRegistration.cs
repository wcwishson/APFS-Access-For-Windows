using System.Collections.Concurrent;
using ApfsAccess.Cli;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public sealed partial class NativeApfsBackend : IEncryptedImageLockObserver
{
    private sealed record CleanRetiredWriter(EncryptedImageProfile Profile, NativeEncryptedImageServiceSession Session, string ClosedIdentity);
    private readonly ConcurrentDictionary<string, CleanRetiredWriter> _encryptedCleanRetirements = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, NativeEncryptedImageServiceSession> _encryptedWriteSessions = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, UnmountResult> _encryptedWriteRetired = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _encryptedWriteGate = new(1, 1);
    private int _encryptedWriteDraining;

    private async Task<MountResult> UnlockWritableEncryptedImageAsync(MountRequest request, EncryptedImageProfile profile,
        SupervisedCredential credential, CancellationToken token)
    {
        using var operation = AcquireLifecycleOperationLease();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, _disposeCts.Token);
        await _encryptedWriteGate.WaitAsync(linked.Token).ConfigureAwait(false);
        NativeEncryptedImageServiceSession? session = null;
        try
        {
            if (!_options.EnableNativeWrite || request.AccessMode != MountAccessMode.ReadWrite ||
                request.VolumeId != profile.VolumeId || !profile.Writable || !profile.IsValid() ||
                !_encryptedImages.TryGetValue(profile.VolumeId, out var r) || r.Profile != profile ||
                r.WriteLease is null || _encryptedWriteSessions.Values.Any(s => s.VolumeId == profile.VolumeId))
                throw new InvalidOperationException("Encrypted writable selection changed or a prior owner remains reserved.");
            if (string.IsNullOrWhiteSpace(_nativeFsHostPath) || !File.Exists(_nativeFsHostPath))
                throw new FileNotFoundException("Native encrypted image host is missing.");
            r.WriteLease.RequireUnchanged();
            _encryptedCleanRetirements.TryRemove(profile.VolumeId, out _);
            var recovery = r.WriteLease.RecoveryDirectory(_options.ManagementJournalRoot!);
            var directory = Path.Combine(recovery, "sessions", Guid.NewGuid().ToString("N"));
            session = NativeEncryptedImageServiceSession.Start(r.WriteLease, _nativeFsHostPath, directory, recovery, credential);
            if (!_encryptedWriteSessions.TryAdd(session.MountPoint, session)) throw new InvalidOperationException("Duplicate encrypted session directory.");
            using var startup = CancellationTokenSource.CreateLinkedTokenSource(linked.Token);
            startup.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(_options.NativeHostStartupTimeoutSeconds, 2, 60)));
            session.SendCredential(credential, startup.Token);
            await session.WaitReadyAsync(startup.Token).ConfigureAwait(false);
            startup.Token.ThrowIfCancellationRequested();
            var state = session.ReadState();
            if (!state.MountReady || state.RecoveryActive || state.RuntimeWatermarksKnown != true)
                throw new IOException("Encrypted owner readiness changed before admission completed.");
            return new(true, session.MountPoint, null, MountAccessMode.ReadWrite, WriteEnabled: true, SafetyGateState: "EncryptedExactImageOwner",
                WriteBackend: "Native", CommitModel: NativeWriteCommitModel.CanonicalApfsCheckpoint,
                NativeWriteReadiness: NativeWriteReadiness.CommitReady, NativeWriteEngineState: NativeWriteEngineState.Transactional,
                NativeWriteValidationState: NativeWriteValidationState.CanonicalImageValidated, NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
                MountReady: true, HostProcessId: state.HostProcessId, WalAcceptedSequence: state.WalAcceptedSequence,
                WalApfsDurableSequence: state.WalApfsDurableSequence, WalCleanupSequence: state.WalCleanupSequence, LastCommitXid: state.LastCommitXid);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            if (session is not null) await StopEncryptedWriteSession_NoLock(session).ConfigureAwait(false);
            return new(false, session?.MountPoint, "Encrypted writable admission refused: " + e.Message, MountAccessMode.ReadWrite,
                DiagnosticCode: "EncryptedImageWritableAdmissionRefused", NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked);
        }
        finally { _encryptedWriteGate.Release(); }
    }

    private async Task<UnmountResult> StopEncryptedWriteSession_NoLock(NativeEncryptedImageServiceSession session)
    {
        var result = await session.StopAsync(GetLifecycleShutdownTimeout()).ConfigureAwait(false);
        if (result.HostOwnershipReleased && result.MountRemoved)
        {
            _encryptedWriteSessions.TryRemove(session.MountPoint, out _);
            _encryptedWriteRetired[session.MountPoint] = result;
            if (result.Success && result.PendingDurabilityCleared && _encryptedImages.TryGetValue(session.VolumeId, out var r))
            {
                var next = r.Profile with { CheckpointXid = session.CheckpointXid };
                NativeEncryptedImageWriteLaunch? pin = null;
                try
                {
                    pin = NativeEncryptedImageWriteLaunch.Prepare(next);
                    _ = pin.RecoveryDirectory(_options.ManagementJournalRoot!);
                    var closedIdentity = CaptureClosedWriterIdentity(pin);
                    _encryptedImages[session.VolumeId] = new(next, null, pin); pin = null;
                    _volumeCache[session.VolumeId] = RegisteredVolume(next);
                    _encryptedCleanRetirements[session.VolumeId] = new(next, session, closedIdentity);
                    r.WriteLease?.Dispose();
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
                { _encryptionStates[session.VolumeId] = EncryptedVolumeState.Failed; }
                finally { pin?.Dispose(); }
            }
        }
        return result;
    }

    private static string CaptureClosedWriterIdentity(NativeEncryptedImageWriteLaunch pin)
    {
        using var read = File.OpenHandle(pin.Profile.ImagePath, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.RandomAccess);
        pin.RequireUnchanged();
        return ImageIdentity(read);
    }

    public async Task<EncryptedImageLockObservation> ObserveLockedImageAsync(EncryptedImageProfile profile, CancellationToken token)
    {
        using var operation = AcquireLifecycleOperationLease();
        await _encryptedWriteGate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            token.ThrowIfCancellationRequested();
            if (!profile.Writable || !profile.IsValid() ||
                !_encryptedImages.TryGetValue(profile.VolumeId, out var registered) || registered.Profile != profile || registered.WriteLease is null ||
                _encryptedWriteSessions.Values.Any(s => s.VolumeId == profile.VolumeId) || _mounts.Values.Any(m => m.VolumeId == profile.VolumeId) ||
                !_encryptedCleanRetirements.TryGetValue(profile.VolumeId, out var retired) || retired.Profile != profile ||
                !retired.Session.ObserveRetiredOwnerAbsent() ||
                CaptureClosedWriterIdentity(registered.WriteLease) != retired.ClosedIdentity)
                return EncryptedImageLockObservation.Unproven;
            return EncryptedImageLockObservation.AlreadyLocked;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or ObjectDisposedException)
        { return EncryptedImageLockObservation.Unproven; }
        finally { _encryptedWriteGate.Release(); }
    }

    private async Task<UnmountResult> UnmountEncryptedWriteImageAsync(string mount, CancellationToken token)
    {
        using var operation = AcquireLifecycleOperationLease();
        await _encryptedWriteGate.WaitAsync(token).ConfigureAwait(false);
        try { return _encryptedWriteSessions.TryGetValue(mount, out var session) ? await StopEncryptedWriteSession_NoLock(session).ConfigureAwait(false) :
            _encryptedWriteRetired.GetValueOrDefault(mount, new(false, mount, "Unknown encrypted writer owner.")); }
        finally { _encryptedWriteGate.Release(); }
    }
    private async Task<IReadOnlyList<MountedVolumeState>> EncryptedWriteMountStatesAsync(CancellationToken token)
    {
        await _encryptedWriteGate.WaitAsync(token).ConfigureAwait(false);
        try { return _encryptedWriteSessions.Values.Select(s => s.ReadState()).ToArray(); }
        finally { _encryptedWriteGate.Release(); }
    }
    private void BeginEncryptedWriteDrain()
    {
        if (Interlocked.Exchange(ref _encryptedWriteDraining, 1) != 0) return;
        _ = Task.Run(async () => {
            while (!_encryptedWriteSessions.IsEmpty)
            {
                await _encryptedWriteGate.WaitAsync().ConfigureAwait(false);
                try
                {
                    foreach (var session in _encryptedWriteSessions.Values)
                    {
                        try { await StopEncryptedWriteSession_NoLock(session).ConfigureAwait(false); }
                        catch (Exception e) when (e is not OutOfMemoryException)
                        { WriteLifecycleDiagnostic("encrypted-writer-drain-retry", session.MountPoint, null, e.Message); }
                    }
                }
                finally { _encryptedWriteGate.Release(); }
                if (!_encryptedWriteSessions.IsEmpty) await Task.Delay(500).ConfigureAwait(false);
            }
            lock (_disposeFinalizationSync) CompleteDisposeIfNoHosts_NoLock();
        });
    }
}
