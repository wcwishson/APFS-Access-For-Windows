using System.Collections.Concurrent;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service;

public sealed class ApfsMountWorker : BackgroundService
{
    private readonly ILogger<ApfsMountWorker> _logger;
    private readonly IApfsBackend _backend;
    private readonly IMountPolicy _mountPolicy;
    private readonly RuntimeStatusPublisher _statusPublisher;
    private readonly IOptionsMonitor<ServiceHostOptions> _optionsMonitor;
    private readonly HashSet<string> _mountedOnce = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _userEjectedVolumeIds = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _unsafeUnmountedVolumeIds = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _missingVolumeProbeCounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, MountRetryState> _mountRetryStates = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _mountOperationLock = new(1, 1);
    private readonly object _shutdownSync = new();
    private Task<ShutdownPreparationResult>? _shutdownPreparation;
    private long _mountCommandGeneration;
    private long _mountOperationGeneration;
    private readonly object _discoveryAdmissionSync = new();
    private long _discoveryGeneration;
    private long _admittedDiscoveryGeneration;
    private DiscoverySnapshot? _admittedDiscovery;
    private readonly SemaphoreSlim _preferenceOperationLock = new(1, 1);
    private int _shutdownRequested;
    private readonly ConcurrentDictionary<(string Device, string Volume, string? Catalog, char Letter), string?> _selectedVolumeUuids = new();
    private IReadOnlyList<VolumeInfo> _preferenceVolumes = Array.Empty<VolumeInfo>();
    private const int MissingVolumeUnmountThreshold = 2;
    public ApfsMountWorker(
        ILogger<ApfsMountWorker> logger,
        IApfsBackend backend,
        IMountPolicy mountPolicy,
        RuntimeStatusPublisher statusPublisher,
        IOptionsMonitor<ServiceHostOptions> optionsMonitor
    )
    {
        _logger = logger;
        _backend = backend;
        _mountPolicy = mountPolicy;
        _statusPublisher = statusPublisher;
        _optionsMonitor = optionsMonitor;
    }

    public Task<ShutdownPreparationResult> PrepareForShutdownAsync(CancellationToken cancellationToken)
    {
        Interlocked.Exchange(ref _shutdownRequested, 1);
        Interlocked.Increment(ref _mountCommandGeneration);

        Task<ShutdownPreparationResult> preparation;
        lock (_shutdownSync)
        {
            _shutdownPreparation ??= PrepareForShutdownCoreAsync();
            preparation = _shutdownPreparation;
        }

        return preparation.WaitAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Publish(
            RuntimeState.Starting,
            Array.Empty<MountedVolumeState>(),
            null,
            warnings: Array.Empty<string>(),
            writeEnabled: false,
            compatibilityWarnings: Array.Empty<string>()
        );

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await RunCycleAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Mount cycle failed.");
                    Publish(
                        RuntimeState.Error,
                        Array.Empty<MountedVolumeState>(),
                        ex.Message,
                        warnings: Array.Empty<string>(),
                        writeEnabled: false,
                        compatibilityWarnings: Array.Empty<string>()
                    );
                }

                var pollSeconds = Math.Clamp(_optionsMonitor.CurrentValue.PollSeconds, 1, 60);
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(pollSeconds), stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
            }
        }
        finally
        {
            var shutdown = await PrepareForShutdownAsync(CancellationToken.None).ConfigureAwait(false);
            PublishShutdownState(shutdown);
        }
    }

    private async Task RunCycleAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _shutdownRequested) != 0)
        {
            return;
        }

        var commandGeneration = Volatile.Read(ref _mountCommandGeneration);
        var discovery = await DiscoverVolumesAsync(cancellationToken).ConfigureAwait(false);

        await _mountOperationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ++_mountOperationGeneration;
            if (Volatile.Read(ref _shutdownRequested) != 0 ||
                commandGeneration != Volatile.Read(ref _mountCommandGeneration))
            {
                return;
            }

            await RunCycleCoreAsync(discovery, cancellationToken).ConfigureAwait(false);
        }
        catch (SelectionSupersededException) { }
        finally
        {
            _mountOperationLock.Release();
        }
    }

    private async Task<DiscoverySnapshot> DiscoverVolumesAsync(CancellationToken cancellationToken)
    {
        var generation = Interlocked.Increment(ref _discoveryGeneration);
        var options = _optionsMonitor.CurrentValue;
        var warnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var compatibilityWarnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Every selection/inventory admission re-observes APFS identities. Partition
        // layout and image timestamps are insufficient to retain UUID associations.
        var inventory = (await _backend.ProbeInventoryAsync(authoritative: true, cancellationToken).ConfigureAwait(false))
            .Select(d => d with { Volumes = d.Volumes.ToArray() }).ToArray();
        cancellationToken.ThrowIfCancellationRequested();
        var connectedDevices = inventory.Select(d => d.Device).ToArray();

        var discoveredVolumeById = new Dictionary<string, VolumeInfo>(StringComparer.OrdinalIgnoreCase);
        var discoveredVolumes = new List<VolumeInfo>();
        foreach (var item in inventory)
        {
            var volumes = item.Volumes;
            foreach (var volume in volumes)
            {
                discoveredVolumes.Add(volume);
                discoveredVolumeById[volume.VolumeId] = volume;

                if (options.SkipEncryptedVolumes && volume.IsEncrypted)
                {
                    warnings.Add($"Skipped encrypted volume '{volume.VolumeName}'.");
                }
                else if (!volume.SupportsExplorerMount)
                {
                    warnings.Add($"Volume '{volume.VolumeName}' cannot be mounted in Explorer.");
                }

                var writeDecision = WriteGatePolicy.EvaluateForVolume(options, volume);
                if (options.EnableNativeWrite && !writeDecision.AllowWrite)
                {
                    compatibilityWarnings.Add(
                        $"Write blocked for '{volume.VolumeName}' " +
                        $"(gate={writeDecision.GateState}): {writeDecision.Reason ?? "no reason provided"}"
                    );
                }
            }
        }

        return new DiscoverySnapshot(
            generation,
            options,
            connectedDevices,
            inventory,
            discoveredVolumeById,
            discoveredVolumes,
            warnings.ToArray(),
            compatibilityWarnings.ToArray());
    }

    private async Task RunCycleCoreAsync(
        DiscoverySnapshot discovery,
        CancellationToken cancellationToken,
        IReadOnlyList<MountedVolumeState>? mountedOverride = null,
        string? requestedVolumeId = null,
        string? requestedDeviceId = null,
        MountAccessMode? requestedAccessMode = null,
        string? requestedRecoveryIdentity = null)
    {
        var options = discovery.Options;
        var connectedDevices = discovery.ConnectedDevices;
        var discoveredVolumeById = discovery.VolumeById;
        // Keep duplicate rows across devices: deduplicating by routing ID would hide
        // ambiguous identities. All selection paths run here under the mount lock.
        if (!TryAdmitDiscovery(discovery)) return;
        var warnings = new HashSet<string>(discovery.Warnings, StringComparer.OrdinalIgnoreCase);
        var compatibilityWarnings = new HashSet<string>(
            discovery.CompatibilityWarnings,
            StringComparer.OrdinalIgnoreCase);

        if (discoveredVolumeById.Count > 0)
        {
            var disconnectedEjectedVolumes = _userEjectedVolumeIds
                .Where(volumeId => !discoveredVolumeById.ContainsKey(volumeId))
                .ToArray();
            foreach (var volumeId in disconnectedEjectedVolumes)
            {
                _userEjectedVolumeIds.Remove(volumeId);
            }
        }

        var mounted = (mountedOverride ?? await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false)).ToList();
        var unmountMissingResult = await UnmountMissingVolumesAsync(
            mounted,
            discoveredVolumeById.Keys,
            warnings,
            cancellationToken
        ).ConfigureAwait(false);
        mounted = unmountMissingResult.Mounted.ToList();
        var mountStateChanged = unmountMissingResult.Changed;

        if (connectedDevices.Count == 0)
        {
            if (mounted.Count == 0)
            {
                _userEjectedVolumeIds.Clear();
            }

            PublishFromMounts(mounted, null, warnings, compatibilityWarnings);
            return;
        }

        if (!options.AutoMountEnabled && string.IsNullOrWhiteSpace(requestedVolumeId))
        {
            PublishFromMounts(mounted, null, warnings, compatibilityWarnings);
            return;
        }

        var mountedVolumeIds = new HashSet<string>(mounted.Select(x => x.VolumeId), StringComparer.OrdinalIgnoreCase);
        var usedLetters = new HashSet<char>(
            mounted
                .Select(TryGetDriveLetter)
                .Where(ch => ch.HasValue)
                .Select(ch => ch!.Value)
        );
        // DriveInfo.GetDrives() asks each filesystem for volume information.
        // A stalled WinFsp provider must not block drive-letter allocation for
        // unrelated volumes, so use the kernel logical-drive bitmask instead.
        foreach (var drive in Environment.GetLogicalDrives())
        {
            if (string.IsNullOrWhiteSpace(drive))
            {
                continue;
            }

            var letter = char.ToUpperInvariant(drive[0]);
            if (letter is >= 'A' and <= 'Z')
            {
                usedLetters.Add(letter);
            }
        }

        string? firstMountError = null;
        var requiresMountStateRefresh = false;
        var deviceDisplayNames = connectedDevices.ToDictionary(
            static device => device.DeviceId,
            static device => device.DisplayName,
            StringComparer.OrdinalIgnoreCase);

        var volumesToProcess = string.IsNullOrWhiteSpace(requestedDeviceId)
            ? discoveredVolumeById.Values
            : discovery.Volumes.Where(volume =>
                string.Equals(volume.DeviceId, requestedDeviceId, StringComparison.OrdinalIgnoreCase));

        var pendingVolumes = new List<VolumeInfo>();
        foreach (var volume in volumesToProcess.OrderBy(x => x.VolumeName, StringComparer.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(requestedVolumeId) &&
                !string.Equals(volume.VolumeId, requestedVolumeId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!RecoveryIdentityMatches(volume.RecoveryIdentity, requestedRecoveryIdentity))
            {
                continue;
            }

            if (options.SkipEncryptedVolumes && volume.IsEncrypted)
            {
                continue;
            }

            if (!volume.SupportsExplorerMount)
            {
                continue;
            }

            if (!_mountPolicy.ShouldAutoMount(volume) || mountedVolumeIds.Contains(volume.VolumeId))
            {
                continue;
            }

            if (_userEjectedVolumeIds.Contains(volume.VolumeId))
            {
                warnings.Add($"'{volume.VolumeName}' is safely ejected; unplug and reinsert it to mount again.");
                continue;
            }

            if (_unsafeUnmountedVolumeIds.Contains(volume.VolumeId))
            {
                warnings.Add($"'{volume.VolumeName}' remains unmounted after an unsafe host stop; use Fix to recover it before remounting.");
                continue;
            }

            if (!options.NativeAutoRemountOnReconnect && _mountedOnce.Contains(volume.VolumeId))
            {
                warnings.Add($"Auto-remount disabled for '{volume.VolumeName}' after prior disconnect.");
                continue;
            }

            if (string.IsNullOrWhiteSpace(requestedVolumeId) &&
                IsMountRetryBackoffActive(volume.VolumeId, out var retryWarning))
            {
                warnings.Add(retryWarning);
                continue;
            }

            pendingVolumes.Add(volume);
        }

        var mountOutcomes = new List<(VolumeInfo Volume, MountAttemptOutcome Outcome)>(pendingVolumes.Count);
        if (_backend is IContainerMountBackend containerBackend && pendingVolumes.Count > 1)
        {
            mountOutcomes.AddRange(await TryMountContainerBatchAsync(
                containerBackend,
                pendingVolumes,
                options,
                usedLetters,
                cancellationToken,
                deviceDisplayNames,
                requestedAccessMode,
                discovery.Generation).ConfigureAwait(false));
        }
        else
        {
            foreach (var volume in pendingVolumes)
            {
                var outcome = await TryMountAsync(
                    volume,
                    options,
                    usedLetters,
                    cancellationToken,
                    deviceDisplayNames.GetValueOrDefault(volume.DeviceId),
                    requestedAccessMode,
                    discovery.Generation).ConfigureAwait(false);
                mountOutcomes.Add((volume, new MountAttemptOutcome(
                    outcome.Success,
                    outcome.Error,
                    outcome.Warning,
                    outcome.CompatibilityWarning,
                    outcome.MountedState)));
            }
        }

        foreach (var (volume, outcome) in mountOutcomes)
        {
            var (success, error, warning, compatibilityWarning, mountedState) = outcome;
            if (success)
            {
                _mountRetryStates.Remove(volume.VolumeId);
                mountStateChanged = true;
                requiresMountStateRefresh = true;
                if (mountedState is not null)
                {
                    mounted.Add(mountedState);
                }
                mountedVolumeIds.Add(volume.VolumeId);
                _mountedOnce.Add(volume.VolumeId);
                _missingVolumeProbeCounts.Remove(volume.VolumeId);
                if (!string.IsNullOrWhiteSpace(warning))
                {
                    warnings.Add(warning);
                }

                if (!string.IsNullOrWhiteSpace(compatibilityWarning))
                {
                    compatibilityWarnings.Add(compatibilityWarning);
                }
                continue;
            }

            if (firstMountError is null && !string.IsNullOrWhiteSpace(error))
            {
                firstMountError = error;
            }

            RecordMountFailure(volume.VolumeId, error);

            if (!string.IsNullOrWhiteSpace(error))
            {
                warnings.Add($"Mount failed for '{volume.VolumeName}': {error}");
            }
        }

        if (requiresMountStateRefresh)
        {
            mounted = (await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false)).ToList();
        }

        PublishFromMounts(mounted, firstMountError, warnings, compatibilityWarnings);
    }

    public async Task<(bool Success, string Message)> EjectAllAsync(CancellationToken cancellationToken)
        => await EjectAsync(null, cancellationToken).ConfigureAwait(false);

    private void UpdatePreferenceDiscovery(IReadOnlyList<VolumeInfo> volumes)
    {
        _preferenceVolumes = volumes.ToArray();
        _mountPolicy.UpdateDiscovery(volumes);
    }

    // Admission uses a short, I/O-free lock independent of mount operations.
    // Generation is allocated before discovery starts, so an old slow observation
    // cannot reinstall identity or clear new ambiguity, even during an eject.
    private bool TryAdmitDiscovery(DiscoverySnapshot discovery)
    {
        lock (_discoveryAdmissionSync)
        {
            if (discovery.Generation < _admittedDiscoveryGeneration) return false;
            if (discovery.Generation == _admittedDiscoveryGeneration) return true;
            _admittedDiscoveryGeneration = discovery.Generation;
            _admittedDiscovery = discovery;
            UpdatePreferenceDiscovery(discovery.Volumes);
            return true;
        }
    }

    public async Task<IReadOnlyList<DeviceInventory>> GetInventoryAsync(CancellationToken cancellationToken)
    {
        var discovery = await DiscoverVolumesAsync(cancellationToken).ConfigureAwait(false);
        var mounts = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
        List<(DeviceInfo Device, (VolumeInfo Volume, Func<DriveLetterPreference?> Preference)[] Volumes)> captured;
        cancellationToken.ThrowIfCancellationRequested();
        lock (_discoveryAdmissionSync)
        {
            if (!TryAdmitDiscovery(discovery)) discovery = _admittedDiscovery!;
            // Preserve the device bucket returned by discovery, including invalid
            // cross-device rows that exact-target validation must reject explicitly.
            captured = discovery.Inventory.Select(d => (d.Device,
                d.Volumes.Select(v => (v, CaptureInventoryPreference(v, mounts))).ToArray())).ToList();
        }
        // Preference storage reads may block in Windows; never perform them under
        // the mount lock, and await their actual completion rather than detach them.
        return await Task.Run<IReadOnlyList<DeviceInventory>>(() => captured.Select(d => new DeviceInventory(d.Device,
            d.Volumes.Select(v => v.Volume with { DriveLetterPreference = v.Preference() }).ToArray())).ToArray(), cancellationToken).ConfigureAwait(false);
    }

    public async Task<AckPayload> SetDriveLetterPreferenceAsync(DriveLetterPreferenceRequestPayload request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.DeviceId) || string.IsNullOrWhiteSpace(request.VolumeId) ||
            !(Guid.TryParseExact(request.VolumeUuid, "D", out var uuid) || Guid.TryParseExact(request.VolumeUuid, "N", out uuid)) ||
            uuid == Guid.Empty || request.Letter is not { Length: 1 } || char.ToUpperInvariant(request.Letter[0]) is < 'A' or > 'Z')
            return new(false, "Supply exact device, volume and actual volume UUID, and one letter A-Z.", ApfsOperationCodes.InvalidArguments);
        await _preferenceOperationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        DriveLetterPreferenceResult result;
        try
        {
            var discovery = await DiscoverVolumesAsync(cancellationToken).ConfigureAwait(false);
            Func<CancellationToken, DriveLetterPreferenceResult> commit;
            lock (_discoveryAdmissionSync)
            {
                if (Volatile.Read(ref _shutdownRequested) != 0)
                    return new(false, "Service is stopping. Try again after restart.", ApfsOperationCodes.ServiceUnavailable);
                if (!TryAdmitDiscovery(discovery))
                    return new(false, "A newer inventory superseded this validation. Refresh and try again.", ApfsOperationCodes.AmbiguousTarget);
                var matches = _preferenceVolumes.Where(v => v.DeviceId == request.DeviceId && v.VolumeId == request.VolumeId).ToArray();
                if (matches.Length != 1)
                    return new(false, "Volume identity is stale or ambiguous. Refresh and try again.",
                        matches.Length == 0 ? ApfsOperationCodes.MissingVolume : ApfsOperationCodes.AmbiguousTarget);
                cancellationToken.ThrowIfCancellationRequested();
                // Admission captures the exact validated UUID. Subsequent inventory
                // changes do not retarget an admitted edit to a replacement volume.
                commit = _mountPolicy.PrepareDriveLetterPreference(matches[0], uuid, request.Letter[0]);
            }

            result = await Task.Run(() => commit(cancellationToken), cancellationToken).ConfigureAwait(false);
        }
        finally { _preferenceOperationLock.Release(); }
        // Commit owns cancellation semantics: no token checks after a saved result.
        // Release the edit gate too before display notification can reenter the worker.
        try { await PublishPreferenceDisplayAsync().ConfigureAwait(false); }
        catch (Exception ex) { _logger.LogWarning(ex, "Preference result retained; display refresh failed."); }
        return new(result.Success, result.Message, result.Code, _statusPublisher.Latest);
    }

    private async Task PublishPreferenceDisplayAsync()
    {
        StatusChangedPayload latest;
        long generation;
        (MountedVolumeDisplay Display, Func<DriveLetterPreference?> Preference)[] captured;
        lock (_discoveryAdmissionSync)
        {
            latest = _statusPublisher.Latest;
            generation = _admittedDiscoveryGeneration;
            captured = (latest.MountedVolumes ?? []).Select(m => (m,
                CapturePreferenceForDisplay(m.DeviceId, m.VolumeId, m.CatalogVolumeId, m.MountPoint))).ToArray();
        }
        var projected = await Task.Run(() => captured.Select(m => m.Display with { DriveLetterPreference = m.Preference() }).ToArray()).ConfigureAwait(false);
        var payload = latest with { MountedVolumes = projected };
        Action? notification = null;
        lock (_discoveryAdmissionSync)
        {
            if (generation == _admittedDiscoveryGeneration)
                _statusPublisher.TryPublish(latest, payload, out notification);
        }
        notification?.Invoke();
    }

    private Func<DriveLetterPreference?> CaptureInventoryPreference(VolumeInfo volume, IReadOnlyList<MountedVolumeState> mounts)
    {
        var matches = mounts.Where(m => m.DeviceId == volume.DeviceId && m.VolumeId == volume.VolumeId && m.CatalogVolumeId == volume.CatalogVolumeId).ToArray();
        var mounted = matches.Length == 1
            ? CapturePreferenceForDisplay(volume.DeviceId, volume.VolumeId, volume.CatalogVolumeId, matches[0].MountPoint)
            : null;
        return () =>
        {
            var preference = mounted?.Invoke();
            return preference?.CanEdit == true ? preference : _mountPolicy.GetDriveLetterPreference(volume, null);
        };
    }

    private sealed class SelectionSupersededException : OperationCanceledException;

    private async Task<char> SelectDriveLetterForVolumeAsync(VolumeInfo volume, IReadOnlySet<char> occupied,
        long discoveryGeneration, CancellationToken cancellationToken)
    {
        if (!_mountPolicy.RequiresDriveLetterStorage)
        {
            // Preserve ordinary in-memory/legacy policies' mount-command ordering.
            var immediate = _mountPolicy.SelectDriveLetter(volume, occupied);
            _selectedVolumeUuids[(volume.DeviceId, volume.VolumeId, volume.CatalogVolumeId, immediate)] = volume.CatalogVolumeUuid;
            return immediate;
        }
        Func<CancellationToken, char> select;
        var commandGeneration = Volatile.Read(ref _mountCommandGeneration);
        var operationGeneration = _mountOperationGeneration;
        lock (_discoveryAdmissionSync)
        {
            if (discoveryGeneration != _admittedDiscoveryGeneration || Volatile.Read(ref _shutdownRequested) != 0)
                throw new SelectionSupersededException();
            select = _mountPolicy.PrepareDriveLetterSelection(volume, occupied);
        }
        char letter;
        _mountOperationLock.Release();
        try { letter = await Task.Run(() => select(cancellationToken), cancellationToken).ConfigureAwait(false); }
        finally
        {
            // Restore ownership even on cancellation/failure; the outer operation owns
            // the matching release. No detached storage work may retain this lock.
            await _mountOperationLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        }
        ValidateDriveLetterSelection(discoveryGeneration, commandGeneration, operationGeneration, cancellationToken);
        _selectedVolumeUuids[(volume.DeviceId, volume.VolumeId, volume.CatalogVolumeId, letter)] = volume.CatalogVolumeUuid;
        return letter;
    }

    private void ValidateDriveLetterSelection(long discoveryGeneration, long commandGeneration,
        long operationGeneration, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_discoveryAdmissionSync)
        {
            if (discoveryGeneration != _admittedDiscoveryGeneration ||
                commandGeneration != Volatile.Read(ref _mountCommandGeneration) ||
                operationGeneration != _mountOperationGeneration || Volatile.Read(ref _shutdownRequested) != 0)
                throw new SelectionSupersededException();
        }
    }

    private DriveLetterPreference? PreferenceForDisplay(string deviceId, string volumeId, string? catalogId, string mountPoint)
        => CapturePreferenceForDisplay(deviceId, volumeId, catalogId, mountPoint, cached: true)();

    private Func<DriveLetterPreference?> CapturePreferenceForDisplay(string deviceId, string volumeId, string? catalogId, string mountPoint, bool cached = false)
    {
        var matches = _preferenceVolumes.Where(v => v.DeviceId == deviceId && v.VolumeId == volumeId && v.CatalogVolumeId == catalogId).ToArray();
        var letter = mountPoint.Length >= 2 && mountPoint[1] == ':' ? (char?)char.ToUpperInvariant(mountPoint[0]) : null;
        if (matches.Length != 1 || !letter.HasValue ||
            !_selectedVolumeUuids.TryGetValue((deviceId, volumeId, catalogId, letter.Value), out var selectedUuid) ||
            !Guid.TryParse(selectedUuid, out var boundUuid) || !Guid.TryParse(matches[0].CatalogVolumeUuid, out var liveUuid) || boundUuid != liveUuid)
            return () => new(null, null, letter?.ToString(), "identity-unavailable",
                "Mounted volume identity is unavailable. Use refreshed inventory or remount before choosing a letter.", "", false);
        return () => cached ? _mountPolicy.GetCachedDriveLetterPreference(matches[0], letter) : _mountPolicy.GetDriveLetterPreference(matches[0], letter);
    }

    public async Task<(bool Success, string Message)> RefreshAsync(
        bool clearUserEjectedVolumes,
        CancellationToken cancellationToken
    )
        => await RefreshAsync(clearUserEjectedVolumes, volumeId: null, cancellationToken).ConfigureAwait(false);

    public async Task<(bool Success, string Message)> RefreshAsync(
        bool clearUserEjectedVolumes,
        string? volumeId,
        CancellationToken cancellationToken
    )
        => await RefreshCoreAsync(
            clearUserEjectedVolumes,
            volumeId,
            requireTargetMounted: false,
            cancellationToken: cancellationToken).ConfigureAwait(false);

    public async Task<(bool Success, string Message)> EnsureMountedAsync(
        string? volumeId,
        CancellationToken cancellationToken)
        => await RefreshCoreAsync(
            clearUserEjectedVolumes: true,
            volumeId,
            requireTargetMounted: true,
            cancellationToken: cancellationToken).ConfigureAwait(false);

    public async Task<(bool Success, string Message)> EnsureMountedAsync(
        string? volumeId,
        MountAccessMode requestedAccessMode,
        CancellationToken cancellationToken)
        => await RefreshCoreAsync(
            clearUserEjectedVolumes: true,
            volumeId,
            requireTargetMounted: true,
            cancellationToken: cancellationToken,
            requestedAccessMode: requestedAccessMode).ConfigureAwait(false);

    public Task<(bool Success, string Message)> EnsureMountedExactAsync(
        string deviceId,
        string volumeId,
        MountAccessMode? requestedAccessMode,
        CancellationToken cancellationToken,
        string? recoveryIdentity = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        ArgumentException.ThrowIfNullOrWhiteSpace(volumeId);
        return RefreshCoreAsync(
            clearUserEjectedVolumes: true,
            volumeId: volumeId,
            requireTargetMounted: true,
            cancellationToken: cancellationToken,
            requestedAccessMode: requestedAccessMode,
            requestedDeviceId: deviceId,
            requestedRecoveryIdentity: recoveryIdentity);
    }

    public Task<IReadOnlyList<MountedVolumeState>> GetAuthoritativeMountStateAsync(
        CancellationToken cancellationToken)
        => _backend.GetMountStateAsync(cancellationToken);

    private async Task<(bool Success, string Message)> RefreshCoreAsync(
        bool clearUserEjectedVolumes,
        string? volumeId,
        bool requireTargetMounted,
        CancellationToken cancellationToken,
        MountAccessMode? requestedAccessMode = null,
        string? requestedDeviceId = null,
        string? requestedRecoveryIdentity = null)
    {
        var commandGeneration = Interlocked.Increment(ref _mountCommandGeneration);
        var discovery = await DiscoverVolumesAsync(cancellationToken).ConfigureAwait(false);

        await _mountOperationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(requestedDeviceId) && !string.IsNullOrWhiteSpace(volumeId) &&
            Volatile.Read(ref _shutdownRequested) == 0 && commandGeneration == Volatile.Read(ref _mountCommandGeneration))
        {
            // Preserve queued exact-target revalidation, but release the mount lock
            // during the expensive observer/Windows work. Command and discovery
            // generations below reject observations superseded before re-admission.
            _mountOperationLock.Release();
            discovery = await DiscoverVolumesAsync(cancellationToken).ConfigureAwait(false);
            await _mountOperationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        try
        {
            ++_mountOperationGeneration;
            if (Volatile.Read(ref _shutdownRequested) != 0)
            {
                return (false, "Refresh was rejected because APFS shutdown cleanup has started.");
            }

            if (commandGeneration != Volatile.Read(ref _mountCommandGeneration))
            {
                return (false, "Refresh was superseded by a newer drive command.");
            }

            if (!TryAdmitDiscovery(discovery))
                return (false, "Refresh was superseded by a newer inventory observation.");

            if (!string.IsNullOrWhiteSpace(requestedDeviceId) &&
                !string.IsNullOrWhiteSpace(volumeId))
            {
                var exactMatches = discovery.Volumes
                    .Where(volume =>
                        string.Equals(volume.DeviceId, requestedDeviceId, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(volume.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase))
                    .ToArray();
                if (exactMatches.Length != 1)
                {
                    return (false, $"Requested APFS volume '{volumeId}' was not uniquely found on device '{requestedDeviceId}'; mutation was not attempted.");
                }

                if (!RecoveryIdentityMatches(exactMatches[0].RecoveryIdentity, requestedRecoveryIdentity))
                {
                    return (false, $"Requested APFS volume '{volumeId}' recovery identity did not match the connected volume; mutation was not attempted.");
                }
            }
            else if (!string.IsNullOrWhiteSpace(volumeId) &&
                     !discovery.VolumeById.ContainsKey(volumeId))
            {
                return (false, $"Requested APFS volume '{volumeId}' was not found.");
            }

            // The admitted snapshot also covers upgrade-remount letter selection.
            IReadOnlyList<MountedVolumeState>? refreshedMounted = null;
            var remountWarnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (clearUserEjectedVolumes)
            {
                if (string.IsNullOrWhiteSpace(volumeId))
                {
                    _userEjectedVolumeIds.Clear();
                    _unsafeUnmountedVolumeIds.Clear();
                }
                else
                {
                    _userEjectedVolumeIds.Remove(volumeId);
                    _unsafeUnmountedVolumeIds.Remove(volumeId);
                }

                refreshedMounted = await RemountUpgradeableReadOnlyVolumesAsync(
                    volumeId,
                    requestedDeviceId,
                    requestedAccessMode,
                    discovery,
                    remountWarnings,
                    cancellationToken).ConfigureAwait(false);
            }

            if (remountWarnings.Count > 0)
            {
                discovery = discovery with
                {
                    Warnings = discovery.Warnings.Concat(remountWarnings).ToArray(),
                };
            }

            await RunCycleCoreAsync(
                discovery,
                cancellationToken,
                refreshedMounted,
                requestedVolumeId: volumeId,
                requestedDeviceId: requestedDeviceId,
                requestedAccessMode: requestedAccessMode,
                requestedRecoveryIdentity: requestedRecoveryIdentity).ConfigureAwait(false);

            if (requireTargetMounted && !string.IsNullOrWhiteSpace(volumeId))
            {
                var mountedAfterRefresh = await _backend
                    .GetMountStateAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (!mountedAfterRefresh.Any(mount =>
                        string.Equals(mount.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase) &&
                        (string.IsNullOrWhiteSpace(requestedDeviceId) ||
                         string.Equals(mount.DeviceId, requestedDeviceId, StringComparison.OrdinalIgnoreCase)) &&
                        RecoveryIdentityMatches(mount.RecoveryIdentity, requestedRecoveryIdentity)))
                {
                    return (false, $"APFS volume '{volumeId}' could not be mounted.");
                }

                return (true, $"APFS volume '{volumeId}' is mounted.");
            }

            return (true, "APFS drives refreshed.");
        }
        catch (SelectionSupersededException)
        {
            return (false, "Refresh was superseded while preparing drive-letter settings. Refresh and try again.");
        }
        finally
        {
            _mountOperationLock.Release();
        }
    }

    private async Task<IReadOnlyList<MountedVolumeState>> RemountUpgradeableReadOnlyVolumesAsync(
        string? volumeId,
        string? deviceId,
        MountAccessMode? requestedAccessMode,
        DiscoverySnapshot discovery,
        HashSet<string> warnings,
        CancellationToken cancellationToken)
    {
        var options = discovery.Options;
        if (!options.AutoMountEnabled || !options.EnableNativeWrite)
        {
            return await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
        }

        var mounted = (await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false)).ToList();
        var remountCandidates = mounted
            .Where(mount =>
                IsUpgradeableOrDegradedMount(mount) ||
                requestedAccessMode.HasValue &&
                string.Equals(mount.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase) &&
                (string.IsNullOrWhiteSpace(deviceId) ||
                 string.Equals(mount.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase)) &&
                mount.AccessMode != requestedAccessMode.Value)
            .ToArray();
        if (remountCandidates.Length == 0)
        {
            return mounted;
        }

        var volumeById = discovery.VolumeById;
        var deviceDisplayNames = discovery.ConnectedDevices.ToDictionary(
            static device => device.DeviceId,
            static device => device.DisplayName,
            StringComparer.OrdinalIgnoreCase);

        var mountedVolumeIds = new HashSet<string>(mounted.Select(static mount => mount.VolumeId), StringComparer.OrdinalIgnoreCase);
        var usedLetters = new HashSet<char>(
            mounted
                .Select(TryGetDriveLetter)
                .Where(static ch => ch.HasValue)
                .Select(static ch => ch!.Value)
        );
        var stateChanged = false;
        var requiresAuthoritativeRefresh = false;
        var preparationCommand = Volatile.Read(ref _mountCommandGeneration);
        var preparationOperation = _mountOperationGeneration;
        var plannedLetters = new HashSet<char>(usedLetters);
        var prepared = new List<(MountedVolumeState Mount, VolumeInfo Volume, char? Letter)>();

        foreach (var mount in remountCandidates)
        {
            if (!string.IsNullOrWhiteSpace(volumeId) &&
                !string.Equals(mount.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(deviceId) &&
                !string.Equals(mount.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var volume = string.IsNullOrWhiteSpace(deviceId)
                ? volumeById.GetValueOrDefault(mount.VolumeId)
                : discovery.Volumes.SingleOrDefault(candidate =>
                    string.Equals(candidate.VolumeId, mount.VolumeId, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(candidate.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase));
            if (volume is null)
            {
                continue;
            }

            if (!_mountPolicy.ShouldAutoMount(volume) ||
                options.SkipEncryptedVolumes && volume.IsEncrypted ||
                !volume.SupportsExplorerMount)
            {
                continue;
            }

            var writeDecision = WriteGatePolicy.EvaluateForVolume(options, volume);
            if (!writeDecision.AllowWrite)
            {
                continue;
            }

            var driveLetter = TryGetDriveLetter(mount);
            if (!driveLetter.HasValue)
            {
                continue;
            }

            char? preparedLetter = null;
            if (_mountPolicy.RequiresDriveLetterStorage)
            {
                // Prepare every upgrade before removing any mount. A later settings
                // wait may be superseded too; all original mounts must remain usable
                // by eject and consistent with the published status until then.
                var occupied = new HashSet<char>(plannedLetters);
                occupied.Remove(driveLetter.Value);
                try
                {
                    preparedLetter = await SelectDriveLetterForVolumeAsync(
                        volume, occupied, discovery.Generation, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Could not allocate drive letter for {VolumeId}", volume.VolumeId);
                    continue;
                }
                plannedLetters.Remove(driveLetter.Value);
                plannedLetters.Add(preparedLetter.Value);
            }
            prepared.Add((mount, volume, preparedLetter));
        }

        if (_mountPolicy.RequiresDriveLetterStorage && prepared.Count > 0)
        {
            var current = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
            ValidateDriveLetterSelection(discovery.Generation, preparationCommand, preparationOperation, cancellationToken);
            // Generation checks cover worker commands. Recheck the backend snapshot
            // as well: external removal/replacement must not inherit an old plan.
            // Runtime diagnostics and WAL counters can refresh on the same owner.
            var ownership = (MountedVolumeState state) => (state.VolumeId, state.DeviceId, state.MountPoint,
                state.CatalogVolumeId, state.RecoveryIdentity, state.HostProcessId, state.AccessMode);
            if (current.Count != mounted.Count || !current.Select(ownership).ToHashSet().SetEquals(mounted.Select(ownership)))
                return current;
        }

        foreach (var (mount, volume, preparedLetter) in prepared)
        {
            var driveLetter = TryGetDriveLetter(mount)!.Value;
            // An earlier unmount can fail and leave its old letter occupied, even
            // though preparation anticipated releasing it. Keep this mount intact.
            if (preparedLetter.HasValue && preparedLetter.Value != driveLetter && usedLetters.Contains(preparedLetter.Value))
                continue;

            var unmount = await UnmountAsync([mount], cancellationToken, warnings).ConfigureAwait(false);
            if (unmount.Removed.Count > 0)
            {
                stateChanged = true;
                mountedVolumeIds.Remove(mount.VolumeId);
                usedLetters.Remove(driveLetter);
                mounted.RemoveAll(candidate => string.Equals(
                    candidate.VolumeId,
                    mount.VolumeId,
                    StringComparison.OrdinalIgnoreCase));
            }
            foreach (var unsafeRemoved in unmount.UnsafeRemoved)
            {
                _unsafeUnmountedVolumeIds.Add(unsafeRemoved.VolumeId);
                warnings.Add(BuildUnsafeUnmountWarning(unsafeRemoved));
            }
            if (unmount.SafelyUnmounted.Count == 0)
            {
                continue;
            }

            var (success, _, warning, _, remountedState) = await TryMountAsync(
                volume,
                options,
                usedLetters,
                cancellationToken,
                deviceDisplayNames.GetValueOrDefault(volume.DeviceId),
                requestedAccessMode,
                discovery.Generation,
                preparedLetter
            ).ConfigureAwait(false);
            if (!success)
            {
                continue;
            }

            stateChanged = true;
            requiresAuthoritativeRefresh = true;
            if (remountedState is not null)
            {
                mounted.Add(remountedState);
            }
            else
            {
                return await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
            }
            mountedVolumeIds.Add(mount.VolumeId);
            _mountedOnce.Add(mount.VolumeId);
            _missingVolumeProbeCounts.Remove(mount.VolumeId);
            if (!string.IsNullOrWhiteSpace(warning))
            {
                warnings.Add(warning);
            }
        }

        if (requiresAuthoritativeRefresh)
        {
            return await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
        }

        if (!stateChanged)
        {
            return mounted;
        }

        return mounted;
    }

    private static bool IsUpgradeableOrDegradedMount(MountedVolumeState mount)
        => mount.AccessMode == MountAccessMode.ReadOnly ||
           mount.RecoveryActive ||
           mount.NativeWriteReadiness is NativeWriteReadiness.RecoveryMode or NativeWriteReadiness.Degraded ||
           mount.NativeWriteSafetyState is NativeWriteSafetyState.ReadOnlyFallback or NativeWriteSafetyState.RecoveryBlocked;

    public async Task<(bool Success, string Message)> EjectAsync(string? volumeId, CancellationToken cancellationToken)
    {
        var result = await EjectCoreAsync(volumeId, deviceId: null, recoveryIdentity: null, cancellationToken).ConfigureAwait(false);
        return (result.Success, result.Message);
    }

    public Task<EjectOperationResult> EjectExactAsync(
        string volumeId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(volumeId);
        return EjectCoreAsync(volumeId, deviceId: null, recoveryIdentity: null, cancellationToken);
    }

    public Task<EjectOperationResult> EjectExactAsync(
        string deviceId,
        string volumeId,
        CancellationToken cancellationToken,
        string? recoveryIdentity = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        ArgumentException.ThrowIfNullOrWhiteSpace(volumeId);
        return EjectCoreAsync(volumeId, deviceId, recoveryIdentity, cancellationToken);
    }

    private async Task<EjectOperationResult> EjectCoreAsync(
        string? volumeId,
        string? deviceId,
        string? recoveryIdentity,
        CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _mountCommandGeneration);
        await _mountOperationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ++_mountOperationGeneration;
            var warnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var mountedBeforeEject = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
            var selectedMounts = SelectMountsForEject(mountedBeforeEject, volumeId, deviceId, recoveryIdentity);
            if (selectedMounts.Count == 0)
            {
                PublishFromMounts(mountedBeforeEject, null, warnings, Array.Empty<string>());
                return new EjectOperationResult(
                    Success: string.IsNullOrWhiteSpace(volumeId),
                    Message: string.IsNullOrWhiteSpace(volumeId)
                        ? "No APFS drives are mounted."
                        : string.IsNullOrWhiteSpace(recoveryIdentity)
                            ? "That APFS drive is no longer mounted."
                            : "That APFS drive no longer matches the requested recovery identity; eject was not attempted.",
                    RemainingMounts: mountedBeforeEject,
                    UnmountResults: new Dictionary<string, UnmountResult>(StringComparer.OrdinalIgnoreCase));
            }

            if (!string.IsNullOrWhiteSpace(volumeId) && selectedMounts.Count != 1)
            {
                PublishFromMounts(mountedBeforeEject, null, warnings, Array.Empty<string>());
                return new EjectOperationResult(
                    Success: false,
                    Message: $"The exact APFS volume has {selectedMounts.Count} matching mount entries; eject was not attempted.",
                    RemainingMounts: mountedBeforeEject,
                    UnmountResults: new Dictionary<string, UnmountResult>(StringComparer.OrdinalIgnoreCase));
            }

            var unmount = await UnmountAsync(selectedMounts, cancellationToken, warnings).ConfigureAwait(false);
            var unmountedIds = unmount.Removed.Select(static x => x.VolumeId).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var remaining = mountedBeforeEject
                .Where(mount => !unmountedIds.Contains(mount.VolumeId))
                .ToArray();
            var remainingIds = remaining.Select(static x => x.VolumeId).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var remainingCount = remaining.Length;
            var statusWarnings = new HashSet<string>(warnings, StringComparer.OrdinalIgnoreCase);
            foreach (var mount in unmount.SafelyUnmounted)
            {
                _userEjectedVolumeIds.Add(mount.VolumeId);
            }
            foreach (var mount in unmount.UnsafeRemoved)
            {
                _unsafeUnmountedVolumeIds.Add(mount.VolumeId);
                statusWarnings.Add(BuildUnsafeUnmountWarning(mount));
            }

            foreach (var mount in unmount.SafelyUnmounted)
            {
                statusWarnings.Add(BuildSafelyEjectedWarning(mount));
            }

            PublishFromMounts(remaining, null, statusWarnings, Array.Empty<string>());

            if (remainingCount == 0 && warnings.Count == 0)
            {
                return new EjectOperationResult(
                    Success: true,
                    Message: string.IsNullOrWhiteSpace(volumeId)
                        ? "All APFS drives were safely ejected."
                        : $"APFS drive {BuildMountDisplayName(selectedMounts[0])} was safely ejected.",
                    RemainingMounts: remaining,
                    UnmountResults: unmount.Results);
            }

            if (!string.IsNullOrWhiteSpace(volumeId) && !remainingIds.Contains(volumeId) && warnings.Count == 0)
            {
                return new EjectOperationResult(
                    Success: true,
                    Message: $"APFS drive {BuildMountDisplayName(selectedMounts[0])} was safely ejected.",
                    RemainingMounts: remaining,
                    UnmountResults: unmount.Results);
            }

            if (!string.IsNullOrWhiteSpace(volumeId) && !remainingIds.Contains(volumeId))
            {
                return new EjectOperationResult(
                    Success: false,
                    Message: string.Join(" ", warnings),
                    RemainingMounts: remaining,
                    UnmountResults: unmount.Results);
            }

            if (remainingCount == 0)
            {
                return new EjectOperationResult(
                    Success: false,
                    Message: string.Join(" ", warnings),
                    RemainingMounts: remaining,
                    UnmountResults: unmount.Results);
            }

            var stillMounted = string.Join(", ", remaining.Select(static x => x.MountPoint));
            var detail = warnings.Count == 0 ? string.Empty : $" {string.Join(" ", warnings)}";
            return new EjectOperationResult(
                Success: false,
                Message: $"Some APFS drives are still mounted: {stillMounted}.{detail}",
                RemainingMounts: remaining,
                UnmountResults: unmount.Results);
        }
        finally
        {
            _mountOperationLock.Release();
        }
    }

    private static IReadOnlyList<MountedVolumeState> SelectMountsForEject(
        IReadOnlyList<MountedVolumeState> mounted,
        string? volumeId,
        string? deviceId = null,
        string? recoveryIdentity = null
    )
    {
        if (string.IsNullOrWhiteSpace(volumeId))
        {
            return mounted;
        }

        return mounted
            .Where(mount =>
                string.Equals(mount.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase) &&
                (string.IsNullOrWhiteSpace(deviceId) ||
                 string.Equals(mount.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase)) &&
                RecoveryIdentityMatches(mount.RecoveryIdentity, recoveryIdentity))
            .ToArray();
    }

    private static bool RecoveryIdentityMatches(string? actual, string? requested)
        => requested is null || string.Equals(actual, requested, StringComparison.Ordinal);

    private static string BuildMountDisplayName(MountedVolumeState mount)
    {
        var drive = TryGetDriveLetter(mount);
        var driveText = drive.HasValue ? $"{drive.Value}:" : mount.MountPoint.TrimEnd('\\');
        var volumeName = !string.IsNullOrWhiteSpace(mount.VolumeName)
            ? mount.VolumeName
            : TryParseVolumeNameFromVolumeId(mount.VolumeId);
        return string.IsNullOrWhiteSpace(volumeName)
            ? driveText
            : $"{driveText} ({volumeName})";
    }

    private static string BuildSafelyEjectedWarning(MountedVolumeState mount)
    {
        var volumeName = !string.IsNullOrWhiteSpace(mount.VolumeName)
            ? mount.VolumeName
            : TryParseVolumeNameFromVolumeId(mount.VolumeId);
        var label = string.IsNullOrWhiteSpace(volumeName)
            ? BuildMountDisplayName(mount)
            : volumeName;
        return $"'{label}' is safely ejected; unplug and reinsert it to mount again.";
    }

    private static string BuildUnsafeUnmountWarning(MountedVolumeState mount)
    {
        var volumeName = !string.IsNullOrWhiteSpace(mount.VolumeName)
            ? mount.VolumeName
            : TryParseVolumeNameFromVolumeId(mount.VolumeId);
        var label = string.IsNullOrWhiteSpace(volumeName)
            ? BuildMountDisplayName(mount)
            : volumeName;
        return $"'{label}' eject was not completed safely because pending writes were not proven durable; use Fix to recover it before remounting.";
    }

    private static string? TryParseVolumeNameFromVolumeId(string? volumeId)
    {
        if (string.IsNullOrWhiteSpace(volumeId))
        {
            return null;
        }

        var separatorIndex = volumeId.LastIndexOf('|');
        if (separatorIndex < 0 || separatorIndex >= volumeId.Length - 1)
        {
            return null;
        }

        var parsed = volumeId[(separatorIndex + 1)..].Trim();
        return string.IsNullOrWhiteSpace(parsed) ? null : parsed;
    }

    private sealed record MountAttemptOutcome(
        bool Success,
        string? Error,
        string? Warning,
        string? CompatibilityWarning,
        MountedVolumeState? MountedState);

    private sealed record PreparedContainerMount(
        VolumeInfo Volume,
        MountRequest Request,
        MountAccessMode RequestedAccess,
        bool ShouldAttemptWrite,
        string? CompatibilityWarning,
        string? DeviceDisplayName);

    private async Task<IReadOnlyList<(VolumeInfo Volume, MountAttemptOutcome Outcome)>> TryMountContainerBatchAsync(
        IContainerMountBackend containerBackend,
        IReadOnlyList<VolumeInfo> volumes,
        ServiceHostOptions options,
        HashSet<char> usedLetters,
        CancellationToken cancellationToken,
        IReadOnlyDictionary<string, string> deviceDisplayNames,
        MountAccessMode? requestedAccessMode,
        long discoveryGeneration)
    {
        var completed = new List<(VolumeInfo, MountAttemptOutcome)>(volumes.Count);
        var prepared = new List<PreparedContainerMount>(volumes.Count);
        foreach (var volume in volumes)
        {
            char letter;
            try
            {
                letter = await SelectDriveLetterForVolumeAsync(volume, usedLetters, discoveryGeneration, cancellationToken).ConfigureAwait(false);
                usedLetters.Add(letter);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "Could not allocate drive letter for {VolumeId}", volume.VolumeId);
                completed.Add((volume, new MountAttemptOutcome(false, ex.Message, null, null, null)));
                continue;
            }

            var writeDecision = WriteGatePolicy.EvaluateForVolume(options, volume);
            var requestedAccess = requestedAccessMode ??
                (writeDecision.AllowWrite ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly);
            var shouldAttemptWrite = requestedAccess == MountAccessMode.ReadWrite && writeDecision.AllowWrite;
            var primaryAccess = shouldAttemptWrite ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly;
            string? compatibilityWarning = null;
            if (!shouldAttemptWrite && options.EnableNativeWrite)
            {
                compatibilityWarning = $"Write gate is active but '{volume.VolumeName}' mounted read-only " +
                                       $"(gate={writeDecision.GateState}, reason={writeDecision.Reason ?? "n/a"}).";
            }
            prepared.Add(new PreparedContainerMount(
                volume,
                new MountRequest(volume.VolumeId, letter, primaryAccess),
                requestedAccess,
                shouldAttemptWrite,
                compatibilityWarning,
                deviceDisplayNames.GetValueOrDefault(volume.DeviceId)));
        }
        if (prepared.Count == 0)
        {
            return completed;
        }

        IReadOnlyList<MountResult> primaryResults;
        try
        {
            primaryResults = await containerBackend.MountContainerAsync(
                prepared.Select(static item => item.Request).ToArray(),
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            primaryResults = prepared.Select(_ => new MountResult(
                false, null, ex.Message, MountAccessMode.ReadOnly,
                DiagnosticCode: "ContainerBatchFailed", IsReadOnly: true)).ToArray();
        }
        if (primaryResults.Count != prepared.Count)
        {
            primaryResults = prepared.Select(_ => new MountResult(
                false, null, "Container backend returned an incomplete mount result set.",
                MountAccessMode.ReadOnly,
                DiagnosticCode: "ContainerBatchResultMismatch",
                IsReadOnly: true)).ToArray();
        }

        var finalResults = primaryResults.ToArray();
        var fallbackIndexes = Enumerable.Range(0, prepared.Count)
            .Where(index => !primaryResults[index].Success &&
                string.Equals(options.ReadWriteMode, "RwWithRoFallback", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (fallbackIndexes.Length > 0)
        {
            var fallbackRequests = fallbackIndexes
                .Select(index => prepared[index].Request with { AccessMode = MountAccessMode.ReadOnly })
                .ToArray();
            var fallbackResults = await containerBackend.MountContainerAsync(
                fallbackRequests, cancellationToken).ConfigureAwait(false);
            if (fallbackResults.Count == fallbackIndexes.Length)
            {
                for (var index = 0; index < fallbackIndexes.Length; index++)
                {
                    finalResults[fallbackIndexes[index]] = fallbackResults[index];
                }
            }
        }

        for (var index = 0; index < prepared.Count; index++)
        {
            var attempt = prepared[index];
            var primary = primaryResults[index];
            var result = finalResults[index];
            var compatibilityWarning = attempt.CompatibilityWarning;
            if (!primary.Success && result.Success && attempt.RequestedAccess == MountAccessMode.ReadWrite)
            {
                var detail = string.IsNullOrWhiteSpace(primary.Error) ? string.Empty : $" detail={primary.Error}";
                compatibilityWarning = $"Write request for '{attempt.Volume.VolumeName}' fell back to read-only " +
                                       $"(gate={result.SafetyGateState ?? "unknown"}, code={result.DiagnosticCode ?? "n/a"}{detail}).";
            }
            else if (result.Success && attempt.RequestedAccess == MountAccessMode.ReadWrite &&
                     result.EffectiveAccessMode != MountAccessMode.ReadWrite)
            {
                compatibilityWarning = $"Write request for '{attempt.Volume.VolumeName}' stayed read-only " +
                                       $"(gate={result.SafetyGateState ?? "unknown"}, code={result.DiagnosticCode ?? "n/a"}).";
            }

            if (!result.Success)
            {
                var error = result.Error ?? "Unknown error";
                _logger.LogWarning(
                    "Failed to mount volume {VolumeId}: {Error} (DiagnosticCode={DiagnosticCode})",
                    attempt.Volume.VolumeId,
                    error,
                    result.DiagnosticCode ?? "n/a");
                completed.Add((attempt.Volume, new MountAttemptOutcome(
                    false, error, null, compatibilityWarning, null)));
                continue;
            }

            var warning = BuildMountWarning(attempt.Volume, result);
            _logger.LogInformation(
                "Mounted volume {VolumeId} at {MountPoint} ({Mode}, ReadOnly={ReadOnly}).",
                attempt.Volume.VolumeId,
                result.MountPoint,
                result.EffectiveAccessMode,
                result.IsReadOnly);
            completed.Add((attempt.Volume, new MountAttemptOutcome(
                true,
                null,
                warning,
                compatibilityWarning,
                BuildMountedStateFromMountResult(attempt.Volume, result, attempt.DeviceDisplayName))));
        }
        return completed;
    }

    private async Task<(
        bool Success,
        string? Error,
        string? Warning,
        string? CompatibilityWarning,
        MountedVolumeState? MountedState)> TryMountAsync(
        VolumeInfo volume,
        ServiceHostOptions options,
        HashSet<char> usedLetters,
        CancellationToken cancellationToken,
        string? deviceDisplayName = null,
        MountAccessMode? requestedAccessMode = null,
        long discoveryGeneration = 0,
        char? preparedLetter = null
    )
    {
        char letter;
        try
        {
            if (preparedLetter.HasValue) cancellationToken.ThrowIfCancellationRequested();
            letter = preparedLetter ?? await SelectDriveLetterForVolumeAsync(volume, usedLetters, discoveryGeneration, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Could not allocate drive letter for {VolumeId}", volume.VolumeId);
            return (false, ex.Message, null, null, null);
        }

        var writeDecision = WriteGatePolicy.EvaluateForVolume(options, volume);
        var requestedAccess = requestedAccessMode ??
            (writeDecision.AllowWrite ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly);
        var shouldAttemptWrite = requestedAccess == MountAccessMode.ReadWrite && writeDecision.AllowWrite;
        var primaryAccess = shouldAttemptWrite ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly;
        var primaryRequest = new MountRequest(volume.VolumeId, letter, primaryAccess);
        var result = await _backend.MountAsync(primaryRequest, cancellationToken).ConfigureAwait(false);
        MountResult? primaryFailureResult = null;

        string? compatibilityWarning = null;
        if (!shouldAttemptWrite && options.EnableNativeWrite)
        {
            compatibilityWarning = $"Write gate is active but '{volume.VolumeName}' mounted read-only " +
                                   $"(gate={writeDecision.GateState}, reason={writeDecision.Reason ?? "n/a"}).";
        }

        if (!result.Success &&
            string.Equals(options.ReadWriteMode, "RwWithRoFallback", StringComparison.OrdinalIgnoreCase))
        {
            primaryFailureResult = result;
            var fallbackRequest = new MountRequest(volume.VolumeId, letter, MountAccessMode.ReadOnly);
            result = await _backend.MountAsync(fallbackRequest, cancellationToken).ConfigureAwait(false);

            if (requestedAccess == MountAccessMode.ReadWrite && result.Success)
            {
                var primaryFailureDetail = string.IsNullOrWhiteSpace(primaryFailureResult?.Error)
                    ? string.Empty
                    : $" detail={primaryFailureResult!.Error}";
                compatibilityWarning = $"Write request for '{volume.VolumeName}' fell back to read-only " +
                                       $"(gate={result.SafetyGateState ?? "unknown"}, code={result.DiagnosticCode ?? "n/a"}{primaryFailureDetail}).";
            }
        }
        else if (result.Success &&
                 requestedAccess == MountAccessMode.ReadWrite &&
                 result.EffectiveAccessMode != MountAccessMode.ReadWrite)
        {
            compatibilityWarning = $"Write request for '{volume.VolumeName}' stayed read-only " +
                                   $"(gate={result.SafetyGateState ?? "unknown"}, code={result.DiagnosticCode ?? "n/a"}).";
        }

        if (!result.Success)
        {
            var error = result.Error ?? "Unknown error";
            _logger.LogWarning(
                "Failed to mount volume {VolumeId}: {Error} (DiagnosticCode={DiagnosticCode})",
                volume.VolumeId,
                error,
                result.DiagnosticCode ?? "n/a"
            );
            return (false, error, null, compatibilityWarning, null);
        }

        usedLetters.Add(letter);
        var warning = BuildMountWarning(volume, result);

        _logger.LogInformation(
            "Mounted volume {VolumeId} at {MountPoint} ({Mode}, ReadOnly={ReadOnly}).",
            volume.VolumeId,
            result.MountPoint,
            result.EffectiveAccessMode,
            result.IsReadOnly
        );
        return (
            true,
            null,
            warning,
            compatibilityWarning,
            BuildMountedStateFromMountResult(volume, result, deviceDisplayName));
    }

    private bool IsMountRetryBackoffActive(string volumeId, out string warning)
    {
        warning = string.Empty;
        if (!_mountRetryStates.TryGetValue(volumeId, out var state))
        {
            return false;
        }

        var remaining = state.NextAttemptUtc - DateTime.UtcNow;
        if (remaining <= TimeSpan.Zero)
        {
            _mountRetryStates.Remove(volumeId);
            return false;
        }

        warning = $"Automatic mount retry for '{volumeId}' is paused for {Math.Ceiling(remaining.TotalSeconds):n0}s after a failed startup; use Fix or an explicit mount command to retry now.";
        return true;
    }

    private void RecordMountFailure(string volumeId, string? error)
    {
        _mountRetryStates.TryGetValue(volumeId, out var previous);
        var failureCount = Math.Min((previous?.FailureCount ?? 0) + 1, 6);
        var delaySeconds = Math.Min(60, 1 << Math.Min(failureCount - 1, 5));
        _mountRetryStates[volumeId] = new MountRetryState(
            failureCount,
            DateTime.UtcNow.AddSeconds(delaySeconds),
            error);
        _logger.LogWarning(
            "Backing off automatic mount retry for {VolumeId} for {DelaySeconds}s after failure {FailureCount}: {Error}",
            volumeId,
            delaySeconds,
            failureCount,
            error ?? "unknown error");
    }

    private static MountedVolumeState? BuildMountedStateFromMountResult(
        VolumeInfo volume,
        MountResult result,
        string? deviceDisplayName)
    {
        if (!result.Success || string.IsNullOrWhiteSpace(result.MountPoint))
        {
            return null;
        }

        var recoveryDiagnostic = result.NativeWriteDiagnostics?
            .FirstOrDefault(static diagnostic => diagnostic.IsFailClosed);
        return new MountedVolumeState(
            VolumeId: volume.VolumeId,
            MountPoint: result.MountPoint,
            AccessMode: result.EffectiveAccessMode,
            VolumeName: volume.VolumeName,
            DeviceId: volume.DeviceId,
            DeviceDisplayName: deviceDisplayName,
            WriteBackend: result.WriteBackend,
            CommitModel: result.CommitModel,
            NativeWriteReadiness: result.NativeWriteReadiness,
            NativeWriteEngineState: result.NativeWriteEngineState,
            NativeWriteValidationState: result.NativeWriteValidationState,
            RecoveryActive: result.RecoveryActive ||
                result.NativeWriteSafetyState == NativeWriteSafetyState.RecoveryBlocked,
            LastCommitXid: result.LastCommitXid,
            RecoveryReason: result.RecoveryReason ?? recoveryDiagnostic?.RecoveryReason,
            NativeWriteSafetyState: result.NativeWriteSafetyState,
            WriteIncompatibilities: result.WriteIncompatibilities ?? volume.WriteIncompatibilities,
            WriteUnsupportedFeatures: result.WriteUnsupportedFeatures ?? volume.WriteUnsupportedFeatures,
            LastRecoveryAction: result.LastRecoveryAction,
            DirtyTransactionCount: result.DirtyTransactionCount,
            ShutdownDrainActive: result.ShutdownDrainActive,
            InFlightMutationCallbacks: result.InFlightMutationCallbacks,
            NativeWriteValidationEvidence: result.NativeWriteValidationEvidence,
            NativeWriteDiagnostics: result.NativeWriteDiagnostics,
            RecoveryIdentity: volume.RecoveryIdentity,
            MountReady: result.MountReady,
            HostProcessId: result.HostProcessId,
            WalAcceptedSequence: result.WalAcceptedSequence,
            WalApfsDurableSequence: result.WalApfsDurableSequence,
            WalCleanupSequence: result.WalCleanupSequence);
    }

    private static string? BuildMountWarning(VolumeInfo volume, MountResult result)
    {
        if (result.WriteEnabled &&
            result.EffectiveAccessMode == MountAccessMode.ReadWrite &&
            !result.IsReadOnly &&
            result.NativeWriteSafetyState is NativeWriteSafetyState.PilotReadWrite or NativeWriteSafetyState.StableReadWrite)
        {
            return null;
        }

        return result.DiagnosticCode switch
        {
            "Phase1ShellMount" => $"Mounted '{volume.VolumeName}' as read-only APFS snapshot. Copy-out is supported; writes do not go back to APFS.",
            null => null,
            _ => $"Mounted '{volume.VolumeName}' with diagnostic '{result.DiagnosticCode}'.",
        };
    }

    private async Task<ShutdownPreparationResult> PrepareForShutdownCoreAsync()
    {
        var stopTimeout = TimeSpan.FromSeconds(Math.Clamp(
            _optionsMonitor.CurrentValue.NativeHostStopTimeoutSeconds,
            1,
            60));
        using var stopCts = new CancellationTokenSource(stopTimeout);
        var warnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        IReadOnlyList<MountedVolumeState> remaining = Array.Empty<MountedVolumeState>();
        UnmountBatchResult? unmount = null;

        try
        {
            await _mountOperationLock.WaitAsync(stopCts.Token).ConfigureAwait(false);
            try
            {
                var mountedBefore = (await _backend
                    .GetMountStateAsync(stopCts.Token)
                    .ConfigureAwait(false))
                    .ToArray();
                remaining = mountedBefore;

                unmount = await UnmountAsync(
                    mountedBefore,
                    stopCts.Token,
                    warnings).ConfigureAwait(false);
                var reconciliation = await ReconcileRemainingMountsAsync(
                    remaining,
                    stopTimeout).ConfigureAwait(false);
                remaining = reconciliation.Mounts;

                var allSelectedHaveResults = mountedBefore.All(mount =>
                    unmount.Results.ContainsKey(mount.VolumeId));
                var ownershipReleased = reconciliation.Succeeded &&
                                        remaining.Count == 0 &&
                                        allSelectedHaveResults &&
                                        mountedBefore.All(mount =>
                                        {
                                            var result = unmount.Results[mount.VolumeId];
                                            return result.Success &&
                                                   result.MountRemoved &&
                                                   result.HostOwnershipReleased;
                                        });
                var durabilityCleared = reconciliation.Succeeded &&
                                        remaining.Count == 0 &&
                                        allSelectedHaveResults &&
                                        mountedBefore.All(mount =>
                                        {
                                            var result = unmount.Results[mount.VolumeId];
                                            return result.Success &&
                                                   result.MountRemoved &&
                                                   result.PendingDurabilityCleared;
                                        });
                var cleanupCompleted = ownershipReleased && durabilityCleared;
                var diagnostic = cleanupCompleted
                    ? null
                    : BuildShutdownDiagnostic(
                        warnings,
                        remaining,
                        reconciliation.Diagnostic);

                return new ShutdownPreparationResult(
                    CleanupCompleted: cleanupCompleted,
                    RemainingMounts: remaining,
                    HostOwnershipReleased: ownershipReleased,
                    PendingDurabilityCleared: durabilityCleared,
                    Diagnostic: diagnostic,
                    UnmountResults: unmount.Results);
            }
            finally
            {
                _mountOperationLock.Release();
            }
        }
        catch (OperationCanceledException) when (stopCts.IsCancellationRequested)
        {
            var reconciliation = await ReconcileRemainingMountsAsync(
                remaining,
                stopTimeout).ConfigureAwait(false);
            remaining = reconciliation.Mounts;
            var diagnostic = BuildShutdownDiagnostic(
                warnings,
                remaining,
                AppendDiagnostic(
                    $"APFS shutdown cleanup did not complete within {stopTimeout.TotalSeconds:n0} seconds.",
                    reconciliation.Diagnostic));
            _logger.LogError("{Diagnostic}", diagnostic);
            return new ShutdownPreparationResult(
                CleanupCompleted: false,
                RemainingMounts: remaining,
                HostOwnershipReleased: false,
                PendingDurabilityCleared: false,
                Diagnostic: diagnostic,
                UnmountResults: unmount?.Results);
        }
        catch (Exception ex)
        {
            var reconciliation = await ReconcileRemainingMountsAsync(
                remaining,
                stopTimeout).ConfigureAwait(false);
            remaining = reconciliation.Mounts;
            var diagnostic = BuildShutdownDiagnostic(
                warnings,
                remaining,
                AppendDiagnostic(
                    $"APFS shutdown cleanup failed: {ex.Message}",
                    reconciliation.Diagnostic));
            _logger.LogError(ex, "APFS shutdown cleanup failed.");
            return new ShutdownPreparationResult(
                CleanupCompleted: false,
                RemainingMounts: remaining,
                HostOwnershipReleased: false,
                PendingDurabilityCleared: false,
                Diagnostic: diagnostic,
                UnmountResults: unmount?.Results);
        }
    }

    private async Task<MountStateReconciliation> ReconcileRemainingMountsAsync(
        IReadOnlyList<MountedVolumeState> fallback,
        TimeSpan stopTimeout)
    {
        var timeout = TimeSpan.FromSeconds(Math.Clamp(
            (int)Math.Ceiling(stopTimeout.TotalSeconds),
            1,
            5));
        using var reconciliationCts = new CancellationTokenSource(timeout);
        try
        {
            var mounts = await _backend
                .GetMountStateAsync(reconciliationCts.Token)
                .ConfigureAwait(false);
            return new MountStateReconciliation(true, mounts.ToArray(), null);
        }
        catch (OperationCanceledException) when (reconciliationCts.IsCancellationRequested)
        {
            return new MountStateReconciliation(
                false,
                fallback,
                $"Authoritative remaining-mount reconciliation timed out after {timeout.TotalSeconds:n0} seconds.");
        }
        catch (Exception ex)
        {
            return new MountStateReconciliation(
                false,
                fallback,
                $"Authoritative remaining-mount reconciliation failed: {ex.Message}");
        }
    }

    private static string BuildShutdownDiagnostic(
        IEnumerable<string> warnings,
        IReadOnlyList<MountedVolumeState> remaining,
        string? prefix = null)
    {
        var details = warnings
            .Where(static warning => !string.IsNullOrWhiteSpace(warning))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var remainingText = remaining.Count == 0
            ? null
            : $"Remaining mounts: {string.Join(", ", remaining.Select(static mount => mount.MountPoint))}.";
        return string.Join(
            " ",
            new[] { prefix, remainingText, string.Join(" ", details) }
                .Where(static text => !string.IsNullOrWhiteSpace(text)));
    }

    private static string AppendDiagnostic(string? first, string? second)
        => string.Join(
            " ",
            new[] { first, second }.Where(static value => !string.IsNullOrWhiteSpace(value)));

    private void PublishShutdownState(ShutdownPreparationResult shutdown)
    {
        var warnings = shutdown.CleanupCompleted || string.IsNullOrWhiteSpace(shutdown.Diagnostic)
            ? Array.Empty<string>()
            : new[] { shutdown.Diagnostic! };
        Publish(
            RuntimeState.Stopping,
            shutdown.RemainingMounts,
            shutdown.CleanupCompleted ? null : shutdown.Diagnostic,
            warnings,
            writeEnabled: false,
            compatibilityWarnings: Array.Empty<string>());
    }

    private async Task<UnmountBatchResult> UnmountAsync(
        IReadOnlyList<MountedVolumeState> mounted,
        CancellationToken cancellationToken,
        HashSet<string>? warnings = null
    )
    {
        var removed = new List<MountedVolumeState>(mounted.Count);
        var safelyUnmounted = new List<MountedVolumeState>(mounted.Count);
        var unsafeRemoved = new List<MountedVolumeState>(mounted.Count);
        var results = new Dictionary<string, UnmountResult>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < mounted.Count; index++)
        {
            var mount = mounted[index];
            UnmountResult result;
            try
            {
                result = await _backend
                    .UnmountAsync(mount.MountPoint, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                result = new UnmountResult(
                    Success: false,
                    MountPoint: mount.MountPoint,
                    Error: "Unmount was cancelled before terminal safety proof was returned.");
                results[mount.VolumeId] = result;
                AddNotReachedUnmountResults(mounted, index + 1, results, "shutdown cancellation");
                warnings?.Add($"Unmount cancelled for '{mount.MountPoint}' before terminal safety proof was returned.");
                break;
            }
            catch (Exception ex)
            {
                result = new UnmountResult(
                    Success: false,
                    MountPoint: mount.MountPoint,
                    Error: $"Unmount failed before terminal safety proof was returned: {ex.Message}");
                results[mount.VolumeId] = result;
                AddNotReachedUnmountResults(mounted, index + 1, results, "an earlier unmount failure");
                warnings?.Add($"Unmount failed for '{mount.MountPoint}': {ex.Message}");
                break;
            }

            results[mount.VolumeId] = result;
            var safelyRemoved = result.Success &&
                                result.MountRemoved &&
                                result.HostOwnershipReleased &&
                                result.PendingDurabilityCleared;
            if (result.MountRemoved)
            {
                removed.Add(mount);
            }
            if (safelyRemoved)
            {
                safelyUnmounted.Add(mount);
            }
            else
            {
                var error = string.IsNullOrWhiteSpace(result.Error)
                    ? "Unmount did not prove mount removal, host ownership release, and pending durability clearance."
                    : result.Error;
                _logger.LogWarning("Failed to safely unmount {MountPoint}: {Error}", mount.MountPoint, error);
                if (!string.IsNullOrWhiteSpace(error))
                {
                    warnings?.Add($"Unmount failed for '{mount.MountPoint}': {error}");
                }
                if (result.MountRemoved)
                {
                    unsafeRemoved.Add(mount);
                }
            }
        }

        return new UnmountBatchResult(removed, safelyUnmounted, unsafeRemoved, results);
    }

    private static void AddNotReachedUnmountResults(
        IReadOnlyList<MountedVolumeState> mounted,
        int startIndex,
        IDictionary<string, UnmountResult> results,
        string reason)
    {
        for (var index = startIndex; index < mounted.Count; index++)
        {
            var mount = mounted[index];
            results[mount.VolumeId] = new UnmountResult(
                Success: false,
                MountPoint: mount.MountPoint,
                Error: $"Unmount was not reached because of {reason}.");
        }
    }

    private async Task<(IReadOnlyList<MountedVolumeState> Mounted, bool Changed)> UnmountMissingVolumesAsync(
        IReadOnlyList<MountedVolumeState> mounted,
        IEnumerable<string> discoveredVolumeIds,
        HashSet<string> warnings,
        CancellationToken cancellationToken
    )
    {
        var discovered = discoveredVolumeIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var remaining = new List<MountedVolumeState>(mounted.Count);
        var changed = false;
        foreach (var mount in mounted)
        {
            if (discovered.Contains(mount.VolumeId))
            {
                _missingVolumeProbeCounts.Remove(mount.VolumeId);
                remaining.Add(mount);
                continue;
            }

            _missingVolumeProbeCounts.TryGetValue(mount.VolumeId, out var misses);
            misses++;
            _missingVolumeProbeCounts[mount.VolumeId] = misses;
            if (misses < MissingVolumeUnmountThreshold)
            {
                warnings.Add(
                    $"APFS drive '{BuildMountDisplayName(mount)}' was not seen in this scan; waiting for another scan before unmounting."
                );
                remaining.Add(mount);
                continue;
            }

            var result = await _backend.UnmountAsync(mount.MountPoint, cancellationToken).ConfigureAwait(false);
            if (!result.Success && !result.MountRemoved)
            {
                _logger.LogWarning(
                    "Failed to unmount stale mount {MountPoint}: {Error}",
                    mount.MountPoint,
                    result.Error
                );

                if (!string.IsNullOrWhiteSpace(result.Error))
                {
                    warnings.Add($"Stale unmount failed for '{mount.MountPoint}': {result.Error}");
                }
                remaining.Add(mount);
            }
            else
            {
                changed = true;
                _missingVolumeProbeCounts.Remove(mount.VolumeId);
                if (result.Success)
                {
                    _logger.LogInformation(
                        "Unmounted stale mount {MountPoint} (volume {VolumeId}).",
                        mount.MountPoint,
                        mount.VolumeId
                    );
                }
                else
                {
                    _unsafeUnmountedVolumeIds.Add(mount.VolumeId);
                    _logger.LogWarning(
                        "Stale mount {MountPoint} disappeared, but final write drain failed: {Error}",
                        mount.MountPoint,
                        result.Error
                    );
                    warnings.Add(BuildUnsafeUnmountWarning(mount));
                    if (!string.IsNullOrWhiteSpace(result.Error))
                    {
                        warnings.Add($"Stale unmount failed for '{mount.MountPoint}': {result.Error}");
                    }
                }
            }
        }

        return (remaining, changed);
    }

    private sealed record UnmountBatchResult(
        IReadOnlyList<MountedVolumeState> Removed,
        IReadOnlyList<MountedVolumeState> SafelyUnmounted,
        IReadOnlyList<MountedVolumeState> UnsafeRemoved,
        IReadOnlyDictionary<string, UnmountResult> Results
    );

    private sealed record MountStateReconciliation(
        bool Succeeded,
        IReadOnlyList<MountedVolumeState> Mounts,
        string? Diagnostic
    );

    private sealed record MountRetryState(
        int FailureCount,
        DateTime NextAttemptUtc,
        string? LastError
    );

    private sealed record DiscoverySnapshot(
        long Generation,
        ServiceHostOptions Options,
        IReadOnlyList<DeviceInfo> ConnectedDevices,
        IReadOnlyList<DeviceInventory> Inventory,
        IReadOnlyDictionary<string, VolumeInfo> VolumeById,
        IReadOnlyList<VolumeInfo> Volumes,
        IReadOnlyList<string> Warnings,
        IReadOnlyList<string> CompatibilityWarnings
    );

    private static char? TryGetDriveLetter(MountedVolumeState state)
    {
        if (string.IsNullOrWhiteSpace(state.MountPoint) || state.MountPoint.Length < 1)
        {
            return null;
        }

        return char.ToUpperInvariant(state.MountPoint[0]);
    }

    private void PublishFromMounts(
        IReadOnlyList<MountedVolumeState> mounts,
        string? lastError,
        IEnumerable<string> warnings,
        IEnumerable<string> compatibilityWarnings
    )
    {
        var warningList = warnings
            .Where(static x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var runtimeCompatibilityWarnings = BuildRuntimeCompatibilityWarnings(mounts, _optionsMonitor.CurrentValue);
        var compatibilityWarningList = compatibilityWarnings
            .Concat(runtimeCompatibilityWarnings)
            .Where(static x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static x => GetCompatibilityWarningPriority(x))
            .ThenBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var (
            writeBackend,
            commitModel,
            nativeWriteReadiness,
            nativeWriteEngineState,
            nativeWriteValidationState,
            nativeWriteValidationEvidence,
            nativeWriteDiagnostics,
            recoveryActive,
            recoveryReason,
            lastCommitXid,
            nativeWriteSafetyState,
            writeIncompatibilities,
            writeUnsupportedFeatures,
            lastRecoveryAction,
            dirtyTransactionCount,
            shutdownDrainActive,
            inFlightMutationCallbacks) = ResolveWriteTelemetry(mounts);

        if (!string.IsNullOrWhiteSpace(lastError))
        {
            Publish(
                RuntimeState.Error,
                mounts,
                lastError,
                warningList,
                writeEnabled: false,
                compatibilityWarnings: compatibilityWarningList,
                writeBackend: writeBackend,
                commitModel: commitModel,
                nativeWriteReadiness: nativeWriteReadiness,
                nativeWriteEngineState: nativeWriteEngineState,
                nativeWriteValidationState: nativeWriteValidationState,
                nativeWriteValidationEvidence: nativeWriteValidationEvidence,
                nativeWriteDiagnostics: nativeWriteDiagnostics,
                recoveryActive: recoveryActive,
                recoveryReason: recoveryReason,
                lastCommitXid: lastCommitXid,
                nativeWriteSafetyState: nativeWriteSafetyState,
                writeIncompatibilities: writeIncompatibilities,
                writeUnsupportedFeatures: writeUnsupportedFeatures,
                lastRecoveryAction: lastRecoveryAction,
                dirtyTransactionCount: dirtyTransactionCount,
                shutdownDrainActive: shutdownDrainActive,
                inFlightMutationCallbacks: inFlightMutationCallbacks
            );
            return;
        }

        RuntimeState state;
        if (mounts.Count == 0)
        {
            state = RuntimeState.Idle;
        }
        else
        {
            state = mounts.Any(static x => x.AccessMode == MountAccessMode.ReadWrite)
                ? RuntimeState.MountedRw
                : RuntimeState.MountedRo;
        }

        Publish(
            state,
            mounts,
            null,
            warningList,
            writeEnabled: mounts.Any(x => x.AccessMode == MountAccessMode.ReadWrite),
            compatibilityWarnings: compatibilityWarningList,
            writeBackend: writeBackend,
            commitModel: commitModel,
            nativeWriteReadiness: nativeWriteReadiness,
            nativeWriteEngineState: nativeWriteEngineState,
            nativeWriteValidationState: nativeWriteValidationState,
            nativeWriteValidationEvidence: nativeWriteValidationEvidence,
            nativeWriteDiagnostics: nativeWriteDiagnostics,
            recoveryActive: recoveryActive,
            recoveryReason: recoveryReason,
            lastCommitXid: lastCommitXid,
            nativeWriteSafetyState: nativeWriteSafetyState,
            writeIncompatibilities: writeIncompatibilities,
            writeUnsupportedFeatures: writeUnsupportedFeatures,
            lastRecoveryAction: lastRecoveryAction,
            dirtyTransactionCount: dirtyTransactionCount,
            shutdownDrainActive: shutdownDrainActive,
            inFlightMutationCallbacks: inFlightMutationCallbacks
        );
    }

    private static IReadOnlyList<string> BuildRuntimeCompatibilityWarnings(
        IReadOnlyList<MountedVolumeState> mounts,
        ServiceHostOptions options
    )
    {
        if (mounts.Count == 0)
        {
            return Array.Empty<string>();
        }

        var warnings = new List<string>();
        foreach (var mountEntry in mounts
            .Select(static x => new
            {
                Mount = x,
                EffectiveRecoveryReason = ResolveMountRecoveryReason(x),
            })
            .OrderBy(x => NativeWriteRecoveryReasons.GetPriority(x.EffectiveRecoveryReason))
            .ThenBy(x => x.Mount.MountPoint, StringComparer.OrdinalIgnoreCase))
        {
            var mount = mountEntry.Mount;
            var mountRecoveryReason = mountEntry.EffectiveRecoveryReason;
            var mountRecoveryAction = ResolveMountRecoveryAction(mount, mountRecoveryReason);

            if (mount.WriteIncompatibilities is { Count: > 0 })
            {
                var details = string.Join(" ", mount.WriteIncompatibilities.Where(x => !string.IsNullOrWhiteSpace(x)));
                if (!string.IsNullOrWhiteSpace(details))
                {
                    warnings.Add($"'{mount.MountPoint}' has write incompatibilities: {details}");
                }
            }

            if (mount.WriteUnsupportedFeatures is { Count: > 0 })
            {
                var details = string.Join(" ", mount.WriteUnsupportedFeatures.Where(x => !string.IsNullOrWhiteSpace(x)));
                if (!string.IsNullOrWhiteSpace(details))
                {
                    warnings.Add($"'{mount.MountPoint}' has unsupported write features: {details}");
                }
            }

            if (mount.NativeWriteSafetyState == NativeWriteSafetyState.RecoveryBlocked)
            {
                var reasonSuffix = BuildRecoveryReasonSuffix(mountRecoveryReason);
                var validationDetailSuffix = BuildValidationEvidenceDetailSuffix(mount, options);
                var actionSuffix = string.IsNullOrWhiteSpace(mountRecoveryAction)
                    ? string.Empty
                    : $" (action={mountRecoveryAction})";
                warnings.Add(
                    $"Native write is safety-blocked for '{mount.MountPoint}'{reasonSuffix}{validationDetailSuffix}{actionSuffix}."
                );
                continue;
            }

            if (mount.NativeWriteReadiness == NativeWriteReadiness.Degraded)
            {
                var reasonSuffix = BuildRecoveryReasonSuffix(mountRecoveryReason);
                var validationDetailSuffix = BuildValidationEvidenceDetailSuffix(mount, options);
                warnings.Add(
                    $"Native write is degraded for '{mount.MountPoint}'; keeping mount read-only " +
                    $"(recoveryPolicy={options.NativeWriteRecoveryPolicy}){reasonSuffix}{validationDetailSuffix}."
                );
                continue;
            }

            if (mount.NativeWriteReadiness == NativeWriteReadiness.RecoveryMode)
            {
                var reasonSuffix = BuildRecoveryReasonSuffix(mountRecoveryReason);
                var validationDetailSuffix = BuildValidationEvidenceDetailSuffix(mount, options);
                warnings.Add(
                    mount.AccessMode == MountAccessMode.ReadWrite
                        ? $"Recovery is active for '{mount.MountPoint}' in best-effort mode; native writes remain enabled{reasonSuffix}{validationDetailSuffix}."
                        : $"Recovery is active for '{mount.MountPoint}'; native writes are blocked until recovery clears{reasonSuffix}{validationDetailSuffix}."
                );
                continue;
            }

            if (mount.RecoveryActive && mount.AccessMode != MountAccessMode.ReadWrite)
            {
                var reasonSuffix = BuildRecoveryReasonSuffix(mountRecoveryReason);
                var validationDetailSuffix = BuildValidationEvidenceDetailSuffix(mount, options);
                warnings.Add($"Recovery marker is active for '{mount.MountPoint}'; mounted read-only for safety{reasonSuffix}{validationDetailSuffix}.");
            }
        }

        var shutdownDrainMountPoints = mounts
            .Where(static x => x.ShutdownDrainActive)
            .Select(static x => x.MountPoint)
            .Where(static x => !string.IsNullOrWhiteSpace(x))
            .OrderBy(static x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (shutdownDrainMountPoints.Length > 0)
        {
            var aggregatedInFlightMutations = mounts
                .Select(static x => Math.Max(0, x.InFlightMutationCallbacks))
                .Sum();
            warnings.Add(
                $"Native shutdown drain is active for {string.Join(", ", shutdownDrainMountPoints)}; " +
                $"new mutation callbacks are blocked until shutdown completes (in-flight={aggregatedInFlightMutations}).");
        }

        return warnings;
    }

    private static string? ResolveMountRecoveryReason(MountedVolumeState mount)
    {
        if (!string.IsNullOrWhiteSpace(mount.RecoveryReason))
        {
            return mount.RecoveryReason.Trim();
        }

        var diagnosticReason = (mount.NativeWriteDiagnostics ?? Array.Empty<NativeWriteDiagnostic>())
            .Where(static x => !string.IsNullOrWhiteSpace(x.RecoveryReason))
            .OrderBy(static x => NativeWriteRecoveryReasons.GetPriority(x.RecoveryReason))
            .ThenByDescending(static x => x.IsFailClosed)
            .ThenBy(x => x.Code, StringComparer.OrdinalIgnoreCase)
            .Select(static x => x.RecoveryReason!.Trim())
            .FirstOrDefault();
        return string.IsNullOrWhiteSpace(diagnosticReason)
            ? null
            : diagnosticReason;
    }

    private static string? ResolveMountRecoveryAction(MountedVolumeState mount, string? effectiveRecoveryReason)
    {
        if (!string.IsNullOrWhiteSpace(mount.LastRecoveryAction))
        {
            return mount.LastRecoveryAction.Trim();
        }

        var diagnosticAction = (mount.NativeWriteDiagnostics ?? Array.Empty<NativeWriteDiagnostic>())
            .Where(x =>
                !string.IsNullOrWhiteSpace(x.RecoveryAction) &&
                (string.IsNullOrWhiteSpace(effectiveRecoveryReason) ||
                 string.Equals(x.RecoveryReason, effectiveRecoveryReason, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(static x => x.IsFailClosed)
            .ThenBy(x => x.Code, StringComparer.OrdinalIgnoreCase)
            .Select(static x => x.RecoveryAction!.Trim())
            .FirstOrDefault();
        return string.IsNullOrWhiteSpace(diagnosticAction)
            ? null
            : diagnosticAction;
    }

    private static int GetCompatibilityWarningPriority(string warning)
    {
        if (string.IsNullOrWhiteSpace(warning))
        {
            return int.MaxValue;
        }

        var reason = NativeWriteRecoveryReasons.TryExtractReasonToken(warning);
        if (!string.IsNullOrWhiteSpace(reason))
        {
            return NativeWriteRecoveryReasons.GetPriority(reason);
        }

        return 4;
    }

    private static string BuildRecoveryReasonSuffix(string? recoveryReason)
    {
        if (string.IsNullOrWhiteSpace(recoveryReason))
        {
            return string.Empty;
        }

        var normalized = recoveryReason.Trim();
        var explanation = normalized switch
        {
            "CommitTimedOut" => "a write transaction exceeded the safety timeout",
            "CommitNotWritable" => "the write path is not writable",
            "CommitModelNotCanonical" => "the native commit path is not canonical and was blocked by policy",
            "CommitNotReady" => "native metadata state is not ready for commit",
            "CommitAllocationFailed" => "storage allocation failed during commit",
            "CommitInvariantFailed" => "consistency checks failed before commit",
            "CommitPersistOrFlushFailed" => "commit data could not be persisted or flushed",
            "CommitInterruptedBeforeCheckpointSwitch" => "commit was interrupted before checkpoint switch",
            "CommitCheckpointWriteFailed" => "checkpoint write failed",
            "CommitInterruptedBeforeCheckpointFlush" => "commit was interrupted before checkpoint flush",
            "CommitCheckpointFlushFailed" => "checkpoint flush failed",
            "NativeWriteBootstrapFailed" => "native write bootstrap failed before commit-ready state",
            "ContainerStateLoadFailed" => "container superblock state could not be loaded for native write",
            "ObjectMapLoadFailed" => "object-map state could not be loaded for native write",
            "SpacemanStateLoadFailed" => "spaceman state could not be loaded for native write",
            "VolumeStateLoadFailed" => "volume state could not be loaded for native write",
            "PersistentStateLoadFailed" => "persistent state could not be loaded for native write",
            "RootStateInvalid" => "root inode/path state failed validation",
            "IntegrityCheckFailedOnMount" => "mount-time integrity checks failed",
            "IntegrityMissingAllocationMap" => "APFS allocation map proof is missing for physical-media write mode",
            "PersistentStateAheadOfSuperblock" => "persistent state checkpoint is ahead of superblock checkpoint and requires replay",
            "PersistentStateBehindSuperblock" => "persistent state checkpoint is behind superblock checkpoint and requires conservative recovery",
            "RecoveryLoadVolumeStateFailed" => "recovery could not load volume state",
            "RecoveryPersistentStateLoadFailed" => "recovery could not load persistent state",
            "ReplayIntegrityCheckFailed" => "replay failed integrity validation",
            "ReplayMetadataStateMissing" => "replay metadata was incomplete or missing",
            "ReplayCanonicalCandidateMissing" => "canonical replay candidates were missing for non-fixture recovery",
            "ReplayCheckpointPendingWindow" => "replay checkpoint metadata indicates a pending recovery window and requires replay before writes can continue",
            "ReplayCheckpointNotPendingWindow" => "replay checkpoint metadata was present but did not describe a pending recovery window",
            "ReplayXidWindowInvalid" => "replay xid state was inconsistent",
            "ReplayCommitBlobInvalid" => "replay commit metadata was invalid",
            "ReplayCommitBlobReadFailed" => "replay commit payload could not be read",
            "ReplayInterruptedBeforeCheckpointSwitch" => "replay was interrupted before checkpoint switch",
            "ReplayCheckpointWriteFailed" => "replay failed to write checkpoint state",
            "ReplayInterruptedBeforeCheckpointFlush" => "replay was interrupted before checkpoint flush",
            "ReplayCheckpointFlushFailed" => "replay failed while flushing checkpoint state",
            "RecoveryMarkerDirty" => "a previous session ended before commit finalized",
            "RecoveryRequired" => "native recovery is required before writes can continue",
            "CanonicalPathNotActive" => "canonical path proof was missing (no explicit canonicalPathActive=true signal)",
            "CanonicalStateNotLoaded" => "canonical state was not fully loaded and canonical gate blocked writable mode",
            "CanonicalVolumeStateLoadFailed" => "canonical volume state could not be loaded for writable mode",
            "CanonicalObjectMapStateInvalid" => "canonical object-map state failed validation for writable mode",
            "CanonicalSpacemanStateInvalid" => "canonical spaceman/free-space state failed validation for writable mode",
            "CanonicalVolumeTreeStateInvalid" => "canonical volume tree state failed validation for writable mode",
            "NativeWriteNotReady" => "native write path was not ready and canonical gate blocked writable mode",
            "WriteDeviceNotAllowed" => "device was not allow-listed for canonical writable mode",
            "CommitPathNotReady" => "commit-path readiness failed canonical gate checks",
            "CanonicalCommitNotReady" => "canonical commit readiness checks did not pass",
            "FixtureCompatibilityPathActive" => "fixture compatibility path activity was detected on non-fixture media and writable mode was blocked",
            "ScaffoldCommitBlobActive" => "scaffold commit-blob mode was detected on non-fixture media and writable mode was blocked",
            "ValidationEvidenceInsufficient" => "native validation evidence does not meet the configured write-promotion threshold",
            "ValidationCrashFaultEvidenceInsufficient" => "native crash-fault validation evidence does not meet the configured write-promotion threshold",
            "ValidationCrashStageMatrixEvidenceInsufficient" => "native crash-stage matrix validation evidence does not meet the configured write-promotion threshold",
            "ValidationHardwarePilotEvidenceInsufficient" => "native hardware-pilot validation evidence does not meet the configured write-promotion threshold",
            "ValidationHotUnplugEvidenceInsufficient" => "native hot-unplug validation evidence does not meet the configured write-promotion threshold",
            "ValidationCrossOsEvidenceInsufficient" => "native cross-OS validation evidence does not meet the configured write-promotion threshold",
            "ValidationMacOsEvidenceInsufficient" => "native macOS validation evidence does not meet the configured stable write threshold",
            "ValidationMacOsConsistencyEvidenceInsufficient" => "native macOS consistency validation evidence does not meet the configured stable write threshold",
            "ValidationPowerLossReplayEvidenceInsufficient" => "native power-loss replay evidence does not meet the configured stable write threshold",
            "ValidationPowerLossEvidenceInsufficient" => "native power-loss validation evidence does not meet the configured stable write threshold",
            "ValidationCanonicalEvidenceInsufficient" => "native canonical-image validation evidence is insufficient for write promotion",
            "ValidationHardwarePilotEvidenceStale" => "native hardware-pilot validation evidence is stale and requires refreshed physical-media validation",
            "ValidationStableEvidenceStale" => "native stable-write validation evidence is stale and requires refreshed validation",
            "WriteGateBlocked" => "write-gate policy no longer allows writable mode for this volume/device",
            _ => string.Empty,
        };

        return string.IsNullOrWhiteSpace(explanation)
            ? $" (reason={normalized})"
            : $" (reason={normalized}; {explanation})";
    }

    private static string BuildValidationEvidenceDetailSuffix(MountedVolumeState mount, ServiceHostOptions options)
    {
        if (!NativeWriteRecoveryReasons.IsValidationEvidenceReason(mount.RecoveryReason))
        {
            return string.Empty;
        }

        var evidence = mount.NativeWriteValidationEvidence ?? new NativeWriteValidationEvidence();
        var requiredValidationState = ResolveRequiredValidationStateForPromotionPolicy(options.NativeWritePromotionPolicy);
        var isRawPhysical = IsRawPhysicalVolumeId(mount.VolumeId);
        var requiredCrashFaultPasses = requiredValidationState >= NativeWriteValidationState.HardwarePilotValidated &&
                                       options.NativeWriteCrashFaultMatrixRequired
            ? Math.Max(0, options.NativeWriteMinCrashFaultPasses)
            : 0;
        var requiredCrashStageMatrixPasses = requiredValidationState >= NativeWriteValidationState.HardwarePilotValidated
            ? Math.Max(0, options.NativeWriteMinCrashStageMatrixPasses)
            : 0;
        var requiredHardwarePilotPasses = requiredValidationState >= NativeWriteValidationState.HardwarePilotValidated
            ? Math.Max(0, options.NativeWriteMinHardwarePilotPasses)
            : 0;
        var requiredHotUnplugPasses = requiredValidationState >= NativeWriteValidationState.HardwarePilotValidated
            ? Math.Max(0, options.NativeWriteMinHotUnplugPasses)
            : 0;
        var requiredMacOsValidationPasses = requiredValidationState >= NativeWriteValidationState.Stable &&
                                            (options.NativeWriteCrossOsValidationRequired ||
                                             options.NativeWriteRequireMacOsValidationForStable)
            ? Math.Max(0, options.NativeWriteMinMacOsValidationPasses)
            : 0;
        var requiredMacOsConsistencyPasses = requiredValidationState >= NativeWriteValidationState.Stable
            ? Math.Max(0, options.NativeWriteMinMacOsConsistencyPasses)
            : 0;
        var requiredPowerLossReplayPasses = requiredValidationState >= NativeWriteValidationState.Stable &&
                                            options.NativeWriteStableRequiresPowerLossPass
            ? Math.Max(0, options.NativeWriteMinPowerLossReplayPasses)
            : 0;
        var requiredPowerLossPass = requiredValidationState >= NativeWriteValidationState.Stable &&
                                    options.NativeWriteStableRequiresPowerLossPass;
        var maxEvidenceAgeDays = requiredValidationState >= NativeWriteValidationState.HardwarePilotValidated &&
                                 isRawPhysical
            ? Math.Max(0, options.NativeWriteValidationEvidenceMaxAgeDays)
            : 0;
        var stale = maxEvidenceAgeDays > 0 &&
                    IsValidationEvidenceStale(evidence.LastValidatedUtc, maxEvidenceAgeDays, DateTime.UtcNow);
        return $" (evidence scope={(isRawPhysical ? "raw" : "nonraw")}, " +
               $"crash={Math.Max(0, evidence.CrashFaultPasses)}/{requiredCrashFaultPasses}, " +
               $"crashMatrix={Math.Max(0, evidence.CrashStageMatrixPasses)}/{requiredCrashStageMatrixPasses}, " +
               $"hardware={Math.Max(0, evidence.HardwarePilotPasses)}/{requiredHardwarePilotPasses}, " +
               $"hotUnplug={Math.Max(0, evidence.HotUnplugPasses)}/{requiredHotUnplugPasses}, " +
               $"macos={Math.Max(0, evidence.MacOsValidationPasses)}/{requiredMacOsValidationPasses}, " +
               $"macosConsistency={Math.Max(0, evidence.MacOsConsistencyPasses)}/{requiredMacOsConsistencyPasses}, " +
               $"powerLossReplay={Math.Max(0, evidence.PowerLossReplayPasses)}/{requiredPowerLossReplayPasses}, " +
               $"powerLoss={(evidence.PowerLossPassVerified ? "true" : "false")}/{(requiredPowerLossPass ? "true" : "false")}, " +
               $"lastValidatedUtc={FormatValidationLastValidatedUtc(evidence.LastValidatedUtc)}, " +
               $"profile={evidence.LastValidationProfileId ?? "n/a"}, " +
               $"maxAgeDays={maxEvidenceAgeDays}, stale={(stale ? "true" : "false")})";
    }

    private static NativeWriteValidationState ResolveRequiredValidationStateForPromotionPolicy(string? promotionPolicy)
    {
        if (string.Equals(promotionPolicy?.Trim(), "Stable", StringComparison.OrdinalIgnoreCase))
        {
            return NativeWriteValidationState.Stable;
        }

        if (string.Equals(promotionPolicy?.Trim(), "PilotHardware", StringComparison.OrdinalIgnoreCase))
        {
            return NativeWriteValidationState.HardwarePilotValidated;
        }

        return NativeWriteValidationState.CanonicalImageValidated;
    }

    private static bool IsRawPhysicalVolumeId(string? volumeId)
    {
        if (string.IsNullOrWhiteSpace(volumeId))
        {
            return false;
        }

        var normalized = volumeId.Trim();
        var separatorIndex = normalized.IndexOf('|');
        var deviceToken = separatorIndex > 0
            ? normalized[..separatorIndex]
            : normalized;
        return deviceToken.StartsWith(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase) ||
               deviceToken.StartsWith(@"\\?\PhysicalDrive", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsValidationEvidenceStale(DateTime? lastValidatedUtc, int maxAgeDays, DateTime nowUtc)
    {
        if (maxAgeDays <= 0)
        {
            return false;
        }

        if (!lastValidatedUtc.HasValue)
        {
            return true;
        }

        var normalized = lastValidatedUtc.Value.Kind switch
        {
            DateTimeKind.Utc => lastValidatedUtc.Value,
            DateTimeKind.Local => lastValidatedUtc.Value.ToUniversalTime(),
            _ => DateTime.SpecifyKind(lastValidatedUtc.Value, DateTimeKind.Utc),
        };
        if (normalized > nowUtc)
        {
            return false;
        }

        return (nowUtc - normalized) > TimeSpan.FromDays(maxAgeDays);
    }

    private static string FormatValidationLastValidatedUtc(DateTime? value)
    {
        if (!value.HasValue)
        {
            return "n/a";
        }

        var normalized = value.Value.Kind switch
        {
            DateTimeKind.Utc => value.Value,
            DateTimeKind.Local => value.Value.ToUniversalTime(),
            _ => DateTime.SpecifyKind(value.Value, DateTimeKind.Utc),
        };
        return normalized.ToString("o");
    }

    private void Publish(
        RuntimeState state,
        IReadOnlyList<MountedVolumeState> mounts,
        string? lastError,
        IReadOnlyList<string> warnings,
        bool writeEnabled,
        IReadOnlyList<string> compatibilityWarnings,
        string writeBackend = "Disabled",
        NativeWriteCommitModel commitModel = NativeWriteCommitModel.ScaffoldCheckpoint,
        NativeWriteReadiness nativeWriteReadiness = NativeWriteReadiness.Unavailable,
        NativeWriteEngineState nativeWriteEngineState = NativeWriteEngineState.Scaffold,
        NativeWriteValidationState nativeWriteValidationState = NativeWriteValidationState.Scaffold,
        NativeWriteValidationEvidence? nativeWriteValidationEvidence = null,
        IReadOnlyList<NativeWriteDiagnostic>? nativeWriteDiagnostics = null,
        bool recoveryActive = false,
        string? recoveryReason = null,
        ulong? lastCommitXid = null,
        NativeWriteSafetyState nativeWriteSafetyState = NativeWriteSafetyState.ReadOnlyFallback,
        IReadOnlyList<string>? writeIncompatibilities = null,
        IReadOnlyList<string>? writeUnsupportedFeatures = null,
        string? lastRecoveryAction = null,
        int dirtyTransactionCount = 0,
        bool shutdownDrainActive = false,
        int inFlightMutationCallbacks = 0
    )
    {
        _statusPublisher.Publish(
            new StatusChangedPayload(
                State: state,
                MountPoints: mounts
                    .Select(static mount => mount.MountPoint)
                    .OrderBy(static mountPoint => mountPoint, StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                MountedVolumes: BuildMountedVolumeDisplays(mounts).Select(m => m with {
                    DriveLetterPreference = PreferenceForDisplay(m.DeviceId, m.VolumeId, m.CatalogVolumeId, m.MountPoint)
                }).ToArray(),
                LastError: lastError,
                TimestampUtc: DateTime.UtcNow,
                Warnings: warnings,
                WriteEnabled: writeEnabled,
                CompatibilityWarnings: compatibilityWarnings,
                WriteBackend: writeBackend,
                CommitModel: commitModel,
                NativeWriteReadiness: nativeWriteReadiness,
                NativeWriteEngineState: nativeWriteEngineState,
                NativeWriteValidationState: nativeWriteValidationState,
                NativeWriteValidationEvidence: nativeWriteValidationEvidence,
                RecoveryActive: recoveryActive,
                RecoveryReason: recoveryReason,
                LastCommitXid: lastCommitXid,
                NativeWriteSafetyState: nativeWriteSafetyState,
                WriteIncompatibilities: writeIncompatibilities,
                WriteUnsupportedFeatures: writeUnsupportedFeatures,
                LastRecoveryAction: lastRecoveryAction,
                DirtyTransactionCount: dirtyTransactionCount,
                ShutdownDrainActive: shutdownDrainActive,
                InFlightMutationCallbacks: inFlightMutationCallbacks,
                NativeWriteDiagnostics: nativeWriteDiagnostics
            )
        );
    }

    private static IReadOnlyList<MountedVolumeDisplay> BuildMountedVolumeDisplays(IReadOnlyList<MountedVolumeState> mounts)
        => mounts
            .Where(static mount => !string.IsNullOrWhiteSpace(mount.MountPoint))
            .Select(static mount => new MountedVolumeDisplay(
                VolumeId: mount.VolumeId,
                MountPoint: mount.MountPoint,
                VolumeName: !string.IsNullOrWhiteSpace(mount.VolumeName)
                    ? mount.VolumeName
                    : TryParseVolumeNameFromVolumeId(mount.VolumeId) ?? "APFS",
                DeviceId: !string.IsNullOrWhiteSpace(mount.DeviceId)
                    ? mount.DeviceId
                    : TryParseDeviceIdFromVolumeId(mount.VolumeId) ?? string.Empty,
                DeviceDisplayName: !string.IsNullOrWhiteSpace(mount.DeviceDisplayName)
                    ? mount.DeviceDisplayName
                    : TryParseDeviceIdFromVolumeId(mount.VolumeId) ?? "APFS drive",
                AccessMode: mount.AccessMode,
                RecoveryIdentity: mount.RecoveryIdentity,
                State: mount.AccessMode == MountAccessMode.ReadWrite
                    ? RuntimeState.MountedRw
                    : RuntimeState.MountedRo,
                WriteEnabled: mount.AccessMode == MountAccessMode.ReadWrite,
                WriteBackend: mount.WriteBackend,
                CommitModel: mount.CommitModel,
                NativeWriteReadiness: mount.NativeWriteReadiness,
                NativeWriteEngineState: mount.NativeWriteEngineState,
                NativeWriteValidationState: mount.NativeWriteValidationState,
                NativeWriteSafetyState: mount.NativeWriteSafetyState,
                RecoveryActive: mount.RecoveryActive,
                RecoveryReason: mount.RecoveryReason,
                LastRecoveryAction: mount.LastRecoveryAction,
                LastCommitXid: mount.LastCommitXid,
                WriteIncompatibilities: mount.WriteIncompatibilities,
                WriteUnsupportedFeatures: mount.WriteUnsupportedFeatures,
                DirtyTransactionCount: mount.DirtyTransactionCount,
                ShutdownDrainActive: mount.ShutdownDrainActive,
                InFlightMutationCallbacks: mount.InFlightMutationCallbacks,
                NativeWriteValidationEvidence: mount.NativeWriteValidationEvidence,
                NativeWriteDiagnostics: mount.NativeWriteDiagnostics,
                MountReady: mount.MountReady,
                HostProcessId: mount.HostProcessId,
                WalAcceptedSequence: mount.WalAcceptedSequence,
                WalApfsDurableSequence: mount.WalApfsDurableSequence,
                WalCleanupSequence: mount.WalCleanupSequence,
                PendingDurability: mount.WalAcceptedSequence > mount.WalApfsDurableSequence ||
                    mount.DirtyTransactionCount > 0 ||
                    mount.ShutdownDrainActive ||
                    mount.InFlightMutationCallbacks > 0,
                HostOwnershipState: mount.HostProcessId > 0 ? "owned" : "unknown",
                CatalogVolumeId: mount.CatalogVolumeId,
                CatalogContainerUuid: mount.CatalogContainerUuid,
                CatalogVolumeObjectId: mount.CatalogVolumeObjectId,
                CatalogDecision: mount.CatalogDecision,
                CatalogReasons: mount.CatalogReasons,
                CatalogAutoMountAllowed: mount.CatalogAutoMountAllowed))
            .OrderBy(static volume => volume.MountPoint, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static string? TryParseDeviceIdFromVolumeId(string? volumeId)
    {
        if (string.IsNullOrWhiteSpace(volumeId))
        {
            return null;
        }

        var separatorIndex = volumeId.IndexOf('|');
        if (separatorIndex <= 0)
        {
            return null;
        }

        var parsed = volumeId[..separatorIndex].Trim();
        return string.IsNullOrWhiteSpace(parsed) ? null : parsed;
    }

    private static (
        string WriteBackend,
        NativeWriteCommitModel CommitModel,
        NativeWriteReadiness NativeWriteReadiness,
        NativeWriteEngineState NativeWriteEngineState,
        NativeWriteValidationState NativeWriteValidationState,
        NativeWriteValidationEvidence NativeWriteValidationEvidence,
        IReadOnlyList<NativeWriteDiagnostic> NativeWriteDiagnostics,
        bool RecoveryActive,
        string? RecoveryReason,
        ulong? LastCommitXid,
        NativeWriteSafetyState NativeWriteSafetyState,
        IReadOnlyList<string> WriteIncompatibilities,
        IReadOnlyList<string> WriteUnsupportedFeatures,
        string? LastRecoveryAction,
        int DirtyTransactionCount,
        bool ShutdownDrainActive,
        int InFlightMutationCallbacks
    ) ResolveWriteTelemetry(IReadOnlyList<MountedVolumeState> mounts)
    {
        if (mounts.Count == 0)
        {
            return (
                "Disabled",
                NativeWriteCommitModel.ScaffoldCheckpoint,
                NativeWriteReadiness.Unavailable,
                NativeWriteEngineState.Scaffold,
                NativeWriteValidationState.Scaffold,
                new NativeWriteValidationEvidence(),
                Array.Empty<NativeWriteDiagnostic>(),
                false,
                null,
                null,
                NativeWriteSafetyState.ReadOnlyFallback,
                Array.Empty<string>(),
                Array.Empty<string>(),
                null,
                0,
                false,
                0);
        }

        var normalizedBackends = mounts
            .Select(static x => NormalizeWriteBackend(x.WriteBackend))
            .Where(static x => !string.Equals(x, "Disabled", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var writeBackend = normalizedBackends.Length > 0
            ? normalizedBackends[0]
            : "Disabled";
        var commitModel = mounts
            .Select(static x => x.CommitModel)
            .DefaultIfEmpty(NativeWriteCommitModel.ScaffoldCheckpoint)
            .MaxBy(static x => (int)x);

        var nativeWriteReadiness = mounts
            .Select(static x => x.NativeWriteReadiness)
            .DefaultIfEmpty(NativeWriteReadiness.Unavailable)
            .MaxBy(static x => (int)x);
        var nativeWriteEngineState = mounts
            .Select(static x => x.NativeWriteEngineState)
            .DefaultIfEmpty(NativeWriteEngineState.Scaffold)
            .MaxBy(static x => (int)x);
        var nativeWriteValidationState = mounts
            .Select(static x => x.NativeWriteValidationState)
            .DefaultIfEmpty(NativeWriteValidationState.Scaffold)
            .MaxBy(static x => (int)x);
        var nativeWriteValidationEvidence = BuildValidationEvidenceAggregate(mounts);
        var nativeWriteDiagnostics = mounts
            .SelectMany(static x => x.NativeWriteDiagnostics ?? Array.Empty<NativeWriteDiagnostic>())
            .Where(static x => !string.IsNullOrWhiteSpace(x.Code))
            .Distinct()
            .OrderBy(static x => x.Code, StringComparer.OrdinalIgnoreCase)
            .ThenBy(static x => x.Scope, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var recoveryActive = mounts.Any(static x => x.RecoveryActive);
        var primaryRecoveryMount = mounts
            .Select(static x => new
            {
                Mount = x,
                EffectiveRecoveryReason = ResolveMountRecoveryReason(x),
            })
            .Where(static x => !string.IsNullOrWhiteSpace(x.EffectiveRecoveryReason))
            .OrderBy(x => NativeWriteRecoveryReasons.GetPriority(x.EffectiveRecoveryReason))
            .ThenByDescending(static x => (int)x.Mount.NativeWriteReadiness)
            .ThenBy(x => x.Mount.MountPoint, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
        var recoveryReason = primaryRecoveryMount?.EffectiveRecoveryReason?.Trim();
        var lastCommitCandidates = mounts
            .Where(static x => x.LastCommitXid.HasValue)
            .Select(static x => x.LastCommitXid!.Value);
        var lastCommitXid = lastCommitCandidates.Any()
            ? lastCommitCandidates.Max()
            : (ulong?)null;
        var safetyState = mounts
            .Select(static x => x.NativeWriteSafetyState)
            .DefaultIfEmpty(NativeWriteSafetyState.ReadOnlyFallback)
            .MaxBy(static x => (int)x);
        var writeIncompatibilities = mounts
            .SelectMany(static x => x.WriteIncompatibilities ?? Array.Empty<string>())
            .Where(static x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var writeUnsupportedFeatures = mounts
            .SelectMany(static x => x.WriteUnsupportedFeatures ?? Array.Empty<string>())
            .Where(static x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var lastRecoveryAction = primaryRecoveryMount is not null
            ? ResolveMountRecoveryAction(primaryRecoveryMount.Mount, primaryRecoveryMount.EffectiveRecoveryReason)
            : null;
        if (string.IsNullOrWhiteSpace(lastRecoveryAction))
        {
            lastRecoveryAction = mounts
                .Select(static x => new
                {
                    Mount = x,
                    EffectiveRecoveryReason = ResolveMountRecoveryReason(x),
                })
                .Where(static x => !string.IsNullOrWhiteSpace(x.EffectiveRecoveryReason))
                .OrderBy(x => NativeWriteRecoveryReasons.GetPriority(x.EffectiveRecoveryReason))
                .ThenByDescending(static x => (int)x.Mount.NativeWriteReadiness)
                .ThenBy(x => x.Mount.MountPoint, StringComparer.OrdinalIgnoreCase)
                .Select(x => ResolveMountRecoveryAction(x.Mount, x.EffectiveRecoveryReason))
                .Where(static x => !string.IsNullOrWhiteSpace(x))
                .FirstOrDefault();
        }
        var dirtyTransactionCount = mounts
            .Select(static x => Math.Max(0, x.DirtyTransactionCount))
            .Sum();
        var shutdownDrainActive = mounts.Any(static x => x.ShutdownDrainActive);
        var inFlightMutationCallbacks = mounts
            .Select(static x => Math.Max(0, x.InFlightMutationCallbacks))
            .Sum();

        return (
            writeBackend,
            commitModel,
            nativeWriteReadiness,
            nativeWriteEngineState,
            nativeWriteValidationState,
            nativeWriteValidationEvidence,
            nativeWriteDiagnostics,
            recoveryActive,
            recoveryReason,
            lastCommitXid,
            safetyState,
            writeIncompatibilities,
            writeUnsupportedFeatures,
            lastRecoveryAction,
            dirtyTransactionCount,
            shutdownDrainActive,
            inFlightMutationCallbacks);
    }

    private static NativeWriteValidationEvidence BuildValidationEvidenceAggregate(
        IReadOnlyList<MountedVolumeState> mounts)
    {
        var crashFaultPasses = 0;
        var crashStageMatrixPasses = 0;
        var hardwarePilotPasses = 0;
        var hotUnplugPasses = 0;
        var macOsValidationPasses = 0;
        var macOsConsistencyPasses = 0;
        var powerLossReplayPasses = 0;
        var powerLossPassVerified = false;
        DateTime? lastValidatedUtc = null;
        string? lastValidationProfileId = null;

        foreach (var mount in mounts)
        {
            if (mount.NativeWriteValidationEvidence is not { } evidence)
            {
                continue;
            }

            crashFaultPasses = Math.Max(crashFaultPasses, Math.Max(0, evidence.CrashFaultPasses));
            crashStageMatrixPasses = Math.Max(crashStageMatrixPasses, Math.Max(0, evidence.CrashStageMatrixPasses));
            hardwarePilotPasses = Math.Max(hardwarePilotPasses, Math.Max(0, evidence.HardwarePilotPasses));
            hotUnplugPasses = Math.Max(hotUnplugPasses, Math.Max(0, evidence.HotUnplugPasses));
            macOsValidationPasses = Math.Max(macOsValidationPasses, Math.Max(0, evidence.MacOsValidationPasses));
            macOsConsistencyPasses = Math.Max(macOsConsistencyPasses, Math.Max(0, evidence.MacOsConsistencyPasses));
            powerLossReplayPasses = Math.Max(powerLossReplayPasses, Math.Max(0, evidence.PowerLossReplayPasses));
            powerLossPassVerified |= evidence.PowerLossPassVerified;

            if (!string.IsNullOrWhiteSpace(evidence.LastValidationProfileId) &&
                (lastValidationProfileId is null || !lastValidatedUtc.HasValue))
            {
                lastValidationProfileId = evidence.LastValidationProfileId;
            }

            if (evidence.LastValidatedUtc.HasValue)
            {
                if (!lastValidatedUtc.HasValue || evidence.LastValidatedUtc.Value > lastValidatedUtc.Value)
                {
                    lastValidatedUtc = evidence.LastValidatedUtc.Value;
                    lastValidationProfileId = evidence.LastValidationProfileId ?? lastValidationProfileId;
                }
            }
        }

        return new NativeWriteValidationEvidence(
            CrashFaultPasses: crashFaultPasses,
            CrashStageMatrixPasses: crashStageMatrixPasses,
            HardwarePilotPasses: hardwarePilotPasses,
            HotUnplugPasses: hotUnplugPasses,
            MacOsValidationPasses: macOsValidationPasses,
            MacOsConsistencyPasses: macOsConsistencyPasses,
            PowerLossReplayPasses: powerLossReplayPasses,
            PowerLossPassVerified: powerLossPassVerified,
            LastValidatedUtc: lastValidatedUtc,
            LastValidationProfileId: lastValidationProfileId
        );
    }

    private static string NormalizeWriteBackend(string? writeBackend)
    {
        if (string.Equals(writeBackend, "Native", StringComparison.OrdinalIgnoreCase))
        {
            return "Native";
        }

        if (string.Equals(writeBackend, "Overlay", StringComparison.OrdinalIgnoreCase))
        {
            return "Overlay";
        }

        return "Disabled";
    }
}

public sealed record ShutdownPreparationResult(
    bool CleanupCompleted,
    IReadOnlyList<MountedVolumeState> RemainingMounts,
    bool HostOwnershipReleased,
    bool PendingDurabilityCleared,
    string? Diagnostic,
    IReadOnlyDictionary<string, UnmountResult>? UnmountResults = null)
{
    public IReadOnlyList<string> RemainingMountPoints => RemainingMounts
        .Select(static mount => mount.MountPoint)
        .ToArray();

    public IReadOnlyDictionary<string, UnmountResult> UnmountResultsOrEmpty =>
        UnmountResults ?? EmptyUnmountResults;

    private static IReadOnlyDictionary<string, UnmountResult> EmptyUnmountResults { get; } =
        new Dictionary<string, UnmountResult>(StringComparer.OrdinalIgnoreCase);
}

public sealed record EjectOperationResult(
    bool Success,
    string Message,
    IReadOnlyList<MountedVolumeState> RemainingMounts,
    IReadOnlyDictionary<string, UnmountResult> UnmountResults);
