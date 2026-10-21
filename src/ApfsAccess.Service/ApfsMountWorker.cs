using System.Collections.Concurrent;
using System.Diagnostics;
using ApfsAccess.Backend.Native;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service;

public sealed partial class ApfsMountWorker : BackgroundService
{
    private readonly ILogger<ApfsMountWorker> _logger;
    private readonly IApfsBackend _backend;
    private readonly IMountPolicy _mountPolicy;
    private readonly RuntimeStatusPublisher _statusPublisher;
    private readonly IOptionsMonitor<ServiceHostOptions> _optionsMonitor;
    private readonly PhysicalWritePermissions? _physicalWritePermissions;
    private readonly HashSet<string> _mountedOnce = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _userEjectedVolumeIds = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _unsafeUnmountedVolumeIds = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _missingVolumeProbeCounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, MountRetryState> _mountRetryStates = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _mountOperationLock = new(1, 1);
    private readonly object _shutdownSync = new();
    private Task<ShutdownPreparationResult>? _shutdownPreparation;
    private IReadOnlyList<MountedVolumeState>? _shutdownSelectedMounts;
    private long _mountCommandGeneration;
    private long _mountOperationGeneration;
    private readonly object _discoveryAdmissionSync = new();
    private long _discoveryGeneration;
    private long _admittedDiscoveryGeneration;
    private long _selectionEvidenceGeneration;
    private DiscoverySnapshot? _admittedDiscovery;
    private readonly SemaphoreSlim _preferenceOperationLock = new(1, 1);
    private readonly AsyncLocal<DeferredNotifications?> _deferredNotifications = new();
    private int _shutdownRequested;
    private readonly ConcurrentDictionary<(string Device, string Volume, string? Catalog, char Letter), string?> _selectedVolumeUuids = new();
    private IReadOnlyList<VolumeInfo> _preferenceVolumes = Array.Empty<VolumeInfo>();
    private const int MissingVolumeUnmountThreshold = 2;
    public ApfsMountWorker(
        ILogger<ApfsMountWorker> logger,
        IApfsBackend backend,
        IMountPolicy mountPolicy,
        RuntimeStatusPublisher statusPublisher,
        IOptionsMonitor<ServiceHostOptions> optionsMonitor,
        PhysicalWritePermissions? physicalWritePermissions = null
    )
    {
        _logger = logger;
        _backend = backend;
        _mountPolicy = mountPolicy;
        _statusPublisher = statusPublisher;
        _optionsMonitor = optionsMonitor;
        _physicalWritePermissions = physicalWritePermissions;
    }

    public Task<ShutdownPreparationResult> PrepareForShutdownAsync(CancellationToken cancellationToken)
        => PrepareForShutdownAsync(cancellationToken, retryIncomplete: false);

    internal Task<ShutdownPreparationResult> PrepareFreshShutdownAttemptAsync(CancellationToken cancellationToken)
        => PrepareForShutdownAsync(cancellationToken, retryIncomplete: true);

    private Task<ShutdownPreparationResult> PrepareForShutdownAsync(CancellationToken cancellationToken, bool retryIncomplete)
    {
        Interlocked.Exchange(ref _shutdownRequested, 1);
        ReserveEncryptedCommand();

        Task<ShutdownPreparationResult> preparation;
        lock (_shutdownSync)
        {
            if (_shutdownPreparation is null)
                _shutdownPreparation = PrepareForShutdownCoreAsync(null);
            else if (retryIncomplete && _shutdownPreparation.IsCompleted &&
                     !(_shutdownPreparation.IsCompletedSuccessfully && _shutdownPreparation.Result.CleanupCompleted))
                _shutdownPreparation = PrepareForShutdownCoreAsync(
                    _shutdownPreparation.IsCompletedSuccessfully ? _shutdownPreparation.Result : null);
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
        using var notifications = new DeferredNotifications(this);
        if (Volatile.Read(ref _shutdownRequested) != 0)
        {
            return;
        }

        await ReconcileVolumeIntentsAsync(cancellationToken).ConfigureAwait(false);
        var commandGeneration = Volatile.Read(ref _mountCommandGeneration);
        var discovery = await DiscoverVolumesAsync(cancellationToken).ConfigureAwait(false);

        await _mountOperationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _shutdownRequested) != 0 ||
                commandGeneration != Volatile.Read(ref _mountCommandGeneration))
            {
                return;
            }

            await ObserveVolumeManagementAvailabilityAsync(discovery.Inventory, cancellationToken).ConfigureAwait(false);
            var mounted = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
            // An empty, auto-mount-disabled cycle cannot change backend ownership.
            if (discovery.Options.AutoMountEnabled || mounted.Count != 0) ++_mountOperationGeneration;
            await RunCycleCoreAsync(discovery, cancellationToken, mounted).ConfigureAwait(false);
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
        DeviceInventory[] inventory;
        try
        {
            inventory = (await _backend.ProbeInventoryAsync(authoritative: true, cancellationToken).ConfigureAwait(false))
                .Where(d => d.Device.IsConnected)
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
                else if (!CatalogMountPolicy.AllowsOrdinaryMount(volume) && !CatalogMountPolicy.AllowsReadOnlyInspection(volume))
                {
                    warnings.Add(CatalogMountPolicy.Refusal(volume, requestedMode: null));
                }

                var writeDecision = EvaluateVolumeWriteGate(options, volume);
                if (options.EnableNativeWrite && !writeDecision.AllowWrite && CatalogMountPolicy.AllowsOrdinaryMount(volume))
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
        catch
        {
            // Probe, projection and policy failures all invalidate older identity.
            // An older failed observation cannot erase a newer admission.
            TryAdmitDiscovery(new(generation, options, [], [],
                new Dictionary<string, VolumeInfo>(), [], [], []));
            throw;
        }
    }

    private async Task RunCycleCoreAsync(
        DiscoverySnapshot discovery,
        CancellationToken cancellationToken,
        IReadOnlyList<MountedVolumeState>? mountedOverride = null,
        string? requestedVolumeId = null,
        string? requestedDeviceId = null,
        MountAccessMode? requestedAccessMode = null,
        string? requestedRecoveryIdentity = null, ApfsControlTarget? selectedTarget = null,
        IReadOnlySet<string>? requestedContainerVolumeIds = null,
        Func<CancellationToken, Task>? validateMountMutation = null)
    {
        var options = discovery.Options;
        var scopedMount = selectedTarget is not null || requestedContainerVolumeIds is not null;
        var connectedDevices = discovery.ConnectedDevices;
        var discoveredVolumeById = discovery.VolumeById;
        // Keep duplicate rows across devices: deduplicating by routing ID would hide
        // ambiguous identities. All selection paths run here under the mount lock.
        if (!(scopedMount ? TryAdmitSelectedDiscovery(discovery) : TryAdmitDiscovery(discovery)))
        {
            if (scopedMount) throw new SelectionSupersededException();
            return;
        }
        var warnings = new HashSet<string>(discovery.Warnings, StringComparer.OrdinalIgnoreCase);
        var compatibilityWarnings = new HashSet<string>(
            discovery.CompatibilityWarnings,
            StringComparer.OrdinalIgnoreCase);

        // Explicit-eject suppression is session-scoped and never auto-clears
        // on discovery signals: backend group turmoil after a container
        // unmount can gap whole devices (not just rows) for tens of seconds,
        // which is indistinguishable from a brief unplug at this layer, and
        // any reappearance-triggered clearing auto-remounts just-unmounted
        // volumes. Suppression clears only on explicit mount/fix of the
        // volume through the normal mount path, or on service restart (fresh
        // boot auto-mounts eligible volumes as before). Consequence: after
        // an explicit eject + physical replug in the same session, use Mount
        // to mount again; this is the safe direction and is stated in the
        // ejected warning below.

        var mounted = (mountedOverride ?? await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false)).ToList();
        var unmountMissingResult = await UnmountMissingVolumesAsync(
            scopedMount ? [] : mounted,
            discoveredVolumeById.Keys,
            warnings,
            cancellationToken
        ).ConfigureAwait(false);
        if (!scopedMount) mounted = unmountMissingResult.Mounted.ToList();
        var mountStateChanged = unmountMissingResult.Changed;

        // Enforce explicit-eject intent against mounts that bypassed
        // suppression (backend host-startup mounts, discovery races):
        // anything mounted while suppressed is unmounted again. Explicit
        // mount clears suppression before mounting, so this never fights
        // user intent; failures stay visible and retry next cycle.
        if (!scopedMount)
        {
            foreach (var mount in mounted.ToArray())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!_userEjectedVolumeIds.Contains(mount.VolumeId))
                {
                    continue;
                }

                UnmountResult enforcement;
                try
                {
                    enforcement = await _backend.UnmountAsync(mount.MountPoint, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    warnings.Add($"Suppressed mount '{BuildMountDisplayName(mount)}' could not be released: {ex.Message}");
                    continue;
                }

                if (enforcement.MountRemoved)
                {
                    mounted.RemoveAll(candidate => string.Equals(
                        candidate.VolumeId,
                        mount.VolumeId,
                        StringComparison.OrdinalIgnoreCase));
                    mountStateChanged = true;
                    warnings.Add($"'{mount.VolumeName}' was mounted despite explicit eject suppression and was unmounted to honor it.");
                }
                else
                {
                    warnings.Add($"Suppressed mount '{BuildMountDisplayName(mount)}' resisted release: {enforcement.Error ?? "no terminal proof"}.");
                }
            }
        }

        // A failed attempt belongs only to a still-connected, unmounted volume
        // that has not been explicitly suppressed.
        foreach (var volumeId in _mountRetryStates.Keys.ToArray())
        {
            if (!discoveredVolumeById.ContainsKey(volumeId) ||
                mounted.Any(mount => string.Equals(mount.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase)) ||
                _userEjectedVolumeIds.Contains(volumeId) || _unsafeUnmountedVolumeIds.Contains(volumeId))
            {
                _mountRetryStates.Remove(volumeId);
            }
        }

        if (connectedDevices.Count == 0)
        {
            // Suppression outlives empty discoveries: replug clears it
            // selectively when devices reappear (see above), so a full
            // discovery outage must not wipe explicit-eject intent.
            PublishFromMounts(mounted, null, warnings, compatibilityWarnings);
            return;
        }

        if (!options.AutoMountEnabled && string.IsNullOrWhiteSpace(requestedVolumeId) && requestedContainerVolumeIds is null)
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
            if (requestedContainerVolumeIds is not null && !requestedContainerVolumeIds.Contains(volume.VolumeId))
            {
                continue;
            }
            if (VolumeIntentBlocks(volume.DeviceId))
            {
                warnings.Add("Volume management intent requires reconciliation for " + volume.DeviceId);
                continue;
            }
            var isRequestedVolume = !string.IsNullOrWhiteSpace(requestedVolumeId) &&
                string.Equals(volume.VolumeId, requestedVolumeId, StringComparison.OrdinalIgnoreCase);

            var isContainerSiblingForInitialOwner = false;
            if (!string.IsNullOrWhiteSpace(requestedVolumeId) && !isRequestedVolume &&
                discoveredVolumeById.TryGetValue(requestedVolumeId, out var targetVol) &&
                !string.IsNullOrWhiteSpace(targetVol.CatalogContainerUuid) &&
                string.Equals(volume.CatalogContainerUuid, targetVol.CatalogContainerUuid, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(volume.DeviceId, targetVol.DeviceId, StringComparison.OrdinalIgnoreCase))
            {
                var containerActive = mounted.Any(m =>
                    string.Equals(m.CatalogContainerUuid, targetVol.CatalogContainerUuid, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(m.DeviceId, targetVol.DeviceId, StringComparison.OrdinalIgnoreCase));
                if (!containerActive && options.AutoMountEnabled && _mountPolicy.ShouldAutoMount(volume))
                {
                    isContainerSiblingForInitialOwner = true;
                }
            }

            if (!string.IsNullOrWhiteSpace(requestedVolumeId) && !isRequestedVolume && !isContainerSiblingForInitialOwner)
            {
                continue;
            }

            if (isRequestedVolume && !RecoveryIdentityMatches(volume.RecoveryIdentity, requestedRecoveryIdentity))
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

            var explicitInspection = (!string.IsNullOrWhiteSpace(requestedVolumeId) || requestedContainerVolumeIds is not null) &&
                requestedAccessMode == MountAccessMode.ReadOnly;
            var explicitBackup = (!string.IsNullOrWhiteSpace(requestedVolumeId) || requestedContainerVolumeIds is not null) &&
                BackupImageMountPolicy.AllowsExplicitMount(options, volume, requestedAccessMode);
            if (!discovery.Inventory.Any(d => d.Volumes.Contains(volume) && TopologyAdmission.Validate(d)) ||
                (!CatalogMountPolicy.AllowsMount(volume, explicitInspection) && !explicitBackup) ||
                (!explicitInspection && !explicitBackup && requestedContainerVolumeIds is null && !_mountPolicy.ShouldAutoMount(volume)) ||
                mountedVolumeIds.Contains(volume.VolumeId))
            {
                continue;
            }

            // Unsafe attention outranks the benign ejected note: an explicit
            // eject that went unsafe stays suppressed AND keeps its
            // use-Fix warning, since suppression now covers every removed
            // mount rather than only the safely unmounted ones.
            if (_incompleteAccessModeVolumeIds.Contains(volume.VolumeId))
            {
                warnings.Add($"'{volume.VolumeName}' remains unmounted after an incomplete container access mode transition; use an explicit mount or Fix to retry.");
                continue;
            }
            var guardedImageFix = validateMountMutation is not null &&
                requestedContainerVolumeIds?.Contains(volume.VolumeId) == true;
            if (_unsafeUnmountedVolumeIds.Contains(volume.VolumeId) && !guardedImageFix)
            {
                warnings.Add($"'{volume.VolumeName}' remains unmounted after an unsafe host stop; use Fix to recover it before remounting.");
                continue;
            }

            if (_userEjectedVolumeIds.Contains(volume.VolumeId) && !guardedImageFix)
            {
                warnings.Add($"'{volume.VolumeName}' is safely ejected; use Mount to mount it again.");
                continue;
            }

            if (string.IsNullOrWhiteSpace(requestedVolumeId) && requestedContainerVolumeIds is null &&
                !options.NativeAutoRemountOnReconnect && _mountedOnce.Contains(volume.VolumeId))
            {
                warnings.Add($"Auto-remount disabled for '{volume.VolumeName}' after prior disconnect.");
                continue;
            }

            if (string.IsNullOrWhiteSpace(requestedVolumeId) && requestedContainerVolumeIds is null &&
                IsMountRetryBackoffActive(volume.VolumeId, out var retryWarning))
            {
                warnings.Add(retryWarning);
                var retainedError = _mountRetryStates[volume.VolumeId].LastError;
                if (!string.IsNullOrWhiteSpace(retainedError))
                {
                    firstMountError ??= retainedError;
                    warnings.Add($"Mount failed for '{volume.VolumeName}': {retainedError}");
                }
                continue;
            }

            pendingVolumes.Add(volume);
        }

        if (validateMountMutation is not null && requestedContainerVolumeIds is not null &&
            (pendingVolumes.Count != requestedContainerVolumeIds.Count ||
             !requestedContainerVolumeIds.SetEquals(pendingVolumes.Select(volume => volume.VolumeId))))
            throw new SelectionSupersededException();

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
                discovery.Generation,
                mounted, validateMountMutation).ConfigureAwait(false));
        }
        else
        {
            IReadOnlyList<MountedVolumeState> preparationMounts = mounted;
            foreach (var volume in pendingVolumes)
            {
                var outcome = await TryMountAsync(
                    volume,
                    options,
                    usedLetters,
                    cancellationToken,
                    deviceDisplayNames.GetValueOrDefault(volume.DeviceId),
                    requestedAccessMode,
                    discovery.Generation, selectedTarget: selectedTarget,
                    preparationMounts: preparationMounts, validateMountMutation: validateMountMutation).ConfigureAwait(false);
                mountOutcomes.Add((volume, new MountAttemptOutcome(
                    outcome.Success,
                    outcome.Error,
                    outcome.Warning,
                    outcome.CompatibilityWarning,
                    outcome.MountedState)));
                if (_mountPolicy.RequiresDriveLetterStorage && mountOutcomes.Count < pendingVolumes.Count)
                    preparationMounts = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        foreach (var (volume, outcome) in mountOutcomes)
        {
            var (success, error, warning, compatibilityWarning, mountedState) = outcome;
            if (success)
            {
                if (validateMountMutation is not null)
                {
                    _userEjectedVolumeIds.Remove(volume.VolumeId);
                    _unsafeUnmountedVolumeIds.Remove(volume.VolumeId);
                }
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
        var admitted = TryAdmitDiscovery(discovery, out var notification);
        NotifyDiscovery(notification);
        return admitted;
    }

    private bool TryAdmitSelectedDiscovery(DiscoverySnapshot discovery)
    {
        if (TryAdmitDiscovery(discovery)) return true;
        // A later identical poll may publish while an explicit mount awaits
        // backend state. Reuse only the existing identity/policy evidence fence.
        lock (_discoveryAdmissionSync) return SelectionDiscoveryIsCurrent(discovery.Generation);
    }

    private void NotifyDiscovery(Action? notification)
    {
        if (notification is null) return;
        if (_deferredNotifications.Value is { } deferred)
        {
            deferred.Pending.Add(notification);
            return;
        }
        try { notification?.Invoke(); }
        catch (Exception ex) { _logger.LogWarning(ex, "Inventory retained; display refresh failed."); }
    }

    // Scope follows this async operation, never another concurrent caller. Install
    // state immediately, but deliver arbitrary callbacks only after its gates close.
    private sealed class DeferredNotifications : IDisposable
    {
        private readonly ApfsMountWorker _owner;
        private readonly DeferredNotifications? _previous;
        internal List<Action> Pending { get; } = [];

        internal DeferredNotifications(ApfsMountWorker owner)
        {
            _owner = owner;
            _previous = owner._deferredNotifications.Value;
            owner._deferredNotifications.Value = this;
        }

        public void Dispose()
        {
            _owner._deferredNotifications.Value = _previous;
            foreach (var notification in Pending) _owner.NotifyDiscovery(notification);
        }
    }

    private bool TryAdmitDiscovery(DiscoverySnapshot discovery, out Action? notification)
    {
        notification = null;
        lock (_discoveryAdmissionSync)
        {
            if (discovery.Generation < _admittedDiscoveryGeneration) return false;
            if (discovery.Generation == _admittedDiscoveryGeneration) return true;
            if (!RetainsSelectionEvidence(discovery)) _selectionEvidenceGeneration = discovery.Generation;
            _admittedDiscoveryGeneration = discovery.Generation;
            _admittedDiscovery = discovery;
            UpdatePreferenceDiscovery(discovery.Volumes);
            StatusChangedPayload latest;
            do
            {
                latest = _statusPublisher.Latest;
            } while (!_statusPublisher.TryPublish(latest, latest with { ConnectedInventory = discovery.Inventory, InventoryGeneration = discovery.Generation }, out notification));
        }
        return true;
    }

    private bool RetainsSelectionEvidence(DiscoverySnapshot next)
    {
        var previous = _admittedDiscovery;
        if (previous is null || !ReferenceEquals(previous.Options, next.Options) ||
            previous.Inventory.Count != next.Inventory.Count ||
            previous.Inventory.Sum(d => d.Volumes.Count) != next.Inventory.Sum(d => d.Volumes.Count)) return false;
        // Legacy/unknown topology keeps strict observation invalidation. Reuse the
        // existing complete selected contracts, including every sibling and bucket.
        foreach (var inventory in new[] { previous.Inventory, next.Inventory })
            if (inventory.Count == 0 || inventory.Count > TopologyGraphIndex.Limit ||
                inventory.Select(d => d.Device.DeviceId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != inventory.Count ||
                inventory.Any(d => d.Topology is null || d.Volumes.Count == 0 || !TopologyAdmission.Validate(d))) return false;
        try
        {
            return previous.Inventory.All(d => d.Volumes.All(v =>
            {
                if (!SelectedControlTarget.Matches(next.Inventory, SelectedControlTarget.Create(d, v))) return false;
                var current = next.Inventory.SelectMany(item => item.Volumes).Single(row =>
                    string.Equals(row.VolumeId, v.VolumeId, StringComparison.OrdinalIgnoreCase));
                return EvaluateVolumeWriteGate(previous.Options, v) ==
                    EvaluateVolumeWriteGate(next.Options, current);
            }));
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { return false; }
    }

    private bool SelectionDiscoveryIsCurrent(long generation) =>
        generation >= _selectionEvidenceGeneration && generation <= _admittedDiscoveryGeneration;

    public async Task<IReadOnlyList<DeviceInventory>> GetInventoryAsync(CancellationToken cancellationToken)
    {
        var discovery = await DiscoverVolumesAsync(cancellationToken).ConfigureAwait(false);
        var mounts = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
        List<(DeviceInventory Inventory, (VolumeInfo Volume, Func<DriveLetterPreference?> Preference)[] Volumes)> captured;
        Action? notification;
        cancellationToken.ThrowIfCancellationRequested();
        lock (_discoveryAdmissionSync)
        {
            if (!TryAdmitDiscovery(discovery, out notification)) discovery = _admittedDiscovery!;
            // Preserve the device bucket returned by discovery, including invalid
            // cross-device rows that exact-target validation must reject explicitly.
            captured = discovery.Inventory.Select(d => (d,
                d.Volumes.Select(v => (v, CaptureInventoryPreference(v, mounts))).ToArray())).ToList();
        }
        NotifyDiscovery(notification);
        // Preference storage reads may block in Windows; never perform them under
        // the mount lock, and await their actual completion rather than detach them.
        return await Task.Run<IReadOnlyList<DeviceInventory>>(() => captured.Select(d => d.Inventory with { Volumes =
            d.Volumes.Select(v => v.Volume with { DriveLetterPreference = v.Preference() }).ToArray() }).ToArray(), cancellationToken).ConfigureAwait(false);
    }

    public async Task<AckPayload> SetDriveLetterPreferenceAsync(DriveLetterPreferenceRequestPayload request, CancellationToken cancellationToken)
    {
        using var notifications = new DeferredNotifications(this);
        if (string.IsNullOrWhiteSpace(request.DeviceId) || string.IsNullOrWhiteSpace(request.VolumeId) ||
            !(Guid.TryParseExact(request.VolumeUuid, "D", out var uuid) || Guid.TryParseExact(request.VolumeUuid, "N", out uuid)) ||
            uuid == Guid.Empty || request.Letter is not { Length: 1 } || char.ToUpperInvariant(request.Letter[0]) is < 'A' or > 'Z')
            return new(false, "Supply exact device, volume and actual volume UUID, and one letter A-Z.", ApfsOperationCodes.InvalidArguments);
        if (request.Target is {} selected && (!SelectedControlTarget.IsAdvertised(selected) || !SelectedControlTarget.IsWellFormed(selected) ||
            !string.Equals(selected.DeviceId, request.DeviceId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(selected.VolumeId, request.VolumeId, StringComparison.OrdinalIgnoreCase) || !TopologyAdmission.SameUuid(selected.VolumeUuid, request.VolumeUuid)))
            return new(false, "Conflicting selected preference identity.", ApfsOperationCodes.AmbiguousTarget);
        await _preferenceOperationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        DriveLetterPreferenceResult result;
        Action? inventoryNotification = null;
        try
        {
            var discovery = await DiscoverVolumesAsync(cancellationToken).ConfigureAwait(false);
            Func<CancellationToken, DriveLetterPreferenceResult> commit;
            lock (_discoveryAdmissionSync)
            {
                if (Volatile.Read(ref _shutdownRequested) != 0)
                    return new(false, "Service is stopping. Try again after restart.", ApfsOperationCodes.ServiceUnavailable);
                if (!TryAdmitDiscovery(discovery, out inventoryNotification))
                    return new(false, "A newer inventory superseded this validation. Refresh and try again.", ApfsOperationCodes.AmbiguousTarget);
                if (request.Target is {} target && !SelectedControlTarget.Matches(discovery.Inventory, target))
                    return new(false, "Selected preference observation changed.", ApfsOperationCodes.AmbiguousTarget);
                var matches = _preferenceVolumes.Where(v => v.DeviceId == request.DeviceId && v.VolumeId == request.VolumeId).ToArray();
                if (matches.Length != 1)
                    return new(false, "Volume identity is stale or ambiguous. Refresh and try again.",
                        matches.Length == 0 ? ApfsOperationCodes.MissingVolume : ApfsOperationCodes.AmbiguousTarget);
                if (!discovery.Inventory.Any(d => d.Volumes.Contains(matches[0]) && TopologyAdmission.Validate(d)))
                    return new(false, "Topology evidence is malformed or contradictory.", ApfsOperationCodes.AmbiguousTarget);
                cancellationToken.ThrowIfCancellationRequested();
                // Admission captures the exact validated UUID. Subsequent inventory
                // changes do not retarget an admitted edit to a replacement volume.
                commit = _mountPolicy.PrepareDriveLetterPreference(matches[0], uuid, request.Letter[0]);
            }

            result = await Task.Run(() => commit(cancellationToken), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _preferenceOperationLock.Release();
            NotifyDiscovery(inventoryNotification);
        }
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
        NotifyDiscovery(notification);
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
            if (!SelectionDiscoveryIsCurrent(discoveryGeneration) || Volatile.Read(ref _shutdownRequested) != 0)
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
            var discoveryCurrent = SelectionDiscoveryIsCurrent(discoveryGeneration);
            var commandChanged = commandGeneration != Volatile.Read(ref _mountCommandGeneration);
            var operationChanged = operationGeneration != _mountOperationGeneration;
            var shutdownRequested = Volatile.Read(ref _shutdownRequested) != 0;
            if (!discoveryCurrent || commandChanged || operationChanged || shutdownRequested)
            {
                _logger.LogWarning("Drive-letter preparation superseded: discovery current={DiscoveryCurrent}, command changed={CommandChanged}, operation changed={OperationChanged}, shutdown={ShutdownRequested}",
                    discoveryCurrent, commandChanged, operationChanged, shutdownRequested);
                throw new SelectionSupersededException();
            }
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
        string? recoveryIdentity = null, ApfsControlTarget? selectedTarget = null)
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
            requestedRecoveryIdentity: recoveryIdentity, selectedTarget: selectedTarget);
    }

    public Task<IReadOnlyList<MountedVolumeState>> GetAuthoritativeMountStateAsync(
        CancellationToken cancellationToken)
        => _backend.GetMountStateAsync(cancellationToken);

    // Snapshot control reaches the live container owner through the backend's
    // owner-held control endpoint. Backends without container ownership report
    // the endpoint unavailable; the executor maps that to service-unavailable.
    public Task<SnapshotControlResult> SendSnapshotControlAsync(
        string containerUuid,
        ulong volumeObjectId,
        SnapshotControlAction action,
        IReadOnlyList<string>? extraLines,
        CancellationToken cancellationToken)
        => _backend is ISnapshotControlBackend snapshotBackend
            ? snapshotBackend.SendSnapshotControlAsync(containerUuid, volumeObjectId, action, extraLines, cancellationToken)
            : Task.FromResult(new SnapshotControlResult(false, "ControlEndpointUnavailable"));

    // Read-only offline verification of a derived scope reaches the
    // backend's observer transport. Backends without a verify endpoint
    // yield null; the executor records verify:unsupported and keeps the
    // legacy mount-health behavior. A null scope is never sent.
    public async Task<ImageVerifyResult?> VerifyImageAsync(
        VerifyScope scope,
        CancellationToken cancellationToken)
        => _backend is IVerifyBackend verifyBackend
            ? await verifyBackend.VerifyImageAsync(scope, cancellationToken).ConfigureAwait(false)
            : null;

    // Management keepers execute planned offline mutations through the
    // backend's native-tool transport. Backends without a keeper report it
    // unavailable; the executor maps that to keeper-unavailable without
    // consuming any further authority (the plan token is already burned).
    public Task<ManagementKeeperRenameResult> SendManagementRenameAsync(
        ManagementKeeperRenameRequest request,
        CancellationToken cancellationToken)
        => _backend is IManagementRenameKeeper keeper
            ? keeper.RenameVolumeAsync(request, cancellationToken)
            : Task.FromResult(new ManagementKeeperRenameResult(false, 0,
                ManagementKeeperCodes.KeeperUnavailable, "The backend has no management keeper endpoint."));

    public Task<ManagementKeeperQuotaResult> SendManagementQuotaAsync(
        ManagementKeeperQuotaRequest request,
        CancellationToken cancellationToken)
        => _backend is IManagementQuotaKeeper keeper
            ? keeper.SetQuotaReserveAsync(request, cancellationToken)
            : Task.FromResult(new ManagementKeeperQuotaResult(false, 0,
                ManagementKeeperCodes.KeeperUnavailable, "The backend has no management keeper endpoint."));

    private async Task<(bool Success, string Message)> RefreshCoreAsync(
        bool clearUserEjectedVolumes,
        string? volumeId,
        bool requireTargetMounted,
        CancellationToken cancellationToken,
        MountAccessMode? requestedAccessMode = null,
        string? requestedDeviceId = null,
        string? requestedRecoveryIdentity = null, ApfsControlTarget? selectedTarget = null)
    {
        using var notifications = new DeferredNotifications(this);
        var commandGeneration = ReserveEncryptedCommand();
        await ReconcileVolumeIntentsAsync(cancellationToken).ConfigureAwait(false);
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

            if (discovery.Volumes.Any(v => (requestedDeviceId is null || string.Equals(v.DeviceId, requestedDeviceId, StringComparison.OrdinalIgnoreCase)) &&
                (volumeId is null || string.Equals(v.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase)) && VolumeIntentBlocks(v.DeviceId)))
                return (false, "Volume management intent requires reconciliation before access.");

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

            if (selectedTarget is not null && !SelectedControlTarget.Matches(discovery.Inventory, selectedTarget))
                return (false, "Selected identity or topology changed; mutation was not attempted.");

            // Only a unique selected volume with an explicit RO mode is inspection.
            // General Refresh/Fix and default-mode requests retain ordinary admission.
            if (!string.IsNullOrWhiteSpace(volumeId))
            {
                var targets = discovery.Volumes.Where(volume =>
                    string.Equals(volume.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase) &&
                    (string.IsNullOrWhiteSpace(requestedDeviceId) ||
                     string.Equals(volume.DeviceId, requestedDeviceId, StringComparison.OrdinalIgnoreCase))).ToArray();
                if (targets.Length != 1)
                    return (false, $"Requested APFS volume '{volumeId}' was not uniquely found; mutation was not attempted.");
                if (!discovery.Inventory.Any(d => d.Volumes.Contains(targets[0]) && TopologyAdmission.Validate(d)))
                    return (false, "Topology evidence is malformed or contradictory.");
                if (!CatalogMountPolicy.AllowsMount(targets[0], requestedAccessMode == MountAccessMode.ReadOnly) &&
                    !BackupImageMountPolicy.AllowsExplicitMount(discovery.Options, targets[0], requestedAccessMode))
                    return (false, CatalogMountPolicy.Refusal(targets[0], requestedAccessMode));
            }

            // The admitted snapshot also covers upgrade-remount letter selection.
            IReadOnlyList<MountedVolumeState>? refreshedMounted = null;
            var remountWarnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (clearUserEjectedVolumes)
            {
                var transition = await TryTransitionSharedContainerAccessModeAsync(
                    volumeId, requestedDeviceId, requestedAccessMode, discovery, selectedTarget,
                    cancellationToken).ConfigureAwait(false);
                if (transition.HasValue) return transition.Value;
                if (volumeId is null) _incompleteAccessModeVolumeIds.Clear();
                else _incompleteAccessModeVolumeIds.Remove(volumeId);

                if (string.IsNullOrWhiteSpace(volumeId))
                {
                    _userEjectedVolumeIds.Clear();
                    _unsafeUnmountedVolumeIds.Clear();
                }
                else
                {
                    _userEjectedVolumeIds.Remove(volumeId);
                    _unsafeUnmountedVolumeIds.Remove(volumeId);
                    if (discovery.VolumeById.TryGetValue(volumeId, out var vTarget) && !string.IsNullOrWhiteSpace(vTarget.CatalogContainerUuid))
                    {
                        var currentMounts = refreshedMounted ?? await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
                        var containerActive = currentMounts.Any(m =>
                            string.Equals(m.CatalogContainerUuid, vTarget.CatalogContainerUuid, StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(m.DeviceId, vTarget.DeviceId, StringComparison.OrdinalIgnoreCase));
                        if (!containerActive && discovery.Options.AutoMountEnabled)
                        {
                            foreach (var peer in discovery.VolumeById.Values.Where(p =>
                                string.Equals(p.CatalogContainerUuid, vTarget.CatalogContainerUuid, StringComparison.OrdinalIgnoreCase) &&
                                string.Equals(p.DeviceId, vTarget.DeviceId, StringComparison.OrdinalIgnoreCase)))
                            {
                                _userEjectedVolumeIds.Remove(peer.VolumeId);
                                _unsafeUnmountedVolumeIds.Remove(peer.VolumeId);
                            }
                        }
                    }
                }

                refreshedMounted = await RemountUpgradeableReadOnlyVolumesAsync(
                    volumeId,
                    requestedDeviceId,
                    requestedAccessMode,
                    discovery,
                    remountWarnings,
                    cancellationToken, selectedTarget).ConfigureAwait(false);
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
                requestedRecoveryIdentity: requestedRecoveryIdentity, selectedTarget: selectedTarget).ConfigureAwait(false);

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
        CancellationToken cancellationToken, ApfsControlTarget? selectedTarget = null)
    {
        var options = discovery.Options;
        if (!options.AutoMountEnabled || !options.EnableNativeWrite)
        {
            return await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
        }

        var mounted = (await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false)).ToList();
        var remountCandidates = mounted
            .Where(mount => selectedTarget is null || SelectedControlTarget.MatchesMount(selectedTarget, mount))
            .Where(mount => requestedAccessMode.HasValue || !RetainsManualReadOnlyMode(mount))
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

            var explicitBackup = !string.IsNullOrWhiteSpace(volumeId) && requestedAccessMode.HasValue &&
                BackupImageMountPolicy.CanRequest(options, volume) &&
                mounted.Count(owner => TopologyAdmission.SameUuid(owner.CatalogContainerUuid, volume.CatalogContainerUuid)) == 1;
            if ((!CatalogMountPolicy.AllowsOrdinaryMount(volume) && !explicitBackup) ||
                (!_mountPolicy.ShouldAutoMount(volume) && !explicitBackup) ||
                options.SkipEncryptedVolumes && volume.IsEncrypted ||
                !volume.SupportsExplorerMount)
            {
                continue;
            }

            var writeDecision = EvaluateVolumeWriteGate(options, volume);
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
            if (!SamePreparedMountOwners(mounted, current))
                return current;
        }

        foreach (var (mount, volume, preparedLetter) in prepared)
        {
            var driveLetter = TryGetDriveLetter(mount)!.Value;
            // An earlier unmount can fail and leave its old letter occupied, even
            // though preparation anticipated releasing it. Keep this mount intact.
            if (preparedLetter.HasValue && preparedLetter.Value != driveLetter && usedLetters.Contains(preparedLetter.Value))
                continue;

            await ValidateSelectedMutationAsync(selectedTarget, cancellationToken, mount).ConfigureAwait(false);
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
                preparedLetter, selectedTarget
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
        string? recoveryIdentity = null, ApfsControlTarget? selectedTarget = null, long encryptedGeneration = 0)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        ArgumentException.ThrowIfNullOrWhiteSpace(volumeId);
        return EjectCoreAsync(volumeId, deviceId, recoveryIdentity, cancellationToken, selectedTarget, encryptedGeneration);
    }

    internal Task<EjectOperationResult> EjectAdmittedPhysicalWriteOwnerAsync(
        ApfsControlTarget target, MountedVolumeState expectedOwner)
        => EjectCoreAsync(target.VolumeId, target.DeviceId, target.RecoveryIdentity, CancellationToken.None,
            target, expectedOwner: expectedOwner);

    private async Task<EjectOperationResult> EjectCoreAsync(
        string? volumeId,
        string? deviceId,
        string? recoveryIdentity,
        CancellationToken cancellationToken, ApfsControlTarget? selectedTarget = null, long encryptedGeneration = 0,
        MountedVolumeState? expectedOwner = null)
    {
        using var notifications = new DeferredNotifications(this);
        if(encryptedGeneration==0) ReserveEncryptedCommand();
        await _mountOperationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ++_mountOperationGeneration;
            var warnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            EjectOperationResult RetainChangedOwner(IReadOnlyList<MountedVolumeState> current)
            {
                PublishFromMounts(current, null, warnings, Array.Empty<string>());
                return new EjectOperationResult(false,
                    "PhysicalWritePermissionCleanupOwnerChanged: The admitted runtime owner changed; current ownership retained.",
                    current, new Dictionary<string, UnmountResult>(StringComparer.OrdinalIgnoreCase));
            }
            var mountedBeforeEject = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
            var selectedMounts = SelectMountsForEject(mountedBeforeEject, volumeId, deviceId, recoveryIdentity);
            if (expectedOwner is not null &&
                (expectedOwner.HostProcessId <= 0 || expectedOwner.HostProcessCreationTimeFileTimeUtc <= 0 ||
                 !SamePreparedMountOwners([expectedOwner], selectedMounts)))
                return RetainChangedOwner(mountedBeforeEject);
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

            await ValidateSelectedMutationAsync(selectedTarget, cancellationToken,
                expectedOwner ?? (selectedTarget is null ? null : selectedMounts.SingleOrDefault())).ConfigureAwait(false);
            if (expectedOwner is not null)
            {
                // Validation awaits discovery; keep the admitted identity through the final unmount boundary.
                var current = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
                var selected = SelectMountsForEject(current, volumeId, deviceId, recoveryIdentity);
                if (!SamePreparedMountOwners([expectedOwner], selected)) return RetainChangedOwner(current);
                mountedBeforeEject = current;
                selectedMounts = selected;
            }
            var unmount = await UnmountAsync(selectedMounts, cancellationToken, warnings,
                sharedOwnerMounts: !string.IsNullOrWhiteSpace(volumeId) ? mountedBeforeEject : null).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(volumeId) && unmount.UnsafeRemoved.Count > 0 &&
                _backend is IUnmountTerminalStateBackend terminalBackend)
            {
                var proofs = unmount.Results.ToDictionary(p => p.Key, p => p.Value, StringComparer.OrdinalIgnoreCase);
                using var proofTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(
                    Math.Clamp(_optionsMonitor.CurrentValue.NativeHostStopTimeoutSeconds, 1, 60)));
                foreach (var mount in unmount.UnsafeRemoved)
                {
                    try
                    {
                        var proof = await terminalBackend.GetUnmountTerminalStateAsync(mount, proofTimeout.Token)
                            .WaitAsync(proofTimeout.Token).ConfigureAwait(false);
                        if (!IsCompleteShutdownProof(mount, proof)) continue;
                        var previous = proofs[mount.VolumeId];
                        var error = string.IsNullOrWhiteSpace(previous.Error)
                            ? "Unmount did not prove mount removal, host ownership release, and pending durability clearance."
                            : previous.Error;
                        warnings.Remove($"Unmount failed for '{mount.MountPoint}': {error}");
                        proofs[mount.VolumeId] = proof;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Could not prove the original shared owner exited for {MountPoint}", mount.MountPoint);
                    }
                }
                var safe = unmount.Removed.Where(m => IsCompleteShutdownProof(m, proofs[m.VolumeId])).ToArray();
                unmount = unmount with { Results = proofs, SafelyUnmounted = safe,
                    UnsafeRemoved = unmount.Removed.Where(m => !IsCompleteShutdownProof(m, proofs[m.VolumeId])).ToArray() };
            }
            var unmountedIds = unmount.Removed.Select(static x => x.VolumeId).ToHashSet(StringComparer.OrdinalIgnoreCase);
            MountedVolumeState[] remaining;
            if (string.IsNullOrWhiteSpace(volumeId))
            {
                try
                {
                    using var finalProbeTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(
                        Math.Clamp(_optionsMonitor.CurrentValue.NativeHostStopTimeoutSeconds, 1, 60)));
                    remaining = (await _backend.GetMountStateAsync(finalProbeTimeout.Token)
                        .WaitAsync(finalProbeTimeout.Token).ConfigureAwait(false)).ToArray();
                }
                catch (Exception ex)
                {
                    warnings.Add("Current mount absence could not be verified after eject: " + ex.Message);
                    remaining = mountedBeforeEject.ToArray();
                }
            }
            else
            {
                remaining = mountedBeforeEject.Where(mount => !unmountedIds.Contains(mount.VolumeId)).ToArray();
            }
            var remainingIds = remaining.Select(static x => x.VolumeId).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var remainingCount = remaining.Length;
            var statusWarnings = new HashSet<string>(warnings, StringComparer.OrdinalIgnoreCase);
            // Explicit eject must stick for every removed mount, not just the
            // safely unmounted ones: unsafe removals otherwise auto-remount on
            // the next cycle while still needing attention. Unsafe members
            // keep their attention marking below; a later explicit mount
            // still clears suppression through the normal mount path.
            foreach (var mount in unmount.Removed)
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

    public Task<EjectOperationResult> EjectContainerAsync(
        string deviceId,
        string containerUuid,
        CancellationToken cancellationToken,
        long encryptedGeneration = 0)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        ArgumentException.ThrowIfNullOrWhiteSpace(containerUuid);
        return EjectContainerCoreAsync(deviceId, containerUuid, cancellationToken, encryptedGeneration);
    }

    public Task<(bool Success, string Message)> MountContainerAsync(
        string deviceId,
        string containerUuid,
        IReadOnlyList<VolumeInfo> admittedMembers,
        MountAccessMode requestedMode,
        CancellationToken cancellationToken)
        => MountContainerCoreAsync(deviceId, containerUuid, admittedMembers, requestedMode, cancellationToken, null);

    private async Task<(bool Success, string Message)> MountContainerCoreAsync(
        string deviceId,
        string containerUuid,
        IReadOnlyList<VolumeInfo> admittedMembers,
        MountAccessMode requestedMode,
        CancellationToken cancellationToken,
        Func<IReadOnlyList<DeviceInventory>, bool>? imageFixAdmission)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        ArgumentException.ThrowIfNullOrWhiteSpace(containerUuid);
        ArgumentNullException.ThrowIfNull(admittedMembers);
        var expectedMembers = admittedMembers.ToArray();
        using var notifications = new DeferredNotifications(this);
        var commandGeneration = ReserveEncryptedCommand();
        await ReconcileVolumeIntentsAsync(cancellationToken).ConfigureAwait(false);
        var discovery = await DiscoverVolumesAsync(cancellationToken).ConfigureAwait(false);
        await _mountOperationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ++_mountOperationGeneration;
            cancellationToken.ThrowIfCancellationRequested();
            if (Volatile.Read(ref _shutdownRequested) != 0 ||
                commandGeneration != Volatile.Read(ref _mountCommandGeneration) || !TryAdmitSelectedDiscovery(discovery))
                return (false, "Container mount was superseded or shutdown cleanup has started.");
            if (imageFixAdmission is not null && !imageFixAdmission(discovery.Inventory))
                return (false, "The original image source, capabilities or container selection changed before mount.");

            var devices = discovery.Inventory.Where(item => string.Equals(
                item.Device.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (devices.Length != 1 || !TopologyAdmission.Validate(devices[0]))
                return (false, "The requested device no longer has unique valid topology.");

            var members = devices[0].Volumes.Where(volume =>
                string.Equals(volume.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) &&
                ApfsTopology.MatchesContainerUuid(containerUuid, volume.CatalogContainerUuid) &&
                (CatalogMountPolicy.AllowsMount(volume, requestedMode == MountAccessMode.ReadOnly) ||
                 BackupImageMountPolicy.AllowsExplicitMount(discovery.Options, volume, requestedMode))).ToArray();
            var memberIds = members.Select(volume => volume.VolumeId).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (members.Length == 0 || memberIds.Count != members.Length || members.Length != expectedMembers.Length ||
                expectedMembers.Select(volume => volume.VolumeId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != expectedMembers.Length ||
                expectedMembers.Any(expected => !members.Any(current =>
                    string.Equals(expected.DeviceId, current.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(expected.VolumeId, current.VolumeId, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(current.RecoveryIdentity, expected.RecoveryIdentity, StringComparison.Ordinal) &&
                    current.CatalogVolumeObjectId == expected.CatalogVolumeObjectId &&
                    string.Equals(current.CatalogVolumeUuid, expected.CatalogVolumeUuid, StringComparison.OrdinalIgnoreCase))))
                return (false, "Container membership or volume identity changed; refresh and retry.");

            if (VolumeIntentBlocks(deviceId))
                return (false, "Volume management intent requires reconciliation before access.");
            if (members.Length > 1 && _backend is not IContainerMountBackend)
                return (false, "The backend cannot mount container siblings as one batch.");

            var mounted = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
            if (mounted.Any(mount => string.Equals(mount.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) &&
                    memberIds.Contains(mount.VolumeId)))
                return (false, "Container members are still mounted after the reset; refresh and retry.");

            async Task ValidateImageFixMutationAsync(CancellationToken token)
            {
                var fresh = await DiscoverVolumesAsync(token).ConfigureAwait(false);
                var currentOwners = await _backend.GetMountStateAsync(token).ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                if (Volatile.Read(ref _shutdownRequested) != 0 || commandGeneration != Volatile.Read(ref _mountCommandGeneration) ||
                    !imageFixAdmission!(fresh.Inventory) || !SamePreparedMountOwners(mounted, currentOwners))
                    throw new SelectionSupersededException();
            }

            // Letter storage releases the mount gate. Retain suppression so a
            // concurrent poll cannot mount outside this Fix's admission guard.
            foreach (var member in members)
            {
                if (imageFixAdmission is not null)
                    _userEjectedVolumeIds.Add(member.VolumeId);
                else
                {
                    _userEjectedVolumeIds.Remove(member.VolumeId);
                    _unsafeUnmountedVolumeIds.Remove(member.VolumeId);
                }
                _mountRetryStates.Remove(member.VolumeId);
            }
            await RunCycleCoreAsync(discovery, cancellationToken, mounted,
                requestedDeviceId: deviceId, requestedAccessMode: requestedMode,
                requestedContainerVolumeIds: memberIds,
                validateMountMutation: imageFixAdmission is null ? null : ValidateImageFixMutationAsync).ConfigureAwait(false);
            var current = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
            var missing = members.Where(member => current.Count(owner =>
                string.Equals(owner.DeviceId, member.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(owner.VolumeId, member.VolumeId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(owner.RecoveryIdentity, member.RecoveryIdentity, StringComparison.Ordinal)) != 1).ToArray();
            if (missing.Length != 0)
                return (false, "Container mount did not install every requested member: " +
                    string.Join(", ", missing.Select(member => member.VolumeName)) + ". " + _statusPublisher.Latest.LastError);
            return (true, "The requested container mounts are present.");
        }
        catch (SelectionSupersededException)
        {
            return (false, "Container mount was superseded while preparing drive-letter settings.");
        }
        finally
        {
            _mountOperationLock.Release();
        }
    }

    // Clears explicit-eject suppression (and unsafe quarantine marks) for
    // exactly the given volumes so a subsequent mount may proceed. Scoped
    // per volume, unlike RefreshAsync(clearUserEjectedVolumes:true) which
    // clears globally. Explicit container mounting instead clears suppression
    // inside its own scoped scheduling operation.
    public async Task ClearEjectSuppressionAsync(
        IReadOnlyList<string> volumeIds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(volumeIds);
        await _mountOperationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            foreach (var volumeId in volumeIds)
            {
                if (string.IsNullOrWhiteSpace(volumeId))
                {
                    continue;
                }

                _userEjectedVolumeIds.Remove(volumeId);
                _unsafeUnmountedVolumeIds.Remove(volumeId);
            }
        }
        finally
        {
            _mountOperationLock.Release();
        }
    }

    // Container-wide eject detaches every mounted member of one container in
    // a single mount-operation scope and then relies on the backend's
    // empty-group host stop (the same path per-volume eject uses for its last
    // member). Fanning out through per-volume eject instead would leave every
    // non-last member in an unprovable state: its mount is gone but the shared
    // host must stay up for its siblings, so host-ownership release can never
    // complete. Suppression covers every safely unmounted member, so explicit
    // container unmount sticks instead of auto-remounting.
    private async Task<EjectOperationResult> EjectContainerCoreAsync(
        string deviceId,
        string containerUuid,
        CancellationToken cancellationToken,
        long encryptedGeneration,
        IReadOnlyList<VolumeInfo>? expectedImageMembers = null,
        Func<IReadOnlyList<DeviceInventory>, bool>? imageFixAdmission = null)
    {
        using var notifications = new DeferredNotifications(this);
        if (encryptedGeneration == 0) ReserveEncryptedCommand();
        await _mountOperationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ++_mountOperationGeneration;
            var warnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var inventory = await _backend.ProbeInventoryAsync(authoritative: true, cancellationToken).ConfigureAwait(false);
            var devices = inventory
                .Where(item => item?.Device is not null &&
                    string.Equals(item.Device.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (devices.Length != 1 || !TopologyAdmission.Validate(devices[0]))
            {
                return new EjectOperationResult(
                    Success: false,
                    Message: devices.Length == 0
                        ? $"Device '{deviceId}' is not connected."
                        : "Container topology evidence is malformed or contradictory; mutation was not attempted.",
                    RemainingMounts: await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false),
                    UnmountResults: new Dictionary<string, UnmountResult>(StringComparer.OrdinalIgnoreCase));
            }

            var memberIds = devices[0].Volumes
                .Where(volume => volume is not null && ApfsTopology.MatchesContainerUuid(containerUuid, volume.CatalogContainerUuid))
                .Select(static volume => volume.VolumeId)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (expectedImageMembers is not null)
            {
                if (imageFixAdmission is null || !imageFixAdmission(inventory))
                    return new EjectOperationResult(false, "The original image source, capabilities or container selection changed before Fix.",
                        await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false),
                        new Dictionary<string, UnmountResult>(StringComparer.OrdinalIgnoreCase));
                var currentMembers = devices[0].Volumes.Where(v =>
                    TopologyAdmission.SameUuid(v.CatalogContainerUuid, containerUuid)).ToArray();
                if (!VolumeTopologyProfile.LocalPath(deviceId) || currentMembers.Length != expectedImageMembers.Count ||
                    expectedImageMembers.Select(v => v.VolumeId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != expectedImageMembers.Count ||
                    expectedImageMembers.Any(expected => !currentMembers.Any(current =>
                        current.VolumeId == expected.VolumeId && current.DeviceId == expected.DeviceId &&
                        current.RecoveryIdentity == expected.RecoveryIdentity && current.CatalogVolumeId == expected.CatalogVolumeId &&
                        current.CatalogVolumeObjectId == expected.CatalogVolumeObjectId &&
                        TopologyAdmission.SameUuid(current.CatalogVolumeUuid, expected.CatalogVolumeUuid) &&
                        TopologyAdmission.SameUuid(current.CatalogContainerUuid, expected.CatalogContainerUuid))))
                    return new EjectOperationResult(false, "The original image container membership changed before Fix; refresh and retry.",
                        await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false),
                        new Dictionary<string, UnmountResult>(StringComparer.OrdinalIgnoreCase));
            }
            if (memberIds.Count == 0)
            {
                return new EjectOperationResult(
                    Success: false,
                    Message: $"Container '{containerUuid}' has no inventoried volumes on device '{deviceId}'.",
                    RemainingMounts: await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false),
                    UnmountResults: new Dictionary<string, UnmountResult>(StringComparer.OrdinalIgnoreCase));
            }

            var mountedBeforeEject = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
            if (expectedImageMembers is not null)
            {
                var affected = mountedBeforeEject.Where(m => string.Equals(m.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) ||
                    TopologyAdmission.SameUuid(m.CatalogContainerUuid, containerUuid)).ToArray();
                if (affected.Any(m => !string.Equals(m.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) || !memberIds.Contains(m.VolumeId)) ||
                    affected.Select(m => m.VolumeId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != affected.Length ||
                    affected.Select(m => m.MountPoint).Distinct(StringComparer.OrdinalIgnoreCase).Count() != affected.Length ||
                    affected.Any(m => m.HostProcessId <= 0 || m.HostProcessCreationTimeFileTimeUtc <= 0) ||
                    affected.Select(m => (m.HostProcessId, m.HostProcessCreationTimeFileTimeUtc)).Distinct().Count() > 1)
                    return new EjectOperationResult(false, "An unrelated, duplicate or conflicting owner still uses the original image source; no members were detached.",
                        mountedBeforeEject, new Dictionary<string, UnmountResult>(StringComparer.OrdinalIgnoreCase));
            }
            var selectedMounts = mountedBeforeEject
                .Where(mount =>
                    string.Equals(mount.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) &&
                    mount.VolumeId is not null && memberIds.Contains(mount.VolumeId))
                .ToArray();
            if (expectedImageMembers is not null && selectedMounts.Any(mount =>
                !expectedImageMembers.Any(member => mount.VolumeId == member.VolumeId && mount.DeviceId == member.DeviceId &&
                    mount.RecoveryIdentity == member.RecoveryIdentity && mount.CatalogVolumeId == member.CatalogVolumeId &&
                    mount.CatalogVolumeObjectId == member.CatalogVolumeObjectId &&
                    TopologyAdmission.SameUuid(mount.CatalogContainerUuid, member.CatalogContainerUuid) &&
                    TopologyAdmission.SameUuid(mount.CatalogVolumeUuid, member.CatalogVolumeUuid))))
                return new EjectOperationResult(false, "The original image owner identity changed before Fix; refresh and retry.",
                    mountedBeforeEject, new Dictionary<string, UnmountResult>(StringComparer.OrdinalIgnoreCase));
            if (selectedMounts.Length == 0)
            {
                PublishFromMounts(mountedBeforeEject, null, warnings, Array.Empty<string>());
                return new EjectOperationResult(
                    Success: true,
                    Message: "No member of the exact APFS container is currently mounted.",
                    RemainingMounts: mountedBeforeEject,
                    UnmountResults: new Dictionary<string, UnmountResult>(StringComparer.OrdinalIgnoreCase));
            }

            if (expectedImageMembers is not null)
            {
                var fresh = await _backend.ProbeInventoryAsync(authoritative: true, cancellationToken).ConfigureAwait(false);
                var currentOwners = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
                if (!imageFixAdmission!(fresh) || !SamePreparedMountOwners(mountedBeforeEject, currentOwners))
                    return new EjectOperationResult(false, "The original image selection or owners changed immediately before Fix; no members were detached.",
                        currentOwners, new Dictionary<string, UnmountResult>(StringComparer.OrdinalIgnoreCase));
            }

            var batchWarnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var unmount = await UnmountAsync(selectedMounts, cancellationToken, batchWarnings).ConfigureAwait(false);
            var merged = new Dictionary<string, UnmountResult>(unmount.Results, StringComparer.OrdinalIgnoreCase);
            // The backend stops the shared host asynchronously once the group
            // is empty, so per-detach results taken immediately can predate
            // the stop and report ownership unreleased even though the stop
            // completes a moment later. Settle briefly and re-request proof
            // for members that detached quiesced but did not witness exit, so
            // a completed stop is observed instead of reported unproven.
            // Bounded (~12 s) and never inventing: only a backend-proven
            // retry replaces the original result, otherwise it stands.
            var unsettled = merged
                .Where(entry => entry.Value.Success && entry.Value.MountRemoved &&
                    entry.Value.PendingDurabilityCleared && !entry.Value.HostOwnershipReleased)
                .Select(static entry => entry.Key)
                .ToArray();
            if (unsettled.Length > 0)
            {
                var settleDeadline = DateTime.UtcNow.AddSeconds(12);
                var pending = unsettled.ToList();
                var reproofNotes = new List<(string VolumeId, string Note)>();
                while (pending.Count > 0 && DateTime.UtcNow < settleDeadline)
                {
                    try
                    {
                        await Task.Delay(1000, cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }

                    foreach (var volumeId in pending.ToArray())
                    {
                        // Cancellation must still reach suppression/debt publication.
                        if (cancellationToken.IsCancellationRequested) break;
                        var mount = selectedMounts.FirstOrDefault(candidate =>
                            string.Equals(candidate.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase));
                        if (mount is null)
                        {
                            continue;
                        }

                        UnmountResult retry;
                        try
                        {
                            retry = await _backend.UnmountAsync(mount.MountPoint, cancellationToken).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }
                        catch (Exception ex)
                        {
                            reproofNotes.Add((volumeId, $"Ownership re-proof failed for '{mount.MountPoint}': {ex.Message}"));
                            continue;
                        }

                        if (retry.Success && retry.HostOwnershipReleased)
                        {
                            merged[volumeId] = retry;
                            pending.Remove(volumeId);
                        }
                    }
                    if (cancellationToken.IsCancellationRequested) break;
                }

                // Re-proof notes describe still-unproven members only: notes
                // for members whose retry eventually proved ownership are
                // dropped, since final-state warnings below are regenerated
                // from merged results.
                var stillUnproven = pending.ToHashSet(StringComparer.OrdinalIgnoreCase);
                foreach (var (_, note) in reproofNotes.Where(entry => stillUnproven.Contains(entry.VolumeId)))
                {
                    warnings.Add(note);
                }
            }

            var removedIds = merged
                .Where(entry => entry.Value.MountRemoved)
                .Select(static entry => entry.Key)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            // Warnings describe FINAL state only: the batch above wrote
            // per-mount failure notes into a throwaway set because settle
            // below can still observe the missing proofs. Regenerate notes
            // for members that remain unproven after settle.
            foreach (var mount in selectedMounts)
            {
                if (!merged.TryGetValue(mount.VolumeId, out var final) ||
                    (final.Success && final.MountRemoved && final.PendingDurabilityCleared && final.HostOwnershipReleased))
                {
                    continue;
                }

                var error = string.IsNullOrWhiteSpace(final?.Error)
                    ? "Unmount did not prove mount removal, host ownership release, and pending durability clearance."
                    : final!.Error;
                warnings.Add($"Unmount failed for '{mount.MountPoint}': {error}");
            }

            var removed = selectedMounts.Where(mount => removedIds.Contains(mount.VolumeId)).ToArray();
            var safelyUnmounted = selectedMounts
                .Where(mount => merged.TryGetValue(mount.VolumeId, out var result) &&
                    result.Success && result.MountRemoved &&
                    result.HostOwnershipReleased && result.PendingDurabilityCleared)
                .ToArray();
            var unsafeRemoved = removed.Where(mount => !safelyUnmounted.Any(candidate =>
                string.Equals(candidate.VolumeId, mount.VolumeId, StringComparison.OrdinalIgnoreCase))).ToArray();
            var unmountedIds = removed.Select(static x => x.VolumeId).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var remaining = mountedBeforeEject
                .Where(mount => !unmountedIds.Contains(mount.VolumeId))
                .ToArray();
            var memberRemaining = remaining
                .Where(mount =>
                    string.Equals(mount.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase) &&
                    mount.VolumeId is not null && memberIds.Contains(mount.VolumeId))
                .ToArray();
            var statusWarnings = new HashSet<string>(warnings, StringComparer.OrdinalIgnoreCase);
            // Explicit container unmount must stick: suppress every detached
            // member (not just the safely unmounted ones), or just-unmounted
            // volumes auto-remount on the next cycle. Unsafe members keep
            // their attention marking; a later explicit mount still clears
            // suppression through the normal mount path.
            foreach (var mount in removed)
            {
                _userEjectedVolumeIds.Add(mount.VolumeId);
            }
            foreach (var mount in unsafeRemoved)
            {
                _unsafeUnmountedVolumeIds.Add(mount.VolumeId);
                statusWarnings.Add(BuildUnsafeUnmountWarning(mount));
            }

            foreach (var mount in safelyUnmounted)
            {
                statusWarnings.Add(BuildSafelyEjectedWarning(mount));
            }

            PublishFromMounts(remaining, null, statusWarnings, Array.Empty<string>());

            if (memberRemaining.Length == 0 && warnings.Count == 0)
            {
                return new EjectOperationResult(
                    Success: true,
                    Message: "All members of the exact APFS container were safely ejected.",
                    RemainingMounts: remaining,
                    UnmountResults: merged);
            }

            if (memberRemaining.Length == 0)
            {
                return new EjectOperationResult(
                    Success: false,
                    Message: string.Join(" ", warnings),
                    RemainingMounts: remaining,
                    UnmountResults: merged);
            }

            var stillMounted = string.Join(", ", memberRemaining.Select(static x => x.MountPoint));
            var detail = warnings.Count == 0 ? string.Empty : $" {string.Join(" ", warnings)}";
            return new EjectOperationResult(
                Success: false,
                Message: $"Some members of the APFS container are still mounted: {stillMounted}.{detail}",
                RemainingMounts: remaining,
                UnmountResults: merged);
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

    private async Task ValidateSelectedMutationAsync(ApfsControlTarget? target, CancellationToken cancellationToken, MountedVolumeState? expectedOwner = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (target is null) return;
        var fresh = await DiscoverVolumesAsync(cancellationToken).ConfigureAwait(false);
        if (!SelectedControlTarget.Matches(fresh.Inventory, target))
        {
            TryAdmitDiscovery(fresh);
            throw new InvalidOperationException("Selected identity or topology changed immediately before mutation.");
        }
        if (expectedOwner is not null)
        {
            var mounts = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
            var owners = mounts.Where(m => m.MountPoint == expectedOwner.MountPoint).ToArray();
            if (owners.Length != 1 || !SelectedControlTarget.MatchesMount(target, owners[0]) ||
                !SamePreparedMountOwners([expectedOwner], owners))
                throw new InvalidOperationException("Selected runtime owner changed immediately before mutation.");
        }
        cancellationToken.ThrowIfCancellationRequested();
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

    private static bool SamePreparedMountOwners(
        IReadOnlyList<MountedVolumeState> prepared, IReadOnlyList<MountedVolumeState> current)
    {
        static bool Matches(MountedVolumeState owner, MountedVolumeState candidate)
            => SameShutdownOwner(owner, candidate) && owner.AccessMode == candidate.AccessMode &&
               string.Equals(owner.CatalogVolumeId, candidate.CatalogVolumeId, StringComparison.OrdinalIgnoreCase);

        return current.Count == prepared.Count &&
            prepared.All(owner => current.Count(candidate => Matches(owner, candidate)) == 1) &&
            current.All(owner => prepared.Count(candidate => Matches(candidate, owner)) == 1);
    }

    private async Task<IReadOnlyList<(VolumeInfo Volume, MountAttemptOutcome Outcome)>> TryMountContainerBatchAsync(
        IContainerMountBackend containerBackend,
        IReadOnlyList<VolumeInfo> volumes,
        ServiceHostOptions options,
        HashSet<char> usedLetters,
        CancellationToken cancellationToken,
        IReadOnlyDictionary<string, string> deviceDisplayNames,
        MountAccessMode? requestedAccessMode,
        long discoveryGeneration,
        IReadOnlyList<MountedVolumeState> preparationMounts,
        Func<CancellationToken, Task>? validateMountMutation = null)
    {
        var preparationCommand = Volatile.Read(ref _mountCommandGeneration);
        var preparationOperation = _mountOperationGeneration;
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

            var writeDecision = EvaluateVolumeWriteGate(options, volume);
            var requestedAccess = ResolveRememberedAccessMode(volume, requestedAccessMode,
                writeDecision.AllowWrite ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly);
            var managementRootReady = requestedAccess != MountAccessMode.ReadWrite || !writeDecision.AllowWrite || ImageMutationRootReady(volume.DeviceId);
            var shouldAttemptWrite = requestedAccess == MountAccessMode.ReadWrite && writeDecision.AllowWrite && managementRootReady;
            var primaryAccess = shouldAttemptWrite ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly;
            string? compatibilityWarning = null;
            if (!shouldAttemptWrite && options.EnableNativeWrite)
            {
                compatibilityWarning = $"Write gate is active but '{volume.VolumeName}' mounted read-only " +
                                         $"(gate={writeDecision.GateState}, reason={(!managementRootReady ? "ManagementJournalRootUninspectedOrPending" : writeDecision.Reason ?? "n/a")}).";
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
        if (validateMountMutation is not null && prepared.Count != volumes.Count)
            throw new SelectionSupersededException();

        if (_mountPolicy.RequiresDriveLetterStorage)
        {
            // Settings waits release the mount gate. Inventory may observe a new
            // backend owner without a worker command; recheck the entire owner set.
            var current = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
            ValidateDriveLetterSelection(discoveryGeneration, preparationCommand, preparationOperation, cancellationToken);
            if (!SamePreparedMountOwners(preparationMounts, current))
                throw new SelectionSupersededException();
        }

        IReadOnlyList<MountResult> primaryResults;
        if (validateMountMutation is not null)
            await validateMountMutation(cancellationToken).ConfigureAwait(false);
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
            if (validateMountMutation is not null && fallbackIndexes.Length != prepared.Count)
                throw new SelectionSupersededException();
            var fallbackRequests = fallbackIndexes
                .Select(index => prepared[index].Request with { AccessMode = MountAccessMode.ReadOnly })
                .ToArray();
            if (validateMountMutation is not null)
                await validateMountMutation(cancellationToken).ConfigureAwait(false);
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
        char? preparedLetter = null, ApfsControlTarget? selectedTarget = null,
        IReadOnlyList<MountedVolumeState>? preparationMounts = null,
        Func<CancellationToken, Task>? validateMountMutation = null
    )
    {
        var preparationCommand = Volatile.Read(ref _mountCommandGeneration);
        var preparationOperation = _mountOperationGeneration;
        if (_mountPolicy.RequiresDriveLetterStorage && preparationMounts is null)
            preparationMounts = (await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false)).ToArray();

        async Task ValidatePreparationOwnersAsync()
        {
            await ValidateSelectedMutationAsync(selectedTarget, cancellationToken).ConfigureAwait(false);
            if (validateMountMutation is not null)
                await validateMountMutation(cancellationToken).ConfigureAwait(false);
            if (_mountPolicy.RequiresDriveLetterStorage && preparationMounts is not null)
            {
                var current = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
                ValidateDriveLetterSelection(discoveryGeneration, preparationCommand, preparationOperation, cancellationToken);
                if (!SamePreparedMountOwners(preparationMounts, current))
                    throw new SelectionSupersededException();
            }
        }

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

        var writeDecision = EvaluateVolumeWriteGate(options, volume);
        var requestedAccess = ResolveRememberedAccessMode(volume, requestedAccessMode,
            writeDecision.AllowWrite ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly);
        var managementRootReady = requestedAccess != MountAccessMode.ReadWrite || !writeDecision.AllowWrite || ImageMutationRootReady(volume.DeviceId);
        var shouldAttemptWrite = requestedAccess == MountAccessMode.ReadWrite && writeDecision.AllowWrite && managementRootReady;
        var primaryAccess = shouldAttemptWrite ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly;
        var primaryRequest = new MountRequest(volume.VolumeId, letter, primaryAccess);
        await ValidatePreparationOwnersAsync().ConfigureAwait(false);
        var result = await _backend.MountAsync(primaryRequest, cancellationToken).ConfigureAwait(false);
        MountResult? primaryFailureResult = null;

        string? compatibilityWarning = null;
        if (!shouldAttemptWrite && options.EnableNativeWrite)
        {
            compatibilityWarning = $"Write gate is active but '{volume.VolumeName}' mounted read-only " +
                                     $"(gate={writeDecision.GateState}, reason={(!managementRootReady ? "ManagementJournalRootUninspectedOrPending" : writeDecision.Reason ?? "n/a")}).";
        }

        if (!result.Success &&
            string.Equals(options.ReadWriteMode, "RwWithRoFallback", StringComparison.OrdinalIgnoreCase))
        {
            primaryFailureResult = result;
            var fallbackRequest = new MountRequest(volume.VolumeId, letter, MountAccessMode.ReadOnly);
            // A failed primary grants no ownership; fallback must retain the original owner set.
            await ValidatePreparationOwnersAsync().ConfigureAwait(false);
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

    private async Task<ShutdownPreparationResult> PrepareForShutdownCoreAsync(ShutdownPreparationResult? previous)
    {
        var stopTimeout = TimeSpan.FromSeconds(Math.Clamp(
            _optionsMonitor.CurrentValue.NativeHostStopTimeoutSeconds,
            1,
            60));
        using var stopCts = new CancellationTokenSource(stopTimeout);
        var attemptStarted = Stopwatch.GetTimestamp();
        var warnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        IReadOnlyList<MountedVolumeState> remaining = Array.Empty<MountedVolumeState>();
        UnmountBatchResult? unmount = null;

        try
        {
            await _mountOperationLock.WaitAsync(stopCts.Token).ConfigureAwait(false);
            try
            {
                var observed = (await _backend
                    .GetMountStateAsync(stopCts.Token)
                    .ConfigureAwait(false))
                    .ToArray();
                // Preserve the first selected owners even if later discovery is
                // empty. Absence cannot manufacture their terminal safety proof.
                var mountedBefore = _shutdownSelectedMounts ??= observed;
                remaining = observed;
                var proofs = new Dictionary<string, UnmountResult>(StringComparer.OrdinalIgnoreCase);
                var pending = new List<MountedVolumeState>();
                foreach (var mount in mountedBefore)
                {
                    if (previous?.UnmountResultsOrEmpty.TryGetValue(mount.VolumeId, out var proven) == true)
                    {
                        proofs[mount.VolumeId] = proven;
                        if (IsCompleteShutdownProof(mount, proven)) continue;
                    }
                    var current = observed.Where(row =>
                        string.Equals(row.MountPoint, mount.MountPoint, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(row.VolumeId, mount.VolumeId, StringComparison.OrdinalIgnoreCase)).ToArray();
                    if (current.Length > 1 || current.Length == 1 && !SameShutdownOwner(mount, current[0]))
                    {
                        if (!proofs.ContainsKey(mount.VolumeId))
                            proofs[mount.VolumeId] = new(false, mount.MountPoint,
                                "The original shutdown selection changed; its terminal proof remains unproven.");
                        warnings.Add($"Shutdown owner changed for '{mount.MountPoint}'; no replacement owner was stopped.");
                        continue;
                    }
                    if (current.Length == 0)
                    {
                        if (!proofs.ContainsKey(mount.VolumeId))
                            proofs[mount.VolumeId] = new(false, mount.MountPoint,
                                "The original shutdown selection is absent; its terminal safety proof remains unproven.");
                        warnings.Add($"Shutdown terminal proof remains unproven for '{mount.MountPoint}': {proofs[mount.VolumeId].Error}");
                        continue;
                    }
                    pending.Add(mount);
                }

                var retainedGracefulDrain = _backend is IGracefulShutdownBackend;
                if (retainedGracefulDrain) stopCts.CancelAfter(Timeout.InfiniteTimeSpan);
                unmount = await UnmountAsync(
                    pending,
                    stopCts.Token,
                    warnings,
                    gracefulShutdown: retainedGracefulDrain).ConfigureAwait(false);
                if (retainedGracefulDrain)
                {
                    // A completed owned drain starts the bounded final-proof phase.
                    attemptStarted = Stopwatch.GetTimestamp();
                    stopCts.CancelAfter(stopTimeout);
                }
                foreach (var result in unmount.Results) proofs[result.Key] = result.Value;
                unmount = unmount with { Results = proofs };
                var reconciliation = await ReconcileRemainingMountsAsync(
                    remaining,
                    stopTimeout, attemptStarted).ConfigureAwait(false);
                remaining = reconciliation.Mounts;

                // Late cleanup can complete after an earlier detach/stop failure.
                // Query only the original incarnation's retained terminal proof.
                var detached = mountedBefore.Where(mount =>
                    unmount.Results.TryGetValue(mount.VolumeId, out var result) &&
                    !IsCompleteShutdownProof(mount, result)).ToArray();
                if (reconciliation.Succeeded && remaining.Count == 0 && detached.Length > 0)
                {
                    foreach (var mount in detached)
                    {
                        UnmountResult terminal;
                        try
                        {
                            if (_backend is not IUnmountTerminalStateBackend terminalBackend ||
                                mount.HostProcessId <= 0 || mount.HostProcessCreationTimeFileTimeUtc <= 0)
                            {
                                warnings.Add($"Shutdown terminal proof is unavailable for the original owner of '{mount.MountPoint}'.");
                                continue;
                            }
                            terminal = await terminalBackend.GetUnmountTerminalStateAsync(mount, stopCts.Token)
                                .WaitAsync(stopCts.Token).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) when (stopCts.IsCancellationRequested)
                        {
                            warnings.Add($"Shutdown terminal proof timed out for '{mount.MountPoint}'; the original detach proof is retained.");
                            break;
                        }
                        catch (Exception ex)
                        {
                            warnings.Add($"Shutdown terminal proof failed for '{mount.MountPoint}': {ex.Message}");
                            continue;
                        }

                        if (IsCompleteShutdownProof(mount, terminal))
                        {
                            proofs[mount.VolumeId] = terminal;
                            warnings.Remove($"Unmount failed for '{mount.MountPoint}': Unmount did not prove mount removal, host ownership release, and pending durability clearance.");
                        }
                        else
                        {
                            warnings.Add($"Shutdown terminal proof remains unproven for '{mount.MountPoint}': " +
                                $"mount={terminal.MountPoint}, success={terminal.Success}, removed={terminal.MountRemoved}, " +
                                $"ownership={terminal.HostOwnershipReleased}, durability={terminal.PendingDurabilityCleared}. {terminal.Error}");
                        }
                    }
                    reconciliation = await ReconcileRemainingMountsAsync(remaining, stopTimeout, attemptStarted).ConfigureAwait(false);
                    remaining = reconciliation.Mounts;
                }

                var allSelectedHaveResults = mountedBefore.All(mount =>
                    unmount.Results.ContainsKey(mount.VolumeId));
                var ownershipReleased = reconciliation.Succeeded &&
                                        remaining.Count == 0 &&
                                        allSelectedHaveResults &&
                                        mountedBefore.All(mount =>
                                        {
                                            var result = unmount.Results[mount.VolumeId];
                                            return result.Success &&
                                                   string.IsNullOrWhiteSpace(result.Error) &&
                                                   string.Equals(result.MountPoint, mount.MountPoint, StringComparison.OrdinalIgnoreCase) &&
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
                                                   string.IsNullOrWhiteSpace(result.Error) &&
                                                   string.Equals(result.MountPoint, mount.MountPoint, StringComparison.OrdinalIgnoreCase) &&
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
                stopTimeout, attemptStarted).ConfigureAwait(false);
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
                UnmountResults: unmount?.Results ?? previous?.UnmountResults);
        }
        catch (Exception ex)
        {
            var reconciliation = await ReconcileRemainingMountsAsync(
                remaining,
                stopTimeout, attemptStarted).ConfigureAwait(false);
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
                UnmountResults: unmount?.Results ?? previous?.UnmountResults);
        }
    }

    private async Task<MountStateReconciliation> ReconcileRemainingMountsAsync(
        IReadOnlyList<MountedVolumeState> fallback,
        TimeSpan stopTimeout,
        long attemptStarted)
    {
        var timeout = TimeSpan.FromSeconds(Math.Clamp(
            (int)Math.Ceiling(stopTimeout.TotalSeconds),
            1,
            5));
        // All independent probes share the original attempt's reconciliation
        // allowance. A second probe or cancellation wait cannot restart it.
        var remaining = stopTimeout + timeout - Stopwatch.GetElapsedTime(attemptStarted);
        if (remaining <= TimeSpan.Zero)
            return new(false, fallback, "The original shutdown reconciliation deadline expired.");
        if (remaining < timeout) timeout = remaining;
        using var reconciliationCts = new CancellationTokenSource(timeout);
        try
        {
            var mounts = await _backend
                .GetMountStateAsync(reconciliationCts.Token)
                .WaitAsync(reconciliationCts.Token)
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

    private static bool IsCompleteShutdownProof(MountedVolumeState mount, UnmountResult proof)
        => proof.Success && proof.MountRemoved && proof.HostOwnershipReleased && proof.PendingDurabilityCleared &&
           string.IsNullOrWhiteSpace(proof.Error) &&
           string.Equals(proof.MountPoint, mount.MountPoint, StringComparison.OrdinalIgnoreCase);

    private static bool SameShutdownOwner(MountedVolumeState original, MountedVolumeState current)
        => string.Equals(original.MountPoint, current.MountPoint, StringComparison.OrdinalIgnoreCase) &&
           string.Equals(original.DeviceId, current.DeviceId, StringComparison.OrdinalIgnoreCase) &&
           string.Equals(original.VolumeId, current.VolumeId, StringComparison.OrdinalIgnoreCase) &&
           string.Equals(original.RecoveryIdentity, current.RecoveryIdentity, StringComparison.Ordinal) &&
           original.HostProcessId == current.HostProcessId &&
           original.HostProcessCreationTimeFileTimeUtc == current.HostProcessCreationTimeFileTimeUtc &&
           string.Equals(original.CatalogContainerUuid, current.CatalogContainerUuid, StringComparison.OrdinalIgnoreCase) &&
           original.CatalogVolumeObjectId == current.CatalogVolumeObjectId &&
           string.Equals(original.CatalogVolumeUuid, current.CatalogVolumeUuid, StringComparison.OrdinalIgnoreCase);

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
        HashSet<string>? warnings = null,
        IReadOnlyList<MountedVolumeState>? sharedOwnerMounts = null,
        bool gracefulShutdown = false
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
                if (gracefulShutdown && _backend is IGracefulShutdownBackend retained)
                {
                    using var acquisition = new CancellationTokenSource(TimeSpan.FromSeconds(
                        Math.Clamp(_optionsMonitor.CurrentValue.NativeHostStopTimeoutSeconds, 1, 60)));
                    result = await retained.UnmountForShutdownAsync(mount.MountPoint, acquisition.Token).ConfigureAwait(false);
                }
                else
                {
                    result = await _backend.UnmountAsync(mount.MountPoint, cancellationToken).ConfigureAwait(false);
                }
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

            if (sharedOwnerMounts is not null && result.ContainerMemberDetached && !result.HostOwnershipReleased)
            {
                var memberProven = false;
                if (sharedOwnerMounts is not null && mounted.Count == 1 &&
                    result.Success && result.MountRemoved && result.PendingDurabilityCleared &&
                    string.Equals(result.MountPoint.TrimEnd('\\', '/'), mount.MountPoint.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        using var proofTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(
                            Math.Clamp(_optionsMonitor.CurrentValue.NativeHostStopTimeoutSeconds, 1, 60)));
                        var current = await _backend.GetMountStateAsync(proofTimeout.Token)
                            .WaitAsync(proofTimeout.Token).ConfigureAwait(false);
                        memberProven = IsSharedContainerMemberDetachProven(mount, sharedOwnerMounts, current);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Could not reconcile the shared owner after detaching {MountPoint}", mount.MountPoint);
                    }
                }
                if (!memberProven)
                    result = result with { ContainerMemberDetached = false,
                        Error = result.Error ?? "The detached drive's original shared owner could not be verified against its mounted sibling." };
            }
            results[mount.VolumeId] = result;
            var safelyRemoved = result.Success &&
                                result.MountRemoved &&
                                (result.HostOwnershipReleased || (sharedOwnerMounts is not null && result.ContainerMemberDetached)) &&
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

    private static bool IsSharedContainerMemberDetachProven(
        MountedVolumeState selected,
        IReadOnlyList<MountedVolumeState> before,
        IReadOnlyList<MountedVolumeState> current)
    {
        if (selected.HostProcessId <= 0 || selected.HostProcessCreationTimeFileTimeUtc <= 0 ||
            string.IsNullOrWhiteSpace(selected.DeviceId) || string.IsNullOrWhiteSpace(selected.CatalogContainerUuid) ||
            string.IsNullOrWhiteSpace(selected.RecoveryIdentity) ||
            current.Any(m => string.Equals(m.VolumeId, selected.VolumeId, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(m.MountPoint.TrimEnd('\\', '/'), selected.MountPoint.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))) return false;
        return before.Any(sibling => !string.Equals(sibling.VolumeId, selected.VolumeId, StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(sibling.RecoveryIdentity) &&
            string.Equals(sibling.DeviceId, selected.DeviceId, StringComparison.OrdinalIgnoreCase) &&
            TopologyAdmission.SameUuid(sibling.CatalogContainerUuid, selected.CatalogContainerUuid) &&
            sibling.HostProcessId == selected.HostProcessId &&
            sibling.HostProcessCreationTimeFileTimeUtc == selected.HostProcessCreationTimeFileTimeUtc &&
            current.Count(m => string.Equals(m.VolumeId, sibling.VolumeId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(m.DeviceId, sibling.DeviceId, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(m.RecoveryIdentity, sibling.RecoveryIdentity, StringComparison.Ordinal) &&
                string.Equals(m.MountPoint.TrimEnd('\\', '/'), sibling.MountPoint.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase) &&
                TopologyAdmission.SameUuid(m.CatalogContainerUuid, selected.CatalogContainerUuid) &&
                m.HostProcessId == selected.HostProcessId &&
                m.HostProcessCreationTimeFileTimeUtc == selected.HostProcessCreationTimeFileTimeUtc &&
                m.MountReady && !m.ShutdownDrainActive) == 1);
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
        PublishWithCurrentInventory(
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

    private void PublishWithCurrentInventory(StatusChangedPayload payload)
    {
        var managementRootInspected = TryInspectManagementRoot();
        Action? notification;
        lock (_discoveryAdmissionSync)
        {
            payload = payload with { ConnectedInventory = _admittedDiscovery?.Inventory, InventoryGeneration = _admittedDiscovery?.Generation,
                VolumeManagementReadyImages = _volumeManagementReadyImages,
                ManagementJournalRootInspected = managementRootInspected, ImageResizeFormatEnabled = ImageResizeFormatEnabled,
                ImageManagementMutationsEnabled = ImageManagementMutationsEnabled };
            StatusChangedPayload latest;
            do { latest = _statusPublisher.Latest; }
            while (!_statusPublisher.TryPublish(latest, payload, out notification));
        }
        NotifyDiscovery(notification);
    }

    private static IReadOnlyList<MountedVolumeDisplay> BuildMountedVolumeDisplays(IReadOnlyList<MountedVolumeState> mounts)
        => MountedStatusProjection.FromMounts(mounts);

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
