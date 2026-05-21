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
    private readonly SemaphoreSlim _mountOperationLock = new(1, 1);
    private static readonly HashSet<string> ValidationEvidenceRecoveryReasons = new(StringComparer.OrdinalIgnoreCase)
    {
        "ValidationEvidenceInsufficient",
        "ValidationCrashFaultEvidenceInsufficient",
        "ValidationCrashStageMatrixEvidenceInsufficient",
        "ValidationHardwarePilotEvidenceInsufficient",
        "ValidationHotUnplugEvidenceInsufficient",
        "ValidationCrossOsEvidenceInsufficient",
        "ValidationMacOsEvidenceInsufficient",
        "ValidationMacOsConsistencyEvidenceInsufficient",
        "ValidationPowerLossReplayEvidenceInsufficient",
        "ValidationPowerLossEvidenceInsufficient",
        "ValidationCanonicalEvidenceInsufficient",
        "ValidationHardwarePilotEvidenceStale",
        "ValidationStableEvidenceStale",
    };
    private static readonly string[] ExplicitCanonicalGateRecoveryReasons =
    [
        "CanonicalStateNotLoaded",
        "CanonicalVolumeStateLoadFailed",
        "CanonicalObjectMapStateInvalid",
        "CanonicalSpacemanStateInvalid",
        "CanonicalVolumeTreeStateInvalid",
        "NativeWriteNotReady",
        "WriteDeviceNotAllowed",
        "CommitPathNotReady",
        "CanonicalCommitNotReady",
        "FixtureCompatibilityPathActive",
        "ScaffoldCommitBlobActive",
    ];
    private static readonly string[] HighPriorityReplayRecoveryReasons =
    [
        "IntegrityMissingAllocationMap",
        "ReplayCheckpointPendingWindow",
        "ReplayCheckpointNotPendingWindow",
        "ReplayCanonicalCandidateMissing",
    ];

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
            Publish(
                RuntimeState.Stopping,
                Array.Empty<MountedVolumeState>(),
                null,
                warnings: Array.Empty<string>(),
                writeEnabled: false,
                compatibilityWarnings: Array.Empty<string>()
            );
            await UnmountAllAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async Task RunCycleAsync(CancellationToken cancellationToken)
    {
        await _mountOperationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await RunCycleCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _mountOperationLock.Release();
        }
    }

    private async Task RunCycleCoreAsync(CancellationToken cancellationToken)
    {
        var options = _optionsMonitor.CurrentValue;
        var warnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var compatibilityWarnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var devices = await _backend.ProbeDevicesAsync(cancellationToken).ConfigureAwait(false);
        var connectedDevices = devices.Where(x => x.IsConnected).ToArray();

        if (connectedDevices.Length == 0)
        {
            _userEjectedVolumeIds.Clear();
            await UnmountAllAsync(cancellationToken, warnings).ConfigureAwait(false);
            Publish(
                RuntimeState.Idle,
                Array.Empty<MountedVolumeState>(),
                null,
                warnings.ToArray(),
                writeEnabled: false,
                compatibilityWarnings: compatibilityWarnings.ToArray()
            );
            return;
        }

        var discoveredVolumeById = new Dictionary<string, VolumeInfo>(StringComparer.OrdinalIgnoreCase);
        foreach (var device in connectedDevices)
        {
            var volumes = await _backend.ProbeVolumesAsync(device.DeviceId, cancellationToken).ConfigureAwait(false);
            foreach (var volume in volumes)
            {
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

        var disconnectedEjectedVolumes = _userEjectedVolumeIds
            .Where(volumeId => !discoveredVolumeById.ContainsKey(volumeId))
            .ToArray();
        foreach (var volumeId in disconnectedEjectedVolumes)
        {
            _userEjectedVolumeIds.Remove(volumeId);
        }

        var mounted = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
        await UnmountMissingVolumesAsync(
            mounted,
            discoveredVolumeById.Keys,
            warnings,
            cancellationToken
        ).ConfigureAwait(false);

        if (!options.AutoMountEnabled)
        {
            var current = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
            PublishFromMounts(current, null, warnings, compatibilityWarnings);
            return;
        }

        mounted = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
        var mountedVolumeIds = new HashSet<string>(mounted.Select(x => x.VolumeId), StringComparer.OrdinalIgnoreCase);
        var usedLetters = new HashSet<char>(
            mounted
                .Select(TryGetDriveLetter)
                .Where(ch => ch.HasValue)
                .Select(ch => ch!.Value)
        );
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (string.IsNullOrWhiteSpace(drive.Name))
            {
                continue;
            }

            var letter = char.ToUpperInvariant(drive.Name[0]);
            if (letter is >= 'A' and <= 'Z')
            {
                usedLetters.Add(letter);
            }
        }

        string? firstMountError = null;

        foreach (var volume in discoveredVolumeById.Values.OrderBy(x => x.VolumeName, StringComparer.OrdinalIgnoreCase))
        {
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

            if (!options.NativeAutoRemountOnReconnect && _mountedOnce.Contains(volume.VolumeId))
            {
                warnings.Add($"Auto-remount disabled for '{volume.VolumeName}' after prior disconnect.");
                continue;
            }

            var (success, error, warning, compatibilityWarning) = await TryMountAsync(
                volume,
                options,
                usedLetters,
                cancellationToken
            ).ConfigureAwait(false);
            if (success)
            {
                mountedVolumeIds.Add(volume.VolumeId);
                _mountedOnce.Add(volume.VolumeId);
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

            if (!string.IsNullOrWhiteSpace(error))
            {
                warnings.Add($"Mount failed for '{volume.VolumeName}': {error}");
            }
        }

        var refreshedMounts = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
        PublishFromMounts(refreshedMounts, firstMountError, warnings, compatibilityWarnings);
    }

    public async Task<(bool Success, string Message)> EjectAllAsync(CancellationToken cancellationToken)
        => await EjectAsync(null, cancellationToken).ConfigureAwait(false);

    public async Task<(bool Success, string Message)> RefreshAsync(
        bool clearUserEjectedVolumes,
        CancellationToken cancellationToken
    )
    {
        await _mountOperationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (clearUserEjectedVolumes)
            {
                _userEjectedVolumeIds.Clear();
            }

            await RunCycleCoreAsync(cancellationToken).ConfigureAwait(false);
            return (true, "APFS drives refreshed.");
        }
        finally
        {
            _mountOperationLock.Release();
        }
    }

    public async Task<(bool Success, string Message)> EjectAsync(string? volumeId, CancellationToken cancellationToken)
    {
        await _mountOperationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var warnings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var mountedBeforeEject = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
            var selectedMounts = SelectMountsForEject(mountedBeforeEject, volumeId);
            if (selectedMounts.Count == 0)
            {
                PublishFromMounts(mountedBeforeEject, null, warnings, Array.Empty<string>());
                return string.IsNullOrWhiteSpace(volumeId)
                    ? (true, "No APFS drives are mounted.")
                    : (false, "That APFS drive is no longer mounted.");
            }

            var unmounted = await UnmountAsync(selectedMounts, cancellationToken, warnings).ConfigureAwait(false);
            var unmountedIds = unmounted.Select(static x => x.VolumeId).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var refreshedRemaining = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
            var remaining = refreshedRemaining
                .Where(mount => !unmountedIds.Contains(mount.VolumeId))
                .ToArray();
            var remainingIds = remaining.Select(static x => x.VolumeId).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var remainingCount = remaining.Length;
            foreach (var mount in unmounted)
            {
                _userEjectedVolumeIds.Add(mount.VolumeId);
            }

            var statusWarnings = new HashSet<string>(warnings, StringComparer.OrdinalIgnoreCase);
            foreach (var mount in unmounted)
            {
                statusWarnings.Add(BuildSafelyEjectedWarning(mount));
            }

            PublishFromMounts(remaining, null, statusWarnings, Array.Empty<string>());

            if (remainingCount == 0 && warnings.Count == 0)
            {
                return string.IsNullOrWhiteSpace(volumeId)
                    ? (true, "All APFS drives were safely ejected.")
                    : (true, $"APFS drive {BuildMountDisplayName(selectedMounts[0])} was safely ejected.");
            }

            if (!string.IsNullOrWhiteSpace(volumeId) && !remainingIds.Contains(volumeId) && warnings.Count == 0)
            {
                return (true, $"APFS drive {BuildMountDisplayName(selectedMounts[0])} was safely ejected.");
            }

            if (!string.IsNullOrWhiteSpace(volumeId) && !remainingIds.Contains(volumeId))
            {
                return (false, string.Join(" ", warnings));
            }

            if (remainingCount == 0)
            {
                return (false, string.Join(" ", warnings));
            }

            var stillMounted = string.Join(", ", remaining.Select(static x => x.MountPoint));
            var detail = warnings.Count == 0 ? string.Empty : $" {string.Join(" ", warnings)}";
            return (false, $"Some APFS drives are still mounted: {stillMounted}.{detail}");
        }
        finally
        {
            _mountOperationLock.Release();
        }
    }

    private static IReadOnlyList<MountedVolumeState> SelectMountsForEject(
        IReadOnlyList<MountedVolumeState> mounted,
        string? volumeId
    )
    {
        if (string.IsNullOrWhiteSpace(volumeId))
        {
            return mounted;
        }

        return mounted
            .Where(mount => string.Equals(mount.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase))
            .ToArray();
    }

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

    private async Task<(bool Success, string? Error, string? Warning, string? CompatibilityWarning)> TryMountAsync(
        VolumeInfo volume,
        ServiceHostOptions options,
        HashSet<char> usedLetters,
        CancellationToken cancellationToken
    )
    {
        char letter;
        try
        {
            letter = _mountPolicy.SelectDriveLetter(volume, usedLetters);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not allocate drive letter for {VolumeId}", volume.VolumeId);
            return (false, ex.Message, null, null);
        }

        var writeDecision = WriteGatePolicy.EvaluateForVolume(options, volume);
        var shouldAttemptWrite = writeDecision.AllowWrite;
        var requestedAccess = shouldAttemptWrite ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly;
        var primaryRequest = new MountRequest(volume.VolumeId, letter, requestedAccess);
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
            return (false, error, null, compatibilityWarning);
        }

        usedLetters.Add(letter);
        var warning = result.DiagnosticCode switch
        {
            "Phase1ShellMount" => $"Mounted '{volume.VolumeName}' as read-only APFS snapshot. Copy-out is supported; writes do not go back to APFS.",
            null => null,
            _ => $"Mounted '{volume.VolumeName}' with diagnostic '{result.DiagnosticCode}'.",
        };

        _logger.LogInformation(
            "Mounted volume {VolumeId} at {MountPoint} ({Mode}, ReadOnly={ReadOnly}).",
            volume.VolumeId,
            result.MountPoint,
            result.EffectiveAccessMode,
            result.IsReadOnly
        );
        return (true, null, warning, compatibilityWarning);
    }

    private async Task UnmountAllAsync(CancellationToken cancellationToken, HashSet<string>? warnings = null)
    {
        var mounted = await _backend.GetMountStateAsync(cancellationToken).ConfigureAwait(false);
        await UnmountAsync(mounted, cancellationToken, warnings).ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<MountedVolumeState>> UnmountAsync(
        IReadOnlyList<MountedVolumeState> mounted,
        CancellationToken cancellationToken,
        HashSet<string>? warnings = null
    )
    {
        var unmounted = new List<MountedVolumeState>(mounted.Count);
        foreach (var mount in mounted)
        {
            var result = await _backend.UnmountAsync(mount.MountPoint, cancellationToken).ConfigureAwait(false);
            if (result.Success)
            {
                unmounted.Add(mount);
            }
            else
            {
                _logger.LogWarning("Failed to unmount {MountPoint}: {Error}", mount.MountPoint, result.Error);
                if (!string.IsNullOrWhiteSpace(result.Error))
                {
                    warnings?.Add($"Unmount failed for '{mount.MountPoint}': {result.Error}");
                }
            }
        }

        return unmounted;
    }

    private async Task UnmountMissingVolumesAsync(
        IReadOnlyList<MountedVolumeState> mounted,
        IEnumerable<string> discoveredVolumeIds,
        HashSet<string> warnings,
        CancellationToken cancellationToken
    )
    {
        var discovered = discoveredVolumeIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var mount in mounted)
        {
            if (discovered.Contains(mount.VolumeId))
            {
                continue;
            }

            var result = await _backend.UnmountAsync(mount.MountPoint, cancellationToken).ConfigureAwait(false);
            if (!result.Success)
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
            }
            else
            {
                _logger.LogInformation(
                    "Unmounted stale mount {MountPoint} (volume {VolumeId}).",
                    mount.MountPoint,
                    mount.VolumeId
                );
            }
        }
    }

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
            .OrderBy(x => GetRecoveryReasonPriority(x.EffectiveRecoveryReason))
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
            .OrderBy(static x => GetRecoveryReasonPriority(x.RecoveryReason))
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

    private static int GetRecoveryReasonPriority(string? recoveryReason)
    {
        if (string.IsNullOrWhiteSpace(recoveryReason))
        {
            return int.MaxValue;
        }

        var normalized = recoveryReason.Trim();
        if (ExplicitCanonicalGateRecoveryReasons.Any(x => string.Equals(x, normalized, StringComparison.OrdinalIgnoreCase)))
        {
            return 0;
        }

        if (HighPriorityReplayRecoveryReasons.Any(x => string.Equals(x, normalized, StringComparison.OrdinalIgnoreCase)))
        {
            return 1;
        }

        if (string.Equals(normalized, "CanonicalPathNotActive", StringComparison.OrdinalIgnoreCase))
        {
            return 2;
        }

        return 3;
    }

    private static int GetCompatibilityWarningPriority(string warning)
    {
        if (string.IsNullOrWhiteSpace(warning))
        {
            return int.MaxValue;
        }

        foreach (var reason in ExplicitCanonicalGateRecoveryReasons)
        {
            if (warning.Contains($"reason={reason}", StringComparison.OrdinalIgnoreCase))
            {
                return 0;
            }
        }

        if (warning.Contains("reason=CanonicalPathNotActive", StringComparison.OrdinalIgnoreCase))
        {
            return 2;
        }

        foreach (var reason in HighPriorityReplayRecoveryReasons)
        {
            if (warning.Contains($"reason={reason}", StringComparison.OrdinalIgnoreCase))
            {
                return 1;
            }
        }

        if (warning.Contains("reason=", StringComparison.OrdinalIgnoreCase))
        {
            return 3;
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
        if (!IsValidationEvidenceRecoveryReason(mount.RecoveryReason))
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

    private static bool IsValidationEvidenceRecoveryReason(string? recoveryReason)
    {
        if (string.IsNullOrWhiteSpace(recoveryReason))
        {
            return false;
        }

        return ValidationEvidenceRecoveryReasons.Contains(recoveryReason.Trim());
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
                MountedVolumes: BuildMountedVolumeDisplays(mounts),
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
                AccessMode: mount.AccessMode))
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
            .OrderBy(x => GetRecoveryReasonPriority(x.EffectiveRecoveryReason))
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
                .OrderBy(x => GetRecoveryReasonPriority(x.EffectiveRecoveryReason))
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
