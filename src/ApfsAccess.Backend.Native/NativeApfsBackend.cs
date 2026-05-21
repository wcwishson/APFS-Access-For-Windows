using System.Collections.Concurrent;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ApfsAccess.Core;

namespace ApfsAccess.Backend.Native;

public sealed class NativeApfsBackend : IApfsBackend, IDisposable
{
    private static readonly Regex SuccessRegexTemplate = new(
        @"APFS:\s*(?<cmd>[a-z]+)\s+returns\s+0\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );

    private static readonly Regex VolumeTokenRegex = new(
        @"'([^']+)'|([^\s]+)",
        RegexOptions.Compiled
    );
    private static readonly Regex IndexedVolumePrefixRegex = new(
        @"^(?:Volume\s*\[\d+\]|\[\d+\]|[-*])\s*:?\s*",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );
    private static readonly Regex VolumeInlineAnnotationRegex = new(@"\([^)]*\)", RegexOptions.Compiled);
    private static readonly Regex ParentheticalAnnotationRegex = new(@"\([^)]*\)", RegexOptions.Compiled);
    private static readonly Regex WhitespaceCollapseRegex = new(@"\s+", RegexOptions.Compiled);
    private static readonly Regex RoleAssignmentSpacingRegex = new(@"\brole\s*=\s*", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex TrailingRoleTokenRegex = new(@"\s+role(?:\s*=\s*|\s+)[a-z0-9_-]+$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly string[] TrailingVolumeMetadataTokens =
    [
        "encrypted",
        "locked",
        "readonly",
        "read-only",
        "case-sensitive",
        "casesensitive",
        "snapshot",
        "clone",
        "sealed",
        "system volume",
        "role=system",
        "role system",
        "role=preboot",
        "role preboot",
        "role=recovery",
        "role recovery",
        "role=vm",
        "role vm",
        "fusion",
    ];

    private const int CommandTimeoutSeconds = 12;
    private const string DefaultMainVolumeName = "Main";
    private static readonly TimeSpan RuntimeStatusPollTimeout = TimeSpan.FromMilliseconds(350);
    private static readonly Guid ApfsPartitionTypeGuid = new("7C3457EF-0000-11AA-AA11-00306543ECAC");
    private static readonly int[] ProbeSectorSizes = [512, 4096];
    private const int MaxGptEntriesToRead = 1024;

    private readonly ServiceHostOptions _options;
    private readonly string? _nativeFsHostPath;
    private readonly IReadOnlyList<string> _deviceCandidates;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly ConcurrentDictionary<string, MountedVolumeState> _mounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, HostProcessState> _hosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, VolumeInfo> _volumeCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DiscoveredDevice> _deviceDiscoveryCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, VolumeMountTarget> _mountTargetsByVolumeId = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, NativeWriteValidationEvidence> _validationEvidenceByVolumeId = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, NativeWriteValidationEvidence> _validationEvidenceByProfileId = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _lastPromotedEvidenceSessionByProfileId = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _deviceDisplayNameById = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _writeDiagnosticsRoot = Path.Combine(Path.GetTempPath(), "ApfsAccess", "write-diagnostics");

    public NativeApfsBackend(ServiceHostOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
        _nativeFsHostPath = ResolveNativeFsHostPath(options);
        _deviceCandidates = BuildDeviceCandidates(options);
        Directory.CreateDirectory(_writeDiagnosticsRoot);
        LoadValidationEvidenceFromDisk();
    }

    public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var devices = new List<DeviceInfo>();
        foreach (var candidate in _deviceCandidates)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var discovered = DiscoverDevice(candidate);
            if (discovered is not null)
            {
                _deviceDiscoveryCache[candidate] = discovered;
                _deviceDisplayNameById[discovered.DeviceId] = discovered.DisplayName;
                devices.Add(new DeviceInfo(discovered.DeviceId, discovered.DisplayName, true));
            }
            else
            {
                _deviceDiscoveryCache.TryRemove(candidate, out _);
                _deviceDisplayNameById.TryRemove(candidate, out _);
            }
        }

        return Task.FromResult<IReadOnlyList<DeviceInfo>>(devices);
    }

    public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(string deviceId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);

        var discovered = DiscoverDevice(deviceId);
        if (discovered is null)
        {
            _deviceDiscoveryCache.TryRemove(deviceId, out _);
            return Task.FromResult<IReadOnlyList<VolumeInfo>>(Array.Empty<VolumeInfo>());
        }

        _deviceDiscoveryCache[deviceId] = discovered;
        _deviceDisplayNameById[discovered.DeviceId] = discovered.DisplayName;

        var volumes = discovered.Volumes
            .Select(discoveredVolume => CreateDiscoveredVolumeInfo(deviceId, discoveredVolume))
            .ToArray();

        foreach (var volume in volumes)
        {
            _volumeCache[volume.VolumeId] = volume;
        }

        return Task.FromResult<IReadOnlyList<VolumeInfo>>(volumes);
    }

    public async Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(request);

        if (string.IsNullOrWhiteSpace(_nativeFsHostPath) || !File.Exists(_nativeFsHostPath))
        {
            return new MountResult(
                Success: false,
                MountPoint: null,
                Error: "APFS mount component is missing or not installed.",
                EffectiveAccessMode: MountAccessMode.ReadOnly,
                DiagnosticCode: "FsHostMissing",
                IsReadOnly: true,
                WriteEnabled: false,
                SafetyGateState: "HostMissing",
                WriteBackend: NormalizeWriteBackendName(_options.WriteBackendMode),
                NativeWriteReadiness: NativeWriteReadiness.Unavailable,
                NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback
            );
        }

        if (request.AccessMode == MountAccessMode.ReadWrite &&
            !IsWriteBackendMode(_options.WriteBackendMode, "Overlay") &&
            !IsWriteBackendMode(_options.WriteBackendMode, "Native"))
        {
            var gateState = GetWriteGateState();
            WriteWriteSessionMarker(
                requestedVolumeId: request.VolumeId,
                requestedAccessMode: request.AccessMode,
                mountPoint: NormalizeMountPoint(request.DriveLetter),
                gateState: gateState,
                diagnosticCode: "WriteBackendDisabled",
                error: "Write backend mode is disabled. Set Service.WriteBackendMode=Overlay or Native for experimental write-path testing."
            );
            return new MountResult(
                Success: false,
                MountPoint: null,
                Error: "Write backend mode is disabled. Set Service.WriteBackendMode=Overlay or Native for experimental write-path testing.",
                EffectiveAccessMode: MountAccessMode.ReadOnly,
                DiagnosticCode: "WriteBackendDisabled",
                IsReadOnly: true,
                WriteEnabled: false,
                SafetyGateState: gateState,
                WriteBackend: "Disabled",
                NativeWriteReadiness: NativeWriteReadiness.Unavailable,
                NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback
            );
        }

        var mountPoint = NormalizeMountPoint(request.DriveLetter);
        var startupTimeout = TimeSpan.FromSeconds(Math.Clamp(_options.NativeHostStartupTimeoutSeconds, 2, 60));
        var resolvedVolume = await ResolveVolumeAsync(request.VolumeId, cancellationToken).ConfigureAwait(false);
        HostProcessState? pendingHostState = null;
        var hostRegistered = false;

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            CleanupExitedHosts_NoLock();

            if (_mounts.ContainsKey(mountPoint))
            {
                return new MountResult(
                    Success: false,
                    MountPoint: null,
                    Error: $"Mount point '{mountPoint}' is already in use.",
                    EffectiveAccessMode: MountAccessMode.ReadOnly,
                    DiagnosticCode: "MountPointBusy",
                    IsReadOnly: true,
                    WriteEnabled: false,
                    SafetyGateState: "MountPointBusy"
                );
            }

            if (IsDriveVisible(mountPoint))
            {
                return new MountResult(
                    Success: false,
                    MountPoint: null,
                    Error: $"Mount point '{mountPoint}' is still visible in Explorer. Close Explorer windows or files and try eject again before remounting.",
                    EffectiveAccessMode: MountAccessMode.ReadOnly,
                    DiagnosticCode: "MountPointStillVisible",
                    IsReadOnly: true,
                    WriteEnabled: false,
                    SafetyGateState: "MountPointStillVisible"
                );
            }

            if (resolvedVolume is null)
            {
                return new MountResult(
                    Success: false,
                    MountPoint: null,
                    Error: $"Unknown volume id '{request.VolumeId}'. Probe volumes before mounting.",
                    EffectiveAccessMode: MountAccessMode.ReadOnly,
                    DiagnosticCode: "UnknownVolume",
                    IsReadOnly: true,
                    WriteEnabled: false,
                    SafetyGateState: "UnknownVolume"
                );
            }

            var volume = resolvedVolume;

            if (volume.IsEncrypted)
            {
                return new MountResult(
                    Success: false,
                    MountPoint: null,
                    Error: $"Volume '{volume.VolumeName}' is encrypted and is skipped in this phase.",
                    EffectiveAccessMode: MountAccessMode.ReadOnly,
                    DiagnosticCode: "EncryptedVolume",
                    IsReadOnly: true,
                    WriteEnabled: false,
                    SafetyGateState: "EncryptedUnsupported",
                    WriteIncompatibilities: volume.WriteIncompatibilities
                );
            }

            if (!volume.SupportsExplorerMount)
            {
                return new MountResult(
                    Success: false,
                    MountPoint: null,
                    Error: $"Volume '{volume.VolumeName}' does not support Explorer mounting.",
                    EffectiveAccessMode: MountAccessMode.ReadOnly,
                    DiagnosticCode: "ExplorerMountUnsupported",
                    IsReadOnly: true,
                    WriteEnabled: false,
                    SafetyGateState: "ExplorerMountUnsupported",
                    WriteIncompatibilities: volume.WriteIncompatibilities
                );
            }

            if (request.AccessMode == MountAccessMode.ReadWrite)
            {
                var writeGateDecision = EvaluateWriteGateDecision(volume);
                var writeGateFailClosedReason = GetWriteGateFailClosedReason(
                    request.AccessMode,
                    _options.WriteBackendMode,
                    writeGateDecision);
                if (writeGateFailClosedReason is not null)
                {
                    var recoveryGateState = BuildRecoveryFailClosedGateState(writeGateFailClosedReason);
                    var recoveryDiagnosticCode = BuildRecoveryFailClosedDiagnosticCode(writeGateFailClosedReason);
                    var writeGateDetail = BuildWriteGateDecisionDetail(writeGateDecision);
                    var gateState = string.IsNullOrWhiteSpace(writeGateDecision.GateState)
                        ? recoveryGateState
                        : writeGateDecision.GateState.Trim();

                    WriteWriteSessionMarker(
                        requestedVolumeId: request.VolumeId,
                        requestedAccessMode: request.AccessMode,
                        mountPoint: mountPoint,
                        gateState: gateState,
                        diagnosticCode: recoveryDiagnosticCode,
                        error: $"Write-gate policy blocked writable mount ({writeGateDetail})."
                    );

                    var attemptedWriteBackend = NormalizeWriteBackendName(_options.WriteBackendMode);
                    return new MountResult(
                        Success: false,
                        MountPoint: null,
                        Error: BuildWriteBlockedMountError(
                            $"Write-gate policy blocked writable mount ({writeGateDetail})"),
                        EffectiveAccessMode: MountAccessMode.ReadOnly,
                        DiagnosticCode: recoveryDiagnosticCode,
                        IsReadOnly: true,
                        WriteEnabled: false,
                        SafetyGateState: gateState,
                        WriteBackend: attemptedWriteBackend,
                        CommitModel: NativeWriteCommitModel.ScaffoldCheckpoint,
                        NativeWriteReadiness: volume.NativeWriteReadiness,
                        NativeWriteEngineState: ResolveNativeWriteEngineState(
                            MountAccessMode.ReadOnly,
                            attemptedWriteBackend,
                            volume.NativeWriteReadiness,
                            recoveryActive: false),
                        NativeWriteValidationState: NativeWriteValidationState.Scaffold,
                        NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                        WriteIncompatibilities: volume.WriteIncompatibilities,
                        WriteUnsupportedFeatures: volume.WriteUnsupportedFeatures,
                        LastRecoveryAction: DeriveLastRecoveryAction(writeGateFailClosedReason, null),
                        NativeWriteDiagnostics: BuildNativeWriteDiagnostics(
                            MountAccessMode.ReadOnly,
                            attemptedWriteBackend,
                            NativeWriteValidationState.Scaffold,
                            ResolveRequiredValidationStateForPromotionPolicy(_options.NativeWritePromotionPolicy),
                            writeGateFailClosedReason,
                            DeriveLastRecoveryAction(writeGateFailClosedReason, null),
                            validationEvidence: null,
                            recoveryActive: false,
                            failClosedTriggered: true,
                            scope: "Mount",
                            deviceProfileId: BuildValidationEvidenceProfileId(volume))
                    );
                }
            }

            pendingHostState = StartHostProcess(volume, mountPoint, request.AccessMode);
            var hostState = pendingHostState;
            var started = await WaitForMountOrExitAsync(
                hostState.Process,
                mountPoint,
                hostState.StatusFilePath,
                request.AccessMode,
                _options.WriteBackendMode,
                startupTimeout,
                cancellationToken
            ).ConfigureAwait(false);

            if (!started)
            {
                await StopHostProcessAsync(hostState, CancellationToken.None).ConfigureAwait(false);
                pendingHostState = null;
                return new MountResult(
                    Success: false,
                    MountPoint: null,
                    Error: $"FsHost did not expose drive {mountPoint} within {startupTimeout.TotalSeconds:n0}s.",
                    EffectiveAccessMode: MountAccessMode.ReadOnly,
                    DiagnosticCode: "FsHostStartupTimeout",
                    IsReadOnly: true,
                    WriteEnabled: false,
                    SafetyGateState: "HostStartupTimeout"
                );
            }

            var hostRuntimeStatus = await ReadHostRuntimeStatusAsync(
                hostState.StatusFilePath,
                request.AccessMode,
                _options.WriteBackendMode,
                timeout: TimeSpan.FromSeconds(3),
                cancellationToken
            ).ConfigureAwait(false);

            var requestedNativeWrite = request.AccessMode == MountAccessMode.ReadWrite &&
                                       IsWriteBackendMode(_options.WriteBackendMode, "Native");
            var nativeWriteValidationEvidence = MergeValidationEvidenceFromRuntimeStatus(
                volume,
                request.AccessMode,
                hostRuntimeStatus,
                ResolveValidationEvidence(volume),
                runtimeSessionId: hostState.StatusFilePath
            );
            var runtimeDeviceProfileId = BuildValidationEvidenceProfileId(volume);
            var requiredValidationState = ResolveRequiredValidationStateForPromotionPolicy(_options.NativeWritePromotionPolicy);
            var isFixtureImage = IsFixtureImagePath(volume.DeviceId);
            var strictNonFixtureScaffoldControls = ResolveEffectiveNonFixtureScaffoldControls(volume.DeviceId);
            var failClosedReason = requestedNativeWrite
                ? GetFailClosedReasonForRuntimeStatus(
                    hostRuntimeStatus,
                    _options.NativeWriteRecoveryPolicy,
                    _options.NativeWriteMaxDirtyTransactions,
                    isFixtureImage,
                    strictNonFixtureScaffoldControls.DisallowScaffoldCommitOnNonFixture,
                    strictNonFixtureScaffoldControls.RejectScaffoldReplayBlobOnNonFixture,
                    strictNonFixtureScaffoldControls.RequireCanonicalReplayCandidateOnNonFixture)
                : null;
            if (requestedNativeWrite && failClosedReason is not null)
            {
                var recoveryGateState = BuildRecoveryFailClosedGateState(failClosedReason);
                var recoveryDiagnosticCode = BuildRecoveryFailClosedDiagnosticCode(failClosedReason);
                var recoveryExplanation = DescribeRecoveryReason(failClosedReason);

                await StopHostProcessAsync(hostState, CancellationToken.None).ConfigureAwait(false);
                pendingHostState = null;
                WriteWriteSessionMarker(
                    requestedVolumeId: request.VolumeId,
                    requestedAccessMode: request.AccessMode,
                    mountPoint: mountPoint,
                    gateState: recoveryGateState,
                    diagnosticCode: recoveryDiagnosticCode,
                    error: $"Native write policy '{_options.NativeWriteRecoveryPolicy}' blocked write mount " +
                           $"(recoveryActive={hostRuntimeStatus.RecoveryActive}, readiness={hostRuntimeStatus.NativeWriteReadiness}, " +
                           $"reason={failClosedReason})."
                );
                return new MountResult(
                    Success: false,
                    MountPoint: null,
                    Error: BuildWriteBlockedMountError(
                        $"APFS write mode paused to protect the drive (reason={failClosedReason}; detail={recoveryExplanation})"),
                    EffectiveAccessMode: MountAccessMode.ReadOnly,
                    DiagnosticCode: recoveryDiagnosticCode,
                    IsReadOnly: true,
                    WriteEnabled: false,
                    SafetyGateState: recoveryGateState,
                    WriteBackend: "Native",
                    CommitModel: hostRuntimeStatus.CommitModel,
                    NativeWriteReadiness: hostRuntimeStatus.NativeWriteReadiness,
                    NativeWriteEngineState: ResolveNativeWriteEngineState(
                        MountAccessMode.ReadOnly,
                        "Native",
                        hostRuntimeStatus.NativeWriteReadiness,
                        hostRuntimeStatus.RecoveryActive),
                    NativeWriteValidationState: hostRuntimeStatus.NativeWriteValidationState,
                    NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                    WriteIncompatibilities: volume.WriteIncompatibilities,
                    WriteUnsupportedFeatures: volume.WriteUnsupportedFeatures,
                    LastRecoveryAction: hostRuntimeStatus.LastRecoveryAction ?? DeriveLastRecoveryAction(failClosedReason, null),
                    DirtyTransactionCount: hostRuntimeStatus.DirtyTransactionCount,
                    ShutdownDrainActive: hostRuntimeStatus.ShutdownDrainActive,
                    InFlightMutationCallbacks: hostRuntimeStatus.InFlightMutationCallbacks,
                    NativeWriteValidationEvidence: nativeWriteValidationEvidence,
                    NativeWriteDiagnostics: BuildNativeWriteDiagnostics(
                        MountAccessMode.ReadOnly,
                        "Native",
                        hostRuntimeStatus.NativeWriteValidationState,
                        requiredValidationState,
                        failClosedReason,
                        hostRuntimeStatus.LastRecoveryAction ?? DeriveLastRecoveryAction(failClosedReason, null),
                        nativeWriteValidationEvidence,
                        hostRuntimeStatus.RecoveryActive,
                        failClosedTriggered: true,
                        scope: "Mount",
                        commitStage: hostRuntimeStatus.CommitStage,
                        replayStage: hostRuntimeStatus.ReplayStage,
                        commitBlobMagic: hostRuntimeStatus.CommitBlobMagic,
                        canonicalPathActive: hostRuntimeStatus.CanonicalPathActive,
                        deviceProfileId: runtimeDeviceProfileId,
                        replayCheckpointCandidatePresent: hostRuntimeStatus.ReplayCheckpointCandidatePresent,
                        replayCheckpointPendingWindow: hostRuntimeStatus.ReplayCheckpointPendingWindow)
                );
            }

            if (requestedNativeWrite &&
                _options.NativeWriteRequireCanonicalCommit &&
                hostRuntimeStatus.CommitModel != NativeWriteCommitModel.CanonicalApfsCheckpoint)
            {
                await StopHostProcessAsync(hostState, CancellationToken.None).ConfigureAwait(false);
                pendingHostState = null;
                WriteWriteSessionMarker(
                    requestedVolumeId: request.VolumeId,
                    requestedAccessMode: request.AccessMode,
                    mountPoint: mountPoint,
                    gateState: "NativeCommitModelNotCanonical",
                    diagnosticCode: "NativeWriteCommitModelNotCanonical",
                    error: $"Native write backend commit model was '{hostRuntimeStatus.CommitModel}'."
                );
                return new MountResult(
                    Success: false,
                    MountPoint: null,
                    Error: BuildWriteBlockedMountError("Native write backend is not using canonical APFS checkpoint commit model"),
                    EffectiveAccessMode: MountAccessMode.ReadOnly,
                    DiagnosticCode: "NativeWriteCommitModelNotCanonical",
                    IsReadOnly: true,
                    WriteEnabled: false,
                    SafetyGateState: "NativeCommitModelNotCanonical",
                    WriteBackend: "Native",
                    CommitModel: hostRuntimeStatus.CommitModel,
                    NativeWriteReadiness: hostRuntimeStatus.NativeWriteReadiness,
                    NativeWriteEngineState: ResolveNativeWriteEngineState(
                        MountAccessMode.ReadOnly,
                        "Native",
                        hostRuntimeStatus.NativeWriteReadiness,
                        hostRuntimeStatus.RecoveryActive),
                    NativeWriteValidationState: hostRuntimeStatus.NativeWriteValidationState,
                    NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                    WriteIncompatibilities: volume.WriteIncompatibilities,
                    WriteUnsupportedFeatures: volume.WriteUnsupportedFeatures,
                    LastRecoveryAction: hostRuntimeStatus.LastRecoveryAction,
                    DirtyTransactionCount: hostRuntimeStatus.DirtyTransactionCount,
                    ShutdownDrainActive: hostRuntimeStatus.ShutdownDrainActive,
                    InFlightMutationCallbacks: hostRuntimeStatus.InFlightMutationCallbacks,
                    NativeWriteValidationEvidence: nativeWriteValidationEvidence,
                    NativeWriteDiagnostics: BuildNativeWriteDiagnostics(
                        MountAccessMode.ReadOnly,
                        "Native",
                        hostRuntimeStatus.NativeWriteValidationState,
                        requiredValidationState,
                        "CommitModelNotCanonical",
                        hostRuntimeStatus.LastRecoveryAction ?? DeriveLastRecoveryAction("CommitModelNotCanonical", null),
                        nativeWriteValidationEvidence,
                        hostRuntimeStatus.RecoveryActive,
                        failClosedTriggered: true,
                        scope: "Mount",
                        commitStage: hostRuntimeStatus.CommitStage,
                        replayStage: hostRuntimeStatus.ReplayStage,
                        commitBlobMagic: hostRuntimeStatus.CommitBlobMagic,
                        canonicalPathActive: hostRuntimeStatus.CanonicalPathActive,
                        deviceProfileId: runtimeDeviceProfileId,
                        replayCheckpointCandidatePresent: hostRuntimeStatus.ReplayCheckpointCandidatePresent,
                        replayCheckpointPendingWindow: hostRuntimeStatus.ReplayCheckpointPendingWindow)
                );
            }

            if (requestedNativeWrite &&
                hostRuntimeStatus.FixtureLegacyFallbackActive)
            {
                await StopHostProcessAsync(hostState, CancellationToken.None).ConfigureAwait(false);
                pendingHostState = null;
                WriteWriteSessionMarker(
                    requestedVolumeId: request.VolumeId,
                    requestedAccessMode: request.AccessMode,
                    mountPoint: mountPoint,
                    gateState: "NativeFixtureFallbackActive",
                    diagnosticCode: "NativeWriteFixtureFallbackActive",
                    error: "Native write backend reported fixture legacy fallback active."
                );
                return new MountResult(
                    Success: false,
                    MountPoint: null,
                    Error: "Native write backend is in fixture-fallback mode and cannot mount writable on production media.",
                    EffectiveAccessMode: MountAccessMode.ReadOnly,
                    DiagnosticCode: "NativeWriteFixtureFallbackActive",
                    IsReadOnly: true,
                    WriteEnabled: false,
                    SafetyGateState: "NativeFixtureFallbackActive",
                    WriteBackend: "Native",
                    CommitModel: hostRuntimeStatus.CommitModel,
                    NativeWriteReadiness: hostRuntimeStatus.NativeWriteReadiness,
                    NativeWriteEngineState: ResolveNativeWriteEngineState(
                        MountAccessMode.ReadOnly,
                        "Native",
                        hostRuntimeStatus.NativeWriteReadiness,
                        hostRuntimeStatus.RecoveryActive),
                    NativeWriteValidationState: hostRuntimeStatus.NativeWriteValidationState,
                    NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                    WriteIncompatibilities: volume.WriteIncompatibilities,
                    WriteUnsupportedFeatures: volume.WriteUnsupportedFeatures,
                    LastRecoveryAction: hostRuntimeStatus.LastRecoveryAction,
                    DirtyTransactionCount: hostRuntimeStatus.DirtyTransactionCount,
                    ShutdownDrainActive: hostRuntimeStatus.ShutdownDrainActive,
                    InFlightMutationCallbacks: hostRuntimeStatus.InFlightMutationCallbacks,
                    NativeWriteValidationEvidence: nativeWriteValidationEvidence,
                    NativeWriteDiagnostics: BuildNativeWriteDiagnostics(
                        MountAccessMode.ReadOnly,
                        "Native",
                        hostRuntimeStatus.NativeWriteValidationState,
                        requiredValidationState,
                        "FixtureLegacyFallbackActive",
                        hostRuntimeStatus.LastRecoveryAction ?? DeriveLastRecoveryAction("FixtureLegacyFallbackActive", null),
                        nativeWriteValidationEvidence,
                        hostRuntimeStatus.RecoveryActive,
                        failClosedTriggered: true,
                        scope: "Mount",
                        commitStage: hostRuntimeStatus.CommitStage,
                        replayStage: hostRuntimeStatus.ReplayStage,
                        commitBlobMagic: hostRuntimeStatus.CommitBlobMagic,
                        canonicalPathActive: hostRuntimeStatus.CanonicalPathActive,
                        deviceProfileId: runtimeDeviceProfileId,
                        replayCheckpointCandidatePresent: hostRuntimeStatus.ReplayCheckpointCandidatePresent,
                        replayCheckpointPendingWindow: hostRuntimeStatus.ReplayCheckpointPendingWindow)
                );
            }

            if (requestedNativeWrite &&
                hostRuntimeStatus.UsesScaffoldCommitBlob &&
                !IsFixtureImagePath(volume.DeviceId))
            {
                await StopHostProcessAsync(hostState, CancellationToken.None).ConfigureAwait(false);
                pendingHostState = null;
                WriteWriteSessionMarker(
                    requestedVolumeId: request.VolumeId,
                    requestedAccessMode: request.AccessMode,
                    mountPoint: mountPoint,
                    gateState: "NativeScaffoldCommitBlobActive",
                    diagnosticCode: "NativeWriteScaffoldCommitBlobActive",
                    error: "Native write backend still reports scaffold commit-blob path for non-fixture media."
                );
                return new MountResult(
                    Success: false,
                    MountPoint: null,
                    Error: BuildWriteBlockedMountError("Native write backend is not yet on canonical production commit path for non-fixture media"),
                    EffectiveAccessMode: MountAccessMode.ReadOnly,
                    DiagnosticCode: "NativeWriteScaffoldCommitBlobActive",
                    IsReadOnly: true,
                    WriteEnabled: false,
                    SafetyGateState: "NativeScaffoldCommitBlobActive",
                    WriteBackend: "Native",
                    CommitModel: hostRuntimeStatus.CommitModel,
                    NativeWriteReadiness: hostRuntimeStatus.NativeWriteReadiness,
                    NativeWriteEngineState: ResolveNativeWriteEngineState(
                        MountAccessMode.ReadOnly,
                        "Native",
                        hostRuntimeStatus.NativeWriteReadiness,
                        hostRuntimeStatus.RecoveryActive),
                    NativeWriteValidationState: hostRuntimeStatus.NativeWriteValidationState,
                    NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                    WriteIncompatibilities: volume.WriteIncompatibilities,
                    WriteUnsupportedFeatures: volume.WriteUnsupportedFeatures,
                    LastRecoveryAction: hostRuntimeStatus.LastRecoveryAction,
                    DirtyTransactionCount: hostRuntimeStatus.DirtyTransactionCount,
                    ShutdownDrainActive: hostRuntimeStatus.ShutdownDrainActive,
                    InFlightMutationCallbacks: hostRuntimeStatus.InFlightMutationCallbacks,
                    NativeWriteValidationEvidence: nativeWriteValidationEvidence,
                    NativeWriteDiagnostics: BuildNativeWriteDiagnostics(
                        MountAccessMode.ReadOnly,
                        "Native",
                        hostRuntimeStatus.NativeWriteValidationState,
                        requiredValidationState,
                        "ScaffoldCommitBlobActive",
                        hostRuntimeStatus.LastRecoveryAction ?? DeriveLastRecoveryAction("ScaffoldCommitBlobActive", null),
                        nativeWriteValidationEvidence,
                        hostRuntimeStatus.RecoveryActive,
                        failClosedTriggered: true,
                        scope: "Mount",
                        commitStage: hostRuntimeStatus.CommitStage,
                        replayStage: hostRuntimeStatus.ReplayStage,
                        commitBlobMagic: hostRuntimeStatus.CommitBlobMagic,
                        canonicalPathActive: hostRuntimeStatus.CanonicalPathActive,
                        deviceProfileId: runtimeDeviceProfileId,
                        replayCheckpointCandidatePresent: hostRuntimeStatus.ReplayCheckpointCandidatePresent,
                        replayCheckpointPendingWindow: hostRuntimeStatus.ReplayCheckpointPendingWindow)
                );
            }

            if (requestedNativeWrite &&
                _options.NativeWriteStrictMode &&
                hostRuntimeStatus.NativeWriteReadiness != NativeWriteReadiness.CommitReady)
            {
                await StopHostProcessAsync(hostState, CancellationToken.None).ConfigureAwait(false);
                pendingHostState = null;
                WriteWriteSessionMarker(
                    requestedVolumeId: request.VolumeId,
                    requestedAccessMode: request.AccessMode,
                    mountPoint: mountPoint,
                    gateState: "NativeNotCommitReady",
                    diagnosticCode: "NativeWriteNotCommitReady",
                    error: $"Native write backend readiness was '{hostRuntimeStatus.NativeWriteReadiness}'."
                );
                return new MountResult(
                    Success: false,
                    MountPoint: null,
                    Error: BuildWriteBlockedMountError("Native write backend is not in CommitReady state"),
                    EffectiveAccessMode: MountAccessMode.ReadOnly,
                    DiagnosticCode: "NativeWriteNotCommitReady",
                    IsReadOnly: true,
                    WriteEnabled: false,
                    SafetyGateState: "NativeNotCommitReady",
                    WriteBackend: "Native",
                    CommitModel: hostRuntimeStatus.CommitModel,
                    NativeWriteReadiness: hostRuntimeStatus.NativeWriteReadiness,
                    NativeWriteEngineState: ResolveNativeWriteEngineState(
                        MountAccessMode.ReadOnly,
                        "Native",
                        hostRuntimeStatus.NativeWriteReadiness,
                        hostRuntimeStatus.RecoveryActive),
                    NativeWriteValidationState: hostRuntimeStatus.NativeWriteValidationState,
                    NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                    WriteIncompatibilities: volume.WriteIncompatibilities,
                    WriteUnsupportedFeatures: volume.WriteUnsupportedFeatures,
                    LastRecoveryAction: hostRuntimeStatus.LastRecoveryAction,
                    DirtyTransactionCount: hostRuntimeStatus.DirtyTransactionCount,
                    ShutdownDrainActive: hostRuntimeStatus.ShutdownDrainActive,
                    InFlightMutationCallbacks: hostRuntimeStatus.InFlightMutationCallbacks,
                    NativeWriteValidationEvidence: nativeWriteValidationEvidence,
                    NativeWriteDiagnostics: BuildNativeWriteDiagnostics(
                        MountAccessMode.ReadOnly,
                        "Native",
                        hostRuntimeStatus.NativeWriteValidationState,
                        requiredValidationState,
                        "CommitNotReady",
                        hostRuntimeStatus.LastRecoveryAction ?? DeriveLastRecoveryAction("CommitNotReady", null),
                        nativeWriteValidationEvidence,
                        hostRuntimeStatus.RecoveryActive,
                        failClosedTriggered: true,
                        scope: "Mount",
                        commitStage: hostRuntimeStatus.CommitStage,
                        replayStage: hostRuntimeStatus.ReplayStage,
                        commitBlobMagic: hostRuntimeStatus.CommitBlobMagic,
                        canonicalPathActive: hostRuntimeStatus.CanonicalPathActive,
                        deviceProfileId: runtimeDeviceProfileId,
                        replayCheckpointCandidatePresent: hostRuntimeStatus.ReplayCheckpointCandidatePresent,
                        replayCheckpointPendingWindow: hostRuntimeStatus.ReplayCheckpointPendingWindow)
                );
            }

            var hostBackend = NormalizeWriteBackendName(hostRuntimeStatus.WriteBackend);
            var commitModel = ResolveEffectiveCommitModel(
                request.AccessMode,
                hostBackend,
                hostRuntimeStatus.CommitModel
            );
            var hostWriteEnabled = request.AccessMode == MountAccessMode.ReadWrite &&
                                   !string.Equals(hostBackend, "Disabled", StringComparison.OrdinalIgnoreCase);
            var effectiveAccess = hostWriteEnabled ? MountAccessMode.ReadWrite : MountAccessMode.ReadOnly;
            var writeEnabled = hostWriteEnabled;
            var writeBackend = writeEnabled
                ? hostBackend
                : "Disabled";
            var nativeWriteReadiness = request.AccessMode == MountAccessMode.ReadWrite
                ? hostRuntimeStatus.NativeWriteReadiness
                : NativeWriteReadiness.Unavailable;
            var nativeWriteSafetyState = ResolveEffectiveSafetyState(
                effectiveAccess,
                writeBackend,
                nativeWriteReadiness,
                hostRuntimeStatus.RecoveryActive,
                hostRuntimeStatus.NativeWriteSafetyState
            );
            var nativeWriteEngineState = ResolveNativeWriteEngineState(
                effectiveAccess,
                writeBackend,
                nativeWriteReadiness,
                hostRuntimeStatus.RecoveryActive
            );
            var nativeWriteValidationState = ResolveNativeWriteValidationState(
                request.AccessMode,
                writeBackend,
                commitModel,
                nativeWriteReadiness,
                hostRuntimeStatus.RecoveryActive,
                hostRuntimeStatus.NativeWriteValidationState,
                nativeWriteValidationEvidence
            );
            var writeIncompatibilities = volume.WriteIncompatibilities ?? Array.Empty<string>();
            var writeUnsupportedFeatures = volume.WriteUnsupportedFeatures ?? Array.Empty<string>();
            var validationPolicyFailClosedReason = GetValidationPolicyFailClosedReasonDetailed(
                effectiveAccess,
                writeBackend,
                nativeWriteValidationState,
                requiredValidationState,
                nativeWriteValidationEvidence,
                volume
            );

            if (requestedNativeWrite &&
                string.Equals(writeBackend, "Native", StringComparison.OrdinalIgnoreCase) &&
                validationPolicyFailClosedReason is not null)
            {
                await StopHostProcessAsync(hostState, CancellationToken.None).ConfigureAwait(false);
                pendingHostState = null;

                var promotionPolicy = string.IsNullOrWhiteSpace(_options.NativeWritePromotionPolicy)
                    ? "ScaffoldOnly"
                    : _options.NativeWritePromotionPolicy.Trim();
                var evidence = nativeWriteValidationEvidence;
                var evidenceDetail = BuildValidationEvidenceDiagnosticDetail(
                    volume,
                    requiredValidationState,
                    evidence,
                    validationPolicyFailClosedReason,
                    DateTime.UtcNow);
                var gateState = BuildRecoveryFailClosedGateState(validationPolicyFailClosedReason);
                var diagnosticCode = BuildRecoveryFailClosedDiagnosticCode(validationPolicyFailClosedReason);
                var recoveryExplanation = DescribeRecoveryReason(validationPolicyFailClosedReason);
                var errorMessage = $"Native write validation state '{nativeWriteValidationState}' does not meet " +
                                   $"policy '{promotionPolicy}' requirement '{requiredValidationState}' " +
                                   $"(evidence: {evidenceDetail}, reason={validationPolicyFailClosedReason}; detail={recoveryExplanation}).";

                WriteWriteSessionMarker(
                    requestedVolumeId: request.VolumeId,
                    requestedAccessMode: request.AccessMode,
                    mountPoint: mountPoint,
                    gateState: gateState,
                    diagnosticCode: diagnosticCode,
                    error: errorMessage
                );

                return new MountResult(
                    Success: false,
                    MountPoint: null,
                    Error: BuildWriteBlockedMountError(errorMessage),
                    EffectiveAccessMode: MountAccessMode.ReadOnly,
                    DiagnosticCode: diagnosticCode,
                    IsReadOnly: true,
                    WriteEnabled: false,
                    SafetyGateState: gateState,
                    WriteBackend: "Native",
                    CommitModel: commitModel,
                    NativeWriteReadiness: nativeWriteReadiness,
                    NativeWriteEngineState: ResolveNativeWriteEngineState(
                        MountAccessMode.ReadOnly,
                        "Native",
                        nativeWriteReadiness,
                        hostRuntimeStatus.RecoveryActive),
                    NativeWriteValidationState: nativeWriteValidationState,
                    NativeWriteSafetyState: NativeWriteSafetyState.RecoveryBlocked,
                    WriteIncompatibilities: writeIncompatibilities,
                    WriteUnsupportedFeatures: writeUnsupportedFeatures,
                    LastRecoveryAction: DeriveLastRecoveryAction(validationPolicyFailClosedReason, null),
                    DirtyTransactionCount: hostRuntimeStatus.DirtyTransactionCount,
                    ShutdownDrainActive: hostRuntimeStatus.ShutdownDrainActive,
                    InFlightMutationCallbacks: hostRuntimeStatus.InFlightMutationCallbacks,
                    NativeWriteValidationEvidence: nativeWriteValidationEvidence,
                    NativeWriteDiagnostics: BuildNativeWriteDiagnostics(
                        MountAccessMode.ReadOnly,
                        "Native",
                        nativeWriteValidationState,
                        requiredValidationState,
                        validationPolicyFailClosedReason,
                        DeriveLastRecoveryAction(validationPolicyFailClosedReason, null),
                        nativeWriteValidationEvidence,
                        hostRuntimeStatus.RecoveryActive,
                        failClosedTriggered: true,
                        scope: "Mount",
                        commitStage: hostRuntimeStatus.CommitStage,
                        replayStage: hostRuntimeStatus.ReplayStage,
                        commitBlobMagic: hostRuntimeStatus.CommitBlobMagic,
                        canonicalPathActive: hostRuntimeStatus.CanonicalPathActive,
                        deviceProfileId: runtimeDeviceProfileId,
                        replayCheckpointCandidatePresent: hostRuntimeStatus.ReplayCheckpointCandidatePresent,
                        replayCheckpointPendingWindow: hostRuntimeStatus.ReplayCheckpointPendingWindow)
                );
            }

            var mountDiagnostics = BuildNativeWriteDiagnostics(
                effectiveAccess,
                writeBackend,
                nativeWriteValidationState,
                requiredValidationState,
                hostRuntimeStatus.RecoveryReason,
                hostRuntimeStatus.LastRecoveryAction,
                nativeWriteValidationEvidence,
                hostRuntimeStatus.RecoveryActive,
                failClosedTriggered: false,
                scope: "Mount",
                commitStage: hostRuntimeStatus.CommitStage,
                replayStage: hostRuntimeStatus.ReplayStage,
                commitBlobMagic: hostRuntimeStatus.CommitBlobMagic,
                canonicalPathActive: hostRuntimeStatus.CanonicalPathActive,
                deviceProfileId: runtimeDeviceProfileId,
                replayCheckpointCandidatePresent: hostRuntimeStatus.ReplayCheckpointCandidatePresent,
                replayCheckpointPendingWindow: hostRuntimeStatus.ReplayCheckpointPendingWindow);

            _hosts[mountPoint] = hostState;
            hostRegistered = true;
            pendingHostState = null;
            _mounts[mountPoint] = new MountedVolumeState(
                    volume.VolumeId,
                    mountPoint,
                    effectiveAccess,
                    VolumeName: volume.VolumeName,
                    DeviceId: volume.DeviceId,
                    DeviceDisplayName: ResolveDeviceDisplayName(volume.DeviceId),
                    WriteBackend: writeBackend,
                    CommitModel: commitModel,
                    NativeWriteReadiness: nativeWriteReadiness,
                    NativeWriteEngineState: nativeWriteEngineState,
                    NativeWriteValidationState: nativeWriteValidationState,
                    RecoveryActive: hostRuntimeStatus.RecoveryActive,
                    LastCommitXid: hostRuntimeStatus.LastCommitXid,
                    RecoveryReason: hostRuntimeStatus.RecoveryReason,
                    NativeWriteSafetyState: nativeWriteSafetyState,
                    WriteIncompatibilities: writeIncompatibilities,
                    WriteUnsupportedFeatures: writeUnsupportedFeatures,
                    LastRecoveryAction: hostRuntimeStatus.LastRecoveryAction,
                    DirtyTransactionCount: hostRuntimeStatus.DirtyTransactionCount,
                    ShutdownDrainActive: hostRuntimeStatus.ShutdownDrainActive,
                    InFlightMutationCallbacks: hostRuntimeStatus.InFlightMutationCallbacks,
                    NativeWriteValidationEvidence: nativeWriteValidationEvidence,
                    NativeWriteDiagnostics: mountDiagnostics
                );

            return new MountResult(
                Success: true,
                MountPoint: mountPoint,
                Error: null,
                EffectiveAccessMode: effectiveAccess,
                DiagnosticCode: writeEnabled
                    ? (IsWriteBackendMode(_options.WriteBackendMode, "Native")
                        ? "ExperimentalNativeWriteMount"
                        : "ExperimentalOverlayWriteMount")
                    : request.AccessMode == MountAccessMode.ReadWrite
                        ? "WriteDowngradedToReadOnly"
                        : "DirectReadMount",
                IsReadOnly: !writeEnabled,
                WriteEnabled: writeEnabled,
                SafetyGateState: GetWriteGateState(),
                WriteBackend: writeBackend,
                CommitModel: commitModel,
                NativeWriteReadiness: nativeWriteReadiness,
                NativeWriteEngineState: nativeWriteEngineState,
                NativeWriteValidationState: nativeWriteValidationState,
                NativeWriteSafetyState: nativeWriteSafetyState,
                WriteIncompatibilities: writeIncompatibilities,
                WriteUnsupportedFeatures: writeUnsupportedFeatures,
                LastRecoveryAction: hostRuntimeStatus.LastRecoveryAction,
                DirtyTransactionCount: hostRuntimeStatus.DirtyTransactionCount,
                ShutdownDrainActive: hostRuntimeStatus.ShutdownDrainActive,
                InFlightMutationCallbacks: hostRuntimeStatus.InFlightMutationCallbacks,
                NativeWriteValidationEvidence: nativeWriteValidationEvidence,
                NativeWriteDiagnostics: mountDiagnostics
            );
        }
        catch (Exception ex)
        {
            if (pendingHostState is not null && !hostRegistered)
            {
                await StopHostProcessAsync(pendingHostState, CancellationToken.None).ConfigureAwait(false);
            }

            return new MountResult(
                Success: false,
                MountPoint: null,
                Error: ex.Message,
                EffectiveAccessMode: MountAccessMode.ReadOnly,
                DiagnosticCode: "FsHostStartFailed",
                IsReadOnly: true,
                WriteEnabled: false,
                SafetyGateState: "HostStartFailed"
            );
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(mountPoint))
        {
            return new UnmountResult(false, mountPoint, "Mount point was not provided.");
        }

        var normalizedMountPoint = NormalizeMountPoint(mountPoint);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            CleanupExitedHosts_NoLock();

            if (!_hosts.TryRemove(normalizedMountPoint, out var hostState))
            {
                if (_mounts.ContainsKey(normalizedMountPoint))
                {
                    var removed = await WaitForDriveRemovalAsync(
                        normalizedMountPoint,
                        TimeSpan.FromSeconds(Math.Clamp(_options.NativeHostStopTimeoutSeconds, 1, 60)),
                        cancellationToken).ConfigureAwait(false);
                    if (removed)
                    {
                        _mounts.TryRemove(normalizedMountPoint, out _);
                        NotifyShellDriveRemoved(normalizedMountPoint);
                        return new UnmountResult(true, normalizedMountPoint, null);
                    }

                    return new UnmountResult(
                        false,
                        normalizedMountPoint,
                        $"Mount point '{normalizedMountPoint}' remained visible after FsHost stopped. Close Explorer windows or files and try eject again."
                    );
                }

                return new UnmountResult(
                    false,
                    normalizedMountPoint,
                    $"Mount point '{normalizedMountPoint}' is not mounted."
                );
            }

            var stopResult = await StopHostProcessAsync(hostState, cancellationToken).ConfigureAwait(false);
            var unmounted = stopResult.ProcessExited && await WaitForDriveRemovalAsync(
                normalizedMountPoint,
                TimeSpan.FromSeconds(Math.Clamp(_options.NativeHostStopTimeoutSeconds, 1, 60)),
                cancellationToken).ConfigureAwait(false);

            if (!unmounted)
            {
                if (!stopResult.ProcessExited)
                {
                    _hosts[normalizedMountPoint] = hostState;
                }

                return new UnmountResult(
                    false,
                    normalizedMountPoint,
                    stopResult.ProcessExited
                        ? $"Mount point '{normalizedMountPoint}' remained visible after FsHost stopped. Close Explorer windows or files and try eject again."
                        : $"FsHost for '{normalizedMountPoint}' did not stop cleanly before timeout."
                );
            }

            _mounts.TryRemove(normalizedMountPoint, out _);
            NotifyShellDriveRemoved(normalizedMountPoint);
            return new UnmountResult(true, normalizedMountPoint, null);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            CleanupExitedHosts_NoLock();
            await RefreshMountedRuntimeState_NoLock(cancellationToken).ConfigureAwait(false);
            return _mounts.Values
                .OrderBy(x => x.MountPoint, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task RefreshMountedRuntimeState_NoLock(CancellationToken cancellationToken)
    {
        foreach (var entry in _hosts.ToArray())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!_mounts.TryGetValue(entry.Key, out var current))
            {
                continue;
            }

            HostRuntimeStatus runtimeStatus;
            try
            {
                runtimeStatus = await ReadHostRuntimeStatusAsync(
                    entry.Value.StatusFilePath,
                    entry.Value.RequestedAccessMode,
                    entry.Value.ConfiguredWriteBackend,
                    RuntimeStatusPollTimeout,
                    cancellationToken
                ).ConfigureAwait(false);
            }
            catch
            {
                continue;
            }

            var normalizedRuntimeBackend = NormalizeWriteBackendName(runtimeStatus.WriteBackend);
            var runtimeAllowsWrite = entry.Value.RequestedAccessMode == MountAccessMode.ReadWrite &&
                                     !string.Equals(normalizedRuntimeBackend, "Disabled", StringComparison.OrdinalIgnoreCase);
            var recoveryFailClosedTriggered = false;
            string? failClosedReason = null;
            string? writeGateDetail = null;
            var runtimeVolumeIsFixtureImage = IsMountedVolumeFixtureImage(current.VolumeId);
            var runtimeStrictNonFixtureScaffoldControls = ResolveEffectiveNonFixtureScaffoldControlsForMountedVolume(current.VolumeId);
            if (runtimeAllowsWrite &&
                string.Equals(normalizedRuntimeBackend, "Native", StringComparison.OrdinalIgnoreCase))
            {
                if (!runtimeVolumeIsFixtureImage &&
                    runtimeStrictNonFixtureScaffoldControls.DisallowScaffoldCommitOnNonFixture &&
                    runtimeStatus.UsesScaffoldCommitBlob)
                {
                    failClosedReason = "ScaffoldCommitBlobActive";
                    runtimeAllowsWrite = false;
                    recoveryFailClosedTriggered = true;
                }
                else if (_options.NativeWriteRequireCanonicalCommit &&
                    runtimeStatus.CommitModel != NativeWriteCommitModel.CanonicalApfsCheckpoint)
                {
                    failClosedReason = "CommitModelNotCanonical";
                    runtimeAllowsWrite = false;
                    recoveryFailClosedTriggered = true;
                }
                else if ((failClosedReason = GetFailClosedReasonForRuntimeStatus(
                    runtimeStatus,
                    _options.NativeWriteRecoveryPolicy,
                    _options.NativeWriteMaxDirtyTransactions,
                    runtimeVolumeIsFixtureImage,
                    runtimeStrictNonFixtureScaffoldControls.DisallowScaffoldCommitOnNonFixture,
                    runtimeStrictNonFixtureScaffoldControls.RejectScaffoldReplayBlobOnNonFixture,
                    runtimeStrictNonFixtureScaffoldControls.RequireCanonicalReplayCandidateOnNonFixture)) is not null)
                {
                    runtimeAllowsWrite = false;
                    recoveryFailClosedTriggered = true;
                }
            }

            if (!recoveryFailClosedTriggered &&
                runtimeAllowsWrite)
            {
                WriteGateDecision writeGateDecision;
                if (TryResolveVolumeForPolicy(current.VolumeId, out var runtimeVolume))
                {
                    writeGateDecision = EvaluateWriteGateDecision(runtimeVolume);
                }
                else
                {
                    writeGateDecision = new WriteGateDecision(
                        AllowWrite: false,
                        GateState: "VolumeUnknown",
                        Reason: $"Volume '{current.VolumeId}' could not be resolved for write-gate evaluation."
                    );
                }

                var writeGateFailClosedReason = GetWriteGateFailClosedReason(
                    MountAccessMode.ReadWrite,
                    normalizedRuntimeBackend,
                    writeGateDecision);
                if (writeGateFailClosedReason is not null)
                {
                    failClosedReason = writeGateFailClosedReason;
                    runtimeAllowsWrite = false;
                    recoveryFailClosedTriggered = true;
                    writeGateDetail = BuildWriteGateDecisionDetail(writeGateDecision);
                }
            }

            var nextAccessMode = current.AccessMode;
            if (nextAccessMode == MountAccessMode.ReadWrite && !runtimeAllowsWrite)
            {
                nextAccessMode = MountAccessMode.ReadOnly;
            }

            var nextWriteBackend = nextAccessMode == MountAccessMode.ReadWrite
                ? normalizedRuntimeBackend
                : "Disabled";
            var nextCommitModel = ResolveEffectiveCommitModel(
                nextAccessMode,
                nextWriteBackend,
                runtimeStatus.CommitModel
            );
            var nextReadiness = entry.Value.RequestedAccessMode == MountAccessMode.ReadWrite
                ? runtimeStatus.NativeWriteReadiness
                : NativeWriteReadiness.Unavailable;
            var nextSafetyState = ResolveEffectiveSafetyState(
                nextAccessMode,
                nextWriteBackend,
                nextReadiness,
                runtimeStatus.RecoveryActive,
                runtimeStatus.NativeWriteSafetyState
            );
            var nextEngineState = ResolveNativeWriteEngineState(
                nextAccessMode,
                nextWriteBackend,
                nextReadiness,
                runtimeStatus.RecoveryActive
            );
            var evidenceVolumeResolved = TryResolveVolumeForPolicy(current.VolumeId, out var evidenceVolume);
            if (!evidenceVolumeResolved)
            {
                evidenceVolume = BuildFallbackVolumeForEvidence(current);
            }
            var validationEvidence = MergeValidationEvidenceFromRuntimeStatus(
                evidenceVolume,
                entry.Value.RequestedAccessMode,
                runtimeStatus,
                ResolveValidationEvidence(evidenceVolume),
                runtimeSessionId: entry.Value.StatusFilePath
            );
            var nextValidationState = ResolveNativeWriteValidationState(
                entry.Value.RequestedAccessMode,
                nextWriteBackend,
                nextCommitModel,
                nextReadiness,
                runtimeStatus.RecoveryActive,
                runtimeStatus.NativeWriteValidationState,
                validationEvidence
            );
            var requiredValidationState = ResolveRequiredValidationStateForPromotionPolicy(_options.NativeWritePromotionPolicy);
            var validationPolicyFailClosedReason = GetValidationPolicyFailClosedReasonDetailed(
                nextAccessMode,
                nextWriteBackend,
                nextValidationState,
                requiredValidationState,
                validationEvidence,
                evidenceVolume
            );
            if (!recoveryFailClosedTriggered &&
                validationPolicyFailClosedReason is not null)
            {
                recoveryFailClosedTriggered = true;
                failClosedReason = validationPolicyFailClosedReason;
                nextAccessMode = MountAccessMode.ReadOnly;
                nextWriteBackend = "Disabled";
                nextCommitModel = ResolveEffectiveCommitModel(
                    nextAccessMode,
                    nextWriteBackend,
                    runtimeStatus.CommitModel
                );
                nextSafetyState = NativeWriteSafetyState.RecoveryBlocked;
                nextEngineState = ResolveNativeWriteEngineState(
                    nextAccessMode,
                    nextWriteBackend,
                    nextReadiness,
                    true
                );
            }

            if (recoveryFailClosedTriggered && current.AccessMode == MountAccessMode.ReadWrite)
            {
                var recoveryGateState = BuildRecoveryFailClosedGateState(failClosedReason);
                var recoveryDiagnosticCode = BuildRecoveryFailClosedDiagnosticCode(failClosedReason);
                var details = new List<string>
                {
                    $"reason={failClosedReason ?? runtimeStatus.RecoveryReason ?? "n/a"}"
                };
                if (IsValidationEvidenceFailClosedReason(failClosedReason))
                {
                    details.Add($"validationState={nextValidationState}");
                    details.Add($"requiredValidationState={requiredValidationState}");
                    var evidence = validationEvidence;
                    details.Add(BuildValidationEvidenceDiagnosticDetail(
                        evidenceVolume,
                        requiredValidationState,
                        evidence,
                        failClosedReason,
                        DateTime.UtcNow));
                }
                if (string.Equals(failClosedReason, "WriteGateBlocked", StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(writeGateDetail))
                {
                    details.Add(writeGateDetail);
                }
                details.Add($"readiness={runtimeStatus.NativeWriteReadiness}");
                details.Add($"recoveryActive={runtimeStatus.RecoveryActive}");
                var detailText = string.Join(", ", details);

                WriteWriteSessionMarker(
                    requestedVolumeId: current.VolumeId,
                    requestedAccessMode: MountAccessMode.ReadWrite,
                    mountPoint: current.MountPoint,
                    gateState: recoveryGateState,
                    diagnosticCode: recoveryDiagnosticCode,
                    error: $"Runtime telemetry downgraded write access to read-only " +
                           $"({detailText})."
                );
            }

            var runtimeDiagnostics = BuildNativeWriteDiagnostics(
                nextAccessMode,
                nextWriteBackend,
                nextValidationState,
                requiredValidationState,
                recoveryFailClosedTriggered
                    ? failClosedReason ?? runtimeStatus.RecoveryReason
                    : runtimeStatus.RecoveryReason,
                recoveryFailClosedTriggered
                    ? runtimeStatus.LastRecoveryAction ?? DeriveLastRecoveryAction(failClosedReason, null)
                    : runtimeStatus.LastRecoveryAction,
                validationEvidence,
                runtimeStatus.RecoveryActive || recoveryFailClosedTriggered,
                failClosedTriggered: recoveryFailClosedTriggered,
                scope: "Runtime",
                commitStage: runtimeStatus.CommitStage,
                replayStage: runtimeStatus.ReplayStage,
                commitBlobMagic: runtimeStatus.CommitBlobMagic,
                canonicalPathActive: runtimeStatus.CanonicalPathActive,
                deviceProfileId: BuildValidationEvidenceProfileId(evidenceVolume),
                replayCheckpointCandidatePresent: runtimeStatus.ReplayCheckpointCandidatePresent,
                replayCheckpointPendingWindow: runtimeStatus.ReplayCheckpointPendingWindow);

            _mounts[entry.Key] = current with
            {
                AccessMode = nextAccessMode,
                WriteBackend = nextWriteBackend,
                CommitModel = nextCommitModel,
                NativeWriteReadiness = nextReadiness,
                NativeWriteEngineState = nextEngineState,
                NativeWriteValidationState = nextValidationState,
                RecoveryActive = runtimeStatus.RecoveryActive || recoveryFailClosedTriggered,
                LastCommitXid = runtimeStatus.LastCommitXid,
                RecoveryReason = recoveryFailClosedTriggered
                    ? failClosedReason ?? runtimeStatus.RecoveryReason
                    : runtimeStatus.RecoveryReason,
                NativeWriteSafetyState = recoveryFailClosedTriggered
                    ? NativeWriteSafetyState.RecoveryBlocked
                    : nextSafetyState,
                LastRecoveryAction = recoveryFailClosedTriggered
                    ? runtimeStatus.LastRecoveryAction ?? DeriveLastRecoveryAction(failClosedReason, null)
                    : runtimeStatus.LastRecoveryAction,
                DirtyTransactionCount = runtimeStatus.DirtyTransactionCount,
                ShutdownDrainActive = runtimeStatus.ShutdownDrainActive,
                InFlightMutationCallbacks = runtimeStatus.InFlightMutationCallbacks,
                NativeWriteValidationEvidence = validationEvidence,
                NativeWriteDiagnostics = runtimeDiagnostics,
            };
        }
    }

    private bool IsMountedVolumeFixtureImage(string? volumeId)
    {
        if (string.IsNullOrWhiteSpace(volumeId))
        {
            return false;
        }

        if (_volumeCache.TryGetValue(volumeId, out var cachedVolume))
        {
            return IsFixtureImagePath(cachedVolume.DeviceId);
        }

        var separatorIndex = volumeId.IndexOf('|');
        if (separatorIndex > 0)
        {
            return IsFixtureImagePath(volumeId[..separatorIndex]);
        }

        return IsFixtureImagePath(volumeId);
    }

    private (bool DisallowScaffoldCommitOnNonFixture, bool RejectScaffoldReplayBlobOnNonFixture, bool RequireCanonicalReplayCandidateOnNonFixture)
        ResolveEffectiveNonFixtureScaffoldControls(string? deviceId)
    {
        // Fail closed when device identity is missing: unknown media should not be
        // allowed to relax non-fixture canonical safety controls.
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return (true, true, true);
        }

        // Raw physical devices always enforce strict canonical-only non-fixture controls.
        if (IsRawPhysicalDevice(deviceId))
        {
            return (true, true, true);
        }

        // Non-fixture production media always enforces strict canonical-only
        // non-fixture controls. Fixture media may use configured relaxations.
        if (!IsFixtureImagePath(deviceId))
        {
            return (true, true, true);
        }

        return (
            _options.NativeWriteDisallowScaffoldCommitOnNonFixture,
            _options.NativeWriteRejectScaffoldReplayBlobOnNonFixture,
            _options.NativeWriteRequireCanonicalReplayCandidateOnNonFixture
        );
    }

    private (bool DisallowScaffoldCommitOnNonFixture, bool RejectScaffoldReplayBlobOnNonFixture, bool RequireCanonicalReplayCandidateOnNonFixture)
        ResolveEffectiveNonFixtureScaffoldControlsForMountedVolume(string? volumeId)
    {
        if (string.IsNullOrWhiteSpace(volumeId))
        {
            return ResolveEffectiveNonFixtureScaffoldControls(null);
        }

        if (_volumeCache.TryGetValue(volumeId, out var cachedVolume))
        {
            return ResolveEffectiveNonFixtureScaffoldControls(cachedVolume.DeviceId);
        }

        var separatorIndex = volumeId.IndexOf('|');
        var deviceId = separatorIndex > 0 ? volumeId[..separatorIndex] : volumeId;
        return ResolveEffectiveNonFixtureScaffoldControls(deviceId);
    }

    private bool ResolveEffectiveAllowLegacyScaffoldForFixtures(string? deviceId)
    {
        // Fail closed for unknown/non-fixture media. Legacy scaffold compatibility
        // is fixture-only and must never be enabled on production paths.
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return false;
        }

        if (IsRawPhysicalDevice(deviceId))
        {
            return false;
        }

        if (!IsFixtureImagePath(deviceId))
        {
            return false;
        }

        return _options.NativeWriteAllowLegacyScaffoldForFixtures;
    }

    public void Dispose()
    {
        foreach (var kvp in _hosts.ToArray())
        {
            if (!_hosts.TryRemove(kvp.Key, out var host))
            {
                continue;
            }

            try
            {
                TrySignalHostStop(host);
                if (!host.Process.HasExited)
                {
                    if (!host.Process.WaitForExit(Math.Clamp(_options.NativeHostStopTimeoutSeconds, 1, 30) * 1000))
                    {
                        host.Process.Kill(entireProcessTree: true);
                        host.Process.WaitForExit(2000);
                    }
                }
            }
            catch
            {
                // Best-effort cleanup.
            }
            finally
            {
                CleanupHostResources(host);
            }
        }

        _mounts.Clear();
        _volumeCache.Clear();
        _gate.Dispose();
    }

    private static string NormalizeMountPoint(char driveLetter)
        => $"{char.ToUpperInvariant(driveLetter)}:\\";

    private static string NormalizeMountPoint(string mountPoint)
    {
        var trimmed = mountPoint.Trim();
        if (trimmed.Length == 0)
        {
            return trimmed;
        }

        var letter = char.ToUpperInvariant(trimmed[0]);
        return $"{letter}:\\";
    }

    private HostProcessState StartHostProcess(VolumeInfo volume, string mountPoint, MountAccessMode accessMode)
    {
        var lifetimeDir = Path.Combine(Path.GetTempPath(), "ApfsAccess", "host-signals");
        var statusDir = Path.Combine(Path.GetTempPath(), "ApfsAccess", "host-status");
        Directory.CreateDirectory(lifetimeDir);
        Directory.CreateDirectory(statusDir);

        var lifetimeFilePath = Path.Combine(
            lifetimeDir,
            $"host_{char.ToUpperInvariant(mountPoint[0])}_{Guid.NewGuid():N}.alive"
        );
        var statusFilePath = Path.Combine(
            statusDir,
            $"host_{char.ToUpperInvariant(mountPoint[0])}_{Guid.NewGuid():N}.status.json"
        );

        File.WriteAllText(lifetimeFilePath, "alive");

        var psi = new ProcessStartInfo
        {
            FileName = _nativeFsHostPath!,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(_nativeFsHostPath!) ?? AppContext.BaseDirectory,
        };
        var mountTarget = ResolveMountTarget(volume);
        psi.ArgumentList.Add("--device");
        psi.ArgumentList.Add(mountTarget.DevicePath);
        if (mountTarget.DeviceOffsetBytes > 0)
        {
            psi.ArgumentList.Add("--device-offset");
            psi.ArgumentList.Add(mountTarget.DeviceOffsetBytes.ToString(CultureInfo.InvariantCulture));
        }
        psi.ArgumentList.Add("--volume");
        psi.ArgumentList.Add(volume.VolumeName);
        psi.ArgumentList.Add("--mount");
        psi.ArgumentList.Add(mountPoint);
        if (accessMode == MountAccessMode.ReadOnly)
        {
            psi.ArgumentList.Add("--readonly");
        }
        else
        {
            psi.ArgumentList.Add("--readwrite");
            psi.ArgumentList.Add("--write-safety-level");
            psi.ArgumentList.Add(_options.WriteSafetyLevel);
            psi.ArgumentList.Add("--write-backend");
            psi.ArgumentList.Add(_options.WriteBackendMode);
            psi.ArgumentList.Add("--write-commit-timeout");
            psi.ArgumentList.Add(Math.Max(1, _options.WriteCommitTimeoutSeconds).ToString());
            psi.ArgumentList.Add("--write-max-dirty-transactions");
            psi.ArgumentList.Add(Math.Max(1, _options.NativeWriteMaxDirtyTransactions).ToString());
            psi.ArgumentList.Add("--write-recovery-policy");
            psi.ArgumentList.Add(_options.NativeWriteRecoveryPolicy);
            psi.ArgumentList.Add("--write-crash-replay-mode");
            psi.ArgumentList.Add(_options.NativeWriteCrashReplayMode);
            psi.ArgumentList.Add("--write-require-canonical-commit");
            psi.ArgumentList.Add(_options.NativeWriteRequireCanonicalCommit ? "true" : "false");
            psi.ArgumentList.Add("--write-integrity-check-on-mount");
            psi.ArgumentList.Add(_options.NativeWriteIntegrityCheckOnMount ? "true" : "false");
            var effectiveAllowLegacyScaffoldForFixtures = ResolveEffectiveAllowLegacyScaffoldForFixtures(volume.DeviceId);
            psi.ArgumentList.Add("--allow-legacy-scaffold-for-fixtures");
            psi.ArgumentList.Add(effectiveAllowLegacyScaffoldForFixtures ? "true" : "false");
            var strictNonFixtureScaffoldControls = ResolveEffectiveNonFixtureScaffoldControls(volume.DeviceId);
            psi.ArgumentList.Add("--write-disallow-scaffold-commit-on-non-fixture");
            psi.ArgumentList.Add(strictNonFixtureScaffoldControls.DisallowScaffoldCommitOnNonFixture ? "true" : "false");
            psi.ArgumentList.Add("--write-reject-scaffold-replay-blob-on-non-fixture");
            psi.ArgumentList.Add(strictNonFixtureScaffoldControls.RejectScaffoldReplayBlobOnNonFixture ? "true" : "false");
            psi.ArgumentList.Add("--write-require-canonical-replay-candidate-on-non-fixture");
            psi.ArgumentList.Add(strictNonFixtureScaffoldControls.RequireCanonicalReplayCandidateOnNonFixture ? "true" : "false");
            var seedCrashFaultPasses = Math.Max(0, _options.NativeWriteEvidenceSeedCrashFaultPasses);
            if (seedCrashFaultPasses > 0)
            {
                psi.ArgumentList.Add("--validation-crash-fault-passes");
                psi.ArgumentList.Add(seedCrashFaultPasses.ToString(CultureInfo.InvariantCulture));
            }

            var seedCrashStageMatrixPasses = Math.Max(0, _options.NativeWriteEvidenceSeedCrashStageMatrixPasses);
            if (seedCrashStageMatrixPasses > 0)
            {
                psi.ArgumentList.Add("--validation-crash-stage-matrix-passes");
                psi.ArgumentList.Add(seedCrashStageMatrixPasses.ToString(CultureInfo.InvariantCulture));
            }

            var seedHardwarePilotPasses = Math.Max(0, _options.NativeWriteEvidenceSeedHardwarePilotPasses);
            if (seedHardwarePilotPasses > 0)
            {
                psi.ArgumentList.Add("--validation-hardware-pilot-passes");
                psi.ArgumentList.Add(seedHardwarePilotPasses.ToString(CultureInfo.InvariantCulture));
            }

            var seedHotUnplugPasses = Math.Max(0, _options.NativeWriteEvidenceSeedHotUnplugPasses);
            if (seedHotUnplugPasses > 0)
            {
                psi.ArgumentList.Add("--validation-hot-unplug-passes");
                psi.ArgumentList.Add(seedHotUnplugPasses.ToString(CultureInfo.InvariantCulture));
            }

            var seedMacOsValidationPasses = Math.Max(0, _options.NativeWriteEvidenceSeedMacOsValidationPasses);
            if (seedMacOsValidationPasses > 0)
            {
                psi.ArgumentList.Add("--validation-macos-validation-passes");
                psi.ArgumentList.Add(seedMacOsValidationPasses.ToString(CultureInfo.InvariantCulture));
            }

            var seedMacOsConsistencyPasses = Math.Max(0, _options.NativeWriteEvidenceSeedMacOsConsistencyPasses);
            if (seedMacOsConsistencyPasses > 0)
            {
                psi.ArgumentList.Add("--validation-macos-consistency-passes");
                psi.ArgumentList.Add(seedMacOsConsistencyPasses.ToString(CultureInfo.InvariantCulture));
            }

            var seedPowerLossReplayPasses = Math.Max(0, _options.NativeWriteEvidenceSeedPowerLossReplayPasses);
            if (seedPowerLossReplayPasses > 0)
            {
                psi.ArgumentList.Add("--validation-power-loss-replay-passes");
                psi.ArgumentList.Add(seedPowerLossReplayPasses.ToString(CultureInfo.InvariantCulture));
            }

            if (_options.NativeWriteEvidenceSeedPowerLossPassVerified)
            {
                psi.ArgumentList.Add("--validation-power-loss-pass-verified");
                psi.ArgumentList.Add("true");
            }

            if (_options.NativeWriteEvidenceSeedLastValidatedUtc.HasValue)
            {
                var normalizedSeedLastValidatedUtc = _options.NativeWriteEvidenceSeedLastValidatedUtc.Value.Kind switch
                {
                    DateTimeKind.Utc => _options.NativeWriteEvidenceSeedLastValidatedUtc.Value,
                    DateTimeKind.Local => _options.NativeWriteEvidenceSeedLastValidatedUtc.Value.ToUniversalTime(),
                    _ => DateTime.SpecifyKind(_options.NativeWriteEvidenceSeedLastValidatedUtc.Value, DateTimeKind.Utc),
                };
                psi.ArgumentList.Add("--validation-last-validated-utc");
                psi.ArgumentList.Add(normalizedSeedLastValidatedUtc.ToString("o", CultureInfo.InvariantCulture));
            }

            var validationProfileId = NormalizeDiagnosticToken(_options.NativeWriteEvidenceSeedLastValidationProfileId) ??
                                      BuildValidationEvidenceProfileId(volume);
            if (!string.IsNullOrWhiteSpace(validationProfileId))
            {
                psi.ArgumentList.Add("--validation-last-profile-id");
                psi.ArgumentList.Add(validationProfileId);
            }
            if (_options.NativeWriteAllowRawPhysicalDevices)
            {
                psi.ArgumentList.Add("--allow-raw-physical-write");
            }
        }
        psi.ArgumentList.Add("--lifetime-file");
        psi.ArgumentList.Add(lifetimeFilePath);
        psi.ArgumentList.Add("--status-file");
        psi.ArgumentList.Add(statusFilePath);

        var process = Process.Start(psi);
        if (process is null)
        {
            throw new InvalidOperationException("Unable to start native mount host process.");
        }

        return new HostProcessState(process, lifetimeFilePath, statusFilePath, accessMode, _options.WriteBackendMode);
    }

    private async Task<HostStopResult> StopHostProcessAsync(HostProcessState host, CancellationToken cancellationToken)
    {
        TrySignalHostStop(host);

        var timeout = TimeSpan.FromSeconds(Math.Clamp(_options.NativeHostStopTimeoutSeconds, 1, 60));
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);

        HostStopResult result;
        try
        {
            if (!host.Process.HasExited)
            {
                await host.Process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
            }

            result = new HostStopResult(ProcessExited: true, ForcedKill: false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            var forcedKill = false;
            try
            {
                if (!host.Process.HasExited)
                {
                    host.Process.Kill(entireProcessTree: true);
                    forcedKill = true;
                    await host.Process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
                }
            }
            catch
            {
                // Best-effort force-kill.
            }

            result = new HostStopResult(ProcessExited: host.Process.HasExited, ForcedKill: forcedKill);
        }
        finally
        {
            if (host.Process.HasExited)
            {
                CleanupHostResources(host);
            }
        }

        return result;
    }

    private static async Task<bool> WaitForMountOrExitAsync(
        Process process,
        string mountPoint,
        string statusFilePath,
        MountAccessMode accessMode,
        string? configuredWriteBackend,
        TimeSpan timeout,
        CancellationToken cancellationToken
    )
    {
        var startedAt = Stopwatch.GetTimestamp();
        var timeoutTicks = timeout.Ticks;

        while (!cancellationToken.IsCancellationRequested)
        {
            if (process.HasExited)
            {
                return false;
            }

            if (IsDriveVisible(mountPoint))
            {
                return true;
            }

            if (await IsHostMountReadyAsync(
                    statusFilePath,
                    accessMode,
                    configuredWriteBackend,
                    cancellationToken
                ).ConfigureAwait(false))
            {
                return true;
            }

            var elapsed = Stopwatch.GetElapsedTime(startedAt);
            if (elapsed.Ticks >= timeoutTicks)
            {
                return false;
            }

            await Task.Delay(250, cancellationToken).ConfigureAwait(false);
        }

        return false;
    }

    private static async Task<bool> WaitForDriveRemovalAsync(
        string mountPoint,
        TimeSpan timeout,
        CancellationToken cancellationToken
    )
    {
        var startedAt = Stopwatch.GetTimestamp();
        var timeoutTicks = timeout.Ticks;

        while (!cancellationToken.IsCancellationRequested)
        {
            if (!IsDriveVisible(mountPoint))
            {
                return true;
            }

            if (Stopwatch.GetElapsedTime(startedAt).Ticks >= timeoutTicks)
            {
                return false;
            }

            await Task.Delay(250, cancellationToken).ConfigureAwait(false);
        }

        return false;
    }

    private static void NotifyShellDriveRemoved(string mountPoint)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var normalized = NormalizeMountPoint(mountPoint);
        if (normalized.Length < 2 || normalized[1] != ':')
        {
            return;
        }

        var letterIndex = char.ToUpperInvariant(normalized[0]) - 'A';
        if (letterIndex is < 0 or >= 26)
        {
            return;
        }

        Win32ShellChangeNotify.NotifyDriveRemoved(letterIndex, normalized);
    }

    private static async Task<bool> IsHostMountReadyAsync(
        string statusFilePath,
        MountAccessMode accessMode,
        string? configuredWriteBackend,
        CancellationToken cancellationToken
    )
    {
        if (string.IsNullOrWhiteSpace(statusFilePath))
        {
            return false;
        }

        var runtimeStatus = await ReadHostRuntimeStatusAsync(
            statusFilePath,
            accessMode,
            configuredWriteBackend,
            timeout: TimeSpan.FromMilliseconds(100),
            cancellationToken
        ).ConfigureAwait(false);

        return runtimeStatus.MountReady;
    }

    private static bool IsDriveVisible(string mountPoint)
    {
        var normalizedMountPoint = NormalizeMountPoint(mountPoint);

        try
        {
            if (DriveInfo.GetDrives()
                .Any(drive => string.Equals(drive.Name, normalizedMountPoint, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }
        catch
        {
            // Fall through to direct Win32 probes below. DriveInfo can lag behind
            // WinFsp drive-letter exposure during mount startup.
        }

        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        return Win32DriveVisibilityProbe.HasRootAttributes(normalizedMountPoint) ||
               Win32DriveVisibilityProbe.HasVolumeInformation(normalizedMountPoint) ||
               Win32DriveVisibilityProbe.HasDosDevice(normalizedMountPoint);
    }

    private static class Win32DriveVisibilityProbe
    {
        private const uint InvalidFileAttributes = 0xFFFFFFFF;
        private const int DosDeviceBufferLength = 4096;

        public static bool HasRootAttributes(string rootPath)
        {
            try
            {
                return GetFileAttributesW(rootPath) != InvalidFileAttributes;
            }
            catch
            {
                return false;
            }
        }

        public static bool HasVolumeInformation(string rootPath)
        {
            try
            {
                return GetVolumeInformationW(
                    rootPath,
                    lpVolumeNameBuffer: null,
                    nVolumeNameSize: 0,
                    lpVolumeSerialNumber: out _,
                    lpMaximumComponentLength: out _,
                    lpFileSystemFlags: out _,
                    lpFileSystemNameBuffer: null,
                    nFileSystemNameSize: 0);
            }
            catch
            {
                return false;
            }
        }

        public static bool HasDosDevice(string rootPath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(rootPath))
                {
                    return false;
                }

                var deviceName = $"{char.ToUpperInvariant(rootPath[0])}:";
                var targetPath = new StringBuilder(DosDeviceBufferLength);
                return QueryDosDeviceW(deviceName, targetPath, targetPath.Capacity) != 0;
            }
            catch
            {
                return false;
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFileAttributesW(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetVolumeInformationW(
            string lpRootPathName,
            StringBuilder? lpVolumeNameBuffer,
            uint nVolumeNameSize,
            out uint lpVolumeSerialNumber,
            out uint lpMaximumComponentLength,
            out uint lpFileSystemFlags,
            StringBuilder? lpFileSystemNameBuffer,
            uint nFileSystemNameSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint QueryDosDeviceW(
            string lpDeviceName,
            StringBuilder lpTargetPath,
            int ucchMax);
    }

    private static class Win32ShellChangeNotify
    {
        private const int ShcneDriveRemoved = 0x00000080;
        private const int ShcneMediaRemoved = 0x00000040;
        private const int ShcneUpdateDir = 0x00001000;
        private const int ShcneAssocChanged = 0x08000000;
        private const uint ShcnfDword = 0x0003;
        private const uint ShcnfPathW = 0x0005;
        private const uint ShcnfIdList = 0x0000;
        private const uint ShcnfFlush = 0x1000;

        public static void NotifyDriveRemoved(int zeroBasedLetterIndex, string rootPath)
        {
            try
            {
                var driveMask = (nint)(1 << zeroBasedLetterIndex);
                SHChangeNotify(ShcneMediaRemoved, ShcnfDword, driveMask, 0);
                SHChangeNotify(ShcneDriveRemoved, ShcnfDword | ShcnfFlush, driveMask, 0);
                SHChangeNotify(ShcneUpdateDir, ShcnfPathW | ShcnfFlush, rootPath, null);
                SHChangeNotify(ShcneAssocChanged, ShcnfIdList, 0, 0);
            }
            catch
            {
                // Best-effort Explorer refresh.
            }
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern void SHChangeNotify(
            int wEventId,
            uint uFlags,
            nint dwItem1,
            nint dwItem2);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern void SHChangeNotify(
            int wEventId,
            uint uFlags,
            string? dwItem1,
            string? dwItem2);
    }

    private static class Win32StorageDescriptor
    {
        private const uint GenericRead = 0x80000000;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint FileShareDelete = 0x00000004;
        private const uint OpenExisting = 3;
        private const uint FileAttributeNormal = 0x00000080;
        private const uint IoctlStorageQueryProperty = 0x002D1400;
        private const int StorageDeviceProperty = 0;
        private const int PropertyStandardQuery = 0;
        private const int DescriptorBufferLength = 4096;

        public static string? TryGetPhysicalDriveDisplayName(string devicePath)
        {
            if (string.IsNullOrWhiteSpace(devicePath) || !OperatingSystem.IsWindows())
            {
                return null;
            }

            var normalizedPath = devicePath.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase)
                ? @"\\.\" + devicePath[4..]
                : devicePath;

            try
            {
                using var handle = CreateFileW(
                    normalizedPath,
                    GenericRead,
                    FileShareRead | FileShareWrite | FileShareDelete,
                    nint.Zero,
                    OpenExisting,
                    FileAttributeNormal,
                    nint.Zero);
                if (handle.IsInvalid)
                {
                    return null;
                }

                var query = new StoragePropertyQuery
                {
                    PropertyId = StorageDeviceProperty,
                    QueryType = PropertyStandardQuery,
                };
                var buffer = new byte[DescriptorBufferLength];
                var success = DeviceIoControl(
                    handle,
                    IoctlStorageQueryProperty,
                    ref query,
                    Marshal.SizeOf<StoragePropertyQuery>(),
                    buffer,
                    buffer.Length,
                    out var bytesReturned,
                    nint.Zero);
                if (!success || bytesReturned < 36)
                {
                    return null;
                }

                var vendor = ReadDescriptorString(buffer, 12);
                var product = ReadDescriptorString(buffer, 16);
                var combined = string.Join(
                    " ",
                    new[] { vendor, product }
                        .Where(static value => !string.IsNullOrWhiteSpace(value))
                        .Select(static value => value!.Trim()))
                    .Trim();
                return string.IsNullOrWhiteSpace(combined) ? null : combined;
            }
            catch
            {
                return null;
            }
        }

        private static string? ReadDescriptorString(byte[] buffer, int offsetFieldIndex)
        {
            if (buffer.Length < offsetFieldIndex + sizeof(uint))
            {
                return null;
            }

            var offset = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offsetFieldIndex, sizeof(uint)));
            if (offset == 0 || offset >= buffer.Length)
            {
                return null;
            }

            var end = (int)offset;
            while (end < buffer.Length && buffer[end] != 0)
            {
                end++;
            }

            if (end <= offset)
            {
                return null;
            }

            return Encoding.ASCII.GetString(buffer, (int)offset, end - (int)offset).Trim();
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StoragePropertyQuery
        {
            public int PropertyId;
            public int QueryType;
            public byte AdditionalParameters;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            nint lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            nint hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            ref StoragePropertyQuery lpInBuffer,
            int nInBufferSize,
            byte[] lpOutBuffer,
            int nOutBufferSize,
            out uint lpBytesReturned,
            nint lpOverlapped);
    }

    private void CleanupExitedHosts_NoLock()
    {
        foreach (var kvp in _hosts.ToArray())
        {
            try
            {
                if (!kvp.Value.Process.HasExited)
                {
                    continue;
                }
            }
            catch
            {
                // Treat disposed process as exited.
            }

            if (_hosts.TryRemove(kvp.Key, out var host))
            {
                if (!_mounts.ContainsKey(kvp.Key) || !IsDriveVisible(kvp.Key))
                {
                    _mounts.TryRemove(kvp.Key, out _);
                }

                CleanupHostResources(host);
            }
        }

        CleanupDetachedMounts_NoLock();
    }

    private void CleanupDetachedMounts_NoLock()
    {
        foreach (var kvp in _mounts.ToArray())
        {
            if (_hosts.ContainsKey(kvp.Key) || IsDriveVisible(kvp.Key))
            {
                continue;
            }

            if (_mounts.TryRemove(kvp.Key, out _))
            {
                NotifyShellDriveRemoved(kvp.Key);
            }
        }
    }

    private static void TrySignalHostStop(HostProcessState host)
    {
        try
        {
            if (File.Exists(host.LifetimeFilePath))
            {
                File.Delete(host.LifetimeFilePath);
            }
        }
        catch
        {
            // Best-effort signaling.
        }
    }

    private static void CleanupHostResources(HostProcessState host)
    {
        try
        {
            host.Process.Dispose();
        }
        catch
        {
            // Best-effort cleanup.
        }

        try
        {
            if (File.Exists(host.LifetimeFilePath))
            {
                File.Delete(host.LifetimeFilePath);
            }
        }
        catch
        {
            // Best-effort cleanup.
        }

        try
        {
            if (File.Exists(host.StatusFilePath))
            {
                File.Delete(host.StatusFilePath);
            }
        }
        catch
        {
            // Best-effort cleanup.
        }
    }

    private static string BuildNativeVolumePath(string deviceId, string volumeName)
        => $@"{deviceId}\ApfsAccess_Volumes\{volumeName}";

    private bool TryBuildVolumeFromId(string volumeId, out VolumeInfo volume)
    {
        volume = default!;
        if (!TryParseVolumeId(volumeId, out var deviceId, out var volumeName))
        {
            return false;
        }

        var writeBackend = (_options.WriteBackendMode ?? string.Empty).Trim();
        var supportsConfiguredWrite = _options.EnableNativeWrite &&
                                      (IsWriteBackendMode(writeBackend, "Overlay") ||
                                       IsWriteBackendMode(writeBackend, "Native"));
        var nativeWriteReadiness = supportsConfiguredWrite
            ? IsWriteBackendMode(writeBackend, "Native")
                ? NativeWriteReadiness.BootstrapReady
                : NativeWriteReadiness.MutationReady
            : NativeWriteReadiness.Unavailable;
        var writeBlockReason = supportsConfiguredWrite
            ? null
            : "Write backend is disabled (set Service.WriteBackendMode=Overlay or Native for experimental write-path testing).";
        var writeIncompatibilities = string.IsNullOrWhiteSpace(writeBlockReason)
            ? Array.Empty<string>()
            : new[] { writeBlockReason };
        var writeUnsupportedFeatures = Array.Empty<string>();

        volume = new VolumeInfo(
            VolumeId: volumeId,
            DeviceId: deviceId,
            VolumeName: volumeName,
            SupportsReadWrite: supportsConfiguredWrite,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: BuildNativeVolumePath(deviceId, volumeName),
            SupportsNativeWrite: supportsConfiguredWrite,
            WriteBlockReason: writeBlockReason,
            WriteIncompatibilities: writeIncompatibilities,
            WriteUnsupportedFeatures: writeUnsupportedFeatures,
            NativeWriteReadiness: nativeWriteReadiness
        );
        return true;
    }

    private static bool TryParseVolumeId(string volumeId, out string deviceId, out string volumeName)
    {
        deviceId = string.Empty;
        volumeName = string.Empty;

        if (string.IsNullOrWhiteSpace(volumeId))
        {
            return false;
        }

        var separatorIndex = volumeId.IndexOf('|');
        if (separatorIndex < 1 || separatorIndex >= volumeId.Length - 1)
        {
            return false;
        }

        deviceId = volumeId[..separatorIndex];
        volumeName = volumeId[(separatorIndex + 1)..];
        return true;
    }

    private VolumeInfo CreateDiscoveredVolumeInfo(string deviceId, DiscoveredVolume discoveredVolume)
    {
        var writeBackend = (_options.WriteBackendMode ?? string.Empty).Trim();
        var writeIncompatibilities = discoveredVolume.WriteIncompatibilities
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var writeUnsupportedFeatures = discoveredVolume.WriteUnsupportedFeatures
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var supportsConfiguredWrite = _options.EnableNativeWrite &&
                                      !discoveredVolume.IsEncrypted &&
                                      writeIncompatibilities.Length == 0 &&
                                      (IsWriteBackendMode(writeBackend, "Overlay") ||
                                       IsWriteBackendMode(writeBackend, "Native"));
        var nativeWriteReadiness = supportsConfiguredWrite
            ? IsWriteBackendMode(writeBackend, "Native")
                ? NativeWriteReadiness.BootstrapReady
                : NativeWriteReadiness.MutationReady
            : NativeWriteReadiness.Unavailable;
        var volumeId = CreateVolumeId(deviceId, discoveredVolume.VolumeName);

        _mountTargetsByVolumeId[volumeId] = discoveredVolume.MountTarget;

        return new VolumeInfo(
            VolumeId: volumeId,
            DeviceId: deviceId,
            VolumeName: discoveredVolume.VolumeName,
            SupportsReadWrite: supportsConfiguredWrite,
            IsEncrypted: discoveredVolume.IsEncrypted,
            SupportsExplorerMount: !discoveredVolume.IsEncrypted,
            NativeVolumePath: discoveredVolume.NativeVolumePath,
            SupportsNativeWrite: supportsConfiguredWrite,
            WriteBlockReason: discoveredVolume.IsEncrypted
                ? "Encrypted APFS write path is not supported in this release."
                : writeIncompatibilities.Length > 0
                    ? string.Join(" ", writeIncompatibilities)
                    : supportsConfiguredWrite
                        ? null
                        : "Write backend is disabled (set Service.WriteBackendMode=Overlay or Native for experimental write-path testing).",
            WriteIncompatibilities: writeIncompatibilities,
            WriteUnsupportedFeatures: writeUnsupportedFeatures,
            NativeWriteReadiness: nativeWriteReadiness
        );
    }

    private async Task<VolumeInfo?> ResolveVolumeAsync(string volumeId, CancellationToken cancellationToken)
    {
        if (_volumeCache.TryGetValue(volumeId, out var cachedVolume))
        {
            return cachedVolume;
        }

        if (!TryParseVolumeId(volumeId, out var deviceId, out _))
        {
            return null;
        }

        var discoveredVolumes = await ProbeVolumesAsync(deviceId, cancellationToken).ConfigureAwait(false);
        var discoveredVolume = discoveredVolumes.FirstOrDefault(volume =>
            string.Equals(volume.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase));
        if (discoveredVolume is not null)
        {
            return discoveredVolume;
        }

        return TryBuildVolumeFromId(volumeId, out var fallbackVolume)
            ? fallbackVolume
            : null;
    }

    private VolumeMountTarget ResolveMountTarget(VolumeInfo volume)
    {
        if (_mountTargetsByVolumeId.TryGetValue(volume.VolumeId, out var mountTarget))
        {
            return mountTarget;
        }

        return new VolumeMountTarget(volume.DeviceId, 0);
    }

    private DiscoveredDevice? DiscoverDevice(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return null;
        }

        var discoveredVolumes = DiscoverVolumes(deviceId);
        if (discoveredVolumes.Count == 0)
        {
            return null;
        }

        var displayName = IsRawPhysicalDevicePath(deviceId)
            ? BuildDeviceDisplayName(deviceId)
            : $"APFS Image ({Path.GetFileName(deviceId)})";

        return new DiscoveredDevice(deviceId, displayName, discoveredVolumes);
    }

    private string ResolveDeviceDisplayName(string deviceId)
    {
        if (_deviceDisplayNameById.TryGetValue(deviceId, out var cached) &&
            !string.IsNullOrWhiteSpace(cached))
        {
            return cached;
        }

        var resolved = BuildDeviceDisplayName(deviceId);
        _deviceDisplayNameById[deviceId] = resolved;
        return resolved;
    }

    private static string BuildDeviceDisplayName(string deviceId)
    {
        if (!IsRawPhysicalDevicePath(deviceId))
        {
            var fileName = Path.GetFileName(deviceId);
            return string.IsNullOrWhiteSpace(fileName)
                ? $"APFS Image ({deviceId})"
                : $"APFS Image ({fileName})";
        }

        var storageDescriptorName = Win32StorageDescriptor.TryGetPhysicalDriveDisplayName(deviceId);
        return string.IsNullOrWhiteSpace(storageDescriptorName)
            ? $"APFS Device ({deviceId})"
            : storageDescriptorName;
    }

    private IReadOnlyList<DiscoveredVolume> DiscoverVolumes(string deviceId)
    {
        var discoveredVolumes = new List<DiscoveredVolume>();
        var usedVolumeNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (TryReadApfsContainerHeader(deviceId, 0, out _))
        {
            discoveredVolumes.Add(new DiscoveredVolume(
                VolumeName: DefaultMainVolumeName,
                IsEncrypted: false,
                WriteIncompatibilities: Array.Empty<string>(),
                WriteUnsupportedFeatures: Array.Empty<string>(),
                NativeVolumePath: BuildNativeVolumePath(deviceId, DefaultMainVolumeName),
                MountTarget: new VolumeMountTarget(deviceId, 0)));
            return discoveredVolumes;
        }

        if (!TryReadGptPartitions(deviceId, out var partitions))
        {
            return discoveredVolumes;
        }

        var apfsPartitions = partitions
            .Where(partition => partition.PartitionTypeGuid == ApfsPartitionTypeGuid)
            .Where(partition => TryReadApfsContainerHeader(deviceId, partition.StartOffsetBytes, out _))
            .ToArray();

        foreach (var partition in apfsPartitions)
        {
            var baseName = NormalizeDiscoveredVolumeName(
                partition.PartitionName,
                allowDefaultMain: apfsPartitions.Length == 1,
                partitionNumber: partition.PartitionNumber);
            var volumeName = baseName;
            for (var suffix = 2; !usedVolumeNames.Add(volumeName); suffix++)
            {
                volumeName = $"{baseName}_{suffix}";
            }

            discoveredVolumes.Add(new DiscoveredVolume(
                VolumeName: volumeName,
                IsEncrypted: false,
                WriteIncompatibilities: Array.Empty<string>(),
                WriteUnsupportedFeatures: Array.Empty<string>(),
                NativeVolumePath: BuildNativeVolumePath(deviceId, volumeName),
                MountTarget: new VolumeMountTarget(deviceId, partition.StartOffsetBytes)));
        }

        return discoveredVolumes;
    }

    private static string NormalizeDiscoveredVolumeName(string? rawName, bool allowDefaultMain, int partitionNumber)
    {
        var sanitized = (rawName ?? string.Empty)
            .Replace('|', '_')
            .Trim();

        if (!string.IsNullOrWhiteSpace(sanitized))
        {
            return sanitized;
        }

        return allowDefaultMain
            ? DefaultMainVolumeName
            : $"Partition{partitionNumber}";
    }

    private static bool TryReadGptPartitions(string deviceId, out IReadOnlyList<GptPartitionInfo> partitions)
    {
        foreach (var sectorSize in ProbeSectorSizes)
        {
            if (!TryReadBytes(deviceId, (ulong)sectorSize, sectorSize, out var header) || header.Length < 92)
            {
                continue;
            }

            if (!header.AsSpan(0, 8).SequenceEqual("EFI PART"u8))
            {
                continue;
            }

            var partitionEntryCount = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(80, 4));
            var partitionEntrySize = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(84, 4));
            if (partitionEntryCount == 0 || partitionEntrySize is < 128 or > 4096)
            {
                continue;
            }

            var cappedEntryCount = (int)Math.Min(partitionEntryCount, (uint)MaxGptEntriesToRead);
            var entryBlockLength = checked(cappedEntryCount * (int)partitionEntrySize);
            var partitionEntryLba = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(72, 8));
            var partitionEntryOffsetBytes = checked(partitionEntryLba * (ulong)sectorSize);
            if (!TryReadBytes(deviceId, partitionEntryOffsetBytes, entryBlockLength, out var entriesBlock))
            {
                continue;
            }

            var discoveredPartitions = new List<GptPartitionInfo>();
            for (var index = 0; index < cappedEntryCount; index++)
            {
                var entryOffset = index * (int)partitionEntrySize;
                var entry = entriesBlock.AsSpan(entryOffset, (int)partitionEntrySize);
                var hasPartitionTypeGuid = false;
                for (var typeIndex = 0; typeIndex < 16; typeIndex++)
                {
                    if (entry[typeIndex] != 0)
                    {
                        hasPartitionTypeGuid = true;
                        break;
                    }
                }

                if (!hasPartitionTypeGuid)
                {
                    continue;
                }

                var typeGuid = new Guid(entry[..16]);
                var startLba = BinaryPrimitives.ReadUInt64LittleEndian(entry.Slice(32, 8));
                var endLba = BinaryPrimitives.ReadUInt64LittleEndian(entry.Slice(40, 8));
                if (startLba == 0 || endLba < startLba)
                {
                    continue;
                }

                var name = Encoding.Unicode.GetString(entry.Slice(56, 72)).TrimEnd('\0', ' ');
                discoveredPartitions.Add(new GptPartitionInfo(
                    PartitionNumber: index + 1,
                    PartitionTypeGuid: typeGuid,
                    StartOffsetBytes: checked(startLba * (ulong)sectorSize),
                    PartitionName: name));
            }

            partitions = discoveredPartitions;
            return true;
        }

        partitions = Array.Empty<GptPartitionInfo>();
        return false;
    }

    private static bool TryReadApfsContainerHeader(string deviceId, ulong offsetBytes, out ApfsContainerHeader? header)
    {
        header = default;

        if (!TryReadBytes(deviceId, offsetBytes, 4096, out var primaryBlock) || primaryBlock.Length < 0xA8)
        {
            return false;
        }

        if (!TryParseApfsContainerHeader(primaryBlock, out var parsedHeader) || parsedHeader is null)
        {
            return false;
        }

        header = parsedHeader;
        if (header.BlockSize > 0 &&
            TryReadBytes(deviceId, checked(offsetBytes + header.BlockSize), 4096, out var secondaryBlock) &&
            secondaryBlock.Length >= 0xA8 &&
            TryParseApfsContainerHeader(secondaryBlock, out var secondaryHeader) &&
            secondaryHeader is not null &&
            secondaryHeader.BlockSize == header.BlockSize &&
            secondaryHeader.TotalBlocks == header.TotalBlocks &&
            secondaryHeader.VolumeRootBlock == header.VolumeRootBlock &&
            secondaryHeader.CheckpointXid > header.CheckpointXid)
        {
            header = secondaryHeader;
        }

        return true;
    }

    private static bool TryParseApfsContainerHeader(byte[] block, out ApfsContainerHeader? header)
    {
        header = default;
        if (block.Length < 0xA8)
        {
            return false;
        }

        const uint nxsbMagic = 0x4253584E;
        var magic = BinaryPrimitives.ReadUInt32LittleEndian(block.AsSpan(0x20, 4));
        var blockSize = BinaryPrimitives.ReadUInt32LittleEndian(block.AsSpan(0x24, 4));
        var totalBlocks = BinaryPrimitives.ReadUInt64LittleEndian(block.AsSpan(0x28, 8));
        var checkpointXid = BinaryPrimitives.ReadUInt64LittleEndian(block.AsSpan(0x10, 8));
        var volumeRootBlock = BinaryPrimitives.ReadUInt64LittleEndian(block.AsSpan(0xA0, 8));

        if (magic != nxsbMagic ||
            blockSize is 0 or > (1 << 20) ||
            totalBlocks == 0 ||
            volumeRootBlock == 0)
        {
            return false;
        }

        header = new ApfsContainerHeader(blockSize, totalBlocks, checkpointXid, volumeRootBlock);
        return true;
    }

    private static bool TryReadBytes(string path, ulong offsetBytes, int length, out byte[] buffer)
    {
        buffer = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(path) || length <= 0 || offsetBytes > long.MaxValue)
        {
            return false;
        }

        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: Math.Min(length, 64 * 1024),
                FileOptions.RandomAccess);
            stream.Seek((long)offsetBytes, SeekOrigin.Begin);

            buffer = new byte[length];
            var totalRead = 0;
            while (totalRead < length)
            {
                var read = stream.Read(buffer, totalRead, length - totalRead);
                if (read <= 0)
                {
                    break;
                }

                totalRead += read;
            }

            if (totalRead == buffer.Length)
            {
                return true;
            }

            Array.Resize(ref buffer, totalRead);
            return totalRead > 0;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool IsRawPhysicalDevicePath(string path)
        => !string.IsNullOrWhiteSpace(path) &&
           (path.StartsWith(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"\\?\PhysicalDrive", StringComparison.OrdinalIgnoreCase));

    private static bool IsSuccessForCommand(string stdout, string commandName)
    {
        if (string.IsNullOrWhiteSpace(stdout))
        {
            return false;
        }

        foreach (Match match in SuccessRegexTemplate.Matches(stdout))
        {
            var cmd = match.Groups["cmd"].Value;
            if (string.Equals(cmd, commandName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static List<ParsedVolumeRow> ParseVolumeRows(string stdout)
    {
        var rows = new List<ParsedVolumeRow>();
        if (string.IsNullOrWhiteSpace(stdout))
        {
            return rows;
        }

        var lines = stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        var collecting = false;

        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.StartsWith("Volumes", StringComparison.OrdinalIgnoreCase))
            {
                collecting = true;
                continue;
            }

            if (!collecting)
            {
                continue;
            }

            if (line.StartsWith("APFS:", StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            var isEncrypted = line.Contains("encrypted", StringComparison.OrdinalIgnoreCase) ||
                              line.Contains("locked", StringComparison.OrdinalIgnoreCase);
            var writeUnsupportedFeatures = ParseWriteUnsupportedFeaturesFromLine(line, isEncrypted);
            var writeIncompatibilities = BuildWriteIncompatibilities(writeUnsupportedFeatures);

            var quotedTokens = VolumeTokenRegex.Matches(line)
                .Select(match => match.Groups[1].Success ? match.Groups[1].Value.Trim() : string.Empty)
                .Where(static token => !string.IsNullOrWhiteSpace(token))
                .ToArray();

            if (quotedTokens.Length > 0)
            {
                foreach (var token in quotedTokens)
                {
                    if (ShouldSkipVolumeToken(token))
                    {
                        continue;
                    }

                    rows.Add(new ParsedVolumeRow(
                        Name: token,
                        IsEncrypted: isEncrypted,
                        WriteIncompatibilities: writeIncompatibilities,
                        WriteUnsupportedFeatures: writeUnsupportedFeatures));
                }

                continue;
            }

            var candidateSegment = ExtractUnquotedVolumeNameCandidate(line);
            if (string.IsNullOrWhiteSpace(candidateSegment))
            {
                continue;
            }

            if (!ShouldSkipVolumeToken(candidateSegment))
            {
                rows.Add(new ParsedVolumeRow(
                    Name: candidateSegment,
                    IsEncrypted: isEncrypted,
                    WriteIncompatibilities: writeIncompatibilities,
                    WriteUnsupportedFeatures: writeUnsupportedFeatures));
            }
        }

        return rows;
    }

    private static string ExtractUnquotedVolumeNameCandidate(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return string.Empty;
        }

        var candidate = line.Trim();
        candidate = IndexedVolumePrefixRegex.Replace(candidate, string.Empty);

        var separatorIndex = candidate.IndexOf(':');
        if (separatorIndex >= 0 && separatorIndex < candidate.Length - 1)
        {
            candidate = candidate[(separatorIndex + 1)..];
        }

        candidate = VolumeInlineAnnotationRegex.Replace(candidate, " ");
        candidate = TrimTrailingMetadataTokens(candidate);
        candidate = WhitespaceCollapseRegex.Replace(candidate, " ").Trim().Trim('"', '\'');
        return candidate;
    }

    private static string TrimTrailingMetadataTokens(string candidate)
    {
        var normalized = candidate.Trim();
        normalized = RoleAssignmentSpacingRegex.Replace(normalized, "role=");
        while (!string.IsNullOrEmpty(normalized))
        {
            var changed = false;
            var roleTrimmed = TrailingRoleTokenRegex.Replace(normalized, string.Empty).TrimEnd(' ', '\t', ',', ';', ':', '-');
            if (!ReferenceEquals(roleTrimmed, normalized) &&
                !string.Equals(roleTrimmed, normalized, StringComparison.Ordinal))
            {
                normalized = roleTrimmed;
                changed = true;
            }

            if (changed)
            {
                continue;
            }

            foreach (var token in TrailingVolumeMetadataTokens)
            {
                if (!normalized.EndsWith(token, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (normalized.Length == token.Length)
                {
                    return string.Empty;
                }

                var prefix = normalized[..(normalized.Length - token.Length)];
                if (prefix.Length == 0 || !char.IsWhiteSpace(prefix[^1]))
                {
                    continue;
                }

                normalized = prefix.TrimEnd(' ', '\t', ',', ';', ':', '-');
                changed = true;
                break;
            }

            if (!changed)
            {
                break;
            }
        }

        return normalized;
    }

    private static bool ShouldSkipVolumeToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return true;
        }

        var value = token.Trim().Trim('"', '\'');
        if (value.Length == 0)
        {
            return true;
        }

        if (value.Equals("Volumes", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("Volume", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("encrypted", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("locked", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (value.EndsWith(':') ||
            value.StartsWith("APFS", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (value[0] is '[' or '(' or '-' or '*' or ':')
        {
            return true;
        }

        if (value.Any(ch => ch is '[' or ']' or '{' or '}' or '='))
        {
            return true;
        }

        if (value.All(char.IsDigit))
        {
            return true;
        }

        return false;
    }

    private static IReadOnlyList<string> ParseWriteUnsupportedFeaturesFromLine(string line, bool isEncrypted)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return Array.Empty<string>();
        }

        var features = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (isEncrypted)
        {
            features.Add("Encrypted");
        }

        if (line.Contains("snapshot", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("clone", StringComparison.OrdinalIgnoreCase))
        {
            features.Add("SnapshotOrClone");
        }

        if (line.Contains("case-sensitive", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("casesensitive", StringComparison.OrdinalIgnoreCase))
        {
            features.Add("CaseSensitive");
        }

        if (line.Contains("sealed", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("system volume", StringComparison.OrdinalIgnoreCase) ||
            ContainsRoleValue(line, "system"))
        {
            features.Add("SealedSystemVolume");
        }

        if (line.Contains("fusion", StringComparison.OrdinalIgnoreCase))
        {
            features.Add("FusionBacked");
        }

        if (line.Contains("read-only", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("readonly", StringComparison.OrdinalIgnoreCase))
        {
            features.Add("VolumeReadOnly");
        }

        if (ContainsRoleValue(line, "preboot") ||
            ContainsRoleValue(line, "recovery") ||
            ContainsRoleValue(line, "vm"))
        {
            features.Add("RolePrebootRecoveryVm");
        }

        return features
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static IReadOnlyList<string> BuildWriteIncompatibilities(IReadOnlyList<string> unsupportedFeatures)
    {
        if (unsupportedFeatures.Count == 0)
        {
            return Array.Empty<string>();
        }

        var issues = new List<string>(unsupportedFeatures.Count);
        foreach (var feature in unsupportedFeatures)
        {
            switch (feature)
            {
                case "Encrypted":
                    issues.Add("Encrypted APFS write support is not available in this release.");
                    break;
                case "SnapshotOrClone":
                    issues.Add("Snapshot/clone mutation semantics are not supported in v1 native write mode.");
                    break;
                case "CaseSensitive":
                    issues.Add("Case-sensitive APFS volumes are not supported in v1 native write mode.");
                    break;
                case "SealedSystemVolume":
                    issues.Add("Sealed/system APFS volumes are not writable in this release.");
                    break;
                case "FusionBacked":
                    issues.Add("Fusion-backed APFS containers are not supported in v1 native write mode.");
                    break;
                case "VolumeReadOnly":
                    issues.Add("Volume is marked read-only and cannot be mounted writable.");
                    break;
                case "RolePrebootRecoveryVm":
                    issues.Add("Special-role APFS volumes (preboot/recovery/vm) are not writable in this release.");
                    break;
                default:
                    issues.Add($"Unsupported APFS write feature: {feature}.");
                    break;
            }
        }

        return issues
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static bool ContainsRoleValue(string line, string role)
    {
        if (string.IsNullOrWhiteSpace(line) || string.IsNullOrWhiteSpace(role))
        {
            return false;
        }

        var normalized = WhitespaceCollapseRegex.Replace(line, " ").Trim();
        var roleToken = $"role={role}";
        var roleTokenWithSpace = $"role = {role}";
        var rolePhrase = $"role {role}";
        return normalized.Contains(roleToken, StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains(roleTokenWithSpace, StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains(rolePhrase, StringComparison.OrdinalIgnoreCase);
    }

    private static string CreateVolumeId(string deviceId, string volumeName)
        => $"{deviceId}|{volumeName}";

    private static string? ResolveNativeFsHostPath(ServiceHostOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.NativeFsHostPath))
        {
            var configured = Path.GetFullPath(options.NativeFsHostPath);
            if (File.Exists(configured))
            {
                return configured;
            }
        }

        var envPath = Environment.GetEnvironmentVariable("APFSACCESS_FS_HOST_PATH");
        if (!string.IsNullOrWhiteSpace(envPath))
        {
            var fromEnv = Path.GetFullPath(envPath);
            if (File.Exists(fromEnv))
            {
                return fromEnv;
            }
        }

        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "ApfsAccess.FsHost.exe"),
            Path.Combine(AppContext.BaseDirectory, "native", "ApfsAccess.FsHost.exe"),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "native", "ApfsAccess.FsHost.exe")),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "artifacts", "native", "Release", "ApfsAccess.FsHost.exe")),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "artifacts", "native", "Debug", "ApfsAccess.FsHost.exe")),
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    private static IReadOnlyList<string> BuildDeviceCandidates(ServiceHostOptions options)
    {
        var values = new List<string>();

        if (options.NativeDeviceCandidates is { Length: > 0 })
        {
            values.AddRange(options.NativeDeviceCandidates.Where(x => !string.IsNullOrWhiteSpace(x)));
        }

        if (options.NativeAutoDiscoverPhysicalDrives)
        {
            var maxIndex = Math.Clamp(options.NativeMaxPhysicalDriveIndex, 0, 128);
            for (var i = 0; i <= maxIndex; i++)
            {
                values.Add($@"\\.\PhysicalDrive{i}");
            }
        }

        return values
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private string GetWriteGateState()
    {
        return WriteGatePolicy.EvaluateForRequest(_options).GateState;
    }

    private WriteGateDecision EvaluateWriteGateDecision(VolumeInfo volume)
    {
        return WriteGatePolicy.EvaluateForVolume(_options, volume);
    }

    private bool TryResolveVolumeForPolicy(string volumeId, out VolumeInfo volume)
    {
        if (_volumeCache.TryGetValue(volumeId, out var cachedVolume) &&
            cachedVolume is not null)
        {
            volume = cachedVolume;
            return true;
        }

        return TryBuildVolumeFromId(volumeId, out volume);
    }

    private static VolumeInfo BuildFallbackVolumeForEvidence(MountedVolumeState current)
    {
        if (TryParseVolumeId(current.VolumeId, out var deviceId, out var volumeName))
        {
            return new VolumeInfo(
                VolumeId: current.VolumeId,
                DeviceId: deviceId,
                VolumeName: volumeName,
                SupportsReadWrite: true,
                IsEncrypted: false,
                SupportsExplorerMount: true,
                NativeVolumePath: BuildNativeVolumePath(deviceId, volumeName),
                SupportsNativeWrite: true,
                WriteBlockReason: null,
                WriteIncompatibilities: Array.Empty<string>(),
                WriteUnsupportedFeatures: Array.Empty<string>(),
                NativeWriteReadiness: current.NativeWriteReadiness
            );
        }

        return new VolumeInfo(
            VolumeId: current.VolumeId,
            DeviceId: current.VolumeId,
            VolumeName: current.VolumeId,
            SupportsReadWrite: true,
            IsEncrypted: false,
            SupportsExplorerMount: true,
            NativeVolumePath: current.VolumeId,
            SupportsNativeWrite: true,
            WriteBlockReason: null,
            WriteIncompatibilities: Array.Empty<string>(),
            WriteUnsupportedFeatures: Array.Empty<string>(),
            NativeWriteReadiness: current.NativeWriteReadiness
        );
    }

    private NativeWriteSafetyState ResolveEffectiveSafetyState(
        MountAccessMode accessMode,
        string writeBackend,
        NativeWriteReadiness readiness,
        bool recoveryActive,
        NativeWriteSafetyState hostState
    )
    {
        if (hostState == NativeWriteSafetyState.RecoveryBlocked)
        {
            return NativeWriteSafetyState.RecoveryBlocked;
        }

        var derivedState = DeriveSafetyState(
            accessMode,
            writeBackend,
            readiness,
            recoveryActive,
            hostState
        );

        if (derivedState == NativeWriteSafetyState.PilotReadWrite &&
            string.Equals(_options.WriteRolloutChannel, "Enabled", StringComparison.OrdinalIgnoreCase))
        {
            return NativeWriteSafetyState.StableReadWrite;
        }

        return derivedState;
    }

    private NativeWriteEngineState ResolveNativeWriteEngineState(
        MountAccessMode accessMode,
        string writeBackend,
        NativeWriteReadiness readiness,
        bool recoveryActive
    )
    {
        if (accessMode != MountAccessMode.ReadWrite ||
            !string.Equals(writeBackend, "Native", StringComparison.OrdinalIgnoreCase))
        {
            return NativeWriteEngineState.Scaffold;
        }

        if (recoveryActive || readiness is NativeWriteReadiness.Degraded or NativeWriteReadiness.RecoveryMode)
        {
            return NativeWriteEngineState.Transactional;
        }

        var promotionPolicy = (_options.NativeWritePromotionPolicy ?? string.Empty).Trim();
        if (string.Equals(promotionPolicy, "Stable", StringComparison.OrdinalIgnoreCase))
        {
            return NativeWriteEngineState.Stable;
        }

        if (string.Equals(promotionPolicy, "PilotHardware", StringComparison.OrdinalIgnoreCase))
        {
            return NativeWriteEngineState.HardwareValidated;
        }

        return readiness switch
        {
            NativeWriteReadiness.CommitReady => NativeWriteEngineState.Transactional,
            NativeWriteReadiness.MutationReady => NativeWriteEngineState.Transactional,
            _ => NativeWriteEngineState.Scaffold,
        };
    }

    private NativeWriteValidationState ResolveNativeWriteValidationState(
        MountAccessMode accessMode,
        string writeBackend,
        NativeWriteCommitModel commitModel,
        NativeWriteReadiness readiness,
        bool recoveryActive,
        NativeWriteValidationState reportedState,
        NativeWriteValidationEvidence? validationEvidence
    )
    {
        if (accessMode != MountAccessMode.ReadWrite ||
            !string.Equals(writeBackend, "Native", StringComparison.OrdinalIgnoreCase))
        {
            return NativeWriteValidationState.Scaffold;
        }

        var evidence = NormalizeValidationEvidence(validationEvidence);
        var canonicalValidationEligible = IsCanonicalValidationEligible(
            commitModel,
            readiness,
            recoveryActive);
        var effective = ClampReportedValidationState(
            reportedState,
            commitModel,
            readiness,
            recoveryActive);
        if (effective == NativeWriteValidationState.Scaffold &&
            canonicalValidationEligible)
        {
            effective = NativeWriteValidationState.CanonicalImageValidated;
        }

        var meetsCrashFaultThreshold = !(_options.NativeWriteCrashFaultMatrixRequired) ||
                                       evidence.CrashFaultPasses >= Math.Max(0, _options.NativeWriteMinCrashFaultPasses);
        var meetsCrashStageMatrixThreshold = evidence.CrashStageMatrixPasses >= Math.Max(0, _options.NativeWriteMinCrashStageMatrixPasses);
        var meetsHardwarePilotThreshold = evidence.HardwarePilotPasses >= Math.Max(0, _options.NativeWriteMinHardwarePilotPasses);
        var meetsHotUnplugThreshold = evidence.HotUnplugPasses >= Math.Max(0, _options.NativeWriteMinHotUnplugPasses);
        var meetsCrossOsThreshold = !_options.NativeWriteCrossOsValidationRequired ||
                                    evidence.MacOsValidationPasses >= Math.Max(0, _options.NativeWriteMinMacOsValidationPasses);
        var meetsMacOsConsistencyThreshold = evidence.MacOsConsistencyPasses >= Math.Max(0, _options.NativeWriteMinMacOsConsistencyPasses);
        var meetsMacOsStableThreshold = !_options.NativeWriteRequireMacOsValidationForStable ||
                                        evidence.MacOsValidationPasses >= Math.Max(0, _options.NativeWriteMinMacOsValidationPasses);
        var meetsPowerLossReplayThreshold = !_options.NativeWriteStableRequiresPowerLossPass ||
                                            evidence.PowerLossReplayPasses >= Math.Max(0, _options.NativeWriteMinPowerLossReplayPasses);
        var meetsPowerLossThreshold = !_options.NativeWriteStableRequiresPowerLossPass ||
                                      evidence.PowerLossPassVerified;

        var promotionPolicy = (_options.NativeWritePromotionPolicy ?? string.Empty).Trim();
        NativeWriteValidationState ceiling;
        if (string.Equals(promotionPolicy, "ScaffoldOnly", StringComparison.OrdinalIgnoreCase))
        {
            ceiling = NativeWriteValidationState.CanonicalImageValidated;
        }
        else if (string.Equals(promotionPolicy, "PilotHardware", StringComparison.OrdinalIgnoreCase))
        {
            ceiling = meetsCrashFaultThreshold &&
                      meetsCrashStageMatrixThreshold &&
                      meetsHardwarePilotThreshold &&
                      meetsHotUnplugThreshold
                ? NativeWriteValidationState.HardwarePilotValidated
                : NativeWriteValidationState.CanonicalImageValidated;
        }
        else if (string.Equals(promotionPolicy, "Stable", StringComparison.OrdinalIgnoreCase))
        {
            if (!meetsCrashFaultThreshold ||
                !meetsCrashStageMatrixThreshold ||
                !meetsHardwarePilotThreshold ||
                !meetsHotUnplugThreshold)
            {
                ceiling = NativeWriteValidationState.CanonicalImageValidated;
            }
            else if (!meetsCrossOsThreshold ||
                     !meetsMacOsStableThreshold ||
                     !meetsMacOsConsistencyThreshold)
            {
                ceiling = NativeWriteValidationState.HardwarePilotValidated;
            }
            else
            {
                ceiling = (meetsPowerLossThreshold && meetsPowerLossReplayThreshold)
                    ? NativeWriteValidationState.Stable
                    : NativeWriteValidationState.CrossOsValidated;
            }
        }
        else
        {
            ceiling = NativeWriteValidationState.CanonicalImageValidated;
        }

        return (NativeWriteValidationState)Math.Min((int)effective, (int)ceiling);
    }

    private static NativeWriteValidationEvidence NormalizeValidationEvidence(NativeWriteValidationEvidence? value)
    {
        if (value is null)
        {
            return new NativeWriteValidationEvidence();
        }

        return new NativeWriteValidationEvidence(
            CrashFaultPasses: Math.Max(0, value.CrashFaultPasses),
            CrashStageMatrixPasses: Math.Max(0, value.CrashStageMatrixPasses),
            HardwarePilotPasses: Math.Max(0, value.HardwarePilotPasses),
            HotUnplugPasses: Math.Max(0, value.HotUnplugPasses),
            MacOsValidationPasses: Math.Max(0, value.MacOsValidationPasses),
            MacOsConsistencyPasses: Math.Max(0, value.MacOsConsistencyPasses),
            PowerLossReplayPasses: Math.Max(0, value.PowerLossReplayPasses),
            PowerLossPassVerified: value.PowerLossPassVerified,
            LastValidatedUtc: value.LastValidatedUtc,
            LastValidationProfileId: NormalizeDiagnosticToken(value.LastValidationProfileId)
        );
    }

    private static NativeWriteValidationState ResolveRequiredValidationStateForPromotionPolicy(string? promotionPolicy)
    {
        var normalized = promotionPolicy?.Trim();
        if (string.Equals(normalized, "Stable", StringComparison.OrdinalIgnoreCase))
        {
            return NativeWriteValidationState.Stable;
        }

        if (string.Equals(normalized, "PilotHardware", StringComparison.OrdinalIgnoreCase))
        {
            return NativeWriteValidationState.HardwarePilotValidated;
        }

        // ScaffoldOnly and unknown policies must at least meet canonical image validation.
        return NativeWriteValidationState.CanonicalImageValidated;
    }

    private static string BuildNativeValidationGateState(NativeWriteValidationState requiredState)
    {
        return requiredState switch
        {
            NativeWriteValidationState.Stable => "NativeValidationStableRequired",
            NativeWriteValidationState.HardwarePilotValidated => "NativeValidationHardwarePilotRequired",
            _ => "NativeValidationCanonicalImageRequired",
        };
    }

    private static string BuildNativeValidationDiagnosticCode(NativeWriteValidationState requiredState)
    {
        return requiredState switch
        {
            NativeWriteValidationState.Stable => "NativeWriteValidationStableRequired",
            NativeWriteValidationState.HardwarePilotValidated => "NativeWriteValidationHardwarePilotRequired",
            _ => "NativeWriteValidationCanonicalImageRequired",
        };
    }

    private static string? GetValidationPolicyFailClosedReason(
        MountAccessMode effectiveAccessMode,
        string effectiveWriteBackend,
        NativeWriteValidationState effectiveValidationState,
        NativeWriteValidationState requiredValidationState)
    {
        if (effectiveAccessMode != MountAccessMode.ReadWrite ||
            !string.Equals(effectiveWriteBackend, "Native", StringComparison.OrdinalIgnoreCase) ||
            effectiveValidationState >= requiredValidationState)
        {
            return null;
        }

        return "ValidationEvidenceInsufficient";
    }

    private string? GetValidationPolicyFailClosedReasonDetailed(
        MountAccessMode effectiveAccessMode,
        string effectiveWriteBackend,
        NativeWriteValidationState effectiveValidationState,
        NativeWriteValidationState requiredValidationState,
        NativeWriteValidationEvidence? effectiveValidationEvidence,
        VolumeInfo volume)
    {
        if (effectiveAccessMode != MountAccessMode.ReadWrite ||
            !string.Equals(effectiveWriteBackend, "Native", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var evidence = ResolvePolicyValidationEvidence(
            volume,
            requiredValidationState,
            effectiveValidationEvidence);
        if (ShouldEnforceValidationEvidenceStaleness(volume, requiredValidationState))
        {
            var maxEvidenceAgeDays = Math.Max(0, _options.NativeWriteValidationEvidenceMaxAgeDays);
            if (maxEvidenceAgeDays > 0 &&
                IsValidationEvidenceStale(
                    evidence,
                    maxEvidenceAgeDays,
                    DateTime.UtcNow))
            {
                return requiredValidationState >= NativeWriteValidationState.Stable
                    ? "ValidationStableEvidenceStale"
                    : "ValidationHardwarePilotEvidenceStale";
                }
        }

        if (requiredValidationState >= NativeWriteValidationState.HardwarePilotValidated)
        {
            if (_options.NativeWriteCrashFaultMatrixRequired &&
                evidence.CrashFaultPasses < Math.Max(0, _options.NativeWriteMinCrashFaultPasses))
            {
                return "ValidationCrashFaultEvidenceInsufficient";
            }

            if (evidence.CrashStageMatrixPasses < Math.Max(0, _options.NativeWriteMinCrashStageMatrixPasses))
            {
                return "ValidationCrashStageMatrixEvidenceInsufficient";
            }

            if (evidence.HardwarePilotPasses < Math.Max(0, _options.NativeWriteMinHardwarePilotPasses))
            {
                return "ValidationHardwarePilotEvidenceInsufficient";
            }

            if (evidence.HotUnplugPasses < Math.Max(0, _options.NativeWriteMinHotUnplugPasses))
            {
                return "ValidationHotUnplugEvidenceInsufficient";
            }
        }

        if (requiredValidationState >= NativeWriteValidationState.Stable)
        {
            if (_options.NativeWriteCrossOsValidationRequired &&
                evidence.MacOsValidationPasses < Math.Max(0, _options.NativeWriteMinMacOsValidationPasses))
            {
                return "ValidationCrossOsEvidenceInsufficient";
            }

            if (evidence.MacOsConsistencyPasses < Math.Max(0, _options.NativeWriteMinMacOsConsistencyPasses))
            {
                return "ValidationMacOsConsistencyEvidenceInsufficient";
            }

            if (_options.NativeWriteRequireMacOsValidationForStable &&
                evidence.MacOsValidationPasses < Math.Max(0, _options.NativeWriteMinMacOsValidationPasses))
            {
                return "ValidationMacOsEvidenceInsufficient";
            }

            if (_options.NativeWriteStableRequiresPowerLossPass &&
                evidence.PowerLossReplayPasses < Math.Max(0, _options.NativeWriteMinPowerLossReplayPasses))
            {
                return "ValidationPowerLossReplayEvidenceInsufficient";
            }

            if (_options.NativeWriteStableRequiresPowerLossPass &&
                !evidence.PowerLossPassVerified)
            {
                return "ValidationPowerLossEvidenceInsufficient";
            }
        }

        if (requiredValidationState == NativeWriteValidationState.CanonicalImageValidated &&
            effectiveValidationState < NativeWriteValidationState.CanonicalImageValidated)
        {
            return "ValidationCanonicalEvidenceInsufficient";
        }

        return effectiveValidationState < requiredValidationState
            ? "ValidationEvidenceInsufficient"
            : null;
    }

    private NativeWriteValidationEvidence ResolvePolicyValidationEvidence(
        VolumeInfo volume,
        NativeWriteValidationState requiredValidationState,
        NativeWriteValidationEvidence? fallbackEvidence)
    {
        var normalizedFallbackEvidence = NormalizeValidationEvidence(fallbackEvidence);
        if (requiredValidationState < NativeWriteValidationState.HardwarePilotValidated ||
            !IsRawPhysicalDevice(volume.DeviceId))
        {
            return normalizedFallbackEvidence;
        }

        var profileEvidence = ResolveValidationEvidenceByProfileId(BuildValidationEvidenceProfileId(volume));
        return profileEvidence;
    }

    private static bool ShouldEnforceValidationEvidenceStaleness(
        VolumeInfo volume,
        NativeWriteValidationState requiredValidationState)
    {
        if (requiredValidationState < NativeWriteValidationState.HardwarePilotValidated)
        {
            return false;
        }

        return IsRawPhysicalDevice(volume.DeviceId);
    }

    private static bool IsValidationEvidenceStale(
        NativeWriteValidationEvidence evidence,
        int maxEvidenceAgeDays,
        DateTime nowUtc)
    {
        if (maxEvidenceAgeDays <= 0)
        {
            return false;
        }

        if (!evidence.LastValidatedUtc.HasValue)
        {
            return true;
        }

        var lastValidatedUtc = evidence.LastValidatedUtc.Value;
        if (lastValidatedUtc.Kind == DateTimeKind.Unspecified)
        {
            lastValidatedUtc = DateTime.SpecifyKind(lastValidatedUtc, DateTimeKind.Utc);
        }
        else if (lastValidatedUtc.Kind == DateTimeKind.Local)
        {
            lastValidatedUtc = lastValidatedUtc.ToUniversalTime();
        }

        if (lastValidatedUtc > nowUtc)
        {
            return false;
        }

        return (nowUtc - lastValidatedUtc) > TimeSpan.FromDays(maxEvidenceAgeDays);
    }

    private string BuildWriteBlockedMountError(string detail)
    {
        var normalizedDetail = string.IsNullOrWhiteSpace(detail)
            ? "APFS write mode paused to protect the drive"
            : detail.Trim().TrimEnd('.');

        return string.Equals(_options.ReadWriteMode, "RwWithRoFallback", StringComparison.OrdinalIgnoreCase)
            ? $"{normalizedDetail}. Falling back to read-only mount."
            : $"{normalizedDetail}. Write mount was blocked.";
    }

    private string BuildValidationEvidenceDiagnosticDetail(
        VolumeInfo volume,
        NativeWriteValidationState requiredValidationState,
        NativeWriteValidationEvidence evidence,
        string? failClosedReason,
        DateTime nowUtc)
    {
        var normalizedEvidence = NormalizeValidationEvidence(evidence);
        var requiredCrashFaultPasses = requiredValidationState >= NativeWriteValidationState.HardwarePilotValidated &&
                                       _options.NativeWriteCrashFaultMatrixRequired
            ? Math.Max(0, _options.NativeWriteMinCrashFaultPasses)
            : 0;
        var requiredCrashStageMatrixPasses = requiredValidationState >= NativeWriteValidationState.HardwarePilotValidated
            ? Math.Max(0, _options.NativeWriteMinCrashStageMatrixPasses)
            : 0;
        var requiredHardwarePilotPasses = requiredValidationState >= NativeWriteValidationState.HardwarePilotValidated
            ? Math.Max(0, _options.NativeWriteMinHardwarePilotPasses)
            : 0;
        var requiredHotUnplugPasses = requiredValidationState >= NativeWriteValidationState.HardwarePilotValidated
            ? Math.Max(0, _options.NativeWriteMinHotUnplugPasses)
            : 0;
        var requiredMacOsValidationPasses = requiredValidationState >= NativeWriteValidationState.Stable &&
                                            (_options.NativeWriteCrossOsValidationRequired ||
                                             _options.NativeWriteRequireMacOsValidationForStable)
            ? Math.Max(0, _options.NativeWriteMinMacOsValidationPasses)
            : 0;
        var requiredMacOsConsistencyPasses = requiredValidationState >= NativeWriteValidationState.Stable
            ? Math.Max(0, _options.NativeWriteMinMacOsConsistencyPasses)
            : 0;
        var requiredPowerLossReplayPasses = requiredValidationState >= NativeWriteValidationState.Stable &&
                                            _options.NativeWriteStableRequiresPowerLossPass
            ? Math.Max(0, _options.NativeWriteMinPowerLossReplayPasses)
            : 0;
        var requiredPowerLossEvidence = requiredValidationState >= NativeWriteValidationState.Stable &&
                                        _options.NativeWriteStableRequiresPowerLossPass;
        var maxEvidenceAgeDays = ShouldEnforceValidationEvidenceStaleness(volume, requiredValidationState)
            ? Math.Max(0, _options.NativeWriteValidationEvidenceMaxAgeDays)
            : 0;
        var evidenceStale = maxEvidenceAgeDays > 0 &&
                            IsValidationEvidenceStale(normalizedEvidence, maxEvidenceAgeDays, nowUtc);
        var normalizedReason = NormalizeRecoveryReason(failClosedReason);

        return $"evidence(scope={(IsRawPhysicalDevice(volume.DeviceId) ? "raw" : "nonraw")}, " +
               $"crash={Math.Max(0, normalizedEvidence.CrashFaultPasses)}/{requiredCrashFaultPasses}, " +
               $"crashMatrix={Math.Max(0, normalizedEvidence.CrashStageMatrixPasses)}/{requiredCrashStageMatrixPasses}, " +
               $"hardware={Math.Max(0, normalizedEvidence.HardwarePilotPasses)}/{requiredHardwarePilotPasses}, " +
               $"hotUnplug={Math.Max(0, normalizedEvidence.HotUnplugPasses)}/{requiredHotUnplugPasses}, " +
               $"macos={Math.Max(0, normalizedEvidence.MacOsValidationPasses)}/{requiredMacOsValidationPasses}, " +
               $"macosConsistency={Math.Max(0, normalizedEvidence.MacOsConsistencyPasses)}/{requiredMacOsConsistencyPasses}, " +
               $"powerLossReplay={Math.Max(0, normalizedEvidence.PowerLossReplayPasses)}/{requiredPowerLossReplayPasses}, " +
               $"powerLoss={(normalizedEvidence.PowerLossPassVerified ? "true" : "false")}/{(requiredPowerLossEvidence ? "true" : "false")}, " +
               $"lastValidatedUtc={FormatValidationLastValidatedUtc(normalizedEvidence.LastValidatedUtc)}, " +
               $"profile={NormalizeDiagnosticToken(normalizedEvidence.LastValidationProfileId) ?? "n/a"}, " +
               $"maxAgeDays={maxEvidenceAgeDays}, stale={(evidenceStale ? "true" : "false")}, " +
               $"reason={(string.IsNullOrWhiteSpace(normalizedReason) ? "n/a" : normalizedReason)})";
    }

    private static string FormatValidationLastValidatedUtc(DateTime? value)
    {
        if (!value.HasValue)
        {
            return "n/a";
        }

        var normalizedValue = value.Value.Kind switch
        {
            DateTimeKind.Utc => value.Value,
            DateTimeKind.Local => value.Value.ToUniversalTime(),
            _ => DateTime.SpecifyKind(value.Value, DateTimeKind.Utc),
        };
        return normalizedValue.ToString("o", CultureInfo.InvariantCulture);
    }

    private static bool IsValidationEvidenceFailClosedReason(string? recoveryReason)
        => NativeWriteRecoveryReasons.IsValidationEvidenceReason(recoveryReason);

    private static IReadOnlyList<NativeWriteDiagnostic> BuildNativeWriteDiagnostics(
        MountAccessMode effectiveAccessMode,
        string effectiveWriteBackend,
        NativeWriteValidationState effectiveValidationState,
        NativeWriteValidationState requiredValidationState,
        string? recoveryReason,
        string? recoveryAction,
        NativeWriteValidationEvidence? validationEvidence,
        bool recoveryActive,
        bool failClosedTriggered,
        string scope,
        string? commitStage = null,
        string? replayStage = null,
        string? commitBlobMagic = null,
        bool? canonicalPathActive = null,
        string? deviceProfileId = null,
        bool? replayCheckpointCandidatePresent = null,
        bool? replayCheckpointPendingWindow = null)
    {
        var normalizedScope = string.IsNullOrWhiteSpace(scope)
            ? "Runtime"
            : scope.Trim();
        var normalizedReason = NormalizeRecoveryReason(recoveryReason);
        var normalizedAction = NormalizeLastRecoveryAction(recoveryAction);
        var normalizedEvidence = NormalizeValidationEvidence(validationEvidence);
        var normalizedCommitStage = NormalizeDiagnosticToken(commitStage);
        var normalizedReplayStage = NormalizeDiagnosticToken(replayStage);
        var normalizedCommitBlobMagic = NormalizeDiagnosticToken(commitBlobMagic);
        var normalizedDeviceProfileId = NormalizeDiagnosticToken(deviceProfileId);
        var evidenceSnapshotId = BuildEvidenceSnapshotId(normalizedEvidence, normalizedDeviceProfileId);
        var validationScenario = ResolveValidationScenario(normalizedReason);
        var diagnostics = new List<NativeWriteDiagnostic>();

        if (!string.IsNullOrWhiteSpace(normalizedReason))
        {
            var isValidationReason = IsValidationEvidenceFailClosedReason(normalizedReason);
            diagnostics.Add(
                new NativeWriteDiagnostic(
                    Code: BuildRecoveryFailClosedDiagnosticCode(normalizedReason),
                    Message: DescribeRecoveryReason(normalizedReason),
                    IsFailClosed: failClosedTriggered || recoveryActive || isValidationReason || effectiveAccessMode != MountAccessMode.ReadWrite,
                    Scope: isValidationReason
                        ? $"{normalizedScope}:ValidationGate"
                        : $"{normalizedScope}:Recovery",
                    RecoveryReason: normalizedReason,
                    RecoveryAction: normalizedAction,
                    ValidationState: effectiveValidationState,
                    RequiredValidationState: requiredValidationState,
                    ValidationEvidence: normalizedEvidence,
                    CommitStage: normalizedCommitStage,
                    ReplayStage: normalizedReplayStage,
                    CommitBlobMagic: normalizedCommitBlobMagic,
                    CanonicalPathActive: canonicalPathActive,
                    DeviceProfileId: normalizedDeviceProfileId,
                    ValidationScenario: validationScenario,
                    EvidenceSnapshotId: evidenceSnapshotId)
                {
                    ReplayCheckpointCandidatePresent = replayCheckpointCandidatePresent,
                    ReplayCheckpointPendingWindow = replayCheckpointPendingWindow,
                }
            );
        }

        if (diagnostics.Count == 0 &&
            effectiveAccessMode == MountAccessMode.ReadWrite &&
            string.Equals(NormalizeWriteBackendName(effectiveWriteBackend), "Native", StringComparison.OrdinalIgnoreCase) &&
            effectiveValidationState < requiredValidationState)
        {
            diagnostics.Add(
                new NativeWriteDiagnostic(
                    Code: BuildNativeValidationDiagnosticCode(requiredValidationState),
                    Message: "Native write validation state does not satisfy the configured promotion policy.",
                    IsFailClosed: true,
                    Scope: $"{normalizedScope}:ValidationGate",
                    RecoveryReason: "ValidationEvidenceInsufficient",
                    RecoveryAction: normalizedAction,
                    ValidationState: effectiveValidationState,
                    RequiredValidationState: requiredValidationState,
                    ValidationEvidence: normalizedEvidence,
                    CommitStage: normalizedCommitStage,
                    ReplayStage: normalizedReplayStage,
                    CommitBlobMagic: normalizedCommitBlobMagic,
                    CanonicalPathActive: canonicalPathActive,
                    DeviceProfileId: normalizedDeviceProfileId,
                    ValidationScenario: validationScenario ?? "ValidationGate",
                    EvidenceSnapshotId: evidenceSnapshotId)
                {
                    ReplayCheckpointCandidatePresent = replayCheckpointCandidatePresent,
                    ReplayCheckpointPendingWindow = replayCheckpointPendingWindow,
                }
            );
        }

        if (diagnostics.Count == 0 &&
            recoveryActive &&
            effectiveAccessMode != MountAccessMode.ReadWrite)
        {
            diagnostics.Add(
                new NativeWriteDiagnostic(
                    Code: "NativeWriteRecoveryActive",
                    Message: "Native recovery remains active and writable mode is blocked.",
                    IsFailClosed: true,
                    Scope: $"{normalizedScope}:Recovery",
                    RecoveryReason: normalizedReason,
                    RecoveryAction: normalizedAction,
                    ValidationState: effectiveValidationState,
                    RequiredValidationState: requiredValidationState,
                    ValidationEvidence: normalizedEvidence,
                    CommitStage: normalizedCommitStage,
                    ReplayStage: normalizedReplayStage,
                    CommitBlobMagic: normalizedCommitBlobMagic,
                    CanonicalPathActive: canonicalPathActive,
                    DeviceProfileId: normalizedDeviceProfileId,
                    ValidationScenario: validationScenario,
                    EvidenceSnapshotId: evidenceSnapshotId)
                {
                    ReplayCheckpointCandidatePresent = replayCheckpointCandidatePresent,
                    ReplayCheckpointPendingWindow = replayCheckpointPendingWindow,
                }
            );
        }

        return diagnostics.Count == 0
            ? Array.Empty<NativeWriteDiagnostic>()
            : diagnostics.ToArray();
    }

    private static string? ResolveValidationScenario(string? recoveryReason)
    {
        return NormalizeRecoveryReason(recoveryReason) switch
        {
            "ValidationCrashFaultEvidenceInsufficient" => "CrashFaultMatrix",
            "ValidationCrashStageMatrixEvidenceInsufficient" => "CrashStageMatrix",
            "ValidationHardwarePilotEvidenceInsufficient" => "HardwarePilot",
            "ValidationHotUnplugEvidenceInsufficient" => "HotUnplug",
            "ValidationCrossOsEvidenceInsufficient" => "CrossOs",
            "ValidationMacOsEvidenceInsufficient" => "MacOsValidation",
            "ValidationMacOsConsistencyEvidenceInsufficient" => "MacOsConsistency",
            "ValidationPowerLossReplayEvidenceInsufficient" => "PowerLossReplay",
            "ValidationPowerLossEvidenceInsufficient" => "PowerLossVerification",
            "ValidationCanonicalEvidenceInsufficient" => "CanonicalImage",
            "ValidationHardwarePilotEvidenceStale" => "HardwarePilotStale",
            "ValidationStableEvidenceStale" => "StableEvidenceStale",
            "ValidationEvidenceInsufficient" => "ValidationGate",
            _ => null,
        };
    }

    private static string? BuildEvidenceSnapshotId(
        NativeWriteValidationEvidence evidence,
        string? profileId)
    {
        var normalizedProfileId = NormalizeDiagnosticToken(profileId) ??
                                  NormalizeDiagnosticToken(evidence.LastValidationProfileId);
        if (string.IsNullOrWhiteSpace(normalizedProfileId))
        {
            return null;
        }

        var timestamp = FormatValidationLastValidatedUtc(evidence.LastValidatedUtc);
        return string.Equals(timestamp, "n/a", StringComparison.OrdinalIgnoreCase)
            ? normalizedProfileId
            : $"{normalizedProfileId}@{timestamp}";
    }

    private static string? GetWriteGateFailClosedReason(
        MountAccessMode effectiveAccessMode,
        string effectiveWriteBackend,
        WriteGateDecision writeGateDecision)
    {
        if (effectiveAccessMode != MountAccessMode.ReadWrite ||
            string.Equals(NormalizeWriteBackendName(effectiveWriteBackend), "Disabled", StringComparison.OrdinalIgnoreCase) ||
            writeGateDecision.AllowWrite)
        {
            return null;
        }

        return "WriteGateBlocked";
    }

    private static string BuildWriteGateDecisionDetail(WriteGateDecision writeGateDecision)
    {
        var gateState = string.IsNullOrWhiteSpace(writeGateDecision.GateState)
            ? "unknown"
            : writeGateDecision.GateState.Trim();
        var reason = string.IsNullOrWhiteSpace(writeGateDecision.Reason)
            ? "n/a"
            : writeGateDecision.Reason.Trim();
        return $"writeGateState={gateState}, writeGateReason={reason}";
    }

    private NativeWriteValidationEvidence ResolveValidationEvidence(VolumeInfo volume)
    {
        var volumeEvidence = ResolveValidationEvidenceByVolumeId(volume.VolumeId);
        var profileEvidence = ResolveValidationEvidenceByProfileId(BuildValidationEvidenceProfileId(volume));
        var combined = CombineValidationEvidence(volumeEvidence, profileEvidence);
        if (!string.IsNullOrWhiteSpace(combined.LastValidationProfileId))
        {
            return combined;
        }

        return combined with { LastValidationProfileId = BuildValidationEvidenceProfileId(volume) };
    }

    private NativeWriteValidationEvidence ResolveValidationEvidenceByVolumeId(string? volumeId)
    {
        if (string.IsNullOrWhiteSpace(volumeId))
        {
            return new NativeWriteValidationEvidence();
        }

        return _validationEvidenceByVolumeId.TryGetValue(volumeId, out var evidence)
            ? NormalizeValidationEvidence(evidence)
            : new NativeWriteValidationEvidence();
    }

    private NativeWriteValidationEvidence ResolveValidationEvidenceByProfileId(string? profileId)
    {
        if (string.IsNullOrWhiteSpace(profileId))
        {
            return new NativeWriteValidationEvidence();
        }

        return _validationEvidenceByProfileId.TryGetValue(profileId, out var evidence)
            ? NormalizeValidationEvidence(evidence)
            : new NativeWriteValidationEvidence();
    }

    private static NativeWriteValidationEvidence CombineValidationEvidence(
        NativeWriteValidationEvidence primary,
        NativeWriteValidationEvidence secondary)
    {
        var left = NormalizeValidationEvidence(primary);
        var right = NormalizeValidationEvidence(secondary);

        DateTime? lastValidatedUtc = null;
        if (left.LastValidatedUtc.HasValue &&
            right.LastValidatedUtc.HasValue)
        {
            lastValidatedUtc = left.LastValidatedUtc.Value >= right.LastValidatedUtc.Value
                ? left.LastValidatedUtc.Value
                : right.LastValidatedUtc.Value;
        }
        else if (left.LastValidatedUtc.HasValue)
        {
            lastValidatedUtc = left.LastValidatedUtc;
        }
        else if (right.LastValidatedUtc.HasValue)
        {
            lastValidatedUtc = right.LastValidatedUtc;
        }

        var lastValidationProfileId = !string.IsNullOrWhiteSpace(right.LastValidationProfileId)
            ? right.LastValidationProfileId
            : left.LastValidationProfileId;

        return new NativeWriteValidationEvidence(
            CrashFaultPasses: Math.Max(left.CrashFaultPasses, right.CrashFaultPasses),
            CrashStageMatrixPasses: Math.Max(left.CrashStageMatrixPasses, right.CrashStageMatrixPasses),
            HardwarePilotPasses: Math.Max(left.HardwarePilotPasses, right.HardwarePilotPasses),
            HotUnplugPasses: Math.Max(left.HotUnplugPasses, right.HotUnplugPasses),
            MacOsValidationPasses: Math.Max(left.MacOsValidationPasses, right.MacOsValidationPasses),
            MacOsConsistencyPasses: Math.Max(left.MacOsConsistencyPasses, right.MacOsConsistencyPasses),
            PowerLossReplayPasses: Math.Max(left.PowerLossReplayPasses, right.PowerLossReplayPasses),
            PowerLossPassVerified: left.PowerLossPassVerified || right.PowerLossPassVerified,
            LastValidatedUtc: lastValidatedUtc,
            LastValidationProfileId: lastValidationProfileId
        );
    }

    private NativeWriteValidationEvidence MergeValidationEvidenceFromRuntimeStatus(
        VolumeInfo volume,
        MountAccessMode requestedAccessMode,
        HostRuntimeStatus runtimeStatus,
        NativeWriteValidationEvidence baselineEvidence,
        string? runtimeSessionId)
    {
        var profileId = BuildValidationEvidenceProfileId(volume);
        var runtimeValidationEvidence = runtimeStatus.ValidationEvidence is null
            ? null
            : NormalizeValidationEvidence(runtimeStatus.ValidationEvidence);
        runtimeValidationEvidence = NormalizeRuntimeValidationEvidenceForVolume(
            profileId,
            runtimeValidationEvidence);
        var runtimeValidationEvidenceHasSignal = runtimeValidationEvidence is not null &&
                                                 HasValidationEvidenceSignal(runtimeValidationEvidence);
        if (runtimeValidationEvidence is not null &&
            IsRawPhysicalDevice(volume.DeviceId) &&
            !_options.NativeWriteAllowRuntimeEvidenceSeedForRawPhysicalDevices)
        {
            runtimeValidationEvidence = null;
            runtimeValidationEvidenceHasSignal = false;
        }
        var effectiveVolumeBaseline = runtimeValidationEvidence is null
            ? NormalizeValidationEvidence(baselineEvidence)
            : CombineValidationEvidence(baselineEvidence, runtimeValidationEvidence);
        var observedValidationState = ResolveObservedValidationStateForEvidence(
            requestedAccessMode,
            NormalizeWriteBackendName(runtimeStatus.WriteBackend),
            runtimeStatus.CommitModel,
            runtimeStatus.NativeWriteReadiness,
            runtimeStatus.RecoveryActive,
            runtimeStatus.NativeWriteValidationState
        );
        var strictNonFixtureScaffoldControls = ResolveEffectiveNonFixtureScaffoldControls(volume.DeviceId);
        if (ShouldBlockObservedValidationPromotionForRuntimeStatus(
                volume.DeviceId,
                requestedAccessMode,
                NormalizeWriteBackendName(runtimeStatus.WriteBackend),
                runtimeStatus,
                strictNonFixtureScaffoldControls))
        {
            observedValidationState = NativeWriteValidationState.Scaffold;
        }
        var mediaScopedObservedValidationState = ClampObservedValidationStateForVolume(
            observedValidationState,
            volume);
        var nowUtc = DateTime.UtcNow;
        var allowCounterIncrement = ShouldPromoteValidationEvidenceForSession(
            profileId,
            runtimeStatus.HostProcessId,
            runtimeSessionId);
        var promotionObservedValidationState = ClampObservedValidationStateForEvidencePromotion(
            mediaScopedObservedValidationState,
            volume,
            runtimeValidationEvidenceHasSignal);
        if (allowCounterIncrement &&
            mediaScopedObservedValidationState >= NativeWriteValidationState.HardwarePilotValidated &&
            runtimeValidationEvidence is null &&
            !HasCanonicalStageProofForValidationPromotion(runtimeStatus))
        {
            // Hardware/stable promotion counters require explicit native stage proof
            // from host telemetry (commit/replay stage or committed xid). This keeps
            // pilot/stable evidence from drifting on ambiguous runtime status payloads.
            allowCounterIncrement = false;
            promotionObservedValidationState = NativeWriteValidationState.Scaffold;
        }
        var promotedEvidence = PromoteValidationEvidenceForObservedState(
            effectiveVolumeBaseline,
            promotionObservedValidationState,
            _options.NativeWriteMinCrashFaultPasses,
            _options.NativeWriteMinCrashStageMatrixPasses,
            _options.NativeWriteMinHardwarePilotPasses,
            _options.NativeWriteMinHotUnplugPasses,
            _options.NativeWriteMinMacOsValidationPasses,
            _options.NativeWriteMinMacOsConsistencyPasses,
            _options.NativeWriteMinPowerLossReplayPasses,
            _options.NativeWriteStableRequiresPowerLossPass,
            nowUtc,
            allowCounterIncrement,
            profileId
        );
        var profileBaseline = ResolveValidationEvidenceByProfileId(profileId);
        if (runtimeValidationEvidence is not null)
        {
            profileBaseline = CombineValidationEvidence(profileBaseline, runtimeValidationEvidence);
        }
        var promotedProfileEvidence = PromoteValidationEvidenceForObservedState(
            profileBaseline,
            promotionObservedValidationState,
            _options.NativeWriteMinCrashFaultPasses,
            _options.NativeWriteMinCrashStageMatrixPasses,
            _options.NativeWriteMinHardwarePilotPasses,
            _options.NativeWriteMinHotUnplugPasses,
            _options.NativeWriteMinMacOsValidationPasses,
            _options.NativeWriteMinMacOsConsistencyPasses,
            _options.NativeWriteMinPowerLossReplayPasses,
            _options.NativeWriteStableRequiresPowerLossPass,
            nowUtc,
            allowCounterIncrement,
            profileId
        );
        var evidenceChanged = false;

        if (!string.IsNullOrWhiteSpace(volume.VolumeId))
        {
            var normalizedVolumeId = volume.VolumeId.Trim();
            if (!_validationEvidenceByVolumeId.TryGetValue(normalizedVolumeId, out var existing) ||
                !Equals(promotedEvidence, existing))
            {
                _validationEvidenceByVolumeId[normalizedVolumeId] = promotedEvidence;
                evidenceChanged = true;
            }
        }

        if (!_validationEvidenceByProfileId.TryGetValue(profileId, out var existingProfileEvidence) ||
            !Equals(promotedProfileEvidence, existingProfileEvidence))
        {
            _validationEvidenceByProfileId[profileId] = promotedProfileEvidence;
            evidenceChanged = true;
        }

        if (evidenceChanged)
        {
            PersistValidationEvidenceToDisk();
        }

        return CombineValidationEvidence(promotedEvidence, promotedProfileEvidence);
    }

    private static NativeWriteValidationEvidence? NormalizeRuntimeValidationEvidenceForVolume(
        string expectedProfileId,
        NativeWriteValidationEvidence? runtimeValidationEvidence)
    {
        if (runtimeValidationEvidence is null)
        {
            return null;
        }

        var normalized = NormalizeValidationEvidence(runtimeValidationEvidence);
        var reportedProfileId = NormalizeDiagnosticToken(normalized.LastValidationProfileId);
        if (!string.IsNullOrWhiteSpace(reportedProfileId) &&
            !string.Equals(reportedProfileId, expectedProfileId, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return normalized with { LastValidationProfileId = expectedProfileId };
    }

    private static NativeWriteValidationState ClampObservedValidationStateForEvidencePromotion(
        NativeWriteValidationState observedValidationState,
        VolumeInfo volume,
        bool runtimeValidationEvidenceHasSignal)
    {
        if (!IsRawPhysicalDevice(volume.DeviceId) ||
            runtimeValidationEvidenceHasSignal)
        {
            return observedValidationState;
        }

        return observedValidationState > NativeWriteValidationState.CanonicalImageValidated
            ? NativeWriteValidationState.CanonicalImageValidated
            : observedValidationState;
    }

    private static bool ShouldBlockObservedValidationPromotionForRuntimeStatus(
        string? deviceId,
        MountAccessMode requestedAccessMode,
        string runtimeWriteBackend,
        HostRuntimeStatus runtimeStatus,
        (bool DisallowScaffoldCommitOnNonFixture, bool RejectScaffoldReplayBlobOnNonFixture, bool RequireCanonicalReplayCandidateOnNonFixture) strictNonFixtureScaffoldControls)
    {
        if (requestedAccessMode != MountAccessMode.ReadWrite ||
            !string.Equals(runtimeWriteBackend, "Native", StringComparison.OrdinalIgnoreCase) ||
            IsFixtureImagePath(deviceId))
        {
            return false;
        }

        return GetNonFixtureCanonicalSafetyReason(
                   runtimeStatus,
                   strictNonFixtureScaffoldControls.DisallowScaffoldCommitOnNonFixture,
                   strictNonFixtureScaffoldControls.RejectScaffoldReplayBlobOnNonFixture,
                   strictNonFixtureScaffoldControls.RequireCanonicalReplayCandidateOnNonFixture) is not null;
    }

    private static string BuildValidationEvidenceProfileId(VolumeInfo volume)
    {
        var scope = IsRawPhysicalDevice(volume.DeviceId)
            ? "raw"
            : IsFixtureImagePath(volume.DeviceId)
                ? "image"
                : "device";
        var deviceToken = NormalizeValidationEvidenceProfileToken(volume.DeviceId);
        var volumeToken = NormalizeValidationEvidenceProfileToken(volume.VolumeName);
        return $"{scope}::{deviceToken}::{volumeToken}";
    }

    private bool ShouldPromoteValidationEvidenceForSession(
        string profileId,
        int hostProcessId,
        string? runtimeSessionId)
    {
        if (string.IsNullOrWhiteSpace(profileId))
        {
            return true;
        }

        var normalizedProfileId = profileId.Trim();
        var normalizedRuntimeSessionId = string.IsNullOrWhiteSpace(runtimeSessionId)
            ? null
            : runtimeSessionId.Trim();
        var sessionToken = normalizedRuntimeSessionId is not null
            ? $"sid::{normalizedRuntimeSessionId}"
            : hostProcessId > 0
                ? $"pid::{hostProcessId}"
                : null;
        if (sessionToken is null)
        {
            return true;
        }

        if (_lastPromotedEvidenceSessionByProfileId.TryGetValue(normalizedProfileId, out var previousSessionToken) &&
            string.Equals(previousSessionToken, sessionToken, StringComparison.Ordinal))
        {
            return false;
        }

        _lastPromotedEvidenceSessionByProfileId[normalizedProfileId] = sessionToken;
        return true;
    }

    private static string NormalizeValidationEvidenceProfileToken(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "unknown";
        }

        var normalized = WhitespaceCollapseRegex.Replace(value.Trim().ToLowerInvariant(), " ");
        return string.IsNullOrWhiteSpace(normalized)
            ? "unknown"
            : normalized;
    }

    private static NativeWriteValidationState ClampObservedValidationStateForVolume(
        NativeWriteValidationState observedValidationState,
        VolumeInfo volume)
    {
        if (observedValidationState <= NativeWriteValidationState.CanonicalImageValidated)
        {
            return observedValidationState;
        }

        return IsRawPhysicalDevice(volume.DeviceId)
            ? observedValidationState
            : NativeWriteValidationState.CanonicalImageValidated;
    }

    private static NativeWriteValidationState ResolveObservedValidationStateForEvidence(
        MountAccessMode requestedAccessMode,
        string runtimeWriteBackend,
        NativeWriteCommitModel commitModel,
        NativeWriteReadiness readiness,
        bool recoveryActive,
        NativeWriteValidationState reportedValidationState)
    {
        if (requestedAccessMode != MountAccessMode.ReadWrite ||
            !string.Equals(runtimeWriteBackend, "Native", StringComparison.OrdinalIgnoreCase) ||
            recoveryActive)
        {
            return NativeWriteValidationState.Scaffold;
        }

        var effective = ClampReportedValidationState(
            reportedValidationState,
            commitModel,
            readiness,
            recoveryActive);
        if (effective > NativeWriteValidationState.Scaffold)
        {
            return effective;
        }

        if (IsCanonicalValidationEligible(
                commitModel,
                readiness,
                recoveryActive))
        {
            return NativeWriteValidationState.CanonicalImageValidated;
        }

        return NativeWriteValidationState.Scaffold;
    }

    private static NativeWriteValidationState ClampReportedValidationState(
        NativeWriteValidationState reportedValidationState,
        NativeWriteCommitModel commitModel,
        NativeWriteReadiness readiness,
        bool recoveryActive)
    {
        if (!IsCanonicalValidationEligible(commitModel, readiness, recoveryActive))
        {
            return NativeWriteValidationState.Scaffold;
        }

        return reportedValidationState switch
        {
            < NativeWriteValidationState.Scaffold => NativeWriteValidationState.Scaffold,
            > NativeWriteValidationState.Stable => NativeWriteValidationState.Stable,
            _ => reportedValidationState,
        };
    }

    private static bool IsCanonicalValidationEligible(
        NativeWriteCommitModel commitModel,
        NativeWriteReadiness readiness,
        bool recoveryActive)
        => !recoveryActive &&
           commitModel == NativeWriteCommitModel.CanonicalApfsCheckpoint &&
           readiness == NativeWriteReadiness.CommitReady;

    private static int IncrementEvidenceCounter(int currentValue, int requiredValue)
    {
        var normalizedCurrent = Math.Max(0, currentValue);
        var normalizedRequired = Math.Max(0, requiredValue);
        if (normalizedRequired == 0 || normalizedCurrent >= normalizedRequired)
        {
            return normalizedCurrent;
        }

        if (normalizedCurrent == int.MaxValue)
        {
            return normalizedCurrent;
        }

        return normalizedCurrent + 1;
    }

    private static NativeWriteValidationEvidence PromoteValidationEvidenceForObservedState(
        NativeWriteValidationEvidence baselineEvidence,
        NativeWriteValidationState observedValidationState,
        int minCrashFaultPasses,
        int minCrashStageMatrixPasses,
        int minHardwarePilotPasses,
        int minHotUnplugPasses,
        int minMacOsValidationPasses,
        int minMacOsConsistencyPasses,
        int minPowerLossReplayPasses,
        bool stableRequiresPowerLossPass,
        DateTime nowUtc,
        bool allowCounterIncrement = true,
        string? lastValidationProfileId = null)
    {
        var baseline = NormalizeValidationEvidence(baselineEvidence);
        var crashFaultPasses = baseline.CrashFaultPasses;
        var crashStageMatrixPasses = baseline.CrashStageMatrixPasses;
        var hardwarePilotPasses = baseline.HardwarePilotPasses;
        var hotUnplugPasses = baseline.HotUnplugPasses;
        var macOsValidationPasses = baseline.MacOsValidationPasses;
        var macOsConsistencyPasses = baseline.MacOsConsistencyPasses;
        var powerLossReplayPasses = baseline.PowerLossReplayPasses;
        var powerLossPassVerified = baseline.PowerLossPassVerified;
        var normalizedProfileId = NormalizeDiagnosticToken(lastValidationProfileId) ??
                                  baseline.LastValidationProfileId;
        var changed = false;

        if (allowCounterIncrement &&
            observedValidationState >= NativeWriteValidationState.HardwarePilotValidated)
        {
            var nextCrashFaultPasses = IncrementEvidenceCounter(crashFaultPasses, minCrashFaultPasses);
            if (nextCrashFaultPasses != crashFaultPasses)
            {
                crashFaultPasses = nextCrashFaultPasses;
                changed = true;
            }

            var nextCrashStageMatrixPasses = IncrementEvidenceCounter(crashStageMatrixPasses, minCrashStageMatrixPasses);
            if (nextCrashStageMatrixPasses != crashStageMatrixPasses)
            {
                crashStageMatrixPasses = nextCrashStageMatrixPasses;
                changed = true;
            }

            var nextHardwarePilotPasses = IncrementEvidenceCounter(hardwarePilotPasses, minHardwarePilotPasses);
            if (nextHardwarePilotPasses != hardwarePilotPasses)
            {
                hardwarePilotPasses = nextHardwarePilotPasses;
                changed = true;
            }

            var nextHotUnplugPasses = IncrementEvidenceCounter(hotUnplugPasses, minHotUnplugPasses);
            if (nextHotUnplugPasses != hotUnplugPasses)
            {
                hotUnplugPasses = nextHotUnplugPasses;
                changed = true;
            }
        }

        if (allowCounterIncrement &&
            observedValidationState >= NativeWriteValidationState.CrossOsValidated)
        {
            var nextMacOsValidationPasses = IncrementEvidenceCounter(macOsValidationPasses, minMacOsValidationPasses);
            if (nextMacOsValidationPasses != macOsValidationPasses)
            {
                macOsValidationPasses = nextMacOsValidationPasses;
                changed = true;
            }

            var nextMacOsConsistencyPasses = IncrementEvidenceCounter(macOsConsistencyPasses, minMacOsConsistencyPasses);
            if (nextMacOsConsistencyPasses != macOsConsistencyPasses)
            {
                macOsConsistencyPasses = nextMacOsConsistencyPasses;
                changed = true;
            }
        }

        if (allowCounterIncrement &&
            observedValidationState >= NativeWriteValidationState.Stable &&
            stableRequiresPowerLossPass)
        {
            var nextPowerLossReplayPasses = IncrementEvidenceCounter(powerLossReplayPasses, minPowerLossReplayPasses);
            if (nextPowerLossReplayPasses != powerLossReplayPasses)
            {
                powerLossReplayPasses = nextPowerLossReplayPasses;
                changed = true;
            }

            if (!powerLossPassVerified)
            {
                powerLossPassVerified = true;
                changed = true;
            }
        }

        var hasValidationSignal = observedValidationState >= NativeWriteValidationState.CanonicalImageValidated;
        var lastValidatedUtc = baseline.LastValidatedUtc;
        if (hasValidationSignal && (changed || lastValidatedUtc is null))
        {
            lastValidatedUtc = nowUtc;
            changed = true;
        }

        if (!changed)
        {
            return baseline;
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
            LastValidationProfileId: normalizedProfileId
        );
    }

    private static bool HasCanonicalStageProofForValidationPromotion(HostRuntimeStatus status)
    {
        if (!string.IsNullOrWhiteSpace(status.CommitStage) ||
            !string.IsNullOrWhiteSpace(status.ReplayStage))
        {
            return true;
        }

        return status.LastCommitXid.HasValue &&
               status.LastCommitXid.Value > 0;
    }

    private void LoadValidationEvidenceFromDisk()
    {
        var configuredPath = _options.NativeWriteEvidenceStorePath;
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            return;
        }

        var path = Environment.ExpandEnvironmentVariables(configuredPath.Trim());
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            var json = File.ReadAllText(path);
            if (string.IsNullOrWhiteSpace(json))
            {
                return;
            }

            var payload = JsonSerializer.Deserialize<ValidationEvidenceStorePayload>(
                json,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                });
            if (payload is null)
            {
                return;
            }

            if (payload.Volumes is { Count: > 0 })
            {
                foreach (var (volumeId, rawEvidence) in payload.Volumes)
                {
                    if (string.IsNullOrWhiteSpace(volumeId) || rawEvidence is null)
                    {
                        continue;
                    }

                    _validationEvidenceByVolumeId[volumeId.Trim()] = NormalizeValidationEvidence(rawEvidence);
                }
            }

            if (payload.Profiles is { Count: > 0 })
            {
                foreach (var (profileId, rawEvidence) in payload.Profiles)
                {
                    if (string.IsNullOrWhiteSpace(profileId) || rawEvidence is null)
                    {
                        continue;
                    }

                    _validationEvidenceByProfileId[profileId.Trim()] = NormalizeValidationEvidence(rawEvidence);
                }
            }
        }
        catch
        {
            // Evidence is best-effort telemetry; ignore malformed files.
        }
    }

    private void PersistValidationEvidenceToDisk()
    {
        var configuredPath = _options.NativeWriteEvidenceStorePath;
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            return;
        }

        try
        {
            var path = Environment.ExpandEnvironmentVariables(configuredPath.Trim());
            if (string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var payload = new ValidationEvidenceStorePayload(
                _validationEvidenceByVolumeId
                    .OrderBy(static x => x.Key, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(
                        static x => x.Key,
                        static x => (NativeWriteValidationEvidence?)NormalizeValidationEvidence(x.Value),
                        StringComparer.OrdinalIgnoreCase),
                _validationEvidenceByProfileId
                    .OrderBy(static x => x.Key, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(
                        static x => x.Key,
                        static x => (NativeWriteValidationEvidence?)NormalizeValidationEvidence(x.Value),
                        StringComparer.OrdinalIgnoreCase)
            );
            var json = JsonSerializer.Serialize(
                payload,
                new JsonSerializerOptions
                {
                    WriteIndented = true,
                }
            );

            var tempPath = path + ".tmp";
            File.WriteAllText(tempPath, json);
            File.Move(tempPath, path, overwrite: true);
        }
        catch
        {
            // Evidence persistence is best-effort telemetry.
        }
    }

    private static bool IsWriteBackendMode(string? configuredValue, string target)
    {
        if (string.IsNullOrWhiteSpace(configuredValue))
        {
            return false;
        }

        return string.Equals(configuredValue.Trim(), target, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsRawPhysicalDevice(string? deviceId)
        => !string.IsNullOrWhiteSpace(deviceId) &&
           (deviceId.StartsWith(@"\\.\PhysicalDrive", StringComparison.OrdinalIgnoreCase) ||
            deviceId.StartsWith(@"\\?\PhysicalDrive", StringComparison.OrdinalIgnoreCase));

    private static bool IsFixtureImagePath(string? devicePath)
    {
        if (string.IsNullOrWhiteSpace(devicePath) || IsRawPhysicalDevice(devicePath))
        {
            return false;
        }

        var normalized = devicePath.Trim().ToLowerInvariant();
        if (normalized.EndsWith(".apfs.img", StringComparison.Ordinal) ||
            normalized.EndsWith(".img", StringComparison.Ordinal) ||
            normalized.EndsWith(".apfs.fixture", StringComparison.Ordinal))
        {
            return true;
        }

        var extension = Path.GetExtension(normalized);
        if (string.Equals(extension, ".img", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(extension, ".apfs", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(extension, ".fixture", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Do not infer fixture mode from parent-directory naming (for example,
        // "...\\fixtures\\volume.bin"). Non-fixture safety gates must rely on
        // explicit image naming, not incidental folder segments.
        return false;
    }

    private static bool IsRecoveryPolicyFailClosed(string? value)
        => string.Equals(value?.Trim(), "FailClosed", StringComparison.OrdinalIgnoreCase);

    private static bool HasRecoverySignal(string? recoveryReason)
        => !string.IsNullOrWhiteSpace(NormalizeRecoveryReason(recoveryReason));

    private static bool IsCanonicalGateFailureReason(string? recoveryReason)
    {
        return NormalizeRecoveryReason(recoveryReason) switch
        {
            "CanonicalPathNotActive" => true,
            "CanonicalStateNotLoaded" => true,
            "CanonicalVolumeStateLoadFailed" => true,
            "CanonicalObjectMapStateInvalid" => true,
            "CanonicalSpacemanStateInvalid" => true,
            "CanonicalVolumeTreeStateInvalid" => true,
            "NativeWriteNotReady" => true,
            "WriteDeviceNotAllowed" => true,
            "CommitPathNotReady" => true,
            "CanonicalCommitNotReady" => true,
            _ => false,
        };
    }

    private static bool ShouldPreserveExplicitRecoveryReasonBeforeCanonicalGate(string? normalizedRecoveryReason)
    {
        return normalizedRecoveryReason is
            "NativeMutationStagingFailed" or
            "DirtyTransactionLimitExceeded" or
            "CommitTimedOut" or
            "CommitNotWritable" or
            "CommitNotReady" or
            "CommitAllocationFailed" or
            "CommitInvariantFailed" or
            "CommitPersistOrFlushFailed" or
            "CommitInterruptedBeforeObjectMapPersist" or
            "CommitObjectMapPersistFailed" or
            "CommitObjectMapRoundTripFailed" or
            "CommitInterruptedBeforeSpacemanPersist" or
            "CommitSpacemanPersistFailed" or
            "CommitSpacemanRoundTripFailed" or
            "CommitInterruptedBeforeInodePersist" or
            "CommitInodePersistFailed" or
            "CommitInodeRoundTripFailed" or
            "CommitInterruptedBeforeBtreePersist" or
            "CommitBtreePersistFailed" or
            "CommitBtreeRoundTripFailed" or
            "CommitInterruptedBeforeReplayPersist" or
            "CommitReplayPersistFailed" or
            "CommitInterruptedBeforeReplayRoundTripVerify" or
            "CommitReplayRoundTripFailed" or
            "CommitInterruptedBeforeCheckpointSwitch" or
            "CommitCheckpointWriteFailed" or
            "CommitInterruptedBeforeCheckpointRoundTripVerify" or
            "CommitCheckpointRoundTripFailed" or
            "CommitInterruptedBeforeCheckpointFlush" or
            "CommitCheckpointFlushFailed" or
            "NativeWriteBootstrapFailed" or
            "ContainerStateLoadFailed" or
            "ObjectMapLoadFailed" or
            "SpacemanStateLoadFailed" or
            "VolumeStateLoadFailed" or
            "PersistentStateLoadFailed" or
            "RootStateInvalid" or
            "IntegrityCheckFailedOnMount" or
            "IntegrityMissingAllocationMap" or
            "PersistentStateAheadOfSuperblock" or
            "PersistentStateBehindSuperblock" or
            "RecoveryLoadVolumeStateFailed" or
            "RecoveryPersistentStateLoadFailed" or
            "ReplayIntegrityCheckFailed" or
            "ReplayMetadataStateMissing" or
            "ReplayCanonicalCandidateMissing" or
            "ReplayCheckpointPendingWindow" or
            "ReplayCheckpointNotPendingWindow" or
            "ReplayXidWindowInvalid" or
            "ReplayCommitBlobInvalid" or
            "ReplayCommitBlobReadFailed" or
            "ReplayInterruptedBeforeCheckpointSwitch" or
            "ReplayCheckpointWriteFailed" or
            "ReplayInterruptedBeforeCheckpointFlush" or
            "ReplayCheckpointFlushFailed" or
            "RecoveryMarkerDirty";
    }

    private static string NormalizeWriteBackendName(string? value)
    {
        var normalized = value?.Trim();

        if (string.Equals(normalized, "Native", StringComparison.OrdinalIgnoreCase))
        {
            return "Native";
        }

        if (string.Equals(normalized, "Overlay", StringComparison.OrdinalIgnoreCase))
        {
            return "Overlay";
        }

        return "Disabled";
    }

    private static NativeWriteCommitModel ResolveEffectiveCommitModel(
        MountAccessMode accessMode,
        string writeBackend,
        NativeWriteCommitModel reportedModel
    )
    {
        if (accessMode != MountAccessMode.ReadWrite ||
            !string.Equals(writeBackend, "Native", StringComparison.OrdinalIgnoreCase))
        {
            return NativeWriteCommitModel.ScaffoldCheckpoint;
        }

        return reportedModel == NativeWriteCommitModel.CanonicalApfsCheckpoint
            ? NativeWriteCommitModel.CanonicalApfsCheckpoint
            : NativeWriteCommitModel.ScaffoldCheckpoint;
    }

    private static HostRuntimeStatus BuildDefaultHostRuntimeStatus(
        MountAccessMode accessMode,
        string? configuredWriteBackend
    )
    {
        if (accessMode != MountAccessMode.ReadWrite)
        {
            return new HostRuntimeStatus(
                "Disabled",
                NativeWriteCommitModel.ScaffoldCheckpoint,
                NativeWriteReadiness.Unavailable,
                NativeWriteValidationState.Scaffold,
                RecoveryActive: false,
                RecoveryReason: null,
                LastCommitXid: null,
                NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
                LastRecoveryAction: null,
                DirtyTransactionCount: 0,
                ShutdownDrainActive: false,
                InFlightMutationCallbacks: 0,
                HostProcessId: 0,
                ValidationEvidence: null,
                FixtureLegacyFallbackActive: false,
                FixtureCompatibilityPathActive: false,
                UsesScaffoldCommitBlob: false,
                CommitStage: null,
                ReplayStage: null,
                CommitBlobMagic: null,
                CanonicalPathActive: null,
                CanonicalGateFailure: null
            )
            {
                MountReady = false,
            };
        }

        if (IsWriteBackendMode(configuredWriteBackend, "Native"))
        {
            return new HostRuntimeStatus(
                "Native",
                NativeWriteCommitModel.ScaffoldCheckpoint,
                NativeWriteReadiness.BootstrapReady,
                NativeWriteValidationState.Scaffold,
                RecoveryActive: false,
                RecoveryReason: null,
                LastCommitXid: null,
                NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
                LastRecoveryAction: null,
                DirtyTransactionCount: 0,
                ShutdownDrainActive: false,
                InFlightMutationCallbacks: 0,
                HostProcessId: 0,
                ValidationEvidence: null,
                FixtureLegacyFallbackActive: false,
                FixtureCompatibilityPathActive: false,
                UsesScaffoldCommitBlob: false,
                CommitStage: null,
                ReplayStage: null,
                CommitBlobMagic: null,
                CanonicalPathActive: null,
                CanonicalGateFailure: null
            )
            {
                MountReady = false,
            };
        }

        if (IsWriteBackendMode(configuredWriteBackend, "Overlay"))
        {
            return new HostRuntimeStatus(
                "Overlay",
                NativeWriteCommitModel.ScaffoldCheckpoint,
                NativeWriteReadiness.MutationReady,
                NativeWriteValidationState.Scaffold,
                RecoveryActive: false,
                RecoveryReason: null,
                LastCommitXid: null,
                NativeWriteSafetyState: NativeWriteSafetyState.PilotReadWrite,
                LastRecoveryAction: null,
                DirtyTransactionCount: 0,
                ShutdownDrainActive: false,
                InFlightMutationCallbacks: 0,
                HostProcessId: 0,
                ValidationEvidence: null,
                FixtureLegacyFallbackActive: false,
                FixtureCompatibilityPathActive: false,
                UsesScaffoldCommitBlob: false,
                CommitStage: null,
                ReplayStage: null,
                CommitBlobMagic: null,
                CanonicalPathActive: null,
                CanonicalGateFailure: null
            )
            {
                MountReady = false,
            };
        }

        return new HostRuntimeStatus(
            "Disabled",
            NativeWriteCommitModel.ScaffoldCheckpoint,
            NativeWriteReadiness.Unavailable,
            NativeWriteValidationState.Scaffold,
            RecoveryActive: false,
            RecoveryReason: null,
            LastCommitXid: null,
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
            LastRecoveryAction: null,
            DirtyTransactionCount: 0,
            ShutdownDrainActive: false,
            InFlightMutationCallbacks: 0,
            HostProcessId: 0,
            ValidationEvidence: null,
            FixtureLegacyFallbackActive: false,
            FixtureCompatibilityPathActive: false,
            UsesScaffoldCommitBlob: false,
            CommitStage: null,
            ReplayStage: null,
            CommitBlobMagic: null,
            CanonicalPathActive: null,
            CanonicalGateFailure: null
        )
        {
            MountReady = false,
        };
    }

    private static NativeWriteReadiness ParseNativeWriteReadiness(
        string? value,
        NativeWriteReadiness fallback
    )
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        return Enum.TryParse<NativeWriteReadiness>(value, ignoreCase: true, out var parsed)
            ? parsed
            : fallback;
    }

    private static NativeWriteSafetyState ParseNativeWriteSafetyState(
        string? value,
        NativeWriteSafetyState fallback
    )
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        return Enum.TryParse<NativeWriteSafetyState>(value, ignoreCase: true, out var parsed)
            ? parsed
            : fallback;
    }

    private static NativeWriteCommitModel ParseNativeWriteCommitModel(
        string? value,
        NativeWriteCommitModel fallback
    )
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        var trimmed = value.Trim();
        if (string.Equals(trimmed, "CanonicalApfsCheckpoint", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(trimmed, "CanonicalApfs", StringComparison.OrdinalIgnoreCase))
        {
            return NativeWriteCommitModel.CanonicalApfsCheckpoint;
        }

        if (string.Equals(trimmed, "ScaffoldCheckpoint", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(trimmed, "Scaffold", StringComparison.OrdinalIgnoreCase))
        {
            return NativeWriteCommitModel.ScaffoldCheckpoint;
        }

        return Enum.TryParse<NativeWriteCommitModel>(trimmed, ignoreCase: true, out var parsed)
            ? parsed
            : fallback;
    }

    private static NativeWriteValidationState ParseNativeWriteValidationState(
        string? value,
        NativeWriteValidationState fallback
    )
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        return Enum.TryParse<NativeWriteValidationState>(value, ignoreCase: true, out var parsed)
            ? parsed
            : fallback;
    }

    private static string? NormalizeRecoveryReason(string? value)
        => NativeWriteRecoveryReasons.Normalize(value);

    private static bool ShouldFailClosedForRuntimeStatus(HostRuntimeStatus status, string? recoveryPolicy)
    {
        return GetFailClosedReasonForRuntimeStatus(
                status,
                recoveryPolicy,
                int.MaxValue,
                isFixtureImage: true,
                disallowScaffoldCommitOnNonFixture: false,
                rejectScaffoldReplayBlobOnNonFixture: false,
                requireCanonicalReplayCandidateOnNonFixture: false) is not null;
    }

    private static string? GetNonFixtureCanonicalSafetyReason(
        HostRuntimeStatus status,
        bool disallowScaffoldCommitOnNonFixture,
        bool rejectScaffoldReplayBlobOnNonFixture,
        bool requireCanonicalReplayCandidateOnNonFixture)
    {
        var normalizedRecoveryReason = NormalizeRecoveryReason(status.RecoveryReason);
        var normalizedCanonicalGateFailure = NormalizeRecoveryReason(status.CanonicalGateFailure);
        if (ShouldPreserveExplicitRecoveryReasonBeforeCanonicalGate(normalizedRecoveryReason))
        {
            return normalizedRecoveryReason;
        }

        if (status.FixtureLegacyFallbackActive)
        {
            return "FixtureLegacyFallbackActive";
        }

        if (status.UsesScaffoldCommitBlob)
        {
            return "ScaffoldCommitBlobActive";
        }

        if (IsScaffoldCommitBlobMagic(status.CommitBlobMagic))
        {
            return "ScaffoldCommitBlobActive";
        }

        if (status.FixtureCompatibilityPathActive)
        {
            return "FixtureCompatibilityPathActive";
        }

        if (!string.IsNullOrWhiteSpace(normalizedCanonicalGateFailure))
        {
            return normalizedCanonicalGateFailure;
        }

        if (ShouldTreatReplayCheckpointTelemetryAsActiveFailure(status, normalizedRecoveryReason) &&
            status.ReplayCheckpointPendingWindow == true)
        {
            return "ReplayCheckpointPendingWindow";
        }

        if (ShouldTreatReplayCheckpointTelemetryAsActiveFailure(status, normalizedRecoveryReason) &&
            status.ReplayCheckpointCandidatePresent == true &&
            status.ReplayCheckpointPendingWindow == false)
        {
            return "ReplayCheckpointNotPendingWindow";
        }

        if (normalizedRecoveryReason is "ReplayCheckpointPendingWindow" or "ReplayCheckpointNotPendingWindow")
        {
            // Pending/non-pending replay-window signals are explicit runtime recovery outcomes and
            // should not be collapsed into canonical proof-gap fallbacks.
            return normalizedRecoveryReason;
        }

        if (string.Equals(normalizedRecoveryReason, "ReplayCanonicalCandidateMissing", StringComparison.Ordinal))
        {
            return "ReplayCanonicalCandidateMissing";
        }

        if (string.Equals(normalizedRecoveryReason, "IntegrityMissingAllocationMap", StringComparison.Ordinal))
        {
            return "IntegrityMissingAllocationMap";
        }

        if (status.CanonicalPathActive != true)
        {
            // Non-fixture production media always requires explicit canonical
            // path proof. Relaxed fixture/debug toggles must never bypass this
            // fail-closed requirement for production media.
            return "CanonicalPathNotActive";
        }

        return null;
    }

    private static bool ShouldTreatReplayCheckpointTelemetryAsActiveFailure(
        HostRuntimeStatus status,
        string? normalizedRecoveryReason)
    {
        if (normalizedRecoveryReason is "ReplayCheckpointPendingWindow" or "ReplayCheckpointNotPendingWindow")
        {
            return true;
        }

        if (status.RecoveryActive ||
            status.NativeWriteReadiness == NativeWriteReadiness.RecoveryMode ||
            status.NativeWriteSafetyState == NativeWriteSafetyState.RecoveryBlocked)
        {
            return true;
        }

        return !IsHealthyCanonicalNativeWriteStatus(status);
    }

    private static bool IsHealthyCanonicalNativeWriteStatus(HostRuntimeStatus status)
    {
        return string.Equals(status.WriteBackend, "Native", StringComparison.OrdinalIgnoreCase) &&
               status.CommitModel == NativeWriteCommitModel.CanonicalApfsCheckpoint &&
               status.NativeWriteReadiness == NativeWriteReadiness.CommitReady &&
               status.NativeWriteSafetyState != NativeWriteSafetyState.RecoveryBlocked &&
               !status.RecoveryActive &&
               string.IsNullOrWhiteSpace(NormalizeRecoveryReason(status.RecoveryReason)) &&
               status.CanonicalPathActive == true &&
               !status.FixtureLegacyFallbackActive &&
               !status.FixtureCompatibilityPathActive &&
               !status.UsesScaffoldCommitBlob &&
               !IsScaffoldCommitBlobMagic(status.CommitBlobMagic) &&
               string.IsNullOrWhiteSpace(NormalizeRecoveryReason(status.CanonicalGateFailure));
    }

    private static string? GetFailClosedReasonForRuntimeStatus(
        HostRuntimeStatus status,
        string? recoveryPolicy,
        int maxDirtyTransactions,
        bool isFixtureImage,
        bool disallowScaffoldCommitOnNonFixture,
        bool rejectScaffoldReplayBlobOnNonFixture,
        bool requireCanonicalReplayCandidateOnNonFixture)
    {
        var isNativeBackend = string.Equals(status.WriteBackend, "Native", StringComparison.OrdinalIgnoreCase);
        var isNativeNonFixture = isNativeBackend && !isFixtureImage;
        var normalizedRecoveryReason = NormalizeRecoveryReason(status.RecoveryReason);
        if (normalizedRecoveryReason is not null &&
            ShouldPreserveExplicitRecoveryReasonBeforeCanonicalGate(normalizedRecoveryReason))
        {
            return IsRecoveryPolicyFailClosed(recoveryPolicy) || isNativeNonFixture
                ? normalizedRecoveryReason
                : null;
        }
        if (isNativeBackend && status.FixtureLegacyFallbackActive)
        {
            if (isNativeNonFixture || IsRecoveryPolicyFailClosed(recoveryPolicy))
            {
                return "FixtureLegacyFallbackActive";
            }
        }

        if (isNativeNonFixture)
        {
            var nonFixtureSafetyReason = GetNonFixtureCanonicalSafetyReason(
                status,
                disallowScaffoldCommitOnNonFixture,
                rejectScaffoldReplayBlobOnNonFixture,
                requireCanonicalReplayCandidateOnNonFixture);
            if (!string.IsNullOrWhiteSpace(nonFixtureSafetyReason))
            {
                return nonFixtureSafetyReason;
            }
        }

        if (!IsRecoveryPolicyFailClosed(recoveryPolicy))
        {
            return null;
        }

        if (normalizedRecoveryReason is not null)
        {
            return normalizedRecoveryReason;
        }

        if (status.RecoveryActive)
        {
            return "RecoveryActive";
        }

        if (status.NativeWriteReadiness is NativeWriteReadiness.Degraded or NativeWriteReadiness.RecoveryMode ||
            status.NativeWriteSafetyState == NativeWriteSafetyState.RecoveryBlocked)
        {
            return "RecoveryRequired";
        }

        var dirtyLimit = Math.Max(1, maxDirtyTransactions);
        if (isNativeBackend && status.DirtyTransactionCount > dirtyLimit)
        {
            return "DirtyTransactionLimitExceeded";
        }

        return null;
    }

    private static string BuildRecoveryFailClosedGateState(string? recoveryReason)
    {
        return NormalizeRecoveryReason(recoveryReason) switch
        {
            "CommitTimedOut" => "RecoveryFailClosedCommitTimeout",
            "CommitNotWritable" => "RecoveryFailClosedCommitNotWritable",
            "CommitModelNotCanonical" => "RecoveryFailClosedCommitModelNotCanonical",
            "FixtureLegacyFallbackActive" => "RecoveryFailClosedFixtureFallback",
            "FixtureCompatibilityPathActive" => "RecoveryFailClosedFixtureCompatibilityPath",
            "ScaffoldCommitBlobActive" => "RecoveryFailClosedScaffoldCommitBlob",
            "CommitNotReady" => "RecoveryFailClosedCommitNotReady",
            "CommitAllocationFailed" => "RecoveryFailClosedAllocationFailed",
            "CommitInvariantFailed" => "RecoveryFailClosedInvariantFailed",
            "CommitPersistOrFlushFailed" => "RecoveryFailClosedCommitPersistFailed",
            "CommitInterruptedBeforeObjectMapPersist" => "RecoveryFailClosedCommitPersistFailed",
            "CommitObjectMapPersistFailed" => "RecoveryFailClosedCommitPersistFailed",
            "CommitObjectMapRoundTripFailed" => "RecoveryFailClosedCommitPersistFailed",
            "CommitInterruptedBeforeSpacemanPersist" => "RecoveryFailClosedCommitPersistFailed",
            "CommitSpacemanPersistFailed" => "RecoveryFailClosedCommitPersistFailed",
            "CommitSpacemanRoundTripFailed" => "RecoveryFailClosedCommitPersistFailed",
            "CommitInterruptedBeforeInodePersist" => "RecoveryFailClosedCommitPersistFailed",
            "CommitInodePersistFailed" => "RecoveryFailClosedCommitPersistFailed",
            "CommitInodeRoundTripFailed" => "RecoveryFailClosedCommitPersistFailed",
            "CommitInterruptedBeforeBtreePersist" => "RecoveryFailClosedCommitPersistFailed",
            "CommitBtreePersistFailed" => "RecoveryFailClosedCommitPersistFailed",
            "CommitBtreeRoundTripFailed" => "RecoveryFailClosedCommitPersistFailed",
            "CommitInterruptedBeforeReplayPersist" => "RecoveryFailClosedCommitPersistFailed",
            "CommitReplayPersistFailed" => "RecoveryFailClosedCommitPersistFailed",
            "CommitInterruptedBeforeReplayRoundTripVerify" => "RecoveryFailClosedCommitPersistFailed",
            "CommitReplayRoundTripFailed" => "RecoveryFailClosedCommitPersistFailed",
            "CommitInterruptedBeforeCheckpointSwitch" => "RecoveryFailClosedCommitPersistFailed",
            "CommitCheckpointWriteFailed" => "RecoveryFailClosedCommitPersistFailed",
            "CommitInterruptedBeforeCheckpointRoundTripVerify" => "RecoveryFailClosedCommitPersistFailed",
            "CommitCheckpointRoundTripFailed" => "RecoveryFailClosedCommitPersistFailed",
            "CommitInterruptedBeforeCheckpointFlush" => "RecoveryFailClosedCommitPersistFailed",
            "CommitCheckpointFlushFailed" => "RecoveryFailClosedCommitPersistFailed",
            "NativeWriteBootstrapFailed" => "RecoveryFailClosedBootstrap",
            "ContainerStateLoadFailed" => "RecoveryFailClosedBootstrap",
            "ObjectMapLoadFailed" => "RecoveryFailClosedBootstrap",
            "SpacemanStateLoadFailed" => "RecoveryFailClosedBootstrap",
            "VolumeStateLoadFailed" => "RecoveryFailClosedBootstrap",
            "PersistentStateLoadFailed" => "RecoveryFailClosedBootstrap",
            "RootStateInvalid" => "RecoveryFailClosedBootstrap",
            "IntegrityCheckFailedOnMount" => "RecoveryFailClosedIntegrity",
            "IntegrityMissingAllocationMap" => "RecoveryFailClosedIntegrityAllocationMap",
            "PersistentStateAheadOfSuperblock" => "RecoveryFailClosedReplay",
            "PersistentStateBehindSuperblock" => "RecoveryFailClosedReplay",
            "RecoveryLoadVolumeStateFailed" => "RecoveryFailClosedReplay",
            "RecoveryPersistentStateLoadFailed" => "RecoveryFailClosedReplay",
            "ReplayIntegrityCheckFailed" => "RecoveryFailClosedReplay",
            "ReplayMetadataStateMissing" => "RecoveryFailClosedReplay",
            "ReplayCanonicalCandidateMissing" => "RecoveryFailClosedReplay",
            "ReplayCheckpointPendingWindow" => "RecoveryFailClosedReplay",
            "ReplayCheckpointNotPendingWindow" => "RecoveryFailClosedReplay",
            "ReplayXidWindowInvalid" => "RecoveryFailClosedReplay",
            "ReplayCommitBlobInvalid" => "RecoveryFailClosedReplay",
            "ReplayCommitBlobReadFailed" => "RecoveryFailClosedReplay",
            "ReplayInterruptedBeforeCheckpointSwitch" => "RecoveryFailClosedReplay",
            "ReplayCheckpointWriteFailed" => "RecoveryFailClosedReplay",
            "ReplayInterruptedBeforeCheckpointFlush" => "RecoveryFailClosedReplay",
            "ReplayCheckpointFlushFailed" => "RecoveryFailClosedReplay",
            "RecoveryMarkerDirty" => "RecoveryFailClosedMarkerDirty",
            "RecoveryRequired" => "RecoveryFailClosedRecoveryRequired",
            "DirtyTransactionLimitExceeded" => "RecoveryFailClosedDirtyLimit",
            "NativeMutationStagingFailed" => "RecoveryFailClosedMutationStaging",
            "CanonicalPathNotActive" => "RecoveryFailClosedCanonicalPath",
            "CanonicalStateNotLoaded" => "RecoveryFailClosedCanonicalGate",
            "CanonicalVolumeStateLoadFailed" => "RecoveryFailClosedCanonicalGate",
            "CanonicalObjectMapStateInvalid" => "RecoveryFailClosedCanonicalGate",
            "CanonicalSpacemanStateInvalid" => "RecoveryFailClosedCanonicalGate",
            "CanonicalVolumeTreeStateInvalid" => "RecoveryFailClosedCanonicalGate",
            "NativeWriteNotReady" => "RecoveryFailClosedCanonicalGate",
            "WriteDeviceNotAllowed" => "RecoveryFailClosedCanonicalGate",
            "CommitPathNotReady" => "RecoveryFailClosedCanonicalGate",
            "CanonicalCommitNotReady" => "RecoveryFailClosedCanonicalGate",
            "ValidationEvidenceInsufficient" => "RecoveryFailClosedValidationEvidence",
            "ValidationCrashFaultEvidenceInsufficient" => "RecoveryFailClosedValidationCrashFaultEvidence",
            "ValidationCrashStageMatrixEvidenceInsufficient" => "RecoveryFailClosedValidationCrashMatrixEvidence",
            "ValidationHardwarePilotEvidenceInsufficient" => "RecoveryFailClosedValidationHardwarePilotEvidence",
            "ValidationHotUnplugEvidenceInsufficient" => "RecoveryFailClosedValidationHotUnplugEvidence",
            "ValidationCrossOsEvidenceInsufficient" => "RecoveryFailClosedValidationCrossOsEvidence",
            "ValidationMacOsEvidenceInsufficient" => "RecoveryFailClosedValidationMacOsEvidence",
            "ValidationMacOsConsistencyEvidenceInsufficient" => "RecoveryFailClosedValidationMacOsConsistencyEvidence",
            "ValidationPowerLossReplayEvidenceInsufficient" => "RecoveryFailClosedValidationPowerLossReplayEvidence",
            "ValidationPowerLossEvidenceInsufficient" => "RecoveryFailClosedValidationPowerLossEvidence",
            "ValidationCanonicalEvidenceInsufficient" => "RecoveryFailClosedValidationCanonicalEvidence",
            "ValidationHardwarePilotEvidenceStale" => "RecoveryFailClosedValidationHardwarePilotStale",
            "ValidationStableEvidenceStale" => "RecoveryFailClosedValidationStableStale",
            "WriteGateBlocked" => "RecoveryFailClosedWriteGate",
            _ => "RecoveryFailClosed",
        };
    }

    private static string BuildRecoveryFailClosedDiagnosticCode(string? recoveryReason)
    {
        return NormalizeRecoveryReason(recoveryReason) switch
        {
            "CommitTimedOut" => "NativeWriteCommitTimedOut",
            "CommitNotWritable" => "NativeWriteCommitNotWritable",
            "CommitModelNotCanonical" => "NativeWriteCommitModelNotCanonical",
            "FixtureLegacyFallbackActive" => "NativeWriteFixtureFallbackActive",
            "FixtureCompatibilityPathActive" => "NativeWriteFixtureCompatibilityPathActive",
            "ScaffoldCommitBlobActive" => "NativeWriteScaffoldCommitBlobActive",
            "CommitNotReady" => "NativeWriteCommitNotReady",
            "CommitAllocationFailed" => "NativeWriteCommitAllocationFailed",
            "CommitInvariantFailed" => "NativeWriteCommitInvariantFailed",
            "CommitPersistOrFlushFailed" => "NativeWriteCommitPersistFailed",
            "CommitInterruptedBeforeObjectMapPersist" => "NativeWriteCommitPersistFailed",
            "CommitObjectMapPersistFailed" => "NativeWriteCommitPersistFailed",
            "CommitObjectMapRoundTripFailed" => "NativeWriteCommitPersistFailed",
            "CommitInterruptedBeforeSpacemanPersist" => "NativeWriteCommitPersistFailed",
            "CommitSpacemanPersistFailed" => "NativeWriteCommitPersistFailed",
            "CommitSpacemanRoundTripFailed" => "NativeWriteCommitPersistFailed",
            "CommitInterruptedBeforeInodePersist" => "NativeWriteCommitPersistFailed",
            "CommitInodePersistFailed" => "NativeWriteCommitPersistFailed",
            "CommitInodeRoundTripFailed" => "NativeWriteCommitPersistFailed",
            "CommitInterruptedBeforeBtreePersist" => "NativeWriteCommitPersistFailed",
            "CommitBtreePersistFailed" => "NativeWriteCommitPersistFailed",
            "CommitBtreeRoundTripFailed" => "NativeWriteCommitPersistFailed",
            "CommitInterruptedBeforeReplayPersist" => "NativeWriteCommitPersistFailed",
            "CommitReplayPersistFailed" => "NativeWriteCommitPersistFailed",
            "CommitInterruptedBeforeReplayRoundTripVerify" => "NativeWriteCommitPersistFailed",
            "CommitReplayRoundTripFailed" => "NativeWriteCommitPersistFailed",
            "CommitInterruptedBeforeCheckpointSwitch" => "NativeWriteCommitPersistFailed",
            "CommitCheckpointWriteFailed" => "NativeWriteCommitPersistFailed",
            "CommitInterruptedBeforeCheckpointRoundTripVerify" => "NativeWriteCommitPersistFailed",
            "CommitCheckpointRoundTripFailed" => "NativeWriteCommitPersistFailed",
            "CommitInterruptedBeforeCheckpointFlush" => "NativeWriteCommitPersistFailed",
            "CommitCheckpointFlushFailed" => "NativeWriteCommitPersistFailed",
            "NativeWriteBootstrapFailed" => "NativeWriteBootstrapFailed",
            "ContainerStateLoadFailed" => "NativeWriteBootstrapFailed",
            "ObjectMapLoadFailed" => "NativeWriteBootstrapFailed",
            "SpacemanStateLoadFailed" => "NativeWriteBootstrapFailed",
            "VolumeStateLoadFailed" => "NativeWriteBootstrapFailed",
            "PersistentStateLoadFailed" => "NativeWriteBootstrapFailed",
            "RootStateInvalid" => "NativeWriteBootstrapFailed",
            "IntegrityCheckFailedOnMount" => "NativeWriteIntegrityCheckFailed",
            "IntegrityMissingAllocationMap" => "NativeWriteIntegrityMissingAllocationMap",
            "PersistentStateAheadOfSuperblock" => "NativeWriteReplayFailed",
            "PersistentStateBehindSuperblock" => "NativeWriteReplayFailed",
            "RecoveryLoadVolumeStateFailed" => "NativeWriteReplayFailed",
            "RecoveryPersistentStateLoadFailed" => "NativeWriteReplayFailed",
            "ReplayIntegrityCheckFailed" => "NativeWriteReplayFailed",
            "ReplayMetadataStateMissing" => "NativeWriteReplayFailed",
            "ReplayCanonicalCandidateMissing" => "NativeWriteReplayFailed",
            "ReplayCheckpointPendingWindow" => "NativeWriteReplayFailed",
            "ReplayCheckpointNotPendingWindow" => "NativeWriteReplayFailed",
            "ReplayXidWindowInvalid" => "NativeWriteReplayFailed",
            "ReplayCommitBlobInvalid" => "NativeWriteReplayFailed",
            "ReplayCommitBlobReadFailed" => "NativeWriteReplayFailed",
            "ReplayInterruptedBeforeCheckpointSwitch" => "NativeWriteReplayFailed",
            "ReplayCheckpointWriteFailed" => "NativeWriteReplayFailed",
            "ReplayInterruptedBeforeCheckpointFlush" => "NativeWriteReplayFailed",
            "ReplayCheckpointFlushFailed" => "NativeWriteReplayFailed",
            "RecoveryMarkerDirty" => "NativeWriteRecoveryMarkerDirty",
            "RecoveryRequired" => "NativeWriteRecoveryRequired",
            "DirtyTransactionLimitExceeded" => "NativeWriteDirtyTransactionLimitExceeded",
            "NativeMutationStagingFailed" => "NativeWriteMutationStagingFailed",
            "CanonicalPathNotActive" => "NativeWriteCanonicalPathNotActive",
            "CanonicalStateNotLoaded" => "NativeWriteCanonicalGateFailure",
            "CanonicalVolumeStateLoadFailed" => "NativeWriteCanonicalGateFailure",
            "CanonicalObjectMapStateInvalid" => "NativeWriteCanonicalGateFailure",
            "CanonicalSpacemanStateInvalid" => "NativeWriteCanonicalGateFailure",
            "CanonicalVolumeTreeStateInvalid" => "NativeWriteCanonicalGateFailure",
            "NativeWriteNotReady" => "NativeWriteCanonicalGateFailure",
            "WriteDeviceNotAllowed" => "NativeWriteCanonicalGateFailure",
            "CommitPathNotReady" => "NativeWriteCanonicalGateFailure",
            "CanonicalCommitNotReady" => "NativeWriteCanonicalGateFailure",
            "ValidationEvidenceInsufficient" => "NativeWriteValidationEvidenceInsufficient",
            "ValidationCrashFaultEvidenceInsufficient" => "NativeWriteValidationCrashFaultEvidenceInsufficient",
            "ValidationCrashStageMatrixEvidenceInsufficient" => "NativeWriteValidationCrashStageMatrixEvidenceInsufficient",
            "ValidationHardwarePilotEvidenceInsufficient" => "NativeWriteValidationHardwarePilotEvidenceInsufficient",
            "ValidationHotUnplugEvidenceInsufficient" => "NativeWriteValidationHotUnplugEvidenceInsufficient",
            "ValidationCrossOsEvidenceInsufficient" => "NativeWriteValidationCrossOsEvidenceInsufficient",
            "ValidationMacOsEvidenceInsufficient" => "NativeWriteValidationMacOsEvidenceInsufficient",
            "ValidationMacOsConsistencyEvidenceInsufficient" => "NativeWriteValidationMacOsConsistencyEvidenceInsufficient",
            "ValidationPowerLossReplayEvidenceInsufficient" => "NativeWriteValidationPowerLossReplayEvidenceInsufficient",
            "ValidationPowerLossEvidenceInsufficient" => "NativeWriteValidationPowerLossEvidenceInsufficient",
            "ValidationCanonicalEvidenceInsufficient" => "NativeWriteValidationCanonicalEvidenceInsufficient",
            "ValidationHardwarePilotEvidenceStale" => "NativeWriteValidationHardwarePilotEvidenceStale",
            "ValidationStableEvidenceStale" => "NativeWriteValidationStableEvidenceStale",
            "WriteGateBlocked" => "NativeWriteGateBlocked",
            _ => "NativeWriteRecoveryFailClosed",
        };
    }

    private static string DescribeRecoveryReason(string? recoveryReason)
    {
        return NormalizeRecoveryReason(recoveryReason) switch
        {
            "CommitTimedOut" => "a write transaction exceeded the configured commit timeout",
            "CommitNotWritable" => "the native write path is no longer writable",
            "CommitModelNotCanonical" => "the native commit path is not using canonical APFS checkpoint semantics",
            "FixtureLegacyFallbackActive" => "native runtime entered legacy fixture-fallback mode and write path was blocked",
            "FixtureCompatibilityPathActive" => "native runtime reported fixture compatibility path activity on non-fixture media and write mode was blocked",
            "ScaffoldCommitBlobActive" => "native runtime reported scaffold commit-blob mode on non-fixture media and write path was blocked",
            "CommitNotReady" => "the native write engine is not ready to commit",
            "CommitAllocationFailed" => "allocation failed while committing metadata",
            "CommitInvariantFailed" => "commit invariants failed and the write path was blocked",
            "CommitPersistOrFlushFailed" => "commit persistence or flush failed",
            "CommitInterruptedBeforeObjectMapPersist" => "commit was interrupted before object-map checkpoint persistence",
            "CommitObjectMapPersistFailed" => "object-map checkpoint persistence failed during commit",
            "CommitObjectMapRoundTripFailed" => "object-map checkpoint round-trip validation failed after commit persistence",
            "CommitInterruptedBeforeSpacemanPersist" => "commit was interrupted before spaceman checkpoint persistence",
            "CommitSpacemanPersistFailed" => "spaceman checkpoint persistence failed during commit",
            "CommitSpacemanRoundTripFailed" => "spaceman checkpoint round-trip validation failed after commit persistence",
            "CommitInterruptedBeforeInodePersist" => "commit was interrupted before inode checkpoint persistence",
            "CommitInodePersistFailed" => "inode checkpoint persistence failed during commit",
            "CommitInodeRoundTripFailed" => "inode checkpoint round-trip validation failed after commit persistence",
            "CommitInterruptedBeforeBtreePersist" => "commit was interrupted before btree checkpoint persistence",
            "CommitBtreePersistFailed" => "btree checkpoint persistence failed during commit",
            "CommitBtreeRoundTripFailed" => "btree checkpoint round-trip validation failed after commit persistence",
            "CommitInterruptedBeforeReplayPersist" => "commit was interrupted before replay metadata checkpoint persistence",
            "CommitReplayPersistFailed" => "replay metadata checkpoint persistence failed during commit",
            "CommitInterruptedBeforeReplayRoundTripVerify" => "commit was interrupted before replay metadata checkpoint round-trip verification",
            "CommitReplayRoundTripFailed" => "replay metadata checkpoint round-trip validation failed after commit persistence",
            "CommitInterruptedBeforeCheckpointSwitch" => "commit was interrupted before checkpoint switch",
            "CommitCheckpointWriteFailed" => "checkpoint write failed during commit",
            "CommitInterruptedBeforeCheckpointRoundTripVerify" => "commit was interrupted before checkpoint superblock round-trip verification",
            "CommitCheckpointRoundTripFailed" => "checkpoint superblock round-trip validation failed after checkpoint switch",
            "CommitInterruptedBeforeCheckpointFlush" => "commit was interrupted before checkpoint flush",
            "CommitCheckpointFlushFailed" => "checkpoint flush failed during commit",
            "NativeWriteBootstrapFailed" => "native write bootstrap failed before the mount entered commit-ready state",
            "ContainerStateLoadFailed" => "container superblock state could not be loaded for native write mode",
            "ObjectMapLoadFailed" => "object-map state could not be loaded for native write mode",
            "SpacemanStateLoadFailed" => "spaceman allocation state could not be loaded for native write mode",
            "VolumeStateLoadFailed" => "volume state load failed during native write bootstrap",
            "PersistentStateLoadFailed" => "persistent native-write state could not be loaded",
            "RootStateInvalid" => "root inode/path state was invalid during bootstrap",
            "IntegrityCheckFailedOnMount" => "mount-time integrity checks failed and write mode was blocked",
            "IntegrityMissingAllocationMap" => "native write cannot prove the APFS spaceman allocation map for existing file extents, so physical-media writes are blocked",
            "PersistentStateAheadOfSuperblock" => "persistent state checkpoint xid is ahead of superblock checkpoint and requires replay",
            "PersistentStateBehindSuperblock" => "persistent state checkpoint xid is behind superblock checkpoint and requires conservative recovery",
            "RecoveryLoadVolumeStateFailed" => "recovery could not load volume state for replay evaluation",
            "RecoveryPersistentStateLoadFailed" => "recovery could not load persistent state metadata",
            "ReplayIntegrityCheckFailed" => "replay safety checks failed integrity validation",
            "ReplayMetadataStateMissing" => "replay metadata was incomplete or missing",
            "ReplayCanonicalCandidateMissing" => "canonical replay candidates were missing for non-fixture recovery",
            "ReplayCheckpointPendingWindow" => "replay checkpoint metadata indicates pending recovery and requires replay before writes can continue",
            "ReplayCheckpointNotPendingWindow" => "replay checkpoint metadata was present but did not describe a pending recovery window",
            "ReplayXidWindowInvalid" => "replay xid state did not match the expected checkpoint window",
            "ReplayCommitBlobInvalid" => "replay commit-blob metadata was invalid",
            "ReplayCommitBlobReadFailed" => "replay commit-blob payload could not be read from media",
            "ReplayInterruptedBeforeCheckpointSwitch" => "replay was interrupted before checkpoint switch",
            "ReplayCheckpointWriteFailed" => "replay failed while writing the checkpoint superblock",
            "ReplayInterruptedBeforeCheckpointFlush" => "replay was interrupted before checkpoint flush",
            "ReplayCheckpointFlushFailed" => "replay failed while flushing checkpoint changes",
            "RecoveryMarkerDirty" => "a previous write session ended before cleanup finished",
            "RecoveryRequired" => "native recovery is required before writes can resume",
            "DirtyTransactionLimitExceeded" => "pending native-write dirty transaction count exceeded the configured safety limit",
            "NativeMutationStagingFailed" => "native metadata staging failed while processing a file operation",
            "CanonicalPathNotActive" => "canonical non-fixture native write path proof was not active and write mode was blocked",
            "CanonicalStateNotLoaded" => "canonical non-fixture write path state was not fully loaded; explicit canonical gate blocked writable mode",
            "CanonicalVolumeStateLoadFailed" => "canonical volume state could not be loaded for non-fixture writable mode",
            "CanonicalObjectMapStateInvalid" => "canonical object-map state failed validation for non-fixture writable mode",
            "CanonicalSpacemanStateInvalid" => "canonical spaceman/free-space state failed validation for non-fixture writable mode",
            "CanonicalVolumeTreeStateInvalid" => "canonical volume tree state failed validation for non-fixture writable mode",
            "NativeWriteNotReady" => "native write path is not ready for canonical commit and was blocked by canonical gate policy",
            "WriteDeviceNotAllowed" => "device is not allow-listed for canonical writable mode and was blocked by canonical gate policy",
            "CommitPathNotReady" => "commit path readiness checks failed canonical gate validation",
            "CanonicalCommitNotReady" => "canonical commit readiness checks did not pass, so writable mode was blocked",
            "ValidationEvidenceInsufficient" => "native write validation evidence did not meet the configured promotion threshold",
            "ValidationCrashFaultEvidenceInsufficient" => "native write crash-fault evidence does not meet the configured promotion threshold",
            "ValidationCrashStageMatrixEvidenceInsufficient" => "native write crash-stage matrix evidence does not meet the configured promotion threshold",
            "ValidationHardwarePilotEvidenceInsufficient" => "native write hardware-pilot evidence does not meet the configured promotion threshold",
            "ValidationHotUnplugEvidenceInsufficient" => "native write hot-unplug evidence does not meet the configured promotion threshold",
            "ValidationCrossOsEvidenceInsufficient" => "native write cross-OS validation evidence does not meet the configured promotion threshold",
            "ValidationMacOsEvidenceInsufficient" => "native write macOS validation evidence does not meet the configured stable threshold",
            "ValidationMacOsConsistencyEvidenceInsufficient" => "native write macOS consistency evidence does not meet the configured stable threshold",
            "ValidationPowerLossReplayEvidenceInsufficient" => "native write power-loss replay evidence does not meet the configured stable threshold",
            "ValidationPowerLossEvidenceInsufficient" => "native write power-loss evidence does not meet the configured stable threshold",
            "ValidationCanonicalEvidenceInsufficient" => "native write canonical-image validation evidence is not sufficient for promotion",
            "ValidationHardwarePilotEvidenceStale" => "native write hardware-pilot validation evidence is stale and must be revalidated on physical media",
            "ValidationStableEvidenceStale" => "native write stable validation evidence is stale and must be refreshed before stable writable mounts",
            "WriteGateBlocked" => "write-gate policy no longer allows writable mode for this volume/device",
            _ => "native recovery safeguards blocked write mode",
        };
    }

    private static ulong? NormalizeLastCommitXid(ulong? value)
    {
        if (!value.HasValue || value.Value == 0)
        {
            return null;
        }

        return value;
    }

    private static string? NormalizeLastRecoveryAction(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.Trim();
    }

    private static string? NormalizeDiagnosticToken(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.Trim();
    }

    private static bool IsScaffoldCommitBlobMagic(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var token = value.Trim();
        return string.Equals(token, "APFSRWSCAFF2", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(token, "APFSRWSCAFF3", StringComparison.OrdinalIgnoreCase);
    }

    private static int NormalizeDirtyTransactionCount(int? value)
    {
        if (!value.HasValue || value.Value < 0)
        {
            return 0;
        }

        return value.Value;
    }

    private static int NormalizeInFlightMutationCallbacks(int? value)
    {
        if (!value.HasValue || value.Value < 0)
        {
            return 0;
        }

        return value.Value;
    }

    private static int NormalizeHostProcessId(int value)
    {
        return value > 0
            ? value
            : 0;
    }

    private static NativeWriteValidationEvidence? ParseValidationEvidenceFromPayload(
        HostRuntimeStatusPayload payload,
        NativeWriteValidationEvidence? fallback)
    {
        var payloadHasEvidenceSignal =
            payload.ValidationCrashFaultPasses.HasValue ||
            payload.ValidationCrashStageMatrixPasses.HasValue ||
            payload.ValidationHardwarePilotPasses.HasValue ||
            payload.ValidationHotUnplugPasses.HasValue ||
            payload.ValidationMacOsValidationPasses.HasValue ||
            payload.ValidationMacOsConsistencyPasses.HasValue ||
            payload.ValidationPowerLossReplayPasses.HasValue ||
            payload.ValidationPowerLossPassVerified.HasValue ||
            !string.IsNullOrWhiteSpace(payload.ValidationLastValidatedUtc) ||
            !string.IsNullOrWhiteSpace(payload.ValidationLastValidationProfileId);

        if (!payloadHasEvidenceSignal && fallback is null)
        {
            return null;
        }

        var baseline = NormalizeValidationEvidence(fallback);
        var crashFaultPasses = payload.ValidationCrashFaultPasses.HasValue
            ? Math.Max(0, payload.ValidationCrashFaultPasses.Value)
            : baseline.CrashFaultPasses;
        var crashStageMatrixPasses = payload.ValidationCrashStageMatrixPasses.HasValue
            ? Math.Max(0, payload.ValidationCrashStageMatrixPasses.Value)
            : baseline.CrashStageMatrixPasses;
        var hardwarePilotPasses = payload.ValidationHardwarePilotPasses.HasValue
            ? Math.Max(0, payload.ValidationHardwarePilotPasses.Value)
            : baseline.HardwarePilotPasses;
        var hotUnplugPasses = payload.ValidationHotUnplugPasses.HasValue
            ? Math.Max(0, payload.ValidationHotUnplugPasses.Value)
            : baseline.HotUnplugPasses;
        var macOsValidationPasses = payload.ValidationMacOsValidationPasses.HasValue
            ? Math.Max(0, payload.ValidationMacOsValidationPasses.Value)
            : baseline.MacOsValidationPasses;
        var macOsConsistencyPasses = payload.ValidationMacOsConsistencyPasses.HasValue
            ? Math.Max(0, payload.ValidationMacOsConsistencyPasses.Value)
            : baseline.MacOsConsistencyPasses;
        var powerLossReplayPasses = payload.ValidationPowerLossReplayPasses.HasValue
            ? Math.Max(0, payload.ValidationPowerLossReplayPasses.Value)
            : baseline.PowerLossReplayPasses;
        var powerLossPassVerified = payload.ValidationPowerLossPassVerified ?? baseline.PowerLossPassVerified;
        var lastValidatedUtc = ParseValidationLastValidatedUtc(payload.ValidationLastValidatedUtc) ?? baseline.LastValidatedUtc;
        var lastValidationProfileId = NormalizeDiagnosticToken(payload.ValidationLastValidationProfileId) ??
                                      baseline.LastValidationProfileId;

        var parsed = new NativeWriteValidationEvidence(
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

        return HasValidationEvidenceSignal(parsed) || fallback is not null
            ? parsed
            : null;
    }

    private static DateTime? ParseValidationLastValidatedUtc(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var token = value.Trim();
        if (!DateTime.TryParse(
                token,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            return null;
        }

        return parsed.Kind switch
        {
            DateTimeKind.Utc => parsed,
            DateTimeKind.Local => parsed.ToUniversalTime(),
            _ => DateTime.SpecifyKind(parsed, DateTimeKind.Utc),
        };
    }

    private static bool HasValidationEvidenceSignal(NativeWriteValidationEvidence value)
    {
        var normalized = NormalizeValidationEvidence(value);
        return normalized.CrashFaultPasses > 0 ||
               normalized.CrashStageMatrixPasses > 0 ||
               normalized.HardwarePilotPasses > 0 ||
               normalized.HotUnplugPasses > 0 ||
               normalized.MacOsValidationPasses > 0 ||
               normalized.MacOsConsistencyPasses > 0 ||
               normalized.PowerLossReplayPasses > 0 ||
               normalized.PowerLossPassVerified ||
               normalized.LastValidatedUtc.HasValue ||
               !string.IsNullOrWhiteSpace(normalized.LastValidationProfileId);
    }

    private static NativeWriteSafetyState DeriveSafetyState(
        MountAccessMode accessMode,
        string writeBackend,
        NativeWriteReadiness readiness,
        bool recoveryActive,
        NativeWriteSafetyState fallback = NativeWriteSafetyState.ReadOnlyFallback
    )
    {
        if (accessMode != MountAccessMode.ReadWrite ||
            string.Equals(writeBackend, "Disabled", StringComparison.OrdinalIgnoreCase))
        {
            return NativeWriteSafetyState.ReadOnlyFallback;
        }

        if (recoveryActive || readiness is NativeWriteReadiness.Degraded or NativeWriteReadiness.RecoveryMode)
        {
            return NativeWriteSafetyState.RecoveryBlocked;
        }

        if (fallback == NativeWriteSafetyState.StableReadWrite)
        {
            return NativeWriteSafetyState.StableReadWrite;
        }

        return NativeWriteSafetyState.PilotReadWrite;
    }

    private static string? DeriveLastRecoveryAction(string? recoveryReason, string? explicitAction)
    {
        var normalizedExplicit = NormalizeLastRecoveryAction(explicitAction);
        if (!string.IsNullOrWhiteSpace(normalizedExplicit))
        {
            return normalizedExplicit;
        }

        return NormalizeRecoveryReason(recoveryReason) switch
        {
            "CommitTimedOut" => "DowngradedAfterCommitTimeout",
            "CommitNotWritable" => "DowngradedAfterNotWritable",
            "CommitModelNotCanonical" => "DowngradedAfterCommitModelMismatch",
            "FixtureLegacyFallbackActive" => "DowngradedAfterFixtureFallback",
            "FixtureCompatibilityPathActive" => "DowngradedAfterFixtureCompatibilityPath",
            "ScaffoldCommitBlobActive" => "DowngradedAfterScaffoldCommitBlob",
            "CommitNotReady" => "DowngradedAfterNotReady",
            "CommitAllocationFailed" => "DowngradedAfterAllocationFailure",
            "CommitInvariantFailed" => "DowngradedAfterInvariantFailure",
            "CommitPersistOrFlushFailed" => "DowngradedAfterPersistFailure",
            "CommitInterruptedBeforeObjectMapPersist" => "DowngradedAfterPersistFailure",
            "CommitObjectMapPersistFailed" => "DowngradedAfterPersistFailure",
            "CommitObjectMapRoundTripFailed" => "DowngradedAfterPersistFailure",
            "CommitInterruptedBeforeSpacemanPersist" => "DowngradedAfterPersistFailure",
            "CommitSpacemanPersistFailed" => "DowngradedAfterPersistFailure",
            "CommitSpacemanRoundTripFailed" => "DowngradedAfterPersistFailure",
            "CommitInterruptedBeforeInodePersist" => "DowngradedAfterPersistFailure",
            "CommitInodePersistFailed" => "DowngradedAfterPersistFailure",
            "CommitInodeRoundTripFailed" => "DowngradedAfterPersistFailure",
            "CommitInterruptedBeforeBtreePersist" => "DowngradedAfterPersistFailure",
            "CommitBtreePersistFailed" => "DowngradedAfterPersistFailure",
            "CommitBtreeRoundTripFailed" => "DowngradedAfterPersistFailure",
            "CommitInterruptedBeforeReplayPersist" => "DowngradedAfterPersistFailure",
            "CommitReplayPersistFailed" => "DowngradedAfterPersistFailure",
            "CommitInterruptedBeforeReplayRoundTripVerify" => "DowngradedAfterPersistFailure",
            "CommitReplayRoundTripFailed" => "DowngradedAfterPersistFailure",
            "CommitInterruptedBeforeCheckpointSwitch" => "DowngradedAfterCheckpointInterruption",
            "CommitCheckpointWriteFailed" => "DowngradedAfterCheckpointWriteFailure",
            "CommitInterruptedBeforeCheckpointRoundTripVerify" => "DowngradedAfterCheckpointInterruption",
            "CommitCheckpointRoundTripFailed" => "DowngradedAfterCheckpointWriteFailure",
            "CommitInterruptedBeforeCheckpointFlush" => "DowngradedAfterCheckpointInterruption",
            "CommitCheckpointFlushFailed" => "DowngradedAfterCheckpointFlushFailure",
            "NativeWriteBootstrapFailed" => "BootstrapFailClosed",
            "ContainerStateLoadFailed" => "BootstrapFailClosed",
            "ObjectMapLoadFailed" => "BootstrapFailClosed",
            "SpacemanStateLoadFailed" => "BootstrapFailClosed",
            "VolumeStateLoadFailed" => "BootstrapFailClosed",
            "PersistentStateLoadFailed" => "BootstrapFailClosed",
            "RootStateInvalid" => "BootstrapFailClosed",
            "IntegrityCheckFailedOnMount" => "BootstrapIntegrityBlocked",
            "IntegrityMissingAllocationMap" => "BootstrapIntegrityMissingAllocationMap",
            "PersistentStateAheadOfSuperblock" => "ReplaySkippedFailClosed",
            "PersistentStateBehindSuperblock" => "ReplaySkippedFailClosed",
            "RecoveryLoadVolumeStateFailed" => "ReplaySkippedFailClosed",
            "RecoveryPersistentStateLoadFailed" => "ReplaySkippedFailClosed",
            "ReplayIntegrityCheckFailed" => "ReplaySkippedFailClosed",
            "ReplayMetadataStateMissing" => "ReplaySkippedFailClosed",
            "ReplayCanonicalCandidateMissing" => "ReplaySkippedFailClosed",
            "ReplayCheckpointPendingWindow" => "ReplaySkippedFailClosed",
            "ReplayCheckpointNotPendingWindow" => "ReplaySkippedFailClosed",
            "ReplayXidWindowInvalid" => "ReplaySkippedFailClosed",
            "ReplayCommitBlobInvalid" => "ReplaySkippedFailClosed",
            "ReplayCommitBlobReadFailed" => "ReplaySkippedFailClosed",
            "ReplayInterruptedBeforeCheckpointSwitch" => "ReplaySkippedFailClosed",
            "ReplayCheckpointWriteFailed" => "ReplaySkippedFailClosed",
            "ReplayInterruptedBeforeCheckpointFlush" => "ReplaySkippedFailClosed",
            "ReplayCheckpointFlushFailed" => "ReplaySkippedFailClosed",
            "RecoveryMarkerDirty" => "RecoveryMarkerDetected",
            "RecoveryRequired" => "RecoveryRequiredBlock",
            "DirtyTransactionLimitExceeded" => "DowngradedAfterDirtyTransactionLimit",
            "NativeMutationStagingFailed" => "DowngradedAfterMutationStagingFailure",
            "CanonicalPathNotActive" => "DowngradedAfterCanonicalPathProofMissing",
            "CanonicalStateNotLoaded" => "DowngradedAfterCanonicalGateFailure",
            "CanonicalVolumeStateLoadFailed" => "DowngradedAfterCanonicalGateFailure",
            "CanonicalObjectMapStateInvalid" => "DowngradedAfterCanonicalGateFailure",
            "CanonicalSpacemanStateInvalid" => "DowngradedAfterCanonicalGateFailure",
            "CanonicalVolumeTreeStateInvalid" => "DowngradedAfterCanonicalGateFailure",
            "NativeWriteNotReady" => "DowngradedAfterCanonicalGateFailure",
            "WriteDeviceNotAllowed" => "DowngradedAfterCanonicalGateFailure",
            "CommitPathNotReady" => "DowngradedAfterCanonicalGateFailure",
            "CanonicalCommitNotReady" => "DowngradedAfterCanonicalGateFailure",
            "ValidationEvidenceInsufficient" => "DowngradedAfterValidationEvidenceGate",
            "ValidationCrashFaultEvidenceInsufficient" => "DowngradedAfterValidationCrashFaultGate",
            "ValidationCrashStageMatrixEvidenceInsufficient" => "DowngradedAfterValidationCrashMatrixGate",
            "ValidationHardwarePilotEvidenceInsufficient" => "DowngradedAfterValidationHardwarePilotGate",
            "ValidationHotUnplugEvidenceInsufficient" => "DowngradedAfterValidationHotUnplugGate",
            "ValidationCrossOsEvidenceInsufficient" => "DowngradedAfterValidationCrossOsGate",
            "ValidationMacOsEvidenceInsufficient" => "DowngradedAfterValidationMacOsGate",
            "ValidationMacOsConsistencyEvidenceInsufficient" => "DowngradedAfterValidationMacOsConsistencyGate",
            "ValidationPowerLossReplayEvidenceInsufficient" => "DowngradedAfterValidationPowerLossReplayGate",
            "ValidationPowerLossEvidenceInsufficient" => "DowngradedAfterValidationPowerLossGate",
            "ValidationCanonicalEvidenceInsufficient" => "DowngradedAfterValidationCanonicalGate",
            "ValidationHardwarePilotEvidenceStale" => "DowngradedAfterValidationHardwarePilotStale",
            "ValidationStableEvidenceStale" => "DowngradedAfterValidationStableStale",
            "WriteGateBlocked" => "DowngradedAfterWriteGatePolicy",
            _ => null,
        };
    }

    private static HostRuntimeStatus BuildHostRuntimeStatusFromPayload(
        HostRuntimeStatusPayload payload,
        MountAccessMode accessMode,
        HostRuntimeStatus fallback
    )
    {
        var recoveryReason = NormalizeRecoveryReason(payload.RecoveryReason);
        var recoverySignaled = HasRecoverySignal(recoveryReason);
        var lastCommitXid = NormalizeLastCommitXid(payload.LastCommitXid);
        var dirtyTransactionCount = NormalizeDirtyTransactionCount(payload.DirtyTransactionCount);
        var shutdownDrainActive = payload.ShutdownDrainActive ?? false;
        var inFlightMutationCallbacks = NormalizeInFlightMutationCallbacks(payload.InFlightMutationCallbacks);
        var hostProcessId = NormalizeHostProcessId(payload.HostPid ?? fallback.HostProcessId);
        var fixtureLegacyFallbackActive = payload.FixtureLegacyFallbackActive ?? fallback.FixtureLegacyFallbackActive;
        var fixtureCompatibilityPathActive = payload.FixtureCompatibilityPathActive ?? fallback.FixtureCompatibilityPathActive;
        var usesScaffoldCommitBlob = payload.UsesScaffoldCommitBlob ?? fallback.UsesScaffoldCommitBlob;
        if (!payload.FixtureLegacyFallbackActive.HasValue &&
            string.Equals(recoveryReason, "FixtureLegacyFallbackActive", StringComparison.Ordinal))
        {
            fixtureLegacyFallbackActive = true;
        }
        if (!payload.FixtureCompatibilityPathActive.HasValue &&
            string.Equals(recoveryReason, "FixtureCompatibilityPathActive", StringComparison.Ordinal))
        {
            fixtureCompatibilityPathActive = true;
        }
        if (!payload.UsesScaffoldCommitBlob.HasValue &&
            string.Equals(recoveryReason, "ScaffoldCommitBlobActive", StringComparison.Ordinal))
        {
            usesScaffoldCommitBlob = true;
        }
        var lastRecoveryAction = DeriveLastRecoveryAction(recoveryReason, payload.LastRecoveryAction);
        var commitStage = NormalizeDiagnosticToken(payload.CommitStage);
        var replayStage = NormalizeDiagnosticToken(payload.ReplayStage);
        var commitBlobMagic = NormalizeDiagnosticToken(payload.CommitBlobMagic);
        var canonicalPathActive = payload.CanonicalPathActive;
        var canonicalGateFailure = NormalizeRecoveryReason(payload.CanonicalGateFailure);
        if (string.IsNullOrWhiteSpace(canonicalGateFailure) &&
            IsCanonicalGateFailureReason(recoveryReason))
        {
            canonicalGateFailure = recoveryReason;
        }
        if (!canonicalPathActive.HasValue &&
            !string.IsNullOrWhiteSpace(canonicalGateFailure))
        {
            canonicalPathActive = false;
        }
        var replayCheckpointCandidatePresent = payload.ReplayCheckpointCandidatePresent;
        var replayCheckpointPendingWindow = payload.ReplayCheckpointPendingWindow;
        var mountReady = payload.MountReady ?? fallback.MountReady;
        var parsedCommitModel = ParseNativeWriteCommitModel(payload.CommitModel, fallback.CommitModel);
        var parsedValidationState = ParseNativeWriteValidationState(
            payload.NativeWriteValidationState,
            fallback.NativeWriteValidationState);
        var parsedValidationEvidence = ParseValidationEvidenceFromPayload(
            payload,
            fallback.ValidationEvidence);

        if (accessMode != MountAccessMode.ReadWrite)
        {
            return new HostRuntimeStatus(
                WriteBackend: "Disabled",
                CommitModel: NativeWriteCommitModel.ScaffoldCheckpoint,
                NativeWriteReadiness: NativeWriteReadiness.Unavailable,
                NativeWriteValidationState: NativeWriteValidationState.Scaffold,
                RecoveryActive: payload.RecoveryActive || recoverySignaled,
                RecoveryReason: recoveryReason,
                LastCommitXid: lastCommitXid,
                NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
                LastRecoveryAction: lastRecoveryAction,
                DirtyTransactionCount: dirtyTransactionCount,
                ShutdownDrainActive: shutdownDrainActive,
                InFlightMutationCallbacks: inFlightMutationCallbacks,
                HostProcessId: hostProcessId,
                ValidationEvidence: parsedValidationEvidence,
                FixtureLegacyFallbackActive: false,
                FixtureCompatibilityPathActive: false,
                UsesScaffoldCommitBlob: false,
                CommitStage: null,
                ReplayStage: null,
                CommitBlobMagic: null,
                CanonicalPathActive: null,
                CanonicalGateFailure: null
            )
            {
                ReplayCheckpointCandidatePresent = null,
                ReplayCheckpointPendingWindow = null,
                MountReady = mountReady,
            };
        }

        var backend = NormalizeWriteBackendName(payload.WriteBackend);
        if (string.Equals(backend, "Disabled", StringComparison.OrdinalIgnoreCase))
        {
            backend = fallback.WriteBackend;
        }

        if (string.Equals(backend, "Native", StringComparison.OrdinalIgnoreCase))
        {
            var readinessFallback = string.Equals(fallback.WriteBackend, "Native", StringComparison.OrdinalIgnoreCase)
                ? fallback.NativeWriteReadiness
                : NativeWriteReadiness.BootstrapReady;
            var readiness = ParseNativeWriteReadiness(payload.NativeWriteReadiness, readinessFallback);
            var recoveryActive = payload.RecoveryActive ||
                                 recoverySignaled ||
                                 readiness is NativeWriteReadiness.Degraded or NativeWriteReadiness.RecoveryMode;
            var safetyState = ParseNativeWriteSafetyState(
                payload.NativeWriteSafetyState,
                DeriveSafetyState(accessMode, backend, readiness, recoveryActive, fallback.NativeWriteSafetyState)
            );
            if (safetyState == NativeWriteSafetyState.RecoveryBlocked)
            {
                recoveryActive = true;
            }
            if (recoveryActive)
            {
                safetyState = NativeWriteSafetyState.RecoveryBlocked;
            }
            else if (readiness is NativeWriteReadiness.Degraded or NativeWriteReadiness.RecoveryMode)
            {
                safetyState = NativeWriteSafetyState.RecoveryBlocked;
            }
            var clampedValidationState = ClampReportedValidationState(
                parsedValidationState,
                parsedCommitModel,
                readiness,
                recoveryActive);
            return new HostRuntimeStatus(
                backend,
                parsedCommitModel,
                readiness,
                clampedValidationState,
                recoveryActive,
                recoveryReason,
                lastCommitXid,
                safetyState,
                lastRecoveryAction,
                dirtyTransactionCount,
                shutdownDrainActive,
                inFlightMutationCallbacks,
                hostProcessId,
                parsedValidationEvidence,
                fixtureLegacyFallbackActive,
                fixtureCompatibilityPathActive,
                usesScaffoldCommitBlob,
                commitStage,
                replayStage,
                commitBlobMagic,
                canonicalPathActive,
                canonicalGateFailure
            )
            {
                ReplayCheckpointCandidatePresent = replayCheckpointCandidatePresent,
                ReplayCheckpointPendingWindow = replayCheckpointPendingWindow,
                MountReady = mountReady,
            };
        }

        if (string.Equals(backend, "Overlay", StringComparison.OrdinalIgnoreCase))
        {
            var readiness = ParseNativeWriteReadiness(
                payload.NativeWriteReadiness,
                NativeWriteReadiness.MutationReady
            );
            if ((int)readiness > (int)NativeWriteReadiness.MutationReady)
            {
                readiness = NativeWriteReadiness.MutationReady;
            }

            var recoveryActive = payload.RecoveryActive || recoverySignaled;
            var safetyState = ParseNativeWriteSafetyState(
                payload.NativeWriteSafetyState,
                DeriveSafetyState(accessMode, backend, readiness, recoveryActive, fallback.NativeWriteSafetyState)
            );
            return new HostRuntimeStatus(
                backend,
                NativeWriteCommitModel.ScaffoldCheckpoint,
                readiness,
                NativeWriteValidationState.Scaffold,
                recoveryActive,
                recoveryReason,
                lastCommitXid,
                safetyState,
                lastRecoveryAction,
                dirtyTransactionCount,
                shutdownDrainActive,
                inFlightMutationCallbacks,
                hostProcessId,
                parsedValidationEvidence,
                false,
                false,
                false,
                null,
                null,
                null,
                null,
                null
            )
            {
                ReplayCheckpointCandidatePresent = null,
                ReplayCheckpointPendingWindow = null,
                MountReady = mountReady,
            };
        }

        return new HostRuntimeStatus(
            WriteBackend: "Disabled",
            CommitModel: NativeWriteCommitModel.ScaffoldCheckpoint,
            NativeWriteReadiness: NativeWriteReadiness.Unavailable,
            NativeWriteValidationState: NativeWriteValidationState.Scaffold,
            RecoveryActive: payload.RecoveryActive || recoverySignaled,
            RecoveryReason: recoveryReason,
            LastCommitXid: lastCommitXid,
            NativeWriteSafetyState: NativeWriteSafetyState.ReadOnlyFallback,
            LastRecoveryAction: lastRecoveryAction,
            DirtyTransactionCount: dirtyTransactionCount,
            ShutdownDrainActive: shutdownDrainActive,
            InFlightMutationCallbacks: inFlightMutationCallbacks,
            HostProcessId: hostProcessId,
            ValidationEvidence: parsedValidationEvidence,
            FixtureLegacyFallbackActive: false,
            FixtureCompatibilityPathActive: false,
            UsesScaffoldCommitBlob: false,
            CommitStage: null,
            ReplayStage: null,
            CommitBlobMagic: null,
            CanonicalPathActive: null,
            CanonicalGateFailure: null
        )
        {
            ReplayCheckpointCandidatePresent = null,
            ReplayCheckpointPendingWindow = null,
            MountReady = mountReady,
        };
    }

    private static async Task<HostRuntimeStatus> ReadHostRuntimeStatusAsync(
        string statusFilePath,
        MountAccessMode accessMode,
        string? configuredWriteBackend,
        TimeSpan timeout,
        CancellationToken cancellationToken
    )
    {
        var fallback = BuildDefaultHostRuntimeStatus(accessMode, configuredWriteBackend);
        if (string.IsNullOrWhiteSpace(statusFilePath))
        {
            return fallback;
        }

        var startedAt = Stopwatch.GetTimestamp();
        while (!cancellationToken.IsCancellationRequested)
        {
            if (Stopwatch.GetElapsedTime(startedAt) >= timeout)
            {
                return fallback;
            }

            try
            {
                if (File.Exists(statusFilePath))
                {
                    var json = await File.ReadAllTextAsync(statusFilePath, cancellationToken).ConfigureAwait(false);
                    if (!string.IsNullOrWhiteSpace(json))
                    {
                        HostRuntimeStatusPayload? payload = null;
                        try
                        {
                            payload = JsonSerializer.Deserialize<HostRuntimeStatusPayload>(
                                json,
                                new JsonSerializerOptions
                                {
                                    PropertyNameCaseInsensitive = true,
                                }
                            );
                        }
                        catch
                        {
                            payload = TryDeserializeHostRuntimeStatusPayloadLenient(json);
                        }

                        payload ??= TryDeserializeHostRuntimeStatusPayloadLenient(json);

                        if (payload is not null)
                        {
                            return BuildHostRuntimeStatusFromPayload(payload, accessMode, fallback);
                        }
                    }
                }
            }
            catch
            {
                // Best-effort polling while FsHost writes status.
            }

            await Task.Delay(150, cancellationToken).ConfigureAwait(false);
        }

        return fallback;
    }

    private static HostRuntimeStatusPayload? TryDeserializeHostRuntimeStatusPayloadLenient(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var payload = new HostRuntimeStatusPayload(
                WriteBackend: ReadJsonString(root, "writeBackend"),
                CommitModel: ReadJsonString(root, "commitModel"),
                NativeWriteReadiness: ReadJsonString(root, "nativeWriteReadiness"),
                NativeWriteValidationState: ReadJsonString(root, "nativeWriteValidationState"),
                RecoveryActive: ReadJsonBoolean(root, "recoveryActive") ?? false,
                RecoveryReason: ReadJsonString(root, "recoveryReason"),
                LastCommitXid: ReadJsonUInt64(root, "lastCommitXid"),
                NativeWriteSafetyState: ReadJsonString(root, "nativeWriteSafetyState"),
                LastRecoveryAction: ReadJsonString(root, "lastRecoveryAction"),
                DirtyTransactionCount: ReadJsonInt32Clamped(root, "dirtyTransactionCount"),
                ShutdownDrainActive: ReadJsonBoolean(root, "shutdownDrainActive"),
                InFlightMutationCallbacks: ReadJsonInt32Clamped(root, "inFlightMutationCallbacks"),
                HostPid: ReadJsonInt32Clamped(root, "hostPid"),
                ValidationCrashFaultPasses: ReadJsonInt32Clamped(root, "validationCrashFaultPasses"),
                ValidationCrashStageMatrixPasses: ReadJsonInt32Clamped(root, "validationCrashStageMatrixPasses"),
                ValidationHardwarePilotPasses: ReadJsonInt32Clamped(root, "validationHardwarePilotPasses"),
                ValidationHotUnplugPasses: ReadJsonInt32Clamped(root, "validationHotUnplugPasses"),
                ValidationMacOsValidationPasses: ReadJsonInt32Clamped(root, "validationMacOsValidationPasses"),
                ValidationMacOsConsistencyPasses: ReadJsonInt32Clamped(root, "validationMacOsConsistencyPasses"),
                ValidationPowerLossReplayPasses: ReadJsonInt32Clamped(root, "validationPowerLossReplayPasses"),
                ValidationPowerLossPassVerified: ReadJsonBoolean(root, "validationPowerLossPassVerified"),
                ValidationLastValidatedUtc: ReadJsonString(root, "validationLastValidatedUtc"),
                ValidationLastValidationProfileId: ReadJsonString(root, "validationLastValidationProfileId"),
                FixtureLegacyFallbackActive: ReadJsonBoolean(root, "fixtureLegacyFallbackActive"),
                FixtureCompatibilityPathActive: ReadJsonBoolean(root, "fixtureCompatibilityPathActive"),
                UsesScaffoldCommitBlob: ReadJsonBoolean(root, "usesScaffoldCommitBlob"),
                CommitStage: ReadJsonString(root, "commitStage"),
                ReplayStage: ReadJsonString(root, "replayStage"),
                CommitBlobMagic: ReadJsonString(root, "commitBlobMagic"),
                CanonicalPathActive: ReadJsonBoolean(root, "canonicalPathActive"),
                CanonicalGateFailure: ReadJsonString(root, "canonicalGateFailure")
            )
            {
                MountReady = ReadJsonBoolean(root, "mountReady"),
                ReplayCheckpointCandidatePresent = ReadJsonBoolean(root, "replayCheckpointCandidatePresent"),
                ReplayCheckpointPendingWindow = ReadJsonBoolean(root, "replayCheckpointPendingWindow"),
            };

            return payload;
        }
        catch
        {
            return null;
        }
    }

    private static bool TryGetJsonPropertyIgnoreCase(JsonElement root, string propertyName, out JsonElement value)
    {
        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty(propertyName, out value))
        {
            return true;
        }

        if (root.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in root.EnumerateObject())
            {
                if (string.Equals(property.Name, propertyName, StringComparison.OrdinalIgnoreCase))
                {
                    value = property.Value;
                    return true;
                }
            }
        }

        value = default;
        return false;
    }

    private static string? ReadJsonString(JsonElement root, string propertyName)
    {
        if (!TryGetJsonPropertyIgnoreCase(root, propertyName, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.Null => null,
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null,
        };
    }

    private static bool? ReadJsonBoolean(JsonElement root, string propertyName)
    {
        if (!TryGetJsonPropertyIgnoreCase(root, propertyName, out var value))
        {
            return null;
        }

        switch (value.ValueKind)
        {
            case JsonValueKind.True:
                return true;
            case JsonValueKind.False:
                return false;
            case JsonValueKind.String:
            {
                var token = value.GetString();
                if (string.IsNullOrWhiteSpace(token))
                {
                    return null;
                }

                token = token.Trim();
                if (bool.TryParse(token, out var parsed))
                {
                    return parsed;
                }

                if (string.Equals(token, "1", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(token, "yes", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(token, "on", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                if (string.Equals(token, "0", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(token, "no", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(token, "off", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                return null;
            }
            case JsonValueKind.Number:
                if (value.TryGetInt64(out var integerNumber))
                {
                    return integerNumber != 0;
                }

                return null;
            default:
                return null;
        }
    }

    private static int? ReadJsonInt32Clamped(JsonElement root, string propertyName)
    {
        if (!TryGetJsonPropertyIgnoreCase(root, propertyName, out var value))
        {
            return null;
        }

        long? parsed = value.ValueKind switch
        {
            JsonValueKind.Number when value.TryGetInt64(out var integerNumber) => integerNumber,
            JsonValueKind.String => ParseInt64Invariant(value.GetString()),
            _ => null,
        };

        if (!parsed.HasValue)
        {
            return null;
        }

        if (parsed.Value > int.MaxValue)
        {
            return int.MaxValue;
        }

        if (parsed.Value < int.MinValue)
        {
            return int.MinValue;
        }

        return (int)parsed.Value;
    }

    private static ulong? ReadJsonUInt64(JsonElement root, string propertyName)
    {
        if (!TryGetJsonPropertyIgnoreCase(root, propertyName, out var value))
        {
            return null;
        }

        switch (value.ValueKind)
        {
            case JsonValueKind.Number:
                if (value.TryGetUInt64(out var unsignedNumber))
                {
                    return unsignedNumber;
                }

                if (value.TryGetInt64(out var signedNumber) && signedNumber >= 0)
                {
                    return (ulong)signedNumber;
                }

                return null;
            case JsonValueKind.String:
            {
                var token = value.GetString();
                if (string.IsNullOrWhiteSpace(token))
                {
                    return null;
                }

                token = token.Trim();
                return ulong.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
                    ? parsed
                    : null;
            }
            default:
                return null;
        }
    }

    private static long? ParseInt64Invariant(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var token = value.Trim();
        return long.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;
    }

    private void WriteWriteSessionMarker(
        string requestedVolumeId,
        MountAccessMode requestedAccessMode,
        string mountPoint,
        string gateState,
        string diagnosticCode,
        string error
    )
    {
        try
        {
            Directory.CreateDirectory(_writeDiagnosticsRoot);
            var marker = new WriteSessionMarker(
                TimestampUtc: DateTime.UtcNow,
                RequestedVolumeId: requestedVolumeId,
                RequestedAccessMode: requestedAccessMode.ToString(),
                MountPoint: mountPoint,
                GateState: gateState,
                DiagnosticCode: diagnosticCode,
                Error: error,
                RolloutChannel: _options.WriteRolloutChannel,
                SafetyLevel: _options.WriteSafetyLevel
            );

            var fileName = $"write_blocked_{DateTime.UtcNow:yyyyMMdd_HHmmss_fff}_{Guid.NewGuid():N}.json";
            var path = Path.Combine(_writeDiagnosticsRoot, fileName);
            var json = System.Text.Json.JsonSerializer.Serialize(marker, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
            });
            File.WriteAllText(path, json);
        }
        catch
        {
            // Best-effort diagnostics.
        }
    }

    private sealed record ParsedVolumeRow(
        string Name,
        bool IsEncrypted,
        IReadOnlyList<string> WriteIncompatibilities,
        IReadOnlyList<string> WriteUnsupportedFeatures
    );

    private sealed record ApfsContainerHeader(
        uint BlockSize,
        ulong TotalBlocks,
        ulong CheckpointXid,
        ulong VolumeRootBlock
    );

    private sealed record GptPartitionInfo(
        int PartitionNumber,
        Guid PartitionTypeGuid,
        ulong StartOffsetBytes,
        string PartitionName
    );

    private sealed record VolumeMountTarget(string DevicePath, ulong DeviceOffsetBytes);

    private sealed record DiscoveredVolume(
        string VolumeName,
        bool IsEncrypted,
        IReadOnlyList<string> WriteIncompatibilities,
        IReadOnlyList<string> WriteUnsupportedFeatures,
        string NativeVolumePath,
        VolumeMountTarget MountTarget
    );

    private sealed record DiscoveredDevice(
        string DeviceId,
        string DisplayName,
        IReadOnlyList<DiscoveredVolume> Volumes
    );

    private sealed record HostProcessState(
        Process Process,
        string LifetimeFilePath,
        string StatusFilePath,
        MountAccessMode RequestedAccessMode,
        string? ConfiguredWriteBackend
    );

    private sealed record HostStopResult(bool ProcessExited, bool ForcedKill);

    private sealed record HostRuntimeStatus(
        string WriteBackend,
        NativeWriteCommitModel CommitModel,
        NativeWriteReadiness NativeWriteReadiness,
        NativeWriteValidationState NativeWriteValidationState,
        bool RecoveryActive,
        string? RecoveryReason,
        ulong? LastCommitXid,
        NativeWriteSafetyState NativeWriteSafetyState,
        string? LastRecoveryAction,
        int DirtyTransactionCount,
        bool ShutdownDrainActive,
        int InFlightMutationCallbacks,
        int HostProcessId,
        NativeWriteValidationEvidence? ValidationEvidence,
        bool FixtureLegacyFallbackActive,
        bool FixtureCompatibilityPathActive,
        bool UsesScaffoldCommitBlob,
        string? CommitStage,
        string? ReplayStage,
        string? CommitBlobMagic,
        bool? CanonicalPathActive,
        string? CanonicalGateFailure
    )
    {
        public bool? ReplayCheckpointCandidatePresent { get; init; }

        public bool? ReplayCheckpointPendingWindow { get; init; }

        public bool MountReady { get; init; }
    }

    private sealed record HostRuntimeStatusPayload(
        string? WriteBackend,
        string? CommitModel,
        string? NativeWriteReadiness,
        string? NativeWriteValidationState,
        bool RecoveryActive,
        string? RecoveryReason,
        ulong? LastCommitXid,
        string? NativeWriteSafetyState,
        string? LastRecoveryAction,
        int? DirtyTransactionCount,
        bool? ShutdownDrainActive,
        int? InFlightMutationCallbacks,
        int? HostPid,
        int? ValidationCrashFaultPasses,
        int? ValidationCrashStageMatrixPasses,
        int? ValidationHardwarePilotPasses,
        int? ValidationHotUnplugPasses,
        int? ValidationMacOsValidationPasses,
        int? ValidationMacOsConsistencyPasses,
        int? ValidationPowerLossReplayPasses,
        bool? ValidationPowerLossPassVerified,
        string? ValidationLastValidatedUtc,
        string? ValidationLastValidationProfileId,
        bool? FixtureLegacyFallbackActive,
        bool? FixtureCompatibilityPathActive,
        bool? UsesScaffoldCommitBlob,
        string? CommitStage,
        string? ReplayStage,
        string? CommitBlobMagic,
        bool? CanonicalPathActive,
        string? CanonicalGateFailure
    )
    {
        public bool? MountReady { get; init; }

        public bool? ReplayCheckpointCandidatePresent { get; init; }

        public bool? ReplayCheckpointPendingWindow { get; init; }
    }

    private sealed record ValidationEvidenceStorePayload(
        IReadOnlyDictionary<string, NativeWriteValidationEvidence?>? Volumes,
        IReadOnlyDictionary<string, NativeWriteValidationEvidence?>? Profiles = null
    );

    private sealed record CommandResult(int ExitCode, string StdOut, string StdErr);

    private sealed record WriteSessionMarker(
        DateTime TimestampUtc,
        string RequestedVolumeId,
        string RequestedAccessMode,
        string MountPoint,
        string GateState,
        string DiagnosticCode,
        string Error,
        string RolloutChannel,
        string SafetyLevel
    );
}

