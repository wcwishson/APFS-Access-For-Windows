using System.Collections.Concurrent;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
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
    private const int MaxHostExitObserverProofAttempts = 8;
    private static readonly TimeSpan HostExitObserverInitialRetryDelay = TimeSpan.FromMilliseconds(50);
    private static readonly TimeSpan HostExitObserverWaitSlice = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan RuntimeStatusPollTimeout = TimeSpan.FromMilliseconds(350);
    private static readonly TimeSpan RuntimeStatusCacheTtl = TimeSpan.FromMilliseconds(250);
    private static readonly Guid ApfsPartitionTypeGuid = new("7C3457EF-0000-11AA-AA11-00306543ECAC");
    private static readonly int[] ProbeSectorSizes = [512, 4096];
    private const int MaxGptEntriesToRead = 1024;

    private readonly ServiceHostOptions _options;
    private readonly string? _nativeFsHostPath;
    private readonly IReadOnlyList<string> _deviceCandidates;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly ConcurrentDictionary<string, MountedVolumeState> _mounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, HostProcessState> _hosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, HostProcessState> _retainedStartupHosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, HostStopResult> _completedHostStops = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, VolumeInfo> _volumeCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DiscoveryCacheEntry> _deviceDiscoveryCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, VolumeMountTarget> _mountTargetsByVolumeId = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, NativeWriteValidationEvidence> _validationEvidenceByVolumeId = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, NativeWriteValidationEvidence> _validationEvidenceByProfileId = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _lastPromotedEvidenceSessionByProfileId = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _deviceDisplayNameById = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, RuntimeStatusCacheEntry> _runtimeStatusCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Lazy<Task<RuntimeStatusReadResult>>> _runtimeStatusReads = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Task> _hostExitObservers = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly object _lifecycleSync = new();
    private readonly object _disposeFinalizationSync = new();
    private readonly TaskCompletionSource _disposeCompleted = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly string _writeDiagnosticsRoot = Path.Combine(Path.GetTempPath(), "ApfsAccess", "write-diagnostics");
    private readonly HostProcessLifecycleTestHooks? _lifecycleTestHooks;
    private long _deviceDiscoveryScanCount;
    private long _mountStateVersion;
    private long _runtimeStatusReadOperationCount;
    private long _writeSessionMarkerIoWhileGateHeldCount;
    private int _activeLifecycleOperations;
    private bool _disposeStarted;
    private bool _disposeFinalizationRunning;
    private TaskCompletionSource? _lifecycleOperationsDrained;

    public NativeApfsBackend(ServiceHostOptions options)
        : this(options, null)
    {
    }

    internal NativeApfsBackend(
        ServiceHostOptions options,
        HostProcessLifecycleTestHooks? lifecycleTestHooks)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
        _lifecycleTestHooks = lifecycleTestHooks;
        _nativeFsHostPath = ResolveNativeFsHostPath(options);
        _deviceCandidates = BuildDeviceCandidates(options);
        Directory.CreateDirectory(_writeDiagnosticsRoot);
        LoadValidationEvidenceFromDisk();
    }

    public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var operationLease = AcquireLifecycleOperationLease();

        var devices = new List<DeviceInfo>();
        foreach (var candidate in _deviceCandidates)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var discovered = DiscoverDevice(candidate);
            if (discovered is not null)
            {
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
        using var operationLease = AcquireLifecycleOperationLease();

        var discovered = DiscoverDevice(deviceId);
        if (discovered is null)
        {
            return Task.FromResult<IReadOnlyList<VolumeInfo>>(Array.Empty<VolumeInfo>());
        }

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
        using var operationLease = AcquireLifecycleOperationLease();

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
        WriteSessionMarkerRequest? pendingMarker = null;

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            CleanupExitedHosts_NoLock();

            if (_mounts.ContainsKey(mountPoint) ||
                _hosts.ContainsKey(mountPoint) ||
                HasRetainedStartupHost_NoLock(mountPoint))
            {
                return new MountResult(
                    Success: false,
                    MountPoint: null,
                    Error: $"Mount point '{mountPoint}' is already in use or still owned by an FsHost process.",
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

                    pendingMarker = CaptureWriteSessionMarker(
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
                var stopResult = await StopStartedHostProcessAsync(
                    mountPoint,
                    hostState,
                    CancellationToken.None).ConfigureAwait(false);
                pendingHostState = null;
                return new MountResult(
                    Success: false,
                    MountPoint: null,
                    Error: $"FsHost did not expose drive {mountPoint} within {startupTimeout.TotalSeconds:n0}s ({DescribeHostStopResult(stopResult)}).",
                    EffectiveAccessMode: MountAccessMode.ReadOnly,
                    DiagnosticCode: "FsHostStartupTimeout",
                    IsReadOnly: true,
                    WriteEnabled: false,
                    SafetyGateState: "HostStartupTimeout"
                );
            }

            var hostRuntimeStatusResult = await ReadHostRuntimeStatusResultCachedAsync(
                hostState.StatusFilePath,
                request.AccessMode,
                _options.WriteBackendMode,
                timeout: TimeSpan.FromSeconds(3),
                cancellationToken
            ).ConfigureAwait(false);
            var hostRuntimeStatus = hostRuntimeStatusResult.IsTrusted
                ? hostRuntimeStatusResult.Status
                : BuildFailClosedRuntimeStatus(
                    request.AccessMode,
                    _options.WriteBackendMode,
                    "RuntimeStatusUntrusted");

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
            var mountedReadOnlyIdentityFallbackReason = GetMountedReadOnlyIdentityFallbackReason(
                request.AccessMode,
                hostRuntimeStatus.WriteBackend,
                hostRuntimeStatus.RecoveryReason);
            var enforceRequestedNativeWritePolicy = requestedNativeWrite &&
                                                    mountedReadOnlyIdentityFallbackReason is null;
            if (enforceRequestedNativeWritePolicy && failClosedReason is not null)
            {
                var recoveryGateState = BuildRecoveryFailClosedGateState(failClosedReason);
                var recoveryDiagnosticCode = BuildRecoveryFailClosedDiagnosticCode(failClosedReason);
                var recoveryExplanation = DescribeRecoveryReason(failClosedReason);

                await StopStartedHostProcessAsync(mountPoint, hostState, CancellationToken.None).ConfigureAwait(false);
                pendingHostState = null;
                pendingMarker = CaptureWriteSessionMarker(
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

            if (enforceRequestedNativeWritePolicy &&
                _options.NativeWriteRequireCanonicalCommit &&
                hostRuntimeStatus.CommitModel != NativeWriteCommitModel.CanonicalApfsCheckpoint)
            {
                await StopStartedHostProcessAsync(mountPoint, hostState, CancellationToken.None).ConfigureAwait(false);
                pendingHostState = null;
                pendingMarker = CaptureWriteSessionMarker(
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

            if (enforceRequestedNativeWritePolicy &&
                hostRuntimeStatus.FixtureLegacyFallbackActive)
            {
                await StopStartedHostProcessAsync(mountPoint, hostState, CancellationToken.None).ConfigureAwait(false);
                pendingHostState = null;
                pendingMarker = CaptureWriteSessionMarker(
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

            if (enforceRequestedNativeWritePolicy &&
                hostRuntimeStatus.UsesScaffoldCommitBlob &&
                !IsFixtureImagePath(volume.DeviceId))
            {
                await StopStartedHostProcessAsync(mountPoint, hostState, CancellationToken.None).ConfigureAwait(false);
                pendingHostState = null;
                pendingMarker = CaptureWriteSessionMarker(
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

            if (enforceRequestedNativeWritePolicy &&
                _options.NativeWriteStrictMode &&
                hostRuntimeStatus.NativeWriteReadiness != NativeWriteReadiness.CommitReady)
            {
                await StopStartedHostProcessAsync(mountPoint, hostState, CancellationToken.None).ConfigureAwait(false);
                pendingHostState = null;
                pendingMarker = CaptureWriteSessionMarker(
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
                await StopStartedHostProcessAsync(mountPoint, hostState, CancellationToken.None).ConfigureAwait(false);
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

                pendingMarker = CaptureWriteSessionMarker(
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

            _completedHostStops.TryRemove(mountPoint, out _);
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
                    NativeWriteDiagnostics: mountDiagnostics,
                    RecoveryIdentity: volume.RecoveryIdentity,
                    MountReady: hostRuntimeStatus.MountReady,
                    HostProcessId: hostRuntimeStatus.HostProcessId,
                    WalAcceptedSequence: hostRuntimeStatus.WalAcceptedSequence,
                    WalApfsDurableSequence: hostRuntimeStatus.WalApfsDurableSequence,
                    WalCleanupSequence: hostRuntimeStatus.WalCleanupSequence
                );
            Interlocked.Increment(ref _mountStateVersion);

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
                NativeWriteDiagnostics: mountDiagnostics,
                MountReady: hostRuntimeStatus.MountReady,
                HostProcessId: hostRuntimeStatus.HostProcessId,
                WalAcceptedSequence: hostRuntimeStatus.WalAcceptedSequence,
                WalApfsDurableSequence: hostRuntimeStatus.WalApfsDurableSequence,
                WalCleanupSequence: hostRuntimeStatus.WalCleanupSequence,
                RecoveryActive: hostRuntimeStatus.RecoveryActive,
                RecoveryReason: hostRuntimeStatus.RecoveryReason,
                LastCommitXid: hostRuntimeStatus.LastCommitXid
            );
        }
        catch (Exception ex)
        {
            if (pendingHostState is not null && !hostRegistered)
            {
                await StopStartedHostProcessAsync(
                    mountPoint,
                    pendingHostState,
                    CancellationToken.None).ConfigureAwait(false);
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
            if (pendingMarker is not null)
            {
                WriteCapturedSessionMarkers([pendingMarker]);
            }
        }
    }

    public async Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var operationLease = AcquireLifecycleOperationLease();
        if (string.IsNullOrWhiteSpace(mountPoint))
        {
            return new UnmountResult(false, mountPoint, "Mount point was not provided.");
        }

        var normalizedMountPoint = NormalizeMountPoint(mountPoint);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            CleanupExitedHosts_NoLock();

            if (!_hosts.TryGetValue(normalizedMountPoint, out var hostState))
            {
                if (_completedHostStops.TryGetValue(normalizedMountPoint, out var completedStop))
                {
                    var removed = !IsDriveVisible(normalizedMountPoint) || await WaitForDriveRemovalAsync(
                        normalizedMountPoint,
                        TimeSpan.FromSeconds(Math.Clamp(_options.NativeHostStopTimeoutSeconds, 1, 60)),
                        cancellationToken).ConfigureAwait(false);
                    if (!removed)
                    {
                        return new UnmountResult(
                            false,
                            normalizedMountPoint,
                            $"Mount point '{normalizedMountPoint}' remained visible after FsHost stopped. Close Explorer windows or files and try eject again."
                        );
                    }

                    _completedHostStops.TryRemove(normalizedMountPoint, out _);
                    _mounts.TryRemove(normalizedMountPoint, out _);
                    NotifyShellDriveRemoved(normalizedMountPoint);
                    return BuildCompletedUnmountResult(normalizedMountPoint, completedStop);
                }

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
                        return new UnmountResult(
                            false,
                            normalizedMountPoint,
                            "FsHost stopped, but its final write status was unavailable.",
                            MountRemoved: true
                        );
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

            InvalidateRuntimeStatusCache(hostState.StatusFilePath);
            // Once shutdown has been signaled, finish the bounded ownership
            // transition even if the request is canceled. Abandoning this
            // section can drop the only reference to a live host and its job.
            var stopResult = await StopHostProcessAsync(
                hostState,
                CancellationToken.None).ConfigureAwait(false);
            if (stopResult.ProcessExited)
            {
                lock (_disposeFinalizationSync)
                {
                    if (!TryFinalizeProvenHost_NoLock(normalizedMountPoint, hostState) &&
                        !IsHostExitObserverOwned_NoLock(hostState))
                    {
                        CleanupHostResources(hostState);
                    }
                }
            }
            var unmounted = stopResult.ProcessExited && await WaitForDriveRemovalAsync(
                normalizedMountPoint,
                TimeSpan.FromSeconds(Math.Clamp(_options.NativeHostStopTimeoutSeconds, 1, 60)),
                CancellationToken.None).ConfigureAwait(false);

            if (!unmounted)
            {
                if (stopResult.ProcessExited)
                {
                    _completedHostStops[normalizedMountPoint] = stopResult;
                }
                else
                {
                    EnsureHostExitObserver(normalizedMountPoint, hostState);
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
            Interlocked.Increment(ref _mountStateVersion);
            InvalidateRuntimeStatusCache(hostState.StatusFilePath);
            NotifyShellDriveRemoved(normalizedMountPoint);
            return BuildCompletedUnmountResult(normalizedMountPoint, stopResult);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var operationLease = AcquireLifecycleOperationLease();
        using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            _disposeCts.Token);
        var refreshCancellationToken = linkedCancellation.Token;

        RuntimeStatusRefreshSnapshot snapshot;
        await _gate.WaitAsync(refreshCancellationToken).ConfigureAwait(false);
        try
        {
            CleanupExitedHosts_NoLock();
            snapshot = CaptureRuntimeStatusRefreshSnapshot_NoLock();
        }
        finally
        {
            _gate.Release();
        }

        var runtimeStatuses = await ReadRuntimeStatusesAsync(snapshot, refreshCancellationToken).ConfigureAwait(false);

        IReadOnlyList<WriteSessionMarkerRequest> markerRequests = Array.Empty<WriteSessionMarkerRequest>();
        IReadOnlyList<MountedVolumeState> mounts;
        await _gate.WaitAsync(refreshCancellationToken).ConfigureAwait(false);
        try
        {
            CleanupExitedHosts_NoLock();
            if (Volatile.Read(ref _mountStateVersion) == snapshot.Version)
            {
                markerRequests = ApplyMountedRuntimeState_NoLock(snapshot, runtimeStatuses);
            }

            mounts = _mounts.Values
                .OrderBy(x => x.MountPoint, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        finally
        {
            _gate.Release();
        }

        WriteCapturedSessionMarkers(markerRequests);
        return mounts;
    }

    private RuntimeStatusRefreshSnapshot CaptureRuntimeStatusRefreshSnapshot_NoLock()
    {
        var entries = new List<RuntimeStatusRefreshEntry>(_hosts.Count);
        foreach (var entry in _hosts.ToArray())
        {
            if (_mounts.TryGetValue(entry.Key, out var current))
            {
                entries.Add(new RuntimeStatusRefreshEntry(entry.Key, entry.Value, current));
            }
        }

        return new RuntimeStatusRefreshSnapshot(
            Volatile.Read(ref _mountStateVersion),
            entries);
    }

    private async Task<IReadOnlyDictionary<string, RuntimeStatusReadResult>> ReadRuntimeStatusesAsync(
        RuntimeStatusRefreshSnapshot snapshot,
        CancellationToken cancellationToken)
    {
        var statuses = new Dictionary<string, RuntimeStatusReadResult>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in snapshot.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                statuses[entry.MountPoint] = await ReadHostRuntimeStatusResultCachedAsync(
                    entry.HostState.StatusFilePath,
                    entry.HostState.RequestedAccessMode,
                    entry.HostState.ConfiguredWriteBackend,
                    RuntimeStatusPollTimeout,
                    cancellationToken
                ).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                statuses[entry.MountPoint] = BuildUntrustedRuntimeStatusResult(
                    entry.HostState,
                    "RuntimeStatusUntrusted",
                    ex.GetType().Name);
            }
        }

        return statuses;
    }

    private IReadOnlyList<WriteSessionMarkerRequest> ApplyMountedRuntimeState_NoLock(
        RuntimeStatusRefreshSnapshot snapshot,
        IReadOnlyDictionary<string, RuntimeStatusReadResult> runtimeStatuses)
    {
        var appliedAny = false;
        var markerRequests = new List<WriteSessionMarkerRequest>();
        foreach (var entry in snapshot.Entries)
        {
            if (!IsRuntimeStatusRefreshEntryCurrent_NoLock(entry, snapshot))
            {
                continue;
            }

            if (!runtimeStatuses.TryGetValue(entry.MountPoint, out var runtimeStatusResult))
            {
                runtimeStatusResult = BuildUntrustedRuntimeStatusResult(
                    entry.HostState,
                    "RuntimeStatusUntrusted",
                    "StatusResultMissing");
            }

            var current = entry.MountedState;
            var trustFailureReason = GetRuntimeStatusTrustFailureReason_NoLock(runtimeStatusResult);
            var runtimeStatus = trustFailureReason is null
                ? runtimeStatusResult.Status
                : BuildFailClosedRuntimeStatus(
                    entry.HostState.RequestedAccessMode,
                    entry.HostState.ConfiguredWriteBackend,
                    trustFailureReason);

            var normalizedRuntimeBackend = NormalizeWriteBackendName(runtimeStatus.WriteBackend);
            var runtimeAllowsWrite = entry.HostState.RequestedAccessMode == MountAccessMode.ReadWrite &&
                                     !string.Equals(normalizedRuntimeBackend, "Disabled", StringComparison.OrdinalIgnoreCase);
            var recoveryFailClosedTriggered = trustFailureReason is not null &&
                                              current.AccessMode == MountAccessMode.ReadWrite;
            string? failClosedReason = trustFailureReason;
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
            var nextReadiness = entry.HostState.RequestedAccessMode == MountAccessMode.ReadWrite
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
                entry.HostState.RequestedAccessMode,
                runtimeStatus,
                ResolveValidationEvidence(evidenceVolume),
                runtimeSessionId: entry.HostState.StatusFilePath
            );
            var nextValidationState = ResolveNativeWriteValidationState(
                entry.HostState.RequestedAccessMode,
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

            WriteSessionMarkerRequest? markerRequest = null;
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

                markerRequest = CaptureWriteSessionMarker(
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

            var updated = current with
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
                MountReady = runtimeStatus.MountReady,
                HostProcessId = runtimeStatus.HostProcessId,
                WalAcceptedSequence = runtimeStatus.WalAcceptedSequence,
                WalApfsDurableSequence = runtimeStatus.WalApfsDurableSequence,
                WalCleanupSequence = runtimeStatus.WalCleanupSequence,
            };
            _mounts[entry.MountPoint] = updated;
            if (markerRequest is not null)
            {
                markerRequests.Add(markerRequest with { ExpectedMountedState = updated });
            }
            appliedAny = true;
        }

        if (appliedAny)
        {
            var appliedVersion = Interlocked.Increment(ref _mountStateVersion);
            for (var index = 0; index < markerRequests.Count; index++)
            {
                markerRequests[index] = markerRequests[index] with { MountStateVersion = appliedVersion };
            }
        }

        return markerRequests;
    }

    private string? GetRuntimeStatusTrustFailureReason_NoLock(RuntimeStatusReadResult result)
    {
        if (!result.IsTrusted || result.Identity is null)
        {
            return "RuntimeStatusUntrusted";
        }

        var currentMetadata = CaptureRuntimeStatusFileMetadata(result.Identity.NormalizedPath);
        return RuntimeStatusFileMetadataMatches(result.Identity.Metadata, currentMetadata)
            ? null
            : "RuntimeStatusChangedBeforeApply";
    }

    private static HostRuntimeStatus BuildFailClosedRuntimeStatus(
        MountAccessMode accessMode,
        string? configuredWriteBackend,
        string recoveryReason)
    {
        var fallback = BuildDefaultHostRuntimeStatus(
            accessMode,
            configuredWriteBackend);
        return fallback with
        {
            WriteBackend = "Disabled",
            NativeWriteReadiness = NativeWriteReadiness.RecoveryMode,
            RecoveryActive = true,
            RecoveryReason = recoveryReason,
            NativeWriteSafetyState = NativeWriteSafetyState.RecoveryBlocked,
            LastRecoveryAction = "DowngradedAfterRuntimeStatusFailure",
            MountReady = false,
        };
    }

    private bool IsRuntimeStatusRefreshEntryCurrent_NoLock(
        RuntimeStatusRefreshEntry entry,
        RuntimeStatusRefreshSnapshot snapshot)
    {
        if (Volatile.Read(ref _mountStateVersion) != snapshot.Version ||
            !_hosts.TryGetValue(entry.MountPoint, out var currentHost) ||
            !ReferenceEquals(currentHost, entry.HostState) ||
            !_mounts.TryGetValue(entry.MountPoint, out var currentMount) ||
            !ReferenceEquals(currentMount, entry.MountedState))
        {
            return false;
        }

        try
        {
            return !entry.HostState.Process.HasExited;
        }
        catch
        {
            return false;
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

    private LifecycleOperationLease AcquireLifecycleOperationLease()
    {
        lock (_lifecycleSync)
        {
            ObjectDisposedException.ThrowIf(_disposeStarted, this);
            _activeLifecycleOperations++;
            return new LifecycleOperationLease(this);
        }
    }

    private void ReleaseLifecycleOperationLease()
    {
        TaskCompletionSource? drained = null;
        lock (_lifecycleSync)
        {
            _activeLifecycleOperations--;
            if (_activeLifecycleOperations == 0)
            {
                drained = _lifecycleOperationsDrained;
                _lifecycleOperationsDrained = null;
            }
        }

        drained?.TrySetResult();
    }

    public void Dispose()
    {
        Task waitTask;
        var ownsDisposal = false;
        lock (_lifecycleSync)
        {
            if (_disposeStarted)
            {
                waitTask = _disposeCompleted.Task;
            }
            else
            {
                _disposeStarted = true;
                ownsDisposal = true;
                if (_activeLifecycleOperations == 0)
                {
                    waitTask = Task.CompletedTask;
                }
                else
                {
                    _lifecycleOperationsDrained = new TaskCompletionSource(
                        TaskCreationOptions.RunContinuationsAsynchronously);
                    waitTask = _lifecycleOperationsDrained.Task;
                }
            }
        }

        if (!ownsDisposal)
        {
            _ = waitTask.Wait(GetLifecycleShutdownTimeout());
            return;
        }

        _disposeCts.Cancel();
        if (!waitTask.Wait(GetLifecycleShutdownTimeout()))
        {
            WriteLifecycleDiagnostic("lifecycle-drain-timeout");
            // Keep this backend alive until every operation releases its lease;
            // cleanup while a caller still holds MountContext-related state
            // would be unsafe. The caller returns on the bounded deadline, and
            // the continuation performs the same cleanup once ownership drains.
            _ = FinishDisposeAfterLifecycleDrainAsync(waitTask);
            return;
        }

        FinishDisposeAfterLifecycleDrain();
    }

    private TimeSpan GetLifecycleShutdownTimeout()
        => TimeSpan.FromSeconds(Math.Clamp(_options.NativeHostStopTimeoutSeconds, 1, 60));

    private async Task FinishDisposeAfterLifecycleDrainAsync(Task lifecycleDrain)
    {
        try
        {
            await lifecycleDrain.ConfigureAwait(false);
        }
        catch
        {
            // Lifecycle leases complete normally; keep cleanup fail-closed if a
            // future implementation faults the drain task.
        }

        FinishDisposeAfterLifecycleDrain();
    }

    private void FinishDisposeAfterLifecycleDrain()
    {
        lock (_disposeFinalizationSync)
        {
            if (_disposeFinalizationRunning)
            {
                return;
            }

            _disposeFinalizationRunning = true;
            try
            {
                foreach (var kvp in _hosts.ToArray())
                {
                    FinishHostShutdown_NoLock(kvp.Key, kvp.Value);
                }

                foreach (var kvp in _retainedStartupHosts.ToArray())
                {
                    FinishHostShutdown_NoLock(kvp.Value.TrackedMountPoint ?? string.Empty, kvp.Value);
                }

                CompleteDisposeIfNoHosts_NoLock();
            }
            finally
            {
                _disposeFinalizationRunning = false;
            }
        }
    }

    private void FinishHostShutdown_NoLock(string mountPoint, HostProcessState host)
    {
        if (TryReleaseExitedHost_NoLock(mountPoint, host))
        {
            return;
        }

        try
        {
            // Signal the child without releasing the lifetime handle. The
            // handle remains owned until exact exit is proven and
            // CleanupHostResources can safely close it.
            TrySignalHostStop(host);
            host.Guardian?.TryTerminate(13);
            if (!TryProveProcessExited(host, out _) &&
                !WaitForProcessExit(host.Process, GetLifecycleShutdownTimeout()))
            {
                host.Guardian?.TryTerminate(13);
                if (!TryProveProcessExited(host, out _) &&
                    TryKillProcess(host.Process))
                {
                    WaitForProcessExit(host.Process, TimeSpan.FromSeconds(2));
                }
            }
        }
        catch
        {
            // Keep the host tracked when any stop operation cannot establish an
            // exit boundary.
        }

        if (TryReleaseExitedHost_NoLock(mountPoint, host))
        {
            return;
        }

        WriteLifecycleDiagnostic(
            "host-exit-unproven",
            mountPoint,
            host,
            "The bounded stop sequence did not prove exact process exit; ownership remains retained.");
        EnsureHostExitObserver_NoLock(mountPoint, host);
    }

    private bool TryReleaseExitedHost_NoLock(string mountPoint, HostProcessState host)
    {
        if (IsHostExitObserverOwned_NoLock(host) ||
            !TryProveProcessExited(host, out _))
        {
            return false;
        }

        return TryFinalizeProvenHost_NoLock(mountPoint, host);
    }

    private bool TryFinalizeProvenHost_NoLock(string mountPoint, HostProcessState host)
    {
        if (IsHostExitObserverOwned_NoLock(host))
        {
            return false;
        }

        if (!TryRemoveTrackedHost(mountPoint, host, out var removedHost))
        {
            return false;
        }

        Interlocked.Increment(ref _mountStateVersion);
        InvalidateRuntimeStatusCache(removedHost.StatusFilePath);
        CleanupHostResources(removedHost);
        return true;
    }

    private void CompleteDisposeIfNoHosts_NoLock()
    {
        if (!_disposeStarted ||
            !_hosts.IsEmpty ||
            !_retainedStartupHosts.IsEmpty ||
            !_hostExitObservers.IsEmpty)
        {
            return;
        }

        _mounts.Clear();
        Interlocked.Increment(ref _mountStateVersion);
        _volumeCache.Clear();
        _runtimeStatusCache.Clear();
        _runtimeStatusReads.Clear();
        _disposeCompleted.TrySetResult();
    }

    private bool TryProveProcessExited(HostProcessState host, out int? exitCode)
        => TryProveProcessExited(
            host.Process,
            host.ProcessId,
            host.ProcessCreationTimeFileTimeUtc,
            out exitCode);

    private bool TryProveProcessExited(Process process, out int? exitCode)
    {
        var processId = TryGetProcessId(process) ?? 0;
        var creationTime = CaptureProcessCreationTime(process);
        return TryProveProcessExited(process, processId, creationTime, out exitCode);
    }

    private bool TryProveProcessExited(
        Process process,
        int processId,
        long? launchCreationTimeFileTimeUtc,
        out int? exitCode)
    {
        exitCode = null;
        bool processExited;
        try
        {
            processExited = process.HasExited;
            if (!processExited)
            {
                return false;
            }
        }
        catch
        {
            return false;
        }

        var exactHandleProof = TryProbeExactProcessHandleExit(process);
        if (exactHandleProof == false)
        {
            // Contradictory process observations fail closed. Never release a
            // host when its exact handle still says the original process lives.
            return false;
        }

        if (processId <= 0)
        {
            WriteLifecycleDiagnostic(
                "host-exit-proof-unavailable",
                null,
                null,
                detail: "The exact process ID was unavailable, so handle state alone was not accepted as exit proof.");
            return false;
        }

        var systemProbeAvailable = TryProbeSystemProcessPresence(processId, out var isEnumerated);
        if (!systemProbeAvailable)
        {
            systemProbeAvailable = TryProbeFallbackSystemProcessPresence(processId, out isEnumerated);
        }

        if (!systemProbeAvailable)
        {
            WriteLifecycleDiagnostic(
                "host-exit-proof-unavailable",
                null,
                null,
                detail: "Both independent system process enumeration probes failed; exact handle state was not accepted as exit proof.");
            return false;
        }

        if (!isEnumerated)
        {
            exitCode = TryGetHostExitCode(process);
            return true;
        }

        // A live process with the same PID is not necessarily the original
        // host. Compare its immutable creation time before treating the PID as
        // evidence that the old host is still present. If identity cannot be
        // read, fail closed rather than letting a signaled handle release a
        // process that Windows still reports under the original PID.
        if (!launchCreationTimeFileTimeUtc.HasValue ||
            !TryProbeProcessCreationTime(processId, out var currentCreationTimeFileTimeUtc))
        {
            WriteLifecycleDiagnostic(
                "host-exit-proof-unavailable",
                null,
                null,
                detail: $"PID {processId} remained enumerated, but its immutable creation time could not be independently verified.");
            return false;
        }

        if (currentCreationTimeFileTimeUtc == launchCreationTimeFileTimeUtc.Value)
        {
            // This is the termination-limbo case: the exact handle may be
            // signaled while Windows still retains the original PID row.
            return false;
        }

        // The PID now belongs to a different process, so the original host is
        // gone even if its old handle reports an exited state.
        exitCode = TryGetHostExitCode(process);
        return true;
    }

    private bool TryProbeSystemProcessPresence(int processId, out bool isEnumerated)
    {
        if (_lifecycleTestHooks?.ProbeSystemProcessPresence is { } probe)
        {
            try
            {
                var result = probe(processId);
                isEnumerated = result.GetValueOrDefault();
                return result.HasValue;
            }
            catch
            {
                isEnumerated = false;
                return false;
            }
        }

        return Win32ProcessPresenceProbe.TryIsEnumerated(processId, out isEnumerated);
    }

    private bool TryProbeFallbackSystemProcessPresence(int processId, out bool isEnumerated)
    {
        if (_lifecycleTestHooks?.ProbeFallbackSystemProcessPresence is { } probe)
        {
            try
            {
                var result = probe(processId);
                isEnumerated = result.GetValueOrDefault();
                return result.HasValue;
            }
            catch
            {
                isEnumerated = false;
                return false;
            }
        }

        return Win32ToolhelpProcessPresenceProbe.TryIsEnumerated(processId, out isEnumerated);
    }

    private bool? TryProbeExactProcessHandleExit(Process process)
    {
        if (_lifecycleTestHooks?.ProbeExactProcessHandleExit is { } probe)
        {
            try
            {
                return probe(process);
            }
            catch
            {
                return null;
            }
        }

        return Win32ProcessIdentityProbe.TryHasExited(process);
    }

    private bool TryProbeProcessCreationTime(int processId, out long creationTimeFileTimeUtc)
    {
        if (_lifecycleTestHooks?.ProbeProcessCreationTime is { } probe)
        {
            try
            {
                var result = probe(processId);
                if (result.HasValue)
                {
                    creationTimeFileTimeUtc = result.Value;
                    return true;
                }
            }
            catch
            {
            }

            creationTimeFileTimeUtc = 0;
            return false;
        }

        return Win32ProcessIdentityProbe.TryGetCreationTime(processId, out creationTimeFileTimeUtc);
    }

    private bool WaitForProcessExit(Process process, TimeSpan timeout)
    {
        if (_lifecycleTestHooks?.WaitForExit is { } waitForExit)
        {
            try
            {
                return waitForExit(process, timeout);
            }
            catch
            {
                return false;
            }
        }

        try
        {
            return process.WaitForExit(Math.Clamp((int)timeout.TotalMilliseconds, 1, int.MaxValue));
        }
        catch
        {
            return false;
        }
    }

    private bool TryKillProcess(Process process)
    {
        if (_lifecycleTestHooks?.KillProcess is { } killProcess)
        {
            try
            {
                return killProcess(process);
            }
            catch
            {
                return false;
            }
        }

        try
        {
            if (process.HasExited)
            {
                return false;
            }

            process.Kill(entireProcessTree: true);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private bool TryRemoveHost(
        string mountPoint,
        HostProcessState expectedHost,
        out HostProcessState removedHost)
    {
        removedHost = expectedHost;
        return ((ICollection<KeyValuePair<string, HostProcessState>>)_hosts)
            .Remove(new KeyValuePair<string, HostProcessState>(mountPoint, expectedHost));
    }

    private bool TryRemoveTrackedHost(
        string mountPoint,
        HostProcessState expectedHost,
        out HostProcessState removedHost)
    {
        if (TryRemoveHost(mountPoint, expectedHost, out removedHost))
        {
            return true;
        }

        return TryRemoveRetainedStartupHost(expectedHost, out removedHost);
    }

    private bool TryRemoveRetainedStartupHost(
        HostProcessState expectedHost,
        out HostProcessState removedHost)
    {
        removedHost = expectedHost;
        return ((ICollection<KeyValuePair<string, HostProcessState>>)_retainedStartupHosts)
            .Remove(new KeyValuePair<string, HostProcessState>(expectedHost.TrackingKey, expectedHost));
    }

    private void EnsureHostExitObserver_NoLock(string mountPoint, HostProcessState host)
    {
        var completion = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_hostExitObservers.TryAdd(host.TrackingKey, completion.Task))
        {
            return;
        }

        _ = RunHostExitObserverAsync(host.TrackingKey, mountPoint, host, completion);
    }

    private void EnsureHostExitObserver(string mountPoint, HostProcessState host)
    {
        lock (_disposeFinalizationSync)
        {
            EnsureHostExitObserver_NoLock(mountPoint, host);
        }
    }

    private async Task RunHostExitObserverAsync(
        string observerKey,
        string mountPoint,
        HostProcessState host,
        TaskCompletionSource completion)
    {
        var proofAttempts = 0;
        string? lastWaitFailure = null;
        try
        {
            while (proofAttempts < MaxHostExitObserverProofAttempts)
            {
                proofAttempts++;
                try
                {
                    using var waitCts = new CancellationTokenSource(HostExitObserverWaitSlice);
                    await host.Process.WaitForExitAsync(waitCts.Token)
                        .ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    lastWaitFailure = ex.GetType().Name;
                }

                try
                {
                    _lifecycleTestHooks?.BeforeObserverProof?.Invoke(host.Process);
                }
                catch (Exception ex)
                {
                    WriteLifecycleDiagnostic(
                        "host-exit-observer-terminal",
                        mountPoint,
                        host,
                        $"Observer proof callback failed after {proofAttempts} attempt(s): {ex.GetType().Name}.");
                    return;
                }

                if (TryProveProcessExited(host, out _))
                {
                    lock (_disposeFinalizationSync)
                    {
                        if (TryRemoveTrackedHost(mountPoint, host, out var removedHost))
                        {
                            Interlocked.Increment(ref _mountStateVersion);
                            InvalidateRuntimeStatusCache(removedHost.StatusFilePath);
                            CleanupHostResources(removedHost);
                        }

                        RemoveHostExitObserver_NoLock(observerKey, completion);
                        CompleteDisposeIfNoHosts_NoLock();
                    }

                    return;
                }

                if (proofAttempts >= MaxHostExitObserverProofAttempts)
                {
                    WriteLifecycleDiagnostic(
                        "host-exit-observer-terminal",
                        mountPoint,
                        host,
                        $"Exact process exit remained unproven after {proofAttempts} bounded observer attempt(s)." +
                        (lastWaitFailure is null ? string.Empty : $" Last wait failure: {lastWaitFailure}."));
                    return;
                }

                var retryDelay = TimeSpan.FromMilliseconds(Math.Min(
                    2000,
                    HostExitObserverInitialRetryDelay.TotalMilliseconds * Math.Pow(2, proofAttempts - 1)));
                await Task.Delay(retryDelay).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            // Retain ownership on any observer failure. A bounded terminal
            // diagnostic is safer than an unbounded retry or false cleanup.
            WriteLifecycleDiagnostic(
                "host-exit-observer-terminal",
                mountPoint,
                host,
                $"Observer stopped after an unexpected {ex.GetType().Name}; ownership remains retained.");
        }
        finally
        {
            completion.TrySetResult();
            RemoveHostExitObserver(observerKey, completion);
        }
    }

    private void RemoveHostExitObserver(
        string observerKey,
        TaskCompletionSource completion)
    {
        lock (_disposeFinalizationSync)
        {
            RemoveHostExitObserver_NoLock(observerKey, completion);
        }
    }

    private void RemoveHostExitObserver_NoLock(
        string observerKey,
        TaskCompletionSource completion)
    {
        ((ICollection<KeyValuePair<string, Task>>)_hostExitObservers)
            .Remove(new KeyValuePair<string, Task>(observerKey, completion.Task));
    }

    private bool IsHostExitObserverOwned_NoLock(HostProcessState host)
        => _hostExitObservers.ContainsKey(host.TrackingKey);

    private bool HasRetainedStartupHost_NoLock(string mountPoint)
    {
        foreach (var host in _retainedStartupHosts.Values)
        {
            if (string.Equals(host.TrackedMountPoint, mountPoint, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private void WriteLifecycleDiagnostic(string stage)
        => WriteLifecycleDiagnostic(stage, null, null, null);

    private void WriteLifecycleDiagnostic(
        string stage,
        string? mountPoint,
        HostProcessState? host,
        string? detail)
    {
        try
        {
            Directory.CreateDirectory(_writeDiagnosticsRoot);
            var path = Path.Combine(
                _writeDiagnosticsRoot,
                $"backend-{stage}-{DateTime.UtcNow:yyyyMMddHHmmssfff}-{Environment.ProcessId}.json");
            File.WriteAllText(
                path,
                JsonSerializer.Serialize(new
                {
                    stage,
                    processId = Environment.ProcessId,
                    activeLifecycleOperations = Volatile.Read(ref _activeLifecycleOperations),
                    mountPoint,
                    hostProcessId = host is null ? (int?)null : TryGetProcessId(host.Process),
                    detail,
                    timestampUtc = DateTime.UtcNow,
                }));
        }
        catch
        {
            // Diagnostics must never turn a bounded shutdown into another wait.
        }

        try
        {
            _lifecycleTestHooks?.OnLifecycleDiagnostic?.Invoke(stage);
        }
        catch
        {
            // Test and telemetry callbacks must not change lifecycle behavior.
        }
    }

    private static int? TryGetProcessId(Process process)
    {
        try
        {
            return process.Id;
        }
        catch
        {
            return null;
        }
    }

    private static long? CaptureProcessCreationTime(Process process)
    {
        return Win32ProcessIdentityProbe.TryGetCreationTime(process, out var creationTimeFileTimeUtc)
            ? creationTimeFileTimeUtc
            : null;
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

        using var startupGate = HostStartupGate.Create(lifetimeDir);
        HostLifetimeSentinel? lifetimeSentinel = null;
        HostProcessGuardian? guardian = null;
        Process? process = null;
        try
        {
            lifetimeSentinel = HostLifetimeSentinel.Create(lifetimeFilePath);
            var psi = new ProcessStartInfo
            {
                FileName = _nativeFsHostPath!,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(_nativeFsHostPath!) ?? AppContext.BaseDirectory,
            };
            PropagateRuntimeScratchEnvironment(psi);
            var mountTarget = ResolveMountTarget(volume);
        psi.ArgumentList.Add("--device");
        psi.ArgumentList.Add(mountTarget.DevicePath);
        if (mountTarget.DeviceOffsetBytes > 0)
        {
            psi.ArgumentList.Add("--device-offset");
            psi.ArgumentList.Add(mountTarget.DeviceOffsetBytes.ToString(CultureInfo.InvariantCulture));
        }
        AppendRecoveryIdentityArgument(psi, mountTarget.RecoveryIdentity);
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
        psi.ArgumentList.Add("--parent-pid");
        psi.ArgumentList.Add(Environment.ProcessId.ToString(CultureInfo.InvariantCulture));
        psi.ArgumentList.Add("--startup-gate-file");
        psi.ArgumentList.Add(startupGate.FilePath);
        psi.ArgumentList.Add("--startup-gate-token");
        psi.ArgumentList.Add(startupGate.AuthorizationToken);
        psi.ArgumentList.Add("--status-file");
        psi.ArgumentList.Add(statusFilePath);

            if (_lifecycleTestHooks?.StartProcess is not null)
            {
                process = _lifecycleTestHooks.StartProcess(psi);
                if (process is null)
                {
                    throw new InvalidOperationException("Unable to start native mount host process.");
                }

                guardian = _lifecycleTestHooks.CreateGuardian?.Invoke(process, startupGate) ??
                           HostProcessGuardian.Create(process, startupGate);
            }
            else
            {
                var launch = HostProcessGuardian.Start(psi, startupGate);
                process = launch.Process;
                guardian = launch.Guardian;
            }

            return new HostProcessState(
                process,
                guardian,
                lifetimeSentinel,
                lifetimeFilePath,
                startupGate.FilePath,
                statusFilePath,
                accessMode,
                _options.WriteBackendMode)
            {
                TrackedMountPoint = mountPoint,
            };
        }
        catch (Exception ex)
        {
            if (process is not null && !TryProveProcessExited(process, out _))
            {
                var retainedHost = new HostProcessState(
                    process,
                    guardian,
                    lifetimeSentinel,
                    lifetimeFilePath,
                    startupGate.FilePath,
                    statusFilePath,
                    accessMode,
                    _options.WriteBackendMode)
                {
                    TrackedMountPoint = mountPoint,
                };

                if (_hosts.TryAdd(mountPoint, retainedHost))
                {
                    // Startup failed, so request the child to stop. Keep every
                    // ownership reference until the observer proves exit.
                    TrySignalHostStop(retainedHost);
                    retainedHost.Guardian?.TryTerminate(13);
                    WriteLifecycleDiagnostic(
                        "startup-host-retained",
                        mountPoint,
                        retainedHost,
                        "Startup failed after Process.Start; the host remains reserved until exact exit is proven.");
                    lock (_disposeFinalizationSync)
                    {
                        EnsureHostExitObserver_NoLock(mountPoint, retainedHost);
                    }
                }
                else
                {
                    // The primary slot is already owned by another host. Keep
                    // this failed-start host in a separate collection so its
                    // process, guardian, and lifetime sentinel remain owned
                    // until the observer proves exit.
                    _retainedStartupHosts[retainedHost.TrackingKey] = retainedHost;
                    WriteLifecycleDiagnostic(
                        "startup-host-registration-failed",
                        mountPoint,
                        retainedHost,
                        "Startup failed and the mount-point ownership slot was unexpectedly occupied; supplemental ownership was retained.");
                    TrySignalHostStop(retainedHost);
                    retainedHost.Guardian?.TryTerminate(13);
                    lock (_disposeFinalizationSync)
                    {
                        EnsureHostExitObserver_NoLock(mountPoint, retainedHost);
                    }
                }
            }
            else
            {
                CleanupHostResources(
                    new HostProcessState(
                        process ?? new Process(),
                        guardian,
                        lifetimeSentinel,
                        lifetimeFilePath,
                        startupGate.FilePath,
                        statusFilePath,
                        accessMode,
                        _options.WriteBackendMode));
            }

            throw new InvalidOperationException(
                "Unable to establish an OS-level lifetime guardian for the native mount host.",
                ex);
        }
    }

    private static void AppendRecoveryIdentityArgument(ProcessStartInfo psi, string? recoveryIdentity)
    {
        if (string.IsNullOrWhiteSpace(recoveryIdentity))
        {
            return;
        }

        psi.ArgumentList.Add("--recovery-identity");
        psi.ArgumentList.Add(recoveryIdentity);
    }

    private static void PropagateRuntimeScratchEnvironment(ProcessStartInfo psi)
    {
        foreach (var key in new[]
        {
            "TEMP",
            "TMP",
            "APFSACCESS_SPOOL_ROOT",
            "APFSACCESS_RUNTIME_ROOT",
            "APFSACCESS_TRACE_MOVES",
            "APFSACCESS_PERF_COUNTERS",
            "APFSACCESS_TRACE_COMMITS",
            "APFSACCESS_TRACE_READS",
            "APFSACCESS_DEFER_CLOSE_COMMITS",
            "APFSACCESS_DISABLE_CONTENT_WRITEBACK",
            "APFSACCESS_ENABLE_GROUPED_DEFERRED_ACCEPTANCE",
            "APFSACCESS_DISABLE_GROUPED_DEFERRED_ACCEPTANCE",
            "APFSACCESS_DISABLE_DEFERRED_INDEX_PERSISTENCE",
            "APFSACCESS_EXPERIMENTAL_NAMESPACE_WRITEBACK",
            "APFSACCESS_DISABLE_NAMESPACE_WRITEBACK",
            "APFSACCESS_DISABLE_ASYNC_BLOCK_IO",
            "APFSACCESS_ASYNC_BLOCK_IO_DEPTH",
            "APFSACCESS_CHECKPOINT_DELTA_SHADOW",
            "APFSACCESS_STRICT_COMMIT_VERIFY",
            "APFSACCESS_DISABLE_WORKING_FREE_SANITIZE_CACHE",
            "APFSACCESS_DISABLE_CHECKPOINT_SERIALIZATION_BUFFER_REUSE",
            "APFSACCESS_DISABLE_CHECKPOINT_SLOT_INDEX",
            "APFSACCESS_DISABLE_CHECKPOINT_BLOCK_INDEX_CACHE",
            "APFSACCESS_DISABLE_INDEX_DELTA",
        })
        {
            var value = Environment.GetEnvironmentVariable(key);
            if (!string.IsNullOrWhiteSpace(value))
            {
                psi.Environment[key] = value;
            }
        }
    }

    private async Task<HostStopResult> StopHostProcessAsync(HostProcessState host, CancellationToken cancellationToken)
    {
        TrySignalHostStop(host);

        if (cancellationToken.IsCancellationRequested)
        {
            var canceledProcessExited = TryProveProcessExited(host, out var canceledExitCode);
            if (!canceledProcessExited && !string.IsNullOrWhiteSpace(host.TrackedMountPoint))
            {
                EnsureHostExitObserver(host.TrackedMountPoint!, host);
            }

            return new HostStopResult(
                ProcessExited: canceledProcessExited,
                ForcedKill: false,
                ExitCode: canceledProcessExited ? canceledExitCode : null);
        }

        var timeout = TimeSpan.FromSeconds(Math.Clamp(_options.NativeHostStopTimeoutSeconds, 1, 60));
        using var timeoutCts = new CancellationTokenSource(timeout);

        HostStopResult result;
        try
        {
            if (!TryProveProcessExited(host, out _))
            {
                await host.Process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
            }

            var processExited = TryProveProcessExited(host, out var exitCode);
            result = new HostStopResult(
                ProcessExited: processExited,
                ForcedKill: false,
                ExitCode: processExited ? exitCode : null);
        }
        catch (OperationCanceledException)
        {
            var forcedKill = false;
            try
            {
                forcedKill = host.Guardian?.TryTerminate(13) == true;
                if (!TryProveProcessExited(host, out _))
                {
                    if (!forcedKill)
                    {
                        forcedKill = TryKillProcess(host.Process);
                    }
                    using var killWaitCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    try
                    {
                        await host.Process.WaitForExitAsync(killWaitCts.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (!TryProveProcessExited(host, out _))
                    {
                        // Keep ProcessExited=false truthful. The caller will
                        // quarantine the mount and refuse a remount while the
                        // old host remains owned.
                    }
                }
            }
            catch
            {
                // Best-effort force-kill.
            }

            var processExited = TryProveProcessExited(host, out _);
            result = new HostStopResult(
                ProcessExited: processExited,
                ForcedKill: forcedKill,
                ExitCode: processExited ? TryGetHostExitCode(host.Process) : null);
        }
        catch (Exception ex)
        {
            WriteLifecycleDiagnostic(
                "host-stop-observation-failed",
                host.TrackedMountPoint,
                host,
                $"Stop observation failed with {ex.GetType().Name}; ownership remains retained.");
            result = new HostStopResult(ProcessExited: false, ForcedKill: false, ExitCode: null);
        }

        if (!result.ProcessExited && !string.IsNullOrWhiteSpace(host.TrackedMountPoint))
        {
            EnsureHostExitObserver(host.TrackedMountPoint!, host);
        }

        return result;
    }

    private async Task<HostStopResult> StopStartedHostProcessAsync(
        string mountPoint,
        HostProcessState host,
        CancellationToken cancellationToken)
    {
        host = host with { TrackedMountPoint = mountPoint };

        // Register ownership before issuing the stop. Any unexpected exception
        // then leaves the host reachable by later cleanup instead of orphaned.
        _hosts[mountPoint] = host;
        Interlocked.Increment(ref _mountStateVersion);
        HostStopResult result;
        try
        {
            result = await StopHostProcessAsync(host, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            TrySignalHostStop(host);
            WriteLifecycleDiagnostic(
                "host-stop-unhandled-failure",
                mountPoint,
                host,
                $"Stop operation failed with {ex.GetType().Name}; ownership remains retained.");
            result = new HostStopResult(ProcessExited: false, ForcedKill: false, ExitCode: null);
        }

        if (result.ProcessExited)
        {
            lock (_disposeFinalizationSync)
            {
                if (!TryFinalizeProvenHost_NoLock(mountPoint, host) &&
                    !IsHostExitObserverOwned_NoLock(host))
                {
                    CleanupHostResources(host);
                }
            }
        }
        else
        {
            EnsureHostExitObserver(mountPoint, host);
        }
        return result;
    }

    private static string DescribeHostStopResult(HostStopResult result)
    {
        if (!result.ProcessExited)
        {
            return "FsHost remained alive after the bounded stop attempt; ownership was retained";
        }

        if (result.ForcedKill)
        {
            return $"FsHost required a forced stop (exitCode={result.ExitCode?.ToString() ?? "unknown"})";
        }

        return $"FsHost exited (exitCode={result.ExitCode?.ToString() ?? "unknown"})";
    }

    private static UnmountResult BuildCompletedUnmountResult(string mountPoint, HostStopResult stopResult)
    {
        if (IsCleanHostStop(stopResult.ProcessExited, stopResult.ForcedKill, stopResult.ExitCode))
        {
            return new UnmountResult(
                true,
                mountPoint,
                null,
                MountRemoved: true,
                HostOwnershipReleased: true,
                PendingDurabilityCleared: true);
        }

        var error = stopResult.ForcedKill
            ? "FsHost was force-stopped before pending writes could be finalized."
            : stopResult.ExitCode.HasValue
                ? $"FsHost stopped with exit code {stopResult.ExitCode.Value}; pending writes were not finalized safely."
                : "FsHost stopped, but its final write status was unavailable.";
        return new UnmountResult(false, mountPoint, error, MountRemoved: true);
    }

    private static bool IsCleanHostStop(bool processExited, bool forcedKill, int? exitCode)
        => processExited && !forcedKill && exitCode == 0;

    private static int? TryGetHostExitCode(Process process)
    {
        try
        {
            return process.HasExited ? process.ExitCode : null;
        }
        catch
        {
            return null;
        }
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

            var driveVisible = IsDriveVisible(mountPoint);
            if (IsMountStartupReady(
                    driveVisible,
                    hostMountReady: false,
                    accessMode,
                    configuredWriteBackend))
            {
                return true;
            }

            var hostMountReady = await IsHostMountReadyAsync(
                    statusFilePath,
                    accessMode,
                    configuredWriteBackend,
                    cancellationToken
                ).ConfigureAwait(false);
            if (IsMountStartupReady(
                    driveVisible,
                    hostMountReady,
                    accessMode,
                    configuredWriteBackend))
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

    private static bool IsMountStartupReady(
        bool driveVisible,
        bool hostMountReady,
        MountAccessMode accessMode,
        string? configuredWriteBackend)
    {
        if (hostMountReady)
        {
            return true;
        }

        var requiresSettledNativeWriteStatus =
            accessMode == MountAccessMode.ReadWrite &&
            IsWriteBackendMode(configuredWriteBackend, "Native");
        return driveVisible && !requiresSettledNativeWriteStatus;
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

        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        // Do not ask the filesystem provider for root attributes or volume
        // information here. Those calls enter WinFsp callbacks and can stall
        // the service's mount/eject state machine when a provider is unhealthy.
        // Mount Manager's DOS-device mapping is a provider-independent signal
        // that is sufficient for drive-letter collision and removal checks.
        return Win32DriveVisibilityProbe.HasDosDevice(normalizedMountPoint);
    }

    private static class Win32ProcessPresenceProbe
    {
        private const int InitialProcessCapacity = 1024;
        private const int MaximumProcessCapacity = 1 << 20;

        public static bool TryIsEnumerated(int processId, out bool isEnumerated)
        {
            isEnumerated = false;
            if (!OperatingSystem.IsWindows() || processId <= 0)
            {
                return false;
            }

            try
            {
                for (var capacity = InitialProcessCapacity;
                     capacity <= MaximumProcessCapacity;
                     capacity *= 2)
                {
                    var processIds = new uint[capacity];
                    var bufferBytes = checked((uint)(processIds.Length * sizeof(uint)));
                    if (!EnumProcesses(processIds, bufferBytes, out var bytesReturned))
                    {
                        return false;
                    }

                    var count = checked((int)(bytesReturned / sizeof(uint)));
                    for (var index = 0; index < count; index++)
                    {
                        if (processIds[index] == (uint)processId)
                        {
                            isEnumerated = true;
                            return true;
                        }
                    }

                    if (bytesReturned < bufferBytes)
                    {
                        return true;
                    }
                }
            }
            catch
            {
                return false;
            }

            return false;
        }

        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EnumProcesses(
            [Out] uint[] processIds,
            uint bufferBytes,
            out uint bytesReturned);
    }

    private static class Win32ToolhelpProcessPresenceProbe
    {
        private const uint SnapshotProcess = 0x00000002;
        private const int ErrorNoMoreFiles = 18;
        private const int MaximumProcessEntries = 131_072;
        private static readonly TimeSpan EnumerationBudget = TimeSpan.FromMilliseconds(250);

        public static bool TryIsEnumerated(int processId, out bool isEnumerated)
        {
            isEnumerated = false;
            if (!OperatingSystem.IsWindows() || processId <= 0)
            {
                return false;
            }

            try
            {
                var snapshotHandle = CreateToolhelp32Snapshot(SnapshotProcess, 0);
                if (snapshotHandle == nint.Zero || snapshotHandle == (nint)(-1))
                {
                    return false;
                }

                using var snapshot = new SnapshotHandle(snapshotHandle);
                var entry = new ProcessEntry32
                {
                    Size = (uint)Marshal.SizeOf<ProcessEntry32>(),
                    ExecutableFile = string.Empty,
                };
                if (!Process32FirstW(snapshot, ref entry))
                {
                    return false;
                }

                var startedAt = Stopwatch.GetTimestamp();
                for (var entryCount = 0; entryCount < MaximumProcessEntries; entryCount++)
                {
                    if (entry.ProcessId == (uint)processId)
                    {
                        isEnumerated = true;
                        return true;
                    }

                    if (Stopwatch.GetElapsedTime(startedAt) >= EnumerationBudget)
                    {
                        return false;
                    }

                    if (Process32NextW(snapshot, ref entry))
                    {
                        continue;
                    }

                    return Marshal.GetLastWin32Error() == ErrorNoMoreFiles;
                }
            }
            catch
            {
                return false;
            }

            return false;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern nint CreateToolhelp32Snapshot(
            uint flags,
            uint processId);

        [DllImport("kernel32.dll", EntryPoint = "Process32FirstW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool Process32FirstW(
            SnapshotHandle snapshot,
            ref ProcessEntry32 entry);

        [DllImport("kernel32.dll", EntryPoint = "Process32NextW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool Process32NextW(
            SnapshotHandle snapshot,
            ref ProcessEntry32 entry);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(nint handle);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ProcessEntry32
        {
            public uint Size;
            public uint UsageCount;
            public uint ProcessId;
            public nuint DefaultHeapId;
            public uint ModuleId;
            public uint ThreadCount;
            public uint ParentProcessId;
            public int BasePriority;
            public uint Flags;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string? ExecutableFile;
        }

        private sealed class SnapshotHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SnapshotHandle(nint handle)
                : base(ownsHandle: true)
            {
                SetHandle(handle);
            }

            protected override bool ReleaseHandle() => CloseHandle(handle);
        }
    }

    private static class Win32ProcessIdentityProbe
    {
        private const uint ProcessQueryLimitedInformation = 0x1000;
        private const uint Synchronize = 0x00100000;
        private const uint WaitObjectSignaled = 0;
        private const uint WaitTimeout = 0x00000102;
        private const uint WaitFailed = 0xFFFFFFFF;

        public static bool? TryHasExited(Process process)
        {
            try
            {
                var handle = process.SafeHandle;
                if (handle is null || handle.IsInvalid || handle.IsClosed)
                {
                    return null;
                }

                var waitResult = WaitForSingleObject(handle, 0);
                return waitResult switch
                {
                    WaitObjectSignaled => true,
                    WaitTimeout => false,
                    WaitFailed => null,
                    _ => null,
                };
            }
            catch
            {
                return null;
            }
        }

        public static bool TryGetCreationTime(Process process, out long creationTimeFileTimeUtc)
        {
            try
            {
                var handle = process.SafeHandle;
                if (handle is null || handle.IsInvalid || handle.IsClosed)
                {
                    creationTimeFileTimeUtc = 0;
                    return false;
                }

                return GetProcessTimes(
                    handle,
                    out creationTimeFileTimeUtc,
                    out _,
                    out _,
                    out _);
            }
            catch
            {
                creationTimeFileTimeUtc = 0;
                return false;
            }
        }

        public static bool TryGetCreationTime(int processId, out long creationTimeFileTimeUtc)
        {
            creationTimeFileTimeUtc = 0;
            if (!OperatingSystem.IsWindows() || processId <= 0)
            {
                return false;
            }

            try
            {
                using var handle = OpenProcess(
                    ProcessQueryLimitedInformation | Synchronize,
                    inheritHandle: false,
                    (uint)processId);
                if (handle is null || handle.IsInvalid || handle.IsClosed)
                {
                    return false;
                }

                return GetProcessTimes(
                    handle,
                    out creationTimeFileTimeUtc,
                    out _,
                    out _,
                    out _);
            }
            catch
            {
                creationTimeFileTimeUtc = 0;
                return false;
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(
            SafeProcessHandle handle,
            uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetProcessTimes(
            SafeProcessHandle process,
            out long creationTime,
            out long exitTime,
            out long kernelTime,
            out long userTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeProcessHandle OpenProcess(
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            uint processId);
    }

    private static class Win32DriveVisibilityProbe
    {
        private const int DosDeviceBufferLength = 4096;

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

    private static class Win32FileGeneration
    {
        public static bool TryRead(string path, out RuntimeStatusFileGeneration generation)
        {
            generation = default;
            if (!OperatingSystem.IsWindows())
            {
                return false;
            }

            try
            {
                using var handle = File.OpenHandle(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                if (!GetFileInformationByHandleEx(
                        handle,
                        FileInfoByHandleClass.FileBasicInfo,
                        out FileBasicInfo basicInfo,
                        (uint)Marshal.SizeOf<FileBasicInfo>()) ||
                    !GetFileInformationByHandleEx(
                        handle,
                        FileInfoByHandleClass.FileIdInfo,
                        out FileIdInfo fileIdInfo,
                        (uint)Marshal.SizeOf<FileIdInfo>()))
                {
                    return false;
                }

                generation = new RuntimeStatusFileGeneration(
                    basicInfo.ChangeTime,
                    fileIdInfo.VolumeSerialNumber,
                    fileIdInfo.FileIdLow,
                    fileIdInfo.FileIdHigh);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private enum FileInfoByHandleClass
        {
            FileBasicInfo = 0,
            FileIdInfo = 18,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileBasicInfo
        {
            public long CreationTime;
            public long LastAccessTime;
            public long LastWriteTime;
            public long ChangeTime;
            public uint FileAttributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileIdInfo
        {
            public ulong VolumeSerialNumber;
            public ulong FileIdLow;
            public ulong FileIdHigh;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle hFile,
            FileInfoByHandleClass fileInformationClass,
            out FileBasicInfo fileInformation,
            uint bufferSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle hFile,
            FileInfoByHandleClass fileInformationClass,
            out FileIdInfo fileInformation,
            uint bufferSize);
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
        private const uint IoctlDiskGetDriveLayoutEx = 0x00070050;
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

        public static bool TryGetPhysicalDriveDiscoveryFingerprint(string devicePath, out DiscoveryFingerprint fingerprint)
        {
            fingerprint = default;

            if (string.IsNullOrWhiteSpace(devicePath) || !OperatingSystem.IsWindows())
            {
                return false;
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
                    return false;
                }

                var bufferLength = 8192;
                for (var attempt = 0; attempt < 3; attempt++)
                {
                    var buffer = new byte[bufferLength];
                    var success = DeviceIoControl(
                        handle,
                        IoctlDiskGetDriveLayoutEx,
                        nint.Zero,
                        0,
                        buffer,
                        buffer.Length,
                        out var bytesReturned,
                        nint.Zero);
                    if (success && bytesReturned > 0)
                    {
                        var hash = SHA256.HashData(buffer.AsSpan(0, (int)bytesReturned));
                        fingerprint = new DiscoveryFingerprint("layout", Convert.ToHexString(hash));
                        return true;
                    }

                    var lastError = Marshal.GetLastWin32Error();
                    if (lastError is not 122 and not 234)
                    {
                        return false;
                    }

                    bufferLength *= 2;
                }
            }
            catch
            {
                return false;
            }

            return false;
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

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            nint lpInBuffer,
            int nInBufferSize,
            byte[] lpOutBuffer,
            int nOutBufferSize,
            out uint lpBytesReturned,
            nint lpOverlapped);
    }

    private void CleanupExitedHosts_NoLock()
    {
        lock (_disposeFinalizationSync)
        {
            foreach (var kvp in _hosts.ToArray())
            {
                if (IsHostExitObserverOwned_NoLock(kvp.Value) ||
                    !TryProveProcessExited(kvp.Value, out var exitCode))
                {
                    // An observer owns its Process until it completes. A
                    // failed process observation is not proof of exit either.
                    continue;
                }

                if (TryRemoveHost(kvp.Key, kvp.Value, out var host))
                {
                    Interlocked.Increment(ref _mountStateVersion);
                    var mountTracked = _mounts.ContainsKey(kvp.Key);
                    if (mountTracked)
                    {
                        var stopResult = new HostStopResult(
                            ProcessExited: true,
                            ForcedKill: false,
                            ExitCode: exitCode);
                        _completedHostStops[kvp.Key] = stopResult;
                        if (!IsCleanHostStop(
                                stopResult.ProcessExited,
                                stopResult.ForcedKill,
                                stopResult.ExitCode) &&
                            _mounts.TryGetValue(kvp.Key, out var mountedState))
                        {
                            _mounts[kvp.Key] = MarkUnexpectedHostStop(mountedState, stopResult);
                        }
                    }

                    InvalidateRuntimeStatusCache(host.StatusFilePath);
                    CleanupHostResources(host);
                }
            }

            foreach (var kvp in _retainedStartupHosts.ToArray())
            {
                var host = kvp.Value;
                if (IsHostExitObserverOwned_NoLock(host) ||
                    !TryProveProcessExited(host, out _))
                {
                    continue;
                }

                if (TryRemoveRetainedStartupHost(host, out var removedHost))
                {
                    Interlocked.Increment(ref _mountStateVersion);
                    InvalidateRuntimeStatusCache(removedHost.StatusFilePath);
                    CleanupHostResources(removedHost);
                }
            }

            CleanupDetachedMounts_NoLock();
            CompleteDisposeIfNoHosts_NoLock();
        }
    }

    private static MountedVolumeState MarkUnexpectedHostStop(
        MountedVolumeState mountedState,
        HostStopResult stopResult)
    {
        var exitDetail = stopResult.ExitCode.HasValue
            ? $"FsHost exited with code {stopResult.ExitCode.Value}."
            : "FsHost exited without a readable exit code.";
        var diagnostic = new NativeWriteDiagnostic(
            Code: "FsHostUnexpectedExit",
            Message: $"{exitDetail} Pending writes were not proven durable.",
            IsFailClosed: true,
            Scope: "Runtime:HostStop",
            RecoveryReason: "FsHostExitedUnexpectedly",
            RecoveryAction: "RemountBlockedUntilFix");
        var diagnostics = (mountedState.NativeWriteDiagnostics ?? Array.Empty<NativeWriteDiagnostic>())
            .Append(diagnostic)
            .ToArray();

        return mountedState with
        {
            AccessMode = MountAccessMode.ReadOnly,
            WriteBackend = "Disabled",
            NativeWriteReadiness = NativeWriteReadiness.RecoveryMode,
            RecoveryActive = true,
            RecoveryReason = "FsHostExitedUnexpectedly",
            NativeWriteSafetyState = NativeWriteSafetyState.RecoveryBlocked,
            LastRecoveryAction = "RemountBlockedUntilFix",
            NativeWriteDiagnostics = diagnostics,
        };
    }

    private void CleanupDetachedMounts_NoLock()
    {
        foreach (var kvp in _mounts.ToArray())
        {
            if (_hosts.ContainsKey(kvp.Key) ||
                HasRetainedStartupHost_NoLock(kvp.Key) ||
                _completedHostStops.ContainsKey(kvp.Key) ||
                IsDriveVisible(kvp.Key))
            {
                continue;
            }

            if (_mounts.TryRemove(kvp.Key, out _))
            {
                Interlocked.Increment(ref _mountStateVersion);
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
        if (!host.TryClaimResourceCleanup())
        {
            return;
        }

        try
        {
            host.LifetimeSentinel?.Dispose();
        }
        catch
        {
            // Best-effort lifetime signal cleanup.
        }

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
            // Closing a live guardian is intentionally a final kill-on-close
            // boundary. Normal paths reach this point only after the host has
            // exited; failed teardown paths use it to prevent an orphan.
            host.Guardian?.Dispose();
        }
        catch
        {
            // Best-effort guardian cleanup.
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

        try
        {
            if (File.Exists(host.StartupGateFilePath))
            {
                File.Delete(host.StartupGateFilePath);
            }
        }
        catch
        {
            // Best-effort startup authorization cleanup.
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
            NativeWriteReadiness: nativeWriteReadiness,
            RecoveryIdentity: discoveredVolume.MountTarget.RecoveryIdentity
        );
    }

    private async Task<VolumeInfo?> ResolveVolumeAsync(string volumeId, CancellationToken cancellationToken)
    {
        if (!TryParseVolumeId(volumeId, out var deviceId, out _))
        {
            return null;
        }

        var discoveredVolumes = await ProbeVolumesAsync(deviceId, cancellationToken).ConfigureAwait(false);
        return discoveredVolumes.FirstOrDefault(volume =>
            string.Equals(volume.VolumeId, volumeId, StringComparison.OrdinalIgnoreCase));
    }

    private VolumeMountTarget ResolveMountTarget(VolumeInfo volume)
    {
        // Runtime-status recovery diagnostics can carry a metadata-only volume
        // fallback. It is not a mount candidate and has no native volume path.
        if (volume.NativeVolumePath is null)
        {
            return new VolumeMountTarget(volume.DeviceId, 0, RecoveryIdentity: null);
        }

        if (TryParseVolumeId(volume.VolumeId, out var volumeDeviceId, out var volumeName) &&
            string.Equals(volume.DeviceId, volumeDeviceId, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(volume.VolumeName, volumeName, StringComparison.OrdinalIgnoreCase) &&
            _mountTargetsByVolumeId.TryGetValue(volume.VolumeId, out var mountTarget) &&
            string.Equals(mountTarget.DevicePath, volumeDeviceId, StringComparison.OrdinalIgnoreCase))
        {
            return mountTarget;
        }

        throw new InvalidOperationException(
            $"No authoritative mount target was discovered for volume '{volume.VolumeId}'.");
    }

    private DiscoveredDevice? DiscoverDevice(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return null;
        }

        if (!TryGetDiscoveryFingerprint(deviceId, out var discoveryFingerprint))
        {
            return DiscoverDeviceWithoutCache(deviceId);
        }

        if (_deviceDiscoveryCache.TryGetValue(deviceId, out var cachedDiscovery) &&
            cachedDiscovery.Fingerprint.Equals(discoveryFingerprint))
        {
            return cachedDiscovery.Device;
        }

        System.Threading.Interlocked.Increment(ref _deviceDiscoveryScanCount);
        var discoveredVolumes = DiscoverVolumes(deviceId);
        if (discoveredVolumes.Count == 0)
        {
            _deviceDiscoveryCache.TryRemove(deviceId, out _);
            RemoveCachedVolumesForDevice(deviceId);
            return null;
        }

        var displayName = IsRawPhysicalDevicePath(deviceId)
            ? BuildDeviceDisplayName(deviceId)
            : $"APFS Image ({Path.GetFileName(deviceId)})";

        var discovered = new DiscoveredDevice(deviceId, displayName, discoveredVolumes);
        _deviceDiscoveryCache[deviceId] = new DiscoveryCacheEntry(discoveryFingerprint, discovered);
        CacheDiscoveredVolumes(discoveredVolumes, deviceId);
        return discovered;
    }

    private DiscoveredDevice? DiscoverDeviceWithoutCache(string deviceId)
    {
        System.Threading.Interlocked.Increment(ref _deviceDiscoveryScanCount);
        var discoveredVolumes = DiscoverVolumes(deviceId);
        if (discoveredVolumes.Count == 0)
        {
            _deviceDiscoveryCache.TryRemove(deviceId, out _);
            RemoveCachedVolumesForDevice(deviceId);
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

        if (TryReadApfsContainerHeader(deviceId, 0, out var directContainerHeader) &&
            directContainerHeader is not null)
        {
            discoveredVolumes.Add(new DiscoveredVolume(
                VolumeName: DefaultMainVolumeName,
                IsEncrypted: false,
                WriteIncompatibilities: Array.Empty<string>(),
                WriteUnsupportedFeatures: Array.Empty<string>(),
                NativeVolumePath: BuildNativeVolumePath(deviceId, DefaultMainVolumeName),
                MountTarget: new VolumeMountTarget(
                    deviceId,
                    0,
                    BuildRecoveryIdentity(
                        partitionUniqueGuid: null,
                        directContainerHeader,
                        allowPartitionlessIdentity: !IsRawPhysicalDevicePath(deviceId)))));
            return discoveredVolumes;
        }

        if (!TryReadGptPartitions(deviceId, out var partitions))
        {
            return discoveredVolumes;
        }

        var apfsPartitions = new List<(GptPartitionInfo Partition, ApfsContainerHeader ContainerHeader)>();
        foreach (var partition in partitions.Where(partition => partition.PartitionTypeGuid == ApfsPartitionTypeGuid))
        {
            if (TryReadApfsContainerHeader(deviceId, partition.StartOffsetBytes, out var containerHeader) &&
                containerHeader is not null)
            {
                apfsPartitions.Add((partition, containerHeader));
            }
        }

        foreach (var (partition, containerHeader) in apfsPartitions)
        {
            var baseName = NormalizeDiscoveredVolumeName(
                partition.PartitionName,
                allowDefaultMain: apfsPartitions.Count == 1,
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
                MountTarget: new VolumeMountTarget(
                    deviceId,
                    partition.StartOffsetBytes,
                    BuildRecoveryIdentity(
                        partition.IdentityMetadataTrusted ? partition.PartitionUniqueGuid : null,
                        containerHeader,
                        allowPartitionlessIdentity: false))));
        }

        return discoveredVolumes;
    }

    private static bool TryGetDiscoveryFingerprint(string deviceId, out DiscoveryFingerprint fingerprint)
    {
        fingerprint = default;

        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return false;
        }

        if (IsRawPhysicalDevicePath(deviceId))
        {
            return TryGetPhysicalDriveDiscoveryFingerprint(deviceId, out fingerprint);
        }

        try
        {
            var fullPath = Path.GetFullPath(deviceId);
            var fileInfo = new FileInfo(fullPath);
            if (!fileInfo.Exists)
            {
                return false;
            }

            fingerprint = new DiscoveryFingerprint(
                Kind: "file",
                Value: $"{fileInfo.Length}:{fileInfo.LastWriteTimeUtc.Ticks}");
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryGetPhysicalDriveDiscoveryFingerprint(string deviceId, out DiscoveryFingerprint fingerprint)
    {
        return Win32StorageDescriptor.TryGetPhysicalDriveDiscoveryFingerprint(deviceId, out fingerprint);
    }

    private void CacheDiscoveredVolumes(IReadOnlyList<DiscoveredVolume> discoveredVolumes, string deviceId)
    {
        var volumeIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var discoveredVolume in discoveredVolumes)
        {
            var volume = CreateDiscoveredVolumeInfo(deviceId, discoveredVolume);
            _volumeCache[volume.VolumeId] = volume;
            volumeIds.Add(volume.VolumeId);
        }

        RemoveStaleVolumeCacheEntries(deviceId, volumeIds);
    }

    private void RemoveCachedVolumesForDevice(string deviceId)
    {
        RemoveStaleVolumeCacheEntries(deviceId, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
    }

    private void RemoveStaleVolumeCacheEntries(string deviceId, HashSet<string> currentVolumeIds)
    {
        foreach (var cachedVolume in _volumeCache.Keys.ToArray())
        {
            if (!TryParseVolumeId(cachedVolume, out var cachedDeviceId, out _) ||
                !string.Equals(cachedDeviceId, deviceId, StringComparison.OrdinalIgnoreCase) ||
                currentVolumeIds.Contains(cachedVolume))
            {
                continue;
            }

            _volumeCache.TryRemove(cachedVolume, out _);
            _mountTargetsByVolumeId.TryRemove(cachedVolume, out _);
        }
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

            var headerChecksumValid = HasValidGptHeaderChecksum(header);
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

            var partitionEntriesChecksumValid = false;
            if (partitionEntryCount <= MaxGptEntriesToRead)
            {
                var storedEntriesChecksum = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(88, 4));
                partitionEntriesChecksumValid = storedEntriesChecksum != 0 &&
                                                ComputeCrc32(entriesBlock) == storedEntriesChecksum;
            }
            var identityMetadataTrusted = headerChecksumValid && partitionEntriesChecksumValid;

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
                var uniqueGuid = new Guid(entry.Slice(16, 16));
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
                    PartitionUniqueGuid: uniqueGuid,
                    IdentityMetadataTrusted: identityMetadataTrusted,
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

        if (!TryReadApfsContainerBlock(deviceId, offsetBytes, out var primaryHeader, out var primaryBlock) ||
            primaryHeader is null)
        {
            return false;
        }

        var selectedHeader = primaryHeader;
        if (primaryHeader.BlockSize > 0 &&
            TryReadApfsContainerBlock(
                deviceId,
                checked(offsetBytes + primaryHeader.BlockSize),
                out var secondaryHeader,
                out var secondaryBlock) &&
            secondaryHeader is not null &&
            secondaryHeader.BlockSize == primaryHeader.BlockSize &&
            secondaryHeader.TotalBlocks == primaryHeader.TotalBlocks &&
            secondaryHeader.VolumeRootBlock == primaryHeader.VolumeRootBlock)
        {
            if (HasLegacyCheckpointWriterChecksumSignature(
                    primaryHeader,
                    primaryBlock,
                    secondaryHeader,
                    secondaryBlock))
            {
                primaryHeader = primaryHeader with { IdentityMetadataTrusted = true };
                secondaryHeader = secondaryHeader with { IdentityMetadataTrusted = true };
                selectedHeader = primaryHeader;
            }

            if (((secondaryHeader.IdentityMetadataTrusted && !primaryHeader.IdentityMetadataTrusted) ||
                 string.Equals(secondaryHeader.ContainerUuid, primaryHeader.ContainerUuid, StringComparison.Ordinal)) &&
                secondaryHeader.CheckpointXid > primaryHeader.CheckpointXid)
            {
                selectedHeader = secondaryHeader;
            }
        }

        header = selectedHeader;
        return true;
    }

    private static bool HasLegacyCheckpointWriterChecksumSignature(
        ApfsContainerHeader primaryHeader,
        byte[] primaryBlock,
        ApfsContainerHeader secondaryHeader,
        byte[] secondaryBlock)
    {
        if (primaryHeader.IdentityMetadataTrusted ||
            secondaryHeader.IdentityMetadataTrusted ||
            primaryHeader.CheckpointXid == 0 ||
            secondaryHeader.CheckpointXid == 0 ||
            string.IsNullOrWhiteSpace(primaryHeader.ContainerUuid) ||
            !string.Equals(primaryHeader.ContainerUuid, secondaryHeader.ContainerUuid, StringComparison.Ordinal) ||
            !primaryHeader.FirstVolumeObjectId.HasValue ||
            primaryHeader.FirstVolumeObjectId.Value == 0 ||
            primaryHeader.FirstVolumeObjectId != secondaryHeader.FirstVolumeObjectId ||
            primaryBlock.Length != secondaryBlock.Length ||
            primaryBlock.Length != primaryHeader.BlockSize)
        {
            return false;
        }

        var lowerXid = Math.Min(primaryHeader.CheckpointXid, secondaryHeader.CheckpointXid);
        var higherXid = Math.Max(primaryHeader.CheckpointXid, secondaryHeader.CheckpointXid);
        if (lowerXid == ulong.MaxValue || higherXid != lowerXid + 1)
        {
            return false;
        }

        const int checkpointXidOffset = 0x10;
        const int checkpointXidBytes = sizeof(ulong);
        for (var index = 0; index < primaryBlock.Length; index++)
        {
            if (index is >= checkpointXidOffset and < checkpointXidOffset + checkpointXidBytes)
            {
                continue;
            }

            if (primaryBlock[index] != secondaryBlock[index])
            {
                return false;
            }
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
        var containerUuidBytes = block.AsSpan(0x48, 16);
        var containerUuid = containerUuidBytes.IndexOfAnyExcept((byte)0) >= 0
            ? Convert.ToHexString(containerUuidBytes)
            : null;
        ulong? firstVolumeObjectId = block.Length >= 0xC0
            ? BinaryPrimitives.ReadUInt64LittleEndian(block.AsSpan(0xB8, 8))
            : null;
        if (firstVolumeObjectId == 0)
        {
            firstVolumeObjectId = null;
        }

        if (magic != nxsbMagic ||
            blockSize is 0 or > (1 << 20) ||
            totalBlocks == 0 ||
            volumeRootBlock == 0)
        {
            return false;
        }

        var identityMetadataTrusted = block.Length == blockSize &&
                                      HasValidApfsObjectChecksum(block);
        header = new ApfsContainerHeader(
            blockSize,
            totalBlocks,
            checkpointXid,
            volumeRootBlock,
            containerUuid,
            firstVolumeObjectId,
            identityMetadataTrusted);
        return true;
    }

    private static bool TryReadApfsContainerBlock(
        string deviceId,
        ulong offsetBytes,
        out ApfsContainerHeader? header,
        out byte[] block)
    {
        header = default;
        block = Array.Empty<byte>();
        if (!TryReadBytes(deviceId, offsetBytes, 4096, out block) ||
            !TryParseApfsContainerHeader(block, out var parsedHeader) ||
            parsedHeader is null)
        {
            return false;
        }

        if (parsedHeader.BlockSize != block.Length)
        {
            if (!TryReadBytes(deviceId, offsetBytes, checked((int)parsedHeader.BlockSize), out block) ||
                !TryParseApfsContainerHeader(block, out parsedHeader) ||
                parsedHeader is null)
            {
                return false;
            }
        }

        header = parsedHeader;
        return true;
    }

    private static string? BuildRecoveryIdentity(
        Guid? partitionUniqueGuid,
        ApfsContainerHeader containerHeader,
        bool allowPartitionlessIdentity)
    {
        if (!containerHeader.IdentityMetadataTrusted)
        {
            return null;
        }

        return BuildRecoveryIdentityFromComponents(
            partitionUniqueGuid,
            containerHeader.ContainerUuid,
            containerHeader.FirstVolumeObjectId,
            allowPartitionlessIdentity);
    }

    private static string? BuildRecoveryIdentityFromComponents(
        Guid? partitionUniqueGuid,
        string? containerUuid,
        ulong? firstVolumeObjectId,
        bool allowPartitionlessIdentity)
    {
        var hasPartitionGuid = partitionUniqueGuid.HasValue && partitionUniqueGuid.Value != Guid.Empty;
        if ((!hasPartitionGuid && !allowPartitionlessIdentity) ||
            string.IsNullOrWhiteSpace(containerUuid) ||
            containerUuid.Length != 32 ||
            !firstVolumeObjectId.HasValue ||
            firstVolumeObjectId.Value == 0)
        {
            return null;
        }

        Span<byte> identityMaterial = stackalloc byte[42];
        identityMaterial.Clear();
        identityMaterial[0] = hasPartitionGuid ? (byte)1 : (byte)0;
        if (hasPartitionGuid)
        {
            partitionUniqueGuid!.Value.TryWriteBytes(identityMaterial.Slice(1, 16));
        }

        Convert.FromHexString(containerUuid).CopyTo(identityMaterial.Slice(17, 16));
        identityMaterial[33] = 1;
        BinaryPrimitives.WriteUInt64LittleEndian(
            identityMaterial.Slice(34, 8),
            firstVolumeObjectId.Value);

        var digest = SHA256.HashData(identityMaterial);
        var encodedDigest = Convert.ToBase64String(digest)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        return $"apfs-recovery-v1-{encodedDigest}";
    }

    private static bool HasValidGptHeaderChecksum(byte[] header)
    {
        var headerSize = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(12, 4));
        if (headerSize is < 92 || headerSize > (uint)header.Length)
        {
            return false;
        }

        var storedChecksum = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(16, 4));
        if (storedChecksum == 0)
        {
            return false;
        }

        var checksumBytes = header.AsSpan(0, checked((int)headerSize)).ToArray();
        checksumBytes.AsSpan(16, 4).Clear();
        return ComputeCrc32(checksumBytes) == storedChecksum;
    }

    private static uint ComputeCrc32(ReadOnlySpan<byte> bytes)
    {
        var crc = uint.MaxValue;
        foreach (var value in bytes)
        {
            crc ^= value;
            for (var bit = 0; bit < 8; bit++)
            {
                crc = (crc >> 1) ^ (0xEDB88320u & (uint)-(int)(crc & 1));
            }
        }

        return ~crc;
    }

    private static bool HasValidApfsObjectChecksum(byte[] block)
    {
        if (block.Length < 12 || (block.Length - 8) % sizeof(uint) != 0)
        {
            return false;
        }

        var storedChecksum = BinaryPrimitives.ReadUInt64LittleEndian(block);
        return storedChecksum != 0 &&
               storedChecksum != ulong.MaxValue &&
               ComputeApfsObjectChecksum(block.AsSpan(8)) == storedChecksum;
    }

    private static ulong ComputeApfsObjectChecksum(ReadOnlySpan<byte> bytes)
    {
        const ulong modulus = uint.MaxValue;
        ulong sum1 = 0;
        ulong sum2 = 0;
        for (var offset = 0; offset < bytes.Length; offset += sizeof(uint))
        {
            sum1 += BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(offset, sizeof(uint)));
            sum2 += sum1;
        }

        var low = modulus - ((sum1 + sum2) % modulus);
        var high = modulus - ((sum1 + low) % modulus);
        return (high << 32) | low;
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

    private static string? GetMountedReadOnlyIdentityFallbackReason(
        MountAccessMode requestedAccessMode,
        string? hostWriteBackend,
        string? recoveryReason)
    {
        if (requestedAccessMode != MountAccessMode.ReadWrite ||
            !string.Equals(
                NormalizeWriteBackendName(hostWriteBackend),
                "Disabled",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return NormalizeRecoveryReason(recoveryReason) switch
        {
            "ImmutableRecoveryIdentityMissing" => "ImmutableRecoveryIdentityMissing",
            "ImmutableRecoveryIdentityInvalid" => "ImmutableRecoveryIdentityInvalid",
            "LegacyRecoveryEvidenceAmbiguous" => "LegacyRecoveryEvidenceAmbiguous",
            _ => null,
        };
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
        var walAcceptedSequence = payload.WalAcceptedSequence ?? fallback.WalAcceptedSequence;
        var walApfsDurableSequence = payload.WalApfsDurableSequence ?? fallback.WalApfsDurableSequence;
        var walCleanupSequence = payload.WalCleanupSequence ?? fallback.WalCleanupSequence;
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
                WalAcceptedSequence = walAcceptedSequence,
                WalApfsDurableSequence = walApfsDurableSequence,
                WalCleanupSequence = walCleanupSequence,
            };
        }

        var backend = NormalizeWriteBackendName(payload.WriteBackend);
        if (string.Equals(backend, "Disabled", StringComparison.OrdinalIgnoreCase) &&
            GetMountedReadOnlyIdentityFallbackReason(accessMode, backend, recoveryReason) is null)
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
                WalAcceptedSequence = walAcceptedSequence,
                WalApfsDurableSequence = walApfsDurableSequence,
                WalCleanupSequence = walCleanupSequence,
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
                WalAcceptedSequence = walAcceptedSequence,
                WalApfsDurableSequence = walApfsDurableSequence,
                WalCleanupSequence = walCleanupSequence,
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
            WalAcceptedSequence = walAcceptedSequence,
            WalApfsDurableSequence = walApfsDurableSequence,
            WalCleanupSequence = walCleanupSequence,
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
                    var json = await ReadAllTextSharedAsync(statusFilePath, cancellationToken).ConfigureAwait(false);
                    if (TryParseHostRuntimeStatus(json, accessMode, fallback, out var status))
                    {
                        return status;
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

    private static bool TryParseHostRuntimeStatus(
        string? json,
        MountAccessMode accessMode,
        HostRuntimeStatus fallback,
        out HostRuntimeStatus status)
    {
        status = fallback;
        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        HostRuntimeStatusPayload? payload = null;
        try
        {
            payload = JsonSerializer.Deserialize<HostRuntimeStatusPayload>(
                json,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                });
        }
        catch
        {
            payload = TryDeserializeHostRuntimeStatusPayloadLenient(json);
        }

        payload ??= TryDeserializeHostRuntimeStatusPayloadLenient(json);
        if (payload is null)
        {
            return false;
        }

        status = BuildHostRuntimeStatusFromPayload(payload, accessMode, fallback);
        return true;
    }

    private static async Task<string> ReadAllTextSharedAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 4096,
            useAsync: true);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<HostRuntimeStatus> ReadHostRuntimeStatusCachedAsync(
        string statusFilePath,
        MountAccessMode accessMode,
        string? configuredWriteBackend,
        TimeSpan timeout,
        CancellationToken cancellationToken
    )
        => (await ReadHostRuntimeStatusResultCachedAsync(
            statusFilePath,
            accessMode,
            configuredWriteBackend,
            timeout,
            cancellationToken).ConfigureAwait(false)).Status;

    private async Task<RuntimeStatusReadResult> ReadHostRuntimeStatusResultCachedAsync(
        string statusFilePath,
        MountAccessMode accessMode,
        string? configuredWriteBackend,
        TimeSpan timeout,
        CancellationToken cancellationToken
    )
    {
        if (string.IsNullOrWhiteSpace(statusFilePath))
        {
            return BuildUntrustedRuntimeStatusResult(
                accessMode,
                configuredWriteBackend,
                "RuntimeStatusUntrusted",
                "StatusPathMissing");
        }

        string cacheKey;
        try
        {
            cacheKey = BuildRuntimeStatusCacheKey(statusFilePath, accessMode, configuredWriteBackend);
        }
        catch (Exception ex)
        {
            return BuildUntrustedRuntimeStatusResult(
                accessMode,
                configuredWriteBackend,
                "RuntimeStatusUntrusted",
                ex.GetType().Name);
        }

        var candidate = new Lazy<Task<RuntimeStatusReadResult>>(
            () => LoadRuntimeStatusAsync(
                cacheKey,
                statusFilePath,
                accessMode,
                configuredWriteBackend,
                timeout,
                _disposeCts.Token),
            LazyThreadSafetyMode.ExecutionAndPublication);
        var sharedRead = _runtimeStatusReads.GetOrAdd(cacheKey, candidate);
        var task = sharedRead.Value;
        _ = task.ContinueWith(
            _ => RemoveCompletedRuntimeStatusRead(cacheKey, sharedRead),
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);

        return await task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<RuntimeStatusReadResult> LoadRuntimeStatusAsync(
        string cacheKey,
        string statusFilePath,
        MountAccessMode accessMode,
        string? configuredWriteBackend,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _runtimeStatusReadOperationCount);
        var fallback = BuildDefaultHostRuntimeStatus(accessMode, configuredWriteBackend);
        var startedAt = Stopwatch.GetTimestamp();
        string? failureDetail = null;
        while (!cancellationToken.IsCancellationRequested)
        {
            var snapshot = await CaptureRuntimeStatusFileSnapshotAsync(
                statusFilePath,
                cancellationToken).ConfigureAwait(false);
            failureDetail = snapshot.FailureDetail;
            if (snapshot.IsStable && snapshot.Identity is not null)
            {
                var now = DateTime.UtcNow;
                if (_runtimeStatusCache.TryGetValue(cacheKey, out var cached) &&
                    RuntimeStatusFileIdentityMatches(cached.Identity, snapshot.Identity) &&
                    now - cached.ReadAtUtc <= RuntimeStatusCacheTtl)
                {
                    return new RuntimeStatusReadResult(
                        cached.Status,
                        snapshot.Identity,
                        IsTrusted: true,
                        FailureDetail: null);
                }

                if (snapshot.Identity.Metadata.Exists &&
                    TryParseHostRuntimeStatus(snapshot.Content, accessMode, fallback, out var status))
                {
                    _runtimeStatusCache[cacheKey] = new RuntimeStatusCacheEntry(
                        snapshot.Identity,
                        now,
                        status);
                    return new RuntimeStatusReadResult(
                        status,
                        snapshot.Identity,
                        IsTrusted: true,
                        FailureDetail: null);
                }
            }

            if (Stopwatch.GetElapsedTime(startedAt) >= timeout)
            {
                break;
            }

            await Task.Delay(150, cancellationToken).ConfigureAwait(false);
        }

        cancellationToken.ThrowIfCancellationRequested();
        return BuildUntrustedRuntimeStatusResult(
            accessMode,
            configuredWriteBackend,
            "RuntimeStatusUntrusted",
            failureDetail ?? "StatusUnavailable");
    }

    private static async Task<RuntimeStatusFileSnapshot> CaptureRuntimeStatusFileSnapshotAsync(
        string statusFilePath,
        CancellationToken cancellationToken)
    {
        string normalizedPath;
        try
        {
            normalizedPath = Path.GetFullPath(statusFilePath);
        }
        catch (Exception ex)
        {
            return new RuntimeStatusFileSnapshot(null, null, IsStable: false, ex.GetType().Name);
        }

        var before = CaptureRuntimeStatusFileMetadata(normalizedPath);
        if (!before.IsReadable)
        {
            return new RuntimeStatusFileSnapshot(null, null, IsStable: false, "MetadataUnavailable");
        }

        if (!before.Exists)
        {
            return new RuntimeStatusFileSnapshot(
                new RuntimeStatusFileIdentity(normalizedPath, before, string.Empty),
                null,
                IsStable: true,
                "StatusFileMissing");
        }

        string content;
        try
        {
            content = await ReadAllTextSharedAsync(normalizedPath, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new RuntimeStatusFileSnapshot(null, null, IsStable: false, ex.GetType().Name);
        }

        var after = CaptureRuntimeStatusFileMetadata(normalizedPath);
        var contentToken = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content)));
        var identity = new RuntimeStatusFileIdentity(normalizedPath, after, contentToken);
        return RuntimeStatusFileMetadataMatches(before, after)
            ? new RuntimeStatusFileSnapshot(identity, content, IsStable: true, FailureDetail: null)
            : new RuntimeStatusFileSnapshot(identity, content, IsStable: false, "StatusChangedDuringRead");
    }

    private static RuntimeStatusFileMetadata CaptureRuntimeStatusFileMetadata(string normalizedPath)
    {
        try
        {
            var info = new FileInfo(normalizedPath);
            info.Refresh();
            RuntimeStatusFileGeneration? generation = null;
            if (info.Exists && Win32FileGeneration.TryRead(normalizedPath, out var capturedGeneration))
            {
                generation = capturedGeneration;
            }
            return info.Exists
                ? new RuntimeStatusFileMetadata(
                    IsReadable: true,
                    Exists: true,
                    Length: info.Length,
                    CreationTimeUtc: info.CreationTimeUtc,
                    LastWriteTimeUtc: info.LastWriteTimeUtc,
                    Generation: generation)
                : new RuntimeStatusFileMetadata(
                    IsReadable: true,
                    Exists: false,
                    Length: 0,
                    CreationTimeUtc: default,
                    LastWriteTimeUtc: default,
                    Generation: null);
        }
        catch
        {
            return new RuntimeStatusFileMetadata(
                IsReadable: false,
                Exists: false,
                Length: 0,
                CreationTimeUtc: default,
                LastWriteTimeUtc: default,
                Generation: null);
        }
    }

    private static bool RuntimeStatusFileMetadataMatches(
        RuntimeStatusFileMetadata left,
        RuntimeStatusFileMetadata right)
        => left.IsReadable &&
           right.IsReadable &&
           left.Exists == right.Exists &&
           (!left.Exists ||
            left.Length == right.Length &&
            left.CreationTimeUtc == right.CreationTimeUtc &&
            left.LastWriteTimeUtc == right.LastWriteTimeUtc &&
            left.Generation == right.Generation);

    private static bool RuntimeStatusFileIdentityMatches(
        RuntimeStatusFileIdentity left,
        RuntimeStatusFileIdentity right)
        => string.Equals(left.NormalizedPath, right.NormalizedPath, StringComparison.OrdinalIgnoreCase) &&
           RuntimeStatusFileMetadataMatches(left.Metadata, right.Metadata) &&
           string.Equals(left.ContentToken, right.ContentToken, StringComparison.Ordinal);

    private static RuntimeStatusReadResult BuildUntrustedRuntimeStatusResult(
        HostProcessState hostState,
        string recoveryReason,
        string failureDetail)
        => BuildUntrustedRuntimeStatusResult(
            hostState.RequestedAccessMode,
            hostState.ConfiguredWriteBackend,
            recoveryReason,
            failureDetail);

    private static RuntimeStatusReadResult BuildUntrustedRuntimeStatusResult(
        MountAccessMode accessMode,
        string? configuredWriteBackend,
        string recoveryReason,
        string failureDetail)
        => new(
            BuildFailClosedRuntimeStatus(
                accessMode,
                configuredWriteBackend,
                recoveryReason),
            Identity: null,
            IsTrusted: false,
            FailureDetail: failureDetail);

    private void RemoveCompletedRuntimeStatusRead(
        string cacheKey,
        Lazy<Task<RuntimeStatusReadResult>> completedRead)
    {
        if (_runtimeStatusReads.TryGetValue(cacheKey, out var current) &&
            ReferenceEquals(current, completedRead))
        {
            _runtimeStatusReads.TryRemove(cacheKey, out _);
        }
    }

    private void InvalidateRuntimeStatusCache(string? statusFilePath)
    {
        if (string.IsNullOrWhiteSpace(statusFilePath))
        {
            return;
        }

        var prefix = Path.GetFullPath(statusFilePath) + "\u001f";
        foreach (var key in _runtimeStatusCache.Keys)
        {
            if (key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                _runtimeStatusCache.TryRemove(key, out _);
            }
        }

        foreach (var key in _runtimeStatusReads.Keys)
        {
            if (key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                _runtimeStatusReads.TryRemove(key, out _);
            }
        }
    }

    private static string BuildRuntimeStatusCacheKey(
        string statusFilePath,
        MountAccessMode accessMode,
        string? configuredWriteBackend)
        => string.Join(
            "\u001f",
            Path.GetFullPath(statusFilePath),
            accessMode,
            configuredWriteBackend?.Trim() ?? string.Empty);

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
                WalAcceptedSequence = ReadJsonUInt64(root, "walAcceptedSequence"),
                WalApfsDurableSequence = ReadJsonUInt64(root, "walApfsDurableSequence"),
                WalCleanupSequence = ReadJsonUInt64(root, "walCleanupSequence"),
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
        => WriteCapturedSessionMarkers(
            [CaptureWriteSessionMarker(
                requestedVolumeId,
                requestedAccessMode,
                mountPoint,
                gateState,
                diagnosticCode,
                error)]);

    private WriteSessionMarkerRequest CaptureWriteSessionMarker(
        string requestedVolumeId,
        MountAccessMode requestedAccessMode,
        string mountPoint,
        string gateState,
        string diagnosticCode,
        string error)
        => new(
            RequestedVolumeId: requestedVolumeId,
            RequestedAccessMode: requestedAccessMode,
            MountPoint: mountPoint,
            GateState: gateState,
            DiagnosticCode: diagnosticCode,
            Error: error,
            MountStateVersion: Volatile.Read(ref _mountStateVersion),
            ExpectedMountedState: null);

    private void WriteCapturedSessionMarkers(IReadOnlyList<WriteSessionMarkerRequest> requests)
    {
        foreach (var request in requests)
        {
            if (IsWriteSessionMarkerRequestCurrent(request))
            {
                WriteWriteSessionMarker(request);
            }
        }
    }

    private bool IsWriteSessionMarkerRequestCurrent(WriteSessionMarkerRequest request)
    {
        if (Volatile.Read(ref _mountStateVersion) != request.MountStateVersion)
        {
            return false;
        }

        return request.ExpectedMountedState is null ||
               _mounts.TryGetValue(request.MountPoint, out var current) &&
               ReferenceEquals(current, request.ExpectedMountedState);
    }

    private void WriteWriteSessionMarker(WriteSessionMarkerRequest request)
    {
        if (_gate.CurrentCount == 0)
        {
            Interlocked.Increment(ref _writeSessionMarkerIoWhileGateHeldCount);
        }

        try
        {
            Directory.CreateDirectory(_writeDiagnosticsRoot);
            var marker = new WriteSessionMarker(
                TimestampUtc: DateTime.UtcNow,
                RequestedVolumeId: request.RequestedVolumeId,
                RequestedAccessMode: request.RequestedAccessMode.ToString(),
                MountPoint: request.MountPoint,
                GateState: request.GateState,
                DiagnosticCode: request.DiagnosticCode,
                Error: request.Error,
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
        ulong VolumeRootBlock,
        string? ContainerUuid,
        ulong? FirstVolumeObjectId,
        bool IdentityMetadataTrusted
    );

    private sealed record GptPartitionInfo(
        int PartitionNumber,
        Guid PartitionTypeGuid,
        Guid PartitionUniqueGuid,
        bool IdentityMetadataTrusted,
        ulong StartOffsetBytes,
        string PartitionName
    );

    private sealed record VolumeMountTarget(
        string DevicePath,
        ulong DeviceOffsetBytes,
        string? RecoveryIdentity);

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

    private sealed record DiscoveryCacheEntry(
        DiscoveryFingerprint Fingerprint,
        DiscoveredDevice Device
    );

    private readonly record struct DiscoveryFingerprint(
        string Kind,
        string Value
    );

    private sealed record RuntimeStatusRefreshSnapshot(
        long Version,
        IReadOnlyList<RuntimeStatusRefreshEntry> Entries
    );

    private sealed record RuntimeStatusRefreshEntry(
        string MountPoint,
        HostProcessState HostState,
        MountedVolumeState MountedState
    );

    private sealed record HostProcessState(
        Process Process,
        HostProcessGuardian? Guardian,
        HostLifetimeSentinel? LifetimeSentinel,
        string LifetimeFilePath,
        string StartupGateFilePath,
        string StatusFilePath,
        MountAccessMode RequestedAccessMode,
        string? ConfiguredWriteBackend
    )
    {
        public string TrackingKey { get; } = Guid.NewGuid().ToString("N");

        public string? TrackedMountPoint { get; init; }

        // These values belong to the exact Process.Start handle and are never
        // refreshed from a PID lookup. They let cleanup distinguish a reused
        // PID from the original FsHost instance.
        public int ProcessId { get; } = TryGetProcessId(Process) ?? 0;

        public long? ProcessCreationTimeFileTimeUtc { get; } = CaptureProcessCreationTime(Process);

        private int _resourceCleanupClaimed;

        public bool TryClaimResourceCleanup()
            => Interlocked.Exchange(ref _resourceCleanupClaimed, 1) == 0;

        // Retain the legacy synthetic-fixture constructor used by the
        // reflection-based runtime-status tests. Real hosts always use the
        // guardian-bearing constructor from StartHostProcess.
        private HostProcessState(
            Process process,
            string lifetimeFilePath,
            string statusFilePath,
            MountAccessMode requestedAccessMode,
            string? configuredWriteBackend)
            : this(
                process,
                null,
                null,
                lifetimeFilePath,
                string.Empty,
                statusFilePath,
                requestedAccessMode,
                configuredWriteBackend)
        {
        }
    }

    private sealed record HostStopResult(bool ProcessExited, bool ForcedKill, int? ExitCode);

    private sealed record RuntimeStatusCacheEntry(
        RuntimeStatusFileIdentity Identity,
        DateTime ReadAtUtc,
        HostRuntimeStatus Status
    );

    private sealed record RuntimeStatusReadResult(
        HostRuntimeStatus Status,
        RuntimeStatusFileIdentity? Identity,
        bool IsTrusted,
        string? FailureDetail
    );

    private sealed record RuntimeStatusFileSnapshot(
        RuntimeStatusFileIdentity? Identity,
        string? Content,
        bool IsStable,
        string? FailureDetail
    );

    private sealed record RuntimeStatusFileIdentity(
        string NormalizedPath,
        RuntimeStatusFileMetadata Metadata,
        string ContentToken
    );

    private readonly record struct RuntimeStatusFileMetadata(
        bool IsReadable,
        bool Exists,
        long Length,
        DateTime CreationTimeUtc,
        DateTime LastWriteTimeUtc,
        RuntimeStatusFileGeneration? Generation
    );

    private readonly record struct RuntimeStatusFileGeneration(
        long ChangeTime,
        ulong VolumeSerialNumber,
        ulong FileIdLow,
        ulong FileIdHigh
    );

    private sealed class LifecycleOperationLease(NativeApfsBackend owner) : IDisposable
    {
        private NativeApfsBackend? _owner = owner;

        public void Dispose()
        {
            Interlocked.Exchange(ref _owner, null)?.ReleaseLifecycleOperationLease();
        }
    }

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

        public ulong WalAcceptedSequence { get; init; }

        public ulong WalApfsDurableSequence { get; init; }

        public ulong WalCleanupSequence { get; init; }
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

        public ulong? WalAcceptedSequence { get; init; }

        public ulong? WalApfsDurableSequence { get; init; }

        public ulong? WalCleanupSequence { get; init; }

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

    private sealed record WriteSessionMarkerRequest(
        string RequestedVolumeId,
        MountAccessMode RequestedAccessMode,
        string MountPoint,
        string GateState,
        string DiagnosticCode,
        string Error,
        long MountStateVersion,
        MountedVolumeState? ExpectedMountedState
    );
}

