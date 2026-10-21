using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace ApfsAccess.Cli;

public sealed record FsHostSupervisorOptions(
    string HostPath,
    IReadOnlyList<string> HostArguments,
    string OwnerPid,
    string LifetimeFile,
    string LaunchRecordPath,
    string EvidenceFile,
    string? WorkingDirectory = null,
    string? StartupGateFile = null,
    string? StartupGateToken = null,
    string? MountPoint = null,
    string? StatusFile = null,
    int GracefulTimeoutMs = 30_000,
    int ProcessAbsenceTimeoutMs = 15_000,
    int OwnerPollIntervalMs = 100,
    bool CredentialInput = false);

public sealed class FsHostSupervisorEvidence
{
    public int SchemaVersion { get; init; } = 2;
    public string Status { get; set; } = "starting";
    public int SupervisorPid { get; init; }
    public string SupervisorExecutable { get; init; } = string.Empty;
    public string SupervisorSha256 { get; init; } = string.Empty;
    public string SupervisorPayloadPath { get; init; } = string.Empty;
    public string SupervisorPayloadSha256 { get; init; } = string.Empty;
    public int? SupervisorExitCode { get; set; }
    public int OwnerPid { get; init; }
    public int? HostPid { get; set; }
    public int? HostParentPid { get; set; }
    public string HostExecutable { get; init; } = string.Empty;
    public IReadOnlyList<string> HostArguments { get; init; } = Array.Empty<string>();
    public string? WorkingDirectory { get; init; }
    public string LifetimeFile { get; init; } = string.Empty;
    public string? StartupGateFile { get; init; }
    public string? LaunchRecordPath { get; init; }
    public string EvidenceFile { get; init; } = string.Empty;
    public string? MountPoint { get; init; }
    public FsHostContainerManifestAuthority? ContainerManifestAuthority { get; set; }
    public IReadOnlyList<FsHostCohortMountProof> MountProofs { get; set; } = Array.Empty<FsHostCohortMountProof>();
    public bool JobMembersAbsent { get; set; }
    public bool CohortKeeperActive { get; set; }
    public int? CohortKeeperPid { get; set; }
    public string? CohortKeeperReason { get; set; }
    public DateTime? CohortKeeperStartedUtc { get; set; }
    public DateTime? CohortKeeperCompletedUtc { get; set; }
    public bool FailedQuarantineChildAbsent { get; set; }
    public string? StatusFile { get; init; }
    public DateTime StartedUtc { get; init; }
    public DateTime? LaunchProvenUtc { get; set; }
    public DateTime? GracefulStopRequestedUtc { get; set; }
    public DateTime? ForcedJobTerminationUtc { get; set; }
    public DateTime? CompletedUtc { get; set; }
    [JsonNumberHandling(JsonNumberHandling.WriteAsString | JsonNumberHandling.AllowReadingFromString)]
    public long? HostCreationTimeFileTime { get; set; }
    public bool OwnerAliveAtLaunch { get; set; }
    public bool OwnerDeathDetected { get; set; }
    public bool JobCreated { get; set; }
    public bool JobAssigned { get; set; }
    public bool Resumed { get; set; }
    public bool StartupGateAuthorized { get; set; }
    public bool SupervisionProven { get; set; }
    public bool GracefulStopRequested { get; set; }
    public bool GracefulStopCompleted { get; set; }
    public string GracefulStopResult { get; set; } = "not-requested";
    public bool ForcedJobTermination { get; set; }
    public string ForcedJobTerminationResult { get; set; } = "not-needed";
    public int? HostExitCode { get; set; }
    public bool HostIdentityCaptured { get; set; }
    public string HostIdentityState { get; set; } = "unknown";
    public bool HostPidAbsentFromProcessEnumeration { get; set; }
    public bool OriginalHostIdentityAbsent { get; set; }
    public bool HostPidReused { get; set; }
    public bool MountAbsentFromStatus { get; set; }
    public bool MountAbsentFromDirectProbe { get; set; }
    public string MountDirectProbeResult { get; set; } = "not-probed";
    public string MountStatusProbeResult { get; set; } = "not-requested";
    public bool MountAbsenceProven { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool StaleReadyStatusDischarged { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? StaleReadyStatusSha256 { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public FsHostCohortCrashBinding? CohortCrashBinding { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public FsHostCohortCrashProof? CohortCrashProof { get; set; }
    public string? MountProbeFailure { get; set; }
    public bool ExactProcessTerminationAttempted { get; set; }
    public string ExactProcessTerminationResult { get; set; } = "not-needed";
    public bool JobClosed { get; set; }
    public bool QuarantineRequired { get; set; }
    public bool QuarantineOwnerStarted { get; set; }
    public int? QuarantineOwnerPid { get; set; }
    public string QuarantineOwnerKind { get; set; } = "none";
    public bool QuarantineOwnerHandleInheritanceProven { get; set; }
    public bool QuarantineExcludedHandleInherited { get; set; }
    public string? QuarantineReleaseFile { get; set; }
    public DateTime? QuarantineStartedUtc { get; set; }
    public DateTime? QuarantineCompletedUtc { get; set; }
    public int EvidenceWriterPid { get; set; }
    public string EvidenceWriterRole { get; set; } = "supervisor";
    public long EvidenceRevision { get; set; }
    public string OwnershipHandoffState { get; set; } = "none";
    public string? OwnershipHandoffToken { get; set; }
    public string? StopReason { get; set; }
    public string? Failure { get; set; }
    public string? FailureDetails { get; set; }
}

public sealed record FsHostContainerManifestVolume(
    string ObjectId, string ContainerUuid, string Name, string MountPoint,
    bool RequestedWrite, string RecoveryIdentity);

public sealed record FsHostContainerManifestAuthority(
    string ManifestPath, string ContentSha256, string ManifestSha256,
    string ContainerUuid, string DeviceId, string DeviceOffsetBytes,
    IReadOnlyList<FsHostContainerManifestVolume> Volumes);

public sealed record FsHostCohortMountProof(
    string ObjectId, string MountPoint, string RecoveryIdentity, string DirectState, string Detail);

public sealed record FsHostCohortCrashBinding(string RunNonce, string NativeSha256);

public sealed record FsHostCohortAliasProof(string ObjectId, string MountPoint, string LocalState, string GlobalState);

public sealed record FsHostCohortCrashProof(
    string Contract, string RunNonce, string NativeSha256, string SupervisorSha256,
    string SupervisorPayloadSha256, string ManifestContentSha256, string StatusSha256,
    string StatusVolumeSerial, string StatusFileId, bool OriginalLeaseReleased,
    IReadOnlyList<FsHostCohortAliasProof> Aliases);

public sealed record FsHostSupervisorResult(int ExitCode, FsHostSupervisorEvidence Evidence)
{
    public bool Success => ExitCode == 0;
}

internal sealed class FsHostSupervisorTestHooks
{
    public Func<bool>? AssignProcessToJobObjectOverride { get; init; }
    public Func<bool>? StartQuarantineOwnerOverride { get; init; }
    public SafeHandle? FailedQuarantineChildHandle { get; init; }
    public Action<FsHostSupervisorEvidence, SafeHandle, SafeHandle, FileStream, SafeHandle?>? CohortKeeperEntered { get; init; }
    public Func<uint, uint, uint>? WaitForSingleObjectOverride { get; init; }
    public Func<SafeHandle, uint, uint, uint?>? WaitForHandleOverride { get; init; }
    public Func<string, FsHostMountProbeResult>? MountPointProbeOverride { get; init; }
    public Func<string, FsHostMountProbeResult>? CohortAliasProbeOverride { get; init; }
    public Func<string?>? CohortNonceOverride { get; init; }
    public Func<uint, long, string>? ObserveProcessIdentityOverride { get; init; }
    public Action<FsHostSupervisorEvidence>? BeforeEvidencePublication { get; init; }
    public nint? ExcludedInheritableHandle { get; init; }
}

internal sealed record FsHostMountProbeResult(bool IsAbsent, string ProbeKind, string Detail);

internal sealed record FsHostMountAbsenceResult(
    bool DirectAbsent,
    bool StatusAbsent,
    string DirectResult,
    string StatusResult,
    string? Failure);

internal sealed record FsHostSupervisorIdentityPaths(string ExecutablePath, string PayloadPath);

internal sealed record QuarantineOptions(
    nint JobHandle,
    nint ProcessHandle,
    int HostPid,
    long HostCreationTimeFileTime,
    bool JobAssigned,
    string MountPoint,
    string? StatusFile,
    string EvidenceFile,
    string ReadyFile,
    string ReadyToken,
    int ProcessAbsenceTimeoutMs,
    string HandoffToken,
    nint? TestExcludedHandle);

public static class FsHostSupervisor
{
    private sealed record QuarantineOwnerStartResult(
        bool OwnershipTransferred, bool ChildTerminationProven, Exception? Failure,
        SafeNativeHandle? FailedChildHandle = null);

    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint CreateNoWindow = 0x08000000;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const nuint ProcThreadAttributeHandleList = 0x00020002;
    private const uint JobObjectExtendedLimitInformationClass = 9;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 258;
    private const uint WaitFailed = 0xFFFFFFFF;
    private const uint StillActive = 259;
    private const uint ProcessSynchronize = 0x00100000;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint ToolhelpSnapshotProcess = 0x00000002;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint InvalidFileAttributes = 0xFFFFFFFF;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorNoMoreFiles = 18;
    private const uint DuplicateSameAccess = 0x00000002;
    private const uint HandleFlagInherit = 0x00000001;
    private const uint HandleFlagProtectFromClose = 0x00000002;
    private const uint WaitKindProcess = 1;
    private const uint WaitKindOwner = 2;
    private const uint WaitKindQuarantine = 3;
    private const int MaxManifestBytes = 1024 * 1024;
    private const int MaxCohortVolumes = 100;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };

    private static readonly AsyncLocal<FsHostSupervisorTestHooks?> TestHooks = new();
    private static readonly AsyncLocal<string?> SupervisorExecutablePathOverride = new();

    internal static IDisposable InstallTestHooks(FsHostSupervisorTestHooks hooks)
    {
        ArgumentNullException.ThrowIfNull(hooks);
        var previous = TestHooks.Value;
        TestHooks.Value = hooks;
        return new TestHookScope(previous);
    }

    internal static IDisposable InstallSupervisorExecutablePathForTests(string path)
    {
        var previous = SupervisorExecutablePathOverride.Value;
        SupervisorExecutablePathOverride.Value = Path.GetFullPath(path);
        return new SupervisorExecutablePathScope(previous);
    }

    internal static FsHostMountAbsenceResult WaitForMountAbsenceForTests(
        string mountPoint,
        string? statusPath,
        int timeoutMs)
        => WaitForMountAbsence(mountPoint, statusPath, timeoutMs);

    internal static string? NormalizeMountPointForTests(string? mountPoint)
        => NormalizeMountPoint(mountPoint);

    internal static void ValidateWaitResultForTests(uint result, string operation)
        => EnsureWaitResult(result, operation);

    internal static string ObserveProcessIdentityForTests(uint processId, long expectedCreationTime)
        => ObserveProcessIdentity(processId, expectedCreationTime).State switch
        {
            ProcessIdentityState.Present => "present",
            ProcessIdentityState.Absent => "absent",
            ProcessIdentityState.ReusedPid => "reused-pid",
            _ => "unknown",
        };

    public static async Task<FsHostSupervisorResult> RunAsync(
        FsHostSupervisorOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var ownerPid = ParsePid(options.OwnerPid, "owner PID");
        var hostPath = Path.GetFullPath(options.HostPath);
        var workingDirectory = string.IsNullOrWhiteSpace(options.WorkingDirectory)
            ? Path.GetDirectoryName(hostPath) ?? Environment.CurrentDirectory
            : Path.GetFullPath(options.WorkingDirectory);
        var supervisorExecutable = ResolveSupervisorExecutablePath();
        var supervisorPayloadPath = ResolveSupervisorPayloadPath(supervisorExecutable);
        var evidence = new FsHostSupervisorEvidence
        {
            SupervisorPid = Environment.ProcessId,
            SupervisorExecutable = supervisorExecutable,
            SupervisorSha256 = ComputeSha256(supervisorExecutable),
            SupervisorPayloadPath = supervisorPayloadPath,
            SupervisorPayloadSha256 = ComputeSha256(supervisorPayloadPath),
            OwnerPid = ownerPid,
            HostExecutable = hostPath,
            HostArguments = Array.AsReadOnly(options.HostArguments.ToArray()),
            WorkingDirectory = workingDirectory,
            LifetimeFile = Path.GetFullPath(options.LifetimeFile),
            StartupGateFile = NormalizeOptionalPath(options.StartupGateFile),
            LaunchRecordPath = NormalizeOptionalPath(options.LaunchRecordPath),
            EvidenceFile = Path.GetFullPath(options.EvidenceFile),
            MountPoint = NormalizeMountPoint(options.MountPoint),
            StatusFile = NormalizeOptionalPath(options.StatusFile),
            StartedUtc = DateTime.UtcNow,
            EvidenceWriterPid = Environment.ProcessId,
        };

        SafeNativeHandle? ownerHandle = null;
        SafeNativeHandle? jobHandle = null;
        SafeNativeHandle? processHandle = null;
        SafeNativeHandle? threadHandle = null;
        FileStream? manifestLease = null;
        SafeNativeHandle? failedQuarantineChildHandle = null;
        SupervisedCredential? credential = null;
        var finalExitCode = 1;
        var ownershipTransferredToQuarantine = false;

        try
        {
            PrepareEvidencePath(evidence.EvidenceFile);
            WriteEvidence(evidence);
            if (evidence.HostArguments.Contains("--container-manifest") || evidence.HostArguments.Contains("--container-manifest-sha256"))
            {
                var manifestPath = ExactManifestArgument(evidence.HostArguments, "--container-manifest");
                RequireNoReparsePath(manifestPath);
                manifestLease = new FileStream(manifestPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                evidence.ContainerManifestAuthority = ReadContainerManifestAuthority(evidence.HostArguments);
                var nonce = TestHooks.Value?.CohortNonceOverride is { } readNonce ? readNonce() :
                    Environment.GetEnvironmentVariable("APFSACCESS_SUPERVISOR_COHORT_NONCE");
                if (nonce is not null)
                {
                    if (nonce.Length != 32 || nonce.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f')))
                        throw new InvalidOperationException("Invalid cohort supervisor nonce.");
                    evidence.CohortCrashBinding = new(nonce, ComputeSha256(hostPath));
                }
            }
            ValidateOptions(options, hostPath, workingDirectory, evidence);

            ownerHandle = OpenOwner(ownerPid);
            evidence.OwnerAliveAtLaunch = true;

            void CheckCredentialOwner()
            {
                if (WaitForObject(ownerHandle, 0, WaitKindOwner, "WaitForSingleObject(owner)") == WaitObject0 ||
                    !File.Exists(evidence.LifetimeFile))
                    throw new InvalidOperationException("Credential transport owner or lifetime ended.");
            }
            if (options.CredentialInput)
            {
                credential = SupervisedCredential.Receive(SupervisedCredential.TakeStandardInput(),
                    cancellationToken, CheckCredentialOwner);
                credential.CreateChildPipe();
                cancellationToken.ThrowIfCancellationRequested();
                CheckCredentialOwner();
            }

            jobHandle = CreateKillOnCloseJob();
            evidence.JobCreated = true;

            var launch = CreateSuspendedChild(hostPath, evidence.HostArguments, workingDirectory, credential?.Reader);
            processHandle = launch.ProcessHandle;
            threadHandle = launch.ThreadHandle;
            credential?.ReleaseLocalReader();
            evidence.HostPid = checked((int)launch.ProcessId);
            evidence.HostParentPid = evidence.SupervisorPid;
            evidence.HostCreationTimeFileTime = CaptureProcessCreationTime(processHandle);
            evidence.HostIdentityCaptured = true;
            evidence.HostIdentityState = "present";

            if (!AssignProcessToJobObject(jobHandle, processHandle))
            {
                var assignmentError = LastWin32Error("AssignProcessToJobObject");
                evidence.Failure = assignmentError.Message;
                TerminateExactProcess(evidence, processHandle);
                throw assignmentError;
            }

            evidence.JobAssigned = true;
            ValidateManifestAuthority(evidence);
            cancellationToken.ThrowIfCancellationRequested();
            if (WaitForObject(ownerHandle, 0, WaitKindOwner, "WaitForSingleObject(owner)") == WaitObject0)
            {
                throw new InvalidOperationException("The supervisor owner exited before the host could be resumed.");
            }

            if (NativeMethods.ResumeThread(threadHandle) == uint.MaxValue)
            {
                throw LastWin32Error("ResumeThread");
            }

            evidence.Resumed = true;
            threadHandle.Dispose();
            threadHandle = null;

            if (evidence.StartupGateFile is not null)
            {
                if (WaitForObject(ownerHandle, 0, WaitKindOwner, "WaitForSingleObject(owner)") == WaitObject0)
                {
                    throw new InvalidOperationException("The supervisor owner exited before startup authorization.");
                }

                if (string.IsNullOrEmpty(options.StartupGateToken))
                {
                    throw new InvalidOperationException("A startup-gate file requires a startup-gate token.");
                }

                ValidateManifestAuthority(evidence);
                WriteAtomicText(evidence.StartupGateFile, options.StartupGateToken);
                evidence.StartupGateAuthorized = true;
            }

            credential?.Send(cancellationToken, () =>
            {
                CheckCredentialOwner();
                if (WaitForObject(processHandle, 0, WaitKindProcess, "WaitForSingleObject(host)") == WaitObject0)
                    throw new InvalidOperationException("Credential transport child exited.");
            });
            credential = null;
            evidence.SupervisionProven = evidence.JobCreated && evidence.JobAssigned && evidence.Resumed;
            evidence.LaunchProvenUtc = DateTime.UtcNow;
            WriteEvidence(evidence);
            cancellationToken.ThrowIfCancellationRequested();
            WriteLaunchRecord(evidence);

            await MonitorChildAsync(
                options,
                evidence,
                ownerHandle,
                jobHandle,
                processHandle,
                cancellationToken).ConfigureAwait(false);

        }
        catch (OperationCanceledException ex)
        {
            evidence.Status = "failed";
            evidence.StopReason ??= "cancelled";
            evidence.Failure = ex.Message;
            evidence.FailureDetails = ex.ToString();
        }
        catch (Exception ex)
        {
            evidence.Status = "failed";
            evidence.Failure = ex.Message;
            evidence.FailureDetails = ex.ToString();
        }
        finally
        {
            credential?.Dispose();
            if (processHandle is not null)
            {
                try
                {
                    CaptureExitCode(evidence, processHandle);
                    var waitState = WaitForObject(
                        processHandle,
                        0,
                        WaitKindProcess,
                        "WaitForSingleObject(host)");
                    if (waitState != WaitObject0)
                    {
                        ForceTerminateHost(evidence, jobHandle, processHandle);
                    }
                }
                catch (Exception ex)
                {
                    RecordFailure(evidence, "Unable to stop the supervised FsHost.", ex);
                    ForceTerminateHost(evidence, jobHandle, processHandle);
                }

                try
                {
                    if (evidence.HostPid is null)
                    {
                        evidence.HostPidAbsentFromProcessEnumeration = true;
                        evidence.OriginalHostIdentityAbsent = true;
                        evidence.HostIdentityState = "not-launched";
                    }
                    else if (!evidence.HostIdentityCaptured || evidence.HostCreationTimeFileTime is null)
                    {
                        evidence.HostIdentityState = "unknown";
                        throw new InvalidOperationException(
                            "The launched FsHost process identity was not captured; PID absence cannot be proven safely.");
                    }
                    else
                    {
                        evidence.OriginalHostIdentityAbsent = WaitForOriginalProcessAbsence(
                            (uint)evidence.HostPid.Value,
                            evidence.HostCreationTimeFileTime.Value,
                            processHandle,
                            options.ProcessAbsenceTimeoutMs,
                            evidence);
                    }
                }
                catch (Exception ex)
                {
                    RecordFailure(evidence, "Unable to prove FsHost PID absence.", ex);
                }

                if (!evidence.OriginalHostIdentityAbsent &&
                    jobHandle is not null &&
                    processHandle is not null &&
                    !jobHandle.IsInvalid &&
                    !jobHandle.IsClosed)
                {
                    ForceTerminateHost(evidence, jobHandle, processHandle);
                    try
                    {
                        if (evidence.HostPid is not null &&
                            evidence.HostIdentityCaptured &&
                            evidence.HostCreationTimeFileTime is not null)
                        {
                            evidence.OriginalHostIdentityAbsent = WaitForOriginalProcessAbsence(
                                (uint)evidence.HostPid.Value,
                                evidence.HostCreationTimeFileTime.Value,
                                processHandle,
                                options.ProcessAbsenceTimeoutMs,
                                evidence);
                        }
                    }
                    catch (Exception ex)
                    {
                        RecordFailure(evidence, "Unable to re-prove FsHost PID absence after exact termination.", ex);
                    }
                }
            }

            try
            {
                var mountProof = WaitForEvidenceMountAbsence(evidence, options.ProcessAbsenceTimeoutMs);
                evidence.MountAbsentFromDirectProbe = mountProof.DirectAbsent;
                evidence.MountAbsentFromStatus = mountProof.StatusAbsent;
                evidence.MountDirectProbeResult = mountProof.DirectResult;
                evidence.MountStatusProbeResult = mountProof.StatusResult;
                evidence.StaleReadyStatusDischarged = TryProveExitedDirectoryStaleReady(
                    evidence, mountProof, processHandle, jobHandle);
                evidence.CohortCrashProof = TryProveExitedCohortStaleReady(evidence, mountProof, processHandle, jobHandle);
                evidence.MountAbsenceProven = IsMountSettlementProven(evidence, mountProof) ||
                    evidence.StaleReadyStatusDischarged || evidence.CohortCrashProof is not null;
                if (mountProof.Failure is not null)
                {
                    evidence.MountProbeFailure = mountProof.Failure;
                }
            }
            catch (Exception ex)
            {
                evidence.MountAbsenceProven = false;
                evidence.MountDirectProbeResult = "error";
                evidence.MountProbeFailure = ex.Message;
                RecordFailure(evidence, "Unable to prove mount absence.", ex);
            }

            if (!evidence.OriginalHostIdentityAbsent && evidence.HostPid is not null)
            {
                evidence.Failure ??= "The original launched FsHost identity remained present or could not be proven absent.";
            }
            if (!evidence.MountAbsentFromDirectProbe)
            {
                evidence.Failure ??= "The FsHost mount was not proven absent by a direct Windows mount-point probe.";
            }
            else if (!evidence.StaleReadyStatusDischarged && evidence.CohortCrashProof is null && evidence.MountStatusProbeResult is ("ready" or "error"))
            {
                evidence.Failure ??= evidence.MountStatusProbeResult == "ready"
                    ? "The FsHost status file still reports the mount as ready."
                    : "The FsHost status file could not be read reliably.";
            }

            evidence.CompletedUtc = DateTime.UtcNow;
            if (evidence.ForcedJobTermination &&
                !string.Equals(evidence.ForcedJobTerminationResult, "succeeded", StringComparison.Ordinal))
            {
                evidence.Failure ??= "Forced Job Object termination was not proven.";
            }

            var ownershipProven = IsOwnershipProven(evidence, jobHandle);
            var quarantineChildTerminationProven = true;
            if (!ownershipProven && jobHandle is not null && processHandle is not null)
            {
                evidence.QuarantineRequired = true;
                evidence.Status = "failed";
                evidence.Failure ??= "FsHost ownership could not be proven; handles remain quarantined.";
                try
                {
                    WriteEvidence(evidence);
                    var quarantineStart = TryStartQuarantineOwner(
                        evidence,
                        options,
                        jobHandle,
                        processHandle);
                    ownershipTransferredToQuarantine = quarantineStart.OwnershipTransferred;
                    quarantineChildTerminationProven = quarantineStart.ChildTerminationProven;
                    failedQuarantineChildHandle = quarantineStart.FailedChildHandle;
                    if (quarantineStart.Failure is not null)
                    {
                        RecordFailure(
                            evidence,
                            "Unable to transfer uncertain FsHost ownership to a quarantine owner.",
                            quarantineStart.Failure);
                    }
                    if (ownershipTransferredToQuarantine)
                    {
                        // The quarantine child is now the sole evidence writer.
                    }
                }
                catch (Exception ex)
                {
                    RecordFailure(evidence, "Unable to transfer uncertain FsHost ownership to a quarantine owner.", ex);
                }

                if (!ownershipTransferredToQuarantine && quarantineChildTerminationProven)
                {
                    // Keep this process as the last enforcement owner if the
                    // managed quarantine owner cannot take the exact handles.
                    ownershipProven = RunInlineQuarantineUntilProven(
                        evidence,
                        options.ProcessAbsenceTimeoutMs,
                        jobHandle,
                        processHandle,
                        cancellationToken);
                }
                else if (!quarantineChildTerminationProven)
                {
                    RecordFailure(
                        evidence,
                        "The failed quarantine child could not be terminated safely; inline fallback was withheld.",
                        new InvalidOperationException(
                            "Quarantine-child termination was not verified before fallback."));
                }
            }

            if (evidence.ContainerManifestAuthority is not null && !ownershipProven &&
                !ownershipTransferredToQuarantine && jobHandle is not null && processHandle is not null)
            {
                evidence = await KeepCohortOwnershipUntilProvenAsync(evidence, jobHandle, processHandle, manifestLease,
                    failedQuarantineChildHandle, null, quarantineChildTerminationProven
                        ? "inline-deadline-or-cancellation" : "failed-child-termination-uncertain").ConfigureAwait(false);
                ownershipProven = true;
            }

            threadHandle?.Dispose();
            ownerHandle?.Dispose();
            failedQuarantineChildHandle?.Dispose();
            manifestLease?.Dispose();
            if (ownershipTransferredToQuarantine)
            {
                processHandle?.Dispose();
                jobHandle?.Dispose();
                evidence.JobClosed = false;
            }
            else if (ownershipProven || processHandle is null)
            {
                processHandle?.Dispose();
                var jobWasCreated = jobHandle is not null;
                jobHandle?.Dispose();
                evidence.JobClosed = jobWasCreated;
            }

            if (evidence.Status == "starting")
            {
                evidence.Status = evidence.Failure is null &&
                    evidence.SupervisionProven &&
                    evidence.OriginalHostIdentityAbsent &&
                    evidence.MountAbsenceProven &&
                    evidence.JobClosed
                    ? "stopped"
                    : "failed";
            }

            finalExitCode = IsSuccessfulTerminalEvidence(evidence) ? 0 : 1;
            evidence.SupervisorExitCode = finalExitCode;

            try
            {
                if (!ownershipTransferredToQuarantine)
                {
                    PrepareEvidencePath(evidence.EvidenceFile);
                    WriteEvidence(evidence);
                    if (evidence.SupervisionProven) WriteLaunchRecord(evidence);
                }
            }
            catch (Exception ex)
            {
                evidence.Status = "failed";
                RecordFailure(evidence, "Unable to persist final supervisor evidence.", ex);
                finalExitCode = 1;
                evidence.SupervisorExitCode = finalExitCode;
                try
                {
                    if (!ownershipTransferredToQuarantine)
                    {
                        WriteEvidence(evidence);
                    }
                }
                catch (Exception retryException)
                {
                    evidence.FailureDetails ??= retryException.ToString();
                }
            }
        }

        return new FsHostSupervisorResult(finalExitCode, evidence);
    }

    private static async Task MonitorChildAsync(
        FsHostSupervisorOptions options,
        FsHostSupervisorEvidence evidence,
        SafeNativeHandle ownerHandle,
        SafeNativeHandle jobHandle,
        SafeNativeHandle processHandle,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (WaitForObject(processHandle, 0, WaitKindProcess, "WaitForSingleObject(host)") == WaitObject0)
            {
                evidence.StopReason = "host-exited";
                evidence.GracefulStopResult = "host-exited-before-request";
                return;
            }

            if (WaitForObject(ownerHandle, 0, WaitKindOwner, "WaitForSingleObject(owner)") == WaitObject0)
            {
                evidence.OwnerDeathDetected = true;
                evidence.StopReason = "owner-exited";
                await RequestGracefulStopAsync(evidence, options, processHandle, cancellationToken)
                    .ConfigureAwait(false);
                return;
            }

            if (!File.Exists(evidence.LifetimeFile))
            {
                evidence.StopReason = "lifetime-file-removed";
                await RequestGracefulStopAsync(evidence, options, processHandle, cancellationToken)
                    .ConfigureAwait(false);
                return;
            }

            await Task.Delay(Math.Max(25, options.OwnerPollIntervalMs), cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task RequestGracefulStopAsync(
        FsHostSupervisorEvidence evidence,
        FsHostSupervisorOptions options,
        SafeNativeHandle processHandle,
        CancellationToken cancellationToken)
    {
        evidence.GracefulStopRequested = true;
        evidence.GracefulStopRequestedUtc = DateTime.UtcNow;
        evidence.GracefulStopResult = "waiting";
        WriteEvidence(evidence);

        var deadline = DateTime.UtcNow.AddMilliseconds(Math.Max(50, options.GracefulTimeoutMs));
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (WaitForObject(processHandle, 0, WaitKindProcess, "WaitForSingleObject(host)") == WaitObject0)
            {
                evidence.GracefulStopCompleted = true;
                evidence.GracefulStopResult = "completed";
                return;
            }

            await Task.Delay(Math.Max(25, options.OwnerPollIntervalMs), cancellationToken).ConfigureAwait(false);
        }

        evidence.GracefulStopResult = "timed-out";
    }

    private static void ForceTerminateHost(
        FsHostSupervisorEvidence evidence,
        SafeNativeHandle? jobHandle,
        SafeNativeHandle processHandle,
        uint waitTimeoutMs = 15_000)
    {
        if (jobHandle is not null &&
            !jobHandle.IsInvalid &&
            !jobHandle.IsClosed &&
            evidence.JobAssigned)
        {
            evidence.ForcedJobTermination = true;
            evidence.ForcedJobTerminationUtc = DateTime.UtcNow;
            if (NativeMethods.TerminateJobObject(jobHandle, 0xE0010001))
            {
                evidence.ForcedJobTerminationResult = "succeeded";
            }
            else
            {
                evidence.ForcedJobTerminationResult =
                    $"failed-win32-{Marshal.GetLastWin32Error()}";
            }
        }
        else if (evidence.JobCreated)
        {
            evidence.ForcedJobTerminationResult = "not-applicable-unassigned";
        }

        var processExited = false;
        try
        {
            processExited = WaitForObject(
                processHandle,
                waitTimeoutMs,
                WaitKindProcess,
                "WaitForSingleObject(host after termination)") == WaitObject0;
        }
        catch (Exception ex)
        {
            RecordFailure(evidence, "Unable to wait for the terminated FsHost.", ex);
        }

        if (!processExited)
        {
            TerminateExactProcess(evidence, processHandle);
        }
    }

    private static void TerminateExactProcess(
        FsHostSupervisorEvidence evidence,
        SafeNativeHandle processHandle)
    {
        evidence.ExactProcessTerminationAttempted = true;
        try
        {
            if (WaitForObject(processHandle, 0, WaitKindProcess, "WaitForSingleObject(host before exact termination)") == WaitObject0)
            {
                evidence.ExactProcessTerminationResult = "already-exited";
                return;
            }
        }
        catch (Exception ex)
        {
            RecordFailure(evidence, "Unable to inspect the exact FsHost before termination.", ex);
        }

        if (NativeMethods.TerminateProcess(processHandle, 0xE0010002))
        {
            evidence.ExactProcessTerminationResult = "succeeded";
        }
        else
        {
            evidence.ExactProcessTerminationResult =
                $"failed-win32-{Marshal.GetLastWin32Error()}";
            evidence.Failure ??= "The exact FsHost process could not be terminated.";
        }
    }

    private static ChildLaunch CreateSuspendedChild(
        string hostPath,
        IReadOnlyList<string> arguments,
        string workingDirectory,
        SafeFileHandle? credentialInput = null)
    {
        var commandLine = new StringBuilder();
        commandLine.Append(QuoteWindowsArgument(hostPath));
        foreach (var argument in arguments)
        {
            commandLine.Append(' ');
            commandLine.Append(QuoteWindowsArgument(argument));
        }

        if (credentialInput is not null)
            return CreateCredentialChild(hostPath, commandLine, workingDirectory, credentialInput);

        var startupInfo = new StartupInfo
        {
            Cb = (uint)Marshal.SizeOf<StartupInfo>(),
        };
        if (!NativeMethods.CreateProcessW(
                hostPath,
                commandLine,
                nint.Zero,
                nint.Zero,
                false,
                CreateSuspended | CreateUnicodeEnvironment | CreateNoWindow,
                nint.Zero,
                workingDirectory,
                ref startupInfo,
                out var processInformation))
        {
            throw LastWin32Error("CreateProcessW");
        }

        return new ChildLaunch(
            new SafeNativeHandle(processInformation.ProcessHandle),
            new SafeNativeHandle(processInformation.ThreadHandle),
            processInformation.ProcessId);
    }

    private static ChildLaunch CreateCredentialChild(string hostPath, StringBuilder commandLine,
        string workingDirectory, SafeFileHandle input)
    {
        nuint size = 0;
        _ = NativeMethods.InitializeProcThreadAttributeList(0, 1, 0, ref size);
        if (size == 0 || Marshal.GetLastWin32Error() != ErrorInsufficientBuffer)
            throw LastWin32Error("InitializeProcThreadAttributeList(credential size)");
        var attributes = Marshal.AllocHGlobal(checked((nint)size));
        var handles = Marshal.AllocHGlobal(nint.Size);
        var initialized = false;
        try
        {
            if (!NativeMethods.InitializeProcThreadAttributeList(attributes, 1, 0, ref size))
                throw LastWin32Error("InitializeProcThreadAttributeList(credential)");
            initialized = true;
            Marshal.WriteIntPtr(handles, input.DangerousGetHandle());
            if (!NativeMethods.UpdateProcThreadAttribute(attributes, 0, ProcThreadAttributeHandleList,
                    handles, (nuint)nint.Size, 0, 0))
                throw LastWin32Error("UpdateProcThreadAttribute(credential)");
            var info = new StartupInfoEx
            {
                StartupInfo = new StartupInfo
                {
                    Cb = (uint)Marshal.SizeOf<StartupInfoEx>(), Flags = 0x100,
                    StdInput = input.DangerousGetHandle(), StdOutput = -1, StdError = -1,
                },
                AttributeList = attributes,
            };
            if (!NativeMethods.CreateProcessW(hostPath, commandLine, 0, 0, true,
                    CreateSuspended | CreateUnicodeEnvironment | CreateNoWindow | ExtendedStartupInfoPresent,
                    0, workingDirectory, ref info, out var process))
                throw LastWin32Error("CreateProcessW(credential)");
            return new ChildLaunch(new SafeNativeHandle(process.ProcessHandle),
                new SafeNativeHandle(process.ThreadHandle), process.ProcessId);
        }
        finally
        {
            GC.KeepAlive(input);
            if (initialized) NativeMethods.DeleteProcThreadAttributeList(attributes);
            Marshal.FreeHGlobal(handles);
            Marshal.FreeHGlobal(attributes);
        }
    }

    private static SafeNativeHandle OpenOwner(int ownerPid)
    {
        var handle = NativeMethods.OpenProcess(
            ProcessSynchronize | ProcessQueryLimitedInformation,
            false,
            (uint)ownerPid);
        if (handle == nint.Zero) throw LastWin32Error("OpenProcess(owner)");
        return new SafeNativeHandle(handle);
    }

    private static SafeNativeHandle CreateKillOnCloseJob()
    {
        var handle = NativeMethods.CreateJobObjectW(nint.Zero, null);
        if (handle == nint.Zero) throw LastWin32Error("CreateJobObjectW");

        var job = new SafeNativeHandle(handle);
        var limits = new JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new JobObjectBasicLimitInformation
            {
                LimitFlags = JobObjectLimitKillOnJobClose,
            },
        };
        if (!NativeMethods.SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformationClass,
                ref limits,
                (uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>()))
        {
            job.Dispose();
            throw LastWin32Error("SetInformationJobObject");
        }

        return job;
    }

    private static bool AssignProcessToJobObject(
        SafeNativeHandle jobHandle,
        SafeNativeHandle processHandle)
        => TestHooks.Value?.AssignProcessToJobObjectOverride?.Invoke() ??
            NativeMethods.AssignProcessToJobObject(jobHandle, processHandle);

    private static void CaptureExitCode(FsHostSupervisorEvidence evidence, SafeNativeHandle processHandle)
    {
        if (NativeMethods.GetExitCodeProcess(processHandle, out var exitCode) && exitCode != StillActive)
        {
            evidence.HostExitCode = unchecked((int)exitCode);
        }
    }

    private static long CaptureProcessCreationTime(SafeNativeHandle processHandle)
    {
        if (!NativeMethods.GetProcessTimes(
                processHandle,
                out var creationTime,
                out _,
                out _,
                out _))
        {
            throw LastWin32Error("GetProcessTimes");
        }

        return creationTime.ToInt64();
    }

    private static bool WaitForOriginalProcessAbsence(
        uint processId,
        long expectedCreationTime,
        SafeNativeHandle originalProcessHandle,
        int timeoutMs,
        FsHostSupervisorEvidence evidence,
        CancellationToken cancellationToken = default,
        DateTime? deadlineUtc = null)
    {
        var deadline = deadlineUtc ?? DateTime.UtcNow.AddMilliseconds(Math.Max(250, timeoutMs));
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var observation = ObserveProcessIdentity(processId, expectedCreationTime);
            RecordProcessIdentityObservation(evidence, observation);
            var originalHandleSignaled = WaitForObject(
                    originalProcessHandle,
                    0,
                    WaitKindProcess,
                    "WaitForSingleObject(host absence proof)") == WaitObject0;
            if (originalHandleSignaled && observation.State is ProcessIdentityState.Absent or ProcessIdentityState.ReusedPid)
            {
                evidence.OriginalHostIdentityAbsent = true;
                return true;
            }

            WaitForCancellationOrTimeout(cancellationToken, deadline, 100);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var finalObservation = ObserveProcessIdentity(processId, expectedCreationTime);
        RecordProcessIdentityObservation(evidence, finalObservation);
        var finalHandleSignaled = WaitForObject(
                originalProcessHandle,
                0,
                WaitKindProcess,
                "WaitForSingleObject(host absence proof)") == WaitObject0;
        evidence.OriginalHostIdentityAbsent = finalHandleSignaled &&
            finalObservation.State is ProcessIdentityState.Absent or ProcessIdentityState.ReusedPid;
        return evidence.OriginalHostIdentityAbsent;
    }

    private static void RecordProcessIdentityObservation(
        FsHostSupervisorEvidence evidence,
        ProcessIdentityObservation observation)
    {
        evidence.HostIdentityState = observation.State switch
        {
            ProcessIdentityState.Present => "present",
            ProcessIdentityState.Absent => "absent",
            ProcessIdentityState.ReusedPid => "reused-pid",
            _ => "unknown",
        };
        evidence.HostPidAbsentFromProcessEnumeration = observation.State == ProcessIdentityState.Absent;
        evidence.HostPidReused = observation.State == ProcessIdentityState.ReusedPid;
    }

    private static ProcessIdentityObservation ObserveProcessIdentity(
        uint processId,
        long expectedCreationTime)
    {
        if (TestHooks.Value?.ObserveProcessIdentityOverride is { } observeOverride)
        {
            return observeOverride(processId, expectedCreationTime) switch
            {
                "present" => new ProcessIdentityObservation(ProcessIdentityState.Present, expectedCreationTime),
                "absent" => new ProcessIdentityObservation(ProcessIdentityState.Absent, null),
                "reused-pid" => new ProcessIdentityObservation(ProcessIdentityState.ReusedPid, expectedCreationTime + 1),
                _ => new ProcessIdentityObservation(ProcessIdentityState.Unknown, null),
            };
        }

        using var snapshot = new SafeNativeHandle(
            NativeMethods.CreateToolhelp32Snapshot(ToolhelpSnapshotProcess, 0));
        if (snapshot.IsInvalid) throw LastWin32Error("CreateToolhelp32Snapshot");

        var entry = new ProcessEntry32
        {
            Size = (uint)Marshal.SizeOf<ProcessEntry32>(),
        };
        if (!NativeMethods.Process32FirstW(snapshot, ref entry))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == ErrorNoMoreFiles)
            {
                return new ProcessIdentityObservation(ProcessIdentityState.Absent, null);
            }

            throw new Win32Exception(error, $"Process32FirstW failed with Win32 error {error}.");
        }

        var found = false;
        while (true)
        {
            if (entry.ProcessId == processId)
            {
                found = true;
                break;
            }

            if (!NativeMethods.Process32NextW(snapshot, ref entry))
            {
                var error = Marshal.GetLastWin32Error();
                if (error != ErrorNoMoreFiles)
                {
                    throw new Win32Exception(error, $"Process32NextW failed with Win32 error {error}.");
                }

                break;
            }
        }

        if (!found)
        {
            return new ProcessIdentityObservation(ProcessIdentityState.Absent, null);
        }

        var currentHandle = NativeMethods.OpenProcess(
            ProcessSynchronize | ProcessQueryLimitedInformation,
            false,
            processId);
        if (currentHandle == nint.Zero)
        {
            throw LastWin32Error("OpenProcess(process identity)");
        }

        using var currentProcess = new SafeNativeHandle(currentHandle);
        var currentCreationTime = CaptureProcessCreationTime(currentProcess);
        return currentCreationTime == expectedCreationTime
            ? new ProcessIdentityObservation(ProcessIdentityState.Present, currentCreationTime)
            : new ProcessIdentityObservation(ProcessIdentityState.ReusedPid, currentCreationTime);
    }

    private static uint WaitForObject(
        SafeNativeHandle handle,
        uint milliseconds,
        uint waitKind,
        string operation)
    {
        var result = TestHooks.Value?.WaitForHandleOverride?.Invoke(handle, milliseconds, waitKind) ??
            TestHooks.Value?.WaitForSingleObjectOverride?.Invoke(milliseconds, waitKind) ??
            NativeMethods.WaitForSingleObject(handle, milliseconds);
        return EnsureWaitResult(result, operation);
    }

    private static void WaitForCancellationOrTimeout(
        CancellationToken cancellationToken,
        DateTime deadlineUtc,
        int maximumDelayMs)
    {
        var remainingMs = GetRemainingMilliseconds(deadlineUtc);
        if (remainingMs <= 0) return;

        var delayMs = Math.Min(maximumDelayMs, remainingMs);
        if (!cancellationToken.CanBeCanceled)
        {
            Thread.Sleep(delayMs);
            return;
        }

        if (cancellationToken.WaitHandle.WaitOne(delayMs))
        {
            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    private static int GetRemainingMilliseconds(DateTime deadlineUtc)
    {
        var remaining = deadlineUtc - DateTime.UtcNow;
        return remaining <= TimeSpan.Zero
            ? 0
            : Math.Max(1, (int)Math.Min(int.MaxValue, Math.Ceiling(remaining.TotalMilliseconds)));
    }

    private static uint EnsureWaitResult(uint result, string operation)
    {
        if (result == WaitFailed)
        {
            throw LastWin32Error(operation);
        }

        if (result != WaitObject0 && result != WaitTimeout)
        {
            throw new InvalidOperationException($"{operation} returned unexpected wait result 0x{result:X8}.");
        }

        return result;
    }

    private static void RecordFailure(
        FsHostSupervisorEvidence evidence,
        string message,
        Exception exception)
    {
        evidence.Failure ??= message;
        evidence.FailureDetails ??= exception.ToString();
    }

    private enum ProcessIdentityState
    {
        Present,
        Absent,
        ReusedPid,
        Unknown,
    }

    private sealed record ProcessIdentityObservation(
        ProcessIdentityState State,
        long? CreationTimeFileTime);

    private sealed record MountStatusObservation(
        bool IsAbsent,
        string Result,
        string? Failure);

    internal static FsHostContainerManifestAuthority? ReadContainerManifestAuthorityForTests(IReadOnlyList<string> args)
        => ReadContainerManifestAuthority(args);

    internal static FsHostMountAbsenceResult WaitForCohortMountAbsenceForTests(FsHostSupervisorEvidence evidence, int timeoutMs)
        => WaitForEvidenceMountAbsence(evidence, timeoutMs);

    internal static string ReadContainerStatusForTests(FsHostSupervisorEvidence evidence)
        => ReadContainerStatus(evidence).Result;

    internal static bool CanReleaseCohortForTests(FsHostSupervisorEvidence evidence, uint activeProcesses)
        => IsCohortOwnershipProven(evidence, activeProcesses);

    internal static string SealCohortHandoffForTests(FsHostSupervisorEvidence evidence)
        => SealCohortHandoff(evidence)!;

    private static string ExactManifestArgument(IReadOnlyList<string> args, string flag)
    {
        if (args.Count(value => value == flag) != 1) throw new InvalidOperationException($"Manifest requires exactly one {flag}.");
        var index = args.ToList().IndexOf(flag);
        if (index + 1 >= args.Count || string.IsNullOrEmpty(args[index + 1]) || args[index + 1].StartsWith("--") || args[index + 1].Contains('\0'))
            throw new InvalidOperationException($"Invalid manifest selector {flag}.");
        return args[index + 1];
    }

    private static void RequireNoReparsePath(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path[Path.GetPathRoot(path)!.Length..].Contains(':'))
            throw new InvalidOperationException("Manifest authority requires an absolute path without alternate streams.");
        for (var current = Path.GetFullPath(path); ; current = Path.GetDirectoryName(current)!)
        {
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Manifest authority path contains a reparse point.");
            if (Path.GetDirectoryName(current) is null) break;
        }
    }

    private static void ValidateUniqueJsonProperties(JsonElement element, int depth = 0)
    {
        if (depth > 32) throw new InvalidOperationException("Authority JSON nesting exceeds bound.");
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new InvalidOperationException("Duplicate authority JSON property.");
                ValidateUniqueJsonProperties(property.Value, depth + 1);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) ValidateUniqueJsonProperties(item, depth + 1);
    }

    private static string ManifestText(JsonElement root, string key, bool optional = false)
    {
        if (optional && !root.TryGetProperty(key, out _)) return string.Empty;
        var property = root.GetProperty(key);
        if (property.ValueKind != JsonValueKind.String) throw new InvalidOperationException($"Invalid manifest {key}.");
        var value = property.GetString()!;
        if ((!optional && value.Length == 0) || value.IndexOfAny(['\0', '\r', '\n']) >= 0 || Encoding.UTF8.GetByteCount(value) > 32768)
            throw new InvalidOperationException($"Invalid manifest {key}.");
        return value;
    }

    private static string AuthorityDecimal(JsonElement value, bool zero = false)
    {
        var text = value.ValueKind == JsonValueKind.String ? value.GetString()! : value.GetRawText();
        if (!ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var number) ||
            (!zero && number == 0) || text != number.ToString(CultureInfo.InvariantCulture))
            throw new InvalidOperationException("Invalid authority unsigned integer.");
        return text;
    }

    private static string NormalizeCohortMountPoint(string mount)
    {
        if (IsDriveMountPoint(mount) && char.IsAsciiLetter(mount[0])) return mount[..2].ToUpperInvariant();
        if (!Path.IsPathFullyQualified(mount) || mount[Path.GetPathRoot(mount)!.Length..].Contains(':'))
            throw new InvalidOperationException("Manifest mount must be absolute or an exact drive root.");
        var full = Path.GetFullPath(mount);
        return full == Path.GetPathRoot(full) ? full : full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static FsHostContainerManifestAuthority? ReadContainerManifestAuthority(IReadOnlyList<string> args)
    {
        if (!args.Contains("--container-manifest") && !args.Contains("--container-manifest-sha256")) return null;
        string[] scalarFlags = ["--device", "--volume", "--volume-oid", "--mount", "--mount-identity", "--recovery-identity",
            "--snapshot-xid", "--encrypted-image", "--fusion-images", "--manifest"];
        if (scalarFlags.Any(args.Contains)) throw new InvalidOperationException("Container manifest cannot mix scalar target selectors.");
        var manifestPath = ExactManifestArgument(args, "--container-manifest");
        RequireNoReparsePath(manifestPath);
        manifestPath = Path.GetFullPath(manifestPath);
        var launchHash = ExactManifestArgument(args, "--container-manifest-sha256").ToUpperInvariant();
        if (launchHash.Length != 64 || launchHash.Any(c => !Uri.IsHexDigit(c))) throw new InvalidOperationException("Invalid launch-bound manifest checksum.");
        using var stream = new FileStream(manifestPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length <= 0 || stream.Length > MaxManifestBytes) throw new InvalidOperationException("Manifest byte bound exceeded.");
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        RequireNoReparsePath(manifestPath);
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
        var raw = document.RootElement;
        ValidateUniqueJsonProperties(raw);
        var container = ManifestText(raw, "containerUuid");
        if (ManifestText(raw, "format") != "apfs-access-container-manifest" || raw.GetProperty("version").GetInt32() != 1 ||
            container.Length != 32 || container.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f')))
            throw new InvalidOperationException("Invalid container manifest schema.");
        var device = ManifestText(raw, "device");
        var offset = AuthorityDecimal(raw.GetProperty("deviceOffsetBytes"), zero: true);
        var rawVolumes = raw.GetProperty("volumes");
        if (rawVolumes.ValueKind != JsonValueKind.Array || rawVolumes.GetArrayLength() is < 1 or > MaxCohortVolumes)
            throw new InvalidOperationException("Invalid container manifest cohort bound.");
        var lines = new List<string> { "manifest-check-v1", container, device, offset };
        var volumes = new List<FsHostContainerManifestVolume>();
        var oids = new HashSet<string>();
        var mounts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var recoveries = new HashSet<string>(StringComparer.Ordinal);
        foreach (var volume in rawVolumes.EnumerateArray())
        {
            var oid = AuthorityDecimal(volume.GetProperty("objectId"));
            var mount = ManifestText(volume, "mount");
            var mountPoint = NormalizeCohortMountPoint(mount);
            var recovery = ManifestText(volume, "recoveryIdentity", optional: true);
            var name = ManifestText(volume, "name", optional: true);
            var requestedWrite = volume.GetProperty("requestedWrite").GetBoolean();
            if (ManifestText(volume, "containerUuid") != container || (requestedWrite && recovery.Length == 0) ||
                !oids.Add(oid) || !mounts.Add(mountPoint) || (recovery.Length != 0 && !recoveries.Add(recovery)))
                throw new InvalidOperationException("Manifest cohort has duplicate or incomplete peer authority.");
            lines.AddRange([oid, container, name, mount, requestedWrite ? "W" : "R", recovery]);
            volumes.Add(new(oid, container, name, mountPoint, requestedWrite, recovery));
        }
        foreach (var a in volumes) foreach (var b in volumes)
            if (a != b && b.MountPoint.StartsWith(a.MountPoint.TrimEnd('\\', '/') + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Manifest cohort mounts overlap.");
        var checksum = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', lines) + "\n")));
        if (checksum != launchHash || ManifestText(raw, "manifestSha256").ToUpperInvariant() != checksum)
            throw new InvalidOperationException("Manifest launch-bound checksum mismatch.");
        return new(manifestPath, Convert.ToHexString(SHA256.HashData(bytes)), checksum, container, device, offset, volumes.AsReadOnly());
    }

    private static void ValidateManifestAuthority(FsHostSupervisorEvidence evidence)
    {
        if (evidence.ContainerManifestAuthority is not { } authority) return;
        var actual = ReadContainerManifestAuthority(evidence.HostArguments);
        if (JsonSerializer.Serialize(actual, JsonOptions) != JsonSerializer.Serialize(authority, JsonOptions))
            throw new InvalidOperationException("Container manifest content/path authority changed.");
    }

    private static MountStatusObservation ReadContainerStatus(FsHostSupervisorEvidence evidence)
    {
        try
        {
            using var stream = new FileStream(evidence.StatusFile!, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length <= 0 || stream.Length > MaxManifestBytes) throw new InvalidOperationException("Container status byte bound exceeded.");
            var bytes = new byte[checked((int)stream.Length)];
            stream.ReadExactly(bytes);
            return ParseContainerStatus(evidence, bytes);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        {
            return new(false, "error", ex.Message);
        }
    }

    private static MountStatusObservation ParseContainerStatus(FsHostSupervisorEvidence evidence, byte[] bytes)
    {
            var authority = evidence.ContainerManifestAuthority ?? throw new InvalidOperationException("Container authority is missing.");
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
            var status = document.RootElement;
            ValidateUniqueJsonProperties(status);
            if (ManifestText(status, "containerUuid") != authority.ContainerUuid ||
                status.GetProperty("ownerPid").GetInt32() != evidence.HostPid ||
                AuthorityDecimal(status.GetProperty("ownerStartFileTimeUtc")) != evidence.HostCreationTimeFileTime?.ToString(CultureInfo.InvariantCulture))
                throw new InvalidOperationException("Container status does not bind the original worker identity.");
            var leaseHeld = status.GetProperty("leaseHeld").GetBoolean();
            var volumes = status.GetProperty("volumes");
            if (volumes.ValueKind != JsonValueKind.Array || volumes.GetArrayLength() > MaxCohortVolumes)
                throw new InvalidOperationException("Invalid container status volume bound.");
            if (volumes.GetArrayLength() == 0) return new(!leaseHeld, leaseHeld ? "pending" : "absent", null);
            if (!leaseHeld || volumes.GetArrayLength() != authority.Volumes.Count)
                throw new InvalidOperationException("Container status omitted an original peer.");
            var seen = new HashSet<string>();
            var ready = true;
            foreach (var volume in volumes.EnumerateArray())
            {
                var oid = AuthorityDecimal(volume.GetProperty("objectId"));
                var original = authority.Volumes.SingleOrDefault(v => v.ObjectId == oid);
                var mounted = volume.GetProperty("mounted").GetBoolean();
                var peerReady = volume.GetProperty("ready").GetBoolean();
                if (original is null || !seen.Add(oid) || ManifestText(volume, "canonicalId") != $"apfs-vol:{authority.ContainerUuid}:{oid}" ||
                    ManifestText(volume, "recoveryIdentity", optional: true) != original.RecoveryIdentity ||
                    !string.Equals(NormalizeCohortMountPoint(ManifestText(volume, "mountPoint")), original.MountPoint, StringComparison.OrdinalIgnoreCase) ||
                    (peerReady && !mounted))
                    throw new InvalidOperationException("Container status peer authority mismatch.");
                ready &= mounted && peerReady;
            }
            return new(false, ready ? "ready" : "pending", null);
    }

    private static bool IsMountSettlementProven(FsHostSupervisorEvidence evidence, FsHostMountAbsenceResult proof)
        => proof.DirectAbsent && (evidence.ContainerManifestAuthority is null
            ? proof.StatusResult is not ("ready" or "error") : proof.StatusAbsent && proof.StatusResult == "absent");

    private static bool TryProveExitedDirectoryStaleReady(
        FsHostSupervisorEvidence evidence, FsHostMountAbsenceResult proof,
        SafeNativeHandle? processHandle, SafeNativeHandle? jobHandle)
    {
        evidence.StaleReadyStatusSha256 = null;
        if (evidence.ContainerManifestAuthority is not null || !proof.DirectAbsent || proof.StatusResult != "ready" ||
            proof.DirectResult is not ("directory-absent" or "directory-no-reparse") ||
            evidence.MountPoint is not { } mount || !Path.IsPathFullyQualified(mount) ||
            mount.StartsWith(@"\\", StringComparison.Ordinal) ||
            string.Equals(Path.TrimEndingDirectorySeparator(mount), Path.TrimEndingDirectorySeparator(Path.GetPathRoot(mount)!), StringComparison.OrdinalIgnoreCase) ||
            evidence.StopReason != "host-exited" || evidence.ForcedJobTermination || evidence.ExactProcessTerminationAttempted ||
            !evidence.SupervisionProven || !evidence.JobCreated || !evidence.JobAssigned ||
            !evidence.HostIdentityCaptured || evidence.HostPid is not > 0 || evidence.HostCreationTimeFileTime is not > 0 ||
            evidence.HostExitCode is null || processHandle is null || processHandle.IsInvalid || processHandle.IsClosed ||
            jobHandle is null || jobHandle.IsInvalid || jobHandle.IsClosed || string.IsNullOrWhiteSpace(evidence.StatusFile))
            return false;

        // A saved status bit is never ownership authority. Re-prove the original
        // process and its entire assigned Job before accepting its stale record.
        if (!WaitForOriginalProcessAbsence((uint)evidence.HostPid.Value, evidence.HostCreationTimeFileTime.Value,
                processHandle, 0, evidence) || !evidence.HostPidAbsentFromProcessEnumeration || evidence.HostPidReused ||
            !NativeMethods.QueryInformationJobObject(jobHandle, 1, out var accounting,
                (uint)Marshal.SizeOf<JobBasicAccountingInformation>(), out _))
            return false;
        evidence.JobMembersAbsent = accounting.ActiveProcesses == 0;
        if (!evidence.JobMembersAbsent) return false;

        try
        {
            var info = new FileInfo(evidence.StatusFile);
            if (!info.Exists || info.Length is <= 0 or > 1024 * 1024 ||
                (info.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0 ||
                info.LastWriteTimeUtc.ToFileTimeUtc() < evidence.HostCreationTimeFileTime.Value)
                return false;
            var length = info.Length;
            var modified = info.LastWriteTimeUtc;
            using var stream = new FileStream(evidence.StatusFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length != length) return false;
            var bytes = new byte[(int)length];
            stream.ReadExactly(bytes);
            if (stream.ReadByte() != -1) return false;
            info.Refresh();
            if (bytes.Length != length || info.Length != length || info.LastWriteTimeUtc != modified) return false;
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) return false;
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in document.RootElement.EnumerateObject())
                if (!names.Add(property.Name)) return false;
            if (!document.RootElement.TryGetProperty("mountReady", out var ready) || ready.ValueKind != JsonValueKind.True ||
                !document.RootElement.TryGetProperty("hostPid", out var pid) || !pid.TryGetInt32(out var owner) || owner != evidence.HostPid)
                return false;
            evidence.StaleReadyStatusSha256 = Convert.ToHexString(SHA256.HashData(bytes));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool HasCohortCrashProof(FsHostSupervisorEvidence evidence)
    {
        var authority = evidence.ContainerManifestAuthority;
        var binding = evidence.CohortCrashBinding;
        var proof = evidence.CohortCrashProof;
        return authority is not null && binding is not null && proof is not null &&
            proof.Contract == "container-manifest-crash-retirement-v1" && proof.OriginalLeaseReleased &&
            binding.RunNonce.Length == 32 && binding.RunNonce.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f') &&
            proof.RunNonce == binding.RunNonce && proof.NativeSha256 == binding.NativeSha256 && IsProofHash(proof.NativeSha256) &&
            proof.SupervisorSha256 == evidence.SupervisorSha256 && IsProofHash(proof.SupervisorSha256) &&
            proof.SupervisorPayloadSha256 == evidence.SupervisorPayloadSha256 && IsProofHash(proof.SupervisorPayloadSha256) &&
            proof.ManifestContentSha256 == authority.ContentSha256 && IsProofHash(proof.StatusSha256) &&
            ulong.TryParse(proof.StatusVolumeSerial, NumberStyles.None, CultureInfo.InvariantCulture, out _) &&
            ulong.TryParse(proof.StatusFileId, NumberStyles.None, CultureInfo.InvariantCulture, out var fileId) && fileId != 0 &&
            evidence.StopReason == "host-exited" && evidence.SupervisionProven && evidence.JobCreated && evidence.JobAssigned &&
            evidence.OriginalHostIdentityAbsent && evidence.HostIdentityCaptured && evidence.HostIdentityState == "absent" &&
            evidence.HostPid is > 0 && evidence.HostCreationTimeFileTime is > 0 && evidence.Failure is null &&
            evidence.HostPidAbsentFromProcessEnumeration && !evidence.HostPidReused && evidence.HostExitCode is not null &&
            !evidence.ForcedJobTermination && !evidence.ExactProcessTerminationAttempted &&
            !evidence.MountAbsentFromStatus && evidence.MountStatusProbeResult == "ready" &&
            proof.Aliases.Count == authority.Volumes.Count && authority.Volumes.All(v =>
                IsDriveMountPoint(v.MountPoint) && proof.Aliases.Count(a => a.ObjectId == v.ObjectId &&
                    a.MountPoint == v.MountPoint && a.LocalState == "absent" && a.GlobalState == "absent") == 1);
    }

    private static bool IsProofHash(string value)
        => value.Length == 64 && value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static FsHostMountProbeResult ProbeCohortDosAlias(string name)
    {
        if (TestHooks.Value?.CohortAliasProbeOverride is { } hook) return hook(name);
        var buffer = new StringBuilder(32768);
        if (NativeMethods.QueryDosDeviceW(name, buffer, buffer.Capacity) != 0)
            return new(false, "drive-assigned", buffer.ToString());
        var error = Marshal.GetLastWin32Error();
        if (error == ErrorFileNotFound) return new(true, "drive-absent", "No DOS alias exists.");
        throw new Win32Exception(error, "Unable to prove original cohort alias absence: " + name);
    }

    private static FsHostCohortCrashProof? TryProveExitedCohortStaleReady(
        FsHostSupervisorEvidence evidence, FsHostMountAbsenceResult proof,
        SafeNativeHandle? processHandle, SafeNativeHandle? jobHandle)
    {
        var authority = evidence.ContainerManifestAuthority;
        var binding = evidence.CohortCrashBinding;
        if (authority is null || binding is null || authority.Volumes.Any(v => !IsDriveMountPoint(v.MountPoint)) ||
            !proof.DirectAbsent || proof.StatusResult != "ready" || proof.Failure is not null ||
            evidence.StopReason != "host-exited" || evidence.Failure is not null ||
            evidence.ForcedJobTermination || evidence.ExactProcessTerminationAttempted ||
            !evidence.SupervisionProven || !evidence.JobCreated || !evidence.JobAssigned ||
            !evidence.HostIdentityCaptured || evidence.HostPid is not > 0 || evidence.HostCreationTimeFileTime is not > 0 ||
            evidence.HostExitCode is null || processHandle is null || processHandle.IsInvalid || processHandle.IsClosed ||
            jobHandle is null || jobHandle.IsInvalid || jobHandle.IsClosed || string.IsNullOrWhiteSpace(evidence.StatusFile)) return null;
        if (!WaitForOriginalProcessAbsence((uint)evidence.HostPid.Value, evidence.HostCreationTimeFileTime.Value,
                processHandle, 0, evidence) || !evidence.HostPidAbsentFromProcessEnumeration || evidence.HostPidReused ||
            !NativeMethods.QueryInformationJobObject(jobHandle, 1, out var accounting,
                (uint)Marshal.SizeOf<JobBasicAccountingInformation>(), out _) || accounting.ActiveProcesses != 0) return null;
        evidence.JobMembersAbsent = true;
        try
        {
            ValidateManifestAuthority(evidence);
            if (ComputeSha256(evidence.HostExecutable) != binding.NativeSha256 ||
                ComputeSha256(evidence.SupervisorExecutable) != evidence.SupervisorSha256 ||
                ComputeSha256(evidence.SupervisorPayloadPath) != evidence.SupervisorPayloadSha256) return null;
            var aliases = new List<FsHostCohortAliasProof>();
            foreach (var volume in authority.Volumes)
            {
                if (!ProbeCohortDosAlias(volume.MountPoint).IsAbsent || !ProbeCohortDosAlias(@"Global\" + volume.MountPoint).IsAbsent)
                    return null;
                aliases.Add(new(volume.ObjectId, volume.MountPoint, "absent", "absent"));
            }
            RequireNoReparsePath(evidence.StatusFile);
            using var stream = new FileStream(evidence.StatusFile, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length is <= 0 or > MaxManifestBytes ||
                !NativeMethods.GetFileInformationByHandle(stream.SafeFileHandle, out var before) ||
                (before.Attributes & (uint)(FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0 ||
                before.LastWrite.ToInt64() < evidence.HostCreationTimeFileTime.Value) return null;
            var bytes = new byte[checked((int)stream.Length)];
            stream.ReadExactly(bytes);
            if (stream.ReadByte() != -1 || ParseContainerStatus(evidence, bytes).Result != "ready" ||
                !NativeMethods.GetFileInformationByHandle(stream.SafeFileHandle, out var after) ||
                before.VolumeSerial != after.VolumeSerial || before.FileIndexHigh != after.FileIndexHigh || before.FileIndexLow != after.FileIndexLow ||
                before.SizeHigh != after.SizeHigh || before.SizeLow != after.SizeLow || before.LastWrite.ToInt64() != after.LastWrite.ToInt64()) return null;
            RequireNoReparsePath(evidence.StatusFile);
            // The retained process and its complete Job are gone. These are the
            // original generation's noninherited handles, not future admission.
            var result = new FsHostCohortCrashProof("container-manifest-crash-retirement-v1", binding.RunNonce,
                binding.NativeSha256, evidence.SupervisorSha256, evidence.SupervisorPayloadSha256, authority.ContentSha256,
                Convert.ToHexString(SHA256.HashData(bytes)), before.VolumeSerial.ToString(CultureInfo.InvariantCulture),
                (((ulong)before.FileIndexHigh << 32) | before.FileIndexLow).ToString(CultureInfo.InvariantCulture), true, aliases.AsReadOnly());
            evidence.CohortCrashProof = result;
            if (!HasCohortCrashProof(evidence)) { evidence.CohortCrashProof = null; return null; }
            return result;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or KeyNotFoundException or FormatException or Win32Exception)
        {
            evidence.CohortCrashProof = null;
            return null;
        }
    }

    private static FsHostMountAbsenceResult WaitForEvidenceMountAbsence(FsHostSupervisorEvidence evidence, int timeoutMs,
        CancellationToken cancellationToken = default, DateTime? sharedDeadlineUtc = null)
    {
        if (evidence.ContainerManifestAuthority is not { } authority)
            return WaitForMountAbsence(evidence.MountPoint, evidence.StatusFile, timeoutMs, cancellationToken, sharedDeadlineUtc);
        evidence.MountProofs = Array.Empty<FsHostCohortMountProof>();
        evidence.MountAbsenceProven = false;
        evidence.MountAbsentFromDirectProbe = false;
        evidence.MountAbsentFromStatus = false;
        evidence.MountStatusProbeResult = "error";
        evidence.CohortCrashProof = null;
        var deadline = DateTime.UtcNow.AddMilliseconds(Math.Max(0, timeoutMs));
        if (sharedDeadlineUtc is { } shared && shared < deadline) deadline = shared;
        FsHostMountAbsenceResult result;
        do
        {
            cancellationToken.ThrowIfCancellationRequested();
            ValidateManifestAuthority(evidence);
            var proofs = new List<FsHostCohortMountProof>();
            foreach (var volume in authority.Volumes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                FsHostMountProbeResult probe;
                try { probe = TestHooks.Value?.MountPointProbeOverride?.Invoke(volume.MountPoint) ?? ProbeMountPointDirect(NormalizeMountPoint(volume.MountPoint)!); }
                catch (Exception ex) { probe = new(false, "error", ex.Message); }
                proofs.Add(new(volume.ObjectId, volume.MountPoint, volume.RecoveryIdentity, probe.IsAbsent ? "absent" : "present", probe.Detail));
            }
            evidence.MountProofs = proofs.AsReadOnly();
            var status = ReadContainerStatus(evidence);
            result = new(proofs.All(p => p.DirectState == "absent"), status.IsAbsent, "cohort-all-mounts", status.Result, status.Failure);
            if (result.DirectAbsent && result.StatusAbsent) return result;
            if (GetRemainingMilliseconds(deadline) > 0) WaitForCancellationOrTimeout(cancellationToken, deadline, 50);
        } while (GetRemainingMilliseconds(deadline) > 0);
        return result;
    }

    private static bool IsCohortOwnershipProven(FsHostSupervisorEvidence evidence, uint activeProcesses)
    {
        evidence.JobMembersAbsent = activeProcesses == 0;
        var authority = evidence.ContainerManifestAuthority!;
        return evidence.OriginalHostIdentityAbsent && evidence.JobMembersAbsent && evidence.MountAbsenceProven &&
            (evidence.MountAbsentFromStatus && evidence.MountStatusProbeResult == "absent" ||
                HasCohortCrashProof(evidence)) &&
            evidence.MountProofs.Count == authority.Volumes.Count && authority.Volumes.All(v =>
                evidence.MountProofs.Count(p => p.ObjectId == v.ObjectId && p.MountPoint == v.MountPoint &&
                    p.RecoveryIdentity == v.RecoveryIdentity && p.DirectState == "absent") == 1);
    }

    private static bool IsOwnershipProven(FsHostSupervisorEvidence evidence, SafeNativeHandle? jobHandle)
    {
        if (evidence.ContainerManifestAuthority is null) return evidence.OriginalHostIdentityAbsent && evidence.MountAbsentFromDirectProbe;
        if (jobHandle is null || jobHandle.IsClosed || jobHandle.IsInvalid) return false;
        if (!NativeMethods.QueryInformationJobObject(jobHandle, 1, out var accounting,
            (uint)Marshal.SizeOf<JobBasicAccountingInformation>(), out _))
        {
            evidence.JobMembersAbsent = false;
            return false;
        }
        return IsCohortOwnershipProven(evidence, accounting.ActiveProcesses);
    }

    private static FsHostMountAbsenceResult WaitForMountAbsence(
        string? mountPoint,
        string? statusPath,
        int timeoutMs,
        CancellationToken cancellationToken = default,
        DateTime? deadlineUtc = null)
    {
        mountPoint = NormalizeMountPoint(mountPoint);
        if (string.IsNullOrWhiteSpace(mountPoint))
        {
            throw new InvalidOperationException(
                "A direct mount-point probe requires the supervised FsHost mount point.");
        }

        var deadline = deadlineUtc ?? DateTime.UtcNow.AddMilliseconds(Math.Max(250, timeoutMs));
        FsHostMountProbeResult? lastDirect = null;
        string? directFailure = null;
        var lastStatus = new MountStatusObservation(false, "not-requested", null);
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                lastDirect = TestHooks.Value?.MountPointProbeOverride?.Invoke(mountPoint) ??
                    ProbeMountPointDirect(mountPoint);
                directFailure = null;
            }
            catch (Exception ex)
            {
                directFailure = ex.Message;
                lastDirect = new FsHostMountProbeResult(
                    IsAbsent: false,
                    ProbeKind: "error",
                    Detail: ex.Message);
            }

            lastStatus = ReadMountStatus(statusPath);
            if (lastDirect.IsAbsent && lastStatus.Result is not ("ready" or "error"))
            {
                return new FsHostMountAbsenceResult(
                    DirectAbsent: true,
                    StatusAbsent: lastStatus.IsAbsent,
                    DirectResult: lastDirect.ProbeKind,
                    StatusResult: lastStatus.Result,
                    Failure: directFailure ?? lastStatus.Failure);
            }

            if (lastDirect.IsAbsent && lastStatus.Result == "error")
            {
                return new FsHostMountAbsenceResult(
                    DirectAbsent: true,
                    StatusAbsent: false,
                    DirectResult: lastDirect.ProbeKind,
                    StatusResult: lastStatus.Result,
                    Failure: directFailure ?? lastStatus.Failure);
            }

            WaitForCancellationOrTimeout(cancellationToken, deadline, 100);
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (lastDirect is null)
        {
            try
            {
                lastDirect = TestHooks.Value?.MountPointProbeOverride?.Invoke(mountPoint) ??
                    ProbeMountPointDirect(mountPoint);
            }
            catch (Exception ex)
            {
                directFailure = ex.Message;
                lastDirect = new FsHostMountProbeResult(
                    IsAbsent: false,
                    ProbeKind: "error",
                    Detail: ex.Message);
            }
        }

        lastStatus = ReadMountStatus(statusPath);
        return new FsHostMountAbsenceResult(
            DirectAbsent: lastDirect.IsAbsent,
            StatusAbsent: lastStatus.IsAbsent,
            DirectResult: lastDirect.ProbeKind,
            StatusResult: lastStatus.Result,
            Failure: directFailure ?? lastStatus.Failure);
    }

    private static FsHostMountProbeResult ProbeMountPointDirect(string mountPoint)
    {
        if (IsDriveMountPoint(mountPoint))
        {
            var capacity = 256;
            while (capacity <= 32 * 1024)
            {
                var target = new StringBuilder(capacity);
                var length = NativeMethods.QueryDosDeviceW(mountPoint, target, target.Capacity);
                if (length != 0)
                {
                    return new FsHostMountProbeResult(
                        IsAbsent: false,
                        ProbeKind: "drive-assigned",
                        Detail: target.ToString());
                }

                var error = Marshal.GetLastWin32Error();
                if (error is ErrorFileNotFound or ErrorPathNotFound)
                {
                    return new FsHostMountProbeResult(
                        IsAbsent: true,
                        ProbeKind: "drive-absent",
                        Detail: $"QueryDosDeviceW returned Win32 error {error}.");
                }

                if (error == ErrorInsufficientBuffer)
                {
                    capacity *= 2;
                    continue;
                }

                throw new Win32Exception(
                    error,
                    $"QueryDosDeviceW failed for '{mountPoint}' with Win32 error {error}.");
            }

            throw new InvalidOperationException(
                $"QueryDosDeviceW returned an overlong mapping for '{mountPoint}'.");
        }

        var attributes = NativeMethods.GetFileAttributesW(mountPoint);
        if (attributes == InvalidFileAttributes)
        {
            var error = Marshal.GetLastWin32Error();
            if (error is ErrorFileNotFound or ErrorPathNotFound)
            {
                return new FsHostMountProbeResult(
                    IsAbsent: true,
                    ProbeKind: "directory-absent",
                    Detail: $"GetFileAttributesW returned Win32 error {error}.");
            }

            throw new Win32Exception(
                error,
                $"GetFileAttributesW failed for '{mountPoint}' with Win32 error {error}.");
        }

        if ((attributes & FileAttributeReparsePoint) != 0)
        {
            return new FsHostMountProbeResult(
                IsAbsent: false,
                ProbeKind: "directory-reparse-present",
                Detail: "The mount point still has a reparse point.");
        }

        return new FsHostMountProbeResult(
            IsAbsent: true,
            ProbeKind: "directory-no-reparse",
            Detail: "The mount path exists without a reparse point.");
    }

    private static MountStatusObservation ReadMountStatus(string? statusPath)
    {
        if (string.IsNullOrWhiteSpace(statusPath))
        {
            return new MountStatusObservation(false, "not-requested", null);
        }

        try
        {
            using var stream = new FileStream(statusPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var document = JsonDocument.Parse(stream);
            if (document.RootElement.TryGetProperty("mountReady", out var mountReady) &&
                mountReady.ValueKind == JsonValueKind.True)
            {
                return new MountStatusObservation(false, "ready", null);
            }

            return new MountStatusObservation(true, "absent", null);
        }
        catch (FileNotFoundException)
        {
            return new MountStatusObservation(false, "missing", null);
        }
        catch (DirectoryNotFoundException)
        {
            return new MountStatusObservation(false, "missing", null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return new MountStatusObservation(false, "error", ex.Message);
        }
    }

    private static QuarantineOwnerStartResult TryStartQuarantineOwner(
        FsHostSupervisorEvidence evidence,
        FsHostSupervisorOptions options,
        SafeNativeHandle jobHandle,
        SafeNativeHandle processHandle)
    {
        if (TestHooks.Value?.StartQuarantineOwnerOverride is { } startOverride)
        {
            var failedChild = TestHooks.Value.FailedQuarantineChildHandle;
            return new QuarantineOwnerStartResult(startOverride(), failedChild is null, null,
                failedChild is null ? null : DuplicateInheritedHandle(failedChild));
        }

        SafeNativeHandle? inheritedJob = null;
        SafeNativeHandle? inheritedProcess = null;
        ChildLaunch? quarantine = null;
        var readyPath = evidence.EvidenceFile + ".quarantine." + Guid.NewGuid().ToString("N") + ".ready";
        var readyToken = Guid.NewGuid().ToString("N");
        var handoffToken = Guid.NewGuid().ToString("N");
        try
        {
            if (File.Exists(readyPath))
            {
                throw new IOException($"The quarantine ready path unexpectedly already exists: {readyPath}");
            }

            inheritedJob = DuplicateInheritedHandle(jobHandle);
            inheritedProcess = DuplicateInheritedHandle(processHandle);

            var commandLine = BuildQuarantineCommandLine(
                inheritedJob.DangerousGetHandle(),
                inheritedProcess.DangerousGetHandle(),
                evidence,
                options,
                readyPath,
                readyToken,
                handoffToken,
                TestHooks.Value?.ExcludedInheritableHandle);
            var self = ResolveSelfLaunch();
            quarantine = CreateRestrictedHandleChild(
                self.ApplicationPath,
                commandLine,
                evidence.WorkingDirectory ?? Environment.CurrentDirectory,
                inheritedJob,
                inheritedProcess);

            evidence.QuarantineRequired = true;
            evidence.QuarantineOwnerStarted = false;
            evidence.QuarantineOwnerPid = checked((int)quarantine.ProcessId);
            evidence.QuarantineOwnerKind = "managed-cli";
            evidence.QuarantineOwnerHandleInheritanceProven = false;
            evidence.QuarantineStartedUtc ??= DateTime.UtcNow;
            evidence.OwnershipHandoffToken = handoffToken;
            evidence.OwnershipHandoffState = "offered";
            evidence.SupervisorExitCode = 1;
            WriteEvidence(evidence);

            if (NativeMethods.ResumeThread(quarantine.ThreadHandle) == uint.MaxValue)
            {
                throw LastWin32Error("ResumeThread(quarantine owner)");
            }
            quarantine.ThreadHandle.Dispose();

            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (DateTime.UtcNow < deadline)
            {
                if (File.Exists(readyPath) &&
                    string.Equals(File.ReadAllText(readyPath), readyToken, StringComparison.Ordinal))
                {
                    if (WaitForObject(
                            quarantine.ProcessHandle,
                            0,
                            WaitKindQuarantine,
                            "WaitForSingleObject(quarantine owner after ready)") == WaitObject0)
                    {
                        throw new InvalidOperationException(
                            "The quarantine owner exited immediately after taking handle ownership.");
                    }

                    ValidateQuarantineAcceptance(
                        evidence.EvidenceFile,
                        checked((int)quarantine.ProcessId),
                        handoffToken);
                    quarantine.ProcessHandle.Dispose();
                    quarantine = null;
                    return new QuarantineOwnerStartResult(true, true, null);
                }

                if (WaitForObject(
                        quarantine.ProcessHandle,
                        0,
                        WaitKindQuarantine,
                        "WaitForSingleObject(quarantine owner)") == WaitObject0)
                {
                    throw new InvalidOperationException("The quarantine owner exited before taking handle ownership.");
                }

                Thread.Sleep(25);
            }

            if (TryValidateQuarantineAcceptance(
                    evidence.EvidenceFile,
                    checked((int)quarantine.ProcessId),
                    handoffToken))
            {
                quarantine.ProcessHandle.Dispose();
                quarantine = null;
                return new QuarantineOwnerStartResult(true, true, null);
            }

            throw new TimeoutException("The quarantine owner did not prove handle ownership within five seconds.");
        }
        catch (Exception exception)
        {
            var childTerminationProven = true;
            SafeNativeHandle? retainedChild = null;
            if (quarantine is not null)
            {
                try
                {
                    childTerminationProven = TryTerminateQuarantineChild(
                        quarantine.ProcessHandle,
                        evidence);
                }
                catch (Exception cleanupException)
                {
                    childTerminationProven = false;
                    RecordFailure(
                        evidence,
                        "Unable to verify failed quarantine-child termination.",
                        cleanupException);
                }

                if (!childTerminationProven && evidence.ContainerManifestAuthority is not null)
                    retainedChild = quarantine.ProcessHandle;
                else
                    try { quarantine.ProcessHandle.Dispose(); } catch { }
                try { quarantine.ThreadHandle.Dispose(); } catch { }
            }

            return new QuarantineOwnerStartResult(
                OwnershipTransferred: false,
                ChildTerminationProven: childTerminationProven,
                Failure: exception,
                FailedChildHandle: retainedChild);
        }
        finally
        {
            inheritedJob?.Dispose();
            inheritedProcess?.Dispose();
            try { File.Delete(readyPath); } catch { }
        }
    }

    private static bool TryTerminateQuarantineChild(
        SafeNativeHandle processHandle,
        FsHostSupervisorEvidence evidence)
    {
        var processExited = false;
        try
        {
            processExited = WaitForObject(
                processHandle,
                0,
                WaitKindQuarantine,
                "WaitForSingleObject(quarantine owner before cleanup)") == WaitObject0;
        }
        catch (Exception ex)
        {
            RecordFailure(evidence, "Unable to inspect the failed quarantine owner.", ex);
        }

        if (!processExited)
        {
            if (!NativeMethods.TerminateProcess(processHandle, 0xE0010003))
            {
                var error = Marshal.GetLastWin32Error();
                RecordFailure(
                    evidence,
                    "Unable to terminate the failed quarantine owner.",
                    new Win32Exception(
                        error,
                        $"TerminateProcess(quarantine owner) failed with Win32 error {error}."));
            }

            try
            {
                processExited = WaitForObject(
                    processHandle,
                    5_000,
                    WaitKindQuarantine,
                    "WaitForSingleObject(quarantine owner after cleanup)") == WaitObject0;
            }
            catch (Exception ex)
            {
                RecordFailure(evidence, "Unable to verify failed quarantine-owner termination.", ex);
            }
        }

        if (!processExited)
        {
            RecordFailure(
                evidence,
                "Unable to verify failed quarantine-owner termination.",
                new TimeoutException("The failed quarantine owner remained present after cleanup."));
        }

        return processExited;
    }

    private static SafeNativeHandle DuplicateInheritedHandle(SafeHandle source)
    {
        if (!NativeMethods.DuplicateHandle(
                NativeMethods.GetCurrentProcess(),
                source.DangerousGetHandle(),
                NativeMethods.GetCurrentProcess(),
                out var duplicate,
                0,
                true,
                DuplicateSameAccess))
        {
            throw LastWin32Error("DuplicateHandle(quarantine owner)");
        }

        return new SafeNativeHandle(duplicate);
    }

    private static void ValidateInheritedHandle(SafeNativeHandle handle, string operation)
    {
        if (handle.IsInvalid || handle.IsClosed ||
            !NativeMethods.GetHandleInformation(handle, out _))
        {
            throw LastWin32Error(operation);
        }
    }

    private static StringBuilder BuildQuarantineCommandLine(
        nint jobHandle,
        nint processHandle,
        FsHostSupervisorEvidence evidence,
        FsHostSupervisorOptions options,
        string readyPath,
        string readyToken,
        string handoffToken,
        nint? testExcludedHandle)
    {
        var self = ResolveSelfLaunch();
        var commandLine = new StringBuilder();
        commandLine.Append(QuoteWindowsArgument(self.ApplicationPath));
        if (self.AssemblyPath is not null)
        {
            commandLine.Append(' ');
            commandLine.Append(QuoteWindowsArgument(self.AssemblyPath));
        }

        commandLine.Append(" quarantine-fshost");
        AppendArgument(commandLine, "--job-handle", jobHandle.ToInt64().ToString(CultureInfo.InvariantCulture));
        AppendArgument(commandLine, "--process-handle", processHandle.ToInt64().ToString(CultureInfo.InvariantCulture));
        AppendArgument(commandLine, "--host-pid", (evidence.HostPid ?? 0).ToString(CultureInfo.InvariantCulture));
        AppendArgument(commandLine, "--host-creation-time", (evidence.HostCreationTimeFileTime ?? 0).ToString(CultureInfo.InvariantCulture));
        AppendArgument(commandLine, "--job-assigned", evidence.JobAssigned ? "true" : "false");
        AppendArgument(commandLine, "--mount-point", SealCohortHandoff(evidence) ?? evidence.MountPoint ?? string.Empty);
        AppendArgument(commandLine, "--status-file", evidence.StatusFile ?? string.Empty);
        AppendArgument(commandLine, "--evidence-file", evidence.EvidenceFile);
        AppendArgument(commandLine, "--ready-file", readyPath);
        AppendArgument(commandLine, "--ready-token", readyToken);
        AppendArgument(commandLine, "--handoff-token", handoffToken);
        AppendArgument(commandLine, "--process-absence-timeout-ms", options.ProcessAbsenceTimeoutMs.ToString(CultureInfo.InvariantCulture));
        if (testExcludedHandle is not null)
        {
            AppendArgument(
                commandLine,
                "--test-excluded-handle",
                testExcludedHandle.Value.ToInt64().ToString(CultureInfo.InvariantCulture));
        }
        return commandLine;
    }

    private sealed record CohortHandoff(FsHostContainerManifestAuthority Authority, IReadOnlyList<string> HostArguments);
    private const string CohortHandoffPrefix = "cohort-sha256:";

    private static string? SealCohortHandoff(FsHostSupervisorEvidence evidence)
    {
        if (evidence.ContainerManifestAuthority is not { } authority) return null;
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new CohortHandoff(authority, evidence.HostArguments), JsonOptions);
        if (bytes.Length > MaxManifestBytes) throw new InvalidOperationException("Cohort handoff byte bound exceeded.");
        var file = evidence.EvidenceFile + ".cohort.json";
        if (!File.Exists(file))
        {
            using var stream = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        RequireNoReparsePath(file);
        var digest = Convert.ToHexString(SHA256.HashData(bytes));
        if (ComputeSha256(file) != digest) throw new InvalidOperationException("Cohort handoff snapshot changed.");
        return CohortHandoffPrefix + digest;
    }

    private static CohortHandoff? ReadCohortHandoff(QuarantineOptions options)
    {
        if (!options.MountPoint.StartsWith(CohortHandoffPrefix, StringComparison.Ordinal)) return null;
        var file = options.EvidenceFile + ".cohort.json";
        RequireNoReparsePath(file);
        if (new FileInfo(file).Length > MaxManifestBytes || ComputeSha256(file) != options.MountPoint[CohortHandoffPrefix.Length..])
            throw new InvalidOperationException("Quarantine cohort handoff digest mismatch.");
        var handoff = JsonSerializer.Deserialize<CohortHandoff>(File.ReadAllBytes(file), JsonOptions)
            ?? throw new InvalidOperationException("Quarantine cohort handoff is missing.");
        var actual = ReadContainerManifestAuthority(handoff.HostArguments);
        if (actual is null || JsonSerializer.Serialize(actual, JsonOptions) != JsonSerializer.Serialize(handoff.Authority, JsonOptions))
            throw new InvalidOperationException("Quarantine manifest authority changed.");
        return handoff;
    }

    private static void RestoreCohortHandoff(FsHostSupervisorEvidence evidence, QuarantineOptions options)
    {
        var handoff = ReadCohortHandoff(options);
        if (handoff is null)
        {
            if (evidence.ContainerManifestAuthority is not null) throw new InvalidOperationException("Quarantine cohort lost its immutable authority.");
            return;
        }
        if (evidence.MountPoint is not null || evidence.StatusFile != options.StatusFile ||
            !evidence.HostArguments.SequenceEqual(handoff.HostArguments) ||
            JsonSerializer.Serialize(evidence.ContainerManifestAuthority, JsonOptions) != JsonSerializer.Serialize(handoff.Authority, JsonOptions))
            throw new InvalidOperationException("Quarantine cohort evidence differs from the inherited authority.");
        evidence.ContainerManifestAuthority = handoff.Authority;
    }

    private static ChildLaunch CreateRestrictedHandleChild(
        string applicationPath,
        StringBuilder commandLine,
        string workingDirectory,
        params SafeNativeHandle[] inheritedHandles)
    {
        nuint attributeListSize = 0;
        _ = NativeMethods.InitializeProcThreadAttributeList(nint.Zero, 1, 0, ref attributeListSize);
        var sizingError = Marshal.GetLastWin32Error();
        if (attributeListSize == 0 || sizingError != ErrorInsufficientBuffer)
        {
            throw new Win32Exception(
                sizingError,
                $"InitializeProcThreadAttributeList(size) failed with Win32 error {sizingError}.");
        }

        var attributeList = Marshal.AllocHGlobal(checked((nint)attributeListSize));
        var handleList = Marshal.AllocHGlobal(checked(inheritedHandles.Length * nint.Size));
        try
        {
            if (!NativeMethods.InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeListSize))
            {
                throw LastWin32Error("InitializeProcThreadAttributeList");
            }

            for (var index = 0; index < inheritedHandles.Length; index++)
            {
                Marshal.WriteIntPtr(handleList, index * nint.Size, inheritedHandles[index].DangerousGetHandle());
            }

            if (!NativeMethods.UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    ProcThreadAttributeHandleList,
                    handleList,
                    checked((nuint)(inheritedHandles.Length * nint.Size)),
                    nint.Zero,
                    nint.Zero))
            {
                throw LastWin32Error("UpdateProcThreadAttribute(handle list)");
            }

            var startupInfo = new StartupInfoEx
            {
                StartupInfo = new StartupInfo
                {
                    Cb = (uint)Marshal.SizeOf<StartupInfoEx>(),
                },
                AttributeList = attributeList,
            };
            if (!NativeMethods.CreateProcessW(
                    applicationPath,
                    commandLine,
                    nint.Zero,
                    nint.Zero,
                    true,
                    CreateSuspended | CreateUnicodeEnvironment | CreateNoWindow | ExtendedStartupInfoPresent,
                    nint.Zero,
                    workingDirectory,
                    ref startupInfo,
                    out var processInformation))
            {
                throw LastWin32Error("CreateProcessW(quarantine owner)");
            }

            return new ChildLaunch(
                new SafeNativeHandle(processInformation.ProcessHandle),
                new SafeNativeHandle(processInformation.ThreadHandle),
                processInformation.ProcessId);
        }
        finally
        {
            if (attributeList != nint.Zero)
            {
                NativeMethods.DeleteProcThreadAttributeList(attributeList);
            }
            Marshal.FreeHGlobal(handleList);
            Marshal.FreeHGlobal(attributeList);
        }
    }

    private static void ValidateQuarantineAcceptance(
        string evidencePath,
        int quarantinePid,
        string handoffToken)
    {
        if (!TryValidateQuarantineAcceptance(evidencePath, quarantinePid, handoffToken))
        {
            throw new InvalidOperationException(
                "The quarantine owner did not publish handle-validated evidence handoff acceptance.");
        }
    }

    private static bool TryValidateQuarantineAcceptance(
        string evidencePath,
        int quarantinePid,
        string handoffToken)
    {
        try
        {
            var accepted = JsonSerializer.Deserialize<FsHostSupervisorEvidence>(
                File.ReadAllText(evidencePath),
                JsonOptions);
            return accepted is not null &&
                accepted.EvidenceWriterPid == quarantinePid &&
                string.Equals(accepted.EvidenceWriterRole, "quarantine", StringComparison.Ordinal) &&
                string.Equals(accepted.OwnershipHandoffToken, handoffToken, StringComparison.Ordinal) &&
                accepted.OwnershipHandoffState is "accepted" or "completed" &&
                accepted.QuarantineOwnerHandleInheritanceProven &&
                !accepted.QuarantineExcludedHandleInherited &&
                HasCurrentSupervisorIdentity(accepted);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return false;
        }
    }

    private static void AppendArgument(StringBuilder commandLine, string name, string value)
    {
        commandLine.Append(' ');
        commandLine.Append(QuoteWindowsArgument(name));
        commandLine.Append(' ');
        commandLine.Append(QuoteWindowsArgument(value));
    }

    private static (string ApplicationPath, string? AssemblyPath) ResolveSelfLaunch()
    {
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath))
        {
            throw new InvalidOperationException("The supervisor process path is unavailable.");
        }

        if (SupervisorExecutablePathOverride.Value is not null)
        {
            return (ResolveSupervisorExecutablePath(), null);
        }

        // Unit tests run this code inside testhost.exe. Use the CLI assembly
        // for managed launchers so a quarantine owner starts the supervisor
        // command, rather than passing quarantine arguments to the test host.
        var loadedAssemblyPath = typeof(FsHostSupervisor).Assembly.Location;
        if (!string.IsNullOrWhiteSpace(loadedAssemblyPath) &&
            Path.GetExtension(loadedAssemblyPath).Equals(".dll", StringComparison.OrdinalIgnoreCase) &&
            File.Exists(loadedAssemblyPath))
        {
            var processName = Path.GetFileName(processPath);
            if (string.Equals(processName, "dotnet.exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(processName, "dotnet", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(processName, "testhost.exe", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(processName, "testhost", StringComparison.OrdinalIgnoreCase))
            {
                return (ResolveDotnetHost(processPath), loadedAssemblyPath);
            }

            // A published apphost can execute the CLI assembly directly. Do
            // not route it back through a machine-wide dotnet.exe that may be
            // absent or a different runtime version.
            return (processPath, null);
        }

        var commandLine = Environment.GetCommandLineArgs();
        var assemblyPath = commandLine.Length > 1 &&
            Path.GetExtension(commandLine[1]).Equals(".dll", StringComparison.OrdinalIgnoreCase)
                ? commandLine[1]
                : null;
        return (processPath, assemblyPath);
    }

    private static string ResolveDotnetHost(string currentProcessPath)
    {
        var explicitHost = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        if (!string.IsNullOrWhiteSpace(explicitHost) && File.Exists(explicitHost))
        {
            return Path.GetFullPath(explicitHost);
        }

        var programFilesHost = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "dotnet",
            "dotnet.exe");
        if (File.Exists(programFilesHost)) return programFilesHost;

        return string.Equals(
            Path.GetFileName(currentProcessPath),
            "dotnet.exe",
            StringComparison.OrdinalIgnoreCase)
            ? currentProcessPath
            : "dotnet.exe";
    }

    private static bool RunInlineQuarantineUntilProven(
        FsHostSupervisorEvidence evidence,
        int processAbsenceTimeoutMs,
        SafeNativeHandle jobHandle,
        SafeNativeHandle processHandle,
        CancellationToken cancellationToken)
    {
        // Scalar cancellation stays bounded. Unsettled cohorts continue in
        // the awaited enforcement keeper after this diagnostic deadline.
        evidence.Status = "quarantined";
        var deadline = DateTime.UtcNow.AddMilliseconds(Math.Max(250, processAbsenceTimeoutMs));
        try
        {
            WriteEvidence(evidence);
        }
        catch (Exception ex)
        {
            RecordFailure(evidence, "Unable to persist quarantine evidence.", ex);
        }

        while (GetRemainingMilliseconds(deadline) > 0)
        {
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                ForceTerminateHost(
                    evidence,
                    jobHandle,
                    processHandle,
                    checked((uint)GetRemainingMilliseconds(deadline)));
                if (evidence.HostPid is not null &&
                    evidence.HostIdentityCaptured &&
                    evidence.HostCreationTimeFileTime is not null)
                {
                    evidence.OriginalHostIdentityAbsent = WaitForOriginalProcessAbsence(
                        (uint)evidence.HostPid.Value,
                        evidence.HostCreationTimeFileTime.Value,
                        processHandle,
                        Math.Min(1000, GetRemainingMilliseconds(deadline)),
                        evidence,
                        cancellationToken,
                        deadline);
                }

                cancellationToken.ThrowIfCancellationRequested();
                if (GetRemainingMilliseconds(deadline) <= 0) break;
                var mountProof = WaitForEvidenceMountAbsence(
                    evidence,
                    Math.Min(1000, GetRemainingMilliseconds(deadline)),
                    cancellationToken,
                    deadline);
                evidence.MountAbsentFromDirectProbe = mountProof.DirectAbsent;
                evidence.MountAbsentFromStatus = mountProof.StatusAbsent;
                evidence.MountDirectProbeResult = mountProof.DirectResult;
                evidence.MountStatusProbeResult = mountProof.StatusResult;
                evidence.MountAbsenceProven = IsMountSettlementProven(evidence, mountProof);
                if (IsOwnershipProven(evidence, jobHandle))
                {
                    return true;
                }
            }
            catch (OperationCanceledException ex)
            {
                RecordFailure(evidence, "Inline quarantine was cancelled before ownership was proven.", ex);
                break;
            }
            catch (Exception ex)
            {
                RecordFailure(evidence, "Quarantine proof is still unavailable.", ex);
            }

            try
            {
                WriteEvidence(evidence);
            }
            catch (Exception ex)
            {
                RecordFailure(evidence, "Unable to persist quarantine evidence.", ex);
            }

            if (cancellationToken.IsCancellationRequested) break;
            WaitForCancellationOrTimeout(cancellationToken, deadline, 250);
        }

        evidence.Status = "failed";
        RecordFailure(
            evidence,
            cancellationToken.IsCancellationRequested
                ? "Inline quarantine was cancelled before ownership was proven."
                : "Inline quarantine reached its deadline before ownership was proven.",
            cancellationToken.IsCancellationRequested
                ? new OperationCanceledException(cancellationToken)
                : new TimeoutException("Inline quarantine reached its deadline."));
        try
        {
            WriteEvidence(evidence);
        }
        catch (Exception ex)
        {
            RecordFailure(evidence, "Unable to persist final inline quarantine evidence.", ex);
        }

        return false;
    }

    private static async Task<FsHostSupervisorEvidence> KeepCohortOwnershipUntilProvenAsync(
        FsHostSupervisorEvidence? evidence,
        SafeNativeHandle jobHandle,
        SafeNativeHandle processHandle,
        FileStream? manifestLease,
        SafeNativeHandle? failedChildHandle,
        QuarantineOptions? recoveryOptions,
        string reason)
    {
        var recovered = recoveryOptions is null;
        var entered = false;
        var leaseOwnedHere = manifestLease is null;
        while (true)
        {
            try
            {
                if (!recovered)
                {
                    var failure = evidence?.Failure;
                    var details = evidence?.FailureDetails;
                    evidence = CreateQuarantineRecoveryEvidence(recoveryOptions!, evidence?.EvidenceRevision ?? 0);
                    evidence.Failure = failure ?? "The durable quarantine owner failed.";
                    evidence.FailureDetails = details;
                    recovered = true;
                }
                var authority = evidence!.ContainerManifestAuthority ??
                    throw new InvalidOperationException("Cohort enforcement authority is unavailable.");
                manifestLease ??= new FileStream(authority.ManifestPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (!entered)
                {
                    evidence.CohortKeeperActive = true;
                    evidence.CohortKeeperPid = Environment.ProcessId;
                    evidence.CohortKeeperReason = reason;
                    evidence.CohortKeeperStartedUtc = DateTime.UtcNow;
                    evidence.CompletedUtc = null;
                    evidence.QuarantineRequired = true;
                    evidence.Status = "quarantined";
                    evidence.SupervisorExitCode = 1;
                    entered = true;
                    TestHooks.Value?.CohortKeeperEntered?.Invoke(evidence, jobHandle, processHandle, manifestLease, failedChildHandle);
                }

                evidence.FailedQuarantineChildAbsent = failedChildHandle is null ||
                    WaitForObject(failedChildHandle, 0, WaitKindQuarantine, "WaitForSingleObject(retained failed quarantine child)") == WaitObject0;
                evidence.OriginalHostIdentityAbsent = false;
                evidence.MountAbsenceProven = false;
                evidence.JobMembersAbsent = false;
                ForceTerminateHost(evidence, jobHandle, processHandle, 250);
                if (evidence.HostPid is not null && evidence.HostIdentityCaptured && evidence.HostCreationTimeFileTime is not null)
                    evidence.OriginalHostIdentityAbsent = WaitForOriginalProcessAbsence(
                        checked((uint)evidence.HostPid.Value), evidence.HostCreationTimeFileTime.Value,
                        processHandle, 250, evidence);
                var mountProof = WaitForEvidenceMountAbsence(evidence, 0);
                evidence.MountAbsentFromDirectProbe = mountProof.DirectAbsent;
                evidence.MountAbsentFromStatus = mountProof.StatusAbsent;
                evidence.MountDirectProbeResult = mountProof.DirectResult;
                evidence.MountStatusProbeResult = mountProof.StatusResult;
                evidence.MountAbsenceProven = IsMountSettlementProven(evidence, mountProof);
                if (IsOwnershipProven(evidence, jobHandle) && evidence.FailedQuarantineChildAbsent)
                {
                    evidence.CohortKeeperActive = false;
                    evidence.CohortKeeperCompletedUtc = DateTime.UtcNow;
                    evidence.CompletedUtc = evidence.CohortKeeperCompletedUtc;
                    evidence.Status = "failed";
                    if (leaseOwnedHere) manifestLease.Dispose();
                    return evidence;
                }
            }
            catch (Exception ex)
            {
                if (evidence is not null)
                {
                    evidence.OriginalHostIdentityAbsent = false;
                    evidence.MountAbsenceProven = false;
                    evidence.JobMembersAbsent = false;
                    RecordFailure(evidence, "Cohort enforcement proof remains unavailable; ownership is retained.", ex);
                }
            }

            if (evidence is not null)
            {
                try
                {
                    // An unacknowledged child may still write the main evidence.
                    if (failedChildHandle is not null && !evidence.FailedQuarantineChildAbsent)
                        WriteAtomicJson(evidence.EvidenceFile + ".retained-owner.json", evidence);
                    else WriteEvidence(evidence);
                }
                catch (Exception ex) { RecordFailure(evidence, "Unable to persist retained cohort ownership.", ex); }
            }
            // This awaited state keeps the CLI, original handles and manifest
            // lease rooted. Caller cancellation cannot authorize their release.
            await Task.Delay(250).ConfigureAwait(false);
            GC.KeepAlive(jobHandle);
            GC.KeepAlive(processHandle);
            GC.KeepAlive(manifestLease);
            GC.KeepAlive(failedChildHandle);
        }
    }

    internal static async Task<int> RunQuarantineAsync(QuarantineOptions options)
    {
        SafeNativeHandle? jobHandle = null;
        SafeNativeHandle? processHandle = null;
        FileStream? manifestLease = null;
        var ownershipProven = false;
        var terminalEvidencePublished = false;
        var evidenceAuthenticated = false;
        FsHostSupervisorEvidence? evidence = null;
        try
        {
            jobHandle = new SafeNativeHandle(options.JobHandle);
            processHandle = new SafeNativeHandle(options.ProcessHandle);
            evidence = JsonSerializer.Deserialize<FsHostSupervisorEvidence>(
                File.ReadAllText(options.EvidenceFile),
                JsonOptions) ?? throw new InvalidOperationException("Quarantine evidence could not be loaded.");
            if (!string.Equals(evidence.OwnershipHandoffToken, options.HandoffToken, StringComparison.Ordinal) ||
                !string.Equals(evidence.OwnershipHandoffState, "offered", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The quarantine ownership handoff token or state is invalid.");
            }
            ValidateCurrentSupervisorIdentity(evidence);
            RestoreCohortHandoff(evidence, options);
            if (evidence.ContainerManifestAuthority is { } authority)
            {
                manifestLease = new FileStream(authority.ManifestPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                ValidateManifestAuthority(evidence);
            }
            ValidateInheritedHandle(jobHandle, "GetHandleInformation(quarantine job)");
            ValidateInheritedHandle(processHandle, "GetHandleInformation(quarantine process)");
            _ = WaitForObject(
                processHandle,
                0,
                WaitKindProcess,
                "WaitForSingleObject(quarantine process)");
            evidence.QuarantineExcludedHandleInherited = options.TestExcludedHandle is not null &&
                NativeMethods.GetHandleInformation(options.TestExcludedHandle.Value, out _);
            if (evidence.QuarantineExcludedHandleInherited)
            {
                throw new InvalidOperationException("The quarantine child inherited an unrelated handle.");
            }
            evidence.QuarantineOwnerStarted = true;
            evidence.QuarantineOwnerPid = Environment.ProcessId;
            evidence.QuarantineStartedUtc ??= DateTime.UtcNow;
            evidence.QuarantineOwnerKind = "managed-cli";
            evidence.QuarantineOwnerHandleInheritanceProven = true;
            evidence.EvidenceWriterPid = Environment.ProcessId;
            evidence.EvidenceWriterRole = "quarantine";
            evidence.OwnershipHandoffState = "accepted";
            evidenceAuthenticated = true;
            WriteEvidence(evidence);
            WriteAtomicText(options.ReadyFile, options.ReadyToken);

            while (true)
            {
                // Parent evidence is diagnostic input only. Re-prove the
                // original identity from the inherited process handle plus
                // current system enumeration before releasing the Job. This
                // prevents a stale or contradictory parent bit from becoming
                // an ownership-release decision.
                try
                {
                    evidence.OriginalHostIdentityAbsent = WaitForOriginalProcessAbsence(
                        checked((uint)options.HostPid),
                        options.HostCreationTimeFileTime,
                        processHandle,
                        Math.Min(1000, options.ProcessAbsenceTimeoutMs),
                        evidence);
                }
                catch (Exception ex)
                {
                    evidence.OriginalHostIdentityAbsent = false;
                    RecordFailure(evidence, "Quarantine could not prove FsHost PID absence.", ex);
                }

                try
                {
                    var mountProof = WaitForEvidenceMountAbsence(
                        evidence,
                        Math.Min(1000, options.ProcessAbsenceTimeoutMs));
                    evidence.MountAbsentFromDirectProbe = mountProof.DirectAbsent;
                    evidence.MountAbsentFromStatus = mountProof.StatusAbsent;
                    evidence.MountDirectProbeResult = mountProof.DirectResult;
                    evidence.MountStatusProbeResult = mountProof.StatusResult;
                    evidence.MountAbsenceProven = IsMountSettlementProven(evidence, mountProof);
                }
                catch (Exception ex)
                {
                    RecordFailure(evidence, "Quarantine could not prove mount absence.", ex);
                }

                if (IsOwnershipProven(evidence, jobHandle))
                {
                    ownershipProven = true;
                    processHandle.Dispose();
                    processHandle = null;
                    jobHandle.Dispose();
                    jobHandle = null;
                    evidence.JobClosed = true;
                    evidence.QuarantineCompletedUtc = DateTime.UtcNow;
                    evidence.OwnershipHandoffState = "completed";
                    evidence.Status = evidence.MountAbsenceProven ? "stopped" : "failed";
                    if (evidence.MountAbsenceProven && IsTransientOwnershipProofFailure(evidence.Failure))
                    {
                        evidence.Failure = null;
                        evidence.FailureDetails = null;
                    }
                    else if (!evidence.MountAbsenceProven)
                    {
                        evidence.Failure ??= evidence.MountStatusProbeResult == "ready"
                            ? "Direct mount absence was proven, but the status file still reports the mount as ready."
                            : "Direct mount absence was proven, but mount status could not be validated.";
                    }
                    evidence.SupervisorExitCode ??= 1;
                    WriteEvidence(evidence);
                    terminalEvidencePublished = true;
                    return evidence.MountAbsenceProven &&
                        evidence.Failure is null &&
                        terminalEvidencePublished
                        ? 0
                        : 1;
                }

                var quarantineEvidence = evidence;
                if (!options.JobAssigned)
                {
                    TerminateExactProcess(quarantineEvidence, processHandle);
                }
                else if (!NativeMethods.TerminateJobObject(jobHandle, 0xE0010001))
                {
                    quarantineEvidence.ForcedJobTermination = true;
                    quarantineEvidence.ForcedJobTerminationResult =
                        $"failed-win32-{Marshal.GetLastWin32Error()}";
                    TerminateExactProcess(quarantineEvidence, processHandle);
                }

                WriteEvidence(quarantineEvidence);
                await Task.Delay(250).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            try
            {
                try
                {
                    evidence ??= JsonSerializer.Deserialize<FsHostSupervisorEvidence>(
                        File.ReadAllText(options.EvidenceFile),
                        JsonOptions);
                }
                catch (Exception readException) when (
                    readException is IOException or UnauthorizedAccessException or JsonException)
                {
                }

                if (!evidenceAuthenticated &&
                    (evidence is null || !HasCurrentSupervisorIdentity(evidence)) &&
                    processHandle is not null &&
                    !processHandle.IsInvalid)
                {
                    evidence = CreateQuarantineRecoveryEvidence(
                        options,
                        evidence?.EvidenceRevision ?? 0);
                }

                if (evidence is not null)
                {
                    RecordFailure(evidence, "The durable quarantine owner failed.", ex);
                    try
                    {
                        WriteEvidence(evidence);
                        terminalEvidencePublished = true;
                    }
                    catch
                    {
                    }

                    if (!ownershipProven &&
                        jobHandle is not null &&
                        processHandle is not null &&
                        !jobHandle.IsInvalid &&
                        !processHandle.IsInvalid &&
                        evidence.HostIdentityCaptured)
                    {
                        ownershipProven = RunInlineQuarantineUntilProven(
                            evidence,
                            options.ProcessAbsenceTimeoutMs,
                            jobHandle,
                            processHandle,
                            CancellationToken.None);
                    }
                }
            }
            catch { }
            return ownershipProven &&
                terminalEvidencePublished &&
                evidence?.Failure is null
                ? 0
                : 1;
        }
        finally
        {
            if (!ownershipProven && jobHandle is not null && processHandle is not null &&
                (options.MountPoint.StartsWith(CohortHandoffPrefix, StringComparison.Ordinal) || evidence?.ContainerManifestAuthority is not null))
            {
                // Publication failure cannot erase already validated lineage.
                // The keeper still refreshes every ownership-release proof.
                evidence = await KeepCohortOwnershipUntilProvenAsync(evidence, jobHandle, processHandle,
                    manifestLease, null, evidenceAuthenticated ? null : options, "quarantine-owner-recovery").ConfigureAwait(false);
                ownershipProven = true;
            }
            if (ownershipProven)
            {
                processHandle?.Dispose();
                jobHandle?.Dispose();
                manifestLease?.Dispose();
                if (evidence?.CohortKeeperCompletedUtc is not null)
                {
                    evidence.JobClosed = true;
                    evidence.QuarantineCompletedUtc = DateTime.UtcNow;
                    evidence.OwnershipHandoffState = "completed";
                    try { WriteEvidence(evidence); }
                    catch (Exception ex) { RecordFailure(evidence, "Unable to persist recovered cohort terminal evidence.", ex); }
                }
            }
        }
    }

    private static bool IsTransientOwnershipProofFailure(string? failure)
        => failure is
            "The original launched FsHost identity remained present or could not be proven absent." or
            "The FsHost mount was not proven absent by a direct Windows mount-point probe." or
            "FsHost ownership could not be proven; handles remain quarantined.";

    private static void ValidateOptions(
        FsHostSupervisorOptions options,
        string hostPath,
        string workingDirectory,
        FsHostSupervisorEvidence evidence)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("FsHost supervision requires Windows.");
        if (!Directory.Exists(workingDirectory)) throw new DirectoryNotFoundException(workingDirectory);
        if (!File.Exists(evidence.LifetimeFile))
        {
            throw new InvalidOperationException("The lifetime file must exist before the supervised host is launched.");
        }

        if (evidence.ContainerManifestAuthority is not null)
        {
            if (evidence.MountPoint is not null || evidence.StatusFile is null)
                throw new InvalidOperationException("Manifest cohort requires native status and no scalar mount point.");
        }
        else if (string.IsNullOrWhiteSpace(evidence.MountPoint))
        {
            throw new InvalidOperationException(
                "The supervised host must provide an exact drive-letter or directory mount point for direct absence proof.");
        }

        if (options.GracefulTimeoutMs < 50 || options.ProcessAbsenceTimeoutMs < 250 || options.OwnerPollIntervalMs < 25)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "Supervisor timeouts are below the safe minimum.");
        }

        if (evidence.StartupGateFile is not null && string.IsNullOrEmpty(options.StartupGateToken))
        {
            throw new InvalidOperationException("A startup-gate file requires a startup-gate token.");
        }
    }

    private static void WriteLaunchRecord(FsHostSupervisorEvidence evidence)
    {
        if (evidence.LaunchRecordPath is null)
        {
            throw new InvalidOperationException("The supervisor launch-record path is required for lifecycle evidence.");
        }

        WriteAtomicJson(evidence.LaunchRecordPath, evidence);
    }

    private static void WriteEvidence(FsHostSupervisorEvidence evidence)
    {
        if (File.Exists(evidence.EvidenceFile))
        {
            try
            {
                var current = JsonSerializer.Deserialize<FsHostSupervisorEvidence>(
                    File.ReadAllText(evidence.EvidenceFile),
                    JsonOptions);
                if (current is not null &&
                    (current.EvidenceRevision > evidence.EvidenceRevision ||
                     (!string.Equals(current.EvidenceWriterRole, evidence.EvidenceWriterRole, StringComparison.Ordinal) &&
                      string.Equals(current.EvidenceWriterRole, "quarantine", StringComparison.Ordinal))))
                {
                    throw new InvalidOperationException(
                        $"Evidence writer lease belongs to {current.EvidenceWriterRole} PID {current.EvidenceWriterPid}." );
                }
            }
            catch (JsonException)
            {
                // Atomic replacement can briefly expose no readable prior file;
                // the next revision remains authoritative.
            }
        }

        evidence.EvidenceWriterPid = Environment.ProcessId;
        evidence.EvidenceRevision++;
        TestHooks.Value?.BeforeEvidencePublication?.Invoke(evidence);
        WriteAtomicJson(evidence.EvidenceFile, evidence);
    }

    private static bool IsSuccessfulTerminalEvidence(FsHostSupervisorEvidence evidence)
        => evidence.Failure is null &&
            evidence.SupervisionProven &&
            evidence.OriginalHostIdentityAbsent &&
            evidence.MountAbsenceProven &&
            (!evidence.StaleReadyStatusDischarged || evidence.JobMembersAbsent) &&
            (evidence.ContainerManifestAuthority is null || evidence.JobMembersAbsent) &&
            evidence.JobClosed;

    internal static FsHostSupervisorIdentityPaths ResolveSupervisorIdentityForTests(
        string supervisorExecutable)
        => ResolveSupervisorIdentity(supervisorExecutable);

    internal static FsHostSupervisorEvidence CreateQuarantineRecoveryEvidenceForTests(
        QuarantineOptions options,
        string supervisorExecutable)
        => CreateQuarantineRecoveryEvidence(options, supervisorExecutable);

    private static FsHostSupervisorEvidence CreateQuarantineRecoveryEvidence(QuarantineOptions options)
        => CreateQuarantineRecoveryEvidence(options, evidenceRevision: 0);

    private static FsHostSupervisorEvidence CreateQuarantineRecoveryEvidence(
        QuarantineOptions options,
        long evidenceRevision)
        => CreateQuarantineRecoveryEvidence(
            options,
            ResolveSupervisorExecutablePath(),
            evidenceRevision);

    private static FsHostSupervisorEvidence CreateQuarantineRecoveryEvidence(
        QuarantineOptions options,
        string supervisorExecutable)
        => CreateQuarantineRecoveryEvidence(options, supervisorExecutable, evidenceRevision: 0);

    private static FsHostSupervisorEvidence CreateQuarantineRecoveryEvidence(
        QuarantineOptions options,
        string supervisorExecutable,
        long evidenceRevision)
    {
        var identity = ResolveSupervisorIdentity(supervisorExecutable);
        var cohort = ReadCohortHandoff(options);
        return new FsHostSupervisorEvidence
        {
            SupervisorPid = Environment.ProcessId,
            SupervisorExecutable = identity.ExecutablePath,
            SupervisorSha256 = ComputeSha256(identity.ExecutablePath),
            SupervisorPayloadPath = identity.PayloadPath,
            SupervisorPayloadSha256 = ComputeSha256(identity.PayloadPath),
            OwnerPid = 0,
            HostPid = options.HostPid,
            HostCreationTimeFileTime = options.HostCreationTimeFileTime,
            HostIdentityCaptured = options.HostCreationTimeFileTime > 0,
            HostIdentityState = "unknown",
            MountPoint = cohort is null ? options.MountPoint : null,
            HostArguments = cohort?.HostArguments ?? Array.Empty<string>(),
            ContainerManifestAuthority = cohort?.Authority,
            StatusFile = options.StatusFile,
            EvidenceFile = Path.GetFullPath(options.EvidenceFile),
            StartedUtc = DateTime.UtcNow,
            JobCreated = true,
            JobAssigned = options.JobAssigned,
            Resumed = true,
            SupervisionProven = options.JobAssigned,
            EvidenceWriterPid = Environment.ProcessId,
            EvidenceWriterRole = "quarantine",
            EvidenceRevision = evidenceRevision,
        };
    }

    private static string ResolveSupervisorExecutablePath()
    {
        var processPath = SupervisorExecutablePathOverride.Value ?? Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath) || !File.Exists(processPath))
        {
            throw new InvalidOperationException("The supervisor executable path is unavailable.");
        }
        return ResolveSupervisorIdentity(processPath).ExecutablePath;
    }

    private static string ResolveSupervisorPayloadPath(string supervisorExecutable)
        => ResolveSupervisorIdentity(supervisorExecutable).PayloadPath;

    private static bool HasCurrentSupervisorIdentity(FsHostSupervisorEvidence evidence)
    {
        try
        {
            ValidateCurrentSupervisorIdentity(evidence);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void ValidateCurrentSupervisorIdentity(FsHostSupervisorEvidence evidence)
    {
        if (string.IsNullOrWhiteSpace(evidence.SupervisorExecutable) ||
            string.IsNullOrWhiteSpace(evidence.SupervisorSha256) ||
            string.IsNullOrWhiteSpace(evidence.SupervisorPayloadPath) ||
            string.IsNullOrWhiteSpace(evidence.SupervisorPayloadSha256))
        {
            throw new InvalidOperationException("The quarantine supervisor identity is incomplete.");
        }

        var current = ResolveSupervisorIdentity(ResolveSupervisorExecutablePath());
        if (!string.Equals(
                Path.GetFullPath(evidence.SupervisorExecutable),
                current.ExecutablePath,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Path.GetFullPath(evidence.SupervisorPayloadPath),
                current.PayloadPath,
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                evidence.SupervisorSha256,
                ComputeSha256(current.ExecutablePath),
                StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                evidence.SupervisorPayloadSha256,
                ComputeSha256(current.PayloadPath),
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The quarantine supervisor identity does not match the current CLI payload.");
        }
    }

    private static FsHostSupervisorIdentityPaths ResolveSupervisorIdentity(string supervisorExecutable)
    {
        var executablePath = Path.GetFullPath(supervisorExecutable);
        if (!string.Equals(
                Path.GetFileName(executablePath),
                "ApfsAccess.Cli.exe",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"The supervisor executable must be the exact ApfsAccess.Cli.exe apphost: {executablePath}");
        }
        if (!File.Exists(executablePath))
        {
            throw new InvalidOperationException($"The supervisor executable does not exist: {executablePath}");
        }

        var payloadCandidate = Path.Combine(
            Path.GetDirectoryName(executablePath) ?? string.Empty,
            "ApfsAccess.Cli.dll");
        var payloadPath = File.Exists(payloadCandidate)
            ? Path.GetFullPath(payloadCandidate)
            : executablePath;
        return new FsHostSupervisorIdentityPaths(executablePath, payloadPath);
    }

    private static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void WriteAtomicJson(string path, object value)
    {
        PrepareEvidencePath(path);
        var temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(
                temporaryPath,
                JsonSerializer.Serialize(value, JsonOptions) + Environment.NewLine,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            try { File.Delete(temporaryPath); } catch { }
        }
    }

    private static void WriteAtomicText(string path, string value)
    {
        PrepareEvidencePath(path);
        var temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporaryPath, value, new UTF8Encoding(false));
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            try { File.Delete(temporaryPath); } catch { }
        }
    }

    private static void PrepareEvidencePath(string path)
    {
        var parent = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(parent)) Directory.CreateDirectory(parent);
    }

    private static string? NormalizeOptionalPath(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : Path.GetFullPath(value);

    private static string? NormalizeMountPoint(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (IsDriveMountPoint(value)) return value[..2].ToUpperInvariant();
        return Path.GetFullPath(value);
    }

    private static bool IsDriveMountPoint(string value)
        => value.Length is 2 or 3 &&
            char.IsLetter(value[0]) &&
            value[1] == ':' &&
            (value.Length == 2 || value[2] is '\\' or '/');

    private static int ParsePid(string value, string label)
        => int.TryParse(value, out var pid) && pid > 0
            ? pid
            : throw new ArgumentException($"Invalid {label}: '{value}'.", nameof(value));

    private static Win32Exception LastWin32Error(string operation)
    {
        var error = Marshal.GetLastWin32Error();
        return new Win32Exception(error, $"{operation} failed with Win32 error {error}.");
    }

    private static string QuoteWindowsArgument(string value)
    {
        if (value.Length == 0) return "\"\"";

        var builder = new StringBuilder(value.Length + 2);
        builder.Append('"');
        var backslashes = 0;
        foreach (var character in value)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }

            if (character == '"')
            {
                builder.Append('\\', backslashes * 2 + 1);
                builder.Append('"');
                backslashes = 0;
                continue;
            }

            builder.Append('\\', backslashes);
            builder.Append(character);
            backslashes = 0;
        }

        builder.Append('\\', backslashes * 2);
        builder.Append('"');
        return builder.ToString();
    }

    private sealed record ChildLaunch(
        SafeNativeHandle ProcessHandle,
        SafeNativeHandle ThreadHandle,
        uint ProcessId);

    private sealed class SafeNativeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeNativeHandle()
            : base(ownsHandle: true)
        {
        }

        public SafeNativeHandle(nint handle)
            : this()
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle() => NativeMethods.CloseHandle(handle);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public uint Cb;
        public string? Reserved;
        public string? Desktop;
        public string? Title;
        public uint X;
        public uint Y;
        public uint XSize;
        public uint YSize;
        public uint XCountChars;
        public uint YCountChars;
        public uint FillAttribute;
        public uint Flags;
        public ushort ShowWindow;
        public ushort Reserved2;
        public nint Reserved3;
        public nint StdInput;
        public nint StdOutput;
        public nint StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public nint AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public nint ProcessHandle;
        public nint ThreadHandle;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobBasicAccountingInformation
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public nuint ProcessMemoryLimit;
        public nuint JobMemoryLimit;
        public nuint PeakProcessMemoryUsed;
        public nuint PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize;
        public nuint MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nuint Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint LowDateTime;
        public uint HighDateTime;

        public long ToInt64()
            => ((long)HighDateTime << 32) | LowDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StatusFileInformation
    {
        public uint Attributes;
        public FileTime Creation, LastAccess, LastWrite;
        public uint VolumeSerial, SizeHigh, SizeLow, Links, FileIndexHigh, FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public nuint DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int BasePriority;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExecutableFile;
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryInformationJobObject(SafeNativeHandle job, uint informationClass,
            out JobBasicAccountingInformation information, uint length, out uint returnedLength);

        [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessW(
            string applicationName,
            [In, Out] StringBuilder commandLine,
            nint processAttributes,
            nint threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags,
            nint environment,
            string currentDirectory,
            ref StartupInfo startupInfo,
            out ProcessInformation processInformation);

        [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessW(
            string applicationName,
            [In, Out] StringBuilder commandLine,
            nint processAttributes,
            nint threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags,
            nint environment,
            string currentDirectory,
            ref StartupInfoEx startupInfo,
            out ProcessInformation processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeProcThreadAttributeList(
            nint attributeList,
            int attributeCount,
            uint flags,
            ref nuint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UpdateProcThreadAttribute(
            nint attributeList,
            uint flags,
            nuint attribute,
            nint value,
            nuint size,
            nint previousValue,
            nint returnSize);

        [DllImport("kernel32.dll")]
        public static extern void DeleteProcThreadAttributeList(nint attributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern nint CreateJobObjectW(nint jobAttributes, string? name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetInformationJobObject(
            SafeNativeHandle job,
            uint informationClass,
            ref JobObjectExtendedLimitInformation limits,
            uint limitsLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AssignProcessToJobObject(SafeNativeHandle job, SafeNativeHandle process);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(SafeNativeHandle thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TerminateJobObject(SafeNativeHandle job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TerminateProcess(SafeNativeHandle process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateHandle(
            nint sourceProcessHandle,
            nint sourceHandle,
            nint targetProcessHandle,
            out nint targetHandle,
            uint desiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            uint options);

        [DllImport("kernel32.dll")]
        public static extern nint GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetHandleInformation(
            SafeNativeHandle handle,
            out uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetHandleInformation(nint handle, out uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(SafeNativeHandle handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetExitCodeProcess(SafeNativeHandle process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetProcessTimes(
            SafeNativeHandle process,
            out FileTime creationTime,
            out FileTime exitTime,
            out FileTime kernelTime,
            out FileTime userTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern nint OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint QueryDosDeviceW(
            string deviceName,
            [Out] StringBuilder targetPath,
            int maxLength);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetFileAttributesW(string fileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern nint CreateToolhelp32Snapshot(uint flags, uint processId);

        [DllImport("kernel32.dll", EntryPoint = "Process32FirstW", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Process32FirstW(SafeNativeHandle snapshot, ref ProcessEntry32 entry);

        [DllImport("kernel32.dll", EntryPoint = "Process32NextW", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Process32NextW(SafeNativeHandle snapshot, ref ProcessEntry32 entry);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(nint handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetFileInformationByHandle(SafeFileHandle handle, out StatusFileInformation information);
    }

    private sealed class TestHookScope(FsHostSupervisorTestHooks? previous) : IDisposable
    {
        public void Dispose() => TestHooks.Value = previous;
    }

    private sealed class SupervisorExecutablePathScope(string? previous) : IDisposable
    {
        public void Dispose() => SupervisorExecutablePathOverride.Value = previous;
    }
}

internal static class FsHostSupervisorCommand
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };

    public static async Task<int> RunAsync(string[] args)
    {
        try
        {
            var options = Parse(args);
            var result = await FsHostSupervisor.RunAsync(options).ConfigureAwait(false);
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                command = "supervise-fshost",
                success = result.Success,
                exitCode = result.ExitCode,
                evidence = result.Evidence,
            }, JsonOptions));
            return result.ExitCode;
        }
        catch (Exception ex)
        {
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                command = "supervise-fshost",
                success = false,
                exitCode = 2,
                error = ex.Message,
            }, JsonOptions));
            return 2;
        }
    }

    public static async Task<int> RunQuarantineAsync(string[] args)
    {
        try
        {
            var options = ParseQuarantine(args);
            return await FsHostSupervisor.RunQuarantineAsync(options).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FsHost quarantine owner failed: {ex.Message}");
            return 2;
        }
    }

    private static QuarantineOptions ParseQuarantine(string[] args)
    {
        string? jobHandle = null;
        string? processHandle = null;
        string? hostPid = null;
        string? creationTime = null;
        string? mountPoint = null;
        string? statusFile = null;
        string? evidenceFile = null;
        string? readyFile = null;
        string? readyToken = null;
        string? handoffToken = null;
        string? testExcludedHandle = null;
        var jobAssigned = false;
        var timeoutMs = 15_000;

        for (var index = 0; index < args.Length; index++)
        {
            var token = args[index];
            string Value()
            {
                if (++index >= args.Length) throw new ArgumentException($"{token} requires a value.");
                return args[index];
            }

            switch (token.ToLowerInvariant())
            {
                case "--job-handle": jobHandle = Value(); break;
                case "--process-handle": processHandle = Value(); break;
                case "--host-pid": hostPid = Value(); break;
                case "--host-creation-time": creationTime = Value(); break;
                case "--job-assigned":
                    jobAssigned = bool.TryParse(Value(), out var parsed) && parsed;
                    break;
                case "--mount-point": mountPoint = Value(); break;
                case "--status-file": statusFile = Value(); break;
                case "--evidence-file": evidenceFile = Value(); break;
                case "--ready-file": readyFile = Value(); break;
                case "--ready-token": readyToken = Value(); break;
                case "--handoff-token": handoffToken = Value(); break;
                case "--test-excluded-handle": testExcludedHandle = Value(); break;
                case "--process-absence-timeout-ms":
                    timeoutMs = ParseInteger(Value(), token);
                    break;
                default: throw new ArgumentException($"Unknown quarantine option '{token}'.");
            }
        }

        return new QuarantineOptions(
            ParseHandle(jobHandle, "--job-handle"),
            ParseHandle(processHandle, "--process-handle"),
            ParsePositiveInt(hostPid, "--host-pid"),
            ParseLong(creationTime, "--host-creation-time"),
            jobAssigned,
            Require(mountPoint, "--mount-point"),
            string.IsNullOrWhiteSpace(statusFile) ? null : statusFile,
            Require(evidenceFile, "--evidence-file"),
            Require(readyFile, "--ready-file"),
            Require(readyToken, "--ready-token"),
            Math.Max(250, timeoutMs),
            Require(handoffToken, "--handoff-token"),
            ParseOptionalHandle(testExcludedHandle, "--test-excluded-handle"));
    }

    private static nint ParseHandle(string? value, string option)
        => long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) && parsed > 0
            ? (nint)parsed
            : throw new ArgumentException($"{option} requires a valid handle.");

    private static nint? ParseOptionalHandle(string? value, string option)
        => string.IsNullOrWhiteSpace(value) ? null : ParseHandle(value, option);

    private static int ParsePositiveInt(string? value, string option)
        => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) && parsed > 0
            ? parsed
            : throw new ArgumentException($"{option} requires a positive integer.");

    private static long ParseLong(string? value, string option)
        => long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) && parsed > 0
            ? parsed
            : throw new ArgumentException($"{option} requires a positive integer.");

    private static FsHostSupervisorOptions Parse(string[] args)
    {
        string? host = null;
        string? ownerPid = null;
        string? lifetimeFile = null;
        string? launchRecord = null;
        string? evidenceFile = null;
        string? workingDirectory = null;
        string? startupGateFile = null;
        string? startupGateToken = null;
        string? mountPoint = null;
        string? statusFile = null;
        var hostArguments = new List<string>();
        var gracefulTimeoutMs = 30_000;
        var processAbsenceTimeoutMs = 15_000;
        var ownerPollIntervalMs = 100;
        var credentialInput = false;

        for (var index = 0; index < args.Length; index++)
        {
            var token = args[index];
            string Value()
            {
                if (++index >= args.Length) throw new ArgumentException($"{token} requires a value.");
                return args[index];
            }

            switch (token.ToLowerInvariant())
            {
                case "--host": host = Value(); break;
                case "--host-arg": hostArguments.Add(Value()); break;
                case "--owner-pid": ownerPid = Value(); break;
                case "--lifetime-file": lifetimeFile = Value(); break;
                case "--launch-record": launchRecord = Value(); break;
                case "--evidence-file": evidenceFile = Value(); break;
                case "--working-directory": workingDirectory = Value(); break;
                case "--startup-gate-file": startupGateFile = Value(); break;
                case "--startup-gate-token": startupGateToken = Value(); break;
                case "--mount-point": mountPoint = Value(); break;
                case "--status-file": statusFile = Value(); break;
                case "--graceful-timeout-ms": gracefulTimeoutMs = ParseInteger(Value(), token); break;
                case "--process-absence-timeout-ms": processAbsenceTimeoutMs = ParseInteger(Value(), token); break;
                case "--owner-poll-interval-ms": ownerPollIntervalMs = ParseInteger(Value(), token); break;
                case "--credential-input":
                    if (credentialInput) throw new ArgumentException("Duplicate credential-input option.");
                    credentialInput = true;
                    break;
                default: throw new ArgumentException($"Unknown supervisor option '{token}'.");
            }
        }

        return new FsHostSupervisorOptions(
            Require(host, "--host"),
            hostArguments,
            Require(ownerPid, "--owner-pid"),
            Require(lifetimeFile, "--lifetime-file"),
            Require(launchRecord, "--launch-record"),
            Require(evidenceFile, "--evidence-file"),
            workingDirectory,
            startupGateFile,
            startupGateToken,
            mountPoint,
            statusFile,
            gracefulTimeoutMs,
            processAbsenceTimeoutMs,
            ownerPollIntervalMs,
            credentialInput);
    }

    private static int ParseInteger(string value, string option)
        => int.TryParse(value, out var parsed)
            ? parsed
            : throw new ArgumentException($"{option} requires an integer.");

    private static string Require(string? value, string option)
        => string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException($"{option} requires a value.")
            : value;
}
