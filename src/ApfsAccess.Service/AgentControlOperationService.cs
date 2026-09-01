using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service;

internal sealed record AgentControlOperationStoreLimits(
    TimeSpan TerminalRetention,
    int MaximumRecordCount,
    long MaximumRecordBytes)
{
    internal static AgentControlOperationStoreLimits Default { get; } = new(
        TimeSpan.FromDays(30),
        MaximumRecordCount: 256,
        MaximumRecordBytes: 256 * 1024);

    internal void Validate()
    {
        if (TerminalRetention < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(TerminalRetention));
        if (MaximumRecordCount <= 0) throw new ArgumentOutOfRangeException(nameof(MaximumRecordCount));
        if (MaximumRecordBytes <= 0) throw new ArgumentOutOfRangeException(nameof(MaximumRecordBytes));
    }
}

internal sealed class AgentControlOperationService
{
    private const uint MoveFileReplaceExisting = 0x1;
    private const uint MoveFileWriteThrough = 0x8;
    private static readonly TimeSpan TemporaryFileRetention = TimeSpan.FromHours(1);
    private static readonly TimeSpan MaximumOperationLifetime = TimeSpan.FromMinutes(5);
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true };
    private readonly Func<ControlOperationRequestPayload, CancellationToken, Task<OperationResultPayload>> _executor;
    private readonly string _root;
    private readonly AgentOperationCoordinator<OperationResultPayload> _coordinator;
    private readonly TimeProvider _clock;
    private readonly AgentControlOperationStoreLimits _storeLimits;
    private readonly Action<OperationResultPayload>? _beforeEvidenceCommit;
    private readonly Action<OperationResultPayload>? _afterUnreconciledEvidenceCommit;
    private readonly object _admissionGate = new();
    private readonly Dictionary<string, NormalizedRequest> _operationContexts = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ReconciliationOwnership> _reconciliations = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _shutdownCts = new();
    private Task? _shutdownCancellationTask;
    private bool _stopping;

    internal AgentControlOperationService(
        Func<ControlOperationRequestPayload, CancellationToken, Task<OperationResultPayload>> executor,
        string evidenceRootPath,
        TimeProvider? timeProvider = null,
        AgentControlOperationStoreLimits? storeLimits = null,
        Action<OperationResultPayload>? beforeEvidenceCommit = null,
        Action<OperationResultPayload>? afterUnreconciledEvidenceCommit = null)
    {
        ArgumentNullException.ThrowIfNull(executor);
        ArgumentException.ThrowIfNullOrWhiteSpace(evidenceRootPath);
        _executor = executor;
        _root = Path.GetFullPath(evidenceRootPath);
        Directory.CreateDirectory(_root);
        _clock = timeProvider ?? TimeProvider.System;
        _storeLimits = storeLimits ?? AgentControlOperationStoreLimits.Default;
        _storeLimits.Validate();
        _beforeEvidenceCommit = beforeEvidenceCommit;
        _afterUnreconciledEvidenceCommit = afterUnreconciledEvidenceCommit;
        _coordinator = new AgentOperationCoordinator<OperationResultPayload>(TimeSpan.FromHours(1), 1024, _clock);
        CleanupOwnedTemporaryFiles(deleteAll: true);
    }

    public Task<OperationResultPayload> ExecuteOrReplayAsync(ControlOperationRequestPayload request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var normalized = Normalize(request);
        if (normalized.ValidationCode is not null) return Done(Failure(normalized, normalized.ValidationCode, normalized.ValidationDiagnostic!));
        lock (_admissionGate)
        {
            var current = _coordinator.TryGet(normalized.OperationId);
            if (current is not null)
            {
                return StringComparer.Ordinal.Equals(current.NormalizedFingerprint, normalized.Fingerprint)
                    ? AwaitRecordAsync(current, normalized)
                    : Done(Conflict(normalized, current.NormalizedFingerprint));
            }
            if (_reconciliations.TryGetValue(normalized.OperationId, out var reconciliation))
            {
                return StringComparer.Ordinal.Equals(reconciliation.Fingerprint, normalized.Fingerprint)
                    ? Done(ResolveOwnedReconciliation(normalized))
                    : Done(Conflict(normalized, reconciliation.Fingerprint));
            }
            var evidence = ReadEvidence(normalized.OperationId);
            if (evidence.Status == EvidenceStatus.Valid)
            {
                var payload = evidence.Payload!;
                return StringComparer.Ordinal.Equals(payload.Fingerprint, normalized.Fingerprint)
                    ? Done(IsTerminal(payload.State) ? payload : RecoverNonterminal(payload, evidence.Path))
                    : Done(Conflict(normalized, payload.Fingerprint));
            }
            if (evidence.Status == EvidenceStatus.Corrupt) return Done(CorruptResponse(normalized.OperationId, evidence.Diagnostic!, normalized));
            if (_stopping) return Done(Failure(normalized, ApfsOperationCodes.ServiceUnavailable, "The operation service is stopping and is not accepting new work."));
            var path = EvidencePath(normalized.OperationId);
            if (normalized.ExpiresAtUtc <= UtcNow())
            {
                var expired = DeadlineTimeout(
                    normalized,
                    normalized.RequestedAtUtc,
                    "The operation expired before execution was admitted.");
                if (!EnsureAdmissionCapacity(expired, path, out var timeoutCapacityDiagnostic))
                {
                    return Done(Failure(normalized, ApfsOperationCodes.ServiceUnavailable, timeoutCapacityDiagnostic));
                }

                return Done(PersistTerminal(expired, path));
            }

            var accepted = Accepted(normalized);
            if (!EnsureAdmissionCapacity(accepted, path, out var capacityDiagnostic))
            {
                return Done(Failure(normalized, ApfsOperationCodes.ServiceUnavailable, capacityDiagnostic));
            }
            if (!TryPersist(accepted, path, out var durableAccepted, out var acceptanceError))
            {
                return Done(PersistenceFailure(normalized, acceptanceError, "The accepted operation record could not be written."));
            }
            _operationContexts[normalized.OperationId] = normalized;
            var admission = _coordinator.Start(normalized.OperationId, normalized.Fingerprint!, token => ExecuteOperationAsync(normalized, durableAccepted, token), normalized.Command != ApfsControlCommands.Quit);
            if (admission.Outcome == AgentOperationAdmissionOutcome.Started &&
                normalized.Command == ApfsControlCommands.Quit)
            {
                _stopping = true;
            }
            if (admission.Record is not null)
            {
                TrackOperationContext(normalized, admission.Record);
            }
            else
            {
                _operationContexts.Remove(normalized.OperationId);
            }
            if (admission.Outcome == AgentOperationAdmissionOutcome.Rejected)
            {
                return Done(PersistTerminal(Failure(normalized, ApfsOperationCodes.ServiceUnavailable, "The operation service rejected the admitted operation.", durableAccepted.RequestedAtUtc), path));
            }
            if (admission.Outcome == AgentOperationAdmissionOutcome.Conflict) return Done(Conflict(normalized, admission.ConflictFingerprint));
            if (admission.Record is null)
            {
                return Done(PersistTerminal(Failure(normalized, ApfsOperationCodes.OperationFailed, "The operation service did not return an operation record.", durableAccepted.RequestedAtUtc), path));
            }
            return AwaitRecordAsync(admission.Record, normalized);
        }
    }

    public OperationResultPayload? Query(string operationId)
    {
        if (!TryCanonicalId(operationId, out var id)) return null;
        var current = _coordinator.TryGet(id);
        if (current is not null)
        {
            if (current.IsTerminal) return TerminalResponse(current, id);
            var evidence = ReadEvidence(id);
            if (evidence.Status == EvidenceStatus.Valid) return evidence.Payload;
            if (evidence.Status == EvidenceStatus.Corrupt) return CorruptResponse(id, evidence.Diagnostic!);
            return NonterminalFallback(current, id);
        }
        return ResolveDurable(id);
    }

    public OperationResultPayload Cancel(string operationId)
    {
        var attempt = BeginCancellation(operationId);
        if (attempt.Immediate is not null) return attempt.Immediate;
        return attempt.Outcome switch
        {
            AgentOperationCancellationOutcome.AlreadyTerminal => TerminalResponse(attempt.Record!, attempt.Id),
            AgentOperationCancellationOutcome.NotCancellable => CancellationRejected(attempt.Record!, attempt.Id),
            AgentOperationCancellationOutcome.Requested => CancellationPending(attempt.Record!, attempt.Id),
            _ => ResolveDurable(attempt.Id),
        };
    }

    public async Task<OperationResultPayload> CancelAsync(
        string operationId,
        CancellationToken waitCancellationToken)
    {
        var attempt = BeginCancellation(operationId);
        if (attempt.Immediate is not null) return attempt.Immediate;
        if (attempt.Outcome != AgentOperationCancellationOutcome.Requested)
        {
            return attempt.Outcome == AgentOperationCancellationOutcome.AlreadyTerminal
                ? TerminalResponse(attempt.Record!, attempt.Id)
                : CancellationRejected(attempt.Record!, attempt.Id);
        }

        await attempt.Record!.Completion.WaitAsync(waitCancellationToken).ConfigureAwait(false);
        return TerminalResponse(attempt.Record, attempt.Id);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        Task shutdownCancellationTask;
        lock (_admissionGate)
        {
            _stopping = true;
            if (_shutdownCancellationTask is null)
            {
                _shutdownCancellationTask = IgnoreCancellationCallbackExceptionsAsync(
                    _shutdownCts.CancelAsync());
                _coordinator.Shutdown();
            }

            shutdownCancellationTask = _shutdownCancellationTask;
        }
        await shutdownCancellationTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        await _coordinator.ShutdownAsync(cancellationToken).ConfigureAwait(false);

        Task[] reconciliations;
        lock (_admissionGate)
        {
            reconciliations = _reconciliations.Values
                .Select(static ownership => ownership.Completion)
                .ToArray();
        }

        if (reconciliations.Length != 0)
        {
            await Task.WhenAll(reconciliations).WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<OperationResultPayload> AwaitRecordAsync(AgentOperationRecord<OperationResultPayload> record, NormalizedRequest normalized)
    {
        await record.Completion.ConfigureAwait(false);
        var evidence = ReadEvidence(normalized.OperationId);
        if (evidence.Status == EvidenceStatus.Valid &&
            (IsTerminal(evidence.Payload!.State) || IsUnreconciledCompletion(record)))
        {
            return evidence.Payload;
        }
        if (evidence.Status == EvidenceStatus.Corrupt) return CorruptResponse(normalized.OperationId, evidence.Diagnostic!, normalized);
        return TerminalFallback(record, normalized.OperationId);
    }

    private async Task<OperationResultPayload> ExecuteOperationAsync(NormalizedRequest normalized, OperationResultPayload accepted, CancellationToken token)
    {
        var path = EvidencePath(normalized.OperationId);
        var started = AtOrAfter(UtcNow(), accepted.RequestedAtUtc);
        var inProgress = accepted with { State = ApfsOperationStates.InProgress, Code = ApfsOperationCodes.OperationInProgress, Success = false, StartedAtUtc = started, CompletedAtUtc = null, EvidencePath = null, Diagnostic = null };
        if (!TryPersist(inProgress, path, out _, out var inProgressError)) return PersistTerminal(Failure(normalized, ApfsOperationCodes.OperationFailed, Append("The in-progress operation record could not be written.", inProgressError?.Message), started), path);
        if (token.IsCancellationRequested) return PersistTerminal(Cancelled(normalized, started, "The operation was cancelled before execution began."), path);
        var deadlineCts = CreateDeadlineCancellationSource(normalized.ExpiresAtUtc);
        var operationCts = CancellationTokenSource.CreateLinkedTokenSource(token, deadlineCts.Token);
        if (deadlineCts.IsCancellationRequested)
        {
            operationCts.Dispose();
            deadlineCts.Dispose();
            return PersistTerminal(
                DeadlineTimeout(normalized, started, "The operation expired before executor dispatch."),
                path);
        }

        Task<OperationResultPayload> executorTask;
        try
        {
            executorTask = _executor(ToRequest(normalized), operationCts.Token)
                ?? Task.FromException<OperationResultPayload>(new InvalidOperationException("The operation executor returned a null task."));
        }
        catch (Exception exception)
        {
            executorTask = Task.FromException<OperationResultPayload>(exception);
        }

        var deadlineSignal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var shutdownSignal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task firstCompletion;
        using (deadlineCts.Token.Register(
                   static state => ((TaskCompletionSource)state!).TrySetResult(),
                   deadlineSignal))
        using (_shutdownCts.Token.Register(
                   static state => ((TaskCompletionSource)state!).TrySetResult(),
                   shutdownSignal))
        {
            firstCompletion = await Task.WhenAny(
                executorTask,
                deadlineSignal.Task,
                shutdownSignal.Task).ConfigureAwait(false);
        }
        if (ReferenceEquals(firstCompletion, executorTask))
        {
            return await ReconcileExecutorAsync(
                normalized,
                started,
                path,
                executorTask,
                deadlineCts,
                operationCts,
                token).ConfigureAwait(false);
        }

        var deadlineExpired = deadlineCts.IsCancellationRequested && !token.IsCancellationRequested;
        var pending = Unreconciled(
            normalized,
            started,
            deadlineExpired
                ? "The operation reached its deadline while the executor remained active; final truth is pending reconciliation."
                : "Service shutdown or cancellation was requested while the executor remained active; final truth is pending reconciliation.");
        var reconciliationStart = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reconciliationTask = ReconcileAfterPublicationAsync(
            reconciliationStart.Task,
            normalized,
            started,
            path,
            executorTask,
            deadlineCts,
            operationCts,
            token);
        OperationResultPayload durablePending;
        try
        {
            lock (_admissionGate)
            {
                TrackReconciliation(normalized, reconciliationTask);
                if (!TryPersist(pending, path, out durablePending, out var pendingError))
                {
                    durablePending = pending with
                    {
                        EvidencePath = null,
                        Diagnostic = Append(
                            pending.Diagnostic,
                            $"The unreconciled operation evidence could not be written: {pendingError?.Message ?? "unknown persistence error"}"),
                    };
                }
                else
                {
                    _afterUnreconciledEvidenceCommit?.Invoke(durablePending);
                }
            }
        }
        finally
        {
            reconciliationStart.TrySetResult();
        }
        return durablePending;
    }

    private async Task<OperationResultPayload> ReconcileAfterPublicationAsync(
        Task publication,
        NormalizedRequest normalized,
        DateTime started,
        string path,
        Task<OperationResultPayload> executorTask,
        CancellationTokenSource deadlineCts,
        CancellationTokenSource operationCts,
        CancellationToken serviceToken)
    {
        await publication.ConfigureAwait(false);
        return await ReconcileExecutorAsync(
            normalized,
            started,
            path,
            executorTask,
            deadlineCts,
            operationCts,
            serviceToken).ConfigureAwait(false);
    }

    private async Task<OperationResultPayload> ReconcileExecutorAsync(
        NormalizedRequest normalized,
        DateTime started,
        string path,
        Task<OperationResultPayload> executorTask,
        CancellationTokenSource deadlineCts,
        CancellationTokenSource operationCts,
        CancellationToken serviceToken)
    {
        try
        {
            try
            {
                var result = await executorTask.ConfigureAwait(false);
                var terminal = NormalizeExecutorResult(normalized, result, started);
                if (deadlineCts.IsCancellationRequested)
                {
                    terminal = terminal with
                    {
                        Diagnostic = Append(
                            terminal.Diagnostic,
                            "The executor completed after the service deadline and this record contains the reconciled final truth."),
                    };
                }
                else if (serviceToken.IsCancellationRequested)
                {
                    terminal = terminal with
                    {
                        Diagnostic = Append(
                            terminal.Diagnostic,
                            "The executor completed after service cancellation and this record contains the reconciled final truth."),
                    };
                }

                return PersistReconciledTerminal(terminal, path);
            }
            catch (OperationCanceledException exception) when (deadlineCts.IsCancellationRequested && !serviceToken.IsCancellationRequested)
            {
                return PersistReconciledTerminal(
                    DeadlineTimeout(normalized, started, exception.Message),
                    path);
            }
            catch (OperationCanceledException exception) when (serviceToken.IsCancellationRequested)
            {
                return PersistReconciledTerminal(Cancelled(normalized, started, exception.Message), path);
            }
            catch (OperationCanceledException exception)
            {
                return PersistReconciledTerminal(Failure(normalized, ApfsOperationCodes.OperationFailed, Append(exception.Message, "The executor threw OperationCanceledException without service cancellation."), started), path);
            }
            catch (Exception exception)
            {
                return PersistReconciledTerminal(Failure(normalized, ApfsOperationCodes.OperationFailed, $"The operation executor failed: {exception.Message}", started), path);
            }
        }
        finally
        {
            operationCts.Dispose();
            deadlineCts.Dispose();
        }
    }

    private void TrackReconciliation(NormalizedRequest normalized, Task<OperationResultPayload> reconciliationTask)
    {
        var ownership = new ReconciliationOwnership(normalized.Fingerprint!, reconciliationTask);
        lock (_admissionGate)
        {
            _reconciliations.Add(normalized.OperationId, ownership);
        }

        _ = reconciliationTask.ContinueWith(
            static (completedTask, state) =>
            {
                if (completedTask.Status != TaskStatus.RanToCompletion ||
                    !IsTerminal(completedTask.Result.State) ||
                    string.IsNullOrWhiteSpace(completedTask.Result.EvidencePath))
                {
                    return;
                }

                var completion = (ReconciliationCompletion)state!;
                completion.Service.ReleaseReconciliation(completion.OperationId, completion.Ownership);
            },
            new ReconciliationCompletion(this, normalized.OperationId, ownership),
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private void TrackOperationContext(
        NormalizedRequest normalized,
        AgentOperationRecord<OperationResultPayload> record)
    {
        _ = record.Completion.ContinueWith(
            static (_, state) =>
            {
                var completion = (OperationContextCompletion)state!;
                completion.Service.ReleaseOperationContext(
                    completion.OperationId,
                    completion.Fingerprint);
            },
            new OperationContextCompletion(this, normalized.OperationId, normalized.Fingerprint!),
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private void ReleaseOperationContext(string operationId, string fingerprint)
    {
        lock (_admissionGate)
        {
            if (_operationContexts.TryGetValue(operationId, out var current) &&
                StringComparer.Ordinal.Equals(current.Fingerprint, fingerprint))
            {
                _operationContexts.Remove(operationId);
            }
        }
    }

    private void ReleaseReconciliation(string operationId, ReconciliationOwnership ownership)
    {
        lock (_admissionGate)
        {
            if (_reconciliations.TryGetValue(operationId, out var current) && ReferenceEquals(current, ownership))
            {
                _reconciliations.Remove(operationId);
            }
        }
    }

    private OperationResultPayload ResolveDurable(string id)
    {
        lock (_admissionGate)
        {
            var evidence = ReadEvidence(id);
            if (evidence.Status == EvidenceStatus.Missing) return UnknownOperation(id);
            if (evidence.Status == EvidenceStatus.Corrupt) return CorruptResponse(id, evidence.Diagnostic!);
            if (IsTerminal(evidence.Payload!.State)) return evidence.Payload;
            return _reconciliations.ContainsKey(id)
                ? evidence.Payload
                : RecoverNonterminal(evidence.Payload, evidence.Path);
        }
    }

    private OperationResultPayload ResolveOwnedReconciliation(NormalizedRequest normalized)
    {
        var evidence = ReadEvidence(normalized.OperationId);
        if (evidence.Status == EvidenceStatus.Valid) return evidence.Payload!;
        if (evidence.Status == EvidenceStatus.Corrupt) return CorruptResponse(normalized.OperationId, evidence.Diagnostic!, normalized);
        return Unreconciled(
            normalized,
            normalized.RequestedAtUtc,
            "The executor remains owned for reconciliation, but its durable operation evidence is unavailable.");
    }

    private OperationResultPayload RecoverNonterminal(OperationResultPayload persisted, string path)
        => PersistTerminal(persisted with { State = ApfsOperationStates.Failed, Code = ApfsOperationCodes.OperationFailed, Success = false, StartedAtUtc = persisted.StartedAtUtc ?? persisted.RequestedAtUtc, CompletedAtUtc = UtcNow(), EvidencePath = null, Diagnostic = Append(persisted.Diagnostic, "A persisted nonterminal operation was recovered after restart and was not reissued.") }, path);

    private OperationResultPayload PersistTerminal(OperationResultPayload terminal, string path)
    {
        var normalized = NormalizeTerminal(terminal);
        if (TryPersist(normalized, path, out var durable, out var error)) return durable;
        return normalized with { State = ApfsOperationStates.Failed, Code = ApfsOperationCodes.OperationFailed, Success = false, EvidencePath = null, Diagnostic = Append(normalized.Diagnostic, $"Terminal evidence could not be written: {error?.Message ?? "unknown persistence error"}") };
    }

    private OperationResultPayload PersistReconciledTerminal(OperationResultPayload terminal, string path)
    {
        lock (_admissionGate)
        {
            return PersistTerminal(terminal, path);
        }
    }

    private OperationResultPayload TerminalResponse(AgentOperationRecord<OperationResultPayload> current, string id)
    {
        lock (_admissionGate)
        {
            var evidence = ReadEvidence(id);
            if (evidence.Status == EvidenceStatus.Valid &&
                (IsTerminal(evidence.Payload!.State) || IsUnreconciledCompletion(current)))
            {
                return evidence.Payload;
            }
            return evidence.Status == EvidenceStatus.Corrupt ? CorruptResponse(id, evidence.Diagnostic!) : TerminalFallback(current, id);
        }
    }

    private OperationResultPayload TerminalFallback(AgentOperationRecord<OperationResultPayload> current, string id)
        => current.TerminalValue is { } terminal && (!IsTerminal(terminal.State) || !terminal.Success)
            ? terminal with { EvidencePath = null }
            : Failure(RecoveryContext(id), ApfsOperationCodes.OperationFailed, "The terminal evidence record is unavailable.");

    private OperationResultPayload NonterminalFallback(AgentOperationRecord<OperationResultPayload> current, string id)
    {
        var evidence = ReadEvidence(id);
        if (evidence.Status == EvidenceStatus.Valid) return evidence.Payload!;
        if (evidence.Status == EvidenceStatus.Corrupt) return CorruptResponse(id, evidence.Diagnostic!);
        var state = current.Status == AgentOperationStatus.Queued
            ? ApfsOperationStates.Accepted
            : ApfsOperationStates.InProgress;
        lock (_admissionGate)
        {
            if (_operationContexts.TryGetValue(id, out var context))
            {
                var started = state == ApfsOperationStates.InProgress
                    ? AtOrAfter(current.StartedAtUtc?.UtcDateTime ?? context.RequestedAtUtc, context.RequestedAtUtc)
                    : (DateTime?)null;
                return Make(
                    context,
                    state,
                    ApfsOperationCodes.OperationInProgress,
                    success: false,
                    started);
            }
        }
        var requestedAt = current.StartedAtUtc?.UtcDateTime ?? UtcNow();
        return WithConservativePendingProof(new OperationResultPayload(
            id,
            ApfsControlCommands.Unknown,
            null,
            Fingerprint: null,
            state,
            ApfsOperationCodes.OperationInProgress,
            false,
            requestedAt,
            state == ApfsOperationStates.InProgress ? requestedAt : null));
    }

    private CancellationAttempt BeginCancellation(string operationId)
    {
        var rawId = operationId?.Trim() ?? string.Empty;
        if (!TryCanonicalId(rawId, out var id))
        {
            var invalid = Failure(RecoveryContext(rawId), ApfsOperationCodes.InvalidOperationId, "The operationId is blank or is not a valid GUID.");
            return new(rawId, null, AgentOperationCancellationOutcome.Unknown, invalid);
        }

        var current = _coordinator.TryGet(id);
        if (current is null) return new(id, null, AgentOperationCancellationOutcome.Unknown, ResolveDurable(id));
        var outcome = _coordinator.Cancel(id);
        return outcome == AgentOperationCancellationOutcome.Unknown
            ? new(id, null, outcome, ResolveDurable(id))
            : new(id, current, outcome, null);
    }

    private OperationResultPayload CancellationPending(AgentOperationRecord<OperationResultPayload> current, string id)
    {
        var snapshot = NonterminalFallback(current, id);
        return IsTerminal(snapshot.State)
            ? snapshot
            : snapshot with { Diagnostic = Append(snapshot.Diagnostic, "Cancellation was requested; the operation is still running.") };
    }

    private OperationResultPayload CancellationRejected(AgentOperationRecord<OperationResultPayload> current, string id)
    {
        var snapshot = NonterminalFallback(current, id);
        if (IsTerminal(snapshot.State)) return snapshot;
        return snapshot with
        {
            Diagnostic = Append(snapshot.Diagnostic, "This operation cannot be explicitly cancelled."),
        };
    }

    private static async Task IgnoreCancellationCallbackExceptionsAsync(Task cancellationTask)
    {
        try
        {
            await cancellationTask.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Cancellation callbacks cannot change the durable operation result.
        }
    }

    private OperationResultPayload Accepted(NormalizedRequest n) => Make(n, ApfsOperationStates.Accepted, ApfsOperationCodes.OperationInProgress, false);
    private OperationResultPayload Failure(NormalizedRequest n, string code, string diagnostic, DateTime? started = null) => Make(n, ApfsOperationStates.Failed, code, false, started, diagnostic);
    private OperationResultPayload Cancelled(NormalizedRequest n, DateTime started, string? diagnostic) => Make(n, ApfsOperationStates.Cancelled, ApfsOperationCodes.OperationCancelled, false, started, string.IsNullOrWhiteSpace(diagnostic) ? "The operation was cancelled." : diagnostic);
    private OperationResultPayload Unreconciled(NormalizedRequest n, DateTime started, string diagnostic)
        => Make(n, ApfsOperationStates.InProgress, ApfsOperationCodes.OperationInProgress, false, started, diagnostic);
    private OperationResultPayload DeadlineTimeout(
        NormalizedRequest n,
        DateTime started,
        string? diagnostic)
        => Make(
            n,
            ApfsOperationStates.Failed,
            ApfsOperationCodes.Timeout,
            false,
            started,
            string.IsNullOrWhiteSpace(diagnostic)
                ? "The operation reached its service-enforced deadline."
                : diagnostic);

    private OperationResultPayload Make(NormalizedRequest n, string state, string code, bool success, DateTime? started = null, string? diagnostic = null)
    {
        var effectiveStarted = IsTerminal(state) ? started ?? n.RequestedAtUtc : started;
        var result = new OperationResultPayload(
            n.OperationId,
            n.Command,
            n.Target,
            n.Fingerprint,
            state,
            code,
            success,
            n.RequestedAtUtc,
            effectiveStarted,
            IsTerminal(state) ? AtOrAfter(UtcNow(), effectiveStarted!.Value) : null,
            RequestedMode: n.RequestedMode,
            Diagnostic: diagnostic,
            ExpiresAtUtc: n.ExpiresAtUtc);
        return !IsTerminal(state) || code == ApfsOperationCodes.Timeout
            ? WithConservativePendingProof(result)
            : result;
    }

    private static OperationResultPayload WithConservativePendingProof(OperationResultPayload result)
        => result with
        {
            FinalStatus = "not-proven",
            RecoveryState = "not-proven",
            PendingDurability = true,
            MountProof = "not-proven",
            OwnershipProof = "not-proven",
            DurabilityProof = "not-proven",
        };
    private OperationResultPayload PersistenceFailure(NormalizedRequest n, Exception? error, string message) => Failure(n, ApfsOperationCodes.OperationFailed, Append(message, error?.Message));
    private OperationResultPayload Conflict(NormalizedRequest n, string? fingerprint) => Failure(n, ApfsOperationCodes.OperationConflict, $"The operationId is already associated with a different request fingerprint '{fingerprint ?? "unknown"}'.");
    private OperationResultPayload UnknownOperation(string id) => Failure(RecoveryContext(id), ApfsOperationCodes.OperationFailed, "The requested operation is unknown or has no persisted evidence.");
    private OperationResultPayload CorruptResponse(string id, string diagnostic, NormalizedRequest? context = null)
    {
        var now = UtcNow();
        return new OperationResultPayload(
            id,
            context?.Command ?? ApfsControlCommands.Unknown,
            context?.Target,
            context?.Fingerprint,
            ApfsOperationStates.Failed,
            ApfsOperationCodes.OperationFailed,
            false,
            context?.RequestedAtUtc ?? now,
            StartedAtUtc: context?.RequestedAtUtc ?? now,
            CompletedAtUtc: now,
            RequestedMode: context?.RequestedMode,
            Diagnostic: $"Corrupt operation evidence was preserved and was not overwritten: {diagnostic}",
            ExpiresAtUtc: context?.ExpiresAtUtc);
    }

    private OperationResultPayload NormalizeExecutorResult(NormalizedRequest n, OperationResultPayload result, DateTime started)
    {
        ArgumentNullException.ThrowIfNull(result);
        var terminal = IsValidTerminalPair(result.State, result.Code, result.Success)
            ? result
            : result with
            {
                State = ApfsOperationStates.Failed,
                Code = ApfsOperationCodes.OperationFailed,
                Success = false,
                Diagnostic = Append(result.Diagnostic, $"The executor result was inconsistent: state='{result.State}', code='{result.Code}', success={result.Success}."),
            };
        return terminal with
        {
            OperationId = n.OperationId,
            Command = n.Command,
            Target = n.Target,
            Fingerprint = n.Fingerprint,
            RequestedAtUtc = n.RequestedAtUtc,
            StartedAtUtc = started,
            CompletedAtUtc = AtOrAfter(UtcNow(), started),
            EvidencePath = null,
            RequestedMode = n.RequestedMode,
            EffectiveMode = NormalizeEffectiveMode(result.EffectiveMode),
            ExpiresAtUtc = n.ExpiresAtUtc,
        };
    }

    private OperationResultPayload NormalizeTerminal(OperationResultPayload terminal)
    {
        var started = AtOrAfter(terminal.StartedAtUtc ?? terminal.RequestedAtUtc, terminal.RequestedAtUtc);
        var completed = AtOrAfter(terminal.CompletedAtUtc ?? UtcNow(), started);
        if (IsValidTerminalPair(terminal.State, terminal.Code, terminal.Success))
        {
            var normalized = terminal with { StartedAtUtc = started, CompletedAtUtc = completed, EvidencePath = null };
            return terminal.Code == ApfsOperationCodes.Timeout
                ? WithConservativePendingProof(normalized)
                : normalized;
        }

        return terminal with
        {
            State = ApfsOperationStates.Failed,
            Code = ApfsOperationCodes.OperationFailed,
            Success = false,
            StartedAtUtc = started,
            CompletedAtUtc = completed,
            EvidencePath = null,
            Diagnostic = Append(terminal.Diagnostic, $"The terminal result was inconsistent: state='{terminal.State}', code='{terminal.Code}', success={terminal.Success}."),
        };
    }

    private bool EnsureAdmissionCapacity(OperationResultPayload accepted, string path, out string diagnostic)
    {
        CleanupOwnedTemporaryFiles(deleteAll: false);
        if (!TryPrepareEvidence(accepted, path, out _, out _, out var preparationDiagnostic))
        {
            diagnostic = $"The operation evidence store cannot admit this record: {preparationDiagnostic}";
            return false;
        }

        string[] records;
        string[] ownedTemporaryFiles;
        try
        {
            records = Directory.GetFiles(_root, "*.json", SearchOption.TopDirectoryOnly);
            ownedTemporaryFiles = Directory.GetFiles(_root, "*.tmp", SearchOption.TopDirectoryOnly)
                .Where(IsOwnedTemporaryFile)
                .ToArray();
        }
        catch (Exception exception)
        {
            diagnostic = $"The operation evidence store could not be inventoried: {exception.Message}";
            return false;
        }

        if (records.Length + ownedTemporaryFiles.Length < _storeLimits.MaximumRecordCount)
        {
            diagnostic = string.Empty;
            return true;
        }

        DateTime cutoff;
        try
        {
            cutoff = UtcNow() - _storeLimits.TerminalRetention;
        }
        catch (ArgumentOutOfRangeException)
        {
            cutoff = DateTime.MinValue;
        }

        var prunable = new List<(string Path, DateTime CompletedAtUtc)>();
        foreach (var recordPath in records)
        {
            var fileId = Path.GetFileNameWithoutExtension(recordPath);
            if (!TryCanonicalId(fileId, out var canonicalId)
                || !StringComparer.Ordinal.Equals(fileId, canonicalId)
                || _coordinator.TryGet(canonicalId) is not null)
            {
                continue;
            }

            var evidence = ReadEvidenceAtPath(canonicalId, recordPath);
            if (evidence.Status == EvidenceStatus.Valid
                && IsTerminal(evidence.Payload!.State)
                && evidence.Payload.CompletedAtUtc <= cutoff)
            {
                prunable.Add((recordPath, evidence.Payload.CompletedAtUtc!.Value));
            }
        }

        var retainedCount = records.Length + ownedTemporaryFiles.Length;
        foreach (var candidate in prunable.OrderBy(item => item.CompletedAtUtc).ThenBy(item => item.Path, StringComparer.Ordinal))
        {
            if (retainedCount < _storeLimits.MaximumRecordCount) break;
            try
            {
                File.Delete(candidate.Path);
                if (!File.Exists(candidate.Path)) retainedCount--;
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        if (retainedCount < _storeLimits.MaximumRecordCount)
        {
            diagnostic = string.Empty;
            return true;
        }

        diagnostic = $"The operation evidence store has reached its {_storeLimits.MaximumRecordCount}-file limit and no owned stale temp or expired terminal record can be safely pruned.";
        return false;
    }

    private void CleanupOwnedTemporaryFiles(bool deleteAll)
    {
        string[] temporaryFiles;
        try
        {
            temporaryFiles = Directory.GetFiles(_root, "*.tmp", SearchOption.TopDirectoryOnly);
        }
        catch (Exception)
        {
            return;
        }

        var cutoff = UtcNow() - TemporaryFileRetention;
        foreach (var temporaryFile in temporaryFiles)
        {
            if (!IsOwnedTemporaryFile(temporaryFile)) continue;
            if (!deleteAll)
            {
                try
                {
                    if (File.GetLastWriteTimeUtc(temporaryFile) > cutoff) continue;
                }
                catch (Exception)
                {
                    continue;
                }
            }

            try { File.Delete(temporaryFile); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static bool IsOwnedTemporaryFile(string path)
    {
        const int expectedLength = 79;
        var name = Path.GetFileName(path);
        if (name.Length != expectedLength
            || name[0] != '.'
            || !name.EndsWith(".tmp", StringComparison.Ordinal)
            || !name.AsSpan(37, 6).SequenceEqual(".json."))
        {
            return false;
        }

        var operationId = name.Substring(1, 36);
        var writeId = name.Substring(43, 32);
        return TryCanonicalId(operationId, out var canonicalId)
            && StringComparer.Ordinal.Equals(operationId, canonicalId)
            && Guid.TryParseExact(writeId, "N", out var parsedWriteId)
            && StringComparer.Ordinal.Equals(writeId, parsedWriteId.ToString("N"));
    }

    private EvidenceReadResult ReadEvidence(string id)
    {
        var canonicalPath = EvidencePath(id);
        return ReadEvidenceAtPath(id, canonicalPath);
    }

    private EvidenceReadResult ReadEvidenceAtPath(string id, string path)
    {
        if (Directory.Exists(path)) return Corrupt(path, "The evidence path is a directory, not a record.");
        if (!File.Exists(path)) return new(EvidenceStatus.Missing, path, null, null);
        try
        {
            var info = new FileInfo(path);
            if (info.Length <= 0 || info.Length > _storeLimits.MaximumRecordBytes) return Corrupt(path, "The evidence file size is invalid.");
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var payload = JsonSerializer.Deserialize<OperationResultPayload>(stream, JsonOptions);
            if (payload is null) return Corrupt(path, "The evidence payload is empty.");
            return IsValidEvidence(payload, id, path, out var diagnostic)
                ? new(EvidenceStatus.Valid, path, payload with { EvidencePath = path }, null)
                : Corrupt(path, diagnostic ?? "The evidence payload is invalid.");
        }
        catch (Exception exception)
        {
            return Corrupt(path, exception.Message);
        }
    }

    private static bool IsValidEvidence(OperationResultPayload payload, string id, string path, out string? diagnostic)
    {
        diagnostic = null;
        if (!TryCanonicalId(payload.OperationId, out var payloadId) || !StringComparer.Ordinal.Equals(payloadId, id) || !StringComparer.Ordinal.Equals(payload.OperationId, payloadId)) return Invalid(out diagnostic, "The evidence operationId is not the canonical GUID for its filename.");
        if (!IsKnownCommand(payload.Command) || !StringComparer.Ordinal.Equals(payload.Command, NormalizeToken(payload.Command))) return Invalid(out diagnostic, "The evidence command is unknown or not normalized.");
        if (!TryNormalizeMode(payload.RequestedMode, out var mode) || !StringComparer.Ordinal.Equals(payload.RequestedMode, mode)) return Invalid(out diagnostic, "The evidence requested mode is unknown or not normalized.");
        if (!TargetsEqual(payload.Target, NormalizeTarget(payload.Target)) || !HasValidTarget(payload.Command, payload.Target)) return Invalid(out diagnostic, "The evidence target is missing, not normalized, or violates the device prefix invariant.");
        if (string.IsNullOrWhiteSpace(payload.Fingerprint) || string.IsNullOrWhiteSpace(payload.Code) || payload.RequestedAtUtc == default || !payload.ExpiresAtUtc.HasValue) return Invalid(out diagnostic, "The evidence is missing required operation identity fields.");
        if (payload.ExpiresAtUtc.Value <= payload.RequestedAtUtc &&
            !(payload.State == ApfsOperationStates.Failed && IsCode(payload.Code, ApfsOperationCodes.Timeout)))
        {
            return Invalid(out diagnostic, "The evidence expiry does not follow its request timestamp.");
        }
        if (!StringComparer.Ordinal.Equals(
                payload.Fingerprint,
                ApfsOperationFingerprint.Compute(
                    payload.Command,
                    payload.Target,
                    payload.RequestedMode,
                    payload.ExpiresAtUtc.Value)))
        {
            return Invalid(out diagnostic, "The evidence fingerprint does not match its command, target, mode, and expiry.");
        }
        if (!IsKnownState(payload.State)) return Invalid(out diagnostic, $"The evidence state '{payload.State}' is unknown.");
        if (!IsPathEqual(payload.EvidencePath, path)) return Invalid(out diagnostic, "The evidence path does not identify the committed record.");
        if (payload.StartedAtUtc.HasValue && payload.StartedAtUtc.Value < payload.RequestedAtUtc) return Invalid(out diagnostic, "The evidence start timestamp precedes its request timestamp.");
        if (payload.CompletedAtUtc.HasValue && payload.CompletedAtUtc.Value < payload.RequestedAtUtc) return Invalid(out diagnostic, "The evidence completion timestamp precedes its request timestamp.");
        if (payload.StartedAtUtc.HasValue && payload.CompletedAtUtc.HasValue && payload.CompletedAtUtc.Value < payload.StartedAtUtc.Value) return Invalid(out diagnostic, "The evidence completion timestamp precedes its start timestamp.");
        if (payload.State == ApfsOperationStates.Accepted)
        {
            if (!IsCode(payload.Code, ApfsOperationCodes.OperationInProgress)) return Invalid(out diagnostic, "Accepted evidence must use the operation-in-progress code.");
            return payload.Success || payload.StartedAtUtc is not null || payload.CompletedAtUtc is not null || !HasConservativePendingProof(payload)
                ? Invalid(out diagnostic, "The accepted evidence fields are inconsistent.")
                : true;
        }

        if (payload.State == ApfsOperationStates.InProgress)
        {
            if (!IsCode(payload.Code, ApfsOperationCodes.OperationInProgress)) return Invalid(out diagnostic, "In-progress evidence must use the operation-in-progress code.");
            return payload.Success || payload.StartedAtUtc is null || payload.CompletedAtUtc is not null || !HasConservativePendingProof(payload)
                ? Invalid(out diagnostic, "The in-progress evidence fields are inconsistent.")
                : true;
        }

        if (!payload.StartedAtUtc.HasValue || !payload.CompletedAtUtc.HasValue) return Invalid(out diagnostic, "Terminal evidence must have start and completion timestamps.");
        if (payload.State == ApfsOperationStates.Succeeded)
        {
            return !payload.Success || !IsSuccessCode(payload.Code)
                ? Invalid(out diagnostic, "Succeeded evidence has an inconsistent result code or success flag.")
                : true;
        }

        if (payload.State == ApfsOperationStates.Failed)
        {
            return payload.Success ||
                   !IsKnownFailureCode(payload.Code) ||
                   (IsCode(payload.Code, ApfsOperationCodes.Timeout) && !HasConservativePendingProof(payload))
                ? Invalid(out diagnostic, "Failed evidence has an inconsistent result code or success flag.")
                : true;
        }

        return payload.Success || !IsCode(payload.Code, ApfsOperationCodes.OperationCancelled)
            ? Invalid(out diagnostic, "Cancelled evidence has an inconsistent result code or success flag.")
            : true;
    }

    private static bool Invalid(out string? diagnostic, string message) { diagnostic = message; return false; }

    private bool TryPersist(OperationResultPayload payload, string path, out OperationResultPayload durable, out Exception? error)
    {
        durable = payload with { EvidencePath = null };
        try
        {
            if (!TryPrepareEvidence(payload, path, out var candidate, out var bytes, out var diagnostic))
            {
                throw new InvalidDataException(diagnostic);
            }
            WriteEvidenceAtomically(path, candidate, bytes);
            var committed = ReadEvidenceAtPath(candidate.OperationId, path);
            if (committed.Status != EvidenceStatus.Valid || committed.Payload is null) throw new IOException(committed.Diagnostic ?? "The committed evidence record could not be validated.");
            durable = committed.Payload;
            error = null;
            return true;
        }
        catch (Exception exception) { error = exception; return false; }
    }

    private bool TryPrepareEvidence(
        OperationResultPayload payload,
        string path,
        out OperationResultPayload candidate,
        out byte[] bytes,
        out string diagnostic)
    {
        candidate = payload with { EvidencePath = path };
        bytes = [];
        var fileId = Path.GetFileNameWithoutExtension(path);
        string? validationDiagnostic = null;
        if (!TryCanonicalId(fileId, out var canonicalId)
            || !StringComparer.Ordinal.Equals(fileId, canonicalId)
            || !IsValidEvidence(candidate, canonicalId, path, out validationDiagnostic))
        {
            diagnostic = validationDiagnostic ?? "The evidence filename is not a canonical operation GUID.";
            return false;
        }

        try
        {
            bytes = JsonSerializer.SerializeToUtf8Bytes(candidate, JsonOptions);
        }
        catch (Exception exception)
        {
            diagnostic = $"The evidence payload could not be serialized: {exception.Message}";
            return false;
        }

        if (bytes.LongLength > _storeLimits.MaximumRecordBytes)
        {
            diagnostic = $"The evidence record exceeds the {_storeLimits.MaximumRecordBytes}-byte limit.";
            return false;
        }

        diagnostic = string.Empty;
        return true;
    }

    private void WriteEvidenceAtomically(string path, OperationResultPayload payload, byte[] bytes)
    {
        var directory = Path.GetDirectoryName(path) ?? throw new InvalidOperationException("The evidence path has no directory.");
        Directory.CreateDirectory(directory);
        var temp = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            _beforeEvidenceCommit?.Invoke(payload);
            if (OperatingSystem.IsWindows())
            {
                if (!MoveFileExW(temp, path, MoveFileReplaceExisting | MoveFileWriteThrough)) throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            else File.Move(temp, path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private NormalizedRequest Normalize(ControlOperationRequestPayload request)
    {
        var rawId = request.OperationId?.Trim() ?? string.Empty;
        var id = TryCanonicalId(rawId, out var canonical) ? canonical : rawId.ToLowerInvariant();
        var command = NormalizeToken(request.Command) ?? string.Empty;
        var target = NormalizeTarget(request.Target);
        var modeValid = TryNormalizeMode(request.RequestedMode, out var mode);
        var requestedAtUtc = UtcNow();
        var expiresAtUtc = request.ExpiresAtUtc?.ToUniversalTime();
        var normalized = new NormalizedRequest(
            id,
            command,
            target,
            mode,
            expiresAtUtc ?? default,
            expiresAtUtc.HasValue && !string.IsNullOrWhiteSpace(command)
                ? ApfsOperationFingerprint.Compute(command, target, mode, expiresAtUtc.Value)
                : null,
            requestedAtUtc,
            null,
            null);
        if (!TryCanonicalId(rawId, out _)) return normalized with { ValidationCode = ApfsOperationCodes.InvalidOperationId, ValidationDiagnostic = "The operationId is blank or is not a valid GUID." };
        if (!IsKnownCommand(command)) return normalized with { ValidationCode = ApfsOperationCodes.UnknownCommand, ValidationDiagnostic = "The operation command is missing or unknown." };
        if (!modeValid) return normalized with { ValidationCode = ApfsOperationCodes.InvalidArguments, ValidationDiagnostic = "RequestedMode must be null, read-only, or read-write." };
        if (!HasValidTarget(command, target)) return normalized with { ValidationCode = command == ApfsControlCommands.Quit ? ApfsOperationCodes.InvalidArguments : ApfsOperationCodes.AmbiguousTarget, ValidationDiagnostic = command == ApfsControlCommands.Quit ? "The quit command must not include a target." : "Mount, fix, and eject require a nonblank target whose volume begins with device + '|'." };
        if (!expiresAtUtc.HasValue) return normalized with { ValidationCode = ApfsOperationCodes.InvalidArguments, ValidationDiagnostic = "ExpiresAtUtc is required for every mutating operation." };
        if (expiresAtUtc.Value > requestedAtUtc + MaximumOperationLifetime) return normalized with { ValidationCode = ApfsOperationCodes.InvalidArguments, ValidationDiagnostic = $"ExpiresAtUtc cannot be more than {MaximumOperationLifetime.TotalMinutes:n0} minutes in the future." };
        return normalized;
    }

    private static ApfsControlTarget? NormalizeTarget(ApfsControlTarget? target) => target is null ? null : new ApfsControlTarget(NormalizeToken(target.DeviceId) ?? string.Empty, NormalizeToken(target.VolumeId) ?? string.Empty, NormalizeOpaque(target.RecoveryIdentity));
    private static string? NormalizeToken(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim().ToLowerInvariant();
    private static string? NormalizeOpaque(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static bool TryNormalizeMode(string? value, out string? normalized)
    {
        if (value is null) { normalized = null; return true; }
        if (string.IsNullOrWhiteSpace(value)) { normalized = null; return false; }
        normalized = value.Trim().ToLowerInvariant() switch { "ro" or "readonly" or "read_only" or "read only" or "read-only" => ApfsControlModes.ReadOnly, "rw" or "readwrite" or "read_write" or "read write" or "read-write" => ApfsControlModes.ReadWrite, _ => null };
        return normalized is not null;
    }

    private static string? NormalizeEffectiveMode(string? value) => TryNormalizeMode(value, out var normalized) ? normalized : NormalizeOpaque(value);
    private static bool HasValidTarget(string command, ApfsControlTarget? target) => command == ApfsControlCommands.Quit ? target is null : target is not null && !string.IsNullOrWhiteSpace(target.DeviceId) && !string.IsNullOrWhiteSpace(target.VolumeId) && target.VolumeId.StartsWith(target.DeviceId + "|", StringComparison.OrdinalIgnoreCase);
    private static bool TargetsEqual(ApfsControlTarget? first, ApfsControlTarget? second) => first is null || second is null ? first is null && second is null : StringComparer.Ordinal.Equals(first.DeviceId, second.DeviceId) && StringComparer.Ordinal.Equals(first.VolumeId, second.VolumeId) && StringComparer.Ordinal.Equals(first.RecoveryIdentity, second.RecoveryIdentity);
    private string EvidencePath(string id) => Path.Combine(_root, $"{id}.json");
    private DateTime UtcNow() => _clock.GetUtcNow().UtcDateTime;

    private CancellationTokenSource CreateDeadlineCancellationSource(DateTime expiresAtUtc)
    {
        var remaining = expiresAtUtc - UtcNow();
        var source = new CancellationTokenSource();
        if (remaining <= TimeSpan.Zero)
        {
            source.Cancel();
        }
        else
        {
            source.CancelAfter(remaining);
        }

        return source;
    }

    private static bool TryCanonicalId(string? value, out string canonical)
    {
        if (string.IsNullOrWhiteSpace(value) || !Guid.TryParse(value.Trim(), out var guid)) { canonical = string.Empty; return false; }
        canonical = guid.ToString("D").ToLowerInvariant();
        return true;
    }
    private static bool IsKnownCommand(string? command) => command is ApfsControlCommands.Mount or ApfsControlCommands.Fix or ApfsControlCommands.Eject or ApfsControlCommands.Quit;
    private static bool IsKnownState(string? state) => state is ApfsOperationStates.Accepted or ApfsOperationStates.InProgress or ApfsOperationStates.Succeeded or ApfsOperationStates.Failed or ApfsOperationStates.Cancelled;
    private static bool IsTerminal(string? state) => state is ApfsOperationStates.Succeeded or ApfsOperationStates.Failed or ApfsOperationStates.Cancelled;
    private static bool IsUnreconciledCompletion(AgentOperationRecord<OperationResultPayload> record)
        => record.TerminalValue is { } value && !IsTerminal(value.State);
    private static bool HasConservativePendingProof(OperationResultPayload payload)
        => payload.PendingDurability &&
           StringComparer.Ordinal.Equals(payload.FinalStatus, "not-proven") &&
           StringComparer.Ordinal.Equals(payload.MountProof, "not-proven") &&
           StringComparer.Ordinal.Equals(payload.OwnershipProof, "not-proven") &&
           StringComparer.Ordinal.Equals(payload.DurabilityProof, "not-proven");
    private static bool IsCode(string? actual, string expected) => StringComparer.Ordinal.Equals(actual, expected);
    private static bool IsSuccessCode(string? code) => code is ApfsOperationCodes.OperationSucceeded or ApfsOperationCodes.AlreadyAchieved;
    private static bool IsKnownFailureCode(string? code) => code is ApfsOperationCodes.InvalidArguments or ApfsOperationCodes.MissingVolume or ApfsOperationCodes.Timeout or ApfsOperationCodes.BlockedRecovery or ApfsOperationCodes.UnsafeOwnership or ApfsOperationCodes.OperationFailed or ApfsOperationCodes.MalformedMessage or ApfsOperationCodes.UnsupportedSchema or ApfsOperationCodes.UnsupportedMessageType or ApfsOperationCodes.InvalidOperationId or ApfsOperationCodes.UnknownCommand or ApfsOperationCodes.AmbiguousTarget or ApfsOperationCodes.ElevationFailed or ApfsOperationCodes.OperationConflict or ApfsOperationCodes.NotCancellable or ApfsOperationCodes.ServiceUnavailable;
    private static bool IsValidTerminalPair(string? state, string? code, bool success)
        => state switch
        {
            ApfsOperationStates.Succeeded => success && IsSuccessCode(code),
            ApfsOperationStates.Failed => !success && IsKnownFailureCode(code),
            ApfsOperationStates.Cancelled => !success && IsCode(code, ApfsOperationCodes.OperationCancelled),
            _ => false,
        };
    private static DateTime AtOrAfter(DateTime value, DateTime floor) => value < floor ? floor : value;
    private static bool IsPathEqual(string? stored, string expected) { if (string.IsNullOrWhiteSpace(stored)) return false; try { return StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(stored), Path.GetFullPath(expected)); } catch (ArgumentException) { return false; } }
    private static EvidenceReadResult Corrupt(string path, string diagnostic) => new(EvidenceStatus.Corrupt, path, null, diagnostic);
    private NormalizedRequest RecoveryContext(string id) { var normalized = TryCanonicalId(id, out var canonical) ? canonical : id.Trim().ToLowerInvariant(); var now = UtcNow(); return new NormalizedRequest(normalized, ApfsControlCommands.Unknown, null, null, now, null, now, null, null); }
    private static ControlOperationRequestPayload ToRequest(NormalizedRequest n) => new(n.OperationId, n.Command, n.Target, n.RequestedMode, n.ExpiresAtUtc);
    private static Task<OperationResultPayload> Done(OperationResultPayload result) => Task.FromResult(result);
    private static string Append(string? first, string? second) => string.IsNullOrWhiteSpace(first) ? second ?? string.Empty : string.IsNullOrWhiteSpace(second) ? first : $"{first} {second}";

    [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileExW(string existingFileName, string newFileName, uint flags);
    private sealed record NormalizedRequest(string OperationId, string Command, ApfsControlTarget? Target, string? RequestedMode, DateTime ExpiresAtUtc, string? Fingerprint, DateTime RequestedAtUtc, string? ValidationCode, string? ValidationDiagnostic);
    private sealed record ReconciliationOwnership(string Fingerprint, Task<OperationResultPayload> Completion);
    private sealed record ReconciliationCompletion(AgentControlOperationService Service, string OperationId, ReconciliationOwnership Ownership);
    private sealed record OperationContextCompletion(AgentControlOperationService Service, string OperationId, string Fingerprint);
    private sealed record CancellationAttempt(string Id, AgentOperationRecord<OperationResultPayload>? Record, AgentOperationCancellationOutcome Outcome, OperationResultPayload? Immediate);
    private enum EvidenceStatus { Missing, Valid, Corrupt }
    private sealed record EvidenceReadResult(EvidenceStatus Status, string Path, OperationResultPayload? Payload, string? Diagnostic);
}
