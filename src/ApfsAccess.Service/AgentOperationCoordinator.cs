namespace ApfsAccess.Service;

public enum AgentOperationStatus
{
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

public enum AgentOperationAdmissionOutcome
{
    Started,
    Replayed,
    Conflict,
    Rejected,
}

public enum AgentOperationCancellationOutcome
{
    Unknown,
    AlreadyTerminal,
    Requested,
    NotCancellable,
}

public sealed class AgentOperationStartResult<TResult>
{
    internal AgentOperationStartResult(
        AgentOperationAdmissionOutcome outcome,
        AgentOperationRecord<TResult>? record,
        string? conflictFingerprint)
    {
        Outcome = outcome;
        Record = record;
        ConflictFingerprint = conflictFingerprint;
    }

    public AgentOperationAdmissionOutcome Outcome { get; }

    public AgentOperationRecord<TResult>? Record { get; }

    public string? ConflictFingerprint { get; }

    public bool IsAccepted
        => Outcome is AgentOperationAdmissionOutcome.Started or AgentOperationAdmissionOutcome.Replayed;

    public bool IsReplayed => Outcome == AgentOperationAdmissionOutcome.Replayed;
}

public sealed class AgentOperationRecord<TResult>
{
    private readonly AgentOperationState<TResult> _state;

    internal AgentOperationRecord(AgentOperationState<TResult> state)
    {
        _state = state;
    }

    public string OperationId => _state.OperationId;

    public string NormalizedFingerprint => _state.NormalizedFingerprint;

    public AgentOperationStatus Status => _state.Status;

    public AgentOperationStatus State => Status;

    public DateTimeOffset? StartedAtUtc => _state.StartedAtUtc;

    public DateTimeOffset? CompletedAtUtc => _state.CompletedAtUtc;

    public TResult? TerminalValue => _state.TerminalValue;

    public Exception? TerminalError => _state.TerminalError;

    public bool IsTerminal => _state.IsTerminal;

    public bool CanCancel => _state.AllowExplicitCancellation;

    public bool CancellationRequested => _state.CancellationRequested;

    public bool ExplicitCancellationRequested => _state.ExplicitCancellationRequested;

    public Task<AgentOperationRecord<TResult>> Completion => _state.Completion;
}

public sealed class AgentOperationCoordinator<TResult>
{
    private readonly object _gate = new();
    private readonly Dictionary<string, AgentOperationState<TResult>> _operations = new(StringComparer.Ordinal);
    private readonly TimeSpan _completedRetention;
    private readonly int _maxCompletedEntries;
    private readonly TimeProvider _timeProvider;
    private long _nextSequence;
    private bool _shutdownRequested;
    private Task _shutdownCancellationTask = Task.CompletedTask;

    public AgentOperationCoordinator(
        TimeSpan completedRetention,
        int maxCompletedEntries,
        TimeProvider? timeProvider = null)
    {
        if (completedRetention < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(completedRetention));
        }

        if (maxCompletedEntries <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxCompletedEntries));
        }

        _completedRetention = completedRetention;
        _maxCompletedEntries = maxCompletedEntries;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public AgentOperationStartResult<TResult> Start(
        string operationId,
        string normalizedFingerprint,
        Func<CancellationToken, Task<TResult>> operation,
        bool allowExplicitCancellation = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
        ArgumentNullException.ThrowIfNull(normalizedFingerprint);
        ArgumentNullException.ThrowIfNull(operation);

        AgentOperationState<TResult> state;
        lock (_gate)
        {
            EvictCompleted_NoLock(_timeProvider.GetUtcNow());

            if (_shutdownRequested)
            {
                return new AgentOperationStartResult<TResult>(
                    AgentOperationAdmissionOutcome.Rejected,
                    record: null,
                    conflictFingerprint: null);
            }

            if (_operations.TryGetValue(operationId, out var existing))
            {
                if (StringComparer.Ordinal.Equals(existing.NormalizedFingerprint, normalizedFingerprint))
                {
                    return new AgentOperationStartResult<TResult>(
                        AgentOperationAdmissionOutcome.Replayed,
                        existing.Record,
                        conflictFingerprint: null);
                }

                return new AgentOperationStartResult<TResult>(
                    AgentOperationAdmissionOutcome.Conflict,
                    record: null,
                    conflictFingerprint: existing.NormalizedFingerprint);
            }

            state = new AgentOperationState<TResult>(
                operationId,
                normalizedFingerprint,
                allowExplicitCancellation,
                Interlocked.Increment(ref _nextSequence));
            var record = new AgentOperationRecord<TResult>(state);
            state.AttachRecord(record);
            _operations.Add(operationId, state);
        }

        QueueOperation(state, operation);
        return new AgentOperationStartResult<TResult>(
            AgentOperationAdmissionOutcome.Started,
            state.Record,
            conflictFingerprint: null);
    }

    public AgentOperationRecord<TResult>? TryGet(string operationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);

        lock (_gate)
        {
            EvictCompleted_NoLock(_timeProvider.GetUtcNow());
            return _operations.TryGetValue(operationId, out var state) ? state.Record : null;
        }
    }

    public AgentOperationCancellationOutcome Cancel(string operationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);

        AgentOperationState<TResult>? state;
        Task? cancellationTask;
        AgentOperationCancellationOutcome outcome;
        lock (_gate)
        {
            EvictCompleted_NoLock(_timeProvider.GetUtcNow());

            if (!_operations.TryGetValue(operationId, out state))
            {
                return AgentOperationCancellationOutcome.Unknown;
            }

            outcome = state.RequestExplicitCancellation(out cancellationTask);
        }

        if (outcome == AgentOperationCancellationOutcome.Requested)
        {
            _ = IgnoreCancellationCallbackExceptionsAsync(cancellationTask!);
        }

        return outcome;
    }

    public void Shutdown()
    {
        lock (_gate)
        {
            EvictCompleted_NoLock(_timeProvider.GetUtcNow());

            if (_shutdownRequested)
            {
                return;
            }

            _shutdownRequested = true;
            _shutdownCancellationTask = IgnoreCancellationCallbackExceptionsAsync(
                Task.WhenAll(_operations.Values.Select(static state =>
                    state.RequestShutdownCancellation())));
        }
    }

    public async Task ShutdownAsync(CancellationToken waitCancellationToken = default)
    {
        Shutdown();

        Task cancellationTask;
        Task[] completions;
        lock (_gate)
        {
            cancellationTask = _shutdownCancellationTask;
            completions = _operations.Values
                .Select(static state => state.Completion)
                .ToArray();
        }

        await Task.WhenAll(completions.Append(cancellationTask))
            .WaitAsync(waitCancellationToken)
            .ConfigureAwait(false);
    }

    private void QueueOperation(
        AgentOperationState<TResult> state,
        Func<CancellationToken, Task<TResult>> operation)
    {
        try
        {
            var task = Task.Run(() => RunOperationAsync(state, operation));
            _ = task.ContinueWith(
                static completedTask => _ = completedTask.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
        catch (Exception exception)
        {
            Complete(state, AgentOperationStatus.Failed, default, exception);
        }
    }

    private async Task RunOperationAsync(
        AgentOperationState<TResult> state,
        Func<CancellationToken, Task<TResult>> operation)
    {
        try
        {
            if (!state.TryMarkRunning(_timeProvider.GetUtcNow()))
            {
                return;
            }

            try
            {
                var value = await operation(state.OperationToken).ConfigureAwait(false);
                Complete(state, AgentOperationStatus.Succeeded, value, error: null);
            }
            catch (OperationCanceledException exception)
            {
                Complete(state, AgentOperationStatus.Cancelled, default, exception);
            }
            catch (Exception exception)
            {
                Complete(state, AgentOperationStatus.Failed, default, exception);
            }
        }
        catch (Exception exception)
        {
            Complete(state, AgentOperationStatus.Failed, default, exception);
        }
    }

    private void Complete(
        AgentOperationState<TResult> state,
        AgentOperationStatus status,
        TResult? value,
        Exception? error)
    {
        if (!state.TryComplete(status, value, error, _timeProvider.GetUtcNow()))
        {
            return;
        }

        lock (_gate)
        {
            EvictCompleted_NoLock(_timeProvider.GetUtcNow());
        }
    }

    private static async Task IgnoreCancellationCallbackExceptionsAsync(Task cancellationTask)
    {
        try
        {
            await cancellationTask.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Cancellation callbacks belong to the operation and must not change the admission result.
        }
    }

    private void EvictCompleted_NoLock(DateTimeOffset nowUtc)
    {
        var completed = _operations.Values
            .Where(static state => state.IsTerminal)
            .OrderBy(static state => state.CompletedAtUtc)
            .ThenBy(static state => state.Sequence)
            .ToArray();

        foreach (var state in completed)
        {
            if (nowUtc - state.CompletedAtUtc!.Value >= _completedRetention)
            {
                _operations.Remove(state.OperationId);
            }
        }

        completed = _operations.Values
            .Where(static state => state.IsTerminal)
            .OrderBy(static state => state.CompletedAtUtc)
            .ThenBy(static state => state.Sequence)
            .ToArray();

        for (var index = 0; index < completed.Length - _maxCompletedEntries; index++)
        {
            _operations.Remove(completed[index].OperationId);
        }
    }
}

internal sealed class AgentOperationState<TResult>
{
    private readonly object _gate = new();
    private readonly CancellationTokenSource _cancellationSource = new();
    private readonly TaskCompletionSource<AgentOperationRecord<TResult>> _completion = new(
        TaskCreationOptions.RunContinuationsAsynchronously);
    private AgentOperationRecord<TResult>? _record;
    private AgentOperationStatus _status = AgentOperationStatus.Queued;
    private DateTimeOffset? _startedAtUtc;
    private DateTimeOffset? _completedAtUtc;
    private TResult? _terminalValue;
    private Exception? _terminalError;
    private bool _explicitCancellationRequested;
    private Task? _cancellationTask;

    public AgentOperationState(
        string operationId,
        string normalizedFingerprint,
        bool allowExplicitCancellation,
        long sequence)
    {
        OperationId = operationId;
        NormalizedFingerprint = normalizedFingerprint;
        AllowExplicitCancellation = allowExplicitCancellation;
        Sequence = sequence;
    }

    public string OperationId { get; }

    public string NormalizedFingerprint { get; }

    public bool AllowExplicitCancellation { get; }

    public long Sequence { get; }

    public AgentOperationRecord<TResult> Record
        => _record ?? throw new InvalidOperationException("The operation record has not been attached.");

    public CancellationToken OperationToken => _cancellationSource.Token;

    public Task<AgentOperationRecord<TResult>> Completion => _completion.Task;

    public AgentOperationStatus Status
    {
        get
        {
            lock (_gate)
            {
                return _status;
            }
        }
    }

    public DateTimeOffset? StartedAtUtc
    {
        get
        {
            lock (_gate)
            {
                return _startedAtUtc;
            }
        }
    }

    public DateTimeOffset? CompletedAtUtc
    {
        get
        {
            lock (_gate)
            {
                return _completedAtUtc;
            }
        }
    }

    public TResult? TerminalValue
    {
        get
        {
            lock (_gate)
            {
                return _terminalValue;
            }
        }
    }

    public Exception? TerminalError
    {
        get
        {
            lock (_gate)
            {
                return _terminalError;
            }
        }
    }

    public bool IsTerminal
    {
        get
        {
            lock (_gate)
            {
                return IsTerminal_NoLock();
            }
        }
    }

    public bool CancellationRequested => _cancellationSource.IsCancellationRequested;

    public bool ExplicitCancellationRequested
    {
        get
        {
            lock (_gate)
            {
                return _explicitCancellationRequested;
            }
        }
    }

    public void AttachRecord(AgentOperationRecord<TResult> record)
        => _record = record;

    public bool TryMarkRunning(DateTimeOffset startedAtUtc)
    {
        lock (_gate)
        {
            if (_status != AgentOperationStatus.Queued)
            {
                return false;
            }

            _status = AgentOperationStatus.Running;
            _startedAtUtc = startedAtUtc;
            return true;
        }
    }

    public AgentOperationCancellationOutcome RequestExplicitCancellation(
        out Task? cancellationTask)
    {
        lock (_gate)
        {
            cancellationTask = null;
            if (IsTerminal_NoLock())
            {
                return AgentOperationCancellationOutcome.AlreadyTerminal;
            }

            if (!AllowExplicitCancellation)
            {
                return AgentOperationCancellationOutcome.NotCancellable;
            }

            _explicitCancellationRequested = true;
            cancellationTask = RequestCancellation_NoLock();
            return AgentOperationCancellationOutcome.Requested;
        }
    }

    public Task RequestShutdownCancellation()
    {
        lock (_gate)
        {
            return IsTerminal_NoLock()
                ? Task.CompletedTask
                : RequestCancellation_NoLock();
        }
    }

    private Task RequestCancellation_NoLock()
        => _cancellationTask ??= _cancellationSource.CancelAsync();

    public bool TryComplete(
        AgentOperationStatus status,
        TResult? value,
        Exception? error,
        DateTimeOffset completedAtUtc)
    {
        if (status is AgentOperationStatus.Queued or AgentOperationStatus.Running)
        {
            throw new ArgumentOutOfRangeException(nameof(status));
        }

        AgentOperationRecord<TResult> record;
        lock (_gate)
        {
            if (IsTerminal_NoLock())
            {
                return false;
            }

            _status = status;
            _terminalValue = value;
            _terminalError = error;
            _completedAtUtc = completedAtUtc;
            record = Record;
            _completion.TrySetResult(record);
            return true;
        }
    }

    private bool IsTerminal_NoLock()
        => _status is AgentOperationStatus.Succeeded
            or AgentOperationStatus.Failed
            or AgentOperationStatus.Cancelled;
}
