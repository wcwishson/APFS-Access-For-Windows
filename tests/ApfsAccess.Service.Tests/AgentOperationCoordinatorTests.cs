using ApfsAccess.Service;

namespace ApfsAccess.Service.Tests;

public sealed class AgentOperationCoordinatorTests
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(10);

    [Fact]
    public async Task SameRequest_ReplaysOneSharedRecordWhileRunningAndAfterCompletion()
    {
        var coordinator = new AgentOperationCoordinator<string>(
            completedRetention: TimeSpan.FromMinutes(5),
            maxCompletedEntries: 8);
        var operationStarted = new TaskCompletionSource<CancellationToken>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<object?>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var executionCount = 0;

        try
        {
            var first = coordinator.Start(
                "operation-1",
                "normalized:fingerprint",
                async token =>
                {
                    Interlocked.Increment(ref executionCount);
                    operationStarted.SetResult(token);
                    await release.Task;
                    return "completed";
                });
            Assert.NotNull(first.Record);
            var firstRecord = first.Record!;

            Assert.Equal(AgentOperationAdmissionOutcome.Started, first.Outcome);
            Assert.False(first.IsReplayed);
            Assert.True(
                firstRecord.Status is AgentOperationStatus.Queued or AgentOperationStatus.Running);

            await operationStarted.Task.WaitAsync(TestTimeout);
            Assert.Equal(AgentOperationStatus.Running, firstRecord.Status);
            Assert.NotNull(firstRecord.StartedAtUtc);
            Assert.Null(firstRecord.CompletedAtUtc);

            var replay = coordinator.Start(
                "operation-1",
                "normalized:fingerprint",
                _ => Task.FromResult("second delegate must not run"));

            Assert.Equal(AgentOperationAdmissionOutcome.Replayed, replay.Outcome);
            Assert.True(replay.IsReplayed);
            Assert.Same(firstRecord, replay.Record);

            release.SetResult(null);
            var completed = await firstRecord.Completion.WaitAsync(TestTimeout);

            Assert.Same(firstRecord, completed);
            Assert.Equal(AgentOperationStatus.Succeeded, completed.Status);
            Assert.Equal("completed", completed.TerminalValue);
            Assert.Null(completed.TerminalError);
            Assert.NotNull(completed.CompletedAtUtc);

            var laterReplay = coordinator.Start(
                "operation-1",
                "normalized:fingerprint",
                _ => Task.FromResult("third delegate must not run"));

            Assert.Equal(AgentOperationAdmissionOutcome.Replayed, laterReplay.Outcome);
            Assert.True(laterReplay.IsReplayed);
            Assert.Same(firstRecord, laterReplay.Record);
            Assert.Equal(1, Volatile.Read(ref executionCount));
        }
        finally
        {
            release.TrySetResult(null);
            await coordinator.ShutdownAsync().WaitAsync(TestTimeout);
        }
    }

    [Fact]
    public async Task ConcurrentAdmission_WithSameRequestExecutesOnlyOneDelegate()
    {
        var coordinator = new AgentOperationCoordinator<string>(
            completedRetention: TimeSpan.FromMinutes(5),
            maxCompletedEntries: 64);
        var operationStarted = new TaskCompletionSource<object?>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<object?>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var executionCount = 0;

        try
        {
            var admissions = await Task.WhenAll(
                Enumerable.Range(0, 64)
                    .Select(_ => Task.Run(() => coordinator.Start(
                        "concurrent-operation",
                        "same-fingerprint",
                        async _ =>
                        {
                            Interlocked.Increment(ref executionCount);
                            operationStarted.SetResult(null);
                            await release.Task;
                            return "one-result";
                        }))));

            await operationStarted.Task.WaitAsync(TestTimeout);

            Assert.Equal(1, admissions.Count(admission =>
                admission.Outcome == AgentOperationAdmissionOutcome.Started));
            Assert.Equal(63, admissions.Count(admission =>
                admission.Outcome == AgentOperationAdmissionOutcome.Replayed));
            Assert.Equal(1, Volatile.Read(ref executionCount));

            var records = admissions
                .Select(admission =>
                {
                    Assert.NotNull(admission.Record);
                    return admission.Record!;
                })
                .ToArray();
            Assert.All(records, record => Assert.Same(records[0], record));

            release.SetResult(null);
            var completed = await records[0].Completion.WaitAsync(TestTimeout);
            Assert.Equal(AgentOperationStatus.Succeeded, completed.Status);
        }
        finally
        {
            release.TrySetResult(null);
            await coordinator.ShutdownAsync().WaitAsync(TestTimeout);
        }
    }

    [Fact]
    public async Task DifferentFingerprint_ReturnsConflictAndNeverRunsSecondDelegate()
    {
        var coordinator = new AgentOperationCoordinator<string>(
            completedRetention: TimeSpan.FromMinutes(5),
            maxCompletedEntries: 8);
        var operationStarted = new TaskCompletionSource<object?>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<object?>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var secondDelegateCount = 0;

        try
        {
            var first = coordinator.Start(
                "operation-conflict",
                "fingerprint-a",
                async _ =>
                {
                    operationStarted.SetResult(null);
                    await release.Task;
                    return "first";
                });
            Assert.NotNull(first.Record);
            var firstRecord = first.Record!;
            await operationStarted.Task.WaitAsync(TestTimeout);

            var conflict = coordinator.Start(
                "operation-conflict",
                "fingerprint-b",
                _ =>
                {
                    Interlocked.Increment(ref secondDelegateCount);
                    return Task.FromResult("second");
                });

            Assert.Equal(AgentOperationAdmissionOutcome.Conflict, conflict.Outcome);
            Assert.False(conflict.IsReplayed);
            Assert.Null(conflict.Record);
            Assert.Equal("fingerprint-a", conflict.ConflictFingerprint);
            Assert.Equal(0, Volatile.Read(ref secondDelegateCount));

            release.SetResult(null);
            Assert.Equal("first", (await firstRecord.Completion.WaitAsync(TestTimeout)).TerminalValue);

            var terminalConflict = coordinator.Start(
                "operation-conflict",
                "fingerprint-b",
                _ =>
                {
                    Interlocked.Increment(ref secondDelegateCount);
                    return Task.FromResult("second-after-completion");
                });

            Assert.Equal(AgentOperationAdmissionOutcome.Conflict, terminalConflict.Outcome);
            Assert.Equal(0, Volatile.Read(ref secondDelegateCount));
        }
        finally
        {
            release.TrySetResult(null);
            await coordinator.ShutdownAsync().WaitAsync(TestTimeout);
        }
    }

    [Fact]
    public async Task Failure_IsStoredAsTerminalErrorWithoutFaultingCompletion()
    {
        var coordinator = new AgentOperationCoordinator<string>(
            completedRetention: TimeSpan.FromMinutes(5),
            maxCompletedEntries: 8);
        var expected = new InvalidOperationException("operation failed");

        try
        {
            var admission = coordinator.Start(
                "operation-failure",
                "fingerprint",
                _ => Task.FromException<string>(expected));
            Assert.NotNull(admission.Record);
            var record = admission.Record!;

            var completed = await record.Completion.WaitAsync(TestTimeout);

            Assert.Equal(AgentOperationStatus.Failed, completed.Status);
            Assert.Null(completed.TerminalValue);
            Assert.Same(expected, completed.TerminalError);
            Assert.NotNull(completed.StartedAtUtc);
            Assert.NotNull(completed.CompletedAtUtc);
        }
        finally
        {
            await coordinator.ShutdownAsync().WaitAsync(TestTimeout);
        }
    }

    [Fact]
    public async Task CallerCancellation_DoesNotCancelAdmittedOperation()
    {
        var coordinator = new AgentOperationCoordinator<string>(
            completedRetention: TimeSpan.FromMinutes(5),
            maxCompletedEntries: 8);
        using var callerCancellation = new CancellationTokenSource();
        var operationStarted = new TaskCompletionSource<CancellationToken>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<object?>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        try
        {
            var admission = coordinator.Start(
                "operation-disconnect",
                "fingerprint",
                async operationToken =>
                {
                    operationStarted.SetResult(operationToken);
                    await release.Task;
                    return operationToken.IsCancellationRequested ? "cancelled" : "completed";
                });
            Assert.NotNull(admission.Record);
            var record = admission.Record!;
            var operationToken = await operationStarted.Task.WaitAsync(TestTimeout);

            callerCancellation.Cancel();
            release.SetResult(null);
            var completed = await record.Completion.WaitAsync(TestTimeout);

            Assert.True(callerCancellation.IsCancellationRequested);
            Assert.False(operationToken.IsCancellationRequested);
            Assert.Equal(AgentOperationStatus.Succeeded, completed.Status);
            Assert.Equal("completed", completed.TerminalValue);
        }
        finally
        {
            release.TrySetResult(null);
            await coordinator.ShutdownAsync().WaitAsync(TestTimeout);
        }
    }

    [Fact]
    public async Task ExplicitCancellation_IsRequestedIdempotentlyAndCompletesCooperatively()
    {
        var coordinator = new AgentOperationCoordinator<string>(
            completedRetention: TimeSpan.FromMinutes(5),
            maxCompletedEntries: 8);
        var operationStarted = new TaskCompletionSource<CancellationToken>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        try
        {
            Assert.Equal(
                AgentOperationCancellationOutcome.Unknown,
                coordinator.Cancel("missing-operation"));

            var admission = coordinator.Start(
                "operation-cancel",
                "fingerprint",
                async token =>
                {
                    operationStarted.SetResult(token);
                    await Task.Delay(Timeout.InfiniteTimeSpan, token);
                    return "must not complete successfully";
                });
            Assert.NotNull(admission.Record);
            var record = admission.Record!;
            var operationToken = await operationStarted.Task.WaitAsync(TestTimeout);

            Assert.True(record.CanCancel);
            Assert.Equal(
                AgentOperationCancellationOutcome.Requested,
                coordinator.Cancel("operation-cancel"));
            Assert.True(operationToken.IsCancellationRequested);
            Assert.Equal(
                AgentOperationCancellationOutcome.Requested,
                coordinator.Cancel("operation-cancel"));

            var completed = await record.Completion.WaitAsync(TestTimeout);

            Assert.Equal(AgentOperationStatus.Cancelled, completed.Status);
            Assert.IsAssignableFrom<OperationCanceledException>(completed.TerminalError);
            Assert.Equal(
                AgentOperationCancellationOutcome.AlreadyTerminal,
                coordinator.Cancel("operation-cancel"));
        }
        finally
        {
            await coordinator.ShutdownAsync().WaitAsync(TestTimeout);
        }
    }

    [Fact]
    public async Task ExplicitCancellation_ReturnsNotCancellableWhenDisabled()
    {
        var coordinator = new AgentOperationCoordinator<string>(
            completedRetention: TimeSpan.FromMinutes(5),
            maxCompletedEntries: 8);
        var operationStarted = new TaskCompletionSource<CancellationToken>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<object?>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        try
        {
            var admission = coordinator.Start(
                "operation-not-cancellable",
                "fingerprint",
                async token =>
                {
                    operationStarted.SetResult(token);
                    await release.Task;
                    return "completed";
                },
                allowExplicitCancellation: false);
            Assert.NotNull(admission.Record);
            var record = admission.Record!;
            var operationToken = await operationStarted.Task.WaitAsync(TestTimeout);

            Assert.False(record.CanCancel);
            Assert.Equal(
                AgentOperationCancellationOutcome.NotCancellable,
                coordinator.Cancel("operation-not-cancellable"));
            Assert.False(operationToken.IsCancellationRequested);

            release.SetResult(null);
            var completed = await record.Completion.WaitAsync(TestTimeout);
            Assert.Equal(AgentOperationStatus.Succeeded, completed.Status);
        }
        finally
        {
            release.TrySetResult(null);
            await coordinator.ShutdownAsync().WaitAsync(TestTimeout);
        }
    }

    [Fact]
    public async Task ExplicitCancellation_RemainsDeterministicWhenARegisteredCallbackThrows()
    {
        var coordinator = new AgentOperationCoordinator<string>(
            completedRetention: TimeSpan.FromMinutes(5),
            maxCompletedEntries: 8);
        var operationStarted = new TaskCompletionSource<CancellationToken>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        try
        {
            var admission = coordinator.Start(
                "operation-throwing-callback",
                "fingerprint",
                async token =>
                {
                    token.Register(static () => throw new InvalidOperationException("callback failed"));
                    operationStarted.SetResult(token);
                    await Task.Delay(Timeout.InfiniteTimeSpan, token);
                    return "must not complete successfully";
                });
            Assert.NotNull(admission.Record);
            var record = admission.Record!;
            await operationStarted.Task.WaitAsync(TestTimeout);

            var outcome = AgentOperationCancellationOutcome.Unknown;
            var exception = Record.Exception(() => outcome = coordinator.Cancel("operation-throwing-callback"));

            Assert.Null(exception);
            Assert.Equal(AgentOperationCancellationOutcome.Requested, outcome);
            Assert.Equal(AgentOperationStatus.Cancelled, (await record.Completion).Status);
        }
        finally
        {
            await coordinator.ShutdownAsync().WaitAsync(TestTimeout);
        }
    }

    [Fact]
    public async Task ExplicitCancellation_DoesNotBlockCallerOnSynchronousTokenCallback()
    {
        var coordinator = new AgentOperationCoordinator<string>(
            completedRetention: TimeSpan.FromMinutes(5),
            maxCompletedEntries: 8);
        var operationStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var callbackEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseCallback = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        try
        {
            var admission = coordinator.Start(
                "operation-blocking-callback",
                "fingerprint",
                async token =>
                {
                    var delay = Task.Delay(Timeout.InfiniteTimeSpan, token);
                    using var registration = token.Register(() =>
                    {
                        callbackEntered.TrySetResult();
                        releaseCallback.Task.GetAwaiter().GetResult();
                    });
                    operationStarted.TrySetResult();
                    await delay;
                    return "must not complete successfully";
                });
            Assert.NotNull(admission.Record);
            await operationStarted.Task.WaitAsync(TestTimeout);

            var cancellation = Task.Run(
                () => coordinator.Cancel("operation-blocking-callback"));
            await callbackEntered.Task.WaitAsync(TestTimeout);
            var first = await Task.WhenAny(
                cancellation,
                Task.Delay(TimeSpan.FromMilliseconds(500)));

            Assert.Same(cancellation, first);
            Assert.Equal(
                AgentOperationCancellationOutcome.Requested,
                await cancellation);

            releaseCallback.TrySetResult();
            Assert.Equal(
                AgentOperationStatus.Cancelled,
                (await admission.Record!.Completion.WaitAsync(TestTimeout)).Status);
        }
        finally
        {
            releaseCallback.TrySetResult();
            await coordinator.ShutdownAsync().WaitAsync(TestTimeout);
        }
    }

    [Fact]
    public async Task ShutdownAsync_HonorsCallerBoundWhenTokenCallbackBlocks()
    {
        var coordinator = new AgentOperationCoordinator<string>(
            completedRetention: TimeSpan.FromMinutes(5),
            maxCompletedEntries: 8);
        var operationStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var callbackEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseCallback = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        try
        {
            var admission = coordinator.Start(
                "operation-blocking-shutdown-callback",
                "fingerprint",
                async token =>
                {
                    var delay = Task.Delay(Timeout.InfiniteTimeSpan, token);
                    using var registration = token.Register(() =>
                    {
                        callbackEntered.TrySetResult();
                        releaseCallback.Task.GetAwaiter().GetResult();
                    });
                    operationStarted.TrySetResult();
                    await delay;
                    return "must not complete successfully";
                });
            Assert.NotNull(admission.Record);
            await operationStarted.Task.WaitAsync(TestTimeout);
            using var stopTimeout = new CancellationTokenSource(
                TimeSpan.FromMilliseconds(100));

            var shutdown = Task.Run(
                () => coordinator.ShutdownAsync(stopTimeout.Token));
            await callbackEntered.Task.WaitAsync(TestTimeout);
            var first = await Task.WhenAny(
                shutdown,
                Task.Delay(TimeSpan.FromSeconds(1)));

            Assert.Same(shutdown, first);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                async () => await shutdown);
        }
        finally
        {
            releaseCallback.TrySetResult();
            await coordinator.ShutdownAsync().WaitAsync(TestTimeout);
        }
    }

    [Fact]
    public async Task Shutdown_CancelsAdmittedWorkAndRejectsLaterAdmission()
    {
        var coordinator = new AgentOperationCoordinator<string>(
            completedRetention: TimeSpan.FromMinutes(5),
            maxCompletedEntries: 8);
        var operationStarted = new TaskCompletionSource<CancellationToken>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        try
        {
            var admission = coordinator.Start(
                "operation-shutdown",
                "fingerprint",
                async token =>
                {
                    operationStarted.SetResult(token);
                    await Task.Delay(Timeout.InfiniteTimeSpan, token);
                    return "must not complete successfully";
                });
            Assert.NotNull(admission.Record);
            var record = admission.Record!;
            var operationToken = await operationStarted.Task.WaitAsync(TestTimeout);

            await coordinator.ShutdownAsync().WaitAsync(TestTimeout);

            Assert.True(operationToken.IsCancellationRequested);
            Assert.Equal(AgentOperationStatus.Cancelled, (await record.Completion).Status);

            var rejected = coordinator.Start(
                "operation-after-shutdown",
                "fingerprint",
                _ => Task.FromResult("must not run"));
            Assert.Equal(AgentOperationAdmissionOutcome.Rejected, rejected.Outcome);
            Assert.Null(rejected.Record);
        }
        finally
        {
            await coordinator.ShutdownAsync().WaitAsync(TestTimeout);
        }
    }

    [Fact]
    public async Task RetentionAndCountEvictionKeepOnlyRecentCompletedRecords()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 8, 27, 0, 0, 0, TimeSpan.Zero));
        var coordinator = new AgentOperationCoordinator<string>(
            completedRetention: TimeSpan.FromSeconds(10),
            maxCompletedEntries: 2,
            timeProvider: clock);

        try
        {
            await CompleteAsync(coordinator, "old", "old");
            clock.Advance(TimeSpan.FromSeconds(1));
            await CompleteAsync(coordinator, "middle", "middle");
            clock.Advance(TimeSpan.FromSeconds(1));
            await CompleteAsync(coordinator, "new", "new");

            Assert.Null(coordinator.TryGet("old"));
            Assert.NotNull(coordinator.TryGet("middle"));
            Assert.NotNull(coordinator.TryGet("new"));

            clock.Advance(TimeSpan.FromSeconds(9));

            Assert.Null(coordinator.TryGet("middle"));
            Assert.NotNull(coordinator.TryGet("new"));
        }
        finally
        {
            await coordinator.ShutdownAsync().WaitAsync(TestTimeout);
        }
    }

    [Fact]
    public async Task CountEviction_NeverRemovesRunningWork()
    {
        var coordinator = new AgentOperationCoordinator<string>(
            completedRetention: TimeSpan.FromMinutes(5),
            maxCompletedEntries: 1);
        var operationStarted = new TaskCompletionSource<object?>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<object?>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        try
        {
            var running = coordinator.Start(
                "running",
                "fingerprint-running",
                async _ =>
                {
                    operationStarted.SetResult(null);
                    await release.Task;
                    return "running-result";
                });
            Assert.NotNull(running.Record);
            var runningRecord = running.Record!;
            await operationStarted.Task.WaitAsync(TestTimeout);

            var completed = coordinator.Start(
                "completed",
                "fingerprint-completed",
                _ => Task.FromResult("completed-result"));
            Assert.NotNull(completed.Record);
            var completedRecord = completed.Record!;
            await completedRecord.Completion.WaitAsync(TestTimeout);

            Assert.NotNull(coordinator.TryGet("running"));
            Assert.Same(completedRecord, coordinator.TryGet("completed"));

            release.SetResult(null);
            Assert.Equal(
                AgentOperationStatus.Succeeded,
                (await runningRecord.Completion.WaitAsync(TestTimeout)).Status);
        }
        finally
        {
            release.TrySetResult(null);
            await coordinator.ShutdownAsync().WaitAsync(TestTimeout);
        }
    }

    private static async Task<AgentOperationRecord<string>> CompleteAsync(
        AgentOperationCoordinator<string> coordinator,
        string operationId,
        string result)
    {
        var admission = coordinator.Start(
            operationId,
            "fingerprint-" + operationId,
            _ => Task.FromResult(result));
        Assert.NotNull(admission.Record);
        var record = admission.Record!;
        return await record.Completion.WaitAsync(TestTimeout);
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private long _utcTicks;

        public ManualTimeProvider(DateTimeOffset initialUtc)
        {
            _utcTicks = initialUtc.UtcTicks;
        }

        public override DateTimeOffset GetUtcNow()
            => new(Interlocked.Read(ref _utcTicks), TimeSpan.Zero);

        public void Advance(TimeSpan amount)
            => Interlocked.Add(ref _utcTicks, amount.Ticks);
    }
}
