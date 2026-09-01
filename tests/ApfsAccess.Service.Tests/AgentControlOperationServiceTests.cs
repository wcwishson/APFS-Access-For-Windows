using System.Diagnostics;
using System.Text.Json;
using ApfsAccess.Ipc;

namespace ApfsAccess.Service.Tests;

public sealed class AgentControlOperationServiceTests
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan DeadlineTestLifetime = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan DeadlineResultTimeout = TimeSpan.FromSeconds(5);
    private static readonly DateTime DefaultExpiresAtUtc = DateTime.UtcNow.AddMinutes(4);
    private static readonly JsonSerializerOptions EvidenceJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };

    [Fact]
    public async Task ExpiryOfUncooperativeExecutor_ReturnsDurableUnreconciledEvidenceWithinDeadline()
    {
        var root = CreateEvidenceRoot();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executorCompleted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var request = CreateRequest(expiresAtUtc: DateTime.UtcNow.Add(DeadlineTestLifetime));
        var service = new AgentControlOperationService(
            async (operation, _) =>
            {
                started.TrySetResult();
                await release.Task;
                executorCompleted.TrySetResult();
                return Success(operation);
            },
            root);

        try
        {
            var elapsed = Stopwatch.StartNew();
            var execution = service.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);

            var pending = await execution.WaitAsync(DeadlineResultTimeout);
            elapsed.Stop();
            var persisted = ReadPayload(GetEvidencePath(root, request.OperationId));

            Assert.True(elapsed.Elapsed < DeadlineResultTimeout);
            Assert.False(executorCompleted.Task.IsCompleted);
            Assert.False(pending.Success);
            Assert.Equal(ApfsOperationStates.InProgress, pending.State);
            Assert.Equal(ApfsOperationCodes.OperationInProgress, pending.Code);
            Assert.Null(pending.CompletedAtUtc);
            Assert.True(pending.PendingDurability);
            Assert.Equal("not-proven", pending.FinalStatus);
            Assert.Equal("not-proven", pending.MountProof);
            Assert.Equal("not-proven", pending.OwnershipProof);
            Assert.Equal("not-proven", pending.DurabilityProof);
            Assert.Contains("deadline", pending.Diagnostic!, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("reconciliation", pending.Diagnostic!, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(pending, persisted);
            Assert.Equal(pending, service.Query(request.OperationId));

            release.TrySetResult();
            await WaitForQueryAsync(service, request.OperationId, result => result.Success);
        }
        finally
        {
            release.TrySetResult();
            await service.StopAsync(CancellationToken.None).WaitAsync(TestTimeout);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ReplayDuringUnreconciledExecution_ReusesPendingOwnershipAndRejectsConflict()
    {
        var root = CreateEvidenceRoot();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executionCount = 0;
        var request = CreateRequest(expiresAtUtc: DateTime.UtcNow.Add(DeadlineTestLifetime));
        var service = new AgentControlOperationService(
            async (operation, _) =>
            {
                Interlocked.Increment(ref executionCount);
                started.TrySetResult();
                await release.Task;
                return Success(operation);
            },
            root);

        try
        {
            var execution = service.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);
            var pending = await execution.WaitAsync(DeadlineResultTimeout);

            var replay = await service.ExecuteOrReplayAsync(request).WaitAsync(TimeSpan.FromSeconds(1));
            var conflict = await service.ExecuteOrReplayAsync(request with
            {
                Target = new ApfsControlTarget("device-2", "device-2|Other"),
            }).WaitAsync(TimeSpan.FromSeconds(1));

            Assert.Equal(1, Volatile.Read(ref executionCount));
            Assert.Equal(pending, replay);
            Assert.Equal(ApfsOperationStates.InProgress, replay.State);
            Assert.True(replay.PendingDurability);
            Assert.Equal(ApfsOperationStates.Failed, conflict.State);
            Assert.Equal(ApfsOperationCodes.OperationConflict, conflict.Code);
            Assert.Null(conflict.EvidencePath);

            release.TrySetResult();
            await WaitForQueryAsync(service, request.OperationId, result => result.Success);
            Assert.Equal(1, Volatile.Read(ref executionCount));
        }
        finally
        {
            release.TrySetResult();
            await service.StopAsync(CancellationToken.None).WaitAsync(TestTimeout);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task QueryDuringTerminalEvidenceCommit_WaitsForFinalTruth()
    {
        var root = CreateEvidenceRoot();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseExecutor = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var terminalCommitStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseTerminalCommit = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var request = CreateRequest(expiresAtUtc: DateTime.UtcNow.Add(DeadlineTestLifetime));
        var service = new AgentControlOperationService(
            async (operation, _) =>
            {
                started.TrySetResult();
                await releaseExecutor.Task;
                return Success(operation);
            },
            root,
            beforeEvidenceCommit: payload =>
            {
                if (payload.State != ApfsOperationStates.Succeeded)
                {
                    return;
                }

                terminalCommitStarted.TrySetResult();
                if (!releaseTerminalCommit.Task.Wait(TestTimeout))
                {
                    throw new TimeoutException("The terminal evidence commit test gate was not released.");
                }
            });

        try
        {
            var execution = service.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);
            var pending = await execution.WaitAsync(DeadlineResultTimeout);
            Assert.Equal(ApfsOperationStates.InProgress, pending.State);

            releaseExecutor.TrySetResult();
            await terminalCommitStarted.Task.WaitAsync(TestTimeout);

            var query = Task.Run(() => service.Query(request.OperationId));
            await Task.Delay(100);
            Assert.False(query.IsCompleted);

            releaseTerminalCommit.TrySetResult();
            var terminal = await query.WaitAsync(TestTimeout);
            Assert.NotNull(terminal);
            Assert.True(terminal.Success);
            Assert.Equal(ApfsOperationStates.Succeeded, terminal.State);
            Assert.Equal(terminal, ReadPayload(GetEvidencePath(root, request.OperationId)));
        }
        finally
        {
            releaseExecutor.TrySetResult();
            releaseTerminalCommit.TrySetResult();
            await service.StopAsync(CancellationToken.None).WaitAsync(TestTimeout);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task UncooperativeExecutorCompletion_ReconcilesPendingEvidenceToFinalTruth()
    {
        var root = CreateEvidenceRoot();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var request = CreateRequest(expiresAtUtc: DateTime.UtcNow.Add(DeadlineTestLifetime));
        var service = new AgentControlOperationService(
            async (operation, _) =>
            {
                started.TrySetResult();
                await release.Task;
                return Success(operation) with
                {
                    FinalStatus = "healthy-rw",
                    MountProof = "present",
                    OwnershipProof = "released",
                    DurabilityProof = "durable",
                    PendingDurability = false,
                };
            },
            root);

        try
        {
            var execution = service.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);
            var pending = await execution.WaitAsync(DeadlineResultTimeout);
            Assert.Equal(ApfsOperationStates.InProgress, pending.State);
            Assert.True(pending.PendingDurability);

            release.TrySetResult();
            var reconciled = await WaitForQueryAsync(service, request.OperationId, result => result.Success);
            var persisted = ReadPayload(GetEvidencePath(root, request.OperationId));

            Assert.Equal(ApfsOperationStates.Succeeded, reconciled.State);
            Assert.Equal(ApfsOperationCodes.OperationSucceeded, reconciled.Code);
            Assert.NotNull(reconciled.CompletedAtUtc);
            Assert.False(reconciled.PendingDurability);
            Assert.Equal("healthy-rw", reconciled.FinalStatus);
            Assert.Equal("present", reconciled.MountProof);
            Assert.Equal("released", reconciled.OwnershipProof);
            Assert.Equal("durable", reconciled.DurabilityProof);
            Assert.Equal(reconciled, persisted);
            Assert.Equal(reconciled, await service.ExecuteOrReplayAsync(request).WaitAsync(TimeSpan.FromSeconds(1)));
        }
        finally
        {
            release.TrySetResult();
            await service.StopAsync(CancellationToken.None).WaitAsync(TestTimeout);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task FailedFinalReconciliationPersistence_RetainsReplayOwnershipAfterCoordinatorEviction()
    {
        var root = CreateEvidenceRoot();
        var clock = new AdjustableTimeProvider(DateTimeOffset.UtcNow);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var terminalPersistenceAttempted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executionCount = 0;
        var request = CreateRequest(expiresAtUtc: clock.GetUtcNow().UtcDateTime.Add(DeadlineTestLifetime));
        var service = new AgentControlOperationService(
            async (operation, _) =>
            {
                Interlocked.Increment(ref executionCount);
                started.TrySetResult();
                await release.Task;
                return Success(operation);
            },
            root,
            timeProvider: clock,
            beforeEvidenceCommit: payload =>
            {
                if (payload.State is ApfsOperationStates.Succeeded
                    or ApfsOperationStates.Failed
                    or ApfsOperationStates.Cancelled)
                {
                    terminalPersistenceAttempted.TrySetResult();
                    throw new IOException("Injected final reconciliation persistence failure.");
                }
            });

        try
        {
            var execution = service.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);
            var pending = await execution.WaitAsync(DeadlineResultTimeout);
            Assert.Equal(ApfsOperationStates.InProgress, pending.State);

            release.TrySetResult();
            await terminalPersistenceAttempted.Task.WaitAsync(TestTimeout);
            await Task.Delay(100);
            clock.Advance(TimeSpan.FromHours(2));

            var queried = service.Query(request.OperationId);
            var replay = await service.ExecuteOrReplayAsync(request).WaitAsync(TimeSpan.FromSeconds(1));
            var conflict = await service.ExecuteOrReplayAsync(request with
            {
                Target = new ApfsControlTarget("device-2", "device-2|Other"),
            }).WaitAsync(TimeSpan.FromSeconds(1));

            Assert.NotNull(queried);
            Assert.Equal(ApfsOperationStates.InProgress, queried!.State);
            Assert.True(queried.PendingDurability);
            Assert.Equal(queried, replay);
            Assert.Equal(ApfsOperationCodes.OperationConflict, conflict.Code);
            Assert.Equal(1, Volatile.Read(ref executionCount));
            Assert.Equal(ApfsOperationStates.InProgress, ReadPayload(GetEvidencePath(root, request.OperationId)).State);
        }
        finally
        {
            release.TrySetResult();
            await service.StopAsync(CancellationToken.None).WaitAsync(TestTimeout);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PendingPublicationAndOwnership_AreAtomicAgainstQueryReplayAndStop()
    {
        var root = CreateEvidenceRoot();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var pendingPublished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var allowPublicationToReturn = new ManualResetEventSlim(initialState: false);
        var releaseExecutor = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executionCount = 0;
        var request = CreateRequest(expiresAtUtc: DateTime.UtcNow.Add(DeadlineTestLifetime));
        var service = new AgentControlOperationService(
            async (operation, _) =>
            {
                Interlocked.Increment(ref executionCount);
                started.TrySetResult();
                await releaseExecutor.Task;
                return Success(operation);
            },
            root,
            afterUnreconciledEvidenceCommit: payload =>
            {
                pendingPublished.TrySetResult();
                if (!allowPublicationToReturn.Wait(TestTimeout))
                {
                    throw new TimeoutException("The atomic pending-publication test gate was not released.");
                }
            });

        try
        {
            var execution = service.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);
            await pendingPublished.Task.WaitAsync(TestTimeout);

            var queriedDuringPublication = service.Query(request.OperationId);
            var replayDuringPublication = Task.Run(() => service.ExecuteOrReplayAsync(request));
            var conflictDuringPublication = Task.Run(() => service.ExecuteOrReplayAsync(request with
            {
                Target = new ApfsControlTarget("device-2", "device-2|Other"),
            }));
            await Task.Delay(100);

            Assert.NotNull(queriedDuringPublication);
            Assert.Equal(ApfsOperationStates.InProgress, queriedDuringPublication!.State);
            Assert.True(queriedDuringPublication.PendingDurability);
            Assert.False(replayDuringPublication.IsCompleted);
            Assert.False(conflictDuringPublication.IsCompleted);
            Assert.Equal(ApfsOperationStates.InProgress, ReadPayload(GetEvidencePath(root, request.OperationId)).State);

            allowPublicationToReturn.Set();
            var pending = await execution.WaitAsync(TestTimeout);
            var replay = await replayDuringPublication.WaitAsync(TestTimeout);
            var conflict = await conflictDuringPublication.WaitAsync(TestTimeout);

            Assert.Equal(ApfsOperationStates.InProgress, pending.State);
            Assert.Equal(pending, replay);
            Assert.Equal(ApfsOperationCodes.OperationConflict, conflict.Code);
            Assert.Equal(1, Volatile.Read(ref executionCount));

            using var stopTimeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => service.StopAsync(stopTimeout.Token));
            Assert.True(stopTimeout.IsCancellationRequested);
            var afterStop = service.Query(request.OperationId);
            Assert.NotNull(afterStop);
            Assert.Equal(ApfsOperationStates.InProgress, afterStop!.State);
            Assert.True(afterStop.PendingDurability);
            Assert.Equal(ApfsOperationStates.InProgress, ReadPayload(GetEvidencePath(root, request.OperationId)).State);

            releaseExecutor.TrySetResult();
            var reconciled = await WaitForQueryAsync(service, request.OperationId, result => result.Success);
            Assert.Equal(ApfsOperationStates.Succeeded, reconciled.State);
        }
        finally
        {
            allowPublicationToReturn.Set();
            releaseExecutor.TrySetResult();
            await service.StopAsync(CancellationToken.None).WaitAsync(TestTimeout);
            allowPublicationToReturn.Dispose();
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task StopAsync_DrainsReconciliationPublishedDuringCoordinatorShutdownBeforeReturning()
    {
        var root = CreateEvidenceRoot();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var pendingPublished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseExecutor = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var terminalPersistenceAttempted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var allowTerminalPersistence = new ManualResetEventSlim(initialState: false);
        Task? stop = null;
        var request = CreateRequest(expiresAtUtc: DateTime.UtcNow.AddMinutes(4));
        var service = new AgentControlOperationService(
            async (operation, _) =>
            {
                started.TrySetResult();
                await releaseExecutor.Task;
                return Success(operation) with
                {
                    FinalStatus = "healthy-rw",
                    MountProof = "present",
                    OwnershipProof = "released",
                    DurabilityProof = "durable",
                    PendingDurability = false,
                };
            },
            root,
            beforeEvidenceCommit: payload =>
            {
                if (payload.State is ApfsOperationStates.Succeeded
                    or ApfsOperationStates.Failed
                    or ApfsOperationStates.Cancelled)
                {
                    terminalPersistenceAttempted.TrySetResult();
                    if (!allowTerminalPersistence.Wait(TestTimeout))
                    {
                        throw new TimeoutException("The terminal-persistence test gate was not released.");
                    }
                }
            },
            afterUnreconciledEvidenceCommit: _ => pendingPublished.TrySetResult());

        try
        {
            var execution = service.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);
            using var stopTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            stop = service.StopAsync(stopTimeout.Token);

            await pendingPublished.Task.WaitAsync(TestTimeout);
            var pending = await execution.WaitAsync(TestTimeout);
            Assert.Equal(ApfsOperationStates.InProgress, pending.State);
            Assert.True(pending.PendingDurability);

            releaseExecutor.TrySetResult();
            await terminalPersistenceAttempted.Task.WaitAsync(TestTimeout);
            Assert.False(stop.IsCompleted);

            allowTerminalPersistence.Set();
            await stop.WaitAsync(TestTimeout);

            var terminal = service.Query(request.OperationId);
            Assert.NotNull(terminal);
            Assert.Equal(ApfsOperationStates.Succeeded, terminal!.State);
            Assert.Equal(ApfsOperationCodes.OperationSucceeded, terminal.Code);
            Assert.True(terminal.Success);
            Assert.False(terminal.PendingDurability);
            Assert.Equal(terminal, ReadPayload(GetEvidencePath(root, request.OperationId)));
        }
        finally
        {
            allowTerminalPersistence.Set();
            releaseExecutor.TrySetResult();
            if (stop is not null) await stop.WaitAsync(TestTimeout);
            await service.StopAsync(CancellationToken.None).WaitAsync(TestTimeout);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task StopAsync_UncooperativeExecutorHonorsCallerCancellationAndReconcilesAfterStop()
    {
        var root = CreateEvidenceRoot();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var request = CreateRequest();
        var service = new AgentControlOperationService(
            async (operation, _) =>
            {
                started.TrySetResult();
                await release.Task;
                return Success(operation);
            },
            root);

        try
        {
            var execution = service.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);
            using var stopTimeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            var elapsed = Stopwatch.StartNew();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => service.StopAsync(stopTimeout.Token));
            elapsed.Stop();
            var pending = await execution.WaitAsync(TimeSpan.FromSeconds(1));

            Assert.True(elapsed.Elapsed < TimeSpan.FromSeconds(2));
            Assert.True(stopTimeout.IsCancellationRequested);
            Assert.Equal(ApfsOperationStates.InProgress, pending.State);
            Assert.Equal(ApfsOperationCodes.OperationInProgress, pending.Code);
            Assert.Null(pending.CompletedAtUtc);
            Assert.True(pending.PendingDurability);
            Assert.Contains("shutdown", pending.Diagnostic!, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(pending, ReadPayload(GetEvidencePath(root, request.OperationId)));

            release.TrySetResult();
            var reconciled = await WaitForQueryAsync(service, request.OperationId, result => result.Success);
            Assert.Equal(ApfsOperationStates.Succeeded, reconciled.State);
            Assert.False(reconciled.PendingDurability);
            Assert.Equal(reconciled, ReadPayload(GetEvidencePath(root, request.OperationId)));
        }
        finally
        {
            release.TrySetResult();
            await service.StopAsync(CancellationToken.None).WaitAsync(TestTimeout);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ExpiryCancelsBlockedExecutorAndPersistsTruthfulTimeoutEvidence()
    {
        var root = CreateEvidenceRoot();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancellationObserved = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var laterWorkCount = 0;
        var expiresAtUtc = DateTime.UtcNow.Add(DeadlineTestLifetime);
        var request = CreateRequest() with { ExpiresAtUtc = expiresAtUtc };
        var service = new AgentControlOperationService(
            async (operation, token) =>
            {
                started.TrySetResult();
                try
                {
                    await release.Task.WaitAsync(token);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    cancellationObserved.TrySetResult();
                    throw;
                }

                Interlocked.Increment(ref laterWorkCount);
                return Success(operation);
            },
            root);

        try
        {
            var execution = service.ExecuteOrReplayAsync(request);
            var firstCompletion = await Task.WhenAny(started.Task, execution).WaitAsync(TestTimeout);
            if (ReferenceEquals(firstCompletion, execution))
            {
                var premature = await execution;
                Assert.Fail($"The operation completed before executor dispatch: {JsonSerializer.Serialize(premature)}");
            }

            var boundary = await execution.WaitAsync(TimeSpan.FromSeconds(3));
            await cancellationObserved.Task.WaitAsync(TestTimeout);
            var timeout = boundary.State == ApfsOperationStates.Failed
                ? boundary
                : await WaitForQueryAsync(
                    service,
                    request.OperationId,
                    result => result.State == ApfsOperationStates.Failed && result.Code == ApfsOperationCodes.Timeout);

            release.TrySetResult();

            Assert.False(timeout.Success);
            Assert.Equal(ApfsOperationStates.Failed, timeout.State);
            Assert.Equal(ApfsOperationCodes.Timeout, timeout.Code);
            Assert.Equal(expiresAtUtc, timeout.ExpiresAtUtc);
            Assert.Equal("not-proven", timeout.FinalStatus);
            Assert.Equal("not-proven", timeout.MountProof);
            Assert.Equal("not-proven", timeout.OwnershipProof);
            Assert.Equal("not-proven", timeout.DurabilityProof);
            Assert.True(timeout.PendingDurability);
            Assert.Equal(0, Volatile.Read(ref laterWorkCount));
            Assert.False(string.IsNullOrWhiteSpace(timeout.EvidencePath));
            Assert.Equal(timeout, service.Query(request.OperationId));
        }
        finally
        {
            release.TrySetResult();
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task AlreadyExpiredRequestPersistsTimeoutWithoutExecutorDispatch()
    {
        var root = CreateEvidenceRoot();
        var executionCount = 0;
        var expiresAtUtc = DateTime.UtcNow.AddSeconds(-1);
        var request = CreateRequest() with { ExpiresAtUtc = expiresAtUtc };
        var service = new AgentControlOperationService(
            (operation, _) =>
            {
                Interlocked.Increment(ref executionCount);
                return Task.FromResult(Success(operation));
            },
            root);

        try
        {
            var timeout = await service.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);

            Assert.Equal(0, Volatile.Read(ref executionCount));
            Assert.False(timeout.Success);
            Assert.Equal(ApfsOperationStates.Failed, timeout.State);
            Assert.Equal(ApfsOperationCodes.Timeout, timeout.Code);
            Assert.Equal(expiresAtUtc, timeout.ExpiresAtUtc);
            Assert.Equal("not-proven", timeout.MountProof);
            Assert.Equal("not-proven", timeout.OwnershipProof);
            Assert.Equal("not-proven", timeout.DurabilityProof);
            Assert.True(timeout.PendingDurability);
            Assert.False(string.IsNullOrWhiteSpace(timeout.EvidencePath));
            Assert.True(File.Exists(timeout.EvidencePath));
            Assert.Equal(timeout, service.Query(request.OperationId));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ExactReplay_ExecutesOnceAndReturnsPersistedTerminalResult()
    {
        var root = CreateEvidenceRoot();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executionCount = 0;
        var request = CreateRequest();
        var service = new AgentControlOperationService(
            async (operation, token) =>
            {
                Interlocked.Increment(ref executionCount);
                started.TrySetResult();
                await release.Task.WaitAsync(token);
                return Success(operation);
            },
            root);

        try
        {
            var first = service.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);
            var replay = service.ExecuteOrReplayAsync(request);

            release.TrySetResult();
            var results = await Task.WhenAll(first, replay).WaitAsync(TestTimeout);

            Assert.Equal(1, Volatile.Read(ref executionCount));
            Assert.All(results, result =>
            {
                Assert.True(result.Success);
                Assert.Equal(ApfsOperationStates.Succeeded, result.State);
                Assert.False(string.IsNullOrWhiteSpace(result.EvidencePath));
                Assert.True(File.Exists(result.EvidencePath));
            });
            Assert.Equal(results[0].EvidencePath, results[1].EvidencePath);
            Assert.All(results, result => Assert.Equal(
                ApfsOperationFingerprint.Compute(
                    request.Command,
                    request.Target,
                    request.RequestedMode,
                    request.ExpiresAtUtc!.Value),
                result.Fingerprint));
            Assert.Empty(Directory.GetFiles(root, "*.tmp", SearchOption.TopDirectoryOnly));

            await service.StopAsync(CancellationToken.None);

            var restartedExecutionCount = 0;
            var restarted = new AgentControlOperationService(
                (operation, _) =>
                {
                    Interlocked.Increment(ref restartedExecutionCount);
                    return Task.FromResult(Success(operation));
                },
                root);
            var restored = await restarted.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);

            Assert.True(restored.Success);
            Assert.Equal(0, Volatile.Read(ref restartedExecutionCount));
            Assert.Equal(results[0].EvidencePath, restored.EvidencePath);
            await restarted.StopAsync(CancellationToken.None);
        }
        finally
        {
            release.TrySetResult();
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ReusingOperationIdWithDifferentTarget_ReturnsConflictWithoutExecutingAgain()
    {
        var root = CreateEvidenceRoot();
        var executionCount = 0;
        var service = new AgentControlOperationService(
            (operation, _) =>
            {
                Interlocked.Increment(ref executionCount);
                return Task.FromResult(Success(operation));
            },
            root);
        var firstRequest = CreateRequest();
        var conflictingRequest = firstRequest with
        {
            Target = new ApfsControlTarget("device-2", "device-2|Main"),
        };

        try
        {
            Assert.True((await service.ExecuteOrReplayAsync(firstRequest)).Success);
            var conflict = await service.ExecuteOrReplayAsync(conflictingRequest);
            var expiryConflict = await service.ExecuteOrReplayAsync(firstRequest with
            {
                ExpiresAtUtc = firstRequest.ExpiresAtUtc!.Value.AddTicks(1),
            });

            Assert.False(conflict.Success);
            Assert.Equal(ApfsOperationCodes.OperationConflict, conflict.Code);
            Assert.Equal(ApfsOperationStates.Failed, conflict.State);
            Assert.False(expiryConflict.Success);
            Assert.Equal(ApfsOperationCodes.OperationConflict, expiryConflict.Code);
            Assert.Equal(1, Volatile.Read(ref executionCount));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ExpiredOperationIdRetainsFingerprintOwnershipUntilRetentionBoundary()
    {
        var root = CreateEvidenceRoot();
        var clock = new AdjustableTimeProvider(DateTimeOffset.UtcNow);
        var executionCount = 0;
        var service = new AgentControlOperationService(
            (operation, _) =>
            {
                Interlocked.Increment(ref executionCount);
                return Task.FromResult(Success(operation));
            },
            root,
            clock,
            new AgentControlOperationStoreLimits(TimeSpan.FromMinutes(1), 1, 64 * 1024));
        var request = CreateRequest(expiresAtUtc: clock.GetUtcNow().UtcDateTime.AddMinutes(1));
        var evidencePath = GetEvidencePath(root, request.OperationId);

        try
        {
            var first = await service.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);
            Assert.True(first.Success);
            Assert.Equal(1, Volatile.Read(ref executionCount));

            clock.Advance(TimeSpan.FromMinutes(2));
            var exactReplay = await service.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);
            var changedExpiry = request with
            {
                ExpiresAtUtc = clock.GetUtcNow().UtcDateTime.AddMinutes(1),
            };
            var retainedConflict = await service.ExecuteOrReplayAsync(changedExpiry).WaitAsync(TestTimeout);

            Assert.True(exactReplay.Success);
            Assert.Equal(first.EvidencePath, exactReplay.EvidencePath);
            Assert.False(retainedConflict.Success);
            Assert.Equal(ApfsOperationCodes.OperationConflict, retainedConflict.Code);
            Assert.Equal(1, Volatile.Read(ref executionCount));

            clock.Advance(TimeSpan.FromHours(2));
            var evidenceConflict = await service.ExecuteOrReplayAsync(changedExpiry with
            {
                ExpiresAtUtc = clock.GetUtcNow().UtcDateTime.AddMinutes(1),
            }).WaitAsync(TestTimeout);

            Assert.False(evidenceConflict.Success);
            Assert.Equal(ApfsOperationCodes.OperationConflict, evidenceConflict.Code);
            Assert.True(File.Exists(evidencePath));
            Assert.Equal(1, Volatile.Read(ref executionCount));

            var pruningRequest = CreateRequest(
                expiresAtUtc: clock.GetUtcNow().UtcDateTime.AddMinutes(1));
            Assert.True((await service.ExecuteOrReplayAsync(pruningRequest).WaitAsync(TestTimeout)).Success);
            Assert.False(File.Exists(evidencePath));
            Assert.Equal(2, Volatile.Read(ref executionCount));

            clock.Advance(TimeSpan.FromHours(2));
            var replacement = request with
            {
                ExpiresAtUtc = clock.GetUtcNow().UtcDateTime.AddMinutes(1),
            };
            var reused = await service.ExecuteOrReplayAsync(replacement).WaitAsync(TestTimeout);

            Assert.True(reused.Success);
            Assert.Equal(3, Volatile.Read(ref executionCount));
            Assert.Equal(ApfsOperationFingerprint.Compute(replacement), reused.Fingerprint);
            Assert.True(File.Exists(evidencePath));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ExplicitCancellation_IsQueryableAndDoesNotDependOnClientLifetime()
    {
        var root = CreateEvidenceRoot();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var request = CreateRequest();
        var service = new AgentControlOperationService(
            async (_, token) =>
            {
                started.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                throw new InvalidOperationException("unreachable");
            },
            root);

        try
        {
            var execution = service.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);

            using var cancellationTimeout = new CancellationTokenSource(TestTimeout);
            var cancellation = await service.CancelAsync(
                request.OperationId,
                cancellationTimeout.Token);
            var terminal = await execution.WaitAsync(TestTimeout);
            var queried = service.Query(request.OperationId);

            Assert.Equal(ApfsOperationStates.Cancelled, cancellation.State);
            Assert.Equal(ApfsOperationCodes.OperationCancelled, cancellation.Code);
            Assert.False(cancellation.Success);
            Assert.False(string.IsNullOrWhiteSpace(cancellation.EvidencePath));
            Assert.Equal(ApfsOperationStates.Cancelled, terminal.State);
            Assert.Equal(ApfsOperationCodes.OperationCancelled, terminal.Code);
            Assert.Equal(terminal.EvidencePath, cancellation.EvidencePath);
            Assert.Equal(terminal.EvidencePath, queried!.EvidencePath);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task CancelAsync_NotCancellableQuitReturnsCoherentNonterminalSnapshot()
    {
        var root = CreateEvidenceRoot();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var request = new ControlOperationRequestPayload(
            Guid.NewGuid().ToString("D"),
            ApfsControlCommands.Quit,
            Target: null,
            RequestedMode: null,
            ExpiresAtUtc: DefaultExpiresAtUtc);
        var service = new AgentControlOperationService(
            async (operation, _) =>
            {
                started.TrySetResult();
                await release.Task;
                return Success(operation);
            },
            root);

        try
        {
            var execution = service.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);
            using var cancellationTimeout = new CancellationTokenSource(TestTimeout);

            var cancellation = await service.CancelAsync(
                request.OperationId,
                cancellationTimeout.Token);
            var queried = service.Query(request.OperationId);

            Assert.False(cancellation.Success);
            Assert.Equal(ApfsOperationStates.InProgress, cancellation.State);
            Assert.Equal(ApfsOperationCodes.OperationInProgress, cancellation.Code);
            Assert.Null(cancellation.CompletedAtUtc);
            Assert.False(string.IsNullOrWhiteSpace(cancellation.EvidencePath));
            Assert.Contains("cannot be explicitly cancelled", cancellation.Diagnostic!, StringComparison.OrdinalIgnoreCase);
            Assert.NotNull(queried);
            Assert.Equal(ApfsOperationStates.InProgress, queried!.State);
            Assert.Equal(ApfsOperationCodes.OperationInProgress, queried.Code);
            Assert.Equal(queried.EvidencePath, cancellation.EvidencePath);
            Assert.False(execution.IsCompleted);

            release.TrySetResult();
            Assert.True((await execution.WaitAsync(TestTimeout)).Success);
        }
        finally
        {
            release.TrySetResult();
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task QuitAdmission_RejectsNewMutationBeforeQuitCompletes()
    {
        var root = CreateEvidenceRoot();
        var quitStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseQuit = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var mountExecutions = 0;
        var quit = new ControlOperationRequestPayload(
            Guid.NewGuid().ToString("D"),
            ApfsControlCommands.Quit,
            Target: null,
            RequestedMode: null,
            ExpiresAtUtc: DefaultExpiresAtUtc);
        var mount = CreateRequest(
            requestedMode: ApfsControlModes.ReadWrite,
            command: ApfsControlCommands.Mount);
        var service = new AgentControlOperationService(
            async (operation, _) =>
            {
                if (operation.Command == ApfsControlCommands.Quit)
                {
                    quitStarted.TrySetResult();
                    await releaseQuit.Task;
                    return Success(operation);
                }

                Interlocked.Increment(ref mountExecutions);
                return Success(operation);
            },
            root);

        try
        {
            var quitExecution = service.ExecuteOrReplayAsync(quit);
            await quitStarted.Task.WaitAsync(TestTimeout);

            var rejected = await service.ExecuteOrReplayAsync(mount).WaitAsync(TestTimeout);

            Assert.False(rejected.Success);
            Assert.Equal(ApfsOperationStates.Failed, rejected.State);
            Assert.Equal(ApfsOperationCodes.ServiceUnavailable, rejected.Code);
            Assert.Contains("stopping", rejected.Diagnostic!, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(0, Volatile.Read(ref mountExecutions));

            releaseQuit.TrySetResult();
            Assert.True((await quitExecution.WaitAsync(TestTimeout)).Success);
        }
        finally
        {
            releaseQuit.TrySetResult();
            await service.StopAsync(CancellationToken.None).WaitAsync(TestTimeout);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task CancelAsync_AlreadyTerminalReturnsExistingTerminal()
    {
        var root = CreateEvidenceRoot();
        var request = CreateRequest();
        var service = new AgentControlOperationService(
            (operation, _) => Task.FromResult(Success(operation)),
            root);

        try
        {
            var terminal = await service.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);
            using var cancellationTimeout = new CancellationTokenSource(TestTimeout);

            var cancellation = await service.CancelAsync(
                request.OperationId,
                cancellationTimeout.Token);

            Assert.True(cancellation.Success);
            Assert.Equal(ApfsOperationStates.Succeeded, cancellation.State);
            Assert.Equal(ApfsOperationCodes.OperationSucceeded, cancellation.Code);
            Assert.Equal(terminal.EvidencePath, cancellation.EvidencePath);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task CancelAsync_UncooperativeExecutorIsCallerBoundedWithoutFabricatingCompletion()
    {
        var root = CreateEvidenceRoot();
        var request = CreateRequest();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var service = new AgentControlOperationService(
            async (operation, _) =>
            {
                started.TrySetResult();
                await release.Task;
                return Success(operation);
            },
            root);

        try
        {
            var execution = service.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);

            var pending = service.Cancel(request.OperationId);
            Assert.Equal(ApfsOperationStates.InProgress, pending.State);
            Assert.Equal(ApfsOperationCodes.OperationInProgress, pending.Code);
            Assert.False(pending.Success);

            using var cancellationTimeout = new CancellationTokenSource(
                TimeSpan.FromMilliseconds(100));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => service.CancelAsync(request.OperationId, cancellationTimeout.Token));

            var queried = service.Query(request.OperationId);
            Assert.NotNull(queried);
            Assert.Equal(ApfsOperationStates.InProgress, queried!.State);
            Assert.Equal(ApfsOperationCodes.OperationInProgress, queried.Code);
            Assert.False(execution.IsCompleted);

            release.TrySetResult();
            var terminal = await execution.WaitAsync(TestTimeout);
            Assert.True(terminal.Success);
            Assert.Equal(ApfsOperationStates.Succeeded, service.Query(request.OperationId)!.State);
        }
        finally
        {
            release.TrySetResult();
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task AcceptedEvidence_IsReadableBeforeExecutorBegins()
    {
        var root = CreateEvidenceRoot();
        var request = CreateRequest();
        var evidencePath = GetEvidencePath(root, request.OperationId);
        var observed = new TaskCompletionSource<OperationResultPayload>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var service = new AgentControlOperationService(
            async (operation, token) =>
            {
                try
                {
                    if (!File.Exists(evidencePath))
                    {
                        throw new InvalidOperationException("Accepted evidence was not present before execution.");
                    }

                    observed.TrySetResult(ReadPayload(evidencePath));
                }
                catch (Exception exception)
                {
                    observed.TrySetException(exception);
                    throw;
                }

                await release.Task.WaitAsync(token);
                return Success(operation);
            },
            root);

        try
        {
            var execution = service.ExecuteOrReplayAsync(request);
            var accepted = await observed.Task.WaitAsync(TestTimeout);
            release.TrySetResult();
            Assert.True((await execution.WaitAsync(TestTimeout)).Success);

            Assert.Equal(request.OperationId, accepted.OperationId);
            Assert.Contains(
                accepted.State,
                new[] { ApfsOperationStates.Accepted, ApfsOperationStates.InProgress });
            Assert.False(accepted.Success);
            Assert.True(accepted.PendingDurability);
            Assert.Equal("not-proven", accepted.FinalStatus);
            Assert.Equal("not-proven", accepted.MountProof);
            Assert.Equal("not-proven", accepted.OwnershipProof);
            Assert.Equal("not-proven", accepted.DurabilityProof);
            Assert.Equal(
                ApfsOperationFingerprint.Compute(
                    request.Command,
                    request.Target,
                    request.RequestedMode,
                    request.ExpiresAtUtc!.Value),
                accepted.Fingerprint);
            Assert.Equal(evidencePath, accepted.EvidencePath);
            Assert.True(File.Exists(evidencePath));
        }
        finally
        {
            release.TrySetResult();
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ConcurrentExactReplay_ExecutesOnce()
    {
        var root = CreateEvidenceRoot();
        var operationId = Guid.NewGuid().ToString("D");
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executionCount = 0;
        var service = new AgentControlOperationService(
            async (operation, token) =>
            {
                Interlocked.Increment(ref executionCount);
                started.TrySetResult();
                await release.Task.WaitAsync(token);
                return Success(operation);
            },
            root);

        try
        {
            var requests = Enumerable.Range(0, 8)
                .Select(_ => service.ExecuteOrReplayAsync(CreateRequest(operationId)))
                .ToArray();
            await started.Task.WaitAsync(TestTimeout);
            release.TrySetResult();

            var results = await Task.WhenAll(requests).WaitAsync(TestTimeout);

            Assert.Equal(1, Volatile.Read(ref executionCount));
            Assert.All(results, result => Assert.True(result.Success));
            Assert.Single(results.Select(result => result.EvidencePath).Distinct());
        }
        finally
        {
            release.TrySetResult();
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task GuidAliases_UseOneCanonicalEvidenceFileAndExecution()
    {
        var root = CreateEvidenceRoot();
        var guid = Guid.NewGuid();
        var aliases = new[]
        {
            guid.ToString("N"),
            $"{{{guid.ToString("D").ToUpperInvariant()}}}",
            guid.ToString("D").ToUpperInvariant(),
        };
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executionCount = 0;
        var service = new AgentControlOperationService(
            async (operation, token) =>
            {
                Interlocked.Increment(ref executionCount);
                started.TrySetResult();
                await release.Task.WaitAsync(token);
                return Success(operation);
            },
            root);

        try
        {
            var first = service.ExecuteOrReplayAsync(CreateRequest(aliases[0]));
            await started.Task.WaitAsync(TestTimeout);
            var second = service.ExecuteOrReplayAsync(CreateRequest(aliases[1]));
            var third = service.ExecuteOrReplayAsync(CreateRequest(aliases[2]));
            release.TrySetResult();

            var results = await Task.WhenAll(first, second, third).WaitAsync(TestTimeout);
            var expectedId = guid.ToString("D").ToLowerInvariant();
            var expectedPath = Path.Combine(root, $"{expectedId}.json");

            Assert.Equal(1, Volatile.Read(ref executionCount));
            Assert.All(results, result =>
            {
                Assert.Equal(expectedId, result.OperationId);
                Assert.Equal(expectedPath, result.EvidencePath);
                Assert.True(result.Success);
            });
            Assert.True(File.Exists(expectedPath));
            Assert.Empty(Directory.GetFiles(root, "*.tmp", SearchOption.TopDirectoryOnly));
        }
        finally
        {
            release.TrySetResult();
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task InvalidGuidModeAndTarget_AreRejectedBeforePersistenceOrExecution()
    {
        var root = CreateEvidenceRoot();
        var executionCount = 0;
        var service = new AgentControlOperationService(
            (operation, _) =>
            {
                Interlocked.Increment(ref executionCount);
                return Task.FromResult(Success(operation));
            },
            root);
        var cases = new[]
        {
            (Request: CreateRequest("not-a-guid"), Code: ApfsOperationCodes.InvalidOperationId),
            (Request: CreateRequest(requestedMode: "write-only"), Code: ApfsOperationCodes.InvalidArguments),
            (Request: CreateRequest(target: new ApfsControlTarget("device-1", "device-2|Main")), Code: ApfsOperationCodes.AmbiguousTarget),
            (Request: CreateRequest(target: new ApfsControlTarget(" ", "device-1|Main")), Code: ApfsOperationCodes.AmbiguousTarget),
            (Request: CreateRequest(target: new ApfsControlTarget("device-1", " ")), Code: ApfsOperationCodes.AmbiguousTarget),
        };

        try
        {
            foreach (var testCase in cases)
            {
                var result = await service.ExecuteOrReplayAsync(testCase.Request);
                Assert.False(result.Success);
                Assert.Equal(testCase.Code, result.Code);
                Assert.Equal(ApfsOperationStates.Failed, result.State);
            }

            Assert.Equal(0, Volatile.Read(ref executionCount));
            Assert.Empty(Directory.GetFiles(root, "*.json", SearchOption.TopDirectoryOnly));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("ro", "read-only")]
    [InlineData("readonly", "read-only")]
    [InlineData("read_only", "read-only")]
    [InlineData("read only", "read-only")]
    [InlineData("rw", "read-write")]
    [InlineData("readwrite", "read-write")]
    [InlineData("read_write", "read-write")]
    [InlineData("read write", "read-write")]
    public async Task ModeAliases_AreCanonicalizedAndRecoveryIdentityPreservesCase(
        string requestedMode,
        string expectedMode)
    {
        var root = CreateEvidenceRoot();
        var observed = new TaskCompletionSource<ControlOperationRequestPayload>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var service = new AgentControlOperationService(
            (operation, _) =>
            {
                observed.TrySetResult(operation);
                return Task.FromResult(Success(operation));
            },
            root);
        var request = CreateRequest(
            target: new ApfsControlTarget("Device-1", "Device-1|Main", "  Opaque-MixedCase  "),
            requestedMode: requestedMode);

        try
        {
            var result = await service.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);
            var executed = await observed.Task.WaitAsync(TestTimeout);

            Assert.True(result.Success);
            Assert.Equal(expectedMode, executed.RequestedMode);
            Assert.Equal("Opaque-MixedCase", executed.Target!.RecoveryIdentity);
            Assert.Equal(expectedMode, result.RequestedMode);
            Assert.Equal("Opaque-MixedCase", result.Target!.RecoveryIdentity);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PersistedNonterminalEvidence_IsFailedClosedAfterRestartWithoutReissue()
    {
        var root = CreateEvidenceRoot();
        var freshRoot = CreateEvidenceRoot();
        var request = CreateRequest();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var sourceExecutionCount = 0;
        var source = new AgentControlOperationService(
            async (_, token) =>
            {
                Interlocked.Increment(ref sourceExecutionCount);
                started.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                throw new InvalidOperationException("unreachable");
            },
            root);

        try
        {
            var sourceExecution = source.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);
            var sourceEvidence = source.Query(request.OperationId);
            Assert.NotNull(sourceEvidence);
            Assert.NotNull(sourceEvidence!.EvidencePath);

            var destinationPath = GetEvidencePath(freshRoot, request.OperationId);
            var copied = ReadPayload(sourceEvidence.EvidencePath!) with { EvidencePath = destinationPath };
            WritePayload(destinationPath, copied);
            Assert.Contains(
                copied.State,
                new[] { ApfsOperationStates.Accepted, ApfsOperationStates.InProgress });

            await source.StopAsync(CancellationToken.None);
            await sourceExecution.WaitAsync(TestTimeout);

            var restartedExecutionCount = 0;
            var restarted = new AgentControlOperationService(
                (operation, _) =>
                {
                    Interlocked.Increment(ref restartedExecutionCount);
                    return Task.FromResult(Success(operation));
                },
                freshRoot);
            try
            {
                var recovered = await restarted.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);
                var persisted = ReadPayload(destinationPath);

                Assert.False(recovered.Success);
                Assert.Equal(ApfsOperationStates.Failed, recovered.State);
                Assert.Equal(ApfsOperationCodes.OperationFailed, recovered.Code);
                Assert.Equal(destinationPath, recovered.EvidencePath);
                Assert.Equal(ApfsOperationStates.Failed, persisted.State);
                Assert.False(persisted.Success);
                Assert.Equal(0, Volatile.Read(ref restartedExecutionCount));
            }
            finally
            {
                await restarted.StopAsync(CancellationToken.None);
            }
        }
        finally
        {
            await source.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
            Directory.Delete(freshRoot, recursive: true);
        }
    }

    [Fact]
    public async Task ExecuteReplayCorruptEvidence_PreservesOriginalRecordWithoutExecution()
    {
        var root = CreateEvidenceRoot();
        var request = CreateRequest();
        var first = new AgentControlOperationService(
            (operation, _) => Task.FromResult(Success(operation)),
            root);
        var evidencePath = string.Empty;
        byte[] originalBytes = [];

        try
        {
            var original = await first.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);
            evidencePath = Assert.IsType<string>(original.EvidencePath);
            var tampered = ReadPayload(evidencePath) with
            {
                Target = new ApfsControlTarget("device-1", "device-1|Tampered"),
            };
            WritePayload(evidencePath, tampered);
            originalBytes = File.ReadAllBytes(evidencePath);
            await first.StopAsync(CancellationToken.None);
        }
        finally
        {
            await first.StopAsync(CancellationToken.None);
        }

        var restartedExecutionCount = 0;
        var restarted = new AgentControlOperationService(
            (operation, _) =>
            {
                Interlocked.Increment(ref restartedExecutionCount);
                return Task.FromResult(Success(operation));
            },
            root);
        try
        {
            var result = await restarted.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);

            AssertSyntheticCorruptResponse(result, request.OperationId);
            Assert.Equal(0, Volatile.Read(ref restartedExecutionCount));
            Assert.Equal(originalBytes, File.ReadAllBytes(evidencePath));
        }
        finally
        {
            await restarted.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task QueryAndCancelCorruptEvidence_PreserveOriginalRecord()
    {
        var root = CreateEvidenceRoot();
        var operationId = Guid.NewGuid().ToString("D");
        var evidencePath = GetEvidencePath(root, operationId);
        File.WriteAllText(evidencePath, "{ this is not valid operation evidence");
        var originalBytes = File.ReadAllBytes(evidencePath);
        var executionCount = 0;
        var service = new AgentControlOperationService(
            (operation, _) =>
            {
                Interlocked.Increment(ref executionCount);
                return Task.FromResult(Success(operation));
            },
            root);

        try
        {
            var queried = service.Query(operationId);
            var cancelled = service.Cancel(operationId);

            Assert.NotNull(queried);
            AssertSyntheticCorruptResponse(queried!, operationId);
            AssertSyntheticCorruptResponse(cancelled, operationId);
            Assert.Equal(originalBytes, File.ReadAllBytes(evidencePath));
            Assert.Equal(0, Volatile.Read(ref executionCount));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Query_UsesOnlyCanonicalEvidencePath()
    {
        var root = CreateEvidenceRoot();
        var operationId = Guid.NewGuid();
        var aliasPath = Path.Combine(root, $"{operationId:N}.json");
        File.WriteAllText(aliasPath, "{ alias evidence must not be scanned");
        var service = new AgentControlOperationService(
            (operation, _) => Task.FromResult(Success(operation)),
            root);

        try
        {
            var result = service.Query(operationId.ToString("D"));

            Assert.NotNull(result);
            Assert.Null(result!.EvidencePath);
            Assert.Contains("unknown", result.Diagnostic!, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("corrupt", result.Diagnostic!, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task EvidenceStateCodeMismatch_IsFailedClosedWithoutExecution()
    {
        var cases = new[]
        {
            (State: ApfsOperationStates.Succeeded, Code: ApfsOperationCodes.OperationFailed, Success: true, Started: (DateTime?)DateTime.UtcNow, Completed: (DateTime?)DateTime.UtcNow),
            (State: ApfsOperationStates.Failed, Code: ApfsOperationCodes.OperationSucceeded, Success: false, Started: (DateTime?)DateTime.UtcNow, Completed: (DateTime?)DateTime.UtcNow),
            (State: ApfsOperationStates.Failed, Code: "persisted-private-code", Success: false, Started: (DateTime?)DateTime.UtcNow, Completed: (DateTime?)DateTime.UtcNow),
            (State: ApfsOperationStates.Accepted, Code: ApfsOperationCodes.OperationSucceeded, Success: false, Started: (DateTime?)null, Completed: (DateTime?)null),
            (State: ApfsOperationStates.InProgress, Code: ApfsOperationCodes.OperationSucceeded, Success: false, Started: (DateTime?)DateTime.UtcNow, Completed: (DateTime?)null),
        };

        foreach (var testCase in cases)
        {
            var root = CreateEvidenceRoot();
            var request = CreateRequest();
            var seed = new AgentControlOperationService(
                (operation, _) => Task.FromResult(Success(operation)),
                root);
            try
            {
                var original = await seed.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);
                var evidencePath = Assert.IsType<string>(original.EvidencePath);
                WritePayload(
                    evidencePath,
                    ReadPayload(evidencePath) with
                    {
                        State = testCase.State,
                        Code = testCase.Code,
                        Success = testCase.Success,
                        StartedAtUtc = testCase.Started,
                        CompletedAtUtc = testCase.Completed,
                    });
                var originalBytes = File.ReadAllBytes(evidencePath);
                await seed.StopAsync(CancellationToken.None);

                var executionCount = 0;
                var restarted = new AgentControlOperationService(
                    (operation, _) =>
                    {
                        Interlocked.Increment(ref executionCount);
                        return Task.FromResult(Success(operation));
                    },
                    root);
                try
                {
                    var result = await restarted.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);

                    AssertSyntheticCorruptResponse(result, request.OperationId);
                    Assert.Equal(originalBytes, File.ReadAllBytes(evidencePath));
                    Assert.Equal(0, Volatile.Read(ref executionCount));
                }
                finally
                {
                    await restarted.StopAsync(CancellationToken.None);
                }
            }
            finally
            {
                await seed.StopAsync(CancellationToken.None);
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Theory]
    [InlineData(ApfsOperationStates.Succeeded, ApfsOperationCodes.Timeout, true)]
    [InlineData(ApfsOperationStates.Failed, ApfsOperationCodes.OperationSucceeded, false)]
    [InlineData(ApfsOperationStates.Failed, "executor-private-code", false)]
    [InlineData(ApfsOperationStates.Cancelled, ApfsOperationCodes.Timeout, false)]
    [InlineData(ApfsOperationStates.InProgress, ApfsOperationCodes.OperationInProgress, false)]
    public async Task InvalidExecutorStateCodePairs_BecomeDurableOperationFailed(
        string state,
        string code,
        bool success)
    {
        var root = CreateEvidenceRoot();
        var request = CreateRequest();
        var service = new AgentControlOperationService(
            (operation, _) => Task.FromResult(Success(operation) with
            {
                State = state,
                Code = code,
                Success = success,
            }),
            root);

        try
        {
            var result = await service.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);
            var evidencePath = Assert.IsType<string>(result.EvidencePath);
            var persisted = ReadPayload(evidencePath);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationStates.Failed, result.State);
            Assert.Equal(ApfsOperationCodes.OperationFailed, result.Code);
            Assert.Contains("executor result", result.Diagnostic!, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(ApfsOperationStates.Failed, persisted.State);
            Assert.Equal(ApfsOperationCodes.OperationFailed, persisted.Code);
            Assert.False(persisted.Success);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData(ApfsOperationStates.Succeeded, ApfsOperationCodes.OperationSucceeded, true)]
    [InlineData(ApfsOperationStates.Succeeded, ApfsOperationCodes.AlreadyAchieved, true)]
    [InlineData(ApfsOperationStates.Failed, ApfsOperationCodes.Timeout, false)]
    [InlineData(ApfsOperationStates.Cancelled, ApfsOperationCodes.OperationCancelled, false)]
    public async Task ValidExecutorStateCodePairs_ArePreserved(
        string state,
        string code,
        bool success)
    {
        var root = CreateEvidenceRoot();
        var service = new AgentControlOperationService(
            (operation, _) => Task.FromResult(Success(operation) with
            {
                State = state,
                Code = code,
                Success = success,
            }),
            root);

        try
        {
            var result = await service.ExecuteOrReplayAsync(CreateRequest()).WaitAsync(TestTimeout);

            Assert.Equal(state, result.State);
            Assert.Equal(code, result.Code);
            Assert.Equal(success, result.Success);
            Assert.False(string.IsNullOrWhiteSpace(result.EvidencePath));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task UnsignalledOperationCanceledException_IsPersistedAsFailure()
    {
        var root = CreateEvidenceRoot();
        var request = CreateRequest();
        var unrelatedToken = new CancellationToken(canceled: true);
        var service = new AgentControlOperationService(
            (_, _) => throw new OperationCanceledException("executor-local cancellation", unrelatedToken),
            root);

        try
        {
            var result = await service.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);
            var persisted = ReadPayload(Assert.IsType<string>(result.EvidencePath));

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationStates.Failed, result.State);
            Assert.Equal(ApfsOperationCodes.OperationFailed, result.Code);
            Assert.Contains("without service cancellation", result.Diagnostic!, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(ApfsOperationStates.Failed, persisted.State);
            Assert.Equal(ApfsOperationCodes.OperationFailed, persisted.Code);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Construction_RemovesOnlyExactOwnedTemporaryFiles()
    {
        var root = CreateEvidenceRoot();
        var operationId = Guid.NewGuid();
        var writeId = Guid.NewGuid();
        var owned = GetOwnedTempPath(root, operationId, writeId);
        var uncertain = new[]
        {
            Path.Combine(root, $".{operationId:D}.json.not-a-guid.tmp"),
            Path.Combine(root, $".{operationId:D}.json.{writeId:D}.tmp"),
            Path.Combine(root, $".{operationId:D}.json.{writeId:N}.tmp.partial"),
            Path.Combine(root, $"{operationId:D}.json.{writeId:N}.tmp"),
            Path.Combine(root, $".{operationId.ToString("D").ToUpperInvariant()}.json.{Guid.NewGuid():N}.tmp"),
            Path.Combine(root, "notes.tmp"),
        };
        File.WriteAllText(owned, "owned crash-left temp");
        foreach (var path in uncertain) File.WriteAllText(path, "must remain");

        var service = new AgentControlOperationService(
            (operation, _) => Task.FromResult(Success(operation)),
            root);

        try
        {
            Assert.False(File.Exists(owned));
            Assert.All(uncertain, path => Assert.True(File.Exists(path), path));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Admission_RemovesStaleOwnedTempsAndCountsFreshOwnedTempsAgainstCapacity()
    {
        var root = CreateEvidenceRoot();
        var executionCount = 0;
        var service = new AgentControlOperationService(
            (operation, _) =>
            {
                Interlocked.Increment(ref executionCount);
                return Task.FromResult(Success(operation));
            },
            root,
            storeLimits: new AgentControlOperationStoreLimits(TimeSpan.FromDays(1), 2, 64 * 1024));
        var staleOwned = Enumerable.Range(0, 8)
            .Select(_ => GetOwnedTempPath(root, Guid.NewGuid(), Guid.NewGuid()))
            .ToArray();
        foreach (var path in staleOwned)
        {
            File.WriteAllText(path, "stale owned temp");
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddHours(-2));
        }
        var freshOwned = GetOwnedTempPath(root, Guid.NewGuid(), Guid.NewGuid());
        File.WriteAllText(freshOwned, "fresh owned temp");
        var uncertain = Path.Combine(root, $".{Guid.NewGuid():D}.json.uncertain.tmp");
        File.WriteAllText(uncertain, "unrelated stale temp");
        File.SetLastWriteTimeUtc(uncertain, DateTime.UtcNow.AddDays(-2));
        var admittedRequest = CreateRequest();
        var rejectedRequest = CreateRequest();

        try
        {
            var admitted = await service.ExecuteOrReplayAsync(admittedRequest).WaitAsync(TestTimeout);
            var rejected = await service.ExecuteOrReplayAsync(rejectedRequest).WaitAsync(TestTimeout);

            Assert.True(admitted.Success);
            Assert.All(staleOwned, path => Assert.False(File.Exists(path), path));
            Assert.True(File.Exists(freshOwned));
            Assert.True(File.Exists(uncertain));
            Assert.False(rejected.Success);
            Assert.Equal(ApfsOperationCodes.ServiceUnavailable, rejected.Code);
            Assert.Null(rejected.EvidencePath);
            Assert.Equal(1, Volatile.Read(ref executionCount));
            Assert.False(File.Exists(GetEvidencePath(root, rejectedRequest.OperationId)));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Admission_PrunesOnlyExpiredValidTerminalEvidence()
    {
        var root = CreateEvidenceRoot();
        var requests = Enumerable.Range(0, 4).Select(_ => CreateRequest()).ToArray();
        var seed = new AgentControlOperationService(
            (operation, _) => Task.FromResult(Success(operation)),
            root);

        try
        {
            foreach (var request in requests)
            {
                Assert.True((await seed.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout)).Success);
            }
        }
        finally
        {
            await seed.StopAsync(CancellationToken.None);
        }

        var now = DateTime.UtcNow;
        var expiredPath = GetEvidencePath(root, requests[0].OperationId);
        WritePayload(expiredPath, ReadPayload(expiredPath) with
        {
            RequestedAtUtc = now.AddDays(-4),
            StartedAtUtc = now.AddDays(-4).AddMinutes(1),
            CompletedAtUtc = now.AddDays(-3),
        });
        var recentPath = GetEvidencePath(root, requests[1].OperationId);
        var nonterminalPath = GetEvidencePath(root, requests[2].OperationId);
        var nonterminal = ReadPayload(nonterminalPath);
        WritePayload(nonterminalPath, nonterminal with
        {
            State = ApfsOperationStates.InProgress,
            Code = ApfsOperationCodes.OperationInProgress,
            Success = false,
            StartedAtUtc = nonterminal.RequestedAtUtc,
            CompletedAtUtc = null,
            FinalStatus = null,
        });
        var invalidTimestampPath = GetEvidencePath(root, requests[3].OperationId);
        WritePayload(invalidTimestampPath, ReadPayload(invalidTimestampPath) with
        {
            RequestedAtUtc = now,
            StartedAtUtc = now.AddDays(-3),
            CompletedAtUtc = now.AddDays(-2),
        });
        var recentBytes = File.ReadAllBytes(recentPath);
        var nonterminalBytes = File.ReadAllBytes(nonterminalPath);
        var invalidTimestampBytes = File.ReadAllBytes(invalidTimestampPath);
        var limits = new AgentControlOperationStoreLimits(TimeSpan.FromDays(1), 4, 64 * 1024);
        var admittedRequest = CreateRequest();
        var service = new AgentControlOperationService(
            (operation, _) => Task.FromResult(Success(operation)),
            root,
            storeLimits: limits);

        try
        {
            var result = await service.ExecuteOrReplayAsync(admittedRequest).WaitAsync(TestTimeout);

            Assert.True(result.Success);
            Assert.False(File.Exists(expiredPath));
            Assert.Equal(recentBytes, File.ReadAllBytes(recentPath));
            Assert.Equal(nonterminalBytes, File.ReadAllBytes(nonterminalPath));
            Assert.Equal(invalidTimestampBytes, File.ReadAllBytes(invalidTimestampPath));
            Assert.Equal(4, Directory.GetFiles(root, "*.json", SearchOption.TopDirectoryOnly).Length);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task AdmissionAtCapacityWithNoSafePrune_RejectsBeforePersistenceOrExecution()
    {
        var root = CreateEvidenceRoot();
        var recentRequest = CreateRequest();
        var nonterminalRequest = CreateRequest();
        var seed = new AgentControlOperationService(
            (operation, _) => Task.FromResult(Success(operation)),
            root);

        try
        {
            await seed.ExecuteOrReplayAsync(recentRequest).WaitAsync(TestTimeout);
            await seed.ExecuteOrReplayAsync(nonterminalRequest).WaitAsync(TestTimeout);
        }
        finally
        {
            await seed.StopAsync(CancellationToken.None);
        }

        var nonterminalPath = GetEvidencePath(root, nonterminalRequest.OperationId);
        var nonterminal = ReadPayload(nonterminalPath);
        WritePayload(nonterminalPath, nonterminal with
        {
            State = ApfsOperationStates.InProgress,
            Code = ApfsOperationCodes.OperationInProgress,
            Success = false,
            StartedAtUtc = nonterminal.RequestedAtUtc,
            CompletedAtUtc = null,
            FinalStatus = null,
        });
        var corruptPath = GetEvidencePath(root, Guid.NewGuid().ToString("D"));
        File.WriteAllText(corruptPath, "{ recent corrupt evidence must be retained");
        var preserved = Directory.GetFiles(root, "*.json", SearchOption.TopDirectoryOnly)
            .ToDictionary(path => path, File.ReadAllBytes, StringComparer.OrdinalIgnoreCase);
        var executionCount = 0;
        var request = CreateRequest();
        var service = new AgentControlOperationService(
            (operation, _) =>
            {
                Interlocked.Increment(ref executionCount);
                return Task.FromResult(Success(operation));
            },
            root,
            storeLimits: new AgentControlOperationStoreLimits(TimeSpan.FromDays(1), 3, 64 * 1024));

        try
        {
            var result = await service.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.ServiceUnavailable, result.Code);
            Assert.Null(result.EvidencePath);
            Assert.Equal(0, Volatile.Read(ref executionCount));
            Assert.False(File.Exists(GetEvidencePath(root, request.OperationId)));
            Assert.Equal(3, Directory.GetFiles(root, "*.json", SearchOption.TopDirectoryOnly).Length);
            Assert.All(preserved, pair => Assert.Equal(pair.Value, File.ReadAllBytes(pair.Key)));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task AdmissionWhoseAcceptedRecordExceedsByteLimit_IsRejectedBeforeExecution()
    {
        var root = CreateEvidenceRoot();
        var executionCount = 0;
        var request = CreateRequest(target: new ApfsControlTarget(
            "device-1",
            "device-1|Main",
            new string('x', 2048)));
        var service = new AgentControlOperationService(
            (operation, _) =>
            {
                Interlocked.Increment(ref executionCount);
                return Task.FromResult(Success(operation));
            },
            root,
            storeLimits: new AgentControlOperationStoreLimits(TimeSpan.FromDays(1), 10, 512));

        try
        {
            var result = await service.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationCodes.ServiceUnavailable, result.Code);
            Assert.Null(result.EvidencePath);
            Assert.Equal(0, Volatile.Read(ref executionCount));
            Assert.Empty(Directory.GetFiles(root, "*.json", SearchOption.TopDirectoryOnly));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PersistenceFailureBeforeAdmission_DoesNotInvokeExecutor()
    {
        var root = CreateEvidenceRoot();
        var request = CreateRequest();
        var evidencePath = GetEvidencePath(root, request.OperationId);
        Directory.CreateDirectory(evidencePath);
        var executionCount = 0;
        var service = new AgentControlOperationService(
            (operation, _) =>
            {
                Interlocked.Increment(ref executionCount);
                return Task.FromResult(Success(operation));
            },
            root);

        try
        {
            var result = await service.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);

            Assert.False(result.Success);
            Assert.Equal(ApfsOperationStates.Failed, result.State);
            Assert.Equal(ApfsOperationCodes.OperationFailed, result.Code);
            Assert.Null(result.EvidencePath);
            Assert.Equal(0, Volatile.Read(ref executionCount));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task TerminalReplacementFailure_LeavesInProgressEvidenceAndFailsClosedAcrossRestart()
    {
        var root = CreateEvidenceRoot();
        var request = CreateRequest();
        var evidencePath = GetEvidencePath(root, request.OperationId);
        var executionCount = 0;
        var service = new AgentControlOperationService(
            (operation, _) =>
            {
                Interlocked.Increment(ref executionCount);
                return Task.FromResult(Success(operation));
            },
            root,
            beforeEvidenceCommit: payload =>
            {
                if (payload.State is ApfsOperationStates.Succeeded
                    or ApfsOperationStates.Failed
                    or ApfsOperationStates.Cancelled)
                {
                    throw new IOException("Injected terminal replacement failure.");
                }
            });

        try
        {
            var result = await service.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);
            var persistedNonterminal = ReadPayload(evidencePath);
            var queried = service.Query(request.OperationId);

            Assert.Equal(1, Volatile.Read(ref executionCount));
            Assert.False(result.Success);
            Assert.Equal(ApfsOperationStates.Failed, result.State);
            Assert.Null(result.EvidencePath);
            Assert.Equal(ApfsOperationStates.InProgress, persistedNonterminal.State);
            Assert.Equal(ApfsOperationCodes.OperationInProgress, persistedNonterminal.Code);
            Assert.NotNull(queried);
            Assert.False(queried!.Success);
            Assert.Equal(ApfsOperationStates.Failed, queried.State);
            Assert.Null(queried.EvidencePath);

            await service.StopAsync(CancellationToken.None);

            var restartedExecutionCount = 0;
            var restarted = new AgentControlOperationService(
                (operation, _) =>
                {
                    Interlocked.Increment(ref restartedExecutionCount);
                    return Task.FromResult(Success(operation));
                },
                root);
            try
            {
                var recovered = restarted.Query(request.OperationId);
                var replay = await restarted.ExecuteOrReplayAsync(request).WaitAsync(TestTimeout);

                Assert.NotNull(recovered);
                Assert.False(recovered!.Success);
                Assert.Equal(ApfsOperationStates.Failed, recovered.State);
                Assert.Equal(evidencePath, recovered.EvidencePath);
                Assert.Equal(evidencePath, replay.EvidencePath);
                Assert.Equal(0, Volatile.Read(ref restartedExecutionCount));
                Assert.Equal(ApfsOperationStates.Failed, ReadPayload(evidencePath).State);
            }
            finally
            {
                await restarted.StopAsync(CancellationToken.None);
            }
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task StopAsync_CooperativelyCancelsAndLeavesQueryableTerminalEvidence()
    {
        var root = CreateEvidenceRoot();
        var request = CreateRequest();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var service = new AgentControlOperationService(
            async (_, token) =>
            {
                started.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
                throw new InvalidOperationException("unreachable");
            },
            root);

        try
        {
            var execution = service.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);
            await service.StopAsync(CancellationToken.None);
            var boundary = await execution.WaitAsync(TestTimeout);
            var terminal = boundary.State == ApfsOperationStates.Cancelled
                ? boundary
                : await WaitForQueryAsync(
                    service,
                    request.OperationId,
                    result => result.State == ApfsOperationStates.Cancelled);
            var queried = service.Query(request.OperationId);

            Assert.Equal(ApfsOperationStates.Cancelled, terminal.State);
            Assert.Equal(ApfsOperationCodes.OperationCancelled, terminal.Code);
            Assert.False(terminal.Success);
            Assert.False(string.IsNullOrWhiteSpace(terminal.EvidencePath));
            Assert.Equal(terminal.EvidencePath, queried!.EvidencePath);
            Assert.Equal(ApfsOperationStates.Cancelled, queried.State);
            Assert.True(File.Exists(queried.EvidencePath));
            Assert.Empty(Directory.GetFiles(root, "*.tmp", SearchOption.TopDirectoryOnly));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task StopAsync_UncooperativeExecutorHonorsCallerCancellationBudgetWithoutFabricatingCompletion()
    {
        var root = CreateEvidenceRoot();
        var request = CreateRequest();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var service = new AgentControlOperationService(
            async (operation, _) =>
            {
                started.TrySetResult();
                await release.Task;
                return Success(operation);
            },
            root);

        try
        {
            var execution = service.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);
            using var stopTimeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => service.StopAsync(stopTimeout.Token));
            var pending = await execution.WaitAsync(TestTimeout);

            Assert.True(stopTimeout.IsCancellationRequested);
            Assert.Equal(ApfsOperationStates.InProgress, pending.State);
            Assert.Equal(ApfsOperationCodes.OperationInProgress, pending.Code);
            Assert.Null(pending.CompletedAtUtc);
            Assert.True(pending.PendingDurability);
            Assert.Equal(pending, service.Query(request.OperationId));

            release.TrySetResult();
            var terminal = await WaitForQueryAsync(service, request.OperationId, result => result.Success);
            Assert.True(terminal.Success);
        }
        finally
        {
            release.TrySetResult();
            await service.StopAsync(CancellationToken.None);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task StopAsync_HonorsCallerBoundWhenExecutorTokenCallbackBlocks()
    {
        var root = CreateEvidenceRoot();
        var request = CreateRequest();
        var started = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var callbackEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseCallback = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var service = new AgentControlOperationService(
            async (_, token) =>
            {
                var delay = Task.Delay(Timeout.InfiniteTimeSpan, token);
                using var registration = token.Register(() =>
                {
                    callbackEntered.TrySetResult();
                    releaseCallback.Task.GetAwaiter().GetResult();
                });
                started.TrySetResult();
                await delay;
                throw new InvalidOperationException("unreachable");
            },
            root);

        try
        {
            _ = service.ExecuteOrReplayAsync(request);
            await started.Task.WaitAsync(TestTimeout);
            using var stopTimeout = new CancellationTokenSource(
                TimeSpan.FromMilliseconds(100));

            var stop = Task.Run(() => service.StopAsync(stopTimeout.Token));
            await callbackEntered.Task.WaitAsync(TestTimeout);
            var first = await Task.WhenAny(
                stop,
                Task.Delay(TimeSpan.FromSeconds(1)));

            Assert.Same(stop, first);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                async () => await stop);
        }
        finally
        {
            releaseCallback.TrySetResult();
            await service.StopAsync(CancellationToken.None).WaitAsync(TestTimeout);
            Directory.Delete(root, recursive: true);
        }
    }

    private static ControlOperationRequestPayload CreateRequest(
        string? operationId = null,
        ApfsControlTarget? target = null,
        string? requestedMode = null,
        string command = ApfsControlCommands.Mount,
        DateTime? expiresAtUtc = null)
        => new(
            OperationId: operationId ?? Guid.NewGuid().ToString("D"),
            Command: command,
            Target: target ?? new ApfsControlTarget("device-1", "device-1|Main"),
            RequestedMode: requestedMode,
            ExpiresAtUtc: expiresAtUtc ?? DefaultExpiresAtUtc);

    private static OperationResultPayload Success(ControlOperationRequestPayload request)
        => new(
            OperationId: request.OperationId,
            Command: request.Command,
            Target: request.Target,
            Fingerprint: null,
            State: ApfsOperationStates.Succeeded,
            Code: ApfsOperationCodes.OperationSucceeded,
            Success: true,
            RequestedAtUtc: DateTime.UtcNow,
            StartedAtUtc: DateTime.UtcNow,
            CompletedAtUtc: DateTime.UtcNow,
            FinalStatus: "healthy-rw");

    private static string CreateEvidenceRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static string GetEvidencePath(string root, string operationId)
        => Path.Combine(root, $"{Guid.Parse(operationId).ToString("D").ToLowerInvariant()}.json");

    private static string GetOwnedTempPath(string root, Guid operationId, Guid writeId)
        => Path.Combine(root, $".{operationId.ToString("D").ToLowerInvariant()}.json.{writeId:N}.tmp");

    private static OperationResultPayload ReadPayload(string path)
        => JsonSerializer.Deserialize<OperationResultPayload>(File.ReadAllText(path), EvidenceJsonOptions)
           ?? throw new InvalidOperationException("The evidence payload was empty.");

    private static async Task<OperationResultPayload> WaitForQueryAsync(
        AgentControlOperationService service,
        string operationId,
        Func<OperationResultPayload, bool> predicate)
    {
        using var timeout = new CancellationTokenSource(TestTimeout);
        OperationResultPayload? last = null;
        try
        {
            while (true)
            {
                last = service.Query(operationId);
                if (last is not null && predicate(last)) return last;
                await Task.Delay(10, timeout.Token);
            }
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"The operation did not reach the expected durable state. Last result: {JsonSerializer.Serialize(last)}");
        }
    }

    private sealed class AdjustableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private readonly object _gate = new();
        private DateTimeOffset _utcNow = utcNow;

        public override DateTimeOffset GetUtcNow()
        {
            lock (_gate) return _utcNow;
        }

        public void Advance(TimeSpan elapsed)
        {
            lock (_gate) _utcNow += elapsed;
        }
    }

    private static void WritePayload(string path, OperationResultPayload payload)
        => File.WriteAllText(path, JsonSerializer.Serialize(payload, EvidenceJsonOptions));

    private static void AssertSyntheticCorruptResponse(OperationResultPayload response, string operationId)
    {
        Assert.Equal(operationId.ToLowerInvariant(), response.OperationId);
        Assert.False(response.Success);
        Assert.Equal(ApfsOperationStates.Failed, response.State);
        Assert.Equal(ApfsOperationCodes.OperationFailed, response.Code);
        Assert.Null(response.EvidencePath);
        Assert.Contains("corrupt", response.Diagnostic!, StringComparison.OrdinalIgnoreCase);
    }
}
