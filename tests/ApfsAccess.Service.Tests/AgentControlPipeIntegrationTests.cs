using System.IO.Pipes;
using System.Reflection;
using ApfsAccess.Core;
using ApfsAccess.Ipc;
using ApfsAccess.Service;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace ApfsAccess.Service.Tests;

public sealed class AgentControlPipeIntegrationTests
{
    private const string DeviceId = @"\\.\PhysicalDrive2";
    private const string VolumeId = @"\\.\PhysicalDrive2|Main";

    [Fact]
    public async Task Schema2ControlRequest_ExecutesOnceAndReplaysTerminalResult()
    {
        var evidenceRoot = TestEvidenceRoot();
        var executorCalls = 0;
        var operationService = new AgentControlOperationService(
            (request, _) =>
            {
                Interlocked.Increment(ref executorCalls);
                return Task.FromResult(Success(request));
            },
            evidenceRoot);
        using var worker = CreateWorker();
        var service = new TrayPipeHostService(
            NullLogger<TrayPipeHostService>.Instance,
            new RuntimeStatusPublisher(),
            worker,
            new RecordingApplicationLifetime(),
            operationService);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var operationId = Guid.NewGuid().ToString("D");
        var request = PipeMessageCodec.Create(
            ApfsMessageTypes.ControlOperationRequest,
            new ControlOperationRequestPayload(
                operationId,
                ApfsControlCommands.Mount,
                new ApfsControlTarget(DeviceId, VolumeId),
                ApfsControlModes.ReadWrite,
                OperationExpiry()),
            requestId: operationId,
            schemaVersion: PipeSchemaVersions.Schema2);

        try
        {
            var first = await ExchangeAsync(service, request, cancellation.Token);
            var replay = await ExchangeAsync(service, request, cancellation.Token);
            var query = await ExchangeAsync(
                service,
                PipeMessageCodec.Create(
                    ApfsMessageTypes.OperationResultQuery,
                    new OperationResultQueryPayload(operationId),
                    requestId: operationId,
                    schemaVersion: PipeSchemaVersions.Schema2),
                cancellation.Token);

            Assert.Equal(PipeSchemaVersions.Schema2, first.SchemaVersion);
            Assert.Equal(ApfsMessageTypes.OperationResult, first.Type);
            Assert.Equal(operationId, first.RequestId);
            Assert.True(PipeMessageCodec.TryGetPayload<OperationResultPayload>(first, out var firstResult));
            Assert.True(PipeMessageCodec.TryGetPayload<OperationResultPayload>(replay, out var replayResult));
            Assert.True(PipeMessageCodec.TryGetPayload<OperationResultPayload>(query, out var queryResult));
            Assert.True(firstResult!.Success);
            Assert.Equal(ApfsOperationStates.Succeeded, firstResult.State);
            Assert.Equal(firstResult, replayResult);
            Assert.Equal(firstResult, queryResult);
            Assert.Equal(1, executorCalls);
            Assert.True(File.Exists(firstResult.EvidencePath));
        }
        finally
        {
            await operationService.StopAsync(CancellationToken.None);
            TryDelete(evidenceRoot);
        }
    }

    [Fact]
    public async Task Schema2MalformedControlPayload_IsRejectedBeforeExecution()
    {
        var evidenceRoot = TestEvidenceRoot();
        var executorCalls = 0;
        var operationService = new AgentControlOperationService(
            (request, _) =>
            {
                Interlocked.Increment(ref executorCalls);
                return Task.FromResult(Success(request));
            },
            evidenceRoot);
        using var worker = CreateWorker();
        var service = new TrayPipeHostService(
            NullLogger<TrayPipeHostService>.Instance,
            new RuntimeStatusPublisher(),
            worker,
            new RecordingApplicationLifetime(),
            operationService);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var operationId = Guid.NewGuid().ToString("D");
        var malformed = PipeMessageCodec.Create(
            ApfsMessageTypes.ControlOperationRequest,
            new ControlOperationRequestPayload(
                operationId,
                ApfsControlCommands.Mount,
                Target: null,
                RequestedMode: ApfsControlModes.ReadWrite,
                ExpiresAtUtc: OperationExpiry()),
            requestId: operationId,
            schemaVersion: PipeSchemaVersions.Schema2);

        try
        {
            var response = await ExchangeAsync(service, malformed, cancellation.Token);

            Assert.Equal(ApfsMessageTypes.OperationResult, response.Type);
            Assert.True(PipeMessageCodec.TryGetPayload<OperationResultPayload>(response, out var result));
            Assert.False(result!.Success);
            Assert.Equal(ApfsOperationStates.Failed, result.State);
            Assert.Equal(ApfsOperationCodes.AmbiguousTarget, result.Code);
            Assert.Equal(0, executorCalls);
            Assert.Empty(Directory.GetFileSystemEntries(evidenceRoot));
        }
        finally
        {
            await operationService.StopAsync(CancellationToken.None);
            TryDelete(evidenceRoot);
        }
    }

    [Theory]
    [InlineData("00000000-0000-0000-0000-000000000101", "NOT-CANONICAL", "00000000-0000-0000-0000-000000000101")]
    [InlineData("00000000-0000-0000-0000-000000000101", "00000000-0000-0000-0000-000000000102", "00000000-0000-0000-0000-000000000101")]
    [InlineData("NOT-CANONICAL", "00000000-0000-0000-0000-000000000102", "00000000-0000-0000-0000-000000000102")]
    [InlineData("NOT-CANONICAL", "ALSO-NOT-CANONICAL", null)]
    public async Task Schema2MalformedRejection_UsesOneCanonicalIdentityByPrecedence(
        string envelopeId,
        string payloadId,
        string? expectedId)
    {
        var evidenceRoot = TestEvidenceRoot();
        var operationService = new AgentControlOperationService(
            (request, _) => Task.FromResult(Success(request)),
            evidenceRoot);
        using var worker = CreateWorker();
        var service = new TrayPipeHostService(
            NullLogger<TrayPipeHostService>.Instance,
            new RuntimeStatusPublisher(),
            worker,
            new RecordingApplicationLifetime(),
            operationService);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var malformed = PipeMessageCodec.Create(
            ApfsMessageTypes.ControlOperationRequest,
            new ControlOperationRequestPayload(
                payloadId,
                ApfsControlCommands.Mount,
                new ApfsControlTarget(DeviceId, VolumeId),
                ApfsControlModes.ReadWrite,
                OperationExpiry()),
            envelopeId,
            PipeSchemaVersions.Schema2);

        try
        {
            var response = await ExchangeAsync(service, malformed, cancellation.Token);
            Assert.True(PipeMessageCodec.TryGetPayload<OperationResultPayload>(response, out var result));
            Assert.NotNull(result);
            Assert.Equal(response.RequestId, result!.OperationId);
            Assert.True(Guid.TryParseExact(response.RequestId, "D", out _));
            Assert.Equal(response.RequestId, response.RequestId!.ToLowerInvariant());
            if (expectedId is not null)
            {
                Assert.Equal(expectedId, response.RequestId);
            }

            var validation = PipeMessageCodec.Validate(response);
            Assert.True(validation.IsValid, validation.Diagnostic);
        }
        finally
        {
            await operationService.StopAsync(CancellationToken.None);
            TryDelete(evidenceRoot);
        }
    }

    [Theory]
    [InlineData(ApfsMessageTypes.OperationResultQuery)]
    [InlineData(ApfsMessageTypes.CancellationRequest)]
    public async Task Schema2UnknownQueryOrCancel_ReturnsCodecValidContextlessResult(string messageType)
    {
        await AssertContextlessResponseValidAsync(messageType, corruptEvidence: false);
    }

    [Theory]
    [InlineData(ApfsMessageTypes.OperationResultQuery)]
    [InlineData(ApfsMessageTypes.CancellationRequest)]
    public async Task Schema2CorruptEvidenceQueryOrCancel_ReturnsCodecValidContextlessResult(string messageType)
    {
        await AssertContextlessResponseValidAsync(messageType, corruptEvidence: true);
    }

    [Fact]
    public async Task DroppedRequester_DoesNotCancelAcceptedOperationAndQueryReturnsTerminalResult()
    {
        var evidenceRoot = TestEvidenceRoot();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var operationService = new AgentControlOperationService(
            async (request, _) =>
            {
                started.TrySetResult();
                await release.Task;
                return Success(request);
            },
            evidenceRoot);
        using var worker = CreateWorker();
        var service = new TrayPipeHostService(
            NullLogger<TrayPipeHostService>.Instance,
            new RuntimeStatusPublisher(),
            worker,
            new RecordingApplicationLifetime(),
            operationService);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var operationId = Guid.NewGuid().ToString("D");
        var request = PipeMessageCodec.Create(
            ApfsMessageTypes.ControlOperationRequest,
            new ControlOperationRequestPayload(
                operationId,
                ApfsControlCommands.Mount,
                new ApfsControlTarget(DeviceId, VolumeId),
                ApfsControlModes.ReadWrite,
                OperationExpiry()),
            requestId: operationId,
            schemaVersion: PipeSchemaVersions.Schema2);
        var pair = await ConnectedPipePair.CreateAsync(
            $"ApfsAccess.AgentControl.Drop.{Guid.NewGuid():N}",
            cancellation.Token);
        var serverPeer = new PipePeer(pair.Server);
        var clientPeer = new PipePeer(pair.Client);
        var handler = InvokeHandleClient(service, serverPeer, cancellation.Token);

        try
        {
            Assert.Equal(
                ApfsMessageTypes.StatusChanged,
                (await clientPeer.ReadMessageAsync(cancellation.Token))!.Type);
            await clientPeer.SendAsync(request, cancellation.Token);
            await started.Task.WaitAsync(cancellation.Token);
            await clientPeer.DisposeAsync();
            release.TrySetResult();
            await handler.WaitAsync(cancellation.Token);
            await serverPeer.DisposeAsync();

            var query = await ExchangeAsync(
                service,
                PipeMessageCodec.Create(
                    ApfsMessageTypes.OperationResultQuery,
                    new OperationResultQueryPayload(operationId),
                    requestId: operationId,
                    schemaVersion: PipeSchemaVersions.Schema2),
                cancellation.Token);
            Assert.True(PipeMessageCodec.TryGetPayload<OperationResultPayload>(query, out var result));
            Assert.True(result!.Success);
            Assert.Equal(ApfsOperationStates.Succeeded, result.State);
            Assert.True(File.Exists(result.EvidencePath));
        }
        finally
        {
            release.TrySetResult();
            await operationService.StopAsync(CancellationToken.None);
            TryDelete(evidenceRoot);
        }
    }

    [Fact]
    public async Task Schema2Cancellation_WaitsForDurableCancelledTerminalResult()
    {
        var evidenceRoot = TestEvidenceRoot();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var operationService = new AgentControlOperationService(
            async (_, operationToken) =>
            {
                started.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, operationToken);
                throw new InvalidOperationException("The cancelled operation unexpectedly resumed.");
            },
            evidenceRoot);
        using var worker = CreateWorker();
        var service = new TrayPipeHostService(
            NullLogger<TrayPipeHostService>.Instance,
            new RuntimeStatusPublisher(),
            worker,
            new RecordingApplicationLifetime(),
            operationService);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var operationId = Guid.NewGuid().ToString("D");
        var pair = await ConnectedPipePair.CreateAsync(
            $"ApfsAccess.AgentControl.Cancel.{Guid.NewGuid():N}",
            cancellation.Token);
        var serverPeer = new PipePeer(pair.Server);
        var clientPeer = new PipePeer(pair.Client);
        var handler = InvokeHandleClient(service, serverPeer, cancellation.Token);
        var clientDisposed = false;

        try
        {
            Assert.Equal(
                ApfsMessageTypes.StatusChanged,
                (await clientPeer.ReadMessageAsync(cancellation.Token))!.Type);
            await clientPeer.SendAsync(
                PipeMessageCodec.Create(
                    ApfsMessageTypes.ControlOperationRequest,
                    new ControlOperationRequestPayload(
                        operationId,
                        ApfsControlCommands.Mount,
                        new ApfsControlTarget(DeviceId, VolumeId),
                        ApfsControlModes.ReadWrite,
                        OperationExpiry()),
                    requestId: operationId,
                    schemaVersion: PipeSchemaVersions.Schema2),
                cancellation.Token);
            await started.Task.WaitAsync(cancellation.Token);

            var cancellationResult = await ExchangeAsync(
                service,
                PipeMessageCodec.Create(
                    ApfsMessageTypes.CancellationRequest,
                    new OperationCancellationRequestPayload(operationId),
                    requestId: operationId,
                    schemaVersion: PipeSchemaVersions.Schema2),
                cancellation.Token);
            var originalResult = await clientPeer.ReadMessageAsync(cancellation.Token);

            Assert.True(PipeMessageCodec.TryGetPayload<OperationResultPayload>(cancellationResult, out var cancelled));
            Assert.Equal(ApfsOperationStates.Cancelled, cancelled!.State);
            Assert.Equal(ApfsOperationCodes.OperationCancelled, cancelled.Code);
            Assert.NotNull(cancelled.CompletedAtUtc);
            Assert.True(File.Exists(cancelled.EvidencePath));
            Assert.True(PipeMessageCodec.TryGetPayload<OperationResultPayload>(originalResult!, out var original));
            Assert.Equal(cancelled, original);
            await clientPeer.DisposeAsync();
            clientDisposed = true;
            await handler.WaitAsync(cancellation.Token);
        }
        finally
        {
            if (!clientDisposed)
            {
                await clientPeer.DisposeAsync();
            }
            await serverPeer.DisposeAsync();
            await operationService.StopAsync(CancellationToken.None);
            TryDelete(evidenceRoot);
        }
    }

    [Fact]
    public async Task Schema2Cancellation_UncooperativeOperationReturnsBoundedTruthfulSnapshot()
    {
        var evidenceRoot = TestEvidenceRoot();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var operationService = new AgentControlOperationService(
            async (request, _) =>
            {
                started.TrySetResult();
                await release.Task;
                return Success(request);
            },
            evidenceRoot);
        using var worker = CreateWorker();
        var service = new TrayPipeHostService(
            NullLogger<TrayPipeHostService>.Instance,
            new RuntimeStatusPublisher(),
            worker,
            new RecordingApplicationLifetime(),
            operationService);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(6));
        var operationId = Guid.NewGuid().ToString("D");
        var pair = await ConnectedPipePair.CreateAsync(
            $"ApfsAccess.AgentControl.CancelBounded.{Guid.NewGuid():N}",
            cancellation.Token);
        var serverPeer = new PipePeer(pair.Server);
        var clientPeer = new PipePeer(pair.Client);
        var handler = InvokeHandleClient(service, serverPeer, cancellation.Token);
        var clientDisposed = false;

        try
        {
            Assert.Equal(
                ApfsMessageTypes.StatusChanged,
                (await clientPeer.ReadMessageAsync(cancellation.Token))!.Type);
            await clientPeer.SendAsync(
                PipeMessageCodec.Create(
                    ApfsMessageTypes.ControlOperationRequest,
                    new ControlOperationRequestPayload(
                        operationId,
                        ApfsControlCommands.Mount,
                        new ApfsControlTarget(DeviceId, VolumeId),
                        ApfsControlModes.ReadWrite,
                        OperationExpiry()),
                    requestId: operationId,
                    schemaVersion: PipeSchemaVersions.Schema2),
                cancellation.Token);
            await started.Task.WaitAsync(cancellation.Token);

            var evidencePath = Path.Combine(evidenceRoot, $"{operationId}.json");
            Assert.True(File.Exists(evidencePath));
            File.Delete(evidencePath);
            var queryResult = await ExchangeAsync(
                service,
                PipeMessageCodec.Create(
                    ApfsMessageTypes.OperationResultQuery,
                    new OperationResultQueryPayload(operationId),
                    requestId: operationId,
                    schemaVersion: PipeSchemaVersions.Schema2),
                cancellation.Token);
            AssertCodecValidOperationResult(queryResult, ApfsControlCommands.Mount);

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var cancellationResult = await ExchangeAsync(
                service,
                PipeMessageCodec.Create(
                    ApfsMessageTypes.CancellationRequest,
                    new OperationCancellationRequestPayload(operationId),
                    requestId: operationId,
                    schemaVersion: PipeSchemaVersions.Schema2),
                cancellation.Token);
            stopwatch.Stop();

            Assert.True(PipeMessageCodec.TryGetPayload<OperationResultPayload>(cancellationResult, out var pending));
            AssertCodecValidOperationResult(cancellationResult, ApfsControlCommands.Mount);
            Assert.Equal(ApfsOperationStates.InProgress, pending!.State);
            Assert.Equal(ApfsOperationCodes.OperationInProgress, pending.Code);
            Assert.Contains("Cancellation was requested", pending.Diagnostic, StringComparison.Ordinal);
            Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(4), $"Cancellation response took {stopwatch.Elapsed}.");

            release.TrySetResult();
            var originalResult = await clientPeer.ReadMessageAsync(cancellation.Token);
            Assert.True(PipeMessageCodec.TryGetPayload<OperationResultPayload>(originalResult!, out var completed));
            Assert.True(completed!.Success);
            await clientPeer.DisposeAsync();
            clientDisposed = true;
            await handler.WaitAsync(cancellation.Token);
        }
        finally
        {
            release.TrySetResult();
            if (!clientDisposed)
            {
                await clientPeer.DisposeAsync();
            }
            await serverPeer.DisposeAsync();
            await operationService.StopAsync(CancellationToken.None);
            TryDelete(evidenceRoot);
        }
    }

    [Fact]
    public async Task Schema2Quit_SendsTerminalResultThenStoppingBeforeStoppingApplication()
    {
        var evidenceRoot = TestEvidenceRoot();
        var operationId = Guid.NewGuid().ToString("D");
        var expectedEvidencePath = Path.Combine(evidenceRoot, $"{operationId}.json");
        var operationService = new AgentControlOperationService(
            (request, _) => Task.FromResult(Success(request)),
            evidenceRoot);
        var statusPublisher = new RuntimeStatusPublisher();
        statusPublisher.Publish(statusPublisher.Latest with
        {
            MountPoints = ["E:\\"],
        });
        using var worker = CreateWorker();
        var lifetime = new RecordingApplicationLifetime(() => File.Exists(expectedEvidencePath));
        var service = new TrayPipeHostService(
            NullLogger<TrayPipeHostService>.Instance,
            statusPublisher,
            worker,
            lifetime,
            operationService);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var request = PipeMessageCodec.Create(
            ApfsMessageTypes.ControlOperationRequest,
            new ControlOperationRequestPayload(
                operationId,
                ApfsControlCommands.Quit,
                Target: null,
                ExpiresAtUtc: OperationExpiry()),
            requestId: operationId,
            schemaVersion: PipeSchemaVersions.Schema2);
        var pair = await ConnectedPipePair.CreateAsync(
            $"ApfsAccess.AgentControl.Quit.{Guid.NewGuid():N}",
            cancellation.Token);
        var serverPeer = new PipePeer(pair.Server);
        var clientPeer = new PipePeer(pair.Client);
        var handler = InvokeHandleClient(service, serverPeer, cancellation.Token);

        try
        {
            Assert.Equal(
                ApfsMessageTypes.StatusChanged,
                (await clientPeer.ReadMessageAsync(cancellation.Token))!.Type);
            await clientPeer.SendAsync(request, cancellation.Token);

            var result = await clientPeer.ReadMessageAsync(cancellation.Token);
            var stopping = await clientPeer.ReadMessageAsync(cancellation.Token);
            Assert.Equal(ApfsMessageTypes.OperationResult, result!.Type);
            Assert.Equal(ApfsMessageTypes.ServiceStopping, stopping!.Type);
            Assert.True(PipeMessageCodec.TryGetPayload<OperationResultPayload>(result, out var payload));
            Assert.True(PipeMessageCodec.TryGetPayload<ServiceStoppingPayload>(stopping, out var stoppingPayload));
            Assert.True(payload!.Success);
            Assert.False(string.IsNullOrWhiteSpace(payload.EvidencePath));
            Assert.True(File.Exists(payload.EvidencePath));
            Assert.True(stoppingPayload!.CleanupCompleted);
            Assert.Empty(stoppingPayload.RemainingMountPoints!);
            await lifetime.StopRequested.Task.WaitAsync(cancellation.Token);
            Assert.True(lifetime.WasStopped);
            Assert.True(lifetime.StopProbePassed);
            await handler.WaitAsync(cancellation.Token);
        }
        finally
        {
            await clientPeer.DisposeAsync();
            await serverPeer.DisposeAsync();
            await operationService.StopAsync(CancellationToken.None);
            TryDelete(evidenceRoot);
        }
    }

    [Fact]
    public async Task StopAsync_RacingDisconnectedHandlerCleanup_DisposesPeerOnceWithoutLeak()
    {
        using var worker = CreateWorker();
        var logger = new RecordingDisconnectLogger();
        var service = new TrayPipeHostService(
            logger,
            new RuntimeStatusPublisher(),
            worker,
            new RecordingApplicationLifetime(),
            operationService: null);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var stream = new ConcurrentCleanupStream();
        var serverPeer = new PipePeer(stream);
        var handler = InvokeHandleClient(service, serverPeer, cancellation.Token);
        try
        {
            await stream.InitialWriteObserved.Task.WaitAsync(cancellation.Token);

            var stop = service.StopAsync(cancellation.Token);
            await stream.DisposeStarted.Task.WaitAsync(cancellation.Token);
            await logger.DisconnectObserved.Task.WaitAsync(cancellation.Token);

            Assert.False(stop.IsCompleted);
            Assert.False(handler.IsCompleted);
            stream.ReleaseDispose.TrySetResult();

            await Task.WhenAll(stop, handler).WaitAsync(cancellation.Token);
            Assert.Equal(1, stream.DisposeAsyncCalls);
            Assert.False(logger.CleanupTimeoutObserved.Task.IsCompleted);
            await serverPeer.DisposeAsync().AsTask().WaitAsync(cancellation.Token);
        }
        finally
        {
            stream.ReleaseDispose.TrySetResult();
        }
    }

    [Fact]
    public async Task StopAsync_PermanentlyBlockedPeerCannotHoldShutdownPastDeadline()
    {
        using var worker = CreateWorker();
        var logger = new RecordingDisconnectLogger();
        var service = new TrayPipeHostService(
            logger,
            new RuntimeStatusPublisher(),
            worker,
            new RecordingApplicationLifetime(),
            operationService: null);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var stream = new ConcurrentCleanupStream();
        var serverPeer = new PipePeer(stream);
        var handler = InvokeHandleClient(service, serverPeer, cancellation.Token);
        Task? stop = null;
        try
        {
            await stream.InitialWriteObserved.Task.WaitAsync(cancellation.Token);

            stop = service.StopAsync(CancellationToken.None);
            await stream.DisposeStarted.Task.WaitAsync(cancellation.Token);
            await stop.WaitAsync(TimeSpan.FromSeconds(4));

            Assert.True(logger.CleanupTimeoutObserved.Task.IsCompleted);
            Assert.False(handler.IsCompleted);
            Assert.Equal(1, stream.DisposeAsyncCalls);
        }
        finally
        {
            stream.ReleaseDispose.TrySetResult();
            await handler.WaitAsync(cancellation.Token);
            if (stop is not null)
            {
                await stop.WaitAsync(cancellation.Token);
            }

            await serverPeer.DisposeAsync().AsTask().WaitAsync(cancellation.Token);
        }
    }

    private static async Task AssertContextlessResponseValidAsync(string messageType, bool corruptEvidence)
    {
        var evidenceRoot = TestEvidenceRoot();
        var operationService = new AgentControlOperationService(
            (request, _) => Task.FromResult(Success(request)),
            evidenceRoot);
        using var worker = CreateWorker();
        var service = new TrayPipeHostService(
            NullLogger<TrayPipeHostService>.Instance,
            new RuntimeStatusPublisher(),
            worker,
            new RecordingApplicationLifetime(),
            operationService);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var operationId = Guid.NewGuid().ToString("D");
        if (corruptEvidence)
        {
            Directory.CreateDirectory(evidenceRoot);
            await File.WriteAllTextAsync(
                Path.Combine(evidenceRoot, $"{operationId}.json"),
                "{ corrupt-evidence",
                cancellation.Token);
        }

        var request = messageType == ApfsMessageTypes.OperationResultQuery
            ? PipeMessageCodec.Create(
                messageType,
                new OperationResultQueryPayload(operationId),
                operationId,
                PipeSchemaVersions.Schema2)
            : PipeMessageCodec.Create(
                messageType,
                new OperationCancellationRequestPayload(operationId),
                operationId,
                PipeSchemaVersions.Schema2);

        try
        {
            var response = await ExchangeAsync(service, request, cancellation.Token);
            AssertCodecValidOperationResult(response, ApfsControlCommands.Unknown);
        }
        finally
        {
            await operationService.StopAsync(CancellationToken.None);
            TryDelete(evidenceRoot);
        }
    }

    private static void AssertCodecValidOperationResult(PipeEnvelope response, string expectedCommand)
    {
        Assert.Equal(ApfsMessageTypes.OperationResult, response.Type);
        var validation = PipeMessageCodec.Validate(response);
        Assert.True(validation.IsValid, validation.Diagnostic);
        Assert.True(PipeMessageCodec.TryGetPayload<OperationResultPayload>(response, out var result));
        Assert.Equal(expectedCommand, result!.Command);
        Assert.False(result.Success);
        if (expectedCommand == ApfsControlCommands.Unknown)
        {
            Assert.Null(result.Target);
            Assert.Null(result.RequestedMode);
            Assert.Null(result.Fingerprint);
        }
        else
        {
            Assert.NotNull(result.Target);
            Assert.False(string.IsNullOrWhiteSpace(result.Fingerprint));
        }
    }

    private static async Task<PipeEnvelope> ExchangeAsync(
        TrayPipeHostService service,
        PipeEnvelope request,
        CancellationToken cancellationToken)
    {
        var pair = await ConnectedPipePair.CreateAsync(
            $"ApfsAccess.AgentControl.{Guid.NewGuid():N}",
            cancellationToken);
        var serverPeer = new PipePeer(pair.Server);
        var clientPeer = new PipePeer(pair.Client);
        var handler = InvokeHandleClient(service, serverPeer, cancellationToken);
        try
        {
            var initial = await clientPeer.ReadMessageAsync(cancellationToken);
            Assert.Equal(ApfsMessageTypes.StatusChanged, initial!.Type);
            await clientPeer.SendAsync(request, cancellationToken);
            return (await clientPeer.ReadMessageAsync(cancellationToken))!;
        }
        finally
        {
            await clientPeer.DisposeAsync();
            await handler;
            await serverPeer.DisposeAsync();
        }
    }

    private static Task InvokeHandleClient(
        TrayPipeHostService service,
        PipePeer peer,
        CancellationToken cancellationToken)
    {
        var method = typeof(TrayPipeHostService).GetMethod(
            "HandleClientAsync",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(method);
        return Assert.IsAssignableFrom<Task>(method!.Invoke(service, [peer, cancellationToken]));
    }

    private static ApfsMountWorker CreateWorker()
        => new(
            NullLogger<ApfsMountWorker>.Instance,
            new NoopBackend(),
            new NoopMountPolicy(),
            new RuntimeStatusPublisher(),
            new FixedOptionsMonitor(new ServiceHostOptions()));

    private static OperationResultPayload Success(ControlOperationRequestPayload request)
    {
        var now = DateTime.UtcNow;
        return new OperationResultPayload(
            request.OperationId,
            request.Command,
            request.Target,
            Fingerprint: null,
            State: ApfsOperationStates.Succeeded,
            Code: ApfsOperationCodes.OperationSucceeded,
            Success: true,
            RequestedAtUtc: now,
            StartedAtUtc: now,
            CompletedAtUtc: now,
            FinalStatus: request.Command == ApfsControlCommands.Quit ? "shutdown-complete" : "healthy-rw",
            RequestedMode: request.RequestedMode,
            EffectiveMode: request.RequestedMode,
            RecoveryState: "inactive",
            RecoveryActive: false,
            DirtyTransactionCount: 0,
            PendingDurability: false,
            MountProof: request.Command == ApfsControlCommands.Quit ? "no-mounts" : "present",
            OwnershipProof: request.Command == ApfsControlCommands.Quit ? "proven" : "not-applicable",
            DurabilityProof: request.Command == ApfsControlCommands.Quit ? "proven" : "not-applicable",
            QuitMarkerWritten: request.Command == ApfsControlCommands.Quit,
            ExpiresAtUtc: request.ExpiresAtUtc);
    }

    private static DateTime OperationExpiry() => DateTime.UtcNow.AddMinutes(2);

    private static string TestEvidenceRoot()
        => Path.Combine(
            Path.GetTempPath(),
            "ApfsAccessTests",
            "AgentControlPipe",
            Guid.NewGuid().ToString("N"));

    private static void TryDelete(string path)
    {
        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch
        {
        }
    }

    private sealed class RecordingApplicationLifetime(Func<bool>? stopProbe = null) : IHostApplicationLifetime
    {
        public TaskCompletionSource StopRequested { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        public bool WasStopped { get; private set; }
        public bool StopProbePassed { get; private set; }
        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => CancellationToken.None;
        public CancellationToken ApplicationStopped => CancellationToken.None;
        public void StopApplication()
        {
            StopProbePassed = stopProbe?.Invoke() ?? true;
            WasStopped = true;
            StopRequested.TrySetResult();
        }
    }

    private sealed class RecordingDisconnectLogger : ILogger<TrayPipeHostService>
    {
        public TaskCompletionSource DisconnectObserved { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource CleanupTimeoutObserved { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var message = formatter(state, exception);
            if (message.Contains("peer cleanup", StringComparison.OrdinalIgnoreCase))
            {
                CleanupTimeoutObserved.TrySetResult();
            }

            if (!message.Contains("disconnected", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            DisconnectObserved.TrySetResult();
        }
    }

    private sealed class ConcurrentCleanupStream : Stream
    {
        public TaskCompletionSource InitialWriteObserved { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource DisposeStarted { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseDispose { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        public int DisposeAsyncCalls;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
            => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            await DisposeStarted.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return 0;
        }

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => InitialWriteObserved.TrySetResult();

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            InitialWriteObserved.TrySetResult();
            return ValueTask.CompletedTask;
        }

        public override async ValueTask DisposeAsync()
        {
            Interlocked.Increment(ref DisposeAsyncCalls);
            DisposeStarted.TrySetResult();
            await ReleaseDispose.Task.ConfigureAwait(false);
            await base.DisposeAsync().ConfigureAwait(false);
        }
    }

    private sealed class NoopMountPolicy : IMountPolicy
    {
        public char SelectDriveLetter(VolumeInfo volume, IReadOnlySet<char> usedLetters)
            => 'E';

        public bool ShouldAutoMount(VolumeInfo volume)
            => false;
    }

    private sealed class FixedOptionsMonitor(ServiceHostOptions options) : IOptionsMonitor<ServiceHostOptions>
    {
        public ServiceHostOptions CurrentValue => options;
        public ServiceHostOptions Get(string? name) => options;
        public IDisposable OnChange(Action<ServiceHostOptions, string> listener)
            => NoopDisposable.Instance;

        private sealed class NoopDisposable : IDisposable
        {
            public static readonly NoopDisposable Instance = new();
            public void Dispose() { }
        }
    }

    private sealed class NoopBackend : IApfsBackend
    {
        public Task<IReadOnlyList<DeviceInfo>> ProbeDevicesAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<DeviceInfo>>(Array.Empty<DeviceInfo>());

        public Task<IReadOnlyList<VolumeInfo>> ProbeVolumesAsync(
            string deviceId,
            CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<VolumeInfo>>(Array.Empty<VolumeInfo>());

        public Task<MountResult> MountAsync(MountRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<UnmountResult> UnmountAsync(string mountPoint, CancellationToken cancellationToken)
            => Task.FromResult(new UnmountResult(true, mountPoint, null, true, true, true));

        public Task<IReadOnlyList<MountedVolumeState>> GetMountStateAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<MountedVolumeState>>(Array.Empty<MountedVolumeState>());
    }

    private sealed class ConnectedPipePair : IAsyncDisposable
    {
        private ConnectedPipePair(NamedPipeServerStream server, NamedPipeClientStream client)
        {
            Server = server;
            Client = client;
        }

        public NamedPipeServerStream Server { get; }
        public NamedPipeClientStream Client { get; }

        public static async Task<ConnectedPipePair> CreateAsync(
            string pipeName,
            CancellationToken cancellationToken)
        {
            var server = new NamedPipeServerStream(
                pipeName,
                PipeDirection.InOut,
                1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);
            var client = new NamedPipeClientStream(
                ".",
                pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous);
            var waitForConnection = server.WaitForConnectionAsync(cancellationToken);
            await client.ConnectAsync(cancellationToken);
            await waitForConnection;
            return new ConnectedPipePair(server, client);
        }

        public async ValueTask DisposeAsync()
        {
            await Client.DisposeAsync();
            await Server.DisposeAsync();
        }
    }
}
