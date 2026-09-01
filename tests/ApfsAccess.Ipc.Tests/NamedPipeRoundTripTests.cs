using ApfsAccess.Ipc;

namespace ApfsAccess.Ipc.Tests;

public sealed class NamedPipeRoundTripTests
{
    [Fact]
    public async Task ServerWithAcl_StartsBeforeClientConnection()
    {
        var pipeName = $"ApfsAccess.Diagnostic.{Guid.NewGuid():N}";
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var server = new NamedPipeMessageServer(pipeName);
        var serverTask = server.RunAsync((_, _) => Task.CompletedTask, cts.Token);

        await Task.Delay(250, cts.Token);
        if (serverTask.IsFaulted)
        {
            throw new Xunit.Sdk.XunitException(serverTask.Exception?.ToString());
        }

        cts.Cancel();
        await serverTask;
    }

    [Fact]
    public async Task PingPong_WorksAcrossNamedPipeServerAndClient()
    {
        var pipeName = $"ApfsAccess.Test.{Guid.NewGuid():N}";
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var server = new NamedPipeMessageServer(pipeName);
        var serverTask = server.RunAsync(async (peer, token) =>
        {
            var incoming = await peer.ReadMessageAsync(token);
            Assert.NotNull(incoming);
            Assert.Equal(ApfsMessageTypes.Ping, incoming!.Type);

            var response = PipeMessageCodec.Create(
                ApfsMessageTypes.Pong,
                new PongPayload(DateTime.UtcNow),
                incoming.RequestId
            );
            await peer.SendAsync(response, token);
        }, cts.Token);

        await using var client = await NamedPipeMessageClient.ConnectAsync(pipeName, 2000, cts.Token);
        var ping = PipeMessageCodec.Create(
            ApfsMessageTypes.Ping,
            new PingPayload(DateTime.UtcNow),
            requestId: "ping-1"
        );
        await client.SendAsync(ping, cts.Token);

        var pong = await client.ReadMessageAsync(cts.Token);
        Assert.NotNull(pong);
        Assert.Equal(ApfsMessageTypes.Pong, pong!.Type);
        Assert.Equal("ping-1", pong.RequestId);

        cts.Cancel();
        await serverTask;
    }

    [Fact]
    public async Task ClientCanReconnectAfterServerRestart()
    {
        var pipeName = $"ApfsAccess.Restart.{Guid.NewGuid():N}";

        async Task RunOneSessionAsync(string requestId)
        {
            using var serverCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var server = new NamedPipeMessageServer(pipeName);
            var serverTask = server.RunAsync(async (peer, token) =>
            {
                var message = await peer.ReadMessageAsync(token);
                Assert.NotNull(message);
                var ack = PipeMessageCodec.Create(
                    ApfsMessageTypes.Ack,
                    new AckPayload(true, "ok"),
                    message!.RequestId
                );
                await peer.SendAsync(ack, token);
                serverCts.Cancel();
            }, serverCts.Token);

            await using var client = await NamedPipeMessageClient.ConnectAsync(pipeName, 2000, CancellationToken.None);
            var request = PipeMessageCodec.Create(
                ApfsMessageTypes.Ping,
                new PingPayload(DateTime.UtcNow),
                requestId
            );
            await client.SendAsync(request, CancellationToken.None);

            var response = await client.ReadMessageAsync(CancellationToken.None);
            Assert.NotNull(response);
            Assert.Equal(ApfsMessageTypes.Ack, response!.Type);
            Assert.Equal(requestId, response.RequestId);

            await serverTask;
        }

        await RunOneSessionAsync("first");
        await RunOneSessionAsync("second");
    }

    [Fact]
    public async Task ServerCompletesCleanly_WhenClientDisconnectsBeforePeerDispose()
    {
        var pipeName = $"ApfsAccess.Disconnect.{Guid.NewGuid():N}";
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var handled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var server = new NamedPipeMessageServer(pipeName);
        var serverTask = server.RunAsync(async (peer, token) =>
        {
            var incoming = await peer.ReadMessageAsync(token);
            Assert.NotNull(incoming);
            handled.SetResult();
        }, cts.Token);

        var client = await NamedPipeMessageClient.ConnectAsync(pipeName, 2000, cts.Token);
        var ping = PipeMessageCodec.Create(
            ApfsMessageTypes.Ping,
            new PingPayload(DateTime.UtcNow),
            requestId: "disconnect-first"
        );
        await client.SendAsync(ping, cts.Token);
        await client.DisposeAsync();

        await handled.Task.WaitAsync(cts.Token);
        await cts.CancelAsync();
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task ServerShutdown_DoesNotWaitForeverForPermanentlyBlockedClient()
    {
        var pipeName = $"ApfsAccess.BlockedShutdown.{Guid.NewGuid():N}";
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var handlerStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handlerCompleted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseHandler = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var server = new NamedPipeMessageServer(pipeName);
        var serverTask = server.RunAsync(async (_, _) =>
        {
            handlerStarted.TrySetResult();
            try
            {
                await releaseHandler.Task.ConfigureAwait(false);
            }
            finally
            {
                handlerCompleted.TrySetResult();
            }
        }, cancellation.Token);

        try
        {
            await using var client = await NamedPipeMessageClient.ConnectAsync(pipeName, 2000, cancellation.Token);
            await handlerStarted.Task.WaitAsync(cancellation.Token);
            await cancellation.CancelAsync();

            Exception? shutdownException = null;
            try
            {
                await serverTask.WaitAsync(TimeSpan.FromSeconds(4));
            }
            catch (Exception exception)
            {
                shutdownException = exception;
            }

            Assert.True(serverTask.IsCompleted);
            Assert.IsType<TimeoutException>(shutdownException);
        }
        finally
        {
            releaseHandler.TrySetResult();
            await handlerCompleted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            try
            {
                await serverTask;
            }
            catch (TimeoutException)
            {
            }
        }
    }

    [Fact]
    public async Task AcceptedClientOwner_CancellationAfterAcceptStillRunsOneBoundedDisposal()
    {
        using var shutdown = new CancellationTokenSource();
        var stream = new BlockingDisposeStream();
        var peer = new PipePeer(stream);
        var handlerCalled = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        var owner = AcceptedPipeClientOwner.Start(
            peer,
            (_, token) =>
            {
                Assert.True(token.IsCancellationRequested);
                handlerCalled.TrySetResult();
                return Task.CompletedTask;
            },
            shutdown.Token,
            TimeSpan.FromMilliseconds(100),
            (work, schedulingToken) =>
            {
                Assert.False(schedulingToken.CanBeCanceled);
                shutdown.Cancel();
                return Task.Run(work, schedulingToken);
            });

        try
        {
            var exception = await Record.ExceptionAsync(() => owner);

            Assert.IsType<TimeoutException>(exception);
            Assert.True(handlerCalled.Task.IsCompleted);
            Assert.Equal(1, stream.DisposeAsyncCalls);
            Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(2));
        }
        finally
        {
            stream.ReleaseDispose.TrySetResult();
            await peer.DisposeAsync();
        }
    }

    [Fact]
    public async Task StructurallyInvalidSchema2Request_ReachesServerForTypedRejection()
    {
        var pipeName = $"ApfsAccess.InvalidSchema2.{Guid.NewGuid():N}";
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var received = new TaskCompletionSource<PipeEnvelope>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        var server = new NamedPipeMessageServer(pipeName);
        var serverTask = server.RunAsync(async (peer, token) =>
        {
            var incoming = await peer.ReadMessageAsync(token);
            Assert.NotNull(incoming);
            received.TrySetResult(incoming!);
        }, cts.Token);

        await using var client = await NamedPipeMessageClient.ConnectAsync(pipeName, 2000, cts.Token);
        var invalid = PipeMessageCodec.Create(
            ApfsMessageTypes.ControlOperationRequest,
            new ControlOperationRequestPayload(
                OperationId: Guid.NewGuid().ToString("D"),
                Command: ApfsControlCommands.Mount,
                Target: null),
            requestId: "invalid-schema2-1",
            schemaVersion: PipeSchemaVersions.Schema2);
        await client.SendAsync(invalid, cts.Token);

        var envelope = await received.Task.WaitAsync(cts.Token);
        Assert.Equal("invalid-schema2-1", envelope.RequestId);
        Assert.False(PipeMessageCodec.Validate(envelope).IsValid);

        await cts.CancelAsync();
        await serverTask;
    }

    private sealed class BlockingDisposeStream : Stream
    {
        public TaskCompletionSource ReleaseDispose { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        public int DisposeAsyncCalls;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => 0;
        public override long Position
        {
            get => 0;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => 0;
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count)
        {
        }

        public override async ValueTask DisposeAsync()
        {
            Interlocked.Increment(ref DisposeAsyncCalls);
            await ReleaseDispose.Task.ConfigureAwait(false);
            await base.DisposeAsync().ConfigureAwait(false);
        }
    }
}
