using System.IO.Pipes;
using System.Text;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Ipc.Tests;

public sealed class AgentControlClientTests
{
    [Theory]
    [InlineData(ApfsMessageTypes.ControlOperationRequest)]
    [InlineData(ApfsMessageTypes.CancellationRequest)]
    [InlineData(ApfsMessageTypes.OperationResultQuery)]
    public async Task ZeroBufferConnection_DrainsLargeGreetingBeforeExactRequest(string type)
    {
        var id = Guid.NewGuid().ToString("D");
        var target = new ApfsControlTarget(@"D:\private-image.apfs", @"D:\private-image.apfs|Main", "private-owner");
        var request = type switch
        {
            ApfsMessageTypes.ControlOperationRequest => PipeMessageCodec.Create(type,
                new ControlOperationRequestPayload(id, ApfsControlCommands.Fix, target,
                    ExpiresAtUtc: DateTime.UtcNow.AddSeconds(90)), id, PipeSchemaVersions.Schema2),
            ApfsMessageTypes.CancellationRequest => PipeMessageCodec.Create(type,
                new OperationCancellationRequestPayload(id), id, PipeSchemaVersions.Schema2),
            _ => PipeMessageCodec.Create(type, new OperationResultQueryPayload(id), id, PipeSchemaVersions.Schema2),
        };
        Assert.True(PipeMessageCodec.Validate(request).IsValid);
        var greeting = Greeting();
        Assert.True(Encoding.UTF8.GetByteCount(PipeMessageCodec.Serialize(greeting)) > 32768);
        await RunAsync(async (peer, token) =>
        {
            for (var i = 0; i < 3; ++i) await peer.SendAsync(greeting, token);
            var received = await peer.ReadMessageAsync(token);
            Assert.NotNull(received);
            Assert.Equal(PipeMessageCodec.Serialize(request), PipeMessageCodec.Serialize(received!));
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.Pong,
                new PongPayload(DateTime.UtcNow), id), token);
        }, async (name, token) =>
        {
            await using var client = await AgentControlClient.ConnectAsync(name, 2000, token);
            await client.SendAsync(request, token);
            var response = await client.ReadMessageAsync(token);
            Assert.NotNull(response);
            Assert.Equal(ApfsMessageTypes.Pong, response!.Type);
            Assert.Equal(id, response.RequestId);
        });
    }

    [Theory]
    [InlineData("wrong-type")]
    [InlineData("null-payload")]
    [InlineData("unknown-schema")]
    public async Task InvalidGreeting_RefusesAndClosesClient(string kind)
    {
        var greeting = kind switch
        {
            "wrong-type" => PipeMessageCodec.Create(ApfsMessageTypes.Pong, new PongPayload(DateTime.UtcNow)),
            "null-payload" => new PipeEnvelope(ApfsMessageTypes.StatusChanged, null, null),
            _ => Greeting() with { SchemaVersion = 99 },
        };
        await RunAsync(async (peer, token) =>
        {
            await peer.SendAsync(greeting, token);
            Assert.Null(await peer.ReadMessageAsync(token));
        }, (name, token) => Assert.ThrowsAsync<IOException>(() => AgentControlClient.ConnectAsync(name, 2000, token)));
    }

    [Fact]
    public Task MissingGreeting_ReportsDisconnect()
        => RunAsync((peer, _) => peer.DisposeAsync().AsTask(),
            (name, token) => Assert.ThrowsAsync<IOException>(() => AgentControlClient.ConnectAsync(name, 2000, token)));

    [Fact]
    public async Task CancellationWhileGreetingPending_ClosesClientWithoutSendingRequest()
    {
        using var cancellation = new CancellationTokenSource();
        var connected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await RunAsync(async (peer, token) =>
        {
            connected.TrySetResult();
            Assert.Null(await peer.ReadMessageAsync(token));
        }, async (name, token) =>
        {
            var connect = AgentControlClient.ConnectAsync(name, 2000, cancellation.Token);
            await connected.Task.WaitAsync(token);
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => connect);
        });
    }

    private static async Task RunAsync(Func<PipePeer, CancellationToken, Task> serve,
        Func<string, CancellationToken, Task> client)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var name = $"ApfsAccess.AgentGreeting.Test.{Guid.NewGuid():N}";
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0);
        async Task OwnServer()
        {
            await server.WaitForConnectionAsync(deadline.Token);
            await using var peer = new PipePeer(server);
            await serve(peer, deadline.Token);
        }
        var owner = OwnServer();
        try
        {
            await client(name, deadline.Token);
            await owner;
        }
        finally
        {
            deadline.Cancel();
            server.Dispose();
            try { await owner; }
            catch when (owner.IsCanceled || owner.IsFaulted) { }
        }
    }

    [Fact]
    public async Task OperationDeadlineAfterGreeting_RemainsCancellationInsteadOfDisconnect()
    {
        using var lifetime = new CancellationTokenSource();
        await RunAsync(async (peer, token) =>
        {
            await peer.SendAsync(Greeting(), token);
            Assert.Null(await peer.ReadMessageAsync(token));
        }, async (name, token) =>
        {
            await using var client = await AgentControlClient.ConnectAsync(name, 2000, lifetime.Token);
            lifetime.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ReadMessageAsync(lifetime.Token));
        });
    }

    [Fact]
    public async Task DisposeWithFullReplyQueue_DrainsReceiverAndIsIdempotent()
    {
        var queued = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await RunAsync(async (peer, token) =>
        {
            await peer.SendAsync(Greeting(), token);
            for (var i = 0; i < 2; ++i)
                await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.Pong, new PongPayload(DateTime.UtcNow)), token);
            queued.TrySetResult();
            Assert.Null(await peer.ReadMessageAsync(token));
        }, async (name, token) =>
        {
            await using var client = await AgentControlClient.ConnectAsync(name, 2000, token);
            await queued.Task.WaitAsync(token);
            await Task.WhenAll(client.DisposeAsync().AsTask(), client.DisposeAsync().AsTask()).WaitAsync(token);
        });
    }

    private static PipeEnvelope Greeting() => PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged,
        new StatusChangedPayload(RuntimeState.Idle, [], null, DateTime.UtcNow, [new string('g', 32768)], false, []));
    [Fact]
    public async Task PeerOverload_ExposesValidatedInitialStatus_AndDisposesPeerOnDispose()
    {
        var greeting = Greeting();
        var stream = new TrackingStream(new MemoryStream(Encoding.UTF8.GetBytes(PipeMessageCodec.Serialize(greeting) + "\n")));
        var peer = new PipePeer(stream);
        var client = await AgentControlClient.ConnectAsync(peer, CancellationToken.None);
        Assert.NotNull(client.InitialStatus);
        Assert.NotNull(client.ValidatedInitialStatus);
        Assert.Equal(client.InitialStatus, client.ValidatedInitialStatus);
        Assert.False(stream.IsDisposed);
        await client.DisposeAsync();
        Assert.True(stream.IsDisposed);
    }

    [Fact]
    public async Task PeerOverload_HandshakeFailure_DeterministicallyDisposesPeer()
    {
        var invalidGreeting = PipeMessageCodec.Create(ApfsMessageTypes.Pong, new PongPayload(DateTime.UtcNow));
        var stream = new TrackingStream(new MemoryStream(Encoding.UTF8.GetBytes(PipeMessageCodec.Serialize(invalidGreeting) + "\n")));
        var peer = new PipePeer(stream);
        await Assert.ThrowsAsync<IOException>(() => AgentControlClient.ConnectAsync(peer, CancellationToken.None));
        Assert.True(stream.IsDisposed);
    }

    [Fact]
    public async Task PeerOverload_EarlyCancellation_DeterministicallyDisposesPeer()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var stream = new TrackingStream(new MemoryStream());
        var peer = new PipePeer(stream);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => AgentControlClient.ConnectAsync(peer, cancelled.Token));
        Assert.True(stream.IsDisposed);
    }

    [Fact]
    public async Task DrainsInterleavedStatusBroadcastsWhileAwaitingResponse()
    {
        var id = Guid.NewGuid().ToString("D");
        var ping = PipeMessageCodec.Create(ApfsMessageTypes.Ping, new PingPayload(DateTime.UtcNow), id);
        var greeting = Greeting();
        await RunAsync(async (peer, token) =>
        {
            await peer.SendAsync(greeting, token);
            await peer.SendAsync(greeting, token);
            var received = await peer.ReadMessageAsync(token);
            Assert.NotNull(received);
            Assert.Equal(ApfsMessageTypes.Ping, received!.Type);
            await peer.SendAsync(greeting, token);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.Pong, new PongPayload(DateTime.UtcNow), id), token);
        }, async (name, token) =>
        {
            await using var client = await AgentControlClient.ConnectAsync(name, 2000, token);
            await client.SendAsync(ping, token);
            var response = await client.ReadMessageAsync(token);
            Assert.NotNull(response);
            Assert.Equal(ApfsMessageTypes.Pong, response!.Type);
            Assert.Equal(id, response.RequestId);
        });
    }

    private sealed class TrackingStream(Stream inner) : Stream
    {
        public bool IsDisposed { get; private set; }
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => inner.CanWrite;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => inner.ReadAsync(buffer, cancellationToken);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => inner.ReadAsync(buffer, offset, count, cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => inner.SetLength(value);
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
        protected override void Dispose(bool disposing) { IsDisposed = true; inner.Dispose(); base.Dispose(disposing); }
        public override async ValueTask DisposeAsync() { IsDisposed = true; await inner.DisposeAsync(); await base.DisposeAsync(); }
    }
}