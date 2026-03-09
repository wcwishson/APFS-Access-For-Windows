using ApfsAccess.Ipc;

namespace ApfsAccess.Ipc.Tests;

public sealed class NamedPipeRoundTripTests
{
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
}
