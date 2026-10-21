using System.IO.Pipes;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class DriveLetterTransportTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task ExchangesPreferenceAfterLargeInitialStatus(int statusCount)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var name = "apfs-preference-test-" + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0);
        var request = new DriveLetterPreferenceRequestPayload("exact-device", "exact-volume",
            "fbda2042-9e07-420e-aea1-eafefed58643", "T");

        async Task ServeAsync()
        {
            await server.WaitForConnectionAsync(deadline.Token);
            await using var serverPeer = new PipePeer(server);
            for (var i = 0; i < statusCount; i++)
                await serverPeer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged,
                    new StatusChangedPayload(RuntimeState.Idle, [], null, DateTime.UtcNow,
                        [new string('x', 65536)], false, [])), deadline.Token);
            var message = await serverPeer.ReadMessageAsync(deadline.Token);
            Assert.NotNull(message);
            Assert.Equal(ApfsMessageTypes.DriveLetterPreferenceRequested, message.Type);
            Assert.True(PipeMessageCodec.TryGetPayload<DriveLetterPreferenceRequestPayload>(message, out var actual));
            Assert.Equal(request, actual);
            await serverPeer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.Ack,
                new AckPayload(true, "Saved"), message.RequestId), deadline.Token);
        }

        var serving = ServeAsync();
        var result = await DriveLetterCommand.ExchangeAsync(name, request, deadline.Token);
        Assert.True(result.Success);
        Assert.Equal("Saved", result.Message);
        await serving;
    }

    [Fact]
    public async Task RejectsUnexpectedInitialFrameBeforeSendingPreference()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var name = "apfs-preference-test-" + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        async Task ServeAsync()
        {
            await server.WaitForConnectionAsync(deadline.Token);
            await using var serverPeer = new PipePeer(server);
            await serverPeer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.Ack,
                new AckPayload(false, "Stopping")), deadline.Token);
        }
        var sending = ServeAsync();
        await Assert.ThrowsAsync<IOException>(() => DriveLetterCommand.ExchangeAsync(name,
            new("exact-device", "exact-volume", "fbda2042-9e07-420e-aea1-eafefed58643", "T"), deadline.Token));
        await sending;
    }
}
