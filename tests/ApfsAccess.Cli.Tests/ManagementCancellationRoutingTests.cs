using System.Collections.Concurrent;
using System.IO.Pipes;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class ManagementCancellationRoutingTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellationAfterDispatchReturnsToSelectedInstanceAndLeavesOtherEndpointUntouched(bool reconnectFails)
    {
        using var bound = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        using var cancelled = new CancellationTokenSource();
        using var stopOther = CancellationTokenSource.CreateLinkedTokenSource(bound.Token);
        var instance = Guid.NewGuid();
        var selected = FusionControlEndpoint.ForPrivateInstance(instance);
        var operationId = Guid.NewGuid().ToString("D");
        var selectedTransport = "management-selected-test-" + Guid.NewGuid().ToString("N");
        var otherTransport = "management-unrelated-test-" + Guid.NewGuid().ToString("N");
        using var requestServer = Server(selectedTransport);
        using var unrelated = Server(otherTransport);
        var issuedSignal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancellationListening = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cancellationSeen = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var runFinished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var connections = new ConcurrentQueue<string>();
        var otherTouched = false;
        var status = CliContainerVerificationFixture.Status(live: false) with { ManagementJournalRootInspected = true };
        var inventory = status.ConnectedInventory!;
        var target = inventory[0].Volumes[0];
        async Task<PipePeer> Connect(string pipe, int milliseconds, CancellationToken token)
        {
            connections.Enqueue(pipe);
            Assert.True(pipe == selected || pipe == ApfsPipeConstants.PipeName);
            if (reconnectFails && pipe == selected && connections.Count > 1) throw new IOException("Selected test endpoint unavailable");
            // Both transports are private test servers. The protected default Service is never contacted.
            return await NamedPipeMessageClient.ConnectAsync(pipe == selected ? selectedTransport : otherTransport, milliseconds, token);
        }
        var other = Task.Run(async () =>
        {
            try
            {
                await unrelated.WaitForConnectionAsync(stopOther.Token);
                await using var peer = new PipePeer(unrelated);
                if (await peer.ReadMessageAsync(stopOther.Token) is { }) otherTouched = true;
            }
            catch (OperationCanceledException) when (stopOther.IsCancellationRequested) { }
        });
        var dispatch = Task.Run(async () =>
        {
            await requestServer.WaitForConnectionAsync(bound.Token);
            await using var peer = new PipePeer(requestServer);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, status), bound.Token);
            Assert.Equal(ApfsMessageTypes.InventoryRequested, (await peer.ReadMessageAsync(bound.Token))!.Type);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.Inventory, new InventoryPayload(inventory, DateTime.UtcNow)), bound.Token);
            var issued = (await peer.ReadMessageAsync(bound.Token))!;
            Assert.Equal(ApfsMessageTypes.ControlOperationRequest, issued.Type);
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(issued, out var request));
            Assert.Equal(operationId, request!.OperationId);
            Assert.Equal(target.VolumeId, request.Target!.VolumeId);
            issuedSignal.SetResult();
            await cancellationListening.Task.WaitAsync(bound.Token);
            cancelled.Cancel();
            await cancellationSeen.Task.WaitAsync(bound.Token);
            await runFinished.Task.WaitAsync(bound.Token);
        });
        var cancellation = Task.Run(async () =>
        {
            await issuedSignal.Task.WaitAsync(bound.Token);
            if (reconnectFails)
            {
                cancellationListening.SetResult();
                cancellationSeen.SetResult();
                return;
            }
            using var cancellationServer = Server(selectedTransport);
            cancellationListening.SetResult();
            await cancellationServer.WaitForConnectionAsync(bound.Token);
            await using var peer = new PipePeer(cancellationServer);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged, status), bound.Token);
            var envelope = (await peer.ReadMessageAsync(bound.Token))!;
            Assert.True(PipeMessageCodec.Validate(envelope).IsValid);
            Assert.Equal(ApfsMessageTypes.CancellationRequest, envelope.Type);
            Assert.True(PipeMessageCodec.TryGetPayload<OperationCancellationRequestPayload>(envelope, out var request));
            Assert.Equal(operationId, request!.OperationId);
            cancellationSeen.SetResult();
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, new { }, operationId, 2), bound.Token);
        });
        try
        {
            var exit = await ManagementCommand.RunAsync(["management-plan", "--device-id", target.DeviceId,
                "--volume-id", target.VolumeId, "--operation", "rename-volume", "--operation-id", operationId],
                CliContainerVerificationFixture.Hex, cancelled.Token, privateInstance: instance, connect: Connect);
            Assert.Equal(5, exit);
            runFinished.SetResult();
            await Task.WhenAll(dispatch, cancellation).WaitAsync(bound.Token);
            Assert.Equal(new[] { selected, selected }, connections);
            Assert.False(otherTouched);
            Assert.False(unrelated.IsConnected);
        }
        finally
        {
            stopOther.Cancel();
            runFinished.TrySetResult();
            bound.Cancel();
            await other;
        }
    }

    private static NamedPipeServerStream Server(string name) => new(name, PipeDirection.InOut, 2,
        PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
}
