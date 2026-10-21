using System.IO.Pipes;
using System.Text.Json;
using ApfsAccess.Core;
using ApfsAccess.Ipc;

namespace ApfsAccess.Cli.Tests;

public sealed class CliStartupDeadlockRepairsTests
{
    private const string DeviceId = @"D:\SyntheticImage.apfs";
    private const string ContainerUuid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string VolumeUuid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    private const string PartitionUuid = "11111111-2222-3333-4444-555555555555";
    private static readonly string ContainerId = ApfsTopology.BuildContainerId(ContainerUuid);
    private static readonly string CatalogVolId = ApfsTopology.BuildVolumeId(ContainerUuid, 101);
    private static readonly string PartitionId = "apfs-part:" + PartitionUuid;
    private static readonly string StoreId = "apfs-store:" + PartitionUuid;
    private const string DiskId = "apfs-disk:image";
    private const string VolumeId = @"D:\SyntheticImage.apfs|Volume-101";

    private static PipeEnvelope OversizedGreeting(int payloadSize = 65536, MountedVolumeDisplay[]? mounts = null)
    {
        var inventory = TestInventory();
        return PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged,
            new StatusChangedPayload(RuntimeState.Idle, [], null, DateTime.UtcNow,
                [new string('g', payloadSize)], false, [],
                MountedVolumes: mounts ?? [],
                ConnectedInventory: inventory.Devices,
                InventoryGeneration: 1));
    }

    private static InventoryPayload TestInventory()
    {
        var volume = new VolumeInfo(VolumeId, DeviceId, "Data", true,
            SupportsNativeWrite: true, RecoveryIdentity: "rec-1",
            CatalogVolumeId: CatalogVolId, CatalogContainerUuid: ContainerUuid,
            CatalogVolumeObjectId: 101, CatalogDecision: ApfsCapabilityDecision.Writable,
            CatalogReasons: [], CatalogAutoMountAllowed: true, CatalogVolumeUuid: VolumeUuid,
            RegisteredImage: null, IsEncrypted: false);
        var topology = new ApfsTopologySnapshot(
            [new ApfsDiskRecord(DiskId, DeviceId, null, 2097152)],
            [new ApfsPartitionRecord(PartitionId, PartitionUuid, DiskId, 1, 0, 2097152, "7C3457EF-0000-11AA-AA11-00306543ECAC", "Apple_APFS")],
            [new ApfsStoreRecord(StoreId, ContainerUuid, PartitionId, ContainerId, 0, 2097152, 4096, null, null)],
            [new ApfsContainerRecord(ContainerId, ContainerUuid, 4096, [StoreId], [CatalogVolId], false, "90", [], [], [])],
            [new ApfsVolumeRecord(CatalogVolId, VolumeUuid, "101", ContainerId, "Data", true, ["data"], 64, null, "CaseSensitive", "none", false, [], [], [], "7", "90")],
            []);
        var device = new DeviceInventory(new(DeviceId, "Synthetic", true), [volume], new(1, DeviceId, [DiskId], topology));
        return new InventoryPayload([device], DateTime.UtcNow);
    }

    private static (PipeEnvelope Greeting, InventoryPayload Inventory, string VolumeId) EncryptedGreeting(int payloadSize = 65536)
    {
        var profile = new EncryptedImageProfile(DeviceId, "windows-file:1:2:4096:4:scope:0:4096", 0, 4096,
            "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", 101, 8, 1, 8, 2, 8,
            "33333333-3333-3333-3333-333333333333", "includes-header");
        var volume = new VolumeInfo(profile.VolumeId, DeviceId, "Encrypted", true,
            SupportsNativeWrite: true, RecoveryIdentity: profile.Contract,
            CatalogVolumeId: profile.VolumeId, CatalogContainerUuid: profile.ContainerUuid,
            CatalogVolumeObjectId: profile.VolumeObjectId, CatalogDecision: ApfsCapabilityDecision.Writable,
            CatalogReasons: [], CatalogAutoMountAllowed: true, CatalogVolumeUuid: profile.VolumeUuid,
            RegisteredImage: profile, IsEncrypted: true);
        var device = new DeviceInventory(new(DeviceId, "Synthetic", true), [volume], null);
        var inventory = new InventoryPayload([device], DateTime.UtcNow);
        var greeting = PipeMessageCodec.Create(ApfsMessageTypes.StatusChanged,
            new StatusChangedPayload(RuntimeState.Idle, [], null, DateTime.UtcNow,
                [new string('g', payloadSize)], false, [],
                MountedVolumes: [],
                ConnectedInventory: inventory.Devices,
                InventoryGeneration: 1));
        return (greeting, inventory, profile.VolumeId);
    }

    private static async Task RunZeroBufferServerAsync(
        string pipeName,
        Func<PipePeer, CancellationToken, Task> serve,
        Func<string, CancellationToken, Task> client,
        CancellationToken cancellationToken)
    {
        await using var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0);
        async Task ServerTask()
        {
            await server.WaitForConnectionAsync(cancellationToken);
            await using var peer = new PipePeer(server);
            await serve(peer, cancellationToken);
        }
        var serverTask = ServerTask();
        try
        {
            await client(pipeName, cancellationToken);
            await serverTask;
        }
        finally
        {
            server.Dispose();
            try { await serverTask; } catch { }
        }
    }

    [Fact]
    public async Task ContainerCommand_ZeroBuffer_OversizedGreetingAndInterleavedStatus_CompletesWithoutDeadlock()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var name = $"ApfsTest.ContainerDeadlock.{Guid.NewGuid():N}";
        var opId = Guid.NewGuid().ToString("D");
        var greeting = OversizedGreeting();
        var inventory = TestInventory();

        await RunZeroBufferServerAsync(name, async (peer, token) =>
        {
            // Initial oversized greeting and interleaved broadcast before reading request
            await peer.SendAsync(greeting, token);
            await peer.SendAsync(greeting, token);

            var invReq = await peer.ReadMessageAsync(token);
            Assert.NotNull(invReq);
            Assert.Equal(ApfsMessageTypes.InventoryRequested, invReq!.Type);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.Inventory, inventory), token);

            var controlReq = await peer.ReadMessageAsync(token);
            Assert.NotNull(controlReq);
            Assert.Equal(ApfsMessageTypes.ControlOperationRequest, controlReq!.Type);
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(controlReq, out var reqPayload));
            Assert.Equal(opId, reqPayload!.OperationId);

            var result = new OperationResultPayload(opId, ApfsControlCommands.ContainerUnmount, reqPayload.Target,
                ApfsOperationFingerprint.Compute(reqPayload), ApfsOperationStates.Succeeded,
                ApfsOperationCodes.OperationSucceeded, true, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, opId), token);
        }, async (pipe, token) =>
        {
            var exit = await ContainerCommand.RunAsync(
                ["container-unmount", "--device-id", DeviceId, "--container-id", ContainerUuid, "--operation-id", opId],
                cancellationToken: token, pipeName: pipe);
            Assert.Equal(0, exit);
        }, deadline.Token);
    }

    [Fact]
    public async Task DeviceCommand_DeviceEject_ZeroBuffer_OversizedGreetingAndInterleavedStatus_CompletesWithoutDeadlock()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var name = $"ApfsTest.DeviceEjectDeadlock.{Guid.NewGuid():N}";
        var opId = Guid.NewGuid().ToString("D");
        var greeting = OversizedGreeting();
        var inventory = TestInventory();

        await RunZeroBufferServerAsync(name, async (peer, token) =>
        {
            await peer.SendAsync(greeting, token);
            await peer.SendAsync(greeting, token);

            var invReq = await peer.ReadMessageAsync(token);
            Assert.NotNull(invReq);
            Assert.Equal(ApfsMessageTypes.InventoryRequested, invReq!.Type);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.Inventory, inventory), token);

            var controlReq = await peer.ReadMessageAsync(token);
            Assert.NotNull(controlReq);
            Assert.Equal(ApfsMessageTypes.ControlOperationRequest, controlReq!.Type);
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(controlReq, out var reqPayload));
            Assert.Equal(opId, reqPayload!.OperationId);

            var result = new OperationResultPayload(opId, ApfsControlCommands.DeviceEject, reqPayload.Target,
                ApfsOperationFingerprint.Compute(reqPayload), ApfsOperationStates.Succeeded,
                ApfsOperationCodes.OperationSucceeded, true, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, opId), token);
        }, async (pipe, token) =>
        {
            var exit = await DeviceCommand.RunAsync(
                ["device-eject", "--device-id", DeviceId, "--operation-id", opId],
                pipeName: pipe);
            Assert.Equal(0, exit);
        }, deadline.Token);
    }

    [Fact]
    public async Task DeviceCommand_Rescan_ZeroBuffer_OversizedGreetingAndInterleavedStatus_CompletesWithoutDeadlock()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var name = $"ApfsTest.DeviceRescanDeadlock.{Guid.NewGuid():N}";
        var opId = Guid.NewGuid().ToString("D");
        var greeting = OversizedGreeting();
        var inventory = TestInventory();

        await RunZeroBufferServerAsync(name, async (peer, token) =>
        {
            await peer.SendAsync(greeting, token);
            await peer.SendAsync(greeting, token);

            var invReq = await peer.ReadMessageAsync(token);
            Assert.NotNull(invReq);
            Assert.Equal(ApfsMessageTypes.InventoryRequested, invReq!.Type);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.Inventory, inventory), token);
        }, async (pipe, token) =>
        {
            var exit = await DeviceCommand.RunAsync(
                ["rescan", "--device-id", DeviceId, "--operation-id", opId],
                pipeName: pipe);
            Assert.Equal(0, exit);
        }, deadline.Token);
    }

    [Fact]
    public async Task EncryptedImageCommand_Lock_ZeroBuffer_OversizedGreetingAndInterleavedStatus_CompletesWithoutDeadlock()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var name = $"ApfsTest.EncryptedDeadlock.{Guid.NewGuid():N}";
        var opId = Guid.NewGuid().ToString("D");
        var (greeting, inventory, encVolumeId) = EncryptedGreeting();

        await RunZeroBufferServerAsync(name, async (peer, token) =>
        {
            await peer.SendAsync(greeting, token);
            await peer.SendAsync(greeting, token);

            var invReq = await peer.ReadMessageAsync(token);
            Assert.NotNull(invReq);
            Assert.Equal(ApfsMessageTypes.InventoryRequested, invReq!.Type);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.Inventory, inventory), token);

            var controlReq = await peer.ReadMessageAsync(token);
            Assert.NotNull(controlReq);
            Assert.Equal(ApfsMessageTypes.ControlOperationRequest, controlReq!.Type);
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(controlReq, out var reqPayload));
            Assert.Equal(opId, reqPayload!.OperationId);

            var result = new OperationResultPayload(opId, "lock", reqPayload.Target,
                ApfsOperationFingerprint.Compute(reqPayload), ApfsOperationStates.Succeeded,
                ApfsOperationCodes.OperationSucceeded, true, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow,
                FinalStatus: "locked", MountProof: "absent", OwnershipProof: "proven", DurabilityProof: "proven",
                EncryptionState: EncryptedVolumeState.Locked);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, opId), token);
        }, async (pipe, token) =>
        {
            var exit = await EncryptedImageCommand.RunAsync(
                ["lock", "--device-id", DeviceId, "--volume-id", encVolumeId, "--operation-id", opId],
                pipeOverride: pipe);
            Assert.Equal(0, exit);
        }, deadline.Token);
    }

    [Fact]
    public async Task SnapshotControlCommand_Recover_ZeroBuffer_OversizedGreetingAndInterleavedStatus_CompletesWithoutDeadlock()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var name = $"ApfsTest.SnapshotDeadlock.{Guid.NewGuid():N}";
        var opId = Guid.NewGuid().ToString("D");
        var greeting = OversizedGreeting();
        var inventory = TestInventory();

        await RunZeroBufferServerAsync(name, async (peer, token) =>
        {
            await peer.SendAsync(greeting, token);
            await peer.SendAsync(greeting, token);

            var invReq = await peer.ReadMessageAsync(token);
            Assert.NotNull(invReq);
            Assert.Equal(ApfsMessageTypes.InventoryRequested, invReq!.Type);
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.Inventory, inventory), token);

            var controlReq = await peer.ReadMessageAsync(token);
            Assert.NotNull(controlReq);
            Assert.Equal(ApfsMessageTypes.ControlOperationRequest, controlReq!.Type);
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(controlReq, out var reqPayload));
            Assert.Equal(opId, reqPayload!.OperationId);

            var result = new OperationResultPayload(opId, ApfsControlCommands.SnapshotRecover, reqPayload.Target,
                ApfsOperationFingerprint.Compute(reqPayload), ApfsOperationStates.Succeeded,
                ApfsOperationCodes.OperationSucceeded, true, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow,
                FinalStatus: "snapshot-recovered", MountProof: "present", OwnershipProof: "proven", DurabilityProof: "not-applicable");
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, opId), token);
        }, async (pipe, token) =>
        {
            var exit = await SnapshotControlCommand.RunAsync(
                ["recover", "--device-id", DeviceId, "--volume-id", VolumeId, "--operation-id", opId],
                pipeName: pipe);
            Assert.Equal(0, exit);
        }, deadline.Token);
    }

    [Fact]
    public async Task ContainerVerificationBatch_PipeClient_ZeroBuffer_OversizedGreetingAndInterleavedStatus_CompletesWithoutDeadlock()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var name = $"ApfsTest.VerificationDeadlock.{Guid.NewGuid():N}";
        var opId = Guid.NewGuid().ToString("D");
        var greeting = OversizedGreeting();
        var target = new ApfsControlTarget(DeviceId, VolumeId);
        var request = new ControlOperationRequestPayload(opId, ApfsControlCommands.VolumeVerify, target,
            ExpiresAtUtc: DateTime.UtcNow.AddSeconds(90));

        await RunZeroBufferServerAsync(name, async (peer, token) =>
        {
            await peer.SendAsync(greeting, token);
            await peer.SendAsync(greeting, token);

            var controlReq = await peer.ReadMessageAsync(token);
            Assert.NotNull(controlReq);
            Assert.Equal(ApfsMessageTypes.ControlOperationRequest, controlReq!.Type);
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(controlReq, out var reqPayload));
            Assert.Equal(opId, reqPayload!.OperationId);

            var result = new OperationResultPayload(opId, ApfsControlCommands.VolumeVerify, reqPayload.Target,
                ApfsOperationFingerprint.Compute(reqPayload), ApfsOperationStates.Succeeded,
                ApfsOperationCodes.OperationSucceeded, true, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow,
                Diagnostic: "Current metadata verified.");
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, opId), token);
        }, async (pipe, token) =>
        {
            await using var client = new PipeContainerVerificationClient(ct => NamedPipeMessageClient.ConnectAsync(pipe, 2000, ct));
            var status = await client.ReadFreshStatusAsync(token);
            Assert.NotNull(status);

            var actual = await client.VerifyAsync(request, token);
            Assert.True(actual.Success);
            Assert.Equal(ApfsOperationStates.Succeeded, actual.State);
        }, deadline.Token);
    }

    [Fact]
    public async Task ManagementCommand_VolumeVerify_ZeroBuffer_OversizedGreetingAndInterleavedStatus_CompletesWithoutDeadlock()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var name = $"ApfsTest.ManagementDeadlock.{Guid.NewGuid():N}";
        var opId = Guid.NewGuid().ToString("D");
        var mounts = new[]
        {
            new MountedVolumeDisplay(VolumeId, "R:\\", "Data", DeviceId, "Synthetic",
                MountAccessMode.ReadWrite, "rec-1", RuntimeState.MountedRw,
                CatalogContainerUuid: ContainerUuid, CatalogVolumeId: CatalogVolId)
        };
        var greeting = OversizedGreeting(mounts: mounts);

        await RunZeroBufferServerAsync(name, async (peer, token) =>
        {
            await peer.SendAsync(greeting, token);
            await peer.SendAsync(greeting, token);

            var controlReq = await peer.ReadMessageAsync(token);
            Assert.NotNull(controlReq);
            Assert.Equal(ApfsMessageTypes.ControlOperationRequest, controlReq!.Type);
            Assert.True(PipeMessageCodec.TryGetPayload<ControlOperationRequestPayload>(controlReq, out var reqPayload));
            Assert.Equal(opId, reqPayload!.OperationId);

            var result = new OperationResultPayload(opId, ApfsControlCommands.VolumeVerify, reqPayload.Target,
                ApfsOperationFingerprint.Compute(reqPayload), ApfsOperationStates.Succeeded,
                ApfsOperationCodes.OperationSucceeded, true, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow,
                FinalStatus: "verified-covered-scope", MountProof: "absent", OwnershipProof: "proven", DurabilityProof: "not-applicable");
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, result, opId), token);
        }, async (pipe, token) =>
        {
            var exit = await ManagementCommand.RunAsync(
                ["volume-verify", "--device-id", DeviceId, "--volume-id", VolumeId, "--operation-id", opId],
                cancellationToken: token,
                clientConnect: (p, ms, ct) => AgentControlClient.ConnectAsync(pipe, ms, ct));
            Assert.Equal(0, exit);
        }, deadline.Token);
    }

    [Fact]
    public async Task ManagementTryCancel_ZeroBuffer_OversizedGreetingAndInterleavedStatus_CompletesWithoutDeadlock()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var name = $"ApfsTest.CancelDeadlock.{Guid.NewGuid():N}";
        var opId = Guid.NewGuid().ToString("D");
        var greeting = OversizedGreeting();

        await RunZeroBufferServerAsync(name, async (peer, token) =>
        {
            await peer.SendAsync(greeting, token);
            await peer.SendAsync(greeting, token);

            var cancelReq = await peer.ReadMessageAsync(token);
            Assert.NotNull(cancelReq);
            Assert.Equal(ApfsMessageTypes.CancellationRequest, cancelReq!.Type);
            Assert.True(PipeMessageCodec.TryGetPayload<OperationCancellationRequestPayload>(cancelReq, out var cancelPayload));
            Assert.Equal(opId, cancelPayload!.OperationId);

            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.OperationResult, new { }, opId, 2), token);
        }, async (pipe, token) =>
        {
            var cancelled = await ManagementCommand.ManagementTryCancelAsync(pipe, opId,
                clientConnect: (p, ms, ct) => AgentControlClient.ConnectAsync(pipe, ms, ct),
                cancellationToken: token);
            Assert.True(cancelled);
        }, deadline.Token);
    }

    [Fact]
    public async Task ManagementTryCancel_ProtocolError_ThrowsIOExceptionWithoutSwallowing()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var name = $"ApfsTest.CancelProtocolError.{Guid.NewGuid():N}";
        var opId = Guid.NewGuid().ToString("D");

        await RunZeroBufferServerAsync(name, async (peer, token) =>
        {
            // Send invalid greeting (Pong instead of StatusChanged)
            await peer.SendAsync(PipeMessageCodec.Create(ApfsMessageTypes.Pong, new PongPayload(DateTime.UtcNow)), token);
        }, async (pipe, token) =>
        {
            await Assert.ThrowsAsync<IOException>(() => ManagementCommand.ManagementTryCancelAsync(pipe, opId,
                clientConnect: (p, ms, ct) => AgentControlClient.ConnectAsync(pipe, ms, ct),
                cancellationToken: token));
        }, deadline.Token);
    }

    [Fact]
    public async Task PipeContainerVerificationClient_HandshakeFailure_DeterministicallyDisposesPeer()
    {
        var invalidGreeting = PipeMessageCodec.Create(ApfsMessageTypes.Pong, new PongPayload(DateTime.UtcNow));
        var stream = new TrackingStream(new MemoryStream(System.Text.Encoding.UTF8.GetBytes(PipeMessageCodec.Serialize(invalidGreeting) + "\n")));
        var peer = new PipePeer(stream);
        await using var client = new PipeContainerVerificationClient(_ => Task.FromResult(peer));
        await Assert.ThrowsAsync<IOException>(() => client.ReadFreshStatusAsync(CancellationToken.None));
        Assert.True(stream.IsDisposed);
    }

    [Fact]
    public async Task PipeContainerVerificationClient_EarlyCancellation_DeterministicallyDisposesPeer()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var stream = new TrackingStream(new MemoryStream());
        var peer = new PipePeer(stream);
        await using var client = new PipeContainerVerificationClient(_ => Task.FromResult(peer));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ReadFreshStatusAsync(cancelled.Token));
        Assert.True(stream.IsDisposed);
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
